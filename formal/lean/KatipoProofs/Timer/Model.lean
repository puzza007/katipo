/-!
# libcurl's timer on libevent: transcription of `formal/KatipoTimer.tla`

The C port's `multi_timer_cb`, `timer_cb` and `event_cb` (`c_src/katipo.c`)
driving libcurl's `Curl_update_timer` (`lib/multi.c`). libcurl asks for its
timer with a delay counted from now; libevent's `evtimer_add` counts it from
the time it cached when the loop iteration began, so a timer set late in a
long callback fires early. libcurl only calls `multi_timer_cb` when its next
deadline changes, and some versions forget the deadline they reported when
run for a timeout ("in case the application asks libcurl to run the timeout
prematurely"): libcurl <= 8.9.1 and >= 8.11.1 do, 8.10.0 to 8.11.0 do not.
libevent and libcurl also read different clocks (libevent's default on Linux
is `CLOCK_MONOTONIC_COARSE`, libcurl's `CLOCK_MONOTONIC_RAW`), so a timer can
fire up to `lag` ticks before its expiry even when it was added at the right
time.

A callback is one step: it starts at `now` (libevent caches that time), runs
the deadlines due by then, runs for `k ≤ P.skew` more ticks, and has libcurl
update its timer at `now + k`. `Tick` is time passing while the loop sleeps,
which cannot pass a pending timer; the timer may fire once the clock is
within `P.lag` of it.

## Where this model says more than the code
* Unbounded clock, any number of deadlines, any deadline delay `d` (the TLA+
  model bounds all three).
* A socket callback may drop any value from libcurl's deadlines, not only one
  it holds, and requests and socket activity may happen at any time.

## Where it says less
* Which transfer a deadline belongs to: every deadline is treated alike.
* `event_cb`'s idle delete (before the fix) tests `still_running <= 0`; here
  it is "libcurl has no deadlines".
* `cache`, `added` and the TLA+ `early` witness are not state here: `cache`
  lives only inside a callback, and the other two are bookkeeping.

## Configuration
| knob           | meaning                                                       |
|----------------|---------------------------------------------------------------|
| `resets`       | libcurl forgets its last reported deadline on a timeout run (<= 8.9.1, >= 8.11.1): it then counts as nothing reported |
| `refresh`      | `multi_timer_cb` refreshes libevent's cached time (the fix)   |
| `rearm`        | `timer_cb` re-arms from `curl_multi_timeout` (the fix)        |
| `deleteOnNone` | `multi_timer_cb` deletes the timer on `-1` (the fix)          |
| `idleDelete`   | `event_cb` deletes the timer when nothing is running (before the fix) |
| `lag`          | how early libevent's clock lets a timer fire (0: one clock)   |
| `skew`         | the longest a callback runs before libcurl updates its timer  |
-/

namespace KatipoProofs.Timer

structure Params where
  resets : Bool
  refresh : Bool
  rearm : Bool
  deleteOnNone : Bool
  idleDelete : Bool
  skew : Nat
  lag : Nat

/-- What libcurl last reported to `multi_timer_cb` (`last_expire_ts`):
nothing, or a deadline. Its reset forgets the deadline, which leaves nothing
reported: a pending deadline is then reported again, and an empty set is not
reported as `-1` again. -/
inductive Rep where
  | none
  | at (n : Nat)
  deriving DecidableEq

structure St where
  now : Nat
  /-- the pending libevent timer's absolute expiry -/
  timer : Option Nat
  /-- libcurl's pending deadlines (absolute times) -/
  ds : List Nat
  last : Rep
  deriving DecidableEq

def init : St := { now := 0, timer := none, ds := [], last := .none }

/-- The earliest deadline (`multi_timeout`). -/
def minD : List Nat → Option Nat
  | [] => none
  | x :: xs =>
    match minD xs with
    | none => some x
    | some y => some (Nat.min x y)

def repOf : Option Nat → Rep
  | none => .none
  | some m => .at m

/-- `multi_timer_cb(timeout_ms)` at time `t`, in a callback that started at
`c`: the timer left pending. `next - t` truncates at 0, like libcurl's delay.
Without `deleteOnNone`, `-1` became `tv_usec = -1000`: a timer that fires at
once. -/
def timerFor (P : Params) (next : Option Nat) (t c : Nat) : Option Nat :=
  match next with
  | none => if P.deleteOnNone then none else some c
  | some m => some ((if P.refresh then t else c) + (m - t))

/-- `Curl_update_timer`: call `multi_timer_cb` only when the next deadline
differs from the last one reported. Returns the pending timer and the new
last-reported value. -/
def update (P : Params) (D : List Nat) (L : Rep) (pend : Option Nat) (t c : Nat) :
    Option Nat × Rep :=
  if repOf (minD D) = L then (pend, L) else (timerFor P (minD D) t c, repOf (minD D))

/-- The deadlines left after a callback starting at `now`: the due ones run,
`drop` finished early, `extra` added. -/
def remaining (s : St) (extra drop : Option Nat) : List Nat :=
  (s.ds.filter (fun y => decide (s.now < y) && decide (some y ≠ drop))) ++ extra.toList

/-- One callback of length `k`: `timer_cb` when `isTimer`, otherwise
`erl_input` (adding `extra`) or `event_cb` (dropping `drop`). -/
def callback (P : Params) (s : St) (isTimer : Bool) (extra drop : Option Nat)
    (k : Nat) : St :=
  let c := s.now
  let t := s.now + k
  let L0 := if isTimer && P.resets then Rep.none else s.last
  let D1 := remaining s extra drop
  let pend0 := if isTimer then none else s.timer
  let u := update P D1 L0 pend0 t c
  let tm2 := if isTimer && P.rearm && u.1 == none && !D1.isEmpty
             then timerFor P (minD D1) t c else u.1
  let tm3 := if P.idleDelete && !isTimer && D1.isEmpty then none else tm2
  { now := t, timer := tm3, ds := D1, last := u.2 }

inductive Step (P : Params) : St → St → Prop
  /-- libevent runs the timer once its clock reaches it (`timer_cb`), up to
  `P.lag` before libcurl's clock does. -/
  | timerFire (s : St) (x k : Nat) :
      s.timer = some x → x ≤ s.now + P.lag → k ≤ P.skew →
      Step P s (callback P s true none none k)
  /-- a request arrives (`erl_input` → `new_conn` → `curl_multi_add_handle`) -/
  | add (s : St) (k d : Nat) :
      k ≤ P.skew → Step P s (callback P s false (some (s.now + k + d)) none k)
  /-- socket activity (`event_cb`), possibly finishing a transfer -/
  | socket (s : St) (k : Nat) (drop : Option Nat) :
      k ≤ P.skew → Step P s (callback P s false none drop k)
  /-- time passes while the loop sleeps, up to the pending timer -/
  | tick (s : St) :
      (∀ x, s.timer = some x → s.now < x) →
      Step P s { s with now := s.now + 1 }

inductive Reach (P : Params) : St → Prop
  | init : Reach P init
  | step (s t : St) : Reach P s → Step P s t → Reach P t

/-- At least one thing re-arms the timer after it fires early, or (the
refresh, with both libraries on one clock) it never fires early. -/
def Safe (P : Params) : Prop :=
  (P.refresh = true ∧ P.lag = 0) ∨ P.rearm = true ∨ P.resets = true

end KatipoProofs.Timer
