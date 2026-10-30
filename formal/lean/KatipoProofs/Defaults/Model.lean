/-!
# Pool defaults: transcription of `formal/KatipoPoolDefaults.tla`

One pool's default request options and their lifetime: `katipo_pool:start/3`
starting a wpool pool for configuration `g`, the pool's supervisor storing
its options (`wpool_pool:init/1`) and then starting its workers,
`katipo_pool:stop/1`, the pool crashing and `wpool_sup` restarting it from
the same arguments, and callers finding the options
(`katipo_defaults:merge_into/2`, `wpool_pool:find_wpool/1`), or finding
none and storing wpool's rebuild over whatever the term holds by then,
asking a worker for its configuration if the options are rebuilt, then
calling a worker. Each `Step` constructor is one TLA+ action, or one
branch of one.

## Where this model says more than the code
* Any number of callers, starts, crashes and restarts, in any order.
* A dying pool's workers may still serve a call or answer an ask.
* A missing term may be rebuilt without the defaults at any time.

## Where it says less
* A stop begins only on a pool that is up: `wpool_sup` handles it only
  after any start or restart it is making.
* The starts and crashes counters bound TLC's exploration only.
* The merge itself: `Defaults/Merge.lean`.

## Configuration
| knob       | meaning                                                  |
|------------|----------------------------------------------------------|
| `genCheck` | workers refuse a request of another generation (shipped) |
| `fallback` | a caller with rebuilt options asks a worker (shipped)     |
-/

namespace KatipoProofs.Defaults

/-- The pool's supervisor: not registered, registered, options stored,
workers up, or going. -/
inductive Reg | down | init | stored | up | dying
  deriving DecidableEq, Repr

inductive PC | idle | «where» | rebuild | rebuilt | ask | read | done
  deriving DecidableEq, Repr

/-- The persistent_term: none, wpool's rebuild, or a configuration's. -/
inductive Term | none | rebuilt | gen (g : Nat)
  deriving DecidableEq, Repr

/-- What a caller read: nothing yet, options without defaults, or a
configuration. -/
inductive RV | none | nodef | gen (g : Nat)
  deriving DecidableEq, Repr

structure Params where
  genCheck : Bool
  fallback : Bool

/-- `KatipoPoolDefaults.tla` VARIABLES, without TLC's counters. -/
structure St where
  child : Option Nat
  reg : Reg
  term : Term
  wgen : Option Nat
  stopping : Bool
  pc : Nat → PC
  v : Nat → RV
  ran : List (Nat × RV × Option Nat)

def upd {α β : Type} [DecidableEq α] (f : α → β) (a : α) (b : β) : α → β :=
  fun x => if x = a then b else f x

def init : St where
  child := none
  reg := .down
  term := .none
  wgen := none
  stopping := false
  pc := fun _ => .idle
  v := fun _ => .none
  ran := []

/-- The pool's workers are there to serve a call. -/
def serving (s : St) : Bool := s.reg == .up || s.reg == .dying

/-- A request read `r` is served by workers of configuration `w` only if
they are the same configuration (`v[c] = wgen` in TLA+). -/
def same : RV → Option Nat → Bool
  | .gen g, some h => g == h
  | _, _ => false

/-- What `Store` stores. -/
def termOf : Option Nat → Term
  | some g => .gen g
  | none => .none

/-- What a worker of configuration `w` answers an ask with. -/
def readOf : Option Nat → RV
  | some g => .gen g
  | none => .nodef

inductive Step (P : Params) : St → St → Prop
  | start (s : St) (g : Nat) : s.child = none → s.reg = .down →
      Step P s { s with child := some g, reg := .init }
  | store (s : St) : s.reg = .init → Step P s { s with term := termOf s.child, reg := .stored }
  | workersUp (s : St) : s.reg = .stored → Step P s { s with reg := .up, wgen := s.child }
  | stopBegin (s : St) : s.reg = .up → s.stopping = false →
      Step P s { s with stopping := true, reg := .dying }
  | stopEnd (s : St) : s.stopping = true → s.reg = .down →
      Step P s { s with stopping := false, child := none }
  | crash (s : St) : s.reg = .up → s.stopping = false → Step P s { s with reg := .dying }
  | poolGone (s : St) : s.reg = .dying → Step P s { s with reg := .down }
  | restart (s : St) : s.reg = .down → s.child.isSome → s.stopping = false →
      Step P s { s with reg := .init }
  | whereNone (s : St) (c : Nat) : s.pc c = .idle → s.reg = .down →
      Step P s { s with pc := upd s.pc c .done }
  | whereSome (s : St) (c : Nat) : s.pc c = .idle → s.reg ≠ .down →
      Step P s { s with pc := upd s.pc c .where }
  | get (s : St) (c : Nat) (g : Nat) : s.pc c = .where → s.term = .gen g →
      Step P s { s with v := upd s.v c (.gen g), pc := upd s.pc c .read }
  | getRebuilt (s : St) (c : Nat) : s.pc c = .where → s.term = .rebuilt →
      Step P s { s with pc := upd s.pc c .rebuilt }
  | getNone (s : St) (c : Nat) : s.pc c = .where → s.term = .none →
      Step P s { s with pc := upd s.pc c .rebuild }
  /-- wpool's rebuild without the defaults, over whatever the term holds -/
  | rebuild (s : St) (c : Nat) : s.pc c = .rebuild →
      Step P s { s with term := .rebuilt, pc := upd s.pc c .rebuilt }
  | rebuildGiveUp (s : St) (c : Nat) : s.pc c = .rebuild →
      Step P s { s with pc := upd s.pc c .done }
  | useAsk (s : St) (c : Nat) : s.pc c = .rebuilt → P.fallback = true →
      Step P s { s with pc := upd s.pc c .ask }
  | useNoDef (s : St) (c : Nat) : s.pc c = .rebuilt → P.fallback = false →
      Step P s { s with v := upd s.v c .nodef, pc := upd s.pc c .read }
  /-- `katipo_worker:defaults/1` -/
  | ask (s : St) (c : Nat) : s.pc c = .ask → serving s = true →
      Step P s { s with v := upd s.v c (readOf s.wgen), pc := upd s.pc c .read }
  | askFail (s : St) (c : Nat) : s.pc c = .ask → serving s = false →
      Step P s { s with pc := upd s.pc c .done }
  | callServe (s : St) (c : Nat) : s.pc c = .read → serving s = true →
      (P.genCheck = true → same (s.v c) s.wgen = true) →
      Step P s { s with pc := upd s.pc c .done, ran := (c, s.v c, s.wgen) :: s.ran }
  | callRefuse (s : St) (c : Nat) : s.pc c = .read →
      (serving s = false ∨ (P.genCheck = true ∧ same (s.v c) s.wgen = false)) →
      Step P s { s with pc := upd s.pc c .done }

inductive Reach (P : Params) : St → Prop
  | init : Reach P init
  | step {s t : St} : Reach P s → Step P s t → Reach P t

end KatipoProofs.Defaults
