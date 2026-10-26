/-!
# Retries: transcription of `formal/KatipoRetry.tla`

Requests with a retry policy, each sent again after a failed attempt,
through one `katipo_worker` and its C port: `register_req`,
`attempt_ended`, `retry_or_resolve`, the `req_timeout`, `{retry, Key}` and
`cancel` clauses of `handle_info`, and the port running each transfer until
curl ends it or a cancel for its id arrives.

Each `Step` constructor is one TLA+ action, or one branch of one, named
after it.

## Where this model says more than the code
* Any number of requests, any `max_retries`.
* Whether an outcome is retryable is the port's free choice, so every
  policy, method and status is covered; a timeout always is.
* Any request may be cancelled, sync ones included. A `{retry, Key}` that
  finds its caller dead drops the request: a cancel in a backoff.
* The worker takes the port's terminal messages in any order, not FIFO,
  and each fired timer's message whenever.
* Timers fire whenever they are armed: backoffs and timeouts are any
  length.

## Where it says less
* Admission, port death and worker crash: `Admission` covers them; a retry
  adds no state that outlives the worker.
* Streams: `retry` with a streamed body or response is `bad_opts`.
* The worker's `ids` map (port id -> key), which `current/2` reads: a
  message names its request directly. Covered by the worker's tests.
* `katipo_retry:delay/5` (pure, unit-tested): its decision is the port's
  free choice of `retry`, and its delay a timer's free choice of when.

## Configuration
| knob         | meaning                                                   |
|--------------|-----------------------------------------------------------|
| `maxRetries` | the policy's `max_retries`                                |
| `fresh`      | each retry's transfer has a fresh port id (shipped)       |
| `matchTref`  | a timer message counts only if it is the entry's (shipped)|
| `cancels`    | the caller may cancel                                     |
-/

namespace KatipoProofs.Retry

/-- A transfer's port id: the request, and an attempt number. -/
structure Id where
  r : Nat
  n : Nat
  deriving DecidableEq, Repr

inductive Kind | req | retry
  deriving DecidableEq, Repr

/-- An `erlang:start_timer/3` timer: its request, kind and token. -/
structure Timer where
  r : Nat
  k : Kind
  tok : Nat
  deriving DecidableEq, Repr

inductive Mode | attempt | backoff
  deriving DecidableEq, Repr

/-- A request: not yet sent, held by the worker (in an attempt or a
backoff, with its current attempt's number and its timer's token), or
resolved. -/
inductive RS
  | new
  | held (m : Mode) (cur tref : Nat)
  | done
  | cancelled
  deriving DecidableEq, Repr

/-- Worker -> port commands. `n` is a ghost: the attempt number. -/
inductive Cmd
  | req (id : Id) (n : Nat)
  | cancel (id : Id)
  deriving DecidableEq, Repr

/-- A transfer the port runs; `n` is a ghost. -/
structure Xfer where
  id : Id
  n : Nat
  deriving DecidableEq, Repr

/-- A port -> worker terminal message; `n` is a ghost. -/
structure Out where
  id : Id
  n : Nat
  retry : Bool
  deriving DecidableEq, Repr

structure Params where
  maxRetries : Nat
  fresh : Bool
  matchTref : Bool
  cancels : Bool

/-- `KatipoRetry.tla` VARIABLES; `st`, `mode`, `cur` and `tref` are `rs`. -/
structure St where
  rs : Nat → RS
  toks : Nat → Nat
  armed : Timer → Bool
  fired : Timer → Bool
  pipe : List Cmd
  running : List Xfer
  out : List Out
  cancelQ : Nat → Bool
  cancelSent : Nat → Bool
  delivered : Nat → Nat
  sent : Nat → Nat
  stale : Bool
  spurious : Bool

def upd {α β : Type} [DecidableEq α] (f : α → β) (a : α) (v : β) : α → β :=
  fun x => if x = a then v else f x

@[simp] theorem upd_same {α β : Type} [DecidableEq α] (f : α → β) (a : α) (v : β) :
    upd f a v a = v := by simp [upd]

@[simp] theorem upd_other {α β : Type} [DecidableEq α] (f : α → β) (a x : α) (v : β)
    (h : x ≠ a) : upd f a v x = f x := by simp [upd, h]

/-- `Id(r, n)`: the port id of request `r`'s attempt `n`. -/
def pid (P : Params) (r n : Nat) : Id := if P.fresh then ⟨r, n⟩ else ⟨r, 0⟩

def init : St where
  rs := fun _ => .new
  toks := fun _ => 0
  armed := fun _ => false
  fired := fun _ => false
  pipe := []
  running := []
  out := []
  cancelQ := fun _ => false
  cancelSent := fun _ => false
  delivered := fun _ => 0
  sent := fun _ => 0
  stale := false
  spurious := false

/-- The armed timers once request `r`'s timer (token `tr`) is cancelled. -/
def cancelTimer (A : Timer → Bool) (r tr : Nat) : Timer → Bool :=
  fun t => if t.r = r ∧ t.tok = tr then false else A t

/-- `RetryOrResolve`, from armed timers `A`: back off and arm the retry
timer, or resolve and deliver. `cur` is the current attempt's number. -/
def retryOrResolve (P : Params) (s : St) (r cur : Nat) (retry : Bool)
    (A : Timer → Bool) : St :=
  if retry ∧ cur < P.maxRetries then
    { s with rs := upd s.rs r (.held .backoff cur (s.toks r + 1))
             toks := upd s.toks r (s.toks r + 1)
             armed := upd A ⟨r, .retry, s.toks r + 1⟩ true }
  else
    { s with rs := upd s.rs r .done
             delivered := upd s.delivered r (s.delivered r + 1)
             armed := A }

def tmatch (P : Params) (t : Timer) (tr : Nat) : Prop := P.matchTref = false ∨ t.tok = tr

inductive Step (P : Params) : St → St → Prop
  /-- `admit_call` + `register_req`: send the first transfer, arm the
  request timer. -/
  | admit (s : St) (r : Nat) : s.rs r = .new →
      Step P s { s with rs := upd s.rs r (.held .attempt 0 (s.toks r + 1))
                        toks := upd s.toks r (s.toks r + 1)
                        armed := upd s.armed ⟨r, .req, s.toks r + 1⟩ true
                        pipe := s.pipe ++ [.req (pid P r 0) 0]
                        sent := upd s.sent r 1 }
  /-- The port takes a request: it runs the transfer. -/
  | portReq (s : St) (id : Id) (n : Nat) (rest : List Cmd) : s.pipe = .req id n :: rest →
      Step P s { s with pipe := rest, running := s.running ++ [⟨id, n⟩] }
  /-- The port takes a cancel: `cancel_conn`, a no-op on an id it no longer
  runs. -/
  | portCancel (s : St) (id : Id) (rest : List Cmd) : s.pipe = .cancel id :: rest →
      Step P s { s with pipe := rest, running := s.running.filter (fun x => x.id ≠ id) }
  /-- curl ends a transfer, with an outcome the policy may or may not
  retry. -/
  | portEnd (s : St) (l1 l2 : List Xfer) (x : Xfer) (retry : Bool) :
      s.running = l1 ++ x :: l2 →
      Step P s { s with running := l1 ++ l2, out := s.out ++ [⟨x.id, x.n, retry⟩] }
  /-- A timer fires. -/
  | fire (s : St) (t : Timer) : s.armed t = true →
      Step P s { s with armed := upd s.armed t false, fired := upd s.fired t true }
  /-- `attempt_ended` on the current transfer: cancel the timer, then
  retry or resolve. -/
  | workerOutCur (s : St) (l1 l2 : List Out) (m : Out) (c tr : Nat) :
      s.out = l1 ++ m :: l2 → s.rs m.id.r = .held .attempt c tr → pid P m.id.r c = m.id →
      Step P s (retryOrResolve P { s with out := l1 ++ l2, stale := s.stale || m.n != c }
                  m.id.r c m.retry (cancelTimer s.armed m.id.r tr))
  /-- `attempt_ended` on any other transfer: dropped. -/
  | workerOutDrop (s : St) (l1 l2 : List Out) (m : Out) :
      s.out = l1 ++ m :: l2 →
      (∀ c tr, s.rs m.id.r = .held .attempt c tr → pid P m.id.r c ≠ m.id) →
      Step P s { s with out := l1 ++ l2 }
  /-- `req_timeout` matching the entry: abort, then retry or resolve with
  `operation_timedout`, which the policy retries. -/
  | reqTimeout (s : St) (t : Timer) (c tr : Nat) : s.fired t = true → t.k = .req →
      s.rs t.r = .held .attempt c tr → tmatch P t tr →
      Step P s (retryOrResolve P
                  { s with fired := upd s.fired t false
                           pipe := s.pipe ++ [.cancel (pid P t.r c)]
                           spurious := s.spurious || t.tok != tr }
                  t.r c true s.armed)
  /-- `req_timeout` matching nothing: dropped. -/
  | reqTimeoutDrop (s : St) (t : Timer) : s.fired t = true → t.k = .req →
      (∀ c tr, s.rs t.r = .held .attempt c tr → ¬ tmatch P t tr) →
      Step P s { s with fired := upd s.fired t false }
  /-- `{retry, Key}` matching the entry: send again, arm a new request
  timer. -/
  | retry (s : St) (t : Timer) (c tr : Nat) : s.fired t = true → t.k = .retry →
      s.rs t.r = .held .backoff c tr → tmatch P t tr →
      Step P s { s with fired := upd s.fired t false
                        rs := upd s.rs t.r (.held .attempt (c + 1) (s.toks t.r + 1))
                        toks := upd s.toks t.r (s.toks t.r + 1)
                        armed := upd s.armed ⟨t.r, .req, s.toks t.r + 1⟩ true
                        pipe := s.pipe ++ [.req (pid P t.r (c + 1)) (c + 1)]
                        sent := upd s.sent t.r (s.sent t.r + 1) }
  /-- `{retry, Key}` matching nothing: dropped. -/
  | retryDrop (s : St) (t : Timer) : s.fired t = true → t.k = .retry →
      (∀ c tr, s.rs t.r = .held .backoff c tr → ¬ tmatch P t tr) →
      Step P s { s with fired := upd s.fired t false }
  /-- The caller cancels, once. -/
  | callerCancel (s : St) (r : Nat) (m : Mode) (c tr : Nat) : P.cancels = true →
      s.rs r = .held m c tr → s.cancelSent r = false →
      Step P s { s with cancelSent := upd s.cancelSent r true,
                        cancelQ := upd s.cancelQ r true }
  /-- `{cancel, Ref}` on a held request: cancel the timer, abort the
  current transfer (none in a backoff), remove. -/
  | workerCancel (s : St) (r : Nat) (m : Mode) (c tr : Nat) : s.cancelQ r = true →
      s.rs r = .held m c tr →
      Step P s { s with cancelQ := upd s.cancelQ r false
                        rs := upd s.rs r .cancelled
                        armed := cancelTimer s.armed r tr
                        pipe := if m = .attempt then s.pipe ++ [.cancel (pid P r c)]
                                else s.pipe }
  /-- `{cancel, Ref}` on anything else: dropped. -/
  | workerCancelDrop (s : St) (r : Nat) : s.cancelQ r = true →
      (∀ m c tr, s.rs r ≠ .held m c tr) →
      Step P s { s with cancelQ := upd s.cancelQ r false }

inductive Reach (P : Params) : St → Prop
  | init : Reach P init
  | step {s t : St} : Reach P s → Step P s t → Reach P t

/-- Whether `id` is its request's current transfer: held in an attempt
whose number `id` carries (the shipped, fresh ids). -/
def isCur (s : St) (id : Id) : Prop := ∃ tr, s.rs id.r = .held .attempt id.n tr

/-- A cancel for `id` is queued in `q`. -/
def cancels (id : Id) (q : List Cmd) : Nat := q.countP (· == .cancel id)

/-- Whether transfer `x` is its request's current attempt, by its ghost
attempt number. -/
def runsCur (s : St) (x : Xfer) : Prop := ∃ tr, s.rs x.id.r = .held .attempt x.n tr

/-- `NoOrphan`: every transfer the port runs is its request's current
attempt, or has an abort on its way. -/
def NoOrphan (s : St) : Prop := ∀ x ∈ s.running, runsCur s x ∨ 0 < cancels x.id s.pipe

end KatipoProofs.Retry
