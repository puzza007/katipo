/-!
# Async admission and delivery: transcription of `formal/KatipoFixed.tla`

The caller -> `katipo_worker` path for async requests, for an arbitrary type
of request identities `R` (any number of requests), with unboundedly many
worker crashes and restarts.

Each `Step` constructor is one TLA+ action or one branch of it:

| constructor        | TLA+ action                      | code                                   |
|--------------------|----------------------------------|----------------------------------------|
| `sendLive/Dead`    | `SendAsync`                      | `katipo:dispatch_async` / `pool_call`  |
| `expire`           | `Expire`                         | wall clock passes the stamped deadline |
| `callerTimeout`    | `CallerTimeout`                  | `katipo:attempt/3` -> admission_timeout|
| `sendCancel`       | `SendCancel`                     | `katipo:cancel/2`                      |
| `recvReqExpired`   | `WorkerRecvReq`, pre-check       | `admit_call`, first `past/1`           |
| `recvReq`          | `WorkerRecvReq`, `send_to_port`  | `admit_call` -> `send_to_port/3`       |
| `checkRefuse/Pass` | `WorkerAdmitCheck`               | `admit_call`, second `past/1`          |
| `admitReply`       | `WorkerAdmitReply`               | `register_req/4` + reply alias         |
| `recvCancel`       | `WorkerRecvCancel`               | `handle_info({cancel, Ref})`           |
| `recvResp`         | `WorkerRecvResp`/`RecvTimeout`   | `finish_req/4`, `req_timeout` clause   |
| `recvChunk`        | `WorkerRecvChunk`                | `forward_progress/3`                   |
| `crash`            | `WorkerRecvExit`, badarg branch  | `terminate/2` + call monitors          |
| `kill`             | (none)                           | `exit(Worker, kill)`: no `terminate/2` |
| `restart`          | `WorkerRestart`                  | supervisor                             |
| `emit`             | `PortComplete`/`PortEmitChunk`/`TimerFire` | C port, request timer        |

## Where this model says more than the code
* The C port and the request timers are replaced by an environment that
  may put a response/timeout (`resp r`) or a chunk (`chunk r`) for ANY
  request into the worker's mailbox at ANY time. The worker only acts on
  them for requests in `Reqs`, which is what makes this sound -- and it
  deletes the port queue, `conns` and the timer bookkeeping from the proof.
  A timeout and a response are handled identically by the worker (deliver
  iff in `Reqs`, remove), so they share one message kind.
* The worker may crash at any time, including mid-admission (the code can
  only crash on the `send_to_port` badarg or on port exit). `WorkerRecvExit`
  is therefore just `crash`, and port deaths are unbounded.
* The worker may also be killed outright (`kill`), skipping `terminate/2`:
  admitted requests are then never told. Not in the TLA+ spec.
* The worker takes its next message from anywhere in its mailbox
  (`pre ++ m :: rest`), not only the head. Erlang orders messages per
  sender pair only; this drops even that assumption.

## Where it says less
* No port queue, so `NoOrphanTransfer` (every running C transfer is owned)
  and `EventualOutcome` (liveness) stay TLC-only.
* `cancelPollution` is constantly `FALSE` in the fixed spec and is omitted.

## Telemetry (Lean only)
`spans` and `metrics` count, per request, the `katipo_span` calls that end
its OpenTelemetry span and record its request metrics. They are pure
observers (no step reads them), so they add no behaviours to the TLA+
spec. The call sites:
* `finish_async/4` (span end + metrics) on every terminal outcome: the
  caller's `dispatch_async` on an admission error, the worker's
  `deliver/4` and `deliver_error/3`, and `terminate/2` via
  `notify_worker_died/2`. Hence `resolve` bumps all three counters.
* `end_async/1` (span end only) on an effective cancel.

## Configuration
`callerTimeouts`, `deadline` and `slack` are the TLA+ constants
`CallerTimeouts`, `DeadlineCheck` and `ReplyWithinSlack`. The shipped code
is `callerTimeouts = deadline = true`; `slack` is the timing assumption.
-/

namespace KatipoProofs.Admission

inductive WMsg (R : Type) where
  | req (r : R)
  | cancel (r : R)
  | resp (r : R)
  | chunk (r : R)
  deriving DecidableEq, Repr

/-- Where the worker is inside `admit_call` (`admitPhase`, `admitRef`). -/
inductive Phase (R : Type) where
  | idle
  | sent (r : R)
  | checked (r : R)
  deriving DecidableEq, Repr

structure Params where
  callerTimeouts : Bool
  deadline : Bool
  slack : Bool

structure St (R : Type) where
  wAlive : Bool
  wQ : List (WMsg R)
  reqs : R → Bool
  sent : R → Bool
  pending : R → Bool
  accepted : R → Bool
  gaveUp : R → Bool
  expired : R → Bool
  cancelled : R → Bool
  effCancel : R → Bool
  delivered : R → Nat
  spans : R → Nat
  metrics : R → Nat
  snap : R → Nat
  phase : Phase R
  progressStop : Bool

variable {R : Type} [DecidableEq R]

/-- Point update of a map. -/
def upd {α : Type} (f : R → α) (r : R) (v : α) : R → α :=
  fun x => if x = r then v else f x

@[simp] theorem upd_same {α : Type} (f : R → α) (r : R) (v : α) : upd f r v r = v := by
  simp [upd]
@[simp] theorem upd_other {α : Type} (f : R → α) (r x : R) (v : α) (h : x ≠ r) :
    upd f r v x = f x := by
  simp [upd, h]

def init : St R where
  wAlive := true
  wQ := []
  reqs := fun _ => false
  sent := fun _ => false
  pending := fun _ => false
  accepted := fun _ => false
  gaveUp := fun _ => false
  expired := fun _ => false
  cancelled := fun _ => false
  effCancel := fun _ => false
  delivered := fun _ => 0
  spans := fun _ => 0
  metrics := fun _ => 0
  snap := fun _ => 0
  phase := .idle
  progressStop := false

/-- `k` terminal outcomes for `r` (`k ≤ 1`): the caller sees each one, and
the code path producing it calls `katipo_span:finish_async/4`. -/
def resolve (s : St R) (r : R) (k : Nat) : St R :=
  { s with delivered := upd s.delivered r (s.delivered r + k)
           spans := upd s.spans r (s.spans r + k)
           metrics := upd s.metrics r (s.metrics r + k) }

/-- `ReplyExpired`: the worker answers `expired`; terminal iff the caller
still waits. -/
def replyExpired (s : St R) (r : R) : St R :=
  { resolve s r (s.pending r).toNat with pending := upd s.pending r false }

/-- `Crash`: `terminate/2` messages every `Reqs` entry, and every waiting
caller's monitor fires. -/
def crash (s : St R) : St R :=
  { s with wAlive := false, wQ := [], reqs := fun _ => false,
           pending := fun _ => false, phase := .idle,
           delivered := fun x => s.delivered x + (s.reqs x || s.pending x).toNat,
           spans := fun x => s.spans x + (s.reqs x || s.pending x).toNat,
           metrics := fun x => s.metrics x + (s.reqs x || s.pending x).toNat }

/-- `Kill`: the worker dies without running `terminate/2` (`exit(Pid, kill)`),
so no `Reqs` entry is told; only waiting callers learn of it, through their
call monitors. -/
def kill (s : St R) : St R :=
  { s with wAlive := false, wQ := [], reqs := fun _ => false,
           pending := fun _ => false, phase := .idle,
           delivered := fun x => s.delivered x + (s.pending x).toNat,
           spans := fun x => s.spans x + (s.pending x).toNat,
           metrics := fun x => s.metrics x + (s.pending x).toNat }

/-- The worker is mid-admission of `r`. -/
def admitting (s : St R) (r : R) : Prop := s.phase = .sent r ∨ s.phase = .checked r

inductive Step (P : Params) : St R → St R → Prop
  | sendLive (s : St R) (r : R) : s.sent r = false → s.wAlive = true →
      Step P s { s with wQ := s.wQ ++ [.req r], sent := upd s.sent r true,
                        pending := upd s.pending r true }
  | sendDead (s : St R) (r : R) : s.sent r = false → s.wAlive = false →
      Step P s { resolve s r 1 with sent := upd s.sent r true }
  | expire (s : St R) (r : R) : (P.callerTimeouts || P.deadline) = true →
      s.pending r = true → s.expired r = false →
      Step P s { s with expired := upd s.expired r true }
  | callerTimeout (s : St R) (r : R) : P.callerTimeouts = true →
      s.pending r = true → s.expired r = true →
      (P.slack = true → s.phase ≠ .checked r) →
      Step P s { resolve s r 1 with pending := upd s.pending r false,
                                    gaveUp := upd s.gaveUp r true }
  | sendCancel (s : St R) (r : R) : s.accepted r = true → s.cancelled r = false →
      Step P s { s with cancelled := upd s.cancelled r true,
                        wQ := if s.wAlive then s.wQ ++ [.cancel r] else s.wQ }
  | recvReqExpired (s : St R) (r : R) (pre rest : List (WMsg R)) : s.wAlive = true →
      s.phase = .idle → s.wQ = pre ++ .req r :: rest →
      (P.deadline && s.expired r) = true →
      Step P s { replyExpired s r with wQ := pre ++ rest }
  | recvReq (s : St R) (r : R) (pre rest : List (WMsg R)) : s.wAlive = true →
      s.phase = .idle → s.wQ = pre ++ .req r :: rest →
      (P.deadline && s.expired r) = false →
      Step P s { s with wQ := pre ++ rest, phase := .sent r }
  | checkRefuse (s : St R) (r : R) : s.wAlive = true → s.phase = .sent r →
      (P.deadline && s.expired r) = true →
      Step P s { replyExpired s r with phase := .idle }
  | checkPass (s : St R) (r : R) : s.wAlive = true → s.phase = .sent r →
      (P.deadline && s.expired r) = false →
      Step P s { s with phase := .checked r }
  | admitReply (s : St R) (r : R) : s.wAlive = true → s.phase = .checked r →
      Step P s { s with reqs := upd s.reqs r true, pending := upd s.pending r false,
                        accepted := upd s.accepted r (s.accepted r || s.pending r),
                        phase := .idle }
  | recvCancel (s : St R) (r : R) (pre rest : List (WMsg R)) : s.wAlive = true →
      s.phase = .idle → s.wQ = pre ++ .cancel r :: rest →
      Step P s (if s.reqs r then
          { s with wQ := pre ++ rest, reqs := upd s.reqs r false,
                   effCancel := upd s.effCancel r true,
                   snap := upd s.snap r (s.delivered r),
                   spans := upd s.spans r (s.spans r + 1) }
        else { s with wQ := pre ++ rest })
  | recvResp (s : St R) (r : R) (pre rest : List (WMsg R)) : s.wAlive = true →
      s.phase = .idle → s.wQ = pre ++ .resp r :: rest →
      Step P s (if s.reqs r then
          { resolve s r 1 with wQ := pre ++ rest, reqs := upd s.reqs r false }
        else { s with wQ := pre ++ rest })
  | recvChunk (s : St R) (r : R) (pre rest : List (WMsg R)) : s.wAlive = true →
      s.phase = .idle → s.wQ = pre ++ .chunk r :: rest →
      Step P s { s with wQ := pre ++ rest,
                        progressStop := s.progressStop ||
                          (s.reqs r && (s.effCancel r || decide (0 < s.delivered r))) }
  | crash (s : St R) : s.wAlive = true → Step P s (crash s)
  | kill (s : St R) : s.wAlive = true → Step P s (kill s)
  | restart (s : St R) : s.wAlive = false → Step P s { s with wAlive := true, wQ := [] }
  | emitResp (s : St R) (r : R) : s.wAlive = true →
      Step P s { s with wQ := s.wQ ++ [.resp r] }
  | emitChunk (s : St R) (r : R) : s.wAlive = true →
      Step P s { s with wQ := s.wQ ++ [.chunk r] }

inductive Reach (P : Params) : St R → Prop
  | init : Reach P init
  | step {s t : St R} : Reach P s → Step P s t → Reach P t

/-- The shipped protocol, or the pre-#185 one whose caller never gave up. -/
def Safe (P : Params) : Prop :=
  P.callerTimeouts = false ∨ (P.deadline = true ∧ P.slack = true)

end KatipoProofs.Admission
