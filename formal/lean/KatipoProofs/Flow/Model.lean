/-!
# Streaming flow control: transcription of `formal/KatipoFlow.tla`

One async streaming request with `stream_window => W`: the C transfer
(`c_src/katipo.c`: `write_cb`, `flow_conn`, `check_multi_info`,
`cancel_conn`), the `katipo_worker` relay (`forward_progress`, `finish_req`,
the `{flow, Ref, N}` / `{cancel, Ref}` / `req_timeout` clauses) and a
consumer that grants back consumed credits through `katipo:update_flow/3`
once `batch` of them are owed.

Each `Step` constructor is one TLA+ action (or one branch of one), named
after it. `EventWrite` and `SyncWrite` differ only in a guard on
`unpausing`, so their union is the unguarded `write*` pair here.

## Where this model says more than the code
* libcurl may call `write_cb` any number of times inside
  `curl_easy_pause(CONT)` (the `write*` steps are enabled while
  `unpausing`).
* The request timer, a consumer cancel and a curl failure may happen at any
  time they are enabled (`P.timeouts`, `P.cancels`, `P.failures`).
* The worker's one mailbox is split into per-sender FIFO queues read in any
  order, which is exactly Erlang's guarantee.

* With `P.deaths`, the C port may die at any moment, even inside
  `curl_easy_pause`. The worker reads the port's `'EXIT'` after everything
  the port sent before it (`exitQ`), then stops; `terminate/2` sends
  `worker_died` (an `error`) if it still held the request.

## Where it says less
* Admission is `KatipoFixed.tla`'s business, and so is an outright kill of
  the worker (`KatipoFlowKill.cfg` shows the consumer then waits forever).
* Unbounded windows (`window = -1` in C) never pause: they are the
  `W > total` case.
* `cancelQ` holds at most one message (a consumer cancels once), so it is a
  `Bool`.
* A cancel command in the worker -> port queue is the grant `0`; real grants
  are always positive (`batch_pos`).

## Configuration
| knob         | meaning                                           |
|--------------|---------------------------------------------------|
| `W`          | `stream_window` (validated `> 0`)                  |
| `total`      | body chunks the server sends                      |
| `batch`      | consumer grants once this many credits are owed   |
| `deaths`     | the C port may die mid-transfer                   |
| `clearFirst` | `flow_conn` clears `paused` before `curl_easy_pause` (shipped: `true`) |
-/

namespace KatipoProofs.Flow

/-- Port -> worker -> consumer message kinds. -/
inductive Msg | headers | chunk | done | error
  deriving DecidableEq, Repr

structure Params where
  W : Nat
  total : Nat
  batch : Nat
  timeouts : Bool
  cancels : Bool
  failures : Bool
  deaths : Bool
  clearFirst : Bool
  W_pos : 0 < W
  batch_pos : 0 < batch

/-- `KatipoFlow.tla` VARIABLES, one field each. -/
structure St where
  window : Nat
  paused : Bool
  curlPaused : Bool
  unpausing : Bool
  remaining : Nat
  headersSent : Bool
  live : Bool
  toW : List Msg
  pQ : List Nat
  inReqs : Bool
  flowQ : List Nat
  cancelQ : Bool
  toC : List Msg
  owed : Nat
  seenHeaders : Bool
  chunksSeen : Nat
  seenDone : Bool
  seenError : Bool
  orderBad : Bool
  cancelled : Bool
  pAlive : Bool
  wAlive : Bool
  exitQ : Bool
  deriving DecidableEq, Repr

/-- `Init`. -/
def init (P : Params) : St where
  window := P.W
  paused := false
  curlPaused := false
  unpausing := false
  remaining := P.total
  headersSent := false
  live := true
  toW := []
  pQ := []
  inReqs := true
  flowQ := []
  cancelQ := false
  toC := []
  owed := 0
  seenHeaders := false
  chunksSeen := 0
  seenDone := false
  seenError := false
  orderBad := false
  cancelled := false
  pAlive := true
  wAlive := true
  exitQ := false

/-- `HeadersIfOwed`. -/
def hdrs (s : St) : List Msg := if s.headersSent then [] else [.headers]

/-- `Terminal`. -/
def terminal (s : St) : Bool := s.seenDone || s.seenError

/-- `ConsumerRecv`'s update for message `m` with `rest` left in `toC`. -/
def recv (s : St) (m : Msg) (rest : List Msg) : St :=
  { s with
    toC := rest
    orderBad := s.orderBad || terminal s
      || (m == .headers && s.seenHeaders)
      || ((m == .chunk || m == .done) && !s.seenHeaders)
    seenHeaders := s.seenHeaders || m == .headers
    chunksSeen := if m = .chunk then s.chunksSeen + 1 else s.chunksSeen
    owed := if m = .chunk then s.owed + 1 else s.owed
    seenDone := s.seenDone || m == .done
    seenError := s.seenError || m == .error }

inductive Step (P : Params) : St → St → Prop
  /-- `write_cb` out of credits: pause, curl keeps the data. -/
  | writePause (s : St) : s.live = true → s.curlPaused = false →
      0 < s.remaining → s.window = 0 →
      Step P s { s with paused := true, curlPaused := true }
  /-- `write_cb` with a credit: headers (once) and a chunk. -/
  | writeChunk (s : St) : s.live = true → s.curlPaused = false →
      0 < s.remaining → s.window ≠ 0 →
      Step P s { s with toW := s.toW ++ hdrs s ++ [.chunk], headersSent := true,
                        window := s.window - 1, remaining := s.remaining - 1 }
  /-- `flow_conn` on a freed conn (`find_conn` returns NULL). -/
  | flowDead (s : St) (n : Nat) (rest : List Nat) : s.unpausing = false →
      s.pQ = n :: rest → n ≠ 0 → s.live = false → s.pAlive = true →
      Step P s { s with pQ := rest }
  /-- `flow_conn` on a running transfer. -/
  | flowRun (s : St) (n : Nat) (rest : List Nat) : s.unpausing = false →
      s.pQ = n :: rest → n ≠ 0 → s.live = true → s.paused = false → s.pAlive = true →
      Step P s { s with pQ := rest, window := s.window + n }
  /-- `flow_conn` on a paused transfer, up to `curl_easy_pause(CONT)`. -/
  | flowUnpause (s : St) (n : Nat) (rest : List Nat) : s.unpausing = false →
      s.pQ = n :: rest → n ≠ 0 → s.live = true → s.paused = true → s.pAlive = true →
      Step P s { s with pQ := rest, window := s.window + n, curlPaused := false,
                        unpausing := true,
                        paused := if P.clearFirst then false else s.paused }
  /-- `curl_easy_pause` returns. -/
  | unpauseReturn (s : St) : s.unpausing = true →
      Step P s { s with unpausing := false,
                        paused := if P.clearFirst then s.paused else false }
  /-- `check_multi_info`, `CURLE_OK`. -/
  | complete (s : St) : s.live = true → s.unpausing = false → s.remaining = 0 →
      s.curlPaused = false →
      Step P s { s with toW := s.toW ++ hdrs s ++ [.done], headersSent := true,
                        live := false }
  /-- `check_multi_info`, curl error. -/
  | fail (s : St) : P.failures = true → s.live = true → s.unpausing = false →
      Step P s { s with toW := s.toW ++ [.error], live := false }
  /-- `cancel_conn`. -/
  | portCancel (s : St) (rest : List Nat) : s.unpausing = false →
      s.pQ = 0 :: rest → s.pAlive = true →
      Step P s { s with pQ := rest, live := false }
  /-- Worker: port message for a request still in `Reqs`. -/
  | workerFwd (s : St) (m : Msg) (rest : List Msg) : s.toW = m :: rest →
      s.inReqs = true → s.wAlive = true →
      Step P s { s with toW := rest, toC := s.toC ++ [m],
                        inReqs := (m == .headers || m == .chunk) }
  /-- Worker: port message for a request no longer in `Reqs`: dropped. -/
  | workerDrop (s : St) (m : Msg) (rest : List Msg) : s.toW = m :: rest →
      s.inReqs = false → s.wAlive = true →
      Step P s { s with toW := rest }
  /-- Worker: `{flow, Ref, N}`, forwarded iff in `Reqs`. -/
  | workerFlow (s : St) (n : Nat) (rest : List Nat) : s.flowQ = n :: rest →
      s.wAlive = true →
      Step P s { s with flowQ := rest, pQ := if s.inReqs then s.pQ ++ [n] else s.pQ }
  /-- Worker: `{cancel, Ref}`. -/
  | workerCancel (s : St) : s.cancelQ = true → s.wAlive = true →
      Step P s { s with cancelQ := false, inReqs := false,
                        pQ := if s.inReqs then s.pQ ++ [0] else s.pQ }
  /-- Worker: `req_timeout`. -/
  | workerTimeout (s : St) : P.timeouts = true → s.inReqs = true → s.wAlive = true →
      Step P s { s with inReqs := false, toC := s.toC ++ [.error],
                        pQ := s.pQ ++ [0] }
  /-- `PortDies`: the port process exits; its conn and pipe are gone. -/
  | portDies (s : St) : P.deaths = true → s.pAlive = true →
      Step P s { s with pAlive := false, live := false, exitQ := true, unpausing := false,
                        paused := false, curlPaused := false }
  /-- `WorkerExit`: the worker reads the `'EXIT'`, stops, and `terminate/2`
  sends `worker_died` if it still held the request. -/
  | workerExit (s : St) : s.wAlive = true → s.exitQ = true → s.toW = [] →
      Step P s { s with wAlive := false, exitQ := false, inReqs := false,
                        toC := if s.inReqs then s.toC ++ [.error] else s.toC }
  | consumerRecv (s : St) (m : Msg) (rest : List Msg) : s.toC = m :: rest →
      Step P s (recv s m rest)
  | consumerGrant (s : St) : P.batch ≤ s.owed → terminal s = false →
      Step P s { s with flowQ := s.flowQ ++ [s.owed], owed := 0 }
  | consumerCancel (s : St) : P.cancels = true → terminal s = false →
      s.cancelled = false →
      Step P s { s with cancelQ := true, cancelled := true }

inductive Reach (P : Params) : St → Prop
  | init : Reach P (init P)
  | step {s t : St} : Reach P s → Step P s t → Reach P t

/-- Occurrences of `x` in a list (`CountIn`). -/
def cnt (x : Msg) : List Msg → Nat
  | [] => 0
  | m :: ms => (if m = x then 1 else 0) + cnt x ms

/-- `SumNat`. -/
def sum : List Nat → Nat
  | [] => 0
  | n :: ns => n + sum ns

/-- `Outstanding`: chunks emitted and not yet granted back. -/
def outstanding (s : St) : Nat := cnt .chunk s.toW + cnt .chunk s.toC + s.owed

/-- Every credit, wherever it currently is. -/
def credits (s : St) : Nat := s.window + outstanding s + sum s.flowQ + sum s.pQ

/-- A good place to stop: the consumer has its terminal message, or it
cancelled (after which no message is owed). -/
def Good (s : St) : Prop := s.seenDone = true ∨ s.seenError = true ∨ s.cancelled = true

/-- No step is enabled. -/
def Stuck (P : Params) (s : St) : Prop := ∀ t, ¬ Step P s t

end KatipoProofs.Flow
