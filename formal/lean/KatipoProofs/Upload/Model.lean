/-!
# Streaming request bodies: transcription of `formal/KatipoUpload.tla`

One async request whose body is streamed by the caller (`body => {stream,
_}`), with a streamed response under a bounded `stream_window`, so the
upload's pause and the response's pause share one curl easy handle: the C
transfer (`c_src/katipo.c`: `read_stream_cb`, `body_conn`, `write_cb`,
`flow_conn`, `complete_conn`, `cancel_conn`), the `katipo_worker` relay and
a caller that answers each demand with `katipo:send_body/3` and grants back
each response chunk. With `P.liar` the caller may also send the wrong
amount: a chunk past `total`, eof short of it, or a chunk after its eof.

Each `Step` constructor is one TLA+ action, or one branch of one, named
after it.

## Where this model says more than the code
* curl may call `read_stream_cb` or `write_cb` whenever that direction is not
  paused, inside `curl_easy_pause` or from the event loop (waiting for a
  writable socket is only a delay).
* With `P.early` the response may run, and complete, while the body is
  still being sent.
* The request timer, a caller cancel and a curl failure may happen at any
  time they are enabled.
* The worker's one mailbox is per-sender FIFO queues read in any order.

## Where it says less
* Port death and worker kill: `Flow` covers them for this request shape.
* `cancelQ` holds at most one message (a caller cancels once): a `Bool`.
* Chunks are indistinguishable and every queue is FIFO, so counting them
  is enough to state that none is lost, duplicated or reordered.
* A chunk is one unit, read whole: with a declared length, `total` chunks
  are the length.

## Configuration
| knob     | meaning                                                      |
|----------|--------------------------------------------------------------|
| `total`  | body chunks the caller sends before eof                      |
| `W`      | the response's `stream_window` (validated `> 0`)             |
| `resp`   | response chunks the server sends                             |
| `length` | `total` chunks declared as the Content-Length; else chunked  |
| `masked` | resume one direction only (shipped: `true`); else `CONT`     |
| `guard`  | at most one demand outstanding (shipped: `true`)             |
| `eager`  | the caller may send without a demand                         |
| `liar`   | the caller may send the wrong amount                         |
| `early`  | the response may run while the body is being sent            |

The demand goes out only when curl finds the buffer empty, as shipped;
the spec's `EarlyDemand` alternative is not transcribed.
-/

namespace KatipoProofs.Upload

/-- Port -> worker -> caller messages. -/
inductive Msg | demand | chunk | done | error
  deriving DecidableEq, Repr

/-- Caller -> worker body messages (`send_body/3`). -/
inductive Body | data | eof
  deriving DecidableEq, Repr

/-- Worker -> port commands. -/
inductive Cmd | body (b : Body) | flow (n : Nat) | cancel
  deriving DecidableEq, Repr

structure Params where
  total : Nat
  W : Nat
  resp : Nat
  length : Bool
  masked : Bool
  guard : Bool
  eager : Bool
  liar : Bool
  early : Bool
  timeouts : Bool
  cancels : Bool
  failures : Bool
  W_pos : 0 < W

/-- `KatipoUpload.tla` VARIABLES, one field each. -/
structure St where
  live : Bool
  buf : Nat
  eofIn : Bool
  upFailed : Bool
  demanded : Bool
  upPaused : Bool
  curlSendPaused : Bool
  paused : Bool
  curlRecvPaused : Bool
  unpausing : Bool
  readN : Nat
  uploadDone : Bool
  window : Nat
  respLeft : Nat
  toW : List Msg
  pQ : List Cmd
  inReqs : Bool
  bodyQ : List Body
  flowQ : List Nat
  cancelQ : Bool
  toC : List Msg
  sentN : Nat
  sentEof : Bool
  lateN : Nat
  pending : Nat
  owed : Nat
  seenChunks : Nat
  seenDone : Bool
  seenError : Bool
  orderBad : Bool
  cancelled : Bool
  deriving DecidableEq, Repr

/-- `Init`. -/
def init (P : Params) : St where
  live := true
  buf := 0
  eofIn := false
  upFailed := false
  demanded := false
  upPaused := false
  curlSendPaused := false
  paused := false
  curlRecvPaused := false
  unpausing := false
  readN := 0
  uploadDone := P.length && P.total == 0
  window := P.W
  respLeft := P.resp
  toW := []
  pQ := []
  inReqs := true
  bodyQ := []
  flowQ := []
  cancelQ := false
  toC := []
  sentN := 0
  sentEof := false
  lateN := 0
  pending := 0
  owed := 0
  seenChunks := 0
  seenDone := false
  seenError := false
  orderBad := false
  cancelled := false

/-- `Terminal`. -/
def terminal (s : St) : Bool := s.seenDone || s.seenError

/-- `CallerRecv`'s update for message `m` with `rest` left in `toC`. -/
def recv (s : St) (m : Msg) (rest : List Msg) : St :=
  { s with
    toC := rest
    orderBad := s.orderBad || terminal s
    pending := if m = .demand then s.pending + 1 else s.pending
    owed := if m = .chunk then s.owed + 1 else s.owed
    seenChunks := if m = .chunk then s.seenChunks + 1 else s.seenChunks
    seenDone := s.seenDone || m == .done
    seenError := s.seenError || m == .error }

/-- `Demand`: finding the buffer empty, `read_stream_cb` asks for more while
more is wanted (no eof, the declared length not all in) and, with the
guard, none is outstanding. -/
def demandOk (P : Params) (s : St) : Bool :=
  !s.eofIn && !(P.length && s.readN + s.buf == P.total) && !(s.demanded && P.guard)

/-- `body_conn`'s length check: a chunk past the declared length, or eof
short of it. -/
def wrong (P : Params) (s : St) (b : Body) : Bool :=
  P.length && (if b = .data then s.readN + s.buf == P.total else decide (s.readN + s.buf < P.total))

/-- `body_conn` on a live conn with neither eof nor a failure, before any
resume: buffer the chunk or eof, or fail the upload if it is the wrong
length, and clear the outstanding demand. -/
def accept (P : Params) (s : St) (b : Body) (rest : List Cmd) : St :=
  { s with pQ := rest
           buf := if b = .data && !wrong P s b then s.buf + 1 else s.buf
           eofIn := s.eofIn || b == .eof
           upFailed := wrong P s b
           demanded := false }

inductive Step (P : Params) : St → St → Prop
  /-- `read_stream_cb` on a failed upload: abort, and curl fails the transfer. -/
  | readFail (s : St) : s.live = true → s.curlSendPaused = false →
      s.uploadDone = false → s.upFailed = true →
      Step P s { s with toW := s.toW ++ [.error], live := false }
  /-- `read_stream_cb` with a chunk buffered: with a declared length, the
  last one completes the body. -/
  | readData (s : St) : s.live = true → s.curlSendPaused = false →
      s.uploadDone = false → s.upFailed = false → 0 < s.buf →
      Step P s { s with buf := s.buf - 1, readN := s.readN + 1,
                        uploadDone := P.length && s.readN + 1 == P.total }
  /-- `read_stream_cb` at eof: the body is complete. -/
  | readEof (s : St) : s.live = true → s.curlSendPaused = false →
      s.uploadDone = false → s.upFailed = false → s.buf = 0 → s.eofIn = true →
      Step P s { s with uploadDone := true }
  /-- `read_stream_cb` with nothing buffered: demand and pause. -/
  | readDemand (s : St) : s.live = true → s.curlSendPaused = false →
      s.uploadDone = false → s.upFailed = false → s.buf = 0 → s.eofIn = false →
      Step P s { s with toW := if demandOk P s then s.toW ++ [.demand] else s.toW,
                        demanded := s.demanded || demandOk P s,
                        upPaused := true, curlSendPaused := true }
  /-- `write_cb` out of credits. -/
  | writePause (s : St) : s.live = true → s.curlRecvPaused = false →
      0 < s.respLeft → (P.early || s.uploadDone) = true → s.window = 0 →
      Step P s { s with paused := true, curlRecvPaused := true }
  /-- `write_cb` with a credit. -/
  | writeChunk (s : St) : s.live = true → s.curlRecvPaused = false →
      0 < s.respLeft → (P.early || s.uploadDone) = true → s.window ≠ 0 →
      Step P s { s with toW := s.toW ++ [.chunk], window := s.window - 1,
                        respLeft := s.respLeft - 1 }
  /-- `body_conn` on a freed conn: dropped. -/
  | bodyDead (s : St) (b : Body) (rest : List Cmd) : s.unpausing = false →
      s.pQ = .body b :: rest → s.live = false →
      Step P s { s with pQ := rest }
  /-- `body_conn` after eof or a failure: ignored. -/
  | bodyIgnored (s : St) (b : Body) (rest : List Cmd) : s.unpausing = false →
      s.pQ = .body b :: rest → s.live = true → (s.eofIn || s.upFailed) = true →
      Step P s { s with pQ := rest }
  /-- `body_conn` while the upload is not paused. -/
  | bodyRun (s : St) (b : Body) (rest : List Cmd) : s.unpausing = false →
      s.pQ = .body b :: rest → s.live = true → s.eofIn = false → s.upFailed = false →
      s.upPaused = false →
      Step P s (accept P s b rest)
  /-- `body_conn` on a paused upload, up to its `curl_easy_pause`. -/
  | bodyResume (s : St) (b : Body) (rest : List Cmd) : s.unpausing = false →
      s.pQ = .body b :: rest → s.live = true → s.eofIn = false → s.upFailed = false →
      s.upPaused = true →
      Step P s { accept P s b rest with
                 upPaused := false, curlSendPaused := false,
                 curlRecvPaused := if P.masked then s.curlRecvPaused else false,
                 unpausing := true }
  /-- `flow_conn` on a freed conn. -/
  | flowDead (s : St) (n : Nat) (rest : List Cmd) : s.unpausing = false →
      s.pQ = .flow n :: rest → s.live = false →
      Step P s { s with pQ := rest }
  /-- `flow_conn` on a running response. -/
  | flowRun (s : St) (n : Nat) (rest : List Cmd) : s.unpausing = false →
      s.pQ = .flow n :: rest → s.live = true → s.paused = false →
      Step P s { s with pQ := rest, window := s.window + n }
  /-- `flow_conn` on a paused response, up to its `curl_easy_pause`. -/
  | flowResume (s : St) (n : Nat) (rest : List Cmd) : s.unpausing = false →
      s.pQ = .flow n :: rest → s.live = true → s.paused = true →
      Step P s { s with pQ := rest, window := s.window + n,
                        paused := false, curlRecvPaused := false,
                        curlSendPaused := if P.masked then s.curlSendPaused else false,
                        unpausing := true }
  /-- `curl_easy_pause` returns. -/
  | unpauseReturn (s : St) : s.unpausing = true →
      Step P s { s with unpausing := false }
  /-- `complete_conn`, `CURLE_OK`: a failed upload is still an error. -/
  | complete (s : St) : s.live = true → s.unpausing = false → s.respLeft = 0 →
      (s.uploadDone || P.early) = true →
      Step P s { s with toW := s.toW ++ [if s.upFailed then .error else .done], live := false }
  /-- `complete_conn`, curl error. -/
  | fail (s : St) : P.failures = true → s.live = true → s.unpausing = false →
      Step P s { s with toW := s.toW ++ [.error], live := false }
  /-- `cancel_conn`. -/
  | portCancel (s : St) (rest : List Cmd) : s.unpausing = false →
      s.pQ = .cancel :: rest →
      Step P s { s with pQ := rest, live := false }
  /-- Worker: port message for a request still in `Reqs`. -/
  | workerFwd (s : St) (m : Msg) (rest : List Msg) : s.toW = m :: rest →
      s.inReqs = true →
      Step P s { s with toW := rest, toC := s.toC ++ [m],
                        inReqs := (m == .demand || m == .chunk) }
  /-- Worker: port message for a request no longer in `Reqs`: dropped. -/
  | workerDrop (s : St) (m : Msg) (rest : List Msg) : s.toW = m :: rest →
      s.inReqs = false →
      Step P s { s with toW := rest }
  /-- Worker: `{send_body, Ref, _}`, to the port iff in `Reqs`. -/
  | workerBody (s : St) (b : Body) (rest : List Body) : s.bodyQ = b :: rest →
      Step P s { s with bodyQ := rest,
                        pQ := if s.inReqs then s.pQ ++ [.body b] else s.pQ }
  /-- Worker: `{flow, Ref, N}`, to the port iff in `Reqs`. -/
  | workerFlow (s : St) (n : Nat) (rest : List Nat) : s.flowQ = n :: rest →
      Step P s { s with flowQ := rest,
                        pQ := if s.inReqs then s.pQ ++ [.flow n] else s.pQ }
  /-- Worker: `{cancel, Ref}`. -/
  | workerCancel (s : St) : s.cancelQ = true →
      Step P s { s with cancelQ := false, inReqs := false,
                        pQ := if s.inReqs then s.pQ ++ [.cancel] else s.pQ }
  /-- Worker: `req_timeout`. -/
  | workerTimeout (s : St) : P.timeouts = true → s.inReqs = true →
      Step P s { s with inReqs := false, toC := s.toC ++ [.error],
                        pQ := s.pQ ++ [.cancel] }
  | callerRecv (s : St) (m : Msg) (rest : List Msg) : s.toC = m :: rest →
      Step P s (recv s m rest)
  /-- `send_body/3` with the next chunk. -/
  | callerData (s : St) : s.sentEof = false → terminal s = false →
      (0 < s.pending ∨ P.eager = true) → s.sentN < P.total →
      Step P s { s with bodyQ := s.bodyQ ++ [.data], sentN := s.sentN + 1,
                        pending := s.pending - 1 }
  /-- `send_body/3` with eof, once every chunk is sent. -/
  | callerEof (s : St) : s.sentEof = false → terminal s = false →
      (0 < s.pending ∨ P.eager = true) → ¬ s.sentN < P.total →
      Step P s { s with bodyQ := s.bodyQ ++ [.eof], sentEof := true,
                        pending := s.pending - 1 }
  /-- A lying caller: a chunk past `total`. -/
  | lieExtra (s : St) : P.liar = true → terminal s = false → s.sentEof = false →
      s.sentN = P.total →
      Step P s { s with bodyQ := s.bodyQ ++ [.data], sentN := s.sentN + 1,
                        pending := s.pending - 1 }
  /-- A lying caller: eof short of `total`. -/
  | lieShort (s : St) : P.liar = true → terminal s = false → s.sentEof = false →
      s.sentN < P.total →
      Step P s { s with bodyQ := s.bodyQ ++ [.eof], sentEof := true,
                        pending := s.pending - 1 }
  /-- A lying caller: a chunk after its eof. -/
  | lieLate (s : St) : P.liar = true → terminal s = false → s.sentEof = true →
      s.lateN = 0 →
      Step P s { s with bodyQ := s.bodyQ ++ [.data], lateN := 1,
                        pending := s.pending - 1 }
  | callerGrant (s : St) : 0 < s.owed → terminal s = false →
      Step P s { s with flowQ := s.flowQ ++ [s.owed], owed := 0 }
  | callerCancel (s : St) : P.cancels = true → terminal s = false →
      s.cancelled = false →
      Step P s { s with cancelQ := true, cancelled := true }

inductive Reach (P : Params) : St → Prop
  | init : Reach P (init P)
  | step {s t : St} : Reach P s → Step P s t → Reach P t

/-- Occurrences of `x` in a list (`CountIn`). -/
def cnt {α : Type} [DecidableEq α] (x : α) : List α → Nat
  | [] => 0
  | m :: ms => (if m = x then 1 else 0) + cnt x ms

/-- Body commands of kind `b` in the worker -> port queue (`CountT`). -/
def cntBody (b : Body) (q : List Cmd) : Nat := cnt (Cmd.body b) q

/-- `DataInFlight`: chunks sent by the caller and not yet read by curl. -/
def inFlight (s : St) : Nat := cnt .data s.bodyQ + cntBody .data s.pQ + s.buf

/-- `Demands`: demands outstanding anywhere. -/
def demands (s : St) : Nat := cnt .demand s.toW + cnt .demand s.toC + s.pending

end KatipoProofs.Upload
