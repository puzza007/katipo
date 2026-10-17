---------------------------- MODULE KatipoFlow ----------------------------
(***************************************************************************)
(* Streaming flow control for ONE async streaming request (stream => true, *)
(* stream_window => W): C transfer <-> katipo_worker relay <-> consumer.   *)
(*                                                                         *)
(*  C port (c_src/katipo.c):                                               *)
(*    write_cb      out of credits (window = 0): set paused, return        *)
(*                  CURL_WRITEFUNC_PAUSE -- curl holds the data and        *)
(*                  re-delivers it after CURLPAUSE_CONT. Otherwise send    *)
(*                  headers (once) and a chunk, window--.                  *)
(*    flow_conn     window += n; if paused: paused = 0, then               *)
(*                  curl_easy_pause(CONT), which may call write_cb         *)
(*                  synchronously (possibly several times, possibly        *)
(*                  re-pausing), then check_multi_info.                    *)
(*    check_multi_info  CURLE_OK: headers (if still owed) + done; else     *)
(*                  error. Then free_conn.                                 *)
(*    cancel_conn   free_conn; no message.                                 *)
(*  Worker (src/katipo_worker.erl):                                        *)
(*    forward_progress  headers/chunk forwarded iff still in Reqs.         *)
(*    finish_req    done/error delivered iff in Reqs, then removed.        *)
(*    {flow, Ref, N}    port_cmd iff in Reqs.                              *)
(*    {cancel, Ref}     remove, abort_transfer.                            *)
(*    req_timeout   remove, deliver operation_timedout, abort_transfer.    *)
(*  Consumer: receives in order, grants back consumed credits via          *)
(*    update_flow/3 once GrantBatch of them have accumulated.              *)
(*                                                                         *)
(* Over-approximations (each only adds behaviours):                        *)
(*  - libcurl may deliver any number of further chunks synchronously       *)
(*    inside curl_easy_pause(CONT) (SyncWrite while unpausing).            *)
(*  - The worker's single mailbox merges port data, flow and cancel        *)
(*    messages; Erlang only orders per sender, so separate FIFO queues     *)
(*    with a nondeterministic pick are exactly that.                       *)
(*  - The request timer may fire at any time while the request is held.    *)
(*                                                                         *)
(* Port death (PortDeathsOn): the C port exits mid-transfer -- the conn    *)
(*  and the worker -> port pipe are gone -- and the worker reads the       *)
(*  port's 'EXIT' after every message the port sent before dying (same     *)
(*  sender, so ordered). It then stops: terminate/2 sends worker_died to   *)
(*  a request still in Reqs, and grants or cancels sent to the dead        *)
(*  alias go nowhere.                                                      *)
(* Kill (KillsOn): exit(Worker, kill) -- no terminate/2, so no message;    *)
(*  the linked port dies with it and the mailbox is lost.                  *)
(*                                                                         *)
(* Out of scope:                                                           *)
(*  - Admission and multi-request interplay: KatipoFixed.tla.              *)
(*  - Other concurrent requests: window and paused are per-conn state, and *)
(*    the only shared resources (the pipes) are FIFO per request here.     *)
(*  - Unbounded windows (window = -1): write_cb never pauses; a strict     *)
(*    restriction of the W > Total case.                                   *)
(*  - Redirect bodies (documented caveat in katipo:async_req/2).           *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
  W,            \* stream_window (validated > 0 by katipo_req)
  Total,        \* body chunks the server sends
  GrantBatch,   \* consumer grants once this many credits are owed
  TimeoutsOn,   \* request timer may fire
  CancelOn,     \* consumer may cancel
  FailuresOn,   \* curl may fail the transfer mid-body
  PortDeathsOn, \* the C port may die mid-transfer (the worker then stops)
  KillsOn,      \* the worker may be killed outright (no terminate/2)
  \* TRUE: flow_conn clears `paused` BEFORE curl_easy_pause(CONT), as the
  \* code does. FALSE: after it -- losing a re-pause raised inside the call.
  ClearPausedFirst

ASSUME W \in Nat \ {0} /\ Total \in Nat /\ GrantBatch \in Nat \ {0}

VARIABLES
  window,      \* conn->window
  paused,      \* conn->paused (katipo's flag)
  curlPaused,  \* libcurl's own pause state for the easy handle
  unpausing,   \* control is inside curl_easy_pause(CONT) in flow_conn
  remaining,   \* body chunks not yet passed to write_cb successfully
  headersSent, \* conn->headers_sent
  live,        \* conn exists (not yet freed)
  toW,         \* port -> worker pipe: "headers" | "chunk" | "done" | "error"
  pQ,          \* worker -> port: grants (n > 0) and Cancel (= 0)
  inReqs,      \* worker still holds the request
  flowQ,       \* consumer -> worker grants (Nat)
  cancelQ,     \* consumer -> worker cancel (0 or 1 messages)
  toC,         \* worker -> consumer messages
  owed,        \* chunks consumed, credits not yet granted back
  seenHeaders, chunksSeen, seenDone, seenError, \* consumer observations
  orderBad,    \* consumer saw an out-of-protocol message
  cancelled,   \* consumer called katipo:cancel/2
  pAlive,      \* the C port process is running
  wAlive,      \* the worker process is running
  exitPending  \* the port's 'EXIT' is queued behind toW

vars == <<window, paused, curlPaused, unpausing, remaining, headersSent, live,
          toW, pQ, inReqs, flowQ, cancelQ, toC, owed,
          seenHeaders, chunksSeen, seenDone, seenError, orderBad, cancelled,
          pAlive, wAlive, exitPending>>
deathVars == <<pAlive, wAlive, exitPending>>
portVars == <<window, paused, curlPaused, unpausing, remaining, headersSent,
              live, deathVars>>
consVars == <<owed, seenHeaders, chunksSeen, seenDone, seenError, orderBad,
             cancelled>>

Init ==
  /\ window = W /\ paused = FALSE /\ curlPaused = FALSE /\ unpausing = FALSE
  /\ remaining = Total /\ headersSent = FALSE /\ live = TRUE
  /\ toW = <<>> /\ pQ = <<>> /\ inReqs = TRUE
  /\ flowQ = <<>> /\ cancelQ = <<>> /\ toC = <<>> /\ owed = 0
  /\ seenHeaders = FALSE /\ chunksSeen = 0 /\ seenDone = FALSE
  /\ seenError = FALSE /\ orderBad = FALSE /\ cancelled = FALSE
  /\ pAlive = TRUE /\ wAlive = TRUE /\ exitPending = FALSE

Cancel == 0  \* the cancel command in pQ; grants are always positive

HeadersIfOwed == IF headersSent THEN <<>> ELSE <<"headers">>

(* ------------------------------- C port --------------------------------*)

\* write_cb for the next body chunk. Reached from event_cb (socket
\* readable) when not unpausing, or synchronously inside
\* curl_easy_pause(CONT) when unpausing. curl only calls it while the
\* handle is not paused.
WriteCb ==
  /\ live /\ ~curlPaused /\ remaining > 0
  /\ IF window = 0
     THEN /\ paused' = TRUE /\ curlPaused' = TRUE
          /\ UNCHANGED <<window, remaining, headersSent, toW>>
     ELSE /\ toW' = toW \o HeadersIfOwed \o <<"chunk">>
          /\ headersSent' = TRUE
          /\ window' = window - 1
          /\ remaining' = remaining - 1
          /\ UNCHANGED <<paused, curlPaused>>
  /\ UNCHANGED <<deathVars, unpausing, live, pQ, inReqs, flowQ, cancelQ, toC, consVars>>

EventWrite == ~unpausing /\ WriteCb
SyncWrite  == unpausing /\ WriteCb

\* flow_conn, up to and including the curl_easy_pause(CONT) call.
PortFlow ==
  /\ pAlive /\ ~unpausing /\ pQ # <<>> /\ Head(pQ) # Cancel
  /\ pQ' = Tail(pQ)
  /\ IF live
     THEN /\ window' = window + Head(pQ)
          /\ IF paused
             THEN /\ curlPaused' = FALSE /\ unpausing' = TRUE
                  /\ paused' = IF ClearPausedFirst THEN FALSE ELSE paused
             ELSE UNCHANGED <<paused, curlPaused, unpausing>>
     ELSE UNCHANGED <<window, paused, curlPaused, unpausing>>
  /\ UNCHANGED <<deathVars, remaining, headersSent, live, toW, inReqs, flowQ, cancelQ,
                 toC, consVars>>

\* curl_easy_pause returns (it stops delivering once re-paused or drained).
UnpauseReturn ==
  /\ unpausing
  /\ unpausing' = FALSE
  /\ paused' = IF ClearPausedFirst THEN paused ELSE FALSE
  /\ UNCHANGED <<deathVars, window, curlPaused, remaining, headersSent, live, toW, pQ,
                 inReqs, flowQ, cancelQ, toC, consVars>>

\* check_multi_info, CURLMSG_DONE with CURLE_OK: the body is drained.
PortComplete ==
  /\ live /\ ~unpausing /\ remaining = 0 /\ ~curlPaused
  /\ toW' = toW \o HeadersIfOwed \o <<"done">>
  /\ headersSent' = TRUE /\ live' = FALSE
  /\ UNCHANGED <<deathVars, window, paused, curlPaused, unpausing, remaining, pQ, inReqs,
                 flowQ, cancelQ, toC, consVars>>

\* check_multi_info with a curl error (reset, transfer timeout, ...).
PortFail ==
  /\ FailuresOn /\ live /\ ~unpausing
  /\ toW' = Append(toW, "error") /\ live' = FALSE
  /\ UNCHANGED <<deathVars, window, paused, curlPaused, unpausing, remaining,
                 headersSent, pQ, inReqs, flowQ, cancelQ, toC, consVars>>

\* cancel_conn: free_conn, no message.
PortCancel ==
  /\ pAlive /\ ~unpausing /\ pQ # <<>> /\ Head(pQ) = Cancel
  /\ pQ' = Tail(pQ) /\ live' = FALSE
  /\ UNCHANGED <<deathVars, window, paused, curlPaused, unpausing, remaining,
                 headersSent, toW, inReqs, flowQ, cancelQ, toC, consVars>>

\* The port process dies, wherever control is (even inside
\* curl_easy_pause): its conns and its end of the pipe are gone.
PortDies ==
  /\ PortDeathsOn /\ pAlive
  /\ pAlive' = FALSE /\ live' = FALSE /\ exitPending' = TRUE
  /\ unpausing' = FALSE /\ paused' = FALSE /\ curlPaused' = FALSE
  /\ UNCHANGED <<window, remaining, headersSent, wAlive, toW, pQ, inReqs,
                 flowQ, cancelQ, toC, consVars>>

(* ------------------------------- worker --------------------------------*)

\* handle_info({'EXIT', Port, _}) -> {stop, port_died} -> terminate/2,
\* which sends worker_died iff the request is still in Reqs.
WorkerExit ==
  /\ wAlive /\ exitPending /\ toW = <<>>
  /\ wAlive' = FALSE /\ exitPending' = FALSE /\ inReqs' = FALSE
  /\ toC' = IF inReqs THEN Append(toC, "error") ELSE toC
  /\ UNCHANGED <<window, paused, curlPaused, unpausing, remaining,
                 headersSent, live, pAlive, toW, pQ, flowQ, cancelQ, consVars>>

\* exit(Worker, kill): no terminate/2, no message. The linked port dies too
\* and the mailbox is lost.
Kill ==
  /\ KillsOn /\ wAlive
  /\ wAlive' = FALSE /\ pAlive' = FALSE /\ live' = FALSE /\ inReqs' = FALSE
  /\ exitPending' = FALSE /\ toW' = <<>>
  /\ unpausing' = FALSE /\ paused' = FALSE /\ curlPaused' = FALSE
  /\ UNCHANGED <<window, remaining, headersSent, pQ, flowQ, cancelQ, toC,
                 consVars>>

WorkerPort ==
  /\ wAlive /\ toW # <<>>
  /\ toW' = Tail(toW)
  /\ IF inReqs
     THEN /\ toC' = Append(toC, Head(toW))
          /\ inReqs' = (Head(toW) \in {"headers", "chunk"})
     ELSE UNCHANGED <<toC, inReqs>>
  /\ UNCHANGED <<portVars, pQ, flowQ, cancelQ, consVars>>

WorkerFlow ==
  /\ wAlive /\ flowQ # <<>>
  /\ flowQ' = Tail(flowQ)
  /\ pQ' = IF inReqs THEN Append(pQ, Head(flowQ)) ELSE pQ
  /\ UNCHANGED <<portVars, toW, inReqs, cancelQ, toC, consVars>>

WorkerCancel ==
  /\ wAlive /\ cancelQ # <<>>
  /\ cancelQ' = Tail(cancelQ)
  /\ IF inReqs
     THEN /\ inReqs' = FALSE /\ pQ' = Append(pQ, Cancel)
     ELSE UNCHANGED <<inReqs, pQ>>
  /\ UNCHANGED <<portVars, toW, flowQ, toC, consVars>>

WorkerTimeout ==
  /\ TimeoutsOn /\ wAlive /\ inReqs
  /\ inReqs' = FALSE
  /\ toC' = Append(toC, "error")
  /\ pQ' = Append(pQ, Cancel)
  /\ UNCHANGED <<portVars, toW, flowQ, cancelQ, consVars>>

(* ------------------------------ consumer -------------------------------*)

Terminal == seenDone \/ seenError

ConsumerRecv ==
  /\ toC # <<>>
  /\ toC' = Tail(toC)
  /\ LET m == Head(toC) IN
     /\ orderBad' = (orderBad \/ Terminal
                      \/ (m = "headers" /\ seenHeaders)
                      \/ (m \in {"chunk", "done"} /\ ~seenHeaders))
     /\ seenHeaders' = (seenHeaders \/ m = "headers")
     /\ chunksSeen' = IF m = "chunk" THEN chunksSeen + 1 ELSE chunksSeen
     /\ owed' = IF m = "chunk" THEN owed + 1 ELSE owed
     /\ seenDone' = (seenDone \/ m = "done")
     /\ seenError' = (seenError \/ m = "error")
  /\ UNCHANGED <<portVars, toW, pQ, inReqs, flowQ, cancelQ, cancelled>>

ConsumerGrant ==
  /\ owed >= GrantBatch /\ ~Terminal
  /\ flowQ' = Append(flowQ, owed) /\ owed' = 0
  /\ UNCHANGED <<portVars, toW, pQ, inReqs, cancelQ, toC, seenHeaders,
                 chunksSeen, seenDone, seenError, orderBad, cancelled>>

\* Once only, and only before the consumer has seen a terminal message.
ConsumerCancel ==
  /\ CancelOn /\ ~Terminal /\ ~cancelled
  /\ cancelQ' = <<"cancel">> /\ cancelled' = TRUE
  /\ UNCHANGED <<portVars, toW, pQ, inReqs, flowQ, toC, owed, seenHeaders,
                 chunksSeen, seenDone, seenError, orderBad>>

(* -------------------------------- spec ---------------------------------*)

PortStep == EventWrite \/ SyncWrite \/ PortFlow \/ UnpauseReturn
            \/ PortComplete \/ PortCancel
WorkerStep == WorkerPort \/ WorkerFlow \/ WorkerCancel \/ WorkerExit

Next ==
  \/ PortStep \/ PortFail \/ PortDies
  \/ WorkerStep \/ WorkerTimeout \/ Kill
  \/ ConsumerRecv \/ ConsumerGrant \/ ConsumerCancel

Fairness ==
  /\ WF_vars(PortStep)
  /\ WF_vars(WorkerStep)
  /\ WF_vars(ConsumerRecv)
  /\ WF_vars(ConsumerGrant)

Spec == Init /\ [][Next]_vars /\ Fairness

(* ----------------------------- properties ------------------------------*)

RECURSIVE CountIn(_, _)
CountIn(s, x) == IF s = <<>> THEN 0
                 ELSE (IF Head(s) = x THEN 1 ELSE 0) + CountIn(Tail(s), x)

RECURSIVE SumNat(_)
SumNat(s) == IF s = <<>> THEN 0 ELSE Head(s) + SumNat(Tail(s))

\* Chunks emitted but not yet granted back.
Outstanding == CountIn(toW, "chunk") + CountIn(toC, "chunk") + owed

\* Credit conservation: while the worker holds the request and the C conn
\* still exists nothing has been dropped, so every one of the W credits is
\* somewhere -- in the port's window, riding a chunk, owed by the consumer,
\* or riding a grant. (Once either side lets go, the worker drops chunks
\* and the port drops grants, and the window no longer means anything.)
CreditConservation ==
  inReqs /\ live => window + Outstanding + SumNat(flowQ) + SumNat(pQ) = W

\* The backpressure guarantee: at most W chunks buffered anywhere between
\* the C port and the consumer's code.
BoundedBuffering == Outstanding <= W

\* write_cb never sends a chunk without a credit.
WindowNonNeg == window >= 0

\* Consumer sees headers, chunk*, then one terminal -- nothing after it.
ProtocolOrder == ~orderBad

\* A done implies the whole body arrived: no chunk lost or duplicated.
NoLostChunks == seenDone => chunksSeen = Total
ChunksBounded == chunksSeen <= Total

\* katipo's flag agrees with libcurl outside flow_conn: if they drift, a
\* paused transfer is never resumed.
PausedAgrees == ~unpausing => (paused = curlPaused)

\* Liveness: with a consumer that keeps granting, the transfer finishes.
EventuallyTerminal == <>(Terminal \/ cancelled)
EventuallyDone == <>seenDone

\* Witnesses (check with -inv, expect VIOLATED): pausing, a synchronous
\* re-pause inside curl_easy_pause, and a full window all happen.
WitnessPaused == ~curlPaused
WitnessRepause == ~(unpausing /\ curlPaused)
WitnessFullWindow == Outstanding < W
\* ... and, with PortDeathsOn, a consumer that saw part of the body then
\* got worker_died.
WitnessDiedMidBody == ~(seenError /\ chunksSeen > 0 /\ ~pAlive)
=============================================================================
