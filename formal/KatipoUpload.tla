--------------------------- MODULE KatipoUpload ---------------------------
(***************************************************************************)
(* Pull-based streaming request bodies for ONE async request               *)
(* (body => {stream, _}), with a streamed response under a bounded         *)
(* stream_window, so the upload's pause and the response's pause share one *)
(* curl easy handle. C transfer <-> katipo_worker relay <-> caller.        *)
(*                                                                         *)
(* STATUS: written before the implementation as a design check; matches   *)
(* katipo branch feat/streaming-body, 2026-10-26. Verdicts as in README.  *)
(*                                                                         *)
(*  C port (c_src/katipo.c):                                               *)
(*    read_stream_cb  the upload has failed: abort. A chunk is buffered:   *)
(*                  hand it to curl. eof received: return 0, the body is   *)
(*                  complete. Otherwise, if more is wanted (the declared   *)
(*                  length not all in), send one demand unless one is      *)
(*                  outstanding, and pause (upload_paused). EarlyDemand,   *)
(*                  not shipped, also demands after the read that drains   *)
(*                  the buffer.                                            *)
(*    body_conn     ignored after eof or a failure. {body, Data} past the  *)
(*                  declared length, or eof short of it, fails the upload; *)
(*                  otherwise buffer it. Clear the outstanding demand; if  *)
(*                  upload_paused: clear it, then curl_easy_pause, which   *)
(*                  may call read_stream_cb, write_cb synchronously.       *)
(*    write_cb      out of credits: set paused, return                     *)
(*                  CURL_WRITEFUNC_PAUSE. Otherwise send a chunk.          *)
(*    flow_conn     window += n; if paused: clear it, curl_easy_pause.     *)
(*    complete_conn a failed upload is reported as an error even if curl   *)
(*                  finished.                                              *)
(*    The resume mask (MaskedResume): curl_easy_pause sets the whole pause *)
(*    state, so CURLPAUSE_CONT also resumes the other direction; the mask  *)
(*    keeps the other direction paused if katipo's flag says it is.        *)
(*  curl: with a declared length (Length) it reads exactly that many       *)
(*    bytes and no eof; without, it reads until the read callback's 0.     *)
(*  Worker (src/katipo_worker.erl): demand and chunk forwarded iff the     *)
(*    request is in Reqs, done/error delivered iff in Reqs and then        *)
(*    removed; {send_body, Ref, _} and {flow, Ref, N} go to the port iff   *)
(*    in Reqs; cancel and the request timer remove it and abort.           *)
(*  Caller: answers each demand with one chunk, or eof once Total chunks   *)
(*    are sent (Eager: may also send without a demand), and grants back    *)
(*    each response chunk it consumes. Liar: may also send a chunk past    *)
(*    Total, eof short of it, or a chunk after its eof.                    *)
(*                                                                         *)
(* Over-approximations (each only adds behaviours):                        *)
(*  - curl may call read_stream_cb or write_cb whenever that direction is  *)
(*    not paused, inside curl_easy_pause or from the event loop; waiting   *)
(*    for a writable socket is a delay, which this allows.                 *)
(*  - With RespEarly the response may arrive, and finish, while the body   *)
(*    is still being sent (HTTP/2, or a server answering early).           *)
(*  - The worker's one mailbox is separate FIFO queues per sender.         *)
(*                                                                         *)
(* Out of scope:                                                           *)
(*  - Port death and worker kill: KatipoFlow.tla covers them for this      *)
(*    request shape; the upload adds no state that outlives the conn.      *)
(*  - Rewinds: a streamed body cannot be rewound, so seek_cb refuses and   *)
(*    curl fails a redirect or auth retry that must resend it              *)
(*    (send_fail_rewind), as PortFail allows.                              *)
(*  - Admission and other requests: KatipoFixed.tla.                       *)
(*  - Chunk sizes: a chunk is one unit, read whole. A curl buffer smaller  *)
(*    than a chunk splits one read into several, with the demand after the *)
(*    last; the fuzz target fuzz_transfer covers that.                     *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
  Total,        \* body chunks the caller sends before eof
  W,            \* the response's stream_window
  Resp,         \* response chunks the server sends
  Length,       \* TRUE: Total chunks declared as the Content-Length
  MaskedResume, \* TRUE: resume one direction only; FALSE: CURLPAUSE_CONT
  DemandGuard,  \* TRUE: at most one demand outstanding; FALSE: one per read
  EarlyDemand,  \* TRUE: also demand as the buffer drains (not shipped)
  Eager,        \* the caller may send a chunk without a demand
  Liar,         \* the caller may send the wrong amount
  RespEarly,    \* the response may run while the body is being sent
  TimeoutsOn,   \* the request timer may fire
  CancelOn,     \* the caller may cancel
  FailuresOn    \* curl may fail the transfer

ASSUME Total \in Nat /\ W \in Nat \ {0} /\ Resp \in Nat

VARIABLES
  live,          \* the conn exists
  buf,           \* chunks buffered in the port, not yet read by curl
  eofIn,         \* the port has eof
  upFailed,      \* the port has failed the upload (upload_error)
  demanded,      \* a demand is outstanding (sent, not yet answered)
  upPaused,      \* katipo's upload_paused
  curlSendPaused,\* curl's own send pause
  paused,        \* katipo's paused (response window)
  curlRecvPaused,\* curl's own receive pause
  unpausing,     \* control is inside curl_easy_pause
  readN,         \* chunks curl has read
  uploadDone,    \* curl has sent the whole body
  window,        \* conn->window
  respLeft,      \* response chunks not yet passed to write_cb
  toW,           \* port -> worker: "demand" | "chunk" | "done" | "error"
  pQ,            \* worker -> port: [t |-> "data" | "eof" | "flow" | "cancel", n |-> grant]
  inReqs,        \* the worker holds the request
  bodyQ,         \* caller -> worker: "data" | "eof"
  flowQ,         \* caller -> worker: grants
  cancelQ,       \* caller -> worker: cancel
  toC,           \* worker -> caller
  sentN,         \* chunks the caller has sent before its eof
  sentEof,       \* the caller has sent eof
  lateN,         \* chunks the caller has sent after its eof (Liar)
  pending,       \* demands the caller has received and not answered
  owed,          \* response chunks consumed, not yet granted back
  seenChunks, seenDone, seenError, orderBad, cancelled

vars == <<live, buf, eofIn, upFailed, demanded, upPaused, curlSendPaused,
          paused, curlRecvPaused, unpausing, readN, uploadDone, window,
          respLeft, toW, pQ, inReqs, bodyQ, flowQ, cancelQ, toC, sentN,
          sentEof, lateN, pending, owed, seenChunks, seenDone, seenError,
          orderBad, cancelled>>
portVars == <<live, buf, eofIn, upFailed, demanded, upPaused, curlSendPaused,
              paused, curlRecvPaused, unpausing, readN, uploadDone, window,
              respLeft>>
callerVars == <<sentN, sentEof, lateN, pending, owed, seenChunks, seenDone,
                seenError, orderBad, cancelled>>

Init ==
  /\ live = TRUE /\ buf = 0 /\ eofIn = FALSE /\ upFailed = FALSE
  /\ demanded = FALSE /\ upPaused = FALSE /\ curlSendPaused = FALSE
  /\ paused = FALSE /\ curlRecvPaused = FALSE /\ unpausing = FALSE
  /\ readN = 0 /\ uploadDone = (Length /\ Total = 0)
  /\ window = W /\ respLeft = Resp
  /\ toW = <<>> /\ pQ = <<>> /\ inReqs = TRUE
  /\ bodyQ = <<>> /\ flowQ = <<>> /\ cancelQ = <<>> /\ toC = <<>>
  /\ sentN = 0 /\ sentEof = FALSE /\ lateN = 0 /\ pending = 0 /\ owed = 0
  /\ seenChunks = 0 /\ seenDone = FALSE /\ seenError = FALSE
  /\ orderBad = FALSE /\ cancelled = FALSE

Msg(t, n) == [t |-> t, n |-> n]

(* ------------------------------- C port --------------------------------*)

\* Chunks the port has taken from the caller (upload_pos).
Got == readN + buf

\* read_stream_cb's demand, once the buffer is empty: only while more is
\* wanted, and with the guard only if none is outstanding.
Demand ==
  IF ~eofIn /\ ~(Length /\ Got = Total) /\ ~(demanded /\ DemandGuard)
  THEN /\ toW' = Append(toW, "demand") /\ demanded' = TRUE
  ELSE UNCHANGED <<toW, demanded>>

ReadCb ==
  /\ live /\ ~curlSendPaused /\ ~uploadDone
  /\ IF upFailed
     THEN \* CURL_READFUNC_ABORT: curl fails the transfer.
          /\ toW' = Append(toW, "error") /\ live' = FALSE
          /\ UNCHANGED <<buf, readN, eofIn, demanded, upPaused, curlSendPaused,
                         uploadDone>>
     ELSE IF buf > 0
     THEN /\ buf' = buf - 1 /\ readN' = readN + 1
          /\ uploadDone' = (Length /\ readN + 1 = Total)
          /\ IF EarlyDemand /\ buf = 1 THEN Demand ELSE UNCHANGED <<toW, demanded>>
          /\ UNCHANGED <<live, eofIn, upPaused, curlSendPaused>>
     ELSE IF eofIn
     THEN /\ uploadDone' = TRUE
          /\ UNCHANGED <<live, buf, readN, eofIn, demanded, upPaused,
                         curlSendPaused, toW>>
     ELSE /\ Demand
          /\ upPaused' = TRUE /\ curlSendPaused' = TRUE
          /\ UNCHANGED <<live, buf, readN, eofIn, uploadDone>>
  /\ UNCHANGED <<upFailed, paused, curlRecvPaused, unpausing, window, respLeft,
                 pQ, inReqs, bodyQ, flowQ, cancelQ, toC, callerVars>>

WriteCb ==
  /\ live /\ ~curlRecvPaused /\ respLeft > 0 /\ (RespEarly \/ uploadDone)
  /\ IF window = 0
     THEN /\ paused' = TRUE /\ curlRecvPaused' = TRUE
          /\ UNCHANGED <<window, respLeft, toW>>
     ELSE /\ toW' = Append(toW, "chunk")
          /\ window' = window - 1 /\ respLeft' = respLeft - 1
          /\ UNCHANGED <<paused, curlRecvPaused>>
  /\ UNCHANGED <<live, buf, eofIn, upFailed, demanded, upPaused, curlSendPaused,
                 unpausing, readN, uploadDone, pQ, inReqs, bodyQ, flowQ,
                 cancelQ, toC, callerVars>>

\* body_conn up to and including its curl_easy_pause call. The port, not
\* curl, holds the body to its declared length: curl before 8.7 would
\* send the excess, or wait for the rest, without complaint.
PortBody ==
  /\ ~unpausing /\ pQ # <<>> /\ Head(pQ).t \in {"data", "eof"}
  /\ pQ' = Tail(pQ)
  /\ IF live /\ ~eofIn /\ ~upFailed
     THEN LET data == Head(pQ).t = "data"
              wrong == Length /\ IF data THEN Got = Total ELSE Got < Total
          IN /\ buf' = IF data /\ ~wrong THEN buf + 1 ELSE buf
             /\ eofIn' = (eofIn \/ ~data)
             /\ upFailed' = wrong
             /\ demanded' = FALSE
             /\ IF upPaused
                THEN /\ upPaused' = FALSE /\ curlSendPaused' = FALSE
                     /\ curlRecvPaused' = IF MaskedResume THEN curlRecvPaused ELSE FALSE
                     /\ unpausing' = TRUE
                ELSE UNCHANGED <<upPaused, curlSendPaused, curlRecvPaused, unpausing>>
     ELSE UNCHANGED <<buf, eofIn, upFailed, demanded, upPaused, curlSendPaused,
                      curlRecvPaused, unpausing>>
  /\ UNCHANGED <<live, paused, readN, uploadDone, window, respLeft, toW,
                 inReqs, bodyQ, flowQ, cancelQ, toC, callerVars>>

\* flow_conn up to and including its curl_easy_pause call.
PortFlow ==
  /\ ~unpausing /\ pQ # <<>> /\ Head(pQ).t = "flow"
  /\ pQ' = Tail(pQ)
  /\ IF live
     THEN /\ window' = window + Head(pQ).n
          /\ IF paused
             THEN /\ paused' = FALSE /\ curlRecvPaused' = FALSE
                  /\ curlSendPaused' = IF MaskedResume THEN curlSendPaused ELSE FALSE
                  /\ unpausing' = TRUE
             ELSE UNCHANGED <<paused, curlRecvPaused, curlSendPaused, unpausing>>
     ELSE UNCHANGED <<window, paused, curlRecvPaused, curlSendPaused, unpausing>>
  /\ UNCHANGED <<live, buf, eofIn, upFailed, demanded, upPaused, readN,
                 uploadDone, respLeft, toW, inReqs, bodyQ, flowQ, cancelQ, toC,
                 callerVars>>

UnpauseReturn ==
  /\ unpausing /\ unpausing' = FALSE
  /\ UNCHANGED <<live, buf, eofIn, upFailed, demanded, upPaused, curlSendPaused,
                 paused, curlRecvPaused, readN, uploadDone, window, respLeft,
                 toW, pQ, inReqs, bodyQ, flowQ, cancelQ, toC, callerVars>>

\* check_multi_info, CURLE_OK: the response is complete. Without
\* RespEarly the body went first; with it, the server may answer before
\* reading it all, and curl stops sending. complete_conn reports a failed
\* upload as an error regardless.
PortComplete ==
  /\ live /\ ~unpausing /\ respLeft = 0 /\ (uploadDone \/ RespEarly)
  /\ toW' = Append(toW, IF upFailed THEN "error" ELSE "done") /\ live' = FALSE
  /\ UNCHANGED <<buf, eofIn, upFailed, demanded, upPaused, curlSendPaused,
                 paused, curlRecvPaused, unpausing, readN, uploadDone, window,
                 respLeft, pQ, inReqs, bodyQ, flowQ, cancelQ, toC, callerVars>>

PortFail ==
  /\ FailuresOn /\ live /\ ~unpausing
  /\ toW' = Append(toW, "error") /\ live' = FALSE
  /\ UNCHANGED <<buf, eofIn, upFailed, demanded, upPaused, curlSendPaused,
                 paused, curlRecvPaused, unpausing, readN, uploadDone, window,
                 respLeft, pQ, inReqs, bodyQ, flowQ, cancelQ, toC, callerVars>>

PortCancel ==
  /\ ~unpausing /\ pQ # <<>> /\ Head(pQ).t = "cancel"
  /\ pQ' = Tail(pQ) /\ live' = FALSE
  /\ UNCHANGED <<buf, eofIn, upFailed, demanded, upPaused, curlSendPaused,
                 paused, curlRecvPaused, unpausing, readN, uploadDone, window,
                 respLeft, toW, inReqs, bodyQ, flowQ, cancelQ, toC, callerVars>>

(* ------------------------------- worker --------------------------------*)

WorkerPort ==
  /\ toW # <<>>
  /\ toW' = Tail(toW)
  /\ IF inReqs
     THEN /\ toC' = Append(toC, Head(toW))
          /\ inReqs' = (Head(toW) \in {"demand", "chunk"})
     ELSE UNCHANGED <<toC, inReqs>>
  /\ UNCHANGED <<portVars, pQ, bodyQ, flowQ, cancelQ, callerVars>>

WorkerBody ==
  /\ bodyQ # <<>>
  /\ bodyQ' = Tail(bodyQ)
  /\ pQ' = IF inReqs THEN Append(pQ, Msg(Head(bodyQ), 0)) ELSE pQ
  /\ UNCHANGED <<portVars, toW, inReqs, flowQ, cancelQ, toC, callerVars>>

WorkerFlow ==
  /\ flowQ # <<>>
  /\ flowQ' = Tail(flowQ)
  /\ pQ' = IF inReqs THEN Append(pQ, Msg("flow", Head(flowQ))) ELSE pQ
  /\ UNCHANGED <<portVars, toW, inReqs, bodyQ, cancelQ, toC, callerVars>>

WorkerCancel ==
  /\ cancelQ # <<>>
  /\ cancelQ' = Tail(cancelQ)
  /\ IF inReqs
     THEN /\ inReqs' = FALSE /\ pQ' = Append(pQ, Msg("cancel", 0))
     ELSE UNCHANGED <<inReqs, pQ>>
  /\ UNCHANGED <<portVars, toW, bodyQ, flowQ, toC, callerVars>>

WorkerTimeout ==
  /\ TimeoutsOn /\ inReqs
  /\ inReqs' = FALSE
  /\ toC' = Append(toC, "error")
  /\ pQ' = Append(pQ, Msg("cancel", 0))
  /\ UNCHANGED <<portVars, toW, bodyQ, flowQ, cancelQ, callerVars>>

(* ------------------------------- caller --------------------------------*)

Terminal == seenDone \/ seenError

CallerRecv ==
  /\ toC # <<>>
  /\ toC' = Tail(toC)
  /\ LET m == Head(toC) IN
     /\ orderBad' = (orderBad \/ Terminal)
     /\ pending' = IF m = "demand" THEN pending + 1 ELSE pending
     /\ owed' = IF m = "chunk" THEN owed + 1 ELSE owed
     /\ seenChunks' = IF m = "chunk" THEN seenChunks + 1 ELSE seenChunks
     /\ seenDone' = (seenDone \/ m = "done")
     /\ seenError' = (seenError \/ m = "error")
  /\ UNCHANGED <<portVars, toW, pQ, inReqs, bodyQ, flowQ, cancelQ, sentN,
                 sentEof, lateN, cancelled>>

\* send_body/3: the next chunk, or eof once all Total are sent. Only in
\* answer to a demand unless Eager, and never after eof or a terminal.
CallerSend ==
  /\ ~sentEof /\ ~Terminal /\ (pending > 0 \/ Eager)
  /\ IF sentN < Total
     THEN /\ bodyQ' = Append(bodyQ, "data") /\ sentN' = sentN + 1
          /\ UNCHANGED sentEof
     ELSE /\ bodyQ' = Append(bodyQ, "eof") /\ sentEof' = TRUE
          /\ UNCHANGED sentN
  /\ pending' = IF pending > 0 THEN pending - 1 ELSE 0
  /\ UNCHANGED <<portVars, toW, pQ, inReqs, flowQ, cancelQ, toC, lateN, owed,
                 seenChunks, seenDone, seenError, orderBad, cancelled>>

\* A caller that sends the wrong amount, demand or not: one chunk past
\* Total, eof short of it, or one chunk after its eof.
CallerLie ==
  /\ Liar /\ ~Terminal
  /\ \/ /\ ~sentEof /\ sentN = Total
        /\ bodyQ' = Append(bodyQ, "data") /\ sentN' = sentN + 1
        /\ UNCHANGED <<sentEof, lateN>>
     \/ /\ ~sentEof /\ sentN < Total
        /\ bodyQ' = Append(bodyQ, "eof") /\ sentEof' = TRUE
        /\ UNCHANGED <<sentN, lateN>>
     \/ /\ sentEof /\ lateN = 0
        /\ bodyQ' = Append(bodyQ, "data") /\ lateN' = 1
        /\ UNCHANGED <<sentN, sentEof>>
  /\ pending' = IF pending > 0 THEN pending - 1 ELSE 0
  /\ UNCHANGED <<portVars, toW, pQ, inReqs, flowQ, cancelQ, toC, owed,
                 seenChunks, seenDone, seenError, orderBad, cancelled>>

CallerGrant ==
  /\ owed > 0 /\ ~Terminal
  /\ flowQ' = Append(flowQ, owed) /\ owed' = 0
  /\ UNCHANGED <<portVars, toW, pQ, inReqs, bodyQ, cancelQ, toC, sentN,
                 sentEof, lateN, pending, seenChunks, seenDone, seenError,
                 orderBad, cancelled>>

CallerCancel ==
  /\ CancelOn /\ ~Terminal /\ ~cancelled
  /\ cancelQ' = <<"cancel">> /\ cancelled' = TRUE
  /\ UNCHANGED <<portVars, toW, pQ, inReqs, bodyQ, flowQ, toC, sentN, sentEof,
                 lateN, pending, owed, seenChunks, seenDone, seenError, orderBad>>

(* -------------------------------- spec ---------------------------------*)

PortStep == ReadCb \/ WriteCb \/ PortBody \/ PortFlow \/ UnpauseReturn
            \/ PortComplete \/ PortCancel
WorkerStep == WorkerPort \/ WorkerBody \/ WorkerFlow \/ WorkerCancel
CallerStep == CallerRecv \/ CallerSend \/ CallerGrant

Next ==
  \/ PortStep \/ PortFail
  \/ WorkerStep \/ WorkerTimeout
  \/ CallerStep \/ CallerCancel \/ CallerLie

Fairness == WF_vars(PortStep) /\ WF_vars(WorkerStep) /\ WF_vars(CallerStep)

Spec == Init /\ [][Next]_vars /\ Fairness

(* ----------------------------- properties ------------------------------*)

RECURSIVE CountIn(_, _)
CountIn(s, x) == IF s = <<>> THEN 0
                 ELSE (IF Head(s) = x THEN 1 ELSE 0) + CountIn(Tail(s), x)

RECURSIVE CountT(_, _)
CountT(s, t) == IF s = <<>> THEN 0
                ELSE (IF Head(s).t = t THEN 1 ELSE 0) + CountT(Tail(s), t)

\* Body chunks sent by the caller and not yet read by curl.
DataInFlight == CountIn(bodyQ, "data") + CountT(pQ, "data") + buf

\* Nothing lost, duplicated or reordered (chunks are indistinguishable
\* and every queue is FIFO, so counting is enough): while the request is
\* held and the conn exists, every chunk sent is read or on its way.
BodyConserved == inReqs /\ live => readN + DataInFlight = sentN

\* curl finishes the upload only after every chunk, and only after the
\* caller's eof unless the length was declared.
CompleteBody == uploadDone => readN = Total /\ (Length \/ sentEof)

\* Whatever the caller sends: curl never gets more than the declared
\* length, nor anything sent after eof, and the upload finishes with
\* exactly the body declared, or sent before eof.
LengthHeld == Length => readN <= Total
BodyIsSent == uploadDone => readN = IF Length THEN Total ELSE sentN

\* The pull guarantee: a caller that sends only on demand has at most one
\* chunk between it and curl. (An Eager caller breaks it: the
\* Eager config checks that it fails.)
OneChunkInFlight == DataInFlight <= 1

\* At most one demand outstanding anywhere, while the request is held.
Demands == CountIn(toW, "demand") + CountIn(toC, "demand") + pending
OneDemand == inReqs => Demands <= 1

\* Nothing reaches the caller after its terminal message (a demand
\* behind a timeout's error, say).
ProtocolOrder == ~orderBad

\* katipo's pause flags agree with curl's outside curl_easy_pause: if they
\* drift, a paused direction may never be resumed.
SendPausedAgrees == ~unpausing => (upPaused = curlSendPaused)
RecvPausedAgrees == ~unpausing => (paused = curlRecvPaused)

WindowNonNeg == window >= 0

\* Liveness: with a caller that answers demands and grants, the request
\* finishes, with the whole body sent; whatever the caller sends, it
\* finishes one way or the other.
EventuallyTerminal == <>(Terminal \/ cancelled)
EventuallyDone == <>(seenDone /\ (RespEarly \/ uploadDone))

\* Witnesses (check with -inv, expect VIOLATED).
WitnessBothPaused == ~(curlSendPaused /\ curlRecvPaused)
WitnessSyncRead == ~(unpausing /\ readN > 0 /\ buf = 0 /\ ~curlSendPaused)
WitnessDemandAfterTimeout == ~(seenError /\ CountIn(toW, "demand") > 0)
WitnessEarlyDemand == ~(demanded /\ ~curlSendPaused /\ ~unpausing /\ live) \* EarlyDemand
WitnessLieFails == ~(upFailed /\ seenError)

(* ------------------ the Lean proof's invariants, mirrored -----------------*)
(* One operator per field of the structures in                             *)
(* lean/KatipoProofs/Upload/Proofs.lean, so TLC can confirm the invariants *)
(* the proofs rest on hold of this spec too (KatipoUploadLeanInv.cfg).     *)

CntBody(q, t) == CountT(q, t)
RECURSIVE EofLastB(_)
EofLastB(q) == q = <<>> \/ ((Head(q) = "eof" => Tail(q) = <<>>) /\ EofLastB(Tail(q)))
RECURSIVE EofLastP(_)
EofLastP(q) == q = <<>> \/
  ((Head(q).t = "eof" => CntBody(Tail(q), "data") = 0 /\ CntBody(Tail(q), "eof") = 0)
   /\ EofLastP(Tail(q)))

LeanEof ==
  /\ sentN <= Total
  /\ sentEof => sentN = Total
  /\ ~sentEof => CountIn(bodyQ, "eof") = 0 /\ CntBody(pQ, "eof") = 0 /\ ~eofIn
  /\ EofLastB(bodyQ)
  /\ EofLastP(pQ)
  /\ CntBody(pQ, "eof") > 0 => CountIn(bodyQ, "data") = 0 /\ CountIn(bodyQ, "eof") = 0
  /\ eofIn => CountIn(bodyQ, "data") = 0 /\ CountIn(bodyQ, "eof") = 0
              /\ CntBody(pQ, "data") = 0 /\ CntBody(pQ, "eof") = 0
  /\ live /\ (CntBody(pQ, "eof") > 0 \/ eofIn) => readN + CntBody(pQ, "data") + buf = Total
  /\ uploadDone => readN = Total /\ (Length \/ sentEof)

LeanHon ==
  /\ lateN = 0
  /\ readN + buf + CntBody(pQ, "data") + CountIn(bodyQ, "data") <= sentN
  /\ ~upFailed
  /\ Length /\ readN = Total => uploadDone

Answerable == pending + CountIn(toC, "demand") + (IF inReqs THEN CountIn(toW, "demand") ELSE 0)
Tokens == Answerable + CountIn(bodyQ, "data") + CountIn(bodyQ, "eof")
          + CntBody(pQ, "data") + CntBody(pQ, "eof")
LeanDem ==
  /\ Tokens + buf <= 1
  /\ inReqs /\ live /\ ~demanded => Tokens = 0
  /\ MaskedResume /\ live /\ demanded => curlSendPaused

\* Any caller, Liar included.
LeanLen ==
  /\ Length => readN + buf <= Total
  /\ Length /\ eofIn /\ ~upFailed => readN + buf = Total
  /\ Length /\ uploadDone => readN = Total

RECURSIVE TermLast(_)
TermLast(q) == q = <<>> \/ ((Head(q) \in {"done", "error"} => Tail(q) = <<>>) /\ TermLast(Tail(q)))
LeanOrd ==
  /\ ~orderBad
  /\ Terminal => toC = <<>>
  /\ (CountIn(toC, "done") + CountIn(toC, "error") > 0 \/ Terminal) => ~inReqs
  /\ TermLast(toC)

LeanAgree == upPaused = curlSendPaused /\ paused = curlRecvPaused
=============================================================================
