--------------------------- MODULE KatipoFixed ---------------------------
(***************************************************************************)
(* Model of katipo's async request path AFTER the dispatch fixes:          *)
(*                                                                         *)
(*  1. async_req admission is a gen_server CALL (wpool:call), so the       *)
(*     caller's monitor converts every dispatch failure -- dead/restarting *)
(*     worker name, call lost in a crashing worker's mailbox, badarg crash *)
(*     in send_to_port -- into an immediate {error, worker_died} return.   *)
(*  2. cancel_async removes the request from Reqs BEFORE port_command and  *)
(*     swallows badarg, so a cancel against a dead port neither crashes    *)
(*     the worker nor lets terminate/2 message a cancelled caller.         *)
(*                                                                         *)
(* delivered[r] counts terminal outcomes for r: an async message from the  *)
(* worker OR an {error, worker_died} return from async_req itself.         *)
(*                                                                         *)
(* See Katipo.tla for the pre-fix model, whose counterexamples motivated   *)
(* these changes; all properties that failed there are expected to hold    *)
(* here.                                                                   *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
  Refs,          \* model values: one per async request
  MaxPortDeaths  \* bound on spontaneous port deaths (state-space bound)

VARIABLES
  wAlive,     \* worker process alive & registered
  pAlive,     \* current incarnation's port open
  wQ,         \* worker mailbox (sequence)
  pQ,         \* worker -> port command pipe (sequence)
  reqs,       \* worker's Reqs map: refs with an in-flight async entry
  timerFired, \* refs whose request timer has already fired
  conns,      \* C side: in-flight transfers
  sent,       \* refs for which the caller has issued async_req
  cancelled,  \* refs for which the caller has issued cancel
  delivered,  \* [Refs -> Nat] terminal outcomes received by the caller
  effCancel,  \* refs whose cancel was processed while the request was held
  effCancelSnap,   \* [Refs -> Nat] delivered[r] when the cancel took effect
  deaths,          \* port deaths so far
  cancelPollution  \* TRUE if processing a cancel itself caused a delivery

vars == <<wAlive, pAlive, wQ, pQ, reqs, timerFired, conns, sent, cancelled,
          delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

ReqMsg(r)     == <<"req", r>>
CancelMsg(r)  == <<"cancel", r>>
RespMsg(r)    == <<"resp", r>>
TimeoutMsg(r) == <<"timeout", r>>
ExitMsg       == <<"exit">>

Init ==
  /\ wAlive = TRUE /\ pAlive = TRUE
  /\ wQ = <<>> /\ pQ = <<>>
  /\ reqs = {} /\ timerFired = {} /\ conns = {}
  /\ sent = {} /\ cancelled = {}
  /\ delivered = [r \in Refs |-> 0]
  /\ effCancel = {} /\ effCancelSnap = [r \in Refs |-> 0]
  /\ deaths = 0
  /\ cancelPollution = FALSE

\* Admission calls still sitting in a queue: when the worker dies, each
\* caller's gen_server:call monitor fires and async_req returns
\* {error, worker_died} -- a terminal outcome.
QueuedCalls(q) == {r \in Refs: \E i \in DOMAIN q: q[i] = ReqMsg(r)}

\* Terminal outcomes when the worker dies with queue q: terminate/2 messages
\* every entry in Reqs, and every queued admission call errors out through
\* its monitor. A ref is never in both (it leaves the queue when it enters
\* Reqs).
CrashedDelivered(q) ==
  [r \in Refs |->
     IF r \in reqs \/ r \in QueuedCalls(q) THEN delivered[r] + 1
                                           ELSE delivered[r]]

(* ----------------------------- caller ----------------------------------*)

\* katipo:async_req -> wpool:call(..., random_worker, infinity). To a live
\* worker the call is enqueued; to a dead/restarting name gen_server:call
\* exits noproc at once and async_req returns {error, worker_died}.
SendAsync(r) ==
  /\ r \notin sent
  /\ sent' = sent \cup {r}
  /\ IF wAlive
     THEN /\ wQ' = Append(wQ, ReqMsg(r))
          /\ UNCHANGED delivered
     ELSE /\ delivered' = [delivered EXCEPT ![r] = @ + 1]
          /\ UNCHANGED wQ
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, conns, cancelled,
                 effCancel, effCancelSnap, deaths, cancelPollution>>

\* katipo:cancel/2 -> wpool:broadcast: still a cast, dropped if dead. Only
\* refs whose admission call returned {ok, Ref} can be cancelled.
SendCancel(r) ==
  /\ r \in sent /\ r \notin cancelled
  /\ r \notin QueuedCalls(wQ)  \* async_req has returned
  /\ cancelled' = cancelled \cup {r}
  /\ wQ' = IF wAlive THEN Append(wQ, CancelMsg(r)) ELSE wQ
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, conns, sent,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

(* ----------------------------- worker ----------------------------------*)

\* handle_call({async_req, ...}): send_to_port, then insert into Reqs, then
\* reply ok (insert and reply have no crash point between them). If the
\* port is closed, badarg crashes the worker BEFORE the insert: terminate/2
\* covers the old entries, the callers of every queued admission call --
\* including this one -- get {error, worker_died} from their monitors.
WorkerRecvReq(r) ==
  /\ wAlive /\ wQ # <<>> /\ Head(wQ) = ReqMsg(r)
  /\ IF pAlive
     THEN /\ wQ' = Tail(wQ)
          /\ pQ' = Append(pQ, ReqMsg(r))
          /\ reqs' = reqs \cup {r}
          /\ UNCHANGED <<wAlive, pAlive, timerFired, conns, sent, cancelled,
                         delivered, effCancel, effCancelSnap, deaths,
                         cancelPollution>>
     ELSE /\ delivered' = CrashedDelivered(wQ)  \* includes r, still queued
          /\ wAlive' = FALSE /\ pAlive' = FALSE
          /\ wQ' = <<>> /\ pQ' = <<>> /\ reqs' = {} /\ conns' = {}
          /\ UNCHANGED <<timerFired, sent, cancelled, effCancel,
                         effCancelSnap, deaths, cancelPollution>>

\* handle_cast({cancel, Ref}) -> cancel_async (FIXED): cancel_timer, then
\* maps:remove, then a best-effort port_command with badarg swallowed. The
\* worker survives a cancel against a dead port and the request is out of
\* Reqs either way.
WorkerRecvCancel(r) ==
  /\ wAlive /\ wQ # <<>> /\ Head(wQ) = CancelMsg(r)
  /\ wQ' = Tail(wQ)
  /\ IF r \in reqs
     THEN /\ reqs' = reqs \ {r}
          /\ effCancel' = effCancel \cup {r}
          /\ effCancelSnap' = [effCancelSnap EXCEPT ![r] = delivered[r]]
          /\ pQ' = IF pAlive THEN Append(pQ, CancelMsg(r)) ELSE pQ
     ELSE /\ UNCHANGED <<reqs, effCancel, effCancelSnap, pQ>>
  /\ UNCHANGED <<wAlive, pAlive, timerFired, conns, sent, cancelled,
                 delivered, deaths, cancelPollution>>

\* handle_info({Port, {data, ...}}): deliver iff still in Reqs, else drop.
WorkerRecvResp(r) ==
  /\ wAlive /\ wQ # <<>> /\ Head(wQ) = RespMsg(r)
  /\ wQ' = Tail(wQ)
  /\ IF r \in reqs
     THEN /\ delivered' = [delivered EXCEPT ![r] = @ + 1]
          /\ reqs' = reqs \ {r}
     ELSE UNCHANGED <<delivered, reqs>>
  /\ UNCHANGED <<wAlive, pAlive, pQ, timerFired, conns, sent, cancelled,
                 effCancel, effCancelSnap, deaths, cancelPollution>>

\* handle_info({timeout, Tref, {req_timeout, From}}): deliver iff in Reqs.
WorkerRecvTimeout(r) ==
  /\ wAlive /\ wQ # <<>> /\ Head(wQ) = TimeoutMsg(r)
  /\ wQ' = Tail(wQ)
  /\ IF r \in reqs
     THEN /\ delivered' = [delivered EXCEPT ![r] = @ + 1]
          /\ reqs' = reqs \ {r}
     ELSE UNCHANGED <<delivered, reqs>>
  /\ UNCHANGED <<wAlive, pAlive, pQ, timerFired, conns, sent, cancelled,
                 effCancel, effCancelSnap, deaths, cancelPollution>>

\* handle_info({'EXIT', Port, _}) -> {stop, port_died} -> terminate/2.
\* Queued admission calls error out via their monitors.
WorkerRecvExit ==
  /\ wAlive /\ wQ # <<>> /\ Head(wQ) = ExitMsg
  /\ delivered' = CrashedDelivered(wQ)
  /\ wAlive' = FALSE /\ pAlive' = FALSE
  /\ wQ' = <<>> /\ pQ' = <<>> /\ reqs' = {} /\ conns' = {}
  /\ UNCHANGED <<timerFired, sent, cancelled, effCancel, effCancelSnap,
                 deaths, cancelPollution>>

TimerFire(r) ==
  /\ wAlive /\ r \in reqs /\ r \notin timerFired
  /\ timerFired' = timerFired \cup {r}
  /\ wQ' = Append(wQ, TimeoutMsg(r))
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, conns, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

WorkerRestart ==
  /\ ~wAlive
  /\ wAlive' = TRUE /\ pAlive' = TRUE
  /\ wQ' = <<>> /\ pQ' = <<>> /\ reqs' = {} /\ conns' = {}
  /\ UNCHANGED <<timerFired, sent, cancelled, delivered, effCancel,
                 effCancelSnap, deaths, cancelPollution>>

(* ----------------------------- C port -----------------------------------*)

PortRecvReq(r) ==
  /\ pAlive /\ pQ # <<>> /\ Head(pQ) = ReqMsg(r)
  /\ pQ' = Tail(pQ)
  /\ conns' = conns \cup {r}
  /\ UNCHANGED <<wAlive, pAlive, wQ, reqs, timerFired, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

PortRecvCancel(r) ==
  /\ pAlive /\ pQ # <<>> /\ Head(pQ) = CancelMsg(r)
  /\ pQ' = Tail(pQ)
  /\ conns' = conns \ {r}
  /\ UNCHANGED <<wAlive, pAlive, wQ, reqs, timerFired, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

PortComplete(r) ==
  /\ pAlive /\ r \in conns
  /\ conns' = conns \ {r}
  /\ wQ' = Append(wQ, RespMsg(r))
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

PortDies ==
  /\ wAlive /\ pAlive /\ deaths < MaxPortDeaths
  /\ pAlive' = FALSE
  /\ deaths' = deaths + 1
  /\ conns' = {} /\ pQ' = <<>>
  /\ wQ' = Append(wQ, ExitMsg)
  /\ UNCHANGED <<wAlive, reqs, timerFired, sent, cancelled, delivered,
                 effCancel, effCancelSnap, cancelPollution>>

(* ----------------------------- spec -------------------------------------*)

WorkerDispatch ==
  \/ \E r \in Refs: WorkerRecvReq(r) \/ WorkerRecvCancel(r)
                 \/ WorkerRecvResp(r) \/ WorkerRecvTimeout(r)
  \/ WorkerRecvExit

PortDispatch == \E r \in Refs: PortRecvReq(r) \/ PortRecvCancel(r)

Environment ==
  \/ \E r \in Refs: SendAsync(r) \/ SendCancel(r) \/ PortComplete(r)
  \/ PortDies

Next ==
  \/ Environment
  \/ WorkerDispatch
  \/ PortDispatch
  \/ \E r \in Refs: TimerFire(r)
  \/ WorkerRestart

Fairness ==
  /\ WF_vars(WorkerDispatch)
  /\ WF_vars(PortDispatch)
  /\ WF_vars(WorkerRestart)
  /\ \A r \in Refs: WF_vars(TimerFire(r))

Spec == Init /\ [][Next]_vars /\ Fairness

(* --------------------------- properties ---------------------------------*)

TypeOK ==
  /\ wAlive \in BOOLEAN /\ pAlive \in BOOLEAN
  /\ reqs \subseteq Refs /\ conns \subseteq Refs
  /\ sent \subseteq Refs /\ cancelled \subseteq Refs
  /\ timerFired \subseteq Refs /\ effCancel \subseteq Refs
  /\ delivered \in [Refs -> Nat]
  /\ deaths \in 0..MaxPortDeaths
  /\ (pAlive => wAlive)

AtMostOneDelivery == \A r \in Refs: delivered[r] <= 1

NoDeliveryAfterEffectiveCancel ==
  \A r \in effCancel: delivered[r] = effCancelSnap[r]

NoCancelPollution == cancelPollution = FALSE

EventualOutcome ==
  \A r \in Refs: (r \in sent) ~> (delivered[r] > 0 \/ r \in cancelled)

=============================================================================
