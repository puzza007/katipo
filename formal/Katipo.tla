------------------------------ MODULE Katipo ------------------------------
(***************************************************************************)
(* Formal model of katipo's async request path:                            *)
(*                                                                         *)
(*   caller --cast--> katipo_worker (gen_server) --pipe--> C port/libcurl  *)
(*                                                                         *)
(* Modeled from src/katipo_worker.erl, src/katipo.erl and c_src/katipo.c:  *)
(*   - async_req dispatch (wpool:cast to a registered name)                *)
(*   - the worker's Reqs map and per-request erlang:start_timer timers     *)
(*   - response/timeout delivery to the ReplyTo mailbox                    *)
(*   - cancel (wpool:broadcast cast; port_command of a cancel tuple)       *)
(*   - port death (EXIT message), worker crash, supervisor restart         *)
(*                                                                         *)
(* Faithfulness notes:                                                     *)
(*   - Erlang local sends enqueue atomically at send time; per-sender-pair *)
(*     FIFO is therefore inherent in the queue representation.             *)
(*   - gen_server:cast to an unregistered name is silently dropped.        *)
(*   - port_command to a closed port raises badarg. In handle_cast this    *)
(*     happens BEFORE the request is added to Reqs (async_req) and BEFORE  *)
(*     maps:remove (cancel_async); wpool_process's try/catch only catches  *)
(*     throw-style control returns, so badarg crashes the worker and       *)
(*     gen_server runs terminate/2, which notifies only the entries then   *)
(*     in Reqs.                                                            *)
(*   - When a process dies its remaining mailbox is dropped; terminate     *)
(*     closes the port, aborting all in-flight transfers.                  *)
(*   - The sync path is not modeled: gen_server:call's monitor converts    *)
(*     any worker death into an exit that call_worker maps to worker_died. *)
(*                                                                         *)
(* Abstractions: one pool, one worker, single-use refs, curl errors and    *)
(* parse errors are folded into RespMsg (same delivery path as success).   *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
  Refs,          \* model values: one per async request
  MaxPortDeaths, \* bound on spontaneous port deaths (state-space bound)
  AllowDeadSend  \* whether the environment may async_req while the worker
                 \* is dead/restarting (toggled per-config to separate the
                 \* two liveness counterexample families)

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
  delivered,  \* [Refs -> Nat] terminal messages received by ReplyTo
  effCancel,  \* refs whose cancel was processed while the request was held
              \* (the "cancel took effect" point in the cancel/2 docs)
  effCancelSnap,   \* [Refs -> Nat] delivered[r] at the moment cancel took
                   \* effect, to check nothing arrives afterwards
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

(* ----------------------------- caller ----------------------------------*)

\* katipo:async_req/2 -> wpool:cast(Pool, ..., random_worker): a plain
\* gen_server:cast to the worker's registered name. If the worker is dead
\* (supervisor restarting it) the cast is silently dropped.
SendAsync(r) ==
  /\ r \notin sent
  /\ (wAlive \/ AllowDeadSend)
  /\ sent' = sent \cup {r}
  /\ wQ' = IF wAlive THEN Append(wQ, ReqMsg(r)) ELSE wQ
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, conns, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

\* katipo:cancel/2 -> wpool:broadcast: also a plain cast, dropped if dead.
\* Callers only cancel refs they hold, i.e. after async_req returned, and
\* async_req's cast is enqueued before it returns -- so a cancel can never
\* overtake its own request's cast.
SendCancel(r) ==
  /\ r \in sent /\ r \notin cancelled
  /\ cancelled' = cancelled \cup {r}
  /\ wQ' = IF wAlive THEN Append(wQ, CancelMsg(r)) ELSE wQ
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, conns, sent,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

(* ----------------------------- worker ----------------------------------*)

\* katipo_worker:terminate/2 (reached via gen_server on stop or crash):
\* notify_worker_died for every async entry still in Reqs; the process dies,
\* so its remaining mailbox is dropped and port_close aborts all transfers.
CrashedDelivered ==
  [r \in Refs |-> IF r \in reqs THEN delivered[r] + 1 ELSE delivered[r]]

\* handle_cast({async_req, ...}): send_to_port THEN start_timer THEN add to
\* Reqs. If the port is already closed, port_command raises badarg first:
\* the worker crashes and terminate covers old entries -- but NOT this one.
WorkerRecvReq(r) ==
  /\ wAlive /\ wQ # <<>> /\ Head(wQ) = ReqMsg(r)
  /\ IF pAlive
     THEN /\ wQ' = Tail(wQ)
          /\ pQ' = Append(pQ, ReqMsg(r))
          /\ reqs' = reqs \cup {r}
          /\ UNCHANGED <<wAlive, pAlive, timerFired, conns, sent, cancelled,
                         delivered, effCancel, effCancelSnap, deaths,
                         cancelPollution>>
     ELSE /\ delivered' = CrashedDelivered
          /\ wAlive' = FALSE /\ pAlive' = FALSE
          /\ wQ' = <<>> /\ pQ' = <<>> /\ reqs' = {} /\ conns' = {}
          /\ UNCHANGED <<timerFired, sent, cancelled, effCancel,
                         effCancelSnap, deaths, cancelPollution>>

\* handle_cast({cancel, Ref}) -> cancel_async: cancel_timer, then
\* port_command(cancel tuple) -- the crash point -- then maps:remove.
\* On badarg the worker crashes with the request STILL in Reqs, so
\* terminate delivers worker_died to a caller who cancelled.
WorkerRecvCancel(r) ==
  /\ wAlive /\ wQ # <<>> /\ Head(wQ) = CancelMsg(r)
  /\ IF r \in reqs
     THEN IF pAlive
          THEN /\ wQ' = Tail(wQ)
               /\ pQ' = Append(pQ, CancelMsg(r))
               /\ reqs' = reqs \ {r}
               /\ effCancel' = effCancel \cup {r}
               /\ effCancelSnap' = [effCancelSnap EXCEPT ![r] = delivered[r]]
               /\ UNCHANGED <<wAlive, pAlive, timerFired, conns, sent,
                              cancelled, delivered, deaths, cancelPollution>>
          ELSE /\ delivered' = CrashedDelivered  \* includes r!
               /\ cancelPollution' = TRUE
               /\ wAlive' = FALSE /\ pAlive' = FALSE
               /\ wQ' = <<>> /\ pQ' = <<>> /\ reqs' = {} /\ conns' = {}
               /\ UNCHANGED <<timerFired, sent, cancelled, effCancel,
                              effCancelSnap, deaths>>
     ELSE \* find_async miss: harmless no-op
          /\ wQ' = Tail(wQ)
          /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, conns, sent,
                         cancelled, delivered, effCancel, effCancelSnap,
                         deaths, cancelPollution>>

\* handle_info({Port, {data, ...}}): deliver iff From is still in Reqs,
\* else drop silently (late response after timeout/cancel).
WorkerRecvResp(r) ==
  /\ wAlive /\ wQ # <<>> /\ Head(wQ) = RespMsg(r)
  /\ wQ' = Tail(wQ)
  /\ IF r \in reqs
     THEN /\ delivered' = [delivered EXCEPT ![r] = @ + 1]
          /\ reqs' = reqs \ {r}
     ELSE UNCHANGED <<delivered, reqs>>
  /\ UNCHANGED <<wAlive, pAlive, pQ, timerFired, conns, sent, cancelled,
                 effCancel, effCancelSnap, deaths, cancelPollution>>

\* handle_info({timeout, Tref, {req_timeout, From}}): deliver
\* operation_timedout iff still in Reqs (Tref match), else ignore.
WorkerRecvTimeout(r) ==
  /\ wAlive /\ wQ # <<>> /\ Head(wQ) = TimeoutMsg(r)
  /\ wQ' = Tail(wQ)
  /\ IF r \in reqs
     THEN /\ delivered' = [delivered EXCEPT ![r] = @ + 1]
          /\ reqs' = reqs \ {r}
     ELSE UNCHANGED <<delivered, reqs>>
  /\ UNCHANGED <<wAlive, pAlive, pQ, timerFired, conns, sent, cancelled,
                 effCancel, effCancelSnap, deaths, cancelPollution>>

\* handle_info({'EXIT', Port, _}) -> {stop, port_died, State} -> terminate.
WorkerRecvExit ==
  /\ wAlive /\ wQ # <<>> /\ Head(wQ) = ExitMsg
  /\ delivered' = CrashedDelivered
  /\ wAlive' = FALSE /\ pAlive' = FALSE
  /\ wQ' = <<>> /\ pQ' = <<>> /\ reqs' = {} /\ conns' = {}
  /\ UNCHANGED <<timerFired, sent, cancelled, effCancel, effCancelSnap,
                 deaths, cancelPollution>>

\* erlang:start_timer fires: the timeout message lands in the worker's
\* mailbox at some arbitrary later point. Fires at most once per request.
TimerFire(r) ==
  /\ wAlive /\ r \in reqs /\ r \notin timerFired
  /\ timerFired' = timerFired \cup {r}
  /\ wQ' = Append(wQ, TimeoutMsg(r))
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, conns, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

\* wpool's supervisor restarts the worker: fresh process, fresh port,
\* empty state. Casts sent while it was down are gone.
WorkerRestart ==
  /\ ~wAlive
  /\ wAlive' = TRUE /\ pAlive' = TRUE
  /\ wQ' = <<>> /\ pQ' = <<>> /\ reqs' = {} /\ conns' = {}
  /\ UNCHANGED <<timerFired, sent, cancelled, delivered, effCancel,
                 effCancelSnap, deaths, cancelPollution>>

(* ----------------------------- C port -----------------------------------*)

\* erl_input decodes an 8-tuple request: new_conn registers the transfer.
PortRecvReq(r) ==
  /\ pAlive /\ pQ # <<>> /\ Head(pQ) = ReqMsg(r)
  /\ pQ' = Tail(pQ)
  /\ conns' = conns \cup {r}
  /\ UNCHANGED <<wAlive, pAlive, wQ, reqs, timerFired, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

\* erl_input decodes {Pid, Ref, cancel}: cancel_conn frees the transfer if
\* still active; no response is ever sent for it. No-op if already done.
PortRecvCancel(r) ==
  /\ pAlive /\ pQ # <<>> /\ Head(pQ) = CancelMsg(r)
  /\ pQ' = Tail(pQ)
  /\ conns' = conns \ {r}
  /\ UNCHANGED <<wAlive, pAlive, wQ, reqs, timerFired, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

\* check_multi_info: transfer finishes (success OR curl error, including
\* curl's own TIMEOUT_MS) -> exactly one response written to the pipe.
PortComplete(r) ==
  /\ pAlive /\ r \in conns
  /\ conns' = conns \ {r}
  /\ wQ' = Append(wQ, RespMsg(r))
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution>>

\* The C process dies (crash/OOM/killed): the port closes, the owning
\* worker (trap_exit) gets an EXIT message; all transfers vanish; pending
\* pipe commands are lost.
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

\* Fair: the scheduler runs the worker and port; timers fire; the
\* supervisor restarts dead workers. NOT fair: callers sending/cancelling,
\* transfers completing (they may hang -- that is what the timers are for),
\* ports dying.
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

\* Safety: a caller never receives two terminal messages for one Ref.
AtMostOneDelivery == \A r \in Refs: delivered[r] <= 1

\* Safety (documented cancel contract): once a cancel "takes effect" --
\* processed by the worker holding the request -- no further message for
\* that Ref is delivered.
NoDeliveryAfterEffectiveCancel ==
  \A r \in effCancel: delivered[r] = effCancelSnap[r]

\* Safety: processing a cancel must never itself cause a delivery for the
\* cancelled Ref.
NoCancelPollution == cancelPollution = FALSE

\* Liveness (library contract): every async request that is not cancelled
\* eventually produces exactly one terminal message: a response, an error,
\* operation_timedout, or worker_died.
EventualOutcome ==
  \A r \in Refs: (r \in sent) ~> (delivered[r] > 0 \/ r \in cancelled)

\* State constraint used by KatipoLiveness2.cfg: mask the badarg-crash
\* counterexample family (a req message pending while the port is closed)
\* so TLC surfaces the dropped-cast-while-restarting family instead.
NoReqPendingOnDeadPort ==
  ~(wAlive /\ ~pAlive /\ \E i \in DOMAIN wQ, r \in Refs: wQ[i] = ReqMsg(r))

=============================================================================
