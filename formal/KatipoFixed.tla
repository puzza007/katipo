--------------------------- MODULE KatipoFixed ---------------------------
(***************************************************************************)
(* Model of katipo's async request path AFTER the dispatch fixes:          *)
(*                                                                         *)
(*  1. async_req admission is a gen_server CALL (wpool:call), so the       *)
(*     caller's monitor converts every dispatch failure -- dead/restarting *)
(*     worker name, call lost in a crashing worker's mailbox, badarg crash *)
(*     in send_to_port -- into an immediate {error, worker_died} return.   *)
(*  2. the cancel handler removes the request from Reqs and only then      *)
(*     writes the best-effort port abort (badarg swallowed), so a cancel   *)
(*     against a dead port neither crashes the worker nor lets             *)
(*     terminate/2 message a cancelled caller.                             *)
(*                                                                         *)
(* delivered[r] counts terminal outcomes for r: an async message from the  *)
(* worker OR an {error, worker_died} return from async_req itself.         *)
(*                                                                         *)
(* See Katipo.tla for the pre-fix model, whose counterexamples motivated   *)
(* these changes; all properties that failed there are expected to hold    *)
(* here.                                                                   *)
(*                                                                         *)
(* Admission-capacity rejection (max_in_flight) is not modeled: a full    *)
(* worker replies {overload, Pid} before touching the port or Reqs -- a    *)
(* strict restriction of WorkerRecvReq that adds no delivery paths.        *)
(*                                                                         *)
(* The bounded admission call (?ADMISSION_TIMEOUT) IS modeled, behind      *)
(* CallerTimeouts: the caller's gen_server:call may time out while its     *)
(* async_req message is still queued (or mid-admission) in the worker's    *)
(* mailbox. gen_server:call cannot withdraw that message, so unless the    *)
(* worker refuses stale admissions (DeadlineCheck) it admits a request     *)
(* whose caller was already told {error, admission_timeout}, and the       *)
(* request later produces a terminal message too. Admission is split into  *)
(* three worker steps mirroring katipo_worker:admit_call/3 -- dequeue +    *)
(* pre-check + send_to_port, post-check, register + reply -- so the race   *)
(* between the post-check and the caller's timer is explicit; see          *)
(* ReplyWithinSlack.                                                       *)
(*                                                                         *)
(* Streaming flow control (stream_window/update_flow) is not modeled       *)
(* explicitly: credits only gate when the port may emit a progress message *)
(* (a strict restriction of PortEmitChunk below) and flow commands only    *)
(* increment a port-side counter, so it removes behaviors from this spec   *)
(* without adding caller-facing message kinds. Safety properties are       *)
(* preserved under behavior restriction, and EventualOutcome does not      *)
(* depend on chunk emission (a stalled transfer resolves via TimerFire).   *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
  Refs,          \* model values: one per async request
  MaxPortDeaths, \* bound on spontaneous port deaths (state-space bound)
  MaxChunks,     \* bound on streaming progress messages per transfer
  \* TRUE: the caller's bounded admission call may time out
  \* (katipo:attempt/3 -> admission_timeout) while the worker has not yet
  \* replied. FALSE: the pre-#185 unbounded call.
  CallerTimeouts,
  \* TRUE: the async_req message carries a deadline and the worker refuses
  \* (replies `expired`, registers nothing) once it has passed -- checked
  \* before send_to_port and again after it, aborting the just-sent
  \* transfer. FALSE: the worker admits whatever reaches it.
  DeadlineCheck,
  \* Assumption: once the worker's post-check passes, its reply reaches the
  \* caller before the caller's timer fires. The caller waits
  \* ?ADMISSION_SLACK longer than the deadline it stamps, and the segment
  \* between post-check and reply (start_timer, map insert, alias, reply)
  \* never blocks, so this holds unless that segment is descheduled for
  \* longer than the slack. FALSE lets TLC exhibit that residual race.
  ReplyWithinSlack

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
  cancelPollution, \* TRUE if processing a cancel itself caused a delivery
  chunksEmitted,   \* [Refs -> Nat] streaming progress messages sent by port
  progressStop,    \* TRUE if a progress message was delivered after the
                   \* request was cancelled or terminally resolved
  pending,    \* refs whose admission call is outstanding (caller waiting)
  accepted,   \* refs whose async_req returned {ok, Ref}
  gaveUp,     \* refs whose async_req returned {error, admission_timeout}
              \* from the caller's own timer
  expired,    \* refs whose admission deadline has passed
  admitPhase, \* worker inside admit_call: "idle" | "sent" | "checked"
  admitRef    \* the ref being admitted (meaningful unless "idle")

admitVars == <<pending, accepted, gaveUp, expired, admitPhase, admitRef>>

vars == <<wAlive, pAlive, wQ, pQ, reqs, timerFired, conns, sent, cancelled,
          delivered, effCancel, effCancelSnap, deaths, cancelPollution,
          chunksEmitted, progressStop, admitVars>>

ReqMsg(r)     == <<"req", r>>
CancelMsg(r)  == <<"cancel", r>>
RespMsg(r)    == <<"resp", r>>
ChunkMsg(r)   == <<"chunk", r>>
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
  /\ chunksEmitted = [r \in Refs |-> 0]
  /\ progressStop = FALSE
  /\ pending = {} /\ accepted = {} /\ gaveUp = {} /\ expired = {}
  /\ admitPhase = "idle" /\ admitRef = CHOOSE r \in Refs: TRUE

\* Terminal outcomes when the worker dies: terminate/2 messages every entry
\* in Reqs, and every caller still waiting on its admission call gets
\* {error, worker_died} from its call monitor. A ref is never in both (it
\* leaves `pending` in the same step it enters Reqs). Callers that already
\* gave up have no monitor left, so their queued calls vanish silently.
CrashedDelivered ==
  [r \in Refs |->
     IF r \in reqs \/ r \in pending THEN delivered[r] + 1 ELSE delivered[r]]

\* Worker death: everything the incarnation held is gone.
Crash ==
  /\ delivered' = CrashedDelivered
  /\ wAlive' = FALSE /\ pAlive' = FALSE
  /\ wQ' = <<>> /\ pQ' = <<>> /\ reqs' = {} /\ conns' = {}
  /\ pending' = {} /\ admitPhase' = "idle"
  /\ UNCHANGED <<accepted, gaveUp, expired, admitRef>>

\* The worker answers the admission call with `expired` (attempt/3 maps it
\* to admission_timeout). Terminal for the caller iff it is still waiting.
ReplyExpired(r) ==
  /\ pending' = pending \ {r}
  /\ delivered' = IF r \in pending THEN [delivered EXCEPT ![r] = @ + 1]
                                    ELSE delivered

(* ----------------------------- caller ----------------------------------*)

\* katipo:async_req -> wpool:call(..., random_worker, infinity). To a live
\* worker the call is enqueued; to a dead/restarting name gen_server:call
\* exits noproc at once and async_req returns {error, worker_died}.
SendAsync(r) ==
  /\ r \notin sent
  /\ sent' = sent \cup {r}
  /\ IF wAlive
     THEN /\ wQ' = Append(wQ, ReqMsg(r))
          /\ pending' = pending \cup {r}
          /\ UNCHANGED delivered
     ELSE /\ delivered' = [delivered EXCEPT ![r] = @ + 1]
          /\ UNCHANGED <<wQ, pending>>
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, conns, cancelled,
                 effCancel, effCancelSnap, deaths, cancelPollution, chunksEmitted, progressStop,
                 accepted, gaveUp, expired, admitPhase, admitRef>>

\* Wall-clock time passes the deadline of an outstanding admission call.
Expire(r) ==
  /\ CallerTimeouts \/ DeadlineCheck
  /\ r \in pending /\ r \notin expired
  /\ expired' = expired \cup {r}
  /\ UNCHANGED <<wAlive, pAlive, wQ, pQ, reqs, timerFired, conns, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution,
                 chunksEmitted, progressStop, pending, accepted, gaveUp,
                 admitPhase, admitRef>>

\* katipo:attempt/3: the bounded wpool call times out -> async_req returns
\* {error, admission_timeout}. The caller's async_req message stays in the
\* worker's mailbox (or the worker is mid-admission); its reply alias is
\* deactivated, so any later reply is dropped.
CallerTimeout(r) ==
  /\ CallerTimeouts
  /\ r \in pending /\ r \in expired
  /\ ReplyWithinSlack => ~(admitPhase = "checked" /\ admitRef = r)
  /\ pending' = pending \ {r}
  /\ gaveUp' = gaveUp \cup {r}
  /\ delivered' = [delivered EXCEPT ![r] = @ + 1]
  /\ UNCHANGED <<wAlive, pAlive, wQ, pQ, reqs, timerFired, conns, sent, cancelled,
                 effCancel, effCancelSnap, deaths, cancelPollution,
                 chunksEmitted, progressStop, accepted, expired,
                 admitPhase, admitRef>>

\* katipo:cancel/2: a direct send to the request's alias Ref, delivered
\* iff the owning worker is alive (the alias dies with it -- same drop
\* semantics the old broadcast-cast had). Only refs whose admission call
\* returned {ok, Ref} can be cancelled.
SendCancel(r) ==
  /\ r \in accepted /\ r \notin cancelled  \* async_req returned {ok, Ref}
  /\ cancelled' = cancelled \cup {r}
  /\ wQ' = IF wAlive THEN Append(wQ, CancelMsg(r)) ELSE wQ
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, conns, sent,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution, chunksEmitted, progressStop,
                 admitVars>>

(* ----------------------------- worker ----------------------------------*)

\* handle_call({async_req, ...}) -> admit_call, step 1: dequeue; refuse an
\* already-expired call without touching the port (pre-check); otherwise
\* send_to_port. If the port is closed, badarg crashes the worker BEFORE
\* anything is registered: terminate/2 covers the Reqs entries, and every
\* waiting caller -- including this one -- gets {error, worker_died} from
\* its monitor.
WorkerRecvReq(r) ==
  /\ wAlive /\ admitPhase = "idle" /\ wQ # <<>> /\ Head(wQ) = ReqMsg(r)
  /\ IF DeadlineCheck /\ r \in expired
     THEN /\ wQ' = Tail(wQ)
          /\ ReplyExpired(r)
          /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, conns, admitPhase, admitRef>>
     ELSE IF pAlive
     THEN /\ wQ' = Tail(wQ)
          /\ pQ' = Append(pQ, ReqMsg(r))
          /\ admitPhase' = "sent" /\ admitRef' = r
          /\ UNCHANGED <<wAlive, pAlive, reqs, conns, delivered, pending>>
     ELSE Crash
  /\ UNCHANGED <<timerFired, sent, cancelled, effCancel, effCancelSnap,
                 deaths, cancelPollution, chunksEmitted, progressStop,
                 accepted, gaveUp, expired>>

\* admit_call step 2, post-check: send_to_port may have blocked past the
\* deadline (a pipe the C side stopped draining). If so, abort the
\* just-sent transfer and refuse.
WorkerAdmitCheck ==
  /\ wAlive /\ admitPhase = "sent"
  /\ LET r == admitRef IN
     IF DeadlineCheck /\ r \in expired
     THEN /\ pQ' = IF pAlive THEN Append(pQ, CancelMsg(r)) ELSE pQ
          /\ ReplyExpired(r)
          /\ admitPhase' = "idle"
     ELSE /\ admitPhase' = "checked"
          /\ UNCHANGED <<pQ, delivered, pending>>
  /\ UNCHANGED <<wAlive, pAlive, wQ, reqs, timerFired, conns, sent, cancelled,
                 effCancel, effCancelSnap, deaths, cancelPollution,
                 chunksEmitted, progressStop, accepted, gaveUp, expired, admitRef>>

\* admit_call step 3: start the request timer, insert into Reqs, reply with
\* the alias. No crash point. A caller that gave up never sees the reply,
\* but the request is now live and WILL produce a terminal message.
WorkerAdmitReply ==
  /\ wAlive /\ admitPhase = "checked"
  /\ LET r == admitRef IN
     /\ reqs' = reqs \cup {r}
     /\ pending' = pending \ {r}
     /\ accepted' = IF r \in pending THEN accepted \cup {r} ELSE accepted
  /\ admitPhase' = "idle"
  /\ UNCHANGED <<wAlive, pAlive, wQ, pQ, timerFired, conns, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution,
                 chunksEmitted, progressStop, gaveUp, expired, admitRef>>

\* abort_transfer/2: best-effort port_command of the cancel tuple with
\* badarg swallowed -- nothing to write if the port is dead. Shared by the
\* cancel and timeout paths, mirroring the code's shared helper.
AbortPQ(r) == IF pAlive THEN Append(pQ, CancelMsg(r)) ELSE pQ

\* handle_info({cancel, Ref}) (sent to the request's alias): cancel_timer,
\* remove from Reqs, deactivate the alias, then abort_transfer. The worker
\* survives a cancel against a dead port and the request is out of Reqs
\* either way.
WorkerRecvCancel(r) ==
  /\ wAlive /\ admitPhase = "idle" /\ wQ # <<>> /\ Head(wQ) = CancelMsg(r)
  /\ wQ' = Tail(wQ)
  /\ IF r \in reqs
     THEN /\ reqs' = reqs \ {r}
          /\ effCancel' = effCancel \cup {r}
          /\ effCancelSnap' = [effCancelSnap EXCEPT ![r] = delivered[r]]
          /\ pQ' = AbortPQ(r)
     ELSE /\ UNCHANGED <<reqs, effCancel, effCancelSnap, pQ>>
  /\ UNCHANGED <<wAlive, pAlive, timerFired, conns, sent, cancelled,
                 delivered, deaths, cancelPollution, chunksEmitted, progressStop,
                 admitVars>>

\* handle_info({Port, {data, ...}}): deliver iff still in Reqs, else drop.
WorkerRecvResp(r) ==
  /\ wAlive /\ admitPhase = "idle" /\ wQ # <<>> /\ Head(wQ) = RespMsg(r)
  /\ wQ' = Tail(wQ)
  /\ IF r \in reqs
     THEN /\ delivered' = [delivered EXCEPT ![r] = @ + 1]
          /\ reqs' = reqs \ {r}
     ELSE UNCHANGED <<delivered, reqs>>
  /\ UNCHANGED <<wAlive, pAlive, pQ, timerFired, conns, sent, cancelled,
                 effCancel, effCancelSnap, deaths, cancelPollution, chunksEmitted, progressStop,
                 admitVars>>

\* handle_info for a streaming progress message ({headers,...}/{chunk,...}):
\* forwarded to the reply_to iff the request is still in Reqs, else dropped
\* (timed out, cancelled, or already resolved). progressStop records the
\* impossible-by-construction case of forwarding after cancel/terminal.
WorkerRecvChunk(r) ==
  /\ wAlive /\ admitPhase = "idle" /\ wQ # <<>> /\ Head(wQ) = ChunkMsg(r)
  /\ wQ' = Tail(wQ)
  /\ IF r \in reqs
     THEN progressStop' = progressStop \/ r \in effCancel \/ delivered[r] > 0
     ELSE UNCHANGED progressStop
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, conns, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution,
                 chunksEmitted,
                 admitVars>>

\* handle_info({timeout, Tref, {req_timeout, From}}): deliver iff in Reqs,
\* and abort_transfer the still-running transfer in the port.
WorkerRecvTimeout(r) ==
  /\ wAlive /\ admitPhase = "idle" /\ wQ # <<>> /\ Head(wQ) = TimeoutMsg(r)
  /\ wQ' = Tail(wQ)
  /\ IF r \in reqs
     THEN /\ delivered' = [delivered EXCEPT ![r] = @ + 1]
          /\ reqs' = reqs \ {r}
          /\ pQ' = AbortPQ(r)
     ELSE UNCHANGED <<delivered, reqs, pQ>>
  /\ UNCHANGED <<wAlive, pAlive, timerFired, conns, sent, cancelled,
                 effCancel, effCancelSnap, deaths, cancelPollution, chunksEmitted, progressStop,
                 admitVars>>

\* handle_info({'EXIT', Port, _}) -> {stop, port_died} -> terminate/2.
\* Queued admission calls error out via their monitors.
WorkerRecvExit ==
  /\ wAlive /\ admitPhase = "idle" /\ wQ # <<>> /\ Head(wQ) = ExitMsg
  /\ Crash
  /\ UNCHANGED <<timerFired, sent, cancelled, effCancel, effCancelSnap,
                 deaths, cancelPollution, chunksEmitted, progressStop>>

TimerFire(r) ==
  /\ wAlive /\ r \in reqs /\ r \notin timerFired
  /\ timerFired' = timerFired \cup {r}
  /\ wQ' = Append(wQ, TimeoutMsg(r))
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, conns, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution, chunksEmitted, progressStop,
                 admitVars>>

WorkerRestart ==
  /\ ~wAlive
  /\ wAlive' = TRUE /\ pAlive' = TRUE
  /\ wQ' = <<>> /\ pQ' = <<>> /\ reqs' = {} /\ conns' = {}
  /\ UNCHANGED <<timerFired, sent, cancelled, delivered, effCancel,
                 effCancelSnap, deaths, cancelPollution, chunksEmitted, progressStop,
                 admitVars>>

(* ----------------------------- C port -----------------------------------*)

PortRecvReq(r) ==
  /\ pAlive /\ pQ # <<>> /\ Head(pQ) = ReqMsg(r)
  /\ pQ' = Tail(pQ)
  /\ conns' = conns \cup {r}
  /\ UNCHANGED <<wAlive, pAlive, wQ, reqs, timerFired, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution, chunksEmitted, progressStop,
                 admitVars>>

PortRecvCancel(r) ==
  /\ pAlive /\ pQ # <<>> /\ Head(pQ) = CancelMsg(r)
  /\ pQ' = Tail(pQ)
  /\ conns' = conns \ {r}
  /\ UNCHANGED <<wAlive, pAlive, wQ, reqs, timerFired, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution, chunksEmitted, progressStop,
                 admitVars>>

\* write_cb on a streaming transfer: forward a body chunk (headers behave
\* identically and are folded into the same message kind). Bounded per
\* transfer to keep the state space finite.
PortEmitChunk(r) ==
  /\ pAlive /\ r \in conns /\ chunksEmitted[r] < MaxChunks
  /\ chunksEmitted' = [chunksEmitted EXCEPT ![r] = @ + 1]
  /\ wQ' = Append(wQ, ChunkMsg(r))
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, conns, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution,
                 progressStop,
                 admitVars>>

PortComplete(r) ==
  /\ pAlive /\ r \in conns
  /\ conns' = conns \ {r}
  /\ wQ' = Append(wQ, RespMsg(r))
  /\ UNCHANGED <<wAlive, pAlive, pQ, reqs, timerFired, sent, cancelled,
                 delivered, effCancel, effCancelSnap, deaths, cancelPollution, chunksEmitted, progressStop,
                 admitVars>>

PortDies ==
  /\ wAlive /\ pAlive /\ deaths < MaxPortDeaths
  /\ pAlive' = FALSE
  /\ deaths' = deaths + 1
  /\ conns' = {} /\ pQ' = <<>>
  /\ wQ' = Append(wQ, ExitMsg)
  /\ UNCHANGED <<wAlive, reqs, timerFired, sent, cancelled, delivered,
                 effCancel, effCancelSnap, cancelPollution, chunksEmitted, progressStop,
                 admitVars>>

(* ----------------------------- spec -------------------------------------*)

WorkerDispatch ==
  \/ \E r \in Refs: WorkerRecvReq(r) \/ WorkerRecvCancel(r)
                 \/ WorkerRecvResp(r) \/ WorkerRecvTimeout(r)
                 \/ WorkerRecvChunk(r)
  \/ WorkerRecvExit
  \/ WorkerAdmitCheck
  \/ WorkerAdmitReply

PortDispatch == \E r \in Refs: PortRecvReq(r) \/ PortRecvCancel(r)

Environment ==
  \/ \E r \in Refs: SendAsync(r) \/ SendCancel(r) \/ PortComplete(r)
                  \/ PortEmitChunk(r) \/ Expire(r) \/ CallerTimeout(r)
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
  /\ pending \subseteq sent /\ accepted \subseteq sent
  /\ gaveUp \subseteq expired /\ admitPhase \in {"idle", "sent", "checked"}

AtMostOneDelivery == \A r \in Refs: delivered[r] <= 1

NoDeliveryAfterEffectiveCancel ==
  \A r \in effCancel: delivered[r] = effCancelSnap[r]

NoCancelPollution == cancelPollution = FALSE

\* Safety: no streaming progress message reaches the caller after the
\* request was cancelled or terminally resolved.
NoProgressAfterStop == progressStop = FALSE

\* The documented admission contract: an async_req that returned an error
\* never also yields a message. Implied by AtMostOneDelivery (the error
\* return is counted), stated separately so a violation names the cause.
NoMessageAfterAdmissionError ==
  \A r \in gaveUp: delivered[r] = 1 /\ r \notin reqs

\* Every transfer running in the C port is owned: tracked in Reqs, being
\* admitted, or with an abort already queued for it. An orphan would run
\* to completion (side effects included) with nobody to deliver to.
NoOrphanTransfer ==
  \A r \in conns:
     \/ r \in reqs
     \/ admitPhase # "idle" /\ admitRef = r
     \/ \E i \in DOMAIN pQ: pQ[i] = CancelMsg(r)

\* Anti-vacuity: the configs must actually reach late/refused admissions.
\* Checked with -inv (expected VIOLATED) as reachability witnesses.
WitnessGaveUpQueued == ~(\E r \in gaveUp: \E i \in DOMAIN wQ: wQ[i] = ReqMsg(r))
WitnessAdmitChecked == admitPhase # "checked"

\* Refs are interchangeable model values: safety-only configs may declare
\* SYMMETRY RefPerms (never a liveness config -- unsound there).
RefPerms == Permutations(Refs)

EventualOutcome ==
  \A r \in Refs: (r \in sent) ~> (delivered[r] > 0 \/ r \in cancelled)

=============================================================================
