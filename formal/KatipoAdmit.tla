------------------------------- MODULE KatipoAdmit -------------------------------
(***************************************************************************)
(* WHAT THIS MODELS. The async admission handshake at message granularity, *)
(* which KatipoReq treats as one atomic step. The subtle part: the         *)
(* caller's bounded gen_server call (?ADMISSION_TIMEOUT, katipo.erl        *)
(* pool_call/attempt) can time out while the admission message is already  *)
(* queued at the worker. The worker later admits anyway - registering the  *)
(* request with its reply_to - and its reply goes to a dead call alias.    *)
(* The request then resolves and delivers a terminal katipo_* message to   *)
(* reply_to, carrying a Ref the caller NEVER RECEIVED, although            *)
(* async_req's documentation promises that an {error, ...} return means    *)
(* "no message is delivered".                                              *)
(*                                                                         *)
(* Real code (file:line as of commit 06f0138):                             *)
(*   - src/katipo.erl     pool_call/attempt: exit:{timeout,_} caught with  *)
(*     Bound =/= infinity -> {error, admission_timeout} (~500..520); the   *)
(*     async_req doc's "no message is delivered" contract (~380..395)      *)
(*   - src/katipo_worker.erl  admit_call registers the request and replies *)
(*     the alias (~60..75); admit arms the timer (~80..92); the worker     *)
(*     comment "a request the worker admits after we gave up is cleaned    *)
(*     up by its own request timer" covers the worker's bookkeeping but    *)
(*     not the terminal message deliver/deliver_timeout then sends to      *)
(*     reply_to (~150..185)                                                *)
(*                                                                         *)
(* THE ACTORS:                                                             *)
(*   - worker - fair; takes the queued admission whenever it gets to it,   *)
(*     then resolves the registered request. Resolution is abstracted to   *)
(*     one exactly-once terminal delivery: that is the property KatipoReq  *)
(*     PROVED, imported here as an assumption.                             *)
(*   - caller - sends the call, then either consumes the reply or times    *)
(*     out; not fair (the timeout branch is always available, which is     *)
(*     the point).                                                         *)
(*                                                                         *)
(* ABSTRACTION CHOICES:                                                    *)
(*   - The fix (DeadlineCheck, now implemented): the caller stamps a       *)
(*     deadline into the message; the worker refuses admissions whose      *)
(*     deadline has passed. Modelled as "the worker sees whether the       *)
(*     caller has already timed out" - sound on one node where both read   *)
(*     the same monotonic clock, with the boundary instant collapsed.      *)
(*   - The late reply to a dead call alias is dropped by the runtime       *)
(*     (OTP 24+ aliases); modelled by the timed-out caller simply never    *)
(*     consuming replyQ.                                                   *)
(*                                                                         *)
(* SPAN OWNERSHIP (second question, same handshake). The caller starts the *)
(* OTel span / metrics observation (katipo_span:start_async) and hands it  *)
(* to the worker inside the admission message, so for a while BOTH hold    *)
(* it and neither can tell. Three things can go wrong, and counting        *)
(* finishes only catches the first:                                        *)
(*   - the same request is recorded twice (metrics double-count);          *)
(*   - the span is never closed (leak);                                    *)
(*   - it is closed exactly once, but with the WRONG outcome. This is the  *)
(*     one a bare counter cannot see. The caller can only ever record      *)
(*     `admission_timeout'; the worker holds the real result. If the       *)
(*     caller wins the claim for a request that actually ran, telemetry    *)
(*     permanently shows a timeout for a request that returned a status,   *)
(*     and the real outcome is silently dropped -- worse than the          *)
(*     double-count, because the surviving record is false. The caller     *)
(*     always wins that race in practice: it claims the instant its bound  *)
(*     elapses, the worker only at resolution.                             *)
(* So the model tracks WHO recorded WHAT, not how many times.              *)
(*                                                                         *)
(* The shipped design, which SpanFixed checks: the caller finishes only    *)
(* for overload / worker_died (no worker took the Obs); on an              *)
(* admission_timeout it finishes nothing, and whichever worker holds the   *)
(* Obs closes it -- with the real outcome if it admitted, or by ending the *)
(* span when it refuses the expired admission.                             *)
(*                                                                         *)
(* OUT OF SCOPE: everything downstream of admission (KatipoReq covers      *)
(* it); spillover retries (each attempt is one instance of this model);    *)
(* worker death during admission (KatipoReq covers the crash path).        *)
(***************************************************************************)
EXTENDS Naturals, TLC

CONSTANTS
    \* TRUE = the fix as implemented (katipo.erl stamp/2 stamps the deadline,
    \* katipo_worker.erl admit_call/expired refuses expired admissions).
    DeadlineCheck,
    \* TRUE = dispatch_async finishes the span on ANY error return,
    \* admission_timeout included (what katipo did before this fix).
    \* FALSE = as implemented: on an admission_timeout the caller finishes
    \* nothing, because it cannot know whether a worker took the Obs.
    CallerFinishesOnTimeout,
    \* TRUE = as implemented: katipo_span:claim/1's atomic makes the second
    \* and later finishes no-ops. FALSE = the pre-fix always-finish.
    Idempotent,
    \* TRUE = as implemented: the worker ends the span when it refuses an
    \* expired admission (katipo_worker:handle_call). FALSE shows that
    \* without it the span leaks whenever the caller stops finishing.
    WorkerEndsOnRefusal

(* --algorithm KatipoAdmit

variables
    admitQ     = "empty",    \* "empty" | "queued" | "taken"  (worker mailbox)
    callerSt   = "idle",     \* "idle" | "waiting" | "got_ref" | "timed_out"
    replyQ     = FALSE,      \* admission reply in flight to the call alias
    registered = FALSE,      \* the request made it into Reqs
    replyToMsgs = 0,         \* terminal katipo_* messages landed at reply_to
    lateAdmit  = FALSE,      \* ghost: worker admitted AFTER the caller gave up
    spanClaimed = FALSE,     \* katipo_span:claim/1 has been won
    spanFinishes = 0,        \* ghost: EFFECTIVE finishes (claims won)
    callerRecorded = FALSE,  \* the caller recorded an admission_timeout outcome
    workerRecorded = FALSE;  \* the worker recorded the request's real outcome

\* One katipo_span finish. Under Idempotent only the first claimant has any
\* effect; Who is "caller", "worker", or "none" (end_async records no
\* outcome, it just closes the span).
macro finish(Who) begin
  if ~Idempotent \/ ~spanClaimed then
    spanClaimed := TRUE;
    spanFinishes := spanFinishes + 1;
    if    Who = "caller" then callerRecorded := TRUE;
    elsif Who = "worker" then workerRecorded := TRUE;
    end if;
  end if;
end macro;

fair process worker = "worker"
begin
WAdmit:
  await admitQ = "queued";
  admitQ := "taken";
  if DeadlineCheck /\ callerSt = "timed_out" then
    \* fix: the deadline in the call has passed; refuse instead of admitting
    \* (the error reply would go to the dead alias and be dropped; nothing
    \* is registered, so nothing will ever reach reply_to). We hold the Obs
    \* and know no outcome will ever exist for it, so we close the span.
    if WorkerEndsOnRefusal then
      finish("none");
    end if;
  else
    registered := TRUE;
    replyQ := TRUE;
    lateAdmit := callerSt = "timed_out";
  end if;
WResolve:
  \* the whole request lifecycle, abstracted: KatipoReq proved an admitted
  \* request delivers EXACTLY ONE terminal message to reply_to (completion,
  \* curl error, its own request timer, or worker death - all collapse here)
  if registered then
    replyToMsgs := replyToMsgs + 1;
    \* every worker-side terminal path finishes the span it was handed,
    \* and it is the only party that knows the request's real outcome
    finish("worker");
  end if;
end process;

process caller = "caller"
begin
CSend:
  callerSt := "waiting";
  admitQ := "queued";
CWait:
  either
    \* the {ok, Ref} reply arrives in time
    await replyQ;
    callerSt := "got_ref";
  or
    \* ?ADMISSION_TIMEOUT fires: async_req returns {error, admission_timeout}
    \* and the call alias dies, so any late reply is dropped by the runtime
    callerSt := "timed_out";
    if CallerFinishesOnTimeout then
      finish("caller");
    end if;
  end either;
end process;

end algorithm; *)

\* Translate with:  java -cp tla2tools.jar pcal.trans formal/KatipoAdmit.tla

\* BEGIN TRANSLATION
VARIABLES admitQ, callerSt, replyQ, registered, replyToMsgs, lateAdmit, 
          spanClaimed, spanFinishes, callerRecorded, workerRecorded, pc

vars == << admitQ, callerSt, replyQ, registered, replyToMsgs, lateAdmit, 
           spanClaimed, spanFinishes, callerRecorded, workerRecorded, pc >>

ProcSet == {"worker"} \cup {"caller"}

Init == (* Global variables *)
        /\ admitQ = "empty"
        /\ callerSt = "idle"
        /\ replyQ = FALSE
        /\ registered = FALSE
        /\ replyToMsgs = 0
        /\ lateAdmit = FALSE
        /\ spanClaimed = FALSE
        /\ spanFinishes = 0
        /\ callerRecorded = FALSE
        /\ workerRecorded = FALSE
        /\ pc = [self \in ProcSet |-> CASE self = "worker" -> "WAdmit"
                                        [] self = "caller" -> "CSend"]

WAdmit == /\ pc["worker"] = "WAdmit"
          /\ admitQ = "queued"
          /\ admitQ' = "taken"
          /\ IF DeadlineCheck /\ callerSt = "timed_out"
                THEN /\ IF WorkerEndsOnRefusal
                           THEN /\ IF ~Idempotent \/ ~spanClaimed
                                      THEN /\ spanClaimed' = TRUE
                                           /\ spanFinishes' = spanFinishes + 1
                                           /\ IF "none" = "caller"
                                                 THEN /\ callerRecorded' = TRUE
                                                      /\ UNCHANGED workerRecorded
                                                 ELSE /\ IF "none" = "worker"
                                                            THEN /\ workerRecorded' = TRUE
                                                            ELSE /\ TRUE
                                                                 /\ UNCHANGED workerRecorded
                                                      /\ UNCHANGED callerRecorded
                                      ELSE /\ TRUE
                                           /\ UNCHANGED << spanClaimed, 
                                                           spanFinishes, 
                                                           callerRecorded, 
                                                           workerRecorded >>
                           ELSE /\ TRUE
                                /\ UNCHANGED << spanClaimed, spanFinishes, 
                                                callerRecorded, workerRecorded >>
                     /\ UNCHANGED << replyQ, registered, lateAdmit >>
                ELSE /\ registered' = TRUE
                     /\ replyQ' = TRUE
                     /\ lateAdmit' = (callerSt = "timed_out")
                     /\ UNCHANGED << spanClaimed, spanFinishes, callerRecorded, 
                                     workerRecorded >>
          /\ pc' = [pc EXCEPT !["worker"] = "WResolve"]
          /\ UNCHANGED << callerSt, replyToMsgs >>

WResolve == /\ pc["worker"] = "WResolve"
            /\ IF registered
                  THEN /\ replyToMsgs' = replyToMsgs + 1
                       /\ IF ~Idempotent \/ ~spanClaimed
                             THEN /\ spanClaimed' = TRUE
                                  /\ spanFinishes' = spanFinishes + 1
                                  /\ IF "worker" = "caller"
                                        THEN /\ callerRecorded' = TRUE
                                             /\ UNCHANGED workerRecorded
                                        ELSE /\ IF "worker" = "worker"
                                                   THEN /\ workerRecorded' = TRUE
                                                   ELSE /\ TRUE
                                                        /\ UNCHANGED workerRecorded
                                             /\ UNCHANGED callerRecorded
                             ELSE /\ TRUE
                                  /\ UNCHANGED << spanClaimed, spanFinishes, 
                                                  callerRecorded, 
                                                  workerRecorded >>
                  ELSE /\ TRUE
                       /\ UNCHANGED << replyToMsgs, spanClaimed, spanFinishes, 
                                       callerRecorded, workerRecorded >>
            /\ pc' = [pc EXCEPT !["worker"] = "Done"]
            /\ UNCHANGED << admitQ, callerSt, replyQ, registered, lateAdmit >>

worker == WAdmit \/ WResolve

CSend == /\ pc["caller"] = "CSend"
         /\ callerSt' = "waiting"
         /\ admitQ' = "queued"
         /\ pc' = [pc EXCEPT !["caller"] = "CWait"]
         /\ UNCHANGED << replyQ, registered, replyToMsgs, lateAdmit, 
                         spanClaimed, spanFinishes, callerRecorded, 
                         workerRecorded >>

CWait == /\ pc["caller"] = "CWait"
         /\ \/ /\ replyQ
               /\ callerSt' = "got_ref"
               /\ UNCHANGED <<spanClaimed, spanFinishes, callerRecorded, workerRecorded>>
            \/ /\ callerSt' = "timed_out"
               /\ IF CallerFinishesOnTimeout
                     THEN /\ IF ~Idempotent \/ ~spanClaimed
                                THEN /\ spanClaimed' = TRUE
                                     /\ spanFinishes' = spanFinishes + 1
                                     /\ IF "caller" = "caller"
                                           THEN /\ callerRecorded' = TRUE
                                                /\ UNCHANGED workerRecorded
                                           ELSE /\ IF "caller" = "worker"
                                                      THEN /\ workerRecorded' = TRUE
                                                      ELSE /\ TRUE
                                                           /\ UNCHANGED workerRecorded
                                                /\ UNCHANGED callerRecorded
                                ELSE /\ TRUE
                                     /\ UNCHANGED << spanClaimed, spanFinishes, 
                                                     callerRecorded, 
                                                     workerRecorded >>
                     ELSE /\ TRUE
                          /\ UNCHANGED << spanClaimed, spanFinishes, 
                                          callerRecorded, workerRecorded >>
         /\ pc' = [pc EXCEPT !["caller"] = "Done"]
         /\ UNCHANGED << admitQ, replyQ, registered, replyToMsgs, lateAdmit >>

caller == CSend \/ CWait

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == worker \/ caller
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(worker)

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

TypeOK ==
    /\ admitQ \in {"empty", "queued", "taken"}
    /\ callerSt \in {"idle", "waiting", "got_ref", "timed_out"}
    /\ replyToMsgs \in 0..1
    /\ spanFinishes \in 0..2

Finished == \A s \in ProcSet : pc[s] = "Done"

(***************************************************************************)
(* The documented contract (katipo.erl async_req doc): an error return     *)
(* means no message is delivered to reply_to. EXPECTED: VIOLATED without   *)
(* the fix (late admit), and STILL violated with it (the reply can be in   *)
(* flight when the timeout fires) - the fix narrows the window, it cannot  *)
(* close it from the worker's side alone.                                  *)
(***************************************************************************)
ContractNoStray == callerSt = "timed_out" => replyToMsgs = 0

\* The scenario DeadlineCheck is meant to kill: the worker registering a
\* request whose caller has already given up. EXPECTED: violated without the
\* fix, holds with it.
NoLateAdmit == ~lateAdmit

(***************************************************************************)
(* SPAN OWNERSHIP.                                                         *)
(***************************************************************************)

\* The span is closed exactly once. Catches the double-count and the leak,
\* but NOT a wrong surviving outcome - that is what the next two are for.
SpanExactlyOnceAtEnd == Finished => spanFinishes = 1

\* The span is closed at all. Separated out so a leak names itself.
NoSpanLeak == Finished => spanFinishes >= 1

\* THE ONE A COUNTER CANNOT SEE. The caller can only ever record
\* `admission_timeout'. If the request actually ran, that record is false,
\* and under an exactly-once rule it also DISPLACES the real outcome. So
\* the caller must never be the one that recorded, for a request that ran.
NoFabricatedOutcome == ~(callerRecorded /\ registered)

\* ...and the real outcome must actually make it out.
RealOutcomeRecorded == Finished /\ registered => workerRecorded

\* Witness: the happy path exists (sanity that the model is not vacuous).
\* EXPECTED: violated.
NoSuccess == callerSt # "got_ref"

===============
