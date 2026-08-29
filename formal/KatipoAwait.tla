------------------------------- MODULE KatipoAwait ------------------------------
(***************************************************************************)
(* WHAT THIS MODELS. katipo:await/2 (src/katipo.erl ~404..419): a receive  *)
(* for the terminal katipo_response/katipo_error message on a Ref, with a  *)
(* timeout branch that flushes a late message with `receive ... after 0`   *)
(* and returns {error, await_timeout}. Two questions:                      *)
(*   1. Can the flush miss? The delivery can land AFTER the after-0 flush  *)
(*      and BEFORE await returns, leaving a stray message in the mailbox   *)
(*      of a caller that was told nothing arrived.                         *)
(*   2. await_timeout does not cancel. The request keeps its worker slot   *)
(*      (a max_in_flight unit, katipo_worker.erl at_capacity) until its    *)
(*      own request timer (CURLOPT_TIMEOUT / #req.timeout) fires - which   *)
(*      can be much later than the await bound, or never observable to     *)
(*      the caller.                                                        *)
(* Both are single-step consequences, so the model is deliberately tiny;   *)
(* its value is stating the contract and proving the CancelOnTimeout       *)
(* variant closes (2) without pretending to close (1).                     *)
(*                                                                         *)
(* Real code:                                                              *)
(*   - src/katipo.erl await/2 (~404..419): main receive, timeout, flush    *)
(*   - src/katipo.erl cancel/2 (~433): Ref ! {cancel, Ref}, best-effort    *)
(*   - src/katipo_worker.erl handle_info cancel (~229..245): take from     *)
(*     Reqs, deactivate alias, abort_transfer; no message to the caller    *)
(*   - src/katipo_worker.erl handle_info req_timeout (~213..228)           *)
(*                                                                         *)
(* THE ACTORS:                                                             *)
(*   - caller - FAIR: await's `after Timeout` is a real timer, so the      *)
(*     caller always leaves the receive; which branch it leaves by is the  *)
(*     nondeterminism.                                                     *)
(*   - worker - fair; delivers the terminal message when the transfer      *)
(*     completes or its timer fires, or drops the request on cancel.       *)
(*   - curl   - NOT fair: the server may stall forever (the timer exists   *)
(*     for exactly that reason).                                           *)
(*   - timer  - fair when ReqTimerFires; disabled otherwise to model a     *)
(*     request timeout far beyond the await bound.                         *)
(*                                                                         *)
(* OUT OF SCOPE: exactly-once terminal delivery (KatipoReq proved it; the  *)
(* worker delivers at most once here by construction); streaming (await   *)
(* is documented buffered-only).                                           *)
(***************************************************************************)
EXTENDS Naturals, TLC

CONSTANTS
    \* TRUE = candidate: await/2 sends cancel/2 on the timeout path after
    \* the flush. FALSE = as implemented (no cancel).
    CancelOnTimeout,
    \* TRUE = the request's own timer can fire; FALSE = it is effectively
    \* infinite relative to the await bound.
    ReqTimerFires

(* --algorithm KatipoAwait

variables
    inFlight  = TRUE,        \* request occupies a Reqs slot in the worker
    responded = FALSE,       \* curl produced a result (or error)
    mbox      = 0,           \* terminal messages for this Ref in the caller's mailbox
    cancelQ   = FALSE,       \* {cancel, Ref} in flight to the worker
    callerSt  = "waiting",   \* "waiting" | "got" | "timed_out"
    stray     = FALSE;       \* ghost: a message landed after await returned

\* NOT fair: the server may never answer.
process curl = "curl"
begin
CRespond:
  responded := TRUE;
end process;

fair process timer = "timer"
begin
TFire:
  await ReqTimerFires /\ inFlight;
  \* deliver_timeout: {katipo_error, Ref, timeout} then abort_transfer
  mbox := mbox + 1;
  inFlight := FALSE;
end process;

fair process worker = "worker"
begin
WLoop:
  await inFlight;
  either
    await responded;
    mbox := mbox + 1;
    inFlight := FALSE;
  or
    await cancelQ;
    \* handle_info cancel: out of Reqs, alias deactivated, nothing sent
    inFlight := FALSE;
  end either;
end process;

fair process caller = "caller"
begin
AWait:
  either
    await mbox > 0;
    mbox := mbox - 1;
    callerSt := "got";
    goto Done;
  or
    \* `after Timeout`
    callerSt := "timed_out";
  end either;
AFlush:
  \* receive {katipo_response|katipo_error, Ref, _} -> ok after 0 -> ok end
  if mbox > 0 then
    mbox := mbox - 1;
  end if;
AReturn:
  \* {error, #{code => await_timeout}} is returned here; anything landing
  \* from now on is a stray the caller was told would not exist
  if CancelOnTimeout then
    cancelQ := TRUE;
  end if;
ADone:
  \* the caller has moved on; observe whether a message landed after all
  stray := mbox > 0;
end process;

end algorithm; *)

\* Translate with:  java -cp tla2tools.jar pcal.trans formal/KatipoAwait.tla

\* BEGIN TRANSLATION
VARIABLES inFlight, responded, mbox, cancelQ, callerSt, stray, pc

vars == << inFlight, responded, mbox, cancelQ, callerSt, stray, pc >>

ProcSet == {"curl"} \cup {"timer"} \cup {"worker"} \cup {"caller"}

Init == (* Global variables *)
        /\ inFlight = TRUE
        /\ responded = FALSE
        /\ mbox = 0
        /\ cancelQ = FALSE
        /\ callerSt = "waiting"
        /\ stray = FALSE
        /\ pc = [self \in ProcSet |-> CASE self = "curl" -> "CRespond"
                                        [] self = "timer" -> "TFire"
                                        [] self = "worker" -> "WLoop"
                                        [] self = "caller" -> "AWait"]

CRespond == /\ pc["curl"] = "CRespond"
            /\ responded' = TRUE
            /\ pc' = [pc EXCEPT !["curl"] = "Done"]
            /\ UNCHANGED << inFlight, mbox, cancelQ, callerSt, stray >>

curl == CRespond

TFire == /\ pc["timer"] = "TFire"
         /\ ReqTimerFires /\ inFlight
         /\ mbox' = mbox + 1
         /\ inFlight' = FALSE
         /\ pc' = [pc EXCEPT !["timer"] = "Done"]
         /\ UNCHANGED << responded, cancelQ, callerSt, stray >>

timer == TFire

WLoop == /\ pc["worker"] = "WLoop"
         /\ inFlight
         /\ \/ /\ responded
               /\ mbox' = mbox + 1
               /\ inFlight' = FALSE
            \/ /\ cancelQ
               /\ inFlight' = FALSE
               /\ mbox' = mbox
         /\ pc' = [pc EXCEPT !["worker"] = "Done"]
         /\ UNCHANGED << responded, cancelQ, callerSt, stray >>

worker == WLoop

AWait == /\ pc["caller"] = "AWait"
         /\ \/ /\ mbox > 0
               /\ mbox' = mbox - 1
               /\ callerSt' = "got"
               /\ pc' = [pc EXCEPT !["caller"] = "Done"]
            \/ /\ callerSt' = "timed_out"
               /\ pc' = [pc EXCEPT !["caller"] = "AFlush"]
               /\ mbox' = mbox
         /\ UNCHANGED << inFlight, responded, cancelQ, stray >>

AFlush == /\ pc["caller"] = "AFlush"
          /\ IF mbox > 0
                THEN /\ mbox' = mbox - 1
                ELSE /\ TRUE
                     /\ mbox' = mbox
          /\ pc' = [pc EXCEPT !["caller"] = "AReturn"]
          /\ UNCHANGED << inFlight, responded, cancelQ, callerSt, stray >>

AReturn == /\ pc["caller"] = "AReturn"
           /\ IF CancelOnTimeout
                 THEN /\ cancelQ' = TRUE
                 ELSE /\ TRUE
                      /\ UNCHANGED cancelQ
           /\ pc' = [pc EXCEPT !["caller"] = "ADone"]
           /\ UNCHANGED << inFlight, responded, mbox, callerSt, stray >>

ADone == /\ pc["caller"] = "ADone"
         /\ stray' = (mbox > 0)
         /\ pc' = [pc EXCEPT !["caller"] = "Done"]
         /\ UNCHANGED << inFlight, responded, mbox, cancelQ, callerSt >>

caller == AWait \/ AFlush \/ AReturn \/ ADone

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == curl \/ timer \/ worker \/ caller
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(timer)
        /\ WF_vars(worker)
        /\ WF_vars(caller)

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

TypeOK ==
    /\ mbox \in 0..1
    /\ callerSt \in {"waiting", "got", "timed_out"}

\* Every timed-out await leaves no message behind. EXPECTED: VIOLATED in
\* every variant - the delivery can land between the after-0 flush and the
\* return (and, with CancelOnTimeout, before the cancel is processed). This
\* is the contract the docs must state: after await_timeout, be prepared to
\* flush a late message for that Ref.
NoStrayAfterTimeout == ~stray

\* The worker slot is eventually released. EXPECTED: holds whenever the
\* request timer can fire; with the timer out of reach (ReqTimerFires =
\* FALSE, a stalled server) it holds ONLY with CancelOnTimeout - as
\* implemented, an await_timeout can leave a max_in_flight unit pinned for
\* the whole request timeout.
SlotEventuallyReleased == <>~inFlight

\* Witness: the happy path exists. EXPECTED: violated.
NoSuccess == callerSt # "got"

===============================================================================
