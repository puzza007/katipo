------------------------------- MODULE KatipoSpill ------------------------------
(***************************************************************************)
(* WHAT THIS MODELS. Pool-level admission routing under max_in_flight:     *)
(* katipo:pool_call/attempt/spillover (src/katipo.erl). One request, one   *)
(* caller, NumWorkers workers, each in one of five states:                 *)
(*   free   - has room, admits at once                                     *)
(*   full   - at max_in_flight, replies {overload, Pid}. ALIVE.            *)
(*   noproc - restarting: the name is unregistered, so handle_call never   *)
(*            ran and NOTHING reached the port                             *)
(*   dying  - alive when called, so handle_call may have run admit/4 --    *)
(*            which calls send_to_port BEFORE replying -- and then died.   *)
(*            The request may already be on the wire.                      *)
(*   slow   - alive but its mailbox is backed up past the admission        *)
(*            budget, so the bounded call times out                        *)
(*                                                                         *)
(* THREE QUESTIONS, one per knob:                                          *)
(*                                                                         *)
(* 1. May a failed attempt be re-offered? (ReOfferOnDeath.) noproc and     *)
(*    dying look similar and are not: re-offering after `dying' can run a  *)
(*    non-idempotent request twice. NoDoubleSend is the property.          *)
(*                                                                         *)
(* 2. What error does an exhausted walk report? (LabelFromFirstPick.)      *)
(*    Taking it from whatever the first RANDOM pick happened to be reports *)
(*    a saturated pool as `worker_died' -- a caller that backs off on      *)
(*    overload but alarms on worker_died then misroutes 1-in-pool_size of  *)
(*    its rejections. LabelHonest is the property.                         *)
(*                                                                         *)
(* 3. Is admission bounded by ?ADMISSION_TIMEOUT, or by pool_size times    *)
(*    it? (SharedDeadline.) A fresh deadline per candidate means a         *)
(*    32-worker pool can block the caller for over two minutes.            *)
(*    WaitsBounded is the property.                                        *)
(*                                                                         *)
(* THE ACTORS: one caller (fair; the whole thing is a synchronous call     *)
(* chain). Worker states are chosen in Init and held for the admission:    *)
(* letting them change mid-walk only adds behaviours, and the questions    *)
(* above are already answered by the static case.                          *)
(*                                                                         *)
(* ABSTRACTION CHOICES:                                                    *)
(*   - Time is counted in admission budgets: a slow worker consumes the    *)
(*     whole remaining budget, a full worker's overload reply consumes 0   *)
(*     or 1 (immediate, or just inside the bound), free/noproc/dying 0.    *)
(*   - Random choice (wpool random_worker, the rotation in                 *)
(*     spillover_candidates) is nondeterministic choice.                   *)
(*   - Sync requests carry no deadline: no slow outcome, so only questions *)
(*     1 and 2 apply to them.                                              *)
(*                                                                         *)
(* OUT OF SCOPE: what happens after admission (KatipoReq); the deadline    *)
(* stamp and span ownership (KatipoAdmit); worker state changing mid-walk. *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    NumWorkers,
    \* the latency claim under test: admission budgets one request may burn
    MaxWaits,
    \* TRUE = pre-fix: spillover's `_NoRoom' catch-all treats a worker that
    \* died with the call in flight like any other miss and offers the same
    \* request to the next candidate. FALSE = as implemented: that ends the
    \* admission, because the request may already have reached a port.
    ReOfferOnDeath,
    \* TRUE = pre-fix: the exhaustion error is whatever the first random
    \* pick suggested. FALSE = as implemented: derived from the walk.
    LabelFromFirstPick,
    \* TRUE = as implemented: ONE deadline, stamped once and shared by every
    \* hop. FALSE = pre-fix: each candidate gets a fresh full bound.
    SharedDeadline

Workers == 1..NumWorkers
States  == {"free", "full", "noproc", "dying", "slow"}

(* --algorithm KatipoSpill

variables
    wstate \in [Workers -> States],
    tried     = {},          \* workers already offered the request
    waits     = 0,           \* admission budgets consumed so far
    budget    = 1,           \* budgets left before the caller gives up
    sent      = 0,           \* times the request reached a worker's port
    sawLive   = FALSE,       \* some worker answered as alive-but-full
    firstPick = "none",      \* what the first attempt suggested as a label
    exhausted = FALSE,       \* the walk ran out of candidates (vs stopped early)
    result    = "pending";

\* One attempt against worker w. Sets result when the admission ends here.
macro offer(w) begin
  tried := tried \cup {w};
  if wstate[w] = "free" then
    sent := sent + 1;
    result := "ok";
  elsif wstate[w] = "slow" then
    \* the bounded call times out, consuming what is left of the budget
    waits := waits + budget;
    budget := 0;
    result := "admission_timeout";
  elsif wstate[w] = "dying" then
    \* handle_call may have run send_to_port before the worker died
    sent := sent + 1;
    if ~ReOfferOnDeath then
      result := "worker_died";
    end if;
  elsif wstate[w] = "full" then
    sawLive := TRUE;
    with cost \in {0, 1} do
      if cost <= budget then
        waits := waits + cost;
        budget := budget - cost;
      end if;
    end with;
  end if;
  \* noproc: the name resolved to nothing, so nothing was sent. Keep going.
end macro;

fair process caller = "caller"
variables w = 0;
begin
First:
  \* wpool:call(PoolName, M, random_worker, Bound)
  with pick \in Workers do w := pick; end with;
  offer(w);
  if wstate[w] = "full" then
    firstPick := "overload";
  elsif wstate[w] = "noproc" then
    firstPick := "worker_died";
  end if;
Spill:
  \* spillover(spillover_candidates(...)): the rest, any order. Each hop
  \* gets a fresh full bound unless the deadline is shared.
  while result = "pending" /\ tried # Workers do
    if ~SharedDeadline then
      budget := 1;
    end if;
Hop:
    if budget = 0 then
      result := "admission_timeout";
    else
      with pick \in Workers \ tried do w := pick; end with;
      offer(w);
    end if;
  end while;
Report:
  if result = "pending" then
    exhausted := TRUE;
    if LabelFromFirstPick /\ firstPick # "none" then
      result := firstPick;
    elsif sawLive then
      result := "overload";
    else
      result := "worker_died";
    end if;
  end if;
end process;

end algorithm; *)

\* Translate with:  java -cp tla2tools.jar pcal.trans formal/KatipoSpill.tla

\* BEGIN TRANSLATION
VARIABLES wstate, tried, waits, budget, sent, sawLive, firstPick, exhausted, 
          result, pc, w

vars == << wstate, tried, waits, budget, sent, sawLive, firstPick, exhausted, 
           result, pc, w >>

ProcSet == {"caller"}

Init == (* Global variables *)
        /\ wstate \in [Workers -> States]
        /\ tried = {}
        /\ waits = 0
        /\ budget = 1
        /\ sent = 0
        /\ sawLive = FALSE
        /\ firstPick = "none"
        /\ exhausted = FALSE
        /\ result = "pending"
        (* Process caller *)
        /\ w = 0
        /\ pc = [self \in ProcSet |-> "First"]

First == /\ pc["caller"] = "First"
         /\ \E pick \in Workers:
              w' = pick
         /\ tried' = (tried \cup {w'})
         /\ IF wstate[w'] = "free"
               THEN /\ sent' = sent + 1
                    /\ result' = "ok"
                    /\ UNCHANGED << waits, budget, sawLive >>
               ELSE /\ IF wstate[w'] = "slow"
                          THEN /\ waits' = waits + budget
                               /\ budget' = 0
                               /\ result' = "admission_timeout"
                               /\ UNCHANGED << sent, sawLive >>
                          ELSE /\ IF wstate[w'] = "dying"
                                     THEN /\ sent' = sent + 1
                                          /\ IF ~ReOfferOnDeath
                                                THEN /\ result' = "worker_died"
                                                ELSE /\ TRUE
                                                     /\ UNCHANGED result
                                          /\ UNCHANGED << waits, budget, 
                                                          sawLive >>
                                     ELSE /\ IF wstate[w'] = "full"
                                                THEN /\ sawLive' = TRUE
                                                     /\ \E cost \in {0, 1}:
                                                          IF cost <= budget
                                                             THEN /\ waits' = waits + cost
                                                                  /\ budget' = budget - cost
                                                             ELSE /\ TRUE
                                                                  /\ UNCHANGED << waits, 
                                                                                  budget >>
                                                ELSE /\ TRUE
                                                     /\ UNCHANGED << waits, 
                                                                     budget, 
                                                                     sawLive >>
                                          /\ UNCHANGED << sent, result >>
         /\ IF wstate[w'] = "full"
               THEN /\ firstPick' = "overload"
               ELSE /\ IF wstate[w'] = "noproc"
                          THEN /\ firstPick' = "worker_died"
                          ELSE /\ TRUE
                               /\ UNCHANGED firstPick
         /\ pc' = [pc EXCEPT !["caller"] = "Spill"]
         /\ UNCHANGED << wstate, exhausted >>

Spill == /\ pc["caller"] = "Spill"
         /\ IF result = "pending" /\ tried # Workers
               THEN /\ IF ~SharedDeadline
                          THEN /\ budget' = 1
                          ELSE /\ TRUE
                               /\ UNCHANGED budget
                    /\ pc' = [pc EXCEPT !["caller"] = "Hop"]
               ELSE /\ pc' = [pc EXCEPT !["caller"] = "Report"]
                    /\ UNCHANGED budget
         /\ UNCHANGED << wstate, tried, waits, sent, sawLive, firstPick, 
                         exhausted, result, w >>

Hop == /\ pc["caller"] = "Hop"
       /\ IF budget = 0
             THEN /\ result' = "admission_timeout"
                  /\ UNCHANGED << tried, waits, budget, sent, sawLive, w >>
             ELSE /\ \E pick \in Workers \ tried:
                       w' = pick
                  /\ tried' = (tried \cup {w'})
                  /\ IF wstate[w'] = "free"
                        THEN /\ sent' = sent + 1
                             /\ result' = "ok"
                             /\ UNCHANGED << waits, budget, sawLive >>
                        ELSE /\ IF wstate[w'] = "slow"
                                   THEN /\ waits' = waits + budget
                                        /\ budget' = 0
                                        /\ result' = "admission_timeout"
                                        /\ UNCHANGED << sent, sawLive >>
                                   ELSE /\ IF wstate[w'] = "dying"
                                              THEN /\ sent' = sent + 1
                                                   /\ IF ~ReOfferOnDeath
                                                         THEN /\ result' = "worker_died"
                                                         ELSE /\ TRUE
                                                              /\ UNCHANGED result
                                                   /\ UNCHANGED << waits, 
                                                                   budget, 
                                                                   sawLive >>
                                              ELSE /\ IF wstate[w'] = "full"
                                                         THEN /\ sawLive' = TRUE
                                                              /\ \E cost \in {0, 1}:
                                                                   IF cost <= budget
                                                                      THEN /\ waits' = waits + cost
                                                                           /\ budget' = budget - cost
                                                                      ELSE /\ TRUE
                                                                           /\ UNCHANGED << waits, 
                                                                                           budget >>
                                                         ELSE /\ TRUE
                                                              /\ UNCHANGED << waits, 
                                                                              budget, 
                                                                              sawLive >>
                                                   /\ UNCHANGED << sent, 
                                                                   result >>
       /\ pc' = [pc EXCEPT !["caller"] = "Spill"]
       /\ UNCHANGED << wstate, firstPick, exhausted >>

Report == /\ pc["caller"] = "Report"
          /\ IF result = "pending"
                THEN /\ exhausted' = TRUE
                     /\ IF LabelFromFirstPick /\ firstPick # "none"
                           THEN /\ result' = firstPick
                           ELSE /\ IF sawLive
                                      THEN /\ result' = "overload"
                                      ELSE /\ result' = "worker_died"
                ELSE /\ TRUE
                     /\ UNCHANGED << exhausted, result >>
          /\ pc' = [pc EXCEPT !["caller"] = "Done"]
          /\ UNCHANGED << wstate, tried, waits, budget, sent, sawLive, 
                          firstPick, w >>

caller == First \/ Spill \/ Hop \/ Report

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == caller
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(caller)

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

Finished == pc["caller"] = "Done"
AnyFree  == \E x \in Workers : wstate[x] = "free"
AnySlow  == \E x \in Workers : wstate[x] = "slow"
AnyDying == \E x \in Workers : wstate[x] = "dying"
AnyFull  == \E x \in Workers : wstate[x] = "full"

TypeOK ==
    /\ waits \in 0..NumWorkers
    /\ sent \in 0..NumWorkers
    /\ result \in {"pending", "ok", "overload", "worker_died", "admission_timeout"}

\* THE OWNERSHIP PROPERTY. A request must reach at most one port: a worker
\* that died with the call in flight may already have handed it to libcurl,
\* so re-offering it can issue a non-idempotent request twice.
\* EXPECTED: VIOLATED with ReOfferOnDeath, holds without it.
NoDoubleSend == sent <= 1

\* THE LABEL PROPERTY. When the walk ran out of candidates, `worker_died'
\* must mean the pool had nothing alive to serve the request, and
\* `overload' must mean it did. Taking the label from the first random pick
\* breaks both directions.
\*
\* Scoped to the exhausted report on purpose: an admission that STOPS early
\* on a worker that died with the call in flight reports worker_died even
\* though free workers remain, and that is correct -- the request may
\* already be on the wire, so it cannot be re-offered, and worker_died is
\* what happened to it.
\* EXPECTED: VIOLATED with LabelFromFirstPick, holds without it.
LabelHonest ==
    /\ (Finished /\ exhausted /\ result = "worker_died" =>
          \A x \in Workers : wstate[x] \in {"noproc", "dying"})
    /\ (Finished /\ exhausted /\ result = "overload" => AnyFull)

\* THE LATENCY PROPERTY: one admission never burns more than MaxWaits
\* admission budgets. EXPECTED: holds at MaxWaits = 1 with SharedDeadline;
\* needs NumWorkers without it.
WaitsBounded == waits <= MaxWaits

\* A request is never refused while some worker has room -- barring the two
\* documented fail-fast paths: the caller's own admission budget running
\* out, or a worker that died with the call in flight ending the walk.
\*
\* The budget exclusion is not a loophole, it is the price of the shared
\* deadline. Under SharedDeadline a first pick that answers {overload, _}
\* just inside the bound leaves nothing for the walk, so free workers go
\* untried and the caller gets admission_timeout -- where a fresh bound per
\* hop would have found one, at up to NumWorkers x ?ADMISSION_TIMEOUT.
\* Honouring the bound the caller asked for is the right side of that
\* trade, but it IS a behaviour change; see _budget_starves_walk.
NoSpuriousFailure ==
    Finished /\ AnyFree /\ ~AnyDying /\ result # "admission_timeout"
      => result = "ok"

\* Witness: the full NumWorkers latency is reachable without a shared
\* deadline. EXPECTED: violated.
NeverAllWaits == waits < NumWorkers

\* Witness for the trade above: with the deadline shared, a request CAN be
\* refused with admission_timeout while a free worker sits untried,
\* because the first pick consumed the whole budget. EXPECTED: violated.
NeverStarvesWalk ==
    ~(Finished /\ AnyFree /\ result = "admission_timeout")

===============================================================================
