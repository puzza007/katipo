------------------------- MODULE KatipoPoolDefaults -------------------------
(***************************************************************************)
(* One pool's default request options and their lifetime.                  *)
(*                                                                         *)
(*  katipo_pool:start(Name, _, [{defaults, D}]) starts a wpool pool under  *)
(*    wpool_sup for configuration G (D and a fresh generation token), the  *)
(*    workers' arguments and the options carrying both. The pool's         *)
(*    supervisor registers the name, then its init/1 stores the options    *)
(*    in a persistent_term (Store), then its workers start (WorkersUp).    *)
(*    The term is never erased: the next start under the name overwrites  *)
(*    it, as may wpool's rebuild (below).                                  *)
(*  katipo_pool:stop/1: wpool_sup terminates the pool, then forgets it.    *)
(*  A crash: the pool exits, and wpool_sup restarts it from the same       *)
(*    arguments, so with the same G.                                       *)
(*  A caller (katipo_defaults:merge_into/2, wpool_pool:find_wpool/1):     *)
(*    whereis the name, no_workers if none; then reads the term. Finding   *)
(*    none, wpool rebuilds options without G and stores them over whatever *)
(*    the term holds by then (or gives up, no_workers). With Fallback, a   *)
(*    caller with rebuilt options asks a worker for its G, failing if none *)
(*    answers. Then the pool call: no_workers unless the pool's workers    *)
(*    are there. With GenCheck the request carries the generation it read, *)
(*    and a worker refuses any other.                                      *)
(*                                                                         *)
(* Over-approximations: callers, crashes and the admin act in any order;   *)
(* a dying pool's workers may still serve a call or answer an ask; a      *)
(* missing term may be rebuilt at any time.                                *)
(* Under-approximation: a stop begins only on a pool that is up, as        *)
(* wpool_sup handles a stop only after any start or restart it is making.  *)
(* Out of scope: the merge itself (Lean: KatipoProofs/Defaults), several   *)
(* pools (each has its own name and term), admission and delivery          *)
(* (KatipoFixed.tla).                                                      *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
  Configs,     \* the configurations a start may use
  C,           \* callers, one request each
  MaxStarts,   \* starts the admin may make
  MaxCrashes,  \* pool crashes
  GenCheck,    \* TRUE: workers refuse a request of another generation
  Fallback     \* TRUE: a caller with rebuilt options asks a worker

None == "none"
NoDef == "nodef"
Rebuilt == "rebuilt"

VARIABLES
  child,     \* wpool_sup's child for the pool: its configuration, or None
  reg,       \* "down" | "init" | "stored" | "up" | "dying": the pool's supervisor
  term,      \* the persistent_term: the configuration last stored, Rebuilt, or None
  wgen,      \* the configuration the pool's workers have
  stopping,  \* katipo_pool:stop/1 is under way
  pc,        \* [C -> "idle" | "where" | "rebuild" | "rebuilt" | "ask" | "read" | "done"]
  v,         \* [C -> the configuration read, NoDef, or None]
  ran,       \* <<caller, configuration read, workers' configuration>> served
  starts, crashes

vars == <<child, reg, term, wgen, stopping, pc, v, ran, starts, crashes>>

Init ==
  /\ child = None /\ reg = "down" /\ term = None /\ wgen = None
  /\ stopping = FALSE
  /\ pc = [c \in C |-> "idle"] /\ v = [c \in C |-> None] /\ ran = {}
  /\ starts = 0 /\ crashes = 0

(* -------------------------------- the pool ----------------------------- *)

\* katipo_pool:start/3: the pool's supervisor registers the name.
Start(g) ==
  /\ child = None /\ reg = "down" /\ starts < MaxStarts
  /\ child' = g /\ reg' = "init" /\ starts' = starts + 1
  /\ UNCHANGED <<term, wgen, stopping, pc, v, ran, crashes>>

\* wpool_pool:init/1 stores the options...
Store ==
  /\ reg = "init"
  /\ term' = child /\ reg' = "stored"
  /\ UNCHANGED <<child, wgen, stopping, pc, v, ran, starts, crashes>>

\* ...then the workers start, with the configuration's generation.
WorkersUp ==
  /\ reg = "stored"
  /\ reg' = "up" /\ wgen' = child
  /\ UNCHANGED <<child, term, stopping, pc, v, ran, starts, crashes>>

\* katipo_pool:stop/1: wpool_sup terminates the pool...
StopBegin ==
  /\ reg = "up" /\ ~stopping
  /\ stopping' = TRUE /\ reg' = "dying"
  /\ UNCHANGED <<child, term, wgen, pc, v, ran, starts, crashes>>

\* ...and once it has gone, forgets it.
StopEnd ==
  /\ stopping /\ reg = "down"
  /\ stopping' = FALSE /\ child' = None
  /\ UNCHANGED <<reg, term, wgen, pc, v, ran, starts, crashes>>

Crash ==
  /\ reg = "up" /\ ~stopping /\ crashes < MaxCrashes
  /\ reg' = "dying" /\ crashes' = crashes + 1
  /\ UNCHANGED <<child, term, wgen, stopping, pc, v, ran, starts>>

PoolGone ==
  /\ reg = "dying" /\ reg' = "down"
  /\ UNCHANGED <<child, term, wgen, stopping, pc, v, ran, starts, crashes>>

\* wpool_sup restarts a crashed pool from the same arguments.
Restart ==
  /\ reg = "down" /\ child # None /\ ~stopping
  /\ reg' = "init"
  /\ UNCHANGED <<child, term, wgen, stopping, pc, v, ran, starts, crashes>>

(* -------------------------------- callers ------------------------------ *)

\* find_wpool/1: whereis(Name)...
Where(c) ==
  /\ pc[c] = "idle"
  /\ pc' = [pc EXCEPT ![c] = IF reg = "down" THEN "done" ELSE "where"]
  /\ UNCHANGED <<child, reg, term, wgen, stopping, v, ran, starts, crashes>>

\* ...then the term...
Get(c) ==
  /\ pc[c] = "where"
  /\ CASE term \in Configs ->
            v' = [v EXCEPT ![c] = term] /\ pc' = [pc EXCEPT ![c] = "read"]
       [] term = Rebuilt -> pc' = [pc EXCEPT ![c] = "rebuilt"] /\ UNCHANGED v
       [] term = None -> pc' = [pc EXCEPT ![c] = "rebuild"] /\ UNCHANGED v
  /\ UNCHANGED <<child, reg, term, wgen, stopping, ran, starts, crashes>>

\* ...or, finding none, wpool's rebuild without it, stored over whatever
\* the term holds by now.
Rebuild(c) ==
  /\ pc[c] = "rebuild"
  /\ \/ term' = Rebuilt /\ pc' = [pc EXCEPT ![c] = "rebuilt"]
     \/ pc' = [pc EXCEPT ![c] = "done"] /\ UNCHANGED term
  /\ UNCHANGED <<child, reg, wgen, stopping, v, ran, starts, crashes>>

\* Rebuilt options: ask a worker, or go without defaults.
UseRebuilt(c) ==
  /\ pc[c] = "rebuilt"
  /\ IF Fallback
     THEN pc' = [pc EXCEPT ![c] = "ask"] /\ UNCHANGED v
     ELSE v' = [v EXCEPT ![c] = NoDef] /\ pc' = [pc EXCEPT ![c] = "read"]
  /\ UNCHANGED <<child, reg, term, wgen, stopping, ran, starts, crashes>>

\* katipo_worker:defaults/1: a worker answers with its configuration.
Ask(c) ==
  /\ pc[c] = "ask"
  /\ IF reg \in {"up", "dying"}
     THEN v' = [v EXCEPT ![c] = wgen] /\ pc' = [pc EXCEPT ![c] = "read"]
     ELSE pc' = [pc EXCEPT ![c] = "done"] /\ UNCHANGED v
  /\ UNCHANGED <<child, reg, term, wgen, stopping, ran, starts, crashes>>

\* The pool call: served, refused for its generation, or no_workers.
Call(c) ==
  /\ pc[c] = "read"
  /\ pc' = [pc EXCEPT ![c] = "done"]
  /\ ran' = IF reg \in {"up", "dying"} /\ ~(GenCheck /\ v[c] # wgen)
            THEN ran \cup {<<c, v[c], wgen>>} ELSE ran
  /\ UNCHANGED <<child, reg, term, wgen, stopping, v, starts, crashes>>

(* --------------------------------- spec -------------------------------- *)

Next ==
  \/ \E g \in Configs : Start(g)
  \/ Store \/ WorkersUp \/ StopBegin \/ StopEnd \/ Crash \/ PoolGone \/ Restart
  \/ \E c \in C : Where(c) \/ Get(c) \/ Rebuild(c) \/ UseRebuilt(c) \/ Ask(c) \/ Call(c)

Fairness ==
  /\ WF_vars(Store) /\ WF_vars(WorkersUp) /\ WF_vars(StopEnd)
  /\ WF_vars(PoolGone) /\ WF_vars(Restart)

Spec == Init /\ [][Next]_vars /\ Fairness

(* ------------------------------ properties ----------------------------- *)

\* A request is served only with the defaults of the pool serving it.
RanWithItsDefaults == \A r \in ran : r[2] = r[3]

\* ...or, weaker, never with another pool's defaults (a request with none
\* aside): what KatipoPoolDefaultsStale.cfg asks.
NoStaleDefaults == \A r \in ran : r[2] = NoDef \/ r[2] = r[3]

\* The pool's workers and the stored options are its own configuration's,
\* or the options are wpool's rebuild.
TermWithPool ==
  reg \in {"stored", "up"} => term \in {child, Rebuilt} /\ (reg = "up" => wgen = child)

\* ...or, stronger, never the rebuild: what KatipoPoolDefaultsRebuild.cfg asks.
TermKept == reg \in {"stored", "up"} => term = child

\* No request is ever left with no generation, which every worker refuses.
NeverWithout == \A c \in C : v[c] # NoDef

\* Nothing outlives a stopped pool: a request then finds no pool.
NothingLeft == child = None => reg = "down"

\* The Lean proof's invariant (lean/KatipoProofs/Defaults/Proofs.lean), mirrored.
LeanInv ==
  /\ GenCheck => RanWithItsDefaults
  /\ Fallback => NeverWithout
  /\ TermWithPool
  /\ NothingLeft
  /\ stopping => child # None

\* A pool that has not been stopped comes back up.
PoolComesBack == (child # None /\ ~stopping) ~> (reg = "up" \/ child = None \/ stopping)

\* Witnesses (expect VIOLATED with -inv): a request served, a restart, a
\* request served while the term is wpool's rebuild.
WitnessServed == ran = {}
WitnessRestarted == ~(crashes > 0 /\ reg = "up")
WitnessServedRebuilt == ~(ran # {} /\ term = Rebuilt)
=============================================================================
