---------------------------- MODULE KatipoTimer ----------------------------
(***************************************************************************)
(* The C port's libcurl timer on libevent: whether a transfer's timeout    *)
(* always fires on time, or can wait for unrelated socket activity.        *)
(*                                                                         *)
(* STATUS: models c_src/katipo.c as of the libcurl timer fix (PR #211,     *)
(* 2026-10-25) and the code before it. Verdict: the old port loses its     *)
(* timer with libcurl 8.10.0-8.11.0 and keeps it with every other version; *)
(* the fixed port keeps it with all of them. The re-arm is what does it:   *)
(* the cached-time refresh alone is enough only if libevent and libcurl    *)
(* read the same clock, and on Linux they do not.                          *)
(*                                                                         *)
(* libcurl asks for its timer through multi_timer_cb with a delay counted  *)
(* from now (lib/multi.c Curl_update_timer). The port adds it with         *)
(* evtimer_add, which counts from the time libevent cached when the loop   *)
(* iteration began, so a timer set late in a long callback fires early by  *)
(* the callback's length. libcurl only calls multi_timer_cb when its next  *)
(* deadline changes. libcurl <= 8.9.1 and >= 8.11.1 clear the deadline     *)
(* they last reported whenever they are run for a timeout ("in case the    *)
(* application asks libcurl to run the timeout prematurely"), so an early  *)
(* fire is answered with a fresh timer. 8.10.0 to 8.11.0 lost that reset:  *)
(* an early fire finds nothing due, the deadline is unchanged, no timer is *)
(* asked for, and none is pending.                                         *)
(*                                                                         *)
(* libevent and libcurl also read different clocks: libevent without       *)
(* EVENT_BASE_FLAG_PRECISE_TIMER uses CLOCK_MONOTONIC_COARSE on Linux      *)
(* (1-4 ms ticks), libcurl CLOCK_MONOTONIC_RAW. So even a timer added at   *)
(* the right time can fire up to ClockLag ticks before libcurl's deadline. *)
(*                                                                         *)
(* Time is a discrete clock. A callback is one atomic step that starts by  *)
(* caching the time (libevent's iteration start), may run for up to        *)
(* MaxSkew ticks, and then has libcurl update its timer at the later time. *)
(* libcurl's pending deadlines are a set of absolute times; a deadline at  *)
(* or before the time a callback starts is run (the transfer times out).   *)
(*                                                                         *)
(* Constants switch the variants:                                          *)
(*   CurlResets   libcurl clears its last reported deadline when run for a *)
(*                timeout: TRUE for <= 8.9.1 and >= 8.11.1, FALSE for      *)
(*                8.10.0-8.11.0 (lib/multi.c multi_socket). Cleared means  *)
(*                "nothing reported": a pending deadline is reported again *)
(*                and an empty set is not reported as -1 again.            *)
(*   RefreshCache multi_timer_cb calls event_base_update_cache_time before *)
(*                evtimer_add (the fix).                                   *)
(*   Rearm        timer_cb re-arms from curl_multi_timeout when libcurl    *)
(*                left no timer pending (the fix's rearm_if_early).        *)
(*   DeleteOnNone multi_timer_cb deletes the timer for timeout_ms = -1     *)
(*                (the fix); before, it added one that fired at once.      *)
(*   IdleDelete   event_cb deletes the timer once no transfers are running *)
(*                (before the fix). Modelled as libcurl having no          *)
(*                deadlines, which is how still_running <= 0 shows here.   *)
(*   ClockLag     how many ticks early libevent's clock can let a timer    *)
(*                fire: 0 if both read one clock, 1 for Linux's default.   *)
(*                                                                         *)
(* Out of scope, and why that is safe:                                     *)
(*   - Which transfer a deadline belongs to: the property is that each     *)
(*     deadline is run on time, whoever owns it.                           *)
(*   - Socket readiness: socket callbacks are an unfair environment action *)
(*     that may run due deadlines, remove one (a transfer finishing) or    *)
(*     do nothing. Being unfair, they cannot be what rescues a timer.      *)
(*   - libcurl's own internal deadlines (connect phases, EXPIRE_RUN_NOW):  *)
(*     they are more deadlines, added like any other.                      *)
(*   - Sub-millisecond rounding: libevent rounds timer waits up, and       *)
(*     libcurl rounds its delay up to whole milliseconds, so neither makes *)
(*     a timer fire earlier than the skew and ClockLag modelled here.      *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    CurlResets, RefreshCache, Rearm, DeleteOnNone, IdleDelete,
    ClockLag,    \* ticks a timer can fire before its expiry
    MaxTime,     \* the clock stops here
    MaxSkew,     \* the longest a callback runs before libcurl updates its timer
    MaxXfers,    \* deadlines added over a run
    MaxTimeout   \* the longest delay a new deadline is set at

None == -1      \* no timer pending / no deadline reported

VARIABLES
    now,        \* the real clock
    cache,      \* libevent's cached time, set when a callback starts
    timer,      \* the pending libevent timer's absolute expiry, or None
    deadlines,  \* libcurl's pending deadlines (absolute times)
    last,       \* the deadline libcurl last reported to multi_timer_cb
    added,      \* deadlines added so far
    early       \* a timer has fired before any deadline was due (witness)

vars == <<now, cache, timer, deadlines, last, added, early>>

Times == 0..MaxTime
Min(S) == CHOOSE x \in S : \A y \in S : x <= y

Init ==
    /\ now = 0
    /\ cache = 0
    /\ timer = None
    /\ deadlines = {}
    /\ last = None
    /\ added = 0
    /\ early = FALSE

(* multi_timer_cb(timeout_ms), called at time t during a callback that   *)
(* started at time c: the timer the port leaves pending.                 *)
TimerFor(next, t, c) ==
    IF next = None
    THEN IF DeleteOnNone THEN None ELSE c  \* old: tv_usec = -1000, fires at once
    ELSE (IF RefreshCache THEN t ELSE c) + (IF next > t THEN next - t ELSE 0)

(* Curl_update_timer at time t, with deadlines D and last reported L:    *)
(* calls multi_timer_cb only when the next deadline changed. Returns     *)
(* <<timer, last>> given the timer pending before the call.               *)
Update(D, L, pending, t, c) ==
    LET next == IF D = {} THEN None ELSE Min(D)
    IN IF next = L THEN <<pending, L>>
       ELSE <<TimerFor(next, t, c), next>>

(* A callback that starts at now: libcurl runs the deadlines due at now,  *)
(* the callback runs for k more ticks, then libcurl updates its timer.    *)
(* Extra is a deadline the callback adds (a new request) or None.         *)
(* Drop is a deadline the callback removes (a transfer finished) or None. *)
Callback(isTimer, extra, drop, k) ==
    LET c     == now
        t     == now + k
        L0    == IF isTimer /\ CurlResets THEN None ELSE last
        due   == {d \in deadlines : d <= now}
        D1    == ((deadlines \ due) \ {drop}) \cup (IF extra = None THEN {} ELSE {extra})
        pend0 == IF isTimer THEN None ELSE timer  \* a fired timer is no longer pending
        u     == Update(D1, L0, pend0, t, c)
        tm1   == u[1]
        \* timer_cb: re-arm from curl_multi_timeout if nothing is pending
        tm2   == IF isTimer /\ Rearm /\ tm1 = None /\ D1 # {}
                 THEN TimerFor(Min(D1), t, c)
                 ELSE tm1
        \* event_cb before the fix: with no transfers left, delete the timer
        tm3   == IF IdleDelete /\ ~isTimer /\ D1 = {} THEN None ELSE tm2
    IN /\ t <= MaxTime
       /\ now' = t
       /\ cache' = c
       /\ deadlines' = D1
       /\ last' = u[2]
       /\ timer' = tm3
       /\ early' = (early \/ (isTimer /\ due = {} /\ deadlines # {}))

(* libevent runs the timer once its clock reaches it, which can be up to   *)
(* ClockLag ticks before libcurl's clock does.                             *)
TimerFire ==
    /\ timer # None
    /\ timer <= now + ClockLag
    /\ \E k \in 0..MaxSkew : Callback(TRUE, None, None, k)
    /\ UNCHANGED added

(* A request arrives from Erlang (erl_input -> new_conn), adding a deadline. *)
AddDeadline ==
    /\ added < MaxXfers
    /\ \E k \in 0..MaxSkew, d \in 1..MaxTimeout :
        /\ now + k + d <= MaxTime - MaxSkew - 1
        /\ Callback(FALSE, now + k + d, None, k)
    /\ added' = added + 1

(* Socket activity on some transfer: runs due deadlines, and may finish a  *)
(* transfer early. Unfair: it is the environment, not something the       *)
(* timer may rely on.                                                      *)
Socket ==
    /\ deadlines # {}
    /\ \E k \in 0..MaxSkew, drop \in deadlines \cup {None} :
        Callback(FALSE, None, drop, k)
    /\ UNCHANGED added

(* Time passes while the loop waits: libevent sleeps until its timer, so   *)
(* the clock cannot pass a pending timer without running it.               *)
Tick ==
    /\ now < MaxTime
    /\ timer = None \/ timer > now
    /\ now' = now + 1
    /\ UNCHANGED <<cache, timer, deadlines, last, added, early>>

Next == TimerFire \/ AddDeadline \/ Socket \/ Tick

(* The timer and the clock are fair; requests and sockets are not. *)
Spec == Init /\ [][Next]_vars /\ WF_vars(TimerFire) /\ WF_vars(Tick)

---------------------------------------------------------------------------
TypeOK ==
    /\ now \in Times /\ cache \in Times
    /\ timer \in Times \cup {None}
    /\ deadlines \subseteq Times
    /\ last \in Times \cup {None}
    /\ added \in 0..MaxXfers
    /\ early \in BOOLEAN

(* While libcurl has a deadline, the port has a timer pending for it. *)
TimerArmed == deadlines # {} => timer # None

(* No deadline is overdue by more than one callback's length: the clock   *)
(* cannot run past a deadline while nothing would wake the loop for it.   *)
Timely == deadlines # {} => now <= Min(deadlines) + MaxSkew

(* The timer is never set before libcurl's next deadline (the cache fix). *)
(* It can still fire before it, by up to ClockLag.                       *)
NotEarly == (timer # None /\ deadlines # {}) => timer >= Min(deadlines)

(* Every deadline is eventually run, with no help from socket activity. *)
Served == \A d \in Times : (d \in deadlines) ~> (d \notin deadlines)

(* The Lean proof's invariant (lean/KatipoProofs/Timer/Proofs.lean, Inv), *)
(* one conjunct per field, checked here so the proof is about this model.  *)
LeanInv ==
    /\ last = IF deadlines = {} THEN None ELSE Min(deadlines)
    /\ deadlines # {} =>
         timer # None /\ (timer <= Min(deadlines) \/ timer <= now)
    /\ (RefreshCache /\ deadlines # {} /\ timer # None) => Min(deadlines) <= timer
    /\ deadlines # {} => now <= Min(deadlines) + MaxSkew

(* Witnesses, checked with -inv to show the model reaches what matters:  *)
(* a timer firing before anything is due, and two deadlines at once.     *)
WitnessNoEarly == ~early
WitnessTwo == Cardinality(deadlines) < 2
=============================================================================
