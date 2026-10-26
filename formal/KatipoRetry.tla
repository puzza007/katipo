---------------------------- MODULE KatipoRetry ----------------------------
(***************************************************************************)
(* Retries in katipo_worker: requests with a retry policy, each sent       *)
(* again after a failed attempt, through one worker and its C port.        *)
(*                                                                         *)
(* STATUS: matches katipo branch feat/retries, 2026-10-26. Verdicts as in  *)
(* README.                                                                 *)
(*                                                                         *)
(*  Worker (src/katipo_worker.erl):                                        *)
(*    register_req   arm the request timer; the first transfer's port id   *)
(*                   is the request's key.                                 *)
(*    attempt_ended  a terminal message for the request's current          *)
(*                   transfer (current/2: its port id is the entry's)      *)
(*                   cancels the timer and goes to retry_or_resolve; any   *)
(*                   other is dropped.                                     *)
(*    req_timeout    if its Tref is the entry's (MatchTref): abort the     *)
(*                   current transfer, then retry_or_resolve with          *)
(*                   operation_timedout.                                   *)
(*    retry_or_resolve  if the policy says retry (katipo_retry:delay/5:    *)
(*                   a retryable outcome and fewer than max_retries sent): *)
(*                   arm the backoff timer, port id `backoff'; else        *)
(*                   deliver and remove.                                   *)
(*    {retry, Key}   if its Tref is the entry's: send the request again    *)
(*                   under a fresh port id (FreshIds; FALSE: the key       *)
(*                   again), arm a new request timer.                      *)
(*    cancel         cancel the timer, abort the current transfer (none in *)
(*                   backoff), remove.                                     *)
(*  C port: runs each transfer it is sent until curl ends it or a cancel   *)
(*    for its id arrives; cancel_conn on an id it no longer runs is a      *)
(*    no-op.                                                               *)
(*  Timers: erlang:start_timer/3. cancel_timer/1 stops an armed timer;     *)
(*    once fired, its message stays in the mailbox.                        *)
(*                                                                         *)
(* Over-approximations (each only adds behaviours):                        *)
(*  - Whether an outcome is retryable is the port's free choice, so every  *)
(*    policy, method and status is covered; a timeout always is.           *)
(*  - Any request may be cancelled, sync ones included.                    *)
(*    A {retry, Key} that finds its caller dead drops the request, which   *)
(*    is a cancel in backoff.                                              *)
(*  - The worker's mailbox is a FIFO queue per sender (the port, the       *)
(*    caller), and each fired timer its own sender, taken in any order.    *)
(*  - Backoff delays and timeouts are any length: a timer fires whenever.  *)
(*                                                                         *)
(* Out of scope:                                                           *)
(*  - Admission, port death, worker crash: KatipoFixed.tla; a retry adds   *)
(*    no state that outlives the worker, whose terminate/2 reports every   *)
(*    entry, in backoff or not, as before.                                 *)
(*  - Streams: retry with a streamed body or response is bad_opts.         *)
(*  - The ids map (port id -> key) that current/2 reads: a message names   *)
(*    its request directly. Covered by the worker's tests.                 *)
(*  - The delay itself (katipo_retry:delay/5): pure, unit-tested.          *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
  R,            \* the requests
  MaxRetries,   \* the policy's max_retries
  FreshIds,     \* TRUE: each retry's transfer has a fresh port id
  MatchTref,    \* TRUE: a timer message counts only if it is the entry's timer
  CancelOn      \* the caller may cancel

ASSUME MaxRetries \in Nat

VARIABLES
  st,         \* [R -> "new" | "held" | "done" | "cancelled"]
  mode,       \* [R -> "attempt" | "backoff" | "none"]
  cur,        \* [R -> retries sent so far]; the current attempt's number
  tref,       \* [R -> the token of the entry's timer]
  toks,       \* [R -> timer tokens minted]
  armed,      \* armed timers: [r, k |-> "req" | "retry", tok]
  fired,      \* fired timers' messages in the worker's mailbox
  pipe,       \* worker -> port: [t |-> "req" | "cancel", id, n]
  running,    \* transfers the port runs: [id, n]; n is a ghost
  out,        \* port -> worker terminal messages: [id, n, retry]
  cancelQ,    \* requests with a cancel message in the mailbox
  cancelSent, \* requests the caller has cancelled
  delivered,  \* [R -> outcomes delivered]
  sent,       \* [R -> transfers sent]
  stale,      \* ghost: an outcome taken from a transfer not the current one
  spurious    \* ghost: an attempt ended by another attempt's timer

vars == <<st, mode, cur, tref, toks, armed, fired, pipe, running, out,
          cancelQ, cancelSent, delivered, sent, stale, spurious>>

\* The port id of request r's attempt n.
Id(r, n) == IF FreshIds THEN <<r, n>> ELSE <<r, 0>>

Init ==
  /\ st = [r \in R |-> "new"]
  /\ mode = [r \in R |-> "none"]
  /\ cur = [r \in R |-> 0]
  /\ tref = [r \in R |-> 0]
  /\ toks = [r \in R |-> 0]
  /\ armed = {}
  /\ fired = {}
  /\ pipe = <<>>
  /\ running = {}
  /\ out = <<>>
  /\ cancelQ = {}
  /\ cancelSent = {}
  /\ delivered = [r \in R |-> 0]
  /\ sent = [r \in R |-> 0]
  /\ stale = FALSE
  /\ spurious = FALSE

\* admit_call + register_req: send the first transfer, arm the request timer.
Admit(r) ==
  /\ st[r] = "new"
  /\ st' = [st EXCEPT ![r] = "held"]
  /\ mode' = [mode EXCEPT ![r] = "attempt"]
  /\ toks' = [toks EXCEPT ![r] = @ + 1]
  /\ tref' = [tref EXCEPT ![r] = toks[r] + 1]
  /\ armed' = armed \cup {[r |-> r, k |-> "req", tok |-> toks[r] + 1]}
  /\ pipe' = Append(pipe, [t |-> "req", id |-> Id(r, 0), n |-> 0])
  /\ sent' = [sent EXCEPT ![r] = 1]
  /\ UNCHANGED <<cur, fired, running, out, cancelQ, cancelSent, delivered,
                 stale, spurious>>

PortRecv ==
  /\ pipe # <<>>
  /\ LET c == Head(pipe) IN
       running' = IF c.t = "req" THEN running \cup {[id |-> c.id, n |-> c.n]}
                  ELSE {x \in running : x.id # c.id}
  /\ pipe' = Tail(pipe)
  /\ UNCHANGED <<st, mode, cur, tref, toks, armed, fired, out, cancelQ,
                 cancelSent, delivered, sent, stale, spurious>>

\* curl ends a transfer, with an outcome the policy may or may not retry.
PortEnd(x, retry) ==
  /\ running' = running \ {x}
  /\ out' = Append(out, [id |-> x.id, n |-> x.n, retry |-> retry])
  /\ UNCHANGED <<st, mode, cur, tref, toks, armed, fired, pipe, cancelQ,
                 cancelSent, delivered, sent, stale, spurious>>

Fire(t) ==
  /\ armed' = armed \ {t}
  /\ fired' = fired \cup {t}
  /\ UNCHANGED <<st, mode, cur, tref, toks, pipe, running, out, cancelQ,
                 cancelSent, delivered, sent, stale, spurious>>

\* The armed timers once the entry's timer is cancelled.
Cancelled(r) == {t \in armed : ~(t.r = r /\ t.tok = tref[r])}

\* retry_or_resolve, from timers A (the armed set after any cancel_timer).
RetryOrResolve(r, retry, A) ==
  IF retry /\ cur[r] < MaxRetries
  THEN /\ mode' = [mode EXCEPT ![r] = "backoff"]
       /\ toks' = [toks EXCEPT ![r] = @ + 1]
       /\ tref' = [tref EXCEPT ![r] = toks[r] + 1]
       /\ armed' = A \cup {[r |-> r, k |-> "retry", tok |-> toks[r] + 1]}
       /\ UNCHANGED <<st, delivered>>
  ELSE /\ st' = [st EXCEPT ![r] = "done"]
       /\ mode' = [mode EXCEPT ![r] = "none"]
       /\ delivered' = [delivered EXCEPT ![r] = @ + 1]
       /\ armed' = A
       /\ UNCHANGED <<toks, tref>>

\* handle_port_msg -> attempt_ended: only the current transfer counts.
WorkerOut ==
  /\ out # <<>>
  /\ LET m == Head(out)
         r == m.id[1]
     IN /\ out' = Tail(out)
        /\ IF st[r] = "held" /\ mode[r] = "attempt" /\ Id(r, cur[r]) = m.id
           THEN /\ stale' = (stale \/ m.n # cur[r])
                /\ RetryOrResolve(r, m.retry, Cancelled(r))
           ELSE UNCHANGED <<st, mode, tref, toks, armed, delivered, stale>>
  /\ UNCHANGED <<cur, fired, pipe, running, cancelQ, cancelSent, sent,
                 spurious>>

Matches(t) == ~MatchTref \/ t.tok = tref[t.r]

\* {timeout, Tref, {req_timeout, Key}}: abort, then retry_or_resolve with
\* operation_timedout, which the policy retries. The fired timer is the
\* entry's, so nothing is cancelled.
WorkerReqTimeout(t) ==
  LET r == t.r IN
  /\ t \in fired /\ t.k = "req"
  /\ fired' = fired \ {t}
  /\ IF st[r] = "held" /\ mode[r] = "attempt" /\ Matches(t)
     THEN /\ spurious' = (spurious \/ t.tok # tref[r])
          /\ pipe' = Append(pipe, [t |-> "cancel", id |-> Id(r, cur[r]), n |-> cur[r]])
          /\ RetryOrResolve(r, TRUE, armed)
     ELSE UNCHANGED <<st, mode, tref, toks, armed, pipe, delivered, spurious>>
  /\ UNCHANGED <<cur, running, out, cancelQ, cancelSent, sent, stale>>

\* {timeout, Tref, {retry, Key}}: send again, arm a new request timer.
WorkerRetry(t) ==
  LET r == t.r
      n == cur[r] + 1
  IN
  /\ t \in fired /\ t.k = "retry"
  /\ fired' = fired \ {t}
  /\ IF st[r] = "held" /\ mode[r] = "backoff" /\ Matches(t)
     THEN /\ cur' = [cur EXCEPT ![r] = n]
          /\ mode' = [mode EXCEPT ![r] = "attempt"]
          /\ toks' = [toks EXCEPT ![r] = @ + 1]
          /\ tref' = [tref EXCEPT ![r] = toks[r] + 1]
          /\ armed' = armed \cup {[r |-> r, k |-> "req", tok |-> toks[r] + 1]}
          /\ pipe' = Append(pipe, [t |-> "req", id |-> Id(r, n), n |-> n])
          /\ sent' = [sent EXCEPT ![r] = @ + 1]
     ELSE UNCHANGED <<cur, mode, toks, tref, armed, pipe, sent>>
  /\ UNCHANGED <<st, running, out, cancelQ, cancelSent, delivered, stale,
                 spurious>>

CallerCancel(r) ==
  /\ CancelOn /\ st[r] = "held" /\ r \notin cancelSent
  /\ cancelSent' = cancelSent \cup {r}
  /\ cancelQ' = cancelQ \cup {r}
  /\ UNCHANGED <<st, mode, cur, tref, toks, armed, fired, pipe, running, out,
                 delivered, sent, stale, spurious>>

\* {cancel, Ref}: cancel the timer, abort the current transfer, remove.
WorkerCancel(r) ==
  /\ r \in cancelQ
  /\ cancelQ' = cancelQ \ {r}
  /\ IF st[r] = "held"
     THEN /\ st' = [st EXCEPT ![r] = "cancelled"]
          /\ mode' = [mode EXCEPT ![r] = "none"]
          /\ armed' = Cancelled(r)
          /\ pipe' = IF mode[r] = "attempt"
                     THEN Append(pipe, [t |-> "cancel", id |-> Id(r, cur[r]), n |-> cur[r]])
                     ELSE pipe
     ELSE UNCHANGED <<st, mode, armed, pipe>>
  /\ UNCHANGED <<cur, tref, toks, fired, running, out, cancelSent, delivered,
                 sent, stale, spurious>>

Next ==
  \/ \E r \in R : Admit(r) \/ CallerCancel(r) \/ WorkerCancel(r)
  \/ PortRecv
  \/ \E x \in running, retry \in BOOLEAN : PortEnd(x, retry)
  \/ \E t \in armed : Fire(t)
  \/ WorkerOut
  \/ \E t \in fired : WorkerReqTimeout(t) \/ WorkerRetry(t)

Spec == Init /\ [][Next]_vars

\* Fair to the worker, the port, curl ending transfers and the timers.
Fairness ==
  /\ \A r \in R : WF_vars(Admit(r)) /\ WF_vars(WorkerCancel(r))
  /\ WF_vars(PortRecv)
  /\ WF_vars(\E x \in running, retry \in BOOLEAN : PortEnd(x, retry))
  /\ WF_vars(\E t \in armed : Fire(t))
  /\ WF_vars(WorkerOut)
  /\ WF_vars(\E t \in fired : WorkerReqTimeout(t) \/ WorkerRetry(t))

FairSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
\* Properties

TypeOK ==
  /\ st \in [R -> {"new", "held", "done", "cancelled"}]
  /\ mode \in [R -> {"attempt", "backoff", "none"}]
  /\ cur \in [R -> 0..MaxRetries]

\* Each request gets at most one outcome.
AtMostOnce == \A r \in R : delivered[r] <= 1

\* The outcome a request gets, or the retry it makes, is its current
\* attempt's: never the late output of one it gave up on.
NoStale == ~stale

\* An attempt ends by timeout only on its own timer.
NoSpurious == ~spurious

\* Nothing is delivered after a cancel takes effect.
CancelQuiet == \A r \in R : st[r] = "cancelled" => delivered[r] = 0

\* At most max_retries retries.
RetriesBounded == \A r \in R : sent[r] <= MaxRetries + 1

CancelQueued(id) == \E i \in 1..Len(pipe) : pipe[i].t = "cancel" /\ pipe[i].id = id

\* Every transfer the port runs is its request's current attempt, or has
\* an abort on its way: none is left running for nobody.
NoOrphan ==
  \A x \in running :
    LET r == x.id[1] IN
      \/ st[r] = "held" /\ mode[r] = "attempt" /\ x.n = cur[r]
      \/ CancelQueued(x.id)

\* Every request ends, and the port is left running nothing.
Termination ==
  <>[](/\ \A r \in R : st[r] \in {"done", "cancelled"}
       /\ running = {} /\ pipe = <<>> /\ out = <<>>)

-----------------------------------------------------------------------------
\* Witnesses (-inv): each is violated, showing the state is reachable.

\* A transfer's late output reaches the worker after the request moved on.
WitnessStaleDropped ==
  ~(\E r \in R : /\ out # <<>> /\ Head(out).id[1] = r
                 /\ st[r] = "held" /\ Head(out).n < cur[r])
\* A request waits out a backoff with a cancel on its way.
WitnessCancelInBackoff == ~(\E r \in cancelQ : mode[r] = "backoff")
\* A request is retried to the limit.
WitnessMaxRetries == ~(\E r \in R : sent[r] = MaxRetries + 1 /\ st[r] = "done")
\* A stale request timer fires while a later attempt runs.
WitnessStaleTimer ==
  ~(\E t \in fired : t.k = "req" /\ st[t.r] = "held" /\ mode[t.r] = "attempt"
                     /\ t.tok # tref[t.r])

=============================================================================
