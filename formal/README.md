# Formal models of katipo

Two layers, each checking the other:

- **TLA+ / TLC** explores every interleaving of small instances (2 requests,
  1–2 port deaths, a handful of chunks) and finds bugs fast.
- **Lean 4** proves the same safety properties for *every* size: any number
  of requests, crashes, restarts, any window and body size.

Both describe the *protocol*. Neither proves the Erlang or C code matches it;
the transcriptions cite the code they mirror, and every bug they found was
reproduced against the real code by a test before it was fixed. Trace
validation (below) checks the link the other way: recorded runs of the real
code, replayed against the Lean admission model.

## TLA+ models

Requires Java and [tla2tools.jar](https://github.com/tlaplus/tlaplus/releases)
(a recent nightly: the configs use `-dump`, `-inv` and `SYMMETRY`).

```sh
java -cp tla2tools.jar tlc2.TLC -deadlock -workers auto -config KatipoFixed.cfg KatipoFixed.tla
```

`-deadlock` is needed throughout: a finished run is a legitimate end state.

### Async admission and delivery

Caller → `katipo_worker` gen_server → C port/libcurl: the `Reqs` registry,
per-request timers, cancels, port death, worker crash, supervisor restart,
the bounded admission call and its deadline. The sync path is not modeled:
`gen_server:call`'s monitor already turns worker death into an exit that
`katipo:call_worker/2` maps to `worker_died`.

| config | spec | question | result |
|---|---|---|---|
| `KatipoSafety.cfg` | `Katipo.tla` | pre-fix at-most-once and effective-cancel | pass |
| `KatipoPollution.cfg` | `Katipo.tla` | pre-fix: cancel against a dead port | **fails** (fixed) |
| `KatipoLiveness1.cfg` | `Katipo.tla` | pre-fix: cast lost in the badarg window | **fails** (fixed) |
| `KatipoLiveness2.cfg` | `Katipo.tla` | pre-fix: cast to a restarting worker | **fails** (fixed) |
| `KatipoAdmissionTimeout.cfg` | `KatipoFixed.tla` | #185's bounded admission call, no deadline | **fails** (fixed) |
| `KatipoDeadlineRace.cfg` | `KatipoFixed.tla` | the deadline without the slack assumption | **fails** (documented residual) |
| `KatipoFixed.cfg` | `KatipoFixed.tla` | current protocol, safety + liveness, 1 port death | pass (~5.3M states, ~3 min) |
| `KatipoFixedSafety.cfg` | `KatipoFixed.tla` | current protocol, safety, 2 port deaths, symmetry | pass |

`Katipo.tla` keeps the protocol before the async dispatch fixes as a record of
three defects (each reproduced in `test/katipo_async_failure_SUITE.erl`).
`KatipoFixed.tla` is the current protocol; its constants switch the variants:

- `CallerTimeouts`: the caller's admission call may time out
  (`katipo:attempt/3` → `admission_timeout`).
- `DeadlineCheck`: the worker refuses an admission past its deadline, checked
  before `send_to_port` and again after it (`katipo_worker:admit_call/3`).
- `ReplyWithinSlack`: the timing assumption the deadline rests on. Once the
  post-check passes, the reply reaches the caller before its timer fires. The
  caller stamps the deadline `?ADMISSION_SLACK` (250 ms) ahead of its own
  timeout, and the segment it must cover (start a timer, insert into a map,
  create an alias, reply) never blocks.

**Found:** with `CallerTimeouts` and no `DeadlineCheck` (the code as of #185),
a caller told `admission_timeout` could still have its request admitted later
by the slow worker. The transfer ran, and a terminal message arrived for a
`Ref` the caller never saw. Trace: `SendAsync → Expire → CallerTimeout →
WorkerRecvReq → WorkerAdmitCheck → WorkerAdmitReply`. Reproduced by
`no_message_after_admission_timeout` (fails before the fix, passes after).

### Streaming flow control

`KatipoFlow.tla`: one streaming request with `stream_window => W`. It covers
the C side (`write_cb` pausing at zero credits, `flow_conn` adding credits and
calling `curl_easy_pause(CONT)`, which may call `write_cb` synchronously and
re-pause), the worker relay, and a consumer granting credits back through
`update_flow/3`. Timer, consumer cancel and curl failure can all happen at any
time, and so can the C port dying (`PortDeathsOn`: the worker reads the
port's `'EXIT'` after everything the port sent, stops, and `terminate/2`
sends `worker_died`) or the worker being killed outright (`KillsOn`).

| config | question | result |
|---|---|---|
| `KatipoFlow.cfg` | credit conservation, ≤ W chunks buffered, protocol order, no lost chunks, `paused` agrees with libcurl, termination (W=2, 4 chunks) | pass |
| `KatipoFlowLiveness.cfg` | a granting consumer always gets `done` (no timer/cancel/failure to hide behind) | pass |
| `KatipoFlowBatchStall.cfg` | consumer waits for more credits than the window holds | **fails** as expected: stall (documented in `update_flow/3`) |
| `KatipoFlowPausedLate.cfg` | sabotage: `flow_conn` clears `paused` after `curl_easy_pause` | **fails** as expected: a re-pause is lost and the transfer hangs forever |
| `KatipoFlowCrash.cfg` | everything above, with the port dying at any moment (even inside `curl_easy_pause`) | pass (13,375 states) |
| `KatipoFlowCrashLiveness.cfg` | port death the only hostile event: a granting consumer still always gets a terminal | pass |
| `KatipoFlowKill.cfg` | the worker killed outright | **fails** as expected: nothing ever arrives (the documented caveat) |

`KatipoFlowPausedLate.cfg` shows that the ordering comment in `flow_conn`
is load-bearing. With `-inv WitnessPaused`, `WitnessRepause`,
`WitnessFullWindow` and (on the crash config) `WitnessDiedMidBody`, TLC
reports each of those states as reachable, so the passing configs are not
vacuous. Dropping `terminate/2`'s `worker_died` makes
`KatipoFlowCrashLiveness.cfg` fail. `streaming_worker_death_mid_body` in
`katipo_SUITE` checks the same thing against the real code: headers, a
chunk, a port kill, then exactly one `worker_died` and silence.


### Body handoff in the C port

`KatipoBodyHandoff.tla`: a buffered response body lives in an evbuffer, and
`send_ok_to_erlang` moves its chains into the output with
`evbuffer_add_buffer` instead of copying them; `free_conn` runs straight
afterwards while the pipe drains later. Two
buffered transfers and a streaming one share the output buffer, writes may
be partial, and bodies may be empty.

| config | question | result |
|---|---|---|
| `KatipoBodyHandoff.cfg` | each body freed exactly once, never written after it is freed, frames intact on the pipe, every body eventually freed | pass (548 states, every action fires) |
| `KatipoBodyHandoffCopy.cfg` | the same for the previous code, which copied the body | pass |
| `KatipoBodyHandoffShared.cfg` | sabotage: the output references the body without taking it over | **fails** as expected: `free_conn` frees the body before libevent writes it |
| `KatipoBodyHandoffSplit.cfg` | sabotage: the frame is appended across callbacks | **fails** as expected: another transfer's frame lands inside it |

## Lean proofs (`lean/`)

Core Lean 4 only (no Mathlib), toolchain pinned in `lean/lean-toolchain`.

```sh
cd lean && ./check.sh
```

`check.sh` builds everything. `KatipoProofs/Axioms.lean` pins every headline
theorem to the standard axioms with `#guard_msgs`, so a `sorry`,
`native_decide` or new `axiom` breaks the build. The script also re-runs the
TLC ↔ Lean state-graph cross-check.

Headline statements live in `Flow/Statements.lean` and
`Admission/Statements.lean`; proofs only delegate to them.

### Flow control: every window and body size

With `P.deaths`, every theorem below also covers the C port dying at any
moment, the worker then reading its `'EXIT'` and stopping.

| theorem | says |
|---|---|
| `credit_conservation` | while both sides hold the request, all `W` credits are in the window, riding a chunk, owed by the consumer, or riding a grant |
| `bounded_buffering` | at most `W` chunks are ever buffered between the C port and the consumer |
| `no_lost_chunks` | `done` implies every body chunk arrived |
| `paused_agrees` | katipo's `paused` flag always equals libcurl's pause state, including inside `curl_easy_pause` |
| `steps_bounded` | every execution, fair or not, ends within `15·total + 31` steps (3 more if the port may die) |
| `stuck_is_good` | with `batch ≤ W`, any state with no enabled step has delivered a terminal message or was cancelled, port death included |
| `batch_gt_window_stalls` | `batch ≤ W` is necessary (explicit trace) |
| `clear_late_stalls` | the `flow_conn` ordering is necessary (explicit trace) |

Together, `steps_bounded` and `stuck_is_good` say every run of the shipped
protocol ends well, with no fairness assumption. TLC needed weak fairness for
the same conclusion.

**Cross-check.** `Flow/Executable.lean` defines a computable `succs`, proved
equal to `Step` (`succs_iff`). `scripts/FlowGraph.lean` enumerates its
reachable graph for `KatipoFlow.cfg`'s instance and for
`KatipoFlowCrash.cfg`'s, and `scripts/crosscheck_flow.py` diffs each against
TLC's `-dump dot`. Both pairs are identical: 7,777 states and 23,546 edges,
and 13,375 states and 42,894 edges. Mutating one TLA+ action
(the timeout no longer aborts the port) makes the diff report 2,028 / 4,056
unmatched states.

### Admission and delivery: any number of requests and crashes

| theorem | says |
|---|---|
| `at_most_once` | each request gets at most one terminal outcome: a message, or an error returned by `async_req` |
| `no_message_after_admission_error` | `admission_timeout` means never admitted, never messaged |
| `no_delivery_after_effective_cancel` | nothing is delivered after a cancel takes effect |
| `no_progress_after_stop` | no chunk is forwarded after cancel or resolution |
| `telemetry_at_most_once` | each request's OpenTelemetry span is ended at most once and its metrics recorded at most once |
| `no_deadline_double_delivery` | the #185 bug, as an explicit trace |
| `no_deadline_double_telemetry` | the same bug also ended the span and recorded metrics twice |
| `no_slack_double_delivery` | the deadline needs `ReplyWithinSlack` (explicit trace) |

The telemetry counters exist only in the Lean model. They count the
`katipo_span` calls at each code site: `finish_async/4` on every terminal
outcome, and `end_async/1` on an effective cancel. No step reads them, so
they add nothing to the TLA+ spec's behaviours.

These hold under `Safe P`, which is either the shipped protocol (deadline plus
slack) or the pre-#185 one whose caller never gave up.

The Lean model is more permissive than the TLA+ one in four ways. The port
and timers may inject any response, timeout or chunk for any request at any
time. The worker may crash at any moment, or be killed outright without
running `terminate/2`. And the worker may take its next message from anywhere
in its mailbox, so the results do not even rest on Erlang's per-sender
ordering. All four only add behaviours, so the safety results carry over to
the real code, and they remove the port queue from the proof.

### The exact model: port, timers, liveness

`Admission/Full.lean` transcribes `KatipoFixed.tla` as it is: one FIFO
mailbox with timeout and exit messages, the worker -> port pipe, the
port's running transfers, port deaths and request timers. Only the
state-space bounds (`MaxPortDeaths`, `MaxChunks`) are dropped.

| theorem | says |
|---|---|
| `exact_refines` | every exact step is a step (or stutter) of the loose model, so all of the above holds for the exact one |
| `no_orphan_transfer` | every transfer the port runs is in `Reqs`, being admitted, or has an abort queued *behind* it |
| `eventual_outcome` | in every behaviour fair to the worker and the request timers, each sent request is answered or was cancelled |
| `timer_fairness_needed` | the timer is necessary: fair to worker, port and supervisor, an admitted request can wait forever |

`eventual_outcome` needs less than the TLA+ spec assumes: no fairness for
the port or the supervisor. The worker draining its mailbox and the
request timer firing are enough, because a dead worker has already
resolved everything it held. The fairness hypotheses use explicit enabling
conditions, and `wenabled_step` / `tenabled_step` show each one implies
TLA's `ENABLED`, so they are no stronger than `WF_vars`. The proof walks a
request through four stages (queued, being admitted, held with its timer
armed, timeout queued), each ended by a fair action that lowers a measure.

### Which mechanisms are redundant

Each candidate is a second model with that mechanism removed
(`Admission/Simplify.lean`, `Flow/Simplify.lean`). Redundancy
is proved by a simulation in both directions: every step of one model is
matched by at most one step of the other, and the two related states agree
on everything a caller or a property can observe. Load-bearing mechanisms
get a counterexample instead.

| mechanism | verdict | theorem |
|---|---|---|
| first deadline check in `admit_call` (before `send_to_port`) | redundant for every `P`. It only saves starting a C transfer that the second check would abort at once | `pre_check_redundant`, `_rev` |
| second deadline check (after `send_to_port`) | load-bearing: without it a request is resolved twice when `port_command` blocks past the deadline | `no_post_check_double_delivery` |
| `is_map_key` guard on `{flow, Ref, N}` in the worker | redundant: a late grant reaches the port only behind the conn's cancel or end, where `find_conn` returns NULL | `flow_guard_redundant`, `_rev` |
| `ConnInfo.paused` in `flow_conn` | always equals libcurl's own pause state, so `curl_easy_pause(CONT)` could be called on every grant. This relies on libcurl's early return when the state does not change | `paused_agrees` |

The admission model already gives timers and responses for any request at
any time, and always delivers cancel messages. So the safety theorems also
hold without three more mechanisms:

* `erlang:cancel_timer/1` on resolution;
* matching `Tref` in the `req_timeout` clause (`From` is never
  registered twice);
* `unalias/1` on resolution.

Of these, `cancel_timer` and `unalias` are still needed for resources: a
timer left running per completed request, and an alias-table entry
leaked for every async request.

## Trace validation

```sh
formal/trace.sh                               # every suite (needs httpbin)
formal/trace.sh --suite katipo_stress_SUITE   # just the randomized workload
```

The test profile compiles `src/` with `KATIPO_TRACE`, which turns the
`?TRACE` hooks in `katipo` and `katipo_worker` into calls to
`test/katipo_trace.erl`; every other build compiles them away. With
`KATIPO_TRACE_DIR` set, the suites record each admission attempt's send and
outcome, each worker decision (pre/post deadline check with the clock read
just before it, admit, deliver or drop, forward or drop a chunk, cancel or
no-op), and the `worker_died` messages `terminate/2` actually sends.

`lake exe tracecheck` replays each worker slot's events against the
admission model (`Admission/Trace.lean`), checking that every branch the
code took is the one the model takes in that state. The checker is correct
by construction: it can only accept a trace by building a proof that the
final state is reachable, so an accepted trace is a run of the model and
the headline theorems hold along it (`accepted_safe`).

`katipo_stress_SUITE` exists mostly for its trace: 24 concurrent callers on
a 3-worker pool with `max_in_flight`, buffered and streaming requests,
random cancels and request timeouts, while a chaos process closes worker
ports, kills a worker and wedges one past the admission deadline. A run
records about 1,900 events.

**Teeth.** Each of these deliberate bugs in `katipo_worker` left every test
passing, stress suite included, and was rejected by the checker:

| mutation | rejected at |
|---|---|
| an effective cancel leaves the request in `Reqs` | `terminate/2` told a request the model had cancelled |
| a terminal response leaves the request in `Reqs` | same |
| `terminate/2` sends no `worker_died` | told `[]`, model's `Reqs` non-empty |
| both deadline checks removed | pre-check passed with the clock past the deadline |

Removing only the pre-check is accepted, rightly: the post-check still
refuses, and the model agrees the pre-check is an optimisation.

**Reach.** Only the async admission path is traced; sync requests, the C
port and streaming credit accounting are not. Telemetry is not observed
directly: its counters follow from deliveries by construction of the code
(`finish_async/4` sits beside every send), which the model assumes. Caller
outcomes are matched by attempt; spillover across workers is visible only
as separate attempts.

## Trusted, not proved

- The transcriptions. Anchors: `katipo_worker.erl`, `katipo.erl` and
  `c_src/katipo.c` as of the commit introducing this directory.
- libcurl's pause contract: data refused with `CURL_WRITEFUNC_PAUSE` is
  re-delivered after `CURLPAUSE_CONT`, and the handle does not complete
  while paused. Synchronous delivery inside `curl_easy_pause` is modeled as
  arbitrary.
- Erlang's per-sender FIFO delivery (flow control only; the admission
  safety proofs no longer need it), the worker reading its mailbox oldest
  first (gen_server's catch-all receive; admission liveness only), and
  `erlang:monotonic_time` being one clock for all processes on a node
  (pools are local).
- The fairness assumptions of `eventual_outcome`: the BEAM schedules a
  runnable worker, and `erlang:start_timer` fires.
- `ReplyWithinSlack`: the 250 ms slack is a timing argument, not a proof.

If you change the worker dispatch/delivery logic or the C flow-control path,
update the matching spec and Lean transcription and re-run everything above.
