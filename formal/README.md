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
With `LimitOn`, `write_cb` may fail any chunk for `max_body_size`, from the
socket or as curl re-delivers it inside `curl_easy_pause`; `CompleteOnFail`
is whether `resume_conn` then completes the transfer itself.

| config | question | result |
|---|---|---|
| `KatipoFlow.cfg` | credit conservation, ≤ W chunks buffered, protocol order, no lost chunks, `paused` agrees with libcurl, termination (W=2, 4 chunks) | pass |
| `KatipoFlowLiveness.cfg` | a granting consumer always gets `done` (no timer/cancel/failure to hide behind) | pass |
| `KatipoFlowBatchStall.cfg` | consumer waits for more credits than the window holds | **fails** as expected: stall (documented in `update_flow/3`) |
| `KatipoFlowPausedLate.cfg` | sabotage: `flow_conn` clears `paused` after `curl_easy_pause` | **fails** as expected: a re-pause is lost and the transfer hangs forever |
| `KatipoFlowCrash.cfg` | everything above, with the port dying at any moment (even inside `curl_easy_pause`) | pass (13,375 states) |
| `KatipoFlowCrashLiveness.cfg` | port death the only hostile event: a granting consumer still always gets a terminal | pass |
| `KatipoFlowKill.cfg` | the worker killed outright | **fails** as expected: nothing ever arrives (the documented caveat) |
| `KatipoFlowLimit.cfg` | everything above, with `max_body_size` able to fail any chunk; a failure inside `curl_easy_pause` ends the transfer when it returns (`FailEnds`) | pass (14,541 states) |
| `KatipoFlowLimitLiveness.cfg` | `max_body_size` the only way to fail: a granting consumer still always gets a terminal | pass |
| `KatipoFlowLimitSwallowed.cfg` | sabotage: `resume_conn` ignores `curl_easy_pause`'s result, as it first shipped | **fails** as expected: the chunk re-delivered on resume fails and nothing ends the transfer but the request timer |

`KatipoFlowPausedLate.cfg` shows that the ordering comment in `flow_conn`
is load-bearing. With `-inv WitnessPaused`, `WitnessRepause`,
`WitnessFullWindow` and (on the crash config) `WitnessDiedMidBody`, TLC
reports each of those states as reachable, so the passing configs are not
vacuous; so is `WitnessFailOnResume` on the limit config. Dropping `terminate/2`'s `worker_died` makes
`KatipoFlowCrashLiveness.cfg` fail. `streaming_worker_death_mid_body` in
`katipo_SUITE` checks the same thing against the real code: headers, a
chunk, a port kill, then exactly one `worker_died` and silence.

**Found:** `KatipoFlowLimitSwallowed.cfg` is the hang a review reproduced on
libcurl 8.7.1: with `stream_window => 1`, the chunk that takes the body past
`max_body_size` was the one curl re-delivers inside `curl_easy_pause`, whose
error `resume_conn` dropped, so the error only came at `timeout_ms`.
`resumed_over_limit` in `katipo_limits_SUITE` reproduces it (fails on 8.7.1
before the fix, passes after), and `fuzz_transfer` now re-delivers a held
chunk inside a stand-in `curl_easy_pause` and checks the transfer ends then.


### Body handoff in the C port

`KatipoBodyHandoff.tla`: a buffered response body lives in an evbuffer, and
`send_ok_to_erlang` moves its chains into the output with
`evbuffer_add_buffer` instead of copying them; `free_conn` runs straight
afterwards while the pipe drains later. Two
buffered transfers and a streaming one share the output buffer, writes may
be partial, and bodies may be empty.

| config | question | result |
|---|---|---|
| `KatipoBodyHandoff.cfg` | each body freed exactly once, never written after it is freed, frames intact on the pipe, every body eventually freed | pass (460 states, every action fires) |
| `KatipoBodyHandoffCopy.cfg` | the same with the body copied into the output instead of moved, as before 2.0.1 (in today's frame layout) | pass |
| `KatipoBodyHandoffShared.cfg` | sabotage: the output references the body without taking it over | **fails** as expected: `free_conn` frees the body before libevent writes it |
| `KatipoBodyHandoffSplit.cfg` | sabotage: the frame is appended across callbacks | **fails** as expected: another transfer's frame lands inside it |

### libcurl's timer in the C port

`KatipoTimer.tla`: the C port's `multi_timer_cb`, `timer_cb` and
`event_cb` driving libcurl's `Curl_update_timer`. libcurl asks for its timer
with a delay counted from now; `evtimer_add` counts it from the time
libevent cached when the loop iteration began, so a timer set late in a long
callback (many transfers finishing at once) fires early. libcurl only asks
again when its next deadline changes. libcurl <= 8.9.1 and >= 8.11.1 forget
the deadline they reported whenever they are run for a timeout, which makes
an early fire harmless; 8.10.0 to 8.11.0 do not, so the early fire left no
timer pending and a timeout waited for unrelated socket activity. That was
the intermittent `async.streaming_timeout` failure in the HTTP/3 CI job,
which builds libcurl 8.11.0 alongside the current release. Timers also fire early for a second reason:
libevent and libcurl read different clocks (on Linux libevent defaults to
`CLOCK_MONOTONIC_COARSE`, libcurl uses `CLOCK_MONOTONIC_RAW`), which
`ClockLag` models. Refreshing libevent's cached time removes the first cause
but not the second, so the re-arm in `timer_cb` is what keeps the timer
armed. Socket activity and new requests are unfair environment actions, so
no result leans on them.

| config | question | result |
|---|---|---|
| `KatipoTimerOld811.cfg` | the port before the fix, libcurl 8.10.0-8.11.0 | **fails**: `AddDeadline → TimerFire` leaves a deadline with no timer |
| `KatipoTimerOld811Liveness.cfg` | the same, liveness only | **fails**: the deadline is never run |
| `KatipoTimerOld.cfg` | the port before the fix, other libcurl versions | pass |
| `KatipoTimerFixed.cfg` | the fix, libcurl 8.10.0-8.11.0: timer armed, deadlines on time, never set early, all run | pass |
| `KatipoTimerFixedReset.cfg` | the fix, other libcurl versions | pass |
| `KatipoTimerRefreshOnly.cfg` | only the cached-time refresh, Linux's coarse clock | **fails**: the timer fires a tick early and nothing re-arms it |
| `KatipoTimerRefreshOnlyOneClock.cfg` | only the refresh, both libraries on one clock | pass |
| `KatipoTimerRearmOnly.cfg` | only the re-arm in `timer_cb` | pass: enough alone, though timers still fire early |

Every config but the two `Old811` ones (no clock lag, to replay the CI
failure) has `ClockLag = 1`. With `-inv WitnessNoEarly`, TLC finds early
fires in every lagged config, the fixed port included, and none in
`RefreshOnlyOneClock`; with `Rearm = FALSE`, `KatipoTimerFixed.cfg` fails
`TimerArmed`, so its pass rests on the re-arm. `WitnessTwo` shows two
deadlines pending at once. Every action fires (`-coverage 1`), and the
verdicts are the same at `MaxTime = 11`, `MaxSkew = 3`, `MaxXfers = 3`.

### Streaming request bodies

`KatipoUpload.tla`: one async request whose body the caller streams on
demand (`body => {stream, _}`), with a streamed, windowed response, so the
upload's pause and the response's pause share one curl easy handle. The C
port's `read_stream_cb` sends one demand and pauses the upload when it
finds nothing to send;
`body_conn` buffers the caller's answer and resumes the upload, holding
the body to its declared length; and `write_cb`/`flow_conn` pause and
resume the response as in `KatipoFlow.tla`. Written before the code, as a
design check, and kept in step with it.

| config | question | result |
|---|---|---|
| `KatipoUpload.cfg` | the design, chunked, with timeouts, cancels, failures and an early response: body whole and in order, one chunk and one demand in flight, nothing after the terminal message, pause flags in step | pass |
| `KatipoUploadLength.cfg` | the same with the length declared: no demand once the whole length is in, and no eof read | pass |
| `KatipoUploadLiveness.cfg` | a caller that answers every demand: does every request finish with the whole body sent? | pass |
| `KatipoUploadEarlyLiveness.cfg` | the same, with the response free to finish before the body | pass |
| `KatipoUploadLengthLiveness.cfg` | the same with the length declared, though the caller is never asked for eof | pass |
| `KatipoUploadLiar.cfg` | a caller that sends past the declared length, ends short of it, or sends after eof: does curl ever get more than the length, or finish the upload with less? | pass |
| `KatipoUploadLiarChunked.cfg` | the same caller, chunked: does curl get exactly what was sent before eof? | pass |
| `KatipoUploadLiarLiveness.cfg` | that caller: does the request still finish, rather than leave the server waiting? | pass |
| `KatipoUploadCont.cfg` | plain `CURLPAUSE_CONT` instead of the masked resume: still safe? | pass |
| `KatipoUploadContLiveness.cfg` | plain `CURLPAUSE_CONT`: still live? | pass |
| `KatipoUploadContAgrees.cfg` | plain `CURLPAUSE_CONT`: do the pause flags drift from curl's? | **fails**, as expected |
| `KatipoUploadNoGuard.cfg` | no one-demand guard, plain `CONT`: a second demand before the first is answered? | **fails**, as expected |
| `KatipoUploadNoGuardMasked.cfg` | no guard, masked resume | pass: the guard is redundant there |
| `KatipoUploadEarly.cfg` | demanding as curl drains the buffer, not shipped: still safe, with the guard? | pass |
| `KatipoUploadNoGuardEarly.cfg` | that, without the guard | **fails**, as expected: the early demand needs the guard |
| `KatipoUploadEager.cfg` | a caller that sends without demand: more than one chunk buffered? | **fails**, as expected (the body still arrives whole) |
| `KatipoUploadLeanInv.cfg`, `KatipoUploadLeanInvChunked.cfg`, `KatipoUploadLeanLen.cfg` | the Lean proofs' invariants, mirrored, at one size larger | pass |

**Found.** `curl_easy_pause` sets the whole pause state, so plain
`CURLPAUSE_CONT` resuming one direction also resumes the other. That is
safe and live, because each callback re-checks its own state and pauses
again, but it lets katipo's flags disagree with curl's; the port resumes
with a mask instead. With the mask the one-demand guard is redundant:
only the answer resumes the upload. It stays as defence in depth.
Sending the demand as soon as curl drains the buffer, so the next chunk
travels while curl sends the last, is safe too, but makes the guard
necessary, since curl's next read finds the buffer empty with the demand
still out; it measured no faster (`test/katipo_upload_bench.erl`), so it
is not shipped. curl before 8.7 does not hold a body to its declared length,
so the port does: a chunk past it, or eof short of it, fails the upload,
and anything after eof is ignored.
Witnesses (`-inv`): both directions paused at once, `read_stream_cb` running
inside `curl_easy_pause`, a demand queued behind a timeout's error, and a
lie ending in an error all happen; with the early demand, so does a
demand outstanding while curl reads. Sabotage that each config catches: never clearing the outstanding
demand or never resuming the upload (liveness), dropping the buffered chunk
(`BodyConserved`), forwarding a demand after letting go (`ProtocolOrder`),
taking a chunk after eof, skipping the length check or not aborting a
failed upload (`BodyIsSent`, `LengthHeld`). Letting the worker relay a
body after a cancel changes nothing: the port drops it. Every action and
branch fires in some config (`-coverage 1`), and the verdicts hold at
`Total = 3`, `W = 2`, `Resp = 3`.

### Retries

`KatipoRetry.tla`: requests with a retry policy, each sent again after a
failed attempt, through one worker and its C port. The worker ends an
attempt on a terminal message for the request's current transfer or on its
own request timer, then backs off and sends again under a fresh port id, or
resolves; a cancel can come at any time, a backoff included. Whether an
outcome is retryable is the port's free choice, so every policy, method
and status is covered, and the worker takes the port's output, each fired
timer and the caller's cancel in any order across senders.

| config | question | result |
|---|---|---|
| `KatipoRetry.cfg` | two requests, one retry each: one outcome per request, from its current attempt; nothing after a cancel; at most `max_retries` retries; no attempt cut short by another's timer; no transfer left running for nobody | pass |
| `KatipoRetryDeep.cfg` | the same, one request retried up to three times | pass |
| `KatipoRetryLiveness.cfg` | fair to the worker, the port, curl and the timers: does every request end with the port running nothing? | pass |
| `KatipoRetryReuse.cfg` | each retry reusing the request's key as its port id | **fails**, as expected: a late message from the attempt given up on is taken for the retry's |
| `KatipoRetryReuseOrphan.cfg` | the same | **fails**, as expected: the retry's transfer runs for a request already resolved |
| `KatipoRetryNoTref.cfg` | no `Tref` match in the `req_timeout` clause | **fails**, as expected: the first attempt's timer, fired as that attempt ended, cuts the retry short |
| `KatipoRetryLeanInv.cfg` | the Lean proof's invariants, mirrored, at one retry more | pass (11.4M states) |

**Found.** Both mechanisms the design added are load-bearing, and both
races need only the port's output and a timer message crossing in the
worker's mailbox. Before retries, `From` was never registered twice, so
matching `Tref` was redundant; with retries one request has a timer per
attempt, and a timer that fired as its attempt ended must not count
against the next. Each counterexample is reproduced against the real
worker by `stale_port_output_dropped` and `stale_timer_ignored` in
`test/katipo_retry_SUITE.erl`, which fail with the matching mechanism
removed. Witnesses (`-inv`): late output arriving after the request moved
on, a cancel queued during a backoff, a request retried to the limit, and
a stale request timer firing while a later attempt runs all happen. Every
action fires (`-coverage 1`).

## Lean proofs (`lean/`)

Core Lean 4 only (no Mathlib), toolchain pinned in `lean/lean-toolchain`.

```sh
cd lean && ./check.sh
```

`check.sh` builds everything. `KatipoProofs/Axioms.lean` pins every headline
theorem to the standard axioms with `#guard_msgs`, so a `sorry`,
`native_decide` or new `axiom` breaks the build. The script also re-runs the
TLC ↔ Lean state-graph cross-check.

Headline statements live in each topic's `Statements.lean`; proofs only
delegate to them.

### Flow control: every window and body size

With `P.deaths`, every theorem below also covers the C port dying at any
moment, the worker then reading its `'EXIT'` and stopping. With `P.limits`,
it also covers `write_cb` failing any chunk for `max_body_size`, from the
socket or inside `curl_easy_pause`.

| theorem | says |
|---|---|
| `credit_conservation` | while both sides hold the request, all `W` credits are in the window, riding a chunk, owed by the consumer, or riding a grant |
| `bounded_buffering` | at most `W` chunks are ever buffered between the C port and the consumer |
| `no_lost_chunks` | `done` implies every body chunk arrived |
| `paused_agrees` | katipo's `paused` flag always equals libcurl's pause state, including inside `curl_easy_pause` |
| `fail_ends` | a transfer `write_cb` failed inside `curl_easy_pause` is over once it returns |
| `steps_bounded` | every execution, fair or not, ends within `15·total + 31` steps (3 more if the port may die, 1 more with `max_body_size`) |
| `stuck_is_good` | with `batch ≤ W` and the shipped `resume_conn`, any state with no enabled step has delivered a terminal message or was cancelled, port death and `max_body_size` included |
| `batch_gt_window_stalls` | `batch ≤ W` is necessary (explicit trace) |
| `clear_late_stalls` | the `flow_conn` ordering is necessary (explicit trace) |
| `swallowed_failure_stalls` | `resume_conn` completing a failed transfer is necessary (explicit trace) |

The statements were re-frozen for `max_body_size`: the earlier model is the
case `P.limits = false`, `steps_bounded`'s bound gained `P.limits`, and
`stuck_is_good` gained the `resume_conn` hypothesis, which
`swallowed_failure_stalls` shows it cannot do without.

Together, `steps_bounded` and `stuck_is_good` say every run of the shipped
protocol ends well, with no fairness assumption. TLC needed weak fairness for
the same conclusion.

**Cross-check.** `Flow/Executable.lean` defines a computable `succs`, proved
equal to `Step` (`succs_iff`). `scripts/FlowGraph.lean` enumerates its
reachable graph for the instances of `KatipoFlow.cfg`, `KatipoFlowCrash.cfg`
and `KatipoFlowLimit.cfg`, and `scripts/crosscheck_flow.py` diffs each
against TLC's `-dump dot`. All three pairs are identical: 7,777 states and
23,546 edges, 13,375 states and 42,894 edges, and 14,541 states and 45,986
edges. Mutating one TLA+ action
(the timeout no longer aborts the port) makes the diff report 2,028 / 4,056
unmatched states.

### `max_body_size`: any limit and any chunk sizes

`Limit/Model.lean` transcribes `body_too_large` and `write_cb`'s use of it
over the chunks curl hands it, with any Content-Length or none.

| theorem | says |
|---|---|
| `fails_iff` | without a usable Content-Length, the transfer fails exactly when the decoded body is over the limit |
| `forwarded_le` | whatever the Content-Length, no more than the limit is ever forwarded |
| `forwarded_is_prefix`, `forwarded_all` | what is forwarded is the body's first chunks, in order, and all of them unless the transfer failed |
| `refused_overflows` | the chunk refused is the one that would have gone over: nothing that fits is refused |
| `upfront_only_sooner` | with an honest Content-Length, the up-front check changes no verdict, and a failure forwards nothing |

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

### libcurl's timer: any clock, callback length and number of deadlines

`Timer/Model.lean` transcribes `KatipoTimer.tla` without its bounds: an
unbounded clock, any number of deadlines at any delay, and callbacks of any
length up to `P.skew`, with libevent's clock up to `P.lag` ahead. `Safe P`
means the re-arm in `timer_cb` or libcurl's own reset is present, or the
cached-time refresh is and both libraries read one clock (`P.lag = 0`).

| theorem | says |
|---|---|
| `timer_armed` | with `Safe P`, a timer is pending whenever libcurl has a deadline |
| `timely` | with `Safe P`, no deadline is overdue by more than one callback |
| `not_early` | with the refresh, the pending timer is never set before libcurl's next deadline (it can fire up to `P.lag` before it) |
| `old_811_late` | the port before the fix with libcurl 8.10.0-8.11.0: a deadline with no timer, overdue by any amount (explicit trace) |
| `refresh_only_late` | the refresh alone, libcurl 8.10.0-8.11.0, `P.lag = 1`: the same (explicit trace) |

The invariant (`Inv`) is mirrored as `LeanInv` in `KatipoTimer.tla`, and
every config the proof covers lists it, so `check-configs.sh` checks it.
Counting the refresh as safe with a lagging clock breaks the proof at the
case where the timer fires before the deadline was due.

### Streaming request bodies: any body and response size

`Upload/Model.lean` transcribes `KatipoUpload.tla` without its bounds: any
number of body chunks, any window, any response length, chunked or with the
length declared, with the demand sent only on an empty read (the
shipped setting; the spec's `EarlyDemand` is not transcribed). Headline
statements are in `Upload/Statements.lean`; the honest-caller ones assume
`P.liar = false`.

| theorem | says |
|---|---|
| `body_conserved` | while both sides hold the request, every chunk sent is read by curl or on its way to it |
| `complete_body` | curl finishes the upload only after every chunk, and after the caller's eof unless the length was declared |
| `one_chunk_in_flight` | a caller that waits for demand has at most one chunk between it and curl (either safeguard) |
| `one_demand` | at most one demand outstanding, given either safeguard: the guard or the masked resume |
| `length_held` | whatever the caller sends, curl never gets more than the declared length |
| `length_complete` | whatever the caller sends, curl finishes the upload only with exactly the declared length |
| `pause_flags_agree` | with the masked resume, both pause flags always equal curl's, inside `curl_easy_pause` too |
| `protocol_order` | nothing reaches the caller after its terminal message |
| `no_safeguard_two_demands` | one safeguard is necessary (explicit trace) |
| `eager_two_chunks` | waiting for demand is necessary for the bound (explicit trace) |
| `cont_flags_drift` | the mask is necessary for the flags to agree (explicit trace) |

Each invariant is mirrored in `KatipoUpload.tla` (`LeanEof`, `LeanHon`,
`LeanDem`, `LeanOrd`, `LeanAgree`, `LeanLen`), which
`KatipoUploadLeanInv.cfg`, `KatipoUploadLeanInvChunked.cfg` and, for a
lying caller, `KatipoUploadLeanLen.cfg` check. Weakening any of four
guards in the model (`read_stream_cb` without a chunk, a send without a
demand, the worker forwarding after letting go, eof before the last chunk)
breaks a proof at the step that needs it, and so do dropping the length
check or buffering a chunk the check refused. Taking a chunk
after eof breaks none: with a declared length the check refuses it anyway,
and a chunked body's lying caller is left to `KatipoUploadLiarChunked.cfg`.
Liveness is TLC-checked only.

### Retries: any number of requests and retries

`Retry/Model.lean` transcribes `KatipoRetry.tla` without its bounds: any
number of requests, any `max_retries`, the worker taking the port's output
in any order. Headline statements are in `Retry/Statements.lean`.

| theorem | says |
|---|---|
| `at_most_once` | each request gets at most one outcome |
| `cancel_quiet` | nothing is delivered after a cancel takes effect |
| `retries_bounded` | a request is sent at most `max_retries + 1` times |
| `no_stale` | with fresh port ids, an outcome or a retry comes from the request's current attempt, never the late output of one it gave up on |
| `no_spurious` | matching `Tref`, an attempt ends by timeout only on its own timer |
| `no_orphan` | with fresh port ids, every transfer the port runs is its request's current attempt or has an abort queued behind it |
| `reuse_stale`, `reuse_orphan` | fresh ids are necessary (explicit traces) |
| `no_tref_spurious` | matching `Tref` is necessary (explicit trace) |

The invariants are mirrored in `KatipoRetry.tla` as `LeanGen` and
`LeanFr`, which `KatipoRetryLeanInv.cfg` checks. Weakening any of five
guards in the model breaks a proof at the step that needs it: the
current-transfer check in `attempt_ended`, the abort on a timeout or on a
cancel, the `Tref` match, and the `max_retries` bound. Liveness is
TLC-checked only.

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
- libcurl's timer contract, read from `lib/multi.c` at curl-8_5_0,
  curl-8_11_0 and curl-8_12_0: `Curl_update_timer` calls the timer callback
  only when the next deadline changes, and the timeout path clears the last
  reported deadline in every version except 8.10.0 to 8.11.0. libevent's
  `evtimer_add` counting from the time cached at the start of the loop
  iteration is from its documentation (`event_base_update_cache_time`).
  The clocks (libevent 2.1 `evutil_time.c`, curl `lib/timeval.c`) are read
  from source; the model assumes their difference is bounded by `ClockLag`
  ticks.

- libcurl's read pause contract: `CURL_READFUNC_PAUSE` pauses sending until
  `curl_easy_pause` resumes it, after which the read callback is called again, and
  `curl_easy_pause` sets both directions' pause state at once.
- libcurl's upload length: with a declared length (`POSTFIELDSIZE_LARGE`)
  curl stops calling the read callback once it has sent that many bytes,
  and reads no eof. It does not hold the callback to the length (before
  8.7 the excess goes on the wire), which is why the port does.

- Retries: `katipo_retry:delay/5` decides whether and when, and is
  unit-tested rather than modelled: the models leave both to the port's
  and the timers' free choice. Nor do the models have the worker's `ids`
  map (port id -> key) that `current/2` resolves a port message through:
  each message names its request directly, and the map's upkeep is left
  to `stale_port_output_dropped` and the other worker tests.

If you change the worker dispatch/delivery logic or the C flow-control path,
update the matching spec and Lean transcription and re-run everything above.
