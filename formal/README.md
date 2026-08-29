# Formal models of the katipo worker/port protocol

TLA+ models of the async request path: caller → `katipo_worker` gen_server →
C port/libcurl, including the `Reqs` registry, per-request timers, cancels,
port death, worker crash, and supervisor restart. The sync path is not
modeled: `gen_server:call`'s monitor already converts worker death into an
exit that `katipo:call_worker/2` maps to `worker_died`.

## Files

- `Katipo.tla` — the protocol **before** the async dispatch fixes, kept as
  documentation of three real defects TLC found (each was reproduced against
  the implementation in `test/katipo_async_failure_SUITE.erl`, then fixed):
  - `KatipoSafety.cfg` — passes: at-most-once delivery and the
    effective-cancel contract held even pre-fix.
  - `KatipoPollution.cfg` — **fails**: a cancel processed against a dead port
    crashed the worker via `port_command` badarg before `maps:remove`, so
    `terminate/2` messaged the cancelled caller.
  - `KatipoLiveness1.cfg` — **fails**: an async cast reaching a worker whose
    port just died was lost in the `send_to_port`-before-`Reqs`-insert crash
    window; no `worker_died` was ever delivered.
  - `KatipoLiveness2.cfg` — **fails**: an async cast to a dead/restarting
    worker name was silently dropped (uses a state constraint to mask the
    first family so TLC exhibits this one).
- `KatipoFixed.tla` / `KatipoFixed.cfg` — the current protocol: async
  admission as a `wpool:call` handshake and best-effort cancel. All four
  properties (at-most-once, effective-cancel, no cancel pollution, eventual
  outcome) pass.
- `KatipoReq.tla` — the full current request lifecycle in one spec: worker,
  C port event loop, request timers, and an unfair caller over per-sender
  FIFO channels; streaming with the credit window, flow grants, cancel,
  timeout, and port death all racing. PlusCal; invariants and properties
  live after the translation. Configs are tiered by state-space size, each
  annotated with its question and expected result:
  - `KatipoReq_safety1.cfg` / `KatipoReq_safety2.cfg` — exactly-once
    terminal delivery, `Reqs`/alias discipline, window accounting, message
    ordering (asserted in the caller's receive step). Both pass (safety2:
    162M distinct states, ~23min).
  - `KatipoReq_liveness.cfg` / `KatipoReq_liveness2.cfg` — every accepted
    request resolves exactly once, resting only on worker/port/timer
    fairness (the caller may walk away). Both pass.
  - `KatipoReq.cfg` — the full-size everything-on config; very large
    (215M+ distinct states explored with no violation before being stopped
    for time, on a pre-slimming encoding). Kept for machines with hours to
    spare.
  - `KatipoReq_witness_*.cfg` — expect **violations**: proofs the model
    reaches the timeout path, pause→grant→resume→done, `worker_died`
    delivery, the stale-message drop, and silent cancel.
  - `KatipoReq_sabotage_*.cfg` — expect **violations**: deliberate model
    mutations (drop the `Reqs` membership check; drop `terminate/2`'s
    notification) proving the invariants and liveness property have teeth.
- `KatipoAdmit.tla` — the admission handshake at message granularity, which
  `KatipoReq` treats as atomic. Found a real contract gap: after
  `{error, admission_timeout}` the request could still run and deliver a
  terminal message to `reply_to` with a ref the caller never received.
  - `KatipoAdmit.cfg` — **fails** (that finding, pre-fix).
  - `KatipoAdmit_fix_lateadmit.cfg` — passes: the deadline stamped into the
    admission call (`katipo:stamp/2`, refused in `admit_call`) closes the
    late-admit mechanism. Reproduced and regression-tested in
    `test/katipo_async_failure_SUITE.erl`
    (`late_admission_refused_after_caller_timeout`).
  - `KatipoAdmit_fix_contract.cfg` — **fails** by design: the residual
    reply-in-flight race is not closable from the worker's side; the
    `async_req` docs state the resulting drop-unknown-refs contract.
  - `KatipoAdmit_span_master.cfg` — **fails**: before any span fix the same
    residual race had both `dispatch_async` and the worker finish the one
    `katipo_span` Obs, so `katipo_metrics:notify` double-counted.
  - `KatipoAdmit_span_idempotent_only.cfg` — **fails** `NoFabricatedOutcome`:
    making the finish idempotent and changing nothing else is *not* enough.
    Exactly-once then holds, but the caller wins the claim (it claims the
    instant its bound elapses; the worker only at resolution), so the
    surviving record is a fabricated `admission_timeout` for a request that
    actually ran, and the real outcome is dropped. A finish *counter*
    cannot see this — which is why the spec tracks who recorded what.
  - `KatipoAdmit_span_fixed.cfg` — **passes**: the design as shipped —
    idempotent claim, the caller finishes nothing on an
    `admission_timeout`, and the worker ends the span when it refuses an
    expired admission. Exactly once, never fabricated, real outcome kept,
    no leak. Regression-tested in `test/katipo_SUITE.erl`
    (`otel_async_finish_exactly_once`).
  - `KatipoAdmit_span_leak.cfg` — **fails** `NoSpanLeak`: proves the
    worker's end-on-refusal is load-bearing, not decoration.
  - `KatipoAdmit_witness_ok.cfg` — expect **violation**: the happy path
    (caller receives the ref) is reachable, i.e. the model is not vacuous.
- `KatipoAwait.tla` — `katipo:await/2`'s timeout branch. Tiny by design.
  - `KatipoAwait.cfg` — **fails**: the after-0 flush can miss a delivery
    that lands before `await` returns (the "flush a late one" contract).
  - `KatipoAwait_slot_pinned.cfg` — **fails**: with the request timer far
    past the await bound, an `await_timeout` leaves the `max_in_flight`
    slot pinned; `KatipoAwait_cancel_slot.cfg` passes with a candidate
    cancel-on-timeout, and `KatipoAwait_cancel_stray.cfg` **fails**: the
    cancel does not close the stray-message window (best-effort).
  - `KatipoAwait_witness_ok.cfg` — expect **violation**: happy path.
- `KatipoSpill.tla` — pool routing under `max_in_flight`
  (`pool_call`/`attempt`/`spillover`), with time counted in admission
  budgets. Three separate questions, one behaviour knob each.
  - `KatipoSpill.cfg` — **passes**: the routing as shipped. A request
    reaches at most one port, the exhaustion error is honest, admission is
    bounded by a single `?ADMISSION_TIMEOUT`, and a free worker is never
    passed over. Regression-tested in `test/katipo_async_failure_SUITE.erl`
    (`admission_spills_over_restarting_worker`).
  - `KatipoSpill_reoffer.cfg` — **fails** `NoDoubleSend`: this is why
    `attempt/3` separates `noproc` (the name resolved to nothing, so
    nothing was sent — re-offer freely) from `worker_died` (the worker was
    alive and may already have run `send_to_port`, so the admission stops).
    Treating both as "keep going" issues a non-idempotent request twice.
  - `KatipoSpill_label_firstpick.cfg` — **fails** `LabelHonest`: taking the
    exhaustion error from whatever the first random pick happened to be
    reports a saturated pool as `worker_died`, so a caller that backs off
    on `overload` but alarms on `worker_died` misroutes roughly one
    rejection in `pool_size`.
  - `KatipoSpill_latency_perhop.cfg` — **fails** `WaitsBounded`: a fresh
    deadline per candidate makes the worst case `pool_size ×
    ?ADMISSION_TIMEOUT` (witnessed by `_witness_allwaits.cfg`). Sharing one
    stamped deadline across the walk is what makes the documented 5s
    admission bound true.
  - `KatipoSpill_budget_starves_walk.cfg` — expect **violation**, and it is
    the price of that fix: with one shared deadline, a first pick that
    answers `{overload, _}` just inside the bound spends the whole budget,
    so free workers go untried and the caller gets `admission_timeout`.
    Honouring the bound the caller asked for is the right side of the
    trade, but it is a real behaviour change and is recorded here rather
    than left to be discovered.
- `KatipoConn.tla` — ownership of one streaming transfer inside the C
  event loop: completion, cancel (also the worker's timer) and flow
  resume racing over the conn and curl's pause buffer.
  - `KatipoConn.cfg` — passes: no double free, use-after-free, chunk after
    free, or orphaned pause buffer.
  - `KatipoConn_sabotage_lookup.cfg` / `_sabotage_touch.cfg` — expect
    **violations**: drop `find_conn`, or read `conn` after the
    `curl_easy_pause`/`check_multi_info` kick in `flow_conn`, and the
    invariants trip. Proves both disciplines are load-bearing.
  - `KatipoConn_witness_pausedcancel.cfg` — expect **violation**.
- `KatipoFlow.tla` — inside the C port's `flow_conn`: the synchronous
  re-entrancy of `write_cb` under `curl_easy_pause(CURLPAUSE_CONT)`.
  Proves the "credits first" ordering in `c_src/katipo.c` is load-bearing:
  - `KatipoFlow.cfg` — passes: with the real order, exact credits complete
    the transfer.
  - `KatipoFlow_swapped.cfg` — **fails**: resume-before-credits loses the
    wakeup; each pause eats a credit and an exact-credit consumer stalls
    (surfacing as spurious `operation_timedout` on windowed streams).
  - `KatipoFlow_swapped_surplus.cfg` — passes: one surplus grant recovers,
    showing the defect is a credit leak, not a hard deadlock.
  - `KatipoFlow_witness_pause.cfg` — expect **violation**: the pause path
    is exercised.

## Running

Requires Java and [tla2tools.jar](https://github.com/tlaplus/tlaplus/releases):

```sh
java -cp tla2tools.jar tlc2.TLC -deadlock -config KatipoFixed.cfg KatipoFixed.tla
```

The newer specs (`KatipoReq`, `KatipoAdmit`, `KatipoFlow`, `KatipoAwait`,
`KatipoSpill`, `KatipoConn`) are PlusCal with
their own `CHECK_DEADLOCK FALSE` in each config, so no `-deadlock` flag:

```sh
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC \
  -config KatipoReq_safety1.cfg -workers 4 KatipoReq.tla
```

After editing a PlusCal block, re-translate before checking (everything
below `END TRANSLATION` survives):

```sh
java -cp tla2tools.jar pcal.trans KatipoReq.tla
```

When code changes, the spec that must be updated and re-checked is:

- worker dispatch/delivery logic (`katipo_worker.erl`, `katipo.erl`
  pool_call/deliver paths) → `KatipoFixed.tla` and `KatipoReq.tla`
- the admission path (`katipo.erl` stamp/attempt/spillover,
  `katipo_worker.erl` admit_call) → `KatipoAdmit.tla`, `KatipoSpill.tla`
- `katipo.erl` await/2 → `KatipoAwait.tla`
- `c_src/katipo.c` free_conn / cancel_conn / flow_conn ownership →
  `KatipoConn.tla`
- `c_src/katipo.c` flow_conn / write_cb streaming and pause logic →
  `KatipoFlow.tla`
