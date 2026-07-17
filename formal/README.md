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

## Running

Requires Java and [tla2tools.jar](https://github.com/tlaplus/tlaplus/releases):

```sh
java -cp tla2tools.jar tlc2.TLC -deadlock -config KatipoFixed.cfg KatipoFixed.tla
```

If you change the worker dispatch/delivery logic, update `KatipoFixed.tla` to
match and re-run all configs.
