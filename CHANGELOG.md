# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Six further TLA+ models under `formal/`, covering the parts of the
  protocol the earlier specs abstracted over: the full request lifecycle
  (`KatipoReq`), the admission handshake and span ownership
  (`KatipoAdmit`), pool routing under `max_in_flight` (`KatipoSpill`),
  `await/2`'s timeout branch (`KatipoAwait`), the C port's pause/resume
  re-entrancy (`KatipoFlow`) and its transfer lifetime (`KatipoConn`).
  The README maps each source file to the spec to re-check when it
  changes, and every config states the question it asks and its expected
  result.

### Fixed
- Async admission now refuses a request whose caller has already given up
  waiting (`admission_timeout`): the bounded admission call carries the
  caller's deadline, so a backed-up worker no longer runs a request nobody
  wants. Expiry is checked ahead of the `max_in_flight` test, so a full
  worker cannot launder an expired admission into a fresh spillover
  attempt. One race remains and cannot be closed worker-side — if the
  worker accepts just as the caller's bound elapses, its `{ok, Ref}` reply
  is lost and `reply_to` still receives that request's terminal message
  under a `Ref` the caller never saw. `async_req/2`'s docs describe it; be
  prepared to drop a message whose `Ref` you do not recognise.
- Admission is now bounded by one `?ADMISSION_TIMEOUT` overall. The
  deadline is stamped once and shared by every attempt, where previously
  each spillover candidate was given a fresh full bound — so a saturated
  pool of N workers could block the caller for N × 5s. One consequence is
  intended and new: if the first worker consumes the budget before
  answering, the request is refused with `admission_timeout` rather than
  spending more of the caller's time looking for room.
- A pool worker that is mid-restart when picked no longer fails the request
  with `worker_died`: nothing was sent to it, so the request is offered to
  the rest of the pool. A worker that dies with the call *in flight* still
  ends the admission — it may already have handed the request to its port,
  and re-offering could issue a non-idempotent request twice.
- The error reported when no worker takes a request now reflects the pool
  rather than whichever worker was picked first: `overload` when workers
  were alive but at capacity, `worker_died` only when none was reachable.
- The OpenTelemetry span and request metrics of an async request are
  finished exactly once, and by the party that knows the outcome. On an
  `admission_timeout` the caller no longer records anything — it cannot
  tell whether a worker took the request — so the span is closed by the
  worker holding it, with the real result if it admitted or by ending the
  span when it refuses. Previously the request could be double-counted;
  making the finish merely idempotent would have replaced that with a
  worse failure, the caller's timeout displacing the real outcome.
- A raising metrics exporter can no longer take down a worker mid-request,
  and an in-flight observation created before a hot code load is finished
  rather than crashing the worker that holds it.
- `katipo_worker` accepts the previous, unstamped admission message, so a
  partial code load does not kill a worker and fail every request it holds.
- `await/1,2` no longer discards a response that arrives while its timeout
  is firing; it returns it.

### Changed
- `await/1,2` documents that a timeout leaves the request running and
  holding its `max_in_flight` slot until its own `timeout_ms`; use
  `cancel/2` if the response is no longer wanted.

## [2.0.0-rc.2] — 2026-07-18

### Changed
- Development and CI now build and test against the current dependency
  versions within the published ranges: `worker_pool` 6.5.3 and
  `opentelemetry_api` 1.5.0 (previously locked to 6.0.1 and 1.4.0).
- `cancel/2` and `update_flow/3` now route directly to the worker holding
  the request: the returned `Ref` is a process alias, so commands are a
  single O(1) send instead of a broadcast to every pool worker (each of
  which scanned its request table). The pool argument is retained for API
  compatibility and no longer used; late or unknown-Ref commands are
  dropped by the runtime, preserving the best-effort no-op contract.
- Dependency requirements are published as semver ranges (`~> 6.0` for
  `worker_pool`, `~> 1.4` for `opentelemetry_api`, `~> 0.5.1` for
  `opentelemetry_api_experimental`) instead of exact pins, so consumers can
  unify versions with the rest of their dependency tree.

### Added
- Request-side backpressure: the `{max_in_flight, N}` pool option caps
  in-flight requests per worker, with spillover to other workers before a
  fast `{error, #{code => overload}}` when the whole pool is full.
- Handing an async request to a worker is now bounded (5s): a wedged or
  deeply backed-up worker yields `{error, #{code => admission_timeout}}`
  instead of blocking the caller indefinitely.
- Streaming responses: pass `stream => true` to any async function to
  receive `{katipo_headers, Ref, _}`, then zero or more
  `{katipo_chunk, Ref, Bin}` messages, then a terminal
  `{katipo_done, Ref, _}` instead of one buffered body.
  `cancel/2`, timeouts, and worker-death handling behave as for buffered
  async requests; synchronous functions reject the option.
- Credit-based flow control for streamed responses: `stream_window => N`
  pauses the transfer after `N` outstanding chunk messages (propagating
  backpressure to the server) until `katipo:update_flow/3` grants more
  credits. Defaults to `infinity`, the previous behavior.
- `xref` and `lint` are now enforced in CI.
- A TLA+ model of the worker/port protocol under `formal/`, with configs
  covering delivery safety, the cancel contract, and request-outcome liveness.

### Fixed
- When the Erlang-side request timer fires (the backstop behind curl's own
  timeouts), the worker now aborts the still-running transfer in the C port
  instead of letting it hold a connection and a curl-multi slot until curl
  notices on its own.
- A synchronous request whose worker port dies mid-flight now returns
  `{error, #{code => worker_died}}` instead of crashing the caller, matching the
  async contract.
- Async requests can no longer be silently lost. Dispatch is now a synchronous
  admission call rather than a fire-and-forget cast, so a request sent while
  the worker is dead or restarting -- or one that reaches a worker whose port
  just died -- returns `{error, #{code => worker_died}}` immediately instead of
  returning `{ok, Ref}` and never delivering anything. An accepted async
  request now always produces exactly one terminal message. (Found by
  model-checking; see `formal/Katipo.tla`.)
- Cancelling an async request whose worker port has just died no longer
  crashes the worker via `port_command`, which previously also delivered a
  spurious `{katipo_error, Ref, worker_died}` message to the caller who
  cancelled.
- Metric emission no longer risks crashing application startup when no
  OpenTelemetry metrics SDK is configured, and the per-request "no SDK" overhead
  dropped from up to nine caught exceptions to one.
- The C port bounds its HTTP status-line scan and checks previously-unchecked
  allocations on the request-decode path.
- The exported `request()`/`opts()` types now include `keypasswd` and allow
  `-1` for `maxredirs`; `response()` no longer advertises a `metrics` field that
  responses do not carry.

## [2.0.0-rc.1] — 2026-02-15

### Added
- Asynchronous request API: `async_req/2` and `async_Method` wrappers return
  `{ok, Ref}` and deliver `{katipo_response, Ref, _}` / `{katipo_error, Ref, _}`
  messages, with `await/1,2` and `cancel/2`. A `reply_to` option redirects the
  response message to another process.
- OpenTelemetry tracing and metrics replace the previous `metrics`-library
  integration.
- Internally split the monolithic `katipo` module into `katipo_req`,
  `katipo_worker`, and `katipo_span` (public API unchanged).

### Changed / Removed (breaking)
- The `mod_metrics` application environment option has been removed.
- The `return_metrics` request option has been removed.
- The `metrics` field is no longer included in response maps. Configure an
  OpenTelemetry exporter to collect the equivalent timing data.

## Roadmap
- Streaming responses to the caller.

## Earlier releases
See the git history and tags (`1.0.x`, `1.1.0`, …) for pre-2.0 changes.
