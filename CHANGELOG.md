# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.0.0-rc.2] — 2026-07-18

### Changed
- Dependency requirements are published as semver ranges (`~> 6.0` for
  `worker_pool`, `~> 1.4` for `opentelemetry_api`, `~> 0.5.1` for
  `opentelemetry_api_experimental`) instead of exact pins, so consumers can
  unify versions with the rest of their dependency tree.

### Added
- `xref` and `lint` are now enforced in CI.
- A TLA+ model of the worker/port protocol under `formal/`, with configs
  covering delivery safety, the cancel contract, and request-outcome liveness.

### Fixed
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
