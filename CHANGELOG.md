# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Exported types for what callers receive: `error()` for the error map,
  `response_map()` for a successful response, and `async_message()` for
  every message an async request can deliver, buffered or streamed.
  `check_opts/1` now takes bare options as well as a full request, and it
  and `katipo_pool:start/3` return `{error, error()}` rather than
  `{error, map()}`.

### Changed
- The synchronous API now rejects the async-only options with `bad_opts`,
  naming them: `reply_to`, which it used to ignore silently, and any
  `stream` or `stream_window`, where before only `stream => true` was
  rejected. Their types match: `opts()` and `request()` leave them out,
  and the async functions take `async_opts()` and `async_request()`, which
  add them, so dialyzer catches the mistake before it runs. A synchronous
  call that passed `reply_to`, `stream => false` or
  `stream_window => infinity` now fails; drop the option.

### Fixed
- A `capath`, `cacert`, `sslcert` or `sslkey` string that is not valid
  text (such as a lone surrogate, or bytes that are not UTF-8) crashed the
  calling process with `try_clause` instead of returning `bad_opts`.
- The `capath`, `cacert`, `sslcert` and `sslkey` types said binary,
  though katipo accepts strings too.
- An integer option larger than 2147483647 (`timeout_ms`,
  `connecttimeout_ms`, `maxredirs`, `dns_cache_timeout`,
  `ca_cache_timeout` or `stream_window`) failed with an unhelpful
  `"Couldn't read req"` from the C port, which reads only 32-bit integers.
  It now fails with `bad_opts` naming the option, and the option types
  give the bounds: `1..2147483647`, or from `-1` for `maxredirs`,
  `dns_cache_timeout` and `ca_cache_timeout`.
- `request()` required `method`, though katipo defaults it to `get`,
  so a spec relying on the default failed to type-check.
- `error_code()` lacked `unknown_error`, returned for a curl code katipo
  has no name for, and on libcurl older than 7.62 named the CA
  verification failure `ssl_cert` where katipo returns `ssl_cacert`.
- Response headers were typed with `headers()`, whose values may be any
  iodata, though a response's are always binaries. Responses now use
  `resp_headers()`, and `headers()` stays the request header type, now
  also allowing the iodata names katipo accepts.
- `metrics()` was any proplist rather than libcurl's seven timings,
  each a float.

## [2.1.0] — 2026-10-21

Three fixes can change what an existing caller sees: a body passed to
`get`, `delete` or `options` is now sent rather than dropped, a `head`
request with a body now fails with `bad_opts`, and a `put` or `patch`
body sent without a `content-type` header no longer goes out as
`application/x-www-form-urlencoded`. Each is described below.

### Changed
- Buffered response bodies and streamed chunks now follow their term in
  the port frame instead of travelling inside it, so the worker takes the
  body as a sub-binary of the frame rather than the copy `binary_to_term`
  made: decoding a 1 MB body in the worker drops from about 430 µs to
  about 20 µs, and the worker's reductions per request no longer grow
  with body size. A body that is less than half its frame is still
  copied, so a kept body references at most twice its own size; call
  `binary:copy/1` on bodies you hold for a long time if even that
  matters. The port's wire format changed, so `priv/katipo` and the
  Erlang modules must be upgraded together: restart rather than
  hot-upgrade.
- A request body sent with any method but `post` no longer gets curl's
  default `Content-Type: application/x-www-form-urlencoded` unless it is
  a form body (a key/value list). Set a `content-type` header if a `put`
  or `patch` relied on that default.

### Fixed
- A request body given with `get`, `delete` or `options` was silently
  dropped: only `post`, `put` and `patch` sent one. Every method but
  `head` now sends its body; an empty body still sends nothing, so
  bodyless requests are unchanged. Code that passed a body to these
  methods (for instance one options map shared across methods) now puts
  it on the wire, and some intermediaries, such as CloudFront and Google
  Cloud load balancers, reject a GET with a body.
- With `followlocation`, a 301, 302 or 303 made a `put`, `patch` (and now
  `get`, `delete` or `options`) request lose its body while keeping its
  method. The body is now re-sent. A `post` still becomes a bodyless GET,
  as browsers do.
- A `head` request with a non-empty body now fails with `bad_opts`
  instead of silently dropping it.
- With an older libcurl (8.5, for one), a folded header (a line starting
  with a space or tab continuing the previous one) came back as an extra
  header named after the continuation text, and a bare CR in a header
  value was returned as is. Folded values are now joined with a single
  space, and CR, LF and NUL in a value are replaced with a space, as RFC
  9110 allows; newer libcurl already unfolds, and rejects those bytes.
- Trailers sent after a chunked (or HTTP/2 or HTTP/3) response body
  were appended to a buffered response's `headers`, and to a streamed
  one's when its body was empty, which RFC 9110 forbids. They are now
  dropped in both modes, so `headers` is only the header section.

## [2.0.1] — 2026-10-19

### Changed
- Buffered responses no longer copy the body in the C port: it is
  collected in an evbuffer, whose chains move to the pipe's output buffer
  and are freed once written, instead of being grown with realloc and then
  copied twice more. Ownership is modelled in `formal/KatipoBodyHandoff.tla`, and
  `bench/run.sh` measures buffered-response throughput.
- Response headers are encoded as they arrive instead of being collected
  in a curl list (two allocations and a temporary copy per header) and
  encoded at the end, and a new status line is recognised by its prefix
  rather than with `sscanf`.
- Response header values are trimmed byte-wise instead of with
  `string:trim/3`, whose Unicode handling made up most of the Erlang-side
  cost of a response with many headers: a response with 20 extra headers
  is now about as fast as one with none.

### Fixed
- A response header value starting with a byte that is not valid UTF-8
  (Latin-1 or other obs-text) crashed the worker, failing every request on
  it; `string:trim/3` raised `badarg` on it.
- Over HTTP/2 and HTTP/3, a followed redirect (or a 1xx, auth retry or
  proxy CONNECT) returned every hop's headers, plus a `{<<"HTTP/2 302 ">>,
  <<>>}` entry for each status line, because those status lines were not
  recognised. Only the final response's headers are returned now, as over
  HTTP/1.1.
- A response with no header lines at all was mis-encoded by the C port and
  crashed the worker.
- A buffered response body that would not fit in a 32-bit frame (about
  4 GiB) now fails that request with `write_error` instead of corrupting
  the port's output and taking down every request on the worker.
- `katipo_worker` no longer warns on OTP 29 (a variable bound inside a
  tuple and used afterwards).

## [2.0.0] — 2026-10-18

The first stable 2.0 release. It includes everything in 2.0.0-rc.1 and
2.0.0-rc.2 below, plus these changes since rc.2.

### Fixed
- An async request whose admission timed out (`{error, #{code =>
  admission_timeout}}`) could still be admitted later by the slow worker:
  the transfer ran and `reply_to` received a terminal message for a `Ref`
  the caller never saw, so a retry could perform the request twice. The
  request's span was also ended twice and its metrics recorded twice. Each
  admission attempt now carries a deadline (`?ADMISSION_SLACK` ahead of the
  caller's own 5s bound) that the worker checks before and after the port
  write, refusing a late admission without registering or delivering
  anything. Found by model checking (`formal/KatipoAdmissionTimeout.cfg`).
- HTTP/1.1 response headers with no space after the colon (`name:value`)
  came back with the whole line as the name and an empty value, and
  values padded with extra spaces or tabs kept the padding. Header values
  are now split on the first `:` and trimmed of optional whitespace.
- `await/2` no longer discards a response that arrives just as its timeout
  fires. `await_timeout` now only ends the wait, so the response can be
  collected by a later `await/2`; the docs spell out that the request
  keeps running until it completes or is cancelled with `cancel/2`.

### Added
- Lean 4 proofs (`formal/lean`) of the async admission/delivery contract
  for any number of requests, crashes and restarts, and of streaming flow
  control (credit conservation, at most `stream_window` chunks buffered,
  no lost chunks, termination) for every window and body size; plus a TLA+
  model of streaming flow control (`formal/KatipoFlow.tla`) whose state
  graph is mechanically checked identical to the Lean transcription.
  Also proved: no transfer the C port runs is ever orphaned, every async
  request is eventually answered or cancelled (given only that the worker
  runs and request timers fire), and a stream whose C port dies mid-body
  still ends with exactly one `worker_died`.
- Trace validation (`formal/trace.sh`): the test suites can record what the
  caller and each worker actually did and replay every run against the
  Lean admission model; `katipo_stress_SUITE` drives a randomized async
  workload with port deaths, a worker kill and a wedged worker for it.

### Documentation
- An admitted async request gets no message at all if its worker is killed
  outright (`exit(Pid, kill)` skips the cleanup that sends `worker_died`);
  keep a timeout on the wait.

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

## Earlier releases
See the git history and tags (`1.0.x`, `1.1.0`, …) for pre-2.0 changes.
