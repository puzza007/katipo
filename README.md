# katipo

[![build status](https://github.com/puzza007/katipo/actions/workflows/ci.yml/badge.svg)](https://github.com/puzza007/katipo/actions/workflows/ci.yml)
[![Hex pm](https://img.shields.io/hexpm/v/katipo.svg?style=flat)](https://hex.pm/packages/katipo)
[![Hex Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/katipo)

An HTTP/1.1, HTTP/2 and HTTP/3 client for Erlang, built on libcurl's multi
interface and libevent: libcurl's protocol support, many concurrent
connections per worker.

## Install

```erlang
{deps, [{katipo, "2.1.0"}]}.
```

Building needs a C compiler, `make`, and the libcurl and libevent (2.1.1 or
later) headers:

```sh
apt-get install gcc make libcurl4-openssl-dev libevent-dev   # Debian/Ubuntu
brew install curl libevent pkg-config                        # macOS
```

On macOS the build prefers Homebrew's curl, which has HTTP/3.

## Quick start

```erlang
{ok, _} = application:ensure_all_started(katipo),
{ok, _} = katipo_pool:start(api, 2, [{pipelining, multiplex}]),

{ok, #{status := 200, body := Body}} = katipo:get(api, <<"https://example.com">>),

{ok, #{status := 200}} =
    katipo:post(api, <<"https://httpbin.org/post">>,
                #{headers => [{<<"content-type">>, <<"application/json">>}],
                  body => <<"{\"name\":\"katipo\"}">>,
                  timeout_ms => 5000}).
```

Every method has a function (`get`, `post`, `put`, `head`, `options`,
`patch`, `delete`) taking a pool, a URL and an optional options map.
`katipo:req(Pool, #{url => Url, method => post, ...})` takes the whole
request as one map.

## Responses

```erlang
{ok, #{status := pos_integer(), headers := [{binary(), binary()}],
       cookiejar := cookiejar(), body := binary()}}
{error, #{code := atom(), message := binary()}}
```

`code` is a curl error name (`couldnt_connect`, `operation_timedout`, ...)
or one of katipo's: `bad_opts`, `worker_died`, `overload`,
`admission_timeout`, `await_timeout`. A malformed response that libcurl
rejects, such as one with an invalid Content-Length, is
`ftp_weird_server_reply`: curl's `CURLE_WEIRD_SERVER_REPLY` under the name
it had before curl 7.51, kept so existing matches keep working.

## Async requests

```erlang
{ok, Ref} = katipo:async_get(api, Url),
{ok, #{status := 200}} = katipo:await(Ref, 5000).
```

The result arrives as one message, `{katipo_response, Ref, Response}` or
`{katipo_error, Ref, Error}`, sent to the caller or to the `reply_to` pid.
`await/1,2` receives it for you; `await_timeout` only ends the wait, so a
later `await` can still collect it. `cancel(Pool, Ref)` aborts the request;
a message already sent before the cancel took effect may still be in the
mailbox.

An admitted request always gets exactly one message, including
`worker_died` if its worker's C port dies. If no worker can take the
request, `async_*` returns the error itself (`worker_died`, `overload` or
`admission_timeout`) and sends nothing. The one gap: a worker killed with
`exit(Pid, kill)` sends nothing, so keep a timeout on the wait.

## Streaming

`stream => true` delivers the body as it arrives instead of buffering it.
`stream_window => N` pauses the transfer after `N` unacknowledged chunks,
which pushes back on the server, until `update_flow/3` grants more:

```erlang
download(Url) ->
    {ok, Ref} = katipo:async_get(api, Url, #{stream => true, stream_window => 8}),
    receive {katipo_headers, Ref, #{status := 200}} -> ok end,
    loop(Ref, []).

loop(Ref, Acc) ->
    receive
        {katipo_chunk, Ref, Bin} ->
            ok = katipo:update_flow(api, Ref, 1),
            loop(Ref, [Acc | Bin]);
        {katipo_done, Ref, _} -> {ok, iolist_to_binary(Acc)};
        {katipo_error, Ref, Error} -> {error, Error}
    end.
```

A `katipo_error` can arrive at any point, including mid-body. Grant at
least once every `N` chunks, or the transfer stays paused until
`timeout_ms` fires. Streaming is async-only and `await` does not apply.
With HTTP/2 or HTTP/3 multiplexing, use a recent libcurl: older versions
can stall other streams on the connection while one is paused.

### Streaming a request body

`body => {stream, #{}}` sends a body you produce as the request goes, for
proxying or for data too big to hold in memory. The C port asks for each
chunk with `{katipo_body_demand, Ref}` once curl has sent the last, and
`send_body/3` answers with the next chunk or `eof`, so at most one chunk
waits in the port:

```erlang
upload(Url, Fd) ->
    {ok, Ref} = katipo:async_put(api, Url, #{body => {stream, #{}}}),
    send(Ref, Fd).

send(Ref, Fd) ->
    receive
        {katipo_body_demand, Ref} ->
            case file:read(Fd, 65536) of
                {ok, Data} -> ok = katipo:send_body(api, Ref, Data);
                eof -> ok = katipo:send_body(api, Ref, eof)
            end,
            send(Ref, Fd);
        {katipo_response, Ref, Response} -> {ok, Response};
        {katipo_error, Ref, Error} -> {error, Error}
    end.
```

Without `length` the body goes chunked (or as HTTP/2 or 3 frames), sent
straight away rather than behind `Expect: 100-continue` unless you set that
header yourself. With `#{length => N}` it goes with that `Content-Length`:
no demand comes once `N` bytes are sent, so no `eof` is needed, and a body
longer or shorter fails the request with `read_error`. Anything sent after
`eof` is ignored. The request timer runs while the port waits for a chunk.
A streamed body cannot be sent twice, so a redirect, an auth retry
(digest, NTLM, Negotiate) or curl's retry on a reused connection the server
had closed fails with `send_fail_rewind`. For a body that is already in a
file, `body => {file, Path}` needs no messages at all. It combines with
`stream => true` for the response. Async only.

### Retries

`retry => true` sends a request again when an attempt fails with a
connection error, a timeout, or a 429 or 503, waiting a random backoff
between attempts, or as long as a `Retry-After` header asks:

```erlang
{ok, #{status := 200}} = katipo:get(api, Url, #{retry => true}).
{ok, _} = katipo:post(api, Url, #{body => Body,
                                  retry => #{methods => [post], max_retries => 5,
                                             statuses => [429, 502, 503, 504]}}).
```

By default only the idempotent methods (GET, HEAD, OPTIONS, PUT, DELETE)
are retried, up to 3 times, with waits of up to 100 ms doubled each retry
and capped at 5 s. A `Retry-After` longer than that cap returns the
response as it is. The caller sees only the last attempt; each attempt has
the whole `timeout_ms`, so give `await/2` a timeout that covers them all. A streamed body or response cannot be sent again,
so `retry` with either is `bad_opts`. See `t:katipo:retry/0` for every
setting.

## Pools

`katipo_pool:start(Name, Size, Opts)` starts `Size` workers, each owning
one curl multi handle. `katipo_pool:stop(Name)` stops them.

| Option                  | Type                          | Default      | Note                                                                                           |
|:------------------------|:------------------------------|:-------------|:-----------------------------------------------------------------------------------------------|
| `pipelining`            | `nothing` <br> `http1` <br> `multiplex` | `nothing`    | HTTP pipelining [CURLMOPT_PIPELINING](https://curl.se/libcurl/c/CURLMOPT_PIPELINING.html) |
| `max_total_connections` | `non_neg_integer()`           | 0 (no limit) | [docs](https://curl.se/libcurl/c/CURLMOPT_MAX_TOTAL_CONNECTIONS.html)                     |
| `max_concurrent_streams`| `non_neg_integer()`           | 100          | [docs](https://curl.se/libcurl/c/CURLMOPT_MAX_CONCURRENT_STREAMS.html) curl >= 7.67.0     |
| `max_in_flight`         | `pos_integer()` \| `infinity` | `infinity`   | katipo's own: per-worker cap on in-flight requests                                             |

With `max_in_flight`, a request that finds its worker full spills over to
another, and fails fast with `overload` when every worker is full.

## Request options

| Option                  | Type                                | Default     | Notes                                                                               |
|:------------------------|:------------------------------------|:------------|:------------------------------------------------------------------------------------|
| `headers`               | `[{iodata(), iodata()}]`            | `[]`        |                                                                                     |
| `cookiejar`             | opaque (returned in response)       | `[]`        |                                                                                     |
| `body`                  | `iodata()` \| `{file, Path}` \| `{stream, #{length => N}}` | `<<>>`      | sent with every method but `head` (an error there); a key/value list is form-encoded, `{file, Path}` is read from the file as it is sent, never held in memory, and `{stream, _}` is sent on demand (async only; see Streaming a request body). Without a `content-type` header, only POST and form bodies get `application/x-www-form-urlencoded` |
| `connecttimeout_ms`     | `1..2147483647`                     | 30000       | [docs](https://curl.se/libcurl/c/CURLOPT_CONNECTTIMEOUT.html)                  |
| `followlocation`        | `boolean()`                         | `false`     | [docs](https://curl.se/libcurl/c/CURLOPT_FOLLOWLOCATION.html)                  |
| `ssl_verifyhost`        | `boolean()`                         | `true`      | [docs](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)                  |
| `ssl_verifypeer`        | `boolean()`                         | `true`      | [docs](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)                  |
| `capath`                | `binary()` \| `string()`            | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_CAPATH.html)                          |
| `cacert`                | `binary()` \| `string()`            | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_CAINFO.html)                          |
| `ca_cache_timeout`      | `-1..2147483647`                    | 86400       | [docs](https://curl.se/libcurl/c/CURLOPT_CA_CACHE_TIMEOUT.html) curl >= 7.87.0 (0=disable, -1=forever) |
| `timeout_ms`            | `1..2147483647`                     | 30000       | [docs](https://curl.se/libcurl/c/CURLOPT_TIMEOUT_MS.html)                      |
| `dns_cache_timeout`     | `-1..2147483647`                    | 60          | [docs](https://curl.se/libcurl/c/CURLOPT_DNS_CACHE_TIMEOUT.html) (0=disable, -1=forever) |
| `maxredirs`             | `-1..2147483647`                    | 9           | [docs](https://curl.se/libcurl/c/CURLOPT_MAXREDIRS.html)                       |
| `proxy`                 | `binary()`                          | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_PROXY.html)                           |
| `tcp_fastopen`          | `boolean()`                         | `false`     | [docs](https://curl.se/libcurl/c/CURLOPT_TCP_FASTOPEN.html) curl >= 7.49.0     |
| `pipewait`              | `boolean()`                         | `true`      | [docs](https://curl.se/libcurl/c/CURLOPT_PIPEWAIT.html) curl >= 7.43.0         |
| `low_speed_limit`       | `1..2147483647`                     | off         | [docs](https://curl.se/libcurl/c/CURLOPT_LOW_SPEED_LIMIT.html) bytes/s; with `low_speed_time`, a slower transfer fails with `operation_timedout` |
| `low_speed_time`        | `1..2147483647`                     | off         | [docs](https://curl.se/libcurl/c/CURLOPT_LOW_SPEED_TIME.html) seconds; requires `low_speed_limit` and vice versa |
| `max_body_size`         | `0..2147483647`                     | no limit    | bytes of the final response's body, after decoding; more fails with `filesize_exceeded`, streamed or not |
| `interface`             | `binary()`                          | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_INTERFACE.html)                       |
| `unix_socket_path`      | `binary()` \| `string()`            | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_UNIX_SOCKET_PATH.html) curl >= 7.40.0 |
| `doh_url`               | `binary()`                          | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_DOH_URL.html) curl >= 7.62.0          |
| `http_version`          | `curl_http_version_none` <br> `curl_http_version_1_0` <br> `curl_http_version_1_1` <br> `curl_http_version_2_0` <br> `curl_http_version_2tls` <br> `curl_http_version_2_prior_knowledge` <br> `curl_http_version_3` | `curl_http_version_none` | [docs](https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html) HTTP/3 requires curl >= 7.66.0 |
| `sslversion`            | `sslversion_default` <br> `sslversion_tlsv1` <br> `sslversion_tlsv1_0` <br> `sslversion_tlsv1_1` <br> `sslversion_tlsv1_2` <br> `sslversion_tlsv1_3` | `sslversion_default` | [docs](https://curl.se/libcurl/c/CURLOPT_SSLVERSION.html) |
| `sslcert`               | `binary()` \| `string()`            | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_SSLCERT.html)                         |
| `sslkey`                | `binary()` \| `string()`            | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_SSLKEY.html)                          |
| `sslkey_blob`           | `binary()` (DER format)             | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_SSLKEY_BLOB.html) curl >= 7.71.0      |
| `keypasswd`             | `binary()`                          | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_KEYPASSWD.html)                       |
| `http_auth`             | `basic` <br> `digest` <br> `ntlm` <br> `negotiate` | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_HTTPAUTH.html)                        |
| `stream`                | `boolean()`                         | `false`     | async only (sync takes only `false`); deliver the body incrementally (see Streaming responses) |
| `stream_window`         | `1..2147483647` \| `infinity`       | `infinity`  | async only (sync takes only `infinity`); chunk credits before the transfer pauses awaiting `update_flow/3` |
| `username`              | `binary()`                          | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_USERNAME.html)                        |
| `password`              | `binary()`                          | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_PASSWORD.html)                        |
| `userpwd`               | `binary()`                          | `undefined` | [docs](https://curl.se/libcurl/c/CURLOPT_USERPWD.html)                         |
| `verbose`               | `boolean()`                         | `false`     | [docs](https://curl.se/libcurl/c/CURLOPT_VERBOSE.html)                         |
| `reply_to`              | `pid()`                             | `self()`    | async only (sync takes only the caller); process that receives the response message |
| `retry`                 | `boolean()` \| map (see Retries)    | `false`     | send the request again after a failed attempt, with backoff                          |

Some options depend on how libcurl was built. Check at runtime with
`katipo:http3_available/0`, `doh_url_available/0`,
`tcp_fastopen_available/0`, `unix_socket_path_available/0` and
`sslkey_blob_available/0`.

## Observability

katipo emits OpenTelemetry spans and metrics. Without an SDK they are
no-ops. Each request gets a span:

| Attribute | Description |
|:----------|:------------|
| `http.request.method` | HTTP method (GET, POST, etc.) |
| `url.full` | Request URL (query string, fragment and userinfo are stripped for security) |
| `server.address` | Target host |
| `http.response.status_code` | Response status code (on success) |

Metrics (histograms are in milliseconds and carry `http.request.method`):

| Metric | Type | Description |
|:-------|:-----|:------------|
| `http.client.requests` | Counter | Number of HTTP requests (with `result` and `http.response.status_code` attributes) |
| `http.client.duration` | Histogram | Total request duration (ms) |
| `http.client.curl_time` | Histogram | Curl total time (ms) |
| `http.client.namelookup_time` | Histogram | DNS lookup time (ms) |
| `http.client.connect_time` | Histogram | Connection time (ms) |
| `http.client.appconnect_time` | Histogram | SSL/TLS handshake time (ms) |
| `http.client.pretransfer_time` | Histogram | Pre-transfer time (ms) |
| `http.client.redirect_time` | Histogram | Redirect processing time (ms) |
| `http.client.starttransfer_time` | Histogram | Time to first byte (ms) |

To export them, add the SDK and an exporter:

```erlang
%% In rebar.config
{deps, [
    {opentelemetry, "1.5.0"},
    {opentelemetry_experimental, "0.5.1"},
    {opentelemetry_exporter, "1.8.0"}
]}.
```

Configure the exporter in your `sys.config`:

```erlang
[
 {opentelemetry, [
   {span_processor, batch},
   {traces_exporter, otlp}
 ]},
 {opentelemetry_experimental, [
   {readers, [
     #{module => otel_metric_reader,
       config => #{exporter => {opentelemetry_exporter, #{}}}}
   ]}
 ]},
 {opentelemetry_exporter, [
   {otlp_endpoint, "http://localhost:4318"}
 ]}
].
```

## Upgrading from 1.x

Metrics moved to OpenTelemetry: `mod_metrics`, the `return_metrics` option
and the `metrics` field in responses are gone, and the histograms above
carry the same timings. Everything else is additive; see the
[CHANGELOG](CHANGELOG.md).

## Development

The tests run against httpbin behind Caddy (HTTPS, HTTP/2 and HTTP/3 on
port 8443):

```sh
(cd test/http3-httpbin && docker compose up -d --build)
curl -k https://localhost:8443/get   # wait for a 200; a 502 means httpbin is down
rebar3 ct
```

The async admission and streaming flow-control protocols are modelled in
TLA+ and proved in Lean under [`formal/`](https://github.com/puzza007/katipo/tree/master/formal), and
`formal/trace.sh` checks the test runs against the Lean model.
