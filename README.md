katipo
=====

An HTTP/HTTP2/HTTP3 client library for Erlang built around libcurl-multi and libevent.

### Status

![build status](https://github.com/puzza007/katipo/actions/workflows/ci.yml/badge.svg)
[![Hex pm](http://img.shields.io/hexpm/v/katipo.svg?style=flat)](https://hex.pm/packages/katipo)
[![Hex Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/katipo)

### Usage

```erlang
{ok, _} = application:ensure_all_started(katipo).
Pool = api_server,
{ok, _} = katipo_pool:start(Pool, 2, [{pipelining, multiplex}]).
Url = <<"https://example.com">>.
ReqHeaders = [{<<"User-Agent">>, <<"katipo">>}].
Opts = #{headers => ReqHeaders,
         body => <<"0d5cb3c25b0c5678d5297efa448e1938">>,
         connecttimeout_ms => 5000,
         proxy => <<"http://127.0.0.1:9000">>,
         ssl_verifyhost => false,
         ssl_verifypeer => false},
{ok, #{status := 200,
       headers := RespHeaders,
       cookiejar := CookieJar,
       body := RespBody}} = katipo:post(Pool, Url, Opts).
```

Or passing the entire request as a map

```erlang
{ok, _} = application:ensure_all_started(katipo).
Pool = api_server,
{ok, _} = katipo_pool:start(Pool, 2, [{pipelining, multiplex}]).
ReqHeaders = [{<<"User-Agent">>, <<"katipo">>}].
Req = #{url => <<"https://example.com">>,
        method => post,
        headers => ReqHeaders,
        body => <<"0d5cb3c25b0c5678d5297efa448e1938">>,
        connecttimeout_ms => 5000,
        proxy => <<"http://127.0.0.1:9000">>,
        ssl_verifyhost => false,
        ssl_verifypeer => false},
{ok, #{status := 200,
       headers := RespHeaders,
       cookiejar := CookieJar,
       body := RespBody}} = katipo:req(Pool, Req).
```

### Why

We wanted a compatible and high-performance HTTP client so took
advantage of the 25+ years of development that has gone into libcurl.
To allow large numbers of simultaneous connections libevent is used
along with the libcurl-multi interface.

### Documentation

#### API

```erlang
-type method() :: get | post | put | head | options | patch | delete.
katipo_pool:start(Name :: atom(), size :: pos_integer(), PoolOptions :: proplist()).
katipo_pool:stop(Name :: atom()).

katipo:req(Pool :: atom(), Req :: map()).
katipo:Method(Pool :: atom(), URL :: binary()).
katipo:Method(Pool :: atom(), URL :: binary(), ReqOptions :: map()).

```

#### Request options

| Option                  | Type                                | Default     | Notes                                                                               |
|:------------------------|:------------------------------------|:------------|:------------------------------------------------------------------------------------|
| `headers`               | `[{binary(), iodata()}]`            | `[]`        |                                                                                     |
| `cookiejar`             | opaque (returned in response)       | `[]`        |                                                                                     |
| `body`                  | `iodata()`                          | `<<>>`      |                                                                                     |
| `connecttimeout_ms`     | `pos_integer()`                     | 30000       | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_CONNECTTIMEOUT.html)                  |
| `followlocation`        | `boolean()`                         | `false`     | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_FOLLOWLOCATION.html)                  |
| `ssl_verifyhost`        | `boolean()`                         | `true`      | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)                  |
| `ssl_verifypeer`        | `boolean()`                         | `true`      | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)                  |
| `capath`                | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_CAPATH.html)                          |
| `cacert`                | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_CAINFO.html)                          |
| `timeout_ms`            | `pos_integer()`                     | 30000       | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_TIMEOUT_MS.html)                      |
| `dns_cache_timeout`     | `integer()`                         | 60          | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_DNS_CACHE_TIMEOUT.html) (0=disable, -1=forever) |
| `maxredirs`             | `non_neg_integer()`                 | 9           | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_MAXREDIRS.html)                       |
| `proxy`                 | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY.html)                           |
| `tcp_fastopen`          | `boolean()`                         | `false`     | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_TCP_FASTOPEN.html) curl >= 7.49.0     |
| `interface`             | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_INTERFACE.html)                       |
| `unix_socket_path`      | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_UNIX_SOCKET_PATH.html) curl >= 7.40.0 |
| `lock_data_ssl_session` | `boolean()`                         | `false`     | [docs](https://curl.haxx.se/libcurl/c/curl_share_setopt.html) curl >= 7.23.0        |
| `doh_url`               | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_DOH_URL.html) curl >= 7.62.0          |
| `http_version`          | `curl_http_version_none` <br> `curl_http_version_1_0` <br> `curl_http_version_1_1` <br> `curl_http_version_2_0` <br> `curl_http_version_2tls` <br> `curl_http_version_2_prior_knowledge` <br> `curl_http_version_3` | `curl_http_version_none` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_HTTP_VERSION.html) HTTP/3 requires curl >= 7.66.0 |
| `sslversion`            | `sslversion_default` <br> `sslversion_tlsv1` <br> `sslversion_tlsv1_0` <br> `sslversion_tlsv1_1` <br> `sslversion_tlsv1_2` <br> `sslversion_tlsv1_3` | `sslversion_default` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSLVERSION.html) |
| `sslcert`               | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSLCERT.html)                         |
| `sslkey`                | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEY.html)                          |
| `sslkey_blob`           | `binary()` (DER format)             | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEY_BLOB.html) curl >= 7.71.0      |
| `keypasswd`             | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_KEYPASSWD.html)                       |
| `http_auth`             | `basic` <br> `digest` <br> `ntlm` <br> `negotiate` | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_HTTPAUTH.html)                        |
| `username`              | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_USERNAME.html)                        |
| `password`              | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_PASSWORD.html)                        |
| `userpwd`               | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_USERPWD.html)                         |
| `verbose`               | `boolean()`                         | `false`     | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html)                         |

#### Responses

```erlang
{ok, #{status := pos_integer(),
       headers := headers(),
       cookiejar := cookiejar(),
       body := body()}}

{error, #{code := atom(), message := binary()}}
```

#### Pool Options

| Option                  | Type                          | Default      | Note                                                                                           |
|:------------------------|:------------------------------|:-------------|:-----------------------------------------------------------------------------------------------|
| `pipelining`            | `nothing` <br> `http1` <br> `multiplex` | `nothing`    | HTTP pipelining [CURLMOPT_PIPELINING](https://curl.haxx.se/libcurl/c/CURLMOPT_PIPELINING.html) |
| `max_pipeline_length`   | `non_neg_integer()`           | 100          |                                                                                                |
| `max_total_connections` | `non_neg_integer()`           | 0 (no limit) | [docs](https://curl.haxx.se/libcurl/c/CURLMOPT_MAX_TOTAL_CONNECTIONS.html)                     |
| `max_concurrent_streams`| `non_neg_integer()`           | 100          | [docs](https://curl.haxx.se/libcurl/c/CURLMOPT_MAX_CONCURRENT_STREAMS.html) curl >= 7.67.0     |

#### Observability

Katipo uses [OpenTelemetry](https://opentelemetry.io/) for tracing and metrics.

##### Tracing

Each HTTP request creates a span with the following attributes:

| Attribute | Description |
|:----------|:------------|
| `http.request.method` | HTTP method (GET, POST, etc.) |
| `url.full` | Request URL (query string, fragment and userinfo are stripped for security) |
| `server.address` | Target host |
| `http.response.status_code` | Response status code (on success) |

##### Metrics

The following metrics are recorded:

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

All histogram metrics include the `http.request.method` attribute for filtering by HTTP method.

##### Enabling OpenTelemetry Export

The OpenTelemetry API is a no-op by default. To export telemetry data add the OpenTelemetry SDK and an exporter to your release:

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

##### Migration from metrics library

If you were using the previous `metrics` library integration, note the following breaking changes:

- The `mod_metrics` application environment option has been removed
- The `return_metrics` request option has been removed
- The `metrics` field is no longer included in response maps

To access timing metrics, configure an OpenTelemetry exporter as shown above. The histogram metrics provide the same timing data (DNS lookup, connect time, TLS handshake, etc.) that was previously available via `return_metrics`.

### System dependencies

* libevent-dev
* libcurl4-openssl-dev
* make
* curl
* libssl-dev
* gcc

## Testing

The official Erlang Docker [image](https://hub.docker.com/_/erlang)
has everything needed to build and test Katipo.

### Local httpbin Setup

The test suite uses a local httpbin instance running behind Caddy (for HTTPS/HTTP2/HTTP3 support).

Start the httpbin container:

```bash
cd test/http3-httpbin
docker-compose up -d
```

This starts:
- **httpbin**: A local instance of the httpbin.org API
- **Caddy**: Reverse proxy providing HTTPS with auto-generated self-signed certificates on port 8443

Run the tests (requires httpbin to be running):

```bash
rebar3 ct
```

To run with coverage:

```bash
rebar3 ct --cover
rebar3 cover --verbose
```

Stop the containers when done:

```bash
cd test/http3-httpbin
docker-compose down
```

### Feature Availability

Some features are only available with newer versions of libcurl. You can check availability at runtime:

```erlang
katipo:tcp_fastopen_available().    %% curl >= 7.49.0
katipo:unix_socket_path_available(). %% curl >= 7.40.0
katipo:doh_url_available().          %% curl >= 7.62.0
katipo:sslkey_blob_available().      %% curl >= 7.71.0
katipo:http3_available().            %% curl >= 7.66.0
```
