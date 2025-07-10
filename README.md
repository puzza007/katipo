katipo
=====

An HTTP/HTTP2 client library for Erlang built around libcurl-multi and libevent.

### Status

![build status](https://github.com/puzza007/katipo/actions/workflows/ci.yml/badge.svg)
[![Hex pm](http://img.shields.io/hexpm/v/katipo.svg?style=flat)](https://hex.pm/packages/katipo)
[![Hex Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/katipo)

### ⚠️ Breaking Changes in v2.0.0

Katipo v2.0.0 introduces breaking changes to improve observability and modernize metrics collection:

- **Removed**: Old metrics system (`mod_metrics` config, `return_metrics` option)
- **Added**: Telemetry events compatible with OpenTelemetry
- **Migration**: See [Telemetry Migration](#telemetry-migration) section below

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
Req = #{url => <<"https://example.com">>.
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
advantage of the 15+ years of development that has gone into libcurl.
To allow large numbers of simultaneous connections libevent is used
along with the libcurl-multi interface.

### Documentation

#### API

```erlang
-type method() :: get | post | put | head | options.
katipo_pool:start(Name :: atom(), size :: pos_integer(), PoolOptions :: proplist()).
katipo_pool:stop(Name :: atom()).

katipo:req(Pool :: atom(), Req :: map()).
katipo:Method(Pool :: atom(), URL :: binary()).
katipo:Method(Pool :: atom(), URL :: binary(), ReqOptions :: map()).

```

#### Telemetry Events

Katipo emits [telemetry](https://github.com/beam-telemetry/telemetry) events that can be used for metrics collection and observability:

| Event | Description | Measurements | Metadata |
|:------|:------------|:-------------|:---------|
| `[katipo, request, stop]` | Emitted when HTTP request completes | `duration`, `response_body_size`, `namelookup_time`, `connect_time`, `appconnect_time`, `pretransfer_time`, `redirect_time`, `starttransfer_time` | `method`, `url`, `status`, `scheme`, `host`, `port` |
| `[katipo, request, error]` | Emitted when HTTP request fails | `count` | `method`, `url`, `error` |

##### Measurements Description

All timing measurements are in **milliseconds**:

- `duration` - Total request duration (includes Erlang overhead)
- `response_body_size` - Size of response body in bytes
- `namelookup_time` - DNS lookup time
- `connect_time` - TCP connection establishment time
- `appconnect_time` - SSL/TLS handshake time (HTTPS only)
- `pretransfer_time` - Time until transfer starts
- `redirect_time` - Time spent on redirects
- `starttransfer_time` - Time until first byte received

##### Basic Usage

```erlang
%% Attach a simple handler to log request metrics
telemetry:attach(
    my_http_metrics,
    [katipo, request, stop],
    fun(EventName, Measurements, Metadata, Config) ->
        Duration = maps:get(duration, Measurements),
        Status = maps:get(status, Metadata),
        Method = maps:get(method, Metadata),
        logger:info("HTTP ~p request took ~p ms, status: ~p", [Method, Duration, Status])
    end,
    undefined
).
```

##### OpenTelemetry Integration

For OpenTelemetry integration, see `examples/telemetry_opentelemetry.erl` which shows how to:
- Convert telemetry events to OpenTelemetry metrics
- Use semantic conventions for HTTP client metrics
- Set up histograms for timing data and counters for errors

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
| `capath`                | `binary()`                          | `undefined` |                                                                                     |
| `cacert`                | `binary()`                          | `undefined` |                                                                                     |
| `timeout_ms`            | `pos_integer()`                     | 30000       |                                                                                     |
| `maxredirs`             | `non_neg_integer()`                 | 9           |                                                                                     |
| `proxy`                 | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY.html)                           |
| `tcp_fastopen`          | `boolean()`                         | `false`     | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_TCP_FASTOPEN.html) curl >= 7.49.0     |
| `interface`             | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_INTERFACE.html)                       |
| `unix_socket_path`      | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_UNIX_SOCKET_PATH.html) curl >= 7.40.0 |
| `lock_data_ssl_session` | `boolean()`                         | `false`     | [docs](https://curl.haxx.se/libcurl/c/curl_share_setopt.html) curl >= 7.23.0        |
| `doh_url`               | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_DOH_URL.html) curl >= 7.62.0          |
| `http_version`          | `curl_http_version_none` <br> `curl_http_version_1_0` <br> `curl_http_version_1_1` <br> `curl_http_version_2_0` <br> `curl_http_version_2tls` <br> `curl_http_version_2_prior_knowledge` | `curl_http_version_none` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_HTTP_VERSION.html) curl >= 7.62.0 |
| `sslcert`               | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSLCERT.html)                         |
| `sslkey`                | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEY.html)                          |
| `sslkey_blob`           | `binary()` (DER format)             | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEY_BLOB.html) curl >= 7.71.0      |
| `keypasswd`             | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_KEYPASSWD.html)                       |
| `http_auth`             | `basic` <br> `digest` <br> `ntlm` <br> `negotiate` | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_HTTPAUTH.html)                        |
| `userpwd`               | `binary()`                          | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_USERPWD.html)                         |

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


### System dependencies

* libevent-dev
* libcurl4-openssl-dev
* make
* curl
* libssl-dev
* gcc

## Testing

The official Erlang Docker [image](https://hub.docker.com/_/erlang)
has everything needed to build and test Katipo

## Telemetry Migration

### Migrating from v1.x Metrics System

If you were using the old metrics system, here's how to migrate:

#### Before (v1.x)
```erlang
%% Old configuration
{katipo, [{mod_metrics, folsom}]}

%% Old usage with return_metrics
{ok, #{status := 200, metrics := Metrics}} =
    katipo:get(Pool, URL, #{return_metrics => true}).
```

#### After (v2.x)
```erlang
%% No configuration needed, telemetry events are always emitted

%% Attach telemetry handlers for metrics collection
telemetry:attach(
    katipo_metrics,
    [katipo, request, stop],
    fun handle_request_metrics/4,
    undefined
).

%% Metrics are now delivered via telemetry events
handle_request_metrics(_Event, Measurements, Metadata, _Config) ->
    %% All the same timing data is available in Measurements
    %% Plus additional metadata about the request
    Duration = maps:get(duration, Measurements),
    Method = maps:get(method, Metadata),
    %% ... process metrics
    ok.
```

#### Key Changes

1. **Configuration**: Remove `mod_metrics` from application config
2. **Dependencies**: Replace `metrics` with `telemetry` in your `rebar.config`
3. **Request Options**: Remove `return_metrics => true` from request options
4. **Metrics Access**: Attach telemetry handlers instead of reading from response maps
5. **Event-Driven**: Metrics are now pushed via events rather than pulled from responses

#### Benefits of Migration

- **Better Performance**: No need to include metrics in every response
- **More Flexible**: Attach multiple handlers for different purposes
- **OpenTelemetry Ready**: Easy integration with modern observability tools
- **Richer Data**: Additional metadata (URL components, HTTP method, etc.)
- **Standard Approach**: Uses BEAM ecosystem standard (telemetry)

### TODO

* A more structured way to ifdef features based on curl version
