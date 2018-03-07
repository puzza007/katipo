katipo
=====

An HTTP client library for Erlang built around libcurl-multi and libevent.

### Status

Beta

[![Build Status][travis_ci_image]][travis_ci]
[![Hex pm](http://img.shields.io/hexpm/v/katipo.svg?style=flat)](https://hex.pm/packages/katipo)
[![Coverage Status](https://coveralls.io/repos/github/puzza007/katipo/badge.svg?branch=master)](https://coveralls.io/github/puzza007/katipo?branch=master)

### Usage

```erlang
{ok, _} = application:ensure_all_started(katipo).
Pool = api_server,
{ok, _} = katipo_pool:start(Pool, 2, [{pipelining, true}]).
Url = <<"https://example.com">>.
ReqHeaders = [{<<"User-Agent">>, <<"katipo">>}].
Opts = #{headers => ReqHeaders,
         body => <<"0d5cb3c25b0c5678d5297efa448e1938">>,
         connecttimeout_ms => 5000,
         proxy => <<"http://127.0.0.1:9000">>,
         sslverifyhost => false,
         sslverifypeer => false},
{ok, #{status := 200,
       headers := RespHeaders,
       cookiejar := CookieJar,
       body := RespBody}} = katipo:post(Pool, Url, Opts).
```

Or passing the entire request as a map

```erlang
{ok, _} = application:ensure_all_started(katipo).
Pool = api_server,
{ok, _} = katipo_pool:start(Pool, 2, [{pipelining, true}]).
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

Session interface. Cookies handled automatically and options merged. Inspired by [Requests sessions](http://docs.python-requests.org/en/latest/user/advanced/#session-objects).

```erlang
{ok, _} = application:ensure_all_started(katipo).
Pool = api_server,
{ok, _} = katipo_pool:start(Pool, 2, [{pipelining, true}]).
ReqHeaders = [{<<"User-Agent">>, <<"katipo">>}].
Opts = #{url => <<"https://example.com">>.
         method => post,
         headers => ReqHeaders,
         connecttimeout_ms => 5000,
         proxy => <<"http://127.0.0.1:9000">>,
         sslverifyhost => false,
         sslverifypeer => false}.
{ok, Session} = katipo_session:new(Pool, Opts).
{{ok, #{status := 200}}, Session2} =
    katipo_session:req(#{body => <<"some data">>}, Session).
{{ok, #{status := 200}}, Session3} =
    katipo_session:req(#{body => <<"different payload data">>}, Session2).
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

#### Application Config
| Option | Values | Default | Notes |
|:-------|:-------|:--------|:------|
| `mod_metrics` | <code>folsom &#124; exometer &#124; noop</code> | `noop` | see [erlang-metrics](https://github.com/benoitc/erlang-metrics) |

#### Request options

| Option              | Type                          | Default     | Notes                                                                           |
|:--------------------|:------------------------------|:------------|:--------------------------------------------------------------------------------|
| `headers`           | `[{binary(), iodata()}]`      | `[]`        |                                                                                 |
| `cookiejar`         | opaque (returned in response) | `[]`        |                                                                                 |
| `body`              | `iodata()`                    | `<<>>`      |                                                                                 |
| `connecttimeout_ms` | `pos_integer()`               | 30000       | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_CONNECTTIMEOUT.html)              |
| `followlocation`    | `boolean()`                   | `false`     | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_FOLLOWLOCATION.html)              |
| `ssl_verifyhost`    | `boolean()`                   | `true`      | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)              |
| `ssl_verifypeer`    | `boolean()`                   | `true`      | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)              |
| `capath`            | `binary()`                    | `undefined` |                                                                                 |
| `cacert`            | `binary()`                    | `undefined` |                                                                                 |
| `timeout_ms`        | `pos_integer()`               | 30000       |                                                                                 |
| `maxredirs`         | `non_neg_integer()`           | 9           |                                                                                 |
| `proxy`             | `binary()`                    | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_PROXY.html)                       |
| `return_metrics`    | `boolean()`                   | `false`     |                                                                                 |
| `tcp_fastopen`      | `boolean()`                   | `false`     | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_TCP_FASTOPEN.html) curl >= 7.49.0 |
| `interface`         | `binary()`                    | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_INTERFACE.html)                   |
| `unix_socket_path`  | `binary()`                    | `undefined` | [docs](https://curl.haxx.se/libcurl/c/CURLOPT_UNIX_SOCKET_PATH.html)            |

#### Responses

```erlang
{ok, #{status := pos_integer(),
       headers := headers(),
       cookiejar := cookiejar(),
       body := body(),
       metrics => proplist()}}

{error, #{code := atom(), message := binary()}}
```

#### Pool Options

| Option                  | Type                | Default      | Note                                                                       |
|:------------------------|:--------------------|:-------------|:---------------------------------------------------------------------------|
| `pipelining`            | `boolean()`         | `false`      | HTTP pipelining                                                            |
| `max_pipeline_length`   | `non_neg_integer()` | 100          |                                                                            |
| `max_total_connections` | `non_neg_integer()` | 0 (no limit) | [docs](https://curl.haxx.se/libcurl/c/CURLMOPT_MAX_TOTAL_CONNECTIONS.html) |

#### Metrics

* ok
* error
* status.XXX
* total_time
* curl_time
* namelookup_time
* connect_time
* appconnect_time
* pretransfer_time
* redirect_time
* starttransfer_time

### Dependencies

#### Ubuntu Trusty

```sh
sudo apt-get install git libwxgtk2.8-0 libwxbase2.8-0 libevent-dev libcurl4-openssl-dev libcurl4-openssl-dev

wget http://packages.erlang-solutions.com/site/esl/esl-erlang/FLAVOUR_1_esl/esl-erlang_18.0-1~ubuntu~trusty_amd64.deb

sudo dpkg -i esl-erlang_18.0-1~ubuntu~trusty_amd64.deb
```

#### OSX

```sh
brew install --with-c-ares --with-nghttp2 curl
brew install libevent
```

### Building

```sh
make
make test
```

[travis_ci]: https://travis-ci.org/puzza007/katipo
[travis_ci_image]: https://travis-ci.org/puzza007/katipo.png
