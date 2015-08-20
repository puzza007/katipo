katipo
=====

[![Build Status][travis_ci_image]][travis_ci]

An HTTP library for Erlang built around libcurl-multi and libevent.

### Status

Alpha `0.1.1`

### Usage

```erlang
{ok, _} = application:ensure_all_started(katipo).
Url = <<"https://testurl.com">>.
ReqHeaders = [{<<"User-Agent">>, <<"katipo">>}].
Opts = #{headers => ReqHeaders,
         body => <<"0d5cb3c25b0c5678d5297efa448e1938">>,
         connecttimeout_ms => 5000},
{ok, #{status := 200,
       headers := RespHeaders,
       cookiejar := CookieJar,
       body := RespBody}} = katipo:post(Url, Opts).
```

### Usage (proxy example)

```erlang
{ok, _} = application:ensure_all_started(katipo).
Url = <<"https://example.com">>.
ReqHeaders = [{<<"User-Agent">>, <<"katipo">>}].
Opts = #{headers => ReqHeaders,
         connecttimeout_ms => 5000,
         proxy => <<"http://127.0.0.1:9000">>,
         sslverifyhost => false,
         sslverifypeer => false},
{ok, #{status := 200,
       headers := RespHeaders,
       cookiejar := CookieJar,
       body := RespBody}} = katipo:get(Url, Opts).
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

katipo:Method(URL :: binary()).
katipo:Method(URL :: binary(), Options :: map()).

```

#### Request options

| Option              | Type                            | Default           |
|:--------------------|:------------------------------- |:----------------- |
| `headers`           | `[{binary(), iodata()}]`        | `[]`              |
| `cookiejar`         | opaque (returned in response)   | `[]`              |
| `body`              | `iodata()`                      | `<<>>`            |
| `connecttimeout_ms` | `pos_integer()`                 | 30000             |
| `followlocation`    | `boolean()`                     | `false`           |
| `ssl_verifyhost`    | `boolean()`                     | `true`            |
| `ssl_verifypeer`    | `boolean()`                     | `true`            |
| `capath`            | `binary()`                      | `undefined`       |
| `timeout_ms`        | `pos_integer()`                 | 30000             |
| `maxredirs`         | `non_neg_integer()`             | 9                 |
| `proxy`             | `binary()`                      | `undefined`       |

#### Responses

```erlang
{ok, #{status => pos_integer(),
       headers => headers(),
       cookiejar => cookiejar(),
       body => body()}}

{error, #{code => atom(), message => binary()}}
```

#### Application config

| Option                | Type                 | Default           | Note                                   |
|:----------------------|:---------------------|:----------------- |----------------------------------------|
| `pipelining`          | `boolean()`          | `false`           | HTTP pipelining                        |
| `max_pipeline_length` | `non_neg_integer()`  | 100               |                                        |
| `pool_size`           | `pos_integer()`      | `erlang:system_info(schedulers)`     | Typically one port executable per core |
| `pool_type`           | `round_robin | hash` | `round_robin`     | Hash is potentially useful when pipelining |

#### Metrics

* ok
* error
* total_time
* curl_time
* namelookup_time
* connect_time
* appconnect_time
* pretransfer_time
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
