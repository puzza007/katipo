katipo
=====

An HTTP library for Erlang built around libcurl-multi and libevent.

### Status

Beta

[![Build Status][travis_ci_image]][travis_ci]
[![Hex pm](http://img.shields.io/hexpm/v/katipo.svg?style=flat)](https://hex.pm/packages/katipo)
[![Coverage Status](https://coveralls.io/repos/github/puzza007/katipo/badge.svg?branch=master)](https://coveralls.io/github/puzza007/katipo?branch=master)

### Usage

```erlang
{ok, _} = application:ensure_all_started(katipo).
Pool = api_server,
{ok, _} = katipo_pool:start(api_server, 2, [{pipelining, true}]).
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
{ok, _} = katipo_pool:start(api_server, 2, [{pipelining, true}]).
ReqHeaders = [{<<"User-Agent">>, <<"katipo">>}].
Req = #{url => <<"https://example.com">>.
        method => post,
        headers => ReqHeaders,
        body => <<"0d5cb3c25b0c5678d5297efa448e1938">>,
        connecttimeout_ms => 5000,
        proxy => <<"http://127.0.0.1:9000">>,
        sslverifyhost => false,
        sslverifypeer => false},
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

#### Application Config
| Option | Values | Default | Notes |
|:-------|:-------|:--------|:------|
| `mod_metrics` | `folsom | exometer | dummy` | `dummy` | see [erlang-metrics](https://github.com/benoitc/erlang-metrics) |

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
| `cacert`            | `binary()`                      | `undefined`       |
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

#### Pool Options

| Option                | Type                 | Default           | Note                                   |
|:----------------------|:---------------------|:----------------- |----------------------------------------|
| `pipelining`          | `boolean()`          | `false`           | HTTP pipelining                        |
| `max_pipeline_length` | `non_neg_integer()`  | 100               |                                        |

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
