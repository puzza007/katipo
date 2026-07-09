-module(katipo).
-moduledoc """
An HTTP/HTTP2/HTTP3 client library for Erlang built around libcurl-multi and libevent.

## Quick Start

```erlang
{ok, _} = application:ensure_all_started(katipo).
{ok, _} = katipo_pool:start(my_pool, 2, [{pipelining, multiplex}]).
{ok, #{status := 200, body := Body}} = katipo:get(my_pool, <<"https://example.com">>).
```

## Request Options

Options can be passed as the third argument to HTTP method functions, or included
directly in the request map passed to `req/2`.

See `t:opts/0` for all available options and `t:request/0` for the full request map type.

## Responses

Synchronous request functions return `t:response/0`:

```erlang
{ok, #{status := pos_integer(), headers := headers(), cookiejar := cookiejar(), body := body()}}
{error, #{code := error_code(), message := error_msg()}}
```

## Async Requests

Async functions (`async_get/2,3`, `async_req/2`, etc.) return `{ok, Ref}` immediately
and deliver the response as a message to the calling process (or the pid specified
by the `reply_to` option):

```erlang
{katipo_response, Ref, #{status := pos_integer(), headers := headers(), ...}}
{katipo_error, Ref, #{code := error_code(), message := error_msg()}}
```

Use `await/1,2` to block until the response arrives, or `cancel/2` to abort an
in-flight request (no response is then delivered).

If the pool worker handling an in-flight async request dies (e.g. its port
crashes), a `{katipo_error, Ref, #{code => worker_died}}` message is delivered
so the caller fails fast instead of blocking until the request timeout.

Async requests emit the same OTel span (`HTTP <METHOD>`, parented to the
caller's context) and metrics as their synchronous counterparts; the span
covers the full request and is finished when the response, a timeout, or a
worker failure arrives.
""".

-compile({no_auto_import, [put/2]}).

-export([req/2]).
-export([get/2]).
-export([get/3]).
-export([post/2]).
-export([post/3]).
-export([put/2]).
-export([put/3]).
-export([head/2]).
-export([head/3]).
-export([options/2]).
-export([options/3]).
-export([patch/2]).
-export([patch/3]).
-export([delete/2]).
-export([delete/3]).

-export([async_req/2]).
-export([async_get/2]).
-export([async_get/3]).
-export([async_post/2]).
-export([async_post/3]).
-export([async_put/2]).
-export([async_put/3]).
-export([async_head/2]).
-export([async_head/3]).
-export([async_options/2]).
-export([async_options/3]).
-export([async_patch/2]).
-export([async_patch/3]).
-export([async_delete/2]).
-export([async_delete/3]).
-export([await/1]).
-export([await/2]).
-export([cancel/2]).

-export([check_opts/1]).

-export([tcp_fastopen_available/0]).
-export([unix_socket_path_available/0]).
-export([doh_url_available/0]).
-export([sslkey_blob_available/0]).
-export([http3_available/0]).

-include("katipo_internal.hrl").

-include("katipo_types.hrl").

-doc "Returns whether TCP Fast Open is available (curl >= 7.49.0).".
tcp_fastopen_available() ->
    ?TCP_FASTOPEN_AVAILABLE.

-doc "Returns whether Unix socket paths are available (curl >= 7.40.0).".
unix_socket_path_available() ->
    ?UNIX_SOCKET_PATH_AVAILABLE.

-doc "Returns whether DNS-over-HTTPS is available (curl >= 7.62.0).".
doh_url_available() ->
    ?DOH_URL_AVAILABLE.

-doc "Returns whether SSL key blob is available (curl >= 7.71.0).".
sslkey_blob_available() ->
    ?SSLKEY_BLOB_AVAILABLE.

-doc "Returns whether HTTP/3 is available (curl >= 7.66.0).".
http3_available() ->
    ?HTTP3_AVAILABLE.

-doc #{equiv => get/3}.
-spec get(katipo_pool:name(), url()) -> response().
get(PoolName, Url) ->
    req(PoolName, #{url => Url, method => get}).

-doc "Performs an HTTP GET request.".
-spec get(katipo_pool:name(), url(), opts()) -> response().
get(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => get}).

-doc #{equiv => post/3}.
-spec post(katipo_pool:name(), url()) -> response().
post(PoolName, Url) ->
    req(PoolName, #{url => Url, method => post}).

-doc "Performs an HTTP POST request.".
-spec post(katipo_pool:name(), url(), opts()) -> response().
post(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => post}).

-doc #{equiv => put/3}.
-spec put(katipo_pool:name(), url()) -> response().
put(PoolName, Url) ->
    req(PoolName, #{url => Url, method => put}).

-doc "Performs an HTTP PUT request.".
-spec put(katipo_pool:name(), url(), opts()) -> response().
put(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => put}).

-doc #{equiv => head/3}.
-spec head(katipo_pool:name(), url()) -> response().
head(PoolName, Url) ->
    req(PoolName, #{url => Url, method => head}).

-doc "Performs an HTTP HEAD request.".
-spec head(katipo_pool:name(), url(), opts()) -> response().
head(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => head}).

-doc #{equiv => options/3}.
-spec options(katipo_pool:name(), url()) -> response().
options(PoolName, Url) ->
    req(PoolName, #{url => Url, method => options}).

-doc "Performs an HTTP OPTIONS request.".
-spec options(katipo_pool:name(), url(), opts()) -> response().
options(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => options}).

-doc #{equiv => patch/3}.
-spec patch(katipo_pool:name(), url()) -> response().
patch(PoolName, Url) ->
    req(PoolName, #{url => Url, method => patch}).

-doc "Performs an HTTP PATCH request.".
-spec patch(katipo_pool:name(), url(), opts()) -> response().
patch(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => patch}).

-doc #{equiv => delete/3}.
-spec delete(katipo_pool:name(), url()) -> response().
delete(PoolName, Url) ->
    req(PoolName, #{url => Url, method => delete}).

-doc "Performs an HTTP DELETE request.".
-spec delete(katipo_pool:name(), url(), opts()) -> response().
delete(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => delete}).

-doc #{equiv => async_get/3}.
-spec async_get(katipo_pool:name(), url()) -> async_response().
async_get(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => get}).

-doc """
Performs an async HTTP GET request. Returns `{ok, Ref}` immediately. The
response is delivered as a `{katipo_response, Ref, Response}` message.
""".
-spec async_get(katipo_pool:name(), url(), opts()) -> async_response().
async_get(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => get}).

-doc #{equiv => async_post/3}.
-spec async_post(katipo_pool:name(), url()) -> async_response().
async_post(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => post}).

-doc "Performs an async HTTP POST request. Returns `{ok, Ref}` immediately.".
-spec async_post(katipo_pool:name(), url(), opts()) -> async_response().
async_post(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => post}).

-doc #{equiv => async_put/3}.
-spec async_put(katipo_pool:name(), url()) -> async_response().
async_put(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => put}).

-doc "Performs an async HTTP PUT request. Returns `{ok, Ref}` immediately.".
-spec async_put(katipo_pool:name(), url(), opts()) -> async_response().
async_put(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => put}).

-doc #{equiv => async_head/3}.
-spec async_head(katipo_pool:name(), url()) -> async_response().
async_head(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => head}).

-doc "Performs an async HTTP HEAD request. Returns `{ok, Ref}` immediately.".
-spec async_head(katipo_pool:name(), url(), opts()) -> async_response().
async_head(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => head}).

-doc #{equiv => async_options/3}.
-spec async_options(katipo_pool:name(), url()) -> async_response().
async_options(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => options}).

-doc "Performs an async HTTP OPTIONS request. Returns `{ok, Ref}` immediately.".
-spec async_options(katipo_pool:name(), url(), opts()) -> async_response().
async_options(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => options}).

-doc #{equiv => async_patch/3}.
-spec async_patch(katipo_pool:name(), url()) -> async_response().
async_patch(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => patch}).

-doc "Performs an async HTTP PATCH request. Returns `{ok, Ref}` immediately.".
-spec async_patch(katipo_pool:name(), url(), opts()) -> async_response().
async_patch(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => patch}).

-doc #{equiv => async_delete/3}.
-spec async_delete(katipo_pool:name(), url()) -> async_response().
async_delete(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => delete}).

-doc "Performs an async HTTP DELETE request. Returns `{ok, Ref}` immediately.".
-spec async_delete(katipo_pool:name(), url(), opts()) -> async_response().
async_delete(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => delete}).

-doc "Performs an HTTP request using the full request map.".
-spec req(katipo_pool:name(), request()) -> response().
req(PoolName, Opts)
  when is_map(Opts) ->
    case katipo_req:build_req(Opts) of
        {ok, Req} ->
            do_req_with_span(PoolName, Req);
        {error, _} = Error ->
            Error
    end.

-doc """
Performs an async HTTP request using the full request map.

Returns `{ok, Ref}` immediately. The response is delivered as a
`{katipo_response, Ref, ResponseMap}` or `{katipo_error, Ref, ErrorMap}`
message to the process specified by the `reply_to` option (defaults to `self()`).

Use `await/1,2` to block until the response arrives.
""".
-spec async_req(katipo_pool:name(), request()) -> async_response().
async_req(PoolName, Opts)
  when is_map(Opts) ->
    {ReplyTo, Opts2} =
        case maps:take(reply_to, Opts) of
            {RT, Rest} -> {RT, Rest};
            error -> {self(), Opts}
        end,
    case is_pid(ReplyTo) of
        false ->
            {error, katipo_req:error_map(bad_opts, <<"[{reply_to,invalid}]">>)};
        true ->
            case katipo_req:build_req(Opts2) of
                {ok, Req} ->
                    UserRef = make_ref(),
                    Obs = katipo_span:start_async(katipo_req:method_int_to_binary(Req#req.method),
                                                  Req#req.url),
                    wpool:cast(PoolName, {async_req, ReplyTo, UserRef, Req, Obs},
                               random_worker),
                    {ok, UserRef};
                {error, _} = Error ->
                    Error
            end
    end.

-doc #{equiv => await/2}.
-spec await(reference()) -> response().
await(Ref) ->
    await(Ref, ?DEFAULT_REQ_TIMEOUT).

-doc "Blocks until an async response for `Ref` arrives or the timeout expires.".
-spec await(reference(), timeout()) -> response().
await(Ref, Timeout) ->
    receive
        {katipo_response, Ref, Response} ->
            {ok, Response};
        {katipo_error, Ref, Error} ->
            {error, Error}
    after Timeout ->
        %% Flush any late-arriving response for this Ref
        receive
            {katipo_response, Ref, _} -> ok;
            {katipo_error, Ref, _} -> ok
        after 0 ->
            ok
        end,
        {error, #{code => await_timeout, message => <<>>}}
    end.

-doc """
Cancels the async request identified by `Ref` (returned by `async_get/2,3`,
`async_req/2`, etc.).

Best-effort: once the cancel takes effect no `{katipo_response, Ref, _}` or
`{katipo_error, Ref, _}` message is delivered. A message that was already
delivered before the cancel raced in may still be in the receiver's mailbox, so
callers should be prepared to flush a late one. Cancelling an unknown or
already-completed `Ref` is a harmless no-op.

Note: the in-flight HTTP transfer is not aborted — it completes in the
background and its result is discarded.
""".
-spec cancel(katipo_pool:name(), reference()) -> ok.
cancel(PoolName, Ref) ->
    wpool:broadcast(PoolName, {cancel, Ref}),
    ok.

-doc false.
do_req_with_span(PoolName, Req) ->
    #req{method = MethodInt, url = Url} = Req,
    Method = katipo_req:method_int_to_binary(MethodInt),
    katipo_span:with_client_span(Method, Url, fun(SpanCtx) ->
        Ts = os:timestamp(),
        {Result, Response, Metrics} = call_worker(PoolName, Req),
        katipo_span:record_outcome(SpanCtx, Method, Ts, Result, Response, Metrics),
        {Result, Response}
    end).

%% Invoke the pool worker for a sync request. If the worker dies mid-request
%% (typically its C port died) the in-flight gen_server:call exits with the
%% shape {Reason, {gen_server, call, _}}; convert only that into the same
%% {error, worker_died} contract the async path delivers, so req/2 honours its
%% response() spec instead of crashing the caller. Config errors such as
%% wpool's bare `no_workers` (unknown/unstarted pool) are left to propagate --
%% mislabeling them worker_died would hide a naming/startup bug behind a
%% transient-looking error.
call_worker(PoolName, Req) ->
    try wpool:call(PoolName, Req, random_worker, infinity) of
        {Result, {Response, Metrics}} -> {Result, Response, Metrics}
    catch
        exit:{_Reason, {gen_server, call, _}} ->
            {error, #{code => worker_died, message => <<>>}, []}
    end.

-doc "Validates request options without performing the request.".
-spec check_opts(request()) -> ok | {error, map()}.
check_opts(Opts) when is_map(Opts) ->
    katipo_req:check_opts(Opts).
