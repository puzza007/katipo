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
so the caller fails fast instead of blocking until the request timeout. If the
request cannot be handed to a worker at all (the worker is dead or being
restarted), the async function returns `{error, #{code => worker_died}}`
instead of `{ok, Ref}` -- an accepted request always produces exactly one
terminal message. Handing an async request to a worker is itself bounded
(5s): a wedged or deeply backed-up worker yields
`{error, #{code => admission_timeout}}` rather than blocking the caller.
(Sync requests are bounded by the request timeout instead -- their single
call carries the whole response.)

With `stream => true` the body is delivered incrementally as
`{katipo_headers, Ref, _}`, `{katipo_chunk, Ref, _}`* and a terminal
`{katipo_done, Ref, _}` instead of one buffered response; see `async_req/2`.

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
-export([update_flow/3]).

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
    case katipo_req:build_req(Opts, sync) of
        {ok, Req} ->
            do_req_with_span(PoolName, Req);
        {error, _} = Error ->
            Error
    end.

-doc """
Performs an async HTTP request using the full request map.

Returns `{ok, Ref}` once a pool worker has accepted the request. The response
is delivered as a `{katipo_response, Ref, ResponseMap}` or
`{katipo_error, Ref, ErrorMap}` message to the process specified by the
`reply_to` option (defaults to `self()`). If no worker could accept the
request, returns `{error, #{code => worker_died | overload |
admission_timeout}}` (no live worker, pool at `max_in_flight` capacity, or
a wedged worker not answering the bounded admission call). For
`worker_died` and `overload` no message is delivered. `admission_timeout`
is the one exception, described next.

Admission calls carry the caller's deadline, so a backed-up worker that
only reaches the call after the caller gave up refuses it rather than
starting a request nobody is waiting for. One narrow race remains, and it
cannot be closed from the worker's side: if the worker accepts just inside
the deadline but its `{ok, Ref}` reply loses the race to the caller's
timeout, the request does run and `reply_to` receives its one terminal
message carrying a `Ref` this caller never saw. So after an
`admission_timeout`, and as with a response arriving after `cancel/2`, be
prepared to drop a message whose `Ref` you do not recognise.

Use `await/1,2` to block until the response arrives.

With `stream => true` the response body is delivered incrementally instead of
as one buffered binary. The message flow is:

```erlang
{katipo_headers, Ref, #{status := pos_integer(), headers := headers()}}
{katipo_chunk, Ref, binary()}     %% zero or more, in order
{katipo_done, Ref, #{status := pos_integer(), cookiejar := cookiejar()}}
```

A `{katipo_error, Ref, ErrorMap}` message is terminal and can arrive at any
point, including after headers and chunks (e.g. a request timeout mid-body).
`cancel/2` works as for buffered async requests. `await/1,2` does not apply
to streamed requests; receive the messages directly. Streaming is only
available through the async API -- `req/2` and the synchronous wrappers
reject `stream => true`.

By default chunks are delivered as fast as the transfer produces them. Pass
`stream_window => N` to bound that: the transfer pauses (propagating
backpressure to the server via TCP or the HTTP/2/3 stream window) once `N`
chunk messages are outstanding, and `update_flow/3` grants more. The request
timer keeps running while a transfer is paused, so a consumer that stops
granting credits eventually receives `operation_timedout`.

Caveat shared with buffered mode: when following redirects
(`followlocation => true`), a redirect response that itself carries a body
surfaces that body through the write path -- in streaming form the
`katipo_headers` message may then describe the redirect response rather
than the final one. Real-world redirect responses rarely carry bodies.
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
            case katipo_req:build_req(Opts2, async) of
                {ok, Req} ->
                    Obs = katipo_span:start_async(katipo_req:method_int_to_binary(Req#req.method),
                                                  Req#req.url),
                    dispatch_async(PoolName, ReplyTo, Req, Obs);
                {error, _} = Error ->
                    Error
            end
    end.

%% Admission is a synchronous call, not a cast, so dispatch failures surface
%% immediately instead of losing the request: a cast to a dead or restarting
%% worker name is silently dropped, and a worker that crashes on port_command
%% before registering the request can notify nobody afterwards. pool_call
%% turns both into an immediate {error, worker_died} return. The returned
%% Ref is worker-minted (a process alias; see the worker's admission clause
%% for the full lifecycle).
dispatch_async(PoolName, ReplyTo, Req, Obs) ->
    case pool_call(PoolName, {async_req, ReplyTo, Req, Obs}) of
        {ok, UserRef} when is_reference(UserRef) ->
            {ok, UserRef};
        {error, Error = #{code := admission_timeout}} ->
            %% Do NOT finish the span here. We do not know whether a worker
            %% took this Obs: our bounded wait elapsing does not mean the
            %% message was not delivered, only that no reply came back in
            %% time. Whichever worker holds it closes it -- with the real
            %% outcome if it admitted the request, or by ending the span
            %% when it refuses the expired admission (katipo_worker's
            %% admit_call). Recording an admission_timeout outcome from
            %% here would win the race against the worker every time (we
            %% claim the instant the bound elapses, it can only claim at
            %% resolution) and would leave the span and the metrics
            %% describing a timeout for a request that actually ran and
            %% returned a status.
            {error, Error};
        {error, Error} ->
            %% overload and worker_died: no worker accepted the message, so
            %% nobody else can close this span.
            katipo_span:finish_async(Obs, error, Error, []),
            {error, Error}
    end.

-doc """
Grants `N` more chunk-message credits to the streaming request `Ref`, which
must have been started with a bounded `stream_window`. Routed like
`cancel/2` (directly to the owning worker; the pool argument is unused) and
equally best-effort: granting credits to an unknown, completed, or
unbounded-window request is a harmless no-op. Granting in batches (e.g.
half the window at a time) amortizes the per-grant messaging.
""".
-spec update_flow(katipo_pool:name(), reference(), pos_integer()) -> ok.
update_flow(_PoolName, Ref, N) when is_reference(Ref) andalso
                                    is_integer(N) andalso N > 0 ->
    Ref ! {flow, Ref, N},
    ok.

-doc #{equiv => await/2}.
-spec await(reference()) -> response().
await(Ref) ->
    await(Ref, ?DEFAULT_REQ_TIMEOUT).

-doc """
Blocks until an async response for `Ref` arrives or the timeout expires.
Only for buffered async requests: a streamed response (`stream => true`)
arrives as a message sequence, which `await` does not understand -- receive
those messages directly.

""".
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
`async_req/2`, etc.). The `Ref` routes directly to the worker holding the
request; the pool argument is retained for API compatibility and not used.

Best-effort: once the cancel takes effect no `{katipo_response, Ref, _}` or
`{katipo_error, Ref, _}` message is delivered. A message that was already
delivered before the cancel raced in may still be in the receiver's mailbox, so
callers should be prepared to flush a late one. Cancelling an unknown or
already-completed `Ref` is a harmless no-op.
""".
-spec cancel(katipo_pool:name(), reference()) -> ok.
cancel(_PoolName, Ref) when is_reference(Ref) ->
    Ref ! {cancel, Ref},
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

%% Invoke the pool worker for a sync request, unpacking the worker's reply so
%% req/2 honours its response() spec instead of crashing the caller.
call_worker(PoolName, Req) ->
    case pool_call(PoolName, Req) of
        {ok, {Result, {Response, Metrics}}} -> {Result, Response, Metrics};
        {error, Error} -> {error, Error, []}
    end.

%% The admission entry point for both request kinds: one wpool attempt,
%% then spillover across the remaining workers if the picked one is full
%% or not currently registered (restarting).
%%
%% The two ways an attempt can fail without a reply are NOT the same, and
%% the difference decides whether the request may be re-offered:
%%   noproc      - the name resolved to nothing, so handle_call never ran
%%                 and nothing reached the port. Safe to offer elsewhere.
%%   worker_died - the worker died with our call in flight. It may already
%%                 have run admit/4, which calls send_to_port BEFORE
%%                 replying, so libcurl may hold the request and may have
%%                 put bytes on the wire. Re-offering could issue a
%%                 non-idempotent request twice, so this always ends the
%%                 admission.
%% Both the first attempt and every spillover hop apply that rule.
%%
%% Config errors such as wpool's bare `no_workers` (unknown/unstarted
%% pool) are left to propagate -- mislabeling them worker_died would hide
%% a naming/startup bug behind a transient-looking error.
pool_call(PoolName, Msg) ->
    Deadline = admission_deadline(Msg),
    case attempt(fun(M, T) -> wpool:call(PoolName, M, random_worker,
                                         T) end, Msg, Deadline) of
        {overload, FullWorker} ->
            %% The randomly-picked worker is at max_in_flight; others may
            %% have room, so offer the request to each remaining worker.
            %% A live-but-full worker is proof the pool is up.
            spillover(spillover_candidates(PoolName, FullWorker), Msg,
                      Deadline, true);
        noproc ->
            %% The picked worker is mid-restart. spillover_candidates drops
            %% every unregistered name, so this is the rest of the live pool.
            %% Nothing live has been seen yet.
            spillover(spillover_candidates(PoolName, undefined), Msg,
                      Deadline, false);
        {ok, Reply} ->
            {ok, Reply};
        Err when Err =:= worker_died; Err =:= admission_timeout ->
            %% admission_timeout fails fast by design: a caller retry
            %% re-rolls onto a (likely healthy) random worker immediately,
            %% and a request the worker admits after we gave up is cleaned
            %% up by its own request timer.
            {error, katipo_req:error_map(Err, <<>>)}
    end.

%% The caller's admission deadline: ONE absolute monotonic instant for the
%% whole admission, computed here and shared by every attempt. It has to be
%% absolute rather than a per-call bound, or the guarantee dissolves --
%% giving each spillover candidate a fresh ?ADMISSION_TIMEOUT makes the
%% worst case pool_size x ?ADMISSION_TIMEOUT (a 32-worker pool whose
%% workers each answer just inside the bound blocks the caller for over two
%% minutes), which is what formal/KatipoSpill_latency_tight.cfg fails on.
%% A sync request's single call carries the whole response and is governed
%% by the worker's request timer instead, so it has no deadline.
admission_deadline({async_req, _ReplyTo, _Req, _Obs}) ->
    erlang:monotonic_time(millisecond) + ?ADMISSION_TIMEOUT;
admission_deadline(#req{}) ->
    infinity.

%% What is left of the admission budget, as a gen_server:call timeout.
remaining(infinity) ->
    infinity;
remaining(Deadline) ->
    max(0, Deadline - erlang:monotonic_time(millisecond)).

%% Stamp the caller's deadline into an async message. A bounded call can
%% sit in a backed-up worker's mailbox past the point where the caller gave
%% up with {error, admission_timeout}; without the deadline the worker
%% would admit it anyway, running a request nobody wants and later
%% delivering a terminal message to reply_to with a ref the caller never
%% received. The worker refuses expired admissions instead (see handle_call
%% in katipo_worker). Sync requests carry no deadline.
stamp({async_req, ReplyTo, Req, Obs}, Deadline) ->
    {async_req, ReplyTo, Req, Obs, Deadline};
stamp(Req = #req{}, _Deadline) ->
    Req.

%% One admission attempt, however the worker is addressed. Every attempt
%% shares the caller's single deadline: it is stamped into the message and
%% it is what remains of it that bounds this call, so the pool walk as a
%% whole can never outlast ?ADMISSION_TIMEOUT. An exhausted budget is an
%% admission_timeout without making the call at all -- a zero timeout would
%% still deliver the message, and admitting a request whose caller has
%% already gone is the thing the deadline exists to prevent.
%%
%% Only a real reply, an at-capacity rejection carrying the full worker's
%% pid, a bounded call timing out against an unresponsive worker, a name
%% that is not registered (noproc: the worker is restarting, nothing was
%% sent), or the worker dying with the call in flight can come back. The
%% timeout mapping guards on the bound: on an unbounded call a {timeout, _}
%% exit can only be a worker that died with exit reason `timeout`.
attempt(CallFun, Msg, Deadline) ->
    case remaining(Deadline) of
        0 ->
            admission_timeout;
        Timeout ->
            try CallFun(stamp(Msg, Deadline), Timeout) of
                {overload, Pid} -> {overload, Pid};
                %% The worker refused because our stamped deadline had
                %% passed when it reached the call. Receiving this reply at
                %% all means we are at the very boundary of the bounded
                %% wait, so surface the same error the wait itself was
                %% about to produce.
                admission_expired -> admission_timeout;
                Reply -> {ok, Reply}
            catch
                exit:{timeout, {gen_server, call, _}} when Timeout =/= infinity ->
                    admission_timeout;
                exit:{noproc, {gen_server, call, _}} ->
                    noproc;
                exit:{_Reason, {gen_server, call, _}} ->
                    worker_died
            end
    end.

%% The rest of the pool in random-rotation order, minus the worker that just
%% rejected (or, with `undefined`, every name that is not registered):
%% rotation spreads spillover load, the exclusion avoids a
%% guaranteed-redundant call into the busiest worker's mailbox. A pool that
%% has been stopped underneath us has no candidates rather than an
%% exception: katipo_pool:stop/1 racing an in-flight request is exactly the
%% window in which the first attempt returns noproc, and async_req/2
%% promises an error tuple there, not an exit in the caller.
spillover_candidates(PoolName, Excluded) ->
    try wpool:get_workers(PoolName) of
        Workers ->
            {Front, Back} = lists:split(rand:uniform(length(Workers)) - 1, Workers),
            [W || W <- Back ++ Front, whereis(W) =/= Excluded]
    catch
        exit:no_workers -> []
    end.

%% SawLive records whether any worker answered as alive-but-full, which is
%% what separates the two exhaustion reports: a saturated pool is
%% `overload`, and only a pool in which nothing was reachable is
%% `worker_died`. Deriving it from the walk rather than from whatever the
%% first random pick happened to be is the difference between a caller
%% backing off and a caller raising an infrastructure alarm.
spillover([], _Msg, _Deadline, SawLive) ->
    Code = case SawLive of
               true -> overload;
               false -> worker_died
           end,
    {error, katipo_req:error_map(Code, <<>>)};
spillover([Worker | Workers], Msg, Deadline, SawLive) ->
    case attempt(fun(M, T) -> wpool_process:call(Worker, M, T) end, Msg,
                 Deadline) of
        {ok, Reply} ->
            {ok, Reply};
        admission_timeout ->
            %% The caller's whole admission budget is gone -- the deadline
            %% is shared, so there is nothing left to offer anyone else.
            {error, katipo_req:error_map(admission_timeout, <<>>)};
        worker_died ->
            %% This worker may already have handed the request to its port
            %% (see pool_call). Offering it to anyone else risks running it
            %% twice, so the admission ends here.
            {error, katipo_req:error_map(worker_died, <<>>)};
        {overload, _FullWorker} ->
            %% Alive, just at max_in_flight: the pool is up.
            spillover(Workers, Msg, Deadline, true);
        noproc ->
            %% Restarting: nothing was sent, keep going.
            spillover(Workers, Msg, Deadline, SawLive)
    end.

-doc """
Validates request options without performing the request. Cross-field rules
are checked under the async API's rules (the superset): `stream => true`
passes here but is additionally rejected by `req/2` and the synchronous
wrappers.
""".
-spec check_opts(request()) -> ok | {error, map()}.
check_opts(Opts) when is_map(Opts) ->
    katipo_req:check_opts(Opts).
