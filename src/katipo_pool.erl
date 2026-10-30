-module(katipo_pool).
-moduledoc "Manages pools of katipo HTTP client workers.".

-export([start/2]).
-export([start/3]).
-export([stop/1]).

-type name() :: atom().
-export_type([name/0]).

-doc #{equiv => start/3}.
-spec start(name(), pos_integer()) -> supervisor:startchild_ret().
start(PoolName, PoolSize) ->
    start(PoolName, PoolSize, []).

-doc """
Starts a named pool of katipo workers with the given size and options: the
curl multi options plus `{max_in_flight, N | infinity}` (default
`infinity`), a per-worker cap on concurrently in-flight requests. When
every worker is at its cap, requests fail fast with
`{error, #{code => overload}}` instead of accumulating without bound.
`{defaults, Defaults}` gives every request on the pool default options
(`t:katipo:pool_defaults/0`): an option a request gives wins, a request
header replaces a default one of the same name, and a relative `url`, or
a default one, is resolved against the default `base_url` (http or https,
with a host and no query), while an absolute one is sent as given.
Default headers, `username`, `password`, `userpwd`, `sslcert`, `sslkey`,
`sslkey_blob` and `keypasswd` go only to `base_url`'s origin, as they may
carry credentials for it. `body`, `reply_to`, `stream` and
`stream_window` are a request's alone. The defaults go with the pool.

An option that is not one of these, or has a value it cannot take, fails
the start with `bad_opts` naming it.
""".
-spec start(name(), pos_integer(), katipo:pool_opts()) ->
                   supervisor:startchild_ret() | {error, katipo:error()}.
start(PoolName, PoolSize, WorkerOpts)
  when is_atom(PoolName) andalso
       is_integer(PoolSize) andalso
       is_list(WorkerOpts) ->
    %% max_in_flight is enforced Erlang-side by the worker; everything else
    %% is a curl-multi argument for the C port. Validate and split it here,
    %% at the API boundary, so a bad value fails the start call directly
    %% instead of surfacing as N worker-init crashes under wpool.
    maybe
        {ok, Defaults, Opts1} ?= take_defaults(WorkerOpts),
        {ok, MaxInFlight, CurlOpts} ?= take_max_in_flight(Opts1),
        {ok, CurlArgs} ?= curl_args(CurlOpts),
        %% A fresh generation for this start: the workers admit only
        %% requests given this pool's defaults (katipo_defaults).
        {katipo_defaults, Get} = Opt = katipo_defaults:wpool_opt(make_ref(), Defaults),
        wpool:start_sup_pool(PoolName,
                             [{worker, {katipo_worker, [MaxInFlight, CurlArgs, Get]}},
                              {workers, PoolSize},
                              {pool_sup_shutdown, infinity},
                              Opt])
    end.

%% Every error in the defaults, in one bad_opts: base_url, which only they
%% take, the options only a request can mean, and the rest as check_opts/2
%% checks them.
take_defaults(Opts) ->
    case lists:keytake(defaults, 1, Opts) of
        {value, {defaults, D}, Rest} when is_map(D) ->
            case defaults_errors(D) of
                [] -> {ok, D, Rest};
                Bad -> {error, katipo_req:error_map(bad_opts, Bad)}
            end;
        {value, {defaults, D}, _Rest} ->
            {error, katipo_req:error_map(bad_opts, [{defaults, D}])};
        false ->
            {ok, #{}, Opts}
    end.

defaults_errors(D) ->
    PerRequest = [body, reply_to, stream, stream_window],
    base_url_errors(D) ++
        [{K, not_allowed_in_defaults} || K <- PerRequest, is_map_key(K, D)] ++
        katipo_req:opts_errors(maps:without([base_url | PerRequest], D), sync).

%% An http or https url with a host, and no query or fragment, which a
%% relative url's own would replace.
base_url_errors(#{base_url := Url}) ->
    case is_binary(Url) andalso uri_string:normalize(Url, [return_map]) of
        #{scheme := S, host := H} = U when (S =:= <<"http">> orelse S =:= <<"https">>)
                                           andalso H =/= <<>>
                                           andalso not is_map_key(query, U)
                                           andalso not is_map_key(fragment, U) ->
            case maps:get(port, U, 1) of
                P when is_integer(P) andalso P > 0 andalso P < 65536 -> [];
                _ -> [{base_url, Url}]
            end;
        _ ->
            [{base_url, Url}]
    end;
base_url_errors(#{}) ->
    [].

curl_args(CurlOpts) ->
    case katipo_worker:curl_args(CurlOpts) of
        {ok, _} = Ok -> Ok;
        {error, Bad} -> {error, katipo_req:error_map(bad_opts, Bad)}
    end.

take_max_in_flight(Opts) ->
    case lists:keytake(max_in_flight, 1, Opts) of
        {value, {max_in_flight, N}, Rest}
          when (is_integer(N) andalso N > 0) orelse N =:= infinity ->
            {ok, N, Rest};
        {value, {max_in_flight, V}, _Rest} ->
            {error, katipo_req:error_map(bad_opts, [{max_in_flight, V}])};
        false ->
            {ok, infinity, Opts}
    end.

-doc "Stops a named pool.".
-spec stop(name()) -> ok.
stop(PoolName) when is_atom(PoolName) ->
    wpool:stop_sup_pool(PoolName).
