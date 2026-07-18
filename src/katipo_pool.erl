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
""".
-spec start(name(), pos_integer(), katipo:pool_opts()) ->
                   supervisor:startchild_ret() | {error, map()}.
start(PoolName, PoolSize, WorkerOpts)
  when is_atom(PoolName) andalso
       is_integer(PoolSize) andalso
       is_list(WorkerOpts) ->
    %% max_in_flight is enforced Erlang-side by the worker; everything else
    %% is a curl-multi argument for the C port. Validate and split it here,
    %% at the API boundary, so a bad value fails the start call directly
    %% instead of surfacing as N worker-init crashes under wpool.
    case take_max_in_flight(WorkerOpts) of
        {error, _} = Error ->
            Error;
        {MaxInFlight, CurlOpts} ->
            Args = [MaxInFlight, CurlOpts],
            PoolOpts = [{worker, {katipo_worker, Args}},
                        {workers, PoolSize},
                        {pool_sup_shutdown, infinity}],
            wpool:start_sup_pool(PoolName, PoolOpts)
    end.

take_max_in_flight(Opts) ->
    case lists:keytake(max_in_flight, 1, Opts) of
        {value, {max_in_flight, N}, Rest}
          when (is_integer(N) andalso N > 0) orelse N =:= infinity ->
            {N, Rest};
        {value, {max_in_flight, V}, _Rest} ->
            {error, katipo_req:error_map(bad_opts, [{max_in_flight, V}])};
        false ->
            {infinity, Opts}
    end.

-doc "Stops a named pool.".
-spec stop(name()) -> ok.
stop(PoolName) when is_atom(PoolName) ->
    wpool:stop_sup_pool(PoolName).
