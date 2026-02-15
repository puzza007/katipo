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

-doc "Starts a named pool of katipo workers with the given size and curl multi options.".
-spec start(name(), pos_integer(), katipo:curlmopts()) ->
                   supervisor:startchild_ret().
start(PoolName, PoolSize, WorkerOpts)
  when is_atom(PoolName) andalso
       is_integer(PoolSize) andalso
       is_list(WorkerOpts) ->
    Args = [WorkerOpts],

    PoolOpts = [{worker, {katipo, Args}},
                {workers, PoolSize},
                {pool_sup_shutdown, infinity}],

    wpool:start_sup_pool(PoolName, PoolOpts).

-doc "Stops a named pool.".
-spec stop(name()) -> ok.
stop(PoolName) when is_atom(PoolName) ->
    wpool:stop_sup_pool(PoolName).
