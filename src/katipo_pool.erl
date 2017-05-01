-module(katipo_pool).

-export([start/2]).
-export([start/3]).
-export([stop/1]).

-type name() :: atom().
-export_type([name/0]).

-spec start(name(), pos_integer()) -> supervisor:startchild_ret().
start(PoolName, PoolSize) ->
    start(PoolName, PoolSize, []).

-spec start(name(), pos_integer(), katipo:curlmopts()) ->
                   supervisor:startchild_ret().
start(PoolName, PoolSize, WorkerOpts)
  when is_atom(PoolName) andalso
       is_integer(PoolSize) andalso
       is_list(WorkerOpts) ->
    Args = [WorkerOpts],

    PoolOpts = [{worker, {katipo, Args}},
                {workers, PoolSize}],

    wpool:start_sup_pool(PoolName, PoolOpts).

-spec stop(name()) -> ok.
stop(PoolName) when is_atom(PoolName) ->
    wpool:stop_pool(PoolName).
