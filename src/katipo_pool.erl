-module(katipo_pool).

-export([start/3]).
-export([stop/1]).
-export([worker_name/2]).

-type name() :: atom().
-export_type([name/0]).

-spec start(name(), pos_integer(), katipo:curlmopts()) ->
                   supervisor:startchild_ret().
start(PoolName, PoolSize, WorkerOpts)
  when is_atom(PoolName) andalso
       is_integer(PoolSize) andalso
       is_list(WorkerOpts) ->
    Args = [PoolName, PoolSize, WorkerOpts],

    ChildSpec = #{id => PoolName,
                  start => {katipo_pool_sup, start_link, Args},
                  restart => permanent,
                  shutdown => 2000,
                  type => supervisor,
                  modules => [katipo_pool_sup]},

    ok = gproc_pool:new(PoolName, round_robin, [{size, PoolSize}]),
    _ = [gproc_pool:add_worker(PoolName, worker_name(PoolName, N))
         || N <- lists:seq(1, PoolSize)],

    supervisor:start_child(katipo_sup, ChildSpec).

-spec stop(name()) -> ok.
stop(PoolName) when is_atom(PoolName) ->
    ok = supervisor:terminate_child(katipo_sup, PoolName),
    true = gproc_pool:force_delete(PoolName),
    ok = supervisor:delete_child(katipo_sup, PoolName).

-spec worker_name(name(), pos_integer()) -> atom().
worker_name(PoolName, N) when is_integer(N) ->
    PoolNameList = atom_to_list(PoolName),
    list_to_atom("katipo_" ++ PoolNameList ++ "_" ++ integer_to_list(N)).
