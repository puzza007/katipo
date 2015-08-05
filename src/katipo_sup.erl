-module(katipo_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    RestartStrategy = one_for_one,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    Restart = permanent,
    Shutdown = 2000,
    Type = worker,

    WorkerOpts = lists:map(fun mopt/1, [max_pipeline_length, pipelining]),
    NumSchedulers = erlang:system_info(schedulers),
    PoolSize = application:get_env(katipo, pool_size, NumSchedulers),

    PoolType = application:get_env(katipo, pool_type, round_robin),
    ok = gproc_pool:new(katipo, PoolType, [{size, PoolSize}]),
    _ = [gproc_pool:add_worker(katipo, id(N)) || N <- lists:seq(1, PoolSize)],

    Children = [{id(N), {katipo, start_link, [WorkerOpts, id(N)]},
                 Restart, Shutdown, Type, [katipo]} || N <- lists:seq(1, PoolSize)],

    {ok, {SupFlags, Children}}.

mopt(K) ->
    {ok, V} = application:get_env(katipo, K),
    {K, V}.


id(N) when is_integer(N) ->
    list_to_atom("katipo_" ++ integer_to_list(N)).
