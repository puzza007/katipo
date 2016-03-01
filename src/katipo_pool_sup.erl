-module(katipo_pool_sup).

-behaviour(supervisor).

-export([start_link/3]).

-export([init/1]).

start_link(PoolName, PoolSize, WorkerOpts) ->
    supervisor:start_link({local, PoolName}, ?MODULE,
                          [PoolName, PoolSize, WorkerOpts]).

init([PoolName, PoolSize, WorkerOpts]) ->
    SupFlags = #{strategy => one_for_one,
                 intensity => 20,
                 period => 5},

    Children = [begin
                    WorkerName = katipo_pool:worker_name(PoolName, N),
                    #{id => WorkerName,
                      start => {katipo, start_link, [PoolName, WorkerOpts, WorkerName]},
                      restart => permanent,
                      shutdown => 2000,
                      type => worker,
                      modules => [katipo]}
                end || N <- lists:seq(1, PoolSize)],

    {ok, {SupFlags, Children}}.
