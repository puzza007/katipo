-module(katipo_pool_SUITE).

%% Pool options that bound curl's connections: max_host_connections and
%% maxconnects, observed through what a test server sees. No httpbin
%% server is required.

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([end_per_testcase/2]).

-export([bad_values/1]).
-export([one_connection_per_host/1]).
-export([two_connections_per_host/1]).
-export([held_request_times_out/1]).
-export([cap_is_per_worker/1]).
-export([cache_evicts/1]).
-export([cache_keeps/1]).

-include_lib("common_test/include/ct.hrl").

-define(WAIT, 5000).
%% How long a request held back by a cap is given to show up anyway.
-define(HELD, 500).

all() ->
    [bad_values, one_connection_per_host, two_connections_per_host,
     held_request_times_out, cap_is_per_worker, cache_evicts, cache_keeps].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    Config.

end_per_suite(Config) ->
    Config.

end_per_testcase(TestCase, _Config) ->
    _ = katipo_pool:stop(TestCase),
    ok.

bad_values(_Config) ->
    [{error, #{code := bad_opts}} = katipo_pool:start(bad_values, 1, [{Opt, V}])
     || Opt <- [max_host_connections, maxconnects], V <- [-1, 1.5, foo, 2147483648]],
    {error, #{code := bad_opts}} = katipo_pool:start(bad_values, 1, [maxconnects]),
    {ok, _} = katipo_pool:start(bad_values, 1, [{max_host_connections, 0}, {maxconnects, 0}]).

%% With one connection allowed to the host, a second request waits for the
%% first, which the server never answers, to time out before it is sent.
%% Requests go without pipewait, so that curl would otherwise open another
%% connection at once rather than wait to see whether the first can
%% multiplex.
one_connection_per_host(_Config) ->
    held(one_connection_per_host, 1, [{max_host_connections, 1}]).

two_connections_per_host(_Config) ->
    held(two_connections_per_host, 2, [{max_host_connections, 2}]).

%% Cap requests to `Cap` hanging requests then one more: the first `Cap`
%% reach the server at once, the last only once one of them has timed out.
held(Pool, Cap, PoolOpts) ->
    {ok, _} = katipo_pool:start(Pool, 1, PoolOpts),
    {ok, Server, Port} = katipo_script_server:start(lists:duplicate(Cap, hang)),
    Url = katipo_script_server:url(Port),
    Hung = [begin
                {ok, Ref} = katipo:async_get(Pool, Url, #{timeout_ms => 2000,
                                                          pipewait => false}),
                Ref
            end || _ <- lists:seq(1, Cap)],
    {ok, Last} = katipo:async_get(Pool, Url, #{pipewait => false}),
    [request(Server) || _ <- Hung],
    no_request(Server),
    [{error, #{code := operation_timedout}} = katipo:await(Ref, ?WAIT) || Ref <- Hung],
    request(Server),
    {ok, #{status := 200}} = katipo:await(Last, ?WAIT).

%% A request held back by the cap still times out on its own timeout_ms,
%% not when the request ahead of it lets go of the connection.
held_request_times_out(_Config) ->
    {ok, _} = katipo_pool:start(held_request_times_out, 1, [{max_host_connections, 1}]),
    {ok, Server, Port} = katipo_script_server:start([hang]),
    Url = katipo_script_server:url(Port),
    {ok, Hung} = katipo:async_get(held_request_times_out, Url,
                                  #{timeout_ms => 4000, pipewait => false}),
    request(Server),
    T0 = erlang:monotonic_time(millisecond),
    {error, #{code := operation_timedout}} =
        katipo:get(held_request_times_out, Url, #{timeout_ms => 500, pipewait => false}),
    true = erlang:monotonic_time(millisecond) - T0 < 2000,
    {error, #{code := operation_timedout}} = katipo:await(Hung, ?WAIT).

%% The cap is per worker, not per pool: two workers, each holding one
%% hanging request, have a connection to the host each. max_in_flight 1
%% sends the second request to the other worker. That the cap holds a
%% request back at all is the tests above.
cap_is_per_worker(_Config) ->
    {ok, _} = katipo_pool:start(cap_is_per_worker, 2, [{max_host_connections, 1},
                                                       {max_in_flight, 1}]),
    {ok, Server, Port} = katipo_script_server:start([hang, hang]),
    Url = katipo_script_server:url(Port),
    Refs = [begin
                {ok, Ref} = katipo:async_get(cap_is_per_worker, Url,
                                             #{timeout_ms => 1000, pipewait => false}),
                Ref
            end || _ <- [1, 2]],
    [request(Server) || _ <- Refs],
    [{error, #{code := operation_timedout}} = katipo:await(Ref, ?WAIT) || Ref <- Refs].

%% A cache of one connection: after requests to A then B, B's connection
%% has taken A's place, so A gets a new one. curl up to 8.11 evicts the
%% oldest by age in whole milliseconds, so the requests are a few apart.
cache_evicts(_Config) ->
    2 = connections_to_a(cache_evicts, [{maxconnects, 1}]).

%% The same with room for both: A's connection is used again.
cache_keeps(_Config) ->
    1 = connections_to_a(cache_keeps, [{maxconnects, 2}]).

connections_to_a(Pool, PoolOpts) ->
    {ok, _} = katipo_pool:start(Pool, 1, PoolOpts),
    {ok, A, PortA} = katipo_script_server:start([keepalive, keepalive]),
    {ok, _B, PortB} = katipo_script_server:start([keepalive]),
    [begin
         {ok, #{status := 200}} = katipo:get(Pool, katipo_script_server:url(P)),
         timer:sleep(5)
     end || P <- [PortA, PortB, PortA]],
    length([x || {script_connection, Server} <- flush(), Server =:= A]).

request(Server) ->
    receive {script_request, Server, _, _} -> ok after ?WAIT -> ct:fail(no_request) end.

no_request(Server) ->
    receive {script_request, Server, _, _} -> ct:fail(not_held) after ?HELD -> ok end.

flush() ->
    receive M -> [M | flush()] after 0 -> [] end.
