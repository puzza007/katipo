-module(katipo_retry_SUITE).

%% Retries: the policy (katipo_retry) on its own, and the worker sending a
%% request again against katipo_script_server, which fails a scripted
%% number of times in a scripted way. No httpbin server is required.

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([policy_defaults/1]).
-export([policy_invalid/1]).
-export([retry_after_header/1]).
-export([backoff_bounds/1]).
-export([delay_decisions/1]).
-export([bad_opts/1]).
-export([status_then_ok/1]).
-export([gives_up_after_max_retries/1]).
-export([no_retry_by_default/1]).
-export([non_idempotent_not_retried/1]).
-export([method_opted_in/1]).
-export([status_not_listed/1]).
-export([honours_retry_after/1]).
-export([retry_after_too_long/1]).
-export([connection_closed_then_ok/1]).
-export([couldnt_connect_retried/1]).
-export([retry_dropped_when_caller_dead/1]).
-export([timeout_then_ok/1]).
-export([body_sent_again/1]).
-export([file_body_sent_again/1]).
-export([async_status_then_ok/1]).
-export([async_cancel_during_backoff/1]).
-export([async_cancel_during_retry/1]).
-export([stale_timer_ignored/1]).
-export([stale_port_output_dropped/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-define(WAIT, 5000).

all() ->
    [{group, policy}, {group, requests}].

groups() ->
    [{policy, [parallel],
      [policy_defaults, policy_invalid, retry_after_header, backoff_bounds,
       delay_decisions, bad_opts]},
     {requests, [parallel],
      [status_then_ok, gives_up_after_max_retries, no_retry_by_default,
       non_idempotent_not_retried, method_opted_in, status_not_listed,
       honours_retry_after, retry_after_too_long, connection_closed_then_ok,
       couldnt_connect_retried, retry_dropped_when_caller_dead, timeout_then_ok, body_sent_again,
       file_body_sent_again, async_status_then_ok, async_cancel_during_backoff,
       async_cancel_during_retry, stale_timer_ignored,
       stale_port_output_dropped]}].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    Config.

end_per_suite(Config) ->
    Config.

init_per_testcase(TestCase, Config) ->
    {ok, _} = katipo_pool:start(TestCase, 1, []),
    [{pool, TestCase} | Config].

end_per_testcase(_TestCase, Config) ->
    ok = katipo_pool:stop(?config(pool, Config)).

%% ---------------------------------------------------------------------
%% The policy

policy_defaults(_Config) ->
    {ok, undefined} = katipo_retry:policy(false),
    {ok, undefined} = katipo_retry:policy(#{max_retries => 0}),
    {ok, Defaults} = katipo_retry:policy(true),
    {ok, Defaults} = katipo_retry:policy(#{}),
    #{max_retries := 3, base_delay_ms := 100, max_delay_ms := 5000,
      statuses := [429, 503], errors := Errors, methods := Methods} = Defaults,
    %% GET, PUT, HEAD, OPTIONS, DELETE; not POST or PATCH.
    [0, 2, 3, 4, 6] = lists:sort(Methods),
    true = lists:member(couldnt_connect, Errors),
    false = lists:member(couldnt_resolve_host, Errors),
    {ok, #{max_retries := 1, statuses := [500], methods := [1]}} =
        katipo_retry:policy(#{max_retries => 1, statuses => [500], methods => [post]}).

policy_invalid(_Config) ->
    [error = katipo_retry:policy(P)
     || P <- [yes, 3, #{max_retries => -1}, #{max_retries => 1.0},
              #{base_delay_ms => -1}, #{max_delay_ms => infinity},
              #{methods => [connect]}, #{methods => get},
              #{statuses => [99]}, #{statuses => [600]}, #{statuses => 503},
              #{errors => ["couldnt_connect"]}, #{unknown => 1},
              #{methods => [get | put]}]].

retry_after_header(_Config) ->
    Now = 1700000000,
    H = fun(V) -> [{<<"Content-Type">>, <<"text/plain">>}, {<<"Retry-After">>, V}] end,
    {ok, 0} = katipo_retry:retry_after(H(<<"0">>), Now),
    {ok, 120000} = katipo_retry:retry_after(H(<<"120">>), Now),
    {ok, 7000} = katipo_retry:retry_after([{<<"retry-AFTER">>, <<"7">>}], Now),
    %% 1700000000 is Tue, 14 Nov 2023 22:13:20 GMT.
    {ok, 30000} = katipo_retry:retry_after(H(<<"Tue, 14 Nov 2023 22:13:50 GMT">>), Now),
    {ok, 0} = katipo_retry:retry_after(H(<<"Tue, 14 Nov 2023 22:00:00 GMT">>), Now),
    %% The obsolete forms a recipient must still accept.
    {ok, 30000} = katipo_retry:retry_after(H(<<"Tuesday, 14-Nov-23 22:13:50 GMT">>), Now),
    {ok, 30000} = katipo_retry:retry_after(H(<<"Tue Nov 14 22:13:50 2023">>), Now),
    {ok, 0} = katipo_retry:retry_after(H(<<"Tue Nov  7 22:13:50 2023">>), Now),
    %% A two-digit year over 50 years ahead is in the past century.
    {ok, 0} = katipo_retry:retry_after(H(<<"Sunday, 06-Nov-94 08:49:37 GMT">>), Now),
    {ok, 0} = katipo_retry:retry_after(H(<<"Sunday, 06-Nov-74 08:49:37 GMT">>), Now),
    {ok, _} = katipo_retry:retry_after(H(<<"Monday, 06-Nov-73 08:49:37 GMT">>), Now),
    [error = katipo_retry:retry_after(Hs, Now)
     || Hs <- [[], H(<<>>), H(<<"-1">>), H(<<"1.5">>), H(<<" 5">>),
               H(<<"Tue, 14 Nov 2023 22:13:50 UTC">>),
               H(<<"Tue, 31 Feb 2023 22:13:50 GMT">>),
               H(<<"Tue, 14 Foo 2023 22:13:50 GMT">>),
               H(<<"Tue, 14 Nov 2023 25:13:50 GMT">>),
               H(<<"Tue, 14-Nov-23 22:13:50 GMT">>),
               H(<<"Tuesday, 14-Nov-2023 22:13:50 GMT">>),
               H(<<"Tue Nov 14 22:13:50 23">>),
               %% A name that is not UTF-8 is compared, not rejected.
               [{<<16#ff, "etry-after">>, <<"5">>}]]].

backoff_bounds(_Config) ->
    {ok, P} = katipo_retry:policy(#{max_retries => 100, base_delay_ms => 10,
                                    max_delay_ms => 1000}),
    Err = #{code => couldnt_connect, message => <<>>},
    Delays = fun(N) -> [D || _ <- lists:seq(1, 200),
                            {ok, D} <- [katipo_retry:delay(P, N, error, Err, 0)]] end,
    D0 = Delays(0),
    200 = length(D0),
    true = lists:max(D0) =< 10,
    true = lists:max(Delays(3)) =< 80,
    true = lists:max(Delays(3)) > 10,
    %% Capped, however many retries.
    true = lists:max(Delays(60)) =< 1000,
    true = lists:max(Delays(60)) > 500,
    true = lists:min(Delays(60)) >= 0.

delay_decisions(_Config) ->
    Now = 1700000000,
    {ok, P} = katipo_retry:policy(#{max_retries => 2, max_delay_ms => 3000}),
    Resp = fun(S, Hs) -> #{status => S, headers => Hs} end,
    {ok, _} = katipo_retry:delay(P, 0, ok, Resp(503, []), Now),
    {ok, _} = katipo_retry:delay(P, 1, ok, Resp(429, []), Now),
    none = katipo_retry:delay(P, 2, ok, Resp(503, []), Now),
    none = katipo_retry:delay(P, 0, ok, Resp(500, []), Now),
    none = katipo_retry:delay(P, 0, ok, Resp(200, []), Now),
    {ok, 2000} = katipo_retry:delay(P, 0, ok, Resp(503, [{<<"Retry-After">>, <<"2">>}]), Now),
    {ok, 3000} = katipo_retry:delay(P, 0, ok, Resp(503, [{<<"Retry-After">>, <<"3">>}]), Now),
    none = katipo_retry:delay(P, 0, ok, Resp(503, [{<<"Retry-After">>, <<"4">>}]), Now),
    %% Retry-After on a status that is not retried changes nothing.
    none = katipo_retry:delay(P, 0, ok, Resp(500, [{<<"Retry-After">>, <<"1">>}]), Now),
    %% A date is waited out from Now.
    {ok, 2000} = katipo_retry:delay(P, 0, ok,
                                    Resp(503, [{<<"Retry-After">>,
                                                <<"Tue, 14 Nov 2023 22:13:22 GMT">>}]),
                                    Now),
    {ok, _} = katipo_retry:delay(P, 0, error, #{code => got_nothing, message => <<>>}, Now),
    none = katipo_retry:delay(P, 0, error, #{code => ssl_cacert, message => <<>>}, Now),
    none = katipo_retry:delay(P, 0, done, #{status => 503}, Now).

bad_opts(Config) ->
    Pool = ?config(pool, Config),
    Url = <<"http://127.0.0.1:1/">>,
    {error, #{code := bad_opts, message := M1}} =
        katipo:async_req(Pool, #{url => Url, method => put, retry => true,
                                 body => {stream, #{}}}),
    {match, _} = re:run(M1, "not_allowed_with_stream"),
    {error, #{code := bad_opts, message := M2}} =
        katipo:async_req(Pool, #{url => Url, retry => true, stream => true}),
    {match, _} = re:run(M2, "not_allowed_with_stream"),
    {error, #{code := bad_opts}} = katipo:get(Pool, Url, #{retry => #{max_retries => x}}),
    ok = katipo:check_opts(#{retry => #{statuses => [500, 502]}}, sync),
    %% Turned off, a retry is no reason to refuse a stream.
    ok = katipo:check_opts(#{retry => false, stream => true}, async),
    ok = katipo:check_opts(#{retry => #{max_retries => 0}, stream => true}, async),
    %% Nor is a policy that would never retry the method.
    ok = katipo:check_opts(#{method => post, retry => true, stream => true}, async).

%% ---------------------------------------------------------------------
%% Requests

status_then_ok(Config) ->
    {ok, Server, Port} = katipo_script_server:start([{respond, status(503, [])}]),
    {ok, #{status := 200, body := <<"ok">>}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port), fast()),
    2 = requests(Server).

gives_up_after_max_retries(Config) ->
    {ok, Server, Port} = katipo_script_server:start(
                           lists:duplicate(5, {respond, status(503, [])})),
    {ok, #{status := 503}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port),
                   #{retry => #{max_retries => 3, base_delay_ms => 1}}),
    4 = requests(Server).

no_retry_by_default(Config) ->
    {ok, Server, Port} = katipo_script_server:start([{respond, status(503, [])}]),
    {ok, #{status := 503}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port)),
    1 = requests(Server).

non_idempotent_not_retried(Config) ->
    {ok, Server, Port} = katipo_script_server:start([{respond, status(503, [])}, close]),
    Url = katipo_script_server:url(Port),
    Pool = ?config(pool, Config),
    {ok, #{status := 503}} = katipo:post(Pool, Url, (fast())#{body => <<"x">>}),
    1 = requests(Server),
    {error, #{code := got_nothing}} = katipo:patch(Pool, Url, (fast())#{body => <<"x">>}),
    1 = requests(Server).

method_opted_in(Config) ->
    {ok, Server, Port} = katipo_script_server:start([{respond, status(503, [])}]),
    {ok, #{status := 200}} =
        katipo:post(?config(pool, Config), katipo_script_server:url(Port),
                    #{body => <<"x">>,
                      retry => #{methods => [post], base_delay_ms => 1}}),
    2 = requests(Server).

status_not_listed(Config) ->
    {ok, Server, Port} = katipo_script_server:start([{respond, status(500, [])},
                                                     {respond, status(502, [])}]),
    Url = katipo_script_server:url(Port),
    Pool = ?config(pool, Config),
    {ok, #{status := 500}} = katipo:get(Pool, Url, fast()),
    1 = requests(Server),
    {ok, #{status := 200}} =
        katipo:get(Pool, Url, #{retry => #{statuses => [502], base_delay_ms => 1}}),
    2 = requests(Server).

honours_retry_after(Config) ->
    {ok, Server, Port} = katipo_script_server:start(
                           [{respond, status(429, ["retry-after: 1\r\n"])}]),
    T0 = erlang:monotonic_time(millisecond),
    {ok, #{status := 200}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port), fast()),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    true = Elapsed >= 1000,
    2 = requests(Server).

retry_after_too_long(Config) ->
    {ok, Server, Port} = katipo_script_server:start(
                           [{respond, status(503, ["retry-after: 60\r\n"])}]),
    T0 = erlang:monotonic_time(millisecond),
    {ok, #{status := 503, headers := Headers}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port), fast()),
    true = erlang:monotonic_time(millisecond) - T0 < 1000,
    {<<"retry-after">>, <<"60">>} = lists:keyfind(<<"retry-after">>, 1, Headers),
    1 = requests(Server).

connection_closed_then_ok(Config) ->
    {ok, Server, Port} = katipo_script_server:start([close, close]),
    {ok, #{status := 200}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port), fast()),
    3 = requests(Server).

%% Nothing listens on port 1, so every attempt fails to connect. The
%% attempts are counted as the worker's retry timers firing.
couldnt_connect_retried(Config) ->
    Url = <<"http://127.0.0.1:1/">>,
    Pool = ?config(pool, Config),
    Worker = worker_pid(Pool),
    1 = erlang:trace(Worker, true, ['receive']),
    {error, #{code := couldnt_connect}} =
        katipo:get(Pool, Url, #{retry => #{max_retries => 2, base_delay_ms => 0}}),
    1 = erlang:trace(Worker, false, ['receive']),
    2 = length(retries_fired(Worker)).

retries_fired(Worker) ->
    receive
        {trace, Worker, 'receive', {timeout, _, {retry, _}}} -> [retry | retries_fired(Worker)];
        {trace, Worker, 'receive', _} -> retries_fired(Worker)
    after 0 -> []
    end.

%% A request whose caller has died is not sent again. Retry-After makes
%% the backoff a fixed second, so the caller dies inside it.
retry_dropped_when_caller_dead(Config) ->
    {ok, Server, Port} = katipo_script_server:start(
                           [{respond, status(503, ["retry-after: 1\r\n"])}]),
    Pool = ?config(pool, Config),
    {Caller, Mon} = spawn_monitor(
                      fun() ->
                              katipo:get(Pool, katipo_script_server:url(Port),
                                         #{retry => true})
                      end),
    first_request(Server),
    %% The 503 is in, and the request waits out its backoff.
    timer:sleep(200),
    exit(Caller, kill),
    receive {'DOWN', Mon, process, Caller, killed} -> ok
    after ?WAIT -> ct:fail(caller_not_killed)
    end,
    receive {script_request, Server, _, _} -> ct:fail(retried_for_dead_caller)
    after 1500 -> ok
    end,
    0 = in_flight(Pool).

%% The first attempt is never answered, so it times out (on curl's timer or
%% the worker's, whichever is first) and is aborted; the retry is answered.
timeout_then_ok(Config) ->
    {ok, Server, Port} = katipo_script_server:start([hang]),
    {ok, #{status := 200}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port),
                   #{timeout_ms => 300, retry => #{base_delay_ms => 0}}),
    2 = requests(Server).

body_sent_again(Config) ->
    {ok, Server, Port} = katipo_script_server:start([{respond, status(503, [])}]),
    Body = binary:copy(<<"abc">>, 1000),
    {ok, #{status := 200}} =
        katipo:put(?config(pool, Config), katipo_script_server:url(Port),
                   (fast())#{body => Body}),
    [Body, Body] = bodies(Server, 2).

file_body_sent_again(Config) ->
    {ok, Server, Port} = katipo_script_server:start([{respond, status(503, [])}]),
    Body = binary:copy(<<"0123456789">>, 10000),
    File = filename:join(?config(priv_dir, Config), "file_body_sent_again"),
    ok = file:write_file(File, Body),
    {ok, #{status := 200}} =
        katipo:put(?config(pool, Config), katipo_script_server:url(Port),
                   (fast())#{body => {file, File}}),
    [Body, Body] = bodies(Server, 2).

async_status_then_ok(Config) ->
    {ok, Server, Port} = katipo_script_server:start([{respond, status(503, [])}, close]),
    {ok, Ref} = katipo:async_get(?config(pool, Config), katipo_script_server:url(Port),
                                 fast()),
    {ok, #{status := 200}} = katipo:await(Ref, ?WAIT),
    3 = requests(Server),
    receive Late -> ct:fail({late, Late}) after 200 -> ok end.

%% A cancel while the request waits to be sent again: nothing is sent and
%% nothing delivered.
async_cancel_during_backoff(Config) ->
    {ok, Server, Port} = katipo_script_server:start(
                           [{respond, status(503, ["retry-after: 1\r\n"])}]),
    Pool = ?config(pool, Config),
    {ok, Ref} = katipo:async_get(Pool, katipo_script_server:url(Port), #{retry => true}),
    receive {script_request, Server, _, _} -> ok after ?WAIT -> ct:fail(no_request) end,
    %% The first response is in before the cancel.
    timer:sleep(200),
    ok = katipo:cancel(Pool, Ref),
    receive
        {script_request, Server, _, _} -> ct:fail(retried_after_cancel);
        {katipo_response, Ref, _} = M -> ct:fail({delivered, M});
        {katipo_error, Ref, _} = M -> ct:fail({delivered, M})
    after 1500 -> ok
    end,
    %% Nothing is left in the worker.
    0 = in_flight(Pool).

%% A cancel while a retry is in flight aborts it.
async_cancel_during_retry(Config) ->
    {ok, Server, Port} = katipo_script_server:start([close, hang]),
    Pool = ?config(pool, Config),
    {ok, Ref} = katipo:async_get(Pool, katipo_script_server:url(Port), fast()),
    [_, _] = [receive {script_request, Server, _, _} -> ok
              after ?WAIT -> ct:fail(no_request) end || _ <- [1, 2]],
    ok = katipo:cancel(Pool, Ref),
    receive
        {katipo_response, Ref, _} = M -> ct:fail({delivered, M});
        {katipo_error, Ref, _} = M -> ct:fail({delivered, M})
    after 500 -> ok
    end,
    0 = in_flight(Pool).

%% formal/KatipoRetryNoTref.cfg: an earlier attempt's request timer, fired
%% as the attempt ended, must not cut the retry short. The message is sent
%% by hand while the retry runs, as erlang:start_timer/3 would have.
stale_timer_ignored(Config) ->
    {ok, Server, Port} = katipo_script_server:start([hang, hang]),
    Pool = ?config(pool, Config),
    {ok, Ref} = katipo:async_get(Pool, katipo_script_server:url(Port),
                                 #{timeout_ms => 1000,
                                   retry => #{max_retries => 1, base_delay_ms => 0}}),
    first_request(Server),
    Worker = worker_pid(Pool),
    Key = {Worker, Ref},
    {inflight, Tref0, _, Key, _, 0} = entry(Pool, Key),
    first_request(Server),
    Retry = {inflight, Tref1, _, {Worker, _}, _, 1} = entry(Pool, Key),
    true = Tref1 =/= Tref0,
    Worker ! {timeout, Tref0, {req_timeout, Key}},
    Retry = entry(Pool, Key),
    %% The retry runs to its own timeout.
    {error, #{code := operation_timedout}} = katipo:await(Ref, ?WAIT),
    0 = in_flight(Pool).

%% formal/KatipoRetryReuse.cfg: output from an attempt given up on, arriving
%% after the retry is sent, must not be taken for the retry's. Sent by hand
%% as the C port would have, under the first attempt's port id.
stale_port_output_dropped(Config) ->
    {ok, Server, Port} = katipo_script_server:start([hang, hang]),
    Pool = ?config(pool, Config),
    {ok, Ref} = katipo:async_get(Pool, katipo_script_server:url(Port),
                                 #{timeout_ms => 500,
                                   retry => #{max_retries => 1, base_delay_ms => 0}}),
    first_request(Server),
    first_request(Server),
    Worker = worker_pid(Pool),
    Key = {Worker, Ref},
    Retry = {inflight, _, _, {Worker, _}, _, 1} = entry(Pool, Key),
    Stale = [term_to_binary({ok, {Key, {200, [<<"HTTP/1.1 200 OK">>], [], <<>>, []}}}),
             <<"stale">>],
    Worker ! {worker_port(Worker), {data, iolist_to_binary(Stale)}},
    Retry = entry(Pool, Key),
    {error, #{code := operation_timedout}} = katipo:await(Ref, ?WAIT).

%% ---------------------------------------------------------------------

first_request(Server) ->
    receive {script_request, Server, _, _} -> ok after ?WAIT -> ct:fail(no_request) end.

worker_pid(Pool) ->
    [Worker] = wpool:get_workers(Pool),
    whereis(Worker).

worker_port(Worker) ->
    [Port] = [P || P <- erlang:ports(),
                   erlang:port_info(P, connected) =:= {connected, Worker}],
    Port.

%% The worker's #inflight{tref, kind, port_id, req, retries} for Key.
entry(Pool, Key) ->
    {state, _, _, {state, _Port, Reqs, _Ids, _Max, _Gen, _Defaults}, _} = sys:get_state(worker_pid(Pool)),
    maps:get(Key, Reqs).

fast() ->
    #{retry => #{base_delay_ms => 1, max_delay_ms => 5000}}.

status(Code, ExtraHeaders) ->
    [<<"HTTP/1.1 ">>, integer_to_binary(Code), <<" Retry\r\n">>, ExtraHeaders,
     <<"content-length: 0\r\nconnection: close\r\n\r\n">>].

%% How many requests the server has had, once they are all in.
requests(Server) ->
    length(bodies(Server, infinity)).

bodies(Server, N) ->
    bodies(Server, N, []).

bodies(_Server, 0, Acc) ->
    lists:reverse(Acc);
bodies(Server, N, Acc) ->
    receive
        {script_request, Server, _Head, Body} ->
            bodies(Server, case N of infinity -> N; _ -> N - 1 end, [Body | Acc])
    after 100 ->
            case N of
                infinity -> lists:reverse(Acc);
                _ -> ct:fail({missing_requests, N})
            end
    end.

in_flight(Pool) ->
    [Worker] = wpool:get_workers(Pool),
    %% katipo_worker's #state{port, reqs, ids, max_in_flight}, inside
    %% wpool_process's wrapper (as katipo_SUITE's worker_state/1).
    {state, _, _, {state, _Port, Reqs, _Ids, _Max, _Gen, _Defaults}, _} = sys:get_state(whereis(Worker)),
    map_size(Reqs).
