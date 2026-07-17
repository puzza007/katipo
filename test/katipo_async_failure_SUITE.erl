-module(katipo_async_failure_SUITE).

%% Regression tests for async dispatch failure windows found by
%% model-checking the worker/port protocol (see formal/). Katipo.tla models
%% the pre-fix protocol and exhibits each failure as a TLC counterexample;
%% KatipoFixed.tla models the current protocol and verifies the contract
%% these tests assert:
%%
%%   - an async request either returns {error, worker_died} from async_req
%%     itself, or produces exactly one terminal message later;
%%   - a cancel never causes a message for the cancelled Ref.
%%
%% The model-found interleavings are forced deterministically with
%% sys:suspend/1 (messages queue but are not processed) and port_close/1
%% (subsequent port_command raises badarg; the owner's 'EXIT' message is
%% enqueued BEHIND anything already in its mailbox).
%%
%% No httpbin server is required: none of these requests ever completes.

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([admission_error_when_port_closes_before_dispatch/1]).
-export([admission_error_when_worker_restarting/1]).
-export([no_message_after_cancel_against_dead_port/1]).

-include_lib("stdlib/include/assert.hrl").

all() ->
    [admission_error_when_port_closes_before_dispatch,
     admission_error_when_worker_restarting,
     no_message_after_cancel_against_dead_port].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    Config.

end_per_suite(Config) ->
    Config.

init_per_testcase(TestCase, Config) ->
    Pool = TestCase,
    {ok, _} = katipo_pool:start(Pool, 1, []),
    [{pool, Pool} | Config].

end_per_testcase(_TestCase, Config) ->
    {pool, Pool} = lists:keyfind(pool, 1, Config),
    ok = katipo_pool:stop(Pool),
    ok.

%% A request to an address that will never connect quickly, so an accepted
%% request stays in the worker's Reqs map for the duration of the test.
blackhole_req() ->
    #{url => <<"http://10.255.255.1/">>,
      method => get,
      connecttimeout_ms => 30000,
      timeout_ms => 30000}.

%% Katipo.tla: EventualOutcome violated via SendAsync -> PortDies ->
%% WorkerRecvReq-badarg. The admission call is already queued when the port
%% dies; the worker crashes in send_to_port before registering the request.
%% The call monitor must convert that into {error, worker_died} -- before
%% the fix the request was cast fire-and-forget and simply vanished.
admission_error_when_port_closes_before_dispatch(Config) ->
    {pool, Pool} = lists:keyfind(pool, 1, Config),
    [WorkerName] = wpool:get_workers(Pool),
    WorkerPid = whereis(WorkerName),
    Port = find_port(sys:get_state(WorkerPid)),
    true = is_port(Port),

    %% Freeze the worker so the admission call queues unprocessed, then
    %% close its port. The 'EXIT' message lands behind the queued call.
    ok = sys:suspend(WorkerPid),
    Parent = self(),
    _Caller = spawn_link(
                fun() ->
                        Res = katipo:async_req(Pool, blackhole_req()),
                        Parent ! {async_result, Res}
                end),
    ok = wait_until(fun() ->
                            {message_queue_len, N} =
                                process_info(WorkerPid, message_queue_len),
                            N >= 1
                    end, 50),
    true = port_close(Port),
    ok = sys:resume(WorkerPid),

    receive
        {async_result, Res} ->
            ?assertMatch({error, #{code := worker_died}}, Res)
    after 2000 ->
            ct:fail(async_req_did_not_return)
    end.

%% Katipo.tla: EventualOutcome violated via PortDies -> WorkerRecvExit ->
%% SendAsync-dropped. While wpool restarts a dead worker its registered
%% name points nowhere; the admission call must fail fast with noproc and
%% surface as {error, worker_died} -- before the fix the cast was silently
%% dropped and async_req still returned {ok, Ref}.
admission_error_when_worker_restarting(Config) ->
    {pool, Pool} = lists:keyfind(pool, 1, Config),
    [WorkerName] = wpool:get_workers(Pool),
    WorkerPid = whereis(WorkerName),

    %% Suspend the worker's supervisor so the restart window stays open
    %% deterministically, then kill the worker.
    {dictionary, Dict} = process_info(WorkerPid, dictionary),
    [Sup | _] = proplists:get_value('$ancestors', Dict),
    ok = sys:suspend(Sup),
    MRef = monitor(process, WorkerPid),
    exit(WorkerPid, kill),
    receive {'DOWN', MRef, process, WorkerPid, killed} -> ok
    after 1000 -> ct:fail(worker_not_killed)
    end,
    undefined = whereis(WorkerName),

    Res = katipo:async_req(Pool, blackhole_req()),
    ok = sys:resume(Sup),
    ?assertMatch({error, #{code := worker_died}}, Res).

%% Katipo.tla: NoCancelPollution violated via SendAsync -> WorkerRecvReq ->
%% PortDies -> WorkerRecvCancel-badarg. A cancel processed against a dead
%% port used to crash the worker via port_command before maps:remove, so
%% terminate/2 delivered worker_died to the caller who cancelled. Fixed
%% cancel_async removes the request first and treats the port write as
%% best-effort: the cancelled caller must hear nothing.
no_message_after_cancel_against_dead_port(Config) ->
    {pool, Pool} = lists:keyfind(pool, 1, Config),
    [WorkerName] = wpool:get_workers(Pool),
    WorkerPid = whereis(WorkerName),

    {ok, Ref} = katipo:async_req(Pool, blackhole_req()),
    ok = wait_until(fun() ->
                            {state, _Port, Reqs} =
                                find_worker_state(sys:get_state(WorkerPid)),
                            maps:size(Reqs) > 0
                    end, 50),
    Port = find_port(sys:get_state(WorkerPid)),
    true = is_port(Port),

    %% Freeze the worker, enqueue the cancel, then close the port so the
    %% cancel is processed against a dead port.
    ok = sys:suspend(WorkerPid),
    ok = katipo:cancel(Pool, Ref),
    true = port_close(Port),
    ok = sys:resume(WorkerPid),

    receive
        {katipo_error, Ref, Error} ->
            ct:fail({message_delivered_after_cancel, Error});
        {katipo_response, Ref, Response} ->
            ct:fail({message_delivered_after_cancel, Response})
    after 1000 ->
            ok
    end.

wait_until(_Fun, 0) ->
    {error, condition_never_true};
wait_until(Fun, Retries) ->
    case Fun() of
        true ->
            ok;
        false ->
            timer:sleep(20),
            wait_until(Fun, Retries - 1)
    end.

%% The worker's #state{port, reqs} record, nested inside wpool_process's
%% own state record. Located structurally to avoid depending on wpool
%% internals.
find_worker_state(T = {state, Port, Reqs}) when is_port(Port), is_map(Reqs) ->
    T;
find_worker_state(T) when is_tuple(T) ->
    find_worker_state(tuple_to_list(T));
find_worker_state([H | T]) ->
    case find_worker_state(H) of
        undefined -> find_worker_state(T);
        Found -> Found
    end;
find_worker_state(_) ->
    undefined.

find_port(T) ->
    case find_worker_state(T) of
        {state, Port, _} -> Port;
        undefined -> undefined
    end.
