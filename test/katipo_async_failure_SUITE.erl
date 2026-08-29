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
-export([timeout_aborts_transfer_in_port/1]).
-export([late_admission_refused_after_caller_timeout/1]).
-export([admission_spills_over_restarting_worker/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

all() ->
    [admission_error_when_port_closes_before_dispatch,
     admission_error_when_worker_restarting,
     no_message_after_cancel_against_dead_port,
     timeout_aborts_transfer_in_port,
     late_admission_refused_after_caller_timeout,
     admission_spills_over_restarting_worker].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    Config.

end_per_suite(Config) ->
    Config.

init_per_testcase(TestCase, Config) ->
    Pool = TestCase,
    {ok, _} = katipo_pool:start(Pool, pool_size(TestCase), []),
    [{pool, Pool} | Config].

pool_size(admission_spills_over_restarting_worker) -> 2;
pool_size(_) -> 1.

end_per_testcase(_TestCase, Config) ->
    ok = katipo_pool:stop(?config(pool, Config)).

%% A request to a TEST-NET address that will never connect, so an accepted
%% request stays in the worker's Reqs map for the duration of the test.
blackhole_req() ->
    #{url => <<"http://192.0.2.1/">>,
      method => get,
      connecttimeout_ms => 30000,
      timeout_ms => 30000}.

%% Katipo.tla: EventualOutcome violated via SendAsync -> PortDies ->
%% WorkerRecvReq-badarg. The admission call is already queued when the port
%% dies; the worker crashes in send_to_port before registering the request.
%% The call monitor must convert that into {error, worker_died} -- before
%% the fix the request was cast fire-and-forget and simply vanished.
admission_error_when_port_closes_before_dispatch(Config) ->
    WorkerPid = worker_pid(?config(pool, Config)),
    Port = worker_port(WorkerPid),

    %% Freeze the worker so the admission call queues unprocessed, then
    %% close its port. The 'EXIT' message lands behind the queued call.
    ok = sys:suspend(WorkerPid),
    Parent = self(),
    _Caller = spawn_link(
                fun() ->
                        Res = katipo:async_req(?config(pool, Config),
                                               blackhole_req()),
                        Parent ! {async_result, Res}
                end),
    ok = wait_until(fun() -> queue_len(WorkerPid) >= 1 end, 50),
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
    Pool = ?config(pool, Config),
    [WorkerName] = wpool:get_workers(Pool),
    WorkerPid = worker_pid(Pool),

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

%% KatipoSpill.tla: NoSpuriousFailure violated with the earlier routing --
%% a restarting worker on the first random pick returned worker_died while
%% a free worker sat untouched, although the same noproc met during
%% spillover was "keep going". A noproc means nothing was sent, so it is
%% safe to offer the request to the rest of the pool. Pool of 2, one worker
%% held mid-restart: every admission must land on the live one. Repeated
%% so the random first pick hits the dead name with overwhelming odds.
admission_spills_over_restarting_worker(Config) ->
    Pool = ?config(pool, Config),
    [W1, _W2] = wpool:get_workers(Pool),
    WorkerPid = registered_pid(W1),
    {dictionary, Dict} = process_info(WorkerPid, dictionary),
    [Sup | _] = proplists:get_value('$ancestors', Dict),
    ok = sys:suspend(Sup),
    MRef = monitor(process, WorkerPid),
    exit(WorkerPid, kill),
    receive {'DOWN', MRef, process, WorkerPid, killed} -> ok
    after 1000 -> ct:fail(worker_not_killed)
    end,
    undefined = whereis(W1),

    Results = try
                  [katipo:async_req(Pool, blackhole_req()) || _ <- lists:seq(1, 20)]
              after
                  ok = sys:resume(Sup)
              end,
    [?assertMatch({ok, Ref} when is_reference(Ref), R) || R <- Results],
    [katipo:cancel(Pool, Ref) || {ok, Ref} <- Results],
    ok.

%% Katipo.tla: NoCancelPollution violated via SendAsync -> WorkerRecvReq ->
%% PortDies -> WorkerRecvCancel-badarg. A cancel processed against a dead
%% port used to crash the worker via port_command before maps:remove, so
%% terminate/2 delivered worker_died to the caller who cancelled. Fixed
%% cancel_async removes the request first and treats the port write as
%% best-effort: the cancelled caller must hear nothing.
no_message_after_cancel_against_dead_port(Config) ->
    Pool = ?config(pool, Config),
    WorkerPid = worker_pid(Pool),

    %% {ok, Ref} means the admission call completed, i.e. the request is
    %% registered in the worker's Reqs map -- no polling needed.
    {ok, Ref} = katipo:async_req(Pool, blackhole_req()),
    Port = worker_port(WorkerPid),

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

%% When the Erlang-side request timer (the backstop behind curl's own
%% timeouts) fires, the worker must deliver operation_timedout AND abort the
%% transfer in the C port -- otherwise the transfer keeps holding a
%% connection and a multi slot until curl notices. Verified at the protocol
%% level: swap the worker's port for a loopback (cat) owned by this process,
%% fire the request timer, and observe the {Pid, Ref, cancel} tuple the
%% worker writes.
timeout_aborts_transfer_in_port(Config) ->
    Pool = ?config(pool, Config),
    WorkerPid = worker_pid(Pool),

    %% Long curl-side timeouts: the C port stays silent for the whole test,
    %% so the only timeout that can fire is the one we send by hand.
    {ok, Ref} = katipo:async_req(Pool, blackhole_req()),
    RealPort = worker_port(WorkerPid),
    [{From, {Tref, _Kind}}] = maps:to_list(worker_reqs(WorkerPid)),

    FakePort = open_port({spawn, "/bin/cat"}, [{packet, 4}, binary]),
    ok = swap_port(WorkerPid, FakePort),

    %% Fire the request timer: this is exactly the message
    %% erlang:start_timer/3 would deliver.
    WorkerPid ! {timeout, Tref, {req_timeout, From}},

    receive
        {katipo_error, Ref, Error} ->
            ?assertMatch(#{code := operation_timedout}, Error)
    after 2000 ->
            ct:fail(timeout_not_delivered)
    end,
    {Pid, InternalRef} = From,
    receive
        {FakePort, {data, Bin}} ->
            ?assertEqual({Pid, InternalRef, cancel}, binary_to_term(Bin))
    after 1000 ->
            ct:fail(no_abort_written_to_port)
    end,

    %% Put the real port back so pool teardown closes it normally.
    ok = swap_port(WorkerPid, RealPort),
    true = port_close(FakePort).

%% Two claims about a worker that accepts no messages (here: suspended; in
%% production a C port that stopped draining its pipe and blocked the
%% worker inside port_command), forced in one 5s window. First, the bounded
%% admission call must not block the caller forever: it gives up and
%% reports admission_timeout. Second -- KatipoAdmit.tla, mechanism 1 (late
%% admit) -- the admission call is still queued when that bounded wait
%% elapses, and before the deadline fix the resumed worker admitted it
%% anyway: an orphaned request nobody was waiting for ran to resolution and
%% pushed a terminal message at reply_to with a ref the caller never
%% received. The stamped deadline makes the worker refuse instead: nothing
%% registered, nothing ever delivered. (KatipoAdmit_fix_contract.cfg shows
%% the complementary reply race is not closable worker-side; that residue
%% is documented on async_req.) Runs for the full 5s admission bound.
late_admission_refused_after_caller_timeout(Config) ->
    Pool = ?config(pool, Config),
    WorkerPid = worker_pid(Pool),
    ok = sys:suspend(WorkerPid),
    %% The request must be one that RESOLVES quickly once admitted, or the
    %% stray-message check below could never fail: with blackhole_req's 30s
    %% timers, an orphaned request produces nothing inside the 500ms
    %% window, and the check would pass whether or not the fix is present.
    %% A 100ms request timer means an admitted orphan pushes
    %% {katipo_error, Ref, timeout} at reply_to almost immediately.
    Res = try
              katipo:async_req(Pool, short_timeout_req())
          after
              %% The queued admission is processed here, after the caller
              %% gave up. Resume even if the assertions below fail, or
              %% end_per_testcase tears down a frozen gen_server.
              ok = sys:resume(WorkerPid)
          end,
    ?assertMatch({error, #{code := admission_timeout}}, Res),
    ok = wait_until(fun() -> queue_len(WorkerPid) =:= 0 end, 50),
    %% The user-visible half of the contract first: no katipo_* message for
    %% a ref we never received. Checked before the Reqs assertion so that
    %% it, not the internal one, is what a regression trips.
    receive
        {Tag, _Ref, _Payload} = Msg
          when Tag =:= katipo_response; Tag =:= katipo_error ->
            ct:fail({stray_message_after_admission_timeout, Msg})
    after 500 ->
            ok
    end,
    %% And the internal one: refused, not admitted, so no orphan in Reqs.
    ?assertEqual(#{}, worker_reqs(WorkerPid)).

%% Unroutable like blackhole_req, but with a request timer short enough
%% that an admitted request resolves well inside a test's patience.
short_timeout_req() ->
    (blackhole_req())#{connecttimeout_ms => 100, timeout_ms => 100}.

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

%% process_info/2 answers `undefined' for a dead process, so a worker that
%% died while we waited (a killed port takes the worker with it) must name
%% itself rather than surface as a badmatch inside a wait_until fun.
queue_len(Pid) ->
    case process_info(Pid, message_queue_len) of
        {message_queue_len, N} -> N;
        undefined -> ct:fail({worker_died_while_waiting, Pid})
    end.

%% The pid of a size-1 pool's only worker. Tests wanting a specific worker
%% of a larger pool (see pool_size/1) should index wpool:get_workers/1 and
%% use registered_pid/1 directly.
worker_pid(Pool) ->
    [WorkerName] = wpool:get_workers(Pool),
    registered_pid(WorkerName).

registered_pid(Name) ->
    case whereis(Name) of
        Pid when is_pid(Pid) -> Pid;
        Other -> ct:fail({not_a_registered_process, Name, Other})
    end.

%% The worker's C port, found via the public port_info seam: the worker
%% process owns exactly one port.
worker_port(WorkerPid) ->
    [Port] = [P || P <- erlang:ports(),
                   erlang:port_info(P, connected) =:= {connected, WorkerPid}],
    Port.

%% White-box helpers for the protocol test: a request's internal {Pid, Ref}
%% identity and timer, and the port slot itself, have no public seam, so
%% match katipo_worker's #state{port, reqs} at its known position inside
%% wpool_process's wrapper (same idiom as katipo_SUITE's worker_state/1;
%% fails loudly if the wrapper shape changes).
worker_reqs(WorkerPid) ->
    {state, _, _, {state, _Port, Reqs, _MaxInFlight}, _} = sys:get_state(WorkerPid),
    Reqs.

swap_port(WorkerPid, NewPort) ->
    _ = sys:replace_state(
          WorkerPid,
          fun(S = {state, _, _, {state, _, Reqs, MaxInFlight}, _}) ->
                  setelement(4, S, {state, NewPort, Reqs, MaxInFlight})
          end, 1000),
    ok.
