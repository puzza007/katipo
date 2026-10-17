-module(katipo_stress_SUITE).

%% A randomized async workload with faults injected, run mainly for its trace
%% (formal/README.md, "Trace validation"): concurrent callers on a small,
%% capacity-limited pool issue buffered and streaming requests with short
%% request timeouts and random cancels, while a chaos process closes worker
%% ports, kills a worker outright and wedges one past the admission
%% deadline. The test itself checks only what a caller can see -- at most
%% one terminal message per request -- and the trace checker replays every
%% worker's decisions against the admission model.

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1]).
-export([random_async_workload_with_faults/1]).

-define(POOL, katipo_stress_pool).
-define(CALLERS, 24).
-define(OPS, 12).

suite() ->
    [{timetrap, {seconds, 90}}].

all() ->
    [random_async_workload_with_faults].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    ok = katipo_trace:start(),
    {ok, _} = katipo_pool:start(?POOL, 3, [{max_in_flight, 8}]),
    Config.

end_per_suite(Config) ->
    ok = katipo_pool:stop(?POOL),
    ok = katipo_trace:dump(?MODULE),
    Config.

random_async_workload_with_faults(_Config) ->
    Port = start_server(),
    Parent = self(),
    Callers = [spawn_link(fun() ->
                                  rand:seed(exsss, {I, I * 7, I * 13}),
                                  Parent ! {caller_done, self(), caller(Port, ?OPS)}
                          end) || I <- lists:seq(1, ?CALLERS)],
    Chaos = spawn_link(fun() -> chaos(), Parent ! {chaos_done, self()} end),
    Outcomes = lists:append(
                 [receive {caller_done, C, Os} -> Os after 80000 -> ct:fail(caller_hung) end
                  || C <- Callers]),
    receive {chaos_done, Chaos} -> ok after 20000 -> ct:fail(chaos_hung) end,
    Counts = lists:foldl(fun(O, A) -> maps:update_with(O, fun(X) -> X + 1 end, 1, A) end,
                         #{}, Outcomes),
    ct:pal("outcomes: ~p", [Counts]),
    ok.

%% One caller: N requests in sequence, each buffered or streamed, some
%% cancelled part-way. Returns each request's outcome.
caller(_Port, 0) ->
    [];
caller(Port, N) ->
    Chunks = rand:uniform(4),
    Delay = rand:uniform(150) - 1,
    Url = iolist_to_binary(io_lib:format("http://127.0.0.1:~b/~b/~b", [Port, Delay, Chunks])),
    Stream = rand:uniform(2) =:= 1,
    Opts0 = #{url => Url, method => get, timeout_ms => 50 + rand:uniform(700)},
    Opts = case Stream of
               true -> Opts0#{stream => true, stream_window => rand:uniform(2)};
               false -> Opts0
           end,
    Outcome = case katipo:async_req(?POOL, Opts) of
                  {ok, Ref} ->
                      CancelAfter = case rand:uniform(4) of
                                        1 -> rand:uniform(200);
                                        _ -> never
                                    end,
                      collect(Ref, CancelAfter);
                  {error, #{code := Code}} ->
                      Code
              end,
    [Outcome | caller(Port, N - 1)].

%% Drain one request's messages. At most one terminal message may ever
%% arrive; a killed worker (no terminate/2) leaves none, so the wait is
%% capped rather than required to end in a terminal.
collect(Ref, CancelAfter) ->
    Deadline = erlang:monotonic_time(millisecond) + 2500,
    case CancelAfter of
        never -> ok;
        Ms -> erlang:send_after(Ms, self(), {cancel_now, Ref})
    end,
    collect(Ref, Deadline, none).

collect(Ref, Deadline, Terminal) ->
    Wait = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {cancel_now, Ref} ->
            ok = katipo:cancel(?POOL, Ref),
            collect(Ref, Deadline, Terminal);
        {katipo_headers, Ref, _} ->
            collect(Ref, Deadline, Terminal);
        {katipo_chunk, Ref, _} ->
            ok = katipo:update_flow(?POOL, Ref, 1),
            collect(Ref, Deadline, Terminal);
        {Tag, Ref, _} when Tag =:= katipo_response; Tag =:= katipo_error;
                           Tag =:= katipo_done ->
            ?assertEqual(none, Terminal, {second_terminal, Ref, Tag}),
            %% Keep listening briefly for a duplicate.
            collect(Ref, erlang:monotonic_time(millisecond) + 100, Tag)
    after Wait ->
        flush_cancel(Ref),
        case Terminal of
            none -> no_terminal;
            T -> T
        end
    end.

flush_cancel(Ref) ->
    receive {cancel_now, Ref} -> ok after 0 -> ok end.

%% Faults, spaced so callers keep running between them.
chaos() ->
    timer:sleep(800),
    close_port(random_worker()),
    timer:sleep(800),
    exit(random_worker(), kill),
    timer:sleep(800),
    %% Wedge a worker past the admission timeout (?ADMISSION_TIMEOUT is
    %% 5000 ms; the worker refuses from 4750 ms): calls queued early in the
    %% wedge time out and must be refused when the worker resumes, later ones
    %% meet the pre-check either side of their deadline.
    W = random_worker(),
    ok = sys:suspend(W),
    timer:sleep(5400),
    ok = sys:resume(W),
    timer:sleep(800),
    close_port(random_worker()).

random_worker() ->
    Workers = [whereis(N) || N <- wpool:get_workers(?POOL)],
    case [P || P <- Workers, is_pid(P)] of
        [] -> timer:sleep(50), random_worker();
        Live -> lists:nth(rand:uniform(length(Live)), Live)
    end.

close_port(WorkerPid) ->
    case [P || P <- erlang:ports(),
               erlang:port_info(P, connected) =:= {connected, WorkerPid}] of
        [Port] -> catch port_close(Port);
        [] -> ok
    end.

%% HTTP/1.1 server: GET /Delay/Chunks answers with Chunks 16-byte pieces,
%% Delay ms apart, then closes. One process per connection.
start_server() ->
    Parent = self(),
    spawn_link(fun() ->
                       {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {backlog, 128},
                                                     {reuseaddr, true}]),
                       {ok, P} = inet:port(L),
                       Parent ! {server_port, P},
                       accept(L)
               end),
    receive {server_port, P} -> P end.

accept(L) ->
    {ok, S} = gen_tcp:accept(L),
    Pid = spawn(fun() -> receive go -> serve(S) end end),
    ok = gen_tcp:controlling_process(S, Pid),
    Pid ! go,
    accept(L).

serve(S) ->
    try
        {ok, Req} = read_request(S, <<>>),
        [_, Path | _] = binary:split(Req, <<" ">>, [global]),
        [<<>>, D, N] = binary:split(Path, <<"/">>, [global]),
        Delay = binary_to_integer(D),
        Chunks = binary_to_integer(N),
        Piece = binary:copy(<<"x">>, 16),
        ok = gen_tcp:send(S, ["HTTP/1.1 200 OK\r\ncontent-length: ",
                              integer_to_list(16 * Chunks),
                              "\r\nconnection: close\r\n\r\n"]),
        [begin timer:sleep(Delay), ok = gen_tcp:send(S, Piece) end
         || _ <- lists:seq(1, Chunks)]
    catch
        _:_ -> ok
    after
        gen_tcp:close(S)
    end.

read_request(S, Acc) ->
    case binary:match(Acc, <<"\r\n\r\n">>) of
        nomatch ->
            case gen_tcp:recv(S, 0, 10000) of
                {ok, Data} -> read_request(S, <<Acc/binary, Data/binary>>);
                Err -> Err
            end;
        _ ->
            {ok, Acc}
    end.
