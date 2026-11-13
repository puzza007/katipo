-module(katipo_stub_statem).

%% A PropEr state machine over a stub pool of one worker, with
%% max_in_flight 3: requests of every kind in flight at once -- sync,
%% async, streamed with a window, streamed uploads chunked or of a declared
%% length, retried -- each driven step by step: its Handler answers with a
%% response or an error, raises, exits, or answers what is not a
%% response; the caller grants credits, sends upload chunks and eof, and
%% cancels; a request times out. The model is what each caller must get,
%% message by message, and after every step:
%%
%%   * every admitted request gets exactly the messages the model says, in
%%     order, and nothing else: one terminal one, none after a cancel or
%%     the terminal, no chunk past the window's credits, one demand at a
%%     time, a request past max_in_flight refused with overload;
%%   * a Handler that crashes fails its own request with stub_failed, and
%%     no other;
%%   * a cancelled or timed-out request's Handler is killed;
%%   * the worker holds exactly the requests the model has in flight, and
%%     the stub exactly their transfers: nothing leaks.
%%
%% Each command waits for the messages the model says it brings, however
%% long they take, and only then a moment more for any it does not: the
%% model's state is kept in step as the commands run (observe/1), so no
%% message is taken for the next command's by coming late.

-include_lib("proper/include/proper.hrl").

-export([prop_requests/0]).
-export([initial_state/0, command/1, precondition/2, next_state/3, postcondition/3]).
-export([start/2, answer/2, grant/2, send/2, eof/1, cancel/1, expire/1]).

-define(POOL, katipo_stub_statem).
-define(MAX, 3).
-define(QUIET, 15).
-define(WAIT, 5000).
-define(RETRIES, 2).

%% A request in flight: its kind, and its stage: waiting on its Handler,
%% streaming the response with Chunks left and Credits, or uploading,
%% Sent bytes so far.
-record(r, {kind, stage = handler, retries = 0}).

prop_requests() ->
    ?FORALL(Cmds, proper_statem:commands(?MODULE),
            begin
                setup(),
                {History, State, Result} = proper_statem:run_commands(?MODULE, Cmds),
                teardown(),
                ?WHENFAIL(io:format("History: ~P~nState: ~P~nResult: ~P~n",
                                    [History, 40, State, 40, Result, 40]),
                          aggregate(proper_statem:command_names(Cmds), Result =:= ok))
            end).

setup() ->
    Self = self(),
    _ = katipo_pool:stop(?POOL),
    {ok, _} = katipo_pool:start(?POOL, 1, [{max_in_flight, ?MAX}, {stub, handler(Self)}]),
    [erase(K) || K = {?MODULE, _} <- get_keys()],
    put({?MODULE, model}, initial_state()),
    flush().

%% A sync caller still waiting would answer into the next run.
teardown() ->
    [begin unlink(Pid), exit(Pid, kill) end || {{?MODULE, {sync, _}}, Pid} <- get()],
    ok = katipo_pool:stop(?POOL),
    flush().

flush() ->
    receive _ -> flush() after 0 -> ok end.

%% Each request names itself in an x-id header; its Handler tells the test
%% it was called, then does as the test says.
handler(Test) ->
    fun(#{headers := Headers}) ->
            Id = binary_to_integer(proplists:get_value(<<"x-id">>, Headers)),
            Test ! {handler, Id, self()},
            receive
                {answer, crash} -> error(crash);
                {answer, exit} -> exit(normal);
                {answer, bad} -> #{status => 700};
                {answer, Answer} -> Answer
            end
    end.

%% =====================================================================
%% Model
%% =====================================================================

initial_state() ->
    #{next => 1, reqs => #{}}.

command(#{next := Id, reqs := Reqs}) ->
    In = maps:to_list(Reqs),
    At = fun(Stage) -> [I || {I, #r{stage = S}} <- In, stage(S) =:= Stage] end,
    Handling = At(handler),
    Streaming = At(streaming),
    Uploading = At(uploading),
    Async = [I || {I, #r{kind = K}} <- In, K =/= sync],
    %% Mostly room for another request; at the limit, only now and then
    %% one to be refused.
    Room = case map_size(Reqs) < ?MAX of true -> 1; false -> 0 end,
    frequency(
      [{1 + 4 * Room, {call, ?MODULE, start, [Id, kind()]}},
       {Room, {call, ?MODULE, expire, [Id]}}] ++
      [{6, ?LET(I, elements(Handling), {call, ?MODULE, answer, [I, handler_answer(Reqs, I)]})}
       || Handling =/= []] ++
      [{4, {call, ?MODULE, grant, [elements(Streaming), range(1, 3)]}} || Streaming =/= []] ++
      [{5, {call, ?MODULE, send, [elements(Uploading), chunk()]}} || Uploading =/= []] ++
      [{2, {call, ?MODULE, eof, [elements(Uploading)]}} || Uploading =/= []] ++
      [{2, {call, ?MODULE, cancel, [elements(Async)]}} || Async =/= []]).

stage({S, _}) -> S;
stage({S, _, _}) -> S;
stage(S) -> S.

kind() ->
    frequency([{2, exactly(buffered)}, {2, exactly(sync)},
               {3, {stream, range(1, 3)}},
               {2, {upload, oneof([exactly(chunked), range(0, 12)])}},
               {1, exactly(retry)}]).

%% Mostly responses; a retried request mostly the status it retries.
handler_answer(Reqs, I) ->
    Response = ?LET({Status, Chunks}, {elements([200, 404, 500]), list(chunk())},
                    #{status => Status, body => Chunks}),
    Retry = case maps:get(I, Reqs) of
                #r{kind = retry} -> [{4, exactly(#{status => 503})}];
                _ -> []
            end,
    frequency(Retry ++
              [{8, Response},
               {1, elements([crash, exit, bad])},
               {1, {error, elements([couldnt_connect, recv_error, ssl_connect_error])}}]).

chunk() ->
    frequency([{1, exactly(<<>>)}, {4, ?LET(N, range(1, 6), binary(N))}]).

precondition(#{reqs := Reqs}, {call, _, answer, [I, _Answer]}) ->
    in_stage(Reqs, I, handler);
precondition(#{reqs := Reqs}, {call, _, grant, [I, _]}) ->
    in_stage(Reqs, I, streaming);
precondition(#{reqs := Reqs}, {call, _, Op, [I | _]}) when Op =:= send; Op =:= eof ->
    in_stage(Reqs, I, uploading);
precondition(#{reqs := Reqs}, {call, _, cancel, [I]}) ->
    case Reqs of #{I := #r{kind = K}} -> K =/= sync; _ -> false end;
precondition(#{next := Next}, {call, _, Op, [Id | _]}) when Op =:= start; Op =:= expire ->
    Id =:= Next.

in_stage(Reqs, I, Stage) ->
    case Reqs of #{I := #r{stage = S}} -> stage(S) =:= Stage; _ -> false end.

next_state(S, _Res, Call) ->
    {State, _Expected} = step(S, Call),
    State.

%% Messages are compared request by request: each request's in order.
postcondition(S, Call, {Observed, Invariant}) ->
    {Next, Expected} = step(S, Call),
    Live = map_size(maps:get(reqs, Next)),
    by_request(Observed) =:= by_request(Expected) andalso Invariant =:= {Live, Live}.

by_request(Msgs) ->
    maps:groups_from_list(fun(M) -> element(1, M) end, Msgs).

%% The state after Call, and the messages it must bring, each {Id, Msg}.
step(S = #{next := Id, reqs := Reqs}, {call, _, start, [Id, Kind]}) ->
    case map_size(Reqs) >= ?MAX of
        true ->
            {S#{next := Id + 1}, [{Id, overload}]};
        false ->
            %% A declared length of 0 is all sent at once.
            Stage = case Kind of
                        {upload, 0} -> handler;
                        {upload, _} -> {uploading, 0};
                        _ -> handler
                    end,
            Msg = case Stage of handler -> handler; _ -> demand end,
            {S#{next := Id + 1, reqs := Reqs#{Id => #r{kind = Kind, stage = Stage}}},
             [{Id, Msg}]}
    end;
step(S = #{next := Id, reqs := Reqs}, {call, _, expire, [Id]}) ->
    case map_size(Reqs) >= ?MAX of
        true -> {S#{next := Id + 1}, [{Id, overload}]};
        false -> {S#{next := Id + 1}, [{Id, handler}, {Id, error, operation_timedout}]}
    end;
step(S = #{reqs := Reqs}, {call, _, answer, [I, Answer]})
  when Answer =:= crash; Answer =:= exit; Answer =:= bad ->
    resolve(S, I, maps:get(I, Reqs), {error, stub_failed});
step(S = #{reqs := Reqs}, {call, _, answer, [I, #{status := 503}]}) ->
    case maps:get(I, Reqs) of
        R = #r{kind = retry, retries = N} when N < ?RETRIES ->
            {S#{reqs := Reqs#{I := R#r{retries = N + 1}}}, [{I, handler}]};
        R ->
            resolve(S, I, R, #{status => 503, body => []})
    end;
step(S = #{reqs := Reqs}, {call, _, answer, [I, Answer]}) ->
    resolve(S, I, maps:get(I, Reqs), Answer);
step(S = #{reqs := Reqs}, {call, _, grant, [I, N]}) ->
    #r{stage = {streaming, Chunks, Credits}} = R = maps:get(I, Reqs),
    stream(S, I, R, Chunks, Credits + N, []);
step(S = #{reqs := Reqs}, {call, _, send, [I, Chunk]}) ->
    R = #r{kind = {upload, Length}, stage = {uploading, Sent}} = maps:get(I, Reqs),
    Now = Sent + byte_size(Chunk),
    if
        is_integer(Length), Now > Length ->
            {S#{reqs := maps:remove(I, Reqs)}, [{I, error, read_error}]};
        Now =:= Length ->
            {S#{reqs := Reqs#{I := R#r{stage = handler}}}, [{I, handler}]};
        true ->
            {S#{reqs := Reqs#{I := R#r{stage = {uploading, Now}}}}, [{I, demand}]}
    end;
step(S = #{reqs := Reqs}, {call, _, eof, [I]}) ->
    R = #r{kind = {upload, Length}, stage = {uploading, Sent}} = maps:get(I, Reqs),
    case is_integer(Length) andalso Sent < Length of
        true -> {S#{reqs := maps:remove(I, Reqs)}, [{I, error, read_error}]};
        false -> {S#{reqs := Reqs#{I := R#r{stage = handler}}}, [{I, handler}]}
    end;
step(S = #{reqs := Reqs}, {call, _, cancel, [I]}) ->
    {S#{reqs := maps:remove(I, Reqs)}, []}.

%% A Handler's answer, as its request's caller gets it.
resolve(S = #{reqs := Reqs}, I, #r{kind = sync}, Answer) ->
    {S#{reqs := maps:remove(I, Reqs)}, [{I, {sync, sync_result(Answer)}}]};
resolve(S, I, R = #r{kind = {stream, Window}}, #{status := Status, body := Body}) ->
    stream(S, I, R#r{stage = {streaming, [C || C <- Body, C =/= <<>>], 0}},
           [C || C <- Body, C =/= <<>>], Window, [{I, headers, Status}]);
resolve(S = #{reqs := Reqs}, I, _R, #{status := Status, body := Body}) ->
    {S#{reqs := maps:remove(I, Reqs)}, [{I, response, Status, iolist_to_binary(Body)}]};
resolve(S = #{reqs := Reqs}, I, _R, {error, Code}) ->
    {S#{reqs := maps:remove(I, Reqs)}, [{I, error, Code}]}.

sync_result(#{status := Status, body := Body}) -> {ok, Status, iolist_to_binary(Body)};
sync_result({error, Code}) -> {error, Code}.

%% Chunks go while there are credits; the last is followed by done.
stream(S = #{reqs := Reqs}, I, _R, [], _Credits, Acc) ->
    {S#{reqs := maps:remove(I, Reqs)}, Acc ++ [{I, done}]};
stream(S = #{reqs := Reqs}, I, R, Chunks, 0, Acc) ->
    {S#{reqs := Reqs#{I := R#r{stage = {streaming, Chunks, 0}}}}, Acc};
stream(S, I, R, [C | Chunks], Credits, Acc) ->
    stream(S, I, R, Chunks, Credits - 1, Acc ++ [{I, chunk, C}]).

%% =====================================================================
%% Commands: each acts, then reports every message that came of it, and
%% how many requests the worker and the stub hold.
%% =====================================================================

-define(OBSERVE(Args), observe({call, ?MODULE, ?FUNCTION_NAME, Args})).

start(Id, Kind) ->
    Opts = #{url => <<"http://example.com/">>, timeout_ms => 60000,
             headers => [{<<"x-id">>, integer_to_binary(Id)}]},
    case Kind of
        sync ->
            Test = self(),
            put({?MODULE, {sync, Id}},
                spawn_link(fun() -> Test ! {sync_done, Id, katipo:req(?POOL, Opts)} end));
        _ ->
            Async = case Kind of
                        buffered -> Opts;
                        retry -> Opts#{retry => #{base_delay_ms => 0, max_retries => ?RETRIES,
                                                  statuses => [503], errors => []}};
                        {stream, W} -> Opts#{stream => true, stream_window => W};
                        {upload, chunked} -> Opts#{method => put, body => {stream, #{}}};
                        {upload, N} -> Opts#{method => put, body => {stream, #{length => N}}}
                    end,
            case katipo:async_req(?POOL, Async) of
                {ok, Ref} -> put({?MODULE, Ref}, Id), put({?MODULE, {ref, Id}}, Ref);
                {error, #{code := overload}} -> self() ! {overload, Id}
            end
    end,
    ?OBSERVE([Id, Kind]).

expire(Id) ->
    Opts = #{url => <<"http://example.com/">>, timeout_ms => 100,
             headers => [{<<"x-id">>, integer_to_binary(Id)}]},
    case katipo:async_req(?POOL, Opts) of
        {ok, Ref} -> put({?MODULE, Ref}, Id);
        {error, #{code := overload}} -> self() ! {overload, Id}
    end,
    {Observed, Invariant} = ?OBSERVE([Id]),
    {Observed, handler_gone(Id, Invariant)}.

answer(I, Answer) ->
    get({?MODULE, {handler, I}}) ! {answer, Answer},
    ?OBSERVE([I, Answer]).

grant(I, N) ->
    ok = katipo:update_flow(?POOL, get({?MODULE, {ref, I}}), N),
    ?OBSERVE([I, N]).

send(I, Chunk) ->
    ok = katipo:send_body(?POOL, get({?MODULE, {ref, I}}), Chunk),
    ?OBSERVE([I, Chunk]).

eof(I) ->
    ok = katipo:send_body(?POOL, get({?MODULE, {ref, I}}), eof),
    ?OBSERVE([I]).

cancel(I) ->
    ok = katipo:cancel(?POOL, get({?MODULE, {ref, I}})),
    {Observed, Invariant} = ?OBSERVE([I]),
    {Observed, handler_gone(I, Invariant)}.

%% A cancelled or timed-out request's Handler, if it was called, is
%% killed, a moment after.
handler_gone(I, Invariant) ->
    case get({?MODULE, {handler, I}}) of
        undefined ->
            Invariant;
        Pid ->
            case katipo_test_util:until(fun() -> not is_process_alive(Pid) end) of
                ok -> Invariant;
                timeout -> {handler_alive, I}
            end
    end.

%% The messages Call brings, in order: as many as the model says, each
%% waited for, then any more that come within a quiet spell. Then the
%% requests the worker holds and the transfers its stub does, once they
%% are as many as the model has in flight: a cancel takes a moment to
%% reach the worker, and a transfer's link goes a moment after it ends.
observe(Call) ->
    {Next, Expected} = step(get({?MODULE, model}), Call),
    put({?MODULE, model}, Next),
    Live = map_size(maps:get(reqs, Next)),
    Observed = messages(length(Expected), []),
    _ = katipo_test_util:until(fun() -> held() =:= {Live, Live} end),
    {Observed, held()}.

messages(N, Acc) ->
    receive
        Msg ->
            messages(max(0, N - 1), [observation(Msg) | Acc])
    after case N of 0 -> ?QUIET; _ -> ?WAIT end ->
            lists:reverse(Acc)
    end.

observation({handler, Id, Pid}) ->
    put({?MODULE, {handler, Id}}, Pid),
    {Id, handler};
observation({overload, Id}) ->
    {Id, overload};
observation({sync_done, Id, {ok, #{status := S, body := B}}}) ->
    {Id, {sync, {ok, S, B}}};
observation({sync_done, Id, {error, #{code := overload}}}) ->
    {Id, overload};
observation({sync_done, Id, {error, #{code := Code}}}) ->
    {Id, {sync, {error, Code}}};
observation({katipo_body_demand, Ref}) -> {get({?MODULE, Ref}), demand};
observation({katipo_headers, Ref, #{status := S}}) -> {get({?MODULE, Ref}), headers, S};
observation({katipo_chunk, Ref, C}) -> {get({?MODULE, Ref}), chunk, C};
observation({katipo_done, Ref, _}) -> {get({?MODULE, Ref}), done};
observation({katipo_response, Ref, #{status := S, body := B}}) -> {get({?MODULE, Ref}), response, S, B};
observation({katipo_error, Ref, #{code := Code}}) -> {get({?MODULE, Ref}), error, Code};
observation(Other) -> {unexpected, Other}.

held() ->
    {Stub, Reqs} = katipo_test_util:worker_state(whereis(wpool_pool:worker_name(?POOL, 1))),
    {links, Links} = process_info(Stub, links),
    {map_size(Reqs), length(Links) - 1}.
