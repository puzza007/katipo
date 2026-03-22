-module(katipo_stream_body_statem).

-behaviour(proper_statem).

-include_lib("proper/include/proper.hrl").
-include_lib("common_test/include/ct.hrl").

-export([prop_streaming/2]).

-export([initial_state/0,
         command/1,
         precondition/2,
         postcondition/3,
         next_state/3]).

-export([start_upload/0,
         start_get/0,
         send_chunk/2,
         finish_upload/1,
         await_response/1,
         await_uploading/1]).

%% Generator for HTTP-safe chunk data (ASCII alphanumeric)
chunk_data() ->
    ?LET(Chars, non_empty(list(oneof([range($a, $z), range($0, $9)]))),
         list_to_binary(Chars)).

-define(POOL, katipo_test_pool).

-record(handle_info, {
    kind :: streaming | get,
    status :: uploading | finished | timed_out,
    chunks = [] :: [binary()]  %% in send order (streaming only)
}).

-record(state, {
    handles = #{} :: #{term() => #handle_info{}}
}).

%% --- Property ---

prop_streaming(BaseUrl, Opts) ->
    put(stream_base_url, BaseUrl),
    put(stream_opts, Opts),
    ?FORALL(Cmds, commands(?MODULE),
        begin
            {_H, S, Res} = run_commands(?MODULE, Cmds),
            cleanup(S),
            ?WHENFAIL(
                ct:pal("Commands: ~p~nFinal state: ~p~nResult: ~p",
                       [Cmds, S, Res]),
                aggregate(command_names(Cmds), Res =:= ok))
        end).

%% --- State machine callbacks ---

initial_state() ->
    #state{}.

command(#state{handles = Handles}) ->
    Uploading = [V || {V, #handle_info{kind = streaming, status = uploading}}
                          <- maps:to_list(Handles)],
    Finished  = [V || {V, #handle_info{status = finished}}
                          <- maps:to_list(Handles)],
    TimedOut  = [V || {V, #handle_info{kind = streaming, status = timed_out}}
                          <- maps:to_list(Handles)],
    frequency(
        [{4, {call, ?MODULE, start_upload, []}}] ++
        [{3, {call, ?MODULE, start_get, []}}] ++
        [{3, {call, ?MODULE, send_chunk,
              [elements(Uploading), chunk_data()]}}
         || Uploading =/= []] ++
        [{3, {call, ?MODULE, finish_upload,
              [elements(Uploading)]}}
         || Uploading =/= []] ++
        [{4, {call, ?MODULE, await_response,
              [elements(Finished)]}}
         || Finished =/= []] ++
        %% Timeout: await before body is finished
        [{2, {call, ?MODULE, await_uploading,
              [elements(Uploading)]}}
         || Uploading =/= []] ++
        %% Recovery: finish a timed-out upload so it becomes awaitable
        [{2, {call, ?MODULE, finish_upload,
              [elements(TimedOut)]}}
         || TimedOut =/= []] ++
        %% Edge cases: double finish, send after finish
        [{1, {call, ?MODULE, finish_upload,
              [elements(Finished)]}}
         || Finished =/= []] ++
        [{1, {call, ?MODULE, send_chunk,
              [elements(Finished), chunk_data()]}}
         || Finished =/= []]
    ).

precondition(_, _) ->
    true.

next_state(S, V, {call, _, start_upload, []}) ->
    Info = #handle_info{kind = streaming, status = uploading},
    S#state{handles = maps:put(V, Info, S#state.handles)};
next_state(S, V, {call, _, start_get, []}) ->
    Info = #handle_info{kind = get, status = finished},
    S#state{handles = maps:put(V, Info, S#state.handles)};
next_state(S, _V, {call, _, finish_upload, [Handle]}) ->
    case maps:get(Handle, S#state.handles, undefined) of
        #handle_info{status = Status} = Info
          when Status =:= uploading; Status =:= timed_out ->
            S#state{handles = maps:put(Handle,
                        Info#handle_info{status = finished},
                        S#state.handles)};
        _ ->
            S
    end;
next_state(S, _V, {call, _, await_response, [Handle]}) ->
    S#state{handles = maps:remove(Handle, S#state.handles)};
next_state(S, _V, {call, _, await_uploading, [Handle]}) ->
    case maps:get(Handle, S#state.handles, undefined) of
        #handle_info{} = Info ->
            S#state{handles = maps:put(Handle,
                        Info#handle_info{status = timed_out},
                        S#state.handles)};
        _ ->
            S
    end;
next_state(S, _V, {call, _, send_chunk, [Handle, Data]}) ->
    case maps:get(Handle, S#state.handles, undefined) of
        #handle_info{status = uploading, chunks = Chunks} = Info ->
            S#state{handles = maps:put(Handle,
                        Info#handle_info{chunks = Chunks ++ [Data]},
                        S#state.handles)};
        _ ->
            S
    end.

%% --- Postconditions ---
%%
%% PropEr postconditions must return true | false (not crash), so we
%% use ct:pal for diagnostics rather than ct assertion macros.

postcondition(_S, {call, _, start_upload, []}, {ok, _}) -> true;
postcondition(_S, {call, _, start_get, []}, {ok, _}) -> true;
postcondition(_S, {call, _, send_chunk, _}, ok) -> true;
postcondition(_S, {call, _, finish_upload, _}, ok) -> true;

postcondition(_S, {call, _, await_uploading, _}, {error, #{code := await_timeout}}) ->
    true;

postcondition(S, {call, _, await_response, [Handle]},
              {ok, #{status := 200, metrics := Metrics} = Response}) ->
    HasMetrics = is_list(Metrics) andalso length(Metrics) > 0,
    case maps:get(Handle, S#state.handles, undefined) of
        #handle_info{kind = get} ->
            HasMetrics;
        #handle_info{kind = streaming, chunks = Chunks} ->
            Expected = iolist_to_binary(Chunks),
            Body = maps:get(body, Response),
            Json = jsx:decode(Body),
            Actual = maps:get(<<"data">>, Json, <<>>),
            case {HasMetrics, Actual =:= Expected} of
                {true, true} ->
                    true;
                _ ->
                    ct:pal("body mismatch or missing metrics~n"
                           "  expected body: ~p~n"
                           "  actual body:   ~p~n"
                           "  has_metrics:   ~p",
                           [Expected, Actual, HasMetrics]),
                    false
            end;
        undefined ->
            ct:pal("handle not found in model state"),
            false
    end;

%% Catch-all failure clause with diagnostics
postcondition(_S, {call, _, Fn, _}, Other) ->
    ct:pal("~p returned unexpected: ~p", [Fn, Other]),
    false.

%% --- Command implementations ---

start_upload() ->
    BaseUrl = get(stream_base_url),
    Opts = get(stream_opts),
    katipo:async_post(?POOL, <<BaseUrl/binary, "/post">>,
        Opts#{headers => [{<<"Content-Type">>, <<"text/plain">>}],
              stream_body => true}).

start_get() ->
    BaseUrl = get(stream_base_url),
    Opts = get(stream_opts),
    katipo:async_get(?POOL, <<BaseUrl/binary, "/get">>, Opts).

send_chunk({ok, Handle}, Data) ->
    katipo:send_body(Handle, Data).

finish_upload({ok, Handle}) ->
    katipo:finish_body(Handle).

await_response({ok, Handle}) ->
    katipo:await(Handle, 10000).

await_uploading({ok, Handle}) ->
    katipo:await(Handle, 1).

%% --- Cleanup ---

cleanup(#state{handles = Handles}) ->
    maps:foreach(fun(HandleResult, #handle_info{kind = Kind, status = Status}) ->
        case HandleResult of
            {ok, Handle} ->
                case {Kind, Status} of
                    {streaming, uploading} ->
                        katipo:finish_body(Handle),
                        katipo:await(Handle, 5000);
                    {streaming, finished} ->
                        katipo:await(Handle, 5000);
                    {streaming, timed_out} ->
                        katipo:finish_body(Handle),
                        katipo:await(Handle, 5000);
                    {get, finished} ->
                        katipo:await(Handle, 5000);
                    _ ->
                        ok
                end;
            _ ->
                ok
        end
    end, Handles).

