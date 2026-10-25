-module(katipo_upload_statem).

%% A PropEr state machine over streamed request bodies: up to three
%% uploads at once, each chunked or of a declared length, driven through
%% the real port and curl against katipo_upload_server. The caller answers
%% demands with chunks of any size, ends with eof, sends past or short of
%% a declared length, sends after eof, cancels, and collects responses, in
%% any interleaving across the uploads. The model is what the caller
%% expects of each: the bytes the server must receive, or the read_error a
%% wrong length must end in. It mirrors the invariants of
%% formal/KatipoUpload.tla on the real stack, where the spec and the Lean
%% proofs see only a model of it.

-include_lib("proper/include/proper.hrl").

-export([prop_uploads/0]).
-export([initial_state/0, command/1, precondition/2, next_state/3,
         postcondition/3]).
-export([start/1, chunk/2, over/2, eof/2, stray/2, cancel/1, finish/1]).

-define(POOL, katipo_prop_pool).
-define(MAX_OPEN, 3).
-define(WAIT, 10000).

%% Per upload: its kind (chunked | {length, N}), the bytes sent, and its
%% state: open, ended (eof taken, or the declared length all sent and
%% curl finishing) or failed (a wrong length, which must end in
%% read_error).
-record(up, {kind, sent = <<>>, state = open}).

prop_uploads() ->
    ?FORALL(Cmds, proper_statem:commands(?MODULE),
            begin
                {History, State, Result} = proper_statem:run_commands(?MODULE, Cmds),
                cleanup(State),
                ?WHENFAIL(io:format("History: ~P~nState: ~P~nResult: ~p~n",
                                    [History, 30, State, 30, Result]),
                          aggregate(proper_statem:command_names(Cmds), Result =:= ok))
            end).

initial_state() -> #{}.

command(Ups) ->
    Open = [{R, U} || R := U <- Ups],
    Wanting = [RU || {_, U} = RU <- Open, wants_chunk(U)],
    Declared = [RU || {_, #up{kind = {length, _}}} = RU <- Wanting],
    frequency(
      [{3, {call, ?MODULE, start, [kind()]}} || map_size(Ups) < ?MAX_OPEN] ++
      [{6, ?LET({R, U}, elements(Wanting), {call, ?MODULE, chunk, [R, chunk_for(U)]})}
       || Wanting =/= []] ++
      [{2, ?LET({R, U}, elements(Declared), {call, ?MODULE, over, [R, over_for(U)]})}
       || Declared =/= []] ++
      [{2, ?LET({R, U}, elements(Open), {call, ?MODULE, eof, [R, awaits_demand(U)]})}
       || Open =/= []] ++
      [{2, ?LET(R, elements([R || {R, _} <- Open]), {call, ?MODULE, stray, [R, binary()]})}
       || Open =/= []] ++
      [{1, ?LET(R, elements([R || {R, _} <- Open]), {call, ?MODULE, cancel, [R]})}
       || Open =/= []] ++
      [{3, ?LET(R, elements([R || {R, _} <- Open]), {call, ?MODULE, finish, [R]})}
       || Open =/= []]).

kind() ->
    frequency([{1, chunked}, {1, {length, frequency([{1, 0}, {4, range(1, 300000)}])}}]).

%% A chunk that fits: empty, small, or bigger than curl's upload buffer.
chunk_for(#up{kind = Kind, sent = Sent}) ->
    Max = case Kind of
              chunked -> 200000;
              {length, N} -> N - byte_size(Sent)
          end,
    ?LET(Len, frequency([{1, 0}, {4, range(1, min(Max, 1000))}, {2, range(0, Max)}]),
         binary:copy(<<"k">>, min(Len, Max))).

%% A chunk past the declared length.
over_for(#up{kind = {length, N}, sent = Sent}) ->
    ?LET(Extra, range(1, 5000), binary:copy(<<"o">>, N - byte_size(Sent) + Extra)).

%% Whether the port will ask for more: an open body whose declared length
%% is not all in.
wants_chunk(#up{state = open, kind = chunked}) -> true;
wants_chunk(#up{state = open, kind = {length, N}, sent = S}) -> byte_size(S) < N;
wants_chunk(_) -> false.

awaits_demand(U) -> wants_chunk(U).

precondition(Ups, {call, _, chunk, [R, Bin]}) ->
    case Ups of
        #{R := U} -> wants_chunk(U) andalso fits(U, Bin);
        _ -> false
    end;
precondition(Ups, {call, _, over, [R, _]}) ->
    case Ups of
        #{R := #up{kind = {length, _}} = U} -> wants_chunk(U);
        _ -> false
    end;
precondition(Ups, {call, _, eof, [R, Await]}) ->
    case Ups of
        #{R := #up{state = open} = U} -> Await =:= awaits_demand(U);
        _ -> false
    end;
precondition(Ups, {call, _, stray, [R, _]}) ->
    case Ups of
        #{R := #up{state = ended}} -> true;
        _ -> false
    end;
precondition(Ups, {call, _, finish, [R]}) ->
    case Ups of
        #{R := #up{state = open} = U} -> not wants_chunk(U);
        #{R := _} -> true;
        _ -> false
    end;
precondition(Ups, {call, _, cancel, [R]}) ->
    is_map_key(R, Ups);
precondition(Ups, {call, _, start, _}) ->
    map_size(Ups) < ?MAX_OPEN.

fits(#up{kind = chunked}, _) -> true;
fits(#up{kind = {length, N}, sent = S}, Bin) -> byte_size(S) + byte_size(Bin) =< N.

next_state(Ups, R, {call, _, start, [Kind]}) ->
    Ups#{R => #up{kind = Kind}};
next_state(Ups, _, {call, _, chunk, [R, Bin]}) ->
    U = #up{sent = S} = maps:get(R, Ups),
    Ups#{R := U#up{sent = <<S/binary, Bin/binary>>}};
next_state(Ups, _, {call, _, over, [R, _]}) ->
    Ups#{R := (maps:get(R, Ups))#up{state = failed}};
next_state(Ups, _, {call, _, eof, [R, _]}) ->
    U = #up{kind = Kind, sent = S} = maps:get(R, Ups),
    State = case Kind of
                {length, N} when byte_size(S) < N -> failed;
                _ -> ended
            end,
    Ups#{R := U#up{state = State}};
next_state(Ups, _, {call, _, stray, _}) ->
    Ups;
next_state(Ups, _, {call, _, Op, [R]}) when Op =:= finish; Op =:= cancel ->
    maps:remove(R, Ups).

postcondition(_Ups, {call, _, start, _}, {Ref, _Path}) ->
    is_reference(Ref);
postcondition(_Ups, {call, _, Op, _}, Result) when Op =:= chunk; Op =:= over ->
    Result =:= ok;
postcondition(_Ups, {call, _, eof, _}, Result) ->
    Result =:= ok;
postcondition(_Ups, {call, _, stray, _}, Result) ->
    Result =:= ok;
postcondition(_Ups, {call, _, cancel, _}, Result) ->
    Result =:= ok;
postcondition(Ups, {call, _, finish, [R]}, Result) ->
    case maps:get(R, Ups) of
        #up{state = failed} ->
            case Result of
                {{error, read_error}, _} -> true;
                _ -> false
            end;
        #up{sent = Sent} ->
            Result =:= {{ok, 200}, Sent}
    end.

%% ---------------------------------------------------------------------
%% Commands, run in the caller, which gets every upload's messages.

start(Kind) ->
    Path = integer_to_binary(erlang:unique_integer([positive])),
    Body = case Kind of
               chunked -> {stream, #{}};
               {length, N} -> {stream, #{length => N}}
           end,
    {ok, Ref} = katipo:async_put(?POOL, <<(url())/binary, Path/binary>>,
                                 #{body => Body,
                                   http_version => curl_http_version_1_1}),
    {Ref, <<"/", Path/binary>>}.

%% Answer the next demand with Bin.
chunk({Ref, _}, Bin) ->
    answer(Ref, Bin).

over({Ref, _}, Bin) ->
    answer(Ref, Bin).

%% eof, in answer to a demand when one is coming.
eof({Ref, _}, true) ->
    answer(Ref, eof);
eof({Ref, _}, false) ->
    katipo:send_body(?POOL, Ref, eof).

%% A chunk after eof, sent without waiting: the port must ignore it.
stray({Ref, _}, Bin) ->
    katipo:send_body(?POOL, Ref, Bin).

%% A cancel may cross the upload's terminal message, as cancel/2 says, so
%% whatever was already on its way is flushed; stream_body_cancel in
%% katipo_SUITE checks that nothing comes after.
cancel({Ref, _}) ->
    ok = katipo:cancel(?POOL, Ref),
    timer:sleep(20),
    flush(Ref).

%% The terminal message, and for a success what the server received.
finish({Ref, Path}) ->
    receive
        {katipo_response, Ref, #{status := Status}} ->
            receive
                {upload_request, _, Path, Body} -> {{ok, Status}, Body}
            after ?WAIT -> {{ok, Status}, no_server_report}
            end;
        {katipo_error, Ref, #{code := Code}} ->
            {{error, Code}, none};
        {katipo_body_demand, Ref} ->
            {unexpected_demand, none}
    after ?WAIT ->
            {timeout, none}
    end.

answer(Ref, What) ->
    receive
        {katipo_body_demand, Ref} -> katipo:send_body(?POOL, Ref, What);
        {katipo_error, Ref, Error} -> {error_before_demand, Error};
        {katipo_response, Ref, _} -> response_before_demand
    after ?WAIT ->
            no_demand
    end.

flush(Ref) ->
    receive
        {katipo_body_demand, Ref} -> flush(Ref);
        {katipo_response, Ref, _} -> flush(Ref);
        {katipo_error, Ref, _} -> flush(Ref)
    after 0 -> ok
    end.

cleanup(Ups) ->
    [katipo:cancel(?POOL, Ref) || {Ref, _} <- maps:keys(Ups), is_reference(Ref)],
    drain().

drain() ->
    receive
        {katipo_body_demand, _} -> drain();
        {katipo_response, _, _} -> drain();
        {katipo_error, _, _} -> drain();
        {upload_request, _, _, _} -> drain();
        {upload_body, _, _} -> drain();
        {upload_head, _, _} -> drain();
        {upload_closed, _, _} -> drain()
    after 100 -> ok
    end.

url() ->
    katipo_upload_server:url(persistent_term:get({?MODULE, port})).
