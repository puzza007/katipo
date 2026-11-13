-module(katipo_stub).
-moduledoc false.

%% The C port's stand-in in a pool started with {stub, Handler}
%% (katipo_pool): a process the worker writes the same command frames to,
%% and that answers with the same messages, but that calls Handler where
%% the port would run a transfer. Everything above the port -- admission,
%% max_in_flight, timeouts, cancel, retries, streaming, defaults, spans --
%% is the worker's own code, so a stub pool behaves as a real one would.
%% Of what curl itself does, it does what shows in the request a server
%% gets or the response a caller gets: the headers it would not send or
%% would add, max_body_size, and header values made safe.
%%
%% Each transfer is two processes. One, linked to the stub, speaks for the
%% port: it collects the request's body, and gives the response, to the
%% window if it is streamed. The other, linked to the first, only calls
%% Handler, so that a Handler may receive whatever it likes: the flow and
%% body commands of its request are not in its mailbox. Cancelling a
%% transfer kills both.
%%
%% A transfer that ends without answering, as one whose Handler raises,
%% exits or answers what is not a response does, fails its own request
%% with stub_failed and the reason, and no other: a test's mistake in a
%% Handler is not a crashed port.

-export([start_link/1]).
%% Called through the module, so that a stub moves to new code.
-export([loop/1]).

-include("katipo_internal.hrl").
-include_lib("kernel/include/file.hrl").

%% The {Worker, Ref} the worker knows a transfer by.
-type id() :: {pid(), term()}.

-record(stub, {worker :: pid(),
               handler :: katipo:stub(),
               %% Each transfer's processes, the port's and Handler's, and
               %% the transfer of each port's.
               ids = #{} :: #{id() => {pid(), pid()}},
               pids = #{} :: #{pid() => id()}}).
-type stub() :: #stub{}.

-spec start_link(katipo:stub()) -> pid().
start_link(Handler) ->
    Worker = self(),
    spawn_link(fun() ->
                       process_flag(trap_exit, true),
                       loop(#stub{worker = Worker, handler = Handler})
               end).

-spec loop(stub()) -> no_return().
loop(S = #stub{worker = Worker, ids = Ids, pids = Pids}) ->
    receive
        {Worker, {command, Frame}} ->
            ?MODULE:loop(command(Frame, S));
        {'EXIT', Worker, _Reason} ->
            _ = [stop(Id, S) || Id <- maps:keys(Ids)],
            exit(shutdown);
        {'EXIT', Pid, Reason} when is_map_key(Pid, Pids) ->
            Id = map_get(Pid, Pids),
            _ = Reason =:= normal orelse
                fail({self(), Worker}, Id, stub_failed,
                     unicode:characters_to_binary(io_lib:format("~0tP", [Reason, 30]))),
            ?MODULE:loop(stop(Id, S));
        {'EXIT', _Pid, _Reason} ->
            %% A cancelled transfer, forgotten when it was cancelled.
            ?MODULE:loop(S)
    end.

%% End a transfer, if it has not ended. Both its processes are killed, as
%% a Handler that traps exits would outlive anything less.
stop(Id, S = #stub{ids = Ids, pids = Pids}) ->
    case Ids of
        #{Id := {Transfer, Runner}} ->
            exit(Transfer, kill),
            exit(Runner, kill),
            S#stub{ids = maps:remove(Id, Ids), pids = maps:remove(Transfer, Pids)};
        _ ->
            S
    end.

%% The commands katipo_worker writes, as c_src/katipo.c's handle_frame
%% reads them. One for a transfer that has ended is dropped.
command(Frame, S = #stub{worker = Worker, handler = Handler, ids = Ids, pids = Pids}) ->
    case binary_to_term(Frame, [used]) of
        {{Self, Ref, cancel}, _} ->
            stop({Self, Ref}, S);
        {{Self, Ref, flow, N}, _} ->
            relay({Self, Ref}, {flow, N}, S);
        {{Self, Ref, body, eof}, _} ->
            relay({Self, Ref}, {body, eof}, S);
        {{Self, Ref, body, <<>>}, Used} ->
            <<_:Used/binary, Chunk/binary>> = Frame,
            relay({Self, Ref}, {body, Chunk}, S);
        {{Self, Ref, Method, Url, Headers, CookieJar, Body, Opts}, _} ->
            Id = {Self, Ref},
            To = {self(), Worker},
            M = lists:nth(Method + 1, ?METHODS),
            Req = #{method => M, url => Url, headers => headers(M, Headers)},
            Runner = spawn(fun() -> run(Handler, Req) end),
            Transfer = spawn_link(fun() ->
                                          transfer(To, Id, Runner, M, CookieJar, Body, Opts)
                                  end),
            S#stub{ids = Ids#{Id => {Transfer, Runner}}, pids = Pids#{Transfer => Id}}
    end.

relay(Id, Msg, S = #stub{ids = Ids}) ->
    _ = case Ids of
            #{Id := {Transfer, _Runner}} -> Transfer ! Msg;
            _ -> ok
        end,
    S.

%% The headers curl would send for "Name: value" lines: not one whose
%% value is blank, which removes one of curl's own instead, and with the
%% Content-Type curl gives a POST unless one is named.
headers(Method, Lines) ->
    Pairs = [{K, value(V)} || L <- Lines, [K, V] <- [binary:split(L, <<":">>)]],
    Sent = [P || {_, V} = P <- Pairs, not blank(V)],
    Named = lists:any(fun({K, _}) -> katipo_req:header_name(K) =:= <<"content-type">> end, Pairs),
    case Method =:= post andalso not Named of
        true -> Sent ++ [{<<"Content-Type">>, <<"application/x-www-form-urlencoded">>}];
        false -> Sent
    end.

%% katipo_req:header_line/1 puts one space after the colon; the value is
%% otherwise as given.
value(<<" ", V/binary>>) -> V;
value(V) -> V.

blank(V) ->
    << <<C>> || <<C>> <= V, C =/= $\s, C =/= $\t >> =:= <<>>.

%% Handler's process: it waits for the request's body, and answers its
%% transfer with what Handler does. A Handler that raises takes it down,
%% which the runtime logs, and its transfer with it.
run(Handler, Req) ->
    receive
        {Transfer, Body} ->
            Transfer ! {self(), try Handler(Req#{body => Body})
                                catch exit:normal -> exit({stub_exited, normal})
                                end}
    end.

transfer(To, Id, Runner, Method, CookieJar, Body, Opts) ->
    link(Runner),
    case request_body(To, Id, Body) of
        {ok, Bin} ->
            Runner ! {self(), Bin},
            receive
                {Runner, Response} -> respond(To, Id, Method, CookieJar, Opts, Response)
            end;
        {error, Code, Message} ->
            fail(To, Id, Code, Message)
    end.

%% A streamed body is asked for a chunk at a time, as the port does, and
%% held to its declared length. Only a regular file is read, as the port's
%% stat_upload has it: a device or a fifo may never end.
request_body(To, Id, {stream, Length}) ->
    stream_body(To, Id, Length, []);
request_body(_To, _Id, {file, Path}) ->
    maybe
        {ok, #file_info{type = regular}} ?= file:read_file_info(Path),
        {ok, _Bin} ?= file:read_file(Path)
    else
        {ok, #file_info{}} -> couldnt_open(Path, "not a regular file");
        {error, Reason} -> couldnt_open(Path, file:format_error(Reason))
    end;
request_body(_To, _Id, Body) ->
    {ok, iolist_to_binary(Body)}.

couldnt_open(Path, Why) ->
    {error, file_couldnt_read_file, iolist_to_binary(["Couldn't open ", Path, ": ", Why])}.

stream_body(_To, _Id, 0, Acc) ->
    {ok, iolist_to_binary(lists:reverse(Acc))};
stream_body(To, Id, Left, Acc) ->
    send(To, {demand, {Id, []}}),
    receive
        {body, eof} when Left > 0 ->
            {error, read_error, <<"Body ended before its declared length">>};
        {body, eof} ->
            {ok, iolist_to_binary(lists:reverse(Acc))};
        {body, Chunk} when Left >= 0, byte_size(Chunk) > Left ->
            {error, read_error, <<"Body longer than its declared length">>};
        {body, Chunk} when Left >= 0 ->
            stream_body(To, Id, Left - byte_size(Chunk), [Chunk | Acc]);
        {body, Chunk} ->
            stream_body(To, Id, Left, [Chunk | Acc])
    end.

%% The whole body is known, as one with a Content-Length is to the port,
%% which fails one over max_body_size before it gives any of the response
%% (body_too_large in c_src/katipo.c), streamed or not.
respond(To, Id, _Method, _CookieJar, _Opts, {error, Code}) when is_atom(Code) ->
    fail(To, Id, Code, <<>>);
respond(To, Id, _Method, _CookieJar, _Opts, {error, Code, Message})
  when is_atom(Code), is_binary(Message) ->
    fail(To, Id, Code, Message);
respond(To, Id, Method, CookieJar, Opts, Response = #{status := Status})
  when is_integer(Status), Status >= 100, Status =< 599 ->
    {Lines, Chunks} = try {lines(Status, maps:get(headers, Response, [])),
                           chunks(Method, maps:get(body, Response, <<>>))}
                      catch error:_ -> exit({bad_stub_response, Response})
                      end,
    Max = proplists:get_value(?MAX_BODY_SIZE, Opts),
    case {too_large(iolist_size(Chunks), Max), proplists:get_value(?STREAM, Opts)} of
        {true, _} ->
            fail(To, Id, filesize_exceeded,
                 iolist_to_binary(io_lib:format("Response body exceeds max_body_size (~b bytes)",
                                                [Max])));
        {false, ?STREAM_TRUE} ->
            stream(To, Id, {Status, Lines, CookieJar}, Chunks,
                   proplists:get_value(?STREAM_WINDOW, Opts), false);
        {false, _} ->
            send(To, {ok, {Id, {Status, Lines, CookieJar, iolist_to_binary(Chunks), []}}})
    end;
respond(_To, _Id, _Method, _CookieJar, _Opts, Response) ->
    exit({bad_stub_response, Response}).

%% The header lines the port would give: the status line, then each
%% header, with CR, LF and NUL replaced with a space, as the port does.
lines(Status, Headers) ->
    [<<"HTTP/1.1 ", (integer_to_binary(Status))/binary>> | [line(H) || H <- Headers]].

line({K, V}) ->
    binary:replace(iolist_to_binary([K, ": ", V]), [<<"\r">>, <<"\n">>, <<0>>], <<" ">>, [global]).

%% A body's chunks, as a streamed response delivers them: each element of
%% a list of binaries and iolists is one, and any other body is one; an
%% empty one is not, as curl never delivers one. A HEAD's response has no
%% body.
chunks(head, _Body) ->
    [];
chunks(_Method, Body) ->
    Chunks = case chunk_list(Body) of
                 true -> [iolist_to_binary(C) || C <- Body];
                 false -> [iolist_to_binary(Body)]
             end,
    [C || C <- Chunks, C =/= <<>>].

chunk_list([]) -> true;
chunk_list([C | Cs]) when is_binary(C); is_list(C) -> chunk_list(Cs);
chunk_list(_) -> false.

too_large(_Size, -1) -> false;
too_large(Size, Max) -> Size > Max.

%% Chunks are sent while the window has credits, as the port's write_cb
%% does, and wait for update_flow/3 to grant more; -1 is unbounded. The
%% headers go before the first chunk, or the done: Started is whether
%% they have gone.
stream(To, Id, {Status, Lines, CookieJar}, [], _Window, Started) ->
    headers_once(To, Id, Status, Lines, Started),
    send(To, {done, {Id, {Status, CookieJar, []}}});
stream(To, Id, Head, Chunks, 0, Started) ->
    receive
        {flow, N} -> stream(To, Id, Head, Chunks, N, Started)
    end;
stream(To, Id, Head = {Status, Lines, _}, [Chunk | Chunks], Window, Started) ->
    headers_once(To, Id, Status, Lines, Started),
    send(To, {chunk, {Id, Chunk}}),
    stream(To, Id, Head, Chunks, case Window of -1 -> -1; _ -> Window - 1 end, true).

headers_once(To, Id, Status, Lines, false) ->
    send(To, {headers, {Id, {Status, Lines}}});
headers_once(_To, _Id, _Status, _Lines, true) ->
    ok.

fail(To, Id, Code, Message) ->
    send(To, {error, {Id, {Code, Message, []}}}).

%% A port message, as the worker reads one (katipo_worker:decode/1). A
%% transfer's Id names its caller, which for a sync request is not the
%% worker, so the worker is given with the stub.
send({Stub, Worker}, Msg) ->
    Worker ! {Stub, {data, term_to_binary(Msg)}},
    ok.
