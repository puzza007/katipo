-module(katipo_upload_server).

%% Minimal HTTP/1.1 server for upload tests that need to see what curl
%% put on the wire -- framing, headers, exact bytes -- which the local
%% httpbin stack hides behind its proxy. Each connection carries one
%% request. The owner hears {upload_head, Pid, Head} once the request's
%% head is read, then {upload_body, Pid, Body} with the body (de-chunked)
%% or {upload_closed, Pid, Partial} if the peer closed first. Linked to
%% its owner, so a failing test tears it down.
%%
%% With `concurrent', each connection is served by its own process, and a
%% body is also reported as {upload_request, Pid, Path, Body}, so the owner
%% can tell concurrent requests apart. With `echo', the server answers at
%% once with a chunked 200 and echoes the body back as it reads it, a piece
%% at a time with a pause between, so the upload and the response flow,
%% and push back, at the same time; the body needs a Content-Length.

-export([start/1]).
-export([stop/1]).
-export([url/1]).

%% Opts: #{continue => auto | ask,  ask: an Expect: 100-continue waits for
%%                                  the owner's `continue' message
%%         response => iodata(),    the raw response, default 200 "ok"
%%         concurrent => boolean(),
%%         echo => {PieceBytes, PauseMs}}
start(Opts) ->
    Owner = self(),
    Pid = spawn_link(fun() -> listen(Owner, Opts) end),
    receive
        {upload_listening, Pid, Port} -> {ok, Pid, Port}
    after 5000 ->
            error(upload_server_not_listening)
    end.

stop(Pid) ->
    unlink(Pid),
    exit(Pid, kill),
    ok.

url(Port) ->
    <<"http://127.0.0.1:", (integer_to_binary(Port))/binary, "/">>.

listen(Owner, Opts) ->
    %% A small receive buffer, so a server that reads slowly pushes back.
    Buf = [{recbuf, 4096} || is_map_key(echo, Opts)],
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false} | Buf]),
    {ok, Port} = inet:port(Listen),
    Owner ! {upload_listening, self(), Port},
    accept(Listen, {Owner, self()}, Opts).

accept(Listen, Who, Opts) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    case maps:get(concurrent, Opts, false) of
        true ->
            Pid = spawn_link(fun() ->
                                     receive go -> serve(Sock, Who, Opts) end
                             end),
            ok = gen_tcp:controlling_process(Sock, Pid),
            Pid ! go;
        false ->
            serve(Sock, Who, Opts)
    end,
    accept(Listen, Who, Opts).

serve(Sock, {Owner, Server}, #{echo := {Piece, Pause}}) ->
    try
        {Head, Rest} = read_head(Sock, <<>>),
        Owner ! {upload_head, Server, Head},
        {match, [Len]} = re:run(string:lowercase(Head),
                                <<"\r\ncontent-length: *([0-9]+)">>,
                                [{capture, all_but_first, binary}]),
        ok = gen_tcp:send(Sock, <<"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n"
                                  "connection: close\r\n\r\n">>),
        Body = echo(Sock, binary_to_integer(Len), Piece, Pause, Rest, []),
        ok = gen_tcp:send(Sock, <<"0\r\n\r\n">>),
        Owner ! {upload_body, Server, Body}
    catch throw:{closed, Partial} ->
            Owner ! {upload_closed, Server, Partial}
    end,
    gen_tcp:close(Sock);
serve(Sock, {Owner, Server}, Opts) ->
    try
        {Head, Rest} = read_head(Sock, <<>>),
        Owner ! {upload_head, Server, Head},
        Lower = string:lowercase(Head),
        case {maps:get(continue, Opts, auto),
              binary:match(Lower, <<"expect: 100-continue">>)} of
            {ask, {_, _}} ->
                receive continue -> ok end,
                ok = gen_tcp:send(Sock, <<"HTTP/1.1 100 Continue\r\n\r\n">>);
            {auto, {_, _}} ->
                ok = gen_tcp:send(Sock, <<"HTTP/1.1 100 Continue\r\n\r\n">>);
            {_, nomatch} ->
                ok
        end,
        Body = read_body(Sock, Lower, Rest),
        Owner ! {upload_body, Server, Body},
        [begin
             [_Method, Path | _] = binary:split(Head, <<" ">>, [global]),
             Owner ! {upload_request, Server, Path, Body}
         end || maps:get(concurrent, Opts, false)],
        ok = gen_tcp:send(Sock, maps:get(response, Opts,
                                         <<"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n"
                                           "connection: close\r\n\r\nok">>))
    catch throw:{closed, Partial} ->
            Owner ! {upload_closed, Server, Partial}
    end,
    gen_tcp:close(Sock).

%% Read the body a piece at a time, pausing between, and send each piece
%% straight back as a response chunk.
echo(_Sock, 0, _Piece, _Pause, _Buf, Acc) ->
    iolist_to_binary(lists:reverse(Acc));
echo(Sock, Left, Piece, Pause, Buf, Acc) ->
    Take = min(Left, Piece),
    {Bytes, Rest} =
        case Buf of
            <<B:Take/binary, R/binary>> -> {B, R};
            _ ->
                case gen_tcp:recv(Sock, Take - byte_size(Buf), 30000) of
                    {ok, More} -> {<<Buf/binary, More/binary>>, <<>>};
                    {error, _} -> throw({closed, iolist_to_binary(lists:reverse(Acc))})
                end
        end,
    timer:sleep(Pause),
    ok = gen_tcp:send(Sock, [integer_to_binary(Take, 16), "\r\n", Bytes, "\r\n"]),
    echo(Sock, Left - Take, Piece, Pause, Rest, [Bytes | Acc]).

read_head(Sock, Acc) ->
    case binary:split(Acc, <<"\r\n\r\n">>) of
        [Head, Rest] -> {Head, Rest};
        [_] -> read_head(Sock, <<Acc/binary, (recv(Sock, Acc))/binary>>)
    end.

read_body(Sock, Lower, Rest) ->
    case re:run(Lower, <<"\r\ncontent-length: *([0-9]+)">>,
                [{capture, all_but_first, binary}]) of
        {match, [Len]} ->
            read_exactly(Sock, binary_to_integer(Len), Rest);
        nomatch ->
            case binary:match(Lower, <<"transfer-encoding: chunked">>) of
                nomatch -> <<>>;
                _ -> read_chunks(Sock, Rest, <<>>)
            end
    end.

read_exactly(_Sock, Len, Acc) when byte_size(Acc) >= Len ->
    binary:part(Acc, 0, Len);
read_exactly(Sock, Len, Acc) ->
    read_exactly(Sock, Len, <<Acc/binary, (recv(Sock, Acc))/binary>>).

read_chunks(Sock, Buf, Body) ->
    case binary:split(Buf, <<"\r\n">>) of
        [SizeLine, Rest] ->
            [Hex | _] = binary:split(SizeLine, <<";">>),
            case binary_to_integer(string:trim(Hex), 16) of
                0 ->
                    Body;
                Size when byte_size(Rest) >= Size + 2 ->
                    <<Chunk:Size/binary, "\r\n", Next/binary>> = Rest,
                    read_chunks(Sock, Next, <<Body/binary, Chunk/binary>>);
                _ ->
                    read_chunks(Sock, <<Buf/binary, (recv(Sock, Body))/binary>>, Body)
            end;
        [_] ->
            read_chunks(Sock, <<Buf/binary, (recv(Sock, Body))/binary>>, Body)
    end.

recv(Sock, Partial) ->
    case gen_tcp:recv(Sock, 0, 30000) of
        {ok, Data} -> Data;
        {error, _} -> throw({closed, Partial})
    end.
