-module(katipo_upload_server).

%% Minimal HTTP/1.1 server for upload tests that need to see what curl
%% put on the wire -- framing, headers, exact bytes -- which the local
%% httpbin stack hides behind its proxy. Each connection carries one
%% request. The owner hears {upload_head, Pid, Head} once the request's
%% head is read, then {upload_body, Pid, Body} with the body (de-chunked)
%% or {upload_closed, Pid, Partial} if the peer closed first. Linked to
%% its owner, so a failing test tears it down.

-export([start/1]).
-export([stop/1]).
-export([url/1]).

%% Opts: #{continue => auto | ask,  ask: an Expect: 100-continue waits for
%%                                  the owner's `continue' message
%%         response => iodata()}    the raw response, default 200 "ok"
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
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}]),
    {ok, Port} = inet:port(Listen),
    Owner ! {upload_listening, self(), Port},
    accept(Listen, Owner, Opts).

accept(Listen, Owner, Opts) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    serve(Sock, Owner, Opts),
    accept(Listen, Owner, Opts).

serve(Sock, Owner, Opts) ->
    try
        {Head, Rest} = read_head(Sock, <<>>),
        Owner ! {upload_head, self(), Head},
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
        Owner ! {upload_body, self(), Body},
        ok = gen_tcp:send(Sock, maps:get(response, Opts,
                                         <<"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n"
                                           "connection: close\r\n\r\nok">>))
    catch throw:{closed, Partial} ->
            Owner ! {upload_closed, self(), Partial}
    end,
    gen_tcp:close(Sock).

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
