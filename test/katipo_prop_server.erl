-module(katipo_prop_server).

%% Keep-alive HTTP/1.1 server for the property tests. Each request is
%% answered from a script registered under the request path's key:
%%   {raw, Bytes}  sent verbatim, so a test controls every header byte and
%%                 can chain 1xx and redirect responses;
%%   {raw_close, Bytes}
%%                 sent verbatim, then the connection is closed: a body
%%                 delimited by the close, a short one, or (with <<>>) no
%%                 response at all;
%%   echo          an empty 200, after recording the request as received,
%%                 {Method, Headers, Body}, for received/1 to return (in the
%%                 table rather than the response, so HEAD works too);
%%   {echo, Bytes} Bytes sent verbatim, after recording the request as echo
%%                 does;
%%   {redirect, Status, NextKey}
%%                 a bodyless redirect to NextKey's URL.
%% Request headers are parsed from the raw bytes, not with {packet, http},
%% so names and values arrive exactly as curl sent them, and a chunked
%% request body is de-chunked. Not linked to its
%% starter, so it outlives init_per_suite's process; stop/1 ends it, its
%% listen socket and its table.

-export([start/0]).
-export([stop/1]).
-export([header/2]).
-export([script/3]).
-export([url/2]).
-export([received/1]).

start() ->
    Self = self(),
    Pid = spawn(fun() ->
                  ?MODULE = ets:new(?MODULE, [named_table, public]),
                  {ok, L} = gen_tcp:listen(0, [binary, {active, false},
                                               {reuseaddr, true}]),
                  {ok, P} = inet:port(L),
                  Self ! {?MODULE, P},
                  accept(L)
          end),
    receive {?MODULE, P} -> {ok, Pid, P} after 5000 -> error(server_not_listening) end.

stop(Pid) ->
    Ref = monitor(process, Pid),
    exit(Pid, kill),
    receive {'DOWN', Ref, process, Pid, _} -> ok end.

%% Register Script under a fresh key and return the URL that requests it.
script(Port, Key, Script) ->
    true = ets:insert(?MODULE, {Key, Script}),
    url(Port, Key).

%% The request an echo script received; it is recorded before the response
%% is sent, so it is there once the client has the response.
received(Key) ->
    [{_, Echo}] = ets:take(?MODULE, {received, Key}),
    Echo.

url(Port, Key) ->
    <<"http://127.0.0.1:", (integer_to_binary(Port))/binary, "/", Key/binary>>.

accept(L) ->
    {ok, S} = gen_tcp:accept(L),
    Pid = spawn(fun() -> receive go -> serve(S) end end),
    ok = gen_tcp:controlling_process(S, Pid),
    Pid ! go,
    accept(L).

%% A client that goes away mid-request, as one whose upload fails does,
%% ends the connection quietly.
serve(S) ->
    try conn(S, <<>>)
    catch error:{badmatch, {error, _}} -> gen_tcp:close(S)
    end.

conn(S, Buf) ->
    case read_head(S, Buf) of
        {ok, Head, Rest} ->
            [RequestLine | Lines] = binary:split(Head, <<"\r\n">>, [global]),
            [Method, <<"/", Key/binary>>, _Version] =
                binary:split(RequestLine, <<" ">>, [global]),
            Headers = [parse_header(L) || L <- Lines],
            _ = case header(<<"expect">>, Headers) of
                    <<"100-continue">> ->
                        gen_tcp:send(S, <<"HTTP/1.1 100 Continue\r\n\r\n">>);
                    _ ->
                        ok
                end,
            {Body, Rest2} =
                case header(<<"transfer-encoding">>, Headers) of
                    <<"chunked">> ->
                        read_chunked(S, Rest, <<>>);
                    _ ->
                        Len = binary_to_integer(header(<<"content-length">>, Headers, <<"0">>)),
                        read_body(S, Rest, Len)
                end,
            case ets:take(?MODULE, Key) of
                [{Key, {raw_close, Bytes}}] ->
                    ok = gen_tcp:send(S, Bytes),
                    gen_tcp:close(S);
                [{Key, Script}] ->
                    ok = gen_tcp:send(S, respond(Script, Key, Method, Headers, Body)),
                    conn(S, Rest2)
            end;
        closed ->
            gen_tcp:close(S)
    end.

respond({raw, Bytes}, _Key, _Method, _Headers, _Body) ->
    Bytes;
respond({redirect, Status, Next}, _Key, _Method, _Headers, _Body) ->
    [<<"HTTP/1.1 ">>, integer_to_binary(Status), <<" Redirect\r\nlocation: /">>, Next,
     <<"\r\ncontent-length: 0\r\n\r\n">>];
respond(echo, Key, Method, Headers, Body) ->
    respond({echo, <<"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n">>},
            Key, Method, Headers, Body);
respond({echo, Bytes}, Key, Method, Headers, Body) ->
    true = ets:insert(?MODULE, {{received, Key}, {Method, Headers, Body}}),
    Bytes.

read_head(S, Buf) ->
    case binary:split(Buf, <<"\r\n\r\n">>) of
        [Head, Rest] ->
            {ok, Head, Rest};
        [_] ->
            case gen_tcp:recv(S, 0, 30000) of
                {ok, Data} -> read_head(S, <<Buf/binary, Data/binary>>);
                {error, _} -> closed
            end
    end.

%% A chunked body, without extensions or trailers, which curl does not
%% send.
read_chunked(S, Buf, Acc) ->
    case binary:split(Buf, <<"\r\n">>) of
        [SizeLine, Rest] ->
            case binary_to_integer(SizeLine, 16) of
                0 ->
                    <<"\r\n", Rest2/binary>> = more(S, Rest, 2),
                    {Acc, Rest2};
                Size ->
                    <<Chunk:Size/binary, "\r\n", Rest2/binary>> = more(S, Rest, Size + 2),
                    read_chunked(S, Rest2, <<Acc/binary, Chunk/binary>>)
            end;
        [_] ->
            {ok, Data} = gen_tcp:recv(S, 0, 30000),
            read_chunked(S, <<Buf/binary, Data/binary>>, Acc)
    end.

%% Buf with at least N bytes.
more(_S, Buf, N) when byte_size(Buf) >= N ->
    Buf;
more(S, Buf, N) ->
    {ok, Data} = gen_tcp:recv(S, 0, 30000),
    more(S, <<Buf/binary, Data/binary>>, N).

read_body(_S, Buf, Len) when byte_size(Buf) >= Len ->
    <<Body:Len/binary, Rest/binary>> = Buf,
    {Body, Rest};
read_body(S, Buf, Len) ->
    {ok, Data} = gen_tcp:recv(S, 0, 30000),
    read_body(S, <<Buf/binary, Data/binary>>, Len).

%% curl writes custom headers as "Name: Value", so one space is dropped;
%% anything else after the colon is the value as sent.
parse_header(Line) ->
    [Name, Value] = binary:split(Line, <<":">>),
    case Value of
        <<" ", V/binary>> -> {Name, V};
        V -> {Name, V}
    end.

%% The first value of a header, by case-insensitive name, or undefined.
header(Name, Headers) ->
    header(Name, Headers, undefined).

header(Name, Headers, Default) ->
    case [V || {K, V} <- Headers, string:lowercase(K) =:= Name] of
        [V | _] -> V;
        [] -> Default
    end.
