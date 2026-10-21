-module(katipo_prop_server).

%% Keep-alive HTTP/1.1 server for the property tests. Each request is
%% answered from a script registered under the request path's key:
%%   {raw, Bytes}  sent verbatim, so a test controls every header byte.
%% Request headers are parsed from the raw bytes, not with {packet, http},
%% so names and values arrive exactly as curl sent them. Not linked to its
%% starter, so it outlives init_per_suite's process; stop/1 ends it, its
%% listen socket and its table.

-export([start/0]).
-export([stop/1]).
-export([script/3]).
-export([url/2]).

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

url(Port, Key) ->
    <<"http://127.0.0.1:", (integer_to_binary(Port))/binary, "/", Key/binary>>.

accept(L) ->
    {ok, S} = gen_tcp:accept(L),
    Pid = spawn(fun() -> receive go -> conn(S, <<>>) end end),
    ok = gen_tcp:controlling_process(S, Pid),
    Pid ! go,
    accept(L).

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
            Len = binary_to_integer(header(<<"content-length">>, Headers, <<"0">>)),
            {Body, Rest2} = read_body(S, Rest, Len),
            [{Key, Script}] = ets:take(?MODULE, Key),
            ok = gen_tcp:send(S, respond(Script, Key, Method, Headers, Body)),
            conn(S, Rest2);
        closed ->
            gen_tcp:close(S)
    end.

respond({raw, Bytes}, _Key, _Method, _Headers, _Body) ->
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
