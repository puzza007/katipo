-module(katipo_keepalive_server).

%% Minimal HTTP/1.1 server that keeps each connection open and answers
%% every request on it with a 200, for tests about connection reuse. The
%% owner hears {keepalive_connection, Server, Conn} for each connection
%% accepted, Conn counting from 1. Linked to its owner, so a failing test
%% tears it down.

-export([start/0]).
-export([url/1]).

-spec start() -> {ok, pid(), inet:port_number()}.
start() ->
    Owner = self(),
    Pid = spawn_link(fun() -> listen(Owner) end),
    receive
        {keepalive_listening, Pid, Port} -> {ok, Pid, Port}
    after 5000 ->
            error(keepalive_server_not_listening)
    end.

url(Port) ->
    <<"http://127.0.0.1:", (integer_to_binary(Port))/binary, "/">>.

listen(Owner) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true},
                                      {packet, http_bin}]),
    {ok, Port} = inet:port(Listen),
    Owner ! {keepalive_listening, self(), Port},
    accept(Listen, Owner, 1).

accept(Listen, Owner, Conn) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Owner ! {keepalive_connection, self(), Conn},
    Pid = spawn_link(fun() -> receive go -> serve(Sock) end end),
    ok = gen_tcp:controlling_process(Sock, Pid),
    Pid ! go,
    accept(Listen, Owner, Conn + 1).

%% One request after another, each a request line and headers (none of the
%% tests sends a body), until the client closes the connection.
serve(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, {http_request, _, _, _}} -> headers(Sock);
        _ -> gen_tcp:close(Sock)
    end.

headers(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, {http_header, _, _, _, _}} ->
            headers(Sock);
        {ok, http_eoh} ->
            ok = gen_tcp:send(Sock, <<"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok">>),
            serve(Sock);
        _ ->
            gen_tcp:close(Sock)
    end.
