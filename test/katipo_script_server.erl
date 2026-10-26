-module(katipo_script_server).

%% Minimal HTTP/1.1 server that answers each connection with the next step
%% of a script, for tests that need a server to fail in a given way a given
%% number of times. Each connection carries one request: the owner hears
%% {script_request, Pid, Head, Body} once it is read (the body by its
%% Content-Length), and the step then decides the answer. Once the script
%% runs out, every request gets a 200. Linked to its owner, so a failing
%% test tears it down.

-export([start/1]).
-export([stop/1]).
-export([url/1]).

%% A step: {respond, Raw} sends Raw, which should carry
%% `connection: close', and closes; `close' closes without a response;
%% `hang' reads the request and never answers; `keepalive' tells the owner
%% {script_connection, Pid} and answers every request on the connection
%% with a 200, keeping it open until the client closes it.
-type step() :: {respond, iodata()} | close | hang | keepalive.

-spec start([step()]) -> {ok, pid(), inet:port_number()}.
start(Script) ->
    Owner = self(),
    Pid = spawn_link(fun() -> listen(Owner, Script) end),
    receive
        {script_listening, Pid, Port} -> {ok, Pid, Port}
    after 5000 ->
            error(script_server_not_listening)
    end.

stop(Pid) ->
    unlink(Pid),
    exit(Pid, kill),
    ok.

url(Port) ->
    <<"http://127.0.0.1:", (integer_to_binary(Port))/binary, "/">>.

listen(Owner, Script) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Listen),
    Owner ! {script_listening, self(), Port},
    accept(Listen, Owner, Script).

accept(Listen, Owner, Script) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    {Step, Rest} = case Script of
                       [S | R] -> {S, R};
                       [] -> {{respond, ok_response()}, []}
                   end,
    Server = self(),
    Pid = spawn_link(fun() -> receive go -> serve(Sock, Owner, Server, Step) end end),
    ok = gen_tcp:controlling_process(Sock, Pid),
    Pid ! go,
    accept(Listen, Owner, Rest).

serve(Sock, Owner, Server, keepalive) ->
    Owner ! {script_connection, Server},
    keepalive(Sock, Owner, Server);
serve(Sock, Owner, Server, Step) ->
    case read_request(Sock) of
        {ok, Head, Body} ->
            Owner ! {script_request, Server, Head, Body},
            answer(Sock, Step);
        closed ->
            ok
    end.

keepalive(Sock, Owner, Server) ->
    case read_request(Sock) of
        {ok, Head, Body} ->
            Owner ! {script_request, Server, Head, Body},
            ok = gen_tcp:send(Sock, <<"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok">>),
            keepalive(Sock, Owner, Server);
        closed ->
            gen_tcp:close(Sock)
    end.

answer(Sock, {respond, Raw}) ->
    _ = gen_tcp:send(Sock, Raw),
    gen_tcp:close(Sock);
answer(Sock, close) ->
    gen_tcp:close(Sock);
answer(Sock, hang) ->
    %% Hold the socket open until the peer gives up.
    _ = gen_tcp:recv(Sock, 0),
    gen_tcp:close(Sock).

ok_response() ->
    <<"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok">>.

read_request(Sock) ->
    case read_head(Sock, <<>>) of
        {Head, Rest} ->
            Len = case re:run(string:lowercase(Head), <<"\r\ncontent-length: *([0-9]+)">>,
                              [{capture, all_but_first, binary}]) of
                      {match, [L]} -> binary_to_integer(L);
                      nomatch -> 0
                  end,
            case read_body(Sock, Len - byte_size(Rest), Rest) of
                {ok, Body} -> {ok, Head, Body};
                closed -> closed
            end;
        closed ->
            closed
    end.

read_head(Sock, Acc) ->
    case binary:split(Acc, <<"\r\n\r\n">>) of
        [Head, Rest] ->
            {Head, Rest};
        [_] ->
            case gen_tcp:recv(Sock, 0) of
                {ok, Data} -> read_head(Sock, <<Acc/binary, Data/binary>>);
                {error, _} -> closed
            end
    end.

read_body(_Sock, Left, Acc) when Left =< 0 ->
    {ok, Acc};
read_body(Sock, Left, Acc) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Data} -> read_body(Sock, Left - byte_size(Data), <<Acc/binary, Data/binary>>);
        {error, _} -> closed
    end.
