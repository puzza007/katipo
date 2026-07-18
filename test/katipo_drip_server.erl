-module(katipo_drip_server).

%% Minimal single-connection HTTP/1.1 server that delivers a response body
%% according to a plan, for streaming tests that need a response genuinely
%% in progress -- something the local httpbin stack cannot produce because
%% its proxy buffers whole responses. Peer-close is reported to the owner
%% as {drip_peer_closed, Pid}: the observable proof that the C port really
%% aborted a transfer. Linked to its owner, so a failing test tears it
%% down.

-export([start/1]).
-export([stop/1]).
-export([url/1]).

%% Plan: #{content_length := non_neg_integer(),   advertised, not enforced
%%         pieces := [{DelayMs :: non_neg_integer(), Bytes :: binary()}],
%%         finish := close | stall}
start(Plan) ->
    Owner = self(),
    Pid = spawn_link(fun() -> serve(Owner, Plan) end),
    receive
        {drip_listening, Pid, Port} -> {ok, Pid, Port}
    after 5000 ->
            error(drip_server_not_listening)
    end.

stop(Pid) ->
    unlink(Pid),
    exit(Pid, kill),
    ok.

url(Port) ->
    <<"http://127.0.0.1:", (integer_to_binary(Port))/binary, "/">>.

serve(Owner, #{content_length := ContentLength,
               pieces := Pieces,
               finish := Finish}) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}]),
    {ok, Port} = inet:port(Listen),
    Owner ! {drip_listening, self(), Port},
    {ok, Sock} = gen_tcp:accept(Listen, 30000),
    ok = read_request(Sock, <<>>),
    ok = gen_tcp:send(Sock,
                      ["HTTP/1.1 200 OK\r\n",
                       "content-length: ", integer_to_list(ContentLength),
                       "\r\n",
                       "connection: close\r\n",
                       "\r\n"]),
    drip(Sock, Owner, Pieces),
    case Finish of
        close ->
            gen_tcp:close(Sock);
        stall ->
            wait_for_peer_close(Sock, Owner)
    end.

read_request(Sock, Acc) ->
    case binary:match(Acc, <<"\r\n\r\n">>) of
        nomatch ->
            {ok, Data} = gen_tcp:recv(Sock, 0, 30000),
            read_request(Sock, <<Acc/binary, Data/binary>>);
        _ ->
            ok
    end.

drip(_Sock, _Owner, []) ->
    ok;
drip(Sock, Owner, [{DelayMs, Bytes} | Rest]) ->
    timer:sleep(DelayMs),
    case gen_tcp:send(Sock, Bytes) of
        ok ->
            drip(Sock, Owner, Rest);
        {error, _Closed} ->
            Owner ! {drip_peer_closed, self()},
            exit(normal)
    end.

wait_for_peer_close(Sock, Owner) ->
    %% The peer is a curl GET that has already sent its request, so the
    %% only thing recv can observe is the close (crash loudly otherwise).
    {error, _ClosedOrTimeout} = gen_tcp:recv(Sock, 0, 30000),
    Owner ! {drip_peer_closed, self()}.
