-module(katipo_tls_server).

%% Local HTTPS servers for the TLS tests, so they need nothing from the
%% internet. Each server presents one certificate on its own port and
%% answers every request with 200 "ok", or, given client_cas, 400 to a
%% client that sent no certificate (as a server that asks for one but does
%% not insist would). A POST to /dns-query is answered as DNS over HTTPS,
%% resolving every A query to 127.0.0.1.
%%
%% Certificates are signed at run time by the test CA committed in
%% katipo_SUITE_data/tls (valid until 2126), so none of them expires on
%% its own. capath/ in the same data dir holds that CA under its OpenSSL
%% subject hash.

-export([start/1]).
-export([stop/1]).
-export([ca/1]).
-export([leaf/2]).
-export([self_signed/0]).
-export([write_pem/3]).

-include_lib("public_key/include/public_key.hrl").

%% Opts: #{cert := DER, key := {Type, DER}}, plus optional
%%       versions => [ssl:tls_version()] and client_cas => [DER].
start(Opts) ->
    %% Not started for us: katipo itself does not use the ssl application.
    {ok, _} = application:ensure_all_started(ssl),
    Owner = self(),
    Pid = spawn(fun() -> listen(Owner, Opts) end),
    receive
        {tls_listening, Pid, Port} -> {ok, Pid, Port}
    after 5000 ->
            error(tls_server_not_listening)
    end.

stop(Pid) ->
    exit(Pid, kill),
    ok.

%% The committed test CA as pkix_test_data/1 takes a root.
ca(DataDir) ->
    #{cert := Cert} = read_pem(filename:join([DataDir, "tls", "ca.pem"])),
    #{key := Key} = read_pem(filename:join([DataDir, "tls", "ca.key"])),
    #{cert => Cert, key => Key}.

%% A certificate signed by Root (a ca/1 map, or options for a fresh root
%% that nothing trusts). Opts: names => [string()] for the subjectAltName,
%% validity => {From, To} as {Y, M, D}, key => a pkix_test_data key spec.
leaf(Root, Opts) ->
    Peer = [{key, maps:get(key, Opts, {namedCurve, secp256r1})},
            {digest, sha256},
            {extensions, [san(maps:get(names, Opts, ["localhost"]))]}]
        ++ [{validity, V} || V <- [maps:get(validity, Opts, default)],
                             V =/= default],
    Chain = public_key:pkix_test_data(#{root => Root,
                                        intermediates => [],
                                        peer => Peer}),
    #{cert => proplists:get_value(cert, Chain),
      key => proplists:get_value(key, Chain)}.

%% A certificate for localhost that signs itself, as no CA would.
self_signed() ->
    #{cert := Cert, key := Key} =
        public_key:pkix_test_root_cert("katipo self-signed",
                                       [{key, {namedCurve, secp256r1}},
                                        {digest, sha256},
                                        {extensions, [san(["localhost"])]}]),
    #{cert => Cert, key => {'ECPrivateKey', public_key:der_encode('ECPrivateKey', Key)}}.

%% Write a certificate and its key as PEM files for curl, the key
%% encrypted with Password unless it is undefined.
write_pem(Dir, #{cert := Cert, key := {KeyType, KeyDer}}, Password) ->
    CertFile = filename:join(Dir, "client.pem"),
    KeyFile = filename:join(Dir, "client.key"),
    ok = file:write_file(CertFile,
                         public_key:pem_encode([{'Certificate', Cert, not_encrypted}])),
    KeyEntry =
        case Password of
            undefined ->
                {KeyType, KeyDer, not_encrypted};
            _ ->
                Key = public_key:der_decode(KeyType, KeyDer),
                public_key:pem_entry_encode(KeyType, Key,
                                            {{"AES-256-CBC", crypto:strong_rand_bytes(16)},
                                             Password})
        end,
    ok = file:write_file(KeyFile, public_key:pem_encode([KeyEntry])),
    {CertFile, KeyFile}.

san(Names) ->
    #'Extension'{extnID = ?'id-ce-subjectAltName',
                 extnValue = [{dNSName, N} || N <- Names],
                 critical = false}.

read_pem(File) ->
    {ok, Pem} = file:read_file(File),
    lists:foldl(fun({'Certificate', Der, not_encrypted}, Acc) ->
                        Acc#{cert => Der};
                   (Entry, Acc) ->
                        Acc#{key => public_key:pem_entry_decode(Entry)}
                end, #{}, public_key:pem_decode(Pem)).

listen(Owner, Opts = #{cert := Cert, key := Key}) ->
    ClientCas = maps:get(client_cas, Opts, []),
    Verify = case ClientCas of
                 [] -> [{verify, verify_none}];
                 _ -> [{verify, verify_peer}, {fail_if_no_peer_cert, false},
                       {cacerts, ClientCas}]
             end,
    Versions = [{versions, V} || V <- [maps:get(versions, Opts, default)],
                                 V =/= default],
    {ok, Listen} = ssl:listen(0, [binary, {active, false}, {reuseaddr, true},
                                  {ip, {127, 0, 0, 1}},
                                  {cert, Cert}, {key, Key} | Verify ++ Versions]),
    {ok, {_, Port}} = ssl:sockname(Listen),
    Owner ! {tls_listening, self(), Port},
    accept(Listen, ClientCas =/= []).

accept(Listen, WantsClientCert) ->
    {ok, Transport} = ssl:transport_accept(Listen),
    Pid = spawn(fun() ->
                        receive go -> ok end,
                        connection(Transport, WantsClientCert)
                end),
    ok = ssl:controlling_process(Transport, Pid),
    Pid ! go,
    accept(Listen, WantsClientCert).

%% A client that rejects the certificate (the point of most of these
%% servers) ends the connection during or just after the handshake.
connection(Transport, WantsClientCert) ->
    case ssl:handshake(Transport, 10000) of
        {ok, Sock} ->
            case read_request(Sock, <<>>) of
                {ok, Head, Body} ->
                    {Status, Type, Reply} = respond(Sock, Head, Body, WantsClientCert),
                    _ = ssl:send(Sock, ["HTTP/1.1 ", Status, "\r\n",
                                        "content-type: ", Type, "\r\n",
                                        "content-length: ",
                                        integer_to_list(byte_size(Reply)), "\r\n",
                                        "connection: close\r\n\r\n", Reply]);
                closed ->
                    ok
            end,
            ssl:close(Sock);
        {error, _} ->
            ok
    end.

respond(_Sock, <<"POST /dns-query ", _/binary>>, Query, _) ->
    {"200 OK", "application/dns-message", doh_answer(Query)};
respond(Sock, _Head, _Body, true) ->
    case ssl:peercert(Sock) of
        {ok, _} -> {"200 OK", "text/plain", <<"ok">>};
        {error, _} -> {"400 Bad Request", "text/plain", <<"no client certificate">>}
    end;
respond(_Sock, _Head, _Body, false) ->
    {"200 OK", "text/plain", <<"ok">>}.

read_request(Sock, Acc) ->
    case binary:split(Acc, <<"\r\n\r\n">>) of
        [Head, Body] ->
            read_body(Sock, Head, content_length(Head), Body);
        [_] ->
            case ssl:recv(Sock, 0, 10000) of
                {ok, Data} -> read_request(Sock, <<Acc/binary, Data/binary>>);
                {error, _} -> closed
            end
    end.

read_body(_Sock, Head, Length, Body) when byte_size(Body) >= Length ->
    {ok, Head, Body};
read_body(Sock, Head, Length, Body) ->
    case ssl:recv(Sock, 0, 10000) of
        {ok, Data} -> read_body(Sock, Head, Length, <<Body/binary, Data/binary>>);
        {error, _} -> closed
    end.

content_length(Head) ->
    case re:run(Head, <<"\r\ncontent-length: *([0-9]+)">>,
                [caseless, {capture, all_but_first, binary}]) of
        {match, [N]} -> binary_to_integer(N);
        nomatch -> 0
    end.

%% Every A query resolves to 127.0.0.1; anything else gets no answer.
doh_answer(Query) ->
    {ok, Msg} = inet_dns:decode(Query),
    Questions = inet_dns:msg(Msg, qdlist),
    Answers = [inet_dns:make_rr([{domain, inet_dns:dns_query(Q, domain)},
                                 {type, a}, {class, in}, {ttl, 60},
                                 {data, {127, 0, 0, 1}}])
               || Q <- Questions, inet_dns:dns_query(Q, type) =:= a],
    Header = inet_dns:make_header(inet_dns:msg(Msg, header), [{qr, true}, {ra, true}]),
    inet_dns:encode(inet_dns:make_msg(Msg, [{header, Header}, {anlist, Answers}])).
