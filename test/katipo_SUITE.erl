-module(katipo_SUITE).

-compile([{nowarn_export_all, true}]).
-compile(export_all).

-include_lib("common_test/include/ct.hrl").

-define(POOL, katipo_test_pool).
-define(POOL_SIZE, 2).

suite() ->
    [{timetrap, {seconds, 30}}].

init_per_suite(Config) ->
    application:ensure_all_started(katipo),
    application:ensure_all_started(meck),
    {ok, _} = katipo_pool:start(?POOL, ?POOL_SIZE),
    Config.

end_per_suite(_Config) ->
    ok = application:stop(katipo).

init_per_group(http, Config) ->
    application:ensure_all_started(cowboy),
    Filename = tempfile:name("katipo_test_"),
    Dispatch = cowboy_router:compile([{'_', [{"/unix", get_handler, []}]}]),
    {ok, _} = cowboy:start_clear(unix_socket, [{ip, {local, Filename}},
                                               {port, 0}], #{env => #{dispatch => Dispatch}}),
    [{unix_socket_file, Filename} | Config];
init_per_group(pool, Config) ->
    application:ensure_all_started(meck),
    Config;
init_per_group(https, Config) ->
    application:ensure_all_started(cowboy),
    Dispatch = cowboy_router:compile([{'_', [{"/", get_handler, []}]}]),
    DataDir = ?config(data_dir, Config),
    CACert = filename:join(DataDir, "cowboy-ca.crt"),
    {ok, _} = cowboy:start_tls(ct_https,
                               [{port, 8443},
                                %% {cacertfile, CACert},
                                {certfile, filename:join(DataDir, "server.crt")},
                                {keyfile, filename:join(DataDir, "server.key")}],
                               #{env => #{dispatch => Dispatch}}),
    [{cacert_file, list_to_binary(CACert)} | Config];
init_per_group(https_mutual, Config) ->
    DataDir = ?config(data_dir, Config),
    Cert = filename:join(DataDir, "badssl.com-client.pem"),
    Key = filename:join(DataDir, "badssl.com-client.key"),
    {ok, PemBin} = file:read_file(Key),
    [KeyPem] = public_key:pem_decode(PemBin),
    KeyDecoded = public_key:pem_entry_decode(KeyPem, <<"badssl.com">>),
    KeyDer = public_key:der_encode('RSAPrivateKey', KeyDecoded),
    [{cert_file, list_to_binary(Cert)},
     {key_file, list_to_binary(Key)},
     {decrypted_key_der, KeyDer} | Config];
init_per_group(_, Config) ->
    Config.

end_per_group(http, Config) ->
    Filename = ?config(unix_socket_file, Config),
    _ = file:delete(Filename),
    Config;
end_per_group(pool, Config) ->
    application:stop(meck),
    Config;
end_per_group(_, Config) ->
    Config.

init_per_testcase(_, Config) ->
    Config.

end_per_testcase(_, Config) ->
    Config.

groups() ->
    [{http, [parallel],
      [get,
       get_http,
       get_req,
       head,
       post_body_binary,
       post_body_iolist,
       post_body_qs_vals,
       post_body_bad,
       post_arity_2,
       post_qs,
       post_qs_invalid,
       post_req,
       url_missing,
       bad_method,
       put_data,
       put_arity_2,
       put_qs,
       patch_data,
       patch_arity_2,
       patch_qs,
       options,
       headers,
       header_remove,
       delete,
       gzip,
       deflate,
       stream,
       statuses,
       cookies,
       cookies_delete,
       cookies_bad_cookie_jar,
       bytes,
       stream_bytes,
       utf8,
       redirect_to,
       connecttimeout_ms,
       followlocation_true,
       followlocation_false,
       tcp_fastopen_true,
       tcp_fastopen_false,
       interface,
       interface_unknown,
       unix_socket_path,
       unix_socket_path_cant_connect,
       timeout_ms,
       maxredirs,
       lock_data_ssl_session_true,
       lock_data_ssl_session_false,
       doh_url,
       badopts,
       proxy_couldnt_connect,
       protocol_restriction]},
     {digest, [],
      [basic_authorised,
       basic_authorised_userpwd,
       basic_unauthorised,
       digest_authorised,
       digest_authorised_userpwd,
       digest_unauthorised]},
     {pool, [],
      [pool_start_stop,
       worker_death,
       port_death,
       port_late_response,
       pool_opts,
       max_pipeline_length]},
     {https, [parallel],
      [verify_host_verify_peer_ok,
       %% TODO :Fix this test. See https://github.com/puzza007/katipo/runs/5281801454?check_suite_focus=true
       %% verify_host_verify_peer_error,
       %% TODO: Fix this test. See https://github.com/puzza007/katipo/runs/5281750037?check_suite_focus=true
       %% cacert_self_signed,
       badssl]},
     {https_mutual, [],
      [badssl_client_cert]},
     {port, [],
      [max_total_connections]},
     {telemetry, [],
      [telemetry_events,
       telemetry_success_measurements,
       telemetry_error_events,
       telemetry_metadata_parsing,
       telemetry_timing_metrics]},
     {http2, [parallel],
      [http2_get]}].

all() ->
    [{group, http},
     {group, digest},
     {group, pool},
     {group, https},
     {group, https_mutual},
     {group, port},
     {group, telemetry},
     {group, http2}].

get(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"https://httpbin.org/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

get_http(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"http://httpbin.org/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

get_req(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:req(?POOL, #{url => <<"https://httpbin.org/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

head(_) ->
    {ok, #{status := 200}} =
        katipo:head(?POOL, <<"https://httpbin.org/get">>).

post_body_binary(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, <<"https://httpbin.org/post">>,
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

post_body_iolist(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, <<"https://httpbin.org/post">>,
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => ["foo", $b, $a, $r, <<"baz">>]}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    <<"foobarbaz">> = proplists:get_value(<<"data">>, Json).

post_body_qs_vals(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, <<"https://httpbin.org/post">>,
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => [<<"!@#$%">>, <<"^&*()">>]}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

post_body_bad(_) ->
    Message = [{body, should_not_be_an_atom}],
    BinaryMessage = iolist_to_binary(io_lib:format("~p", [Message])),
    {error, #{code := bad_opts, message := BinaryMessage}} =
        katipo:post(?POOL, <<"https://httpbin.org/post">>,
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => should_not_be_an_atom}).

post_arity_2(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, <<"https://httpbin.org/post">>),
    Json = jsx:decode(Body, [{return_maps, false}]),
    undefined = proplists:get_value(<<>>, Json).

post_qs(_) ->
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, <<"https://httpbin.org/post">>, #{body => QsVals}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

post_qs_invalid(_) ->
    QsVals = [{hi, <<"bar">>}],
    {error, #{code := bad_opts}} =
        katipo:post(?POOL, <<"https://httpbin.org/post">>, #{body => QsVals}).

post_req(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:req(?POOL, #{url => <<"https://httpbin.org/post">>,
                     method => post,
                     headers => [{<<"Content-Type">>, <<"application/json">>}],
                     body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

url_missing(_) ->
    Message = [{url, undefined}],
    BinaryMessage = iolist_to_binary(io_lib:format("~p", [Message])),
    {error, #{code := bad_opts, message := BinaryMessage}} =
        katipo:req(?POOL, #{method => post,
                     headers => [{<<"Content-Type">>, <<"application/json">>}],
                     body => <<"!@#$%^&*()">>}).

bad_method(_) ->
    Message = [{method, toast}],
    BinaryMessage = iolist_to_binary(io_lib:format("~p", [Message])),
    {error, #{code := bad_opts, message := BinaryMessage}} =
        katipo:req(?POOL, #{method => toast,
                     headers => [{<<"Content-Type">>, <<"application/json">>}],
                     body => <<"!@#$%^&*()">>}).

put_data(_) ->
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:put(?POOL, <<"https://httpbin.org/put">>,
                   #{headers => Headers, body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

put_arity_2(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:put(?POOL, <<"https://httpbin.org/put">>),
    Json = jsx:decode(Body, [{return_maps, false}]),
    undefined = proplists:get_value(<<>>, Json).

put_qs(_) ->
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:put(?POOL, <<"https://httpbin.org/put">>, #{body => QsVals}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

patch_data(_) ->
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:patch(?POOL, <<"https://httpbin.org/patch">>,
                   #{headers => Headers, body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

patch_arity_2(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:patch(?POOL, <<"https://httpbin.org/patch">>),
    Json = jsx:decode(Body, [{return_maps, false}]),
    <<>> = proplists:get_value(<<"data">>, Json).

patch_qs(_) ->
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:patch(?POOL, <<"https://httpbin.org/patch">>, #{body => QsVals}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

options(_) ->
    {ok, #{status := 200, headers := Headers}} = katipo:options(?POOL, <<"https://httpbin.org">>),
    LowerHeaders = [{string:lowercase(K), V} || {K, V} <- Headers],
    <<"GET, POST, PUT, DELETE, PATCH, OPTIONS">> =
        proplists:get_value(<<"access-control-allow-methods">>, LowerHeaders).

delete(_) ->
    {ok, #{status := 200}} = katipo:delete(?POOL, <<"https://httpbin.org/delete">>).

headers(_) ->
    Headers = [{<<"header1">>, <<"!@#$%^&*()">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"https://httpbin.org/gzip">>, #{headers => Headers}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    Expected =  [{<<"Accept">>,<<"*/*">>},
                 {<<"Accept-Encoding">>,<<"gzip,deflate">>},
                 {<<"Header1">>,<<"!@#$%^&*()">>},
                 {<<"Host">>,<<"httpbin.org">>}],
    [] = Expected -- proplists:get_value(<<"headers">>, Json).

header_remove(_) ->
    Headers = [{<<"Accept-Encoding">>, <<>>}],
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"https://httpbin.org/get">>, #{headers => Headers}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    Expected =  [{<<"Accept">>,<<"*/*">>},
                 {<<"Host">>,<<"httpbin.org">>}],
    [] = Expected -- proplists:get_value(<<"headers">>, Json).

gzip(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, <<"https://httpbin.org/gzip">>),
    Json = jsx:decode(Body, [{return_maps, false}]),
    true = proplists:get_value(<<"gzipped">>, Json).

deflate(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, <<"https://httpbin.org/deflate">>),
    Json = jsx:decode(Body, [{return_maps, false}]),
    true = proplists:get_value(<<"deflated">>, Json).

bytes(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, <<"https://httpbin.org/bytes/1024?seed=9999">>),
    1024 = byte_size(Body),
    <<168,123,193,120,18,120,65,73,67,119,198,61,39,1,24,169>> = crypto:hash(md5, Body).

stream_bytes(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, <<"https://httpbin.org/bytes/1024?seed=9999&chunk_size=8">>),
    1024 = byte_size(Body),
    <<168,123,193,120,18,120,65,73,67,119,198,61,39,1,24,169>> = crypto:hash(md5, Body).

utf8(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, <<"https://httpbin.org/encoding/utf8">>),
    case xmerl_ucs:from_utf8(Body) of
        [_|_] -> ok
    end.

stream(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, <<"https://httpbin.org/stream/20">>),
    20 = length(binary:split(Body, <<"\n">>, [global, trim])).

statuses(_) ->
    MFAs = [begin
                B = integer_to_binary(S),
                Url = <<"https://httpbin.org/status/",B/binary>>,
                {katipo, get, [?POOL, Url]}
            end || S <- http_status_codes()],
    Results = rpc:parallel_eval(MFAs),
    Results2 = [S || {ok, #{status := S}} <- Results],
    Results2 = http_status_codes().

cookies(_) ->
    Url = <<"https://httpbin.org/cookies/set?cname=cvalue">>,
    Opts = #{followlocation => true},
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, Url, Opts),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [{<<"cname">>, <<"cvalue">>}] = proplists:get_value(<<"cookies">>, Json).

cookies_delete(_) ->
    GetUrl = <<"https://httpbin.org/cookies/set?cname=cvalue">>,
    Opts = #{followlocation => true},
    {ok, #{status := 200, cookiejar := CookieJar}} = katipo:get(?POOL, GetUrl, Opts),
    DeleteUrl = <<"https://httpbin.org/cookies/delete?cname">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, DeleteUrl, #{cookiejar => CookieJar, followlocation => true}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [{}] = proplists:get_value(<<"cookies">>, Json).

cookies_bad_cookie_jar(_) ->
    Url = <<"https://httpbin.org/cookies/delete?cname">>,
    CookieJar = ["has to be a binary"],
    Message = <<"[{cookiejar,[\"has to be a binary\"]}]">>,
    {error, #{code := bad_opts, message := Message}} =
        katipo:get(?POOL, Url, #{cookiejar => CookieJar}).

%% TODO
redirect_to(_) ->
    {ok, #{status := 302}} = katipo:get(?POOL, <<"https://nghttp2.org/httpbin/redirect-to?url=https://google.com">>).

connecttimeout_ms(_) ->
    {error, #{code := operation_timedout}} =
        katipo:get(?POOL, <<"http://google.com">>, #{connecttimeout_ms => 1}).

followlocation_true(_) ->
    {ok, #{status := 200}} =
        katipo:get(?POOL, <<"https://nghttp2.org/httpbin/redirect/6">>, #{followlocation => true}).

followlocation_false(_) ->
    {ok, #{status := 302}} =
        katipo:get(?POOL, <<"https://nghttp2.org/httpbin/redirect/6">>, #{followlocation => false}).

tcp_fastopen_true(_) ->
    case katipo:get(?POOL, <<"https://httpbin.org/get">>, #{tcp_fastopen => true}) of
        {ok, #{}} ->
            ok;
        {error, #{code := bad_opts}} ->
            ct:pal("tcp_fastopen not supported by installed version of curl"),
            ok
    end.


tcp_fastopen_false(_) ->
    case katipo:get(?POOL, <<"https://httpbin.org/get">>, #{tcp_fastopen => false}) of
        {ok, #{}} ->
            ok;
        {error, #{code := bad_opts}} ->
            ct:pal("tcp_fastopen not supported by installed version of curl"),
            ok
    end.

interface(_) ->
    Travis = os:getenv("TRAVIS") == "true",
    Interface = case os:type() of
                    {unix, darwin} ->
                        <<"en0">>;
                    {unix, _} when Travis->
                        <<"ens4">>;
                    {unix, _} ->
                        <<"eth0">>;
                    _ ->
                        erlang:error({unknown_operating_system, fixme})
                end,
    {ok, #{}} =
        katipo:get(?POOL, <<"https://httpbin.org/get">>, #{interface => Interface}).

interface_unknown(_) ->
    {error, #{code := interface_failed}} =
        katipo:get(?POOL, <<"https://httpbin.org/get">>, #{interface => <<"cannot_be_an_interface">>}).

unix_socket_path(Config) ->
    Filename = list_to_binary(?config(unix_socket_file, Config)),
    case katipo:get(?POOL, <<"http://localhost/unix">>, #{unix_socket_path => Filename}) of
        {ok, #{status := 200, headers := Headers}} ->
            <<"Cowboy">> = proplists:get_value(<<"server">>, Headers);
        {error, #{code := bad_opts}} ->
            ct:pal("unix_socket_path not supported by installed version of curl"),
            ok
    end.

unix_socket_path_cant_connect(_) ->
    case katipo:get(?POOL, <<"http://localhost/images/json">>, #{unix_socket_path => <<"4e199b4a1c40b497a95fcd1cd896351733849949">>}) of
        {error, #{code := couldnt_connect}} ->
            ok;
        {error, #{code := bad_opts}} ->
            ct:pal("unix_socket_path not supported by installed version of curl"),
            ok
    end.

maxredirs(_) ->
    Opts = #{followlocation => true, maxredirs => 2},
    {error, #{code := too_many_redirects, message := <<"Maximum (2) redirects followed">>}} =
        katipo:get(?POOL, <<"https://nghttp2.org/httpbin/redirect/6">>, Opts).

basic_unauthorised(_) ->
    {ok, #{status := 401}} =
        katipo:get(?POOL, <<"https://httpbin.org/basic-auth/johndoe/p455w0rd">>).

basic_authorised(_) ->
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"https://httpbin.org/basic-auth/johndoe/p455w0rd">>,
                  #{http_auth => basic, username => Username, password => Password}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    true = proplists:get_value(<<"authenticated">>, Json),
    Username = proplists:get_value(<<"user">>, Json).

basic_authorised_userpwd(_) ->
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"https://httpbin.org/basic-auth/johndoe/p455w0rd">>,
                  #{http_auth => basic, userpwd => <<Username/binary,":",Password/binary>>}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    true = proplists:get_value(<<"authenticated">>, Json),
    Username = proplists:get_value(<<"user">>, Json).

digest_unauthorised(_) ->
    {ok, #{status := 401}} =
        katipo:get(?POOL, <<"https://httpbin.org/digest-auth/auth/johndoe/p455w0rd">>).

digest_authorised(_) ->
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"https://httpbin.org/digest-auth/auth/johndoe/p455w0rd">>,
                  #{http_auth => digest, username => Username, password => Password}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    true = proplists:get_value(<<"authenticated">>, Json),
    Username = proplists:get_value(<<"user">>, Json).

digest_authorised_userpwd(_) ->
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"https://httpbin.org/digest-auth/auth/johndoe/p455w0rd">>,
                  #{http_auth => digest, userpwd => <<Username/binary,":",Password/binary>>}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    true = proplists:get_value(<<"authenticated">>, Json),
    Username = proplists:get_value(<<"user">>, Json).

lock_data_ssl_session_true(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"https://httpbin.org/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>,
                  #{lock_data_ssl_session => true}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

lock_data_ssl_session_false(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"https://httpbin.org/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>,
                  #{lock_data_ssl_session => false}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

doh_url(_) ->
    case katipo:doh_url_available() of
        true ->
            {ok, #{status := 301}} =
                katipo:get(?POOL, <<"https://google.com">>,
                           #{doh_url => <<"https://1.1.1.1/dns-query">>});
        false ->
            ok
    end.

badopts(_) ->
    {error, #{code := bad_opts, message := Message}} =
        katipo:get(?POOL, <<"https://httpbin.org/get">>, #{timeout_ms => <<"wrong">>, what => not_even_close}),
    {ok, Tokens, _} = erl_scan:string(binary_to_list(Message) ++ "."),
    {ok, L} = erl_parse:parse_term(Tokens),
    [] = L -- [{what, not_even_close}, {timeout_ms, <<"wrong">>}].

proxy_couldnt_connect(_) ->
    Url = <<"https://httpbin.org/get">>,
    {error, #{code := couldnt_connect}} =
        katipo:get(?POOL, Url, #{proxy => <<"http://localhost:3128">>}).

protocol_restriction(_) ->
    {error, #{code := unsupported_protocol}} = katipo:get(?POOL, <<"dict.org">>).

timeout_ms(_) ->
    {error, #{code := operation_timedout}} =
        katipo:get(?POOL, <<"https://httpbin.org/delay/1">>, #{timeout_ms => 500}).

couldnt_resolve_host(_) ->
    {error, #{code := couldnt_resolve_host,
              message := <<"Couldn't resolve host 'abadhostnamethatdoesnotexist'">>}} =
        katipo:get(?POOL, <<"http://abadhostnamethatdoesnotexist">>).

http_status_codes() ->
    [200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301,
     302, 303, 304, 305, 306, 307, 308,
     400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414,
     415, 416, 417, 421, 422, 423, 424, 426, 428, 429, 431,
     500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511].

pool_start_stop(_) ->
    PoolName = start_stop_pool,
    PoolSize = 2,
    {ok, Pid} = katipo_pool:start(PoolName, PoolSize, []),
    ok = katipo_pool:stop(PoolName),
    receive
    after 2500 ->
            ok
    end,
    {ok, Pid2} = katipo_pool:start(PoolName, PoolSize, []),
    ok = katipo_pool:stop(PoolName),
    true = Pid =/= Pid2.

active_workers() ->
    Pids = [begin
                Name = lists:flatten(io_lib:format("wpool_pool-~s-~B", [?POOL, N])),
                NameAtom = list_to_existing_atom(Name),
                whereis(NameAtom)
            end || N <- lists:seq(1, ?POOL_SIZE)],
    [P || P <- Pids, P /= undefined].

worker_death(_) ->
    Active = active_workers(),
    _ = [exit(W, kill) || W <- Active],
    Fun = fun() ->
                  Active2 = active_workers(),
                  [] == Active2 -- (Active2 -- Active)
          end,
    true = repeat_until_true(Fun),
    Fun2 = fun() ->
                  length(Active) == length(active_workers())
          end,
    true = repeat_until_true(Fun2),
    Fun3 = fun() ->
                   {ok, #{status := 200}} = katipo:get(?POOL, <<"https://httpbin.org/get">>),
                   true
           end,
    true = repeat_until_true(Fun3).

port_death(_) ->
    PoolName = this_process_will_be_killed,
    PoolSize = 1,
    {ok, _} = katipo_pool:start(PoolName, PoolSize),
    WorkerName = wpool_pool:best_worker(PoolName),
    WorkerPid = whereis(WorkerName),
    {state, _, katipo, {state, Port, _}, _} = sys:get_state(WorkerPid),
    true = port_command(Port, <<"hdfjkshkjsdfgjsgafdjgsdjgfj">>),
    Fun = fun() ->
                  WorkerName2 = wpool_pool:best_worker(PoolName),
                  WorkerPid2 = whereis(WorkerName2),
                  case sys:get_state(WorkerPid2) of
                      {state, _, katipo, {state, Port2, _}, _} when Port =/= Port2 ->
                          {ok, #{status := 200}} =
                              katipo:get(PoolName, <<"https://httpbin.org/get">>),
                          true
                  end
          end,
    true = repeat_until_true(Fun).

port_late_response(_) ->
    ok = meck:new(katipo, [passthrough]),
    meck:expect(katipo, get_timeout, fun(_) -> 100 end),
    {error, #{code := operation_timedout, message := <<>>}} =
        katipo:get(?POOL, <<"https://httpbin.org/delay/1">>),
    meck:unload(katipo).

pool_opts(_) ->
    PoolName = pool_opts,
    PoolSize = 1,
    PoolOpts = [{pipelining, multiplex},
                {max_pipeline_length, 5},
                {max_total_connections, 10},
                {ignore_junk_opt, hithere}],
    {error, _} = katipo_pool:start(PoolName, PoolSize, PoolOpts),
    ok = katipo_pool:stop(PoolName).

max_pipeline_length(_) ->
    PoolName = pool_opts,
    PoolSize = 1,
    PoolOpts = [{pipelining, multiplex},
                {max_pipeline_length, 5},
                {max_total_connections, 10}],
    {ok, _} = katipo_pool:start(PoolName, PoolSize, PoolOpts),
    ok = katipo_pool:stop(PoolName).

verify_host_verify_peer_ok(_) ->
    Opts = [#{ssl_verifyhost => true, ssl_verifypeer => true},
            #{ssl_verifyhost => false, ssl_verifypeer => true},
            #{ssl_verifyhost => true, ssl_verifypeer => false},
            #{ssl_verifyhost => false, ssl_verifypeer => false}],
    [{ok, _} = katipo:get(?POOL, <<"https://google.com">>, O) || O <- Opts].

verify_host_verify_peer_error(_) ->
    {error, #{code := Code}} =
         katipo:get(?POOL, <<"https://localhost:8443">>,
                    #{ssl_verifyhost => true, ssl_verifypeer => true}),
    %% TODO: this could be made to reflect the ifdef from katipo.c...
    ok = case Code of
             ssl_cacert -> ok;
             peer_failed_verification -> ok
         end,
    {error, #{code := Code}} =
         katipo:get(?POOL, <<"https://localhost:8443">>,
                    #{ssl_verifyhost => false, ssl_verifypeer => true}),
    ok = case Code of
             ssl_cacert -> ok;
             peer_failed_verification -> ok
         end,
    {ok, #{status := 200}} =
        katipo:get(?POOL, <<"https://localhost:8443">>,
                   #{ssl_verifyhost => true, ssl_verifypeer => false}),
    {ok, #{status := 200}} =
        katipo:get(?POOL, <<"https://localhost:8443">>,
                   #{ssl_verifyhost => false, ssl_verifypeer => false}).

cacert_self_signed(Config) ->
    CACert = ?config(cacert_file, Config),
    {ok, #{status := 200}} =
        katipo:get(?POOL, <<"https://localhost:8443">>,
                   #{verbose => true, ssl_verifyhost => true, ssl_verifypeer => true, cacert => CACert}).

badssl(_) ->
    {error, _} =
        katipo:get(?POOL, <<"https://expired.badssl.com/">>),
    {error, _} =
        katipo:get(?POOL, <<"https://wrong.host.badssl.com/">>),
    {error, _} =
        katipo:get(?POOL, <<"https://self-signed.badssl.com/">>),
    {error, _} =
        katipo:get(?POOL, <<"https://untrusted-root.badssl.com/">>).

badssl_client_cert(Config) ->
    {ok, #{status := 400}} =
        katipo:get(?POOL, <<"https://client.badssl.com">>,
                   #{ssl_verifyhost => true,
                     ssl_verifypeer => true}),
    CertFile = ?config(cert_file, Config),
    KeyFile = ?config(key_file, Config),
    %% Certificate provided but no key
    {error, #{code := ssl_certproblem}} =
        katipo:get(?POOL, <<"https://client.badssl.com">>,
                   #{ssl_verifyhost => true,
                     ssl_verifypeer => true,
                     sslcert => CertFile}),
    %% This key requires a passphrase
    {error, #{code := ssl_certproblem}} =
        katipo:get(?POOL, <<"https://client.badssl.com">>,
                   #{ssl_verifyhost => true,
                     ssl_verifypeer => true,
                     sslcert => CertFile,
                     sslkey => KeyFile}),
    {ok, #{status := 200}} =
        katipo:get(?POOL, <<"https://client.badssl.com">>,
                   #{ssl_verifyhost => true,
                     ssl_verifypeer => true,
                     sslcert => CertFile,
                     sslkey => KeyFile,
                     keypasswd => <<"badssl.com">>}),
    case katipo:sslkey_blob_available() of
        true ->
            KeyDer = ?config(decrypted_key_der, Config),
            {ok, #{status := 200}} =
                katipo:get(?POOL, <<"https://client.badssl.com">>,
                        #{ssl_verifyhost => true,
                            ssl_verifypeer => true,
                            sslcert => CertFile,
                            sslkey_blob => KeyDer});
        false ->
            ok
    end,
    ok.

max_total_connections(_) ->
    PoolName = max_total_connections,
    {ok, _} = katipo_pool:start(PoolName, 1, [{pipelining, nothing}, {max_total_connections, 1}]),
    Self = self(),
    Fun = fun() ->
                  {ok, #{status := 200}} =
                      katipo:get(PoolName, <<"https://httpbin.org/delay/5">>),
                  Self ! ok
          end,
    spawn(Fun),
    spawn(Fun),
    Start = erlang:system_time(seconds),
    [receive ok -> ok end || _ <- [1, 2]],
    Diff = erlang:system_time(seconds) - Start,
    true = Diff >= 10.

telemetry_events(_) ->
    %% Set up a test handler to capture telemetry events
    Events = [[katipo, request, stop], [katipo, request, error]],
    TestPid = self(),
    HandlerFun = fun(EventName, Measurements, Metadata, _Config) ->
        TestPid ! {telemetry_event, EventName, Measurements, Metadata}
    end,

    lists:foreach(fun(Event) ->
        telemetry:attach(
            list_to_atom(lists:concat([test_, lists:last(Event)])),
            Event,
            HandlerFun,
            undefined
        )
    end, Events),

    %% Make a successful request
    {ok, #{status := 200}} = katipo:head(?POOL, <<"https://httpbin.org/get">>),

    %% Verify telemetry event was emitted
    receive
        {telemetry_event, [katipo, request, stop], Measurements, Metadata} ->
            %% Verify measurements contain expected keys
            true = maps:is_key(duration, Measurements),
            true = maps:is_key(response_body_size, Measurements),
            true = maps:is_key(namelookup_time, Measurements),
            true = maps:is_key(connect_time, Measurements),
            true = maps:is_key(appconnect_time, Measurements),
            true = maps:is_key(pretransfer_time, Measurements),
            true = maps:is_key(redirect_time, Measurements),
            true = maps:is_key(starttransfer_time, Measurements),
            %% Verify metadata contains expected keys
            true = maps:is_key(method, Metadata),
            true = maps:is_key(url, Metadata),
            true = maps:is_key(status, Metadata),
            true = maps:is_key(scheme, Metadata),
            true = maps:is_key(host, Metadata),
            ok
    after 5000 ->
        error(no_telemetry_event)
    end,

    %% Clean up handlers
    lists:foreach(fun(Event) ->
        telemetry:detach(list_to_atom(lists:concat([test_, lists:last(Event)])))
    end, Events).

telemetry_success_measurements(_) ->
    %% Test that successful requests emit all expected measurements
    TestPid = self(),
    HandlerFun = fun(EventName, Measurements, Metadata, _Config) ->
        TestPid ! {telemetry_event, EventName, Measurements, Metadata}
    end,

    telemetry:attach(
        test_success_measurements,
        [katipo, request, stop],
        HandlerFun,
        undefined
    ),

    %% Make a successful request
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, <<"https://httpbin.org/get">>),

    %% Verify all measurements are present and reasonable
    receive
        {telemetry_event, [katipo, request, stop], Measurements, _Metadata} ->
            %% Check that all timing measurements are present
            RequiredMeasurements = [duration, namelookup_time, connect_time,
                                  appconnect_time, pretransfer_time, redirect_time,
                                  starttransfer_time, response_body_size],
            lists:foreach(fun(Key) ->
                case maps:get(Key, Measurements, undefined) of
                    undefined ->
                        error({missing_measurement, Key});
                    Value when is_number(Value) ->
                        ok;
                    Value ->
                        error({invalid_measurement_type, Key, Value})
                end
            end, RequiredMeasurements),

            %% Verify response body size matches actual body
            ExpectedSize = iolist_size(Body),
            ExpectedSize = maps:get(response_body_size, Measurements),

            %% Verify timing values are reasonable (>= 0)
            TimingKeys = [duration, namelookup_time, connect_time, appconnect_time,
                         pretransfer_time, redirect_time, starttransfer_time],
            lists:foreach(fun(Key) ->
                Value = maps:get(Key, Measurements),
                case Value >= 0 of
                    true -> ok;
                    false -> error({negative_timing, Key, Value})
                end
            end, TimingKeys),

            ok
    after 5000 ->
        error(no_telemetry_event)
    end,

    telemetry:detach(test_success_measurements).

telemetry_error_events(_) ->
    %% Test that error requests emit error events
    TestPid = self(),
    HandlerFun = fun(EventName, Measurements, Metadata, _Config) ->
        TestPid ! {telemetry_event, EventName, Measurements, Metadata}
    end,

    telemetry:attach(
        test_error_events,
        [katipo, request, error],
        HandlerFun,
        undefined
    ),

    %% Make a request that will fail (invalid URL)
    {error, _} = katipo:get(?POOL, <<"http://nonexistent.invalid.domain">>),

    %% Verify error event was emitted
    receive
        {telemetry_event, [katipo, request, error], Measurements, Metadata} ->
            %% Check measurements
            1 = maps:get(count, Measurements),

            %% Check metadata has error info
            true = maps:is_key(error, Metadata),
            true = maps:is_key(method, Metadata),
            true = maps:is_key(url, Metadata),

            %% Verify method is correct
            get = maps:get(method, Metadata),

            ok
    after 5000 ->
        error(no_error_telemetry_event)
    end,

    telemetry:detach(test_error_events).

telemetry_metadata_parsing(_) ->
    %% Test that URL metadata is parsed correctly
    TestPid = self(),
    HandlerFun = fun(EventName, Measurements, Metadata, _Config) ->
        TestPid ! {telemetry_event, EventName, Measurements, Metadata}
    end,

    telemetry:attach(
        test_metadata_parsing,
        [katipo, request, stop],
        HandlerFun,
        undefined
    ),

    %% Make a request with a URL that has scheme, host, and port
    {ok, #{status := 200}} = katipo:get(?POOL, <<"https://httpbin.org:443/get">>),

    %% Verify metadata parsing
    receive
        {telemetry_event, [katipo, request, stop], _Measurements, Metadata} ->
            %% Check URL components
            get = maps:get(method, Metadata),
            <<"https://httpbin.org:443/get">> = maps:get(url, Metadata),
            <<"https">> = maps:get(scheme, Metadata),
            <<"httpbin.org">> = maps:get(host, Metadata),
            443 = maps:get(port, Metadata),
            200 = maps:get(status, Metadata),

            ok
    after 5000 ->
        error(no_metadata_telemetry_event)
    end,

    telemetry:detach(test_metadata_parsing).

telemetry_timing_metrics(_) ->
    %% Test that timing metrics are captured from libcurl
    TestPid = self(),
    HandlerFun = fun(EventName, Measurements, Metadata, _Config) ->
        TestPid ! {telemetry_event, EventName, Measurements, Metadata}
    end,

    telemetry:attach(
        test_timing_metrics,
        [katipo, request, stop],
        HandlerFun,
        undefined
    ),

    %% Make a request to a server that will have measurable timing
    {ok, #{status := 200}} = katipo:get(?POOL, <<"https://httpbin.org/delay/1">>),

    %% Verify timing metrics are reasonable
    receive
        {telemetry_event, [katipo, request, stop], Measurements, _Metadata} ->
            %% Total time should be at least 1 second (1000ms) due to delay
            Duration = maps:get(duration, Measurements),
            case Duration >= 1000 of
                true -> ok;
                false -> error({duration_too_short, Duration})
            end,

            %% DNS lookup time should be non-negative
            NameLookupTime = maps:get(namelookup_time, Measurements),
            case NameLookupTime >= 0 of
                true -> ok;
                false -> error({negative_namelookup_time, NameLookupTime})
            end,

            %% Connect time should be non-negative
            ConnectTime = maps:get(connect_time, Measurements),
            case ConnectTime >= 0 of
                true -> ok;
                false -> error({negative_connect_time, ConnectTime})
            end,

            %% For HTTPS, app connect time (TLS handshake) should be > 0
            AppConnectTime = maps:get(appconnect_time, Measurements),
            case AppConnectTime >= 0 of
                true -> ok;
                false -> error({negative_appconnect_time, AppConnectTime})
            end,

            %% Verify timing progression makes sense
            %% (each timing should be >= previous timing)
            Timings = [
                {namelookup_time, NameLookupTime},
                {connect_time, ConnectTime},
                {appconnect_time, AppConnectTime},
                {pretransfer_time, maps:get(pretransfer_time, Measurements)},
                {starttransfer_time, maps:get(starttransfer_time, Measurements)},
                {duration, Duration}
            ],

            %% Check that timings are in logical order (allowing for 0 values)
            lists:foldl(fun({Name, Time}, PrevTime) ->
                case Time >= PrevTime orelse Time =:= 0 of
                    true -> Time;
                    false -> error({timing_order_violation, Name, Time, PrevTime})
                end
            end, 0, Timings),

            ok
    after 10000 ->  %% Longer timeout for delayed request
        error(no_timing_telemetry_event)
    end,

    telemetry:detach(test_timing_metrics).

http2_get(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, <<"https://nghttp2.org/httpbin/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>,
                   #{http_version => curl_http_version_2_prior_knowledge}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

repeat_until_true(Fun) ->
    try
        case Fun() of
            true ->
                true;
            _ ->
                timer:sleep(100),
                repeat_until_true(Fun)
        end
    catch _:_ ->
            timer:sleep(100),
            repeat_until_true(Fun)
    end.
