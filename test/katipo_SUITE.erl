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
    DataDir = ?config(data_dir, Config),
    CACert = filename:join(DataDir, "ca-bundle.crt"),
    [{cacert_file, list_to_binary(CACert)} | Config].

end_per_suite(_Config) ->
    ok = application:stop(katipo).

init_per_group(curl, Config) ->
    application:ensure_all_started(cowboy),
    Filename = tempfile:name("katipo_test_"),
    Name = make_ref(),
    Dispatch = cowboy_router:compile([{'_', [{"/unix", get_handler, []}]}]),
    {ok, _} = cowboy:start_clear(Name, [{ip, {local, Filename}},
                                        {port, 0}], #{env => #{dispatch => Dispatch}}),
    [{unix_socket_file, Filename}, {unix_server_name, Name}] ++ Config;
init_per_group(session, Config) ->
    application:ensure_all_started(katipo),
    Config;
init_per_group(pool, Config) ->
    application:ensure_all_started(meck),
    Config;
init_per_group(proxy, Config) ->
    application:ensure_all_started(http_proxy),
    Config;
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
init_per_group(http1, Config) ->
    [{httpbin_base, <<"https://httpbin.org">>}, {http_version, curl_http_version_1_1}] ++ Config;
init_per_group(http2, Config) ->
    [{httpbin_base, <<"https://nghttp2.org/httpbin">>}, {http_version, curl_http_version_2_prior_knowledge}] ++ Config;
init_per_group(http3, Config) ->
    [{httpbin_base, <<"https://cloudflare-quic.com/b">>}, {http_version, curl_http_version_3}] ++ Config;
init_per_group(_, Config) ->
    Config.

end_per_group(curl, Config) ->
    Filename = ?config(unix_socket_file, Config),
    Name = ?config(unix_server_name, Config),
    _ = file:delete(Filename),
    ok = cowboy:stop_listener(Name),
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
       bytes,
       stream_bytes,
       utf8,
       redirect_to,
       connecttimeout_ms,
       followlocation_true,
       followlocation_false,
       timeout_ms,
       maxredirs,
       basic_unauthorised,
       basic_authorised,
       digest_unauthorised,
       digest_authorised,
       proxy_couldnt_connect]},
     {curl, [parallel],
      [url_missing,
       bad_method,
       cookies_bad_cookie_jar,
       tcp_fastopen_true,
       tcp_fastopen_false,
       interface,
       interface_unknown,
       unix_socket_path,
       unix_socket_path_cant_connect,
       lock_data_ssl_session_true,
       lock_data_ssl_session_false,
       doh_url,
       badopts,
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
     {metrics, [],
      [metrics_true,
       metrics_false]},
     {http1, [parallel],
      [{group, http},
       {group, https}]},
     {http2, [parallel],
      [{group, http},
       {group, https}]},
     {http3, [parallel],
      [{group, http},
       {group, https}]}].

all() ->
    [{group, http1},
     {group, curl},
     {group, digest},
     {group, pool},
     {group, proxy},
     {group, session},
     {group, https_mutual},
     {group, port},
     {group, metrics},
     {group, http2},
     {group, http3}].

get(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>), #{http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

get_http(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>), #{http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

get_req(Config) ->
    HTTPVersion = ?config(http_version, Config),
    Url = httpbin_url(Config, <<"/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>),
    {ok, #{status := 200, body := Body}} =
        katipo:req(?POOL, #{url => Url, http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

head(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200}} =
        katipo:head(?POOL, httpbin_url(Config, <<"/get">>), #{http_version => HTTPVersion}).

post_body_binary(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, httpbin_url(Config, <<"/post">>),
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => <<"!@#$%^&*()">>,
                      http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

post_body_iolist(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, httpbin_url(Config, <<"/post">>),
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => ["foo", $b, $a, $r, <<"baz">>],
                      http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    <<"foobarbaz">> = proplists:get_value(<<"data">>, Json).

post_body_qs_vals(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, httpbin_url(Config, <<"/post">>),
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => [<<"!@#$%">>, <<"^&*()">>],
                      http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

post_body_bad(_) ->
    Message = [{body, should_not_be_an_atom}],
    BinaryMessage = iolist_to_binary(io_lib:format("~p", [Message])),
    {error, #{code := bad_opts, message := BinaryMessage}} =
        katipo:post(?POOL, <<"https://httpbin.org/post">>,
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => should_not_be_an_atom}).

post_arity_2(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, httpbin_url(Config, <<"/post">>), #{http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    undefined = proplists:get_value(<<>>, Json).

post_qs(Config) ->
    HTTPVersion = ?config(http_version, Config),
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, httpbin_url(Config, <<"/post">>), #{body => QsVals, http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

post_qs_invalid(_) ->
    QsVals = [{hi, <<"bar">>}],
    {error, #{code := bad_opts}} =
        katipo:post(?POOL, <<"https://httpbin.org/post">>, #{body => QsVals}).

post_req(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:req(?POOL, #{url => httpbin_url(Config, <<"/post">>),
                            method => post,
                            headers => [{<<"Content-Type">>, <<"application/json">>}],
                            body => <<"!@#$%^&*()">>,
                            http_version => HTTPVersion}),
    Json = jsx:decode(Body),
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

put_data(Config) ->
    HTTPVersion = ?config(http_version, Config),
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:put(?POOL, httpbin_url(Config, <<"/put">>),
                   #{headers => Headers, body => <<"!@#$%^&*()">>, http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

put_arity_2(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:put(?POOL, httpbin_url(Config, <<"/put">>), #{http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    undefined = proplists:get_value(<<>>, Json).

put_qs(Config) ->
    HTTPVersion = ?config(http_version, Config),
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:put(?POOL, httpbin_url(Config, <<"/put">>), #{body => QsVals, http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

patch_data(Config) ->
    HTTPVersion = ?config(http_version, Config),
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:patch(?POOL, httpbin_url(Config, <<"/patch">>),
                   #{headers => Headers, body => <<"!@#$%^&*()">>, http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

patch_arity_2(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:patch(?POOL, httpbin_url(Config, <<"/patch">>), #{http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    <<>> = proplists:get_value(<<"data">>, Json).

patch_qs(Config) ->
    HTTPVersion = ?config(http_version, Config),
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:patch(?POOL, httpbin_url(Config, <<"/patch">>), #{body => QsVals, http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

options(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, headers := Headers}} = katipo:options(?POOL, httpbin_url(Config, <<"/get">>), #{http_version => HTTPVersion}),
    Lowercase = lists:map(fun({K, V}) -> {string:lowercase(K), V} end, Headers),
    %% Different httpbin servers have different header capitalisations
    <<"GET, POST, PUT, DELETE, PATCH, OPTIONS">> =
        proplists:get_value(<<"access-control-allow-methods">>, Lowercase).

delete(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200}} = katipo:delete(?POOL, httpbin_url(Config, <<"/delete">>), #{http_version => HTTPVersion}).

headers(Config) ->
    Url = httpbin_url(Config, <<"/gzip">>),
    Parsed = uri_string:parse(Url),
    Host = maps:get(host, Parsed),
    HTTPVersion = ?config(http_version, Config),
    Headers = [{<<"header1">>, <<"!@#$%^&*()">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, Url, #{headers => Headers, http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    Expected =  [{<<"Accept">>,<<"*/*">>},
                 {<<"Header1">>,<<"!@#$%^&*()">>},
                 {<<"Host">>,Host}],
    [] = Expected -- proplists:get_value(<<"headers">>, Json).

header_remove(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    Parsed = uri_string:parse(Url),
    Host = maps:get(host, Parsed),
    HTTPVersion = ?config(http_version, Config),
    Headers = [{<<"Accept-Encoding">>, <<>>}],
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, Url, #{headers => Headers, http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    Expected =  [{<<"Accept">>,<<"*/*">>},
                 {<<"Host">>,Host}],
    [] = Expected -- proplists:get_value(<<"headers">>, Json).

gzip(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/gzip">>), #{http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    true = proplists:get_value(<<"gzipped">>, Json).

deflate(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/deflate">>), #{http_version => HTTPVersion}),
    Json = jsx:decode(Body),
    true = proplists:get_value(<<"deflated">>, Json).

bytes(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/bytes/1024?seed=9999">>), #{http_version => HTTPVersion}),
    1024 = byte_size(Body),
    <<168,123,193,120,18,120,65,73,67,119,198,61,39,1,24,169>> = crypto:hash(md5, Body).

stream_bytes(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/bytes/1024?seed=9999&chunk_size=8">>), #{http_version => HTTPVersion}),
    1024 = byte_size(Body),
    <<168,123,193,120,18,120,65,73,67,119,198,61,39,1,24,169>> = crypto:hash(md5, Body).

utf8(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/encoding/utf8">>), #{http_version => HTTPVersion}),
    case xmerl_ucs:from_utf8(Body) of
        [_|_] -> ok
    end.

stream(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/stream/20">>), #{http_version => HTTPVersion}),
    20 = length(binary:split(Body, <<"\n">>, [global, trim])).

statuses(Config) ->
    HTTPVersion = ?config(http_version, Config),
    MFAs = [begin
                B = integer_to_binary(S),
                Url = httpbin_url(Config, <<"/status/",B/binary>>),
                {katipo, get, [?POOL, Url, #{http_version => HTTPVersion}]}
            end || S <- http_status_codes()],
    Results = rpc:parallel_eval(MFAs),
    Results2 = [S || {ok, #{status := S}} <- Results],
    Results2 = http_status_codes().

cookies(Config) ->
    HTTPVersion = ?config(http_version, Config),
    Url = httpbin_url(Config, <<"/cookies/set?cname=cvalue">>),
    Opts = #{followlocation => true, http_version => HTTPVersion},
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, Url, Opts),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [{<<"cname">>, <<"cvalue">>}] = proplists:get_value(<<"cookies">>, Json).

cookies_delete(Config) ->
    HTTPVersion = ?config(http_version, Config),
    GetUrl = httpbin_url(Config, <<"/cookies/set?cname=cvalue">>),
    Opts = #{followlocation => true, http_version => HTTPVersion},
    {ok, #{status := 200, cookiejar := CookieJar}} = katipo:get(?POOL, GetUrl, Opts),
    DeleteUrl = httpbin_url(Config, <<"/cookies/delete?cname">>),
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, DeleteUrl, #{cookiejar => CookieJar, followlocation => true}),
    Json = jsx:decode(Body, [{return_maps, false}]),
    [{}] = proplists:get_value(<<"cookies">>, Json).

cookies_bad_cookie_jar(_) ->
    Url = <<"http://httpbin.org/cookies/delete?cname">>,
    CookieJar = ["has to be a binary"],
    Message = <<"[{cookiejar,[\"has to be a binary\"]}]">>,
    {error, #{code := bad_opts, message := Message}} =
        katipo:get(?POOL, Url, #{cookiejar => CookieJar}).

redirect_to(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 302}} = katipo:get(?POOL, httpbin_url(Config, <<"/redirect-to?url=https://google.com">>), #{http_version => HTTPVersion}).

connecttimeout_ms(_) ->
    {error, #{code := operation_timedout}} =
        katipo:get(?POOL, <<"http://google.com">>, #{connecttimeout_ms => 1}).

followlocation_true(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 200}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/redirect/6">>), #{followlocation => true, http_version => HTTPVersion}).

followlocation_false(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 302}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/redirect/6">>), #{followlocation => false, http_version => HTTPVersion}).

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

maxredirs(Config) ->
    HTTPVersion = ?config(http_version, Config),
    Opts = #{followlocation => true, maxredirs => 2, http_version => HTTPVersion},
    {error, #{code := too_many_redirects, message := <<"Maximum (2) redirects followed">>}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/redirect/6">>), Opts).

basic_unauthorised(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 401}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/basic-auth/johndoe/p455w0rd">>), #{http_version => HTTPVersion}).

basic_authorised(Config) ->
    HTTPVersion = ?config(http_version, Config),
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/basic-auth/johndoe/p455w0rd">>),
                  #{http_auth => basic, username => Username, password => Password, http_version => HTTPVersion}),
    Json = jsx:decode(Body),
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

digest_unauthorised(Config) ->
    HTTPVersion = ?config(http_version, Config),
    {ok, #{status := 401}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/digest-auth/auth/johndoe/p455w0rd">>), #{http_version => HTTPVersion}).

digest_authorised(Config) ->
    HTTPVersion = ?config(http_version, Config),
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/digest-auth/auth/johndoe/p455w0rd">>),
                  #{http_auth => digest, username => Username, password => Password, http_version => HTTPVersion}),
    Json = jsx:decode(Body),
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

timeout_ms(Config) ->
    HTTPVersion = ?config(http_version, Config),
    ok = case katipo:get(?POOL, httpbin_url(Config, <<"/delay/1">>), #{timeout_ms => 500, http_version => HTTPVersion}) of
             {error, #{code := operation_timedout}} ->
                 ok;
             %% http2 seems to return this when it times out
             {error, #{code := couldnt_connect}} ->
                 ok
         end.

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
         katipo:get(?POOL, <<"https://self-signed.badssl.com/">>,
                    #{ssl_verifyhost => true, ssl_verifypeer => true}),
    %% TODO: this could be made to reflect the ifdef from katipo.c...
    ok = case Code of
             ssl_cacert -> ok;
             peer_failed_verification -> ok
         end,
    {error, #{code := Code}} =
         katipo:get(?POOL, <<"https://self-signed.badssl.com/">>,
                    #{ssl_verifyhost => false, ssl_verifypeer => true}),
    ok = case Code of
             ssl_cacert -> ok;
             peer_failed_verification -> ok
         end,
    {ok, #{status := 200}} =
        katipo:get(?POOL, <<"https://self-signed.badssl.com/">>,
                   #{ssl_verifyhost => true, ssl_verifypeer => false}),
    {ok, #{status := 200}} =
        katipo:get(?POOL, <<"https://self-signed.badssl.com/">>,
                   #{ssl_verifyhost => false, ssl_verifypeer => false}).

cacert_self_signed(Config) ->
    CACert = ?config(cacert_file, Config),
    {ok, #{status := 301}} =
        katipo:get(?POOL, <<"https://google.com">>,
                   #{ssl_verifyhost => true, ssl_verifypeer => true, cacert => CACert}).

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

metrics_true(_) ->
    ok = meck:new(metrics, [passthrough]),
    ok = meck:expect(metrics, update_or_create,
                     fun(X, _, spiral) when X =:= "katipo.status.200" orelse
                                            X =:= "katipo.ok" ->
                             ok;
                        (X, _, histogram) when X =:= "katipo.curl_time" orelse
                                               X =:= "katipo.total_time" orelse
                                               X =:= "katipo.namelookup_time" orelse
                                               X =:= "katipo.connect_time" orelse
                                               X =:= "katipo.appconnect_time" orelse
                                               X =:= "katipo.pretransfer_time" orelse
                                               X =:= "katipo.redirect_time" orelse
                                               X =:= "katipo.starttransfer_time" ->
                             ok
                     end),
    {ok, #{status := 200, metrics := Metrics}} =
        katipo:head(?POOL, <<"https://httpbin.org/get">>, #{return_metrics => true}),
    10 = meck:num_calls(metrics, update_or_create, 3),
    MetricKeys = [K || {K, _} <- Metrics],
    ExpectedMetricKeys = [curl_time,total_time,namelookup_time,connect_time,
                          appconnect_time,pretransfer_time,redirect_time,
                          starttransfer_time],
    true = lists:sort(MetricKeys) == lists:sort(ExpectedMetricKeys),
    meck:unload(metrics).

metrics_false(_) ->
    {ok, #{status := 200} = Res} =
        katipo:head(?POOL, <<"https://httpbin.org/get">>, #{return_metrics => false}),
    false = maps:is_key(metrics, Res).

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

httpbin_url(Config, Path) ->
    Base = ?config(httpbin_base, Config),
    <<Base/binary, Path/binary>>.
