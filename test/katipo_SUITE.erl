-module(katipo_SUITE).

-compile([{nowarn_export_all, true}]).
-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("opentelemetry/include/otel_span.hrl").

-define(POOL, katipo_test_pool).
-define(POOL_SIZE, 2).

suite() ->
    [{timetrap, {seconds, 30}}].

init_per_suite(Config) ->
    %% Start OpenTelemetry SDKs for proper metrics/tracing support in tests
    application:ensure_all_started(opentelemetry),
    application:ensure_all_started(opentelemetry_experimental),
    application:ensure_all_started(katipo),
    application:ensure_all_started(meck),
    {ok, _} = katipo_pool:start(?POOL, ?POOL_SIZE),
    DataDir = ?config(data_dir, Config),
    CACert = filename:join(DataDir, "ca-bundle.crt"),
    %% Use local httpbin instance (must be started manually with docker-compose)
    HttpbinBase = <<"https://localhost:8443">>,
    HttpbinOpts = #{ssl_verifyhost => false, ssl_verifypeer => false},
    [{cacert_file, list_to_binary(CACert)},
     {httpbin_base, HttpbinBase},
     {httpbin_opts, HttpbinOpts} | Config].

end_per_suite(_Config) ->
    ok = application:stop(katipo).

init_per_group(otel, Config) ->
    %% OTel tests will configure their own exporters since each test
    %% runs in its own process
    Config;
init_per_group(curl, Config) ->
    application:ensure_all_started(cowboy),
    Filename = tempfile:name("katipo_test_"),
    Name = make_ref(),
    Dispatch = cowboy_router:compile([{'_', [{"/unix", get_handler, []}]}]),
    {ok, _} = cowboy:start_clear(Name, [{ip, {local, Filename}},
                                        {port, 0}], #{env => #{dispatch => Dispatch}}),
    [{unix_socket_file, Filename}, {unix_server_name, Name}] ++ Config;
init_per_group(pool, Config) ->
    application:ensure_all_started(meck),
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
    %% Use local httpbin instance for HTTP/1.1 tests
    [{httpbin_base, <<"https://localhost:8443">>},
     {req_opts, #{http_version => curl_http_version_1_1,
                  ssl_verifyhost => false,
                  ssl_verifypeer => false}}] ++ Config;
init_per_group(http2, Config) ->
    %% Use local httpbin instance for HTTP/2 tests
    [{httpbin_base, <<"https://localhost:8443">>},
     {req_opts, #{http_version => curl_http_version_2_prior_knowledge,
                  ssl_verifyhost => false,
                  ssl_verifypeer => false}}] ++ Config;
init_per_group(http3, Config) ->
    %% Use local httpbin instance for HTTP/3 tests
    %% Disable SSL verification since we use self-signed certs
    [{httpbin_base, <<"https://localhost:8443">>},
     {req_opts, #{http_version => curl_http_version_3,
                  ssl_verifyhost => false,
                  ssl_verifypeer => false}}] ++ Config;
init_per_group(digest, Config) ->
    %% Digest auth tests using local httpbin
    [{httpbin_base, <<"https://localhost:8443">>},
     {req_opts, #{http_version => curl_http_version_1_1,
                  ssl_verifyhost => false,
                  ssl_verifypeer => false}}] ++ Config;
init_per_group(_, Config) ->
    Config.

end_per_group(otel, Config) ->
    Config;
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
       protocol_restriction,
       dns_cache_timeout,
       ca_cache_timeout,
       pipewait]},
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
       max_pipeline_length,
       max_concurrent_streams]},
     {https, [parallel],
      [verify_host_verify_peer_ok,
       %% TODO :Fix this test. See https://github.com/puzza007/katipo/runs/5281801454?check_suite_focus=true
       %% verify_host_verify_peer_error,
       %% TODO: Fix this test. See https://github.com/puzza007/katipo/runs/5281750037?check_suite_focus=true
       %% cacert_self_signed,
       capath,
       sslversion,
       badssl]},
     {https_mutual, [],
      [badssl_client_cert]},
     {port, [],
      [max_total_connections]},
     {otel, [],
      [otel_span_created,
       otel_metrics_recorded,
       otel_url_sanitization]},
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
    BaseGroups = [{group, http1},
                  {group, curl},
                  {group, digest},
                  {group, pool},
                  {group, https_mutual},
                  {group, port},
                  {group, otel}],
    %% HTTP/2 tests always run (local httpbin supports HTTP/2)
    Http2Groups = [{group, http2}],
    %% HTTP/3 tests run when KATIPO_TEST_HTTP3 is set
    %% (requires curl with HTTP/3 support)
    Http3Groups = case os:getenv("KATIPO_TEST_HTTP3") of
        false -> [];
        _ -> [{group, http3}]
    end,
    BaseGroups ++ Http2Groups ++ Http3Groups.

get(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>), Opts),
    Json = jsx:decode(Body),
    ?assertEqual(<<"!@#$%^&*()_+">>, maps:get(<<"a">>, maps:get(<<"args">>, Json))).

get_http(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>), Opts),
    Json = jsx:decode(Body),
    ?assertEqual(<<"!@#$%^&*()_+">>, maps:get(<<"a">>, maps:get(<<"args">>, Json))).

get_req(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    Url = httpbin_url(Config, <<"/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>),
    {ok, #{status := 200, body := Body}} =
        katipo:req(?POOL, Opts#{url => Url}),
    Json = jsx:decode(Body),
    ?assertEqual(<<"!@#$%^&*()_+">>, maps:get(<<"a">>, maps:get(<<"args">>, Json))).

head(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200}} =
        katipo:head(?POOL, httpbin_url(Config, <<"/get">>), Opts).

post_body_binary(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, httpbin_url(Config, <<"/post">>),
                    Opts#{headers => [{<<"Content-Type">>, <<"application/json">>}],
                          body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body),
    ?assertEqual(<<"!@#$%^&*()">>, maps:get(<<"data">>, Json)).

post_body_iolist(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, httpbin_url(Config, <<"/post">>),
                    Opts#{headers => [{<<"Content-Type">>, <<"application/json">>}],
                          body => ["foo", $b, $a, $r, <<"baz">>]}),
    Json = jsx:decode(Body),
    ?assertEqual(<<"foobarbaz">>, maps:get(<<"data">>, Json)).

post_body_qs_vals(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, httpbin_url(Config, <<"/post">>),
                    Opts#{headers => [{<<"Content-Type">>, <<"application/json">>}],
                          body => [<<"!@#$%">>, <<"^&*()">>]}),
    Json = jsx:decode(Body),
    ?assertEqual(<<"!@#$%^&*()">>, maps:get(<<"data">>, Json)).

post_body_bad(_) ->
    Message = [{body, should_not_be_an_atom}],
    BinaryMessage = iolist_to_binary(io_lib:format("~p", [Message])),
    %% URL doesn't matter - request fails during option validation
    {error, #{code := bad_opts, message := BinaryMessage}} =
        katipo:post(?POOL, <<"https://localhost/post">>,
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => should_not_be_an_atom}).

post_arity_2(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, httpbin_url(Config, <<"/post">>), Opts),
    Json = jsx:decode(Body),
    ?assertNot(maps:is_key(<<>>, Json)).

post_qs(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:post(?POOL, httpbin_url(Config, <<"/post">>), Opts#{body => QsVals}),
    Json = jsx:decode(Body),
    Form = maps:get(<<"form">>, Json),
    ?assertEqual(<<>>, maps:get(<<"baz">>, Form)),
    ?assertEqual(<<"bar">>, maps:get(<<"foo">>, Form)).

post_qs_invalid(_) ->
    QsVals = [{hi, <<"bar">>}],
    %% URL doesn't matter - request fails during option validation
    {error, #{code := bad_opts}} =
        katipo:post(?POOL, <<"https://localhost/post">>, #{body => QsVals}).

post_req(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:req(?POOL, Opts#{url => httpbin_url(Config, <<"/post">>),
                                method => post,
                                headers => [{<<"Content-Type">>, <<"application/json">>}],
                                body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body),
    ?assertEqual(<<"!@#$%^&*()">>, maps:get(<<"data">>, Json)).

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
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:put(?POOL, httpbin_url(Config, <<"/put">>),
                   Opts#{headers => Headers, body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body),
    ?assertEqual(<<"!@#$%^&*()">>, maps:get(<<"data">>, Json)).

put_arity_2(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:put(?POOL, httpbin_url(Config, <<"/put">>), Opts),
    Json = jsx:decode(Body),
    ?assertNot(maps:is_key(<<>>, Json)).

put_qs(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:put(?POOL, httpbin_url(Config, <<"/put">>), Opts#{body => QsVals}),
    Json = jsx:decode(Body),
    Form = maps:get(<<"form">>, Json),
    ?assertEqual(<<>>, maps:get(<<"baz">>, Form)),
    ?assertEqual(<<"bar">>, maps:get(<<"foo">>, Form)).

patch_data(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:patch(?POOL, httpbin_url(Config, <<"/patch">>),
                   Opts#{headers => Headers, body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body),
    ?assertEqual(<<"!@#$%^&*()">>, maps:get(<<"data">>, Json)).

patch_arity_2(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} =
        katipo:patch(?POOL, httpbin_url(Config, <<"/patch">>), Opts),
    Json = jsx:decode(Body),
    ?assertEqual(<<>>, maps:get(<<"data">>, Json)).

patch_qs(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:patch(?POOL, httpbin_url(Config, <<"/patch">>), Opts#{body => QsVals}),
    Json = jsx:decode(Body),
    Form = maps:get(<<"form">>, Json),
    ?assertEqual(<<>>, maps:get(<<"baz">>, Form)),
    ?assertEqual(<<"bar">>, maps:get(<<"foo">>, Form)).

options(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, headers := Headers}} = katipo:options(?POOL, httpbin_url(Config, <<"/get">>), Opts),
    HeadersMap = maps:from_list([{string:lowercase(K), V} || {K, V} <- Headers]),
    %% Different httpbin servers have different header capitalisations
    ?assertEqual(<<"GET, POST, PUT, DELETE, PATCH, OPTIONS">>,
                 maps:get(<<"access-control-allow-methods">>, HeadersMap)).

delete(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200}} = katipo:delete(?POOL, httpbin_url(Config, <<"/delete">>), Opts).

headers(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    Url = httpbin_url(Config, <<"/gzip">>),
    Parsed = uri_string:parse(Url),
    Host = maps:get(host, Parsed),
    %% Include port in expected Host header when non-standard port is used
    ExpectedHost = case maps:find(port, Parsed) of
        {ok, Port} when Port =/= 443 andalso Port =/= 80 ->
            iolist_to_binary([Host, ":", integer_to_list(Port)]);
        _ ->
            Host
    end,
    Headers = [{<<"header1">>, <<"!@#$%^&*()">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, Url, Opts#{headers => Headers}),
    Json = jsx:decode(Body),
    RespHeaders = maps:get(<<"headers">>, Json),
    ?assertEqual(<<"*/*">>, maps:get(<<"Accept">>, RespHeaders)),
    ?assertEqual(<<"!@#$%^&*()">>, maps:get(<<"Header1">>, RespHeaders)),
    ?assertEqual(ExpectedHost, maps:get(<<"Host">>, RespHeaders)).

header_remove(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    Url = httpbin_url(Config, <<"/get">>),
    Parsed = uri_string:parse(Url),
    Host = maps:get(host, Parsed),
    %% Include port in expected Host header when non-standard port is used
    ExpectedHost = case maps:find(port, Parsed) of
        {ok, Port} when Port =/= 443 andalso Port =/= 80 ->
            iolist_to_binary([Host, ":", integer_to_list(Port)]);
        _ ->
            Host
    end,
    Headers = [{<<"Accept-Encoding">>, <<>>}],
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, Url, Opts#{headers => Headers}),
    Json = jsx:decode(Body),
    RespHeaders = maps:get(<<"headers">>, Json),
    ?assertEqual(<<"*/*">>, maps:get(<<"Accept">>, RespHeaders)),
    ?assertEqual(ExpectedHost, maps:get(<<"Host">>, RespHeaders)).

gzip(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/gzip">>), Opts),
    Json = jsx:decode(Body),
    ?assert(maps:get(<<"gzipped">>, Json)).

deflate(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/deflate">>), Opts),
    Json = jsx:decode(Body),
    ?assert(maps:get(<<"deflated">>, Json)).

bytes(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/bytes/1024?seed=9999">>), Opts),
    1024 = byte_size(Body),
    <<168,123,193,120,18,120,65,73,67,119,198,61,39,1,24,169>> = crypto:hash(md5, Body).

stream_bytes(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/bytes/1024?seed=9999&chunk_size=8">>), Opts),
    1024 = byte_size(Body),
    <<168,123,193,120,18,120,65,73,67,119,198,61,39,1,24,169>> = crypto:hash(md5, Body).

utf8(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/encoding/utf8">>), Opts),
    case xmerl_ucs:from_utf8(Body) of
        [_|_] -> ok
    end.

stream(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, httpbin_url(Config, <<"/stream/20">>), Opts),
    20 = length(binary:split(Body, <<"\n">>, [global, trim])).

statuses(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    %% Test a subset of status codes sequentially to avoid overwhelming
    %% the httpbin server and test framework. Previously used rpc:parallel_eval
    %% which caused test framework crashes when running in parallel groups.
    StatusCodes = [200, 201, 204, 301, 302, 400, 401, 404, 500, 502],
    Results = [begin
                   B = integer_to_binary(S),
                   Url = httpbin_url(Config, <<"/status/",B/binary>>),
                   {ok, #{status := S}} = katipo:get(?POOL, Url, Opts),
                   S
               end || S <- StatusCodes],
    ?assertEqual(StatusCodes, Results).

cookies(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    Url = httpbin_url(Config, <<"/cookies/set?cname=cvalue">>),
    {ok, #{status := 200, body := Body}} = katipo:get(?POOL, Url, Opts#{followlocation => true}),
    Json = jsx:decode(Body),
    ?assertEqual(#{<<"cname">> => <<"cvalue">>}, maps:get(<<"cookies">>, Json)).

cookies_delete(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    GetUrl = httpbin_url(Config, <<"/cookies/set?cname=cvalue">>),
    {ok, #{status := 200, cookiejar := CookieJar}} = katipo:get(?POOL, GetUrl, Opts#{followlocation => true}),
    DeleteUrl = httpbin_url(Config, <<"/cookies/delete?cname">>),
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, DeleteUrl, Opts#{cookiejar => CookieJar, followlocation => true}),
    Json = jsx:decode(Body),
    ?assertEqual(#{}, maps:get(<<"cookies">>, Json)).

cookies_bad_cookie_jar(_) ->
    %% URL doesn't matter - request fails during option validation
    Url = <<"https://localhost/cookies/delete?cname">>,
    CookieJar = ["has to be a binary"],
    Message = <<"[{cookiejar,[\"has to be a binary\"]}]">>,
    {error, #{code := bad_opts, message := Message}} =
        katipo:get(?POOL, Url, #{cookiejar => CookieJar}).

redirect_to(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 302}} = katipo:get(?POOL, httpbin_url(Config, <<"/redirect-to?url=https://google.com">>), Opts).

connecttimeout_ms(_) ->
    {error, #{code := operation_timedout}} =
        katipo:get(?POOL, <<"http://google.com">>, #{connecttimeout_ms => 1}).

followlocation_true(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 200}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/redirect/6">>), Opts#{followlocation => true}).

followlocation_false(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 302}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/redirect/6">>), Opts#{followlocation => false}).

tcp_fastopen_true(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    BaseOpts = ?config(httpbin_opts, Config),
    case katipo:get(?POOL, Url, BaseOpts#{tcp_fastopen => true}) of
        {ok, #{}} ->
            ok;
        {error, #{code := bad_opts}} ->
            ct:pal("tcp_fastopen not supported by installed version of curl"),
            ok
    end.


tcp_fastopen_false(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    BaseOpts = ?config(httpbin_opts, Config),
    case katipo:get(?POOL, Url, BaseOpts#{tcp_fastopen => false}) of
        {ok, #{}} ->
            ok;
        {error, #{code := bad_opts}} ->
            ct:pal("tcp_fastopen not supported by installed version of curl"),
            ok
    end.

interface(_Config) ->
    %% Interface binding test requires an external URL (not localhost)
    %% because localhost traffic uses the loopback interface, not physical interfaces
    Url = <<"https://httpbin.org/get">>,
    Interface = case os:type() of
                    {unix, darwin} ->
                        <<"en0">>;
                    {unix, linux} ->
                        %% Try common interface names: ens5 (GitHub Actions/AWS),
                        %% eth0 (traditional), ens4 (GCP)
                        find_linux_interface([<<"ens5">>, <<"eth0">>, <<"ens4">>]);
                    _ ->
                        erlang:error({unknown_operating_system, fixme})
                end,
    {ok, #{}} = katipo:get(?POOL, Url, #{interface => Interface}).

find_linux_interface([]) ->
    <<"eth0">>; %% fallback
find_linux_interface([Iface | Rest]) ->
    Path = <<"/sys/class/net/", Iface/binary>>,
    case filelib:is_dir(binary_to_list(Path)) of
        true -> Iface;
        false -> find_linux_interface(Rest)
    end.

interface_unknown(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    BaseOpts = ?config(httpbin_opts, Config),
    {error, #{code := interface_failed}} =
        katipo:get(?POOL, Url, BaseOpts#{interface => <<"cannot_be_an_interface">>}).

unix_socket_path(Config) ->
    Filename = list_to_binary(?config(unix_socket_file, Config)),
    case katipo:get(?POOL, <<"http://localhost/unix">>, #{unix_socket_path => Filename}) of
        {ok, #{status := 200, headers := Headers}} ->
            HeadersMap = maps:from_list(Headers),
            ?assertEqual(<<"Cowboy">>, maps:get(<<"server">>, HeadersMap));
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
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    %% Message may include SSL warnings with self-signed certs, so just check the code
    {error, #{code := too_many_redirects}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/redirect/6">>), Opts#{followlocation => true, maxredirs => 2}).

basic_unauthorised(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 401}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/basic-auth/johndoe/p455w0rd">>), Opts).

basic_authorised(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/basic-auth/johndoe/p455w0rd">>),
                  Opts#{http_auth => basic, username => Username, password => Password}),
    Json = jsx:decode(Body),
    ?assert(maps:get(<<"authenticated">>, Json)),
    ?assertEqual(Username, maps:get(<<"user">>, Json)).

basic_authorised_userpwd(Config) ->
    BaseOpts = ?config(httpbin_opts, Config),
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/basic-auth/johndoe/p455w0rd">>),
                  BaseOpts#{http_auth => basic, userpwd => <<Username/binary,":",Password/binary>>}),
    Json = jsx:decode(Body),
    ?assert(maps:get(<<"authenticated">>, Json)),
    ?assertEqual(Username, maps:get(<<"user">>, Json)).

digest_unauthorised(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    {ok, #{status := 401}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/digest-auth/auth/johndoe/p455w0rd">>), Opts).

digest_authorised(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/digest-auth/auth/johndoe/p455w0rd">>),
                  Opts#{http_auth => digest, username => Username, password => Password}),
    Json = jsx:decode(Body),
    ?assert(maps:get(<<"authenticated">>, Json)),
    ?assertEqual(Username, maps:get(<<"user">>, Json)).

digest_authorised_userpwd(Config) ->
    BaseOpts = ?config(httpbin_opts, Config),
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, httpbin_url(Config, <<"/digest-auth/auth/johndoe/p455w0rd">>),
                  BaseOpts#{http_auth => digest, userpwd => <<Username/binary,":",Password/binary>>}),
    Json = jsx:decode(Body),
    ?assert(maps:get(<<"authenticated">>, Json)),
    ?assertEqual(Username, maps:get(<<"user">>, Json)).

lock_data_ssl_session_true(Config) ->
    BaseOpts = ?config(httpbin_opts, Config),
    Url = httpbin_url(Config, <<"/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>),
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, Url, BaseOpts#{lock_data_ssl_session => true}),
    Json = jsx:decode(Body),
    ?assertEqual(<<"!@#$%^&*()_+">>, maps:get(<<"a">>, maps:get(<<"args">>, Json))).

lock_data_ssl_session_false(Config) ->
    BaseOpts = ?config(httpbin_opts, Config),
    Url = httpbin_url(Config, <<"/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>),
    {ok, #{status := 200, body := Body}} =
        katipo:get(?POOL, Url, BaseOpts#{lock_data_ssl_session => false}),
    Json = jsx:decode(Body),
    ?assertEqual(<<"!@#$%^&*()_+">>, maps:get(<<"a">>, maps:get(<<"args">>, Json))).

doh_url(_) ->
    case katipo:doh_url_available() of
        true ->
            {ok, #{status := 301}} =
                katipo:get(?POOL, <<"https://google.com">>,
                           #{doh_url => <<"https://1.1.1.1/dns-query">>});
        false ->
            ok
    end.

badopts(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    BaseOpts = ?config(httpbin_opts, Config),
    {error, #{code := bad_opts, message := Message}} =
        katipo:get(?POOL, Url, BaseOpts#{timeout_ms => <<"wrong">>, what => not_even_close}),
    {ok, Tokens, _} = erl_scan:string(binary_to_list(Message) ++ "."),
    {ok, L} = erl_parse:parse_term(Tokens),
    [] = L -- [{what, not_even_close}, {timeout_ms, <<"wrong">>}].

proxy_couldnt_connect(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    BaseOpts = ?config(httpbin_opts, Config),
    {error, #{code := couldnt_connect}} =
        katipo:get(?POOL, Url, BaseOpts#{proxy => <<"http://localhost:3128">>}).

protocol_restriction(_) ->
    {error, #{code := unsupported_protocol}} = katipo:get(?POOL, <<"dict.org">>).

dns_cache_timeout(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    BaseOpts = ?config(httpbin_opts, Config),
    %% cache disabled
    {ok, #{status := 200}} = katipo:get(?POOL, Url, BaseOpts#{dns_cache_timeout => 0}),
    %% 120 second cache
    {ok, #{status := 200}} = katipo:get(?POOL, Url, BaseOpts#{dns_cache_timeout => 120}),
    %% forever cache
    {ok, #{status := 200}} = katipo:get(?POOL, Url, BaseOpts#{dns_cache_timeout => -1}).

ca_cache_timeout(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    BaseOpts = ?config(httpbin_opts, Config),
    %% cache disabled
    {ok, #{status := 200}} = katipo:get(?POOL, Url, BaseOpts#{ca_cache_timeout => 0}),
    %% 1 hour cache
    {ok, #{status := 200}} = katipo:get(?POOL, Url, BaseOpts#{ca_cache_timeout => 3600}),
    %% forever cache
    {ok, #{status := 200}} = katipo:get(?POOL, Url, BaseOpts#{ca_cache_timeout => -1}).

pipewait(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    BaseOpts = ?config(httpbin_opts, Config),
    %% pipewait enabled (default)
    {ok, #{status := 200}} = katipo:get(?POOL, Url, BaseOpts#{pipewait => true}),
    %% pipewait disabled
    {ok, #{status := 200}} = katipo:get(?POOL, Url, BaseOpts#{pipewait => false}).

timeout_ms(Config) ->
    {req_opts, Opts} = lists:keyfind(req_opts, 1, Config),
    ok = case katipo:get(?POOL, httpbin_url(Config, <<"/delay/1">>), Opts#{timeout_ms => 500}) of
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

worker_death(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    BaseOpts = ?config(httpbin_opts, Config),
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
                   {ok, #{status := 200}} = katipo:get(?POOL, Url, BaseOpts),
                   true
           end,
    true = repeat_until_true(Fun3).

port_death(Config) ->
    Url = httpbin_url(Config, <<"/get">>),
    BaseOpts = ?config(httpbin_opts, Config),
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
                              katipo:get(PoolName, Url, BaseOpts),
                          true
                  end
          end,
    true = repeat_until_true(Fun),
    ok = katipo_pool:stop(PoolName).

port_late_response(Config) ->
    Url = httpbin_url(Config, <<"/delay/1">>),
    BaseOpts = ?config(httpbin_opts, Config),
    ok = meck:new(katipo, [passthrough]),
    meck:expect(katipo, get_timeout, fun(_) -> 100 end),
    {error, #{code := operation_timedout, message := <<>>}} =
        katipo:get(?POOL, Url, BaseOpts),
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

max_concurrent_streams(_) ->
    PoolName = pool_max_streams,
    PoolSize = 1,
    PoolOpts = [{pipelining, multiplex},
                {max_concurrent_streams, 50}],
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

capath(Config) ->
    %% Test the capath option which specifies a directory containing CA certs
    %% The capath directory contains pre-split certificates with hash symlinks
    %% (created by openssl rehash). This avoids needing openssl rehash at runtime.
    DataDir = ?config(data_dir, Config),
    CAPath = list_to_binary(filename:join(DataDir, "capath")),
    {ok, #{status := 301}} =
        katipo:get(?POOL, <<"https://google.com">>,
                   #{ssl_verifyhost => true,
                     ssl_verifypeer => true,
                     capath => CAPath}).

sslversion(_) ->
    %% Test the sslversion option to set minimum TLS version
    %% TLS 1.2 should work with most modern servers
    {ok, #{status := 301}} =
        katipo:get(?POOL, <<"https://google.com">>,
                   #{sslversion => sslversion_tlsv1_2}),
    %% TLS 1.3 should also work with google.com
    {ok, #{status := 301}} =
        katipo:get(?POOL, <<"https://google.com">>,
                   #{sslversion => sslversion_tlsv1_3}),
    %% badssl.com has endpoints that only support specific TLS versions
    %% tls-v1-2.badssl.com:1012 only supports TLS 1.2
    %% Requiring TLS 1.3 minimum should fail against a TLS 1.2-only server
    {error, #{code := ssl_connect_error}} =
        katipo:get(?POOL, <<"https://tls-v1-2.badssl.com:1012/">>,
                   #{sslversion => sslversion_tlsv1_3,
                     ssl_verifyhost => false,
                     ssl_verifypeer => false}).

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
    %% Certificate provided but no key - different curl versions return different errors
    {error, #{code := Code1}} =
        katipo:get(?POOL, <<"https://client.badssl.com">>,
                   #{ssl_verifyhost => true,
                     ssl_verifypeer => true,
                     sslcert => CertFile}),
    ?assert(Code1 =:= ssl_certproblem orelse Code1 =:= bad_function_argument),
    %% This key requires a passphrase - different curl versions return different errors
    {error, #{code := Code2}} =
        katipo:get(?POOL, <<"https://client.badssl.com">>,
                   #{ssl_verifyhost => true,
                     ssl_verifypeer => true,
                     sslcert => CertFile,
                     sslkey => KeyFile}),
    ?assert(Code2 =:= ssl_certproblem orelse Code2 =:= bad_function_argument),
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

max_total_connections(Config) ->
    PoolName = max_total_connections,
    {ok, _} = katipo_pool:start(PoolName, 1, [{pipelining, nothing}, {max_total_connections, 1}]),
    Url = httpbin_url(Config, <<"/delay/5">>),
    BaseOpts = ?config(httpbin_opts, Config),
    Self = self(),
    Fun = fun() ->
                  {ok, #{status := 200}} =
                      katipo:get(PoolName, Url, BaseOpts),
                  Self ! ok
          end,
    spawn(Fun),
    spawn(Fun),
    Start = erlang:system_time(seconds),
    [receive ok -> ok end || _ <- [1, 2]],
    Diff = erlang:system_time(seconds) - Start,
    ok = katipo_pool:stop(PoolName),
    true = Diff >= 10.

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

%% OpenTelemetry integration tests

otel_span_created(_Config) ->
    Self = self(),
    application:set_env(opentelemetry, processors,
                        [{otel_simple_processor, #{exporter => {otel_exporter_pid, Self}}}]),
    application:stop(opentelemetry),
    {ok, _} = application:ensure_all_started(opentelemetry),

    {ok, #{status := 200}} =
        katipo:get(?POOL, <<"https://localhost:8443/get">>,
                   #{ssl_verifyhost => false, ssl_verifypeer => false}),
    receive
        {span, #span{name = SpanName}} ->
            ?assertEqual(<<"HTTP GET">>, SpanName)
    after 5000 ->
        ct:fail("Timeout waiting for span")
    end.

otel_metrics_recorded(_Config) ->
    Self = self(),
    ReadersConfig = [#{module => otel_metric_reader,
                       config => #{exporter => {otel_metric_exporter_pid, Self},
                                  export_interval_ms => 100}}],
    application:set_env(opentelemetry_experimental, readers, ReadersConfig),
    application:stop(opentelemetry_experimental),
    {ok, _} = application:ensure_all_started(opentelemetry_experimental),

    %% Re-register instruments with new meter provider
    ok = katipo_metrics:init(),

    flush_otel_metrics(),
    {ok, #{status := 200}} =
        katipo:get(?POOL, <<"https://localhost:8443/get">>,
                   #{ssl_verifyhost => false, ssl_verifypeer => false}),

    ok = otel_meter_server:force_flush(),
    timer:sleep(300),

    Metrics = collect_otel_metrics(),
    ?assert(length(Metrics) > 0),
    HasRequestCounter = lists:any(
        fun(Metric) ->
            case Metric of
                {Name, _, _, _} when Name =:= 'http.client.requests' -> true;
                _ -> metric_contains_name(Metric, 'http.client.requests')
            end
        end, Metrics),
    ?assert(HasRequestCounter).

flush_otel_metrics() ->
    receive
        {otel_metric, _} -> flush_otel_metrics()
    after 0 -> ok
    end.

collect_otel_metrics() ->
    collect_otel_metrics([]).

collect_otel_metrics(Acc) ->
    receive
        {otel_metric, Metric} ->
            collect_otel_metrics([Metric | Acc])
    after 100 ->
        lists:reverse(Acc)
    end.

metric_contains_name(Metric, Name) when is_tuple(Metric) ->
    metric_contains_name(tuple_to_list(Metric), Name);
metric_contains_name([Name | _], Name) when is_atom(Name) ->
    true;
metric_contains_name([H | T], Name) ->
    metric_contains_name(H, Name) orelse metric_contains_name(T, Name);
metric_contains_name(_, _) ->
    false.

otel_url_sanitization(_Config) ->
    %% Test that query strings are stripped (prevents leaking API keys, tokens, etc.)
    {Url1, Host1} = katipo:parse_url_for_span(<<"https://api.example.com/users?api_key=secret123&token=abc">>),
    ?assertEqual(<<"https://api.example.com/users">>, Url1),
    ?assertEqual(<<"api.example.com">>, Host1),

    %% Test that fragments are stripped
    {Url2, Host2} = katipo:parse_url_for_span(<<"https://example.com/page#section">>),
    ?assertEqual(<<"https://example.com/page">>, Url2),
    ?assertEqual(<<"example.com">>, Host2),

    %% Test that both query and fragment are stripped
    {Url3, Host3} = katipo:parse_url_for_span(<<"https://example.com/path?foo=bar#anchor">>),
    ?assertEqual(<<"https://example.com/path">>, Url3),
    ?assertEqual(<<"example.com">>, Host3),

    %% Test URL without query or fragment is unchanged
    {Url4, Host4} = katipo:parse_url_for_span(<<"https://example.com/path">>),
    ?assertEqual(<<"https://example.com/path">>, Url4),
    ?assertEqual(<<"example.com">>, Host4),

    %% Test URL with port
    {Url5, Host5} = katipo:parse_url_for_span(<<"https://example.com:8443/api?secret=value">>),
    ?assertEqual(<<"https://example.com:8443/api">>, Url5),
    ?assertEqual(<<"example.com">>, Host5),

    %% Test URL with userinfo - credentials are stripped for security
    {Url6, Host6} = katipo:parse_url_for_span(<<"https://user:pass@example.com/path?token=x">>),
    ?assertEqual(<<"https://example.com/path">>, Url6),
    ?assertEqual(<<"example.com">>, Host6),

    ok.
