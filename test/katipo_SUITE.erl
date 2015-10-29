-module(katipo_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

suite() ->
    [{timetrap, {seconds, 30}}].

init_per_suite(Config) ->
    application:ensure_all_started(katipo),
    application:ensure_all_started(meck),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(pool, Config) ->
    application:ensure_all_started(katipo),
    application:ensure_all_started(meck),
    Config;
init_per_group(https, Config) ->
    application:ensure_all_started(katipo),
    application:ensure_all_started(cowboy),
    Dispatch = cowboy_router:compile([{'_', [{"/", get_handler, []}]}]),
    DataDir = ?config(data_dir, Config),
    CACert = filename:join(DataDir, "cowboy-ca.crt"),
    {ok, _} = cowboy:start_https(ct_https, 1,
                                 [{port, 8443},
                                  {cacertfile, CACert},
                                  {certfile, filename:join(DataDir, "server.crt")},
                                  {keyfile, filename:join(DataDir, "server.key")}],
                                 [{env, [{dispatch, Dispatch}]}]),
    [{cacert_file, list_to_binary(CACert)} | Config];
init_per_group(proxy, Config) ->
    application:ensure_all_started(katipo),
    application:ensure_all_started(cowboy),
    {ok, HttpProxyService} = http_proxy:start(3128, []),
    [{http_proxy, HttpProxyService} | Config];
init_per_group(_, Config) ->
    application:ensure_all_started(katipo),
    application:ensure_all_started(http_proxy),
    Config.

end_per_group(pool, Config) ->
    application:stop(meck),
    application:stop(katipo),
    application:stop(gproc),
    Config;
end_per_group(proxy, Config) ->
    application:stop(katipo),
    application:stop(gproc),
    HttpProxyService = ?config(http_proxy, Config),
    ok = http_proxy:stop(HttpProxyService),
    application:stop(http_proxy),
    Config;
end_per_group(_, Config) ->
    application:stop(katipo),
    application:stop(gproc),
    Config.

groups() ->
    [{http, [parallel],
      [get,
       get_req,
       head,
       post_data,
       post_qs,
       post_req,
       url_missing,
       bad_method,
       put_data,
       put_qs,
       patch_data,
       patch_qs,
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
       badopts,
       proxy_couldnt_connect]},
     {pool, [],
      [worker_death,
       port_late_response]},
     {https, [],
      [verify_host_verify_peer_ok,
       verify_host_verify_peer_error,
       cacert_self_signed]},
     {proxy, [],
      [proxy_get,
       proxy_post_data]},
     {stream, [],
      [stream_chunked_data]}].

all() ->
    [{group, http},
     {group, pool},
     {group, https},
     {group, proxy},
     {group, stream}].

get(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:get(<<"http://httpbin.org/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>),
    Json = jsx:decode(Body),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

get_req(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:req(#{url => <<"http://httpbin.org/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>}),
    Json = jsx:decode(Body),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

head(_) ->
    {ok, #{status := 200}} =
        katipo:head(<<"http://httpbin.org/get">>).

post_data(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:post(<<"http://httpbin.org/post">>,
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

post_qs(_) ->
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:post(<<"http://httpbin.org/post">>, #{body => QsVals}),
    Json = jsx:decode(Body),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

post_req(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:req(#{url => <<"http://httpbin.org/post">>,
                     method => post,
                     headers => [{<<"Content-Type">>, <<"application/json">>}],
                     body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

url_missing(_) ->
    {error, {bad_opts, [{url, undefined}]}} =
        katipo:req(#{method => post,
                     headers => [{<<"Content-Type">>, <<"application/json">>}],
                     body => <<"!@#$%^&*()">>}).

bad_method(_) ->
    {error, {bad_opts, [{method, toast}]}} =
        katipo:req(#{method => toast,
                     headers => [{<<"Content-Type">>, <<"application/json">>}],
                     body => <<"!@#$%^&*()">>}).

put_data(_) ->
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:put(<<"http://httpbin.org/put">>,
                   #{headers => Headers, body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

put_qs(_) ->
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:put(<<"http://httpbin.org/put">>, #{body => QsVals}),
    Json = jsx:decode(Body),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

patch_data(_) ->
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:patch(<<"http://httpbin.org/patch">>,
                   #{headers => Headers, body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

patch_qs(_) ->
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:patch(<<"http://httpbin.org/patch">>, #{body => QsVals}),
    Json = jsx:decode(Body),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

delete(_) ->
    {ok, #{status := 200}} = katipo:delete(<<"http://httpbin.org/delete">>).

headers(_) ->
    Headers = [{<<"header1">>, <<"!@#$%^&*()">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:get(<<"http://httpbin.org/gzip">>, #{headers => Headers}),
    Json = jsx:decode(Body),
    Expected =  [{<<"Accept">>,<<"*/*">>},
                 {<<"Accept-Encoding">>,<<"gzip,deflate">>},
                 {<<"Header1">>,<<"!@#$%^&*()">>},
                 {<<"Host">>,<<"httpbin.org">>}],
    [] = Expected -- proplists:get_value(<<"headers">>, Json).

header_remove(_) ->
    Headers = [{<<"Accept-Encoding">>, <<>>}],
    {ok, #{status := 200, body := Body}} =
        katipo:get(<<"http://httpbin.org/get">>, #{headers => Headers}),
    Json = jsx:decode(Body),
    Expected =  [{<<"Accept">>,<<"*/*">>},
                 {<<"Host">>,<<"httpbin.org">>}],
    [] = Expected -- proplists:get_value(<<"headers">>, Json).

gzip(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://httpbin.org/gzip">>),
    Json = jsx:decode(Body),
    true = proplists:get_value(<<"gzipped">>, Json).

deflate(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://httpbin.org/deflate">>),
    Json = jsx:decode(Body),
    true = proplists:get_value(<<"deflated">>, Json).

bytes(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://httpbin.org/bytes/1024?seed=9999">>),
    1024 = byte_size(Body),
    <<214,141,60,147,148,212,22,181,40,183,133,31,67,245,222,40>> = crypto:hash(md5, Body).

stream_bytes(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://httpbin.org/bytes/1024?seed=9999&chunk_size=8">>),
    1024 = byte_size(Body),
    <<214,141,60,147,148,212,22,181,40,183,133,31,67,245,222,40>> = crypto:hash(md5, Body).

utf8(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://httpbin.org/encoding/utf8">>),
    case xmerl_ucs:from_utf8(Body) of
        [_|_] -> ok
    end.

stream(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://httpbin.org/stream/20">>),
    20 = length(binary:split(Body, <<"\n">>, [global, trim])).

statuses(_) ->
    [begin
         B = integer_to_binary(S),
         Url = <<"http://httpbin.org/status/",B/binary>>,
         {ok, #{status := S}} = katipo:get(Url)
     end || S <- http_status_codes()].

cookies(_) ->
    Url = <<"http://httpbin.org/cookies/set?cname=cvalue">>,
    Opts = #{followlocation => true},
    {ok, #{status := 200, cookiejar := CookieJar, body := Body}} = katipo:get(Url, Opts),
    Json = jsx:decode(Body),
    [{<<"cname">>, <<"cvalue">>}] = proplists:get_value(<<"cookies">>, Json),
    [<<"httpbin.org\tFALSE\t/\tFALSE\t0\tcname\tcvalue">>] = CookieJar.

cookies_delete(_) ->
    Url = <<"http://httpbin.org/cookies/delete?cname">>,
    CookieJar = [<<"httpbin.org\tFALSE\t/\tFALSE\t0\tcname\tcvalue">>],
    {ok, #{status := 200, cookiejar := [_], body := Body}} =
        katipo:get(Url, #{cookiejar => CookieJar, followlocation => true}),
    Json = jsx:decode(Body),
    [{}] = proplists:get_value(<<"cookies">>, Json).

%% TODO
redirect_to(_) ->
    {ok, #{status := 302}} = katipo:get(<<"http://httpbin.org/redirect-to?url=https://google.com">>).

connecttimeout_ms(_) ->
    {error, #{code := operation_timedout}} =
        katipo:get(<<"http://google.com">>, #{connecttimeout_ms => 1}).

followlocation_true(_) ->
    {ok, #{status := 200, headers := Headers}} =
        katipo:get(<<"http://httpbin.org/redirect/6">>, #{followlocation => true}),
    1 = length(proplists:get_all_values(<<"Server">>, Headers)).

followlocation_false(_) ->
    {ok, #{status := 302}} =
        katipo:get(<<"http://httpbin.org/redirect/6">>).

maxredirs(_) ->
    Opts = #{followlocation => true, maxredirs => 2},
    {error, #{code := too_many_redirects, message := <<"Maximum (2) redirects followed">>}} =
        katipo:get(<<"http://httpbin.org/redirect/6">>, Opts).

basic_unauthorised(_) ->
    {ok, #{status := 401}} =
        katipo:get(<<"http://httpbin.org/basic-auth/johndoe/p455w0rd">>).

basic_authorised(_) ->
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(<<"http://httpbin.org/basic-auth/johndoe/p455w0rd">>,
                  #{http_auth => basic, username => Username, password => Password}),
    Json = jsx:decode(Body),
    true = proplists:get_value(<<"authenticated">>, Json),
    Username = proplists:get_value(<<"user">>, Json).

digest_unauthorised(_) ->
    {ok, #{status := 401}} =
        katipo:get(<<"http://httpbin.org/digest-auth/auth/johndoe/p455w0rd">>).

digest_authorised(_) ->
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(<<"http://httpbin.org/digest-auth/auth/johndoe/p455w0rd">>,
                  #{http_auth => digest, username => Username, password => Password}),
    Json = jsx:decode(Body),
    true = proplists:get_value(<<"authenticated">>, Json),
    Username = proplists:get_value(<<"user">>, Json).

badopts(_) ->
    {error, {bad_opts, L}} =
        katipo:get(<<"http://httpbin.org/get">>, #{timeout_ms => <<"wrong">>, what => not_even_close}),
    [] = L -- [{what, not_even_close}, {timeout_ms, <<"wrong">>}].

proxy_couldnt_connect(_) ->
    Url = <<"http://httpbin.org/get">>,
    {error, #{code := couldnt_connect}} =
        katipo:get(Url, #{proxy => <<"http://localhost:3128">>}).

timeout_ms(_) ->
    {error, #{code := operation_timedout}} =
        katipo:get(<<"http://httpbin.org/delay/1">>, #{timeout_ms => 500}).

couldnt_resolve_host(_) ->
    {error, #{code := couldnt_resolve_host,
              message := <<"Couldn't resolve host 'abadhostnamethatdoesnotexist'">>}} =
        katipo:get(<<"http://abadhostnamethatdoesnotexist">>).

http_status_codes() ->
    [200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301,
     302, 303, 304, 305, 306, 307, 308,
     400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414,
     415, 416, 417, 421, 422, 423, 424, 426, 428, 429, 431,
     500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511].

worker_death(_) ->
    Active = gproc_pool:active_workers(katipo),
    _ = [exit(W, i_expect_you_to_die) || {_, W} <- Active],
    Fun = fun() ->
                  length(Active) == length(gproc_pool:active_workers(katipo))
          end,
    true = repeat_until_true(Fun),
    Fun2 = fun() ->
                   {ok, #{status := 200}} = katipo:get(<<"http://httpbin.org/get">>),
                   true
           end,
    true = repeat_until_true(Fun2).

port_late_response(_) ->
    ok = meck:new(katipo, [passthrough]),
    meck:expect(katipo, get_timeout, fun(_) -> 100 end),
    {error, #{code := operation_timedout, message := <<>>}} = katipo:get(<<"http://httpbin.org/delay/1">>),
    meck:unload(katipo).

verify_host_verify_peer_ok(_) ->
    Opts = [#{ssl_verifyhost => true, ssl_verifypeer => true},
            #{ssl_verifyhost => false, ssl_verifypeer => true},
            #{ssl_verifyhost => true, ssl_verifypeer => false},
            #{ssl_verifyhost => false, ssl_verifypeer => false}],
    [{ok, _} = katipo:get(<<"https://google.com">>, O) || O <- Opts].

verify_host_verify_peer_error(_) ->
    {error, #{code := ssl_cacert}} =
         katipo:get(<<"https://localhost:8443">>,
                    #{ssl_verifyhost => true, ssl_verifypeer => true}),
    {error, #{code := ssl_cacert}} =
         katipo:get(<<"https://localhost:8443">>,
                    #{ssl_verifyhost => false, ssl_verifypeer => true}),
    {ok, #{status := 200}} =
        katipo:get(<<"https://localhost:8443">>,
                   #{ssl_verifyhost => true, ssl_verifypeer => false}),
    {ok, #{status := 200}} =
        katipo:get(<<"https://localhost:8443">>,
                   #{ssl_verifyhost => false, ssl_verifypeer => false}).

cacert_self_signed(Config) ->
    CACert = ?config(cacert_file, Config),
    {ok, #{status := 200}} =
        katipo:get(<<"https://localhost:8443">>,
                   #{ssl_verifyhost => true, ssl_verifypeer => true, cacert => CACert}).

proxy_get(_) ->
    Url = <<"http://httpbin.org/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(Url, #{proxy => <<"http://localhost:3128">>}),
    Json = jsx:decode(Body),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

proxy_post_data(_) ->
    Url = <<"http://httpbin.org/post">>,
    {ok, #{status := 200, body := Body}} =
        katipo:post(Url,
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => <<"!@#$%^&*()">>,
                      proxy => <<"http://localhost:3128">>}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

process_stream(Receiver) ->
    process_stream(Receiver, orddict:new()).

process_stream(Receiver, Dict0) ->
    receive
        {status, {_, {#{state := Status}, _}}} ->
            error_logger:info_msg("Status"),
            Dict1 = orddict:store(status, Status, Dict0),
            process_stream(Receiver, Dict1);
        {headers, {_, {#{headers := Headers}, _}}} ->
            error_logger:info_msg("Headers"),
            Dict1 = orddict:store(headers, Headers, Dict0),
            process_stream(Receiver, Dict1);
        {done, _} -> Receiver ! {ok, Dict0};
        {chunk, {_, {#{chunk := Chunk}, _}}} ->
            error_logger:info_msg("Chunk"),
            Dict1 = orddict:append(body, Chunk, Dict0),
            process_stream(Receiver, Dict1);
        _ -> Receiver ! {error, wrong_result}
    end.

stream_chunked_data(_) ->
    Url = <<"http://httpbin.org/bytes/1024?seed=9999&chunk_size=8">>,
    _ = katipo:get(Url,
                   #{stream_to => process_stream(self())}),
    receive
        {ok, #{status := Status, headers := Headers, body := Body}} ->
            200 = Status,
            _ = Headers,
            _ = Body;
        _ ->
            erlang:error(bad_stream_response)
    end.

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
