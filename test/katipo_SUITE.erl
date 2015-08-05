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
init_per_group(_, Config) ->
    application:ensure_all_started(katipo),
    Config.

end_per_group(pool, Config) ->
    application:stop(meck),
    application:stop(katipo),
    application:stop(gproc),
    Config;
end_per_group(_, Config) ->
    application:stop(katipo),
    application:stop(gproc),
    Config.

groups() ->
    [{http, [],
      [get,
       post_data,
       post_qs,
       put_data,
       put_qs,
       headers,
       header_remove,
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
       badopts]},
     {pool, [],
      [worker_death,
       port_late_response]}].

all() ->
    [{group, http},
     {group, pool}].

get(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:get(<<"http://127.0.0.1:8000/get?a=%21%40%23%24%25%5E%26%2A%28%29_%2B">>),
    Json = jsx:decode(Body),
    [{<<"a">>, <<"!@#$%^&*()_+">>}] = proplists:get_value(<<"args">>, Json).

post_data(_) ->
    {ok, #{status := 200, body := Body}} =
        katipo:post(<<"http://127.0.0.1:8000/post">>,
                    #{headers => [{<<"Content-Type">>, <<"application/json">>}],
                      body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

post_qs(_) ->
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:post(<<"http://127.0.0.1:8000/post">>, #{body => QsVals}),
    Json = jsx:decode(Body),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

put_data(_) ->
    Headers = [{<<"Content-Type">>, <<"application/json">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:put(<<"http://127.0.0.1:8000/put">>,
                   #{headers => Headers, body => <<"!@#$%^&*()">>}),
    Json = jsx:decode(Body),
    <<"!@#$%^&*()">> = proplists:get_value(<<"data">>, Json).

put_qs(_) ->
    QsVals = [{<<"foo">>, <<"bar">>}, {<<"baz">>, true}],
    {ok, #{status := 200, body := Body}} =
        katipo:put(<<"http://127.0.0.1:8000/put">>, #{body => QsVals}),
    Json = jsx:decode(Body),
    [] = [{<<"baz">>,<<>>},{<<"foo">>,<<"bar">>}] -- proplists:get_value(<<"form">>, Json).

delete(_) ->
    {ok, {200, _, _, _}} = katipo:delete(<<"http://127.0.0.1:8000/delete">>).

headers(_) ->
    Headers = [{<<"header1">>, <<"!@#$%^&*()">>}],
    {ok, #{status := 200, body := Body}} =
        katipo:get(<<"http://127.0.0.1:8000/gzip">>, #{headers => Headers}),
    Json = jsx:decode(Body),
    Expected =  [{<<"Accept">>,<<"*/*">>},
                 {<<"Accept-Encoding">>,<<"gzip,deflate">>},
                 {<<"Header1">>,<<"!@#$%^&*()">>},
                 {<<"Host">>,<<"127.0.0.1:8000">>}],
    [] = Expected -- proplists:get_value(<<"headers">>, Json).

header_remove(_) ->
    Headers = [{<<"Accept-Encoding">>, <<>>}],
    {ok, #{status := 200, body := Body}} =
        katipo:get(<<"http://127.0.0.1:8000/get">>, #{headers => Headers}),
    Json = jsx:decode(Body),
    Expected =  [{<<"Accept">>,<<"*/*">>},
                 {<<"Host">>,<<"127.0.0.1:8000">>}],
    [] = Expected -- proplists:get_value(<<"headers">>, Json).

gzip(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://127.0.0.1:8000/gzip">>),
    Json = jsx:decode(Body),
    true = proplists:get_value(<<"gzipped">>, Json).

deflate(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://127.0.0.1:8000/deflate">>),
    Json = jsx:decode(Body),
    true = proplists:get_value(<<"deflated">>, Json).

bytes(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://127.0.0.1:8000/bytes/1024?seed=9999">>),
    1024 = byte_size(Body),
    <<214,141,60,147,148,212,22,181,40,183,133,31,67,245,222,40>> = crypto:hash(md5, Body).

stream_bytes(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://127.0.0.1:8000/bytes/1024?seed=9999&chunk_size=8">>),
    1024 = byte_size(Body),
    <<214,141,60,147,148,212,22,181,40,183,133,31,67,245,222,40>> = crypto:hash(md5, Body).

utf8(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://127.0.0.1:8000/encoding/utf8">>),
    case xmerl_ucs:from_utf8(Body) of
        [_|_] -> ok
    end.

stream(_) ->
    {ok, #{status := 200, body := Body}} = katipo:get(<<"http://127.0.0.1:8000/stream/20">>),
    20 = length(binary:split(Body, <<"\n">>, [global, trim_all])).

statuses(_) ->
    [begin
         B = integer_to_binary(S),
         Url = <<"http://127.0.0.1:8000/status/",B/binary>>,
         {ok, #{status := S}} = katipo:get(Url)
     end || S <- http_status_codes()].

cookies(_) ->
    Url = <<"http://127.0.0.1:8000/cookies/set?cname=cvalue">>,
    Opts = #{followlocation => true},
    {ok, #{status := 200, cookiejar := CookieJar, body := Body}} = katipo:get(Url, Opts),
    Json = jsx:decode(Body),
    [{<<"cname">>, <<"cvalue">>}] = proplists:get_value(<<"cookies">>, Json),
    [<<"127.0.0.1\tFALSE\t/\tFALSE\t0\tcname\tcvalue">>] = CookieJar.

cookies_delete(_) ->
    Url = <<"http://127.0.0.1:8000/cookies/delete?cname">>,
    CookieJar = [<<"127.0.0.1\tFALSE\t/\tFALSE\t0\tcname\tcvalue">>],
    {ok, #{status := 200, cookiejar := [_], body := Body}} =
        katipo:get(Url, #{cookiejar => CookieJar, followlocation => true}),
    Json = jsx:decode(Body),
    [{}] = proplists:get_value(<<"cookies">>, Json).

%% TODO
redirect_to(_) ->
    {ok, #{status := 302}} = katipo:get(<<"http://127.0.0.1:8000/redirect-to?url=https://google.com">>).

connecttimeout_ms(_) ->
    {error, #{code := operation_timedout}} =
        katipo:get(<<"http://google.com">>, #{connecttimeout_ms => 1}).

followlocation_true(_) ->
    {ok, #{status := 200, headers := Headers}} =
        katipo:get(<<"http://127.0.0.1:8000/redirect/6">>, #{followlocation => true}),
    1 = length(proplists:get_all_values(<<"Server">>, Headers)).

followlocation_false(_) ->
    {ok, #{status := 302}} =
        katipo:get(<<"http://127.0.0.1:8000/redirect/6">>).

maxredirs(_) ->
    Opts = #{followlocation => true, maxredirs => 2},
    {error, #{code := too_many_redirects, message := <<"Maximum (2) redirects followed">>}} =
        katipo:get(<<"http://127.0.0.1:8000/redirect/6">>, Opts).

basic_unauthorised(_) ->
    {ok, #{status := 401}} =
        katipo:get(<<"http://127.0.0.1:8000/basic-auth/johndoe/p455w0rd">>).

basic_authorised(_) ->
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(<<"http://127.0.0.1:8000/basic-auth/johndoe/p455w0rd">>,
                  #{http_auth => basic, username => Username, password => Password}),
    Json = jsx:decode(Body),
    true = proplists:get_value(<<"authenticated">>, Json),
    Username = proplists:get_value(<<"user">>, Json).

digest_unauthorised(_) ->
    {ok, #{status := 401}} =
        katipo:get(<<"http://127.0.0.1:8000/digest-auth/auth/johndoe/p455w0rd">>).

digest_authorised(_) ->
    Username = <<"johndoe">>,
    Password = <<"p455w0rd">>,
    {ok, #{status := 200, body := Body}} =
        katipo:get(<<"http://127.0.0.1:8000/digest-auth/auth/johndoe/p455w0rd">>,
                  #{http_auth => digest, username => Username, password => Password}),
    Json = jsx:decode(Body),
    true = proplists:get_value(<<"authenticated">>, Json),
    Username = proplists:get_value(<<"user">>, Json).

badopts(_) ->
    {error, {bad_opts, L}} =
        katipo:get(<<"http://127.0.0.1:8000/get">>, #{timeout_ms => <<"wrong">>, what => not_even_close}),
    [] = L -- [{what, not_even_close}, {timeout_ms, <<"wrong">>}].

timeout_ms(_) ->
    {error, #{code := operation_timedout}} =
        katipo:get(<<"http://127.0.0.1:8000/delay/1">>, #{timeout_ms => 500}).

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
                   {ok, #{status := 200}} = katipo:get(<<"http://127.0.0.1:8000/get">>),
                   true
           end,
    true = repeat_until_true(Fun2).

port_late_response(_) ->
    ok = meck:new(katipo, [passthrough]),
    meck:expect(katipo, get_timeout, fun(_) -> 100 end),
    {error, #{code := operation_timedout, message := <<>>}} = katipo:get(<<"http://127.0.0.1:8000/delay/1">>),
    meck:unload(katipo).

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
