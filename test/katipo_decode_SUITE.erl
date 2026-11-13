-module(katipo_decode_SUITE).

%% Content decoding. By default curl asks for every encoding it can decode
%% and decodes the body, and the response does not name the encoding, nor
%% the length of the encoded body, so the headers describe the body the
%% caller is given. A response with no body (a HEAD's, a 204 or a 304)
%% keeps them, as they describe the body another request would get. With
%% decode => false the body and headers are as the server sent them, and no
%% Accept-Encoding is sent but the caller's own.

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([bad_opts/1]).
-export([decoded/1]).
-export([decoded_streamed/1]).
-export([not_encoded/1]).
-export([bodiless_kept/1]).
-export([not_decoded/1]).
-export([not_decoded_streamed/1]).
-export([not_decoded_limit/1]).
-export([stub/1]).

-include_lib("common_test/include/ct.hrl").

-define(WAIT, 5000).

all() ->
    [bad_opts, decoded, decoded_streamed, not_encoded, bodiless_kept, not_decoded,
     not_decoded_streamed, not_decoded_limit, stub].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    Config.

end_per_suite(Config) ->
    Config.

init_per_testcase(TestCase, Config) ->
    {ok, _} = katipo_pool:start(TestCase, 1, []),
    [{pool, TestCase} | Config].

end_per_testcase(_TestCase, Config) ->
    ok = katipo_pool:stop(?config(pool, Config)).

bad_opts(_Config) ->
    ok = katipo:check_opts(#{decode => false}),
    ok = katipo:check_opts(#{decode => true}),
    {error, #{code := bad_opts, message := <<"[{decode,1}]">>}} = katipo:check_opts(#{decode => 1}).

%% The body decoded, sized or chunked, and its encoding not named; curl
%% asked for it.
decoded(Config) ->
    Body = <<"hello, decoded">>,
    Gzip = zlib:gzip(Body),
    [begin
         {ok, _Server, Port} = katipo_script_server:start([{respond, Raw}]),
         {ok, #{status := 200, body := Body, headers := Headers}} =
             katipo:get(?config(pool, Config), katipo_script_server:url(Port)),
         [{<<"x-kept">>, <<"1">>}, {<<"connection">>, <<"close">>}] =
             [H || {K, _} = H <- Headers, K =/= <<"transfer-encoding">>],
         {match, _} = re:run(request_head(), <<"(?i)accept-encoding: ">>)
     end
     || Raw <- [sized(<<"content-encoding: gzip\r\nx-kept: 1\r\n">>, Gzip),
                [<<"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nx-kept: 1\r\n"
                   "transfer-encoding: chunked\r\nconnection: close\r\n\r\n">>,
                 integer_to_binary(byte_size(Gzip), 16), <<"\r\n">>, Gzip, <<"\r\n0\r\n\r\n">>]]].

decoded_streamed(Config) ->
    Body = binary:copy(<<"streamed ">>, 100),
    {ok, _Server, Port} = katipo_script_server:start(
                            [{respond, sized(<<"content-encoding: gzip\r\n">>, zlib:gzip(Body))}]),
    {ok, Ref} = katipo:async_req(?config(pool, Config),
                                 #{url => katipo_script_server:url(Port), stream => true}),
    receive
        {katipo_headers, Ref, #{headers := [{<<"connection">>, <<"close">>}]}} -> ok
    after ?WAIT -> ct:fail(no_headers)
    end,
    Body = chunks(Ref, <<>>).

%% With no encoding, the Content-Length stays.
not_encoded(Config) ->
    {ok, _Server, Port} = katipo_script_server:start([{respond, sized(<<>>, <<"plain">>)}]),
    {ok, #{body := <<"plain">>, headers := [{<<"content-length">>, <<"5">>} | _]}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port)).

%% A HEAD's response, a 204 and a 304 describe a body they do not have.
bodiless_kept(Config) ->
    Pool = ?config(pool, Config),
    Encoded = <<"content-encoding: gzip\r\ncontent-length: 40\r\nconnection: close\r\n\r\n">>,
    {ok, _, Head} = katipo_script_server:start([{respond, [<<"HTTP/1.1 200 OK\r\n">>, Encoded]}]),
    {ok, #{status := 200, headers := [{<<"content-encoding">>, _}, {<<"content-length">>, _} | _]}} =
        katipo:head(Pool, katipo_script_server:url(Head)),
    [begin
         {ok, _, Port} = katipo_script_server:start([{respond, [<<"HTTP/1.1 ">>, Status, <<"\r\n">>,
                                                                 Encoded]}]),
         {ok, #{headers := [{<<"content-encoding">>, _}, {<<"content-length">>, _} | _]}} =
             katipo:get(Pool, katipo_script_server:url(Port))
     end || Status <- [<<"204 No Content">>, <<"304 Not Modified">>]].

%% The body as sent, its headers kept, and no Accept-Encoding but the
%% caller's.
not_decoded(Config) ->
    Pool = ?config(pool, Config),
    Gzip = zlib:gzip(<<"raw">>),
    Size = integer_to_binary(byte_size(Gzip)),
    {ok, _, Port} = katipo_script_server:start(
                      [{respond, sized(<<"content-encoding: gzip\r\n">>, Gzip)},
                       {respond, sized(<<"content-encoding: gzip\r\n">>, Gzip)}]),
    Url = katipo_script_server:url(Port),
    {ok, #{body := Gzip, headers := [{<<"content-encoding">>, <<"gzip">>},
                                     {<<"content-length">>, Size} | _]}} =
        katipo:get(Pool, Url, #{decode => false}),
    nomatch = re:run(request_head(), <<"(?i)accept-encoding">>),
    {ok, #{body := Gzip}} =
        katipo:get(Pool, Url, #{decode => false, headers => [{<<"Accept-Encoding">>, <<"gzip">>}]}),
    {match, _} = re:run(request_head(), <<"\r\nAccept-Encoding: gzip(\r|$)">>).

not_decoded_streamed(Config) ->
    Gzip = zlib:gzip(binary:copy(<<"streamed ">>, 100)),
    {ok, _Server, Port} = katipo_script_server:start(
                            [{respond, sized(<<"content-encoding: gzip\r\n">>, Gzip)}]),
    {ok, Ref} = katipo:async_req(?config(pool, Config),
                                 #{url => katipo_script_server:url(Port), stream => true,
                                   decode => false}),
    receive
        {katipo_headers, Ref, #{headers := [{<<"content-encoding">>, <<"gzip">>} | _]}} -> ok
    after ?WAIT -> ct:fail(no_headers)
    end,
    Gzip = chunks(Ref, <<>>).

%% max_body_size counts the bytes as sent: a small gzip that would inflate
%% past the limit is under it, and a Content-Length over the limit fails
%% at once, as it is the size of the body given.
not_decoded_limit(Config) ->
    Pool = ?config(pool, Config),
    Bomb = zlib:gzip(binary:copy(<<0>>, 1 bsl 19)),
    {ok, _, Port} = katipo_script_server:start([{respond, sized(<<"content-encoding: gzip\r\n">>, Bomb)}]),
    {ok, #{body := Bomb}} =
        katipo:get(Pool, katipo_script_server:url(Port), #{decode => false, max_body_size => 1000}),
    Big = crypto:strong_rand_bytes(2000),
    {ok, _, Port2} = katipo_script_server:start([{respond, sized(<<"content-encoding: gzip\r\n">>, Big)}]),
    {error, #{code := filesize_exceeded}} =
        katipo:get(Pool, katipo_script_server:url(Port2), #{decode => false, max_body_size => 1000}).

%% A stub pool's response is taken as one curl would have decoded, unless
%% decode is false.
stub(Config) ->
    Pool = ?config(pool, Config),
    ok = katipo_pool:stop(Pool),
    {ok, _} = katipo_pool:start(Pool, 1,
                                [{stub, fun(_) ->
                                                #{status => 200, body => <<"abc">>,
                                                  headers => [{<<"Content-Encoding">>, <<"br">>},
                                                              {<<"Content-Length">>, <<"2">>},
                                                              {<<"X">>, <<"y">>}]}
                                        end}]),
    {ok, #{headers := [{<<"X">>, <<"y">>}]}} = katipo:get(Pool, <<"http://h/">>),
    {ok, #{headers := [_, _, _]}} = katipo:get(Pool, <<"http://h/">>, #{decode => false}).

chunks(Ref, Acc) ->
    receive
        {katipo_chunk, Ref, Chunk} -> chunks(Ref, <<Acc/binary, Chunk/binary>>);
        {katipo_done, Ref, _} -> Acc;
        {katipo_error, Ref, Error} -> ct:fail({error, Error})
    after ?WAIT -> ct:fail(no_chunk)
    end.

sized(Headers, Body) ->
    katipo_script_server:sized(<<"200 OK">>, Headers, Body).

%% The head of the next request the script server was sent.
request_head() ->
    receive {script_request, _, Head, _} -> Head
    after ?WAIT -> ct:fail(no_request)
    end.
