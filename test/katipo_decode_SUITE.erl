-module(katipo_decode_SUITE).

%% Content decoding. By default curl asks for every encoding it can decode
%% and decodes the body. With decode => false the body and headers are as
%% the server sent them, and no Accept-Encoding is sent but the caller's
%% own.

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([bad_opts/1]).
-export([not_decoded/1]).
-export([not_decoded_streamed/1]).
-export([not_decoded_limit/1]).

-include_lib("common_test/include/ct.hrl").

-define(WAIT, 5000).

all() ->
    [bad_opts, not_decoded, not_decoded_streamed, not_decoded_limit].

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
    receive {script_request, _, Head, _} -> nomatch = re:run(Head, <<"(?i)accept-encoding">>)
    after ?WAIT -> ct:fail(no_request)
    end,
    {ok, #{body := Gzip}} =
        katipo:get(Pool, Url, #{decode => false, headers => [{<<"Accept-Encoding">>, <<"gzip">>}]}),
    receive {script_request, _, Head2, _} -> {match, _} = re:run(Head2, <<"\r\nAccept-Encoding: gzip(\r|$)">>)
    after ?WAIT -> ct:fail(no_request)
    end.

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

chunks(Ref, Acc) ->
    receive
        {katipo_chunk, Ref, Chunk} -> chunks(Ref, <<Acc/binary, Chunk/binary>>);
        {katipo_done, Ref, _} -> Acc;
        {katipo_error, Ref, Error} -> ct:fail({error, Error})
    after ?WAIT -> ct:fail(no_chunk)
    end.

sized(Headers, Body) ->
    [<<"HTTP/1.1 200 OK\r\n">>, Headers,
     <<"content-length: ">>, integer_to_binary(byte_size(Body)),
     <<"\r\nconnection: close\r\n\r\n">>, Body].
