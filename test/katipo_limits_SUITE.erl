-module(katipo_limits_SUITE).

%% Stall and size limits: low_speed_limit/low_speed_time and max_body_size,
%% against katipo_script_server. No httpbin server is required.

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([bad_opts/1]).
-export([stall_fails/1]).
-export([body_at_limit/1]).
-export([content_length_over_limit/1]).
-export([chunked_over_limit/1]).
-export([decoded_over_limit/1]).
-export([streamed_over_limit/1]).
-export([head_not_limited/1]).
-export([redirect_not_limited/1]).
-export([decoded_at_limit/1]).
-export([resumed_over_limit/1]).

-include_lib("common_test/include/ct.hrl").

-define(WAIT, 5000).

all() ->
    [bad_opts, stall_fails, body_at_limit, content_length_over_limit,
     chunked_over_limit, decoded_over_limit, streamed_over_limit,
     head_not_limited, redirect_not_limited, decoded_at_limit, resumed_over_limit].

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
    ok = katipo:check_opts(#{low_speed_limit => 1, low_speed_time => 1}),
    ok = katipo:check_opts(#{max_body_size => 0}),
    {error, #{message := <<"[{low_speed_limit,requires_low_speed_time}]">>}} =
        katipo:check_opts(#{low_speed_limit => 1}),
    {error, #{message := <<"[{low_speed_time,requires_low_speed_limit}]">>}} =
        katipo:check_opts(#{low_speed_time => 1}),
    %% An invalid partner is named once, not also as missing.
    {error, #{message := <<"[{low_speed_time,0}]">>}} =
        katipo:check_opts(#{low_speed_limit => 1, low_speed_time => 0}),
    {error, #{code := bad_opts}} = katipo:check_opts(#{max_body_size => -1}).

%% The server never answers: the transfer is under 1 byte/s for a second,
%% well inside timeout_ms.
stall_fails(Config) ->
    {ok, _Server, Port} = katipo_script_server:start([hang]),
    T0 = erlang:monotonic_time(millisecond),
    {error, #{code := operation_timedout}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port),
                   #{low_speed_limit => 1, low_speed_time => 1}),
    true = erlang:monotonic_time(millisecond) - T0 < 5000.

body_at_limit(Config) ->
    Body = binary:copy(<<"x">>, 1000),
    {ok, _Server, Port} = katipo_script_server:start([{respond, sized(Body)}]),
    {ok, #{status := 200, body := Body}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port),
                   #{max_body_size => 1000}).

content_length_over_limit(Config) ->
    over_limit(Config, sized(binary:copy(<<"x">>, 1001))).

chunked_over_limit(Config) ->
    Chunk = binary:copy(<<"x">>, 600),
    over_limit(Config, [<<"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n"
                          "connection: close\r\n\r\n">>,
                        [[<<"258\r\n">>, Chunk, <<"\r\n">>] || _ <- [1, 2]],
                        <<"0\r\n\r\n">>]).

%% A gzip body far under the limit that inflates far past it.
decoded_over_limit(Config) ->
    Gzip = zlib:gzip(binary:copy(<<0>>, 1 bsl 19)),
    true = byte_size(Gzip) < 1000,
    over_limit(Config, [<<"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\n"
                          "content-length: ">>, integer_to_binary(byte_size(Gzip)),
                        <<"\r\nconnection: close\r\n\r\n">>, Gzip]).

%% A streamed response is cut off mid-body: the chunks under the limit
%% arrive, then the error.
streamed_over_limit(Config) ->
    Chunk = binary:copy(<<"x">>, 600),
    {ok, _Server, Port} = katipo_script_server:start(
                            [{respond, [<<"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n"
                                          "connection: close\r\n\r\n">>,
                                        <<"258\r\n">>, Chunk, <<"\r\n">>,
                                        <<"258\r\n">>, Chunk, <<"\r\n0\r\n\r\n">>]}]),
    {ok, Ref} = katipo:async_req(?config(pool, Config),
                                 #{url => katipo_script_server:url(Port), stream => true,
                                   max_body_size => 1000}),
    receive {katipo_headers, Ref, #{status := 200}} -> ok after ?WAIT -> ct:fail(no_headers) end,
    600 = stream_until_error(Ref, 0).

%% A HEAD's Content-Length describes a body it does not have.
head_not_limited(Config) ->
    {ok, _Server, Port} = katipo_script_server:start(
                            [{respond, <<"HTTP/1.1 200 OK\r\ncontent-length: 5000\r\n"
                                         "connection: close\r\n\r\n">>}]),
    {ok, #{status := 200}} =
        katipo:head(?config(pool, Config), katipo_script_server:url(Port),
                    #{max_body_size => 1000}).

%% Only the final response's body counts, not a redirect's.
redirect_not_limited(Config) ->
    {ok, _Server, Port} = katipo_script_server:start(
                            [{respond, sized(<<"302 Found">>, <<"location: /small\r\n">>,
                                             binary:copy(<<"x">>, 5000))},
                             {respond, sized(<<"small">>)}]),
    {ok, #{status := 200, body := <<"small">>}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port),
                   #{followlocation => true, max_body_size => 1000}).

%% A body that decodes to exactly the limit, though more bytes on the wire.
decoded_at_limit(Config) ->
    Body = crypto:strong_rand_bytes(1000),
    Gzip = zlib:gzip(Body),
    true = byte_size(Gzip) > 1000,
    Gzipped = <<"content-encoding: gzip\r\n">>,
    Pool = ?config(pool, Config),
    [begin
         {ok, _Server, Port} = katipo_script_server:start([{respond, Raw}]),
         {ok, #{status := 200, body := Body}} =
             katipo:get(Pool, katipo_script_server:url(Port), #{max_body_size => 1000})
     end
     || Raw <- [sized(<<"200 OK">>, Gzipped, Gzip),
                [<<"HTTP/1.1 200 OK\r\n">>, Gzipped,
                 <<"transfer-encoding: chunked\r\nconnection: close\r\n\r\n">>,
                 integer_to_binary(byte_size(Gzip), 16), <<"\r\n">>, Gzip,
                 <<"\r\n0\r\n\r\n">>]]].

%% With a window of one chunk, the chunk that goes over the limit can be
%% the one curl hands back as the transfer resumes: the error must still
%% come at once, not when timeout_ms runs out.
resumed_over_limit(Config) ->
    Gzip = zlib:gzip(binary:copy(<<"x">>, 1 bsl 16)),
    Pool = ?config(pool, Config),
    {ok, _Server, Port} = katipo_script_server:start(
                            [{respond, sized(<<"200 OK">>, <<"content-encoding: gzip\r\n">>,
                                             Gzip)}]),
    {ok, Ref} = katipo:async_req(Pool, #{url => katipo_script_server:url(Port), stream => true,
                                         stream_window => 1, max_body_size => 20000,
                                         timeout_ms => 30000}),
    receive {katipo_headers, Ref, #{status := 200}} -> ok after ?WAIT -> ct:fail(no_headers) end,
    T0 = erlang:monotonic_time(millisecond),
    Received = grant_until_error(Pool, Ref, 0),
    true = Received > 0 andalso Received =< 20000,
    true = erlang:monotonic_time(millisecond) - T0 < ?WAIT.

grant_until_error(Pool, Ref, Received) ->
    receive
        {katipo_chunk, Ref, Chunk} ->
            ok = katipo:update_flow(Pool, Ref, 1),
            grant_until_error(Pool, Ref, Received + byte_size(Chunk));
        {katipo_error, Ref, #{code := filesize_exceeded}} ->
            Received;
        {script_request, _, _, _} ->
            grant_until_error(Pool, Ref, Received);
        Other ->
            ct:fail({unexpected, Other})
    after ?WAIT ->
            ct:fail(no_error)
    end.

stream_until_error(Ref, Received) ->
    receive
        {katipo_chunk, Ref, Chunk} ->
            stream_until_error(Ref, Received + byte_size(Chunk));
        {katipo_error, Ref, #{code := filesize_exceeded}} ->
            Received;
        {script_request, _, _, _} ->
            stream_until_error(Ref, Received);
        Other ->
            ct:fail({unexpected, Other})
    after ?WAIT ->
            ct:fail(no_error)
    end.

over_limit(Config, Raw) ->
    {ok, _Server, Port} = katipo_script_server:start([{respond, Raw}]),
    {error, #{code := filesize_exceeded}} =
        katipo:get(?config(pool, Config), katipo_script_server:url(Port),
                   #{max_body_size => 1000}).

sized(Body) ->
    sized(<<"200 OK">>, <<>>, Body).

sized(Status, Headers, Body) ->
    [<<"HTTP/1.1 ">>, Status, <<"\r\n">>, Headers,
     <<"content-length: ">>, integer_to_binary(byte_size(Body)),
     <<"\r\nconnection: close\r\n\r\n">>, Body].
