-module(katipo_stub_SUITE).

%% Pools started with {stub, Handler}: requests go to Handler instead of
%% the C port, and every part of the request's life above the port --
%% defaults, streaming, flow control, timeouts, cancel, retries,
%% max_in_flight, a Handler failing -- works as it does on a real pool.
%% No server is required.

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([end_per_testcase/2]).
-export([unknown_transfers_ignored/1]).

-export([response/1]).
-export([request_seen/1]).
-export([defaults_applied/1]).
-export([error_returned/1]).
-export([async_response/1]).
-export([head_has_no_body/1]).
-export([streamed_response/1]).
-export([stream_window/1]).
-export([streamed_request_body/1]).
-export([streamed_request_length/1]).
-export([file_body/1]).
-export([timeout/1]).
-export([cancel/1]).
-export([retried/1]).
-export([overload/1]).
-export([handler_crash/1]).
-export([bad_response/1]).
-export([bad_stub/1]).
-export([chunked_bodies/1]).
-export([max_body_size/1]).
-export([header_values_made_safe/1]).
-export([handler_exits/1]).
-export([handler_killed_with_pool/1]).
-export([handler_mailbox/1]).

-include_lib("common_test/include/ct.hrl").

-define(WAIT, 5000).

all() ->
    [response, request_seen, defaults_applied, error_returned, async_response,
     head_has_no_body, streamed_response, stream_window, streamed_request_body,
     streamed_request_length, file_body, timeout, cancel, retried, overload,
     handler_crash, bad_response, bad_stub, chunked_bodies, max_body_size,
     header_values_made_safe, handler_exits, handler_killed_with_pool,
     handler_mailbox, unknown_transfers_ignored].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    Config.

end_per_suite(Config) ->
    Config.

end_per_testcase(TestCase, _Config) ->
    _ = katipo_pool:stop(TestCase),
    ok.

response(_Config) ->
    stub(?FUNCTION_NAME, fun(_) ->
                                 #{status => 201, headers => [{<<"X-A">>, "b"}],
                                   body => [<<"he">>, "llo"]}
                         end),
    {ok, #{status := 201, headers := [{<<"X-A">>, <<"b">>}], body := <<"hello">>,
           cookiejar := _}} = katipo:get(?FUNCTION_NAME, <<"http://example.com/">>),
    stub(?FUNCTION_NAME, fun(_) -> #{status => 204} end),
    {ok, #{status := 204, headers := [], body := <<>>}} =
        katipo:get(?FUNCTION_NAME, <<"http://example.com/">>).

request_seen(_Config) ->
    seen(?FUNCTION_NAME, []),
    {ok, #{status := 200}} =
        katipo:put(?FUNCTION_NAME, <<"http://example.com/a?b=c">>,
                   #{headers => [{"X-One", [<<"1">>]}, {<<"X-Two">>, <<"a:">>}],
                     body => [<<"ab">>, "c"]}),
    #{method := put, url := <<"http://example.com/a?b=c">>,
      headers := [{<<"X-One">>, <<"1">>}, {<<"X-Two">>, <<"a:">>}], body := <<"abc">>} = req(),
    %% A form is encoded, and a POST given the Content-Type curl adds to
    %% one, unless it names its own.
    Form = [{<<"Content-Type">>, <<"application/x-www-form-urlencoded">>}],
    {ok, #{status := 200}} =
        katipo:post(?FUNCTION_NAME, <<"http://example.com/">>, #{body => [{<<"k">>, <<"v w">>}]}),
    #{method := post, headers := Form, body := <<"k=v+w">>} = req(),
    {ok, #{status := 200}} = katipo:post(?FUNCTION_NAME, <<"http://example.com/">>),
    #{headers := Form, body := <<>>} = req(),
    {ok, #{status := 200}} =
        katipo:post(?FUNCTION_NAME, <<"http://example.com/">>,
                    #{headers => [{<<"content-type">>, <<"text/plain">>}]}),
    #{headers := [{<<"content-type">>, <<"text/plain">>}]} = req(),
    %% A blank value removes one of curl's own headers, so it is not sent.
    {ok, #{status := 200}} =
        katipo:post(?FUNCTION_NAME, <<"http://example.com/">>,
                    #{headers => [{<<"Accept">>, <<>>}, {<<"Content-Type">>, <<" ">>}]}),
    #{headers := []} = req(),
    {ok, #{status := 200}} =
        katipo:patch(?FUNCTION_NAME, <<"http://example.com/">>, #{body => [{<<"k">>, <<"v">>}]}),
    #{headers := [{<<"Content-Type">>, <<"application/x-www-form-urlencoded">>}]} = req().

defaults_applied(_Config) ->
    seen(?FUNCTION_NAME, [{defaults, #{base_url => <<"https://api.example.com/v1/">>,
                                       headers => [{<<"Authorization">>, <<"t">>},
                                                   {<<"Accept">>, <<"*/*">>}]}}]),
    {ok, #{status := 200}} =
        katipo:get(?FUNCTION_NAME, <<"items">>, #{headers => [{<<"accept">>, <<"text/plain">>}]}),
    #{url := <<"https://api.example.com/v1/items">>,
      headers := [{<<"accept">>, <<"text/plain">>}, {<<"Authorization">>, <<"t">>}]} = req(),
    %% Another origin gets none of the default headers.
    {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, <<"https://other.example.com/">>),
    #{headers := []} = req().

error_returned(_Config) ->
    stub(?FUNCTION_NAME, fun(#{url := <<"http://a/">>}) -> {error, couldnt_connect};
                            (_) -> {error, ssl_connect_error, <<"bad cert">>}
                         end),
    {error, #{code := couldnt_connect, message := <<>>}} = katipo:get(?FUNCTION_NAME, <<"http://a/">>),
    {error, #{code := ssl_connect_error, message := <<"bad cert">>}} =
        katipo:get(?FUNCTION_NAME, <<"http://b/">>).

async_response(_Config) ->
    stub(?FUNCTION_NAME, fun(_) -> #{status => 200, body => <<"x">>} end),
    {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>),
    {ok, #{status := 200, body := <<"x">>}} = katipo:await(Ref, ?WAIT),
    Self = self(),
    Other = spawn_link(fun() -> receive M -> Self ! {got, M} end end),
    {ok, Ref2} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>, #{reply_to => Other}),
    receive {got, {katipo_response, Ref2, #{body := <<"x">>}}} -> ok
    after ?WAIT -> ct:fail(no_response)
    end.

head_has_no_body(_Config) ->
    stub(?FUNCTION_NAME, fun(_) -> #{status => 200, body => <<"x">>} end),
    {ok, #{status := 200, body := <<>>}} = katipo:head(?FUNCTION_NAME, <<"http://example.com/">>).

streamed_response(_Config) ->
    stub(?FUNCTION_NAME, fun(_) ->
                                 #{status => 200, headers => [{<<"A">>, <<"1">>}],
                                   body => [<<"a">>, <<>>, ["b", <<"c">>]]}
                         end),
    {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>, #{stream => true}),
    {katipo_headers, Ref, #{status := 200, headers := [{<<"A">>, <<"1">>}]}} = next(),
    {katipo_chunk, Ref, <<"a">>} = next(),
    {katipo_chunk, Ref, <<"bc">>} = next(),
    {katipo_done, Ref, #{status := 200}} = next(),
    %% A binary body is one chunk, and an empty one none.
    stub(?FUNCTION_NAME, fun(_) -> #{status => 404} end),
    {ok, Ref2} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>, #{stream => true}),
    {katipo_headers, Ref2, #{status := 404}} = next(),
    {katipo_done, Ref2, #{status := 404}} = next().

stream_window(_Config) ->
    stub(?FUNCTION_NAME, fun(_) -> #{status => 200, body => [<<"a">>, <<"b">>, <<"c">>]} end),
    {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>,
                                 #{stream => true, stream_window => 1}),
    {katipo_headers, Ref, _} = next(),
    {katipo_chunk, Ref, <<"a">>} = next(),
    nothing = next(200),
    ok = katipo:update_flow(?FUNCTION_NAME, Ref, 2),
    {katipo_chunk, Ref, <<"b">>} = next(),
    {katipo_chunk, Ref, <<"c">>} = next(),
    {katipo_done, Ref, _} = next().

streamed_request_body(_Config) ->
    seen(?FUNCTION_NAME, []),
    {ok, Ref} = katipo:async_put(?FUNCTION_NAME, <<"http://example.com/">>,
                                 #{body => {stream, #{}}}),
    {katipo_body_demand, Ref} = next(),
    ok = katipo:send_body(?FUNCTION_NAME, Ref, <<"ab">>),
    {katipo_body_demand, Ref} = next(),
    %% An empty chunk is answered with another demand.
    ok = katipo:send_body(?FUNCTION_NAME, Ref, <<>>),
    {katipo_body_demand, Ref} = next(),
    ok = katipo:send_body(?FUNCTION_NAME, Ref, ["c", <<"d">>]),
    {katipo_body_demand, Ref} = next(),
    ok = katipo:send_body(?FUNCTION_NAME, Ref, eof),
    {katipo_response, Ref, #{status := 200}} = next(),
    #{body := <<"abcd">>} = req().

streamed_request_length(_Config) ->
    seen(?FUNCTION_NAME, []),
    Put = fun(Length) ->
                  katipo:async_put(?FUNCTION_NAME, <<"http://example.com/">>,
                                   #{body => {stream, #{length => Length}}})
          end,
    %% The declared length ends the body: no eof, and no demand after it.
    {ok, Ref} = Put(3),
    {katipo_body_demand, Ref} = next(),
    ok = katipo:send_body(?FUNCTION_NAME, Ref, <<"abc">>),
    {katipo_response, Ref, #{status := 200}} = next(),
    #{body := <<"abc">>} = req(),
    {ok, Ref2} = Put(2),
    {katipo_body_demand, Ref2} = next(),
    ok = katipo:send_body(?FUNCTION_NAME, Ref2, <<"abc">>),
    {katipo_error, Ref2, #{code := read_error}} = next(),
    {ok, Ref3} = Put(4),
    {katipo_body_demand, Ref3} = next(),
    ok = katipo:send_body(?FUNCTION_NAME, Ref3, <<"abc">>),
    {katipo_body_demand, Ref3} = next(),
    ok = katipo:send_body(?FUNCTION_NAME, Ref3, eof),
    {katipo_error, Ref3, #{code := read_error}} = next(),
    %% Neither reached the handler.
    receive {req, Req} -> ct:fail({handled, Req}) after 200 -> ok end.

file_body(Config) ->
    seen(?FUNCTION_NAME, []),
    File = filename:join(?config(priv_dir, Config), "file_body"),
    ok = file:write_file(File, <<"from a file">>),
    {ok, #{status := 200}} = katipo:put(?FUNCTION_NAME, <<"http://example.com/">>,
                                        #{body => {file, File}}),
    #{body := <<"from a file">>} = req(),
    Missing = filename:join(?config(priv_dir, Config), "no_such_file"),
    {error, #{code := file_couldnt_read_file, message := Message}} =
        katipo:put(?FUNCTION_NAME, <<"http://example.com/">>, #{body => {file, Missing}}),
    {match, _} = re:run(Message, <<"no_such_file">>),
    %% Only a regular file is read, as by the port: a device may never end.
    {error, #{code := file_couldnt_read_file, message := <<"Couldn't open /dev/zero: not a regular file">>}} =
        katipo:put(?FUNCTION_NAME, <<"http://example.com/">>, #{body => {file, "/dev/zero"}}),
    receive {req, Req} -> ct:fail({handled, Req}) after 0 -> ok end.

timeout(_Config) ->
    stub(?FUNCTION_NAME, fun(_) -> receive after infinity -> ok end end),
    {error, #{code := operation_timedout}} =
        katipo:get(?FUNCTION_NAME, <<"http://example.com/">>, #{timeout_ms => 100}).

cancel(_Config) ->
    Self = self(),
    stub(?FUNCTION_NAME, fun(_) ->
                                 Self ! {handler, self()},
                                 receive after infinity -> ok end
                         end),
    {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>),
    Handler = receive {handler, H} -> H after ?WAIT -> ct:fail(no_handler) end,
    Mon = monitor(process, Handler),
    ok = katipo:cancel(?FUNCTION_NAME, Ref),
    receive {'DOWN', Mon, process, Handler, killed} -> ok
    after ?WAIT -> ct:fail(handler_not_stopped)
    end,
    nothing = next(200),
    %% The pool goes on.
    stub(?FUNCTION_NAME, fun(_) -> #{status => 200} end),
    {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, <<"http://example.com/">>).

retried(_Config) ->
    Count = counters:new(1, []),
    stub(?FUNCTION_NAME, fun(_) ->
                                 counters:add(Count, 1, 1),
                                 case counters:get(Count, 1) of
                                     N when N < 3 -> #{status => 503};
                                     _ -> #{status => 200}
                                 end
                         end),
    {ok, #{status := 200}} =
        katipo:get(?FUNCTION_NAME, <<"http://example.com/">>,
                   #{retry => #{base_delay_ms => 0}}),
    3 = counters:get(Count, 1).

overload(_Config) ->
    Self = self(),
    stub(?FUNCTION_NAME, [{max_in_flight, 1}],
         fun(_) ->
                 Self ! {handler, self()},
                 receive go -> #{status => 200} end
         end),
    {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>),
    Handler = receive {handler, H} -> H after ?WAIT -> ct:fail(no_handler) end,
    {error, #{code := overload}} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>),
    Handler ! go,
    {ok, #{status := 200}} = katipo:await(Ref, ?WAIT).

%% A Handler that raises fails its own request, with the reason, and no
%% other on its worker, however often: more often here than wpool would
%% let a worker restart.
handler_crash(_Config) ->
    Self = self(),
    stub(?FUNCTION_NAME, fun(#{url := <<"http://crash/">>}) ->
                                 error(boom);
                            (_) ->
                                 process_flag(trap_exit, true),
                                 Self ! {handler, self()},
                                 receive go -> #{status => 200} end
                         end),
    {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://wait/">>),
    Handler = receive {handler, H} -> H after ?WAIT -> ct:fail(no_handler) end,
    Worker = whereis(wpool_pool:worker_name(?FUNCTION_NAME, 1)),
    [begin
         {error, #{code := stub_failed, message := Message}} =
             katipo:get(?FUNCTION_NAME, <<"http://crash/">>),
         {match, _} = re:run(Message, <<"boom">>)
     end || _ <- lists:seq(1, 10)],
    Worker = whereis(wpool_pool:worker_name(?FUNCTION_NAME, 1)),
    Handler ! go,
    {ok, #{status := 200}} = katipo:await(Ref, ?WAIT).

%% What is not a response fails the request, and says what it was.
bad_response(_Config) ->
    [begin
         stub(?FUNCTION_NAME, fun(_) -> Bad end),
         {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>),
         {katipo_error, Ref, #{code := stub_failed, message := Message}} = next(),
         {match, _} = re:run(Message, <<"bad_stub_response">>)
     end || Bad <- [#{status => 700},
                    ok,
                    #{status => 200, headers => [<<"location: /x">>]},
                    #{status => 200, headers => [{<<"a">>, <<"b">>, extra}]},
                    #{status => 200, headers => #{}},
                    #{status => 200, headers => [{<<"a">>, b}]},
                    #{status => 200, body => body}]].

bad_stub(_Config) ->
    {error, #{code := bad_opts, message := Message}} =
        katipo_pool:start(?FUNCTION_NAME, 1, [{stub, fun() -> ok end}]),
    {match, _} = re:run(Message, <<"stub">>),
    %% Started, so end_per_testcase has a pool to stop.
    stub(?FUNCTION_NAME, fun(_) -> #{status => 200} end).

%% Any iodata is a body: a list of binaries and iolists is streamed a
%% chunk an element, and anything else as one chunk.
chunked_bodies(_Config) ->
    Streamed = fun(Body) ->
                       stub(?FUNCTION_NAME, fun(_) -> #{status => 200, body => Body} end),
                       {ok, #{body := Whole}} = katipo:get(?FUNCTION_NAME, <<"http://example.com/">>),
                       {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>,
                                                    #{stream => true}),
                       {katipo_headers, Ref, _} = next(),
                       {Whole, chunks(Ref, [])}
               end,
    {<<"hello">>, [<<"hello">>]} = Streamed("hello"),
    {<<"ab">>, [<<"ab">>]} = Streamed([<<"a">> | <<"b">>]),
    {<<"abc">>, [<<"a">>, <<"bc">>]} = Streamed([<<"a">>, [$b, <<"c">>]]),
    {<<"ab">>, [<<"ab">>]} = Streamed([$a, <<"b">>]).

max_body_size(_Config) ->
    stub(?FUNCTION_NAME, fun(_) -> #{status => 200, body => [<<"abc">>, <<"def">>]} end),
    {ok, #{body := <<"abcdef">>}} =
        katipo:get(?FUNCTION_NAME, <<"http://example.com/">>, #{max_body_size => 6}),
    {error, #{code := filesize_exceeded}} =
        katipo:get(?FUNCTION_NAME, <<"http://example.com/">>, #{max_body_size => 5}),
    %% Streamed, none of it is sent, though its first chunk would fit: the
    %% port knows the length from the start.
    {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>,
                                 #{stream => true, max_body_size => 4}),
    {katipo_error, Ref, #{code := filesize_exceeded}} = next(),
    {ok, Ref2} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>,
                                  #{stream => true, max_body_size => 6}),
    {katipo_headers, Ref2, _} = next(),
    [<<"abc">>, <<"def">>] = chunks(Ref2, []),
    %% A HEAD's response has no body to be too large.
    {ok, #{status := 200}} =
        katipo:head(?FUNCTION_NAME, <<"http://example.com/">>, #{max_body_size => 0}).

header_values_made_safe(_Config) ->
    stub(?FUNCTION_NAME, fun(_) -> #{status => 200, headers => [{<<"X">>, <<"a\r\nb", 0, "c">>}]} end),
    {ok, #{headers := [{<<"X">>, <<"a  b c">>}]}} =
        katipo:get(?FUNCTION_NAME, <<"http://example.com/">>).

%% A Handler that ends without answering fails its request, however it
%% ends: by exiting, even normally, or killed.
handler_exits(_Config) ->
    Self = self(),
    stub(?FUNCTION_NAME, fun(#{url := <<"http://exit/">>}) -> exit(normal);
                            (#{url := <<"http://throw/">>}) -> throw(up);
                            (_) -> Self ! {handler, self()}, receive after infinity -> ok end
                         end),
    {error, #{code := stub_failed, message := <<"{stub_exited,normal}">>}} =
        katipo:get(?FUNCTION_NAME, <<"http://exit/">>, #{timeout_ms => ?WAIT}),
    {error, #{code := stub_failed, message := <<"{{nocatch,up},", _/binary>>}} =
        katipo:get(?FUNCTION_NAME, <<"http://throw/">>, #{timeout_ms => ?WAIT}),
    {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://killed/">>),
    receive {handler, H} -> exit(H, kill) after ?WAIT -> ct:fail(no_handler) end,
    {katipo_error, Ref, #{code := stub_failed, message := <<"killed">>}} = next().

%% A Handler that traps exits still goes with its pool.
handler_killed_with_pool(_Config) ->
    Self = self(),
    stub(?FUNCTION_NAME, fun(_) ->
                                 process_flag(trap_exit, true),
                                 Self ! {handler, self()},
                                 receive after infinity -> ok end
                         end),
    {ok, _Ref} = katipo:async_get(?FUNCTION_NAME, <<"http://example.com/">>),
    Handler = receive {handler, H} -> H after ?WAIT -> ct:fail(no_handler) end,
    Mon = monitor(process, Handler),
    ok = katipo_pool:stop(?FUNCTION_NAME),
    receive {'DOWN', Mon, process, Handler, killed} -> ok
    after ?WAIT -> ct:fail(handler_outlived_pool)
    end,
    stub(?FUNCTION_NAME, fun(_) -> #{status => 200} end).

%% A Handler's mailbox is its own: its request's body and flow commands
%% do not reach it, and are not lost to it.
handler_mailbox(_Config) ->
    Self = self(),
    stub(?FUNCTION_NAME, fun(_) ->
                                 Self ! {handler, self()},
                                 receive
                                     go -> ok;
                                     Msg -> Self ! {handler_got, Msg}
                                 end,
                                 #{status => 200, body => [<<"a">>, <<"b">>, <<"c">>]}
                         end),
    {ok, Ref} = katipo:async_put(?FUNCTION_NAME, <<"http://example.com/">>,
                                 #{body => {stream, #{length => 1}},
                                   stream => true, stream_window => 1}),
    {katipo_body_demand, Ref} = next(),
    ok = katipo:send_body(?FUNCTION_NAME, Ref, <<"x">>),
    Handler = receive {handler, H} -> H after ?WAIT -> ct:fail(no_handler) end,
    %% While the Handler waits: an eof the body's length has no need of,
    %% and credits before the response has begun.
    ok = katipo:send_body(?FUNCTION_NAME, Ref, eof),
    ok = katipo:update_flow(?FUNCTION_NAME, Ref, 2),
    Worker = whereis(wpool_pool:worker_name(?FUNCTION_NAME, 1)),
    {Stub, _} = katipo_test_util:worker_state(Worker),
    ok = katipo_test_util:until(fun() ->
                                        process_info(Stub, [message_queue_len, status]) =:=
                                            [{message_queue_len, 0}, {status, waiting}]
                                end),
    Handler ! go,
    {katipo_headers, Ref, _} = next(),
    [<<"a">>, <<"b">>, <<"c">>] = chunks(Ref, []),
    receive {handler_got, Got} -> ct:fail({handler_got, Got}) after 0 -> ok end.

chunks(Ref, Acc) ->
    case next() of
        {katipo_chunk, Ref, C} -> chunks(Ref, [C | Acc]);
        {katipo_done, Ref, _} -> lists:reverse(Acc)
    end.

%% Commands for transfers the stub does not have -- ended, or never
%% started -- are dropped, as the port drops them.
unknown_transfers_ignored(_Config) ->
    stub(?FUNCTION_NAME, fun(_) -> #{status => 200} end),
    Worker = whereis(wpool_pool:worker_name(?FUNCTION_NAME, 1)),
    {Stub, _} = katipo_test_util:worker_state(Worker),
    [Stub ! {Worker, {command, iolist_to_binary(Frame)}}
     || Frame <- [term_to_binary({Worker, make_ref(), cancel}),
                  term_to_binary({Worker, make_ref(), flow, 1}),
                  term_to_binary({Worker, make_ref(), body, eof}),
                  [term_to_binary({Worker, make_ref(), body, <<>>}), <<"x">>]]],
    {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, <<"http://example.com/">>),
    {Stub, _} = katipo_test_util:worker_state(Worker).

%% (Re)start Pool as a stub pool of one worker.
stub(Pool, Handler) ->
    stub(Pool, [], Handler).

stub(Pool, Opts, Handler) ->
    _ = katipo_pool:stop(Pool),
    {ok, _} = katipo_pool:start(Pool, 1, [{stub, Handler} | Opts]).

%% A stub pool that sends the test each request it is given.
seen(Pool, Opts) ->
    Self = self(),
    stub(Pool, Opts, fun(Req) -> Self ! {req, Req}, #{status => 200} end).

req() ->
    receive {req, Req} -> Req
    after ?WAIT -> ct:fail(no_request)
    end.

next() ->
    case next(?WAIT) of
        nothing -> ct:fail(no_message);
        Msg -> Msg
    end.

%% The next message of an async request.
next(Timeout) ->
    receive
        Msg when element(1, Msg) =:= katipo_headers; element(1, Msg) =:= katipo_chunk;
                 element(1, Msg) =:= katipo_done; element(1, Msg) =:= katipo_response;
                 element(1, Msg) =:= katipo_error; element(1, Msg) =:= katipo_body_demand ->
            Msg
    after Timeout -> nothing
    end.
