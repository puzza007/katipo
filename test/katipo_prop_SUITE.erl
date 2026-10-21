-module(katipo_prop_SUITE).

%% Property tests, end to end through the C port against a local scripted
%% server (katipo_prop_server), so the C encoder and decoder are under
%% test rather than models of them: response bodies (the body frame)
%% arrive byte-for-byte, buffered and streamed, and a kept body references
%% at most twice its own size.
%%
%% Generators are weighted toward edges, and generators_cover_edges checks
%% by sampling that they actually reach them.

-include_lib("common_test/include/ct.hrl").
-include_lib("proper/include/proper.hrl").

-compile(export_all).
-compile(nowarn_export_all).

-define(POOL, katipo_prop_pool).
-define(NUMTESTS, 300).
%% Binaries this small live on the heap, where referenced_byte_size/1
%% counts something other than the bytes a sub-binary pins.
-define(HEAP_BIN_LIMIT, 64).

all() ->
    [generators_cover_edges,
     buffered_body_round_trips,
     streamed_body_round_trips].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    {ok, _} = katipo_pool:start(?POOL, 2, []),
    {ok, Server, Port} = katipo_prop_server:start(),
    [{server, Server}, {port, Port} | Config].

end_per_suite(Config) ->
    ok = katipo_pool:stop(?POOL),
    ok = katipo_prop_server:stop(?config(server, Config)),
    application:stop(katipo),
    Config.

run(Prop) ->
    case proper:quickcheck(Prop, [{numtests, ?NUMTESTS},
                                  {to_file, user},
                                  long_result]) of
        true -> ok;
        CounterExample -> ct:fail({property_failed, CounterExample})
    end.

%% =====================================================================
%% Response bodies
%% =====================================================================

buffered_body_round_trips(Config) ->
    Port = ?config(port, Config),
    run(?FORALL({Body, Headers}, {resp_body(), resp_body_headers()},
                begin
                    Url = raw_response(Port, Body, Headers),
                    {ok, #{status := 200, headers := Got, body := B}} =
                        katipo:get(?POOL, Url),
                    B =:= Body andalso has_headers(Headers, Got)
                        andalso bounded(B)
                end)).

streamed_body_round_trips(Config) ->
    Port = ?config(port, Config),
    run(?FORALL({Body, Headers}, {resp_body(), resp_body_headers()},
                begin
                    Url = raw_response(Port, Body, Headers),
                    {ok, Ref} = katipo:async_get(?POOL, Url, #{stream => true}),
                    {200, Got, Chunks} = collect(Ref),
                    iolist_to_binary(Chunks) =:= Body
                        andalso has_headers(Headers, Got)
                        andalso lists:all(fun bounded/1, Chunks)
                end)).

raw_response(Port, Body, Headers) ->
    katipo_prop_server:script(
      Port, key(),
      {raw, iolist_to_binary(
              [<<"HTTP/1.1 200 OK\r\n">>,
               [[K, <<": ">>, V, <<"\r\n">>] || {K, V} <- Headers],
               <<"content-length: ">>, integer_to_binary(byte_size(Body)),
               <<"\r\n\r\n">>, Body])}).

%% A kept body is the frame's sub-binary only when it is at least half the
%% frame, and a copy of exactly its own size otherwise.
bounded(B) when byte_size(B) =< ?HEAP_BIN_LIMIT ->
    true;
bounded(B) ->
    binary:referenced_byte_size(B) =< 2 * byte_size(B).

has_headers(Sent, Got) ->
    lists:all(fun(H) -> lists:member(H, Got) end, Sent).

collect(Ref) ->
    receive
        {katipo_headers, Ref, #{status := Status, headers := Headers}} ->
            {Status, Headers, collect_chunks(Ref, [])}
    after 10000 ->
            ct:fail(no_stream_headers)
    end.

collect_chunks(Ref, Acc) ->
    receive
        {katipo_chunk, Ref, Chunk} -> collect_chunks(Ref, [Chunk | Acc]);
        {katipo_done, Ref, #{}} -> lists:reverse(Acc);
        {katipo_error, Ref, Error} -> ct:fail({stream_error, Error})
    after 10000 ->
            ct:fail(no_stream_done)
    end.

resp_body() ->
    ?LET({Len, Seed, Lead}, {resp_body_len(), non_empty(binary()), lead()},
         fill(Len, Seed, Lead)).

resp_body_len() ->
    frequency([{1, exactly(0)},
               {3, range(1, 200)},
               {3, range(?HEAP_BIN_LIMIT - 2, ?HEAP_BIN_LIMIT + 2)},
               {3, range(200, 4000)},           %% the copy/share cutoff
               {2, range(16384 - 4, 16384 + 4)},
               {1, range(16384, 300000)}]).

%% 131 is the external term format's version byte: a body that starts
%% like a term must still be treated as opaque bytes.
lead() ->
    frequency([{4, exactly(<<>>)}, {1, exactly(<<131>>)},
               {1, exactly(<<131, 109>>)}]).

%% Len bytes: Lead, then Seed repeated. Shrinks with Seed, unlike random
%% bytes drawn outside PropEr.
fill(Len, Seed, Lead) ->
    Repeated = binary:copy(Seed, Len div byte_size(Seed) + 1),
    binary:part(<<Lead/binary, Repeated/binary>>, 0, Len).

%% Plain headers whose only job is to move the copy/share cutoff.
resp_body_headers() ->
    ?LET(N, range(0, 40),
         [{<<"x-prop-", (integer_to_binary(I))/binary>>, filler_value()}
          || I <- lists:seq(1, N)]).

filler_value() ->
    ?LET(Len, range(1, 120), list_to_binary(lists:duplicate(Len, $v))).

%% =====================================================================
%% Generator coverage
%% =====================================================================

%% Sample each generator and require every edge it is weighted toward to
%% turn up often enough that ?NUMTESTS cases are all but certain to hit
%% it. A generator that drifts away from its edges fails here, not by
%% silently testing less.
generators_cover_edges(_Config) ->
    N = 2000,
    check_coverage(resp_body, N, resp_body(), fun(B) -> byte_size(B) end,
                   [{empty, fun(S) -> S =:= 0 end, 0.03},
                    {around_heap_limit,
                     fun(S) -> S >= ?HEAP_BIN_LIMIT - 2 andalso S =< ?HEAP_BIN_LIMIT + 2 end,
                     0.1},
                    {cutoff_range, fun(S) -> S >= 200 andalso S =< 4000 end, 0.15},
                    {around_16k, fun(S) -> abs(S - 16384) =< 4 end, 0.08},
                    {over_16k, fun(S) -> S > 16388 end, 0.03}]),
    check_coverage(resp_body_lead, N, resp_body(),
                   fun(<<Lead, _/binary>>) -> Lead; (_) -> none end,
                   [{starts_like_a_term, fun(Lead) -> Lead =:= 131 end,
                     0.15}]),
    ok.

check_coverage(Name, N, Gen, Classify, Classes) ->
    Samples = [Classify(sample(Gen)) || _ <- lists:seq(1, N)],
    Shares = [{Class, length([S || S <- Samples, Pred(S)]) / N, Min}
              || {Class, Pred, Min} <- Classes],
    ct:pal("~p coverage over ~B samples:~n~s",
           [Name, N, [io_lib:format("  ~-26w ~5.1f%  (min ~4.1f%)~n",
                                    [C, 100 * S, 100 * M])
                      || {C, S, M} <- Shares]]),
    case [C || {C, S, Min} <- Shares, S < Min] of
        [] -> ok;
        Short -> ct:fail({under_covered, Name, Short})
    end.

%% A value as quickcheck would draw it across a run: sizes 1..42.
sample(Gen) ->
    {ok, V} = proper_gen:pick(Gen, rand:uniform(42)),
    V.

key() ->
    integer_to_binary(erlang:unique_integer([positive])).
