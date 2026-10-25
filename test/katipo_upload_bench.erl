-module(katipo_upload_bench).

%% Upload throughput: the same body sent in memory, from a file, and
%% streamed in chunks of several sizes, to a local sink that discards it as
%% fast as it arrives. Reports MB/s and the CPU the C port and the VM spent
%% per MB. Not part of any suite; run with a test build:
%%
%%   rebar3 as test compile
%%   erl -noshell -pa _build/test/lib/*/ebin -pa _build/test/lib/katipo/test \
%%       -eval 'katipo_upload_bench:run(), halt().'
%%
%% run/1 takes #{size => Bytes, runs => N}; each case reports its median.

-export([run/0, run/1]).

-define(POOL, katipo_bench_pool).
-define(CHUNKS, [4096, 16384, 65536, 262144, 1048576]).

run() ->
    run(#{}).

run(Opts) ->
    Size = maps:get(size, Opts, 256 * 1048576),
    Runs = maps:get(runs, Opts, 5),
    {ok, _} = application:ensure_all_started(katipo),
    {ok, _} = katipo_pool:start(?POOL, 1, []),
    {Sink, Port} = sink(),
    Url = <<"http://127.0.0.1:", (integer_to_binary(Port))/binary, "/">>,
    Body = binary:copy(<<"x">>, Size),
    File = filename:join(os:getenv("TMPDIR", "/tmp"), "katipo_upload_bench.bin"),
    ok = file:write_file(File, Body),
    Cases = [{"iodata", fun() -> sync(Url, Body) end},
             {"file", fun() -> sync(Url, {file, File}) end}]
        ++ [{"stream " ++ human(C), fun() -> stream(Url, Size, C) end} || C <- ?CHUNKS],
    io:format("~nbody ~s, median of ~b runs~n~n", [human(Size), Runs]),
    io:format("~-14s ~10s ~16s ~16s~n", ["case", "MB/s", "port CPU ms/MB", "VM CPU ms/MB"]),
    [report(Name, Size, [measure(F) || _ <- lists:seq(1, Runs)]) || {Name, F} <- Cases],
    ok = file:delete(File),
    exit(Sink, kill),
    ok = katipo_pool:stop(?POOL).

sync(Url, Body) ->
    {ok, #{status := 200}} = katipo:put(?POOL, Url, #{body => Body, timeout_ms => 600000}),
    ok.

%% A caller that answers each demand at once with the same chunk.
stream(Url, Size, ChunkSize) ->
    Chunk = binary:copy(<<"x">>, ChunkSize),
    {ok, Ref} = katipo:async_put(?POOL, Url, #{body => {stream, #{length => Size}},
                                               timeout_ms => 600000}),
    feed(Ref, Size, Chunk).

feed(Ref, Left, Chunk) ->
    receive
        {katipo_body_demand, Ref} ->
            Take = min(Left, byte_size(Chunk)),
            ok = katipo:send_body(?POOL, Ref, binary:part(Chunk, 0, Take)),
            feed(Ref, Left - Take, Chunk);
        {katipo_response, Ref, #{status := 200}} ->
            ok;
        {katipo_error, Ref, Error} ->
            error({upload_failed, Error})
    end.

measure(F) ->
    Ports = port_pids(),
    P0 = cpu_ms(Ports),
    {V0, _} = statistics(runtime),
    T0 = erlang:monotonic_time(microsecond),
    ok = F(),
    T1 = erlang:monotonic_time(microsecond),
    {V1, _} = statistics(runtime),
    {T1 - T0, cpu_ms(Ports) - P0, V1 - V0}.

report(Name, Size, Samples) ->
    MB = Size / 1048576,
    {Us, PortMs, VmMs} = median(Samples),
    io:format("~-14s ~10.1f ~16.3f ~16.3f~n",
              [Name, MB / (Us / 1.0e6), PortMs / MB, VmMs / MB]).

median(Samples) ->
    lists:nth((length(Samples) + 1) div 2, lists:keysort(1, Samples)).

%% The OS pids of the pool's C ports.
port_pids() ->
    [Pid || P <- erlang:ports(),
            {name, Name} <- [erlang:port_info(P, name)],
            string:find(Name, "katipo") =/= nomatch,
            {os_pid, Pid} <- [erlang:port_info(P, os_pid)]].

%% User plus system CPU in ms: from /proc on Linux, else from ps, which
%% on macOS reports it to the hundredth of a second.
cpu_ms(Pids) ->
    lists:sum([cpu_ms1(integer_to_list(Pid)) || Pid <- Pids]).

cpu_ms1(Pid) ->
    case file:read_file("/proc/" ++ Pid ++ "/stat") of
        {ok, Stat} ->
            [_, AfterComm] = string:split(Stat, ") "),
            Fields = string:lexemes(AfterComm, " "),
            Ticks = binary_to_integer(lists:nth(12, Fields))
                + binary_to_integer(lists:nth(13, Fields)),
            Ticks * 1000 div list_to_integer(string:trim(os:cmd("getconf CLK_TCK")));
        {error, _} ->
            parse_time(string:trim(os:cmd("ps -o time= -p " ++ Pid)))
    end.

%% [[H:]M:]S.cc
parse_time(S) ->
    [Secs | Rest] = lists:reverse(string:split(S, ":", all)),
    {Whole, Cs} = case string:split(Secs, ".") of
                      [W, C] -> {W, C};
                      [W] -> {W, "0"}
                  end,
    Mins = lists:foldl(fun(P, Acc) -> Acc * 60 + list_to_integer(P) end, 0,
                       lists:reverse(Rest)),
    (Mins * 60 + list_to_integer(Whole)) * 1000 + list_to_integer(Cs) * 10.

human(N) when N >= 1048576 -> integer_to_list(N div 1048576) ++ "M";
human(N) -> integer_to_list(N div 1024) ++ "K".

%% A sink: one request per connection, Content-Length bodies, read and
%% dropped in large pieces, then 200.
sink() ->
    Self = self(),
    Pid = spawn(fun() ->
                        {ok, L} = gen_tcp:listen(0, [binary, {active, false},
                                                     {recbuf, 1048576}]),
                        {ok, Port} = inet:port(L),
                        Self ! {sink, Port},
                        sink_loop(L)
                end),
    receive {sink, Port} -> {Pid, Port} end.

sink_loop(L) ->
    {ok, S} = gen_tcp:accept(L),
    spawn(fun() -> sink_conn(S) end) ! go,
    sink_loop(L).

sink_conn(S) ->
    receive go -> sink_conn_next(S) end.

%% Keep the connection for the next request, as curl reuses it.
sink_conn_next(S) ->
    case head(S, <<>>) of
        closed -> gen_tcp:close(S);
        {Head, Rest} ->
            Lower = string:lowercase(Head),
            {match, [Len]} = re:run(Lower, <<"content-length: *([0-9]+)">>,
                                    [{capture, all_but_first, binary}]),
            %% curl holds a body over 1 MB behind Expect: 100-continue for
            %% up to a second; answer it, as most servers do.
            [ok = gen_tcp:send(S, <<"HTTP/1.1 100 Continue\r\n\r\n">>)
             || binary:match(Lower, <<"expect: 100-continue">>) =/= nomatch],
            drain(S, binary_to_integer(Len) - byte_size(Rest)),
            ok = gen_tcp:send(S, <<"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n">>),
            sink_conn_next(S)
    end.

head(S, Acc) ->
    case binary:split(Acc, <<"\r\n\r\n">>) of
        [H, R] -> {H, R};
        [_] ->
            case gen_tcp:recv(S, 0) of
                {ok, D} -> head(S, <<Acc/binary, D/binary>>);
                {error, _} -> closed
            end
    end.

drain(_S, Left) when Left =< 0 -> ok;
drain(S, Left) ->
    {ok, D} = gen_tcp:recv(S, 0),
    drain(S, Left - byte_size(D)).
