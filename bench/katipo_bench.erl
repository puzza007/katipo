-module(katipo_bench).

%% Throughput of buffered responses through one katipo worker, against a
%% local keep-alive HTTP/1.1 server serving /<Bytes> from memory, so the
%% port and the worker -- not the network or a slow server -- are what is
%% measured. Reports requests/s and the CPU time of the C port process,
%% from ps: 10 ms ticks on macOS, but whole seconds on Linux, where that
%% column means little. Run with bench/run.sh.

-export([main/1]).

-define(POOL, katipo_bench).

main(Args) ->
    Reps = case Args of [R] -> list_to_integer(R); _ -> 3 end,
    {ok, _} = application:ensure_all_started(katipo),
    {ok, _} = katipo_pool:start(?POOL, 1, []),
    Port = start_server(),
    OsPid = port_os_pid(),
    io:format("~-10s ~8s ~6s ~10s ~10s ~12s~n",
              ["body", "requests", "conc", "req/s", "MB/s", "port CPU ms"]),
    [run(Port, OsPid, Size, N, C, Reps)
     || {Size, N, C} <- [{1024, 20000, 16},
                         {65536, 5000, 16},
                         {1048576, 1000, 8},
                         {10485760, 100, 4}]],
    ok.

run(Port, OsPid, Size, N, Conc, Reps) ->
    Url = iolist_to_binary(["http://127.0.0.1:", integer_to_list(Port), "/",
                            integer_to_list(Size)]),
    _ = batch(Url, Size, min(N, 50), Conc),   %% warm up the connections
    Results = [measure(Url, OsPid, Size, N, Conc) || _ <- lists:seq(1, Reps)],
    {Secs, CpuMs} = median(Results),
    io:format("~-10s ~8B ~6B ~10B ~10.1f ~12B~n",
              [human(Size), N, Conc, round(N / Secs), N * Size / Secs / 1048576, CpuMs]).

measure(Url, OsPid, Size, N, Conc) ->
    Cpu0 = cpu_ms(OsPid),
    T0 = erlang:monotonic_time(microsecond),
    ok = batch(Url, Size, N, Conc),
    T1 = erlang:monotonic_time(microsecond),
    {(T1 - T0) / 1.0e6, cpu_ms(OsPid) - Cpu0}.

%% N requests, Conc in flight at a time. A failed request stops the run.
batch(Url, Size, N, Conc) ->
    Mons = [spawn_monitor(fun() -> worker(Url, Size, K) end)
            || I <- lists:seq(1, Conc),
               K <- [N div Conc + if I =< N rem Conc -> 1; true -> 0 end]],
    [receive {'DOWN', M, process, P, R} -> normal = R end || {P, M} <- Mons],
    ok.

worker(_Url, _Size, 0) ->
    ok;
worker(Url, Size, K) ->
    {ok, #{status := 200, body := B}} = katipo:get(?POOL, Url, #{timeout_ms => 60000}),
    Size = byte_size(B),
    worker(Url, Size, K - 1).

median(Results) ->
    Sorted = lists:sort(Results),
    lists:nth((length(Sorted) + 1) div 2, Sorted).

human(B) when B >= 1048576 -> integer_to_list(B div 1048576) ++ "MB";
human(B) when B >= 1024 -> integer_to_list(B div 1024) ++ "KB";
human(B) -> integer_to_list(B) ++ "B".

%% The C port's OS pid: the pool has one worker, so one katipo port.
port_os_pid() ->
    [Port] = [P || P <- erlang:ports(),
                   {name, Name} <- [erlang:port_info(P, name)],
                   string:find(Name, "priv/katipo") =/= nomatch],
    {os_pid, OsPid} = erlang:port_info(Port, os_pid),
    OsPid.

%% user + system CPU of a process, in ms, from ps (cputime is [hh:]mm:ss.ss,
%% in 10 ms ticks on macOS).
cpu_ms(OsPid) ->
    Out = string:trim(os:cmd("ps -o time= -p " ++ integer_to_list(OsPid))),
    Secs = lists:foldl(fun(F, A) -> A * 60 + num(F) end, 0, string:split(Out, ":", all)),
    round(Secs * 1000).

num(S) ->
    try list_to_float(S) catch error:badarg -> list_to_integer(S) end.

%% ---- a minimal keep-alive HTTP/1.1 server serving GET /<Bytes> ----

start_server() ->
    Self = self(),
    spawn_link(fun() ->
        {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true},
                                     {packet, http_bin}, {backlog, 128}]),
        {ok, P} = inet:port(L),
        Self ! {port, P},
        accept(L)
    end),
    receive {port, P} -> P end.

accept(L) ->
    {ok, S} = gen_tcp:accept(L),
    Pid = spawn(fun() -> receive go -> conn(S, #{}) end end),
    ok = gen_tcp:controlling_process(S, Pid),
    Pid ! go,
    accept(L).

conn(S, Cache) ->
    case gen_tcp:recv(S, 0) of
        {ok, {http_request, 'GET', {abs_path, <<"/", N/binary>>}, _}} ->
            ok = skip_headers(S),
            Size = binary_to_integer(N),
            {Body, Cache2} = body(Size, Cache),
            ok = gen_tcp:send(S, [<<"HTTP/1.1 200 OK\r\nContent-Length: ">>,
                                  integer_to_binary(Size), <<"\r\n\r\n">>, Body]),
            conn(S, Cache2);
        _ ->
            gen_tcp:close(S)
    end.

skip_headers(S) ->
    case gen_tcp:recv(S, 0) of
        {ok, http_eoh} -> ok;
        {ok, {http_header, _, _, _, _}} -> skip_headers(S)
    end.

body(Size, Cache) ->
    case Cache of
        #{Size := B} -> {B, Cache};
        _ -> B = binary:copy(<<"x">>, Size), {B, Cache#{Size => B}}
    end.
