-module(katipo_test_util).

%% What the suites share.

-export([worker_state/1]).
-export([until/1]).
-export([until/2]).

%% A worker's port, or the stub standing in for it, and the requests it
%% has in flight: katipo_worker's #state{port, reqs}, inside
%% wpool_process's own state. Neither has a public seam, so this is the
%% one place that knows the shape of both, and fails loudly if either
%% changes.
-spec worker_state(pid()) -> {port() | pid(), map()}.
worker_state(Worker) ->
    {state, _, _, {state, Port, Reqs, _Ids, _Max, _Gen, _Defaults}, _} = sys:get_state(Worker),
    {Port, Reqs}.

%% Poll until Fun() is true, for five seconds unless told how long.
-spec until(fun(() -> boolean())) -> ok | timeout.
until(Fun) ->
    until(Fun, 5000).

-spec until(fun(() -> boolean()), non_neg_integer()) -> ok | timeout.
until(Fun, Ms) ->
    poll(Fun, erlang:monotonic_time(millisecond) + Ms).

poll(Fun, Deadline) ->
    case Fun() of
        true ->
            ok;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> timeout;
                false -> timer:sleep(10), poll(Fun, Deadline)
            end
    end.
