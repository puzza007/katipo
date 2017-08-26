-module(katipo_metrics).

-export([init/0]).
-export([notify/3]).
-export([notify_error/0]).

-spec notify(katipo:response(), katipo:metrics(), number()) -> katipo:metrics().
notify({ok, Response}, Metrics, TotalUs) ->
    #{status := Status} = Response,
    StatusMetric = status_metric_name(Status),
    ok = metrics:update_or_create(StatusMetric, {c, 1}, spiral),
    OkMetric = name(ok),
    ok = metrics:update_or_create(OkMetric, {c, 1}, spiral),
    notify_metrics(Metrics, TotalUs);
notify({error, _Error}, Metrics, TotalUs) ->
    ok = notify_error(),
    notify_metrics(Metrics, TotalUs).

notify_error() ->
    ErrorMetric = name(error),
    ok = metrics:update_or_create(ErrorMetric, {c, 1}, spiral).

name(M) ->
    L = atom_to_list(M),
    "katipo." ++ L.

status_metric_name(Status) when is_integer(Status) ->
    L = integer_to_list(Status),
    "katipo.status." ++ L.

notify_metrics(Metrics, TotalUs) ->
    %% Curl metrics are in seconds
    Metrics1 = [{K, 1000 * V} || {K, V} <- Metrics],
    %% now_diff is in microsecs
    Total = TotalUs / 1000.0,
    Metrics3 =
        case lists:keytake(total_time, 1, Metrics1) of
            {value, {total_time, CurlTotal}, Metrics2} ->
                [{curl_time, CurlTotal},
                 {total_time, Total} | Metrics2];
            false ->
                [{total_time, Total} | Metrics1]
        end,
    Notify = fun({K, V}) ->
                     Name = name(K),
                     ok = metrics:update_or_create(Name, {c, V}, histogram)
             end,
    ok = lists:foreach(Notify, Metrics3),
    Metrics3.

-spec init() -> ok.
init() ->
    Mod = mod_metrics(),
    ok = metrics:backend(Mod).

mod_metrics() ->
    case application:get_env(katipo, mod_metrics, noop) of
        folsom -> metrics_folsom;
        exometer -> metrics_exometer;
        noop -> metrics_noop;
        Mod -> Mod
    end.
