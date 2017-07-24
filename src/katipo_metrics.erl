-module(katipo_metrics).

-export([init/0]).
-export([notify/3]).
-export([notify_error/0]).

-spec notify(katipo:response(), proplists:proplist(),
             number()) -> ok.
notify({_, _} = Ret, Metrics, TotalUs) ->
    MetricsEngine = application:get_env(katipo, metrics_engine, metrics_dummy),
    notify(MetricsEngine, Ret, Metrics, TotalUs).

notify(MetricsEngine, {ok, Response}, Metrics, TotalUs) ->
    #{status := Status} = Response,
    StatusMetric = status_metric_name(Status),
    ok = metrics:increment_spiral(MetricsEngine, StatusMetric),
    OkMetric = name(ok),
    ok = metrics:increment_spiral(MetricsEngine, OkMetric),
    ok = notify_metrics(MetricsEngine, Metrics, TotalUs);
notify(MetricsEngine, {error, _Error}, Metrics, TotalUs) ->
    ok = notify_error(MetricsEngine),
    ok = notify_metrics(MetricsEngine, Metrics, TotalUs).

notify_error() ->
    MetricsEngine = application:get_env(katipo, metrics_engine, metrics_dummy),
    notify_error(MetricsEngine).

notify_error(MetricsEngine) ->
    ErrorMetric = name(error),
    ok = metrics:increment_spiral(MetricsEngine, ErrorMetric).
    
name(M) ->
    B = atom_to_binary(M, latin1),
    <<"katipo.", B/binary>>.

status_metric_name(Status) when is_integer(Status) ->
    B = integer_to_binary(Status),
    <<"katipo.status.", B/binary>>.

notify_metrics(MetricsEngine, Metrics, TotalUs) ->
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
                     ok = metrics:update_histogram(MetricsEngine, Name, V)
             end,
    ok = lists:foreach(Notify, Metrics3).

-spec init() -> ok.
init() ->
    Mod = mod_metrics(),
    MetricsEngine = metrics:init(Mod),
    ok = application:set_env(katipo, metrics_engine, MetricsEngine).

mod_metrics() ->
    case application:get_env(katipo, mod_metrics, metrics_dummy) of
        folsom -> metrics_folsom;
        exometer -> metrics_exometers;
        dummy -> metrics_dummy;
        Mod -> Mod
    end.
