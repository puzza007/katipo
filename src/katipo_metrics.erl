%% @hidden
-module(katipo_metrics).

-export([notify/3]).
-export([notify_error/0]).

-spec notify(katipo:response(), katipo:metrics(), number()) -> katipo:metrics().
notify({ok, Response}, Metrics, TotalUs) ->
    #{status := Status} = Response,
    Metrics2 = process_metrics(Metrics, TotalUs),

    %% Convert metrics list to a measurements map
    Measurements = maps:from_list(Metrics2),

    %% Emit telemetry event for successful request
    telemetry:execute(
        [katipo, request, stop],
        Measurements,
        #{result => ok, status => Status}
    ),

    Metrics2;
notify({error, Error}, Metrics, TotalUs) ->
    Metrics2 = process_metrics(Metrics, TotalUs),

    %% Convert metrics list to a measurements map
    Measurements = maps:from_list(Metrics2),

    %% Emit telemetry event for error
    telemetry:execute(
        [katipo, request, exception],
        Measurements,
        #{kind => error, reason => Error}
    ),

    Metrics2.

notify_error() ->
    %% Emit telemetry event for error without detailed metrics
    telemetry:execute(
        [katipo, request, exception],
        #{},
        #{kind => error}
    ),
    ok.

process_metrics(Metrics, TotalUs) ->
    %% Curl metrics are in seconds, convert to milliseconds
    Metrics1 = [{K, 1000 * V} || {K, V} <- Metrics],
    %% now_diff is in microsecs, convert to milliseconds
    Total = TotalUs / 1000.0,
    case lists:keytake(total_time, 1, Metrics1) of
        {value, {total_time, CurlTotal}, Metrics2} ->
            [{curl_time, CurlTotal},
             {total_time, Total} | Metrics2];
        false ->
            [{total_time, Total} | Metrics1]
    end.
