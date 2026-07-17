-module(katipo_metrics).
-moduledoc false.

-include_lib("opentelemetry_api_experimental/include/otel_meter.hrl").

%% Suppress dialyzer warnings from OTel macro expansion
%% (macros use is_atom checks that always match since we use atom names)
-dialyzer({nowarn_function, [create_instruments/0, emit/4,
                             emit_timing_metrics/3, record_timing/3]}).

-export([init/0]).
-export([notify/4]).

%% Metric names
-define(REQUESTS_COUNTER, 'http.client.requests').
-define(DURATION_HISTOGRAM, 'http.client.duration').
-define(CURL_TIME_HISTOGRAM, 'http.client.curl_time').
-define(NAMELOOKUP_TIME_HISTOGRAM, 'http.client.namelookup_time').
-define(CONNECT_TIME_HISTOGRAM, 'http.client.connect_time').
-define(APPCONNECT_TIME_HISTOGRAM, 'http.client.appconnect_time').
-define(PRETRANSFER_TIME_HISTOGRAM, 'http.client.pretransfer_time').
-define(REDIRECT_TIME_HISTOGRAM, 'http.client.redirect_time').
-define(STARTTRANSFER_TIME_HISTOGRAM, 'http.client.starttransfer_time').

-spec init() -> ok.
init() ->
    %% When no OTel metrics SDK is configured, the experimental API's noop meter
    %% raises undef (opentelemetry-erlang#876). Guard instrument creation the
    %% same way the record path is guarded, so starting katipo can't crash the
    %% whole application on a plain (no-SDK) deployment.
    try create_instruments()
    catch error:undef -> ok end,
    ok.

create_instruments() ->
    %% Create request counter
    _ = ?create_counter(?REQUESTS_COUNTER, #{
        description => <<"Number of HTTP requests made">>,
        unit => request
    }),
    %% Create timing histograms
    _ = ?create_histogram(?DURATION_HISTOGRAM, #{
        description => <<"Total request duration (Erlang-side)">>,
        unit => ms
    }),
    _ = ?create_histogram(?CURL_TIME_HISTOGRAM, #{
        description => <<"Curl total time">>,
        unit => ms
    }),
    _ = ?create_histogram(?NAMELOOKUP_TIME_HISTOGRAM, #{
        description => <<"DNS lookup time">>,
        unit => ms
    }),
    _ = ?create_histogram(?CONNECT_TIME_HISTOGRAM, #{
        description => <<"Connection time">>,
        unit => ms
    }),
    _ = ?create_histogram(?APPCONNECT_TIME_HISTOGRAM, #{
        description => <<"SSL/TLS handshake time">>,
        unit => ms
    }),
    _ = ?create_histogram(?PRETRANSFER_TIME_HISTOGRAM, #{
        description => <<"Pre-transfer time">>,
        unit => ms
    }),
    _ = ?create_histogram(?REDIRECT_TIME_HISTOGRAM, #{
        description => <<"Redirect processing time">>,
        unit => ms
    }),
    _ = ?create_histogram(?STARTTRANSFER_TIME_HISTOGRAM, #{
        description => <<"Time to first byte">>,
        unit => ms
    }),
    ok.

-spec notify(katipo:response(), katipo:metrics(), number(), binary()) -> ok.
notify(Result, Metrics, TotalUs, Method) ->
    %% One guard around the whole emission rather than one per instrument: with
    %% no metrics SDK the noop meter raises undef on the first call, so a single
    %% catch skips the rest (down from up to nine exceptions per request). It is
    %% re-attempted every request, so metrics begin flowing if an SDK is
    %% configured after startup.
    try emit(Result, Metrics, TotalUs, Method)
    catch error:undef -> ok end,
    ok.

emit({ok, Response}, Metrics, TotalUs, Method) ->
    #{status := Status} = Response,
    Attrs = #{result => ok, 'http.response.status_code' => Status},
    ?counter_add(?REQUESTS_COUNTER, 1, Attrs),
    emit_timing_metrics(Metrics, TotalUs, Method);
emit({error, _Error}, Metrics, TotalUs, Method) ->
    ?counter_add(?REQUESTS_COUNTER, 1, #{result => error}),
    emit_timing_metrics(Metrics, TotalUs, Method).

emit_timing_metrics(Metrics, TotalUs, Method) ->
    %% Curl metrics are in seconds, convert to milliseconds
    Metrics1 = [{K, 1000 * V} || {K, V} <- Metrics],
    %% now_diff is in microsecs, convert to milliseconds
    TotalMs = TotalUs / 1000.0,
    Metrics3 =
        case lists:keytake(total_time, 1, Metrics1) of
            {value, {total_time, CurlTotal}, Metrics2} ->
                [{curl_time, CurlTotal},
                 {total_time, TotalMs} | Metrics2];
            false ->
                [{total_time, TotalMs} | Metrics1]
        end,
    Attrs = #{'http.request.method' => Method},
    lists:foreach(fun({K, V}) -> record_timing(K, V, Attrs) end, Metrics3).

record_timing(total_time, V, Attrs) ->
    ?histogram_record(?DURATION_HISTOGRAM, V, Attrs);
record_timing(curl_time, V, Attrs) ->
    ?histogram_record(?CURL_TIME_HISTOGRAM, V, Attrs);
record_timing(namelookup_time, V, Attrs) ->
    ?histogram_record(?NAMELOOKUP_TIME_HISTOGRAM, V, Attrs);
record_timing(connect_time, V, Attrs) ->
    ?histogram_record(?CONNECT_TIME_HISTOGRAM, V, Attrs);
record_timing(appconnect_time, V, Attrs) ->
    ?histogram_record(?APPCONNECT_TIME_HISTOGRAM, V, Attrs);
record_timing(pretransfer_time, V, Attrs) ->
    ?histogram_record(?PRETRANSFER_TIME_HISTOGRAM, V, Attrs);
record_timing(redirect_time, V, Attrs) ->
    ?histogram_record(?REDIRECT_TIME_HISTOGRAM, V, Attrs);
record_timing(starttransfer_time, V, Attrs) ->
    ?histogram_record(?STARTTRANSFER_TIME_HISTOGRAM, V, Attrs);
record_timing(_, _, _) ->
    ok.
