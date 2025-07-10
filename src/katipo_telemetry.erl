-module(katipo_telemetry).

-export([init/0,
         record_request/4]).

%% Exported for testing
-export([build_measurements/2,
         build_metadata/3,
         parse_url_metadata/2,
         get_metric_value/3,
         ensure_binary/1]).

-define(PREFIX, [katipo, request]).

init() ->
    %% Declare telemetry events that will be emitted
    Events = [
        %% HTTP request completed event
        {?PREFIX ++ [stop],
         #{description => <<"Emitted when an HTTP request completes">>,
           measurements => <<"duration: total request duration in milliseconds\n"
                            "response_body_size: size of response body in bytes\n"
                            "namelookup_time: DNS lookup time in milliseconds\n"
                            "connect_time: connection time in milliseconds\n"
                            "appconnect_time: SSL/TLS handshake time in milliseconds\n"
                            "pretransfer_time: time until transfer starts in milliseconds\n"
                            "redirect_time: time spent on redirects in milliseconds\n"
                            "starttransfer_time: time until first byte in milliseconds">>,
           metadata => <<"method: HTTP method atom\n"
                         "url: request URL\n"
                         "status: HTTP status code (if successful)\n"
                         "scheme: URL scheme (http/https)\n"
                         "host: server hostname\n"
                         "port: server port (if specified)">>}},

        %% HTTP request error event
        {?PREFIX ++ [error],
         #{description => <<"Emitted when an HTTP request fails">>,
           measurements => <<"count: always 1">>,
           metadata => <<"method: HTTP method atom\n"
                         "url: request URL\n"
                         "error: error reason">>}}
    ],
    lists:foreach(fun({Event, _Doc}) ->
        telemetry:attach(
            list_to_atom(lists:concat([katipo, "_", lists:last(Event)])),
            Event,
            fun log_handler/4,
            undefined
        )
    end, Events),
    ok.

record_request(Method, Url, Response, Metrics) ->
    Measurements = build_measurements(Response, Metrics),
    Metadata = build_metadata(Method, Url, Response),

    case Response of
        {ok, _} ->
            telemetry:execute(?PREFIX ++ [stop], Measurements, Metadata);
        {error, _} ->
            telemetry:execute(?PREFIX ++ [error], #{count => 1}, Metadata)
    end.

build_measurements({ok, #{body := Body}}, Metrics) ->
    #{
        duration => get_metric_value(total_time, Metrics, 0),
        response_body_size => iolist_size(Body),
        namelookup_time => get_metric_value(namelookup_time, Metrics, 0),
        connect_time => get_metric_value(connect_time, Metrics, 0),
        appconnect_time => get_metric_value(appconnect_time, Metrics, 0),
        pretransfer_time => get_metric_value(pretransfer_time, Metrics, 0),
        redirect_time => get_metric_value(redirect_time, Metrics, 0),
        starttransfer_time => get_metric_value(starttransfer_time, Metrics, 0)
    };
build_measurements(_, Metrics) ->
    #{
        duration => get_metric_value(total_time, Metrics, 0),
        namelookup_time => get_metric_value(namelookup_time, Metrics, 0),
        connect_time => get_metric_value(connect_time, Metrics, 0),
        appconnect_time => get_metric_value(appconnect_time, Metrics, 0),
        pretransfer_time => get_metric_value(pretransfer_time, Metrics, 0),
        redirect_time => get_metric_value(redirect_time, Metrics, 0),
        starttransfer_time => get_metric_value(starttransfer_time, Metrics, 0)
    }.

build_metadata(Method, Url, {ok, #{status := Status}}) ->
    BaseMetadata = parse_url_metadata(Method, Url),
    BaseMetadata#{status => Status};
build_metadata(Method, Url, {error, #{code := Code}}) ->
    BaseMetadata = parse_url_metadata(Method, Url),
    BaseMetadata#{error => Code}.

parse_url_metadata(Method, Url) ->
    Base = #{method => Method, url => Url},
    case uri_string:parse(Url) of
        #{scheme := Scheme, host := Host} = UrlMap ->
            Base1 = Base#{
                scheme => ensure_binary(Scheme),
                host => ensure_binary(Host)
            },
            case maps:get(port, UrlMap, undefined) of
                undefined -> Base1;
                Port -> Base1#{port => Port}
            end;
        _ ->
            Base
    end.

ensure_binary(Value) when is_binary(Value) -> Value;
ensure_binary(Value) when is_list(Value) -> list_to_binary(Value);
ensure_binary(Value) -> iolist_to_binary(io_lib:format("~p", [Value])).

get_metric_value(Key, Metrics, Default) ->
    case lists:keyfind(Key, 1, Metrics) of
        {Key, Value} -> Value;
        false -> Default
    end.

%% Simple log handler for development - users should attach their own handlers
log_handler(_EventName, _Measurements, _Metadata, _Config) ->
    ok.