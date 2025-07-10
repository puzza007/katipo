-module(katipo_telemetry_SUITE).

-compile([{nowarn_export_all, true}]).
-compile(export_all).

-include_lib("common_test/include/ct.hrl").

suite() ->
    [{timetrap, {seconds, 30}}].

init_per_suite(Config) ->
    application:ensure_all_started(telemetry),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

all() ->
    [
     init_test,
     record_successful_request,
     record_error_request,
     build_measurements_with_body,
     build_measurements_without_body,
     build_metadata_success,
     build_metadata_error,
     parse_url_metadata,
     get_metric_value_test
    ].

init_test(_) ->
    %% Test that init doesn't crash
    ok = katipo_telemetry:init().

record_successful_request(_) ->
    %% Test recording a successful request
    TestPid = self(),
    HandlerFun = fun(EventName, Measurements, Metadata, _Config) ->
        TestPid ! {telemetry_event, EventName, Measurements, Metadata}
    end,

    telemetry:attach(
        test_successful_request,
        [katipo, request, stop],
        HandlerFun,
        undefined
    ),

    %% Mock successful response and metrics
    Method = get,
    Url = <<"https://example.com/test">>,
    Response = {ok, #{status => 200, body => <<"test body">>}},
    Metrics = [
        {total_time, 150},
        {namelookup_time, 10},
        {connect_time, 30},
        {appconnect_time, 50},
        {pretransfer_time, 70},
        {redirect_time, 0},
        {starttransfer_time, 100}
    ],

    %% Record the request
    katipo_telemetry:record_request(Method, Url, Response, Metrics),

    %% Verify event was emitted
    receive
        {telemetry_event, [katipo, request, stop], EventMeasurements, EventMetadata} ->
            %% Check measurements
            150 = maps:get(duration, EventMeasurements),
            9 = maps:get(response_body_size, EventMeasurements),  % "test body" = 9 bytes
            10 = maps:get(namelookup_time, EventMeasurements),
            30 = maps:get(connect_time, EventMeasurements),
            50 = maps:get(appconnect_time, EventMeasurements),
            70 = maps:get(pretransfer_time, EventMeasurements),
            0 = maps:get(redirect_time, EventMeasurements),
            100 = maps:get(starttransfer_time, EventMeasurements),

            %% Check metadata
            get = maps:get(method, EventMetadata),
            <<"https://example.com/test">> = maps:get(url, EventMetadata),
            200 = maps:get(status, EventMetadata),
            <<"https">> = maps:get(scheme, EventMetadata),
            <<"example.com">> = maps:get(host, EventMetadata),

            ok
    after 1000 ->
        error(no_telemetry_event)
    end,

    telemetry:detach(test_successful_request).

record_error_request(_) ->
    %% Test recording an error request
    TestPid = self(),
    HandlerFun = fun(EventName, Measurements, Metadata, _Config) ->
        TestPid ! {telemetry_event, EventName, Measurements, Metadata}
    end,

    telemetry:attach(
        test_error_request,
        [katipo, request, error],
        HandlerFun,
        undefined
    ),

    %% Mock error response and metrics
    Method = post,
    Url = <<"http://invalid.domain/test">>,
    Response = {error, #{code => couldnt_resolve_host}},
    Metrics = [{total_time, 5000}],  % Timeout

    %% Record the request
    katipo_telemetry:record_request(Method, Url, Response, Metrics),

    %% Verify event was emitted
    receive
        {telemetry_event, [katipo, request, error], EventMeasurements, EventMetadata} ->
            %% Check measurements
            1 = maps:get(count, EventMeasurements),

            %% Check metadata
            post = maps:get(method, EventMetadata),
            <<"http://invalid.domain/test">> = maps:get(url, EventMetadata),
            couldnt_resolve_host = maps:get(error, EventMetadata),
            <<"http">> = maps:get(scheme, EventMetadata),
            <<"invalid.domain">> = maps:get(host, EventMetadata),

            ok
    after 1000 ->
        error(no_error_telemetry_event)
    end,

    telemetry:detach(test_error_request).

build_measurements_with_body(_) ->
    %% Test building measurements with response body
    Response = {ok, #{body => <<"hello world">>}},
    Metrics = [
        {total_time, 200},
        {namelookup_time, 5},
        {connect_time, 15},
        {appconnect_time, 25},
        {pretransfer_time, 35},
        {redirect_time, 0},
        {starttransfer_time, 45}
    ],

    Measurements = katipo_telemetry:build_measurements(Response, Metrics),

    %% Verify measurements
    200 = maps:get(duration, Measurements),
    11 = maps:get(response_body_size, Measurements),  % "hello world" = 11 bytes
    5 = maps:get(namelookup_time, Measurements),
    15 = maps:get(connect_time, Measurements),
    25 = maps:get(appconnect_time, Measurements),
    35 = maps:get(pretransfer_time, Measurements),
    0 = maps:get(redirect_time, Measurements),
    45 = maps:get(starttransfer_time, Measurements).

build_measurements_without_body(_) ->
    %% Test building measurements without response body
    Response = {error, #{code => timeout}},
    Metrics = [{total_time, 30000}],

    Measurements = katipo_telemetry:build_measurements(Response, Metrics),

    %% Verify measurements
    30000 = maps:get(duration, Measurements),
    0 = maps:get(namelookup_time, Measurements),  % Default value
    0 = maps:get(connect_time, Measurements),
    0 = maps:get(appconnect_time, Measurements),
    0 = maps:get(pretransfer_time, Measurements),
    0 = maps:get(redirect_time, Measurements),
    0 = maps:get(starttransfer_time, Measurements).

build_metadata_success(_) ->
    %% Test building metadata for successful request
    Method = put,
    Url = <<"https://api.example.com:8080/users/123">>,
    Response = {ok, #{status => 201}},

    Metadata = katipo_telemetry:build_metadata(Method, Url, Response),

    %% Verify metadata
    put = maps:get(method, Metadata),
    <<"https://api.example.com:8080/users/123">> = maps:get(url, Metadata),
    201 = maps:get(status, Metadata),
    <<"https">> = maps:get(scheme, Metadata),
    <<"api.example.com">> = maps:get(host, Metadata),
    8080 = maps:get(port, Metadata).

build_metadata_error(_) ->
    %% Test building metadata for error request
    Method = delete,
    Url = <<"http://localhost:3000/items/456">>,
    Response = {error, #{code => connection_refused}},

    Metadata = katipo_telemetry:build_metadata(Method, Url, Response),

    %% Verify metadata
    delete = maps:get(method, Metadata),
    <<"http://localhost:3000/items/456">> = maps:get(url, Metadata),
    connection_refused = maps:get(error, Metadata),
    <<"http">> = maps:get(scheme, Metadata),
    <<"localhost">> = maps:get(host, Metadata),
    3000 = maps:get(port, Metadata).

parse_url_metadata(_) ->
    %% Test URL parsing for metadata
    Method = get,

    %% Test URL with port
    Url1 = <<"https://example.com:9000/path">>,
    Metadata1 = katipo_telemetry:parse_url_metadata(Method, Url1),
    get = maps:get(method, Metadata1),
    <<"https://example.com:9000/path">> = maps:get(url, Metadata1),
    <<"https">> = maps:get(scheme, Metadata1),
    <<"example.com">> = maps:get(host, Metadata1),
    9000 = maps:get(port, Metadata1),

    %% Test URL without port
    Url2 = <<"http://test.com/api">>,
    Metadata2 = katipo_telemetry:parse_url_metadata(Method, Url2),
    get = maps:get(method, Metadata2),
    <<"http://test.com/api">> = maps:get(url, Metadata2),
    <<"http">> = maps:get(scheme, Metadata2),
    <<"test.com">> = maps:get(host, Metadata2),
    false = maps:is_key(port, Metadata2),

    %% Test invalid URL
    Url3 = <<"not-a-url">>,
    Metadata3 = katipo_telemetry:parse_url_metadata(Method, Url3),
    get = maps:get(method, Metadata3),
    <<"not-a-url">> = maps:get(url, Metadata3),
    false = maps:is_key(scheme, Metadata3),
    false = maps:is_key(host, Metadata3).

get_metric_value_test(_) ->
    %% Test getting metric values
    Metrics = [
        {total_time, 123},
        {connect_time, 45},
        {namelookup_time, 0}
    ],

    %% Test existing values
    123 = katipo_telemetry:get_metric_value(total_time, Metrics, 999),
    45 = katipo_telemetry:get_metric_value(connect_time, Metrics, 999),
    0 = katipo_telemetry:get_metric_value(namelookup_time, Metrics, 999),

    %% Test non-existing value returns default
    999 = katipo_telemetry:get_metric_value(unknown_metric, Metrics, 999),
    42 = katipo_telemetry:get_metric_value(missing, Metrics, 42).