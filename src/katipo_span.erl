-module(katipo_span).
-moduledoc false.

%% OpenTelemetry span handling for katipo requests, factored out of katipo.
%%
%% The synchronous path wraps the request in a scoped span (with_client_span/3).
%% The async path starts the span in the calling process (start_async/2) and
%% finishes it in the worker when the response, a timeout, or a worker failure
%% arrives (finish_async/4, end_async/1) -- it cannot use the scoped ?with_span
%% macro because the span crosses a process boundary. Both paths share the
%% request-attr, response-attr, and metrics-emitting leaves below.

-export([with_client_span/3]).
-export([start_async/2]).
-export([finish_async/4]).
-export([end_async/1]).
-export([record_outcome/6]).
-export([parse_url_for_span/1]). %% exported for testing

-include_lib("opentelemetry_api/include/otel_tracer.hrl").

%% Opaque OTel span context; kept as term() so this module doesn't depend on
%% OTel's internal record type.
-type span_ctx() :: term().
-type obs() :: #{method := binary(),
                 ts := erlang:timestamp(),
                 span := span_ctx()}.
-export_type([obs/0]).

%% @doc Run Fun inside a scoped "HTTP <METHOD>" client span with request
%% attributes set. Used by the synchronous request path.
-spec with_client_span(binary(), katipo:url(), fun((span_ctx()) -> Result)) -> Result.
with_client_span(Method, Url, Fun) ->
    SpanName = <<"HTTP ", Method/binary>>,
    ?with_span(SpanName, #{kind => client}, fun(SpanCtx) ->
        set_request_span_attrs(SpanCtx, Method, Url),
        Fun(SpanCtx)
    end).

%% @doc Start a client span parented to the caller's context (so an async
%% request appears under the caller's trace) and capture what the worker needs
%% to finish it: the method, the start time, and the span.
-spec start_async(binary(), katipo:url()) -> obs().
start_async(Method, Url) ->
    SpanName = <<"HTTP ", Method/binary>>,
    SpanCtx = otel_tracer:start_span(otel_ctx:get_current(),
                                     opentelemetry:get_application_tracer(?MODULE),
                                     SpanName, #{kind => client}),
    set_request_span_attrs(SpanCtx, Method, Url),
    #{method => Method, ts => os:timestamp(), span => SpanCtx}.

%% @doc Emit metrics and finish the span for a completed async request.
-spec finish_async(obs(), ok | error, map(), katipo:metrics()) -> ok.
finish_async(Obs = #{method := Method, ts := Ts, span := SpanCtx},
             Result, Response, Metrics) ->
    record_outcome(SpanCtx, Method, Ts, Result, Response, Metrics),
    end_async(Obs).

%% @doc End the span without recording an outcome (used when a request is
%% cancelled). Every async terminal path ends the span exactly once.
-spec end_async(obs()) -> ok.
end_async(#{span := SpanCtx}) ->
    _ = otel_span:end_span(SpanCtx),
    ok.

%% @doc Set response span attributes and emit request metrics -- the shared tail
%% of the sync request and an async request completing in the worker.
-spec record_outcome(span_ctx(), binary(), erlang:timestamp(),
                     ok | error, map(), katipo:metrics()) -> ok.
record_outcome(SpanCtx, Method, Ts, Result, Response, Metrics) ->
    TotalUs = timer:now_diff(os:timestamp(), Ts),
    set_response_span_attrs(SpanCtx, Result, Response),
    _ = katipo_metrics:notify({Result, Response}, Metrics, TotalUs, Method),
    ok.

%% Set the request span attributes (method + sanitized URL), only when the span
%% is recording (URL parsing is skipped otherwise).
set_request_span_attrs(SpanCtx, Method, Url) ->
    case otel_span:is_recording(SpanCtx) of
        true ->
            otel_span:set_attribute(SpanCtx, 'http.request.method', Method),
            set_url_span_attrs(SpanCtx, Url);
        false ->
            ok
    end.

set_response_span_attrs(SpanCtx, ok, #{status := Status}) ->
    otel_span:set_attribute(SpanCtx, 'http.response.status_code', Status),
    case Status >= 400 of
        true -> otel_span:set_status(SpanCtx, error, <<>>);
        false -> ok
    end;
set_response_span_attrs(SpanCtx, error, #{code := Code, message := _Msg}) ->
    %% Don't include error message in span - it may contain sensitive URL info
    otel_span:set_status(SpanCtx, error, <<>>),
    otel_span:set_attribute(SpanCtx, 'error.type', Code);
set_response_span_attrs(_SpanCtx, _, _) ->
    ok.

set_url_span_attrs(SpanCtx, Url) ->
    case parse_url_for_span(Url) of
        {<<>>, _} ->
            ok;
        {SanitizedUrl, Host} ->
            otel_span:set_attribute(SpanCtx, 'url.full', SanitizedUrl),
            otel_span:set_attribute(SpanCtx, 'server.address', Host)
    end.

%% @doc Parse a URL into {SanitizedUrl, Host}, stripping query/fragment/userinfo
%% so no secrets leak into span attributes. Returns {<<>>, <<>>} if unparseable.
%% uri_string:parse/1 only accepts ASCII hosts (RFC 3986), so Host is already a
%% binary when the URL is a binary -- no unicode conversion is needed. It can
%% also *throw* on some malformed byte sequences, not just return an error, so
%% the whole call is guarded to honour the "unparseable -> {<<>>, <<>>}"
%% contract (relevant on the async path, where this runs in the worker process).
-spec parse_url_for_span(binary()) -> {binary(), binary()}.
parse_url_for_span(Url) when is_binary(Url) ->
    try uri_string:parse(Url) of
        #{host := Host} = Parsed when is_binary(Host) ->
            {sanitize_parsed_url(Parsed), Host};
        _ ->
            {<<>>, <<>>}
    catch
        _:_ ->
            {<<>>, <<>>}
    end.

sanitize_parsed_url(Parsed) ->
    Sanitized = maps:without([query, fragment, userinfo], Parsed),
    case uri_string:recompose(Sanitized) of
        {error, _, _} -> <<>>;
        Recomposed -> iolist_to_binary(Recomposed)
    end.
