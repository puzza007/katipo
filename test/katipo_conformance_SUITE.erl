-module(katipo_conformance_SUITE).

%% Fixed cases for responses a server should not send, taken from Dart's
%% http_client_conformance_tests (pkgs/http_client_conformance_tests in
%% dart-lang/http), against the scripted katipo_prop_server. They pin what
%% katipo does with each. RFC 9110 lets a recipient of NUL, CR or LF in a
%% field value either reject the message or replace each with SP: newer
%% libcurl rejects it, with CURLE_WEIRD_SERVER_REPLY (which katipo reports
%% by its old name, ftp_weird_server_reply), and with an older libcurl that
%% lets one through, katipo replaces it, so both are accepted.

-include_lib("common_test/include/ct.hrl").

-compile(export_all).
-compile(nowarn_export_all).

-define(POOL, katipo_conformance_pool).

all() ->
    [nul_in_header_value,
     bare_cr_in_header_value,
     bare_lf_in_header_value,
     quotes_in_header_value,
     content_length_padded,
     content_length_not_a_number,
     content_length_negative,
     content_length_longer_than_body,
     head_with_content_length,
     closed_without_response].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    {ok, _} = katipo_pool:start(?POOL, 1, []),
    {ok, Server, Port} = katipo_prop_server:start(),
    [{server, Server}, {port, Port} | Config].

end_per_suite(Config) ->
    ok = katipo_pool:stop(?POOL),
    ok = katipo_prop_server:stop(?config(server, Config)),
    application:stop(katipo),
    Config.

nul_in_header_value(Config) ->
    rejected_or_blanked(
      get(Config, raw, [<<"invalid: 1">>, 0, <<"2\r\ncontent-length: 0\r\n\r\n">>])).

bare_cr_in_header_value(Config) ->
    rejected_or_blanked(get(Config, raw, <<"invalid: 1\r2\r\ncontent-length: 0\r\n\r\n">>)).

bare_lf_in_header_value(Config) ->
    rejected_or_blanked(get(Config, raw, <<"invalid: 1\n2\r\ncontent-length: 0\r\n\r\n">>)).

%% The two outcomes RFC 9110 5.5 allows for "invalid: 1<X>2" with X one of
%% NUL, CR or LF.
rejected_or_blanked({error, #{code := ftp_weird_server_reply}}) ->
    ok;
rejected_or_blanked({ok, #{headers := [{<<"invalid">>, <<"1 2">>} | _]}}) ->
    ok.

%% Quotes and backslashes are value bytes like any other.
quotes_in_header_value(Config) ->
    Value = <<"\"\\\"1, 2, 3\\\"\"">>,
    {ok, #{headers := [{<<"FOO">>, Value} | _]}} =
        get(Config, raw, [<<"FOO: ">>, Value, <<"\r\ncontent-length: 0\r\n\r\n">>]).

content_length_padded(Config) ->
    {ok, #{status := 200, body := <<>>}} =
        get(Config, raw, <<"content-length: \t 0 \t \r\n\r\n">>).

content_length_not_a_number(Config) ->
    {error, #{code := ftp_weird_server_reply}} =
        get(Config, raw, <<"content-length: cat\r\n\r\n">>).

content_length_negative(Config) ->
    {error, #{code := ftp_weird_server_reply}} =
        get(Config, raw, <<"content-length: -5\r\n\r\n">>).

content_length_longer_than_body(Config) ->
    {error, #{code := partial_file}} =
        get(Config, raw_close, <<"content-length: 100\r\n\r\nok">>).

%% A HEAD response declares the length of the body a GET would get, and
%% has none.
head_with_content_length(Config) ->
    {ok, #{status := 200, body := <<>>,
           headers := [{<<"content-length">>, <<"100">>}]}} =
        req(Config, head, raw, <<"content-length: 100\r\n\r\n">>).

closed_without_response(Config) ->
    {error, #{code := got_nothing}} =
        req(Config, get, raw_close, none).

get(Config, Kind, Rest) ->
    req(Config, get, Kind, Rest).

%% A response of a 200 status line followed by Rest (headers, blank line
%% and body), or with Rest = none, the connection closed without one.
req(Config, Method, Kind, Rest) ->
    Bytes = case Rest of
                none -> <<>>;
                _ -> iolist_to_binary([<<"HTTP/1.1 200 OK\r\n">>, Rest])
            end,
    Key = integer_to_binary(erlang:unique_integer([positive])),
    Url = katipo_prop_server:script(?config(port, Config), Key, {Kind, Bytes}),
    katipo:req(?POOL, #{url => Url, method => Method, timeout_ms => 5000}).
