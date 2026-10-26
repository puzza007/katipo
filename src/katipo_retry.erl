-module(katipo_retry).

-moduledoc false.

%% The retry policy of a request: validating the `retry' option into a
%% policy (policy/1), and deciding, once an attempt has ended, whether to
%% send the request again and after how long (delay/5). Pure but for the
%% jitter: the caller passes the clock in, and the worker owns the timers
%% and the attempts.

-export([policy/1]).
-export([delay/5]).
-export([retry_after/2]).

-include("katipo_internal.hrl").

-type policy() :: #{max_retries := pos_integer(),
                    base_delay_ms := non_neg_integer(),
                    max_delay_ms := non_neg_integer(),
                    methods := [method_int()],
                    statuses := [100..599],
                    errors := [atom()]}.
-export_type([policy/0]).

%% RFC 9110 9.2.2: the methods whose intended effect is the same however
%% many times the request is sent.
-define(IDEMPOTENT, [get, head, options, put, delete]).

%% Failures that leave the request unanswered and are worth another try:
%% the connection could not be made or broke, or the server sent nothing
%% or not all of it, or the attempt ran out of time.
-define(TRANSIENT, [couldnt_connect, operation_timedout, got_nothing,
                    send_error, recv_error, partial_file, http2,
                    http2_stream, http3, quic_connect_error]).

-define(DEFAULTS, #{max_retries => 3,
                    base_delay_ms => 100,
                    max_delay_ms => 5000,
                    methods => ?IDEMPOTENT,
                    statuses => [429, 503],
                    errors => ?TRANSIENT}).

%% The policy for a `retry' option, or undefined for no retries: false, or
%% max_retries 0.
-spec policy(term()) -> {ok, policy() | undefined} | error.
policy(false) ->
    {ok, undefined};
policy(true) ->
    policy(#{});
policy(Opts) when is_map(Opts) ->
    Merged = maps:merge(?DEFAULTS, Opts),
    case map_size(Merged) =:= map_size(?DEFAULTS) andalso
        maps:fold(fun(K, V, Ok) -> Ok andalso valid(K, V) end, true, Merged) of
        true when map_get(max_retries, Merged) =:= 0 ->
            {ok, undefined};
        true ->
            {ok, Merged#{methods := [katipo_req:method_to_int(M)
                                     || M <- map_get(methods, Merged)]}};
        false ->
            error
    end;
policy(_) ->
    error.

valid(max_retries, N) -> ?IS_INT_OPT(N, 0);
valid(base_delay_ms, N) -> ?IS_INT_OPT(N, 0);
valid(max_delay_ms, N) -> ?IS_INT_OPT(N, 0);
valid(methods, Ms) -> all(fun(M) -> lists:member(M, ?METHODS) end, Ms);
valid(statuses, Ss) -> all(fun(S) -> is_integer(S) andalso S >= 100 andalso S =< 599 end, Ss);
valid(errors, Es) -> all(fun erlang:is_atom/1, Es).

%% An improper list makes lists:all/2 raise; it is as invalid as any other.
all(Pred, L) ->
    try is_list(L) andalso lists:all(Pred, L)
    catch error:function_clause -> false
    end.

%% Whether to send the request again after an attempt ended with Result,
%% and after how many milliseconds, given Retries already sent, at Now
%% (Unix seconds). A
%% retryable status waits as long as its Retry-After says, if it says, and
%% the response stands if that is longer than max_delay_ms: retrying
%% sooner than the server asked would be refused again. Anything else
%% waits a backoff with full jitter: any time up to base_delay_ms doubled
%% for each retry already sent, capped at max_delay_ms.
-spec delay(policy(), non_neg_integer(), ok | error | done, map(), integer()) ->
          {ok, non_neg_integer()} | none.
delay(#{max_retries := Max}, Retries, _, _, _) when Retries >= Max ->
    none;
delay(Policy = #{statuses := Statuses, max_delay_ms := MaxDelay}, Retries, ok,
      #{status := Status, headers := Headers}, Now) ->
    case lists:member(Status, Statuses) of
        true ->
            case retry_after(Headers, Now) of
                {ok, Ms} when Ms =< MaxDelay -> {ok, Ms};
                {ok, _TooLong} -> none;
                error -> {ok, backoff(Policy, Retries)}
            end;
        false ->
            none
    end;
delay(Policy = #{errors := Errors}, Retries, error, #{code := Code}, _Now) ->
    case lists:member(Code, Errors) of
        true -> {ok, backoff(Policy, Retries)};
        false -> none
    end;
delay(_Policy, _Retries, _Result, _Response, _Now) ->
    none.

backoff(#{base_delay_ms := Base, max_delay_ms := MaxDelay}, Retries) ->
    Cap = min(MaxDelay, Base bsl min(Retries, 32)),
    rand:uniform(Cap + 1) - 1.

%% The wait a Retry-After header asks for, in milliseconds, at Now (Unix
%% seconds): RFC 9110 10.2.3 gives it as delay-seconds or an HTTP-date,
%% and a date already past asks for none. A header that is missing or not
%% understood is `error'.
-spec retry_after(katipo:resp_headers(), integer()) -> {ok, non_neg_integer()} | error.
retry_after(Headers, Now) ->
    case [V || {K, V} <- Headers, byte_size(K) =:= 11,
               katipo_req:ascii_lowercase(K) =:= <<"retry-after">>] of
        [Value | _] -> parse_retry_after(Value, Now);
        [] -> error
    end.

parse_retry_after(Value, Now) ->
    case is_digits(Value) of
        true ->
            {ok, binary_to_integer(Value) * 1000};
        false ->
            case http_date(Value, Now) of
                {ok, Secs} -> {ok, max(0, Secs - Now) * 1000};
                error -> error
            end
    end.

is_digits(<<>>) -> false;
is_digits(Bin) -> lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(Bin)).

%% An HTTP-date (RFC 9110 5.6.7) as Unix seconds, in any of the three forms
%% a recipient must accept: IMF-fixdate, "Sun, 06 Nov 1994 08:49:37 GMT";
%% the obsolete RFC 850 form, "Sunday, 06-Nov-94 08:49:37 GMT"; and
%% asctime, "Sun Nov  6 08:49:37 1994".
http_date(<<_Day:3/binary, ", ", D:2/binary, " ", Mon:3/binary, " ", Y:4/binary, " ",
            Time:8/binary, " GMT">>, _Now) ->
    datetime(D, Mon, Y, Time);
http_date(<<_Day:3/binary, " ", Mon:3/binary, " ", D:2/binary, " ", Time:8/binary, " ",
            Y:4/binary>>, _Now) ->
    datetime(string:trim(D, leading), Mon, Y, Time);
http_date(Value, Now) ->
    case binary:split(Value, <<", ">>) of
        [<<_:6/binary, _/binary>>,
         <<D:2/binary, "-", Mon:3/binary, "-", YY:2/binary, " ", Time:8/binary, " GMT">>] ->
            case is_digits(YY) of
                true -> datetime(D, Mon, full_year(binary_to_integer(YY), Now), Time);
                false -> error
            end;
        _ ->
            error
    end.

%% RFC 9110 5.6.7: a two-digit year more than 50 years in the future is the
%% most recent past year with the same last two digits.
full_year(YY, Now) ->
    {{This, _, _}, _} = calendar:gregorian_seconds_to_datetime(Now + ?UNIX_EPOCH_GREGORIAN),
    Y = This - This rem 100 + YY,
    integer_to_binary(case Y > This + 50 of true -> Y - 100; false -> Y end).

datetime(D, Mon, Y, <<H:2/binary, ":", Mi:2/binary, ":", S:2/binary>>) ->
    case lists:all(fun is_digits/1, [D, Y, H, Mi, S]) andalso month(Mon) of
        false ->
            error;
        0 ->
            error;
        M ->
            Date = {binary_to_integer(Y), M, binary_to_integer(D)},
            Time = {Hour, Min, Sec} = {binary_to_integer(H), binary_to_integer(Mi),
                                       binary_to_integer(S)},
            case calendar:valid_date(Date) andalso Hour < 24 andalso Min < 60
                andalso Sec < 61 of
                true ->
                    {ok, calendar:datetime_to_gregorian_seconds({Date, Time})
                         - ?UNIX_EPOCH_GREGORIAN};
                false ->
                    error
            end
    end;
datetime(_, _, _, _) ->
    error.

month(Mon) ->
    Months = [<<"Jan">>, <<"Feb">>, <<"Mar">>, <<"Apr">>, <<"May">>, <<"Jun">>,
              <<"Jul">>, <<"Aug">>, <<"Sep">>, <<"Oct">>, <<"Nov">>, <<"Dec">>],
    case lists:keyfind(Mon, 1, lists:zip(Months, lists:seq(1, 12))) of
        {_, M} -> M;
        false -> 0
    end.
