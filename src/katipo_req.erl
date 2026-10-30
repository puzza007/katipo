-module(katipo_req).

-moduledoc false.

%% Turns a user options map into a validated #req{} record for the worker to
%% send to the C port. Owns all request-option validation (opt/3), body
%% encoding, header formatting, and the method<->code conversions. Factored out
%% of katipo to keep the public facade small.

-export([build_req/2]).
-export([check_opts/2]).
-export([get_timeout/1]).
-export([method_int_to_binary/1]).
-export([error_map/2]).
-export([method_to_int/1]).
-export([ascii_lowercase/1]).

-include("katipo_internal.hrl").

%% method_int() and http_auth_int() come from katipo_internal.hrl (they type the
%% #req wire fields); req() is the validated request this module produces.
-type req() :: #req{}.
-export_type([method_int/0, req/0]).

-dialyzer({nowarn_function, opt/3}).

%% Build a validated, timeout-stamped #req{} from an opts map. Shared by the
%% sync req/2 and async_req/2 entry points; Mode says whether the async-only
%% options are allowed.
-spec build_req(katipo:request(), sync | async) ->
          {ok, req()} | {error, katipo:error()}.
build_req(Opts, Mode) ->
    case validate(Opts, Mode, url) of
        {ok, Req0} ->
            Req = content_type(Req0, Opts),
            {ok, Req#req{timeout = ?MODULE:get_timeout(Req)}};
        {error, _} = Error ->
            Error
    end.

%% The checks build_req/2 makes for the same Mode, except that the
%% options may leave out url.
-spec check_opts(katipo:partial_request(), sync | async) ->
          ok | {error, katipo:error()}.
check_opts(Opts, Mode) when is_map(Opts) ->
    case validate(Opts, Mode, no_url) of
        {ok, _} -> ok;
        {error, _} = Error -> Error
    end.

%% Every invalid option, and every rule between options that is broken, is
%% named in the one error, so fixing a request takes one round. A rule is
%% checked only on options that were valid: one that was not is left at its
%% default in Req, and is named already.
validate(Opts, Mode, Url) ->
    {Req0, Errors} = process_opts(Opts, Mode),
    Req = retry_method(Req0),
    Invalid = [K || {K, _} <- Errors],
    case Errors ++ cross_field_errors(Req, Url, Invalid) ++ stream_body_error(Req, Mode) of
        [] -> {ok, Req};
        All -> {error, error_map(bad_opts, All)}
    end.

cross_field_errors(Req, Url, Invalid) ->
    url_error(Req, Url, Invalid) ++ head_body_error(Req) ++
        stream_opts_error(Req, Invalid) ++ low_speed_error(Req, Invalid) ++ retry_error(Req).

url_error(#req{url = undefined}, url, Invalid) ->
    [{url, undefined} || not lists:member(url, Invalid)];
url_error(#req{}, _, _) -> [].

%% A HEAD request cannot carry a body (curl's NOBODY), so one given is a
%% mistake to report rather than drop. The message names the rule, not the
%% body, which may be large.
head_body_error(#req{method = ?HEAD, body = Body}) ->
    case sends_body(Body) of
        true -> [{body, not_allowed_with_head}];
        false -> []
    end;
head_body_error(#req{}) ->
    [].

%% A streamed body is sent in answer to messages the caller receives, which
%% only the async API delivers.
stream_body_error(#req{body = {stream, _}}, sync) -> [{body, stream_requires_async}];
stream_body_error(#req{}, _) -> [].

%% A stream_window only means something on a streaming request.
stream_opts_error(#req{stream = ?STREAM_FALSE, stream_window = W}, Invalid)
  when W =/= ?STREAM_WINDOW_UNLIMITED ->
    [{stream_window, W} || not lists:member(stream, Invalid)];
stream_opts_error(#req{}, _) ->
    [].

%% curl checks the transfer speed only with both a limit and a time.
low_speed_error(#req{low_speed_limit = L, low_speed_time = 0}, Invalid) when L > 0 ->
    [{low_speed_limit, requires_low_speed_time} || not lists:member(low_speed_time, Invalid)];
low_speed_error(#req{low_speed_limit = 0, low_speed_time = T}, Invalid) when T > 0 ->
    [{low_speed_time, requires_low_speed_limit} || not lists:member(low_speed_limit, Invalid)];
low_speed_error(#req{}, _) ->
    [].

%% A policy that does not retry the request's method is no policy for it,
%% so the request is neither kept nor checked for it.
retry_method(Req = #req{method = Method, retry = #{methods := Methods}}) ->
    case lists:member(Method, Methods) of
        true -> Req;
        false -> Req#req{retry = undefined}
    end;
retry_method(Req = #req{}) ->
    Req.

%% A retry sends the request again from the start, which a streamed body
%% cannot be, and a streamed response has already delivered the failed
%% attempt's headers and chunks by the time it ends.
retry_error(#req{retry = undefined}) ->
    [];
retry_error(#req{body = {stream, _}}) ->
    [{retry, not_allowed_with_stream}];
retry_error(#req{stream = ?STREAM_TRUE}) ->
    [{retry, not_allowed_with_stream}];
retry_error(#req{}) ->
    [].

%% The worker's own bound on an attempt: timeout_ms, which in curl already
%% covers connecting. curl enforces it too, but up to at least 8.11 not on
%% a transfer still waiting for a connection (max_host_connections), as
%% katipo drives it with curl_multi_socket_action.
-spec get_timeout(req()) -> pos_integer().
get_timeout(#req{timeout_ms = Ms}) ->
    Ms.

-spec method_int_to_binary(method_int()) -> binary().
method_int_to_binary(?GET) -> <<"GET">>;
method_int_to_binary(?POST) -> <<"POST">>;
method_int_to_binary(?PUT) -> <<"PUT">>;
method_int_to_binary(?HEAD) -> <<"HEAD">>;
method_int_to_binary(?OPTIONS) -> <<"OPTIONS">>;
method_int_to_binary(?PATCH) -> <<"PATCH">>;
method_int_to_binary(?DELETE) -> <<"DELETE">>.

%% The request so far and the options that were invalid. The sync API acts
%% on none of
%% the async-only options, so it takes only the values that change nothing
%% there (the reply goes to the caller, the body is not streamed) and
%% rejects the rest, rather than ignoring a mistake.
-spec process_opts(katipo:partial_request(), sync | async) ->
          {req(), [{atom(), term()}]}.
process_opts(Opts, async) ->
    maps:fold(fun opt/3, {#req{}, []}, Opts);
process_opts(Opts, sync) ->
    {SyncOpts, Rejected} = lists:foldl(fun take_sync_noop/2, {Opts, []},
                                       ?KATIPO_ASYNC_OPTS),
    maps:fold(fun opt/3, {#req{}, Rejected}, SyncOpts).

take_sync_noop(Key, {Opts, Rejected}) ->
    case maps:take(Key, Opts) of
        error -> {Opts, Rejected};
        {Value, Rest} ->
            case sync_noop(Key, Value) of
                true -> {Rest, Rejected};
                false -> {Rest, [{Key, Value} | Rejected]}
            end
    end.

sync_noop(reply_to, Pid) -> Pid =:= self();
sync_noop(stream, false) -> true;
sync_noop(stream_window, infinity) -> true;
sync_noop(_, _) -> false.

%% curl sends any body it is given as a form POST would, adding
%% Content-Type: application/x-www-form-urlencoded unless the caller set
%% one. That is right for POST, where it has always been the default, and
%% for a form body (a key/value list) with any method; for any other body
%% sent with another method it is a guess, so the header is disabled (an
%% empty "Name:" removes one of curl's own) and the caller's own, if any,
%% is left alone.
content_type(Req = #req{method = Method, headers = Headers, body = Body}, Opts)
  when Method =/= ?POST, Method =/= ?HEAD ->
    Sends = Method =:= ?PUT orelse Method =:= ?PATCH orelse sends_body(Body),
    case Sends andalso not has_content_type(maps:get(headers, Opts, [])) of
        true -> Req#req{headers = Headers ++ [content_type_line(maps:get(body, Opts, <<>>))]};
        false -> Req
    end;
content_type(Req, _Opts) ->
    Req.

content_type_line([{_, _} | _]) -> <<"Content-Type: application/x-www-form-urlencoded">>;
content_type_line(_) -> <<"Content-Type:">>.

%% Header names are bytes, not necessarily UTF-8, so they are compared with
%% ASCII case folding: string:lowercase/1 raises badarg on a name that is
%% not valid UTF-8. The headers have been validated by then (opt/3).
has_content_type(Headers) ->
    lists:any(fun({K, _}) ->
                      iolist_size(K) =:= 12 andalso
                          ascii_lowercase(iolist_to_binary(K)) =:= <<"content-type">>
              end, Headers).

-spec ascii_lowercase(binary()) -> binary().
ascii_lowercase(Bin) ->
    << <<(case C of _ when C >= $A, C =< $Z -> C + 32; _ -> C end)>> || <<C>> <= Bin >>.

%% Whether a body has any bytes. The body has been validated (opt/3). A
%% file's size is the port's to find out, when it opens it, so a file
%% counts as a body even if it turns out empty.
sends_body({file, _}) ->
    true;
sends_body({stream, _}) ->
    true;
sends_body(Body) ->
    iolist_size(Body) > 0.

%% A path option as a binary: given as one, or converted from a string as
%% UTF-8. Text that is not valid makes unicode:characters_to_binary/1
%% return {error, _, _} or {incomplete, _, _}, and a list that is not
%% chardata makes it raise badarg; either is an invalid option. So is a
%% NUL, which OTP's own file functions reject too: the C port hands the
%% path to curl as a C string, which would end there.
-spec path_to_binary(term()) -> {ok, binary()} | error.
path_to_binary(Path) when is_binary(Path) ->
    without_nul(Path);
path_to_binary(Path) when is_list(Path) ->
    try unicode:characters_to_binary(Path) of
        Bin when is_binary(Bin) -> without_nul(Bin);
        _Invalid -> error
    catch error:badarg -> error
    end;
path_to_binary(_) ->
    error.

without_nul(Bin) ->
    case binary:match(Bin, <<0>>) of
        nomatch -> {ok, Bin};
        _ -> error
    end.

%% Each header must be a {Name, Value} pair of binaries or iolists; a bare
%% integer would otherwise go out as a single byte. A bad one is named by
%% its position (from 1), not echoed: headers carry credentials, and the
%% error is usually logged.
-spec headers_to_binary(term()) -> {ok, [binary()]} | {error, pos_integer()}.
headers_to_binary(Headers) ->
    headers_to_binary(Headers, 1, []).

headers_to_binary([], _, Acc) ->
    {ok, lists:reverse(Acc)};
headers_to_binary([H | T], N, Acc) ->
    try header_line(H) of
        Line -> headers_to_binary(T, N + 1, [Line | Acc])
    catch error:_ -> {error, N}
    end;
headers_to_binary(_ImproperTail, N, _) ->
    {error, N}.

header_line({K, V}) when (is_binary(K) orelse is_list(K)) andalso
                         (is_binary(V) orelse is_list(V)) ->
    iolist_to_binary([K, <<": ">>, V]).

-spec method_to_int(katipo:method()) -> method_int().
method_to_int(get)     -> ?GET;
method_to_int(post)    -> ?POST;
method_to_int(put)     -> ?PUT;
method_to_int(head)    -> ?HEAD;
method_to_int(options) -> ?OPTIONS;
method_to_int(patch)   -> ?PATCH;
method_to_int(delete)  -> ?DELETE.

%% A form (a key/value list) is encoded, and a file's path converted as a
%% path option is; anything else must be iodata, so a bad body is named
%% here rather than failing in the C port. A list body is not echoed in
%% the error, as it may be large.
-spec encode_body(term()) ->
          {ok, iodata() | {file, binary()} | {stream, integer()}} |
          {error, {atom(), term()}}.
encode_body({stream, Opts}) when is_map(Opts) ->
    case maps:to_list(Opts) of
        [] -> {ok, {stream, -1}};
        [{length, N}] when is_integer(N), N >= 0, N =< ?MAX_STREAM_LENGTH -> {ok, {stream, N}};
        _ -> {error, {invalid_body, {stream, Opts}}}
    end;
encode_body({file, Path}) ->
    case path_to_binary(Path) of
        %% The port's working directory is the VM's when it started.
        {ok, Bin} -> {ok, {file, filename:absname(Bin)}};
        error -> {error, {invalid_body, {file, Path}}}
    end;
encode_body([{_, _} | _] = KVs) ->
    try uri_string:compose_query(KVs) of
        {error, Reason, Message} ->
            {error, {Reason, Message}};
        Body ->
            {ok, Body}
    catch error:_ ->
            {error, {invalid_body, not_a_form}}
    end;
encode_body(Body) when is_binary(Body) ->
    {ok, Body};
encode_body(Body) when is_list(Body) ->
    try iolist_size(Body) of
        _ -> {ok, Body}
    catch error:badarg ->
            {error, {invalid_body, not_iodata}}
    end;
encode_body(Body) ->
    {error, {invalid_body, Body}}.

-spec error_map(katipo:error_code(), term()) -> katipo:error().
error_map(Code, Message) when is_atom(Code) andalso is_binary(Message) ->
    #{code => Code, message => Message};
error_map(Code, Message) when is_atom(Code) ->
    Chars = io_lib:format("~p", [Message]),
    BinaryMessage = unicode:characters_to_binary(Chars),
    error_map(Code, BinaryMessage).

opt(url, Url, {Req, Errors}) when is_binary(Url) ->
    {Req#req{url = Url}, Errors};
opt(method, Method, {Req, Errors}) when is_atom(Method) ->
    case lists:member(Method, ?METHODS) of
        true ->
            {Req#req{method = method_to_int(Method)}, Errors};
        false ->
            {Req, [{method, Method} | Errors]}
    end;
opt(headers, Headers, {Req, Errors}) when is_list(Headers) ->
    case headers_to_binary(Headers) of
        {ok, Bins} -> {Req#req{headers = Bins}, Errors};
        {error, N} -> {Req, [{headers, {invalid_header, N}} | Errors]}
    end;
opt(cookiejar, CookieJar, {Req, Errors}) when is_list(CookieJar) ->
    case lists:all(fun erlang:is_binary/1, CookieJar) of
        true ->
            {Req#req{cookiejar = CookieJar}, Errors};
        false ->
            {Req, [{cookiejar, CookieJar} | Errors]}
    end;
opt(body, Body, {Req, Errors}) ->
    case encode_body(Body) of
        {error, Error} ->
            {Req, [{body, Error} | Errors]};
        {ok, Encoded} ->
            {Req#req{body = Encoded}, Errors}
    end;
opt(connecttimeout_ms, Ms, {Req, Errors}) when ?IS_INT_OPT(Ms, 1) ->
    {Req#req{connecttimeout_ms = Ms}, Errors};
opt(followlocation, true, {Req, Errors}) ->
    {Req#req{followlocation = ?FOLLOWLOCATION_TRUE}, Errors};
opt(followlocation, false, {Req, Errors}) ->
    {Req#req{followlocation = ?FOLLOWLOCATION_FALSE}, Errors};
opt(ssl_verifyhost, true, {Req, Errors}) ->
    {Req#req{ssl_verifyhost = ?SSL_VERIFYHOST_TRUE}, Errors};
opt(ssl_verifyhost, false, {Req, Errors}) ->
    {Req#req{ssl_verifyhost = ?SSL_VERIFYHOST_FALSE}, Errors};
opt(ssl_verifypeer, true, {Req, Errors}) ->
    {Req#req{ssl_verifypeer = ?SSL_VERIFYPEER_TRUE}, Errors};
opt(ssl_verifypeer, false, {Req, Errors}) ->
    {Req#req{ssl_verifypeer = ?SSL_VERIFYPEER_FALSE}, Errors};
opt(capath, CAPath, Acc) ->
    path_opt(capath, #req.capath, CAPath, Acc);
opt(cacert, CACert, Acc) ->
    path_opt(cacert, #req.cacert, CACert, Acc);
opt(timeout_ms, Ms, {Req, Errors}) when ?IS_INT_OPT(Ms, 1) ->
    {Req#req{timeout_ms = Ms}, Errors};
opt(maxredirs, M, {Req, Errors}) when ?IS_INT_OPT(M, -1) ->
    {Req#req{maxredirs = M}, Errors};
opt(http_auth, basic, {Req, Errors}) ->
    {Req#req{http_auth = ?CURLAUTH_BASIC}, Errors};
opt(http_auth, digest, {Req, Errors}) ->
    {Req#req{http_auth = ?CURLAUTH_DIGEST}, Errors};
opt(http_auth, ntlm, {Req, Errors}) ->
    {Req#req{http_auth = ?CURLAUTH_NTLM}, Errors};
opt(http_auth, negotiate, {Req, Errors}) ->
    {Req#req{http_auth = ?CURLAUTH_NEGOTIATE}, Errors};
opt(username, Username, {Req, Errors}) when is_binary(Username) ->
    {Req#req{username = Username}, Errors};
opt(password, Password, {Req, Errors}) when is_binary(Password) ->
    {Req#req{password = Password}, Errors};
opt(proxy, Proxy, {Req, Errors}) when is_binary(Proxy) ->
    {Req#req{proxy = Proxy}, Errors};
opt(tcp_fastopen, true, {Req, Errors}) when ?TCP_FASTOPEN_AVAILABLE ->
    {Req#req{tcp_fastopen = ?TCP_FASTOPEN_TRUE}, Errors};
opt(tcp_fastopen, false, {Req, Errors}) when ?TCP_FASTOPEN_AVAILABLE ->
    {Req#req{tcp_fastopen = ?TCP_FASTOPEN_FALSE}, Errors};
opt(interface, Interface, {Req, Errors}) when is_binary(Interface) ->
    {Req#req{interface = Interface}, Errors};
opt(unix_socket_path, UnixSocketPath, Acc) when ?UNIX_SOCKET_PATH_AVAILABLE ->
    path_opt(unix_socket_path, #req.unix_socket_path, UnixSocketPath, Acc);
opt(doh_url, DOHURL, {Req, Errors}) when ?DOH_URL_AVAILABLE andalso is_binary(DOHURL) ->
    {Req#req{doh_url = DOHURL}, Errors};
opt(http_version, curl_http_version_none, {Req, Errors}) ->
    {Req#req{http_version = ?CURL_HTTP_VERSION_NONE}, Errors};
opt(http_version, curl_http_version_1_0, {Req, Errors}) ->
    {Req#req{http_version = ?CURL_HTTP_VERSION_1_0}, Errors};
opt(http_version, curl_http_version_1_1, {Req, Errors}) ->
    {Req#req{http_version = ?CURL_HTTP_VERSION_1_1}, Errors};
opt(http_version, curl_http_version_2_0, {Req, Errors}) ->
    {Req#req{http_version = ?CURL_HTTP_VERSION_2_0}, Errors};
opt(http_version, curl_http_version_2tls, {Req, Errors}) ->
    {Req#req{http_version = ?CURL_HTTP_VERSION_2TLS}, Errors};
opt(http_version, curl_http_version_2_prior_knowledge, {Req, Errors}) ->
    {Req#req{http_version = ?CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE}, Errors};
opt(http_version, curl_http_version_3, {Req, Errors}) when ?HTTP3_AVAILABLE ->
    {Req#req{http_version = ?CURL_HTTP_VERSION_3}, Errors};
opt(sslversion, sslversion_default, {Req, Errors}) ->
    {Req#req{sslversion = ?CURL_SSLVERSION_DEFAULT}, Errors};
opt(sslversion, sslversion_tlsv1, {Req, Errors}) ->
    {Req#req{sslversion = ?CURL_SSLVERSION_TLSV1}, Errors};
opt(sslversion, sslversion_tlsv1_0, {Req, Errors}) ->
    {Req#req{sslversion = ?CURL_SSLVERSION_TLSV1_0}, Errors};
opt(sslversion, sslversion_tlsv1_1, {Req, Errors}) ->
    {Req#req{sslversion = ?CURL_SSLVERSION_TLSV1_1}, Errors};
opt(sslversion, sslversion_tlsv1_2, {Req, Errors}) ->
    {Req#req{sslversion = ?CURL_SSLVERSION_TLSV1_2}, Errors};
opt(sslversion, sslversion_tlsv1_3, {Req, Errors}) ->
    {Req#req{sslversion = ?CURL_SSLVERSION_TLSV1_3}, Errors};
opt(verbose, true, {Req, Errors}) ->
    {Req#req{verbose = ?VERBOSE_TRUE}, Errors};
opt(verbose, false, {Req, Errors}) ->
    {Req#req{verbose = ?VERBOSE_FALSE}, Errors};
opt(sslcert, Cert, Acc) ->
    path_opt(sslcert, #req.sslcert, Cert, Acc);
opt(sslkey, Key, Acc) ->
    path_opt(sslkey, #req.sslkey, Key, Acc);
opt(sslkey_blob, Key, {Req, Errors})
  when ?SSLKEY_BLOB_AVAILABLE andalso is_binary(Key) ->
    {Req#req{sslkey_blob = Key}, Errors};
opt(keypasswd, Pass, {Req, Errors}) when is_binary(Pass) ->
    {Req#req{keypasswd = Pass}, Errors};
opt(userpwd, UserPwd, {Req, Errors}) when is_binary(UserPwd) ->
    {Req#req{userpwd = UserPwd}, Errors};
opt(dns_cache_timeout, Secs, {Req, Errors}) when ?IS_INT_OPT(Secs, -1) ->
    {Req#req{dns_cache_timeout = Secs}, Errors};
opt(low_speed_limit, Bytes, {Req, Errors}) when ?IS_INT_OPT(Bytes, 1) ->
    {Req#req{low_speed_limit = Bytes}, Errors};
opt(low_speed_time, Secs, {Req, Errors}) when ?IS_INT_OPT(Secs, 1) ->
    {Req#req{low_speed_time = Secs}, Errors};
opt(max_body_size, Bytes, {Req, Errors}) when ?IS_INT_OPT(Bytes, 0) ->
    {Req#req{max_body_size = Bytes}, Errors};
opt(ca_cache_timeout, Secs, {Req, Errors}) when ?IS_INT_OPT(Secs, -1) ->
    {Req#req{ca_cache_timeout = Secs}, Errors};
opt(pipewait, true, {Req, Errors}) ->
    {Req#req{pipewait = ?PIPEWAIT_TRUE}, Errors};
opt(pipewait, false, {Req, Errors}) ->
    {Req#req{pipewait = ?PIPEWAIT_FALSE}, Errors};
opt(stream, true, {Req, Errors}) ->
    {Req#req{stream = ?STREAM_TRUE}, Errors};
opt(stream, false, {Req, Errors}) ->
    {Req#req{stream = ?STREAM_FALSE}, Errors};
opt(stream_window, infinity, {Req, Errors}) ->
    {Req#req{stream_window = ?STREAM_WINDOW_UNLIMITED}, Errors};
opt(stream_window, N, {Req, Errors}) when ?IS_INT_OPT(N, 1) ->
    {Req#req{stream_window = N}, Errors};
opt(retry, Retry, {Req, Errors}) ->
    case katipo_retry:policy(Retry) of
        {ok, Policy} -> {Req#req{retry = Policy}, Errors};
        error -> {Req, [{retry, Retry} | Errors]}
    end;
opt(reply_to, Pid, {Req, Errors}) when is_pid(Pid) ->
    {Req, Errors};
opt(K, V, {Req, Errors}) ->
    {Req, [{K, V} | Errors]}.

%% A path option: stored as a binary in the #req field at Pos.
path_opt(Key, Pos, Path, {Req, Errors}) ->
    case path_to_binary(Path) of
        {ok, Bin} -> {setelement(Pos, Req, Bin), Errors};
        error -> {Req, [{Key, Path} | Errors]}
    end.
