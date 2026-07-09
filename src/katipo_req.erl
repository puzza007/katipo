-module(katipo_req).

-moduledoc false.

%% Turns a user options map into a validated #req{} record for the worker to
%% send to the C port. Owns all request-option validation (opt/3), body
%% encoding, header formatting, and the method<->code conversions. Factored out
%% of katipo to keep the public facade small.

-export([build_req/1]).
-export([check_opts/1]).
-export([get_timeout/1]).
-export([method_int_to_binary/1]).
-export([error_map/2]).

-include("katipo_internal.hrl").

%% method_int() and http_auth_int() come from katipo_internal.hrl (they type the
%% #req wire fields); req() is the validated request this module produces.
-type req() :: #req{}.
-export_type([method_int/0, req/0]).

-dialyzer({nowarn_function, opt/3}).

%% Build a validated, timeout-stamped #req{} from an opts map. Shared by the
%% sync req/2 and async_req/2 entry points.
-spec build_req(katipo:request()) -> {ok, req()} | {error, map()}.
build_req(Opts) ->
    case process_opts(Opts) of
        {ok, #req{url = undefined}} ->
            {error, error_map(bad_opts, <<"[{url,undefined}]">>)};
        {ok, Req} ->
            {ok, Req#req{timeout = ?MODULE:get_timeout(Req)}};
        {error, _} = Error ->
            Error
    end.

-spec check_opts(katipo:request()) -> ok | {error, map()}.
check_opts(Opts) when is_map(Opts) ->
    case process_opts(Opts) of
        {ok, _} ->
            ok;
        {error, _} = Error ->
            Error
    end.

-spec get_timeout(req()) -> pos_integer().
get_timeout(#req{connecttimeout_ms = ConnMs, timeout_ms = ReqMs}) ->
    max(ConnMs, ReqMs).

-spec method_int_to_binary(method_int()) -> binary().
method_int_to_binary(?GET) -> <<"GET">>;
method_int_to_binary(?POST) -> <<"POST">>;
method_int_to_binary(?PUT) -> <<"PUT">>;
method_int_to_binary(?HEAD) -> <<"HEAD">>;
method_int_to_binary(?OPTIONS) -> <<"OPTIONS">>;
method_int_to_binary(?PATCH) -> <<"PATCH">>;
method_int_to_binary(?DELETE) -> <<"DELETE">>.

-spec process_opts(katipo:request()) -> {ok, req()} | {error, map()}.
process_opts(Opts) ->
    case maps:fold(fun opt/3, {#req{}, []}, Opts) of
        {Req = #req{}, []} ->
            {ok, Req};
        {#req{}, Errors} ->
            {error, error_map(bad_opts, Errors)}
    end.

-spec headers_to_binary(katipo:headers()) -> [binary()].
headers_to_binary(Headers) ->
    [iolist_to_binary([K, <<": ">>, V]) || {K, V} <- Headers].

-spec method_to_int(katipo:method()) -> method_int().
method_to_int(get)     -> ?GET;
method_to_int(post)    -> ?POST;
method_to_int(put)     -> ?PUT;
method_to_int(head)    -> ?HEAD;
method_to_int(options) -> ?OPTIONS;
method_to_int(patch)   -> ?PATCH;
method_to_int(delete)  -> ?DELETE.

-spec encode_body(katipo:req_body()) -> {ok, iodata()} | {error, {atom(), term()}}.
encode_body([{_, _} | _] = KVs) ->
    case uri_string:compose_query(KVs) of
        {error, Reason, Message} ->
            {error, {Reason, Message}};
        Body ->
            {ok, Body}
    end;
%% iodata
encode_body(Body) when is_binary(Body) orelse is_list(Body) ->
    {ok, Body};
encode_body(Body) ->
    {error, {invalid_body, Body}}.

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
    {Req#req{headers = headers_to_binary(Headers)}, Errors};
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
opt(connecttimeout_ms, Ms, {Req, Errors}) when is_integer(Ms) andalso Ms > 0 ->
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
opt(capath, CAPath, {Req, Errors}) when is_binary(CAPath) ->
    {Req#req{capath = CAPath}, Errors};
opt(capath, CAPath, {Req, Errors}) when is_list(CAPath) ->
    try unicode:characters_to_binary(CAPath) of
        Bin when is_binary(Bin) -> {Req#req{capath = Bin}, Errors}
    catch _:_ -> {Req, [{capath, CAPath} | Errors]} end;
opt(cacert, CACert, {Req, Errors}) when is_binary(CACert) ->
    {Req#req{cacert = CACert}, Errors};
opt(cacert, CACert, {Req, Errors}) when is_list(CACert) ->
    try unicode:characters_to_binary(CACert) of
        Bin when is_binary(Bin) -> {Req#req{cacert = Bin}, Errors}
    catch _:_ -> {Req, [{cacert, CACert} | Errors]} end;
opt(timeout_ms, Ms, {Req, Errors}) when is_integer(Ms) andalso Ms > 0 ->
    {Req#req{timeout_ms = Ms}, Errors};
opt(maxredirs, M, {Req, Errors}) when is_integer(M) andalso M >= -1 ->
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
opt(unix_socket_path, UnixSocketPath, {Req, Errors})
  when is_binary(UnixSocketPath) andalso ?UNIX_SOCKET_PATH_AVAILABLE ->
    {Req#req{unix_socket_path = UnixSocketPath}, Errors};
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
opt(sslcert, Cert, {Req, Errors}) when is_binary(Cert) ->
    {Req#req{sslcert = Cert}, Errors};
opt(sslcert, Cert, {Req, Errors}) when is_list(Cert) ->
    try unicode:characters_to_binary(Cert) of
        Bin when is_binary(Bin) -> {Req#req{sslcert = Bin}, Errors}
    catch _:_ -> {Req, [{sslcert, Cert} | Errors]} end;
opt(sslkey, Key, {Req, Errors}) when is_binary(Key) ->
    {Req#req{sslkey = Key}, Errors};
opt(sslkey, Key, {Req, Errors}) when is_list(Key) ->
    try unicode:characters_to_binary(Key) of
        Bin when is_binary(Bin) -> {Req#req{sslkey = Bin}, Errors}
    catch _:_ -> {Req, [{sslkey, Key} | Errors]} end;
opt(sslkey_blob, Key, {Req, Errors})
  when ?SSLKEY_BLOB_AVAILABLE andalso is_binary(Key) ->
    {Req#req{sslkey_blob = Key}, Errors};
opt(keypasswd, Pass, {Req, Errors}) when is_binary(Pass) ->
    {Req#req{keypasswd = Pass}, Errors};
opt(userpwd, UserPwd, {Req, Errors}) when is_binary(UserPwd) ->
    {Req#req{userpwd = UserPwd}, Errors};
opt(dns_cache_timeout, Secs, {Req, Errors}) when is_integer(Secs) andalso Secs >= -1 ->
    {Req#req{dns_cache_timeout = Secs}, Errors};
opt(ca_cache_timeout, Secs, {Req, Errors}) when is_integer(Secs) andalso Secs >= -1 ->
    {Req#req{ca_cache_timeout = Secs}, Errors};
opt(pipewait, true, {Req, Errors}) ->
    {Req#req{pipewait = ?PIPEWAIT_TRUE}, Errors};
opt(pipewait, false, {Req, Errors}) ->
    {Req#req{pipewait = ?PIPEWAIT_FALSE}, Errors};
opt(reply_to, Pid, {Req, Errors}) when is_pid(Pid) ->
    {Req, Errors};
opt(K, V, {Req, Errors}) ->
    {Req, [{K, V} | Errors]}.
