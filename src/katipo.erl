-module(katipo).

-behaviour(gen_server).

-compile({no_auto_import, [put/2]}).

-export([start_link/1]).

-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).
-export([req/2]).
-export([get/2]).
-export([get/3]).
-export([post/2]).
-export([post/3]).
-export([put/2]).
-export([put/3]).
-export([head/2]).
-export([head/3]).
-export([options/2]).
-export([options/3]).
-export([patch/2]).
-export([patch/3]).
-export([delete/2]).
-export([delete/3]).

-export([check_opts/1]).

%% only for mocking during tests
-export([get_timeout/1]).

-export([tcp_fastopen_available/0]).
-export([unix_socket_path_available/0]).
-export([doh_url_available/0]).
-export([sslkey_blob_available/0]).
-export([http3_available/0]).

-ifdef(tcp_fastopen_available).
-define(TCP_FASTOPEN_AVAILABLE, true).
-else.
-define(TCP_FASTOPEN_AVAILABLE, false).
-endif.

-ifdef(unix_socket_path_available).
-define(UNIX_SOCKET_PATH_AVAILABLE, true).
-else.
-define(UNIX_SOCKET_PATH_AVAILABLE, false).
-endif.

-ifdef(doh_url_available).
-define(DOH_URL_AVAILABLE, true).
-define(SSL_CACERT_ERROR_CODE, peer_failed_verification).
-else.
-define(DOH_URL_AVAILABLE, false).
-define(SSL_CACERT_ERROR_CODE, ssl_cert).
-endif.

-ifdef(sslkey_blob_available).
-define(SSLKEY_BLOB_AVAILABLE, true).
-else.
-define(SSLKEY_BLOB_AVAILABLE, false).
-endif.

-ifdef(http3_available).
-define(HTTP3_AVAILABLE, true).
-else.
-define(HTTP3_AVAILABLE, false).
-endif.

-record(state, {port :: port(),
                reqs = #{} :: map()}).

-define(GET, 0).
-define(POST, 1).
-define(PUT, 2).
-define(HEAD, 3).
-define(OPTIONS, 4).
-define(PATCH, 5).
-define(DELETE, 6).

-define(CONNECTTIMEOUT_MS, 5).
-define(FOLLOWLOCATION, 6).
-define(SSL_VERIFYHOST, 7).
-define(TIMEOUT_MS, 8).
-define(MAXREDIRS, 9).
-define(SSL_VERIFYPEER, 10).
-define(CAPATH, 11).
-define(HTTP_AUTH, 12).
-define(USERNAME, 13).
-define(PASSWORD, 14).
-define(PROXY, 15).
-define(CACERT, 16).
-define(TCP_FASTOPEN, 17).
-define(INTERFACE, 18).
-define(UNIX_SOCKET_PATH, 19).
-define(LOCK_DATA_SSL_SESSION, 20).
-define(DOH_URL, 21).
-define(HTTP_VERSION, 22).
-define(VERBOSE, 23).
-define(SSLCERT, 24).
-define(SSLKEY, 25).
-define(SSLKEY_BLOB, 26).
-define(KEYPASSWD, 27).
-define(USERPWD, 28).
-define(SSLVERSION, 29).

-define(DEFAULT_REQ_TIMEOUT, 30000).
-define(FOLLOWLOCATION_TRUE, 1).
-define(FOLLOWLOCATION_FALSE, 0).
-define(SSL_VERIFYHOST_TRUE, 2).
-define(SSL_VERIFYHOST_FALSE, 0).
-define(SSL_VERIFYPEER_TRUE, 1).
-define(SSL_VERIFYPEER_FALSE, 0).
-define(CURLAUTH_BASIC, 100).
-define(CURLAUTH_DIGEST, 101).
-define(CURLAUTH_UNDEFINED, 102).
-define(CURLAUTH_NTLM, 103).
-define(CURLAUTH_NEGOTIATE, 104).
-define(TCP_FASTOPEN_FALSE, 0).
-define(TCP_FASTOPEN_TRUE, 1).
-define(LOCK_DATA_SSL_SESSION_FALSE, 0).
-define(LOCK_DATA_SSL_SESSION_TRUE, 1).
-define(VERBOSE_TRUE, 1).
-define(VERBOSE_FALSE, 0).

-define(METHODS, [get, post, put, head, options, patch, delete]).

-type method() :: get | post | put | head | options | patch | delete.
-type method_int() :: ?GET | ?POST | ?PUT | ?HEAD | ?OPTIONS | ?PATCH | ?DELETE.
-type url() :: binary().
-type error_code() ::
        ok |
        unsupported_protocol |
        failed_init |
        url_malformat |
        not_built_in |
        couldnt_resolve_proxy |
        couldnt_resolve_host |
        couldnt_connect |
        ftp_weird_server_reply |
        remote_access_denied |
        ftp_accept_failed |
        ftp_weird_pass_reply |
        ftp_accept_timeout |
        ftp_weird_pasv_reply |
        ftp_weird_227_format |
        ftp_cant_get_host |
        http2 |
        ftp_couldnt_set_type |
        partial_file |
        ftp_couldnt_retr_file |
        obsolete20 |
        quote_error |
        http_returned_error |
        write_error |
        obsolete24 |
        upload_failed |
        read_error |
        out_of_memory |
        operation_timedout |
        obsolete29 |
        ftp_port_failed |
        ftp_couldnt_use_rest |
        obsolete32 |
        range_error |
        http_post_error |
        ssl_connect_error |
        bad_download_resume |
        file_couldnt_read_file |
        ldap_cannot_bind |
        ldap_search_failed |
        obsolete40 |
        function_not_found |
        aborted_by_callback |
        bad_function_argument |
        obsolete44 |
        interface_failed |
        obsolete46 |
        too_many_redirects |
        unknown_option |
        telnet_option_syntax |
        obsolete50 |
        got_nothing |
        ssl_engine_notfound |
        ssl_engine_setfailed |
        send_error |
        recv_error |
        obsolete57 |
        ssl_certproblem |
        ssl_cipher |
        %% Gone since 7.62.0
        %% TODO: more structured way to do version-dependent stuff
        ?SSL_CACERT_ERROR_CODE |
        bad_content_encoding |
        ldap_invalid_url |
        filesize_exceeded |
        use_ssl_failed |
        send_fail_rewind |
        ssl_engine_initfailed |
        login_denied |
        tftp_notfound |
        tftp_perm |
        remote_disk_full |
        tftp_illegal |
        tftp_unknownid |
        remote_file_exists |
        tftp_nosuchuser |
        conv_failed |
        conv_reqd |
        ssl_cacert_badfile |
        remote_file_not_found |
        ssh |
        ssl_shutdown_failed |
        again |
        ssl_crl_badfile |
        ssl_issuer_error |
        ftp_pret_failed |
        rtsp_cseq_error |
        rtsp_session_error |
        ftp_bad_file_list |
        chunk_failed |
        no_connection_available |
        obsolete16 |
        ssl_pinnedpubkeynotmatch |
        ssl_invalidcertstatus |
        curl_last |
        %% returned by us, not curl
        bad_opts.

-type curlmopt() ::
        %% curlmopt_chunk_length_penalty_size |
        %% curlmopt_content_length_penalty_size |
        %% curlmopt_max_host_connections |
        max_pipeline_length |
        curlmopt_max_total_connections |
        %% curlmopt_maxconnects |
        pipelining.
        %% curlmopt_pipelining_site_bl |
        %% curlmopt_pipelining_server_bl |
        %% curlmopt_pushfunction |
        %% curlmopt_pushdata |
        %% curlmopt_socketfunction |
        %% curlmopt_socketdata |
        %% curlmopt_timerfunction |
        %% curlmopt_timerdata.

-type error_msg() :: binary().
-type status() :: pos_integer().
-type header() :: {binary(), iodata()}.
-type headers() :: [header()].
-opaque cookiejar() :: [binary()].
-type qs_vals() :: [{unicode:chardata(), unicode:chardata() | true}].
-type req_body() :: iodata() | qs_vals().
-type body() :: binary().
-type connecttimeout_ms() :: pos_integer().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_CONNECTTIMEOUT.html]
-type ssl_verifyhost() :: boolean().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html]
-type ssl_verifypeer() :: boolean().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html]
-type proxy() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_PROXY.html]
-type tcp_fastopen() :: boolean().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_TCP_FASTOPEN.html]
-type interface() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_INTERFACE.html]
-type unix_socket_path() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_UNIX_SOCKET_PATH.html]
-type doh_url() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_DOH_URL.html]
-type sslcert() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_SSLCERT.html]
-type sslkey() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEY.html]
-type sslkey_blob() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEY_BLOB.html]
-type userpwd() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_USERPWD.html]
-type request() :: #{url := binary(),
                    method := method(),
                    headers => headers(),
                    cookiejar => cookiejar(),
                    body => req_body(),
                    connecttimeout_ms => connecttimeout_ms(),
                    followlocation => boolean(),
                    ssl_verifyhost => ssl_verifyhost(),
                    ssl_verifypeer => ssl_verifypeer(),
                    capath => binary(),
                    cacert => binary(),
                    timeout_ms => pos_integer(),
                    maxredirs => non_neg_integer(),
                    http_auth => http_auth(),
                    username => binary(),
                    password => binary(),
                    proxy => proxy(),
                    return_metrics => boolean(),
                    tcp_fastopen => tcp_fastopen(),
                    interface => interface(),
                    unix_socket_path => unix_socket_path(),
                    lock_data_ssl_session => boolean(),
                    doh_url => doh_url(),
                    http_version => curlopt_http_version(),
                    sslversion => curlopt_sslversion(),
                    verbose => boolean(),
                    sslcert => sslcert(),
                    sslkey => sslkey(),
                    sslkey_blob => sslkey_blob(),
                    userpwd => userpwd()}.
-type opts() :: #{headers => headers(),
                    cookiejar => cookiejar(),
                    body => req_body(),
                    connecttimeout_ms => connecttimeout_ms(),
                    followlocation => boolean(),
                    ssl_verifyhost => ssl_verifyhost(),
                    ssl_verifypeer => ssl_verifypeer(),
                    capath => binary(),
                    cacert => binary(),
                    timeout_ms => pos_integer(),
                    maxredirs => non_neg_integer(),
                    http_auth => http_auth(),
                    username => binary(),
                    password => binary(),
                    proxy => proxy(),
                    return_metrics => boolean(),
                    tcp_fastopen => tcp_fastopen(),
                    interface => interface(),
                    unix_socket_path => unix_socket_path(),
                    lock_data_ssl_session => boolean(),
                    doh_url => doh_url(),
                    http_version => curlopt_http_version(),
                    sslversion => curlopt_sslversion(),
                    verbose => boolean(),
                    sslcert => sslcert(),
                    sslkey => sslkey(),
                    sslkey_blob => sslkey_blob(),
                    userpwd => userpwd()}.
-export_type([opts/0]).
-type metrics() :: proplists:proplist().
-type response() :: {ok, #{status := status(),
                           headers := headers(),
                           cookiejar := cookiejar(),
                           body := body(),
                           metrics => proplists:proplist()}} |
                    {error, #{code := error_code(),
                              message := error_msg()}}.
-type http_auth() :: basic | digest | ntlm | negotiate.
-type http_auth_int() :: ?CURLAUTH_UNDEFINED |
                         ?CURLAUTH_BASIC |
                         ?CURLAUTH_DIGEST |
                         ?CURLAUTH_NTLM |
                         ?CURLAUTH_NEGOTIATE.
-type pipelining() :: nothing | http1 | multiplex.
-type curlopt_http_version() :: curl_http_version_none |
                                curl_http_version_1_0 |
                                curl_http_version_1_1 |
                                curl_http_version_2_0 |
                                curl_http_version_2tls |
                                curl_http_version_2_prior_knowledge |
                                curl_http_version_3.
%% HTTP protocol version to use
%% see [https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html]
-type curlopt_sslversion() :: sslversion_default |
                              sslversion_tlsv1 |
                              sslversion_tlsv1_0 |
                              sslversion_tlsv1_1 |
                              sslversion_tlsv1_2 |
                              sslversion_tlsv1_3.
%% Minimum SSL/TLS version to use
%% see [https://curl.se/libcurl/c/CURLOPT_SSLVERSION.html]
-type curlmopts() :: [{max_pipeline_length, non_neg_integer()} |
                      {pipelining, pipelining()} |
                      {max_total_connections, non_neg_integer()}].

-export_type([method/0]).
-export_type([url/0]).
-export_type([error_code/0]).
-export_type([error_msg/0]).
-export_type([status/0]).
-export_type([header/0]).
-export_type([headers/0]).
-export_type([cookiejar/0]).
-export_type([req_body/0]).
-export_type([body/0]).
-export_type([request/0]).
-export_type([metrics/0]).
-export_type([response/0]).
-export_type([http_auth/0]).
-export_type([curlmopts/0]).
-export_type([connecttimeout_ms/0]).
-export_type([ssl_verifyhost/0]).
-export_type([ssl_verifypeer/0]).
-export_type([proxy/0]).
-export_type([tcp_fastopen/0]).
-export_type([interface/0]).
-export_type([unix_socket_path/0]).
-export_type([doh_url/0]).
-export_type([sslcert/0]).
-export_type([sslkey/0]).
-export_type([sslkey_blob/0]).
-export_type([userpwd/0]).

-record(req, {
          method = ?GET :: method_int(),
          url :: undefined | binary(),
          headers = [] :: headers(),
          cookiejar = [] :: cookiejar(),
          body = <<>> :: body(),
          connecttimeout_ms = ?DEFAULT_REQ_TIMEOUT :: pos_integer(),
          followlocation = ?FOLLOWLOCATION_FALSE :: integer(),
          ssl_verifyhost = ?SSL_VERIFYHOST_TRUE :: integer(),
          ssl_verifypeer = ?SSL_VERIFYPEER_TRUE :: integer(),
          capath = undefined :: undefined | binary() | file:name_all(),
          cacert = undefined :: undefined | binary() | file:name_all(),
          timeout_ms = ?DEFAULT_REQ_TIMEOUT :: pos_integer(),
          maxredirs = 9 :: non_neg_integer(),
          timeout = ?DEFAULT_REQ_TIMEOUT :: pos_integer(),
          http_auth = ?CURLAUTH_UNDEFINED :: http_auth_int(),
          username = undefined :: undefined | binary(),
          password = undefined :: undefined | binary(),
          proxy = undefined :: undefined | binary(),
          return_metrics = false :: boolean(),
          tcp_fastopen = ?TCP_FASTOPEN_FALSE :: ?TCP_FASTOPEN_FALSE | ?TCP_FASTOPEN_TRUE,
          interface = undefined :: undefined | binary(),
          unix_socket_path = undefined :: undefined | binary(),
          lock_data_ssl_session = ?LOCK_DATA_SSL_SESSION_FALSE ::
            ?LOCK_DATA_SSL_SESSION_FALSE | ?LOCK_DATA_SSL_SESSION_TRUE,
          doh_url = undefined :: undefined | doh_url(),
          http_version = curl_http_version_none :: curlopt_http_version(),
          sslversion = sslversion_default :: curlopt_sslversion(),
          verbose = ?VERBOSE_FALSE :: ?VERBOSE_FALSE | ?VERBOSE_TRUE,
          sslcert = undefined :: undefined | binary() | file:name_all(),
          sslkey = undefined :: undefined | binary() | file:name_all(),
          sslkey_blob = undefined :: undefined | binary(),
          keypasswd = undefined :: undefined | binary(),
          userpwd = undefined :: undefined | binary()
         }).

-type req() :: #req{}.

%% @private
tcp_fastopen_available() ->
    ?TCP_FASTOPEN_AVAILABLE.

%% @private
unix_socket_path_available() ->
    ?UNIX_SOCKET_PATH_AVAILABLE.

%% @private
doh_url_available() ->
    ?DOH_URL_AVAILABLE.

%% @private
sslkey_blob_available() ->
    ?SSLKEY_BLOB_AVAILABLE.

%% @private
http3_available() ->
    ?HTTP3_AVAILABLE.

-dialyzer({nowarn_function, opt/3}).

%% @equiv get(Poolname, Url, #{})
-spec get(katipo_pool:name(), url()) -> response().
get(PoolName, Url) ->
    req(PoolName, #{url => Url, method => get}).

-spec get(katipo_pool:name(), url(), opts()) -> response().
get(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => get}).

%% @equiv post(Poolname, Url, #{})
-spec post(katipo_pool:name(), url()) -> response().
post(PoolName, Url) ->
    req(PoolName, #{url => Url, method => post}).

-spec post(katipo_pool:name(), url(), opts()) -> response().
post(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => post}).

%% @equiv put(Poolname, Url, #{})
-spec put(katipo_pool:name(), url()) -> response().
put(PoolName, Url) ->
    req(PoolName, #{url => Url, method => put}).

-spec put(katipo_pool:name(), url(), opts()) -> response().
put(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => put}).

%% @equiv head(Poolname, Url, #{})
-spec head(katipo_pool:name(), url()) -> response().
head(PoolName, Url) ->
    req(PoolName, #{url => Url, method => head}).

-spec head(katipo_pool:name(), url(), opts()) -> response().
head(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => head}).

%% @equiv options(Poolname, Url, #{})
-spec options(katipo_pool:name(), url()) -> response().
options(PoolName, Url) ->
    req(PoolName, #{url => Url, method => options}).

-spec options(katipo_pool:name(), url(), opts()) -> response().
options(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => options}).

%% @equiv patch(Poolname, Url, #{})
-spec patch(katipo_pool:name(), url()) -> response().
patch(PoolName, Url) ->
    req(PoolName, #{url => Url, method => patch}).

-spec patch(katipo_pool:name(), url(), opts()) -> response().
patch(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => patch}).

%% @equiv delete(Poolname, Url, #{})
-spec delete(katipo_pool:name(), url()) -> response().
delete(PoolName, Url) ->
    req(PoolName, #{url => Url, method => delete}).

-spec delete(katipo_pool:name(), url(), opts()) -> response().
delete(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => delete}).

%% @private
-spec req(katipo_pool:name(), request()) -> response().
req(PoolName, Opts)
  when is_map(Opts) ->
    case process_opts(Opts) of
        {ok, #req{url = undefined}} ->
            {error, error_map(bad_opts, <<"[{url,undefined}]">>)};
        {ok, Req} ->
            Timeout = ?MODULE:get_timeout(Req),
            Req2 = Req#req{timeout = Timeout},
            Ts = os:timestamp(),
            {Result, {Response, Metrics}} =
                wpool:call(PoolName, Req2, random_worker, infinity),
            TotalUs = timer:now_diff(os:timestamp(), Ts),
            Metrics2 = katipo_metrics:notify({Result, Response}, Metrics, TotalUs),
            Response2 = maybe_return_metrics(Req2, Metrics2, Response),
            {Result, Response2};
        {error, _} = Error ->
            ok = katipo_metrics:notify_error(),
            Error
    end.

%% @private
start_link(CurlOpts) when is_list(CurlOpts) ->
    Args = [CurlOpts],
    gen_server:start_link(?MODULE, Args, []).

%% @private
init([CurlOpts]) ->
    process_flag(trap_exit, true),
    case get_mopts(CurlOpts) of
        {ok, Args} ->
            Prog = filename:join([code:priv_dir(katipo), "katipo"]),
            Port = open_port({spawn, Prog ++ " " ++ Args}, [{packet, 4}, binary]),
            {ok, #state{port = Port, reqs = #{}}};
        {error, Error} ->
            {stop, Error}
    end.

%% @private
handle_call(#req{method = Method,
                 url = Url,
                 headers = Headers,
                 cookiejar = CookieJar,
                 body = Body,
                 connecttimeout_ms = ConnTimeoutMs,
                 followlocation = FollowLocation,
                 ssl_verifyhost = SslVerifyHost,
                 ssl_verifypeer = SslVerifyPeer,
                 capath = CAPath,
                 cacert = CACert,
                 timeout_ms = TimeoutMs,
                 maxredirs = MaxRedirs,
                 timeout = Timeout,
                 http_auth = HTTPAuth,
                 username = Username,
                 password = Password,
                 proxy = Proxy,
                 tcp_fastopen = TCPFastOpen,
                 interface = Interface,
                 unix_socket_path = UnixSocketPath,
                 lock_data_ssl_session = LockDataSslSession,
                 doh_url = DOHURL,
                 http_version = HTTPVersion,
                 sslversion = SSLVersion,
                 verbose = Verbose,
                 sslcert = SSLCert,
                 sslkey = SSLKey,
                 sslkey_blob = SSLKeyBlob,
                 keypasswd = KeyPasswd,
                 userpwd = UserPwd},
             From,
             State = #state{port = Port, reqs = Reqs}) ->
    {Self, Ref} = From,
    Opts = [{?CONNECTTIMEOUT_MS, ConnTimeoutMs},
            {?FOLLOWLOCATION, FollowLocation},
            {?SSL_VERIFYHOST, SslVerifyHost},
            {?SSL_VERIFYPEER, SslVerifyPeer},
            {?CAPATH, CAPath},
            {?CACERT, CACert},
            {?TIMEOUT_MS, TimeoutMs},
            {?MAXREDIRS, MaxRedirs},
            {?HTTP_AUTH, HTTPAuth},
            {?USERNAME, Username},
            {?PASSWORD, Password},
            {?PROXY, Proxy},
            {?TCP_FASTOPEN, TCPFastOpen},
            {?INTERFACE, Interface},
            {?UNIX_SOCKET_PATH, UnixSocketPath},
            {?LOCK_DATA_SSL_SESSION, LockDataSslSession},
            {?DOH_URL, DOHURL},
            {?HTTP_VERSION, HTTPVersion},
            {?SSLVERSION, SSLVersion},
            {?VERBOSE, Verbose},
            {?SSLCERT, SSLCert},
            {?SSLKEY, SSLKey},
            {?SSLKEY_BLOB, SSLKeyBlob},
            {?KEYPASSWD, KeyPasswd},
            {?USERPWD, UserPwd}],
    Command = {Self, Ref, Method, Url, Headers, CookieJar, Body, Opts},
    true = port_command(Port, term_to_binary(Command)),
    Tref = erlang:start_timer(Timeout, self(), {req_timeout, From}),
    Reqs2 = maps:put(From, Tref, Reqs),
    {noreply, State#state{reqs = Reqs2}}.

%% @private
handle_cast(Msg, State) ->
    error_logger:error_msg("Unexpected cast: ~p", [Msg]),
    {noreply, State}.

%% @private
handle_info({Port, {data, Data}}, State = #state{port = Port, reqs = Reqs}) ->
    {Result, {From, Response}} =
        case binary_to_term(Data) of
            {ok, {From0, {Status, Headers, CookieJar, Body, Metrics}}} ->
                R = #{status => Status,
                      headers => parse_headers(Headers),
                      cookiejar => CookieJar,
                      body => Body},
                {ok, {From0, {R, Metrics}}};
            {error, {From0, {Code, Message, Metrics}}} ->
                Error = #{code => Code, message => Message},
                {error, {From0, {Error, Metrics}}}
        end,
    case maps:find(From, Reqs) of
        {ok, Tref} ->
            _ = erlang:cancel_timer(Tref),
            _ = gen_server:reply(From, {Result, Response});
        error ->
            ok
    end,
    Reqs2 = maps:remove(From, Reqs),
    {noreply, State#state{reqs = Reqs2}};
handle_info({timeout, Tref, {req_timeout, From}}, State = #state{reqs = Reqs}) ->
    Reqs2 =
        case maps:find(From, Reqs) of
            {ok, Tref} ->
                Error = #{code => operation_timedout, message => <<>>},
                Metrics = [],
                _ = gen_server:reply(From, {error, {Error, Metrics}}),
                maps:remove(From, Reqs);
            error ->
                Reqs
        end,
    {noreply, State#state{reqs = Reqs2}};
handle_info({'EXIT', Port, Reason}, State = #state{port = Port}) ->
    error_logger:error_msg("Port ~p died with reason: ~p", [Port, Reason]),
    {stop, port_died, State}.

%% @private
terminate(_Reason, #state{port = Port}) ->
    true = port_close(Port),
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

-spec headers_to_binary(headers()) -> [binary()].
headers_to_binary(Headers) ->
    [iolist_to_binary([K, <<": ">>, V]) || {K, V} <- Headers].

-spec method_to_int(method()) -> method_int().
method_to_int(get)     -> ?GET;
method_to_int(post)    -> ?POST;
method_to_int(put)     -> ?PUT;
method_to_int(head)    -> ?HEAD;
method_to_int(options) -> ?OPTIONS;
method_to_int(patch)   -> ?PATCH;
method_to_int(delete)  -> ?DELETE.

-spec parse_headers([binary()]) -> headers().
parse_headers([_StatusLine | Lines]) ->
    [parse_header(L) || L <- Lines].

-spec parse_header(binary()) -> header().
parse_header(Line) when is_binary(Line) ->
    case binary:split(Line, <<": ">>, [trim]) of
        [K] -> {K, <<>>};
        [K, V] -> {K, V}
    end.

-spec encode_body(req_body()) -> {ok, iodata()} | {error, {atom(), term()}}.
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
    {error, Body}.

get_mopts(Opts) ->
    L = lists:filtermap(fun mopt_supported/1, Opts),
    LengthOpts = length(Opts),
    case length(L) of
        LengthOpts ->
            {ok, string:join(L, " ")};
        _ ->
            {error, {bad_opts, Opts}}
    end.

-spec mopt_supported({curlmopt(), any()}) -> false | {true, any()}.
mopt_supported({max_pipeline_length, Val})
  when is_integer(Val) andalso Val >= 0 ->
    {true, "--max-pipeline-length " ++ integer_to_list(Val)};
mopt_supported({pipelining, nothing}) ->
    {true, "--pipelining 0"};
mopt_supported({pipelining, http1}) ->
    {true, "--pipelining 1"};
mopt_supported({pipelining, multiplex}) ->
    {true, "--pipelining 2"};
mopt_supported({max_total_connections, Val})
  when is_integer(Val) andalso Val >= 0 ->
    {true, "--max-total-connections " ++ integer_to_list(Val)};
mopt_supported({_, _}) ->
    false.

%% @private
-spec get_timeout(req()) -> pos_integer().
get_timeout(#req{connecttimeout_ms = ConnMs, timeout_ms = ReqMs}) ->
    max(ConnMs, ReqMs).

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
opt(cacert, CACert, {Req, Errors}) when is_binary(CACert) ->
    {Req#req{cacert = CACert}, Errors};
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
opt(return_metrics, Flag, {Req, Errors}) when is_boolean(Flag) ->
    {Req#req{return_metrics = Flag}, Errors};
opt(tcp_fastopen, true, {Req, Errors}) when ?TCP_FASTOPEN_AVAILABLE ->
    {Req#req{tcp_fastopen = ?TCP_FASTOPEN_TRUE}, Errors};
opt(tcp_fastopen, false, {Req, Errors}) when ?TCP_FASTOPEN_AVAILABLE ->
    {Req#req{tcp_fastopen = ?TCP_FASTOPEN_FALSE}, Errors};
opt(interface, Interface, {Req, Errors}) when is_binary(Interface) ->
    {Req#req{interface = Interface}, Errors};
opt(unix_socket_path, UnixSocketPath, {Req, Errors})
  when is_binary(UnixSocketPath) andalso ?UNIX_SOCKET_PATH_AVAILABLE ->
    {Req#req{unix_socket_path = UnixSocketPath}, Errors};
opt(lock_data_ssl_session, true, {Req, Errors}) ->
    {Req#req{lock_data_ssl_session = ?LOCK_DATA_SSL_SESSION_TRUE}, Errors};
opt(lock_data_ssl_session, false, {Req, Errors}) ->
    {Req#req{lock_data_ssl_session = ?LOCK_DATA_SSL_SESSION_FALSE}, Errors};
opt(doh_url, DOHURL, {Req, Errors}) when ?DOH_URL_AVAILABLE andalso is_binary(DOHURL) ->
    {Req#req{doh_url = DOHURL}, Errors};
opt(http_version, curl_http_version_none, {Req, Errors}) ->
    {Req#req{http_version = 0}, Errors};
opt(http_version, curl_http_version_1_0, {Req, Errors}) ->
    {Req#req{http_version = 1}, Errors};
opt(http_version, curl_http_version_1_1, {Req, Errors}) ->
    {Req#req{http_version = 2}, Errors};
opt(http_version, curl_http_version_2_0, {Req, Errors}) ->
    {Req#req{http_version = 3}, Errors};
opt(http_version, curl_http_version_2tls, {Req, Errors}) ->
    {Req#req{http_version = 4}, Errors};
opt(http_version, curl_http_version_2_prior_knowledge, {Req, Errors}) ->
    {Req#req{http_version = 5}, Errors};
%% CURL_HTTP_VERSION_3 = 30
%% See: https://github.com/curl/curl/blob/
%%      32d64b2e875f0d74cd433dff8bda9f8a98dcd44e/include/curl/curl.h#L1983
opt(http_version, curl_http_version_3, {Req, Errors}) when ?HTTP3_AVAILABLE ->
    {Req#req{http_version = 30}, Errors};
opt(sslversion, sslversion_default, {Req, Errors}) ->
    {Req#req{sslversion = 0}, Errors};
opt(sslversion, sslversion_tlsv1, {Req, Errors}) ->
    {Req#req{sslversion = 1}, Errors};
opt(sslversion, sslversion_tlsv1_0, {Req, Errors}) ->
    {Req#req{sslversion = 4}, Errors};
opt(sslversion, sslversion_tlsv1_1, {Req, Errors}) ->
    {Req#req{sslversion = 5}, Errors};
opt(sslversion, sslversion_tlsv1_2, {Req, Errors}) ->
    {Req#req{sslversion = 6}, Errors};
opt(sslversion, sslversion_tlsv1_3, {Req, Errors}) ->
    {Req#req{sslversion = 7}, Errors};
opt(verbose, true, {Req, Errors}) ->
    {Req#req{verbose = ?VERBOSE_TRUE}, Errors};
opt(verbose, false, {Req, Errors}) ->
    {Req#req{verbose = ?VERBOSE_FALSE}, Errors};
opt(sslcert, Cert, {Req, Errors}) when is_binary(Cert) ->
    {Req#req{sslcert = Cert}, Errors};
opt(sslkey, Key, {Req, Errors}) when is_binary(Key) ->
    {Req#req{sslkey = Key}, Errors};
opt(sslkey_blob, Key, {Req, Errors})
  when ?SSLKEY_BLOB_AVAILABLE andalso is_binary(Key) ->
    {Req#req{sslkey_blob = Key}, Errors};
opt(keypasswd, Pass, {Req, Errors}) when is_binary(Pass) ->
    {Req#req{keypasswd = Pass}, Errors};
opt(userpwd, UserPwd, {Req, Errors}) when is_binary(UserPwd) ->
    {Req#req{userpwd = UserPwd}, Errors};
opt(K, V, {Req, Errors}) ->
    {Req, [{K, V} | Errors]}.

-spec process_opts(request()) -> {ok, req()} | {error, map()}.
process_opts(Opts) ->
    case maps:fold(fun opt/3, {#req{}, []}, Opts) of
        {Req = #req{}, []} ->
            {ok, Req};
        {#req{}, Errors} ->
            {error, error_map(bad_opts, Errors)}
    end.

%% @private
-spec check_opts(request()) -> ok | {error, map()}.
check_opts(Opts) when is_map(Opts) ->
    case process_opts(Opts) of
        {ok, _} ->
            ok;
        {error, _} = Error ->
            Error
    end.

maybe_return_metrics(#req{return_metrics = true}, Metrics, Response) ->
    maps:put(metrics, Metrics, Response);
maybe_return_metrics(_Req, _Metrics, Response) ->
    Response.

error_map(Code, Message) when is_atom(Code) andalso is_binary(Message) ->
    #{code => Code, message => Message};
error_map(Code, Message) when is_atom(Code) ->
    BinaryMessage = iolist_to_binary(io_lib:format("~p", [Message])),
    error_map(Code, BinaryMessage).
