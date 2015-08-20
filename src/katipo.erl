-module(katipo).

-behaviour(gen_server).

-compile({no_auto_import,[put/2]}).

-export([start_link/2]).

-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-export([get/1]).
-export([get/2]).
-export([post/1]).
-export([post/2]).
-export([put/1]).
-export([put/2]).
-export([head/1]).
-export([head/2]).
-export([options/1]).
-export([options/2]).

%% only for mocking during tests
-export([get_timeout/1]).

-record(state, {port :: port(),
                reqs = #{} :: map()}).

-define(get, 0).
-define(post, 1).
-define(put, 2).
-define(head, 3).
-define(options, 4).

-define(connecttimeout_ms, 5).
-define(followlocation, 6).
-define(ssl_verifyhost, 7).
-define(timeout_ms, 8).
-define(maxredirs, 9).
-define(ssl_verifypeer, 10).
-define(capath, 11).
-define(http_auth, 12).
-define(username, 13).
-define(password, 14).
-define(proxy, 15).

-define(DEFAULT_REQ_TIMEOUT, 30000).
-define(FOLLOWLOCATION_TRUE, 1).
-define(FOLLOWLOCATION_FALSE, 0).
-define(SSL_VERIFYHOST_TRUE, 2).
-define(SSL_VERIFYHOST_FALSE, 0).
-define(SSL_VERIFYPEER_TRUE, 1).
-define(SSL_VERIFYPEER_FALSE, 0).
-define(CURLAUTH_BASIC, 100).
-define(CURLAUTH_DIGEST, 101).

-type method() :: get | post | put | head | options.
-type method_int() :: ?get | ?post | ?put | ?head | ?options.
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
        peer_failed_verification |
        got_nothing |
        ssl_engine_notfound |
        ssl_engine_setfailed |
        send_error |
        recv_error |
        obsolete57 |
        ssl_certproblem |
        ssl_cipher |
        ssl_cacert |
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
        %% curlmopt_max_total_connections |
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
-type headers() :: [{binary(), iodata()}].
-opaque cookiejar() :: [binary()].
-type qs_vals() :: [{binary(), binary() | true}].
-type req_body() :: iodata() | qs_vals().
-type body() :: binary().
%% {ok, #{status => status(),
%%        headers => headers(),
%%        cookiejar => cookiejar(),
%%        body => body()}}
%% {error, #{code => error_code(),
%%           message => error_msg()}}
-type response() :: {ok, map()} | {error, map()}.
-type http_auth() :: basic | digest.
-type http_auth_int() :: ?CURLAUTH_BASIC | ?CURLAUTH_DIGEST.

-export_type([method/0]).
-export_type([url/0]).
-export_type([error_code/0]).
-export_type([error_msg/0]).
-export_type([status/0]).
-export_type([headers/0]).
-export_type([cookiejar/0]).
-export_type([req_body/0]).
-export_type([body/0]).
-export_type([response/0]).
-export_type([http_auth/0]).

-record(req, {
          method = ?get :: method_int(),
          url :: binary(),
          headers = [] :: headers(),
          cookiejar = [] :: cookiejar(),
          body = <<>> :: body(),
          connecttimeout_ms = ?DEFAULT_REQ_TIMEOUT :: pos_integer(),
          followlocation = ?FOLLOWLOCATION_FALSE :: integer(),
          ssl_verifyhost = ?SSL_VERIFYHOST_TRUE :: integer(),
          ssl_verifypeer = ?SSL_VERIFYPEER_TRUE :: integer(),
          capath = undefined :: undefined | binary(),
          timeout_ms = ?DEFAULT_REQ_TIMEOUT :: pos_integer(),
          maxredirs = 9 :: non_neg_integer(),
          timeout = ?DEFAULT_REQ_TIMEOUT :: pos_integer(),
          http_auth = undefined :: undefined | http_auth_int(),
          username = undefined :: undefined | binary(),
          password = undefined :: undefined | binary(),
	  proxy = undefined :: undefined | binary()
         }).

-spec get(url()) -> response().
get(Url) ->
    get(Url, #{}).

-spec get(url(), map()) -> response().
get(Url, Opts) ->
    req(Url, get, Opts).

-spec post(url()) -> response().
post(Url) ->
    post(Url, #{}).

-spec post(url(), map()) -> response().
post(Url, Opts) ->
    req(Url, post, Opts).

-spec put(url()) -> response().
put(Url) ->
    put(Url, #{}).

-spec put(url(), map()) -> response().
put(Url, Opts) ->
    req(Url, put, Opts).

-spec head(url()) -> response().
head(Url) ->
    head(Url, #{}).

-spec head(url(), map()) -> response().
head(Url, Opts) ->
    req(Url, head, Opts).

-spec options(url()) -> response().
options(Url) ->
    options(Url, #{}).

-spec options(url(), map()) -> response().
options(Url, Opts) ->
    req(Url, options, Opts).

-spec req(url(), method(), map()) -> response().
req(Url, Method, Opts)
  when is_binary(Url) andalso is_atom(Method) andalso is_map(Opts) ->
    case process_opts(Opts) of
        {ok, Req} ->
            Timeout = ?MODULE:get_timeout(Req),
            MethodInt = method_to_int(Method),
            Req2 = Req#req{url=Url, method=MethodInt, timeout=Timeout},
            Ts = os:timestamp(),
            Pid = get_worker(Url),
            Res = gen_server:call(Pid, Req2, infinity),
            TotalUs = timer:now_diff(os:timestamp(), Ts),
            process_metrics(Res, TotalUs);
        {error, _} = Error ->
            ErrorMetric = metric_name(error),
            quintana:notify_spiral(ErrorMetric, 1),
            Error
    end.

start_link(CurlOpts, WorkerId) when is_list(CurlOpts) andalso
                                    is_atom(WorkerId) ->
    gen_server:start_link({local, WorkerId}, ?MODULE, [CurlOpts, WorkerId], []).

init([CurlOpts, WorkerId]) ->
    process_flag(trap_exit, true),
    Args = get_mopts(CurlOpts),
    Prog = filename:join([code:priv_dir(katipo), "katipo"]),
    Port = open_port({spawn, Prog ++ " " ++ Args}, [{packet, 4}, binary]),
    true = gproc_pool:connect_worker(katipo, WorkerId),
    {ok, #state{port=Port, reqs=#{}}}.

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
                 timeout_ms = TimeoutMs,
                 maxredirs = MaxRedirs,
                 timeout = Timeout,
                 http_auth = HTTPAuth,
                 username = Username,
                 password = Password,
		 proxy = Proxy},
             From,
             State=#state{port=Port, reqs=Reqs}) ->
    {Self, Ref} = From,
    Opts = [{?connecttimeout_ms, ConnTimeoutMs},
            {?followlocation, FollowLocation},
            {?ssl_verifyhost, SslVerifyHost},
            {?ssl_verifypeer, SslVerifyPeer},
            {?capath, CAPath},
            {?timeout_ms, TimeoutMs},
            {?maxredirs, MaxRedirs},
            {?http_auth, HTTPAuth},
            {?username, Username},
            {?password, Password},
	    {?proxy, Proxy}],
    Command = {Self, Ref, Method, Url, Headers, CookieJar, Body, Opts},
    true = port_command(Port, term_to_binary(Command)),
    Tref = erlang:start_timer(Timeout, self(), {req_timeout, From}),
    Reqs2 = maps:put(From, Tref, Reqs),
    {noreply, State#state{reqs=Reqs2}}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({Port, {data, Data}}, State=#state{port=Port, reqs=Reqs}) ->
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
    {noreply, State#state{reqs=Reqs2}};
handle_info({timeout, Tref, {req_timeout, From}}, State=#state{reqs=Reqs}) ->
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
    {noreply, State#state{reqs=Reqs2}};
handle_info({'EXIT', Port, Reason}, State=#state{port=Port}) ->
    {stop, Reason, State}.

terminate(_Reason, #state{port=Port}) ->
    true = port_close(Port),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

-spec headers_to_binary(headers()) -> [binary()].
headers_to_binary(Headers) ->
    [iolist_to_binary([K, <<": ">>, V]) || {K, V} <- Headers].

method_to_int(get)     -> ?get;
method_to_int(post)    -> ?post;
method_to_int(put)     -> ?put;
method_to_int(head)    -> ?head;
method_to_int(options) -> ?options.

parse_headers([_StatusLine | Lines]) ->
    [parse_header(L) || L <- Lines].

parse_header(Line) when is_binary(Line) ->
    case binary:split(Line, <<": ">>, [trim]) of
        [K] -> {K, <<>>};
        [K, V] -> {K, V}
    end.

-spec encode_body(req_body()) -> body().
encode_body([{_, _}|_] = KVs) ->
    cow_qs:qs(KVs);
encode_body(Body) when is_binary(Body) ->
    Body;
encode_body(Body) when is_list(Body) ->
    iolist_to_binary(Body).

get_mopts(Opts) ->
    L = lists:filtermap(fun mopt_supported/1, Opts),
    string:join(L, " ").

-spec mopt_supported({curlmopt(), any()}) -> false | {true, any()}.
mopt_supported({max_pipeline_length, Val})
  when is_integer(Val) andalso Val >= 0 ->
    {true, "--max-pipeline-length " ++ integer_to_list(Val)};
mopt_supported({pipelining, true}) ->
    {true, "--pipelining"};
mopt_supported({_, _}) ->
    false.

-spec get_timeout(#req{}) -> pos_integer().
get_timeout(#req{connecttimeout_ms=ConnMs, timeout_ms=ReqMs}) ->
    max(ConnMs, ReqMs).

-spec process_metrics({ok | error, {map(), proplists:proplist()}}, non_neg_integer()) ->
                             response().
process_metrics({ok, {Response, Metrics}}, Total) ->
    #{status := Status} = Response,
    StatusMetric = status_metric_name(Status),
    quintana:notify_spiral(StatusMetric, 1),
    OkMetric = metric_name(ok),
    quintana:notify_spiral(OkMetric, 1),
    process_metrics_1(Metrics, Total),
    {ok, Response};
process_metrics({error, {Error, Metrics}}, Total) ->
    ErrorMetric = metric_name(error),
    quintana:notify_spiral(ErrorMetric, 1),
    process_metrics_1(Metrics, Total),
    {error, Error}.

metric_name(M) ->
    B = atom_to_binary(M, latin1),
    <<"katipo.", B/binary>>.

status_metric_name(Status) when is_integer(Status) ->
    B = integer_to_binary(Status),
    <<"katipo.status.", B/binary>>.

process_metrics_1(Metrics, Total) ->
    %% Curl metrics are in seconds
    Metrics1 = [{K, 1000 * V} || {K, V} <- Metrics],
    %% now_diff is in microsecs
    Total1 = Total / 1000.0,
    Metrics3 =
        case lists:keytake(total_time, 1, Metrics1) of
            {value, {total_time, CurlTotal}, Metrics2} ->
                [{curl_time, CurlTotal},
                 {total_time, Total1} | Metrics2];
            false ->
                [{total_time, Total1} | Metrics]
        end,
    Notify = fun({K, V}) ->
                     Name = metric_name(K),
                     ok = quintana:notify_histogram(Name, V)
             end,
    ok = lists:foreach(Notify, Metrics3).

opt(headers, Headers, {Req, Errors}) when is_list(Headers) ->
    {Req#req{headers=headers_to_binary(Headers)}, Errors};
opt(cookiejar, CookieJar, {Req, Errors}) when is_list(CookieJar) ->
    case lists:all(fun erlang:is_binary/1, CookieJar) of
        true ->
            {Req#req{cookiejar=CookieJar}, Errors};
        false ->
            {Req, [{cookiejar, CookieJar} | Errors]}
    end;
opt(body, Body, {Req, Errors}) ->
    {Req#req{body=encode_body(Body)}, Errors};
opt(connecttimeout_ms, Ms, {Req, Errors}) when is_integer(Ms) andalso Ms > 0 ->
    {Req#req{connecttimeout_ms=Ms}, Errors};
opt(followlocation, true, {Req, Errors}) ->
    {Req#req{followlocation=?FOLLOWLOCATION_TRUE}, Errors};
opt(followlocation, false, {Req, Errors}) ->
    {Req#req{followlocation=?FOLLOWLOCATION_FALSE}, Errors};
opt(ssl_verifyhost, true, {Req, Errors}) ->
    {Req#req{ssl_verifyhost=?SSL_VERIFYHOST_TRUE}, Errors};
opt(ssl_verifyhost, false, {Req, Errors}) ->
    {Req#req{ssl_verifyhost=?SSL_VERIFYHOST_FALSE}, Errors};
opt(ssl_verifypeer, true, {Req, Errors}) ->
    {Req#req{ssl_verifypeer=?SSL_VERIFYPEER_TRUE}, Errors};
opt(ssl_verifypeer, false, {Req, Errors}) ->
    {Req#req{ssl_verifypeer=?SSL_VERIFYPEER_FALSE}, Errors};
opt(capath, CAPath, {Req, Errors}) when is_binary(CAPath) ->
    {Req#req{capath=CAPath}, Errors};
opt(timeout_ms, Ms, {Req, Errors}) when is_integer(Ms) andalso Ms > 0 ->
    {Req#req{timeout_ms=Ms}, Errors};
opt(maxredirs, M, {Req, Errors}) when is_integer(M) andalso M >= -1 ->
    {Req#req{maxredirs=M}, Errors};
opt(http_auth, basic, {Req, Errors}) ->
    {Req#req{http_auth=?CURLAUTH_BASIC}, Errors};
opt(http_auth, digest, {Req, Errors}) ->
    {Req#req{http_auth=?CURLAUTH_DIGEST}, Errors};
opt(username, Username, {Req, Errors}) when is_binary(Username) ->
    {Req#req{username=Username}, Errors};
opt(password, Password, {Req, Errors}) when is_binary(Password) ->
    {Req#req{password=Password}, Errors};
opt(proxy, Proxy, {Req, Errors}) when is_binary(Proxy) ->
    {Req#req{proxy=Proxy}, Errors};
opt(K, V, {Req, Errors}) ->
    {Req, [{K, V} | Errors]}.

-spec process_opts(map()) -> {ok, #req{}} | {error, {bad_opts, [any()]}}. %%todo
process_opts(Opts) ->
    case maps:fold(fun opt/3, {#req{}, []}, Opts) of
        {Req=#req{}, []} ->
            {ok, Req};
        {#req{}, Errors} ->
            {error, {bad_opts, Errors}}
    end.

-spec get_worker(url()) -> pid().
get_worker(Url) ->
    Pid = case application:get_env(katipo, pool_type, round_robin) of
              round_robin ->
                  gproc_pool:pick_worker(katipo);
              hash ->
                  HostAndPort = host_and_port(Url),
                  gproc_pool:pick_worker(katipo, HostAndPort)
          end,
    case Pid of
        Pid when is_pid(Pid) ->
            Pid
    end.

host_and_port(Url) when is_binary(Url) ->
    UrlList = binary_to_list(Url),
    {ok, {_, _, Hostname, Port, _, _}} = uri:parse(UrlList),
    {Hostname, Port}.
