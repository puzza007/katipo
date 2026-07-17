-module(katipo_worker).

-moduledoc false.

%% The gen_server that owns a single libcurl C port. wpool runs one of these per
%% pool worker. At init it parses the pool's curl-multi options (get_mopts) into
%% the port's spawn arguments. Thereafter it marshals a validated #req{} to the
%% port, tracks in-flight requests, and delivers responses/timeouts/errors back
%% to sync callers and async reply_to processes. Factored out of katipo.
%%
%% Both sync requests and async registrations arrive as gen_server calls, so
%% dispatch failures (dead worker, port_command crash) surface to the caller
%% through the call monitor instead of vanishing with a cast. The response for
%% an async request still flows back asynchronously via the reply_to process.

-behaviour(gen_server).

-export([start_link/1]).
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-include("katipo_internal.hrl").

-record(state, {port :: port(),
                reqs = #{} :: map()}).

-type curlmopt() ::
        max_total_connections |
        max_concurrent_streams |
        pipelining.

start_link(CurlOpts) when is_list(CurlOpts) ->
    Args = [CurlOpts],
    gen_server:start_link(?MODULE, Args, []).

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

handle_call(Req = #req{}, From, State) ->
    {noreply, admit(From, sync, Req, State)};
handle_call({async_req, ReplyTo, UserRef, Req = #req{}, Obs}, _From, State) ->
    State2 = admit({self(), make_ref()}, {async, ReplyTo, UserRef, Obs}, Req, State),
    {reply, ok, State2}.

%% Register a request: hand it to the port, arm its timer, record it in Reqs.
%% send_to_port runs BEFORE the Reqs insert on purpose: if the port is
%% already closed, port_command's badarg crashes us while this request is
%% still unregistered, so terminate/2 sends nothing for it and the caller's
%% call monitor reports the death instead. Registering first would make
%% terminate AND the call monitor both report it. The insert and the reply
%% have no crash point between them, so an admitted request is always
%% exactly-once: either the ok/response reply or a worker_died notification.
admit(From, Kind, Req = #req{timeout = Timeout},
      State = #state{port = Port, reqs = Reqs}) ->
    send_to_port(Port, From, Req),
    Tref = erlang:start_timer(Timeout, self(), {req_timeout, From}),
    State#state{reqs = Reqs#{From => {Tref, Kind}}}.

handle_cast({cancel, UserRef}, State = #state{port = Port, reqs = Reqs}) ->
    %% Broadcast reaches every worker; only the one holding this request acts.
    Reqs2 = cancel_async(Port, UserRef, Reqs),
    {noreply, State#state{reqs = Reqs2}};
handle_cast(Msg, State) ->
    logger:error("Unexpected cast: ~p", [Msg]),
    {noreply, State}.

%% Deliver a completed response to a sync caller (via gen_server:reply) or an
%% async ReplyTo (via a flattened katipo_response/katipo_error message).
deliver(sync, From, Result, Response) ->
    gen_server:reply(From, {Result, Response});
deliver({async, ReplyTo, UserRef, Obs}, _From, Result, {ResponseMap, Metrics}) ->
    Tag = case Result of ok -> katipo_response; error -> katipo_error end,
    ReplyTo ! {Tag, UserRef, ResponseMap},
    katipo_span:finish_async(Obs, Result, ResponseMap, Metrics).

%% Deliver a request timeout to a sync caller or an async ReplyTo.
deliver_timeout(Kind, From) ->
    deliver_error(Kind, From, #{code => operation_timedout, message => <<>>}).

%% Deliver an error map to a sync caller (as a gen_server reply) or an async
%% reply_to (as a katipo_error message).
deliver_error(sync, From, Error) ->
    gen_server:reply(From, {error, {Error, []}});
deliver_error({async, ReplyTo, UserRef, Obs}, _From, Error) ->
    ReplyTo ! {katipo_error, UserRef, Error},
    katipo_span:finish_async(Obs, error, Error, []).

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
    _ = case maps:find(From, Reqs) of
        {ok, {Tref, Kind}} ->
            _ = erlang:cancel_timer(Tref),
            deliver(Kind, From, Result, Response);
        error ->
            ok
    end,
    Reqs2 = maps:remove(From, Reqs),
    {noreply, State#state{reqs = Reqs2}};
handle_info({timeout, Tref, {req_timeout, From}}, State = #state{reqs = Reqs}) ->
    Reqs2 =
        case maps:find(From, Reqs) of
            {ok, {Tref, Kind}} ->
                _ = deliver_timeout(Kind, From),
                maps:remove(From, Reqs);
            _ ->
                Reqs
        end,
    {noreply, State#state{reqs = Reqs2}};
handle_info({'EXIT', Port, Reason}, State = #state{port = Port}) ->
    logger:error("Port ~p died with reason: ~p", [Port, Reason]),
    {stop, port_died, State}.

terminate(_Reason, #state{port = Port, reqs = Reqs}) ->
    %% The worker is going away (typically because its port died) with
    %% requests still in flight. Sync callers are covered by their in-flight
    %% gen_server:call monitor, but an admitted async request was already
    %% replied `ok` and no monitor watches it, so push a worker_died error to
    %% each async reply_to before we exit -- otherwise those callers would
    %% block until their await/request timeout.
    maps:foreach(fun notify_worker_died/2, Reqs),
    %% port_close/1 raises badarg if the port is already dead (the common case
    %% when we get here via port death); ignore it -- we're terminating anyway.
    try port_close(Port)
    catch error:badarg -> ok
    end,
    ok.

notify_worker_died(From, {_Tref, {async, _, _, _} = Kind}) ->
    deliver_error(Kind, From, katipo_req:error_map(worker_died, <<>>));
notify_worker_died(_From, {_Tref, sync}) ->
    ok.

%% Cancel the async request with this user Ref, if this worker holds it: tell
%% the port to abort the transfer, cancel the timer, and drop the reqs entry so
%% no response is delivered.
cancel_async(Port, UserRef, Reqs) ->
    case find_async(UserRef, Reqs) of
        {ok, {Self, Ref} = From, Tref, Obs} ->
            _ = erlang:cancel_timer(Tref),
            Reqs2 = maps:remove(From, Reqs),
            %% port_command raises badarg if the port died and its 'EXIT'
            %% message is still queued behind this cancel. The transfer is
            %% gone either way, so the abort is best-effort -- crashing here
            %% would leave the request in Reqs and make terminate/2 send
            %% worker_died to a caller who cancelled.
            try port_command(Port, term_to_binary({Self, Ref, cancel}))
            catch error:badarg -> ok
            end,
            katipo_span:end_async(Obs),
            Reqs2;
        error ->
            Reqs
    end.

find_async(UserRef, Reqs) ->
    case [{From, Tref, Obs}
          || From := {Tref, {async, _ReplyTo, UR, Obs}} <- Reqs, UR =:= UserRef] of
        [{From, Tref, Obs} | _] -> {ok, From, Tref, Obs};
        [] -> error
    end.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

send_to_port(Port, {Self, Ref},
             #req{method = Method,
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
                  http_auth = HTTPAuth,
                  username = Username,
                  password = Password,
                  proxy = Proxy,
                  tcp_fastopen = TCPFastOpen,
                  interface = Interface,
                  unix_socket_path = UnixSocketPath,
                  doh_url = DOHURL,
                  http_version = HTTPVersion,
                  sslversion = SSLVersion,
                  verbose = Verbose,
                  sslcert = SSLCert,
                  sslkey = SSLKey,
                  sslkey_blob = SSLKeyBlob,
                  keypasswd = KeyPasswd,
                  userpwd = UserPwd,
                  dns_cache_timeout = DNSCacheTimeout,
                  ca_cache_timeout = CACacheTimeout,
                  pipewait = Pipewait}) ->
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
            {?DOH_URL, DOHURL},
            {?HTTP_VERSION, HTTPVersion},
            {?SSLVERSION, SSLVersion},
            {?VERBOSE, Verbose},
            {?SSLCERT, SSLCert},
            {?SSLKEY, SSLKey},
            {?SSLKEY_BLOB, SSLKeyBlob},
            {?KEYPASSWD, KeyPasswd},
            {?USERPWD, UserPwd},
            {?DNS_CACHE_TIMEOUT, DNSCacheTimeout},
            {?CA_CACHE_TIMEOUT, CACacheTimeout},
            {?PIPEWAIT, Pipewait}],
    Command = {Self, Ref, Method, Url, Headers, CookieJar, Body, Opts},
    true = port_command(Port, term_to_binary(Command)).

-spec parse_headers([binary()]) -> katipo:headers().
parse_headers([_StatusLine | Lines]) ->
    [parse_header(L) || L <- Lines].

-spec parse_header(binary()) -> katipo:header().
parse_header(Line) when is_binary(Line) ->
    case binary:split(Line, <<": ">>, [trim]) of
        [K] -> {K, <<>>};
        [K, V] -> {K, V}
    end.

get_mopts(Opts) ->
    L = lists:filtermap(fun mopt_supported/1, Opts),
    LengthOpts = length(Opts),
    case length(L) of
        LengthOpts ->
            {ok, string:join(L, " ")};
        _ ->
            {error, {bad_opts, Opts}}
    end.

-spec mopt_supported({curlmopt(), any()}) -> false | {true, string()}.
mopt_supported({pipelining, nothing}) ->
    {true, "--pipelining 0"};
mopt_supported({pipelining, http1}) ->
    {true, "--pipelining 1"};
mopt_supported({pipelining, multiplex}) ->
    {true, "--pipelining 2"};
mopt_supported({max_total_connections, Val})
  when is_integer(Val) andalso Val >= 0 ->
    {true, "--max-total-connections " ++ integer_to_list(Val)};
mopt_supported({max_concurrent_streams, Val})
  when is_integer(Val) andalso Val >= 0 ->
    {true, "--max-concurrent-streams " ++ integer_to_list(Val)};
mopt_supported({_, _}) ->
    false.
