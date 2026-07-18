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
                reqs = #{} :: map(),
                max_in_flight = infinity :: pos_integer() | infinity}).

-type curlmopt() ::
        max_total_connections |
        max_concurrent_streams |
        maxconnects |
        pipelining.

start_link([MaxInFlight, CurlOpts]) when is_list(CurlOpts) ->
    gen_server:start_link(?MODULE, [MaxInFlight, CurlOpts], []).

init([MaxInFlight, CurlOpts]) ->
    process_flag(trap_exit, true),
    case get_mopts(CurlOpts) of
        {ok, Args} ->
            Prog = filename:join([code:priv_dir(katipo), "katipo"]),
            Port = open_port({spawn, Prog ++ " " ++ Args}, [{packet, 4}, binary]),
            {ok, #state{port = Port, reqs = #{}, max_in_flight = MaxInFlight}};
        {error, Error} ->
            {stop, Error}
    end.

%% Admission is gated on max_in_flight: a full worker replies
%% {overload, self()} without registering anything, and pool_call in katipo
%% offers the request to the remaining workers.
handle_call(Msg, From, State) ->
    case at_capacity(State) of
        true ->
            {reply, {overload, self()}, State};
        false ->
            admit_call(Msg, From, State)
    end.

admit_call(Req = #req{}, From, State) ->
    {noreply, admit(From, sync, Req, State)};
admit_call({async_req, ReplyTo, Req = #req{}, Obs}, _From, State) ->
    %% The user-facing Ref is a process alias, so cancel/flow commands are
    %% plain sends to the Ref itself: they route straight to this worker,
    %% and once the alias dies (with us) or is deactivated (on resolution)
    %% the runtime drops them -- the documented best-effort no-op. Doubling
    %% it as the ref in the port identity makes command handling a direct
    %% map lookup on {self(), Ref}.
    Alias = alias(),
    State2 = admit({self(), Alias}, {async, ReplyTo, Obs}, Req, State),
    {reply, Alias, State2}.

at_capacity(#state{max_in_flight = infinity}) ->
    false;
at_capacity(#state{reqs = Reqs, max_in_flight = Max}) ->
    maps:size(Reqs) >= Max.

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

handle_cast(Msg, State) ->
    logger:error("Unexpected cast: ~p", [Msg]),
    {noreply, State}.

%% One decoded message from the C port. Terminal messages ({ok, ...},
%% {error, ...}, {done, ...}) resolve the request: cancel its timer, deliver,
%% and drop it from Reqs. Streaming progress messages ({headers, ...},
%% {chunk, ...}) are forwarded to the async reply_to and leave the request in
%% flight. Any message whose From is no longer in Reqs is dropped silently --
%% the request timed out, was cancelled, or already completed.
handle_port_msg({ok, {From, {Status, Headers, CookieJar, Body, Metrics}}}, Reqs) ->
    R = #{status => Status,
          headers => parse_headers(Headers),
          cookiejar => CookieJar,
          body => Body},
    finish_req(From, ok, {R, Metrics}, Reqs);
handle_port_msg({error, {From, {Code, Message, Metrics}}}, Reqs) ->
    Error = #{code => Code, message => Message},
    finish_req(From, error, {Error, Metrics}, Reqs);
handle_port_msg({headers, {From, {Status, Headers}}}, Reqs) ->
    forward_progress(From, Reqs,
                     fun(UserRef) ->
                             {katipo_headers, UserRef,
                              #{status => Status,
                                headers => parse_headers(Headers)}}
                     end);
handle_port_msg({chunk, {From, Body}}, Reqs) ->
    forward_progress(From, Reqs,
                     fun(UserRef) -> {katipo_chunk, UserRef, Body} end);
handle_port_msg({done, {From, {Status, CookieJar, Metrics}}}, Reqs) ->
    Done = #{status => Status, cookiejar => CookieJar},
    finish_req(From, done, {Done, Metrics}, Reqs).

%% Progress messages forward to the async reply_to iff the request is still
%% in flight; otherwise they are dropped silently (the request timed out,
%% was cancelled, or already completed). The message is only built when it
%% will be sent.
forward_progress(From = {_Self, UserRef}, Reqs, BuildMsg) ->
    _ = case maps:find(From, Reqs) of
            {ok, {_Tref, {async, ReplyTo, _Obs}}} ->
                ReplyTo ! BuildMsg(UserRef);
            _ ->
                ok
        end,
    Reqs.

%% Resolve a request with its terminal result, if it is still in flight.
finish_req(From, Result, Response, Reqs) ->
    case maps:take(From, Reqs) of
        {{Tref, Kind}, Rest} ->
            _ = erlang:cancel_timer(Tref),
            deliver(Kind, From, Result, Response),
            deactivate(From, Kind),
            Rest;
        error ->
            Reqs
    end.

%% Deactivate a resolved async request's alias (the ref in its From key) so
%% late cancel/flow sends are dropped by the runtime instead of landing in
%% our mailbox.
deactivate({_Self, Alias}, {async, _ReplyTo, _Obs}) ->
    _ = unalias(Alias),
    ok;
deactivate(_From, sync) ->
    ok.

%% Deliver a terminal outcome to a sync caller (via gen_server:reply) or an
%% async ReplyTo (via a flattened katipo_response/katipo_error/katipo_done
%% message). `done` only occurs for streaming requests, which are async by
%% construction.
deliver({async, ReplyTo, Obs}, {_Self, UserRef}, done, {DoneMap, Metrics}) ->
    ReplyTo ! {katipo_done, UserRef, DoneMap},
    katipo_span:finish_async(Obs, ok, DoneMap, Metrics);
deliver(sync, From, Result, Response) ->
    gen_server:reply(From, {Result, Response});
deliver({async, ReplyTo, Obs}, {_Self, UserRef}, Result, {ResponseMap, Metrics}) ->
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
deliver_error({async, ReplyTo, Obs}, {_Self, UserRef}, Error) ->
    ReplyTo ! {katipo_error, UserRef, Error},
    katipo_span:finish_async(Obs, error, Error, []).

handle_info({Port, {data, Data}}, State = #state{port = Port, reqs = Reqs}) ->
    Reqs2 = handle_port_msg(binary_to_term(Data), Reqs),
    {noreply, State#state{reqs = Reqs2}};
handle_info({timeout, Tref, {req_timeout, From}},
            State = #state{port = Port, reqs = Reqs}) ->
    Reqs2 =
        case maps:take(From, Reqs) of
            {{Tref, Kind}, Rest} ->
                _ = deliver_timeout(Kind, From),
                deactivate(From, Kind),
                %% Abort the transfer still running in the C port: its
                %% eventual output would be dropped anyway now that the
                %% request is out of Reqs.
                abort_transfer(Port, From),
                Rest;
            error ->
                Reqs
        end,
    {noreply, State#state{reqs = Reqs2}};
handle_info({cancel, Ref}, State = #state{port = Port, reqs = Reqs}) ->
    %% Sent directly to the request's alias by katipo:cancel/2; a stale or
    %% foreign Ref cannot match a live entry. Async entries are keyed by
    %% {self(), Alias}, so this is a straight lookup.
    From = {self(), Ref},
    Reqs2 =
        case maps:take(From, Reqs) of
            {{Tref, Kind = {async, _ReplyTo, Obs}}, Rest} ->
                _ = erlang:cancel_timer(Tref),
                deactivate(From, Kind),
                abort_transfer(Port, From),
                katipo_span:end_async(Obs),
                Rest;
            error ->
                Reqs
        end,
    {noreply, State#state{reqs = Reqs2}};
handle_info({flow, Ref, N}, State = #state{port = Port, reqs = Reqs}) ->
    %% Sent directly to the request's alias by katipo:update_flow/3.
    From = {Self = self(), Ref},
    _ = case is_map_key(From, Reqs) of
            true -> port_cmd(Port, {Self, Ref, flow, N});
            false -> ok
        end,
    {noreply, State};
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

notify_worker_died(From, {_Tref, {async, _, _} = Kind}) ->
    deliver_error(Kind, From, katipo_req:error_map(worker_died, <<>>));
notify_worker_died(_From, {_Tref, sync}) ->
    ok.

%% Ask the C port to abort the in-flight transfer identified by {Pid, Ref}
%% (a no-op there if it already completed).
abort_transfer(Port, {Pid, Ref}) ->
    port_cmd(Port, {Pid, Ref, cancel}).

%% Best-effort port write: port_command raises badarg if the port died and
%% its 'EXIT' message is still queued behind us; whatever we were telling the
%% port is moot then, and crashing here would let terminate/2 message callers
%% that have already been dealt with.
port_cmd(Port, Tuple) ->
    try port_command(Port, term_to_binary(Tuple))
    catch error:badarg -> ok
    end,
    ok.

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
                  pipewait = Pipewait,
                  stream = Stream,
                  stream_window = StreamWindow}) ->
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
            {?PIPEWAIT, Pipewait},
            {?STREAM, Stream},
            {?STREAM_WINDOW, StreamWindow}],
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
mopt_supported({maxconnects, Val})
  when is_integer(Val) andalso Val >= 0 ->
    {true, "--maxconnects " ++ integer_to_list(Val)};
mopt_supported({_, _}) ->
    false.
