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
%% For the raw-port tests, which read the C port without a worker.
-export([decode/1]).

-include("katipo_internal.hrl").

%% The {Pid, Ref} a transfer is known by in the C port.
-type port_id() :: {pid(), reference()}.

%% A request in flight, under the key its caller knows it by: From for a
%% sync request, {self(), Alias} for an async one. It holds the timer that
%% bounds the current attempt, or the backoff before the next; where its
%% outcome goes (sync, or {async, ReplyTo, Obs}); the port_id of its
%% current transfer, or `backoff' between attempts; and, only for a
%% request with a retry policy, the request itself and the number of
%% retries sent so far. The first transfer's port_id is the key itself;
%% each retry's is fresh, so that output from an attempt that was given up
%% on can never be taken for the current one's.
-record(inflight, {tref :: reference(),
                   kind :: sync | {async, pid(), katipo_span:obs()},
                   port_id :: port_id() | backoff,
                   req :: undefined | #req{},
                   retries = 0 :: non_neg_integer()}).

-record(state, {port :: port(),
                reqs = #{} :: map(),
                %% The key of each request whose port_id is not the key.
                ids = #{} :: #{port_id() => port_id()},
                max_in_flight = infinity :: pos_integer() | infinity}).

-type curlmopt() ::
        max_total_connections |
        max_concurrent_streams |
        pipelining.

start_link([MaxInFlight, CurlOpts]) when is_list(CurlOpts) ->
    gen_server:start_link(?MODULE, [MaxInFlight, CurlOpts], []).

init([MaxInFlight, CurlOpts]) ->
    process_flag(trap_exit, true),
    case get_mopts(CurlOpts) of
        {ok, Args} ->
            Prog = filename:join([code:priv_dir(katipo), "katipo"]),
            Port = open_port({spawn, Prog ++ " " ++ Args}, [{packet, 4}, binary]),
            ?TRACE(start),
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
            ?TRACE({overload, Msg}),
            {reply, {overload, self()}, State};
        false ->
            admit_call(Msg, From, State)
    end.

admit_call(Req = #req{}, From, State = #state{port = Port}) ->
    true = port_command(Port, command(From, Req)),
    {noreply, register_req(From, sync, Req, State)};
admit_call({async_req, ReplyTo, Req = #req{}, Obs, Deadline}, _From,
           State = #state{port = Port}) ->
    %% The user-facing Ref is a process alias, so cancel/flow commands are
    %% plain sends to the Ref itself: they route straight to this worker,
    %% and once the alias dies (with us) or is deactivated (on resolution)
    %% the runtime drops them -- the documented best-effort no-op. Doubling
    %% it as the ref in the port identity makes command handling a direct
    %% map lookup on {self(), Ref}.
    %%
    %% The deadline is checked twice: before the port write (the usual
    %% stale case -- a backed-up mailbox -- never reaches the port) and
    %% after it, since port_command itself can block past the deadline when
    %% the C side stops draining its pipe; the just-sent transfer is then
    %% aborted. Either way nothing is registered and the reply is dropped
    %% with the caller's expired call alias. See katipo:stamp/2.
    ?TRACE({clock, Deadline}),
    case past(Deadline) of
        true ->
            ?TRACE(pre_refused),
            {reply, expired, State};
        false ->
            ?TRACE(sending),
            Alias = alias(),
            From = {self(), Alias},
            true = port_command(Port, command(From, Req)),
            ?TRACE({clock, Deadline}),
            case past(Deadline) of
                true ->
                    ?TRACE({post_refused, Alias}),
                    _ = unalias(Alias),
                    abort_transfer(Port, From),
                    {reply, expired, State};
                false ->
                    ?TRACE({admitted, Alias}),
                    {reply, Alias,
                     register_req(From, {async, ReplyTo, Obs}, Req, State)}
            end
    end.

past(Deadline) ->
    erlang:monotonic_time(millisecond) >= Deadline.

at_capacity(#state{max_in_flight = infinity}) ->
    false;
at_capacity(#state{reqs = Reqs, max_in_flight = Max}) ->
    maps:size(Reqs) >= Max.

%% Register a request already handed to the port: arm its timer, record it
%% in Reqs. The port_command runs BEFORE this on purpose: if the port is already
%% closed, port_command's badarg crashes us while this request is still
%% unregistered, so terminate/2 sends nothing for it and the caller's call
%% monitor reports the death instead. Registering first would make terminate
%% AND the call monitor both report it. The insert and the reply have no
%% crash point between them, so an admitted request is always exactly-once:
%% either the ok/response reply or a worker_died notification.
register_req(From, Kind, Req = #req{timeout = Timeout, retry = Retry},
             State = #state{reqs = Reqs}) ->
    Tref = erlang:start_timer(Timeout, self(), {req_timeout, From}),
    Kept = case Retry of undefined -> undefined; _ -> Req end,
    State#state{reqs = Reqs#{From => #inflight{tref = Tref, kind = Kind,
                                               port_id = From, req = Kept}}}.

handle_cast(Msg, State) ->
    logger:error("Unexpected cast: ~p", [Msg]),
    {noreply, State}.

%% One decoded message from the C port, for the transfer it names.
%% Terminal messages ({ok, ...}, {error, ...}, {done, ...}) end the
%% attempt: the request is retried or resolved (attempt_ended/4).
%% Streaming progress messages ({headers, ...}, {chunk, ...}) are forwarded
%% to the async reply_to and leave the request in flight. Any message for a
%% transfer that is not a request's current one is dropped silently -- the
%% request timed out, was cancelled, already completed, or has moved on to
%% another attempt.
handle_port_msg({ok, {PortId, {Status, Headers, CookieJar, Body, Metrics}}}, State) ->
    R = #{status => Status,
          headers => parse_headers(Headers),
          cookiejar => CookieJar,
          body => Body},
    attempt_ended(PortId, ok, {R, Metrics}, State);
handle_port_msg({error, {PortId, {Code, Message, Metrics}}}, State) ->
    Error = #{code => Code, message => Message},
    attempt_ended(PortId, error, {Error, Metrics}, State);
handle_port_msg({headers, {PortId, {Status, Headers}}}, State) ->
    forward_progress(PortId, State,
                     fun(UserRef) ->
                             {katipo_headers, UserRef,
                              #{status => Status,
                                headers => parse_headers(Headers)}}
                     end);
handle_port_msg({demand, {PortId, []}}, State) ->
    forward_progress(PortId, State,
                     fun(UserRef) -> {katipo_body_demand, UserRef} end);
handle_port_msg({chunk, {PortId, Body}}, State) ->
    forward_progress(PortId, State,
                     fun(UserRef) -> {katipo_chunk, UserRef, Body} end);
handle_port_msg({done, {PortId, {Status, CookieJar, Metrics}}}, State) ->
    Done = #{status => Status, cookiejar => CookieJar},
    attempt_ended(PortId, done, {Done, Metrics}, State).

%% The request whose current transfer is PortId, as {Key, Entry}.
current(PortId, #state{reqs = Reqs, ids = Ids}) ->
    Key = maps:get(PortId, Ids, PortId),
    case Reqs of
        #{Key := Entry = #inflight{port_id = PortId}} -> {Key, Entry};
        _ -> error
    end.

%% Decode one port frame. An ok or chunk frame is a body frame: its term
%% has an empty-binary placeholder for the body, whose raw bytes follow the
%% term. Keeping the body out of the term lets it be a sub-binary of the
%% frame, where binary_to_term would copy it; `used' says where it starts.
-spec decode(binary()) -> term().
decode(Data) ->
    case binary_to_term(Data, [used]) of
        {{ok, {From, {Status, Headers, CookieJar, <<>>, Metrics}}}, Used} ->
            {ok, {From, {Status, Headers, CookieJar, body(Data, Used), Metrics}}};
        {{chunk, {From, <<>>}}, Used} ->
            {chunk, {From, body(Data, Used)}};
        {Msg, _Used} ->
            Msg
    end.

body(Data, Used) ->
    <<_:Used/binary, Body/binary>> = Data,
    own_body(Body, Data).

%% A sub-binary keeps the whole frame alive for as long as the caller holds
%% the body, so it is only worth it when the body is most of the frame. A
%% small body under a large header block is copied out instead, which is
%% cheap precisely because it is small.
own_body(Body, Frame) when byte_size(Body) * 2 >= byte_size(Frame) ->
    Body;
own_body(Body, _Frame) ->
    binary:copy(Body).

%% Progress messages forward to the async reply_to iff the transfer is
%% its request's current one; otherwise they are dropped silently (the
%% request timed out, was cancelled, or already completed). The message is
%% only built when it will be sent.
forward_progress(PortId, State, BuildMsg) ->
    _ = case current(PortId, State) of
            {Key = {_Self, UserRef}, #inflight{kind = {async, ReplyTo, _Obs}}} ->
                ReplyTo ! BuildMsg(UserRef),
                ?TRACE({progress, Key, forwarded});
            _ ->
                ?TRACE({progress, PortId, dropped})
        end,
    State.

%% A transfer ended with its terminal result. If it is its request's
%% current one, the request is retried or resolved.
attempt_ended(PortId, Result, Response, State) ->
    case current(PortId, State) of
        {Key, Entry = #inflight{tref = Tref}} ->
            _ = erlang:cancel_timer(Tref),
            retry_or_resolve(Key, Entry, Result, Response, State);
        error ->
            ?TRACE({terminal, PortId, dropped}),
            State
    end.

%% Wait and send the request again if its retry policy says to, else
%% resolve it with this result.
retry_or_resolve(Key, Entry = #inflight{kind = Kind, port_id = PortId},
                 Result, Response, State = #state{reqs = Reqs, ids = Ids}) ->
    Ids2 = maps:remove(PortId, Ids),
    case retry_delay(Entry, Result, Response) of
        {ok, Delay} ->
            Tref = erlang:start_timer(Delay, self(), {retry, Key}),
            State#state{reqs = Reqs#{Key := Entry#inflight{tref = Tref,
                                                           port_id = backoff}},
                        ids = Ids2};
        none ->
            deliver(Kind, Key, Result, Response),
            deactivate(Key, Kind),
            State#state{reqs = maps:remove(Key, Reqs), ids = Ids2}
    end.

retry_delay(#inflight{req = undefined}, _Result, _Response) ->
    none;
retry_delay(#inflight{req = #req{retry = Policy}, retries = Retries},
            Result, {ResponseMap, _Metrics}) ->
    katipo_retry:delay(Policy, Retries, Result, ResponseMap, os:system_time(second)).

%% Send the request in backoff under Key again, as a fresh transfer. A
%% failed write means the port has died, and its 'EXIT' will stop us.
retry(Key, State = #state{port = Port, reqs = Reqs, ids = Ids}) ->
    Entry = #inflight{req = Req, retries = Retries} = maps:get(Key, Reqs),
    PortId = {self(), make_ref()},
    port_cmd(Port, command(PortId, Req)),
    Tref = erlang:start_timer(Req#req.timeout, self(), {req_timeout, Key}),
    State#state{reqs = Reqs#{Key := Entry#inflight{tref = Tref, port_id = PortId,
                                                   retries = Retries + 1}},
                ids = Ids#{PortId => Key}}.

%% Drop the request in backoff under Key, whose outcome would go to a
%% process that has died: there is nobody to send it again for.
drop(Key, State = #state{reqs = Reqs}) ->
    {#inflight{kind = Kind}, Rest} = maps:take(Key, Reqs),
    ?TRACE({retry, Key, owner_dead}),
    deactivate(Key, Kind),
    _ = case Kind of
            {async, _ReplyTo, Obs} -> katipo_span:end_async(Obs);
            sync -> ok
        end,
    State#state{reqs = Rest}.

%% The process a request's outcome goes to.
owner({Caller, _Tag}, sync) -> Caller;
owner(_Key, {async, ReplyTo, _Obs}) -> ReplyTo.

%% is_process_alive/1 only answers for a local process; a remote one is
%% taken to be alive.
alive(Pid) when node(Pid) =:= node() -> is_process_alive(Pid);
alive(_Pid) -> true.

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
deliver({async, ReplyTo, Obs}, From = {_Self, UserRef}, done, {DoneMap, Metrics}) ->
    ReplyTo ! {katipo_done, UserRef, DoneMap},
    ?TRACE({delivered, From}),
    katipo_span:finish_async(Obs, ok, DoneMap, Metrics);
deliver(sync, From, Result, Response) ->
    gen_server:reply(From, {Result, Response});
deliver({async, ReplyTo, Obs}, From = {_Self, UserRef}, Result, {ResponseMap, Metrics}) ->
    Tag = case Result of ok -> katipo_response; error -> katipo_error end,
    ReplyTo ! {Tag, UserRef, ResponseMap},
    ?TRACE({delivered, From}),
    katipo_span:finish_async(Obs, Result, ResponseMap, Metrics).

%% Deliver an error map to an async reply_to as a katipo_error message.
deliver_error({async, ReplyTo, Obs}, From = {_Self, UserRef}, Error) ->
    ReplyTo ! {katipo_error, UserRef, Error},
    ?TRACE({delivered, From}),
    katipo_span:finish_async(Obs, error, Error, []).

handle_info({Port, {data, Data}}, State = #state{port = Port}) ->
    {noreply, handle_port_msg(decode(Data), State)};
handle_info({timeout, Tref, {req_timeout, Key}},
            State = #state{port = Port, reqs = Reqs}) ->
    case Reqs of
        #{Key := Entry = #inflight{tref = Tref, port_id = PortId}} ->
            %% Abort the transfer still running in the C port: its eventual
            %% output would be dropped anyway, as the request no longer has
            %% it as its current transfer.
            abort_transfer(Port, PortId),
            Timeout = #{code => operation_timedout, message => <<>>},
            {noreply, retry_or_resolve(Key, Entry, error, {Timeout, []}, State)};
        _ ->
            ?TRACE({terminal, Key, dropped}),
            {noreply, State}
    end;
handle_info({timeout, Tref, {retry, Key}}, State = #state{reqs = Reqs}) ->
    case Reqs of
        #{Key := #inflight{tref = Tref, kind = Kind}} ->
            case alive(owner(Key, Kind)) of
                true -> {noreply, retry(Key, State)};
                false -> {noreply, drop(Key, State)}
            end;
        _ ->
            {noreply, State}
    end;
handle_info({cancel, Ref}, State = #state{port = Port, reqs = Reqs, ids = Ids}) ->
    %% Sent directly to the request's alias by katipo:cancel/2; a stale or
    %% foreign Ref cannot match a live entry. Async entries are keyed by
    %% {self(), Alias}, so this is a straight lookup.
    Key = {self(), Ref},
    case maps:take(Key, Reqs) of
        {#inflight{tref = Tref, kind = Kind = {async, _ReplyTo, Obs},
                   port_id = PortId}, Rest} ->
            ?TRACE({cancel, Key, effective}),
            _ = erlang:cancel_timer(Tref),
            deactivate(Key, Kind),
            abort_transfer(Port, PortId),
            katipo_span:end_async(Obs),
            {noreply, State#state{reqs = Rest, ids = maps:remove(PortId, Ids)}};
        error ->
            ?TRACE({cancel, Key, noop}),
            {noreply, State}
    end;
handle_info({flow, Ref, N}, State) ->
    %% Sent directly to the request's alias by katipo:update_flow/3.
    relay(Ref, flow, N, State);
handle_info({send_body, Ref, Data}, State) ->
    %% Sent directly to the request's alias by katipo:send_body/3.
    relay(Ref, body, Data, State);
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
    ?TRACE(terminate),
    maps:foreach(fun notify_worker_died/2, Reqs),
    %% port_close/1 raises badarg if the port is already dead (the common case
    %% when we get here via port death); ignore it -- we're terminating anyway.
    try port_close(Port)
    catch error:badarg -> ok
    end,
    ok.

notify_worker_died(From, #inflight{kind = {async, _, _} = Kind}) ->
    deliver_error(Kind, From, katipo_req:error_map(worker_died, <<>>));
notify_worker_died(_From, #inflight{kind = sync}) ->
    ok.

%% Ask the C port to abort the in-flight transfer identified by {Pid, Ref}
%% (a no-op there if it already completed). Between attempts there is none.
abort_transfer(Port, {Pid, Ref}) ->
    port_cmd(Port, term_to_binary({Pid, Ref, cancel}));
abort_transfer(_Port, backoff) ->
    ok.

%% Pass a caller's command for one of our requests to the port; one for a
%% request that has finished is dropped. A body chunk goes after the term,
%% whose own element is an empty-binary placeholder, so it is neither
%% copied into the term nor decoded by the port: the mirror of decode/1.
relay(Ref, Tag, Arg, State = #state{port = Port, reqs = Reqs}) ->
    Self = self(),
    _ = case is_map_key({Self, Ref}, Reqs) of
            true when Tag =:= body, Arg =/= eof ->
                port_cmd(Port, [term_to_binary({Self, Ref, body, <<>>}), Arg]);
            true ->
                port_cmd(Port, term_to_binary({Self, Ref, Tag, Arg}));
            false ->
                ok
        end,
    {noreply, State}.

%% Best-effort port write: port_command raises badarg if the port died and
%% its 'EXIT' message is still queued behind us; whatever we were telling the
%% port is moot then, and crashing here would let terminate/2 message callers
%% that have already been dealt with.
port_cmd(Port, Frame) ->
    try port_command(Port, Frame)
    catch error:badarg -> ok
    end,
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% The port command that starts a transfer of Req under {Self, Ref}.
command({Self, Ref},
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
    term_to_binary({Self, Ref, Method, Url, Headers, CookieJar, Body, Opts}).

-spec parse_headers([binary()]) -> katipo:resp_headers().
parse_headers([]) ->
    [];
parse_headers([_StatusLine | Lines]) ->
    Colon = binary:compile_pattern(<<":">>),
    [parse_header(L, Colon) || L <- unfold(Lines)].

%% RFC 9112 5.2: a line starting with SP or HTAB continues the previous
%% field's value (obs-fold), and a recipient may replace the fold with a
%% single SP. Newer libcurl unfolds before handing lines over; older
%% versions (8.5, for one) pass the continuation through as a line of its
%% own, which would otherwise become a header whose name is the text.
unfold([Line, <<C, _/binary>> = Next | Rest]) when C =:= $\s; C =:= $\t ->
    unfold([<<(rtrim_ows(Line, byte_size(Line)))/binary, " ",
              (trim_ows(Next))/binary>> | Rest]);
unfold([Line | Rest]) ->
    [Line | unfold(Rest)];
unfold([]) ->
    [].

%% RFC 9110: field-name ":" OWS field-value OWS, where OWS is any run of
%% spaces and tabs -- possibly none. libcurl passes HTTP/1.1 lines through
%% verbatim, so "name:value" and padded values do occur. OWS is octets, so
%% it is trimmed byte-wise rather than with string:trim, whose grapheme
%% handling dominated the cost of a response with many headers.
-spec parse_header(binary(), binary:cp()) -> katipo:resp_header().
parse_header(Line, Colon) ->
    case binary:split(Line, Colon) of
        [K] -> {K, <<>>};
        [K, V] -> {K, trim_ows(V)}
    end.

trim_ows(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t ->
    trim_ows(Rest);
trim_ows(V) ->
    rtrim_ows(V, byte_size(V)).

rtrim_ows(V, N) when N > 0 ->
    case binary:at(V, N - 1) of
        C when C =:= $\s; C =:= $\t -> rtrim_ows(V, N - 1);
        _ -> binary:part(V, 0, N)
    end;
rtrim_ows(_V, 0) ->
    <<>>.

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
