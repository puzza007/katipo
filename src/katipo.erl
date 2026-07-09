-module(katipo).
-moduledoc """
An HTTP/HTTP2/HTTP3 client library for Erlang built around libcurl-multi and libevent.

## Quick Start

```erlang
{ok, _} = application:ensure_all_started(katipo).
{ok, _} = katipo_pool:start(my_pool, 2, [{pipelining, multiplex}]).
{ok, #{status := 200, body := Body}} = katipo:get(my_pool, <<"https://example.com">>).
```

## Request Options

Options can be passed as the third argument to HTTP method functions, or included
directly in the request map passed to `req/2`.

See `t:opts/0` for all available options and `t:request/0` for the full request map type.

## Responses

Synchronous request functions return `t:response/0`:

```erlang
{ok, #{status := pos_integer(), headers := headers(), cookiejar := cookiejar(), body := body()}}
{error, #{code := error_code(), message := error_msg()}}
```

## Async Requests

Async functions (`async_get/2,3`, `async_req/2`, etc.) return `{ok, Ref}` immediately
and deliver the response as a message to the calling process (or the pid specified
by the `reply_to` option):

```erlang
{katipo_response, Ref, #{status := pos_integer(), headers := headers(), ...}}
{katipo_error, Ref, #{code := error_code(), message := error_msg()}}
```

Use `await/1,2` to block until the response arrives, or `cancel/2` to abort an
in-flight request (no response is then delivered).

If the pool worker handling an in-flight async request dies (e.g. its port
crashes), a `{katipo_error, Ref, #{code => worker_died}}` message is delivered
so the caller fails fast instead of blocking until the request timeout.

Async requests emit the same OTel span (`HTTP <METHOD>`, parented to the
caller's context) and metrics as their synchronous counterparts; the span
covers the full request and is finished when the response, a timeout, or a
worker failure arrives.
""".

-compile({no_auto_import, [put/2]}).

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

-export([async_req/2]).
-export([async_get/2]).
-export([async_get/3]).
-export([async_post/2]).
-export([async_post/3]).
-export([async_put/2]).
-export([async_put/3]).
-export([async_head/2]).
-export([async_head/3]).
-export([async_options/2]).
-export([async_options/3]).
-export([async_patch/2]).
-export([async_patch/3]).
-export([async_delete/2]).
-export([async_delete/3]).
-export([await/1]).
-export([await/2]).
-export([cancel/2]).

-export([check_opts/1]).

%% only for mocking during tests

-export([tcp_fastopen_available/0]).
-export([unix_socket_path_available/0]).
-export([doh_url_available/0]).
-export([sslkey_blob_available/0]).
-export([http3_available/0]).

-include("katipo_internal.hrl").

-type method() :: get | post | put | head | options | patch | delete.
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
        http2_stream |
        recursive_api_call |
        auth_error |
        http3 |
        proxy |
        ssl_clientcert |
        quic_connect_error |
        unrecoverable_poll |
        too_large |
        ech_required |
        curl_last |
        %% returned by us, not curl
        bad_opts |
        await_timeout |
        worker_died.

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
                    reply_to => pid(),
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
                    tcp_fastopen => tcp_fastopen(),
                    interface => interface(),
                    unix_socket_path => unix_socket_path(),
                    doh_url => doh_url(),
                    http_version => curlopt_http_version(),
                    sslversion => curlopt_sslversion(),
                    verbose => boolean(),
                    sslcert => sslcert(),
                    sslkey => sslkey(),
                    sslkey_blob => sslkey_blob(),
                    userpwd => userpwd(),
                    dns_cache_timeout => integer(),
                    ca_cache_timeout => integer(),
                    pipewait => boolean()}.
-type opts() :: #{reply_to => pid(),
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
                    tcp_fastopen => tcp_fastopen(),
                    interface => interface(),
                    unix_socket_path => unix_socket_path(),
                    doh_url => doh_url(),
                    http_version => curlopt_http_version(),
                    sslversion => curlopt_sslversion(),
                    verbose => boolean(),
                    sslcert => sslcert(),
                    sslkey => sslkey(),
                    sslkey_blob => sslkey_blob(),
                    userpwd => userpwd(),
                    dns_cache_timeout => integer(),
                    ca_cache_timeout => integer(),
                    pipewait => boolean()}.
-export_type([opts/0]).
-type metrics() :: proplists:proplist().
-type response() :: {ok, #{status := status(),
                           headers := headers(),
                           cookiejar := cookiejar(),
                           body := body(),
                           metrics => proplists:proplist()}} |
                    {error, #{code := error_code(),
                              message := error_msg()}}.
-type async_response() :: {ok, reference()} |
                          {error, #{code := error_code(),
                                    message := error_msg()}}.
-type http_auth() :: basic | digest | ntlm | negotiate.
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
-type curlmopts() :: [{pipelining, pipelining()} |
                      {max_total_connections, non_neg_integer()} |
                      {max_concurrent_streams, non_neg_integer()}].

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
-export_type([async_response/0]).

-doc "Returns whether TCP Fast Open is available (curl >= 7.49.0).".
tcp_fastopen_available() ->
    ?TCP_FASTOPEN_AVAILABLE.

-doc "Returns whether Unix socket paths are available (curl >= 7.40.0).".
unix_socket_path_available() ->
    ?UNIX_SOCKET_PATH_AVAILABLE.

-doc "Returns whether DNS-over-HTTPS is available (curl >= 7.62.0).".
doh_url_available() ->
    ?DOH_URL_AVAILABLE.

-doc "Returns whether SSL key blob is available (curl >= 7.71.0).".
sslkey_blob_available() ->
    ?SSLKEY_BLOB_AVAILABLE.

-doc "Returns whether HTTP/3 is available (curl >= 7.66.0).".
http3_available() ->
    ?HTTP3_AVAILABLE.

-doc #{equiv => get/3}.
-spec get(katipo_pool:name(), url()) -> response().
get(PoolName, Url) ->
    req(PoolName, #{url => Url, method => get}).

-doc "Performs an HTTP GET request.".
-spec get(katipo_pool:name(), url(), opts()) -> response().
get(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => get}).

-doc #{equiv => post/3}.
-spec post(katipo_pool:name(), url()) -> response().
post(PoolName, Url) ->
    req(PoolName, #{url => Url, method => post}).

-doc "Performs an HTTP POST request.".
-spec post(katipo_pool:name(), url(), opts()) -> response().
post(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => post}).

-doc #{equiv => put/3}.
-spec put(katipo_pool:name(), url()) -> response().
put(PoolName, Url) ->
    req(PoolName, #{url => Url, method => put}).

-doc "Performs an HTTP PUT request.".
-spec put(katipo_pool:name(), url(), opts()) -> response().
put(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => put}).

-doc #{equiv => head/3}.
-spec head(katipo_pool:name(), url()) -> response().
head(PoolName, Url) ->
    req(PoolName, #{url => Url, method => head}).

-doc "Performs an HTTP HEAD request.".
-spec head(katipo_pool:name(), url(), opts()) -> response().
head(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => head}).

-doc #{equiv => options/3}.
-spec options(katipo_pool:name(), url()) -> response().
options(PoolName, Url) ->
    req(PoolName, #{url => Url, method => options}).

-doc "Performs an HTTP OPTIONS request.".
-spec options(katipo_pool:name(), url(), opts()) -> response().
options(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => options}).

-doc #{equiv => patch/3}.
-spec patch(katipo_pool:name(), url()) -> response().
patch(PoolName, Url) ->
    req(PoolName, #{url => Url, method => patch}).

-doc "Performs an HTTP PATCH request.".
-spec patch(katipo_pool:name(), url(), opts()) -> response().
patch(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => patch}).

-doc #{equiv => delete/3}.
-spec delete(katipo_pool:name(), url()) -> response().
delete(PoolName, Url) ->
    req(PoolName, #{url => Url, method => delete}).

-doc "Performs an HTTP DELETE request.".
-spec delete(katipo_pool:name(), url(), opts()) -> response().
delete(PoolName, Url, Opts) ->
    req(PoolName, Opts#{url => Url, method => delete}).

-doc #{equiv => async_get/3}.
-spec async_get(katipo_pool:name(), url()) -> async_response().
async_get(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => get}).

-doc "Performs an async HTTP GET request. Returns `{ok, Ref}` immediately. The response is delivered as a `{katipo_response, Ref, Response}` message.".
-spec async_get(katipo_pool:name(), url(), opts()) -> async_response().
async_get(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => get}).

-doc #{equiv => async_post/3}.
-spec async_post(katipo_pool:name(), url()) -> async_response().
async_post(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => post}).

-doc "Performs an async HTTP POST request. Returns `{ok, Ref}` immediately.".
-spec async_post(katipo_pool:name(), url(), opts()) -> async_response().
async_post(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => post}).

-doc #{equiv => async_put/3}.
-spec async_put(katipo_pool:name(), url()) -> async_response().
async_put(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => put}).

-doc "Performs an async HTTP PUT request. Returns `{ok, Ref}` immediately.".
-spec async_put(katipo_pool:name(), url(), opts()) -> async_response().
async_put(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => put}).

-doc #{equiv => async_head/3}.
-spec async_head(katipo_pool:name(), url()) -> async_response().
async_head(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => head}).

-doc "Performs an async HTTP HEAD request. Returns `{ok, Ref}` immediately.".
-spec async_head(katipo_pool:name(), url(), opts()) -> async_response().
async_head(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => head}).

-doc #{equiv => async_options/3}.
-spec async_options(katipo_pool:name(), url()) -> async_response().
async_options(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => options}).

-doc "Performs an async HTTP OPTIONS request. Returns `{ok, Ref}` immediately.".
-spec async_options(katipo_pool:name(), url(), opts()) -> async_response().
async_options(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => options}).

-doc #{equiv => async_patch/3}.
-spec async_patch(katipo_pool:name(), url()) -> async_response().
async_patch(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => patch}).

-doc "Performs an async HTTP PATCH request. Returns `{ok, Ref}` immediately.".
-spec async_patch(katipo_pool:name(), url(), opts()) -> async_response().
async_patch(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => patch}).

-doc #{equiv => async_delete/3}.
-spec async_delete(katipo_pool:name(), url()) -> async_response().
async_delete(PoolName, Url) ->
    async_req(PoolName, #{url => Url, method => delete}).

-doc "Performs an async HTTP DELETE request. Returns `{ok, Ref}` immediately.".
-spec async_delete(katipo_pool:name(), url(), opts()) -> async_response().
async_delete(PoolName, Url, Opts) ->
    async_req(PoolName, Opts#{url => Url, method => delete}).

-doc "Performs an HTTP request using the full request map.".
-spec req(katipo_pool:name(), request()) -> response().
req(PoolName, Opts)
  when is_map(Opts) ->
    case katipo_req:build_req(Opts) of
        {ok, Req} ->
            do_req_with_span(PoolName, Req);
        {error, _} = Error ->
            Error
    end.

-doc """
Performs an async HTTP request using the full request map.

Returns `{ok, Ref}` immediately. The response is delivered as a
`{katipo_response, Ref, ResponseMap}` or `{katipo_error, Ref, ErrorMap}`
message to the process specified by the `reply_to` option (defaults to `self()`).

Use `await/1,2` to block until the response arrives.
""".
-spec async_req(katipo_pool:name(), request()) -> async_response().
async_req(PoolName, Opts)
  when is_map(Opts) ->
    {ReplyTo, Opts2} =
        case maps:take(reply_to, Opts) of
            {RT, Rest} -> {RT, Rest};
            error -> {self(), Opts}
        end,
    case is_pid(ReplyTo) of
        false ->
            {error, katipo_req:error_map(bad_opts, <<"[{reply_to,invalid}]">>)};
        true ->
            case katipo_req:build_req(Opts2) of
                {ok, Req} ->
                    UserRef = make_ref(),
                    Obs = katipo_span:start_async(katipo_req:method_int_to_binary(Req#req.method),
                                                  Req#req.url),
                    wpool:cast(PoolName, {async_req, ReplyTo, UserRef, Req, Obs},
                               random_worker),
                    {ok, UserRef};
                {error, _} = Error ->
                    Error
            end
    end.

-doc #{equiv => await/2}.
-spec await(reference()) -> response().
await(Ref) ->
    await(Ref, ?DEFAULT_REQ_TIMEOUT).

-doc "Blocks until an async response for `Ref` arrives or the timeout expires.".
-spec await(reference(), timeout()) -> response().
await(Ref, Timeout) ->
    receive
        {katipo_response, Ref, Response} ->
            {ok, Response};
        {katipo_error, Ref, Error} ->
            {error, Error}
    after Timeout ->
        %% Flush any late-arriving response for this Ref
        receive
            {katipo_response, Ref, _} -> ok;
            {katipo_error, Ref, _} -> ok
        after 0 ->
            ok
        end,
        {error, #{code => await_timeout, message => <<>>}}
    end.

-doc """
Cancels the async request identified by `Ref` (returned by `async_get/2,3`,
`async_req/2`, etc.).

Best-effort: once the cancel takes effect no `{katipo_response, Ref, _}` or
`{katipo_error, Ref, _}` message is delivered. A message that was already
delivered before the cancel raced in may still be in the receiver's mailbox, so
callers should be prepared to flush a late one. Cancelling an unknown or
already-completed `Ref` is a harmless no-op.

Note: the in-flight HTTP transfer is not aborted — it completes in the
background and its result is discarded.
""".
-spec cancel(katipo_pool:name(), reference()) -> ok.
cancel(PoolName, Ref) ->
    wpool:broadcast(PoolName, {cancel, Ref}),
    ok.

-doc false.
do_req_with_span(PoolName, Req) ->
    #req{method = MethodInt, url = Url} = Req,
    Method = katipo_req:method_int_to_binary(MethodInt),
    katipo_span:with_client_span(Method, Url, fun(SpanCtx) ->
        Ts = os:timestamp(),
        {Result, {Response, Metrics}} =
            wpool:call(PoolName, Req, random_worker, infinity),
        katipo_span:record_outcome(SpanCtx, Method, Ts, Result, Response, Metrics),
        {Result, Response}
    end).

-doc "Validates request options without performing the request.".
-spec check_opts(request()) -> ok | {error, map()}.
check_opts(Opts) when is_map(Opts) ->
    katipo_req:check_opts(Opts).
