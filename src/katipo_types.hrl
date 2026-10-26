%% Public type definitions for the katipo API. Kept out of katipo.erl to keep
%% the facade focused on functions. Self-contained: it pulls in
%% katipo_internal.hrl for the ?MAX_INT_OPT macro the types below
%% reference, so include order does not matter.

-ifndef(KATIPO_TYPES_HRL).
-define(KATIPO_TYPES_HRL, true).

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
        %% The CA verification failure: ssl_cacert before libcurl 7.62.0,
        %% peer_failed_verification since. The C port picks one from the
        %% curl headers it is built with, which the Erlang build cannot
        %% see reliably, so both are listed.
        ssl_cacert |
        peer_failed_verification |
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
        %% a curl code katipo's C port has no name for
        unknown_error |
        %% returned by us, not curl
        bad_opts |
        await_timeout |
        worker_died |
        overload |
        admission_timeout.

-type error_msg() :: binary().
-type status() :: pos_integer().
-doc "A request header. Name and value may be any iodata.".
-type header() :: {iodata(), iodata()}.
-type headers() :: [header()].
-doc """
A response header, as libcurl received it except that the value's
surrounding whitespace is trimmed, a folded value's lines are joined with
one space, and a CR, LF or NUL inside it is replaced with a space.
""".
-type resp_header() :: {binary(), binary()}.
-type resp_headers() :: [resp_header()].
-opaque cookiejar() :: [binary()].
-type qs_vals() :: [{unicode:chardata(), unicode:chardata() | true}].
-doc """
A request body: iodata, sent as given; a form, sent form-urlencoded;
`{file, Path}`, a file the C port reads as it sends it, so it is never
held in memory, and seeks back to its start to send it again after a
redirect; or, for the async API only, `{stream, #{length => N}}`, a body
the caller sends with `katipo:send_body/3`, one chunk per
`{katipo_body_demand, Ref}` message.

A relative `Path` is taken from the VM's working directory when the
request is made. `Content-Length` is the file's size then: if the file
grows, no more is sent, and if it shrinks the request fails with
`read_error`.

A streamed body with `length` goes with that `Content-Length`, and one
longer or shorter fails the request with `read_error`; without, it is
sent chunked (or as HTTP/2 or 3 frames). It cannot be sent again, so a
redirect, an auth retry (digest, NTLM, Negotiate) or curl's retry on a
reused connection the server had closed, any of which would need to,
fails with `send_fail_rewind`.
""".
-type req_body() :: iodata() | qs_vals() | {file, unicode:chardata()} |
                    {stream, #{length => non_neg_integer()}}.
-type body() :: binary().
-type connecttimeout_ms() :: 1..?MAX_INT_OPT.
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
-type unix_socket_path() :: unicode:chardata().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_UNIX_SOCKET_PATH.html]
-type doh_url() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_DOH_URL.html]
-type sslcert() :: unicode:chardata().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_SSLCERT.html]
-type capath() :: unicode:chardata().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_CAPATH.html]
-type cacert() :: unicode:chardata().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_CAINFO.html]
-type sslkey() :: unicode:chardata().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEY.html]
-type sslkey_blob() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_SSLKEY_BLOB.html]
-type userpwd() :: binary().
%% See [https://curl.haxx.se/libcurl/c/CURLOPT_USERPWD.html]
%% The request options, shared by every request type: Erlang cannot compose
%% map types, so the fields are spelled out once here instead.
-define(KATIPO_OPTS_FIELDS,
        headers => headers(),
        cookiejar => cookiejar(),
        body => req_body(),
        connecttimeout_ms => connecttimeout_ms(),
        followlocation => boolean(),
        ssl_verifyhost => ssl_verifyhost(),
        ssl_verifypeer => ssl_verifypeer(),
        capath => capath(),
        cacert => cacert(),
        timeout_ms => 1..?MAX_INT_OPT,
        maxredirs => -1..?MAX_INT_OPT,
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
        keypasswd => binary(),
        userpwd => userpwd(),
        dns_cache_timeout => -1..?MAX_INT_OPT,
        ca_cache_timeout => -1..?MAX_INT_OPT,
        pipewait => boolean(),
        low_speed_limit => 1..?MAX_INT_OPT,
        low_speed_time => 1..?MAX_INT_OPT,
        max_body_size => 0..?MAX_INT_OPT,
        retry => retry()).
%% The options only the async API acts on: where to deliver the response,
%% and whether to stream it. ?KATIPO_ASYNC_OPTS (katipo_internal.hrl) lists
%% the same keys for katipo_req; keep the two in step.
-define(KATIPO_ASYNC_OPTS_FIELDS,
        reply_to => pid(),
        stream => boolean(),
        stream_window => 1..?MAX_INT_OPT | infinity).
%% The same keys as the synchronous API takes them: only with the values
%% that change nothing there.
-define(KATIPO_SYNC_NOOP_FIELDS,
        reply_to => pid(),
        stream => false,
        stream_window => infinity).
-doc """
Options for any request: `async_get/3` and the other async method
functions take all of them. The synchronous functions take
`t:sync_opts/0`.
""".
-type opts() :: #{?KATIPO_OPTS_FIELDS, ?KATIPO_ASYNC_OPTS_FIELDS}.
-doc """
A request for `async_req/2`: the options plus `url`, and `method`
(default `get`). `req/2` takes `t:sync_request/0`.
""".
-type request() :: #{url := url(), method => method(),
                     ?KATIPO_OPTS_FIELDS, ?KATIPO_ASYNC_OPTS_FIELDS}.
-doc """
Options for `get/3` and the other synchronous method functions. They
reject `stream => true`, a bounded `stream_window`, and a `reply_to`
other than the caller with `bad_opts`; the values that change nothing
are accepted.
""".
-type sync_opts() :: #{?KATIPO_OPTS_FIELDS, ?KATIPO_SYNC_NOOP_FIELDS}.
-doc "A request for `req/2`: the synchronous options plus `url` and `method`.".
-type sync_request() :: #{url := url(), method => method(),
                          ?KATIPO_OPTS_FIELDS, ?KATIPO_SYNC_NOOP_FIELDS}.
-doc """
Any options or request, with `url` and `method` both optional, as
`check_opts/1` and `check_opts/2` take them.
""".
-type partial_request() :: #{url => url(), method => method(),
                             ?KATIPO_OPTS_FIELDS, ?KATIPO_ASYNC_OPTS_FIELDS}.
-export_type([opts/0]).
-export_type([sync_opts/0]).
-export_type([sync_request/0]).
-export_type([partial_request/0]).
-doc "One of the timings libcurl reports for a request.".
-type metric() :: total_time | namelookup_time | connect_time |
                  appconnect_time | pretransfer_time | redirect_time |
                  starttransfer_time.
-doc """
libcurl's timings for the request, in seconds. Empty when libcurl reported
none: the request failed validation, timed out or lost its worker on the
Erlang side, or never reached a transfer.
""".
-type metrics() :: [{metric(), float()}].
-type error() :: #{code := error_code(), message := error_msg()}.
-type response_map() :: #{status := status(),
                          headers := resp_headers(),
                          cookiejar := cookiejar(),
                          body := body()}.
-type response() :: {ok, response_map()} | {error, error()}.
-type async_response() :: {ok, reference()} | {error, error()}.
-doc """
Every message an async request can deliver to its `reply_to` process. A
buffered request ends with one `katipo_response` or `katipo_error`. A
streamed one (`stream => true`) gets `katipo_headers`, then zero or more
`katipo_chunk`, then `katipo_done`, and `katipo_error` can end it at any
point. A cancelled request gets nothing more, nor does one whose worker is
killed outright, so keep a timeout on the receive.
""".
-type async_message() ::
        {katipo_response, reference(), response_map()} |
        {katipo_error, reference(), error()} |
        {katipo_headers, reference(), #{status := status(), headers := resp_headers()}} |
        {katipo_chunk, reference(), binary()} |
        {katipo_done, reference(), #{status := status(), cookiejar := cookiejar()}} |
        {katipo_body_demand, reference()}.
-doc """
Whether and how to send a request again when an attempt fails: `false`
(the default) never; `true` with the defaults below; or a map overriding
any of them.

- `max_retries` (3): the most times the request is sent again. 0 is the
  same as `false`.
- `methods` (`[get, head, options, put, delete]`, the idempotent ones):
  the methods that are retried; a request with any other is never.
- `statuses` (`[429, 503]`): the response statuses that are retried.
- `errors`: the error codes that are retried. By default
  `couldnt_connect`, `operation_timedout`, `got_nothing`, `send_error`,
  `recv_error`, `partial_file`, `http2`, `http2_stream`, `http3` and
  `quic_connect_error`: the connection could not be made or broke, the
  server sent nothing or not all of it, or the attempt ran out of time.
- `base_delay_ms` (100) and `max_delay_ms` (5000): the wait before each
  retry is a random time up to `base_delay_ms` doubled for each retry
  already sent, capped at `max_delay_ms`.

A retried status waits instead as long as its `Retry-After` header asks,
in seconds or as an HTTP-date, if it has one. If that is longer than
`max_delay_ms`, the response is returned as it is.

The caller sees only the last attempt's response or error. Each attempt
has the whole `timeout_ms`, so with retries a request can take
`max_retries + 1` times as long, plus the waits. A retry is sent from the
start: a body is sent again, and a file body is read again. A streamed
body or response cannot be, so `retry` with either is `bad_opts`.
""".
-type retry() :: boolean() |
                 #{max_retries => 0..?MAX_INT_OPT,
                   methods => [method()],
                   statuses => [100..599],
                   errors => [error_code()],
                   base_delay_ms => 0..?MAX_INT_OPT,
                   max_delay_ms => 0..?MAX_INT_OPT}.
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
-type curlmopts() :: [curlmopt()].
-type curlmopt() :: {pipelining, pipelining()} |
                    {max_total_connections, 0..?MAX_INT_OPT} |
                    {max_concurrent_streams, 0..?MAX_INT_OPT} |
                    {maxconnects, 0..?MAX_INT_OPT} |
                    {max_host_connections, 0..?MAX_INT_OPT}.
%% Pool options: the curl-multi options above plus katipo's own Erlang-side
%% per-worker admission cap.
-type pool_opts() :: [curlmopt() | {max_in_flight, pos_integer() | infinity}].

-export_type([method/0]).
-export_type([url/0]).
-export_type([error_code/0]).
-export_type([error_msg/0]).
-export_type([status/0]).
-export_type([header/0]).
-export_type([headers/0]).
-export_type([resp_header/0]).
-export_type([resp_headers/0]).
-export_type([capath/0]).
-export_type([cacert/0]).
-export_type([metric/0]).
-export_type([cookiejar/0]).
-export_type([req_body/0]).
-export_type([body/0]).
-export_type([request/0]).
-export_type([metrics/0]).
-export_type([response/0]).
-export_type([http_auth/0]).
-export_type([retry/0]).
-export_type([curlmopts/0]).
-export_type([pool_opts/0]).
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
-export_type([error/0]).
-export_type([response_map/0]).
-export_type([async_message/0]).

-endif.
