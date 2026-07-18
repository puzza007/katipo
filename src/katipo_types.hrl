%% Public type definitions for the katipo API. Kept out of katipo.erl to keep
%% the facade focused on functions. Self-contained: it pulls in
%% katipo_internal.hrl for the ?SSL_CACERT_ERROR_CODE macro that the
%% error_code() union references, so include order does not matter.

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
        worker_died |
        overload.

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
                    maxredirs => -1 | non_neg_integer(),
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
                    dns_cache_timeout => integer(),
                    ca_cache_timeout => integer(),
                    pipewait => boolean(),
                    stream => boolean(),
                    stream_window => pos_integer() | infinity}.
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
                    maxredirs => -1 | non_neg_integer(),
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
                    dns_cache_timeout => integer(),
                    ca_cache_timeout => integer(),
                    pipewait => boolean(),
                    stream => boolean(),
                    stream_window => pos_integer() | infinity}.
-export_type([opts/0]).
-type metrics() :: proplists:proplist().
-type response() :: {ok, #{status := status(),
                           headers := headers(),
                           cookiejar := cookiejar(),
                           body := body()}} |
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
%% Pool options: the curl-multi options above plus katipo's own Erlang-side
%% per-worker admission cap.
-type pool_opts() :: [{pipelining, pipelining()} |
                      {max_total_connections, non_neg_integer()} |
                      {max_concurrent_streams, non_neg_integer()} |
                      {max_in_flight, pos_integer() | infinity}].

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

-endif.
