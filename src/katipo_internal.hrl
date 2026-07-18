%% Internal shared definitions for the katipo application: the request record
%% and the numeric option/method constants of the C port wire protocol. Included
%% by katipo, katipo_req, and katipo_worker. Not a public interface.

-ifndef(KATIPO_INTERNAL_HRL).
-define(KATIPO_INTERNAL_HRL, true).

%% Compile-time curl feature availability (flags set by rebar.config.script).
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

%% HTTP method codes.
-define(GET, 0).
-define(POST, 1).
-define(PUT, 2).
-define(HEAD, 3).
-define(OPTIONS, 4).
-define(PATCH, 5).
-define(DELETE, 6).

%% Wire option indices (must match the K_CURLOPT_* values in c_src/katipo.c).
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
-define(DOH_URL, 21).
-define(HTTP_VERSION, 22).
-define(VERBOSE, 23).
-define(SSLCERT, 24).
-define(SSLKEY, 25).
-define(SSLKEY_BLOB, 26).
-define(KEYPASSWD, 27).
-define(USERPWD, 28).
-define(SSLVERSION, 29).
-define(DNS_CACHE_TIMEOUT, 31).
-define(CA_CACHE_TIMEOUT, 32).
-define(PIPEWAIT, 33).
-define(STREAM, 34).
-define(STREAM_WINDOW, 35).

-define(DEFAULT_REQ_TIMEOUT, 30000).
%% Bound on the admission gen_server:call into a pool worker. Admission is a
%% port write plus a map insert, so a healthy worker answers in microseconds;
%% this only trips when a worker is wedged (e.g. its C port stopped draining
%% the pipe and port_command blocked it) or its mailbox is deeply backed up.
-define(ADMISSION_TIMEOUT, 5000).
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
-define(VERBOSE_TRUE, 1).
-define(VERBOSE_FALSE, 0).
-define(PIPEWAIT_TRUE, 1).
-define(PIPEWAIT_FALSE, 0).
-define(STREAM_TRUE, 1).
-define(STREAM_FALSE, 0).
-define(STREAM_WINDOW_UNLIMITED, -1).

%% CURLOPT_HTTP_VERSION values
-define(CURL_HTTP_VERSION_NONE, 0).
-define(CURL_HTTP_VERSION_1_0, 1).
-define(CURL_HTTP_VERSION_1_1, 2).
-define(CURL_HTTP_VERSION_2_0, 3).
-define(CURL_HTTP_VERSION_2TLS, 4).
-define(CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE, 5).
-define(CURL_HTTP_VERSION_3, 30).

%% CURLOPT_SSLVERSION values
-define(CURL_SSLVERSION_DEFAULT, 0).
-define(CURL_SSLVERSION_TLSV1, 1).
-define(CURL_SSLVERSION_TLSV1_0, 4).
-define(CURL_SSLVERSION_TLSV1_1, 5).
-define(CURL_SSLVERSION_TLSV1_2, 6).
-define(CURL_SSLVERSION_TLSV1_3, 7).

-define(METHODS, [get, post, put, head, options, patch, delete]).

-type method_int() :: ?GET | ?POST | ?PUT | ?HEAD | ?OPTIONS | ?PATCH | ?DELETE.
-type http_auth_int() :: ?CURLAUTH_UNDEFINED
                       | ?CURLAUTH_BASIC
                       | ?CURLAUTH_DIGEST
                       | ?CURLAUTH_NTLM
                       | ?CURLAUTH_NEGOTIATE.

%% The validated request built from an options map (katipo_req) and consumed by
%% the worker (katipo_worker). The wire-value field types stay in this shared
%% header so the record and its validators (katipo_req:opt/3) draw from one
%% definition rather than two spellings that can drift.
-record(req, {
          method = ?GET :: method_int(),
          url :: undefined | binary(),
          headers = [] :: [binary()],
          cookiejar = [] :: [binary()],
          body = <<>> :: iodata(),
          connecttimeout_ms = ?DEFAULT_REQ_TIMEOUT :: pos_integer(),
          followlocation = ?FOLLOWLOCATION_FALSE :: integer(),
          ssl_verifyhost = ?SSL_VERIFYHOST_TRUE :: integer(),
          ssl_verifypeer = ?SSL_VERIFYPEER_TRUE :: integer(),
          capath = undefined :: undefined | binary() | file:name_all(),
          cacert = undefined :: undefined | binary() | file:name_all(),
          timeout_ms = ?DEFAULT_REQ_TIMEOUT :: pos_integer(),
          maxredirs = 9 :: -1 | non_neg_integer(),
          timeout = ?DEFAULT_REQ_TIMEOUT :: pos_integer(),
          http_auth = ?CURLAUTH_UNDEFINED :: http_auth_int(),
          username = undefined :: undefined | binary(),
          password = undefined :: undefined | binary(),
          proxy = undefined :: undefined | binary(),
          tcp_fastopen = ?TCP_FASTOPEN_FALSE :: ?TCP_FASTOPEN_FALSE | ?TCP_FASTOPEN_TRUE,
          interface = undefined :: undefined | binary(),
          unix_socket_path = undefined :: undefined | binary(),
          doh_url = undefined :: undefined | binary(),
          http_version = ?CURL_HTTP_VERSION_NONE :: integer(),
          sslversion = ?CURL_SSLVERSION_DEFAULT :: integer(),
          verbose = ?VERBOSE_FALSE :: ?VERBOSE_FALSE | ?VERBOSE_TRUE,
          sslcert = undefined :: undefined | binary() | file:name_all(),
          sslkey = undefined :: undefined | binary() | file:name_all(),
          sslkey_blob = undefined :: undefined | binary(),
          keypasswd = undefined :: undefined | binary(),
          userpwd = undefined :: undefined | binary(),
          dns_cache_timeout = 60 :: integer(),
          ca_cache_timeout = 86400 :: integer(),
          pipewait = ?PIPEWAIT_TRUE :: ?PIPEWAIT_FALSE | ?PIPEWAIT_TRUE,
          stream = ?STREAM_FALSE :: ?STREAM_FALSE | ?STREAM_TRUE,
          stream_window = ?STREAM_WINDOW_UNLIMITED :: integer()
         }).

-endif.
