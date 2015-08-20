#include <stdlib.h>
#include <event.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <err.h>
#include <string.h>
#include <ei.h>
#include <curl/curl.h>
#include <getopt.h>

#define KATIPO_GET 0
#define KATIPO_POST 1
#define KATIPO_PUT 2
#define KATIPO_HEAD 3
#define KATIPO_OPTIONS 4

#define K_CURLOPT_CONNECTTIMEOUT_MS 5
#define K_CURLOPT_FOLLOWLOCATION 6
#define K_CURLOPT_SSL_VERIFYHOST 7
#define K_CURLOPT_TIMEOUT_MS 8
#define K_CURLOPT_MAXREDIRS 9
#define K_CURLOPT_SSL_VERIFYPEER 10
#define K_CURLOPT_CAPATH 11
#define K_CURLOPT_HTTP_AUTH 12
#define K_CURLOPT_USERNAME 13
#define K_CURLOPT_PASSWORD 14
#define K_CURLOPT_PROXY 15

#define K_CURLAUTH_BASIC 100
#define K_CURLAUTH_DIGEST 101

struct bufferevent *to_erlang;
struct bufferevent *from_erlang;

typedef struct _GlobalInfo {
  struct event_base *evbase;
  struct event *timer_event;
  CURLM *multi;
  int still_running;
  size_t to_get;
} GlobalInfo;

typedef struct _ConnInfo {
  CURL *easy;
  char *url;
  erlang_pid *pid;
  erlang_ref *ref;
  char *memory;
  size_t size;
  GlobalInfo *global;
  char error[CURL_ERROR_SIZE];
  size_t num_headers;
  struct curl_slist *resp_headers;
  struct curl_slist *req_headers;
  struct curl_slist *req_cookies;
  int response_code;
  char *post_data;
  long post_data_size;
  // metrics
  double total_time;
  double namelookup_time;
  double connect_time;
  double appconnect_time;
  double pretransfer_time;
  double starttransfer_time;
} ConnInfo;

typedef struct _SockInfo {
  curl_socket_t sockfd;
  CURL *easy;
  int action;
  long timeout;
  struct event *ev;
  int evset;
  GlobalInfo *global;
} SockInfo;

typedef struct _EasyOpts {
  long curlopt_connecttimeout_ms;
  long curlopt_followlocation;
  long curlopt_ssl_verifyhost;
  long curlopt_ssl_verifypeer;
  char *curlopt_capath;
  long curlopt_timeout_ms;
  long curlopt_maxredirs;
  long curlopt_http_auth;
  char *curlopt_username;
  char *curlopt_password;
  char *curlopt_proxy;
} EasyOpts;

static const char *curl_error_code(CURLcode error) {
  switch (error) {
    case CURLE_OK:
      return "ok";
    case CURLE_UNSUPPORTED_PROTOCOL:
      return "unsupported_protocol";
    case CURLE_FAILED_INIT:
      return "failed_init";
    case CURLE_URL_MALFORMAT:
      return "url_malformat";
    case CURLE_NOT_BUILT_IN:
      return "not_built_in";
    case CURLE_COULDNT_RESOLVE_PROXY:
      return "couldnt_resolve_proxy";
    case CURLE_COULDNT_RESOLVE_HOST:
      return "couldnt_resolve_host";
    case CURLE_COULDNT_CONNECT:
      return "couldnt_connect";
    case CURLE_FTP_WEIRD_SERVER_REPLY:
      return "ftp_weird_server_reply";
    case CURLE_REMOTE_ACCESS_DENIED:
      return "remote_access_denied";
    case CURLE_FTP_ACCEPT_FAILED:
      return "ftp_accept_failed";
    case CURLE_FTP_WEIRD_PASS_REPLY:
      return "ftp_weird_pass_reply";
    case CURLE_FTP_ACCEPT_TIMEOUT:
      return "ftp_accept_timeout";
    case CURLE_FTP_WEIRD_PASV_REPLY:
      return "ftp_weird_pasv_reply";
    case CURLE_FTP_WEIRD_227_FORMAT:
      return "ftp_weird_227_format";
    case CURLE_FTP_CANT_GET_HOST:
      return "ftp_cant_get_host";
    /* case CURLE_HTTP2: */
    /*   return "http2"; */
    case CURLE_FTP_COULDNT_SET_TYPE:
      return "ftp_couldnt_set_type";
    case CURLE_PARTIAL_FILE:
      return "partial_file";
    case CURLE_FTP_COULDNT_RETR_FILE:
      return "ftp_couldnt_retr_file";
    case CURLE_OBSOLETE20:
      return "obsolete20";
    case CURLE_QUOTE_ERROR:
      return "quote_error";
    case CURLE_HTTP_RETURNED_ERROR:
      return "http_returned_error";
    case CURLE_WRITE_ERROR:
      return "write_error";
    case CURLE_OBSOLETE24:
      return "obsolete24";
    case CURLE_UPLOAD_FAILED:
      return "upload_failed";
    case CURLE_READ_ERROR:
      return "read_error";
    case CURLE_OUT_OF_MEMORY:
      return "out_of_memory";
    case CURLE_OPERATION_TIMEDOUT:
      return "operation_timedout";
    case CURLE_OBSOLETE29:
      return "obsolete29";
    case CURLE_FTP_PORT_FAILED:
      return "ftp_port_failed";
    case CURLE_FTP_COULDNT_USE_REST:
      return "ftp_couldnt_use_rest";
    case CURLE_OBSOLETE32:
      return "obsolete32";
    case CURLE_RANGE_ERROR:
      return "range_error";
    case CURLE_HTTP_POST_ERROR:
      return "http_post_error";
    case CURLE_SSL_CONNECT_ERROR:
      return "ssl_connect_error";
    case CURLE_BAD_DOWNLOAD_RESUME:
      return "bad_download_resume";
    case CURLE_FILE_COULDNT_READ_FILE:
      return "file_couldnt_read_file";
    case CURLE_LDAP_CANNOT_BIND:
      return "ldap_cannot_bind";
    case CURLE_LDAP_SEARCH_FAILED:
      return "ldap_search_failed";
    case CURLE_OBSOLETE40:
      return "obsolete40";
    case CURLE_FUNCTION_NOT_FOUND:
      return "function_not_found";
    case CURLE_ABORTED_BY_CALLBACK:
      return "aborted_by_callback";
    case CURLE_BAD_FUNCTION_ARGUMENT:
      return "bad_function_argument";
    case CURLE_OBSOLETE44:
      return "obsolete44";
    case CURLE_INTERFACE_FAILED:
      return "interface_failed";
    case CURLE_OBSOLETE46:
      return "obsolete46";
    case CURLE_TOO_MANY_REDIRECTS:
      return "too_many_redirects";
    case CURLE_UNKNOWN_OPTION:
      return "unknown_option";
    case CURLE_TELNET_OPTION_SYNTAX:
      return "telnet_option_syntax";
    case CURLE_OBSOLETE50:
      return "obsolete50";
    case CURLE_PEER_FAILED_VERIFICATION:
      return "peer_failed_verification";
    case CURLE_GOT_NOTHING:
      return "got_nothing";
    case CURLE_SSL_ENGINE_NOTFOUND:
      return "ssl_engine_notfound";
    case CURLE_SSL_ENGINE_SETFAILED:
      return "ssl_engine_setfailed";
    case CURLE_SEND_ERROR:
      return "send_error";
    case CURLE_RECV_ERROR:
      return "recv_error";
    case CURLE_OBSOLETE57:
      return "obsolete57";
    case CURLE_SSL_CERTPROBLEM:
      return "ssl_certproblem";
    case CURLE_SSL_CIPHER:
      return "ssl_cipher";
    case CURLE_SSL_CACERT:
      return "ssl_cacert";
    case CURLE_BAD_CONTENT_ENCODING:
      return "bad_content_encoding";
    case CURLE_LDAP_INVALID_URL:
      return "ldap_invalid_url";
    case CURLE_FILESIZE_EXCEEDED:
      return "filesize_exceeded";
    case CURLE_USE_SSL_FAILED:
      return "use_ssl_failed";
    case CURLE_SEND_FAIL_REWIND:
      return "send_fail_rewind";
    case CURLE_SSL_ENGINE_INITFAILED:
      return "ssl_engine_initfailed";
    case CURLE_LOGIN_DENIED:
      return "login_denied";
    case CURLE_TFTP_NOTFOUND:
      return "tftp_notfound";
    case CURLE_TFTP_PERM:
      return "tftp_perm";
    case CURLE_REMOTE_DISK_FULL:
      return "remote_disk_full";
    case CURLE_TFTP_ILLEGAL:
      return "tftp_illegal";
    case CURLE_TFTP_UNKNOWNID:
      return "tftp_unknownid";
    case CURLE_REMOTE_FILE_EXISTS:
      return "remote_file_exists";
    case CURLE_TFTP_NOSUCHUSER:
      return "tftp_nosuchuser";
    case CURLE_CONV_FAILED:
      return "conv_failed";
    case CURLE_CONV_REQD:
      return "conv_reqd";
    case CURLE_SSL_CACERT_BADFILE:
      return "ssl_cacert_badfile";
    case CURLE_REMOTE_FILE_NOT_FOUND:
      return "remote_file_not_found";
    case CURLE_SSH:
      return "ssh";
    case CURLE_SSL_SHUTDOWN_FAILED:
      return "ssl_shutdown_failed";
    case CURLE_AGAIN:
      return "again";
    case CURLE_SSL_CRL_BADFILE:
      return "ssl_crl_badfile";
    case CURLE_SSL_ISSUER_ERROR:
      return "ssl_issuer_error";
    case CURLE_FTP_PRET_FAILED:
      return "ftp_pret_failed";
    case CURLE_RTSP_CSEQ_ERROR:
      return "rtsp_cseq_error";
    case CURLE_RTSP_SESSION_ERROR:
      return "rtsp_session_error";
    case CURLE_FTP_BAD_FILE_LIST:
      return "ftp_bad_file_list";
    case CURLE_CHUNK_FAILED:
      return "chunk_failed";
    case CURLE_NO_CONNECTION_AVAILABLE:
      return "no_connection_available";
    case CURLE_OBSOLETE16:
      return "obsolete16";
    /* case CURLE_SSL_PINNEDPUBKEYNOTMATCH: */
    /*   return "ssl_pinnedpubkeynotmatch"; */
    /* case CURLE_SSL_INVALIDCERTSTATUS: */
    /*   return "ssl_invalidcertstatus"; */
    case CURL_LAST:
      return "curl_last";
    default:
      return "unknown_error";
  }
  return "unknown_error";
}

/* Die if we get a bad CURLMcode somewhere */
static void mcode_or_die(const char *where, CURLMcode code) {
  if (CURLM_OK != code) {
    const char *s;
    switch (code) {
      case CURLM_BAD_HANDLE:
        s = "CURLM_BAD_HANDLE";
        break;
      case CURLM_BAD_EASY_HANDLE:
        s = "CURLM_BAD_EASY_HANDLE";
        break;
      case CURLM_OUT_OF_MEMORY:
        s = "CURLM_OUT_OF_MEMORY";
        break;
      case CURLM_INTERNAL_ERROR:
        s = "CURLM_INTERNAL_ERROR";
        break;
      case CURLM_UNKNOWN_OPTION:
        s = "CURLM_UNKNOWN_OPTION";
        break;
      case CURLM_LAST:
        s = "CURLM_LAST";
        break;
      default:
        s = "CURLM_unknown";
        break;
      case CURLM_BAD_SOCKET:
        s = "CURLM_BAD_SOCKET";
        fprintf(stderr, "ERROR: %s returns %s\n", where, s);
        /* TODO: what to do on this error? */
        return;
    }
    errx(2, "ERROR: %s returns %s\n", where, s);
  }
}

static void send_to_erlang(char *buffer, size_t buffer_len) {
  u_int32_t erl_pkt_len;
  char size_buf[4];

  erl_pkt_len = htonl((uint32_t)buffer_len);

  (void)memcpy(size_buf, &erl_pkt_len, sizeof(erl_pkt_len));
  if (bufferevent_write(to_erlang, size_buf, sizeof(size_buf)) < 0) {
    errx(2, "bufferevent_write");
  }

  if (bufferevent_write(to_erlang, buffer, buffer_len) < 0) {
    errx(2, "bufferevent_write");
  }
}

static int is_status_line(const char *header) {
  int httpversion_major;
  int httpversion;
  int httpcode;
  int nc;

  nc = sscanf(header, "HTTP/%d.%d %d", &httpversion_major, &httpversion,
              &httpcode);
  if (nc == 3)
    return 1;
  // NCSA 1.5.x
  nc = sscanf(header, "HTTP %3d", &httpcode);
  return nc;
}

static void encode_metrics(ei_x_buff *result, ConnInfo *conn) {
  if (ei_x_encode_list_header(result, 6)) {
    errx(2, "Failed to encode stats list header");
  }
  if (ei_x_encode_tuple_header(result, 2) ||
      ei_x_encode_atom(result, "total_time") ||
      ei_x_encode_double(result, conn->total_time) ||
      ei_x_encode_tuple_header(result, 2) ||
      ei_x_encode_atom(result, "namelookup_time") ||
      ei_x_encode_double(result, conn->namelookup_time) ||
      ei_x_encode_tuple_header(result, 2) ||
      ei_x_encode_atom(result, "connect_time") ||
      ei_x_encode_double(result, conn->connect_time) ||
      ei_x_encode_tuple_header(result, 2) ||
      ei_x_encode_atom(result, "appconnect_time") ||
      ei_x_encode_double(result, conn->appconnect_time) ||
      ei_x_encode_tuple_header(result, 2) ||
      ei_x_encode_atom(result, "pretransfer_time") ||
      ei_x_encode_double(result, conn->pretransfer_time) ||
      ei_x_encode_tuple_header(result, 2) ||
      ei_x_encode_atom(result, "starttransfer_time") ||
      ei_x_encode_double(result, conn->starttransfer_time) ||
      ei_x_encode_empty_list(result)) {
    errx(2, "Failed to encode stats");
  }
}

static void encode_cookies(ei_x_buff *result, ConnInfo *conn) {
  struct curl_slist *cookies = NULL;
  struct curl_slist *nc = NULL;
  int num_cookies = 0;

  curl_easy_getinfo(conn->easy, CURLINFO_COOKIELIST, &cookies);
  nc = cookies;
  while (nc) {
    nc = nc->next;
    num_cookies++;
  }

  if (num_cookies > 0) {
    if (ei_x_encode_list_header(result, num_cookies)) {
      errx(2, "Failed to encode cookies");
    }
  }

  nc = cookies;
  while (nc) {
    if (ei_x_encode_binary(result, nc->data, strlen(nc->data))) {
      errx(2, "Failed to encode cookies");
    }
    nc = nc->next;
  }

  if (ei_x_encode_empty_list(result)) {
    errx(2, "Failed to encode cookies");
  }
  curl_slist_free_all(cookies);
}

static void encode_headers(ei_x_buff *result, ConnInfo *conn) {
  struct curl_slist *headers = NULL;

  headers = conn->resp_headers;
  while (headers) {
    if (ei_x_encode_binary(result, headers->data, strlen(headers->data))) {
      errx(2, "Failed to encode headers");
    }
    headers = headers->next;
  }

  if (ei_x_encode_empty_list(result)) {
    errx(2, "Failed to encode headers");
  }
}

static void send_ok_to_erlang(ConnInfo *conn) {
  ei_x_buff result;

  if (ei_x_new_with_version(&result) ||
      ei_x_encode_tuple_header(&result, 2) ||
      ei_x_encode_atom(&result, "ok") ||
      ei_x_encode_tuple_header(&result, 2) ||

      ei_x_encode_tuple_header(&result, 2) ||
      ei_x_encode_pid(&result, conn->pid) ||
      ei_x_encode_ref(&result, conn->ref) ||

      ei_x_encode_tuple_header(&result, 5) ||
      ei_x_encode_long(&result, conn->response_code) ||
      ei_x_encode_list_header(&result, conn->num_headers)) {
    errx(2, "Failed to encode &result");
  }

  encode_headers(&result, conn);

  encode_cookies(&result, conn);

  if (ei_x_encode_binary(&result, conn->memory, conn->size)) {
    errx(2, "Failed to encode body");
  }

  encode_metrics(&result, conn);

  send_to_erlang(result.buff, result.buffsz);
  ei_x_free(&result);
}

static void send_error_to_erlang(CURLcode curl_code, ConnInfo *conn) {
  ei_x_buff result;
  size_t error_msg_len;
  const char *error_code;

  error_code = curl_error_code(curl_code);
  error_msg_len = strlen(conn->error);

  if (ei_x_new_with_version(&result) ||
      ei_x_encode_tuple_header(&result, 2) ||
      ei_x_encode_atom(&result, "error") ||
      ei_x_encode_tuple_header(&result, 2) ||
      ei_x_encode_tuple_header(&result, 2) ||
      ei_x_encode_pid(&result, conn->pid) ||
      ei_x_encode_ref(&result, conn->ref) ||
      ei_x_encode_tuple_header(&result, 3) ||
      ei_x_encode_atom(&result, error_code) ||
      ei_x_encode_binary(&result, conn->error, error_msg_len)) {
    errx(2, "Failed to encode result");
  }

  encode_metrics(&result, conn);

  send_to_erlang(result.buff, result.buffsz);
  ei_x_free(&result);
}

static void check_multi_info(GlobalInfo *global) {
  CURLMsg *msg;
  int msgs_left;
  ConnInfo *conn;
  CURL *easy;
  CURLcode res;

  while ((msg = curl_multi_info_read(global->multi, &msgs_left))) {
    if (msg->msg == CURLMSG_DONE) {
      easy = msg->easy_handle;
      res = msg->data.result;
      curl_easy_getinfo(easy, CURLINFO_PRIVATE, &conn);
      curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &conn->response_code);
      curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME, &conn->total_time);
      curl_easy_getinfo(easy, CURLINFO_NAMELOOKUP_TIME, &conn->namelookup_time);
      curl_easy_getinfo(easy, CURLINFO_CONNECT_TIME, &conn->connect_time);
      curl_easy_getinfo(easy, CURLINFO_APPCONNECT_TIME, &conn->appconnect_time);
      curl_easy_getinfo(easy, CURLINFO_PRETRANSFER_TIME, &conn->pretransfer_time);
      curl_easy_getinfo(easy, CURLINFO_STARTTRANSFER_TIME, &conn->starttransfer_time);

      if (res == CURLE_OK) {
        send_ok_to_erlang(conn);
      } else {
        send_error_to_erlang(res, conn);
      }

      curl_multi_remove_handle(global->multi, easy);
      free(conn->url);
      free(conn->pid);
      free(conn->ref);
      free(conn->memory);
      free(conn->post_data);
      curl_slist_free_all(conn->req_cookies);
      curl_slist_free_all(conn->req_headers);
      curl_slist_free_all(conn->resp_headers);
      curl_easy_cleanup(easy);
      free(conn);
    }
  }
}

static void timer_cb(int fd, short kind, void *userp) {
  GlobalInfo *global = (GlobalInfo *)userp;
  CURLMcode rc;
  (void)fd;
  (void)kind;

  rc = curl_multi_socket_action(global->multi, CURL_SOCKET_TIMEOUT, 0,
                                &global->still_running);
  mcode_or_die("timer_cb: curl_multi_socket_action", rc);
  check_multi_info(global);
}

static void event_cb(int fd, short kind, void *userp) {
  GlobalInfo *global = (GlobalInfo *)userp;
  CURLMcode rc;

  int action = (kind & EV_READ ? CURL_CSELECT_IN : 0) |
               (kind & EV_WRITE ? CURL_CSELECT_OUT : 0);

  rc = curl_multi_socket_action(global->multi, fd, action,
                                &global->still_running);
  mcode_or_die("event_cb: curl_multi_socket_action", rc);

  check_multi_info(global);
  if (global->still_running <= 0) {
    if (evtimer_pending(global->timer_event, NULL)) {
      evtimer_del(global->timer_event);
    }
  }
}

static void setsock(SockInfo *f, curl_socket_t s, CURL *e, int act,
                    GlobalInfo *global) {
  int kind = (act & CURL_POLL_IN ? EV_READ : 0) |
             (act & CURL_POLL_OUT ? EV_WRITE : 0) | EV_PERSIST;

  f->sockfd = s;
  f->action = act;
  f->easy = e;
  if (f->evset)
    event_free(f->ev);
  f->ev = event_new(global->evbase, f->sockfd, kind, event_cb, global);
  f->evset = 1;
  event_add(f->ev, NULL);
}

static void addsock(curl_socket_t s, CURL *easy, int action,
                    GlobalInfo *global) {
  SockInfo *fdp = calloc(sizeof(SockInfo), 1);

  fdp->global = global;
  setsock(fdp, s, easy, action, global);
  curl_multi_assign(global->multi, s, fdp);
}

static void remsock(SockInfo *f) {
  if (f) {
    if (f->evset)
      event_free(f->ev);
    free(f);
  }
}

static int sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp) {
  GlobalInfo *global = (GlobalInfo *)cbp;
  SockInfo *fdp = (SockInfo *)sockp;

  if (what == CURL_POLL_REMOVE) {
    remsock(fdp);
  } else {
    if (!fdp) {
      addsock(s, e, what, global);
    } else {
      setsock(fdp, s, e, what, global);
    }
  }
  return 0;
}

static int multi_timer_cb(CURLM *multi, long timeout_ms, GlobalInfo *global) {
  struct timeval timeout;

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
  evtimer_add(global->timer_event, &timeout);
  return 0;
}

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data) {
  size_t realsize = size * nmemb;
  ConnInfo *conn = (ConnInfo *)data;

  conn->memory = (char *)realloc(conn->memory, conn->size + realsize);
  memcpy(&(conn->memory[conn->size]), ptr, realsize);
  conn->size += realsize;

  return realsize;
}

static size_t header_cb(void *ptr, size_t size, size_t nmemb, void *data) {
  size_t realsize = size * nmemb;
  ConnInfo *conn = (ConnInfo *)data;
  char *header;

  // the last two chars of headers are \r\n
  if (realsize > 2) {
    if (conn->resp_headers && is_status_line(ptr)) {
      curl_slist_free_all(conn->resp_headers);
      conn->resp_headers = NULL;
      conn->num_headers = 0;
    }
    header = (char *)malloc(realsize - 1);
    strncpy(header, ptr, realsize - 2);
    header[realsize - 2] = '\0';
    conn->resp_headers = curl_slist_append(conn->resp_headers, header);
    free(header);
    conn->num_headers++;
  }
  return realsize;
}

static void set_method(long method, ConnInfo *conn) {
  switch (method) {
    case KATIPO_GET:
      break;
    case KATIPO_POST:
      curl_easy_setopt(conn->easy, CURLOPT_POST, 1);
      curl_easy_setopt(conn->easy, CURLOPT_POSTFIELDS, conn->post_data);
      curl_easy_setopt(conn->easy, CURLOPT_POSTFIELDSIZE, conn->post_data_size);
      break;
    case KATIPO_PUT:
      curl_easy_setopt(conn->easy, CURLOPT_CUSTOMREQUEST, "PUT");
      curl_easy_setopt(conn->easy, CURLOPT_POSTFIELDS, conn->post_data);
      curl_easy_setopt(conn->easy, CURLOPT_POSTFIELDSIZE, conn->post_data_size);
      break;
    case KATIPO_HEAD:
      curl_easy_setopt(conn->easy, CURLOPT_CUSTOMREQUEST, "HEAD");
      break;
    case KATIPO_OPTIONS:
      curl_easy_setopt(conn->easy, CURLOPT_CUSTOMREQUEST, "OPTIONS");
      break;
    default:
      errx(2, "Uknown method: '%ld'", method);
  }
}

static void new_conn(long method, char *url, struct curl_slist *req_headers,
                     struct curl_slist *req_cookies, char *post_data,
                     long post_data_size, EasyOpts eopts, erlang_pid *pid,
                     erlang_ref *ref, GlobalInfo *global) {
  ConnInfo *conn;
  CURLMcode rc;
  struct curl_slist *nc;

  conn = calloc(1, sizeof(ConnInfo));
  memset(conn, 0, sizeof(ConnInfo));
  conn->error[0] = '\0';

  conn->memory = (char *)malloc(1);
  conn->size = 0;
  conn->num_headers = 0;
  conn->resp_headers = NULL;

  conn->easy = curl_easy_init();
  if (!conn->easy) {
    errx(2, "curl_easy_init() failed, exiting!\n");
  }
  conn->global = global;
  conn->url = url;
  conn->pid = pid;
  conn->ref = ref;
  conn->req_headers = req_headers;
  conn->req_cookies = req_cookies;
  conn->post_data = post_data;
  conn->post_data_size = post_data_size;

  curl_easy_setopt(conn->easy, CURLOPT_URL, conn->url);
  curl_easy_setopt(conn->easy, CURLOPT_HTTPHEADER, conn->req_headers);
  // curl_easy_setopt(conn->easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
  curl_easy_setopt(conn->easy, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(conn->easy, CURLOPT_WRITEDATA, conn);
  curl_easy_setopt(conn->easy, CURLOPT_HEADERFUNCTION, header_cb);
  curl_easy_setopt(conn->easy, CURLOPT_HEADERDATA, conn);
  // curl_easy_setopt(conn->easy, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(conn->easy, CURLOPT_ERRORBUFFER, conn->error);
  curl_easy_setopt(conn->easy, CURLOPT_PRIVATE, conn);
  curl_easy_setopt(conn->easy, CURLOPT_ACCEPT_ENCODING, "gzip,deflate");

  curl_easy_setopt(conn->easy, CURLOPT_CONNECTTIMEOUT_MS,
                   eopts.curlopt_connecttimeout_ms);
  curl_easy_setopt(conn->easy, CURLOPT_FOLLOWLOCATION,
                   eopts.curlopt_followlocation);
  curl_easy_setopt(conn->easy, CURLOPT_SSL_VERIFYHOST,
                   eopts.curlopt_ssl_verifyhost);
  curl_easy_setopt(conn->easy, CURLOPT_SSL_VERIFYPEER,
                   eopts.curlopt_ssl_verifypeer);
  if (eopts.curlopt_capath != NULL) {
    curl_easy_setopt(conn->easy, CURLOPT_CAPATH,
                     eopts.curlopt_capath);
  }
  curl_easy_setopt(conn->easy, CURLOPT_TIMEOUT_MS, eopts.curlopt_timeout_ms);
  curl_easy_setopt(conn->easy, CURLOPT_MAXREDIRS, eopts.curlopt_maxredirs);
  if (eopts.curlopt_http_auth != -1) {
    curl_easy_setopt(conn->easy, CURLOPT_HTTPAUTH,
                     eopts.curlopt_http_auth);
  }
  if (eopts.curlopt_username != NULL) {
    curl_easy_setopt(conn->easy, CURLOPT_USERNAME,
                     eopts.curlopt_username);
  }
  if (eopts.curlopt_password != NULL) {
    curl_easy_setopt(conn->easy, CURLOPT_PASSWORD,
                     eopts.curlopt_password);
  }
  if (eopts.curlopt_proxy != NULL) {
    curl_easy_setopt(conn->easy, CURLOPT_PROXY,
		     eopts.curlopt_proxy);
  }
  curl_easy_setopt(conn->easy, CURLOPT_COOKIEFILE, "");
  nc = req_cookies;
  while (nc) {
    curl_easy_setopt(conn->easy, CURLOPT_COOKIELIST, nc->data);
    nc = nc->next;
  }

  if (eopts.curlopt_capath != NULL) {
    free(eopts.curlopt_capath);
  }
  if (eopts.curlopt_username != NULL) {
    free(eopts.curlopt_username);
  }
  if (eopts.curlopt_password != NULL) {
    free(eopts.curlopt_password);
  }

  set_method(method, conn);
  rc = curl_multi_add_handle(global->multi, conn->easy);
  mcode_or_die("new_conn: curl_multi_add_handle", rc);
}

static void erl_input(struct bufferevent *ev, void *arg) {
  u_int32_t len;
  size_t data_read;
  char *buf;
  int index;
  int version;
  int arity;
  int erl_type;
  int size;
  long sizel;
  erlang_pid *pid;
  erlang_ref *ref;
  long method;
  char *url;

  GlobalInfo *global = (GlobalInfo *)arg;
  struct evbuffer *input = bufferevent_get_input(from_erlang);
  struct curl_slist *req_headers;
  struct curl_slist *req_cookies;
  char *header;
  char *cookie;
  int num_headers;
  int num_cookies;
  int i;
  char *post_data;
  long post_data_size;
  EasyOpts eopts;
  int num_eopts;
  long eopt;
  long eopt_long;
  char* eopt_binary = NULL;

  while (global->to_get > 0 || evbuffer_get_length(input) > sizeof(len)) {
    if (global->to_get > 0) {
      len = global->to_get;
      global->to_get = 0;
    } else {
      if (bufferevent_read(from_erlang, &len, sizeof(len)) != sizeof(len)) {
        errx(2, "Couldn't allocate len");
      }
      len = ntohl(len);
    }

    if (evbuffer_get_length(input) < len) {
      global->to_get = len;
      break;
    }

    buf = (char *)malloc(len);

    data_read = bufferevent_read(from_erlang, buf, len);
    if (data_read != len) {
      errx(2, "Wanted to read %u bytes data but got %zu", len, data_read);
    }

    index = 0;

    pid = (erlang_pid *)malloc(sizeof(erlang_pid));
    ref = (erlang_ref *)malloc(sizeof(erlang_ref));
    if (ei_decode_version(buf, &index, &version) ||
        ei_decode_tuple_header(buf, &index, &arity) ||
        ei_decode_pid(buf, &index, pid) ||
        ei_decode_ref(buf, &index, ref) ||
        ei_decode_long(buf, &index, &method) ||
        ei_get_type(buf, &index, &erl_type, &size)) {
      errx(2, "Couldn't read req");
    }

    url = (char *)malloc(size + 1);

    if (ei_decode_binary(buf, &index, url, &sizel)) {
      errx(2, "Couldn't read url");
    }

    url[size] = '\0';

    if (ei_decode_list_header(buf, &index, &num_headers)) {
      errx(2, "Couldn't decode headers length");
    }
    req_headers = NULL;
    for (i = 0; i < num_headers; i++) {
      if (ei_get_type(buf, &index, &erl_type, &size)) {
        errx(2, "Couldn't read header size");
      }
      header = (char *)malloc(size + 1);
      if (ei_decode_binary(buf, &index, header, &sizel)) {
        errx(2, "Couldn't read header");
      }
      header[size] = '\0';
      req_headers = curl_slist_append(req_headers, header);
      free(header);
    }

    if (num_headers > 0 && ei_skip_term(buf, &index)) {
      errx(2, "Couldn't skip empty list");
    }

    if (ei_decode_list_header(buf, &index, &num_cookies)) {
      errx(2, "Couldn't decode cookies length");
    }
    req_cookies = NULL;
    for (i = 0; i < num_cookies; i++) {
      if (ei_get_type(buf, &index, &erl_type, &size)) {
        errx(2, "Couldn't read cookie size");
      }
      cookie = (char *)malloc(size + 1);
      if (ei_decode_binary(buf, &index, cookie, &sizel)) {
        errx(2, "Couldn't read cookie");
      }
      cookie[size] = '\0';
      req_cookies = curl_slist_append(req_cookies, cookie);
      free(cookie);
    }

    if (num_cookies > 0 && ei_skip_term(buf, &index)) {
      errx(2, "Couldn't skip empty list");
    }

    if (ei_get_type(buf, &index, &erl_type, &size)) {
      errx(2, "Couldn't read req body size");
    }

    post_data = (char *)malloc(size);

    if (ei_decode_binary(buf, &index, post_data, &post_data_size)) {
      errx(2, "Couldn't read req body size");
    }

    eopts.curlopt_connecttimeout_ms = 30000;
    eopts.curlopt_followlocation = 0;
    eopts.curlopt_ssl_verifyhost = 2;
    eopts.curlopt_ssl_verifypeer = 1;
    eopts.curlopt_capath = NULL;
    eopts.curlopt_timeout_ms = 30000;
    eopts.curlopt_maxredirs = 100;
    eopts.curlopt_http_auth = -1;
    eopts.curlopt_username = NULL;
    eopts.curlopt_password = NULL;
    eopts.curlopt_proxy = NULL;

    if (ei_decode_list_header(buf, &index, &num_eopts)) {
      errx(2, "Couldn't decode eopts length");
    }
    for (i = 0; i < num_eopts; i++) {
      if (ei_decode_tuple_header(buf, &index, &arity) ||
          ei_decode_long(buf, &index, &eopt)) {
        errx(2, "Couldn't read eopt tuple");
      }

      if (ei_get_type(buf, &index, &erl_type, &size)) {
        errx(2, "Couldn't read eopt type");
      }
      switch (erl_type) {
      case ERL_SMALL_INTEGER_EXT:
      case ERL_INTEGER_EXT:
        if (ei_decode_long(buf, &index, &eopt_long)) {
          errx(2, "Couldn't read eopt long value");
        }
        break;
      case ERL_BINARY_EXT:
        eopt_binary = (char *)malloc(size + 1);
        if (ei_decode_binary(buf, &index, eopt_binary, &sizel)) {
          errx(2, "Couldn't read eopt binary value");
        }
        eopt_binary[size] = '\0';
        break;
      case ERL_ATOM_EXT:
        // assuming this is 'undefined' == NULL
        if (ei_skip_term(buf, &index)) {
          errx(2, "Couldn't skip eopt atom value");
        }
        break;
      default:
        errx(2, "Couldn't read eopt value '%c'", erl_type);
        break;
      }

      switch (eopt) {
        case K_CURLOPT_CONNECTTIMEOUT_MS:
          eopts.curlopt_connecttimeout_ms = eopt_long;
          break;
        case K_CURLOPT_FOLLOWLOCATION:
          eopts.curlopt_followlocation = eopt_long;
          break;
        case K_CURLOPT_SSL_VERIFYHOST:
          eopts.curlopt_ssl_verifyhost = eopt_long;
          break;
        case K_CURLOPT_SSL_VERIFYPEER:
          eopts.curlopt_ssl_verifypeer = eopt_long;
          break;
        case K_CURLOPT_CAPATH:
          if (erl_type == ERL_BINARY_EXT) {
            eopts.curlopt_capath = eopt_binary;
          }
          break;
        case K_CURLOPT_TIMEOUT_MS:
          eopts.curlopt_timeout_ms = eopt_long;
          break;
        case K_CURLOPT_MAXREDIRS:
          eopts.curlopt_maxredirs = eopt_long;
          break;
        case K_CURLOPT_HTTP_AUTH:
          if (erl_type != ERL_ATOM_EXT) {
            if (eopt_long == K_CURLAUTH_BASIC) {
              eopts.curlopt_http_auth = CURLAUTH_BASIC;
            } else if (eopt_long == K_CURLAUTH_DIGEST) {
              eopts.curlopt_http_auth = CURLAUTH_DIGEST;
            }
          }
        case K_CURLOPT_USERNAME:
          if (erl_type == ERL_BINARY_EXT) {
            eopts.curlopt_username = eopt_binary;
          }
          break;
        case K_CURLOPT_PASSWORD:
          if (erl_type == ERL_BINARY_EXT) {
            eopts.curlopt_password = eopt_binary;
          }
          break;
        case K_CURLOPT_PROXY:
	  if (erl_type == ERL_BINARY_EXT) {
	    eopts.curlopt_proxy = eopt_binary;
	  }
	  break;
        default:
          errx(2, "Unknown eopt value %ld", eopt);
      }
    }

    if (num_eopts > 0 && ei_skip_term(buf, &index)) {
      errx(2, "Couldn't skip empty eopt list");
    }

    new_conn(method, url, req_headers, req_cookies, post_data, post_data_size,
             eopts, pid, ref, arg);

    free(buf);
  }
}

static void erl_error(struct bufferevent *ev, short event, void *ud) {
  exit(-1);
}

static void erlang_init(GlobalInfo *global) {
  from_erlang =
      bufferevent_new(STDIN_FILENO, erl_input, NULL, erl_error, global);
  if (from_erlang == NULL) {
    errx(2, "bufferevent_new");
  }

  to_erlang = bufferevent_new(STDOUT_FILENO, NULL, NULL, erl_error, global);
  if (to_erlang == NULL) {
    errx(2, "bufferevent_new");
  }

  bufferevent_setwatermark(from_erlang, EV_READ, 4, 0);
  bufferevent_enable(from_erlang, EV_READ);
  bufferevent_enable(to_erlang, EV_WRITE);
}

int main(int argc, char **argv) {
  GlobalInfo global;
  int option_index = 0;
  int pipelining_flag = 0;
  int c;
  struct option long_options[] = {
    { "pipelining", no_argument, &pipelining_flag, 1 },
    { "max-pipeline-length", required_argument, 0, 'a' },
    { 0, 0, 0, 0 }
  };

  memset(&global, 0, sizeof(GlobalInfo));
  global.evbase = event_init();

  if (curl_global_init(CURL_GLOBAL_ALL)) {
    errx(2, "curl_global_init failed");
  }
  global.multi = curl_multi_init();
  if (!global.multi) {
    errx(2, "curl_multi_init failed");
  }
  global.timer_event = evtimer_new(global.evbase, timer_cb, &global);
  global.to_get = 0;

  curl_multi_setopt(global.multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
  curl_multi_setopt(global.multi, CURLMOPT_SOCKETDATA, &global);
  curl_multi_setopt(global.multi, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
  curl_multi_setopt(global.multi, CURLMOPT_TIMERDATA, &global);

  while (1) {
    c = getopt_long(argc, argv, "a:", long_options, &option_index);
    if (c == -1)
      break;
    switch (c) {
      case 0:
        break;
      case 'a':
        curl_multi_setopt(global.multi, CURLMOPT_MAX_PIPELINE_LENGTH,
                          atoi(optarg));
        break;
      default:
        errx(2, "Unknown option '%c'\n", c);
    }
  }

  curl_multi_setopt(global.multi, CURLMOPT_PIPELINING, pipelining_flag);

  erlang_init(&global);

  event_base_dispatch(global.evbase);

  return (0);
}
