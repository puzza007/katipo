/* T2: decoding requests and commands from Erlang (handle_frame).
 *
 * The pipe from Erlang is trusted, so this target only builds terms Erlang
 * can send: the input picks a series of requests, cancels and flow grants,
 * and each is encoded as katipo_worker encodes it -- every option present
 * once, each value an integer, a binary or 'undefined', integers anywhere
 * in the range katipo_req's guards let through, encoded as term_to_binary
 * encodes them. Each frame goes through
 * handle_frame against a real curl multi handle; no transfer is run.
 *
 * Checked after every frame:
 *  - the port sends nothing back (a request Erlang accepted must not come
 *    back as bad_opts);
 *  - the in-flight list holds exactly the requests not yet cancelled, each
 *    findable by its {Pid, Ref};
 *  - a flow grant adds to the window of a bounded streaming request. */
#include "fuzz_common.h"
#include "fuzz_etf.h"

#define MAX_OPS 32
#define MAX_LIVE 64

static GlobalInfo global;

typedef struct {
  erlang_pid pid;
  erlang_ref ref;
  long window;
  int live;
} Live;

static Live live[MAX_LIVE];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  global_init(&global);
  /* No fd: whatever the port writes to Erlang accumulates in the output
   * evbuffer, where the target reads it back. */
  global.to_erlang = bufferevent_socket_new(global.evbase, -1, 0);
  FUZZ_ASSERT(global.to_erlang != NULL);
  return 0;
}

/* {Id, Value} for each option, in katipo_worker's order. */
enum { INT_POS, INT_BOOL, INT_VERIFYHOST, INT_GE_M1, INT_AUTH, INT_HTTPVER,
       INT_SSLVER, INT_WINDOW, BIN_OR_UNDEF };

static const struct { long id; int kind; } opts[] = {
  {K_CURLOPT_CONNECTTIMEOUT_MS, INT_POS},
  {K_CURLOPT_FOLLOWLOCATION, INT_BOOL},
  {K_CURLOPT_SSL_VERIFYHOST, INT_VERIFYHOST},
  {K_CURLOPT_SSL_VERIFYPEER, INT_BOOL},
  {K_CURLOPT_CAPATH, BIN_OR_UNDEF},
  {K_CURLOPT_CACERT, BIN_OR_UNDEF},
  {K_CURLOPT_TIMEOUT_MS, INT_POS},
  {K_CURLOPT_MAXREDIRS, INT_GE_M1},
  {K_CURLOPT_HTTP_AUTH, INT_AUTH},
  {K_CURLOPT_USERNAME, BIN_OR_UNDEF},
  {K_CURLOPT_PASSWORD, BIN_OR_UNDEF},
  {K_CURLOPT_PROXY, BIN_OR_UNDEF},
  {K_CURLOPT_TCP_FASTOPEN, INT_BOOL},
  {K_CURLOPT_INTERFACE, BIN_OR_UNDEF},
  {K_CURLOPT_UNIX_SOCKET_PATH, BIN_OR_UNDEF},
  {K_CURLOPT_DOH_URL, BIN_OR_UNDEF},
  {K_CURLOPT_HTTP_VERSION, INT_HTTPVER},
  {K_CURLOPT_SSLVERSION, INT_SSLVER},
  {K_CURLOPT_VERBOSE, INT_BOOL},
  {K_CURLOPT_SSLCERT, BIN_OR_UNDEF},
  {K_CURLOPT_SSLKEY, BIN_OR_UNDEF},
  {K_CURLOPT_SSLKEY_BLOB, BIN_OR_UNDEF},
  {K_CURLOPT_KEYPASSWD, BIN_OR_UNDEF},
  {K_CURLOPT_USERPWD, BIN_OR_UNDEF},
  {K_CURLOPT_DNS_CACHE_TIMEOUT, INT_GE_M1},
  {K_CURLOPT_CA_CACHE_TIMEOUT, INT_GE_M1},
  {K_CURLOPT_PIPEWAIT, INT_BOOL},
  {K_CURLOPT_STREAM, INT_BOOL},
  {K_CURLOPT_STREAM_WINDOW, INT_WINDOW},
};
#define NUM_OPTS (sizeof(opts) / sizeof(opts[0]))

/* Encodes the option list; returns the stream window the port should
 * start the request with (-1 for unbounded). The port keeps it whether or
 * not the request streams. */
static long encode_opts(ei_x_buff *x, FuzzInput *in) {
  long window = -1;

  FUZZ_ASSERT(ei_x_encode_list_header(x, NUM_OPTS) == 0);
  for (size_t i = 0; i < NUM_OPTS; i++) {
    uint8_t pick = fi_u8(in);
    FUZZ_ASSERT(ei_x_encode_tuple_header(x, 2) == 0);
    encode_int(x, 0, (uint64_t)opts[i].id);
    switch (opts[i].kind) {
    case INT_POS:
      encode_int(x, 0, pos_int(in));
      break;
    case INT_BOOL:
      encode_int(x, 0, pick & 1);
      break;
    case INT_VERIFYHOST:
      encode_int(x, 0, (pick & 1) ? 2 : 0);
      break;
    case INT_GE_M1:
      if (pick & 1) {
        encode_int(x, 1, 1);
      } else {
        encode_int(x, 0, pos_int(in) - 1);
      }
      break;
    case INT_AUTH:
      encode_int(x, 0, K_CURLAUTH_BASIC + pick % 5);
      break;
    case INT_HTTPVER:
      /* none, 1.0, 1.1, 2, 2tls, 2 prior knowledge (and 3, 30). */
      encode_int(x, 0, (uint64_t[]){0, 1, 2, 3, 4, 5, 30}[pick % 7]);
      break;
    case INT_SSLVER:
      encode_int(x, 0, pick % 8);
      break;
    case INT_WINDOW:
      if (pick & 1) {
        encode_int(x, 1, 1);
        window = -1;
      } else {
        uint64_t w = pos_int(in);
        encode_int(x, 0, w);
        window = w > LONG_MAX ? -2 : (long)w;
      }
      break;
    case BIN_OR_UNDEF:
      if (pick & 1) {
        encode_bin(x, in);
      } else {
        FUZZ_ASSERT(ei_x_encode_atom(x, "undefined") == 0);
      }
      break;
    }
  }
  FUZZ_ASSERT(ei_x_encode_empty_list(x) == 0);
  return window;
}

/* Run one frame through the port and check it said nothing back. */
static void run_frame(ei_x_buff *x) {
  struct evbuffer *out = bufferevent_get_output(global.to_erlang);
  char *buf = malloc(x->index);

  FUZZ_ASSERT(buf != NULL);
  memcpy(buf, x->buff, x->index);
  handle_frame(&global, buf);
  free(buf);
  if (evbuffer_get_length(out) != 0) {
    char *term = NULL;
    int index = 1;
    ei_s_print_term(&term, x->buff, &index);
    fprintf(stderr, "port replied to a frame Erlang could send (%zu bytes):\n%s\n",
            evbuffer_get_length(out), term ? term : "?");
    abort();
  }
}

static size_t count_active(void) {
  size_t n = 0;
  for (ConnInfo *c = global.active_conns; c; c = c->next) {
    n++;
  }
  return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzInput in = {data, size};
  uint32_t next_id = 0;
  size_t live_n = 0;

  memset(live, 0, sizeof(live));

  for (int op = 0; op < MAX_OPS && in.size > 0; op++) {
    uint8_t kind = fi_u8(&in);
    ei_x_buff x;
    erlang_pid pid;
    erlang_ref ref;

    FUZZ_ASSERT(ei_x_new_with_version(&x) == 0);
    if (kind % 4 < 2 && next_id < MAX_LIVE) {
      /* {Pid, Ref, Method, Url, Headers, CookieJar, Body, Opts} */
      Live *l = &live[next_id];
      make_pid(&pid, fi_u8(&in));
      make_ref(&ref, next_id++);
      FUZZ_ASSERT(ei_x_encode_tuple_header(&x, 8) == 0);
      FUZZ_ASSERT(ei_x_encode_pid(&x, &pid) == 0);
      FUZZ_ASSERT(ei_x_encode_ref(&x, &ref) == 0);
      encode_int(&x, 0, fi_u8(&in) % 7);
      encode_bin(&x, &in);
      encode_bin_list(&x, &in);
      encode_bin_list(&x, &in);
      if (fi_u8(&in) & 1) {
        encode_bin_list(&x, &in); /* an iolist body */
      } else {
        encode_bin(&x, &in);
      }
      l->window = encode_opts(&x, &in);
      l->pid = pid;
      l->ref = ref;
      l->live = 1;
      run_frame(&x);
      live_n++;
    } else if (next_id > 0) {
      uint32_t id = fi_u8(&in) % next_id;
      Live *l = &live[id];
      if (kind % 4 == 2) {
        /* {Pid, Ref, cancel} */
        FUZZ_ASSERT(ei_x_encode_tuple_header(&x, 3) == 0);
        FUZZ_ASSERT(ei_x_encode_pid(&x, &l->pid) == 0);
        FUZZ_ASSERT(ei_x_encode_ref(&x, &l->ref) == 0);
        FUZZ_ASSERT(ei_x_encode_atom(&x, "cancel") == 0);
        run_frame(&x);
        if (l->live) {
          l->live = 0;
          live_n--;
        }
        FUZZ_ASSERT(find_conn(&global, &l->pid, &l->ref) == NULL);
      } else {
        /* {Pid, Ref, flow, N} */
        uint64_t n = pos_int(&in);
        FUZZ_ASSERT(ei_x_encode_tuple_header(&x, 4) == 0);
        FUZZ_ASSERT(ei_x_encode_pid(&x, &l->pid) == 0);
        FUZZ_ASSERT(ei_x_encode_ref(&x, &l->ref) == 0);
        FUZZ_ASSERT(ei_x_encode_atom(&x, "flow") == 0);
        encode_int(&x, 0, n);
        run_frame(&x);
        if (l->live && l->window >= 0) {
          ConnInfo *c = find_conn(&global, &l->pid, &l->ref);
          FUZZ_ASSERT(c != NULL);
          /* The window must only grow, and stay a credit count: going
           * negative would turn a bounded stream unbounded. */
          FUZZ_ASSERT(c->window >= l->window);
          l->window = c->window;
        }
      }
    }
    ei_x_free(&x);

    FUZZ_ASSERT(count_active() == live_n);
    for (uint32_t i = 0; i < next_id; i++) {
      if (live[i].live) {
        ConnInfo *c = find_conn(&global, &live[i].pid, &live[i].ref);
        FUZZ_ASSERT(c != NULL);
        FUZZ_ASSERT(c->window == live[i].window);
      }
    }
  }

  while (global.active_conns) {
    free_conn(&global, global.active_conns);
  }
  return 0;
}
