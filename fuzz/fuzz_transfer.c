/* T4: what the port writes to Erlang for a transfer (write_cb, header_cb,
 * flow_conn, complete_conn and the send_*_to_erlang encoders).
 *
 * The input picks a buffered or streaming transfer, its stream window, and
 * a series of header lines, body chunks and flow grants, delivered as curl
 * delivers them: a chunk refused with CURL_WRITEFUNC_PAUSE is held and
 * delivered again once a grant resumes the transfer. The transfer then
 * finishes, with success or an error, through complete_conn. No transfer
 * is run; the easy handle is never added to the multi.
 *
 * Every frame the port wrote is then decoded, and checked:
 *  - its length prefix matches, and it decodes as {Tag, {{Pid, Ref}, _}}
 *    for this transfer, with a body frame's raw bytes after the term;
 *  - streaming: one headers message, before the first chunk, the chunks
 *    are the body bytes in order, write_cb pauses exactly when the window
 *    is spent, and no more chunks go out than the window and grants allow;
 *  - buffered: one ok message whose body is every byte delivered;
 *  - exactly one terminal message (ok, done or error), and it is last;
 *  - the transfer is freed. */
#include "fuzz_common.h"
#include "fuzz_etf.h"

#define MAX_OPS 64
#define MAX_CHUNK 4096
#define MAX_BODY (MAX_OPS * MAX_CHUNK)

static GlobalInfo global;
static uint8_t delivered[MAX_BODY];
static uint8_t received[MAX_BODY];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  global_init(&global);
  global.to_erlang = bufferevent_socket_new(global.evbase, -1, 0);
  FUZZ_ASSERT(global.to_erlang != NULL);
  /* A bufferevent freezes the start of its output buffer for its own
   * writes; the target drains it instead. */
  FUZZ_ASSERT(evbuffer_unfreeze(bufferevent_get_output(global.to_erlang), 1) == 0);
  return 0;
}

static ConnInfo *make_conn(int stream, long window) {
  ConnInfo *conn = calloc(1, sizeof(*conn));

  FUZZ_ASSERT(conn != NULL);
  conn->easy = curl_easy_init();
  conn->body = evbuffer_new();
  conn->pid = malloc(sizeof(*conn->pid));
  conn->ref = malloc(sizeof(*conn->ref));
  FUZZ_ASSERT(conn->easy && conn->body && conn->pid && conn->ref);
  FUZZ_ASSERT(ei_x_new(&conn->resp_headers) == 0);
  make_pid(conn->pid, 1);
  make_ref(conn->ref, 42);
  conn->global = &global;
  conn->stream = stream;
  conn->window = window;
  conn->upload_fd = -1; /* a buffered body, so free_conn closes nothing */
  register_conn(&global, conn);
  return conn;
}

/* A decoded frame: its tag, and for body frames the raw bytes after the
 * term. */
typedef struct {
  char tag[MAXATOMLEN];
  const char *body;
  size_t body_len;
} Frame;

/* Decode the frame in buf[0..len) and check its envelope. */
static void decode_frame(const char *buf, size_t len, Frame *f) {
  int index = 0;
  int version;
  int arity;
  int term_end;
  erlang_pid pid;
  erlang_ref ref;
  erlang_pid want_pid;
  erlang_ref want_ref;

  make_pid(&want_pid, 1);
  make_ref(&want_ref, 42);
  FUZZ_ASSERT(ei_decode_version(buf, &index, &version) == 0);
  term_end = index;
  FUZZ_ASSERT(ei_skip_term(buf, &term_end) == 0);
  FUZZ_ASSERT((size_t)term_end <= len);
  FUZZ_ASSERT(ei_decode_tuple_header(buf, &index, &arity) == 0 && arity == 2);
  FUZZ_ASSERT(ei_decode_atom(buf, &index, f->tag) == 0);
  FUZZ_ASSERT(ei_decode_tuple_header(buf, &index, &arity) == 0 && arity == 2);
  FUZZ_ASSERT(ei_decode_tuple_header(buf, &index, &arity) == 0 && arity == 2);
  FUZZ_ASSERT(ei_decode_pid(buf, &index, &pid) == 0);
  FUZZ_ASSERT(ei_decode_ref(buf, &index, &ref) == 0);
  FUZZ_ASSERT(ei_cmp_pids(&pid, &want_pid) == 0);
  FUZZ_ASSERT(ei_cmp_refs(&ref, &want_ref) == 0);

  f->body = buf + term_end;
  f->body_len = len - (size_t)term_end;
  /* Only ok and chunk carry raw body bytes after the term. */
  if (strcmp(f->tag, "ok") != 0 && strcmp(f->tag, "chunk") != 0) {
    FUZZ_ASSERT(f->body_len == 0);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzInput in = {data, size};
  struct evbuffer *out = bufferevent_get_output(global.to_erlang);
  uint8_t mode = fi_u8(&in);
  int stream = mode & 1;
  long window = (mode & 2) ? -1 : (long)(fi_u8(&in) % 8);
  long credits = window; /* chunks the window and grants allow */
  ConnInfo *conn = make_conn(stream, window);
  size_t delivered_n = 0;
  size_t received_n = 0;
  const uint8_t *held = NULL; /* a chunk refused with a pause */
  size_t held_len = 0;
  int ok;

  for (int op = 0; op < MAX_OPS && in.size > 0; op++) {
    uint8_t kind = fi_u8(&in) % 3;
    const uint8_t *bytes;
    size_t len;

    if (kind == 0 && held == NULL) {
      len = fi_bytes(&in, 512, &bytes);
      uint8_t *copy = malloc(len ? len : 1);
      FUZZ_ASSERT(copy != NULL);
      memcpy(copy, bytes, len);
      FUZZ_ASSERT(header_cb(copy, 1, len, conn) == len);
      free(copy);
    } else if (kind == 1 && held == NULL) {
      len = fi_bytes(&in, MAX_CHUNK, &bytes);
      if (len == 0) {
        continue; /* curl never calls write_cb with nothing */
      }
      held = bytes;
      held_len = len;
    } else if (kind == 2 && stream) {
      long n = fi_u8(&in) % 4 + 1;
      flow_conn(&global, conn->pid, conn->ref, n);
      if (credits >= 0) {
        credits += n;
      }
      if (held == NULL) {
        continue;
      }
      /* Resumed: curl delivers the held chunk again. */
    } else {
      continue;
    }

    if (held != NULL) {
      int spent = stream && conn->window == 0;
      size_t r = write_cb((void *)held, 1, held_len, conn);
      if (spent) {
        FUZZ_ASSERT(r == CURL_WRITEFUNC_PAUSE && conn->paused);
      } else {
        FUZZ_ASSERT(r == held_len);
        memcpy(delivered + delivered_n, held, held_len);
        delivered_n += held_len;
        held = NULL;
      }
    }
  }

  ok = fi_u8(&in) & 1;
  complete_conn(&global, conn, ok ? CURLE_OK : CURLE_RECV_ERROR);
  FUZZ_ASSERT(global.active_conns == NULL);

  {
    size_t total = evbuffer_get_length(out);
    char *all = malloc(total ? total : 1);
    size_t pos = 0;
    int headers = 0;
    int chunks = 0;
    int terminal = 0;

    FUZZ_ASSERT(all != NULL);
    FUZZ_ASSERT(evbuffer_remove(out, all, total) == (int)total);
    while (pos < total) {
      uint32_t flen;
      Frame f;

      FUZZ_ASSERT(!terminal); /* nothing after the terminal message */
      FUZZ_ASSERT(total - pos >= 4);
      memcpy(&flen, all + pos, 4);
      flen = ntohl(flen);
      pos += 4;
      FUZZ_ASSERT(flen <= total - pos);
      decode_frame(all + pos, flen, &f);
      pos += flen;

      if (strcmp(f.tag, "headers") == 0) {
        FUZZ_ASSERT(stream && headers == 0 && chunks == 0);
        headers++;
      } else if (strcmp(f.tag, "chunk") == 0) {
        FUZZ_ASSERT(stream && headers == 1 && f.body_len > 0);
        memcpy(received + received_n, f.body, f.body_len);
        received_n += f.body_len;
        chunks++;
      } else if (strcmp(f.tag, "done") == 0) {
        FUZZ_ASSERT(stream && ok && headers == 1);
        terminal = 1;
      } else if (strcmp(f.tag, "ok") == 0) {
        FUZZ_ASSERT(!stream && ok);
        memcpy(received + received_n, f.body, f.body_len);
        received_n += f.body_len;
        terminal = 1;
      } else if (strcmp(f.tag, "error") == 0) {
        FUZZ_ASSERT(!ok);
        terminal = 1;
      } else {
        FUZZ_ASSERT(!"unknown message tag");
      }
    }
    FUZZ_ASSERT(terminal);
    if (credits >= 0) {
      FUZZ_ASSERT(chunks <= credits);
    }
    /* An error drops a buffered body; anything else arrives in full. */
    if (stream || ok) {
      FUZZ_ASSERT(received_n == delivered_n);
      FUZZ_ASSERT(memcmp(received, delivered, delivered_n) == 0);
    }
    free(all);
  }
  return 0;
}
