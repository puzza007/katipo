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
 *  - with a max_body_size, write_cb aborts the chunk that takes the body
 *    past it, and the transfer ends in an error at once, even when the
 *    chunk is the one curl re-delivers inside curl_easy_pause;
 *  - buffered: one ok message whose body is every byte delivered;
 *  - exactly one terminal message (ok, done or error), and it is last;
 *  - the transfer is freed.
 *
 * With a streamed request body (body => {stream, _}), chunked or of a
 * declared length, the input also interleaves curl's reads
 * (read_stream_cb, with any buffer size, never while the upload is paused
 * nor past a declared length) with the caller's chunks, eof and
 * undecodable commands (body_conn), in any order and after eof too, and
 * checks: a read returns the bytes sent, in order, as many as fit; with
 * nothing buffered it returns 0 after eof and otherwise pauses the upload;
 * exactly one demand goes out per pause with none outstanding; anything after
 * eof is ignored; a body past its declared length, eof short of it or an
 * undecodable command fails the upload, so reads abort and the transfer
 * ends in an error even if curl finished. */
/* curl re-delivers the chunk it held while paused inside curl_easy_pause,
 * and returns what write_cb made of it; this stand-in does the same. */
#define curl_easy_pause fuzz_easy_pause
#include "fuzz_common.h"
#include "fuzz_etf.h"

#define MAX_OPS 64
#define MAX_CHUNK 4096
#define MAX_BODY (MAX_OPS * MAX_CHUNK)

static GlobalInfo global;
/* The chunk curl holds for a paused transfer, and what write_cb returned
 * when fuzz_easy_pause re-delivered it (-1 = it was not). */
static const uint8_t *held = NULL;
static size_t held_len = 0;
static size_t redelivered = (size_t)-1;

CURLcode fuzz_easy_pause(CURL *easy, int bitmask) {
  ConnInfo *conn;

  if (held == NULL || (bitmask & CURLPAUSE_RECV) ||
      curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char **)&conn) != CURLE_OK) {
    return CURLE_OK;
  }
  redelivered = write_cb((void *)held, 1, held_len, conn);
  return redelivered == 0 ? CURLE_WRITE_ERROR : CURLE_OK;
}
static uint8_t delivered[MAX_BODY];
static uint8_t received[MAX_BODY];
static uint8_t sent_up[MAX_BODY];

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
  curl_easy_setopt(conn->easy, CURLOPT_PRIVATE, conn);
  conn->stream = stream;
  conn->window = window;
  conn->upload_fd = -1; /* no file body, so free_conn closes nothing */
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
  int upload = (mode & 4) != 0;
  long declared = (mode & 8) ? (long)fi_u8(&in) * 4 : -1; /* bytes, or chunked */
  long limit = (mode & 16) ? (long)fi_u8(&in) * 64 : -1; /* max_body_size */
  int ended = 0;      /* the port has completed the transfer itself */
  size_t sent_n = 0;  /* body bytes the port took */
  size_t read_n = 0;  /* body bytes curl read */
  int sent_eof = 0;   /* the port has eof */
  int read_eof = 0;
  int failed = 0;     /* the port should have failed the transfer */
  int demanded = 0;   /* the model's outstanding demand */
  int demands = 0;    /* demands the port should have sent */
  size_t delivered_n = 0;
  size_t received_n = 0;
  int ok;

  conn->body_limited = limit >= 0;
  conn->max_body_size = limit;
  if (upload) {
    conn->upload_stream = 1;
    conn->upload_size = declared;
    conn->upload_buf = evbuffer_new();
    FUZZ_ASSERT(conn->upload_buf != NULL);
  }

  for (int op = 0; op < MAX_OPS && in.size > 0; op++) {
    uint8_t kind = fi_u8(&in) % 5;
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
    } else if (kind == 3 && upload && !conn->upload_paused && !read_eof &&
               (declared < 0 || read_n < (size_t)declared)) {
      /* curl reads the body into a buffer of any size, but no further
       * than a declared length. */
      uint8_t buf[64];
      size_t want = fi_u8(&in) % sizeof(buf) + 1;
      size_t r = read_stream_cb((char *)buf, 1, want, conn);
      size_t avail = sent_n - read_n;
      if (failed) {
        FUZZ_ASSERT(r == CURL_READFUNC_ABORT);
        read_eof = 1; /* curl gives up the upload */
        continue;
      }
      if (avail > 0) {
        size_t n = avail < want ? avail : want;
        FUZZ_ASSERT(r == n);
        FUZZ_ASSERT(memcmp(buf, sent_up + read_n, n) == 0);
        read_n += n;
      } else if (sent_eof) {
        FUZZ_ASSERT(r == 0);
        read_eof = 1;
      } else {
        FUZZ_ASSERT(r == CURL_READFUNC_PAUSE && conn->upload_paused);
        if (!demanded) {
          demanded = 1;
          demands++;
        }
      }
      continue;
    } else if (kind == 4 && upload) {
      /* The caller sends a chunk or eof, or a command the port cannot
       * decode, even after eof. */
      uint8_t what = fi_u8(&in) % 8;
      int taken = !sent_eof && !failed;
      if (what == 0) {
        body_conn(&global, conn->pid, conn->ref, BODY_EOF, NULL, 0);
        if (taken) {
          sent_eof = 1;
          failed = declared >= 0 && sent_n < (size_t)declared;
        }
      } else if (what == 1) {
        body_conn(&global, conn->pid, conn->ref, BODY_BAD, NULL, 0);
        failed |= taken;
      } else {
        len = fi_bytes(&in, 512, &bytes);
        if (sent_n + len > MAX_BODY) {
          continue;
        }
        body_conn(&global, conn->pid, conn->ref, BODY_CHUNK, (const char *)bytes, len);
        if (taken && declared >= 0 && sent_n + len > (size_t)declared) {
          failed = 1;
        } else if (taken) {
          memcpy(sent_up + sent_n, bytes, len);
          sent_n += len;
        }
      }
      if (taken) {
        demanded = 0;
        FUZZ_ASSERT(!conn->upload_paused);
      }
      continue;
    } else if (kind == 2 && stream) {
      long n = fi_u8(&in) % 4 + 1;
      int over = limit >= 0 && delivered_n + held_len > (size_t)limit;
      redelivered = (size_t)-1;
      flow_conn(&global, conn->pid, conn->ref, n);
      if (credits >= 0) {
        credits += n;
      }
      if (held == NULL) {
        continue;
      }
      /* Resumed: curl delivered the held chunk again inside
       * curl_easy_pause. */
      FUZZ_ASSERT(redelivered != (size_t)-1);
      if (over) {
        /* curl_easy_pause failed, and arms nothing more: the port must
         * end the transfer then and there. */
        FUZZ_ASSERT(redelivered == 0 && global.active_conns == NULL);
        failed = 1;
        ended = 1;
        held = NULL;
        break;
      }
      FUZZ_ASSERT(redelivered == held_len);
      memcpy(delivered + delivered_n, held, held_len);
      delivered_n += held_len;
      held = NULL;
      continue;
    } else {
      continue;
    }

    if (held != NULL) {
      /* A chunk arriving from the socket. */
      int spent = stream && conn->window == 0;
      int over = limit >= 0 && delivered_n + held_len > (size_t)limit;
      size_t r = write_cb((void *)held, 1, held_len, conn);
      if (spent) {
        FUZZ_ASSERT(r == CURL_WRITEFUNC_PAUSE && conn->paused);
      } else if (over) {
        /* Short: curl aborts the transfer, and calls nothing more. */
        FUZZ_ASSERT(r == 0);
        failed = 1;
        break;
      } else {
        FUZZ_ASSERT(r == held_len);
        memcpy(delivered + delivered_n, held, held_len);
        delivered_n += held_len;
        held = NULL;
      }
    }
  }

  ok = fi_u8(&in) & 1;
  held = NULL;
  if (!ended) {
    complete_conn(&global, conn, ok ? CURLE_OK : CURLE_RECV_ERROR);
  }
  FUZZ_ASSERT(global.active_conns == NULL);

  {
    size_t total = evbuffer_get_length(out);
    char *all = malloc(total ? total : 1);
    size_t pos = 0;
    int headers = 0;
    int chunks = 0;
    int demand_frames = 0;
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
        FUZZ_ASSERT(stream && ok && !failed && headers == 1);
        terminal = 1;
      } else if (strcmp(f.tag, "ok") == 0) {
        FUZZ_ASSERT(!stream && ok && !failed);
        memcpy(received + received_n, f.body, f.body_len);
        received_n += f.body_len;
        terminal = 1;
      } else if (strcmp(f.tag, "demand") == 0) {
        FUZZ_ASSERT(upload);
        demand_frames++;
      } else if (strcmp(f.tag, "error") == 0) {
        FUZZ_ASSERT(!ok || failed);
        terminal = 1;
      } else {
        FUZZ_ASSERT(!"unknown message tag");
      }
    }
    FUZZ_ASSERT(terminal);
    FUZZ_ASSERT(demand_frames == demands);
    if (credits >= 0) {
      FUZZ_ASSERT(chunks <= credits);
    }
    /* An error drops a buffered body; anything else arrives in full. */
    if (stream || (ok && !failed)) {
      FUZZ_ASSERT(received_n == delivered_n);
      FUZZ_ASSERT(memcmp(received, delivered, delivered_n) == 0);
    }
    free(all);
  }
  return 0;
}
