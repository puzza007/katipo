/* T3: reassembling frames from the pipe (erl_input).
 *
 * The input picks a series of requests and cancels, encoded as
 * katipo_worker encodes them, and lays them end to end with the 4-byte
 * length prefix {packet, 4} adds. That stream is then handed to erl_input
 * in pieces of fuzzer-chosen sizes, as reads from the pipe would deliver
 * it, so a prefix or a term can be split anywhere.
 *
 * Checked after every piece:
 *  - exactly the frames that have arrived in full have been handled: the
 *    in-flight list holds the requests among them not cancelled since;
 *  - the port sends nothing back (every request is one Erlang accepted).
 * And at the end, nothing is left half read. */
#include "fuzz_common.h"
#include "fuzz_etf.h"

#define MAX_FRAMES 16

static GlobalInfo global;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  global_init(&global);
  /* No fds: the target writes the pipe's bytes straight into the input
   * evbuffer, and reads whatever the port writes back from the output. */
  global.from_erlang = bufferevent_socket_new(global.evbase, -1, 0);
  global.to_erlang = bufferevent_socket_new(global.evbase, -1, 0);
  FUZZ_ASSERT(global.from_erlang != NULL && global.to_erlang != NULL);
  /* A bufferevent freezes the end of its input buffer for its own reads;
   * the target stands in for those. */
  FUZZ_ASSERT(evbuffer_unfreeze(bufferevent_get_input(global.from_erlang), 0) == 0);
  return 0;
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
  struct evbuffer *pipe_in = bufferevent_get_input(global.from_erlang);
  struct evbuffer *out = bufferevent_get_output(global.to_erlang);
  ei_x_buff stream;
  /* Where each frame ends in the stream, and how many requests are in
   * flight once it has been handled. */
  size_t frame_end[MAX_FRAMES];
  size_t live_after[MAX_FRAMES];
  int frames = 0;
  int requests = 0;
  size_t live_n = 0;
  int latest_live = 0;
  size_t sent = 0;
  int handled = 0;

  FUZZ_ASSERT(ei_x_new(&stream) == 0);
  while (frames < MAX_FRAMES && in.size > 0) {
    ei_x_buff x;
    erlang_pid pid;
    erlang_ref ref;
    uint32_t len;

    FUZZ_ASSERT(ei_x_new_with_version(&x) == 0);
    if (requests == 0 || fi_u8(&in) % 3 != 0) {
      make_pid(&pid, 0);
      make_ref(&ref, (uint32_t)requests++);
      encode_request(&x, &in, &pid, &ref);
      latest_live = 1;
      live_n++;
    } else {
      /* {Pid, Ref, cancel} for the latest request; a repeat is a no-op. */
      make_pid(&pid, 0);
      make_ref(&ref, (uint32_t)requests - 1);
      FUZZ_ASSERT(ei_x_encode_tuple_header(&x, 3) == 0);
      FUZZ_ASSERT(ei_x_encode_pid(&x, &pid) == 0);
      FUZZ_ASSERT(ei_x_encode_ref(&x, &ref) == 0);
      FUZZ_ASSERT(ei_x_encode_atom(&x, "cancel") == 0);
      if (latest_live) {
        latest_live = 0;
        live_n--;
      }
    }
    len = htonl((uint32_t)x.index);
    FUZZ_ASSERT(ei_x_append_buf(&stream, (char *)&len, 4) == 0);
    FUZZ_ASSERT(ei_x_append_buf(&stream, x.buff, x.index) == 0);
    ei_x_free(&x);
    frame_end[frames] = (size_t)stream.index;
    live_after[frames] = live_n;
    frames++;
  }

  while (sent < (size_t)stream.index) {
    size_t piece = (size_t)fi_u16(&in) % 512 + 1;
    if (piece > (size_t)stream.index - sent) {
      piece = (size_t)stream.index - sent;
    }
    FUZZ_ASSERT(evbuffer_add(pipe_in, stream.buff + sent, piece) == 0);
    sent += piece;
    erl_input(global.from_erlang, &global);

    while (handled < frames && frame_end[handled] <= sent) {
      handled++;
    }
    FUZZ_ASSERT(count_active() == (handled ? live_after[handled - 1] : 0));
    FUZZ_ASSERT(evbuffer_get_length(out) == 0);
  }
  FUZZ_ASSERT(evbuffer_get_length(pipe_in) == 0);
  FUZZ_ASSERT(global.to_get == 0);

  ei_x_free(&stream);
  while (global.active_conns) {
    free_conn(&global, global.active_conns);
  }
  return 0;
}
