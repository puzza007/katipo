/* T1: the response header state machine (header_cb + encode_headers).
 *
 * The input is a series of header lines, each a 16-bit length then the
 * bytes, passed to header_cb one call per line as curl does. A model of
 * what the headers list should hold afterwards is kept alongside, and the
 * list the port would send Erlang is decoded and compared with it:
 *
 *  - it decodes as a proper list of exactly num_headers binaries;
 *  - each is the line with trailing CR/LF stripped and any other CR, LF or
 *    NUL replaced by a space (RFC 9110 5.5);
 *  - only the lines since the last status line are there, and none that
 *    came after that response's blank line (trailers are dropped). */
#include "fuzz_common.h"

#define MAX_LINES 256
#define MAX_LINE 4096

typedef struct {
  size_t len;
  uint8_t bytes[MAX_LINE];
} ModelLine;

static ModelLine model[MAX_LINES];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzInput in = {data, size};
  ConnInfo *conn = calloc(1, sizeof(*conn));
  size_t model_n = 0;
  int model_interim = 0;
  int model_ended = 0;
  ei_x_buff out;
  int index = 0;
  int version;
  int n;

  FUZZ_ASSERT(conn != NULL);
  FUZZ_ASSERT(ei_x_new(&conn->resp_headers) == 0);

  for (int line = 0; line < MAX_LINES && in.size > 0; line++) {
    const uint8_t *bytes;
    size_t len = fi_bytes(&in, MAX_LINE, &bytes);
    /* header_cb may write through the pointer it is given in a future
     * version; hand it a private copy so the input stays intact. */
    uint8_t *copy = malloc(len ? len : 1);
    size_t stripped = len;

    FUZZ_ASSERT(copy != NULL);
    memcpy(copy, bytes, len);
    FUZZ_ASSERT(header_cb(copy, 1, len, conn) == len);
    free(copy);

    while (stripped > 0 &&
           (bytes[stripped - 1] == '\r' || bytes[stripped - 1] == '\n')) {
      stripped--;
    }
    if (stripped == 0) {
      if (!model_interim) {
        model_ended = 1;
      }
      continue;
    }
    if (stripped > 5 && memcmp(bytes, "HTTP", 4) == 0 &&
        (bytes[4] == '/' || bytes[4] == ' ') && bytes[5] >= '0' &&
        bytes[5] <= '9') {
      const uint8_t *space = memchr(bytes + 4, ' ', stripped - 4);
      model_n = 0;
      model_interim = space != NULL && space + 1 < bytes + stripped &&
                      space[1] == '1';
      model_ended = 0;
    } else if (model_ended) {
      continue;
    }
    model[model_n].len = stripped;
    for (size_t i = 0; i < stripped; i++) {
      uint8_t c = bytes[i];
      model[model_n].bytes[i] = (c == '\r' || c == '\n' || c == '\0') ? ' ' : c;
    }
    model_n++;
  }

  FUZZ_ASSERT(conn->num_headers == model_n);

  FUZZ_ASSERT(ei_x_new_with_version(&out) == 0);
  encode_headers(&out, conn);

  FUZZ_ASSERT(ei_decode_version(out.buff, &index, &version) == 0);
  FUZZ_ASSERT(ei_decode_list_header(out.buff, &index, &n) == 0);
  FUZZ_ASSERT((size_t)n == model_n);
  for (int i = 0; i < n; i++) {
    int type;
    int bin_size;
    long got;
    char *bin;

    FUZZ_ASSERT(ei_get_type(out.buff, &index, &type, &bin_size) == 0);
    FUZZ_ASSERT(type == ERL_BINARY_EXT);
    FUZZ_ASSERT((size_t)bin_size == model[i].len);
    bin = malloc(bin_size ? bin_size : 1);
    FUZZ_ASSERT(bin != NULL);
    FUZZ_ASSERT(ei_decode_binary(out.buff, &index, bin, &got) == 0);
    FUZZ_ASSERT(memcmp(bin, model[i].bytes, bin_size) == 0);
    free(bin);
  }
  if (n > 0) {
    /* The tail of a non-empty proper list. */
    FUZZ_ASSERT(ei_decode_list_header(out.buff, &index, &n) == 0 && n == 0);
  }
  FUZZ_ASSERT(index == out.index);

  ei_x_free(&out);
  ei_x_free(&conn->resp_headers);
  free(conn);
  return 0;
}
