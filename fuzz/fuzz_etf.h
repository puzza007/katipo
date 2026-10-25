/* Encoders for the terms katipo_worker sends the port, shared by the
 * targets that feed handle_frame. */
#ifndef KATIPO_FUZZ_ETF_H
#define KATIPO_FUZZ_ETF_H

#include "fuzz_common.h"

#ifndef MAX_STR
#define MAX_STR 2048
#endif
#ifndef MAX_LIST
#define MAX_LIST 8
#endif

static void make_pid(erlang_pid *pid, uint8_t n) {
  memset(pid, 0, sizeof(*pid));
  strcpy(pid->node, "nonode@nohost");
  pid->num = n % 4;
  pid->serial = 0;
  pid->creation = 1;
}

static void make_ref(erlang_ref *ref, uint32_t id) {
  memset(ref, 0, sizeof(*ref));
  strcpy(ref->node, "nonode@nohost");
  ref->len = 3;
  ref->n[0] = id;
  ref->n[1] = 7;
  ref->n[2] = 11;
  ref->creation = 1;
}

/* An integer the way term_to_binary writes it: SMALL_INTEGER_EXT for
 * 0..255, INTEGER_EXT for the rest of the 32-bit range, SMALL_BIG_EXT
 * beyond. Hand-encoded because ei's long encoder switches to a bignum
 * above 2^27, which term_to_binary never does. */
static void encode_int(ei_x_buff *x, int negative, uint64_t magnitude) {
  uint8_t b[3 + 8];
  int n = 0;

  if (!negative && magnitude <= 255) {
    b[0] = ERL_SMALL_INTEGER_EXT;
    b[1] = (uint8_t)magnitude;
    n = 2;
  } else if (magnitude <= (uint64_t)INT32_MAX + (negative ? 1 : 0)) {
    uint32_t v = negative ? (uint32_t)-(int64_t)magnitude : (uint32_t)magnitude;
    b[0] = ERL_INTEGER_EXT;
    b[1] = (uint8_t)(v >> 24);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 8);
    b[4] = (uint8_t)v;
    n = 5;
  } else {
    uint64_t m = magnitude;
    int digits = 0;
    while (m) {
      b[3 + digits++] = (uint8_t)m;
      m >>= 8;
    }
    b[0] = ERL_SMALL_BIG_EXT;
    b[1] = (uint8_t)digits;
    b[2] = (uint8_t)negative;
    n = 3 + digits;
  }
  FUZZ_ASSERT(ei_x_append_buf(x, (char *)b, n) == 0);
}

/* A positive integer of fuzzer-chosen width, up to 64 bits. */
static uint64_t pos_int_any(FuzzInput *in) {
  uint8_t width = fi_u8(in) % 9;
  uint64_t v = 0;
  for (int i = 0; i < width; i++) {
    v = v << 8 | fi_u8(in);
  }
  return v ? v : 1;
}

/* A positive integer option value or flow grant: katipo_req and
 * update_flow/3 accept up to 2^31-1 (?MAX_INT_OPT). */
static uint64_t pos_int(FuzzInput *in) {
  uint64_t v = pos_int_any(in) & 0x7fffffff;
  return v ? v : 1;
}

static void encode_bin(ei_x_buff *x, FuzzInput *in) {
  const uint8_t *bytes;
  size_t len = fi_bytes(in, MAX_STR, &bytes);
  FUZZ_ASSERT(ei_x_encode_binary(x, bytes, (int)len) == 0);
}

static void encode_bin_list(ei_x_buff *x, FuzzInput *in) {
  int n = fi_u8(in) % (MAX_LIST + 1);
  if (n > 0) {
    FUZZ_ASSERT(ei_x_encode_list_header(x, n) == 0);
    for (int i = 0; i < n; i++) {
      encode_bin(x, in);
    }
  }
  FUZZ_ASSERT(ei_x_encode_empty_list(x) == 0);
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

/* A request as katipo_worker sends it:
 * {Pid, Ref, Method, Url, Headers, CookieJar, Body, Opts}. Returns the
 * stream window the port should start it with, as encode_opts does. */
static long encode_request(ei_x_buff *x, FuzzInput *in, erlang_pid *pid,
                           erlang_ref *ref) {
  FUZZ_ASSERT(ei_x_encode_tuple_header(x, 8) == 0);
  FUZZ_ASSERT(ei_x_encode_pid(x, pid) == 0);
  FUZZ_ASSERT(ei_x_encode_ref(x, ref) == 0);
  encode_int(x, 0, fi_u8(in) % 7);
  encode_bin(x, in);
  encode_bin_list(x, in);
  encode_bin_list(x, in);
  switch (fi_u8(in) % 3) {
  case 0:
    encode_bin(x, in);
    break;
  case 1:
    encode_bin_list(x, in); /* an iolist body */
    break;
  default:
    /* {stream, Length}: -1, or a length up to 2^63-1, encoded as
     * term_to_binary encodes it. */
    FUZZ_ASSERT(ei_x_encode_tuple_header(x, 2) == 0);
    FUZZ_ASSERT(ei_x_encode_atom(x, "stream") == 0);
    if (fi_u8(in) & 1) {
      encode_int(x, 1, 1);
    } else {
      encode_int(x, 0, (pos_int_any(in) - 1) & 0x7fffffffffffffffULL);
    }
    break;
  }
  return encode_opts(x, in);
}

#endif
