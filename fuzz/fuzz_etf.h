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

#endif
