/* Shared prelude for the katipo fuzz targets.
 *
 * Each target compiles c_src/katipo.c into itself, so the static functions
 * are reachable without exporting anything from the shipped port. The
 * port's main() is renamed out of the way, and errx() is routed to
 * katipo_fatal(), which aborts: the pipe from Erlang is trusted, so every
 * input a target feeds the port is one Erlang could send, and the port
 * dying on one is a bug worth a crash report. */
#ifndef KATIPO_FUZZ_COMMON_H
#define KATIPO_FUZZ_COMMON_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void katipo_fatal(int status, const char *fmt, ...)
    __attribute__((noreturn, format(printf, 2, 3)));

#define main katipo_main
#define errx katipo_fatal
#include "../c_src/katipo.c"
#undef errx
#undef main

void katipo_fatal(int status, const char *fmt, ...) {
  va_list ap;

  fprintf(stderr, "katipo_fatal(%d): ", status);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  abort();
}

/* An invariant the target checks; a failure is reported as a crash. */
#define FUZZ_ASSERT(cond)                                                   \
  do {                                                                      \
    if (!(cond)) {                                                          \
      fprintf(stderr, "%s:%d: invariant failed: %s\n", __FILE__, __LINE__, \
              #cond);                                                       \
      abort();                                                              \
    }                                                                       \
  } while (0)

/* A cursor over the fuzzer's input. Reads past the end yield zeros, so a
 * target never has to bail out half way through building its input. */
typedef struct {
  const uint8_t *data;
  size_t size;
} FuzzInput;

static inline uint8_t fi_u8(FuzzInput *in) {
  uint8_t v = 0;
  if (in->size > 0) {
    v = in->data[0];
    in->data++;
    in->size--;
  }
  return v;
}

static inline uint16_t fi_u16(FuzzInput *in) {
  uint16_t hi = fi_u8(in);
  return (uint16_t)(hi << 8 | fi_u8(in));
}

/* Up to max bytes, the length coming from the input itself. */
static inline size_t fi_bytes(FuzzInput *in, size_t max, const uint8_t **out) {
  size_t len = fi_u16(in);
  if (len > max) {
    len = max;
  }
  if (len > in->size) {
    len = in->size;
  }
  *out = in->data;
  in->data += len;
  in->size -= len;
  return len;
}

#endif
