/* A main() for replaying saved inputs through a fuzz target without
 * libFuzzer, so the regression corpus can run under any compiler. Each
 * argument is a file or a directory of files. */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
/* Optional in a target, as under libFuzzer. */
int LLVMFuzzerInitialize(int *argc, char ***argv) __attribute__((weak));

static int run_file(const char *path) {
  FILE *f = fopen(path, "rb");
  uint8_t *buf;
  long len;

  if (f == NULL || fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0) {
    perror(path);
    return 1;
  }
  rewind(f);
  buf = malloc(len ? (size_t)len : 1);
  if (buf == NULL || fread(buf, 1, (size_t)len, f) != (size_t)len) {
    perror(path);
    return 1;
  }
  fclose(f);
  LLVMFuzzerTestOneInput(buf, (size_t)len);
  free(buf);
  return 0;
}

static int run_path(const char *path) {
  struct stat st;
  DIR *dir;
  struct dirent *ent;
  int failed = 0;

  if (stat(path, &st) != 0) {
    perror(path);
    return 1;
  }
  if (!S_ISDIR(st.st_mode)) {
    return run_file(path);
  }
  if ((dir = opendir(path)) == NULL) {
    perror(path);
    return 1;
  }
  while ((ent = readdir(dir)) != NULL) {
    char child[4096];
    if (ent->d_name[0] == '.') {
      continue;
    }
    snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
    failed |= run_path(child);
  }
  closedir(dir);
  return failed;
}

int main(int argc, char **argv) {
  int failed = 0;

  if (LLVMFuzzerInitialize) {
    LLVMFuzzerInitialize(&argc, &argv);
  }
  for (int i = 1; i < argc; i++) {
    failed |= run_path(argv[i]);
  }
  return failed;
}
