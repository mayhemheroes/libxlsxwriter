// standalone_main.cpp — single-file run-once driver for the libxlsxwriter OSS-Fuzz harness.
// Links against the harness's LLVMFuzzerTestOneInput (no libFuzzer runtime); reads ONE input file
// and feeds its bytes to the harness exactly once. Used for crash reproduction / replay.
#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
    return 1;
  }
  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    fprintf(stderr, "failed to open %s\n", argv[1]);
    return 2;
  }
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (size < 0) { fclose(f); return 3; }
  uint8_t *data = (uint8_t *)malloc(size ? size : 1);
  if (!data) { fclose(f); return 3; }
  size_t got = size ? fread(data, 1, (size_t)size, f) : 0;
  fclose(f);
  LLVMFuzzerTestOneInput(data, got);
  free(data);
  return 0;
}
