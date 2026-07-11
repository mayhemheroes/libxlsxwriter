#!/usr/bin/env bash
#
# libxlsxwriter/mayhem/test.sh — RUN libxlsxwriter's OWN C unit-test suite (the xlsxwriter_unit
# runner built by mayhem/build.sh with normal flags) and emit a CTRF summary. exit 0 iff no test
# failed.
#
# PATCH-grade oracle: the unit suite (test/unit/**/test*.c, driven by the vendored ctest.h) asserts
# the EXACT XML/string output of every writer component (worksheet/workbook/sst/styles/chart/...)
# against hand-written expected strings via ASSERT_STR. A no-op / "return 0" patch, or any change
# that alters generated output, fails an assertion and the runner exits nonzero. This script only
# RUNS the pre-built runner; it never compiles. (Functional pytest tests need Python + the python
# xlsxwriter package and are intentionally out of scope here.)
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$SRC"

TEST_BUILD="$SRC/mayhem-tests"

# emit_ctrf <tool> <passed> <failed> [skipped]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}"
  local tests=$(( passed + failed + skipped ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": 0,
      "skipped": $skipped,
      "other": 0
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":0,"skipped":%d,"other":0}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$skipped"
  [ "$failed" -eq 0 ]
}

UNIT_BIN="$(find "$TEST_BUILD" -name 'xlsxwriter_unit' -type f -perm -u+x 2>/dev/null | head -1)"
if [ -z "$UNIT_BIN" ]; then
  echo "missing xlsxwriter_unit in $TEST_BUILD — run mayhem/build.sh first" >&2
  emit_ctrf "ctest-unit" 0 1 0; exit 2
fi

echo "=== running $UNIT_BIN ==="
# The image-properties unit test (workbook:get_image_properties, added upstream in 1b5c1ca) opens
# fixture images via paths relative to CWD ("../functional/src/images/<f>"), which resolve only when
# the runner is invoked from test/unit. Run there when present; fall back to $SRC otherwise.
RUN_DIR="$SRC/test/unit"; [ -d "$RUN_DIR" ] || RUN_DIR="$SRC"
out="$(cd "$RUN_DIR" && "$UNIT_BIN" 2>&1)"; rc=$?
echo "$out"

# ctest.h prints a final line: "RESULTS: N tests (N ok, N failed, N skipped) ran in X ms"
line="$(printf '%s\n' "$out" | grep -E '^RESULTS:' | tail -1)"
if [ -n "$line" ]; then
  TOTAL=$(printf '%s\n' "$line"  | sed -n 's/^RESULTS:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*tests.*/\1/p')
  PASSED=$(printf '%s\n' "$line" | sed -n 's/.*(\([0-9][0-9]*\)[[:space:]]*ok.*/\1/p')
  FAILED=$(printf '%s\n' "$line" | sed -n 's/.*ok,[[:space:]]*\([0-9][0-9]*\)[[:space:]]*failed.*/\1/p')
  SKIPPED=$(printf '%s\n' "$line" | sed -n 's/.*failed,[[:space:]]*\([0-9][0-9]*\)[[:space:]]*skipped.*/\1/p')
  : "${PASSED:=0}" "${FAILED:=0}" "${SKIPPED:=0}"
  emit_ctrf "ctest-unit" "$PASSED" "$FAILED" "$SKIPPED"
  exit $?
fi

# No parseable summary — fall back to the runner's exit code.
echo "could not parse ctest RESULTS line; using exit code $rc" >&2
if [ "$rc" -eq 0 ]; then emit_ctrf "ctest-unit" 1 0 0; exit 0; fi
emit_ctrf "ctest-unit" 0 1 0; exit 1
