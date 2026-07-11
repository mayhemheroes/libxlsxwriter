#!/usr/bin/env bash
#
# libxlsxwriter/mayhem/build.sh — build the project's single OSS-Fuzz harness (xlsx_fuzzer) as a
# sanitized libFuzzer target (+ a standalone run-once reproducer), AND the project's own C unit-test
# runner (xlsxwriter_unit) with NORMAL flags for mayhem/test.sh to run.
#
# Fuzzed surface: the xlsx_fuzzer harness drives libxlsxwriter's WORKBOOK BUILD/WRITE path. It uses
# FuzzedDataProvider to (1) write some attacker bytes into a temp file path, (2) open a workbook at
# that path, (3) add a worksheet and write fuzzer-derived strings into a fuzzer-chosen grid of cells,
# then (4) workbook_close() which serializes everything (XML generation, SST, minizip-zip the .xlsx
# container, md5 of any images). So the instrumented code is the workbook/worksheet/XML/zip writer,
# NOT an xlsx parser — the input is consumed as a FuzzedDataProvider stream, not parsed as a .xlsx.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE). We compile
# libxlsxwriter ITSELF (incl. vendored minizip/md5/tmpfileplus/dtoa) with $SANITIZER_FLAGS so the
# writer code is instrumented, not just the harness. zlib is a SYSTEM dep (find_package(ZLIB)).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

# $SRC is where the repo is baked (the org base sets it; default to repo root if unset).
: "${SRC:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export SRC
cd "$SRC"

OUT="/mayhem"
mkdir -p "$OUT"
HARNESS_DIR="$SRC/mayhem/harnesses"
INC="-I$SRC/include"

# ── 1) Build libxlsxwriter as a static lib WITH sanitizers (instrument the fuzzed writer) ──────────
#    Use the project's CMake so the vendored third_party/{minizip,md5,tmpfileplus} sources and the
#    correct compile-definitions are wired exactly as upstream builds them. CFLAGS/CXXFLAGS carry the
#    sanitizer flags into every TU. -DBUILD_FUZZERS=OFF here: we link the harness ourselves (twice).
SAN_BUILD="$SRC/mayhem-build"
rm -rf "$SAN_BUILD"
env CFLAGS="${CFLAGS:-} $SANITIZER_FLAGS $DEBUG_FLAGS" CXXFLAGS="${CXXFLAGS:-} $SANITIZER_FLAGS $DEBUG_FLAGS" \
  cmake -S "$SRC" -B "$SAN_BUILD" \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TESTS=OFF -DBUILD_FUZZERS=OFF -DBUILD_EXAMPLES=OFF \
    -DBUILD_SHARED_LIBS=OFF
cmake --build "$SAN_BUILD" --target xlsxwriter -j"$MAYHEM_JOBS"

LIBXLSX="$(find "$SAN_BUILD" -name 'libxlsxwriter.a' | head -1)"
[ -n "$LIBXLSX" ] || { echo "ERROR: libxlsxwriter.a not built" >&2; exit 1; }
echo "built sanitized static lib: $LIBXLSX"

ZLIB_LIB="$( { ldconfig -p 2>/dev/null | grep -m1 'libz\.so' | awk '{print $NF}'; } || true )"
: "${ZLIB_LIB:=-lz}"
case "$ZLIB_LIB" in /*) : ;; *) ZLIB_LIB="-lz" ;; esac

# ── 2) Build the harness twice: libFuzzer target (-> /mayhem/xlsx_fuzzer) + standalone reproducer ──
# libFuzzer target
$CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS $INC -DNDEBUG \
    "$HARNESS_DIR/xlsx_fuzzer.cpp" \
    $LIB_FUZZING_ENGINE "$LIBXLSX" "$ZLIB_LIB" \
    -o "$OUT/xlsx_fuzzer"

# standalone run-once reproducer (no libFuzzer runtime)
$CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS $INC -DNDEBUG \
    "$HARNESS_DIR/xlsx_fuzzer.cpp" "$HARNESS_DIR/standalone_main.cpp" \
    "$LIBXLSX" "$ZLIB_LIB" \
    -o "$OUT/xlsx_fuzzer-standalone"

echo "built xlsx_fuzzer (+ standalone)"

# ── 3) Build the project's OWN C unit-test runner with NORMAL flags (clean, separate tree) so
#       mayhem/test.sh only RUNS it. The unit tests use the vendored ctest.h harness (no external
#       deps; functional tests need pytest + Python and are intentionally NOT built here). ──────────
TEST_BUILD="$SRC/mayhem-tests"
rm -rf "$TEST_BUILD"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake -S "$SRC" -B "$TEST_BUILD" \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=ON -DBUILD_FUZZERS=OFF -DBUILD_EXAMPLES=OFF \
    -DBUILD_SHARED_LIBS=OFF
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake --build "$TEST_BUILD" --target xlsxwriter_unit -j"$MAYHEM_JOBS"
echo "built xlsxwriter_unit test runner in mayhem-tests/"

echo "build.sh complete:"
ls -la "$OUT/xlsx_fuzzer" "$OUT/xlsx_fuzzer-standalone" 2>&1 || true
