#!/usr/bin/env bash
#
# mayhem/build.sh — build pyodbc three ways:
#   1. NORMAL flags (setup.py build_ext --inplace) + a plain `pyodbc_python` interpreter: the oracle
#      that mayhem/test.sh runs the upstream suite under.
#   2. SANITIZED: every src/*.cpp compiled with $SANITIZER_FLAGS + SanCov, linked into the embedding
#      fuzz harness /mayhem/pyodbc_fuzz (and /mayhem/pyodbc_fuzz-standalone).
# Dependencies (python3-dev, unixodbc-dev, libsqliteodbc, pytest) are apt packages baked into the image,
# so a re-run needs no network.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

VERSION=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' pyproject.toml | head -n1)
PYINC=$(python3-config --includes)
PYLD=$(python3-config --embed --ldflags)
ODBC_CFLAGS=$( (odbc_config --cflags 2>/dev/null) || true)

# --- 1. oracle build: project's normal flags ---------------------------------------------------------
CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" python3 setup.py build_ext --inplace
$CC -O2 $COVERAGE_FLAGS $PYINC mayhem/pyodbc_python.c $PYLD -o /mayhem/pyodbc_python

# --- 2. fuzz build: sanitized project objects + embedding harness ------------------------------------
OBJ=/mayhem/build/fuzz
mkdir -p "$OBJ"
# -fno-sanitize=alignment: params.cpp packs SQLLEN indicators at unaligned offsets of its parameter
# buffers (e.g. params.cpp:802); it is benign on x86 but halts on the first bound parameter, which
# would starve every input. ASan and the rest of UBSan stay on.
FUZZ_CXXFLAGS="$SANITIZER_FLAGS -fno-sanitize=alignment $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link -Wno-write-strings \
  -fPIC -DPYODBC_VERSION=\"$VERSION\" $PYINC $ODBC_CFLAGS"

for f in src/*.cpp; do
  echo "$f"
done | xargs -P "$MAYHEM_JOBS" -I{} sh -c \
  '$0 $1 -c {} -o "$2/$(basename {} .cpp).o"' "$CXX" "$FUZZ_CXXFLAGS" "$OBJ"

# driver.py is baked into the harness as a byte array (no file access at fuzz time).
python3 - mayhem/pyodbc_fuzz/driver.py "$OBJ/driver_source.cc" <<'PY'
import sys
data = open(sys.argv[1], "rb").read() + b"\0"
body = ",".join(str(b) for b in data)
open(sys.argv[2], "w").write('extern "C" const char kDriverSource[] = {%s};\n' % body)
PY
$CXX -c "$OBJ/driver_source.cc" -o "$OBJ/driver_source.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OBJ/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link $PYINC -c mayhem/pyodbc_fuzz/pyodbc_fuzz.cc \
  -o "$OBJ/pyodbc_fuzz.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

PROJ_OBJS=$(ls "$OBJ"/*.o | grep -v -E '/(driver_source|lsan_off|pyodbc_fuzz|standalone_main)\.o$')

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $LIB_FUZZING_ENGINE \
  "$OBJ/pyodbc_fuzz.o" $PROJ_OBJS "$OBJ/driver_source.o" "$OBJ/lsan_off.o" $PYLD -lodbc \
  -o /mayhem/pyodbc_fuzz
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link \
  "$OBJ/pyodbc_fuzz.o" $PROJ_OBJS "$OBJ/driver_source.o" "$OBJ/lsan_off.o" "$OBJ/standalone_main.o" $PYLD -lodbc \
  -o /mayhem/pyodbc_fuzz-standalone
