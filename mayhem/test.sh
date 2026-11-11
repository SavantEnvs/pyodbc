#!/usr/bin/env bash
#
# mayhem/test.sh — RUN pyodbc's own SQLite suite (tests/sqlite_test.py, through unixODBC and the
# SQLite3 ODBC driver) under the normal-flags build that mayhem/build.sh left in src/, plus known-answer
# probes. Both run through /mayhem/pyodbc_python (a project-built executable), so a neutered program
# yields no output and the script fails.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$skipped" "$pending" "$other"
  [ "$failed" -eq 0 ]
}

PY=/mayhem/pyodbc_python
[ -x "$PY" ] || { echo "missing $PY — mayhem/build.sh must build it" >&2; exit 1; }
ls src/pyodbc*.so >/dev/null 2>&1 || { echo "missing src/pyodbc*.so — mayhem/build.sh must build it" >&2; exit 1; }
export PYTHONPATH="$SRC/src" PYTHONDONTWRITEBYTECODE=1

passed=0 failed=0 skipped=0

# 1. Known-answer probes: exact expected output.
probe=$("$PY" mayhem/kat.py 2>&1)
expected=$(cat <<'EOT'
params 42 héllo 世界 0001fe bytes
decimal '12345.678' 12 -7 ['a', 'b', 'c']
count (6, 3)
named 3
version 5.5.0
EOT
)
if [ "$probe" = "$expected" ]; then
  echo "KAT probes: ok"; passed=$((passed + 5))
else
  echo "KAT probes: MISMATCH"; echo "--- got"; echo "$probe"; echo "--- expected"; echo "$expected"
  failed=$((failed + 1))
fi

# 2. Upstream functional suite.
log=$(mktemp)
"$PY" -m pytest -p no:cacheprovider -q -rf tests/sqlite_test.py 2>&1 | tee "$log"
summary=$(grep -E '^(=+ )?[0-9]+ (passed|failed|skipped|error)' "$log" | tail -n1 || true)
if [ -z "$summary" ]; then
  echo "pytest produced no summary line" >&2
  failed=$((failed + 1))
else
  count() { local n; n=$(grep -oE "[0-9]+ $1" <<<"$summary" | grep -oE '^[0-9]+' | head -n1); echo "${n:-0}"; }
  passed=$((passed + $(count passed)))
  failed=$((failed + $(count failed) + $(count error)))
  skipped=$((skipped + $(count skipped)))
fi
rm -f "$log"

emit_ctrf "pytest" "$passed" "$failed" "$skipped"
