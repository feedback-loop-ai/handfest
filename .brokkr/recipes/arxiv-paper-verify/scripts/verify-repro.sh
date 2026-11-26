#!/usr/bin/env bash
# Deterministic verifier seat. The box denies network; Cargo is also told
# explicitly to stay offline so a cache miss is reported as such.
# Each command's output is kept beside the result, as <result>.cargo-test.log
# and <result>.compile.log, so a passing verify keeps its per-binary times
# and a killed one keeps what it reached (operator, 2026-11-11).
set -u

prompt_file="${1:-}"
[ -f "$prompt_file" ] || { echo "verify-seat: prompt file missing" >&2; exit 2; }
result_path=""
while IFS= read -r line; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    case "$trimmed" in /*.json) result_path="$trimmed" ;; esac
done < "$prompt_file"
[ -n "$result_path" ] || { echo "verify-seat: result path missing from prompt" >&2; exit 2; }
mkdir -p "$(dirname "$result_path")"
notes_file="$(dirname "$result_path")/verify-seat-notes.$$"
trap 'rm -f "$notes_file"' EXIT

write_result() {
    seat_result="$1"
    awk -v result="$seat_result" '
      function json(text, out, i, byte, character) {
        for (i = 1; i <= length(text); i++) {
          character = substr(text, i, 1)
          if (character == "\\") out = out "\\\\"
          else if (character == "\"") out = out "\\\""
          else {
            for (byte = 1; byte < 32 && character != sprintf("%c", byte); byte++) {}
            out = out (byte < 32 ? sprintf("\\u%04x", byte) : character)
          }
        }
        return out
      }
      BEGIN { printf "{\"result\": \"%s\", \"notes\": \"", result }
      { if (NR > 1) printf "\\n"; printf "%s", json($0) }
      END { print "\"}" }' "$notes_file" > "$result_path"
}

failure_notes() {
    command_name="$1"
    printf '%s failed; decisive output follows verbatim:\n' "$command_name" > "$notes_file"
    grep -E '^test .+ \.\.\. FAILED$' "$output" | tail -n 20 >> "$notes_file" || true
    awk '/panicked at/ { print; if (getline > 0) print }' "$output" \
        | tail -n 20 >> "$notes_file" || true
    grep -E '^test result: FAILED|^error: test failed' "$output" \
        | tail -n 20 >> "$notes_file" || true
    grep -E '(^|[[:space:]])(error|Error|ERROR|Caused by|not found|offline)' "$output" \
        | tail -n 20 >> "$notes_file" || true
    [ "$(wc -l < "$notes_file")" -gt 1 ] || tail -n 20 "$output" >> "$notes_file"
    successful_summaries="$(grep -c '^test result: ok' "$output" || true)"
    failed_summaries="$(grep -c '^test result: FAILED' "$output" || true)"
    printf 'counts: %s successful test-suite summaries, %s failed\n' \
        "$successful_summaries" "$failed_summaries" >> "$notes_file"
    write_result fail
    exit 0
}

export CARGO_NET_OFFLINE=true
output="${result_path%.json}.cargo-test.log"
if ! cargo test --workspace --locked > "$output" 2>&1 </dev/null; then
    failure_notes "cargo test --workspace --locked"
fi
test_summaries="$(grep -c '^test result: ok' "$output" || true)"
output="${result_path%.json}.clippy.log"
if ! cargo clippy --workspace --all-targets --locked -- -D warnings > "$output" 2>&1 </dev/null; then
    failure_notes "cargo clippy --workspace --all-targets --locked -- -D warnings"
fi
output="${result_path%.json}.fmt.log"
if ! cargo fmt --all -- --check > "$output" 2>&1 </dev/null; then
    failure_notes "cargo fmt --all -- --check"
fi
printf 'cargo test --workspace --locked: %s successful test-suite summaries, 0 failed; cargo clippy --workspace --all-targets --locked -- -D warnings: passed; cargo fmt --all -- --check: passed (offline from the bound Cargo registry cache); outputs kept beside this result as .cargo-test.log, .clippy.log and .fmt.log' "$test_summaries" > "$notes_file"
write_result pass
