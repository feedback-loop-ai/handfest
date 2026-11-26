#!/usr/bin/env bash
# Single-responsibility deterministic gate 4: build-pdf
# Compiles docs/paper/handfest-ricardian-mandates.tex with tectonic and fails
# on any TeX error, undefined reference/citation (??), or severe Overfull \hbox (>10pt).
set -euo pipefail
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

prompt_file="${1:-}"
[ -f "$prompt_file" ] || { echo "build-pdf: prompt file missing" >&2; exit 2; }
result_path=""
while IFS= read -r line; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    case "$trimmed" in /*.json) result_path="$trimmed" ;; esac
done < "$prompt_file"
[ -n "$result_path" ] || { echo "build-pdf: result path missing" >&2; exit 2; }
mkdir -p "$(dirname "$result_path")" ".brokkr/state/paper-audit"

tmp_out="$(mktemp -d)"
trap 'rm -rf "$tmp_out"' EXIT

log_out="${result_path%.json}.tectonic.log"
if ! tectonic -X compile docs/paper/handfest-ricardian-mandates.tex --outdir "$tmp_out" --keep-logs >"$log_out" 2>&1; then
    python3 - "$result_path" "$log_out" <<'PY'
import json, pathlib, sys
tail = pathlib.Path(sys.argv[2]).read_text(errors="replace").splitlines()[-30:]
pathlib.Path(sys.argv[1]).write_text(json.dumps({"result": "fail", "notes": "tectonic compile failed:\n" + "\n".join(tail)}) + "\n")
PY
    exit 0
fi

python3 - "$result_path" "$tmp_out/handfest-ricardian-mandates.log" "$tmp_out/handfest-ricardian-mandates.pdf" <<'PY'
import json, pathlib, re, sys

result_path = pathlib.Path(sys.argv[1])
log_text = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace")
pdf_path = pathlib.Path(sys.argv[3])
report_path = pathlib.Path(".brokkr/state/paper-audit/pdf-report.json")

errors = []
if not pdf_path.is_file() or pdf_path.stat().st_size < 1024:
    errors.append("compiled PDF missing or empty")

undef = re.findall(r"LaTeX Warning: (?:Reference|Citation) `([^']+)' .* undefined", log_text)
if undef:
    errors.append(f"undefined references/citations: {sorted(set(undef))}")

severe_overfull = []
for m in re.finditer(r"Overfull \\hbox \(([0-9.]+)pt too wide\)[^\n]*", log_text):
    if float(m.group(1)) > 10.0:
        severe_overfull.append(m.group(0))
if severe_overfull:
    errors.append(f"severe Overfull \\hbox (>10pt): {severe_overfull[:10]}")

report = {
    "pdf_bytes": pdf_path.stat().st_size if pdf_path.is_file() else 0,
    "undefined_refs": sorted(set(undef)),
    "severe_overfull": severe_overfull,
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

if errors:
    out = {"result": "fail", "notes": "build-pdf failed:\n" + "\n".join(f"- {e}" for e in errors)}
else:
    out = {"result": "pass", "notes": f"build-pdf passed: {report['pdf_bytes']} bytes, 0 undefined refs/cites, 0 severe overfull hboxes (>10pt)"}
result_path.write_text(json.dumps(out) + "\n", encoding="utf-8")
PY
