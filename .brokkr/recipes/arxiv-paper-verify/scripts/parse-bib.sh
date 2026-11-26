#!/usr/bin/env bash
# Single-responsibility deterministic gate 1: parse-bib
# Verifies 1:1 bijection between \cite{...} keys in .tex and entries in .bib,
# rejects duplicate BibTeX keys, and verifies required fields per entry type.
set -euo pipefail

prompt_file="${1:-}"
[ -f "$prompt_file" ] || { echo "parse-bib: prompt file missing" >&2; exit 2; }
result_path=""
while IFS= read -r line; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    case "$trimmed" in /*.json) result_path="$trimmed" ;; esac
done < "$prompt_file"
[ -n "$result_path" ] || { echo "parse-bib: result path missing" >&2; exit 2; }
mkdir -p "$(dirname "$result_path")" ".brokkr/state/paper-audit"

python3 - "$result_path" <<'PY'
import json, pathlib, re, sys

result_path = pathlib.Path(sys.argv[1])
tex_path = pathlib.Path("docs/paper/handfest-ricardian-mandates.tex")
bib_path = pathlib.Path("docs/paper/references.bib")
report_path = pathlib.Path(".brokkr/state/paper-audit/bib-report.json")

errors = []
if not tex_path.is_file():
    errors.append(f"missing {tex_path}")
if not bib_path.is_file():
    errors.append(f"missing {bib_path}")

cited = set()
entries = {}
dups = []

if not errors:
    tex = tex_path.read_text(encoding="utf-8")
    # Strip comments
    tex_nc = re.sub(r"(?<!\\)%.*", "", tex)
    for m in re.finditer(r"\\cite[a-zA-Z*]*\s*(?:\[[^\]]*\]\s*)*\{([^}]+)\}", tex_nc):
        for k in m.group(1).split(","):
            k = k.strip()
            if k:
                cited.add(k)

    bib = bib_path.read_text(encoding="utf-8")
    # Parse @type{key, ...}
    pos = 0
    while True:
        m = re.search(r"@([a-zA-Z]+)\s*\{\s*([^,\s]+)\s*,", bib[pos:])
        if not m:
            break
        etype = m.group(1).lower()
        key = m.group(2).strip()
        start = pos + m.end()
        depth = 1
        i = start
        while i < len(bib) and depth > 0:
            if bib[i] == "{":
                depth += 1
            elif bib[i] == "}":
                depth -= 1
            i += 1
        body = bib[start : i - 1]
        pos = i
        if etype in ("comment", "preamble", "string"):
            continue
        if key in entries:
            dups.append(key)
        fields = {}
        for fm in re.finditer(r"([a-zA-Z0-9_-]+)\s*=\s*(\{(?:[^{}]|\{[^{}]*\})*\}|\"[^\"]*\"|\d+)", body, re.S):
            fname = fm.group(1).lower()
            fval = fm.group(2).strip()
            if (fval.startswith("{") and fval.endswith("}")) or (fval.startswith('"') and fval.endswith('"')):
                fval = fval[1:-1].strip()
            fields[fname] = fval
        entries[key] = {"type": etype, "fields": fields}

    if dups:
        errors.append(f"duplicate BibTeX keys: {sorted(dups)}")
    missing = sorted(cited - set(entries.keys()))
    uncited = sorted(set(entries.keys()) - cited)
    if missing:
        errors.append(f"undefined \\cite keys: {missing}")
    if uncited:
        errors.append(f"uncited .bib entries: {uncited}")
    for key, info in sorted(entries.items()):
        f = info["fields"]
        for req in ("title", "year"):
            if not f.get(req):
                errors.append(f"{key}: missing required field '{req}'")
        if not (f.get("author") or f.get("editor")):
            errors.append(f"{key}: missing 'author' or 'editor'")

report = {
    "cited_count": len(cited),
    "bib_count": len(entries),
    "entries": entries,
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

if errors:
    out = {"result": "fail", "notes": "parse-bib failed:\n" + "\n".join(f"- {e}" for e in errors)}
else:
    out = {"result": "pass", "notes": f"parse-bib passed: {len(cited)} cited keys match {len(entries)} BibTeX entries 1:1 with zero duplicates and all required fields present; report at {report_path}"}
result_path.write_text(json.dumps(out) + "\n", encoding="utf-8")
PY
