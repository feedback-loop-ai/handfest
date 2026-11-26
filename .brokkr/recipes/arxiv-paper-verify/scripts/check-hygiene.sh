#!/usr/bin/env bash
# Single-responsibility deterministic gate 3: check-hygiene
# Enforces human-written arXiv submission hygiene:
# - sole human author Valentin Yanakiev (no AI co-author)
# - arXiv-compliant AI Assistance Disclosure present
# - no TODO/FIXME/TBD/XXX or leftover LLM prompt artifacts
# - no robotic "(MIT OR Apache-2.0, commit ...)" in abstract
# - no ASCII-art \begin{verbatim} architecture diagrams (TikZ required)
set -euo pipefail

prompt_file="${1:-}"
[ -f "$prompt_file" ] || { echo "check-hygiene: prompt file missing" >&2; exit 2; }
result_path=""
while IFS= read -r line; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    case "$trimmed" in /*.json) result_path="$trimmed" ;; esac
done < "$prompt_file"
[ -n "$result_path" ] || { echo "check-hygiene: result path missing" >&2; exit 2; }
mkdir -p "$(dirname "$result_path")" ".brokkr/state/paper-audit"

python3 - "$result_path" <<'PY'
import json, pathlib, re, sys

result_path = pathlib.Path(sys.argv[1])
tex_path = pathlib.Path("docs/paper/handfest-ricardian-mandates.tex")
report_path = pathlib.Path(".brokkr/state/paper-audit/hygiene-report.json")
tex = tex_path.read_text(encoding="utf-8")
tex_nc = re.sub(r"(?<!\\)%.*", "", tex)

errors = []

# 1. Author check
auth_m = re.search(r"\\author\{([^}]*)\}", tex_nc, re.S)
if not auth_m or "Valentin Yanakiev" not in auth_m.group(1):
    errors.append("missing \\author{Valentin Yanakiev}")
elif re.search(r"\b(claude|gpt|gemini|qwen|llm|ai assistant|chatgpt)\b", auth_m.group(1), re.I):
    errors.append("AI model/tool listed inside \\author{...} (violates arXiv policy)")

# 2. AI assistance disclosure present
if not re.search(r"AI Assistance Disclosure|LLM-assisted|generative AI", tex_nc, re.I):
    errors.append("missing arXiv-compliant AI Assistance Disclosure section/paragraph")

# 3. Forbidden placeholder / prompt artifacts
for pat, label in [
    (r"\b(TODO|FIXME|TBD|XXX)\b", "placeholder marker (TODO/FIXME/TBD/XXX)"),
    (r"as an ai language model|fill in the real numbers|insert citation here", "leftover LLM prompt artifact"),
]:
    if re.search(pat, tex_nc, re.I):
        errors.append(f"found forbidden {label}")

# 4. No robotic license/commit boilerplate in abstract
abs_m = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", tex_nc, re.S)
if abs_m:
    abstract = abs_m.group(1)
    if re.search(r"MIT OR Apache-2\.0|commit\s+[0-9a-f]{7}", abstract, re.I):
        errors.append("abstract contains robotic license/commit boilerplate; move artifact pointer to end of paper")

# 5. TikZ diagrams required, no box-drawing ASCII art in verbatim
if "\\usepackage{tikz}" not in tex_nc:
    errors.append("missing \\usepackage{tikz} for publication-grade diagrams")
if len(re.findall(r"\\begin\{tikzpicture\}", tex_nc)) < 2:
    errors.append("expected at least 2 TikZ diagrams (architecture diagram + abstract sequence diagram)")
for vm in re.finditer(r"\\begin\{verbatim\}(.*?)\\end\{verbatim\}", tex_nc, re.S):
    if re.search(r"[┌┐└┘│─┼├┤┬┴▼▲◄►]|\+---+\+", vm.group(1)):
        errors.append("found ASCII-art diagram inside \\begin{verbatim}; replace with TikZ vector diagram")

report = {"errors": errors, "tikzpicture_count": len(re.findall(r"\\begin\{tikzpicture\}", tex_nc))}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

if errors:
    out = {"result": "fail", "notes": "check-hygiene failed:\n" + "\n".join(f"- {e}" for e in errors)}
else:
    out = {"result": "pass", "notes": f"check-hygiene passed: author=Valentin Yanakiev, AI disclosure present, zero placeholders/ASCII art, {report['tikzpicture_count']} TikZ diagrams"}
result_path.write_text(json.dumps(out) + "\n", encoding="utf-8")
PY
