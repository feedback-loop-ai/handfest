#!/usr/bin/env bash
# Single-responsibility deterministic gate 2: check-links
# Verifies EVERY URL, DOI (via Crossref API), and arXiv ID (via arXiv API)
# in docs/paper/references.bib and docs/paper/handfest-ricardian-mandates.tex.
set -euo pipefail

prompt_file="${1:-}"
[ -f "$prompt_file" ] || { echo "check-links: prompt file missing" >&2; exit 2; }
result_path=""
while IFS= read -r line; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    case "$trimmed" in /*.json) result_path="$trimmed" ;; esac
done < "$prompt_file"
[ -n "$result_path" ] || { echo "check-links: result path missing" >&2; exit 2; }
mkdir -p "$(dirname "$result_path")" ".brokkr/state/paper-audit"

python3 - "$result_path" <<'PY'
import json, pathlib, re, sys, urllib.error, urllib.parse, urllib.request, xml.etree.ElementTree as ET

result_path = pathlib.Path(sys.argv[1])
bib_report_path = pathlib.Path(".brokkr/state/paper-audit/bib-report.json")
tex_path = pathlib.Path("docs/paper/handfest-ricardian-mandates.tex")
report_path = pathlib.Path(".brokkr/state/paper-audit/links-report.json")

UA = "handfest-arxiv-verifier/1.0 (mailto:valentin.yanakiev@gmail.com)"

def fetch(url: str, timeout: int = 20):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.geturl(), resp.read(256 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, url, ""
    except Exception as e:
        return 0, url, str(e)

def norm_words(s: str) -> set[str]:
    s = re.sub(r"\\[a-zA-Z]+\{([^}]*)\}", r"\1", s)
    s = re.sub(r"[{}]", "", s)
    return {w for w in re.findall(r"[a-z0-9]+", s.lower()) if len(w) > 2}

bib_report = json.loads(bib_report_path.read_text(encoding="utf-8"))
entries = bib_report.get("entries", {})
errors = []
checks = []

# 1. Verify every DOI, arXiv eprint, and URL in BibTeX entries
for key, info in sorted(entries.items()):
    f = info["fields"]
    entry_check = {"key": key, "bib_title": f.get("title", ""), "bib_year": f.get("year", ""), "verifications": []}
    doi = f.get("doi", "").strip()
    eprint = f.get("eprint", "").strip()
    url = f.get("url", "").strip()

    if doi:
        api = f"https://api.crossref.org/works/{urllib.parse.quote(doi, safe='')}"
        code, final_url, body = fetch(api)
        if code != 200:
            errors.append(f"{key}: DOI {doi} failed Crossref lookup (HTTP {code})")
            entry_check["verifications"].append({"kind": "doi", "doi": doi, "status": code})
        else:
            msg = json.loads(body).get("message", {})
            cr_title = (msg.get("title") or [""])[0]
            overlap = len(norm_words(f.get("title", "")) & norm_words(cr_title)) / max(1, len(norm_words(f.get("title", ""))))
            entry_check["verifications"].append({"kind": "doi", "doi": doi, "status": 200, "crossref_title": cr_title, "title_overlap": round(overlap, 2)})
            if overlap < 0.5:
                errors.append(f"{key}: DOI {doi} title mismatch (bib='{f.get('title','')}' vs crossref='{cr_title}')")

    if eprint and (f.get("archiveprefix", "").lower() == "arxiv" or re.match(r"^\d{4}\.\d{4,5}", eprint)):
        api = f"https://export.arxiv.org/api/query?id_list={urllib.parse.quote(eprint, safe='')}"
        code, _, body = fetch(api)
        if code != 200:
            errors.append(f"{key}: arXiv {eprint} failed API lookup (HTTP {code})")
            entry_check["verifications"].append({"kind": "arxiv", "eprint": eprint, "status": code})
        else:
            root = ET.fromstring(body)
            ns = {"a": "http://www.w3.org/2005/Atom"}
            titles = [el.text.strip() for el in root.findall("a:entry/a:title", ns) if el.text]
            ax_title = titles[0] if titles else ""
            overlap = len(norm_words(f.get("title", "")) & norm_words(ax_title)) / max(1, len(norm_words(f.get("title", ""))))
            entry_check["verifications"].append({"kind": "arxiv", "eprint": eprint, "status": 200, "arxiv_title": ax_title, "title_overlap": round(overlap, 2)})
            if not ax_title or overlap < 0.5:
                errors.append(f"{key}: arXiv {eprint} title mismatch (bib='{f.get('title','')}' vs arxiv='{ax_title}')")

    if url:
        code, final_url, _ = fetch(url)
        entry_check["verifications"].append({"kind": "url", "url": url, "status": code, "final_url": final_url})
        if code not in (200, 301, 302, 303, 307, 308, 403):
            # 403 is flagged as warning only if DOI/arXiv already verified; if no DOI/arXiv, fail closed!
            errors.append(f"{key}: URL {url} unreachable (HTTP {code})")
        elif code == 403 and not (doi or eprint):
            errors.append(f"{key}: URL {url} returned HTTP 403 with no DOI/arXiv verification")

    checks.append(entry_check)

# 2. Verify all raw URLs in .tex (\url{...} and \href{...}{...})
tex = re.sub(r"(?<!\\)%.*", "", tex_path.read_text(encoding="utf-8"))
tex_urls = sorted(set(re.findall(r"\\(?:url|href)\{(https?://[^}]+)\}", tex)))
tex_url_checks = []
for u in tex_urls:
    code, final_url, _ = fetch(u)
    tex_url_checks.append({"url": u, "status": code, "final_url": final_url})
    if code not in (200, 301, 302, 303, 307, 308):
        errors.append(f"tex URL {u} failed (HTTP {code})")

report = {"bib_checks": checks, "tex_urls": tex_url_checks, "errors": errors}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

if errors:
    out = {"result": "fail", "notes": "check-links failed:\n" + "\n".join(f"- {e}" for e in errors)}
else:
    out = {"result": "pass", "notes": f"check-links passed: verified {len(checks)} BibTeX entries (DOI/arXiv/URL) and {len(tex_url_checks)} inline TeX URLs; report at {report_path}"}
result_path.write_text(json.dumps(out) + "\n", encoding="utf-8")
PY
