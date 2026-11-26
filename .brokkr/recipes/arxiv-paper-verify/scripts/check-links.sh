#!/usr/bin/env bash
# Single-responsibility deterministic gate 2: check-links
# Verifies EVERY URL, DOI (via Crossref API), arXiv ID (via arXiv API),
# EU ELI (via EU Publications Office Cellar SPARQL), and PDF front-matter
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
import html, json, pathlib, re, subprocess, sys, tempfile, urllib.error, urllib.parse, urllib.request, xml.etree.ElementTree as ET

result_path = pathlib.Path(sys.argv[1])
bib_report_path = pathlib.Path(".brokkr/state/paper-audit/bib-report.json")
tex_path = pathlib.Path("docs/paper/handfest-ricardian-mandates.tex")
report_path = pathlib.Path(".brokkr/state/paper-audit/links-report.json")

UA = "handfest-arxiv-verifier/1.1 (mailto:valentin.yanakiev@gmail.com)"

def fetch_raw(url: str, timeout: int = 25, max_bytes: int = 512 * 1024):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            data = resp.read(max_bytes)
            return resp.status, resp.geturl(), ctype, data
    except urllib.error.HTTPError as e:
        return e.code, url, "", b""
    except Exception as e:
        return 0, url, "", str(e).encode("utf-8", errors="replace")

def fetch(url: str, timeout: int = 25):
    code, final_url, _, data = fetch_raw(url, timeout=timeout)
    return code, final_url, data.decode("utf-8", errors="replace")

def norm_words(s: str) -> set[str]:
    s = re.sub(r"\\[a-zA-Z]+\{([^}]*)\}", r"\1", s)
    s = re.sub(r"[{}]", "", s)
    return {w for w in re.findall(r"[a-z0-9]+", s.lower()) if len(w) > 2}

def strip_tags(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", html.unescape(s)).strip()

def extract_pdf_front_matter(data: bytes) -> str:
    try:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as tf:
            tf.write(data)
            tf.flush()
            proc = subprocess.run(
                ["pdftotext", "-f", "1", "-l", "2", tf.name, "-"],
                capture_output=True, text=True, timeout=15
            )
            if proc.returncode == 0:
                return re.sub(r"\s+", " ", proc.stdout).strip()[:900]
    except Exception:
        pass
    return ""

def extract_html_meta(body: str) -> dict:
    info = {}
    tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if tm:
        info["page_title"] = strip_tags(tm.group(1))[:200]
    headings = [strip_tags(m) for m in re.findall(r"<h[12][^>]*>(.*?)</h[12]>", body, re.I | re.S)]
    headings = [h for h in headings if h][:6]
    if headings:
        info["headings"] = headings
    authors = []
    dates = []
    for tag in re.findall(r"<meta\s+[^>]+>", body, re.I):
        nm = re.search(r'(?:name|property)=["\']([^"\']+)["\']', tag, re.I)
        cm = re.search(r'content=["\']([^"\']+)["\']', tag, re.I)
        if not (nm and cm):
            continue
        k = nm.group(1).lower()
        v = html.unescape(cm.group(1)).strip()
        if any(x in k for x in ("author", "creator")):
            authors.append(v)
        elif any(x in k for x in ("date", "published")):
            dates.append(v)
    if authors:
        info["meta_authors"] = authors[:8]
    if dates:
        info["meta_dates"] = dates[:4]
    return info

bib_report = json.loads(bib_report_path.read_text(encoding="utf-8"))
entries = bib_report.get("entries", {})
errors = []
checks = []

# 1. Verify every DOI, arXiv eprint, and URL in BibTeX entries
for key, info in sorted(entries.items()):
    f = info["fields"]
    entry_check = {
        "key": key,
        "bib_author": f.get("author", ""),
        "bib_title": f.get("title", ""),
        "bib_year": f.get("year", ""),
        "verifications": [],
    }
    doi = f.get("doi", "").strip()
    eprint = f.get("eprint", "").strip()
    url = f.get("url", "").strip()
    if not url:
        m_url = re.search(r"https?://[^\s},\"]+", f.get("note", "") + " " + f.get("howpublished", ""))
        if m_url:
            url = m_url.group(0).rstrip(".,;")

    if doi:
        api = f"https://api.crossref.org/works/{urllib.parse.quote(doi, safe='')}"
        code, final_url, body = fetch(api)
        if code != 200:
            errors.append(f"{key}: DOI {doi} failed Crossref lookup (HTTP {code})")
            entry_check["verifications"].append({"kind": "doi", "doi": doi, "status": code})
        else:
            msg = json.loads(body).get("message", {})
            cr_title = (msg.get("title") or [""])[0]
            cr_authors = [
                " ".join(x for x in (a.get("given", ""), a.get("family", "")) if x).strip() or a.get("name", "")
                for a in (msg.get("author") or msg.get("editor") or [])
            ]
            cr_year = None
            for dk in ("published-print", "published-online", "issued", "created"):
                parts = (msg.get(dk) or {}).get("date-parts") or []
                if parts and parts[0] and parts[0][0]:
                    cr_year = str(parts[0][0])
                    break
            cr_container = (msg.get("container-title") or [""])[0]
            overlap = len(norm_words(f.get("title", "")) & norm_words(cr_title)) / max(1, len(norm_words(f.get("title", ""))))
            entry_check["verifications"].append({
                "kind": "doi",
                "doi": doi,
                "status": 200,
                "crossref_title": cr_title,
                "crossref_authors": cr_authors,
                "crossref_year": cr_year,
                "crossref_container": cr_container,
                "title_overlap": round(overlap, 2),
            })
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
            titles = [re.sub(r"\s+", " ", el.text).strip() for el in root.findall("a:entry/a:title", ns) if el.text]
            ax_title = titles[0] if titles else ""
            ax_authors = [el.text.strip() for el in root.findall("a:entry/a:author/a:name", ns) if el.text]
            pub = [el.text.strip() for el in root.findall("a:entry/a:published", ns) if el.text]
            ax_year = pub[0][:4] if pub else None
            overlap = len(norm_words(f.get("title", "")) & norm_words(ax_title)) / max(1, len(norm_words(f.get("title", ""))))
            entry_check["verifications"].append({
                "kind": "arxiv",
                "eprint": eprint,
                "status": 200,
                "arxiv_title": ax_title,
                "arxiv_authors": ax_authors,
                "arxiv_year": ax_year,
                "title_overlap": round(overlap, 2),
            })
            if not ax_title or overlap < 0.5:
                errors.append(f"{key}: arXiv {eprint} title mismatch (bib='{f.get('title','')}' vs arxiv='{ax_title}')")

    if url:
        eli_m = re.match(r"^https?://data\.europa\.eu/eli/(.+)$", url)
        if eli_m:
            rel = eli_m.group(1).strip("/")
            q = (
                "PREFIX cdm: <http://publications.europa.eu/ontology/cdm#> "
                "SELECT ?title WHERE { ?work cdm:resource_legal_eli ?eli . "
                f'FILTER(STR(?eli) = "{rel}" || STR(?eli) = "http://data.europa.eu/eli/{rel}") '
                "?expr cdm:expression_belongs_to_work ?work ; "
                "cdm:expression_uses_language <http://publications.europa.eu/resource/authority/language/ENG> ; "
                "cdm:expression_title ?title . } LIMIT 1"
            )
            sparql_url = "https://publications.europa.eu/webapi/rdf/sparql?query=" + urllib.parse.quote(q)
            req = urllib.request.Request(sparql_url, headers={"Accept": "application/sparql-results+json", "User-Agent": UA})
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    rows = json.loads(resp.read().decode("utf-8", errors="replace")).get("results", {}).get("bindings", [])
                eli_title = rows[0]["title"]["value"] if rows else ""
                overlap = len(norm_words(f.get("title", "")) & norm_words(eli_title)) / max(1, len(norm_words(f.get("title", ""))))
                entry_check["verifications"].append({"kind": "eu_eli_cellar", "eli": rel, "status": 200, "cellar_title": eli_title[:240], "title_overlap": round(overlap, 2)})
                if not eli_title or overlap < 0.5:
                    errors.append(f"{key}: EU ELI {url} title mismatch via Cellar (bib='{f.get('title','')}' vs cellar='{eli_title[:120]}')")
            except Exception as exc:
                errors.append(f"{key}: EU ELI {url} Cellar SPARQL lookup failed: {exc}")
                entry_check["verifications"].append({"kind": "eu_eli_cellar", "eli": rel, "status": 0})
        else:
            is_pdf_hint = url.lower().endswith(".pdf")
            code, final_url, ctype, raw = fetch_raw(url, max_bytes=(4 * 1024 * 1024 if is_pdf_hint else 512 * 1024))
            ver = {"kind": "url", "url": url, "status": code, "final_url": final_url}
            if code == 200 and ("application/pdf" in ctype or is_pdf_hint or raw.startswith(b"%PDF")):
                front = extract_pdf_front_matter(raw)
                if front:
                    ver["pdf_front_matter"] = front
                    ver["title_overlap"] = round(len(norm_words(f.get("title", "")) & norm_words(front)) / max(1, len(norm_words(f.get("title", "")))), 2)
            elif code == 200:
                body = raw.decode("utf-8", errors="replace")
                meta = extract_html_meta(body)
                ver.update(meta)
                title_corpus = " ".join([meta.get("page_title", "")] + meta.get("headings", []))
                if title_corpus.strip():
                    ver["title_overlap"] = round(len(norm_words(f.get("title", "")) & norm_words(title_corpus)) / max(1, len(norm_words(f.get("title", "")))), 2)
                # For IETF Datatracker HTML drafts, also capture header author/date block
                if "datatracker.ietf.org/doc/html/" in final_url:
                    pm = re.search(r"<pre[^>]*class=[\"'][^\"']*newpage[^\"']*[\"'][^>]*>(.*?)</pre>", body, re.I | re.S)
                    if not pm:
                        pm = re.search(r"<table[^>]*class=[\"'][^\"']*ears[^\"']*[\"'][^>]*>(.*?)</table>", body, re.I | re.S)
                    if pm:
                        ver["ietf_header"] = strip_tags(pm.group(1))[:500]
                    else:
                        # Capture first 600 chars of visible text inside <body
                        bm = re.search(r"<body[^>]*>(.*?)</body>", body, re.I | re.S)
                        if bm:
                            ver["body_excerpt"] = strip_tags(bm.group(1))[:600]
            entry_check["verifications"].append(ver)
            if code not in (200, 301, 302, 303, 307, 308, 403):
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
    out = {"result": "pass", "notes": f"check-links passed: verified {len(checks)} BibTeX entries (DOI/arXiv/EU-ELI/PDF/HTML with authors, years, and front-matter) and {len(tex_url_checks)} inline TeX URLs; report at {report_path}"}
result_path.write_text(json.dumps(out) + "\n", encoding="utf-8")
PY
