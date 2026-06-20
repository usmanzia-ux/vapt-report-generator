# VAPT Report Generator

> Turn raw vulnerability-scanner output into clean, client-ready penetration-test reports — with consistent CVSS v3.1 scoring — in one command.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-pytest-success.svg)](tests/)

Writing VAPT reports by hand is the slowest part of any engagement. This tool
ingests the output you already produce — **Nmap**, **Nessus**, or a simple
**JSON/YAML findings file** for manual web/API/cloud findings — normalises every
finding into one model, (re)scores it with the official **CVSS v3.1** equations,
and renders a polished report in **HTML, PDF, or Excel**.

I built it to standardise the 50+ assessment reports I deliver, so the scoring,
severity ratings, and layout are identical every time regardless of which tool
found the issue.

---

## Features

- **Multi-source ingestion** — Nmap, Nessus, Nuclei, Burp Suite, OWASP ZAP,
  Acunetix, and a generic JSON/YAML findings format. Mix several scanners into
  one consolidated report.
- **Auto-detection** — point it at a file; it figures out the format.
- **Interactive wizard** — run `vaptreport` with no arguments for a guided,
  styled shell flow: pick input → pick template → choose format → name it.
- **CVSS v3.1 engine** — a spec-compliant base-score calculator (not a lookup
  table) derives scores from vectors and maps them to severity ratings.
- **Smart de-duplication** — the same Nessus plugin across many hosts becomes a
  single finding with all affected targets aggregated.
- **Four output formats** — PDF (default, via WeasyPrint), **Word (.docx)**,
  print-ready HTML, and a styled multi-sheet Excel workbook.
- **Bring your own template** — match your firm's branding with an HTML/Jinja2
  template *or* a **Word .docx template** that fills every field; a PDF template
  has its cover page reused. Falls back to a polished generic theme.
- **Safe by default** — report output is HTML-escaped, so an XSS payload sitting
  in a scanner's evidence field can't execute when the report is opened.
- **Executive + technical** — cover page, severity summary, findings overview
  table, and detailed per-finding sections with evidence and remediation.
- **Tested** — CVSS math and every parser/reporter are covered by `pytest`.

---

## Installation

```bash
git clone https://github.com/usmanzia-ux/vapt-report-generator.git
cd vapt-report-generator
pip install -e .

# Optional: PDF support (needs WeasyPrint system libs)
pip install -e ".[pdf]"

# Optional: Word (.docx) input templates and output
pip install -e ".[docx]"
```

---

## Quick start

```bash
# Guided interactive wizard — just run it with no arguments
vaptreport

# Default output is PDF — what most clients actually want
vaptreport examples/sample_findings.json -o report.pdf

# Ingest an Acunetix Developer Report PDF directly
vaptreport acunetix_developer_report.pdf -o report.pdf

# Consolidate many scanners into ONE report
vaptreport nmap.xml scan.nessus nuclei.jsonl burp.xml zap.json \
    -o engagement.pdf --client "Example Corporation"

# Use your company's own branded template (HTML/Jinja2 for pdf/html…)
vaptreport examples/sample_nessus.nessus -t examples/custom_template.html.j2 \
    -o branded_report.pdf

# …or a Word .docx template that fills every field, output as .docx
vaptreport examples/sample_nessus.nessus -f docx \
    -t examples/company_template.docx -o branded_report.docx

# Other formats: HTML (web preview) and a styled Excel workbook
vaptreport examples/sample_nessus.nessus -f html -o report.html
vaptreport examples/sample_nessus.nessus -f xlsx -o report.xlsx
```

### Interactive mode

Run `vaptreport` with no input files (or `vaptreport -i`) and a guided,
styled wizard walks you through the whole thing — no flags to remember:

1. choose the scan / findings file(s)
2. choose a template — the default theme or **your own company template**
3. watch the report build with live progress
4. choose the output format (**PDF / Word / HTML / Excel**)
5. name the output file — done

It's the same engine as the flags below, just collected one question at a time.

Example terminal output:

```
VAPT Report Generator v1.0.0

✓ examples/sample_findings.json: parsed 5 finding(s)
        Findings Summary
┏━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Severity      ┃ Count ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Critical      │     2 │
│ High          │     1 │
│ Medium        │     1 │
│ Low           │     0 │
│ Informational │     1 │
│ Total         │     5 │
└───────────────┴───────┘
Overall risk rating: Critical

✓ Report written: report.pdf
```

---

## Supported scanner inputs

The format is auto-detected from the file extension and content — just pass the
files, in any combination.

| Scanner            | Format to export            | Extension        | Notes |
|--------------------|-----------------------------|------------------|-------|
| **Nmap**           | XML (`-oX`)                 | `.xml`           | Open ports + NSE `vuln` script hits |
| **Nessus**         | Nessus export               | `.nessus`        | Same plugin across hosts is merged |
| **Nuclei**         | JSON-Lines (`-jsonl`)       | `.jsonl`/`.json` | CVSS/CWE/CVE from `classification` |
| **Burp Suite**     | XML issue export            | `.xml`           | Same issue across paths is merged |
| **OWASP ZAP**      | JSON or XML report          | `.json`/`.xml`   | Risk codes mapped to severity |
| **Acunetix**       | Developer Report **PDF**    | `.pdf`           | Best-effort text extraction; XML is lossless if available |
| **Manual / other** | Findings file (this schema) | `.json`/`.yaml`  | For findings no scanner produces |

> **Why native exports, not PDFs?** Structured exports (XML/JSON) parse
> losslessly and reliably. PDF layouts are fragile to parse, so PDF input is
> reserved for Acunetix (where the report PDF is the common artifact). For every
> other scanner, use its XML/JSON export.

---

## CLI reference

```
vaptreport [INPUT ...] [options]      # omit INPUT to launch the wizard

  -i, --interactive                   Launch the guided interactive wizard
  -f, --format {pdf,html,docx,xlsx}   Output format (default: pdf)
  -o, --output PATH                   Output file path
  -t, --template PATH                 Custom template: .html.j2 (pdf/html),
                                      .docx (docx, fills every field),
                                      or .pdf (reuses its cover page)
      --client NAME                   Override client name
      --title TITLE                   Override report title
      --assessor NAME                 Override assessor name
      --id-prefix PREFIX              Finding ID prefix (default: VR)
  -V, --version                       Show version
```

## Custom templates (use your company's branding)

The bundled theme is the default, but real engagements often require the
client's or your firm's own report layout. Supply any HTML/Jinja2 template with
`-t/--template` and the PDF/HTML output uses it instead:

```bash
vaptreport scan.nessus -t my_company_template.html.j2 -o report.pdf
```

Start from [`examples/custom_template.html.j2`](examples/custom_template.html.j2)
— it documents every variable available to the template (`report`, `findings`,
severity counts, CVSS, targets, …) and shows a fully restyled corporate theme
with letterhead and page numbers. Copy it, drop in your colours/logo/wording,
and you get pixel-consistent branded reports every time.

### Word (.docx) templates

Most firms keep their report template as a **Word document**. Point `-t` at it
and `-f docx` — it works two ways, chosen automatically:

```bash
vaptreport scan.nessus -f docx -t company_template.docx -o report.docx
```

**1. Just use your template — "auto-fill" (zero setup).** If your `.docx` has a
"Vulnerability Technical Details" (or "Detailed Findings") section with one
**example finding** that uses normal labels (`Vulnerability Description:`,
`CVSS Scoring:`, `CWE ID:`, `Severity:`, `Affected URL:`, `Suggested
Remediation:`, `References:`), the tool **detects that example, removes it, and
writes every real finding in its exact place and formatting** — and refreshes
the summary findings table too. Nothing is appended outside the template:

```bash
vaptreport scan.pdf -f docx -t your_company_template.docx -o report.docx
```

Want the PDF in the same format? Use `-f pdf -t your_company_template.docx` —
the tool builds the .docx and converts it to PDF with LibreOffice (`soffice`).

**2. Explicit control — "clone-fill" with markers.** For precise control over
where each value lands, mark **one** example finding with simple `[[markers]]`
and the tool clones that block once per finding, preserving its formatting:

```text
[[finding]]
[[title]]
Vulnerability Description: [[description]]
CVSS Scoring: [[cvss]]   ([[cvss_vector]])
CWE ID: [[cwe]]      Severity: [[severity]]
Affected URL: [[targets]]
Proof of Concept: [[evidence]]
Suggested Remediation: [[remediation]]
References: [[references]]
[[/finding]]
```

Put `[[finding]]` / `[[/finding]]` on their own lines around your example
finding, drop the field markers where each value goes, and (optionally) add a
summary-table row whose first cell contains `[[findings_row]]`. Document-level
markers `[[client]]`, `[[date]]`, `[[assessor]]`, `[[risk_rating]]`,
`[[total_findings]]`, `[[count_critical]]` … are filled once. Everything else in
your document — cover, methodology, appendices, header/footer — is untouched.
Field markers: `[[id]] [[title]] [[severity]] [[cvss]] [[cvss_vector]] [[cwe]]
[[cve]] [[targets]] [[description]] [[evidence]] [[remediation]] [[references]]`.

> **Tip:** put each marker exactly where the *value* goes, keeping it out of a
> bold label run — e.g. `CWE ID: [[cwe]]` with only `CWE ID:` bold. The tool
> fills each marker in place and preserves that run's formatting, so a bold
> label stays bold and the value keeps the value's styling.

**3. Fallback — "branding shell".** If no example finding block can be detected
and there are no markers/tags, the tool keeps the *entire* document and
**appends the findings** as a new section in the document's own styles.

**4. Jinja2 field-filling — tagged template (docxtpl).** Add `{{ }}` placeholders
for docxtpl-style filling. Start from
[`examples/company_template.docx`](examples/company_template.docx). Placeholders:
`{{ client }}`, `{{ title }}`, `{{ assessor }}`, `{{ date }}`, `{{ standard }}`,
`{{ risk_rating }}`, `{{ counts['Critical'] }}` (High/Medium/Low/Informational),
and a findings loop:

```jinja
{% for f in findings %}
{{ f.finding_id }} — {{ f.title }} [{{ f.severity.value }}]
CVSS {{ f.cvss_score }} · {{ f.cwe }} · Source: {{ f.source }}
{{ f.description }}
{{ f.remediation }}
{% endfor %}
```

Requires the docx extra: `pip install 'vapt-report-generator[docx]'`.

> **What about a PDF template?** A finished PDF has no fields to fill (it's not
> an editable form), so it can't be field-filled like a `.docx`/`.html.j2`. When
> you pass a `.pdf` to `-t` with `-f pdf`, the tool does the next best thing:
> it **reuses the PDF's first page as the report cover/letterhead** and appends
> the findings in the default style. For true field-by-field branding, use a
> `.docx` or `.html.j2` template.

---

## The findings file format

For manual findings that no scanner produces (business logic, IDOR, broken
access control…), write a JSON or YAML file. Only `title` is required per
finding; supply a `cvss_vector` and the score + severity are computed for you.

```json
{
  "report": {
    "client": "Example Corporation",
    "title": "Web Application Penetration Test Report",
    "assessor": "Usman Zia",
    "scope": ["https://app.example.com"]
  },
  "findings": [
    {
      "title": "SQL Injection in Login Form",
      "description": "The username parameter is concatenated into a SQL query...",
      "targets": ["app.example.com:443"],
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe": "CWE-89",
      "remediation": "Use parameterised queries.",
      "evidence": "username=admin' OR '1'='1'-- -"
    }
  ]
}
```

See [`examples/`](examples/) for complete Nmap, Nessus, and findings samples.

---

## Architecture

```
vaptreport/
├── models.py            # Finding / Report / Severity / Target  (shared model)
├── scoring.py           # CVSS v3.1 base-score calculator
├── parsers/             # one module per scanner; all normalise into Finding
│   ├── nmap.py          # Nmap XML
│   ├── nessus.py        # Nessus .nessus (host-merged)
│   ├── nuclei.py        # Nuclei JSON / JSON-Lines (template-merged)
│   ├── burp.py          # Burp Suite XML (path-merged)
│   ├── zap.py           # OWASP ZAP JSON + XML
│   ├── acunetix_pdf.py  # Acunetix Developer Report PDF
│   ├── findings.py      # JSON/YAML — the canonical schema
│   └── _util.py         # shared HTML-strip / URL / target helpers
├── reporters/
│   ├── html.py          # Jinja2 -> HTML
│   ├── pdf.py           # HTML -> PDF (WeasyPrint)
│   └── excel.py         # -> styled .xlsx workbook
├── templates/report.html.j2   # bundled generic theme
└── cli.py               # argparse + rich CLI

examples/custom_template.html.j2  # starting point for your own branded theme
```

Every parser normalises into the same `Finding` model, so adding a new scanner
means writing one parser — all three output formats work automatically.

---

## Running the tests

```bash
pip install -e ".[dev]"
pytest -v
```

---

## Roadmap

- [x] Custom HTML/Jinja2 template support (`-t/--template`)

- [ ] Trend/delta mode (compare two scans to show fixed vs. new findings)
- [ ] Markdown output for GitHub issues

---

## Disclaimer

This tool only formats and scores findings you provide; it does not perform
scanning or exploitation. Use it solely for **authorised** security assessments.

## License

MIT © Usman Zia — see [LICENSE](LICENSE).
