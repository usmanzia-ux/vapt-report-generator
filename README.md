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

- **Multi-source ingestion** — Nmap XML, Nessus `.nessus`, and a generic
  JSON/YAML findings format. Mix several inputs into one report.
- **Auto-detection** — point it at a file; it figures out the format.
- **CVSS v3.1 engine** — a spec-compliant base-score calculator (not a lookup
  table) derives scores from vectors and maps them to severity ratings.
- **Smart de-duplication** — the same Nessus plugin across many hosts becomes a
  single finding with all affected targets aggregated.
- **Three output formats** — PDF (default, via WeasyPrint), print-ready HTML,
  and a styled multi-sheet Excel workbook (Cover / Findings / Summary).
- **Custom templates** — bring your own HTML/Jinja2 template (`-t`) to match a
  client's or your firm's branding; falls back to a polished generic theme.
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
```

---

## Quick start

```bash
# Default output is PDF — what most clients actually want
vaptreport examples/sample_findings.json -o report.pdf

# Combine an Nmap scan and manual findings into one PDF
vaptreport examples/sample_nmap.xml examples/sample_findings.json \
    -o engagement.pdf --client "Example Corporation"

# Use your company's own branded template
vaptreport examples/sample_nessus.nessus -t examples/custom_template.html.j2 \
    -o branded_report.pdf

# Other formats: HTML (web preview) and a styled Excel workbook
vaptreport examples/sample_nessus.nessus -f html -o report.html
vaptreport examples/sample_nessus.nessus -f xlsx -o report.xlsx
```

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

## CLI reference

```
vaptreport INPUT [INPUT ...] [options]

  -f, --format {pdf,html,xlsx}   Output format (default: pdf)
  -o, --output PATH              Output file path
  -t, --template PATH            Custom HTML/Jinja2 template for pdf/html output
      --client NAME              Override client name
      --title TITLE              Override report title
      --assessor NAME            Override assessor name
      --id-prefix PREFIX         Finding ID prefix (default: VR)
  -V, --version                  Show version
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

> **Note on PDF "templates":** a finished PDF can't be used directly as a
> fill-in template (PDFs aren't editable forms). Instead, reproduce the layout
> once as an HTML/Jinja template — it's reusable, version-controllable, and
> renders identically on every report.

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
├── parsers/
│   ├── nmap.py          # Nmap XML  -> Findings
│   ├── nessus.py        # Nessus .nessus -> Findings (host-merged)
│   └── findings.py      # JSON/YAML  -> Findings  (also the canonical schema)
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
- [ ] Burp Suite XML and OWASP ZAP JSON parsers
- [ ] Trend/delta mode (compare two scans to show fixed vs. new findings)
- [ ] Markdown output for GitHub issues

---

## Disclaimer

This tool only formats and scores findings you provide; it does not perform
scanning or exploitation. Use it solely for **authorised** security assessments.

## License

MIT © Usman Zia — see [LICENSE](LICENSE).
