"""Parser for Acunetix "Developer Report" PDF exports.

A PDF has no stable machine schema, but the Acunetix Developer Report follows a
predictable textual layout that we can reconstruct:

* an **Alerts summary** section — one entry per alert with its CVSS vector, CWE
  and CVE, in report order; followed by
* an **Alerts details** section — the same alerts, same order, each with a
  ``Severity`` line, Description, Recommendation, References and evidence.

We extract the text with ``pypdf``, parse both sections, and zip them together
by position (falling back to title matching) into normalised Findings.

Best-effort by nature: free-text fields are lifted verbatim and may carry minor
spacing artefacts from PDF text extraction. The structured fields (title,
severity, CVSS, CWE, CVE) are reliable. For lossless, fully-automated ingestion,
export the scan as Acunetix **XML** instead.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..models import Finding, Severity, Target

_LIGATURES = {"ﬁ": "fi", "ﬂ": "fl", "ﬀ": "ff", "ﬃ": "ffi", "ﬄ": "ffl", "ﬆ": "st"}
_LEVELS = ("Critical", "High", "Medium", "Low", "Informational")
_SEV_RE = re.compile(r"^Severity (%s)$" % "|".join(_LEVELS))
_CVSS3_RE = re.compile(r"CVSS:3\.1/(?:[A-Z]{1,2}:[A-Z]/)+[A-Z]{1,2}:[A-Z]")
_CWE_RE = re.compile(r"CWE-\d+")
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
_URL_RE = re.compile(r"https?://[^\s)]+")
_DETAIL_HEADERS = ("Description", "Impact", "Recommendation", "References",
                   "Affected items", "Details")


def _clean(text: str) -> str:
    for lig, rep in _LIGATURES.items():
        text = text.replace(lig, rep)
    return re.sub(r"[ \t]+", " ", text).strip()


def _norm_title(title: str) -> str:
    return re.sub(r"[^a-z0-9]", "", title.lower())


def _extract_text(path: str) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Parsing PDF input requires pypdf. Install it with:\n"
            "    pip install 'vapt-report-generator[pdf]'"
        ) from exc
    reader = PdfReader(path)
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def _delig(text: str) -> str:
    for lig, rep in _LIGATURES.items():
        text = text.replace(lig, rep)
    return text


def _clean_lines(text: str) -> List[str]:
    """Split into de-ligatured, stripped non-empty lines, dropping page numbers.

    Acunetix PDFs use typographic ligatures (ﬁ, ﬀ, …), so section headers like
    "Classiﬁcation" and "Aﬀected items" must be normalised before matching.
    """
    out: List[str] = []
    for raw in text.splitlines():
        s = _delig(raw).strip()
        if not s or s.isdigit():
            continue
        out.append(s)
    return out


def _host_from(text: str) -> str:
    m = re.search(r"^Host (\S+)", text, re.M)
    if m:
        return m.group(1)
    m = re.search(r"Start url https?://([^/\s]+)", text)
    return m.group(1) if m else "scan target"


def _slice_between(body: List[str], start: str, ends) -> str:
    """Join lines after the first ``start`` header up to the next header in ``ends``."""
    try:
        i = body.index(start)
    except ValueError:
        return ""
    collected = []
    for line in body[i + 1:]:
        if line in ends:
            break
        collected.append(line)
    return _clean(" ".join(collected))


def _parse_summary(lines: List[str]) -> List[Dict]:
    """Return per-alert {cvss_vector, cwe, cve} in report order."""
    class_idx = [i for i, l in enumerate(lines) if l == "Classification"]
    entries: List[Dict] = []
    for k, ci in enumerate(class_idx):
        title = lines[ci - 1] if ci > 0 else ""
        end = (class_idx[k + 1] - 1) if k + 1 < len(class_idx) else len(lines)
        body = "\n".join(lines[ci + 1:end])
        vec = _CVSS3_RE.search(body)
        cwe = _CWE_RE.search(body)
        entries.append({
            "title": title,
            "cvss_vector": vec.group(0) if vec else None,
            "cwe": cwe.group(0) if cwe else None,
            "cve": sorted(set(_CVE_RE.findall(body))),
        })
    return entries


def _parse_details(lines: List[str], host: str) -> List[Dict]:
    """Return per-alert detail dicts (title, severity, text fields) in order."""
    sev_idx = [i for i, l in enumerate(lines) if _SEV_RE.match(l)]
    findings: List[Dict] = []
    for k, si in enumerate(sev_idx):
        severity = _SEV_RE.match(lines[si]).group(1)
        title = lines[si - 1] if si > 0 else "Untitled Finding"
        end = (sev_idx[k + 1] - 1) if k + 1 < len(sev_idx) else len(lines)
        body = lines[si + 1:end]

        evidence = _slice_between(body, "Details", ("Request headers",))
        findings.append({
            "title": _clean(title),
            "severity": severity,
            "description": _slice_between(body, "Description", _DETAIL_HEADERS),
            "remediation": _slice_between(body, "Recommendation", _DETAIL_HEADERS),
            "references": _URL_RE.findall(
                _slice_between(body, "References", _DETAIL_HEADERS)),
            "evidence": evidence,
            "host": host,
        })
    return findings


def parse_text(text: str) -> List[Finding]:
    """Parse already-extracted Acunetix report text into Findings."""
    lines = _clean_lines(text)
    host = _host_from(text)

    def _section(start: str, stop: Optional[str]) -> List[str]:
        try:
            a = lines.index(start)
        except ValueError:
            return []
        b = len(lines)
        if stop:
            for i in range(a + 1, len(lines)):
                if lines[i].startswith(stop):
                    b = i
                    break
        return lines[a + 1:b]

    summary = _parse_summary(_section("Alerts summary", "Alerts details"))
    details = _parse_details(
        _section("Alerts details", "Scanned items"), host)

    by_title = {_norm_title(e["title"]): e for e in summary}

    findings: List[Finding] = []
    for i, d in enumerate(details):
        meta = {}
        if i < len(summary) and _norm_title(summary[i]["title"]) == _norm_title(d["title"]):
            meta = summary[i]
        else:
            meta = by_title.get(_norm_title(d["title"]), {})

        findings.append(Finding(
            title=d["title"],
            severity=Severity.coerce(d["severity"]),
            description=d["description"],
            targets=[Target(host=d["host"], port=443, service="https")],
            cvss_vector=meta.get("cvss_vector"),
            cwe=meta.get("cwe"),
            cve=meta.get("cve", []),
            remediation=d["remediation"],
            references=d["references"],
            evidence=d["evidence"],
            source="acunetix",
        ))
    return findings


def parse(path: str) -> List[Finding]:
    return parse_text(_extract_text(path))
