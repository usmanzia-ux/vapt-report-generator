"""Parser for Nuclei output (``nuclei -jsonl`` / ``-json``).

Accepts either JSON-Lines (one JSON object per line, the ``-jsonl`` default) or a
single JSON array. Results for the same template across multiple hosts are
merged into one finding with the affected targets aggregated.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from ..models import Finding, Severity
from ._util import as_list, target_from_uri


def _load_records(path: str) -> List[dict]:
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        data = json.loads(text)           # JSON array or single object
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        pass
    records = []                           # fall back to JSON-Lines
    for line in text.splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def _first_cwe(value) -> str | None:
    cwes = as_list(value)
    if not cwes:
        return None
    cwe = cwes[0].upper()
    return cwe if cwe.startswith("CWE") else f"CWE-{cwe}"


def parse(path: str) -> List[Finding]:
    merged: Dict[str, Finding] = {}

    for r in _load_records(path):
        info = r.get("info", {}) or {}
        classification = info.get("classification") or {}
        template_id = r.get("template-id") or r.get("templateID") or info.get("name", "")
        matched = r.get("matched-at") or r.get("matched") or r.get("host") or "unknown"
        target = target_from_uri(matched, fallback_host=r.get("host"))

        if template_id in merged:
            merged[template_id].targets.append(target)
            merged[template_id].cve = sorted(
                set(merged[template_id].cve) | set(as_list(classification.get("cve-id"))))
            continue

        score = classification.get("cvss-score")
        evidence = []
        if matched:
            evidence.append(f"Matched at: {matched}")
        if r.get("extracted-results"):
            evidence.append("Extracted: " + ", ".join(as_list(r["extracted-results"])))
        if r.get("curl-command"):
            evidence.append("PoC: " + r["curl-command"])

        merged[template_id] = Finding(
            title=info.get("name") or template_id,
            severity=Severity.coerce(info.get("severity")),
            description=info.get("description", "") or "",
            targets=[target],
            cvss_vector=classification.get("cvss-metrics"),
            cvss_score=float(score) if score is not None else None,
            cwe=_first_cwe(classification.get("cwe-id")),
            cve=as_list(classification.get("cve-id")),
            remediation=info.get("remediation", "") or "",
            references=as_list(info.get("reference")),
            evidence="\n".join(evidence),
            source="nuclei",
        )

    return list(merged.values())
