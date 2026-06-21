"""Parser for the tool's own generic findings format (JSON or YAML).

This is the format you hand-edit for manual pentest findings (web app, API,
cloud, business-logic) that no scanner produces. It is also what every other
parser ultimately normalises into, so the schema doubles as documentation.

Schema (all keys optional except ``title``)::

    {
      "report": {
        "client": "Example Corporation",
        "title": "Web Application Penetration Test",
        "assessor": "Security Assessor",
        "assessment_date": "2026-06-18",
        "scope": ["https://app.example.com"],
        "standard": "OWASP Top 10 (2021)"
      },
      "findings": [
        {
          "title": "SQL Injection in Login Form",
          "severity": "Critical",
          "description": "...",
          "targets": [{"host": "app.example.com", "port": 443, "service": "https"}],
          "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "cwe": "CWE-89",
          "cve": ["CVE-2024-1234"],
          "remediation": "Use parameterised queries.",
          "references": ["https://owasp.org/..."],
          "evidence": "payload: ' OR '1'='1"
        }
      ]
    }

``targets`` may also be given as a list of plain strings (``"host:port"``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ..models import Finding, Severity, Target


def _load(path: str) -> Dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    if path.lower().endswith((".yaml", ".yml")):
        import yaml  # imported lazily so JSON-only users skip the dependency

        return yaml.safe_load(text) or {}
    return json.loads(text)


def _coerce_target(raw: Any) -> Target:
    if isinstance(raw, str):
        host, _, port = raw.partition(":")
        return Target(host=host, port=int(port) if port.isdigit() else None)
    if isinstance(raw, dict):
        return Target(
            host=raw.get("host", "unknown"),
            port=raw.get("port"),
            service=raw.get("service"),
        )
    raise ValueError(f"Invalid target entry: {raw!r}")


def _build_finding(raw: Dict[str, Any]) -> Finding:
    if "title" not in raw:
        raise ValueError("Each finding requires a 'title'.")
    return Finding(
        title=raw["title"],
        severity=Severity.coerce(raw.get("severity")),
        description=raw.get("description", ""),
        targets=[_coerce_target(t) for t in raw.get("targets", [])],
        cvss_score=raw.get("cvss_score"),
        cvss_vector=raw.get("cvss_vector"),
        cwe=raw.get("cwe"),
        cve=raw.get("cve", []) or [],
        remediation=raw.get("remediation", ""),
        references=raw.get("references", []) or [],
        evidence=raw.get("evidence", ""),
        source=raw.get("source", "manual"),
    )


def parse(path: str) -> List[Finding]:
    data = _load(path)
    raw_findings = data.get("findings", data if isinstance(data, list) else [])
    return [_build_finding(f) for f in raw_findings]


def parse_report_meta(path: str) -> Dict[str, Any]:
    """Return the optional ``report`` metadata block from a findings file."""
    data = _load(path)
    return data.get("report", {}) if isinstance(data, dict) else {}
