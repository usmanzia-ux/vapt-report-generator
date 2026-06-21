"""Normalised data model shared by every parser and reporter."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum
from typing import Dict, List, Optional

from . import scoring


class Severity(str, Enum):
    """Ordered severity levels (highest first when sorted by ``rank``)."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def rank(self) -> int:
        order = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
            "Informational": 4,
        }
        return order[self.value]

    @classmethod
    def coerce(cls, value: Optional[str]) -> "Severity":
        """Best-effort conversion of any string into a Severity member."""
        if not value:
            return cls.INFO
        v = value.strip().lower()
        aliases = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "none": cls.INFO,
        }
        return aliases.get(v, cls.INFO)


@dataclass
class Target:
    """A host / endpoint that was assessed."""

    host: str
    port: Optional[int] = None
    service: Optional[str] = None

    def label(self) -> str:
        if self.port:
            svc = f" ({self.service})" if self.service else ""
            return f"{self.host}:{self.port}{svc}"
        return self.host


@dataclass
class Finding:
    """A single normalised vulnerability finding."""

    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    targets: List[Target] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    cve: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    evidence: str = ""
    source: str = "manual"  # which parser produced it: nmap / nessus / findings

    def __post_init__(self) -> None:
        # Derive score from vector, or severity from score, when possible.
        if self.cvss_vector and self.cvss_score is None:
            try:
                self.cvss_score = scoring.base_score(self.cvss_vector)
            except ValueError:
                pass
        if self.cvss_score is not None and self.severity == Severity.INFO:
            self.severity = Severity.coerce(scoring.severity_from_score(self.cvss_score))

    @property
    def finding_id(self) -> str:
        # Stable-ish ID set later by the Report; placeholder until assigned.
        return getattr(self, "_fid", "VR-???")


@dataclass
class Report:
    """A full assessment: metadata + a list of findings."""

    client: str = "Confidential Client"
    title: str = "Vulnerability Assessment & Penetration Test Report"
    assessor: str = "Security Assessor"
    assessment_date: str = field(default_factory=lambda: date.today().isoformat())
    scope: List[str] = field(default_factory=list)
    standard: str = "OWASP Top 10 (2021) / CVSS v3.1"
    findings: List[Finding] = field(default_factory=list)

    def sort_findings(self) -> None:
        """Sort by severity (Critical first), then by CVSS score descending."""
        self.findings.sort(
            key=lambda f: (f.severity.rank, -(f.cvss_score or 0.0))
        )

    def assign_ids(self, prefix: str = "VR") -> None:
        for i, f in enumerate(self.findings, start=1):
            f._fid = f"{prefix}-{i:03d}"

    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def risk_rating(self) -> str:
        """Overall engagement risk based on the worst findings present."""
        c = self.severity_counts()
        if c["Critical"]:
            return "Critical"
        if c["High"]:
            return "High"
        if c["Medium"]:
            return "Medium"
        if c["Low"]:
            return "Low"
        return "Informational"

    def finalize(self, prefix: str = "VR") -> "Report":
        """Sort, then assign IDs. Call once before rendering."""
        self.sort_findings()
        self.assign_ids(prefix)
        return self

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity_counts"] = self.severity_counts()
        d["risk_rating"] = self.risk_rating()
        return d
