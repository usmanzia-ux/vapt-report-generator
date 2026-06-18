"""Unit tests for vapt-report-generator."""

from pathlib import Path

import pytest

from vaptreport import scoring
from vaptreport.models import Finding, Report, Severity, Target
from vaptreport.parsers import detect_and_parse

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


# ── CVSS scoring ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # EternalBlue
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", 8.2),
    ],
)
def test_base_score(vector, expected):
    assert scoring.base_score(vector) == expected


def test_severity_from_score():
    assert scoring.severity_from_score(9.8) == "Critical"
    assert scoring.severity_from_score(7.0) == "High"
    assert scoring.severity_from_score(4.0) == "Medium"
    assert scoring.severity_from_score(0.1) == "Low"
    assert scoring.severity_from_score(0.0) == "Informational"


def test_invalid_vector_raises():
    with pytest.raises(ValueError):
        scoring.base_score("CVSS:3.1/AV:N/AC:L")  # missing metrics


# ── Models ─────────────────────────────────────────────────────────────────────
def test_finding_derives_score_from_vector():
    f = Finding(title="x", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert f.cvss_score == 9.8
    assert f.severity == Severity.CRITICAL


def test_report_sort_and_ids():
    report = Report(findings=[
        Finding(title="low", severity=Severity.LOW),
        Finding(title="crit", severity=Severity.CRITICAL),
        Finding(title="med", severity=Severity.MEDIUM),
    ])
    report.finalize()
    assert [f.title for f in report.findings] == ["crit", "med", "low"]
    assert report.findings[0].finding_id == "VR-001"
    assert report.risk_rating() == "Critical"


def test_severity_coerce():
    assert Severity.coerce("HIGH") == Severity.HIGH
    assert Severity.coerce("moderate") == Severity.MEDIUM
    assert Severity.coerce(None) == Severity.INFO


def test_target_label():
    assert Target("h", 443, "https").label() == "h:443 (https)"
    assert Target("h").label() == "h"


# ── Parsers ────────────────────────────────────────────────────────────────────
def test_parse_findings_json():
    findings = detect_and_parse(str(EXAMPLES / "sample_findings.json"))
    assert len(findings) == 5
    sqli = next(f for f in findings if "SQL Injection" in f.title)
    assert sqli.severity == Severity.CRITICAL
    assert sqli.cvss_score == 9.8


def test_parse_nmap():
    findings = detect_and_parse(str(EXAMPLES / "sample_nmap.xml"))
    # POODLE vuln script + open-service inventory
    assert any("ssl-poodle" in f.title for f in findings)
    assert any("Open Network Services" in f.title for f in findings)


def test_parse_nessus_merges_hosts():
    findings = detect_and_parse(str(EXAMPLES / "sample_nessus.nessus"))
    eternalblue = next(f for f in findings if "EternalBlue" in f.title)
    # Same plugin on two hosts -> one finding, two targets.
    assert len(eternalblue.targets) == 2
    assert eternalblue.severity == Severity.CRITICAL


# ── Reporters ──────────────────────────────────────────────────────────────────
def test_render_html(tmp_path):
    from vaptreport import reporters

    findings = detect_and_parse(str(EXAMPLES / "sample_findings.json"))
    report = Report(findings=findings).finalize()
    out = reporters.render(report, "html", str(tmp_path / "r.html"))
    html = Path(out).read_text()
    assert "SQL Injection" in html
    assert "VR-001" in html


def test_render_xlsx(tmp_path):
    from vaptreport import reporters

    findings = detect_and_parse(str(EXAMPLES / "sample_findings.json"))
    report = Report(findings=findings).finalize()
    out = reporters.render(report, "xlsx", str(tmp_path / "r.xlsx"))
    assert Path(out).exists() and Path(out).stat().st_size > 0
