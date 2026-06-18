"""CVSS v3.1 base-score calculator.

Implements the official CVSS v3.1 specification base-score equations so that
findings can be scored consistently regardless of which scanner produced them.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from typing import Dict, Optional

# ── Metric value lookup tables (CVSS v3.1 §7) ──────────────────────────────────
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
# Privileges Required depends on Scope.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A roundup: round up to one decimal place."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10.0


def parse_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS vector string into a {metric: value} dict.

    Accepts an optional ``CVSS:3.1/`` prefix. Example::

        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    metrics: Dict[str, str] = {}
    for part in vector.strip().split("/"):
        if not part or part.upper().startswith("CVSS"):
            continue
        key, _, val = part.partition(":")
        if val:
            metrics[key.strip().upper()] = val.strip().upper()
    return metrics


def base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score from a vector string.

    Raises ``ValueError`` if a required base metric is missing or invalid.
    """
    m = parse_vector(vector)
    missing = [k for k in _REQUIRED if k not in m]
    if missing:
        raise ValueError(f"Vector missing required base metrics: {', '.join(missing)}")

    scope_changed = m["S"] == "C"
    try:
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        ui = _UI[m["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
        conf, integ, avail = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:  # invalid metric value
        raise ValueError(f"Invalid CVSS metric value: {exc}") from exc

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = (impact + exploitability) * (1.08 if scope_changed else 1.0)
    return _roundup(min(raw, 10.0))


def severity_from_score(score: Optional[float]) -> str:
    """Map a numeric CVSS base score to a qualitative severity rating."""
    if score is None:
        return "Informational"
    if score == 0:
        return "Informational"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
