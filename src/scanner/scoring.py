"""Severity-weighted scoring -> numeric score (0–100) and an A–F grade.

Pure functions, no I/O, fully unit-tested. The model is intentionally simple and
explainable: start at 100, subtract each finding's severity weight (with mild
diminishing returns when the same issue type recurs), clamp to [0, 100].
"""

from __future__ import annotations

from .models import Finding, Severity

#: Letter-grade thresholds, highest first.
GRADE_BANDS: list[tuple[int, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


def grade_for_score(score: int) -> str:
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"  # pragma: no cover - unreachable, 0 band catches all


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    """Return ``(score, grade)`` for a list of findings.

    INFO findings never affect the score. Repeated findings of the same id
    contribute with diminishing weight so one noisy category cannot dominate.
    """
    penalty = 0.0
    seen_counts: dict[str, int] = {}
    for f in findings:
        if f.severity is Severity.INFO:
            continue
        n = seen_counts.get(f.id, 0)
        seen_counts[f.id] = n + 1
        # First occurrence full weight; subsequent at 40% each.
        factor = 1.0 if n == 0 else 0.4
        penalty += f.severity.weight * factor

    score = max(0, min(100, round(100 - penalty)))
    return score, grade_for_score(score)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity slug (always includes every level)."""
    counts = {s.slug: 0 for s in Severity}
    for f in findings:
        counts[f.severity.slug] += 1
    return counts
