"""Tests for the scoring + grading engine."""

from __future__ import annotations

from scanner.models import Finding, Severity
from scanner.scoring import grade_for_score, score_findings, severity_counts


def f(sev, fid="x"):
    return Finding(id=fid, title="t", severity=sev, category="c", evidence="e")


def test_clean_site_scores_a():
    score, grade = score_findings([])
    assert score == 100
    assert grade == "A"


def test_info_findings_do_not_affect_score():
    score, grade = score_findings([f(Severity.INFO), f(Severity.INFO, "y")])
    assert score == 100
    assert grade == "A"


def test_single_critical_drops_below_a():
    score, grade = score_findings([f(Severity.CRITICAL)])
    assert score == 60  # 100 - 40
    assert grade == "D"


def test_grade_bands():
    assert grade_for_score(100) == "A"
    assert grade_for_score(90) == "A"
    assert grade_for_score(89) == "B"
    assert grade_for_score(80) == "B"
    assert grade_for_score(70) == "C"
    assert grade_for_score(60) == "D"
    assert grade_for_score(59) == "F"
    assert grade_for_score(0) == "F"


def test_score_never_negative():
    findings = [f(Severity.CRITICAL, fid=str(i)) for i in range(10)]
    score, grade = score_findings(findings)
    assert score == 0
    assert grade == "F"


def test_repeated_same_id_has_diminishing_weight():
    # Two LOW findings with the SAME id: 4 + 4*0.4 = 5.6 -> round -> 94
    same = score_findings([f(Severity.LOW, "dup"), f(Severity.LOW, "dup")])[0]
    # Two LOW findings with DIFFERENT ids: 4 + 4 = 8 -> 92
    diff = score_findings([f(Severity.LOW, "a"), f(Severity.LOW, "b")])[0]
    assert same > diff


def test_severity_counts_includes_all_levels():
    counts = severity_counts([f(Severity.HIGH), f(Severity.HIGH, "y"), f(Severity.LOW, "z")])
    assert counts["high"] == 2
    assert counts["low"] == 1
    assert counts["critical"] == 0
    assert set(counts.keys()) == {"critical", "high", "medium", "low", "info"}
