"""Core data model: Severity, Remediation, Finding, ScanResult.

Every check returns ``Finding`` objects of a fixed shape. The engine attaches a
``Remediation`` (tailored to the detected server) and computes a ``ScanResult``.
These objects are deliberately plain so reporting layers only render — they never
recompute anything.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


class Severity(enum.Enum):
    """Ordered severity levels. ``weight`` feeds the scoring engine."""

    CRITICAL = ("critical", 40, "Critical")
    HIGH = ("high", 20, "High")
    MEDIUM = ("medium", 10, "Medium")
    LOW = ("low", 4, "Low")
    INFO = ("info", 0, "Info")

    def __init__(self, slug: str, weight: int, label: str) -> None:
        self.slug = slug
        self.weight = weight
        self.label = label

    @property
    def rank(self) -> int:
        """Lower rank == more severe. Used for sorting findings."""
        order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        return order[self.slug]


@dataclass(frozen=True)
class Remediation:
    """A concrete, tailored fix for a finding.

    ``snippets`` maps a server key ("nginx" | "apache" | "cloudflare" |
    "generic") to a copy-paste remediation. ``detected`` names the variant the
    UI should show first.
    """

    why: str
    snippets: dict[str, str]
    references: list[str] = field(default_factory=list)
    detected: str = "generic"

    def primary_snippet(self) -> str:
        return self.snippets.get(self.detected) or self.snippets.get("generic", "")


@dataclass
class Finding:
    """A single issue (or advisory) discovered by a check.

    Fixed shape, per architecture rule: id, title, severity, category, evidence,
    remediation, references. ``remediation`` is populated by the engine after the
    detected server stack is known.
    """

    id: str
    title: str
    severity: Severity
    category: str
    evidence: str
    description: str = ""
    references: list[str] = field(default_factory=list)
    remediation: Remediation | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.slug,
            "severity_label": self.severity.label,
            "category": self.category,
            "evidence": self.evidence,
            "description": self.description,
            "references": list(self.references),
            "remediation": (
                {
                    "why": self.remediation.why,
                    "snippets": dict(self.remediation.snippets),
                    "references": list(self.remediation.references),
                    "detected": self.remediation.detected,
                }
                if self.remediation
                else None
            ),
        }


@dataclass
class ScanResult:
    """The full result of a scan: target, findings, score, grade, metadata."""

    target: str
    findings: list[Finding]
    score: int
    grade: str
    detected_server: str
    started_at: datetime
    finished_at: datetime
    checks_run: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "score": self.score,
            "grade": self.grade,
            "detected_server": self.detected_server,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 2),
            "checks_run": list(self.checks_run),
            "counts": dict(self.counts),
            "notes": list(self.notes),
            "findings": [f.to_dict() for f in self.findings],
        }


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
