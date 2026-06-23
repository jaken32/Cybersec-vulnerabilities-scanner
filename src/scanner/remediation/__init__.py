"""Remediation engine: maps finding id + detected server -> tailored fix."""

from .fixes import resolve_remediation, SERVER_KEYS

__all__ = ["resolve_remediation", "SERVER_KEYS"]
