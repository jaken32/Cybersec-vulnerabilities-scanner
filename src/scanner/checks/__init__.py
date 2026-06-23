"""Security checks. Each module implements one or more :class:`Check` subclasses.

Adding a check = adding a module here and registering it in ``ALL_CHECKS``.
"""

from __future__ import annotations

from .base import Check, ScanContext
from .content import ContentCheck
from .cookies import CookieCheck
from .disclosure import DisclosureCheck
from .dns_email import DnsEmailCheck
from .fingerprint import FingerprintCheck
from .headers import SecurityHeadersCheck
from .tls import TLSCheck

#: The full ordered registry of checks the engine runs.
ALL_CHECKS: list[type[Check]] = [
    SecurityHeadersCheck,
    TLSCheck,
    CookieCheck,
    DisclosureCheck,
    DnsEmailCheck,
    ContentCheck,
    FingerprintCheck,
]

__all__ = ["Check", "ScanContext", "ALL_CHECKS"]
