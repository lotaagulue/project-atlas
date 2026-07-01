from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Asset:
    """Something discovered about your own attack surface (host, subdomain, port, cert...)."""

    target: str
    asset_type: str
    value: str
    source: str
    raw: dict[str, Any] = field(default_factory=dict)
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Finding:
    """A threat-intel record tied to an indicator (IP, domain, hash, URL...)."""

    indicator: str
    indicator_type: str
    verdict: str
    source: str
    raw: dict[str, Any] = field(default_factory=dict)
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
