import ipaddress
import re
from typing import Protocol, Union

from core.models import Asset, Finding

CollectResult = list[Union[Asset, Finding]]

_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$", re.IGNORECASE)


def looks_like_ip(target: str) -> bool:
    """True for valid IPv4/IPv6 addresses."""
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def looks_like_domain(target: str) -> bool:
    """True for plausible hostnames (has a dot, valid label chars, not an IP) -- for connectors that only handle domains."""
    target = target.strip()
    if looks_like_ip(target):
        return False
    return bool(_DOMAIN_RE.match(target))


class Connector(Protocol):
    name: str

    def collect(self, target: str) -> CollectResult: ...


_REGISTRY: dict[str, Connector] = {}


def register(connector: Connector) -> Connector:
    """Add a connector instance to the registry. Call this once per connector module."""
    _REGISTRY[connector.name] = connector
    return connector


def all_connectors() -> list[Connector]:
    return list(_REGISTRY.values())
