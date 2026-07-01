from typing import Protocol, Union

from core.models import Asset, Finding

CollectResult = list[Union[Asset, Finding]]


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
