import re

import httpx

from connectors.base import CollectResult, register
from core.models import Asset

PEERINGDB_URL = "https://www.peeringdb.com/api/net"
ASN_RE = re.compile(r"^as(\d+)$", re.IGNORECASE)


class PeeringDbConnector:
    """PeeringDB — network/organization info for an ASN target (e.g. AS13335). No API key required."""

    name = "peeringdb"

    def collect(self, target: str) -> CollectResult:
        match = ASN_RE.match(target.strip())
        if not match:
            return []  # this connector only resolves ASN targets like "AS13335"

        response = httpx.get(PEERINGDB_URL, params={"asn": match.group(1)}, timeout=20)
        response.raise_for_status()
        records = response.json().get("data", [])
        if not records:
            return []

        record = records[0]
        return [
            Asset(target=target, asset_type="asn_info", value=record.get("name", "unknown"), source=self.name, raw=record)
        ]


register(PeeringDbConnector())
