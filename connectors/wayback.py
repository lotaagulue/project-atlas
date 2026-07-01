from urllib.parse import urlparse

import httpx

from connectors.base import CollectResult, looks_like_domain, register
from core.models import Asset

CDX_URL = "https://web.archive.org/cdx/search/cdx"
ROW_LIMIT = 5000  # safety cap so a huge domain's archive history doesn't hang the refresh


class WaybackConnector:
    """Wayback Machine CDX API — historical subdomain discovery, no API key required."""

    name = "wayback"

    def collect(self, target: str) -> CollectResult:
        if not looks_like_domain(target):
            return []  # the CDX API indexes URLs by hostname, not IPs/CVEs/ASNs

        response = httpx.get(
            CDX_URL,
            params={
                "url": target,
                "matchType": "domain",
                "output": "json",
                "fl": "original,timestamp",
                "collapse": "urlkey",
                "limit": ROW_LIMIT,
            },
            timeout=90,
        )
        response.raise_for_status()
        try:
            rows = response.json()
        except ValueError:
            return []  # empty body when there are no captures at all

        subdomains: dict[str, dict] = {}
        for original, timestamp in rows[1:]:  # first row is the CDX header
            host = (urlparse(original).hostname or "").lower()
            if host and (host == target or host.endswith(f".{target}")):
                subdomains.setdefault(host, {"first_seen_url": original, "timestamp": timestamp})

        return [
            Asset(target=target, asset_type="subdomain", value=host, source=self.name, raw=raw)
            for host, raw in subdomains.items()
        ]

register(WaybackConnector())
