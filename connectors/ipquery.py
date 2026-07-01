import ipaddress

import httpx

from connectors.base import CollectResult, register
from core.models import Asset, Finding

API_URL = "https://api.ipquery.io/{ip}"


class IPQueryConnector:
    """ipquery.io — free IP geolocation/ISP/risk lookup, no API key required."""

    name = "ipquery"

    def collect(self, target: str) -> CollectResult:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return []  # ipquery.io only resolves IPs, not domains

        response = httpx.get(API_URL.format(ip=target), params={"format": "json"}, timeout=10)
        response.raise_for_status()
        data = response.json()

        location = data.get("location", {})
        isp = data.get("isp", {})
        risk = data.get("risk", {})

        asset = Asset(
            target=target,
            asset_type="ip_info",
            value=f"{isp.get('org', 'unknown')} ({location.get('country_code', '??')})",
            source=self.name,
            raw=data,
        )

        flags = [k[len("is_"):] for k, v in risk.items() if k.startswith("is_") and v]
        verdict = f"risk_score={risk.get('risk_score', 0)}"
        if flags:
            verdict += f", flags={','.join(flags)}"

        finding = Finding(
            indicator=target,
            indicator_type="ip",
            verdict=verdict,
            source=self.name,
            raw=data,
        )

        return [asset, finding]


register(IPQueryConnector())
