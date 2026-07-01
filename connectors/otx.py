import os

import httpx

from connectors.base import CollectResult, looks_like_domain, looks_like_ip, register
from core.models import Finding

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


class OtxConnector:
    """AlienVault OTX — threat-intel pulse lookups for IPs/domains. Requires a free OTX_API_KEY."""

    name = "otx"

    def collect(self, target: str) -> CollectResult:
        if looks_like_ip(target):
            section, indicator_type = "IPv4", "ip"
        elif looks_like_domain(target):
            section, indicator_type = "domain", "domain"
        else:
            return []  # this connector only resolves IPs and domains

        api_key = os.getenv("OTX_API_KEY")
        if not api_key:
            raise RuntimeError("OTX_API_KEY is not set")

        response = httpx.get(
            f"{BASE_URL}/{section}/{target}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        verdict = f"seen in {pulse_count} threat-intel pulse(s)" if pulse_count else "no pulses found"

        return [
            Finding(indicator=target, indicator_type=indicator_type, verdict=verdict, source=self.name, raw=data)
        ]


register(OtxConnector())
