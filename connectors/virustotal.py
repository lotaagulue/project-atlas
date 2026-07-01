import os

import httpx

from connectors.base import CollectResult, looks_like_domain, looks_like_ip, register
from core.models import Finding

BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalConnector:
    """VirusTotal — multi-engine IP/domain reputation. Requires a free VIRUSTOTAL_API_KEY."""

    name = "virustotal"

    def collect(self, target: str) -> CollectResult:
        if looks_like_ip(target):
            endpoint, indicator_type = f"{BASE_URL}/ip_addresses/{target}", "ip"
        elif looks_like_domain(target):
            endpoint, indicator_type = f"{BASE_URL}/domains/{target}", "domain"
        else:
            return []  # this connector only resolves IPs and domains

        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            raise RuntimeError("VIRUSTOTAL_API_KEY is not set")

        response = httpx.get(endpoint, headers={"x-apikey": api_key}, timeout=20)
        response.raise_for_status()
        data = response.json()["data"]

        stats = data["attributes"].get("last_analysis_stats", {})
        total = sum(stats.values()) or 1
        verdict = (
            f"{stats.get('malicious', 0)}/{total} engines flagged malicious, "
            f"{stats.get('suspicious', 0)} suspicious"
        )

        return [
            Finding(indicator=target, indicator_type=indicator_type, verdict=verdict, source=self.name, raw=data)
        ]


register(VirusTotalConnector())
