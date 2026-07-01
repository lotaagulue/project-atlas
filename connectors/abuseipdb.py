import os

import httpx

from connectors.base import CollectResult, looks_like_ip, register
from core.models import Finding

API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBConnector:
    """AbuseIPDB — IP abuse/reputation reports. Requires a free ABUSEIPDB_API_KEY."""

    name = "abuseipdb"

    def collect(self, target: str) -> CollectResult:
        if not looks_like_ip(target):
            return []  # AbuseIPDB only checks IPs

        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            raise RuntimeError("ABUSEIPDB_API_KEY is not set")

        response = httpx.get(
            API_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": target, "maxAgeInDays": 90},
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()["data"]

        score = data.get("abuseConfidenceScore", 0)
        verdict = f"abuse_confidence={score}%, reports={data.get('totalReports', 0)}"

        return [
            Finding(indicator=target, indicator_type="ip", verdict=verdict, source=self.name, raw=data)
        ]


register(AbuseIPDBConnector())
