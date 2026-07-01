import re
import time

import httpx

from connectors.base import CollectResult, register
from core.models import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CACHE_TTL_SECONDS = 3600

_catalog: dict[str, dict] = {}
_catalog_fetched_at = 0.0


class CisaKevConnector:
    """CISA Known Exploited Vulnerabilities catalog — flags a CVE as actively exploited in the wild. No API key required."""

    name = "cisa_kev"

    def collect(self, target: str) -> CollectResult:
        if not CVE_ID_RE.match(target):
            return []  # this connector only resolves CVE IDs

        entry = self._get_catalog().get(target.upper())
        if not entry:
            return []  # not in the KEV catalog -- absence just means "not confirmed exploited", not "safe"

        verdict = f"actively exploited, added {entry['dateAdded']}"
        if entry.get("knownRansomwareCampaignUse") == "Known":
            verdict += ", used in ransomware campaigns"

        return [
            Finding(
                indicator=entry["cveID"],
                indicator_type="cve",
                verdict=verdict,
                source=self.name,
                raw=entry,
            )
        ]

    def _get_catalog(self) -> dict[str, dict]:
        global _catalog_fetched_at
        if not _catalog or time.time() - _catalog_fetched_at > CACHE_TTL_SECONDS:
            response = httpx.get(KEV_URL, timeout=60)
            response.raise_for_status()
            vulnerabilities = response.json().get("vulnerabilities", [])
            _catalog.clear()
            _catalog.update({v["cveID"]: v for v in vulnerabilities})
            _catalog_fetched_at = time.time()
        return _catalog


register(CisaKevConnector())
