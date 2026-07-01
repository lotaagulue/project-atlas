import re

import httpx

from connectors.base import CollectResult, register
from core.models import Finding

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class NvdConnector:
    """NVD CVE API — vulnerability details + CVSS score for a CVE ID target (e.g. CVE-2021-44228). No API key required."""

    name = "nvd"

    def collect(self, target: str) -> CollectResult:
        if not CVE_ID_RE.match(target):
            return []  # this connector only resolves CVE IDs

        response = httpx.get(NVD_URL, params={"cveId": target.upper()}, timeout=30)
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
        if not vulnerabilities:
            return []

        cve = vulnerabilities[0]["cve"]
        description = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        score, severity = self._best_cvss(cve.get("metrics", {}))
        verdict = f"{severity or 'UNKNOWN'} (CVSS {score})" if score is not None else "no CVSS score"

        return [
            Finding(
                indicator=cve["id"],
                indicator_type="cve",
                verdict=verdict,
                source=self.name,
                raw={"description": description, **cve},
            )
        ]

    @staticmethod
    def _best_cvss(metrics: dict) -> tuple[float | None, str | None]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0]["cvssData"]
                return data.get("baseScore"), data.get("baseSeverity")
        return None, None


register(NvdConnector())
