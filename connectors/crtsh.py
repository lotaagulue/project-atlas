import time

import httpx

from connectors.base import CollectResult, looks_like_domain, register
from core.models import Asset

CRT_SH_URL = "https://crt.sh/"
MAX_ATTEMPTS = 3


class CrtShConnector:
    """crt.sh — certificate transparency log search, no API key required."""

    name = "crtsh"

    def collect(self, target: str) -> CollectResult:
        if not looks_like_domain(target):
            return []  # crt.sh searches domains only

        response = self._get_with_retry(target)
        response.raise_for_status()
        try:
            entries = response.json()
        except ValueError:
            return []  # crt.sh returns an empty (non-JSON) body when there are no matches

        subdomains: dict[str, dict] = {}
        for entry in entries:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and (name == target or name.endswith(f".{target}")):
                    subdomains.setdefault(name, entry)

        return [
            Asset(target=target, asset_type="subdomain", value=name, source=self.name, raw=entry)
            for name, entry in subdomains.items()
        ]

    def _get_with_retry(self, target: str) -> httpx.Response:
        # crt.sh's public instance frequently 502s under load; retry with backoff before giving up.
        last_error: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            if attempt:
                time.sleep(2**attempt)
            try:
                response = httpx.get(CRT_SH_URL, params={"q": f"%.{target}", "output": "json"}, timeout=60)
            except httpx.TransportError as exc:
                last_error = exc
                continue
            if response.status_code < 500:
                return response
            last_error = httpx.HTTPStatusError(
                f"{response.status_code} from crt.sh", request=response.request, response=response
            )
        raise last_error


register(CrtShConnector())
