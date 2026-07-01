from core.models import Asset, Finding
from core.storage import SupabaseStorage
from connectors.base import all_connectors


def run(targets: list[str], storage: SupabaseStorage | None = None) -> tuple[int, int]:
    """Run every registered connector against every target and persist the results.

    Returns (assets_stored, findings_stored).
    """
    storage = storage or SupabaseStorage()
    assets: list[Asset] = []
    findings: list[Finding] = []

    for target in targets:
        for connector in all_connectors():
            for record in connector.collect(target):
                if isinstance(record, Asset):
                    assets.append(record)
                elif isinstance(record, Finding):
                    findings.append(record)

    storage.upsert_assets(assets)
    storage.upsert_findings(findings)
    return len(assets), len(findings)
