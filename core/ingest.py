from core.models import Asset, Finding
from core.storage import SupabaseStorage
from connectors.base import all_connectors


def run(targets: list[str], storage: SupabaseStorage | None = None) -> tuple[int, int, list[str]]:
    """Run every registered connector against every target and persist the results.

    A connector failing (e.g. a flaky upstream API) does not abort the others.
    Returns (assets_stored, findings_stored, errors).
    """
    storage = storage or SupabaseStorage()
    assets: list[Asset] = []
    findings: list[Finding] = []
    errors: list[str] = []

    for target in targets:
        for connector in all_connectors():
            try:
                records = connector.collect(target)
            except Exception as exc:
                errors.append(f"{connector.name} failed for {target}: {exc}")
                continue
            for record in records:
                if isinstance(record, Asset):
                    assets.append(record)
                elif isinstance(record, Finding):
                    findings.append(record)

    storage.upsert_assets(assets)
    storage.upsert_findings(findings)
    return len(assets), len(findings), errors
