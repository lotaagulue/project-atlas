from dataclasses import asdict

from supabase import Client, create_client

from core.config import settings
from core.models import Asset, Finding


class SupabaseStorage:
    def __init__(self, client: Client | None = None) -> None:
        self.client = client or create_client(settings.supabase_url, settings.supabase_key)

    def upsert_assets(self, assets: list[Asset]) -> None:
        if not assets:
            return
        rows = [self._prepare(asdict(a)) for a in assets]
        self.client.table("assets").upsert(rows, on_conflict="source,target,asset_type,value").execute()

    def upsert_findings(self, findings: list[Finding]) -> None:
        if not findings:
            return
        rows = [self._prepare(asdict(f)) for f in findings]
        self.client.table("findings").upsert(rows, on_conflict="source,indicator,indicator_type").execute()

    def get_assets(self) -> list[dict]:
        return self.client.table("assets").select("*").order("fetched_at", desc=True).execute().data

    def get_findings(self) -> list[dict]:
        return self.client.table("findings").select("*").order("fetched_at", desc=True).execute().data

    def get_targets(self) -> list[str]:
        rows = self.client.table("targets").select("value").order("value").execute().data
        return [row["value"] for row in rows]

    def add_target(self, value: str) -> None:
        self.client.table("targets").upsert({"value": value}, on_conflict="value").execute()

    def remove_target(self, value: str) -> None:
        self.client.table("targets").delete().eq("value", value).execute()

    @staticmethod
    def _prepare(row: dict) -> dict:
        row["fetched_at"] = row["fetched_at"].isoformat()
        return row
