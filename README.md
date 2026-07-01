# Project Atlas

A unified dashboard for attack surface management (ASM) and cyber threat
intelligence (CTI). It aggregates data from external security APIs
(Shodan, VirusTotal, AbuseIPDB, OTX, crt.sh, ...) into two normalized views:

- **Assets** — things discovered about your own attack surface (hosts, subdomains, open ports, certs).
- **Findings** — threat-intel/reputation records tied to an indicator (IP, domain, hash, URL).

## Setup

1. Install dependencies:

   ```sh
   uv sync
   ```

2. Create a [Supabase](https://supabase.com) project, then in its SQL editor run the contents of [schema.sql](schema.sql) to create the `targets`, `assets`, and `findings` tables.
3. Copy `.env.example` to `.env` and fill in `SUPABASE_URL` and `SUPABASE_KEY` from your Supabase project's API settings.
4. Run the dashboard:

   ```sh
   uv run streamlit run app.py
   ```

## Adding a new API connector

Each data source is one file in `connectors/`. A connector implements the
`Connector` protocol from `connectors/base.py`:

```python
# connectors/example.py
from connectors.base import register
from core.models import Asset

class ExampleConnector:
    name = "example"

    def collect(self, target: str) -> list[Asset]:
        # call the API, normalize results into Asset/Finding objects
        return [Asset(target=target, asset_type="host", value="1.2.3.4", source=self.name, raw={})]

register(ExampleConnector())
```

Then import the module once (e.g. in `app.py` or a small `connectors/__init__.py`
import list) so it registers itself, and add its API key to `.env`. No other
file needs to change — `core/ingest.py` automatically runs every registered
connector against every tracked target.

## Deployment

- **App**: [Streamlit Community Cloud](https://streamlit.io/cloud) is the easiest way to host this — connect the GitHub repo, set the same variables from `.env` in its secrets manager, done. For scheduled background ingestion (not just on-demand refresh), move the ingestion job to a small worker on Fly.io or Railway.
- **Database**: Supabase's own hosted cloud (free tier is enough to start).
