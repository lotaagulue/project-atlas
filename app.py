import streamlit as st

from core import ingest
from core.config import settings
from core.severity import META, score_finding, score_target
from core.storage import SupabaseStorage

st.set_page_config(page_title="Project Atlas", layout="wide")
st.title("Project Atlas — ASM / CTI Dashboard")

if not settings.supabase_url or not settings.supabase_key:
    st.warning("SUPABASE_URL / SUPABASE_KEY are not set. Copy .env.example to .env and fill them in.")
    st.stop()


@st.cache_resource
def get_storage() -> SupabaseStorage:
    return SupabaseStorage()


storage = get_storage()
targets = storage.get_targets()
all_assets = storage.get_assets()
all_findings = storage.get_findings()

assets_by_target: dict[str, list[dict]] = {}
for asset in all_assets:
    assets_by_target.setdefault(asset["target"], []).append(asset)

findings_by_target: dict[str, list[dict]] = {}
for finding in all_findings:
    findings_by_target.setdefault(finding["indicator"], []).append(finding)

with st.sidebar:
    st.header("Tracked targets")

    new_target = st.text_input("Add a target (domain, IP, CVE ID, or ASN)")
    if st.button("Add target") and new_target:
        storage.add_target(new_target.strip())
        st.rerun()

    for t in targets:
        level = score_target(findings_by_target.get(t, []))
        col1, col2 = st.columns([4, 1])
        col1.write(f"{META[level].emoji} {t}")
        if col2.button("x", key=f"remove-{t}"):
            storage.remove_target(t)
            st.rerun()

    st.divider()
    if st.button("Refresh now", type="primary"):
        with st.spinner("Running connectors..."):
            n_assets, n_findings, errors = ingest.run(targets, storage=storage)
        st.success(f"Stored {n_assets} assets and {n_findings} findings.")
        for error in errors:
            st.warning(error)
        st.rerun()

tab_overview, tab_raw = st.tabs(["Overview", "Raw Data"])

with tab_overview:
    if not targets:
        st.info("Add a target in the sidebar to get started.")

    ranked_targets = sorted(targets, key=lambda t: score_target(findings_by_target.get(t, [])), reverse=True)

    for t in ranked_targets:
        t_assets = assets_by_target.get(t, [])
        t_findings = findings_by_target.get(t, [])
        meta = META[score_target(t_findings)]

        with st.container(border=True):
            header = st.columns([1, 5, 3])
            header[0].badge(meta.label, color=meta.color)
            header[1].markdown(f"**{t}**")
            timestamps = [row["fetched_at"] for row in t_assets + t_findings]
            if timestamps:
                header[2].caption(f"Last updated: {max(timestamps)[:19].replace('T', ' ')}")

            if not t_assets and not t_findings:
                st.caption("No data yet — click Refresh now in the sidebar.")
                continue

            if t_findings:
                st.markdown("**Findings**")
                for f in sorted(t_findings, key=score_finding, reverse=True):
                    f_meta = META[score_finding(f)]
                    row = st.columns([1, 2, 6])
                    row[0].badge(f_meta.label, color=f_meta.color)
                    row[1].write(f["source"])
                    row[2].write(f["verdict"])
                    with st.expander("raw", expanded=False):
                        st.json(f["raw"])

            if t_assets:
                st.markdown("**Assets**")
                by_type: dict[str, list[dict]] = {}
                for a in t_assets:
                    by_type.setdefault(a["asset_type"], []).append(a)
                for asset_type, items in by_type.items():
                    with st.expander(f"{asset_type} ({len(items)})", expanded=len(items) <= 5):
                        for item in items:
                            st.write(f"`{item['source']}` — {item['value']}")

with tab_raw:
    st.subheader("Assets")
    if all_assets:
        st.dataframe(all_assets, width="stretch")
    else:
        st.info("No assets yet.")

    st.subheader("Findings")
    if all_findings:
        st.dataframe(all_findings, width="stretch")
    else:
        st.info("No findings yet.")
