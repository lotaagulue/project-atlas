import streamlit as st

from core import ingest
from core.config import settings
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

with st.sidebar:
    st.header("Tracked targets")
    targets = storage.get_targets()

    new_target = st.text_input("Add a target (domain or IP)")
    if st.button("Add target") and new_target:
        storage.add_target(new_target.strip())
        st.rerun()

    for t in targets:
        col1, col2 = st.columns([4, 1])
        col1.write(t)
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

tab_assets, tab_findings = st.tabs(["Assets", "Findings"])

with tab_assets:
    rows = storage.get_assets()
    if rows:
        st.dataframe(rows, use_container_width=True)
    else:
        st.info("No assets yet. Add a target and connectors, then click Refresh now.")

with tab_findings:
    rows = storage.get_findings()
    if rows:
        st.dataframe(rows, use_container_width=True)
    else:
        st.info("No findings yet. Add a target and connectors, then click Refresh now.")
