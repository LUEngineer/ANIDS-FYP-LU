import sys
import os

# Project root added to path because Streamlit runs this file from
# app/pages/, where scanner/storage packages aren't otherwise importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
from storage.db import init_db, get_history, get_scan_detail

init_db()

st.set_page_config(page_title="ANIDS - Scan History", page_icon="📜")
st.title("📜 Scan History")

history = get_history()

if not history:
    st.info("No scans yet. Run one from the Home page.")
else:
    # Aggregate counts per severity level across all saved scans.
    severity_counts = {}
    for scan in history:
        sev = scan["overall_severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    st.caption(f"{len(history)} total scans — " + ", ".join(f"{v} {k}" for k, v in severity_counts.items()))

    # Case-insensitive substring match on target, computed in memory.
    filter_text = st.text_input("Filter by target", value="")
    filtered = [s for s in history if filter_text.lower() in s["target"].lower()]

    severity_icons = {"high": "🔴", "medium": "🟡", "info": "🔵", "low": "🔵"}

    for scan in filtered:
        icon = severity_icons.get(scan["overall_severity"].lower(), "⚪")
        label = f"{icon} {scan['target']} — {scan['timestamp']} — {scan['overall_severity'].upper()}"

        with st.expander(label):
            detail = get_scan_detail(scan["id"])
            for finding in detail["findings"]:
                f_icon = severity_icons.get(finding["severity"].lower(), "⚪")
                st.markdown(f"{f_icon} **{finding['check_name']}** — {finding['description']}")