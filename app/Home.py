import sys
import os

# Add project root to path so `scanner` and `storage` packages are importable
# when Streamlit runs this file from inside /app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
from scanner.run_scan import run_scan
from storage.db import init_db, save_scan

# Ensures tables exist even on a fresh clone of the repo
init_db()

st.set_page_config(page_title="ANIDS - New Scan", page_icon="🛡️")

st.title("🛡️ ANIDS - Run New Scan")
st.caption("Scans are restricted to private/loopback targets only (localhost, 127.0.0.1, private IP ranges).")

target = st.text_input("Target (hostname or IP)", value="localhost")

if st.button("Run Scan", type="primary"):
    with st.spinner(f"Scanning {target}..."):
        result = run_scan(target)

    if result.get("errors"):
        st.error(f"Scan failed: {result['errors']}")
    else:
        scan_id = save_scan(result)
        st.success(f"Scan complete and saved (scan_id: {scan_id})")

        st.subheader(f"Results for {result['target']}")
        st.metric("Overall Severity", result["overall_severity"].upper())

        # Emoji badge per severity - simple visual cue, no extra CSS needed
        severity_icons = {"high": "🔴", "medium": "🟡", "info": "🔵", "low": "🔵"}

        for finding in result["findings"]:
            icon = severity_icons.get(finding["severity"].lower(), "⚪")
            st.markdown(f"{icon} **{finding['check']}** — {finding['description']}")