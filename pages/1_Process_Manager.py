# ─────────────────────────────────────────────────────────────────────────────
# pages/1_Process_Manager.py — Streamlit page: search and browse processes
#
# Streamlit multi-page apps: any Python file inside the pages/ folder is
# automatically shown as a sidebar menu item. The filename prefix (1_) sets
# the order; the rest becomes the page label shown to the user.
#
# Run the whole app with:  streamlit run app.py
# ─────────────────────────────────────────────────────────────────────────────

import streamlit as st
import pandas as pd
import sys
import os

# Add the project root to sys.path so we can import our own modules.
# __file__ is this file's path; dirname twice goes up to the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitoring.process_monitor import get_all_processes, collect_and_store_snapshot
from services.process_service import search_processes, apply_filters, build_display_dataframe
from database.connection import get_database, test_connection
import config

# ── Page configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Process Manager",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 Process Manager")
st.caption(
    "Browse and search all currently running processes. "
    "CPU values update on each refresh (first load always shows 0% — this is normal)."
)

# ── Cached process loader ─────────────────────────────────────────────────────
# st.cache_data(ttl=30) caches the function result for 30 seconds.
# This means typing in the search box does NOT trigger a new psutil read
# every keystroke — it reuses the cached list. Only "Refresh" clears it.
@st.cache_data(ttl=30)
def load_processes() -> list[dict]:
    """Read all processes from the OS. Cached for 30 seconds."""
    return get_all_processes()

# ── Top controls row ──────────────────────────────────────────────────────────
col_search, col_btn = st.columns([5, 1])

with col_search:
    search_query = st.text_input(
        "Search",
        placeholder="Type a process name (e.g. chrome) or a PID (e.g. 1234)",
        label_visibility="collapsed",
    )

with col_btn:
    if st.button("🔄 Refresh", use_container_width=True):
        # Clear the cache so the next load_processes() reads fresh data
        st.cache_data.clear()
        st.rerun()

# ── Load processes ────────────────────────────────────────────────────────────
all_processes = load_processes()

# ── Filter row ────────────────────────────────────────────────────────────────
st.markdown("**Quick filters:**")
fcol1, fcol2, fcol3 = st.columns(3)

with fcol1:
    show_high_cpu = st.checkbox(
        f"High CPU  (> {config.CPU_ALERT_THRESHOLD:.0f}%)"
    )
with fcol2:
    show_high_mem = st.checkbox(
        f"High Memory  (> {config.MEMORY_ALERT_THRESHOLD_MB:.0f} MB)"
    )
with fcol3:
    # Let the user adjust the CPU threshold on the fly
    cpu_slider = st.slider(
        "CPU threshold %",
        min_value=10,
        max_value=100,
        value=int(config.CPU_ALERT_THRESHOLD),
        step=5,
        help="Only used when 'High CPU' filter is active",
    )

# ── Apply search and filters ──────────────────────────────────────────────────
filtered = search_processes(all_processes, search_query)
filtered = apply_filters(
    filtered,
    high_cpu=show_high_cpu,
    high_memory=show_high_mem,
    cpu_threshold=float(cpu_slider),
)

# ── Summary metrics strip ─────────────────────────────────────────────────────
st.markdown("---")
m1, m2, m3, m4 = st.columns(4)

total_loaded  = len(all_processes)
showing_count = len(filtered)
high_cpu_count = len([p for p in all_processes if p["cpu_percent"] > config.CPU_ALERT_THRESHOLD])
high_mem_count = len([p for p in all_processes if p["memory_mb"]   > config.MEMORY_ALERT_THRESHOLD_MB])

m1.metric("Total Processes",   total_loaded)
m2.metric("Showing",           showing_count)
m3.metric("High CPU",          high_cpu_count,  delta_color="inverse")
m4.metric("High Memory",       high_mem_count,  delta_color="inverse")

st.markdown("---")

# ── Process table ─────────────────────────────────────────────────────────────
if not filtered:
    if search_query or show_high_cpu or show_high_mem:
        st.info("No processes match your search or filters. Try clearing some filters.")
    else:
        st.warning("No processes found. Click Refresh to try again.")
else:
    df = build_display_dataframe(filtered)

    # Column configuration controls how each column is displayed in st.dataframe
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        height=520,
        column_config={
            "PID": st.column_config.NumberColumn(
                "PID",
                help="Process ID — unique number assigned by the OS",
                format="%d",
                width="small",
            ),
            "CPU %": st.column_config.NumberColumn(
                "CPU %",
                help="Percentage of CPU time used",
                format="%.1f%%",
                width="small",
            ),
            "Memory MB": st.column_config.NumberColumn(
                "Memory MB",
                help="Resident Set Size — actual RAM in use (MB)",
                format="%.1f",
                width="small",
            ),
            "Threads": st.column_config.NumberColumn(
                "Threads",
                format="%d",
                width="small",
            ),
            "Flag": st.column_config.TextColumn(
                "Flag",
                help="Normal = within thresholds.  High CPU / High Mem = exceeds threshold.",
                width="small",
            ),
            "Path": st.column_config.TextColumn(
                "Executable Path",
                width="large",
            ),
        },
    )

# ── Save snapshot button ──────────────────────────────────────────────────────
st.markdown("---")
st.markdown("### Save Snapshot to Database")
st.caption(
    "This saves the current list of all running processes to MongoDB for historical analysis. "
    "In normal operation this happens automatically every 30 seconds."
)

if st.button("Save Current Snapshot"):
    ok, msg = test_connection()
    if not ok:
        st.error(f"Cannot reach MongoDB: {msg}")
    else:
        db = get_database()
        count = collect_and_store_snapshot(db)
        st.success(f"Saved {count} process records to the database.")

# ── Educational note ──────────────────────────────────────────────────────────
with st.expander("About the Flag column and resource thresholds"):
    st.markdown(
        f"""
**What the Flag column means:**
- **Normal** — CPU below {config.CPU_ALERT_THRESHOLD}% AND memory below {config.MEMORY_ALERT_THRESHOLD_MB} MB
- **High CPU** — CPU exceeded {config.CPU_ALERT_THRESHOLD}% at the time of the last refresh
- **High Mem** — Memory exceeded {config.MEMORY_ALERT_THRESHOLD_MB} MB at the time of the last refresh
- A process can have both flags at once

**Important limitation:**
High resource usage does not prove a cyberattack. A video editor rendering a file,
a browser loading a complex page, or an antivirus scan will all show high CPU.
The Flag column is a starting point for investigation — not a verdict.

**Why do CPU values show 0% on first load?**
psutil measures CPU usage as the difference between two readings taken at different
times. On the very first call for each process there is no previous reading, so
psutil reports 0%. Click **Refresh** to get real values.

**You can change thresholds in your `.env` file:**
- `CPU_ALERT_THRESHOLD` (currently {config.CPU_ALERT_THRESHOLD})
- `MEMORY_ALERT_THRESHOLD_MB` (currently {config.MEMORY_ALERT_THRESHOLD_MB})
        """
    )

# ── Coming in Phase 5 ─────────────────────────────────────────────────────────
st.info(
    "**Process termination** will be added in Phase 5. "
    "It will require explicit confirmation and protect critical system processes."
)

