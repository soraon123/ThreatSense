# ─────────────────────────────────────────────────────────────────────────────
# app.py — Main dashboard page
#
# This is the entry point for the Streamlit app.
# Run with:  streamlit run app.py
#
# Streamlit automatically discovers pages/1_Process_Manager.py and other
# files in the pages/ folder and adds them to the sidebar navigation.
#
# This page shows a high-level security overview:
#   - Live process count
#   - Open alerts and active incidents (from MongoDB)
#   - Top resource-hungry processes
#   - Recent security events
# ─────────────────────────────────────────────────────────────────────────────

import streamlit as st
import pandas as pd
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from monitoring.process_monitor import get_all_processes
from database.connection import get_database, test_connection
from database.collections import (
    get_open_events,
    count_events_by_status,
    count_active_incidents,
    get_all_incidents,
    get_top_cpu_processes,
)
import config

# ── Page configuration — must be the very first Streamlit call ────────────────
st.set_page_config(
    page_title="Threat Response Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ Adaptive Dynamic Threat Response System")
st.caption("Real-time process monitoring and security event dashboard")
st.markdown("---")

# ── Database connection status ────────────────────────────────────────────────
db_ok, db_msg = test_connection()

if not db_ok:
    st.error(
        f"**MongoDB is not reachable.** Some dashboard sections will be unavailable.\n\n"
        f"Details: {db_msg}\n\n"
        f"Fix: Make sure MongoDB is running, then refresh this page."
    )

# ── Live process data (always available even without DB) ──────────────────────
@st.cache_data(ttl=30)
def load_live_processes() -> list[dict]:
    """Load all running processes. Cached for 30 seconds."""
    return get_all_processes()

live_processes = load_live_processes()
high_cpu_procs = [p for p in live_processes if p["cpu_percent"] > config.CPU_ALERT_THRESHOLD]
high_mem_procs = [p for p in live_processes if p["memory_mb"]   > config.MEMORY_ALERT_THRESHOLD_MB]

# ── Fetch database stats ──────────────────────────────────────────────────────
open_event_count   = 0
active_incident_count = 0
event_status_counts = {}
recent_events       = []
top_cpu_from_db     = []

if db_ok:
    try:
        db = get_database()
        event_status_counts   = count_events_by_status(db)
        open_event_count      = event_status_counts.get("open", 0)
        active_incident_count = count_active_incidents(db)
        recent_events         = get_open_events(db, limit=10)
        top_cpu_from_db       = get_top_cpu_processes(db, top_n=5)
    except Exception as e:
        st.warning(f"Could not load database stats: {e}")

# ── Key metrics row ───────────────────────────────────────────────────────────
st.subheader("Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    label="Running Processes",
    value=len(live_processes),
    help="Total processes readable by the application right now",
)
col2.metric(
    label="Open Security Alerts",
    value=open_event_count,
    delta=None,
    help="Security events in the database with status = 'open'",
    delta_color="inverse",
)
col3.metric(
    label="Active Incidents",
    value=active_incident_count,
    delta=None,
    help="Incidents currently open or under investigation",
    delta_color="inverse",
)
col4.metric(
    label="High CPU Processes",
    value=len(high_cpu_procs),
    help=f"Processes currently using more than {config.CPU_ALERT_THRESHOLD}% CPU",
    delta_color="inverse",
)

st.markdown("---")

# ── Two-column layout for the rest of the dashboard ──────────────────────────
left_col, right_col = st.columns([3, 2])

# ── LEFT: High-resource processes (live) ─────────────────────────────────────
with left_col:
    st.subheader("High-Resource Processes (Live)")

    if high_cpu_procs or high_mem_procs:
        # Combine and deduplicate by PID
        seen_pids = set()
        combined  = []
        for p in high_cpu_procs + high_mem_procs:
            if p["pid"] not in seen_pids:
                seen_pids.add(p["pid"])
                combined.append(p)

        display_rows = []
        for p in sorted(combined, key=lambda x: x["cpu_percent"], reverse=True):
            flags = []
            if p["cpu_percent"] > config.CPU_ALERT_THRESHOLD:
                flags.append("High CPU")
            if p["memory_mb"] > config.MEMORY_ALERT_THRESHOLD_MB:
                flags.append("High Mem")
            display_rows.append({
                "PID":       p["pid"],
                "Name":      p["name"],
                "CPU %":     p["cpu_percent"],
                "Memory MB": p["memory_mb"],
                "Flag":      ", ".join(flags),
            })

        df_hr = pd.DataFrame(display_rows)
        st.dataframe(
            df_hr,
            use_container_width=True,
            hide_index=True,
            column_config={
                "CPU %":     st.column_config.NumberColumn(format="%.1f%%"),
                "Memory MB": st.column_config.NumberColumn(format="%.1f"),
            },
        )
        st.caption(
            "These processes exceed your configured thresholds. "
            "High resource usage alone is not evidence of an attack."
        )
    else:
        st.success(
            f"No processes currently exceed {config.CPU_ALERT_THRESHOLD}% CPU "
            f"or {config.MEMORY_ALERT_THRESHOLD_MB} MB memory."
        )

    # ── Top CPU processes from database history ───────────────────────────────
    if db_ok and top_cpu_from_db:
        st.subheader("Top CPU Processes (Historical Average)")
        df_top = pd.DataFrame(top_cpu_from_db)
        df_top["avg_cpu"] = df_top["avg_cpu"].round(1)
        df_top.columns = ["Process Name", "Avg CPU %"]
        st.dataframe(df_top, use_container_width=True, hide_index=True)
        st.caption(
            "Average CPU usage calculated from all stored process snapshots in the database."
        )

# ── RIGHT: Recent security alerts ─────────────────────────────────────────────
with right_col:
    st.subheader("Recent Security Alerts")

    if not db_ok:
        st.warning("Connect to MongoDB to see security alerts.")

    elif not recent_events:
        st.info(
            "No open security alerts. "
            "Alerts will appear here after the detection engine runs (Phase 6)."
        )

    else:
        for event in recent_events:
            severity = event.get("severity", "low")

            # Choose an icon based on severity level
            icon = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(
                severity, "⚪"
            )

            # Format the timestamp for display
            ts = event.get("timestamp")
            ts_str = ts.strftime("%Y-%m-%d %H:%M") if ts else "Unknown time"

            with st.container():
                st.markdown(
                    f"{icon} **{event.get('event_type', 'Unknown')}** "
                    f"— {event.get('process_name', 'N/A')}  \n"
                    f"<small>{ts_str} &nbsp;|&nbsp; Severity: {severity}</small>",
                    unsafe_allow_html=True,
                )
                st.caption(event.get("evidence", ""))
                st.markdown("---")

    # ── Alert status summary ──────────────────────────────────────────────────
    if db_ok and event_status_counts:
        st.subheader("Alert Status Summary")
        status_df = pd.DataFrame([
            {"Status": k.title(), "Count": v}
            for k, v in event_status_counts.items()
        ])
        st.dataframe(status_df, use_container_width=True, hide_index=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
col_nav1, col_nav2, col_nav3 = st.columns(3)

col_nav1.page_link("pages/1_Process_Manager.py", label="Go to Process Manager",
                   icon="🔍")
col_nav2.page_link("pages/2_Security_Alerts.py", label="Go to Security Alerts",
                   icon="🚨")
col_nav3.page_link("pages/3_Analytics.py",       label="Go to Analytics",
                   icon="📊")

st.caption(
    f"Thresholds: CPU > {config.CPU_ALERT_THRESHOLD}%  |  "
    f"Memory > {config.MEMORY_ALERT_THRESHOLD_MB} MB  |  "
    f"Refresh interval: {config.MONITOR_INTERVAL_SECONDS}s  |  "
    f"Snapshot retention: {config.SNAPSHOT_RETENTION_DAYS} days"
)
