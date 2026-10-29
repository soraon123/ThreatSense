# ─────────────────────────────────────────────────────────────────────────────
# config.py — Central place for all application settings
#
# Every tunable value lives here. When you want to change a threshold or
# interval, you only change it in one place — not scattered across many files.
#
# Values are read from the .env file. If a value is missing, a safe default
# is used so the app can still start.
# ─────────────────────────────────────────────────────────────────────────────

import os
from dotenv import load_dotenv

# Load values from the .env file into the environment.
# This must run before we read any os.getenv() calls.
load_dotenv()


# ── MongoDB settings ──────────────────────────────────────────────────────────

# The connection string used to reach MongoDB.
# Default points to a local MongoDB instance on the standard port.
MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/")

# The database we will use. All four collections live inside this database.
MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "threat_response_db")


# ── Monitoring settings ───────────────────────────────────────────────────────

# How many seconds to wait between process snapshot collections.
# 30 seconds is a good balance — frequent enough to catch events, slow enough
# not to flood the database.
MONITOR_INTERVAL_SECONDS: int = int(os.getenv("MONITOR_INTERVAL_SECONDS", "30"))

# Process snapshots older than this many days will be deleted automatically.
# This prevents the database from growing without limit.
SNAPSHOT_RETENTION_DAYS: int = int(os.getenv("SNAPSHOT_RETENTION_DAYS", "7"))


# ── Alert thresholds ──────────────────────────────────────────────────────────

# A process exceeding this CPU percentage is considered high-CPU.
# NOTE: High CPU alone does NOT confirm a cyberattack.
CPU_ALERT_THRESHOLD: float = float(os.getenv("CPU_ALERT_THRESHOLD", "80"))

# A process using more than this many megabytes of RAM is considered high-memory.
MEMORY_ALERT_THRESHOLD_MB: float = float(os.getenv("MEMORY_ALERT_THRESHOLD_MB", "500"))

# An alert is only created if the process stays above the CPU threshold for
# this many consecutive monitoring intervals. This reduces false positives.
CPU_ALERT_CONSECUTIVE_COUNT: int = int(os.getenv("CPU_ALERT_CONSECUTIVE_COUNT", "3"))


# ── Feature flags ─────────────────────────────────────────────────────────────

# When True, the optional Isolation Forest ML model will also run.
# When False (the default), only rule-based detection is used.
ENABLE_ML_DETECTOR: bool = os.getenv("ENABLE_ML_DETECTOR", "false").lower() == "true"


# ── Process safety blocklist ──────────────────────────────────────────────────

# These critical Windows system processes can NEVER be terminated by this app,
# regardless of what the user requests. This is a hard safety guardrail.
PROTECTED_PROCESS_NAMES: list = [
    "system",
    "svchost.exe",
    "lsass.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "services.exe",
    "explorer.exe",
]

# The application's own process name is added dynamically at runtime in
# process_service.py to prevent the app from terminating itself.


# ── Collection names ──────────────────────────────────────────────────────────
# Keeping collection names as constants avoids typos across multiple files.

COL_SNAPSHOTS: str = "process_snapshots"
COL_EVENTS: str = "security_events"
COL_INCIDENTS: str = "incidents"
COL_RESPONSE_LOGS: str = "response_logs"

