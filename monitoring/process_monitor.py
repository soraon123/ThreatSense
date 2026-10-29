# ─────────────────────────────────────────────────────────────────────────────
# monitoring/process_monitor.py — Reads running processes using psutil
#
# This file has ONE job: talk to the operating system via psutil and return
# clean, structured process data. It does not filter, search, or terminate.
#
# Key psutil concepts used here:
#   process_iter()  — iterates over all running processes efficiently
#   proc.oneshot()  — context manager that caches multiple psutil calls for
#                     one process into a single system call. Much faster than
#                     calling each attribute separately.
#   AccessDenied    — raised when we try to read a protected system process
#   NoSuchProcess   — raised if a process exits while we are reading it
# ─────────────────────────────────────────────────────────────────────────────

import psutil
from datetime import datetime, timezone
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def get_process_info(proc: psutil.Process) -> dict | None:
    """
    Safely read all useful fields for one process.

    Returns a dict with process data, or None if the process is inaccessible.

    Why None instead of raising an exception?
        We iterate over hundreds of processes. Some are system-protected and
        will always raise AccessDenied. Returning None lets the caller simply
        skip them with a clean 'if info is not None' check.

    Why proc.oneshot()?
        Without it, each attribute (name, status, cpu_percent, etc.) makes a
        separate OS system call. With oneshot(), psutil bundles them into one
        call — much faster when reading hundreds of processes.
    """
    try:
        with proc.oneshot():

            # cpu_percent(interval=None) returns usage since the last call.
            # The very first call for a process always returns 0.0 — this is
            # a known psutil behaviour. Values become meaningful after a refresh.
            cpu = proc.cpu_percent(interval=None)

            # memory_info().rss is the Resident Set Size: the amount of RAM
            # the process is actually using right now (not virtual memory).
            # We convert bytes → megabytes for readability.
            mem_info  = proc.memory_info()
            memory_mb = round(mem_info.rss / (1024 * 1024), 2)

            # create_time() is a Unix timestamp (seconds since 1970-01-01).
            # We convert it to a Python datetime object with timezone info.
            start_time = datetime.fromtimestamp(proc.create_time(), tz=timezone.utc)

            # exe() gives the full path to the executable.
            # Many system processes block this with AccessDenied, so we
            # catch that specifically and fall back to None.
            try:
                exe_path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                exe_path = None

            return {
                "pid":         proc.pid,
                "name":        proc.name(),
                "status":      proc.status(),
                "cpu_percent": cpu,
                "memory_mb":   memory_mb,
                "num_threads": proc.num_threads(),
                "start_time":  start_time,
                "exe_path":    exe_path,
            }

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # NoSuchProcess  — the process exited between process_iter() and our read
        # AccessDenied   — we have no permission to read this process at all
        # ZombieProcess  — a Unix-specific state where the process has finished
        #                  but its parent hasn't cleaned it up yet (rare on Windows)
        return None


def get_all_processes() -> list[dict]:
    """
    Return a list of info dicts for all readable running processes.

    Processes that cannot be read (due to permissions or early exit) are
    silently skipped. This is intentional — we report what we can see.
    """
    processes = []
    for proc in psutil.process_iter():
        info = get_process_info(proc)
        if info is not None:
            processes.append(info)
    return processes


def get_high_cpu_processes(
    processes: list[dict],
    threshold: float | None = None,
) -> list[dict]:
    """
    Filter and return processes whose CPU usage exceeds the threshold.

    NOTE: High CPU alone does NOT mean a cyberattack. Many legitimate
    processes (video editors, compilers, browsers) use lots of CPU.
    This function is a starting point for investigation, not a verdict.
    """
    if threshold is None:
        threshold = config.CPU_ALERT_THRESHOLD
    return [p for p in processes if p["cpu_percent"] > threshold]


def get_high_memory_processes(
    processes: list[dict],
    threshold_mb: float | None = None,
) -> list[dict]:
    """
    Filter and return processes whose memory usage exceeds the threshold.

    Same caution as high CPU — high memory is not proof of malicious activity.
    """
    if threshold_mb is None:
        threshold_mb = config.MEMORY_ALERT_THRESHOLD_MB
    return [p for p in processes if p["memory_mb"] > threshold_mb]


def collect_and_store_snapshot(db) -> int:
    """
    Read all current processes and save them to the database as a batch.

    This function is meant to be called on a schedule (e.g., every 30 seconds)
    to build historical process data. The Streamlit dashboard calls it manually
    via a "Save Snapshot" button, or it can be triggered from a background loop.

    Returns the number of snapshot records saved.

    Why not store exe_path in bulk snapshots?
        For 200+ processes, storing full paths would use unnecessary space.
        The key metrics (CPU, memory, threads) are what matter for analysis.
    """
    from database.collections import insert_many_snapshots

    processes = get_all_processes()
    if not processes:
        return 0

    snapshots = []
    for p in processes:
        snapshots.append({
            "pid":         int(p["pid"]),
            "name":        p["name"],
            "cpu_percent": float(p["cpu_percent"]),
            "memory_mb":   float(p["memory_mb"]),
            "status":      p["status"],
            "num_threads": int(p["num_threads"]) if p["num_threads"] else None,
            "start_time":  p["start_time"],
            "exe_path":    None,
        })

    return insert_many_snapshots(db, snapshots)

