# ─────────────────────────────────────────────────────────────────────────────
# services/process_service.py — Search, filter, and safe termination
#
# Phase 4 added: search_processes(), apply_filters(), build_display_dataframe()
# Phase 5 adds:  is_protected(), lookup_process_by_pid(), terminate_process_safely()
#
# The termination function is the most safety-critical code in the project.
# Every safety check is a separate, independently meaningful step.
# If even one check fails, termination is aborted and logged.
# ─────────────────────────────────────────────────────────────────────────────

import os
import sys
import psutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import services.response_service as response_service


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Search and filter (from Phase 4, unchanged)
# ═════════════════════════════════════════════════════════════════════════════

def search_processes(processes: list[dict], query: str) -> list[dict]:
    """
    Filter processes by a text query matching process name or PID.

    Rules:
        - Empty query  → return everything (no filtering)
        - Numeric query → match any PID that STARTS WITH the query digits
        - Text query   → match any name that CONTAINS the query (case-insensitive)
    """
    query = query.strip()
    if not query:
        return processes

    query_lower = query.lower()
    is_numeric  = query.isdigit()

    results = []
    for proc in processes:
        name_matches = query_lower in proc["name"].lower()
        pid_matches  = is_numeric and str(proc["pid"]).startswith(query)
        if name_matches or pid_matches:
            results.append(proc)
    return results


def apply_filters(
    processes: list[dict],
    high_cpu:    bool  = False,
    high_memory: bool  = False,
    cpu_threshold:       float | None = None,
    memory_threshold_mb: float | None = None,
) -> list[dict]:
    """
    Apply optional boolean filters to narrow down the process list.
    Both filters are AND-ed: a process must pass all active filters.
    """
    if cpu_threshold is None:
        cpu_threshold = config.CPU_ALERT_THRESHOLD
    if memory_threshold_mb is None:
        memory_threshold_mb = config.MEMORY_ALERT_THRESHOLD_MB

    result = processes
    if high_cpu:
        result = [p for p in result if p["cpu_percent"] > cpu_threshold]
    if high_memory:
        result = [p for p in result if p["memory_mb"] > memory_threshold_mb]
    return result


def build_display_dataframe(processes: list[dict]):
    """
    Convert a list of process dicts into a Pandas DataFrame for display.
    Sorted by CPU% descending. Adds a human-readable Flag column.
    """
    import pandas as pd

    if not processes:
        return pd.DataFrame(
            columns=["PID", "Name", "CPU %", "Memory MB", "Status", "Threads", "Path", "Flag"]
        )

    rows = []
    for p in processes:
        flags = []
        if p["cpu_percent"] > config.CPU_ALERT_THRESHOLD:
            flags.append("High CPU")
        if p["memory_mb"] > config.MEMORY_ALERT_THRESHOLD_MB:
            flags.append("High Mem")
        rows.append({
            "PID":       p["pid"],
            "Name":      p["name"],
            "CPU %":     p["cpu_percent"],
            "Memory MB": p["memory_mb"],
            "Status":    p["status"],
            "Threads":   p["num_threads"],
            "Path":      p["exe_path"] or "(restricted)",
            "Flag":      ", ".join(flags) if flags else "Normal",
        })

    import pandas as pd
    df = pd.DataFrame(rows)
    df = df.sort_values("CPU %", ascending=False).reset_index(drop=True)
    return df


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Process lookup and protection check (Phase 5)
# ═════════════════════════════════════════════════════════════════════════════

def is_protected(process_name: str) -> bool:
    """
    Return True if this process name is on the critical system process list.

    Comparison is case-insensitive because Windows process names can vary
    in capitalisation between OS versions (e.g. "System" vs "system").

    The protected list is defined in config.py so it can be reviewed easily
    without digging through service code.
    """
    name_lower = process_name.lower()
    return any(name_lower == protected.lower() for protected in config.PROTECTED_PROCESS_NAMES)


def lookup_process_by_pid(pid: int) -> dict | None:
    """
    Find a running process by PID and return its info dict.

    This is a FRESH read directly from the OS — it does NOT use the
    cached process list. This is important for termination: we need
    current information, not stale data from 30 seconds ago.

    Returns None if the process does not exist or cannot be read.
    """
    try:
        proc = psutil.Process(pid)
        # Import here to avoid circular imports at module load time
        from monitoring.process_monitor import get_process_info
        return get_process_info(proc)
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        # We found the process but can't read its details.
        # Return a minimal dict so the caller knows it exists.
        return {"pid": pid, "name": "(access denied)", "cpu_percent": 0.0,
                "memory_mb": 0.0, "status": "unknown", "num_threads": None,
                "start_time": None, "exe_path": None}


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Safe process termination (Phase 5)
# ═════════════════════════════════════════════════════════════════════════════

def terminate_process_safely(
    pid: int,
    expected_name: str,
    db,
) -> tuple[bool, str]:
    """
    Attempt to terminate a process after passing FIVE independent safety checks.

    Each check is a separate guard. If any check fails, we stop immediately,
    log the denial or failure, and return a clear explanation to the user.

    The five checks, in order:
        1. Never terminate our own process (the Streamlit app itself)
        2. Never terminate a name on the protected-process blocklist
        3. Verify the PID actually exists right now (not from cached data)
        4. PID-reuse guard: confirm the actual process name still matches
           the name the user selected (PIDs can be recycled by the OS)
        5. Double-check the ACTUAL name against the protected list again
           (the cached name the user saw might have been replaced)

    After all checks pass, we:
        a. Call proc.terminate() — sends a polite "please exit" signal
        b. Wait up to 3 seconds for it to exit gracefully
        c. If it hasn't exited, call proc.kill() — forced immediate stop
        d. Log the outcome to response_logs
        e. Return (True, success_message) or (False, error_message)

    Why two-phase termination (terminate then kill)?
        On Linux/macOS, terminate() sends SIGTERM, giving the process a
        chance to save data and exit cleanly. Kill() sends SIGKILL, which
        cannot be caught or ignored.
        On Windows, both effectively call TerminateProcess(), so the wait
        step is brief but we keep the same pattern for cross-platform code.

    Args:
        pid:           The PID shown to the user at the time they clicked Terminate
        expected_name: The process name the user saw — used for PID-reuse check
        db:            The MongoDB database object for audit logging

    Returns:
        (True,  success_message)  if the process was terminated
        (False, error_message)    if any check failed or an error occurred
    """

    # ── Check 1: Never terminate ourselves ───────────────────────────────────
    our_pid = os.getpid()
    if pid == our_pid:
        response_service.log_termination(
            db, pid, expected_name, "denied",
            "Attempted to terminate the monitoring application itself."
        )
        return False, "Cannot terminate PID {}: that is this application's own process.".format(pid)

    # ── Check 2: Protected name check (using the name the user saw) ───────────
    # We check the name the user selected, before even touching the OS.
    # This catches the most common case where someone accidentally picks
    # a system process from the list.
    if is_protected(expected_name):
        response_service.log_termination(
            db, pid, expected_name, "denied",
            f"'{expected_name}' is on the protected system process list."
        )
        return False, (
            f"Cannot terminate '{expected_name}': it is a protected system process. "
            "Terminating it could crash Windows."
        )

    # ── Check 3: Verify the PID still exists (fresh OS read) ─────────────────
    # The user may have selected a process that has since exited on its own.
    # We must not act on stale cached data for a termination request.
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        response_service.log_termination(
            db, pid, expected_name, "failure",
            "Process no longer exists — it may have exited on its own."
        )
        return False, (
            f"Process with PID {pid} no longer exists. "
            "It may have exited on its own before you confirmed."
        )

    # ── Check 4: PID-reuse guard ──────────────────────────────────────────────
    # Operating systems recycle PID numbers. After a process exits, a new,
    # completely unrelated process can get that same PID within seconds.
    # If we blindly terminate by PID, we could kill the wrong process.
    # We prevent this by reading the CURRENT process name and comparing it
    # to what the user originally selected.
    try:
        actual_name = proc.name()
    except psutil.AccessDenied:
        response_service.log_termination(
            db, pid, expected_name, "failure",
            "Access denied while trying to verify process identity."
        )
        return False, (
            f"Access denied while verifying PID {pid}. "
            "Cannot confirm the process is still '{expected_name}'."
        )
    except psutil.NoSuchProcess:
        response_service.log_termination(
            db, pid, expected_name, "failure",
            "Process exited between identity check and termination."
        )
        return False, f"Process {pid} exited before we could verify and terminate it."

    if actual_name.lower() != expected_name.lower():
        # PID reuse detected — a different process now owns this PID!
        reuse_msg = (
            f"PID reuse detected: PID {pid} now belongs to '{actual_name}', "
            f"not '{expected_name}'. The original process has already exited."
        )
        response_service.log_termination(db, pid, expected_name, "denied", reuse_msg)
        return False, (
            f"Safety check failed: {reuse_msg} "
            "Termination aborted to prevent accidentally harming the wrong process."
        )

    # ── Check 5: Double-check ACTUAL name against protected list ─────────────
    # The name the user saw might have been correct, but we always verify
    # the actual current name too — belt and suspenders.
    if is_protected(actual_name):
        response_service.log_termination(
            db, pid, actual_name, "denied",
            f"Actual process name '{actual_name}' is on the protected list."
        )
        return False, (
            f"Cannot terminate '{actual_name}' (PID {pid}): protected system process."
        )

    # ── All 5 checks passed — attempt termination ─────────────────────────────
    try:
        # Step a: Polite termination request
        proc.terminate()

        # Step b: Wait up to 3 seconds for the process to exit gracefully
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            # Step c: Process ignored the polite request — force-kill it
            proc.kill()

        # Step d: Log success
        response_service.log_termination(
            db, pid, actual_name, "success",
            "User confirmed termination through the dashboard. All safety checks passed."
        )
        return True, f"Process '{actual_name}' (PID {pid}) was terminated successfully."

    except psutil.AccessDenied:
        # This happens when the process runs as Administrator and our app does not.
        error_msg = (
            "Access denied. The process is running with higher privileges than "
            "this application. Try restarting the dashboard as Administrator."
        )
        response_service.log_termination(db, pid, actual_name, "failure", error_msg)
        return False, f"Cannot terminate '{actual_name}': {error_msg}"

    except psutil.NoSuchProcess:
        # The process exited on its own between our last check and the terminate call.
        # This is harmless — the process is gone, which is what we wanted.
        response_service.log_termination(
            db, pid, actual_name, "failure",
            "Process exited on its own just before termination was sent."
        )
        return False, (
            f"'{actual_name}' (PID {pid}) exited on its own just before the "
            "termination signal was sent. The process is gone."
        )

    except Exception as e:
        response_service.log_termination(
            db, pid, actual_name, "failure", f"Unexpected error: {e}"
        )
        return False, f"Unexpected error while terminating '{actual_name}': {e}"
