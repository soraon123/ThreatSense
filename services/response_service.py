# ─────────────────────────────────────────────────────────────────────────────
# services/response_service.py — Audit logging for every user action
#
# This file is the ONLY place in the application that writes to response_logs.
# Every action — terminate, acknowledge, resolve, add note — goes through here.
#
# Why a dedicated file?
#   If 5 different pages all call db_ops.log_action() directly, and you later
#   want to change the log format, you'd have to find and change 5 files.
#   This way, you change one function here and everything updates.
# ─────────────────────────────────────────────────────────────────────────────

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.collections import log_action, get_recent_logs


# ── Action type constants ──────────────────────────────────────────────────────
# Using constants instead of bare strings prevents typos.
# If you misspell "TERMINATE_SUCCESS" as a constant, Python raises a NameError
# immediately. A misspelled string silently stores the wrong value.

ACTION_TERMINATE_SUCCESS = "TERMINATE_SUCCESS"
ACTION_TERMINATE_FAILED  = "TERMINATE_FAILED"
ACTION_TERMINATE_DENIED  = "TERMINATE_DENIED"
ACTION_ACKNOWLEDGE_EVENT = "ACKNOWLEDGE_EVENT"
ACTION_RESOLVE_EVENT     = "RESOLVE_EVENT"
ACTION_ADD_NOTE          = "ADD_NOTE"
ACTION_SNAPSHOT_SAVED    = "SNAPSHOT_SAVED"


def log_termination(
    db,
    pid: int,
    process_name: str,
    outcome: str,
    reason: str,
) -> str:
    """
    Record one process termination attempt in the audit log.

    outcome must be one of: "success", "failure", "denied"

    The three outcomes map to different action names:
        success → TERMINATE_SUCCESS  (process was ended)
        failure → TERMINATE_FAILED   (tried but could not end it)
        denied  → TERMINATE_DENIED   (blocked before even trying)

    Returns the new log entry's _id as a string.
    """
    action_map = {
        "success": ACTION_TERMINATE_SUCCESS,
        "failure": ACTION_TERMINATE_FAILED,
        "denied":  ACTION_TERMINATE_DENIED,
    }
    action = action_map.get(outcome, "TERMINATE_UNKNOWN")
    return log_action(
        db,
        action=action,
        outcome=outcome,
        reason=reason,
        pid=pid,
        process_name=process_name,
    )


def log_user_action(
    db,
    action_type: str,
    outcome: str,
    reason: str,
    pid: int = None,
    process_name: str = None,
) -> str:
    """
    Record any other user action (acknowledge alert, add note, etc.).

    action_type: one of the ACTION_* constants defined above
    outcome:     "success", "failure", or "denied"
    reason:      human-readable explanation of what happened
    """
    return log_action(
        db,
        action=action_type,
        outcome=outcome,
        reason=reason,
        pid=pid,
        process_name=process_name,
    )


def get_action_history(db, limit: int = 50) -> list[dict]:
    """
    Return the most recent user action log entries, newest first.
    Used by the Analytics page to show the audit trail.
    """
    return get_recent_logs(db, limit=limit)

