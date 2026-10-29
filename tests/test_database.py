# ─────────────────────────────────────────────────────────────────────────────
# tests/test_database.py — Automated tests for the database layer
#
# Run with:  pytest tests/test_database.py -v
#
# IMPORTANT: These tests use a SEPARATE test database (threat_response_test_db)
# so they never touch your real data. The test database is created before each
# test and deleted (dropped) after each test by the pytest fixture below.
#
# What is a pytest fixture?
#   A fixture is a function that sets up resources a test needs, gives them to
#   the test, and then cleans up after the test finishes. The `yield` keyword
#   is where the test runs — everything after yield is cleanup.
# ─────────────────────────────────────────────────────────────────────────────

import sys
import os
import pytest
from datetime import datetime, timezone
from pymongo import MongoClient

# Make sure Python can find our project modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from database.connection import test_connection
from database import collections as db_ops

# Use a dedicated test database — never the production database
TEST_DB_NAME = "threat_response_test_db"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def test_db():
    """
    Create a fresh, empty test database for one test.
    After the test finishes, the entire test database is dropped.

    scope="function" means: run this fixture once per test function.
    This guarantees every test starts with a clean slate.
    """
    client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=3000)
    db = client[TEST_DB_NAME]

    # Set up collections and indexes in the test database
    db_ops.setup_collections(db)

    yield db  # <── test runs here

    # Cleanup: drop the test database so nothing persists
    client.drop_database(TEST_DB_NAME)
    client.close()


# ── Connection tests ───────────────────────────────────────────────────────────

def test_connection_succeeds():
    """MongoDB should be reachable and return a success message."""
    success, message = test_connection()
    assert success is True, f"Expected connection to succeed. Got: {message}"
    assert "Connected" in message


# ── process_snapshots tests ────────────────────────────────────────────────────

def test_insert_and_read_snapshot(test_db):
    """
    Insert one snapshot and verify it can be read back.
    This tests the basic Create → Read cycle.
    """
    snapshot = {
        "pid":         int(9999),
        "name":        "test_proc.exe",
        "cpu_percent": float(50.0),
        "memory_mb":   float(128.0),
        "status":      "running",
        "exe_path":    None,
        "num_threads": int(4),
        "start_time":  datetime.now(timezone.utc),
    }
    inserted_id = db_ops.insert_snapshot(test_db, snapshot)

    # The returned ID should be a non-empty string
    assert isinstance(inserted_id, str)
    assert len(inserted_id) > 0

    # Read it back and verify the data
    snapshots = db_ops.get_recent_snapshots(test_db, limit=10)
    assert len(snapshots) == 1
    assert snapshots[0]["name"] == "test_proc.exe"
    assert snapshots[0]["pid"]  == 9999


def test_insert_many_snapshots(test_db):
    """insert_many should insert all documents in a single call."""
    batch = [
        {"pid": int(i), "name": f"proc_{i}.exe", "cpu_percent": float(i * 10),
         "memory_mb": float(100.0), "status": "running", "exe_path": None,
         "num_threads": int(2), "start_time": None}
        for i in range(1, 6)   # 5 snapshots
    ]
    count = db_ops.insert_many_snapshots(test_db, batch)
    assert count == 5

    all_snaps = db_ops.get_recent_snapshots(test_db, limit=10)
    assert len(all_snaps) == 5


# ── security_events tests ──────────────────────────────────────────────────────

def test_insert_and_read_event(test_db):
    """Insert a security event and verify it appears in open events."""
    event_id = db_ops.insert_event(test_db, {
        "event_type":   "HIGH_CPU",
        "severity":     "medium",
        "pid":          int(1234),
        "process_name": "bad_proc.exe",
        "evidence":     "CPU stayed above 80% for 3 intervals.",
    })
    assert isinstance(event_id, str)

    open_events = db_ops.get_open_events(test_db)
    assert len(open_events) == 1
    assert open_events[0]["event_type"] == "HIGH_CPU"
    assert open_events[0]["status"]     == "open"


def test_get_event_by_id(test_db):
    """Fetching an event by its _id string should return the correct document."""
    event_id = db_ops.insert_event(test_db, {
        "event_type":   "HIGH_MEMORY",
        "severity":     "high",
        "evidence":     "Memory exceeded threshold.",
    })

    found = db_ops.get_event_by_id(test_db, event_id)
    assert found is not None
    assert found["event_type"] == "HIGH_MEMORY"


def test_get_event_by_invalid_id(test_db):
    """Passing a malformed ID string should return None, not raise an exception."""
    result = db_ops.get_event_by_id(test_db, "not-a-valid-objectid")
    assert result is None


def test_update_event_status(test_db):
    """Updating an event's status should change it from 'open' to 'acknowledged'."""
    event_id = db_ops.insert_event(test_db, {
        "event_type": "HIGH_CPU",
        "severity":   "low",
        "evidence":   "Brief spike.",
    })

    success = db_ops.update_event_status(
        test_db,
        event_id=event_id,
        new_status="acknowledged",
        notes="Reviewed, harmless.",
        acknowledged_by="test_user",
    )
    assert success is True

    # Verify it is no longer in the open list
    open_events = db_ops.get_open_events(test_db)
    assert len(open_events) == 0

    # Verify the notes were saved
    updated = db_ops.get_event_by_id(test_db, event_id)
    assert updated["status"]           == "acknowledged"
    assert updated["notes"]            == "Reviewed, harmless."
    assert updated["acknowledged_by"]  == "test_user"


def test_count_events_by_status(test_db):
    """Aggregation grouping by status should return correct counts."""
    db_ops.insert_event(test_db, {"event_type": "A", "severity": "low",  "evidence": "e1"})
    db_ops.insert_event(test_db, {"event_type": "B", "severity": "high", "evidence": "e2"})

    event_id = db_ops.insert_event(test_db, {"event_type": "C", "severity": "low", "evidence": "e3"})
    db_ops.update_event_status(test_db, event_id, "resolved")

    counts = db_ops.count_events_by_status(test_db)
    assert counts.get("open", 0)     == 2
    assert counts.get("resolved", 0) == 1


# ── incidents tests ────────────────────────────────────────────────────────────

def test_create_and_read_incident(test_db):
    """Create an incident and confirm it appears in the active incidents list."""
    incident_id = db_ops.create_incident(
        test_db,
        title="Test incident",
        severity="high",
        related_event_ids=[],
    )
    assert isinstance(incident_id, str)

    active = db_ops.get_active_incidents(test_db)
    assert len(active) == 1
    assert active[0]["title"]    == "Test incident"
    assert active[0]["status"]   == "open"
    assert active[0]["severity"] == "high"


def test_update_incident(test_db):
    """Updating an incident's status should change it and refresh updated_at."""
    incident_id = db_ops.create_incident(test_db, "Sample", "low")

    success = db_ops.update_incident(
        test_db,
        incident_id=incident_id,
        updates={"status": "resolved", "notes": "No real threat."},
    )
    assert success is True

    all_incidents = db_ops.get_all_incidents(test_db)
    resolved = [i for i in all_incidents if i["status"] == "resolved"]
    assert len(resolved) == 1
    assert resolved[0]["notes"] == "No real threat."

    # A resolved incident is not active
    active = db_ops.count_active_incidents(test_db)
    assert active == 0


# ── response_logs tests ────────────────────────────────────────────────────────

def test_log_action(test_db):
    """Log an action and confirm it is stored correctly."""
    log_id = db_ops.log_action(
        test_db,
        action="TERMINATE_PROCESS",
        outcome="success",
        reason="User confirmed termination.",
        pid=7777,
        process_name="dummy.exe",
    )
    assert isinstance(log_id, str)

    logs = db_ops.get_recent_logs(test_db, limit=5)
    assert len(logs) == 1
    assert logs[0]["action"]       == "TERMINATE_PROCESS"
    assert logs[0]["outcome"]      == "success"
    assert logs[0]["process_name"] == "dummy.exe"


# ── aggregation tests ──────────────────────────────────────────────────────────

def test_get_events_by_severity(test_db):
    """Aggregation pipeline should correctly count events by severity."""
    db_ops.insert_event(test_db, {"event_type": "A", "severity": "high",   "evidence": "x"})
    db_ops.insert_event(test_db, {"event_type": "B", "severity": "high",   "evidence": "x"})
    db_ops.insert_event(test_db, {"event_type": "C", "severity": "medium", "evidence": "x"})

    results = db_ops.get_events_by_severity(test_db)
    result_dict = {r["severity"]: r["count"] for r in results}

    assert result_dict.get("high",   0) == 2
    assert result_dict.get("medium", 0) == 1


def test_get_top_cpu_processes(test_db):
    """Aggregation should return the process with the highest average CPU."""
    db_ops.insert_many_snapshots(test_db, [
        {"pid": int(1), "name": "hungry.exe",  "cpu_percent": float(90.0),
         "memory_mb": float(100.0), "status": "running", "exe_path": None,
         "num_threads": int(1), "start_time": None},
        {"pid": int(2), "name": "idle.exe",    "cpu_percent": float(2.0),
         "memory_mb": float(50.0),  "status": "running", "exe_path": None,
         "num_threads": int(1), "start_time": None},
    ])

    top = db_ops.get_top_cpu_processes(test_db, top_n=1)
    assert len(top) == 1
    assert top[0]["process_name"] == "hungry.exe"
    assert top[0]["avg_cpu"]      == pytest.approx(90.0)

