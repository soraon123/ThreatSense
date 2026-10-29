# ─────────────────────────────────────────────────────────────────────────────
# database/collections.py — Collection setup, schemas, indexes, and CRUD helpers
#
# This file is organized in five clear sections:
#   1. setup_collections()  — create collections with schema validators + indexes
#   2. process_snapshots    — CRUD helpers for snapshot data
#   3. security_events      — CRUD helpers for alert data
#   4. incidents            — CRUD helpers for investigation cases
#   5. response_logs        — CRUD helpers for audit trail
#   6. aggregation helpers  — analytics queries used by the dashboard
# ─────────────────────────────────────────────────────────────────────────────

from datetime import datetime, timedelta, timezone
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.database import Database
from pymongo.errors import CollectionInvalid
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Collection Setup (validators + indexes)
# ═════════════════════════════════════════════════════════════════════════════

def _create_collection_safe(db: Database, name: str, validator: dict):
    """
    Create a collection with a schema validator.

    If the collection already exists (e.g., the app restarts), we skip
    creation silently instead of crashing. CollectionInvalid is the error
    MongoDB raises when a collection with that name already exists.
    """
    try:
        db.create_collection(name, validator=validator)
        print(f"  Created collection: {name}")
    except CollectionInvalid:
        # Collection already exists — that is fine, just move on
        print(f"  Collection already exists (skipped): {name}")


def setup_collections(db: Database):
    """
    Create all four collections with MongoDB schema validation and indexes.

    MongoDB Schema Validation:
        Unlike SQL tables, MongoDB does not enforce a schema by default.
        We add a $jsonSchema validator so MongoDB rejects documents that
        don't match our expected structure. This catches bugs early.

        validationAction: "warn" means MongoDB accepts the document but
        logs a warning. Use "error" for stricter enforcement.
    """
    print("\nSetting up MongoDB collections...")

    # ── process_snapshots ────────────────────────────────────────────────────
    # Stores one document per process per monitoring interval.
    # Required fields: pid (integer) and name (string).
    # All other fields are optional because psutil may not access them
    # for every process (e.g., system processes restrict path access).
    _create_collection_safe(
        db,
        config.COL_SNAPSHOTS,
        validator={
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["pid", "name", "captured_at"],
                "properties": {
                    "pid":          {"bsonType": "int",    "description": "Process ID"},
                    "name":         {"bsonType": "string", "description": "Process name"},
                    "cpu_percent":  {"bsonType": ["double", "null"]},
                    "memory_mb":    {"bsonType": ["double", "null"]},
                    "status":       {"bsonType": ["string", "null"]},
                    "exe_path":     {"bsonType": ["string", "null"]},
                    "num_threads":  {"bsonType": ["int", "null"]},
                    "start_time":   {"bsonType": ["date", "null"]},
                    "captured_at":  {"bsonType": "date"},
                },
            }
        },
    )

    # ── security_events ──────────────────────────────────────────────────────
    # One document per detected suspicious behavior.
    _create_collection_safe(
        db,
        config.COL_EVENTS,
        validator={
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["event_type", "severity", "timestamp", "status"],
                "properties": {
                    "event_type":     {"bsonType": "string"},
                    "severity":       {"enum": ["low", "medium", "high", "critical"]},
                    "pid":            {"bsonType": ["int", "null"]},
                    "process_name":   {"bsonType": ["string", "null"]},
                    "evidence":       {"bsonType": "string"},
                    "timestamp":      {"bsonType": "date"},
                    "status":         {"enum": ["open", "acknowledged", "resolved"]},
                    "acknowledged_by":{"bsonType": ["string", "null"]},
                    "notes":          {"bsonType": "string"},
                },
            }
        },
    )

    # ── incidents ────────────────────────────────────────────────────────────
    # Groups related security_events into an investigation case.
    # related_event_ids is an array of ObjectIds that reference security_events.
    # This is the "referencing" pattern (vs embedding).
    _create_collection_safe(
        db,
        config.COL_INCIDENTS,
        validator={
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["title", "severity", "status", "created_at"],
                "properties": {
                    "title":             {"bsonType": "string"},
                    "severity":          {"enum": ["low", "medium", "high", "critical"]},
                    "status":            {"enum": ["open", "investigating", "resolved", "closed"]},
                    "created_at":        {"bsonType": "date"},
                    "updated_at":        {"bsonType": "date"},
                    "related_event_ids": {"bsonType": "array"},
                    "notes":             {"bsonType": "string"},
                },
            }
        },
    )

    # ── response_logs ────────────────────────────────────────────────────────
    # Immutable audit trail. Every user action is recorded here.
    _create_collection_safe(
        db,
        config.COL_RESPONSE_LOGS,
        validator={
            "$jsonSchema": {
                "bsonType": "object",
                "required": ["action", "outcome", "performed_at"],
                "properties": {
                    "action":        {"bsonType": "string"},
                    "pid":           {"bsonType": ["int", "null"]},
                    "process_name":  {"bsonType": ["string", "null"]},
                    "outcome":       {"enum": ["success", "failure", "denied"]},
                    "reason":        {"bsonType": "string"},
                    "performed_at":  {"bsonType": "date"},
                },
            }
        },
    )

    # ── Create indexes ───────────────────────────────────────────────────────
    _create_indexes(db)
    print("\nCollection setup complete.\n")


def _create_indexes(db: Database):
    """
    Create indexes for query performance.

    Why indexes matter:
        Without an index, MongoDB scans every document in a collection
        to find matches (a "collection scan"). With an index, it jumps
        directly to matching documents — much faster for large collections.

    Index types used here:
        Single-field index  — one field, e.g., {"timestamp": -1}
        Compound index      — multiple fields together
        TTL index           — automatically deletes documents after a set time
    """
    print("  Creating indexes...")

    snapshots = db[config.COL_SNAPSHOTS]
    events    = db[config.COL_EVENTS]
    incidents = db[config.COL_INCIDENTS]
    logs      = db[config.COL_RESPONSE_LOGS]

    # process_snapshots indexes
    # We often query snapshots by time (most recent first) → index on captured_at
    snapshots.create_index([("captured_at", DESCENDING)], name="idx_snapshot_time")

    # We also filter snapshots by process name and PID
    snapshots.create_index([("name", ASCENDING)],         name="idx_snapshot_name")
    snapshots.create_index([("pid",  ASCENDING)],         name="idx_snapshot_pid")

    # TTL index: MongoDB automatically deletes snapshot documents older than
    # SNAPSHOT_RETENTION_DAYS. expireAfterSeconds tells MongoDB how long to keep them.
    # This prevents the collection from growing forever.
    retention_seconds = config.SNAPSHOT_RETENTION_DAYS * 24 * 60 * 60
    snapshots.create_index(
        [("captured_at", ASCENDING)],
        expireAfterSeconds=retention_seconds,
        name="idx_snapshot_ttl",
    )

    # security_events indexes
    # Dashboard shows open events sorted by time → compound index
    events.create_index(
        [("status", ASCENDING), ("timestamp", DESCENDING)],
        name="idx_event_status_time",
    )
    events.create_index([("severity",  ASCENDING)], name="idx_event_severity")
    events.create_index([("pid",       ASCENDING)], name="idx_event_pid")

    # incidents indexes
    incidents.create_index(
        [("status", ASCENDING), ("created_at", DESCENDING)],
        name="idx_incident_status_time",
    )

    # response_logs indexes
    logs.create_index([("performed_at", DESCENDING)], name="idx_log_time")
    logs.create_index([("pid",          ASCENDING)],  name="idx_log_pid")

    print("  Indexes created.")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — process_snapshots CRUD
# ═════════════════════════════════════════════════════════════════════════════

def insert_snapshot(db: Database, snapshot: dict) -> str:
    """
    Insert one process snapshot document.

    snapshot should contain: pid, name, cpu_percent, memory_mb, etc.
    captured_at is added automatically here so callers don't have to remember.

    Returns the new document's _id as a string.
    """
    snapshot["captured_at"] = datetime.now(timezone.utc)
    # Ensure pid is stored as int (BSON int), not Python float
    snapshot["pid"] = int(snapshot.get("pid", 0))
    result = db[config.COL_SNAPSHOTS].insert_one(snapshot)
    return str(result.inserted_id)


def insert_many_snapshots(db: Database, snapshots: list[dict]) -> int:
    """
    Insert multiple snapshot documents in a single database round-trip.

    insert_many is much more efficient than calling insert_one in a loop
    when you have many documents to save at once.

    Returns the number of documents inserted.
    """
    now = datetime.now(timezone.utc)
    for snap in snapshots:
        snap["captured_at"] = now
        snap["pid"] = int(snap.get("pid", 0))
    result = db[config.COL_SNAPSHOTS].insert_many(snapshots)
    return len(result.inserted_ids)


def get_recent_snapshots(db: Database, limit: int = 200) -> list[dict]:
    """
    Retrieve the most recent process snapshots, newest first.

    The sort uses the idx_snapshot_time index we created, so this
    query is fast even with thousands of documents.
    """
    cursor = (
        db[config.COL_SNAPSHOTS]
        .find({}, {"_id": 0})          # exclude _id to keep data simple
        .sort("captured_at", DESCENDING)
        .limit(limit)
    )
    return list(cursor)


def delete_old_snapshots(db: Database) -> int:
    """
    Manually delete snapshots older than SNAPSHOT_RETENTION_DAYS.

    Note: The TTL index also does this automatically, but running this
    manually lets us trigger cleanup on demand during testing.

    Returns the number of documents deleted.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=config.SNAPSHOT_RETENTION_DAYS)
    result = db[config.COL_SNAPSHOTS].delete_many({"captured_at": {"$lt": cutoff}})
    return result.deleted_count


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — security_events CRUD
# ═════════════════════════════════════════════════════════════════════════════

def insert_event(db: Database, event: dict) -> str:
    """
    Insert one security event document.

    Required keys in event: event_type, severity, evidence
    Optional: pid, process_name

    timestamp and default status are added automatically.
    Returns the new document's _id as a string.
    """
    event.setdefault("timestamp",       datetime.now(timezone.utc))
    event.setdefault("status",          "open")
    event.setdefault("acknowledged_by", None)
    event.setdefault("notes",           "")
    event.setdefault("pid",             None)
    event.setdefault("process_name",    None)
    result = db[config.COL_EVENTS].insert_one(event)
    return str(result.inserted_id)


def get_open_events(db: Database, limit: int = 50) -> list[dict]:
    """Return security events with status 'open', newest first."""
    cursor = (
        db[config.COL_EVENTS]
        .find({"status": "open"})
        .sort("timestamp", DESCENDING)
        .limit(limit)
    )
    return list(cursor)


def get_all_events(db: Database, limit: int = 100) -> list[dict]:
    """Return all security events regardless of status, newest first."""
    cursor = (
        db[config.COL_EVENTS]
        .find({})
        .sort("timestamp", DESCENDING)
        .limit(limit)
    )
    return list(cursor)


def get_event_by_id(db: Database, event_id: str) -> dict | None:
    """
    Find one event by its _id string.

    MongoDB stores _id as a BSON ObjectId, not a plain string.
    We must convert the string to ObjectId before querying.
    """
    try:
        oid = ObjectId(event_id)
    except Exception:
        return None  # Invalid ObjectId format
    return db[config.COL_EVENTS].find_one({"_id": oid})


def update_event_status(
    db: Database,
    event_id: str,
    new_status: str,
    notes: str = "",
    acknowledged_by: str = "",
) -> bool:
    """
    Update an event's status (e.g., open → acknowledged → resolved).

    $set only changes the specified fields. Other fields are untouched.
    This is safer than replacing the whole document.

    Returns True if a document was actually updated, False otherwise.
    """
    try:
        oid = ObjectId(event_id)
    except Exception:
        return False

    update_fields = {"status": new_status}
    if notes:
        update_fields["notes"] = notes
    if acknowledged_by:
        update_fields["acknowledged_by"] = acknowledged_by

    result = db[config.COL_EVENTS].update_one(
        {"_id": oid},
        {"$set": update_fields},
    )
    return result.modified_count > 0


def count_events_by_status(db: Database) -> dict:
    """
    Count events grouped by status.

    Returns a dict like: {"open": 5, "acknowledged": 2, "resolved": 10}
    This uses a simple aggregation pipeline.
    """
    pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        {"$sort": {"_id": ASCENDING}},
    ]
    results = db[config.COL_EVENTS].aggregate(pipeline)
    return {doc["_id"]: doc["count"] for doc in results}


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 — incidents CRUD
# ═════════════════════════════════════════════════════════════════════════════

def create_incident(db: Database, title: str, severity: str, related_event_ids: list = None) -> str:
    """
    Create a new investigation incident.

    related_event_ids is a list of security_event _id strings.
    We store them as BSON ObjectIds (the referencing pattern).

    Returns the new incident's _id as a string.
    """
    now = datetime.now(timezone.utc)

    # Convert string IDs to ObjectId for proper BSON storage
    oid_list = []
    for eid in (related_event_ids or []):
        try:
            oid_list.append(ObjectId(eid))
        except Exception:
            pass  # Skip malformed IDs

    incident = {
        "title":             title,
        "severity":          severity,
        "status":            "open",
        "created_at":        now,
        "updated_at":        now,
        "related_event_ids": oid_list,
        "notes":             "",
    }
    result = db[config.COL_INCIDENTS].insert_one(incident)
    return str(result.inserted_id)


def get_active_incidents(db: Database) -> list[dict]:
    """Return incidents that are not yet closed, newest first."""
    cursor = (
        db[config.COL_INCIDENTS]
        .find({"status": {"$ne": "closed"}})
        .sort("created_at", DESCENDING)
    )
    return list(cursor)


def get_all_incidents(db: Database) -> list[dict]:
    """Return all incidents, newest first."""
    return list(db[config.COL_INCIDENTS].find({}).sort("created_at", DESCENDING))


def update_incident(db: Database, incident_id: str, updates: dict) -> bool:
    """
    Update any fields on an incident.

    updates is a dict of field-value pairs, e.g.:
        {"status": "investigating", "notes": "Confirmed false positive."}

    updated_at is always refreshed automatically.
    """
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return False

    updates["updated_at"] = datetime.now(timezone.utc)
    result = db[config.COL_INCIDENTS].update_one(
        {"_id": oid},
        {"$set": updates},
    )
    return result.modified_count > 0


def count_active_incidents(db: Database) -> int:
    """Return the number of incidents that are open or under investigation."""
    return db[config.COL_INCIDENTS].count_documents(
        {"status": {"$in": ["open", "investigating"]}}
    )


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5 — response_logs CRUD
# ═════════════════════════════════════════════════════════════════════════════

def log_action(db: Database, action: str, outcome: str, reason: str,
               pid: int = None, process_name: str = None) -> str:
    """
    Record one user action in the audit log.

    This collection is append-only — we never update or delete response logs.
    Every termination attempt, acknowledgment, and note is recorded here forever
    (or until you manually purge old records).

    Returns the new log entry's _id as a string.
    """
    log_entry = {
        "action":       action,
        "pid":          pid,
        "process_name": process_name,
        "outcome":      outcome,
        "reason":       reason,
        "performed_at": datetime.now(timezone.utc),
    }
    result = db[config.COL_RESPONSE_LOGS].insert_one(log_entry)
    return str(result.inserted_id)


def get_recent_logs(db: Database, limit: int = 50) -> list[dict]:
    """Return the most recent response log entries, newest first."""
    cursor = (
        db[config.COL_RESPONSE_LOGS]
        .find({})
        .sort("performed_at", DESCENDING)
        .limit(limit)
    )
    return list(cursor)


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Aggregation pipeline helpers (used by the Analytics page)
# ═════════════════════════════════════════════════════════════════════════════

def get_events_by_severity(db: Database) -> list[dict]:
    """
    Count security events grouped by severity level.

    Aggregation pipeline steps:
        $group  — group all documents by the 'severity' field,
                  counting how many are in each group
        $sort   — order the results (critical first)

    Returns: [{"severity": "high", "count": 3}, ...]
    """
    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$project": {"severity": "$_id", "count": 1, "_id": 0}},
        {"$sort": {"count": DESCENDING}},
    ]
    return list(db[config.COL_EVENTS].aggregate(pipeline))


def get_top_cpu_processes(db: Database, top_n: int = 10) -> list[dict]:
    """
    Find the processes with the highest average CPU usage across all snapshots.

    Pipeline steps:
        $match   — only include documents where cpu_percent is not null
        $group   — group by process name, compute the average cpu_percent
        $sort    — highest average first
        $limit   — only return the top N
        $project — rename _id to process_name for clarity
    """
    pipeline = [
        {"$match":   {"cpu_percent": {"$ne": None}}},
        {"$group":   {"_id": "$name", "avg_cpu": {"$avg": "$cpu_percent"}}},
        {"$sort":    {"avg_cpu": DESCENDING}},
        {"$limit":   top_n},
        {"$project": {"process_name": "$_id", "avg_cpu": 1, "_id": 0}},
    ]
    return list(db[config.COL_SNAPSHOTS].aggregate(pipeline))


def get_events_per_day(db: Database, days: int = 7) -> list[dict]:
    """
    Count how many security events occurred each day for the last N days.

    $dateToString converts a BSON date to a "YYYY-MM-DD" string so we can
    group by calendar day.

    Returns: [{"date": "2026-10-29", "count": 5}, ...]
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    pipeline = [
        {"$match": {"timestamp": {"$gte": cutoff}}},
        {"$group": {
            "_id": {
                "$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}
            },
            "count": {"$sum": 1},
        }},
        {"$project": {"date": "$_id", "count": 1, "_id": 0}},
        {"$sort": {"date": ASCENDING}},
    ]
    return list(db[config.COL_EVENTS].aggregate(pipeline))


def demonstrate_explain(db: Database):
    """
    Run a query with explain("executionStats") to show how MongoDB executes it.

    This is used in the Analytics page to compare indexed vs non-indexed queries.
    The output shows:
        totalDocsExamined  — how many documents MongoDB had to look at
        totalKeysExamined  — how many index entries were checked
        executionTimeMillis — how long the query took

    A well-indexed query has totalKeysExamined ≈ nReturned (very efficient).
    A collection scan has totalDocsExamined = total documents in collection.
    """
    # PyMongo 4.x: explain() takes no arguments; the verbosity is set separately.
    # We use command() directly to get executionStats verbosity.
    query = {"status": "open"}
    explain_result = db.command(
        "explain",
        {"find": config.COL_EVENTS, "filter": query},
        verbosity="executionStats",
    )
    stats = explain_result.get("executionStats", {})
    return {
        "totalDocsExamined":  stats.get("totalDocsExamined",  "N/A"),
        "totalKeysExamined":  stats.get("totalKeysExamined",  "N/A"),
        "nReturned":          stats.get("nReturned",          "N/A"),
        "executionTimeMillis":stats.get("executionTimeMillis","N/A"),
    }
