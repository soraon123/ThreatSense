# ─────────────────────────────────────────────────────────────────────────────
# database/demo_crud.py — Interactive demo of all database operations
#
# Run this script to see every CRUD operation in action:
#   python database/demo_crud.py
#
# This script:
#   1. Connects to MongoDB
#   2. Sets up collections and indexes
#   3. Inserts sample documents (Create)
#   4. Queries them back (Read)
#   5. Updates a document (Update)
#   6. Deletes a document (Delete)
#   7. Runs aggregation pipelines
#   8. Shows explain() output
#   9. Cleans up the demo data
# ─────────────────────────────────────────────────────────────────────────────

import sys
import os
from datetime import datetime, timezone
from pprint import pprint   # pprint = "pretty print" -- formats dicts nicely

# Make sure Python can find our project modules from any working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import get_database, test_connection
from database import collections as db_ops
import config


def divider(title: str):
    """Print a clearly visible section separator."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print('=' * 60)


def main():
    # Step 1: Test the connection
    divider("Step 1: Test MongoDB Connection")
    success, message = test_connection()
    print(f"  {message}")
    if not success:
        print("\n  Cannot continue without a database connection. Exiting.")
        sys.exit(1)

    db = get_database()
    print(f"  Using database: {db.name}")

    # Step 2: Set up collections
    divider("Step 2: Set Up Collections and Indexes")
    db_ops.setup_collections(db)

    # Step 3: INSERT -- Create sample documents
    divider("Step 3: INSERT (Create)")

    # Insert a process snapshot
    snapshot_id = db_ops.insert_snapshot(db, {
        "pid":          int(1234),
        "name":         "demo_process.exe",
        "cpu_percent":  float(85.5),
        "memory_mb":    float(312.0),
        "status":       "running",
        "exe_path":     "C:/demo/demo_process.exe",
        "num_threads":  int(8),
        "start_time":   datetime.now(timezone.utc),
    })
    print(f"  Inserted snapshot _id: {snapshot_id}")

    # Insert a security event
    event_id = db_ops.insert_event(db, {
        "event_type":   "HIGH_CPU",
        "severity":     "medium",
        "pid":          int(1234),
        "process_name": "demo_process.exe",
        "evidence":     "CPU usage 85.5% exceeded threshold 80% for 3 consecutive checks.",
    })
    print(f"  Inserted event _id:    {event_id}")

    # Insert a second event (high severity) for aggregation demo
    event_id_2 = db_ops.insert_event(db, {
        "event_type":   "HIGH_MEMORY",
        "severity":     "high",
        "pid":          int(5678),
        "process_name": "another_demo.exe",
        "evidence":     "Memory usage 600 MB exceeded threshold 500 MB.",
    })
    print(f"  Inserted event _id:    {event_id_2}")

    # Insert an incident that references both events
    incident_id = db_ops.create_incident(
        db,
        title="Demo Incident: High resource usage on demo processes",
        severity="medium",
        related_event_ids=[event_id, event_id_2],
    )
    print(f"  Inserted incident _id: {incident_id}")

    # Insert a response log entry
    log_id = db_ops.log_action(
        db,
        action="ACKNOWLEDGE_EVENT",
        outcome="success",
        reason="User reviewed the alert during demo.",
        pid=1234,
        process_name="demo_process.exe",
    )
    print(f"  Inserted log _id:      {log_id}")

    # Step 4: READ -- Query documents back
    divider("Step 4: READ (Query)")

    print("\n  [a] Recent snapshots (limit 3):")
    snapshots = db_ops.get_recent_snapshots(db, limit=3)
    for s in snapshots:
        print(f"      PID {s['pid']:>6}  {s['name']:<25}  CPU: {s.get('cpu_percent')}%")

    print("\n  [b] Open security events:")
    events = db_ops.get_open_events(db)
    for e in events:
        print(f"      [{e['severity'].upper():8}] {e['event_type']:<15} -- {e['process_name']}")

    print("\n  [c] Active incidents:")
    incidents = db_ops.get_active_incidents(db)
    for i in incidents:
        print(f"      [{i['status'].upper():15}] {i['title']}")

    print("\n  [d] Get one event by _id:")
    single_event = db_ops.get_event_by_id(db, event_id)
    if single_event:
        print(f"      Found: {single_event['event_type']} on {single_event['process_name']}")

    # Step 5: UPDATE -- Modify a document
    divider("Step 5: UPDATE")

    print("\n  Acknowledging the first event...")
    updated = db_ops.update_event_status(
        db,
        event_id=event_id,
        new_status="acknowledged",
        notes="Reviewed during CRUD demo. CPU spike was brief.",
        acknowledged_by="demo_user",
    )
    print(f"  Update result: {'success' if updated else 'no document changed'}")

    print("\n  Updating incident status to 'investigating'...")
    updated_incident = db_ops.update_incident(
        db,
        incident_id=incident_id,
        updates={"status": "investigating", "notes": "Under active investigation."},
    )
    print(f"  Incident update result: {'success' if updated_incident else 'no document changed'}")

    # Verify the update by reading back
    updated_event = db_ops.get_event_by_id(db, event_id)
    if updated_event:
        print(f"\n  Event status is now: {updated_event['status']}")
        print(f"  Notes: {updated_event['notes']}")

    # Step 6: Aggregation pipelines
    divider("Step 6: Aggregation Pipelines")

    print("\n  [a] Events grouped by severity:")
    by_severity = db_ops.get_events_by_severity(db)
    for row in by_severity:
        print(f"      {row['severity']:<10} -> {row['count']} event(s)")

    print("\n  [b] Events grouped by status:")
    by_status = db_ops.count_events_by_status(db)
    for status, count in by_status.items():
        print(f"      {status:<15} -> {count} event(s)")

    print("\n  [c] Top CPU processes from snapshots:")
    top_cpu = db_ops.get_top_cpu_processes(db, top_n=5)
    for row in top_cpu:
        print(f"      {row['process_name']:<25} avg CPU: {row['avg_cpu']:.1f}%")

    print("\n  [d] Events per day (last 7 days):")
    per_day = db_ops.get_events_per_day(db, days=7)
    for row in per_day:
        print(f"      {row['date']}  ->  {row['count']} event(s)")

    # Step 7: explain() -- Query execution stats
    divider("Step 7: explain('executionStats') -- Index Performance")

    print("\n  Running explain() on: find({'status': 'open'})")
    print("  This uses the compound index (status + timestamp).")
    stats = db_ops.demonstrate_explain(db)
    print(f"\n  totalDocsExamined:   {stats['totalDocsExamined']}")
    print(f"  totalKeysExamined:   {stats['totalKeysExamined']}")
    print(f"  nReturned:           {stats['nReturned']}")
    print(f"  executionTimeMillis: {stats['executionTimeMillis']} ms")
    print()
    print("  Interpretation:")
    print("  If totalKeysExamined ~ nReturned  -> index is being used efficiently.")
    print("  If totalDocsExamined >> nReturned -> full collection scan (no index).")

    # Step 8: DELETE -- Clean up demo data
    divider("Step 8: DELETE (Cleanup Demo Data)")

    # We delete only the demo documents we inserted, identified by process name.
    # In a real app you would use the _id field for precise deletion.
    events_col    = db[config.COL_EVENTS]
    snapshots_col = db[config.COL_SNAPSHOTS]
    incidents_col = db[config.COL_INCIDENTS]
    logs_col      = db[config.COL_RESPONSE_LOGS]

    r1 = snapshots_col.delete_many({"name": "demo_process.exe"})
    r2 = events_col.delete_many({"process_name": {"$in": ["demo_process.exe", "another_demo.exe"]}})
    r3 = incidents_col.delete_many({"title": {"$regex": "Demo Incident"}})
    r4 = logs_col.delete_many({"process_name": "demo_process.exe"})

    print(f"\n  Deleted {r1.deleted_count} snapshot(s)")
    print(f"  Deleted {r2.deleted_count} event(s)")
    print(f"  Deleted {r3.deleted_count} incident(s)")
    print(f"  Deleted {r4.deleted_count} log entry(ies)")

    # Done
    divider("Demo Complete")
    print("  All CRUD operations, aggregation pipelines, and explain() ran successfully.")
    print("  Your database layer is ready for Phase 4.\n")


if __name__ == "__main__":
    main()
