# ─────────────────────────────────────────────────────────────────────────────
# database/connection.py — Creates and manages the MongoDB connection
#
# Why a separate file?
#   Every other file needs the database. If we put connection logic everywhere,
#   we'd repeat ourselves and have to fix bugs in multiple places.
#   This file is the single source of the database connection.
#
# Key concept — module-level variable:
#   Python runs a module only once. So _client below is created once and reused
#   every time another file calls get_database(). This is the simplest way to
#   avoid opening a new connection on every function call.
# ─────────────────────────────────────────────────────────────────────────────

from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import sys
import os

# Add the project root to sys.path so we can import config from any subfolder
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# _client holds the MongoDB connection. It starts as None (not yet connected).
# We only create the real connection when get_database() is first called.
# This is called "lazy initialization" — delay work until it's actually needed.
_client: MongoClient | None = None


def get_client() -> MongoClient:
    """
    Return the MongoDB client. Create it if this is the first call.

    serverSelectionTimeoutMS=5000 means:
        If MongoDB does not respond within 5 seconds, raise an error
        instead of waiting forever. This gives users a clear error message.
    """
    global _client
    if _client is None:
        _client = MongoClient(
            config.MONGO_URI,
            serverSelectionTimeoutMS=5000,
        )
    return _client


def get_database() -> Database:
    """
    Return the application database object.

    A MongoClient can hold many databases. This always returns the one
    named in config.MONGO_DB_NAME (default: threat_response_db).
    """
    client = get_client()
    return client[config.MONGO_DB_NAME]


def test_connection() -> tuple[bool, str]:
    """
    Ping MongoDB and return a (success, message) tuple.

    Why ping instead of just connecting?
        Creating a MongoClient does not actually open a socket. The real
        connection happens on the first operation. ping is the lightest
        possible operation — it just asks "are you there?".

    Returns:
        (True, success_message)  if MongoDB responds
        (False, error_message)   if MongoDB is unreachable or errors occur
    """
    try:
        client = get_client()
        # admin.command("ping") asks the server to reply with {"ok": 1}
        client.admin.command("ping")
        return True, f"[OK] Connected to MongoDB at {config.MONGO_URI}"

    except ServerSelectionTimeoutError:
        return (
            False,
            "[ERROR] Cannot reach MongoDB. "
            "Make sure MongoDB is running (local) or your URI is correct (Atlas).",
        )
    except ConnectionFailure as e:
        return False, f"[ERROR] Connection failed: {e}"
    except Exception as e:
        return False, f"[ERROR] Unexpected error: {e}"


def close_connection():
    """
    Cleanly close the MongoDB client.

    Call this when the application shuts down to release the connection.
    Not strictly required for small apps, but good practice.
    """
    global _client
    if _client is not None:
        _client.close()
        _client = None
