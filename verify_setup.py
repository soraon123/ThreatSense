# ─────────────────────────────────────────────────────────────────────────────
# verify_setup.py — Run this script to confirm your environment is ready.
#
# This script checks:
#   1. Python version
#   2. All required packages are installed
#   3. MongoDB is reachable
#   4. The .env file exists and has required keys
#   5. psutil can read running processes
#
# Run it with:  python verify_setup.py
# ─────────────────────────────────────────────────────────────────────────────

import sys
import os

# We print section headers to make the output easy to read.
def section(title: str):
    print(f"\n{'─' * 50}")
    print(f"  {title}")
    print('─' * 50)

def check_passed(msg: str):
    print(f"  ✅  {msg}")

def check_failed(msg: str):
    print(f"  ❌  {msg}")


# ── 1. Python version ─────────────────────────────────────────────────────────
section("1. Python Version")
major, minor = sys.version_info.major, sys.version_info.minor
print(f"  Python {major}.{minor} detected.")
if major == 3 and minor >= 9:
    check_passed("Python version is 3.9 or higher — OK.")
else:
    check_failed("Please upgrade to Python 3.9 or higher.")


# ── 2. Required packages ──────────────────────────────────────────────────────
section("2. Required Packages")

# Each entry is (import_name, display_name)
required_packages = [
    ("streamlit",    "streamlit"),
    ("psutil",       "psutil"),
    ("pymongo",      "pymongo"),
    ("pandas",       "pandas"),
    ("sklearn",      "scikit-learn"),
    ("dotenv",       "python-dotenv"),
    ("pytest",       "pytest"),
    ("plotly",       "plotly"),
]

all_packages_ok = True
for import_name, display_name in required_packages:
    try:
        __import__(import_name)
        check_passed(f"{display_name} is installed.")
    except ImportError:
        check_failed(f"{display_name} is NOT installed.  Run: pip install {display_name}")
        all_packages_ok = False


# ── 3. .env file ──────────────────────────────────────────────────────────────
section("3. Environment File (.env)")

env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(env_path):
    check_passed(".env file found.")
else:
    check_failed(".env file not found.  Copy .env.example to .env and fill in your values.")

# Load it and check required keys exist
try:
    from dotenv import load_dotenv
    load_dotenv()
    required_keys = ["MONGO_URI", "MONGO_DB_NAME"]
    for key in required_keys:
        value = os.getenv(key)
        if value:
            check_passed(f"{key} is set.")
        else:
            check_failed(f"{key} is missing from .env.")
except Exception as e:
    check_failed(f"Could not read .env file: {e}")


# ── 4. MongoDB connection ──────────────────────────────────────────────────────
section("4. MongoDB Connection")

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    db_name   = os.getenv("MONGO_DB_NAME", "threat_response_db")

    # serverSelectionTimeoutMS=3000 means: if MongoDB is not reachable
    # within 3 seconds, give up and raise an error instead of hanging forever.
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)

    # ping is a lightweight command that just checks if the server responds.
    client.admin.command("ping")
    check_passed(f"MongoDB is reachable at: {mongo_uri}")

    # Check that we can access our database
    db = client[db_name]
    # list_collection_names() is a harmless read operation
    collections = db.list_collection_names()
    check_passed(f"Database '{db_name}' is accessible. Collections: {collections or '(empty — will be created later)'}")

    client.close()

except ServerSelectionTimeoutError:
    check_failed(
        "Cannot reach MongoDB. Make sure MongoDB is running.\n"
        "  Local:  Run 'mongod' or start the MongoDB service.\n"
        "  Atlas:  Check your internet connection and MONGO_URI in .env."
    )
except Exception as e:
    check_failed(f"MongoDB error: {e}")


# ── 5. psutil process reading ─────────────────────────────────────────────────
section("5. psutil — Reading Running Processes")

try:
    import psutil
    processes = list(psutil.process_iter(["pid", "name", "status"]))
    count = len(processes)
    check_passed(f"psutil can read {count} running processes.")

    # Show a sample of 3 processes so you can see it's working
    print("\n  Sample processes:")
    for proc in processes[:3]:
        info = proc.info
        print(f"    PID {info['pid']:>6}  {info['name']}")
except Exception as e:
    check_failed(f"psutil error: {e}")


# ── Summary ───────────────────────────────────────────────────────────────────
section("Setup Verification Complete")
print("  If all checks show ✅, your environment is ready for Phase 3.")
print("  Fix any ❌ items before continuing.\n")

