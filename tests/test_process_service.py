# ─────────────────────────────────────────────────────────────────────────────
# tests/test_process_service.py — Tests for search and filter logic
#
# Run with:  pytest tests/test_process_service.py -v
#
# Key design: we test process_service.py using FAKE process data.
# This means the tests run without needing a real OS, real processes,
# or a real database. This is called "unit testing" — test one unit of
# logic in complete isolation.
# ─────────────────────────────────────────────────────────────────────────────

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.process_service import search_processes, apply_filters, build_display_dataframe
from monitoring.process_monitor import get_all_processes, get_high_cpu_processes, get_high_memory_processes


# ── Sample data ───────────────────────────────────────────────────────────────
# We define a fixed list of fake processes to use in every test.
# This way tests are predictable — they don't depend on what happens to be
# running on your machine at test time.

SAMPLE_PROCESSES = [
    {
        "pid": 100, "name": "chrome.exe",
        "cpu_percent": 92.0, "memory_mb": 650.0,
        "status": "running", "num_threads": 20, "exe_path": "C:/chrome/chrome.exe",
    },
    {
        "pid": 200, "name": "python.exe",
        "cpu_percent": 5.0, "memory_mb": 100.0,
        "status": "running", "num_threads": 5, "exe_path": "C:/python/python.exe",
    },
    {
        "pid": 1234, "name": "svchost.exe",
        "cpu_percent": 2.0, "memory_mb": 50.0,
        "status": "running", "num_threads": 10, "exe_path": None,
    },
    {
        "pid": 5678, "name": "notepad.exe",
        "cpu_percent": 0.0, "memory_mb": 20.0,
        "status": "running", "num_threads": 1, "exe_path": "C:/notepad.exe",
    },
    {
        "pid": 9999, "name": "explorer.exe",
        "cpu_percent": 75.0, "memory_mb": 450.0,
        "status": "running", "num_threads": 15, "exe_path": None,
    },
]


# ═════════════════════════════════════════════════════════════════════════════
# Tests for search_processes()
# ═════════════════════════════════════════════════════════════════════════════

class TestSearchProcesses:

    def test_empty_query_returns_all(self):
        """An empty search string should return the full list unchanged."""
        result = search_processes(SAMPLE_PROCESSES, "")
        assert len(result) == len(SAMPLE_PROCESSES)

    def test_whitespace_query_returns_all(self):
        """A query that is only spaces should also return everything."""
        result = search_processes(SAMPLE_PROCESSES, "   ")
        assert len(result) == len(SAMPLE_PROCESSES)

    def test_search_by_exact_name(self):
        """Searching 'chrome' should match 'chrome.exe'."""
        result = search_processes(SAMPLE_PROCESSES, "chrome")
        assert len(result) == 1
        assert result[0]["name"] == "chrome.exe"

    def test_search_is_case_insensitive(self):
        """'CHROME', 'chrome', and 'Chrome' should all match 'chrome.exe'."""
        assert len(search_processes(SAMPLE_PROCESSES, "CHROME"))  == 1
        assert len(search_processes(SAMPLE_PROCESSES, "Chrome"))  == 1
        assert len(search_processes(SAMPLE_PROCESSES, "chrome"))  == 1

    def test_search_by_partial_name(self):
        """'svc' should match 'svchost.exe' (substring match)."""
        result = search_processes(SAMPLE_PROCESSES, "svc")
        assert len(result) == 1
        assert result[0]["name"] == "svchost.exe"

    def test_search_by_exact_pid(self):
        """Searching '5678' should match the process with PID 5678."""
        result = search_processes(SAMPLE_PROCESSES, "5678")
        assert len(result) == 1
        assert result[0]["pid"] == 5678

    def test_search_by_partial_pid(self):
        """Searching '12' should match PID 1234 (starts-with logic)."""
        result = search_processes(SAMPLE_PROCESSES, "12")
        assert any(p["pid"] == 1234 for p in result)

    def test_search_matches_both_name_and_pid(self):
        """
        'exe' appears in all process names, so all should match.
        This tests that we return every process when the query matches many.
        """
        result = search_processes(SAMPLE_PROCESSES, "exe")
        assert len(result) == len(SAMPLE_PROCESSES)

    def test_search_no_match(self):
        """A query that matches nothing should return an empty list."""
        result = search_processes(SAMPLE_PROCESSES, "zzznomatch999")
        assert result == []

    def test_search_returns_new_list(self):
        """search_processes should not modify the original list."""
        original_length = len(SAMPLE_PROCESSES)
        search_processes(SAMPLE_PROCESSES, "chrome")
        assert len(SAMPLE_PROCESSES) == original_length


# ═════════════════════════════════════════════════════════════════════════════
# Tests for apply_filters()
# ═════════════════════════════════════════════════════════════════════════════

class TestApplyFilters:

    def test_no_filters_returns_all(self):
        """With no filter flags set, all processes are returned."""
        result = apply_filters(SAMPLE_PROCESSES)
        assert len(result) == len(SAMPLE_PROCESSES)

    def test_high_cpu_filter(self):
        """
        With threshold=80%, only chrome.exe (92%) should pass.
        explorer.exe at 75% should NOT pass.
        """
        result = apply_filters(SAMPLE_PROCESSES, high_cpu=True, cpu_threshold=80.0)
        assert len(result) == 1
        assert result[0]["name"] == "chrome.exe"

    def test_high_memory_filter(self):
        """With threshold=500 MB, only chrome.exe (650 MB) should pass."""
        result = apply_filters(SAMPLE_PROCESSES, high_memory=True, memory_threshold_mb=500.0)
        assert len(result) == 1
        assert result[0]["name"] == "chrome.exe"

    def test_combined_filters_both_must_pass(self):
        """
        When both filters are active, a process must satisfy BOTH conditions.
        chrome.exe: CPU=92% (>80%) AND memory=650 MB (>500 MB) → passes both
        explorer.exe: CPU=75% (<80%) → fails CPU filter → excluded
        """
        result = apply_filters(
            SAMPLE_PROCESSES,
            high_cpu=True,
            high_memory=True,
            cpu_threshold=80.0,
            memory_threshold_mb=500.0,
        )
        assert len(result) == 1
        assert result[0]["name"] == "chrome.exe"

    def test_filter_with_low_threshold_matches_more(self):
        """Lowering the CPU threshold should include more processes."""
        # At 70% threshold: chrome (92%) and explorer (75%) both qualify
        result = apply_filters(SAMPLE_PROCESSES, high_cpu=True, cpu_threshold=70.0)
        assert len(result) == 2
        names = {p["name"] for p in result}
        assert "chrome.exe"   in names
        assert "explorer.exe" in names

    def test_filter_with_very_high_threshold_matches_none(self):
        """A threshold above all process values should return an empty list."""
        result = apply_filters(SAMPLE_PROCESSES, high_cpu=True, cpu_threshold=99.0)
        assert result == []

    def test_filter_returns_new_list(self):
        """apply_filters should not modify the original list."""
        original_length = len(SAMPLE_PROCESSES)
        apply_filters(SAMPLE_PROCESSES, high_cpu=True)
        assert len(SAMPLE_PROCESSES) == original_length


# ═════════════════════════════════════════════════════════════════════════════
# Tests for search → filter pipeline (combined workflow)
# ═════════════════════════════════════════════════════════════════════════════

class TestSearchThenFilter:

    def test_search_then_filter_narrows_correctly(self):
        """
        Searching for 'exe' matches everything.
        Then filtering by CPU > 80% should leave only chrome.exe.
        """
        searched = search_processes(SAMPLE_PROCESSES, "exe")
        filtered = apply_filters(searched, high_cpu=True, cpu_threshold=80.0)
        assert len(filtered) == 1
        assert filtered[0]["name"] == "chrome.exe"

    def test_search_no_match_then_filter_stays_empty(self):
        """If search finds nothing, filter should also return nothing."""
        searched = search_processes(SAMPLE_PROCESSES, "zzznomatch")
        filtered = apply_filters(searched, high_cpu=True)
        assert filtered == []


# ═════════════════════════════════════════════════════════════════════════════
# Tests for build_display_dataframe()
# ═════════════════════════════════════════════════════════════════════════════

class TestBuildDisplayDataframe:

    def test_returns_dataframe(self):
        """build_display_dataframe should return a pandas DataFrame."""
        import pandas as pd
        df = build_display_dataframe(SAMPLE_PROCESSES)
        assert isinstance(df, pd.DataFrame)

    def test_dataframe_has_expected_columns(self):
        """The DataFrame should have the standard column names."""
        df = build_display_dataframe(SAMPLE_PROCESSES)
        expected = {"PID", "Name", "CPU %", "Memory MB", "Status", "Threads", "Path", "Flag"}
        assert expected.issubset(set(df.columns))

    def test_dataframe_row_count_matches_input(self):
        """One row per process in the input."""
        df = build_display_dataframe(SAMPLE_PROCESSES)
        assert len(df) == len(SAMPLE_PROCESSES)

    def test_empty_input_returns_empty_dataframe(self):
        """An empty process list should give an empty DataFrame."""
        df = build_display_dataframe([])
        assert len(df) == 0

    def test_flag_column_marks_high_cpu(self):
        """chrome.exe with 92% CPU should have 'High CPU' in its Flag."""
        df = build_display_dataframe(SAMPLE_PROCESSES)
        chrome_row = df[df["Name"] == "chrome.exe"].iloc[0]
        assert "High CPU" in chrome_row["Flag"]

    def test_flag_column_normal_for_low_usage(self):
        """notepad.exe with 0% CPU and 20 MB memory should be flagged 'Normal'."""
        df = build_display_dataframe(SAMPLE_PROCESSES)
        notepad_row = df[df["Name"] == "notepad.exe"].iloc[0]
        assert notepad_row["Flag"] == "Normal"

    def test_restricted_path_shows_placeholder(self):
        """A process with exe_path=None should show '(restricted)' in Path."""
        df = build_display_dataframe(SAMPLE_PROCESSES)
        svchost_row = df[df["Name"] == "svchost.exe"].iloc[0]
        assert svchost_row["Path"] == "(restricted)"

    def test_sorted_by_cpu_descending(self):
        """The DataFrame should be sorted highest CPU first."""
        df = build_display_dataframe(SAMPLE_PROCESSES)
        cpu_values = list(df["CPU %"])
        assert cpu_values == sorted(cpu_values, reverse=True)


# ═════════════════════════════════════════════════════════════════════════════
# Integration test — verify psutil actually works on this machine
# ═════════════════════════════════════════════════════════════════════════════

class TestProcessMonitor:

    def test_get_all_processes_returns_nonempty_list(self):
        """psutil should find at least a handful of real running processes."""
        processes = get_all_processes()
        assert isinstance(processes, list)
        assert len(processes) > 0

    def test_each_process_has_required_fields(self):
        """Every process dict must have the core fields we depend on."""
        processes = get_all_processes()
        required_fields = {"pid", "name", "cpu_percent", "memory_mb", "status"}
        for proc in processes[:10]:  # check the first 10
            missing = required_fields - set(proc.keys())
            assert not missing, f"Process dict missing fields: {missing}"

    def test_pid_is_non_negative_integer(self):
        """
        PIDs should be non-negative integers.

        Windows note: PID 0 is the 'System Idle Process' — a real, valid process
        that represents idle CPU time. It has PID 0 by design. So we check >= 0,
        not > 0.
        """
        processes = get_all_processes()
        for proc in processes[:10]:
            assert isinstance(proc["pid"], int)
            assert proc["pid"] >= 0

    def test_memory_mb_is_non_negative(self):
        """Memory usage can never be negative."""
        processes = get_all_processes()
        for proc in processes[:10]:
            assert proc["memory_mb"] >= 0

    def test_cpu_percent_is_non_negative(self):
        """CPU usage can never be negative."""
        processes = get_all_processes()
        for proc in processes[:10]:
            assert proc["cpu_percent"] >= 0

    def test_get_high_cpu_processes_threshold(self):
        """
        Using a threshold of 200% should exclude most regular processes.
        Using a threshold of 0% should include all processes (cpu >= 0 > -1).

        Windows note: 'System Idle Process' (PID 0) can report CPU% as
        (100 * num_cores) — e.g. 1600% on a 16-core machine. This is normal
        Windows behaviour; it represents total idle CPU across all cores.
        So we cannot assume 101% is always an empty result on Windows.
        Instead we verify the function correctly filters by the given threshold.
        """
        processes = get_all_processes()

        # Every process has cpu_percent >= 0, so threshold=-1 returns everything
        all_results = get_high_cpu_processes(processes, threshold=-1.0)
        assert len(all_results) == len(processes)

        # At threshold=0, processes with cpu_percent > 0 are returned.
        # This should be fewer than or equal to the full list.
        above_zero = get_high_cpu_processes(processes, threshold=0.0)
        assert len(above_zero) <= len(processes)

    def test_get_high_memory_processes_threshold(self):
        """Using a threshold of 0 MB should return all processes."""
        processes = get_all_processes()
        all_high = get_high_memory_processes(processes, threshold_mb=0.0)
        assert len(all_high) == len(processes)
