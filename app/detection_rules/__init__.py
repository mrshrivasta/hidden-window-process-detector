"""
Detection Rules — Hidden Window Process Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL context dict built from one row of a real,
parsed process-list CSV export (or, for HWP-006, from the CSV's own
header) and returns a Finding dict if the condition is met. Rules are
pure functions — no I/O, no side effects — so they can be unit tested in
isolation with synthetic context dicts, and are exercised end-to-end by
the Security Engine against genuine CSV files written to disk.

Context dict shape (built by app.security_engine for every parsed row):
    {
        "csv_path": str,                # real path to the CSV that was parsed
        "row": dict,                     # raw csv.DictReader row
        "name": str,                     # row["Name"], lowered for matching
        "command_line": str,             # row["CommandLine"] (raw, original case)
        "process_id": str,
        "parent_process_id": str,
        "executable_path": str,          # row.get("ExecutablePath", "")
        "user": str,
        "ps_hidden_match": str | None,    # matched snippet for HWP-001
        "cmd_bg_match": str | None,       # matched snippet for HWP-002
        "wscript_match": str | None,      # matched snippet for HWP-003
        "net_launcher_match": str | None, # low-confidence .NET launcher snippet
        "any_hidden_flag": bool,          # True if 001/002/003/net_launcher matched
        "suspicious_location": bool,      # True if executable_path is in a watch dir
        "consoleless_match": bool,        # True if name is a naturally console-less interpreter
    }

For HWP-006 the context dict instead carries:
    {"csv_path": str, "missing_header": True, "found_columns": list}
"""

# Severity scale used consistently across the whole project
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

def rule_powershell_hidden_window_flag(ctx):
    """HWP-001: The row's real CommandLine contains an explicit PowerShell
    hidden-window flag (-WindowStyle Hidden / -w hidden / -window hidden).
    This is the classic, extremely common silent-execution indicator seen in
    real malicious PowerShell launchers — high confidence, high severity."""
    if ctx.get("missing_header"):
        return None
    match = ctx.get("ps_hidden_match")
    name = (ctx.get("name") or "").lower()
    if match and "powershell" in name:
        return {
            "rule_id": "HWP-001",
            "rule_name": "PowerShell Hidden-Window Flag",
            "severity": SEVERITY_HIGH,
            "description": (
                f"Process '{ctx.get('name')}' (PID {ctx.get('process_id')}) was launched with an "
                f"explicit PowerShell hidden-window flag ('{match}') found in its real CommandLine. "
                f"This is a classic indicator of silent, no-console script execution."
            ),
            "matched_snippet": match,
        }
    return None


def rule_cmd_background_start(ctx):
    """HWP-002: The row's real CommandLine contains the cmd.exe background
    launch pattern ('start' combined with the '/B' no-new-window flag on the
    same line) — commonly used to launch a process without a visible console
    window from a batch script or another process."""
    if ctx.get("missing_header"):
        return None
    match = ctx.get("cmd_bg_match")
    if match:
        return {
            "rule_id": "HWP-002",
            "rule_name": "cmd.exe Background/No-Window Start",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Process '{ctx.get('name')}' (PID {ctx.get('process_id')}) was launched via the "
                f"cmd.exe 'start /B' background-launch pattern found in its real CommandLine "
                f"('{match}'), suppressing a visible console window."
            ),
            "matched_snippet": match,
        }
    return None


def rule_wscript_hidden_run_pattern(ctx):
    """HWP-003: The row's real CommandLine contains a WScript.Shell .Run(...)
    call whose windowStyle argument is 0 (hidden) — the standard VBScript
    idiom for launching a process without any visible window."""
    if ctx.get("missing_header"):
        return None
    match = ctx.get("wscript_match")
    if match:
        return {
            "rule_id": "HWP-003",
            "rule_name": "WScript.Shell Hidden .Run() Pattern",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Process '{ctx.get('name')}' (PID {ctx.get('process_id')}) has a WScript.Shell "
                f".Run(...) call with windowStyle 0 (hidden) embedded in its real CommandLine "
                f"('{match}') — the standard VBScript hidden-window execution idiom."
            ),
            "matched_snippet": match,
        }
    return None


def rule_hidden_and_suspicious_location(ctx):
    """HWP-004: A row already flagged by HWP-001/002/003 (or carrying the
    lower-confidence .NET CreateNoWindow launcher signal) whose real
    ExecutablePath sits in a well-known suspicious execution directory
    (AppData\\Local\\Temp, Users\\Public, ProgramData) — a compounded
    hidden-window + suspicious-location signal. Requires ExecutablePath;
    degrades gracefully (returns None) when that column is absent."""
    if ctx.get("missing_header"):
        return None
    if not ctx.get("executable_path"):
        return None
    if ctx.get("any_hidden_flag") and ctx.get("suspicious_location"):
        return {
            "rule_id": "HWP-004",
            "rule_name": "Hidden-Window Process In Suspicious Location",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Process '{ctx.get('name')}' (PID {ctx.get('process_id')}) both exhibits a "
                f"hidden-window launch pattern AND runs from a suspicious execution directory "
                f"('{ctx.get('executable_path')}') — a compounded, higher-confidence signal."
            ),
            "matched_snippet": ctx.get("executable_path"),
        }
    return None


def rule_naturally_consoleless_interpreter(ctx):
    """HWP-005: A naturally console-less interpreter (pythonw.exe, mshta.exe,
    or wscript.exe launching a .vbs script) is present WITHOUT any explicit
    hidden-window flag. These process classes inherently run without a
    visible window by design, so this is a low-confidence, informational
    note rather than a strong indicator — still worth analyst awareness
    during a hidden-window-focused review."""
    if ctx.get("missing_header"):
        return None
    if ctx.get("consoleless_match") and not ctx.get("any_hidden_flag"):
        return {
            "rule_id": "HWP-005",
            "rule_name": "Naturally Console-less Interpreter Present",
            "severity": SEVERITY_LOW,
            "description": (
                f"Process '{ctx.get('name')}' (PID {ctx.get('process_id')}) is a naturally "
                f"console-less interpreter (no visible window by design) with no explicit "
                f"hidden-window flag in its CommandLine. Informational — worth noting during a "
                f"hidden-window review, not necessarily malicious on its own."
            ),
            "matched_snippet": ctx.get("name"),
        }
    return None


def rule_unrecognized_export_format(ctx):
    """HWP-006: A CSV's header lacked the minimum required real columns
    (Name + CommandLine) — an unrecognized process-list export format.
    This is a parse-note, not a crash: the file is skipped for row-level
    detection but the gap is reported so an analyst knows why."""
    if not ctx.get("missing_header"):
        return None
    return {
        "rule_id": "HWP-006",
        "rule_name": "Unrecognized Process-List Export Format",
        "severity": SEVERITY_LOW,
        "description": (
            f"CSV '{ctx.get('csv_path')}' does not contain the minimum required columns "
            f"(Name, CommandLine). Found columns: {ctx.get('found_columns')}. This file was "
            f"parsed but skipped for row-level hidden-window detection."
        ),
        "matched_snippet": ",".join(ctx.get("found_columns") or []),
    }


ALL_RULES = [
    rule_powershell_hidden_window_flag,
    rule_cmd_background_start,
    rule_wscript_hidden_run_pattern,
    rule_hidden_and_suspicious_location,
    rule_naturally_consoleless_interpreter,
    rule_unrecognized_export_format,
]
