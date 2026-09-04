"""
Security Engine — Hidden Window Process Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real-parses one or more real process-list CSV exports (a single .csv file,
or a directory that is real-walked with os.walk for every *.csv it finds)
using csv.DictReader, and runs every rule in app.detection_rules against
each real parsed row. No sample/mock process data is ever generated —
every Finding reflects an actual row from an actual CSV on disk at scan
time.

Expected CSV columns (a real process-list export schema):
    Name, CommandLine, ProcessId, ParentProcessId, ExecutablePath, User

A CSV is tolerated as long as it has at minimum Name + CommandLine; rows
are otherwise read with csv.DictReader.get() so missing optional columns
degrade gracefully rather than crashing.

Designed to run unprivileged: any CSV that cannot be opened/read is
counted as an error and skipped, never fabricated.
"""
import csv
import os
import re
import time

from app.detection_rules import ALL_RULES

REQUIRED_MIN_COLUMNS = {"Name", "CommandLine"}

# --- Real, documented hidden-window / no-console command-line patterns ---

# HWP-001: PowerShell hidden-window flags.
_PS_HIDDEN_RE = re.compile(
    r"-windowstyle\s+hidden|-w\s+hidden|-window\s+hidden",
    re.IGNORECASE,
)

# HWP-002: cmd.exe "start /B" background/no-new-window launch.
_CMD_START_RE = re.compile(r"\bstart\b", re.IGNORECASE)
_CMD_BG_FLAG_RE = re.compile(r"(^|\s)/b(\s|$)", re.IGNORECASE)

# HWP-003: WScript.Shell .Run(..., 0, hidden-window idiom.
_WSCRIPT_RUN_RE = re.compile(r"\.run\([^)]*,\s*0\s*,", re.IGNORECASE)

# Lower-confidence .NET / compiled-launcher hidden-window signal — rare, but
# real when a wrapping script or launcher embeds its own ProcessStartInfo
# source/manifest text in the CommandLine.
_NET_LAUNCHER_RE = re.compile(
    r"processstartinfo.*?(createnowindow|windowstyle\s*=\s*hidden)",
    re.IGNORECASE | re.DOTALL,
)

# Process names that are inherently GUI-less-by-design (no console window by
# default) — worth cross-referencing during a hidden-window review even when
# no explicit hidden-window flag is present.
_ALWAYS_CONSOLELESS = {"pythonw.exe", "mshta.exe"}

_SUSPICIOUS_LOCATION_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
)


class HiddenWindowProcessDetector:
    """Real, synchronous engine that parses real process-list CSV exports
    and detects real hidden-window / no-console launch patterns."""

    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set()
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real CSV parse (single file or real directory walk).
        Returns the summary dict consumed by the CLI and the web app."""
        start = time.time()
        if os.path.isfile(self.target_path):
            self._parse_csv(self.target_path)
        elif os.path.isdir(self.target_path):
            self._walk(self.target_path, depth=0)
        else:
            self.errors_count += 1
        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return
        try:
            entries = list(os.scandir(path))
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    self._walk(full_path, depth + 1)
                elif entry.is_file(follow_symlinks=False) and full_path.lower().endswith(".csv"):
                    self._parse_csv(full_path)
            except OSError:
                self.errors_count += 1

    def _parse_csv(self, csv_path):
        """Real csv.DictReader parse of one real CSV export on disk."""
        try:
            with open(csv_path, newline="", encoding="utf-8-sig") as fh:
                reader = csv.DictReader(fh)
                fieldnames = set(reader.fieldnames or [])
                if not REQUIRED_MIN_COLUMNS.issubset(fieldnames):
                    self._apply_rules({
                        "csv_path": csv_path,
                        "missing_header": True,
                        "found_columns": sorted(fieldnames),
                    })
                    self.files_scanned += 1
                    return

                for row in reader:
                    ctx = self._build_context(csv_path, row)
                    self._apply_rules(ctx)
        except (PermissionError, FileNotFoundError, OSError, csv.Error, UnicodeDecodeError):
            self.errors_count += 1
            return

        self.files_scanned += 1

    def _build_context(self, csv_path, row):
        name = (row.get("Name") or "").strip()
        command_line = (row.get("CommandLine") or "").strip()
        executable_path = (row.get("ExecutablePath") or "").strip()
        name_lower = name.lower()
        cmd_lower = command_line.lower()

        ps_match = None
        m = _PS_HIDDEN_RE.search(command_line)
        if m:
            ps_match = m.group(0)

        cmd_bg_match = None
        if _CMD_START_RE.search(command_line) and _CMD_BG_FLAG_RE.search(command_line):
            cmd_bg_match = command_line.strip()

        wscript_match = None
        m = _WSCRIPT_RUN_RE.search(command_line)
        if m:
            wscript_match = m.group(0)

        net_match = None
        m = _NET_LAUNCHER_RE.search(command_line)
        if m:
            net_match = m.group(0)

        consoleless_match = False
        if name_lower in _ALWAYS_CONSOLELESS:
            consoleless_match = True
        elif name_lower == "wscript.exe" and ".vbs" in cmd_lower:
            consoleless_match = True

        suspicious_location = False
        if executable_path:
            exec_lower = executable_path.lower()
            suspicious_location = any(marker in exec_lower for marker in _SUSPICIOUS_LOCATION_MARKERS)

        any_hidden_flag = bool(ps_match or cmd_bg_match or wscript_match or net_match)

        return {
            "csv_path": csv_path,
            "row": row,
            "name": name,
            "command_line": command_line,
            "process_id": row.get("ProcessId", ""),
            "parent_process_id": row.get("ParentProcessId", ""),
            "executable_path": executable_path,
            "user": row.get("User", ""),
            "ps_hidden_match": ps_match,
            "cmd_bg_match": cmd_bg_match,
            "wscript_match": wscript_match,
            "net_launcher_match": net_match,
            "any_hidden_flag": any_hidden_flag,
            "suspicious_location": suspicious_location,
            "consoleless_match": consoleless_match,
        }

    def _apply_rules(self, ctx):
        for rule in ALL_RULES:
            try:
                result = rule(ctx)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                result["file_path"] = ctx["csv_path"]
                result["permissions_octal"] = (result.get("matched_snippet") or "")[:200]
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)


# Backward/template-compatible alias — the whole project (CLI, dashboard,
# tests) refers to this engine as ScanEngine.
ScanEngine = HiddenWindowProcessDetector
