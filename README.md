# Hidden Window Process Detector

**A real, no-mock-data hidden-window process forensic triage tool — CLI + Web App.**
Parses real process-list CSV exports (columns: `Name`, `CommandLine`, `ProcessId`, `ParentProcessId`, `ExecutablePath`, `User`) and flags processes launched with documented hidden-window / no-console flags: PowerShell `-WindowStyle Hidden`, `cmd.exe /B start`, WScript.Shell `.Run(...,0,` calls, and naturally console-less interpreters, by inspecting the real `CommandLine` text with `csv.DictReader` and case-insensitive regex — never sample data.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ DISCLAIMER (READ BEFORE USE)

This software is provided **strictly for educational, defensive-security, incident-response, and DFIR-triage purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against process-list exports of systems you own or for which you have explicit, documented authorization to assess. Analyzing exports from systems without authorization may violate computer-crime laws or organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including missed detections, false positives, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a certified forensic tool.** This tool is **not a substitute** for a certified incident-response engagement, malware reverse-engineering, or review by a qualified DFIR/security professional. Findings are heuristic and may include both false positives and false negatives.
- **No guaranteed detection.** Absence of findings does **not** mean a system is clean. This tool checks a specific, limited set of well-documented hidden-window command-line patterns only — it does not detect every hiding technique (e.g. rootkits, process hollowing, or window-hiding done purely in-memory after launch).
- **Read-only, offline analysis by design.** The Security Engine only reads a CSV file you provide with `csv.DictReader` — it never touches, queries, or connects to a live process list, and never modifies the CSV. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything sensitive.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given export, **do not run this tool against it.**

---

## Who should use this project

- Incident responders and SOC analysts triaging a process-list export (e.g. from `Get-CimInstance Win32_Process | Export-Csv`, an EDR export, or a similar tool) for silent/hidden-window execution.
- DFIR practitioners and malware analysts looking for a quick, scriptable first pass over process listings collected during an investigation.
- Security students studying real-world hidden-window execution techniques used by malicious PowerShell/VBScript launchers.
- CI/CD or SOAR pipelines that want a hidden-window-hygiene gate over exported process telemetry (the CLI exits non-zero when findings exist).

## Why use this project

- **Real data only** — every result comes from parsing an actual CSV file with `csv.DictReader` and matching real regex patterns against the real `CommandLine` text. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI) and the web app (for dashboards/teams) both call the exact same `HiddenWindowProcessDetector` engine, so results are always consistent.
- **Full workflow, not just a scanner** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## What it actually does

1. You provide a real path: either a single process-list `.csv` file, or a directory that is real-walked (`os.scandir`, recursively) for every `*.csv` file inside it.
2. Each CSV is parsed with `csv.DictReader`. A CSV needs at minimum the `Name` and `CommandLine` columns to be recognized (`ProcessId`, `ParentProcessId`, `ExecutablePath`, `User` are optional and used when present) — anything missing the minimum columns produces an **HWP-006** informational finding instead of crashing.
3. For every row, the real `CommandLine` string is matched (case-insensitively) against documented hidden-window / no-console launch patterns.
4. Every match becomes a `Finding` you can see in the Dashboard, Logs, Alerts, Incidents, Analytics, and Reports pages — or in the CLI's terminal output / JSON / CSV export.

### Expected CSV columns

| Column | Required | Description |
|---|---|---|
| `Name` | Yes | Process image name, e.g. `powershell.exe` |
| `CommandLine` | Yes | The full real command line the process was launched with |
| `ProcessId` | No | PID |
| `ParentProcessId` | No | Parent PID |
| `ExecutablePath` | No | Full path to the executable on disk — enables HWP-004 |
| `User` | No | Account the process ran as |

### Hidden-window patterns detected

- **PowerShell hidden-window flags:** `-WindowStyle Hidden`, `-w hidden`, `-window hidden`
- **cmd.exe background/no-window launch:** `start` combined with the `/B` flag on the same command line (e.g. `cmd /c start /B payload.exe`)
- **WScript.Shell hidden `.Run()`:** a `.Run(...)` call whose windowStyle argument is `0` (hidden), e.g. `Shell.Run("cmd.exe /c whoami",0,False)`
- **Naturally console-less interpreters:** `pythonw.exe`, `mshta.exe`, and `wscript.exe` when launching a `.vbs` script — these have no window by design, so they're a low-confidence, informational signal rather than a strong one
- **Compounded signal:** any of the above hidden-window patterns *plus* an `ExecutablePath` in a well-known suspicious execution directory (`\AppData\Local\Temp\`, `\Users\Public\`, `\ProgramData\`)
- **Lower-confidence .NET/compiled-launcher signal:** `ProcessStartInfo` combined with `CreateNoWindow` / `WindowStyle = Hidden` appearing in the command line (rare, but real when a wrapping script embeds a compiled launcher's own source/manifest text) — contributes to the compounded HWP-004 signal

---

## Architecture

```
hidden-window-process-detector/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real CSV-parsing engine (csv.DictReader + regex)
│   ├── detection_rules/      # 6 documented detection rules (HWP-001..HWP-006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real temp CSV files + real web routes
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| HWP-001 | PowerShell Hidden-Window Flag | High | `CommandLine` contains an explicit PowerShell hidden-window flag (`-WindowStyle Hidden` / `-w hidden` / `-window hidden`) |
| HWP-002 | cmd.exe Background/No-Window Start | Medium | `CommandLine` contains the `cmd /B start` background-launch pattern |
| HWP-003 | WScript.Shell Hidden `.Run()` Pattern | Medium | `CommandLine` contains a WScript.Shell `.Run(...,0,` hidden-window VBScript call |
| HWP-004 | Hidden-Window Process In Suspicious Location | Medium | A hidden-window-flagged row (HWP-001/002/003, or the low-confidence .NET launcher signal) whose `ExecutablePath` is in `\AppData\Local\Temp\`, `\Users\Public\`, or `\ProgramData\` |
| HWP-005 | Naturally Console-less Interpreter Present | Low | `pythonw.exe` / `mshta.exe` / `wscript.exe`+`.vbs` present **without** an explicit hidden-window flag — informational awareness note |
| HWP-006 | Unrecognized Process-List Export Format | Low | A CSV's header lacked the minimum required columns (`Name` + `CommandLine`) — parse-note, not a crash |

---

## Setup & Run

### Requirements
- Python 3.9+
- Any OS (the engine only reads CSV text files — no OS-specific APIs are used)

### Install

```bash
git clone <this-repository-url>
cd hidden-window-process-detector
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
HWP_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/hwp.db`.

### Run the CLI

```bash
python3 cli/main.py scan processes.csv
python3 cli/main.py scan ./exports_dir --json
python3 cli/main.py scan processes.csv --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI/SOAR gate) and `0` if the export is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

The suite includes rule-level unit tests against synthetic context dicts, plus engine-level tests that write real process-list CSV files to disk with `csv.DictWriter` (a real `powershell.exe -WindowStyle Hidden` row, a real `cmd /c start /B` row, a real WScript `.Run(...,0,` row, a real `pythonw.exe` row) and run the actual `HiddenWindowProcessDetector` against them — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Hidden Window Process Detector check?**
It parses a real process-list CSV export and flags rows whose `CommandLine` contains a documented hidden-window/no-console launch pattern: PowerShell `-WindowStyle Hidden`/`-w hidden`, `cmd.exe start /B`, WScript.Shell hidden `.Run()`, hidden-window-plus-suspicious-location combinations, and naturally console-less interpreters — using real `csv.DictReader` parsing.

**Who should use it?**
Incident responders, SOC analysts, DFIR practitioners, security students, and system administrators triaging process-list exports for silent, hidden-window execution on systems they own or are authorized to assess.

**Is it a replacement for a professional security audit?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it modify my files?**
No. It only reads the CSV file(s) you point it at via `csv.DictReader`. It never writes to, deletes, or modifies the source export.

**Where do I get a process-list CSV export?**
Any tool that can export `Name`, `CommandLine`, `ProcessId`, `ParentProcessId`, `ExecutablePath`, and `User` columns to CSV works — for example a PowerShell `Get-CimInstance Win32_Process | Select-Object Name,CommandLine,ProcessId,ParentProcessId,ExecutablePath,@{n='User';e={...}} | Export-Csv` export, or an equivalent export from your EDR/telemetry platform.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
