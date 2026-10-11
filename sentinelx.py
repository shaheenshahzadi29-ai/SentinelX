import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("SENTINELX_DB_PATH", str(BASE_DIR / "sentinelx.db")))

INDICATORS = {
    b"powershell -enc": "Encoded PowerShell command",
    b"cmd.exe /c": "Windows command interpreter usage",
    b"createremotethread": "Possible process injection API",
    b"virtualalloc": "Memory allocation API often examined in malware",
    b"socket(": "Possible network communication code",
}


def save_scan_to_database(report):
    """Save scan metadata and results to the local SQLite database."""
    file_info = report["file"]
    analysis = report["analysis"]

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                findings_count INTEGER NOT NULL,
                assessment TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                findings_json TEXT NOT NULL DEFAULT '[]'
            )
        """)

        connection.execute("""
            INSERT INTO scan_history (
                file_name, sha256, file_size,
                findings_count, assessment, scanned_at, findings_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            file_info["name"],
            file_info["sha256"],
            file_info["size_bytes"],
            analysis["indicator_count"],
            analysis["assessment"],
            report["analysis_time_utc"],
            json.dumps(analysis["findings"]),
        ))


def analyze_file(filename):
    path = Path(filename)

    if not path.is_file():
        print("Error: File not found.")
        return

    data = path.read_bytes()
    findings = []

    for pattern, description in INDICATORS.items():
        if pattern in data.lower():
            findings.append({
                "indicator": description,
                "matched_pattern": pattern.decode("ascii")
            })

    report = {
        "tool": "SentinelX",
        "report_version": "1.0",
        "analysis_time_utc": datetime.now(timezone.utc).isoformat(),
        "file": {
            "name": path.name,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()
        },
        "analysis": {
            "type": "basic_static_indicator_scan",
            "indicator_count": len(findings),
            "findings": findings,
            "assessment": (
                "Indicators found; further investigation recommended"
                if findings
                else "No configured indicators found"
            ),
            "limitations": (
                "String matches alone do not establish that a file is malicious."
            )
        }
    }

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / f"{path.name}.json"
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    try:
        save_scan_to_database(report)
    except sqlite3.Error as error:
        print(f"Warning: JSON report saved, but database save failed: {error}")
        print(f"JSON report saved to: {report_path}")
        return

    print("SentinelX analysis completed.")
    print(f"SHA-256: {report['file']['sha256']}")
    print(f"Indicators found: {report['analysis']['indicator_count']}")
    print(f"JSON report saved to: {report_path}")
    print("Scan history saved to the SQLite database.")



def show_details(scan_id):
    """Display the details of one saved scan."""
    if not DATABASE_PATH.exists():
        print("No scan history database found yet.")
        return

    with sqlite3.connect(DATABASE_PATH) as connection:
        row = connection.execute("""
            SELECT id, file_name, sha256, file_size,
                   findings_count, assessment, scanned_at, findings_json
            FROM scan_history
            WHERE id = ?
        """, (scan_id,)).fetchone()

    if row is None:
        print(f"No scan found with ID {scan_id}.")
        return

    scan_id, name, sha256, size, count, assessment, scanned_at, findings_json = row

    print(f"Scan ID: {scan_id}")
    print(f"File: {name}")
    print(f"SHA-256: {sha256}")
    print(f"File size: {size} bytes")
    print(f"Findings: {count}")
    print(f"Assessment: {assessment}")
    print(f"Scanned at: {scanned_at}")
    print("Detailed findings:")

    if findings_json:
        findings = json.loads(findings_json)
        if findings:
            for finding in findings:
                print(f"- {finding['indicator']}")
                print(f"  Matched pattern: {finding['matched_pattern']}")
        else:
            print("- No configured indicators found.")
    else:
        print("- Detailed findings are unavailable for this older scan.")

def show_history():
    """Display the most recent scan records."""
    if not DATABASE_PATH.exists():
        print("No scan history database found yet.")
        return

    with sqlite3.connect(DATABASE_PATH) as connection:
        rows = connection.execute("""
            SELECT id, file_name, findings_count, assessment, scanned_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT 20
        """).fetchall()

    if not rows:
        print("No scans recorded yet.")
        return

    print("\\nSentinelX Scan History")
    print("=" * 80)
    for scan_id, name, count, assessment, scanned_at in rows:
        print(f"ID: {scan_id} | File: {name} | Findings: {count}")
        print(f"Assessment: {assessment}")
        print(f"Scanned at: {scanned_at}")
        print("-" * 80)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--history":
        show_history()
    elif len(sys.argv) == 3 and sys.argv[1] == "--details":
        try:
            show_details(int(sys.argv[2]))
        except ValueError:
            print("Error: Scan ID must be a number.")
    elif len(sys.argv) == 2:
        analyze_file(sys.argv[1])
    else:
        print("Usage: python3 sentinelx.py <file_path>")
        print("       python3 sentinelx.py --history")
        print("       python3 sentinelx.py --details <scan_id>")
