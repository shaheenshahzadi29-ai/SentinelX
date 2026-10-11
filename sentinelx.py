
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

INDICATORS = {
    b"powershell -enc": "Encoded PowerShell command",
    b"cmd.exe /c": "Windows command interpreter usage",
    b"createremotethread": "Possible process injection API",
    b"virtualalloc": "Memory allocation API often examined in malware",
    b"socket(": "Possible network communication code",
}


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
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("SentinelX analysis completed.")
    print(f"SHA-256: {report['file']['sha256']}")
    print(f"Indicators found: {report['analysis']['indicator_count']}")
    print(f"JSON report saved to: {report_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 sentinelx.py <file_path>")
    else:
        analyze_file(sys.argv[1])
