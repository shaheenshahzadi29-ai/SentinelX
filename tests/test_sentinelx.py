
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_DIR / "sentinelx.py"


class SentinelXTests(unittest.TestCase):

    def test_hash_and_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            sample = temp / "sample.txt"
            sample.write_bytes(b"hello sentinelx")

            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(sample)],
                cwd=temp,
                capture_output=True,
                text=True,
                check=True,
            )

            report_path = temp / "reports" / "sample.txt.json"
            self.assertTrue(report_path.exists())

            report = json.loads(report_path.read_text(encoding="utf-8"))
            expected_hash = hashlib.sha256(b"hello sentinelx").hexdigest()

            self.assertEqual(report["file"]["sha256"], expected_hash)
            self.assertEqual(report["file"]["size_bytes"], 15)
            self.assertEqual(report["analysis"]["indicator_count"], 0)
            self.assertIn("analysis completed", result.stdout.lower())

    def test_indicator_detection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            sample = temp / "sample.txt"
            sample.write_bytes(b"Example contains VirtualAlloc")

            subprocess.run(
                [sys.executable, str(SCRIPT), str(sample)],
                cwd=temp,
                capture_output=True,
                text=True,
                check=True,
            )

            report_path = temp / "reports" / "sample.txt.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertGreaterEqual(
                report["analysis"]["indicator_count"], 1
            )


    def test_database_saves_detailed_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            sample = temp / "sample.txt"
            database = temp / "sentinelx.db"
            sample.write_bytes(b"Example contains VirtualAlloc")

            env = os.environ.copy()
            env["SENTINELX_DB_PATH"] = str(database)

            subprocess.run(
                [sys.executable, str(SCRIPT), str(sample)],
                cwd=temp,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )

            self.assertTrue(database.exists())

            with sqlite3.connect(database) as connection:
                row = connection.execute("""
                    SELECT file_name, sha256, findings_count, findings_json
                    FROM scan_history
                    ORDER BY id DESC
                    LIMIT 1
                """).fetchone()

            self.assertIsNotNone(row)
            self.assertEqual(row[0], "sample.txt")
            self.assertEqual(
                row[1],
                hashlib.sha256(b"Example contains VirtualAlloc").hexdigest()
            )
            self.assertGreaterEqual(row[2], 1)

            findings = json.loads(row[3])
            self.assertTrue(
                any("virtualalloc" in item["matched_pattern"].lower()
                    for item in findings)
            )


if __name__ == "__main__":
    unittest.main()
