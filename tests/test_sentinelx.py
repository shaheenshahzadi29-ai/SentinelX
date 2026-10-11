
import hashlib
import json
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


if __name__ == "__main__":
    unittest.main()
