import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.caretaker import next_task, summarize
from vibe_lube.core import Finding, Report

ROOT = Path(__file__).resolve().parent.parent


class TestNextTask(unittest.TestCase):
    def test_first_unchecked_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = Path(tmp) / "TASK_QUEUE.md"
            queue.write_text("- [x] Done\n- [ ] Do this next\n- [ ] Later\n", encoding="utf-8")
            self.assertEqual(next_task(queue), "Do this next")

    def test_empty_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = Path(tmp) / "TASK_QUEUE.md"
            queue.write_text("- [x] All done\n", encoding="utf-8")
            self.assertIn("empty", next_task(queue))


class TestSummarize(unittest.TestCase):
    def test_counts_by_severity_and_rule(self):
        report = Report(root=".", files_scanned=3)
        report.findings = [
            Finding("secret_key", "critical", "a.py", 1, "masked", "rotate"),
            Finding("secret_key", "critical", "b.py", 2, "masked", "rotate"),
            Finding("todos", "low", "c.py", 3, "todo", "triage"),
        ]
        summary = summarize(report)
        self.assertEqual(summary["finding_count"], 3)
        self.assertEqual(summary["by_severity"], {"critical": 2, "low": 1})
        self.assertEqual(summary["by_rule"]["secret_key"], 2)


class TestCaretakerScript(unittest.TestCase):
    def test_json_report_on_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text('version = "0.1.0"\n', encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "agent" / "caretaker.py"),
                    "--root",
                    tmp,
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=ROOT,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["summary"]["grade"], "A")
            # An empty dir legitimately reports no_tests + no_readme.
            self.assertEqual(payload["summary"]["finding_count"], 2)
            self.assertEqual(set(payload["summary"]["by_rule"]), {"no_tests", "no_readme"})


if __name__ == "__main__":
    unittest.main()
