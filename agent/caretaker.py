"""Caretaker report for vibe-lube. Read-only by default.

Run from the repo root (or anywhere, with --root):

    python agent/caretaker.py
    python agent/caretaker.py --json

It runs vibe-lube's own inspector on the repo (dogfooding), prints the
health grade, findings grouped by severity and rule, and the first open
item from agent/TASK_QUEUE.md. It never fixes, merges, deploys, or
transmits anything. Safe fixes stay a separate, human-approved step.
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def read_version(root: Path) -> str:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return "unknown"
    text = pyproject.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else "unknown"


def next_task(queue_path: Path) -> str:
    if not queue_path.exists():
        return "No agent/TASK_QUEUE.md found."
    for line in queue_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped.startswith("- [ ]"):
            return stripped[5:].strip()
    return "Task queue is empty - owner to add the next item."


def summarize(report) -> dict:
    by_severity = Counter(f.severity for f in report.findings)
    by_rule = Counter(f.rule for f in report.findings)
    return {
        "files_scanned": report.files_scanned,
        "score": report.score,
        "grade": report.grade,
        "finding_count": len(report.findings),
        "by_severity": dict(by_severity),
        "by_rule": dict(by_rule),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only caretaker report for vibe-lube.")
    parser.add_argument("--root", type=Path, default=repo_root(), help="Repo root to inspect.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    args = parser.parse_args(argv)

    root = args.root
    # Import the inspector from the caretaker's own repo, not from the
    # directory being inspected: otherwise inspecting an empty or
    # unrelated directory would shadow vibe_lube with nothing.
    sys.path.insert(0, str(repo_root()))
    try:
        from vibe_lube.core import inspect
    except ImportError as exc:  # pragma: no cover - defensive, tested via real import
        print(f"Cannot import vibe_lube.core from {repo_root()}: {exc}", file=sys.stderr)
        return 2

    report = inspect(str(root))
    summary = summarize(report)
    task = next_task(root / "agent" / "TASK_QUEUE.md")
    payload = {
        "repo": "eliem08/vibe-lube",
        "version": read_version(root),
        "summary": summary,
        "next_task": task,
        "top_findings": [
            {
                "rule": f.rule,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "detail": f.detail,
            }
            for f in report.findings[:10]
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"vibe-lube caretaker - version {payload['version']}")
    print(f"Scanned {summary['files_scanned']} files - score {summary['score']} (grade {summary['grade']})")
    print(f"Findings: {summary['finding_count']} {summary['by_severity']}")
    if summary["by_rule"]:
        print(f"By rule: {summary['by_rule']}")
    for finding in payload["top_findings"]:
        print(f"  {finding['severity']}: {finding['rule']} {finding['file']}:{finding['line']} - {finding['detail']}")
    print(f"Next task: {task}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
