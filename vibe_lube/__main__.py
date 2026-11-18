import argparse
import csv
import json
import os
import sys

from .core import SERVICE_MENU, apply_safe_fixes, inspect, load_baseline, write_baseline

LABEL = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW "}


def build_parser():
    ap = argparse.ArgumentParser(prog="vibe-lube", description="Inspect and tune up AI-built apps.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("inspect")
    i.add_argument("path")
    i.add_argument("--fix", action="store_true", help="apply safe, non-destructive fixes")
    i.add_argument("--json", action="store_true")
    i.add_argument("--baseline", help="report only findings not in this baseline file")
    i.add_argument("--write-baseline", metavar="FILE", help="record today's findings as accepted")
    i.add_argument(
        "--min-confidence",
        choices=("low", "medium", "high"),
        default="low",
        help="hide findings below this confidence (low ones never cost points)",
    )
    return ap


def _run(argv=None):
    ap = build_parser()
    a = ap.parse_args(argv)
    rep = inspect(a.path, load_baseline(a.baseline) if a.baseline else None)
    floor = {"low": 0, "medium": 1, "high": 2}
    rep.findings = [f for f in rep.findings if floor[f.confidence] >= floor[a.min_confidence]]
    if a.write_baseline:
        n = write_baseline(a.write_baseline, rep)
        print(
            f"baseline: {n} finding(s) recorded in {a.write_baseline}; later scans with --baseline show only new ones"
        )
        return 0
    if a.json:
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        print(f"vibe-lube inspection: {a.path}  ({rep.files_scanned} files)")
        print(f"Health {rep.score}/100 - grade {rep.grade}\n")
        low_header = False
        for f in rep.findings:
            if f.confidence == "low" and not low_header:
                print("\n  Worth a look (low confidence, not scored or quoted):")
                low_header = True
            loc = f"{f.file}:{f.line}" if f.line else f.file
            conf = "" if f.confidence == "high" else f"  ({f.confidence} confidence)"
            print(f"  [{LABEL[f.severity]}] {f.rule:<20} {loc}{conf}")
            print(f"         {f.detail}")
            print(f"         fix: {f.fix}")
        if rep.suppressed:
            print(f"\n  {rep.suppressed} finding(s) hidden by ignore comments, .vibe-lube-ignore or the baseline")
        if any(f.confidence != "low" for f in rep.findings):
            print("\nService menu:")
            for rule in sorted({f.rule for f in rep.findings if f.confidence != "low"}):
                name, mins, usd = SERVICE_MENU[rule]
                print(f"  {name:<44} {mins:>4} min  {'free' if not usd else f'${usd}'}")
            print(f"  {'Total':<44} {rep.quote_minutes:>4} min  ${rep.quote_usd}")
    if a.fix:
        for line in apply_safe_fixes(a.path, rep):
            print(f"fixed: {line}")
    return 0 if rep.grade in "ABC" else 1


def main(argv=None):
    """Run the CLI; a bad input file or argument exits 2 with a one-line error instead of a traceback.

    Set AGENT_ECONOMY_DEBUG=1 to see the full traceback.
    """
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    try:
        return _run(argv)
    except (OSError, ValueError, KeyError, csv.Error) as e:
        if os.environ.get("AGENT_ECONOMY_DEBUG"):
            raise
        msg = e.args[0] if isinstance(e, KeyError) and e.args else e
        print(f"error: {msg}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
