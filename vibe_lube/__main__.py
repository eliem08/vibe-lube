import argparse
import json
import sys

from .core import SERVICE_MENU, apply_safe_fixes, inspect

LABEL = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW "}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vibe-lube", description="Inspect and tune up AI-built apps.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("inspect")
    i.add_argument("path")
    i.add_argument("--fix", action="store_true", help="apply safe, non-destructive fixes")
    i.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rep = inspect(a.path)
    if a.json:
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        print(f"vibe-lube inspection: {a.path}  ({rep.files_scanned} files)")
        print(f"Health {rep.score}/100 - grade {rep.grade}\n")
        for f in rep.findings:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            print(f"  [{LABEL[f.severity]}] {f.rule:<20} {loc}")
            print(f"         {f.detail}")
            print(f"         fix: {f.fix}")
        if rep.findings:
            print("\nService menu:")
            for rule in sorted({f.rule for f in rep.findings}):
                name, mins, usd = SERVICE_MENU[rule]
                print(f"  {name:<44} {mins:>4} min  {'free' if not usd else f'${usd}'}")
            print(f"  {'Total':<44} {rep.quote_minutes:>4} min  ${rep.quote_usd}")
    if a.fix:
        for line in apply_safe_fixes(a.path, rep):
            print(f"fixed: {line}")
    return 0 if rep.grade in "ABC" else 1


if __name__ == "__main__":
    sys.exit(main())
