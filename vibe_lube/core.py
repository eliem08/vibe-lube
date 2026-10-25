"""Static inspection of AI-built ("vibe-coded") apps, with safe auto-fixes."""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import asdict, dataclass, field

__all__ = ["Finding", "Report", "inspect", "apply_safe_fixes", "SERVICE_MENU"]

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".venv",
    "venv",
    "__pycache__",
    ".turbo",
    "coverage",
    ".vercel",
}
CODE_EXTS = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".py",
    ".rb",
    ".go",
    ".php",
    ".vue",
    ".svelte",
    ".java",
    ".cs",
}
TEXT_EXTS = CODE_EXTS | {".json", ".yml", ".yaml", ".toml", ".env", ".md", ".html", ".sh", ".txt", ".ini", ".cfg"}
CLIENT_HINTS = ("src/", "app/", "pages/", "components/", "public/", "client/", "frontend/")

SECRET_PATTERNS = [
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("stripe_secret", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----")),
    ("generic_secret", re.compile(r"""(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*["'][^"'\s]{12,}["']""")),
]
ENV_REF = re.compile(
    r"process\.env\.([A-Z][A-Z0-9_]+)|import\.meta\.env\.([A-Z][A-Z0-9_]+)|os\.environ(?:\.get)?\(\s*[\"']([A-Z][A-Z0-9_]+)|os\.getenv\(\s*[\"']([A-Z][A-Z0-9_]+)|os\.environ\[\s*[\"']([A-Z][A-Z0-9_]+)"
)
PUBLIC_SECRET = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD)[A-Z0-9_]*"
)
RISKY = [
    ("eval", "high", re.compile(r"(?<![\w.])eval\s*\("), "Remove eval(); parse data with JSON.parse or a real parser."),
    (
        "sql_concat",
        "high",
        re.compile(
            r"""(?i)(?:execute|query|raw)\s*\(\s*(?:f["']|["'][^"']*(?:select|insert|update|delete)[^"']*["']\s*\+)"""
        ),
        "Use parameterised queries instead of building SQL strings.",
    ),
    (
        "cors_wildcard",
        "medium",
        re.compile(
            r"""(?i)(?:access-control-allow-origin["']?\s*[:,]\s*["']\*|cors\(\s*\)|origin\s*:\s*["']\*["']|allow_origins\s*=\s*\[\s*["']\*)"""
        ),
        "Restrict CORS to your real domains.",
    ),
    (
        "debug_mode",
        "medium",
        re.compile(r"(?i)\bdebug\s*=\s*true\b|app\.run\([^)]*debug\s*=\s*True"),
        "Turn off debug mode in production.",
    ),
]
SEVERITY_POINTS = {"critical": 25, "high": 12, "medium": 5, "low": 1}

SERVICE_MENU = {
    "secret_in_code": ("Rotate key + move to env var", 30, 49),
    "env_not_ignored": ("Git-ignore .env, scrub history", 20, 39),
    "missing_env_example": ("Generate .env.example", 5, 0),
    "public_secret": ("Move secret to server-side route", 45, 79),
    "service_role_client": ("Replace service_role with anon key + RLS", 60, 99),
    "no_lockfile": ("Add lockfile, pin deps", 10, 19),
    "unpinned_dep": ("Pin dependency versions", 10, 19),
    "eval": ("Remove eval", 20, 39),
    "sql_concat": ("Parameterise SQL queries", 30, 59),
    "cors_wildcard": ("Lock down CORS", 10, 19),
    "debug_mode": ("Disable debug in prod", 5, 9),
    "no_tests": ("Add smoke tests for critical flows", 90, 149),
    "no_readme": ("Write README + run instructions", 15, 19),
    "huge_file": ("Split oversized file", 45, 69),
    "console_logs": ("Strip debug logging", 10, 9),
    "todos": ("Triage TODOs into issues", 15, 0),
}


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    detail: str
    fix: str


@dataclass
class Report:
    root: str
    files_scanned: int
    findings: list = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    env_vars: list = field(default_factory=list)
    quote_minutes: int = 0
    quote_usd: int = 0

    def to_dict(self):
        return asdict(self)


def _mask(s: str) -> str:
    return s[:6] + "..." + s[-2:] if len(s) > 10 else "***"


MAX_SCAN_BYTES = 2_000_000


def _walk(root):
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (d.startswith(".") and d not in {".github"})]
        for f in files:
            yield os.path.join(r, f)


def _gitignored(root: str, rel: str) -> bool:
    """Does the root .gitignore ignore `rel`? Git semantics for the cases that matter for secrets.

    Last matching line wins, `!pattern` re-includes, a leading `/` anchors to the root, and a pattern
    without a slash matches the basename at any depth. Note `.env.*` does NOT ignore `.env` itself.
    """
    gi = os.path.join(root, ".gitignore")
    if not os.path.exists(gi):
        return False
    with open(gi, encoding="utf-8", errors="ignore") as fh:
        patterns = [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    rel = rel.replace("\\", "/")
    ignored = False
    for pat in patterns:
        negate = pat.startswith("!")
        pat = pat[1:] if negate else pat
        pat = pat.rstrip("/")
        if pat.startswith("/") or "/" in pat:
            hit = fnmatch.fnmatchcase(rel, pat.lstrip("/"))
        else:
            hit = fnmatch.fnmatchcase(os.path.basename(rel), pat)
        if hit:
            ignored = not negate
    return ignored


def inspect(root: str) -> Report:
    rep = Report(root=root, files_scanned=0)
    env_vars: set[str] = set()
    console_logs, todos = 0, 0
    has_tests = False

    def add(rule, sev, path, line, detail, fix):
        rep.findings.append(Finding(rule, sev, os.path.relpath(path, root).replace("\\", "/"), line, detail, fix))

    for path in _walk(root):
        rel = os.path.relpath(path, root).replace("\\", "/")
        base = os.path.basename(path)
        ext = os.path.splitext(base)[1].lower()
        if re.search(r"(^|/)(tests?|__tests__|spec)(/|$)|\.(test|spec)\.\w+$|^test_.*\.py$", rel):
            has_tests = True
        is_env_file = base.startswith(".env") and base not in {".env.example", ".env.sample", ".env.template"}
        if is_env_file and not _gitignored(root, rel):
            add(
                "env_not_ignored",
                "critical",
                path,
                0,
                f"{base} is not in .gitignore",
                "Add it to .gitignore and rotate anything inside.",
            )
        if ext not in TEXT_EXTS and not base.startswith(".env"):
            continue
        try:
            if os.path.getsize(path) > MAX_SCAN_BYTES:  # minified bundles / data dumps: not worth the memory
                continue
            with open(path, encoding="utf-8", errors="ignore") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        rep.files_scanned += 1
        is_code = ext in CODE_EXTS
        is_client = (
            is_code
            and ext in {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".mjs"}
            and rel.startswith(CLIENT_HINTS)
            and "/api/" not in rel
        )
        if is_code and len(lines) > 1000:
            add("huge_file", "low", path, 0, f"{len(lines)} lines", "Split into smaller modules.")
        for i, line in enumerate(lines, 1):
            if not base.startswith(".env") and base not in {".env.example"}:
                for name, rx in SECRET_PATTERNS:
                    m = rx.search(line)
                    if m and "example" not in line.lower() and "xxxx" not in m.group(0).lower():
                        add(
                            "secret_in_code",
                            "critical",
                            path,
                            i,
                            f"{name}: {_mask(m.group(0))}",
                            "Rotate this key now, then load it from an environment variable.",
                        )
                        break
            for m in ENV_REF.finditer(line):
                env_vars.add(next(g for g in m.groups() if g))
            pm = PUBLIC_SECRET.search(line)
            if pm:
                add(
                    "public_secret",
                    "critical",
                    path,
                    i,
                    f"{pm.group(0)} is bundled into the browser",
                    "Rename without the public prefix and use it only server-side.",
                )
            if is_client and re.search(r"service_role|SERVICE_ROLE", line):
                add(
                    "service_role_client",
                    "critical",
                    path,
                    i,
                    "Supabase service_role used in client code",
                    "Use the anon key in the browser and protect tables with RLS.",
                )
            if is_code:
                for rule, sev, rx, fix in RISKY:
                    if rx.search(line):
                        add(rule, sev, path, i, line.strip()[:100], fix)
                if "console.log(" in line:
                    console_logs += 1
                if re.search(r"\b(TODO|FIXME|HACK)\b", line):
                    todos += 1
        if base == "package.json":
            try:
                pkg = json.loads("\n".join(lines))
            except json.JSONDecodeError:
                pkg = {}
            d = os.path.dirname(path)
            if not any(
                os.path.exists(os.path.join(d, lf))
                for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock")
            ):
                add(
                    "no_lockfile",
                    "medium",
                    path,
                    0,
                    "no lockfile next to package.json",
                    "Commit your lockfile so installs are reproducible.",
                )
            for section in ("dependencies", "devDependencies"):
                for dep, ver in (pkg.get(section) or {}).items():
                    if ver in {"*", "latest", ""}:
                        add("unpinned_dep", "medium", path, 0, f"{dep}@{ver}", "Pin to a specific version range.")

    if env_vars and not any(
        os.path.exists(os.path.join(root, f)) for f in (".env.example", ".env.sample", ".env.template")
    ):
        rep.findings.append(
            Finding(
                "missing_env_example",
                "low",
                ".env.example",
                0,
                f"{len(env_vars)} env vars referenced, no .env.example",
                "Run with --fix to generate one.",
            )
        )
    if not has_tests:
        rep.findings.append(
            Finding(
                "no_tests",
                "medium",
                "-",
                0,
                "no test files found",
                "Add smoke tests for sign-up, payment and core flows.",
            )
        )
    if not any(os.path.exists(os.path.join(root, f)) for f in ("README.md", "readme.md", "README")):
        rep.findings.append(Finding("no_readme", "low", "-", 0, "no README", "Document how to run and deploy the app."))
    if console_logs > 10:
        rep.findings.append(
            Finding("console_logs", "low", "-", 0, f"{console_logs} console.log calls", "Remove or gate debug logging.")
        )
    if todos > 10:
        rep.findings.append(
            Finding("todos", "low", "-", 0, f"{todos} TODO/FIXME markers", "Turn them into tracked issues.")
        )

    rep.env_vars = sorted(env_vars)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rep.findings.sort(key=lambda f: (sev_rank[f.severity], f.file, f.line))
    penalty = sum(SEVERITY_POINTS[f.severity] for f in rep.findings)
    rep.score = max(0, 100 - penalty)
    rep.grade = (
        "A"
        if rep.score >= 90
        else "B"
        if rep.score >= 75
        else "C"
        if rep.score >= 60
        else "D"
        if rep.score >= 40
        else "F"
    )
    rules = {f.rule for f in rep.findings}
    rep.quote_minutes = sum(SERVICE_MENU[r][1] for r in rules)
    rep.quote_usd = sum(SERVICE_MENU[r][2] for r in rules)
    return rep


def apply_safe_fixes(root: str, rep: Report) -> list[str]:
    """Only non-destructive fixes: git-ignore env files, write .env.example with names (never values)."""
    done = []
    rules = {f.rule for f in rep.findings}
    if "env_not_ignored" in rules:
        gi = os.path.join(root, ".gitignore")
        existing = ""
        if os.path.exists(gi):
            with open(gi, encoding="utf-8-sig") as fh:
                existing = fh.read()
        add = [p for p in (".env", ".env.*", "!.env.example") if p not in existing.split()]
        with open(gi, "a", encoding="utf-8") as fh:
            fh.write(("\n" if existing and not existing.endswith("\n") else "") + "\n".join(add) + "\n")
        done.append(f"added {', '.join(add)} to .gitignore (rotate any keys that were committed!)")
    if "missing_env_example" in rules and rep.env_vars:
        try:  # "x": never overwrite a .env.example the user already has
            with open(os.path.join(root, ".env.example"), "x", encoding="utf-8") as fh:
                fh.write("# Generated by vibe-lube - fill in real values in .env (never commit it)\n")
                fh.write("".join(f"{v}=\n" for v in rep.env_vars))
            done.append(f"wrote .env.example with {len(rep.env_vars)} variables")
        except FileExistsError:
            done.append("left existing .env.example untouched")
    return done
