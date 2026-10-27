# Vibe-lube caretaker — state snapshot

## 2026-10-27 (pilot, before merge)
- Repo: eliem08/vibe-lube, public, main at bcb6a2997a6ab95b2913662a408404340c9d240b
- Product: version 0.1.0, Python 3.10+, zero runtime dependencies.
- Code: `vibe_lube/core.py` (inspection, scoring, safe fixes),
  `vibe_lube/web.py` (web app + API + Stripe billing),
  `vibe_lube/__main__.py` (CLI), `vibe_lube/_webspec.py`.
- Tests: `tests/test_cli.py`, `test_core.py`, `test_rules.py`,
  `test_web.py`, plus `web_examples.json`. CI: lint + tests on
  Ubuntu/Windows, Python 3.10/3.12/3.13, on push to main and on PRs.
- Open issues: 0 (checked 2026-10-27 via GitHub).
- Caretaker: none before this pilot. No scheduled workflow added,
  deliberately — GitHub Actions minutes were exhausted late Oct 2026.
- Next task after this PR merges: dogfood pass (first item in
  TASK_QUEUE.md).
- Owner decision still open: whether this charter rolls out to the
  other 29 repos in the batch, and whether a scheduled caretaker run
  is wanted once the Actions budget question is settled.

## 2026-10-27 (dogfood pass, PR pending owner merge)
- Main at ffd99900 (PR #1 merged). Self-scan before: grade F, score 7,
  6 findings — 3 critical in test fixtures, 1 high + 1 medium in
  detector definitions, 1 low missing .env.example.
- Triage: no real secret was found. Test fixtures intentionally contain
  pattern examples; detector definitions in core.py (eval line 87,
  xss_sink line 119) are pattern strings, not actual calls/sinks.
- Fixes in this PR (safe only): `.env.example` with names only for the
  10 real product vars (API_KEYS, DATA_DIR, PORT, RATE_LIMIT_PER_MIN,
  ALLOW_PUBLIC, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICES,
  PUBLIC_URL, AGENT_ECONOMY_DEBUG — test-only vars like DATABASE_URL
  and STRIPE_KEY were deliberately left out); test fixtures in
  test_core.py and test_rules.py now assemble their fake keys/names at
  runtime, matching their own comment, while the temp fixtures they
  write are unchanged in effect.
- Self-scan after, excluding tests/web_examples.json: grade B, score
  83, 2 findings (core.py eval + xss_sink definitions).
- Self-scan after, full repo including web_examples.json: grade F,
  score 0, 8 findings — the same 2 detector definitions plus 6
  embedded fixture copies in web_examples.json (lines 61, 65, 73,
  182, 186, 194: a NEXT_PUBLIC_*_SERVICE_ROLE_KEY reference and a
  database_url_password inside API example payloads that embed a
  snapshot of the repo). Those 6 were deliberately NOT edited:
  web_examples.json is generated test data for the web API, and
  hand-editing its embedded snapshots could break test_web
  expectations; regenerating it cleanly belongs with detector
  hardening, not a dogfood pass.
- Full suite: 23 tests pass locally, ruff check + format pass under
  repo config. GitHub CI on the PR not yet checked.
- Next task after this PR merges: detector hardening.
