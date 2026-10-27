# Vibe-lube caretaker — task queue

One item at a time, top first. Each item is one line so `agent/caretaker.py` can report it in full. Check an item off only when its PR is merged. If an item turns out larger than one PR, replace it with its first slice and keep the rest below it.

## Now
- [ ] Detector hardening (ARCHITECTURE.md §6): add entropy checks and provider-specific validators for secret detection, to cut false positives and negatives, with tests for a true positive, a suppressed placeholder (example/xxxx), and a newly excluded false positive. Dogfood note: the scanner still flags its own detector definitions in core.py (eval, xss_sink) — a good first hardening target is suppressing pattern-definition lines, without weakening detection in customer code.

## Next
- [ ] Runtime checks (README roadmap): probe a deployed URL for exposed /.env, /.git/config, open Supabase tables, and missing RLS, using read-only probes with a test double for each probe.
- [ ] Fix-PR generator (README roadmap): generate a fix PR from findings, behind mandatory human approval, never pushing to main or merging itself.
- [ ] GitHub App: inspection on every PR plus one-click "book a mechanic" (human expert). Largest item: split into webhook intake, sandboxed scan, and check-run annotations before building any of it.

## Done
- [x] Pilot: caretaker charter, runbook, task queue, state snapshot, and read-only `agent/caretaker.py` with tests (PR #1, merged 2026-10-27).
- [x] Dogfood pass: self-scan went from grade F (score 7, 6 findings) to grade F (score 0, 8 findings) on the full repo including tests/web_examples.json — added .env.example (names only), aligned test fixtures with their assembled-at-runtime comment, and triaged all 8 remaining findings as known false positives: 2 detector definitions in core.py plus 6 embedded fixture copies in web_examples.json (PR, owner to merge).
