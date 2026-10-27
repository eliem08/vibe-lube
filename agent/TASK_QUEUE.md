# Vibe-lube caretaker — task queue

One item at a time, top first. Each item is one line so `agent/caretaker.py` can report it in full. Check an item off only when its PR is merged. If an item turns out larger than one PR, replace it with its first slice and keep the rest below it.

## Now
- [ ] Dogfood pass: run the caretaker report on this repo, triage every finding it reports on itself, and fix only the safe ones (same rule as the product: never auto-rotate keys or refactor risky code).
- [ ] Detector hardening (ARCHITECTURE.md §6): add entropy checks and provider-specific validators for secret detection, to cut false positives and negatives, with tests for a true positive, a suppressed placeholder (example/xxxx), and a newly excluded false positive.

## Next
- [ ] Runtime checks (README roadmap): probe a deployed URL for exposed /.env, /.git/config, open Supabase tables, and missing RLS, using read-only probes with a test double for each probe.
- [ ] Fix-PR generator (README roadmap): generate a fix PR from findings, behind mandatory human approval, never pushing to main or merging itself.
- [ ] GitHub App: inspection on every PR plus one-click "book a mechanic" (human expert). Largest item: split into webhook intake, sandboxed scan, and check-run annotations before building any of it.

## Done
- [x] Pilot: caretaker charter, runbook, task queue, state snapshot, and read-only `agent/caretaker.py` with tests (PR, owner to merge).
