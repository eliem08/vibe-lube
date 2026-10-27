# Vibe-lube caretaker — runbook

One run = one task, one PR, one report. Do not batch tasks.

## 1. Report (5 minutes)
- Run `python agent/caretaker.py` from the repo root. Note grade, score,
  finding count, and the next queued task.
- Check open issues and the latest CI run on main. If CI on main is
  red, that becomes the task, ahead of the queue.

## 2. Pick
- Take the first unchecked `- [ ]` item in `agent/TASK_QUEUE.md`.
- If the item is vague or larger than one PR, split it in the queue
  first and do only the first slice. Say so in the report.

## 3. Build
- Implement the slice in the product code, not in docs alone,
  unless the task is explicitly a docs task.
- Add or update tests in `tests/` for the new behaviour.
- Run, in order:
  - `python -m unittest discover -s tests -t .`
  - `ruff check . && ruff format --check .`
  - `python agent/caretaker.py` (confirm the self-scan still makes sense)
  - `vibe-lube --help` if the CLI surface changed
- If any step fails, fix it or stop and report the failure. Do not
  weaken an assertion to make a test pass.

## 4. Propose
- Create a branch `agent/<short-task-name>` from main.
- Commit only the task's files. Update `agent/TASK_QUEUE.md`
  (check the item off, or replace it with its next slice) and
  `agent/STATE.md` (new state, date, test result).
- Open a pull request to main with: task, what changed, tests run
  and their result, and what was not verified. Do not merge it.
- Do not request a merge from the owner as a formality: the PR is
  the proposal, the owner's merge is the decision.

## 5. Report back to the owner
- One short message: task done, PR link, test result, next queued task.
- If blocked (quota, sign-in, a design choice only the owner can make),
  say what is blocked, what would unblock it, and stop. Do not work
  around a block with a different account, endpoint, or tool.

## Owner triggers
- "Run the vibe-lube caretaker" — one run, as above.
- "Caretaker status" — report only, no code change, no PR.
- Anything else (deploy, price change, new workflow) needs its own
  explicit approval and is not covered by this runbook.
