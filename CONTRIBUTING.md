# Contributing to depvet

Thanks for helping gate agent installs everywhere. Ground rules:

## Adding a red flag or threshold change

1. Every check must trace to a **documented incident or attack class** — link
   it in the issue/PR. No vibes-based security.
2. State the false-positive cost: which legitimate packages get flagged?
3. BLOCKs need a strong paper trail; when in doubt, prefer WARN.
4. Add the signal to `skills/depvet/references/red-flags.md`, the decision to
   `references/verdicts.md`, and the implementation to
   `scripts/depvet_check.py` in the same PR.

## Adding a registry adapter

1. Read-only public endpoints only. No auth, no scraping.
2. Map your registry's fields onto the existing signal set (or document why a
   signal doesn't apply, as PyPI does for maintainers).
3. Include the popular-package seed list for typosquat distance checks.

## Style

- Zero dependencies, stdlib only, Python 3.8+ compatible.
- `python3 -m py_compile scripts/depvet_check.py` must pass; CI runs
  `tests/test_offline.py` and `tests/test_action.py` (both fully offline via
  fixture files) plus live registry smoke tests — keep those deterministic
  (well-known packages).
- New verdict logic needs tests: pure functions go in `tests/test_offline.py`;
  add fixture files for any new registry field the check reads.
- SKILL.md stays under ~200 lines; details go to `references/`.

## Reporting a wrong verdict

Open a bug issue with the command, the output, and why you believe the
verdict is wrong. Both false positives and false negatives are gold — they
tune the thresholds.
