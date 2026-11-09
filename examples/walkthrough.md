# Walkthrough — depvet on a real session

Run date: 2026-11-09. Everything below is genuine output from the bundled
checker against the live npm and PyPI registries.

## Scenario

An agent (or you) is about to add `react`, `axios`, and — because a
colleague misremembered the name — `crossenv` instead of `cross-env`. A
half-remembered AI suggestion also floats in: `react-fast-carousel-pro`.

## The command

```bash
python3 scripts/depvet_check.py react axios crossenv react-fast-carousel-pro
```

## Output

```text
PACKAGE                  VERDICT  AGE     DOWNLOADS      MAINT  SCRIPTS  LICENSE
crossenv                 BLOCK    3400d   2,325/wk       1      no       NONE
    [BLOCK] CONFUSABLE IDENTITY: 'crossenv' differs from popular package 'cross-env'
            only by separators/case (the crossenv-vs-cross-env typosquat pattern).
            Did you mean 'cross-env'?
react-fast-carousel-pro  BLOCK    ?       -              -      no       NONE
axios                    WARN     4454d   144,374,997/wk 1      yes      MIT
    [WARN]  single maintainer (bus factor / account-takeover blast radius)
react                    PASS     5492d   252,579,442/wk 2      no       MIT

BLOCKED: crossenv, react-fast-carousel-pro - do NOT install. Ask the user how to proceed.
WARNINGS: axios - surface to the user before installing.
```

Exit code: `2` (BLOCK present).

## How to read it

| Row | Verdict | Why |
|---|---|---|
| `crossenv` | **BLOCK** | Canonical name identical to `cross-env` — the exact 2017 credential-stealing typosquat, still live and still pulling ~2k downloads/week. The checker says: install `cross-env` instead. |
| `react-fast-carousel-pro` | **BLOCK** | Not on npm. If an AI invented this name, publishing or guessing substitutes is how slopsquatting works. Ask the user. |
| `axios` | WARN | True fact: single maintainer. WARN = confirm with the user, not refuse. |
| `react` | PASS | Massive adoption, 2 maintainers, MIT. Install and move on. |

## PyPI behaves the same

```bash
python3 scripts/depvet_check.py --registry pypi requests reqests totally-fake-ai-package
```

```text
PACKAGE                  VERDICT  AGE  DOWNLOADS  MAINT  SCRIPTS  LICENSE
reqests                  BLOCK    ?    -          -      no       NONE
totally-fake-ai-package  BLOCK    ?    -          -      no       NONE
requests                 PASS     5747d  -        -      no       Apache-2.0
```

`reqests` (missing an 'u') gets the typosquat BLOCK; the invented name gets
the slopsquat BLOCK; `requests` sails through.

## What the agent does with this

Per the skill protocol, the agent reports one table plus ≤ 3 sentences,
installs nothing blocked, and waits for the user on anything warned.
