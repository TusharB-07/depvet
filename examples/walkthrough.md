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

---

# Walkthrough v1.1 — whole-manifest scans

Run date: 2026-11-11. All output below is genuine, from the live registries.

## Scenario 2: the lockfile

A fresh clone with a `package-lock.json` you have never read. One command
vets every pinned dependency — direct *and* nested transitive:

```bash
python3 scripts/depvet_check.py --lockfile demo-package-lock.json
```

The demo lockfile contains `express`, `lodash`, `event-stream`, and — planted
as a nested dependency, where nobody looks — `crossenv`:

```text
PACKAGE      VERDICT  AGE    DOWNLOADS       MAINT  SCRIPTS  LICENSE
crossenv     BLOCK    3401d  2,545/wk        1      no       NONE
    [BLOCK] CONFUSABLE IDENTITY: 'crossenv' differs from popular package 'cross-env'
            only by separators/case (the crossenv-vs-cross-env typosquat pattern).
            Did you mean 'cross-env'?
event-stream WARN     5559d  8,030,026/wk    1      yes      MIT
lodash       WARN     5314d  202,301,867/wk  1      yes      MIT
express      PASS     5794d  195,493,804/wk  5      yes      MIT

scanned 4 packages (4 deps from demo-package-lock.json)
BLOCKED: crossenv - do NOT install. Ask the user how to proceed.
```

Exit code: `2`. This is the event-stream/eslint-scope lesson applied: the
squat never appears in `package.json` — it appears two levels down, and this
mode is the one that sees it.

## Scenario 3: deprecation, live

`request` — 14M downloads/week, deprecated by its own maintainers in 2020,
still in millions of lockfiles:

```bash
python3 scripts/depvet_check.py request
```

```text
PACKAGE  VERDICT  AGE    DOWNLOADS      MAINT  SCRIPTS  LICENSE
request  WARN     5771d  13,964,396/wk  4      yes      Apache-2.0
    [WARN]  deprecated on npm: request has been deprecated,
            see https://github.com/request/request/issues/3142
    [WARN]  latest version published 6+ year(s) ago (possibly abandoned)
```

## Scenario 4: requirements.txt on PyPI

```bash
python3 scripts/depvet_check.py --requirements demo-requirements.txt
```

with

```text
# demo requirements.txt
requests==2.31.0
flask>=3.0
reqests
```

```text
PACKAGE  VERDICT  AGE    DOWNLOADS  MAINT  SCRIPTS  LICENSE
reqests  BLOCK    ?      -          -      no       NONE
flask    PASS     6052d  -          -      no       BSD-3-Clause
requests PASS     5748d  -          -      no       Apache-2.0

scanned 3 packages (3 deps from demo-requirements.txt)
BLOCKED: reqests - do NOT install. Ask the user how to proceed.
```

Comments, version pins and extras are stripped before scanning; the
one-character typo of `requests` is caught.

## Scenario 5: allowlisting a reviewed warning

Your team has reviewed `axios` and accepts the single-maintainer risk:

```json
// .depvetrc.json
{ "allow": { "axios": "single maintainer accepted, reviewed 2026-11" } }
```

```bash
python3 scripts/depvet_check.py axios
```

The WARN becomes PASS, with the reason kept in the notes:

```text
verdict: PASS
notes: [..., 'WARN suppressed by allowlist (single maintainer accepted, reviewed 2026-11)']
```

BLOCK verdicts ignore the allowlist — trust annotations cannot override
evidence.
