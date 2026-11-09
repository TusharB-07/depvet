<h1 align="center">depvet</h1>

<p align="center"><b>Vet every dependency before your AI agent installs it.</b><br>
An agent skill that catches typosquats, slopsquats, dangerous install scripts
and dead packages — <i>before</i> <code>npm install</code> runs, not after.</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-1b1b19?style=flat-square" alt="MIT license"></a>
  <a href="https://agentskills.io"><img src="https://img.shields.io/badge/Agent_Skills-compatible-1b1b19?style=flat-square" alt="Agent Skills compatible"></a>
  <img src="https://img.shields.io/badge/dependencies-0-1b1b19?style=flat-square" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/python-%E2%89%A53.8-1b1b19?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+">
</p>

---

## The problem

Your coding agent adds packages without reading them. That is the exact path
of every big supply-chain failure of the last decade:

- **`crossenv` (2017)** — one character away from `cross-env`. Stole npm
  credentials on install. **It is still live on npm today, still collecting
  typo traffic** (depvet catches it — see the real run below).
- **Sep 2025 npm compromise** — one phished maintainer; malware in packages
  with billions of weekly downloads; self-propagating.
- **Shai-Hulud worm (Nov 2025)** — 100+ packages (Zapier, PostHog, AsyncAPI,
  ENS…) infected via lifecycle scripts and stolen tokens.
- **Slopsquatting (OWASP-documented)** — attackers publish malicious packages
  under the *hallucinated names* that AI assistants invent. Your agent is the
  attack surface.

`npm audit` scans *after* you depend on something. Snyk and Socket watch repos
and registries continuously. **Nobody gates the moment the agent decides to
install.** depvet is that gate.

## What it does

Before any install, depvet runs a read-only check against the registry and
returns a verdict:

| Verdict | Meaning |
|---|---|
| **PASS** | No red flags — install, mention it in one line |
| **WARN** | Risk signals (single maintainer, abandoned, license gap…) — user confirms |
| **BLOCK** | Typosquat / confusable name / nonexistent name / dangerous install scripts / fresh-drop — **do not install, propose the real alternative** |

Checks performed on every candidate: confusable identity (separator/case
variants of famous names), edit-distance ≤ 2 from top packages, registry
existence (slopsquat path), lifecycle-script payloads (`curl|sh`, `base64`,
`eval`, credential paths…), package age, weekly downloads, maintainer count,
repository presence, abandonment, and license.

## Real output (not a mockup)

`python3 scripts/depvet_check.py react axios crossenv react-fast-carousel-pro`

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

That `crossenv` row is the actual 2017 credential-stealing typosquat, still
sitting on the registry — caught by the confusable-identity check, live, with
zero configuration.

## Install

Works with any agent that reads Agent Skills: **Claude Code, Codex,
Gemini CLI, Antigravity, OpenCode**, and friends.

**Claude Code** — global:

```bash
git clone https://github.com/TusharB-07/depvet.git
mkdir -p ~/.claude/skills && cp -r depvet/skills/depvet ~/.claude/skills/
```

…or per project: copy into `.claude/skills/` inside the repo.

**Codex / OpenCode**:

```bash
mkdir -p ~/.agents/skills && cp -r depvet/skills/depvet ~/.agents/skills/
```

**Gemini CLI / Antigravity**:

```bash
mkdir -p ~/.gemini/antigravity/skills && cp -r depvet/skills/depvet ~/.gemini/antigravity/skills/
```

No config, no API keys, no network setup beyond registry access the agent
already has.

## Use

Say it, or just install something — the skill triggers on dependency work:

```
> add zod and axios to this project
```

```
> depvet lodash-es is-odd event-stream
```

Or use the checker standalone (it is a normal CLI):

```bash
python3 scripts/depvet_check.py express koa fastify      # npm
python3 scripts/depvet_check.py --registry pypi requests # PyPI
python3 scripts/depvet_check.py --json react             # machine-readable
```

Exit codes: `0` all PASS · `1` WARN present · `2` BLOCK present — so you can
wire it into CI: `depvet_check.py --strict $(cat new-deps.txt) || exit 1`.

## What depvet is not

- Not a malware sandbox — it reads registry metadata, it does not execute
  package code (that is the point).
- Not a deep-tree scanner — it gates **direct adds**. Use `npm audit`,
  [Socket](https://socket.dev) or Snyk for continuous transitive scanning;
  they complement depvet, they don't replace it.
- Not a blocker of private packages — scoped internal names (`@company/*`
  on your own registry) are explicitly out of scope.

## FAQ

**Does it phone anywhere besides the package registry?**
No. Two GET endpoints per package (registry metadata + download counts), read-only, no auth, no telemetry.

**Will it slow my agent down?**
One registry round-trip per package, ~200–500 ms. Batches are checked in one pass.

**Why WARN on `axios` (144M downloads/week)?**
Because it is factually single-maintainer — the exact profile that made the Sep 2025 phishing compromise possible. WARN means *surface and confirm*, not *refuse*.

**Can the agent override a BLOCK?**
No. Only the user can, explicitly. If the user overrides two lookalike-name blocks in one session, the skill stops and re-verifies — that pattern is how typosquat disasters start.

## Roadmap

- [ ] `--lockfile package-lock.json` batch mode
- [ ] Go module proxy + crates.io adapters
- [ ] Optional provenance/attestation check (`npm provenance`)
- [ ] GitHub Action for PR-level dependency gating

PRs welcome — see [CONTRIBUTING](CONTRIBUTING.md).

## Acknowledgments

Pattern and structure inspired by the great agent skills
([unslop](https://github.com/heydamir/unslop),
[anatomy](https://github.com/wheresryan22/anatomy)). Incident research drawn
from OWASP's NPM cheat sheet, FortiGuard, Microsoft Security, Snyk, and
Socket research — full list in
[references/incidents.md](skills/depvet/references/incidents.md).

## License

[MIT](LICENSE) © 2026 TusharB-07
