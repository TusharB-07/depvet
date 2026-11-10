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
  ENS…) infected via lifecycle scripts and stolen tokens; exfiltrated through
  `webhook.site` and GitHub Actions; Shai-Hulud 2.0 shipped staged
  `setup_bun.js` droppers.
- **`@acitons/artifact` (Nov 2025)** — typosquatted the *scope* of GitHub's
  own Actions package, collected CI tokens from ~47k installs through a
  postinstall payload with a time bomb. Nobody reads the org prefix.
- **WEL1DROPPER (Aug 2026)** — 1,000+ npm packages under AI-slop typo names
  delivering a remote-access trojan: slopsquatting went industrial.
- **Slopsquatting (OWASP-documented)** — attackers publish malicious packages
  under the *hallucinated names* that AI assistants invent. Your agent is the
  attack surface.

Postinstall-script malware grew another **61% in H1 2026** alone. `npm audit`
scans *after* you depend on something — and the community consensus is that
it is broken-by-design anyway (Dan Abramov's writeup; Reddit: "npm audit
passes clean on packages that are actively compromised — these tools check a
database of known issues"). Snyk and Socket watch repos and registries
continuously. **Nobody gates the moment the agent decides to install.**
depvet is that gate.

## What it does

Before any install, depvet runs a read-only check against the registry and
returns a verdict:

| Verdict | Meaning |
|---|---|
| **PASS** | No red flags — install, mention it in one line |
| **WARN** | Risk signals (single maintainer, abandoned, license gap…) — user confirms |
| **BLOCK** | Typosquat / confusable name / nonexistent name / dangerous install scripts / fresh-drop — **do not install, propose the real alternative** |

Checks performed on every candidate: confusable identity (separator/case
variants of famous names), edit-distance ≤ 2 from top packages, **scoped
near-misses of well-known scopes** (`@acitons` vs `@actions`), registry
existence (slopsquat path), lifecycle-script payloads (`curl|sh`, `base64`,
`eval`, credential paths, webhook exfil endpoints, CI-token harvesting,
Shai-Hulud bun droppers…), package age, weekly downloads, maintainer count,
repository presence, abandonment, npm deprecation notices, PyPI yanked
releases, provenance attestations, and license.

It also scans **whole manifests** — `package-lock.json` (v1/v2/v3),
`yarn.lock` (v1 + Berry, incl. `npm:` aliases), `pnpm-lock.yaml` (v6/v9,
peer-suffixed snapshots) and `requirements.txt` — because event-stream and
eslint-scope both arrived through the dependency tree, not through a direct
add. `--production` skips dev-only dependencies so you can vet just the
deploy surface.

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

## Scan a whole lockfile or requirements file

Most compromises arrive as **transitive** dependencies. One command vets
every package in the locked tree — npm (`package-lock.json` v1/v2/v3),
yarn (`yarn.lock` v1 + Berry), pnpm (`pnpm-lock.yaml` v6/v9) — or a
requirements file:

`python3 scripts/depvet_check.py --lockfile package-lock.json`
`python3 scripts/depvet_check.py --lockfile yarn.lock --production`
`python3 scripts/depvet_check.py --lockfile pnpm-lock.yaml --production`

Real run — a demo lockfile containing `express`, `lodash`, the deprecated
`event-stream`, and the `crossenv` typosquat hiding as a nested dep:

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

`--requirements requirements.txt` does the same for PyPI, with the same
verdicts (`reqests` typosquat inside a requirements file gets BLOCKed).

Deprecated packages get called out by name — the real output for `request`
(14M downloads/week, still installed everywhere):

```text
request  WARN     5771d  13,964,396/wk  4      yes      Apache-2.0
    [WARN]  deprecated on npm: request has been deprecated,
            see https://github.com/request/request/issues/3142
    [WARN]  latest version published 6+ year(s) ago (possibly abandoned)
```

## How it compares

Grounded in what developers actually report about these tools:

| Tool | Gates the install? | Novel malware? | Noise profile | Cost |
|---|---|---|---|---|
| **depvet** | **yes — the moment of install / PR** | yes (name + behavior signals, no advisory DB needed) | BLOCK needs strong evidence; WARN is explainable; allowlist for reviewed packages | free, zero-dep |
| `npm audit` | no — audits what you already installed | no (advisory DB only) | 99%+ false-positive rate documented (dev-dep noise, duplicate paths) — "broken by design" (Dan Abramov) | free |
| Snyk | no | advisory DB + own research | commercial SCA; needs account/agent | paid tiers |
| Socket | no — continuous monitoring | yes (behavioral) | low | commercial; free tier for OSS |
| Phylum | — | was behavioral | — | **acquired by Veracode (Jan 2025), folded into a commercial SCA suite** |

depvet is not trying to replace continuous monitors — see [What depvet is
not](#what-depvet-is-not). It closes the specific gap everyone else leaves
open: **the gate at the moment a package is chosen**, which is exactly where
agents operate.

## Gate your CI

depvet ships as a reusable GitHub Action. Add this to the repo you want
gated — the job goes red if a BLOCK verdict appears (with `strict: true`,
on any WARN too):

```yaml
name: depvet
on:
  pull_request:
    paths: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'requirements*.txt']
jobs:
  vet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: TusharB-07/depvet@v1
        with:
          lockfile: package-lock.json
          production: true
          strict: true
```

## Allowlist reviewed warnings

Teams keep shipping `axios` (single maintainer) or `request` (deprecated but
still needed). Record the review once and stop re-litigating it — create
`.depvetrc.json` next to where you run depvet:

```json
{
  "allow": {
    "axios": "single maintainer accepted, reviewed 2026-11"
  }
}
```

Allowlisted packages have WARN downgraded to PASS **with the reason recorded
in the output**. BLOCK is never downgraded by an allowlist — trust
annotations do not override typosquat evidence.

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
python3 scripts/depvet_check.py express koa fastify          # npm
python3 scripts/depvet_check.py --registry pypi requests     # PyPI
python3 scripts/depvet_check.py --lockfile package-lock.json # whole tree (npm)
python3 scripts/depvet_check.py --lockfile yarn.lock         # whole tree (yarn v1/Berry)
python3 scripts/depvet_check.py --lockfile pnpm-lock.yaml    # whole tree (pnpm v6/v9)
python3 scripts/depvet_check.py --production --lockfile package-lock.json  # skip dev-only deps
python3 scripts/depvet_check.py --requirements requirements.txt
python3 scripts/depvet_check.py --json react                 # machine-readable
python3 scripts/depvet_check.py --no-cache react             # bypass the 24h verdict cache
python3 scripts/depvet_check.py --workers 1 express koa      # sequential, paced lookups
```

Exit codes: `0` no red flags · `1` WARN present **with `--strict`** ·
`2` BLOCK present (always fails) — so CI gates work out of the box.
JSON output includes one object per package with `verdict`, `flags`,
`warnings`, `notes`, and `registry`, ready for your own tooling.

## Performance (v1.2)

Same 88-dependency `package-lock.json`, same machine, same network, fresh
registry data both times (Nov 2026):

| Run | Wall time |
|---|---|
| v1.1 — sequential, one package at a time | **85.8 s** |
| v1.2 — cold (network, no cache) | **2.9 s** |
| v1.2 — warm (24 h verdict cache) | **0.08 s** |

All three runs return **identical verdicts for all 88 packages** — the diff
against the old engine is empty. What changed:

- **Concurrent by default** — batches run on 8 worker threads (`--workers N`;
  `--workers 1` restores the old sequential, paced behavior).
- **Keep-alive + gzip** — per-thread pooled connections to the registry CDNs,
  compressed responses, and one automatic retry when a server silently closes
  an idle socket.
- **Bulk download counts** — one request answers up to 128 npm names, so an
  88-package lockfile needs 1 downloads request instead of 88 (scoped names
  and failed bulk calls fall back to per-name queries).
- **Disk cache** — verdicts are reused for 24 h (`~/.depvet-cache`; override
  the location with `DEPVET_CACHE_DIR`). ERROR rows are never cached; use
  `--no-cache` for the freshest data, `--cache-ttl SECONDS` to tune.
- **Mirrors / self-hosted registries** — `DEPVET_NPM_REGISTRY`,
  `DEPVET_NPM_DOWNLOADS`, `DEPVET_PYPI_REGISTRY` point depvet at an
  Artifactory/Nexus mirror; proxied environments fall back to urllib so
  `HTTP(S)_PROXY` keeps working.

**Why not Rust?** We evaluated a Rust port for this release and rejected it:
the wall time is network-bound — waiting on registry CDNs, not computing — so
threads + connection reuse + caching recover essentially all of it, while the
zero-dependency, single-file, runs-on-any-Python-3.8 property is exactly what
makes depvet installable by an agent in seconds. A compiled binary would add
a build toolchain and distribution matrix for no measurable win. If a
genuinely CPU-bound use case appears (bulk name screening offline at millions
of names), a Rust core becomes interesting — see the roadmap.

## What depvet is not

- Not a malware sandbox — it reads registry metadata, it does not execute
  package code (that is the point).
- Not a continuous monitor — it gates the moment of install (or a PR's
  lockfile). It does not watch registries over time; run it per change, and
  use [Socket](https://socket.dev) or Snyk for continuous scanning.
- Not a deep behavioral scanner — lockfile mode vets every *pinned* package,
  but it cannot see what a fresh `npm install` would resolve tomorrow. Pin
  your deps, run depvet on the lockfile, and keep `npm audit` for advisory
  data.
- Not a blocker of private packages — scoped internal names (`@company/*`
  on your own registry) are explicitly out of scope.

## FAQ

**Does it phone anywhere besides the package registry?**
No. Two GET endpoints per package (registry metadata + download counts), read-only, no auth, no telemetry.

**Will it slow my agent down?**
No — that was v1.2's whole point: lookups run 8-way concurrent over keep-alive
connections, download counts come from npm's bulk endpoint, and verdicts are
cached on disk for 24 h. A 90-package lockfile scans in ~3 s cold and ~0.1 s
warm. Run `--no-cache` when you explicitly want the freshest registry data.

**Why does a 144M-downloads/week package WARN?**
Because `axios` is factually single-maintainer — the exact profile that made
the Sep 2025 phishing compromise possible. WARN means *surface and confirm*,
not *refuse*. Reviewed it? Put it in `.depvetrc.json` and move on.

**Does the allowlist weaken the gate?**
No. It only silences *already-surfaced* WARNs, records who/why, and cannot
touch BLOCK verdicts (confusable names, dangerous scripts, nonexistent
packages, fresh drops).

**npm 12 stopped running lifecycle scripts by default — is this obsolete?**
No, for four reasons: scripts still run on npm < 12, scripted CI installs,
yarn/pnpm/bun defaults and every package that opts in; the 2025-26 incident
wave (Shai-Hulud, s1ngularity, @acitons) was *entirely* script-driven;
half of depvet's checks don't involve scripts at all (identity, distance,
scope, 404/slopsquat, age, maintainers, license); and a package that runs
its own scripts still deserves a look before you hand it your machine.

**Why check scopes like `@acitons` against popular scopes?**
Because `@acitons/artifact` (a real Nov 2025 typosquat of
`@actions/artifact`, used in GitHub Actions workflows) collected ~47k
installs and CI tokens before anyone noticed. depvet warns when a young,
low-adoption package sits under a scope that is 1-2 edits from a famous one.

**Can the agent override a BLOCK?**
No. Only the user can, explicitly. If the user overrides two lookalike-name
blocks in one session, the skill stops and re-verifies — that pattern is how
typosquat disasters start.

## Roadmap

- [x] `--lockfile package-lock.json` + `--requirements requirements.txt` batch mode (v1.1)
- [x] GitHub Action for PR-level dependency gating (v1.1)
- [x] Allowlist for reviewed packages (`.depvetrc.json`) (v1.1)
- [x] Deprecation / provenance / yanked signals (v1.1)
- [x] Performance pass: concurrent lookups, bulk downloads API, keep-alive +
  gzip, disk cache — 88-dep lockfile 85.8 s → 2.9 s cold, 0.08 s warm (v1.2)
- [x] `yarn.lock` (v1 + Berry) and `pnpm-lock.yaml` (v6/v9) batch mode,
  `--production` dev-only filtering (v1.3)
- [x] 2025-26 IOC wave in install-script checks: webhook exfil endpoints,
  Discord webhooks, CI/publish token harvesting, Shai-Hulud bun droppers,
  cloud credential paths (v1.3)
- [x] Scoped typosquat detection (`@acitons` vs `@actions` pattern) (v1.3)
- [ ] Go module proxy + crates.io adapters
- [ ] MCP server mode (for Claude Desktop and MCP-capable agents)
- [ ] Optional Rust core for offline bulk-name screening (only if a CPU-bound
  use case shows up — measured rationale in [Performance](#performance-v12))
- [ ] `depvet approve` command to manage `.depvetrc.json` interactively

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
