# Red flags — every signal depvet checks, and why

Each signal below is drawn from a documented attack or incident. Thresholds
are deliberately conservative: a WARN never blocks silently, a BLOCK always
names its reason.

## 1. Confusable identity (BLOCK)

The package name equals a famous package after removing `-`, `_`, `.`, `/`,
case, or scope. Examples: `crossenv` vs `cross-env`, `lodashs` vs `lodash`,
`reactrouter` vs `react-router`.

**Why:** the 2017 `crossenv` typosquat stole npm credentials from thousands
of developers this way. Variants are still being published today, and the
original squats often stay on the registry for years, collecting typo
traffic (the real `crossenv` still shows ~2k weekly downloads years later).

**Rule:** if canonical forms match but literal names differ → BLOCK and
suggest the real name.

## 2. Edit-distance typosquat (BLOCK)

Canonical edit distance 1–2 from a top package, with low adoption for the
candidate name. Examples seen in the wild: `reqests`, `colour`, `node-fetchc`.

**Why:** OWASP's NPM cheat sheet lists typosquatting as a top attack class;
Microsoft reported an active single-actor typosquat campaign (May 2026)
stealing cloud and CI/CD credentials via lookalike npm names.

**Rule:** distance ≤ 2 against the popular list → BLOCK with "did you mean".

## 3. Nonexistent name / slopsquat (BLOCK)

The registry returns 404. Two cases:
- The user/agent misremembered a name → suggest the closest real package.
- An AI hallucinated the name → **slopsquat**: attackers watch LLM outputs
  and publish malicious packages under hallucinated names before anyone
  notices. OWASP documents this as a distinct attack vector on AI coding
  assistants.

**Rule:** 404 → BLOCK. Never invent a substitute name; never probe-publish.

## 4. Dangerous install scripts (BLOCK)

npm runs `preinstall` / `install` / `postinstall` (and `prepare` /
`prepack`) with full user privileges — before the user has read a single
line of the package. Red patterns inside those scripts: `curl|sh`,
`wget -O`, `base64 -d`, `eval`, `child_process`, `node -e`, encoded
PowerShell, `certutil`, references to `.npmrc` / `.ssh` / `.git-credentials`
/ trufflehog / gitleaks, or any remote URL.

**Why:** the Shai-Hulud worm (Nov 2025) propagated via lifecycle scripts and
stole tokens with TruffleHog; the Sep 2025 npm phishing compromise injected
code through published packages that ran on install.

**Rule:** any suspicious pattern in a lifecycle script → BLOCK, quoting the
script line.

## 5. Fresh-drop profile (BLOCK if also low adoption)

Age < 21 days AND weekly downloads < 100 (npm), or age < 21 days with ≤ 2
releases (PyPI).

**Why:** malicious packages live short lives — published, downloaded by
victims, removed. A package nobody has ever heard of, that appeared this
week, has no reputation to lose. Legitimate new packages usually announce
themselves (repo, docs, README, versions).

**Rule:** fresh + invisible → BLOCK. Fresh + visible (repo, docs, real
team) → WARN at most.

## 6. Unaccountable provenance (BLOCK combo)

No source repository + single maintainer + low adoption (<1000/week).

**Why:** if something goes wrong there is no second maintainer to notice,
no repo to diff against the published tarball, and no community watching.
This is the profile of the classic credential-stealer uploads tracked by
Socket and Snyk.

## 7. Single maintainer (WARN)

Bus-factor risk: one compromised account is how chalk/debug-class
compromises happen (one developer phished → packages with billions of
weekly downloads updated with malware). Not a reason to refuse — a reason
to surface and let the user decide.

## 8. Abandonment (WARN)

Latest version published > 2 years ago, especially combined with single
maintainership. `request` (14M+ weekly downloads, unmaintained since ~2020)
is the canonical example: abandoned packages stop getting security fixes
while continuing to be installed.

## 9. License gap (WARN)

No license declared → default copyright, redistribution technically
infringing. Matters for companies; flag it, let legal decide.

## 10. Low adoption (WARN)

< 1000 weekly downloads. Weak signal alone — every package starts at zero —
but it amplifies every other signal. Never WARN on adoption by itself for
packages younger than a week that have a real repo.

## 11. Deprecated in place (WARN)

npm exposes a deprecation notice on the package version itself.

**Why:** deprecation does not remove a package — it stays installable and
its install scripts keep running. `request` is the canonical case: 14M+
weekly downloads, deprecated since 2020, still pulling downstream projects
into an unmaintained dependency. Takedown-squats are also often deprecated
in place rather than deleted, so a deprecation notice on a young
low-adoption package corroborates the squat verdict.

**Rule:** `deprecated` field present → WARN with the maintainer's message.
Deprecated + other red flags → the other flags do their own work; the
notice is surfaced alongside.

## 12. Missing provenance on a brand-new package (WARN, corroborating only)

npm provenance publishes signed attestations linking a package to its build
(`dist.attestations` in registry metadata).

**Why:** absence on a package that has existed for years means nothing —
provenance is optional and recent. Absence on a package published *days*
ago removes the one link that would tie the release to a public repository,
which matters because fresh-drop + no-repo + single maintainer is exactly
the profile of Socket/Snyk-tracked credential stealers.

**Rule:** no attestations AND age < fresh-days → WARN. Never warn on the
absence alone for established packages.

## 13. Yanked release (WARN, PyPI)

Every file of the latest release carries `"yanked": true`.

**Why:** a yank means the maintainer (or PyPI staff) withdrew the release —
accidental upload, broken artifact, or malicious code removal. Either way
the "latest" version is not what `pip` resolves by default, and anything
that pins to it should be questioned.

**Rule:** all files of the latest version yanked → WARN.
