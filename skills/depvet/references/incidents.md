# Incident file — why this skill exists

Real supply-chain failures, condensed to the lesson each one teaches. Dates
and facts as reported by the sources named at the end.

## 2017 — `crossenv` (npm, typosquat)

An attacker published `crossenv`, a one-character variant of `cross-env`
(then ~1M weekly downloads). The payload ran on install and harvested npm
credentials from environment variables. Thousands of installs before
takedown. **The squat is still live on npm today, still collecting typo
traffic.**
Lesson: confusable names are permanent bait; the gate must run before the
install, not after a report.

## 2018 — `event-stream` (npm, maintainer takeover)

The maintainer of a package with millions of weekly downloads handed it to
a helpful stranger; the stranger added an obfuscated dependency targeting
one Bitcoin wallet app. Discovered months later.
Lesson: single-maintainer and takeover risk is real even for famous,
widely-trusted packages.

## 2018 — `eslint-scope` (npm, typosquat)

Lookalike of `eslint-scope` published during a busy workday; its
`postinstall` script exfiltrated npm tokens. Victims included CI systems.
Lesson: install scripts + typosquat is the classic combo — exactly the two
signals depvet weights most.

## September 2025 — npm phishing compromise (chalk/debug class)

A developer-phishing campaign ("ghostbackend" actor) compromised maintainers
of packages with billions of combined weekly downloads; malicious versions
were published and began self-propagating by authenticating to npm as the
compromised developers. Browser payloads redirected cryptocurrency traffic.
Lesson: one phished maintainer is a global event; weekly-download fame does
not protect you, so vetting cannot be skipped for famous packages either.

## August 2025 — s1ngularity (Nx build system, CI pipeline exploit)

Attackers exploited the `pull_request_target` trigger in GitHub Actions
workflows to steal an npm publishing token, then published malicious Nx
packages whose `telemetry.js` ran on postinstall, harvested credentials and
exfiltrated them to public GitHub repos under the victims' own accounts
(2,000+ unique secrets in the first phase; a second phase made private repos
public with stolen GitHub tokens).
Lesson: install scripts are the first-stage payload; CI token hygiene and
credential rotation decide how far the blast radius spreads.

## October–November 2025 — @acitons/artifact (npm, scoped typosquat)

`@acitons/artifact` typosquatted `@actions/artifact`, the npm package used
inside GitHub Actions workflows. It accumulated ~47k downloads across
4.0.12–4.0.17, then used a postinstall hook to drop an obfuscated "harness"
script plus `verify.js`, which collected `GITHUB_*` workflow variables and
exfiltrated them encrypted to an `app.github[.]dev` subdomain. The payload
was time-bombed to self-disable after 2025-11-06. (GitHub later stated this
particular package was its own red-team exercise — which makes the lesson,
not the risk, smaller: a scoped lookalike collecting CI tokens went
undetected through tens of thousands of installs.)
Lesson: the scope prefix is a typosquat surface; nobody reads the org name.

## November 2025 — Shai-Hulud worm (npm, self-replicating)

The first large self-replicating npm worm: infected maintainer tokens were
used to publish infected versions across 100+ packages (second wave hit
Zapier, ENS, AsyncAPI, PostHog among others), stealing secrets with
TruffleHog and republishing itself through victims' credentials. Exfiltration
ran through GitHub Actions workflows to `webhook[.]site`; Shai-Hulud 2.0
(Nov 2025) added staged droppers (`setup_bun.js`, `bun_environment.js`) that
executed the payload through the bun runtime.
Lesson: lifecycle scripts executed at install time are the payload
delivery of choice; the install moment is the last point of control.

## May 2026 — coordinated typosquat campaign (Microsoft report)

Microsoft identified a single threat actor publishing typosquatted npm
packages that stole cloud and CI/CD credentials at scale.
Lesson: typosquatting is not history — it is an active, industrialized
campaign class.

## August 2026 — WEL1DROPPER (npm, AI-slopsquat campaign)

A campaign of nearly 800 (later 1,000+) confirmed npm packages under AI-
slop-squatted and randomly generated typo names delivering a remote-access
trojan — industrialized slopsquatting, exactly the OWASP-documented scenario
where attackers seed the names LLMs hallucinate.
Lesson: slopsquatting went from theory to assembly line; unverifiable names
are bait by default.

## 2022–ongoing — PyPI typosquat campaigns (ransomware, Info-Stealer)

Ongoing campaigns publish typosquats of the biggest PyPI names (the
"requests"-misspell ransomware runs are the canonical case) and rely on
typo traffic; PyPI now blocks *new* conflicting names, but canonicalization
(`foo_bar` == `foo-bar` == `foobar` on PyPI) still leaves confusable
identity variants installable.
Lesson: PyPI is not safer than npm — the gate must run there too.

## Ongoing — slopsquatting (OWASP-documented AI-era attack)

Attackers monitor LLM outputs, note hallucinated-but-plausible package
names, and publish malicious packages under exactly those names, betting
that the next developer the model gives the same name to will install it.
OWASP's NPM cheat sheet now tells developers to verify AI-suggested package
names before installing.
Lesson: an agent must treat every unverified name — including its own
suggestions — as hostile until checked.

## Sources

- OWASP NPM Security Cheat Sheet (typosquatting, slopsquatting sections)
- FortiGuard Labs threat signal report on Shai-Hulud (Nov 2025)
- GitHub Security Lab / npm incident disclosures (Sep 2025 compromise)
- Datadog Security Labs: "Learnings from recent npm supply chain compromises"
  (Oct 2025) and "The Shai-Hulud 2.0 npm worm" (Nov 2025)
- The Hacker News: @acitons/artifact analysis (Nov 2025); WEL1DROPPER
  campaign report (Aug 2026)
- safeguard.sh: npm postinstall malware trends H1 2026 (+61% YoY)
- Microsoft Security blog (May 2026 typosquat campaign)
- Snyk research blog (typosquatting case studies)
