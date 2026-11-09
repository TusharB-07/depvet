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

## November 2025 — Shai-Hulud worm (npm, self-replicating)

The first large self-replicating npm worm: infected maintainer tokens were
used to publish infected versions across 100+ packages (second wave hit
Zapier, ENS, AsyncAPI, PostHog among others), stealing secrets with
TruffleHog and republishing itself through victims' credentials.
Lesson: lifecycle scripts executed at install time are the payload
delivery of choice; the install moment is the last point of control.

## May 2026 — coordinated typosquat campaign (Microsoft report)

Microsoft identified a single threat actor publishing typosquatted npm
packages that stole cloud and CI/CD credentials at scale.
Lesson: typosquatting is not history — it is an active, industrialized
campaign class.

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
- Microsoft Security blog (May 2026 typosquat campaign)
- Snyk research blog (typosquatting case studies)
