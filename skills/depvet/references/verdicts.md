# Verdict matrix

Decision table for turning signals into verdicts. Signals are defined in
[red-flags.md](red-flags.md).

## BLOCK — never install on your own authority

| Signal | Verdict note must include |
|---|---|
| Confusable identity (§1) | the real package name, the difference |
| Edit distance ≤ 2 from a top package (§2) | distance + the real name |
| Registry 404 (§3) | whether a close real name exists |
| Suspicious lifecycle script (§4) | the quoted script line |
| Fresh-drop profile (§5) | age + downloads |
| Unaccountable provenance (§6) | the three components |

Rules:
- BLOCK + an obvious correct name → propose it, wait for confirmation.
- BLOCK + no obvious name → state what you know, ask the user. Do not
  guess, do not substitute a "similar" package unilaterally.
- The user can override any BLOCK — once, explicitly, by a human. Record
  the override in your summary. Two overrides on lookalike names in one
  session = stop and re-verify the user actually meant those names.

## WARN — install only after the user sees the warning

| Signal | Typical good reason to proceed anyway |
|---|---|
| Single maintainer (§7) | de-facto standard (`axios`-class), user accepts risk |
| Abandoned (§8) | stable, frozen, low attack surface — user accepts |
| License gap (§9) | internal tool, user accepts legal review |
| Low adoption (§10) alone | brand new but published by a team the user knows |
| Age < 63 days | user is the author, or vetted the repo themselves |

Never merge a WARN into a PASS silently. The report shows WARN rows even
when everything proceeds.

## PASS — proceed

No BLOCK signals and no WARN signals. Still pin the exact version you
resolved and mention it.

## ERROR — registry unreachable

Retry once. If it still fails, say so and stop: an unverified install is a
WARN at best, never a PASS. Never treat "couldn't check" as "probably
fine".

## Proportions to keep

- One table, ≤ 3 sentences of prose around it.
- BLOCK reasons are quotes or facts, not adjectives ("runs
  `curl ... | sh` in postinstall", not "very suspicious").
- If everything passes, say so in one line and move on — the gate exists
  to keep work flowing, not to perform security theater.
