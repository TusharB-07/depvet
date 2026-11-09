# Registry API cookbook (read-only, no auth)

When `scripts/depvet_check.py` is unavailable, query registries directly.
All endpoints are public, read-only, and safe to call. Apply the thresholds
from [verdicts.md](verdicts.md) to whatever fields you fetch.

## npm

### Package metadata
```
GET https://registry.npmjs.org/<name>
GET https://registry.npmjs.org/<version>            # one version
```
Scope-encode: `@types/node` → `@types%2Fnode` (or pass `@` through unescaped).
404 means the name does not exist → slopsquat/typosquat handling.

Fields to extract:
| Field | Meaning | Signal |
|---|---|---|
| `dist-tags.latest` | current release | pin this after PASS |
| `time.created` | first publish date | age |
| `time.<latest>` | latest publish date | abandonment |
| `versions` | version manifests | version count |
| `versions[latest].scripts` | lifecycle scripts | **payload risk** |
| `versions[latest].license` | license | legal |
| `versions[latest].repository` | source repo | provenance |
| `maintainers` | accounts that can publish | bus factor |

### Weekly downloads
```
GET https://api.npmjs.org/downloads/point/last-week/<name>
```
Returns `{"downloads": N, ...}` for the last 7 days. Scoped packages work
with the same path shape. A 404 here just means "not tracked yet".

### Lifecycle scripts worth reading
`preinstall`, `install`, `postinstall`, `prepack`, `postpack`, `prepare`,
`prepublishOnly`. Any of them is worth a look; dangerous content patterns
are listed in [red-flags.md](red-flags.md) §4.

## PyPI

```
GET https://pypi.org/pypi/<name>/json
```
404 = name does not exist.

| Field | Meaning | Signal |
|---|---|---|
| `info.version` | latest version | pin this |
| `info.license` / `info.license_expression` | license | legal |
| `info.project_urls` | repo/homepage | provenance |
| `releases` | all versions + files | version count, first/last upload dates (`upload_time_iso_8601` per file) |

PyPI's JSON API does not expose maintainer accounts or download counts —
skip those signals and rely on age, release cadence, and repository links.

## politeness

- Cache within a session; re-check only on version change.
- No bulk crawling: check the packages you are about to install, nothing more.
- Never authenticate to a registry as part of vetting. Read-only, always.
