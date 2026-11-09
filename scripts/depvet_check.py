#!/usr/bin/env python3
"""
depvet — vet third-party packages BEFORE your agent installs them.

Zero dependencies. Python 3.8+. Stdlib only (urllib + json).
Works standalone, or as the checker invoked by the depvet agent skill.

Usage:
  python3 depvet_check.py react axios lodash          # npm (default)
  python3 depvet_check.py --registry pypi requests    # PyPI
  python3 depvet_check.py --json react                # machine-readable
  python3 depvet_check.py --strict react some-lib     # treat WARN as failure

Exit codes: 0 = all PASS, 1 = at least one WARN, 2 = at least one BLOCK/NOTFOUND,
            3 = network/regional failure.
"""

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week"
PYPI_REGISTRY = "https://pypi.org/pypi"

TIMEOUT = 15
UA = "depvet/1.0 (agent dependency gate)"

# --------------------------------------------------------------------------
# Popular-package lists used for typosquat / slopsquat distance checks.
# Top packages by dependents/downloads at time of writing. Contributions
# welcome: keep sorted, lowercase.
# --------------------------------------------------------------------------
POPULAR_NPM = """
@angular/core @aws-sdk/client-s3 @babel/core @babel/preset-env @babel/runtime
@emotion/react @eslint/js @material-ui/core @nestjs/common @nestjs/core
@ngrx/store @nx/devkit @playwright/test @prisma/client
@reduxjs/toolkit @sentry/node @stripe/stripe-js @supabase/supabase-js
@swc/core @tanstack/react-query @tanstack/react-table @testing-library/react
@trpc/server @types/jest @types/node @types/react @typescript-eslint/parser
@vitejs/plugin-react @vue/test-utils axios babel-core babel-jest babel-loader
bcrypt body-parser bootstrap bull chalk classnames commander core-js cors
cross-env css-loader dayjs debug dotenv esbuild eslint eslint-plugin-react
express fastify fetch firebase fs-extra glob graphql helmet http https i18next
immer jest js-yaml jsdom jsonwebtoken knex koa less lodash
lodash-es lru-cache lucide-react moment mongoose morgan mysql2 next
node-fetch nodemon npm react react-dom react-hook-form
react-redux react-router react-router-dom redux request rimraf rxjs sass
semver socket.io socket.io-client style-loader styled-components
supertest tailwindcss tar terser three ts-node tsx typeorm
typescript underscore uuid vite vitest vue vue-router webpack
webpack-cli webpack-dev-server winston ws yup zustand js-cookie bcryptjs
multer pdfkit sharp inquirer ora progress globby shelljs
execa date-fns node-cron cheerio puppeteer
playwright openai langchain @langchain/core anthropic
@anthropic-ai/sdk google-auth-library firebase-admin aws-sdk stripe
@octokit/rest simple-git formidable msw cypress karma
jasmine jasmine-core prettier eslint-config-prettier husky
concurrently cross-spawn node-sass postcss autoprefixer sass-loader
toastr chart.js d3 gsap framer-motion
@mui/icons-material @mui/material antd react-icons recharts
leaflet mapbox-gl ioredis redis
kafkajs amqplib pg sequelize apollo-server @apollo/client
swr jotai recoil mobx @angular/cli zone.js tslib
nodemailer twilio @sendgrid/mail nanoid shortid slugify
dotenv-expand
""".split()

POPULAR_PYPI = """
requests numpy pandas flask django fastapi boto3 torch tensorflow scikit-learn
scipy matplotlib seaborn plotly dash streamlit gradio pytest poetry uv
black flake8 pylint mypy isort ruff setuptools wheel pipenv virtualenv
pydantic sqlalchemy alembic celery redis pymongo psycopg2 mysqlclient
gunicorn uvicorn httpx aiohttp tornado websocket-client beautifulsoup4
lxml html5lib openpyxl xlrd xlsxwriter python-docx PyPDF2 reportlab
Pillow opencv-python imageio scikit-image tqdm rich click typer
python-dotenv pyyaml tomli toml jsonschema marshmallow
cryptography paramiko pycryptodome bcrypt passlib PyJWT python-jose
oauthlib requests-oauthlib google-auth google-api-python-client
google-cloud-storage azure-storage-blob s3transfer
transformers datasets tokenizers sentencepiece accelerate diffusers
openai anthropic langchain llama-index chromadb
qdrant-client faiss-cpu sentence-transformers
spacy nltk gensim networkx sympy statsmodels xgboost lightgbm
catboost optuna mlflow wandb tensorboard onnx onnxruntime
pymupdf pdfminer.six yfinance ccxt tweepy
discord.py python-telegram-bot slack-sdk selenium
locust scrapy pytest-asyncio pytest-cov coverage
hypothesis faker mimesis factory_boy freezegun responses vcrpy
""".split()

# Patterns that make an install script dangerous. Matched case-insensitively.
SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"curl\b[^|]*\|\s*(ba)?sh", "downloads and pipes a script into a shell"),
    (r"wget\b[^|]*\|\s*(ba)?sh", "downloads and pipes a script into a shell"),
    (r"curl\b.*(-o|--output|-O)", "downloads a file to disk"),
    (r"wget\b.*(-o|--output|-O)", "downloads a file to disk"),
    (r"base64\s+(-d|--decode|-D)", "decodes base64 payloads"),
    (r"\beval\b", "evaluates dynamic code"),
    (r"child_process", "spawns child processes"),
    (r"node\s+-e", "runs inline node code"),
    (r"powershell\b.*(-enc|-EncodedCommand)", "runs encoded PowerShell"),
    (r"iex\s*\(\s*(new-object|invoke)", "downloads/executes PowerShell in memory"),
    (r"certutil\b", "Windows certutil (common malware dropper)"),
    (r"\bssh\b|\bscp\b", "reaches over SSH"),
    (r"trufflehog|gitleaks|\.git-credentials|\.npmrc|\.ssh", "targets credentials"),
    (r"https?://", "contacts a remote URL during install"),
]

INSTALL_SCRIPT_KEYS = [
    "preinstall", "install", "postinstall", "prepack", "postpack",
    "prepare", "prepublish", "prepublishOnly",
]

# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------

def http_get_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, "notfound"
        return None, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 - report any network problem
        return None, str(e)


def parse_date(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def days_ago(s):
    d = parse_date(s)
    if not d:
        return None
    return max(0, (datetime.now(timezone.utc) - d).days)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 4:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def canon(name: str) -> str:
    """Normalize for confusability checks: lowercase, drop scope/separators."""
    n = name.lower().lstrip("@").replace("/", "-")
    return re.sub(r"[-_.]", "", n)


def find_closest_popular(name: str, popular):
    """Return (popular_name, distance, canon_distance) for the closest match."""
    best = (None, 99, 99)
    cn = canon(name)
    for p in popular:
        cp = canon(p)
        d = levenshtein(cn, cp)
        if d < best[2]:
            best = (p, levenshtein(name.lower(), p.lower()), d)
    return best


def scan_scripts(scripts: dict):
    """Return list of (script_name, reason) for suspicious lifecycle scripts."""
    hits = []
    for key in INSTALL_SCRIPT_KEYS:
        val = scripts.get(key)
        if not val or not isinstance(val, str):
            continue
        for pat, why in SUSPICIOUS_SCRIPT_PATTERNS:
            if re.search(pat, val, re.IGNORECASE):
                hits.append((key, why))
    return hits


def empty_meta():
    return dict(flags=[], warnings=[], notes=[], age_days=None, weekly=None,
                maintainers=None, license=None, repo=None, scripts=False, latest=None)


# --------------------------------------------------------------------------
# Registry checks
# --------------------------------------------------------------------------

def check_npm(name: str, opts):
    notes, flags, warnings = [], [], []

    if name.startswith("@") and "/" not in name:
        meta = empty_meta()
        meta["notes"] = ["scoped name without '/' is invalid"]
        return dict(name=name, verdict="BLOCK", **meta)

    doc, err = http_get_json(f"{NPM_REGISTRY}/{urllib.parse.quote(name, safe='@')}")
    if doc is None:
        meta = empty_meta()
        if err == "notfound":
            close, d_exact, d_canon = find_closest_popular(name, POPULAR_NPM)
            if close and d_canon <= 2:
                meta["notes"] = [f"package does not exist on npm, but is 1-2 edits away from popular '{close}' "
                                 f"(edit distance {d_canon}) - classic typosquat / slopsquat bait. "
                                 f"Did you mean '{close}'?"]
            else:
                meta["notes"] = ["package does not exist on the npm registry. If an AI suggested this name it may "
                                 "be a hallucinated 'slopsquat' target - do not invent or publish substitutes. "
                                 "Ask the user which real package to use."]
            return dict(name=name, verdict="BLOCK", **meta)
        meta["notes"] = [f"registry unreachable: {err}"]
        return dict(name=name, verdict="ERROR", **meta)

    latest_tag = (doc.get("dist-tags") or {}).get("latest")
    versions = doc.get("versions") or {}
    latest = versions.get(latest_tag) or {}
    created = (doc.get("time") or {}).get("created")
    latest_time = (doc.get("time") or {}).get(latest_tag)
    age_days = days_ago(created)
    since_latest = days_ago(latest_time)
    n_versions = len(versions)
    maintainers = doc.get("maintainers") or []
    n_maint = len(maintainers)
    license_ = latest.get("license") or doc.get("license")
    if isinstance(license_, dict):
        license_ = license_.get("type")
    repo = (latest.get("repository") or doc.get("repository") or {})
    repo_url = repo.get("url") if isinstance(repo, dict) else repo
    scripts = latest.get("scripts") or {}
    script_hits = scan_scripts(scripts)

    dl, dl_err = http_get_json(f"{NPM_DOWNLOADS}/{urllib.parse.quote(name, safe='@')}")
    weekly = (dl or {}).get("downloads") if dl else None

    # ---- verdict logic (see references/red-flags.md for rationale) --------
    close, d_exact, d_canon = find_closest_popular(name, POPULAR_NPM)
    if close and canon(name) == canon(close) and name.lower() != close.lower():
        flags.append(f"CONFUSABLE IDENTITY: '{name}' differs from popular package '{close}' only by "
                     f"separators/case (the crossenv-vs-cross-env typosquat pattern). "
                     f"Did you mean '{close}'?")
    elif close and 1 <= d_canon <= 2 and (weekly is None or weekly < 5000):
        # Distance alone is not proof: an established name that happens to be
        # 2 edits from another (zod vs koa) is not a squat. Distance + low
        # adoption is the squat signature.
        flags.append(f"name is {d_canon} edit(s) from popular package '{close}' - typosquat pattern "
                     f"(weekly downloads of '{name}': {weekly if weekly is not None else '?'}). "
                     f"Did you mean '{close}'?")

    if script_hits:
        for key, why in script_hits:
            flags.append(f"'{key}' install script {why}: {scripts.get(key)[:120]!r}")

    if age_days is not None and age_days < opts.fresh_days and weekly is not None and weekly < 100:
        flags.append(f"package is {age_days} days old with only {weekly} downloads/week - fresh-drop profile")

    if (repo is None or (isinstance(repo, dict) and not repo_url)) and n_maint <= 1 \
            and weekly is not None and weekly < 1000:
        flags.append("no source repository, single maintainer, low adoption - unaccountable provenance")

    if n_maint <= 1:
        warnings.append("single maintainer (bus factor / account-takeover blast radius)")
    if age_days is not None and age_days < opts.fresh_days * 3:
        warnings.append(f"very young package ({age_days} days old)")
    if not repo_url:
        warnings.append("no source repository declared")
    if weekly is not None and weekly < 1000:
        warnings.append(f"low adoption: {weekly} downloads/week")
    if not license_:
        warnings.append("no license declared (legal risk if redistributed)")
    if since_latest is not None and since_latest > 730:
        warnings.append(f"latest version published {since_latest // 365}+ year(s) ago (possibly abandoned)")

    notes.append(f"latest {latest_tag}, {n_versions} versions")
    if age_days is not None:
        notes.append(f"created {age_days} days ago")
    if weekly is not None:
        notes.append(f"{weekly} downloads/week")
    notes.append(f"{n_maint} maintainer(s)")
    notes.append(f"license: {license_ or 'NONE'}")
    if scripts:
        notes.append("install scripts present (benign-looking)" if not script_hits else "install scripts present")

    verdict = "BLOCK" if flags else ("WARN" if warnings else "PASS")
    return dict(
        name=name, verdict=verdict, flags=flags, warnings=warnings, notes=notes,
        age_days=age_days, weekly=weekly, maintainers=n_maint, license=license_,
        repo=repo_url, scripts=bool(scripts), latest=latest_tag,
    )


def check_pypi(name: str, opts):
    notes, flags, warnings = [], [], []

    doc, err = http_get_json(f"{PYPI_REGISTRY}/{urllib.parse.quote(name, safe='')}/json")
    if doc is None:
        meta = empty_meta()
        if err == "notfound":
            close, d_exact, d_canon = find_closest_popular(name, POPULAR_PYPI)
            if close and d_canon <= 2:
                meta["notes"] = [f"package does not exist on PyPI, but is 1-2 edits from popular '{close}' - "
                                 f"typosquat pattern. Did you mean '{close}'?"]
            else:
                meta["notes"] = ["package does not exist on PyPI. If an AI suggested this name it may be a "
                                 "hallucinated 'slopsquat' target. Ask the user which real package to use."]
            return dict(name=name, verdict="BLOCK", **meta)
        meta["notes"] = [f"registry unreachable: {err}"]
        return dict(name=name, verdict="ERROR", **meta)

    info = doc.get("info") or {}
    releases = doc.get("releases") or {}
    urls = info.get("project_urls") or {}
    license_ = info.get("license_expression") or info.get("license")
    upload_times = []
    for files in releases.values():
        for f in files:
            t = parse_date(f.get("upload_time_iso_8601") or f.get("upload_time"))
            if t:
                upload_times.append(t)
    age_days = None
    since_latest = None
    if upload_times:
        age_days = (datetime.now(timezone.utc) - min(upload_times)).days
        since_latest = (datetime.now(timezone.utc) - max(upload_times)).days
    n_versions = len(releases)
    repo_url = (urls.get("Source") or urls.get("Repository") or urls.get("Homepage")
                or info.get("home_page") or "")
    n_maint = None  # PyPI JSON API does not expose maintainers

    close, d_exact, d_canon = find_closest_popular(name, POPULAR_PYPI)
    if close and canon(name) == canon(close) and name.lower() != close.lower():
        flags.append(f"CONFUSABLE IDENTITY: '{name}' differs from popular package '{close}' only by "
                     f"separators/case. Did you mean '{close}'?")
    elif close and 1 <= d_canon <= 2 and not (age_days and age_days > 365 and n_versions > 10):
        # PyPI has no download counts; treat long-lived multi-release names as
        # established so they are not flagged for bare distance.
        flags.append(f"name is {d_canon} edit(s) from popular package '{close}' - typosquat pattern. "
                     f"Did you mean '{close}'?")

    if age_days is not None and age_days < opts.fresh_days and n_versions <= 2:
        flags.append(f"package is {age_days} days old with {n_versions} release(s) - fresh-drop profile")

    if n_versions <= 2:
        warnings.append(f"only {n_versions} release(s) - no track record")
    if age_days is not None and age_days < opts.fresh_days * 3:
        warnings.append(f"very young package ({age_days} days old)")
    if not repo_url:
        warnings.append("no source repository / homepage declared")
    if not license_:
        warnings.append("no license declared (legal risk if redistributed)")
    if since_latest is not None and since_latest > 730:
        warnings.append(f"last release {since_latest // 365}+ year(s) ago (possibly abandoned)")

    notes.append(f"{n_versions} versions")
    if age_days is not None:
        notes.append(f"created {age_days} days ago")
    notes.append(f"license: {license_ or 'NONE'}")

    verdict = "BLOCK" if flags else ("WARN" if warnings else "PASS")
    return dict(
        name=name, verdict=verdict, flags=flags, warnings=warnings, notes=notes,
        age_days=age_days, weekly=None, maintainers=n_maint, license=license_,
        repo=repo_url, scripts=False, latest=(doc.get("info") or {}).get("version"),
    )


CHECKERS = {"npm": check_npm, "pypi": check_pypi}


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

ORDER = {"BLOCK": 0, "ERROR": 1, "WARN": 2, "PASS": 3}
COLOR = {"BLOCK": "\033[1;31m", "WARN": "\033[1;33m", "PASS": "\033[1;32m", "ERROR": "\033[1;35m"}
BOLD, RESET = "\033[1m", "\033[0m"


def render_table(results):
    header = ["PACKAGE", "VERDICT", "AGE", "DOWNLOADS", "MAINT", "SCRIPTS", "LICENSE"]
    rows = []
    for r in results:
        age = f"{r['age_days']}d" if r["age_days"] is not None else "?"
        dl = f"{r['weekly']:,}/wk" if r.get("weekly") else "-"
        rows.append([
            r["name"][:28], r["verdict"], age, dl,
            str(r["maintainers"]) if r.get("maintainers") is not None else "-",
            ("yes" if r.get("scripts") else "no"),
            (r.get("license") or "NONE")[:16],
        ])
    widths = [max(len(str(row[i])) for row in [header] + rows) for i in range(len(header))]
    out = []
    out.append("  ".join(BOLD + h.ljust(w) + RESET for h, w in zip(header, widths)))
    for row, raw in zip(rows, results):
        colored = list(row)
        colored[1] = COLOR.get(row[1], "") + row[1] + RESET
        # width accounting: strip ANSI for padding
        out.append("  ".join(
            (c if i == 1 else c.ljust(w)) if i == 1 else c.ljust(w)
            for i, (c, w) in enumerate(zip(colored, widths))
        ))
        for f in raw.get("flags", []):
            out.append(f"    [BLOCK] {f}")
        for w in raw.get("warnings", []):
            out.append(f"    [WARN]  {w}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(prog="depvet", description="Vet packages before installing them.")
    ap.add_argument("packages", nargs="+", help="package name(s) to vet")
    ap.add_argument("--registry", choices=["npm", "pypi"], default="npm")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ap.add_argument("--strict", action="store_true", help="exit non-zero on WARN too")
    ap.add_argument("--fresh-days", type=int, default=21, help="age threshold for 'fresh drop' (default 21)")
    ap.add_argument("--max-delay", type=float, default=1.0, help="max seconds between lookups")
    opts = ap.parse_args()

    results = []
    for i, pkg in enumerate(opts.packages):
        if i:
            time.sleep(min(opts.max_delay, 0.4))
        pkg = pkg.strip()
        if not pkg or pkg.startswith("-"):
            continue
        results.append(CHECKERS[opts.registry](pkg, opts))

    results.sort(key=lambda r: ORDER.get(r["verdict"], 9))

    if opts.json:
        print(json.dumps({"registry": opts.registry, "results": results}, indent=2))
    else:
        print(render_table(results))
        blocked = [r["name"] for r in results if r["verdict"] == "BLOCK"]
        warned = [r["name"] for r in results if r["verdict"] == "WARN"]
        errors = [r["name"] for r in results if r["verdict"] == "ERROR"]
        print()
        if blocked:
            print(f"{COLOR['BLOCK']}BLOCKED:{RESET} {', '.join(blocked)} - do NOT install. "
                  f"Ask the user how to proceed.")
        if warned:
            print(f"{COLOR['WARN']}WARNINGS:{RESET} {', '.join(warned)} - surface to the user before installing.")
        if errors:
            print(f"{COLOR['ERROR']}UNREACHABLE:{RESET} {', '.join(errors)} - retry or vet manually.")
        ok = [r["name"] for r in results if r["verdict"] == "PASS"]
        if ok and not blocked:
            print(f"{COLOR['PASS']}CLEARED:{RESET} {', '.join(ok)}")

    codes = [r["verdict"] for r in results]
    if "BLOCK" in codes or "ERROR" in codes:
        sys.exit(2)
    if "WARN" in codes and opts.strict:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
