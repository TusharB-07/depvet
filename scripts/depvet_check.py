#!/usr/bin/env python3
"""
depvet — vet third-party packages BEFORE your agent installs them.

Zero dependencies. Python 3.8+. Stdlib only.
Works standalone, or as the checker invoked by the depvet agent skill.

Batches run concurrently (8 registry connections by default), npm download
counts come from the bulk endpoint (one request per 128 names), gzip is
negotiated with the registry CDNs, and finished verdicts are cached on disk
(~/.depvet-cache, 24h TTL) - an 88-package lockfile scan drops from ~86 s
(v1.1, sequential) to a few seconds. A Rust port was evaluated for this pass
and rejected: the wall time is network-bound, so threads + connection reuse +
caching deliver the speedup without asking users to install a toolchain.

Usage:
  python3 depvet_check.py react axios lodash          # npm (default)
  python3 depvet_check.py --registry pypi requests    # PyPI
  python3 depvet_check.py --lockfile package-lock.json   # every dep in a lockfile
  python3 depvet_check.py --lockfile yarn.lock           # yarn v1 / Berry
  python3 depvet_check.py --lockfile pnpm-lock.yaml      # pnpm v6 / v9
  python3 depvet_check.py --requirements requirements.txt  # every dep, PyPI
  python3 depvet_check.py --production --lockfile package-lock.json  # skip dev-only deps
  python3 depvet_check.py --json react                # machine-readable
  python3 depvet_check.py --strict react some-lib     # treat WARN as failure
  python3 depvet_check.py --allow axios react         # silence a reviewed WARN
  python3 depvet_check.py --no-cache react            # bypass the verdict cache
  python3 depvet_check.py --workers 1 react           # sequential lookups

Exit codes: 0 = all PASS, 1 = at least one WARN (--strict escalates),
            2 = at least one BLOCK/NOTFOUND, 3 = network/regional failure.
"""

import argparse
import functools
import gzip
import hashlib
import http.client
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

# Registry endpoints. Override with env vars to vet against a mirror or a
# self-hosted registry (Artifactory/Nexus in an air-gapped org):
#   DEPVET_NPM_REGISTRY, DEPVET_NPM_DOWNLOADS, DEPVET_PYPI_REGISTRY
NPM_REGISTRY = os.environ.get("DEPVET_NPM_REGISTRY", "https://registry.npmjs.org")
NPM_DOWNLOADS = os.environ.get("DEPVET_NPM_DOWNLOADS", "https://api.npmjs.org/downloads/point/last-week")
PYPI_REGISTRY = os.environ.get("DEPVET_PYPI_REGISTRY", "https://pypi.org/pypi")

TIMEOUT = 15
UA = "depvet/1.3 (agent dependency gate)"

# Performance defaults: batches run on a small thread pool with per-thread
# keep-alive connections and gzip; npm weekly-download counts are fetched in
# bulk (128 names per request); verdicts are cached on disk with a TTL.
DEFAULT_WORKERS = 8
BULK_CHUNK = 128
CACHE_TTL_DEFAULT = 86400

# --------------------------------------------------------------------------
# Popular-package lists used for typosquat / slopsquat distance checks.
# Top packages by dependents/downloads at time of writing. Contributions
# welcome: keep sorted, lowercase.
# --------------------------------------------------------------------------
POPULAR_NPM = """
@actions/artifact @actions/cache @actions/core @actions/exec @actions/github
@actions/glob @actions/io @actions/tool-cache @actions/upload-artifact
@actions/download-artifact @angular/core @aws-sdk/client-s3 @babel/core @babel/preset-env @babel/runtime
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

# npm scopes taken from the popular list above. A *brand-new or low-adoption*
# package whose scope is a near-miss of one of these (@acitons vs @actions,
# Nov 2025) is the scoped-typosquat pattern.
KNOWN_SCOPES = sorted({p.split("/", 1)[0] for p in POPULAR_NPM if p.startswith("@")})

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
# Maintained against observed in-the-wild payloads: the classic curl|sh and
# base64 droppers, plus the 2025-2026 wave (Shai-Hulud 1.0/2.0, s1ngularity,
# @acitons/artifact, WEL1DROPPER): webhook exfil, Discord webhooks, bun
# payload files, CI/publish token harvesting, env dumping, cloud creds.
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
    (r"trufflehog|gitleaks|\.git-credentials|\.npmrc|\.ssh|\.aws\b|aws[/\\]credentials",
     "targets credentials"),
    (r"\b(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN)\b",
     "reads CI/registry publish tokens"),
    (r"printenv|\benv\b\s*\|", "dumps environment variables"),
    (r"webhook\.site|discord(app)?\.com/api/webhooks|discordapp\.com/api/webhooks"
     r"|pipedream\.net|requestbin\b|interact\.sh|app\.github\.dev",
     "exfiltrates to a webhook/harvest endpoint"),
    (r"setup_bun|bun_environment",
     "drops the Shai-Hulud worm's bun payload files"),
    (r"https?://", "contacts a remote URL during install"),
]

INSTALL_SCRIPT_KEYS = [
    "preinstall", "install", "postinstall", "prepack", "postpack",
    "prepare", "prepublish", "prepublishOnly",
]

# --------------------------------------------------------------------------
# HTTP layer: per-thread keep-alive connections, gzip decoding, redirects,
# and one automatic retry when a server has silently closed an idle socket.
# --------------------------------------------------------------------------

_tls = threading.local()


def _pooled_conn(scheme: str, host: str):
    pool = getattr(_tls, "pool", None)
    if pool is None:
        pool = {}
        _tls.pool = pool
    key = (scheme, host)
    conn = pool.get(key)
    if conn is None:
        cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        conn = cls(host, timeout=TIMEOUT)
        pool[key] = conn
    return conn


def _drop_conn(scheme: str, host: str):
    pool = getattr(_tls, "pool", None)
    if pool:
        conn = pool.pop((scheme, host), None)
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - closing a dead socket must never raise
                pass


def _request_once(scheme: str, host: str, path: str):
    """One GET over the pooled connection. Returns (state, status, headers, body)
    where state is "ok" or "error"; a connection error also drops the cached
    socket so the caller's retry builds a fresh one."""
    try:
        conn = _pooled_conn(scheme, host)
        conn.request("GET", path, headers={
            "User-Agent": UA,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
        })
        resp = conn.getresponse()
        body = resp.read()
        if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
            try:
                body = gzip.decompress(body)
            except OSError:
                return "error", 0, None, "registry sent a malformed gzip body"
        return "ok", resp.status, resp.headers, body
    except (http.client.HTTPException, OSError) as e:
        _drop_conn(scheme, host)
        return "error", 0, None, str(e) or type(e).__name__


def _proxied_env() -> bool:
    return any(os.environ.get(k) for k in
               ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                "ALL_PROXY", "all_proxy"))


def _urllib_get(url: str):
    """Fallback for proxied environments: urllib honours HTTP(S)_PROXY, the
    pooled http.client connections below do not."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return None, resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "notfound", None
        return f"HTTP {e.code}", None
    except Exception as e:  # noqa: BLE001 - report any network problem
        return str(e), None


def fetch_raw(url: str):
    """GET a URL. Returns (err, body): err is None on success, "notfound" on
    HTTP 404, otherwise a human-readable failure string."""
    if _proxied_env():
        return _urllib_get(url)
    current = url
    for _hop in range(4):
        parts = urllib.parse.urlsplit(current)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        state, status, headers, payload = _request_once(parts.scheme, parts.netloc, path)
        if state == "error":
            # almost always a server-closed idle keep-alive socket: retry once
            # on a fresh connection before giving up
            state, status, headers, payload = _request_once(parts.scheme, parts.netloc, path)
            if state == "error":
                return str(payload), None
        if status in (301, 302, 303, 307, 308):
            loc = headers.get("Location") if headers is not None else None
            if not loc:
                return f"HTTP {status}", None
            current = urllib.parse.urljoin(current, loc)
            continue
        if status == 404:
            return "notfound", None
        if status != 200:
            return f"HTTP {status}", None
        return None, payload
    return "too many redirects", None


def http_get_json(url: str):
    # Test hook: when DEPVET_FIXTURES points to a directory, responses come
    # from files named sha256(url)[:24].json (body = JSON, "404", or "ERR").
    fx = os.environ.get("DEPVET_FIXTURES")
    if fx:
        fname = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24] + ".json"
        path = os.path.join(fx, fname)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
        except OSError:
            return None, f"fixture missing: {fname}"
        if raw == "404":
            return None, "notfound"
        if raw == "ERR":
            return None, "simulated failure"
        try:
            return json.loads(raw), None
        except ValueError:
            return None, "fixture is not valid JSON"

    err, body = fetch_raw(url)
    if err:
        return None, err
    try:
        return json.loads(body.decode("utf-8", "replace")), None
    except ValueError:
        return None, "registry returned invalid JSON"


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


@functools.lru_cache(maxsize=8192)
def canon(name: str) -> str:
    """Normalize for confusability checks: lowercase, drop scope/separators.

    lru_cache: every package compares against the same ~250 popular names,
    so memoizing this turns the distance precheck into dict lookups."""
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
# Manifest / lockfile parsing and allowlist (pure functions - unit tested)
# --------------------------------------------------------------------------

def parse_package_lock(doc):
    """Extract dependency names from a package-lock.json dict (v1, v2, v3).

    v2/v3 use a flat "packages" map keyed by "node_modules/<name>" paths
    (possibly nested); v1 uses a recursive "dependencies" tree. The event-
    stream and eslint-scope compromises both arrived through transitive
    dependencies, which is exactly why the whole locked tree gets vetted.
    """
    names = []
    pkgs = doc.get("packages")
    if isinstance(pkgs, dict):
        for key in pkgs:
            if not isinstance(key, str) or key == "":
                continue  # root entry / malformed
            parts = key.split("node_modules/")
            if len(parts) > 1 and parts[-1]:
                names.append(parts[-1])
        return sorted(set(names))
    deps = doc.get("dependencies")
    if isinstance(deps, dict):
        def walk(subtree):
            for k, v in subtree.items():
                names.append(k)
                if isinstance(v, dict) and isinstance(v.get("dependencies"), dict):
                    walk(v["dependencies"])
        walk(deps)
        return sorted(set(names))
    return []


def parse_package_lock_entries(doc):
    """Extract (name, is_dev_only) pairs from a package-lock.json dict.

    v2/v3 carry a per-entry "dev"/"devOptional" flag; v1 nodes may set
    "dev": true on the dependency subtree. A name that appears both with and
    without a dev flag is NOT dev-only (it is installed for production too).
    """
    entries = []
    pkgs = doc.get("packages")
    if isinstance(pkgs, dict):
        for key, val in pkgs.items():
            if not isinstance(key, str) or key == "":
                continue  # root entry / malformed
            parts = key.split("node_modules/")
            if len(parts) > 1 and parts[-1]:
                dev = bool(val.get("dev") or val.get("devOptional")) if isinstance(val, dict) else False
                entries.append((parts[-1], dev))
        return sorted(set(entries))
    deps = doc.get("dependencies")
    if isinstance(deps, dict):
        def walk(subtree, inherited_dev):
            for k, v in subtree.items():
                dev = inherited_dev or (isinstance(v, dict) and bool(v.get("dev")))
                entries.append((k, dev))
                if isinstance(v, dict) and isinstance(v.get("dependencies"), dict):
                    walk(v["dependencies"], dev)
        walk(deps, False)
        return sorted(set(entries))
    return []


def split_prod_dev(entries):
    """Collapse [(name, is_dev)] into {name: is_dev_only}.

    A name counts as dev-only only when EVERY occurrence is dev-flagged."""
    out = {}
    for name, is_dev in entries:
        out[name] = out.get(name, True) and bool(is_dev)
    return out


def parse_package_lock(doc):
    """Back-compat wrapper: just the names (sorted, deduped)."""
    return sorted({n for n, _ in parse_package_lock_entries(doc)})


def _spec_name(spec: str):
    """'@babel/core@^7.0.0' -> '@babel/core'; 'ajv@^6.12.4' -> 'ajv'.

    Handles yarn Berry's npm: protocol ('axios@npm:^1.6.0' -> 'axios', alias
    'foo@npm:bar@^1.0.0' -> 'bar') and skips git/url/workspace specs depvet
    cannot vet by name."""
    s = spec.strip().strip('"').strip("'")
    if not s or s.startswith("__") or "://" in s:
        return None
    if "@npm:" in s:
        left, right = s.rsplit("@npm:", 1)
        # alias specs point at the real target on the right ('bar@^1.0.0');
        # plain npm: specs/resolutions keep the left side ('axios', '@babel/core')
        s = right if "@" in right else left
    if s.startswith("@"):
        rest = s[1:]
        return ("@" + rest.split("@", 1)[0]) if "@" in rest else ("@" + rest if rest else None)
    if "@" not in s:
        return s or None  # bare name (Berry resolution lines carry no range)
    name = s.split("@", 1)[0].strip()
    return name or None


def parse_yarn_lock(text: str):
    """Parse a yarn.lock (v1 classic or Berry) into (names, dev_names).

    v1 names come from the quoted/unquoted spec headers; Berry names also
    come from resolution: lines. Yarn lockfiles carry no per-package dev
    marker, so dev_names is always empty."""
    names = set()
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith(" ") or line.startswith("\t"):
            indented = line.strip()
            if indented.startswith("resolution:"):
                n = _spec_name(indented.split(":", 1)[1])
                if n:
                    names.add(n)
            continue
        if line.endswith(":"):
            for spec in line[:-1].split(","):
                n = _spec_name(spec)
                if n:
                    names.add(n)
    return sorted(names), []


def _pnpm_key_name(key: str):
    """'axios@1.6.0(underscore@1.13.2)' -> 'axios';
    \"'@babel/core@7.24.0(core-js@3.6.5)'\" -> '@babel/core'."""
    k = key.strip().strip("'").strip('"')
    if not k:
        return None
    if k.startswith("@"):
        head = k[1:].split("@", 1)[0]
        return ("@" + head) if head else None
    if "@" not in k:
        return None
    return k.split("@", 1)[0] or None


def parse_pnpm_lock(text: str):
    """Parse a pnpm-lock.yaml (v6/v9, tolerant of v5) into (names, dev_names).

    Root dependencies:/devDependencies:/optionalDependencies: sections give
    direct deps (devDependencies feed dev_names); the flat packages:/
    snapshots: maps give the full tree."""
    names, dev = set(), set()
    section = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0:
            section = stripped[:-1] if stripped.endswith(":") else None
            continue
        if indent != 2:
            continue
        if section in ("dependencies", "devDependencies", "optionalDependencies"):
            key = stripped.split(":", 1)[0].strip().strip("'").strip('"')
            name = _pnpm_key_name(key if "@" in key else key + "@")  # bare or name@range
            if name:
                names.add(name)
                if section == "devDependencies":
                    dev.add(name)
        elif section in ("packages", "snapshots"):
            if stripped.endswith(":"):
                n = _pnpm_key_name(stripped[:-1])
                if n:
                    names.add(n)
    return sorted(names), sorted(dev & names)


def parse_lockfile(path: str, text: str):
    """Dispatch a lockfile by filename, falling back to content sniffing.
    Returns [(name, is_dev_only)]. Raises ValueError on unknown formats."""
    base = os.path.basename(path).lower()
    if base.endswith(".json"):
        return parse_package_lock_entries(json.loads(text))
    if base == "yarn.lock":
        return [(n, False) for n in parse_yarn_lock(text)[0]]
    if base == "pnpm-lock.yaml":
        return [(n, n in set(parse_pnpm_lock(text)[1])) for n in parse_pnpm_lock(text)[0]]
    head = text.lstrip()[:400]
    if head.startswith("{"):
        return parse_package_lock_entries(json.loads(text))
    if "yarn lockfile" in head or head.startswith("# THIS IS AN AUTOGENERATED FILE"):
        return [(n, False) for n in parse_yarn_lock(text)[0]]
    if head.startswith("lockfileVersion:"):
        return [(n, n in set(parse_pnpm_lock(text)[1])) for n in parse_pnpm_lock(text)[0]]
    raise ValueError("unrecognized lockfile format (tried package-lock.json, yarn.lock, pnpm-lock.yaml)")


def parse_requirements_line(line: str):
    """Parse one requirements.txt line into a bare package name (or None).

    Ignores comments, blank lines, options (-r/--index-url/...), editable
    installs, VCS/URL deps, environment markers and extras.
    """
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return None
    if "://" in line:  # VCS or direct-URL dep - not vettable by name
        return None
    line = line.split(";", 1)[0]      # environment marker
    line = line.split("[", 1)[0]      # extras
    for op in ("~", "<", ">", "=", "!"):  # version specifier (~= first: ~= contains =)
        idx = line.find(op)
        if idx > 0:
            line = line[:idx]
            break
    return line.strip() or None


def parse_requirements(lines):
    """Parse requirements.txt content (iterable of lines) into names."""
    out = []
    for line in lines:
        name = parse_requirements_line(line)
        if name:
            out.append(name)
    return sorted(set(out))


def load_allowlist(path: str):
    """Load a .depvetrc.json-style allowlist: {"allow": {"name": "reason"}}.

    Returns dict (possibly empty), or None if the file exists but is broken.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return None
    allow = doc.get("allow") if isinstance(doc, dict) else None
    if not isinstance(allow, dict):
        return {}
    return {str(k).lower(): str(v or "reviewed") for k, v in allow.items()}


def apply_allowlist(results, allow):
    """Downgrade WARN -> PASS for allowlisted packages (reason recorded).

    BLOCK and ERROR are never downgraded: an allowlist documents trust, it
    does not override evidence of a typosquat or a dangerous install script.
    """
    if not allow:
        return results
    for r in results:
        reason = allow.get(r["name"].lower())
        if reason and r["verdict"] == "WARN":
            r["verdict"] = "PASS"
            r.setdefault("notes", []).append(f"WARN suppressed by allowlist ({reason})")
    return results


# --------------------------------------------------------------------------
# Performance layer (see README "Performance"):
#   - bulk npm download counts: one request answers up to BULK_CHUNK names
#   - disk cache: verdicts are reused for --cache-ttl seconds (default 24h)
# Both are best-effort: on any failure the slower per-name path takes over.
# --------------------------------------------------------------------------

def bulk_chunks(names, size=BULK_CHUNK):
    names = list(names)
    return [names[i:i + size] for i in range(0, len(names), size)]


def parse_bulk_downloads(doc, chunk):
    """Map a bulk downloads response to {name: weekly|None}.

    npm answers {"<name>": {"downloads": N}} per entry; a name the registry
    does not know comes back as null. None means "unknown" and the caller
    falls back to a per-name query - None is never trusted as a real count
    (that could mask an established package and flip a verdict)."""
    out = {}
    for n in chunk:
        entry = doc.get(n) if isinstance(doc, dict) else None
        if isinstance(entry, dict) and isinstance(entry.get("downloads"), int):
            out[n] = entry["downloads"]
        else:
            out[n] = None
    return out


def fetch_weekly_bulk(names):
    out = {}
    for chunk in bulk_chunks(names):
        url = "{}/{}".format(NPM_DOWNLOADS,
                             ",".join(urllib.parse.quote(n, safe="") for n in chunk))
        doc, err = http_get_json(url)
        if err or not isinstance(doc, dict):
            continue  # per-name fallback inside check_npm covers these
        out.update(parse_bulk_downloads(doc, chunk))
    return out


def _cache_dir():
    return os.environ.get("DEPVET_CACHE_DIR") or os.path.join(
        os.path.expanduser("~"), ".depvet-cache")


def _cache_path(reg: str, name: str) -> str:
    digest = hashlib.sha1("{}:{}".format(reg, name).lower().encode("utf-8")).hexdigest()
    return os.path.join(_cache_dir(), digest[:2], digest + ".json")


def cache_get(reg: str, name: str, ttl):
    try:
        with open(_cache_path(reg, name), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    ts, row = doc.get("ts"), doc.get("row")
    if not isinstance(ts, (int, float)) or not isinstance(row, dict):
        return None
    if time.time() - ts > ttl:
        return None
    return row


def cache_put(reg: str, name: str, row: dict):
    path = _cache_path(reg, name)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = "{}.{}.{}.tmp".format(path, os.getpid(), threading.get_ident())
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"ts": time.time(), "row": row}, fh)
        os.replace(tmp, path)  # atomic: readers never see a half-written row
    except OSError:
        pass  # read-only home, full disk, ... - the cache is optional


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

    # Weekly downloads: bulk-pre-fetched when available (one request answers
    # up to 128 names), otherwise a per-name query.
    pre = getattr(opts, "weekly_pre", None) or {}
    if isinstance(pre.get(name), int):
        weekly = pre[name]
    else:
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

    # Scoped typosquat: a near-miss of a well-known scope (@acitons vs
    # @actions, Nov 2025 - the @actions/artifact typosquat exfiltrated CI
    # tokens from 47k installs before it was pulled). Warning-tier, gated on
    # low adoption like the name-distance rule above.
    if name.startswith("@") and "/" in name and (weekly is None or weekly < 5000):
        scope = name.split("/", 1)[0].lower()
        if scope not in KNOWN_SCOPES:
            cs = canon(scope)
            best_scope, best_d = None, 99
            for s in KNOWN_SCOPES:
                d = levenshtein(cs, canon(s))
                if d < best_d:
                    best_scope, best_d = s, d
            if best_scope and 1 <= best_d <= 2:
                warnings.append(f"scope '{scope}' is {best_d} edit(s) from popular scope '{best_scope}' - "
                                f"scoped typosquat pattern (cf. @acitons/artifact, Nov 2025)")

    if script_hits:
        for key, why in script_hits:
            flags.append(f"'{key}' install script {why}: {scripts.get(key)[:120]!r}")

    if age_days is not None and age_days < opts.fresh_days and weekly is not None and weekly < 100:
        flags.append(f"package is {age_days} days old with only {weekly} downloads/week - fresh-drop profile")

    if (repo is None or (isinstance(repo, dict) and not repo_url)) and n_maint <= 1 \
            and weekly is not None and weekly < 1000:
        flags.append("no source repository, single maintainer, low adoption - unaccountable provenance")

    deprecated = latest.get("deprecated")
    if deprecated:
        # Deprecated packages stay installable and keep running their install
        # scripts; takedown-squats are often deprecated in place rather than
        # removed (see references/red-flags.md #11).
        warnings.append(f"deprecated on npm: {str(deprecated)[:110]}")

    has_attestations = bool((latest.get("dist") or {}).get("attestations"))
    if has_attestations:
        notes.append("npm provenance attestations present")
    elif age_days is not None and age_days < opts.fresh_days:
        warnings.append("brand-new package without npm provenance attestations")

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

    latest_ver = info.get("version")
    latest_files = releases.get(latest_ver) or []
    yanked = [f for f in latest_files if f.get("yanked")]
    if latest_files and len(yanked) == len(latest_files):
        warnings.append(f"latest release {latest_ver} is yanked from PyPI")

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


def visible_len(s: str) -> int:
    return len(re.sub(r"\033\[[0-9;]*m", "", s))


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
        # pad every cell to its visible width (strip ANSI before measuring)
        out.append("  ".join(c + " " * (w - visible_len(c)) for c, w in zip(colored, widths)))
        for f in raw.get("flags", []):
            out.append(f"    [BLOCK] {f}")
        for w in raw.get("warnings", []):
            out.append(f"    [WARN]  {w}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(prog="depvet", description="Vet packages before installing them.")
    ap.add_argument("packages", nargs="*", help="package name(s) to vet")
    ap.add_argument("--registry", choices=["npm", "pypi"], default=None,
                    help="defaults to npm for names, pypi for --requirements, npm for --lockfile")
    ap.add_argument("--lockfile", action="append", metavar="FILE",
                    help="vet every dependency in a package-lock.json / yarn.lock / "
                         "pnpm-lock.yaml / npm-shrinkwrap.json (repeatable)")
    ap.add_argument("--production", action="store_true",
                    help="skip dev-only dependencies (package-lock dev flags; pnpm "
                         "devDependencies; no-op for yarn.lock, which marks none)")
    ap.add_argument("--requirements", action="append", metavar="FILE",
                    help="vet every dependency in a requirements*.txt file (repeatable)")
    ap.add_argument("--allow", action="append", metavar="NAME",
                    help="downgrade WARN to PASS for this reviewed package (repeatable; BLOCK is never downgraded)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ap.add_argument("--strict", action="store_true", help="exit non-zero on WARN too")
    ap.add_argument("--fresh-days", type=int, default=21, help="age threshold for 'fresh drop' (default 21)")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                    help="parallel registry lookups (default %(default)s; 1 = sequential)")
    ap.add_argument("--no-cache", action="store_true",
                    help="skip the on-disk verdict cache, query registries fresh")
    ap.add_argument("--cache-ttl", type=int, default=CACHE_TTL_DEFAULT,
                    help="seconds a cached verdict stays valid (default %(default)s = 24h)")
    ap.add_argument("--max-delay", type=float, default=1.0,
                    help="max seconds between lookups in sequential mode (--workers 1)")
    opts = ap.parse_args()

    # ---- collect the vetting jobs: (registry, name) pairs --------------------
    jobs = []          # [(registry, name)], order = input order
    sources = []       # human-readable provenance of the job list

    for path in opts.lockfile or []:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as e:
            print(f"depvet: cannot read lockfile {path}: {e}", file=sys.stderr)
            sys.exit(3)
        try:
            entries = parse_lockfile(path, text)
        except ValueError as e:
            print(f"depvet: cannot parse lockfile {path}: {e}", file=sys.stderr)
            sys.exit(3)
        if not entries:
            print(f"depvet: no dependencies found in {path} (not a recognized lockfile?)", file=sys.stderr)
            sys.exit(3)
        dev_only = split_prod_dev(entries)
        picked = sorted(n for n, is_dev in dev_only.items() if not (opts.production and is_dev))
        skipped = len(dev_only) - len(picked)
        if not picked:
            print(f"depvet: every dependency in {path} is dev-only (--production)", file=sys.stderr)
            sys.exit(3)
        jobs += [("npm", n) for n in picked]
        src = f"{len(picked)} deps from {path}"
        if skipped:
            src += f" ({skipped} dev-only skipped)"
        sources.append(src)

    for path in opts.requirements or []:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                names = parse_requirements(fh)
        except OSError as e:
            print(f"depvet: cannot read requirements file {path}: {e}", file=sys.stderr)
            sys.exit(3)
        if not names:
            print(f"depvet: no dependencies found in {path}", file=sys.stderr)
            sys.exit(3)
        jobs += [("pypi", n) for n in names]
        sources.append(f"{len(names)} deps from {path}")

    for pkg in opts.packages:
        pkg = pkg.strip()
        if not pkg or pkg.startswith("-"):
            continue
        jobs.append((opts.registry or "npm", pkg))
    if not jobs:
        ap.error("give package names, --lockfile FILE, or --requirements FILE")

    # ---- allowlist: .depvetrc.json (cwd) merged with --allow flags -----------
    allow = load_allowlist(".depvetrc.json")
    if allow is None:
        print("depvet: .depvetrc.json exists but is not valid JSON - ignoring it", file=sys.stderr)
        allow = {}
    for name in opts.allow or []:
        allow[name.lower()] = "CLI --allow flag"

    # ---- run ----------------------------------------------------------------
    # Cached verdicts first (zero network), then one bulk downloads request
    # per 128 npm names, then the remaining checks on a small thread pool.
    # `--workers 1` keeps the old sequential, paced behavior.
    use_cache = not opts.no_cache and not os.environ.get("DEPVET_FIXTURES")

    results = [None] * len(jobs)
    pending = []
    for i, (reg, pkg) in enumerate(jobs):
        row = cache_get(reg, pkg, opts.cache_ttl) if use_cache else None
        if row is not None:
            row = dict(row)
            row["registry"] = reg
            results[i] = row
        else:
            pending.append(i)

    if pending:
        if not os.environ.get("DEPVET_FIXTURES"):
            npm_names = sorted({jobs[i][1] for i in pending
                                if jobs[i][0] == "npm" and not jobs[i][1].startswith("@")})
            if len(npm_names) > 1:
                opts.weekly_pre = fetch_weekly_bulk(npm_names)

        def vet(i):
            reg, pkg = jobs[i]
            try:
                r = CHECKERS[reg](pkg, opts)
            except Exception as e:  # noqa: BLE001 - one bad name must not sink the batch
                r = dict(name=pkg, verdict="ERROR", **empty_meta())
                r["notes"] = [f"check failed: {e}"]
            r["registry"] = reg
            if use_cache and r["verdict"] != "ERROR":
                cache_put(reg, pkg, r)
            results[i] = r

        workers = max(1, min(opts.workers, len(pending)))
        if workers > 1:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(vet, pending))
        else:
            for j, i in enumerate(pending):
                if j:
                    time.sleep(min(opts.max_delay, 0.4))
                vet(i)

    results = apply_allowlist(results, allow)
    results.sort(key=lambda r: ORDER.get(r["verdict"], 9))

    if opts.json:
        print(json.dumps({
            "registry": opts.registry or ("npm" if not opts.requirements else "pypi"),
            "sources": sources,
            "results": results,
        }, indent=2))
    else:
        print(render_table(results))
        blocked = [r["name"] for r in results if r["verdict"] == "BLOCK"]
        warned = [r["name"] for r in results if r["verdict"] == "WARN"]
        errors = [r["name"] for r in results if r["verdict"] == "ERROR"]
        print()
        if sources:
            print(f"scanned {len(results)} packages ({'; '.join(sources)})")
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
