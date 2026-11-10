#!/usr/bin/env python3
"""Validate action.yml: YAML parses, and the composite run-step logic works
when simulated locally (fixtures mode, offline). Not a unit test suite -
run alongside test_offline.py in CI."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
failures = []


def check(label, cond):
    print(("  ok  " if cond else "FAIL  ") + label)
    if not cond:
        failures.append(label)


# 1. YAML parses (PyYAML is present on GitHub runners; skip politely if absent)
try:
    import yaml
    with open(os.path.join(ROOT, "action.yml"), "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    check("action.yml is valid YAML", isinstance(doc, dict))
    check("action uses composite runtime", doc.get("runs", {}).get("using") == "composite")
    check("action declares the expected inputs",
          {"lockfile", "requirements", "packages", "registry", "strict"} <= set(doc.get("inputs", {})))
    script = doc["runs"]["steps"][0]["run"]
except ImportError:
    print("  --  PyYAML not available, skipping YAML checks (runners have it)")
    script = None

# 2. Simulate the run step: substitute ${{ inputs.* }}, execute with fixtures
tmp = tempfile.mkdtemp(prefix="depvet-action-")
try:
    # fixtures for one PASS npm package
    meta = {"dist-tags": {"latest": "1.0.0"},
            "time": {"created": "2020-01-01T00:00:00Z", "1.0.0": "2026-11-01T00:00:00Z"},
            "maintainers": [{}, {}],
            "versions": {"1.0.0": {"license": "MIT",
                                   "repository": {"url": "git+https://github.com/x/y.git"},
                                   "scripts": {}}}}
    import hashlib
    def fx(url, body):
        name = hashlib.sha256(url.encode()).hexdigest()[:24] + ".json"
        with open(os.path.join(tmp, name), "w") as fh:
            fh.write(body)
    fx("https://registry.npmjs.org/safe-lib", json.dumps(meta))
    fx("https://api.npmjs.org/downloads/point/last-week/safe-lib", json.dumps({"downloads": 90000}))

    lockpath = os.path.join(tmp, "package-lock.json")
    with open(lockpath, "w") as fh:
        json.dump({"lockfileVersion": 3,
                   "packages": {"": {"name": "app"},
                                "node_modules/safe-lib": {"version": "1.0.0"}}}, fh)

    if script:
        # emulate the GitHub templating, action_path, and workspace
        run = script.replace("${{ github.action_path }}", ROOT)
        run = run.replace("${{ inputs.lockfile }}", lockpath)
        run = run.replace("${{ inputs.requirements }}", "")
        run = run.replace("${{ inputs.packages }}", "safe-lib")
        run = run.replace("${{ inputs.registry }}", "npm")
        run = run.replace("${{ inputs.strict }}", "false")
        path = os.path.join(tmp, "simulated_step.sh")
        with open(path, "w") as fh:
            fh.write(run)
        env = dict(os.environ, DEPVET_FIXTURES=tmp)
        p = subprocess.run(["bash", path], capture_output=True, text=True, env=env,
                           cwd=tmp, timeout=60)
        check("simulated action step exits 0 (all PASS)", p.returncode == 0)
        check("simulated action step scanned lockfile + package",
              "scanned 2 packages" in p.stdout and "safe-lib" in p.stdout)

        # strict=false with a 404 package must exit 2 (BLOCK)
        run2 = script.replace("${{ github.action_path }}", ROOT)
        run2 = run2.replace("${{ inputs.lockfile }}", "")
        run2 = run2.replace("${{ inputs.requirements }}", "")
        run2 = run2.replace("${{ inputs.packages }}", "not-a-package-xyz")
        run2 = run2.replace("${{ inputs.registry }}", "npm")
        run2 = run2.replace("${{ inputs.strict }}", "true")
        path2 = os.path.join(tmp, "simulated_step2.sh")
        with open(path2, "w") as fh:
            fh.write(run2)
        p2 = subprocess.run(["bash", path2], capture_output=True, text=True, env=env,
                            cwd=tmp, timeout=60)
        check("simulated action step fails on BLOCK (exit 2)", p2.returncode == 2)

        # nothing to vet -> ::error:: + exit 1
        run3 = script.replace("${{ github.action_path }}", ROOT)
        for inp in ("lockfile", "requirements", "packages"):
            run3 = run3.replace("${{ inputs.%s }}" % inp, "")
        run3 = run3.replace("${{ inputs.registry }}", "npm")
        run3 = run3.replace("${{ inputs.strict }}", "false")
        path3 = os.path.join(tmp, "simulated_step3.sh")
        with open(path3, "w") as fh:
            fh.write(run3)
        p3 = subprocess.run(["bash", path3], capture_output=True, text=True, env=env,
                            cwd=tmp, timeout=60)
        check("simulated action step errors when nothing to vet", p3.returncode == 1)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print()
if failures:
    print(f"{len(failures)} action check(s) failed:", *failures, sep="\n  - ")
    sys.exit(1)
print("action.yml checks passed")
