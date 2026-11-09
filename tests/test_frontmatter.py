#!/usr/bin/env python3
"""Validate that skills/depvet/SKILL.md carries valid Agent Skills frontmatter."""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.join(HERE, "..", "skills", "depvet", "SKILL.md")
md = open(SKILL, encoding="utf-8").read()

m = re.match(r"^---\n(.*?)\n---\n", md, re.DOTALL)
assert m, "SKILL.md must start with YAML frontmatter"
fm = m.group(1)
assert re.search(r"^name:\s*depvet\s*$", fm, re.M), "missing name: depvet"
assert re.search(r"^description:\s*>", fm, re.M), "missing description block"
assert "typosquat" in fm and "slopsquat" in fm, "trigger words missing from description"
body = md[m.end():]
assert "Step 1" in body and "BLOCK" in body, "protocol body incomplete"
print("SKILL.md frontmatter + body OK")
