#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Two reading passes over a module. Writes nothing.

  code <module.h> ...     comments stripped: the structure, with nothing to take on trust
  claims <module.h> ...   every comment paired with the code it sits above, so the prose can be
                          checked against what the code does rather than read as if it were true

Uses strip_comments.rewrite - the literal-aware one already in the tree - not a regex: `//.*$`
truncates "http://x", and /\*.*?\*/ eats a "/*" inside a string literal. `rewrite` also keeps the
licence block, which `strip` alone removes; reading its output as the file made two crypto modules
look like they had no copyright header at all.
"""
import io, os, re, sys

ROOT = os.getcwd()
sys.path.insert(0, os.path.join(ROOT, "tools", "dev_env"))
from strip_comments import rewrite
from codemask import code_mask


def paths(rel):
    """A module header pairs with its .c; anything else (a test .c, a suite dir) stands alone."""
    p = os.path.join(ROOT, rel.replace("/", os.sep))
    if os.path.isdir(p):
        return sorted(
            os.path.join(p, n) for n in os.listdir(p) if n.endswith((".c", ".h")) and n != "unity_runner.c"
        )
    if rel.endswith(".h"):
        return [x for x in (p, p[:-2] + ".c") if os.path.exists(x)]
    return [p] if os.path.exists(p) else []


def show_code(p):
    """EVERY comment goes, the licence and @file block included.

    Not a formality: a doc block states what the code is meant to do, and reading it first is how a
    conformity pass ends up confirming the prose instead of the code. The claims pass exists to meet
    the prose separately, AFTER the structure has been read on its own terms.
    """
    text = io.open(p, encoding="utf-8").read()
    keep = [ln.rstrip() for ln in rewrite(text, False).splitlines() if ln.strip()]
    print("\n" + "=" * 90 + "\n### " + os.path.relpath(p, ROOT).replace("\\", "/") + "\n" + "=" * 90)
    print("\n".join(keep))


def show_claims(p):
    """Every comment, with the code line it introduces, so a claim can be met with its subject."""
    text = io.open(p, encoding="utf-8").read()
    m = code_mask(text)
    lines = text.splitlines()
    print("\n" + "=" * 90 + "\n### " + os.path.relpath(p, ROOT).replace("\\", "/") + "\n" + "=" * 90)
    i, n = 0, len(text)
    while i < n:
        if m[i] or text[i] in " \t\r\n" or text[i] in "\"'":
            i += 1
            continue
        j = i
        while j < n and not m[j]:
            j += 1
        block = text[i:j].strip()
        if block.startswith(("//", "/*")) and len(block) > 4:
            ln = text.count("\n", 0, i) + 1
            end = text.count("\n", 0, j) + 1
            # the first code line after the comment: what the claim is about
            subject = ""
            for k in range(end - 1, min(end + 3, len(lines))):
                if k < len(lines) and lines[k].strip():
                    subject = lines[k].strip()
                    break
            print("\n[%d] %s" % (ln, block))
            if subject:
                print("     -> %s" % subject)
        i = j


def main():
    args = sys.argv[1:]
    mode = args[0] if args and args[0] in ("code", "claims") else "code"
    rels = [a for a in args if a not in ("code", "claims")]
    show = show_code if mode == "code" else show_claims
    for rel in rels:
        for p in paths(rel):
            show(p)


main()
