#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every namespace table whose struct is conditional and whose initializer is not.

A namespace header declares its entries twice: once as members of an XNs struct, and once as an
aggregate initializer over that struct. When a capability guards a member with #if and the
initializer names it unconditionally, the pair compiles in the full build and only in the full
build - the reduced build reports "XNs has no member named ...", which is a name the reader can see
declared four lines above.

That is not hypothetical: netif, loopif and dispatch each carried one, and the whole reduced-build
space was unbuildable because of it while every suite passed.

This reads the headers rather than building them, so it answers in a second where the capability
matrix takes minutes. It is the static half; the matrix is the other half, and neither replaces the
other - this cannot see a .c that names a guarded type, and the matrix cannot say which line.

    python tools/dev_env/guards.py

Exits nonzero when it finds one, so CI can run it as a gate.
"""
import os
import re
import sys

ROOT = os.getcwd()

# A namespace struct is the anonymous typedef that ends in an XNs tag, and the table is the one
# static const of that type. Both are matched over the whole file, so a header carrying two
# namespaces is read as two.
STRUCT = re.compile(r"typedef struct\s*\{(.*?)\}\s*(\w+Ns);", re.S)
TABLE = re.compile(r"static const (\w+Ns) \w+ IDEMIP_UNUSED = \{(.*?)\};", re.S)
MEMBER = re.compile(r"\(\*const (\w+)\)")
SETS = re.compile(r"\.(\w+)\s*=")


def guarded_spans(body):
    """The [start, end) ranges of body that sit inside any #if / #endif, however nested."""
    spans, stack = [], []
    for m in re.finditer(r"^\s*#\s*(if\w*|endif)\b", body, re.M):
        if m.group(1) == "endif":
            if stack:
                spans.append((stack.pop(), m.start()))
        else:
            stack.append(m.start())
    return spans


def inside(spans, pos):
    return any(a <= pos < b for a, b in spans)


def main():
    bad = 0
    for dirpath, _, names in os.walk(os.path.join(ROOT, "src")):
        for name in sorted(names):
            if not name.endswith(".h"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as f:
                text = f.read()

            structs = {}
            for m in STRUCT.finditer(text):
                body, tag = m.group(1), m.group(2)
                spans = guarded_spans(body)
                structs[tag] = {mm.group(1): inside(spans, mm.start()) for mm in MEMBER.finditer(body)}

            for m in TABLE.finditer(text):
                tag, body = m.group(1), m.group(2)
                if tag not in structs:
                    continue
                spans = guarded_spans(body)
                for mm in SETS.finditer(body):
                    field = mm.group(1)
                    if structs[tag].get(field) and not inside(spans, mm.start()):
                        line = text[: m.start(2) + mm.start()].count("\n") + 1
                        rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
                        print(f"{rel}:{line}: {tag}.{field} is guarded in the struct and set unguarded")
                        bad += 1

    if bad:
        print(f"\n{bad} initializer(s) name a member their own #if can remove")
        return 1
    print("every namespace table matches the struct it initialises")
    return 0


if __name__ == "__main__":
    sys.exit(main())
