#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Two things a header can say that only the full build, or no build at all, would contradict.

THE INITIALIZER CHECK. A namespace header declares its entries twice: once as members of an XNs
struct, and once as an aggregate initializer over that struct. When a capability guards a member
with #if and the initializer names it unconditionally, the pair compiles in the full build and only
in the full build - the reduced build reports "XNs has no member named ...", which is a name the
reader can see declared four lines above.

That is not hypothetical: netif, loopif and dispatch each carried one, and the whole reduced-build
space was unbuildable because of it while every suite passed.

THE FRONT-DOOR CHECK. src/idemip.h is "the one header an application includes: every unit's
namespace, borrow map and constant", and nothing in the library includes it, so an omission is not
a build error anywhere - it is a unit the caller cannot reach and no compiler will say so. dispatch
and tick were both missing while IDEMIP_TOTAL_BORROW counted both borrows, so the front door sized
two units it would not let the caller call. Every header defining a namespace table has to be named
in idemip.h's include closure, capability gate or no: a header behind an #if that is off still has
to be NAMED, because whether it contributes anything is that header's own business.

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

# Anchored at the start of a line so the worked example inside idemip.h's own doc comment, whose
# lines begin " *   #include", is read as prose and not as an include.
INCLUDE = re.compile(r"^\s*#\s*include\s+\"(src/[\w/]+\.h)\"", re.M)

FRONT_DOOR = "src/idemip.h"


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


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def headers():
    """Every header under src/, repo-relative and forward-slashed, in a stable order."""
    out = []
    for dirpath, _, names in os.walk(os.path.join(ROOT, "src")):
        for name in sorted(names):
            if name.endswith(".h"):
                path = os.path.join(dirpath, name)
                out.append(os.path.relpath(path, ROOT).replace(os.sep, "/"))
    return sorted(out)


def check_initializers(rel, text):
    """Members the struct guards and the table sets anyway. Returns how many."""
    bad = 0
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
                print(f"{rel}:{line}: {tag}.{field} is guarded in the struct and set unguarded")
                bad += 1
    return bad


def closure(rel):
    """Every header idemip.h names, directly or through one it names. #if is not consulted."""
    seen, stack = set(), [rel]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        try:
            text = read(cur)
        except OSError:
            continue
        stack.extend(m.group(1) for m in INCLUDE.finditer(text))
    return seen


def check_front_door(exporters):
    """Namespace headers the front door does not name. Returns how many."""
    reachable = closure(FRONT_DOOR)
    missing = [rel for rel in exporters if rel not in reachable]
    for rel in missing:
        print(f"{FRONT_DOOR}: does not include {rel}, which exports a namespace")
    return len(missing)


def main():
    bad = 0
    exporters = []
    for rel in headers():
        text = read(rel)
        bad += check_initializers(rel, text)
        if TABLE.search(text):
            exporters.append(rel)

    front = check_front_door(exporters)

    if bad:
        print(f"\n{bad} initializer(s) name a member their own #if can remove")
    if front:
        print(f"\n{front} namespace(s) are unreachable from {FRONT_DOOR}")
    if bad or front:
        return 1
    print(f"every namespace table matches its struct, and {FRONT_DOOR} names all {len(exporters)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
