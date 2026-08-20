#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fields a unit writes into its borrow and never reads back.

A unit's context and its table rows are private to its .c: nothing outside that file can name them.
So a field only that file writes, and that file never reads, is state nobody asks - and when it came
from a published operand it is worse than dead, because the caller was asked for a value, had it
validated, and then watched it decide nothing.

Both of those have been real here. loopif took an MTU, refused a zero and refused one above
IDEMIP_ETH_MAX_PAYLOAD, stored it, and bounded no frame with it. tcp_pcb took a listen backlog,
stored it beside an accepts_pending nothing ever incremented, and let one listener hold every
connection in the build. Neither showed up as a warning, a test failure or a capability-matrix
break: the code compiles, the suites pass, and the field reads back whatever it was written.

WHAT COUNTS AS BORROW STATE. Only the structs the file reaches through the borrow, which in this
tree is always the same cast: (Tag *)(void *)((w) + OFFSET). A parse result or a lookup result
returned by value is not borrow state and is not read here - it is reached with a dot, and a dot is
not scoped to a type without knowing what the local was declared as. Restricting to the pointer
idiom is what keeps `io->bind_args.mtu` from reading as a use of LoopifCtx::mtu.

A write is an assignment to the field, or the field as the first argument of a memcpy, memset or
memmove. So is a statement that only puts the value back where it came from, because such a
statement asks the field nothing: `x->f = x->f + 1`, `x->f++`, `x->f += n`. A counter kept that way
hides behind its own arithmetic, which is where three of these were found - igmp's and mld6's
membership counts and dma's tally of returned receive descriptors. Anything else that names the
field is a read. Padding is not state and is skipped by name.

    python tools/dev_env/deadstate.py

Exits nonzero when it finds one, so CI can run it as a gate.
"""
import os
import re
import sys

ROOT = os.getcwd()

# Every struct this file defines, by tag.
STRUCT = re.compile(r"typedef struct\s*\{(.*?)\}\s*(\w+);", re.S)
# A member declaration: the last identifier before ; or [.
FIELD = re.compile(r"^\s*[A-Za-z_][\w \t\*]*?\b(\w+)\s*(?:\[[^\]]*\])?\s*;", re.M)

# Names that are storage rather than state, and are meant to be written by nothing at all.
PADDING = {"pad", "padding", "reserved"}


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


UNION = re.compile(r"typedef union\s*\{(.*?)\}\s*(\w+);", re.S)
MEMBER_TYPE = re.compile(r"^\s*(\w+)\s+\w+\s*(?:\[[^\]]*\])?\s*;", re.M)


def borrow_tags(text):
    """Every struct tag this file reaches through the borrow.

    Directly, by the one cast idiom this tree uses for a region - (Tag *)(void *)((w) + OFFSET) - and
    through it, since a row is often a union of a field set and a raw byte array sized to the entry
    width, and the cast then names the union rather than the field set inside it.
    """
    cast = re.compile(r"\(\s*(\w+)\s*\*\s*\)\s*\(\s*void\s*\*\s*\)")
    tags = {m.group(1) for m in cast.finditer(text)}
    for m in UNION.finditer(text):
        if m.group(2) in tags:
            tags |= {mm.group(1) for mm in MEMBER_TYPE.finditer(m.group(1))}
    return tags


# A statement that is nothing but a read-modify-write of one field: `x->f++`, `x->f--`, `x->f += n`.
# The value is read, changed and put straight back, so the field is no more consulted than a plain
# assignment consults it. Only when the RMW IS the whole statement: `y = x->f++` reads it, and so
# does `if (x->f-- > 0)`.
RMW_OP = re.compile(r"(\+=|-=|\*=|/=|%=|\|=|&=|\^=|<<=|>>=)")


def rmw_only(text, pos, field):
    """True when the statement around @p pos is a read-modify-write of `->field` and nothing else."""
    start = max(text.rfind(";", 0, pos), text.rfind("{", 0, pos), text.rfind("}", 0, pos))
    end = text.find(";", pos)
    stmt = text[start + 1 : len(text) if end < 0 else end].strip()
    tail = "->" + field
    if stmt.endswith("++") or stmt.endswith("--"):
        lhs = stmt[:-2].rstrip()
        return "=" not in lhs and lhs.endswith(tail)
    m = RMW_OP.search(stmt)
    if m is None:
        return False
    lhs = stmt[: m.start()].rstrip()
    return "=" not in lhs and lhs.endswith(tail)


def base_of(text, arrow):
    """The identifier immediately left of the `->` at @p arrow, or None if it is not one.

    A macro expansion - IGMP_CTX(work)->groups - ends in a parenthesis rather than a name, and two
    of those are not known to be the same object, so None never matches None.
    """
    m = re.search(r"(\w+)\s*$", text[max(0, arrow - 64) : arrow])
    return m.group(1) if m else None


def uses(text, field):
    """(writes, reads) over every `->field` in the file.

    A read on the right of an assignment to the same field OF THE SAME OBJECT is not a read.
    `ctx->groups = (uint8_t)(ctx->groups + 1u)` names the field twice and consults it exactly as
    much as `ctx->groups = 0u` does: the value goes back where it came from and nothing downstream
    asks. A counter kept that way is the same dead state as a field written once, and it hides
    behind its own increment - which is how igmp's membership count sat here unreported.

    Of the same object, because a field name is not unique to a struct and this searches one file
    for `->field` rather than resolving what the pointer points at. arp_table.c writes
    `io->netif = e->netif`, where the right side is a genuine read of the table row and only the
    NAME is shared with the operand block on the left. Same base identifier or it does not count.
    """
    writes = 0
    reads = 0
    # Every position that is a write, and every position that is only the right-hand side of one.
    write_at = set()
    self_read = set()
    for m in re.finditer(r"->" + re.escape(field) + r"\b", text):
        # Enough lookahead that "==" is still two characters after the spaces are gone: a two-wide
        # window strips " =" out of " == " and reads a comparison as an assignment.
        tail = text[m.end() : m.end() + 8].lstrip()
        if tail.startswith("=") and not tail.startswith("=="):
            write_at.add(m.start())
            lhs = base_of(text, m.start())
            if lhs is None:
                continue
            end = text.find(";", m.end())
            if end < 0:
                end = len(text)
            for r in re.finditer(r"->" + re.escape(field) + r"\b", text[m.end() : end]):
                at = m.end() + r.start()
                if base_of(text, at) == lhs:
                    self_read.add(at)
    for m in re.finditer(r"->" + re.escape(field) + r"\b", text):
        if m.start() in write_at:
            writes += 1
            continue
        if m.start() in self_read:
            continue
        if rmw_only(text, m.start(), field):
            writes += 1
            continue
        # memcpy(x->field, ...) and memset(x->field, ...) write it through their FIRST argument. No
        # comma in between, or the source of a memcpy reads as a write - which is what the RFC 6528
        # secret looked like, laid into the connection-id block as the second argument.
        head = text[max(0, m.start() - 64) : m.start()]
        if re.search(r"\bmem(cpy|set|move)\s*\([^;(),]*$", head):
            writes += 1
            continue
        reads += 1
    return writes, reads


def main():
    findings = 0
    for dirpath, _, names in os.walk(os.path.join(ROOT, "src")):
        for name in sorted(names):
            if not name.endswith(".c"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            with open(path, encoding="utf-8") as f:
                text = strip_comments(f.read())

            reached = borrow_tags(text)
            for m in STRUCT.finditer(text):
                body, tag = m.group(1), m.group(2)
                if tag not in reached:
                    continue
                for fm in FIELD.finditer(body):
                    field = fm.group(1)
                    if field in PADDING:
                        continue
                    writes, reads = uses(text, field)
                    if writes > 0 and reads == 0:
                        print(f"{rel}: {tag}.{field} is written {writes} time(s) and read none")
                        findings += 1

    if findings:
        print(f"\n{findings} field(s) this borrow writes and never reads")
        return 1
    print("every field a unit writes into its borrow is read back by that unit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
