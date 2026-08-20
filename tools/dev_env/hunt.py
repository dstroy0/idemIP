#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hunt for shapes worth looking at: the ones that are wrong, and the ones that are slow.

  hunt.py            [PATH ...]   every rule
  hunt.py correct    [PATH ...]   only the rules about what the code does
  hunt.py fast       [PATH ...]   only the rules about what it costs
  hunt.py <rule-id>  [PATH ...]   one rule
  hunt.py rules                   what each rule looks for, and why

A hit is a CANDIDATE and never a defect. Each rule states the invariant it is checking, and a site
that trips one still has to be read against the RFC or the measurement before anything is changed.
The point is to reduce 106 files to a list short enough to read.

Matching is over the token stream dedup.py already builds - comments stripped by readclean's
literal-aware pass, directives kept apart - so a rule cannot fire on prose, on a string literal, or
on a line that only names the thing it is looking for. A pattern is written as a list of tokens, so
`(` is a token and not a regex group, and these four stand for a class rather than a literal:

  %ID%     one identifier
  %VAR%    one identifier that is not ALL_CAPS, so a value rather than a macro constant
  %NUM%    one integer constant
  %ANY%    one token, whatever it is
  %GAP%    zero to twelve tokens, lazily

%VAR% is what makes the correctness rules readable. This tree spells every compile-time constant
ALL_CAPS, so `<< IDEMIP_ARP_ENTRY_SHIFT` is a constant shift and `<< n` is not, and a rule that
cannot tell them apart reports 286 sites of which none is a candidate.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dedup import load, sources, rel, ROOT

CLASS = {
    "%ID%": r"[A-Za-z_][A-Za-z_0-9]*",
    "%VAR%": r"(?![A-Z_0-9]+(?![A-Za-z_0-9]))[A-Za-z_][A-Za-z_0-9]*",
    "%NUM%": r"(?:0[xX][0-9A-Fa-f]+[uUlL]*|[0-9]+[uUlL]*)",
    "%ANY%": r"\S+",
    "%GAP%": r"(?:\S+ ){0,12}?",
    # A run inside one argument: it may not cross a comma into the next, or a paren out of the call.
    "%ARG%": r"(?:(?![,;()])\S+ ){0,12}?",
}

# id, class, what it looks for, and the invariant that makes a hit worth reading.
RULES = [
    (
        "div-const",
        "fast",
        ["/", "%NUM%"],
        "A divide by a constant. The house rule is shift and mask before divide and modulo: a "
        "power-of-two divisor is a shift, and a part without a divider pays for the rest in a call.",
    ),
    (
        "mod-const",
        "fast",
        ["%", "%NUM%"],
        "A modulo by a constant. A power-of-two modulus is a mask.",
    ),
    (
        "div-var",
        "fast",
        ["/", "%VAR%"],
        "A divide by a value. Unavoidable in general, but on a per-packet path it is worth knowing "
        "the divisor's range: if it is a power of two the shift is a variable shift, not a divide.",
    ),
    (
        "memcmp",
        "fast",
        ["memcmp", "("],
        "memcmp where the result is only tested against zero is an equality test, which "
        "idemip_bytes_eq does a word at a time. Every one of the twenty-seven in this tree was "
        "already converted; a new one is a regression.",
    ),
    (
        "byte-loop",
        "fast",
        ["for", "(", "%GAP%", ";", "%GAP%", "<", "%GAP%", ";", "%GAP%", "++", ")", "{", "%GAP%", "[", "%ID%", "]"],
        "A loop that indexes a buffer one octet at a time. Over a span whose width is known - an "
        "address, a prefix, a header - a word at a time is the same answer for a fraction of the "
        "work, which is what common.h's span helpers do.",
    ),
    (
        "seq-read",
        "fast",
        ["idemip_rd16", "(", "%GAP%", ")", "%GAP%", "idemip_rd16", "("],
        "Two adjacent 16-bit reads. If the offsets are consecutive one 32-bit read covers both.",
    ),
    (
        "shift-var",
        "correct",
        ["<<", "%VAR%"],
        "A shift by a value rather than a constant. C11 sec 6.5.7p3 makes a shift undefined when the "
        "right operand is negative or at least the width of the promoted left operand, so the range "
        "of that value has to be bounded by something the reader can see.",
    ),
    (
        "memcpy-var",
        "correct",
        ["memcpy", "(", "%ARG%", ",", "%ARG%", ",", "%VAR%", ")"],
        "A copy whose length is a value rather than a constant or a sizeof. The bound that keeps it "
        "inside the destination has to be established before the call, on every path that reaches it.",
    ),
    (
        "assign-in-if",
        "correct",
        ["if", "(", "%VAR%", "="],
        "An assignment where a comparison is the usual intent. If it is deliberate the value is being "
        "both stored and tested, which is worth saying out loud.",
    ),
    (
        "banned-stdlib",
        "correct",
        ["%BANNED%", "("],
        "Library code takes no stdlib beyond the freestanding headers. A call here either has a "
        "hosted dependency the target may not have, or allocates, or reads a locale.",
    ),
    (
        "auto-keyword",
        "correct",
        ["auto", "%ID%"],
        "`auto` is banned in src/: a type that is not written down is a type the reader has to infer, "
        "and the widths here are the wire's.",
    ),
]

BANNED = (
    "malloc calloc realloc free strlen strcpy strncpy strcat strcmp strncmp sprintf snprintf printf "
    "fprintf sscanf atoi atol strtol abs labs rand srand qsort bsearch time clock exit abort assert"
).split()


def compile_pattern(spec):
    out = []
    for tok in spec:
        if tok == "%BANNED%":
            out.append("(?:" + "|".join(BANNED) + ")")
        elif tok in CLASS:
            out.append(CLASS[tok])
        else:
            out.append(re.escape(tok))
    # %GAP% and %ARG% carry their own trailing space; everything else is one token followed by one.
    parts = []
    for tok, rx in zip(spec, out):
        parts.append(rx if tok in ("%GAP%", "%ARG%") else rx + " ")
    # The stream is space-joined, so a match must start where a token starts. Without this, `assert`
    # matches the tail of `static_assert` and every compile-time assertion in the tree is a hit.
    return re.compile(r"(?<![^ ])" + "".join(parts))


def stream(tokens):
    """The tokens as one space-joined string, plus where each token starts in it."""
    at, starts = 0, []
    for t in tokens:
        starts.append(at)
        at += len(t[1]) + 1
    return " ".join(t[1] for t in tokens) + " ", starts


def token_at(starts, pos):
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo


def run(rule, files):
    rid, cls, spec, why = rule
    rx = compile_pattern(spec)
    hits = []
    for p in files:
        code, directives = load(p)
        for tokens in [code] + [d for _, d in directives]:
            if not tokens:
                continue
            text, starts = stream(tokens)
            for m in rx.finditer(text):
                i = token_at(starts, m.start())
                hits.append((rel(p), tokens[i][2], m.group().strip()))
    return hits


def main():
    args = sys.argv[1:]
    ids = {r[0] for r in RULES}
    if args and args[0] == "rules":
        for rid, cls, spec, why in RULES:
            print("%-14s %-8s %s" % (rid, cls, " ".join(spec)))
            print("               %s\n" % why)
        return 0

    sel = args[0] if args and (args[0] in ("correct", "fast") or args[0] in ids) else None
    paths = [a for a in args if a != sel] or ["src"]
    files = list(sources(paths, ["build", ".git", "__pycache__", "docs/learn"]))

    chosen = [r for r in RULES if sel is None or r[0] == sel or r[1] == sel]
    total = 0
    for rule in chosen:
        hits = run(rule, files)
        total += len(hits)
        print("\n=== %s  (%s)  %d hits" % (rule[0], rule[1], len(hits)))
        print("    %s" % rule[3])
        for f, ln, txt in hits[:40]:
            print("    %s:%d  %s" % (f, ln, txt if len(txt) < 90 else txt[:87] + "..."))
        if len(hits) > 40:
            print("    ... and %d more" % (len(hits) - 40))
    print("\n%d files, %d rules, %d candidates" % (len(files), len(chosen), total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
