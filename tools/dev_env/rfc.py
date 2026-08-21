#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The RFC text a citation claims to quote, read out of docs/learn/RFC and searched here.

docs/learn/RFC/README.md calls that directory the law and says what to do with it: "Read the section,
do not recall it." This is that instruction with an interface. Nearly every comment in src/ and test/
cites an RFC and most of them quote it, and a quote written from memory reads exactly like one that
was checked - it carries the authority of the document without the document having said it. A suite
is worse again, because a case named after a sentence is asserting that sentence, and if the sentence
is not in the document the case is asserting something nobody wrote.

The 101 documents in docs/learn/RFC are the source, and a sibling ProtoCore checkout's own set is
read after them when one is there. IDEMIP_RFC_PATH prepends directories. One no path carries is
fetched from the RFC Editor into .rfc-cache, which is ignored - so the tool needs no network for any
RFC the library actually cites, and CI can run the audit offline.

    python tools/dev_env/rfc.py 768                          the whole document
    python tools/dev_env/rfc.py 8415 --section 18.2.10.1     one section, by its number
    python tools/dev_env/rfc.py 1122 --grep "Timestamp"      every line that matches, with context
    python tools/dev_env/rfc.py 1122 --quote "A host MAY implement Timestamp and Timestamp Reply"

--quote is the one to reach for while writing a case: it answers whether the sentence is in the
document, in those words, and prints where. Line breaks, page breaks and the running headers between
them are folded away first, so a quote that spans two lines still matches.

--audit walks the tree instead of one quote: every quoted string in a comment is checked against the
RFC named nearest before it, and anything that does not appear is printed with the file and line.
Nearest-before, because a block here cites three or four documents and quotes each in turn. Exits
nonzero when a quote does not hold, so it can be run as a gate.

    python tools/dev_env/rfc.py --audit
    python tools/dev_env/rfc.py --audit src/dhcp

A quote the audit cannot find is not always wrong: an RFC quoting another RFC, a phrase assembled
from two sentences, a word this file's own prose put in quotes. It is always worth reading, which is
why the report prints the text rather than a count.
"""
import argparse
import os
import re
import sys
import urllib.error
import urllib.request

ROOT = os.getcwd()
CACHE = os.path.join(ROOT, ".rfc-cache")


def law():
    """Where a vendored RFC is looked for, nearest copy first.

    docs/learn/RFC is this tree's own and answers every RFC the library cites. ProtoCore carries a
    larger set beside it and a checkout that has one is worth reading; a checkout that does not is
    not an error, because the fall-through is the RFC Editor. IDEMIP_RFC_PATH prepends directories
    for a layout neither guess covers.
    """
    out = [os.path.join(ROOT, "docs", "learn", "RFC")]
    env = os.environ.get("IDEMIP_RFC_PATH", "")
    out = [d for d in env.split(os.pathsep) if d] + out
    out.append(os.path.join(ROOT, os.pardir, os.pardir, "ProtoCore", "docs", "learn", "rfc", "text"))
    return [d for d in out if os.path.isdir(d)]
URL = "https://www.rfc-editor.org/rfc/rfc{n}.txt"
TIMEOUT = 30

# A page break, the running footer above it and the running header below it. All three are furniture
# the document's own text does not include, and a quote that spans a page boundary has to step over
# them to match.
PAGE = re.compile(r"\n?\f\n?")
FOOTER = re.compile(r"^.*\[Page \d+\]\s*$", re.M)
HEADER = re.compile(r"^RFC \d+\s+.*\d{4}\s*$", re.M)

# "RFC 8415", "RFC1122", and the sec 18.2.10.1 form this tree writes beside them.
RFC_REF = re.compile(r"\bRFC\s?(\d{3,5})\b")

# A quoted run long enough to be a sentence and not a field name. Matched against the block after it
# has been folded to one line, because this tree wraps a quotation across as many comment lines as it
# needs and a per-line match pairs the wrong quotes: the open quote of one sentence with the close
# quote of the next, which reports prose nobody claimed an RFC said.
QUOTED = re.compile(r'"([^"]{16,})"')


def read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def fetch(number):
    """The text of one RFC: the vendored copy, then the cache, then the RFC Editor."""
    for d in law():
        for name in ("rfc%s.txt" % number, "rfc%s.txt" % str(number).zfill(4)):
            local = os.path.join(d, name)
            if os.path.exists(local):
                return read(local)
    if not os.path.isdir(CACHE):
        os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, "rfc%s.txt" % number)
    if os.path.exists(path):
        return read(path)
    req = urllib.request.Request(
        URL.format(n=number),
        headers={"User-Agent": "idemIP-rfc-tool (+https://github.com/dstroy0/idemIP)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise SystemExit("RFC %s: the RFC Editor answered %s" % (number, e.code))
    except Exception as e:  # noqa: BLE001 - a name, a timeout and a refused connection read the same here
        raise SystemExit("RFC %s: %s, and no directory on the RFC path carries it" % (number, e))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return body


def flatten(text):
    """One line, one space between words, no page furniture. What a quote is matched against."""
    text = FOOTER.sub("", text)
    text = PAGE.sub("\n", text)
    text = HEADER.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def normalize(quote):
    """The same folding, applied to what the caller is asking about."""
    return re.sub(r"\s+", " ", quote).strip()


def contains(flat, quote):
    """Where @p flat says @p quote, or -1.

    An elision is a quotation too. This tree writes "A ... B" for a sentence it has taken the middle
    out of, and the claim that makes is that A appears, and that B appears after it - not that the
    document holds the string with the dots in. So the parts are matched in order, and a part too
    short to be a claim is skipped rather than searched for: "..." next to a comma finds anything.
    """
    parts = [normalize(x) for x in re.split(r"\.\.\.+|\u2026", quote)]
    parts = [x.strip(" ,;:") for x in parts]
    parts = [x for x in parts if len(x) >= 8]
    if not parts:
        return -1
    first = flat.find(parts[0])
    at = first
    for part in parts[1:]:
        if at < 0:
            return -1
        at = flat.find(part, at)
    return first if at >= 0 else -1


def line_of(text, flat_index):
    """Which line of the original text a flattened offset lands in. Approximate by construction:
    the folding drops furniture, so this walks the original counting non-space characters."""
    want = len(re.sub(r"\s", "", flatten(text)[:flat_index]))
    seen = 0
    for n, line in enumerate(text.splitlines(), 1):
        seen += len(re.sub(r"\s", "", line))
        if seen >= want:
            return n
    return 0


def cmd_section(text, number, section):
    """One numbered section, from its heading to the next heading at or above its level."""
    depth = section.count(".") + 1
    start = re.compile(r"^\s{0,3}%s\.?\s+\S" % re.escape(section), re.M)
    m = start.search(text)
    if not m:
        raise SystemExit("RFC %s: no section %s" % (number, section))
    rest = text[m.start() :]
    nxt = None
    for cand in re.finditer(r"^\s{0,3}(\d+(?:\.\d+)*)\.?\s+\S", rest[1:], re.M):
        if cand.group(1) == section:
            continue
        if cand.group(1).count(".") + 1 <= depth:
            nxt = cand.start() + 1
            break
    body = rest[:nxt] if nxt else rest
    sys.stdout.write(FOOTER.sub("", PAGE.sub("\n", body)).rstrip() + "\n")
    return 0


def cmd_grep(text, pattern, context):
    """Every line that matches, numbered, with @p context lines either side."""
    rx = re.compile(pattern, re.I)
    lines = text.splitlines()
    hits = [n for n, line in enumerate(lines) if rx.search(line)]
    if not hits:
        print("no line matches %r" % pattern)
        return 1
    shown = set()
    for n in hits:
        for i in range(max(0, n - context), min(len(lines), n + context + 1)):
            if i not in shown:
                shown.add(i)
                print("%5d %s" % (i + 1, lines[i].rstrip()))
        print("")
    return 0


def cmd_quote(text, number, quote):
    """Whether the document says it, in those words."""
    flat = flatten(text)
    want = normalize(quote)
    at = contains(flat, want)
    if at < 0:
        print("RFC %s does NOT contain:" % number)
        print("  %s" % want)
        # The longest leading run that IS there, which is where the wording parts company.
        lo, hi = 0, len(want)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if flat.find(want[:mid]) >= 0:
                lo = mid
            else:
                hi = mid - 1
        if lo >= 16:
            print("  it holds up to: %s" % want[:lo])
            print("  and the document reads: ...%s" % flat[flat.find(want[:lo]) : flat.find(want[:lo]) + lo + 60])
        return 1
    print("RFC %s, around line %d:" % (number, line_of(text, at)))
    print("  %s" % flat[max(0, at - 60) : at + len(want) + 60].strip())
    return 0


def comment_blocks(path):
    """(first_line, text) for each run of adjacent comment lines. // and /* */ alike, because this
    tree writes both and a block is a paragraph either way."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    blocks = []
    cur, start, in_c = [], 0, False
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        is_comment = in_c or line.startswith("//") or line.startswith("/*") or line.startswith("*")
        if line.startswith("/*") and "*/" not in line:
            in_c = True
        if in_c and "*/" in line:
            in_c = False
        if is_comment:
            if not cur:
                start = n
            cur.append(re.sub(r"^\s*(//+|/\*+|\*+/?)\s?", "", raw))
        elif cur:
            blocks.append((start, "\n".join(cur)))
            cur = []
    if cur:
        blocks.append((start, "\n".join(cur)))
    return blocks


def cmd_audit(paths):
    """Every comment block that names exactly one RFC, with its quotes checked against it."""
    roots = paths or ["src", "test"]
    files = []
    for root in roots:
        if os.path.isfile(root):
            files.append(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {"__pycache__", "vendor", "MMgr"}]
            for name in sorted(filenames):
                if name.endswith((".c", ".h")):
                    files.append(os.path.join(dirpath, name))

    flats = {}
    checked = skipped = 0
    bad = []
    for path in sorted(files):
        for start, block in comment_blocks(path):
            flat_block = normalize(block)
            marks = [(m.start(), m.group(1)) for m in RFC_REF.finditer(flat_block)]
            if not marks:
                skipped += len([q for q in QUOTED.findall(flat_block) if " " in q])
                continue
            for m in QUOTED.finditer(flat_block):
                q = m.group(1)
                if " " not in q:
                    continue
                # The RFC named nearest before the quote owns it. A block here routinely cites three
                # or four documents and quotes each in turn - "RFC 1213 udpInErrors is ..." after a
                # sentence about RFC 768 - so taking the block's one RFC would either skip the block
                # or blame the wrong document for every quote in it.
                number = None
                for at, ref in marks:
                    if at < m.start():
                        number = ref
                    else:
                        break
                if number is None:
                    skipped += 1
                    continue
                if number not in flats:
                    flats[number] = flatten(fetch(number))
                checked += 1
                if contains(flats[number], normalize(q)) < 0:
                    bad.append((path, start, number, normalize(q)))

    for path, line, number, q in bad:
        print("%s:%d: RFC %s does not contain" % (path.replace(os.sep, "/"), line, number))
        print('    "%s"' % q)
    print("")
    print("%d quotes checked against %d RFCs, %d not found" % (checked, len(flats), len(bad)))
    if skipped:
        print("%d quotes with no RFC named before them, not checked" % skipped)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description="RFC text, and the quotes this tree takes from it")
    ap.add_argument("number", nargs="?", help="RFC number")
    ap.add_argument("--section", help="print one numbered section")
    ap.add_argument("--grep", help="print every line matching this regex")
    ap.add_argument("--context", type=int, default=2, help="lines either side of a --grep hit")
    ap.add_argument("--quote", help="check the document says this, in these words")
    ap.add_argument("--audit", nargs="*", help="check every quote in the tree, or under these paths")
    args = ap.parse_args()

    if args.audit is not None:
        return cmd_audit(args.audit)
    if not args.number:
        ap.error("an RFC number, or --audit")

    text = fetch(args.number)
    if args.section:
        return cmd_section(text, args.number, args.section)
    if args.grep:
        return cmd_grep(text, args.grep, args.context)
    if args.quote:
        return cmd_quote(text, args.number, args.quote)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
