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
    python tools/dev_env/rfc.py --find "each octet is a valid DHCP option code"

--find is the other half of a finding: --audit says a comment's RFC does not hold its quote, and this
says which one does. A sentence attributed to RFC 1542 that RFC 2132 actually carries is a citation to
correct, not a quotation to rewrite.

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
# RFC 1122 and its contemporaries print the running header as "RFC1122 LINK LAYER October 1989",
# with no space after RFC, and one left in the middle of a sentence breaks every quotation that
# spans that page break.
HEADER = re.compile(r"^RFC\s?\d+\s+.*\d{4}\s*$", re.M)

# A reference set into the middle of a sentence: RFC 8200's "not an extension header [IANA-EH]
# indicates", RFC 6528's "MD5 [RFC1321] would be a good choice", RFC 1122's "IP multicasting [IP:4],
# while". It is apparatus and not words - a comment quoting the sentence around it has quoted the
# sentence - so it comes out with the page furniture. The bound keeps it to a marker: a bracket
# holding twenty characters is a citation, one holding a paragraph is prose.
# The parenthesised form of the same thing, which RFC 1122 and RFC 8415 use everywhere: "Destination
# Unreachable (see Section 3.2.2.1)", "the Status Code option (see Section 21.13) returned by the
# server". A comment quoting the sentence has quoted the sentence.
INLINE_REF = re.compile(r"\[[^\]\n]{1,20}\]|\((?:see|See)\s[^)\n]{1,40}\)")

# "RFC 8415", "RFC1122", and the sec 18.2.10.1 form this tree writes beside them.
RFC_REF = re.compile(r"\bRFC\s?(\d{3,5})\b")

# A quoted run long enough to be a sentence and not a field name. Matched against the block after it
# has been folded to one line, because this tree wraps a quotation across as many comment lines as it
# needs and a per-line match pairs the wrong quotes: the open quote of one sentence with the close
# quote of the next, which reports prose nobody claimed an RFC said.
QUOTED = re.compile(r'"([^"]{16,})"')

# A capture that opens on punctuation, or on a lowercase word after one, is the tell of a block whose
# quote marks did not pair the way the writer meant: what got matched is the prose BETWEEN two
# quotations, running from the close mark of one to the open mark of the next. That happens whenever a
# block holds an odd number of marks - an apostrophe written as a double, a quotation opened in one
# comment and closed in another - and after the first one every pairing in the block is off by one.
# Reporting those as misquotes buries the real ones under prose nobody claimed an RFC said.
NOT_A_QUOTATION = re.compile(r'^[,;:.)\]]|^\s')


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


# What a quotation is allowed to differ from the document in and still be the same quotation.
# The tree lowercases a leading capital to set a sentence inside one of its own - RFC 1213's "The
# number of subnetwork-unicast packets delivered" becomes "the number of ..." mid-comment - and it
# writes the document's own inner double quotes as single ones, because the outer pair is already
# taken: RFC 1112's "all-hosts" group is 'all-hosts' by the time it is quoted. Neither changes what
# is being claimed. A dash is folded because the documents are transcribed with several of them.
QUOTE_CHARS = "\u2018\u2019\u201c\u201d`'\""
DASH_CHARS = "\u2010\u2011\u2012\u2013\u2014\u2212"


def fold(text):
    """The form a quotation and the document are compared in. Not for printing: the report prints
    what the comment actually says, so a reader sees the words they wrote."""
    out = []
    for ch in text.lower():
        if ch in QUOTE_CHARS:
            out.append("'")
        elif ch in DASH_CHARS:
            out.append("-")
        else:
            out.append(ch)
    return "".join(out)


def squeeze(text):
    """The form a quotation and a document are compared in, and where each surviving character came
    from in the input.

    Letters and digits only, because everything else is layout. A printed RFC breaks a line wherever
    the column runs out and the break leaves nothing reliable behind: RFC 1213 wraps "re-assembly" as
    "re-" then "assembly" and RFC 4291 wraps "address" as "addr-" then "ess", so one needs the hyphen
    kept and the other needs it dropped and nothing in the text says which. A document that sets a
    list down the page - RFC 9293's "SND.WND <- SEG.WND" and "SND.WL1 <- SEG.SEQ" on their own lines,
    each behind a "+", RFC 2131's message types behind bullets - is quoted in a comment with one line
    to work with, so the breaks come back as commas and the markers do not come back at all.

    A reference set into the middle of a sentence goes too, on both sides: the document's "[IANA-EH]"
    and a comment that kept it are the same sentence, and dropping it from one road only would break
    every quotation that was faithful about it.

    None of that is what the audit is for. It is looking for a word that was bent to fit the sentence
    around it, a subject swapped for a pronoun, a sentence nobody wrote - and every one of those still
    shows, because the words themselves are what is compared. A run of sixteen alphanumerics does not
    match by accident.

    fold() maps one character to one character, so an index into the folded text is an index into the
    input, and the map returned here carries that through the squeeze.
    """
    folded = fold(text)
    skip = set()
    for m in INLINE_REF.finditer(folded):
        skip.update(range(m.start(), m.end()))
    out, idx = [], []
    for i, ch in enumerate(folded):
        if i in skip or not ch.isalnum():
            continue
        out.append(ch)
        idx.append(i)
    return "".join(out), idx


def contains(flat, quote):
    """Where @p flat says @p quote, or -1.

    An elision is a quotation too. This tree writes "A ... B" for a sentence it has taken the middle
    out of, and the claim that makes is that A appears, and that B appears after it - not that the
    document holds the string with the dots in. So the parts are matched in order, and a part too
    short to be a claim is skipped rather than searched for: "..." next to a comma finds anything.
    """
    parts = []
    for raw in re.split(r"\.\.\.+|\u2026", quote):
        part, _ = squeeze(normalize(raw).strip(" ,;:."))
        if len(part) >= 8:
            parts.append(part)
    if not parts:
        return -1
    hay, idx = squeeze(flat)
    first = hay.find(parts[0])
    at = first
    for part in parts[1:]:
        if at < 0:
            return -1
        at = hay.find(part, at)
    return idx[first] if (at >= 0 and first >= 0) else -1


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


def cmd_find(quote):
    """Which vendored RFC says it. The answer to what --audit and --quote only ever ask half of.

    A quote the audit reports is one of two things: wording that drifted, or a sentence attributed to
    the wrong document. Only the second has a right answer somewhere else in the corpus, and this is
    how to get it - the same folded comparison, run over every RFC on the path instead of one.
    """
    seen = set()
    hits = []
    for d in law():
        for name in sorted(os.listdir(d)):
            m = re.match(r"^rfc0*(\d+)\.txt$", name)
            if not m or m.group(1) in seen:
                continue
            seen.add(m.group(1))
            text = read(os.path.join(d, name))
            at = contains(flatten(text), quote)
            if at >= 0:
                hits.append((int(m.group(1)), name, flatten(text), at))
    if not hits:
        print("no RFC on the path says it, in these words")
        print("  %d documents searched" % len(seen))
        return 1
    for number, _, flat, at in sorted(hits):
        print("RFC %d:" % number)
        print("  ...%s..." % flat[max(0, at - 50) : at + len(normalize(quote)) + 50].strip())
    return 0


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
    checked = skipped = unpaired = 0
    bad = []
    for path in sorted(files):
        # The RFC a stretch of file is about is often named on a banner above it rather than in the
        # comment doing the quoting: "// --- RFC 3828 sec 3.5, Jumbograms ---" and then a case whose
        # comment quotes sec 3.5 without naming the document again, because a reader four lines below
        # the banner does not need telling twice. So a block's candidates carry forward.
        recent = []
        for start, block in comment_blocks(path):
            flat_block = normalize(block)
            marks = [(m.start(), m.group(1)) for m in RFC_REF.finditer(flat_block)]
            for _, ref in marks:
                if ref in recent:
                    recent.remove(ref)
                recent.insert(0, ref)
            del recent[6:]
            if not marks and not recent:
                skipped += len([q for q in QUOTED.findall(flat_block) if " " in q])
                continue
            # An odd number of marks means every pairing after the first is wrong, so the block is
            # reported as unpaired rather than as a page of misquotes.
            if flat_block.count('"') % 2 == 1:
                unpaired += len([q for q in QUOTED.findall(flat_block) if " " in q])
                continue
            for m in QUOTED.finditer(flat_block):
                q = m.group(1)
                if " " not in q:
                    continue
                if NOT_A_QUOTATION.search(q):
                    unpaired += 1
                    continue
                # Every RFC the block names is a candidate, nearest-before first because that is
                # usually the one, and the quote is a finding only when NONE of them holds it. A
                # block here routinely cites three or four documents and quotes each in turn, and a
                # sentence about one MIB is regularly quoted beside the RFC that defines the message
                # it counts - RFC 2466's ipv6IfIcmpInMsgs described next to RFC 4443's Code 1. Which
                # of the two a quote belongs to is not on the line, and guessing it wrong reports a
                # misquote that is not one. What this can still catch is the thing worth catching: a
                # sentence that is in none of the documents the comment appeals to.
                near = None
                for at, ref in marks:
                    if at < m.start():
                        near = ref
                    else:
                        break
                cands = ([near] if near else []) + [r for _, r in marks if r != near]
                cands += [r for r in recent if r not in cands]
                if not cands:
                    skipped += 1
                    continue
                checked += 1
                found = False
                for number in cands:
                    if number not in flats:
                        flats[number] = flatten(fetch(number))
                    if contains(flats[number], normalize(q)) >= 0:
                        found = True
                        break
                if not found:
                    bad.append((path, start, cands[0], normalize(q)))

    for path, line, number, q in bad:
        print("%s:%d: no RFC this comment cites contains (nearest is RFC %s)" % (path.replace(os.sep, "/"), line, number))
        print('    "%s"' % q)
    print("")
    print("%d quotes checked against %d RFCs, %d not found" % (checked, len(flats), len(bad)))
    if skipped:
        print("%d quotes with no RFC named before them, not checked" % skipped)
    if unpaired:
        print("%d in a comment whose quote marks do not pair, not checked" % unpaired)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description="RFC text, and the quotes this tree takes from it")
    ap.add_argument("number", nargs="?", help="RFC number")
    ap.add_argument("--section", help="print one numbered section")
    ap.add_argument("--grep", help="print every line matching this regex")
    ap.add_argument("--context", type=int, default=2, help="lines either side of a --grep hit")
    ap.add_argument("--quote", help="check the document says this, in these words")
    ap.add_argument("--find", help="which RFC on the path says this, whoever the comment blamed")
    ap.add_argument("--audit", nargs="*", help="check every quote in the tree, or under these paths")
    args = ap.parse_args()

    if args.audit is not None:
        return cmd_audit(args.audit)
    if args.find:
        return cmd_find(args.find)
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
