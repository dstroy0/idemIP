"""Namespace entries a unit exports that no library .c outside that unit ever calls.

unwired.py reports the same shape one level down, over what a header DEFINES: a macro, an
enumerator, an inline accessor. An entry in a namespace struct is neither, so it is invisible to
that scan, and it is the level a receive path is wired at. Ip4Reass.input, IcmpIn.recv and
UdpPcb.lookup are each named by core/dispatch.c; an entry no .c outside its own unit names is a
message the stack parses nowhere.

Reports per entry: the unit that exports it, and how many times library code outside the unit and
test code name it. Its own unit is excluded because every unit names its entries once, in the
namespace initializer.
"""
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LIB = os.path.join(ROOT, "src")
TEST = os.path.join(ROOT, "test")

# `const XNs X = {.entry = ...}` in the .c, and `void (*const entry)(uint8_t *restrict work);`
# in the header's namespace struct.
DEF_ENTRY = re.compile(r"^\s*void\s*\(\*const\s+(\w+)\)\s*\(uint8_t \*restrict work\);", re.M)
# `const DispatchNs Dispatch = {` names the object a caller writes as `Dispatch.input`.
DEF_NS = re.compile(r"^(?:extern\s+)?const\s+(\w+Ns)\s+(\w+);", re.M)


def sources(base, ext):
    out = []
    for dirpath, _d, files in os.walk(base):
        if "build" in dirpath.split(os.sep):
            continue
        for f in files:
            if f.endswith(ext):
                out.append(os.path.join(dirpath, f))
    return sorted(out)


def read(p):
    with open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read()


# unit -> (namespace object, header, [entries])
units = []
for h in sources(LIB, ".h"):
    text = read(h)
    ns = DEF_NS.findall(text)
    entries = DEF_ENTRY.findall(text)
    if ns and entries:
        units.append((ns[-1][1], h, entries))

texts = {c: read(c) for c in sources(LIB, ".c")}
test_text = "\n".join(read(c) for c in sources(TEST, ".c"))

rows = []
for obj, hdr, entries in units:
    own = os.path.dirname(hdr)
    outside = "\n".join(t for c, t in texts.items() if not c.startswith(own + os.sep))
    for e in entries:
        pat = r"\b" + re.escape(obj) + r"\s*\.\s*" + re.escape(e) + r"\b"
        in_lib = len(re.findall(pat, outside))
        if in_lib == 0:
            in_test = len(re.findall(pat, test_text))
            rows.append(("%s.%s" % (obj, e), os.path.relpath(hdr, ROOT).replace("\\", "/"), in_test))

for name, where, in_test in rows:
    note = "tests only (%d)" % in_test if in_test else "NO CALLER ANYWHERE"
    print("%-34s %-30s %s" % (name, where, note))
print("\n%d entries no library code outside the unit calls" % len(rows))
