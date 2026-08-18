"""Identifiers a header defines that no library .c file ever names.

Three of the twenty-four confirmed security defects were exactly this shape: idemip_udp_cksum_valid
sat in udp.h with no caller, IDEMIP_IGMP_OFF_CKSUM had no reader, and IDEMIP_DISPATCH_DROP_IP_SOURCE
was an enumerator nothing raised. Each was a requirement someone encoded and never wired.

Reports per identifier: where it is defined, and how many times library code and test code name it.
A definition used only by tests, or by nothing at all, is the interesting case.
"""
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LIB = os.path.join(ROOT, "idemIP")
TEST = os.path.join(ROOT, "test")

# What a header defines: an inline function, a function-like or object-like macro, an enumerator.
DEF_INLINE = re.compile(r"^IDEMIP_INLINE\s+[A-Za-z_][\w \*]*?\b(\w+)\s*\(", re.M)
DEF_MACRO = re.compile(r"^#define\s+(\w+)", re.M)
DEF_ENUM = re.compile(r"^\s*(IDEMIP_[A-Z0-9_]+)\s*(?:=[^,]*)?,\s*(?:///<.*)?$", re.M)


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


defs = {}
for h in sources(LIB, ".h"):
    text = read(h)
    for pat in (DEF_INLINE, DEF_MACRO, DEF_ENUM):
        for name in pat.findall(text):
            defs.setdefault(name, h)

lib_text = "\n".join(read(c) for c in sources(LIB, ".c"))
hdr_text = "\n".join(read(h) for h in sources(LIB, ".h"))
test_text = "\n".join(read(c) for c in sources(TEST, ".c"))


def count(text, name):
    return len(re.findall(r"\b" + re.escape(name) + r"\b", text))


rows = []
for name, where in defs.items():
    in_lib = count(lib_text, name)
    in_hdr = count(hdr_text, name) - 1  # its own definition
    in_test = count(test_text, name)
    if in_lib == 0 and in_hdr == 0:
        rows.append((name, os.path.relpath(where, ROOT).replace("\\", "/"), in_test))

rows.sort(key=lambda r: (r[1], r[0]))
for name, where, in_test in rows:
    note = "tests only (%d)" % in_test if in_test else "NO CALLER ANYWHERE"
    print("%-46s %-34s %s" % (name, where, note))
print("\n%d definitions no library code names" % len(rows))
