"""Identifiers a header defines that no library .c file ever names, and the same scan run the other way.

  unwired.py [root]             definitions no library code names
  unwired.py [root] --untested  outcomes the library raises that no test ever names

Three of the twenty-four confirmed security defects were exactly this shape: idemip_udp_cksum_valid
sat in udp.h with no caller, IDEMIP_IGMP_OFF_CKSUM had no reader, and IDEMIP_DISPATCH_DROP_IP_SOURCE
was an enumerator nothing raised. Each was a requirement someone encoded and never wired.

Reports per identifier: where it is defined, and how many times library code and test code name it.
A definition used only by tests, or by nothing at all, is the interesting case.

--untested is the inverse axis, and the one the weak-test count needs. A drop code, an action flag, a
state or an RFC 1213 counter that library code RAISES and no test ever names is a branch the suite
cannot be distinguishing: whatever the code does there, the suite is green. It is a smell and not a
proof, the same way harness.py deps is, because a test can reach the branch through a value it never
spells. What it proves is that no case says which outcome it expects.
"""
import os
import re
import sys

ARGS = [a for a in sys.argv[1:] if not a.startswith("-")]
UNTESTED = "--untested" in sys.argv[1:]
ROOT = ARGS[0] if ARGS else "."

# The definitions that name an OUTCOME: what a call reports, not where a field lies. These are the
# ones a case is expected to spell out, so a library that raises one and a suite that never names it
# is the shape the weak-test count describes.
OUTCOME = ("_DROP_", "_ACT_", "_STATE_", "_STAT_", "_ERR", "_FLAG_", "_CODE_")
LIB = os.path.join(ROOT, "src")
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
    rel = os.path.relpath(where, ROOT).replace("\\", "/")
    if UNTESTED:
        if in_lib > 0 and in_test == 0 and any(k in name for k in OUTCOME):
            rows.append((name, rel, in_lib))
    elif in_lib == 0 and in_hdr == 0:
        rows.append((name, rel, in_test))

rows.sort(key=lambda r: (r[1], r[0]))
if not UNTESTED:
    for name, where, in_test in rows:
        note = "tests only (%d)" % in_test if in_test else "NO CALLER ANYWHERE"
        print("%-46s %-34s %s" % (name, where, note))
    print("\n%d definitions no library code names" % len(rows))
    sys.exit(0)

for name, where, in_lib in rows:
    print("%-46s %-34s raised at %d site%s" % (name, where, in_lib, "" if in_lib == 1 else "s"))
if not rows:
    print("every outcome the library raises is named by at least one case")
    sys.exit(0)
print("""
%d outcomes the library raises that no case names.

  A smell, not a proof: a case can reach the branch through a value it never spells,
  and this cannot see that. What it proves is that no case says which outcome it
  expects, so whatever the code does there the suite stays green.

  Fix one of two ways: assert the outcome where a case already reaches it, or send the
  input that raises it and assert it there.""" % len(rows))
