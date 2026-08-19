#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""idemIP test harness: suite discovery and Unity runner generation.

  harness.py suites                          every suite, its cases, and the capabilities it needs
  harness.py runners gen <dir> --unity <rb>  write <dir>/unity_runner.c
  harness.py cases <dir>                     what Unity will register, and what it will walk past

A capability is a set of translation units the feature tree selects, so a suite whose capabilities
are off is not built at all:

  cmake -S . -B ../build -G Ninja -DIDEMIP_ENABLE_TCP=OFF -DIDEMIP_ENABLE_UDP=OFF

The capabilities each suite needs are test/CMakeLists.txt's map, which is what `suites` reads: a
suite naming a capability it never drives, or driving one it does not name, is how a reduced build
fails while the full one passes.

A case Unity's generator does not collect is not an error to the generator: it is simply never
registered, so the suite passes while the case never ran. `cases` and `runners gen` both break
that silence by naming the near misses.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNIT = os.path.join(ROOT, "test", "unit")
INTEGRATION = os.path.join(ROOT, "test", "integration")
GENERATED_RUNNER = "unity_runner.c"

# What Unity's generate_test_runner.rb collects, and the shape a case has to have to be collected.
UNITY_CASE = re.compile(r"^[ \t]*void[ \t]+(test_\w+)[ \t]*\([ \t]*(?:void)?[ \t]*\)", re.M)
NEAR_MISS = re.compile(r"^[ \t]*void[ \t]+(\w+)[ \t]*\([ \t]*(?:void)?[ \t]*\)[ \t]*\r?\n[ \t]*\{", re.M)
NOT_A_CASE = ("setUp", "tearDown", "main", "suiteSetUp", "suiteTearDown")

# test/CMakeLists.txt's map: which capabilities a suite needs before the build carries it.
SUITE_CAP = re.compile(r"^set\(IDEMIP_SUITE_CAP_(\w+)\s+([^)]*)\)", re.M)

# A conditional over a capability, and the two directives that end or invert one.
CAP_IF = re.compile(r"^[ \t]*#[ \t]*if[ \t]+IDEMIP_ENABLE_(\w+)[ \t]*$", re.M)
ANY_IF = re.compile(r"^[ \t]*#[ \t]*if")
ANY_ELSE = re.compile(r"^[ \t]*#[ \t]*el(se|if)")
ANY_ENDIF = re.compile(r"^[ \t]*#[ \t]*endif")


def guarded_cases(path):
    """Each registered case in @p path, with the capabilities whose #if it sits inside.

    Unity's generator reads the case names out of the source text and does not see a preprocessor
    conditional, so a case inside a capability's #if is still declared and called by the runner. With
    that capability off the definition is gone and the suite fails to LINK, which is what makes this
    the same finding as a capability the map does not name.
    """
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    out = {}
    stack = []  # one entry per open #if: the capability it tests, or None
    for line in lines:
        if ANY_ENDIF.match(line):
            if stack:
                stack.pop()
            continue
        if ANY_ELSE.match(line):
            if stack:
                stack[-1] = None  # the other arm is not the capability's
            continue
        if ANY_IF.match(line):
            m = CAP_IF.match(line)
            stack.append(m.group(1) if m else None)
            continue
        m = UNITY_CASE.match(line)
        if m:
            out[m.group(1)] = sorted({c for c in stack if c})
    return out


def suite_caps():
    """The capabilities each suite needs, as test/CMakeLists.txt's map states them."""
    path = os.path.join(ROOT, "test", "CMakeLists.txt")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return {name: caps.split() for name, caps in SUITE_CAP.findall(text)}


def runner_cases(path):
    """The cases Unity's generator will register in @p path, and the ones it will walk past."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    found = UNITY_CASE.findall(text)
    missed = [n for n in NEAR_MISS.findall(text) if n not in found and n not in NOT_A_CASE]
    return found, missed


def suite_source(suite_dir):
    """The one .c in a suite that holds its cases, or None."""
    if not os.path.isdir(suite_dir):
        return None
    for name in sorted(os.listdir(suite_dir)):
        path = os.path.join(suite_dir, name)
        if name.endswith(".c") and name != GENERATED_RUNNER and runner_cases(path)[0]:
            return path
    return None


def discover():
    """Every suite directory, which is any dir holding a .c with a collectable case."""
    out = []
    for base in (UNIT, INTEGRATION):
        for dirpath, _dirnames, filenames in os.walk(base):
            if any(f.endswith(".c") and f != GENERATED_RUNNER for f in filenames):
                if suite_source(dirpath):
                    out.append(dirpath)
    return sorted(out)


def find_ruby():
    """Ruby runs Unity's generator. A missing one is an error, never a silent skip."""
    return shutil.which("ruby")


def generate_runner(suite_dir, unity_rb):
    """Emit suite_dir/unity_runner.c from the one source that holds the cases."""
    candidates = [f for f in sorted(os.listdir(suite_dir)) if f.endswith(".c") and f != GENERATED_RUNNER]
    sources = [f for f in candidates if runner_cases(os.path.join(suite_dir, f))[0]]
    if not sources:
        for f in candidates:
            _, missed = runner_cases(os.path.join(suite_dir, f))
            if missed:
                raise SystemExit(
                    "runners: %s holds no case Unity's generator will register.\n"
                    "  It collects file-scope `void test_<name>(void)` and nothing else, so these\n"
                    "  are walked past and never run: %s\n"
                    "  Rename each to test_<name> - a case the generator skips costs coverage in\n"
                    "  silence, because the suite still passes."
                    % (os.path.relpath(os.path.join(suite_dir, f), ROOT), ", ".join(missed))
                )
        raise SystemExit("runners: no test case found in %s" % os.path.relpath(suite_dir, ROOT))
    # The generator takes one input file and emits one main(), so cases spread across several
    # sources cannot be registered from any single one of them.
    if len(sources) > 1:
        raise SystemExit(
            "runners: %s holds test cases in %d sources (%s).\n"
            "  Unity's generator registers one source per runner, so the rest would never run.\n"
            "  Put the cases in one file, or give each file its own suite directory."
            % (os.path.relpath(suite_dir, ROOT), len(sources), ", ".join(sources))
        )
    ruby = find_ruby()
    if not ruby:
        raise SystemExit("runners: ruby not found on PATH - install it (choco install ruby)")
    if not os.path.isfile(unity_rb):
        raise SystemExit("runners: Unity's generate_test_runner.rb not found at %s" % unity_rb)
    src = os.path.join(suite_dir, sources[0])
    out = os.path.join(suite_dir, GENERATED_RUNNER)
    subprocess.run([ruby, unity_rb, src, out], check=True)
    # Report the near misses even on success: the runner is written, and these still never ran.
    _, missed = runner_cases(src)
    if missed:
        print(
            "runners: %s registered %d cases, and walked past %s - rename each to test_<name>"
            % (os.path.relpath(src, ROOT), len(runner_cases(src)[0]), ", ".join(missed)),
            file=sys.stderr,
        )
    return out


# A suite that binds a dependency and never drives it looks covered and is not. test_dispatch bound
# the IGMP borrow from the day it was written and no case ever fed it a message, so RFC 2236
# sec 2.3's "the checksum MUST be verified" went missing for a whole phase behind a green suite.
BIND_DEP = re.compile(r"bind_args\.(\w+)\s*=\s*(\w+_mem)\b")


def _is_setup_use(line, mem):
    """True when this line only declares, binds, or clears the borrow.

    Those three are how a dependency is made ready, not how it is exercised, and a suite that does
    only them has bound a unit it never asks anything of. Where the setup lives does not matter:
    test_dispatch clears in a wire_units() helper rather than in setUp, so keying on the function
    would have missed exactly the case this check exists for.
    """
    esc = re.escape(mem)
    if re.search(r"\b(static|uint8_t)\b.*\b" + esc + r"\b\s*\[", line):
        return True  # the declaration
    if re.search(r"bind_args\.\w+\s*=\s*" + esc + r"\b", line):
        return True  # the bind
    if re.search(r"\w+\.(clear|reset)\s*\(\s*" + esc + r"\s*\)", line):
        return True  # made ready, not asked anything
    return False


def undriven_deps(path):
    """Dependencies a suite binds that no line exercises beyond declaring, binding and clearing."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    text = "\n".join(lines)
    out = []
    for dep, mem in set(BIND_DEP.findall(text)):
        driven = any(mem in ln and not _is_setup_use(ln, mem) for ln in lines)
        if not driven:
            out.append((dep, mem))
    return sorted(out)


def cmd_deps(a):
    bad = 0
    for d in discover():
        src = suite_source(d)
        if not src:
            continue
        un = undriven_deps(src)
        rel = os.path.relpath(d, ROOT).replace("\\", "/")
        if un:
            bad += len(un)
            print("%s" % rel)
            for dep, mem in un:
                print("   UNASSERTED  %-14s (%s)" % (dep, mem))
    if not bad:
        print("every bound dependency is asserted on by at least one case")
        return 0
    print(
        "\n%d dependencies are bound and then never named again outside setup.\n"
        "\n"
        "  This is a smell, not a proof. A unit the suite reaches only THROUGH the unit under\n"
        "  test is still exercised, and this cannot see that. What it does prove is that no case\n"
        "  ASSERTS anything about the dependency's own state, so a defect in the interaction\n"
        "  between the two is invisible either way.\n"
        "\n"
        "  test_dispatch bound the IGMP borrow this way from the day it was written. No case ever\n"
        "  fed it a message, RFC 2236 sec 2.3's 'the checksum MUST be verified' was simply absent,\n"
        "  and the suite was green throughout.\n"
        "\n"
        "  Fix one of two ways: drive it and assert its state, or stop binding it so the suite\n"
        "  says what it tests." % bad
    )
    return 1 if a.strict else 0


def cmd_suites(a):
    caps = suite_caps()
    unnamed = []
    for d in discover():
        src = suite_source(d)
        found, missed = runner_cases(src)
        name = os.path.basename(d)
        need = caps.get(name, [])
        note = "" if not missed else "   NOT REGISTERED: " + ", ".join(missed)
        for case, guards in guarded_cases(src).items():
            for cap in guards:
                if cap not in need:
                    unnamed.append((name, cap, case))
        print("%-52s %2d cases  %-18s%s"
              % (os.path.relpath(d, ROOT).replace("\\", "/"), len(found), " ".join(need) or "-", note))

    if not unnamed:
        print("\nevery case a capability guards is in a suite that names that capability")
        return 0

    print("\n%d cases sit inside a capability their suite does not name:\n" % len(unnamed))
    for suite, cap, case in unnamed:
        print("   %-22s needs %-10s %s" % (suite, cap, case))
    print("""
  Unity's generator reads the case names out of the source text and does not see a
  preprocessor conditional, so the runner declares and calls each of these however the
  capability is set. With it off the definition is gone and the suite fails to LINK, so
  the reduced build breaks while the full one stays green.

  Fix one of two ways: add the capability to the suite's IDEMIP_SUITE_CAP_ line in
  test/CMakeLists.txt, which gates the whole suite on it, or move the cases to a suite
  that already names it.""")
    return 1 if a.strict else 0


def cmd_cases(a):
    for d in a.suite:
        src = suite_source(d)
        if not src:
            print("%s: no collectable case" % d)
            continue
        found, missed = runner_cases(src)
        print("%s" % os.path.relpath(src, ROOT).replace("\\", "/"))
        for name in found:
            print("   registered   %s" % name)
        for name in missed:
            print("   WALKED PAST  %s" % name)
    return 0


def cmd_runners_gen(a):
    for d in a.suite:
        out = generate_runner(d, a.unity)
        print("wrote %s" % os.path.relpath(out, ROOT).replace("\\", "/"))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("suites", help="every suite, its cases, and the capabilities it needs")
    p.add_argument("--strict", action="store_true", help="exit non-zero on a finding, for a CI gate")
    p.set_defaults(fn=cmd_suites)

    p = sub.add_parser("deps", help="dependencies a suite binds but no case asserts on")
    p.add_argument("--strict", action="store_true", help="exit non-zero on a finding, for a CI gate")
    p.set_defaults(fn=cmd_deps)

    p = sub.add_parser("cases", help="what Unity will register, and what it will walk past")
    p.add_argument("suite", nargs="+")
    p.set_defaults(fn=cmd_cases)

    p = sub.add_parser("runners", help="Unity runner generation")
    psub = p.add_subparsers(dest="sub", required=True)
    g = psub.add_parser("gen", help="write a suite's unity_runner.c")
    g.add_argument("suite", nargs="+")
    g.add_argument("--unity", required=True, help="path to Unity's auto/generate_test_runner.rb")
    g.set_defaults(fn=cmd_runners_gen)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
