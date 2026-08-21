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

# A conditional this can mirror into the runner: IDEMIP_ENABLE_ terms joined by && or ||, and
# nothing else. Every capability reaches every target as a definition of the library itself
# (target_compile_definitions(idemip PUBLIC IDEMIP_ENABLE_<cap>=0|1)), so the runner reads one the
# same way the suite it registers does. A conditional over anything else is not mirrored: the macro
# may not be visible in the runner's translation unit, and an undefined macro reads as zero, which
# would drop the case in silence rather than say so.
CAP_IF = re.compile(r"^[ \t]*#[ \t]*if[ \t]+"
                    r"(IDEMIP_ENABLE_\w+(?:[ \t]*(?:&&|\|\|)[ \t]*IDEMIP_ENABLE_\w+)*)[ \t]*$", re.M)
CAP_TERM = re.compile(r"IDEMIP_ENABLE_(\w+)")
ANY_IF = re.compile(r"^[ \t]*#[ \t]*if")
ANY_ELSE = re.compile(r"^[ \t]*#[ \t]*el(se|if)")
ANY_ENDIF = re.compile(r"^[ \t]*#[ \t]*endif")

# The two lines a runner names a case on, which are the two this has to guard.
RUNNER_EXTERN = re.compile(r"^extern void (test_\w+)\(void\);[ \t]*$")
RUNNER_RUN = re.compile(r"^[ \t]*run_test\((test_\w+),")


def guarded_cases(path):
    """Each registered case in @p path, with the conditionals it sits inside, outermost first.

    Unity's generator reads the case names out of the source text and does not see a preprocessor
    conditional, so a case inside a capability's #if would still be declared and called by the
    runner. With that capability off the definition is gone and the suite fails to LINK. What this
    reads is what generate_runner mirrors onto the two lines the runner names the case on, so the
    case leaves the runner exactly where it leaves the suite.

    An entry is the conditional's text where CAP_IF can mirror it and None where it cannot, so a
    case standing under something this cannot carry across is a finding and not a silence.
    """
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    out = {}
    stack = []  # one entry per open #if: the conditional's text, or None where it is not mirrorable
    for line in lines:
        if ANY_ENDIF.match(line):
            if stack:
                stack.pop()
            continue
        if ANY_ELSE.match(line):
            if stack:
                stack[-1] = None  # the other arm is not the one the #if names
            continue
        if ANY_IF.match(line):
            m = CAP_IF.match(line)
            stack.append(m.group(1) if m else None)
            continue
        m = UNITY_CASE.match(line)
        if m:
            out[m.group(1)] = list(stack)
    return out


def caps_of(guards):
    """The capabilities named anywhere in a case's conditionals."""
    return sorted({c for g in guards if g for c in CAP_TERM.findall(g)})


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


def guard_runner(runner, src):
    """Carry @p src's conditionals onto the two lines @p runner names each case on.

    Unity's generator does not see a preprocessor conditional; this does, and it is the whole of
    what the runner needs. Mirroring the #if is what lets a capability compile a single case out
    instead of the suite around it: with the capability off the definition is gone from the suite
    and the declaration and the call are gone from the runner, so the reduced build links and runs
    every case it still holds.

    The conditional is copied across rather than interpreted, so && and || and a nest of them all
    carry. What is not copied is a conditional over something other than a capability - see CAP_IF.
    """
    guards = {case: g for case, g in guarded_cases(src).items() if g}
    unreadable = sorted(case for case, g in guards.items() if any(x is None for x in g))
    if unreadable:
        raise SystemExit(
            "runners: %s holds %d cases inside a conditional the runner cannot be given.\n"
            "  Only IDEMIP_ENABLE_ terms are carried across, because only those are defined for\n"
            "  every translation unit; anything else may be invisible where the runner is compiled,\n"
            "  and an undefined macro reads as zero, which would drop the case in silence: %s\n"
            "  Put the conditional inside the case body, where the case still registers and the\n"
            "  build it does not apply to can say so."
            % (os.path.relpath(src, ROOT), len(unreadable), ", ".join(unreadable))
        )
    if not guards:
        return
    # A nest is a conjunction: every #if a case stands inside held for it to be compiled at all.
    expr = {case: " && ".join("(%s)" % g for g in gs) for case, gs in guards.items()}
    with open(runner, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    out = []
    standing = None  # the conditional the emitted lines are inside, so a run of them opens one #if
    for line in lines:
        m = RUNNER_EXTERN.match(line) or RUNNER_RUN.match(line)
        want = expr.get(m.group(1)) if m else None
        if want != standing:
            if standing is not None:
                out.append("#endif")
            if want is not None:
                out.append("#if %s" % want)
            standing = want
        out.append(line)
    if standing is not None:
        out.append("#endif")
    with open(runner, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(out))


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
    # The generator writes the path it was handed into the runner's own UnityBegin(), so an absolute
    # one puts the machine that ran it into a file the tree tracks, and a second checkout regenerates
    # a file that differs from the committed one in nothing but where it was built. Handing it a
    # path relative to the root, from the root, is what makes the bytes the same everywhere - which
    # is what lets a build check that the committed runner is the one the sources generate.
    rel = [os.path.relpath(p, ROOT).replace("\\", "/") for p in (src, out)]
    subprocess.run([ruby, unity_rb] + rel, check=True, cwd=ROOT)
    # Unity's generator opens its output in text mode, so on Windows every line lands CRLF while
    # .gitattributes holds this tree at "LF in the repository and LF in the working copy". The runner
    # is tracked, so that difference shows as a modified file after every build that regenerates one.
    # git normalizes the content it stores either way, so nothing was ever committed wrong; rewriting
    # the bytes here is what leaves the working copy as the build found it, on every platform. A
    # no-op where the generator already wrote LF.
    with open(out, "rb") as fh:
        written = fh.read()
    lf = written.replace(b"\r\n", b"\n")
    if lf != written:
        with open(out, "wb") as fh:
            fh.write(lf)
    guard_runner(out, src)
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
    unreadable = []
    compiled_out = []
    for d in discover():
        src = suite_source(d)
        found, missed = runner_cases(src)
        name = os.path.basename(d)
        need = caps.get(name, [])
        note = "" if not missed else "   NOT REGISTERED: " + ", ".join(missed)
        for case, guards in guarded_cases(src).items():
            if any(g is None for g in guards):
                unreadable.append((name, case))
                continue
            # A capability the suite already names holds wherever the suite is built at all, so a
            # conditional over one of those takes no case out of any run. The rest do.
            takes = [c for c in caps_of(guards) if c not in need]
            if takes:
                compiled_out.append((name, " ".join(takes), case))
        print("%-52s %2d cases  %-18s%s"
              % (os.path.relpath(d, ROOT).replace("\\", "/"), len(found), " ".join(need) or "-", note))

    if compiled_out:
        print("\n%d cases stand inside a capability their suite does not name. The suite is still\n"
              "built without it, and the case leaves the runner with the definition, so what the\n"
              "reduced run covers is the suite minus these:\n" % len(compiled_out))
        for suite, cap, case in compiled_out:
            print("   %-22s without %-10s %s" % (suite, cap, case))

    if not unreadable:
        print("\nevery conditional standing over a case is one the runner can be given as well")
        return 0

    print("\n%d cases sit inside a conditional the runner cannot be given:\n" % len(unreadable))
    for suite, case in unreadable:
        print("   %-22s %s" % (suite, case))
    print("""
  Unity's generator reads the case names out of the source text and does not see a
  preprocessor conditional; harness.py copies each one onto the runner's declaration and
  call so the case leaves both together. Only IDEMIP_ENABLE_ terms are copied, because the
  build defines those for every translation unit - a conditional over anything else may be
  invisible where the runner is compiled, and an undefined macro reads as zero, so the case
  would stop running without failing.

  Fix one of two ways: state the conditional over IDEMIP_ENABLE_ terms, or move it inside
  the case body, where the case still registers and the build it does not apply to can say
  so rather than vanish.""")
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
