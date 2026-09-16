#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""idemIP checker entry point: which reader answers which question, and the CI set.

  check.py list             every checker and what it answers
  check.py ci               the four the workflows run, in their order
  check.py <name> [args]    one checker, with its own flags passed through
  check.py <name> --help    that checker's own help

tools/dev_env holds fourteen readers and nothing said which to reach for. Four are named in
.github/workflows and the other ten were reachable only by opening them. That is the gap this
closes: a reader asks one question, and the answer to "which do I run" should not be "read all
fourteen".

WHAT THIS DOES NOT DO. It carries no description of its own. Every line `list` prints is the first
line of that script's module docstring, read out of the file at run time, so a checker whose
purpose changes says so here without anyone editing this file. A second copy of those descriptions
would be a second thing to keep true, and the tree already has one that drifted: docs/index.html
carried a footprint the source had moved past, which is why tools/dev_env/docsgen.py exists.

  python tools/check.py list
  python tools/check.py ci
  python tools/check.py rfc --audit src/dhcp
  python tools/check.py quotes --help
"""

import argparse
import ast
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEV_ENV = os.path.join(REPO_ROOT, "tools", "dev_env")

# The set .github/workflows runs, in the order the workflows run them. A checker enters this list by
# being named in a workflow, so the list and the workflows are checked against each other by
# `check.py ci --dry-run` rather than by anyone remembering.
CI_SET = (
    ("guards", ()),
    ("counters", ()),
    ("rfc", ("--audit",)),
    ("deadstate", ()),
)


def checkers():
    """Every checker in tools/dev_env, as (name, first docstring line).

    The description is read from the script. Nothing here restates one.
    """
    found = []
    for entry in sorted(os.listdir(DEV_ENV)):
        if not entry.endswith(".py") or entry.startswith("_"):
            continue
        path = os.path.join(DEV_ENV, entry)
        with open(path, encoding="utf-8") as handle:
            try:
                doc = ast.get_docstring(ast.parse(handle.read()))
            except SyntaxError:
                doc = None
        summary = doc.strip().splitlines()[0] if doc else "(no module docstring)"
        found.append((entry[:-3], summary))
    return found


def script_for(name):
    """The path of one checker, or None when no script carries that name."""
    path = os.path.join(DEV_ENV, name + ".py")
    return path if os.path.isfile(path) else None


def run(name, argv, dry_run):
    """Run one checker with its own arguments. Return its exit status."""
    path = script_for(name)
    if path is None:
        print("no checker named {}. `check.py list` names every one.".format(name))
        return 2
    command = [sys.executable, path] + list(argv)
    print("  " + " ".join(command))
    if dry_run:
        return 0
    return subprocess.run(command, cwd=REPO_ROOT, check=False).returncode


def cmd_list(args):
    """Print every checker and the question it answers."""
    rows = checkers()
    width = max(len(name) for name, _ in rows)
    ci_names = [name for name, _ in CI_SET]
    print("idemIP checkers, in tools/dev_env. A star marks one the workflows run.\n")
    for name, summary in rows:
        mark = "*" if name in ci_names else " "
        print("  {} {:<{w}}  {}".format(mark, name, summary, w=width))
    print("\n  python tools/check.py <name> --help   that checker's own flags")
    print("  python tools/check.py ci             the starred four, in workflow order")
    return 0


def cmd_ci(args):
    """Run the set the workflows run, stopping at the first failure."""
    for name, argv in CI_SET:
        status = run(name, argv, args.dry_run)
        if status != 0:
            print("\n{} reported {}. The workflows fail here too.".format(name, status))
            return status
    print("\nevery checker the workflows run reported clean")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, add_help=False
    )
    ap.add_argument("name", nargs="?", help="list, ci, or a checker name")
    ap.add_argument("-n", "--dry-run", action="store_true", help="print the commands without running them")
    ap.add_argument("-h", "--help", action="store_true", help="show this help")

    # Everything after the checker name belongs to that checker, including --help, so this parses
    # only what it owns and hands the rest through untouched.
    args, rest = ap.parse_known_args()

    if args.name is None or (args.help and args.name is None):
        ap.print_help()
        return 0
    if args.name == "list":
        return cmd_list(args)
    if args.name == "ci":
        return cmd_ci(args)
    if args.help:
        rest = rest + ["--help"]
    return run(args.name, rest, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
