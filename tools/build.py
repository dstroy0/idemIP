#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""idemIP build driver: prerequisites, configure, and every buildable tree in one entry.

  build.py check                 the toolchain this repo needs, and what each part is needed for
  build.py configure             write the CMake cache and stop
  build.py lib                   the static library from src/, plus the idemip_sizes tool
  build.py examples              the examples/ tree
  build.py tests                 the suites, then ctest over them
  build.py all                   lib, examples and tests in one pass

The build directory sits outside the repository because .clangd reads a compile database at
../build. That path is the default here so an editor and this script agree without configuration.

Every subcommand takes --dry-run, which prints the exact cmake and ctest invocations without
running them. A reader who wants to drive the build by hand runs `check` for the prerequisites and
`--dry-run` for the commands, and needs nothing else from this file.

Capabilities are CMake options, so a capability that is off reaches the compiler as no file at all.
Pass them through with -D, which this script forwards to the configure step verbatim:

  build.py lib -D IDEMIP_ENABLE_TCP=OFF -D IDEMIP_ENABLE_UDP=OFF
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The README pins CMake at 3.20 or newer, and CMakeLists.txt:4 is the cmake_minimum_required that
# refuses an older one. Both numbers are stated here so `check` fails with a reason instead of
# letting the configure step fail with a stack of CMake output.
CMAKE_MINIMUM = (3, 20)

# Ruby runs Unity's generate_test_runner.rb and Python drives test/harness.py, so neither is needed
# for a library build. `check` reports them as test-only rather than as a hard prerequisite.
PREREQUISITES = [
    ("cmake", "configures and drives every build here", True),
    ("ninja", "the default generator; --generator picks another", False),
    ("python3", "drives test/harness.py, which writes the Unity runners", False),
    ("ruby", "runs Unity's generate_test_runner.rb", False),
]


def tool_version(executable_name):
    """Return the first version-shaped token that `executable_name --version` prints, or None."""
    path = shutil.which(executable_name)
    if path is None:
        return None
    try:
        completed = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    found = re.search(r"(\d+\.\d+(?:\.\d+)?)", completed.stdout + completed.stderr)
    return found.group(1) if found else ""


def c_compiler_name():
    """Return the C compiler a configure step would pick, or None when there is none to pick."""
    from_environment = os.environ.get("CC")
    if from_environment and shutil.which(from_environment):
        return from_environment
    for candidate in ("cc", "gcc", "clang"):
        if shutil.which(candidate):
            return candidate
    return None


def resolve_build_dir(explicit=None):
    """Return the absolute build directory, defaulting to the ../build that .clangd expects.

    Every tool in this tree that needs to know where the build went calls this. It stood in two
    implementations until 2026-09-16: this one, which takes --build-dir, and a four-candidate guess
    inside tools/dev_env/docsgen.py, which took nothing. The two disagreed the moment anyone passed
    --build-dir, and docsgen then reported a built idemip_sizes as missing and printed a rebuild
    command naming a directory that did not exist.
    """
    if explicit:
        return os.path.abspath(explicit)
    return os.path.abspath(os.path.join(REPO_ROOT, os.pardir, "build"))


def resolve_built_tool(name, build_dir=None):
    """Return the path to a built executable under the build directory, or None when it is absent.

    The suffix is the platform's, so a caller names the target and not the file.
    """
    root = resolve_build_dir(build_dir)
    for candidate in (name + ".exe", name):
        path = os.path.join(root, candidate)
        if os.path.isfile(path):
            return path
    return None


def build_directory(args):
    """The build directory this invocation runs in."""
    return resolve_build_dir(args.build_dir)


def run(command, dry_run):
    """Print a command, then run it unless this is a dry run. Return its exit status."""
    print("  " + " ".join(command))
    if dry_run:
        return 0
    completed = subprocess.run(command, cwd=REPO_ROOT, check=False)
    return completed.returncode


def configure(args, extra_defines=()):
    """Write the CMake cache for this build directory. Return an exit status."""
    destination = build_directory(args)
    if args.clean and os.path.isdir(destination):
        print(f"removing {destination}")
        if not args.dry_run:
            shutil.rmtree(destination)

    command = ["cmake", "-S", REPO_ROOT, "-B", destination]
    if args.generator:
        command += ["-G", args.generator]
    command.append(f"-DCMAKE_BUILD_TYPE={args.type}")
    for define in list(extra_defines) + list(args.define or []):
        command.append(f"-D{define}")
    return run(command, args.dry_run)


def build_targets(args, targets):
    """Build the named targets out of an already configured build directory."""
    command = ["cmake", "--build", build_directory(args)]
    for target in targets:
        command += ["--target", target]
    if args.jobs:
        command += ["-j", str(args.jobs)]
    return run(command, args.dry_run)


def examples_are_present():
    """Return True when the examples tree carries the CMakeLists.txt that wires it into the build."""
    return os.path.isfile(os.path.join(REPO_ROOT, "examples", "CMakeLists.txt"))


def cmd_check(args):
    """Report every prerequisite, what it gates, and whether this host has it."""
    print("idemIP prerequisites\n")
    missing_required = []

    for executable_name, purpose, is_required in PREREQUISITES:
        version = tool_version(executable_name)
        tier = "required" if is_required else "optional"
        if version is None:
            print(f"  [ MISSING ] {executable_name:<8} ({tier})  {purpose}")
            if is_required:
                missing_required.append(executable_name)
            continue
        shown = version if version else "present"
        print(f"  [ found   ] {executable_name:<8} {shown:<8} {purpose}")
        if executable_name == "cmake" and version:
            parts = tuple(int(piece) for piece in version.split(".")[:2])
            if parts < CMAKE_MINIMUM:
                wanted = ".".join(str(piece) for piece in CMAKE_MINIMUM)
                print(f"              cmake {version} is older than the {wanted} CMakeLists.txt requires")
                missing_required.append("cmake")

    compiler = c_compiler_name()
    if compiler is None:
        print("  [ MISSING ] C compiler (required)  any C11 compiler; -Os and the warning set assume GCC or Clang")
        missing_required.append("C compiler")
    else:
        print(f"  [ found   ] {compiler:<8} {tool_version(compiler) or 'present':<8} builds the library")

    print("\n  Unity v2.6.1 is cloned by FetchContent the first time a test build configures,")
    print("  so that one configure step needs the network.")

    print("\ntrees this script builds\n")
    print("  [ found   ] src/        the library, built by `build.py lib`")
    if examples_are_present():
        print("  [ found   ] examples/   built by `build.py examples`")
    else:
        print("  [ absent  ] examples/   no examples/CMakeLists.txt, so `build.py examples` has nothing to build")
    print("  [ found   ] test/       the suites, built and run by `build.py tests`")

    if missing_required:
        print("\ninstall these before building: " + ", ".join(missing_required))
        return 1
    print("\nready. `build.py all` builds everything this host can build.")
    return 0


def cmd_configure(args):
    return configure(args)


def cmd_lib(args):
    """Configure without the test tree, then build the library and the footprint tool."""
    status = configure(args, extra_defines=["BUILD_TESTING=OFF"])
    if status != 0:
        return status
    return build_targets(args, ["idemip", "idemip_sizes"])


def cmd_examples(args):
    """Build the examples tree, or name what is missing when there is no tree to build."""
    if not examples_are_present():
        print("examples/CMakeLists.txt is not in this tree, so there is nothing to build.")
        print("Add examples/CMakeLists.txt and the root CMakeLists.txt picks it up on the next configure.")
        return 0
    status = configure(args, extra_defines=["IDEMIP_EXAMPLES=ON", "BUILD_TESTING=OFF"])
    if status != 0:
        return status
    return build_targets(args, ["idemip_examples"])


def cmd_tests(args):
    """Configure with the test tree on, build it, then run ctest over the suites."""
    status = configure(args, extra_defines=["BUILD_TESTING=ON"])
    if status != 0:
        return status
    status = build_targets(args, [])
    if status != 0:
        return status
    command = ["ctest", "--test-dir", build_directory(args), "--output-on-failure"]
    if args.jobs:
        command += ["-j", str(args.jobs)]
    return run(command, args.dry_run)


def cmd_all(args):
    """Build every tree this repository carries, stopping at the first failure."""
    for step in (cmd_lib, cmd_examples, cmd_tests):
        status = step(args)
        if status != 0:
            return status
    return 0


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--build-dir", help="where to configure; the default is ../build, which .clangd reads")
    common.add_argument("--type", default="Release", help="CMAKE_BUILD_TYPE, Release by default")
    common.add_argument("--generator", default="Ninja", help="CMake generator, Ninja by default")
    common.add_argument("--jobs", type=int, help="parallel jobs handed to cmake --build and ctest")
    common.add_argument("--clean", action="store_true", help="delete the build directory before configuring")
    common.add_argument("-n", "--dry-run", action="store_true", help="print the commands without running them")
    common.add_argument("-D", "--define", action="append", metavar="VAR=VALUE",
                        help="a CMake define forwarded to the configure step; repeatable")

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check", parents=[common], help="the toolchain this repo needs, and what each part is for")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("configure", parents=[common], help="write the CMake cache and stop")
    p.set_defaults(fn=cmd_configure)

    p = sub.add_parser("lib", parents=[common], help="the static library from src/, plus idemip_sizes")
    p.set_defaults(fn=cmd_lib)

    p = sub.add_parser("examples", parents=[common], help="the examples/ tree")
    p.set_defaults(fn=cmd_examples)

    p = sub.add_parser("tests", parents=[common], help="the suites, then ctest over them")
    p.set_defaults(fn=cmd_tests)

    p = sub.add_parser("all", parents=[common], help="lib, examples and tests in one pass")
    p.set_defaults(fn=cmd_all)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
