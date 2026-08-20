#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The determinism window, from a bench run.

    padwindow.py <entries.csv> [--grade FINE|COARSE]

A pad has to cover the widest cost its entry has, so the ceiling is the worst measured case rounded
up to a whole tick and the floor is the narrowest. Prints the idemip_config.h block; it is not
written for you, because a window is a claim about a host and pasting one in should be deliberate.

The unit is the grade's: microseconds at FINE and LITERAL, milliseconds at COARSE. A run measured on
one host says nothing about another, and the entries do not scale by one factor between them - the
ones that walk a structure lose more to a smaller cache than the ones that fold a fixed-width field
- so regenerate rather than multiply.
"""
import io
import math
import sys
from collections import defaultdict


def rows(path):
    """The one CSV block whose header names an entry."""
    out, hdr = [], None
    for line in io.open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if parts[0] == "unit":
            hdr = parts
            continue
        if hdr:
            out.append(dict(zip(hdr, parts)))
    return out


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 2
    path = argv[1]
    grade = "COARSE" if "--grade" in argv and "COARSE" in argv else "FINE"
    column = "ns_per_call"
    per_tick = 1e6 if grade == "COARSE" else 1e3  # nanoseconds in one tick of the grade's unit

    by = defaultdict(list)
    for r in rows(path):
        if r["unit"] == "bench":
            continue  # the empty loop, which is the harness and not an entry
        by[(r["unit"], r["entry"])].append(float(r[column]))
    if not by:
        print(f"{path}: no entry rows", file=sys.stderr)
        return 1

    worst = {k: max(v) / per_tick for k, v in by.items()}
    best = {k: min(v) / per_tick for k, v in by.items()}
    unit = "ms" if grade == "COARSE" else "us"

    ceiling = max(math.ceil(v) for v in worst.values())
    floor = max(1, min(math.ceil(v) for v in worst.values()))

    print(f"// Measured, not chosen. Regenerate with tools/dev_env/padwindow.py at the {grade} grade.")
    print(f"// Widest entry: {max(worst, key=worst.get)[0]}.{max(worst, key=worst.get)[1]}"
          f" at {max(worst.values()):.4f} {unit}.")
    print()
    print("#ifndef IDEMIP_DETERMINISM_PAD_MIN")
    print(f"#define IDEMIP_DETERMINISM_PAD_MIN {floor}u")
    print("#endif")
    print()
    print("#ifndef IDEMIP_DETERMINISM_PAD_MAX")
    print(f"#define IDEMIP_DETERMINISM_PAD_MAX {max(ceiling * 8, 8)}u")
    print("#endif")
    print()
    print("#ifndef IDEMIP_DETERMINISM_PAD_DEFAULT")
    print(f"#define IDEMIP_DETERMINISM_PAD_DEFAULT {ceiling}u")
    print("#endif")
    print()
    print(f"// per entry, {unit}, worst and narrowest measured:")
    for k in sorted(by, key=lambda k: -worst[k]):
        flat = "constant" if worst[k] - best[k] < best[k] * 0.05 else "varies with input"
        print(f"//   {k[0]}.{k[1]:<16} ceil {math.ceil(worst[k])}  "
              f"(worst {worst[k]:.4f}, least {best[k]:.4f}, {flat})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
