#!/usr/bin/env python3
"""Validate the bench output, then report what it was run to answer."""
import csv
import io
import sys
from collections import defaultdict


def load(path, want):
    """Rows of the one CSV block whose header starts with `want`."""
    rows, hdr = [], None
    for line in io.open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        if hdr is None or line.startswith(want.split(",")[0] + ","):
            if line.startswith(want.split(",")[0] + ",") and "," in line and not line[0].isdigit():
                parts = line.split(",")
                if all(not p.replace(".", "").replace("-", "").isdigit() for p in parts[:2]):
                    hdr = parts
                    rows = []
                    continue
        if hdr:
            rows.append(dict(zip(hdr, line.split(","))))
    return rows


def blocks(path):
    """Split the file into (header, rows) blocks; a new header starts a block."""
    out, hdr, rows = [], None, []
    for line in io.open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        looks_like_header = all(not _isnum(p) for p in parts)
        if looks_like_header:
            if hdr:
                out.append((hdr, rows))
            hdr, rows = parts, []
        elif hdr:
            rows.append(dict(zip(hdr, parts)))
    if hdr:
        out.append((hdr, rows))
    return out


def _isnum(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


words_path, entries_path = sys.argv[1], sys.argv[2]

tail_rows, span_rows = [], []
for hdr, rows in blocks(words_path):
    if any("remainder" in h for h in hdr):
        tail_rows = rows
    elif "span" in hdr:
        span_rows = rows

print("=" * 78)
print("VALIDITY")
print("=" * 78)

by = defaultdict(list)
for r in span_rows:
    by[(r["variant"], int(r["span"]))].append(float(r["cycles_per_call"]))
spans = sorted({int(r["span"]) for r in span_rows})
variants = []
for r in span_rows:
    if r["variant"] not in variants:
        variants.append(r["variant"])

nop = {s: min(by[("nop", s)]) for s in spans}
nops = list(nop.values())
print(f"  nop is flat across every span      : {min(nops):.3f} to {max(nops):.3f} cycles"
      f"  ({'PASS' if max(nops) - min(nops) < 0.15 else 'FAIL'})")

b0 = min(float(r["cycles_per_call"]) for r in span_rows
         if r["variant"] == "byte" and int(r["span"]) == 1500 and int(r["density_pct"]) == 0)
b100 = min(float(r["cycles_per_call"]) for r in span_rows
           if r["variant"] == "byte" and int(r["span"]) == 1500
           and int(r["density_pct"]) == 100 and r["distribution"] == "clustered")
print(f"  byte exits early, so density moves it: {b0:.0f} vs {b100:.2f} cycles"
      f"  ({'PASS' if b0 > 50 * b100 else 'FAIL'})")

mono = all(min(by[("w16le", s)]) >= min(by[("w32le", s)]) >= min(by[("w64le", s)]) for s in spans)
print(f"  a wider word is never slower        : {'PASS' if mono else 'FAIL'}")

lin = []
for s in spans:
    if s >= 64:
        lin.append(min(by[("w32le", s)]) / min(by[("w64le", s)]))
print(f"  32->64 halves the work at n >= 64   : {sum(lin)/len(lin):.2f}x mean"
      f"  ({'PASS' if 1.6 <= sum(lin)/len(lin) <= 2.4 else 'CHECK'})")

tl = {r["arm"]: float(r["cycles_per_call"]) for r in tail_rows}
if tl:
    print(f"  the tail is a small constant        : " + ", ".join(f"{k} {v:.2f}" for k, v in tl.items()))

print()
print("=" * 78)
print("SHAPE  -  cycles per call, the loop taken off, vectorizer off")
print("=" * 78)
print(f"{'span':>5} {'w16':>8} {'w32':>8} {'w64':>8}   {'16/32':>6} {'32/64':>6}   "
      f"{'cyc/octet w64':>13}")
for s in spans:
    v = {w: max(min(by[(w + "le", s)]) - nop[s], 1e-9) for w in ("w16", "w32", "w64")}
    print(f"{s:>5} {v['w16']:>8.2f} {v['w32']:>8.2f} {v['w64']:>8.2f}   "
          f"{v['w16']/v['w32']:>5.2f}x {v['w32']/v['w64']:>5.2f}x   {v['w64']/s:>13.3f}")

print()
print("  A word-at-a-time loop costs floor(n/W) bodies plus one tail, so per-octet cost")
print("  should fall as 1/W while n > W, and flatten to the tail alone once W >= n.")

print()
print("=" * 78)
print("ENDIANNESS  -  the tail alone, per remainder")
print("=" * 78)
arms = []
for r in tail_rows:
    if r["arm"] not in arms:
        arms.append(r["arm"])
print(f"{'arm':>7} {'cycles/call':>12}")
for r in tail_rows:
    print(f"{r['arm']:>7} {float(r['cycles_per_call']):>12.3f}")
le = [float(r['cycles_per_call']) for r in tail_rows if r['arm'].endswith('le')]
be = [float(r['cycles_per_call']) for r in tail_rows if r['arm'].endswith('be')]
if le and be:
    print(f"  big-endian arm costs {sum(be)/len(be) - sum(le)/len(le):+.3f} cycles more, averaged")

print()
print("=" * 78)
print("SPREAD  -  what a determinism pad must cover")
print("=" * 78)
print(f"{'variant':>7} {'span':>5} {'min cyc':>9} {'max cyc':>9} {'spread':>9} {'spread %':>9}")
for v in variants:
    for s in (16, 1500):
        vals = by[(v, s)]
        lo, hi = min(vals), max(vals)
        print(f"{v:>7} {s:>5} {lo:>9.3f} {hi:>9.3f} {hi-lo:>9.3f} "
              f"{(hi-lo)/lo*100 if lo else 0:>8.1f}%")

print()
print("=" * 78)
print("ENTRIES  -  the library's own, its own flags, vectorizer on")
print("=" * 78)
erows = []
for hdr, rows in blocks(entries_path):
    if "entry" in hdr:
        erows = rows
eby = defaultdict(list)
for r in erows:
    eby[(r["unit"], r["entry"])].append((float(r["cycles_per_call"]), float(r["ns_per_call"])))
print(f"{'unit':>10} {'entry':>16} {'min cyc':>9} {'max cyc':>9} {'spread':>9} {'spread %':>9} {'max us':>8}")
for k, v in eby.items():
    cyc = [c for c, _ in v]
    ns = [n for _, n in v]
    lo, hi = min(cyc), max(cyc)
    print(f"{k[0]:>10} {k[1]:>16} {lo:>9.1f} {hi:>9.1f} {hi-lo:>9.1f} "
          f"{(hi-lo)/lo*100 if lo else 0:>8.1f}% {max(ns)/1000.0:>8.4f}")
