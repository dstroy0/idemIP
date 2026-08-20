#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Write the parts of docs/index.html that are facts about this tree, from this tree.

README.md printed a footprint of 20328 / 4976 / 30280 while idemip_sizes printed 20872 / 5376 /
31624, and nothing in the repository noticed. idemip_config.h predicted exactly that in its own
comment - "a number in this comment goes stale the moment it is right, and one already had" - and
then the README went stale anyway, because a number typed into prose has nothing holding it.

A documentation page is worse than a README for this. It is longer, it is read by people who cannot
check it against the source, and it is the first thing anyone sees. So the parts of it that are
facts are not typed: every region between

    <!-- docsgen:NAME -->  ...  <!-- /docsgen:NAME -->

is generated here and overwritten in place. Everything outside those markers is prose, is written by
hand, and is never touched.

    python tools/dev_env/docsgen.py             what would change
    python tools/dev_env/docsgen.py --write     write it
    python tools/dev_env/docsgen.py --check     exit nonzero when a region is out of date

--check is the CI shape, beside guards.py, counters.py and deadstate.py. It needs idemip_sizes to
have been built, because the footprint is the compiler's arithmetic and not this script's:

    cmake --build ../build --target idemip_sizes

WHERE EACH REGION COMES FROM

    stats         the tree: translation units, headers, suites, cases, lines, vendored RFCs
    footprint     tools/idemip_sizes, run - every borrow term and the two sums, to scale
    capabilities  CMakeLists.txt - the tree, the options and the refusal strings, verbatim
    units         src/idemip.h's include list for the layer and the RFCs each unit is for, then
                  each header for its namespace, its entries and its borrow
    law           docs/learn/RFC - one chip per vendored RFC, linked to the text itself
    suites        test/harness.py suites

The unit cards come off the front door rather than a directory walk because src/idemip.h already
groups every header by layer and names what each one is for, in a comment maintained beside the
include. A walk would have to invent both.
"""
import argparse
import collections
import html
import io
import os
import re
import subprocess
import sys

ROOT = os.getcwd()
PAGE = os.path.join("docs", "index.html")
FRONT = os.path.join("src", "idemip.h")
RFC_DIR = os.path.join("docs", "learn", "RFC")

MARK = "<!-- docsgen:{} -->"
ENDMARK = "<!-- /docsgen:{} -->"

LAYER_RULE = re.compile(r"^//\s*---\s*(.+?)\s*-{3,}\s*$")
INCLUDE = re.compile(r'^#include\s+"(src/[^"]+)"\s*(?://\s*(.*))?$')
TABLE = re.compile(r"^static const (\w+Ns) (\w+) IDEMIP_UNUSED = \{", re.M)
TYPEDEF = re.compile(r"typedef struct\s*\{(.*?)\}\s*(\w+Ns);", re.S)
ENTRY = re.compile(r"void \(\*const (\w+)\)\(uint8_t \*restrict work\);")
BRIEF = re.compile(r"@brief\s+(.+?)(?:\n\s*\*\s*\n|\n\s*\*/)", re.S)
# A header MENTIONS several borrows - tick.h names the dma and nd6 ones its bind takes, rdnss.h and
# slaac.h name the phy one describing the shape - and none of them is defined here, because all 46
# are defined in idemip_config.h. What a header does carry once is its own operand block, so the
# unit whose OFF_IO this is, is the unit whose borrow this is. It survives the names that do not
# transliterate: ArpTable is IDEMIP_ARP_BORROW and UdpLite is IDEMIP_UDPLITE_BORROW.
BORROW_OWN = re.compile(r"^#define IDEMIP_([A-Z0-9_]+)_OFF_IO\b", re.M)
RFC_REF = re.compile(r"\bRFC\s*(\d{1,4})\b")

SIZE_TERM = re.compile(r"^\s{2}(IDEMIP_[A-Z0-9_]+_BORROW)\s+(\d+)\s*$")
SIZE_SUM = re.compile(r"^\s*=\s*(IDEMIP_[A-Z0-9_]+)\s+(\d+)(?:\s+x\s+(\d+))?\s*$")
SIZE_TOTAL = re.compile(r"^\s*(IDEMIP_TOTAL_BORROW)\s+(\d+)\s*$")

# The three sums are spelled like every other term and would be read as one. TOTAL in particular
# is indented exactly as a per-interface term is, so it lands in that section and the section
# comes back with one row too many.
SIZE_SUMS = {"IDEMIP_TOTAL_BORROW", "IDEMIP_SHARED_BORROW", "IDEMIP_PER_NETIF_BORROW"}

ROOT_OPT = re.compile(r'add_root_option\((\w+)\s+"([^"]*)"\s+(ON|OFF)\)')
CHILD_OPT = re.compile(r'add_child_option\((\w+)\s+"([^"]*)"\s+(ON|OFF)\s*\n\s*"([^"]*)"\s*\n\s*([\w\s]+?)\)', re.M)

E = html.escape


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# The tree
# ---------------------------------------------------------------------------


def front_door():
    """(layer, header, comment) for every include in src/idemip.h, in file order."""
    layer, out = None, []
    for line in read(FRONT).splitlines():
        rule = LAYER_RULE.match(line.strip())
        if rule:
            layer = rule.group(1)
            continue
        inc = INCLUDE.match(line.strip())
        if inc and layer:
            out.append((layer, inc.group(1), (inc.group(2) or "").strip()))
    return out


def unit(rel):
    """What a header publishes: its namespace, its entries, its borrow macro and its brief."""
    text = read(rel)
    tables = TABLE.findall(text)
    brief = BRIEF.search(text)
    brief = re.sub(r"\s*\*\s*", " ", brief.group(1)).strip() if brief else ""
    # The RFCs a card shows: the ones the front door names for this header, else the ones the
    # header cites most. phy.h and dma.h are the reason for the second - the front-door comment
    # for each is about the driver contract and names no RFC, so the card had nothing on it.
    ranked = [n for n, _ in collections.Counter(RFC_REF.findall(text)).most_common()]
    if not tables:
        return {"ns": None, "entries": [], "borrow": None, "brief": brief, "ranked": ranked}
    type_name, ns_name = tables[0]
    body = next((m.group(1) for m in TYPEDEF.finditer(text) if m.group(2) == type_name), "")
    own = BORROW_OWN.search(text)
    return {
        "ns": ns_name,
        "entries": ENTRY.findall(body),
        "borrow": "IDEMIP_{}_BORROW".format(own.group(1)) if own else None,
        "brief": brief,
        "ranked": ranked,
    }


def sizes():
    """Run idemip_sizes and read back every borrow term and the sums."""
    exe = None
    for candidate in ("../build/idemip_sizes.exe", "../build/idemip_sizes",
                      "build/idemip_sizes.exe", "build/idemip_sizes"):
        path = os.path.join(ROOT, candidate)
        if os.path.exists(path):
            exe = path
            break
    if exe is None:
        sys.exit(
            "idemip_sizes is not built, and the footprint is its arithmetic rather than this "
            "script's.\n    cmake --build ../build --target idemip_sizes"
        )
    out = subprocess.run([exe], capture_output=True, text=True, check=True).stdout

    shared, per_netif, sums, section = [], [], {}, None
    for line in out.splitlines():
        if line.startswith("shared,"):
            section = shared
            continue
        if line.startswith("per interface"):
            section = per_netif
            continue
        total = SIZE_TOTAL.match(line)
        if total:
            sums["IDEMIP_TOTAL_BORROW"] = int(total.group(2))
            continue
        term = SIZE_TERM.match(line)
        if term and section is not None and term.group(1) not in SIZE_SUMS:
            section.append((term.group(1), int(term.group(2))))
            continue
        summ = SIZE_SUM.match(line)
        if summ:
            sums[summ.group(1)] = int(summ.group(2))
            if summ.group(3):
                sums["IDEMIP_NETIF_COUNT"] = int(summ.group(3))
    return {"shared": shared, "per_netif": per_netif, "sums": sums,
            "bytes": dict(shared + per_netif)}


def capabilities():
    """The feature tree as CMakeLists.txt declares it, refusal strings and all."""
    text = read("CMakeLists.txt")
    root = ROOT_OPT.search(text)
    out = [{"name": root.group(1), "doc": root.group(2), "default": root.group(3),
            "why": "", "parents": []}]
    for m in CHILD_OPT.finditer(text):
        out.append({
            "name": m.group(1), "doc": m.group(2), "default": m.group(3),
            "why": m.group(4), "parents": m.group(5).split(),
        })
    return out


def matrix_tags():
    """The capability sets CI actually builds, each with the four flags it sets.

    The page names the set a reader's selection corresponds to, so it has to carry the flags and
    not just the tag. ETHERNET is not in the matrix because it is the root and every entry has it.
    """
    text = read(os.path.join(".github", "workflows", "capabilities.yml"))
    out = []
    for m in re.finditer(
        r"\{\s*tag:\s*([\w-]+),\s*ipv4:\s*\"(ON|OFF)\",\s*ipv6:\s*\"(ON|OFF)\","
        r"\s*tcp:\s*\"(ON|OFF)\",\s*udp:\s*\"(ON|OFF)\"\s*\}", text
    ):
        out.append({
            "tag": m.group(1),
            "IDEMIP_ENABLE_ETHERNET": True,
            "IDEMIP_ENABLE_IPV4": m.group(2) == "ON",
            "IDEMIP_ENABLE_IPV6": m.group(3) == "ON",
            "IDEMIP_ENABLE_TCP": m.group(4) == "ON",
            "IDEMIP_ENABLE_UDP": m.group(5) == "ON",
        })
    return out


def rfcs():
    """Every vendored RFC, with the title docs/learn/RFC/README.md gives it."""
    titles = {}
    for num, title in re.findall(r"\|\s*\[(\d+)\]\([^)]+\)\s*\|\s*(.+?)\s*\|",
                                 read(os.path.join(RFC_DIR, "README.md"))):
        titles[num] = title
    have = sorted(
        (m.group(1) for m in (re.match(r"rfc(\d+)\.txt$", n)
                              for n in os.listdir(os.path.join(ROOT, RFC_DIR))) if m),
        key=int,
    )
    return [(n, titles.get(n, "")) for n in have]


def cited():
    """How many times each RFC is cited across src/, so the busiest can be marked."""
    count = collections.Counter()
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "src")):
        dirnames[:] = sorted(dirnames)
        for name in sorted(filenames):
            if name.endswith((".c", ".h")):
                with io.open(os.path.join(dirpath, name), encoding="utf-8") as handle:
                    count.update(RFC_REF.findall(handle.read()))
    return count


def suites():
    """Every CTest suite, its case count and the capabilities it needs."""
    out = subprocess.run([sys.executable, os.path.join("test", "harness.py"), "suites"],
                         capture_output=True, text=True, cwd=ROOT).stdout
    rows = []
    for line in out.splitlines():
        m = re.match(r"^(\S+)\s+(\d+) cases\s+(.*?)\s*$", line)
        if m:
            caps = m.group(3).strip()
            rows.append((m.group(1), int(m.group(2)), "" if caps == "-" else caps))
    return rows


def tree_stats():
    """Counts the page states about itself."""
    units = headers = src_lines = test_lines = 0
    for base, is_src in ((os.path.join(ROOT, "src"), True), (os.path.join(ROOT, "test"), False)):
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in sorted(dirnames) if d != "__pycache__"]
            for name in sorted(filenames):
                # unity_runner.c is generated by harness.py from the suite beside it, so counting
                # it would report the generator's output as test somebody wrote.
                if not name.endswith((".c", ".h")) or name == "unity_runner.c":
                    continue
                with io.open(os.path.join(dirpath, name), encoding="utf-8", errors="replace") as f:
                    n = sum(1 for _ in f)
                if is_src:
                    units += name.endswith(".c")
                    headers += name.endswith(".h")
                    src_lines += n
                else:
                    test_lines += n
    return {"units": units, "headers": headers, "src_lines": src_lines, "test_lines": test_lines}


# ---------------------------------------------------------------------------
# The regions
# ---------------------------------------------------------------------------


def bar(width_pct, label, value, kind):
    return ('<div class="bar {}" style="--w:{:.4f}%" title="{} - {} bytes">'
            '<span class="bar-l">{}</span><span class="bar-v">{}</span></div>').format(
        kind, width_pct, E(label), value, E(label), value)


def region_stats(data):
    s, f, r = data["tree"], data["sizes"], data["rfcs"]
    total = f["sums"].get("IDEMIP_TOTAL_BORROW", 0)
    cells = [
        ("{:,}".format(total), "bytes of .bss", "IDEMIP_TOTAL_BORROW, at the counts in idemip_config.h"),
        ("0", "heap allocations", "there is no <code>&lt;stdlib.h&gt;</code> anywhere in <code>src/</code>"),
        (str(s["units"]), "translation units", "{} headers, {:,} lines".format(s["headers"], s["src_lines"])),
        ("{:,}".format(s["test_lines"]), "lines of test", "against {:,} lines of library".format(s["src_lines"])),
        (str(len(data["suites"])), "CTest suites", "{:,} cases".format(sum(n for _, n, _ in data["suites"]))),
        (str(len(r)), "RFCs vendored", "the text every rule is written against"),
    ]
    return "\n".join(
        '<div class="stat"><b>{}</b><span>{}</span><em>{}</em></div>'.format(v, E(k), note)
        for v, k, note in cells
    )


def region_footprint(data):
    f = data["sizes"]
    total = f["sums"].get("IDEMIP_TOTAL_BORROW", 1)
    count = f["sums"].get("IDEMIP_NETIF_COUNT", 1)
    shared_sum = f["sums"].get("IDEMIP_SHARED_BORROW", 0)
    per_sum = f["sums"].get("IDEMIP_PER_NETIF_BORROW", 0)

    out = ['<div class="map" role="img" aria-label="every borrow, to scale, summing to '
           '{} bytes">'.format(total)]
    for name, value in f["shared"]:
        out.append(bar(100.0 * value / total, name, value, "shared"))
    for _ in range(count):
        for name, value in f["per_netif"]:
            out.append(bar(100.0 * value / total, name, value, "netif"))
    out.append("</div>")

    out.append('<table class="terms"><thead><tr><th>borrow</th><th class="n">bytes</th>'
               '<th class="n">share</th></tr></thead><tbody>')
    out.append('<tr class="grp"><th colspan="3">shared, one table across every interface</th></tr>')
    for name, value in f["shared"]:
        out.append('<tr><td><code>{}</code></td><td class="n">{:,}</td>'
                   '<td class="n">{:.1f}%</td></tr>'.format(name, value, 100.0 * value / total))
    out.append('<tr class="sum"><td><code>IDEMIP_SHARED_BORROW</code></td>'
               '<td class="n">{:,}</td><td class="n">{:.1f}%</td></tr>'.format(
                   shared_sum, 100.0 * shared_sum / total))
    out.append('<tr class="grp"><th colspan="3">per interface, taken IDEMIP_NETIF_COUNT '
               '({}) times</th></tr>'.format(count))
    for name, value in f["per_netif"]:
        out.append('<tr><td><code>{}</code></td><td class="n">{:,}</td>'
                   '<td class="n">{:.1f}%</td></tr>'.format(
                       name, value, 100.0 * value * count / total))
    out.append('<tr class="sum"><td><code>IDEMIP_PER_NETIF_BORROW</code> &times; {}</td>'
               '<td class="n">{:,}</td><td class="n">{:.1f}%</td></tr>'.format(
                   count, per_sum * count, 100.0 * per_sum * count / total))
    out.append('<tr class="total"><td><code>IDEMIP_TOTAL_BORROW</code></td>'
               '<td class="n">{:,}</td><td class="n">100%</td></tr>'.format(total))
    out.append("</tbody></table>")
    return "\n".join(out)


def region_capabilities(data):
    caps = data["capabilities"]
    out = ['<div class="caps" id="caps">']
    for c in caps:
        out.append(
            '<label class="cap" data-cap="{name}" data-parents="{parents}">'
            '<input type="checkbox" checked data-name="{name}">'
            '<span class="cap-n">{name}</span>'
            '<span class="cap-d">{doc}</span></label>'.format(
                name=c["name"], parents=" ".join(c["parents"]), doc=E(c["doc"])))
    out.append("</div>")
    out.append('<script type="application/json" id="cap-data">{}</script>'.format(
        _json(caps)))
    out.append('<script type="application/json" id="matrix-data">{}</script>'.format(
        _json(data["matrix"])))
    return "\n".join(out)


def _json(obj):
    import json
    return json.dumps(obj, separators=(",", ":")).replace("</", "<\\/")


def region_units(data):
    groups = collections.OrderedDict()
    for layer, rel, comment in data["front"]:
        groups.setdefault(layer, []).append((rel, comment))

    out = []
    for layer, items in groups.items():
        out.append('<h3 class="layer">{}</h3><div class="cards">'.format(E(layer)))
        for rel, comment in items:
            u = data["units"][rel]
            refs = (RFC_REF.findall(comment) or RFC_REF.findall(u["brief"])
                    or u["ranked"][:3])
            chips = "".join(
                '<a class="rfc" href="learn/RFC/rfc{n}.txt">RFC {n}</a>'.format(n=n)
                for n in list(dict.fromkeys(refs))[:4] if n in data["have_rfc"])
            size = data["sizes"]["bytes"].get(u["borrow"]) if u["borrow"] else None
            if u["ns"]:
                head = '<b>{}</b><span class="hdr">{}</span>'.format(E(u["ns"]), E(rel))
                body = '<div class="entries">{}</div>'.format(
                    "".join('<code>{}</code>'.format(E(e)) for e in u["entries"]))
                foot = ('<div class="borrow"><code>{}</code><span>{}</span></div>'.format(
                    u["borrow"], "{:,} bytes".format(size) if size is not None
                    else "per build") if u["borrow"] else "")
            else:
                head = '<b>{}</b><span class="hdr">{}</span>'.format(
                    E(os.path.basename(rel)), E(rel))
                body = '<div class="entries none">header only - no state, no borrow</div>'
                foot = ""
            out.append('<article class="card{}"><header>{}</header>{}{}'
                       '<footer>{}</footer></article>'.format(
                           "" if u["ns"] else " plain", head, body, foot, chips))
        out.append("</div>")
    return "\n".join(out)


def clipped(title, width=90):
    """The title, cut at the last word that fits, so a chip never ends mid-word."""
    if len(title) <= width:
        return title
    cut = title[:width]
    space = cut.rfind(" ")
    return (cut if space < 0 else cut[:space]).rstrip(" ,:;-") + "…"


def region_law(data):
    out = ['<div class="law">']
    for num, title in data["rfcs"]:
        n = data["cited"].get(num, 0)
        # The chip is one line wide and the long titles do not fit, but the hover has no width to
        # run out of, so it carries the whole thing.
        out.append(
            '<a class="lex{hot}" href="learn/RFC/rfc{n}.txt" title="{full}">'
            '<b>{n}</b><span>{t}</span></a>'.format(
                n=num, t=E(clipped(title)), full=E(title), hot=" hot" if n >= 10 else ""))
    out.append("</div>")
    return "\n".join(out)


def region_suites(data):
    rows = data["suites"]
    out = ['<table class="suites"><thead><tr><th>suite</th><th class="n">cases</th>'
           '<th>capabilities it drives</th></tr></thead><tbody>']
    for path, cases, caps in rows:
        chips = "".join('<span class="cc">{}</span>'.format(E(c)) for c in caps.split()) \
            or '<span class="cc any">any build</span>'
        out.append('<tr><td><code>{}</code></td><td class="n">{}</td><td>{}</td></tr>'.format(
            E(path), cases, chips))
    out.append('<tr class="total"><td>{} suites</td><td class="n">{:,}</td><td></td></tr>'.format(
        len(rows), sum(n for _, n, _ in rows)))
    out.append("</tbody></table>")
    return "\n".join(out)


REGIONS = {
    "stats": region_stats,
    "footprint": region_footprint,
    "capabilities": region_capabilities,
    "units": region_units,
    "law": region_law,
    "suites": region_suites,
}


def gather():
    front = front_door()
    have = {n for n, _ in rfcs()}
    return {
        "front": front,
        "units": {rel: unit(rel) for _, rel, _ in front},
        "sizes": sizes(),
        "capabilities": capabilities(),
        "matrix": matrix_tags(),
        "rfcs": rfcs(),
        "have_rfc": have,
        "cited": cited(),
        "suites": suites(),
        "tree": tree_stats(),
    }


def apply(page, data):
    """The page with every marked region replaced. Prose outside the markers is untouched."""
    for name, build in REGIONS.items():
        open_m, close_m = MARK.format(name), ENDMARK.format(name)
        if open_m not in page:
            sys.exit("{} has no {} region".format(PAGE, open_m))
        start = page.index(open_m) + len(open_m)
        end = page.index(close_m)
        page = page[:start] + "\n" + build(data) + "\n" + page[end:]
    return page


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="write the regions")
    mode.add_argument("--check", action="store_true", help="exit nonzero when out of date")
    args = ap.parse_args()

    page = read(PAGE)
    data = gather()
    updated = apply(page, data)

    if updated == page:
        print("docs/index.html is up to date with the tree")
        return 0
    if args.write:
        with io.open(os.path.join(ROOT, PAGE), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(updated)
        print("wrote {} region(s) into {}".format(len(REGIONS), PAGE))
        return 0
    print("{} is out of date - run `python tools/dev_env/docsgen.py --write`".format(PAGE))
    return 1 if args.check else 0


if __name__ == "__main__":
    sys.exit(main())
