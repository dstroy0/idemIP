#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which MIB counters this library reaches, and which it carries without reaching.

src/core/stats.h carries the field sets of six MIB groups because the id block is the MIB's shape
and not this library's, so a counter with no event to reach it is still carried. That is a real
decision and it has a real failure mode: a counter nothing writes reads zero forever, and a manager
cannot tell "no traffic" from "not counted". The only defence is knowing exactly which ones those
are, and the file said "the out counters of both groups" on the IPv6 side when the whole library was
that way, including four IPv4 out counters and every counter of the two IPv6 groups' twins.

So the list is not prose. This computes the unreachable set from the source and compares it to the
register below, and a counter that goes dead, or comes alive, or is added to the enum and never
wired, changes the set and fails here.

src/core/stats.c is excluded from the scan: it is the unit that STORES counters, and the three ids
it names are its own gauge predicates rather than any event.

    python tools/dev_env/counters.py

Exits nonzero when the set has moved, so CI can run it as a gate.
"""
import os
import re
import sys

ROOT = os.getcwd()
STATS_H = "src/core/stats.h"
STATS_C = "src/core/stats.c"

ID = re.compile(r"\bIDEMIP_STAT_[A-Z0-9_]+\b")
SKIP = {"IDEMIP_STAT_COUNT", "IDEMIP_STAT_IF_COUNT"}

# ---------------------------------------------------------------------------
# The register
# ---------------------------------------------------------------------------
# Three reasons a counter is carried and never written, and no fourth. Every id below is one this
# library cannot raise an event for; every id NOT below has to be written somewhere in src/.

# RFC 1155 sec 3.2.3.4 gauges, which StatsNs::set writes and no event bumps. Each is read off the
# thing it measures rather than accumulated: ifSpeed off the PHY's link state, ifOutQLen off the
# driver's transmit queue, tcpCurrEstab off the TCB table, which is a count of rows in a state and
# not a running total. Tracking a gauge by deltas drifts - tcpCurrEstab would need every departure
# from ESTABLISHED, and a close the caller starts is not a segment dispatch sees.
GAUGES = """
IF_SPEED IF_OUT_QLEN TCP_CURR_ESTAB
"""

# RFC 1122 sec 3.2.2.9 leaves the Address Mask pair optional and this library does not carry it, so
# neither direction has a message, let alone a count. The only ids here that are not a send path.
NO_MESSAGE = """
ICMP4_IN_ADDR_MASKS ICMP4_IN_ADDR_MASK_REPS ICMP4_OUT_ADDR_MASKS ICMP4_OUT_ADDR_MASK_REPS
"""

# The send path, which dispatch does not own. Dispatch holds the stats borrow and walks one frame
# IN; what goes out is the caller's, driving IcmpIn.error, Ip4Frag, Ip6Frag, Ip4Forward, Ip6Forward,
# TcpOut, the ND and MLD senders and the DMA engine, and the caller holds that same borrow and can
# reach StatsNs::bump for every one of them. Note which ids are here rather than which names read
# _OUT_: RFC 2465 counts a failed route and an oversized forward on the way IN
# (ipv6IfStatsInNoRoutes, InTooBigErrors) where RFC 1213 counts the first on the way out
# (ipOutNoRoutes), and both belong to the forwarder either way.
SEND_PATH = """
IP4_FORW_DATAGRAMS IP4_OUT_REQUESTS IP4_OUT_DISCARDS IP4_OUT_NO_ROUTES
IP4_FRAG_OKS IP4_FRAG_FAILS IP4_FRAG_CREATES IP4_ROUTING_DISCARDS

ICMP4_OUT_ERRORS ICMP4_OUT_DEST_UNREACHS ICMP4_OUT_TIME_EXCDS ICMP4_OUT_PARM_PROBS
ICMP4_OUT_SRC_QUENCHS ICMP4_OUT_REDIRECTS ICMP4_OUT_ECHOS
ICMP4_OUT_TIMESTAMPS ICMP4_OUT_TIMESTAMP_REPS

IP6_IN_TOO_BIG_ERRORS IP6_IN_NO_ROUTES IP6_OUT_FORW_DATAGRAMS IP6_OUT_REQUESTS IP6_OUT_DISCARDS
IP6_OUT_FRAG_OKS IP6_OUT_FRAG_FAILS IP6_OUT_FRAG_CREATES IP6_OUT_MCAST_PKTS

ICMP6_OUT_ERRORS ICMP6_OUT_DEST_UNREACHS ICMP6_OUT_ADMIN_PROHIBS ICMP6_OUT_TIME_EXCDS
ICMP6_OUT_PARM_PROBLEMS ICMP6_OUT_PKT_TOO_BIGS ICMP6_OUT_ECHOS
ICMP6_OUT_ROUTER_SOLICITS ICMP6_OUT_ROUTER_ADVERTISEMENTS
ICMP6_OUT_NEIGHBOR_SOLICITS ICMP6_OUT_NEIGHBOR_ADVERTISEMENTS ICMP6_OUT_REDIRECTS
ICMP6_OUT_GROUP_MEMB_QUERIES ICMP6_OUT_GROUP_MEMB_RESPONSES ICMP6_OUT_GROUP_MEMB_REDUCTIONS

TCP_ACTIVE_OPENS TCP_ATTEMPT_FAILS TCP_ESTAB_RESETS TCP_OUT_SEGS TCP_RETRANS_SEGS

UDP_OUT_DATAGRAMS

IF_OUT_OCTETS IF_OUT_UCAST_PKTS IF_OUT_NUCAST_PKTS IF_OUT_DISCARDS IF_OUT_ERRORS
"""

# The out counters dispatch DOES reach, held here as a positive claim: these five name messages this
# library builds itself, so a caller could not count them without re-parsing what dispatch just
# built. One going quiet is as much a finding as a new dead counter.
BUILT = """
TCP_OUT_RSTS
ICMP4_OUT_MSGS ICMP4_OUT_ECHO_REPS
ICMP6_OUT_MSGS ICMP6_OUT_ECHO_REPLIES
"""


def ids(block):
    return {"IDEMIP_STAT_" + name for name in block.split()}


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def declared():
    """Every counter id the enums declare, in stats.h."""
    return {name for name in ID.findall(read(STATS_H)) if name not in SKIP}


def written():
    """Every counter id some translation unit names, stats.c aside."""
    out = set()
    for dirpath, _, names in os.walk(os.path.join(ROOT, "src")):
        for name in sorted(names):
            if not name.endswith(".c"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")
            if rel == STATS_C:
                continue
            out |= {n for n in ID.findall(read(rel)) if n not in SKIP}
    return out


def report(title, names):
    for name in sorted(names):
        print(f"  {name[len('IDEMIP_STAT_'):]}")
    print(f"{len(names)} counter(s) {title}\n")


def main():
    have = declared()
    live = written() & have
    dead = have - live

    register = ids(GAUGES) | ids(NO_MESSAGE) | ids(SEND_PATH)
    built = ids(BUILT)

    unknown = (register | built) - have
    if unknown:
        print("the register names ids stats.h does not declare:")
        report("are not in the enum", unknown)
        return 1

    bad = 0
    # A BUILT id gone quiet is reported once, below, where the message says which site was lost.
    newly_dead = dead - register - built
    if newly_dead:
        print("carried and never written, and not in the register:")
        report("read zero forever with no reason on record", newly_dead)
        bad += len(newly_dead)

    newly_live = register & live
    if newly_live:
        print("in the register as unreachable, and written anyway:")
        report("are reachable now, so the register is stale", newly_live)
        bad += len(newly_live)

    quiet = built - live
    if quiet:
        print("claimed as built by this library, and written by nothing:")
        report("lost the only site that wrote them", quiet)
        bad += len(quiet)

    if bad:
        return 1

    print(f"{len(have)} counters: {len(live)} written, {len(dead)} carried for the MIB's shape")
    print(f"  {len(ids(GAUGES))} gauges the caller sets, {len(ids(NO_MESSAGE))} with no message in "
          f"this library, {len(ids(SEND_PATH))} on the caller's send path")
    print(f"  and {len(built)} out counters dispatch builds the message for, so writes itself")
    return 0


if __name__ == "__main__":
    sys.exit(main())
