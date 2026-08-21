#!/usr/bin/env python3
# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Write the seed corpus fuzz_dispatch.c starts from.

  seed_corpus.py <dir>     write one file per seed into <dir>

A corpus is normally a directory of bytes nobody can read. These are written by a program instead,
so each seed carries the clause it is a case of and a reader can check it against the document -
the same rule the rest of the tree is under. A seed is not a test: it is a frame far enough in that
the mutations after it start from somewhere the walk has to answer, rather than from noise the
first length check turns away.

The file format is fuzz_dispatch.c's: a two-octet big-endian length, that many octets, repeated. A
seed of several records is a sequence the walk carries state across.
"""

import os
import struct
import sys

LOCAL_MAC = bytes.fromhex("0200 5E10 0001".replace(" ", ""))
REMOTE_MAC = bytes.fromhex("0200 5E10 0002".replace(" ", ""))
BROADCAST = b"\xff" * 6

# RFC 5737 sec 3's TEST-NET-1 and RFC 3849's documentation prefix: no seed names a host that exists.
LOCAL_IP4 = bytes([192, 0, 2, 1])
REMOTE_IP4 = bytes([192, 0, 2, 9])
LOCAL_IP6 = bytes.fromhex("20010db8000000000000000000000001")
REMOTE_IP6 = bytes.fromhex("20010db8000000000000000000000009")

UDP_PORT = 5001
TCP_PORT = 5002
EPHEMERAL = 40000

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100


def ones_complement(data):
    """RFC 1071 sec 1: "the 16-bit one's complement of the one's complement sum"."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def pseudo4(src, dst, proto, length):
    """RFC 768's pseudo header: the addresses, the protocol and the length, and nothing else."""
    return src + dst + bytes([0, proto]) + struct.pack("!H", length)


def pseudo6(src, dst, length, nh):
    """RFC 8200 sec 8.1's pseudo-header, which puts the Next Header in the last of four zero octets."""
    return src + dst + struct.pack("!I", length) + b"\x00\x00\x00" + bytes([nh])


def eth(dst, src, ethertype):
    return dst + src + struct.pack("!H", ethertype)


def vlan(dst, src, ethertype, vid, pcp=0):
    """IEEE 802.1Q: the tag stands where the EtherType was, and the EtherType moves behind it."""
    tci = (pcp << 13) | vid
    return dst + src + struct.pack("!HHH", ETHERTYPE_VLAN, tci, ethertype)


def ip4(proto, payload, src=REMOTE_IP4, dst=LOCAL_IP4, ident=0x1234, flags=0, offset=0, ttl=64):
    total = 20 + len(payload)
    frag = (flags << 13) | offset
    head = struct.pack("!BBHHHBBH", 0x45, 0, total, ident, frag, ttl, proto, 0) + src + dst
    head = head[:10] + struct.pack("!H", ones_complement(head)) + head[12:]
    return head + payload


def ip6(nh, payload, src=REMOTE_IP6, dst=LOCAL_IP6, hops=64):
    return struct.pack("!IHBB", 0x60000000, len(payload), nh, hops) + src + dst + payload


def udp(payload, sport=EPHEMERAL, dport=UDP_PORT, src=REMOTE_IP4, dst=LOCAL_IP4, v6=False):
    length = 8 + len(payload)
    head = struct.pack("!HHHH", sport, dport, length, 0)
    ph = pseudo6(src, dst, length, 17) if v6 else pseudo4(src, dst, 17, length)
    ck = ones_complement(ph + head + payload)
    return head[:6] + struct.pack("!H", ck or 0xFFFF) + payload


def tcp(flags, payload=b"", seq=0x10000000, ack=0, sport=EPHEMERAL, dport=TCP_PORT,
        src=REMOTE_IP4, dst=LOCAL_IP4, window=8192):
    head = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, window, 0, 0)
    ph = pseudo4(src, dst, 6, len(head) + len(payload))
    ck = ones_complement(ph + head + payload)
    return head[:16] + struct.pack("!H", ck) + head[18:] + payload


def icmp4(type_, code, rest, payload=b""):
    head = struct.pack("!BBHI", type_, code, 0, rest)
    ck = ones_complement(head + payload)
    return head[:2] + struct.pack("!H", ck) + head[4:] + payload


def icmp6(type_, code, body, src=REMOTE_IP6, dst=LOCAL_IP6):
    head = struct.pack("!BBH", type_, code, 0)
    ck = ones_complement(pseudo6(src, dst, len(head) + len(body), 58) + head + body)
    return head[:2] + struct.pack("!H", ck) + body


def solicited_node(addr):
    """RFC 4291 sec 2.7.1: FF02::1:FF00:0/104 with the low 24 bits of the address appended."""
    return bytes.fromhex("ff0200000000000000000001ff") + addr[13:]


def record(*frames):
    out = b""
    for f in frames:
        out += struct.pack("!H", len(f)) + f
    return out


def seeds():
    """Each seed, as (name, bytes, the clause it is a case of)."""
    s = []

    # --- RFC 826, the link layer's own protocol -------------------------------
    arp_req = struct.pack("!HHBBH", 1, ETHERTYPE_IPV4, 6, 4, 1) + REMOTE_MAC + REMOTE_IP4 + b"\x00" * 6 + LOCAL_IP4
    s.append(("arp_request", record(eth(BROADCAST, REMOTE_MAC, ETHERTYPE_ARP) + arp_req),
              "RFC 826: a REQUEST for this node's protocol address, which the second step answers"))
    arp_rep = struct.pack("!HHBBH", 1, ETHERTYPE_IPV4, 6, 4, 2) + REMOTE_MAC + REMOTE_IP4 + LOCAL_MAC + LOCAL_IP4
    s.append(("arp_reply", record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_ARP) + arp_rep),
              "RFC 826: the REPLY that merges the pair the request asked for"))

    # --- RFC 791 and what rides on it ----------------------------------------
    s.append(("ip4_udp", record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4) + ip4(17, udp(b"idemip"))),
              "RFC 768: a datagram to a bound port, which is delivered"))
    s.append(("ip4_udp_unbound",
              record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4) + ip4(17, udp(b"x", dport=9999))),
              "RFC 1122 sec 4.1.3.1: no binding, so udpNoPorts and an ICMP Port Unreachable"))
    s.append(("ip4_icmp_echo",
              record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4) + ip4(1, icmp4(8, 0, 0x00010001, b"abcdefgh"))),
              "RFC 792: an Echo Request, which is answered with an Echo Reply"))

    # Two fragments of one datagram, in order. The reassembler holds the first and completes on the
    # second, which is a state one frame cannot reach.
    whole = udp(b"A" * 32)
    first = ip4(17, whole[:24], flags=1, offset=0, ident=0x2222)
    second = ip4(17, whole[24:], flags=0, offset=3, ident=0x2222)
    s.append(("ip4_fragments",
              record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4) + first,
                     eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4) + second),
              "RFC 791 sec 3.2: two fragments of one datagram, the second completing it"))

    s.append(("ip4_igmp_query",
              record(eth(bytes.fromhex("01005e000001"), REMOTE_MAC, ETHERTYPE_IPV4)
                     + ip4(2, icmp4(0x11, 0, 0) + b"\x00" * 0, ttl=1)),
              "RFC 2236 sec 2.1: a Membership Query, whose checksum sec 2.3 says MUST be verified"))

    # RFC 1042: the same datagram behind an 802.3 length and a SNAP header.
    payload = ip4(17, udp(b"snap"))
    snap = b"\xaa\xaa\x03\x00\x00\x00" + struct.pack("!H", ETHERTYPE_IPV4) + payload
    s.append(("ip4_snap", record(LOCAL_MAC + REMOTE_MAC + struct.pack("!H", len(snap)) + snap),
              "RFC 1042: an IP datagram inside an 802.2 SNAP header, read by its OUI and EtherType"))

    s.append(("vlan_ip4_udp",
              record(vlan(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4, 100) + ip4(17, udp(b"tagged"))),
              "IEEE 802.1Q: the same datagram behind a tag, which the interface's membership decides on"))

    # --- RFC 9293, which needs a sequence ------------------------------------
    syn = tcp(0x02)
    s.append(("tcp_syn", record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4) + ip4(6, syn)),
              "RFC 9293 sec 3.10.7.2: a SYN at a listener, which is the one passive OPEN"))
    s.append(("tcp_syn_then_data",
              record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4) + ip4(6, syn),
                     eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4) + ip4(6, tcp(0x10, b"hello", seq=0x10000001)),
                     eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4) + ip4(6, tcp(0x11, seq=0x10000006))),
              "RFC 9293 sec 3.10.7.4: the segments after the SYN, which reach the arrival machine"))
    s.append(("tcp_rst", record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4) + ip4(6, tcp(0x04))),
              "RFC 9293 sec 3.10.7.1: a RST at a listener, which creates no control block"))

    # --- RFC 8200 and RFC 4443 ----------------------------------------------
    s.append(("ip6_udp",
              record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV6)
                     + ip6(17, udp(b"idemip", src=REMOTE_IP6, dst=LOCAL_IP6, v6=True))),
              "RFC 8200: a datagram over IPv6, whose UDP checksum RFC 8200 sec 8.1 makes mandatory"))
    s.append(("ip6_icmp6_echo",
              record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV6)
                     + ip6(58, icmp6(128, 0, struct.pack("!HH", 1, 1) + b"abcdefgh"))),
              "RFC 4443 sec 4.1: an Echo Request over IPv6"))

    # RFC 4861 sec 4.3 with sec 7.1.1's hop limit of 255, and sec 4.6.1's source link-layer option.
    ns = struct.pack("!I", 0) + LOCAL_IP6 + b"\x01\x01" + REMOTE_MAC
    s.append(("ip6_neighbor_solicit",
              record(eth(bytes.fromhex("3333ff000001"), REMOTE_MAC, ETHERTYPE_IPV6)
                     + ip6(58, icmp6(135, 0, ns, dst=solicited_node(LOCAL_IP6)),
                           dst=solicited_node(LOCAL_IP6), hops=255)),
              "RFC 4861 sec 4.3: a Neighbor Solicitation for this node's solicited-node address"))

    # RFC 8200 sec 4.5, in two fragments, with the Fragment header sec 4.5 defines.
    inner = udp(b"B" * 24, src=REMOTE_IP6, dst=LOCAL_IP6, v6=True)
    fh_a = bytes([17, 0]) + struct.pack("!HI", (0 << 3) | 1, 0xABCD) + inner[:16]
    fh_b = bytes([17, 0]) + struct.pack("!HI", (2 << 3) | 0, 0xABCD) + inner[16:]
    s.append(("ip6_fragments",
              record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV6) + ip6(44, fh_a),
                     eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV6) + ip6(44, fh_b)),
              "RFC 8200 sec 4.5: two fragments of one datagram, the second completing it"))

    # RFC 8200 sec 4.2, an option area ahead of the transport header.
    hop = bytes([17, 0, 0x01, 0x04, 0, 0, 0, 0])
    s.append(("ip6_hop_by_hop",
              record(eth(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV6)
                     + ip6(0, hop + udp(b"opt", src=REMOTE_IP6, dst=LOCAL_IP6, v6=True))),
              "RFC 8200 sec 4.2: a PadN option the node skips, ahead of the transport header"))

    # --- the short ones the first checks turn away ---------------------------
    s.append(("runt", record(b"\x01\x02\x03"),
              "a frame with no room for an Ethernet header, which is an error and not an unknown protocol"))
    s.append(("empty", record(b""), "a frame of no octets, which the entry refuses"))

    # Not a case about the walk: a case about the harness's own framing. A trailing octet with no
    # room for a length is a record of itself, and reading it was the first thing the fuzzer found.
    s.append(("trailing_octet", record(eth(BROADCAST, REMOTE_MAC, ETHERTYPE_ARP) + arp_req) + b"\x01",
              "an input ending in an octet with no length field, which is a record of one octet"))
    return s


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, data, why in seeds():
        with open(os.path.join(out, name + ".bin"), "wb") as fh:
            fh.write(data)
        print("%-24s %4d octets  %s" % (name, len(data), why))
    return 0


if __name__ == "__main__":
    sys.exit(main())
