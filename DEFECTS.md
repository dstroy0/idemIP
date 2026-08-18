# Phase 5 findings

Sixteen skeptics read the tree against the RFCs and reported 87 confirmed defects, 24 of them
security. Every one below was confirmed by a probe program linked against the tree's own
`libidemip.a`, not by inspection. Line numbers are from the commit the skeptics read and drift as
the tree changes; the named function is the anchor.

Several skeptics found the same defect independently. The duplicates are listed with the finding
they duplicate, because two reports of one fault are one fault.

Closing a defect here means: the law was read from the RFC in the session that fixed it, a test
fails when the fix is reverted, and the file hash returns to its pre-mutation value.

## Security, closed

| # | Site | Law | Fault | Closed by |
|---|---|---|---|---|
| 1 | `core/tick.c` `t_sole_netif` | PLAN.md sec 3.5 | Returned `NETIF_NONE` once two interfaces had a DMA ring, so on the shipped two-interface default no pinned descriptor was ever handed back. The ring drained one frame per hold until receive stopped. | `475c965` |
| 11 | `core/tick.c:109` | `tick.h:25-27` | Duplicate of 1. | `475c965` |
| 4 | `core/dispatch.c` `d_udp` | RFC 1122 sec 4.1.3.4, RFC 8200 sec 8.1 | The UDP checksum was never verified. `idemip_udp_cksum_valid()` existed at `udp.h:204` and no library code called it. A zero checksum on IPv6 was accepted, which sec 8.1 forbids. | `e9eae6b` |
| 8, 23 | `core/dispatch.c:365`, `:342` | RFC 1122 sec 4.1.3.4 | Duplicates of 4. | `e9eae6b` |
| 5 | `core/dispatch.c` `d_igmp` | RFC 2236 sec 2.3, sec 6 | The IGMP checksum was never verified: no checksum code existed anywhere under `idemIP/igmp/`. A corrupt Query moved a group Idle Member to Delaying Member. No IGMP dispatch test existed at all. | `e9eae6b` |
| 10, 16 | `core/dispatch.c:822`, `:816` | RFC 2236 sec 2.3 | Duplicates of 5. | `e9eae6b` |
| 2 | `tcp/tcp_pcb.c` `tcp_pcb_queues_free` | PLAN.md sec 3.5 | `tcp_pcb_close` memset every out-of-order entry, discarding the `desc` each pinned. Nothing unpinned them and nothing reported them. The close is now BUSY while the hold is not empty. | `013f535` |
| 6 | `tcp/tcp_in.c` `tcp_in_check_syn` | RFC 9293 sec 3.10.7.4, RFC 5961 sec 4.2 | Returned SYN-RECEIVED to LISTEN without consulting `res.acceptable`, so a SYN bearing any sequence number destroyed a half-open passive connection. sec 3.10.7.4 first returns before the fourth step for an unacceptable segment, and RFC 5961's "irrespective of the sequence number" is written for the synchronized states, which SYN-RECEIVED is not. | `c9babcb` |
| 22 | `tcp/tcp_in.c:895` | RFC 9293 sec 3.10.7.4 | Duplicate of 6, seen from the calling side. | `c9babcb` |
| 15 | `netif/netif.c` `netif_find4` | RFC 1122 sec 3.2.1.3 (a) | An interface bound but not yet addressed carries `addr == 0` and was reported as holding 0.0.0.0, which `d_ip4_dest` turns into a local delivery. The same zeroed entry carries mask 0, so `netif_on_link` put every destination on its link. Both now go through `netif_has_addr4`. | `2ad0d3b` |
| 9, 24 | `core/dispatch.c` `d_ip4` | RFC 1122 sec 3.2.1.3, sec 4.1.3.6 | No source address validation on the receive path. Added in the IP layer, so every transport is covered once. { 0, 0 } stays valid, which is what a DHCP client's first datagram carries. | `7946ff0` |
| 18 | `nd/nd6.c` `nd6_retrans_ms` | RFC 4861 sec 7.3.3, sec 6.3.4 | RetransTimer was copied verbatim from a Router Advertisement. Above the deadline span a solicitation deadline reads as already past, inverting the per-neighbour MUST NOT into one solicitation per tick. Held at the span, which is the deadline max shifted down by MAX_MULTICAST_SOLICIT + 1. | `86dc94a` |
| 19 | `nd/dad.c` `dad_start` | RFC 4862 sec 5.4 | The same unbounded timer on the DAD wait, which collapsed to the next tick and declared an address unique before any defence could arrive. | `86dc94a` |
| 17 | `nd/nd6.c` `nd6_router_set` | RFC 4861 sec 7.2, sec 6.3.4 | Created a Neighbor Cache entry for every RA source, NULL link-layer address and INCOMPLETE. `Nd6RouterArgs` now carries the SLLAO; without it only an existing entry has IsRouter set, and the Default Router List holds the address itself so a router that omits the option is still listed. | `fc0b37a` |
| 7 | `acd/acd.c` `acd_claim` | RFC 5227 sec 2.1.1 | Gated a new claim on state RATE_LIMIT, entered only from an abandon, so a defended conflict raised the count without ever closing the gate. The gate now reads the count, which is what sec 2.1.1 says applies "not only to conflicts experienced during the initial probing phase, but also to conflicts experienced later". | `84f09b1` |
| 12 | `icmp/icmp6_in.c` `icmp6_in_error` | RFC 4443 sec 2.2 | Copied the invoking packet's Destination Address into the Source Address of an error the node originates, for every case but multicast - including a unicast address that is not the node's. `dst_local_unicast` now separates sec 2.2 (a) from (b). | `3349e1b` |
| 20 | `tcp/tcp_pcb.c` `tcp_pcb_bind` | RFC 9293 sec 3.4.1 | Refused a local port another TCB held, so a server served one client per port. Uniqueness is the pair of sockets, which `tcp_pcb_connect` already enforces. | `d7fe64f` |
| 21 | `tcp/tcp_pcb.c` `tcp_pcb_port_draw` | RFC 6056 sec 3.3.1 | The ephemeral draw walked from a stored cursor, so one observed port named the next. Now Algorithm 1, placed by the caller's random word, with the modulo as an AND. | `d7fe64f` |
| 13 | `ip/ip6_reass.c` `ip6_reass_file` | RFC 8200 sec 4.5, RFC 815 sec 3 | Nothing held the packet to the end its M-flag-zero fragment fixed, so a last fragment landing in a bounded hole completed a datagram whose middle was never received. The datagram now records that end and abandons any packet inconsistent with it. | `93b8cb2` |
| 3 | `ip/ip6_reass.c` `ip6_reass_payload_len` | RFC 8200 sec 4.5 | Took FO.last and FL.last from the tail of the offset-sorted list rather than from the fragment carrying the M flag clear. Now reads the recorded end. | `93b8cb2` |
| 14 | `ip/ip6_reass.c` `ip6_reass_file` | RFC 8200 sec 4.5, sec 10 | An atomic fragment was matched into whatever HOLDING datagram shared its key. sec 4.5 processes it as a fully reassembled packet and every matching fragment independently, so it now joins nothing. | `93b8cb2` |

## Security, open

None. All twenty-four are closed.

## Correctness

The phase 5 correctness, robustness and cosmetic findings were counted and never itemised. The
transcript holds the twenty-four security items and nothing else, so this section is re-derived
rather than recovered.

The method that found the ones below generalises three of the security findings, which all had one
shape: a requirement encoded in a header that no library code ever names. `idemip_udp_cksum_valid`
sat in `udp.h` with no caller, `IDEMIP_IGMP_OFF_CKSUM` had no reader, and
`IDEMIP_DISPATCH_DROP_IP_SOURCE` was an enumerator nothing raised. Scanning every header definition
for one no `.c` under `idemIP/` names reports 249 candidates; most are legitimately caller-facing
(packet builders, ICMP code values the caller chooses), so each has to be read against the RFC. The
scan is `scratchpad/unwired.py`.

| Site | Law | Fault | Closed by |
|---|---|---|---|
| `ip/ipv6.h` `idemip_ip6_walk` | RFC 8200 sec 4.4 | A Routing header was stepped over on its length alone. This library executes no Routing Type, so every one with a non-zero Segments Left is sec 4.4's unrecognized case and must be discarded. `idemip_ip6_rt_segs_left` quoted the rule in its own doc comment and had no caller. | `5aaecc8` |
| `ip/ipv6.h` `idemip_ip6_walk` | RFC 8200 sec 4.2 | The options of a Hop-by-Hop or Destination Options header were never walked, so every unrecognized option behaved as action 00 whatever its two high-order bits said. All four action constants had no reader. | `ca7dff7` |
| `core/dispatch.c` `d_icmp` | RFC 1122 sec 3.2.2 | `IDEMIP_ICMP_IN_ACT_DISCARD` was raised at eight sites in `icmp_in.c` and read at none. Dispatch, its only caller, delivered every message the unit refused: unknown type, a checksum that does not hold, a message shorter than its type requires, and the types sec 3.2.2.7 and sec 3.2.2.8 leave unimplemented. | `4aeec20` |
| `core/dispatch.c` `d_icmp` | RFC 2011 | Fifty-three ICMP counters were defined and not one was bumped anywhere under `idemIP/`, while IP, interface, TCP and UDP all counted. icmpInMsgs, icmpInErrors and the per-Type counters are now kept. | `4aeec20` |
| `core/dispatch.c` `d_icmp6` | RFC 4443 sec 2.4 (b) | The same defect on the ICMPv6 side, over four sites in `icmp6_in.c`. | `d0a463c` |

Checked and found correct, against the same suspicion: UDP-Lite verifies both its Checksum Coverage
and its checksum (`udplite_check`), and the unused `idemip_udplite_cksum_valid` is only a wrapper.

## The rest

26 robustness and 6 cosmetic findings, plus 83 test cases that assert nothing an RFC requires and 231
attacks that held. Not itemised anywhere recoverable either.

A pattern worth keeping: finding 2's test, `test_a_close_frees_every_held_segment`, described the
correct behaviour in its comment - "every pinned descriptor the connection named is reported free
for the caller to unpin" - and then asserted only that the entries were gone. It documented the fix
and tested the bug. A green suite is not evidence; 2,461 of them were passing when these 87 were
found.
