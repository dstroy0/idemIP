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

## Security, open

| # | Site | Law | Fault |
|---|---|---|---|
| 3 | `ip/ip6_reass.c` `ip6_reass_payload_len` | RFC 8200 sec 4.5 | Takes FO.last and FL.last from the tail of the linked list. The tail is the greatest Fragment Offset, not the fragment with the greatest end, so the reassembled Payload Length can be short. |
| 13 | `ip/ip6_reass.c` `ip6_reass_carve` | RFC 8200 sec 4.5, RFC 815 sec 3 step 6 | A last fragment landing inside a bounded hole leaves neither head nor tail hole, so the datagram is declared complete while octets of the Fragmentable Part were never received. The stack delivers bytes it never got. |
| 14 | `ip/ip6_reass.c` `ip6_reass_file` | RFC 8200 sec 4.5, sec 10 (RFC 6946) | An atomic fragment (Fragment Offset 0, M 0) is matched into whatever HOLDING datagram shares its {Source, Destination, Identification} instead of being processed independently, so one atomic fragment poisons a legitimate reassembly. |
| 7 | `acd/acd.c` `acd_claim` | RFC 5227 sec 2.1.1 | Gates a new claim on state RATE_LIMIT rather than on the conflict count, and RATE_LIMIT is only entered from `acd_abandon`. A defended conflict raises `conflicts` but leaves the machine in ONGOING, so the sec 2.1.1 MAX_CONFLICTS rate limit never engages. |
| 12 | `icmp/icmp6_in.c` `icmp6_in_error` | RFC 4443 sec 2.2 (b) | Picks the error's Source Address as `is_multicast(dst) ? if_addr : dst`, covering only the first of the three cases sec 2.2 (b) lists. For an invoking packet addressed to an anycast address, or to a unicast address that is not the node's, it copies that address into the Source Address of an ICMPv6 error the node originates. |
| 20 | `tcp/tcp_pcb.c` `tcp_pcb_port_taken` | RFC 9293 sec 3.4.1 | Reports a local port taken whenever any other open TCB holds it, ignoring the remote socket. A connection is a pair of sockets, so two peers reaching one local socket are two connections; the second cannot bind. |
| 21 | `tcp/tcp_pcb.c:415` | RFC 6056 sec 3.3 | Ephemeral port selection is not obfuscated as BCP 156 requires. |

## The rest

34 correctness, 26 robustness, 6 cosmetic, plus 83 test cases that assert nothing an RFC requires
and 231 attacks that held. Those are tracked in the session that raised them and are not itemised
here yet.

A pattern worth keeping: finding 2's test, `test_a_close_frees_every_held_segment`, described the
correct behaviour in its comment - "every pinned descriptor the connection named is reported free
for the caller to unpin" - and then asserted only that the entries were gone. It documented the fix
and tested the bug. A green suite is not evidence; 2,461 of them were passing when these 87 were
found.
