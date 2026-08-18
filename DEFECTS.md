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

## Security, open

| # | Site | Law | Fault |
|---|---|---|---|
| 3 | `ip/ip6_reass.c` `ip6_reass_payload_len` | RFC 8200 sec 4.5 | Takes FO.last and FL.last from the tail of the linked list. The tail is the greatest Fragment Offset, not the fragment with the greatest end, so the reassembled Payload Length can be short. |
| 13 | `ip/ip6_reass.c` `ip6_reass_carve` | RFC 8200 sec 4.5, RFC 815 sec 3 step 6 | A last fragment landing inside a bounded hole leaves neither head nor tail hole, so the datagram is declared complete while octets of the Fragmentable Part were never received. The stack delivers bytes it never got. |
| 14 | `ip/ip6_reass.c` `ip6_reass_file` | RFC 8200 sec 4.5, sec 10 (RFC 6946) | An atomic fragment (Fragment Offset 0, M 0) is matched into whatever HOLDING datagram shares its {Source, Destination, Identification} instead of being processed independently, so one atomic fragment poisons a legitimate reassembly. |
| 7 | `acd/acd.c` `acd_claim` | RFC 5227 sec 2.1.1 | Gates a new claim on state RATE_LIMIT rather than on the conflict count, and RATE_LIMIT is only entered from `acd_abandon`. A defended conflict raises `conflicts` but leaves the machine in ONGOING, so the sec 2.1.1 MAX_CONFLICTS rate limit never engages. |
| 9, 24 | `core/dispatch.c` `d_ip4`, `d_udp` | RFC 1122 sec 3.2.1.3, sec 4.1.3.6 | No IP source address validation on the local-delivery path. A datagram whose Source Address is the limited broadcast, a multicast group, the receiving interface's directed broadcast, or Class E is delivered. sec 3.2.1.3 makes discarding it a MUST. |
| 12 | `icmp/icmp6_in.c` `icmp6_in_error` | RFC 4443 sec 2.2 (b) | Picks the error's Source Address as `is_multicast(dst) ? if_addr : dst`, covering only the first of the three cases sec 2.2 (b) lists. For an invoking packet addressed to an anycast address, or to a unicast address that is not the node's, it copies that address into the Source Address of an ICMPv6 error the node originates. |
| 15 | `netif/netif.c` `netif_find4` | RFC 1122 sec 3.2.1.3 | Matches on `entry->addr == dst` with no test that the interface is configured. `netif_bind_at` memsets the entry, so an interface bound but not yet given an address carries `addr == 0` and is reported as holding 0.0.0.0 - the normal state before a DHCP lease. |
| 17 | `nd/nd6.c` `nd6_router_set` | RFC 4861 sec 7.2, sec 6.3.4 | Creates a Neighbor Cache entry for the RA source unconditionally, with a NULL link-layer address and state INCOMPLETE. sec 7.2 says a message without a link-layer address option MUST NOT create or update a cache entry except for the IsRouter flag. |
| 18 | `nd/nd6.c` `nd6_sweep` | RFC 4861 sec 7.3.3 | Arms the next solicitation at `now + retrans` with RetransTimer copied verbatim from a Router Advertisement and no bound. `nd6_due` reads the difference as `int32_t`, so any RetransTimer above 2^31 ms reads as already past and the per-neighbour rate limit inverts into a solicitation flood. |
| 19 | `nd/dad.c` `dad_send` | RFC 4862 sec 5.4 | The same unbounded RetransTimer, on the DAD wait. Above 2^31 ms the wait expires on the next tick, so an address is declared unique one millisecond after the single NS goes out. |
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
