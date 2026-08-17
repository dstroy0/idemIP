// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file idemip_config.h
 * @brief The one entry point: the vocabulary every file here uses, and every count it is built to.
 *
 * Nothing in this tree allocates. Every table size is fixed here, at compile time, so a unit's
 * storage is a number the linker places in .bss and never a call into an allocator. A count that
 * needs changing is changed here and the tree is rebuilt.
 *
 * Each count is guarded, so a build system or a board profile sets it on the command line and this
 * file supplies the default.
 */

#ifndef IDEMIP_CONFIG_H
#define IDEMIP_CONFIG_H

#include <assert.h> // static_assert
#include <stddef.h> // size_t, NULL, offsetof
#include <stdint.h> // the fixed widths every wire field is read into
#include <string.h> // memcpy, memset, memcmp

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

#ifdef __cplusplus
#define IDEMIP_BEGIN_DECLS extern "C" {
#define IDEMIP_END_DECLS }
#else
#define IDEMIP_BEGIN_DECLS
#define IDEMIP_END_DECLS
#endif

/** @brief Definition emitted in every translation unit that reads it, and folded by the compiler. */
#define IDEMIP_INLINE static inline

/**
 * @brief Narrow an enum to the smallest type that holds it.
 *
 * An enum here names a wire value, and the wire fixes its width. Where the attribute is
 * unavailable the enum keeps the implementation's default width, which costs space and changes
 * nothing else: no enum is ever read or written through a pointer to a frame.
 */
#if defined(__GNUC__) || defined(__clang__)
#define IDEMIP_ENUM_PACKED __attribute__((__packed__))
#else
#define IDEMIP_ENUM_PACKED
#endif

/** @brief A truth value. Named rather than `bool` so the width is the same on every target. */
typedef uint8_t idemip_bool;
#define IDEMIP_TRUE ((idemip_bool)1)
#define IDEMIP_FALSE ((idemip_bool)0)

/**
 * @brief What a call reports. No entry in this tree blocks, so every one of them answers with this.
 *
 * A caller drives progress from its timer rather than by waiting. An entry that cannot finish now
 * says so and returns, and the caller comes back on a later tick. That is the whole concurrency
 * model: nothing sleeps, nothing spins, and no entry holds the CPU waiting on hardware or on a
 * peer.
 *
 * Three states, because three is what a timer-driven caller can act on: go on, come back, or stop.
 * A ring with nothing in it, a ring with no room, and a management transaction still on the wire
 * are all BUSY, since the caller does the same thing for each.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_OK = 0, ///< the call finished, and any result member is set
    IDEMIP_BUSY,   ///< no progress now: nothing waiting, no room, or still in flight. Call again.
    IDEMIP_ERR,    ///< refused: a null borrow, a bad argument, or the wrong state. Do not retry.
} IdemIpStatus;

// ---------------------------------------------------------------------------
// Capability gates
// ---------------------------------------------------------------------------
// A gate gets the golden file shape: the config include above it, everything else below, so a
// capability that is off compiles to nothing at all.

#ifndef IDEMIP_ENABLE_ETHERNET
#define IDEMIP_ENABLE_ETHERNET 1
#endif
#ifndef IDEMIP_ENABLE_IPV4
#define IDEMIP_ENABLE_IPV4 1
#endif
#ifndef IDEMIP_ENABLE_IPV6
#define IDEMIP_ENABLE_IPV6 1
#endif
#ifndef IDEMIP_ENABLE_TCP
#define IDEMIP_ENABLE_TCP 1
#endif
#ifndef IDEMIP_ENABLE_UDP
#define IDEMIP_ENABLE_UDP 1
#endif

// What each gate needs under it. A combination that cannot compile is refused here, where the
// message names the gate, rather than fifty lines into a header that cannot see its own dependency.
#if IDEMIP_ENABLE_IPV4 && !IDEMIP_ENABLE_ETHERNET
#error "IDEMIP_ENABLE_IPV4 needs IDEMIP_ENABLE_ETHERNET: arp.h resolves to a 48-bit Ethernet address (RFC 826)"
#endif
#if IDEMIP_ENABLE_IPV6 && !IDEMIP_ENABLE_ETHERNET
#error "IDEMIP_ENABLE_IPV6 needs IDEMIP_ENABLE_ETHERNET: the link layer here is Ethernet II (RFC 2464)"
#endif
#if IDEMIP_ENABLE_TCP && !(IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6)
#error "IDEMIP_ENABLE_TCP needs IDEMIP_ENABLE_IPV4 or IDEMIP_ENABLE_IPV6: the checksum covers a pseudo-header"
#endif
#if IDEMIP_ENABLE_UDP && !(IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6)
#error "IDEMIP_ENABLE_UDP needs IDEMIP_ENABLE_IPV4 or IDEMIP_ENABLE_IPV6: the checksum covers a pseudo-header"
#endif

// ---------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------

/**
 * @brief Bytes in a data cache line.
 *
 * A DMA buffer starts on a line boundary and occupies whole lines, because invalidating a partial
 * line discards whatever else shares it. Every receive buffer stride rounds up to this.
 */
#ifndef IDEMIP_CACHE_LINE_BYTES
#define IDEMIP_CACHE_LINE_BYTES 32u
#endif

/** @brief Alignment every borrow that holds no DMA buffer is taken at. */
#ifndef IDEMIP_ALIGN
#define IDEMIP_ALIGN 8u
#endif

/** @brief Round @p n up to the next multiple of @p a, which must be a power of two. */
#define IDEMIP_ROUND_UP(n, a) (((size_t)(n) + ((size_t)(a) - 1u)) & ~((size_t)(a) - 1u))

// ---------------------------------------------------------------------------
// Link
// ---------------------------------------------------------------------------

/**
 * @brief Receive descriptors in the DMA ring.
 *
 * Bounded below by IDEMIP_MAX_PINNED_FRAMES, which the assert at the foot of this file checks: the
 * ring has to outlast every retaining unit being full at once. A power of two, so the ring index
 * is a mask.
 */
#ifndef IDEMIP_RX_DESCRIPTORS
#define IDEMIP_RX_DESCRIPTORS 64u
#endif

/** @brief Transmit descriptors in the DMA ring. */
#ifndef IDEMIP_TX_DESCRIPTORS
#define IDEMIP_TX_DESCRIPTORS 8u
#endif

/**
 * @brief Octets one frame buffer spans, header included.
 *
 * RFC 894: "the maximum length of an IP datagram sent over an Ethernet is 1500 octets", carried
 * behind the 14-octet Ethernet II header, so 1514 octets reach the wire.
 */
#ifndef IDEMIP_DMA_FRAME_MAX
#define IDEMIP_DMA_FRAME_MAX 1514u
#endif

/**
 * @brief Octets between one frame buffer and the next, rounded to whole cache lines.
 *
 * The buffers themselves are the DRIVER's storage: phy.h's rx_claim hands back a pointer into the
 * buffer the engine filled, and tx_claim hands back one the engine will read, so no idemIP borrow
 * holds a frame and this stride enters no _BORROW below. A driver rounds its own buffers to it.
 */
#define IDEMIP_DMA_BUF_STRIDE IDEMIP_ROUND_UP(IDEMIP_DMA_FRAME_MAX, IDEMIP_CACHE_LINE_BYTES)

/** @brief Interfaces this build carries. Forwarding needs at least two. */
#ifndef IDEMIP_NETIF_COUNT
#define IDEMIP_NETIF_COUNT 2u
#endif

/** @brief Frames the loopback interface holds between output and the next dispatch pass. */
#ifndef IDEMIP_LOOPIF_FRAMES
#define IDEMIP_LOOPIF_FRAMES 2u
#endif

/**
 * @brief Bytes one bound link runs out of. The borrow IS the interface, so two links are two.
 *
 * Covers the operand block and the context. The assert in phy.c proves it, and fires if either
 * grows past it.
 */
#ifndef IDEMIP_PHY_BORROW
#define IDEMIP_PHY_BORROW 128u
#endif

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

/** @brief lwIP ARP_TABLE_SIZE. */
#ifndef IDEMIP_ARP_ENTRIES
#define IDEMIP_ARP_ENTRIES 10u
#endif

/** @brief lwIP ARP_MAXAGE, seconds an entry survives without use (RFC 1122 sec 2.3.2.1). */
#ifndef IDEMIP_ARP_MAXAGE_S
#define IDEMIP_ARP_MAXAGE_S 300u
#endif

/** @brief Frames held pending address resolution. Each pins a receive descriptor. */
#ifndef IDEMIP_ARP_PENDING
#define IDEMIP_ARP_PENDING 4u
#endif

/** @brief lwIP ARP_TMR_INTERVAL, milliseconds between two sweeps of the table. */
#ifndef IDEMIP_ARP_TMR_INTERVAL_MS
#define IDEMIP_ARP_TMR_INTERVAL_MS 1000u
#endif

/** @brief Fragments held during reassembly. Each pins a receive descriptor. */
#ifndef IDEMIP_IP4_REASS_FRAGS
#define IDEMIP_IP4_REASS_FRAGS 8u
#endif

/** @brief lwIP MEMP_NUM_REASSDATA, datagrams reassembled at once (RFC 791 sec 3.2). */
#ifndef IDEMIP_IP4_REASS_DATAGRAMS
#define IDEMIP_IP4_REASS_DATAGRAMS 5u
#endif

/**
 * @brief Hole descriptors the IPv4 reassembler holds (RFC 815).
 *
 * RFC 815 sec 3 opens a datagram with one hole, "a hole reaching from zero to infinity". Steps 4
 * through 6 delete the hole a fragment lands in and create at most two, so each fragment adds at
 * most one. D datagrams holding N fragments therefore reach at most D + N descriptors.
 */
#define IDEMIP_IP4_REASS_HOLES (IDEMIP_IP4_REASS_DATAGRAMS + IDEMIP_IP4_REASS_FRAGS)

/** @brief lwIP IP_TMR_INTERVAL, milliseconds between two reassembly timeout sweeps. */
#ifndef IDEMIP_IP_TMR_INTERVAL_MS
#define IDEMIP_IP_TMR_INTERVAL_MS 1000u
#endif

/** @brief lwIP IP_REASS_MAXAGE, seconds a partial datagram is held (RFC 791 sec 3.2). */
#ifndef IDEMIP_IP_REASS_MAXAGE_S
#define IDEMIP_IP_REASS_MAXAGE_S 15u
#endif

/** @brief lwIP IP_DEFAULT_TTL. */
#ifndef IDEMIP_IP_DEFAULT_TTL
#define IDEMIP_IP_DEFAULT_TTL 255u
#endif

/** @brief Routes in the IPv4 table. */
#ifndef IDEMIP_IP4_ROUTES
#define IDEMIP_IP4_ROUTES 4u
#endif

// RFC 5227 sec 1.1, values as printed. Seconds became milliseconds, deadlines being held in
// milliseconds throughout this tree.
#ifndef IDEMIP_ACD_PROBE_WAIT_MS
#define IDEMIP_ACD_PROBE_WAIT_MS 1000u
#endif
#ifndef IDEMIP_ACD_PROBE_NUM
#define IDEMIP_ACD_PROBE_NUM 3u
#endif
#ifndef IDEMIP_ACD_PROBE_MIN_MS
#define IDEMIP_ACD_PROBE_MIN_MS 1000u
#endif
#ifndef IDEMIP_ACD_PROBE_MAX_MS
#define IDEMIP_ACD_PROBE_MAX_MS 2000u
#endif
#ifndef IDEMIP_ACD_ANNOUNCE_WAIT_MS
#define IDEMIP_ACD_ANNOUNCE_WAIT_MS 2000u
#endif
#ifndef IDEMIP_ACD_ANNOUNCE_NUM
#define IDEMIP_ACD_ANNOUNCE_NUM 2u
#endif
#ifndef IDEMIP_ACD_ANNOUNCE_INTERVAL_MS
#define IDEMIP_ACD_ANNOUNCE_INTERVAL_MS 2000u
#endif
#ifndef IDEMIP_ACD_MAX_CONFLICTS
#define IDEMIP_ACD_MAX_CONFLICTS 10u
#endif
#ifndef IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS
#define IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS 60000u
#endif
#ifndef IDEMIP_ACD_DEFEND_INTERVAL_MS
#define IDEMIP_ACD_DEFEND_INTERVAL_MS 10000u
#endif

/** @brief lwIP ACD_TMR_INTERVAL, milliseconds between two probe/announce/defend ticks. */
#ifndef IDEMIP_ACD_TMR_INTERVAL_MS
#define IDEMIP_ACD_TMR_INTERVAL_MS 100u
#endif

/**
 * @brief The range AutoIP draws a link-local address from (RFC 3927 sec 2.1).
 *
 * "a uniform distribution in the range from 169.254.1.0 to 169.254.254.255 inclusive", the same
 * section reserving "The first 256 and last 256 addresses in the 169.254/16 prefix". RFC 3927
 * sec 2.2.1 defines PROBE_NUM, PROBE_MIN, PROBE_MAX, RATE_LIMIT_INTERVAL and MAX_CONFLICTS, sec 2.4
 * ANNOUNCE_NUM and ANNOUNCE_INTERVAL, and sec 2.5 DEFEND_INTERVAL, at the values RFC 5227 sec 1.1
 * prints above.
 */
#define IDEMIP_AUTOIP_PREFIX 0xA9FE0000u
#define IDEMIP_AUTOIP_FIRST 0xA9FE0100u
#define IDEMIP_AUTOIP_LAST 0xA9FEFEFFu

/** @brief IPv4 multicast groups joined (RFC 2236). */
#ifndef IDEMIP_IGMP_GROUPS
#define IDEMIP_IGMP_GROUPS 4u
#endif

// RFC 2236 sec 8, the host-side values as printed.
/** @brief RFC 2236 sec 8.1 Robustness Variable, "Default: 2". */
#ifndef IDEMIP_IGMP_ROBUSTNESS
#define IDEMIP_IGMP_ROBUSTNESS 2u
#endif
/** @brief RFC 2236 sec 8.10 Unsolicited Report Interval, "Default: 10 seconds". */
#ifndef IDEMIP_IGMP_UNSOLICITED_REPORT_MS
#define IDEMIP_IGMP_UNSOLICITED_REPORT_MS 10000u
#endif
/** @brief RFC 2236 sec 8.11 Version 1 Router Present Timeout, "Value: 400 seconds". */
#ifndef IDEMIP_IGMP_V1_ROUTER_PRESENT_MS
#define IDEMIP_IGMP_V1_ROUTER_PRESENT_MS 400000u
#endif

/** @brief lwIP IGMP_TMR_INTERVAL. Deadlines are held in milliseconds, so this scales nothing. */
#ifndef IDEMIP_IGMP_TMR_INTERVAL_MS
#define IDEMIP_IGMP_TMR_INTERVAL_MS 100u
#endif

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

/** @brief lwIP LWIP_ND6_NUM_NEIGHBORS (RFC 4861 sec 5.1 Neighbor Cache). */
#ifndef IDEMIP_ND6_NUM_NEIGHBORS
#define IDEMIP_ND6_NUM_NEIGHBORS 10u
#endif

/** @brief lwIP LWIP_ND6_NUM_DESTINATIONS (RFC 4861 sec 5.1 Destination Cache). */
#ifndef IDEMIP_ND6_NUM_DESTINATIONS
#define IDEMIP_ND6_NUM_DESTINATIONS 10u
#endif

/** @brief lwIP LWIP_ND6_NUM_PREFIXES (RFC 4861 sec 5.1 Prefix List). */
#ifndef IDEMIP_ND6_NUM_PREFIXES
#define IDEMIP_ND6_NUM_PREFIXES 5u
#endif

/** @brief lwIP LWIP_ND6_NUM_ROUTERS (RFC 4861 sec 5.1 Default Router List). */
#ifndef IDEMIP_ND6_NUM_ROUTERS
#define IDEMIP_ND6_NUM_ROUTERS 3u
#endif

/** @brief Frames held pending neighbor resolution. Each pins a receive descriptor. */
#ifndef IDEMIP_ND6_PENDING
#define IDEMIP_ND6_PENDING 4u
#endif

/** @brief lwIP ND6_TMR_INTERVAL, milliseconds between two sweeps of the neighbor cache. */
#ifndef IDEMIP_ND6_TMR_INTERVAL_MS
#define IDEMIP_ND6_TMR_INTERVAL_MS 1000u
#endif

/** @brief Fragments held during IPv6 reassembly. Each pins a receive descriptor. */
#ifndef IDEMIP_IP6_REASS_FRAGS
#define IDEMIP_IP6_REASS_FRAGS 8u
#endif

/** @brief Datagrams reassembled at once, lwIP MEMP_NUM_REASSDATA (RFC 8200 sec 4.5). */
#ifndef IDEMIP_IP6_REASS_DATAGRAMS
#define IDEMIP_IP6_REASS_DATAGRAMS 5u
#endif

/** @brief Hole descriptors the IPv6 reassembler holds, bounded as RFC 815 bounds the IPv4 list. */
#define IDEMIP_IP6_REASS_HOLES (IDEMIP_IP6_REASS_DATAGRAMS + IDEMIP_IP6_REASS_FRAGS)

/**
 * @brief Milliseconds a partial IPv6 packet is held (RFC 8200 sec 4.5).
 *
 * "If insufficient fragments are received to complete reassembly of a packet within 60 seconds of
 * the reception of the first-arriving fragment of that packet, reassembly of that packet must be
 * abandoned and all the fragments that have been received for that packet must be discarded."
 */
#ifndef IDEMIP_IP6_REASS_MAXAGE_MS
#define IDEMIP_IP6_REASS_MAXAGE_MS 60000u
#endif

/** @brief Addresses per interface (RFC 4862 gives a node several). */
#ifndef IDEMIP_IP6_ADDRESSES
#define IDEMIP_IP6_ADDRESSES 4u
#endif

/** @brief lwIP MEMP_NUM_MLD6_GROUP (RFC 2710). */
#ifndef IDEMIP_MLD6_GROUPS
#define IDEMIP_MLD6_GROUPS 4u
#endif

// RFC 4861 sec 10, read from the RFC. Node constants.
#ifndef IDEMIP_ND6_MAX_MULTICAST_SOLICIT
#define IDEMIP_ND6_MAX_MULTICAST_SOLICIT 3u
#endif
#ifndef IDEMIP_ND6_MAX_UNICAST_SOLICIT
#define IDEMIP_ND6_MAX_UNICAST_SOLICIT 3u
#endif
#ifndef IDEMIP_ND6_MAX_ANYCAST_DELAY_MS
#define IDEMIP_ND6_MAX_ANYCAST_DELAY_MS 1000u
#endif
#ifndef IDEMIP_ND6_MAX_NEIGHBOR_ADVERTISEMENT
#define IDEMIP_ND6_MAX_NEIGHBOR_ADVERTISEMENT 3u
#endif
#ifndef IDEMIP_ND6_REACHABLE_TIME_MS
#define IDEMIP_ND6_REACHABLE_TIME_MS 30000u
#endif
#ifndef IDEMIP_ND6_RETRANS_TIMER_MS
#define IDEMIP_ND6_RETRANS_TIMER_MS 1000u
#endif
#ifndef IDEMIP_ND6_DELAY_FIRST_PROBE_MS
#define IDEMIP_ND6_DELAY_FIRST_PROBE_MS 5000u
#endif

// RFC 4861 sec 10, host constants.
#ifndef IDEMIP_ND6_MAX_RTR_SOLICITATION_DELAY_MS
#define IDEMIP_ND6_MAX_RTR_SOLICITATION_DELAY_MS 1000u
#endif
#ifndef IDEMIP_ND6_RTR_SOLICITATION_INTERVAL_MS
#define IDEMIP_ND6_RTR_SOLICITATION_INTERVAL_MS 4000u
#endif
#ifndef IDEMIP_ND6_MAX_RTR_SOLICITATIONS
#define IDEMIP_ND6_MAX_RTR_SOLICITATIONS 3u
#endif

// RFC 4861 sec 6.3.2: ReachableTime is drawn between MIN_RANDOM_FACTOR and MAX_RANDOM_FACTOR times
// BaseReachableTime. Both factors are exact in shifts, .5 being x >> 1 and 1.5 being x + (x >> 1),
// so neither needs a float or a divide.
#define IDEMIP_ND6_MIN_RANDOM(x) ((x) >> 1)
#define IDEMIP_ND6_MAX_RANDOM(x) ((x) + ((x) >> 1))

/** @brief lwIP MLD6_TMR_INTERVAL. Deadlines are held in milliseconds, so this scales nothing. */
#ifndef IDEMIP_MLD6_TMR_INTERVAL_MS
#define IDEMIP_MLD6_TMR_INTERVAL_MS 100u
#endif

/** @brief lwIP MLD6_JOIN_DELAYING_MEMBER_TMR_MS. */
#ifndef IDEMIP_MLD6_JOIN_DELAY_MS
#define IDEMIP_MLD6_JOIN_DELAY_MS 500u
#endif

/** @brief lwIP MLD6_HL: RFC 2710 sec 3 puts every MLD message at hop limit 1. */
#ifndef IDEMIP_MLD6_HL
#define IDEMIP_MLD6_HL 1u
#endif

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/** @brief lwIP MEMP_NUM_TCP_PCB. */
#ifndef IDEMIP_TCP_PCBS
#define IDEMIP_TCP_PCBS 5u
#endif

/** @brief lwIP MEMP_NUM_TCP_PCB_LISTEN. */
#ifndef IDEMIP_TCP_LISTEN_PCBS
#define IDEMIP_TCP_LISTEN_PCBS 8u
#endif

/** @brief lwIP MEMP_NUM_TCP_SEG. */
#ifndef IDEMIP_TCP_SEGS
#define IDEMIP_TCP_SEGS 16u
#endif

/** @brief Out-of-order segments held per connection. Each pins a receive descriptor. */
#ifndef IDEMIP_TCP_OOSEQ_SEGS
#define IDEMIP_TCP_OOSEQ_SEGS 4u
#endif

/** @brief lwIP TCP_MSS. */
#ifndef IDEMIP_TCP_MSS
#define IDEMIP_TCP_MSS 536u
#endif

/** @brief lwIP TCP_WND. */
#ifndef IDEMIP_TCP_WND
#define IDEMIP_TCP_WND (4u * IDEMIP_TCP_MSS)
#endif

/** @brief lwIP TCP_MAXRTX. */
#ifndef IDEMIP_TCP_MAXRTX
#define IDEMIP_TCP_MAXRTX 12u
#endif

/** @brief lwIP TCP_SYNMAXRTX. */
#ifndef IDEMIP_TCP_SYNMAXRTX
#define IDEMIP_TCP_SYNMAXRTX 6u
#endif

/** @brief lwIP TCP_TMR_INTERVAL. */
#ifndef IDEMIP_TCP_TMR_INTERVAL_MS
#define IDEMIP_TCP_TMR_INTERVAL_MS 250u
#endif

/** @brief lwIP TCP_MSL. */
#ifndef IDEMIP_TCP_MSL_MS
#define IDEMIP_TCP_MSL_MS 60000u
#endif

/** @brief UDP bindings. */
#ifndef IDEMIP_UDP_PCBS
#define IDEMIP_UDP_PCBS 8u
#endif

/** @brief Raw IP protocol bindings (RFC 1122 sec 3.2). */
#ifndef IDEMIP_RAW_PCBS
#define IDEMIP_RAW_PCBS 2u
#endif

/**
 * @brief Octets of secret the RFC 6528 sec 3 ISN generator keys its PRF with.
 *
 * "ISN = M + F(localip, localport, remoteip, remoteport, secretkey)", and of the key: "Key lengths
 * of 128 bits should be adequate."
 */
#ifndef IDEMIP_TCP_ISN_SECRET_BYTES
#define IDEMIP_TCP_ISN_SECRET_BYTES 16u
#endif

/**
 * @brief Octets the RFC 6528 sec 3 connection-id block spans in the borrow.
 *
 * The PRF input is the concatenation of localip, localport, remoteip, remoteport and secretkey: 16,
 * 2, 16, 2 and IDEMIP_TCP_ISN_SECRET_BYTES octets, 52 in all, taken at a power of two so an index
 * into it is a shift.
 */
#ifndef IDEMIP_TCP_ISN_BLOCK_BYTES
#define IDEMIP_TCP_ISN_BLOCK_BYTES 64u
#endif

/**
 * @brief Octets the PRF's own working set spans in the borrow.
 *
 * RFC 6528 sec 3: "The PRF could be implemented as a cryptographic hash of the concatenation of the
 * connection-id and some secret data". Sized at what ProtoCore's SHA-256 golden takes,
 * PROTOCORE_SHA256_BORROW being 256.
 */
#ifndef IDEMIP_TCP_ISN_HASH_BYTES
#define IDEMIP_TCP_ISN_HASH_BYTES 256u
#endif

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

/** @brief Outstanding DNS queries (RFC 1035). */
#ifndef IDEMIP_DNS_QUERIES
#define IDEMIP_DNS_QUERIES 4u
#endif

/** @brief Cached DNS answers. */
#ifndef IDEMIP_DNS_ENTRIES
#define IDEMIP_DNS_ENTRIES 8u
#endif

/** @brief DNS servers held, from DHCP or RFC 8106 RDNSS. */
#ifndef IDEMIP_DNS_SERVERS
#define IDEMIP_DNS_SERVERS 2u
#endif

/**
 * @brief Octets one held name spans, terminator included.
 *
 * RFC 1035 sec 2.3.4 size limits: "names 255 octets or less". lwIP DNS_MAX_NAME_LENGTH is the same
 * 256 with the terminator.
 */
#ifndef IDEMIP_DNS_NAME_MAX
#define IDEMIP_DNS_NAME_MAX 256u
#endif

/** @brief Names held: one per outstanding query, one per cached answer. */
#define IDEMIP_DNS_NAMES (IDEMIP_DNS_QUERIES + IDEMIP_DNS_ENTRIES)

/** @brief lwIP DNS_TMR_INTERVAL, milliseconds between two retry sweeps. */
#ifndef IDEMIP_DNS_TMR_INTERVAL_MS
#define IDEMIP_DNS_TMR_INTERVAL_MS 1000u
#endif

/** @brief lwIP DHCP_FINE_TIMER_MSECS, the request retransmission tick (RFC 2131 sec 4.1). */
#ifndef IDEMIP_DHCP4_FINE_TIMER_MS
#define IDEMIP_DHCP4_FINE_TIMER_MS 500u
#endif

/** @brief lwIP DHCP_COARSE_TIMER_SECS, the T1 and T2 lease tick (RFC 2131 sec 4.4.5). */
#ifndef IDEMIP_DHCP4_COARSE_TIMER_MS
#define IDEMIP_DHCP4_COARSE_TIMER_MS 60000u
#endif

/** @brief lwIP DHCP6_TIMER_MSECS, the retransmission tick (RFC 8415 sec 15). */
#ifndef IDEMIP_DHCP6_TIMER_MS
#define IDEMIP_DHCP6_TIMER_MS 500u
#endif

/**
 * @brief Octets one held DUID spans (RFC 8415 sec 11.1).
 *
 * "The length of the DUID (not including the type code) is at least 1 octet and at most 128
 * octets", so 130 with the 2-octet type code. A client holds the server's, which arrives opaque.
 */
#ifndef IDEMIP_DHCP6_DUID_MAX
#define IDEMIP_DHCP6_DUID_MAX 130u
#endif

/**
 * @brief Timeouts the list carries at once.
 *
 * lwIP MEMP_NUM_SYS_TIMEOUT is LWIP_NUM_SYS_TIMEOUT_INTERNAL, one deadline per active service
 * summed over the enabled features. The same sum here: one for TCP; three under IPv4 for
 * reassembly, ARP and IGMP; four under IPv6 for ND, reassembly, MLD and DAD; one for DNS; and four
 * per interface for ACD, AutoIP, DHCPv4 and DHCPv6.
 */
#ifndef IDEMIP_TIMEOUTS
#define IDEMIP_TIMEOUTS                                                                                                \
    ((IDEMIP_ENABLE_TCP * 1u) + (IDEMIP_ENABLE_IPV4 * 3u) + (IDEMIP_ENABLE_IPV6 * 4u) + 1u +                           \
     (IDEMIP_NETIF_COUNT * 4u))
#endif

// ---------------------------------------------------------------------------
// The borrow contract
// ---------------------------------------------------------------------------
/*
 * One IDEMIP_<UNIT>_BORROW per stateful unit, the way PROTOCORE_SHA256_BORROW is stated in
 * protocore_config.h. Each is a FORMULA over the counts above, never a number, so changing a count
 * resizes the borrow and no offset drifts.
 *
 * Three kinds of term appear in one:
 *
 *   IDEMIP_<UNIT>_CTX_BYTES        the running context, the region a unit keeps outside any table.
 *                                  A guess, kept generous. The unit's .c carries
 *                                  static_assert(sizeof(<Unit>Ctx) <= IDEMIP_<UNIT>_CTX_BYTES), so a
 *                                  context that outgrows it fails the build naming this macro.
 *   IDEMIP_<UNIT>_<T>_ENTRY_SHIFT  the width of one entry in table T, as a shift. THE ENTRY STRUCT
 *                                  IN THE .c MUST BE PADDED TO 1 << SHIFT, and the .c must assert
 *                                  sizeof(entry) == (1u << SHIFT), so an index is (i << SHIFT) and
 *                                  never (i * sizeof). Each width below is the field list the RFC
 *                                  or the lwIP struct names, rounded up to a power of two.
 *   a count                        from the sections above, so capacity and footprint move together.
 *
 * The borrow IS the instance, so a unit whose state the RFC puts on one interface has one borrow per
 * interface and the caller takes IDEMIP_NETIF_COUNT of them. Those are marked PER INTERFACE and
 * enter IDEMIP_TOTAL_BORROW scaled. No unit anywhere holds an instance table or a live count.
 */

// --- netif: RFC 1122 sec 3.3.1, RFC 4862 sec 5.5.4 -----------------------------------------------
// One entry per interface: the IPv4 address, mask and gateway RFC 1122 sec 3.3.1 routes an outbound
// datagram by, the MTU the link reports and the MTU a Router Advertisement revised, the hardware
// address, the flags, the checksum-offload mask, and the address of the phy borrow this interface is
// bound through. The IPv6 addresses are their own table, IDEMIP_IP6_ADDRESSES per interface, each
// holding the address, its state, and the preferred and valid lifetimes RFC 4862 sec 5.5.4 ages it
// by.
#ifndef IDEMIP_NETIF_ENTRY_SHIFT
#define IDEMIP_NETIF_ENTRY_SHIFT 6u
#endif
#ifndef IDEMIP_NETIF_ADDR6_ENTRY_SHIFT
#define IDEMIP_NETIF_ADDR6_ENTRY_SHIFT 5u
#endif
// The region ahead of the two tables carries the operand block as well as the context, the operands
// living in the borrow rather than on the namespace: 160 octets of NetifIo, then 32 for NetifCtx.
#ifndef IDEMIP_NETIF_CTX_BYTES
#define IDEMIP_NETIF_CTX_BYTES 192u
#endif
#define IDEMIP_NETIF_BORROW                                                                                            \
    (IDEMIP_NETIF_CTX_BYTES + (IDEMIP_NETIF_COUNT << IDEMIP_NETIF_ENTRY_SHIFT) +                                       \
     ((IDEMIP_NETIF_COUNT * IDEMIP_IP6_ADDRESSES) << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT))

// --- loopif: RFC 1122 sec 3.2.1.3, RFC 4291 sec 2.5.3 --------------------------------------------
// The context holds the two loopback addresses: RFC 1122 sec 3.2.1.3 case (g) "{ 127, <any> }
// Internal host loopback address", and RFC 4291 sec 2.5.3 "The unicast address 0:0:0:0:0:0:0:1 is
// called the loopback address". A looped frame has no DMA buffer to sit in, so the borrow carries
// IDEMIP_LOOPIF_FRAMES of them, each region wide enough for the 1500 octets RFC 8200 sec 5 requires
// a node to accept plus the Ethernet II header, at a power of two.
#ifndef IDEMIP_LOOPIF_FRAME_SHIFT
#define IDEMIP_LOOPIF_FRAME_SHIFT 11u
#endif
// The region ahead of the frame regions carries the operand block as well as the context: 88 octets
// of LoopifIo, then 64 for LoopifCtx.
#ifndef IDEMIP_LOOPIF_CTX_BYTES
#define IDEMIP_LOOPIF_CTX_BYTES 152u
#endif
#define IDEMIP_LOOPIF_BORROW (IDEMIP_LOOPIF_CTX_BYTES + (IDEMIP_LOOPIF_FRAMES << IDEMIP_LOOPIF_FRAME_SHIFT))

// --- dma: PLAN.md sec 3.5, PER INTERFACE ---------------------------------------------------------
// One descriptor ring belongs to one MAC, so this borrow is per interface. An entry holds the
// address of the frame buffer the driver owns, the length, the ownership and status flags, and the
// pin count that keeps a retained receive buffer out of the engine's hands. The buffers themselves
// are the driver's, reached through phy.h's claim entries, so no frame octet is in this borrow.
#ifndef IDEMIP_DMA_DESC_ENTRY_SHIFT
#define IDEMIP_DMA_DESC_ENTRY_SHIFT 4u
#endif
// The region ahead of the two rings carries the operand block as well as the context: 48 octets of
// DmaIo, then 48 for DmaCtx.
#ifndef IDEMIP_DMA_CTX_BYTES
#define IDEMIP_DMA_CTX_BYTES 96u
#endif
#define IDEMIP_DMA_BORROW                                                                                              \
    (IDEMIP_DMA_CTX_BYTES + (IDEMIP_RX_DESCRIPTORS << IDEMIP_DMA_DESC_ENTRY_SHIFT) +                                   \
     (IDEMIP_TX_DESCRIPTORS << IDEMIP_DMA_DESC_ENTRY_SHIFT))

// --- arp_table: RFC 826 --------------------------------------------------------------------------
// RFC 826 puts "the <protocol type, sender protocol address, sender hardware address> triplet" in
// the table, which over IPv4 on Ethernet is 2, 4 and 6 octets; an entry adds the state, the
// interface it was learned on, the head of its pending list, and the millisecond it was last used.
// A pending entry holds the pinned receive descriptor, the frame length, the table entry it waits
// on, its deadline, and the next index.
#ifndef IDEMIP_ARP_ENTRY_SHIFT
#define IDEMIP_ARP_ENTRY_SHIFT 5u
#endif
#ifndef IDEMIP_ARP_PENDING_ENTRY_SHIFT
#define IDEMIP_ARP_PENDING_ENTRY_SHIFT 4u
#endif
// The head region: the arp_table.h operand block, then the private context. sizeof(ArpTableIo) is 96
// on a 64-bit host and the context is 12, so the assert in arp_table.c holds at 128.
#ifndef IDEMIP_ARP_CTX_BYTES
#define IDEMIP_ARP_CTX_BYTES 128u
#endif
#define IDEMIP_ARP_BORROW                                                                                              \
    (IDEMIP_ARP_CTX_BYTES + (IDEMIP_ARP_ENTRIES << IDEMIP_ARP_ENTRY_SHIFT) +                                           \
     (IDEMIP_ARP_PENDING << IDEMIP_ARP_PENDING_ENTRY_SHIFT))

// --- ip4_route: RFC 1122 sec 3.3.1 ---------------------------------------------------------------
// An entry holds the destination, the mask, the next hop, the interface index, the flags, the
// metric, and the RFC 1191 path MTU with the millisecond it was learned.
#ifndef IDEMIP_IP4_ROUTE_ENTRY_SHIFT
#define IDEMIP_IP4_ROUTE_ENTRY_SHIFT 5u
#endif
// The head region: the ip4_route.h operand block, then the private context. sizeof(Ip4RouteIo) is 68
// on a 64-bit host and the context is 8, so the assert in ip4_route.c holds at 96.
#ifndef IDEMIP_IP4_ROUTE_CTX_BYTES
#define IDEMIP_IP4_ROUTE_CTX_BYTES 96u
#endif
#define IDEMIP_IP4_ROUTE_BORROW                                                                                        \
    (IDEMIP_IP4_ROUTE_CTX_BYTES + (IDEMIP_IP4_ROUTES << IDEMIP_IP4_ROUTE_ENTRY_SHIFT))

// --- ip4_reass: RFC 791 sec 3.2, RFC 815 ---------------------------------------------------------
// Three tables. A datagram entry keys on the RFC 791 sec 3.2 buffer identifier, "the concatenation
// of the source, destination, protocol, and identification fields", and carries its deadline, its
// running total length, and the heads of its fragment and hole lists. A fragment entry holds the
// pinned receive descriptor, the fragment offset, the length, the header length and the next index.
// A hole entry is RFC 815's own eight octets: "To store hole.first and hole.last will presumably
// require two octets each. An additional two octets will be required to thread together the entries
// on the hole descriptor list. This leaves at least two more octets to deal with implementation
// idiosyncrasies."
#ifndef IDEMIP_IP4_REASS_DATAGRAM_ENTRY_SHIFT
#define IDEMIP_IP4_REASS_DATAGRAM_ENTRY_SHIFT 5u
#endif
#ifndef IDEMIP_IP4_REASS_FRAG_ENTRY_SHIFT
#define IDEMIP_IP4_REASS_FRAG_ENTRY_SHIFT 4u
#endif
#ifndef IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT
#define IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT 3u
#endif
// The head region: the ip4_reass.h operand block, then the private context. sizeof(Ip4ReassIo) is 40
// on a 64-bit host and the context is 12, so the assert in ip4_reass.c holds at 64.
#ifndef IDEMIP_IP4_REASS_CTX_BYTES
#define IDEMIP_IP4_REASS_CTX_BYTES 64u
#endif
#define IDEMIP_IP4_REASS_BORROW                                                                                        \
    (IDEMIP_IP4_REASS_CTX_BYTES + (IDEMIP_IP4_REASS_DATAGRAMS << IDEMIP_IP4_REASS_DATAGRAM_ENTRY_SHIFT) +              \
     (IDEMIP_IP4_REASS_FRAGS << IDEMIP_IP4_REASS_FRAG_ENTRY_SHIFT) +                                                   \
     (IDEMIP_IP4_REASS_HOLES << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT))

// --- acd: RFC 5227, PER INTERFACE ----------------------------------------------------------------
// RFC 5227 sec 2.1 through sec 2.4 run one machine over one address: the address being probed, the
// state, the probes or announcements sent, the next deadline, the millisecond of the last defense,
// and the conflicts counted against MAX_CONFLICTS.
#ifndef IDEMIP_ACD_CTX_BYTES
#define IDEMIP_ACD_CTX_BYTES 32u
#endif
#define IDEMIP_ACD_BORROW (IDEMIP_ACD_CTX_BYTES)

// --- autoip: RFC 3927, PER INTERFACE -------------------------------------------------------------
// The selected 169.254/16 address, the state, and the count of addresses tried. The probing and
// defending is ACD's, in its own borrow.
#ifndef IDEMIP_AUTOIP_CTX_BYTES
#define IDEMIP_AUTOIP_CTX_BYTES 32u
#endif
#define IDEMIP_AUTOIP_BORROW (IDEMIP_AUTOIP_CTX_BYTES)

// --- igmp: RFC 2236 ------------------------------------------------------------------------------
// One table across interfaces, as lwIP MEMP_NUM_IGMP_GROUP counts "The number of multicast groups
// whose network interfaces can be members at the same time". An entry holds the group address, the
// interface index, the RFC 2236 sec 6 state, the last-reporter flag, and the report deadline.
#ifndef IDEMIP_IGMP_ENTRY_SHIFT
#define IDEMIP_IGMP_ENTRY_SHIFT 4u
#endif
#ifndef IDEMIP_IGMP_CTX_BYTES
#define IDEMIP_IGMP_CTX_BYTES 32u
#endif
#define IDEMIP_IGMP_BORROW (IDEMIP_IGMP_CTX_BYTES + (IDEMIP_IGMP_GROUPS << IDEMIP_IGMP_ENTRY_SHIFT))

// --- ip6_reass: RFC 8200 sec 4.5 -----------------------------------------------------------------
// The same three tables as IPv4, at IPv6 widths. RFC 8200 sec 4.5 matches the fragments of one
// packet by "the same IPv6 Source Address, IPv6 Destination Address, and Fragment Identification",
// 16, 16 and 4 octets, plus the deadline, the running total length, and the two list heads.
#ifndef IDEMIP_IP6_REASS_DATAGRAM_ENTRY_SHIFT
#define IDEMIP_IP6_REASS_DATAGRAM_ENTRY_SHIFT 6u
#endif
#ifndef IDEMIP_IP6_REASS_FRAG_ENTRY_SHIFT
#define IDEMIP_IP6_REASS_FRAG_ENTRY_SHIFT 4u
#endif
#ifndef IDEMIP_IP6_REASS_HOLE_ENTRY_SHIFT
#define IDEMIP_IP6_REASS_HOLE_ENTRY_SHIFT 3u
#endif
// Spans the operand block and the context together, as IDEMIP_PHY_BORROW does: ip6_reass.h puts
// Ip6ReassIo at offset zero and the context behind it, and the assert in ip6_reass.c fires naming
// this macro if either outgrows the pair.
#ifndef IDEMIP_IP6_REASS_CTX_BYTES
#define IDEMIP_IP6_REASS_CTX_BYTES 96u
#endif
#define IDEMIP_IP6_REASS_BORROW                                                                                        \
    (IDEMIP_IP6_REASS_CTX_BYTES + (IDEMIP_IP6_REASS_DATAGRAMS << IDEMIP_IP6_REASS_DATAGRAM_ENTRY_SHIFT) +              \
     (IDEMIP_IP6_REASS_FRAGS << IDEMIP_IP6_REASS_FRAG_ENTRY_SHIFT) +                                                   \
     (IDEMIP_IP6_REASS_HOLES << IDEMIP_IP6_REASS_HOLE_ENTRY_SHIFT))

// --- nd6: RFC 4861 sec 5.1, RFC 4862, PER INTERFACE ----------------------------------------------
// RFC 4861 sec 5.1: "Hosts will need to maintain the following pieces of information for each
// interface", then names the four. dad and slaac share this borrow, so the context carries their
// RFC 4862 sec 5.4 state as well.
//
//   neighbor cache    "keyed on the neighbor's on-link unicast IP address and contain such
//                     information as its link-layer address, a flag indicating whether the neighbor
//                     is a router..., a pointer to any queued packets..., the reachability state,
//                     the number of unanswered probes, and the time the next Neighbor
//                     Unreachability Detection event is scheduled": 16, 6, 1, 1, 1, 1 and 4 octets.
//   destination cache "maps a destination IP address to the IP address of the next-hop neighbor",
//                     with "the Path MTU (PMTU) and round-trip timers": 16, 16, 2 and 4, plus the
//                     shared neighbor index sec 5.1 requires.
//   prefix list       the prefix and "an associated invalidation timer value": 16 and 4, plus the
//                     prefix length and the interface index.
//   default router    "Router list entries point to entries in the Neighbor Cache" and each "has an
//                     associated invalidation timer value": an index, 4 octets, and the flags.
//   pending           one pinned receive descriptor per held frame, with its length, the neighbor it
//                     waits on, its deadline and the next index.
#ifndef IDEMIP_ND6_NEIGHBOR_ENTRY_SHIFT
#define IDEMIP_ND6_NEIGHBOR_ENTRY_SHIFT 5u
#endif
#ifndef IDEMIP_ND6_DESTINATION_ENTRY_SHIFT
#define IDEMIP_ND6_DESTINATION_ENTRY_SHIFT 6u
#endif
#ifndef IDEMIP_ND6_PREFIX_ENTRY_SHIFT
#define IDEMIP_ND6_PREFIX_ENTRY_SHIFT 5u
#endif
#ifndef IDEMIP_ND6_ROUTER_ENTRY_SHIFT
#define IDEMIP_ND6_ROUTER_ENTRY_SHIFT 3u
#endif
#ifndef IDEMIP_ND6_PENDING_ENTRY_SHIFT
#define IDEMIP_ND6_PENDING_ENTRY_SHIFT 4u
#endif
// Spans the operand block, the context, and the RFC 4862 sec 5.4 state dad.c and slaac.c keep in this
// borrow. nd6.h puts Nd6Io at offset zero and the context behind it, and the assert in nd6.c fires
// naming this macro if the pair outgrows it.
#ifndef IDEMIP_ND6_CTX_BYTES
#define IDEMIP_ND6_CTX_BYTES 320u
#endif
#define IDEMIP_ND6_BORROW                                                                                              \
    (IDEMIP_ND6_CTX_BYTES + (IDEMIP_ND6_NUM_NEIGHBORS << IDEMIP_ND6_NEIGHBOR_ENTRY_SHIFT) +                            \
     (IDEMIP_ND6_NUM_DESTINATIONS << IDEMIP_ND6_DESTINATION_ENTRY_SHIFT) +                                             \
     (IDEMIP_ND6_NUM_PREFIXES << IDEMIP_ND6_PREFIX_ENTRY_SHIFT) +                                                      \
     (IDEMIP_ND6_NUM_ROUTERS << IDEMIP_ND6_ROUTER_ENTRY_SHIFT) +                                                       \
     (IDEMIP_ND6_PENDING << IDEMIP_ND6_PENDING_ENTRY_SHIFT))

// --- mld6: RFC 2710 ------------------------------------------------------------------------------
// One table across interfaces, as lwIP MEMP_NUM_MLD6_GROUP counts them. An entry holds the 16-octet
// group address, the interface index, the state, the last-reporter flag, and the report deadline in
// milliseconds, which is what RFC 2710 sec 3.4 states Maximum Response Delay in.
#ifndef IDEMIP_MLD6_ENTRY_SHIFT
#define IDEMIP_MLD6_ENTRY_SHIFT 5u
#endif
// Spans the operand block and the context together, as IDEMIP_PHY_BORROW does: mld6.h puts Mld6Io at
// offset zero and the context behind it, and the assert in mld6.c fires naming this macro if either
// outgrows the pair.
#ifndef IDEMIP_MLD6_CTX_BYTES
#define IDEMIP_MLD6_CTX_BYTES 96u
#endif
#define IDEMIP_MLD6_BORROW (IDEMIP_MLD6_CTX_BYTES + (IDEMIP_MLD6_GROUPS << IDEMIP_MLD6_ENTRY_SHIFT))

// --- raw_pcb: RFC 1122 sec 3.4, RFC 3542 sec 3.1 -------------------------------------------------
// RFC 1122 sec 3.4 names what a binding onto IP itself carries, "SEND(src, dst, prot, TOS, TTL,
// BufPTR, len, Id, DF, opt => result )", the interface having to "provide full access to all the
// mechanisms of the IP layer, including options, Type-of-Service, and Time-to-Live". So an entry is
// the local and remote addresses at 16 octets each with their zones, the interface index, the type of
// service, the hop limit, the protocol, the flags, and the offset RFC 3542 sec 3.1's IPV6_CHECKSUM
// puts the checksum at.
#ifndef IDEMIP_RAW_PCB_ENTRY_SHIFT
#define IDEMIP_RAW_PCB_ENTRY_SHIFT 6u
#endif
// The region also carries raw_pcb.h's operand block, which is 120 octets, the context 4 behind it.
#ifndef IDEMIP_RAW_PCB_CTX_BYTES
#define IDEMIP_RAW_PCB_CTX_BYTES 160u
#endif
#define IDEMIP_RAW_PCB_BORROW (IDEMIP_RAW_PCB_CTX_BYTES + (IDEMIP_RAW_PCBS << IDEMIP_RAW_PCB_ENTRY_SHIFT))

// --- udp_pcb: RFC 768, RFC 1122 sec 4.1 ----------------------------------------------------------
// The same address pair and options as a raw pcb, plus the local and remote ports RFC 768 names, the
// multicast interface and hop limit, and the two RFC 3828 partial-coverage checksum lengths.
#ifndef IDEMIP_UDP_PCB_ENTRY_SHIFT
#define IDEMIP_UDP_PCB_ENTRY_SHIFT 6u
#endif
// The region also carries udp_pcb.h's operand block, which is 136 octets, the context 8 behind it.
#ifndef IDEMIP_UDP_PCB_CTX_BYTES
#define IDEMIP_UDP_PCB_CTX_BYTES 192u
#endif
#define IDEMIP_UDP_PCB_BORROW (IDEMIP_UDP_PCB_CTX_BYTES + (IDEMIP_UDP_PCBS << IDEMIP_UDP_PCB_ENTRY_SHIFT))

// --- tcp_pcb: RFC 9293 sec 3.3.1 -----------------------------------------------------------------
// Four tables. A TCB carries what RFC 9293 sec 3.3.1 lists: "the local and remote IP addresses and
// port numbers", then the send variables SND.UNA, SND.NXT, SND.WND, SND.UP, SND.WL1, SND.WL2 and
// ISS, and the receive variables RCV.NXT, RCV.WND, RCV.UP and IRS, at 4 octets each. Added to those:
// the sec 3.3.2 state, the RFC 6298 SRTT, RTTVAR and RTO with the retransmission count, the RFC 5681
// cwnd and ssthresh with the RFC 3465 byte counter, the RFC 7323 window scales and timestamps, the
// RFC 2018 SACK blocks at 8 octets each, the RFC 1122 sec 4.2.3.6 keepalive counters, and the heads
// of the three queues below. A listener is the address pair, the port, the state and the backlog. A
// send-queue segment is its sequence number, length, option flags and data reference. An
// out-of-order segment is the pinned receive descriptor with its sequence number, length and offset.
#ifndef IDEMIP_TCP_PCB_ENTRY_SHIFT
#define IDEMIP_TCP_PCB_ENTRY_SHIFT 8u
#endif
#ifndef IDEMIP_TCP_LISTEN_ENTRY_SHIFT
#define IDEMIP_TCP_LISTEN_ENTRY_SHIFT 6u
#endif
#ifndef IDEMIP_TCP_SEG_ENTRY_SHIFT
#define IDEMIP_TCP_SEG_ENTRY_SHIFT 5u
#endif
#ifndef IDEMIP_TCP_OOSEQ_ENTRY_SHIFT
#define IDEMIP_TCP_OOSEQ_ENTRY_SHIFT 4u
#endif
// The region also carries tcp_pcb.h's operand block, which is 360 octets, the context 8 behind it.
// The block holds one whole TCB's worth of fields, load and store copying the RFC 9293 sec 3.3.1
// variables, the sec 3.3.2 state and the estimator and congestion state through it.
#ifndef IDEMIP_TCP_PCB_CTX_BYTES
#define IDEMIP_TCP_PCB_CTX_BYTES 416u
#endif
#define IDEMIP_TCP_PCB_BORROW                                                                                          \
    (IDEMIP_TCP_PCB_CTX_BYTES + (IDEMIP_TCP_PCBS << IDEMIP_TCP_PCB_ENTRY_SHIFT) +                                      \
     (IDEMIP_TCP_LISTEN_PCBS << IDEMIP_TCP_LISTEN_ENTRY_SHIFT) +                                                       \
     (IDEMIP_TCP_SEGS << IDEMIP_TCP_SEG_ENTRY_SHIFT) +                                                                 \
     ((IDEMIP_TCP_PCBS * IDEMIP_TCP_OOSEQ_SEGS) << IDEMIP_TCP_OOSEQ_ENTRY_SHIFT))

// --- tcp_isn: RFC 6528 ---------------------------------------------------------------------------
// The context holds the secret key and the 4-microsecond timer's base. The block is the
// connection-id the PRF is fed, and the hash region is the PRF's working set; both are regions of
// the borrow because no array here has automatic storage duration.
// The region also carries tcp_isn.h's operand block, which is 64 octets, the context 28 behind it:
// the secret key, M's base, and the mark reset leaves.
#ifndef IDEMIP_TCP_ISN_CTX_BYTES
#define IDEMIP_TCP_ISN_CTX_BYTES 128u
#endif
#define IDEMIP_TCP_ISN_BORROW (IDEMIP_TCP_ISN_CTX_BYTES + IDEMIP_TCP_ISN_BLOCK_BYTES + IDEMIP_TCP_ISN_HASH_BYTES)

// --- dhcp4: RFC 2131, PER INTERFACE --------------------------------------------------------------
// One lease machine per interface: the sec 4.4 state, the 'xid' sec 4.1 matches replies on, the
// retry count and its deadline, the server that offered the lease, the offered address, mask and
// gateway, and the sec 4.4.5 lease time with T1 and T2. The RFC 2131 sec 2 'file' field is not in
// it; a build that wants BOOTP's 128-octet boot file name raises this macro.
//
// dhcp4 holds no table, so this region is the whole borrow and carries the operand block of dhcp4.h
// as well as the context: 144 and 72 octets on a target with 8-octet pointers.
#ifndef IDEMIP_DHCP4_CTX_BYTES
#define IDEMIP_DHCP4_CTX_BYTES 232u
#endif
#define IDEMIP_DHCP4_BORROW (IDEMIP_DHCP4_CTX_BYTES)

// --- dhcp6: RFC 8415, PER INTERFACE --------------------------------------------------------------
// The sec 18 state machine, the transaction id, the retry count and its sec 15 deadline, and the
// sec 21.4 IA_NA with its IAID, T1, T2 and the sec 21.6 IAADDR address with its preferred and valid
// lifetimes. The server's DUID gets its own region, being opaque and up to IDEMIP_DHCP6_DUID_MAX
// octets.
//
// This region carries the operand block of dhcp6.h as well as the context, the DUID region following
// both: 168 and 104 octets on a target with 8-octet pointers.
#ifndef IDEMIP_DHCP6_CTX_BYTES
#define IDEMIP_DHCP6_CTX_BYTES 288u
#endif
#define IDEMIP_DHCP6_BORROW (IDEMIP_DHCP6_CTX_BYTES + IDEMIP_ROUND_UP(IDEMIP_DHCP6_DUID_MAX, IDEMIP_ALIGN))

// --- dns: RFC 1035, RFC 5452 ---------------------------------------------------------------------
// A query entry holds the RFC 5452 random transaction id and source port, the server index, the
// retry count, the state, its deadline, and the index of the name it asked for. A cached entry holds
// the answer address, the RFC 1035 sec 3.2.1 TYPE, the TTL and the same name index. Names are one
// table at IDEMIP_DNS_NAME_MAX each, one per query and one per cached answer. A server entry is an
// address with its zone.
#ifndef IDEMIP_DNS_QUERY_ENTRY_SHIFT
#define IDEMIP_DNS_QUERY_ENTRY_SHIFT 5u
#endif
#ifndef IDEMIP_DNS_ENTRY_SHIFT
#define IDEMIP_DNS_ENTRY_SHIFT 5u
#endif
#ifndef IDEMIP_DNS_NAME_SHIFT
#define IDEMIP_DNS_NAME_SHIFT 8u
#endif
#ifndef IDEMIP_DNS_SERVER_ENTRY_SHIFT
#define IDEMIP_DNS_SERVER_ENTRY_SHIFT 5u
#endif
// This region carries the operand block of dns.h as well as the context, the four tables following
// both: 200 and 16 octets on a target with 8-octet pointers.
#ifndef IDEMIP_DNS_CTX_BYTES
#define IDEMIP_DNS_CTX_BYTES 232u
#endif
#define IDEMIP_DNS_BORROW                                                                                              \
    (IDEMIP_DNS_CTX_BYTES + (IDEMIP_DNS_QUERIES << IDEMIP_DNS_QUERY_ENTRY_SHIFT) +                                     \
     (IDEMIP_DNS_ENTRIES << IDEMIP_DNS_ENTRY_SHIFT) + (IDEMIP_DNS_NAMES << IDEMIP_DNS_NAME_SHIFT) +                    \
     (IDEMIP_DNS_SERVERS << IDEMIP_DNS_SERVER_ENTRY_SHIFT))

// --- timeouts ------------------------------------------------------------------------------------
// An entry is a millisecond deadline, the id of the unit whose tick it belongs to, an argument index
// into that unit's own table, the flags, and the next index. No entry holds a function pointer: the
// tick order is fixed in core/dispatch.c, so a deadline names a unit rather than dispatching to one.
#ifndef IDEMIP_TIMEOUT_ENTRY_SHIFT
#define IDEMIP_TIMEOUT_ENTRY_SHIFT 3u
#endif
#ifndef IDEMIP_TIMEOUTS_CTX_BYTES
#define IDEMIP_TIMEOUTS_CTX_BYTES 32u
#endif
#define IDEMIP_TIMEOUTS_BORROW (IDEMIP_TIMEOUTS_CTX_BYTES + (IDEMIP_TIMEOUTS << IDEMIP_TIMEOUT_ENTRY_SHIFT))

// --- stats: RFC 1213 -----------------------------------------------------------------------------
// The context holds the counters RFC 1213 defines outside its per-interface table: 17 in the IP
// group of sec 6.6, 26 in the ICMP group of sec 6.7, 10 in the TCP group of sec 6.8 and 4 in the UDP
// group of sec 6.9, at 4 octets each, with the IP and ICMP groups counted once for IPv4 and once for
// IPv6. The per-interface entry is the 13 counters and gauges of the sec 6.4 ifEntry: ifSpeed,
// ifInOctets, ifInUcastPkts, ifInNUcastPkts, ifInDiscards, ifInErrors, ifInUnknownProtos,
// ifOutOctets, ifOutUcastPkts, ifOutNUcastPkts, ifOutDiscards, ifOutErrors and ifOutQLen.
#ifndef IDEMIP_STATS_IF_ENTRY_SHIFT
#define IDEMIP_STATS_IF_ENTRY_SHIFT 6u
#endif
#ifndef IDEMIP_STATS_CTX_BYTES
#define IDEMIP_STATS_CTX_BYTES 512u
#endif
#define IDEMIP_STATS_BORROW (IDEMIP_STATS_CTX_BYTES + (IDEMIP_NETIF_COUNT << IDEMIP_STATS_IF_ENTRY_SHIFT))

// --- the whole footprint -------------------------------------------------------------------------

/**
 * @brief Every borrow a per-interface unit takes, for one interface.
 *
 * phy, dma, nd6, acd, autoip, dhcp4 and dhcp6 hold state the RFC puts on one interface, so the
 * caller takes IDEMIP_NETIF_COUNT of each.
 */
#define IDEMIP_PER_NETIF_BORROW                                                                                        \
    (IDEMIP_PHY_BORROW + IDEMIP_DMA_BORROW + IDEMIP_ND6_BORROW + IDEMIP_ACD_BORROW + IDEMIP_AUTOIP_BORROW +            \
     IDEMIP_DHCP4_BORROW + IDEMIP_DHCP6_BORROW)

/** @brief Every borrow a unit holding one table across all interfaces takes. */
#define IDEMIP_SHARED_BORROW                                                                                           \
    (IDEMIP_NETIF_BORROW + IDEMIP_LOOPIF_BORROW + IDEMIP_ARP_BORROW + IDEMIP_IP4_ROUTE_BORROW +                        \
     IDEMIP_IP4_REASS_BORROW + IDEMIP_IGMP_BORROW + IDEMIP_IP6_REASS_BORROW + IDEMIP_MLD6_BORROW +                     \
     IDEMIP_RAW_PCB_BORROW + IDEMIP_UDP_PCB_BORROW + IDEMIP_TCP_PCB_BORROW + IDEMIP_TCP_ISN_BORROW +                   \
     IDEMIP_DNS_BORROW + IDEMIP_TIMEOUTS_BORROW + IDEMIP_STATS_BORROW)

/**
 * @brief Every octet of .bss a full build takes, so the footprint is one number a reader can see.
 *
 * 20696 bytes at the default counts and IDEMIP_NETIF_COUNT of 2: 14488 shared, and 3104 for each
 * interface. The frame buffers are not in it, being the driver's storage rather than any borrow's,
 * and neither is the caller's own stack. tools/idemip_sizes.c prints every term.
 */
#define IDEMIP_TOTAL_BORROW (IDEMIP_SHARED_BORROW + (IDEMIP_NETIF_COUNT * IDEMIP_PER_NETIF_BORROW))

// ---------------------------------------------------------------------------
// The receive ring cannot starve
// ---------------------------------------------------------------------------

/**
 * @brief Receive descriptors every retaining unit can hold pinned at once.
 *
 * A retained frame stays in the buffer the DMA engine wrote it to, so the descriptor is not
 * returned to the ring until the unit holding it is done. Every one of these capacities is fixed
 * above, so the worst case is a number rather than a risk.
 *
 * The five terms are every table above whose entry holds a pinned receive descriptor. The loopback
 * frames are loopif's own region and the DNS names are the resolver's own, so neither pins one, and
 * the send-queue and listener tables face the transmit ring.
 */
#define IDEMIP_MAX_PINNED_FRAMES                                                                                       \
    (IDEMIP_IP4_REASS_FRAGS + IDEMIP_IP6_REASS_FRAGS + (IDEMIP_TCP_PCBS * IDEMIP_TCP_OOSEQ_SEGS) +                     \
     IDEMIP_ARP_PENDING + IDEMIP_ND6_PENDING)

static_assert(IDEMIP_RX_DESCRIPTORS > IDEMIP_MAX_PINNED_FRAMES,
              "the receive ring starves when every retaining unit is full: raise IDEMIP_RX_DESCRIPTORS above "
              "IDEMIP_MAX_PINNED_FRAMES, or lower a retention count");

static_assert((IDEMIP_CACHE_LINE_BYTES & (IDEMIP_CACHE_LINE_BYTES - 1u)) == 0u,
              "IDEMIP_CACHE_LINE_BYTES must be a power of two: a buffer stride rounds up to it with a mask");

static_assert((IDEMIP_ALIGN & (IDEMIP_ALIGN - 1u)) == 0u, "IDEMIP_ALIGN must be a power of two");

static_assert((IDEMIP_RX_DESCRIPTORS & (IDEMIP_RX_DESCRIPTORS - 1u)) == 0u,
              "IDEMIP_RX_DESCRIPTORS must be a power of two: the ring index is a mask");

static_assert((IDEMIP_TX_DESCRIPTORS & (IDEMIP_TX_DESCRIPTORS - 1u)) == 0u,
              "IDEMIP_TX_DESCRIPTORS must be a power of two: the ring index is a mask");

// ---------------------------------------------------------------------------
// The borrow map holds together
// ---------------------------------------------------------------------------

static_assert(IDEMIP_NETIF_COUNT >= 1u,
              "IDEMIP_NETIF_COUNT must be at least one: every borrow above is an interface's");

// Every table starts right after its context and every entry after the one before it, so a context
// that is not a multiple of IDEMIP_ALIGN, or an entry narrower than it, misaligns the table.
static_assert(((IDEMIP_NETIF_CTX_BYTES | IDEMIP_LOOPIF_CTX_BYTES | IDEMIP_DMA_CTX_BYTES | IDEMIP_ARP_CTX_BYTES |
                IDEMIP_IP4_ROUTE_CTX_BYTES | IDEMIP_IP4_REASS_CTX_BYTES | IDEMIP_ACD_CTX_BYTES |
                IDEMIP_AUTOIP_CTX_BYTES | IDEMIP_IGMP_CTX_BYTES | IDEMIP_IP6_REASS_CTX_BYTES | IDEMIP_ND6_CTX_BYTES |
                IDEMIP_MLD6_CTX_BYTES | IDEMIP_RAW_PCB_CTX_BYTES | IDEMIP_UDP_PCB_CTX_BYTES |
                IDEMIP_TCP_PCB_CTX_BYTES | IDEMIP_TCP_ISN_CTX_BYTES | IDEMIP_DHCP4_CTX_BYTES |
                IDEMIP_DHCP6_CTX_BYTES | IDEMIP_DNS_CTX_BYTES | IDEMIP_TIMEOUTS_CTX_BYTES | IDEMIP_STATS_CTX_BYTES) &
               (IDEMIP_ALIGN - 1u)) == 0u,
              "every IDEMIP_*_CTX_BYTES must be a multiple of IDEMIP_ALIGN: a table starts at the end of its context");

static_assert((1u << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT) >= IDEMIP_ALIGN &&
                  (1u << IDEMIP_ND6_ROUTER_ENTRY_SHIFT) >= IDEMIP_ALIGN &&
                  (1u << IDEMIP_TIMEOUT_ENTRY_SHIFT) >= IDEMIP_ALIGN,
              "the narrowest entry width must still be IDEMIP_ALIGN or wider: entry i sits at (i << SHIFT)");

// RFC 815 sizes the hole descriptor itself: two octets for hole.first, two for hole.last, two to
// thread the list, and two spare.
static_assert((1u << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT) >= 8u && (1u << IDEMIP_IP6_REASS_HOLE_ENTRY_SHIFT) >= 8u,
              "a hole descriptor is eight octets (RFC 815): raise IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT");

// RFC 815 opens a datagram with one hole and each fragment adds at most one.
static_assert(IDEMIP_IP4_REASS_HOLES >= IDEMIP_IP4_REASS_DATAGRAMS + IDEMIP_IP4_REASS_FRAGS &&
                  IDEMIP_IP6_REASS_HOLES >= IDEMIP_IP6_REASS_DATAGRAMS + IDEMIP_IP6_REASS_FRAGS,
              "the hole list is short of one hole per datagram plus one per fragment (RFC 815)");

// RFC 1035 sec 2.3.4: "names 255 octets or less", and the terminator makes 256.
static_assert(IDEMIP_DNS_NAME_MAX >= 256u, "IDEMIP_DNS_NAME_MAX is short of RFC 1035 sec 2.3.4's 255 octets");
static_assert((1u << IDEMIP_DNS_NAME_SHIFT) >= IDEMIP_DNS_NAME_MAX,
              "the name region is narrower than IDEMIP_DNS_NAME_MAX: raise IDEMIP_DNS_NAME_SHIFT");

// RFC 8415 sec 11.1: at most 128 octets, behind a 2-octet type code.
static_assert(IDEMIP_DHCP6_DUID_MAX >= 130u, "IDEMIP_DHCP6_DUID_MAX is short of RFC 8415 sec 11.1's 128 octets");

// RFC 6528 sec 3 feeds the PRF localip, localport, remoteip, remoteport and the key: 16, 2, 16, 2.
static_assert(IDEMIP_TCP_ISN_SECRET_BYTES >= 16u, "RFC 6528 sec 3: \"Key lengths of 128 bits should be adequate\"");
static_assert(IDEMIP_TCP_ISN_BLOCK_BYTES >= 36u + IDEMIP_TCP_ISN_SECRET_BYTES,
              "the connection-id block is short of RFC 6528 sec 3's inputs and the key");

// A looped frame is held in the borrow, so its region carries a whole one.
static_assert((1u << IDEMIP_LOOPIF_FRAME_SHIFT) >= IDEMIP_DMA_FRAME_MAX,
              "a loopback frame region is narrower than a frame: raise IDEMIP_LOOPIF_FRAME_SHIFT");

// A partial cache line invalidate discards whatever shares the line, so a buffer spans whole ones.
static_assert((IDEMIP_DMA_BUF_STRIDE & (IDEMIP_CACHE_LINE_BYTES - 1u)) == 0u,
              "IDEMIP_DMA_BUF_STRIDE must span whole cache lines");

// RFC 5227 sec 2.1.1 draws each probe delay from PROBE_MIN through PROBE_MAX.
static_assert(IDEMIP_ACD_PROBE_MAX_MS > IDEMIP_ACD_PROBE_MIN_MS,
              "RFC 5227 sec 1.1 puts PROBE_MAX above PROBE_MIN: the delay is drawn between them");

// One deadline per service, and every interface runs four of them.
static_assert(IDEMIP_TIMEOUTS >= (IDEMIP_NETIF_COUNT * 4u),
              "IDEMIP_TIMEOUTS is short of four deadlines per interface: ACD, AutoIP, DHCPv4 and DHCPv6");

#endif // IDEMIP_CONFIG_H
