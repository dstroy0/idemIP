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

/** @brief Interfaces this build carries. Forwarding needs at least two. */
#ifndef IDEMIP_NETIF_COUNT
#define IDEMIP_NETIF_COUNT 2u
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

/** @brief Fragments held during reassembly. Each pins a receive descriptor. */
#ifndef IDEMIP_IP4_REASS_FRAGS
#define IDEMIP_IP4_REASS_FRAGS 8u
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

/** @brief IPv4 multicast groups joined (RFC 2236). */
#ifndef IDEMIP_IGMP_GROUPS
#define IDEMIP_IGMP_GROUPS 4u
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

/** @brief Fragments held during IPv6 reassembly. Each pins a receive descriptor. */
#ifndef IDEMIP_IP6_REASS_FRAGS
#define IDEMIP_IP6_REASS_FRAGS 8u
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

// ---------------------------------------------------------------------------
// The receive ring cannot starve
// ---------------------------------------------------------------------------

/**
 * @brief Receive descriptors every retaining unit can hold pinned at once.
 *
 * A retained frame stays in the buffer the DMA engine wrote it to, so the descriptor is not
 * returned to the ring until the unit holding it is done. Every one of these capacities is fixed
 * above, so the worst case is a number rather than a risk.
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

#endif // IDEMIP_CONFIG_H
