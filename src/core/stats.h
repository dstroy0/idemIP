// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file stats.h
 * @brief The per-protocol counters, one MIB object each.
 *
 * One counter per object, at the object's own name. Four documents name them, one per protocol
 * version, because IPv6 was given its own MIBs rather than a second index on IPv4's:
 *
 *   RFC 1213 sec 6.6   the IP group, 17 counters, IPv4
 *   RFC 1213 sec 6.7   the ICMP group, 26 counters, ICMPv4
 *   RFC 2465 sec 4     ipv6IfStatsEntry, 20 counters, IPv6
 *   RFC 2466 sec 4     ipv6IfIcmpEntry, 34 counters, ICMPv6
 *   RFC 1213 sec 6.8   the TCP group, 10 counters, both versions
 *   RFC 1213 sec 6.9   the UDP group, 4 counters, both versions
 *
 * and the 13 counters and gauges of RFC 1213 sec 6.4's ifEntry, one set per interface.
 *
 * The two IPv6 sets are not the IPv4 sets renamed. RFC 2465 drops ipRoutingDiscards and adds
 * ipv6IfStatsInTooBigErrors, InTruncatedPkts, InMcastPkts and OutMcastPkts; it counts a route
 * failure on the way in (ipv6IfStatsInNoRoutes) where RFC 1213 counts it on the way out
 * (ipOutNoRoutes). RFC 2466 drops the four Source Quench, Timestamp and Address Mask pairs RFC 4443
 * defines no message for, and adds a pair each for Packet Too Big, the four RFC 4861 Neighbor
 * Discovery types, the three RFC 2710 Multicast Listener types, and Destination Unreachable Code 1.
 *
 * RFC 1213 imports Counter and Gauge from RFC 1155; RFC 2465 and RFC 2466 use RFC 2578's Counter32,
 * "which increases monotonically until it reaches a maximum value of 2^32-1, when it wraps around
 * and starts increasing again from zero" (sec 7.1.6) - the same object under a later name. A
 * Counter is what @ref StatsNs::bump does. A Gauge "may increase or decrease, but ... latches at a
 * maximum value" (RFC 1155 sec 3.2.3.4), which is what @ref StatsNs::set does. ifSpeed, ifOutQLen
 * and tcpCurrEstab are the three gauges.
 *
 * A counter with no event to reach it is still carried, so the id block is the MIB's shape and not
 * this library's. There are three reasons one is carried and never written, and no fourth:
 *
 *   the RFC 1155 sec 3.2.3.4 gauges, which @ref StatsNs::set writes off the thing they measure -
 *   the PHY's link speed, the driver's transmit queue, the count of TCB rows in a state - rather
 *   than accumulating, so no event bumps them and tracking one by deltas would only drift;
 *
 *   the Address Mask ids, both directions, RFC 1122 sec 3.2.2.9 leaving the pair optional and this
 *   library not carrying it, so there is no message to count;
 *
 *   and the send path. Dispatch holds this borrow and walks one frame IN, so what goes out is the
 *   caller's, driving IcmpIn.error, the fragmenters, the forwarders, TcpOut, the ND and MLD senders
 *   and the DMA engine - and the caller holds this same borrow, so bump is in its reach for all of
 *   them.
 *
 * WHICH ids those are is not written here. A list in a comment goes stale the moment it is right,
 * and one already had: it said "the out counters of both groups" on the IPv6 side of a library that
 * was that way throughout, IPv4 and the interface included. Run tools/dev_env/counters.py, which
 * computes the set from the source, holds the reason for each, and fails when the set moves.
 *
 * Five out counters are not on it, because this library builds those messages itself and no caller
 * could count them without re-parsing what dispatch just handed back: tcpOutRsts for the resets
 * dispatch sends, and icmpOutMsgs and icmpOutEchoReps with their two RFC 2466 twins for the echo
 * replies icmp_in and icmp6_in build.
 */

#ifndef IDEMIP_STATS_H
#define IDEMIP_STATS_H

#include "src/idemip_config.h"

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/**
 * @brief Which counter a call names. The id IS the index into the counter block.
 *
 * Grouped in layout order: the IPv4 IP group, the ICMPv4 group, the IPv6 IP group, the ICMPv6
 * group, the TCP group, the UDP group. Each name is its own MIB's object, with the prefix the MIB
 * itself uses dropped: IDEMIP_STAT_IP4_IN_RECEIVES is RFC 1213's ipInReceives,
 * IDEMIP_STAT_IP6_IN_RECEIVES is RFC 2465's ipv6IfStatsInReceives, and
 * IDEMIP_STAT_ICMP6_IN_PKT_TOO_BIGS is RFC 2466's ipv6IfIcmpInPktTooBigs.
 *
 * So a name is not a v4 name with the version swapped, and the two sides differ where the MIBs do:
 * ICMP4_IN_PARM_PROBS is icmpInParmProbs and ICMP6_IN_PARM_PROBLEMS is ipv6IfIcmpInParmProblems;
 * ICMP4_IN_ECHO_REPS is icmpInEchoReps and ICMP6_IN_ECHO_REPLIES is ipv6IfIcmpInEchoReplies.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    // RFC 1213 sec 6.6, the IP group, for IPv4.
    IDEMIP_STAT_IP4_IN_RECEIVES = 0,
    IDEMIP_STAT_IP4_IN_HDR_ERRORS,
    IDEMIP_STAT_IP4_IN_ADDR_ERRORS,
    IDEMIP_STAT_IP4_FORW_DATAGRAMS,
    IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS,
    IDEMIP_STAT_IP4_IN_DISCARDS,
    IDEMIP_STAT_IP4_IN_DELIVERS,
    IDEMIP_STAT_IP4_OUT_REQUESTS,
    IDEMIP_STAT_IP4_OUT_DISCARDS,
    IDEMIP_STAT_IP4_OUT_NO_ROUTES,
    IDEMIP_STAT_IP4_REASM_REQDS,
    IDEMIP_STAT_IP4_REASM_OKS,
    IDEMIP_STAT_IP4_REASM_FAILS,
    IDEMIP_STAT_IP4_FRAG_OKS,
    IDEMIP_STAT_IP4_FRAG_FAILS,
    IDEMIP_STAT_IP4_FRAG_CREATES,
    IDEMIP_STAT_IP4_ROUTING_DISCARDS,

    // RFC 1213 sec 6.7, the ICMP group, for ICMPv4.
    IDEMIP_STAT_ICMP4_IN_MSGS,
    IDEMIP_STAT_ICMP4_IN_ERRORS,
    IDEMIP_STAT_ICMP4_IN_DEST_UNREACHS,
    IDEMIP_STAT_ICMP4_IN_TIME_EXCDS,
    IDEMIP_STAT_ICMP4_IN_PARM_PROBS,
    IDEMIP_STAT_ICMP4_IN_SRC_QUENCHS,
    IDEMIP_STAT_ICMP4_IN_REDIRECTS,
    IDEMIP_STAT_ICMP4_IN_ECHOS,
    IDEMIP_STAT_ICMP4_IN_ECHO_REPS,
    IDEMIP_STAT_ICMP4_IN_TIMESTAMPS,
    IDEMIP_STAT_ICMP4_IN_TIMESTAMP_REPS,
    IDEMIP_STAT_ICMP4_IN_ADDR_MASKS,
    IDEMIP_STAT_ICMP4_IN_ADDR_MASK_REPS,
    IDEMIP_STAT_ICMP4_OUT_MSGS,
    IDEMIP_STAT_ICMP4_OUT_ERRORS,
    IDEMIP_STAT_ICMP4_OUT_DEST_UNREACHS,
    IDEMIP_STAT_ICMP4_OUT_TIME_EXCDS,
    IDEMIP_STAT_ICMP4_OUT_PARM_PROBS,
    IDEMIP_STAT_ICMP4_OUT_SRC_QUENCHS,
    IDEMIP_STAT_ICMP4_OUT_REDIRECTS,
    IDEMIP_STAT_ICMP4_OUT_ECHOS,
    IDEMIP_STAT_ICMP4_OUT_ECHO_REPS,
    IDEMIP_STAT_ICMP4_OUT_TIMESTAMPS,
    IDEMIP_STAT_ICMP4_OUT_TIMESTAMP_REPS,
    IDEMIP_STAT_ICMP4_OUT_ADDR_MASKS,
    IDEMIP_STAT_ICMP4_OUT_ADDR_MASK_REPS,

    // RFC 2465 sec 4, ipv6IfStatsEntry, in its own order: entry 1 through entry 20.
    IDEMIP_STAT_IP6_IN_RECEIVES,
    IDEMIP_STAT_IP6_IN_HDR_ERRORS,
    IDEMIP_STAT_IP6_IN_TOO_BIG_ERRORS,
    IDEMIP_STAT_IP6_IN_NO_ROUTES,
    IDEMIP_STAT_IP6_IN_ADDR_ERRORS,
    IDEMIP_STAT_IP6_IN_UNKNOWN_PROTOS,
    IDEMIP_STAT_IP6_IN_TRUNCATED_PKTS,
    IDEMIP_STAT_IP6_IN_DISCARDS,
    IDEMIP_STAT_IP6_IN_DELIVERS,
    IDEMIP_STAT_IP6_OUT_FORW_DATAGRAMS,
    IDEMIP_STAT_IP6_OUT_REQUESTS,
    IDEMIP_STAT_IP6_OUT_DISCARDS,
    IDEMIP_STAT_IP6_OUT_FRAG_OKS,
    IDEMIP_STAT_IP6_OUT_FRAG_FAILS,
    IDEMIP_STAT_IP6_OUT_FRAG_CREATES,
    IDEMIP_STAT_IP6_REASM_REQDS,
    IDEMIP_STAT_IP6_REASM_OKS,
    IDEMIP_STAT_IP6_REASM_FAILS,
    IDEMIP_STAT_IP6_IN_MCAST_PKTS,
    IDEMIP_STAT_IP6_OUT_MCAST_PKTS,

    // RFC 2466 sec 4, ipv6IfIcmpEntry, in its own order: entry 1 through entry 34.
    IDEMIP_STAT_ICMP6_IN_MSGS,
    IDEMIP_STAT_ICMP6_IN_ERRORS,
    IDEMIP_STAT_ICMP6_IN_DEST_UNREACHS,
    IDEMIP_STAT_ICMP6_IN_ADMIN_PROHIBS,
    IDEMIP_STAT_ICMP6_IN_TIME_EXCDS,
    IDEMIP_STAT_ICMP6_IN_PARM_PROBLEMS,
    IDEMIP_STAT_ICMP6_IN_PKT_TOO_BIGS,
    IDEMIP_STAT_ICMP6_IN_ECHOS,
    IDEMIP_STAT_ICMP6_IN_ECHO_REPLIES,
    IDEMIP_STAT_ICMP6_IN_ROUTER_SOLICITS,
    IDEMIP_STAT_ICMP6_IN_ROUTER_ADVERTISEMENTS,
    IDEMIP_STAT_ICMP6_IN_NEIGHBOR_SOLICITS,
    IDEMIP_STAT_ICMP6_IN_NEIGHBOR_ADVERTISEMENTS,
    IDEMIP_STAT_ICMP6_IN_REDIRECTS,
    IDEMIP_STAT_ICMP6_IN_GROUP_MEMB_QUERIES,
    IDEMIP_STAT_ICMP6_IN_GROUP_MEMB_RESPONSES,
    IDEMIP_STAT_ICMP6_IN_GROUP_MEMB_REDUCTIONS,
    IDEMIP_STAT_ICMP6_OUT_MSGS,
    IDEMIP_STAT_ICMP6_OUT_ERRORS,
    IDEMIP_STAT_ICMP6_OUT_DEST_UNREACHS,
    IDEMIP_STAT_ICMP6_OUT_ADMIN_PROHIBS,
    IDEMIP_STAT_ICMP6_OUT_TIME_EXCDS,
    IDEMIP_STAT_ICMP6_OUT_PARM_PROBLEMS,
    IDEMIP_STAT_ICMP6_OUT_PKT_TOO_BIGS,
    IDEMIP_STAT_ICMP6_OUT_ECHOS,
    IDEMIP_STAT_ICMP6_OUT_ECHO_REPLIES,
    IDEMIP_STAT_ICMP6_OUT_ROUTER_SOLICITS,
    IDEMIP_STAT_ICMP6_OUT_ROUTER_ADVERTISEMENTS,
    IDEMIP_STAT_ICMP6_OUT_NEIGHBOR_SOLICITS,
    IDEMIP_STAT_ICMP6_OUT_NEIGHBOR_ADVERTISEMENTS,
    IDEMIP_STAT_ICMP6_OUT_REDIRECTS,
    IDEMIP_STAT_ICMP6_OUT_GROUP_MEMB_QUERIES,
    IDEMIP_STAT_ICMP6_OUT_GROUP_MEMB_RESPONSES,
    IDEMIP_STAT_ICMP6_OUT_GROUP_MEMB_REDUCTIONS,

    // RFC 1213 sec 6.8, the TCP group. tcpCurrEstab is a Gauge.
    IDEMIP_STAT_TCP_ACTIVE_OPENS,
    IDEMIP_STAT_TCP_PASSIVE_OPENS,
    IDEMIP_STAT_TCP_ATTEMPT_FAILS,
    IDEMIP_STAT_TCP_ESTAB_RESETS,
    IDEMIP_STAT_TCP_CURR_ESTAB,
    IDEMIP_STAT_TCP_IN_SEGS,
    IDEMIP_STAT_TCP_OUT_SEGS,
    IDEMIP_STAT_TCP_RETRANS_SEGS,
    IDEMIP_STAT_TCP_IN_ERRS,
    IDEMIP_STAT_TCP_OUT_RSTS,

    // RFC 1213 sec 6.9, the UDP group.
    IDEMIP_STAT_UDP_IN_DATAGRAMS,
    IDEMIP_STAT_UDP_NO_PORTS,
    IDEMIP_STAT_UDP_IN_ERRORS,
    IDEMIP_STAT_UDP_OUT_DATAGRAMS,

    IDEMIP_STAT_COUNT, ///< one past the last counter, so a bad id is one compare
} IdemIpStatsCounter;

/**
 * @brief Which per-interface counter a call names. The id IS the index into an interface's entry.
 *
 * RFC 1213 sec 6.4's ifEntry, its counters and gauges only. ifSpeed and ifOutQLen are the two
 * gauges; ifIndex, ifDescr, ifType, ifMtu, ifPhysAddress, ifAdminStatus, ifOperStatus, ifLastChange
 * and ifSpecific are not counted, the interface itself holding what they report.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_STAT_IF_SPEED = 0, ///< ifSpeed, a Gauge
    IDEMIP_STAT_IF_IN_OCTETS,
    IDEMIP_STAT_IF_IN_UCAST_PKTS,
    IDEMIP_STAT_IF_IN_NUCAST_PKTS,
    IDEMIP_STAT_IF_IN_DISCARDS,
    IDEMIP_STAT_IF_IN_ERRORS,
    IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS,
    IDEMIP_STAT_IF_OUT_OCTETS,
    IDEMIP_STAT_IF_OUT_UCAST_PKTS,
    IDEMIP_STAT_IF_OUT_NUCAST_PKTS,
    IDEMIP_STAT_IF_OUT_DISCARDS,
    IDEMIP_STAT_IF_OUT_ERRORS,
    IDEMIP_STAT_IF_OUT_QLEN, ///< ifOutQLen, a Gauge
    IDEMIP_STAT_IF_COUNT,    ///< one past the last, so a bad id is one compare
} IdemIpStatsIfCounter;

/** @brief What a group counter access takes. */
typedef struct
{
    IdemIpStatsCounter id;
    uint32_t value; ///< what bump adds and what set assigns; unread by read
} StatsCtrArgs;

/** @brief What a per-interface counter access takes. */
typedef struct
{
    uint8_t netif; ///< the interface, below IDEMIP_NETIF_COUNT
    IdemIpStatsIfCounter id;
    uint32_t value; ///< what if_bump adds and what if_set assigns; unread by if_read
} StatsIfArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var StatsIo::ctr_args  the group counter a call names, and the value it carries
 * @var StatsIo::if_args   the interface and per-interface counter a call names, and its value
 * @var StatsIo::status    what the call reports: OK, BUSY, or ERR
 * @var StatsIo::value     what read and if_read report
 */
typedef struct
{
    StatsCtrArgs ctr_args;
    StatsIfArgs if_args;

    IdemIpStatus status;
    uint32_t value;
} StatsIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The counter block is IDEMIP_STAT_COUNT
// counters of four octets; the interface table sits at the end of the context region, whose width
// IDEMIP_STATS_CTX_BYTES fixes.

/**
 * @brief Octets one counter spans, as a shift.
 *
 * RFC 1155 sec 3.2.3.3 fixes a Counter's maximum at 2^32-1, and RFC 2578 sec 7.1.6 fixes Counter32's
 * at the same value.
 */
#define IDEMIP_STATS_CTR_SHIFT 2u

#define IDEMIP_STATS_OFF_IO 0u ///< the operand and result block
#define IDEMIP_STATS_OFF_CTR IDEMIP_ROUND_UP(IDEMIP_STATS_OFF_IO + sizeof(StatsIo), IDEMIP_ALIGN)
// The counter block is a count of four-octet counters, so it lands on IDEMIP_ALIGN only when that
// count is even. Rounded, because what follows it is a context an entry addresses as a struct.
#define IDEMIP_STATS_OFF_CTX                                                                                           \
    IDEMIP_ROUND_UP(IDEMIP_STATS_OFF_CTR + ((size_t)IDEMIP_STAT_COUNT << IDEMIP_STATS_CTR_SHIFT), IDEMIP_ALIGN)
#define IDEMIP_STATS_OFF_IF IDEMIP_STATS_CTX_BYTES ///< IDEMIP_NETIF_COUNT entries, 1 << IDEMIP_STATS_IF_ENTRY_SHIFT each

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_STATS_IO(w) ((StatsIo *)(void *)((w) + IDEMIP_STATS_OFF_IO))

/**
 * @brief The RFC 1213 counters.
 *
 *   Stats.clear(work);
 *   IDEMIP_STATS_IO(work)->ctr_args.id = IDEMIP_STAT_IP4_IN_RECEIVES;
 *   IDEMIP_STATS_IO(work)->ctr_args.value = 1u;
 *   Stats.bump(work);
 *   IDEMIP_STATS_IO(work)->ctr_args.id = IDEMIP_STAT_IP4_IN_RECEIVES;
 *   Stats.read(work);
 *   if (IDEMIP_STATS_IO(work)->status == IDEMIP_OK) { ... IDEMIP_STATS_IO(work)->value ... }
 *
 * @c work is IDEMIP_STATS_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the counter set, so
 * two sets are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata
 * and the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick.
 *
 * @var StatsNs::clear    zero every counter and mark the borrow bound. Every other entry refuses a
 *                        borrow this has not run on.
 * @var StatsNs::bump     add @ref StatsCtrArgs::value to a group Counter, wrapping at 2^32-1
 *                        (RFC 1155 sec 3.2.3.3)
 * @var StatsNs::set      assign @ref StatsCtrArgs::value to a group Gauge (RFC 1155 sec 3.2.3.4)
 * @var StatsNs::read     report a group counter in @ref StatsIo::value
 * @var StatsNs::if_bump  add @ref StatsIfArgs::value to one interface's Counter
 * @var StatsNs::if_set   assign @ref StatsIfArgs::value to one interface's Gauge
 * @var StatsNs::if_read  report one interface's counter in @ref StatsIo::value
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const bump)(uint8_t *restrict work);
    void (*const set)(uint8_t *restrict work);
    void (*const read)(uint8_t *restrict work);
    void (*const if_bump)(uint8_t *restrict work);
    void (*const if_set)(uint8_t *restrict work);
    void (*const if_read)(uint8_t *restrict work);
} StatsNs;

// What the table binds. Each takes the one borrow and nothing else: everything an entry reads is an
// operand in the block at IDEMIP_STATS_OFF_IO, or a region of the borrow at a fixed offset.
void idemip_stats_clear(uint8_t *restrict work);
void idemip_stats_bump(uint8_t *restrict work);
void idemip_stats_set(uint8_t *restrict work);
void idemip_stats_read(uint8_t *restrict work);
void idemip_stats_if_bump(uint8_t *restrict work);
void idemip_stats_if_set(uint8_t *restrict work);
void idemip_stats_if_read(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A `const`
 * object whose initializer every translation unit can see is a compile-time fact, so `Stats.bump(w)`
 * resolves to a named function and becomes a direct call, and the table itself is read by nothing at
 * run time and is not emitted. An `extern` table leaves the call indirect: the caller loads the
 * pointer and branches through it, because nothing at the call site says what it holds.
 */
static const StatsNs Stats IDEMIP_UNUSED = {.clear = idemip_stats_clear,
                                            .bump = idemip_stats_bump,
                                            .set = idemip_stats_set,
                                            .read = idemip_stats_read,
                                            .if_bump = idemip_stats_if_bump,
                                            .if_set = idemip_stats_if_set,
                                            .if_read = idemip_stats_if_read};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_STATS_H
