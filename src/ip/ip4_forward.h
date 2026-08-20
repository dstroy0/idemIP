// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_forward.h
 * @brief The RFC 1812 sec 5.2.1.2 forwarding decision: whether a datagram is forwarded, where it
 *        goes, and which ICMP the caller owes its source.
 *
 * sec 5.2.1.2 prints the steps this unit answers, in its own order: (6) "the forwarder verifies that
 * forwarding the packet is permitted", (7) "the forwarder decrements (by at least one) and checks the
 * packet's TTL, as described in Section [5.3.1]", and (9) "the forwarder performs any necessary IP
 * fragmentation". Steps (5), (10) and (11) are the caller's: the route, the link-layer address and
 * the frame. sec 5.2.1 (1) puts header validation ahead of everything, "before performing any actions
 * based on the contents of the header", so the sec 5.2.2 checks run here first.
 *
 * Nothing is written into the datagram and no message is built. The decremented Time to Live and the
 * ICMP type, code and pointer are reported, and the caller writes and sends them.
 *
 * The address rules are RFC 1812 sec 5.3.7 Martian Address Filtering over the special addresses of
 * sec 4.2.2.11 and sec 4.2.3.1, sec 5.3.4 for a frame that arrived as a link-layer broadcast, and
 * sec 5.3.5 for a broadcast destination. RFC 3927 sec 7's "A router MUST NOT forward a packet with an
 * IPv4 Link-Local source or destination address" runs ahead of the sec 5.3.7 switch, that sentence
 * ending "irrespective of the router's default route configuration". Which ICMP may be sent at all is
 * sec 4.3.2.7, whose list "TAKE[S] PRECEDENCE OVER ANY REQUIREMENT ELSEWHERE IN THIS DOCUMENT FOR
 * SENDING ICMP ERROR MESSAGES".
 *
 * sec 5.2.3's Local Delivery Decision is the caller's, not this unit's. Its multicast rule reads "The
 * packet's destination is an IP multicast address which is never forwarded (such as 224.0.0.1 or
 * 224.0.0.2) and (at least) one of the logical interfaces associated with the physical interface on
 * which the packet arrived is a member of the destination multicast group", and a group membership is
 * not among the operands a decision takes. A caller that hands a never-forwarded group to decide gets
 * an ordinary forwarding answer for it. src/core/dispatch.c makes that decision before raising
 * IDEMIP_DISPATCH_ACT_FORWARD, so no multicast destination reaches this unit through it.
 */

#ifndef IDEMIP_IP4_FORWARD_H
#define IDEMIP_IP4_FORWARD_H

#include "src/icmp/icmp.h" // the types, codes and pointer a decision names

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/**
 * @brief What the forwarder decided to do with the datagram.
 *
 * @var IDEMIP_IP4_FORWARD_DISCARD the datagram is not forwarded; @ref Ip4ForwardIo::reason names the
 *                                 rule, and @ref Ip4ForwardIo::icmp whether one is owed
 * @var IDEMIP_IP4_FORWARD_SEND    the datagram is forwarded to @ref Ip4ForwardIo::next_hop with
 *                                 @ref Ip4ForwardIo::ttl written into its Time to Live
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP4_FORWARD_DISCARD = 0,
    IDEMIP_IP4_FORWARD_SEND,
} IdemIpIp4ForwardAction;

/**
 * @brief Which rule decided, each in the RFC's own words.
 *
 * @var IDEMIP_IP4_FORWARD_R_OK          every check passed
 * @var IDEMIP_IP4_FORWARD_R_HEADER      sec 5.2.2: "If the packet fails any of the following tests,
 *                                       it MUST be silently discarded"
 * @var IDEMIP_IP4_FORWARD_R_LINK_BCAST  sec 5.3.4: "A router MUST NOT forward any packet that the
 *                                       router received as a Link Layer broadcast, unless it is
 *                                       directed to an IP Multicast address"
 * @var IDEMIP_IP4_FORWARD_R_SRC         sec 5.3.7: "A router SHOULD NOT forward any packet that has
 *                                       an invalid IP source address or a source address on network 0"
 * @var IDEMIP_IP4_FORWARD_R_DST         sec 5.3.7: "A router SHOULD NOT forward any packet that has
 *                                       an invalid IP destination address or a destination address on
 *                                       network 0"
 * @var IDEMIP_IP4_FORWARD_R_LIMITED     sec 5.3.5.1: "Limited broadcasts MUST NOT be forwarded"
 * @var IDEMIP_IP4_FORWARD_R_DIRECTED    sec 5.3.5.2's disable option, which
 *                                       @ref IDEMIP_IP4_FORWARD_P_DIRECTED lowered
 * @var IDEMIP_IP4_FORWARD_R_STRICT      sec 5.2.2: a destination that "is not one of the addresses of
 *                                       the router" carrying "a strict source route option"
 * @var IDEMIP_IP4_FORWARD_R_NO_ROUTE    sec 4.3.3.1: "it has no routes at all (including no default
 *                                       route) to the destination specified in the packet"
 * @var IDEMIP_IP4_FORWARD_R_TTL         sec 5.3.1: "If the TTL is reduced to zero (or less), the
 *                                       packet MUST be discarded"
 * @var IDEMIP_IP4_FORWARD_R_DF          the datagram exceeds the outgoing MTU with RFC 791 sec 3.1's
 *                                       Don't Fragment flag set
 * @var IDEMIP_IP4_FORWARD_R_NO_ROUTE_TOS sec 4.3.3.1: "the router does have routes to the destination
 *                                       network specified in the packet but the TOS specified for the
 *                                       routes is neither the default TOS (0000) nor the TOS of the
 *                                       packet"
 * @var IDEMIP_IP4_FORWARD_R_LINK_LOCAL  RFC 3927 sec 7: "A router MUST NOT forward a packet with an
 *                                       IPv4 Link-Local source or destination address, irrespective
 *                                       of the router's default route configuration or routes
 *                                       obtained from dynamic routing protocols"
 * @var IDEMIP_IP4_FORWARD_R_SRC_BCAST   RFC 1812 sec 4.2.2.11 (d), of { <Network-prefix>, -1 }: "It
 *                                       MUST NOT be used as a source address"
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP4_FORWARD_R_OK = 0,
    IDEMIP_IP4_FORWARD_R_HEADER,
    IDEMIP_IP4_FORWARD_R_LINK_BCAST,
    IDEMIP_IP4_FORWARD_R_SRC,
    IDEMIP_IP4_FORWARD_R_DST,
    IDEMIP_IP4_FORWARD_R_LIMITED,
    IDEMIP_IP4_FORWARD_R_DIRECTED,
    IDEMIP_IP4_FORWARD_R_STRICT,
    IDEMIP_IP4_FORWARD_R_NO_ROUTE,
    IDEMIP_IP4_FORWARD_R_TTL,
    IDEMIP_IP4_FORWARD_R_DF,
    IDEMIP_IP4_FORWARD_R_NO_ROUTE_TOS,
    IDEMIP_IP4_FORWARD_R_LINK_LOCAL,
    IDEMIP_IP4_FORWARD_R_SRC_BCAST,
} IdemIpIp4ForwardReason;

/**
 * @brief The switches RFC 1812 requires, one bit each. clear raises both.
 *
 * sec 5.3.7 of the address checks: "A router MAY have a switch that allows the network manager to
 * disable these checks. If such a switch is provided, it MUST default to performing the checks."
 * sec 5.3.5.2 of the directed broadcast: "A router ... MUST have an option to disable forwarding
 * network-prefix-directed broadcasts. These options MUST default to permit receiving and forwarding
 * network-prefix-directed broadcasts."
 *
 * @var IDEMIP_IP4_FORWARD_P_MARTIAN  the sec 5.3.7 source and destination checks run
 * @var IDEMIP_IP4_FORWARD_P_DIRECTED a network-prefix-directed broadcast is forwarded
 */
#define IDEMIP_IP4_FORWARD_P_MARTIAN (1u << 0)
#define IDEMIP_IP4_FORWARD_P_DIRECTED (1u << 1)

/** @brief Every switch a caller may set, so a reserved bit is refused rather than stored. */
#define IDEMIP_IP4_FORWARD_P_MASK ((uint8_t)(IDEMIP_IP4_FORWARD_P_MARTIAN | IDEMIP_IP4_FORWARD_P_DIRECTED))

/** @brief No ICMP is owed. @ref Ip4ForwardIo::icmp_type reads this whenever @c icmp is false. */
#define IDEMIP_IP4_FORWARD_ICMP_NONE 0xFFu

/**
 * @brief What decide takes.
 *
 * Steps (1) through (5) of sec 5.2.1.2 are the caller's, so their results arrive here: the datagram
 * the link layer delivered, how it was addressed at the link layer (sec 5.3.4), and what the routing
 * table answered (sec 5.2.4).
 *
 * @var Ip4ForwardArgs::hdr          the datagram, at its RFC 791 sec 3.1 header
 * @var Ip4ForwardArgs::len          octets readable at @ref Ip4ForwardArgs::hdr, "the packet length
 *                                   reported by the Link Layer" of sec 5.2.2 test (1)
 * @var Ip4ForwardArgs::next_hop     what Ip4Route.lookup put in Ip4RouteIo::next_hop, host order
 * @var Ip4ForwardArgs::in_addr      the receiving interface's own address, host order, RFC 1122
 *                                   sec 3.3.1.1 (a)
 * @var Ip4ForwardArgs::in_mask      its address mask, which sec 5.2.7.2 compares the source and the
 *                                   next hop under
 * @var Ip4ForwardArgs::out_addr     the outgoing interface's own address, host order
 * @var Ip4ForwardArgs::out_mask     its address mask, which the sec 5.3.5.2 directed broadcast
 *                                   { <Network-prefix>, -1 } is formed from
 * @var Ip4ForwardArgs::out_mtu      octets the outgoing link carries in one frame
 * @var Ip4ForwardArgs::in_netif     the interface the datagram arrived on
 * @var Ip4ForwardArgs::out_netif    the interface the route chose
 * @var Ip4ForwardArgs::routed       the lookup found a row, so @ref Ip4ForwardArgs::next_hop holds one
 * @var Ip4ForwardArgs::direct       the route transmits directly, RFC 1122 sec 3.3.1.1 (b)
 * @var Ip4ForwardArgs::tos_blocked  the lookup found rows for the destination but none whose
 *                                   route.tos is the packet's or the default, which RFC 1812 sec
 *                                   4.3.3.1 answers with Destination Unreachable Code 11 or 12
 *                                   rather than Code 0. @ref Ip4RouteIo::tos_blocked reports it.
 * @var Ip4ForwardArgs::ll_broadcast the frame arrived addressed to the link-layer broadcast address
 * @var Ip4ForwardArgs::ll_multicast the frame arrived addressed to a link-layer multicast address
 */
typedef struct
{
    const uint8_t *hdr;
    size_t len;
    uint32_t next_hop;
    uint32_t in_addr;
    uint32_t in_mask;
    uint32_t out_addr;
    uint32_t out_mask;
    uint16_t out_mtu;
    uint8_t in_netif;
    uint8_t out_netif;
    idemip_bool routed;
    idemip_bool direct;
    idemip_bool tos_blocked;
    idemip_bool ll_broadcast;
    idemip_bool ll_multicast;
} Ip4ForwardArgs;

/**
 * @brief What set_policy takes: the switches raised, then the switches lowered.
 *
 * @var Ip4ForwardPolicyArgs::set   IDEMIP_IP4_FORWARD_P_* raised
 * @var Ip4ForwardPolicyArgs::clear IDEMIP_IP4_FORWARD_P_* lowered, applied after
 *                                  @ref Ip4ForwardPolicyArgs::set
 */
typedef struct
{
    uint8_t set;
    uint8_t clear;
} Ip4ForwardPolicyArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Ip4ForwardIo::fwd_args    the datagram, the link-layer addressing and the route
 * @var Ip4ForwardIo::policy_args the switches set_policy raises and lowers
 * @var Ip4ForwardIo::status      what the call reports: OK, BUSY, or ERR
 * @var Ip4ForwardIo::next_hop    where the frame goes, host order: the sec 5.2.1.2 step (5) next hop
 * @var Ip4ForwardIo::redirect_gw the better first-hop router a sec 5.2.7.2 Redirect names, host order
 * @var Ip4ForwardIo::mtu         the next-hop MTU an RFC 1191 sec 4 Destination Unreachable code 4
 *                                carries in its unused half-word
 * @var Ip4ForwardIo::action      forward the datagram, or discard it
 * @var Ip4ForwardIo::reason      which rule decided
 * @var Ip4ForwardIo::ttl         the sec 5.3.1 Time to Live the caller writes into the header
 * @var Ip4ForwardIo::netif       the interface the frame leaves through
 * @var Ip4ForwardIo::icmp_type   the RFC 792 Type the caller must send, or
 *                                IDEMIP_IP4_FORWARD_ICMP_NONE
 * @var Ip4ForwardIo::icmp_code   its Code
 * @var Ip4ForwardIo::icmp_ptr    the Pointer a Parameter Problem carries, octets into the header
 * @var Ip4ForwardIo::policy      the switches now raised
 * @var Ip4ForwardIo::icmp        an ICMP error is owed and sec 4.3.2.7 permits it
 * @var Ip4ForwardIo::fragment    the datagram exceeds the outgoing MTU with Don't Fragment clear, so
 *                                sec 5.2.1.2 step (9) fragmentation runs before the frame is built
 * @var Ip4ForwardIo::redirect    a sec 5.2.7.2 Code 1 Redirect for Host is owed alongside the forward
 */
typedef struct
{
    Ip4ForwardArgs fwd_args;
    Ip4ForwardPolicyArgs policy_args;

    uint32_t next_hop;
    uint32_t redirect_gw;
    uint16_t mtu;
    IdemIpStatus status;
    IdemIpIp4ForwardAction action;
    IdemIpIp4ForwardReason reason;
    uint8_t ttl;
    uint8_t netif;
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint8_t icmp_ptr;
    uint8_t policy;
    idemip_bool icmp;
    idemip_bool fragment;
    idemip_bool redirect;
} Ip4ForwardIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. This unit holds no table: the decision is a
// function of one datagram, so the whole borrow is the operand block and the switches.

#define IDEMIP_IP4_FORWARD_OFF_IO 0u ///< the operand and result block
#define IDEMIP_IP4_FORWARD_OFF_CTX                                                                                     \
    IDEMIP_ROUND_UP(IDEMIP_IP4_FORWARD_OFF_IO + sizeof(Ip4ForwardIo), IDEMIP_ALIGN) ///< the switches

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IP4_FORWARD_IO(w) ((Ip4ForwardIo *)(void *)((w) + IDEMIP_IP4_FORWARD_OFF_IO))

/**
 * @brief The forwarding decision.
 *
 *   Ip4Forward.clear(work);
 *   IDEMIP_IP4_FORWARD_IO(work)->fwd_args.hdr = datagram;
 *   IDEMIP_IP4_FORWARD_IO(work)->fwd_args.len = len;
 *   IDEMIP_IP4_FORWARD_IO(work)->fwd_args.routed = IDEMIP_TRUE;
 *   IDEMIP_IP4_FORWARD_IO(work)->fwd_args.next_hop = gw;
 *   IDEMIP_IP4_FORWARD_IO(work)->fwd_args.out_mtu = 1500u;
 *   Ip4Forward.decide(work);
 *   if (IDEMIP_IP4_FORWARD_IO(work)->action == IDEMIP_IP4_FORWARD_SEND) { ... }
 *
 * @c work is IDEMIP_IP4_FORWARD_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the forwarder, so two
 * forwarders are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks, and nothing here reports IDEMIP_BUSY. A decision is a function of the operands
 * it was handed, so a call that could not answer them can never answer them on a later tick, and
 * reporting BUSY would spin the caller on a datagram the RFC already decided. A datagram the RFC
 * discards is a decision that succeeded: the status is OK and the action is
 * IDEMIP_IP4_FORWARD_DISCARD. ERR is the borrow itself: never cleared, no datagram, a reserved switch
 * bit, or an outgoing MTU below the RFC 791 sec 3.2 minimum a router must be able to forward.
 *
 * @var Ip4ForwardNs::clear      zero the switches, raise the two the RFC defaults on, and mark the
 *                               borrow usable. The operand block is the caller's and is left alone.
 * @var Ip4ForwardNs::set_policy raise @ref Ip4ForwardPolicyArgs::set, then lower
 *                               @ref Ip4ForwardPolicyArgs::clear. A bit outside
 *                               IDEMIP_IP4_FORWARD_P_MASK is ERR.
 * @var Ip4ForwardNs::decide     the sec 5.2.1.2 steps (6), (7), (9) and (12) over one datagram
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const set_policy)(uint8_t *restrict work);
    void (*const decide)(uint8_t *restrict work);
} Ip4ForwardNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_ip4_forward_clear(uint8_t *restrict work);
void idemip_ip4_forward_set_policy(uint8_t *restrict work);
void idemip_ip4_forward_decide(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Ip4Forward.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Ip4ForwardNs Ip4Forward IDEMIP_UNUSED = {
    .clear = idemip_ip4_forward_clear,
    .set_policy = idemip_ip4_forward_set_policy,
    .decide = idemip_ip4_forward_decide};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_IP4_FORWARD_H
