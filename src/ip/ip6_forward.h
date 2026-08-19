// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip6_forward.h
 * @brief The IPv6 forwarding decision: whether a packet is forwarded, where it goes, and which
 *        ICMPv6 the caller owes its source.
 *
 * RFC 8200 sec 3 of the Hop Limit field: "Decremented by 1 by each node that forwards the packet.
 * When forwarding, the packet is discarded if Hop Limit was zero when received or is decremented to
 * zero." RFC 4443 sec 3.3 completes it: "If a router receives a packet with a Hop Limit of zero, or
 * if a router decrements a packet's Hop Limit to zero, it MUST discard the packet and originate an
 * ICMPv6 Time Exceeded message with Code 0 to the source of the packet."
 *
 * A router never fragments. RFC 8200 sec 4.5: "unlike IPv4, fragmentation in IPv6 is performed only
 * by source nodes, not by routers along a packet's delivery path", and sec 5 puts the rule with the
 * 1280-octet minimum link MTU. An oversized packet is therefore discarded, and RFC 4443 sec 3.2: "A
 * Packet Too Big MUST be sent by a router in response to a packet that it cannot forward because the
 * packet is larger than the MTU of the outgoing link."
 *
 * The address rules are RFC 4291: sec 2.5.2 "An IPv6 packet with a source address of unspecified must
 * never be forwarded by an IPv6 router", sec 2.5.3 of the loopback address "must never be forwarded
 * by an IPv6 router", sec 2.5.6 "Routers must not forward any packets with Link-Local source or
 * destination addresses to other links", and sec 2.7 "Multicast addresses must not be used as source
 * addresses" with "Routers must not forward any multicast packets beyond of the scope indicated by
 * the scop field".
 *
 * Which ICMPv6 may be sent at all is RFC 4443 sec 2.4 (e), whose note reads "THE RESTRICTIONS UNDER
 * (e) AND (f) ABOVE TAKE PRECEDENCE OVER ANY REQUIREMENT ELSEWHERE IN THIS DOCUMENT FOR ORIGINATING
 * ICMP ERROR MESSAGES".
 *
 * Nothing is written into the packet and no message is built. The decremented Hop Limit and the
 * ICMPv6 type and code are reported, and the caller writes and sends them.
 */

#ifndef IDEMIP_IP6_FORWARD_H
#define IDEMIP_IP6_FORWARD_H

#include "src/icmp/icmpv6.h" // the types and codes a decision names

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/**
 * @brief What the forwarder decided to do with the packet.
 *
 * @var IDEMIP_IP6_FORWARD_DISCARD the packet is not forwarded; @ref Ip6ForwardIo::reason names the
 *                                 rule, and @ref Ip6ForwardIo::icmp whether one is owed
 * @var IDEMIP_IP6_FORWARD_SEND    the packet is forwarded to @ref Ip6ForwardIo::next_hop with
 *                                 @ref Ip6ForwardIo::hop_limit written into its Hop Limit
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP6_FORWARD_DISCARD = 0,
    IDEMIP_IP6_FORWARD_SEND,
} IdemIpIp6ForwardAction;

/**
 * @brief Which rule decided, each in the RFC's own words.
 *
 * @var IDEMIP_IP6_FORWARD_R_OK        every check passed
 * @var IDEMIP_IP6_FORWARD_R_HEADER    RFC 8200 sec 3: the Version is not 6, or the Payload Length
 *                                     names octets the span does not hold
 * @var IDEMIP_IP6_FORWARD_R_SRC_UNSPEC RFC 4291 sec 2.5.2: "An IPv6 packet with a source address of
 *                                     unspecified must never be forwarded by an IPv6 router"
 * @var IDEMIP_IP6_FORWARD_R_SRC_MCAST RFC 4291 sec 2.7: "Multicast addresses must not be used as
 *                                     source addresses in IPv6 packets"
 * @var IDEMIP_IP6_FORWARD_R_SRC_LOOP  RFC 4291 sec 2.5.3: "The loopback address must not be used as
 *                                     the source address in IPv6 packets that are sent outside of a
 *                                     single node"
 * @var IDEMIP_IP6_FORWARD_R_DST_UNSPEC RFC 4291 sec 2.5.2: "The unspecified address must not be used
 *                                     as the destination address of IPv6 packets"
 * @var IDEMIP_IP6_FORWARD_R_DST_LOOP  RFC 4291 sec 2.5.3: a packet with a destination of loopback
 *                                     "must never be forwarded by an IPv6 router"
 * @var IDEMIP_IP6_FORWARD_R_LINK_LOCAL RFC 4291 sec 2.5.6: "Routers must not forward any packets with
 *                                     Link-Local source or destination addresses to other links"
 * @var IDEMIP_IP6_FORWARD_R_SCOPE     RFC 4291 sec 2.7: "Routers must not forward any multicast
 *                                     packets beyond of the scope indicated by the scop field", and
 *                                     a scop of 0 "must be silently dropped"
 * @var IDEMIP_IP6_FORWARD_R_NO_ROUTE  RFC 4443 sec 3.1 Code 0, "No route to destination"
 * @var IDEMIP_IP6_FORWARD_R_HOP_LIMIT RFC 8200 sec 3: "the packet is discarded if Hop Limit was zero
 *                                     when received or is decremented to zero"
 * @var IDEMIP_IP6_FORWARD_R_TOO_BIG   RFC 8200 sec 4.5: a router does not fragment, so a packet
 *                                     larger than the outgoing link's MTU is discarded
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP6_FORWARD_R_OK = 0,
    IDEMIP_IP6_FORWARD_R_HEADER,
    IDEMIP_IP6_FORWARD_R_SRC_UNSPEC,
    IDEMIP_IP6_FORWARD_R_SRC_MCAST,
    IDEMIP_IP6_FORWARD_R_SRC_LOOP,
    IDEMIP_IP6_FORWARD_R_DST_UNSPEC,
    IDEMIP_IP6_FORWARD_R_DST_LOOP,
    IDEMIP_IP6_FORWARD_R_LINK_LOCAL,
    IDEMIP_IP6_FORWARD_R_SCOPE,
    IDEMIP_IP6_FORWARD_R_NO_ROUTE,
    IDEMIP_IP6_FORWARD_R_HOP_LIMIT,
    IDEMIP_IP6_FORWARD_R_TOO_BIG,
} IdemIpIp6ForwardReason;

/** @brief No ICMPv6 is owed. @ref Ip6ForwardIo::icmp_type reads this whenever @c icmp is false. */
#define IDEMIP_IP6_FORWARD_ICMP_NONE 0u

/**
 * @brief What decide takes.
 *
 * The local delivery decision and the route are the caller's, so their results arrive here: the
 * packet the link layer delivered, how it was addressed at the link layer (RFC 4443 sec 2.4 (e.4)
 * and (e.5)), and what the destination cache or routing table answered.
 *
 * @var Ip6ForwardArgs::hdr          the packet, at its RFC 8200 sec 3 header
 * @var Ip6ForwardArgs::len          octets readable at @ref Ip6ForwardArgs::hdr
 * @var Ip6ForwardArgs::next_hop     IDEMIP_IP6_ADDR_LEN octets, the next-hop address the route chose;
 *                                   the destination itself when the destination is on-link
 * @var Ip6ForwardArgs::out_mtu      octets the outgoing link carries in one packet, which RFC 8200
 *                                   sec 5 puts at 1280 or greater
 * @var Ip6ForwardArgs::in_netif     the interface the packet arrived on
 * @var Ip6ForwardArgs::out_netif    the interface the route chose
 * @var Ip6ForwardArgs::routed       the route was found, so @ref Ip6ForwardArgs::next_hop holds one
 * @var Ip6ForwardArgs::ll_multicast the frame arrived addressed to a link-layer multicast address
 * @var Ip6ForwardArgs::ll_broadcast the frame arrived addressed to the link-layer broadcast address
 * @var Ip6ForwardArgs::src_neighbor RFC 4861 sec 8.2: "the Source Address field of the packet
 *                                   identifies a neighbor", which the neighbor cache answered
 */
typedef struct
{
    const uint8_t *hdr;
    size_t len;
    const uint8_t *next_hop;
    uint16_t out_mtu;
    uint8_t in_netif;
    uint8_t out_netif;
    idemip_bool routed;
    idemip_bool ll_multicast;
    idemip_bool ll_broadcast;
    idemip_bool src_neighbor;
} Ip6ForwardArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns. The two address results point into the
 * operands this call was handed and are read while those still stand.
 *
 * @var Ip6ForwardIo::fwd_args        the packet, the link-layer addressing and the route
 * @var Ip6ForwardIo::status          what the call reports: OK, BUSY, or ERR
 * @var Ip6ForwardIo::next_hop        where the frame goes, IDEMIP_IP6_ADDR_LEN octets
 * @var Ip6ForwardIo::redirect_target the RFC 4861 sec 4.5 Target Address a Redirect names
 * @var Ip6ForwardIo::mtu             the RFC 4443 sec 3.2 MTU field, "The Maximum Transmission Unit
 *                                    of the next-hop link"
 * @var Ip6ForwardIo::action          forward the packet, or discard it
 * @var Ip6ForwardIo::reason          which rule decided
 * @var Ip6ForwardIo::hop_limit       the RFC 8200 sec 3 Hop Limit the caller writes into the header
 * @var Ip6ForwardIo::netif           the interface the frame leaves through
 * @var Ip6ForwardIo::icmp_type       the RFC 4443 Type the caller must send, or
 *                                    IDEMIP_IP6_FORWARD_ICMP_NONE
 * @var Ip6ForwardIo::icmp_code       its Code
 * @var Ip6ForwardIo::icmp            an ICMPv6 error is owed and RFC 4443 sec 2.4 (e) permits it
 * @var Ip6ForwardIo::redirect        an RFC 4861 sec 8.2 Redirect is owed alongside the forward
 */
typedef struct
{
    Ip6ForwardArgs fwd_args;

    const uint8_t *next_hop;
    const uint8_t *redirect_target;
    uint32_t mtu;
    IdemIpStatus status;
    IdemIpIp6ForwardAction action;
    IdemIpIp6ForwardReason reason;
    uint8_t hop_limit;
    uint8_t netif;
    uint8_t icmp_type;
    uint8_t icmp_code;
    idemip_bool icmp;
    idemip_bool redirect;
} Ip6ForwardIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. This unit holds no table: the decision is a
// function of one packet, so the whole borrow is the operand block and the mark clear leaves.

#define IDEMIP_IP6_FORWARD_OFF_IO 0u ///< the operand and result block
#define IDEMIP_IP6_FORWARD_OFF_CTX                                                                                     \
    IDEMIP_ROUND_UP(IDEMIP_IP6_FORWARD_OFF_IO + sizeof(Ip6ForwardIo), IDEMIP_ALIGN) ///< the mark

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IP6_FORWARD_IO(w) ((Ip6ForwardIo *)(void *)((w) + IDEMIP_IP6_FORWARD_OFF_IO))

/**
 * @brief The IPv6 forwarding decision.
 *
 *   Ip6Forward.clear(work);
 *   IDEMIP_IP6_FORWARD_IO(work)->fwd_args.hdr = packet;
 *   IDEMIP_IP6_FORWARD_IO(work)->fwd_args.len = len;
 *   IDEMIP_IP6_FORWARD_IO(work)->fwd_args.routed = IDEMIP_TRUE;
 *   IDEMIP_IP6_FORWARD_IO(work)->fwd_args.next_hop = router;
 *   IDEMIP_IP6_FORWARD_IO(work)->fwd_args.out_mtu = 1500u;
 *   Ip6Forward.decide(work);
 *   if (IDEMIP_IP6_FORWARD_IO(work)->action == IDEMIP_IP6_FORWARD_SEND) { ... }
 *
 * @c work is IDEMIP_IP6_FORWARD_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the forwarder, so two
 * forwarders are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks, and nothing here reports IDEMIP_BUSY. A decision is a function of the operands
 * it was handed, so a call that could not answer them can never answer them on a later tick, and
 * reporting BUSY would spin the caller on a packet the RFC already decided. A packet the RFC discards
 * is a decision that succeeded: the status is OK and the action is IDEMIP_IP6_FORWARD_DISCARD. ERR is
 * the borrow itself: never cleared, no packet, a routed call with no next hop, or an outgoing MTU
 * below the 1280 octets RFC 8200 sec 5 requires of every link.
 *
 * @var Ip6ForwardNs::clear  zero the context and mark the borrow usable. The operand block is the
 *                           caller's and is left alone.
 * @var Ip6ForwardNs::decide the RFC 8200 sec 3 Hop Limit, the RFC 4291 address rules, the sec 4.5
 *                           no-fragmentation rule and the RFC 4861 sec 8.2 Redirect over one packet
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const decide)(uint8_t *restrict work);
} Ip6ForwardNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const Ip6ForwardNs Ip6Forward;

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_IP6_FORWARD_H
