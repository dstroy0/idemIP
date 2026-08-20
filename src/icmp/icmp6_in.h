// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmp6_in.h
 * @brief One arriving RFC 4443 message, and the sec 2.4 rules on originating an error.
 *
 * Two entries carry the work. @ref Icmp6InNs::recv reads one message that arrived in an IPv6 packet,
 * walking the RFC 8200 sec 4 chain to it, reports what the caller does with it, and builds the sec
 * 4.2 Echo Reply when the message is an Echo Request. @ref Icmp6InNs::error builds one of the four
 * sec 3 error messages about a packet, after the six MUST NOT rules of sec 2.4 (e) and the rate limit
 * of sec 2.4 (f).
 *
 * Nothing here sends. A call writes into the buffer the operand block names and reports its length,
 * the Source Address the IPv6 header carries and the Destination it goes to.
 *
 * A fragmented packet reaches this after reassembly: only the first fragment carries the message
 * head, so a chain ending at a Fragment header with a non-zero Fragment Offset carries nothing this
 * reads.
 *
 * The field offsets, the codes and the build helpers are icmpv6.h's; nothing here restates one.
 */

#ifndef IDEMIP_ICMP6_IN_H
#define IDEMIP_ICMP6_IN_H

#include "src/icmp/icmpv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/**
 * @brief The Redirect type of RFC 4861 sec 4.5, which RFC 4443 sec 2.4 (e.2) names.
 *
 * "Type 137". The Neighbor Discovery message formats are that document's; this is the one type
 * number sec 2.4 (e) needs and nothing here parses the message.
 */
#define IDEMIP_ICMP6_IN_ND_REDIRECT 137u

// ---------------------------------------------------------------------------
// What a received message asks the caller to do
// ---------------------------------------------------------------------------
// One bit per action RFC 4443 sec 2.4 names. A caller acts on the set and nothing else: the entries
// here send no packet and signal no user.

/** @brief Send the @ref Icmp6InIo::out_len octets built at @ref Icmp6InRecvArgs::out. */
#define IDEMIP_ICMP6_IN_ACT_REPLY (1u << 0)

/**
 * @brief Pass the error to the upper-layer process @ref Icmp6InIo::proto names.
 *
 * RFC 4443 sec 2.4 (d): "the upper-layer protocol type is extracted from the original packet
 * (contained in the body of the ICMPv6 error message) and used to select the appropriate upper-layer
 * process to handle the error." sec 2.4 (a) sends an error message of unknown type the same way.
 */
#define IDEMIP_ICMP6_IN_ACT_TRANSPORT (1u << 1)

/**
 * @brief Pass the message to a process receiving ICMP messages.
 *
 * RFC 4443 sec 4.2: "Echo Reply messages MUST be passed to the process that originated an Echo
 * Request message."
 */
#define IDEMIP_ICMP6_IN_ACT_USER (1u << 2)

/**
 * @brief Silently discard the message.
 *
 * RFC 4443 sec 2.4 (b): "If an ICMPv6 informational message of unknown type is received, it MUST be
 * silently discarded." Also set for a message whose checksum does not hold, for one shorter than its
 * type requires, and for an error message sec 2.4 (d) cannot retrieve an upper-layer protocol type
 * from, which "is silently dropped after any IPv6-layer processing".
 */
#define IDEMIP_ICMP6_IN_ACT_DISCARD (1u << 3)

// ---------------------------------------------------------------------------
// Which sec 2.4 rule refused an error message
// ---------------------------------------------------------------------------
// RFC 4443 sec 2.4 (e): "An ICMPv6 error message MUST NOT be originated as a result of receiving the
// following". Reported in @ref Icmp6InIo::suppress for diagnostics; no control flow branches on it.

#define IDEMIP_ICMP6_IN_SUPPRESS_NONE 0u       ///< no rule refused it
#define IDEMIP_ICMP6_IN_SUPPRESS_ERROR 1u      ///< (e.1) "An ICMPv6 error message."
#define IDEMIP_ICMP6_IN_SUPPRESS_REDIRECT 2u   ///< (e.2) "An ICMPv6 redirect message"
#define IDEMIP_ICMP6_IN_SUPPRESS_DST_MCAST 3u  ///< (e.3) "A packet destined to an IPv6 multicast address."
#define IDEMIP_ICMP6_IN_SUPPRESS_LINK_MCAST 4u ///< (e.4) "A packet sent as a link-layer multicast"
#define IDEMIP_ICMP6_IN_SUPPRESS_LINK_BCAST 5u ///< (e.5) "A packet sent as a link-layer broadcast"
#define IDEMIP_ICMP6_IN_SUPPRESS_SRC 6u        ///< (e.6) a source that names no single node

/**
 * @brief (f) The token bucket was empty, so the message was not originated now.
 *
 * "an IPv6 node MUST limit the rate of ICMPv6 error messages it originates." The only reason a later
 * call about the same packet can succeed, and the only one reported with IDEMIP_BUSY.
 */
#define IDEMIP_ICMP6_IN_SUPPRESS_RATE 7u

/**
 * @brief What a received message takes.
 *
 * @var Icmp6InRecvArgs::packet   the RFC 8200 sec 3 IPv6 header, the sec 4 chain and the message
 *                                behind it
 * @var Icmp6InRecvArgs::len      readable octets at @p packet
 * @var Icmp6InRecvArgs::out      where an Echo Reply is built, @p out_cap octets, not overlapping
 *                                @p packet
 * @var Icmp6InRecvArgs::out_cap  octets available at @p out
 * @var Icmp6InRecvArgs::if_addr  a unicast address of the interface it arrived on,
 *                                IDEMIP_IP6_ADDR_LEN octets, which RFC 4443 sec 4.2 makes the reply's
 *                                Source Address when the request was not unicast
 * @var Icmp6InRecvArgs::dst_anycast the Destination Address is an anycast address this node
 *                                implements, which sec 2.2 (b) groups with a multicast destination
 */
typedef struct
{
    const uint8_t *packet;
    size_t len;
    uint8_t *out;
    size_t out_cap;
    const uint8_t *if_addr;
    idemip_bool dst_anycast;
} Icmp6InRecvArgs;

/**
 * @brief What originating an error message takes.
 *
 * @var Icmp6InErrArgs::invoking the IPv6 header of "the packet that caused the error", its chain and
 *                               data behind it
 * @var Icmp6InErrArgs::len      readable octets at @p invoking
 * @var Icmp6InErrArgs::out      where the message is built, @p out_cap octets, not overlapping
 *                               @p invoking
 * @var Icmp6InErrArgs::out_cap  octets available at @p out
 * @var Icmp6InErrArgs::if_addr  a unicast address of the interface, IDEMIP_IP6_ADDR_LEN octets, which
 *                               sec 2.2 (b) makes the Source Address for every destination case but
 *                               one: "a multicast group address, an anycast address implemented by
 *                               the node, or a unicast address that does not belong to the node"
 * @var Icmp6InErrArgs::dst_local_unicast the invoking packet's Destination Address is a unicast
 *                               address belonging to this node, which is sec 2.2 (a)'s one case:
 *                               "the Source Address of the reply MUST be that same address". An
 *                               anycast address the node implements is not one of these - sec 2.2 (b)
 *                               lists it - and neither is an address the node only forwards toward.
 * @var Icmp6InErrArgs::word     the 32 bits at IDEMIP_ICMP6_OFF_BODY: Unused for sec 3.1 and sec 3.3,
 *                               MTU for sec 3.2, Pointer for sec 3.4
 * @var Icmp6InErrArgs::now_ms   the caller's monotonic millisecond count, which the sec 2.4 (f) token
 *                               bucket refills on
 * @var Icmp6InErrArgs::type     one of the four sec 3 error types
 * @var Icmp6InErrArgs::code     that type's code
 * @var Icmp6InErrArgs::link_mcast the packet arrived as a link-layer multicast, sec 2.4 (e.4)
 * @var Icmp6InErrArgs::link_bcast the packet arrived as a link-layer broadcast, sec 2.4 (e.5)
 * @var Icmp6InErrArgs::src_anycast its Source Address is "an address known by the ICMP message
 *                               originator to be an IPv6 anycast address", sec 2.4 (e.6)
 */
typedef struct
{
    const uint8_t *invoking;
    size_t len;
    uint8_t *out;
    size_t out_cap;
    const uint8_t *if_addr;
    uint32_t word;
    uint32_t now_ms;
    uint8_t type;
    uint8_t code;
    idemip_bool link_mcast;
    idemip_bool link_bcast;
    idemip_bool src_anycast;
    idemip_bool dst_local_unicast;
} Icmp6InErrArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns. Two workers on two borrows share no byte
 * of this.
 *
 * @var Icmp6InIo::recv_args the arriving message
 * @var Icmp6InIo::err_args  the packet an error is originated about
 * @var Icmp6InIo::status    what the call reports: OK, BUSY, or ERR
 * @var Icmp6InIo::src       the Source Address the reply's IPv6 header carries, IDEMIP_IP6_ADDR_LEN
 *                           octets where they lie
 * @var Icmp6InIo::dst       where it goes, "Copied from the Source Address field of the invoking
 *                           packet", the same width
 * @var Icmp6InIo::out_len   octets the built message occupies at the operand block's @c out
 * @var Icmp6InIo::msg_off   octets from the IPv6 header to the message the chain walk found
 * @var Icmp6InIo::msg_len   octets of that message
 * @var Icmp6InIo::mtu       the sec 3.2 MTU a Packet Too Big carried
 * @var Icmp6InIo::pointer   the sec 3.4 Pointer a Parameter Problem carried
 * @var Icmp6InIo::id        the sec 4.1 Identifier
 * @var Icmp6InIo::seq       the sec 4.1 Sequence Number
 * @var Icmp6InIo::act       the actions above, ORed
 * @var Icmp6InIo::type      the arriving Type
 * @var Icmp6InIo::code      the arriving Code
 * @var Icmp6InIo::proto     the upper-layer protocol sec 2.4 (d) extracted from the invoking packet
 * @var Icmp6InIo::suppress  which sec 2.4 rule refused an error message
 * @var Icmp6InIo::tokens    sec 2.4 (f) error messages the bucket still allows in a burst
 * @var Icmp6InIo::cksum_ok  the sec 2.3 checksum over the message and the RFC 8200 sec 8.1
 *                           pseudo-header held
 * @var Icmp6InIo::bad_len   the message stopped before the field its own type reaches. RFC 2466
 *                           ipv6IfIcmpInErrors counts messages "determined as having ICMP-specific
 *                           errors (bad ICMP checksums, bad length, etc.)", so this and @ref
 *                           Icmp6InIo::cksum_ok are the two that name one. A discard with neither
 *                           set is sec 2.4 (b)'s unknown informational type and is no error.
 * @var Icmp6InIo::truncated the error message's quoted packet does not reach its upper-layer header,
 *                           which sec 2.4 (d) names as ordinary: "the ICMPv6 message is silently
 *                           dropped after any IPv6-layer processing. One example of such a case is an
 *                           ICMPv6 message with an unusually large amount of extension headers that
 *                           does not have the upper-layer protocol type due to truncation of the
 *                           original packet to meet the minimum IPv6 MTU limit." Reported with
 *                           @ref IDEMIP_ICMP6_IN_ACT_DISCARD and without @ref Icmp6InIo::bad_len,
 *                           because sec 2.4 (c)'s quote is "as much of invoking packet as possible"
 *                           and a short one is no error of the message.
 */
typedef struct
{
    Icmp6InRecvArgs recv_args;
    Icmp6InErrArgs err_args;

    const uint8_t *src;
    const uint8_t *dst;
    size_t out_len;
    size_t msg_off;
    size_t msg_len;
    uint32_t mtu;
    uint32_t pointer;
    uint16_t id;
    uint16_t seq;
    IdemIpStatus status;
    uint8_t act;
    uint8_t type;
    uint8_t code;
    uint8_t proto;
    uint8_t suppress;
    uint8_t tokens;
    idemip_bool cksum_ok;
    idemip_bool bad_len;
    idemip_bool truncated;
} Icmp6InIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only
// the map is public.

#define IDEMIP_ICMP6_IN_OFF_IO 0u ///< the operand and result block
#define IDEMIP_ICMP6_IN_OFF_CTX (IDEMIP_ICMP6_IN_OFF_IO + sizeof(Icmp6InIo)) ///< the running context

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_ICMP6_IN_IO(w) ((Icmp6InIo *)(void *)((w) + IDEMIP_ICMP6_IN_OFF_IO))

/**
 * @brief The RFC 4443 message path: answer an Echo Request, and originate the sec 3 errors.
 *
 *   Icmp6In.clear(work);
 *   IDEMIP_ICMP6_IN_IO(work)->recv_args.packet = frame + IDEMIP_ETH_HDR_LEN;
 *   IDEMIP_ICMP6_IN_IO(work)->recv_args.len = len;
 *   IDEMIP_ICMP6_IN_IO(work)->recv_args.out = tx;
 *   IDEMIP_ICMP6_IN_IO(work)->recv_args.out_cap = cap;
 *   Icmp6In.recv(work);
 *   if (IDEMIP_ICMP6_IN_IO(work)->act & IDEMIP_ICMP6_IN_ACT_REPLY) { ... }
 *
 * @c work is IDEMIP_ICMP6_IN_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * message paths are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. A borrow clear has not run on, a null pointer, a packet whose version is not
 * 6 or whose chain does not close, an out buffer too small for the message, and a type that is not
 * one of the four sec 3 error types are ERR: none of them changes on a later tick. An error message
 * a sec 2.4 (e) rule refuses is ERR for the same reason, with @ref Icmp6InIo::suppress naming the
 * rule. The one BUSY is sec 2.4 (f)'s empty token bucket, which the millisecond clock refills, so a
 * caller comes back on a later tick.
 *
 * @var Icmp6InNs::clear zero the context and the operand block, refill the sec 2.4 (f) bucket, and
 *                       mark the borrow usable
 * @var Icmp6InNs::recv  read one arriving message, report what to do with it, and build the sec 4.2
 *                       Echo Reply when it is an Echo Request
 * @var Icmp6InNs::error build one sec 3 error message about a packet, after the sec 2.4 (e) MUST NOT
 *                       rules and the sec 2.4 (f) rate limit
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const recv)(uint8_t *restrict work);
    void (*const error)(uint8_t *restrict work);
} Icmp6InNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const Icmp6InNs Icmp6In;

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_ICMP6_IN_H
