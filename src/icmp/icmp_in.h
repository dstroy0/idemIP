// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmp_in.h
 * @brief One arriving RFC 792 message, and the RFC 1122 sec 3.2.2 rules on originating an error.
 *
 * Two entries carry the work. @ref IcmpInNs::recv reads one message that arrived in a verified
 * internet datagram, reports what the caller does with it, and builds the Echo Reply of RFC 792
 * "Echo or Echo Reply Message" when the message is an Echo. @ref IcmpInNs::error builds one of the
 * five RFC 1122 sec 3.2.2 error messages about a datagram, after the five MUST NOT rules that
 * section states.
 *
 * Nothing here sends. A call writes into the buffer the operand block names and reports its length,
 * the source address the internet header carries and the destination it goes to.
 *
 * The field offsets, the codes and the build helpers are icmp.h's; nothing here restates one.
 */

#ifndef IDEMIP_ICMP_IN_H
#define IDEMIP_ICMP_IN_H

#include "src/icmp/icmp.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// What a received message asks the caller to do
// ---------------------------------------------------------------------------
// One bit per action RFC 1122 sec 3.2.2 names. A caller acts on the set and nothing else: the
// entries here send no datagram and signal no user.

/** @brief Send the @ref IcmpInIo::out_len octets built at @ref IcmpInRecvArgs::out. */
#define IDEMIP_ICMP_IN_ACT_REPLY (1u << 0)

/**
 * @brief Pass the error to the transport entity @ref IcmpInIo::proto names.
 *
 * RFC 1122 sec 3.2.2: "In those cases where the Internet layer is required to pass an ICMP error
 * message to the transport layer, the IP protocol number MUST be extracted from the original header
 * and used to select the appropriate transport protocol entity to handle the error."
 */
#define IDEMIP_ICMP_IN_ACT_TRANSPORT (1u << 1)

/**
 * @brief Update the routing information from the Redirect.
 *
 * RFC 1122 sec 3.2.2.2: "A host receiving a Redirect message MUST update its routing information
 * accordingly." The Gateway Internet Address is @ref IcmpInIo::gateway.
 */
#define IDEMIP_ICMP_IN_ACT_ROUTE (1u << 2)

/**
 * @brief Pass the message to the ICMP user interface.
 *
 * RFC 1122 sec 3.2.2.6: "Echo Reply messages MUST be passed to the ICMP user interface, unless the
 * corresponding Echo Request originated in the IP layer."
 */
#define IDEMIP_ICMP_IN_ACT_USER (1u << 3)

/**
 * @brief Silently discard the message.
 *
 * RFC 1122 sec 3.2.2: "If an ICMP message of unknown type is received, it MUST be silently
 * discarded." Also set for a message whose checksum does not hold, for one shorter than its own
 * type requires, and for the types RFC 1122 sec 3.2.2.7 and sec 3.2.2.8 leave unimplemented here.
 */
#define IDEMIP_ICMP_IN_ACT_DISCARD (1u << 4)

// ---------------------------------------------------------------------------
// Which MUST NOT rule refused an error message (RFC 1122 sec 3.2.2)
// ---------------------------------------------------------------------------
// "An ICMP error message MUST NOT be sent as the result of receiving: an ICMP error message, or a
// datagram destined to an IP broadcast or IP multicast address, or a datagram sent as a link-layer
// broadcast, or a non-initial fragment, or a datagram whose source address does not define a single
// host". Reported in @ref IcmpInIo::suppress for diagnostics; no control flow branches on it.

#define IDEMIP_ICMP_IN_SUPPRESS_NONE 0u      ///< no rule refused it
#define IDEMIP_ICMP_IN_SUPPRESS_ICMP_ERROR 1u ///< "an ICMP error message"
#define IDEMIP_ICMP_IN_SUPPRESS_DST_BCAST 2u  ///< "a datagram destined to an IP broadcast ... address"
#define IDEMIP_ICMP_IN_SUPPRESS_DST_MCAST 3u  ///< "or IP multicast address"
#define IDEMIP_ICMP_IN_SUPPRESS_LINK_BCAST 4u ///< "a datagram sent as a link-layer broadcast"
#define IDEMIP_ICMP_IN_SUPPRESS_FRAGMENT 5u   ///< "a non-initial fragment"
#define IDEMIP_ICMP_IN_SUPPRESS_SRC 6u        ///< "whose source address does not define a single host"

/**
 * @brief RFC 1122 sec 3.2.2.2: "A host SHOULD NOT send an ICMP Redirect message; Redirects are to be
 * sent only by gateways."
 */
#define IDEMIP_ICMP_IN_SUPPRESS_REDIRECT 7u

/**
 * @brief RFC 1812 sec 4.3.2.8: the rate limit refused it.
 *
 * "A router which sends ICMP Source Quench messages MUST be able to limit the rate at which the
 * messages can be generated. A router SHOULD also be able to limit the rate at which it sends other
 * sorts of ICMP error messages." Reported with @ref IcmpInIo::status BUSY, because the clock refills
 * the bucket and a later call succeeds.
 */
#define IDEMIP_ICMP_IN_SUPPRESS_RATE 8u

/**
 * @brief What a received message takes.
 *
 * @var IcmpInRecvArgs::datagram the RFC 791 sec 3.1 internet header, the RFC 792 message behind it.
 *                               Already through @ref idemip_ip4_verify, which the entry repeats.
 * @var IcmpInRecvArgs::len      readable octets at @p datagram
 * @var IcmpInRecvArgs::out      where an Echo Reply is built, @p out_cap octets, not overlapping
 *                               @p datagram
 * @var IcmpInRecvArgs::out_cap  RFC 1122 sec 3.2.2.6's "maximum transmission size", which a reply
 *                               longer than is truncated to
 * @var IcmpInRecvArgs::if_addr  an address of the interface it arrived on, host order, which is the
 *                               RFC 1122 sec 3.2.1.3 specific-destination address when the datagram
 *                               was broadcast or multicast
 * @var IcmpInRecvArgs::if_mask  that interface's RFC 1122 sec 3.3.1.1 address mask, host order
 * @var IcmpInRecvArgs::link_bcast the frame arrived as a link-layer broadcast, which RFC 1122
 *                               sec 3.2.2 IMPLEMENTATION has the link layer report
 */
typedef struct
{
    const uint8_t *datagram;
    size_t len;
    uint8_t *out;
    size_t out_cap;
    uint32_t if_addr;
    uint32_t if_mask;
    idemip_bool link_bcast;
} IcmpInRecvArgs;

/**
 * @brief What originating an error message takes.
 *
 * @var IcmpInErrArgs::datagram the internet header of the datagram the error is about, its data
 *                              behind it. Already through @ref idemip_ip4_verify.
 * @var IcmpInErrArgs::len      readable octets at @p datagram
 * @var IcmpInErrArgs::out      where the message is built, @p out_cap octets, not overlapping
 *                              @p datagram
 * @var IcmpInErrArgs::out_cap  octets available at @p out
 * @var IcmpInErrArgs::if_mask  the receiving interface's address mask, host order, which decides the
 *                              RFC 1122 sec 3.2.1.3 (e) directed broadcast form
 * @var IcmpInErrArgs::word     the 32 bits at IDEMIP_ICMP_OFF_UNUSED: zero where RFC 792 labels the
 *                              field unused, the Pointer at IDEMIP_ICMP_POINTER_SHIFT for parameter
 *                              problem
 * @var IcmpInErrArgs::now_ms   the caller's monotonic millisecond count, which RFC 1812 sec 4.3.2.8's
 *                              rate limit refills its bucket from
 * @var IcmpInErrArgs::type     one of the five types RFC 1122 sec 3.2.2 groups as errors
 * @var IcmpInErrArgs::code     that type's code
 * @var IcmpInErrArgs::link_bcast the datagram arrived as a link-layer broadcast
 */
typedef struct
{
    const uint8_t *datagram;
    size_t len;
    uint8_t *out;
    size_t out_cap;
    uint32_t if_mask;
    uint32_t word;
    uint32_t now_ms;
    uint8_t type;
    uint8_t code;
    idemip_bool link_bcast;
} IcmpInErrArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns. Two workers on two borrows share no byte
 * of this.
 *
 * @var IcmpInIo::recv_args the arriving message
 * @var IcmpInIo::err_args  the datagram an error is originated about
 * @var IcmpInIo::status    what the call reports: OK, BUSY, or ERR
 * @var IcmpInIo::out_len   octets the built message occupies at the operand block's @c out
 * @var IcmpInIo::src       the Source Address the reply's internet header carries, host order. RFC
 *                          1122 sec 3.2.2.6: "The IP source address in an ICMP Echo Reply MUST be
 *                          the same as the specific-destination address ... of the corresponding
 *                          ICMP Echo Request message." An error message carries the same address.
 * @var IcmpInIo::dst       where it goes: the Source Address of the datagram that caused it, host
 *                          order, which RFC 792 states for every message as "The source network and
 *                          address from the original datagram's data"
 * @var IcmpInIo::gateway   the Gateway Internet Address a Redirect carried, host order
 * @var IcmpInIo::act       the actions above, ORed
 * @var IcmpInIo::type      the arriving Type
 * @var IcmpInIo::code      the arriving Code
 * @var IcmpInIo::proto     the Protocol field of the quoted internet header, which the transport
 *                          demux of RFC 1122 sec 3.2.2 selects on
 * @var IcmpInIo::id        the arriving Identifier, an echo or a query type
 * @var IcmpInIo::seq       the arriving Sequence Number
 * @var IcmpInIo::suppress  which RFC 1122 sec 3.2.2 rule refused an error message
 * @var IcmpInIo::cksum_ok  the RFC 792 checksum over the arriving message held
 * @var IcmpInIo::bad_len   the message stopped before the field its own type reaches. RFC 2011
 *                          icmpInErrors counts messages "determined as having ICMP-specific errors
 *                          (bad ICMP checksums, bad length, etc.)", so this and @ref
 *                          IcmpInIo::cksum_ok are the two that name one. A discard with neither set
 *                          is one RFC 1122 sec 3.2.2 takes silently and is no error.
 * @var IcmpInIo::truncated the Echo Reply did not fit @ref IcmpInRecvArgs::out_cap and was cut to it
 * @var IcmpInIo::tokens    RFC 1812 sec 4.3.2.8 error messages the bucket still allows in a burst
 * @var IcmpInIo::quoted_dst the Destination Address of the datagram a Redirect quotes, host order,
 *                          zero when the quote carried no whole header. RFC 1122 sec 3.2.2.2's
 *                          second test, "the source of the Redirect is not the current first-hop
 *                          gateway for the specified destination", is the caller's to apply against
 *                          it, and sec 3.3.1.2 (c) keys the route cache entry on it.
 */
typedef struct
{
    IcmpInRecvArgs recv_args;
    IcmpInErrArgs err_args;

    IdemIpStatus status;
    size_t out_len;
    uint32_t src;
    uint32_t dst;
    uint32_t gateway;
    uint32_t quoted_dst;
    uint8_t act;
    uint8_t type;
    uint8_t code;
    uint8_t proto;
    uint16_t id;
    uint16_t seq;
    uint8_t suppress;
    uint8_t tokens;
    idemip_bool cksum_ok;
    idemip_bool bad_len;
    idemip_bool truncated;
} IcmpInIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only
// the map is public.

#define IDEMIP_ICMP_IN_OFF_IO 0u ///< the operand and result block
#define IDEMIP_ICMP_IN_OFF_CTX (IDEMIP_ICMP_IN_OFF_IO + IDEMIP_ROUND_UP(sizeof(IcmpInIo), IDEMIP_ALIGN)) ///< the running context

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_ICMP_IN_IO(w) ((IcmpInIo *)(void *)((w) + IDEMIP_ICMP_IN_OFF_IO))

/**
 * @brief The RFC 792 message path: answer an Echo, and originate the errors RFC 1122 sec 3.2.2 lets
 *        a host originate.
 *
 *   IcmpIn.clear(work);
 *   IDEMIP_ICMP_IN_IO(work)->recv_args.datagram = frame + IDEMIP_ETH_HDR_LEN;
 *   IDEMIP_ICMP_IN_IO(work)->recv_args.len = len;
 *   IDEMIP_ICMP_IN_IO(work)->recv_args.out = tx;
 *   IDEMIP_ICMP_IN_IO(work)->recv_args.out_cap = mtu - IDEMIP_IPV4_HDR_LEN;
 *   IcmpIn.recv(work);
 *   if (IDEMIP_ICMP_IN_IO(work)->act & IDEMIP_ICMP_IN_ACT_REPLY) { ... }
 *
 * @c work is IDEMIP_ICMP_IN_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * message paths are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. A borrow clear has not run on, a null pointer, a datagram
 * @ref idemip_ip4_verify refuses, an out buffer too small to hold the smallest message of its kind,
 * and a type that is not one of the five RFC 1122 sec 3.2.2 error types are all ERR: none of them
 * changes on a later tick, so a caller stops rather than retrying. An error message the sec 3.2.2
 * rules refuse is ERR for the same reason, with @ref IcmpInIo::suppress naming the rule. No entry
 * reports BUSY, because none of them holds a resource that a later call frees.
 *
 * @var IcmpInNs::clear zero the context and the operand block, and mark the borrow usable
 * @var IcmpInNs::recv  read one arriving message, report what to do with it, and build the RFC 792
 *                      Echo Reply when it is an Echo
 * @var IcmpInNs::error build one RFC 792 error message about a datagram, after the RFC 1122
 *                      sec 3.2.2 MUST NOT rules
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const recv)(uint8_t *work);
    void (*const error)(uint8_t *work);
} IcmpInNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_icmp_in_clear(uint8_t *work);
void idemip_icmp_in_recv(uint8_t *work);
void idemip_icmp_in_error(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `IcmpIn.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const IcmpInNs IcmpIn IDEMIP_UNUSED = {
    .clear = idemip_icmp_in_clear,
    .recv = idemip_icmp_in_recv,
    .error = idemip_icmp_in_error};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_ICMP_IN_H
