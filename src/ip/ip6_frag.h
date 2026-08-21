// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip6_frag.h
 * @brief IPv6 fragmentation, RFC 8200 sec 4.5: one original packet in, fragment packets out.
 *
 * The section opens by naming who may do this at all: "unlike IPv4, fragmentation in IPv6 is
 * performed only by source nodes, not by routers along a packet's delivery path". So this unit sits
 * on the send path and nowhere else.
 *
 * An original packet is three parts: "The Per-Fragment headers must consist of the IPv6 header plus
 * any extension headers that must be processed by nodes en route to the destination, that is, all
 * headers up to and including the Routing header if present, else the Hop-by-Hop Options header if
 * present, else no extension headers." Behind them come the Extension and Upper-Layer headers, and
 * behind those the Fragmentable Part.
 *
 * Every fragment packet is "The Per-Fragment headers of the original packet, with the Payload Length
 * of the original IPv6 header changed to contain the length of this fragment packet only (excluding
 * the length of the IPv6 header itself), and the Next Header field of the last header of the
 * Per-Fragment headers changed to 44", then "A Fragment header containing: The Next Header value
 * that identifies the first header after the Per-Fragment headers of the original packet. A Fragment
 * Offset containing the offset of the fragment, in 8-octet units... The Identification value
 * generated for the original packet." The Identification arrives from the caller: sec 4.5 requires
 * it "be different than that of any other fragmented packet sent recently with the same Source
 * Address and Destination Address", which is a property of the sender and not of one split.
 *
 * "Each complete fragment, except possibly the last ('rightmost') one, is an integer multiple of 8
 * octets long", and "Fragments must not be created that overlap with any other fragments created
 * from the original packet", so the cut walks forward in 8-octet units and never revisits one.
 *
 * The Fragment header fields themselves are in ipv6.h. Nothing here lays one out.
 */

#ifndef IDEMIP_IP6_FRAG_H
#define IDEMIP_IP6_FRAG_H

#include "src/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/**
 * @brief Why a call was refused.
 *
 * RFC 8200 sec 4.5 names no ICMP message a sender answers itself with, its five error conditions
 * being a receiver's. A refusal here is the send path's own, and MTU is the one a caller acts on:
 * the packet cannot be made to fit the path.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP6_FRAG_ERR_NONE = 0,   ///< nothing refused
    IDEMIP_IP6_FRAG_ERR_HEADER,     ///< the packet's own header or extension chain did not hold up
    IDEMIP_IP6_FRAG_ERR_FRAGMENTED, ///< a Fragment header is already in the chain
    IDEMIP_IP6_FRAG_ERR_MTU,        ///< an MTU below RFC 8200 sec 5's 1280-octet minimum link MTU
    IDEMIP_IP6_FRAG_ERR_HEADERS,    ///< the headers leave no room for an 8-octet fragment behind them
    IDEMIP_IP6_FRAG_ERR_ROOM,       ///< the caller's buffer is short of this fragment packet
    IDEMIP_IP6_FRAG_ERR_DONE,       ///< every fragment of this packet has been written
    IDEMIP_IP6_FRAG_ERR_STATE,      ///< no split is open, or clear has not run on this borrow
} IdemIpIp6FragError;

/**
 * @brief What begin takes: the packet to split, the MTU it has to fit, and its Identification.
 *
 * @var Ip6FragBeginArgs::pkt   the packet's RFC 8200 sec 3 header, its chain and data behind it
 * @var Ip6FragBeginArgs::len   octets readable at @c pkt, never below the header plus Payload Length
 * @var Ip6FragBeginArgs::ident the 32-bit Identification every fragment of this packet carries
 * @var Ip6FragBeginArgs::mtu   "the MTU of the path to the packet's destination(s)", header included
 * @var Ip6FragBeginArgs::upper_hdr_len octets of the Upper-Layer header, which sec 4.5 item (3) puts
 *                              in the first fragment along with the extension headers. Zero when the
 *                              caller does not know it, which still requires the first fragment to
 *                              reach past the extension headers rather than stop on them.
 */
typedef struct
{
    const uint8_t *pkt;
    size_t len;
    uint32_t ident;
    uint16_t mtu;
    uint16_t upper_hdr_len;
} Ip6FragBeginArgs;

/**
 * @brief What next takes: where the fragment packet is written.
 *
 * @var Ip6FragNextArgs::out the caller's buffer, which the whole fragment packet is built into
 * @var Ip6FragNextArgs::cap octets writable at @c out
 */
typedef struct
{
    uint8_t *out;
    size_t cap;
} Ip6FragNextArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Ip6FragIo::begin_args the packet, the MTU and the Identification
 * @var Ip6FragIo::next_args  the buffer a fragment packet is written into
 * @var Ip6FragIo::status     what the call reports: OK or ERR
 * @var Ip6FragIo::err        which refusal
 * @var Ip6FragIo::split      the packet is larger than the MTU, so it is being divided
 * @var Ip6FragIo::more       the M flag this fragment carries, "1 = more fragments; 0 = last"
 * @var Ip6FragIo::index      which fragment this is, counting from zero
 * @var Ip6FragIo::offset     its Fragment Offset, in octets, from the start of the fragmentable part
 * @var Ip6FragIo::len        octets written at @ref Ip6FragNextArgs::out
 * @var Ip6FragIo::hdr_len    the Per-Fragment headers and the Fragment header, of those
 * @var Ip6FragIo::data_len   fragment octets of those
 * @var Ip6FragIo::unfrag_len octets the Per-Fragment headers span, the IPv6 header included
 * @var Ip6FragIo::next_hdr   what the Fragment header's Next Header carries, which is the Next
 *                            Header the last Per-Fragment header held before it was changed to 44
 */
typedef struct
{
    Ip6FragBeginArgs begin_args;
    Ip6FragNextArgs next_args;

    IdemIpStatus status;
    IdemIpIp6FragError err;
    idemip_bool split;
    idemip_bool more;
    uint16_t index;
    uint16_t offset;
    uint16_t len;
    uint16_t hdr_len;
    uint16_t data_len;
    uint16_t unfrag_len;
    uint8_t next_hdr;
} Ip6FragIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. This unit holds no table, so the operand
// block and the context are the whole borrow.

#define IDEMIP_IP6_FRAG_OFF_IO 0u ///< the operand and result block
#define IDEMIP_IP6_FRAG_OFF_CTX (IDEMIP_IP6_FRAG_OFF_IO + IDEMIP_ROUND_UP(sizeof(Ip6FragIo), IDEMIP_ALIGN))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IP6_FRAG_IO(w) ((Ip6FragIo *)(void *)((w) + IDEMIP_IP6_FRAG_OFF_IO))

// RFC 8200 sec 5: "IPv6 requires that every link in the Internet have an MTU of 1280 octets or
// greater." At that floor the fixed header and one Fragment header still leave whole 8-octet units.
static_assert(IDEMIP_IPV6_MIN_MTU > IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_FRAG_HDR_LEN + IDEMIP_IP6_EXT_UNIT,
              "RFC 8200 sec 5's 1280-octet floor must leave whole 8-octet fragments behind the two headers");

// The 13-bit Fragment Offset sits three places up in its field, so the field already carries the
// octet position and reaches every offset a 65,535-octet fragmentable part can hold.
static_assert(IDEMIP_IP6_FRAG_OFF_MASK >= (IDEMIP_IP6_PAYLOAD_MAX & ~(IDEMIP_IP6_EXT_UNIT - 1u)),
              "the Fragment Offset field must reach the last 8-octet unit of a full-length packet");

/**
 * @brief The fragmenter, RFC 8200 sec 4.5.
 *
 *   Ip6Frag.clear(work);
 *   IDEMIP_IP6_FRAG_IO(work)->begin_args.pkt = pkt;
 *   IDEMIP_IP6_FRAG_IO(work)->begin_args.len = len;
 *   IDEMIP_IP6_FRAG_IO(work)->begin_args.mtu = mtu;
 *   IDEMIP_IP6_FRAG_IO(work)->begin_args.ident = ident;
 *   Ip6Frag.begin(work);
 *   IDEMIP_IP6_FRAG_IO(work)->next_args.out = buf;
 *   IDEMIP_IP6_FRAG_IO(work)->next_args.cap = sizeof buf;
 *   while (Ip6Frag.next(work), IDEMIP_IP6_FRAG_IO(work)->status == IDEMIP_OK) { send(buf, io->len); }
 *
 * @c work is IDEMIP_IP6_FRAG_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the split, so two
 * packets being divided at once are two borrows and share not one byte.
 *
 * The packet itself is not copied into the borrow: begin records where it lies and every next reads
 * it there, so it stays put until the split ends.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks, and nothing here reports IDEMIP_BUSY: this unit waits on no ring, no peer and
 * no timer, so every refusal is one that repeating the call cannot lift. A short buffer, an MTU below
 * the RFC 8200 sec 5 minimum link MTU, a chain already carrying a Fragment header and a finished
 * split are all IDEMIP_ERR with @ref Ip6FragIo::err naming which.
 *
 * @var Ip6FragNs::clear zero the context and mark the borrow usable
 * @var Ip6FragNs::begin take one packet, the MTU and the Identification, walk the chain for the
 *                       Per-Fragment headers, and size the fragments. A packet at or under the MTU is
 *                       accepted whole, carries no Fragment header, and is written unchanged by one
 *                       next.
 * @var Ip6FragNs::next  write the next fragment packet into the caller's buffer: the Per-Fragment
 *                       headers with their Payload Length corrected and their last Next Header set to
 *                       44, then the Fragment header, then the fragment
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const begin)(uint8_t *work);
    void (*const next)(uint8_t *work);
} Ip6FragNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_ip6_frag_clear(uint8_t *work);
void idemip_ip6_frag_begin(uint8_t *work);
void idemip_ip6_frag_next(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Ip6Frag.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Ip6FragNs Ip6Frag IDEMIP_UNUSED = {
    .clear = idemip_ip6_frag_clear,
    .begin = idemip_ip6_frag_begin,
    .next = idemip_ip6_frag_next};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_IP6_FRAG_H
