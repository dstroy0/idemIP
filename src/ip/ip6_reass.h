// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip6_reass.h
 * @brief IPv6 reassembly, RFC 8200 sec 4.5: fragments in, one original packet out.
 *
 * A held fragment stays in the buffer the DMA engine wrote it to, so the entry holds the receive
 * descriptor rather than a copy. RFC 8200 sec 4.5 matches fragments by "the same IPv6 Source
 * Address, IPv6 Destination Address, and Fragment Identification", and abandons a packet whose
 * fragments have not all arrived within 60 seconds of the first.
 *
 * The Fragment header fields themselves are in ipv6.h. Nothing here parses one.
 */

#ifndef IDEMIP_IP6_REASS_H
#define IDEMIP_IP6_REASS_H

#include "src/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/** @brief No datagram, no fragment. Every index in this contract reads this when it names none. */
#define IDEMIP_IP6_REASS_NONE 0xFFu

/**
 * @brief What RFC 8200 sec 4.5 says to answer a fragment with.
 *
 * The section lists five error conditions. Four name the ICMP message to send and where its Pointer
 * points; the fifth, overlap, says "no ICMP error messages should be sent".
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP6_REASS_ERR_NONE = 0,      ///< nothing to answer
    IDEMIP_IP6_REASS_ERR_TIMEOUT,       ///< "ICMP Time Exceeded -- Fragment Reassembly Time Exceeded"
    IDEMIP_IP6_REASS_ERR_PAYLOAD_LEN,   ///< Parameter Problem, Code 0, pointing at Payload Length
    IDEMIP_IP6_REASS_ERR_FRAG_OFFSET,   ///< Parameter Problem, Code 0, pointing at Fragment Offset
    IDEMIP_IP6_REASS_ERR_HEADER_CHAIN,  ///< Parameter Problem, Code 3, Pointer zero
    IDEMIP_IP6_REASS_ERR_OVERLAP,       ///< abandoned, and "no ICMP error messages should be sent"
} IdemIpIp6ReassError;

/**
 * @brief What a fragment arrival takes.
 *
 * @var Ip6ReassInputArgs::pkt      the IPv6 header of the fragment packet, where the engine left it
 * @var Ip6ReassInputArgs::len      octets readable at @p pkt
 * @var Ip6ReassInputArgs::frag_hdr octets from @p pkt to the sec 4.5 Fragment header
 * @var Ip6ReassInputArgs::now_ms   the millisecond clock, which starts the sec 4.5 60-second bound
 * @var Ip6ReassInputArgs::desc     the receive descriptor pinned while this fragment is held
 */
typedef struct
{
    const uint8_t *pkt;
    size_t len;
    size_t frag_hdr;
    uint32_t now_ms;
    uint16_t desc;
} Ip6ReassInputArgs;

/** @brief What a sweep takes: the millisecond clock the deadlines are compared against. */
typedef struct
{
    uint32_t now_ms;
} Ip6ReassTickArgs;

/**
 * @brief Which held fragment a walk names.
 *
 * @var Ip6ReassFragArgs::datagram the datagram, as @ref Ip6ReassIo::datagram reported it
 * @var Ip6ReassFragArgs::index    the fragment's place in that datagram, rising with Fragment Offset
 */
typedef struct
{
    uint8_t datagram;
    uint8_t index;
} Ip6ReassFragArgs;

/** @brief Which datagram is given up: its fragments are released and its slot freed. */
typedef struct
{
    uint8_t datagram;
} Ip6ReassDropArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Ip6ReassIo::input_args  the arriving fragment
 * @var Ip6ReassIo::tick_args   the clock a sweep ages against
 * @var Ip6ReassIo::frag_args   which held fragment a walk names
 * @var Ip6ReassIo::drop_args   which datagram is given up
 * @var Ip6ReassIo::status      what the call reports: OK, BUSY, or ERR
 * @var Ip6ReassIo::err         the sec 4.5 error the caller answers the fragment with
 * @var Ip6ReassIo::complete    every fragment of the datagram has arrived
 * @var Ip6ReassIo::datagram    the datagram the call touched, or IDEMIP_IP6_REASS_NONE
 * @var Ip6ReassIo::frag_count  fragments the datagram holds
 * @var Ip6ReassIo::next_hdr    Next Header of the Fragment header of the offset-zero fragment,
 *                              which sec 4.5 makes the reassembled packet's
 * @var Ip6ReassIo::expired     datagrams a sweep abandoned
 * @var Ip6ReassIo::total_len   Payload Length of the reassembled packet, by the sec 4.5 formula
 * @var Ip6ReassIo::frag_desc   the descriptor the named fragment pins
 * @var Ip6ReassIo::frag_offset that fragment's Fragment Offset, in octets
 * @var Ip6ReassIo::frag_len     octets of fragment data following its Fragment header
 * @var Ip6ReassIo::frag_hdr_len octets from that fragment packet's IPv6 header to its fragment data
 */
typedef struct
{
    Ip6ReassInputArgs input_args;
    Ip6ReassTickArgs tick_args;
    Ip6ReassFragArgs frag_args;
    Ip6ReassDropArgs drop_args;

    IdemIpStatus status;
    IdemIpIp6ReassError err;
    idemip_bool complete;
    uint8_t datagram;
    uint8_t frag_count;
    uint8_t next_hdr;
    uint8_t expired;
    uint16_t total_len;
    uint16_t frag_desc;
    uint16_t frag_offset;
    uint16_t frag_len;
    uint16_t frag_hdr_len;
} Ip6ReassIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only
// the map is public.

// IDEMIP_IP6_REASS_CTX_BYTES spans the operand block and the context together, the way
// IDEMIP_PHY_BORROW covers both, so the tables start at a constant that no growth in either moves.

#define IDEMIP_IP6_REASS_OFF_IO 0u ///< the operand and result block
#define IDEMIP_IP6_REASS_OFF_CTX (IDEMIP_IP6_REASS_OFF_IO + IDEMIP_ROUND_UP(sizeof(Ip6ReassIo), IDEMIP_ALIGN))
#define IDEMIP_IP6_REASS_OFF_DATAGRAMS (IDEMIP_IP6_REASS_OFF_IO + IDEMIP_IP6_REASS_CTX_BYTES)
#define IDEMIP_IP6_REASS_OFF_FRAGS                                                                                     \
    (IDEMIP_IP6_REASS_OFF_DATAGRAMS + (IDEMIP_IP6_REASS_DATAGRAMS << IDEMIP_IP6_REASS_DATAGRAM_ENTRY_SHIFT))
#define IDEMIP_IP6_REASS_OFF_HOLES                                                                                     \
    (IDEMIP_IP6_REASS_OFF_FRAGS + (IDEMIP_IP6_REASS_FRAGS << IDEMIP_IP6_REASS_FRAG_ENTRY_SHIFT))
#define IDEMIP_IP6_REASS_OFF_END                                                                                       \
    (IDEMIP_IP6_REASS_OFF_HOLES + (IDEMIP_IP6_REASS_HOLES << IDEMIP_IP6_REASS_HOLE_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IP6_REASS_IO(w) ((Ip6ReassIo *)(void *)((w) + IDEMIP_IP6_REASS_OFF_IO))

/**
 * @brief The reassembler, RFC 8200 sec 4.5.
 *
 *   Ip6Reass.clear(work);
 *   IDEMIP_IP6_REASS_IO(work)->input_args.pkt = ip6;
 *   IDEMIP_IP6_REASS_IO(work)->input_args.len = ip6_len;
 *   IDEMIP_IP6_REASS_IO(work)->input_args.frag_hdr = chain.frag_hdr;
 *   IDEMIP_IP6_REASS_IO(work)->input_args.desc = desc;
 *   IDEMIP_IP6_REASS_IO(work)->input_args.now_ms = now;
 *   Ip6Reass.input(work);
 *
 * @c work is IDEMIP_IP6_REASS_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. The borrow IS the
 * instance, so two reassemblers are two borrows and share not one byte.
 *
 * A borrow is refused until @ref Ip6ReassNs::clear has run on it: clear zeroes every region above
 * and leaves one nonzero octet in the context region, the mark that says these bytes are this
 * module's. It does not touch the operand block.
 *
 * Nothing here blocks. A table with no free slot reports IDEMIP_BUSY, since a slot frees when a
 * datagram completes or times out. A fragment sec 4.5 says to discard reports IDEMIP_ERR with
 * @ref Ip6ReassIo::err naming the ICMP answer.
 *
 * @var Ip6ReassNs::clear   zero the context and the three tables, and mark the borrow cleared
 * @var Ip6ReassNs::input   file an arriving fragment, reporting completion or the sec 4.5 error
 * @var Ip6ReassNs::frag_at read one held fragment of a datagram, so the caller can copy it out
 * @var Ip6ReassNs::drop    give up a datagram, freeing its fragment and hole entries
 * @var Ip6ReassNs::tick    abandon every datagram past the sec 4.5 60-second bound
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const input)(uint8_t *work);
    void (*const frag_at)(uint8_t *work);
    void (*const drop)(uint8_t *work);
    void (*const tick)(uint8_t *work);
} Ip6ReassNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_ip6_reass_clear(uint8_t *work);
void idemip_ip6_reass_input(uint8_t *work);
void idemip_ip6_reass_frag_at(uint8_t *work);
void idemip_ip6_reass_drop(uint8_t *work);
void idemip_ip6_reass_tick(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Ip6Reass.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Ip6ReassNs Ip6Reass IDEMIP_UNUSED = {
    .clear = idemip_ip6_reass_clear,
    .input = idemip_ip6_reass_input,
    .frag_at = idemip_ip6_reass_frag_at,
    .drop = idemip_ip6_reass_drop,
    .tick = idemip_ip6_reass_tick};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_IP6_REASS_H
