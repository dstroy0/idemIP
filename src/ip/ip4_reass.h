// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_reass.h
 * @brief IPv4 reassembly, RFC 791 sec 3.2 keyed by the RFC 815 hole descriptor list.
 *
 * RFC 791 sec 3.2 "An Example Reassembly Procedure": "For each datagram the buffer identifier is
 * computed as the concatenation of the source, destination, protocol, and identification fields",
 * which is what a datagram row here holds.
 *
 * RFC 815 replaces the bit table with holes. sec 2: "Each hole can be characterized by two numbers,
 * hole.first, the number of the first octet in the hole, and hole.last, the number of the last octet
 * in the hole", gathered in "the hole descriptor list". sec 3 opens a datagram with one hole, "the
 * entry which describes the datagram as being completely missing. In this case, hole.first equals
 * zero, and hole.last equals infinity", and step 8: "If the hole descriptor list is now empty, the
 * datagram is now complete."
 *
 * RFC 815 sec 4 puts each descriptor "in the first octets of the hole itself". Nothing here holds a
 * reassembly buffer: a fragment stays in the buffer the DMA engine wrote it to, with its receive
 * descriptor pinned, so the hole descriptors are their own table in the borrow and carry the thread
 * that section sizes two octets for.
 *
 * The deadline on a row is RFC 791 sec 3.2's timer: step (17) "TIMER <- MAX(TIMER,TTL)", step (19)
 * "timer expires: flush all reassembly with this BUFID", with IDEMIP_IP_REASS_MAXAGE_S as the "lower
 * bound on the reassembly waiting time" that section sets at 15 seconds.
 */

#ifndef IDEMIP_IP4_REASS_H
#define IDEMIP_IP4_REASS_H

#include "src/ip/ipv4.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/** @brief No row and no list link. Every index result and every list terminator reads this. */
#define IDEMIP_IP4_REASS_INDEX_NONE 0xFFu

/**
 * @brief What hole.last is set to before the last fragment arrives, RFC 815 sec 3.
 *
 * "hole.last equals infinity. (Infinity is presumably implemented by a very large integer, greater
 * than 576, of the implementor's choice.)" A datagram is at most RFC 791's Total Length, so the
 * largest octet number a hole can name is that less one, and the field is 16 bits wide.
 */
#define IDEMIP_IP4_REASS_INFINITY 0xFFFFu

/**
 * @brief What a datagram row is.
 *
 * RFC 791 sec 3.2 has three ends for a row: the fragments complete it and it goes on, the timer runs
 * out, or a whole datagram flushes it. COMPLETE and RECLAIM both still pin receive descriptors, so a
 * row is not free until they are handed back.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP4_REASS_FREE = 0,  ///< no datagram in this row
    IDEMIP_IP4_REASS_HOLDING,   ///< fragments are held and the hole list is not empty
    IDEMIP_IP4_REASS_COMPLETE,  ///< the hole list emptied, RFC 815 sec 3 step 8
    IDEMIP_IP4_REASS_RECLAIM,   ///< done with, and its descriptors are waiting to be handed back
} IdemIpIp4ReassState;

/**
 * @brief What hold takes: one fragment, where the engine left it.
 *
 * @c hdr points at the RFC 791 sec 3.1 header, from which the buffer identifier, the Fragment Offset,
 * the More Fragments flag and the Total Length are read. The octets are never copied out of the
 * engine's buffer, so what is held is @c desc, the descriptor keeping that buffer out of the ring.
 */
typedef struct
{
    const uint8_t *hdr; ///< the fragment's IPv4 header, in the pinned receive buffer
    uint16_t desc;      ///< the pinned receive descriptor
    uint16_t len;       ///< octets readable at @c hdr
} Ip4ReassHoldArgs;

/** @brief What next takes: the datagram row whose fragments are being walked. */
typedef struct
{
    uint8_t index;
} Ip4ReassNextArgs;

/**
 * @brief What release takes: the datagram row to be done with.
 *
 * RFC 791 sec 3.2 step (16): "free all reassembly resources for this BUFID".
 */
typedef struct
{
    uint8_t index;
} Ip4ReassReleaseArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Ip4ReassIo::hold_args    the fragment hold takes in
 * @var Ip4ReassIo::next_args    the datagram row next walks
 * @var Ip4ReassIo::release_args the datagram row release is done with
 * @var Ip4ReassIo::now_ms       the millisecond clock the caller read before the call. Every deadline
 *                               this unit stamps and every age it compares comes from it.
 * @var Ip4ReassIo::status       what the call reports: OK, BUSY, or ERR
 * @var Ip4ReassIo::total_len    RFC 791 sec 3.2's TDL, the datagram's data length once the last
 *                               fragment has landed, and 0 until then
 * @var Ip4ReassIo::off          the fragment offset in octets of the fragment next reported
 * @var Ip4ReassIo::len          its octet count
 * @var Ip4ReassIo::desc         its pinned receive descriptor, which reclaim also reports
 * @var Ip4ReassIo::hdr_len      octets of IPv4 header in front of its data
 * @var Ip4ReassIo::index        the datagram row the call touched, or IDEMIP_IP4_REASS_INDEX_NONE
 * @var Ip4ReassIo::state        that row's state
 * @var Ip4ReassIo::complete     the hole descriptor list emptied on this call, RFC 815 sec 3 step 8
 * @var Ip4ReassIo::src          the Source Address of the datagram a tick timed out, which RFC 1122
 *                               sec 3.3.2 answers with an ICMP Time Exceeded: "the
 *                               partially-reassembled datagram MUST be discarded and an ICMP Time
 *                               Exceeded message sent to the source host"
 * @var Ip4ReassIo::frag_zero    fragment zero of that datagram was among the fragments held, which is
 *                               the condition sec 3.3.2 puts on sending it
 */
typedef struct
{
    Ip4ReassHoldArgs hold_args;
    Ip4ReassNextArgs next_args;
    Ip4ReassReleaseArgs release_args;

    uint32_t now_ms;
    uint32_t src;

    uint16_t total_len;
    uint16_t off;
    uint16_t len;
    uint16_t desc;
    uint8_t hdr_len;
    IdemIpStatus status;
    IdemIpIp4ReassState state;
    uint8_t index;
    idemip_bool complete;
    idemip_bool frag_zero;
} Ip4ReassIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. IDEMIP_IP4_REASS_CTX_BYTES covers everything
// outside the three tables, which is the operand block and this module's private context.

/** @brief The operand and result block. */
#define IDEMIP_IP4_REASS_OFF_IO 0u

/** @brief The private context, right behind the operand block. */
#define IDEMIP_IP4_REASS_OFF_CTX (IDEMIP_IP4_REASS_OFF_IO + sizeof(Ip4ReassIo))

/** @brief IDEMIP_IP4_REASS_DATAGRAMS rows, one RFC 791 buffer identifier each. */
#define IDEMIP_IP4_REASS_OFF_DGRAM IDEMIP_IP4_REASS_CTX_BYTES

/** @brief IDEMIP_IP4_REASS_FRAGS held fragments, one pinned receive descriptor each. */
#define IDEMIP_IP4_REASS_OFF_FRAG                                                                                      \
    (IDEMIP_IP4_REASS_OFF_DGRAM + (IDEMIP_IP4_REASS_DATAGRAMS << IDEMIP_IP4_REASS_DATAGRAM_ENTRY_SHIFT))

/** @brief IDEMIP_IP4_REASS_HOLES hole descriptors, RFC 815 sec 2. */
#define IDEMIP_IP4_REASS_OFF_HOLE                                                                                      \
    (IDEMIP_IP4_REASS_OFF_FRAG + (IDEMIP_IP4_REASS_FRAGS << IDEMIP_IP4_REASS_FRAG_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IP4_REASS_IO(w) ((Ip4ReassIo *)(void *)((w) + IDEMIP_IP4_REASS_OFF_IO))

// A row index and a list link are one octet, so a count at or above the terminator is unaddressable.
static_assert(IDEMIP_IP4_REASS_DATAGRAMS < IDEMIP_IP4_REASS_INDEX_NONE,
              "IDEMIP_IP4_REASS_DATAGRAMS must stay below IDEMIP_IP4_REASS_INDEX_NONE: a row index is one octet");
static_assert(IDEMIP_IP4_REASS_FRAGS < IDEMIP_IP4_REASS_INDEX_NONE,
              "IDEMIP_IP4_REASS_FRAGS must stay below IDEMIP_IP4_REASS_INDEX_NONE: a list link is one octet");
static_assert(IDEMIP_IP4_REASS_HOLES < IDEMIP_IP4_REASS_INDEX_NONE,
              "IDEMIP_IP4_REASS_HOLES must stay below IDEMIP_IP4_REASS_INDEX_NONE: a list link is one octet");

// RFC 791's Total Length is 16 bits, so the last octet a hole can name is inside a 16-bit field.
static_assert(IDEMIP_IP4_REASS_INFINITY >= IDEMIP_IP4_TOTAL_LEN_MAX - 1u,
              "RFC 815 sec 3 opens a hole reaching to infinity: it must reach the last octet RFC 791 allows");

/**
 * @brief The reassembler.
 *
 *   Ip4Reass.clear(work);
 *   IDEMIP_IP4_REASS_IO(work)->now_ms = tick_ms;
 *   IDEMIP_IP4_REASS_IO(work)->hold_args.hdr = frame + IDEMIP_ETH_HDR_LEN;
 *   IDEMIP_IP4_REASS_IO(work)->hold_args.desc = desc;
 *   IDEMIP_IP4_REASS_IO(work)->hold_args.len = len;
 *   Ip4Reass.hold(work);
 *   if (IDEMIP_IP4_REASS_IO(work)->complete) { ... Ip4Reass.next(work); ... }
 *
 * @c work is IDEMIP_IP4_REASS_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the reassembler, so
 * two of them are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick. A borrow that clear has not run on is refused.
 *
 * Every held fragment pins a receive descriptor, and IDEMIP_MAX_PINNED_FRAMES counts
 * IDEMIP_IP4_REASS_FRAGS of them, so a descriptor is handed back through reclaim rather than dropped.
 *
 * @var Ip4ReassNs::clear   zero the context and all three tables, and mark the borrow usable
 * @var Ip4ReassNs::hold    take one fragment into its datagram's row, running the RFC 815 sec 3
 *                          eight steps over the hole list, and raising the row's deadline the way
 *                          RFC 791 sec 3.2 step (17) does, "TIMER <- MAX(TIMER,TTL)". BUSY when no
 *                          row or no fragment slot is free, which the timeout sweep frees.
 * @var Ip4ReassNs::next    the next held fragment of a row, in ascending fragment offset. BUSY once
 *                          the row's fragments have all been reported.
 * @var Ip4ReassNs::release be done with a row, RFC 791 sec 3.2 step (16), leaving its descriptors to
 *                          be reclaimed
 * @var Ip4ReassNs::reclaim one pinned descriptor of a released or timed-out row, to hand back to the
 *                          ring. BUSY when none is waiting.
 * @var Ip4ReassNs::tick    time out rows older than IDEMIP_IP_REASS_MAXAGE_S, RFC 791 sec 3.2 step
 *                          (19). BUSY when the sweep found nothing.
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const hold)(uint8_t *restrict work);
    void (*const next)(uint8_t *restrict work);
    void (*const release)(uint8_t *restrict work);
    void (*const reclaim)(uint8_t *restrict work);
    void (*const tick)(uint8_t *restrict work);
} Ip4ReassNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const Ip4ReassNs Ip4Reass;

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_IP4_REASS_H
