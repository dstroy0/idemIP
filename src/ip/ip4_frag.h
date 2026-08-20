// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_frag.h
 * @brief IPv4 fragmentation, the RFC 791 sec 3.2 "Example Fragmentation Procedure".
 *
 * One oversized datagram in, one fragment per call out, written into a buffer the caller owns. The
 * procedure the section prints is followed step for step:
 *
 *   "IF TL =< MTU THEN Submit this datagram to the next step in datagram processing ELSE IF DF = 1
 *   THEN discard the datagram ELSE ... (3) NFB <- (MTU-IHL*4)/8; (4) Attach the first NFB*8 data
 *   octets; (5) Correct the header: MF <- 1; TL <- (IHL*4)+(NFB*8); Recompute Checksum;"
 *
 * and for every fragment after the first, "(7) Selectively copy the internet header (some options
 * are not copied, see option definitions); (8) Append the remaining data; (9) Correct the header:
 * IHL <- (((OIHL*4)-(length of options not copied))+3)/4; TL <- OTL - NFB*8 - (OIHL-IHL)*4);
 * FO <- OFO + NFB; MF <- OMF; Recompute Checksum;".
 *
 * Which options survive is the option-type octet's own top bit, RFC 791 sec 3.1: "The copied flag
 * indicates that this option is copied into all fragments on fragmentation. 0 = not copied,
 * 1 = copied."
 *
 * A datagram carrying DF is not fragmented. RFC 791 sec 3.2: "If the Don't Fragment flag (DF) bit
 * is set, then internet fragmentation of this datagram is NOT permitted, although it may be
 * discarded." RFC 1191 sec 4 is what the caller answers with: "the router is required to return an
 * ICMP Destination Unreachable message to the source of the datagram, with the Code indicating
 * "fragmentation needed and DF set"", Type 3 Code 4, carrying "the MTU of that next-hop network in
 * the low-order 16 bits".
 */

#ifndef IDEMIP_IP4_FRAG_H
#define IDEMIP_IP4_FRAG_H

#include "src/ip/ipv4.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// The option-type octet (RFC 791 sec 3.1)
// ---------------------------------------------------------------------------
// "The option-type octet is viewed as having 3 fields: 1 bit copied flag, 2 bits option class,
// 5 bits option number."

/** @brief The copied flag, bit 7: set means the option goes in every fragment. */
#define IDEMIP_IP4_FRAG_OPT_COPIED 0x80u

/** @brief The two class bits, bits 6 and 5. */
#define IDEMIP_IP4_FRAG_OPT_CLASS_MASK 0x60u

/** @brief The five number bits, bits 4 through 0. */
#define IDEMIP_IP4_FRAG_OPT_NUMBER_MASK 0x1Fu

/**
 * @brief End of Option List, type 0.
 *
 * RFC 791 sec 3.1: "This option indicates the end of the option list... This option occupies only 1
 * octet; it has no length octet." The pad octets a reduced header ends on are this type.
 */
#define IDEMIP_IP4_FRAG_OPT_EOL 0u

/** @brief No Operation, type 1: "This option occupies only 1 octet; it has no length octet." */
#define IDEMIP_IP4_FRAG_OPT_NOP 1u

/** @brief Octets an option carries at minimum once it has a length octet: the type and the length. */
#define IDEMIP_IP4_FRAG_OPT_MIN_LEN 2u

/**
 * @brief Why a call was refused, so the caller knows which ICMP message answers it.
 *
 * Only DF names a message. RFC 791 sec 3.2 discards a DF datagram that will not fit, and RFC 1191
 * sec 4 requires Destination Unreachable Type 3 Code 4 with the next-hop MTU in reply.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP4_FRAG_ERR_NONE = 0, ///< nothing refused
    IDEMIP_IP4_FRAG_ERR_DF,       ///< DF set on a datagram larger than the MTU: RFC 1191 sec 4
    IDEMIP_IP4_FRAG_ERR_HEADER,   ///< the datagram's own header did not verify (RFC 1122 sec 3.2.1)
    IDEMIP_IP4_FRAG_ERR_MTU,      ///< an MTU below RFC 791 sec 3.2's 68-octet floor
    IDEMIP_IP4_FRAG_ERR_OFFSET,   ///< the split would run past the 13-bit Fragment Offset field
    IDEMIP_IP4_FRAG_ERR_ROOM,     ///< the caller's buffer is short of this fragment
    IDEMIP_IP4_FRAG_ERR_DONE,     ///< every fragment of this datagram has been written
    IDEMIP_IP4_FRAG_ERR_STATE,    ///< no split is open, or clear has not run on this borrow
} IdemIpIp4FragError;

/**
 * @brief What begin takes: the datagram to split, and the MTU it has to fit.
 *
 * @var Ip4FragBeginArgs::dgram the datagram's RFC 791 sec 3.1 header, its data behind it
 * @var Ip4FragBeginArgs::len   octets readable at @c dgram, never below Total Length
 * @var Ip4FragBeginArgs::mtu   "The maximum sized datagram that can be transmitted through the next
 *                              network", RFC 791 sec 3.2, header included
 */
typedef struct
{
    const uint8_t *dgram;
    size_t len;
    uint16_t mtu;
} Ip4FragBeginArgs;

/**
 * @brief What next takes: where the fragment is written.
 *
 * @var Ip4FragNextArgs::out the caller's buffer, which the whole fragment is built into
 * @var Ip4FragNextArgs::cap octets writable at @c out
 */
typedef struct
{
    uint8_t *out;
    size_t cap;
} Ip4FragNextArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Ip4FragIo::begin_args the datagram and the MTU
 * @var Ip4FragIo::next_args  the buffer a fragment is written into
 * @var Ip4FragIo::status     what the call reports: OK or ERR
 * @var Ip4FragIo::err        which refusal, so the caller can answer RFC 1191 sec 4
 * @var Ip4FragIo::split      Total Length exceeded the MTU, so the datagram is being cut
 * @var Ip4FragIo::more       the More Fragments flag this fragment carries
 * @var Ip4FragIo::index      which fragment this is, counting from zero
 * @var Ip4FragIo::units      its Fragment Offset field, in units of eight octets
 * @var Ip4FragIo::offset     that offset in octets, the field shifted up by three
 * @var Ip4FragIo::len        octets written at @ref Ip4FragNextArgs::out, its Total Length
 * @var Ip4FragIo::hdr_len    header octets of those, which is IHL times four
 * @var Ip4FragIo::data_len   data octets of those
 */
typedef struct
{
    Ip4FragBeginArgs begin_args;
    Ip4FragNextArgs next_args;

    IdemIpStatus status;
    IdemIpIp4FragError err;
    idemip_bool split;
    idemip_bool more;
    uint16_t index;
    uint16_t units;
    uint16_t offset;
    uint16_t len;
    uint16_t hdr_len;
    uint16_t data_len;
} Ip4FragIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. This unit holds no table, so the operand
// block and the context are the whole borrow.

#define IDEMIP_IP4_FRAG_OFF_IO 0u ///< the operand and result block
#define IDEMIP_IP4_FRAG_OFF_CTX (IDEMIP_IP4_FRAG_OFF_IO + IDEMIP_ROUND_UP(sizeof(Ip4FragIo), IDEMIP_ALIGN))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IP4_FRAG_IO(w) ((Ip4FragIo *)(void *)((w) + IDEMIP_IP4_FRAG_OFF_IO))

// RFC 791 sec 3.2: "Every internet module must be able to forward a datagram of 68 octets without
// further fragmentation. This is because an internet header may be up to 60 octets, and the minimum
// fragment is 8 octets." At that floor even the widest header leaves one whole 8-octet unit, so
// NFB is never zero and the split always advances.
static_assert(IDEMIP_IP4_MIN_FORWARD_MTU >= IDEMIP_IP4_HDR_MAX + IDEMIP_IP4_FRAG_UNIT,
              "RFC 791 sec 3.2's 68-octet floor must leave one 8-octet fragment behind a 60-octet header");

// The three fields of the option-type octet fill it and do not overlap (RFC 791 sec 3.1).
static_assert((IDEMIP_IP4_FRAG_OPT_COPIED | IDEMIP_IP4_FRAG_OPT_CLASS_MASK | IDEMIP_IP4_FRAG_OPT_NUMBER_MASK) == 0xFFu,
              "the copied flag, the 2 class bits and the 5 number bits fill the option-type octet");
static_assert((IDEMIP_IP4_FRAG_OPT_COPIED & (IDEMIP_IP4_FRAG_OPT_CLASS_MASK | IDEMIP_IP4_FRAG_OPT_NUMBER_MASK)) == 0u,
              "the copied flag must not overlap the class or number fields");

// End of Option List and No Operation both read with the copied flag clear, so the flag alone drops
// them and no type is special-cased when a reduced header is built (RFC 791 sec 3.1).
static_assert((IDEMIP_IP4_FRAG_OPT_EOL & IDEMIP_IP4_FRAG_OPT_COPIED) == 0u &&
                  (IDEMIP_IP4_FRAG_OPT_NOP & IDEMIP_IP4_FRAG_OPT_COPIED) == 0u,
              "RFC 791 sec 3.1 leaves End of Option List and No Operation not copied");

/**
 * @brief The fragmenter, RFC 791 sec 3.2.
 *
 *   Ip4Frag.clear(work);
 *   IDEMIP_IP4_FRAG_IO(work)->begin_args.dgram = dgram;
 *   IDEMIP_IP4_FRAG_IO(work)->begin_args.len = len;
 *   IDEMIP_IP4_FRAG_IO(work)->begin_args.mtu = mtu;
 *   Ip4Frag.begin(work);
 *   IDEMIP_IP4_FRAG_IO(work)->next_args.out = buf;
 *   IDEMIP_IP4_FRAG_IO(work)->next_args.cap = sizeof buf;
 *   while (Ip4Frag.next(work), IDEMIP_IP4_FRAG_IO(work)->status == IDEMIP_OK) { send(buf, io->len); }
 *
 * @c work is IDEMIP_IP4_FRAG_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the split, so two
 * datagrams being cut at once are two borrows and share not one byte.
 *
 * The datagram itself is not copied into the borrow: begin records where it lies and every next
 * reads it there, so it stays put until the split ends.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks, and nothing here reports IDEMIP_BUSY: this unit waits on no ring, no peer and
 * no timer, so every refusal is one that repeating the call cannot lift. A short buffer, a DF
 * datagram, an MTU below the RFC 791 sec 3.2 floor and a finished split are all IDEMIP_ERR with
 * @ref Ip4FragIo::err naming which.
 *
 * @var Ip4FragNs::clear zero the context and mark the borrow usable
 * @var Ip4FragNs::begin take one datagram and the MTU, run the sec 3.2 fragmentation test, and size
 *                       the first and the following fragments. A datagram at or under the MTU is
 *                       accepted whole and written unchanged by one next.
 * @var Ip4FragNs::next  write the next fragment into the caller's buffer, correcting Total Length,
 *                       the More Fragments flag, the Fragment Offset, IHL and the Header Checksum,
 *                       and copying only the options RFC 791 sec 3.1's copied flag marks
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const begin)(uint8_t *work);
    void (*const next)(uint8_t *work);
} Ip4FragNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_ip4_frag_clear(uint8_t *work);
void idemip_ip4_frag_begin(uint8_t *work);
void idemip_ip4_frag_next(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Ip4Frag.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Ip4FragNs Ip4Frag IDEMIP_UNUSED = {
    .clear = idemip_ip4_frag_clear,
    .begin = idemip_ip4_frag_begin,
    .next = idemip_ip4_frag_next};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_IP4_FRAG_H
