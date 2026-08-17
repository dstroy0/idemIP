// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp.h
 * @brief The TCP header, RFC 9293 sec 3.1.
 *
 * Field offsets, the control bits, the options RFC 9293 sec 3.2 requires, and the pseudo-header the
 * checksum covers. Read out of the caller's bytes; holds nothing.
 */

#ifndef IDEMIP_TCP_H
#define IDEMIP_TCP_H

#include "idemIP/checksum.h"
#include "idemIP/ip/ipv4.h"

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// Field offsets (RFC 9293 sec 3.1, Figure 1)
// ---------------------------------------------------------------------------

#define IDEMIP_TCP_OFF_SRC_PORT 0u    ///< 16-bit Source Port
#define IDEMIP_TCP_OFF_DST_PORT 2u    ///< 16-bit Destination Port
#define IDEMIP_TCP_OFF_SEQ 4u         ///< 32-bit Sequence Number
#define IDEMIP_TCP_OFF_ACK 8u         ///< 32-bit Acknowledgment Number
#define IDEMIP_TCP_OFF_OFFS_FLAGS 12u ///< 4-bit Data Offset, 4-bit Reserved, 8 control bits
#define IDEMIP_TCP_OFF_WINDOW 14u     ///< 16-bit Window
#define IDEMIP_TCP_OFF_CKSUM 16u      ///< 16-bit Checksum
#define IDEMIP_TCP_OFF_URGENT 18u     ///< 16-bit Urgent Pointer
#define IDEMIP_TCP_OFF_OPTIONS 20u    ///< Options, then data

// ---------------------------------------------------------------------------
// Data Offset (RFC 9293 sec 3.1)
// ---------------------------------------------------------------------------
// "The number of 32-bit words in the TCP header. This indicates where the data begins. The TCP
// header (even one including options) is an integer multiple of 32 bits long."

#define IDEMIP_TCP_DOFF_SHIFT 12u
#define IDEMIP_TCP_DOFF_MASK 0x0Fu

/** @brief An option-free header is five 32-bit words. */
#define IDEMIP_TCP_DOFF_MIN 5u

/** @brief Data Offset is 4 bits, so the header cannot exceed fifteen words. */
#define IDEMIP_TCP_DOFF_MAX 15u

/** @brief A Data Offset word is four octets, so words to octets is a shift by two. */
#define IDEMIP_TCP_WORD_SHIFT 2u

/** @brief Header bytes for a Data Offset of @p doff words. */
#define IDEMIP_TCP_HDR_BYTES(doff) ((size_t)(doff) << IDEMIP_TCP_WORD_SHIFT)

/** @brief The Data Offset a header of @p n bytes carries. */
#define IDEMIP_TCP_DOFF_FROM_BYTES(n) ((uint8_t)((n) >> IDEMIP_TCP_WORD_SHIFT))

/**
 * @brief Octets the options can occupy.
 *
 * RFC 9293 sec 3.1: "size(Options) == (DOffset-5)*32", so the largest Data Offset leaves ten words.
 * RFC 2018 sec 3 counts the same span as "the 40 bytes available for TCP options".
 */
#define IDEMIP_TCP_OPTS_MAX (IDEMIP_TCP_HDR_BYTES(IDEMIP_TCP_DOFF_MAX) - IDEMIP_TCP_HDR_LEN)

/**
 * @brief RFC 9293 sec 3.1: Reserved "Must be zero in generated segments and must be ignored in
 * received segments if the corresponding future features are not implemented".
 */
#define IDEMIP_TCP_RSRVD_MASK 0x0F00u

// ---------------------------------------------------------------------------
// Control bits (RFC 9293 sec 3.1)
// ---------------------------------------------------------------------------
// Assignment is IANA's; these are the eight currently assigned, in the order the figure lays them
// out above the window.

#define IDEMIP_TCP_CWR (1u << 7) ///< Congestion Window Reduced
#define IDEMIP_TCP_ECE (1u << 6) ///< ECN-Echo
#define IDEMIP_TCP_URG (1u << 5) ///< Urgent pointer field is significant
#define IDEMIP_TCP_ACK (1u << 4) ///< Acknowledgment field is significant
#define IDEMIP_TCP_PSH (1u << 3) ///< Push function
#define IDEMIP_TCP_RST (1u << 2) ///< Reset the connection
#define IDEMIP_TCP_SYN (1u << 1) ///< Synchronize sequence numbers
#define IDEMIP_TCP_FIN (1u << 0) ///< No more data from sender

// ---------------------------------------------------------------------------
// Options (RFC 9293 sec 3.2)
// ---------------------------------------------------------------------------
// Kind 0 and 1 are single octets; every other kind carries its own length octet, which is what
// lets a parser step past an option it does not implement. RFC 9293 sec 3.1 MUST-68: "All TCP
// Options except End of Option List Option (EOL) and No-Operation (NOP) MUST have length fields,
// including all future options".

#define IDEMIP_TCP_OPT_END 0u     ///< End of Option List
#define IDEMIP_TCP_OPT_NOP 1u     ///< No-Operation
#define IDEMIP_TCP_OPT_MSS 2u     ///< Maximum Segment Size
#define IDEMIP_TCP_OPT_MSS_LEN 4u ///< kind, length, and a 16-bit value

/**
 * @brief RFC 9293 sec 3.7.1 MUST-14: "TCP endpoints MUST implement both sending and receiving the
 * MSS Option."
 */
#define IDEMIP_TCP_MSS_KIND IDEMIP_TCP_OPT_MSS

// The two octets every option but kind 0 and kind 1 begins with, then its data.

#define IDEMIP_TCP_OPT_OFF_KIND 0u ///< 8-bit option-kind
#define IDEMIP_TCP_OPT_OFF_LEN 1u  ///< 8-bit option-length
#define IDEMIP_TCP_OPT_OFF_DATA 2u ///< the option-data octets

/**
 * @brief RFC 9293 sec 3.1: "The option-length counts the two octets of option-kind and
 * option-length as well as the option-data octets."
 *
 * So a length below two is illegal, which MUST-7 requires a parser to be ready for: "TCP
 * implementations MUST be prepared to handle an illegal option length (e.g., zero)".
 */
#define IDEMIP_TCP_OPT_LEN_MIN 2u

// ---------------------------------------------------------------------------
// Window Scale (RFC 7323 sec 2.2)
// ---------------------------------------------------------------------------
// "Kind: 3", "Length: 3 bytes", the third octet carrying shift.cnt.

#define IDEMIP_TCP_OPT_WS 3u           ///< Window Scale
#define IDEMIP_TCP_OPT_WS_LEN 3u       ///< kind, length, and shift.cnt
#define IDEMIP_TCP_OPT_OFF_WS_SHIFT 2u ///< 8-bit shift.cnt

/**
 * @brief RFC 7323 sec 2.2: "The maximum scale exponent is limited to 14 for a maximum permissible
 * receive window size of 1 GiB (2^(14+16))."
 *
 * sec 2.3: a larger shift.cnt received "MUST use 14 instead of the specified value".
 */
#define IDEMIP_TCP_WS_MAX 14u

// ---------------------------------------------------------------------------
// Timestamps (RFC 7323 sec 3.2)
// ---------------------------------------------------------------------------
// "Kind: 8", "Length: 10 bytes", carrying "two four-byte timestamp fields", TSval then TSecr.

#define IDEMIP_TCP_OPT_TS 8u        ///< Timestamps
#define IDEMIP_TCP_OPT_TS_LEN 10u   ///< kind, length, TSval and TSecr
#define IDEMIP_TCP_OPT_OFF_TSVAL 2u ///< 32-bit TS Value
#define IDEMIP_TCP_OPT_OFF_TSECR 6u ///< 32-bit TS Echo Reply

// ---------------------------------------------------------------------------
// Selective acknowledgment (RFC 2018 sec 2 and sec 3)
// ---------------------------------------------------------------------------
// sec 2: SACK-permitted is "Kind: 4" and "Length=2", sent only in a SYN. sec 3: the SACK option
// itself is "Kind: 5", "Length: Variable", a list of blocks each of two 32-bit edges.

#define IDEMIP_TCP_OPT_SACK_PERM 4u     ///< SACK-Permitted
#define IDEMIP_TCP_OPT_SACK_PERM_LEN 2u ///< kind and length, no data
#define IDEMIP_TCP_OPT_SACK 5u          ///< SACK

/** @brief A block is a Left Edge and a Right Edge, 32 bits each. */
#define IDEMIP_TCP_SACK_BLOCK_LEN 8u
#define IDEMIP_TCP_SACK_BLOCK_SHIFT 3u ///< block index to octet offset

/**
 * @brief RFC 2018 sec 3: "A SACK option that specifies n blocks will have a length of 8*n+2 bytes,
 * so the 40 bytes available for TCP options can specify a maximum of 4 blocks."
 */
#define IDEMIP_TCP_SACK_BLOCKS_MAX 4u

/** @brief Octets a SACK option carrying @p n blocks occupies, the 8*n+2 of sec 3. */
#define IDEMIP_TCP_SACK_BYTES(n) (IDEMIP_TCP_OPT_LEN_MIN + ((size_t)(n) << IDEMIP_TCP_SACK_BLOCK_SHIFT))

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------
// Sequence and acknowledgment sit at 4 and 8 of a header that starts 20 bytes into an IPv4
// datagram that itself starts 14 into a frame - so 32-bit fields land on a two-byte boundary.

/** @brief Source Port. */
IDEMIP_INLINE uint16_t idemip_tcp_src_port(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_TCP_OFF_SRC_PORT);
}

/** @brief Destination Port. */
IDEMIP_INLINE uint16_t idemip_tcp_dst_port(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_TCP_OFF_DST_PORT);
}

/** @brief Sequence Number. */
IDEMIP_INLINE uint32_t idemip_tcp_seq(const uint8_t *h)
{
    return idemip_rd32(h + IDEMIP_TCP_OFF_SEQ);
}

/** @brief Acknowledgment Number; significant only when ACK is set. */
IDEMIP_INLINE uint32_t idemip_tcp_ack(const uint8_t *h)
{
    return idemip_rd32(h + IDEMIP_TCP_OFF_ACK);
}

/** @brief Data Offset, in 32-bit words. */
IDEMIP_INLINE uint8_t idemip_tcp_doff(const uint8_t *h)
{
    return (uint8_t)((idemip_rd16(h + IDEMIP_TCP_OFF_OFFS_FLAGS) >> IDEMIP_TCP_DOFF_SHIFT) & IDEMIP_TCP_DOFF_MASK);
}

/** @brief The eight control bits, as the low octet of the offset/flags word. */
IDEMIP_INLINE uint8_t idemip_tcp_flags(const uint8_t *h)
{
    return (uint8_t)(idemip_rd16(h + IDEMIP_TCP_OFF_OFFS_FLAGS) & 0xFFu);
}

/** @brief Window: octets this sender is willing to accept. */
IDEMIP_INLINE uint16_t idemip_tcp_window(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_TCP_OFF_WINDOW);
}

/** @brief Checksum as carried. */
IDEMIP_INLINE uint16_t idemip_tcp_cksum(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_TCP_OFF_CKSUM);
}

/** @brief Urgent Pointer; significant only when URG is set. */
IDEMIP_INLINE uint16_t idemip_tcp_urgent(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_TCP_OFF_URGENT);
}

/** @brief Header octets, options included, from the Data Offset. */
IDEMIP_INLINE size_t idemip_tcp_hdr_len(const uint8_t *h)
{
    return IDEMIP_TCP_HDR_BYTES(idemip_tcp_doff(h));
}

/** @brief The options region, where the fixed fields end. */
IDEMIP_INLINE const uint8_t *idemip_tcp_opts(const uint8_t *h)
{
    return h + IDEMIP_TCP_OFF_OPTIONS;
}

/**
 * @brief Octets the Data Offset gives the options.
 *
 * RFC 9293 sec 3.1: "size(Options) == (DOffset-5)*32; present only when DOffset > 5", padding
 * included. A Data Offset below the five-word minimum names no options at all.
 */
IDEMIP_INLINE size_t idemip_tcp_opts_len(const uint8_t *h)
{
    uint8_t doff = idemip_tcp_doff(h);
    if (doff <= IDEMIP_TCP_DOFF_MIN)
    {
        return 0u;
    }
    return (size_t)(doff - IDEMIP_TCP_DOFF_MIN) << IDEMIP_TCP_WORD_SHIFT;
}

// ---------------------------------------------------------------------------
// The option walk (RFC 9293 sec 3.1, "There are two cases for the format of an option")
// ---------------------------------------------------------------------------
// Case 1 is a single octet of option-kind, which MUST-68 confines to kinds 0 and 1. Case 2 is a
// kind octet, a length octet counting both of them, and the data. The walk holds its position in
// the caller's own object; it borrows the segment and copies no byte of it.

/**
 * @brief Where a walk stands in one segment's options.
 *
 * @var IdemIpTcpOptWalk::opts the options region
 * @var IdemIpTcpOptWalk::end  octets the Data Offset gives it
 * @var IdemIpTcpOptWalk::pos  octets stepped over
 * @var IdemIpTcpOptWalk::opt  the option this step landed on, null before the first and after the
 *                             last
 * @var IdemIpTcpOptWalk::kind that option's option-kind
 * @var IdemIpTcpOptWalk::len  octets it occupies, its kind and length octets included
 * @var IdemIpTcpOptWalk::bad  a length below two, or one running past the region, ended the walk
 */
typedef struct
{
    const uint8_t *opts;
    size_t end;
    size_t pos;
    const uint8_t *opt;
    uint8_t kind;
    uint8_t len;
    idemip_bool bad;
} IdemIpTcpOptWalk;

/** @brief Aim a walk at the options of the header at @p h. */
IDEMIP_INLINE void idemip_tcp_opt_walk(IdemIpTcpOptWalk *w, const uint8_t *h)
{
    w->opts = idemip_tcp_opts(h);
    w->end = idemip_tcp_opts_len(h);
    w->pos = 0u;
    w->opt = NULL;
    w->kind = (uint8_t)IDEMIP_TCP_OPT_END;
    w->len = 0u;
    w->bad = IDEMIP_FALSE;
}

/**
 * @brief Step to the next option, reporting whether one was there.
 *
 * Kind 0 and kind 1 are one octet and carry no length. Kind 0 ends the list: RFC 9293 sec 3.2
 * "This option code indicates the end of the option list", and sec 3.1 MUST-69 makes the rest of
 * the region padding, so the walk stops on it after reporting it. Every other kind is stepped by
 * its own length octet, which is what lets an unimplemented option be ignored per MUST-6.
 *
 * A length below two, or one reaching past the options, is the illegal length of MUST-7: the walk
 * sets @ref IdemIpTcpOptWalk::bad and ends rather than reading outside the region.
 */
IDEMIP_INLINE idemip_bool idemip_tcp_opt_next(IdemIpTcpOptWalk *w)
{
    w->opt = NULL;
    w->len = 0u;
    if (w->pos >= w->end)
    {
        return IDEMIP_FALSE;
    }
    const uint8_t *o = w->opts + w->pos;
    uint8_t kind = o[IDEMIP_TCP_OPT_OFF_KIND];
    size_t left = w->end - w->pos;
    size_t len = 1u;
    if (kind != IDEMIP_TCP_OPT_END && kind != IDEMIP_TCP_OPT_NOP)
    {
        if (left < IDEMIP_TCP_OPT_LEN_MIN)
        {
            w->bad = IDEMIP_TRUE;
            w->pos = w->end;
            return IDEMIP_FALSE;
        }
        len = (size_t)o[IDEMIP_TCP_OPT_OFF_LEN];
        if (len < IDEMIP_TCP_OPT_LEN_MIN || len > left)
        {
            w->bad = IDEMIP_TRUE;
            w->pos = w->end;
            return IDEMIP_FALSE;
        }
    }
    w->opt = o;
    w->kind = kind;
    w->len = (uint8_t)len;
    w->pos = (kind == IDEMIP_TCP_OPT_END) ? w->end : (w->pos + len);
    return IDEMIP_TRUE;
}

// ---------------------------------------------------------------------------
// Option data
// ---------------------------------------------------------------------------
// Each reads the option the walk landed on. An option begins on any octet boundary (RFC 9293
// sec 3.1), so every multi-octet field is assembled from its bytes.

/** @brief Maximum Segment Size, the 2-byte value of kind 2 (RFC 9293 sec 3.2). */
IDEMIP_INLINE uint16_t idemip_tcp_opt_mss(const uint8_t *o)
{
    return idemip_rd16(o + IDEMIP_TCP_OPT_OFF_DATA);
}

/**
 * @brief shift.cnt of kind 3, clamped to fourteen.
 *
 * RFC 7323 sec 2.3: "If a Window Scale option is received with a shift.cnt value larger than 14,
 * the TCP SHOULD log the error but MUST use 14 instead of the specified value."
 */
IDEMIP_INLINE uint8_t idemip_tcp_opt_ws(const uint8_t *o)
{
    uint8_t shift = o[IDEMIP_TCP_OPT_OFF_WS_SHIFT];
    return (shift > IDEMIP_TCP_WS_MAX) ? (uint8_t)IDEMIP_TCP_WS_MAX : shift;
}

/** @brief TSval, the first four-byte field of kind 8 (RFC 7323 sec 3.2). */
IDEMIP_INLINE uint32_t idemip_tcp_opt_tsval(const uint8_t *o)
{
    return idemip_rd32(o + IDEMIP_TCP_OPT_OFF_TSVAL);
}

/** @brief TSecr, the second; valid only when the header's ACK bit is set (RFC 7323 sec 3.2). */
IDEMIP_INLINE uint32_t idemip_tcp_opt_tsecr(const uint8_t *o)
{
    return idemip_rd32(o + IDEMIP_TCP_OPT_OFF_TSECR);
}

/** @brief Blocks kind 5 carries: its length less the two header octets, in eights. */
IDEMIP_INLINE uint8_t idemip_tcp_opt_sack_blocks(const uint8_t *o)
{
    uint8_t len = o[IDEMIP_TCP_OPT_OFF_LEN];
    if (len < IDEMIP_TCP_OPT_LEN_MIN)
    {
        return 0u;
    }
    return (uint8_t)((size_t)(len - IDEMIP_TCP_OPT_LEN_MIN) >> IDEMIP_TCP_SACK_BLOCK_SHIFT);
}

/** @brief Left Edge of block @p i: "the first sequence number of this block" (RFC 2018 sec 3). */
IDEMIP_INLINE uint32_t idemip_tcp_opt_sack_left(const uint8_t *o, uint8_t i)
{
    return idemip_rd32(o + IDEMIP_TCP_OPT_OFF_DATA + ((size_t)i << IDEMIP_TCP_SACK_BLOCK_SHIFT));
}

/**
 * @brief Right Edge of block @p i: "the sequence number immediately following the last sequence
 * number of this block" (RFC 2018 sec 3).
 */
IDEMIP_INLINE uint32_t idemip_tcp_opt_sack_right(const uint8_t *o, uint8_t i)
{
    return idemip_rd32(o + IDEMIP_TCP_OPT_OFF_DATA + ((size_t)i << IDEMIP_TCP_SACK_BLOCK_SHIFT) + 4u);
}

// ---------------------------------------------------------------------------
// Option build
// ---------------------------------------------------------------------------
// Each writes one option into the caller's bytes at @p o and returns the octets it wrote, so a
// list is built by advancing @p o by each return. The caller sizes the region and sets Data Offset.

/** @brief End of Option List, one octet of kind 0 (RFC 9293 sec 3.2). */
IDEMIP_INLINE size_t idemip_tcp_opt_put_end(uint8_t *o)
{
    o[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_END;
    return 1u;
}

/**
 * @brief No-Operation, one octet of kind 1.
 *
 * RFC 9293 sec 3.2: "This option code can be used between options, for example, to align the
 * beginning of a subsequent option on a word boundary."
 */
IDEMIP_INLINE size_t idemip_tcp_opt_put_nop(uint8_t *o)
{
    o[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_NOP;
    return 1u;
}

/**
 * @brief Maximum Segment Size: kind 2, length 4, and @p mss.
 *
 * RFC 9293 sec 3.2 MUST-65: it "may be sent in the initial connection request (i.e., in segments
 * with the SYN control bit set) and MUST NOT be sent in other segments".
 */
IDEMIP_INLINE size_t idemip_tcp_opt_put_mss(uint8_t *o, uint16_t mss)
{
    o[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_MSS;
    o[IDEMIP_TCP_OPT_OFF_LEN] = (uint8_t)IDEMIP_TCP_OPT_MSS_LEN;
    idemip_wr16(o + IDEMIP_TCP_OPT_OFF_DATA, mss);
    return IDEMIP_TCP_OPT_MSS_LEN;
}

/**
 * @brief Window Scale: kind 3, length 3, and @p shift clamped to fourteen.
 *
 * RFC 7323 sec 2.2: "The three-byte Window Scale option MAY be sent in a <SYN> segment", and the
 * shift count "MUST be limited to 14" (sec 2.3).
 */
IDEMIP_INLINE size_t idemip_tcp_opt_put_ws(uint8_t *o, uint8_t shift)
{
    o[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_WS;
    o[IDEMIP_TCP_OPT_OFF_LEN] = (uint8_t)IDEMIP_TCP_OPT_WS_LEN;
    o[IDEMIP_TCP_OPT_OFF_WS_SHIFT] = (shift > IDEMIP_TCP_WS_MAX) ? (uint8_t)IDEMIP_TCP_WS_MAX : shift;
    return IDEMIP_TCP_OPT_WS_LEN;
}

/**
 * @brief Timestamps: kind 8, length 10, TSval then TSecr.
 *
 * RFC 7323 sec 3.2: "If the ACK bit is not set in the outgoing TCP header, the sender of that
 * segment SHOULD set the TSecr field to zero."
 */
IDEMIP_INLINE size_t idemip_tcp_opt_put_ts(uint8_t *o, uint32_t tsval, uint32_t tsecr)
{
    o[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_TS;
    o[IDEMIP_TCP_OPT_OFF_LEN] = (uint8_t)IDEMIP_TCP_OPT_TS_LEN;
    idemip_wr32(o + IDEMIP_TCP_OPT_OFF_TSVAL, tsval);
    idemip_wr32(o + IDEMIP_TCP_OPT_OFF_TSECR, tsecr);
    return IDEMIP_TCP_OPT_TS_LEN;
}

/**
 * @brief SACK-Permitted: kind 4, length 2, no data.
 *
 * RFC 2018 sec 2: "This two-byte option may be sent in a SYN by a TCP that has been extended to
 * receive (and presumably process) the SACK option once the connection has opened. It MUST NOT be
 * sent on non-SYN segments."
 */
IDEMIP_INLINE size_t idemip_tcp_opt_put_sack_perm(uint8_t *o)
{
    o[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_SACK_PERM;
    o[IDEMIP_TCP_OPT_OFF_LEN] = (uint8_t)IDEMIP_TCP_OPT_SACK_PERM_LEN;
    return IDEMIP_TCP_OPT_SACK_PERM_LEN;
}

/**
 * @brief Accumulate the pseudo-header the checksum covers.
 *
 * The same shape as UDP's: the two addresses, a zero octet, the protocol, and the length of the
 * TCP segment - header and data, which is not a field of the header and so is passed in.
 */
IDEMIP_INLINE uint32_t idemip_tcp_pseudo_accum(uint32_t sum, uint32_t src, uint32_t dst, uint16_t seg_len)
{
    sum += (src >> 16) & 0xFFFFu;
    sum += src & 0xFFFFu;
    sum += (dst >> 16) & 0xFFFFu;
    sum += dst & 0xFFFFu;
    sum += (uint32_t)IDEMIP_IP4_PROTO_TCP; // the zero octet leaves the protocol as the low half
    sum += (uint32_t)seg_len;
    return sum;
}

/**
 * @brief The checksum to write, over the pseudo-header and @p len bytes of segment at @p h.
 *
 * The caller zeroes the checksum field first. Unlike UDP there is no "no checksum" encoding: a
 * result of zero is written as zero.
 */
IDEMIP_INLINE uint16_t idemip_tcp_cksum_compute(const uint8_t *h, size_t len, uint32_t src, uint32_t dst)
{
    uint32_t sum = idemip_tcp_pseudo_accum(0u, src, dst, (uint16_t)len);
    return idemip_cksum_final(idemip_cksum_accum(sum, h, len));
}

static_assert(IDEMIP_TCP_OFF_OPTIONS == IDEMIP_TCP_HDR_LEN,
              "the RFC 9293 field offsets must sum to the option-free header length");
static_assert(IDEMIP_TCP_HDR_BYTES(IDEMIP_TCP_DOFF_MIN) == IDEMIP_TCP_HDR_LEN,
              "the minimum Data Offset of 5 words is the option-free header (RFC 9293 sec 3.1)");
static_assert((1u << IDEMIP_TCP_WORD_SHIFT) == 4u,
              "Data Offset counts 32-bit words, so words to octets is a shift by two (RFC 9293 sec 3.1)");
static_assert(IDEMIP_TCP_DOFF_FROM_BYTES(IDEMIP_TCP_HDR_LEN) == IDEMIP_TCP_DOFF_MIN,
              "the option-free header is a Data Offset of five words (RFC 9293 sec 3.1)");
static_assert(IDEMIP_TCP_OPTS_MAX == 40u,
              "the largest Data Offset leaves ten words of options, RFC 2018 sec 3's \"40 bytes available\"");
static_assert((IDEMIP_TCP_CWR | IDEMIP_TCP_ECE | IDEMIP_TCP_URG | IDEMIP_TCP_ACK | IDEMIP_TCP_PSH | IDEMIP_TCP_RST |
               IDEMIP_TCP_SYN | IDEMIP_TCP_FIN) == 0xFFu,
              "the eight assigned control bits fill the low octet of the word at offset 12 (RFC 9293 sec 3.1 Fig 1)");
static_assert((((uint32_t)IDEMIP_TCP_DOFF_MASK << IDEMIP_TCP_DOFF_SHIFT) | IDEMIP_TCP_RSRVD_MASK | 0xFFu) == 0xFFFFu,
              "Data Offset, Reserved and the control bits fill the 16-bit word at offset 12 (RFC 9293 sec 3.1)");
static_assert((IDEMIP_TCP_RSRVD_MASK & 0xFFu) == 0u,
              "Reserved sits above the control bits and never overlaps one (RFC 9293 sec 3.1)");
static_assert(IDEMIP_TCP_OPT_OFF_DATA + 2u == IDEMIP_TCP_OPT_MSS_LEN,
              "kind 2 is two header octets and a 16-bit value (RFC 9293 sec 3.2)");
static_assert(IDEMIP_TCP_OPT_OFF_WS_SHIFT + 1u == IDEMIP_TCP_OPT_WS_LEN,
              "kind 3 is two header octets and shift.cnt (RFC 7323 sec 2.2)");
static_assert(IDEMIP_TCP_OPT_OFF_TSECR + 4u == IDEMIP_TCP_OPT_TS_LEN,
              "kind 8 is two header octets and two four-byte timestamps (RFC 7323 sec 3.2)");
static_assert(((uint32_t)1u << (IDEMIP_TCP_WS_MAX + 16u)) == 0x40000000u,
              "RFC 7323 sec 2.2 caps the scale exponent at 14 for a 1 GiB receive window, 2^(14+16)");
static_assert((1u << IDEMIP_TCP_SACK_BLOCK_SHIFT) == IDEMIP_TCP_SACK_BLOCK_LEN,
              "a SACK block is two 32-bit edges, so a block index is a shift by three (RFC 2018 sec 3)");
static_assert(IDEMIP_TCP_SACK_BYTES(IDEMIP_TCP_SACK_BLOCKS_MAX) <= IDEMIP_TCP_OPTS_MAX,
              "four SACK blocks fit the options, at 8*n+2 bytes (RFC 2018 sec 3)");
static_assert(IDEMIP_TCP_SACK_BYTES(IDEMIP_TCP_SACK_BLOCKS_MAX + 1u) > IDEMIP_TCP_OPTS_MAX,
              "four is the most 40 bytes of options hold, so a fifth block must not fit (RFC 2018 sec 3)");

IDEMIP_END_DECLS

#endif // IDEMIP_TCP_H
