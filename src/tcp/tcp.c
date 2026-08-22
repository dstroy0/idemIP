// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp.c
 * @brief The TCP header, RFC 9293 sec 3.1, read out of the caller's bytes and written into them.
 *
 * Every entry below takes one parameter, a pointer to TcpCtx. A header or option access is the
 * octets and, when it writes, what goes into them, so those are one context.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/tcp/tcp.h"
#include "src/tcp/tcp_defines.h" // the RFC 9293 field map, which this file is the first user of

#if IDEMIP_ENABLE_TCP

IDEMIP_BEGIN_DECLS

/** @brief One header or option access. */
typedef struct
{
    const uint8_t *h;      /**< The header or option a read walks. */
    uint8_t *w;            /**< The option region a build writes into. */
    IdemIpTcpOptWalk *walk; /**< The caller's walk position. */
    size_t len;            /**< Octets the sum spans. */
    uint32_t sum;          /**< A running checksum. */
    uint32_t src;          /**< Source address, for the pseudo-header. */
    uint32_t dst;          /**< Destination address, the same. */
    uint32_t tsval;        /**< RFC 7323 TS Value a build writes. */
    uint32_t tsecr;        /**< RFC 7323 TS Echo Reply a build writes. */
    uint16_t seg_len;      /**< Segment length the pseudo-header carries. */
    uint16_t mss;          /**< Maximum Segment Size a build writes. */
    uint8_t shift;         /**< Window Scale shift.cnt a build writes. */
    uint8_t index;         /**< Which SACK block a read asks for. */
} TcpCtx;

// --- reading a field -------------------------------------------------------

/** @brief Source Port. */
IDEMIP_INLINE uint16_t tcp_src_port(const TcpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_TCP_OFF_SRC_PORT);
}

/** @brief Destination Port. */
IDEMIP_INLINE uint16_t tcp_dst_port(const TcpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_TCP_OFF_DST_PORT);
}

/** @brief Sequence Number. */
IDEMIP_INLINE uint32_t tcp_seq(const TcpCtx *c)
{
    return idemip_rd32(c->h + IDEMIP_TCP_OFF_SEQ);
}

/** @brief Acknowledgment Number; significant only when ACK is set. */
IDEMIP_INLINE uint32_t tcp_ack(const TcpCtx *c)
{
    return idemip_rd32(c->h + IDEMIP_TCP_OFF_ACK);
}

/** @brief Data Offset, in 32-bit words. */
IDEMIP_INLINE uint8_t tcp_doff(const TcpCtx *c)
{
    return (uint8_t)((idemip_rd16(c->h + IDEMIP_TCP_OFF_OFFS_FLAGS) >> IDEMIP_TCP_DOFF_SHIFT) & IDEMIP_TCP_DOFF_MASK);
}

/** @brief The eight control bits, as the low octet of the offset/flags word. */
IDEMIP_INLINE uint8_t tcp_flags(const TcpCtx *c)
{
    return (uint8_t)(idemip_rd16(c->h + IDEMIP_TCP_OFF_OFFS_FLAGS) & 0xFFu);
}

/** @brief Window: octets this sender is willing to accept. */
IDEMIP_INLINE uint16_t tcp_window(const TcpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_TCP_OFF_WINDOW);
}

/** @brief Checksum as carried. */
IDEMIP_INLINE uint16_t tcp_cksum_field(const TcpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_TCP_OFF_CKSUM);
}

/** @brief Urgent Pointer; significant only when URG is set. */
IDEMIP_INLINE uint16_t tcp_urgent(const TcpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_TCP_OFF_URGENT);
}

/** @brief Header octets, options included, from the Data Offset. */
IDEMIP_INLINE size_t tcp_hdr_len(const TcpCtx *c)
{
    return IDEMIP_TCP_HDR_BYTES(tcp_doff(c));
}

/** @brief The options region, where the fixed fields end. */
IDEMIP_INLINE const uint8_t *tcp_opts(const TcpCtx *c)
{
    return c->h + IDEMIP_TCP_OFF_OPTIONS;
}

/**
 * @brief Octets the Data Offset gives the options.
 *
 * RFC 9293 sec 3.1: "size(Options) == (DOffset-5)*32; present only when DOffset > 5", padding
 * included. A Data Offset below the five-word minimum names no options at all.
 */
IDEMIP_INLINE size_t tcp_opts_len(const TcpCtx *c)
{
    uint8_t doff = tcp_doff(c);
    if (doff <= IDEMIP_TCP_DOFF_MIN)
    {
        return 0u;
    }
    return (size_t)(doff - IDEMIP_TCP_DOFF_MIN) << IDEMIP_TCP_WORD_SHIFT;
}

// --- the option walk -------------------------------------------------------

/** @brief Aim a walk at the options of the header. */
IDEMIP_INLINE void tcp_opt_walk(const TcpCtx *c)
{
    IdemIpTcpOptWalk *w = c->walk;
    w->opts = idemip_tcp_opts(c->h);
    w->end = idemip_tcp_opts_len(c->h);
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
 * sets bad and ends rather than reading outside the region.
 */
IDEMIP_INLINE idemip_bool tcp_opt_next(const TcpCtx *c)
{
    IdemIpTcpOptWalk *w = c->walk;
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

// --- reading option data ---------------------------------------------------

/** @brief Maximum Segment Size, the 2-byte value of kind 2 (RFC 9293 sec 3.2). */
IDEMIP_INLINE uint16_t tcp_opt_mss(const TcpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_TCP_OPT_OFF_DATA);
}

/**
 * @brief shift.cnt of kind 3, clamped to fourteen.
 *
 * RFC 7323 sec 2.3: "If a Window Scale option is received with a shift.cnt value larger than 14,
 * the TCP SHOULD log the error but MUST use 14 instead of the specified value."
 */
IDEMIP_INLINE uint8_t tcp_opt_ws(const TcpCtx *c)
{
    uint8_t shift = c->h[IDEMIP_TCP_OPT_OFF_WS_SHIFT];
    return (shift > IDEMIP_TCP_WS_MAX) ? (uint8_t)IDEMIP_TCP_WS_MAX : shift;
}

/** @brief TSval, the first four-byte field of kind 8 (RFC 7323 sec 3.2). */
IDEMIP_INLINE uint32_t tcp_opt_tsval(const TcpCtx *c)
{
    return idemip_rd32(c->h + IDEMIP_TCP_OPT_OFF_TSVAL);
}

/** @brief TSecr, the second; valid only when the header's ACK bit is set (RFC 7323 sec 3.2). */
IDEMIP_INLINE uint32_t tcp_opt_tsecr(const TcpCtx *c)
{
    return idemip_rd32(c->h + IDEMIP_TCP_OPT_OFF_TSECR);
}

/** @brief Blocks kind 5 carries: its length less the two header octets, in eights. */
IDEMIP_INLINE uint8_t tcp_opt_sack_blocks(const TcpCtx *c)
{
    uint8_t len = c->h[IDEMIP_TCP_OPT_OFF_LEN];
    if (len < IDEMIP_TCP_OPT_LEN_MIN)
    {
        return 0u;
    }
    return (uint8_t)((size_t)(len - IDEMIP_TCP_OPT_LEN_MIN) >> IDEMIP_TCP_SACK_BLOCK_SHIFT);
}

/** @brief Left Edge of the named block: "the first sequence number of this block" (RFC 2018 sec 3). */
IDEMIP_INLINE uint32_t tcp_opt_sack_left(const TcpCtx *c)
{
    return idemip_rd32(c->h + IDEMIP_TCP_OPT_OFF_DATA + ((size_t)c->index << IDEMIP_TCP_SACK_BLOCK_SHIFT));
}

/**
 * @brief Right Edge of the named block: "the sequence number immediately following the last sequence
 * number of this block" (RFC 2018 sec 3).
 */
IDEMIP_INLINE uint32_t tcp_opt_sack_right(const TcpCtx *c)
{
    return idemip_rd32(c->h + IDEMIP_TCP_OPT_OFF_DATA + ((size_t)c->index << IDEMIP_TCP_SACK_BLOCK_SHIFT) + 4u);
}

// --- writing an option -----------------------------------------------------

/** @brief End of Option List, one octet of kind 0 (RFC 9293 sec 3.2). */
IDEMIP_INLINE size_t tcp_put_end(const TcpCtx *c)
{
    c->w[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_END;
    return 1u;
}

/**
 * @brief No-Operation, one octet of kind 1.
 *
 * RFC 9293 sec 3.2: "This option code can be used between options, for example, to align the
 * beginning of a subsequent option on a word boundary."
 */
IDEMIP_INLINE size_t tcp_put_nop(const TcpCtx *c)
{
    c->w[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_NOP;
    return 1u;
}

/**
 * @brief Maximum Segment Size: kind 2, length 4, and the value.
 *
 * RFC 9293 sec 3.2 MUST-65: it "may be sent in the initial connection request (i.e., in segments
 * with the SYN control bit set) and MUST NOT be sent in other segments".
 */
IDEMIP_INLINE size_t tcp_put_mss(const TcpCtx *c)
{
    c->w[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_MSS;
    c->w[IDEMIP_TCP_OPT_OFF_LEN] = (uint8_t)IDEMIP_TCP_OPT_MSS_LEN;
    idemip_wr16(c->w + IDEMIP_TCP_OPT_OFF_DATA, c->mss);
    return IDEMIP_TCP_OPT_MSS_LEN;
}

/**
 * @brief Window Scale: kind 3, length 3, and the shift clamped to fourteen.
 *
 * RFC 7323 sec 2.2: "The three-byte Window Scale option MAY be sent in a <SYN> segment", and the
 * shift count "MUST be limited to 14" (sec 2.3).
 */
IDEMIP_INLINE size_t tcp_put_ws(const TcpCtx *c)
{
    c->w[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_WS;
    c->w[IDEMIP_TCP_OPT_OFF_LEN] = (uint8_t)IDEMIP_TCP_OPT_WS_LEN;
    c->w[IDEMIP_TCP_OPT_OFF_WS_SHIFT] = (c->shift > IDEMIP_TCP_WS_MAX) ? (uint8_t)IDEMIP_TCP_WS_MAX : c->shift;
    return IDEMIP_TCP_OPT_WS_LEN;
}

/**
 * @brief Timestamps: kind 8, length 10, TSval then TSecr.
 *
 * RFC 7323 sec 3.2: "If the ACK bit is not set in the outgoing TCP header, the sender of that
 * segment SHOULD set the TSecr field to zero."
 */
IDEMIP_INLINE size_t tcp_put_ts(const TcpCtx *c)
{
    c->w[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_TS;
    c->w[IDEMIP_TCP_OPT_OFF_LEN] = (uint8_t)IDEMIP_TCP_OPT_TS_LEN;
    idemip_wr32(c->w + IDEMIP_TCP_OPT_OFF_TSVAL, c->tsval);
    idemip_wr32(c->w + IDEMIP_TCP_OPT_OFF_TSECR, c->tsecr);
    return IDEMIP_TCP_OPT_TS_LEN;
}

/**
 * @brief SACK-Permitted: kind 4, length 2, no data.
 *
 * RFC 2018 sec 2: "This two-byte option may be sent in a SYN by a TCP that has been extended to
 * receive (and presumably process) the SACK option once the connection has opened. It MUST NOT be
 * sent on non-SYN segments."
 */
IDEMIP_INLINE size_t tcp_put_sack_perm(const TcpCtx *c)
{
    c->w[IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_SACK_PERM;
    c->w[IDEMIP_TCP_OPT_OFF_LEN] = (uint8_t)IDEMIP_TCP_OPT_SACK_PERM_LEN;
    return IDEMIP_TCP_OPT_SACK_PERM_LEN;
}

// --- the checksum ----------------------------------------------------------

/**
 * @brief Accumulate the pseudo-header the checksum covers.
 *
 * The same shape as UDP's: the two addresses, a zero octet, the protocol, and the length of the
 * TCP segment - header and data, which is not a field of the header and so is passed in.
 */
IDEMIP_INLINE uint32_t tcp_pseudo_accum(const TcpCtx *c)
{
    uint32_t sum = c->sum;
    sum += (c->src >> 16) & 0xFFFFu;
    sum += c->src & 0xFFFFu;
    sum += (c->dst >> 16) & 0xFFFFu;
    sum += c->dst & 0xFFFFu;
    sum += (uint32_t)IDEMIP_TCP_PROTO; // the zero octet leaves the protocol as the low half
    sum += (uint32_t)c->seg_len;
    return sum;
}

/**
 * @brief The checksum to write, over the pseudo-header and the segment.
 *
 * The caller zeroes the checksum field first. Unlike UDP there is no "no checksum" encoding: a
 * result of zero is written as zero.
 */
IDEMIP_INLINE uint16_t tcp_cksum_compute(const TcpCtx *c)
{
    uint32_t sum = idemip_tcp_pseudo_accum(0u, c->src, c->dst, (uint16_t)c->len);
    return idemip_cksum_final(idemip_cksum_accum(sum, c->h, c->len));
}

/* The namespaces are tables of function pointers with the caller's argument lists in their types,
   so these are what they point at. Each builds the context and hands it to the body above. */

uint16_t idemip_tcp_src_port(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_src_port, TcpCtx, .h = h);
}

uint16_t idemip_tcp_dst_port(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_dst_port, TcpCtx, .h = h);
}

uint32_t idemip_tcp_seq(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_seq, TcpCtx, .h = h);
}

uint32_t idemip_tcp_ack(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_ack, TcpCtx, .h = h);
}

uint8_t idemip_tcp_doff(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_doff, TcpCtx, .h = h);
}

uint8_t idemip_tcp_flags(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_flags, TcpCtx, .h = h);
}

uint16_t idemip_tcp_window(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_window, TcpCtx, .h = h);
}

uint16_t idemip_tcp_cksum(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_cksum_field, TcpCtx, .h = h);
}

uint16_t idemip_tcp_urgent(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_urgent, TcpCtx, .h = h);
}

size_t idemip_tcp_hdr_len(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_hdr_len, TcpCtx, .h = h);
}

const uint8_t *idemip_tcp_opts(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_opts, TcpCtx, .h = h);
}

size_t idemip_tcp_opts_len(const uint8_t *h)
{
    return IDEMIP_CALL(tcp_opts_len, TcpCtx, .h = h);
}

void idemip_tcp_opt_walk(IdemIpTcpOptWalk *w, const uint8_t *h)
{
    IDEMIP_CALL(tcp_opt_walk, TcpCtx, .walk = w, .h = h);
}

idemip_bool idemip_tcp_opt_next(IdemIpTcpOptWalk *w)
{
    return IDEMIP_CALL(tcp_opt_next, TcpCtx, .walk = w);
}

uint16_t idemip_tcp_opt_mss(const uint8_t *o)
{
    return IDEMIP_CALL(tcp_opt_mss, TcpCtx, .h = o);
}

uint8_t idemip_tcp_opt_ws(const uint8_t *o)
{
    return IDEMIP_CALL(tcp_opt_ws, TcpCtx, .h = o);
}

uint32_t idemip_tcp_opt_tsval(const uint8_t *o)
{
    return IDEMIP_CALL(tcp_opt_tsval, TcpCtx, .h = o);
}

uint32_t idemip_tcp_opt_tsecr(const uint8_t *o)
{
    return IDEMIP_CALL(tcp_opt_tsecr, TcpCtx, .h = o);
}

uint8_t idemip_tcp_opt_sack_blocks(const uint8_t *o)
{
    return IDEMIP_CALL(tcp_opt_sack_blocks, TcpCtx, .h = o);
}

uint32_t idemip_tcp_opt_sack_left(const uint8_t *o, uint8_t i)
{
    return IDEMIP_CALL(tcp_opt_sack_left, TcpCtx, .h = o, .index = i);
}

uint32_t idemip_tcp_opt_sack_right(const uint8_t *o, uint8_t i)
{
    return IDEMIP_CALL(tcp_opt_sack_right, TcpCtx, .h = o, .index = i);
}

size_t idemip_tcp_opt_put_end(uint8_t *o)
{
    return IDEMIP_CALL(tcp_put_end, TcpCtx, .w = o);
}

size_t idemip_tcp_opt_put_nop(uint8_t *o)
{
    return IDEMIP_CALL(tcp_put_nop, TcpCtx, .w = o);
}

size_t idemip_tcp_opt_put_mss(uint8_t *o, uint16_t mss)
{
    return IDEMIP_CALL(tcp_put_mss, TcpCtx, .w = o, .mss = mss);
}

size_t idemip_tcp_opt_put_ws(uint8_t *o, uint8_t shift)
{
    return IDEMIP_CALL(tcp_put_ws, TcpCtx, .w = o, .shift = shift);
}

size_t idemip_tcp_opt_put_ts(uint8_t *o, uint32_t tsval, uint32_t tsecr)
{
    return IDEMIP_CALL(tcp_put_ts, TcpCtx, .w = o, .tsval = tsval, .tsecr = tsecr);
}

size_t idemip_tcp_opt_put_sack_perm(uint8_t *o)
{
    return IDEMIP_CALL(tcp_put_sack_perm, TcpCtx, .w = o);
}

uint32_t idemip_tcp_pseudo_accum(uint32_t sum, uint32_t src, uint32_t dst, uint16_t seg_len)
{
    return IDEMIP_CALL(tcp_pseudo_accum, TcpCtx, .sum = sum, .src = src, .dst = dst, .seg_len = seg_len);
}

uint16_t idemip_tcp_cksum_compute(const uint8_t *h, size_t len, uint32_t src, uint32_t dst)
{
    return IDEMIP_CALL(tcp_cksum_compute, TcpCtx, .h = h, .len = len, .src = src, .dst = dst);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TCP
