// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp.h
 * @brief The TCP header, RFC 9293 sec 3.1.
 *
 * Read out of the caller's bytes; holds nothing. The field offsets, the control bits and the option
 * kinds are tcp_defines.h, which a .c includes when it genuinely needs the numbers. A caller that
 * wants a field asks for it here.
 *
 * The tables are the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_TCP_H
#define IDEMIP_TCP_H

#include "src/checksum.h"
#include "src/common.h"

#if IDEMIP_ENABLE_TCP

IDEMIP_BEGIN_DECLS

/**
 * @brief Where a walk stands in one segment's options.
 *
 * The walk holds its position in the caller's own object; it borrows the segment and copies no byte
 * of it.
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

/**
 * @brief Reading a field out of the header.
 *
 * Sequence and acknowledgment sit at 4 and 8 of a header that starts 20 bytes into an IPv4 datagram
 * that itself starts 14 into a frame, so 32-bit fields land on a two-byte boundary and every
 * multi-octet field is assembled from its bytes.
 */
typedef struct
{
    uint16_t (*src_port)(const uint8_t *h);
    uint16_t (*dst_port)(const uint8_t *h);
    uint32_t (*seq)(const uint8_t *h);
    uint32_t (*ack)(const uint8_t *h);
    uint8_t (*doff)(const uint8_t *h);
    uint8_t (*flags)(const uint8_t *h);
    uint16_t (*window)(const uint8_t *h);
    uint16_t (*cksum)(const uint8_t *h);
    uint16_t (*urgent)(const uint8_t *h);
    size_t (*hdr_len)(const uint8_t *h);
    const uint8_t *(*opts)(const uint8_t *h);
    size_t (*opts_len)(const uint8_t *h);
} TcpReadNs;
IDEMIP_NS_LAYOUT(TcpReadNs, src_port, dst_port, seq, ack, doff, flags, window, cksum, urgent, hdr_len, opts,
                 opts_len);

/**
 * @brief The option walk, RFC 9293 sec 3.1: "There are two cases for the format of an option".
 *
 * Case 1 is a single octet of option-kind, which MUST-68 confines to kinds 0 and 1. Case 2 is a
 * kind octet, a length octet counting both of them, and the data.
 */
typedef struct
{
    void (*start)(IdemIpTcpOptWalk *w, const uint8_t *h);
    idemip_bool (*next)(IdemIpTcpOptWalk *w);
} TcpWalkNs;
IDEMIP_NS_LAYOUT(TcpWalkNs, start, next);

/**
 * @brief Reading the option a walk landed on.
 *
 * An option begins on any octet boundary (RFC 9293 sec 3.1), so every multi-octet field is
 * assembled from its bytes.
 */
typedef struct
{
    uint16_t (*mss)(const uint8_t *o);
    uint8_t (*ws)(const uint8_t *o);
    uint32_t (*tsval)(const uint8_t *o);
    uint32_t (*tsecr)(const uint8_t *o);
    uint8_t (*sack_blocks)(const uint8_t *o);
    uint32_t (*sack_left)(const uint8_t *o, uint8_t i);
    uint32_t (*sack_right)(const uint8_t *o, uint8_t i);
} TcpOptNs;
IDEMIP_NS_LAYOUT(TcpOptNs, mss, ws, tsval, tsecr, sack_blocks, sack_left, sack_right);

/**
 * @brief Writing one option into the caller's bytes.
 *
 * Each returns the octets it wrote, so a list is built by advancing the pointer by each return. The
 * caller sizes the region and sets Data Offset.
 */
typedef struct
{
    size_t (*end)(uint8_t *o);
    size_t (*nop)(uint8_t *o);
    size_t (*mss)(uint8_t *o, uint16_t mss);
    size_t (*ws)(uint8_t *o, uint8_t shift);
    size_t (*ts)(uint8_t *o, uint32_t tsval, uint32_t tsecr);
    size_t (*sack_perm)(uint8_t *o);
} TcpOptPutNs;
IDEMIP_NS_LAYOUT(TcpOptPutNs, end, nop, mss, ws, ts, sack_perm);

/** @brief The checksum, over the pseudo-header and the segment. */
typedef struct
{
    uint32_t (*pseudo_accum)(uint32_t sum, uint32_t src, uint32_t dst, uint16_t seg_len);
    uint16_t (*compute)(const uint8_t *h, size_t len, uint32_t src, uint32_t dst);
} TcpCksumNs;
IDEMIP_NS_LAYOUT(TcpCksumNs, pseudo_accum, compute);

/** @name The entries the tables point at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The tables are
 *         still the whole surface: call through them.
 *  @{ */
uint16_t idemip_tcp_src_port(const uint8_t *h);
uint16_t idemip_tcp_dst_port(const uint8_t *h);
uint32_t idemip_tcp_seq(const uint8_t *h);
uint32_t idemip_tcp_ack(const uint8_t *h);
uint8_t idemip_tcp_doff(const uint8_t *h);
uint8_t idemip_tcp_flags(const uint8_t *h);
uint16_t idemip_tcp_window(const uint8_t *h);
uint16_t idemip_tcp_cksum(const uint8_t *h);
uint16_t idemip_tcp_urgent(const uint8_t *h);
size_t idemip_tcp_hdr_len(const uint8_t *h);
const uint8_t *idemip_tcp_opts(const uint8_t *h);
size_t idemip_tcp_opts_len(const uint8_t *h);

void idemip_tcp_opt_walk(IdemIpTcpOptWalk *w, const uint8_t *h);
idemip_bool idemip_tcp_opt_next(IdemIpTcpOptWalk *w);

uint16_t idemip_tcp_opt_mss(const uint8_t *o);
uint8_t idemip_tcp_opt_ws(const uint8_t *o);
uint32_t idemip_tcp_opt_tsval(const uint8_t *o);
uint32_t idemip_tcp_opt_tsecr(const uint8_t *o);
uint8_t idemip_tcp_opt_sack_blocks(const uint8_t *o);
uint32_t idemip_tcp_opt_sack_left(const uint8_t *o, uint8_t i);
uint32_t idemip_tcp_opt_sack_right(const uint8_t *o, uint8_t i);

size_t idemip_tcp_opt_put_end(uint8_t *o);
size_t idemip_tcp_opt_put_nop(uint8_t *o);
size_t idemip_tcp_opt_put_mss(uint8_t *o, uint16_t mss);
size_t idemip_tcp_opt_put_ws(uint8_t *o, uint8_t shift);
size_t idemip_tcp_opt_put_ts(uint8_t *o, uint32_t tsval, uint32_t tsecr);
size_t idemip_tcp_opt_put_sack_perm(uint8_t *o);

uint32_t idemip_tcp_pseudo_accum(uint32_t sum, uint32_t src, uint32_t dst, uint16_t seg_len);
uint16_t idemip_tcp_cksum_compute(const uint8_t *h, size_t len, uint32_t src, uint32_t dst);
/** @} */

/**
 * @brief The module namespaces.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS TcpReadNs tcp_read IDEMIP_UNUSED = {
    .src_port = idemip_tcp_src_port,
    .dst_port = idemip_tcp_dst_port,
    .seq = idemip_tcp_seq,
    .ack = idemip_tcp_ack,
    .doff = idemip_tcp_doff,
    .flags = idemip_tcp_flags,
    .window = idemip_tcp_window,
    .cksum = idemip_tcp_cksum,
    .urgent = idemip_tcp_urgent,
    .hdr_len = idemip_tcp_hdr_len,
    .opts = idemip_tcp_opts,
    .opts_len = idemip_tcp_opts_len,
};

IDEMIP_NS TcpWalkNs tcp_walk IDEMIP_UNUSED = {
    .start = idemip_tcp_opt_walk,
    .next = idemip_tcp_opt_next,
};

IDEMIP_NS TcpOptNs tcp_opt IDEMIP_UNUSED = {
    .mss = idemip_tcp_opt_mss,
    .ws = idemip_tcp_opt_ws,
    .tsval = idemip_tcp_opt_tsval,
    .tsecr = idemip_tcp_opt_tsecr,
    .sack_blocks = idemip_tcp_opt_sack_blocks,
    .sack_left = idemip_tcp_opt_sack_left,
    .sack_right = idemip_tcp_opt_sack_right,
};

IDEMIP_NS TcpOptPutNs tcp_opt_put IDEMIP_UNUSED = {
    .end = idemip_tcp_opt_put_end,
    .nop = idemip_tcp_opt_put_nop,
    .mss = idemip_tcp_opt_put_mss,
    .ws = idemip_tcp_opt_put_ws,
    .ts = idemip_tcp_opt_put_ts,
    .sack_perm = idemip_tcp_opt_put_sack_perm,
};

IDEMIP_NS TcpCksumNs tcp_cksum IDEMIP_UNUSED = {
    .pseudo_accum = idemip_tcp_pseudo_accum,
    .compute = idemip_tcp_cksum_compute,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TCP

#endif // IDEMIP_TCP_H
