// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file udplite.c
 * @brief The RFC 3828 Checksum Coverage rules and the sum they bound.
 *
 * The operand block and the context are regions of the one pointer each entry is handed, at
 * compile-time offsets, and no entry reads or writes a byte outside it and the datagram the operand
 * block names. Two borrows therefore share nothing, and the same call on the same borrow does the
 * same thing.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/pseudo.h"
#include "src/udp/udplite.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. A borrow that was never cleared carries no mark, so every
// entry refuses it.
typedef struct
{
    uint32_t ready;
} UdpLiteCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_UDPLITE_OFF_CTX, sizeof(UdpLiteCtx), IDEMIP_UDPLITE_BORROW, "udplite's context");

// The mark clear leaves.
#define UDPLITE_READY 0x554C5445u

// The caller's borrow, split: the operand block, then the context. udplite.h publishes the offsets;
// the assert below proves the span covers them before anything runs.
static_assert(IDEMIP_UDPLITE_OFF_CTX + sizeof(UdpLiteCtx) <= IDEMIP_UDPLITE_BORROW,
              "IDEMIP_UDPLITE_BORROW is short of the operand block and the context - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define UDPLITE_CTX(w) ((UdpLiteCtx *)(void *)((w) + IDEMIP_UDPLITE_OFF_CTX))
#define UDPLITE_IO(w) IDEMIP_UDPLITE_IO(w)

// --- the statics -----------------------------------------------------------

// RFC 3828 sec 3.1, the three rules a Coverage is kept under, and the octets it spans.
//
// "The UDP-Lite header MUST always be covered by the checksum", which an IP payload under eight
// octets cannot satisfy at any Coverage. "A Checksum Coverage of zero indicates that the entire
// UDP-Lite packet is covered by the checksum. This means that the value of the Checksum Coverage
// field MUST be either 0 or at least 8. A UDP-Lite packet with a Checksum Coverage value of 1 to 7
// MUST be discarded by the receiver." "UDP-Lite packets with a Checksum Coverage greater than the IP
// length MUST also be discarded."
//
// sec 3.5: the field is 16 bits, so a nonzero Coverage reaches at most 65535 octets and a Jumbogram
// is covered whole only through the zero value.
static IdemIpUdpLiteReason udplite_cov_span(uint16_t cov, uint32_t ip_payload_len, uint32_t *span)
{
    if (ip_payload_len < (uint32_t)IDEMIP_UDPLITE_COV_MIN)
    {
        return IDEMIP_UDPLITE_REASON_SHORT;
    }
    if (cov == (uint16_t)IDEMIP_UDPLITE_COV_ALL)
    {
        *span = ip_payload_len;
        return IDEMIP_UDPLITE_REASON_NONE;
    }
    if (cov < (uint16_t)IDEMIP_UDPLITE_COV_MIN)
    {
        return IDEMIP_UDPLITE_REASON_COV_ILLEGAL;
    }
    if ((uint32_t)cov > ip_payload_len)
    {
        return IDEMIP_UDPLITE_REASON_COV_PAST_LEN;
    }
    *span = (uint32_t)cov;
    return IDEMIP_UDPLITE_REASON_NONE;
}

// The sec 3.2 pseudo-header of one IP version, accumulated into @p sum, which pseudo.h holds for
// every transport.
//
// RFC 3828 sec 3.2: "UDP and UDP-Lite use the same conceptually prefixed pseudo header from the IP
// layer for the checksum. This pseudo header is different for IPv4 and IPv6. The pseudo header of
// UDP-Lite is different from the pseudo header of UDP in one way: The value of the Length field of
// the pseudo header is not taken from the UDP-Lite header, but rather from information provided by
// the IP module." So @p ip_payload_len goes in it, never the Coverage, and the protocol is the 136
// of sec 7 rather than RFC 768's 17.
static idemip_bool udplite_pseudo(uint32_t *sum, const uint8_t *src, const uint8_t *dst, uint32_t ip_payload_len,
                                  uint8_t ip_version)
{
    return idemip_pseudo_accum(sum, ip_version, (uint8_t)IDEMIP_UDPLITE_PROTO, src, dst, ip_payload_len);
}

// The refused state every entry starts from: ERR with nothing reported.
static UdpLiteIo *udplite_refuse(uint8_t *restrict work)
{
    UdpLiteIo *io = UDPLITE_IO(work);
    io->status = IDEMIP_ERR;
    io->reason = IDEMIP_UDPLITE_REASON_ARG;
    io->res.payload = NULL;
    io->res.payload_len = 0u;
    io->res.cov_bytes = 0u;
    io->res.cov = 0u;
    io->res.cksum = 0u;
    io->res.covered = IDEMIP_FALSE;
    return io;
}

// The span, the payload and the Coverage a finished call reports. The payload is the octet after the
// eight-octet header, which RFC 3828 sec 3.4 makes the length delivered depend on the IP payload.
static void udplite_report(UdpLiteIo *io, const uint8_t *dgram, uint16_t cov, uint32_t span, uint32_t ip_payload_len,
                           uint16_t cksum)
{
    io->res.payload = dgram + IDEMIP_UDPLITE_HDR_LEN;
    io->res.payload_len = ip_payload_len - (uint32_t)IDEMIP_UDPLITE_HDR_LEN;
    io->res.cov_bytes = span;
    io->res.cov = cov;
    io->res.cksum = cksum;
    io->res.covered = (span == ip_payload_len) ? IDEMIP_TRUE : IDEMIP_FALSE;
    io->reason = IDEMIP_UDPLITE_REASON_NONE;
    io->status = IDEMIP_OK;
}

// --- the entries -----------------------------------------------------------

void idemip_udplite_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work, 0, (size_t)IDEMIP_UDPLITE_BORROW);
    UDPLITE_CTX(work)->ready = UDPLITE_READY;
    UDPLITE_IO(work)->status = IDEMIP_OK;
    UDPLITE_IO(work)->reason = IDEMIP_UDPLITE_REASON_NONE;
}

// The sec 3.1 rules over the Coverage the datagram carries, and nothing else: no address is read and
// no sum is run.
void idemip_udplite_cover(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpLiteIo *io = udplite_refuse(work);
    if (UDPLITE_CTX(work)->ready != UDPLITE_READY)
    {
        return;
    }
    const UdpLiteCheckArgs *a = &io->check_args;
    if (a->dgram == NULL)
    {
        return;
    }
    if (a->ip_payload_len < (uint32_t)IDEMIP_UDPLITE_COV_MIN)
    {
        io->reason = IDEMIP_UDPLITE_REASON_SHORT;
        return;
    }
    uint16_t cov = idemip_udplite_cov(a->dgram);
    uint32_t span = 0u;
    IdemIpUdpLiteReason r = udplite_cov_span(cov, a->ip_payload_len, &span);
    if (r != IDEMIP_UDPLITE_REASON_NONE)
    {
        io->reason = r;
        io->res.cov = cov;
        return;
    }
    udplite_report(io, a->dgram, cov, span, a->ip_payload_len, idemip_udp_cksum(a->dgram));
}

// The sec 3.1 rules, then the sum: the sec 3.2 pseudo-header first, then the covered octets with the
// Checksum field as it arrived. RFC 1071 sec 1 makes that come out zero when the datagram checks out.
void idemip_udplite_check(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpLiteIo *io = udplite_refuse(work);
    if (UDPLITE_CTX(work)->ready != UDPLITE_READY)
    {
        return;
    }
    const UdpLiteCheckArgs *a = &io->check_args;
    if (a->dgram == NULL || a->src == NULL || a->dst == NULL)
    {
        return;
    }
    uint32_t sum = 0u;
    if (!udplite_pseudo(&sum, a->src, a->dst, a->ip_payload_len, a->ip_version))
    {
        return;
    }
    if (a->ip_payload_len < (uint32_t)IDEMIP_UDPLITE_COV_MIN)
    {
        io->reason = IDEMIP_UDPLITE_REASON_SHORT;
        return;
    }
    uint16_t cov = idemip_udplite_cov(a->dgram);
    uint32_t span = 0u;
    IdemIpUdpLiteReason r = udplite_cov_span(cov, a->ip_payload_len, &span);
    if (r != IDEMIP_UDPLITE_REASON_NONE)
    {
        io->reason = r;
        io->res.cov = cov;
        return;
    }
    uint16_t carried = idemip_udp_cksum(a->dgram);
    if (carried == (uint16_t)IDEMIP_UDP_CKSUM_NONE)
    {
        io->reason = IDEMIP_UDPLITE_REASON_CKSUM_ZERO;
        io->res.cov = cov;
        return;
    }
    if (idemip_cksum_final(idemip_cksum_accum(sum, a->dgram, (size_t)span)) != 0u)
    {
        io->reason = IDEMIP_UDPLITE_REASON_CKSUM_BAD;
        io->res.cov = cov;
        return;
    }
    udplite_report(io, a->dgram, cov, span, a->ip_payload_len, carried);
}

// The eight header octets with the requested Coverage and a cleared Checksum field, then the sum over
// the covered span stored back into that field. RFC 3828 sec 3.1: "Prior to computation, the checksum
// field MUST be set to zero. If the computed checksum is 0, it is transmitted as all ones."
void idemip_udplite_build_io(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpLiteIo *io = udplite_refuse(work);
    if (UDPLITE_CTX(work)->ready != UDPLITE_READY)
    {
        return;
    }
    const UdpLiteBuildArgs *a = &io->build_args;
    if (a->dgram == NULL || a->src == NULL || a->dst == NULL)
    {
        return;
    }
    uint32_t sum = 0u;
    if (!udplite_pseudo(&sum, a->src, a->dst, a->ip_payload_len, a->ip_version))
    {
        return;
    }
    uint32_t span = 0u;
    IdemIpUdpLiteReason r = udplite_cov_span(a->cov, a->ip_payload_len, &span);
    if (r != IDEMIP_UDPLITE_REASON_NONE)
    {
        io->reason = r;
        return;
    }
    idemip_udplite_build(a->dgram, a->src_port, a->dst_port, a->cov);
    uint16_t c = idemip_cksum_final(idemip_cksum_accum(sum, a->dgram, (size_t)span));
    if (c == 0u)
    {
        c = (uint16_t)IDEMIP_UDP_CKSUM_ZERO_AS;
    }
    idemip_udp_set_cksum(a->dgram, c);
    udplite_report(io, a->dgram, a->cov, span, a->ip_payload_len, c);
}

IDEMIP_END_DECLS
