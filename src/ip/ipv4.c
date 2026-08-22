// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ipv4.c
 * @brief The internet header, RFC 791 sec 3.1: read, written, verified.
 *
 * Every entry below takes one parameter, a pointer to Ip4Ctx. A header access is the octets and,
 * when it writes, what goes into them, so those are one context.
 *
 * The source and destination addresses sit at 12 and 16 of a header that itself starts 14 bytes
 * into an Ethernet frame, so neither is aligned for a 32-bit read in the frame it arrived in. Every
 * multi-byte field is therefore assembled from its bytes.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ipv4.h"
#include "src/ip/ipv4_defines.h" // the RFC 791 field map, which this file is the first user of
#include "src/common_defines.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/** @brief One header access. */
typedef struct
{
    const uint8_t *h;          /**< The header a read takes its fields out of. */
    uint8_t *w;                /**< The header a write puts them into. */
    const IdemIpIp4Fields *f;  /**< The fields a build writes. */
    size_t avail;              /**< Readable octets at the header, for the length checks. */
    uint32_t addr;             /**< An address a write sends. */
    uint32_t mask;             /**< A subnet mask the arithmetic reads. */
    uint16_t v16;              /**< A 16-bit field a write sends. */
    uint8_t v8;                /**< An 8-bit field a write sends. */
} Ip4Ctx;

// --- reading a field -------------------------------------------------------

/** @brief Version, the high nibble of the first octet. */
IDEMIP_INLINE uint8_t ip4_version(const Ip4Ctx *c)
{
    return (uint8_t)((c->h[IDEMIP_IP4_OFF_VER_IHL] >> IDEMIP_IP4_VER_SHIFT) & IDEMIP_IP4_VER_MASK);
}

/** @brief IHL in 32-bit words, the low nibble of the first octet. */
IDEMIP_INLINE uint8_t ip4_ihl(const Ip4Ctx *c)
{
    return (uint8_t)(c->h[IDEMIP_IP4_OFF_VER_IHL] & IDEMIP_IP4_IHL_MASK);
}

/** @brief Header octets: the IHL word count shifted up by two. */
IDEMIP_INLINE size_t ip4_hdr_len(const Ip4Ctx *c)
{
    return IDEMIP_IP4_HDR_BYTES(ip4_ihl(c));
}

/** @brief Type of Service, the second octet. */
IDEMIP_INLINE uint8_t ip4_tos(const Ip4Ctx *c)
{
    return c->h[IDEMIP_IP4_OFF_TOS];
}

/** @brief Total Length: the whole datagram, header included. */
IDEMIP_INLINE uint16_t ip4_total_len(const Ip4Ctx *c)
{
    return idemip_rd16(c->h + IDEMIP_IP4_OFF_TOTAL_LEN);
}

/** @brief Identification, the value fragments of one datagram share. */
IDEMIP_INLINE uint16_t ip4_id(const Ip4Ctx *c)
{
    return idemip_rd16(c->h + IDEMIP_IP4_OFF_ID);
}

/** @brief The three flags and the fragment offset, as one field. */
IDEMIP_INLINE uint16_t ip4_flags_frag(const Ip4Ctx *c)
{
    return idemip_rd16(c->h + IDEMIP_IP4_OFF_FLAGS_FRAG);
}

/** @brief Flags bit 0, which RFC 791 sec 3.1 reserves and requires to be zero. */
IDEMIP_INLINE idemip_bool ip4_reserved(const Ip4Ctx *c)
{
    return (idemip_bool)((ip4_flags_frag(c) & IDEMIP_IP4_FLAG_RESERVED) != 0u);
}

/** @brief Flags bit 1: set means this datagram may not be fragmented. */
IDEMIP_INLINE idemip_bool ip4_df(const Ip4Ctx *c)
{
    return (idemip_bool)((ip4_flags_frag(c) & IDEMIP_IP4_FLAG_DF) != 0u);
}

/** @brief Flags bit 2: set means a later fragment follows. */
IDEMIP_INLINE idemip_bool ip4_mf(const Ip4Ctx *c)
{
    return (idemip_bool)((ip4_flags_frag(c) & IDEMIP_IP4_FLAG_MF) != 0u);
}

/** @brief The 13-bit fragment offset field, in units of eight octets. */
IDEMIP_INLINE uint16_t ip4_frag_units(const Ip4Ctx *c)
{
    return (uint16_t)(ip4_flags_frag(c) & IDEMIP_IP4_FRAG_OFF_MASK);
}

/** @brief Fragment offset in bytes: the field counts units of eight octets. */
IDEMIP_INLINE uint32_t ip4_frag_offset_bytes(const Ip4Ctx *c)
{
    return (uint32_t)ip4_frag_units(c) << IDEMIP_IP4_FRAG_SHIFT;
}

/**
 * @brief True when this datagram is a fragment.
 *
 * RFC 791 sec 3.2: "an unfragmented datagram has all zero fragmentation information (MF = 0,
 * fragment offset = 0)", so either one nonzero makes a fragment.
 */
IDEMIP_INLINE idemip_bool ip4_is_fragment(const Ip4Ctx *c)
{
    return (idemip_bool)((ip4_flags_frag(c) & (IDEMIP_IP4_FLAG_MF | IDEMIP_IP4_FRAG_OFF_MASK)) != 0u);
}

/** @brief Time to Live, decremented by every module that forwards the datagram. */
IDEMIP_INLINE uint8_t ip4_ttl(const Ip4Ctx *c)
{
    return c->h[IDEMIP_IP4_OFF_TTL];
}

/** @brief Protocol carried in the data field. */
IDEMIP_INLINE uint8_t ip4_proto(const Ip4Ctx *c)
{
    return c->h[IDEMIP_IP4_OFF_PROTO];
}

/** @brief Header Checksum, as the sender left it. */
IDEMIP_INLINE uint16_t ip4_cksum(const Ip4Ctx *c)
{
    return idemip_rd16(c->h + IDEMIP_IP4_OFF_CKSUM);
}

/** @brief Source address. */
IDEMIP_INLINE uint32_t ip4_src(const Ip4Ctx *c)
{
    return idemip_rd32(c->h + IDEMIP_IP4_OFF_SRC);
}

/** @brief Destination address. */
IDEMIP_INLINE uint32_t ip4_dst(const Ip4Ctx *c)
{
    return idemip_rd32(c->h + IDEMIP_IP4_OFF_DST);
}

/** @brief Data octets: Total Length less the header. Reads a header a verify already accepted. */
IDEMIP_INLINE uint16_t ip4_payload_len(const Ip4Ctx *c)
{
    return (uint16_t)(ip4_total_len(c) - (uint16_t)ip4_hdr_len(c));
}

/** @brief The option area, at offset 20. Empty when IHL is 5. */
IDEMIP_INLINE const uint8_t *ip4_options(const Ip4Ctx *c)
{
    return c->h + IDEMIP_IP4_OFF_OPTIONS;
}

/** @brief Option octets: the header less its twenty fixed ones, padding included. */
IDEMIP_INLINE size_t ip4_options_len(const Ip4Ctx *c)
{
    return ip4_hdr_len(c) - IDEMIP_IPV4_HDR_LEN;
}

// --- writing a field -------------------------------------------------------

/** @brief Version 4 in the high nibble, the given IHL words in the low one. */
IDEMIP_INLINE void ip4_set_ver_ihl(const Ip4Ctx *c)
{
    c->w[IDEMIP_IP4_OFF_VER_IHL] =
        (uint8_t)((IDEMIP_IP4_VERSION << IDEMIP_IP4_VER_SHIFT) | (c->v8 & IDEMIP_IP4_IHL_MASK));
}

/** @brief Type of Service. */
IDEMIP_INLINE void ip4_set_tos(const Ip4Ctx *c)
{
    c->w[IDEMIP_IP4_OFF_TOS] = c->v8;
}

/** @brief Total Length. */
IDEMIP_INLINE void ip4_set_total_len(const Ip4Ctx *c)
{
    idemip_wr16(c->w + IDEMIP_IP4_OFF_TOTAL_LEN, c->v16);
}

/** @brief Identification. */
IDEMIP_INLINE void ip4_set_id(const Ip4Ctx *c)
{
    idemip_wr16(c->w + IDEMIP_IP4_OFF_ID, c->v16);
}

/** @brief The three flags ORed with the 13-bit offset, written as one field. */
IDEMIP_INLINE void ip4_set_flags_frag(const Ip4Ctx *c)
{
    idemip_wr16(c->w + IDEMIP_IP4_OFF_FLAGS_FRAG, c->v16);
}

/** @brief Time to Live. */
IDEMIP_INLINE void ip4_set_ttl(const Ip4Ctx *c)
{
    c->w[IDEMIP_IP4_OFF_TTL] = c->v8;
}

/** @brief Protocol. */
IDEMIP_INLINE void ip4_set_proto(const Ip4Ctx *c)
{
    c->w[IDEMIP_IP4_OFF_PROTO] = c->v8;
}

/** @brief Header Checksum. */
IDEMIP_INLINE void ip4_set_cksum(const Ip4Ctx *c)
{
    idemip_wr16(c->w + IDEMIP_IP4_OFF_CKSUM, c->v16);
}

/** @brief Source Address. */
IDEMIP_INLINE void ip4_set_src(const Ip4Ctx *c)
{
    idemip_wr32(c->w + IDEMIP_IP4_OFF_SRC, c->addr);
}

/** @brief Destination Address. */
IDEMIP_INLINE void ip4_set_dst(const Ip4Ctx *c)
{
    idemip_wr32(c->w + IDEMIP_IP4_OFF_DST, c->addr);
}

/**
 * @brief Recompute the Header Checksum over IHL words and store it.
 *
 * RFC 791 sec 3.1: "The checksum field is the 16 bit one's complement of the one's complement sum
 * of all 16 bit words in the header. For purposes of computing the checksum, the value of the
 * checksum field is zero." The field is zeroed, the sum taken over the whole header including the
 * options, and the result written back.
 */
IDEMIP_INLINE void ip4_recksum(const Ip4Ctx *c)
{
    idemip_ip4_set_cksum(c->w, 0u);
    idemip_ip4_set_cksum(c->w, idemip_cksum(c->w, idemip_ip4_hdr_len(c->w)));
}

/**
 * @brief Write the twenty octets of an option-free header and seal them with the checksum.
 *
 * Version is 4 and IHL is 5 (RFC 791 sec 3.1). A caller that appends options raises IHL with
 * set_ver_ihl and calls recksum again.
 */
IDEMIP_INLINE void ip4_build(const Ip4Ctx *c)
{
    idemip_ip4_set_ver_ihl(c->w, (uint8_t)IDEMIP_IP4_IHL_MIN);
    idemip_ip4_set_tos(c->w, c->f->tos);
    idemip_ip4_set_total_len(c->w, c->f->total_len);
    idemip_ip4_set_id(c->w, c->f->id);
    idemip_ip4_set_flags_frag(c->w, c->f->flags_frag);
    idemip_ip4_set_ttl(c->w, c->f->ttl);
    idemip_ip4_set_proto(c->w, c->f->proto);
    idemip_ip4_set_src(c->w, c->f->src);
    idemip_ip4_set_dst(c->w, c->f->dst);
    idemip_ip4_recksum(c->w);
}

// --- the checks RFC 1122 sec 3.2.1 puts on a received datagram --------------

/** @brief RFC 1122 sec 3.2.1.1: "A datagram whose version number is not 4 MUST be silently discarded." */
IDEMIP_INLINE idemip_bool ip4_version_ok(const Ip4Ctx *c)
{
    return (idemip_bool)(ip4_version(c) == IDEMIP_IP4_VERSION);
}

/** @brief RFC 791 sec 3.1: IHL is four bits and "the minimum value for a correct header is 5". */
IDEMIP_INLINE idemip_bool ip4_ihl_ok(const Ip4Ctx *c)
{
    const uint8_t ihl = ip4_ihl(c);
    // Not measured on the ceiling: the field is four bits, so ip4_ihl reports at most 15, which is
    // IDEMIP_IP4_IHL_MAX. It is written because the header length this reports on is what every
    // walk over the options is bounded by, and the two ends of sec 3.1's range are stated together
    // there.
    return (idemip_bool)(ihl >= IDEMIP_IP4_IHL_MIN && ihl <= IDEMIP_IP4_IHL_MAX); // GCOVR_EXCL_BR_LINE
}

/**
 * @brief The header and Total Length both fit in the readable octets, and Total Length covers the
 *        header.
 *
 * RFC 791 sec 3.1 counts Total Length "including internet header and data", so it is never below
 * the header. RFC 894 pads a short frame and that padding "is not included in the total length
 * field of the IP header", so the readable count may exceed it. Reads IHL, which ihl_ok bounds
 * first.
 */
IDEMIP_INLINE idemip_bool ip4_len_ok(const Ip4Ctx *c)
{
    const size_t hdr = ip4_hdr_len(c);
    const size_t total = (size_t)ip4_total_len(c);
    return (idemip_bool)(hdr <= c->avail && total >= hdr && total <= c->avail);
}

/**
 * @brief RFC 1122 sec 3.2.1.2: "A host MUST verify the IP header checksum on every received
 * datagram and silently discard every datagram that has a bad checksum."
 *
 * The sum runs over the header as it arrived, checksum field included, which RFC 1071 sec 1 makes
 * all ones on a good header. Reads IHL, which ihl_ok bounds first.
 */
IDEMIP_INLINE idemip_bool ip4_cksum_ok(const Ip4Ctx *c)
{
    return idemip_cksum_valid(c->h, ip4_hdr_len(c));
}

/**
 * @brief Every check above, over the readable octets.
 *
 * OK when the header is version 4, its IHL is in range, its lengths agree, and its checksum holds.
 * ERR otherwise, and on fewer than twenty readable octets. Flags bit 0 is read by ip4_reserved and
 * not tested here: RFC 791 sec 3.1 requires a sender to zero it and neither RFC 791 nor RFC 1122
 * sec 3.2.1 makes a receiver discard a datagram carrying it set.
 */
IDEMIP_INLINE IdemIpStatus ip4_verify_all(const Ip4Ctx *c)
{
    if (c->avail < IDEMIP_IPV4_HDR_LEN)
    {
        return IDEMIP_ERR;
    }
    if (!ip4_version_ok(c) || !ip4_ihl_ok(c))
    {
        return IDEMIP_ERR;
    }
    if (!ip4_len_ok(c) || !ip4_cksum_ok(c))
    {
        return IDEMIP_ERR;
    }
    return IDEMIP_OK;
}

// --- arithmetic over a subnet mask -----------------------------------------

/** @brief Ones in the mask, folded in five steps. Shifts and masks only: no divide, no table. */
IDEMIP_INLINE uint8_t ip4_mask_ones(const Ip4Ctx *c)
{
    uint32_t n = c->mask - ((c->mask >> 1) & 0x55555555u);
    n = (n & 0x33333333u) + ((n >> 2) & 0x33333333u);
    n = (n + (n >> 4)) & 0x0F0F0F0Fu;
    n = n + (n >> 8);
    n = n + (n >> 16);
    return (uint8_t)(n & 0x3Fu);
}

/**
 * @brief True when the mask's ones are its leading bits, with no hole below them.
 *
 * Such a mask leaves a host part one below a power of two, so adding one to the complement clears
 * every bit but the carry. RFC 1122 sec 3.2.1.3 allows a mask with holes, which fails this test and
 * is reported rather than refused.
 */
IDEMIP_INLINE idemip_bool ip4_mask_contiguous(const Ip4Ctx *c)
{
    uint32_t host = (~c->mask) + 1u;
    return ((host & (host - 1u)) == 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

/* The namespaces are tables of function pointers with the caller's argument lists in their types,
   so these are what they point at. Each builds the context and hands it to the body above. */

uint8_t idemip_ip4_version(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_version, Ip4Ctx, .h = h);
}

uint8_t idemip_ip4_ihl(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_ihl, Ip4Ctx, .h = h);
}

size_t idemip_ip4_hdr_len(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_hdr_len, Ip4Ctx, .h = h);
}

uint8_t idemip_ip4_tos(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_tos, Ip4Ctx, .h = h);
}

uint16_t idemip_ip4_total_len(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_total_len, Ip4Ctx, .h = h);
}

uint16_t idemip_ip4_id(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_id, Ip4Ctx, .h = h);
}

uint16_t idemip_ip4_flags_frag(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_flags_frag, Ip4Ctx, .h = h);
}

idemip_bool idemip_ip4_reserved(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_reserved, Ip4Ctx, .h = h);
}

idemip_bool idemip_ip4_df(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_df, Ip4Ctx, .h = h);
}

idemip_bool idemip_ip4_mf(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_mf, Ip4Ctx, .h = h);
}

uint16_t idemip_ip4_frag_units(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_frag_units, Ip4Ctx, .h = h);
}

uint32_t idemip_ip4_frag_offset_bytes(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_frag_offset_bytes, Ip4Ctx, .h = h);
}

idemip_bool idemip_ip4_is_fragment(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_is_fragment, Ip4Ctx, .h = h);
}

uint8_t idemip_ip4_ttl(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_ttl, Ip4Ctx, .h = h);
}

uint8_t idemip_ip4_proto(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_proto, Ip4Ctx, .h = h);
}

uint16_t idemip_ip4_cksum(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_cksum, Ip4Ctx, .h = h);
}

uint32_t idemip_ip4_src(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_src, Ip4Ctx, .h = h);
}

uint32_t idemip_ip4_dst(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_dst, Ip4Ctx, .h = h);
}

uint16_t idemip_ip4_payload_len(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_payload_len, Ip4Ctx, .h = h);
}

const uint8_t *idemip_ip4_options(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_options, Ip4Ctx, .h = h);
}

size_t idemip_ip4_options_len(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_options_len, Ip4Ctx, .h = h);
}

void idemip_ip4_set_ver_ihl(uint8_t *h, uint8_t ihl)
{
    IDEMIP_CALL(ip4_set_ver_ihl, Ip4Ctx, .w = h, .v8 = ihl);
}

void idemip_ip4_set_tos(uint8_t *h, uint8_t tos)
{
    IDEMIP_CALL(ip4_set_tos, Ip4Ctx, .w = h, .v8 = tos);
}

void idemip_ip4_set_total_len(uint8_t *h, uint16_t len)
{
    IDEMIP_CALL(ip4_set_total_len, Ip4Ctx, .w = h, .v16 = len);
}

void idemip_ip4_set_id(uint8_t *h, uint16_t id)
{
    IDEMIP_CALL(ip4_set_id, Ip4Ctx, .w = h, .v16 = id);
}

void idemip_ip4_set_flags_frag(uint8_t *h, uint16_t flags_frag)
{
    IDEMIP_CALL(ip4_set_flags_frag, Ip4Ctx, .w = h, .v16 = flags_frag);
}

void idemip_ip4_set_ttl(uint8_t *h, uint8_t ttl)
{
    IDEMIP_CALL(ip4_set_ttl, Ip4Ctx, .w = h, .v8 = ttl);
}

void idemip_ip4_set_proto(uint8_t *h, uint8_t proto)
{
    IDEMIP_CALL(ip4_set_proto, Ip4Ctx, .w = h, .v8 = proto);
}

void idemip_ip4_set_cksum(uint8_t *h, uint16_t sum)
{
    IDEMIP_CALL(ip4_set_cksum, Ip4Ctx, .w = h, .v16 = sum);
}

void idemip_ip4_set_src(uint8_t *h, uint32_t addr)
{
    IDEMIP_CALL(ip4_set_src, Ip4Ctx, .w = h, .addr = addr);
}

void idemip_ip4_set_dst(uint8_t *h, uint32_t addr)
{
    IDEMIP_CALL(ip4_set_dst, Ip4Ctx, .w = h, .addr = addr);
}

void idemip_ip4_recksum(uint8_t *h)
{
    IDEMIP_CALL(ip4_recksum, Ip4Ctx, .w = h);
}

void idemip_ip4_build(uint8_t *h, const IdemIpIp4Fields *f)
{
    IDEMIP_CALL(ip4_build, Ip4Ctx, .w = h, .f = f);
}

idemip_bool idemip_ip4_version_ok(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_version_ok, Ip4Ctx, .h = h);
}

idemip_bool idemip_ip4_ihl_ok(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_ihl_ok, Ip4Ctx, .h = h);
}

idemip_bool idemip_ip4_len_ok(const uint8_t *h, size_t avail)
{
    return IDEMIP_CALL(ip4_len_ok, Ip4Ctx, .h = h, .avail = avail);
}

idemip_bool idemip_ip4_cksum_ok(const uint8_t *h)
{
    return IDEMIP_CALL(ip4_cksum_ok, Ip4Ctx, .h = h);
}

IdemIpStatus idemip_ip4_verify(const uint8_t *h, size_t avail)
{
    return IDEMIP_CALL(ip4_verify_all, Ip4Ctx, .h = h, .avail = avail);
}

uint8_t idemip_ip4_addr_mask_ones(uint32_t mask)
{
    return IDEMIP_CALL(ip4_mask_ones, Ip4Ctx, .mask = mask);
}

idemip_bool idemip_ip4_addr_mask_contiguous(uint32_t mask)
{
    return IDEMIP_CALL(ip4_mask_contiguous, Ip4Ctx, .mask = mask);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4
