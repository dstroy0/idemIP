// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ipv4.h
 * @brief The internet header, RFC 791 sec 3.1.
 *
 * Field offsets and the masks that split the packed ones, read out of and written into the caller's
 * bytes. A build fills the twenty fixed octets and seals them with the header checksum; a verify
 * runs the checks RFC 1122 sec 3.2.1 puts on a received datagram. Nothing here stores or moves
 * anything.
 */

#ifndef IDEMIP_IPV4_H
#define IDEMIP_IPV4_H

#include "src/checksum.h"
#include "src/common.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// Field offsets (RFC 791 sec 3.1, Figure 4)
// ---------------------------------------------------------------------------

#define IDEMIP_IP4_OFF_VER_IHL 0u    ///< 4-bit Version, 4-bit IHL
#define IDEMIP_IP4_OFF_TOS 1u        ///< 8-bit Type of Service
#define IDEMIP_IP4_OFF_TOTAL_LEN 2u  ///< 16-bit Total Length
#define IDEMIP_IP4_OFF_ID 4u         ///< 16-bit Identification
#define IDEMIP_IP4_OFF_FLAGS_FRAG 6u ///< 3-bit Flags, 13-bit Fragment Offset
#define IDEMIP_IP4_OFF_TTL 8u        ///< 8-bit Time to Live
#define IDEMIP_IP4_OFF_PROTO 9u      ///< 8-bit Protocol
#define IDEMIP_IP4_OFF_CKSUM 10u     ///< 16-bit Header Checksum
#define IDEMIP_IP4_OFF_SRC 12u       ///< 32-bit Source Address
#define IDEMIP_IP4_OFF_DST 16u       ///< 32-bit Destination Address
#define IDEMIP_IP4_OFF_OPTIONS 20u   ///< Options, then padding to a 32-bit boundary

// ---------------------------------------------------------------------------
// Version and IHL, the first octet
// ---------------------------------------------------------------------------

/** @brief RFC 791 sec 3.1: "This document describes version 4." */
#define IDEMIP_IP4_VERSION 4u

#define IDEMIP_IP4_VER_SHIFT 4u
#define IDEMIP_IP4_VER_MASK 0x0Fu
#define IDEMIP_IP4_IHL_MASK 0x0Fu

/**
 * @brief RFC 791 sec 3.1: "Internet Header Length is the length of the internet header in 32 bit
 * words... the minimum value for a correct header is 5."
 */
#define IDEMIP_IP4_IHL_MIN 5u

/** @brief IHL is 4 bits, so the header cannot exceed 15 words. */
#define IDEMIP_IP4_IHL_MAX 15u

/** @brief A 32-bit word is four octets, so a word count scales by a shift of two. */
#define IDEMIP_IP4_IHL_SHIFT 2u

/** @brief Header bytes for an IHL of @p ihl words. */
#define IDEMIP_IP4_HDR_BYTES(ihl) ((size_t)(ihl) << IDEMIP_IP4_IHL_SHIFT)

/** @brief RFC 791 sec 3.1: "The maximal internet header is 60 octets". */
#define IDEMIP_IP4_HDR_MAX 60u

// ---------------------------------------------------------------------------
// Total Length, the third and fourth octets
// ---------------------------------------------------------------------------

/**
 * @brief RFC 791 sec 3.1: "Total Length is the length of the datagram, measured in octets,
 * including internet header and data. This field allows the length of a datagram to be up to
 * 65,535 octets."
 */
#define IDEMIP_IP4_TOTAL_LEN_MAX 65535u

// ---------------------------------------------------------------------------
// Flags and Fragment Offset, the seventh and eighth octets
// ---------------------------------------------------------------------------
// RFC 791 sec 3.1: "Bit 0: reserved, must be zero. Bit 1: (DF) 0 = May Fragment, 1 = Don't
// Fragment. Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments." The three sit above a 13-bit
// fragment offset in one 16-bit field, so both come out of a single read.

#define IDEMIP_IP4_FLAG_RESERVED (1u << 15) ///< must be zero
#define IDEMIP_IP4_FLAG_DF (1u << 14)       ///< don't fragment
#define IDEMIP_IP4_FLAG_MF (1u << 13)       ///< more fragments
#define IDEMIP_IP4_FRAG_OFF_MASK 0x1FFFu    ///< the 13-bit fragment offset

/**
 * @brief RFC 791 sec 3.1: the fragment offset "is measured in units of 8 octets (64 bits)", so the
 * field counts eight-byte units and the byte position is the field shifted up by three.
 */
#define IDEMIP_IP4_FRAG_UNIT 8u
#define IDEMIP_IP4_FRAG_SHIFT 3u

/**
 * @brief RFC 791 sec 3.2: "This format allows 2**13 = 8192 fragments of 8 octets each for a total
 * of 65,536 octets."
 */
#define IDEMIP_IP4_FRAG_MAX_UNITS 8192u

/**
 * @brief RFC 791 sec 3.2: "Every internet module must be able to forward a datagram of 68 octets
 * without further fragmentation. This is because an internet header may be up to 60 octets, and the
 * minimum fragment is 8 octets."
 */
#define IDEMIP_IP4_MIN_FORWARD_MTU 68u

// ---------------------------------------------------------------------------
// Protocol numbers this tree carries (RFC 791 sec 3.1, assigned by IANA)
// ---------------------------------------------------------------------------

#define IDEMIP_IP4_PROTO_ICMP 1u
#define IDEMIP_IP4_PROTO_TCP 6u
#define IDEMIP_IP4_PROTO_UDP 17u

// ---------------------------------------------------------------------------
// Accessors: every multi-byte field is assembled from its bytes
// ---------------------------------------------------------------------------
// The source and destination addresses sit at 12 and 16 of a header that itself starts 14 bytes
// into an Ethernet frame, so neither is aligned for a 32-bit read in the frame it arrived in.

/** @brief Version, the high nibble of the first octet. */
IDEMIP_INLINE uint8_t idemip_ip4_version(const uint8_t *h)
{
    return (uint8_t)((h[IDEMIP_IP4_OFF_VER_IHL] >> IDEMIP_IP4_VER_SHIFT) & IDEMIP_IP4_VER_MASK);
}

/** @brief IHL in 32-bit words, the low nibble of the first octet. */
IDEMIP_INLINE uint8_t idemip_ip4_ihl(const uint8_t *h)
{
    return (uint8_t)(h[IDEMIP_IP4_OFF_VER_IHL] & IDEMIP_IP4_IHL_MASK);
}

/** @brief Header octets: the IHL word count shifted up by two. */
IDEMIP_INLINE size_t idemip_ip4_hdr_len(const uint8_t *h)
{
    return IDEMIP_IP4_HDR_BYTES(idemip_ip4_ihl(h));
}

/** @brief Type of Service, the second octet. */
IDEMIP_INLINE uint8_t idemip_ip4_tos(const uint8_t *h)
{
    return h[IDEMIP_IP4_OFF_TOS];
}

/** @brief Total Length: the whole datagram, header included. */
IDEMIP_INLINE uint16_t idemip_ip4_total_len(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_IP4_OFF_TOTAL_LEN);
}

/** @brief Identification, the value fragments of one datagram share. */
IDEMIP_INLINE uint16_t idemip_ip4_id(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_IP4_OFF_ID);
}

/** @brief The three flags and the fragment offset, as one field. */
IDEMIP_INLINE uint16_t idemip_ip4_flags_frag(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_IP4_OFF_FLAGS_FRAG);
}

/** @brief Flags bit 0, which RFC 791 sec 3.1 reserves and requires to be zero. */
IDEMIP_INLINE idemip_bool idemip_ip4_reserved(const uint8_t *h)
{
    return (idemip_bool)((idemip_ip4_flags_frag(h) & IDEMIP_IP4_FLAG_RESERVED) != 0u);
}

/** @brief Flags bit 1: set means this datagram may not be fragmented. */
IDEMIP_INLINE idemip_bool idemip_ip4_df(const uint8_t *h)
{
    return (idemip_bool)((idemip_ip4_flags_frag(h) & IDEMIP_IP4_FLAG_DF) != 0u);
}

/** @brief Flags bit 2: set means a later fragment follows. */
IDEMIP_INLINE idemip_bool idemip_ip4_mf(const uint8_t *h)
{
    return (idemip_bool)((idemip_ip4_flags_frag(h) & IDEMIP_IP4_FLAG_MF) != 0u);
}

/** @brief The 13-bit fragment offset field, in units of eight octets. */
IDEMIP_INLINE uint16_t idemip_ip4_frag_units(const uint8_t *h)
{
    return (uint16_t)(idemip_ip4_flags_frag(h) & IDEMIP_IP4_FRAG_OFF_MASK);
}

/** @brief Fragment offset in bytes: the field counts units of eight octets. */
IDEMIP_INLINE uint32_t idemip_ip4_frag_offset_bytes(const uint8_t *h)
{
    return (uint32_t)idemip_ip4_frag_units(h) << IDEMIP_IP4_FRAG_SHIFT;
}

/**
 * @brief True when this datagram is a fragment.
 *
 * RFC 791 sec 3.2: "an unfragmented datagram has all zero fragmentation information (MF = 0,
 * fragment offset = 0)", so either one nonzero makes a fragment.
 */
IDEMIP_INLINE idemip_bool idemip_ip4_is_fragment(const uint8_t *h)
{
    return (idemip_bool)((idemip_ip4_flags_frag(h) & (IDEMIP_IP4_FLAG_MF | IDEMIP_IP4_FRAG_OFF_MASK)) != 0u);
}

/** @brief Time to Live, decremented by every module that forwards the datagram. */
IDEMIP_INLINE uint8_t idemip_ip4_ttl(const uint8_t *h)
{
    return h[IDEMIP_IP4_OFF_TTL];
}

/** @brief Protocol carried in the data field. */
IDEMIP_INLINE uint8_t idemip_ip4_proto(const uint8_t *h)
{
    return h[IDEMIP_IP4_OFF_PROTO];
}

/** @brief Header Checksum, as the sender left it. */
IDEMIP_INLINE uint16_t idemip_ip4_cksum(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_IP4_OFF_CKSUM);
}

/** @brief Source address. */
IDEMIP_INLINE uint32_t idemip_ip4_src(const uint8_t *h)
{
    return idemip_rd32(h + IDEMIP_IP4_OFF_SRC);
}

/** @brief Destination address. */
IDEMIP_INLINE uint32_t idemip_ip4_dst(const uint8_t *h)
{
    return idemip_rd32(h + IDEMIP_IP4_OFF_DST);
}

/** @brief Data octets: Total Length less the header. Reads a header a verify already accepted. */
IDEMIP_INLINE uint16_t idemip_ip4_payload_len(const uint8_t *h)
{
    return (uint16_t)(idemip_ip4_total_len(h) - (uint16_t)idemip_ip4_hdr_len(h));
}

/** @brief The option area, at offset 20. Empty when IHL is 5. */
IDEMIP_INLINE const uint8_t *idemip_ip4_options(const uint8_t *h)
{
    return h + IDEMIP_IP4_OFF_OPTIONS;
}

/** @brief Option octets: the header less its twenty fixed ones, padding included. */
IDEMIP_INLINE size_t idemip_ip4_options_len(const uint8_t *h)
{
    return idemip_ip4_hdr_len(h) - IDEMIP_IPV4_HDR_LEN;
}

// ---------------------------------------------------------------------------
// Writers: each field back into the caller's bytes, in network order
// ---------------------------------------------------------------------------

/** @brief Version 4 in the high nibble, @p ihl words in the low one. */
IDEMIP_INLINE void idemip_ip4_set_ver_ihl(uint8_t *h, uint8_t ihl)
{
    h[IDEMIP_IP4_OFF_VER_IHL] =
        (uint8_t)((IDEMIP_IP4_VERSION << IDEMIP_IP4_VER_SHIFT) | (ihl & IDEMIP_IP4_IHL_MASK));
}

IDEMIP_INLINE void idemip_ip4_set_tos(uint8_t *h, uint8_t tos)
{
    h[IDEMIP_IP4_OFF_TOS] = tos;
}

IDEMIP_INLINE void idemip_ip4_set_total_len(uint8_t *h, uint16_t len)
{
    idemip_wr16(h + IDEMIP_IP4_OFF_TOTAL_LEN, len);
}

IDEMIP_INLINE void idemip_ip4_set_id(uint8_t *h, uint16_t id)
{
    idemip_wr16(h + IDEMIP_IP4_OFF_ID, id);
}

/** @brief The three flags ORed with the 13-bit offset, written as one field. */
IDEMIP_INLINE void idemip_ip4_set_flags_frag(uint8_t *h, uint16_t flags_frag)
{
    idemip_wr16(h + IDEMIP_IP4_OFF_FLAGS_FRAG, flags_frag);
}

IDEMIP_INLINE void idemip_ip4_set_ttl(uint8_t *h, uint8_t ttl)
{
    h[IDEMIP_IP4_OFF_TTL] = ttl;
}

IDEMIP_INLINE void idemip_ip4_set_proto(uint8_t *h, uint8_t proto)
{
    h[IDEMIP_IP4_OFF_PROTO] = proto;
}

IDEMIP_INLINE void idemip_ip4_set_cksum(uint8_t *h, uint16_t sum)
{
    idemip_wr16(h + IDEMIP_IP4_OFF_CKSUM, sum);
}

IDEMIP_INLINE void idemip_ip4_set_src(uint8_t *h, uint32_t addr)
{
    idemip_wr32(h + IDEMIP_IP4_OFF_SRC, addr);
}

IDEMIP_INLINE void idemip_ip4_set_dst(uint8_t *h, uint32_t addr)
{
    idemip_wr32(h + IDEMIP_IP4_OFF_DST, addr);
}

/**
 * @brief Recompute the Header Checksum over IHL words and store it.
 *
 * RFC 791 sec 3.1: "The checksum field is the 16 bit one's complement of the one's complement sum
 * of all 16 bit words in the header. For purposes of computing the checksum, the value of the
 * checksum field is zero." The field is zeroed, the sum taken over the whole header including the
 * options, and the result written back.
 */
IDEMIP_INLINE void idemip_ip4_recksum(uint8_t *h)
{
    idemip_ip4_set_cksum(h, 0u);
    idemip_ip4_set_cksum(h, idemip_cksum(h, idemip_ip4_hdr_len(h)));
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/**
 * @brief The fields a build writes, in host order.
 *
 * @var IdemIpIp4Fields::tos        Type of Service
 * @var IdemIpIp4Fields::total_len  Total Length: header plus data
 * @var IdemIpIp4Fields::id         Identification
 * @var IdemIpIp4Fields::flags_frag the three flags ORed with the 13-bit offset in eight-octet units
 * @var IdemIpIp4Fields::ttl        Time to Live
 * @var IdemIpIp4Fields::proto      Protocol
 * @var IdemIpIp4Fields::src        Source Address
 * @var IdemIpIp4Fields::dst        Destination Address
 */
typedef struct
{
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t proto;
    uint32_t src;
    uint32_t dst;
} IdemIpIp4Fields;

/**
 * @brief Write the twenty octets of an option-free header at @p h and seal them with the checksum.
 *
 * Version is 4 and IHL is 5 (RFC 791 sec 3.1). A caller that appends options raises IHL with
 * @ref idemip_ip4_set_ver_ihl and calls @ref idemip_ip4_recksum again.
 */
IDEMIP_INLINE void idemip_ip4_build(uint8_t *h, const IdemIpIp4Fields *f)
{
    idemip_ip4_set_ver_ihl(h, (uint8_t)IDEMIP_IP4_IHL_MIN);
    idemip_ip4_set_tos(h, f->tos);
    idemip_ip4_set_total_len(h, f->total_len);
    idemip_ip4_set_id(h, f->id);
    idemip_ip4_set_flags_frag(h, f->flags_frag);
    idemip_ip4_set_ttl(h, f->ttl);
    idemip_ip4_set_proto(h, f->proto);
    idemip_ip4_set_src(h, f->src);
    idemip_ip4_set_dst(h, f->dst);
    idemip_ip4_recksum(h);
}

// ---------------------------------------------------------------------------
// Verify: the checks RFC 1122 sec 3.2.1 puts on a received datagram
// ---------------------------------------------------------------------------

/** @brief RFC 1122 sec 3.2.1.1: "A datagram whose version number is not 4 MUST be silently discarded." */
IDEMIP_INLINE idemip_bool idemip_ip4_version_ok(const uint8_t *h)
{
    return (idemip_bool)(idemip_ip4_version(h) == IDEMIP_IP4_VERSION);
}

/** @brief RFC 791 sec 3.1: IHL is four bits and "the minimum value for a correct header is 5". */
IDEMIP_INLINE idemip_bool idemip_ip4_ihl_ok(const uint8_t *h)
{
    const uint8_t ihl = idemip_ip4_ihl(h);
    return (idemip_bool)(ihl >= IDEMIP_IP4_IHL_MIN && ihl <= IDEMIP_IP4_IHL_MAX);
}

/**
 * @brief The header and Total Length both fit in @p avail, and Total Length covers the header.
 *
 * RFC 791 sec 3.1 counts Total Length "including internet header and data", so it is never below
 * the header. RFC 894 pads a short frame and that padding "is not included in the total length
 * field of the IP header", so @p avail may exceed it. Reads IHL, which @ref idemip_ip4_ihl_ok
 * bounds first.
 */
IDEMIP_INLINE idemip_bool idemip_ip4_len_ok(const uint8_t *h, size_t avail)
{
    const size_t hdr = idemip_ip4_hdr_len(h);
    const size_t total = (size_t)idemip_ip4_total_len(h);
    return (idemip_bool)(hdr <= avail && total >= hdr && total <= avail);
}

/**
 * @brief RFC 1122 sec 3.2.1.2: "A host MUST verify the IP header checksum on every received
 * datagram and silently discard every datagram that has a bad checksum."
 *
 * The sum runs over the header as it arrived, checksum field included, which RFC 1071 sec 1 makes
 * all ones on a good header. Reads IHL, which @ref idemip_ip4_ihl_ok bounds first.
 */
IDEMIP_INLINE idemip_bool idemip_ip4_cksum_ok(const uint8_t *h)
{
    return idemip_cksum_valid(h, idemip_ip4_hdr_len(h));
}

/**
 * @brief Every check above, over @p avail readable octets at @p h.
 *
 * OK when the header is version 4, its IHL is in range, its lengths agree with @p avail, and its
 * checksum holds. ERR otherwise, and on fewer than twenty readable octets. Flags bit 0 is read by
 * @ref idemip_ip4_reserved and not tested here: RFC 791 sec 3.1 requires a sender to zero it and
 * neither RFC 791 nor RFC 1122 sec 3.2.1 makes a receiver discard a datagram carrying it set.
 */
IDEMIP_INLINE IdemIpStatus idemip_ip4_verify(const uint8_t *h, size_t avail)
{
    if (avail < IDEMIP_IPV4_HDR_LEN)
    {
        return IDEMIP_ERR;
    }
    if (!idemip_ip4_version_ok(h) || !idemip_ip4_ihl_ok(h))
    {
        return IDEMIP_ERR;
    }
    if (!idemip_ip4_len_ok(h, avail) || !idemip_ip4_cksum_ok(h))
    {
        return IDEMIP_ERR;
    }
    return IDEMIP_OK;
}

// ---------------------------------------------------------------------------
// A subnet mask
// ---------------------------------------------------------------------------
// Arithmetic over the mask itself, which both the address classifier and the routing table ask for.
// RFC 1122 sec 3.3.1.1 (a) makes it "a 32-bit mask that selects the network number and subnet number
// fields", and RFC 1812 sec 5.2.4.3 rule 1 reads the same mask as "the most significant
// route.length bits".
//
// They lived in ip4_addr.h. ip4_route has no reason to include a header about classifying addresses,
// so it wrote its own copy of each, the same arithmetic character for character. Here they are one
// copy, in the header both units already take.

/** @brief Ones in the mask, folded in five steps. Shifts and masks only: no divide, no table. */
IDEMIP_INLINE uint8_t idemip_ip4_addr_mask_ones(uint32_t mask)
{
    uint32_t n = mask - ((mask >> 1) & 0x55555555u);
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
IDEMIP_INLINE idemip_bool idemip_ip4_addr_mask_contiguous(uint32_t mask)
{
    uint32_t host = (~mask) + 1u;
    return ((host & (host - 1u)) == 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// ---------------------------------------------------------------------------
// The map closes on itself
// ---------------------------------------------------------------------------
// Each offset is the one before it plus that field's width, and the last lands on the option-free
// header length.

static_assert(IDEMIP_IP4_OFF_TOS == IDEMIP_IP4_OFF_VER_IHL + 1u, "Version and IHL share one octet");
static_assert(IDEMIP_IP4_OFF_TOTAL_LEN == IDEMIP_IP4_OFF_TOS + 1u, "Type of Service is 8 bits");
static_assert(IDEMIP_IP4_OFF_ID == IDEMIP_IP4_OFF_TOTAL_LEN + 2u, "Total Length is 16 bits");
static_assert(IDEMIP_IP4_OFF_FLAGS_FRAG == IDEMIP_IP4_OFF_ID + 2u, "Identification is 16 bits");
static_assert(IDEMIP_IP4_OFF_TTL == IDEMIP_IP4_OFF_FLAGS_FRAG + 2u, "Flags and Fragment Offset share 16 bits");
static_assert(IDEMIP_IP4_OFF_PROTO == IDEMIP_IP4_OFF_TTL + 1u, "Time to Live is 8 bits");
static_assert(IDEMIP_IP4_OFF_CKSUM == IDEMIP_IP4_OFF_PROTO + 1u, "Protocol is 8 bits");
static_assert(IDEMIP_IP4_OFF_SRC == IDEMIP_IP4_OFF_CKSUM + 2u, "Header Checksum is 16 bits");
static_assert(IDEMIP_IP4_OFF_DST == IDEMIP_IP4_OFF_SRC + 4u, "Source Address is 32 bits");
static_assert(IDEMIP_IP4_OFF_OPTIONS == IDEMIP_IP4_OFF_DST + 4u, "Destination Address is 32 bits");

static_assert(IDEMIP_IP4_OFF_OPTIONS == IDEMIP_IPV4_HDR_LEN,
              "the RFC 791 field offsets must sum to the option-free header length");
static_assert(IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN) == IDEMIP_IPV4_HDR_LEN,
              "the minimum IHL of 5 words is the option-free header (RFC 791 sec 3.1)");
static_assert(IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MAX) == IDEMIP_IP4_HDR_MAX,
              "RFC 791 sec 3.1: an IHL of 15 words is the 60-octet maximal internet header");
static_assert(IDEMIP_IP4_TOTAL_LEN_MAX == 0xFFFFu,
              "RFC 791 sec 3.1: Total Length is 16 bits, allowing up to 65,535 octets");

static_assert(IDEMIP_IP4_FLAG_RESERVED == 0x8000u && IDEMIP_IP4_FLAG_DF == 0x4000u && IDEMIP_IP4_FLAG_MF == 0x2000u,
              "RFC 791 sec 3.1 Flags: bit 0 reserved, bit 1 DF, bit 2 MF, most significant first");
static_assert((IDEMIP_IP4_FLAG_RESERVED | IDEMIP_IP4_FLAG_DF | IDEMIP_IP4_FLAG_MF | IDEMIP_IP4_FRAG_OFF_MASK) ==
                  0xFFFFu,
              "the three flags and the 13-bit Fragment Offset fill one 16-bit field");
static_assert((IDEMIP_IP4_FRAG_OFF_MASK & (IDEMIP_IP4_FLAG_RESERVED | IDEMIP_IP4_FLAG_DF | IDEMIP_IP4_FLAG_MF)) == 0u,
              "the Fragment Offset mask must not reach a flag bit");
static_assert(IDEMIP_IP4_FRAG_UNIT == (1u << IDEMIP_IP4_FRAG_SHIFT),
              "RFC 791 sec 3.1: the fragment offset is measured in units of 8 octets, so its shift is three");
static_assert(IDEMIP_IP4_FRAG_MAX_UNITS == IDEMIP_IP4_FRAG_OFF_MASK + 1u,
              "RFC 791 sec 3.2: 2**13 = 8192 fragments is the whole 13-bit field");
static_assert(IDEMIP_IP4_FRAG_MAX_UNITS * IDEMIP_IP4_FRAG_UNIT == 65536u,
              "RFC 791 sec 3.2: 8192 fragments of 8 octets each total 65,536 octets");
static_assert(IDEMIP_IP4_MIN_FORWARD_MTU == IDEMIP_IP4_HDR_MAX + IDEMIP_IP4_FRAG_UNIT,
              "RFC 791 sec 3.2: 68 octets is a 60-octet header plus the 8-octet minimum fragment");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_IPV4_H
