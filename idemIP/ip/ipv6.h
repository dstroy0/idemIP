// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ipv6.h
 * @brief The IPv6 header, RFC 8200 sec 3, and the headers that chain off it.
 *
 * Field offsets, the masks that split the packed first word, the extension header chain of sec 4,
 * and the upper-layer pseudo-header of sec 8.1. Read out of the caller's bytes; holds nothing.
 */

#ifndef IDEMIP_IPV6_H
#define IDEMIP_IPV6_H

#include "idemIP/checksum.h"
#include "idemIP/common.h"

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// Field offsets (RFC 8200 sec 3)
// ---------------------------------------------------------------------------

#define IDEMIP_IP6_OFF_VER_TC_FLOW 0u ///< 4-bit Version, 8-bit Traffic Class, 20-bit Flow Label
#define IDEMIP_IP6_OFF_PAYLOAD_LEN 4u ///< 16-bit Payload Length
#define IDEMIP_IP6_OFF_NEXT_HDR 6u    ///< 8-bit Next Header
#define IDEMIP_IP6_OFF_HOP_LIMIT 7u   ///< 8-bit Hop Limit
#define IDEMIP_IP6_OFF_SRC 8u         ///< 128-bit Source Address
#define IDEMIP_IP6_OFF_DST 24u        ///< 128-bit Destination Address
#define IDEMIP_IP6_OFF_PAYLOAD 40u    ///< extension headers, then the upper-layer header

/** @brief An address is sixteen octets (RFC 8200 sec 3). */
#define IDEMIP_IP6_ADDR_LEN 16u

// ---------------------------------------------------------------------------
// Version, Traffic Class and Flow Label, the first word
// ---------------------------------------------------------------------------
// RFC 8200 sec 3: a 4-bit version, an 8-bit traffic class and a 20-bit flow label, packed into one
// 32-bit word, so all three come out of a single read.

/** @brief RFC 8200 sec 3: "4-bit Internet Protocol version number = 6." */
#define IDEMIP_IP6_VERSION 6u

#define IDEMIP_IP6_VER_SHIFT 28u
#define IDEMIP_IP6_VER_MASK 0x0Fu
#define IDEMIP_IP6_TC_SHIFT 20u
#define IDEMIP_IP6_TC_MASK 0xFFu
#define IDEMIP_IP6_FLOW_MASK 0x000FFFFFu ///< the 20-bit flow label

// ---------------------------------------------------------------------------
// Next Header values (RFC 8200 sec 4, assigned by IANA)
// ---------------------------------------------------------------------------
// The same numbering as the IPv4 Protocol field, extension headers included: sec 4 says "when
// processing a sequence of Next Header values in a packet, the first one that is not an extension
// header indicates that the next item in the packet is the corresponding upper-layer header".

#define IDEMIP_IP6_NH_HOPOPT 0u ///< Hop-by-Hop Options, and only immediately after the header
#define IDEMIP_IP6_NH_TCP 6u
#define IDEMIP_IP6_NH_UDP 17u
#define IDEMIP_IP6_NH_ROUTING 43u  ///< Routing header (sec 4.4)
#define IDEMIP_IP6_NH_FRAGMENT 44u ///< Fragment header (sec 4.5)
#define IDEMIP_IP6_NH_ICMPV6 58u   ///< ICMPv6 (RFC 4443)
#define IDEMIP_IP6_NH_NONE 59u     ///< No Next Header (sec 4.7)
#define IDEMIP_IP6_NH_DSTOPTS 60u  ///< Destination Options (sec 4.6)

/**
 * @brief True for the four extension headers this document specifies, false for everything else.
 *
 * RFC 8200 sec 4 lists "Hop-by-Hop Options, Fragment, Destination Options, Routing" as the ones
 * "specified in this document", and "the first one that is not an extension header indicates that
 * the next item in the packet is the corresponding upper-layer header". Authentication and
 * Encapsulating Security Payload are the other two the section names, and are sized by RFC 4302 and
 * RFC 4303 rather than by sec 4's 8-octet rule, so neither is stepped over here; sec 4.5 already
 * counts ESP as an upper-layer header.
 */
IDEMIP_INLINE idemip_bool idemip_ip6_nh_is_ext(uint8_t nh)
{
    return (nh == IDEMIP_IP6_NH_HOPOPT || nh == IDEMIP_IP6_NH_ROUTING || nh == IDEMIP_IP6_NH_FRAGMENT ||
            nh == IDEMIP_IP6_NH_DSTOPTS)
               ? IDEMIP_TRUE
               : IDEMIP_FALSE;
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------
// The header starts 14 bytes into an Ethernet frame, so its 32-bit fields land on a two-byte
// boundary and are assembled from their bytes.

/** @brief Version, the high nibble of the first word. */
IDEMIP_INLINE uint8_t idemip_ip6_version(const uint8_t *h)
{
    return (uint8_t)((idemip_rd32(h + IDEMIP_IP6_OFF_VER_TC_FLOW) >> IDEMIP_IP6_VER_SHIFT) & IDEMIP_IP6_VER_MASK);
}

/** @brief Traffic Class, the octet below the version. */
IDEMIP_INLINE uint8_t idemip_ip6_traffic_class(const uint8_t *h)
{
    return (uint8_t)((idemip_rd32(h + IDEMIP_IP6_OFF_VER_TC_FLOW) >> IDEMIP_IP6_TC_SHIFT) & IDEMIP_IP6_TC_MASK);
}

/** @brief Flow Label, the low twenty bits of the first word. */
IDEMIP_INLINE uint32_t idemip_ip6_flow_label(const uint8_t *h)
{
    return idemip_rd32(h + IDEMIP_IP6_OFF_VER_TC_FLOW) & IDEMIP_IP6_FLOW_MASK;
}

/**
 * @brief Payload Length: everything after this header, extension headers included.
 *
 * RFC 8200 sec 3: "Length of the IPv6 payload, i.e., the rest of the packet following this IPv6
 * header, in octets." Unlike IPv4's Total Length, the fixed header is not counted.
 */
IDEMIP_INLINE uint16_t idemip_ip6_payload_len(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_IP6_OFF_PAYLOAD_LEN);
}

/** @brief Next Header: the type of the header immediately following. */
IDEMIP_INLINE uint8_t idemip_ip6_next_hdr(const uint8_t *h)
{
    return h[IDEMIP_IP6_OFF_NEXT_HDR];
}

/** @brief Hop Limit, decremented by each forwarding node. */
IDEMIP_INLINE uint8_t idemip_ip6_hop_limit(const uint8_t *h)
{
    return h[IDEMIP_IP6_OFF_HOP_LIMIT];
}

/** @brief The sixteen octets of the source address, in place. */
IDEMIP_INLINE const uint8_t *idemip_ip6_src(const uint8_t *h)
{
    return h + IDEMIP_IP6_OFF_SRC;
}

/** @brief The sixteen octets of the destination address, in place. */
IDEMIP_INLINE const uint8_t *idemip_ip6_dst(const uint8_t *h)
{
    return h + IDEMIP_IP6_OFF_DST;
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------
// Writes the caller's bytes at the offsets above. Reserves no storage and holds nothing.

/**
 * @brief Largest Payload Length the field carries.
 *
 * RFC 8200 sec 4.5: a fragment whose "length and offset ... are such that the Payload Length of the
 * packet reassembled from that fragment would exceed 65,535 octets" is discarded.
 */
#define IDEMIP_IP6_PAYLOAD_MAX 65535u

/**
 * @brief What a header build takes.
 *
 * @var IdemIpIp6BuildArgs::src           IDEMIP_IP6_ADDR_LEN octets, copied to Source Address
 * @var IdemIpIp6BuildArgs::dst           IDEMIP_IP6_ADDR_LEN octets, copied to Destination Address
 * @var IdemIpIp6BuildArgs::flow_label    masked to the low twenty bits of the first word (sec 6)
 * @var IdemIpIp6BuildArgs::payload_len   octets after the fixed header, extension headers included
 * @var IdemIpIp6BuildArgs::traffic_class masked to eight bits (sec 7)
 * @var IdemIpIp6BuildArgs::next_hdr      the type of the header immediately following
 * @var IdemIpIp6BuildArgs::hop_limit     decremented by each forwarding node
 */
typedef struct
{
    const uint8_t *src;
    const uint8_t *dst;
    uint32_t flow_label;
    uint16_t payload_len;
    uint8_t traffic_class;
    uint8_t next_hdr;
    uint8_t hop_limit;
} IdemIpIp6BuildArgs;

/**
 * @brief Write the forty octets of an RFC 8200 sec 3 header at @p h.
 *
 * The first word is Version 6 shifted to the top nibble, the Traffic Class masked to eight bits and
 * shifted above the Flow Label, and the Flow Label masked to twenty, so one 32-bit store carries all
 * three. Payload Length, Next Header and Hop Limit follow, then the two addresses are copied where
 * they lie.
 */
IDEMIP_INLINE void idemip_ip6_build(uint8_t *h, const IdemIpIp6BuildArgs *a)
{
    idemip_wr32(h + IDEMIP_IP6_OFF_VER_TC_FLOW,
                ((uint32_t)IDEMIP_IP6_VERSION << IDEMIP_IP6_VER_SHIFT) |
                    (((uint32_t)a->traffic_class & IDEMIP_IP6_TC_MASK) << IDEMIP_IP6_TC_SHIFT) |
                    (a->flow_label & IDEMIP_IP6_FLOW_MASK));
    idemip_wr16(h + IDEMIP_IP6_OFF_PAYLOAD_LEN, a->payload_len);
    h[IDEMIP_IP6_OFF_NEXT_HDR] = a->next_hdr;
    h[IDEMIP_IP6_OFF_HOP_LIMIT] = a->hop_limit;
    memcpy(h + IDEMIP_IP6_OFF_SRC, a->src, IDEMIP_IP6_ADDR_LEN);
    memcpy(h + IDEMIP_IP6_OFF_DST, a->dst, IDEMIP_IP6_ADDR_LEN);
}

/** @brief Write Payload Length (RFC 8200 sec 3). */
IDEMIP_INLINE void idemip_ip6_set_payload_len(uint8_t *h, uint16_t len)
{
    idemip_wr16(h + IDEMIP_IP6_OFF_PAYLOAD_LEN, len);
}

/** @brief Write Next Header (RFC 8200 sec 3). */
IDEMIP_INLINE void idemip_ip6_set_next_hdr(uint8_t *h, uint8_t nh)
{
    h[IDEMIP_IP6_OFF_NEXT_HDR] = nh;
}

/** @brief Write Hop Limit (RFC 8200 sec 3). */
IDEMIP_INLINE void idemip_ip6_set_hop_limit(uint8_t *h, uint8_t hop_limit)
{
    h[IDEMIP_IP6_OFF_HOP_LIMIT] = hop_limit;
}

// ---------------------------------------------------------------------------
// Extension headers (RFC 8200 sec 4)
// ---------------------------------------------------------------------------
// Hop-by-Hop Options, Routing and Destination Options all begin the same two octets: the next
// header, then the length of this one. Fragment does not, and is sized by the standard instead.

#define IDEMIP_IP6_EXT_OFF_NEXT_HDR 0u ///< 8-bit Next Header
#define IDEMIP_IP6_EXT_OFF_LEN 1u      ///< 8-bit Hdr Ext Len

/**
 * @brief RFC 8200 sec 4: "Each extension header is an integer multiple of 8 octets long, in order
 * to retain 8-octet alignment for subsequent headers."
 */
#define IDEMIP_IP6_EXT_UNIT 8u

/**
 * @brief Bytes of an extension header whose Hdr Ext Len field reads @p len.
 *
 * RFC 8200 sec 4.3: "Length of the Hop-by-Hop Options header in 8-octet units, not including the
 * first 8 octets", so the first unit is implied and a field of zero is a header of eight.
 */
#define IDEMIP_IP6_EXT_BYTES(len) (((size_t)(len) + 1u) * IDEMIP_IP6_EXT_UNIT)

/** @brief Bytes the widest Hdr Ext Len reaches, the field being eight bits. */
#define IDEMIP_IP6_EXT_BYTES_MAX IDEMIP_IP6_EXT_BYTES(0xFFu)

/** @brief Next Header of an extension header carrying the common two octets. */
IDEMIP_INLINE uint8_t idemip_ip6_ext_next_hdr(const uint8_t *e)
{
    return e[IDEMIP_IP6_EXT_OFF_NEXT_HDR];
}

/** @brief Bytes this extension header occupies. */
IDEMIP_INLINE size_t idemip_ip6_ext_len(const uint8_t *e)
{
    return IDEMIP_IP6_EXT_BYTES(e[IDEMIP_IP6_EXT_OFF_LEN]);
}

// ---------------------------------------------------------------------------
// Options (RFC 8200 sec 4.2)
// ---------------------------------------------------------------------------
// The Hop-by-Hop Options and Destination Options headers carry a type-length-value sequence. Pad1
// is the one type with no length octet.

#define IDEMIP_IP6_OPT_OFF_TYPE 0u ///< 8-bit Option Type
#define IDEMIP_IP6_OPT_OFF_LEN 1u  ///< 8-bit Opt Data Len
#define IDEMIP_IP6_OPT_PAD1 0u     ///< one octet of padding, no length and no value
#define IDEMIP_IP6_OPT_PADN 1u     ///< N octets of padding, the length field reading N-2

/**
 * @brief The two bits saying what to do with a type this node does not recognize.
 *
 * RFC 8200 sec 4.2: "The Option Type identifiers are internally encoded such that their
 * highest-order 2 bits specify the action that must be taken if the processing IPv6 node does not
 * recognize the Option Type".
 */
#define IDEMIP_IP6_OPT_ACT_MASK 0xC0u
#define IDEMIP_IP6_OPT_ACT_SKIP 0x00u         ///< 00, skip over this option and keep going
#define IDEMIP_IP6_OPT_ACT_DISCARD 0x40u      ///< 01, discard the packet
#define IDEMIP_IP6_OPT_ACT_DISCARD_ICMP 0x80u ///< 10, discard and always answer Parameter Problem
#define IDEMIP_IP6_OPT_ACT_DISCARD_UNI 0xC0u  ///< 11, discard, and answer only if not multicast

/**
 * @brief RFC 8200 sec 4.2: the third-highest bit "specifies whether or not the Option Data of that
 * option can change en route to the packet's final destination".
 */
#define IDEMIP_IP6_OPT_CHG_MASK 0x20u

/** @brief Bytes an option occupies: Pad1 is one octet, every other type carries its length. */
IDEMIP_INLINE size_t idemip_ip6_opt_len(const uint8_t *o)
{
    return (o[IDEMIP_IP6_OPT_OFF_TYPE] == IDEMIP_IP6_OPT_PAD1) ? 1u : ((size_t)o[IDEMIP_IP6_OPT_OFF_LEN] + 2u);
}

// ---------------------------------------------------------------------------
// Fragment header (RFC 8200 sec 4.5)
// ---------------------------------------------------------------------------
// Eight octets, and the only extension header this document gives a fixed size. Fragmentation is
// the source node's alone: sec 4.5 notes it is "performed only by source nodes, not by routers
// along a packet's delivery path".

#define IDEMIP_IP6_FRAG_OFF_NEXT_HDR 0u ///< 8-bit Next Header
#define IDEMIP_IP6_FRAG_OFF_RESERVED 1u ///< 8-bit Reserved, zero on transmission
#define IDEMIP_IP6_FRAG_OFF_OFFS_M 2u   ///< 13-bit Fragment Offset, 2-bit Res, 1-bit M
#define IDEMIP_IP6_FRAG_OFF_IDENT 4u    ///< 32-bit Identification
#define IDEMIP_IP6_FRAG_HDR_LEN 8u

/**
 * @brief RFC 8200 sec 4.5: the offset is "in 8-octet units", and it sits three bits up in the
 * field, so masking off the reserved bits and the M flag leaves the byte position already scaled.
 */
#define IDEMIP_IP6_FRAG_OFF_MASK 0xFFF8u

/**
 * @brief RFC 8200 sec 4.5: the "2-bit reserved field" between the offset and the M flag,
 * "Initialized to zero for transmission; ignored on reception."
 */
#define IDEMIP_IP6_FRAG_RES_MASK 0x0006u

/** @brief RFC 8200 sec 4.5: "1 = more fragments; 0 = last fragment." */
#define IDEMIP_IP6_FRAG_M (1u << 0)

/** @brief Offset of this fragment's data, in bytes, from the start of the fragmentable part. */
IDEMIP_INLINE uint16_t idemip_ip6_frag_offset_bytes(const uint8_t *f)
{
    return (uint16_t)(idemip_rd16(f + IDEMIP_IP6_FRAG_OFF_OFFS_M) & IDEMIP_IP6_FRAG_OFF_MASK);
}

/** @brief True when more fragments follow this one. */
IDEMIP_INLINE idemip_bool idemip_ip6_frag_more(const uint8_t *f)
{
    return (idemip_rd16(f + IDEMIP_IP6_FRAG_OFF_OFFS_M) & IDEMIP_IP6_FRAG_M) != 0u;
}

/** @brief Identification: the fragments of one original packet share it. */
IDEMIP_INLINE uint32_t idemip_ip6_frag_ident(const uint8_t *f)
{
    return idemip_rd32(f + IDEMIP_IP6_FRAG_OFF_IDENT);
}

/**
 * @brief Write the eight octets of an RFC 8200 sec 4.5 Fragment header at @p f.
 *
 * Reserved is zeroed, the byte offset is masked to the thirteen bits three places up, which drops
 * any remainder below an 8-octet unit and leaves Res clear, and the M flag is set in the low bit.
 *
 * @param offset_bytes offset of this fragment from the start of the Fragmentable Part, in octets
 */
IDEMIP_INLINE void idemip_ip6_frag_build(uint8_t *f, uint8_t next_hdr, uint16_t offset_bytes, idemip_bool more,
                                        uint32_t ident)
{
    f[IDEMIP_IP6_FRAG_OFF_NEXT_HDR] = next_hdr;
    f[IDEMIP_IP6_FRAG_OFF_RESERVED] = 0u;
    idemip_wr16(f + IDEMIP_IP6_FRAG_OFF_OFFS_M,
                (uint16_t)((offset_bytes & IDEMIP_IP6_FRAG_OFF_MASK) | (more ? IDEMIP_IP6_FRAG_M : 0u)));
    idemip_wr32(f + IDEMIP_IP6_FRAG_OFF_IDENT, ident);
}

// ---------------------------------------------------------------------------
// Routing header (RFC 8200 sec 4.4)
// ---------------------------------------------------------------------------
// The common two octets, then the variant and how far along it is.

#define IDEMIP_IP6_RT_OFF_TYPE 2u      ///< 8-bit Routing Type
#define IDEMIP_IP6_RT_OFF_SEGS_LEFT 3u ///< 8-bit Segments Left

/**
 * @brief RFC 8200 sec 4.4: how an unrecognized Routing Type is answered turns on this field. "If
 * Segments Left is zero, the node must ignore the Routing header and proceed to process the next
 * header"; if it is not, the packet is discarded and Parameter Problem Code 0 is sent.
 */
IDEMIP_INLINE uint8_t idemip_ip6_rt_segs_left(const uint8_t *r)
{
    return r[IDEMIP_IP6_RT_OFF_SEGS_LEFT];
}

/** @brief RFC 8200 sec 4.4 Routing Type: "8-bit identifier of a particular Routing header variant." */
IDEMIP_INLINE uint8_t idemip_ip6_rt_type(const uint8_t *r)
{
    return r[IDEMIP_IP6_RT_OFF_TYPE];
}

// ---------------------------------------------------------------------------
// The chain walk (RFC 8200 sec 4)
// ---------------------------------------------------------------------------

/**
 * @brief Where a chain walk stopped.
 *
 * @var IdemIpIp6Chain::offset     octets from the start of the IPv6 header to the upper-layer header,
 *                                 or to the header the walk could not step when @c ok is false
 * @var IdemIpIp6Chain::frag_hdr   octets to the Fragment header, set only when @c fragmented
 * @var IdemIpIp6Chain::next_hdr   the upper-layer protocol, or IDEMIP_IP6_NH_NONE per sec 4.7
 * @var IdemIpIp6Chain::hops       extension headers stepped over
 * @var IdemIpIp6Chain::fragmented a sec 4.5 Fragment header appeared in the chain
 * @var IdemIpIp6Chain::ok         every stepped header lay wholly inside the span, and no Next
 *                                 Header of zero appeared below the IPv6 header
 */
typedef struct
{
    size_t offset;
    size_t frag_hdr;
    uint8_t next_hdr;
    uint16_t hops;
    idemip_bool fragmented;
    idemip_bool ok;
} IdemIpIp6Chain;

/**
 * @brief Step the Next Header chain from the IPv6 header to the upper-layer header.
 *
 * RFC 8200 sec 4: "the first one that is not an extension header indicates that the next item in the
 * packet is the corresponding upper-layer header", and headers are "processed strictly in the order
 * they appear". Each step reads the current header's Next Header, adds that header's length, and
 * repeats. sec 4 fixes every extension header at "an integer multiple of 8 octets", so the offset
 * rises by at least eight per step and the walk ends inside @p len with no separate bound.
 *
 * A Fragment header is eight octets by sec 4.5, and its second octet is Reserved rather than a Hdr
 * Ext Len, so it is sized by the standard and never by the field. A Next Header of zero below the
 * IPv6 header stops the walk: sec 4.1 restricts Hop-by-Hop Options to "appear immediately after an
 * IPv6 header only", and sec 4 answers "a Next Header value of zero in any header other than an IPv6
 * header" the same way as an unrecognized one.
 *
 * @param p   the IPv6 header
 * @param len octets of packet readable at @p p, the fixed header included
 */
IDEMIP_INLINE IdemIpIp6Chain idemip_ip6_walk(const uint8_t *p, size_t len)
{
    IdemIpIp6Chain c;
    c.offset = IDEMIP_IP6_OFF_PAYLOAD;
    c.frag_hdr = 0u;
    c.next_hdr = IDEMIP_IP6_NH_NONE;
    c.hops = 0u;
    c.fragmented = IDEMIP_FALSE;
    c.ok = IDEMIP_FALSE;

    if (len < IDEMIP_IPV6_HDR_LEN)
    {
        c.offset = 0u;
        return c;
    }

    c.next_hdr = idemip_ip6_next_hdr(p);
    while (idemip_ip6_nh_is_ext(c.next_hdr))
    {
        if (c.next_hdr == IDEMIP_IP6_NH_HOPOPT && c.hops != 0u)
        {
            return c;
        }
        if (c.offset + IDEMIP_IP6_EXT_UNIT > len)
        {
            return c;
        }
        size_t step = (c.next_hdr == IDEMIP_IP6_NH_FRAGMENT) ? (size_t)IDEMIP_IP6_FRAG_HDR_LEN
                                                            : idemip_ip6_ext_len(p + c.offset);
        if (c.offset + step > len)
        {
            return c;
        }
        if (c.next_hdr == IDEMIP_IP6_NH_FRAGMENT)
        {
            c.fragmented = IDEMIP_TRUE;
            c.frag_hdr = c.offset;
        }
        c.next_hdr = idemip_ip6_ext_next_hdr(p + c.offset);
        c.offset += step;
        c.hops = (uint16_t)(c.hops + 1u);
    }
    c.ok = IDEMIP_TRUE;
    return c;
}

/** @brief Octets of extension headers the walk stepped over, and zero for a walk that stopped short. */
IDEMIP_INLINE size_t idemip_ip6_chain_ext_bytes(const IdemIpIp6Chain *c)
{
    return (c->offset > IDEMIP_IP6_OFF_PAYLOAD) ? (c->offset - IDEMIP_IP6_OFF_PAYLOAD) : 0u;
}

// ---------------------------------------------------------------------------
// Upper-layer pseudo-header (RFC 8200 sec 8.1)
// ---------------------------------------------------------------------------

/**
 * @brief Accumulate the pseudo-header TCP, UDP and ICMPv6 checksums cover.
 *
 * RFC 8200 sec 8.1: the two 128-bit addresses, a 32-bit Upper-Layer Packet Length, twenty-four zero
 * bits, and the Next Header. The length is "the length of the upper-layer header and data", and the
 * Next Header "identifies the upper-layer protocol", which differs from the packet's own Next
 * Header when extension headers sit between.
 *
 * The addresses are summed where they lie, sixteen octets each, which is the same word pairing the
 * figure lays out. Not part of the packet: it is summed, never sent.
 */
IDEMIP_INLINE uint32_t idemip_ip6_pseudo_accum(uint32_t sum, const uint8_t *src, const uint8_t *dst,
                                                  uint32_t upper_len, uint8_t next_hdr)
{
    sum = idemip_cksum_accum(sum, src, IDEMIP_IP6_ADDR_LEN);
    sum = idemip_cksum_accum(sum, dst, IDEMIP_IP6_ADDR_LEN);
    sum += (upper_len >> 16) & 0xFFFFu;
    sum += upper_len & 0xFFFFu;
    sum += (uint32_t)next_hdr; // the twenty-four zero bits leave it as the low half
    return sum;
}

/**
 * @brief Upper-Layer Packet Length for the sec 8.1 pseudo-header, from the header and a walk.
 *
 * RFC 8200 sec 8.1: for a protocol that carries no length of its own "the length used in the
 * pseudo-header is the Payload Length from the IPv6 header, minus the length of any extension headers
 * present between the IPv6 header and the upper-layer header". A Payload Length shorter than the
 * headers the walk stepped gives zero rather than wrapping.
 */
IDEMIP_INLINE uint32_t idemip_ip6_upper_len(const uint8_t *h, const IdemIpIp6Chain *c)
{
    uint32_t payload = (uint32_t)idemip_ip6_payload_len(h);
    uint32_t ext = (uint32_t)idemip_ip6_chain_ext_bytes(c);
    return (payload > ext) ? (payload - ext) : 0u;
}

static_assert(IDEMIP_IP6_OFF_PAYLOAD == IDEMIP_IPV6_HDR_LEN,
              "the RFC 8200 field offsets must sum to the fixed header length");
static_assert(IDEMIP_IP6_OFF_DST + IDEMIP_IP6_ADDR_LEN == IDEMIP_IPV6_HDR_LEN,
              "the destination address must end the RFC 8200 sec 3 header");
static_assert(IDEMIP_IP6_EXT_BYTES(0u) == IDEMIP_IP6_EXT_UNIT,
              "a Hdr Ext Len of zero is one 8-octet unit (RFC 8200 sec 4.3)");
static_assert(IDEMIP_IP6_EXT_BYTES_MAX == 2048u,
              "an 8-bit Hdr Ext Len reaches 256 units of 8 octets (RFC 8200 sec 4.3)");
static_assert(IDEMIP_IP6_FRAG_OFF_IDENT + 4u == IDEMIP_IP6_FRAG_HDR_LEN,
              "the RFC 8200 sec 4.5 fields must sum to the fragment header length");

// The packed fields fill their word and do not overlap, as the sec 3 and sec 4.5 figures lay them out.
static_assert((((uint32_t)IDEMIP_IP6_VER_MASK << IDEMIP_IP6_VER_SHIFT) |
               ((uint32_t)IDEMIP_IP6_TC_MASK << IDEMIP_IP6_TC_SHIFT) | IDEMIP_IP6_FLOW_MASK) == 0xFFFFFFFFu,
              "Version, Traffic Class and Flow Label must fill the first word (RFC 8200 sec 3)");
static_assert((((uint32_t)IDEMIP_IP6_VER_MASK << IDEMIP_IP6_VER_SHIFT) &
               ((uint32_t)IDEMIP_IP6_TC_MASK << IDEMIP_IP6_TC_SHIFT)) == 0u,
              "Version must not overlap Traffic Class (RFC 8200 sec 3)");
static_assert((((uint32_t)IDEMIP_IP6_TC_MASK << IDEMIP_IP6_TC_SHIFT) & IDEMIP_IP6_FLOW_MASK) == 0u,
              "Traffic Class must not overlap the Flow Label (RFC 8200 sec 3)");
static_assert((IDEMIP_IP6_FRAG_OFF_MASK | IDEMIP_IP6_FRAG_RES_MASK | IDEMIP_IP6_FRAG_M) == 0xFFFFu,
              "the 13-bit Fragment Offset, the 2-bit Res and the M flag must fill the field "
              "(RFC 8200 sec 4.5)");
static_assert((IDEMIP_IP6_FRAG_OFF_MASK & (IDEMIP_IP6_FRAG_RES_MASK | IDEMIP_IP6_FRAG_M)) == 0u,
              "the Fragment Offset must not overlap Res or the M flag (RFC 8200 sec 4.5)");
static_assert((IDEMIP_IP6_OPT_ACT_MASK | IDEMIP_IP6_OPT_CHG_MASK) == 0xE0u,
              "the two action bits and the change bit are the three high-order bits of an Option Type "
              "(RFC 8200 sec 4.2)");
static_assert(IDEMIP_IP6_RT_OFF_SEGS_LEFT < IDEMIP_IP6_EXT_UNIT,
              "the four named Routing header octets lie in its first 8-octet unit (RFC 8200 sec 4.4)");

IDEMIP_END_DECLS

#endif // IDEMIP_IPV6_H
