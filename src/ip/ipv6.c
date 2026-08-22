// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ipv6.c
 * @brief The IPv6 header, RFC 8200 sec 3, and the headers that chain off it.
 *
 * Every entry below takes one parameter, a pointer to Ip6Ctx. A header access is the octets and,
 * when it writes, what goes into them, so those are one context.
 *
 * The header starts 14 bytes into an Ethernet frame, so its 32-bit fields land on a two-byte
 * boundary and are assembled from their bytes.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ipv6.h"
#include "src/ip/ipv6_defines.h" // the RFC 8200 field map, which this file is the first user of
#include "src/common_defines.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/** @brief One header, extension header, option or pseudo-header access. */
typedef struct
{
    const uint8_t *h;              /**< The header, extension header or option a read walks. */
    uint8_t *w;                    /**< The header a write puts fields into. */
    const IdemIpIp6BuildArgs *a;   /**< The fields a build writes. */
    const IdemIpIp6Chain *chain;   /**< A walk's result, when a caller asks what it stepped. */
    const uint8_t *src;            /**< Source address, summing the sec 8.1 pseudo-header. */
    const uint8_t *dst;            /**< Destination address, the same. */
    size_t *bad;                   /**< Where an option walk reports the offset it refused. */
    size_t len;                    /**< Readable octets, or the bound of an option walk. */
    size_t first;                  /**< Octets to the first Option Type. */
    uint32_t sum;                  /**< A running checksum. */
    uint32_t upper_len;            /**< Upper-Layer Packet Length (sec 8.1). */
    uint32_t ident;                /**< A Fragment header Identification. */
    uint16_t v16;                  /**< A 16-bit field a write sends. */
    uint8_t v8;                    /**< An 8-bit field a write sends. */
    uint8_t nh;                    /**< A Next Header value. */
    idemip_bool more;              /**< The sec 4.5 M flag a build sets. */
} Ip6Ctx;

// --- reading the fixed header ----------------------------------------------

/** @brief Version, the high nibble of the first word. */
IDEMIP_INLINE uint8_t ip6_version(const Ip6Ctx *c)
{
    return (uint8_t)((idemip_rd32(c->h + IDEMIP_IP6_OFF_VER_TC_FLOW) >> IDEMIP_IP6_VER_SHIFT) & IDEMIP_IP6_VER_MASK);
}

/** @brief Traffic Class, the octet below the version. */
IDEMIP_INLINE uint8_t ip6_traffic_class(const Ip6Ctx *c)
{
    return (uint8_t)((idemip_rd32(c->h + IDEMIP_IP6_OFF_VER_TC_FLOW) >> IDEMIP_IP6_TC_SHIFT) & IDEMIP_IP6_TC_MASK);
}

/** @brief Flow Label, the low twenty bits of the first word. */
IDEMIP_INLINE uint32_t ip6_flow_label(const Ip6Ctx *c)
{
    return idemip_rd32(c->h + IDEMIP_IP6_OFF_VER_TC_FLOW) & IDEMIP_IP6_FLOW_MASK;
}

/**
 * @brief Payload Length: everything after this header, extension headers included.
 *
 * RFC 8200 sec 3: "Length of the IPv6 payload, i.e., the rest of the packet following this IPv6
 * header, in octets." Unlike IPv4's Total Length, the fixed header is not counted.
 */
IDEMIP_INLINE uint16_t ip6_payload_len(const Ip6Ctx *c)
{
    return idemip_rd16(c->h + IDEMIP_IP6_OFF_PAYLOAD_LEN);
}

/** @brief Next Header: the type of the header immediately following. */
IDEMIP_INLINE uint8_t ip6_next_hdr(const Ip6Ctx *c)
{
    return c->h[IDEMIP_IP6_OFF_NEXT_HDR];
}

/** @brief Hop Limit, decremented by each forwarding node. */
IDEMIP_INLINE uint8_t ip6_hop_limit(const Ip6Ctx *c)
{
    return c->h[IDEMIP_IP6_OFF_HOP_LIMIT];
}

/** @brief The sixteen octets of the source address, in place. */
IDEMIP_INLINE const uint8_t *ip6_src(const Ip6Ctx *c)
{
    return c->h + IDEMIP_IP6_OFF_SRC;
}

/** @brief The sixteen octets of the destination address, in place. */
IDEMIP_INLINE const uint8_t *ip6_dst(const Ip6Ctx *c)
{
    return c->h + IDEMIP_IP6_OFF_DST;
}

// --- writing the fixed header ----------------------------------------------

/**
 * @brief Write the forty octets of an RFC 8200 sec 3 header.
 *
 * The first word is Version 6 shifted to the top nibble, the Traffic Class masked to eight bits and
 * shifted above the Flow Label, and the Flow Label masked to twenty, so one 32-bit store carries all
 * three. Payload Length, Next Header and Hop Limit follow, then the two addresses are copied where
 * they lie.
 */
IDEMIP_INLINE void ip6_build(const Ip6Ctx *c)
{
    idemip_wr32(c->w + IDEMIP_IP6_OFF_VER_TC_FLOW,
                ((uint32_t)IDEMIP_IP6_VERSION << IDEMIP_IP6_VER_SHIFT) |
                    (((uint32_t)c->a->traffic_class & IDEMIP_IP6_TC_MASK) << IDEMIP_IP6_TC_SHIFT) |
                    (c->a->flow_label & IDEMIP_IP6_FLOW_MASK));
    idemip_wr16(c->w + IDEMIP_IP6_OFF_PAYLOAD_LEN, c->a->payload_len);
    c->w[IDEMIP_IP6_OFF_NEXT_HDR] = c->a->next_hdr;
    c->w[IDEMIP_IP6_OFF_HOP_LIMIT] = c->a->hop_limit;
    memcpy(c->w + IDEMIP_IP6_OFF_SRC, c->a->src, IDEMIP_IP6_ADDR_LEN);
    memcpy(c->w + IDEMIP_IP6_OFF_DST, c->a->dst, IDEMIP_IP6_ADDR_LEN);
}

/** @brief Write Payload Length (RFC 8200 sec 3). */
IDEMIP_INLINE void ip6_set_payload_len(const Ip6Ctx *c)
{
    idemip_wr16(c->w + IDEMIP_IP6_OFF_PAYLOAD_LEN, c->v16);
}

/** @brief Write Next Header (RFC 8200 sec 3). */
IDEMIP_INLINE void ip6_set_next_hdr(const Ip6Ctx *c)
{
    c->w[IDEMIP_IP6_OFF_NEXT_HDR] = c->v8;
}

/** @brief Write Hop Limit (RFC 8200 sec 3). */
IDEMIP_INLINE void ip6_set_hop_limit(const Ip6Ctx *c)
{
    c->w[IDEMIP_IP6_OFF_HOP_LIMIT] = c->v8;
}

// --- extension headers and their options -----------------------------------

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
IDEMIP_INLINE idemip_bool ip6_nh_is_ext(const Ip6Ctx *c)
{
    return (c->nh == IDEMIP_IP6_NH_HOPOPT || c->nh == IDEMIP_IP6_NH_ROUTING || c->nh == IDEMIP_IP6_NH_FRAGMENT ||
            c->nh == IDEMIP_IP6_NH_DSTOPTS)
               ? IDEMIP_TRUE
               : IDEMIP_FALSE;
}

/** @brief Next Header of an extension header carrying the common two octets. */
IDEMIP_INLINE uint8_t ip6_ext_next_hdr(const Ip6Ctx *c)
{
    return c->h[IDEMIP_IP6_EXT_OFF_NEXT_HDR];
}

/** @brief Bytes this extension header occupies. */
IDEMIP_INLINE size_t ip6_ext_len(const Ip6Ctx *c)
{
    return IDEMIP_IP6_EXT_BYTES(c->h[IDEMIP_IP6_EXT_OFF_LEN]);
}

/** @brief Bytes an option occupies: Pad1 is one octet, every other type carries its length. */
IDEMIP_INLINE size_t ip6_opt_len(const Ip6Ctx *c)
{
    return (c->h[IDEMIP_IP6_OPT_OFF_TYPE] == IDEMIP_IP6_OPT_PAD1) ? 1u
                                                                  : ((size_t)c->h[IDEMIP_IP6_OPT_OFF_LEN] + 2u);
}

/**
 * @brief Walk the options of one Hop-by-Hop or Destination Options header for one this node refuses.
 * @param c The walk. @c h is the packet, @c first the first Option Type, @c len one past the header.
 * @return true when an option runs past the header, or one is refused; @c bad is set only in the
 *         second case, so a caller distinguishes them by whether it changed.
 *
 * RFC 8200 sec 4.2 gives the two padding options as the ones that "must be recognized by all IPv6
 * implementations"; this library recognizes no other, so every other type is the section's
 * unrecognized case and its two high-order bits decide. 00 skips and is not reported. 01, 10 and 11
 * all discard, and differ only in whether the caller owes a Parameter Problem, which it reads back
 * off the Option Type octet this reports.
 */
IDEMIP_INLINE idemip_bool ip6_opts_refused(const Ip6Ctx *c)
{
    const uint8_t *p = c->h;
    const size_t last = c->len;
    size_t at = c->first;
    while (at < last)
    {
        const uint8_t type = p[at + IDEMIP_IP6_OPT_OFF_TYPE];
        if (type != IDEMIP_IP6_OPT_PAD1 && at + 2u > last)
        {
            return IDEMIP_TRUE; // the length octet is not inside the header
        }
        const size_t step = idemip_ip6_opt_len(p + at);
        // Not measured on the first: idemip_ip6_opt_len reports one octet for a Pad1 and two more
        // than the Opt Data Len for every other option, so it is never nothing. It is written
        // because the walk advances by it, and a walk that advanced by nothing would not end.
        if (step == 0u || at + step > last) // GCOVR_EXCL_BR_LINE
        {
            return IDEMIP_TRUE;
        }
        if (type != IDEMIP_IP6_OPT_PAD1 && type != IDEMIP_IP6_OPT_PADN &&
            (type & IDEMIP_IP6_OPT_ACT_MASK) != IDEMIP_IP6_OPT_ACT_SKIP)
        {
            *c->bad = at;
            return IDEMIP_TRUE;
        }
        at += step;
    }
    return IDEMIP_FALSE;
}

// --- the Fragment header (RFC 8200 sec 4.5) --------------------------------

/** @brief Offset of this fragment's data, in bytes, from the start of the fragmentable part. */
IDEMIP_INLINE uint16_t ip6_frag_offset_bytes(const Ip6Ctx *c)
{
    return (uint16_t)(idemip_rd16(c->h + IDEMIP_IP6_FRAG_OFF_OFFS_M) & IDEMIP_IP6_FRAG_OFF_MASK);
}

/** @brief True when more fragments follow this one. */
IDEMIP_INLINE idemip_bool ip6_frag_more(const Ip6Ctx *c)
{
    return (idemip_rd16(c->h + IDEMIP_IP6_FRAG_OFF_OFFS_M) & IDEMIP_IP6_FRAG_M) != 0u;
}

/** @brief Identification: the fragments of one original packet share it. */
IDEMIP_INLINE uint32_t ip6_frag_ident(const Ip6Ctx *c)
{
    return idemip_rd32(c->h + IDEMIP_IP6_FRAG_OFF_IDENT);
}

/**
 * @brief Write the eight octets of an RFC 8200 sec 4.5 Fragment header.
 *
 * Reserved is zeroed, the byte offset is masked to the thirteen bits three places up, which drops
 * any remainder below an 8-octet unit and leaves Res clear, and the M flag is set in the low bit.
 */
IDEMIP_INLINE void ip6_frag_build(const Ip6Ctx *c)
{
    c->w[IDEMIP_IP6_FRAG_OFF_NEXT_HDR] = c->nh;
    c->w[IDEMIP_IP6_FRAG_OFF_RESERVED] = 0u;
    idemip_wr16(c->w + IDEMIP_IP6_FRAG_OFF_OFFS_M,
                (uint16_t)((c->v16 & IDEMIP_IP6_FRAG_OFF_MASK) | (c->more ? IDEMIP_IP6_FRAG_M : 0u)));
    idemip_wr32(c->w + IDEMIP_IP6_FRAG_OFF_IDENT, c->ident);
}

// --- the Routing header (RFC 8200 sec 4.4) ---------------------------------

/**
 * @brief RFC 8200 sec 4.4: how an unrecognized Routing Type is answered turns on this field. "If
 * Segments Left is zero, the node must ignore the Routing header and proceed to process the next
 * header"; if it is not, the packet is discarded and Parameter Problem Code 0 is sent.
 */
IDEMIP_INLINE uint8_t ip6_rt_segs_left(const Ip6Ctx *c)
{
    return c->h[IDEMIP_IP6_RT_OFF_SEGS_LEFT];
}

/** @brief RFC 8200 sec 4.4 Routing Type: "8-bit identifier of a particular Routing header variant." */
IDEMIP_INLINE uint8_t ip6_rt_type(const Ip6Ctx *c)
{
    return c->h[IDEMIP_IP6_RT_OFF_TYPE];
}

// --- the chain walk (RFC 8200 sec 4) ---------------------------------------

/**
 * @brief Step the Next Header chain from the IPv6 header to the upper-layer header.
 * @param c The walk. @c h is the IPv6 header, @c len the readable octets, fixed header included.
 * @return Where the walk stopped.
 *
 * RFC 8200 sec 4: "the first one that is not an extension header indicates that the next item in the
 * packet is the corresponding upper-layer header", and headers are "processed strictly in the order
 * they appear". Each step reads the current header's Next Header, adds that header's length, and
 * repeats. sec 4 fixes every extension header at "an integer multiple of 8 octets", so the offset
 * rises by at least eight per step and the walk ends inside @c len with no separate bound.
 *
 * A Fragment header is eight octets by sec 4.5, and its second octet is Reserved rather than a Hdr
 * Ext Len, so it is sized by the standard and never by the field. A Next Header of zero below the
 * IPv6 header stops the walk: sec 4.1 restricts Hop-by-Hop Options to "appear immediately after an
 * IPv6 header only", and sec 4 answers "a Next Header value of zero in any header other than an IPv6
 * header" the same way as an unrecognized one.
 */
IDEMIP_INLINE IdemIpIp6Chain ip6_walk(const Ip6Ctx *ctx)
{
    const uint8_t *p = ctx->h;
    const size_t len = ctx->len;
    IdemIpIp6Chain c;
    c.offset = IDEMIP_IP6_OFF_PAYLOAD;
    c.frag_hdr = 0u;
    c.routing_hdr = 0u;
    c.next_hdr_off = 0u;
    c.opt_hdr = 0u;
    c.next_hdr = IDEMIP_IP6_NH_NONE;
    c.hops = 0u;
    c.fragmented = IDEMIP_FALSE;
    c.routed = IDEMIP_FALSE;
    c.refused = IDEMIP_FALSE;
    c.ok = IDEMIP_FALSE;

    if (len < IDEMIP_IPV6_HDR_LEN)
    {
        c.offset = 0u;
        return c;
    }

    c.next_hdr_off = (size_t)IDEMIP_IP6_OFF_NEXT_HDR;
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
        size_t step =
            (c.next_hdr == IDEMIP_IP6_NH_FRAGMENT) ? (size_t)IDEMIP_IP6_FRAG_HDR_LEN : idemip_ip6_ext_len(p + c.offset);
        if (c.offset + step > len)
        {
            return c;
        }
        if (c.next_hdr == IDEMIP_IP6_NH_FRAGMENT)
        {
            c.fragmented = IDEMIP_TRUE;
            c.frag_hdr = c.offset;
            // sec 4.5 lays a fragment packet out as "(1) The Per-Fragment headers ... (2) A Fragment
            // header ... (3) The fragment itself", and puts the Extension and Upper-Layer headers
            // "in the first fragment" alone. On-arrival processing covers "whatever headers are
            // present, preceding the Fragment header in each fragment packet", so past a non-zero
            // Fragment Offset the bytes are fragment data and the walk ends here.
            if (idemip_ip6_frag_offset_bytes(p + c.offset) != 0u)
            {
                c.offset += step;
                c.hops = (uint16_t)(c.hops + 1u);
                c.ok = IDEMIP_TRUE;
                return c;
            }
        }
        // sec 4.4, over a Routing Type this library executes none of. Segments Left zero is the case
        // the same section ignores, so only a non-zero one is recorded.
        if (c.next_hdr == IDEMIP_IP6_NH_ROUTING && !c.routed && idemip_ip6_rt_segs_left(p + c.offset) != 0u)
        {
            c.routed = IDEMIP_TRUE;
            c.routing_hdr = c.offset;
        }
        // sec 4.2, over the two headers that carry options. An option that runs past its header is a
        // header this walk could not step, and one the node refuses stops the packet here.
        if ((c.next_hdr == IDEMIP_IP6_NH_HOPOPT || c.next_hdr == IDEMIP_IP6_NH_DSTOPTS) && !c.refused)
        {
            size_t bad = 0u;
            if (idemip_ip6_opts_refused(p, c.offset + 2u, c.offset + step, &bad))
            {
                if (bad == 0u)
                {
                    return c; // malformed, and c.ok is still false
                }
                c.refused = IDEMIP_TRUE;
                c.opt_hdr = bad;
            }
        }
        c.next_hdr_off = c.offset;
        c.next_hdr = idemip_ip6_ext_next_hdr(p + c.offset);
        c.offset += step;
        c.hops = (uint16_t)(c.hops + 1u);
    }
    c.ok = IDEMIP_TRUE;
    return c;
}

/** @brief Octets of extension headers the walk stepped over, and zero for a walk that stopped short. */
IDEMIP_INLINE size_t ip6_chain_ext_bytes(const Ip6Ctx *c)
{
    return (c->chain->offset > IDEMIP_IP6_OFF_PAYLOAD) ? (c->chain->offset - IDEMIP_IP6_OFF_PAYLOAD) : 0u;
}

// --- the upper-layer pseudo-header (RFC 8200 sec 8.1) ----------------------

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
IDEMIP_INLINE uint32_t ip6_pseudo_accum(const Ip6Ctx *c)
{
    uint32_t sum = c->sum;
    sum = idemip_cksum_accum(sum, c->src, IDEMIP_IP6_ADDR_LEN);
    sum = idemip_cksum_accum(sum, c->dst, IDEMIP_IP6_ADDR_LEN);
    sum += (c->upper_len >> 16) & 0xFFFFu;
    sum += c->upper_len & 0xFFFFu;
    sum += (uint32_t)c->nh; // the twenty-four zero bits leave it as the low half
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
IDEMIP_INLINE uint32_t ip6_upper_len(const Ip6Ctx *c)
{
    uint32_t payload = (uint32_t)idemip_ip6_payload_len(c->h);
    uint32_t ext = (uint32_t)idemip_ip6_chain_ext_bytes(c->chain);
    return (payload > ext) ? (payload - ext) : 0u;
}

/* The namespaces are tables of function pointers with the caller's argument lists in their types,
   so these are what they point at. Each builds the context and hands it to the body above. */

uint8_t idemip_ip6_version(const uint8_t *h)
{
    return IDEMIP_CALL(ip6_version, Ip6Ctx, .h = h);
}

uint8_t idemip_ip6_traffic_class(const uint8_t *h)
{
    return IDEMIP_CALL(ip6_traffic_class, Ip6Ctx, .h = h);
}

uint32_t idemip_ip6_flow_label(const uint8_t *h)
{
    return IDEMIP_CALL(ip6_flow_label, Ip6Ctx, .h = h);
}

uint16_t idemip_ip6_payload_len(const uint8_t *h)
{
    return IDEMIP_CALL(ip6_payload_len, Ip6Ctx, .h = h);
}

uint8_t idemip_ip6_next_hdr(const uint8_t *h)
{
    return IDEMIP_CALL(ip6_next_hdr, Ip6Ctx, .h = h);
}

uint8_t idemip_ip6_hop_limit(const uint8_t *h)
{
    return IDEMIP_CALL(ip6_hop_limit, Ip6Ctx, .h = h);
}

const uint8_t *idemip_ip6_src(const uint8_t *h)
{
    return IDEMIP_CALL(ip6_src, Ip6Ctx, .h = h);
}

const uint8_t *idemip_ip6_dst(const uint8_t *h)
{
    return IDEMIP_CALL(ip6_dst, Ip6Ctx, .h = h);
}

void idemip_ip6_build(uint8_t *h, const IdemIpIp6BuildArgs *a)
{
    IDEMIP_CALL(ip6_build, Ip6Ctx, .w = h, .a = a);
}

void idemip_ip6_set_payload_len(uint8_t *h, uint16_t len)
{
    IDEMIP_CALL(ip6_set_payload_len, Ip6Ctx, .w = h, .v16 = len);
}

void idemip_ip6_set_next_hdr(uint8_t *h, uint8_t nh)
{
    IDEMIP_CALL(ip6_set_next_hdr, Ip6Ctx, .w = h, .v8 = nh);
}

void idemip_ip6_set_hop_limit(uint8_t *h, uint8_t hop_limit)
{
    IDEMIP_CALL(ip6_set_hop_limit, Ip6Ctx, .w = h, .v8 = hop_limit);
}

idemip_bool idemip_ip6_nh_is_ext(uint8_t nh)
{
    return IDEMIP_CALL(ip6_nh_is_ext, Ip6Ctx, .nh = nh);
}

uint8_t idemip_ip6_ext_next_hdr(const uint8_t *e)
{
    return IDEMIP_CALL(ip6_ext_next_hdr, Ip6Ctx, .h = e);
}

size_t idemip_ip6_ext_len(const uint8_t *e)
{
    return IDEMIP_CALL(ip6_ext_len, Ip6Ctx, .h = e);
}

size_t idemip_ip6_opt_len(const uint8_t *o)
{
    return IDEMIP_CALL(ip6_opt_len, Ip6Ctx, .h = o);
}

idemip_bool idemip_ip6_opts_refused(const uint8_t *p, size_t first, size_t last, size_t *bad)
{
    return IDEMIP_CALL(ip6_opts_refused, Ip6Ctx, .h = p, .first = first, .len = last, .bad = bad);
}

uint16_t idemip_ip6_frag_offset_bytes(const uint8_t *f)
{
    return IDEMIP_CALL(ip6_frag_offset_bytes, Ip6Ctx, .h = f);
}

idemip_bool idemip_ip6_frag_more(const uint8_t *f)
{
    return IDEMIP_CALL(ip6_frag_more, Ip6Ctx, .h = f);
}

uint32_t idemip_ip6_frag_ident(const uint8_t *f)
{
    return IDEMIP_CALL(ip6_frag_ident, Ip6Ctx, .h = f);
}

void idemip_ip6_frag_build(uint8_t *f, uint8_t next_hdr, uint16_t offset_bytes, idemip_bool more, uint32_t ident)
{
    IDEMIP_CALL(ip6_frag_build, Ip6Ctx, .w = f, .nh = next_hdr, .v16 = offset_bytes, .more = more, .ident = ident);
}

uint8_t idemip_ip6_rt_segs_left(const uint8_t *r)
{
    return IDEMIP_CALL(ip6_rt_segs_left, Ip6Ctx, .h = r);
}

uint8_t idemip_ip6_rt_type(const uint8_t *r)
{
    return IDEMIP_CALL(ip6_rt_type, Ip6Ctx, .h = r);
}

IdemIpIp6Chain idemip_ip6_walk(const uint8_t *p, size_t len)
{
    return IDEMIP_CALL(ip6_walk, Ip6Ctx, .h = p, .len = len);
}

size_t idemip_ip6_chain_ext_bytes(const IdemIpIp6Chain *c)
{
    return IDEMIP_CALL(ip6_chain_ext_bytes, Ip6Ctx, .chain = c);
}

uint32_t idemip_ip6_pseudo_accum(uint32_t sum, const uint8_t *src, const uint8_t *dst, uint32_t upper_len,
                                 uint8_t next_hdr)
{
    return IDEMIP_CALL(ip6_pseudo_accum, Ip6Ctx, .sum = sum, .src = src, .dst = dst, .upper_len = upper_len,
                       .nh = next_hdr);
}

uint32_t idemip_ip6_upper_len(const uint8_t *h, const IdemIpIp6Chain *c)
{
    return IDEMIP_CALL(ip6_upper_len, Ip6Ctx, .h = h, .chain = c);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6
