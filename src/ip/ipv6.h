// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ipv6.h
 * @brief The IPv6 header, RFC 8200 sec 3, and the headers that chain off it.
 *
 * Read out of the caller's bytes; holds nothing. The field offsets, the masks that split the packed
 * first word, and the layouts of the extension headers are ipv6_defines.h, which a .c includes when
 * it genuinely needs the numbers. A caller that wants a field asks for it here.
 *
 * The tables are the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_IPV6_H
#define IDEMIP_IPV6_H

#include "src/checksum.h"
#include "src/common.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

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
 * @brief Where a chain walk stopped.
 *
 * @var IdemIpIp6Chain::offset     octets from the start of the IPv6 header to the upper-layer header,
 *                                 or to the header the walk could not step when @c ok is false
 * @var IdemIpIp6Chain::frag_hdr   octets to the Fragment header, set only when @c fragmented
 * @var IdemIpIp6Chain::next_hdr   the upper-layer protocol, or IDEMIP_IP6_NH_NONE per sec 4.7
 * @var IdemIpIp6Chain::next_hdr_off the offset of the Next Header field @ref IdemIpIp6Chain::next_hdr
 *                                  was read from, which is the IPv6 header's own for a chain of
 *                                  no extension headers. RFC 8200 sec 4, of an unrecognized Next
 *                                  Header: "send an ICMP Parameter Problem message to the source
 *                                  of the packet, with an ICMP Code value of 1 ('unrecognized
 *                                  Next Header type encountered') and the ICMP Pointer field
 *                                  containing the offset of the unrecognized value within the
 *                                  original packet."
 * @var IdemIpIp6Chain::hops       extension headers stepped over
 * @var IdemIpIp6Chain::routing_hdr octets to the first sec 4.4 Routing header carrying a non-zero
 *                                 Segments Left, set only when @c routed. This library executes no
 *                                 Routing Type, so every one of them is sec 4.4's unrecognized case:
 *                                 "If Segments Left is non-zero, the node must discard the packet and
 *                                 send an ICMP Parameter Problem, Code 0, message to the packet's
 *                                 Source Address, pointing to the unrecognized Routing Type." One
 *                                 whose Segments Left is zero is ignored, as the same section says.
 * @var IdemIpIp6Chain::opt_hdr    octets to the Option Type of a sec 4.2 option this node does not
 *                                 recognize and whose two high-order bits are not 00, set only when
 *                                 @c refused. The octet carries its own action, so the caller reads
 *                                 back whether a Parameter Problem, Code 2 is owed.
 * @var IdemIpIp6Chain::fragmented a sec 4.5 Fragment header appeared in the chain
 * @var IdemIpIp6Chain::routed     such a Routing header appeared
 * @var IdemIpIp6Chain::refused    such an option appeared, so the packet is discarded
 * @var IdemIpIp6Chain::ok         every stepped header lay wholly inside the span, and no Next
 *                                 Header of zero appeared below the IPv6 header
 */
typedef struct
{
    size_t offset;
    size_t frag_hdr;
    size_t routing_hdr;
    size_t opt_hdr;
    size_t next_hdr_off;
    uint8_t next_hdr;
    uint16_t hops;
    idemip_bool fragmented;
    idemip_bool routed;
    idemip_bool refused;
    idemip_bool ok;
} IdemIpIp6Chain;

// ---------------------------------------------------------------------------
// The tables
// ---------------------------------------------------------------------------
// Seven, because these are seven jobs: read a field, write one, step an extension header and its
// options, the Fragment header, the Routing header, the chain walk itself, and the sec 8.1
// pseudo-header. Each is a run of function pointers addressed by offset, so each has its layout
// asserted under it.

/**
 * @brief Reading a field out of the fixed header.
 *
 * The header starts 14 bytes into an Ethernet frame, so its 32-bit fields land on a two-byte
 * boundary and are assembled from their bytes.
 */
typedef struct
{
    uint8_t (*version)(const uint8_t *h);
    uint8_t (*traffic_class)(const uint8_t *h);
    uint32_t (*flow_label)(const uint8_t *h);
    uint16_t (*payload_len)(const uint8_t *h);
    uint8_t (*next_hdr)(const uint8_t *h);
    uint8_t (*hop_limit)(const uint8_t *h);
    const uint8_t *(*src)(const uint8_t *h);
    const uint8_t *(*dst)(const uint8_t *h);
} Ip6ReadNs;
IDEMIP_NS_LAYOUT(Ip6ReadNs, version, traffic_class, flow_label, payload_len, next_hdr, hop_limit, src, dst);

/** @brief Writing the fixed header, and the three fields a forwarder rewrites. */
typedef struct
{
    void (*build)(uint8_t *h, const IdemIpIp6BuildArgs *a);
    void (*set_payload_len)(uint8_t *h, uint16_t len);
    void (*set_next_hdr)(uint8_t *h, uint8_t nh);
    void (*set_hop_limit)(uint8_t *h, uint8_t hop_limit);
} Ip6WriteNs;
IDEMIP_NS_LAYOUT(Ip6WriteNs, build, set_payload_len, set_next_hdr, set_hop_limit);

/** @brief The extension headers of RFC 8200 sec 4, and the options of sec 4.2. */
typedef struct
{
    idemip_bool (*nh_is_ext)(uint8_t nh);
    uint8_t (*next_hdr)(const uint8_t *e);
    size_t (*len)(const uint8_t *e);
    size_t (*opt_len)(const uint8_t *o);
    idemip_bool (*opts_refused)(const uint8_t *p, size_t first, size_t last, size_t *bad);
} Ip6ExtNs;
IDEMIP_NS_LAYOUT(Ip6ExtNs, nh_is_ext, next_hdr, len, opt_len, opts_refused);

/** @brief The Fragment header, RFC 8200 sec 4.5. */
typedef struct
{
    uint16_t (*offset_bytes)(const uint8_t *f);
    idemip_bool (*more)(const uint8_t *f);
    uint32_t (*ident)(const uint8_t *f);
    void (*build)(uint8_t *f, uint8_t next_hdr, uint16_t offset_bytes, idemip_bool more, uint32_t ident);
} Ip6FragHdrNs;
IDEMIP_NS_LAYOUT(Ip6FragHdrNs, offset_bytes, more, ident, build);

/** @brief The Routing header, RFC 8200 sec 4.4. */
typedef struct
{
    uint8_t (*segs_left)(const uint8_t *r);
    uint8_t (*type)(const uint8_t *r);
} Ip6RouteNs;
IDEMIP_NS_LAYOUT(Ip6RouteNs, segs_left, type);

/** @brief The chain walk of RFC 8200 sec 4, and what it stepped over. */
typedef struct
{
    IdemIpIp6Chain (*walk)(const uint8_t *p, size_t len);
    size_t (*ext_bytes)(const IdemIpIp6Chain *c);
} Ip6ChainNs;
IDEMIP_NS_LAYOUT(Ip6ChainNs, walk, ext_bytes);

/** @brief The upper-layer pseudo-header, RFC 8200 sec 8.1. Summed, never sent. */
typedef struct
{
    uint32_t (*accum)(uint32_t sum, const uint8_t *src, const uint8_t *dst, uint32_t upper_len, uint8_t next_hdr);
    uint32_t (*upper_len)(const uint8_t *h, const IdemIpIp6Chain *c);
} Ip6PseudoNs;
IDEMIP_NS_LAYOUT(Ip6PseudoNs, accum, upper_len);

/** @name The entries the tables point at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The tables are
 *         still the whole surface: call through them.
 *  @{ */
uint8_t idemip_ip6_version(const uint8_t *h);
uint8_t idemip_ip6_traffic_class(const uint8_t *h);
uint32_t idemip_ip6_flow_label(const uint8_t *h);
uint16_t idemip_ip6_payload_len(const uint8_t *h);
uint8_t idemip_ip6_next_hdr(const uint8_t *h);
uint8_t idemip_ip6_hop_limit(const uint8_t *h);
const uint8_t *idemip_ip6_src(const uint8_t *h);
const uint8_t *idemip_ip6_dst(const uint8_t *h);

void idemip_ip6_build(uint8_t *h, const IdemIpIp6BuildArgs *a);
void idemip_ip6_set_payload_len(uint8_t *h, uint16_t len);
void idemip_ip6_set_next_hdr(uint8_t *h, uint8_t nh);
void idemip_ip6_set_hop_limit(uint8_t *h, uint8_t hop_limit);

idemip_bool idemip_ip6_nh_is_ext(uint8_t nh);
uint8_t idemip_ip6_ext_next_hdr(const uint8_t *e);
size_t idemip_ip6_ext_len(const uint8_t *e);
size_t idemip_ip6_opt_len(const uint8_t *o);
idemip_bool idemip_ip6_opts_refused(const uint8_t *p, size_t first, size_t last, size_t *bad);

uint16_t idemip_ip6_frag_offset_bytes(const uint8_t *f);
idemip_bool idemip_ip6_frag_more(const uint8_t *f);
uint32_t idemip_ip6_frag_ident(const uint8_t *f);
void idemip_ip6_frag_build(uint8_t *f, uint8_t next_hdr, uint16_t offset_bytes, idemip_bool more, uint32_t ident);

uint8_t idemip_ip6_rt_segs_left(const uint8_t *r);
uint8_t idemip_ip6_rt_type(const uint8_t *r);

IdemIpIp6Chain idemip_ip6_walk(const uint8_t *p, size_t len);
size_t idemip_ip6_chain_ext_bytes(const IdemIpIp6Chain *c);

uint32_t idemip_ip6_pseudo_accum(uint32_t sum, const uint8_t *src, const uint8_t *dst, uint32_t upper_len,
                                 uint8_t next_hdr);
uint32_t idemip_ip6_upper_len(const uint8_t *h, const IdemIpIp6Chain *c);
/** @} */

/**
 * @brief The module namespaces.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS Ip6ReadNs ip6_read IDEMIP_UNUSED = {
    .version = idemip_ip6_version,
    .traffic_class = idemip_ip6_traffic_class,
    .flow_label = idemip_ip6_flow_label,
    .payload_len = idemip_ip6_payload_len,
    .next_hdr = idemip_ip6_next_hdr,
    .hop_limit = idemip_ip6_hop_limit,
    .src = idemip_ip6_src,
    .dst = idemip_ip6_dst,
};

IDEMIP_NS Ip6WriteNs ip6_write IDEMIP_UNUSED = {
    .build = idemip_ip6_build,
    .set_payload_len = idemip_ip6_set_payload_len,
    .set_next_hdr = idemip_ip6_set_next_hdr,
    .set_hop_limit = idemip_ip6_set_hop_limit,
};

IDEMIP_NS Ip6ExtNs ip6_ext IDEMIP_UNUSED = {
    .nh_is_ext = idemip_ip6_nh_is_ext,
    .next_hdr = idemip_ip6_ext_next_hdr,
    .len = idemip_ip6_ext_len,
    .opt_len = idemip_ip6_opt_len,
    .opts_refused = idemip_ip6_opts_refused,
};

IDEMIP_NS Ip6FragHdrNs ip6_frag_hdr IDEMIP_UNUSED = {
    .offset_bytes = idemip_ip6_frag_offset_bytes,
    .more = idemip_ip6_frag_more,
    .ident = idemip_ip6_frag_ident,
    .build = idemip_ip6_frag_build,
};

IDEMIP_NS Ip6RouteNs ip6_route IDEMIP_UNUSED = {
    .segs_left = idemip_ip6_rt_segs_left,
    .type = idemip_ip6_rt_type,
};

IDEMIP_NS Ip6ChainNs ip6_chain IDEMIP_UNUSED = {
    .walk = idemip_ip6_walk,
    .ext_bytes = idemip_ip6_chain_ext_bytes,
};

IDEMIP_NS Ip6PseudoNs ip6_pseudo IDEMIP_UNUSED = {
    .accum = idemip_ip6_pseudo_accum,
    .upper_len = idemip_ip6_upper_len,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_IPV6_H
