// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ipv4.h
 * @brief The internet header, RFC 791 sec 3.1.
 *
 * Fields read out of and written into the caller's bytes. A build fills the twenty fixed octets and
 * seals them with the header checksum; a verify runs the checks RFC 1122 sec 3.2.1 puts on a
 * received datagram. Nothing here stores or moves anything.
 *
 * The field offsets and the masks that split the packed fields are ipv4_defines.h, which a .c
 * includes when it genuinely needs the numbers. A caller that wants a field asks for it here.
 *
 * The tables are the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_IPV4_H
#define IDEMIP_IPV4_H

#include "src/checksum.h"
#include "src/common.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

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

// ---------------------------------------------------------------------------
// The tables
// ---------------------------------------------------------------------------
// Four, because these are four jobs over the same twenty octets. Each is a run of function pointers
// addressed by offset, so each has its layout asserted under it.

/** @brief Reading a field out of a header. Every multi-byte field is assembled from its bytes. */
typedef struct
{
    uint8_t (*version)(const uint8_t *h);
    uint8_t (*ihl)(const uint8_t *h);
    size_t (*hdr_len)(const uint8_t *h);
    uint8_t (*tos)(const uint8_t *h);
    uint16_t (*total_len)(const uint8_t *h);
    uint16_t (*id)(const uint8_t *h);
    uint16_t (*flags_frag)(const uint8_t *h);
    idemip_bool (*reserved)(const uint8_t *h);
    idemip_bool (*df)(const uint8_t *h);
    idemip_bool (*mf)(const uint8_t *h);
    uint16_t (*frag_units)(const uint8_t *h);
    uint32_t (*frag_offset_bytes)(const uint8_t *h);
    idemip_bool (*is_fragment)(const uint8_t *h);
    uint8_t (*ttl)(const uint8_t *h);
    uint8_t (*proto)(const uint8_t *h);
    uint16_t (*cksum)(const uint8_t *h);
    uint32_t (*src)(const uint8_t *h);
    uint32_t (*dst)(const uint8_t *h);
    uint16_t (*payload_len)(const uint8_t *h);
    const uint8_t *(*options)(const uint8_t *h);
    size_t (*options_len)(const uint8_t *h);
} Ip4ReadNs;
IDEMIP_NS_LAYOUT(Ip4ReadNs, version, ihl, hdr_len, tos, total_len, id, flags_frag, reserved, df, mf, frag_units,
                 frag_offset_bytes, is_fragment, ttl, proto, cksum, src, dst, payload_len, options, options_len);

/** @brief Writing a field into a header, in network order, and sealing one. */
typedef struct
{
    void (*set_ver_ihl)(uint8_t *h, uint8_t ihl);
    void (*set_tos)(uint8_t *h, uint8_t tos);
    void (*set_total_len)(uint8_t *h, uint16_t len);
    void (*set_id)(uint8_t *h, uint16_t id);
    void (*set_flags_frag)(uint8_t *h, uint16_t flags_frag);
    void (*set_ttl)(uint8_t *h, uint8_t ttl);
    void (*set_proto)(uint8_t *h, uint8_t proto);
    void (*set_cksum)(uint8_t *h, uint16_t sum);
    void (*set_src)(uint8_t *h, uint32_t addr);
    void (*set_dst)(uint8_t *h, uint32_t addr);
    void (*recksum)(uint8_t *h);
    void (*build)(uint8_t *h, const IdemIpIp4Fields *f);
} Ip4WriteNs;
IDEMIP_NS_LAYOUT(Ip4WriteNs, set_ver_ihl, set_tos, set_total_len, set_id, set_flags_frag, set_ttl, set_proto,
                 set_cksum, set_src, set_dst, recksum, build);

/** @brief The checks RFC 1122 sec 3.2.1 puts on a received datagram. */
typedef struct
{
    idemip_bool (*version_ok)(const uint8_t *h);
    idemip_bool (*ihl_ok)(const uint8_t *h);
    idemip_bool (*len_ok)(const uint8_t *h, size_t avail);
    idemip_bool (*cksum_ok)(const uint8_t *h);
    IdemIpStatus (*verify)(const uint8_t *h, size_t avail);
} Ip4VerifyNs;
IDEMIP_NS_LAYOUT(Ip4VerifyNs, version_ok, ihl_ok, len_ok, cksum_ok, verify);

/**
 * @brief Arithmetic over the mask itself, which both the address classifier and the routing table
 *        ask for.
 *
 * RFC 1122 sec 3.3.1.1 (a) makes it "a 32-bit mask that selects the network number and subnet
 * number fields", and RFC 1812 sec 5.2.4.3 rule 1 reads the same mask as "the most significant
 * route.length bits".
 *
 * They lived in ip4_addr.h. ip4_route has no reason to include a header about classifying
 * addresses, so it wrote its own copy of each, the same arithmetic character for character. Here
 * they are one copy, in the header both units already take.
 */
typedef struct
{
    uint8_t (*ones)(uint32_t mask);
    idemip_bool (*contiguous)(uint32_t mask);
} Ip4MaskNs;
IDEMIP_NS_LAYOUT(Ip4MaskNs, ones, contiguous);

/** @name The entries the tables point at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The tables are
 *         still the whole surface: call through them.
 *  @{ */
uint8_t idemip_ip4_version(const uint8_t *h);
uint8_t idemip_ip4_ihl(const uint8_t *h);
size_t idemip_ip4_hdr_len(const uint8_t *h);
uint8_t idemip_ip4_tos(const uint8_t *h);
uint16_t idemip_ip4_total_len(const uint8_t *h);
uint16_t idemip_ip4_id(const uint8_t *h);
uint16_t idemip_ip4_flags_frag(const uint8_t *h);
idemip_bool idemip_ip4_reserved(const uint8_t *h);
idemip_bool idemip_ip4_df(const uint8_t *h);
idemip_bool idemip_ip4_mf(const uint8_t *h);
uint16_t idemip_ip4_frag_units(const uint8_t *h);
uint32_t idemip_ip4_frag_offset_bytes(const uint8_t *h);
idemip_bool idemip_ip4_is_fragment(const uint8_t *h);
uint8_t idemip_ip4_ttl(const uint8_t *h);
uint8_t idemip_ip4_proto(const uint8_t *h);
uint16_t idemip_ip4_cksum(const uint8_t *h);
uint32_t idemip_ip4_src(const uint8_t *h);
uint32_t idemip_ip4_dst(const uint8_t *h);
uint16_t idemip_ip4_payload_len(const uint8_t *h);
const uint8_t *idemip_ip4_options(const uint8_t *h);
size_t idemip_ip4_options_len(const uint8_t *h);

void idemip_ip4_set_ver_ihl(uint8_t *h, uint8_t ihl);
void idemip_ip4_set_tos(uint8_t *h, uint8_t tos);
void idemip_ip4_set_total_len(uint8_t *h, uint16_t len);
void idemip_ip4_set_id(uint8_t *h, uint16_t id);
void idemip_ip4_set_flags_frag(uint8_t *h, uint16_t flags_frag);
void idemip_ip4_set_ttl(uint8_t *h, uint8_t ttl);
void idemip_ip4_set_proto(uint8_t *h, uint8_t proto);
void idemip_ip4_set_cksum(uint8_t *h, uint16_t sum);
void idemip_ip4_set_src(uint8_t *h, uint32_t addr);
void idemip_ip4_set_dst(uint8_t *h, uint32_t addr);
void idemip_ip4_recksum(uint8_t *h);
void idemip_ip4_build(uint8_t *h, const IdemIpIp4Fields *f);

idemip_bool idemip_ip4_version_ok(const uint8_t *h);
idemip_bool idemip_ip4_ihl_ok(const uint8_t *h);
idemip_bool idemip_ip4_len_ok(const uint8_t *h, size_t avail);
idemip_bool idemip_ip4_cksum_ok(const uint8_t *h);
IdemIpStatus idemip_ip4_verify(const uint8_t *h, size_t avail);

uint8_t idemip_ip4_addr_mask_ones(uint32_t mask);
idemip_bool idemip_ip4_addr_mask_contiguous(uint32_t mask);
/** @} */

/**
 * @brief The module namespaces.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS Ip4ReadNs ip4_read IDEMIP_UNUSED = {
    .version = idemip_ip4_version,
    .ihl = idemip_ip4_ihl,
    .hdr_len = idemip_ip4_hdr_len,
    .tos = idemip_ip4_tos,
    .total_len = idemip_ip4_total_len,
    .id = idemip_ip4_id,
    .flags_frag = idemip_ip4_flags_frag,
    .reserved = idemip_ip4_reserved,
    .df = idemip_ip4_df,
    .mf = idemip_ip4_mf,
    .frag_units = idemip_ip4_frag_units,
    .frag_offset_bytes = idemip_ip4_frag_offset_bytes,
    .is_fragment = idemip_ip4_is_fragment,
    .ttl = idemip_ip4_ttl,
    .proto = idemip_ip4_proto,
    .cksum = idemip_ip4_cksum,
    .src = idemip_ip4_src,
    .dst = idemip_ip4_dst,
    .payload_len = idemip_ip4_payload_len,
    .options = idemip_ip4_options,
    .options_len = idemip_ip4_options_len,
};

IDEMIP_NS Ip4WriteNs ip4_write IDEMIP_UNUSED = {
    .set_ver_ihl = idemip_ip4_set_ver_ihl,
    .set_tos = idemip_ip4_set_tos,
    .set_total_len = idemip_ip4_set_total_len,
    .set_id = idemip_ip4_set_id,
    .set_flags_frag = idemip_ip4_set_flags_frag,
    .set_ttl = idemip_ip4_set_ttl,
    .set_proto = idemip_ip4_set_proto,
    .set_cksum = idemip_ip4_set_cksum,
    .set_src = idemip_ip4_set_src,
    .set_dst = idemip_ip4_set_dst,
    .recksum = idemip_ip4_recksum,
    .build = idemip_ip4_build,
};

IDEMIP_NS Ip4VerifyNs ip4_verify IDEMIP_UNUSED = {
    .version_ok = idemip_ip4_version_ok,
    .ihl_ok = idemip_ip4_ihl_ok,
    .len_ok = idemip_ip4_len_ok,
    .cksum_ok = idemip_ip4_cksum_ok,
    .verify = idemip_ip4_verify,
};

IDEMIP_NS Ip4MaskNs ip4_mask IDEMIP_UNUSED = {
    .ones = idemip_ip4_addr_mask_ones,
    .contiguous = idemip_ip4_addr_mask_contiguous,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_IPV4_H
