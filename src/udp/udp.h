// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file udp.h
 * @brief The user datagram header, RFC 768, and the UDP-Lite variant of it, RFC 3828.
 *
 * The field offsets and the protocol numbers are udp_defines.h, which a .c includes when it
 * genuinely needs the numbers. A caller that wants a field asks for it here.
 *
 * The tables are the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_UDP_H
#define IDEMIP_UDP_H

#include "src/checksum.h"

#if IDEMIP_ENABLE_UDP

IDEMIP_BEGIN_DECLS

/**
 * @brief Reading a received datagram.
 *
 * The header starts 20 bytes into an option-free IPv4 header that itself starts 14 bytes into an
 * Ethernet frame, so a field lands at an even offset from an odd address and is assembled from its
 * bytes.
 */
typedef struct
{
    uint16_t (*src_port)(const uint8_t *h);
    uint16_t (*dst_port)(const uint8_t *h);
    uint16_t (*len)(const uint8_t *h);
    uint16_t (*cksum)(const uint8_t *h);
    idemip_bool (*len_valid)(const uint8_t *h);
    uint16_t (*payload_len)(const uint8_t *h);
    idemip_bool (*cksum_present)(const uint8_t *h);
} UdpReadNs;
IDEMIP_NS_LAYOUT(UdpReadNs, src_port, dst_port, len, cksum, len_valid, payload_len, cksum_present);

/** @brief Writing the four fields into the caller's bytes. */
typedef struct
{
    void (*set_src_port)(uint8_t *h, uint16_t port);
    void (*set_dst_port)(uint8_t *h, uint16_t port);
    void (*set_len)(uint8_t *h, uint16_t len);
    void (*set_cksum)(uint8_t *h, uint16_t cksum);
    void (*build)(uint8_t *h, uint16_t src_port, uint16_t dst_port, uint16_t len);
} UdpWriteNs;
IDEMIP_NS_LAYOUT(UdpWriteNs, set_src_port, set_dst_port, set_len, set_cksum, build);

/**
 * @brief The checksum RFC 768 "Fields" defines, over the pseudo-header and the datagram.
 *
 * The pseudo-header is not part of the datagram: it is summed, never sent.
 */
typedef struct
{
    uint32_t (*pseudo_accum)(uint32_t sum, uint32_t src, uint32_t dst, uint16_t udp_len, uint8_t proto);
    uint16_t (*compute)(const uint8_t *h, size_t len, uint32_t src, uint32_t dst);
    void (*write)(uint8_t *h, size_t len, uint32_t src, uint32_t dst);
    idemip_bool (*valid)(const uint8_t *h, size_t len, uint32_t src, uint32_t dst);
} UdpCksumNs;
IDEMIP_NS_LAYOUT(UdpCksumNs, pseudo_accum, compute, write, valid);

/** @brief UDP-Lite, RFC 3828: Length becomes Checksum Coverage, and the sum spans only that. */
typedef struct
{
    uint16_t (*cov)(const uint8_t *h);
    void (*set_cov)(uint8_t *h, uint16_t cov);
    void (*build)(uint8_t *h, uint16_t src_port, uint16_t dst_port, uint16_t cov);
    size_t (*cov_bytes)(uint16_t cov, uint16_t ip_payload_len);
    idemip_bool (*cov_valid)(uint16_t cov, uint16_t ip_payload_len);
    uint16_t (*compute)(const uint8_t *h, uint16_t cov, uint16_t ip_payload_len, uint32_t src, uint32_t dst);
    void (*write)(uint8_t *h, uint16_t cov, uint16_t ip_payload_len, uint32_t src, uint32_t dst);
    idemip_bool (*valid)(const uint8_t *h, uint16_t cov, uint16_t ip_payload_len, uint32_t src, uint32_t dst);
} UdpLiteWireNs;
IDEMIP_NS_LAYOUT(UdpLiteWireNs, cov, set_cov, build, cov_bytes, cov_valid, compute, write, valid);

/** @name The entries the tables point at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The tables are
 *         still the whole surface: call through them.
 *  @{ */
uint16_t idemip_udp_src_port(const uint8_t *h);
uint16_t idemip_udp_dst_port(const uint8_t *h);
uint16_t idemip_udp_len(const uint8_t *h);
uint16_t idemip_udp_cksum(const uint8_t *h);
idemip_bool idemip_udp_len_valid(const uint8_t *h);
uint16_t idemip_udp_payload_len(const uint8_t *h);
idemip_bool idemip_udp_cksum_present(const uint8_t *h);

void idemip_udp_set_src_port(uint8_t *h, uint16_t port);
void idemip_udp_set_dst_port(uint8_t *h, uint16_t port);
void idemip_udp_set_len(uint8_t *h, uint16_t len);
void idemip_udp_set_cksum(uint8_t *h, uint16_t cksum);
void idemip_udp_build(uint8_t *h, uint16_t src_port, uint16_t dst_port, uint16_t len);

uint32_t idemip_udp_pseudo_accum(uint32_t sum, uint32_t src, uint32_t dst, uint16_t udp_len, uint8_t proto);
uint16_t idemip_udp_cksum_compute(const uint8_t *h, size_t len, uint32_t src, uint32_t dst);
void idemip_udp_cksum_write(uint8_t *h, size_t len, uint32_t src, uint32_t dst);
idemip_bool idemip_udp_cksum_valid(const uint8_t *h, size_t len, uint32_t src, uint32_t dst);

uint16_t idemip_udplite_cov(const uint8_t *h);
void idemip_udplite_set_cov(uint8_t *h, uint16_t cov);
void idemip_udplite_build(uint8_t *h, uint16_t src_port, uint16_t dst_port, uint16_t cov);
size_t idemip_udplite_cov_bytes(uint16_t cov, uint16_t ip_payload_len);
idemip_bool idemip_udplite_cov_valid(uint16_t cov, uint16_t ip_payload_len);
uint16_t idemip_udplite_cksum_compute(const uint8_t *h, uint16_t cov, uint16_t ip_payload_len, uint32_t src,
                                      uint32_t dst);
void idemip_udplite_cksum_write(uint8_t *h, uint16_t cov, uint16_t ip_payload_len, uint32_t src, uint32_t dst);
idemip_bool idemip_udplite_cksum_valid(const uint8_t *h, uint16_t cov, uint16_t ip_payload_len, uint32_t src,
                                       uint32_t dst);
/** @} */

/**
 * @brief The module namespaces.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS UdpReadNs udp_read IDEMIP_UNUSED = {
    .src_port = idemip_udp_src_port,
    .dst_port = idemip_udp_dst_port,
    .len = idemip_udp_len,
    .cksum = idemip_udp_cksum,
    .len_valid = idemip_udp_len_valid,
    .payload_len = idemip_udp_payload_len,
    .cksum_present = idemip_udp_cksum_present,
};

IDEMIP_NS UdpWriteNs udp_write IDEMIP_UNUSED = {
    .set_src_port = idemip_udp_set_src_port,
    .set_dst_port = idemip_udp_set_dst_port,
    .set_len = idemip_udp_set_len,
    .set_cksum = idemip_udp_set_cksum,
    .build = idemip_udp_build,
};

IDEMIP_NS UdpCksumNs udp_cksum IDEMIP_UNUSED = {
    .pseudo_accum = idemip_udp_pseudo_accum,
    .compute = idemip_udp_cksum_compute,
    .write = idemip_udp_cksum_write,
    .valid = idemip_udp_cksum_valid,
};

IDEMIP_NS UdpLiteWireNs udplite_wire IDEMIP_UNUSED = {
    .cov = idemip_udplite_cov,
    .set_cov = idemip_udplite_set_cov,
    .build = idemip_udplite_build,
    .cov_bytes = idemip_udplite_cov_bytes,
    .cov_valid = idemip_udplite_cov_valid,
    .compute = idemip_udplite_cksum_compute,
    .write = idemip_udplite_cksum_write,
    .valid = idemip_udplite_cksum_valid,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_UDP

#endif // IDEMIP_UDP_H
