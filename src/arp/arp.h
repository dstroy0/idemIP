// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file arp.h
 * @brief Address resolution, RFC 826: a protocol address to a 48-bit Ethernet address.
 *
 * The packet layout is arp_defines.h, which a .c includes when it genuinely needs the numbers. A
 * caller that wants a field asks for it here.
 *
 * The tables are the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_ARP_H
#define IDEMIP_ARP_H

#include "src/endian.h"
#include "src/ethernet/ethernet.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/** @brief Opcode (ar$op). RFC 826: ares_op$REQUEST | ares_op$REPLY. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ARP_OP_REQUEST = 1,
    IDEMIP_ARP_OP_REPLY = 2,
} IdemIpArpOp;

/**
 * @brief Reading the fields out of a received packet, and the questions RFC 826 "Packet Reception"
 *        asks of them.
 *
 * RFC 826 "Why is it done this way??": "The packet data should be viewed as a byte stream in which
 * only 3 byte pairs are defined to be words (ar$hrd, ar$pro and ar$op) which are sent most
 * significant byte first". Those three are assembled from their two octets; the addresses are byte
 * streams, so ar$spa and ar$tpa are assembled from their four and ar$sha and ar$tha stay where they
 * lie.
 */
typedef struct
{
    uint16_t (*hrd)(const uint8_t *h);
    uint16_t (*pro)(const uint8_t *h);
    uint8_t (*hln)(const uint8_t *h);
    uint8_t (*pln)(const uint8_t *h);
    uint16_t (*op)(const uint8_t *h);
    const uint8_t *(*sha)(const uint8_t *h);
    uint32_t (*spa)(const uint8_t *h);
    const uint8_t *(*tha)(const uint8_t *h);
    uint32_t (*tpa)(const uint8_t *h);
    idemip_bool (*is_ethernet_ipv4)(const uint8_t *h);
    idemip_bool (*is_request)(const uint8_t *h);
    idemip_bool (*is_reply)(const uint8_t *h);
    idemip_bool (*is_target)(const uint8_t *h, uint32_t pa);
} ArpParseNs;
IDEMIP_NS_LAYOUT(ArpParseNs, hrd, pro, hln, pln, op, sha, spa, tha, tpa, is_ethernet_ipv4, is_request, is_reply,
                 is_target);

/**
 * @brief Writing a packet into the caller's bytes.
 *
 * The caller owns IDEMIP_ARP_LEN bytes and every entry here writes all of them.
 */
typedef struct
{
    void (*build)(uint8_t *p, uint16_t op, const uint8_t *sha, uint32_t spa, uint32_t tpa);
    void (*request)(uint8_t *p, const uint8_t *sha, uint32_t spa, uint32_t tpa);
    void (*reply)(uint8_t *p, const uint8_t *sha, uint32_t spa, const uint8_t *tha, uint32_t tpa);
    void (*reply_in_place)(uint8_t *p, const uint8_t *local_sha);
} ArpBuildNs;
IDEMIP_NS_LAYOUT(ArpBuildNs, build, request, reply, reply_in_place);

/** @name The entries the tables point at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The tables are
 *         still the whole surface: call through them.
 *  @{ */
uint16_t idemip_arp_hrd(const uint8_t *h);
uint16_t idemip_arp_pro(const uint8_t *h);
uint8_t idemip_arp_hln(const uint8_t *h);
uint8_t idemip_arp_pln(const uint8_t *h);
uint16_t idemip_arp_op(const uint8_t *h);
const uint8_t *idemip_arp_sha(const uint8_t *h);
uint32_t idemip_arp_spa(const uint8_t *h);
const uint8_t *idemip_arp_tha(const uint8_t *h);
uint32_t idemip_arp_tpa(const uint8_t *h);
idemip_bool idemip_arp_is_ethernet_ipv4(const uint8_t *h);
idemip_bool idemip_arp_is_request(const uint8_t *h);
idemip_bool idemip_arp_is_reply(const uint8_t *h);
idemip_bool idemip_arp_is_target(const uint8_t *h, uint32_t pa);

void idemip_arp_build(uint8_t *p, uint16_t op, const uint8_t *sha, uint32_t spa, uint32_t tpa);
void idemip_arp_build_request(uint8_t *p, const uint8_t *sha, uint32_t spa, uint32_t tpa);
void idemip_arp_build_reply(uint8_t *p, const uint8_t *sha, uint32_t spa, const uint8_t *tha, uint32_t tpa);
void idemip_arp_reply_in_place(uint8_t *p, const uint8_t *local_sha);
/** @} */

/**
 * @brief The module namespaces.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS ArpParseNs arp_parse IDEMIP_UNUSED = {
    .hrd = idemip_arp_hrd,
    .pro = idemip_arp_pro,
    .hln = idemip_arp_hln,
    .pln = idemip_arp_pln,
    .op = idemip_arp_op,
    .sha = idemip_arp_sha,
    .spa = idemip_arp_spa,
    .tha = idemip_arp_tha,
    .tpa = idemip_arp_tpa,
    .is_ethernet_ipv4 = idemip_arp_is_ethernet_ipv4,
    .is_request = idemip_arp_is_request,
    .is_reply = idemip_arp_is_reply,
    .is_target = idemip_arp_is_target,
};

IDEMIP_NS ArpBuildNs arp_build IDEMIP_UNUSED = {
    .build = idemip_arp_build,
    .request = idemip_arp_build_request,
    .reply = idemip_arp_build_reply,
    .reply_in_place = idemip_arp_reply_in_place,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_ARP_H
