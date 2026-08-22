// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ethernet.h
 * @brief Ethernet II framing, as RFC 894 defines it for IP.
 *
 * A frame is read where the DMA engine left it and built where the engine will read it, so nothing
 * here holds or copies one. The addresses are handed back as pointers into the caller's frame, so
 * reading a field copies nothing.
 *
 * This is the root of the feature tree: every other capability names it as the parent it sits on.
 * The frame layout itself - the offsets, the type codes, the RFC 1042 LLC and SNAP values - is in
 * ethernet.c, which is the first translation unit that uses it. Nothing downstream reads the
 * layout; it reaches a field through an entry below.
 *
 * The tables are the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_ETHERNET_H
#define IDEMIP_ETHERNET_H

#include "src/common.h"

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/** @brief Type field values: RFC 894 IPv4, RFC 1042 ARP, RFC 2464 IPv6. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ETHERTYPE_IPV4 = 0x0800, ///< RFC 894: "must contain the value hexadecimal 0800"
    IDEMIP_ETHERTYPE_ARP = 0x0806,  ///< RFC 1042 "Frame Format": "the EtherType ... ARP = 2054"
    IDEMIP_ETHERTYPE_IPV6 = 0x86DD, ///< RFC 2464 sec 3: "must contain the value 86DD hexadecimal"
} IdemIpEtherType;

/**
 * @brief Reading a frame where the engine left it.
 *
 * RFC 894 "Frame Format" names the type field and the data field but prints no figure. RFC 2464
 * sec 3 draws the header this framing shares: "The Ethernet header contains the Destination and
 * Source Ethernet addresses and the Ethernet type code", in that order, two 48-bit addresses then
 * one 16-bit type code.
 */
typedef struct
{
    const uint8_t *(*dst)(const uint8_t *h);
    const uint8_t *(*src)(const uint8_t *h);
    uint16_t (*type)(const uint8_t *h);
    const uint8_t *(*payload)(const uint8_t *h);
    idemip_bool (*is_broadcast)(const uint8_t *mac);
    idemip_bool (*llc_is_snap)(const uint8_t *p);
} EthParseNs;
IDEMIP_NS_LAYOUT(EthParseNs, dst, src, type, payload, is_broadcast, llc_is_snap);

/**
 * @brief Building a frame where the engine will read it, and the RFC 894 pad.
 *
 * RFC 894: "The minimum length of the data field of a packet sent over an Ethernet is 46 octets.
 * If necessary, the data field should be padded (with octets of zero) to meet the Ethernet minimum
 * frame size. This padding is not part of the IP packet and is not included in the total length
 * field of the IP header." A receiver therefore takes the length from the IP header, never from
 * the frame.
 */
typedef struct
{
    void (*build)(uint8_t *h, const uint8_t *dst, const uint8_t *src, uint16_t type);
    size_t (*padded_payload)(size_t payload_len);
    size_t (*frame_len)(size_t payload_len);
    size_t (*pad)(uint8_t *h, size_t payload_len);
} EthBuildNs;
IDEMIP_NS_LAYOUT(EthBuildNs, build, padded_payload, frame_len, pad);

/** @name The entries the tables point at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The tables are
 *         still the whole surface: call through them.
 *  @{ */
const uint8_t *idemip_eth_dst(const uint8_t *h);
const uint8_t *idemip_eth_src(const uint8_t *h);
uint16_t idemip_eth_type(const uint8_t *h);
const uint8_t *idemip_eth_payload(const uint8_t *h);
idemip_bool idemip_eth_is_broadcast(const uint8_t *mac);
idemip_bool idemip_llc_is_snap(const uint8_t *p);

void idemip_eth_build(uint8_t *h, const uint8_t *dst, const uint8_t *src, uint16_t type);
size_t idemip_eth_padded_payload(size_t payload_len);
size_t idemip_eth_frame_len(size_t payload_len);
size_t idemip_eth_pad(uint8_t *h, size_t payload_len);
/** @} */

/**
 * @brief The module namespaces.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS EthParseNs eth_parse IDEMIP_UNUSED = {
    .dst = idemip_eth_dst,
    .src = idemip_eth_src,
    .type = idemip_eth_type,
    .payload = idemip_eth_payload,
    .is_broadcast = idemip_eth_is_broadcast,
    .llc_is_snap = idemip_llc_is_snap,
};

IDEMIP_NS EthBuildNs eth_build IDEMIP_UNUSED = {
    .build = idemip_eth_build,
    .padded_payload = idemip_eth_padded_payload,
    .frame_len = idemip_eth_frame_len,
    .pad = idemip_eth_pad,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_ETHERNET_H
