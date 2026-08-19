// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ethernet.h
 * @brief Ethernet II framing, as RFC 894 defines it for IP.
 *
 * Constants, field offsets, and accessors over the caller's bytes. A frame is read where the DMA
 * engine left it and built where the engine will read it, so nothing here holds or copies one.
 */

#ifndef IDEMIP_ETHERNET_H
#define IDEMIP_ETHERNET_H

#include "src/common.h"

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/** @brief An Ethernet address: 48 bits (RFC 894 "48-bit addresses"). */
#define IDEMIP_MAC_LEN 6u

/**
 * @brief Ethernet II header: destination, source, type. The FCS is the link's, not ours.
 *
 * RFC 894: "IP datagrams are transmitted in standard Ethernet frames. The type field of the
 * Ethernet frame must contain the value hexadecimal 0800. The data field contains the IP header
 * followed immediately by the IP data."
 */
#define IDEMIP_ETH_HDR_LEN 14u

// ---------------------------------------------------------------------------
// Field offsets
// ---------------------------------------------------------------------------
// RFC 894 "Frame Format" names the type field and the data field but prints no figure. RFC 2464
// sec 3 draws the header this framing shares: "The Ethernet header contains the Destination and
// Source Ethernet addresses and the Ethernet type code", in that order, two 48-bit addresses then
// one 16-bit type code.

#define IDEMIP_ETH_OFF_DST 0u      ///< Destination Ethernet Address, IDEMIP_MAC_LEN bytes
#define IDEMIP_ETH_OFF_SRC 6u      ///< Source Ethernet Address, IDEMIP_MAC_LEN bytes
#define IDEMIP_ETH_OFF_TYPE 12u    ///< 16-bit Ethernet type code
#define IDEMIP_ETH_OFF_PAYLOAD 14u ///< the data field

/** @brief The type code is 16 bits wide (RFC 2464 sec 3). */
#define IDEMIP_ETH_TYPE_LEN 2u

/** @brief Type field values: RFC 894 IPv4, RFC 1042 ARP, RFC 2464 IPv6. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ETHERTYPE_IPV4 = 0x0800, ///< RFC 894: "must contain the value hexadecimal 0800"
    IDEMIP_ETHERTYPE_ARP = 0x0806,  ///< RFC 1042 "Frame Format": "the EtherType ... ARP = 2054"
    IDEMIP_ETHERTYPE_IPV6 = 0x86DD, ///< RFC 2464 sec 3: "must contain the value 86DD hexadecimal"
} IdemIpEtherType;

/**
 * @brief Smallest data field a frame may carry (RFC 894).
 *
 * "The minimum length of the data field of a packet sent over an Ethernet is 46 octets. If
 * necessary, the data field should be padded (with octets of zero) to meet the Ethernet minimum
 * frame size. This padding is not part of the IP packet and is not included in the total length
 * field of the IP header." A receiver therefore takes the length from the IP header, never from
 * the frame.
 */
#define IDEMIP_ETH_MIN_PAYLOAD 46u

/**
 * @brief Largest data field a frame may carry (RFC 894).
 *
 * "the maximum length of an IP datagram sent over an Ethernet is 1500 octets. Implementations are
 * encouraged to support full-length packets."
 */
#define IDEMIP_ETH_MAX_PAYLOAD 1500u

/** @brief Whole frame on the wire, header included. The FCS is added and checked by the MAC. */
#define IDEMIP_ETH_FRAME_MAX (IDEMIP_ETH_HDR_LEN + IDEMIP_ETH_MAX_PAYLOAD)

/** @brief Shortest frame on the wire, the RFC 894 pad included. */
#define IDEMIP_ETH_FRAME_MIN (IDEMIP_ETH_HDR_LEN + IDEMIP_ETH_MIN_PAYLOAD)

/** @brief Every octet of the broadcast address (RFC 894: "all binary ones, FF-FF-FF-FF-FF-FF hex"). */
#define IDEMIP_ETH_BROADCAST_OCTET 0xFFu

// ---------------------------------------------------------------------------
// Parse: the addresses stay where they landed, the type is assembled from its bytes
// ---------------------------------------------------------------------------
// A frame starts wherever the engine wrote it, so the type code is read one byte at a time and the
// result does not depend on that address. The addresses are handed back as pointers into the frame,
// so reading a field copies nothing.

/** @brief Destination Ethernet Address, IDEMIP_MAC_LEN bytes in the caller's frame. */
IDEMIP_INLINE const uint8_t *idemip_eth_dst(const uint8_t *h)
{
    return h + IDEMIP_ETH_OFF_DST;
}

/** @brief Source Ethernet Address, IDEMIP_MAC_LEN bytes in the caller's frame. */
IDEMIP_INLINE const uint8_t *idemip_eth_src(const uint8_t *h)
{
    return h + IDEMIP_ETH_OFF_SRC;
}

/** @brief The type code, assembled from its two octets. */
IDEMIP_INLINE uint16_t idemip_eth_type(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_ETH_OFF_TYPE);
}

/** @brief The data field: the IP header followed immediately by the IP data (RFC 894). */
IDEMIP_INLINE const uint8_t *idemip_eth_payload(const uint8_t *h)
{
    return h + IDEMIP_ETH_OFF_PAYLOAD;
}

/** @brief True when every octet of @p mac is ones, which is the RFC 894 broadcast address. */
IDEMIP_INLINE idemip_bool idemip_eth_is_broadcast(const uint8_t *mac)
{
    return (idemip_bool)((mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == IDEMIP_ETH_BROADCAST_OCTET);
}

// ---------------------------------------------------------------------------
// Build: fourteen octets into the caller's buffer, then the RFC 894 pad
// ---------------------------------------------------------------------------

/** @brief Write the header at @p h: @p dst, @p src, then @p type. IDEMIP_ETH_HDR_LEN bytes. */
IDEMIP_INLINE void idemip_eth_build(uint8_t *h, const uint8_t *dst, const uint8_t *src, uint16_t type)
{
    memcpy(h + IDEMIP_ETH_OFF_DST, dst, IDEMIP_MAC_LEN);
    memcpy(h + IDEMIP_ETH_OFF_SRC, src, IDEMIP_MAC_LEN);
    idemip_wr16(h + IDEMIP_ETH_OFF_TYPE, type);
}

/** @brief Data field length RFC 894 sends for @p payload_len octets: under 46 goes out as 46. */
IDEMIP_INLINE size_t idemip_eth_padded_payload(size_t payload_len)
{
    return (payload_len < IDEMIP_ETH_MIN_PAYLOAD) ? (size_t)IDEMIP_ETH_MIN_PAYLOAD : payload_len;
}

/** @brief Frame length for @p payload_len octets of data, header and pad included. */
IDEMIP_INLINE size_t idemip_eth_frame_len(size_t payload_len)
{
    return IDEMIP_ETH_HDR_LEN + idemip_eth_padded_payload(payload_len);
}

/**
 * @brief Zero the pad after @p payload_len octets of data at @p h, and report the data length.
 *
 * RFC 894: "the data field should be padded (with octets of zero) to meet the Ethernet minimum
 * frame size." Reaches IDEMIP_ETH_FRAME_MIN bytes from @p h.
 */
IDEMIP_INLINE size_t idemip_eth_pad(uint8_t *h, size_t payload_len)
{
    size_t padded = idemip_eth_padded_payload(payload_len);
    memset(h + IDEMIP_ETH_OFF_PAYLOAD + payload_len, 0, padded - payload_len);
    return padded;
}

static_assert(IDEMIP_ETH_OFF_DST + IDEMIP_MAC_LEN == IDEMIP_ETH_OFF_SRC,
              "the destination address is the first 48 bits of the header (RFC 2464 sec 3)");
static_assert(IDEMIP_ETH_OFF_SRC + IDEMIP_MAC_LEN == IDEMIP_ETH_OFF_TYPE,
              "the source address is the second 48 bits of the header (RFC 2464 sec 3)");
static_assert(IDEMIP_ETH_OFF_TYPE + IDEMIP_ETH_TYPE_LEN == IDEMIP_ETH_OFF_PAYLOAD,
              "the type code is the last 16 bits of the header (RFC 2464 sec 3)");
static_assert(IDEMIP_ETH_OFF_PAYLOAD == IDEMIP_ETH_HDR_LEN,
              "the field offsets must sum to the Ethernet II header length");

// RFC 894 encourages full-length packets, and a receiver that cannot take one has to advertise a
// smaller MSS instead. The link buffer therefore carries a whole frame or the tree does not build.
static_assert(IDEMIP_ETH_MAX_PAYLOAD >= IDEMIP_IPV4_MIN_MTU,
              "an Ethernet frame carries at least the IPv4 minimum reassembly buffer (RFC 1122 sec 3.3.2)");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_ETHERNET_H
