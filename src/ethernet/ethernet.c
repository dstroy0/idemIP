// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ethernet.c
 * @brief Ethernet II framing, as RFC 894 defines it for IP.
 *
 * Every entry below takes one parameter, a pointer to EthCtx. A frame access is the bytes and,
 * when it builds, what goes into them, so those are one context.
 *
 * The frame layout lives here rather than in the header. ethernet is the root of the feature tree,
 * so this is the first translation unit that uses it, and a define has no scope: in the header it
 * would be visible to every capability that grows from this one, and each of them could re-derive
 * a field instead of asking for it.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/ethernet/ethernet.h"
#include "src/ethernet/ethernet_defines.h" // the frame layout this file is the first user of

#if IDEMIP_ENABLE_ETHERNET


IDEMIP_BEGIN_DECLS

/** @brief One frame access. */
typedef struct
{
    const uint8_t *h;   /**< The frame a read takes its fields out of, or the LLC header. */
    uint8_t *w;         /**< The frame a build writes into. */
    const uint8_t *dst; /**< Destination address a build writes. */
    const uint8_t *src; /**< Source address a build writes. */
    size_t payload_len; /**< Octets of data, before the RFC 894 pad. */
    uint16_t type;      /**< The type code a build writes. */
} EthCtx;

/** @brief Destination Ethernet Address, IDEMIP_MAC_LEN bytes in the caller's frame. */
IDEMIP_INLINE const uint8_t *eth_dst(const EthCtx *c)
{
    return c->h + IDEMIP_ETH_OFF_DST;
}

/** @brief Source Ethernet Address, IDEMIP_MAC_LEN bytes in the caller's frame. */
IDEMIP_INLINE const uint8_t *eth_src(const EthCtx *c)
{
    return c->h + IDEMIP_ETH_OFF_SRC;
}

/**
 * @brief The type code, assembled from its two octets.
 *
 * A frame starts wherever the engine wrote it, so the type code is read one byte at a time and the
 * result does not depend on that address.
 */
IDEMIP_INLINE uint16_t eth_type(const EthCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_ETH_OFF_TYPE);
}

/** @brief The data field: the IP header followed immediately by the IP data (RFC 894). */
IDEMIP_INLINE const uint8_t *eth_payload(const EthCtx *c)
{
    return c->h + IDEMIP_ETH_OFF_PAYLOAD;
}

/** @brief True when every octet is ones, which is the RFC 894 broadcast address. */
IDEMIP_INLINE idemip_bool eth_is_broadcast(const EthCtx *c)
{
    const uint8_t *m = c->h;
    return (idemip_bool)((m[0] & m[1] & m[2] & m[3] & m[4] & m[5]) == IDEMIP_ETH_BROADCAST_OCTET);
}

/** @brief True for the eight octets RFC 1042 puts an EtherType behind. The LLC header is read. */
IDEMIP_INLINE idemip_bool llc_is_snap(const EthCtx *c)
{
    const uint8_t *p = c->h;
    return (p[IDEMIP_LLC_OFF_DSAP] == (uint8_t)IDEMIP_LLC_SAP_SNAP &&
            p[IDEMIP_LLC_OFF_SSAP] == (uint8_t)IDEMIP_LLC_SAP_SNAP &&
            p[IDEMIP_LLC_OFF_CONTROL] == (uint8_t)IDEMIP_LLC_CONTROL_UI && p[IDEMIP_LLC_OFF_ORG] == 0u &&
            p[IDEMIP_LLC_OFF_ORG + 1u] == 0u && p[IDEMIP_LLC_OFF_ORG + 2u] == 0u)
               ? IDEMIP_TRUE
               : IDEMIP_FALSE;
}

/** @brief Write the header: destination, source, then type. IDEMIP_ETH_HDR_LEN bytes. */
IDEMIP_INLINE void eth_build_hdr(const EthCtx *c)
{
    memcpy(c->w + IDEMIP_ETH_OFF_DST, c->dst, IDEMIP_MAC_LEN);
    memcpy(c->w + IDEMIP_ETH_OFF_SRC, c->src, IDEMIP_MAC_LEN);
    idemip_wr16(c->w + IDEMIP_ETH_OFF_TYPE, c->type);
}

/** @brief Data field length RFC 894 sends for the given octets: under 46 goes out as 46. */
IDEMIP_INLINE size_t eth_padded_payload(const EthCtx *c)
{
    return (c->payload_len < IDEMIP_ETH_MIN_PAYLOAD) ? (size_t)IDEMIP_ETH_MIN_PAYLOAD : c->payload_len;
}

/** @brief Frame length for that many octets of data, header and pad included. */
IDEMIP_INLINE size_t eth_frame_len(const EthCtx *c)
{
    return IDEMIP_ETH_HDR_LEN + eth_padded_payload(c);
}

/**
 * @brief Zero the pad after the data and report the data length.
 *
 * RFC 894: "the data field should be padded (with octets of zero) to meet the Ethernet minimum
 * frame size." Reaches IDEMIP_ETH_FRAME_MIN bytes from the frame.
 */
IDEMIP_INLINE size_t eth_pad(const EthCtx *c)
{
    size_t padded = eth_padded_payload(c);
    memset(c->w + IDEMIP_ETH_OFF_PAYLOAD + c->payload_len, 0, padded - c->payload_len);
    return padded;
}

/* The namespaces are tables of function pointers with the caller's argument lists in their types,
   so these are what they point at. Each builds the context and hands it to the body above. */

const uint8_t *idemip_eth_dst(const uint8_t *h)
{
    return IDEMIP_CALL(eth_dst, EthCtx, .h = h);
}

const uint8_t *idemip_eth_src(const uint8_t *h)
{
    return IDEMIP_CALL(eth_src, EthCtx, .h = h);
}

uint16_t idemip_eth_type(const uint8_t *h)
{
    return IDEMIP_CALL(eth_type, EthCtx, .h = h);
}

const uint8_t *idemip_eth_payload(const uint8_t *h)
{
    return IDEMIP_CALL(eth_payload, EthCtx, .h = h);
}

idemip_bool idemip_eth_is_broadcast(const uint8_t *mac)
{
    return IDEMIP_CALL(eth_is_broadcast, EthCtx, .h = mac);
}

idemip_bool idemip_llc_is_snap(const uint8_t *p)
{
    return IDEMIP_CALL(llc_is_snap, EthCtx, .h = p);
}

void idemip_eth_build(uint8_t *h, const uint8_t *dst, const uint8_t *src, uint16_t type)
{
    IDEMIP_CALL(eth_build_hdr, EthCtx, .w = h, .dst = dst, .src = src, .type = type);
}

size_t idemip_eth_padded_payload(size_t payload_len)
{
    return IDEMIP_CALL(eth_padded_payload, EthCtx, .payload_len = payload_len);
}

size_t idemip_eth_frame_len(size_t payload_len)
{
    return IDEMIP_CALL(eth_frame_len, EthCtx, .payload_len = payload_len);
}

size_t idemip_eth_pad(uint8_t *h, size_t payload_len)
{
    return IDEMIP_CALL(eth_pad, EthCtx, .w = h, .payload_len = payload_len);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET
