// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file arp.c
 * @brief Address resolution, RFC 826, read out of the caller's bytes and written into them.
 *
 * Every entry below takes one parameter, a pointer to ArpCtx. A packet access is the octets and,
 * when it writes, the addresses going into them, so those are one context.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/arp/arp.h"
#include "src/arp/arp_defines.h" // the RFC 826 packet layout, which this file is the first user of

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/** @brief One packet access. */
typedef struct
{
    const uint8_t *h;   /**< The packet a read takes its fields out of. */
    uint8_t *w;         /**< The packet a build writes into. */
    const uint8_t *sha; /**< Sender hardware address a build writes, or the local one. */
    const uint8_t *tha; /**< Target hardware address a reply writes. */
    uint32_t spa;       /**< Sender protocol address a build writes. */
    uint32_t tpa;       /**< Target protocol address a build writes, or the one a test asks about. */
    uint16_t op;        /**< The opcode a build writes. */
} ArpCtx;

// --- reading a received packet ---------------------------------------------

/** @brief Hardware address space (ar$hrd). */
IDEMIP_INLINE uint16_t arp_hrd(const ArpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_ARP_OFF_HRD);
}

/** @brief Protocol address space (ar$pro). */
IDEMIP_INLINE uint16_t arp_pro(const ArpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_ARP_OFF_PRO);
}

/** @brief Byte length of each hardware address (ar$hln). */
IDEMIP_INLINE uint8_t arp_hln(const ArpCtx *c)
{
    return c->h[IDEMIP_ARP_OFF_HLN];
}

/** @brief Byte length of each protocol address (ar$pln). */
IDEMIP_INLINE uint8_t arp_pln(const ArpCtx *c)
{
    return c->h[IDEMIP_ARP_OFF_PLN];
}

/** @brief Opcode (ar$op). */
IDEMIP_INLINE uint16_t arp_op(const ArpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_ARP_OFF_OP);
}

/** @brief Sender hardware address (ar$sha), IDEMIP_ARP_HLN_ETHERNET bytes where they lie. */
IDEMIP_INLINE const uint8_t *arp_sha(const ArpCtx *c)
{
    return c->h + IDEMIP_ARP_OFF_SHA;
}

/** @brief Sender protocol address (ar$spa). */
IDEMIP_INLINE uint32_t arp_spa(const ArpCtx *c)
{
    return idemip_rd32(c->h + IDEMIP_ARP_OFF_SPA);
}

/** @brief Target hardware address (ar$tha), IDEMIP_ARP_HLN_ETHERNET bytes where they lie. */
IDEMIP_INLINE const uint8_t *arp_tha(const ArpCtx *c)
{
    return c->h + IDEMIP_ARP_OFF_THA;
}

/** @brief Target protocol address (ar$tpa). */
IDEMIP_INLINE uint32_t arp_tpa(const ArpCtx *c)
{
    return idemip_rd32(c->h + IDEMIP_ARP_OFF_TPA);
}

/**
 * @brief True when the packet is the <Ethernet, IPv4> pairing these offsets describe.
 *
 * RFC 826 "Packet Reception" asks "?Do I have the hardware type in ar$hrd?" and "?Do I speak the
 * protocol in ar$pro?", with "[optionally check the hardware length ar$hln]" and "[optionally check
 * the protocol length ar$pln]". Both lengths are checked here, because every offset is fixed at
 * ar$hln 6 and ar$pln 4 and a packet carrying other lengths puts its addresses elsewhere.
 */
IDEMIP_INLINE idemip_bool arp_is_ethernet_ipv4(const ArpCtx *c)
{
    return (idemip_bool)(arp_hrd(c) == IDEMIP_ARP_HRD_ETHERNET && arp_pro(c) == IDEMIP_ARP_PRO_IPV4 &&
                         arp_hln(c) == IDEMIP_ARP_HLN_ETHERNET && arp_pln(c) == IDEMIP_ARP_PLN_IPV4);
}

/** @brief RFC 826 "Packet Reception": "?Is the opcode ares_op$REQUEST?" */
IDEMIP_INLINE idemip_bool arp_is_request(const ArpCtx *c)
{
    return (idemip_bool)(arp_op(c) == (uint16_t)IDEMIP_ARP_OP_REQUEST);
}

/** @brief The reply form of the packet, ar$op ares_op$REPLY. */
IDEMIP_INLINE idemip_bool arp_is_reply(const ArpCtx *c)
{
    return (idemip_bool)(arp_op(c) == (uint16_t)IDEMIP_ARP_OP_REPLY);
}

/** @brief RFC 826 "Packet Reception": "?Am I the target protocol address?" */
IDEMIP_INLINE idemip_bool arp_is_target(const ArpCtx *c)
{
    return (idemip_bool)(arp_tpa(c) == c->tpa);
}

// --- writing a packet ------------------------------------------------------

/**
 * @brief Write every field but ar$tha, which the request and the reply fill differently.
 *
 * RFC 826 "Packet Generation" fixes ar$hrd to ares_hrd$Ethernet, ar$pro to the protocol being
 * resolved, ar$hln to 6 and ar$pln to the length of an address in that protocol.
 */
IDEMIP_INLINE void arp_build_pkt(const ArpCtx *c)
{
    idemip_wr16(c->w + IDEMIP_ARP_OFF_HRD, (uint16_t)IDEMIP_ARP_HRD_ETHERNET);
    idemip_wr16(c->w + IDEMIP_ARP_OFF_PRO, (uint16_t)IDEMIP_ARP_PRO_IPV4);
    c->w[IDEMIP_ARP_OFF_HLN] = (uint8_t)IDEMIP_ARP_HLN_ETHERNET;
    c->w[IDEMIP_ARP_OFF_PLN] = (uint8_t)IDEMIP_ARP_PLN_IPV4;
    idemip_wr16(c->w + IDEMIP_ARP_OFF_OP, c->op);
    memcpy(c->w + IDEMIP_ARP_OFF_SHA, c->sha, IDEMIP_ARP_HLN_ETHERNET);
    idemip_wr32(c->w + IDEMIP_ARP_OFF_SPA, c->spa);
    idemip_wr32(c->w + IDEMIP_ARP_OFF_TPA, c->tpa);
}

/**
 * @brief A request for the hardware address behind the target protocol address.
 *
 * RFC 826 "Packet Generation" sets "ar$op to ares_op$REQUEST, ar$sha with the 48.bit ethernet
 * address of itself, ar$spa with the protocol address of itself, and ar$tpa with the protocol
 * address of the machine that is trying to be accessed. It does not set ar$tha to anything in
 * particular, because it is this value that it is trying to determine." Zeroed here, so the bytes
 * are a function of the arguments alone.
 */
IDEMIP_INLINE void arp_request(const ArpCtx *c)
{
    idemip_arp_build(c->w, (uint16_t)IDEMIP_ARP_OP_REQUEST, c->sha, c->spa, c->tpa);
    memset(c->w + IDEMIP_ARP_OFF_THA, 0, IDEMIP_ARP_HLN_ETHERNET);
}

/**
 * @brief A reply carrying the sender hardware address behind the sender protocol address.
 *
 * RFC 826 "Why is it done this way??" on ar$tha: "Its meaning in the reply form is the address of
 * the machine making the request", and the target protocol address is that machine's.
 */
IDEMIP_INLINE void arp_reply(const ArpCtx *c)
{
    idemip_arp_build(c->w, (uint16_t)IDEMIP_ARP_OP_REPLY, c->sha, c->spa, c->tpa);
    memcpy(c->w + IDEMIP_ARP_OFF_THA, c->tha, IDEMIP_ARP_HLN_ETHERNET);
}

/**
 * @brief Turn a received request into its reply, in the bytes it arrived in.
 *
 * RFC 826 "Packet Reception", the request branch: "Swap hardware and protocol fields, putting the
 * local hardware and protocol addresses in the sender fields. Set the ar$op field to
 * ares_op$REPLY". "This format allows the packet buffer to be reused if a reply is generated; a
 * reply has the same length as a request, and several of the fields are the same."
 *
 * The swap moves ar$tpa into the sender field, and that branch is only reached once "?Am I the
 * target protocol address?" answered yes, so the local protocol address is what lands there.
 * ar$tha arrives don't care and is overwritten by the requester's ar$sha.
 */
IDEMIP_INLINE void arp_reply_in_place(const ArpCtx *c)
{
    uint32_t spa = idemip_rd32(c->w + IDEMIP_ARP_OFF_SPA);
    uint32_t tpa = idemip_rd32(c->w + IDEMIP_ARP_OFF_TPA);
    memcpy(c->w + IDEMIP_ARP_OFF_THA, c->w + IDEMIP_ARP_OFF_SHA, IDEMIP_ARP_HLN_ETHERNET);
    memcpy(c->w + IDEMIP_ARP_OFF_SHA, c->sha, IDEMIP_ARP_HLN_ETHERNET);
    idemip_wr32(c->w + IDEMIP_ARP_OFF_SPA, tpa);
    idemip_wr32(c->w + IDEMIP_ARP_OFF_TPA, spa);
    idemip_wr16(c->w + IDEMIP_ARP_OFF_OP, (uint16_t)IDEMIP_ARP_OP_REPLY);
}

/* The namespaces are tables of function pointers with the caller's argument lists in their types,
   so these are what they point at. Each builds the context and hands it to the body above. */

uint16_t idemip_arp_hrd(const uint8_t *h)
{
    return IDEMIP_CALL(arp_hrd, ArpCtx, .h = h);
}

uint16_t idemip_arp_pro(const uint8_t *h)
{
    return IDEMIP_CALL(arp_pro, ArpCtx, .h = h);
}

uint8_t idemip_arp_hln(const uint8_t *h)
{
    return IDEMIP_CALL(arp_hln, ArpCtx, .h = h);
}

uint8_t idemip_arp_pln(const uint8_t *h)
{
    return IDEMIP_CALL(arp_pln, ArpCtx, .h = h);
}

uint16_t idemip_arp_op(const uint8_t *h)
{
    return IDEMIP_CALL(arp_op, ArpCtx, .h = h);
}

const uint8_t *idemip_arp_sha(const uint8_t *h)
{
    return IDEMIP_CALL(arp_sha, ArpCtx, .h = h);
}

uint32_t idemip_arp_spa(const uint8_t *h)
{
    return IDEMIP_CALL(arp_spa, ArpCtx, .h = h);
}

const uint8_t *idemip_arp_tha(const uint8_t *h)
{
    return IDEMIP_CALL(arp_tha, ArpCtx, .h = h);
}

uint32_t idemip_arp_tpa(const uint8_t *h)
{
    return IDEMIP_CALL(arp_tpa, ArpCtx, .h = h);
}

idemip_bool idemip_arp_is_ethernet_ipv4(const uint8_t *h)
{
    return IDEMIP_CALL(arp_is_ethernet_ipv4, ArpCtx, .h = h);
}

idemip_bool idemip_arp_is_request(const uint8_t *h)
{
    return IDEMIP_CALL(arp_is_request, ArpCtx, .h = h);
}

idemip_bool idemip_arp_is_reply(const uint8_t *h)
{
    return IDEMIP_CALL(arp_is_reply, ArpCtx, .h = h);
}

idemip_bool idemip_arp_is_target(const uint8_t *h, uint32_t pa)
{
    return IDEMIP_CALL(arp_is_target, ArpCtx, .h = h, .tpa = pa);
}

void idemip_arp_build(uint8_t *p, uint16_t op, const uint8_t *sha, uint32_t spa, uint32_t tpa)
{
    IDEMIP_CALL(arp_build_pkt, ArpCtx, .w = p, .op = op, .sha = sha, .spa = spa, .tpa = tpa);
}

void idemip_arp_build_request(uint8_t *p, const uint8_t *sha, uint32_t spa, uint32_t tpa)
{
    IDEMIP_CALL(arp_request, ArpCtx, .w = p, .sha = sha, .spa = spa, .tpa = tpa);
}

void idemip_arp_build_reply(uint8_t *p, const uint8_t *sha, uint32_t spa, const uint8_t *tha, uint32_t tpa)
{
    IDEMIP_CALL(arp_reply, ArpCtx, .w = p, .sha = sha, .spa = spa, .tha = tha, .tpa = tpa);
}

void idemip_arp_reply_in_place(uint8_t *p, const uint8_t *local_sha)
{
    IDEMIP_CALL(arp_reply_in_place, ArpCtx, .w = p, .sha = local_sha);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4
