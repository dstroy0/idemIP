// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file arp.h
 * @brief Address resolution, RFC 826: a protocol address to a 48-bit Ethernet address.
 */

#ifndef IDEMIP_ARP_H
#define IDEMIP_ARP_H

#include "idemIP/endian.h"
#include "idemIP/ethernet/ethernet.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/**
 * @brief Hardware address space (ar$hrd). RFC 826 "Definitions": "ares_hrd$Ethernet (= 1)".
 */
#define IDEMIP_ARP_HRD_ETHERNET 1u

/**
 * @brief Protocol address space (ar$pro). RFC 826: "For Ethernet hardware, this is from the set of
 * type fields ether_typ$<protocol>", so IPv4 carries the Ethernet type value.
 */
#define IDEMIP_ARP_PRO_IPV4 IDEMIP_ETHERTYPE_IPV4

/** @brief Opcode (ar$op). RFC 826: ares_op$REQUEST | ares_op$REPLY. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ARP_OP_REQUEST = 1,
    IDEMIP_ARP_OP_REPLY = 2,
} IdemIpArpOp;

/** @brief Length of an IPv4 protocol address (ar$pln), in bytes. RFC 826: "DOD Internet addresses
 * are 32.bits". */
#define IDEMIP_ARP_PLN_IPV4 4u

/**
 * @brief Length of an Ethernet hardware address (ar$hln), in bytes.
 *
 * RFC 826 "Packet Generation" sets "ar$hln to 6 (the number of bytes in a 48.bit Ethernet
 * address)", and "Generalization": "For the 10Mbit Ethernet <ar$hrd, ar$hln> takes on the value
 * <1, 6>."
 */
#define IDEMIP_ARP_HLN_ETHERNET IDEMIP_MAC_LEN

/**
 * @brief Offsets into the ARP payload, in the order RFC 826 lists them.
 *
 * The address fields are variable: ar$sha and ar$tha are ar$hln bytes, ar$spa and ar$tpa are
 * ar$pln. The offsets below are the Ethernet/IPv4 case, which is the only pairing this end
 * resolves; a packet whose ar$hln or ar$pln disagrees is not that pairing and is discarded rather
 * than reinterpreted.
 */
#define IDEMIP_ARP_OFF_HRD 0u  ///< 16-bit hardware address space
#define IDEMIP_ARP_OFF_PRO 2u  ///< 16-bit protocol address space
#define IDEMIP_ARP_OFF_HLN 4u  ///< 8-bit hardware address length
#define IDEMIP_ARP_OFF_PLN 5u  ///< 8-bit protocol address length
#define IDEMIP_ARP_OFF_OP 6u   ///< 16-bit opcode
#define IDEMIP_ARP_OFF_SHA 8u  ///< sender hardware address, ar$hln bytes
#define IDEMIP_ARP_OFF_SPA 14u ///< sender protocol address, ar$pln bytes
#define IDEMIP_ARP_OFF_THA 18u ///< target hardware address, ar$hln bytes
#define IDEMIP_ARP_OFF_TPA 24u ///< target protocol address, ar$pln bytes

/** @brief An Ethernet/IPv4 ARP payload, header excluded. */
#define IDEMIP_ARP_LEN 28u

// Each field starts where the one before it ends, in the order RFC 826 "Packet format" lists them.
static_assert(IDEMIP_ARP_OFF_PRO == IDEMIP_ARP_OFF_HRD + 2u, "ar$pro follows the 16-bit ar$hrd");
static_assert(IDEMIP_ARP_OFF_HLN == IDEMIP_ARP_OFF_PRO + 2u, "ar$hln follows the 16-bit ar$pro");
static_assert(IDEMIP_ARP_OFF_PLN == IDEMIP_ARP_OFF_HLN + 1u, "ar$pln follows the 8-bit ar$hln");
static_assert(IDEMIP_ARP_OFF_OP == IDEMIP_ARP_OFF_PLN + 1u, "ar$op follows the 8-bit ar$pln");
static_assert(IDEMIP_ARP_OFF_SHA == IDEMIP_ARP_OFF_OP + 2u, "ar$sha follows the 16-bit ar$op");
static_assert(IDEMIP_ARP_OFF_SPA == IDEMIP_ARP_OFF_SHA + IDEMIP_ARP_HLN_ETHERNET,
              "ar$spa follows ar$hln bytes of ar$sha");
static_assert(IDEMIP_ARP_OFF_THA == IDEMIP_ARP_OFF_SPA + IDEMIP_ARP_PLN_IPV4,
              "ar$tha follows ar$pln bytes of ar$spa");
static_assert(IDEMIP_ARP_OFF_TPA == IDEMIP_ARP_OFF_THA + IDEMIP_ARP_HLN_ETHERNET,
              "ar$tha is ar$hln bytes and ar$tpa follows it: RFC 826 leaves no padding between addresses");
static_assert(IDEMIP_ARP_OFF_TPA + IDEMIP_ARP_PLN_IPV4 == IDEMIP_ARP_LEN,
              "the RFC 826 field offsets must sum to the Ethernet/IPv4 payload length");

// RFC 894 pads a short frame to 46 octets, and an ARP payload is 28, so an ARP frame is always
// padded on the wire. The pad is not part of the packet, so a parser reads the fields at their
// offsets and never takes a length from the frame.
static_assert(IDEMIP_ARP_LEN < IDEMIP_ETH_MIN_PAYLOAD,
              "an ARP payload is shorter than the RFC 894 minimum data field and is padded to it");

// ---------------------------------------------------------------------------
// Parse: the fields, read out of the caller's bytes
// ---------------------------------------------------------------------------
// RFC 826 "Why is it done this way??": "The packet data should be viewed as a byte stream in which
// only 3 byte pairs are defined to be words (ar$hrd, ar$pro and ar$op) which are sent most
// significant byte first". Those three are read with idemip_rd16; the addresses are byte streams,
// so ar$spa and ar$tpa are assembled from their four bytes and ar$sha and ar$tha stay where they
// lie.

/** @brief Hardware address space (ar$hrd). */
IDEMIP_INLINE uint16_t idemip_arp_hrd(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_ARP_OFF_HRD);
}

/** @brief Protocol address space (ar$pro). */
IDEMIP_INLINE uint16_t idemip_arp_pro(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_ARP_OFF_PRO);
}

/** @brief Byte length of each hardware address (ar$hln). */
IDEMIP_INLINE uint8_t idemip_arp_hln(const uint8_t *h)
{
    return h[IDEMIP_ARP_OFF_HLN];
}

/** @brief Byte length of each protocol address (ar$pln). */
IDEMIP_INLINE uint8_t idemip_arp_pln(const uint8_t *h)
{
    return h[IDEMIP_ARP_OFF_PLN];
}

/** @brief Opcode (ar$op). */
IDEMIP_INLINE uint16_t idemip_arp_op(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_ARP_OFF_OP);
}

/** @brief Sender hardware address (ar$sha), IDEMIP_ARP_HLN_ETHERNET bytes where they lie. */
IDEMIP_INLINE const uint8_t *idemip_arp_sha(const uint8_t *h)
{
    return h + IDEMIP_ARP_OFF_SHA;
}

/** @brief Sender protocol address (ar$spa). */
IDEMIP_INLINE uint32_t idemip_arp_spa(const uint8_t *h)
{
    return idemip_rd32(h + IDEMIP_ARP_OFF_SPA);
}

/** @brief Target hardware address (ar$tha), IDEMIP_ARP_HLN_ETHERNET bytes where they lie. */
IDEMIP_INLINE const uint8_t *idemip_arp_tha(const uint8_t *h)
{
    return h + IDEMIP_ARP_OFF_THA;
}

/** @brief Target protocol address (ar$tpa). */
IDEMIP_INLINE uint32_t idemip_arp_tpa(const uint8_t *h)
{
    return idemip_rd32(h + IDEMIP_ARP_OFF_TPA);
}

/**
 * @brief True when the packet is the <Ethernet, IPv4> pairing these offsets describe.
 *
 * RFC 826 "Packet Reception" asks "?Do I have the hardware type in ar$hrd?" and "?Do I speak the
 * protocol in ar$pro?", with "[optionally check the hardware length ar$hln]" and "[optionally check
 * the protocol length ar$pln]". Both lengths are checked here, because every offset above is fixed
 * at ar$hln 6 and ar$pln 4 and a packet carrying other lengths puts its addresses elsewhere.
 */
IDEMIP_INLINE idemip_bool idemip_arp_is_ethernet_ipv4(const uint8_t *h)
{
    return (idemip_bool)(idemip_arp_hrd(h) == IDEMIP_ARP_HRD_ETHERNET && idemip_arp_pro(h) == IDEMIP_ARP_PRO_IPV4 &&
                         idemip_arp_hln(h) == IDEMIP_ARP_HLN_ETHERNET && idemip_arp_pln(h) == IDEMIP_ARP_PLN_IPV4);
}

/** @brief RFC 826 "Packet Reception": "?Is the opcode ares_op$REQUEST?" */
IDEMIP_INLINE idemip_bool idemip_arp_is_request(const uint8_t *h)
{
    return (idemip_bool)(idemip_arp_op(h) == (uint16_t)IDEMIP_ARP_OP_REQUEST);
}

/** @brief The reply form of the packet, ar$op ares_op$REPLY. */
IDEMIP_INLINE idemip_bool idemip_arp_is_reply(const uint8_t *h)
{
    return (idemip_bool)(idemip_arp_op(h) == (uint16_t)IDEMIP_ARP_OP_REPLY);
}

/** @brief RFC 826 "Packet Reception": "?Am I the target protocol address?", @p pa being this end's. */
IDEMIP_INLINE idemip_bool idemip_arp_is_target(const uint8_t *h, uint32_t pa)
{
    return (idemip_bool)(idemip_arp_tpa(h) == pa);
}

// ---------------------------------------------------------------------------
// Build: the fields, written into the caller's bytes
// ---------------------------------------------------------------------------
// The caller owns IDEMIP_ARP_LEN bytes at @p p and every helper here writes all of them.

/**
 * @brief Write every field but ar$tha, which the request and the reply fill differently.
 *
 * RFC 826 "Packet Generation" fixes ar$hrd to ares_hrd$Ethernet, ar$pro to the protocol being
 * resolved, ar$hln to 6 and ar$pln to the length of an address in that protocol.
 */
IDEMIP_INLINE void idemip_arp_build(uint8_t *p, uint16_t op, const uint8_t *sha, uint32_t spa, uint32_t tpa)
{
    idemip_wr16(p + IDEMIP_ARP_OFF_HRD, (uint16_t)IDEMIP_ARP_HRD_ETHERNET);
    idemip_wr16(p + IDEMIP_ARP_OFF_PRO, (uint16_t)IDEMIP_ARP_PRO_IPV4);
    p[IDEMIP_ARP_OFF_HLN] = (uint8_t)IDEMIP_ARP_HLN_ETHERNET;
    p[IDEMIP_ARP_OFF_PLN] = (uint8_t)IDEMIP_ARP_PLN_IPV4;
    idemip_wr16(p + IDEMIP_ARP_OFF_OP, op);
    memcpy(p + IDEMIP_ARP_OFF_SHA, sha, IDEMIP_ARP_HLN_ETHERNET);
    idemip_wr32(p + IDEMIP_ARP_OFF_SPA, spa);
    idemip_wr32(p + IDEMIP_ARP_OFF_TPA, tpa);
}

/**
 * @brief A request for the hardware address behind @p tpa.
 *
 * RFC 826 "Packet Generation" sets "ar$op to ares_op$REQUEST, ar$sha with the 48.bit ethernet
 * address of itself, ar$spa with the protocol address of itself, and ar$tpa with the protocol
 * address of the machine that is trying to be accessed. It does not set ar$tha to anything in
 * particular, because it is this value that it is trying to determine." Zeroed here, so the bytes
 * are a function of the arguments alone.
 */
IDEMIP_INLINE void idemip_arp_build_request(uint8_t *p, const uint8_t *sha, uint32_t spa, uint32_t tpa)
{
    idemip_arp_build(p, (uint16_t)IDEMIP_ARP_OP_REQUEST, sha, spa, tpa);
    memset(p + IDEMIP_ARP_OFF_THA, 0, IDEMIP_ARP_HLN_ETHERNET);
}

/**
 * @brief A reply carrying @p sha as the hardware address behind @p spa.
 *
 * RFC 826 "Why is it done this way??" on ar$tha: "Its meaning in the reply form is the address of
 * the machine making the request", which is @p tha, and @p tpa is that machine's protocol address.
 */
IDEMIP_INLINE void idemip_arp_build_reply(uint8_t *p, const uint8_t *sha, uint32_t spa, const uint8_t *tha,
                                          uint32_t tpa)
{
    idemip_arp_build(p, (uint16_t)IDEMIP_ARP_OP_REPLY, sha, spa, tpa);
    memcpy(p + IDEMIP_ARP_OFF_THA, tha, IDEMIP_ARP_HLN_ETHERNET);
}

/**
 * @brief Turn a received request at @p p into its reply, in the bytes it arrived in.
 *
 * RFC 826 "Packet Reception", the request branch: "Swap hardware and protocol fields, putting the
 * local hardware and protocol addresses in the sender fields. Set the ar$op field to
 * ares_op$REPLY". "This format allows the packet buffer to be reused if a reply is generated; a
 * reply has the same length as a request, and several of the fields are the same."
 *
 * The swap moves ar$tpa into the sender field, and that branch is only reached once "?Am I the
 * target protocol address?" answered yes, so the local protocol address is what lands there.
 * @p local_sha is the local hardware address. ar$tha arrives don't care and is overwritten by the
 * requester's ar$sha.
 */
IDEMIP_INLINE void idemip_arp_reply_in_place(uint8_t *p, const uint8_t *local_sha)
{
    uint32_t spa = idemip_arp_spa(p);
    uint32_t tpa = idemip_arp_tpa(p);
    memcpy(p + IDEMIP_ARP_OFF_THA, p + IDEMIP_ARP_OFF_SHA, IDEMIP_ARP_HLN_ETHERNET);
    memcpy(p + IDEMIP_ARP_OFF_SHA, local_sha, IDEMIP_ARP_HLN_ETHERNET);
    idemip_wr32(p + IDEMIP_ARP_OFF_SPA, tpa);
    idemip_wr32(p + IDEMIP_ARP_OFF_TPA, spa);
    idemip_wr16(p + IDEMIP_ARP_OFF_OP, (uint16_t)IDEMIP_ARP_OP_REPLY);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_ARP_H
