// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file arp_defines.h
 * @brief The RFC 826 packet layout for the <Ethernet, IPv4> pairing.
 *
 * Constants only. No entry, no table, no storage.
 *
 * Separate from arp.h so that including the module does not drag the layout in with it. Included by
 * .c files that genuinely need the numbers, and by no surface header.
 */

#ifndef IDEMIP_ARP_DEFINES_H
#define IDEMIP_ARP_DEFINES_H

#include "src/ethernet/ethernet_defines.h" // ar$hln is the Ethernet address, ar$pro the type value

/** @brief Hardware address space (ar$hrd). RFC 826 "Definitions": "ares_hrd$Ethernet (= 1)". */
#define IDEMIP_ARP_HRD_ETHERNET 1u

/**
 * @brief Protocol address space (ar$pro). RFC 826: "For Ethernet hardware, this is from the set of
 * type fields ether_typ$<protocol>", so IPv4 carries the Ethernet type value.
 */
#define IDEMIP_ARP_PRO_IPV4 0x0800u

/**
 * @brief Length of an IPv4 protocol address (ar$pln), in bytes. RFC 826: "DOD Internet addresses
 * are 32.bits".
 */
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

#endif // IDEMIP_ARP_DEFINES_H
