// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file vlan_defines.h
 * @brief The IEEE 802.1Q C-Tag layout: where the tag sits, and the three fields it packs.
 *
 * Constants only. No entry, no table, no storage.
 *
 * Separate from vlan.h so that including the module does not drag the layout in with it. Included
 * by .c files that genuinely need the numbers, and by no surface header.
 *
 * WHAT IS CITED AND WHAT IS NOT. IEEE Std 802.1Q itself is not readable without purchase, so no
 * clause of it is cited here. Every constant below is taken from an open document that states it:
 *
 *   - RFC 7042 Appendix B.2: "0x8100  IEEE Std 802.1Q  - Customer VLAN Tag Type (C-Tag, formerly
 *     called the Q-Tag)", and "0x88A8  IEEE Std 802.1Q  - Service VLAN tag identifier (S-Tag)",
 *     which this module does not write.
 *   - RFC 6325 sec 4.1 Figure 7 draws the tag's place in the frame: the two MAC addresses, then
 *     "Ethertype = C-Tag [802.1Q-2005] | Inner.VLAN Tag Information", then "Ethertype of Original
 *     Payload".
 *   - RFC 6325 sec 4.1.1 Figure 8 draws the Tag Control Information as "Priority | C | VLAN ID",
 *     three bits, one bit and twelve bits.
 */

#ifndef IDEMIP_VLAN_DEFINES_H
#define IDEMIP_VLAN_DEFINES_H

#include "src/ethernet/ethernet_defines.h" // the tag's offsets are stated in the frame's terms

// ---------------------------------------------------------------------------
// The tag, and where it sits
// ---------------------------------------------------------------------------

/** @brief RFC 6325 sec 4.1.1: "The C-Tag Ethertype [RFC5342] is 0x8100." */
#define IDEMIP_VLAN_TPID 0x8100u

/** @brief The Ethertype an 802.1ad S-Tag carries (RFC 7042 Appendix B.2). Not written here. */
#define IDEMIP_VLAN_STAG_TPID 0x88A8u

/**
 * @brief Octets the tag adds to a frame: the C-Tag Ethertype and the Tag Control Information.
 *
 * RFC 6325 sec 4.1 Figure 7 draws both as 16-bit fields. lwIP `SIZEOF_VLAN_HDR` and Linux
 * `VLAN_HLEN` are the same four.
 */
#define IDEMIP_VLAN_TAG_LEN 4u

/** @brief The C-Tag Ethertype, where an untagged frame carries its own type code. */
#define IDEMIP_VLAN_OFF_TPID IDEMIP_ETH_OFF_TYPE

/** @brief 16-bit Tag Control Information. */
#define IDEMIP_VLAN_OFF_TCI (IDEMIP_VLAN_OFF_TPID + IDEMIP_ETH_TYPE_LEN)

/** @brief The type code the payload is, which RFC 6325 sec 4.1 Figure 7 puts behind the tag. */
#define IDEMIP_VLAN_OFF_TYPE (IDEMIP_VLAN_OFF_TCI + IDEMIP_ETH_TYPE_LEN)

/** @brief The data field of a tagged frame. */
#define IDEMIP_VLAN_OFF_PAYLOAD (IDEMIP_VLAN_OFF_TYPE + IDEMIP_ETH_TYPE_LEN)

/** @brief Header octets a tagged frame carries ahead of its data field. Linux `VLAN_ETH_HLEN`. */
#define IDEMIP_VLAN_HDR_LEN (IDEMIP_ETH_HDR_LEN + IDEMIP_VLAN_TAG_LEN)

/**
 * @brief Whole tagged frame on the wire, the tag included.
 *
 * The tag is four octets no untagged frame carries. Linux `include/linux/if_vlan.h` states the same
 * 1518 as `VLAN_ETH_FRAME_LEN`, noting "According to 802.3ac, the packet can be 4 bytes longer";
 * IEEE Std 802.3ac is not readable without purchase and is not cited.
 */
#define IDEMIP_VLAN_FRAME_MAX (IDEMIP_ETH_FRAME_MAX + IDEMIP_VLAN_TAG_LEN)

// ---------------------------------------------------------------------------
// The Tag Control Information (RFC 6325 sec 4.1.1 Figure 8)
// ---------------------------------------------------------------------------
// "Priority | C | VLAN ID", three bits then one bit then twelve, in one 16-bit field. Each field is
// a shift and a mask; nothing here divides.

#define IDEMIP_VLAN_PCP_SHIFT 13u  ///< Priority, the three high bits
#define IDEMIP_VLAN_PCP_MASK 0x07u ///< the value once shifted down
#define IDEMIP_VLAN_DEI_SHIFT 12u  ///< the "C" bit RFC 6325 sec 4.1.1 draws between the two fields
#define IDEMIP_VLAN_DEI_MASK 0x01u
#define IDEMIP_VLAN_VID_MASK 0x0FFFu ///< VLAN ID, the twelve low bits

/** @brief RFC 6325 sec 4.1.1: "the priority field contains an unsigned value from 0 through 7". */
#define IDEMIP_VLAN_PCP_MAX 7u

/** @brief Values the 12-bit VLAN ID field spans. Linux `VLAN_N_VID`. */
#define IDEMIP_VLAN_VIDS 4096u

/**
 * @brief RFC 6325 sec 4.1.1: "VLAN ID zero is the null VLAN identifier and indicates that no VLAN
 * is specified", a frame carrying it being "called 'priority tagged' rather than 'VLAN tagged'".
 */
#define IDEMIP_VLAN_VID_NULL 0x000u

/** @brief RFC 6325 sec 4.1.1: "allow use of the full range of VLAN IDs from 0x001 through 0xFFE". */
#define IDEMIP_VLAN_VID_FIRST 0x001u
#define IDEMIP_VLAN_VID_LAST 0x0FFEu

/** @brief RFC 6325 sec 4.1.1: "VLAN ID 0xFFF is reserved", and "MUST NOT be used". */
#define IDEMIP_VLAN_VID_RESERVED 0x0FFFu

// ---------------------------------------------------------------------------
// The map closes on itself
// ---------------------------------------------------------------------------

// RFC 6325 sec 4.1 Figure 7: the C-Tag Ethertype and the Tag Control Information, two 16-bit fields.
static_assert(IDEMIP_VLAN_OFF_TYPE - IDEMIP_VLAN_OFF_TPID == IDEMIP_VLAN_TAG_LEN,
              "the tag is the C-Tag Ethertype and the Tag Control Information, four octets");

// The tag sits where an untagged frame's type code sits, and the payload's type code follows it.
static_assert(IDEMIP_VLAN_OFF_TPID == IDEMIP_ETH_OFF_TYPE,
              "the C-Tag Ethertype occupies the Ethernet II type field (RFC 6325 sec 4.1 Figure 7)");
static_assert(IDEMIP_VLAN_OFF_PAYLOAD == IDEMIP_ETH_OFF_PAYLOAD + IDEMIP_VLAN_TAG_LEN,
              "a tag moves the data field four octets further in");
static_assert(IDEMIP_VLAN_HDR_LEN == IDEMIP_VLAN_OFF_PAYLOAD,
              "the field offsets must sum to the tagged header length");

// RFC 6325 sec 4.1.1 Figure 8: three bits of Priority, one C bit, twelve bits of VLAN ID.
static_assert(IDEMIP_VLAN_PCP_SHIFT == IDEMIP_VLAN_DEI_SHIFT + 1u,
              "the C bit sits directly below the three Priority bits (RFC 6325 sec 4.1.1)");
static_assert(IDEMIP_VLAN_DEI_SHIFT == 12u && IDEMIP_VLAN_VID_MASK == 0x0FFFu,
              "the VLAN ID is the twelve low bits, the C bit the one above them");
static_assert(((IDEMIP_VLAN_PCP_MASK << IDEMIP_VLAN_PCP_SHIFT) | (IDEMIP_VLAN_DEI_MASK << IDEMIP_VLAN_DEI_SHIFT) |
               IDEMIP_VLAN_VID_MASK) == 0xFFFFu,
              "the three fields must cover the whole 16-bit Tag Control Information");
static_assert(IDEMIP_VLAN_PCP_MAX == IDEMIP_VLAN_PCP_MASK,
              "RFC 6325 sec 4.1.1 puts the Priority at 0 through 7, which is the three-bit field");
static_assert(IDEMIP_VLAN_VIDS == IDEMIP_VLAN_VID_MASK + 1u, "the VLAN ID field spans IDEMIP_VLAN_VIDS values");
static_assert(IDEMIP_VLAN_VID_RESERVED == IDEMIP_VLAN_VID_MASK && IDEMIP_VLAN_VID_LAST + 1u == IDEMIP_VLAN_VID_RESERVED,
              "RFC 6325 sec 4.1.1 runs the usable range 0x001 through 0xFFE and reserves 0xFFF");

#endif // IDEMIP_VLAN_DEFINES_H
