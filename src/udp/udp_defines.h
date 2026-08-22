// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file udp_defines.h
 * @brief The RFC 768 header layout, and the RFC 3828 UDP-Lite variant of it.
 *
 * Constants only. No entry, no table, no storage.
 *
 * Separate from udp.h so that including the module does not drag the layout in with it. Included by
 * .c files that genuinely need the numbers, and by no surface header.
 */

#ifndef IDEMIP_UDP_DEFINES_H
#define IDEMIP_UDP_DEFINES_H

#include "src/idemip_config.h"

// ---------------------------------------------------------------------------
// Field offsets (RFC 768, "Format")
// ---------------------------------------------------------------------------

#define IDEMIP_UDP_OFF_SRC_PORT 0u ///< 16-bit Source Port
#define IDEMIP_UDP_OFF_DST_PORT 2u ///< 16-bit Destination Port
#define IDEMIP_UDP_OFF_LEN 4u      ///< 16-bit Length
#define IDEMIP_UDP_OFF_CKSUM 6u    ///< 16-bit Checksum
#define IDEMIP_UDP_HDR_LEN 8u      ///< the header, data follows

/**
 * @brief RFC 768: Length "is the length in octets of this user datagram including this header and
 * the data. (This means the minimum value of the length is eight.)"
 */
#define IDEMIP_UDP_LEN_MIN IDEMIP_UDP_HDR_LEN

/**
 * @brief RFC 768: "An all zero transmitted checksum value means that the transmitter generated no
 * checksum (for debugging or for higher level protocols that don't care)."
 */
#define IDEMIP_UDP_CKSUM_NONE 0x0000u

/**
 * @brief RFC 768: "If the computed checksum is zero, it is transmitted as all ones (the equivalent
 * in one's complement arithmetic)."
 *
 * Zero already means "no checksum", so a real result of zero is sent as its other representation
 * rather than being mistaken for an absent one.
 */
#define IDEMIP_UDP_CKSUM_ZERO_AS 0xFFFFu

/**
 * @brief IANA Assigned Internet Protocol Numbers: UDP is 17.
 *
 * RFC 8200 sec 3 gives the IPv6 Next Header "the same values as the IPv4 Protocol field", so this
 * one number is what both pseudo-headers carry.
 */
#define IDEMIP_UDP_PROTO 17u

// ---------------------------------------------------------------------------
// UDP-Lite (RFC 3828)
// ---------------------------------------------------------------------------
// RFC 3828 sec 3: "Its format differs from UDP in that the Length field has been replaced with a
// Checksum Coverage field." Ports and Checksum keep their offsets, so only the third field is
// named again here.

/** @brief 16-bit Checksum Coverage, where RFC 768 puts Length (RFC 3828 sec 3, Figure 1). */
#define IDEMIP_UDPLITE_OFF_COV IDEMIP_UDP_OFF_LEN

/** @brief The header is the same eight octets. */
#define IDEMIP_UDPLITE_HDR_LEN IDEMIP_UDP_HDR_LEN

/**
 * @brief RFC 3828 sec 3.1: "A Checksum Coverage of zero indicates that the entire UDP-Lite packet
 * is covered by the checksum."
 */
#define IDEMIP_UDPLITE_COV_ALL 0u

/**
 * @brief RFC 3828 sec 3.1: "the value of the Checksum Coverage field MUST be either 0 or at least
 * 8. A UDP-Lite packet with a Checksum Coverage value of 1 to 7 MUST be discarded by the receiver."
 *
 * Eight is this header, which "MUST always be covered by the checksum".
 */
#define IDEMIP_UDPLITE_COV_MIN IDEMIP_UDPLITE_HDR_LEN

/** @brief RFC 3828 sec 7: "A new IP protocol number, 136 has been assigned for UDP-Lite." */
#define IDEMIP_UDPLITE_PROTO 136u

// ---------------------------------------------------------------------------
// The map closes on itself
// ---------------------------------------------------------------------------

static_assert(IDEMIP_UDP_OFF_SRC_PORT + 2u == IDEMIP_UDP_OFF_DST_PORT,
              "Source Port is 16 bits and Destination Port follows it (RFC 768, Format)");
static_assert(IDEMIP_UDP_OFF_DST_PORT + 2u == IDEMIP_UDP_OFF_LEN,
              "Destination Port is 16 bits and Length follows it (RFC 768, Format)");
static_assert(IDEMIP_UDP_OFF_LEN + 2u == IDEMIP_UDP_OFF_CKSUM,
              "Length is 16 bits and Checksum follows it (RFC 768, Format)");
static_assert(IDEMIP_UDP_OFF_CKSUM + 2u == IDEMIP_UDP_HDR_LEN,
              "the RFC 768 field offsets must sum to the header length");
static_assert(IDEMIP_UDP_LEN_MIN == 8u, "RFC 768: \"the minimum value of the length is eight\"");
static_assert(IDEMIP_UDP_CKSUM_NONE != IDEMIP_UDP_CKSUM_ZERO_AS,
              "RFC 768's two checksum special cases are the two representations of zero, not one");
static_assert(IDEMIP_UDPLITE_OFF_COV == IDEMIP_UDP_OFF_LEN,
              "RFC 3828 sec 3 replaces Length with Checksum Coverage in place");
static_assert(IDEMIP_UDPLITE_COV_MIN == IDEMIP_UDPLITE_HDR_LEN,
              "RFC 3828 sec 3.1: the smallest nonzero Coverage is the header it must always cover");

#endif // IDEMIP_UDP_DEFINES_H
