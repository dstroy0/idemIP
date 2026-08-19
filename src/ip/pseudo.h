// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pseudo.h
 * @brief The pseudo-header a transport checksum covers, in the form its IP version fixes.
 *
 * RFC 768 and RFC 9293 sec 3.1 prefix the IPv4 form: the two 32-bit addresses, a zero octet, the
 * protocol, and the length of the upper-layer header and data. RFC 8200 sec 8.1 prefixes the IPv6
 * form: the two 128-bit addresses, a 32-bit Upper-Layer Packet Length, twenty-four zero bits, and
 * the Next Header. RFC 8200 sec 3 gives Next Header "the same values as the IPv4 Protocol field",
 * so one protocol number reaches both forms.
 *
 * One entry over both versions, so a caller holding a version it learned at run time writes the
 * branch once. The version's own arithmetic is a translation unit the build selects, and the
 * version a build left out answers false.
 *
 * Reads the caller's bytes and returns a number. Holds nothing.
 */

#ifndef IDEMIP_PSEUDO_H
#define IDEMIP_PSEUDO_H

#include "src/checksum.h"

IDEMIP_BEGIN_DECLS

/** @brief RFC 791 sec 3.1's Version 4. */
#define IDEMIP_PSEUDO_V4 4u

/** @brief RFC 8200 sec 3's Version 6. */
#define IDEMIP_PSEUDO_V6 6u

/** @brief Largest upper-layer length the IPv4 form's 16-bit field carries. */
#define IDEMIP_PSEUDO_V4_LEN_MAX 0xFFFFu

/**
 * @brief Accumulate the pseudo-header @p ip_version fixes into @p sum.
 *
 * @param sum running sum, which the caller then carries over the header and data.
 * @param ip_version IDEMIP_PSEUDO_V4 or IDEMIP_PSEUDO_V6.
 * @param proto the IANA protocol number: the IPv4 Protocol field, the IPv6 Next Header.
 * @param src source address, four octets under V4 and sixteen under V6.
 * @param dst destination address, the same widths.
 * @param upper_len the length of the upper-layer header and data.
 * @return false when the build carries no such version, and when the length that version's
 *         pseudo-header cannot carry.
 */
idemip_bool idemip_pseudo_accum(uint32_t *sum, uint8_t ip_version, uint8_t proto, const uint8_t *src,
                                const uint8_t *dst, uint32_t upper_len);

/** @brief The V4 half, RFC 768's form. Present when IDEMIP_ENABLE_IPV4, false when not. */
idemip_bool idemip_pseudo4_accum(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst,
                                 uint32_t upper_len);

/** @brief The V6 half, RFC 8200 sec 8.1's form. Present when IDEMIP_ENABLE_IPV6, false when not. */
idemip_bool idemip_pseudo6_accum(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst,
                                 uint32_t upper_len);

IDEMIP_END_DECLS

#endif // IDEMIP_PSEUDO_H
