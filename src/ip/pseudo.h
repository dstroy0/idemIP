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
 *
 * The table is the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_PSEUDO_H
#define IDEMIP_PSEUDO_H

#include "src/checksum.h"

IDEMIP_BEGIN_DECLS

/** @brief Dispatch table. Addressed by offset, so the layout is asserted below. */
typedef struct
{
    idemip_bool (*accum)(uint32_t *sum, uint8_t ip_version, uint8_t proto, const uint8_t *src, const uint8_t *dst,
                         uint32_t upper_len);
    idemip_bool (*accum4)(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst, uint32_t upper_len);
    idemip_bool (*accum6)(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst, uint32_t upper_len);
} PseudoNs;
IDEMIP_NS_LAYOUT(PseudoNs, accum, accum4, accum6);

/** @name The entries the table points at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The table is
 *         still the whole surface: call through it. The halves are named here because the version
 *         branch calls them across translation units, the build having selected which one each is.
 *  @{ */
idemip_bool idemip_pseudo_accum(uint32_t *sum, uint8_t ip_version, uint8_t proto, const uint8_t *src,
                                const uint8_t *dst, uint32_t upper_len);
idemip_bool idemip_pseudo4_accum(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst,
                                 uint32_t upper_len);
idemip_bool idemip_pseudo6_accum(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst,
                                 uint32_t upper_len);
/** @} */

/**
 * @brief Module namespace.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS PseudoNs pseudo IDEMIP_UNUSED = {
    .accum = idemip_pseudo_accum,
    .accum4 = idemip_pseudo4_accum,
    .accum6 = idemip_pseudo6_accum,
};

IDEMIP_END_DECLS

#endif // IDEMIP_PSEUDO_H
