// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file checksum.h
 * @brief The internet checksum, RFC 1071.
 *
 * RFC 791 sec 3.1 states the field this computes: "the 16 bit one's complement of the one's
 * complement sum of all 16 bit words in the header". RFC 1071 is where the arithmetic that gets
 * there is set out. Every header here carries one: the IPv4 header over itself (RFC 791 sec 3.1),
 * ICMP over its message (RFC 792), and TCP and UDP over a pseudo-header and their payload.
 *
 * Reads the caller's bytes and returns a number. Holds nothing.
 *
 * The table is the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_CHECKSUM_H
#define IDEMIP_CHECKSUM_H

#include "src/common.h"
#include "src/endian.h"

IDEMIP_BEGIN_DECLS

/** @brief Dispatch table. Addressed by offset, so the layout is asserted below. */
typedef struct
{
    uint32_t (*accum)(uint32_t sum, const uint8_t *p, size_t len);
    uint16_t (*final)(uint32_t sum);
    uint16_t (*cksum)(const uint8_t *p, size_t len);
    idemip_bool (*valid)(const uint8_t *p, size_t len);
} ChecksumNs;
IDEMIP_NS_LAYOUT(ChecksumNs, accum, final, cksum, valid);

/** @name The entries the table points at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The table is
 *         still the whole surface: call through it.
 *  @{ */
uint32_t idemip_cksum_accum(uint32_t sum, const uint8_t *p, size_t len);
uint16_t idemip_cksum_final(uint32_t sum);
uint16_t idemip_cksum(const uint8_t *p, size_t len);
idemip_bool idemip_cksum_valid(const uint8_t *p, size_t len);
/** @} */

/**
 * @brief Module namespace.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS ChecksumNs cksum IDEMIP_UNUSED = {
    .accum = idemip_cksum_accum,
    .final = idemip_cksum_final,
    .cksum = idemip_cksum,
    .valid = idemip_cksum_valid,
};

IDEMIP_END_DECLS

#endif // IDEMIP_CHECKSUM_H
