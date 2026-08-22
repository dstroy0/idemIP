// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file endian.h
 * @brief Wire integers, byte at a time.
 *
 * Every protocol here puts its multi-byte fields in network byte order, and lands them wherever the
 * preceding fields end - RFC 826 puts a 32-bit protocol address at offset 14, RFC 791 puts one at
 * 12 inside a header that itself starts 14 bytes into the frame. Neither is aligned for its width.
 *
 * So a field is assembled from its bytes with shifts and masks rather than read through a cast. A
 * cast to a wider type at an odd address is a fault on the parts in the target list that require
 * natural alignment, and a silent penalty on the ones that only prefer it. Byte reads are always
 * aligned, so this is the only form that is correct everywhere and it is what every accessor here
 * compiles to.
 *
 * The table is the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_ENDIAN_H
#define IDEMIP_ENDIAN_H

#include "src/idemip_config.h"

IDEMIP_BEGIN_DECLS

/** @brief Dispatch table. Addressed by offset, so the layout is asserted below. */
typedef struct
{
    uint16_t (*rd16)(const uint8_t *p);
    uint32_t (*rd32)(const uint8_t *p);
    void (*wr16)(uint8_t *p, uint16_t v);
    void (*wr32)(uint8_t *p, uint32_t v);
} EndianNs;
IDEMIP_NS_LAYOUT(EndianNs, rd16, rd32, wr16, wr32);

/** @name The entries the table points at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The table is
 *         still the whole surface: call through it.
 *  @{ */
uint16_t idemip_rd16(const uint8_t *p);
uint32_t idemip_rd32(const uint8_t *p);
void idemip_wr16(uint8_t *p, uint16_t v);
void idemip_wr32(uint8_t *p, uint32_t v);
/** @} */

/**
 * @brief Module namespace.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS EndianNs endian IDEMIP_UNUSED = {
    .rd16 = idemip_rd16,
    .rd32 = idemip_rd32,
    .wr16 = idemip_wr16,
    .wr32 = idemip_wr32,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENDIAN_H
