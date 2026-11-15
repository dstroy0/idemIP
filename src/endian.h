// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file endian.h
 * @brief Wire integers in network byte order, read and written through MMgr's magna_extremitas.
 *
 * Every protocol here puts its multi-byte fields in network byte order, and lands them wherever the
 * preceding fields end - RFC 826 puts a 32-bit protocol address at offset 14, RFC 791 puts one at
 * 12 inside a header that itself starts 14 bytes into the frame. Neither is aligned for its width.
 *
 * magna_extremitas reads and writes the most significant byte first, through proxim's loads and
 * stores, which take any address. These four give each width its own type, so a call site states the
 * width once.
 */

#ifndef IDEMIP_ENDIAN_H
#define IDEMIP_ENDIAN_H

#include "src/idemip_config.h"

#include "endian/endian.h"

EMBED_BEGIN_DECLS

/**
 * @brief Reads a 16-bit field in network byte order.
 * @param p The first of the two bytes [BORROWS].
 * @return  The field.
 */
EMBED_INLINE uint16_t idemip_rd16(const uint8_t *p)
{
    // Explicit cast narrows the 64-bit read to the 16 bits MMGR_ENDIAN_16 reads
    return (uint16_t)EMBED_CALL(magna_extremitas.rd, EndianCfg, .src = p, .width = MMGR_ENDIAN_16);
}

/**
 * @brief Reads a 32-bit field in network byte order.
 * @param p The first of the four bytes [BORROWS].
 * @return  The field.
 */
EMBED_INLINE uint32_t idemip_rd32(const uint8_t *p)
{
    // Explicit cast narrows the 64-bit read to the 32 bits MMGR_ENDIAN_32 reads
    return (uint32_t)EMBED_CALL(magna_extremitas.rd, EndianCfg, .src = p, .width = MMGR_ENDIAN_32);
}

/**
 * @brief Writes a 16-bit field in network byte order.
 * @param p The first of the two bytes [BORROWS].
 * @param v The field.
 */
EMBED_INLINE void idemip_wr16(uint8_t *p, uint16_t v)
{
    EMBED_CALL(magna_extremitas.wr, EndianCfg, .dst = p, .val = v, .width = MMGR_ENDIAN_16);
}

/**
 * @brief Writes a 32-bit field in network byte order.
 * @param p The first of the four bytes [BORROWS].
 * @param v The field.
 */
EMBED_INLINE void idemip_wr32(uint8_t *p, uint32_t v)
{
    EMBED_CALL(magna_extremitas.wr, EndianCfg, .dst = p, .val = v, .width = MMGR_ENDIAN_32);
}

EMBED_END_DECLS

#endif // IDEMIP_ENDIAN_H
