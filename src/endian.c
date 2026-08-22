// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file endian.c
 * @brief Wire integers, byte at a time.
 *
 * Every entry below takes one parameter, a pointer to EndianCtx. A wire access is a span and, when
 * it writes, the value going into it, so those are one context.
 *
 * A field is assembled from its bytes with shifts and masks rather than read through a cast. A cast
 * to a wider type at an odd address is a fault on the parts in the target list that require natural
 * alignment, and a silent penalty on the ones that only prefer it. Byte reads are always aligned,
 * so this is the only form that is correct everywhere.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/endian.h"

IDEMIP_BEGIN_DECLS

/** @brief One wire access. */
typedef struct
{
    const uint8_t *r; /**< The span a read takes its octets from. */
    uint8_t *w;       /**< The span a write puts them into. */
    uint32_t v;       /**< The value a write sends, as wide as the widest entry that takes one. */
} EndianCtx;

/** @brief Read a big-endian 16-bit field. */
IDEMIP_INLINE uint16_t endian_rd16(const EndianCtx *c)
{
    return (uint16_t)(((uint16_t)c->r[0] << 8) | (uint16_t)c->r[1]);
}

/** @brief Read a big-endian 32-bit field. */
IDEMIP_INLINE uint32_t endian_rd32(const EndianCtx *c)
{
    return ((uint32_t)c->r[0] << 24) | ((uint32_t)c->r[1] << 16) | ((uint32_t)c->r[2] << 8) | (uint32_t)c->r[3];
}

/** @brief Write the value as a big-endian 16-bit field. */
IDEMIP_INLINE void endian_wr16(const EndianCtx *c)
{
    c->w[0] = (uint8_t)(c->v >> 8);
    c->w[1] = (uint8_t)(c->v & 0xFFu);
}

/** @brief Write the value as a big-endian 32-bit field. */
IDEMIP_INLINE void endian_wr32(const EndianCtx *c)
{
    c->w[0] = (uint8_t)(c->v >> 24);
    c->w[1] = (uint8_t)((c->v >> 16) & 0xFFu);
    c->w[2] = (uint8_t)((c->v >> 8) & 0xFFu);
    c->w[3] = (uint8_t)(c->v & 0xFFu);
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so these are what it points at. Each builds the context and hands it to the body above. */

uint16_t idemip_rd16(const uint8_t *p)
{
    return IDEMIP_CALL(endian_rd16, EndianCtx, .r = p);
}

uint32_t idemip_rd32(const uint8_t *p)
{
    return IDEMIP_CALL(endian_rd32, EndianCtx, .r = p);
}

void idemip_wr16(uint8_t *p, uint16_t v)
{
    IDEMIP_CALL(endian_wr16, EndianCtx, .w = p, .v = v);
}

void idemip_wr32(uint8_t *p, uint32_t v)
{
    IDEMIP_CALL(endian_wr32, EndianCtx, .w = p, .v = v);
}

IDEMIP_END_DECLS
