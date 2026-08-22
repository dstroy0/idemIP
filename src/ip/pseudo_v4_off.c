// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pseudo_v4_off.c
 * @brief The V4 half of pseudo.h in a build without IPv4: no such form.
 *
 * The build selects this instead of pseudo_v4.c, so a caller holding a version it learned at run
 * time takes the same branch and is answered false.
 *
 * The entry below takes one parameter, a pointer to Pseudo4Ctx, so it is the same shape as the
 * half it stands in for. Nothing reads the context: there is no form here to read it for.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/ip/pseudo.h"

IDEMIP_BEGIN_DECLS

/** @brief One accumulate that has no form in this build. */
typedef struct
{
    uint32_t *sum;      /**< The running sum, left as it was. */
    const uint8_t *src; /**< Source address, unread. */
    const uint8_t *dst; /**< Destination address, unread. */
    uint32_t upper_len; /**< Length of the upper-layer header and data, unread. */
    uint8_t proto;      /**< The IANA protocol number, unread. */
} Pseudo4Ctx;

/**
 * @brief Report that this build has no IPv4 pseudo-header.
 * @param c The accumulate, unread.
 * @return IDEMIP_FALSE always.
 *
 * The sum is left as it was, so a caller that goes on to carry it over the header and data carries
 * a sum nothing was added to.
 */
IDEMIP_INLINE idemip_bool pseudo4_accum(const Pseudo4Ctx *c)
{
    (void)c;
    return IDEMIP_FALSE;
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so this is what it points at. It builds the context and hands it to the body above. */

idemip_bool idemip_pseudo4_accum(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst,
                                 uint32_t upper_len)
{
    return IDEMIP_CALL(pseudo4_accum, Pseudo4Ctx, .sum = sum, .proto = proto, .src = src, .dst = dst,
                       .upper_len = upper_len);
}

IDEMIP_END_DECLS
