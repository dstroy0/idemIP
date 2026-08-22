// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pseudo.c
 * @brief The version branch, once, for every transport checksum this stack computes.
 *
 * The entry below takes one parameter, a pointer to PseudoCtx. A pseudo-header is a running sum,
 * two addresses, a length and the protocol they are being covered for, so those are one context.
 *
 * The two arms are their own translation units, so the binary holds one copy of each version's
 * arithmetic however many transports call this.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/ip/pseudo.h"

/** @brief RFC 791 sec 3.1's Version 4. */
#define IDEMIP_PSEUDO_V4 4u

/** @brief RFC 8200 sec 3's Version 6. */
#define IDEMIP_PSEUDO_V6 6u

IDEMIP_BEGIN_DECLS

/** @brief One accumulate. */
typedef struct
{
    uint32_t *sum;      /**< The running sum, accumulated into in place. */
    const uint8_t *src; /**< Source address, four octets under V4 and sixteen under V6. */
    const uint8_t *dst; /**< Destination address, the same widths. */
    uint32_t upper_len; /**< Length of the upper-layer header and data. */
    uint8_t ip_version; /**< IDEMIP_PSEUDO_V4 or IDEMIP_PSEUDO_V6. */
    uint8_t proto;      /**< The IANA protocol number: the IPv4 Protocol, the IPv6 Next Header. */
} PseudoCtx;

/**
 * @brief Accumulate the pseudo-header @c ip_version fixes into @c sum.
 * @param c The accumulate.
 * @return IDEMIP_FALSE when the build carries no such version, and when the length is one that
 *         version's pseudo-header cannot carry.
 *
 * RFC 791 sec 3.1's Version 4 and RFC 8200 sec 3's Version 6 are the two forms there are. A version
 * that is neither has no pseudo-header at all, so it is false, and no later call gives it one.
 *
 * The halves are this module's own entries in their own translation units, the build having
 * selected which one each is, so the branch reaches them by name. Each reports for itself, and the
 * one a build left out reports false without touching the sum.
 */
IDEMIP_INLINE idemip_bool pseudo_accum(const PseudoCtx *c)
{
    if (c->ip_version == (uint8_t)IDEMIP_PSEUDO_V4)
    {
        return idemip_pseudo4_accum(c->sum, c->proto, c->src, c->dst, c->upper_len);
    }
    if (c->ip_version == (uint8_t)IDEMIP_PSEUDO_V6)
    {
        return idemip_pseudo6_accum(c->sum, c->proto, c->src, c->dst, c->upper_len);
    }
    return IDEMIP_FALSE;
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so this is what it points at. It builds the context and hands it to the body above.

   It is nameable rather than file local because a static const table in the header has to be able
   to point at it, and a static const table is what gcc devirtualizes. Through an extern one every
   call from another translation unit is a load of the table, a load of the entry, and an indirect
   call it cannot see through. */

idemip_bool idemip_pseudo_accum(uint32_t *sum, uint8_t ip_version, uint8_t proto, const uint8_t *src,
                                const uint8_t *dst, uint32_t upper_len)
{
    return IDEMIP_CALL(pseudo_accum, PseudoCtx, .sum = sum, .ip_version = ip_version, .proto = proto, .src = src,
                       .dst = dst, .upper_len = upper_len);
}

IDEMIP_END_DECLS
