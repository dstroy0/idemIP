// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pseudo_v4.c
 * @brief The IPv4 pseudo-header, RFC 768 and RFC 9293 sec 3.1.
 *
 * RFC 768: "The pseudo header conceptually prefixed to the UDP header contains the source address,
 * the destination address, the protocol, and the UDP length." A zero octet leaves the protocol as
 * the low half of its word. The length field is sixteen bits, so a longer upper layer has no form
 * here and is refused.
 *
 * The entry below takes one parameter, a pointer to Pseudo4Ctx. A pseudo-header is a running sum,
 * two addresses, a length and the protocol they are being covered for, so those are one context.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/ip/pseudo.h"

/** @brief Largest upper-layer length the IPv4 form's 16-bit field carries. */
#define IDEMIP_PSEUDO_V4_LEN_MAX 0xFFFFu

IDEMIP_BEGIN_DECLS

/** @brief One accumulate, RFC 768's form. */
typedef struct
{
    uint32_t *sum;      /**< The running sum, accumulated into in place. */
    const uint8_t *src; /**< Source address, four octets. */
    const uint8_t *dst; /**< Destination address, four octets. */
    uint32_t upper_len; /**< Length of the upper-layer header and data. */
    uint8_t proto;      /**< The IANA protocol number, RFC 791 sec 3.1's Protocol field. */
} Pseudo4Ctx;

/**
 * @brief Accumulate RFC 768's pseudo-header into @c sum.
 * @param c The accumulate.
 * @return IDEMIP_FALSE when the length is one this form's sixteen-bit field cannot carry, in which
 *         case the sum is left as it was.
 *
 * The two addresses are summed as halves of their words, then the protocol, then the length. The
 * zero octet RFC 768 puts before the protocol is why the protocol is added as the low half of its
 * word and nothing is added for the octet itself.
 */
IDEMIP_INLINE idemip_bool pseudo4_accum(const Pseudo4Ctx *c)
{
    if (c->upper_len > (uint32_t)IDEMIP_PSEUDO_V4_LEN_MAX)
    {
        return IDEMIP_FALSE;
    }
    uint32_t s = idemip_rd32(c->src);
    uint32_t d = idemip_rd32(c->dst);
    uint32_t a = *c->sum;
    a += (s >> 16) & 0xFFFFu;
    a += s & 0xFFFFu;
    a += (d >> 16) & 0xFFFFu;
    a += d & 0xFFFFu;
    a += (uint32_t)c->proto; // the zero octet leaves the protocol as the low half
    a += c->upper_len;
    *c->sum = a;
    return IDEMIP_TRUE;
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
