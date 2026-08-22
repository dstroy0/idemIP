// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pseudo_v6.c
 * @brief The IPv6 pseudo-header, RFC 8200 sec 8.1.
 *
 * The two 128-bit addresses, a 32-bit Upper-Layer Packet Length, twenty-four zero bits, and the
 * Next Header. The addresses are summed where they lie, sixteen octets each, which is the word
 * pairing the figure lays out.
 *
 * The entry below takes one parameter, a pointer to Pseudo6Ctx. A pseudo-header is a running sum,
 * two addresses, a length and the protocol they are being covered for, so those are one context.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/ip/ipv6.h"
#include "src/ip/pseudo.h"
#include "src/ip/ipv6_defines.h"

IDEMIP_BEGIN_DECLS

/** @brief One accumulate, RFC 8200 sec 8.1's form. */
typedef struct
{
    uint32_t *sum;      /**< The running sum, accumulated into in place. */
    const uint8_t *src; /**< Source address, sixteen octets. */
    const uint8_t *dst; /**< Destination address, sixteen octets. */
    uint32_t upper_len; /**< The Upper-Layer Packet Length, a 32-bit field in this form. */
    uint8_t proto;      /**< The Next Header value, RFC 8200 sec 3 giving it the IPv4 Protocol's. */
} Pseudo6Ctx;

/**
 * @brief Accumulate RFC 8200 sec 8.1's pseudo-header into @c sum.
 * @param c The accumulate.
 * @return IDEMIP_TRUE always: this form's length field is 32 bits, so every length has a form.
 *
 * The addresses are summed where they lie rather than read out as words, sixteen octets each. The
 * twenty-four zero bits sec 8.1 puts before the Next Header are why the protocol is added as the
 * low half of its word and nothing is added for the zeroes themselves.
 */
IDEMIP_INLINE idemip_bool pseudo6_accum(const Pseudo6Ctx *c)
{
    uint32_t a = *c->sum;
    a = idemip_cksum_accum(a, c->src, IDEMIP_IP6_ADDR_LEN);
    a = idemip_cksum_accum(a, c->dst, IDEMIP_IP6_ADDR_LEN);
    a += (c->upper_len >> 16) & 0xFFFFu;
    a += c->upper_len & 0xFFFFu;
    a += (uint32_t)c->proto; // the twenty-four zero bits leave it as the low half
    *c->sum = a;
    return IDEMIP_TRUE;
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so this is what it points at. It builds the context and hands it to the body above. */

idemip_bool idemip_pseudo6_accum(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst,
                                 uint32_t upper_len)
{
    return IDEMIP_CALL(pseudo6_accum, Pseudo6Ctx, .sum = sum, .proto = proto, .src = src, .dst = dst,
                       .upper_len = upper_len);
}

IDEMIP_END_DECLS
