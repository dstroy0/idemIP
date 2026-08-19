// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pseudo_v6.c
 * @brief The IPv6 pseudo-header, RFC 8200 sec 8.1.
 *
 * The two 128-bit addresses, a 32-bit Upper-Layer Packet Length, twenty-four zero bits, and the
 * Next Header. The addresses are summed where they lie, sixteen octets each, which is the word
 * pairing the figure lays out.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/ip/ipv6.h"
#include "src/ip/pseudo.h"

IDEMIP_BEGIN_DECLS

idemip_bool idemip_pseudo6_accum(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst,
                                 uint32_t upper_len)
{
    uint32_t a = *sum;
    a = idemip_cksum_accum(a, src, IDEMIP_IP6_ADDR_LEN);
    a = idemip_cksum_accum(a, dst, IDEMIP_IP6_ADDR_LEN);
    a += (upper_len >> 16) & 0xFFFFu;
    a += upper_len & 0xFFFFu;
    a += (uint32_t)proto; // the twenty-four zero bits leave it as the low half
    *sum = a;
    return IDEMIP_TRUE;
}

IDEMIP_END_DECLS
