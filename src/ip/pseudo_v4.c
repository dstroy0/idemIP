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
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/ip/pseudo.h"

IDEMIP_BEGIN_DECLS

idemip_bool idemip_pseudo4_accum(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst,
                                 uint32_t upper_len)
{
    if (upper_len > (uint32_t)IDEMIP_PSEUDO_V4_LEN_MAX)
    {
        return IDEMIP_FALSE;
    }
    uint32_t s = idemip_rd32(src);
    uint32_t d = idemip_rd32(dst);
    uint32_t a = *sum;
    a += (s >> 16) & 0xFFFFu;
    a += s & 0xFFFFu;
    a += (d >> 16) & 0xFFFFu;
    a += d & 0xFFFFu;
    a += (uint32_t)proto; // the zero octet leaves the protocol as the low half
    a += upper_len;
    *sum = a;
    return IDEMIP_TRUE;
}

IDEMIP_END_DECLS
