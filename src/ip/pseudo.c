// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pseudo.c
 * @brief The version branch, once, for every transport checksum this stack computes.
 *
 * The two arms are their own translation units, so the binary holds one copy of each version's
 * arithmetic however many transports call this.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/ip/pseudo.h"

IDEMIP_BEGIN_DECLS

idemip_bool idemip_pseudo_accum(uint32_t *sum, uint8_t ip_version, uint8_t proto, const uint8_t *src,
                                const uint8_t *dst, uint32_t upper_len)
{
    if (ip_version == (uint8_t)IDEMIP_PSEUDO_V4)
    {
        return idemip_pseudo4_accum(sum, proto, src, dst, upper_len);
    }
    if (ip_version == (uint8_t)IDEMIP_PSEUDO_V6)
    {
        return idemip_pseudo6_accum(sum, proto, src, dst, upper_len);
    }
    return IDEMIP_FALSE;
}

IDEMIP_END_DECLS
