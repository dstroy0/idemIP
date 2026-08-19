// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pseudo_v6_off.c
 * @brief The V6 half of pseudo.h in a build without IPv6: no such form.
 *
 * The build selects this instead of pseudo_v6.c, so a caller holding a version it learned at run
 * time takes the same branch and is answered false.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/ip/pseudo.h"

IDEMIP_BEGIN_DECLS

idemip_bool idemip_pseudo6_accum(uint32_t *sum, uint8_t proto, const uint8_t *src, const uint8_t *dst,
                                 uint32_t upper_len)
{
    (void)sum;
    (void)proto;
    (void)src;
    (void)dst;
    (void)upper_len;
    return IDEMIP_FALSE;
}

IDEMIP_END_DECLS
