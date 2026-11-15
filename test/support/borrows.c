// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file borrows.c
 * @brief The memory of one suite's program: the pool, the site over it, and the owner table.
 */

#include "support/borrows.h"

/**
 * @brief Bytes in the pool every suite takes its borrows from.
 *
 * @note Large enough for the most borrows a suite takes, two instances of each unit with their canary
 *       bytes, and the two words each cell costs.
 */
#ifndef IDEMIP_TEST_POOL_BYTES
#define IDEMIP_TEST_POOL_BYTES (512u * 1024u)
#endif

ParsMemoriaeInternae(idemip_test_pool, IDEMIP_TEST_POOL_BYTES);
LocusCarcerum(idemip_test_site, MMGR_MINIMUM_SECURITY(idemip_test_pool));
MMGR_OWNERS(IDEMIP_TEST_OWNERS)

void *idemip_test_take(size_t bytes, const CellOwner *owner)
{
    void *const cell = idemip_test_site.idemip_test_pool.persistent_buf_alloc(bytes, owner);
    if (cell == NULL)
    {
        MMGR_FATAL("the suite pool cannot meet a borrow: raise IDEMIP_TEST_POOL_BYTES");
    }
    return cell;
}

void idemip_test_borrow(uint8_t **slot, size_t bytes, const CellOwner *owner)
{
    if (*slot != NULL)
    {
        return;
    }
    *slot = idemip_test_take(bytes, owner);
}
