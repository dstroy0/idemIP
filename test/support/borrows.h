// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file borrows.h
 * @brief The borrows of a suite, as LocusCarcerum cells over one MMgr pool.
 *
 * A suite takes each borrow once, in setUp, at the bytes it declares, and the cell is the suite's for the
 * whole run. support/borrows.c holds the program's memory: one pool, one site with one cellblock over it,
 * and the owner table with idemIP's owners. It is one translation unit of each suite, because Unity's
 * runner includes every header the suite includes, and a definition in a header would be in both.
 *
 * The DMA buffers are no borrow and no cell. Each set is its own pool, which MMGR_ALIGN_BYTES puts on a
 * cache line, and a suite passes the pool's storage array to Dma.bind.
 */

#ifndef IDEMIP_TEST_BORROWS_H
#define IDEMIP_TEST_BORROWS_H

#include "src/idemip_config.h"
#include "src/idemip_owners.h"

/**
 * @brief The owner list of a suite's program: idemIP's owners, and the one owner of the suites.
 * @param macro_ A macro of two arguments, as MMGR_OWNERS takes.
 * @note idemip_test_owner_node counts a cell that holds the borrows of many units together, as
 *       test_loopback takes for each of its two instances.
 */
#define IDEMIP_TEST_OWNERS(macro_) IDEMIP_OWNERS(macro_) macro_(idemip_test_owner_node, "test.node")

// The owner of the suites, which support/borrows.c defines with the rest of the table.
MMGR_OWNER_EXTERN(idemip_test_owner_node, "test.node")

/**
 * @brief Takes a cell of bytes bytes for owner.
 * @param bytes The bytes of the cell.
 * @param owner The owner that counts the cell [BORROWS].
 * @return      The cell's first byte [RETURNS OWNERSHIP].
 * @note A take the cellblock cannot meet stops the suite at once, as idemip_test_borrow does.
 */
void *idemip_test_take(size_t bytes, const CellOwner *owner);

/**
 * @brief Takes a borrow of bytes bytes for owner, once: a pointer that already holds a cell keeps it.
 * @param slot  Where the suite holds the borrow [BORROWS].
 * @param bytes The bytes the suite declares for the borrow, its canary bytes included.
 * @param owner The unit's owner [BORROWS].
 * @note A take the cellblock cannot meet stops the suite at once, because every case after it would
 *       report on a borrow that is not there.
 */
void idemip_test_borrow(uint8_t **slot, size_t bytes, const CellOwner *owner);

#endif // IDEMIP_TEST_BORROWS_H
