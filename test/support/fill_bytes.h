// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file fill_bytes.h
 * @brief A fill of a suite's bytes at any address, one byte at a time.
 *
 * memor.set stores whole words, and so it takes memory on the grain of a word. A suite also writes
 * patterns into frames at the offsets the wire puts its fields at, and those addresses are off the
 * grain. MMgr has no fill for an address off the grain, and so a suite takes this one.
 */

#ifndef IDEMIP_TEST_FILL_BYTES_H
#define IDEMIP_TEST_FILL_BYTES_H

#include "src/idemip_config.h"

/**
 * @brief Writes val into bytes bytes at dst.
 * @param dst   The first byte to write, of any byte type [BORROWS].
 * @param val   The byte to write into each of them.
 * @param bytes The count.
 */
EMBED_INLINE void fill_bytes(void *dst, uint8_t val, size_t bytes)
{
    uint8_t *const first = dst;
    for (size_t at = 0u; at < bytes; at++)
    {
        first[at] = val;
    }
}

#endif // IDEMIP_TEST_FILL_BYTES_H
