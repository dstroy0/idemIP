// idemIP v0.2.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file time_determinism_defines.h
 * @brief The layout of a pad word: the pad in ticks, and the state of the last release.
 *
 * Constants only. No entry, no table, no storage.
 *
 * The pad uses the low thirty bits, and the top two hold the state of the last release. One load
 * of the word gives both. theory/time_determinism/TimeDeterminism/Word.lean proves that the two
 * fields fill the word, share no bit, and unpack to what was packed.
 *
 * Included by time_determinism.c, and by a suite that composes a pad word itself.
 */

#ifndef IDEMIP_TIME_DETERMINISM_DEFINES_H
#define IDEMIP_TIME_DETERMINISM_DEFINES_H

#include "src/idemip_config.h"

/** @brief Bits of the pad, low. */
#define IDEMIP_CLOCK_PAD_MASK 0x3FFFFFFFu

/** @brief The shift of the state of the last release, high. */
#define IDEMIP_CLOCK_PAD_SHIFT 30u

/** @brief The two bits of that state, after the shift. */
#define IDEMIP_CLOCK_PAD_STATE_MASK 0x3u

// The pad and the state fill the word and share no bit.
EMBED_STATIC_ASSERT((IDEMIP_CLOCK_PAD_MASK & (IDEMIP_CLOCK_PAD_STATE_MASK << IDEMIP_CLOCK_PAD_SHIFT)) == 0u &&
                        (IDEMIP_CLOCK_PAD_MASK | (IDEMIP_CLOCK_PAD_STATE_MASK << IDEMIP_CLOCK_PAD_SHIFT)) ==
                            0xFFFFFFFFu,
                    "the pad and the state must fill the word and must not overlap");

#endif // IDEMIP_TIME_DETERMINISM_DEFINES_H
