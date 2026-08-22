// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file time_determinism_defines.h
 * @brief How a pad word is laid out: the pad itself, and the state the last pass ended in.
 *
 * Constants only. No entry, no table, no storage.
 *
 * A pad is milliseconds and never needs thirty-two bits of them, so the top two carry the state the
 * last pass ended in. That is the whole of a function's timing memory: one word, and the hysteresis
 * reads its own previous answer out of the same load that fetched the pad.
 *
 * Separate from time_determinism.h so that including the module does not drag the layout in with
 * it. Included by the grade translation units, and by anything that composes a pad word itself.
 */

#ifndef IDEMIP_TIME_DETERMINISM_DEFINES_H
#define IDEMIP_TIME_DETERMINISM_DEFINES_H

#include "src/idemip_config.h"

/** @brief Bits the pad itself occupies, low. */
#define IDEMIP_CLOCK_PAD_MASK 0x3FFFFFFFu

/** @brief Where the state the last pass ended in sits, high. */
#define IDEMIP_CLOCK_PAD_SHIFT 30u

/** @brief The two bits that state occupies once shifted down. */
#define IDEMIP_CLOCK_PAD_STATE_MASK 0x3u

// The pad and the state fill the word and do not overlap.
static_assert((IDEMIP_CLOCK_PAD_MASK & (IDEMIP_CLOCK_PAD_STATE_MASK << IDEMIP_CLOCK_PAD_SHIFT)) == 0u &&
                  (IDEMIP_CLOCK_PAD_MASK | (IDEMIP_CLOCK_PAD_STATE_MASK << IDEMIP_CLOCK_PAD_SHIFT)) == 0xFFFFFFFFu,
              "the pad and the state must fill the word and must not overlap");

#endif // IDEMIP_TIME_DETERMINISM_DEFINES_H
