// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file time_determinism.h
 * @brief determinism_pad(): the fourth reading, which a build chooses.
 *
 * Determinism in the time domain is not something every target wants, and a target that does not
 * want it should not carry the word per entry or the tuning. CMake owns the value: -D
 * IDEMIP_ENABLE_TIME_DETERMINISM=ON puts this module in, and off leaves clock.h at now(), stamp()
 * and epoch(), which every build needs either way.
 *
 * Which grade it is built at is CMake's too, and it picks the translation unit: the pad is
 * milliseconds off the epoch at COARSE, microseconds off a reading of its own at FINE, and pinned
 * to a measured ceiling at LITERAL. Every entry below is there at every grade.
 *
 * The pad does not block, and the clock does not enforce it. pad_state reports which of four states
 * a pass stands in and the unit decides: a unit inside its pad reports IDEMIP_BUSY and is called
 * again. Nothing here sleeps, spins or holds a core.
 *
 * The table is the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_TIME_DETERMINISM_H
#define IDEMIP_TIME_DETERMINISM_H

#include "src/clock.h"

#if IDEMIP_ENABLE_TIME_DETERMINISM

IDEMIP_BEGIN_DECLS

/**
 * @brief The four answers, so the reading that tunes a pad and the reading that waits on one are
 *        the same reading.
 *
 * Told apart because a function needs all four: two of them mean carry on, one means come back, and
 * the last is the only evidence a pad is too small to hold.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_CLOCK_PAD_UNSET = 0, ///< no pad tuned on this function, so there is nothing to run to
    IDEMIP_CLOCK_PAD_EARLY,     ///< inside the pad: the unit reports IDEMIP_BUSY and is called again
    IDEMIP_CLOCK_PAD_MET,       ///< the pad elapsed exactly, which is what a tuned one does
    IDEMIP_CLOCK_PAD_OVER,      ///< the work outran the pad, so the pad is short and wants raising
} IdemIpClockPad;

/** @brief Dispatch table. Addressed by offset, so the layout is asserted below. */
typedef struct
{
    void (*refresh_fine)(IdemIpClock *c, uint32_t now_us);
    uint32_t (*pad)(const IdemIpClock *c, uint32_t word);
    uint32_t (*tick)(const IdemIpClock *c);
    uint32_t (*tick_stamp)(const IdemIpClock *c);
    uint32_t (*spent)(const IdemIpClock *c);
    uint32_t (*pad_ticks)(uint32_t word);
    IdemIpClockPad (*pad_state)(const IdemIpClock *c, uint32_t word);
    uint32_t (*tune)(uint32_t word, IdemIpClockPad state, uint32_t lo, uint32_t hi);
} TimeDeterminismNs;
IDEMIP_NS_LAYOUT(TimeDeterminismNs, refresh_fine, pad, tick, tick_stamp, spent, pad_ticks, pad_state, tune);

/** @name The entries the table points at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The table is
 *         still the whole surface: call through it.
 *  @{ */
void idemip_clock_refresh_fine(IdemIpClock *c, uint32_t now_us);
uint32_t idemip_determinism_pad(const IdemIpClock *c, uint32_t word);
uint32_t idemip_determinism_tick(const IdemIpClock *c);
uint32_t idemip_determinism_tick_stamp(const IdemIpClock *c);
uint32_t idemip_determinism_spent(const IdemIpClock *c);
uint32_t idemip_determinism_pad_ticks(uint32_t word);
IdemIpClockPad idemip_clock_pad_state(const IdemIpClock *c, uint32_t word);
uint32_t idemip_determinism_tune(uint32_t word, IdemIpClockPad state, uint32_t lo, uint32_t hi);
/** @} */

/**
 * @brief Module namespace.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS TimeDeterminismNs time_determinism IDEMIP_UNUSED = {
    .refresh_fine = idemip_clock_refresh_fine,
    .pad = idemip_determinism_pad,
    .tick = idemip_determinism_tick,
    .tick_stamp = idemip_determinism_tick_stamp,
    .spent = idemip_determinism_spent,
    .pad_ticks = idemip_determinism_pad_ticks,
    .pad_state = idemip_clock_pad_state,
    .tune = idemip_determinism_tune,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TIME_DETERMINISM

#endif // IDEMIP_TIME_DETERMINISM_H
