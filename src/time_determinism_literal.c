// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file time_determinism_literal.c
 * @brief The pad at the LITERAL grade: microseconds, and the pad does not walk.
 *
 * Every entry below takes one parameter, a pointer to TimeDeterminismCtx. A pad question is a
 * clock, the word the function remembers, and the bounds it may walk between, so those are one
 * context.
 *
 * The readings are FINE's: a microsecond tick of its own, and the stamp taken in that same unit.
 * What differs is the tuning, and only the tuning. FINE walks its pad towards the cost the function
 * turns out to have on the host it is running on. LITERAL does not walk: the ceiling is a
 * compile-time constant per entry, measured beforehand, and every call runs to it. A pass that
 * outruns it reports OVER, which is a fault to be read and not a step to be taken - the constant
 * was wrong, or the host is not the one it was measured on.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/time_determinism.h"
#include "src/time_determinism_defines.h" // the pad word's layout

#if IDEMIP_ENABLE_TIME_DETERMINISM

IDEMIP_BEGIN_DECLS

// Four states is two bits, which is what leaves the state room in the top of the pad word and the
// hysteresis able to read its own previous answer out of the load that fetched the pad.
static_assert((uint32_t)IDEMIP_CLOCK_PAD_OVER <= IDEMIP_CLOCK_PAD_STATE_MASK,
              "the four pad states must fit the two bits the pad word carries them in");

/** @brief One pad reading, or one step of one. */
typedef struct
{
    IdemIpClock *clk;      /**< The clock a reading is written to. */
    const IdemIpClock *ro; /**< The clock a reading is taken from. */
    uint32_t word;         /**< What the function remembers: pad low, the last state high. */
    uint32_t now_us;       /**< The caller's microsecond reading. */
    uint32_t lo;           /**< The floor. Unread at this grade: the pad does not step. */
    uint32_t hi;           /**< The ceiling. Unread at this grade, the pad being pinned to it. */
    IdemIpClockPad state;  /**< Where this pass stood. */
} TimeDeterminismCtx;

/**
 * @brief Take the caller's microsecond reading, which is the one a pad is measured against.
 * @param t The reading.
 */
IDEMIP_INLINE void td_refresh_fine(const TimeDeterminismCtx *t)
{
    t->clk->tick = t->now_us;
}

/** @brief What one unit of a pad is: microseconds at this grade. */
IDEMIP_INLINE uint32_t td_tick(const TimeDeterminismCtx *t)
{
    return t->ro->tick;
}

/** @brief The stamp in that same unit, which is what the pad adds to. */
IDEMIP_INLINE uint32_t td_tick_stamp(const TimeDeterminismCtx *t)
{
    return t->ro->tick_stamp;
}

/**
 * @brief The stamp with this function's pad added, which is the whole job.
 * @param t The reading.
 * @return That instant, in the pad's unit.
 *
 * The clock adds and reports; it does not decide anything. It is handed the word on every call and
 * keeps no copy, because a function retunes its own pad and the clock is never told: a deadline
 * cached here would be one taken against a pad that no longer exists.
 */
IDEMIP_INLINE uint32_t td_pad(const TimeDeterminismCtx *t)
{
    return (uint32_t)(t->ro->tick_stamp + (t->word & IDEMIP_CLOCK_PAD_MASK));
}

/** @brief What this pass has cost so far, in the pad's unit. What the ceiling is checked against. */
IDEMIP_INLINE uint32_t td_spent(const TimeDeterminismCtx *t)
{
    return (td_tick(t) - td_tick_stamp(t));
}

/** @brief The pad out of that word, for a caller that wants the microseconds alone. */
IDEMIP_INLINE uint32_t td_pad_ticks(const TimeDeterminismCtx *t)
{
    return t->word & IDEMIP_CLOCK_PAD_MASK;
}

/**
 * @brief Where this pass stands against the pad, and nothing more.
 * @param t The reading.
 * @return Which of the four states the pass is in.
 *
 * The clock reports; the unit decides. EARLY is what a unit turns into IDEMIP_BUSY, which is the
 * same answer it already gives for a ring that is not ready and a deadline that has not passed:
 * nothing here sleeps, spins or holds a core, and a pad is not the exception. At this grade OVER is
 * a fault the caller reads rather than something to tune on.
 *
 * The difference is taken unsigned between two of the caller's own readings, so a wrap between them
 * subtracts out and no pad shorter than the reading's period is disturbed by one.
 */
IDEMIP_INLINE IdemIpClockPad td_pad_state(const TimeDeterminismCtx *t)
{
    const uint32_t want = t->word & IDEMIP_CLOCK_PAD_MASK;
    if (want == 0u)
    {
        return IDEMIP_CLOCK_PAD_UNSET;
    }
    const uint32_t spent = td_spent(t);
    if (spent < want)
    {
        return IDEMIP_CLOCK_PAD_EARLY;
    }
    return (spent == want) ? IDEMIP_CLOCK_PAD_MET : IDEMIP_CLOCK_PAD_OVER;
}

/**
 * @brief Remember where this pass stood. The pad itself does not move.
 * @param t The step.
 * @return The word to remember, the pad unchanged and this pass's state high.
 *
 * LITERAL does not walk. The ceiling was measured beforehand and every call runs to it, so the only
 * thing kept here is which state the pass ended in: OVER at this grade is a fault the caller reads,
 * not a step this takes. The bounds are the caller's and this reads neither.
 */
IDEMIP_INLINE uint32_t td_tune(const TimeDeterminismCtx *t)
{
    return (uint32_t)((((uint32_t)t->state & IDEMIP_CLOCK_PAD_STATE_MASK) << IDEMIP_CLOCK_PAD_SHIFT) |
                      (t->word & IDEMIP_CLOCK_PAD_MASK));
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so these are what it points at. Each builds the context and hands it to the body above. */

void idemip_clock_refresh_fine(IdemIpClock *c, uint32_t now_us)
{
    IDEMIP_CALL(td_refresh_fine, TimeDeterminismCtx, .clk = c, .now_us = now_us);
}

uint32_t idemip_determinism_pad(const IdemIpClock *c, uint32_t word)
{
    return IDEMIP_CALL(td_pad, TimeDeterminismCtx, .ro = c, .word = word);
}

uint32_t idemip_determinism_tick(const IdemIpClock *c)
{
    return IDEMIP_CALL(td_tick, TimeDeterminismCtx, .ro = c);
}

uint32_t idemip_determinism_tick_stamp(const IdemIpClock *c)
{
    return IDEMIP_CALL(td_tick_stamp, TimeDeterminismCtx, .ro = c);
}

uint32_t idemip_determinism_spent(const IdemIpClock *c)
{
    return IDEMIP_CALL(td_spent, TimeDeterminismCtx, .ro = c);
}

uint32_t idemip_determinism_pad_ticks(uint32_t word)
{
    return IDEMIP_CALL(td_pad_ticks, TimeDeterminismCtx, .word = word);
}

IdemIpClockPad idemip_clock_pad_state(const IdemIpClock *c, uint32_t word)
{
    return IDEMIP_CALL(td_pad_state, TimeDeterminismCtx, .ro = c, .word = word);
}

uint32_t idemip_determinism_tune(uint32_t word, IdemIpClockPad state, uint32_t lo, uint32_t hi)
{
    return IDEMIP_CALL(td_tune, TimeDeterminismCtx, .word = word, .state = state, .lo = lo, .hi = hi);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TIME_DETERMINISM
