// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file time_determinism_coarse.c
 * @brief The pad at the COARSE grade: milliseconds, off the epoch's own reading, and it walks.
 *
 * Every entry below takes one parameter, a pointer to TimeDeterminismCtx. A pad question is a
 * clock, the word the function remembers, and the bounds it may walk between, so those are one
 * context.
 *
 * The cheap grade: the pad costs no reading of its own, because it is measured in the unit the
 * epoch is already in. There is no microsecond reading at this grade, so @ref IdemIpClock carries
 * no tick and refresh_fine has nothing to take - it is present so the table is the same table at
 * every grade, and it does nothing.
 *
 * clock.h's own note on the choice: every entry this tree has been measured at costs well under a
 * microsecond, so padding to a millisecond pads to about thirty thousand times the work. See
 * test/bench/results.
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
    IdemIpClock *clk;      /**< The clock a reading would be written to. Unread at this grade. */
    const IdemIpClock *ro; /**< The clock a reading is taken from. */
    uint32_t word;         /**< What the function remembers: pad low, the last state high. */
    uint32_t now_us;       /**< The caller's microsecond reading. Unread at this grade. */
    uint32_t lo;           /**< The floor the caller allows, which a pad never steps below. */
    uint32_t hi;           /**< The ceiling, which a pad never steps above. */
    IdemIpClockPad state;  /**< Where this pass stood. */
} TimeDeterminismCtx;

/**
 * @brief Take a microsecond reading, of which this grade has none.
 * @param t The reading, unread.
 *
 * There is no tick at this grade, so there is nothing to take. It is here so that the table is the
 * same table whichever grade a build took, and a caller that refreshes unconditionally is right at
 * every one of them.
 */
IDEMIP_INLINE void td_refresh_fine(const TimeDeterminismCtx *t)
{
    (void)t;
}

/** @brief What one unit of a pad is: milliseconds at this grade, which is the epoch's own. */
IDEMIP_INLINE uint32_t td_tick(const TimeDeterminismCtx *t)
{
    return t->ro->reading;
}

/** @brief The stamp in that same unit, which is what the pad adds to. */
IDEMIP_INLINE uint32_t td_tick_stamp(const TimeDeterminismCtx *t)
{
    return t->ro->stamp;
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
    return (uint32_t)(t->ro->stamp + (t->word & IDEMIP_CLOCK_PAD_MASK));
}

/** @brief What this pass has cost so far, in the pad's unit. What a pad is tuned against. */
IDEMIP_INLINE uint32_t td_spent(const TimeDeterminismCtx *t)
{
    return (td_tick(t) - td_tick_stamp(t));
}

/** @brief The pad out of that word, for a caller that wants the milliseconds alone. */
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
 * nothing here sleeps, spins or holds a core, and a pad is not the exception. OVER is what a
 * function tunes on, since it is the one state that says the pad did not cover the work.
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
 * @brief One step of a pad, up or down, inside [lo, hi], with hysteresis.
 * @param t The step.
 * @return The word to remember, pad low and this pass's state high.
 *
 * The tuning itself, and the only arithmetic this file does on a pad. A millisecond at a time, so
 * the pad walks towards the cost the function actually has and settles there: OVER means the work
 * did not fit and the pad steps up, EARLY means there was room to spare so it steps down and the
 * next pass measures again, and MET is where a tuned pad stays. UNSET is a function with no pad,
 * which stays that way until one is set.
 *
 * Stepping on every pass would make the pad chase every disturbance, one millisecond up on a pass
 * that was interrupted and one back down after it, so it would never be still. The hysteresis is
 * that a state has to repeat before it moves anything: the word carries the state the last pass
 * ended in, this pass exclusive-ors the two, and only a zero - the same answer twice - opens the
 * step. An outlier changes what is remembered and moves the pad not at all.
 *
 * An exclusive-or, three compares, two ands and an add: no branch, no multiply, no divide and no
 * history beyond the word already loaded, so the pass that raises the pad costs what the pass that
 * leaves it alone costs. A function tuning itself must not be timed by whether it tuned.
 */
IDEMIP_INLINE uint32_t td_tune(const TimeDeterminismCtx *t)
{
    const uint32_t ms = t->word & IDEMIP_CLOCK_PAD_MASK;
    const uint32_t last = (t->word >> IDEMIP_CLOCK_PAD_SHIFT) & IDEMIP_CLOCK_PAD_STATE_MASK;
    const uint32_t seen = (uint32_t)t->state & IDEMIP_CLOCK_PAD_STATE_MASK;

    // The hysteresis, and the whole of it: zero means this pass agrees with the one before it, and
    // only agreement opens a step. The two bounds are anded in here rather than clamped afterwards,
    // so the step that would leave the range is the step that is never taken and nothing underflows.
    const uint32_t settled = (uint32_t)((last ^ seen) == 0u);
    const uint32_t up = settled & (uint32_t)(seen == (uint32_t)IDEMIP_CLOCK_PAD_OVER) & (uint32_t)(ms < t->hi);
    const uint32_t down = settled & (uint32_t)(seen == (uint32_t)IDEMIP_CLOCK_PAD_EARLY) & (uint32_t)(ms > t->lo);

    const uint32_t next = (ms + up - down);
    return (uint32_t)((seen << IDEMIP_CLOCK_PAD_SHIFT) | (next & IDEMIP_CLOCK_PAD_MASK));
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
