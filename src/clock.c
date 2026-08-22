// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file clock.c
 * @brief The three readings, and the two calls that write them.
 *
 * Every entry below takes one parameter, a pointer to ClockCtx. A reading is a clock and, when the
 * call writes, the value being carried onto it, so those are one context.
 *
 * The clock holds no storage of its own: the IdemIpClock is the caller's, in the caller's borrow,
 * so two modules keeping time are two borrows and share not one byte.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/clock.h"

IDEMIP_BEGIN_DECLS

/** @brief One reading, taken or carried. */
typedef struct
{
    IdemIpClock *clk;      /**< The clock a call writes. */
    const IdemIpClock *ro; /**< The clock a reading is taken from. */
    uint32_t now_ms;       /**< The caller's millisecond reading. */
} ClockCtx;

/**
 * @brief Take the caller's reading onto the epoch.
 * @param c The reading.
 * @return The epoch, so the caller that refreshes also gets the value it came for.
 *
 * A reading below the one before it has wrapped, which raises the high word. That is the two words
 * the module already holds, widened, and no second clock.
 *
 * Call this once at the top of an entry that reads or writes a deadline, before it does either. It
 * does not touch the stamp: refreshing is every pass, and taking a stamp is a separate decision the
 * function makes when it starts work it means to pad.
 */
IDEMIP_INLINE IdemIpMs clock_refresh(const ClockCtx *c)
{
    if (c->now_ms < c->clk->reading)
    {
        c->clk->hi++;
    }
    c->clk->reading = c->now_ms;
    return ((IdemIpMs)c->clk->hi << 32) | (IdemIpMs)c->now_ms;
}

/**
 * @brief Open a pass: the stamp every pad is then measured from is the reading standing now.
 * @param c The pass.
 */
IDEMIP_INLINE void clock_open(const ClockCtx *c)
{
    c->clk->stamp = c->clk->reading;
#if IDEMIP_ENABLE_TIME_DETERMINISM && IDEMIP_DETERMINISM_HAS_TICK
    c->clk->tick_stamp = c->clk->tick;
#endif
}

/** @brief now(): the caller's latest millisecond reading, verbatim. Wraps; not the epoch. */
IDEMIP_INLINE uint32_t clock_now(const ClockCtx *c)
{
    return c->ro->reading;
}

/** @brief stamp(): the reading this pass entered on, which every pad is measured from. */
IDEMIP_INLINE uint32_t clock_stamp(const ClockCtx *c)
{
    return c->ro->stamp;
}

/**
 * @brief What this pass has cost so far: now() less stamp().
 * @param c The reading.
 * @return The difference, in the reading's own unit.
 *
 * Both are the caller's own readings and the difference is taken unsigned, so a wrap between them
 * subtracts out. It is here rather than in time_determinism.h because it answers a question about
 * the stamp, which every build has; it is also what a pad is tuned against.
 */
IDEMIP_INLINE uint32_t clock_elapsed(const ClockCtx *c)
{
    return (c->ro->reading - c->ro->stamp);
}

/** @brief epoch(): now() carried across its wraps. This is time; deadlines are these. */
IDEMIP_INLINE IdemIpMs clock_epoch(const ClockCtx *c)
{
    return ((IdemIpMs)c->ro->hi << 32) | (IdemIpMs)c->ro->reading;
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so these are what it points at. Each builds the context and hands it to the body above.

   They are nameable rather than file local because a static const table in the header has to be
   able to point at them, and a static const table is what gcc devirtualizes. Through an extern one
   every call from another translation unit is a load of the table, a load of the entry, and an
   indirect call it cannot see through. */

IdemIpMs idemip_clock_refresh(IdemIpClock *c, uint32_t now_ms)
{
    return IDEMIP_CALL(clock_refresh, ClockCtx, .clk = c, .now_ms = now_ms);
}

void idemip_clock_open(IdemIpClock *c)
{
    IDEMIP_CALL(clock_open, ClockCtx, .clk = c);
}

uint32_t idemip_clock_now(const IdemIpClock *c)
{
    return IDEMIP_CALL(clock_now, ClockCtx, .ro = c);
}

uint32_t idemip_clock_stamp(const IdemIpClock *c)
{
    return IDEMIP_CALL(clock_stamp, ClockCtx, .ro = c);
}

uint32_t idemip_clock_elapsed(const IdemIpClock *c)
{
    return IDEMIP_CALL(clock_elapsed, ClockCtx, .ro = c);
}

IdemIpMs idemip_clock_epoch(const IdemIpClock *c)
{
    return IDEMIP_CALL(clock_epoch, ClockCtx, .ro = c);
}

IDEMIP_END_DECLS
