// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ms.c
 * @brief The arithmetic over the epoch: a lifetime into it, and it into two words and back.
 *
 * Every entry below takes one parameter, a pointer to MsCtx. These are functions of their operands
 * and of nothing else - no clock is read here, and nothing is held.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/ms.h"

/** @brief Milliseconds in a second, the scale between an RFC lifetime field and the epoch. */
#define IDEMIP_MS_PER_S 1000u

IDEMIP_BEGIN_DECLS

// The widest lifetime a 32-bit RFC seconds field can name has to convert into the epoch whole and
// still leave room to be added to a stamp, or a deadline would land behind the stamp that made it.
static_assert((IdemIpMs)0xFFFFFFFFu * (IdemIpMs)IDEMIP_MS_PER_S < (IdemIpMs)0xFFFFFFFFFFFFFFFFu / 2u,
              "the widest RFC lifetime field must convert into IdemIpMs with room to be added to a stamp");

static_assert(sizeof(IdemIpMs) == 8u, "idemip_ms_hi and idemip_ms_lo split a 64-bit epoch in two halves");

/** @brief One conversion, split or join. */
typedef struct
{
    IdemIpMs t;        /**< An epoch value being split. */
    uint32_t seconds;  /**< An RFC lifetime field, seconds. */
    uint32_t hi;       /**< The high half, joining. */
    uint32_t lo;       /**< The low half, joining. */
    uint32_t *hi_word; /**< The high word extend raises on each wrap. */
    uint32_t *last_ms; /**< The last reading extend saw, updated to now_ms. */
    uint32_t now_ms;   /**< The reading extend takes. */
} MsCtx;

/**
 * @brief One RFC lifetime field, seconds, as milliseconds on the epoch.
 * @param m The conversion.
 * @return That many milliseconds, as a duration.
 *
 * 1000 is 1024 - 16 - 8, so the scale is three shifts and two subtractions and no multiply. This is
 * for the moment a lifetime is taken, which turns it into a deadline; the sweep that reads that
 * deadline compares two epoch values and scales nothing.
 *
 * The result is a duration. It names no instant until it is added to an epoch value.
 */
IDEMIP_INLINE IdemIpMs ms_from_s(const MsCtx *m)
{
    IdemIpMs s = (IdemIpMs)m->seconds;
    return (s << 10) - (s << 4) - (s << 3);
}

/** @brief The high half of an epoch value. */
IDEMIP_INLINE uint32_t ms_hi(const MsCtx *m)
{
    return (uint32_t)(m->t >> 32);
}

/** @brief Its low half. */
IDEMIP_INLINE uint32_t ms_lo(const MsCtx *m)
{
    return (uint32_t)(m->t & 0xFFFFFFFFu);
}

/** @brief The two halves back into one epoch value. */
IDEMIP_INLINE IdemIpMs ms_join(const MsCtx *m)
{
    return ((IdemIpMs)m->hi << 32) | (IdemIpMs)m->lo;
}

/**
 * @brief idemip_clock_refresh over two loose words rather than an IdemIpClock.
 * @param m The reading.
 * @return The epoch, the high word having been raised if the reading wrapped.
 *
 * Same wrap rule and the same epoch. It opens no pass, so a function using this has no stamp() and
 * cannot be padded; a module that wants a pad holds an IdemIpClock instead.
 */
IDEMIP_INLINE IdemIpMs ms_extend(const MsCtx *m)
{
    if (m->now_ms < *m->last_ms)
    {
        (*m->hi_word)++;
    }
    *m->last_ms = m->now_ms;
    return ((IdemIpMs)(*m->hi_word) << 32) | (IdemIpMs)m->now_ms;
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so these are what it points at. Each builds the context and hands it to the body above. */

IdemIpMs idemip_ms_from_s(uint32_t seconds)
{
    return IDEMIP_CALL(ms_from_s, MsCtx, .seconds = seconds);
}

uint32_t idemip_ms_hi(IdemIpMs t)
{
    return IDEMIP_CALL(ms_hi, MsCtx, .t = t);
}

uint32_t idemip_ms_lo(IdemIpMs t)
{
    return IDEMIP_CALL(ms_lo, MsCtx, .t = t);
}

IdemIpMs idemip_ms_join(uint32_t hi, uint32_t lo)
{
    return IDEMIP_CALL(ms_join, MsCtx, .hi = hi, .lo = lo);
}

IdemIpMs idemip_ms_extend(uint32_t *last_ms, uint32_t *hi, uint32_t now_ms)
{
    return IDEMIP_CALL(ms_extend, MsCtx, .last_ms = last_ms, .hi_word = hi, .now_ms = now_ms);
}

IDEMIP_END_DECLS
