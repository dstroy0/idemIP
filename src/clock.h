// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file clock.h
 * @brief Time. Three readings, each read-only, and the two calls that write them.
 *
 * The clock is system time and it is the input a timing correction is added to. Three quantities,
 * and each is a 32-bit count of something, which is one C type for all three: keeping them apart is
 * the whole point of this file.
 *
 *   now()     @ref idemip_clock_now, uint32_t. The caller's latest millisecond reading, verbatim.
 *             The only time value that crosses this library's surface, and not a clock: it wraps
 *             every 49.7 days. Read-only.
 *
 *   stamp()   @ref idemip_clock_stamp, uint32_t. The reading this pass entered on. Every function
 *             running in one pass measures its pad from the same instant, so a pass has one stamp
 *             and not one per entry. Read-only.
 *
 *   epoch()   @ref idemip_clock_epoch, IdemIpMs. now() carried across its wraps, 64 bits,
 *             monotonic. THIS is time. Every deadline is one of these and every question about
 *             time is one comparison of two. Read-only.
 *
 * The fourth reading, determinism_pad(), is time_determinism.h. It is a feature: CMake decides
 * whether it is built at all, and which grade's translation unit implements it.
 *
 * Two calls write - @ref idemip_clock_refresh, which carries a reading onto the epoch, and
 * @ref idemip_clock_open, which takes the stamp. Refreshing happens every pass; taking a stamp is a
 * decision a function makes when it starts work it means to pad.
 *
 * The failure this file exists to stop: a deadline stamped on the epoch and then swept against
 * now(). Both are unsigned and the compiler widens the reading silently, so it builds, and it is
 * right until the reading wraps or a lifetime pushes the deadline past what 32 bits of milliseconds
 * can count. After that the deadline is unreachable and the entry never expires.
 *
 * The table is the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_CLOCK_H
#define IDEMIP_CLOCK_H

#include "src/endian.h" // the fixed widths, IdemIpWord, and IDEMIP_INLINE
#include "src/ms.h"     // IdemIpMs, the epoch every reading here is carried onto

/** @brief Microseconds in a millisecond, the scale between the two grades below. */
#define IDEMIP_US_PER_MS 1000u

// ---------------------------------------------------------------------------
// What a pad is measured in
// ---------------------------------------------------------------------------
// CMake owns both values. They are here because IdemIpClock's own fields are gated on them and the
// struct is a type this header has to declare; what reads them otherwise is time_determinism.h.

#ifndef IDEMIP_ENABLE_TIME_DETERMINISM
#define IDEMIP_ENABLE_TIME_DETERMINISM 0
#endif

/** @brief Milliseconds. The epoch's own unit, so a pad costs no reading of its own. */
#define IDEMIP_DETERMINISM_COARSE 1

/** @brief Microseconds, taken as a second reading beside the epoch. */
#define IDEMIP_DETERMINISM_FINE 2

/**
 * @brief Microseconds, and the pad is not tuned: it is pinned to the measured worst case.
 *
 * FINE walks its pad towards the cost the function turns out to have on the host it is running on.
 * LITERAL does not walk: the ceiling is a compile-time constant per entry, measured beforehand, and
 * every call runs to it. A pass that outruns it reports OVER, which is a fault to be read and not a
 * step to be taken - the constant was wrong, or the host is not the one it was measured on.
 */
#define IDEMIP_DETERMINISM_LITERAL 3

/**
 * @brief Which of the three a build takes. CMake owns the value.
 *
 * COARSE is the cheap one and it is almost certainly the wrong one here: every entry this tree has
 * been measured at costs well under a microsecond, so padding to a millisecond pads to about thirty
 * thousand times the work. See test/bench/results.
 */
#ifndef IDEMIP_TIME_DETERMINISM_GRADE
#define IDEMIP_TIME_DETERMINISM_GRADE IDEMIP_DETERMINISM_FINE
#endif

/** @brief True when the pad is measured against a reading of its own rather than the epoch's. */
#define IDEMIP_DETERMINISM_HAS_TICK (IDEMIP_TIME_DETERMINISM_GRADE >= IDEMIP_DETERMINISM_FINE)

IDEMIP_BEGIN_DECLS

/**
 * @brief The three words a module keeps so the readings can be answered.
 *
 * It lives in the caller's borrow like everything else here, so two modules keeping time are two
 * borrows and share not one byte, and this file owns no storage of its own.
 *
 * One of these per unit, in that unit's own context, with the pads behind it - one word per entry
 * that pads, indexed by the entry:
 *
 *   typedef struct
 *   {
 *       uint32_t ready;
 *       IdemIpClock clock;
 *       uint32_t pad[IDEMIP_X_PADDED];
 *       ...
 *   } XCtx;
 *
 * The clock is per unit because a pass is per unit; the pad is per entry because it is the entry
 * that has a cost. How those bytes are carved stays the unit's, as every other region here is: this
 * file names no offset and reserves no storage.
 *
 * The pad array is words, so a unit with an odd number of padded entries owes the same rounding
 * this struct takes: what follows the array has to start on the system's word, or every access to it
 * is a split load. IDEMIP_ROUND_UP over the count is what the rest of the tree already uses.
 *
 * The tick fields are the clock's storage for the pad's own reading. time_determinism.h is what
 * reads and writes them; they are here because they are storage, and storage is what this type is.
 *
 * @var IdemIpClock::reading what now() answers: the last reading handed in
 * @var IdemIpClock::hi      how many times that reading has wrapped, which is what makes the epoch
 *                           64 bits without a second clock
 * @var IdemIpClock::stamp   what stamp() answers: the reading the current pass entered on
 * @var IdemIpClock::pad_to_word the fourth word. Three readings are twelve octets, which is not a
 *                           whole number of the system's word on a 64-bit target, so the region
 *                           behind this one would start off the word and every access to it would
 *                           be a split load. common.h asserts the width once that type is visible.
 */
typedef struct
{
    uint32_t reading;
    uint32_t hi;
    uint32_t stamp;
#if IDEMIP_ENABLE_TIME_DETERMINISM && IDEMIP_DETERMINISM_HAS_TICK
    uint32_t tick;       ///< the caller's reading in the pad's own unit, microseconds
    uint32_t tick_stamp; ///< it, at the instant the pass opened
#endif
    uint32_t pad_to_word;
} IdemIpClock;

/** @brief Dispatch table. Addressed by offset, so the layout is asserted below. */
typedef struct
{
    IdemIpMs (*refresh)(IdemIpClock *c, uint32_t now_ms);
    void (*open)(IdemIpClock *c);
    uint32_t (*now)(const IdemIpClock *c);
    uint32_t (*stamp)(const IdemIpClock *c);
    uint32_t (*elapsed)(const IdemIpClock *c);
    IdemIpMs (*epoch)(const IdemIpClock *c);
} ClockNs;
IDEMIP_NS_LAYOUT(ClockNs, refresh, open, now, stamp, elapsed, epoch);

/** @name The entries the table points at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The table is
 *         still the whole surface: call through it.
 *  @{ */
IdemIpMs idemip_clock_refresh(IdemIpClock *c, uint32_t now_ms);
void idemip_clock_open(IdemIpClock *c);
uint32_t idemip_clock_now(const IdemIpClock *c);
uint32_t idemip_clock_stamp(const IdemIpClock *c);
uint32_t idemip_clock_elapsed(const IdemIpClock *c);
IdemIpMs idemip_clock_epoch(const IdemIpClock *c);
/** @} */

/**
 * @brief Module namespace.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 *
 * Named clk rather than clock: <time.h> declares clock(), and a file that reads both would have
 * one spelling naming two things.
 */
IDEMIP_NS ClockNs clk IDEMIP_UNUSED = {
    .refresh = idemip_clock_refresh,
    .open = idemip_clock_open,
    .now = idemip_clock_now,
    .stamp = idemip_clock_stamp,
    .elapsed = idemip_clock_elapsed,
    .epoch = idemip_clock_epoch,
};

IDEMIP_END_DECLS

#endif // IDEMIP_CLOCK_H
