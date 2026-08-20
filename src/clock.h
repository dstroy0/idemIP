// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file clock.h
 * @brief Time. Four readings, each read-only, and the one call that refreshes them.
 *
 * The clock is system time and it is the input a timing correction is added to, so both jobs are
 * here and nowhere else. Four quantities, and three of them are a 32-bit count of something, which
 * is one C type for all three: keeping them apart is the whole point of this file.
 *
 *   now()              @ref idemip_clock_now, uint32_t. The caller's latest millisecond reading,
 *                      verbatim. The only time value that crosses this library's surface, and not a
 *                      clock: it wraps every 49.7 days. Read-only.
 *
 *   stamp()            @ref idemip_clock_stamp, uint32_t. The reading this pass entered on. Every
 *                      function running in one pass measures its pad from the same instant, so a
 *                      pass has one stamp and not one per entry. Read-only.
 *
 *   epoch()            @ref idemip_clock_epoch, IdemIpMs. now() carried across its wraps, 64 bits,
 *                      monotonic. THIS is time. Every deadline is one of these and every question
 *                      about time is one comparison of two. Read-only.
 *
 *   determinism_pad()  @ref idemip_determinism_pad, uint32_t. stamp() with one millisecond count
 *                      added: the pad a function times itself to tune, within a range, so that it
 *                      runs to the same instant every time rather than to whatever its inputs cost.
 *                      One value per function and the only thing a function remembers about its own
 *                      timing. The clock is handed it on every call and keeps no copy, because a
 *                      function retunes its pad and never tells the clock: a deadline cached here
 *                      would be one taken against a pad that no longer exists.
 *
 * Two calls write - @ref idemip_clock_refresh, which carries a reading onto the epoch, and
 * @ref idemip_clock_open, which takes the stamp. Refreshing happens every pass; taking a stamp is a
 * decision a function makes when it starts work it means to pad. Everything else here reads.
 *
 * The pad does not block, and the clock does not enforce it. @ref idemip_clock_pad_state reports
 * which of four states a pass stands in and the unit decides what to do: a unit inside its pad
 * reports IDEMIP_BUSY and is called again, which is the same answer this tree already gives for a
 * ring that is not ready and a deadline that has not passed. Nothing here sleeps, spins or holds a
 * core.
 *
 * The failure this file exists to stop: a deadline stamped on the epoch and then swept against
 * now(). Both are unsigned and the compiler widens the reading silently, so it builds, and it is
 * right until the reading wraps or a lifetime pushes the deadline past what 32 bits of milliseconds
 * can count. After that the deadline is unreachable and the entry never expires.
 */

#ifndef IDEMIP_CLOCK_H
#define IDEMIP_CLOCK_H

#include "src/endian.h" // the fixed widths, IdemIpWord, and IDEMIP_INLINE

IDEMIP_BEGIN_DECLS

/** @brief Milliseconds in a second, the scale between an RFC lifetime field and the epoch. */
#define IDEMIP_MS_PER_S 1000u

// ---------------------------------------------------------------------------
// The epoch
// ---------------------------------------------------------------------------

/**
 * @brief The clock everything is timed against: milliseconds, sixty-four bits.
 *
 * One word on a 64-bit target, two on a 32-bit one, four on a 16-bit one, so it is always a whole
 * number of dumb loads. Milliseconds throughout, so nothing is ever rounded to a second, and a span
 * of 584 million years, so a lifetime the RFCs state in a 32-bit seconds field converts into it
 * whole. It is one scalar, so an interval is one subtraction and a correction for deterministic
 * timing is one addition.
 */
typedef uint64_t IdemIpMs;

// The assert that this is a whole number of IdemIpWord sits in common.h, where that type is
// declared: this header is under it and cannot see it.

// The widest lifetime a 32-bit RFC seconds field can name has to convert into the epoch whole and
// still leave room to be added to a stamp, or a deadline would land behind the stamp that made it.
static_assert((IdemIpMs)0xFFFFFFFFu * (IdemIpMs)IDEMIP_MS_PER_S < (IdemIpMs)0xFFFFFFFFFFFFFFFFu / 2u,
              "the widest RFC lifetime field must convert into IdemIpMs with room to be added to a stamp");

// ---------------------------------------------------------------------------
// What a module holds
// ---------------------------------------------------------------------------

/**
 * @brief The three words a module keeps so the four readings can be answered.
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
    uint32_t pad_to_word;
} IdemIpClock;

// ---------------------------------------------------------------------------
// The one call that writes
// ---------------------------------------------------------------------------

/**
 * @brief Take the caller's reading onto the epoch.
 *
 * A reading below the one before it has wrapped, which raises the high word. That is the two words
 * the module already holds, widened, and no second clock.
 *
 * Call this once at the top of an entry that reads or writes a deadline, before it does either. It
 * does not touch the stamp: refreshing is every pass, and taking a stamp is a separate decision the
 * function makes when it starts work it means to pad.
 *
 * @return the epoch, so the caller that refreshes also gets the value it came for
 */
IDEMIP_INLINE IdemIpMs idemip_clock_refresh(IdemIpClock *c, uint32_t now_ms)
{
    if (now_ms < c->reading)
    {
        c->hi++;
    }
    c->reading = now_ms;
    return ((IdemIpMs)c->hi << 32) | (IdemIpMs)now_ms;
}

/** @brief Open a pass: the stamp every pad is then measured from is the reading standing now. */
IDEMIP_INLINE void idemip_clock_open(IdemIpClock *c)
{
    c->stamp = c->reading;
}

// ---------------------------------------------------------------------------
// The four readings
// ---------------------------------------------------------------------------

/** @brief now(): the caller's latest millisecond reading, verbatim. Wraps; not the epoch. */
IDEMIP_INLINE uint32_t idemip_clock_now(const IdemIpClock *c)
{
    return c->reading;
}

/** @brief stamp(): the reading this pass entered on, which every pad is measured from. */
IDEMIP_INLINE uint32_t idemip_clock_stamp(const IdemIpClock *c)
{
    return c->stamp;
}

/**
 * @brief What this pass has cost so far: now() less stamp().
 *
 * Both are the caller's own readings and the difference is taken unsigned, so a wrap between them
 * subtracts out. It is here rather than behind the determinism gate because it answers a question
 * about the stamp, which every build has; it is also what a pad is tuned against.
 */
IDEMIP_INLINE uint32_t idemip_clock_elapsed(const IdemIpClock *c)
{
    return (uint32_t)(c->reading - c->stamp);
}

/** @brief epoch(): now() carried across its wraps. This is time; deadlines are these. */
IDEMIP_INLINE IdemIpMs idemip_clock_epoch(const IdemIpClock *c)
{
    return ((IdemIpMs)c->hi << 32) | (IdemIpMs)c->reading;
}

// ---------------------------------------------------------------------------
// determinism_pad(), which a build chooses
// ---------------------------------------------------------------------------
// Determinism in the time domain is not something every target wants, and a target that does not
// want it should not carry the word per entry or the tuning. CMake owns the value: -D
// IDEMIP_ENABLE_TIME_DETERMINISM=ON puts this section in, and off leaves the file at now(), stamp() and
// epoch(), which every build needs either way.
//
// A pad is milliseconds and never needs thirty-two bits of them, so the top two carry the state the
// last pass ended in. That is the whole of a function's timing memory: one word, and the hysteresis
// below reads its own previous answer out of the same load that fetches the pad.

#ifndef IDEMIP_ENABLE_TIME_DETERMINISM
#define IDEMIP_ENABLE_TIME_DETERMINISM 0
#endif

#if IDEMIP_ENABLE_TIME_DETERMINISM

/** @brief Bits the pad itself occupies, low. */
#define IDEMIP_CLOCK_PAD_MASK 0x3FFFFFFFu

/** @brief Where the state the last pass ended in sits, high. */
#define IDEMIP_CLOCK_PAD_SHIFT 30u

/** @brief The two bits that state occupies once shifted down. */
#define IDEMIP_CLOCK_PAD_STATE_MASK 0x3u

/**
 * @brief determinism_pad(): the stamp with this function's pad added, which is the whole job.
 *
 * The clock adds and reports; it does not decide anything. It is handed @p pad on every call and
 * keeps no copy, because a function retunes its own pad and the clock is never told: a deadline
 * cached here would be one taken against a pad that no longer exists.
 *
 * @param pad the word this one function remembers, pad in the low bits. What it runs to, whatever
 *            its inputs cost.
 */
IDEMIP_INLINE uint32_t idemip_determinism_pad(const IdemIpClock *c, uint32_t pad)
{
    return (uint32_t)(c->stamp + (pad & IDEMIP_CLOCK_PAD_MASK));
}

/** @brief The pad out of that word, for a caller that wants the milliseconds alone. */
IDEMIP_INLINE uint32_t idemip_determinism_pad_ms(uint32_t pad)
{
    return pad & IDEMIP_CLOCK_PAD_MASK;
}

// ---------------------------------------------------------------------------
// Where the pass stands against the pad
// ---------------------------------------------------------------------------

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

// Four states is two bits, which is what leaves the state room in the top of the pad word and the
// hysteresis able to read its own previous answer out of the load that fetched the pad.
static_assert((uint32_t)IDEMIP_CLOCK_PAD_OVER <= IDEMIP_CLOCK_PAD_STATE_MASK,
              "the four pad states must fit the two bits the pad word carries them in");
static_assert((IDEMIP_CLOCK_PAD_MASK & (IDEMIP_CLOCK_PAD_STATE_MASK << IDEMIP_CLOCK_PAD_SHIFT)) == 0u &&
                  (IDEMIP_CLOCK_PAD_MASK | (IDEMIP_CLOCK_PAD_STATE_MASK << IDEMIP_CLOCK_PAD_SHIFT)) == 0xFFFFFFFFu,
              "the pad and the state must fill the word and must not overlap");

/**
 * @brief Where this pass stands against @p pad_ms, and nothing more.
 *
 * The clock reports; the unit decides. EARLY is what a unit turns into IDEMIP_BUSY, which is the
 * same answer it already gives for a ring that is not ready and a deadline that has not passed:
 * nothing here sleeps, spins or holds a core, and a pad is not the exception. OVER is what a
 * function tunes on, since it is the one state that says the pad did not cover the work.
 *
 * The difference is taken unsigned between two of the caller's own readings, so a wrap between them
 * subtracts out and no pad shorter than the reading's period is disturbed by one.
 */
IDEMIP_INLINE IdemIpClockPad idemip_clock_pad_state(const IdemIpClock *c, uint32_t pad_ms)
{
    if (pad_ms == 0u)
    {
        return IDEMIP_CLOCK_PAD_UNSET;
    }
    const uint32_t spent = (uint32_t)(c->reading - c->stamp);
    if (spent < pad_ms)
    {
        return IDEMIP_CLOCK_PAD_EARLY;
    }
    return (spent == pad_ms) ? IDEMIP_CLOCK_PAD_MET : IDEMIP_CLOCK_PAD_OVER;
}

/**
 * @brief One step of a pad, up or down, inside [@p lo, @p hi], with hysteresis.
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
 *
 * @param pad   the word this function remembers: pad low, the last state high
 * @param state where this pass stood, from @ref idemip_clock_pad_state
 * @param lo    the floor the caller allows, which a pad never steps below
 * @param hi    the ceiling, which a pad never steps above
 * @return the word to remember, pad low and this pass's state high
 */
IDEMIP_INLINE uint32_t idemip_determinism_tune(uint32_t pad, IdemIpClockPad state, uint32_t lo, uint32_t hi)
{
    const uint32_t ms = pad & IDEMIP_CLOCK_PAD_MASK;
    const uint32_t last = (pad >> IDEMIP_CLOCK_PAD_SHIFT) & IDEMIP_CLOCK_PAD_STATE_MASK;
    const uint32_t seen = (uint32_t)state & IDEMIP_CLOCK_PAD_STATE_MASK;

    // The hysteresis, and the whole of it: zero means this pass agrees with the one before it, and
    // only agreement opens a step. The two bounds are anded in here rather than clamped afterwards,
    // so the step that would leave the range is the step that is never taken and nothing underflows.
    const uint32_t settled = (uint32_t)((last ^ seen) == 0u);
    const uint32_t up = settled & (uint32_t)(seen == (uint32_t)IDEMIP_CLOCK_PAD_OVER) & (uint32_t)(ms < hi);
    const uint32_t down = settled & (uint32_t)(seen == (uint32_t)IDEMIP_CLOCK_PAD_EARLY) & (uint32_t)(ms > lo);

    const uint32_t next = (uint32_t)(ms + up - down);
    return (uint32_t)((seen << IDEMIP_CLOCK_PAD_SHIFT) | (next & IDEMIP_CLOCK_PAD_MASK));
}

#endif // IDEMIP_ENABLE_TIME_DETERMINISM

// ---------------------------------------------------------------------------
// A span off the wire
// ---------------------------------------------------------------------------

/**
 * @brief One RFC lifetime field, seconds, as milliseconds on the epoch.
 *
 * 1000 is 1024 - 16 - 8, so the scale is three shifts and two subtractions and no multiply. This is
 * for the moment a lifetime is taken, which turns it into a deadline; the sweep that reads that
 * deadline compares two epoch values and scales nothing.
 *
 * The result is a duration. It names no instant until it is added to an epoch value.
 */
IDEMIP_INLINE IdemIpMs idemip_ms_from_s(uint32_t seconds)
{
    IdemIpMs s = (IdemIpMs)seconds;
    return (s << 10) - (s << 4) - (s << 3);
}

// ---------------------------------------------------------------------------
// One epoch value in two words
// ---------------------------------------------------------------------------
// For a target whose registers do not hold 64 bits. Neither half is a time on its own.

/** @brief The high half of an epoch value. */
IDEMIP_INLINE uint32_t idemip_ms_hi(IdemIpMs t)
{
    return (uint32_t)(t >> 32);
}

/** @brief Its low half. */
IDEMIP_INLINE uint32_t idemip_ms_lo(IdemIpMs t)
{
    return (uint32_t)(t & 0xFFFFFFFFu);
}

/** @brief The two halves back into one epoch value. */
IDEMIP_INLINE IdemIpMs idemip_ms_join(uint32_t hi, uint32_t lo)
{
    return ((IdemIpMs)hi << 32) | (IdemIpMs)lo;
}

static_assert(sizeof(IdemIpMs) == 8u, "idemip_ms_hi and idemip_ms_lo split a 64-bit epoch in two halves");

// ---------------------------------------------------------------------------
// The reading, widened, for a module that keeps its two words itself
// ---------------------------------------------------------------------------

/**
 * @brief @ref idemip_clock_refresh over two loose words rather than an @ref IdemIpClock.
 *
 * Same wrap rule and the same epoch. It opens no pass, so a function using this has no stamp() and
 * cannot be padded; a module that wants a pad holds an @ref IdemIpClock instead.
 *
 * @param last_ms the last reading this module saw, updated to @p now_ms
 * @param hi      the high word, raised on each wrap
 */
IDEMIP_INLINE IdemIpMs idemip_ms_extend(uint32_t *last_ms, uint32_t *hi, uint32_t now_ms)
{
    if (now_ms < *last_ms)
    {
        (*hi)++;
    }
    *last_ms = now_ms;
    return ((IdemIpMs)(*hi) << 32) | (IdemIpMs)now_ms;
}

IDEMIP_END_DECLS

#endif // IDEMIP_CLOCK_H
