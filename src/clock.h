// idemIP v0.2.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
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
 * The padded call is time_determinism.h. It is a feature, and CMake decides whether the build has
 * it. Its pad counts ticks of its own clock, and it reads no field of this one.
 *
 * Two calls write - @ref idemip_clock_refresh, which carries a reading onto the epoch, and
 * @ref idemip_clock_open, which takes the stamp. A refresh comes on every pass. A function takes a
 * stamp when it starts work that it measures.
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

#include "src/endian.h" // the fixed widths, embed_word, and EMBED_INLINE
#include "src/ms.h"     // IdemIpMs, the epoch every reading here is carried onto

EMBED_BEGIN_DECLS

/**
 * @brief The three words a module keeps so the readings can be answered.
 *
 * It lives in the caller's borrow like everything else here, so two modules keeping time are two
 * borrows and share not one byte, and this file owns no storage of its own.
 *
 * One of these for each unit that keeps time, in the context of that unit. The unit sets its
 * offset, as it does for every other region. This file names no offset and reserves no storage.
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
EMBED_TABLE_LAYOUT(ClockNs, refresh, open, now, stamp, elapsed, epoch);

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
EMBED_TABLE_STORAGE ClockNs clk EMBED_UNUSED = {
    .refresh = idemip_clock_refresh,
    .open = idemip_clock_open,
    .now = idemip_clock_now,
    .stamp = idemip_clock_stamp,
    .elapsed = idemip_clock_elapsed,
    .epoch = idemip_clock_epoch,
};

EMBED_END_DECLS

#endif // IDEMIP_CLOCK_H
