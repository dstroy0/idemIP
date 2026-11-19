// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file time_determinism.h
 * @brief The padded call: an entry that gives its result when its pad elapses, and not before.
 *
 * CMake owns IDEMIP_ENABLE_TIME_DETERMINISM. Off, this header declares nothing and the build has no
 * pad. On, the program pads each call that it wants padded with time_determinism.run.
 *
 * A padded call site has a borrow of IDEMIP_PAD_BORROW octets: one slot for each thread place. A
 * slot holds the pad, the stamp of the held call, the status that the body gave, and whether a
 * result is held. run reads the slot that embed_thread_place selects, so two cores keep two pads.
 *
 * The first call runs the entry. Where the pad has not elapsed, the slot keeps the status and the
 * call answers IDEMIP_BUSY. The program calls again with the same borrows. That call runs no entry:
 * it answers IDEMIP_BUSY until the pad elapses, and then it gives the kept status. The result
 * members of the entry's operand block hold what the entry wrote.
 *
 * The pad counts ticks of the clock that embed_clock.h selects. The program defines
 * idemip_clock_ticks, which reads that clock. The window in idemip_config.h is microseconds at FINE
 * and LITERAL and milliseconds at COARSE, and time_determinism.c scales it with EMBED_CLOCK_HZ.
 *
 * A pad walks up and never down. A body that overruns its pad raises the pad to the ticks that the
 * body spent, up to the ceiling. At LITERAL the pad never walks, and an overrun is a fault.
 *
 * theory/time_determinism proves the release window, the held result and the ratchet. It proves
 * the masks of the C on BitVec 32 too.
 *
 * Nothing here sleeps, spins or holds a core. The table is the whole surface.
 */

#ifndef IDEMIP_TIME_DETERMINISM_H
#define IDEMIP_TIME_DETERMINISM_H

#include "src/idemip_config.h" // IdemIpStatus, IDEMIP_ROUND_UP, IDEMIP_ALIGN and the window

#ifndef IDEMIP_ENABLE_TIME_DETERMINISM
#define IDEMIP_ENABLE_TIME_DETERMINISM 0
#endif

/** @brief Milliseconds: the window in idemip_config.h states a pad in milliseconds, and the pad walks. */
#define IDEMIP_DETERMINISM_COARSE 1

/** @brief Microseconds: the window states a pad in microseconds, and the pad walks. */
#define IDEMIP_DETERMINISM_FINE 2

/**
 * @brief Microseconds, and the pad never walks.
 *
 * The pad is IDEMIP_DETERMINISM_PAD_DEFAULT on every call. Measure the worst case first. A call
 * that overruns the pad reports OVER, which is a fault: the measure was wrong, or the host differs.
 */
#define IDEMIP_DETERMINISM_LITERAL 3

/** @brief Which of the three the build takes. CMake owns the value. */
#ifndef IDEMIP_TIME_DETERMINISM_GRADE
#define IDEMIP_TIME_DETERMINISM_GRADE IDEMIP_DETERMINISM_FINE
#endif

#if IDEMIP_ENABLE_TIME_DETERMINISM

EMBED_BEGIN_DECLS

/**
 * @brief Where a pass stands against its pad.
 *
 * EARLY holds the result. UNSET, MET and OVER give it. OVER is the one state that says the body
 * did not fit the pad.
 */
EMBED_ENUM_BYTE(IdemIpClockPad,
                IDEMIP_CLOCK_PAD_UNSET = 0, ///< the pad is zero, so the call gives its result at once
                IDEMIP_CLOCK_PAD_EARLY,     ///< inside the pad: the call answers IDEMIP_BUSY
                IDEMIP_CLOCK_PAD_MET,       ///< the pad elapsed to the tick
                IDEMIP_CLOCK_PAD_OVER,      ///< the pad elapsed before the call came back, or the body overran it
);

/**
 * @brief One thread's state for one padded call site.
 *
 * @var IdemIpPadSlot::word   the pad in ticks, low, and the state of the last release, high
 * @var IdemIpPadSlot::stamp  the reading that the held call opened on
 * @var IdemIpPadSlot::held   EMBED_TRUE while the slot holds a result
 * @var IdemIpPadSlot::status the status that the body gave, which the release gives
 */
typedef struct
{
    uint32_t word;
    uint32_t stamp;
    embed_bool held;
    uint8_t status;
    uint8_t pad_to_word[6];
} IdemIpPadSlot;

/** @brief Octets from one slot to the next, so that each slot starts on IDEMIP_ALIGN. */
#define IDEMIP_PAD_SLOT_BYTES IDEMIP_ROUND_UP(sizeof(IdemIpPadSlot), IDEMIP_ALIGN)

/** @brief Octets of the borrow of one padded call site: one slot for each thread place. */
#define IDEMIP_PAD_BORROW ((size_t)IDEMIP_PAD_THREADS * IDEMIP_PAD_SLOT_BYTES)

/** @brief An entry of a unit: the shape of every entry that a table holds. */
typedef void (*IdemIpEntry)(uint8_t *work);

/**
 * @brief The reading of the clock that embed_clock.h selects, in its own ticks.
 * @return The count of the clock, modulo 2^32.
 *
 * The program defines this. With EMBED_CLOCK_CALLER it reads the clock that the program runs. With
 * EMBED_CLOCK_OWN it reads the counter pinned to EMBED_CLOCK_CORE. A program that pads calls and
 * defines no reading fails at the link, and the error names this function.
 */
uint32_t idemip_clock_ticks(void);

/** @brief Dispatch table. Addressed by offset, so the layout is asserted below. */
typedef struct
{
    void (*clear)(uint8_t *pads);
    void (*run)(uint8_t *pads, IdemIpEntry entry, uint8_t *work, IdemIpStatus *status);
    uint32_t (*pad_ticks)(const uint8_t *pads);
    IdemIpClockPad (*state)(const uint8_t *pads);
} TimeDeterminismNs;
EMBED_TABLE_LAYOUT(TimeDeterminismNs, clear, run, pad_ticks, state);

/** @name The entries the table points at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The table is
 *         still the whole surface: call through it.
 *  @{ */
void idemip_determinism_clear(uint8_t *pads);
void idemip_determinism_run(uint8_t *pads, IdemIpEntry entry, uint8_t *work, IdemIpStatus *status);
uint32_t idemip_determinism_pad_ticks(const uint8_t *pads);
IdemIpClockPad idemip_determinism_state(const uint8_t *pads);
/** @} */

/**
 * @brief Module namespace.
 *
 * clear   sets every slot of a call site's borrow to the default pad, with no result held. Call it
 *         once, before the first run.
 * run     runs the entry on the work, or gives the held result, as this header describes. *status
 *         is the status member of the entry's operand block.
 * pad_ticks the pad of the calling thread's slot, in ticks.
 * state   the state of the last release of the calling thread's slot.
 *
 * @warning A call site pads one entry. Do not change the operands, and do not call another entry
 *          of the unit on the same work, while the slot holds a result: the held status belongs
 *          to the operands that the first call read.
 * @warning A held call must come back within 2^32 ticks. A later call reads a wrapped difference,
 *          and the release comes later still. theory/time_determinism proves that it never comes
 *          early.
 */
EMBED_TABLE_STORAGE TimeDeterminismNs time_determinism EMBED_UNUSED = {
    .clear = idemip_determinism_clear,
    .run = idemip_determinism_run,
    .pad_ticks = idemip_determinism_pad_ticks,
    .state = idemip_determinism_state,
};

EMBED_END_DECLS

#endif // IDEMIP_ENABLE_TIME_DETERMINISM

#endif // IDEMIP_TIME_DETERMINISM_H
