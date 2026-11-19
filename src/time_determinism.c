// idemIP v0.2.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file time_determinism.c
 * @brief The padded call, at each of the three grades.
 *
 * Every entry below takes one parameter, a pointer to TimeDeterminismCtx. A padded call is the
 * borrow of the call site, the entry, the work of the entry, and its status member, so those are
 * one context.
 *
 * The pad counts ticks of the clock that embed_clock.h selects, at every grade. The grade sets the
 * unit of the window in idemip_config.h, and whether the pad walks. The difference of two readings
 * is unsigned, so a wrap between them subtracts out.
 *
 * Each step below has a theorem in theory/time_determinism. td_run is Slot.call, td_state is
 * Reading.classify, td_next is Word.next, and the ratchet that td_next applies is Ratchet.tune.
 */

#include "src/idemip_config.h" // the entry point: the widths and the window

#include "src/time_determinism.h"
#include "src/time_determinism_defines.h" // the pad word's layout

#if IDEMIP_ENABLE_TIME_DETERMINISM

#include "embed_clock.h"     // EMBED_CLOCK_HZ and the ticks in a microsecond
#include "embed_turnstile.h" // embed_thread_place

// embedded_types is a system include path in this build, and a compiler gives no warning from a
// system header. So this file gives the warnings of embed_clock.h again, for each clock value that
// the build does not set.
#ifdef EMBED_UNSET_CLOCK_HZ
EMBED_BUILD_WARNING("EMBED_CLOCK_HZ is not set, so a pad reads a tick as one microsecond. Set IDEMIP_CLOCK_HZ.")
#endif
#ifdef EMBED_UNSET_CLOCK_SOURCE
EMBED_BUILD_WARNING("EMBED_CLOCK_SOURCE is not set, so embed_clock.h took a default. Set IDEMIP_CLOCK_SOURCE.")
#endif
#ifdef EMBED_UNSET_CLOCK_CORE
EMBED_BUILD_WARNING("EMBED_CLOCK_CORE is not set, so the pinned counter is on core zero. Set IDEMIP_CLOCK_CORE.")
#endif

EMBED_BEGIN_DECLS

// The four states fit the two bits of the word.
EMBED_STATIC_ASSERT((uint32_t)IDEMIP_CLOCK_PAD_OVER <= IDEMIP_CLOCK_PAD_STATE_MASK,
                    "the four pad states must fit the two bits the pad word carries them in");

// A slot selects with a mask, so the count of slots is a power of two.
EMBED_STATIC_ASSERT(IDEMIP_PAD_THREADS >= 1u && (IDEMIP_PAD_THREADS & (IDEMIP_PAD_THREADS - 1u)) == 0u,
                    "IDEMIP_PAD_THREADS must be a power of two");

/** @brief Ticks of the clock in one unit of the window: a millisecond at COARSE, a microsecond otherwise. */
#if IDEMIP_TIME_DETERMINISM_GRADE == IDEMIP_DETERMINISM_COARSE
#define TD_TICKS_PER_UNIT ((uint32_t)EMBED_CLOCK_TICKS_PER_MICRO * 1000u)
#else
#define TD_TICKS_PER_UNIT ((uint32_t)EMBED_CLOCK_TICKS_PER_MICRO)
#endif

/** @brief 1 where the pad walks up on an overrun, 0 at LITERAL, where the pad never walks. */
#if IDEMIP_TIME_DETERMINISM_GRADE == IDEMIP_DETERMINISM_LITERAL
#define TD_WALKS 0u
#else
#define TD_WALKS 1u
#endif

/** @brief The ceiling of a pad, in ticks. */
#define TD_PAD_MAX_TICKS ((uint32_t)IDEMIP_DETERMINISM_PAD_MAX * TD_TICKS_PER_UNIT)

/** @brief The first pad of a slot, in ticks. */
#define TD_PAD_DEFAULT_TICKS ((uint32_t)IDEMIP_DETERMINISM_PAD_DEFAULT * TD_TICKS_PER_UNIT)

// The window is a window, and its ceiling in ticks fits the bits of the pad. The product is taken
// in 64 bits here, so a wide window fails the assert and does not wrap past it.
EMBED_STATIC_ASSERT(IDEMIP_DETERMINISM_PAD_MIN <= IDEMIP_DETERMINISM_PAD_DEFAULT &&
                        IDEMIP_DETERMINISM_PAD_DEFAULT <= IDEMIP_DETERMINISM_PAD_MAX,
                    "IDEMIP_DETERMINISM_PAD_DEFAULT must lie in [PAD_MIN, PAD_MAX]");
EMBED_STATIC_ASSERT((uint64_t)IDEMIP_DETERMINISM_PAD_MAX *(uint64_t)TD_TICKS_PER_UNIT <= IDEMIP_CLOCK_PAD_MASK,
                    "IDEMIP_DETERMINISM_PAD_MAX in ticks does not fit the thirty bits of a pad");

/** @brief One padded call, or one question about a call site. */
typedef struct
{
    uint8_t *pads;        /**< The borrow of the call site: one slot for each thread place. */
    const uint8_t *ro;    /**< The same borrow, read only. */
    IdemIpEntry entry;    /**< The entry that the call pads. */
    uint8_t *work;        /**< The work that the entry runs on. */
    IdemIpStatus *status; /**< The status member of the entry's operand block. */
} TimeDeterminismCtx;

/**
 * @brief The slot of the calling thread.
 * @param pads The borrow of the call site.
 * @return The slot that embed_thread_place selects, modulo IDEMIP_PAD_THREADS.
 */
EMBED_INLINE IdemIpPadSlot *td_slot(uint8_t *pads)
{
    const uint32_t place = (uint32_t)embed_thread_place() & (uint32_t)(IDEMIP_PAD_THREADS - 1u);
    return (IdemIpPadSlot *)(void *)(pads + ((size_t)place * IDEMIP_PAD_SLOT_BYTES));
}

/**
 * @brief Where a pass that spent `spent` ticks stands against a pad of `pad` ticks.
 * @param pad   The pad.
 * @param spent The ticks from the stamp to the reading.
 * @return UNSET where the pad is zero, EARLY below it, MET at it, and OVER past it.
 */
EMBED_INLINE IdemIpClockPad td_state(uint32_t pad, uint32_t spent)
{
    if (pad == 0u)
    {
        return IDEMIP_CLOCK_PAD_UNSET;
    }
    if (spent < pad)
    {
        return IDEMIP_CLOCK_PAD_EARLY;
    }
    return (spent == pad) ? IDEMIP_CLOCK_PAD_MET : IDEMIP_CLOCK_PAD_OVER;
}

/**
 * @brief The pad after a release, with no branch.
 * @param pad   The pad, which is not above TD_PAD_MAX_TICKS.
 * @param spent The ticks that the body spent.
 * @param over  1 where the body overran the pad and the grade walks, else 0.
 * @return The smaller of spent and the ceiling where over is 1, and pad where it is 0.
 *
 * cover is the smaller of spent and the ceiling. The mask of over adds the rise from the pad to
 * cover, or adds nothing. An overrun has spent above the pad, and the pad is not above the
 * ceiling, so cover is not below the pad and the subtraction does not wrap.
 */
EMBED_INLINE uint32_t td_next(uint32_t pad, uint32_t spent, uint32_t over)
{
    const uint32_t below = (uint32_t)(spent < TD_PAD_MAX_TICKS);
    const uint32_t cover = TD_PAD_MAX_TICKS ^ ((spent ^ TD_PAD_MAX_TICKS) & (0u - below));
    return pad + ((cover - pad) & (0u - over));
}

/**
 * @brief Set every slot of a call site to the default pad, with no result held.
 * @param t The call site.
 */
EMBED_INLINE void td_clear(const TimeDeterminismCtx *t)
{
    for (size_t place = 0u; place < (size_t)IDEMIP_PAD_THREADS; place++)
    {
        IdemIpPadSlot *const slot = (IdemIpPadSlot *)(void *)(t->pads + (place * IDEMIP_PAD_SLOT_BYTES));
        *slot = (IdemIpPadSlot){.word = TD_PAD_DEFAULT_TICKS, .held = EMBED_FALSE};
    }
}

/**
 * @brief One padded call.
 * @param t The call.
 *
 * A slot with no held result opens on a reading, runs the entry and keeps its status. A slot with a
 * held result runs no entry. Then both read the clock again. Inside the pad the slot holds the
 * result and the call answers IDEMIP_BUSY. Past it the call gives the kept status, and the slot
 * holds no result.
 *
 * The pad walks only on a call that ran the entry. That call measures the body. A held call
 * measures the gap between the calls of the program, which is not the cost of the body.
 */
EMBED_INLINE void td_run(const TimeDeterminismCtx *t)
{
    IdemIpPadSlot *const slot = td_slot(t->pads);
    const embed_bool ran = (embed_bool)!slot->held;
    if (ran)
    {
        slot->stamp = idemip_clock_ticks();
        t->entry(t->work);
        // Explicit cast keeps the one-octet status of the body
        slot->status = (uint8_t)*t->status;
    }
    const uint32_t spent = idemip_clock_ticks() - slot->stamp;
    const uint32_t pad = slot->word & IDEMIP_CLOCK_PAD_MASK;
    const IdemIpClockPad state = td_state(pad, spent);
    if (state == IDEMIP_CLOCK_PAD_EARLY)
    {
        slot->held = EMBED_TRUE;
        *t->status = IDEMIP_BUSY;
        return;
    }
    const uint32_t over = (uint32_t)ran & (uint32_t)(state == IDEMIP_CLOCK_PAD_OVER) & TD_WALKS;
    slot->word = ((uint32_t)state << IDEMIP_CLOCK_PAD_SHIFT) | (td_next(pad, spent, over) & IDEMIP_CLOCK_PAD_MASK);
    slot->held = EMBED_FALSE;
    // Explicit cast gives back the one-octet status that the body gave
    *t->status = (IdemIpStatus)slot->status;
}

/** @brief The pad of the calling thread's slot, in ticks. */
EMBED_INLINE uint32_t td_pad_ticks(const TimeDeterminismCtx *t)
{
    // Explicit cast drops the const for td_slot, which reads the slot and writes nothing here
    return td_slot((uint8_t *)(size_t)t->ro)->word & IDEMIP_CLOCK_PAD_MASK;
}

/** @brief The state of the last release of the calling thread's slot. */
EMBED_INLINE IdemIpClockPad td_last_state(const TimeDeterminismCtx *t)
{
    // Explicit cast drops the const for td_slot, which reads the slot and writes nothing here
    const uint32_t word = td_slot((uint8_t *)(size_t)t->ro)->word;
    return (IdemIpClockPad)((word >> IDEMIP_CLOCK_PAD_SHIFT) & IDEMIP_CLOCK_PAD_STATE_MASK);
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so these are what it points at. Each builds the context and hands it to the body above. */

void idemip_determinism_clear(uint8_t *pads)
{
    EMBED_CALL(td_clear, TimeDeterminismCtx, .pads = pads);
}

void idemip_determinism_run(uint8_t *pads, IdemIpEntry entry, uint8_t *work, IdemIpStatus *status)
{
    EMBED_CALL(td_run, TimeDeterminismCtx, .pads = pads, .entry = entry, .work = work, .status = status);
}

uint32_t idemip_determinism_pad_ticks(const uint8_t *pads)
{
    return EMBED_CALL(td_pad_ticks, TimeDeterminismCtx, .ro = pads);
}

IdemIpClockPad idemip_determinism_state(const uint8_t *pads)
{
    return EMBED_CALL(td_last_state, TimeDeterminismCtx, .ro = pads);
}

EMBED_END_DECLS

#endif // IDEMIP_ENABLE_TIME_DETERMINISM
