// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file timeouts.c
 * @brief The deadline table and the context over it, both regions of the caller's borrow.
 *
 * Every entry is a function of the one pointer it is handed: the operand block, the context and the
 * table are regions of that borrow at compile-time offsets, and no entry reads or writes a byte
 * outside it. Two borrows therefore share nothing, and the same call on the same borrow does the
 * same thing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_ETHERNET

#include "idemIP/core/timeouts.h"

IDEMIP_BEGIN_DECLS

// One slot, padded to its published width so slot i sits at (i << SHIFT) and no index multiplies.
// next threads the armed slots in deadline order; a slot is free when flags carries no ARMED bit.
typedef struct
{
    uint32_t deadline_ms;
    IdemIpTimeoutUnit unit;
    uint8_t arg;
    uint8_t flags;
    uint8_t next;
} TimeoutEntry;

// The running context. magic is written by clear and read by every other entry, so a borrow that
// was never cleared is refused rather than run on whatever the caller's memory held.
typedef struct
{
    uint32_t magic;
    uint32_t now_ms;
    uint8_t head;
    uint8_t armed;
    uint8_t pad[2];
} TimeoutsCtx;

#define TIMEOUTS_MAGIC 0x54494D45u ///< what clear writes
#define TIMEOUTS_NONE 0xFFu        ///< the end of the armed list
#define TIMEOUTS_TAB_BYTES ((size_t)(IDEMIP_TIMEOUTS) << IDEMIP_TIMEOUT_ENTRY_SHIFT)

// Slot i sits at (i << IDEMIP_TIMEOUT_ENTRY_SHIFT), so the width is a power of two.
static_assert(sizeof(TimeoutEntry) == (1u << IDEMIP_TIMEOUT_ENTRY_SHIFT),
              "TimeoutEntry is not 1 << IDEMIP_TIMEOUT_ENTRY_SHIFT wide - pad it, or raise the shift in "
              "idemip_config.h");

// next is one octet, so the last index has to be below the sentinel.
static_assert(IDEMIP_TIMEOUTS <= TIMEOUTS_NONE, "IDEMIP_TIMEOUTS reaches the one-octet end-of-list sentinel");

// The caller's borrow, split: the operand block, the context, then the table. timeouts.h publishes
// the offsets; the asserts below prove the span covers them before anything runs.
static_assert(IDEMIP_TIMEOUTS_OFF_CTX + sizeof(TimeoutsCtx) <= IDEMIP_TIMEOUTS_OFF_TAB,
              "the operand block and the context overrun the table's offset - raise IDEMIP_TIMEOUTS_CTX_BYTES in "
              "idemip_config.h");
static_assert(IDEMIP_TIMEOUTS_OFF_TAB + TIMEOUTS_TAB_BYTES <= IDEMIP_TIMEOUTS_BORROW,
              "IDEMIP_TIMEOUTS_BORROW is short of the context and the table - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define TIMEOUTS_IO(w) IDEMIP_TIMEOUTS_IO(w)
#define TIMEOUTS_CTX(w) ((TimeoutsCtx *)(void *)((w) + IDEMIP_TIMEOUTS_OFF_CTX))
#define TIMEOUTS_AT(w, i)                                                                                              \
    ((TimeoutEntry *)(void *)((w) + IDEMIP_TIMEOUTS_OFF_TAB + ((size_t)(i) << IDEMIP_TIMEOUT_ENTRY_SHIFT)))

// --- the entries -----------------------------------------------------------

// Zeroes the table and the context, then marks the borrow bound. A zeroed slot carries
// IDEMIP_TIMEOUT_UNIT_NONE and no ARMED bit, so the list is empty and every slot is free.
static void timeouts_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_TIMEOUTS_OFF_CTX, 0, sizeof(TimeoutsCtx));
    memset(work + IDEMIP_TIMEOUTS_OFF_TAB, 0, TIMEOUTS_TAB_BYTES);
    TimeoutsCtx *ctx = TIMEOUTS_CTX(work);
    ctx->magic = TIMEOUTS_MAGIC;
    ctx->head = TIMEOUTS_NONE;
    TimeoutsIo *io = TIMEOUTS_IO(work);
    io->armed = 0;
    io->status = IDEMIP_OK;
}

static void timeouts_arm(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TimeoutsIo *io = TIMEOUTS_IO(work);
    io->status = IDEMIP_ERR;
    TimeoutsCtx *ctx = TIMEOUTS_CTX(work);
    if (ctx->magic != TIMEOUTS_MAGIC || io->arm_args.unit == IDEMIP_TIMEOUT_UNIT_NONE ||
        io->arm_args.unit >= IDEMIP_TIMEOUT_UNIT_COUNT)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.4b, one deadline per service, held in milliseconds and keyed on unit and arg.
    io->status = IDEMIP_ERR;
}

static void timeouts_cancel(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TimeoutsIo *io = TIMEOUTS_IO(work);
    io->status = IDEMIP_ERR;
    TimeoutsCtx *ctx = TIMEOUTS_CTX(work);
    if (ctx->magic != TIMEOUTS_MAGIC || io->cancel_args.unit == IDEMIP_TIMEOUT_UNIT_NONE ||
        io->cancel_args.unit >= IDEMIP_TIMEOUT_UNIT_COUNT)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.4b, a deadline is dropped by the unit that armed it, on resolution or timeout.
    io->status = IDEMIP_ERR;
}

static void timeouts_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TimeoutsIo *io = TIMEOUTS_IO(work);
    io->status = IDEMIP_ERR;
    TimeoutsCtx *ctx = TIMEOUTS_CTX(work);
    if (ctx->magic != TIMEOUTS_MAGIC)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.4b, the tick is the scheduler: it advances the list and reports the next deadline.
    io->status = IDEMIP_ERR;
}

static void timeouts_expire(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TimeoutsIo *io = TIMEOUTS_IO(work);
    io->status = IDEMIP_ERR;
    TimeoutsCtx *ctx = TIMEOUTS_CTX(work);
    if (ctx->magic != TIMEOUTS_MAGIC)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.4b, run each service's timers in dependency order, earliest deadline first.
    io->status = IDEMIP_ERR;
}

const TimeoutsNs Timeouts = {.clear = timeouts_clear,
                             .arm = timeouts_arm,
                             .cancel = timeouts_cancel,
                             .tick = timeouts_tick,
                             .expire = timeouts_expire};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET
