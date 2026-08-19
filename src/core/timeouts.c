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

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/core/timeouts.h"

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
#define TIMEOUTS_HALF_PERIOD_MS 0x7FFFFFFFu ///< half the millisecond count's range

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

// --- the list --------------------------------------------------------------

// Answers whether a precedes b on a count that wraps: the unsigned difference a - b lands in the
// upper half of the range. A plain a < b calls every deadline past the wrap due at once.
static idemip_bool timeouts_before(uint32_t a, uint32_t b)
{
    return (idemip_bool)((uint32_t)(a - b) > TIMEOUTS_HALF_PERIOD_MS);
}

// The index of the armed slot holding unit and arg, TIMEOUTS_NONE when none does.
static uint8_t timeouts_find(uint8_t *restrict work, IdemIpTimeoutUnit unit, uint8_t arg)
{
    for (uint8_t i = 0; i < (uint8_t)(IDEMIP_TIMEOUTS); i++)
    {
        const TimeoutEntry *e = TIMEOUTS_AT(work, i);
        if ((e->flags & (uint8_t)IDEMIP_TIMEOUT_FLAG_ARMED) != 0u && e->unit == unit && e->arg == arg)
        {
            return i;
        }
    }
    return TIMEOUTS_NONE;
}

// The index of the first slot carrying no ARMED bit, TIMEOUTS_NONE when every slot is armed.
static uint8_t timeouts_free(uint8_t *restrict work)
{
    for (uint8_t i = 0; i < (uint8_t)(IDEMIP_TIMEOUTS); i++)
    {
        if ((TIMEOUTS_AT(work, i)->flags & (uint8_t)IDEMIP_TIMEOUT_FLAG_ARMED) == 0u)
        {
            return i;
        }
    }
    return TIMEOUTS_NONE;
}

// Threads slot i into the deadline order, ahead of the first slot whose deadline it precedes. The
// compare is a difference of two deadlines, so the order does not move as now_ms advances.
static void timeouts_link(uint8_t *restrict work, uint8_t i)
{
    TimeoutsCtx *ctx = TIMEOUTS_CTX(work);
    TimeoutEntry *ins = TIMEOUTS_AT(work, i);
    uint8_t prev = TIMEOUTS_NONE;
    uint8_t cur = ctx->head;
    while (cur != TIMEOUTS_NONE && !timeouts_before(ins->deadline_ms, TIMEOUTS_AT(work, cur)->deadline_ms))
    {
        prev = cur;
        cur = TIMEOUTS_AT(work, cur)->next;
    }
    ins->next = cur;
    if (prev == TIMEOUTS_NONE)
    {
        ctx->head = i;
        return;
    }
    TIMEOUTS_AT(work, prev)->next = i;
}

// Takes slot i out of the deadline order, leaving its fields alone.
static void timeouts_unlink(uint8_t *restrict work, uint8_t i)
{
    TimeoutsCtx *ctx = TIMEOUTS_CTX(work);
    if (ctx->head == i)
    {
        ctx->head = TIMEOUTS_AT(work, i)->next;
        return;
    }
    uint8_t prev = ctx->head;
    while (prev != TIMEOUTS_NONE && TIMEOUTS_AT(work, prev)->next != i)
    {
        prev = TIMEOUTS_AT(work, prev)->next;
    }
    if (prev != TIMEOUTS_NONE)
    {
        TIMEOUTS_AT(work, prev)->next = TIMEOUTS_AT(work, i)->next;
    }
}

// Unlinks slot i and zeroes it, so a dropped deadline leaves the slot as clear left it.
static void timeouts_drop(uint8_t *restrict work, uint8_t i)
{
    timeouts_unlink(work, i);
    memset(TIMEOUTS_AT(work, i), 0, sizeof(TimeoutEntry));
    TIMEOUTS_CTX(work)->armed--;
}

// Writes what the list holds and the milliseconds from the recorded count to the earliest deadline:
// 0 when one is due, IDEMIP_TIMEOUT_FOREVER when the list is empty.
static void timeouts_report(uint8_t *restrict work)
{
    TimeoutsCtx *ctx = TIMEOUTS_CTX(work);
    TimeoutsIo *io = TIMEOUTS_IO(work);
    io->armed = ctx->armed;
    if (ctx->head == TIMEOUTS_NONE)
    {
        io->until_ms = IDEMIP_TIMEOUT_FOREVER;
        return;
    }
    uint32_t deadline = TIMEOUTS_AT(work, ctx->head)->deadline_ms;
    io->until_ms = timeouts_before(ctx->now_ms, deadline) ? (uint32_t)(deadline - ctx->now_ms) : 0u;
}

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
    timeouts_report(work);
    TIMEOUTS_IO(work)->status = IDEMIP_OK;
}

// Keys a slot on the unit and argument index and holds the deadline in milliseconds. A slot already
// holding that pair is rearmed in place, moving to the deadline the caller now names. A list with
// every slot armed is BUSY: a cancel or an expire frees one, so the retry can succeed.
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
    uint8_t i = timeouts_find(work, io->arm_args.unit, io->arm_args.arg);
    if (i != TIMEOUTS_NONE)
    {
        timeouts_unlink(work, i);
    }
    else
    {
        i = timeouts_free(work);
        if (i == TIMEOUTS_NONE)
        {
            timeouts_report(work);
            io->status = IDEMIP_BUSY;
            return;
        }
        ctx->armed++;
    }
    TimeoutEntry *e = TIMEOUTS_AT(work, i);
    e->deadline_ms = io->arm_args.deadline_ms;
    e->unit = io->arm_args.unit;
    e->arg = io->arm_args.arg;
    e->flags = (uint8_t)(io->arm_args.flags | (uint8_t)IDEMIP_TIMEOUT_FLAG_ARMED);
    timeouts_link(work, i);
    timeouts_report(work);
    io->status = IDEMIP_OK;
}

// Drops the deadline the unit and argument index name and frees its slot, leaving the order of the
// rest as it was. No slot holding that pair reports BUSY, which is what timeouts.h states for it.
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
    uint8_t i = timeouts_find(work, io->cancel_args.unit, io->cancel_args.arg);
    if (i == TIMEOUTS_NONE)
    {
        timeouts_report(work);
        io->status = IDEMIP_BUSY;
        return;
    }
    timeouts_drop(work, i);
    timeouts_report(work);
    io->status = IDEMIP_OK;
}

// Records the caller's millisecond count, which is the count expire compares each deadline against,
// and reports the wait to the earliest one. It drops nothing, so the list is unchanged.
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
    ctx->now_ms = io->tick_args.now_ms;
    timeouts_report(work);
    io->status = IDEMIP_OK;
}

// Takes the head of the deadline order when the recorded count has reached its deadline, reports the
// unit and argument index that named it, and frees the slot. Called again it takes the next one, so a
// caller drains every due deadline in order. Nothing due is BUSY: a later tick makes the head due.
static void timeouts_expire(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TimeoutsIo *io = TIMEOUTS_IO(work);
    io->status = IDEMIP_ERR;
    io->unit = IDEMIP_TIMEOUT_UNIT_NONE;
    io->arg = 0;
    io->deadline_ms = 0;
    TimeoutsCtx *ctx = TIMEOUTS_CTX(work);
    if (ctx->magic != TIMEOUTS_MAGIC)
    {
        return;
    }
    uint8_t i = ctx->head;
    if (i == TIMEOUTS_NONE || timeouts_before(ctx->now_ms, TIMEOUTS_AT(work, i)->deadline_ms))
    {
        timeouts_report(work);
        io->status = IDEMIP_BUSY;
        return;
    }
    const TimeoutEntry *e = TIMEOUTS_AT(work, i);
    io->unit = e->unit;
    io->arg = e->arg;
    io->deadline_ms = e->deadline_ms;
    timeouts_drop(work, i);
    timeouts_report(work);
    io->status = IDEMIP_OK;
}

const TimeoutsNs Timeouts = {.clear = timeouts_clear,
                             .arm = timeouts_arm,
                             .cancel = timeouts_cancel,
                             .tick = timeouts_tick,
                             .expire = timeouts_expire};

IDEMIP_END_DECLS
