// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file stats.c
 * @brief The counter block, the per-interface table, and the context over them, all regions of the
 *        caller's borrow.
 *
 * Every entry is a function of the one pointer it is handed: the operand block, the counters, the
 * interface table and the context are regions of that borrow at compile-time offsets, and no entry
 * reads or writes a byte outside it. Two borrows therefore share nothing, and the same call on the
 * same borrow does the same thing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_ETHERNET

#include "idemIP/core/stats.h"

IDEMIP_BEGIN_DECLS

// The pad below is the width left over, so the width has to cover the counters first.
static_assert((size_t)(1u << IDEMIP_STATS_IF_ENTRY_SHIFT) >= ((size_t)IDEMIP_STAT_IF_COUNT << IDEMIP_STATS_CTR_SHIFT),
              "an interface entry is narrower than the RFC 1213 sec 6.4 ifEntry counters - raise "
              "IDEMIP_STATS_IF_ENTRY_SHIFT in idemip_config.h");

// One interface's counters, padded to the published width so interface i sits at (i << SHIFT) and no
// index multiplies. RFC 1213 sec 6.4: the 13 counters and gauges of ifEntry, at the id's index.
typedef struct
{
    uint32_t ctr[IDEMIP_STAT_IF_COUNT];
    uint8_t pad[(1u << IDEMIP_STATS_IF_ENTRY_SHIFT) - ((size_t)IDEMIP_STAT_IF_COUNT << IDEMIP_STATS_CTR_SHIFT)];
} StatsIfEntry;

// The running context. magic is written by clear and read by every other entry, so a borrow that was
// never cleared is refused rather than run on whatever the caller's memory held.
typedef struct
{
    uint32_t magic;
} StatsCtx;

#define STATS_MAGIC 0x53544154u ///< what clear writes
#define STATS_CTR_BYTES ((size_t)IDEMIP_STAT_COUNT << IDEMIP_STATS_CTR_SHIFT)
#define STATS_IF_BYTES ((size_t)(IDEMIP_NETIF_COUNT) << IDEMIP_STATS_IF_ENTRY_SHIFT)

// A counter is read and written as a uint32_t at (id << IDEMIP_STATS_CTR_SHIFT).
static_assert(sizeof(uint32_t) == (1u << IDEMIP_STATS_CTR_SHIFT),
              "IDEMIP_STATS_CTR_SHIFT is not the width of a counter");

// Interface i sits at (i << IDEMIP_STATS_IF_ENTRY_SHIFT), so the width is a power of two.
static_assert(sizeof(StatsIfEntry) == (1u << IDEMIP_STATS_IF_ENTRY_SHIFT),
              "StatsIfEntry is not 1 << IDEMIP_STATS_IF_ENTRY_SHIFT wide - pad it, or raise the shift in "
              "idemip_config.h");

// RFC 1213: 17 counters in the IP group (sec 6.6) and 26 in the ICMP group (sec 6.7), one set for
// IPv4 and one for IPv6, then 10 in the TCP group (sec 6.8) and 4 in the UDP group (sec 6.9).
static_assert((size_t)IDEMIP_STAT_COUNT == ((17u + 26u) * 2u) + 10u + 4u,
              "the counter ids are not the RFC 1213 group field sets");
static_assert((size_t)IDEMIP_STAT_IF_COUNT == 13u, "the interface ids are not the RFC 1213 sec 6.4 ifEntry counters");

// The caller's borrow, split: the operand block, the counters, the context, then the interface
// table. stats.h publishes the offsets; the asserts below prove the span covers them before anything
// runs.
static_assert(IDEMIP_STATS_OFF_CTX + sizeof(StatsCtx) <= IDEMIP_STATS_OFF_IF,
              "the operand block, the counters and the context overrun the interface table's offset - raise "
              "IDEMIP_STATS_CTX_BYTES in idemip_config.h");
static_assert(IDEMIP_STATS_OFF_IF + STATS_IF_BYTES <= IDEMIP_STATS_BORROW,
              "IDEMIP_STATS_BORROW is short of the context and the interface table - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define STATS_IO(w) IDEMIP_STATS_IO(w)
#define STATS_CTX(w) ((StatsCtx *)(void *)((w) + IDEMIP_STATS_OFF_CTX))
#define STATS_CTR(w) ((uint32_t *)(void *)((w) + IDEMIP_STATS_OFF_CTR))
#define STATS_IF_AT(w, i)                                                                                              \
    ((StatsIfEntry *)(void *)((w) + IDEMIP_STATS_OFF_IF + ((size_t)(i) << IDEMIP_STATS_IF_ENTRY_SHIFT)))

// --- the entries -----------------------------------------------------------

// Zeroes the counter block, the interface table and the context, then marks the borrow bound.
static void stats_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_STATS_OFF_CTR, 0, STATS_CTR_BYTES);
    memset(work + IDEMIP_STATS_OFF_CTX, 0, sizeof(StatsCtx));
    memset(work + IDEMIP_STATS_OFF_IF, 0, STATS_IF_BYTES);
    StatsCtx *ctx = STATS_CTX(work);
    ctx->magic = STATS_MAGIC;
    StatsIo *io = STATS_IO(work);
    io->value = 0;
    io->status = IDEMIP_OK;
}

static void stats_bump(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    StatsIo *io = STATS_IO(work);
    io->status = IDEMIP_ERR;
    StatsCtx *ctx = STATS_CTX(work);
    if (ctx->magic != STATS_MAGIC || io->ctr_args.id >= IDEMIP_STAT_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 1155 sec 3.2.3.3, a Counter wraps at 2^32-1 and starts again from zero.
    io->status = IDEMIP_ERR;
}

static void stats_set(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    StatsIo *io = STATS_IO(work);
    io->status = IDEMIP_ERR;
    StatsCtx *ctx = STATS_CTX(work);
    if (ctx->magic != STATS_MAGIC || io->ctr_args.id >= IDEMIP_STAT_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 1155 sec 3.2.3.4, a Gauge may rise or fall and latches at 2^32-1.
    io->status = IDEMIP_ERR;
}

static void stats_read(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    StatsIo *io = STATS_IO(work);
    io->status = IDEMIP_ERR;
    io->value = 0;
    StatsCtx *ctx = STATS_CTX(work);
    if (ctx->magic != STATS_MAGIC || io->ctr_args.id >= IDEMIP_STAT_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 1213 sec 6.6 through sec 6.9, the group counter the id names.
    io->status = IDEMIP_ERR;
}

static void stats_if_bump(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    StatsIo *io = STATS_IO(work);
    io->status = IDEMIP_ERR;
    StatsCtx *ctx = STATS_CTX(work);
    if (ctx->magic != STATS_MAGIC || io->if_args.netif >= IDEMIP_NETIF_COUNT || io->if_args.id >= IDEMIP_STAT_IF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 1213 sec 6.4, the ifEntry Counter objects of one interface.
    io->status = IDEMIP_ERR;
}

static void stats_if_set(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    StatsIo *io = STATS_IO(work);
    io->status = IDEMIP_ERR;
    StatsCtx *ctx = STATS_CTX(work);
    if (ctx->magic != STATS_MAGIC || io->if_args.netif >= IDEMIP_NETIF_COUNT || io->if_args.id >= IDEMIP_STAT_IF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 1213 sec 6.4, ifSpeed and ifOutQLen are the ifEntry Gauge objects.
    io->status = IDEMIP_ERR;
}

static void stats_if_read(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    StatsIo *io = STATS_IO(work);
    io->status = IDEMIP_ERR;
    io->value = 0;
    StatsCtx *ctx = STATS_CTX(work);
    if (ctx->magic != STATS_MAGIC || io->if_args.netif >= IDEMIP_NETIF_COUNT || io->if_args.id >= IDEMIP_STAT_IF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 1213 sec 6.4, the ifEntry counter the id names, on the interface it names.
    io->status = IDEMIP_ERR;
}

const StatsNs Stats = {.clear = stats_clear,
                       .bump = stats_bump,
                       .set = stats_set,
                       .read = stats_read,
                       .if_bump = stats_if_bump,
                       .if_set = stats_if_set,
                       .if_read = stats_if_read};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET
