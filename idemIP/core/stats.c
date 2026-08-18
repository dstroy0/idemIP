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

// --- which objects are Gauges ----------------------------------------------

// RFC 1213 sec 6.8 gives tcpCurrEstab SYNTAX Gauge. Every other object of sec 6.6 through sec 6.9 is
// SYNTAX Counter.
static idemip_bool stats_group_is_gauge(IdemIpStatsCounter id)
{
    return (id == IDEMIP_STAT_TCP_CURR_ESTAB) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 1213 sec 6.4 gives ifSpeed and ifOutQLen SYNTAX Gauge. The other eleven ifEntry objects here
// are SYNTAX Counter.
static idemip_bool stats_if_is_gauge(IdemIpStatsIfCounter id)
{
    return (id == IDEMIP_STAT_IF_SPEED || id == IDEMIP_STAT_IF_OUT_QLEN) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- the counter a call names ----------------------------------------------

// The group counter at (id << IDEMIP_STATS_CTR_SHIFT) in the counter block.
static uint32_t *stats_group_at(uint8_t *restrict work, IdemIpStatsCounter id)
{
    return &STATS_CTR(work)[id];
}

// The ifEntry counter the id names, in the row at (netif << IDEMIP_STATS_IF_ENTRY_SHIFT).
static uint32_t *stats_if_at(uint8_t *restrict work, uint8_t netif, IdemIpStatsIfCounter id)
{
    return &STATS_IF_AT(work, netif)->ctr[id];
}

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

// Adds ctr_args.value to a group Counter. RFC 1155 sec 3.2.3.3: a Counter increases monotonically to
// 2^32-1, then wraps and increases again from zero, which is the uint32_t sum. A Gauge id is refused,
// sec 3.2.3.4 letting a Gauge fall, so it is written by set instead.
//
// Every refusal is ERR and none is BUSY: an uncleared borrow, an id past the block, and a Gauge id
// all read the same on the next call, so retrying cannot succeed. Nothing here defers.
static void stats_bump(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    StatsIo *io = STATS_IO(work);
    io->status = IDEMIP_ERR;
    StatsCtx *ctx = STATS_CTX(work);
    if (ctx->magic != STATS_MAGIC || io->ctr_args.id >= IDEMIP_STAT_COUNT || stats_group_is_gauge(io->ctr_args.id))
    {
        return;
    }
    uint32_t *ctr = stats_group_at(work, io->ctr_args.id);
    *ctr = (uint32_t)(*ctr + io->ctr_args.value);
    io->status = IDEMIP_OK;
}

// Assigns ctr_args.value to a group Gauge. RFC 1155 sec 3.2.3.4: a Gauge rises and falls and latches
// at 2^32-1, which a uint32_t store cannot pass. A Counter id is refused, sec 3.2.3.3 having it
// increase monotonically, so it is reached by bump instead.
static void stats_set(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    StatsIo *io = STATS_IO(work);
    io->status = IDEMIP_ERR;
    StatsCtx *ctx = STATS_CTX(work);
    if (ctx->magic != STATS_MAGIC || io->ctr_args.id >= IDEMIP_STAT_COUNT || !stats_group_is_gauge(io->ctr_args.id))
    {
        return;
    }
    *stats_group_at(work, io->ctr_args.id) = io->ctr_args.value;
    io->status = IDEMIP_OK;
}

// Reports a group counter in io->value. RFC 1213 sec 6.6 through sec 6.9 give every object of those
// groups ACCESS read-only, Counter and Gauge alike, so both kinds read here.
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
    io->value = *stats_group_at(work, io->ctr_args.id);
    io->status = IDEMIP_OK;
}

// Adds if_args.value to one interface's ifEntry Counter, RFC 1213 sec 6.4. RFC 1155 sec 3.2.3.3
// wraps it at 2^32-1, which is the uint32_t sum. ifSpeed and ifOutQLen are refused, being Gauges.
static void stats_if_bump(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    StatsIo *io = STATS_IO(work);
    io->status = IDEMIP_ERR;
    StatsCtx *ctx = STATS_CTX(work);
    if (ctx->magic != STATS_MAGIC || io->if_args.netif >= IDEMIP_NETIF_COUNT ||
        io->if_args.id >= IDEMIP_STAT_IF_COUNT || stats_if_is_gauge(io->if_args.id))
    {
        return;
    }
    uint32_t *ctr = stats_if_at(work, io->if_args.netif, io->if_args.id);
    *ctr = (uint32_t)(*ctr + io->if_args.value);
    io->status = IDEMIP_OK;
}

// Assigns if_args.value to one interface's ifSpeed or ifOutQLen, the RFC 1213 sec 6.4 Gauges. RFC 1155
// sec 3.2.3.4 latches a Gauge at 2^32-1, which a uint32_t store cannot pass. A Counter id is refused.
static void stats_if_set(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    StatsIo *io = STATS_IO(work);
    io->status = IDEMIP_ERR;
    StatsCtx *ctx = STATS_CTX(work);
    if (ctx->magic != STATS_MAGIC || io->if_args.netif >= IDEMIP_NETIF_COUNT ||
        io->if_args.id >= IDEMIP_STAT_IF_COUNT || !stats_if_is_gauge(io->if_args.id))
    {
        return;
    }
    *stats_if_at(work, io->if_args.netif, io->if_args.id) = io->if_args.value;
    io->status = IDEMIP_OK;
}

// Reports one interface's ifEntry counter in io->value, RFC 1213 sec 6.4, Counter and Gauge alike.
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
    io->value = *stats_if_at(work, io->if_args.netif, io->if_args.id);
    io->status = IDEMIP_OK;
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
