// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file mld6.c
 * @brief The RFC 2710 group membership table, in the caller's borrow.
 *
 * One entry per group an interface listens to, holding the group address, the interface, the sec 5
 * state, whether this node sent the last Report, and the report delay deadline in milliseconds. Every
 * entry is a function of the one pointer it is handed: the operand block, the context and the table
 * are all regions of that borrow, at compile-time offsets, and no entry reads or writes a byte
 * outside it.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV6

#include "idemIP/mld/mld6.h"

IDEMIP_BEGIN_DECLS

// One group on one interface. deadline_ms is the sec 4 report delay timer, drawn from
// [0, Maximum Response Delay] and held in the milliseconds sec 3.4 states that field in.
typedef struct
{
    uint32_t deadline_ms;
    uint8_t group[IDEMIP_IP6_ADDR_LEN];
    IdemIpMld6State state;
    uint8_t netif;
    idemip_bool last_reporter;
    idemip_bool used;
    uint8_t pad[8];
} Mld6Group;

// The running context. ready is the mark clear leaves, so a borrow no one cleared is refused.
typedef struct
{
    uint32_t now_ms;
    uint8_t groups;
    idemip_bool ready;
    uint8_t pad[2];
} Mld6Ctx;

// An index is (i << SHIFT), so each entry is exactly its width.
static_assert(sizeof(Mld6Group) == (1u << IDEMIP_MLD6_ENTRY_SHIFT),
              "a group entry must be 1 << IDEMIP_MLD6_ENTRY_SHIFT wide");
// The caller's borrow, split: the operand block, the context, then the table. mld6.h publishes the
// offsets; these two asserts prove the span covers them before anything runs. The first keeps the
// context inside the region ahead of the group table, the second the whole map inside the borrow.
static_assert(IDEMIP_MLD6_OFF_CTX + sizeof(Mld6Ctx) <= IDEMIP_MLD6_OFF_GROUPS,
              "IDEMIP_MLD6_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_MLD6_OFF_END <= IDEMIP_MLD6_BORROW,
              "IDEMIP_MLD6_BORROW is short of the map - raise IDEMIP_MLD6_CTX_BYTES in idemip_config.h");

// Every table index counts the entries the borrow holds, so IDEMIP_MLD6_NONE names none of them.
static_assert(IDEMIP_MLD6_GROUPS < IDEMIP_MLD6_NONE, "the table is wider than the index a result member carries");

// The regions, at their offsets in the caller's borrow.
#define MLD6_IO(w) IDEMIP_MLD6_IO(w)
#define MLD6_CTX(w) ((Mld6Ctx *)(void *)((w) + IDEMIP_MLD6_OFF_CTX))
#define MLD6_GROUP_AT(w, i)                                                                                            \
    ((Mld6Group *)(void *)((w) + IDEMIP_MLD6_OFF_GROUPS + ((size_t)(i) << IDEMIP_MLD6_ENTRY_SHIFT)))

// Octets the context and the table span, which is what clear zeroes.
#define MLD6_STATE_BYTES (IDEMIP_MLD6_OFF_END - IDEMIP_MLD6_OFF_CTX)

// --- the entries -----------------------------------------------------------

// Zeroes the context and the table, then marks the borrow this module's. A zeroed entry is in the
// sec 5 Non-Listener state, which "requires no storage in the node". The operand block is the
// caller's and is left alone.
static void mld6_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    Mld6Io *io = MLD6_IO(work);
    memset(work + IDEMIP_MLD6_OFF_CTX, 0, MLD6_STATE_BYTES);
    MLD6_CTX(work)->ready = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

static void mld6_join(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Mld6Io *io = MLD6_IO(work);
    Mld6Ctx *ctx = MLD6_CTX(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_MLD6_NONE;
    io->send_report = IDEMIP_FALSE;
    if (!ctx->ready || io->group_args.group == NULL || io->group_args.netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 2710 sec 4: "When a node starts listening to a multicast address on an interface,
    // it should immediately transmit an unsolicited Report for that address on that interface", and
    // sec 5's start listening transition into Delaying Listener.
    io->status = IDEMIP_ERR;
}

static void mld6_leave(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Mld6Io *io = MLD6_IO(work);
    Mld6Ctx *ctx = MLD6_CTX(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_MLD6_NONE;
    io->send_done = IDEMIP_FALSE;
    if (!ctx->ready || io->group_args.group == NULL || io->group_args.netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 2710 sec 4: a node ceasing to listen "SHOULD send a single Done message to the
    // link-scope all-routers multicast address (FF02::2)", and MAY send nothing when its last Report
    // was suppressed.
    io->status = IDEMIP_ERR;
}

static void mld6_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Mld6Io *io = MLD6_IO(work);
    Mld6Ctx *ctx = MLD6_CTX(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_MLD6_NONE;
    io->group = NULL;
    io->state = IDEMIP_MLD6_NON_LISTENER;
    io->deadline_ms = 0u;
    if (!ctx->ready || io->group_args.group == NULL)
    {
        return;
    }
    // PHASE 3: RFC 2710 sec 5, which holds one state per multicast address per interface.
    io->status = IDEMIP_ERR;
}

static void mld6_query_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Mld6Io *io = MLD6_IO(work);
    Mld6Ctx *ctx = MLD6_CTX(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_MLD6_NONE;
    io->send_report = IDEMIP_FALSE;
    if (!ctx->ready || (!io->query_args.general && io->query_args.group == NULL))
    {
        return;
    }
    // PHASE 3: RFC 2710 sec 4, which sets a timer per listened address on a General Query and one
    // timer on a Multicast-Address-Specific Query, each "to a different random value ... selected
    // from the range [0, Maximum Response Delay]", resets a running timer only when the requested
    // delay is less than what remains, and reports at once on a Maximum Response Delay of zero.
    io->status = IDEMIP_ERR;
}

static void mld6_report_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Mld6Io *io = MLD6_IO(work);
    Mld6Ctx *ctx = MLD6_CTX(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_MLD6_NONE;
    if (!ctx->ready || io->group_args.group == NULL)
    {
        return;
    }
    // PHASE 3: RFC 2710 sec 4: on another node's Report for an address whose timer is running, a node
    // "stops its timer and does not send a Report for that address, thus suppressing duplicate
    // reports on the link". sec 5 ignores it in Non-Listener and Idle Listener.
    io->status = IDEMIP_ERR;
}

static void mld6_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Mld6Io *io = MLD6_IO(work);
    Mld6Ctx *ctx = MLD6_CTX(work);
    io->status = IDEMIP_ERR;
    io->expired = 0u;
    io->send_report = IDEMIP_FALSE;
    io->index = IDEMIP_MLD6_NONE;
    if (!ctx->ready)
    {
        return;
    }
    // PHASE 3: RFC 2710 sec 4, where an expiring timer transmits a Report "to that address via that
    // interface", and sec 5's timer expired transition into Idle Listener with this node the last
    // reporter.
    io->status = IDEMIP_ERR;
}

const Mld6Ns Mld6 = {.clear = mld6_clear,
                     .join = mld6_join,
                     .leave = mld6_leave,
                     .find = mld6_find,
                     .query_in = mld6_query_in,
                     .report_in = mld6_report_in,
                     .tick = mld6_tick};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6
