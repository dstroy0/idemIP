// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tick.c
 * @brief The three phases, in the one order PLAN.md sec 3.4b fixes, over the borrows the caller bound.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block, the context and the per-interface rows are regions of that borrow at compile-time offsets.
 * The phase and the two cursors live in the context, so where the order has reached is a property of
 * the borrow and not of the caller's control flow.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_ETHERNET

#include "idemIP/core/tick.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. cursor is the IdemIpTickUnit the phase has reached and
// if_cursor the interface inside a per-interface step; hold_desc is the descriptor the last step
// reported, which is unpinned on the step after so the caller reads the frame between the two.
typedef struct
{
    uint8_t *dispatch;
    uint8_t *timeouts;
    uint8_t *stats;
#if IDEMIP_ENABLE_IPV4
    uint8_t *arp;
    uint8_t *ip4_reass;
    uint8_t *igmp;
#endif
#if IDEMIP_ENABLE_IPV6
    uint8_t *ip6_reass;
    uint8_t *mld6;
#endif
    uint8_t *netif;
    uint32_t now_ms;
    uint32_t ready;
    uint16_t hold_desc;
    uint8_t hold_netif;
    uint8_t phase;
    uint8_t cursor;
    uint8_t if_cursor;
} TickCtx;

// The mark clear leaves.
#define TICK_READY 0x54494B4Bu

// One interface's row: its rings, its neighbor machine, and the transmit buffer the receive path
// builds a reply into. The fields fill the stride exactly on a target with 8-octet pointers, so the
// row is padded by the span it overlays rather than by a trailing array, which would be zero-sized
// there and is not C11.
typedef union
{
    struct
    {
        uint8_t *dma;
#if IDEMIP_ENABLE_IPV6
        uint8_t *nd6;
#endif
        uint8_t *out;
        size_t out_cap;
    } f;
    uint8_t pad[1u << IDEMIP_TICK_IF_ENTRY_SHIFT];
} TickIfRow;

static_assert(sizeof(TickIfRow) == (1u << IDEMIP_TICK_IF_ENTRY_SHIFT),
              "a TickIfRow is not 1 << IDEMIP_TICK_IF_ENTRY_SHIFT octets wide - raise the shift in "
              "idemip_config.h");

// The caller's borrow, split: the operand block, the context, then the table. tick.h publishes the
// offsets; the asserts below prove the span covers them before anything runs.
static_assert(IDEMIP_TICK_OFF_CTX + sizeof(TickCtx) <= IDEMIP_TICK_CTX_BYTES,
              "IDEMIP_TICK_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_TICK_OFF_END <= IDEMIP_TICK_BORROW,
              "IDEMIP_TICK_BORROW is short of the borrow map - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define T_IO(w) IDEMIP_TICK_IO(w)
#define T_CTX(w) ((TickCtx *)(void *)((w) + IDEMIP_TICK_OFF_CTX))
#define T_IF_AT(w, i) ((TickIfRow *)(void *)((w) + IDEMIP_TICK_OFF_IF + ((size_t)(i) << IDEMIP_TICK_IF_ENTRY_SHIFT)))

static idemip_bool t_ready(uint8_t *restrict work)
{
    return (idemip_bool)(T_CTX(work)->ready == TICK_READY);
}

static void t_reset(TickIo *io)
{
    io->unit = IDEMIP_TICK_UNIT_NONE;
    io->timeout_unit = IDEMIP_TIMEOUT_UNIT_NONE;
    io->timeout_arg = 0u;
    io->netif = IDEMIP_DISPATCH_NETIF_NONE;
    io->desc = IDEMIP_DISPATCH_DESC_NONE;
    io->len = 0u;
    io->ip = 0u;
}

// The interface a descriptor a shared unit handed back belongs to, read out of the descriptor.
//
// A retaining unit stores what dispatch handed it and reads no interface out of it, so what it
// hands back must name its own ring: dispatch files
// IDEMIP_DISPATCH_DESC_HANDLE(netif, index) and this takes the two apart again. An index alone
// would be ambiguous the moment a second interface has a ring, and the descriptor would be
// returned to an engine that never owned it, or to none.
static uint8_t t_desc_netif(uint16_t handle)
{
    return (handle == IDEMIP_DISPATCH_DESC_NONE) ? (uint8_t)IDEMIP_DISPATCH_NETIF_NONE
                                                 : IDEMIP_DISPATCH_DESC_NETIF(handle);
}

static void t_unpin(uint8_t *restrict work, uint8_t netif, uint16_t desc)
{
    if (netif >= IDEMIP_NETIF_COUNT || desc == IDEMIP_DISPATCH_DESC_NONE)
    {
        return;
    }
    TickIfRow *row = T_IF_AT(work, netif);
    if (row->f.dma == NULL)
    {
        return;
    }
    IDEMIP_DMA_IO(row->f.dma)->desc_args.index = IDEMIP_DISPATCH_DESC_INDEX(desc);
    Dma.unpin(row->f.dma);
}

// The descriptor the last step reported goes back now, the caller having had the call between the
// two to read it.
static void t_drop_hold(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    t_unpin(work, ctx->hold_netif, ctx->hold_desc);
    ctx->hold_desc = IDEMIP_DISPATCH_DESC_NONE;
    ctx->hold_netif = IDEMIP_DISPATCH_NETIF_NONE;
}

static void t_hold(uint8_t *restrict work, uint8_t netif, uint16_t desc, uint16_t len)
{
    TickCtx *ctx = T_CTX(work);
    TickIo *io = T_IO(work);
    ctx->hold_desc = desc;
    ctx->hold_netif = netif;
    io->desc = desc;
    io->len = len;
    io->netif = netif;
}

// --- phase 1, drain --------------------------------------------------------

// One frame off one ring, dispatched. A frame a retaining unit pinned stays out of the ring; every
// other one goes straight back.
static idemip_bool t_drain_one(uint8_t *restrict work, uint8_t netif)
{
    TickCtx *ctx = T_CTX(work);
    TickIo *io = T_IO(work);
    TickIfRow *row = T_IF_AT(work, netif);
    if (row->f.dma == NULL || ctx->dispatch == NULL)
    {
        return IDEMIP_FALSE;
    }
    Dma.rx_take(row->f.dma);
    DmaIo *dm = IDEMIP_DMA_IO(row->f.dma);
    if (dm->status != IDEMIP_OK || dm->buf == NULL)
    {
        return IDEMIP_FALSE;
    }
    uint8_t desc = dm->index;
    DispatchIo *di = IDEMIP_DISPATCH_IO(ctx->dispatch);
    di->input_args.frame = dm->buf;
    di->input_args.len = (size_t)dm->len;
    di->input_args.out = row->f.out;
    di->input_args.out_cap = row->f.out_cap;
    di->input_args.now_ms = ctx->now_ms;
    di->input_args.desc = desc;
    di->input_args.netif = netif;
    Dispatch.input(ctx->dispatch);

    io->netif = netif;
    io->desc = desc;
    io->len = dm->len;
    if ((di->act & IDEMIP_DISPATCH_ACT_PINNED) == 0u)
    {
        IDEMIP_DMA_IO(row->f.dma)->desc_args.index = desc;
        Dma.rx_post(row->f.dma);
    }
    io->frames = (uint16_t)(io->frames + 1u);
    return IDEMIP_TRUE;
}

// --- phase 2, the services in dependency order -----------------------------

#if IDEMIP_ENABLE_IPV4

// RFC 826 resolution ages first, because the queues that wait on it read what it releases. A tick
// report carrying a nonzero length is a held frame's descriptor; one carrying zero is an address a
// REQUEST is due for.
static idemip_bool t_service_arp(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    TickIo *io = T_IO(work);
    if (ctx->arp == NULL)
    {
        return IDEMIP_FALSE;
    }
    ArpTableIo *ar = IDEMIP_ARP_IO(ctx->arp);
    ar->now_ms = ctx->now_ms;
    ArpTable.tick(ctx->arp);
    if (ar->status != IDEMIP_OK)
    {
        return IDEMIP_FALSE;
    }
    io->ip = ar->ip;
    if (ar->len != 0u)
    {
        t_hold(work, t_desc_netif(ar->desc), ar->desc, ar->len);
    }
    return IDEMIP_TRUE;
}

static idemip_bool t_service_ip4_reass(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    if (ctx->ip4_reass == NULL)
    {
        return IDEMIP_FALSE;
    }
    IDEMIP_IP4_REASS_IO(ctx->ip4_reass)->now_ms = ctx->now_ms;
    Ip4Reass.tick(ctx->ip4_reass);
    return (idemip_bool)(IDEMIP_IP4_REASS_IO(ctx->ip4_reass)->status == IDEMIP_OK);
}

static idemip_bool t_service_igmp(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    if (ctx->igmp == NULL)
    {
        return IDEMIP_FALSE;
    }
    IDEMIP_IGMP_IO(ctx->igmp)->tick_args.now_ms = ctx->now_ms;
    Igmp.tick(ctx->igmp);
    return (idemip_bool)(IDEMIP_IGMP_IO(ctx->igmp)->status == IDEMIP_OK &&
                         IDEMIP_IGMP_IO(ctx->igmp)->expired != 0u);
}

#endif // IDEMIP_ENABLE_IPV4

#if IDEMIP_ENABLE_IPV6

// RFC 4861 sec 7.3.3, one interface's neighbor machine. Like ARP, a report carrying a length is a
// frame it held until resolution finished.
static idemip_bool t_service_nd6(uint8_t *restrict work, uint8_t netif)
{
    TickCtx *ctx = T_CTX(work);
    TickIo *io = T_IO(work);
    TickIfRow *row = T_IF_AT(work, netif);
    if (row->f.nd6 == NULL)
    {
        return IDEMIP_FALSE;
    }
    Nd6Io *nd = IDEMIP_ND6_IO(row->f.nd6);
    nd->tick_args.now_ms = ctx->now_ms;
    Nd6.tick(row->f.nd6);
    if (nd->status != IDEMIP_OK)
    {
        return IDEMIP_FALSE;
    }
    io->netif = netif;
    if (nd->len != 0u)
    {
        t_hold(work, netif, nd->desc, nd->len);
    }
    return IDEMIP_TRUE;
}

static idemip_bool t_service_ip6_reass(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    if (ctx->ip6_reass == NULL)
    {
        return IDEMIP_FALSE;
    }
    IDEMIP_IP6_REASS_IO(ctx->ip6_reass)->tick_args.now_ms = ctx->now_ms;
    Ip6Reass.tick(ctx->ip6_reass);
    return (idemip_bool)(IDEMIP_IP6_REASS_IO(ctx->ip6_reass)->status == IDEMIP_OK &&
                         IDEMIP_IP6_REASS_IO(ctx->ip6_reass)->expired != 0u);
}

static idemip_bool t_service_mld6(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    if (ctx->mld6 == NULL)
    {
        return IDEMIP_FALSE;
    }
    IDEMIP_MLD6_IO(ctx->mld6)->tick_args.now_ms = ctx->now_ms;
    Mld6.tick(ctx->mld6);
    return (idemip_bool)(IDEMIP_MLD6_IO(ctx->mld6)->status == IDEMIP_OK &&
                         IDEMIP_MLD6_IO(ctx->mld6)->expired != 0u);
}

#endif // IDEMIP_ENABLE_IPV6

// RFC 4862 sec 5.5.4, the address lifetimes.
static idemip_bool t_service_netif(uint8_t *restrict work)
{
#if IDEMIP_ENABLE_IPV6
    TickCtx *ctx = T_CTX(work);
    if (ctx->netif == NULL)
    {
        return IDEMIP_FALSE;
    }
    IDEMIP_NETIF_IO(ctx->netif)->tick_args.now_ms = ctx->now_ms;
    Netif.tick(ctx->netif);
    return (idemip_bool)(IDEMIP_NETIF_IO(ctx->netif)->status == IDEMIP_OK &&
                         IDEMIP_NETIF_IO(ctx->netif)->aged != 0u);
#else
    (void)work;
    return IDEMIP_FALSE;
#endif
}

// The deadline list. An expiry names a unit and an index into that unit's own table; the units this
// scheduler drives have already run above, and the pair is reported so a caller drives the rest.
static idemip_bool t_service_timeouts(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    TickIo *io = T_IO(work);
    if (ctx->timeouts == NULL)
    {
        return IDEMIP_FALSE;
    }
    Timeouts.expire(ctx->timeouts);
    TimeoutsIo *to = IDEMIP_TIMEOUTS_IO(ctx->timeouts);
    if (to->status != IDEMIP_OK)
    {
        return IDEMIP_FALSE;
    }
    io->timeout_unit = to->unit;
    io->timeout_arg = to->arg;
    return IDEMIP_TRUE;
}

// --- phase 3, the deferred work --------------------------------------------

#if IDEMIP_ENABLE_IPV4

// A frame ARP held until the REPLY arrived. Its descriptor is handed back on the step after this
// one, so the caller sends the frame in between.
static idemip_bool t_flush_arp(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    TickIo *io = T_IO(work);
    if (ctx->arp == NULL)
    {
        return IDEMIP_FALSE;
    }
    ArpTableIo *ar = IDEMIP_ARP_IO(ctx->arp);
    ar->now_ms = ctx->now_ms;
    ArpTable.dequeue(ctx->arp);
    if (ar->status != IDEMIP_OK)
    {
        return IDEMIP_FALSE;
    }
    io->ip = ar->ip;
    t_hold(work, ar->netif, ar->desc, ar->len);
    return IDEMIP_TRUE;
}

// RFC 791 sec 3.2 step (16), "free all reassembly resources for this BUFID": the descriptors a
// released or timed-out row held go back to the ring.
static idemip_bool t_flush_ip4_reass(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    if (ctx->ip4_reass == NULL)
    {
        return IDEMIP_FALSE;
    }
    IDEMIP_IP4_REASS_IO(ctx->ip4_reass)->now_ms = ctx->now_ms;
    Ip4Reass.reclaim(ctx->ip4_reass);
    if (IDEMIP_IP4_REASS_IO(ctx->ip4_reass)->status != IDEMIP_OK)
    {
        return IDEMIP_FALSE;
    }
    t_hold(work, t_desc_netif(IDEMIP_IP4_REASS_IO(ctx->ip4_reass)->desc), IDEMIP_IP4_REASS_IO(ctx->ip4_reass)->desc, 0u);
    return IDEMIP_TRUE;
}

#endif // IDEMIP_ENABLE_IPV4

#if IDEMIP_ENABLE_IPV6

// RFC 8200 sec 4.5: "reassembly of that packet must be abandoned and all the fragments that have been
// received for that packet must be discarded." Each fragment's descriptor is unpinned before the
// datagram's slot is freed, nothing being left to read out of a datagram given up on.
static idemip_bool t_flush_ip6_reass(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    TickIo *io = T_IO(work);
    if (ctx->ip6_reass == NULL)
    {
        return IDEMIP_FALSE;
    }
    Ip6ReassIo *re = IDEMIP_IP6_REASS_IO(ctx->ip6_reass);
    re->tick_args.now_ms = ctx->now_ms;
    Ip6Reass.tick(ctx->ip6_reass);
    if (re->status != IDEMIP_OK || re->expired == 0u)
    {
        return IDEMIP_FALSE;
    }
    uint8_t datagram = re->datagram;
    uint8_t frags = re->frag_count;
    uint8_t netif = IDEMIP_DISPATCH_NETIF_NONE;
    // The fragments of one datagram can have arrived on different interfaces, so each descriptor
    // names its own ring and is returned to that one. io->netif reports the last, which is what a
    // caller reads to know a ring moved.
    for (uint8_t i = 0u; i < frags; i++)
    {
        re->frag_args.datagram = datagram;
        re->frag_args.index = i;
        Ip6Reass.frag_at(ctx->ip6_reass);
        if (re->status == IDEMIP_OK)
        {
            netif = t_desc_netif(re->frag_desc);
            t_unpin(work, netif, re->frag_desc);
        }
    }
    re->drop_args.datagram = datagram;
    Ip6Reass.drop(ctx->ip6_reass);
    io->netif = netif;
    io->len = frags;
    return IDEMIP_TRUE;
}

#endif // IDEMIP_ENABLE_IPV6

#if IDEMIP_ENABLE_TCP

// RFC 9293 sec 3.10.7.4 (MUST-59): the batch is through, so the acknowledgments it aggregated go out
// now, one per connection.
static idemip_bool t_flush_tcp_ack(uint8_t *restrict work)
{
    TickCtx *ctx = T_CTX(work);
    TickIo *io = T_IO(work);
    if (ctx->dispatch == NULL)
    {
        return IDEMIP_FALSE;
    }
    Dispatch.tcp_ack(ctx->dispatch);
    if (IDEMIP_DISPATCH_IO(ctx->dispatch)->status != IDEMIP_OK)
    {
        return IDEMIP_FALSE;
    }
    io->netif = IDEMIP_DISPATCH_IO(ctx->dispatch)->netif;
    return IDEMIP_TRUE;
}

#endif // IDEMIP_ENABLE_TCP

// --- the entries -----------------------------------------------------------

static void tick_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_TICK_OFF_CTX, 0, IDEMIP_TICK_OFF_END - IDEMIP_TICK_OFF_CTX);
    TickCtx *ctx = T_CTX(work);
    ctx->hold_desc = IDEMIP_DISPATCH_DESC_NONE;
    ctx->hold_netif = IDEMIP_DISPATCH_NETIF_NONE;
    ctx->phase = (uint8_t)IDEMIP_TICK_PHASE_IDLE;
    ctx->ready = TICK_READY;
    TickIo *io = T_IO(work);
    t_reset(io);
    io->phase = IDEMIP_TICK_PHASE_IDLE;
    io->frames = 0u;
    io->steps = 0u;
    io->until_ms = IDEMIP_TIMEOUT_FOREVER;
    io->status = IDEMIP_OK;
}

static void tick_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TickIo *io = T_IO(work);
    io->status = IDEMIP_ERR;
    if (!t_ready(work))
    {
        return;
    }
    TickCtx *ctx = T_CTX(work);
    const TickBindArgs *b = &io->bind_args;
    ctx->dispatch = b->dispatch;
    ctx->timeouts = b->timeouts;
    ctx->stats = b->stats;
#if IDEMIP_ENABLE_IPV4
    ctx->arp = b->arp;
    ctx->ip4_reass = b->ip4_reass;
    ctx->igmp = b->igmp;
#endif
#if IDEMIP_ENABLE_IPV6
    ctx->ip6_reass = b->ip6_reass;
    ctx->mld6 = b->mld6;
#endif
    ctx->netif = b->netif;
    io->status = IDEMIP_OK;
}

static void tick_if_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TickIo *io = T_IO(work);
    io->status = IDEMIP_ERR;
    if (!t_ready(work) || io->if_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    TickIfRow *row = T_IF_AT(work, io->if_args.index);
    row->f.dma = io->if_args.dma;
#if IDEMIP_ENABLE_IPV6
    row->f.nd6 = io->if_args.nd6;
#endif
    row->f.out = io->if_args.out;
    row->f.out_cap = io->if_args.out_cap;
    io->status = IDEMIP_OK;
}

// The clock arrives from the caller and every deadline this tick compares is measured from it, so
// one tick is one instant however long its phases take.
static void tick_open(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TickIo *io = T_IO(work);
    io->status = IDEMIP_ERR;
    if (!t_ready(work))
    {
        return;
    }
    TickCtx *ctx = T_CTX(work);
    ctx->now_ms = io->open_args.now_ms;
    ctx->phase = (uint8_t)IDEMIP_TICK_PHASE_DRAIN;
    ctx->cursor = (uint8_t)IDEMIP_TICK_UNIT_ARP;
    ctx->if_cursor = 0u;
    t_reset(io);
    io->frames = 0u;
    io->steps = 0u;
    io->phase = IDEMIP_TICK_PHASE_DRAIN;
    io->until_ms = IDEMIP_TIMEOUT_FOREVER;
    if (ctx->timeouts != NULL)
    {
        IDEMIP_TIMEOUTS_IO(ctx->timeouts)->tick_args.now_ms = ctx->now_ms;
        Timeouts.tick(ctx->timeouts);
        if (IDEMIP_TIMEOUTS_IO(ctx->timeouts)->status == IDEMIP_OK)
        {
            io->until_ms = IDEMIP_TIMEOUTS_IO(ctx->timeouts)->until_ms;
        }
    }
    io->status = IDEMIP_OK;
}

static void tick_drain(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TickIo *io = T_IO(work);
    io->status = IDEMIP_ERR;
    if (!t_ready(work))
    {
        return;
    }
    TickCtx *ctx = T_CTX(work);
    io->phase = (IdemIpTickPhase)ctx->phase;
    if (ctx->phase != (uint8_t)IDEMIP_TICK_PHASE_DRAIN)
    {
        return; // out of its phase, which no retry changes
    }
    t_reset(io);
    while (ctx->if_cursor < (uint8_t)IDEMIP_NETIF_COUNT)
    {
        if (t_drain_one(work, ctx->if_cursor))
        {
            io->status = IDEMIP_OK;
            return;
        }
        ctx->if_cursor++;
    }
    ctx->phase = (uint8_t)IDEMIP_TICK_PHASE_SERVICE;
    ctx->cursor = (uint8_t)IDEMIP_TICK_UNIT_ARP;
    ctx->if_cursor = 0u;
    io->phase = IDEMIP_TICK_PHASE_SERVICE;
    io->status = IDEMIP_BUSY;
}

// One step of one service. A unit that reported work stays under the cursor, so it is asked again
// before the next unit runs; one that reported none moves the cursor on.
static void tick_service(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TickIo *io = T_IO(work);
    io->status = IDEMIP_ERR;
    if (!t_ready(work))
    {
        return;
    }
    TickCtx *ctx = T_CTX(work);
    io->phase = (IdemIpTickPhase)ctx->phase;
    if (ctx->phase != (uint8_t)IDEMIP_TICK_PHASE_SERVICE)
    {
        return;
    }
    t_reset(io);
    t_drop_hold(work);
    while (ctx->cursor <= (uint8_t)IDEMIP_TICK_UNIT_TIMEOUTS)
    {
        idemip_bool ran = IDEMIP_FALSE;
        switch ((IdemIpTickUnit)ctx->cursor)
        {
#if IDEMIP_ENABLE_IPV4
        case IDEMIP_TICK_UNIT_ARP:
            ran = t_service_arp(work);
            break;
        case IDEMIP_TICK_UNIT_IP4_REASS:
            ran = t_service_ip4_reass(work);
            break;
        case IDEMIP_TICK_UNIT_IGMP:
            ran = t_service_igmp(work);
            break;
#endif
#if IDEMIP_ENABLE_IPV6
        case IDEMIP_TICK_UNIT_ND6:
            while (ctx->if_cursor < (uint8_t)IDEMIP_NETIF_COUNT && !ran)
            {
                ran = t_service_nd6(work, ctx->if_cursor);
                if (!ran)
                {
                    ctx->if_cursor++;
                }
            }
            break;
        case IDEMIP_TICK_UNIT_IP6_REASS:
            ran = t_service_ip6_reass(work);
            break;
        case IDEMIP_TICK_UNIT_MLD6:
            ran = t_service_mld6(work);
            break;
#endif
        case IDEMIP_TICK_UNIT_NETIF:
            ran = t_service_netif(work);
            break;
        case IDEMIP_TICK_UNIT_TIMEOUTS:
            ran = t_service_timeouts(work);
            break;
        default:
            break;
        }
        if (ran)
        {
            io->unit = (IdemIpTickUnit)ctx->cursor;
            io->steps = (uint16_t)(io->steps + 1u);
            io->status = IDEMIP_OK;
            return;
        }
        ctx->cursor++;
        ctx->if_cursor = 0u;
    }
    ctx->phase = (uint8_t)IDEMIP_TICK_PHASE_FLUSH;
    ctx->cursor = (uint8_t)IDEMIP_TICK_UNIT_ARP_HOLD;
    io->phase = IDEMIP_TICK_PHASE_FLUSH;
    io->status = IDEMIP_BUSY;
}

static void tick_flush(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TickIo *io = T_IO(work);
    io->status = IDEMIP_ERR;
    if (!t_ready(work))
    {
        return;
    }
    TickCtx *ctx = T_CTX(work);
    io->phase = (IdemIpTickPhase)ctx->phase;
    if (ctx->phase != (uint8_t)IDEMIP_TICK_PHASE_FLUSH)
    {
        return;
    }
    t_reset(io);
    t_drop_hold(work);
    while (ctx->cursor < (uint8_t)IDEMIP_TICK_UNIT_COUNT)
    {
        idemip_bool ran = IDEMIP_FALSE;
        switch ((IdemIpTickUnit)ctx->cursor)
        {
#if IDEMIP_ENABLE_IPV4
        case IDEMIP_TICK_UNIT_ARP_HOLD:
            ran = t_flush_arp(work);
            break;
        case IDEMIP_TICK_UNIT_IP4_RECLAIM:
            ran = t_flush_ip4_reass(work);
            break;
#endif
#if IDEMIP_ENABLE_IPV6
        case IDEMIP_TICK_UNIT_IP6_DROP:
            ran = t_flush_ip6_reass(work);
            break;
#endif
#if IDEMIP_ENABLE_TCP
        case IDEMIP_TICK_UNIT_TCP_ACK:
            ran = t_flush_tcp_ack(work);
            break;
#endif
        default:
            break;
        }
        if (ran)
        {
            io->unit = (IdemIpTickUnit)ctx->cursor;
            io->steps = (uint16_t)(io->steps + 1u);
            io->status = IDEMIP_OK;
            return;
        }
        ctx->cursor++;
    }
    ctx->phase = (uint8_t)IDEMIP_TICK_PHASE_DONE;
    io->phase = IDEMIP_TICK_PHASE_DONE;
    io->status = IDEMIP_BUSY;
}

const TickNs Tick = {.clear = tick_clear,
                     .bind = tick_bind,
                     .if_bind = tick_if_bind,
                     .open = tick_open,
                     .drain = tick_drain,
                     .service = tick_service,
                     .flush = tick_flush};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET
