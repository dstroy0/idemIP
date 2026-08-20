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

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip6_addr.h"
#include "src/mld/mld6.h"

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

// RFC 4291 sec 2.7: an address whose first octet is 11111111 is multicast, and the low nibble of the
// second octet is the 4-bit scop field. Scope 1 is Interface-Local, which RFC 2710 calls node-local.
#define MLD6_MULTICAST_PREFIX 0xFFu
#define MLD6_SCOPE_MASK 0x0Fu
#define MLD6_SCOPE_INTERFACE_LOCAL 1u

// Redraws a masked value that landed above the bound before falling back to a narrower mask.
#define MLD6_DRAW_TRIES 8u

// The constant a zero word enters the mixer as, 2^32 divided by the golden ratio.
#define MLD6_MIX_SEED 0x9E3779B9u

// --- addresses -------------------------------------------------------------

// RFC 2710 sec 5: "MLD messages are never sent for multicast addresses whose scope is 0 (reserved)
// or 1 (node-local)", and the link-scope all-nodes address "never transitions to another state, and
// never sends a Report or Done". Everything else, sec 5 included, is reported. The scope test runs
// first, so the RFC 4291 sec 2.7.1 form ip6_addr.h names reaches this only at link scope.
static idemip_bool mld6_reportable(const uint8_t *addr)
{
    if ((addr[1] & MLD6_SCOPE_MASK) <= MLD6_SCOPE_INTERFACE_LOCAL)
    {
        return IDEMIP_FALSE;
    }
    return idemip_ip6_addr_is_all_nodes(addr) ? IDEMIP_FALSE : IDEMIP_TRUE;
}

// The sec 3.6 Multicast Address a Report or Done carries names a multicast address, RFC 4291 sec 2.7.
static idemip_bool mld6_is_multicast(const uint8_t *addr)
{
    return (addr[0] == MLD6_MULTICAST_PREFIX) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- the table -------------------------------------------------------------

// The entry a group holds on an interface, or IDEMIP_MLD6_NONE. RFC 2710 sec 5 keeps one state per
// multicast address per interface.
static uint8_t mld6_index_of(uint8_t *work, const uint8_t *group, uint8_t netif)
{
    for (uint8_t i = 0u; i < IDEMIP_MLD6_GROUPS; i++)
    {
        const Mld6Group *g = MLD6_GROUP_AT(work, i);
        if (g->used && g->netif == netif && idemip_bytes_eq(g->group, group, IDEMIP_IP6_ADDR_LEN))
        {
            return i;
        }
    }
    return IDEMIP_MLD6_NONE;
}

// The first entry no group holds, or IDEMIP_MLD6_NONE.
static uint8_t mld6_free_index(uint8_t *work)
{
    for (uint8_t i = 0u; i < IDEMIP_MLD6_GROUPS; i++)
    {
        if (!MLD6_GROUP_AT(work, i)->used)
        {
            return i;
        }
    }
    return IDEMIP_MLD6_NONE;
}

// Copies an entry into the result members.
static void mld6_report_entry(Mld6Io *io, const Mld6Group *g, uint8_t index)
{
    io->index = index;
    io->group = g->group;
    io->deadline_ms = g->deadline_ms;
    io->state = g->state;
    io->netif = g->netif;
    io->last_reporter = g->last_reporter;
}

// --- the clock -------------------------------------------------------------

// A deadline has passed when the signed difference against the clock is not negative, which keeps the
// comparison right across the millisecond clock's wrap.
static idemip_bool mld6_due(uint32_t now_ms, uint32_t deadline_ms)
{
    return ((int32_t)(now_ms - deadline_ms) >= 0) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// What is left of a running timer, zero once it is due.
static uint32_t mld6_remaining(uint32_t now_ms, uint32_t deadline_ms)
{
    return mld6_due(now_ms, deadline_ms) ? 0u : (deadline_ms - now_ms);
}

// --- the random delay ------------------------------------------------------

// xorshift32. A zero word has no successor under it, so it enters as MLD6_MIX_SEED.
static uint32_t mld6_mix(uint32_t x)
{
    uint32_t v = (x == 0u) ? MLD6_MIX_SEED : x;
    v ^= v << 13;
    v ^= v >> 17;
    v ^= v << 5;
    return v;
}

// RFC 2710 sec 4: a delay "selected from the range [0, Maximum Response Delay]". The mask is the next
// power of two above the bound, minus one, so a draw is an AND and never a divide. Each candidate
// advances the caller's word, so a candidate a draw rejected is never the next draw's first candidate;
// a bound of zero masks to zero and takes the first. After MLD6_DRAW_TRIES candidates land above the
// bound the mask's top bit drops, whose result is at most (mask >> 1) and so at most max - 1.
static uint32_t mld6_draw(uint32_t *state, uint32_t max)
{
    uint32_t mask = max;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
    for (uint8_t i = 0u; i < MLD6_DRAW_TRIES; i++)
    {
        *state = mld6_mix(*state);
        uint32_t d = *state & mask;
        if (d <= max)
        {
            return d;
        }
    }
    return *state & (mask >> 1);
}

// RFC 2710 sec 4: a timer that is not running starts at the drawn delay; one that is running "is reset
// to the new random value only if the requested Maximum Response Delay is less than the remaining
// value of the running timer". The comparison is against the requested delay, not the drawn one. A
// Maximum Response Delay of zero draws zero, so the deadline lands on the clock and the sweep fires it.
static idemip_bool mld6_arm(Mld6Group *g, uint32_t now_ms, uint32_t max_resp_ms, uint32_t draw_ms)
{
    if (g->state == IDEMIP_MLD6_DELAYING_LISTENER && max_resp_ms >= mld6_remaining(now_ms, g->deadline_ms))
    {
        return IDEMIP_FALSE;
    }
    g->deadline_ms = now_ms + draw_ms;
    g->state = IDEMIP_MLD6_DELAYING_LISTENER;
    return IDEMIP_TRUE;
}

// --- the entries -----------------------------------------------------------

// Zeroes the context and the table, then marks the borrow this module's. A zeroed entry is in the
// sec 5 Non-Listener state, which "requires no storage in the node". The operand block is the
// caller's and is left alone.
void idemip_mld6_clear(uint8_t *restrict work)
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

// RFC 2710 sec 5 start listening: "(send report, set flag, start timer)" into Delaying Listener. sec 4
// puts the unsolicited Report out at once and repeats it after IDEMIP_MLD6_JOIN_DELAY_MS, measured
// from the clock the last sweep left in the context. A group already listened to is not in Non-Listener
// state, where sec 5 puts start listening, so it transitions nothing and reports the entry it has.
// A full table is BUSY, since an entry frees when the node stops listening; a bad address or interface
// is ERR, since no retry changes it.
void idemip_mld6_join(uint8_t *restrict work)
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
    if (!mld6_is_multicast(io->group_args.group))
    {
        return;
    }

    uint8_t index = mld6_index_of(work, io->group_args.group, io->group_args.netif);
    if (index != IDEMIP_MLD6_NONE)
    {
        mld6_report_entry(io, MLD6_GROUP_AT(work, index), index);
        io->status = IDEMIP_OK;
        return;
    }

    index = mld6_free_index(work);
    if (index == IDEMIP_MLD6_NONE)
    {
        io->status = IDEMIP_BUSY;
        return;
    }

    Mld6Group *g = MLD6_GROUP_AT(work, index);
    memcpy(g->group, io->group_args.group, IDEMIP_IP6_ADDR_LEN);
    g->netif = io->group_args.netif;
    g->used = IDEMIP_TRUE;
    ctx->groups++;
    if (mld6_reportable(g->group))
    {
        // sec 5 start listening: "If this is an unsolicited Report, the timer is set to a delay value
        // chosen uniformly from the interval [0, [Unsolicited Report Interval] ]." A fixed delay would
        // put every node that joined at the same instant on the same repeat.
        uint32_t mixer = io->group_args.rand;
        g->state = IDEMIP_MLD6_DELAYING_LISTENER;
        g->last_reporter = IDEMIP_TRUE;
        g->deadline_ms = io->group_args.now_ms + mld6_draw(&mixer, (uint32_t)IDEMIP_MLD6_JOIN_DELAY_MS);
        io->send_report = IDEMIP_TRUE;
    }
    else
    {
        g->state = IDEMIP_MLD6_IDLE_LISTENER;
        g->last_reporter = IDEMIP_FALSE;
        g->deadline_ms = 0u;
    }
    mld6_report_entry(io, g, index);
    io->status = IDEMIP_OK;
}

// RFC 2710 sec 5 stop listening: "(stop timer, send done if flag set)" out of either listening state
// into Non-Listener, which "requires no storage in the node", so the entry frees. sec 4: a node "SHOULD
// send a single Done message to the link-scope all-routers multicast address (FF02::2)", and "if the
// node's most recent Report message was suppressed by hearing another Report message, it MAY send
// nothing". The freed entry is scrubbed, so the reported address is the caller's own operand.
void idemip_mld6_leave(uint8_t *restrict work)
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

    uint8_t index = mld6_index_of(work, io->group_args.group, io->group_args.netif);
    if (index == IDEMIP_MLD6_NONE)
    {
        return; // sec 5 puts stop listening only in Delaying Listener and Idle Listener
    }

    Mld6Group *g = MLD6_GROUP_AT(work, index);
    // sec 4: "If the node's most recent Report message was suppressed by hearing another Report
    // message, it MAY send nothing ... If this optimization is implemented, it MUST be able to be
    // turned off but SHOULD default to on." Off, the Done goes out for every group sec 5 reports at
    // all, and still for none of the ones it forbids MLD messages for.
    io->send_done = io->group_args.done_always ? mld6_reportable(g->group) : g->last_reporter;
    io->last_reporter = g->last_reporter;
    memset(g, 0, sizeof(*g));
    ctx->groups--;

    io->index = index;
    io->group = io->group_args.group;
    io->deadline_ms = 0u;
    io->state = IDEMIP_MLD6_NON_LISTENER;
    io->netif = io->group_args.netif;
    io->status = IDEMIP_OK;
}

// RFC 2710 sec 5, which holds one state per multicast address per interface. A group the node does not
// listen to on that interface is in Non-Listener state, which holds nothing to report, so it is ERR.
void idemip_mld6_find(uint8_t *restrict work)
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

    uint8_t index = mld6_index_of(work, io->group_args.group, io->group_args.netif);
    if (index == IDEMIP_MLD6_NONE)
    {
        return;
    }
    mld6_report_entry(io, MLD6_GROUP_AT(work, index), index);
    io->status = IDEMIP_OK;
}

// RFC 2710 sec 4. A General Query "sets a delay timer for each multicast address to which it is
// listening on the interface from which it received the Query, EXCLUDING the link-scope all-nodes
// address and any multicast addresses of scope 0 (reserved) or 1 (node-local)", each "to a different
// random value ... selected from the range [0, Maximum Response Delay]". A Multicast-Address-Specific
// Query sets the one address's timer the same way. Each draw advances the caller's word and no draw
// reuses a word another consumed, so the timers a General Query sets take different values. A Maximum
// Response Delay of zero draws zero, which
// lands the deadline on the clock and leaves the sec 5 timer expired action to the sweep that follows.
// A Query names a group in Non-Listener state, which sec 5 ignores and which no retry changes, so ERR.
void idemip_mld6_query_in(uint8_t *restrict work)
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
    if (io->query_args.netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }

    uint32_t mixer = io->query_args.rand;
    if (!io->query_args.general)
    {
        uint8_t index = mld6_index_of(work, io->query_args.group, io->query_args.netif);
        if (index == IDEMIP_MLD6_NONE)
        {
            return;
        }
        Mld6Group *g = MLD6_GROUP_AT(work, index);
        if (mld6_reportable(g->group))
        {
            (void)mld6_arm(g, io->query_args.now_ms, io->query_args.max_resp_ms,
                           mld6_draw(&mixer, io->query_args.max_resp_ms));
        }
        mld6_report_entry(io, g, index);
        io->status = IDEMIP_OK;
        return;
    }

    for (uint8_t i = 0u; i < IDEMIP_MLD6_GROUPS; i++)
    {
        Mld6Group *g = MLD6_GROUP_AT(work, i);
        if (!g->used || g->netif != io->query_args.netif || !mld6_reportable(g->group))
        {
            continue;
        }
        if (mld6_arm(g, io->query_args.now_ms, io->query_args.max_resp_ms,
                     mld6_draw(&mixer, io->query_args.max_resp_ms)))
        {
            mld6_report_entry(io, g, i);
        }
    }
    io->status = IDEMIP_OK;
}

// RFC 2710 sec 4: on another node's Report "for a multicast address while it has a timer running for
// that same address on that interface, it stops its timer and does not send a Report for that address,
// thus suppressing duplicate reports on the link". sec 5 draws that as "(stop timer, clear flag)" into
// Idle Listener, and "It is ignored in the Non-Listener or Idle Listener state". A Report for a group
// this node does not listen to on that interface is Non-Listener, which holds no entry, so it is ERR.
void idemip_mld6_report_in(uint8_t *restrict work)
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

    uint8_t index = mld6_index_of(work, io->group_args.group, io->group_args.netif);
    if (index == IDEMIP_MLD6_NONE)
    {
        return;
    }

    Mld6Group *g = MLD6_GROUP_AT(work, index);
    if (g->state == IDEMIP_MLD6_DELAYING_LISTENER)
    {
        g->state = IDEMIP_MLD6_IDLE_LISTENER;
        g->deadline_ms = 0u;
        g->last_reporter = IDEMIP_FALSE;
    }
    mld6_report_entry(io, g, index);
    io->status = IDEMIP_OK;
}

// RFC 2710 sec 4: "If a node's timer for a particular multicast address on a particular interface
// expires, the node transmits a Report to that address via that interface", which sec 5 draws as
// "timer expired (send report, set flag)" into Idle Listener. Mld6Io names one group and carries one
// send_report, so a sweep fires the first due timer and counts every timer due at this clock into
// expired; the caller sweeps again while send_report is set. Nothing here blocks, so a sweep with no
// timer due is OK with expired zero, not BUSY.
void idemip_mld6_tick(uint8_t *restrict work)
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
    ctx->now_ms = io->tick_args.now_ms;

    uint8_t first = IDEMIP_MLD6_NONE;
    for (uint8_t i = 0u; i < IDEMIP_MLD6_GROUPS; i++)
    {
        const Mld6Group *g = MLD6_GROUP_AT(work, i);
        if (g->used && g->state == IDEMIP_MLD6_DELAYING_LISTENER && mld6_due(ctx->now_ms, g->deadline_ms))
        {
            io->expired++;
            if (first == IDEMIP_MLD6_NONE)
            {
                first = i;
            }
        }
    }
    if (first == IDEMIP_MLD6_NONE)
    {
        io->group = NULL;
        io->status = IDEMIP_OK;
        return;
    }

    Mld6Group *g = MLD6_GROUP_AT(work, first);
    g->state = IDEMIP_MLD6_IDLE_LISTENER;
    g->last_reporter = IDEMIP_TRUE;
    g->deadline_ms = 0u;
    io->send_report = IDEMIP_TRUE;
    mld6_report_entry(io, g, first);
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
