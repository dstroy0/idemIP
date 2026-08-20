// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file igmp.c
 * @brief The RFC 2236 group membership table, in the caller's borrow.
 *
 * One entry per group an interface is a member of, holding the group address, the interface, the sec 6
 * state, whether this host sent the last Report, and the report delay deadline in milliseconds. The
 * context carries the sec 4 record of an IGMPv1 Querier, one deadline per interface. Every entry is a
 * function of the one pointer it is handed: the operand block, the context and the table are all
 * regions of that borrow, at compile-time offsets, and no entry reads or writes a byte outside it.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/igmp/igmp.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads something else here and
// every entry but clear refuses it.
#define IGMP_READY 0x49474D50u

// One group on one interface. deadline_ms is the sec 3 report delay timer, drawn from (0, Max Response
// Time] and held in milliseconds. Padded to 1 << IDEMIP_IGMP_ENTRY_SHIFT so entry i sits at
// (i << IDEMIP_IGMP_ENTRY_SHIFT).
typedef struct
{
    uint32_t deadline_ms;
    uint32_t group;
    IdemIpIgmpState state;
    uint8_t netif;
    idemip_bool last_reporter;
    idemip_bool used;
    // RFC 1112 sec 7.2: "Each membership should have an associated reference count or similar
    // mechanism to handle multiple requests to join and leave the same group", sec 7.1 adding that
    // "LeaveHostGroup may succeed, but the membership persist, if more than one upper-layer protocol
    // has requested membership in the same group". The RFC 2236 sec 6 state machine sits below it and
    // sees only the first join and the last leave.
    uint8_t refs;
    uint8_t reserved[3];
} IgmpGroup;

// The running context. v1_deadline_ms holds, per interface, the millisecond at which the sec 4
// [Version 1 Router Present Timeout] since the last IGMPv1 Query expires, and v1_present says whether
// one has been heard at all, since millisecond zero is a valid clock reading.
typedef struct
{
    uint32_t ready;
    uint32_t v1_deadline_ms[IDEMIP_NETIF_COUNT];
    uint8_t groups;
    idemip_bool v1_present[IDEMIP_NETIF_COUNT];
} IgmpCtx;

// An index is (i << SHIFT), so each entry is exactly its width.
static_assert(sizeof(IgmpGroup) == (1u << IDEMIP_IGMP_ENTRY_SHIFT),
              "an IgmpGroup must be exactly 1 << IDEMIP_IGMP_ENTRY_SHIFT wide - pad it, or raise the shift");

// The caller's borrow, split: the operand block, the context, then the table. igmp.h publishes the
// offsets; these two asserts prove the span covers them before anything runs. The first keeps the
// context inside the region ahead of the group table, the second the whole map inside the borrow.
static_assert(IDEMIP_IGMP_OFF_CTX + sizeof(IgmpCtx) <= IDEMIP_IGMP_OFF_GROUPS,
              "IDEMIP_IGMP_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_IGMP_OFF_END <= IDEMIP_IGMP_BORROW,
              "IDEMIP_IGMP_BORROW is short of the map - raise IDEMIP_IGMP_CTX_BYTES in idemip_config.h");

// clear zeroes the table, so the sec 6 Non-Member state, which "requires no storage in the host", is
// the zero state.
static_assert(IDEMIP_IGMP_NON_MEMBER == 0, "IDEMIP_IGMP_NON_MEMBER must be zero: clear zeroes the table");

// The widest Max Response Time RFC 2236 sec 2.2 can carry: an 8-bit field "in units of 1/10 second".
#define IGMP_MAX_RESP_MS_MAX (255u * IDEMIP_IGMP_MAX_RESP_UNIT_MS)

// RFC 2236 sec 4 reads an IGMPv1 Query's zero Max Response Time "as a value of 100 (10 seconds)".
#define IGMP_V1_MAX_RESP_MS (IDEMIP_IGMP_V1_MAX_RESP * IDEMIP_IGMP_MAX_RESP_UNIT_MS)

// igmp_draw scales a bound by a 16-bit word in 32 bits, so every bound it is handed fits 16 bits.
static_assert(IGMP_MAX_RESP_MS_MAX <= 0xFFFFu && IDEMIP_IGMP_UNSOLICITED_REPORT_MS <= 0xFFFFu &&
                  IGMP_V1_MAX_RESP_MS <= 0xFFFFu,
              "a delay bound must fit 16 bits: igmp_draw scales it by a 16-bit word in 32 bits");

// The regions, at their offsets in the caller's borrow.
#define IGMP_IO(w) IDEMIP_IGMP_IO(w)
#define IGMP_CTX(w) ((IgmpCtx *)(void *)((w) + IDEMIP_IGMP_OFF_CTX))
#define IGMP_GROUP_AT(w, i)                                                                                            \
    ((IgmpGroup *)(void *)((w) + IDEMIP_IGMP_OFF_GROUPS + ((size_t)(i) << IDEMIP_IGMP_ENTRY_SHIFT)))

// Octets the context and the table span, which is what clear zeroes.
#define IGMP_STATE_BYTES ((size_t)IDEMIP_IGMP_OFF_END - (size_t)IDEMIP_IGMP_OFF_CTX)

// A borrow clear has not run on holds no mark, so every entry but clear refuses it.
static idemip_bool igmp_ready(uint8_t *restrict work)
{
    return (idemip_bool)(IGMP_CTX(work)->ready == IGMP_READY);
}

// RFC 1112 sec 4: "Host groups are identified by class D IP addresses, i.e., those with "1110" as
// their high-order four bits." RFC 2236 sec 3 excludes the all-systems group from the memberships a
// host reports.
static idemip_bool igmp_group_ok(uint32_t group)
{
    return (idemip_bool)((group & 0xF0000000u) == 0xE0000000u && group != IDEMIP_IGMP_ALL_SYSTEMS);
}

// --- time and the draw -----------------------------------------------------

// True when deadline_ms is at or before now_ms. The difference is taken in the unsigned width and
// tested against the half range, so a clock that wrapped past 0xFFFFFFFF still compares.
static idemip_bool igmp_passed(uint32_t now_ms, uint32_t deadline_ms)
{
    return (idemip_bool)((uint32_t)(now_ms - deadline_ms) < 0x80000000u);
}

// Milliseconds left on a running timer, zero once it has passed.
static uint32_t igmp_remaining(uint32_t now_ms, uint32_t deadline_ms)
{
    return igmp_passed(now_ms, deadline_ms) ? 0u : (uint32_t)(deadline_ms - now_ms);
}

// A delay in RFC 2236 sec 6's interval (0, max_ms], "chosen uniformly": the high 16 bits of the word
// scale max_ms in 32 bits, the product is shifted back down, and one is added. A zero word gives 1
// and an all-ones word gives max_ms, so the closed top is reachable and the open zero is not. No
// divide and no modulo.
static uint32_t igmp_draw(uint32_t rand, uint32_t max_ms)
{
    return (uint32_t)((((rand >> 16) * max_ms) >> 16) + 1u);
}

// Marsaglia, "Xorshift RNGs", Journal of Statistical Software 8(14) 2003, the (13, 17, 5) triple.
// The first timer a Query arms draws from the caller's word and each later one from a further step, so
// RFC 2236 sec 3's "Each timer is set to a different random value" holds across the memberships one
// General Query arms. Zero is the fixed point of the recurrence, so a zero word steps from the module
// mark instead.
static uint32_t igmp_step(uint32_t x)
{
    uint32_t v = (x == 0u) ? IGMP_READY : x;
    v ^= (uint32_t)(v << 13);
    v ^= (uint32_t)(v >> 17);
    v ^= (uint32_t)(v << 5);
    return v;
}

// --- the table -------------------------------------------------------------

// The entry a group on an interface occupies, or IDEMIP_IGMP_NONE. RFC 2236 sec 6 holds one state
// "with respect to any single IP multicast group on any single network interface", so the pair keys
// the table.
static uint8_t igmp_lookup(uint8_t *restrict work, uint32_t group, uint8_t netif)
{
    for (uint32_t i = 0u; i < IDEMIP_IGMP_GROUPS; i++)
    {
        const IgmpGroup *entry = IGMP_GROUP_AT(work, i);
        if (entry->used && entry->group == group && entry->netif == netif)
        {
            return (uint8_t)i;
        }
    }
    return IDEMIP_IGMP_NONE;
}

// The first entry in the sec 6 Non-Member state, which "requires no storage in the host", or
// IDEMIP_IGMP_NONE when the table is full.
static uint8_t igmp_free_slot(uint8_t *restrict work)
{
    for (uint32_t i = 0u; i < IDEMIP_IGMP_GROUPS; i++)
    {
        if (!IGMP_GROUP_AT(work, i)->used)
        {
            return (uint8_t)i;
        }
    }
    return IDEMIP_IGMP_NONE;
}

// What a call reports about the entry it touched.
static void igmp_report_entry(IgmpIo *io, const IgmpGroup *entry, uint8_t index)
{
    io->index = index;
    io->group = entry->group;
    io->netif = entry->netif;
    io->state = entry->state;
    io->deadline_ms = entry->deadline_ms;
    io->last_reporter = entry->last_reporter;
}

// --- the statics the entries delegate to -----------------------------------

// RFC 2236 sec 6 join group "may occur only in the Non-Member state", so a group already in the table
// is refused. sec 6's actions on the transition are "send report, set flag, start timer", the timer
// "chosen uniformly from the interval (0, [Unsolicited Report Interval] ]". sec 4's per-interface
// record decides the report's version, since that variable "MUST be used to decide what type of
// Membership Reports to send for unsolicited Membership Reports as well".
static void igmp_do_join(uint8_t *restrict work)
{
    IgmpIo *io = IGMP_IO(work);
    IgmpCtx *ctx = IGMP_CTX(work);
    const uint32_t group = io->group_args.group;
    const uint8_t netif = io->group_args.netif;
    // RFC 1112 sec 7.2 notifies the local network module only "On the first request to join and the
    // last request to leave a group on a given interface", so a repeat join takes a reference and
    // leaves the sec 6 state machine where it is. A count at its ceiling is BUSY: a leave frees one.
    const uint8_t held = igmp_lookup(work, group, netif);
    if (held != IDEMIP_IGMP_NONE)
    {
        IgmpGroup *e = IGMP_GROUP_AT(work, held);
        if (e->refs == 0xFFu)
        {
            io->status = IDEMIP_BUSY;
            return;
        }
        e->refs++;
        igmp_report_entry(io, e, held);
        io->status = IDEMIP_OK;
        return;
    }
    const uint8_t index = igmp_free_slot(work);
    if (index == IDEMIP_IGMP_NONE)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    IgmpGroup *entry = IGMP_GROUP_AT(work, index);
    entry->group = group;
    entry->netif = netif;
    entry->used = IDEMIP_TRUE;
    entry->refs = 1u;
    entry->state = IDEMIP_IGMP_DELAYING_MEMBER;
    entry->last_reporter = IDEMIP_TRUE;
    entry->deadline_ms =
        io->group_args.now_ms + igmp_draw(io->group_args.rand, IDEMIP_IGMP_UNSOLICITED_REPORT_MS);
    ctx->groups = (uint8_t)(ctx->groups + 1u);
    igmp_report_entry(io, entry, index);
    io->send_report = IDEMIP_TRUE;
    io->report_v1 = ctx->v1_present[netif];
    io->status = IDEMIP_OK;
}

// RFC 2236 sec 6 leave group "may occur only in the Delaying Member and Idle Member states", so a
// group not in the table is refused. Both arcs run "send leave if flag set" and land in Non-Member,
// and sec 6's send leave "SHOULD be skipped" where "the interface state says the Querier is running
// IGMPv1". Zeroing the entry stops the timer and frees it.
static void igmp_do_leave(uint8_t *restrict work)
{
    IgmpIo *io = IGMP_IO(work);
    IgmpCtx *ctx = IGMP_CTX(work);
    const uint8_t index = igmp_lookup(work, io->group_args.group, io->group_args.netif);
    if (index == IDEMIP_IGMP_NONE)
    {
        return;
    }
    IgmpGroup *entry = IGMP_GROUP_AT(work, index);
    // sec 7.2's "last request to leave a group on a given interface" is what reaches the sec 6 state
    // machine; a leave that only drops one of several references leaves the membership standing.
    if (entry->refs > 1u)
    {
        entry->refs--;
        igmp_report_entry(io, entry, index);
        io->status = IDEMIP_OK;
        return;
    }
    io->send_leave = (idemip_bool)(entry->last_reporter && !ctx->v1_present[entry->netif]);
    igmp_report_entry(io, entry, index);
    memset(entry, 0, sizeof *entry);
    ctx->groups = (uint8_t)(ctx->groups - 1u);
    io->state = IDEMIP_IGMP_NON_MEMBER;
    io->deadline_ms = 0u;
    io->status = IDEMIP_OK;
}

// RFC 2236 sec 6 holds one state per multicast group per interface, and this reports it.
static void igmp_do_find(uint8_t *restrict work)
{
    IgmpIo *io = IGMP_IO(work);
    const uint8_t index = igmp_lookup(work, io->group_args.group, io->group_args.netif);
    if (index == IDEMIP_IGMP_NONE)
    {
        return;
    }
    igmp_report_entry(io, IGMP_GROUP_AT(work, index), index);
    io->status = IDEMIP_OK;
}

// RFC 2236 sec 3: a General Query "sets delay timers for each group (excluding the all-systems group)
// of which it is a member on the interface from which it received the query", a Group-Specific Query
// one timer "for the group being queried if it is a member on the interface", each "set to a
// different random value ... selected from the range (0, Max Response Time]". A running timer "is
// reset to the random value only if the requested Max Response Time is less than the remaining value
// of the running timer". sec 6 ignores a Query "for memberships in the Non-Member state", so an entry
// the table does not hold is left alone rather than refused. sec 6's "IGMPv1 query received" is a
// Query "with the Max Response Time field set to 0", which sec 4 reads as 100 units and which sets
// the per-interface timer "to its maximum value [Version 1 Router Present Timeout]".
static void igmp_do_query_in(uint8_t *restrict work)
{
    IgmpIo *io = IGMP_IO(work);
    IgmpCtx *ctx = IGMP_CTX(work);
    const uint8_t netif = io->query_args.netif;
    const uint32_t now_ms = io->query_args.now_ms;
    const idemip_bool v1 = (idemip_bool)(io->query_args.v1 || io->query_args.max_resp_ms == 0u);
    const uint32_t max_resp_ms = v1 ? IGMP_V1_MAX_RESP_MS : io->query_args.max_resp_ms;
    if (v1)
    {
        ctx->v1_present[netif] = IDEMIP_TRUE;
        ctx->v1_deadline_ms[netif] = now_ms + IDEMIP_IGMP_V1_ROUTER_PRESENT_MS;
    }
    uint32_t seed = io->query_args.rand;
    for (uint32_t i = 0u; i < IDEMIP_IGMP_GROUPS; i++)
    {
        IgmpGroup *entry = IGMP_GROUP_AT(work, i);
        if (!entry->used || entry->netif != netif)
        {
            continue;
        }
        if (!io->query_args.general && entry->group != io->query_args.group)
        {
            continue;
        }
        if (entry->state == IDEMIP_IGMP_IDLE_MEMBER)
        {
            entry->state = IDEMIP_IGMP_DELAYING_MEMBER;
            entry->deadline_ms = now_ms + igmp_draw(seed, max_resp_ms);
            seed = igmp_step(seed);
        }
        else if (max_resp_ms < igmp_remaining(now_ms, entry->deadline_ms))
        {
            entry->deadline_ms = now_ms + igmp_draw(seed, max_resp_ms);
            seed = igmp_step(seed);
        }
        else
        {
            continue;
        }
        if (io->index == IDEMIP_IGMP_NONE)
        {
            igmp_report_entry(io, entry, (uint8_t)i);
        }
    }
    io->status = IDEMIP_OK;
}

// RFC 2236 sec 3: on another host's Report "while it has a timer running, it stops its timer for the
// specified group and does not send a Report, in order to suppress duplicate Reports". sec 6's report
// received arc runs "stop timer, clear flag" into Idle Member and "is ignored for memberships in the
// Non-Member or Idle Member state", so both of those are a completed call that changed nothing. sec 5
// requires the suppression to work for "either a Version 1 Membership Report or a Version 2
// Membership Report", so no version is read here.
static void igmp_do_report_in(uint8_t *restrict work)
{
    IgmpIo *io = IGMP_IO(work);
    const uint8_t index = igmp_lookup(work, io->report_args.group, io->report_args.netif);
    if (index == IDEMIP_IGMP_NONE)
    {
        io->status = IDEMIP_OK;
        return;
    }
    IgmpGroup *entry = IGMP_GROUP_AT(work, index);
    if (entry->state == IDEMIP_IGMP_DELAYING_MEMBER)
    {
        entry->state = IDEMIP_IGMP_IDLE_MEMBER;
        entry->deadline_ms = 0u;
        entry->last_reporter = IDEMIP_FALSE;
    }
    igmp_report_entry(io, entry, index);
    io->status = IDEMIP_OK;
}

// RFC 2236 sec 6: the "IGMPv1 Router Present" state falls back to "No IGMPv1 Router Present" when
// "the timer set to note the presence of an IGMPv1 router expires", which is aged first so a Report
// this sweep fires reads the current version. sec 3: "When a group's timer expires, the host
// multicasts a Version 2 Membership Report to the group", and sec 6's timer expired arc runs "send
// report, set flag" into Idle Member. expired counts every timer this sweep found due; the lowest
// entry among them is the one fired, so a caller that sends one Report per call ticks again while
// expired is non-zero and each call hands it exactly one group.
static void igmp_do_tick(uint8_t *restrict work)
{
    IgmpIo *io = IGMP_IO(work);
    IgmpCtx *ctx = IGMP_CTX(work);
    const uint32_t now_ms = io->tick_args.now_ms;
    for (uint32_t n = 0u; n < IDEMIP_NETIF_COUNT; n++)
    {
        if (ctx->v1_present[n] && igmp_passed(now_ms, ctx->v1_deadline_ms[n]))
        {
            ctx->v1_present[n] = IDEMIP_FALSE;
        }
    }
    for (uint32_t i = 0u; i < IDEMIP_IGMP_GROUPS; i++)
    {
        IgmpGroup *entry = IGMP_GROUP_AT(work, i);
        if (!entry->used || entry->state != IDEMIP_IGMP_DELAYING_MEMBER ||
            !igmp_passed(now_ms, entry->deadline_ms))
        {
            continue;
        }
        io->expired = (uint8_t)(io->expired + 1u);
        if (io->index != IDEMIP_IGMP_NONE)
        {
            continue;
        }
        entry->state = IDEMIP_IGMP_IDLE_MEMBER;
        entry->last_reporter = IDEMIP_TRUE;
        entry->deadline_ms = 0u;
        igmp_report_entry(io, entry, (uint8_t)i);
        io->send_report = IDEMIP_TRUE;
        io->report_v1 = ctx->v1_present[entry->netif];
    }
    io->status = IDEMIP_OK;
}

// --- the entries -----------------------------------------------------------

// The context and the table, zeroed, then the mark. A zeroed entry is in the sec 6 Non-Member state,
// which "requires no storage in the host". The operand block is the caller's and is left as it stands.
void idemip_igmp_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IGMP_OFF_CTX, 0, IGMP_STATE_BYTES);
    IGMP_CTX(work)->ready = IGMP_READY;
    IGMP_IO(work)->status = IDEMIP_OK;
}

// Every member an entry reports, back to the state a call that decided nothing leaves. All seven
// entries share the one operand block, so a flag or a group left standing from an earlier call would
// be read alongside this call's answer: RFC 2236 sec 6 binds "send leave" to the "leave group" event
// and "send report" to the events that raise them, and a Leave Group message for a group the host
// has not left is outside the state machine.
static void igmp_result_clear(IgmpIo *io)
{
    io->index = IDEMIP_IGMP_NONE;
    io->group = 0u;
    io->netif = 0u;
    io->state = IDEMIP_IGMP_NON_MEMBER;
    io->deadline_ms = 0u;
    io->expired = 0u;
    io->last_reporter = IDEMIP_FALSE;
    io->send_report = IDEMIP_FALSE;
    io->send_leave = IDEMIP_FALSE;
    io->report_v1 = IDEMIP_FALSE;
}

// A full table is BUSY: leave frees an entry, so the retry succeeds once a membership is dropped. A
// bad address, an interface this build does not carry, an uncleared borrow and a group already joined
// are ERR, since no later call changes any of them.
void idemip_igmp_join(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    igmp_result_clear(io);
    if (!igmp_ready(work) || !igmp_group_ok(io->group_args.group) || io->group_args.netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    igmp_do_join(work);
}

// A group that is not joined is ERR: sec 6's leave group event "may occur only in the Delaying Member
// and Idle Member states", and no retry puts it in one.
void idemip_igmp_leave(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    igmp_result_clear(io);
    if (!igmp_ready(work) || !igmp_group_ok(io->group_args.group) || io->group_args.netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    igmp_do_leave(work);
}

void idemip_igmp_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    igmp_result_clear(io);
    if (!igmp_ready(work) || !igmp_group_ok(io->group_args.group) || io->group_args.netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    igmp_do_find(work);
}

// A Max Response Time wider than the sec 2.2 field can carry is ERR: the field is 8 bits "in units of
// 1/10 second", so no arriving Query produces one and no retry makes it legal. A Query the host holds
// no membership for is OK, since sec 6 ignores it rather than refusing it.
void idemip_igmp_query_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    igmp_result_clear(io);
    if (!igmp_ready(work) || io->query_args.netif >= IDEMIP_NETIF_COUNT ||
        (!io->query_args.general && !igmp_group_ok(io->query_args.group)) ||
        io->query_args.max_resp_ms > IGMP_MAX_RESP_MS_MAX)
    {
        return;
    }
    igmp_do_query_in(work);
}

// A Report for a group the host is not a member of is OK: sec 6 ignores it "for memberships in the
// Non-Member or Idle Member state", which is a completed call that changed nothing.
void idemip_igmp_report_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    igmp_result_clear(io);
    if (!igmp_ready(work) || io->report_args.netif >= IDEMIP_NETIF_COUNT || !igmp_group_ok(io->report_args.group))
    {
        return;
    }
    igmp_do_report_in(work);
}

// A sweep that found nothing due is OK, not BUSY: it completed, and expired says nothing fired.
void idemip_igmp_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    igmp_result_clear(io);
    io->expired = 0u;
    io->send_report = IDEMIP_FALSE;
    io->report_v1 = IDEMIP_FALSE;
    if (!igmp_ready(work))
    {
        return;
    }
    igmp_do_tick(work);
}

IDEMIP_END_DECLS
