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

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV4

#include "idemIP/igmp/igmp.h"

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
    uint8_t reserved[4];
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

// --- the entries -----------------------------------------------------------

// The context and the table, zeroed, then the mark. A zeroed entry is in the sec 6 Non-Member state,
// which "requires no storage in the host". The operand block is the caller's and is left as it stands.
static void igmp_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IGMP_OFF_CTX, 0, IGMP_STATE_BYTES);
    IGMP_CTX(work)->ready = IGMP_READY;
    IGMP_IO(work)->status = IDEMIP_OK;
}

static void igmp_join(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_IGMP_NONE;
    io->send_report = IDEMIP_FALSE;
    io->report_v1 = IDEMIP_FALSE;
    if (!igmp_ready(work) || !igmp_group_ok(io->group_args.group) || io->group_args.netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 2236 sec 3: "When a host joins a multicast group, it should immediately transmit an
    // unsolicited Version 2 Membership Report for that group", repeated after [Unsolicited Report
    // Interval], and sec 6's join group transition into Delaying Member with the last-reporter flag
    // set.
    io->status = IDEMIP_ERR;
}

static void igmp_leave(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_IGMP_NONE;
    io->send_leave = IDEMIP_FALSE;
    if (!igmp_ready(work) || !igmp_group_ok(io->group_args.group) || io->group_args.netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 2236 sec 3: a host that "was the last host to reply to a Query with a Membership
    // Report for that group ... SHOULD send a Leave Group message to the all-routers multicast group
    // (224.0.0.2)", and sec 6's send leave, which is skipped where the Querier is running IGMPv1 or
    // the last-reporter flag is clear.
    io->status = IDEMIP_ERR;
}

static void igmp_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_IGMP_NONE;
    io->group = 0u;
    io->state = IDEMIP_IGMP_NON_MEMBER;
    io->deadline_ms = 0u;
    io->last_reporter = IDEMIP_FALSE;
    if (!igmp_ready(work) || !igmp_group_ok(io->group_args.group))
    {
        return;
    }
    // PHASE 3: RFC 2236 sec 6, which holds one state per multicast group per interface.
    io->status = IDEMIP_ERR;
}

static void igmp_query_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_IGMP_NONE;
    io->send_report = IDEMIP_FALSE;
    if (!igmp_ready(work) || io->query_args.netif >= IDEMIP_NETIF_COUNT ||
        (!io->query_args.general && !igmp_group_ok(io->query_args.group)))
    {
        return;
    }
    // PHASE 3: RFC 2236 sec 3, which on a General Query "sets delay timers for each group (excluding
    // the all-systems group) of which it is a member on the interface from which it received the
    // query" and on a Group-Specific Query one timer, each "selected from the range (0, Max Response
    // Time]", resets a running timer "only if the requested Max Response Time is less than the
    // remaining value of the running timer", and per sec 4 records an IGMPv1 Query against [Version 1
    // Router Present Timeout]. sec 6 ignores a Query "for memberships in the Non-Member state".
    io->status = IDEMIP_ERR;
}

static void igmp_report_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_IGMP_NONE;
    if (!igmp_ready(work) || io->report_args.netif >= IDEMIP_NETIF_COUNT || !igmp_group_ok(io->report_args.group))
    {
        return;
    }
    // PHASE 3: RFC 2236 sec 3: on another host's Report "while it has a timer running, it stops its
    // timer for the specified group and does not send a Report, in order to suppress duplicate
    // Reports", and sec 6's report received transition into Idle Member clearing the last-reporter
    // flag. sec 6 ignores it "for memberships in the Non-Member or Idle Member state".
    io->status = IDEMIP_ERR;
}

static void igmp_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IgmpIo *io = IGMP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_IGMP_NONE;
    io->expired = 0u;
    io->send_report = IDEMIP_FALSE;
    io->report_v1 = IDEMIP_FALSE;
    if (!igmp_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 2236 sec 3, where "When a group's timer expires, the host multicasts a Version 2
    // Membership Report to the group, with IP TTL of 1", sec 6's timer expired transition into Idle
    // Member setting the last-reporter flag, and sec 4's per-interface record of an IGMPv1 Querier
    // aging out after [Version 1 Router Present Timeout].
    io->status = IDEMIP_ERR;
}

const IgmpNs Igmp = {.clear = igmp_clear,
                     .join = igmp_join,
                     .leave = igmp_leave,
                     .find = igmp_find,
                     .query_in = igmp_query_in,
                     .report_in = igmp_report_in,
                     .tick = igmp_tick};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4
