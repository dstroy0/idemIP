// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file igmp.h
 * @brief Internet Group Management Protocol version 2, RFC 2236: which multicast groups this node
 *        belongs to, and when it answers a Query about them.
 *
 * One table across interfaces, an entry per group an interface is a member of. RFC 2236 sec 6 gives a
 * group on an interface one of three states and runs a report delay timer over it.
 *
 * Every deadline here is a millisecond. RFC 2236 sec 2.2 states Max Response Time "in units of 1/10
 * second", so a field value reaches milliseconds by multiplying by
 * IDEMIP_IGMP_MAX_RESP_UNIT_MS. Nothing here divides.
 *
 * The message format is sec 2's, at the offsets below. RFC 2236 sec 2 puts every message behind an
 * IPv4 header carrying "the IP Router Alert option [RFC 2113]", whose four octets are below as well.
 */

#ifndef IDEMIP_IGMP_H
#define IDEMIP_IGMP_H

#include "src/ip/ipv4.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/** @brief No entry. Every index in this contract reads this when it names none. */
#define IDEMIP_IGMP_NONE 0xFFu

/**
 * @brief The IP protocol number a message rides on.
 *
 * RFC 2236 sec 2: "IGMP messages are encapsulated in IP datagrams, with an IP protocol number of 2."
 */
#define IDEMIP_IGMP_IP_PROTO 2u

/**
 * @brief The IPv4 Time to Live every message carries.
 *
 * RFC 2236 sec 2: "All IGMP messages described in this document are sent with IP TTL 1".
 */
#define IDEMIP_IGMP_TTL 1u

// ---------------------------------------------------------------------------
// Field offsets (RFC 2236 sec 2)
// ---------------------------------------------------------------------------
// sec 2 draws Type, Max Resp Time and Checksum above the 32-bit Group Address.

#define IDEMIP_IGMP_OFF_TYPE 0u     ///< 8-bit Type
#define IDEMIP_IGMP_OFF_MAX_RESP 1u ///< 8-bit Max Resp Time, in units of 1/10 second
#define IDEMIP_IGMP_OFF_CKSUM 2u    ///< 16-bit Checksum
#define IDEMIP_IGMP_OFF_GROUP 4u    ///< 32-bit Group Address

/**
 * @brief Octets of a message this version reads.
 *
 * RFC 2236 sec 2.5: "As long as the Type is one that is recognized, an IGMPv2 implementation MUST
 * ignore anything past the first 8 octets while processing the packet.  However, the IGMP checksum is
 * always computed over the whole IP payload, not just over the first 8 octets."
 */
#define IDEMIP_IGMP_MSG_LEN 8u

/**
 * @brief What a message is (RFC 2236 sec 2.1).
 *
 * sec 2.1 names three types "of concern to the host-router interaction" and one more "for
 * backwards-compatibility with IGMPv1". "Unrecognized message types should be silently ignored."
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IGMP_TYPE_QUERY = 0x11u,     ///< Membership Query, General or Group-Specific
    IDEMIP_IGMP_TYPE_REPORT_V1 = 0x12u, ///< Version 1 Membership Report (RFC 1112 Appendix I type 2)
    IDEMIP_IGMP_TYPE_REPORT_V2 = 0x16u, ///< Version 2 Membership Report
    IDEMIP_IGMP_TYPE_LEAVE = 0x17u,     ///< Leave Group
} IdemIpIgmpType;

/**
 * @brief Where a message goes (RFC 2236 sec 9).
 *
 * sec 9: a General Query to ALL-SYSTEMS (224.0.0.1), a Group-Specific Query and a Membership Report
 * to the group itself, and a Leave Message to ALL-ROUTERS (224.0.0.2).
 */
#define IDEMIP_IGMP_ALL_SYSTEMS 0xE0000001u
#define IDEMIP_IGMP_ALL_ROUTERS 0xE0000002u

/**
 * @brief Milliseconds one unit of the Max Resp Time field stands for.
 *
 * RFC 2236 sec 2.2: the field "specifies the maximum allowed time before sending a responding report
 * in units of 1/10 second". A field value reaches milliseconds by multiplying, so no divide exists.
 */
#define IDEMIP_IGMP_MAX_RESP_UNIT_MS 100u

/**
 * @brief What an IGMPv1 Query's zero Max Response Time stands for.
 *
 * RFC 2236 sec 4: "The IGMPv1 router will send General Queries with the Max Response Time set to 0.
 * This MUST be interpreted as a value of 100 (10 seconds)."
 */
#define IDEMIP_IGMP_V1_MAX_RESP 100u

// ---------------------------------------------------------------------------
// The Router Alert option (RFC 2113 sec 2.1)
// ---------------------------------------------------------------------------
// RFC 2113 sec 2.1 draws the option as |10010100|00000100| 2 octet value |, with "Copied flag: 1 (all
// fragments must carry the option), Option class: 0 (control), Option number: 20 (decimal)",
// "Length: 4", and value "0 - Router shall examine packet".

#define IDEMIP_IGMP_RA_TYPE 0x94u  ///< the option type octet: copied flag set, class 0, number 20
#define IDEMIP_IGMP_RA_LEN 4u      ///< the whole option, type and length octets included
#define IDEMIP_IGMP_RA_VALUE 0x0000u ///< "0 - Router shall examine packet"

/**
 * @brief What a group is doing on an interface (RFC 2236 sec 6).
 *
 * sec 6: "A host may be in one of three possible states with respect to any single IP multicast group
 * on any single network interface". Non-Member "is the initial state for all memberships on all
 * network interfaces; it requires no storage in the host", so a cleared entry is in it.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IGMP_NON_MEMBER = 0,     ///< not a member of the group on the interface
    IDEMIP_IGMP_DELAYING_MEMBER,    ///< a member, with a report delay timer running
    IDEMIP_IGMP_IDLE_MEMBER,        ///< a member, with no report delay timer running
} IdemIpIgmpState;

/**
 * @brief What a membership call takes.
 *
 * RFC 2236 sec 3: on joining, a host "should immediately transmit an unsolicited Version 2 Membership
 * Report for that group", and sec 6 then starts a timer "chosen uniformly from the interval (0,
 * [Unsolicited Report Interval] ]".
 *
 * @var IgmpGroupArgs::group  the sec 2.4 Group Address, in host order
 * @var IgmpGroupArgs::rand   a random word the unsolicited report delay is drawn from
 * @var IgmpGroupArgs::now_ms the millisecond clock that delay is added to
 * @var IgmpGroupArgs::netif  the interface the membership is on
 */
typedef struct
{
    uint32_t group;
    uint32_t rand;
    uint32_t now_ms;
    uint8_t netif;
} IgmpGroupArgs;

/**
 * @brief What an arriving Query takes (RFC 2236 sec 3).
 *
 * sec 2.4: the Group Address field "is set to zero when sending a General Query, and set to the group
 * address being queried when sending a Group-Specific Query". sec 3 sets each timer "to a different
 * random value, using the highest clock granularity available on the host, selected from the range (0,
 * Max Response Time]".
 *
 * @var IgmpQueryArgs::group       the queried group, unread when @p general
 * @var IgmpQueryArgs::max_resp_ms the sec 2.2 Max Resp Time, already in milliseconds
 * @var IgmpQueryArgs::rand        a random word the delay over (0, Max Response Time] is drawn from
 * @var IgmpQueryArgs::now_ms      the millisecond clock the drawn delay is added to
 * @var IgmpQueryArgs::netif       the interface the Query arrived on
 * @var IgmpQueryArgs::general     the Group Address field was zero, so the Query "applies to all
 *                                 memberships on the interface from which the Query is received"
 * @var IgmpQueryArgs::v1          the Query was an IGMPv1 one, which sec 4 keeps a per-interface
 *                                 state variable for over [Version 1 Router Present Timeout]
 */
typedef struct
{
    uint32_t group;
    uint32_t max_resp_ms;
    uint32_t rand;
    uint32_t now_ms;
    uint8_t netif;
    idemip_bool general;
    idemip_bool v1;
} IgmpQueryArgs;

/**
 * @brief What another host's arriving Report takes (RFC 2236 sec 3).
 *
 * sec 3: "If the host receives another host's Report (version 1 or 2) while it has a timer running, it
 * stops its timer for the specified group and does not send a Report, in order to suppress duplicate
 * Reports", and sec 5 requires a v2 host to "allow its Membership Report to be suppressed by either a
 * Version 1 Membership Report or a Version 2 Membership Report".
 *
 * @var IgmpReportArgs::group the group the Report named
 * @var IgmpReportArgs::netif the interface it arrived on
 */
typedef struct
{
    uint32_t group;
    uint8_t netif;
} IgmpReportArgs;

/** @brief What a sweep takes: the millisecond clock every deadline is compared against. */
typedef struct
{
    uint32_t now_ms;
} IgmpTickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var IgmpIo::group_args    the group a membership call names
 * @var IgmpIo::query_args    the arriving Query
 * @var IgmpIo::report_args   another host's arriving Report
 * @var IgmpIo::tick_args     the clock a sweep ages against
 * @var IgmpIo::status        what the call reports: OK, BUSY, or ERR
 * @var IgmpIo::group         the group address the call touched
 * @var IgmpIo::deadline_ms   when that group's report delay timer fires
 * @var IgmpIo::index         the entry the call touched, or IDEMIP_IGMP_NONE
 * @var IgmpIo::state         that group's sec 6 state
 * @var IgmpIo::netif         the interface that entry belongs to
 * @var IgmpIo::expired       report delay timers a sweep found due. The lowest-numbered entry among
 *                            them is the one the sweep fires, so a caller ticks again while this is
 *                            non-zero and each call hands it one group to report.
 * @var IgmpIo::last_reporter sec 6's "set flag that we were the last host to send a report for this
 *                            group"
 * @var IgmpIo::send_report   sec 6's "send report" for @ref IgmpIo::group, to the group itself
 * @var IgmpIo::send_leave    sec 6's "send leave" for @ref IgmpIo::group, to ALL-ROUTERS
 * @var IgmpIo::report_v1     the Report to send is a Version 1 one, which sec 4 decides from the
 *                            per-interface record of whether an IGMPv1 Query was heard within
 *                            [Version 1 Router Present Timeout]
 */
typedef struct
{
    IgmpGroupArgs group_args;
    IgmpQueryArgs query_args;
    IgmpReportArgs report_args;
    IgmpTickArgs tick_args;

    uint32_t group;
    uint32_t deadline_ms;
    IdemIpStatus status;
    IdemIpIgmpState state;
    uint8_t index;
    uint8_t netif;
    uint8_t expired;
    idemip_bool last_reporter;
    idemip_bool send_report;
    idemip_bool send_leave;
    idemip_bool report_v1;
} IgmpIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only the
// map is public.
//
// IDEMIP_IGMP_CTX_BYTES spans the operand block and the context together, the way IDEMIP_PHY_BORROW
// covers both, so the table starts at a constant that no growth in either moves.

#define IDEMIP_IGMP_OFF_IO 0u ///< the operand and result block
#define IDEMIP_IGMP_OFF_CTX (IDEMIP_IGMP_OFF_IO + IDEMIP_ROUND_UP(sizeof(IgmpIo), IDEMIP_ALIGN))
#define IDEMIP_IGMP_OFF_GROUPS (IDEMIP_IGMP_OFF_IO + IDEMIP_IGMP_CTX_BYTES)
#define IDEMIP_IGMP_OFF_END (IDEMIP_IGMP_OFF_GROUPS + (IDEMIP_IGMP_GROUPS << IDEMIP_IGMP_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IGMP_IO(w) ((IgmpIo *)(void *)((w) + IDEMIP_IGMP_OFF_IO))

/**
 * @brief The group membership table, RFC 2236.
 *
 *   Igmp.clear(work);
 *   IDEMIP_IGMP_IO(work)->group_args.group = 0xE0000009u;
 *   IDEMIP_IGMP_IO(work)->group_args.netif = 0u;
 *   Igmp.join(work);
 *   if (IDEMIP_IGMP_IO(work)->send_report) { ... }
 *
 * @c work is IDEMIP_IGMP_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved is
 * this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * tables are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * A borrow is refused until @ref IgmpNs::clear has run on it: clear zeroes the context and the table
 * and leaves the mark that says these bytes are this module's. It does not touch the operand block.
 *
 * Nothing here blocks. A table with no free entry reports IDEMIP_BUSY, since an entry frees when a
 * membership is dropped. A bad argument, an uncleared borrow or a group that is not joined reports
 * IDEMIP_ERR.
 *
 * An arriving Query or Report the host holds no membership for reports IDEMIP_OK with
 * @ref IgmpIo::index at IDEMIP_IGMP_NONE. RFC 2236 sec 6 ignores both "for memberships in the
 * Non-Member state" rather than refusing them, so the call completed and changed nothing.
 *
 * @var IgmpNs::clear     zero the context and the group table, and mark the borrow cleared
 * @var IgmpNs::join      sec 6's "join group", which "may occur only in the Non-Member state"
 * @var IgmpNs::leave     sec 6's "leave group", which "may occur only in the Delaying Member and Idle
 *                        Member states"
 * @var IgmpNs::find      the entry for a group on an interface, and its state and deadline
 * @var IgmpNs::query_in  sec 6's "query received": set the report delay timers the Query applies to
 * @var IgmpNs::report_in sec 6's "report received", which suppresses this node's own Report
 * @var IgmpNs::tick      sec 6's "timer expired": fire every report delay timer that has passed, and
 *                        age the sec 4 record of an IGMPv1 Querier
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const join)(uint8_t *restrict work);
    void (*const leave)(uint8_t *restrict work);
    void (*const find)(uint8_t *restrict work);
    void (*const query_in)(uint8_t *restrict work);
    void (*const report_in)(uint8_t *restrict work);
    void (*const tick)(uint8_t *restrict work);
} IgmpNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_igmp_clear(uint8_t *restrict work);
void idemip_igmp_join(uint8_t *restrict work);
void idemip_igmp_leave(uint8_t *restrict work);
void idemip_igmp_find(uint8_t *restrict work);
void idemip_igmp_query_in(uint8_t *restrict work);
void idemip_igmp_report_in(uint8_t *restrict work);
void idemip_igmp_tick(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Igmp.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const IgmpNs Igmp IDEMIP_UNUSED = {
    .clear = idemip_igmp_clear,
    .join = idemip_igmp_join,
    .leave = idemip_igmp_leave,
    .find = idemip_igmp_find,
    .query_in = idemip_igmp_query_in,
    .report_in = idemip_igmp_report_in,
    .tick = idemip_igmp_tick};
// RFC 2236 sec 2 draws Type, Max Resp Time and Checksum above the 32-bit Group Address, which is the 8
// octets sec 2.5 bounds the processed part of a message at.
static_assert(IDEMIP_IGMP_OFF_GROUP + 4u == IDEMIP_IGMP_MSG_LEN,
              "the RFC 2236 sec 2 fields must sum to the 8 octets sec 2.5 processes");

// RFC 2113 sec 2.1: the type octet is the copied flag over class 0 and option number 20.
static_assert(IDEMIP_IGMP_RA_TYPE == (0x80u | 20u),
              "RFC 2113 sec 2.1: Router Alert is copied flag 1, option class 0, option number 20");

// sec 4 reads a zero Max Response Time as 100 units, and sec 8.3's default Query Response Interval is
// the same 100, which is the 10 seconds both name.
static_assert(IDEMIP_IGMP_V1_MAX_RESP * IDEMIP_IGMP_MAX_RESP_UNIT_MS == 10000u,
              "RFC 2236 sec 4: a zero Max Response Time is \"a value of 100 (10 seconds)\"");

// RFC 2236 sec 9 sends a General Query to ALL-SYSTEMS and a Leave to ALL-ROUTERS, both in 224/4.
static_assert((IDEMIP_IGMP_ALL_SYSTEMS & 0xF0000000u) == 0xE0000000u &&
                  (IDEMIP_IGMP_ALL_ROUTERS & 0xF0000000u) == 0xE0000000u,
              "RFC 1112 sec 4: a host group address is class D, the high four bits 1110");

// An entry index and the result member that carries it are one octet, so a count at or above the
// value that means "no entry" is unaddressable.
static_assert(IDEMIP_IGMP_GROUPS < IDEMIP_IGMP_NONE,
              "IDEMIP_IGMP_GROUPS must stay below IDEMIP_IGMP_NONE: an entry index is one octet");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_IGMP_H
