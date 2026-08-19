// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file mld6.h
 * @brief Multicast Listener Discovery, RFC 2710: which groups this node listens to, and when it
 *        answers a Query about them.
 *
 * One table across interfaces, an entry per group an interface listens to. RFC 2710 sec 5 gives a
 * group on an interface one of three states, and sec 4 runs a report delay timer over it.
 *
 * Every deadline here is a millisecond, because sec 3.4 states Maximum Response Delay "in units of
 * milliseconds" and the clock this compares against is a millisecond clock. No conversion exists, so
 * no divide exists.
 *
 * The MLD message format is icmpv6.h's, whose types 130 through 132 sec 3.1 assigns. Nothing here
 * parses one.
 */

#ifndef IDEMIP_MLD6_H
#define IDEMIP_MLD6_H

#include "src/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/** @brief No group. Every index in this contract reads this when it names none. */
#define IDEMIP_MLD6_NONE 0xFFu

/**
 * @brief RFC 2710 sec 3.7: "MUST NOT send an MLD message longer than 24 octets and MUST ignore
 * anything past the first 24 octets of a received MLD message."
 */
#define IDEMIP_MLD6_MSG_LEN 24u

/**
 * @brief What a group is doing on an interface, RFC 2710 sec 5.
 *
 * "A node may be in one of three possible states with respect to any single IPv6 multicast address on
 * any single interface". Non-Listener "requires no storage in the node", so a cleared entry is in it.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_MLD6_NON_LISTENER = 0,   ///< not listening to the address on the interface
    IDEMIP_MLD6_DELAYING_LISTENER,  ///< listening, with a report delay timer running
    IDEMIP_MLD6_IDLE_LISTENER,      ///< listening, with no report delay timer running
} IdemIpMld6State;

/**
 * @brief What a membership call takes.
 *
 * @var Mld6GroupArgs::group the sec 3.6 Multicast Address, IDEMIP_IP6_ADDR_LEN octets
 * @var Mld6GroupArgs::netif the interface the node listens on
 */
typedef struct
{
    const uint8_t *group;
    uint8_t netif;
} Mld6GroupArgs;

/**
 * @brief What an arriving Query takes (RFC 2710 sec 4).
 *
 * sec 3.6: the Multicast Address field "is set to zero when sending a General Query, and set to a
 * specific IPv6 multicast address when sending a Multicast-Address-Specific Query". sec 4 sets each
 * timer "to a different random value, using the highest clock granularity available on the node,
 * selected from the range [0, Maximum Response Delay]".
 *
 * @var Mld6QueryArgs::group       the queried group, unread when @p general
 * @var Mld6QueryArgs::max_resp_ms the sec 3.4 Maximum Response Delay, in milliseconds
 * @var Mld6QueryArgs::rand        a random word the caller supplies, from which the delay over
 *                                 [0, Maximum Response Delay] is drawn
 * @var Mld6QueryArgs::now_ms      the millisecond clock the drawn delay is added to
 * @var Mld6QueryArgs::netif       the interface the Query arrived on
 * @var Mld6QueryArgs::general     the Multicast Address field was zero, so the Query "applies to all
 *                                 multicast addresses on the interface from which the Query is
 *                                 received"
 */
typedef struct
{
    const uint8_t *group;
    uint32_t max_resp_ms;
    uint32_t rand;
    uint32_t now_ms;
    uint8_t netif;
    idemip_bool general;
} Mld6QueryArgs;

/** @brief What a sweep takes: the millisecond clock every deadline is compared against. */
typedef struct
{
    uint32_t now_ms;
} Mld6TickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Mld6Io::group_args    the group a membership call names
 * @var Mld6Io::query_args    the arriving Query
 * @var Mld6Io::tick_args     the clock a sweep ages against
 * @var Mld6Io::status        what the call reports: OK, BUSY, or ERR
 * @var Mld6Io::group         the group address, IDEMIP_IP6_ADDR_LEN octets where it lies
 * @var Mld6Io::deadline_ms   when that group's report delay timer fires
 * @var Mld6Io::index         the entry the call touched, or IDEMIP_MLD6_NONE
 * @var Mld6Io::state         that group's sec 5 state
 * @var Mld6Io::netif         the interface that entry belongs to
 * @var Mld6Io::expired       report delay timers a sweep fired
 * @var Mld6Io::last_reporter this node sent the last Report for that group
 * @var Mld6Io::send_report   a Report goes out for @ref Mld6Io::group, to the group itself
 * @var Mld6Io::send_done     a Done goes out for @ref Mld6Io::group, to the all-routers address
 */
typedef struct
{
    Mld6GroupArgs group_args;
    Mld6QueryArgs query_args;
    Mld6TickArgs tick_args;

    IdemIpStatus status;
    const uint8_t *group;
    uint32_t deadline_ms;
    uint8_t index;
    IdemIpMld6State state;
    uint8_t netif;
    uint8_t expired;
    idemip_bool last_reporter;
    idemip_bool send_report;
    idemip_bool send_done;
} Mld6Io;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only
// the map is public.

// IDEMIP_MLD6_CTX_BYTES spans the operand block and the context together, the way IDEMIP_PHY_BORROW
// covers both, so the table starts at a constant that no growth in either moves.

#define IDEMIP_MLD6_OFF_IO 0u ///< the operand and result block
#define IDEMIP_MLD6_OFF_CTX (IDEMIP_MLD6_OFF_IO + IDEMIP_ROUND_UP(sizeof(Mld6Io), IDEMIP_ALIGN))
#define IDEMIP_MLD6_OFF_GROUPS (IDEMIP_MLD6_OFF_IO + IDEMIP_MLD6_CTX_BYTES)
#define IDEMIP_MLD6_OFF_END (IDEMIP_MLD6_OFF_GROUPS + (IDEMIP_MLD6_GROUPS << IDEMIP_MLD6_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_MLD6_IO(w) ((Mld6Io *)(void *)((w) + IDEMIP_MLD6_OFF_IO))

/**
 * @brief The group membership table, RFC 2710.
 *
 *   Mld6.clear(work);
 *   IDEMIP_MLD6_IO(work)->group_args.group = solicited_node;
 *   IDEMIP_MLD6_IO(work)->group_args.netif = 0u;
 *   Mld6.join(work);
 *   if (IDEMIP_MLD6_IO(work)->send_report) { ... }
 *
 * @c work is IDEMIP_MLD6_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. The borrow IS the
 * instance, so two tables are two borrows and share not one byte.
 *
 * A borrow is refused until @ref Mld6Ns::clear has run on it: clear zeroes every region above and
 * leaves one nonzero octet in the context region, the mark that says these bytes are this module's.
 * It does not touch the operand block.
 *
 * Nothing here blocks. A table with no free entry reports IDEMIP_BUSY, since an entry frees when the
 * node stops listening. A bad argument or a group that is not listened to reports IDEMIP_ERR.
 *
 * @var Mld6Ns::clear     zero the context and the group table, and mark the borrow cleared
 * @var Mld6Ns::join      start listening, which sec 4 answers with an unsolicited Report
 * @var Mld6Ns::leave     stop listening, which sec 4 answers with a Done to FF02::2
 * @var Mld6Ns::find      the entry for a group on an interface, and its state and deadline
 * @var Mld6Ns::query_in  a Query arrived: set the sec 4 report delay timers it applies to
 * @var Mld6Ns::report_in another node's Report arrived, which sec 4 suppresses ours with
 * @var Mld6Ns::tick      fire every report delay timer whose deadline has passed
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
} Mld6Ns;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const Mld6Ns Mld6;

// RFC 2710 sec 3 draws Type, Code, Checksum, Maximum Response Delay and Reserved above the 16-octet
// Multicast Address, which is the 24 octets sec 3.7 bounds a message at.
static_assert(IDEMIP_MLD6_MSG_LEN == 8u + IDEMIP_IP6_ADDR_LEN,
              "the RFC 2710 sec 3 fields must sum to the 24 octets sec 3.7 bounds a message at");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_MLD6_H
