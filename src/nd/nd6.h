// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file nd6.h
 * @brief Neighbor Discovery state, RFC 4861 sec 5.1, and the five reachability states of sec 7.3.2.
 *
 * RFC 4861 sec 5.1: "Hosts will need to maintain the following pieces of information for each
 * interface", and names four: the Neighbor Cache, the Destination Cache, the Prefix List and the
 * Default Router List. All four are regions of one borrow, and the borrow is per interface. A fifth
 * table holds the frames sec 7.2.2 requires be queued while address resolution completes; each pins
 * the receive descriptor its octets lie in.
 *
 * The Neighbor Discovery message and option formats are icmpv6.h's. Nothing here parses one.
 */

#ifndef IDEMIP_ND6_H
#define IDEMIP_ND6_H

#include "src/ethernet/ethernet.h" // IDEMIP_MAC_LEN, the link-layer address RFC 2464 sec 2 fixes
#include "src/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/** @brief No neighbor, no destination, no prefix, no router, no queued frame. */
#define IDEMIP_ND6_NONE 0xFFu

/**
 * @brief RFC 4861 sec 4.6.2: a Valid Lifetime "of all one bits (0xffffffff) represents infinity".
 *
 * sec 5.1 gives the Prefix List "a special 'infinity' timer value" that "specifies that a prefix
 * remains valid forever".
 */
#define IDEMIP_ND6_LIFETIME_INFINITE 0xFFFFFFFFu

/**
 * @brief A neighbor's reachability state, RFC 4861 sec 5.1 and sec 7.3.2.
 *
 * sec 5.1: "a neighbor's reachability state, which is one of five possible values", and sec 7.3.2
 * gives each its precise definition.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ND6_INCOMPLETE = 0, ///< "Address resolution is being performed on the entry"
    IDEMIP_ND6_REACHABLE,      ///< positive confirmation within the last ReachableTime milliseconds
    IDEMIP_ND6_STALE,          ///< more than ReachableTime has elapsed since that confirmation
    IDEMIP_ND6_DELAY,          ///< a packet was sent within the last DELAY_FIRST_PROBE_TIME
    IDEMIP_ND6_PROBE,          ///< unicast solicitations sent every RetransTimer milliseconds
} IdemIpNd6State;

/**
 * @brief What a Neighbor Cache call takes (RFC 4861 sec 5.1).
 *
 * @var Nd6NeighborArgs::addr      the neighbor's on-link unicast address, IDEMIP_IP6_ADDR_LEN octets
 * @var Nd6NeighborArgs::lladdr    its link-layer address, IDEMIP_MAC_LEN octets, or null when none
 *                                 is known yet (sec 7.3.2 INCOMPLETE)
 * @var Nd6NeighborArgs::state     the reachability state a CREATED entry takes. An entry that is
 *                                 already there takes its state from sec 7.2.5 instead, so this is
 *                                 unread then.
 * @var Nd6NeighborArgs::is_router the sec 5.1 IsRouter flag, written on every call. sec 7.2.3 leaves
 *                                 an existing entry's flag alone, so a solicitation's caller passes
 *                                 back what @ref Nd6Ns::neighbor_find reported.
 * @var Nd6NeighborArgs::solicited a solicited advertisement, which sec 7.3.3 makes REACHABLE
 * @var Nd6NeighborArgs::override  the sec 4.4 Override flag. sec 7.2.5 rule I: with it clear and a
 *                                 different link-layer address supplied, a REACHABLE entry goes
 *                                 STALE and any other state ignores the advertisement, which
 *                                 "MUST NOT update the cache".
 * @var Nd6NeighborArgs::index     which entry a call by index names
 */
typedef struct
{
    const uint8_t *addr;
    const uint8_t *lladdr;
    IdemIpNd6State state;
    idemip_bool is_router;
    idemip_bool solicited;
    idemip_bool override;
    uint8_t index;
} Nd6NeighborArgs;

/**
 * @brief What a Destination Cache call takes (RFC 4861 sec 5.1, RFC 8201).
 *
 * sec 5.1: the cache "maps a destination IP address to the IP address of the next-hop neighbor", and
 * an implementation may store with it "the Path MTU (PMTU) and round-trip timers".
 *
 * @var Nd6DestArgs::dst      the destination, IDEMIP_IP6_ADDR_LEN octets
 * @var Nd6DestArgs::next_hop the next-hop neighbor's address, IDEMIP_IP6_ADDR_LEN octets
 * @var Nd6DestArgs::pmtu     the path MTU, or zero to leave the held one alone
 * @var Nd6DestArgs::neighbor the Neighbor Cache entry this destination shares, which sec 5.1
 *                            requires be shared by every destination using that router
 */
typedef struct
{
    const uint8_t *dst;
    const uint8_t *next_hop;
    uint16_t pmtu;
    uint8_t neighbor;
} Nd6DestArgs;

/**
 * @brief What a Prefix List call takes (RFC 4861 sec 4.6.2, sec 5.1, sec 6.3.4).
 *
 * @var Nd6PrefixArgs::prefix     the prefix, IDEMIP_IP6_ADDR_LEN octets, its bits past @p prefix_len
 *                                reserved
 * @var Nd6PrefixArgs::lifetime_s the sec 4.6.2 Valid Lifetime in seconds, which sec 5.1 makes the
 *                                entry's invalidation timer. IDEMIP_ND6_LIFETIME_INFINITE is
 *                                infinity.
 * @var Nd6PrefixArgs::prefix_len leading valid bits, "from 0 to 128" (sec 4.6.2)
 * @var Nd6PrefixArgs::on_link    the sec 4.6.2 L flag
 * @var Nd6PrefixArgs::autonomous the sec 4.6.2 A flag
 */
typedef struct
{
    const uint8_t *prefix;
    uint32_t lifetime_s;
    uint8_t prefix_len;
    idemip_bool on_link;
    idemip_bool autonomous;
} Nd6PrefixArgs;

/**
 * @brief What a Default Router List call takes (RFC 4861 sec 4.2, sec 6.3.4).
 *
 * @var Nd6RouterArgs::addr       the advertising router's source address, IDEMIP_IP6_ADDR_LEN octets
 * @var Nd6RouterArgs::lladdr     the sec 4.6.1 Source Link-Layer Address option the advertisement
 *                                carried, IDEMIP_MAC_LEN octets, or NULL when it carried none. sec
 *                                4.2 says that option "MAY be omitted to facilitate in-bound load
 *                                balancing over replicated interfaces", and sec 7.2 makes the
 *                                difference matter: a message without one "MUST NOT create or update
 *                                neighbor cache entries, except with respect to the IsRouter flag".
 * @var Nd6RouterArgs::lifetime_s the sec 4.2 Router Lifetime in seconds. sec 6.3.4: a zero one
 *                                "immediately time-out the entry".
 */
typedef struct
{
    const uint8_t *addr;
    const uint8_t *lladdr;
    uint16_t lifetime_s;
} Nd6RouterArgs;

/**
 * @brief What a queued frame takes (RFC 4861 sec 7.2.2).
 *
 * sec 7.2.2: "the sender MUST, for each neighbor, retain a small queue of packets waiting for
 * address resolution to complete", and transmits them once resolution completes.
 *
 * @var Nd6PendingArgs::desc     the receive descriptor pinned while the frame is held
 * @var Nd6PendingArgs::len      octets of frame
 * @var Nd6PendingArgs::neighbor the neighbor whose resolution it waits on
 */
typedef struct
{
    uint16_t desc;
    uint16_t len;
    uint8_t neighbor;
} Nd6PendingArgs;

/**
 * @brief What the host variables a Router Advertisement revises take (RFC 4861 sec 6.3.4).
 *
 * sec 6.3.4 sets CurHopLimit, BaseReachableTime, RetransTimer and LinkMTU from a received
 * advertisement, and "A Router Advertisement field ... may contain a value denoting that it is
 * unspecified. In such cases, the parameter should be ignored and the host should continue using
 * whatever value it is already using."
 *
 * @var Nd6ParamsArgs::reachable_time_ms sec 4.2 Reachable Time, milliseconds; zero is unspecified
 * @var Nd6ParamsArgs::retrans_timer_ms  sec 4.2 Retrans Timer, milliseconds; zero is unspecified
 * @var Nd6ParamsArgs::link_mtu          sec 4.6.4 MTU option; one below IDEMIP_IPV6_MIN_MTU or above
 *                                       IDEMIP_ETH_MAX_PAYLOAD is not copied into LinkMTU
 * @var Nd6ParamsArgs::rand              a random word the sec 6.3.2 ReachableTime draw is taken
 *                                       from, which "should be a uniformly distributed random value
 *                                       between MIN_RANDOM_FACTOR and MAX_RANDOM_FACTOR times
 *                                       BaseReachableTime"
 * @var Nd6ParamsArgs::cur_hop_limit     sec 4.2 Cur Hop Limit; zero is unspecified
 * @var Nd6ParamsArgs::managed           sec 4.2 M flag, "Managed address configuration"
 * @var Nd6ParamsArgs::other             sec 4.2 O flag, "Other configuration"
 */
typedef struct
{
    uint32_t reachable_time_ms;
    uint32_t retrans_timer_ms;
    uint32_t link_mtu;
    uint32_t rand;
    uint8_t cur_hop_limit;
    idemip_bool managed;
    idemip_bool other;
} Nd6ParamsArgs;

/**
 * @brief The millisecond clock every deadline is stamped from and compared against.
 *
 * Every entry latches it, not the sweep alone, so a caller that sets it once per tick has every
 * deadline stamped from that tick and a caller that sets it per call has each stamped exactly.
 */
typedef struct
{
    uint32_t now_ms;
    /** A random word. RFC 4861 sec 6.3.2 asks that ReachableTime be re-computed "at least every few
     *  hours even if no Router Advertisements are received", and sec 6.3.4 gives the reason: "Using a
     *  random component eliminates the possibility that Neighbor Unreachability Detection messages
     *  will synchronize with each other." The sweep draws from this when that interval comes round. */
    uint32_t rand;
} Nd6TickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Nd6Io::neighbor_args  the Neighbor Cache operands
 * @var Nd6Io::dest_args      the Destination Cache operands
 * @var Nd6Io::prefix_args    the Prefix List operands
 * @var Nd6Io::router_args    the Default Router List operands
 * @var Nd6Io::pending_args   the queued frame operands
 * @var Nd6Io::params_args    the sec 6.3.4 host variables
 * @var Nd6Io::tick_args      the clock a sweep ages against
 * @var Nd6Io::status         what the call reports: OK, BUSY, or ERR
 * @var Nd6Io::lladdr         the cached link-layer address, IDEMIP_MAC_LEN octets where it lies
 * @var Nd6Io::next_hop       the destination's next hop, IDEMIP_IP6_ADDR_LEN octets where it lies
 * @var Nd6Io::target         the address a sweep wants a Neighbor Solicitation sent to
 * @var Nd6Io::next_event_ms  when the entry's next Neighbor Unreachability Detection event is due
 * @var Nd6Io::reachable_ms   ReachableTime, drawn between MIN_RANDOM_FACTOR and MAX_RANDOM_FACTOR
 *                            times BaseReachableTime (sec 6.3.2)
 * @var Nd6Io::retrans_ms     RetransTimer (sec 6.3.4)
 * @var Nd6Io::link_mtu       LinkMTU (sec 6.3.4)
 * @var Nd6Io::pmtu           the destination's path MTU
 * @var Nd6Io::desc           the descriptor a dequeued frame pins
 * @var Nd6Io::len            octets of that frame
 * @var Nd6Io::neighbor       the Neighbor Cache entry the call touched, or IDEMIP_ND6_NONE
 * @var Nd6Io::destination    the Destination Cache entry, or IDEMIP_ND6_NONE
 * @var Nd6Io::prefix         the Prefix List entry, or IDEMIP_ND6_NONE
 * @var Nd6Io::router         the Default Router List entry, or IDEMIP_ND6_NONE
 * @var Nd6Io::pending        the queued frame entry, or IDEMIP_ND6_NONE
 * @var Nd6Io::state          that neighbor's reachability state
 * @var Nd6Io::probes         unanswered solicitations on that entry (sec 5.1)
 * @var Nd6Io::cur_hop_limit  CurHopLimit (sec 6.3.4)
 * @var Nd6Io::expired        entries a sweep invalidated
 * @var Nd6Io::is_router      that neighbor's IsRouter flag
 * @var Nd6Io::on_link        the address matched a Prefix List entry with the L flag set
 * @var Nd6Io::solicit        a sweep asks for a Neighbor Solicitation to @ref Nd6Io::target
 * @var Nd6Io::multicast      that solicitation goes to the solicited-node multicast address rather
 *                            than to the cached link-layer address (sec 7.2.2, sec 7.3.3)
 * @var Nd6Io::managed        the M flag last advertised
 * @var Nd6Io::other          the O flag last advertised
 */
typedef struct
{
    Nd6NeighborArgs neighbor_args;
    Nd6DestArgs dest_args;
    Nd6PrefixArgs prefix_args;
    Nd6RouterArgs router_args;
    Nd6PendingArgs pending_args;
    Nd6ParamsArgs params_args;
    Nd6TickArgs tick_args;

    IdemIpStatus status;
    const uint8_t *lladdr;
    const uint8_t *next_hop;
    const uint8_t *target;
    uint32_t next_event_ms;
    uint32_t reachable_ms;
    uint32_t retrans_ms;
    uint32_t link_mtu;
    uint16_t pmtu;
    uint16_t desc;
    uint16_t len;
    uint8_t neighbor;
    uint8_t destination;
    uint8_t prefix;
    uint8_t router;
    uint8_t pending;
    IdemIpNd6State state;
    uint8_t probes;
    uint8_t cur_hop_limit;
    uint8_t expired;
    idemip_bool is_router;
    idemip_bool on_link;
    idemip_bool solicit;
    idemip_bool multicast;
    idemip_bool managed;
    idemip_bool other;
} Nd6Io;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only
// the map is public. dad.c and slaac.c share this borrow, and their RFC 4862 sec 5.4 state lives in
// the context region below.

// IDEMIP_ND6_CTX_BYTES spans the operand block and the context together, the way IDEMIP_PHY_BORROW
// covers both, so the tables start at a constant that no growth in either moves.

#define IDEMIP_ND6_OFF_IO 0u ///< the operand and result block
#define IDEMIP_ND6_OFF_CTX (IDEMIP_ND6_OFF_IO + IDEMIP_ROUND_UP(sizeof(Nd6Io), IDEMIP_ALIGN))
#define IDEMIP_ND6_OFF_NEIGHBORS (IDEMIP_ND6_OFF_IO + IDEMIP_ND6_CTX_BYTES)
#define IDEMIP_ND6_OFF_DESTINATIONS                                                                                    \
    (IDEMIP_ND6_OFF_NEIGHBORS + (IDEMIP_ND6_NUM_NEIGHBORS << IDEMIP_ND6_NEIGHBOR_ENTRY_SHIFT))
#define IDEMIP_ND6_OFF_PREFIXES                                                                                        \
    (IDEMIP_ND6_OFF_DESTINATIONS + (IDEMIP_ND6_NUM_DESTINATIONS << IDEMIP_ND6_DESTINATION_ENTRY_SHIFT))
#define IDEMIP_ND6_OFF_ROUTERS (IDEMIP_ND6_OFF_PREFIXES + (IDEMIP_ND6_NUM_PREFIXES << IDEMIP_ND6_PREFIX_ENTRY_SHIFT))
#define IDEMIP_ND6_OFF_PENDING (IDEMIP_ND6_OFF_ROUTERS + (IDEMIP_ND6_NUM_ROUTERS << IDEMIP_ND6_ROUTER_ENTRY_SHIFT))
#define IDEMIP_ND6_OFF_END (IDEMIP_ND6_OFF_PENDING + (IDEMIP_ND6_PENDING << IDEMIP_ND6_PENDING_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_ND6_IO(w) ((Nd6Io *)(void *)((w) + IDEMIP_ND6_OFF_IO))

/**
 * @brief One interface's Neighbor Discovery state, RFC 4861 sec 5.1.
 *
 *   Nd6.clear(work);
 *   IDEMIP_ND6_IO(work)->neighbor_args.addr = idemip_ip6_src(pkt);
 *   IDEMIP_ND6_IO(work)->neighbor_args.lladdr = sllao;
 *   IDEMIP_ND6_IO(work)->neighbor_args.state = IDEMIP_ND6_STALE;
 *   Nd6.neighbor_set(work);
 *   if (IDEMIP_ND6_IO(work)->status == IDEMIP_OK) { ... }
 *
 * @c work is IDEMIP_ND6_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. sec 5.1 keeps this state
 * "for each interface", so the borrow IS the interface and the caller takes IDEMIP_NETIF_COUNT of
 * them; two interfaces share not one byte.
 *
 * A borrow is refused until @ref Nd6Ns::clear has run on it: clear zeroes every region above and
 * leaves one nonzero octet in the context region, the mark that says these bytes are this module's.
 * It does not touch the operand block.
 *
 * Nothing here blocks. A table with no free slot reports IDEMIP_BUSY, since a slot frees when an
 * entry's invalidation timer fires or resolution completes. A bad argument or an entry that is not
 * there reports IDEMIP_ERR.
 *
 * A frame this module holds stays in the buffer the engine wrote it to, so what it keeps is the
 * descriptor index. Every entry that hands one back reports it in @ref Nd6Io::desc with
 * @ref Nd6Io::len nonzero, and the caller unpins it through dma.
 *
 * @var Nd6Ns::clear            zero the context and the five tables, and mark the borrow cleared
 * @var Nd6Ns::neighbor_find    the Neighbor Cache entry keyed on an on-link unicast address
 * @var Nd6Ns::neighbor_set     create or update one, per sec 7.2.3, sec 7.2.5, sec 6.3.4 and sec 8.3
 * @var Nd6Ns::neighbor_confirm upper-layer advice that the forward path works, which sec 7.3.3 makes
 *                              REACHABLE, and which sec 7.3.3 makes a no-op on an INCOMPLETE entry
 * @var Nd6Ns::neighbor_used    a packet went to a STALE neighbor, which sec 7.3.3 makes DELAY
 * @var Nd6Ns::neighbor_remove  delete an entry, as sec 7.3.3 does when resolution fails. Reports
 *                              IDEMIP_BUSY once per frame still queued on it, handing each
 *                              descriptor back so sec 7.2.2's ICMP Destination Unreachable code 3
 *                              is answered, and IDEMIP_OK on the call that frees the entry.
 * @var Nd6Ns::dest_find        the next hop a destination resolves to (sec 5.2)
 * @var Nd6Ns::dest_set         install or revise one, as a Redirect (sec 8.3) or a PMTU does
 * @var Nd6Ns::prefix_set       install a Prefix Information option's prefix (sec 6.3.4)
 * @var Nd6Ns::prefix_on_link   longest prefix match over the Prefix List (sec 5.2), which answers
 *                              IDEMIP_OK either way and puts the answer in @ref Nd6Io::on_link
 * @var Nd6Ns::router_set       install or time out a Default Router List entry (sec 6.3.4)
 * @var Nd6Ns::router_select    pick a default router, favoring the reachable (sec 6.3.6)
 * @var Nd6Ns::pending_push     hold a frame awaiting resolution (sec 7.2.2). A full table with a
 *                              frame already queued on that neighbor replaces the oldest and hands
 *                              its descriptor back.
 * @var Nd6Ns::pending_pop      take back the next frame held for a neighbor (sec 7.2.2)
 * @var Nd6Ns::params_set       copy the sec 6.3.4 host variables out of a Router Advertisement
 * @var Nd6Ns::tick             run the sec 7.3.3 reachability machine and every invalidation timer.
 *                              Reports one event per call, a released frame before a due
 *                              solicitation, and IDEMIP_BUSY when nothing was due.
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const neighbor_find)(uint8_t *restrict work);
    void (*const neighbor_set)(uint8_t *restrict work);
    void (*const neighbor_confirm)(uint8_t *restrict work);
    void (*const neighbor_used)(uint8_t *restrict work);
    void (*const neighbor_remove)(uint8_t *restrict work);
    void (*const dest_find)(uint8_t *restrict work);
    void (*const dest_set)(uint8_t *restrict work);
    void (*const prefix_set)(uint8_t *restrict work);
    void (*const prefix_on_link)(uint8_t *restrict work);
    void (*const router_set)(uint8_t *restrict work);
    void (*const router_select)(uint8_t *restrict work);
    void (*const pending_push)(uint8_t *restrict work);
    void (*const pending_pop)(uint8_t *restrict work);
    void (*const params_set)(uint8_t *restrict work);
    void (*const tick)(uint8_t *restrict work);
} Nd6Ns;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_nd6_clear(uint8_t *restrict work);
void idemip_nd6_neighbor_find(uint8_t *restrict work);
void idemip_nd6_neighbor_set(uint8_t *restrict work);
void idemip_nd6_neighbor_confirm(uint8_t *restrict work);
void idemip_nd6_neighbor_used(uint8_t *restrict work);
void idemip_nd6_neighbor_remove(uint8_t *restrict work);
void idemip_nd6_dest_find(uint8_t *restrict work);
void idemip_nd6_dest_set(uint8_t *restrict work);
void idemip_nd6_prefix_set(uint8_t *restrict work);
void idemip_nd6_prefix_on_link(uint8_t *restrict work);
void idemip_nd6_router_set(uint8_t *restrict work);
void idemip_nd6_router_select(uint8_t *restrict work);
void idemip_nd6_pending_push(uint8_t *restrict work);
void idemip_nd6_pending_pop(uint8_t *restrict work);
void idemip_nd6_params_set(uint8_t *restrict work);
void idemip_nd6_tick(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Nd6.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Nd6Ns Nd6 IDEMIP_UNUSED = {
    .clear = idemip_nd6_clear,
    .neighbor_find = idemip_nd6_neighbor_find,
    .neighbor_set = idemip_nd6_neighbor_set,
    .neighbor_confirm = idemip_nd6_neighbor_confirm,
    .neighbor_used = idemip_nd6_neighbor_used,
    .neighbor_remove = idemip_nd6_neighbor_remove,
    .dest_find = idemip_nd6_dest_find,
    .dest_set = idemip_nd6_dest_set,
    .prefix_set = idemip_nd6_prefix_set,
    .prefix_on_link = idemip_nd6_prefix_on_link,
    .router_set = idemip_nd6_router_set,
    .router_select = idemip_nd6_router_select,
    .pending_push = idemip_nd6_pending_push,
    .pending_pop = idemip_nd6_pending_pop,
    .params_set = idemip_nd6_params_set,
    .tick = idemip_nd6_tick};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_ND6_H
