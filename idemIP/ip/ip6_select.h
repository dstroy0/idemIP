// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip6_select.h
 * @brief Default address selection, RFC 6724: sec 5's source rules and sec 6's destination rules.
 *
 * Two algorithms over one policy table. sec 5 picks one source address out of a candidate set for a
 * given destination; sec 6 sorts a list of destinations, computing Source(D) for each as it goes.
 * Both read the sec 2.1 policy table, which @ref Ip6SelectNs::clear loads with the default rows
 * sec 2.1 prints and @ref Ip6SelectNs::policy_set overrides.
 *
 * The candidate set, the destination list and the policy table are all regions of the caller's
 * borrow, at published offsets, so two callers sorting two lists share not one byte.
 *
 * What an address IS is ip6_addr.h's; this file only orders addresses.
 */

#ifndef IDEMIP_IP6_SELECT_H
#define IDEMIP_IP6_SELECT_H

#include "idemIP/ip/ip6_addr.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/** @brief No candidate, no destination, no policy row. */
#define IDEMIP_IP6_SELECT_NONE 0xFFu

/**
 * @brief Rows the default policy table of RFC 6724 sec 2.1 prints.
 *
 *      Prefix        Precedence Label
 *      ::1/128               50     0
 *      ::/0                  40     1
 *      ::ffff:0:0/96         35     4
 *      2002::/16             30     2
 *      2001::/32              5     5
 *      fc00::/7               3    13
 *      ::/96                  1     3
 *      fec0::/10              1    11
 *      3ffe::/16              1    12
 */
#define IDEMIP_IP6_SELECT_DEFAULT_POLICIES 9u

/**
 * @brief Bits RFC 6724 sec 2.2 stops a common prefix at.
 *
 * sec 2.2: the common prefix length is measured "up to the length of S's prefix (i.e., the portion
 * of the address not including the interface ID)", and RFC 4291 sec 2.5.1 fixes that interface ID
 * at 64 bits: "For all unicast addresses, except those that start with the binary value 000,
 * Interface IDs are required to be 64 bits long". sec 2.2's own example is
 * CommonPrefixLen(fe80::1, fe80::2) = 64, which is the cap rather than the 127 bits the two share.
 */
#define IDEMIP_IP6_SELECT_COMMON_PREFIX_MAX 64u

/**
 * @brief Which rule of RFC 6724 sec 5 or sec 6 decided a comparison.
 *
 * A diagnostic, reported in @ref Ip6SelectIo::rule. No control flow anywhere branches on it. sec 5
 * numbers one of its rules 5.5, which is 55 here so the sequence stays ordered in one octet.
 */
#define IDEMIP_IP6_SELECT_RULE_NONE 0u
#define IDEMIP_IP6_SELECT_RULE_5_5 55u

// ---------------------------------------------------------------------------
// Operands
// ---------------------------------------------------------------------------

/**
 * @brief What adding a candidate source address takes (RFC 6724 sec 4, sec 5).
 *
 * sec 4: "It is RECOMMENDED that the candidate source addresses be the set of unicast addresses
 * assigned to the interface that will be used to send to the destination", and "In any case,
 * multicast addresses and the unspecified address MUST NOT be included in a candidate set."
 *
 * The four flags sec 5 cannot derive from the address are the caller's: RFC 4862 gives an address
 * its preferred or deprecated state, RFC 6275 makes it a home or a care-of address, RFC 4941 makes
 * it temporary or public, and only an implementation that tracks which next-hop advertised which
 * prefix can set sec 5's Rule 5.5.
 *
 * @var Ip6SelectSourceArgs::addr       IDEMIP_IP6_ADDR_LEN octets, copied into the borrow
 * @var Ip6SelectSourceArgs::zone       its RFC 4007 sec 6 zone index, or IDEMIP_IP6_ZONE_DEFAULT
 * @var Ip6SelectSourceArgs::netif      the interface it is assigned to (Rule 5)
 * @var Ip6SelectSourceArgs::deprecated the RFC 4862 state Rule 3 reads
 * @var Ip6SelectSourceArgs::temporary  the RFC 4941 kind Rule 7 reads
 * @var Ip6SelectSourceArgs::home       a home address (Rule 4)
 * @var Ip6SelectSourceArgs::care_of    a care-of address; both flags set is the "simultaneously"
 *                                      case Rule 4 puts first
 * @var Ip6SelectSourceArgs::next_hop   this address or its prefix was assigned by the next-hop
 *                                      selected for the destination (Rule 5.5)
 */
typedef struct
{
    const uint8_t *addr;
    uint32_t zone;
    uint8_t netif;
    idemip_bool deprecated;
    idemip_bool temporary;
    idemip_bool home;
    idemip_bool care_of;
    idemip_bool next_hop;
} Ip6SelectSourceArgs;

/**
 * @brief What adding a destination takes (RFC 6724 sec 6).
 *
 * @var Ip6SelectDestArgs::addr         IDEMIP_IP6_ADDR_LEN octets. sec 6: "To find the attributes
 *                                      of an IPv4 address in the policy table, the IPv4 address
 *                                      MUST be represented as an IPv4-mapped address."
 * @var Ip6SelectDestArgs::zone         its RFC 4007 sec 6 zone index
 * @var Ip6SelectDestArgs::netif        the interface that will be used to send to it, which Rule 5
 *                                      of sec 5 prefers a source address from
 * @var Ip6SelectDestArgs::unreachable  Rule 1's "known to be unreachable", which sec 6 leaves
 *                                      "implementation-dependent"
 * @var Ip6SelectDestArgs::encapsulated Rule 7's "reached via an encapsulating transition mechanism"
 */
typedef struct
{
    const uint8_t *addr;
    uint32_t zone;
    uint8_t netif;
    idemip_bool unreachable;
    idemip_bool encapsulated;
} Ip6SelectDestArgs;

/**
 * @brief What a policy row takes (RFC 6724 sec 2.1).
 *
 * @var Ip6SelectPolicyArgs::prefix     IDEMIP_IP6_ADDR_LEN octets, its bits past @p prefix_len
 *                                      unread
 * @var Ip6SelectPolicyArgs::zone       sec 2.1: "Policy table entries for address prefixes that are
 *                                      not of global scope MAY be qualified with an optional zone
 *                                      index", and IDEMIP_IP6_ZONE_DEFAULT qualifies with none
 * @var Ip6SelectPolicyArgs::prefix_len leading bits the row matches on, 0 through 128
 * @var Ip6SelectPolicyArgs::precedence Precedence(A), which sec 6 Rule 6 sorts destinations by
 * @var Ip6SelectPolicyArgs::label      Label(A), which sec 5 Rule 6 and sec 6 Rule 5 match on
 */
typedef struct
{
    const uint8_t *prefix;
    uint32_t zone;
    uint8_t prefix_len;
    uint8_t precedence;
    uint8_t label;
} Ip6SelectPolicyArgs;

/**
 * @brief What a query takes.
 *
 * @var Ip6SelectQueryArgs::addr  the destination a source selection is for, the address a lookup or
 *                                a scope names, or S in a common prefix length
 * @var Ip6SelectQueryArgs::peer  D in a common prefix length, unread by every other entry
 * @var Ip6SelectQueryArgs::zone  the RFC 4007 sec 6 zone of @ref Ip6SelectQueryArgs::addr
 * @var Ip6SelectQueryArgs::netif the interface that will be used to send to it (sec 5 Rule 5)
 * @var Ip6SelectQueryArgs::index which destination, in sorted order, a read names
 */
typedef struct
{
    const uint8_t *addr;
    const uint8_t *peer;
    uint32_t zone;
    uint8_t netif;
    uint8_t index;
} Ip6SelectQueryArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Ip6SelectIo::source_args the candidate source address being added
 * @var Ip6SelectIo::dest_args   the destination being added
 * @var Ip6SelectIo::policy_args the sec 2.1 row being set
 * @var Ip6SelectIo::query_args  what a selection, a sort read, a lookup or a length is asked about
 * @var Ip6SelectIo::status      what the call reports: OK or ERR
 * @var Ip6SelectIo::source      the selected source address, where it lies in the borrow, or null
 * @var Ip6SelectIo::dest        the destination a sorted read named, where it lies in the borrow
 * @var Ip6SelectIo::source_zone that source address's zone index
 * @var Ip6SelectIo::dest_zone   that destination's zone index
 * @var Ip6SelectIo::sources     candidates held
 * @var Ip6SelectIo::dests       destinations held
 * @var Ip6SelectIo::policies    policy rows held
 * @var Ip6SelectIo::index       the candidate or destination entry the call names, or
 *                               IDEMIP_IP6_SELECT_NONE
 * @var Ip6SelectIo::rule        which rule of sec 5 decided the last comparison the winner was in,
 *                               or IDEMIP_IP6_SELECT_RULE_NONE when every rule tied
 * @var Ip6SelectIo::precedence  Precedence(A) from the sec 2.1 lookup
 * @var Ip6SelectIo::label       Label(A) from the same lookup
 * @var Ip6SelectIo::prefix_len  the matched row's prefix length, or 0 when none matched
 * @var Ip6SelectIo::common      CommonPrefixLen (sec 2.2), capped at
 *                               IDEMIP_IP6_SELECT_COMMON_PREFIX_MAX
 * @var Ip6SelectIo::netif       the interface the selected source address is assigned to
 * @var Ip6SelectIo::scope       the sec 3 scope of the address a query named
 * @var Ip6SelectIo::found       a selection or a lookup produced an answer
 * @var Ip6SelectIo::sorted      the destination list is in sec 6 order
 */
typedef struct
{
    Ip6SelectSourceArgs source_args;
    Ip6SelectDestArgs dest_args;
    Ip6SelectPolicyArgs policy_args;
    Ip6SelectQueryArgs query_args;

    IdemIpStatus status;
    const uint8_t *source;
    const uint8_t *dest;
    uint32_t source_zone;
    uint32_t dest_zone;
    uint8_t sources;
    uint8_t dests;
    uint8_t policies;
    uint8_t index;
    uint8_t rule;
    uint8_t precedence;
    uint8_t label;
    uint8_t prefix_len;
    uint8_t common;
    uint8_t netif;
    IdemIpIp6Scope scope;
    idemip_bool found;
    idemip_bool sorted;
} Ip6SelectIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only
// the map is public.
//
// IDEMIP_IP6_SELECT_CTX_BYTES spans the operand block and the context together, the way
// IDEMIP_PHY_BORROW covers both, so the tables start at a constant that no growth in either moves.

#define IDEMIP_IP6_SELECT_OFF_IO 0u ///< the operand and result block
#define IDEMIP_IP6_SELECT_OFF_CTX (IDEMIP_IP6_SELECT_OFF_IO + IDEMIP_ROUND_UP(sizeof(Ip6SelectIo), IDEMIP_ALIGN))
#define IDEMIP_IP6_SELECT_OFF_SOURCES (IDEMIP_IP6_SELECT_OFF_IO + IDEMIP_IP6_SELECT_CTX_BYTES)
#define IDEMIP_IP6_SELECT_OFF_DESTS                                                                                    \
    (IDEMIP_IP6_SELECT_OFF_SOURCES + (IDEMIP_IP6_SELECT_SOURCES << IDEMIP_IP6_SELECT_SOURCE_ENTRY_SHIFT))
#define IDEMIP_IP6_SELECT_OFF_POLICIES                                                                                 \
    (IDEMIP_IP6_SELECT_OFF_DESTS + (IDEMIP_IP6_SELECT_DESTS << IDEMIP_IP6_SELECT_DEST_ENTRY_SHIFT))
#define IDEMIP_IP6_SELECT_OFF_ORDER                                                                                    \
    (IDEMIP_IP6_SELECT_OFF_POLICIES + (IDEMIP_IP6_SELECT_POLICIES << IDEMIP_IP6_SELECT_POLICY_ENTRY_SHIFT))
#define IDEMIP_IP6_SELECT_OFF_END                                                                                      \
    (IDEMIP_IP6_SELECT_OFF_ORDER + IDEMIP_ROUND_UP(IDEMIP_IP6_SELECT_DESTS, IDEMIP_ALIGN))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IP6_SELECT_IO(w) ((Ip6SelectIo *)(void *)((w) + IDEMIP_IP6_SELECT_OFF_IO))

/**
 * @brief RFC 6724 default address selection, over one candidate set and one destination list.
 *
 *   Ip6Select.clear(work);
 *   IDEMIP_IP6_SELECT_IO(work)->source_args.addr = my_global;
 *   Ip6Select.source_add(work);
 *   IDEMIP_IP6_SELECT_IO(work)->query_args.addr = peer;
 *   Ip6Select.source_select(work);
 *   if (IDEMIP_IP6_SELECT_IO(work)->found) { ... IDEMIP_IP6_SELECT_IO(work)->source ... }
 *
 * @c work is IDEMIP_IP6_SELECT_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. The borrow IS the
 * instance, so two selections in flight are two borrows and share not one byte.
 *
 * A borrow is refused until @ref Ip6SelectNs::clear has run on it: clear zeroes the context and the
 * four regions, loads the sec 2.1 default policy table, and leaves one nonzero octet in the context,
 * the mark that says these bytes are this module's.
 *
 * Nothing here blocks, and no entry ever reports IDEMIP_BUSY. A full candidate set, a full
 * destination list and a full policy table are all IDEMIP_ERR rather than IDEMIP_BUSY: no timer
 * frees a slot in any of them and nothing else does either, so the same call on a later tick fails
 * the same way. Only @ref Ip6SelectNs::clear empties them, and that is the caller's own call.
 *
 * A destination takes a source of its own family. sec 5 states its bound, "This algorithm only
 * applies to IPv6 destination addresses, not IPv4 addresses", and sec 6 adds "Source address
 * selection for IPv4 addresses is not specified in this document", so an IPv4-mapped destination is
 * ordered against the IPv4-mapped candidates and an IPv6 destination against the rest.
 *
 * @var Ip6SelectNs::clear         zero the four regions and load the sec 2.1 default policy table
 * @var Ip6SelectNs::policy_set    add or override one sec 2.1 row
 * @var Ip6SelectNs::policy_lookup Precedence(A) and Label(A), longest matching prefix (sec 2.1)
 * @var Ip6SelectNs::scope_of      the sec 3 scope of one address, IPv4 mappings included
 * @var Ip6SelectNs::common_prefix CommonPrefixLen(S, D) (sec 2.2)
 * @var Ip6SelectNs::source_add    add one candidate source address (sec 4)
 * @var Ip6SelectNs::dest_add      add one destination to the list
 * @var Ip6SelectNs::source_select run sec 5's rules and report the winning candidate
 * @var Ip6SelectNs::dest_sort     run sec 6's rules over the whole list
 * @var Ip6SelectNs::dest_at       read the destination that sort put at one position
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const policy_set)(uint8_t *restrict work);
    void (*const policy_lookup)(uint8_t *restrict work);
    void (*const scope_of)(uint8_t *restrict work);
    void (*const common_prefix)(uint8_t *restrict work);
    void (*const source_add)(uint8_t *restrict work);
    void (*const dest_add)(uint8_t *restrict work);
    void (*const source_select)(uint8_t *restrict work);
    void (*const dest_sort)(uint8_t *restrict work);
    void (*const dest_at)(uint8_t *restrict work);
} Ip6SelectNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const Ip6SelectNs Ip6Select;

// Every table index counts the entries the borrow holds, so IDEMIP_IP6_SELECT_NONE names none.
static_assert(IDEMIP_IP6_SELECT_SOURCES < IDEMIP_IP6_SELECT_NONE &&
                  IDEMIP_IP6_SELECT_DESTS < IDEMIP_IP6_SELECT_NONE &&
                  IDEMIP_IP6_SELECT_POLICIES < IDEMIP_IP6_SELECT_NONE,
              "a table is wider than the index a result member carries");

// sec 2.1's default table has to fit, or clear could not load it.
static_assert(IDEMIP_IP6_SELECT_POLICIES >= IDEMIP_IP6_SELECT_DEFAULT_POLICIES,
              "IDEMIP_IP6_SELECT_POLICIES is short of the nine rows RFC 6724 sec 2.1 prints");

// sec 2.2 measures up to S's prefix, which RFC 4291 sec 2.5.1 puts at 64 bits.
static_assert(IDEMIP_IP6_SELECT_COMMON_PREFIX_MAX == (IDEMIP_IP6_ADDR_BITS >> 1),
              "the interface ID is half an address (RFC 4291 sec 2.5.1)");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_IP6_SELECT_H
