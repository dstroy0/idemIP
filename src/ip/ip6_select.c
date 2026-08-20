// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip6_select.c
 * @brief RFC 6724 sec 5's eight source rules and sec 6's ten destination rules, over one borrow.
 *
 * Every entry is a function of the one pointer it is handed: the operand block, the context, the
 * candidate set, the destination list, the policy table and the sorted order are all regions of that
 * borrow, at compile-time offsets, and no entry reads or writes a byte outside it. Two borrows
 * therefore share nothing, and the same call on the same borrow does the same thing.
 *
 * What an address IS comes from ip6_addr.h's inline tests. This file only orders addresses.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip6_select.h"

IDEMIP_BEGIN_DECLS

// RFC 6724 sec 4's candidate set, one entry per address the caller offered. The four flags sec 5
// cannot derive from the address itself arrive with it: RFC 4862's preferred or deprecated state,
// RFC 6275's home and care-of designation, RFC 4941's temporary or public kind, and whether the
// selected next-hop assigned this address or its prefix (Rule 5.5).
typedef struct
{
    uint32_t zone;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    uint8_t netif;
    idemip_bool deprecated;
    idemip_bool temporary;
    idemip_bool home;
    idemip_bool care_of;
    idemip_bool next_hop;
    idemip_bool used;
    uint8_t pad[5];
} Ip6SelectSource;

// One destination of the list sec 6 sorts, with the candidate index sec 6 writes Source(D) as.
typedef struct
{
    uint32_t zone;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    uint8_t netif;
    uint8_t source;
    idemip_bool unreachable;
    idemip_bool encapsulated;
    idemip_bool used;
    uint8_t pad[7];
} Ip6SelectDest;

// RFC 6724 sec 2.1: "The policy table is a longest-matching-prefix lookup table, much like a routing
// table. Given an address A, a lookup in the policy table produces two values: a precedence value
// denoted Precedence(A) and a classification or label denoted Label(A)."
typedef struct
{
    uint32_t zone;
    uint8_t prefix[IDEMIP_IP6_ADDR_LEN];
    uint8_t prefix_len;
    uint8_t precedence;
    uint8_t label;
    idemip_bool used;
    uint8_t pad[8];
} Ip6SelectPolicy;

// The occupancy of each region, whether the order region is current, and the mark clear leaves.
typedef struct
{
    uint8_t sources;
    uint8_t dests;
    uint8_t policies;
    idemip_bool sorted;
    idemip_bool ready;
} Ip6SelectCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_IP6_SELECT_OFF_CTX, sizeof(Ip6SelectCtx), IDEMIP_IP6_SELECT_OFF_END, "ip6_select's context");

// An index is (i << SHIFT), so each entry is exactly its width.
static_assert(sizeof(Ip6SelectSource) == (1u << IDEMIP_IP6_SELECT_SOURCE_ENTRY_SHIFT),
              "a candidate entry must be 1 << IDEMIP_IP6_SELECT_SOURCE_ENTRY_SHIFT wide");
static_assert(sizeof(Ip6SelectDest) == (1u << IDEMIP_IP6_SELECT_DEST_ENTRY_SHIFT),
              "a destination entry must be 1 << IDEMIP_IP6_SELECT_DEST_ENTRY_SHIFT wide");
static_assert(sizeof(Ip6SelectPolicy) == (1u << IDEMIP_IP6_SELECT_POLICY_ENTRY_SHIFT),
              "a policy entry must be 1 << IDEMIP_IP6_SELECT_POLICY_ENTRY_SHIFT wide");

// The caller's borrow, split: the operand block, the context, then the four regions. ip6_select.h
// publishes the offsets; these two asserts prove the span covers them before anything runs. The
// first keeps the context inside the region ahead of the candidate set, the second the whole map
// inside the borrow.
static_assert(IDEMIP_IP6_SELECT_OFF_CTX + sizeof(Ip6SelectCtx) <= IDEMIP_IP6_SELECT_OFF_SOURCES,
              "IDEMIP_IP6_SELECT_CTX_BYTES is short of the operand block and the context - raise it in "
              "idemip_config.h");
static_assert(IDEMIP_IP6_SELECT_OFF_END <= IDEMIP_IP6_SELECT_BORROW,
              "IDEMIP_IP6_SELECT_BORROW is short of the map - raise IDEMIP_IP6_SELECT_CTX_BYTES in "
              "idemip_config.h");

// Each region starts at the end of the one before it, so a context that is not a multiple of
// IDEMIP_ALIGN, or an entry narrower than it, misaligns a table.
static_assert((IDEMIP_IP6_SELECT_CTX_BYTES & (IDEMIP_ALIGN - 1u)) == 0u,
              "IDEMIP_IP6_SELECT_CTX_BYTES must be a multiple of IDEMIP_ALIGN: a table starts at its end");
static_assert((1u << IDEMIP_IP6_SELECT_SOURCE_ENTRY_SHIFT) >= IDEMIP_ALIGN &&
                  (1u << IDEMIP_IP6_SELECT_DEST_ENTRY_SHIFT) >= IDEMIP_ALIGN &&
                  (1u << IDEMIP_IP6_SELECT_POLICY_ENTRY_SHIFT) >= IDEMIP_ALIGN,
              "each entry width must be IDEMIP_ALIGN or wider: entry i sits at (i << SHIFT)");

// The regions, at their offsets in the caller's borrow.
#define IP6_SELECT_IO(w) IDEMIP_IP6_SELECT_IO(w)
#define IP6_SELECT_CTX(w) ((Ip6SelectCtx *)(void *)((w) + IDEMIP_IP6_SELECT_OFF_CTX))
#define IP6_SELECT_SOURCE_AT(w, i)                                                                                     \
    ((Ip6SelectSource *)(void *)((w) + IDEMIP_IP6_SELECT_OFF_SOURCES +                                                 \
                                 ((size_t)(i) << IDEMIP_IP6_SELECT_SOURCE_ENTRY_SHIFT)))
#define IP6_SELECT_DEST_AT(w, i)                                                                                       \
    ((Ip6SelectDest *)(void *)((w) + IDEMIP_IP6_SELECT_OFF_DESTS +                                                     \
                               ((size_t)(i) << IDEMIP_IP6_SELECT_DEST_ENTRY_SHIFT)))
#define IP6_SELECT_POLICY_AT(w, i)                                                                                     \
    ((Ip6SelectPolicy *)(void *)((w) + IDEMIP_IP6_SELECT_OFF_POLICIES +                                                \
                                 ((size_t)(i) << IDEMIP_IP6_SELECT_POLICY_ENTRY_SHIFT)))
#define IP6_SELECT_ORDER(w) ((uint8_t *)((w) + IDEMIP_IP6_SELECT_OFF_ORDER))

// Octets the context and the four regions span, which is what clear zeroes.
#define IP6_SELECT_STATE_BYTES (IDEMIP_IP6_SELECT_OFF_END - IDEMIP_IP6_SELECT_OFF_CTX)

// Each count as the octet an index is compared against.
#define IP6_SELECT_SOURCES ((uint8_t)IDEMIP_IP6_SELECT_SOURCES)
#define IP6_SELECT_DESTS ((uint8_t)IDEMIP_IP6_SELECT_DESTS)
#define IP6_SELECT_POLICIES ((uint8_t)IDEMIP_IP6_SELECT_POLICIES)

// RFC 6724 sec 3.2 assigns two IPv4 prefixes link-local scope: "IPv4 auto-configuration addresses
// [RFC3927], which have the prefix 169.254/16" and "IPv4 loopback addresses (Section 4.2.2.11 of
// [RFC1812]), which have the prefix 127/8".
#define IP6_SELECT_V4_LINK_LOCAL_0 169u
#define IP6_SELECT_V4_LINK_LOCAL_1 254u
#define IP6_SELECT_V4_LOOPBACK_0 127u

// The default policy table, exactly the nine rows RFC 6724 sec 2.1 prints. Immutable, so it lives in
// rodata and no borrow holds a second copy of it.
typedef struct
{
    uint8_t prefix[IDEMIP_IP6_ADDR_LEN];
    uint8_t prefix_len;
    uint8_t precedence;
    uint8_t label;
} Ip6SelectDefaultRow;

static const Ip6SelectDefaultRow ip6_select_default_policy[IDEMIP_IP6_SELECT_DEFAULT_POLICIES] = {
    {{0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u}, 128u, 50u, 0u},    // ::1/128
    {{0u}, 0u, 40u, 1u},                                                                  // ::/0
    {{0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0xFFu, 0xFFu}, 96u, 35u, 4u},               // ::ffff:0:0/96
    {{0x20u, 0x02u}, 16u, 30u, 2u},                                                       // 2002::/16
    {{0x20u, 0x01u}, 32u, 5u, 5u},                                                        // 2001::/32
    {{0xFCu}, 7u, 3u, 13u},                                                               // fc00::/7
    {{0u}, 96u, 1u, 3u},                                                                  // ::/96
    {{0xFEu, 0xC0u}, 10u, 1u, 11u},                                                       // fec0::/10
    {{0x3Fu, 0xFEu}, 16u, 1u, 12u},                                                       // 3ffe::/16
};

// --- the properties an ordering reads --------------------------------------

/**
 * The scope RFC 6724 sec 3 gives an address, which extends the RFC 4291 and RFC 4007 scope in one
 * place: sec 3.2 says an IPv4 address "MUST be represented as an IPv4-mapped address" and then
 * assigns 169.254/16 and 127/8 link-local scope, "Other IPv4 addresses ... global scope". sec 3.3
 * separately makes every address with an embedded IPv4 address global, IPv4-mapped named among
 * them; the two sections conflict on that one form, and sec 3.2 is the one sec 10.2's own example
 * follows, ordering 2001:db8:1::1 ahead of 198.51.100.121 by "prefer matching scope" only because
 * the candidate 169.254.13.78 is link-local rather than global.
 */
static IdemIpIp6Scope ip6_select_scope(const uint8_t *addr)
{
    IdemIpIp6Type type = idemip_ip6_addr_type(addr);
    if (type == IDEMIP_IP6_TYPE_V4_MAPPED)
    {
        const uint8_t *v4 = addr + IDEMIP_IP6_V4_EMBED_OFF;
        if ((v4[0] == IP6_SELECT_V4_LINK_LOCAL_0 && v4[1] == IP6_SELECT_V4_LINK_LOCAL_1) ||
            v4[0] == IP6_SELECT_V4_LOOPBACK_0)
        {
            return IDEMIP_IP6_SCOPE_LINK_LOCAL;
        }
        return IDEMIP_IP6_SCOPE_GLOBAL;
    }
    return idemip_ip6_addr_scope_of(addr, type);
}

// RFC 6724 sec 6 Rule 9 compares two destinations only "When DA and DB belong to the same address
// family (both are IPv6 or both are IPv4)", and sec 3.2 makes an IPv4 address an IPv4-mapped one.
static idemip_bool ip6_select_is_v4(const uint8_t *addr)
{
    return (idemip_ip6_addr_type(addr) == IDEMIP_IP6_TYPE_V4_MAPPED) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

/**
 * RFC 6724 sec 2.2: "the length of the longest prefix (looking at the most significant, or leftmost,
 * bits) that the two addresses have in common, up to the length of S's prefix (i.e., the portion of
 * the address not including the interface ID). For example, CommonPrefixLen(fe80::1, fe80::2) is
 * 64." The cap is the 64-bit interface ID RFC 4291 sec 2.5.1 fixes.
 */
static uint8_t ip6_select_common_prefix(const uint8_t *s, const uint8_t *d)
{
    uint8_t n = 0u;
    for (size_t i = 0u; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        uint8_t x = (uint8_t)(s[i] ^ d[i]);
        if (x == 0u)
        {
            n = (uint8_t)(n + 8u);
            continue;
        }
        while ((uint8_t)(x & 0x80u) == 0u)
        {
            n = (uint8_t)(n + 1u);
            x = (uint8_t)(x << 1);
        }
        break;
    }
    return (n > IDEMIP_IP6_SELECT_COMMON_PREFIX_MAX) ? (uint8_t)IDEMIP_IP6_SELECT_COMMON_PREFIX_MAX : n;
}

/**
 * The longest matching row of the sec 2.1 table. sec 2.1 also qualifies a row by zone: "a prefix
 * table entry only matches against an address during a lookup if the zone index also matches the
 * address's zone index", which a row left at the default index does not ask for.
 */
static uint8_t ip6_select_policy_find(uint8_t *work, const uint8_t *addr, uint32_t zone)
{
    uint8_t best = IDEMIP_IP6_SELECT_NONE;
    uint8_t best_len = 0u;
    for (uint8_t i = 0u; i < IP6_SELECT_POLICIES; i++)
    {
        const Ip6SelectPolicy *row = IP6_SELECT_POLICY_AT(work, i);
        if (!row->used)
        {
            continue;
        }
        if (row->zone != IDEMIP_IP6_ZONE_DEFAULT && row->zone != zone)
        {
            continue;
        }
        if (!idemip_ip6_addr_prefix_eq(addr, row->prefix, row->prefix_len))
        {
            continue;
        }
        if (best == IDEMIP_IP6_SELECT_NONE || row->prefix_len > best_len)
        {
            best = i;
            best_len = row->prefix_len;
        }
    }
    return best;
}

// Precedence(A) of sec 2.1, and zero where no row matches.
static uint8_t ip6_select_precedence(uint8_t *work, const uint8_t *addr, uint32_t zone)
{
    uint8_t row = ip6_select_policy_find(work, addr, zone);
    return (row == IDEMIP_IP6_SELECT_NONE) ? 0u : IP6_SELECT_POLICY_AT(work, row)->precedence;
}

// Label(A) of sec 2.1. A row that matches nothing carries a label no row's label equals, so the two
// Rule 6 and Rule 5 comparisons that match labels never call an unlabeled pair equal.
static uint8_t ip6_select_label(uint8_t *work, const uint8_t *addr, uint32_t zone)
{
    uint8_t row = ip6_select_policy_find(work, addr, zone);
    return (row == IDEMIP_IP6_SELECT_NONE) ? IDEMIP_IP6_SELECT_NONE : IP6_SELECT_POLICY_AT(work, row)->label;
}

// RFC 4007 sec 5 re-uses a non-global address in different zones, so two equal addresses name the
// same interface only when their zones agree; sec 6 reserves index zero to "use the default zone",
// which matches whatever zone the other names.
static idemip_bool ip6_select_same_addr(const uint8_t *a, uint32_t a_zone, const uint8_t *b, uint32_t b_zone)
{
    if (!idemip_bytes_eq(a, b, IDEMIP_IP6_ADDR_LEN))
    {
        return IDEMIP_FALSE;
    }
    if (ip6_select_scope(a) == IDEMIP_IP6_SCOPE_GLOBAL)
    {
        return IDEMIP_TRUE;
    }
    return (a_zone == b_zone || a_zone == IDEMIP_IP6_ZONE_DEFAULT || b_zone == IDEMIP_IP6_ZONE_DEFAULT)
               ? IDEMIP_TRUE
               : IDEMIP_FALSE;
}

/**
 * RFC 6724 sec 4 narrows the candidate set before sec 5 orders it: "For all multicast and link-local
 * destination addresses, the set of candidate source addresses MUST only include addresses assigned
 * to interfaces belonging to the same link as the outgoing interface", and "For site-local unicast
 * destination addresses ... belonging to the same site as the outgoing interface".
 *
 * RFC 4007 sec 6's default assignment gives each interface its own link index, so the same link is
 * the same interface index. A site zone "must be defined and configured by network administrators"
 * (RFC 4007 sec 5), so the site test compares the zones the caller supplied and admits the pair when
 * either is the default index.
 *
 * The family test is sec 5's own bound: "This algorithm only applies to IPv6 destination addresses,
 * not IPv4 addresses", and sec 6 adds "Source address selection for IPv4 addresses is not specified
 * in this document". An IPv4 destination therefore takes an IPv4 source, which is what sec 10.2's
 * first example requires when it pairs 198.51.100.121 with 169.254.13.78 while a global IPv6
 * candidate is present; sec 3.2 makes both of them IPv4-mapped addresses here.
 */
static idemip_bool ip6_select_candidate_ok(const Ip6SelectSource *src, const uint8_t *d, uint32_t d_zone,
                                           uint8_t d_netif)
{
    if (ip6_select_is_v4(src->addr) != ip6_select_is_v4(d))
    {
        return IDEMIP_FALSE;
    }
    IdemIpIp6Type dtype = idemip_ip6_addr_type(d);
    if (dtype == IDEMIP_IP6_TYPE_MULTICAST || dtype == IDEMIP_IP6_TYPE_LINK_LOCAL)
    {
        return (src->netif == d_netif) ? IDEMIP_TRUE : IDEMIP_FALSE;
    }
    if (dtype == IDEMIP_IP6_TYPE_SITE_LOCAL)
    {
        return (d_zone == IDEMIP_IP6_ZONE_DEFAULT || src->zone == IDEMIP_IP6_ZONE_DEFAULT || src->zone == d_zone)
                   ? IDEMIP_TRUE
                   : IDEMIP_FALSE;
    }
    return IDEMIP_TRUE;
}

// --- RFC 6724 sec 5, the source rules --------------------------------------

/**
 * One pair-wise comparison of two candidates against destination D. Positive prefers SA, negative
 * prefers SB, zero is sec 5's "equal to", which the caller breaks by keeping the incumbent.
 *
 * sec 5 opens "a list of eight pair-wise comparison rules" and then numbers nine of them, Rule 5.5
 * sitting between Rule 5 and Rule 6; every one of them is applied here, in the printed order.
 */
static int ip6_select_cmp_source(uint8_t *work, uint8_t ia, uint8_t ib, const uint8_t *d, uint32_t d_zone,
                                 uint8_t d_netif, uint8_t *rule)
{
    const Ip6SelectSource *sa = IP6_SELECT_SOURCE_AT(work, ia);
    const Ip6SelectSource *sb = IP6_SELECT_SOURCE_AT(work, ib);

    // Rule 1: "If SA = D, then prefer SA. Similarly, if SB = D, then prefer SB."
    *rule = 1u;
    idemip_bool a_is_d = ip6_select_same_addr(sa->addr, sa->zone, d, d_zone);
    idemip_bool b_is_d = ip6_select_same_addr(sb->addr, sb->zone, d, d_zone);
    if (a_is_d != b_is_d)
    {
        return a_is_d ? 1 : -1;
    }

    // Rule 2: "If Scope(SA) < Scope(SB): If Scope(SA) < Scope(D), then prefer SB and otherwise
    // prefer SA."
    *rule = 2u;
    IdemIpIp6Scope as = ip6_select_scope(sa->addr);
    IdemIpIp6Scope bs = ip6_select_scope(sb->addr);
    IdemIpIp6Scope ds = ip6_select_scope(d);
    if (as < bs)
    {
        return (as < ds) ? -1 : 1;
    }
    if (bs < as)
    {
        return (bs < ds) ? 1 : -1;
    }

    // Rule 3: "If one of the two source addresses is 'preferred' and one of them is 'deprecated' (in
    // the RFC 4862 sense), then prefer the one that is 'preferred'."
    *rule = 3u;
    if (sa->deprecated != sb->deprecated)
    {
        return sa->deprecated ? -1 : 1;
    }

    // Rule 4: "If SA is simultaneously a home address and care-of address and SB is not, then prefer
    // SA ... If SA is just a home address and SB is just a care-of address, then prefer SA."
    *rule = 4u;
    idemip_bool a_both = (sa->home && sa->care_of) ? IDEMIP_TRUE : IDEMIP_FALSE;
    idemip_bool b_both = (sb->home && sb->care_of) ? IDEMIP_TRUE : IDEMIP_FALSE;
    if (a_both != b_both)
    {
        return a_both ? 1 : -1;
    }
    if (!a_both)
    {
        idemip_bool a_home = (sa->home && !sa->care_of) ? IDEMIP_TRUE : IDEMIP_FALSE;
        idemip_bool b_home = (sb->home && !sb->care_of) ? IDEMIP_TRUE : IDEMIP_FALSE;
        idemip_bool a_care = (sa->care_of && !sa->home) ? IDEMIP_TRUE : IDEMIP_FALSE;
        idemip_bool b_care = (sb->care_of && !sb->home) ? IDEMIP_TRUE : IDEMIP_FALSE;
        if (a_home && b_care)
        {
            return 1;
        }
        if (b_home && a_care)
        {
            return -1;
        }
    }

    // Rule 5: "If SA is assigned to the interface that will be used to send to D and SB is assigned
    // to a different interface, then prefer SA."
    *rule = 5u;
    idemip_bool a_out = (sa->netif == d_netif) ? IDEMIP_TRUE : IDEMIP_FALSE;
    idemip_bool b_out = (sb->netif == d_netif) ? IDEMIP_TRUE : IDEMIP_FALSE;
    if (a_out != b_out)
    {
        return a_out ? 1 : -1;
    }

    // Rule 5.5: "If SA or SA's prefix is assigned by the selected next-hop that will be used to send
    // to D and SB or SB's prefix is assigned by a different next-hop, then prefer SA." The RFC notes
    // it "is only applicable to implementations that track this information", which is why the flag
    // arrives with the candidate rather than being derived.
    *rule = IDEMIP_IP6_SELECT_RULE_5_5;
    if (sa->next_hop != sb->next_hop)
    {
        return sa->next_hop ? 1 : -1;
    }

    // Rule 6: "If Label(SA) = Label(D) and Label(SB) <> Label(D), then prefer SA."
    *rule = 6u;
    uint8_t dl = ip6_select_label(work, d, d_zone);
    idemip_bool a_label = (ip6_select_label(work, sa->addr, sa->zone) == dl) ? IDEMIP_TRUE : IDEMIP_FALSE;
    idemip_bool b_label = (ip6_select_label(work, sb->addr, sb->zone) == dl) ? IDEMIP_TRUE : IDEMIP_FALSE;
    if (a_label != b_label)
    {
        return a_label ? 1 : -1;
    }

    // Rule 7: "If SA is a temporary address and SB is a public address, then prefer SA."
    *rule = 7u;
    if (sa->temporary != sb->temporary)
    {
        return sa->temporary ? 1 : -1;
    }

    // Rule 8: "If CommonPrefixLen(SA, D) > CommonPrefixLen(SB, D), then prefer SA."
    *rule = 8u;
    uint8_t ac = ip6_select_common_prefix(sa->addr, d);
    uint8_t bc = ip6_select_common_prefix(sb->addr, d);
    if (ac != bc)
    {
        return (ac > bc) ? 1 : -1;
    }

    // sec 5: "If the eight rules fail to choose a single address, the tiebreaker is
    // implementation-specific." The incumbent keeps the place, so the order the caller added
    // candidates in decides, and the same borrow answers the same way every time.
    *rule = IDEMIP_IP6_SELECT_RULE_NONE;
    return 0;
}

// The front of the sorted candidate list, which sec 5 notes "an implementation need not actually
// sort the set; it need only identify the 'maximum' value". IDEMIP_IP6_SELECT_NONE when the
// candidate set has nothing sec 4 admits for this destination, which sec 6 calls Source(D)
// undefined.
static uint8_t ip6_select_best_source(uint8_t *work, const uint8_t *d, uint32_t d_zone, uint8_t d_netif,
                                      uint8_t *rule)
{
    uint8_t best = IDEMIP_IP6_SELECT_NONE;
    *rule = IDEMIP_IP6_SELECT_RULE_NONE;
    for (uint8_t i = 0u; i < IP6_SELECT_SOURCES; i++)
    {
        const Ip6SelectSource *src = IP6_SELECT_SOURCE_AT(work, i);
        if (!src->used || !ip6_select_candidate_ok(src, d, d_zone, d_netif))
        {
            continue;
        }
        if (best == IDEMIP_IP6_SELECT_NONE)
        {
            best = i;
            continue;
        }
        uint8_t why = IDEMIP_IP6_SELECT_RULE_NONE;
        int order = ip6_select_cmp_source(work, i, best, d, d_zone, d_netif, &why);
        if (order != 0)
        {
            *rule = why; // the rule that decided, whether it moved the front or held it
        }
        if (order > 0)
        {
            best = i;
        }
    }
    return best;
}

// --- RFC 6724 sec 6, the destination rules ---------------------------------

/**
 * One pair-wise comparison of two destinations, DA having appeared before DB in the original list.
 * Positive prefers DA. sec 6: "The pair-wise comparison of destination addresses consists of ten
 * rules, which MUST be applied in order."
 *
 * Rules 2 through 5 and Rule 9 all read Source(D), so a pair in which either side has none skips
 * past them to Rule 8; Rule 1 has already preferred the usable one whenever exactly one is usable.
 */
static int ip6_select_cmp_dest(uint8_t *work, uint8_t ia, uint8_t ib, uint8_t *rule)
{
    const Ip6SelectDest *da = IP6_SELECT_DEST_AT(work, ia);
    const Ip6SelectDest *db = IP6_SELECT_DEST_AT(work, ib);

    // Rule 1: "If DB is known to be unreachable or if Source(DB) is undefined, then prefer DA."
    *rule = 1u;
    idemip_bool a_bad = (da->unreachable || da->source == IDEMIP_IP6_SELECT_NONE) ? IDEMIP_TRUE : IDEMIP_FALSE;
    idemip_bool b_bad = (db->unreachable || db->source == IDEMIP_IP6_SELECT_NONE) ? IDEMIP_TRUE : IDEMIP_FALSE;
    if (a_bad != b_bad)
    {
        return a_bad ? -1 : 1;
    }

    // Rules 2 through 5 and Rule 9 read Source(DA) and Source(DB), which sec 6 makes inapplicable
    // only when "there is no source address available for destination D". The unreachable flag is
    // Rule 1's operand alone, and a tie there is broken by Rule 2 next: "If a rule determines a
    // result, then the remaining rules are not relevant and MUST be ignored."
    idemip_bool sourced =
        (da->source != IDEMIP_IP6_SELECT_NONE && db->source != IDEMIP_IP6_SELECT_NONE) ? IDEMIP_TRUE : IDEMIP_FALSE;
    if (sourced)
    {
        const Ip6SelectSource *sa = IP6_SELECT_SOURCE_AT(work, da->source);
        const Ip6SelectSource *sb = IP6_SELECT_SOURCE_AT(work, db->source);

        // Rule 2: "If Scope(DA) = Scope(Source(DA)) and Scope(DB) <> Scope(Source(DB)), then prefer
        // DA."
        *rule = 2u;
        idemip_bool a_match = (ip6_select_scope(da->addr) == ip6_select_scope(sa->addr)) ? IDEMIP_TRUE : IDEMIP_FALSE;
        idemip_bool b_match = (ip6_select_scope(db->addr) == ip6_select_scope(sb->addr)) ? IDEMIP_TRUE : IDEMIP_FALSE;
        if (a_match != b_match)
        {
            return a_match ? 1 : -1;
        }

        // Rule 3: "If Source(DA) is deprecated and Source(DB) is not, then prefer DB."
        *rule = 3u;
        if (sa->deprecated != sb->deprecated)
        {
            return sa->deprecated ? -1 : 1;
        }

        // Rule 4: "If Source(DA) is simultaneously a home address and care-of address and Source(DB)
        // is not, then prefer DA ... If Source(DA) is just a home address and Source(DB) is just a
        // care-of address, then prefer DA."
        *rule = 4u;
        idemip_bool a_both = (sa->home && sa->care_of) ? IDEMIP_TRUE : IDEMIP_FALSE;
        idemip_bool b_both = (sb->home && sb->care_of) ? IDEMIP_TRUE : IDEMIP_FALSE;
        if (a_both != b_both)
        {
            return a_both ? 1 : -1;
        }
        if (!a_both)
        {
            idemip_bool a_home = (sa->home && !sa->care_of) ? IDEMIP_TRUE : IDEMIP_FALSE;
            idemip_bool b_home = (sb->home && !sb->care_of) ? IDEMIP_TRUE : IDEMIP_FALSE;
            idemip_bool a_care = (sa->care_of && !sa->home) ? IDEMIP_TRUE : IDEMIP_FALSE;
            idemip_bool b_care = (sb->care_of && !sb->home) ? IDEMIP_TRUE : IDEMIP_FALSE;
            if (a_home && b_care)
            {
                return 1;
            }
            if (b_home && a_care)
            {
                return -1;
            }
        }

        // Rule 5: "If Label(Source(DA)) = Label(DA) and Label(Source(DB)) <> Label(DB), then prefer
        // DA."
        *rule = 5u;
        idemip_bool a_label = (ip6_select_label(work, sa->addr, sa->zone) ==
                               ip6_select_label(work, da->addr, da->zone))
                                  ? IDEMIP_TRUE
                                  : IDEMIP_FALSE;
        idemip_bool b_label = (ip6_select_label(work, sb->addr, sb->zone) ==
                               ip6_select_label(work, db->addr, db->zone))
                                  ? IDEMIP_TRUE
                                  : IDEMIP_FALSE;
        if (a_label != b_label)
        {
            return a_label ? 1 : -1;
        }
    }

    // Rule 6: "If Precedence(DA) > Precedence(DB), then prefer DA."
    *rule = 6u;
    uint8_t ap = ip6_select_precedence(work, da->addr, da->zone);
    uint8_t bp = ip6_select_precedence(work, db->addr, db->zone);
    if (ap != bp)
    {
        return (ap > bp) ? 1 : -1;
    }

    // Rule 7: "If DA is reached via an encapsulating transition mechanism (e.g., IPv6 in IPv4) and
    // DB is not, then prefer DB."
    *rule = 7u;
    if (da->encapsulated != db->encapsulated)
    {
        return da->encapsulated ? -1 : 1;
    }

    // Rule 8: "If Scope(DA) < Scope(DB), then prefer DA."
    *rule = 8u;
    IdemIpIp6Scope as = ip6_select_scope(da->addr);
    IdemIpIp6Scope bs = ip6_select_scope(db->addr);
    if (as != bs)
    {
        return (as < bs) ? 1 : -1;
    }

    // Rule 9: "When DA and DB belong to the same address family (both are IPv6 or both are IPv4):
    // If CommonPrefixLen(Source(DA), DA) > CommonPrefixLen(Source(DB), DB), then prefer DA."
    *rule = 9u;
    if (sourced && ip6_select_is_v4(da->addr) == ip6_select_is_v4(db->addr))
    {
        uint8_t ac = ip6_select_common_prefix(IP6_SELECT_SOURCE_AT(work, da->source)->addr, da->addr);
        uint8_t bc = ip6_select_common_prefix(IP6_SELECT_SOURCE_AT(work, db->source)->addr, db->addr);
        if (ac != bc)
        {
            return (ac > bc) ? 1 : -1;
        }
    }

    // Rule 10: "If DA preceded DB in the original list, prefer DA."
    *rule = 10u;
    return (ia < ib) ? 1 : -1;
}

// --- the entries -----------------------------------------------------------

// Loads the sec 2.1 default table, which the section makes the behavior of an unconfigured
// implementation: "If an implementation is not configurable or has not been configured, then it
// SHOULD operate according to the algorithms specified here in conjunction with the following
// default policy table".
void idemip_ip6_select_clear(uint8_t *work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP6_SELECT_OFF_CTX, 0, IP6_SELECT_STATE_BYTES);
    Ip6SelectCtx *ctx = IP6_SELECT_CTX(work);
    for (uint8_t i = 0u; i < (uint8_t)IDEMIP_IP6_SELECT_DEFAULT_POLICIES; i++)
    {
        Ip6SelectPolicy *row = IP6_SELECT_POLICY_AT(work, i);
        memcpy(row->prefix, ip6_select_default_policy[i].prefix, IDEMIP_IP6_ADDR_LEN);
        row->zone = IDEMIP_IP6_ZONE_DEFAULT;
        row->prefix_len = ip6_select_default_policy[i].prefix_len;
        row->precedence = ip6_select_default_policy[i].precedence;
        row->label = ip6_select_default_policy[i].label;
        row->used = IDEMIP_TRUE;
    }
    ctx->policies = (uint8_t)IDEMIP_IP6_SELECT_DEFAULT_POLICIES;
    ctx->ready = IDEMIP_TRUE;
    Ip6SelectIo *io = IP6_SELECT_IO(work);
    io->status = IDEMIP_OK;
    io->policies = ctx->policies;
    io->sources = 0u;
    io->dests = 0u;
    io->sorted = IDEMIP_FALSE;
}

// A row whose prefix and length already sit in the table is overwritten, so a caller reconfigures
// one of sec 2.1's defaults rather than adding a second row that shadows it. A table with no free
// row is ERR: nothing frees one on a later tick, so the same call would fail the same way.
void idemip_ip6_select_policy_set(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6SelectIo *io = IP6_SELECT_IO(work);
    Ip6SelectCtx *ctx = IP6_SELECT_CTX(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_IP6_SELECT_NONE;
    const uint8_t *prefix = io->policy_args.prefix;
    if (!ctx->ready || prefix == NULL || io->policy_args.prefix_len > IDEMIP_IP6_ADDR_BITS)
    {
        return;
    }
    uint8_t slot = IDEMIP_IP6_SELECT_NONE;
    for (uint8_t i = 0u; i < IP6_SELECT_POLICIES; i++)
    {
        const Ip6SelectPolicy *row = IP6_SELECT_POLICY_AT(work, i);
        if (row->used && row->prefix_len == io->policy_args.prefix_len && row->zone == io->policy_args.zone &&
            idemip_bytes_eq(row->prefix, prefix, IDEMIP_IP6_ADDR_LEN))
        {
            slot = i;
            break;
        }
        if (!row->used && slot == IDEMIP_IP6_SELECT_NONE)
        {
            slot = i;
        }
    }
    if (slot == IDEMIP_IP6_SELECT_NONE)
    {
        return;
    }
    Ip6SelectPolicy *row = IP6_SELECT_POLICY_AT(work, slot);
    if (!row->used)
    {
        ctx->policies = (uint8_t)(ctx->policies + 1u);
    }
    memcpy(row->prefix, prefix, IDEMIP_IP6_ADDR_LEN);
    row->zone = io->policy_args.zone;
    row->prefix_len = io->policy_args.prefix_len;
    row->precedence = io->policy_args.precedence;
    row->label = io->policy_args.label;
    row->used = IDEMIP_TRUE;
    io->index = slot;
    io->policies = ctx->policies;
    io->status = IDEMIP_OK;
}

void idemip_ip6_select_policy_lookup(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6SelectIo *io = IP6_SELECT_IO(work);
    io->status = IDEMIP_ERR;
    io->found = IDEMIP_FALSE;
    io->index = IDEMIP_IP6_SELECT_NONE;
    io->precedence = 0u;
    io->label = IDEMIP_IP6_SELECT_NONE;
    io->prefix_len = 0u;
    const uint8_t *addr = io->query_args.addr;
    if (!IP6_SELECT_CTX(work)->ready || addr == NULL)
    {
        return;
    }
    uint8_t row = ip6_select_policy_find(work, addr, io->query_args.zone);
    if (row != IDEMIP_IP6_SELECT_NONE)
    {
        const Ip6SelectPolicy *p = IP6_SELECT_POLICY_AT(work, row);
        io->found = IDEMIP_TRUE;
        io->index = row;
        io->precedence = p->precedence;
        io->label = p->label;
        io->prefix_len = p->prefix_len;
    }
    io->status = IDEMIP_OK;
}

void idemip_ip6_select_scope_of(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6SelectIo *io = IP6_SELECT_IO(work);
    io->status = IDEMIP_ERR;
    io->scope = IDEMIP_IP6_SCOPE_RESERVED;
    const uint8_t *addr = io->query_args.addr;
    if (!IP6_SELECT_CTX(work)->ready || addr == NULL)
    {
        return;
    }
    io->scope = ip6_select_scope(addr);
    io->status = IDEMIP_OK;
}

void idemip_ip6_select_common_prefix_entry(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6SelectIo *io = IP6_SELECT_IO(work);
    io->status = IDEMIP_ERR;
    io->common = 0u;
    if (!IP6_SELECT_CTX(work)->ready || io->query_args.addr == NULL || io->query_args.peer == NULL)
    {
        return;
    }
    io->common = ip6_select_common_prefix(io->query_args.addr, io->query_args.peer);
    io->status = IDEMIP_OK;
}

// RFC 6724 sec 4: "In any case, multicast addresses and the unspecified address MUST NOT be included
// in a candidate set." Both are ERR, since no later call makes either eligible. A full candidate set
// is ERR for the same reason: only clear empties it.
void idemip_ip6_select_source_add(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6SelectIo *io = IP6_SELECT_IO(work);
    Ip6SelectCtx *ctx = IP6_SELECT_CTX(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_IP6_SELECT_NONE;
    const uint8_t *addr = io->source_args.addr;
    if (!ctx->ready || addr == NULL || ctx->sources >= IP6_SELECT_SOURCES)
    {
        return;
    }
    IdemIpIp6Type type = idemip_ip6_addr_type(addr);
    if (type == IDEMIP_IP6_TYPE_MULTICAST || type == IDEMIP_IP6_TYPE_UNSPECIFIED)
    {
        return;
    }
    Ip6SelectSource *src = IP6_SELECT_SOURCE_AT(work, ctx->sources);
    memcpy(src->addr, addr, IDEMIP_IP6_ADDR_LEN);
    src->zone = io->source_args.zone;
    src->netif = io->source_args.netif;
    src->deprecated = io->source_args.deprecated;
    src->temporary = io->source_args.temporary;
    src->home = io->source_args.home;
    src->care_of = io->source_args.care_of;
    src->next_hop = io->source_args.next_hop;
    src->used = IDEMIP_TRUE;
    io->index = ctx->sources;
    ctx->sources = (uint8_t)(ctx->sources + 1u);
    ctx->sorted = IDEMIP_FALSE;
    io->sources = ctx->sources;
    io->sorted = IDEMIP_FALSE;
    io->status = IDEMIP_OK;
}

// The list keeps the order it was added in, which is the "original list" sec 6 Rule 10 falls back
// to. A full list is ERR: only clear empties it.
void idemip_ip6_select_dest_add(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6SelectIo *io = IP6_SELECT_IO(work);
    Ip6SelectCtx *ctx = IP6_SELECT_CTX(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_IP6_SELECT_NONE;
    const uint8_t *addr = io->dest_args.addr;
    if (!ctx->ready || addr == NULL || ctx->dests >= IP6_SELECT_DESTS)
    {
        return;
    }
    Ip6SelectDest *dst = IP6_SELECT_DEST_AT(work, ctx->dests);
    memcpy(dst->addr, addr, IDEMIP_IP6_ADDR_LEN);
    dst->zone = io->dest_args.zone;
    dst->netif = io->dest_args.netif;
    dst->source = IDEMIP_IP6_SELECT_NONE;
    dst->unreachable = io->dest_args.unreachable;
    dst->encapsulated = io->dest_args.encapsulated;
    dst->used = IDEMIP_TRUE;
    io->index = ctx->dests;
    ctx->dests = (uint8_t)(ctx->dests + 1u);
    ctx->sorted = IDEMIP_FALSE;
    io->dests = ctx->dests;
    io->sorted = IDEMIP_FALSE;
    io->status = IDEMIP_OK;
}

// A destination with no eligible candidate is sec 6's "Source(D) is undefined", which is an answer
// rather than a fault: the call reports OK with found clear.
void idemip_ip6_select_source_select(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6SelectIo *io = IP6_SELECT_IO(work);
    io->status = IDEMIP_ERR;
    io->found = IDEMIP_FALSE;
    io->source = NULL;
    io->source_zone = IDEMIP_IP6_ZONE_DEFAULT;
    io->index = IDEMIP_IP6_SELECT_NONE;
    io->rule = IDEMIP_IP6_SELECT_RULE_NONE;
    io->netif = 0u;
    const uint8_t *d = io->query_args.addr;
    if (!IP6_SELECT_CTX(work)->ready || d == NULL)
    {
        return;
    }
    uint8_t rule = IDEMIP_IP6_SELECT_RULE_NONE;
    uint8_t best = ip6_select_best_source(work, d, io->query_args.zone, io->query_args.netif, &rule);
    if (best != IDEMIP_IP6_SELECT_NONE)
    {
        const Ip6SelectSource *src = IP6_SELECT_SOURCE_AT(work, best);
        io->found = IDEMIP_TRUE;
        io->index = best;
        io->source = src->addr;
        io->source_zone = src->zone;
        io->netif = src->netif;
        io->rule = rule;
    }
    io->status = IDEMIP_OK;
}

// sec 6 runs the source algorithm per destination first, then orders the list. A selection sort over
// the order region walks a fixed count of pairs and moves no entry, so the destinations keep the
// original positions Rule 10 compares.
void idemip_ip6_select_dest_sort(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6SelectIo *io = IP6_SELECT_IO(work);
    Ip6SelectCtx *ctx = IP6_SELECT_CTX(work);
    io->status = IDEMIP_ERR;
    io->sorted = IDEMIP_FALSE;
    if (!ctx->ready)
    {
        return;
    }
    uint8_t *order = IP6_SELECT_ORDER(work);
    for (uint8_t i = 0u; i < ctx->dests; i++)
    {
        Ip6SelectDest *dst = IP6_SELECT_DEST_AT(work, i);
        uint8_t rule = IDEMIP_IP6_SELECT_RULE_NONE;
        dst->source = ip6_select_best_source(work, dst->addr, dst->zone, dst->netif, &rule);
        order[i] = i;
    }
    for (uint8_t i = 0u; i < ctx->dests; i++)
    {
        uint8_t best = i;
        for (uint8_t j = (uint8_t)(i + 1u); j < ctx->dests; j++)
        {
            uint8_t rule = IDEMIP_IP6_SELECT_RULE_NONE;
            if (ip6_select_cmp_dest(work, order[j], order[best], &rule) > 0)
            {
                best = j;
            }
        }
        uint8_t swap = order[i];
        order[i] = order[best];
        order[best] = swap;
    }
    ctx->sorted = IDEMIP_TRUE;
    io->dests = ctx->dests;
    io->sorted = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

// Reads one place of the sorted list. A list no sort has run over, and a place past its end, are
// both ERR: neither becomes readable on a later tick without a call the caller makes.
void idemip_ip6_select_dest_at(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6SelectIo *io = IP6_SELECT_IO(work);
    const Ip6SelectCtx *ctx = IP6_SELECT_CTX(work);
    io->status = IDEMIP_ERR;
    io->dest = NULL;
    io->source = NULL;
    io->dest_zone = IDEMIP_IP6_ZONE_DEFAULT;
    io->source_zone = IDEMIP_IP6_ZONE_DEFAULT;
    io->index = IDEMIP_IP6_SELECT_NONE;
    io->found = IDEMIP_FALSE;
    if (!ctx->ready || !ctx->sorted || io->query_args.index >= ctx->dests)
    {
        return;
    }
    uint8_t which = IP6_SELECT_ORDER(work)[io->query_args.index];
    const Ip6SelectDest *dst = IP6_SELECT_DEST_AT(work, which);
    io->index = which;
    io->dest = dst->addr;
    io->dest_zone = dst->zone;
    io->netif = dst->netif;
    if (dst->source != IDEMIP_IP6_SELECT_NONE)
    {
        const Ip6SelectSource *src = IP6_SELECT_SOURCE_AT(work, dst->source);
        io->source = src->addr;
        io->source_zone = src->zone;
        io->found = IDEMIP_TRUE;
    }
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
