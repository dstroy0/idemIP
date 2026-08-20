// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_route.c
 * @brief The rows of the RFC 1122 sec 3.3.1 routing table.
 *
 * The row type is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block, the context and the table are regions of that borrow, at compile-time offsets, and no entry
 * reads or writes a byte outside it.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip4_route.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and every
// entry refuses it.
#define IP4_ROUTE_READY 0x52543400u

// Every bit of the destination is significant, so RFC 1122 sec 3.3.1.3 field (2) is "the full IP
// address of the destination host".
#define IP4_ROUTE_MASK_HOST 0xFFFFFFFFu

// RFC 1812 sec 5.2.4.3 rule 3 fills route.tos from routing protocols that distribute it, and treats
// "routes from other routing protocols ... as if they have the default TOS (0000)". A Redirect and a
// Datagram Too Big carry no TOS, so the rows they build key on this.
#define IP4_ROUTE_TOS_DEFAULT 0u

// One row: the four fields RFC 1122 sec 3.3.1.3 names, the mask sec 3.3.1.1 compares against, the
// flags and metric, and the RFC 1191 sec 6.3 path MTU with the millisecond it was stamped. Padded to
// 1 << IDEMIP_IP4_ROUTE_ENTRY_SHIFT so row i sits at (i << IDEMIP_IP4_ROUTE_ENTRY_SHIFT).
typedef struct
{
    uint32_t dst;
    uint32_t mask;
    uint32_t gw;
    uint32_t pmtu_ms;
    uint16_t pmtu;
    uint16_t metric;
    uint8_t netif;
    uint8_t tos;
    uint8_t flags;
    uint8_t state;
    uint8_t plen; ///< RFC 1812 sec 5.2.4.3's route.length, taken from the mask when the row is written
    uint8_t reserved[7];
} Ip4RouteEntry;

// The context: the mark, and the millisecond of the last aging sweep.
typedef struct
{
    uint32_t ready;
    uint32_t tick_ms;
} Ip4RouteCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_IP4_ROUTE_OFF_CTX, sizeof(Ip4RouteCtx), IDEMIP_IP4_ROUTE_OFF_TAB, "ip4_route's context");

// Row i is at (i << SHIFT), so the width has to be exactly the shift.
static_assert(sizeof(Ip4RouteEntry) == (1u << IDEMIP_IP4_ROUTE_ENTRY_SHIFT),
              "an Ip4RouteEntry must be exactly 1 << IDEMIP_IP4_ROUTE_ENTRY_SHIFT wide - pad it, or raise the shift");

// The head region carries the operand block and the context, both outside the table.
static_assert(IDEMIP_IP4_ROUTE_OFF_CTX + sizeof(Ip4RouteCtx) <= IDEMIP_IP4_ROUTE_CTX_BYTES,
              "IDEMIP_IP4_ROUTE_CTX_BYTES is short of the operand block and the context - raise it in "
              "idemip_config.h");

// The caller's borrow, split: the head region, then the rows. ip4_route.h publishes the offsets; the
// assert proves the span covers them before anything runs.
static_assert(IDEMIP_IP4_ROUTE_OFF_TAB + (IDEMIP_IP4_ROUTES << IDEMIP_IP4_ROUTE_ENTRY_SHIFT) <=
                  IDEMIP_IP4_ROUTE_BORROW,
              "IDEMIP_IP4_ROUTE_BORROW is short of the head region and the table - raise it in idemip_config.h");

// clear zeroes the table, so the empty row is the zero state.
static_assert(IDEMIP_IP4_ROUTE_FREE == 0, "IDEMIP_IP4_ROUTE_FREE must be zero: clear zeroes the table");

// A pmtu of zero is RFC 1191 sec 6.3's "reserved" timestamp value, "indicating that the PMTU has
// never been changed", and every legal estimate is at or above the RFC 791 sec 3.2 minimum.
static_assert(IDEMIP_IP4_MIN_FORWARD_MTU > 0u, "a pmtu of zero must not be a legal estimate: it marks an unset row");

// The regions, at their offsets in the caller's borrow.
#define IP4_ROUTE_IO(w) IDEMIP_IP4_ROUTE_IO(w)
#define IP4_ROUTE_CTX(w) ((Ip4RouteCtx *)(void *)((w) + IDEMIP_IP4_ROUTE_OFF_CTX))
#define IP4_ROUTE_AT(w, i)                                                                                             \
    ((Ip4RouteEntry *)(void *)((w) + IDEMIP_IP4_ROUTE_OFF_TAB + ((size_t)(i) << IDEMIP_IP4_ROUTE_ENTRY_SHIFT)))

// A borrow clear has not run on carries no table, so every entry but clear refuses it.
static idemip_bool ip4_route_ready(uint8_t *restrict work)
{
    return (idemip_bool)(IP4_ROUTE_CTX(work)->ready == IP4_ROUTE_READY);
}

// --- the row helpers -------------------------------------------------------

// RFC 1122 sec 3.3.1.1 (a): the mask "selects the network number and subnet number fields", and RFC
// 1812 sec 5.2.4.3 rule 1 reads it as "the most significant route.length bits", so the set bits run
// from bit 31 down with no gap. A route whose mask has a hole has no route.length to match on and is
// refused. ipv4.h holds the test, and held it while this unit carried its own copy of the same
// arithmetic.
static idemip_bool ip4_route_mask_ok(uint32_t mask)
{
    return idemip_ip4_addr_mask_contiguous(mask);
}

// route.length of RFC 1812 sec 5.2.4.3, taken once when a row is written rather than on every pass
// that reads it. The lookup makes four passes over the table and each needs this for every row it
// looks at, so the row carrying it turns 4N population counts per lookup into none.
static uint8_t ip4_route_prefix_len(uint32_t mask)
{
    return idemip_ip4_addr_mask_ones(mask);
}

// The row carrying exactly these four RFC 1122 sec 3.3.1.3 fields, or the terminator. Field (4) is
// part of the key because sec 3.3.1.2 states "The IP layer MUST support multiple default gateways",
// and two default gateways differ in nothing else.
static uint8_t ip4_route_find_key(uint8_t *restrict work, uint32_t dst, uint32_t mask, uint8_t tos, uint32_t gw)
{
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_IP4_ROUTES; i++)
    {
        Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
        if (e->state == IDEMIP_IP4_ROUTE_USED && e->mask == mask && e->dst == (dst & mask) && e->tos == tos &&
            e->gw == gw)
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
}

// The lowest row holding no route, or the terminator.
static uint8_t ip4_route_find_free(uint8_t *restrict work)
{
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_IP4_ROUTES; i++)
    {
        if (IP4_ROUTE_AT(work, i)->state != IDEMIP_IP4_ROUTE_USED)
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
}

// RFC 1812 sec 5.2.4.3 rule 1, Basic Match: the row keeps the destination when "the most significant
// route.length bits of route.dest and ip.dest are equal", which the stored mask extracts.
static idemip_bool ip4_route_basic_match(const Ip4RouteEntry *e, uint32_t dst)
{
    return (idemip_bool)(e->state == IDEMIP_IP4_ROUTE_USED && (dst & e->mask) == e->dst);
}

// What rule 2 left, for RFC 1812 sec 4.3.3.1's split between Code 0 and Codes 11 and 12: whether any
// row basic-matched the destination at all, and whether any of those transmits directly.
typedef struct
{
    idemip_bool matched;
    idemip_bool direct;
} Ip4RouteBest;

// The four pruning rules of RFC 1812 sec 5.2.4.3, in the order the section prints them, over the
// whole table: rule 1 Basic Match and rule 2 Longest Match fix the prefix length, rule 3 Weak TOS
// picks the type of service inside that length, rule 4 Best Metric picks among what is left. Rule 5
// Vendor Policy is the lowest surviving row.
static uint8_t ip4_route_best(uint8_t *restrict work, uint32_t dst, uint8_t tos, Ip4RouteBest *out)
{
    // Rules 1 and 2: the largest route.length among the rows that basic-match.
    uint8_t best_len = 0;
    idemip_bool matched = IDEMIP_FALSE;
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_IP4_ROUTES; i++)
    {
        Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
        if (!ip4_route_basic_match(e, dst))
        {
            continue;
        }
        uint8_t len = e->plen;
        if (!matched || len > best_len)
        {
            best_len = len;
            matched = IDEMIP_TRUE;
        }
    }
    if (out)
    {
        out->matched = matched;
        out->direct = IDEMIP_FALSE;
    }
    if (!matched)
    {
        return (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    }

    // Rule 3: "if it contains any routes for which route.tos = ip.tos ... all routes except those
    // for which route.tos = ip.tos are discarded. If not, all routes except those for which
    // route.tos = 0000 are discarded", applied to what rule 2 left.
    idemip_bool exact = IDEMIP_FALSE;
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_IP4_ROUTES; i++)
    {
        Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
        if (ip4_route_basic_match(e, dst) && e->plen == best_len && e->tos == tos)
        {
            exact = IDEMIP_TRUE;
        }
    }
    uint8_t want = exact ? tos : (uint8_t)IP4_ROUTE_TOS_DEFAULT;

    // Rule 4: "if ... route.metric is strictly inferior for one when compared with the other, then
    // the one with the inferior metric is discarded", the larger metric being the inferior one.
    uint8_t best = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    uint16_t best_metric = 0;
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_IP4_ROUTES; i++)
    {
        Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
        if (!ip4_route_basic_match(e, dst) || e->plen != best_len || e->tos != want)
        {
            continue;
        }
        if (best == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE || e->metric < best_metric)
        {
            best = i;
            best_metric = e->metric;
        }
    }
    // sec 4.3.3.1 splits the two unreachable codes on whether the destination is "on a network that
    // is directly connected to the router", which the rows rule 2 left are what says.
    if (out)
    {
        for (uint8_t i = 0; i < (uint8_t)IDEMIP_IP4_ROUTES; i++)
        {
            Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
            if (ip4_route_basic_match(e, dst) && e->plen == best_len &&
                (e->flags & (uint8_t)IDEMIP_IP4_ROUTE_F_GATEWAY) == 0u)
            {
                out->direct = IDEMIP_TRUE;
            }
        }
    }
    return best;
}

// A row built from the row that routes the destination today: RFC 1191 sec 6.2 creates a per-host
// route "almost as if a per-host ICMP Redirect is being processed; the new route uses the same
// first-hop router as the current route". The path is new, so it carries no MTU estimate yet.
static void ip4_route_derive_host(Ip4RouteEntry *e, const Ip4RouteEntry *from, uint32_t dst)
{
    e->dst = dst;
    e->mask = IP4_ROUTE_MASK_HOST;
    e->plen = ip4_route_prefix_len(IP4_ROUTE_MASK_HOST);
    e->gw = from->gw;
    e->pmtu_ms = 0;
    e->pmtu = 0;
    e->metric = from->metric;
    e->netif = from->netif;
    e->tos = (uint8_t)IP4_ROUTE_TOS_DEFAULT;
    e->flags = (uint8_t)((from->flags & (uint8_t)IDEMIP_IP4_ROUTE_F_GATEWAY) | (uint8_t)IDEMIP_IP4_ROUTE_F_HOST);
    e->state = (uint8_t)IDEMIP_IP4_ROUTE_USED;
}

// --- the entries -----------------------------------------------------------

// The context and the table, zeroed, then the mark. The operand block is the caller's and is left as
// it stands.
void idemip_ip4_route_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP4_ROUTE_OFF_CTX, 0,
           (size_t)IDEMIP_IP4_ROUTE_BORROW - (size_t)IDEMIP_IP4_ROUTE_OFF_CTX);
    IP4_ROUTE_CTX(work)->ready = IP4_ROUTE_READY;
    IP4_ROUTE_IO(work)->status = IDEMIP_OK;
}

// One row of RFC 1122 sec 3.3.1.3: field (1) the interface, field (2) the destination and the sec
// 3.3.1.1 (a) mask that selects it, field (3) the type of service, field (4) the next-hop gateway,
// plus the sec 3.3.1.2 static and overridable flags. A row carrying the same destination, mask, type
// of service and gateway is rewritten in place, so the table holds one route per key. A full table is
// BUSY: a remove frees a row. A mask with a gap, or a gateway route naming no gateway, is ERR: the
// same operands can never be written.
void idemip_ip4_route_add(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    uint32_t mask = io->add_args.mask;
    if (!ip4_route_mask_ok(mask))
    {
        return;
    }
    if ((io->add_args.flags & (uint8_t)IDEMIP_IP4_ROUTE_F_GATEWAY) != 0u && io->add_args.gw == 0u)
    {
        return;
    }
    uint32_t dst = io->add_args.dst & mask;
    uint8_t i = ip4_route_find_key(work, dst, mask, io->add_args.tos, io->add_args.gw);
    if (i == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE)
    {
        i = ip4_route_find_free(work);
    }
    if (i == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE)
    {
        io->status = IDEMIP_BUSY; // every row is taken, and a remove frees one
        return;
    }

    Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
    e->dst = dst;
    e->mask = mask;
    e->plen = ip4_route_prefix_len(mask);
    e->gw = io->add_args.gw;
    e->pmtu_ms = 0;
    e->pmtu = 0;
    e->metric = io->add_args.metric;
    e->netif = io->add_args.netif;
    e->tos = io->add_args.tos;
    // IDEMIP_IP4_ROUTE_F_HOST follows the mask: sec 3.3.1.3 field (2) is "the full IP address of the
    // destination host" exactly when every bit is significant.
    e->flags = (uint8_t)(io->add_args.flags & ~(uint8_t)IDEMIP_IP4_ROUTE_F_HOST);
    if (mask == IP4_ROUTE_MASK_HOST)
    {
        e->flags = (uint8_t)(e->flags | (uint8_t)IDEMIP_IP4_ROUTE_F_HOST);
    }
    e->state = (uint8_t)IDEMIP_IP4_ROUTE_USED;

    io->index = i;
    io->netif = e->netif;
    io->status = IDEMIP_OK;
}

// The rows holding this destination and mask go back to FREE, whatever type of service each carries,
// since RemoveArgs names no type of service. RFC 1191 sec 6.3: "PMTU estimates may disappear from the
// routing table if the per-host routes are removed", so the estimate goes with the row. A destination
// and mask no row holds is ERR: the table cannot grow that row on its own.
void idemip_ip4_route_remove(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    uint32_t mask = io->remove_args.mask;
    uint32_t dst = io->remove_args.dst & mask;
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_IP4_ROUTES; i++)
    {
        Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
        if (e->state != IDEMIP_IP4_ROUTE_USED || e->mask != mask || e->dst != dst)
        {
            continue;
        }
        memset(e, 0, sizeof *e);
        if (io->index == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE)
        {
            io->index = i;
        }
        io->status = IDEMIP_OK;
    }
}

// RFC 1122 sec 3.3.1.1's local/remote decision, then sec 3.3.1.2's gateway selection, over the RFC
// 1812 sec 5.2.4.3 pruning rules. A row without IDEMIP_IP4_ROUTE_F_GATEWAY is case (b), "the datagram
// is to be transmitted directly to the destination host", so the next hop is the destination itself;
// with it, case (c) sends to field (4). No row matching and no default gateway is BUSY: sec 3.3.1.2
// builds rows as datagrams flow, and an added route or a Redirect makes the same lookup succeed.
void idemip_ip4_route_lookup(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->next_hop = 0;
    io->pmtu = 0;
    io->netif = 0;
    io->direct = IDEMIP_FALSE;
    io->tos_blocked = IDEMIP_FALSE;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    Ip4RouteBest best = {IDEMIP_FALSE, IDEMIP_FALSE};
    uint8_t i = ip4_route_best(work, io->lookup_args.dst, io->lookup_args.tos, &best);
    if (i == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE)
    {
        // RFC 1812 sec 4.3.3.1 separates "no routes at all (including no default route)" from "the
        // router does have routes to the destination network specified in the packet but the TOS
        // specified for the routes is neither the default TOS (0000) nor the TOS of the packet".
        io->tos_blocked = best.matched;
        io->direct = best.direct;
        io->status = IDEMIP_BUSY;
        return;
    }

    Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
    io->index = i;
    io->netif = e->netif;
    io->pmtu = e->pmtu;
    io->direct = (idemip_bool)((e->flags & (uint8_t)IDEMIP_IP4_ROUTE_F_GATEWAY) == 0u);
    io->next_hop = io->direct ? io->lookup_args.dst : e->gw;
    io->status = IDEMIP_OK;
}

// RFC 1122 sec 3.3.1.2 (c): "the host updates the next-hop gateway in the appropriate route cache
// entry", and a Network Redirect is treated as a Host Redirect, so the row written is the one keyed on
// the full destination address, "created, if an entry for that host did not exist". The row the
// destination routes through today is the one the Redirect answers, and it is rewritten when it
// already keys on the whole address. sec 3.2.2.2 discards a Redirect "if the new gateway address it
// specifies is not on the same connected (sub-)net", which here is the gateway resolving to a row that
// transmits directly. RFC 1191 sec 6.3 drops the cached estimate with the path: "notify the
// packetization layer of a possible PMTU change whenever a Redirect message causes a route change".
//
// A gateway of zero, a gateway off every connected net, and a route sec 3.3.1.2 flagged static without
// flagging it overridable are all ERR: the same Redirect can never be applied. A table with no row for
// the destination, or no free row to create one in, is BUSY.
void idemip_ip4_route_redirect(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    uint32_t gw = io->redirect_args.gw;
    if (gw == 0u)
    {
        return;
    }
    uint8_t g = ip4_route_best(work, gw, (uint8_t)IP4_ROUTE_TOS_DEFAULT, NULL);
    if (g == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE ||
        (IP4_ROUTE_AT(work, g)->flags & (uint8_t)IDEMIP_IP4_ROUTE_F_GATEWAY) != 0u)
    {
        return;
    }

    uint32_t dst = io->redirect_args.dst;
    uint8_t cur = ip4_route_best(work, dst, (uint8_t)IP4_ROUTE_TOS_DEFAULT, NULL);
    if (cur == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE)
    {
        io->status = IDEMIP_BUSY; // nothing routes the destination yet, and an added route does
        return;
    }
    Ip4RouteEntry *c = IP4_ROUTE_AT(work, cur);
    if ((c->flags & (uint8_t)IDEMIP_IP4_ROUTE_F_STATIC) != 0u &&
        (c->flags & (uint8_t)IDEMIP_IP4_ROUTE_F_REDIRECT_OK) == 0u)
    {
        return;
    }

    uint8_t i = cur;
    if (c->mask != IP4_ROUTE_MASK_HOST)
    {
        uint8_t n = ip4_route_find_free(work);
        if (n == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE)
        {
            io->status = IDEMIP_BUSY; // every row is taken, and a remove frees one
            return;
        }
        ip4_route_derive_host(IP4_ROUTE_AT(work, n), c, dst);
        i = n;
    }

    Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
    e->gw = gw;
    e->flags = (uint8_t)(e->flags | (uint8_t)IDEMIP_IP4_ROUTE_F_GATEWAY);
    e->pmtu = 0;
    e->pmtu_ms = 0;
    io->index = i;
    io->netif = e->netif;
    io->status = IDEMIP_OK;
}

// RFC 1191 sec 6.2: "If a per-host route for this path does not exist, then one is created ... If the
// PMTU estimate associated with the per-host route is higher than the new estimate, then the value in
// the routing entry is changed", and sec 6.3 stamps it: "Whenever the PMTU is decreased in response
// to a Datagram Too Big message, the timestamp is set to the current time". Only the per-host row is
// written, sec 6.2 holding that the estimates on per-network and default rows "must never be changed
// by the PMTU Discovery process".
//
// An estimate below the RFC 791 sec 3.2 minimum is ERR: sec 4 states the field "will never contain a
// value less than 68". No row routing the destination, and no free row to hold the per-host route,
// are BUSY.
void idemip_ip4_route_set_pmtu(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->pmtu = 0;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    if (io->pmtu_args.mtu < IDEMIP_IP4_MIN_FORWARD_MTU)
    {
        return;
    }

    uint32_t dst = io->pmtu_args.dst;
    uint8_t cur = ip4_route_best(work, dst, (uint8_t)IP4_ROUTE_TOS_DEFAULT, NULL);
    if (cur == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE)
    {
        io->status = IDEMIP_BUSY; // no first hop to copy, and an added route supplies one
        return;
    }
    uint8_t i = cur;
    if (IP4_ROUTE_AT(work, cur)->mask != IP4_ROUTE_MASK_HOST)
    {
        uint8_t n = ip4_route_find_free(work);
        if (n == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE)
        {
            io->status = IDEMIP_BUSY; // every row is taken, and a remove frees one
            return;
        }
        ip4_route_derive_host(IP4_ROUTE_AT(work, n), IP4_ROUTE_AT(work, cur), dst);
        i = n;
    }

    Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
    if (e->pmtu == 0u || io->pmtu_args.mtu < e->pmtu)
    {
        e->pmtu = io->pmtu_args.mtu;
        e->pmtu_ms = io->now_ms;
    }
    io->pmtu = e->pmtu;
    io->index = i;
    io->netif = e->netif;
    io->status = IDEMIP_OK;
}

// RFC 1191 sec 6.3: "Once a minute, a timer-driven procedure runs through the routing table, and for
// each entry whose timestamp is not 'reserved' and is older than the timeout interval: the PMTU
// estimate is set to the MTU of the associated first hop." A row carrying no estimate reports the
// first-hop MTU to its caller, so clearing the estimate is that assignment. A sweep that is not due
// is BUSY: the next tick past the period runs it.
void idemip_ip4_route_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    Ip4RouteCtx *ctx = IP4_ROUTE_CTX(work);
    if ((uint32_t)(io->now_ms - ctx->tick_ms) < (uint32_t)IDEMIP_IP4_ROUTE_PMTU_SWEEP_MS)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    ctx->tick_ms = io->now_ms;

    for (uint8_t i = 0; i < (uint8_t)IDEMIP_IP4_ROUTES; i++)
    {
        Ip4RouteEntry *e = IP4_ROUTE_AT(work, i);
        if (e->state != IDEMIP_IP4_ROUTE_USED || e->pmtu == 0u)
        {
            continue;
        }
        if ((uint32_t)(io->now_ms - e->pmtu_ms) < (uint32_t)IDEMIP_IP4_ROUTE_PMTU_TIMEOUT_MS)
        {
            continue;
        }
        e->pmtu = 0;
        e->pmtu_ms = 0;
        if (io->index == (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE)
        {
            io->index = i;
        }
    }
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
