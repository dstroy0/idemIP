// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file nd6.c
 * @brief The four RFC 4861 sec 5.1 structures and the queued-frame table, in the caller's borrow.
 *
 * Every entry is a function of the one pointer it is handed: the operand block, the context and the
 * five tables are all regions of that borrow, at compile-time offsets, and no entry reads or writes a
 * byte outside it. sec 5.1 keeps this state per interface, so two interfaces are two borrows and
 * share nothing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV6

#include "idemIP/nd/nd6.h"

IDEMIP_BEGIN_DECLS

// RFC 4861 sec 5.1 Neighbor Cache: an entry is "keyed on the neighbor's on-link unicast IP address"
// and holds "its link-layer address, a flag indicating whether the neighbor is a router or a host
// (called IsRouter in this document), a pointer to any queued packets waiting for address resolution
// to complete", and from Neighbor Unreachability Detection "the reachability state, the number of
// unanswered probes, and the time the next Neighbor Unreachability Detection event is scheduled to
// take place".
typedef struct
{
    uint32_t next_event_ms;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    uint8_t lladdr[IDEMIP_MAC_LEN];
    IdemIpNd6State state;
    uint8_t probes;
    uint8_t pending_head;
    idemip_bool is_router;
    idemip_bool used;
    uint8_t pad[1];
} Nd6Neighbor;

// RFC 4861 sec 5.1 Destination Cache: it "maps a destination IP address to the IP address of the
// next-hop neighbor", carries "the Path MTU (PMTU) and round-trip timers", and shares the Neighbor
// Cache entry every destination through that router uses.
typedef struct
{
    uint32_t rtt_ms;
    uint8_t dst[IDEMIP_IP6_ADDR_LEN];
    uint8_t next_hop[IDEMIP_IP6_ADDR_LEN];
    uint16_t pmtu;
    uint8_t neighbor;
    idemip_bool used;
    uint8_t pad[24];
} Nd6Destination;

// RFC 4861 sec 5.1 Prefix List: "the prefixes that define a set of addresses that are on-link", each
// with "an associated invalidation timer value (extracted from the advertisement)". The flags are the
// sec 4.6.2 L and A bits.
typedef struct
{
    uint32_t invalidate_ms;
    uint8_t prefix[IDEMIP_IP6_ADDR_LEN];
    uint8_t prefix_len;
    uint8_t netif;
    idemip_bool on_link;
    idemip_bool autonomous;
    idemip_bool infinite;
    idemip_bool used;
    uint8_t pad[6];
} Nd6Prefix;

// RFC 4861 sec 5.1 Default Router List: "Router list entries point to entries in the Neighbor Cache",
// and each "has an associated invalidation timer value (extracted from Router Advertisements)".
typedef struct
{
    uint32_t invalidate_ms;
    uint8_t neighbor;
    idemip_bool used;
    uint8_t pad[2];
} Nd6Router;

// One frame held while address resolution completes (RFC 4861 sec 7.2.2). The octets stay in the
// buffer the engine wrote them to, pinned by desc.
typedef struct
{
    uint32_t deadline_ms;
    uint16_t desc;
    uint16_t len;
    uint8_t neighbor;
    uint8_t next;
    idemip_bool used;
    uint8_t pad[5];
} Nd6Pending;

// The running context: the host variables RFC 4861 sec 6.3.4 sets from a Router Advertisement, the
// sec 6.3.7 Router Solicitation count and its deadline, and the occupancy of each table. ready is the
// mark clear leaves, so a borrow no one cleared is refused. dad.c and slaac.c hold their RFC 4862
// sec 5.4 state in the rest of the IDEMIP_ND6_CTX_BYTES region this occupies the head of.
typedef struct
{
    uint32_t now_ms;
    uint32_t base_reachable_ms;
    uint32_t reachable_ms;
    uint32_t retrans_ms;
    uint32_t link_mtu;
    uint32_t rtr_solicit_ms;
    uint8_t cur_hop_limit;
    uint8_t rtr_solicits;
    uint8_t neighbors;
    uint8_t destinations;
    uint8_t prefixes;
    uint8_t routers;
    uint8_t pendings;
    idemip_bool managed;
    idemip_bool other;
    idemip_bool ready;
} Nd6Ctx;

// An index is (i << SHIFT), so each entry is exactly its width.
static_assert(sizeof(Nd6Neighbor) == (1u << IDEMIP_ND6_NEIGHBOR_ENTRY_SHIFT),
              "a neighbor entry must be 1 << IDEMIP_ND6_NEIGHBOR_ENTRY_SHIFT wide");
static_assert(sizeof(Nd6Destination) == (1u << IDEMIP_ND6_DESTINATION_ENTRY_SHIFT),
              "a destination entry must be 1 << IDEMIP_ND6_DESTINATION_ENTRY_SHIFT wide");
static_assert(sizeof(Nd6Prefix) == (1u << IDEMIP_ND6_PREFIX_ENTRY_SHIFT),
              "a prefix entry must be 1 << IDEMIP_ND6_PREFIX_ENTRY_SHIFT wide");
static_assert(sizeof(Nd6Router) == (1u << IDEMIP_ND6_ROUTER_ENTRY_SHIFT),
              "a router entry must be 1 << IDEMIP_ND6_ROUTER_ENTRY_SHIFT wide");
static_assert(sizeof(Nd6Pending) == (1u << IDEMIP_ND6_PENDING_ENTRY_SHIFT),
              "a pending entry must be 1 << IDEMIP_ND6_PENDING_ENTRY_SHIFT wide");
// The caller's borrow, split: the operand block, the context, then the five tables. nd6.h publishes
// the offsets; these two asserts prove the span covers them before anything runs. The first keeps the
// context inside the region ahead of the neighbor cache, the second the whole map inside the borrow.
static_assert(IDEMIP_ND6_OFF_CTX + sizeof(Nd6Ctx) <= IDEMIP_ND6_OFF_NEIGHBORS,
              "IDEMIP_ND6_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_ND6_OFF_END <= IDEMIP_ND6_BORROW,
              "IDEMIP_ND6_BORROW is short of the map - raise IDEMIP_ND6_CTX_BYTES in idemip_config.h");

// Every table index counts the entries the borrow holds, so IDEMIP_ND6_NONE names none of them.
static_assert(IDEMIP_ND6_NUM_NEIGHBORS < IDEMIP_ND6_NONE && IDEMIP_ND6_NUM_DESTINATIONS < IDEMIP_ND6_NONE &&
                  IDEMIP_ND6_NUM_PREFIXES < IDEMIP_ND6_NONE && IDEMIP_ND6_NUM_ROUTERS < IDEMIP_ND6_NONE &&
                  IDEMIP_ND6_PENDING < IDEMIP_ND6_NONE,
              "a table is wider than the index a result member carries");

// The regions, at their offsets in the caller's borrow.
#define ND6_IO(w) IDEMIP_ND6_IO(w)
#define ND6_CTX(w) ((Nd6Ctx *)(void *)((w) + IDEMIP_ND6_OFF_CTX))
#define ND6_NEIGHBOR_AT(w, i)                                                                                          \
    ((Nd6Neighbor *)(void *)((w) + IDEMIP_ND6_OFF_NEIGHBORS + ((size_t)(i) << IDEMIP_ND6_NEIGHBOR_ENTRY_SHIFT)))
#define ND6_DESTINATION_AT(w, i)                                                                                       \
    ((Nd6Destination *)(void *)((w) + IDEMIP_ND6_OFF_DESTINATIONS +                                                    \
                                ((size_t)(i) << IDEMIP_ND6_DESTINATION_ENTRY_SHIFT)))
#define ND6_PREFIX_AT(w, i)                                                                                            \
    ((Nd6Prefix *)(void *)((w) + IDEMIP_ND6_OFF_PREFIXES + ((size_t)(i) << IDEMIP_ND6_PREFIX_ENTRY_SHIFT)))
#define ND6_ROUTER_AT(w, i)                                                                                            \
    ((Nd6Router *)(void *)((w) + IDEMIP_ND6_OFF_ROUTERS + ((size_t)(i) << IDEMIP_ND6_ROUTER_ENTRY_SHIFT)))
#define ND6_PENDING_AT(w, i)                                                                                           \
    ((Nd6Pending *)(void *)((w) + IDEMIP_ND6_OFF_PENDING + ((size_t)(i) << IDEMIP_ND6_PENDING_ENTRY_SHIFT)))

// Octets the context and the five tables span, which is what clear zeroes.
#define ND6_STATE_BYTES (IDEMIP_ND6_OFF_END - IDEMIP_ND6_OFF_CTX)

// --- the entries -----------------------------------------------------------

// Zeroes the context and the five tables, then marks the borrow this module's. The operand block is
// the caller's and is left alone.
static void nd6_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    Nd6Io *io = ND6_IO(work);
    memset(work + IDEMIP_ND6_OFF_CTX, 0, ND6_STATE_BYTES);
    ND6_CTX(work)->ready = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

static void nd6_neighbor_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->neighbor = IDEMIP_ND6_NONE;
    io->lladdr = NULL;
    if (!ctx->ready || io->neighbor_args.addr == NULL)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 5.1, whose Neighbor Cache entries are "keyed on the neighbor's on-link
    // unicast IP address".
    io->status = IDEMIP_ERR;
}

static void nd6_neighbor_set(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->neighbor = IDEMIP_ND6_NONE;
    if (!ctx->ready || io->neighbor_args.addr == NULL || io->neighbor_args.state > IDEMIP_ND6_PROBE)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 7.2.5 and sec 6.3.4, which record the link-layer address and set the
    // entry STALE when a different one arrives, and sec 7.3.3, which creates an entry INCOMPLETE
    // when address resolution starts.
    io->status = IDEMIP_ERR;
}

static void nd6_neighbor_confirm(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    if (!ctx->ready || io->neighbor_args.index >= IDEMIP_ND6_NUM_NEIGHBORS)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 7.3.3: "When a reachability confirmation is received (either through
    // upper-layer advice or a solicited Neighbor Advertisement), an entry's state changes to
    // REACHABLE", with upper-layer advice having no effect on an INCOMPLETE entry.
    io->status = IDEMIP_ERR;
}

static void nd6_neighbor_used(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    if (!ctx->ready || io->neighbor_args.index >= IDEMIP_ND6_NUM_NEIGHBORS)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 7.3.3: "The first time a node sends a packet to a neighbor whose entry is
    // STALE, the sender changes the state to DELAY and sets a timer to expire in
    // DELAY_FIRST_PROBE_TIME seconds."
    io->status = IDEMIP_ERR;
}

static void nd6_neighbor_remove(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    if (!ctx->ready || io->neighbor_args.index >= IDEMIP_ND6_NUM_NEIGHBORS)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 7.3.3, which deletes an entry when address resolution fails or when
    // MAX_UNICAST_SOLICIT probes go unanswered, and sec 7.2.2, which answers each queued frame with
    // ICMP Destination Unreachable code 3.
    io->status = IDEMIP_ERR;
}

static void nd6_dest_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->destination = IDEMIP_ND6_NONE;
    io->next_hop = NULL;
    io->pmtu = 0u;
    if (!ctx->ready || io->dest_args.dst == NULL)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 5.2 next-hop determination, which consults the Destination Cache before
    // the Prefix List and the Default Router List.
    io->status = IDEMIP_ERR;
}

static void nd6_dest_set(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->destination = IDEMIP_ND6_NONE;
    if (!ctx->ready || io->dest_args.dst == NULL)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 5.1, which updates the Destination Cache "with information learned from
    // Redirect messages" (sec 8.3), and RFC 8201, which records the path MTU on the same entry.
    io->status = IDEMIP_ERR;
}

static void nd6_prefix_set(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->prefix = IDEMIP_ND6_NONE;
    if (!ctx->ready || io->prefix_args.prefix == NULL || io->prefix_args.prefix_len > 128u)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 6.3.4, which creates a Prefix List entry from a Prefix Information option
    // with the L flag set and initializes its invalidation timer from the sec 4.6.2 Valid Lifetime.
    io->status = IDEMIP_ERR;
}

static void nd6_prefix_on_link(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->prefix = IDEMIP_ND6_NONE;
    io->on_link = IDEMIP_FALSE;
    if (!ctx->ready || io->prefix_args.prefix == NULL)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 5.2, where "The sender performs a longest prefix match against the Prefix
    // List to determine whether the packet's destination is on- or off-link", as RFC 5942 sec 5
    // constrains it.
    io->status = IDEMIP_ERR;
}

static void nd6_router_set(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->router = IDEMIP_ND6_NONE;
    if (!ctx->ready || io->router_args.addr == NULL)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 6.3.4, which creates a Default Router List entry when the Router Lifetime
    // is non-zero, resets its invalidation timer when the router is already listed, and times the
    // entry out at once when the lifetime is zero.
    io->status = IDEMIP_ERR;
}

static void nd6_router_select(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->router = IDEMIP_ND6_NONE;
    io->neighbor = IDEMIP_ND6_NONE;
    io->next_hop = NULL;
    if (!ctx->ready)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 6.3.6 default router selection, which "favors routers known to be
    // reachable over those whose reachability is suspect" and round-robins among the rest.
    io->status = IDEMIP_ERR;
}

static void nd6_pending_push(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->pending = IDEMIP_ND6_NONE;
    if (!ctx->ready || io->pending_args.neighbor >= IDEMIP_ND6_NUM_NEIGHBORS || io->pending_args.len == 0u)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 7.2.2, whose queue "MUST hold at least one packet", is limited "to some
    // small value", and on overflow has "the new arrival SHOULD replace the oldest entry".
    io->status = IDEMIP_ERR;
}

static void nd6_pending_pop(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->pending = IDEMIP_ND6_NONE;
    io->desc = 0u;
    io->len = 0u;
    if (!ctx->ready || io->pending_args.neighbor >= IDEMIP_ND6_NUM_NEIGHBORS)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 7.2.2: "Once address resolution completes, the node transmits any queued
    // packets."
    io->status = IDEMIP_ERR;
}

static void nd6_params_set(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    if (!ctx->ready)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 6.3.4, which copies Cur Hop Limit, Reachable Time, Retrans Timer and the
    // MTU option into CurHopLimit, BaseReachableTime, RetransTimer and LinkMTU, ignores an
    // unspecified field, and redraws ReachableTime over sec 6.3.2's two random factors.
    io->status = IDEMIP_ERR;
}

static void nd6_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    io->status = IDEMIP_ERR;
    io->expired = 0u;
    io->solicit = IDEMIP_FALSE;
    io->multicast = IDEMIP_FALSE;
    io->target = NULL;
    if (!ctx->ready)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 7.3.3, which walks REACHABLE to STALE at ReachableTime, DELAY to PROBE at
    // DELAY_FIRST_PROBE_TIME and retransmits every RetransTimer up to MAX_UNICAST_SOLICIT, and
    // sec 6.3.5, which deletes a Default Router List or Prefix List entry whose invalidation timer
    // fired.
    io->status = IDEMIP_ERR;
}

const Nd6Ns Nd6 = {.clear = nd6_clear,
                   .neighbor_find = nd6_neighbor_find,
                   .neighbor_set = nd6_neighbor_set,
                   .neighbor_confirm = nd6_neighbor_confirm,
                   .neighbor_used = nd6_neighbor_used,
                   .neighbor_remove = nd6_neighbor_remove,
                   .dest_find = nd6_dest_find,
                   .dest_set = nd6_dest_set,
                   .prefix_set = nd6_prefix_set,
                   .prefix_on_link = nd6_prefix_on_link,
                   .router_set = nd6_router_set,
                   .router_select = nd6_router_select,
                   .pending_push = nd6_pending_push,
                   .pending_pop = nd6_pending_pop,
                   .params_set = nd6_params_set,
                   .tick = nd6_tick};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6
