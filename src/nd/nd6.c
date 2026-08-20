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

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/nd/nd6.h"

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
//
// The address is held here rather than only in the Neighbor Cache entry, because sec 6.3.4 states
// the list in terms of addresses - "a host MUST retain at least two router addresses" - and sec 7.2
// forbids an advertisement with no Source Link-Layer Address option from creating a cache entry at
// all. sec 4.2 says that option "MAY be omitted to facilitate in-bound load balancing over
// replicated interfaces", so a router that never sends one must still be listed. neighbor is the
// sec 5.1 pointer once a cache entry exists, and IDEMIP_ND6_NONE until then.
typedef struct
{
    uint32_t invalidate_ms;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    uint8_t neighbor;
    idemip_bool used;
    uint8_t pad[10];
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
    uint32_t reachable_redraw_ms; // when sec 6.3.2's "at least every few hours" draw next comes round
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
    uint8_t router_cursor;
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

// Each count as the octet an index is compared against.
#define ND6_NEIGHBORS ((uint8_t)IDEMIP_ND6_NUM_NEIGHBORS)
#define ND6_DESTINATIONS ((uint8_t)IDEMIP_ND6_NUM_DESTINATIONS)
#define ND6_PREFIXES ((uint8_t)IDEMIP_ND6_NUM_PREFIXES)
#define ND6_ROUTERS ((uint8_t)IDEMIP_ND6_NUM_ROUTERS)
#define ND6_PENDINGS ((uint8_t)IDEMIP_ND6_PENDING)

// A deadline is one absolute millisecond stamp compared as a signed difference, so the span it
// carries is half the clock's period. RFC 4861 sec 4.6.2 states a Valid Lifetime in seconds, and a
// finite one longer than this is held at the bound.
#define ND6_DEADLINE_MAX_MS 0x7FFFFFFFu
#define ND6_LIFETIME_S_MAX 2147483u
static_assert((uint64_t)ND6_LIFETIME_S_MAX * 1000u <= (uint64_t)ND6_DEADLINE_MAX_MS,
              "ND6_LIFETIME_S_MAX seconds must fit ND6_DEADLINE_MAX_MS milliseconds");

// RFC 4861 sec 7.2.2 arms the address-resolution deadline at RetransTimer times
// MAX_MULTICAST_SOLICIT + 1, so the interval is the deadline span shifted down by that count. A
// RetransTimer above this cannot be represented: the deadline it arms lands more than half the
// clock's period out and reads as already past, which turns sec 7.3.3's "A node MUST NOT send
// Neighbor Solicitations to the same neighbor more frequently than once every RetransTimer
// milliseconds" into a solicitation on every tick. A count that is a power of two makes the bound a
// shift.
#define ND6_RETRANS_SHIFT 2u
#define ND6_RETRANS_MAX_MS (ND6_DEADLINE_MAX_MS >> ND6_RETRANS_SHIFT)
static_assert(((uint32_t)IDEMIP_ND6_MAX_MULTICAST_SOLICIT + 1u) == (1u << ND6_RETRANS_SHIFT),
              "ND6_RETRANS_SHIFT must be the log2 of MAX_MULTICAST_SOLICIT + 1 - RFC 4861 sec 10");
static_assert((uint64_t)ND6_RETRANS_MAX_MS * ((uint64_t)IDEMIP_ND6_MAX_MULTICAST_SOLICIT + 1u) <=
                  (uint64_t)ND6_DEADLINE_MAX_MS,
              "a sec 7.2.2 retransmit deadline must fit ND6_DEADLINE_MAX_MS milliseconds");
static_assert((uint32_t)IDEMIP_ND6_RETRANS_TIMER_MS <= ND6_RETRANS_MAX_MS,
              "the RETRANS_TIMER default must fit the deadline span");

// RFC 4291 sec 2.5.6 gives the link-local prefix as FE80::/10, which RFC 4861 sec 5.1 keeps on the
// Prefix List "with an infinite invalidation timer regardless of whether routers are advertising a
// prefix for it".
#define ND6_LINK_LOCAL_LEN 10u

// RFC 4291 sec 2.7: a multicast address begins with FF, and RFC 4861 sec 5.2 considers it on-link.
#define ND6_MULTICAST_TAG 0xFFu

// --- addresses -------------------------------------------------------------

// RFC 4861 sec 5.1 keys a Neighbor Cache entry on the whole unicast address.
static idemip_bool nd6_addr_eq(const uint8_t *a, const uint8_t *b)
{
    return (memcmp(a, b, IDEMIP_IP6_ADDR_LEN) == 0) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 4861 sec 5.2 longest prefix match over the first len bits: (len >> 3) whole octets compare
// exactly, and the remaining (len & 7) bits compare under a mask of that many leading bits.
static idemip_bool nd6_prefix_eq(const uint8_t *a, const uint8_t *b, uint8_t len)
{
    size_t whole = (size_t)(len >> 3);
    uint8_t bits = (uint8_t)(len & 7u);
    if (whole != 0u && memcmp(a, b, whole) != 0)
    {
        return IDEMIP_FALSE;
    }
    if (bits != 0u)
    {
        uint8_t mask = (uint8_t)(0xFFu << (8u - bits));
        if ((uint8_t)((a[whole] ^ b[whole]) & mask) != 0u)
        {
            return IDEMIP_FALSE;
        }
    }
    return IDEMIP_TRUE;
}

// RFC 4291 sec 2.5.6: the first ten bits of a link-local address are 1111111010.
static idemip_bool nd6_is_link_local(const uint8_t *addr)
{
    return (addr[0] == 0xFEu && (uint8_t)(addr[1] & 0xC0u) == 0x80u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 4291 sec 2.7: FF00::/8.
static idemip_bool nd6_is_multicast(const uint8_t *addr)
{
    return (addr[0] == ND6_MULTICAST_TAG) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- the clock -------------------------------------------------------------

// True when the clock is at or past the deadline. The difference is taken signed, so the comparison
// holds across one wrap of the millisecond clock.
static idemip_bool nd6_due(uint32_t now_ms, uint32_t deadline_ms)
{
    return ((int32_t)(now_ms - deadline_ms) >= 0) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// Milliseconds still to run on a deadline, and zero once it is due.
static uint32_t nd6_remaining(uint32_t now_ms, uint32_t deadline_ms)
{
    return nd6_due(now_ms, deadline_ms) ? 0u : (uint32_t)(deadline_ms - now_ms);
}

// RFC 4861 sec 4.6.2 and sec 4.2 state a lifetime in seconds, and sec 5.1 makes it the entry's
// invalidation timer. Held to ND6_DEADLINE_MAX_MS so the multiply and the deadline both fit.
static uint32_t nd6_lifetime_ms(uint32_t lifetime_s)
{
    return (lifetime_s >= ND6_LIFETIME_S_MAX) ? ND6_DEADLINE_MAX_MS : (lifetime_s * 1000u);
}

// RFC 4861 sec 6.3.2: ReachableTime "should be a uniformly distributed random value between
// MIN_RANDOM_FACTOR and MAX_RANDOM_FACTOR times BaseReachableTime milliseconds". sec 10 prints those
// as .5 and 1.5, so the low end is base >> 1 and the span above it is base. The offset is the top 32
// bits of rand times base, which lands uniformly in [0, base) without a divide.
// The draw reaches MAX_RANDOM_FACTOR times the base, so the base is bounded at the span divided by
// that factor rather than at the span itself: base >> 1 plus an offset below base must still land
// inside a deadline. sec 4.2 makes Reachable Time a remote party's 32-bit word, so this is what stops
// an advertised value from arming a deadline that reads as already passed.
#define ND6_REACHABLE_MAX_MS (ND6_DEADLINE_MAX_MS / 3u)

static_assert((uint64_t)(ND6_REACHABLE_MAX_MS >> 1) + (uint64_t)ND6_REACHABLE_MAX_MS <=
                  (uint64_t)ND6_DEADLINE_MAX_MS,
              "a sec 6.3.2 ReachableTime draw must fit ND6_DEADLINE_MAX_MS milliseconds");

static uint32_t nd6_draw_reachable(uint32_t base_ms, uint32_t rand_word)
{
    uint32_t base = (base_ms > ND6_REACHABLE_MAX_MS) ? (uint32_t)ND6_REACHABLE_MAX_MS : base_ms;
    uint32_t offset = (uint32_t)(((uint64_t)rand_word * (uint64_t)base) >> 32);
    return IDEMIP_ND6_MIN_RANDOM(base) + offset;
}

// RFC 4861 sec 6.3.2: the host variables "have default values that are overridden by information
// received in Router Advertisement messages". A zero is the value clear leaves, so it reads as the
// default.
static uint32_t nd6_reachable_ms(const Nd6Ctx *ctx)
{
    return (ctx->reachable_ms != 0u) ? ctx->reachable_ms : IDEMIP_ND6_REACHABLE_TIME_MS;
}

// BaseReachableTime: what an advertisement set, or sec 6.3.2's default until one does.
static uint32_t nd6_base_reachable_ms(const Nd6Ctx *ctx)
{
    return (ctx->base_reachable_ms != 0u) ? ctx->base_reachable_ms : (uint32_t)IDEMIP_ND6_REACHABLE_TIME_MS;
}

// RFC 4861 sec 6.3.4: "The RetransTimer variable SHOULD be copied from the Retrans Timer field, if
// the received value is non-zero." A value past ND6_RETRANS_MAX_MS is held at the bound, which is
// where every reader of the timer takes it, so no deadline armed from it can land outside the span.
static uint32_t nd6_retrans_ms(const Nd6Ctx *ctx)
{
    uint32_t ms = (ctx->retrans_ms != 0u) ? ctx->retrans_ms : (uint32_t)IDEMIP_ND6_RETRANS_TIMER_MS;
    return (ms > ND6_RETRANS_MAX_MS) ? ND6_RETRANS_MAX_MS : ms;
}

// RFC 2464 sec 2: "The default MTU size for IPv6 packets on an Ethernet is 1500 octets."
static uint32_t nd6_link_mtu(const Nd6Ctx *ctx)
{
    return (ctx->link_mtu != 0u) ? ctx->link_mtu : (uint32_t)IDEMIP_ETH_MAX_PAYLOAD;
}

static uint8_t nd6_cur_hop_limit(const Nd6Ctx *ctx)
{
    return (ctx->cur_hop_limit != 0u) ? ctx->cur_hop_limit : (uint8_t)IDEMIP_IP_DEFAULT_TTL;
}

// --- the neighbor cache ----------------------------------------------------

static uint8_t nd6_neighbor_lookup(uint8_t *restrict work, const uint8_t *addr)
{
    for (uint8_t i = 0u; i < ND6_NEIGHBORS; i++)
    {
        const Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, i);
        if (n->used && nd6_addr_eq(n->addr, addr))
        {
            return i;
        }
    }
    return IDEMIP_ND6_NONE;
}

// The deadline the reachability machine puts on an entry as it enters a state (RFC 4861 sec 7.3.2).
// INCOMPLETE and PROBE are due at once, since each sends a solicitation on entry; REACHABLE runs for
// ReachableTime; DELAY runs for DELAY_FIRST_PROBE_TIME; STALE has no timer and waits for a packet.
static void nd6_arm(const Nd6Ctx *ctx, Nd6Neighbor *n)
{
    uint32_t now = ctx->now_ms;
    switch (n->state)
    {
    case IDEMIP_ND6_REACHABLE:
        n->next_event_ms = now + nd6_reachable_ms(ctx);
        break;
    case IDEMIP_ND6_DELAY:
        n->next_event_ms = now + IDEMIP_ND6_DELAY_FIRST_PROBE_MS;
        break;
    case IDEMIP_ND6_INCOMPLETE:
    case IDEMIP_ND6_PROBE:
    case IDEMIP_ND6_STALE:
    default:
        n->next_event_ms = now;
        break;
    }
}

// STALE takes no deadline, so nothing schedules an event on it (RFC 4861 sec 7.3.2: "While stale, no
// action takes place until a packet is sent").
static idemip_bool nd6_has_timer(const Nd6Neighbor *n)
{
    return (n->state != IDEMIP_ND6_STALE) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 4861 sec 5.2: with no entry for the next hop "the sender creates one, sets its state to
// INCOMPLETE, initiates Address Resolution". A full cache reports IDEMIP_ND6_NONE, since sec 7.3.3
// frees a slot as solicitations go unanswered.
static uint8_t nd6_create_neighbor(uint8_t *restrict work, const uint8_t *addr, const uint8_t *lladdr,
                                   IdemIpNd6State state, idemip_bool is_router)
{
    Nd6Ctx *ctx = ND6_CTX(work);
    for (uint8_t i = 0u; i < ND6_NEIGHBORS; i++)
    {
        Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, i);
        if (n->used)
        {
            continue;
        }
        memset(n, 0, sizeof *n);
        memcpy(n->addr, addr, IDEMIP_IP6_ADDR_LEN);
        n->pending_head = IDEMIP_ND6_NONE;
        n->state = state;
        n->is_router = is_router;
        n->used = IDEMIP_TRUE;
        if (lladdr != NULL)
        {
            memcpy(n->lladdr, lladdr, IDEMIP_MAC_LEN);
        }
        nd6_arm(ctx, n);
        ctx->neighbors++;
        return i;
    }
    return IDEMIP_ND6_NONE;
}

static void nd6_report_neighbor(uint8_t *restrict work, uint8_t i)
{
    Nd6Io *io = ND6_IO(work);
    const Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, i);
    io->neighbor = i;
    io->state = n->state;
    io->probes = n->probes;
    io->is_router = n->is_router;
    io->next_event_ms = n->next_event_ms;
    io->lladdr = (n->state == IDEMIP_ND6_INCOMPLETE) ? NULL : n->lladdr;
}

// --- the queued frames -----------------------------------------------------

// RFC 4861 sec 7.2.2 keeps the queue in arrival order, so a push lands at the tail.
static void nd6_pending_link(uint8_t *restrict work, uint8_t ni, uint8_t pi)
{
    Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, ni);
    ND6_PENDING_AT(work, pi)->next = IDEMIP_ND6_NONE;
    if (n->pending_head >= ND6_PENDINGS)
    {
        n->pending_head = pi;
        return;
    }
    uint8_t t = n->pending_head;
    while (ND6_PENDING_AT(work, t)->next < ND6_PENDINGS)
    {
        t = ND6_PENDING_AT(work, t)->next;
    }
    ND6_PENDING_AT(work, t)->next = pi;
}

static void nd6_pending_unlink(uint8_t *restrict work, uint8_t ni, uint8_t pi)
{
    Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, ni);
    if (n->pending_head == pi)
    {
        n->pending_head = ND6_PENDING_AT(work, pi)->next;
        return;
    }
    uint8_t t = n->pending_head;
    while (t < ND6_PENDINGS)
    {
        Nd6Pending *q = ND6_PENDING_AT(work, t);
        if (q->next == pi)
        {
            q->next = ND6_PENDING_AT(work, pi)->next;
            return;
        }
        t = q->next;
    }
}

// Takes one frame off its neighbor's queue and reports the descriptor it pins, so the caller unpins
// it and, where address resolution failed, answers RFC 4861 sec 7.2.2's ICMP Destination Unreachable
// code 3.
static void nd6_release_pending(uint8_t *restrict work, uint8_t pi)
{
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    Nd6Pending *p = ND6_PENDING_AT(work, pi);
    uint8_t ni = p->neighbor;
    if (ni < ND6_NEIGHBORS)
    {
        nd6_pending_unlink(work, ni, pi);
    }
    io->pending = pi;
    io->desc = p->desc;
    io->len = p->len;
    io->neighbor = ni;
    p->used = IDEMIP_FALSE;
    p->next = IDEMIP_ND6_NONE;
    p->neighbor = IDEMIP_ND6_NONE;
    p->desc = 0u;
    p->len = 0u;
    p->deadline_ms = 0u;
    if (ctx->pendings != 0u)
    {
        ctx->pendings--;
    }
}

// --- the destination cache and the default router list ---------------------

// RFC 4861 sec 6.3.5: on removing a router "the node MUST update the Destination Cache in such a way
// that all entries using the router perform next-hop determination again", which the entry's slot
// going free forces.
static void nd6_drop_destinations_via(uint8_t *restrict work, uint8_t ni)
{
    Nd6Ctx *ctx = ND6_CTX(work);
    for (uint8_t i = 0u; i < ND6_DESTINATIONS; i++)
    {
        Nd6Destination *d = ND6_DESTINATION_AT(work, i);
        if (d->used && d->neighbor == ni)
        {
            d->used = IDEMIP_FALSE;
            d->neighbor = IDEMIP_ND6_NONE;
            if (ctx->destinations != 0u)
            {
                ctx->destinations--;
            }
        }
    }
}

static void nd6_drop_router(uint8_t *restrict work, uint8_t ri)
{
    Nd6Ctx *ctx = ND6_CTX(work);
    Nd6Router *r = ND6_ROUTER_AT(work, ri);
    uint8_t ni = r->neighbor;
    r->used = IDEMIP_FALSE;
    r->invalidate_ms = 0u;
    r->neighbor = IDEMIP_ND6_NONE;
    memset(r->addr, 0, IDEMIP_IP6_ADDR_LEN);
    if (ctx->routers != 0u)
    {
        ctx->routers--;
    }
    // sec 6.3.5 asks only that the entry be discarded and the Destination Cache entries through it
    // redo next-hop determination. The neighbor's IsRouter is left alone: Appendix D says "when there
    // is no host vs. router information in the ND message, the receipt of the message MUST NOT cause a
    // change to the IsRouter state", and the only TRUE-to-FALSE transition the document gives is sec
    // 7.2.5's, off the R bit of a Neighbor Advertisement.
    if (ni < ND6_NEIGHBORS)
    {
        nd6_drop_destinations_via(work, ni);
    }
}

// RFC 4861 sec 7.2.5: when IsRouter goes from TRUE to FALSE "the node MUST remove that router from
// the Default Router List and update the Destination Cache entries for all destinations using that
// neighbor as a router".
static void nd6_drop_router_of(uint8_t *restrict work, uint8_t ni)
{
    for (uint8_t i = 0u; i < ND6_ROUTERS; i++)
    {
        const Nd6Router *r = ND6_ROUTER_AT(work, i);
        if (r->used && r->neighbor == ni)
        {
            nd6_drop_router(work, i);
            return;
        }
    }
    nd6_drop_destinations_via(work, ni);
}

// RFC 4861 sec 7.3.3: "Neighbor Unreachability Detection signals the need for next-hop determination
// by deleting a Neighbor Cache entry", so every structure pointing at it goes with it.
static void nd6_free_neighbor(uint8_t *restrict work, uint8_t ni)
{
    Nd6Ctx *ctx = ND6_CTX(work);
    Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, ni);
    nd6_drop_router_of(work, ni);
    memset(n, 0, sizeof *n);
    n->pending_head = IDEMIP_ND6_NONE;
    if (ctx->neighbors != 0u)
    {
        ctx->neighbors--;
    }
}

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
    // RFC 4861 sec 5.1, whose Neighbor Cache entries are "keyed on the neighbor's on-link unicast IP
    // address". A miss is ERR: the caller creates the entry rather than repeating the lookup.
    ctx->now_ms = io->tick_args.now_ms;
    uint8_t i = nd6_neighbor_lookup(work, io->neighbor_args.addr);
    if (i == IDEMIP_ND6_NONE)
    {
        return;
    }
    nd6_report_neighbor(work, i);
    io->status = IDEMIP_OK;
}

// RFC 4861 sec 7.2.3, sec 7.2.5, sec 6.3.4 and sec 8.3 all reach the Neighbor Cache the same way: a
// missing entry is created in the state the caller names, and an entry that is there is revised by
// sec 7.2.5's two rules. A full cache is BUSY, since sec 7.3.3 deletes an entry whose solicitations
// go unanswered.
static void nd6_set_neighbor(uint8_t *restrict work)
{
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    const Nd6NeighborArgs *a = &io->neighbor_args;
    uint8_t i = nd6_neighbor_lookup(work, a->addr);

    if (i == IDEMIP_ND6_NONE)
    {
        i = nd6_create_neighbor(work, a->addr, a->lladdr, a->state, a->is_router);
        if (i == IDEMIP_ND6_NONE)
        {
            io->status = IDEMIP_BUSY;
            return;
        }
        nd6_report_neighbor(work, i);
        io->status = IDEMIP_OK;
        return;
    }

    Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, i);
    idemip_bool differs =
        (a->lladdr != NULL && memcmp(n->lladdr, a->lladdr, IDEMIP_MAC_LEN) != 0) ? IDEMIP_TRUE : IDEMIP_FALSE;
    idemip_bool was_router = n->is_router;

    if (n->state == IDEMIP_ND6_INCOMPLETE)
    {
        // sec 7.2.5 on an INCOMPLETE entry: with no link-layer address supplied the advertisement is
        // discarded, and otherwise the address is recorded, a set Solicited flag makes the entry
        // REACHABLE and a clear one STALE. "the Override flag is ignored if the entry is in the
        // INCOMPLETE state".
        if (a->lladdr != NULL)
        {
            memcpy(n->lladdr, a->lladdr, IDEMIP_MAC_LEN);
            n->state = a->solicited ? IDEMIP_ND6_REACHABLE : IDEMIP_ND6_STALE;
            n->probes = 0u;
            n->is_router = a->is_router;
            nd6_arm(ctx, n);
        }
    }
    else if (differs && !a->override)
    {
        // sec 7.2.5 rule I: "If the state of the entry is REACHABLE, set it to STALE, but do not
        // update the entry in any other way", and any other state ignores the advertisement, which
        // "MUST NOT update the cache".
        if (n->state == IDEMIP_ND6_REACHABLE)
        {
            n->state = IDEMIP_ND6_STALE;
            n->probes = 0u;
            nd6_arm(ctx, n);
        }
    }
    else
    {
        // sec 7.2.5 rule II: the supplied address is inserted when it differs, a set Solicited flag
        // makes the entry REACHABLE, a clear one with a changed address makes it STALE, and otherwise
        // the state stands. sec 7.2.3 and sec 6.3.4 reach the same result for a changed address.
        if (differs)
        {
            memcpy(n->lladdr, a->lladdr, IDEMIP_MAC_LEN);
        }
        if (a->solicited)
        {
            n->state = IDEMIP_ND6_REACHABLE;
            n->probes = 0u;
            nd6_arm(ctx, n);
        }
        else if (differs)
        {
            n->state = IDEMIP_ND6_STALE;
            n->probes = 0u;
            nd6_arm(ctx, n);
        }
        n->is_router = a->is_router;
    }

    if (was_router && !n->is_router)
    {
        nd6_drop_router_of(work, i);
    }
    nd6_report_neighbor(work, i);
    io->status = IDEMIP_OK;
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
    ctx->now_ms = io->tick_args.now_ms;
    nd6_set_neighbor(work);
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
    // RFC 4861 sec 7.3.3: "When a reachability confirmation is received (either through upper-layer
    // advice or a solicited Neighbor Advertisement), an entry's state changes to REACHABLE. The one
    // exception is that upper-layer advice has no effect on entries in the INCOMPLETE state".
    Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, io->neighbor_args.index);
    if (!n->used)
    {
        return;
    }
    ctx->now_ms = io->tick_args.now_ms;
    if (n->state != IDEMIP_ND6_INCOMPLETE)
    {
        n->state = IDEMIP_ND6_REACHABLE;
        n->probes = 0u;
        nd6_arm(ctx, n);
    }
    nd6_report_neighbor(work, io->neighbor_args.index);
    io->status = IDEMIP_OK;
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
    // RFC 4861 sec 7.3.3: "The first time a node sends a packet to a neighbor whose entry is STALE,
    // the sender changes the state to DELAY and sets a timer to expire in DELAY_FIRST_PROBE_TIME
    // seconds." Every other state sends nothing and is left as it stands.
    Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, io->neighbor_args.index);
    if (!n->used)
    {
        return;
    }
    ctx->now_ms = io->tick_args.now_ms;
    if (n->state == IDEMIP_ND6_STALE)
    {
        n->state = IDEMIP_ND6_DELAY;
        n->probes = 0u;
        nd6_arm(ctx, n);
    }
    nd6_report_neighbor(work, io->neighbor_args.index);
    io->status = IDEMIP_OK;
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
    io->pending = IDEMIP_ND6_NONE;
    io->desc = 0u;
    io->len = 0u;
    if (!ctx->ready || io->neighbor_args.index >= IDEMIP_ND6_NUM_NEIGHBORS)
    {
        return;
    }
    // RFC 4861 sec 7.3.3 deletes an entry when address resolution fails or when the solicitations go
    // unanswered, and sec 7.2.2 answers each frame queued on it with ICMP Destination Unreachable
    // code 3. One queued frame comes back per call and reports BUSY, so its descriptor is unpinned
    // before the entry goes; the call that finds the queue empty frees the entry and reports OK.
    uint8_t ni = io->neighbor_args.index;
    Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, ni);
    if (!n->used)
    {
        return;
    }
    ctx->now_ms = io->tick_args.now_ms;
    io->neighbor = ni;
    if (n->pending_head < ND6_PENDINGS)
    {
        nd6_release_pending(work, n->pending_head);
        io->status = IDEMIP_BUSY;
        return;
    }
    nd6_free_neighbor(work, ni);
    io->status = IDEMIP_OK;
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
    // RFC 4861 sec 5.2 next-hop determination: "When the sending node has a packet to send, it first
    // examines the Destination Cache." A miss is ERR, and the caller then runs the Prefix List and
    // the Default Router List and installs the result.
    ctx->now_ms = io->tick_args.now_ms;
    for (uint8_t i = 0u; i < ND6_DESTINATIONS; i++)
    {
        const Nd6Destination *d = ND6_DESTINATION_AT(work, i);
        if (d->used && nd6_addr_eq(d->dst, io->dest_args.dst))
        {
            io->destination = i;
            io->next_hop = d->next_hop;
            io->pmtu = d->pmtu;
            io->neighbor = d->neighbor;
            io->status = IDEMIP_OK;
            return;
        }
    }
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
    // RFC 4861 sec 5.1 keeps the Destination Cache "updated with information learned from Redirect
    // messages" (sec 8.3), and stores with it "the Path MTU (PMTU)" that RFC 8201 sec 5.2 records.
    // A full cache is BUSY: sec 6.3.5 frees the entries through a router as it is removed.
    ctx->now_ms = io->tick_args.now_ms;
    const Nd6DestArgs *a = &io->dest_args;
    uint8_t i = IDEMIP_ND6_NONE;
    for (uint8_t k = 0u; k < ND6_DESTINATIONS; k++)
    {
        if (ND6_DESTINATION_AT(work, k)->used && nd6_addr_eq(ND6_DESTINATION_AT(work, k)->dst, a->dst))
        {
            i = k;
            break;
        }
    }
    if (i == IDEMIP_ND6_NONE)
    {
        if (a->next_hop == NULL)
        {
            return; // sec 5.1 maps a destination onto a next hop, so a new entry needs one
        }
        for (uint8_t k = 0u; k < ND6_DESTINATIONS; k++)
        {
            if (!ND6_DESTINATION_AT(work, k)->used)
            {
                i = k;
                break;
            }
        }
        if (i == IDEMIP_ND6_NONE)
        {
            io->status = IDEMIP_BUSY;
            return;
        }
        Nd6Destination *d = ND6_DESTINATION_AT(work, i);
        memset(d, 0, sizeof *d);
        memcpy(d->dst, a->dst, IDEMIP_IP6_ADDR_LEN);
        d->neighbor = IDEMIP_ND6_NONE;
        d->used = IDEMIP_TRUE;
        ctx->destinations++;
    }
    Nd6Destination *d = ND6_DESTINATION_AT(work, i);
    if (a->next_hop != NULL)
    {
        memcpy(d->next_hop, a->next_hop, IDEMIP_IP6_ADDR_LEN);
    }
    if (a->pmtu != 0u)
    {
        d->pmtu = a->pmtu;
    }
    if (a->neighbor < ND6_NEIGHBORS)
    {
        d->neighbor = a->neighbor;
    }
    io->destination = i;
    io->next_hop = d->next_hop;
    io->pmtu = d->pmtu;
    io->neighbor = d->neighbor;
    io->status = IDEMIP_OK;
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
    // RFC 4861 sec 6.3.4, for each Prefix Information option with the on-link flag set: the
    // link-local prefix is silently ignored; a prefix that is not listed and carries a non-zero Valid
    // Lifetime creates an entry whose invalidation timer starts at that lifetime; a prefix already
    // listed has its timer reset, and a zero lifetime times it out immediately; a zero lifetime on a
    // prefix that is not listed is silently ignored.
    ctx->now_ms = io->tick_args.now_ms;
    const Nd6PrefixArgs *a = &io->prefix_args;
    if (nd6_is_link_local(a->prefix))
    {
        io->status = IDEMIP_OK;
        return;
    }
    // sec 4.6.2: "if the L flag is not set a host MUST NOT conclude that an address derived from the
    // prefix is off-link. That is, it MUST NOT update a previous indication that the address is
    // on-link." sec 6.3.4 scopes the whole Prefix List procedure to options with the flag set and
    // gives the one way to cancel an indication: "advertise that prefix with the L-bit set and the
    // Lifetime set to zero". So an option with L clear carries no on-link information: it neither
    // stores an entry, nor clears one, nor takes a slot.
    if (!a->on_link)
    {
        io->status = IDEMIP_OK;
        return;
    }
    uint8_t i = IDEMIP_ND6_NONE;
    for (uint8_t k = 0u; k < ND6_PREFIXES; k++)
    {
        const Nd6Prefix *p = ND6_PREFIX_AT(work, k);
        if (p->used && p->prefix_len == a->prefix_len && nd6_prefix_eq(p->prefix, a->prefix, a->prefix_len))
        {
            i = k;
            break;
        }
    }
    if (i == IDEMIP_ND6_NONE)
    {
        if (a->lifetime_s == 0u)
        {
            io->status = IDEMIP_OK;
            return;
        }
        for (uint8_t k = 0u; k < ND6_PREFIXES; k++)
        {
            if (!ND6_PREFIX_AT(work, k)->used)
            {
                i = k;
                break;
            }
        }
        if (i == IDEMIP_ND6_NONE)
        {
            io->status = IDEMIP_BUSY; // a slot frees when sec 6.3.5 times an entry out
            return;
        }
        Nd6Prefix *p = ND6_PREFIX_AT(work, i);
        memset(p, 0, sizeof *p);
        memcpy(p->prefix, a->prefix, IDEMIP_IP6_ADDR_LEN);
        p->prefix_len = a->prefix_len;
        p->used = IDEMIP_TRUE;
        ctx->prefixes++;
    }
    Nd6Prefix *p = ND6_PREFIX_AT(work, i);
    p->on_link = a->on_link;
    p->autonomous = a->autonomous;
    p->infinite = (a->lifetime_s == IDEMIP_ND6_LIFETIME_INFINITE) ? IDEMIP_TRUE : IDEMIP_FALSE;
    p->invalidate_ms = ctx->now_ms + nd6_lifetime_ms(a->lifetime_s);
    io->prefix = i;
    io->status = IDEMIP_OK;
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
    // RFC 4861 sec 5.2: "The sender performs a longest prefix match against the Prefix List to
    // determine whether the packet's destination is on- or off-link." RFC 5942 sec 3 leaves the
    // Prefix List as the only source of on-link information here, with the link-local prefix
    // "effectively considered a permanent entry", and sec 5.2 treats a multicast destination as
    // on-link. RFC 5942 sec 3 point 2: a destination with no such information is off-link, which is
    // an answer rather than a failure, so this reports OK either way.
    ctx->now_ms = io->tick_args.now_ms;
    const uint8_t *addr = io->prefix_args.prefix;
    uint8_t best_len = 0u;
    idemip_bool matched = IDEMIP_FALSE;
    if (nd6_is_multicast(addr) || nd6_is_link_local(addr))
    {
        best_len = (uint8_t)ND6_LINK_LOCAL_LEN;
        matched = IDEMIP_TRUE;
    }
    for (uint8_t i = 0u; i < ND6_PREFIXES; i++)
    {
        const Nd6Prefix *p = ND6_PREFIX_AT(work, i);
        if (!p->used || !p->on_link)
        {
            continue;
        }
        if (matched && p->prefix_len <= best_len)
        {
            continue;
        }
        if (nd6_prefix_eq(p->prefix, addr, p->prefix_len))
        {
            best_len = p->prefix_len;
            matched = IDEMIP_TRUE;
            io->prefix = i;
        }
    }
    io->on_link = matched;
    io->status = IDEMIP_OK;
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
    // sec 6.1.2's first validity check: "IP Source Address is a link-local address. Routers must use
    // their link-local address as the source for Router Advertisement and Redirect messages so that
    // hosts can uniquely identify routers." A message failing it is not the "valid advertisement"
    // sec 6.3.4 speaks of, so it names no router.
    if (!nd6_is_link_local(io->router_args.addr))
    {
        return;
    }
    // RFC 4861 sec 6.3.4, on the source address of a valid Router Advertisement: a router that is not
    // listed and advertises a non-zero Router Lifetime creates an entry whose invalidation timer
    // starts at that lifetime; a router already listed has its timer reset; a router already listed
    // that advertises a zero lifetime is timed out at once as sec 6.3.5 specifies. The list is keyed
    // on the address, which is what sec 6.3.4 says a host retains.
    //
    // The Neighbor Cache is a separate question. sec 6.3.4: "If the advertisement contains a Source
    // Link-Layer Address option, the link-layer address SHOULD be recorded in the Neighbor Cache
    // entry for the router (creating an entry if necessary) and the IsRouter flag in the Neighbor
    // Cache entry MUST be set to TRUE. If no Source Link-Layer Address is included, but a
    // corresponding Neighbor Cache entry exists, its IsRouter flag MUST be set to TRUE... If a
    // Neighbor Cache entry is created for the router, its reachability state MUST be set to STALE."
    // sec 7.2 closes the remaining case: an advertisement without that option "MUST NOT create or
    // update neighbor cache entries, except with respect to the IsRouter flag", and "If a Neighbor
    // Cache entry does not exist for the source of such a message, Address Resolution will be
    // required before unicast communications with that address can begin."
    ctx->now_ms = io->tick_args.now_ms;
    const Nd6RouterArgs *a = &io->router_args;
    uint8_t ni = nd6_neighbor_lookup(work, a->addr);
    uint8_t ri = IDEMIP_ND6_NONE;
    for (uint8_t k = 0u; k < ND6_ROUTERS; k++)
    {
        const Nd6Router *r = ND6_ROUTER_AT(work, k);
        if (r->used && nd6_addr_eq(r->addr, a->addr))
        {
            ri = k;
            break;
        }
    }
    // sec 4.2: "The Router Lifetime applies only to the router's usefulness as a default router; it
    // does not apply to information contained in other message fields or options." A lifetime of zero
    // therefore takes the router out of the Default Router List and nothing else; the Source
    // Link-Layer Address recording and the IsRouter write below run for every valid advertisement.
    const idemip_bool default_router = (idemip_bool)(a->lifetime_s != 0u);
    if (!default_router && ri != IDEMIP_ND6_NONE)
    {
        nd6_drop_router(work, ri);
        ri = (uint8_t)IDEMIP_ND6_NONE;
    }
    if (a->lladdr != NULL)
    {
        if (ni == IDEMIP_ND6_NONE)
        {
            ni = nd6_create_neighbor(work, a->addr, a->lladdr, IDEMIP_ND6_STALE, IDEMIP_TRUE);
            if (ni == IDEMIP_ND6_NONE)
            {
                io->status = IDEMIP_BUSY; // a slot frees as sec 7.3.3 deletes an unanswered entry
                return;
            }
        }
        else
        {
            Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, ni);
            if (memcmp(n->lladdr, a->lladdr, IDEMIP_MAC_LEN) != 0)
            {
                // "If a cache entry already exists and is updated with a different link-layer
                // address, the reachability state MUST also be set to STALE."
                memcpy(n->lladdr, a->lladdr, IDEMIP_MAC_LEN);
                n->state = IDEMIP_ND6_STALE;
                nd6_arm(ctx, n);
            }
        }
    }
    if (default_router)
    {
        if (ri == IDEMIP_ND6_NONE)
        {
            for (uint8_t k = 0u; k < ND6_ROUTERS; k++)
            {
                if (!ND6_ROUTER_AT(work, k)->used)
                {
                    ri = k;
                    break;
                }
            }
            if (ri == IDEMIP_ND6_NONE)
            {
                io->status = IDEMIP_BUSY; // a slot frees when sec 6.3.5 times an entry out
                return;
            }
            Nd6Router *r = ND6_ROUTER_AT(work, ri);
            r->used = IDEMIP_TRUE;
            memcpy(r->addr, a->addr, IDEMIP_IP6_ADDR_LEN);
            ctx->routers++;
        }
        ND6_ROUTER_AT(work, ri)->neighbor = ni;
        ND6_ROUTER_AT(work, ri)->invalidate_ms = ctx->now_ms + nd6_lifetime_ms((uint32_t)a->lifetime_s);
    }
    // sec 6.3.4: "If no Source Link-Layer Address is included, but a corresponding Neighbor Cache
    // entry exists, its IsRouter flag MUST be set to TRUE." An advertisement is a router saying so,
    // whatever its Router Lifetime.
    if (ni < ND6_NEIGHBORS)
    {
        ND6_NEIGHBOR_AT(work, ni)->is_router = IDEMIP_TRUE;
        nd6_report_neighbor(work, ni);
    }
    io->router = ri;
    io->status = IDEMIP_OK;
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
    // RFC 4861 sec 6.3.6 rule 1: "Routers that are reachable or probably reachable (i.e., in any
    // state other than INCOMPLETE) SHOULD be preferred over routers whose reachability is unknown or
    // suspect". Rule 2: with none of them known reachable, "routers SHOULD be selected in a
    // round-robin fashion, so that subsequent requests for a default router do not return the same
    // router until all other routers have been selected". An empty list is ERR: RFC 5942 sec 4 rule
    // 4c has the host answer Destination Unreachable rather than come back for the same answer.
    ctx->now_ms = io->tick_args.now_ms;
    uint8_t probable = IDEMIP_ND6_NONE;
    for (uint8_t i = 0u; i < ND6_ROUTERS; i++)
    {
        const Nd6Router *r = ND6_ROUTER_AT(work, i);
        if (!r->used || r->neighbor >= ND6_NEIGHBORS)
        {
            continue;
        }
        const Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, r->neighbor);
        if (!n->used)
        {
            continue;
        }
        if (n->state == IDEMIP_ND6_REACHABLE)
        {
            probable = i;
            break;
        }
        if (n->state != IDEMIP_ND6_INCOMPLETE && probable == IDEMIP_ND6_NONE)
        {
            probable = i;
        }
    }
    if (probable == IDEMIP_ND6_NONE)
    {
        uint8_t start = ctx->router_cursor;
        for (uint8_t k = 0u; k < ND6_ROUTERS; k++)
        {
            uint8_t i = (uint8_t)(start + k);
            while (i >= ND6_ROUTERS)
            {
                i = (uint8_t)(i - ND6_ROUTERS);
            }
            if (ND6_ROUTER_AT(work, i)->used)
            {
                probable = i;
                uint8_t next = (uint8_t)(i + 1u);
                ctx->router_cursor = (next >= ND6_ROUTERS) ? 0u : next;
                break;
            }
        }
    }
    if (probable == IDEMIP_ND6_NONE)
    {
        return;
    }
    const Nd6Router *sel = ND6_ROUTER_AT(work, probable);
    uint8_t ni = sel->neighbor;
    io->router = probable;
    if (ni < ND6_NEIGHBORS && ND6_NEIGHBOR_AT(work, ni)->used)
    {
        io->next_hop = ND6_NEIGHBOR_AT(work, ni)->addr;
        nd6_report_neighbor(work, ni);
    }
    else
    {
        // sec 7.2: with no cache entry for it, "Address Resolution will be required before unicast
        // communications with that address can begin". The next hop is the router's address either
        // way, so the caller resolves it.
        io->next_hop = sel->addr;
    }
    io->status = IDEMIP_OK;
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
    io->desc = 0u;
    io->len = 0u;
    if (!ctx->ready || io->pending_args.neighbor >= IDEMIP_ND6_NUM_NEIGHBORS || io->pending_args.len == 0u)
    {
        return;
    }
    // RFC 4861 sec 7.2.2: "the sender MUST, for each neighbor, retain a small queue of packets waiting
    // for address resolution to complete. The queue MUST hold at least one packet... When a queue
    // overflows, the new arrival SHOULD replace the oldest entry." The oldest is the head of this
    // neighbor's queue, and its descriptor comes back in desc so the caller unpins it. A full table
    // with nothing of this neighbor's in it is BUSY, since another neighbor's resolution completes or
    // times out.
    uint8_t ni = io->pending_args.neighbor;
    Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, ni);
    if (!n->used)
    {
        return;
    }
    ctx->now_ms = io->tick_args.now_ms;
    uint8_t pi = IDEMIP_ND6_NONE;
    for (uint8_t k = 0u; k < ND6_PENDINGS; k++)
    {
        if (!ND6_PENDING_AT(work, k)->used)
        {
            pi = k;
            break;
        }
    }
    if (pi == IDEMIP_ND6_NONE)
    {
        if (n->pending_head >= ND6_PENDINGS)
        {
            io->status = IDEMIP_BUSY;
            return;
        }
        pi = n->pending_head;
        nd6_release_pending(work, pi);
    }
    Nd6Pending *p = ND6_PENDING_AT(work, pi);
    p->desc = io->pending_args.desc;
    p->len = io->pending_args.len;
    p->neighbor = ni;
    p->next = IDEMIP_ND6_NONE;
    p->used = IDEMIP_TRUE;
    // sec 7.2.2 retransmits every RetransTimer and gives up after MAX_MULTICAST_SOLICIT
    // solicitations, so a held frame outlives address resolution by no more than that.
    p->deadline_ms = ctx->now_ms + (nd6_retrans_ms(ctx) * (uint32_t)(IDEMIP_ND6_MAX_MULTICAST_SOLICIT + 1u));
    nd6_pending_link(work, ni, pi);
    ctx->pendings++;
    io->pending = pi;
    io->neighbor = ni;
    io->status = IDEMIP_OK;
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
    // RFC 4861 sec 7.2.2: "Once address resolution completes, the node transmits any queued packets."
    // The queue is in arrival order, so this takes the head. An empty queue is ERR, which is what
    // ends the caller's drain.
    uint8_t ni = io->pending_args.neighbor;
    Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, ni);
    if (!n->used || n->pending_head >= ND6_PENDINGS)
    {
        return;
    }
    ctx->now_ms = io->tick_args.now_ms;
    nd6_release_pending(work, n->pending_head);
    io->status = IDEMIP_OK;
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
    // RFC 4861 sec 6.3.4: a non-zero Cur Hop Limit sets CurHopLimit, a non-zero Reachable Time sets
    // BaseReachableTime and re-computes ReachableTime when it differs from the previous value, and
    // RetransTimer "SHOULD be copied from the Retrans Timer field, if the received value is
    // non-zero". An unspecified field "should be ignored and the host should continue using whatever
    // value it is already using". The MTU option is copied "so long as the value is greater than or
    // equal to the minimum link MTU [IPv6] and does not exceed the maximum LinkMTU value specified in
    // the link-type-specific document", which RFC 2464 sec 2 puts at 1500 octets for Ethernet.
    ctx->now_ms = io->tick_args.now_ms;
    const Nd6ParamsArgs *a = &io->params_args;
    if (a->cur_hop_limit != 0u)
    {
        ctx->cur_hop_limit = a->cur_hop_limit;
    }
    if (a->reachable_time_ms != 0u && a->reachable_time_ms != ctx->base_reachable_ms)
    {
        ctx->base_reachable_ms = a->reachable_time_ms;
        ctx->reachable_ms = nd6_draw_reachable(a->reachable_time_ms, a->rand);
    }
    if (a->retrans_timer_ms != 0u)
    {
        ctx->retrans_ms = a->retrans_timer_ms;
    }
    if (a->link_mtu >= (uint32_t)IDEMIP_IPV6_MIN_MTU && a->link_mtu <= (uint32_t)IDEMIP_ETH_MAX_PAYLOAD)
    {
        ctx->link_mtu = a->link_mtu;
    }
    ctx->managed = a->managed;
    ctx->other = a->other;
    io->cur_hop_limit = nd6_cur_hop_limit(ctx);
    io->reachable_ms = nd6_reachable_ms(ctx);
    io->retrans_ms = nd6_retrans_ms(ctx);
    io->link_mtu = nd6_link_mtu(ctx);
    io->managed = ctx->managed;
    io->other = ctx->other;
    io->status = IDEMIP_OK;
}

// RFC 4861 sec 6.3.5 ages the Prefix List and the Default Router List, and sec 7.3.3 walks the
// reachability machine. One event comes back per sweep, a released frame before a due solicitation,
// since a released frame carries the descriptor the caller has to unpin.
static void nd6_sweep(uint8_t *restrict work)
{
    Nd6Io *io = ND6_IO(work);
    Nd6Ctx *ctx = ND6_CTX(work);
    uint32_t now = ctx->now_ms;
    uint32_t retrans = nd6_retrans_ms(ctx);
    uint8_t expired = 0u;

    // sec 6.3.2: a new random ReachableTime "should be calculated when BaseReachableTime changes (due
    // to Router Advertisements) or at least every few hours even if no Router Advertisements are
    // received". A stream of identical advertisements changes nothing, so without this the first draw
    // stands forever and a rack of identically seeded nodes keeps its NUD probes synchronized.
    if (nd6_due(now, ctx->reachable_redraw_ms))
    {
        ctx->reachable_ms = nd6_draw_reachable(nd6_base_reachable_ms(ctx), io->tick_args.rand);
        ctx->reachable_redraw_ms = now + (uint32_t)IDEMIP_ND6_REACHABLE_REDRAW_MS;
    }

    // sec 6.3.5: "Whenever the invalidation timer expires for a Prefix List entry, that entry is
    // discarded." sec 5.1 exempts the entries whose timer is the "special 'infinity' timer value".
    for (uint8_t i = 0u; i < ND6_PREFIXES; i++)
    {
        Nd6Prefix *p = ND6_PREFIX_AT(work, i);
        if (p->used && !p->infinite && nd6_due(now, p->invalidate_ms))
        {
            memset(p, 0, sizeof *p);
            if (ctx->prefixes != 0u)
            {
                ctx->prefixes--;
            }
            expired++;
        }
    }

    // sec 6.3.5: "Whenever the Lifetime of an entry in the Default Router List expires, that entry is
    // discarded", and every Destination Cache entry through it performs next-hop determination again.
    for (uint8_t i = 0u; i < ND6_ROUTERS; i++)
    {
        const Nd6Router *r = ND6_ROUTER_AT(work, i);
        if (r->used && nd6_due(now, r->invalidate_ms))
        {
            nd6_drop_router(work, i);
            expired++;
        }
    }

    // sec 7.3.3: deleting a Neighbor Cache entry "signals the need for next-hop determination", so a
    // Destination Cache entry whose next hop is gone frees its slot.
    for (uint8_t i = 0u; i < ND6_DESTINATIONS; i++)
    {
        Nd6Destination *d = ND6_DESTINATION_AT(work, i);
        if (d->used && d->neighbor < ND6_NEIGHBORS && !ND6_NEIGHBOR_AT(work, d->neighbor)->used)
        {
            d->used = IDEMIP_FALSE;
            d->neighbor = IDEMIP_ND6_NONE;
            if (ctx->destinations != 0u)
            {
                ctx->destinations--;
            }
            expired++;
        }
    }

    // sec 7.3.3: "When ReachableTime milliseconds have passed since receipt of the last reachability
    // confirmation for a neighbor, the Neighbor Cache entry's state changes from REACHABLE to STALE",
    // and "If the entry is still in the DELAY state when the timer expires, the entry's state changes
    // to PROBE". Entering PROBE sends a solicitation, so the entry is left due at once.
    for (uint8_t i = 0u; i < ND6_NEIGHBORS; i++)
    {
        Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, i);
        if (!n->used || !nd6_due(now, n->next_event_ms))
        {
            continue;
        }
        if (n->state == IDEMIP_ND6_REACHABLE)
        {
            n->state = IDEMIP_ND6_STALE;
            n->probes = 0u;
            n->next_event_ms = now;
        }
        else if (n->state == IDEMIP_ND6_DELAY)
        {
            n->state = IDEMIP_ND6_PROBE;
            n->probes = 0u;
            n->next_event_ms = now;
        }
    }

    // sec 7.2.2: "If no Neighbor Advertisement is received after MAX_MULTICAST_SOLICIT solicitations,
    // address resolution has failed. The sender MUST return ICMP destination unreachable indications
    // with code 3 (Address Unreachable) for each packet queued awaiting address resolution."
    // sec 7.3.3: after MAX_UNICAST_SOLICIT solicitations in PROBE "retransmissions cease and the
    // entry SHOULD be deleted".
    idemip_bool reported = IDEMIP_FALSE;
    for (uint8_t i = 0u; i < ND6_NEIGHBORS && !reported; i++)
    {
        Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, i);
        if (!n->used || !nd6_due(now, n->next_event_ms))
        {
            continue;
        }
        uint8_t cap = (n->state == IDEMIP_ND6_INCOMPLETE) ? (uint8_t)IDEMIP_ND6_MAX_MULTICAST_SOLICIT
                                                          : (uint8_t)IDEMIP_ND6_MAX_UNICAST_SOLICIT;
        if ((n->state != IDEMIP_ND6_INCOMPLETE && n->state != IDEMIP_ND6_PROBE) || n->probes < cap)
        {
            continue;
        }
        if (n->pending_head < ND6_PENDINGS)
        {
            nd6_release_pending(work, n->pending_head);
            reported = IDEMIP_TRUE;
        }
        else
        {
            nd6_free_neighbor(work, i);
            expired++;
        }
    }

    // A frame held past its own deadline comes back so the descriptor it pins is not held forever.
    for (uint8_t i = 0u; i < ND6_PENDINGS && !reported; i++)
    {
        const Nd6Pending *p = ND6_PENDING_AT(work, i);
        if (p->used && nd6_due(now, p->deadline_ms))
        {
            nd6_release_pending(work, i);
            reported = IDEMIP_TRUE;
        }
    }

    // sec 7.2.2 sends the solicitation for an INCOMPLETE entry "to the solicited-node multicast
    // address corresponding to the target address", and sec 7.3.3 sends the PROBE one "to the
    // neighbor using the cached link-layer address". Both are rate-limited to one per neighbor per
    // RetransTimer, which the next deadline enforces.
    for (uint8_t i = 0u; i < ND6_NEIGHBORS && !reported; i++)
    {
        Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, i);
        if (!n->used || !nd6_due(now, n->next_event_ms))
        {
            continue;
        }
        if (n->state != IDEMIP_ND6_INCOMPLETE && n->state != IDEMIP_ND6_PROBE)
        {
            continue;
        }
        n->probes++;
        n->next_event_ms = now + retrans;
        io->solicit = IDEMIP_TRUE;
        io->multicast = (n->state == IDEMIP_ND6_INCOMPLETE) ? IDEMIP_TRUE : IDEMIP_FALSE;
        io->target = n->addr;
        nd6_report_neighbor(work, i);
        reported = IDEMIP_TRUE;
    }

    // The soonest deadline any table still holds, so the caller knows when to come back.
    uint32_t soonest = 0xFFFFFFFFu;
    for (uint8_t i = 0u; i < ND6_NEIGHBORS; i++)
    {
        const Nd6Neighbor *n = ND6_NEIGHBOR_AT(work, i);
        if (n->used && nd6_has_timer(n))
        {
            uint32_t rem = nd6_remaining(now, n->next_event_ms);
            soonest = (rem < soonest) ? rem : soonest;
        }
    }
    for (uint8_t i = 0u; i < ND6_PREFIXES; i++)
    {
        const Nd6Prefix *p = ND6_PREFIX_AT(work, i);
        if (p->used && !p->infinite)
        {
            uint32_t rem = nd6_remaining(now, p->invalidate_ms);
            soonest = (rem < soonest) ? rem : soonest;
        }
    }
    for (uint8_t i = 0u; i < ND6_ROUTERS; i++)
    {
        const Nd6Router *r = ND6_ROUTER_AT(work, i);
        if (r->used)
        {
            uint32_t rem = nd6_remaining(now, r->invalidate_ms);
            soonest = (rem < soonest) ? rem : soonest;
        }
    }
    for (uint8_t i = 0u; i < ND6_PENDINGS; i++)
    {
        const Nd6Pending *p = ND6_PENDING_AT(work, i);
        if (p->used)
        {
            uint32_t rem = nd6_remaining(now, p->deadline_ms);
            soonest = (rem < soonest) ? rem : soonest;
        }
    }
    io->next_event_ms = now + ((soonest == 0xFFFFFFFFu) ? 0u : soonest);
    io->expired = expired;
    io->status = (expired != 0u || reported) ? IDEMIP_OK : IDEMIP_BUSY;
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
    io->neighbor = IDEMIP_ND6_NONE;
    io->pending = IDEMIP_ND6_NONE;
    io->desc = 0u;
    io->len = 0u;
    if (!ctx->ready)
    {
        return;
    }
    ctx->now_ms = io->tick_args.now_ms;
    nd6_sweep(work);
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
