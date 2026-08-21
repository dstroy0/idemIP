// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for nd6, modeled on test_phy. It tests the CONTRACT and nothing else:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the interface, so two interfaces share not one byte
//   4. a canary past IDEMIP_ND6_BORROW is intact after every case
//   5. the published offset map is ordered, aligned, and does not overlap
//   6. clear zeroes the regions, and a borrow no one cleared is refused
//
// No case here asserts what an entry reports once its RFC 4861 logic exists, so none of them has to
// be inverted when it does.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/nd/nd6.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because RFC 4861 sec 5.1 keeps this state "for each
// interface". A canary follows each so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(IDEMIP_ALIGN) uint8_t work_a[IDEMIP_ND6_BORROW + 16];
static _Alignas(IDEMIP_ALIGN) uint8_t work_b[IDEMIP_ND6_BORROW + 16];

// The span clear owns: the context and the five tables.
#define STATE_OFF ((size_t)IDEMIP_ND6_OFF_CTX)
#define TABLE_OFF ((size_t)IDEMIP_ND6_OFF_NEIGHBORS)
#define STATE_END ((size_t)IDEMIP_ND6_OFF_END)

static const uint8_t g_addr_a[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_addr_b[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};
static const uint8_t g_lladdr[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_ND6_BORROW, CANARY, cap - IDEMIP_ND6_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_ND6_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_ND6_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// Every entry, in namespace order, so a new one added to Nd6Ns is added here too.
static void call_every_entry(uint8_t *w)
{
    Nd6.clear(w);
    Nd6.neighbor_find(w);
    Nd6.neighbor_set(w);
    Nd6.neighbor_confirm(w);
    Nd6.neighbor_used(w);
    Nd6.neighbor_remove(w);
    Nd6.dest_find(w);
    Nd6.dest_set(w);
    Nd6.prefix_set(w);
    Nd6.prefix_on_link(w);
    Nd6.router_set(w);
    Nd6.router_select(w);
    Nd6.pending_push(w);
    Nd6.pending_pop(w);
    Nd6.params_set(w);
    Nd6.tick(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the interface, and the operand block is in it, so two interfaces share no byte at
// all. This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    Nd6.clear(work_a);
    Nd6.clear(work_b);

    IDEMIP_ND6_IO(work_a)->neighbor_args.addr = g_addr_a;
    IDEMIP_ND6_IO(work_a)->neighbor_args.lladdr = g_lladdr;
    IDEMIP_ND6_IO(work_a)->neighbor_args.state = IDEMIP_ND6_STALE;
    IDEMIP_ND6_IO(work_b)->neighbor_args.addr = g_addr_b;
    IDEMIP_ND6_IO(work_b)->neighbor_args.lladdr = NULL;
    IDEMIP_ND6_IO(work_b)->neighbor_args.state = IDEMIP_ND6_INCOMPLETE;

    TEST_ASSERT_EQUAL_PTR(g_addr_a, IDEMIP_ND6_IO(work_a)->neighbor_args.addr);
    TEST_ASSERT_EQUAL_PTR(g_lladdr, IDEMIP_ND6_IO(work_a)->neighbor_args.lladdr);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_STALE, IDEMIP_ND6_IO(work_a)->neighbor_args.state);
    TEST_ASSERT_EQUAL_PTR(g_addr_b, IDEMIP_ND6_IO(work_b)->neighbor_args.addr);
    TEST_ASSERT_NULL(IDEMIP_ND6_IO(work_b)->neighbor_args.lladdr);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_INCOMPLETE, IDEMIP_ND6_IO(work_b)->neighbor_args.state);
}

// A call on one borrow reaches no byte of another, clear included, which is the widest-reaching entry
// this module has.
void test_clear_on_one_borrow_leaves_the_other_untouched(void)
{
    memset(work_b + STATE_OFF, 0xC3, STATE_END - STATE_OFF);
    IDEMIP_ND6_IO(work_b)->pending_args.desc = 0x7777u;

    Nd6.clear(work_a);

    for (size_t i = STATE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[i], "clear on one borrow wrote into another");
    }
    TEST_ASSERT_EQUAL_HEX16(0x7777u, IDEMIP_ND6_IO(work_b)->pending_args.desc);
}

// --- the published map -------------------------------------------------------

// The map is public so a reader can place every region without opening the .c. Each of the five
// tables starts where the one before it ends, so nothing overlaps and nothing is unreachable.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ND6_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_ND6_OFF_CTX >= sizeof(Nd6Io), "the context starts inside the operand block");
    TEST_ASSERT_TRUE_MESSAGE(TABLE_OFF >= (size_t)IDEMIP_ND6_OFF_CTX, "the neighbor cache starts before the context");
    TEST_ASSERT_EQUAL_size_t(TABLE_OFF + ((size_t)IDEMIP_ND6_NUM_NEIGHBORS << IDEMIP_ND6_NEIGHBOR_ENTRY_SHIFT),
                             (size_t)IDEMIP_ND6_OFF_DESTINATIONS);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_ND6_OFF_DESTINATIONS +
                                 ((size_t)IDEMIP_ND6_NUM_DESTINATIONS << IDEMIP_ND6_DESTINATION_ENTRY_SHIFT),
                             (size_t)IDEMIP_ND6_OFF_PREFIXES);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_ND6_OFF_PREFIXES +
                                 ((size_t)IDEMIP_ND6_NUM_PREFIXES << IDEMIP_ND6_PREFIX_ENTRY_SHIFT),
                             (size_t)IDEMIP_ND6_OFF_ROUTERS);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_ND6_OFF_ROUTERS +
                                 ((size_t)IDEMIP_ND6_NUM_ROUTERS << IDEMIP_ND6_ROUTER_ENTRY_SHIFT),
                             (size_t)IDEMIP_ND6_OFF_PENDING);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_ND6_OFF_PENDING +
                                 ((size_t)IDEMIP_ND6_PENDING << IDEMIP_ND6_PENDING_ENTRY_SHIFT),
                             STATE_END);
    TEST_ASSERT_TRUE_MESSAGE(STATE_END <= (size_t)IDEMIP_ND6_BORROW, "the map runs past IDEMIP_ND6_BORROW");
}

// Every table starts at the end of the region before it, so a misaligned offset would misalign the
// whole table behind it.
void test_every_published_offset_is_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ND6_OFF_CTX & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, TABLE_OFF & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ND6_OFF_DESTINATIONS & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ND6_OFF_PREFIXES & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ND6_OFF_ROUTERS & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ND6_OFF_PENDING & (IDEMIP_ALIGN - 1u));
}

// The operand block is reached at its published offset and nowhere else.
void test_the_io_macro_reaches_the_operand_block(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_ND6_OFF_IO, (uint8_t *)IDEMIP_ND6_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_ND6_OFF_IO, (uint8_t *)IDEMIP_ND6_IO(work_b));
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Nd6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
}

// The five tables come out of clear zeroed whatever was in them, so no stale neighbor, destination,
// prefix, router or queued frame survives into the next use of the borrow.
void test_clear_zeroes_the_tables(void)
{
    memset(work_a, 0xFF, IDEMIP_ND6_BORROW);
    Nd6.clear(work_a);
    for (size_t i = TABLE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00u, work_a[i], "clear left a table byte set");
    }
}

// The context comes out zeroed too, apart from the one octet nd6.h says clear leaves as the mark that
// these bytes were cleared. The RFC 4862 sec 5.4 state dad.c and slaac.c keep in this region is
// zeroed with it.
void test_clear_zeroes_the_context_apart_from_the_cleared_mark(void)
{
    memset(work_a, 0xFF, IDEMIP_ND6_BORROW);
    Nd6.clear(work_a);
    size_t set = 0;
    for (size_t i = STATE_OFF; i < TABLE_OFF; i++)
    {
        if (work_a[i] != 0x00u)
        {
            set++;
        }
    }
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1u, set, "clear must zero the context apart from the cleared mark");
}

// The operand block is the caller's, so clear does not touch what the caller put there.
void test_clear_leaves_the_operand_block_alone(void)
{
    Nd6.clear(work_a);
    IDEMIP_ND6_IO(work_a)->neighbor_args.addr = g_addr_a;
    IDEMIP_ND6_IO(work_a)->prefix_args.prefix_len = 64u;
    Nd6.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_addr_a, IDEMIP_ND6_IO(work_a)->neighbor_args.addr);
    TEST_ASSERT_EQUAL_UINT8(64u, IDEMIP_ND6_IO(work_a)->prefix_args.prefix_len);
}

// An entry is a function of its borrow alone, so clearing twice leaves the same bytes as clearing
// once.
void test_clear_is_idempotent(void)
{
    memset(work_a, 0xFF, IDEMIP_ND6_BORROW);
    Nd6.clear(work_a);
    memcpy(work_b, work_a, IDEMIP_ND6_BORROW);
    Nd6.clear(work_a);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(work_b + STATE_OFF, work_a + STATE_OFF, STATE_END - STATE_OFF);
}

// A borrow no one cleared is not this module's, so every entry that reads the tables refuses it
// rather than reading whatever the caller's memory held.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_ND6_IO(work_a)->neighbor_args.addr = g_addr_a;
    IDEMIP_ND6_IO(work_a)->dest_args.dst = g_addr_a;
    IDEMIP_ND6_IO(work_a)->prefix_args.prefix = g_addr_a;
    IDEMIP_ND6_IO(work_a)->router_args.addr = g_addr_a;

    Nd6.neighbor_find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.neighbor_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.neighbor_confirm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.neighbor_used(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.neighbor_remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.dest_find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.dest_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.prefix_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.prefix_on_link(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.router_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.pending_push(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.pending_pop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.params_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
}

// Clearing one borrow does not make another one cleared: the mark is in the borrow, not in the
// module.
void test_clearing_one_borrow_does_not_ready_the_other(void)
{
    Nd6.clear(work_a);
    Nd6.tick(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_b)->status);
}

// --- the contract's own constants --------------------------------------------

// Every index a result member carries is one octet, so no table may be as wide as the value that
// means "none of them".
void test_none_is_outside_every_table(void)
{
    TEST_ASSERT_TRUE(IDEMIP_ND6_NUM_NEIGHBORS < IDEMIP_ND6_NONE);
    TEST_ASSERT_TRUE(IDEMIP_ND6_NUM_DESTINATIONS < IDEMIP_ND6_NONE);
    TEST_ASSERT_TRUE(IDEMIP_ND6_NUM_PREFIXES < IDEMIP_ND6_NONE);
    TEST_ASSERT_TRUE(IDEMIP_ND6_NUM_ROUTERS < IDEMIP_ND6_NONE);
    TEST_ASSERT_TRUE(IDEMIP_ND6_PENDING < IDEMIP_ND6_NONE);
}

// RFC 4861 sec 5.1 names five reachability states and sec 7.3.2 defines each. They are distinct, and
// they fit one octet so a cache entry can hold one.
void test_the_five_reachability_states_are_distinct_and_one_octet(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_ND6_INCOMPLETE);
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_ND6_REACHABLE);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_ND6_STALE);
    TEST_ASSERT_EQUAL_INT(3, IDEMIP_ND6_DELAY);
    TEST_ASSERT_EQUAL_INT(4, IDEMIP_ND6_PROBE);
    TEST_ASSERT_EQUAL_size_t(1u, sizeof(IdemIpNd6State));
}

// RFC 4861 sec 4.6.2: a Valid Lifetime "of all one bits (0xffffffff) represents infinity".
void test_the_infinite_lifetime_is_all_one_bits(void)
{
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, IDEMIP_ND6_LIFETIME_INFINITE);
}

// RFC 4861 sec 6.3.2 draws ReachableTime between MIN_RANDOM_FACTOR and MAX_RANDOM_FACTOR times
// BaseReachableTime. sec 10 prints those as .5 and 1.5, which are a shift and an add.
void test_the_random_factors_are_shifts_of_base_reachable_time(void)
{
    TEST_ASSERT_EQUAL_UINT32(15000u, IDEMIP_ND6_MIN_RANDOM(IDEMIP_ND6_REACHABLE_TIME_MS));
    TEST_ASSERT_EQUAL_UINT32(45000u, IDEMIP_ND6_MAX_RANDOM(IDEMIP_ND6_REACHABLE_TIME_MS));
}

// =============================================================================
// The behavior cases.
//
// RFC 4861 prints message and option layouts but no worked example of a Neighbor Cache transition, a
// prefix list, or a router list, so nothing below is a byte vector out of a figure. Each case asserts
// a property the text states, quoted at the case, and the constants come from sec 10 read in full.
// =============================================================================

// RFC 3849 reserves 2001:DB8::/32 for documentation, so the prefixes and destinations below are drawn
// from it. The two prefix lengths differ so a longest prefix match has something to choose between.
static const uint8_t g_pfx32[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t g_pfx64[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t g_in64[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x05};
static const uint8_t g_in32[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0x05};
static const uint8_t g_off[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05};
static const uint8_t g_mcast[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_lladdr2[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
static uint8_t g_scratch_addr[IDEMIP_IP6_ADDR_LEN];

#define T IDEMIP_TRUE
#define F IDEMIP_FALSE

static void at(uint8_t *w, uint32_t ms)
{
    IDEMIP_ND6_IO(w)->tick_args.now_ms = ms;
}

static uint8_t nb_set(uint8_t *w, const uint8_t *addr, const uint8_t *ll, IdemIpNd6State st, idemip_bool router,
                      idemip_bool solicited, idemip_bool override)
{
    Nd6Io *io = IDEMIP_ND6_IO(w);
    io->neighbor_args.addr = addr;
    io->neighbor_args.lladdr = ll;
    io->neighbor_args.state = st;
    io->neighbor_args.is_router = router;
    io->neighbor_args.solicited = solicited;
    io->neighbor_args.override = override;
    Nd6.neighbor_set(w);
    return io->neighbor;
}

static IdemIpStatus nb_find(uint8_t *w, const uint8_t *addr)
{
    IDEMIP_ND6_IO(w)->neighbor_args.addr = addr;
    Nd6.neighbor_find(w);
    return IDEMIP_ND6_IO(w)->status;
}

static IdemIpNd6State nb_state(uint8_t *w, const uint8_t *addr)
{
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, nb_find(w, addr));
    return IDEMIP_ND6_IO(w)->state;
}

static void nb_index(uint8_t *w, uint8_t i)
{
    IDEMIP_ND6_IO(w)->neighbor_args.index = i;
}

static void pfx_set(uint8_t *w, const uint8_t *prefix, uint8_t len, uint32_t life_s, idemip_bool on_link)
{
    Nd6Io *io = IDEMIP_ND6_IO(w);
    io->prefix_args.prefix = prefix;
    io->prefix_args.prefix_len = len;
    io->prefix_args.lifetime_s = life_s;
    io->prefix_args.on_link = on_link;
    io->prefix_args.autonomous = F;
    Nd6.prefix_set(w);
}

static idemip_bool on_link_of(uint8_t *w, const uint8_t *addr)
{
    IDEMIP_ND6_IO(w)->prefix_args.prefix = addr;
    Nd6.prefix_on_link(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(w)->status);
    return IDEMIP_ND6_IO(w)->on_link;
}

// An advertisement carrying a Source Link-Layer Address option, which RFC 4861 sec 6.3.4 needs
// before it may touch the Neighbor Cache.
static void rtr_set_ll(uint8_t *w, const uint8_t *addr, const uint8_t *ll, uint16_t life_s)
{
    IDEMIP_ND6_IO(w)->router_args.addr = addr;
    IDEMIP_ND6_IO(w)->router_args.lladdr = ll;
    IDEMIP_ND6_IO(w)->router_args.lifetime_s = life_s;
    Nd6.router_set(w);
}

// One without it, which sec 4.2 permits "to facilitate in-bound load balancing over replicated
// interfaces".
static void rtr_set(uint8_t *w, const uint8_t *addr, uint16_t life_s)
{
    rtr_set_ll(w, addr, NULL, life_s);
}

// --- RFC 4861 sec 5.1, the tables are finite ---------------------------------

// sec 5.1 gives a host a Neighbor Cache, a Destination Cache, a Prefix List and a Default Router List.
// This build gives each of them a fixed number of entries, and what a call does when they are all
// taken is BUSY rather than ERR: sec 6.3.5 times a neighbor out, sec 7.3.3 deletes one that never
// answered, and a prefix or a router leaves when its lifetime runs down, so the room the caller asked
// for arrives on a later tick and asking again is the right thing to do.
static uint8_t g_many[24][IDEMIP_IP6_ADDR_LEN];

// 2001:DB8::n, out of the range RFC 3849 reserves for documentation.
static const uint8_t *nth(unsigned n)
{
    uint8_t *a = g_many[n];
    memset(a, 0, IDEMIP_IP6_ADDR_LEN);
    a[0] = 0x20u;
    a[1] = 0x01u;
    a[2] = 0x0Du;
    a[3] = 0xB8u;
    a[7] = (uint8_t)(n + 1u);  // inside the /64, so two of these are two prefixes
    a[15] = (uint8_t)(n + 1u); // and inside the interface identifier, so two addresses
    return a;
}

void test_a_full_destination_cache_is_busy(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    uint8_t nb = nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_REACHABLE, T, T, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    for (unsigned i = 0; i < (unsigned)IDEMIP_ND6_NUM_DESTINATIONS; i++)
    {
        Nd6Io *io = IDEMIP_ND6_IO(work_a);
        io->dest_args.dst = nth(i);
        io->dest_args.next_hop = g_addr_a;
        io->dest_args.pmtu = 0u;
        io->dest_args.neighbor = nb;
        Nd6.dest_set(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    }

    Nd6Io *io = IDEMIP_ND6_IO(work_a);
    io->dest_args.dst = nth((unsigned)IDEMIP_ND6_NUM_DESTINATIONS);
    io->dest_args.next_hop = g_addr_a;
    io->dest_args.pmtu = 0u;
    io->dest_args.neighbor = nb;
    Nd6.dest_set(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, io->status, "a full Destination Cache is BUSY, not ERR");
}

// sec 5.1's Destination Cache "maps a destination IP address to the IP address of the next-hop
// neighbor", so an entry that names no next hop is not one this cache can hold. Nothing is written and
// the call reports nothing, which is what tells it from the full case above.
void test_a_destination_with_no_next_hop_is_not_recorded(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    Nd6Io *io = IDEMIP_ND6_IO(work_a);
    io->dest_args.dst = g_in64;
    io->dest_args.next_hop = NULL;
    io->dest_args.pmtu = 0u;
    io->dest_args.neighbor = IDEMIP_ND6_NONE;
    Nd6.dest_set(work_a);

    io->dest_args.dst = g_in64;
    Nd6.dest_find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "a destination with no next hop was recorded");
}

void test_a_full_prefix_list_is_busy(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    for (unsigned i = 0; i < (unsigned)IDEMIP_ND6_NUM_PREFIXES; i++)
    {
        pfx_set(work_a, nth(i), 64u, 1800u, T);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    }
    pfx_set(work_a, nth((unsigned)IDEMIP_ND6_NUM_PREFIXES), 64u, 1800u, T);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_ND6_IO(work_a)->status,
                                  "a full Prefix List is BUSY: a prefix leaves when its lifetime runs down");
}

// sec 6.1.2's first validity check: "IP Source Address is a link-local address. Routers must use their
// link-local address as the source for Router Advertisement and Redirect messages so that hosts can
// uniquely identify routers." So a router is named by an fe80:: address and nothing else.
static const uint8_t *nth_ll(unsigned n)
{
    uint8_t *a = g_many[n];
    memset(a, 0, IDEMIP_IP6_ADDR_LEN);
    a[0] = 0xFEu;
    a[1] = 0x80u;
    a[15] = (uint8_t)(n + 1u);
    return a;
}

void test_a_full_default_router_list_is_busy(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    for (unsigned i = 0; i < (unsigned)IDEMIP_ND6_NUM_ROUTERS; i++)
    {
        rtr_set_ll(work_a, nth_ll(i), g_lladdr, 1800u); // sec 6.3.4 records the router as a neighbor
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    }
    rtr_set_ll(work_a, nth_ll((unsigned)IDEMIP_ND6_NUM_ROUTERS), g_lladdr, 1800u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_ND6_IO(work_a)->status,
                                  "a full Default Router List is BUSY, not ERR");
}

// RFC 4861 sec 4.6.2: "if the L flag is not set a host MUST NOT conclude that an address derived from
// the prefix is off-link. That is, it MUST NOT update a previous indication that the address is
// on-link." sec 6.3.4 gives the one way to cancel it: "advertise that prefix with the L-bit set and
// the Lifetime set to zero."
void test_an_l_clear_option_does_not_cancel_an_on_link_indication(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx64, 64u, 1800u, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_TRUE(on_link_of(work_a, g_in64));

    // The same prefix with L clear, which sec 6.3.4 calls a normal configuration.
    pfx_set(work_a, g_pfx64, 64u, 1800u, F);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(on_link_of(work_a, g_in64),
                             "an L=0 option cancelled a previous on-link indication");

    // The way that is cancelled: L set with the Lifetime zero, which sets the entry's invalidation
    // timer to now and the sec 6.3.5 sweep then discards it.
    pfx_set(work_a, g_pfx64, 64u, 0u, T);
    at(work_a, 1u);
    Nd6.tick(work_a);
    TEST_ASSERT_FALSE(on_link_of(work_a, g_in64));
}

// The same option must not take a Prefix List slot either, or a later L=1 option finds the list full.
void test_an_l_clear_option_takes_no_prefix_list_slot(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    for (uint8_t i = 0u; i < IDEMIP_ND6_NUM_PREFIXES + 1u; i++)
    {
        uint8_t p[IDEMIP_IP6_ADDR_LEN];
        memcpy(p, g_pfx64, IDEMIP_IP6_ADDR_LEN);
        p[7] = (uint8_t)(0x10u + i);
        pfx_set(work_a, p, 64u, 1800u, F);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status, "an L=0 option was refused");
    }
    // The list is still empty, so an L=1 option lands.
    pfx_set(work_a, g_pfx64, 64u, 1800u, T);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status, "L=0 options filled the Prefix List");
    TEST_ASSERT_TRUE(on_link_of(work_a, g_in64));
}

// RFC 4861 sec 4.2: "The Router Lifetime applies only to the router's usefulness as a default router;
// it does not apply to information contained in other message fields or options." sec 6.3.4: the
// Source Link-Layer Address "SHOULD be recorded in the Neighbor Cache entry for the router (creating
// an entry if necessary) and the IsRouter flag in the Neighbor Cache entry MUST be set to TRUE."
void test_a_zero_router_lifetime_still_records_the_link_layer_address(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set_ll(work_a, g_addr_a, g_lladdr, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    IDEMIP_ND6_IO(work_a)->neighbor_args.addr = g_addr_a;
    Nd6.neighbor_find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status,
                                  "a zero Router Lifetime created no Neighbor Cache entry");
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_lladdr, IDEMIP_ND6_IO(work_a)->lladdr, IDEMIP_MAC_LEN);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_ND6_IO(work_a)->is_router, "IsRouter was not set by a valid advertisement");
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_STALE, IDEMIP_ND6_IO(work_a)->state);
}

// Appendix D: "when there is no host vs. router information in the ND message, the receipt of the
// message MUST NOT cause a change to the IsRouter state." Timing a router out of the Default Router
// List is sec 6.3.5, which asks only that the entry go and the Destination Cache be updated.
void test_dropping_a_default_router_leaves_is_router_alone(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set_ll(work_a, g_addr_a, g_lladdr, 1800u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    // The router steps down as a default router but stays a router on the link.
    rtr_set_ll(work_a, g_addr_a, g_lladdr, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    IDEMIP_ND6_IO(work_a)->neighbor_args.addr = g_addr_a;
    Nd6.neighbor_find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_ND6_IO(work_a)->is_router,
                             "leaving the Default Router List cleared IsRouter");
}

static void push(uint8_t *w, uint8_t neighbor, uint16_t desc, uint16_t len)
{
    IDEMIP_ND6_IO(w)->pending_args.neighbor = neighbor;
    IDEMIP_ND6_IO(w)->pending_args.desc = desc;
    IDEMIP_ND6_IO(w)->pending_args.len = len;
    Nd6.pending_push(w);
}

static IdemIpStatus pop(uint8_t *w, uint8_t neighbor)
{
    IDEMIP_ND6_IO(w)->pending_args.neighbor = neighbor;
    Nd6.pending_pop(w);
    return IDEMIP_ND6_IO(w)->status;
}

// --- sec 10, the protocol constants ------------------------------------------

// RFC 4861 sec 10, page 78, read from the downloaded text: the node constants this unit's machine is
// built on.
void test_the_node_constants_are_the_ones_section_10_prints(void)
{
    TEST_ASSERT_EQUAL_UINT32(3u, IDEMIP_ND6_MAX_MULTICAST_SOLICIT);
    TEST_ASSERT_EQUAL_UINT32(3u, IDEMIP_ND6_MAX_UNICAST_SOLICIT);
    TEST_ASSERT_EQUAL_UINT32(30000u, IDEMIP_ND6_REACHABLE_TIME_MS);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_ND6_RETRANS_TIMER_MS);
    TEST_ASSERT_EQUAL_UINT32(5000u, IDEMIP_ND6_DELAY_FIRST_PROBE_MS);
}

// --- the neighbor cache, sec 5.1 and sec 7.2 ---------------------------------

// RFC 4861 sec 5.1 keys an entry "on the neighbor's on-link unicast IP address", so a lookup on that
// address finds it and a lookup on another does not.
void test_an_entry_is_keyed_on_the_neighbors_address(void)
{
    Nd6.clear(work_a);
    at(work_a, 1000u);
    TEST_ASSERT_EQUAL_UINT8(0u, nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, F, F, T));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, nb_find(work_a, g_addr_a));
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ND6_IO(work_a)->neighbor);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lladdr, IDEMIP_ND6_IO(work_a)->lladdr, IDEMIP_MAC_LEN);

    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, nb_find(work_a, g_addr_b));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ND6_NONE, IDEMIP_ND6_IO(work_a)->neighbor);
}

// RFC 4861 sec 7.3.3: an entry "enters the STALE state when created as a result of receiving packets
// other than solicited Neighbor Advertisements", and sec 5.2 creates one INCOMPLETE when address
// resolution starts. The created state is the caller's, so both arrive as asked.
void test_a_created_entry_takes_the_state_the_caller_names(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_STALE, nb_state(work_a, g_addr_a));

    nb_set(work_a, g_addr_b, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_INCOMPLETE, nb_state(work_a, g_addr_b));
    TEST_ASSERT_NULL_MESSAGE(IDEMIP_ND6_IO(work_a)->lladdr,
                             "sec 7.3.2 INCOMPLETE has no link-layer address to report");
}

// RFC 4861 sec 7.2.5 on an INCOMPLETE entry: "If the advertisement's Solicited flag is set, the state
// of the entry is set to REACHABLE; otherwise, it is set to STALE."
void test_an_advertisement_resolving_an_incomplete_entry_uses_the_solicited_flag(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_INCOMPLETE, F, T, F);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_REACHABLE, nb_state(work_a, g_addr_a));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lladdr, IDEMIP_ND6_IO(work_a)->lladdr, IDEMIP_MAC_LEN);

    nb_set(work_a, g_addr_b, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);
    nb_set(work_a, g_addr_b, g_lladdr2, IDEMIP_ND6_INCOMPLETE, F, F, F);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_STALE, nb_state(work_a, g_addr_b));
}

// RFC 4861 sec 7.2.5: on an INCOMPLETE entry, "If the link layer has addresses and no Target
// Link-Layer Address option is included, the receiving node SHOULD silently discard the received
// advertisement."
void test_an_advertisement_with_no_link_layer_address_leaves_an_incomplete_entry_alone(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);
    nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, T, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_INCOMPLETE, nb_state(work_a, g_addr_a));
}

// RFC 4861 sec 7.2.5 rule I.a: with the Override flag clear and a differing link-layer address, "If
// the state of the entry is REACHABLE, set it to STALE, but do not update the entry in any other
// way."
void test_an_override_clear_advertisement_makes_a_reachable_entry_stale_and_keeps_the_address(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_REACHABLE, F, F, T);
    nb_set(work_a, g_addr_a, g_lladdr2, IDEMIP_ND6_REACHABLE, F, F, F);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_STALE, nb_state(work_a, g_addr_a));
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(g_lladdr, IDEMIP_ND6_IO(work_a)->lladdr, IDEMIP_MAC_LEN,
                                         "sec 7.2.5 I.a must not update the entry in any other way");
}

// RFC 4861 sec 7.2.5 rule I.b: with the Override flag clear, a differing link-layer address and any
// state other than REACHABLE, "the received advertisement should be ignored and MUST NOT update the
// cache."
void test_an_override_clear_advertisement_is_ignored_outside_reachable(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
    nb_set(work_a, g_addr_a, g_lladdr2, IDEMIP_ND6_STALE, F, T, F);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_STALE, nb_state(work_a, g_addr_a));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lladdr, IDEMIP_ND6_IO(work_a)->lladdr, IDEMIP_MAC_LEN);
}

// RFC 4861 sec 7.2.5 rule II: with the Override flag set "The link-layer address in the Target
// Link-Layer Address option MUST be inserted in the cache", and "If the Solicited flag is set, the
// state of the entry MUST be set to REACHABLE."
void test_an_override_set_solicited_advertisement_replaces_the_address_and_makes_it_reachable(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
    nb_set(work_a, g_addr_a, g_lladdr2, IDEMIP_ND6_STALE, F, T, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_REACHABLE, nb_state(work_a, g_addr_a));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lladdr2, IDEMIP_ND6_IO(work_a)->lladdr, IDEMIP_MAC_LEN);
}

// RFC 4861 sec 7.2.5 rule II: "If the Solicited flag is zero and the link-layer address was updated
// with a different address, the state MUST be set to STALE. Otherwise, the entry's state remains
// unchanged."
void test_an_unsolicited_advertisement_changes_the_state_only_when_the_address_changes(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_REACHABLE, F, F, T);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_REACHABLE, F, F, T);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ND6_REACHABLE, nb_state(work_a, g_addr_a),
                                  "the same address leaves the state unchanged");

    nb_set(work_a, g_addr_a, g_lladdr2, IDEMIP_ND6_REACHABLE, F, F, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_STALE, nb_state(work_a, g_addr_a));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lladdr2, IDEMIP_ND6_IO(work_a)->lladdr, IDEMIP_MAC_LEN);
}

// RFC 4861 sec 7.2.5: "The IsRouter flag in the cache entry MUST be set based on the Router flag in
// the received advertisement. In those cases where the IsRouter flag changes from TRUE to FALSE as a
// result of this update, the node MUST remove that router from the Default Router List".
void test_the_router_flag_going_false_removes_the_router_from_the_default_router_list(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, T, F, T);
    rtr_set(work_a, g_addr_a, 1800u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ND6_NONE, IDEMIP_ND6_IO(work_a)->router);
}

// A cache with no free entry reports BUSY, since RFC 4861 sec 7.3.3 deletes an entry whose
// solicitations go unanswered and frees a slot.
void test_a_full_neighbor_cache_is_busy(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    memcpy(g_scratch_addr, g_addr_a, IDEMIP_IP6_ADDR_LEN);
    for (unsigned k = 0; k < IDEMIP_ND6_NUM_NEIGHBORS; k++)
    {
        g_scratch_addr[15] = (uint8_t)(0x10u + k);
        nb_set(work_a, g_scratch_addr, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    }
    g_scratch_addr[15] = 0x7Fu;
    nb_set(work_a, g_scratch_addr, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ND6_IO(work_a)->status);
}

// --- neighbor unreachability detection, sec 7.3 ------------------------------

// RFC 4861 sec 7.3.3: "When a reachability confirmation is received (either through upper-layer
// advice or a solicited Neighbor Advertisement), an entry's state changes to REACHABLE. The one
// exception is that upper-layer advice has no effect on entries in the INCOMPLETE state".
void test_confirm_makes_an_entry_reachable_but_not_an_incomplete_one(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    uint8_t stale = nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
    uint8_t incomplete = nb_set(work_a, g_addr_b, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);

    nb_index(work_a, stale);
    Nd6.neighbor_confirm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_REACHABLE, nb_state(work_a, g_addr_a));

    nb_index(work_a, incomplete);
    Nd6.neighbor_confirm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_INCOMPLETE, nb_state(work_a, g_addr_b));
}

// RFC 4861 sec 7.3.3: "The first time a node sends a packet to a neighbor whose entry is STALE, the
// sender changes the state to DELAY and sets a timer to expire in DELAY_FIRST_PROBE_TIME seconds."
// sec 7.3.2 REACHABLE: "While REACHABLE, no special action takes place as packets are sent."
void test_a_packet_to_a_stale_neighbor_makes_it_delay_and_leaves_reachable_alone(void)
{
    Nd6.clear(work_a);
    at(work_a, 4000u);
    uint8_t stale = nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
    uint8_t reachable = nb_set(work_a, g_addr_b, g_lladdr2, IDEMIP_ND6_REACHABLE, F, F, T);

    nb_index(work_a, stale);
    Nd6.neighbor_used(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_DELAY, IDEMIP_ND6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(4000u + IDEMIP_ND6_DELAY_FIRST_PROBE_MS, IDEMIP_ND6_IO(work_a)->next_event_ms);

    nb_index(work_a, reachable);
    Nd6.neighbor_used(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_REACHABLE, IDEMIP_ND6_IO(work_a)->state);
}

// RFC 4861 sec 7.3.3: "When ReachableTime milliseconds have passed since receipt of the last
// reachability confirmation for a neighbor, the Neighbor Cache entry's state changes from REACHABLE
// to STALE."
void test_reachable_becomes_stale_after_reachable_time(void)
{
    Nd6.clear(work_a);
    at(work_a, 1000u);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_REACHABLE, F, F, T);

    at(work_a, 1000u + IDEMIP_ND6_REACHABLE_TIME_MS - 1u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_REACHABLE, nb_state(work_a, g_addr_a));

    at(work_a, 1000u + IDEMIP_ND6_REACHABLE_TIME_MS);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_STALE, nb_state(work_a, g_addr_a));
}

// RFC 4861 sec 7.3.3: "If the entry is still in the DELAY state when the timer expires, the entry's
// state changes to PROBE", and "Upon entering the PROBE state, a node sends a unicast Neighbor
// Solicitation message to the neighbor using the cached link-layer address."
void test_delay_becomes_probe_and_sends_a_unicast_solicitation(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    uint8_t i = nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
    nb_index(work_a, i);
    Nd6.neighbor_used(work_a);

    at(work_a, IDEMIP_ND6_DELAY_FIRST_PROBE_MS - 1u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(F, IDEMIP_ND6_IO(work_a)->solicit);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_DELAY, nb_state(work_a, g_addr_a));

    at(work_a, IDEMIP_ND6_DELAY_FIRST_PROBE_MS);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(T, IDEMIP_ND6_IO(work_a)->solicit);
    TEST_ASSERT_EQUAL_INT_MESSAGE(F, IDEMIP_ND6_IO(work_a)->multicast,
                                  "a PROBE solicitation goes to the cached link-layer address");
    TEST_ASSERT_NOT_NULL(IDEMIP_ND6_IO(work_a)->lladdr);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_addr_a, IDEMIP_ND6_IO(work_a)->target, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_PROBE, IDEMIP_ND6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ND6_IO(work_a)->probes);
}

// RFC 4861 sec 7.2.2: address resolution "entails creating a Neighbor Cache entry in the INCOMPLETE
// state and transmitting a Neighbor Solicitation message... sent to the solicited-node multicast
// address corresponding to the target address", retransmitted "approximately every RetransTimer
// milliseconds". sec 7.3.3: "A node MUST NOT send Neighbor Solicitations to the same neighbor more
// frequently than once every RetransTimer milliseconds."
void test_an_incomplete_entry_multicasts_a_solicitation_once_per_retrans_timer(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);

    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(T, IDEMIP_ND6_IO(work_a)->solicit);
    TEST_ASSERT_EQUAL_INT(T, IDEMIP_ND6_IO(work_a)->multicast);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_addr_a, IDEMIP_ND6_IO(work_a)->target, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ND6_IO(work_a)->probes);

    at(work_a, IDEMIP_ND6_RETRANS_TIMER_MS - 1u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(F, IDEMIP_ND6_IO(work_a)->solicit, "sec 7.3.3 rate-limits to one per RetransTimer");

    at(work_a, IDEMIP_ND6_RETRANS_TIMER_MS);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(T, IDEMIP_ND6_IO(work_a)->solicit);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_ND6_IO(work_a)->probes);
}

// RFC 4861 sec 7.2.2: "If no Neighbor Advertisement is received after MAX_MULTICAST_SOLICIT
// solicitations, address resolution has failed", and sec 7.3.3 then deletes the entry so that
// "subsequent traffic to that neighbor invokes the next-hop determination procedure again".
void test_an_unanswered_incomplete_entry_is_deleted_after_max_multicast_solicit(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);

    for (unsigned k = 0; k < IDEMIP_ND6_MAX_MULTICAST_SOLICIT; k++)
    {
        at(work_a, (uint32_t)k * IDEMIP_ND6_RETRANS_TIMER_MS);
        Nd6.tick(work_a);
        TEST_ASSERT_EQUAL_INT(T, IDEMIP_ND6_IO(work_a)->solicit);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(k + 1u), IDEMIP_ND6_IO(work_a)->probes);
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, nb_find(work_a, g_addr_a));

    at(work_a, (uint32_t)IDEMIP_ND6_MAX_MULTICAST_SOLICIT * IDEMIP_ND6_RETRANS_TIMER_MS);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ND6_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, nb_find(work_a, g_addr_a), "sec 7.3.3 deletes the entry");
}

// RFC 4861 sec 7.3.3: "Note that all Neighbor Solicitations are rate-limited on a per-neighbor
// basis. A node MUST NOT send Neighbor Solicitations to the same neighbor more frequently than once
// every RetransTimer milliseconds." sec 6.3.4 lets a Router Advertisement set that timer, so the
// value is a remote party's. A deadline is one absolute stamp read as a span below half the clock's
// range, so a RetransTimer past that bound arms a deadline that is already past and the rate limit
// inverts into a solicitation on every tick - one Router Advertisement turning the node into a
// solicitation source.
void test_a_retrans_timer_past_the_deadline_span_still_rate_limits(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    memset(&IDEMIP_ND6_IO(work_a)->params_args, 0, sizeof IDEMIP_ND6_IO(work_a)->params_args);
    IDEMIP_ND6_IO(work_a)->params_args.retrans_timer_ms = 0xFFFFFFFFu;
    Nd6.params_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);

    unsigned sent = 0u;
    for (uint32_t t = 0u; t < 16u; t++)
    {
        at(work_a, t);
        Nd6.tick(work_a);
        if (IDEMIP_ND6_IO(work_a)->solicit)
        {
            sent++;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(sent <= 1u, "a RetransTimer past the deadline span solicited on every tick");
}

// RFC 4861 sec 7.3.3: "If no response is received after waiting RetransTimer milliseconds after
// sending the MAX_UNICAST_SOLICIT solicitations, retransmissions cease and the entry SHOULD be
// deleted." A probe is answered by a confirmation, which returns the entry to REACHABLE.
void test_a_probe_stops_after_max_unicast_solicit_and_a_confirmation_returns_it_to_reachable(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    uint8_t i = nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
    nb_index(work_a, i);
    Nd6.neighbor_used(work_a);

    uint32_t base = IDEMIP_ND6_DELAY_FIRST_PROBE_MS;
    for (unsigned k = 0; k < IDEMIP_ND6_MAX_UNICAST_SOLICIT; k++)
    {
        at(work_a, base + (uint32_t)k * IDEMIP_ND6_RETRANS_TIMER_MS);
        Nd6.tick(work_a);
        TEST_ASSERT_EQUAL_INT(T, IDEMIP_ND6_IO(work_a)->solicit);
        TEST_ASSERT_EQUAL_INT(F, IDEMIP_ND6_IO(work_a)->multicast);
    }
    nb_index(work_a, i);
    Nd6.neighbor_confirm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_REACHABLE, nb_state(work_a, g_addr_a));
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_ND6_IO(work_a)->probes, "a confirmation clears the unanswered probes");
}

void test_an_unanswered_probe_deletes_the_entry(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    uint8_t i = nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, F, F, T);
    nb_index(work_a, i);
    Nd6.neighbor_used(work_a);

    uint32_t base = IDEMIP_ND6_DELAY_FIRST_PROBE_MS;
    for (unsigned k = 0; k <= IDEMIP_ND6_MAX_UNICAST_SOLICIT; k++)
    {
        at(work_a, base + (uint32_t)k * IDEMIP_ND6_RETRANS_TIMER_MS);
        Nd6.tick(work_a);
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, nb_find(work_a, g_addr_a));
}

// --- the queued frames, sec 7.2.2 --------------------------------------------

// RFC 4861 sec 7.2.2: "the sender MUST, for each neighbor, retain a small queue of packets waiting
// for address resolution to complete... Once address resolution completes, the node transmits any
// queued packets." The queue is in arrival order, and an empty one ends the drain.
void test_queued_frames_come_back_in_arrival_order(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    uint8_t i = nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);

    push(work_a, i, 7u, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_ND6_IO(work_a)->len, "nothing was evicted, so no descriptor came back");
    push(work_a, i, 8u, 200u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, pop(work_a, i));
    TEST_ASSERT_EQUAL_UINT16(7u, IDEMIP_ND6_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_UINT16(100u, IDEMIP_ND6_IO(work_a)->len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, pop(work_a, i));
    TEST_ASSERT_EQUAL_UINT16(8u, IDEMIP_ND6_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_UINT16(200u, IDEMIP_ND6_IO(work_a)->len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, pop(work_a, i));
}

// RFC 4861 sec 7.2.2: "When a queue overflows, the new arrival SHOULD replace the oldest entry." The
// replaced descriptor comes back so the caller unpins it.
void test_a_full_queue_replaces_the_oldest_and_hands_its_descriptor_back(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    uint8_t i = nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);

    for (unsigned k = 0; k < IDEMIP_ND6_PENDING; k++)
    {
        push(work_a, i, (uint16_t)(10u + k), (uint16_t)(100u + k));
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    }
    push(work_a, i, 99u, 999u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(10u, IDEMIP_ND6_IO(work_a)->desc, "the oldest descriptor is handed back");
    TEST_ASSERT_EQUAL_UINT16(100u, IDEMIP_ND6_IO(work_a)->len);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, pop(work_a, i));
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(11u, IDEMIP_ND6_IO(work_a)->desc, "the second arrival is now the oldest");
}

// RFC 4861 sec 7.2.2: on failed resolution the sender "MUST return ICMP destination unreachable
// indications with code 3 (Address Unreachable) for each packet queued awaiting address resolution",
// so every queued descriptor comes back before the entry goes.
void test_removing_a_neighbor_hands_back_every_queued_descriptor_first(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    uint8_t i = nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);
    push(work_a, i, 21u, 300u);
    push(work_a, i, 22u, 400u);

    nb_index(work_a, i);
    Nd6.neighbor_remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(21u, IDEMIP_ND6_IO(work_a)->desc);

    Nd6.neighbor_remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(22u, IDEMIP_ND6_IO(work_a)->desc);

    Nd6.neighbor_remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, nb_find(work_a, g_addr_a));
}

// A sweep that fails address resolution hands back each queued descriptor before it deletes the
// entry, so no pinned descriptor is lost (RFC 4861 sec 7.2.2, PLAN sec 3.5).
void test_a_failed_resolution_releases_its_queued_descriptor_before_deleting_the_entry(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    uint8_t i = nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);
    push(work_a, i, 31u, 500u);

    for (unsigned k = 0; k < IDEMIP_ND6_MAX_MULTICAST_SOLICIT; k++)
    {
        at(work_a, (uint32_t)k * IDEMIP_ND6_RETRANS_TIMER_MS);
        Nd6.tick(work_a);
    }
    at(work_a, (uint32_t)IDEMIP_ND6_MAX_MULTICAST_SOLICIT * IDEMIP_ND6_RETRANS_TIMER_MS);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(31u, IDEMIP_ND6_IO(work_a)->desc, "the pinned descriptor comes back");
    TEST_ASSERT_EQUAL_UINT16(500u, IDEMIP_ND6_IO(work_a)->len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, nb_find(work_a, g_addr_a), "the entry outlives its queue by one sweep");

    at(work_a, (uint32_t)(IDEMIP_ND6_MAX_MULTICAST_SOLICIT + 1u) * IDEMIP_ND6_RETRANS_TIMER_MS);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, nb_find(work_a, g_addr_a));
}

// --- the prefix list, sec 6.3.4 and RFC 5942 ---------------------------------

// RFC 4861 sec 6.3.4: "If the prefix is not already present in the Prefix List, and the Prefix
// Information option's Valid Lifetime field is non-zero, create a new entry for the prefix and
// initialize its invalidation timer to the Valid Lifetime value".
void test_a_prefix_with_a_non_zero_lifetime_is_installed_and_makes_its_addresses_on_link(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx64, 64u, 1800u, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ND6_IO(work_a)->prefix);
    TEST_ASSERT_EQUAL_INT(T, on_link_of(work_a, g_in64));
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ND6_IO(work_a)->prefix);
}

// RFC 4861 sec 6.3.4: "If the Prefix Information option's Valid Lifetime field is zero, and the
// prefix is not present in the host's Prefix List, silently ignore the option."
void test_a_zero_lifetime_on_an_unlisted_prefix_is_silently_ignored(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx64, 64u, 0u, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ND6_NONE, IDEMIP_ND6_IO(work_a)->prefix);
    TEST_ASSERT_EQUAL_INT(F, on_link_of(work_a, g_in64));
}

// RFC 4861 sec 6.3.4: a prefix already listed has its timer reset, and "If the new Lifetime value is
// zero, time-out the prefix immediately (see Section 6.3.5)."
void test_a_zero_lifetime_times_out_a_listed_prefix(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx64, 64u, 1800u, T);
    TEST_ASSERT_EQUAL_INT(T, on_link_of(work_a, g_in64));

    pfx_set(work_a, g_pfx64, 64u, 0u, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ND6_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT(F, on_link_of(work_a, g_in64));
}

// RFC 4861 sec 6.3.4: "If the prefix is already present in the host's Prefix List as the result of a
// previously received advertisement, reset its invalidation timer to the Valid Lifetime value".
void test_a_second_advertisement_resets_the_invalidation_timer(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx64, 64u, 10u, T);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ND6_IO(work_a)->prefix);

    at(work_a, 9000u);
    pfx_set(work_a, g_pfx64, 64u, 10u, T);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_ND6_IO(work_a)->prefix, "the same prefix reuses its entry");

    at(work_a, 10000u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(T, on_link_of(work_a, g_in64), "the reset timer has not expired yet");
    at(work_a, 19000u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(F, on_link_of(work_a, g_in64));
}

// RFC 5942 sec 4 rule 2: "if the RA advertises a prefix with the on-link (L) bit set and later the
// Valid Lifetime expires, the host MUST then consider addresses of the prefix to be off-link".
void test_an_expired_prefix_makes_its_addresses_off_link_again(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx64, 64u, 2u, T);
    at(work_a, 1999u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(T, on_link_of(work_a, g_in64));
    at(work_a, 2000u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ND6_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT(F, on_link_of(work_a, g_in64));
}

// RFC 4861 sec 5.1: the Prefix List has "a special 'infinity' timer value" that "specifies that a
// prefix remains valid forever", and sec 4.6.2 spells it as all one bits.
void test_an_infinite_lifetime_prefix_never_expires(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx64, 64u, IDEMIP_ND6_LIFETIME_INFINITE, T);
    at(work_a, 0xF0000000u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(T, on_link_of(work_a, g_in64));
}

// RFC 4861 sec 6.3.4: "If the prefix is the link-local prefix, silently ignore the Prefix Information
// option." sec 5.1 keeps it on the list anyway: "The link-local prefix is considered to be on the
// prefix list with an infinite invalidation timer regardless of whether routers are advertising a
// prefix for it."
void test_the_link_local_prefix_is_ignored_as_an_option_and_on_link_regardless(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_addr_a, 64u, 1800u, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(IDEMIP_ND6_NONE, IDEMIP_ND6_IO(work_a)->prefix,
                                    "sec 6.3.4 silently ignores the link-local prefix option");
    TEST_ASSERT_EQUAL_INT(T, on_link_of(work_a, g_addr_b));
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(IDEMIP_ND6_NONE, IDEMIP_ND6_IO(work_a)->prefix,
                                    "sec 5.1's permanent entry is not one of the table's");
}

// RFC 4861 sec 5.2: "The sender performs a longest prefix match against the Prefix List to determine
// whether the packet's destination is on- or off-link."
void test_the_longest_matching_prefix_wins(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx32, 32u, 1800u, T);
    uint8_t shorter = IDEMIP_ND6_IO(work_a)->prefix;
    pfx_set(work_a, g_pfx64, 64u, 1800u, T);
    uint8_t longer = IDEMIP_ND6_IO(work_a)->prefix;
    TEST_ASSERT_NOT_EQUAL_UINT8(shorter, longer);

    TEST_ASSERT_EQUAL_INT(T, on_link_of(work_a, g_in64));
    TEST_ASSERT_EQUAL_UINT8(longer, IDEMIP_ND6_IO(work_a)->prefix);

    TEST_ASSERT_EQUAL_INT(T, on_link_of(work_a, g_in32));
    TEST_ASSERT_EQUAL_UINT8(shorter, IDEMIP_ND6_IO(work_a)->prefix);
}

// RFC 5942 sec 3 point 2: "a destination is assumed to be off-link, unless there is explicit
// information indicating that it is on-link", and sec 4 rule 1 forbids inventing one.
void test_an_address_with_no_on_link_information_is_off_link(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx64, 64u, 1800u, T);
    TEST_ASSERT_EQUAL_INT(F, on_link_of(work_a, g_off));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ND6_NONE, IDEMIP_ND6_IO(work_a)->prefix);
}

// RFC 4861 sec 6.3.4: "a Prefix Information option with the on-link flag set to zero conveys no
// information concerning on-link determination and MUST NOT be interpreted to mean that addresses
// covered by the prefix are off-link."
void test_a_prefix_without_the_l_flag_conveys_no_on_link_information(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx64, 64u, 1800u, F);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(F, on_link_of(work_a, g_in64));
}

// RFC 4861 sec 5.2: "For multicast packets, the next-hop is always the (multicast) destination
// address and is considered to be on-link."
void test_a_multicast_destination_is_on_link(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(T, on_link_of(work_a, g_mcast));
}

// RFC 4861 sec 4.6.2: the Prefix Length "value ranges from 0 to 128". A wider one is a bad argument.
void test_a_prefix_length_past_128_is_refused(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    pfx_set(work_a, g_pfx64, 129u, 1800u, T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
}

// --- the default router list, sec 6.3.4 and sec 6.3.6 ------------------------

// RFC 4861 sec 6.3.4: "If the address is not already present in the host's Default Router List, and
// the advertisement's Router Lifetime is non-zero, create a new entry in the list." With a Source
// Link-Layer Address option the same section reaches the Neighbor Cache too: "the link-layer address
// SHOULD be recorded in the Neighbor Cache entry for the router (creating an entry if necessary) and
// the IsRouter flag in the Neighbor Cache entry MUST be set to TRUE... If a Neighbor Cache entry is
// created for the router, its reachability state MUST be set to STALE."
void test_a_router_advertising_its_link_layer_address_is_listed_and_cached_stale(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set_ll(work_a, g_addr_a, g_lladdr, 1800u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ND6_IO(work_a)->router);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, nb_find(work_a, g_addr_a));
    TEST_ASSERT_EQUAL_INT_MESSAGE(T, IDEMIP_ND6_IO(work_a)->is_router, "sec 6.3.4 sets IsRouter TRUE");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ND6_STALE, IDEMIP_ND6_IO(work_a)->state,
                                  "a cache entry created for a router MUST be set to STALE");
}

// RFC 4861 sec 7.2: "It is possible that a host may receive a solicitation, a router advertisement,
// or a Redirect message without a link-layer address option included. These messages MUST NOT create
// or update neighbor cache entries, except with respect to the IsRouter flag as specified in Sections
// 6.3.4 and 7.2.5. If a Neighbor Cache entry does not exist for the source of such a message, Address
// Resolution will be required before unicast communications with that address can begin."
//
// sec 4.2 permits the omission "to facilitate in-bound load balancing over replicated interfaces", so
// the router is still listed - sec 6.3.4 keeps the Default Router List in terms of addresses, and
// requires a host to "retain at least two router addresses". Without this, one advertisement per
// source fills the Neighbor Cache with entries that hold no link-layer address.
void test_a_router_advertising_no_link_layer_address_is_listed_without_a_cache_entry(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set(work_a, g_addr_a, 1800u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_ND6_IO(work_a)->router,
                                    "sec 6.3.4 lists the router whether or not it advertised an address");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, nb_find(work_a, g_addr_a),
                                  "sec 7.2 forbids an advertisement with no link-layer address option "
                                  "from creating a neighbor cache entry");

    // It is still the router the selection returns, and the next hop is its address, which is what
    // address resolution then runs on.
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ND6_IO(work_a)->router);
    TEST_ASSERT_NOT_NULL_MESSAGE(IDEMIP_ND6_IO(work_a)->next_hop, "the selected router named no next hop");
    TEST_ASSERT_EQUAL_MEMORY(g_addr_a, IDEMIP_ND6_IO(work_a)->next_hop, IDEMIP_IP6_ADDR_LEN);
}

// A later advertisement that does carry the option fills in the cache entry sec 7.2 held back.
void test_a_later_advertisement_with_a_link_layer_address_fills_the_cache_entry(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set(work_a, g_addr_a, 1800u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, nb_find(work_a, g_addr_a));

    rtr_set_ll(work_a, g_addr_a, g_lladdr, 1800u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_ND6_IO(work_a)->router, "the router was listed twice");
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, nb_find(work_a, g_addr_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ND6_STALE, IDEMIP_ND6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_INT(T, IDEMIP_ND6_IO(work_a)->is_router);
}

// RFC 4861 sec 6.3.4 conditions creation on a non-zero Router Lifetime, so a zero one on a router
// that is not listed creates nothing at all.
void test_a_zero_lifetime_on_an_unlisted_router_creates_nothing(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set(work_a, g_addr_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ND6_NONE, IDEMIP_ND6_IO(work_a)->router);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, nb_find(work_a, g_addr_a), "no Neighbor Cache entry is created either");
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
}

// RFC 4861 sec 6.3.4: "If the address is already present in the host's Default Router List and the
// received Router Lifetime value is zero, immediately time-out the entry as specified in Section
// 6.3.5."
void test_a_zero_lifetime_times_out_a_listed_router(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set(work_a, g_addr_a, 1800u);
    rtr_set(work_a, g_addr_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
}

// RFC 4861 sec 6.3.5: "Whenever the Lifetime of an entry in the Default Router List expires, that
// entry is discarded."
void test_a_router_lifetime_expires_the_entry(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set(work_a, g_addr_a, 2u);
    at(work_a, 1999u);
    Nd6.tick(work_a);
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    at(work_a, 2000u);
    Nd6.tick(work_a);
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
}

// RFC 4861 sec 6.3.5: "When removing a router from the Default Router list, the node MUST update the
// Destination Cache in such a way that all entries using the router perform next-hop determination
// again rather than continue sending traffic to the (deleted) router."
void test_removing_a_router_makes_its_destinations_redo_next_hop_determination(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set_ll(work_a, g_addr_a, g_lladdr, 1800u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, nb_find(work_a, g_addr_a));
    uint8_t ni = IDEMIP_ND6_IO(work_a)->neighbor;

    IDEMIP_ND6_IO(work_a)->dest_args.dst = g_off;
    IDEMIP_ND6_IO(work_a)->dest_args.next_hop = g_addr_a;
    IDEMIP_ND6_IO(work_a)->dest_args.pmtu = 1500u;
    IDEMIP_ND6_IO(work_a)->dest_args.neighbor = ni;
    Nd6.dest_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    rtr_set(work_a, g_addr_a, 0u);
    IDEMIP_ND6_IO(work_a)->dest_args.dst = g_off;
    Nd6.dest_find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status,
                                  "the destination must redo next-hop determination");
}

// RFC 4861 sec 6.3.6 rule 1: "Routers that are reachable or probably reachable (i.e., in any state
// other than INCOMPLETE) SHOULD be preferred over routers whose reachability is unknown or suspect
// (i.e., in the INCOMPLETE state, or for which no Neighbor Cache entry exists)."
void test_select_prefers_a_router_that_is_not_incomplete(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set(work_a, g_addr_a, 1800u); // no link-layer address advertised, so no cache entry exists
    nb_set(work_a, g_addr_b, g_lladdr2, IDEMIP_ND6_STALE, T, F, T);
    rtr_set(work_a, g_addr_b, 1800u);

    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(g_addr_b, IDEMIP_ND6_IO(work_a)->next_hop, IDEMIP_IP6_ADDR_LEN,
                                         "the STALE router is preferred over the INCOMPLETE one");
}

// RFC 4861 sec 6.3.6 rule 1 also prefers the one known reachable, since REACHABLE is the only state
// that means "Positive confirmation was received within the last ReachableTime milliseconds"
// (sec 7.3.2).
void test_select_prefers_a_reachable_router_over_a_stale_one(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_STALE, T, F, T);
    rtr_set(work_a, g_addr_a, 1800u);
    nb_set(work_a, g_addr_b, g_lladdr2, IDEMIP_ND6_REACHABLE, T, F, T);
    rtr_set(work_a, g_addr_b, 1800u);

    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_addr_b, IDEMIP_ND6_IO(work_a)->next_hop, IDEMIP_IP6_ADDR_LEN);
}

// RFC 4861 sec 6.3.6 rule 2: "When no routers on the list are known to be reachable or probably
// reachable, routers SHOULD be selected in a round-robin fashion, so that subsequent requests for a
// default router do not return the same router until all other routers have been selected."
void test_select_round_robins_among_routers_of_unknown_reachability(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set(work_a, g_addr_a, 1800u);
    rtr_set(work_a, g_addr_b, 1800u);

    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    uint8_t first = IDEMIP_ND6_IO(work_a)->router;
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    uint8_t second = IDEMIP_ND6_IO(work_a)->router;
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(first, second, "a second request must not return the same router");
}

// RFC 5942 sec 4 rule 4c: with an empty Default Router List and no other on-link information "the
// host should send an ICMPv6 Destination Unreachable indication", which is an answer rather than a
// condition to retry.
void test_select_on_an_empty_default_router_list_is_an_error(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ND6_NONE, IDEMIP_ND6_IO(work_a)->router);
    TEST_ASSERT_NULL(IDEMIP_ND6_IO(work_a)->next_hop);
}

// --- the destination cache, sec 5.1, sec 5.2 and sec 8.3 ---------------------

// RFC 4861 sec 5.1: "the Destination Cache maps a destination IP address to the IP address of the
// next-hop neighbor", and stores with it "the Path MTU (PMTU)".
void test_a_destination_maps_to_its_next_hop_and_path_mtu(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    IDEMIP_ND6_IO(work_a)->dest_args.dst = g_off;
    IDEMIP_ND6_IO(work_a)->dest_args.next_hop = g_addr_a;
    IDEMIP_ND6_IO(work_a)->dest_args.pmtu = 1400u;
    IDEMIP_ND6_IO(work_a)->dest_args.neighbor = IDEMIP_ND6_NONE;
    Nd6.dest_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);

    IDEMIP_ND6_IO(work_a)->dest_args.dst = g_off;
    Nd6.dest_find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_addr_a, IDEMIP_ND6_IO(work_a)->next_hop, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT16(1400u, IDEMIP_ND6_IO(work_a)->pmtu);
}

// RFC 4861 sec 8.3: "A host receiving a valid redirect SHOULD update its Destination Cache
// accordingly so that subsequent traffic goes to the specified target." sec 5.2 keeps the rest of the
// entry: "it is generally beneficial to retain such cached information as the PMTU".
void test_a_redirect_revises_the_next_hop_and_keeps_the_path_mtu(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    IDEMIP_ND6_IO(work_a)->dest_args.dst = g_off;
    IDEMIP_ND6_IO(work_a)->dest_args.next_hop = g_addr_a;
    IDEMIP_ND6_IO(work_a)->dest_args.pmtu = 1400u;
    IDEMIP_ND6_IO(work_a)->dest_args.neighbor = IDEMIP_ND6_NONE;
    Nd6.dest_set(work_a);
    uint8_t first = IDEMIP_ND6_IO(work_a)->destination;

    IDEMIP_ND6_IO(work_a)->dest_args.next_hop = g_addr_b;
    IDEMIP_ND6_IO(work_a)->dest_args.pmtu = 0u;
    Nd6.dest_set(work_a);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(first, IDEMIP_ND6_IO(work_a)->destination, "the same destination reuses its entry");
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_addr_b, IDEMIP_ND6_IO(work_a)->next_hop, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(1400u, IDEMIP_ND6_IO(work_a)->pmtu, "a zero PMTU leaves the held one alone");
}

// RFC 4861 sec 5.2: "When the sending node has a packet to send, it first examines the Destination
// Cache. If no entry exists for the destination, next-hop determination is invoked".
void test_finding_an_unknown_destination_is_an_error(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    IDEMIP_ND6_IO(work_a)->dest_args.dst = g_off;
    Nd6.dest_find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ND6_NONE, IDEMIP_ND6_IO(work_a)->destination);
    TEST_ASSERT_NULL(IDEMIP_ND6_IO(work_a)->next_hop);
}

// --- the host variables, sec 6.3.2 and sec 6.3.4 -----------------------------

// RFC 4861 sec 6.3.4: "If the received Cur Hop Limit value is non-zero, the host SHOULD set its
// CurHopLimit variable to the received value", the same for Reachable Time and Retrans Timer, and an
// unspecified field "should be ignored and the host should continue using whatever value it is
// already using".
void test_an_unspecified_field_leaves_the_host_variable_alone(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    Nd6Io *io = IDEMIP_ND6_IO(work_a);
    io->params_args.cur_hop_limit = 60u;
    io->params_args.retrans_timer_ms = 2000u;
    io->params_args.reachable_time_ms = 20000u;
    io->params_args.link_mtu = 1400u;
    io->params_args.rand = 0u;
    io->params_args.managed = T;
    io->params_args.other = F;
    Nd6.params_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT8(60u, io->cur_hop_limit);
    TEST_ASSERT_EQUAL_UINT32(2000u, io->retrans_ms);
    TEST_ASSERT_EQUAL_UINT32(1400u, io->link_mtu);
    TEST_ASSERT_EQUAL_INT(T, io->managed);

    io->params_args.cur_hop_limit = 0u;
    io->params_args.retrans_timer_ms = 0u;
    io->params_args.reachable_time_ms = 0u;
    io->params_args.link_mtu = 0u;
    Nd6.params_set(work_a);
    TEST_ASSERT_EQUAL_UINT8(60u, io->cur_hop_limit);
    TEST_ASSERT_EQUAL_UINT32(2000u, io->retrans_ms);
    TEST_ASSERT_EQUAL_UINT32(1400u, io->link_mtu);
}

// RFC 4861 sec 6.3.2: ReachableTime "should be a uniformly distributed random value between
// MIN_RANDOM_FACTOR and MAX_RANDOM_FACTOR times BaseReachableTime milliseconds". sec 10 prints those
// as .5 and 1.5, so the low end of the draw is the base halved and the high end is one base above it.
void test_reachable_time_is_drawn_between_the_two_random_factors(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    Nd6Io *io = IDEMIP_ND6_IO(work_a);
    io->params_args.cur_hop_limit = 0u;
    io->params_args.retrans_timer_ms = 0u;
    io->params_args.link_mtu = 0u;

    io->params_args.reachable_time_ms = 30000u;
    io->params_args.rand = 0u;
    Nd6.params_set(work_a);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(IDEMIP_ND6_MIN_RANDOM(30000u), io->reachable_ms,
                                     "the smallest word draws MIN_RANDOM_FACTOR times the base");

    Nd6.clear(work_a);
    io->params_args.reachable_time_ms = 30000u;
    io->params_args.rand = 0x80000000u;
    Nd6.params_set(work_a);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(30000u, io->reachable_ms, "the midpoint word draws the base itself");

    Nd6.clear(work_a);
    io->params_args.reachable_time_ms = 30000u;
    io->params_args.rand = 0xFFFFFFFFu;
    Nd6.params_set(work_a);
    TEST_ASSERT_TRUE(io->reachable_ms >= IDEMIP_ND6_MIN_RANDOM(30000u));
    TEST_ASSERT_TRUE_MESSAGE(io->reachable_ms < IDEMIP_ND6_MAX_RANDOM(30000u),
                             "the draw stays under MAX_RANDOM_FACTOR times the base");
}

// RFC 4861 sec 6.3.4: "If the new value differs from the previous value, the host SHOULD re-compute a
// new random ReachableTime value." An unchanged BaseReachableTime is not a new value.
void test_a_repeated_reachable_time_does_not_redraw(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    Nd6Io *io = IDEMIP_ND6_IO(work_a);
    io->params_args.cur_hop_limit = 0u;
    io->params_args.retrans_timer_ms = 0u;
    io->params_args.link_mtu = 0u;

    io->params_args.reachable_time_ms = 30000u;
    io->params_args.rand = 0u;
    Nd6.params_set(work_a);
    uint32_t drawn = io->reachable_ms;

    io->params_args.rand = 0xFFFFFFFFu;
    Nd6.params_set(work_a);
    TEST_ASSERT_EQUAL_UINT32(drawn, io->reachable_ms);

    io->params_args.reachable_time_ms = 20000u;
    Nd6.params_set(work_a);
    TEST_ASSERT_NOT_EQUAL_UINT32_MESSAGE(drawn, io->reachable_ms, "a changed base re-computes the draw");
}

// RFC 4861 sec 6.3.4: the MTU option is copied "so long as the value is greater than or equal to the
// minimum link MTU [IPv6] and does not exceed the maximum LinkMTU value specified in the link-type-
// specific document". RFC 8200 sec 5 fixes the minimum at 1280, and RFC 2464 sec 2 fixes the Ethernet
// maximum at 1500: an option "specifying an MTU larger than 1500... must be otherwise ignored".
void test_an_mtu_option_outside_the_link_bounds_is_not_copied(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    Nd6Io *io = IDEMIP_ND6_IO(work_a);
    io->params_args.cur_hop_limit = 0u;
    io->params_args.retrans_timer_ms = 0u;
    io->params_args.reachable_time_ms = 0u;
    io->params_args.rand = 0u;

    io->params_args.link_mtu = IDEMIP_IPV6_MIN_MTU - 1u;
    Nd6.params_set(work_a);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_ETH_MAX_PAYLOAD, io->link_mtu);

    io->params_args.link_mtu = IDEMIP_ETH_MAX_PAYLOAD + 1u;
    Nd6.params_set(work_a);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_ETH_MAX_PAYLOAD, io->link_mtu);

    io->params_args.link_mtu = IDEMIP_IPV6_MIN_MTU;
    Nd6.params_set(work_a);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_IPV6_MIN_MTU, io->link_mtu);
}

// RFC 4861 sec 6.3.4: "The RetransTimer variable SHOULD be copied from the Retrans Timer field", and
// sec 7.2.2 retransmits "approximately every RetransTimer milliseconds", so an advertised value
// governs the interval the sweep uses.
void test_the_advertised_retrans_timer_governs_the_solicitation_interval(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    Nd6Io *io = IDEMIP_ND6_IO(work_a);
    io->params_args.cur_hop_limit = 0u;
    io->params_args.reachable_time_ms = 0u;
    io->params_args.link_mtu = 0u;
    io->params_args.rand = 0u;
    io->params_args.retrans_timer_ms = 4000u;
    Nd6.params_set(work_a);

    nb_set(work_a, g_addr_a, NULL, IDEMIP_ND6_INCOMPLETE, F, F, F);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(T, IDEMIP_ND6_IO(work_a)->solicit);

    at(work_a, 3999u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(F, IDEMIP_ND6_IO(work_a)->solicit);
    at(work_a, 4000u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(T, IDEMIP_ND6_IO(work_a)->solicit);
}

// --- the sweep ----------------------------------------------------------------

// A sweep with nothing due reports BUSY, since the caller comes back on a later tick rather than
// treating an idle table as a failure (PLAN sec 3.4a).
void test_a_sweep_with_nothing_due_is_busy(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ND6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ND6_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT(F, IDEMIP_ND6_IO(work_a)->solicit);
}

// The sweep reports when the next Neighbor Unreachability Detection event is due (RFC 4861 sec 5.1,
// "the time the next Neighbor Unreachability Detection event is scheduled to take place").
void test_a_sweep_reports_the_soonest_deadline(void)
{
    Nd6.clear(work_a);
    at(work_a, 1000u);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_REACHABLE, F, F, T);
    pfx_set(work_a, g_pfx64, 64u, 2u, T);

    Nd6.tick(work_a);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1000u + 2000u, IDEMIP_ND6_IO(work_a)->next_event_ms,
                                     "the prefix expires before the neighbor goes stale");
}

// Two interfaces are two borrows, so a neighbor learned on one is unknown on the other even after
// both have run the whole machine (RFC 4861 sec 5.1 keeps this state "for each interface").
void test_the_machine_on_one_borrow_reaches_no_byte_of_another(void)
{
    Nd6.clear(work_a);
    Nd6.clear(work_b);
    at(work_a, 0u);
    at(work_b, 0u);
    nb_set(work_a, g_addr_a, g_lladdr, IDEMIP_ND6_REACHABLE, F, F, T);
    pfx_set(work_a, g_pfx64, 64u, 1800u, T);
    rtr_set(work_a, g_addr_b, 1800u);

    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, nb_find(work_b, g_addr_a));
    TEST_ASSERT_EQUAL_INT(F, on_link_of(work_b, g_in64));
    Nd6.router_select(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ND6_IO(work_b)->status);
}

// RFC 4861 sec 6.1.2 opens a MUST-silently-discard list for Router Advertisements, and its first
// entry is "IP Source Address is a link-local address. Routers must use their link-local address as
// the source for Router Advertisement and Redirect messages so that hosts can uniquely identify
// routers." A message failing it is not a "valid advertisement", which is the term sec 6.3.4 uses
// for what reaches the Default Router List, so an address outside FE80::/10 names no router. Every
// other case here offers one that is link-local, so nothing asked.
void test_a_router_advertised_from_a_global_address_names_no_router(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set(work_a, g_pfx64, 1800u); // 2001:DB8:0:1::, a global address and no router's source

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status,
                                  "a Router Advertisement from a global source is not a valid one");
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_ND6_IO(work_a)->status,
                                  "an invalid advertisement installed a default router");
}

// The same source on the entry that would otherwise be identical, so the pair says which half of the
// rule refused it.
void test_a_router_advertised_from_a_link_local_address_names_one(void)
{
    Nd6.clear(work_a);
    at(work_a, 0u);
    rtr_set(work_a, g_addr_a, 1800u);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
    Nd6.router_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ND6_IO(work_a)->status);
}

