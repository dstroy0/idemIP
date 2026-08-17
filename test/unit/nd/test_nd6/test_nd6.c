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

#include "idemIP/nd/nd6.h"

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
