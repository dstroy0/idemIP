// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for core/stats, modeled on test_phy. It tests the CONTRACT, so every case here
// stays valid once the counter logic lands:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. the published offsets are ordered, non-overlapping, and inside IDEMIP_STATS_BORROW
//   6. the counter ids are the RFC 1213 group field sets, counted
//   7. a canary past IDEMIP_STATS_BORROW is intact after every case
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/core/stats.h"

#include <string.h>
#include <unity.h>

#define CANARY 0x5Au
#define CTR_BYTES ((size_t)IDEMIP_STAT_COUNT << IDEMIP_STATS_CTR_SHIFT)
#define IF_BYTES ((size_t)(IDEMIP_NETIF_COUNT) << IDEMIP_STATS_IF_ENTRY_SHIFT)

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each so
// a write past the map is visible.
static _Alignas(8) uint8_t work_a[IDEMIP_STATS_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_STATS_BORROW + 16];

static void arm_canary(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_STATS_BORROW, CANARY, cap - IDEMIP_STATS_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_STATS_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_STATS_BORROW");
    }
}

// Fill the mapped span, leaving the canary alone, so a region a call fails to touch is visible.
static void dirty(uint8_t *w, uint8_t v)
{
    memset(w, v, IDEMIP_STATS_BORROW);
}

static void expect_span(const uint8_t *w, size_t off, size_t len, uint8_t v, const char *what)
{
    for (size_t i = off; i < off + len; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(v, w[i], what);
    }
}

void setUp(void)
{
    arm_canary(work_a, sizeof work_a);
    arm_canary(work_b, sizeof work_b);
}
void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// Plausible operands for every entry, so a case can drive the whole namespace.
static void load_operands(uint8_t *w)
{
    IDEMIP_STATS_IO(w)->ctr_args.id = IDEMIP_STAT_IP4_IN_RECEIVES;
    IDEMIP_STATS_IO(w)->ctr_args.value = 1u;
    IDEMIP_STATS_IO(w)->if_args.netif = 0u;
    IDEMIP_STATS_IO(w)->if_args.id = IDEMIP_STAT_IF_IN_OCTETS;
    IDEMIP_STATS_IO(w)->if_args.value = 64u;
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Stats.clear(NULL);
    Stats.bump(NULL);
    Stats.set(NULL);
    Stats.read(NULL);
    Stats.if_bump(NULL);
    Stats.if_set(NULL);
    Stats.if_read(NULL);
    TEST_PASS();
}

// The borrow IS the counter set, and the operand block is in it, so two sets share no byte at all.
// This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_STATS_IO(work_a)->ctr_args.id = IDEMIP_STAT_IP4_IN_RECEIVES;
    IDEMIP_STATS_IO(work_a)->ctr_args.value = 111u;
    IDEMIP_STATS_IO(work_b)->ctr_args.id = IDEMIP_STAT_TCP_IN_SEGS;
    IDEMIP_STATS_IO(work_b)->ctr_args.value = 222u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_INT(IDEMIP_STAT_IP4_IN_RECEIVES, IDEMIP_STATS_IO(work_a)->ctr_args.id);
    TEST_ASSERT_EQUAL_UINT32(111u, IDEMIP_STATS_IO(work_a)->ctr_args.value);
    TEST_ASSERT_EQUAL_INT(IDEMIP_STAT_TCP_IN_SEGS, IDEMIP_STATS_IO(work_b)->ctr_args.id);
    TEST_ASSERT_EQUAL_UINT32(222u, IDEMIP_STATS_IO(work_b)->ctr_args.value);

    // And a call on one borrow writes nothing in the other: b is filled, a is cleared, and every
    // mapped byte of b still holds the fill.
    dirty(work_b, 0x55u);
    Stats.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    expect_span(work_b, 0u, IDEMIP_STATS_BORROW, 0x55u, "clear on one borrow wrote into the other");
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports. This is the determinism the design is named for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    dirty(work_a, 0xAAu);
    dirty(work_b, 0x33u);

    Stats.clear(work_a);
    IdemIpStatus first = IDEMIP_STATS_IO(work_a)->status;
    uint32_t first_value = IDEMIP_STATS_IO(work_a)->value;

    Stats.clear(work_b);
    Stats.clear(work_a);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, first);
    TEST_ASSERT_EQUAL_INT(first, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(first_value, IDEMIP_STATS_IO(work_a)->value);
}

// The map is public, so a reader can see where every region sits. Ordered, non-overlapping, and the
// last region ends inside the borrow.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_STATS_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_STATS_OFF_CTR >= IDEMIP_STATS_OFF_IO + sizeof(StatsIo),
                             "the counter block overlaps the operand block");
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_STATS_OFF_CTX >= IDEMIP_STATS_OFF_CTR + CTR_BYTES,
                             "the context overlaps the counter block");
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_STATS_OFF_IF > IDEMIP_STATS_OFF_CTX, "the interface table is not past the context");
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_STATS_OFF_IF + IF_BYTES <= IDEMIP_STATS_BORROW,
                             "the interface table runs past IDEMIP_STATS_BORROW");
    // Every region starts on the alignment the tree takes its borrows at.
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_STATS_OFF_CTR & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_STATS_OFF_IF & (IDEMIP_ALIGN - 1u));
    // A counter is four octets and an interface entry a power of two wide, so both index by a shift.
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), (size_t)1u << IDEMIP_STATS_CTR_SHIFT);
    TEST_ASSERT_EQUAL_size_t(0u, (1u << IDEMIP_STATS_IF_ENTRY_SHIFT) & ((1u << IDEMIP_STATS_IF_ENTRY_SHIFT) - 1u));
}

// --- the RFC 1213 field sets -------------------------------------------------

// RFC 1213 sec 6.6 has 17 counters in the IP group and sec 6.7 has 26 in the ICMP group, one set for
// IPv4 and one for IPv6; sec 6.8 has 10 in the TCP group and sec 6.9 has 4 in the UDP group. The id
// is the index into the counter block, so the group boundaries are those counts summed.
void test_the_counter_ids_are_the_rfc_1213_group_field_sets(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_STAT_IP4_IN_RECEIVES);
    TEST_ASSERT_EQUAL_INT(17, IDEMIP_STAT_ICMP4_IN_MSGS);
    TEST_ASSERT_EQUAL_INT(17 + 26, IDEMIP_STAT_IP6_IN_RECEIVES);
    TEST_ASSERT_EQUAL_INT(17 + 26 + 17, IDEMIP_STAT_ICMP6_IN_MSGS);
    TEST_ASSERT_EQUAL_INT(17 + 26 + 17 + 26, IDEMIP_STAT_TCP_ACTIVE_OPENS);
    TEST_ASSERT_EQUAL_INT(17 + 26 + 17 + 26 + 10, IDEMIP_STAT_UDP_IN_DATAGRAMS);
    TEST_ASSERT_EQUAL_INT(17 + 26 + 17 + 26 + 10 + 4, IDEMIP_STAT_COUNT);
    // RFC 1213 sec 6.4's ifEntry: 13 counters and gauges, the rest of the row not being counted.
    TEST_ASSERT_EQUAL_INT(13, IDEMIP_STAT_IF_COUNT);
    // The counter block is what those counts cost: 100 counters of four octets.
    TEST_ASSERT_EQUAL_size_t(400u, CTR_BYTES);
    TEST_ASSERT_TRUE_MESSAGE(((size_t)IDEMIP_STAT_IF_COUNT << IDEMIP_STATS_CTR_SHIFT) <=
                                 (size_t)(1u << IDEMIP_STATS_IF_ENTRY_SHIFT),
                             "an interface entry is narrower than the ifEntry counters");
}

// --- clear -------------------------------------------------------------------

void test_clear_zeroes_the_counter_and_interface_regions(void)
{
    dirty(work_a, 0xAAu);
    Stats.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    expect_span(work_a, IDEMIP_STATS_OFF_CTR, CTR_BYTES, 0u, "clear left a group counter dirty");
    expect_span(work_a, IDEMIP_STATS_OFF_IF, IF_BYTES, 0u, "clear left an interface counter dirty");
}

void test_clear_is_repeatable(void)
{
    Stats.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    Stats.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    expect_span(work_a, IDEMIP_STATS_OFF_CTR, CTR_BYTES, 0u, "the second clear left a counter dirty");
    expect_span(work_a, IDEMIP_STATS_OFF_IF, IF_BYTES, 0u, "the second clear left an interface counter dirty");
}

// --- refusals ----------------------------------------------------------------

// Zeroed, never cleared: every entry must refuse rather than run on whatever the caller's memory
// held. Retrying cannot help, so it is ERR and not BUSY.
void test_an_uncleared_borrow_is_refused(void)
{
    load_operands(work_a);
    Stats.bump(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.read(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.if_bump(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.if_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.if_read(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
}

// A borrow filled with garbage is not a cleared one either.
void test_a_dirty_borrow_is_refused(void)
{
    dirty(work_a, 0xAAu);
    load_operands(work_a);
    Stats.bump(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.if_read(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
}

// IDEMIP_STAT_COUNT is one past the last counter, so it names none. A bad argument can never succeed
// on a retry, so it is ERR.
void test_a_counter_id_the_map_does_not_carry_is_refused(void)
{
    Stats.clear(work_a);
    load_operands(work_a);
    IDEMIP_STATS_IO(work_a)->ctr_args.id = IDEMIP_STAT_COUNT;
    Stats.bump(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.read(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
}

void test_an_interface_counter_id_the_map_does_not_carry_is_refused(void)
{
    Stats.clear(work_a);
    load_operands(work_a);
    IDEMIP_STATS_IO(work_a)->if_args.id = IDEMIP_STAT_IF_COUNT;
    Stats.if_bump(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.if_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.if_read(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
}

// The table holds IDEMIP_NETIF_COUNT rows, so the count itself is one past the last interface.
void test_an_interface_this_build_does_not_carry_is_refused(void)
{
    Stats.clear(work_a);
    load_operands(work_a);
    IDEMIP_STATS_IO(work_a)->if_args.netif = (uint8_t)IDEMIP_NETIF_COUNT;
    Stats.if_bump(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.if_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    Stats.if_read(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
}

// --- the whole namespace on a bound borrow -----------------------------------

// Every entry, on a cleared borrow, with plausible operands. tearDown proves none of them wrote past
// IDEMIP_STATS_BORROW, and the canary on the other borrow proves none reached across.
void test_every_entry_stays_inside_the_borrow(void)
{
    Stats.clear(work_a);
    load_operands(work_a);
    Stats.bump(work_a);
    Stats.set(work_a);
    Stats.read(work_a);
    Stats.if_bump(work_a);
    Stats.if_set(work_a);
    Stats.if_read(work_a);
    expect_span(work_b, 0u, IDEMIP_STATS_BORROW, 0u, "a call on one borrow wrote into the other");
}
