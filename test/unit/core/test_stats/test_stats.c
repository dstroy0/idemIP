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

#include "src/core/stats.h"

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

// =============================================================================
// The behavior cases.
//
// RFC 1213 and RFC 1155 print no numeric vectors for these objects: no figure, no worked example,
// no sample counter value anywhere in either document. Every case below therefore asserts a property
// the text states, quoted at the case, rather than a vector the RFC does not print.
//
// The one number both documents do print is the ceiling: RFC 1155 sec 3.2.3.3 and sec 3.2.3.4 each
// specify "a maximum value of 2^32-1 (4294967295 decimal)".
// =============================================================================

// RFC 1155 sec 3.2.3.3 and sec 3.2.3.4, the maximum both a Counter and a Gauge is specified to.
#define RFC1155_MAX 4294967295u

// The three Gauges. RFC 1213 sec 6.8 gives tcpCurrEstab SYNTAX Gauge; sec 6.4 gives ifSpeed and
// ifOutQLen SYNTAX Gauge. Every other object carried here is SYNTAX Counter.
#define GROUP_GAUGE IDEMIP_STAT_TCP_CURR_ESTAB

static void bump_by(uint8_t *w, IdemIpStatsCounter id, uint32_t by)
{
    IDEMIP_STATS_IO(w)->ctr_args.id = id;
    IDEMIP_STATS_IO(w)->ctr_args.value = by;
    Stats.bump(w);
}

static void set_to(uint8_t *w, IdemIpStatsCounter id, uint32_t v)
{
    IDEMIP_STATS_IO(w)->ctr_args.id = id;
    IDEMIP_STATS_IO(w)->ctr_args.value = v;
    Stats.set(w);
}

static uint32_t read_ctr(uint8_t *w, IdemIpStatsCounter id)
{
    IDEMIP_STATS_IO(w)->ctr_args.id = id;
    Stats.read(w);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_STATS_IO(w)->status, "read refused an id the map carries");
    return IDEMIP_STATS_IO(w)->value;
}

static void if_bump_by(uint8_t *w, uint8_t netif, IdemIpStatsIfCounter id, uint32_t by)
{
    IDEMIP_STATS_IO(w)->if_args.netif = netif;
    IDEMIP_STATS_IO(w)->if_args.id = id;
    IDEMIP_STATS_IO(w)->if_args.value = by;
    Stats.if_bump(w);
}

static void if_set_to(uint8_t *w, uint8_t netif, IdemIpStatsIfCounter id, uint32_t v)
{
    IDEMIP_STATS_IO(w)->if_args.netif = netif;
    IDEMIP_STATS_IO(w)->if_args.id = id;
    IDEMIP_STATS_IO(w)->if_args.value = v;
    Stats.if_set(w);
}

static uint32_t if_read_ctr(uint8_t *w, uint8_t netif, IdemIpStatsIfCounter id)
{
    IDEMIP_STATS_IO(w)->if_args.netif = netif;
    IDEMIP_STATS_IO(w)->if_args.id = id;
    Stats.if_read(w);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_STATS_IO(w)->status, "if_read refused an id the map carries");
    return IDEMIP_STATS_IO(w)->value;
}

static int group_is_gauge(int id)
{
    return id == (int)GROUP_GAUGE;
}

static int if_is_gauge(int id)
{
    return id == (int)IDEMIP_STAT_IF_SPEED || id == (int)IDEMIP_STAT_IF_OUT_QLEN;
}

// --- the group Counters ------------------------------------------------------

// RFC 1213 sec 6.6: ipInReceives is "The total number of input datagrams received from interfaces,
// including those received in error." A total accumulates, so bump adds and read reports the sum.
void test_bump_accumulates_and_read_reports_the_total(void)
{
    Stats.clear(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));

    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(1u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));

    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 1u);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 7u);
    TEST_ASSERT_EQUAL_UINT32(9u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
}

// RFC 1155 sec 3.2.3.3: a Counter "monotonically increases". Every bump of a nonzero amount leaves
// the counter strictly greater, up to the ceiling the wrap cases below cover.
void test_a_counter_increases_monotonically(void)
{
    Stats.clear(work_a);
    uint32_t prev = 0u;
    for (uint32_t i = 1u; i <= 64u; i++)
    {
        bump_by(work_a, IDEMIP_STAT_IP4_IN_HDR_ERRORS, i);
        uint32_t now = read_ctr(work_a, IDEMIP_STAT_IP4_IN_HDR_ERRORS);
        TEST_ASSERT_TRUE_MESSAGE(now > prev, "a bump did not increase the counter");
        prev = now;
    }
    // 1 + 2 + ... + 64.
    TEST_ASSERT_EQUAL_UINT32(2080u, prev);
}

// A bump of nothing is still a bump: the counter is unchanged and the call reports OK.
void test_a_bump_of_zero_leaves_the_counter_unchanged(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_DISCARDS, 5u);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_DISCARDS, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(5u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_DISCARDS));
}

// read does not disturb what it reports, so the same read repeats. RFC 1213 sec 6.6 gives
// ipInReceives ACCESS read-only.
void test_read_is_repeatable_and_does_not_disturb_the_counter(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_DELIVERS, 42u);
    TEST_ASSERT_EQUAL_UINT32(42u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_DELIVERS));
    TEST_ASSERT_EQUAL_UINT32(42u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_DELIVERS));
    TEST_ASSERT_EQUAL_UINT32(42u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_DELIVERS));
}

// --- the ceiling ------------------------------------------------------------

// RFC 1155 sec 3.2.3.3 specifies "a maximum value of 2^32-1 (4294967295 decimal) for counters", and
// the ceiling is reachable exactly.
void test_a_counter_reaches_the_rfc_1155_ceiling_exactly(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, RFC1155_MAX);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
    TEST_ASSERT_EQUAL_UINT32(4294967295u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
}

// One short of the ceiling is not the ceiling: the counter reaches 2^32-1 and has not wrapped.
void test_a_counter_one_below_the_ceiling_does_not_wrap(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, RFC1155_MAX - 1u);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFEu, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 1u);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
}

// RFC 1155 sec 3.2.3.3, quoted in full: a Counter "monotonically increases until it reaches a maximum
// value, when it WRAPS AROUND and starts increasing again from zero". At the ceiling plus one the
// counter is zero.
//
// This case pins wrap, not saturation. The two are not interchangeable and this suite asserts the one
// the RFC states: a saturating counter would read 4294967295 here and for every bump after it, so the
// object would stop reporting traffic permanently rather than for one poll interval.
void test_a_counter_at_the_ceiling_wraps_to_zero_as_rfc_1155_states(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, RFC1155_MAX);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));

    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(0x00000000u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
}

// "starts increasing again from zero": the wrap carries the remainder of the amount rather than
// stopping at the ceiling or restarting the amount.
void test_a_wrap_carries_the_remainder_and_keeps_counting(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_OUT_REQUESTS, RFC1155_MAX);
    bump_by(work_a, IDEMIP_STAT_IP4_OUT_REQUESTS, 5u);
    TEST_ASSERT_EQUAL_UINT32(4u, read_ctr(work_a, IDEMIP_STAT_IP4_OUT_REQUESTS));

    bump_by(work_a, IDEMIP_STAT_IP4_OUT_REQUESTS, 1u);
    TEST_ASSERT_EQUAL_UINT32(5u, read_ctr(work_a, IDEMIP_STAT_IP4_OUT_REQUESTS));
}

// The ceiling is a property of the counter, not of the first id: every group Counter wraps.
void test_every_group_counter_wraps_at_the_ceiling(void)
{
    Stats.clear(work_a);
    for (int id = 0; id < (int)IDEMIP_STAT_COUNT; id++)
    {
        if (group_is_gauge(id))
        {
            continue;
        }
        bump_by(work_a, (IdemIpStatsCounter)id, RFC1155_MAX);
        TEST_ASSERT_EQUAL_HEX32_MESSAGE(0xFFFFFFFFu, read_ctr(work_a, (IdemIpStatsCounter)id),
                                        "a group counter did not reach the ceiling");
        bump_by(work_a, (IdemIpStatsCounter)id, 1u);
        TEST_ASSERT_EQUAL_HEX32_MESSAGE(0u, read_ctr(work_a, (IdemIpStatsCounter)id),
                                        "a group counter did not wrap at the ceiling");
    }
}

// An interface Counter carries the same ceiling. RFC 1213 sec 6.4 ifInOctets is SYNTAX Counter.
void test_an_interface_counter_wraps_at_the_ceiling(void)
{
    Stats.clear(work_a);
    if_bump_by(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS, RFC1155_MAX);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS));
    if_bump_by(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS, 3u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(2u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS));
}

// --- the Gauges -------------------------------------------------------------

// RFC 1155 sec 3.2.3.4: a Gauge "may increase or decrease". RFC 1213 sec 6.8 defines tcpCurrEstab as
// "The number of TCP connections for which the current state is either ESTABLISHED or CLOSE- WAIT",
// which falls when a connection closes.
void test_a_group_gauge_rises_and_falls(void)
{
    Stats.clear(work_a);
    set_to(work_a, GROUP_GAUGE, 5u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(5u, read_ctr(work_a, GROUP_GAUGE));

    set_to(work_a, GROUP_GAUGE, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(2u, read_ctr(work_a, GROUP_GAUGE));

    set_to(work_a, GROUP_GAUGE, 0u);
    TEST_ASSERT_EQUAL_UINT32(0u, read_ctr(work_a, GROUP_GAUGE));
}

// RFC 1155 sec 3.2.3.4: a Gauge "latches at a maximum value", specified as 2^32-1. The ceiling holds
// the value it is assigned and no assignment can pass it.
void test_a_gauge_latches_at_the_rfc_1155_ceiling(void)
{
    Stats.clear(work_a);
    set_to(work_a, GROUP_GAUGE, RFC1155_MAX);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(4294967295u, read_ctr(work_a, GROUP_GAUGE));
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, read_ctr(work_a, GROUP_GAUGE));

    // The ceiling latches rather than wrapping: it is still the maximum, not zero.
    set_to(work_a, GROUP_GAUGE, RFC1155_MAX);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, read_ctr(work_a, GROUP_GAUGE));
}

// RFC 1213 sec 6.4: ifSpeed is "An estimate of the interface's current bandwidth in bits per second",
// ifOutQLen "The length of the output packet queue". Both are SYNTAX Gauge, so both rise and fall.
void test_the_interface_gauges_rise_and_fall(void)
{
    Stats.clear(work_a);
    if_set_to(work_a, 0u, IDEMIP_STAT_IF_SPEED, 100000000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(100000000u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_SPEED));
    if_set_to(work_a, 0u, IDEMIP_STAT_IF_SPEED, 10000000u);
    TEST_ASSERT_EQUAL_UINT32(10000000u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_SPEED));

    if_set_to(work_a, 0u, IDEMIP_STAT_IF_OUT_QLEN, 4u);
    TEST_ASSERT_EQUAL_UINT32(4u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_OUT_QLEN));
    if_set_to(work_a, 0u, IDEMIP_STAT_IF_OUT_QLEN, 0u);
    TEST_ASSERT_EQUAL_UINT32(0u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_OUT_QLEN));
}

void test_an_interface_gauge_latches_at_the_ceiling(void)
{
    Stats.clear(work_a);
    if_set_to(work_a, 1u, IDEMIP_STAT_IF_SPEED, RFC1155_MAX);
    TEST_ASSERT_EQUAL_UINT32(4294967295u, if_read_ctr(work_a, 1u, IDEMIP_STAT_IF_SPEED));
    if_set_to(work_a, 1u, IDEMIP_STAT_IF_SPEED, RFC1155_MAX);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, if_read_ctr(work_a, 1u, IDEMIP_STAT_IF_SPEED));
}

// --- Counter and Gauge are not the same object -------------------------------

// RFC 1155 sec 3.2.3.4 lets a Gauge fall, so it is assigned rather than added to. bump refuses the
// one group Gauge, RFC 1213 sec 6.8's tcpCurrEstab, and leaves it alone. ERR and not BUSY: the id
// reads the same on the next call, so no retry can succeed.
void test_bump_refuses_the_group_gauge(void)
{
    Stats.clear(work_a);
    set_to(work_a, GROUP_GAUGE, 3u);
    bump_by(work_a, GROUP_GAUGE, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(3u, read_ctr(work_a, GROUP_GAUGE));
}

// RFC 1155 sec 3.2.3.3 has a Counter increase monotonically, so it is added to rather than assigned.
// set refuses every group Counter and leaves it alone.
void test_set_refuses_a_group_counter(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 9u);
    set_to(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(9u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
}

// Exactly one group object is a Gauge, so bump takes the other 99 ids and set takes only that one.
void test_bump_and_set_split_the_group_ids_by_syntax(void)
{
    Stats.clear(work_a);
    for (int id = 0; id < (int)IDEMIP_STAT_COUNT; id++)
    {
        bump_by(work_a, (IdemIpStatsCounter)id, 1u);
        IdemIpStatus bumped = IDEMIP_STATS_IO(work_a)->status;
        set_to(work_a, (IdemIpStatsCounter)id, 1u);
        IdemIpStatus assigned = IDEMIP_STATS_IO(work_a)->status;

        if (group_is_gauge(id))
        {
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, bumped, "bump accepted the group Gauge");
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, assigned, "set refused the group Gauge");
        }
        else
        {
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, bumped, "bump refused a group Counter");
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, assigned, "set accepted a group Counter");
        }
    }
}

// The same split over RFC 1213 sec 6.4's ifEntry: ifSpeed and ifOutQLen are the Gauges, the other
// eleven carried here are Counters.
void test_if_bump_and_if_set_split_the_interface_ids_by_syntax(void)
{
    Stats.clear(work_a);
    for (int id = 0; id < (int)IDEMIP_STAT_IF_COUNT; id++)
    {
        if_bump_by(work_a, 0u, (IdemIpStatsIfCounter)id, 1u);
        IdemIpStatus bumped = IDEMIP_STATS_IO(work_a)->status;
        if_set_to(work_a, 0u, (IdemIpStatsIfCounter)id, 1u);
        IdemIpStatus assigned = IDEMIP_STATS_IO(work_a)->status;

        if (if_is_gauge(id))
        {
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, bumped, "if_bump accepted an ifEntry Gauge");
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, assigned, "if_set refused an ifEntry Gauge");
        }
        else
        {
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, bumped, "if_bump refused an ifEntry Counter");
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, assigned, "if_set accepted an ifEntry Counter");
        }
    }
}

// --- one id, one cell -------------------------------------------------------

// The id IS the index, so each of the 100 group objects has to be its own four octets. Each is given
// a distinct value and every one is read back, so an index that lands on a neighbor is visible.
void test_every_group_object_is_its_own_cell(void)
{
    Stats.clear(work_a);
    for (int id = 0; id < (int)IDEMIP_STAT_COUNT; id++)
    {
        uint32_t v = 0x01000000u + (uint32_t)id;
        if (group_is_gauge(id))
        {
            set_to(work_a, (IdemIpStatsCounter)id, v);
        }
        else
        {
            bump_by(work_a, (IdemIpStatsCounter)id, v);
        }
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status, "an id the map carries was refused");
    }
    for (int id = 0; id < (int)IDEMIP_STAT_COUNT; id++)
    {
        TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x01000000u + (uint32_t)id, read_ctr(work_a, (IdemIpStatsCounter)id),
                                        "a group object aliased another");
    }
}

void test_every_interface_object_is_its_own_cell(void)
{
    Stats.clear(work_a);
    for (uint8_t netif = 0u; netif < (uint8_t)IDEMIP_NETIF_COUNT; netif++)
    {
        for (int id = 0; id < (int)IDEMIP_STAT_IF_COUNT; id++)
        {
            uint32_t v = 0x02000000u + ((uint32_t)netif << 8) + (uint32_t)id;
            if (if_is_gauge(id))
            {
                if_set_to(work_a, netif, (IdemIpStatsIfCounter)id, v);
            }
            else
            {
                if_bump_by(work_a, netif, (IdemIpStatsIfCounter)id, v);
            }
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status,
                                          "an interface id the map carries was refused");
        }
    }
    for (uint8_t netif = 0u; netif < (uint8_t)IDEMIP_NETIF_COUNT; netif++)
    {
        for (int id = 0; id < (int)IDEMIP_STAT_IF_COUNT; id++)
        {
            TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x02000000u + ((uint32_t)netif << 8) + (uint32_t)id,
                                            if_read_ctr(work_a, netif, (IdemIpStatsIfCounter)id),
                                            "an interface object aliased another");
        }
    }
}

// RFC 1213 sec 6.4 carries one ifEntry per interface, so a count on one interface is not a count on
// another.
void test_the_interface_rows_do_not_alias(void)
{
    Stats.clear(work_a);
    if_bump_by(work_a, 0u, IDEMIP_STAT_IF_IN_UCAST_PKTS, 11u);
    TEST_ASSERT_EQUAL_UINT32(11u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_IN_UCAST_PKTS));
    TEST_ASSERT_EQUAL_UINT32(0u, if_read_ctr(work_a, 1u, IDEMIP_STAT_IF_IN_UCAST_PKTS));

    if_bump_by(work_a, 1u, IDEMIP_STAT_IF_IN_UCAST_PKTS, 22u);
    TEST_ASSERT_EQUAL_UINT32(11u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_IN_UCAST_PKTS));
    TEST_ASSERT_EQUAL_UINT32(22u, if_read_ctr(work_a, 1u, IDEMIP_STAT_IF_IN_UCAST_PKTS));
}

// The group block and the interface table are separate regions of the borrow, so a count in one is
// not a count in the other.
void test_the_group_block_and_the_interface_table_do_not_alias(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 7u);
    if_bump_by(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS, 64u);
    TEST_ASSERT_EQUAL_UINT32(7u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
    TEST_ASSERT_EQUAL_UINT32(64u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS));

    // And the interface row did not reach the group counter that shares its id number.
    TEST_ASSERT_EQUAL_UINT32(0u, read_ctr(work_a, (IdemIpStatsCounter)IDEMIP_STAT_IF_IN_OCTETS));
}

// RFC 1213 sec 6.6 carries the IPv4 IP group, and the IPv6 copy is a second set of the same objects,
// so ipInReceives for one version is not the other's.
void test_the_ipv4_and_ipv6_groups_are_separate_sets(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 3u);
    bump_by(work_a, IDEMIP_STAT_IP6_IN_RECEIVES, 8u);
    TEST_ASSERT_EQUAL_UINT32(3u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
    TEST_ASSERT_EQUAL_UINT32(8u, read_ctr(work_a, IDEMIP_STAT_IP6_IN_RECEIVES));

    bump_by(work_a, IDEMIP_STAT_ICMP4_IN_ECHOS, 1u);
    TEST_ASSERT_EQUAL_UINT32(1u, read_ctr(work_a, IDEMIP_STAT_ICMP4_IN_ECHOS));
    TEST_ASSERT_EQUAL_UINT32(0u, read_ctr(work_a, IDEMIP_STAT_ICMP6_IN_ECHOS));
}

// --- the published offset, not just a consistent one -------------------------

// The four octets at a published offset, read as bytes so nothing is assumed about the region type.
static uint32_t raw_ctr(const uint8_t *w, size_t off)
{
    uint32_t v = 0;
    memcpy(&v, w + off, sizeof v);
    return v;
}

// The borrow map is public, so a reader finds the object an id names at
// IDEMIP_STATS_OFF_CTR + (id << IDEMIP_STATS_CTR_SHIFT) and nowhere else.
//
// bump, set and read all reach the block through one index, so a permutation of the block cancels out
// when the same suite writes and reads through the API: every count still reads back its own value. The
// raw offset is what pins each object to its published place, and an SNMP agent or a debugger walking
// the borrow reads it that way rather than through read.
void test_a_group_object_lands_at_its_published_offset(void)
{
    Stats.clear(work_a);
    for (int id = 0; id < (int)IDEMIP_STAT_COUNT; id++)
    {
        uint32_t v = 0x11000000u + (uint32_t)id;
        if (group_is_gauge(id))
        {
            set_to(work_a, (IdemIpStatsCounter)id, v);
        }
        else
        {
            bump_by(work_a, (IdemIpStatsCounter)id, v);
        }
    }
    for (int id = 0; id < (int)IDEMIP_STAT_COUNT; id++)
    {
        size_t off = (size_t)IDEMIP_STATS_OFF_CTR + ((size_t)id << IDEMIP_STATS_CTR_SHIFT);
        TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x11000000u + (uint32_t)id, raw_ctr(work_a, off),
                                        "a group object is not at its published offset");
    }
}

// RFC 1213 sec 6.6: ipInReceives ::= { ip 3 } is the first counted object, so it is the first four
// octets of the block, and a count on it moves those octets and no others.
void test_ip_in_receives_is_the_first_four_octets_of_the_block(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 0x0000002Au);
    TEST_ASSERT_EQUAL_HEX32(0x0000002Au, raw_ctr(work_a, IDEMIP_STATS_OFF_CTR));
    TEST_ASSERT_EQUAL_HEX32(0u, raw_ctr(work_a, (size_t)IDEMIP_STATS_OFF_CTR + sizeof(uint32_t)));

    // ipInHdrErrors ::= { ip 4 } is the next four, and counting it does not move ipInReceives.
    bump_by(work_a, IDEMIP_STAT_IP4_IN_HDR_ERRORS, 0x0000000Bu);
    TEST_ASSERT_EQUAL_HEX32(0x0000002Au, raw_ctr(work_a, IDEMIP_STATS_OFF_CTR));
    TEST_ASSERT_EQUAL_HEX32(0x0000000Bu, raw_ctr(work_a, (size_t)IDEMIP_STATS_OFF_CTR + sizeof(uint32_t)));
}

// The same for the interface table: interface i's row is at IDEMIP_STATS_OFF_IF plus
// (i << IDEMIP_STATS_IF_ENTRY_SHIFT), and the id indexes inside the row.
void test_an_interface_object_lands_at_its_published_offset(void)
{
    Stats.clear(work_a);
    for (uint8_t netif = 0u; netif < (uint8_t)IDEMIP_NETIF_COUNT; netif++)
    {
        for (int id = 0; id < (int)IDEMIP_STAT_IF_COUNT; id++)
        {
            uint32_t v = 0x22000000u + ((uint32_t)netif << 8) + (uint32_t)id;
            if (if_is_gauge(id))
            {
                if_set_to(work_a, netif, (IdemIpStatsIfCounter)id, v);
            }
            else
            {
                if_bump_by(work_a, netif, (IdemIpStatsIfCounter)id, v);
            }
        }
    }
    for (uint8_t netif = 0u; netif < (uint8_t)IDEMIP_NETIF_COUNT; netif++)
    {
        for (int id = 0; id < (int)IDEMIP_STAT_IF_COUNT; id++)
        {
            size_t off = (size_t)IDEMIP_STATS_OFF_IF + ((size_t)netif << IDEMIP_STATS_IF_ENTRY_SHIFT) +
                         ((size_t)id << IDEMIP_STATS_CTR_SHIFT);
            TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x22000000u + ((uint32_t)netif << 8) + (uint32_t)id,
                                            raw_ctr(work_a, off),
                                            "an interface object is not at its published offset");
        }
    }
}

// Counting never reaches the context that holds the bound mark, which sits past the block. If a count
// could reach it, the borrow would come unbound under load.
void test_counting_never_reaches_the_context(void)
{
    Stats.clear(work_a);
    uint32_t magic = raw_ctr(work_a, IDEMIP_STATS_OFF_CTX);
    TEST_ASSERT_NOT_EQUAL_UINT32(0u, magic);

    // The last group object and the last object of the last interface row, both at the ceiling.
    bump_by(work_a, (IdemIpStatsCounter)((int)IDEMIP_STAT_COUNT - 1), RFC1155_MAX);
    if_set_to(work_a, (uint8_t)((int)IDEMIP_NETIF_COUNT - 1), IDEMIP_STAT_IF_OUT_QLEN, RFC1155_MAX);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(magic, raw_ctr(work_a, IDEMIP_STATS_OFF_CTX), "a count reached the context");

    // Still bound afterwards.
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
}

// --- the RFC 1213 OID order -------------------------------------------------

// The id is the index, and the ids are laid out in the order RFC 1213 sec 6.6 assigns the OIDs.
// ipInReceives ::= { ip 3 } through ipOutNoRoutes ::= { ip 12 } are consecutive, so the id is the
// OID's last arc less three. ipReasmTimeout ::= { ip 13 } is SYNTAX INTEGER and is not counted here,
// so ipReasmReqds ::= { ip 14 } picks up after the gap.
void test_the_ip_group_ids_follow_the_rfc_1213_oid_order(void)
{
    TEST_ASSERT_EQUAL_INT(3 - 3, IDEMIP_STAT_IP4_IN_RECEIVES);       // { ip 3 }
    TEST_ASSERT_EQUAL_INT(4 - 3, IDEMIP_STAT_IP4_IN_HDR_ERRORS);     // { ip 4 }
    TEST_ASSERT_EQUAL_INT(5 - 3, IDEMIP_STAT_IP4_IN_ADDR_ERRORS);    // { ip 5 }
    TEST_ASSERT_EQUAL_INT(6 - 3, IDEMIP_STAT_IP4_FORW_DATAGRAMS);    // { ip 6 }
    TEST_ASSERT_EQUAL_INT(7 - 3, IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS); // { ip 7 }
    TEST_ASSERT_EQUAL_INT(8 - 3, IDEMIP_STAT_IP4_IN_DISCARDS);       // { ip 8 }
    TEST_ASSERT_EQUAL_INT(9 - 3, IDEMIP_STAT_IP4_IN_DELIVERS);       // { ip 9 }
    TEST_ASSERT_EQUAL_INT(10 - 3, IDEMIP_STAT_IP4_OUT_REQUESTS);     // { ip 10 }
    TEST_ASSERT_EQUAL_INT(11 - 3, IDEMIP_STAT_IP4_OUT_DISCARDS);     // { ip 11 }
    TEST_ASSERT_EQUAL_INT(12 - 3, IDEMIP_STAT_IP4_OUT_NO_ROUTES);    // { ip 12 }

    // { ip 13 } is ipReasmTimeout, SYNTAX INTEGER, so the counted ids close the gap by one.
    TEST_ASSERT_EQUAL_INT(14 - 4, IDEMIP_STAT_IP4_REASM_REQDS);  // { ip 14 }
    TEST_ASSERT_EQUAL_INT(15 - 4, IDEMIP_STAT_IP4_REASM_OKS);    // { ip 15 }
    TEST_ASSERT_EQUAL_INT(16 - 4, IDEMIP_STAT_IP4_REASM_FAILS);  // { ip 16 }
    TEST_ASSERT_EQUAL_INT(17 - 4, IDEMIP_STAT_IP4_FRAG_OKS);     // { ip 17 }
    TEST_ASSERT_EQUAL_INT(18 - 4, IDEMIP_STAT_IP4_FRAG_FAILS);   // { ip 18 }
    TEST_ASSERT_EQUAL_INT(19 - 4, IDEMIP_STAT_IP4_FRAG_CREATES); // { ip 19 }

    // ipRoutingDiscards ::= { ip 23 } is the last Counter of the group and the last id in it.
    TEST_ASSERT_EQUAL_INT(17 - 1, IDEMIP_STAT_IP4_ROUTING_DISCARDS);
}

// RFC 1213 sec 6.8 assigns the TCP group tcpActiveOpens ::= { tcp 5 } through tcpRetransSegs
// ::= { tcp 12 }, with tcpCurrEstab ::= { tcp 9 } the Gauge in the middle of the run, then
// tcpInErrs ::= { tcp 14 } and tcpOutRsts ::= { tcp 15 } after the tcpConnTable.
void test_the_tcp_group_ids_follow_the_rfc_1213_oid_order(void)
{
    const int base = (int)IDEMIP_STAT_TCP_ACTIVE_OPENS;
    TEST_ASSERT_EQUAL_INT(base + (5 - 5), IDEMIP_STAT_TCP_ACTIVE_OPENS);  // { tcp 5 }
    TEST_ASSERT_EQUAL_INT(base + (6 - 5), IDEMIP_STAT_TCP_PASSIVE_OPENS); // { tcp 6 }
    TEST_ASSERT_EQUAL_INT(base + (7 - 5), IDEMIP_STAT_TCP_ATTEMPT_FAILS); // { tcp 7 }
    TEST_ASSERT_EQUAL_INT(base + (8 - 5), IDEMIP_STAT_TCP_ESTAB_RESETS);  // { tcp 8 }
    TEST_ASSERT_EQUAL_INT(base + (9 - 5), IDEMIP_STAT_TCP_CURR_ESTAB);    // { tcp 9 }, SYNTAX Gauge
    TEST_ASSERT_EQUAL_INT(base + (10 - 5), IDEMIP_STAT_TCP_IN_SEGS);      // { tcp 10 }
    TEST_ASSERT_EQUAL_INT(base + (11 - 5), IDEMIP_STAT_TCP_OUT_SEGS);     // { tcp 11 }
    TEST_ASSERT_EQUAL_INT(base + (12 - 5), IDEMIP_STAT_TCP_RETRANS_SEGS); // { tcp 12 }
    TEST_ASSERT_EQUAL_INT(base + 8, IDEMIP_STAT_TCP_IN_ERRS);             // { tcp 14 }
    TEST_ASSERT_EQUAL_INT(base + 9, IDEMIP_STAT_TCP_OUT_RSTS);            // { tcp 15 }
}

// --- clear over live counters -----------------------------------------------

// clear zeroes counters that were bumped, not only a fresh borrow, and the borrow stays bound.
void test_clear_zeroes_counters_that_were_bumped(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 1234u);
    if_bump_by(work_a, 1u, IDEMIP_STAT_IF_OUT_OCTETS, 5678u);
    set_to(work_a, GROUP_GAUGE, 9u);

    Stats.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(0u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
    TEST_ASSERT_EQUAL_UINT32(0u, read_ctr(work_a, GROUP_GAUGE));
    TEST_ASSERT_EQUAL_UINT32(0u, if_read_ctr(work_a, 1u, IDEMIP_STAT_IF_OUT_OCTETS));

    // Still bound, so a bump after the clear is accepted.
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(work_a)->status);
}

// --- two borrows, live counters ---------------------------------------------

// The borrow IS the counter set. Counting on one set does not move the other's counters, which is the
// storage model's claim carried through to real counts.
void test_counts_on_two_borrows_are_independent(void)
{
    Stats.clear(work_a);
    Stats.clear(work_b);

    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 100u);
    bump_by(work_b, IDEMIP_STAT_IP4_IN_RECEIVES, 7u);
    if_bump_by(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS, 1500u);

    TEST_ASSERT_EQUAL_UINT32(100u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
    TEST_ASSERT_EQUAL_UINT32(7u, read_ctr(work_b, IDEMIP_STAT_IP4_IN_RECEIVES));
    TEST_ASSERT_EQUAL_UINT32(1500u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS));
    TEST_ASSERT_EQUAL_UINT32(0u, if_read_ctr(work_b, 0u, IDEMIP_STAT_IF_IN_OCTETS));

    // Clearing one set leaves the other's counts standing.
    Stats.clear(work_b);
    TEST_ASSERT_EQUAL_UINT32(100u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
    TEST_ASSERT_EQUAL_UINT32(0u, read_ctr(work_b, IDEMIP_STAT_IP4_IN_RECEIVES));
}

// A bump interleaved on another borrow does not change what this one reads, at the ceiling too, where
// an aliasing bug would show as an early wrap.
void test_a_count_is_a_function_of_its_borrow_alone_at_the_ceiling(void)
{
    Stats.clear(work_a);
    Stats.clear(work_b);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, RFC1155_MAX);

    bump_by(work_b, IDEMIP_STAT_IP4_IN_RECEIVES, 1u);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
    TEST_ASSERT_EQUAL_UINT32(1u, read_ctr(work_b, IDEMIP_STAT_IP4_IN_RECEIVES));

    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 1u);
    TEST_ASSERT_EQUAL_UINT32(0u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
    TEST_ASSERT_EQUAL_UINT32(1u, read_ctr(work_b, IDEMIP_STAT_IP4_IN_RECEIVES));
}

// --- refusals past the published ids ----------------------------------------

// The ids are packed to one octet, so a caller can hand over any value up to 255. Everything at or
// past the count is refused rather than indexed, and nothing is written.
void test_an_id_far_past_the_count_is_refused(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 5u);

    for (int bad = (int)IDEMIP_STAT_COUNT; bad <= 255; bad++)
    {
        bump_by(work_a, (IdemIpStatsCounter)bad, 1u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status, "a bump past the count was accepted");
        set_to(work_a, (IdemIpStatsCounter)bad, 1u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status, "a set past the count was accepted");
        IDEMIP_STATS_IO(work_a)->ctr_args.id = (IdemIpStatsCounter)bad;
        Stats.read(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status, "a read past the count was accepted");
    }
    // The counter that was live is untouched by any of it.
    TEST_ASSERT_EQUAL_UINT32(5u, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));
}

void test_an_interface_id_far_past_the_count_is_refused(void)
{
    Stats.clear(work_a);
    if_bump_by(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS, 5u);

    for (int bad = (int)IDEMIP_STAT_IF_COUNT; bad <= 255; bad++)
    {
        if_bump_by(work_a, 0u, (IdemIpStatsIfCounter)bad, 1u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status,
                                      "an if_bump past the count was accepted");
        if_set_to(work_a, 0u, (IdemIpStatsIfCounter)bad, 1u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status,
                                      "an if_set past the count was accepted");
    }
    TEST_ASSERT_EQUAL_UINT32(5u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS));
}

// Every interface number the build does not carry is refused, all the way to 255, and no count moves.
void test_an_interface_far_past_the_count_is_refused(void)
{
    Stats.clear(work_a);
    if_bump_by(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS, 5u);

    for (int bad = (int)IDEMIP_NETIF_COUNT; bad <= 255; bad++)
    {
        if_bump_by(work_a, (uint8_t)bad, IDEMIP_STAT_IF_IN_OCTETS, 1u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status,
                                      "an if_bump on an absent interface was accepted");
        if_set_to(work_a, (uint8_t)bad, IDEMIP_STAT_IF_SPEED, 1u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status,
                                      "an if_set on an absent interface was accepted");
    }
    TEST_ASSERT_EQUAL_UINT32(5u, if_read_ctr(work_a, 0u, IDEMIP_STAT_IF_IN_OCTETS));
}

// Nothing in this unit defers, so nothing is ever BUSY: a counter is written where it stands. Every
// entry, over every operand this suite drives, answers OK or ERR and never BUSY.
void test_no_entry_ever_reports_busy(void)
{
    Stats.clear(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_STATS_IO(work_a)->status);

    for (int id = 0; id < (int)IDEMIP_STAT_COUNT + 8; id++)
    {
        bump_by(work_a, (IdemIpStatsCounter)id, 1u);
        TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_STATS_IO(work_a)->status, "bump reported BUSY");
        set_to(work_a, (IdemIpStatsCounter)id, 1u);
        TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_STATS_IO(work_a)->status, "set reported BUSY");
        IDEMIP_STATS_IO(work_a)->ctr_args.id = (IdemIpStatsCounter)id;
        Stats.read(work_a);
        TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_STATS_IO(work_a)->status, "read reported BUSY");
    }
    for (int netif = 0; netif < (int)IDEMIP_NETIF_COUNT + 2; netif++)
    {
        for (int id = 0; id < (int)IDEMIP_STAT_IF_COUNT + 2; id++)
        {
            if_bump_by(work_a, (uint8_t)netif, (IdemIpStatsIfCounter)id, 1u);
            TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_STATS_IO(work_a)->status, "if_bump reported BUSY");
            if_set_to(work_a, (uint8_t)netif, (IdemIpStatsIfCounter)id, 1u);
            TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_STATS_IO(work_a)->status, "if_set reported BUSY");
            IDEMIP_STATS_IO(work_a)->if_args.netif = (uint8_t)netif;
            IDEMIP_STATS_IO(work_a)->if_args.id = (IdemIpStatsIfCounter)id;
            Stats.if_read(work_a);
            TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_STATS_IO(work_a)->status, "if_read reported BUSY");
        }
    }
}

// A refused call reports nothing in io->value, so a caller cannot read a stale count as a fresh one.
void test_a_refused_read_reports_zero(void)
{
    Stats.clear(work_a);
    bump_by(work_a, IDEMIP_STAT_IP4_IN_RECEIVES, 0xDEADBEEFu);
    TEST_ASSERT_EQUAL_HEX32(0xDEADBEEFu, read_ctr(work_a, IDEMIP_STAT_IP4_IN_RECEIVES));

    IDEMIP_STATS_IO(work_a)->ctr_args.id = IDEMIP_STAT_COUNT;
    Stats.read(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_STATS_IO(work_a)->value);

    IDEMIP_STATS_IO(work_a)->if_args.netif = (uint8_t)IDEMIP_NETIF_COUNT;
    IDEMIP_STATS_IO(work_a)->if_args.id = IDEMIP_STAT_IF_IN_OCTETS;
    Stats.if_read(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_STATS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_STATS_IO(work_a)->value);
}
