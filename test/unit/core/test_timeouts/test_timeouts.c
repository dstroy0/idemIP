// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for core/timeouts, modeled on test_phy. It tests the CONTRACT, so every case
// here stays valid once the deadline logic lands:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. the published offsets are ordered, non-overlapping, and inside IDEMIP_TIMEOUTS_BORROW
//   6. a canary past IDEMIP_TIMEOUTS_BORROW is intact after every case
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/core/timeouts.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
#define TAB_BYTES ((size_t)(IDEMIP_TIMEOUTS) << IDEMIP_TIMEOUT_ENTRY_SHIFT)

static _Alignas(8) uint8_t work_a[IDEMIP_TIMEOUTS_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_TIMEOUTS_BORROW + 16];

static void arm_canary(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_TIMEOUTS_BORROW, CANARY, cap - IDEMIP_TIMEOUTS_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_TIMEOUTS_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_TIMEOUTS_BORROW");
    }
}

// Fill the mapped span, leaving the canary alone, so a region a call fails to touch is visible.
static void dirty(uint8_t *w, uint8_t v)
{
    memset(w, v, IDEMIP_TIMEOUTS_BORROW);
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
    IDEMIP_TIMEOUTS_IO(w)->arm_args.unit = IDEMIP_TIMEOUT_UNIT_ARP;
    IDEMIP_TIMEOUTS_IO(w)->arm_args.arg = 0u;
    IDEMIP_TIMEOUTS_IO(w)->arm_args.deadline_ms = 1000u;
    IDEMIP_TIMEOUTS_IO(w)->arm_args.flags = IDEMIP_TIMEOUT_FLAG_ARMED;
    IDEMIP_TIMEOUTS_IO(w)->cancel_args.unit = IDEMIP_TIMEOUT_UNIT_ARP;
    IDEMIP_TIMEOUTS_IO(w)->cancel_args.arg = 0u;
    IDEMIP_TIMEOUTS_IO(w)->tick_args.now_ms = 500u;
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Timeouts.clear(NULL);
    Timeouts.arm(NULL);
    Timeouts.cancel(NULL);
    Timeouts.tick(NULL);
    Timeouts.expire(NULL);
    TEST_PASS();
}

// The borrow IS the list, and the operand block is in it, so two lists share no byte at all. This is
// the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_TIMEOUTS_IO(work_a)->arm_args.unit = IDEMIP_TIMEOUT_UNIT_ARP;
    IDEMIP_TIMEOUTS_IO(work_a)->arm_args.deadline_ms = 111u;
    IDEMIP_TIMEOUTS_IO(work_b)->arm_args.unit = IDEMIP_TIMEOUT_UNIT_DNS;
    IDEMIP_TIMEOUTS_IO(work_b)->arm_args.deadline_ms = 222u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_ARP, IDEMIP_TIMEOUTS_IO(work_a)->arm_args.unit);
    TEST_ASSERT_EQUAL_UINT32(111u, IDEMIP_TIMEOUTS_IO(work_a)->arm_args.deadline_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_DNS, IDEMIP_TIMEOUTS_IO(work_b)->arm_args.unit);
    TEST_ASSERT_EQUAL_UINT32(222u, IDEMIP_TIMEOUTS_IO(work_b)->arm_args.deadline_ms);

    // And a call on one borrow writes nothing in the other: b is filled, a is cleared, and every
    // mapped byte of b still holds the fill.
    dirty(work_b, 0x55u);
    Timeouts.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TIMEOUTS_IO(work_a)->status);
    expect_span(work_b, 0u, IDEMIP_TIMEOUTS_BORROW, 0x55u, "clear on one borrow wrote into the other");
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports. This is the determinism the design is named for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    dirty(work_a, 0xAAu);
    dirty(work_b, 0x33u);

    Timeouts.clear(work_a);
    IdemIpStatus first = IDEMIP_TIMEOUTS_IO(work_a)->status;
    uint8_t first_armed = IDEMIP_TIMEOUTS_IO(work_a)->armed;

    Timeouts.clear(work_b);
    Timeouts.clear(work_a);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, first);
    TEST_ASSERT_EQUAL_INT(first, IDEMIP_TIMEOUTS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(first_armed, IDEMIP_TIMEOUTS_IO(work_a)->armed);
}

// The map is public, so a reader can see where every region sits. Ordered, non-overlapping, and the
// last region ends inside the borrow.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_TIMEOUTS_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TIMEOUTS_OFF_CTX >= IDEMIP_TIMEOUTS_OFF_IO + sizeof(TimeoutsIo),
                             "the context overlaps the operand block");
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TIMEOUTS_OFF_TAB > IDEMIP_TIMEOUTS_OFF_CTX, "the table is not past the context");
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TIMEOUTS_OFF_TAB + TAB_BYTES <= IDEMIP_TIMEOUTS_BORROW,
                             "the table runs past IDEMIP_TIMEOUTS_BORROW");
    // Every region starts on the alignment the tree takes its borrows at.
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_TIMEOUTS_OFF_CTX & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_TIMEOUTS_OFF_TAB & (IDEMIP_ALIGN - 1u));
    // A slot is a power of two wide, so slot i is at (i << SHIFT).
    TEST_ASSERT_EQUAL_size_t(0u, (1u << IDEMIP_TIMEOUT_ENTRY_SHIFT) & ((1u << IDEMIP_TIMEOUT_ENTRY_SHIFT) - 1u));
}

// --- clear -------------------------------------------------------------------

// A zeroed slot holds no deadline, so clear zeroes the whole table however dirty it was.
void test_clear_zeroes_the_table_region(void)
{
    dirty(work_a, 0xAAu);
    Timeouts.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TIMEOUTS_IO(work_a)->status);
    expect_span(work_a, IDEMIP_TIMEOUTS_OFF_TAB, TAB_BYTES, 0u, "clear left a slot dirty");
}

void test_clear_reports_an_empty_list(void)
{
    dirty(work_a, 0xAAu);
    Timeouts.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TIMEOUTS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
}

// Clearing one borrow twice reports the same thing, and the second run finds the first's state.
void test_clear_is_repeatable(void)
{
    Timeouts.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TIMEOUTS_IO(work_a)->status);
    Timeouts.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TIMEOUTS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
    expect_span(work_a, IDEMIP_TIMEOUTS_OFF_TAB, TAB_BYTES, 0u, "the second clear left a slot dirty");
}

// --- refusals ----------------------------------------------------------------

// Zeroed, never cleared: every entry must refuse rather than run on whatever the caller's memory
// held. Retrying cannot help, so it is ERR and not BUSY.
void test_an_uncleared_borrow_is_refused(void)
{
    load_operands(work_a);
    Timeouts.arm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TIMEOUTS_IO(work_a)->status);
    Timeouts.cancel(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TIMEOUTS_IO(work_a)->status);
    Timeouts.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TIMEOUTS_IO(work_a)->status);
    Timeouts.expire(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TIMEOUTS_IO(work_a)->status);
}

// A borrow filled with garbage is not a cleared one either.
void test_a_dirty_borrow_is_refused(void)
{
    dirty(work_a, 0xAAu);
    load_operands(work_a);
    Timeouts.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TIMEOUTS_IO(work_a)->status);
    Timeouts.expire(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TIMEOUTS_IO(work_a)->status);
}

// IDEMIP_TIMEOUT_UNIT_NONE marks a free slot and COUNT is one past the last unit, so neither names
// a tick. A bad argument can never succeed on a retry, so it is ERR.
void test_arm_refuses_a_unit_the_list_does_not_carry(void)
{
    Timeouts.clear(work_a);
    load_operands(work_a);

    IDEMIP_TIMEOUTS_IO(work_a)->arm_args.unit = IDEMIP_TIMEOUT_UNIT_NONE;
    Timeouts.arm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TIMEOUTS_IO(work_a)->status);

    IDEMIP_TIMEOUTS_IO(work_a)->arm_args.unit = IDEMIP_TIMEOUT_UNIT_COUNT;
    Timeouts.arm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TIMEOUTS_IO(work_a)->status);
}

void test_cancel_refuses_a_unit_the_list_does_not_carry(void)
{
    Timeouts.clear(work_a);
    load_operands(work_a);

    IDEMIP_TIMEOUTS_IO(work_a)->cancel_args.unit = IDEMIP_TIMEOUT_UNIT_NONE;
    Timeouts.cancel(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TIMEOUTS_IO(work_a)->status);

    IDEMIP_TIMEOUTS_IO(work_a)->cancel_args.unit = IDEMIP_TIMEOUT_UNIT_COUNT;
    Timeouts.cancel(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TIMEOUTS_IO(work_a)->status);
}

// --- the whole namespace on a bound borrow -----------------------------------

// Every entry, on a cleared borrow, with plausible operands. tearDown proves none of them wrote
// past IDEMIP_TIMEOUTS_BORROW, and the canary on the other borrow proves none reached across.
void test_every_entry_stays_inside_the_borrow(void)
{
    Timeouts.clear(work_a);
    load_operands(work_a);
    Timeouts.arm(work_a);
    Timeouts.tick(work_a);
    Timeouts.expire(work_a);
    Timeouts.cancel(work_a);
    expect_span(work_b, 0u, IDEMIP_TIMEOUTS_BORROW, 0u, "a call on one borrow wrote into the other");
}

// =============================================================================
// Behavior. No RFC governs a deadline list, so these assert the properties the
// header states: one deadline per unit and argument index, earliest first, and a
// millisecond count that WRAPS, compared by the signed difference.
// =============================================================================

// The millisecond count wraps at 2^32, so these vectors straddle the wrap. 0xFFFFFF00 + 0x200 is
// 0x00000100, which every plain compare calls smaller than the count it is 512 ms after.
#define NOW_PRE_WRAP 0xFFFFFF00u
#define DEADLINE_POST_WRAP 0x00000100u
#define WRAP_DELTA_MS 0x200u
#define HALF_PERIOD_MS 0x80000000u

static void clear_ok(uint8_t *w)
{
    Timeouts.clear(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TIMEOUTS_IO(w)->status);
}

static IdemIpStatus arm_try(uint8_t *w, IdemIpTimeoutUnit unit, uint8_t arg, uint32_t deadline_ms)
{
    IDEMIP_TIMEOUTS_IO(w)->arm_args.unit = unit;
    IDEMIP_TIMEOUTS_IO(w)->arm_args.arg = arg;
    IDEMIP_TIMEOUTS_IO(w)->arm_args.deadline_ms = deadline_ms;
    IDEMIP_TIMEOUTS_IO(w)->arm_args.flags = IDEMIP_TIMEOUT_FLAG_NONE;
    Timeouts.arm(w);
    return IDEMIP_TIMEOUTS_IO(w)->status;
}

static void arm_ok(uint8_t *w, IdemIpTimeoutUnit unit, uint8_t arg, uint32_t deadline_ms)
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, arm_try(w, unit, arg, deadline_ms), "arm was refused");
}

static void tick_ok(uint8_t *w, uint32_t now_ms)
{
    IDEMIP_TIMEOUTS_IO(w)->tick_args.now_ms = now_ms;
    Timeouts.tick(w);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_TIMEOUTS_IO(w)->status, "tick was refused");
}

static IdemIpStatus cancel_try(uint8_t *w, IdemIpTimeoutUnit unit, uint8_t arg)
{
    IDEMIP_TIMEOUTS_IO(w)->cancel_args.unit = unit;
    IDEMIP_TIMEOUTS_IO(w)->cancel_args.arg = arg;
    Timeouts.cancel(w);
    return IDEMIP_TIMEOUTS_IO(w)->status;
}

static IdemIpStatus expire_next(uint8_t *w)
{
    Timeouts.expire(w);
    return IDEMIP_TIMEOUTS_IO(w)->status;
}

// --- what the tick reports ---------------------------------------------------

// An empty list has no earliest deadline, so the wait is IDEMIP_TIMEOUT_FOREVER and not zero.
void test_a_tick_on_an_empty_list_reports_forever(void)
{
    clear_ok(work_a);
    tick_ok(work_a, 1234u);
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_TIMEOUT_FOREVER, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
}

void test_clear_reports_forever(void)
{
    dirty(work_a, 0xAAu);
    clear_ok(work_a);
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_TIMEOUT_FOREVER, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
}

// until_ms is the wait from the count the tick recorded to the earliest deadline.
void test_a_tick_reports_the_wait_to_the_earliest_deadline(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 1000u);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
    tick_ok(work_a, 400u);
    TEST_ASSERT_EQUAL_UINT32(600u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
}

// The wait is zero once the deadline is reached, which is what tells a caller to drain.
void test_a_tick_at_the_deadline_reports_a_zero_wait(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 1000u);
    tick_ok(work_a, 1000u);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    tick_ok(work_a, 1001u);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
}

// The wait tracks the earliest of several, not the one armed last.
void test_a_tick_reports_the_earliest_of_several(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 900u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 300u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_TCP, 0u, 600u);
    tick_ok(work_a, 100u);
    TEST_ASSERT_EQUAL_UINT32(200u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
}

// A tick reports; it does not drain. The list is what it was.
void test_a_tick_drops_nothing(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 100u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 200u);
    tick_ok(work_a, 5000u);
    tick_ok(work_a, 5000u);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
}

// --- what expire takes ------------------------------------------------------

// Nothing due is BUSY, not ERR: a later tick makes the head due. ERR would abandon a live deadline.
void test_expire_before_the_deadline_is_busy(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 3u, 1000u);
    tick_ok(work_a, 999u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_NONE, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
}

// An empty list is BUSY for the same reason an empty ring is: an arm makes the retry succeed.
void test_expire_on_an_empty_list_is_busy(void)
{
    clear_ok(work_a);
    tick_ok(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_TIMEOUT_FOREVER, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
}

// The deadline is reached at the millisecond it names, so that tick is the one that fires it.
void test_expire_at_the_deadline_reports_the_pair_that_armed_it(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DHCP4, 7u, 1000u);
    tick_ok(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_DHCP4, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_UINT8(7u, IDEMIP_TIMEOUTS_IO(work_a)->arg);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);
}

// A deadline the tick ran past still fires, once.
void test_expire_past_the_deadline_still_reports_it(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_MLD6, 2u, 1000u);
    tick_ok(work_a, 60000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_MLD6, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_TIMEOUT_FOREVER, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
}

// Expire takes what the LAST TICK recorded, never the caller's clock directly: with no tick the
// recorded count is clear's zero, so nothing is due.
void test_expire_uses_the_count_the_last_tick_recorded(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
    tick_ok(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
}

// Earliest deadline first, whatever order they were armed in.
void test_expire_reports_deadlines_in_deadline_order(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 300u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 100u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_TCP, 0u, 200u);
    tick_ok(work_a, 300u);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_DNS, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_UINT32(100u, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_TCP, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_UINT32(200u, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_ARP, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_UINT32(300u, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);

    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
}

// The drain stops at the first deadline the recorded count has not reached, and the wait to it is
// what the report then carries.
void test_expire_drains_only_what_is_due(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 100u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 200u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_TCP, 0u, 900u);
    tick_ok(work_a, 250u);

    int drained = 0;
    while (expire_next(work_a) == IDEMIP_OK)
    {
        drained++;
    }
    TEST_ASSERT_EQUAL_INT(2, drained);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
    TEST_ASSERT_EQUAL_UINT32(650u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
}

// Two deadlines on the same millisecond both fire, in the order they were armed.
void test_two_deadlines_on_the_same_millisecond_both_fire(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 500u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 500u);
    tick_ok(work_a, 500u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_ARP, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_DNS, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
}

// --- arm keyed on the pair --------------------------------------------------

// One deadline per unit and argument index: arming the same pair again moves it rather than taking a
// second slot, and the deadline it moved to is the one that fires.
void test_arm_rearms_the_same_pair_in_place(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 4u, 1000u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 4u, 5000u);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_TIMEOUTS_IO(work_a)->armed);

    tick_ok(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
    TEST_ASSERT_EQUAL_UINT32(4000u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);

    tick_ok(work_a, 5000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_UINT32(5000u, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);
}

// A rearm that moves a deadline earlier reorders it against the rest.
void test_a_rearm_earlier_reorders_the_list(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 900u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 500u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 100u);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
    tick_ok(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_ARP, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_UINT32(100u, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_DNS, IDEMIP_TIMEOUTS_IO(work_a)->unit);
}

// The argument index is part of the key, so one unit holds a deadline per entry of its own table.
void test_the_same_unit_at_two_argument_indices_holds_two_deadlines(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DAD, 0u, 400u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DAD, 1u, 200u);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
    tick_ok(work_a, 400u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_TIMEOUTS_IO(work_a)->arg);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_TIMEOUTS_IO(work_a)->arg);
}

// Every unit the enum names is armable, and the flags the caller passed keep the ARMED bit.
void test_arm_accepts_every_unit_the_enum_names(void)
{
    clear_ok(work_a);
    unsigned n = (unsigned)IDEMIP_TIMEOUT_UNIT_COUNT - 1u;
    if (n > (unsigned)(IDEMIP_TIMEOUTS))
    {
        n = (unsigned)(IDEMIP_TIMEOUTS);
    }
    for (unsigned u = 1u; u <= n; u++)
    {
        arm_ok(work_a, (IdemIpTimeoutUnit)u, 0u, (uint32_t)(u * 10u));
    }
    TEST_ASSERT_EQUAL_UINT8((uint8_t)n, IDEMIP_TIMEOUTS_IO(work_a)->armed);
    tick_ok(work_a, (uint32_t)(n * 10u));
    for (unsigned u = 1u; u <= n; u++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
        TEST_ASSERT_EQUAL_INT((int)u, (int)IDEMIP_TIMEOUTS_IO(work_a)->unit);
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
}

// Every slot armed is BUSY, because a cancel or an expire frees one and the retry then succeeds.
// ERR would abandon a service's timer while the list is merely full.
void test_a_full_list_is_busy_and_the_retry_succeeds(void)
{
    clear_ok(work_a);
    for (unsigned i = 0u; i < (unsigned)(IDEMIP_TIMEOUTS); i++)
    {
        arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, (uint8_t)i, (uint32_t)(1000u + i));
    }
    TEST_ASSERT_EQUAL_UINT8((uint8_t)(IDEMIP_TIMEOUTS), IDEMIP_TIMEOUTS_IO(work_a)->armed);

    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, arm_try(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 500u));
    TEST_ASSERT_EQUAL_UINT8((uint8_t)(IDEMIP_TIMEOUTS), IDEMIP_TIMEOUTS_IO(work_a)->armed);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, arm_try(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 500u));
    TEST_ASSERT_EQUAL_UINT8((uint8_t)(IDEMIP_TIMEOUTS), IDEMIP_TIMEOUTS_IO(work_a)->armed);
}

// A full list still rearms a pair it already holds, since that takes no new slot.
void test_a_full_list_still_rearms_a_pair_it_holds(void)
{
    clear_ok(work_a);
    for (unsigned i = 0u; i < (unsigned)(IDEMIP_TIMEOUTS); i++)
    {
        arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, (uint8_t)i, (uint32_t)(1000u + i));
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, arm_try(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 77u));
    tick_ok(work_a, 77u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_UINT32(77u, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);
}

// --- cancel ------------------------------------------------------------------

// The deadline is gone, so the tick that would have fired it finds nothing due.
void test_cancel_drops_the_deadline(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_IGMP, 1u, 800u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_IGMP, 1u));
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_TIMEOUT_FOREVER, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    tick_ok(work_a, 5000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
}

// A freed slot is left as clear left it, so nothing of the dropped deadline remains in the table.
void test_cancel_zeroes_the_slot_it_freed(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_IGMP, 1u, 800u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_IGMP, 1u));
    expect_span(work_a, IDEMIP_TIMEOUTS_OFF_TAB, TAB_BYTES, 0u, "cancel left the slot armed");
}

// An expired deadline is dropped too, so its slot goes back as clear left it.
void test_expire_frees_the_slot_it_took(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_IGMP, 1u, 800u);
    tick_ok(work_a, 800u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    expect_span(work_a, IDEMIP_TIMEOUTS_OFF_TAB, TAB_BYTES, 0u, "expire left the slot armed");
}

// A pair the list does not hold is BUSY, which is what timeouts.h states for it.
void test_cancel_of_a_deadline_the_list_does_not_hold_is_busy(void)
{
    clear_ok(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u));
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 1u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u));
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
}

// A cancel twice: the second finds nothing to drop.
void test_a_second_cancel_is_busy(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u));
}

// Cancelling out of the middle leaves the order of the rest intact.
void test_cancel_keeps_the_order_of_the_rest(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 100u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 200u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_TCP, 0u, 300u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u));
    tick_ok(work_a, 300u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_ARP, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_TCP, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
}

// Cancelling the head moves the earliest deadline to the next one.
void test_cancel_of_the_head_moves_the_wait_to_the_next(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 100u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 400u);
    tick_ok(work_a, 0u);
    TEST_ASSERT_EQUAL_UINT32(100u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u));
    TEST_ASSERT_EQUAL_UINT32(400u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
}

// A slot cancelled and armed again is reused, so the list neither leaks nor loses order.
void test_slots_are_reused_across_cancel_and_arm(void)
{
    clear_ok(work_a);
    for (unsigned round = 0u; round < 4u; round++)
    {
        for (unsigned i = 0u; i < (unsigned)(IDEMIP_TIMEOUTS); i++)
        {
            arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, (uint8_t)i, (uint32_t)(100u + i));
        }
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(IDEMIP_TIMEOUTS), IDEMIP_TIMEOUTS_IO(work_a)->armed);
        for (unsigned i = 0u; i < (unsigned)(IDEMIP_TIMEOUTS); i++)
        {
            TEST_ASSERT_EQUAL_INT(IDEMIP_OK, cancel_try(work_a, IDEMIP_TIMEOUT_UNIT_ARP, (uint8_t)i));
        }
        TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
        expect_span(work_a, IDEMIP_TIMEOUTS_OFF_TAB, TAB_BYTES, 0u, "a slot survived its cancel");
    }
}

// --- the wrap ----------------------------------------------------------------
// The millisecond count wraps at 2^32. Every comparison here is the signed difference, so a deadline
// whose count is numerically smaller than the clock's is still in the future.

// 0xFFFFFF00 + 512 is 0x00000100. A plain deadline <= now would call it due 512 ms early, and every
// timer in the stack would fire at once at the wrap.
void test_a_deadline_past_the_wrap_is_not_due_before_it(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_TCP, 0u, DEADLINE_POST_WRAP);
    tick_ok(work_a, NOW_PRE_WRAP);
    TEST_ASSERT_EQUAL_UINT32(WRAP_DELTA_MS, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_TIMEOUTS_IO(work_a)->armed);
}

// One millisecond short of the deadline, with the count already past the wrap.
void test_a_deadline_past_the_wrap_is_not_due_one_millisecond_early(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_TCP, 0u, DEADLINE_POST_WRAP);
    tick_ok(work_a, DEADLINE_POST_WRAP - 1u);
    TEST_ASSERT_EQUAL_UINT32(1u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
}

// And it fires at the millisecond it names, on the far side of the wrap.
void test_a_deadline_past_the_wrap_fires_after_the_wrap(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_TCP, 5u, DEADLINE_POST_WRAP);
    tick_ok(work_a, NOW_PRE_WRAP);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
    tick_ok(work_a, DEADLINE_POST_WRAP);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_TCP, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_TIMEOUTS_IO(work_a)->arg);
    TEST_ASSERT_EQUAL_UINT32(DEADLINE_POST_WRAP, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);
}

// Order across the wrap: 0xFFFFFF80 precedes 0x00000100 even though it is the larger number. Armed
// in the wrong order so the ordering, not the arm order, is what is asserted.
void test_the_order_holds_across_the_wrap(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, DEADLINE_POST_WRAP);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 0xFFFFFF80u);
    tick_ok(work_a, NOW_PRE_WRAP);
    TEST_ASSERT_EQUAL_UINT32(0x80u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);

    tick_ok(work_a, DEADLINE_POST_WRAP);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_ARP, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFF80u, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_DNS, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_HEX32(DEADLINE_POST_WRAP, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);
}

// A count that steps over the wrap fires everything it passed, in order.
void test_a_tick_that_steps_over_the_wrap_drains_in_order(void)
{
    clear_ok(work_a);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 0xFFFFFFF0u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_DNS, 0u, 0x00000010u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_TCP, 0u, 0x00000030u);
    tick_ok(work_a, 0xFFFFFFE0u);
    TEST_ASSERT_EQUAL_UINT32(0x10u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));

    tick_ok(work_a, 0x00000020u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFF0u, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_HEX32(0x00000010u, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
    TEST_ASSERT_EQUAL_UINT32(0x10u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
}

// A deadline armed at the count itself is due at once, wrap or not.
void test_a_deadline_at_the_recorded_count_is_due(void)
{
    clear_ok(work_a);
    tick_ok(work_a, 0xFFFFFFFFu);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ACD, 0u, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, IDEMIP_TIMEOUTS_IO(work_a)->deadline_ms);
}

// The signed difference holds over one half period ahead, and one millisecond past that a deadline
// reads as behind the count. That is the window a wrapping count has, and it is 24.8 days.
void test_the_forward_window_is_one_half_period(void)
{
    clear_ok(work_a);
    tick_ok(work_a, 1000u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 1000u + HALF_PERIOD_MS);
    TEST_ASSERT_EQUAL_HEX32(HALF_PERIOD_MS, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));

    clear_ok(work_a);
    tick_ok(work_a, 1000u);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 1000u + HALF_PERIOD_MS + 1u);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
}

// An armed deadline never reports the empty list's wait, whatever the wrap does, so a caller cannot
// read FOREVER while something is pending.
void test_an_armed_deadline_never_reports_forever(void)
{
    static const uint32_t nows[] = {0u, 1u, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFF00u, 0xFFFFFFFFu};
    static const uint32_t deads[] = {0u, 1u, 0x100u, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFFu};
    for (unsigned i = 0u; i < sizeof nows / sizeof nows[0]; i++)
    {
        for (unsigned j = 0u; j < sizeof deads / sizeof deads[0]; j++)
        {
            clear_ok(work_a);
            arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ND6, 0u, deads[j]);
            tick_ok(work_a, nows[i]);
            TEST_ASSERT_NOT_EQUAL_UINT32(IDEMIP_TIMEOUT_FOREVER, IDEMIP_TIMEOUTS_IO(work_a)->until_ms);
            TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TIMEOUTS_IO(work_a)->until_ms <= HALF_PERIOD_MS,
                                     "the wait ran past one half period");
        }
    }
}

// --- two borrows -------------------------------------------------------------

// The borrow IS the list, so a deadline armed in one is not in the other.
void test_two_borrows_hold_independent_lists(void)
{
    clear_ok(work_a);
    clear_ok(work_b);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 100u);
    tick_ok(work_b, 5000u);
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_TIMEOUT_FOREVER, IDEMIP_TIMEOUTS_IO(work_b)->until_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_b));
    tick_ok(work_a, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
}

// An expire is a function of its borrow alone: interleaving one on the other changes neither.
void test_an_expire_is_a_function_of_its_borrow_alone(void)
{
    clear_ok(work_a);
    clear_ok(work_b);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 1u, 100u);
    arm_ok(work_b, IDEMIP_TIMEOUT_UNIT_DNS, 2u, 100u);
    tick_ok(work_a, 100u);
    tick_ok(work_b, 100u);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_b));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_DNS, IDEMIP_TIMEOUTS_IO(work_b)->unit);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_ARP, IDEMIP_TIMEOUTS_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_TIMEOUTS_IO(work_a)->arg);
}

// A tick recorded in one borrow is not the count the other compares against.
void test_a_tick_in_one_borrow_does_not_advance_the_other(void)
{
    clear_ok(work_a);
    clear_ok(work_b);
    arm_ok(work_a, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 100u);
    arm_ok(work_b, IDEMIP_TIMEOUT_UNIT_ARP, 0u, 100u);
    tick_ok(work_b, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, expire_next(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, expire_next(work_b));
}
