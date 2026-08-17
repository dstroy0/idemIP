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
