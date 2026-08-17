// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for the RFC 1122 sec 3.4 raw bindings. It tests the contract, not the protocol:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. the published offsets are ordered, non-overlapping, and inside IDEMIP_RAW_PCB_BORROW
//   5. clear zeroes the regions and marks the borrow, and a borrow that was never cleared is refused
//   6. an index past the table and a missing address operand are refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/raw/raw_pcb.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_RAW_PCB_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_RAW_PCB_BORROW + 16];

#define TAB_BYTES ((size_t)IDEMIP_RAW_PCBS << IDEMIP_RAW_PCB_ENTRY_SHIFT)

static const uint8_t g_local[IDEMIP_RAW_PCB_ADDR_BYTES] = {192u, 0u, 2u, 1u};
static const uint8_t g_remote[IDEMIP_RAW_PCB_ADDR_BYTES] = {192u, 0u, 2u, 9u};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_RAW_PCB_BORROW, CANARY, cap - IDEMIP_RAW_PCB_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_RAW_PCB_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_RAW_PCB_BORROW");
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

static void call_every_entry(uint8_t *w)
{
    RawPcb.open(w);
    RawPcb.close(w);
    RawPcb.bind(w);
    RawPcb.connect(w);
    RawPcb.disconnect(w);
    RawPcb.set_opts(w);
    RawPcb.load(w);
    RawPcb.find(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    RawPcb.clear(NULL);
    call_every_entry(NULL);
    TEST_PASS();
}

// The map is public, so a reader can place every region without opening the .c. Each region starts
// where the one before it ends, and the last one ends inside the borrow.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_RAW_PCB_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_RAW_PCB_OFF_IO + sizeof(RawPcbIo), (size_t)IDEMIP_RAW_PCB_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_RAW_PCB_OFF_TAB >= (size_t)IDEMIP_RAW_PCB_OFF_CTX,
                             "the table overlaps the context");
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_RAW_PCB_OFF_TAB + TAB_BYTES <= (size_t)IDEMIP_RAW_PCB_BORROW,
                             "the table runs past IDEMIP_RAW_PCB_BORROW");
    TEST_ASSERT_TRUE_MESSAGE(sizeof(RawPcbIo) <= (size_t)IDEMIP_RAW_PCB_CTX_BYTES,
                             "the operand block runs into the table");
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_RAW_PCB_OFF_IO, IDEMIP_RAW_PCB_IO(work_a));
}

// Zeroed, never cleared: every entry must refuse rather than read a table that was never zeroed.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_RAW_PCB_IO(work_a)->bind_args.ip = g_local;
    IDEMIP_RAW_PCB_IO(work_a)->connect_args.ip = g_remote;
    IDEMIP_RAW_PCB_IO(work_a)->find_args.local_ip = g_local;
    IDEMIP_RAW_PCB_IO(work_a)->find_args.remote_ip = g_remote;

    RawPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.disconnect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
}

// --- clear -------------------------------------------------------------------

void test_clear_zeroes_the_table(void)
{
    memset(work_a + IDEMIP_RAW_PCB_OFF_CTX, 0xEE, (size_t)IDEMIP_RAW_PCB_BORROW - IDEMIP_RAW_PCB_OFF_CTX);
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);
    for (size_t i = 0; i < TAB_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[IDEMIP_RAW_PCB_OFF_TAB + i], "clear left an entry unzeroed");
    }
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, IDEMIP_RAW_PCB_IO(work_a)->index);
}

// A second clear is the same call on the same bytes, so it reports the same thing.
void test_clear_repeats(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);
}

// The operand block is the caller's. clear reports through the result members and leaves the
// operands where they were.
void test_clear_leaves_the_operands_alone(void)
{
    IDEMIP_RAW_PCB_IO(work_a)->open_args.proto = 253u;
    IDEMIP_RAW_PCB_IO(work_a)->bind_args.ip = g_local;
    IDEMIP_RAW_PCB_IO(work_a)->opt_args.ttl = 64u;
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT8(253u, IDEMIP_RAW_PCB_IO(work_a)->open_args.proto);
    TEST_ASSERT_EQUAL_PTR(g_local, IDEMIP_RAW_PCB_IO(work_a)->bind_args.ip);
    TEST_ASSERT_EQUAL_UINT8(64u, IDEMIP_RAW_PCB_IO(work_a)->opt_args.ttl);
}

// --- two borrows -------------------------------------------------------------

// The borrow IS the table, and the operand block is in it, so two tables share no byte at all. This
// is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_RAW_PCB_IO(work_a)->open_args.proto = 253u;
    IDEMIP_RAW_PCB_IO(work_a)->pcb_args.index = 1u;
    IDEMIP_RAW_PCB_IO(work_b)->open_args.proto = 254u;
    IDEMIP_RAW_PCB_IO(work_b)->pcb_args.index = 0u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_UINT8(253u, IDEMIP_RAW_PCB_IO(work_a)->open_args.proto);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_RAW_PCB_IO(work_a)->pcb_args.index);
    TEST_ASSERT_EQUAL_UINT8(254u, IDEMIP_RAW_PCB_IO(work_b)->open_args.proto);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_RAW_PCB_IO(work_b)->pcb_args.index);

    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);

    // And b's operands are still b's after a's call.
    TEST_ASSERT_EQUAL_UINT8(254u, IDEMIP_RAW_PCB_IO(work_b)->open_args.proto);
    TEST_ASSERT_EQUAL_UINT8(253u, IDEMIP_RAW_PCB_IO(work_a)->open_args.proto);
}

// A clear on one borrow reaches no byte of the other's table.
void test_a_clear_on_one_borrow_leaves_the_other_table_untouched(void)
{
    memset(work_b + IDEMIP_RAW_PCB_OFF_TAB, 0xC3, TAB_BYTES);
    RawPcb.clear(work_a);
    for (size_t i = 0; i < TAB_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[IDEMIP_RAW_PCB_OFF_TAB + i], "a clear crossed into b's table");
    }
    RawPcb.clear(work_b);
    for (size_t i = 0; i < TAB_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_b[IDEMIP_RAW_PCB_OFF_TAB + i], "clear left an entry unzeroed");
    }
}

// --- the bounds on an operand ------------------------------------------------

// An index no entry has is refused, and reporting it as BUSY would have the caller retry a call that
// can never succeed.
void test_an_index_past_the_table_is_refused(void)
{
    RawPcb.clear(work_a);
    IDEMIP_RAW_PCB_IO(work_a)->pcb_args.index = (uint16_t)IDEMIP_RAW_PCBS;
    RawPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.disconnect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);

    IDEMIP_RAW_PCB_IO(work_a)->bind_args.index = (uint16_t)IDEMIP_RAW_PCBS;
    IDEMIP_RAW_PCB_IO(work_a)->bind_args.ip = g_local;
    RawPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);

    IDEMIP_RAW_PCB_IO(work_a)->opt_args.index = (uint16_t)IDEMIP_RAW_PCBS;
    RawPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
}

// A bind and a connect read IDEMIP_RAW_PCB_ADDR_BYTES from the operand, so a null one is refused
// rather than dereferenced.
void test_a_missing_address_operand_is_refused(void)
{
    RawPcb.clear(work_a);
    IDEMIP_RAW_PCB_IO(work_a)->bind_args.index = 0u;
    IDEMIP_RAW_PCB_IO(work_a)->bind_args.ip = NULL;
    RawPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);

    IDEMIP_RAW_PCB_IO(work_a)->connect_args.index = 0u;
    IDEMIP_RAW_PCB_IO(work_a)->connect_args.ip = NULL;
    RawPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);

    IDEMIP_RAW_PCB_IO(work_a)->find_args.local_ip = g_local;
    IDEMIP_RAW_PCB_IO(work_a)->find_args.remote_ip = NULL;
    RawPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, IDEMIP_RAW_PCB_IO(work_a)->index);
}

// A load that reports nothing leaves nothing of a former load behind.
void test_a_refused_load_reports_no_binding(void)
{
    RawPcb.clear(work_a);
    IDEMIP_RAW_PCB_IO(work_a)->info.proto = 253u;
    IDEMIP_RAW_PCB_IO(work_a)->info.local_ip = g_local;
    IDEMIP_RAW_PCB_IO(work_a)->pcb_args.index = (uint16_t)IDEMIP_RAW_PCBS;
    RawPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_RAW_PCB_IO(work_a)->info.proto);
    TEST_ASSERT_NULL(IDEMIP_RAW_PCB_IO(work_a)->info.local_ip);
}
