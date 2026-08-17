// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for arp_table. It tests the CONTRACT, not the RFC 826 behavior:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_ARP_BORROW is intact after every case
//   5. the published offsets are ordered, sized and non-overlapping
//   6. clear leaves both tables zeroed, and a borrow clear has not run on is refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/arp/arp_table.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
#define DIRT 0xCCu
static _Alignas(8) uint8_t work_a[IDEMIP_ARP_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_ARP_BORROW + 16];

static const uint8_t g_sha[IDEMIP_ARP_HLN_ETHERNET] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t g_packet[IDEMIP_ARP_LEN];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_ARP_BORROW, CANARY, cap - IDEMIP_ARP_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_ARP_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_ARP_BORROW");
    }
}

// Every byte the two tables span, so a case can dirty them and see clear take them back.
static void dirty_tables(uint8_t *w)
{
    memset(w + IDEMIP_ARP_OFF_TAB, DIRT, (size_t)IDEMIP_ARP_BORROW - (size_t)IDEMIP_ARP_OFF_TAB);
}

static void assert_tables_zero(const uint8_t *w)
{
    for (size_t i = IDEMIP_ARP_OFF_TAB; i < (size_t)IDEMIP_ARP_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, w[i], "clear left a byte of the tables set");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_packet, 0, sizeof g_packet);
    idemip_arp_build_request(g_packet, g_sha, 0x0A000001u, 0x0A000002u);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    ArpTable.clear(NULL);
    ArpTable.add(NULL);
    ArpTable.find(NULL);
    ArpTable.remove(NULL);
    ArpTable.input(NULL);
    ArpTable.queue(NULL);
    ArpTable.dequeue(NULL);
    ArpTable.tick(NULL);
    TEST_PASS();
}

// The borrow IS the table, and the operand block is in it, so two tables share no byte at all. This
// is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    ArpTable.clear(work_a);
    ArpTable.clear(work_b);

    IDEMIP_ARP_IO(work_a)->add_args.pro = IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(work_a)->add_args.spa = 0x0A000001u;
    IDEMIP_ARP_IO(work_a)->add_args.sha = g_sha;
    IDEMIP_ARP_IO(work_a)->add_args.netif = 0u;
    IDEMIP_ARP_IO(work_a)->now_ms = 1000u;

    IDEMIP_ARP_IO(work_b)->add_args.pro = IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(work_b)->add_args.spa = 0x0A000002u;
    IDEMIP_ARP_IO(work_b)->add_args.sha = NULL;
    IDEMIP_ARP_IO(work_b)->add_args.netif = 1u;
    IDEMIP_ARP_IO(work_b)->now_ms = 2000u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_HEX32(0x0A000001u, IDEMIP_ARP_IO(work_a)->add_args.spa);
    TEST_ASSERT_EQUAL_PTR(g_sha, IDEMIP_ARP_IO(work_a)->add_args.sha);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ARP_IO(work_a)->add_args.netif);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_ARP_IO(work_a)->now_ms);

    // And a call on b leaves a's operands as they were.
    ArpTable.add(work_b);
    TEST_ASSERT_EQUAL_HEX32(0x0A000001u, IDEMIP_ARP_IO(work_a)->add_args.spa);
    TEST_ASSERT_EQUAL_PTR(g_sha, IDEMIP_ARP_IO(work_a)->add_args.sha);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_ARP_IO(work_a)->now_ms);
}

// clear writes every byte of one borrow's context and tables, so it is the widest write this module
// makes. It still reaches no byte of the other borrow.
void test_clear_on_one_borrow_leaves_the_other_alone(void)
{
    dirty_tables(work_b);
    ArpTable.clear(work_a);

    for (size_t i = IDEMIP_ARP_OFF_TAB; i < (size_t)IDEMIP_ARP_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(DIRT, work_b[i], "clear on one borrow reached into the other");
    }
    assert_tables_zero(work_a);
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    ArpTable.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ARP_IO(work_a)->status);
}

// Every row and every hold is the zero state, so a cleared table holds nothing.
void test_clear_zeroes_the_tables(void)
{
    dirty_tables(work_a);
    ArpTable.clear(work_a);
    assert_tables_zero(work_a);
}

// The operand block is the caller's. clear takes the context and the tables and leaves the operands
// where the caller put them.
void test_clear_leaves_the_operand_block_alone(void)
{
    IDEMIP_ARP_IO(work_a)->find_args.spa = 0x0A0000FEu;
    IDEMIP_ARP_IO(work_a)->find_args.pro = IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(work_a)->now_ms = 4242u;
    ArpTable.clear(work_a);
    TEST_ASSERT_EQUAL_HEX32(0x0A0000FEu, IDEMIP_ARP_IO(work_a)->find_args.spa);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ARP_PRO_IPV4, IDEMIP_ARP_IO(work_a)->find_args.pro);
    TEST_ASSERT_EQUAL_UINT32(4242u, IDEMIP_ARP_IO(work_a)->now_ms);
}

// A zeroed borrow is not an empty table: every list link in it reads as row zero rather than as
// IDEMIP_ARP_INDEX_NONE, so an entry that has not seen clear must refuse rather than walk it.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_ARP_IO(work_a)->add_args.sha = g_sha;
    IDEMIP_ARP_IO(work_a)->input_args.packet = g_packet;

    ArpTable.add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.queue(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.dequeue(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
}

// An entry that found nothing says so with the published terminator, not with row zero.
void test_a_refused_call_reports_no_row(void)
{
    ArpTable.find(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ARP_INDEX_NONE, IDEMIP_ARP_IO(work_a)->index);
    TEST_ASSERT_NULL(IDEMIP_ARP_IO(work_a)->mac);
}

// --- the published map -------------------------------------------------------

// The map is public so a reader can see where every region sits. These are the claims it makes.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ARP_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(sizeof(ArpTableIo), (size_t)IDEMIP_ARP_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_ARP_OFF_CTX < (size_t)IDEMIP_ARP_OFF_TAB,
                             "the context must sit between the operand block and the rows");
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_ARP_OFF_TAB + (IDEMIP_ARP_ENTRIES << IDEMIP_ARP_ENTRY_SHIFT),
                             (size_t)IDEMIP_ARP_OFF_PENDING);
}

void test_the_borrow_covers_the_published_map(void)
{
    size_t end = (size_t)IDEMIP_ARP_OFF_PENDING + (IDEMIP_ARP_PENDING << IDEMIP_ARP_PENDING_ENTRY_SHIFT);
    TEST_ASSERT_TRUE_MESSAGE(end <= (size_t)IDEMIP_ARP_BORROW, "IDEMIP_ARP_BORROW is short of the map");
}

// An index is one octet, and the terminator is one of its values.
void test_a_row_index_fits_the_published_terminator(void)
{
    TEST_ASSERT_TRUE(IDEMIP_ARP_ENTRIES < IDEMIP_ARP_INDEX_NONE);
    TEST_ASSERT_TRUE(IDEMIP_ARP_PENDING < IDEMIP_ARP_INDEX_NONE);
}

// Each table starts on IDEMIP_ALIGN, so row i is reachable at (i << SHIFT) from the borrow the caller
// took at that alignment.
void test_every_region_starts_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ARP_OFF_TAB & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ARP_OFF_PENDING & (IDEMIP_ALIGN - 1u));
}
