// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for ip4_reass. It tests the CONTRACT, not the RFC 791 sec 3.2 or RFC 815
// behavior:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_IP4_REASS_BORROW is intact after every case
//   5. the published offsets are ordered, sized and non-overlapping across all three tables
//   6. clear leaves the tables zeroed, and a borrow clear has not run on is refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/ip/ip4_reass.h"

#include <string.h>
#include <unity.h>

#define CANARY 0x5Au
#define DIRT 0xCCu
static _Alignas(8) uint8_t work_a[IDEMIP_IP4_REASS_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_IP4_REASS_BORROW + 16];

// A fragment header for the operands to point at. The suite never asks the unit to read it.
static uint8_t g_hdr[IDEMIP_IP4_HDR_MAX];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP4_REASS_BORROW, CANARY, cap - IDEMIP_IP4_REASS_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP4_REASS_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP4_REASS_BORROW");
    }
}

// Every byte the three tables span, so a case can dirty them and see clear take them back.
static void dirty_tables(uint8_t *w)
{
    memset(w + IDEMIP_IP4_REASS_OFF_DGRAM, DIRT,
           (size_t)IDEMIP_IP4_REASS_BORROW - (size_t)IDEMIP_IP4_REASS_OFF_DGRAM);
}

static void assert_tables_zero(const uint8_t *w)
{
    for (size_t i = IDEMIP_IP4_REASS_OFF_DGRAM; i < (size_t)IDEMIP_IP4_REASS_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, w[i], "clear left a byte of the tables set");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_hdr, 0, sizeof g_hdr);
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
    Ip4Reass.clear(NULL);
    Ip4Reass.hold(NULL);
    Ip4Reass.next(NULL);
    Ip4Reass.release(NULL);
    Ip4Reass.reclaim(NULL);
    Ip4Reass.tick(NULL);
    TEST_PASS();
}

// The borrow IS the reassembler, and the operand block is in it, so two of them share no byte.
void test_two_borrows_share_no_byte(void)
{
    Ip4Reass.clear(work_a);
    Ip4Reass.clear(work_b);

    IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr = g_hdr;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc = 3u;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.len = 100u;
    IDEMIP_IP4_REASS_IO(work_a)->now_ms = 1000u;

    IDEMIP_IP4_REASS_IO(work_b)->hold_args.hdr = NULL;
    IDEMIP_IP4_REASS_IO(work_b)->hold_args.desc = 9u;
    IDEMIP_IP4_REASS_IO(work_b)->hold_args.len = 200u;
    IDEMIP_IP4_REASS_IO(work_b)->now_ms = 2000u;

    TEST_ASSERT_EQUAL_PTR(g_hdr, IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr);
    TEST_ASSERT_EQUAL_UINT16(3u, IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc);
    TEST_ASSERT_EQUAL_UINT16(100u, IDEMIP_IP4_REASS_IO(work_a)->hold_args.len);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_IP4_REASS_IO(work_a)->now_ms);

    // A call on b leaves a's operands as they were.
    Ip4Reass.hold(work_b);
    TEST_ASSERT_EQUAL_PTR(g_hdr, IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr);
    TEST_ASSERT_EQUAL_UINT16(3u, IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_IP4_REASS_IO(work_a)->now_ms);
}

// clear writes every byte of one borrow's context and tables, and still reaches no byte of the other.
void test_clear_on_one_borrow_leaves_the_other_alone(void)
{
    dirty_tables(work_b);
    Ip4Reass.clear(work_a);

    for (size_t i = IDEMIP_IP4_REASS_OFF_DGRAM; i < (size_t)IDEMIP_IP4_REASS_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(DIRT, work_b[i], "clear on one borrow reached into the other");
    }
    assert_tables_zero(work_a);
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_REASS_IO(work_a)->status);
}

// Every datagram row, every held fragment and every hole descriptor is the zero state.
void test_clear_zeroes_the_tables(void)
{
    dirty_tables(work_a);
    Ip4Reass.clear(work_a);
    assert_tables_zero(work_a);
}

void test_clear_leaves_the_operand_block_alone(void)
{
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr = g_hdr;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc = 7u;
    IDEMIP_IP4_REASS_IO(work_a)->now_ms = 4242u;
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_hdr, IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr);
    TEST_ASSERT_EQUAL_UINT16(7u, IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc);
    TEST_ASSERT_EQUAL_UINT32(4242u, IDEMIP_IP4_REASS_IO(work_a)->now_ms);
}

// A zeroed borrow is not an empty reassembler: every list link in it reads as row zero rather than as
// IDEMIP_IP4_REASS_INDEX_NONE, so an entry that has not seen clear must refuse rather than walk it.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr = g_hdr;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.len = 100u;

    Ip4Reass.hold(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
    Ip4Reass.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
    Ip4Reass.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
    Ip4Reass.reclaim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
    Ip4Reass.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
}

// A hold that took nothing in says so with the published terminator, and claims no completion.
void test_a_refused_hold_reports_no_row(void)
{
    Ip4Reass.hold(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_REASS_INDEX_NONE, IDEMIP_IP4_REASS_IO(work_a)->index);
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// --- the published map -------------------------------------------------------

void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_REASS_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(sizeof(Ip4ReassIo), (size_t)IDEMIP_IP4_REASS_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_IP4_REASS_OFF_CTX < (size_t)IDEMIP_IP4_REASS_OFF_DGRAM,
                             "the context must sit between the operand block and the datagram rows");
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_IP4_REASS_OFF_DGRAM +
                                 (IDEMIP_IP4_REASS_DATAGRAMS << IDEMIP_IP4_REASS_DATAGRAM_ENTRY_SHIFT),
                             (size_t)IDEMIP_IP4_REASS_OFF_FRAG);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_IP4_REASS_OFF_FRAG +
                                 (IDEMIP_IP4_REASS_FRAGS << IDEMIP_IP4_REASS_FRAG_ENTRY_SHIFT),
                             (size_t)IDEMIP_IP4_REASS_OFF_HOLE);
}

void test_the_borrow_covers_the_published_map(void)
{
    size_t end = (size_t)IDEMIP_IP4_REASS_OFF_HOLE + (IDEMIP_IP4_REASS_HOLES << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT);
    TEST_ASSERT_TRUE_MESSAGE(end <= (size_t)IDEMIP_IP4_REASS_BORROW, "IDEMIP_IP4_REASS_BORROW is short of the map");
}

void test_a_row_index_fits_the_published_terminator(void)
{
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_DATAGRAMS < IDEMIP_IP4_REASS_INDEX_NONE);
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_FRAGS < IDEMIP_IP4_REASS_INDEX_NONE);
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_HOLES < IDEMIP_IP4_REASS_INDEX_NONE);
}

void test_every_region_starts_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_REASS_OFF_DGRAM & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_REASS_OFF_FRAG & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_REASS_OFF_HOLE & (IDEMIP_ALIGN - 1u));
}

// RFC 815 sec 3 opens a datagram with one hole reaching to infinity, and RFC 815 sec 4 sizes a hole
// descriptor at eight octets.
void test_the_hole_table_matches_rfc_815(void)
{
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_HOLES >= IDEMIP_IP4_REASS_DATAGRAMS + IDEMIP_IP4_REASS_FRAGS);
    TEST_ASSERT_TRUE((1u << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT) >= 8u);
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_INFINITY >= IDEMIP_IP4_TOTAL_LEN_MAX - 1u);
}
