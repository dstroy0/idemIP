// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for ip4_route. It tests the CONTRACT, not the RFC 1122 sec 3.3.1 behavior:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_IP4_ROUTE_BORROW is intact after every case
//   5. the published offsets are ordered, sized and non-overlapping
//   6. clear leaves the table zeroed, and a borrow clear has not run on is refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/ip/ip4_route.h"

#include <string.h>
#include <unity.h>

#define CANARY 0x5Au
#define DIRT 0xCCu
static _Alignas(8) uint8_t work_a[IDEMIP_IP4_ROUTE_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_IP4_ROUTE_BORROW + 16];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP4_ROUTE_BORROW, CANARY, cap - IDEMIP_IP4_ROUTE_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP4_ROUTE_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP4_ROUTE_BORROW");
    }
}

static void dirty_table(uint8_t *w)
{
    memset(w + IDEMIP_IP4_ROUTE_OFF_TAB, DIRT,
           (size_t)IDEMIP_IP4_ROUTE_BORROW - (size_t)IDEMIP_IP4_ROUTE_OFF_TAB);
}

static void assert_table_zero(const uint8_t *w)
{
    for (size_t i = IDEMIP_IP4_ROUTE_OFF_TAB; i < (size_t)IDEMIP_IP4_ROUTE_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, w[i], "clear left a byte of the table set");
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

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Ip4Route.clear(NULL);
    Ip4Route.add(NULL);
    Ip4Route.remove(NULL);
    Ip4Route.lookup(NULL);
    Ip4Route.redirect(NULL);
    Ip4Route.set_pmtu(NULL);
    Ip4Route.tick(NULL);
    TEST_PASS();
}

// The borrow IS the table, and the operand block is in it, so two routing tables share no byte.
void test_two_borrows_share_no_byte(void)
{
    Ip4Route.clear(work_a);
    Ip4Route.clear(work_b);

    IDEMIP_IP4_ROUTE_IO(work_a)->add_args.dst = 0xC0A80100u;
    IDEMIP_IP4_ROUTE_IO(work_a)->add_args.mask = 0xFFFFFF00u;
    IDEMIP_IP4_ROUTE_IO(work_a)->add_args.gw = 0u;
    IDEMIP_IP4_ROUTE_IO(work_a)->add_args.netif = 0u;
    IDEMIP_IP4_ROUTE_IO(work_a)->now_ms = 1000u;

    IDEMIP_IP4_ROUTE_IO(work_b)->add_args.dst = 0u;
    IDEMIP_IP4_ROUTE_IO(work_b)->add_args.mask = 0u;
    IDEMIP_IP4_ROUTE_IO(work_b)->add_args.gw = 0x0A000001u;
    IDEMIP_IP4_ROUTE_IO(work_b)->add_args.netif = 1u;
    IDEMIP_IP4_ROUTE_IO(work_b)->now_ms = 2000u;

    TEST_ASSERT_EQUAL_HEX32(0xC0A80100u, IDEMIP_IP4_ROUTE_IO(work_a)->add_args.dst);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFF00u, IDEMIP_IP4_ROUTE_IO(work_a)->add_args.mask);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP4_ROUTE_IO(work_a)->add_args.netif);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_IP4_ROUTE_IO(work_a)->now_ms);

    // A call on b leaves a's operands as they were.
    Ip4Route.add(work_b);
    TEST_ASSERT_EQUAL_HEX32(0xC0A80100u, IDEMIP_IP4_ROUTE_IO(work_a)->add_args.dst);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_IP4_ROUTE_IO(work_a)->now_ms);
}

// clear writes every byte of one borrow's context and table, and still reaches no byte of the other.
void test_clear_on_one_borrow_leaves_the_other_alone(void)
{
    dirty_table(work_b);
    Ip4Route.clear(work_a);

    for (size_t i = IDEMIP_IP4_ROUTE_OFF_TAB; i < (size_t)IDEMIP_IP4_ROUTE_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(DIRT, work_b[i], "clear on one borrow reached into the other");
    }
    assert_table_zero(work_a);
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Ip4Route.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

void test_clear_zeroes_the_table(void)
{
    dirty_table(work_a);
    Ip4Route.clear(work_a);
    assert_table_zero(work_a);
}

void test_clear_leaves_the_operand_block_alone(void)
{
    IDEMIP_IP4_ROUTE_IO(work_a)->lookup_args.dst = 0x08080808u;
    IDEMIP_IP4_ROUTE_IO(work_a)->lookup_args.tos = 0x10u;
    IDEMIP_IP4_ROUTE_IO(work_a)->now_ms = 4242u;
    Ip4Route.clear(work_a);
    TEST_ASSERT_EQUAL_HEX32(0x08080808u, IDEMIP_IP4_ROUTE_IO(work_a)->lookup_args.dst);
    TEST_ASSERT_EQUAL_HEX8(0x10u, IDEMIP_IP4_ROUTE_IO(work_a)->lookup_args.tos);
    TEST_ASSERT_EQUAL_UINT32(4242u, IDEMIP_IP4_ROUTE_IO(work_a)->now_ms);
}

// A zeroed borrow is not an empty table, so an entry that has not seen clear refuses it.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_IP4_ROUTE_IO(work_a)->lookup_args.dst = 0x08080808u;

    Ip4Route.add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    Ip4Route.remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    Ip4Route.lookup(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    Ip4Route.redirect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    Ip4Route.set_pmtu(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    Ip4Route.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// A lookup that routed nothing says so with the published terminator, not with row zero.
void test_a_refused_lookup_reports_no_row(void)
{
    Ip4Route.lookup(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ROUTE_IO(work_a)->direct);
}

// --- the published map -------------------------------------------------------

void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_ROUTE_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(sizeof(Ip4RouteIo), (size_t)IDEMIP_IP4_ROUTE_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_IP4_ROUTE_OFF_CTX < (size_t)IDEMIP_IP4_ROUTE_OFF_TAB,
                             "the context must sit between the operand block and the rows");
}

void test_the_borrow_covers_the_published_map(void)
{
    size_t end = (size_t)IDEMIP_IP4_ROUTE_OFF_TAB + (IDEMIP_IP4_ROUTES << IDEMIP_IP4_ROUTE_ENTRY_SHIFT);
    TEST_ASSERT_TRUE_MESSAGE(end <= (size_t)IDEMIP_IP4_ROUTE_BORROW, "IDEMIP_IP4_ROUTE_BORROW is short of the map");
}

void test_a_row_index_fits_the_published_terminator(void)
{
    TEST_ASSERT_TRUE(IDEMIP_IP4_ROUTES < IDEMIP_IP4_ROUTE_INDEX_NONE);
}

void test_the_table_starts_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_ROUTE_OFF_TAB & (IDEMIP_ALIGN - 1u));
}

// The flags are one octet on the row, so each published bit has to fit in one.
void test_the_published_flags_fit_one_octet(void)
{
    unsigned int all = IDEMIP_IP4_ROUTE_F_GATEWAY | IDEMIP_IP4_ROUTE_F_STATIC | IDEMIP_IP4_ROUTE_F_REDIRECT_OK |
                       IDEMIP_IP4_ROUTE_F_HOST;
    unsigned int sum = IDEMIP_IP4_ROUTE_F_GATEWAY + IDEMIP_IP4_ROUTE_F_STATIC + IDEMIP_IP4_ROUTE_F_REDIRECT_OK +
                       IDEMIP_IP4_ROUTE_F_HOST;
    TEST_ASSERT_EQUAL_UINT(0u, all & ~0xFFu);
    // The sum matches the union only where no two flags share a bit.
    TEST_ASSERT_EQUAL_UINT(sum, all);
}
