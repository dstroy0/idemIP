// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for ip4_route. The storage half tests the CONTRACT, not the RFC 1122 sec 3.3.1 behavior:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_IP4_ROUTE_BORROW is intact after every case
//   5. the published offsets are ordered, sized and non-overlapping
//   6. clear leaves the table zeroed, and a borrow clear has not run on is refused
//
// The behavior half drives the RFC's own printed vectors:
//
//   RFC 1812 sec 5.2.4.3 rule 1 Basic Match prints 10.144.2.5 against 128.12.0.0/16, 10.0.0.0/8 and
//   10.144.0.0/16, then 10.144.2.5 against 10.144.1.0/24, 10.144.2.0/24 and 10.144.3.0/24. Rule 2
//   Longest Match prints 10.144.2.5 against 10.144.2.0/24, 10.144.0.0/16 and 10.0.0.0/8.
//
//   RFC 1122 sec 3.3.1 prints no addresses and RFC 1191 prints no routes, so what those sections
//   state as text is asserted as a property instead. RFC 1191 table 7-1's plateau values 1492, 576
//   and 296 are the estimates driven here.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ip/ip4_route.h"

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

// RFC 1812 sec 5.2.4.3: "If the set ever becomes empty, the packet is discarded because the
// destination is unreachable." A lookup that routed nothing says so with the published terminator,
// not with row zero, and reports BUSY because an added route makes the same lookup succeed.
void test_a_lookup_that_routed_nothing_reports_no_row(void)
{
    Ip4Route.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    IDEMIP_IP4_ROUTE_IO(work_a)->lookup_args.dst = 0x08080808u;
    IDEMIP_IP4_ROUTE_IO(work_a)->lookup_args.tos = 0u;
    Ip4Route.lookup(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status,
                                  "an empty table routes nothing, which a later add changes");
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ROUTE_IO(work_a)->direct);
    // RFC 1812 sec 4.3.3.1's Code 0 case: "no routes at all (including no default route)".
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP4_ROUTE_IO(work_a)->tos_blocked,
                              "no row matched at all, so the TOS is not what blocked it");
}

// A borrow no clear has run on carries no table, so a lookup refuses it outright.
void test_a_lookup_on_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_IP4_ROUTE_IO(work_a)->lookup_args.dst = 0x08080808u;
    Ip4Route.lookup(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);
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

// ============================================================================
// The behavior half
// ============================================================================

// The addresses RFC 1812 sec 5.2.4.3 prints, and RFC 1191 table 7-1's plateau values.
#define IP_10_144_2_5 0x0A900205u
#define NET_128_12_16 0x800C0000u
#define NET_10_8 0x0A000000u
#define NET_10_144_16 0x0A900000u
#define NET_10_144_1_24 0x0A900100u
#define NET_10_144_2_24 0x0A900200u
#define NET_10_144_3_24 0x0A900300u
#define M8 0xFF000000u
#define M16 0xFFFF0000u
#define M24 0xFFFFFF00u
#define M32 0xFFFFFFFFu

#define LAN_192_168_1_24 0xC0A80100u
#define GW_192_168_1_1 0xC0A80101u
#define GW_192_168_1_9 0xC0A80109u
#define GW_10_0_0_1 0x0A000001u
#define OFFNET_GW_172_16_0_1 0xAC100001u

#define MTU_1492 1492u
#define MTU_576 576u
#define MTU_296 296u
#define MTU_MIN 68u
#define SWEEP_MS IDEMIP_IP4_ROUTE_PMTU_SWEEP_MS
#define AGE_MS IDEMIP_IP4_ROUTE_PMTU_TIMEOUT_MS

static uint8_t add_row(uint8_t *w, uint32_t dst, uint32_t mask, uint32_t gw, uint8_t flags, uint8_t netif, uint8_t tos,
                       uint16_t metric)
{
    IDEMIP_IP4_ROUTE_IO(w)->add_args.dst = dst;
    IDEMIP_IP4_ROUTE_IO(w)->add_args.mask = mask;
    IDEMIP_IP4_ROUTE_IO(w)->add_args.gw = gw;
    IDEMIP_IP4_ROUTE_IO(w)->add_args.flags = flags;
    IDEMIP_IP4_ROUTE_IO(w)->add_args.netif = netif;
    IDEMIP_IP4_ROUTE_IO(w)->add_args.tos = tos;
    IDEMIP_IP4_ROUTE_IO(w)->add_args.metric = metric;
    Ip4Route.add(w);
    return IDEMIP_IP4_ROUTE_IO(w)->index;
}

static uint8_t add_net(uint8_t *w, uint32_t dst, uint32_t mask)
{
    return add_row(w, dst, mask, 0u, 0u, 0u, 0u, 0u);
}

static void look(uint8_t *w, uint32_t dst, uint8_t tos)
{
    IDEMIP_IP4_ROUTE_IO(w)->lookup_args.dst = dst;
    IDEMIP_IP4_ROUTE_IO(w)->lookup_args.tos = tos;
    Ip4Route.lookup(w);
}

static void drop(uint8_t *w, uint32_t dst, uint32_t mask)
{
    IDEMIP_IP4_ROUTE_IO(w)->remove_args.dst = dst;
    IDEMIP_IP4_ROUTE_IO(w)->remove_args.mask = mask;
    Ip4Route.remove(w);
}

static void redirect(uint8_t *w, uint32_t dst, uint32_t gw)
{
    IDEMIP_IP4_ROUTE_IO(w)->redirect_args.dst = dst;
    IDEMIP_IP4_ROUTE_IO(w)->redirect_args.gw = gw;
    Ip4Route.redirect(w);
}

static void set_pmtu(uint8_t *w, uint32_t dst, uint16_t mtu, uint32_t now_ms)
{
    IDEMIP_IP4_ROUTE_IO(w)->pmtu_args.dst = dst;
    IDEMIP_IP4_ROUTE_IO(w)->pmtu_args.mtu = mtu;
    IDEMIP_IP4_ROUTE_IO(w)->now_ms = now_ms;
    Ip4Route.set_pmtu(w);
}

static void tick(uint8_t *w, uint32_t now_ms)
{
    IDEMIP_IP4_ROUTE_IO(w)->now_ms = now_ms;
    Ip4Route.tick(w);
}

// A directly connected LAN, and a default gateway on it. Two rows, so two are left.
static void lan_and_default(uint8_t *w)
{
    Ip4Route.clear(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(w)->status);
    add_net(w, LAN_192_168_1_24, M24);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(w)->status);
    add_row(w, 0u, 0u, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(w)->status);
}

// The RFC 1812 vectors need four rows, so a table narrower than that would test something else.
void test_the_table_holds_the_rows_the_rfc_1812_vectors_need(void)
{
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP4_ROUTES >= 4u, "the RFC 1812 sec 5.2.4.3 vectors need four rows");
}

// --- add ---------------------------------------------------------------------

void test_add_writes_a_row_and_reports_it(void)
{
    Ip4Route.clear(work_a);
    TEST_ASSERT_EQUAL_UINT8(0u, add_net(work_a, NET_10_144_16, M16));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// RFC 1122 sec 3.3.1.1 (a): the mask "selects the network number and subnet number fields", and RFC
// 1812 sec 5.2.4.3 reads it as "the most significant route.length bits", so a mask with a gap names no
// prefix at all. Retrying the same operands can never write it, so it is ERR.
void test_add_refuses_a_mask_with_a_gap(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, NET_10_144_16, 0xFF00FF00u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);

    add_net(work_a, NET_10_144_16, 0x7FFFFFFFu); // the run does not start at bit 31
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    add_net(work_a, NET_10_144_16, 0x00FFFFFFu);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// Every prefix length from the default route to a host route is a legal mask.
void test_add_accepts_every_prefix_length(void)
{
    for (unsigned int len = 0; len <= 32; len++)
    {
        uint32_t mask = (len == 0) ? 0u : (uint32_t)(0xFFFFFFFFu << (32u - len));
        Ip4Route.clear(work_a);
        add_net(work_a, NET_10_144_16, mask);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status, "a contiguous mask was refused");
    }
}

// RFC 1122 sec 3.3.1.3 field (4) is the next-hop gateway address, so a row that says it routes
// through a gateway has to name one. ERR, not BUSY: the same operands never become writable.
void test_add_refuses_a_gateway_route_with_no_gateway(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, 0u, 0u, 0u, IDEMIP_IP4_ROUTE_F_GATEWAY, 0u, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// Only the bits the mask selects are significant (RFC 1812 sec 5.2.4.3 rule 1), so the row keeps the
// prefix and any host bits handed in are dropped.
void test_add_masks_the_destination_down_to_the_prefix(void)
{
    Ip4Route.clear(work_a);
    TEST_ASSERT_EQUAL_UINT8(0u, add_net(work_a, IP_10_144_2_5, M16));
    look(work_a, 0x0A90FFFEu, 0u); // another address inside 10.144.0.0/16
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP4_ROUTE_IO(work_a)->index);
}

// One row per destination, mask, type of service and gateway, so the same key rewrites rather than
// fills a second row.
void test_add_rewrites_the_row_with_the_same_key(void)
{
    Ip4Route.clear(work_a);
    TEST_ASSERT_EQUAL_UINT8(0u, add_row(work_a, NET_10_8, M8, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u));
    TEST_ASSERT_EQUAL_UINT8(0u, add_row(work_a, NET_10_8, M8, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 2u, 0u, 7u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    look(work_a, 0x0A010203u, 0u);
    TEST_ASSERT_EQUAL_HEX32(GW_10_0_0_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);

    // A second gateway to the same prefix is a second row, not a rewrite.
    TEST_ASSERT_EQUAL_UINT8(1u, add_row(work_a, NET_10_8, M8, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 3u, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// RFC 1122 sec 3.3.1.3 field (3) is part of the key, so two rows to one prefix with different types
// of service are two rows.
void test_add_keeps_rows_that_differ_only_in_the_type_of_service(void)
{
    Ip4Route.clear(work_a);
    TEST_ASSERT_EQUAL_UINT8(0u, add_row(work_a, NET_10_8, M8, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u));
    TEST_ASSERT_EQUAL_UINT8(1u, add_row(work_a, NET_10_8, M8, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 2u, 0x10u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// The flag records what the mask already says: field (2) is the full destination address exactly when
// every bit of it is significant.
void test_the_host_flag_follows_the_mask(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, LAN_192_168_1_24, M24);
    // A host row asked for without the flag still answers as a host row.
    add_net(work_a, IP_10_144_2_5, M32);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    set_pmtu(work_a, IP_10_144_2_5, MTU_1492, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IDEMIP_IP4_ROUTE_IO(work_a)->index,
                                    "the /32 row was not recognized as the per-host route");
}

// A full table is BUSY, not ERR: RFC 1122 sec 3.3.1.2's cache is finite, and a remove frees a row,
// so the same add succeeds later. Reported ERR the caller would abandon a healthy table.
void test_a_full_table_is_busy_and_a_remove_frees_a_row(void)
{
    Ip4Route.clear(work_a);
    for (unsigned int i = 0; i < IDEMIP_IP4_ROUTES; i++)
    {
        add_net(work_a, NET_10_8 | (uint32_t)((i + 1u) << 16), M16);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    }
    add_net(work_a, NET_128_12_16, M16);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);

    drop(work_a, NET_10_8 | (1u << 16), M16);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    add_net(work_a, NET_128_12_16, M16);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// --- remove ------------------------------------------------------------------

void test_remove_drops_the_row_and_the_route_with_it(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, NET_10_144_16, M16);
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);

    drop(work_a, NET_10_144_16, M16);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// A destination and mask no row holds is ERR: nothing frees to make that row appear, so a retry is a
// spin.
void test_remove_of_a_row_no_table_holds_is_refused(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, NET_10_144_16, M16);
    drop(work_a, NET_128_12_16, M16);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);
}

// RemoveArgs names no type of service, so every row on that destination and mask goes.
void test_remove_drops_every_type_of_service_on_the_destination(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, NET_10_8, M8, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    add_row(work_a, NET_10_8, M8, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 2u, 0x10u, 0u);
    drop(work_a, NET_10_8, M8);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP4_ROUTE_IO(work_a)->index);

    look(work_a, 0x0A010203u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    look(work_a, 0x0A010203u, 0x10u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// RFC 1191 sec 6.3: "PMTU estimates may disappear from the routing table if the per-host routes are
// removed", so a rewritten row starts with no estimate.
void test_remove_takes_the_cached_pmtu_with_the_row(void)
{
    lan_and_default(work_a);
    set_pmtu(work_a, IP_10_144_2_5, MTU_576, 1000u);
    TEST_ASSERT_EQUAL_UINT16(MTU_576, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);

    drop(work_a, IP_10_144_2_5, M32);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    add_net(work_a, IP_10_144_2_5, M32);
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
}

// --- lookup, the RFC 1812 sec 5.2.4.3 vectors --------------------------------

// Rule 1 as printed: "if a packet's IP Destination Address is 10.144.2.5, this step would discard a
// route to net 128.12.0.0/16 but would retain any routes to the network prefixes 10.0.0.0/8 and
// 10.144.0.0/16, and any default routes."
void test_basic_match_discards_a_route_to_another_network(void)
{
    Ip4Route.clear(work_a);
    uint8_t other = add_row(work_a, NET_128_12_16, M16, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    uint8_t eight = add_row(work_a, NET_10_8, M8, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 2u, 0u, 0u);
    uint8_t sixteen = add_row(work_a, NET_10_144_16, M16, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 3u, 0u, 0u);
    uint8_t def = add_row(work_a, 0u, 0u, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 4u, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);

    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    // 128.12.0.0/16 is discarded; of what is retained 10.144.0.0/16 is the longest.
    TEST_ASSERT_NOT_EQUAL_UINT8(other, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_NOT_EQUAL_UINT8(eight, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_NOT_EQUAL_UINT8(def, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT8(sixteen, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);
}

// Rule 1 as printed: "if a packet's IP Destination Address is 10.144.2.5 and there are network
// prefixes 10.144.1.0/24, 10.144.2.0/24, and 10.144.3.0/24, this rule would keep only 10.144.2.0/24".
void test_basic_match_keeps_only_the_prefix_whose_bits_match(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, NET_10_144_1_24, M24);
    uint8_t two = add_net(work_a, NET_10_144_2_24, M24);
    add_net(work_a, NET_10_144_3_24, M24);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);

    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(two, IDEMIP_IP4_ROUTE_IO(work_a)->index);
}

// Rule 2 as printed: "if a packet's IP Destination Address is 10.144.2.5 and there are network
// prefixes 10.144.2.0/24, 10.144.0.0/16, and 10.0.0.0/8, then this rule would keep only the first
// (10.144.2.0/24) because its prefix length is longest."
void test_longest_match_keeps_the_longest_prefix(void)
{
    Ip4Route.clear(work_a);
    uint8_t twentyfour = add_row(work_a, NET_10_144_2_24, M24, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 24u, 0u, 0u);
    add_row(work_a, NET_10_144_16, M16, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 16u, 0u, 0u);
    add_row(work_a, NET_10_8, M8, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 8u, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);

    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(twentyfour, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT8(24u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);
}

// The order the rows were written in does not decide the answer: the same three prefixes, reversed,
// route the same way.
void test_longest_match_does_not_depend_on_the_row_order(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, NET_10_8, M8, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 8u, 0u, 0u);
    add_row(work_a, NET_10_144_16, M16, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 16u, 0u, 0u);
    add_row(work_a, NET_10_144_2_24, M24, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 24u, 0u, 0u);

    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(24u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);
}

// RFC 1812 sec 5.2.4.3: the default route "is by definition the route whose prefix length is zero",
// and RFC 1122 sec 3.3.1.2 (a) sends to it when nothing else holds the destination.
void test_the_default_route_carries_what_no_prefix_matches(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, NET_10_144_16, M16);
    uint8_t def = add_row(work_a, 0u, 0u, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 7u, 0u, 0u);

    look(work_a, NET_128_12_16 | 9u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(def, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_EQUAL_HEX32(GW_10_0_0_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ROUTE_IO(work_a)->direct);
}

// RFC 1122 sec 3.3.1.2: "The IP layer MUST support multiple default gateways." Two defaults differ in
// field (4) alone, so field (4) is part of the row key or the second overwrites the first. sec 3.3.1.6
// (3) makes the metric the "preference level", and sec 3.3.1.5 selects a different default when the
// preferred one fails.
void test_multiple_default_gateways_are_separate_rows(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, 0u, 0u, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    add_row(work_a, 0u, 0u, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 2u, 0u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IDEMIP_IP4_ROUTE_IO(work_a)->index,
                                    "the second default gateway overwrote the first");

    // The preferred default carries it while it is preferred.
    look(work_a, NET_128_12_16 | 9u, 0u);
    TEST_ASSERT_EQUAL_HEX32(GW_10_0_0_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);

    // Both defaults share a destination and mask, so a keyed remove takes both. Rewriting the failed
    // one with a worse preference is how sec 3.3.1.5 hands the route to the other.
    add_row(work_a, 0u, 0u, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 5u);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    look(work_a, NET_128_12_16 | 9u, 0u);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);

    // A remove keyed on the default prefix takes every default with it.
    drop(work_a, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    look(work_a, NET_128_12_16 | 9u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// RFC 1122 sec 3.3.1.1 (b): the destination bits match the connected network, so "the datagram is to
// be transmitted directly to the destination host".
void test_a_connected_route_sends_directly_to_the_destination(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, LAN_192_168_1_24, M24, 0u, 0u, 5u, 0u, 0u);
    look(work_a, GW_192_168_1_9, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ROUTE_IO(work_a)->direct);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_9, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);
}

// RFC 1122 sec 3.3.1.1 (c): "the destination is accessible only through a gateway", so the next hop is
// field (4) and not the destination.
void test_a_gateway_route_sends_to_the_gateway(void)
{
    lan_and_default(work_a);
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ROUTE_IO(work_a)->direct);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);
}

// RFC 1812 sec 5.2.4.3 rule 3: "if it contains any routes for which route.tos = ip.tos ... all routes
// except those for which route.tos = ip.tos are discarded".
void test_weak_tos_prefers_the_type_of_service_the_packet_asked_for(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, NET_10_144_16, M16, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    add_row(work_a, NET_10_144_16, M16, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 2u, 0x10u, 0u);

    look(work_a, IP_10_144_2_5, 0x10u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);
}

// Rule 3 continued: "If not, all routes except those for which route.tos = 0000 are discarded."
void test_weak_tos_falls_back_to_the_default_type_of_service(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, NET_10_144_16, M16, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    add_row(work_a, NET_10_144_16, M16, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 2u, 0x10u, 0u);

    look(work_a, IP_10_144_2_5, 0x08u); // no row carries this one
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(GW_10_0_0_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);
}

// Rule 3's DISCUSSION: "Routes with a non-default TOS that is not the TOS requested in the packet are
// never used, even if such routes are the only available routes that go to the packet's destination."
// The rules are applied in the printed order, so rule 2 fixes the prefix length first and rule 3 then
// empties the set: the /16 with the default TOS is already gone, and the destination is unreachable.
void test_weak_tos_never_falls_back_to_another_type_of_service(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, NET_10_144_2_24, M24, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 2u, 0x10u, 0u);
    add_row(work_a, NET_10_144_16, M16, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);

    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);

    // The same table routes the type of service the /24 carries.
    look(work_a, IP_10_144_2_5, 0x10u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
}

// RFC 1812 sec 4.3.3.1 wants two different ICMP codes here: Code 0 when the router "has no routes at
// all (including no default route) to the destination specified in the packet", and Code 11 when "the
// router does have routes to the destination network specified in the packet but the TOS specified
// for the routes is neither the default TOS (0000) nor the TOS of the packet". Both are BUSY, so the
// lookup has to say which.
void test_a_lookup_blocked_only_by_the_type_of_service_says_so(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, NET_10_144_2_24, M24, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 2u, 0x10u, 0u);

    look(work_a, IP_10_144_2_5, 0x08u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP4_ROUTE_IO(work_a)->tos_blocked,
                             "a row matched the destination, so only the TOS blocked it");
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP4_ROUTE_IO(work_a)->direct,
                              "the matching row goes through a gateway, so sec 4.3.3.1 wants Code 11");

    // A destination no row holds at all is the Code 0 case.
    look(work_a, GW_192_168_1_1, 0x08u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ROUTE_IO(work_a)->tos_blocked);

    // A directly connected row that matched is sec 4.3.3.1's Code 12 case, "a host that is on a
    // network that is directly connected to the router".
    Ip4Route.clear(work_a);
    add_row(work_a, NET_10_144_2_24, M24, 0u, 0u, 2u, 0x10u, 0u);
    look(work_a, IP_10_144_2_5, 0x08u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ROUTE_IO(work_a)->tos_blocked);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ROUTE_IO(work_a)->direct);

    // And a row carrying the default TOS is what rule 3 falls back to, so nothing is blocked.
    add_row(work_a, NET_10_144_2_24, M24, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    look(work_a, IP_10_144_2_5, 0x08u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ROUTE_IO(work_a)->tos_blocked);
}

// RFC 1812 sec 5.2.4.3 rule 4: "if route.metric is strictly inferior for one when compared with the
// other, then the one with the inferior metric is discarded".
void test_best_metric_discards_the_inferior_metric(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, NET_10_144_16, M16, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 9u);
    // Same prefix and type of service, so only the metric separates them: rewriting the key would
    // replace the row, and a second row needs a distinct type of service to exist at all.
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);

    Ip4Route.clear(work_a);
    add_row(work_a, 0u, 0u, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 9u);
    add_row(work_a, 0u, 0u, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 2u, 0u, 0u);
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
}

// RFC 1812 sec 5.2.4.3: "If the set ever becomes empty, the packet is discarded because the
// destination is unreachable." BUSY, not ERR: RFC 1122 sec 3.3.1.2 builds the cache as datagrams
// flow, so an add or a Redirect makes the same lookup succeed. Reported ERR a caller would stop
// asking for a destination a route is about to appear for.
void test_a_table_with_no_route_to_the_destination_is_busy(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, NET_10_144_16, M16);
    look(work_a, NET_128_12_16 | 9u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);

    // The retry succeeds, which is what separates BUSY from ERR.
    add_row(work_a, 0u, 0u, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    look(work_a, NET_128_12_16 | 9u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// RFC 1122 sec 3.3.1.3: a row is "a natural place to cache data on the properties of the path.
// Examples of such properties might be the maximum unfragmented datagram size".
void test_lookup_reports_the_cached_pmtu(void)
{
    lan_and_default(work_a);
    set_pmtu(work_a, IP_10_144_2_5, MTU_576, 1000u);
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(MTU_576, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
}

// The same call on the same bytes reports the same thing, whatever ran on the other borrow between
// the two. This is the determinism the design is named for.
void test_a_lookup_is_a_function_of_its_borrow_alone(void)
{
    lan_and_default(work_a);
    Ip4Route.clear(work_b);
    add_row(work_b, 0u, 0u, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 9u, 0u, 0u);

    look(work_a, IP_10_144_2_5, 0u);
    uint32_t first = IDEMIP_IP4_ROUTE_IO(work_a)->next_hop;
    look(work_b, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_HEX32(GW_10_0_0_1, IDEMIP_IP4_ROUTE_IO(work_b)->next_hop);
    look(work_a, IP_10_144_2_5, 0u);
    uint32_t second = IDEMIP_IP4_ROUTE_IO(work_a)->next_hop;

    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, first);
    TEST_ASSERT_EQUAL_HEX32(first, second);
}

// --- redirect ----------------------------------------------------------------

// RFC 1122 sec 3.3.1.2: "a Network Redirect message SHOULD be treated identically to a Host Redirect
// message; i.e., the cache entry for the destination host (only) would be updated (or created, if an
// entry for that host did not exist) for the new gateway."
void test_a_redirect_creates_the_host_row(void)
{
    lan_and_default(work_a);
    redirect(work_a, IP_10_144_2_5, GW_192_168_1_9);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    // The created row inherits field (1) from the row that routed the destination.
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);

    // "later datagrams to the same destination will go directly to the best gateway"
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_9, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ROUTE_IO(work_a)->direct);

    // Only the host is redirected: another address on the same /16 still takes the default.
    look(work_a, 0x0A90FFFEu, 0u);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
}

// The second Redirect updates the row the first created rather than filling another.
void test_a_second_redirect_updates_the_same_host_row(void)
{
    lan_and_default(work_a);
    redirect(work_a, IP_10_144_2_5, GW_192_168_1_9);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    redirect(work_a, IP_10_144_2_5, GW_192_168_1_1);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP4_ROUTE_IO(work_a)->index);

    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
}

// RFC 1122 sec 3.2.2.2: "A Redirect message SHOULD be silently discarded if the new gateway address it
// specifies is not on the same connected (sub-)net through which the Redirect arrived". A gateway no
// connected row reaches is ERR: the same Redirect can never be applied.
void test_a_redirect_to_a_gateway_off_every_connected_net_is_refused(void)
{
    lan_and_default(work_a);
    redirect(work_a, IP_10_144_2_5, OFFNET_GW_172_16_0_1);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);

    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
}

// RFC 1122 sec 3.3.1.3 field (4) is a gateway address, and zero is not one.
void test_a_redirect_naming_no_gateway_is_refused(void)
{
    lan_and_default(work_a);
    redirect(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// RFC 1122 sec 3.3.1.2: "Each such static route MAY include a flag specifying whether it may be
// overridden by ICMP Redirects." Without the flag the row stands, and ERR says so.
void test_a_redirect_leaves_a_static_row_it_may_not_override(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, LAN_192_168_1_24, M24);
    add_row(work_a, IP_10_144_2_5, M32, GW_192_168_1_1,
            IDEMIP_IP4_ROUTE_F_GATEWAY | IDEMIP_IP4_ROUTE_F_STATIC, 1u, 0u, 0u);

    redirect(work_a, IP_10_144_2_5, GW_192_168_1_9);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
}

void test_a_redirect_overrides_a_static_row_flagged_overridable(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, LAN_192_168_1_24, M24);
    add_row(work_a, IP_10_144_2_5, M32, GW_192_168_1_1,
            IDEMIP_IP4_ROUTE_F_GATEWAY | IDEMIP_IP4_ROUTE_F_STATIC | IDEMIP_IP4_ROUTE_F_REDIRECT_OK, 1u, 0u, 0u);

    redirect(work_a, IP_10_144_2_5, GW_192_168_1_9);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_9, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
}

// A Redirect names a better gateway for a destination the table already routes, so with nothing
// routing it the Redirect has no row to build from. BUSY: an added route supplies one.
void test_a_redirect_for_a_destination_nothing_routes_is_busy(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, LAN_192_168_1_24, M24);
    redirect(work_a, IP_10_144_2_5, GW_192_168_1_9);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);

    add_row(work_a, 0u, 0u, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    redirect(work_a, IP_10_144_2_5, GW_192_168_1_9);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// RFC 1191 sec 6.3: "notify the packetization layer of a possible PMTU change whenever a Redirect
// message causes a route change". The path changed, so the estimate on it goes.
void test_a_redirect_drops_the_cached_pmtu(void)
{
    lan_and_default(work_a);
    set_pmtu(work_a, IP_10_144_2_5, MTU_576, 1000u);
    TEST_ASSERT_EQUAL_UINT16(MTU_576, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);

    redirect(work_a, IP_10_144_2_5, GW_192_168_1_9);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
}

// A full table cannot hold the row a Redirect creates. BUSY: a remove frees one.
void test_a_redirect_with_no_free_row_is_busy(void)
{
    Ip4Route.clear(work_a);
    add_net(work_a, LAN_192_168_1_24, M24);
    add_row(work_a, 0u, 0u, GW_192_168_1_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    for (unsigned int i = 2; i < IDEMIP_IP4_ROUTES; i++)
    {
        add_net(work_a, NET_10_8 | (uint32_t)(i << 16), M16);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    }
    redirect(work_a, IP_10_144_2_5, GW_192_168_1_9);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);

    drop(work_a, NET_10_8 | (2u << 16), M16);
    redirect(work_a, IP_10_144_2_5, GW_192_168_1_9);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// --- set_pmtu ----------------------------------------------------------------

// RFC 1191 sec 6.2: "If a per-host route for this path does not exist, then one is created (almost as
// if a per-host ICMP Redirect is being processed; the new route uses the same first-hop router as the
// current route)."
void test_set_pmtu_creates_the_per_host_route_from_the_current_route(void)
{
    lan_and_default(work_a);
    set_pmtu(work_a, IP_10_144_2_5, MTU_1492, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(MTU_1492, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP4_ROUTE_IO(work_a)->netif);

    // The first hop is the one the current route named.
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
    TEST_ASSERT_EQUAL_UINT16(MTU_1492, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
}

// RFC 1191 sec 6.2: "If the PMTU estimate associated with the per-host route is higher than the new
// estimate, then the value in the routing entry is changed." A higher estimate is not an estimate a
// Datagram Too Big produced, and sec 6.3 gives the increase to the aging sweep alone.
void test_set_pmtu_lowers_the_estimate_and_never_raises_it(void)
{
    lan_and_default(work_a);
    set_pmtu(work_a, IP_10_144_2_5, MTU_1492, 1000u);
    TEST_ASSERT_EQUAL_UINT16(MTU_1492, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);

    set_pmtu(work_a, IP_10_144_2_5, MTU_576, 2000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(MTU_576, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);

    set_pmtu(work_a, IP_10_144_2_5, MTU_1492, 3000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(MTU_576, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);

    set_pmtu(work_a, IP_10_144_2_5, MTU_296, 4000u);
    TEST_ASSERT_EQUAL_UINT16(MTU_296, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
}

// RFC 1191 sec 4 on the Next-Hop MTU field: "This field will never contain a value less than 68, since
// every router must be able to forward a datagram of 68 octets without fragmentation". ERR: no retry
// makes 67 a legal path MTU.
void test_set_pmtu_refuses_an_estimate_below_the_official_minimum(void)
{
    lan_and_default(work_a);
    set_pmtu(work_a, IP_10_144_2_5, (uint16_t)(MTU_MIN - 1u), 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);

    set_pmtu(work_a, IP_10_144_2_5, MTU_MIN, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(MTU_MIN, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
}

// RFC 1191 sec 6.2: the estimates on per-network and default rows "must never be changed by the PMTU
// Discovery process. (PMTU Discovery only creates or changes entries for per-host routes)."
void test_set_pmtu_leaves_the_per_network_row_alone(void)
{
    Ip4Route.clear(work_a);
    add_row(work_a, NET_10_144_16, M16, 0u, 0u, 3u, 0u, 0u);
    set_pmtu(work_a, IP_10_144_2_5, MTU_576, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP4_ROUTE_IO(work_a)->index);

    // Another host on the same network is still routed by the untouched per-network row.
    look(work_a, 0x0A90FFFEu, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP4_ROUTE_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
}

// Nothing routes the destination, so there is no first hop to copy. BUSY: an added route supplies one.
void test_set_pmtu_with_no_route_to_the_destination_is_busy(void)
{
    Ip4Route.clear(work_a);
    set_pmtu(work_a, IP_10_144_2_5, MTU_576, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);

    add_row(work_a, 0u, 0u, GW_10_0_0_1, IDEMIP_IP4_ROUTE_F_GATEWAY, 1u, 0u, 0u);
    set_pmtu(work_a, IP_10_144_2_5, MTU_576, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(MTU_576, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
}

// --- tick --------------------------------------------------------------------

// RFC 1191 sec 6.3: "Once a minute, a timer-driven procedure runs through the routing table". A tick
// before the period is BUSY, and the tick past it runs the sweep.
void test_a_sweep_that_is_not_due_is_busy(void)
{
    Ip4Route.clear(work_a);
    tick(work_a, SWEEP_MS - 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    tick(work_a, SWEEP_MS);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    // The sweep just ran, so the next one is a period away.
    tick(work_a, SWEEP_MS);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    tick(work_a, SWEEP_MS + SWEEP_MS);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
}

// RFC 1191 sec 6.3: "for each entry whose timestamp is not 'reserved' and is older than the timeout
// interval: the PMTU estimate is set to the MTU of the associated first hop." A row carrying no
// estimate reports the first-hop MTU to its caller, so clearing the estimate is that assignment.
void test_the_sweep_clears_an_estimate_older_than_the_timeout(void)
{
    lan_and_default(work_a);
    set_pmtu(work_a, IP_10_144_2_5, MTU_576, 1000u);
    TEST_ASSERT_EQUAL_UINT16(MTU_576, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);

    tick(work_a, 1000u + AGE_MS);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP4_ROUTE_IO(work_a)->index);

    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
    // The row itself stays: only the estimate ages out.
    TEST_ASSERT_EQUAL_HEX32(GW_192_168_1_1, IDEMIP_IP4_ROUTE_IO(work_a)->next_hop);
}

// A millisecond short of the interval is not "older than the timeout interval".
void test_the_sweep_keeps_an_estimate_inside_the_timeout(void)
{
    lan_and_default(work_a);
    set_pmtu(work_a, IP_10_144_2_5, MTU_576, 1000u);

    tick(work_a, 1000u + AGE_MS - 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);

    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_UINT16(MTU_576, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu);
}

// RFC 1191 sec 6.3: the timestamp "is initialized to a 'reserved' value, indicating that the PMTU has
// never been changed", and the sweep passes such a row by. A zero estimate is that reserved value.
void test_the_sweep_passes_a_row_that_never_carried_an_estimate(void)
{
    lan_and_default(work_a);
    tick(work_a, AGE_MS + AGE_MS);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_ROUTE_INDEX_NONE, IDEMIP_IP4_ROUTE_IO(work_a)->index);

    look(work_a, GW_192_168_1_9, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ROUTE_IO(work_a)->direct);
}

// The stamp the sweep compares is the one set_pmtu wrote, so a decrease inside the interval restarts
// it: RFC 1191 sec 6.3 ages a value that "has not been decreased for a while".
void test_a_decrease_restarts_the_age_of_the_estimate(void)
{
    lan_and_default(work_a);
    set_pmtu(work_a, IP_10_144_2_5, MTU_1492, 1000u);
    set_pmtu(work_a, IP_10_144_2_5, MTU_576, 1000u + AGE_MS - 1u);

    tick(work_a, 1000u + AGE_MS);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(MTU_576, IDEMIP_IP4_ROUTE_IO(work_a)->pmtu,
                                     "the decrease did not restamp the estimate");
}

// --- two tables --------------------------------------------------------------

// The borrow IS the table, so a route in one is invisible in the other.
void test_two_tables_route_independently(void)
{
    lan_and_default(work_a);
    Ip4Route.clear(work_b);
    add_row(work_b, NET_10_144_16, M16, 0u, 0u, 4u, 0u, 0u);

    look(work_a, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ROUTE_IO(work_a)->direct);

    look(work_b, IP_10_144_2_5, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ROUTE_IO(work_b)->status);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ROUTE_IO(work_b)->direct);
    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_IP4_ROUTE_IO(work_b)->netif);

    // b holds no LAN row, so a's gateway is off every connected net of b.
    look(work_b, GW_192_168_1_9, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ROUTE_IO(work_b)->status);
}
