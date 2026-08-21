// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ip6_select against RFC 6724 sec 2 through sec 6.
//
// The vectors are the RFC's own: sec 2.1's default policy table, sec 2.2's worked CommonPrefixLen,
// and every case sec 10.1 and sec 10.2 print. sec 10 opens "These examples are provided for
// illustrative purposes; they are not to be construed as normative", so each case below also names
// the rule of sec 5 or sec 6 the example turns on, and asserts that that rule is the one that
// decided.
//
// Two of sec 10.1's printed results carry typos, noted at their cases: the first names a result
// address that is not among its own candidates, and the fifth writes an address with three colons.
//
// Same six checks every unit's suite carries:
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. the vectors are the RFC's own
//   6. BUSY and ERR are separated by whether retrying can ever succeed
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ip/ip6_select.h"

#include <string.h>
#include <unity.h>

// A pool of addresses, so each vector reads as the RFC prints it and nothing is reused by accident.
#define POOL 16
static uint8_t pool[POOL][IDEMIP_IP6_ADDR_LEN];
static int pool_n;

// Eight 16-bit pieces, the "preferred form" of RFC 4291 sec 2.2. One block in, not eight arguments,
// so every A(...) below is one pointer at the call.
typedef struct
{
    uint16_t g0;
    uint16_t g1;
    uint16_t g2;
    uint16_t g3;
    uint16_t g4;
    uint16_t g5;
    uint16_t g6;
    uint16_t g7;
} A6Groups;

static uint8_t *a6_ctx(const A6Groups *a)
{
    TEST_ASSERT_LESS_THAN_INT(POOL, pool_n);
    uint8_t *out = pool[pool_n++];
    const uint16_t g[8] = {a->g0, a->g1, a->g2, a->g3, a->g4, a->g5, a->g6, a->g7};
    for (int i = 0; i < 8; i++)
    {
        out[i * 2] = (uint8_t)(g[i] >> 8);
        out[i * 2 + 1] = (uint8_t)(g[i] & 0xFFu);
    }
    return out;
}

#define A(...) IDEMIP_CALL(a6_ctx, A6Groups, __VA_ARGS__)

// RFC 6724 sec 3.2: "IPv4 addresses MUST be represented as IPv4-mapped addresses", which is
// RFC 4291 sec 2.5.5.2's ::FFFF:a.b.c.d.
static uint8_t *V4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return A(0, 0, 0, 0, 0, 0xFFFFu, (uint16_t)(((uint16_t)a << 8) | b), (uint16_t)(((uint16_t)c << 8) | d));
}

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_IP6_SELECT_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_IP6_SELECT_BORROW + 16];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP6_SELECT_BORROW, CANARY, cap - IDEMIP_IP6_SELECT_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP6_SELECT_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP6_SELECT_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    pool_n = 0;
    memset(pool, 0, sizeof pool);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- adding, in the shape the operand block takes ----------------------------

typedef struct
{
    uint8_t *w;
    const uint8_t *addr;
    uint8_t netif;
    int deprecated;
    int temporary;
    int home;
    int care_of;
    int next_hop;
} SrcAddArgs;

static void src_add_ctx(const SrcAddArgs *a)
{
    Ip6SelectSourceArgs *s = &IDEMIP_IP6_SELECT_IO(a->w)->source_args;
    s->addr = a->addr;
    s->zone = 0u;
    s->netif = a->netif;
    s->deprecated = (idemip_bool)(a->deprecated ? 1 : 0);
    s->temporary = (idemip_bool)(a->temporary ? 1 : 0);
    s->home = (idemip_bool)(a->home ? 1 : 0);
    s->care_of = (idemip_bool)(a->care_of ? 1 : 0);
    s->next_hop = (idemip_bool)(a->next_hop ? 1 : 0);
    Ip6Select.source_add(a->w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(a->w)->status);
}

#define src_add(...) IDEMIP_CALL(src_add_ctx, SrcAddArgs, __VA_ARGS__)

static void src(uint8_t *w, const uint8_t *addr)
{
    src_add(w, addr, 0u, 0, 0, 0, 0, 0);
}

static void dst_add(uint8_t *w, const uint8_t *addr, uint8_t netif, int unreachable, int encapsulated)
{
    Ip6SelectDestArgs *d = &IDEMIP_IP6_SELECT_IO(w)->dest_args;
    d->addr = addr;
    d->zone = 0u;
    d->netif = netif;
    d->unreachable = (idemip_bool)(unreachable ? 1 : 0);
    d->encapsulated = (idemip_bool)(encapsulated ? 1 : 0);
    Ip6Select.dest_add(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(w)->status);
}

static void dst(uint8_t *w, const uint8_t *addr)
{
    dst_add(w, addr, 0u, 0, 0);
}

// Runs sec 5 for D and asserts the winner, then the rule that put it there.
static void select_is(uint8_t *w, const uint8_t *d, const uint8_t *want, uint8_t rule)
{
    IDEMIP_IP6_SELECT_IO(w)->query_args.addr = d;
    IDEMIP_IP6_SELECT_IO(w)->query_args.zone = 0u;
    IDEMIP_IP6_SELECT_IO(w)->query_args.netif = 0u;
    Ip6Select.source_select(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(w)->status);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP6_SELECT_IO(w)->found, "sec 5 found no source for the destination");
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, IDEMIP_IP6_SELECT_IO(w)->source, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(rule, IDEMIP_IP6_SELECT_IO(w)->rule, "a different rule decided");
}

// Reads the destination sec 6 put at one place, and the source it was paired with.
static void sorted_is(uint8_t *w, uint8_t place, const uint8_t *want_dest, const uint8_t *want_src)
{
    IDEMIP_IP6_SELECT_IO(w)->query_args.index = place;
    Ip6Select.dest_at(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(w)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want_dest, IDEMIP_IP6_SELECT_IO(w)->dest, IDEMIP_IP6_ADDR_LEN);
    if (want_src != NULL)
    {
        TEST_ASSERT_TRUE(IDEMIP_IP6_SELECT_IO(w)->found);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(want_src, IDEMIP_IP6_SELECT_IO(w)->source, IDEMIP_IP6_ADDR_LEN);
    }
}

static void lookup(uint8_t *w, const uint8_t *addr)
{
    IDEMIP_IP6_SELECT_IO(w)->query_args.addr = addr;
    IDEMIP_IP6_SELECT_IO(w)->query_args.zone = 0u;
    Ip6Select.policy_lookup(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(w)->status);
}

// The same lookup in a named RFC 4007 sec 6 zone rather than the default one.
static void lookup_in(uint8_t *w, const uint8_t *addr, uint32_t zone)
{
    IDEMIP_IP6_SELECT_IO(w)->query_args.addr = addr;
    IDEMIP_IP6_SELECT_IO(w)->query_args.zone = zone;
    Ip6Select.policy_lookup(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(w)->status);
}

// --- the borrow --------------------------------------------------------------

void test_every_entry_survives_a_null_borrow(void)
{
    Ip6Select.clear(NULL);
    Ip6Select.policy_set(NULL);
    Ip6Select.policy_lookup(NULL);
    Ip6Select.scope_of(NULL);
    Ip6Select.common_prefix(NULL);
    Ip6Select.source_add(NULL);
    Ip6Select.dest_add(NULL);
    Ip6Select.source_select(NULL);
    Ip6Select.dest_sort(NULL);
    Ip6Select.dest_at(NULL);
    TEST_PASS();
}

// The borrow IS the instance, so two selections in flight share no byte at all.
void test_two_borrows_share_no_byte(void)
{
    Ip6Select.clear(work_a);
    Ip6Select.clear(work_b);
    const uint8_t *global = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *ll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);

    src(work_a, global);
    src(work_b, ll);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_SELECT_IO(work_a)->sources);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_SELECT_IO(work_b)->sources);

    const uint8_t *d = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.addr = d;
    Ip6Select.source_select(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP6_SELECT_IO(work_a)->found);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(global, IDEMIP_IP6_SELECT_IO(work_a)->source, IDEMIP_IP6_ADDR_LEN);

    IDEMIP_IP6_SELECT_IO(work_b)->query_args.addr = d;
    Ip6Select.source_select(work_b);
    TEST_ASSERT_TRUE(IDEMIP_IP6_SELECT_IO(work_b)->found);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ll, IDEMIP_IP6_SELECT_IO(work_b)->source, IDEMIP_IP6_ADDR_LEN);

    // a's answer is still a's after b's call.
    TEST_ASSERT_EQUAL_UINT8_ARRAY(global, IDEMIP_IP6_SELECT_IO(work_a)->source, IDEMIP_IP6_ADDR_LEN);
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    Ip6Select.clear(work_a);
    Ip6Select.clear(work_b);
    const uint8_t *a1 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *b1 = A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 2u);
    src(work_a, a1);
    src(work_b, b1);

    const uint8_t *d = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.addr = d;
    IDEMIP_IP6_SELECT_IO(work_b)->query_args.addr = d;

    Ip6Select.source_select(work_a);
    uint8_t first[IDEMIP_IP6_ADDR_LEN];
    memcpy(first, IDEMIP_IP6_SELECT_IO(work_a)->source, IDEMIP_IP6_ADDR_LEN);
    Ip6Select.source_select(work_b);
    Ip6Select.source_select(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_IP6_SELECT_IO(work_a)->source, IDEMIP_IP6_ADDR_LEN);
}

// Zeroed, never cleared: every entry must refuse. ERR and not BUSY, because no later tick clears
// the borrow for the caller.
void test_uncleared_borrow_refuses_work(void)
{
    const uint8_t *a1 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    IDEMIP_IP6_SELECT_IO(work_a)->source_args.addr = a1;
    IDEMIP_IP6_SELECT_IO(work_a)->dest_args.addr = a1;
    IDEMIP_IP6_SELECT_IO(work_a)->policy_args.prefix = a1;
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.addr = a1;
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.peer = a1;

    Ip6Select.source_add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
    Ip6Select.dest_add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
    Ip6Select.policy_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
    Ip6Select.policy_lookup(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
    Ip6Select.common_prefix(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
    Ip6Select.source_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
    Ip6Select.dest_sort(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
    Ip6Select.dest_at(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
}

// --- RFC 6724 sec 2.1, the default policy table ------------------------------

// sec 2.1: "If an implementation is not configurable or has not been configured, then it SHOULD
// operate according to the algorithms specified here in conjunction with the following default
// policy table", which prints nine rows.
void test_sec2_1_clear_loads_the_nine_default_rows(void)
{
    Ip6Select.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_SELECT_DEFAULT_POLICIES, IDEMIP_IP6_SELECT_IO(work_a)->policies);
}

// Row by row, as sec 2.1 prints them.
void test_sec2_1_default_precedences_and_labels(void)
{
    Ip6Select.clear(work_a);

    lookup(work_a, A(0, 0, 0, 0, 0, 0, 0, 1u)); // ::1/128 -> 50, 0
    TEST_ASSERT_EQUAL_UINT8(50u, IDEMIP_IP6_SELECT_IO(work_a)->precedence);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_SELECT_IO(work_a)->label);
    TEST_ASSERT_EQUAL_UINT8(128u, IDEMIP_IP6_SELECT_IO(work_a)->prefix_len);

    lookup(work_a, A(0x2001u, 0x0DB8u, 0, 0, 0, 0, 0, 1u)); // ::/0 -> 40, 1
    TEST_ASSERT_EQUAL_UINT8(40u, IDEMIP_IP6_SELECT_IO(work_a)->precedence);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_SELECT_IO(work_a)->label);

    lookup(work_a, V4(198u, 51u, 100u, 121u)); // ::ffff:0:0/96 -> 35, 4
    TEST_ASSERT_EQUAL_UINT8(35u, IDEMIP_IP6_SELECT_IO(work_a)->precedence);
    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_IP6_SELECT_IO(work_a)->label);

    lookup(work_a, A(0x2002u, 0xC633u, 0x6401u, 0, 0, 0, 0, 1u)); // 2002::/16 -> 30, 2
    TEST_ASSERT_EQUAL_UINT8(30u, IDEMIP_IP6_SELECT_IO(work_a)->precedence);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP6_SELECT_IO(work_a)->label);

    lookup(work_a, A(0x2001u, 0, 0, 0, 0, 0, 0, 1u)); // 2001::/32 -> 5, 5
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_IP6_SELECT_IO(work_a)->precedence);
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_IP6_SELECT_IO(work_a)->label);

    lookup(work_a, A(0xFD00u, 0, 0, 0, 0, 0, 0, 1u)); // fc00::/7 -> 3, 13
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_IP6_SELECT_IO(work_a)->precedence);
    TEST_ASSERT_EQUAL_UINT8(13u, IDEMIP_IP6_SELECT_IO(work_a)->label);

    lookup(work_a, A(0xFEC0u, 0, 0, 0, 0, 0, 0, 1u)); // fec0::/10 -> 1, 11
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_SELECT_IO(work_a)->precedence);
    TEST_ASSERT_EQUAL_UINT8(11u, IDEMIP_IP6_SELECT_IO(work_a)->label);

    lookup(work_a, A(0x3FFEu, 0, 0, 0, 0, 0, 0, 1u)); // 3ffe::/16 -> 1, 12
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_SELECT_IO(work_a)->precedence);
    TEST_ASSERT_EQUAL_UINT8(12u, IDEMIP_IP6_SELECT_IO(work_a)->label);
}

// sec 2.1: "The policy table is a longest-matching-prefix lookup table", so 2001::/32 wins over
// ::/0 and ::1/128 wins over ::/96 and ::/0.
void test_sec2_1_lookup_takes_the_longest_matching_prefix(void)
{
    Ip6Select.clear(work_a);
    lookup(work_a, A(0x2001u, 0, 0, 0, 0, 0, 0, 1u));
    TEST_ASSERT_EQUAL_UINT8(32u, IDEMIP_IP6_SELECT_IO(work_a)->prefix_len);

    lookup(work_a, A(0, 0, 0, 0, 0, 0, 0, 1u));
    TEST_ASSERT_EQUAL_UINT8(128u, IDEMIP_IP6_SELECT_IO(work_a)->prefix_len);

    // ::13.1.68.3 is inside ::/96 but not ::1/128.
    lookup(work_a, A(0, 0, 0, 0, 0, 0, 0x0D01u, 0x4403u));
    TEST_ASSERT_EQUAL_UINT8(96u, IDEMIP_IP6_SELECT_IO(work_a)->prefix_len);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_SELECT_IO(work_a)->precedence);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_IP6_SELECT_IO(work_a)->label);
}

// sec 2.1: "Policy table entries for address prefixes that are not of global scope MAY be qualified
// with an optional zone index." A qualified row answers a lookup made in its own zone, and a lookup
// in any other zone passes it over and falls back to whatever unqualified row still matches - here
// the default table's ::/0, which sec 2.1 gives precedence 40.
void test_sec2_1_a_zone_qualified_row_answers_only_its_own_zone(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectPolicyArgs *p = &IDEMIP_IP6_SELECT_IO(work_a)->policy_args;
    p->prefix = A(0xFE80u, 0, 0, 0, 0, 0, 0, 0);
    p->zone = 2u;
    p->prefix_len = 10u;
    p->precedence = 55u;
    p->label = 9u;
    Ip6Select.policy_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);

    const uint8_t *ll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);

    // In its own zone the qualified row wins, and it wins on length: ::/0 matches this address too,
    // and sec 2.1 makes the policy table "a longest-matching-prefix lookup table, much like a routing
    // table".
    lookup_in(work_a, ll, 2u);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(55u, IDEMIP_IP6_SELECT_IO(work_a)->precedence,
                                    "a row qualified with the queried zone did not answer it");
    TEST_ASSERT_EQUAL_UINT8(9u, IDEMIP_IP6_SELECT_IO(work_a)->label);

    // In another zone it is not a candidate at all, so the longest remaining match answers.
    lookup_in(work_a, ll, 3u);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(40u, IDEMIP_IP6_SELECT_IO(work_a)->precedence,
                                    "a row qualified with another zone answered this one");
}

// sec 2.1 makes the table configurable, "It is important that implementations provide a way to
// change the default policies". A row already in the table is overwritten rather than shadowed.
void test_sec2_1_a_row_can_be_reconfigured(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectPolicyArgs *p = &IDEMIP_IP6_SELECT_IO(work_a)->policy_args;
    p->prefix = A(0, 0, 0, 0, 0, 0xFFFFu, 0, 0);
    p->zone = 0u;
    p->prefix_len = 96u;
    p->precedence = 100u;
    p->label = 4u;
    Ip6Select.policy_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_SELECT_DEFAULT_POLICIES, IDEMIP_IP6_SELECT_IO(work_a)->policies);

    lookup(work_a, V4(10u, 1u, 2u, 3u));
    TEST_ASSERT_EQUAL_UINT8(100u, IDEMIP_IP6_SELECT_IO(work_a)->precedence);
}

// A table with no free row is ERR and never BUSY: nothing frees a row on a later tick, so a retry
// fails exactly the same way. Only clear empties it.
void test_a_full_policy_table_is_err_not_busy(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectPolicyArgs *p = &IDEMIP_IP6_SELECT_IO(work_a)->policy_args;
    for (uint16_t i = 0; i < IDEMIP_IP6_SELECT_POLICIES; i++)
    {
        p->prefix = A((uint16_t)(0x2100u + i), 0, 0, 0, 0, 0, 0, 0);
        p->zone = 0u;
        p->prefix_len = 16u;
        p->precedence = 7u;
        p->label = 7u;
        Ip6Select.policy_set(work_a);
        if (IDEMIP_IP6_SELECT_IO(work_a)->status != IDEMIP_OK)
        {
            TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
            TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_SELECT_POLICIES, IDEMIP_IP6_SELECT_IO(work_a)->policies);
            TEST_PASS();
        }
        pool_n = 0; // the row was copied into the borrow, so the pool slot is free again
    }
    TEST_FAIL_MESSAGE("the policy table never filled");
}

// --- RFC 6724 sec 2.2, CommonPrefixLen ---------------------------------------

// The section's own worked example: "CommonPrefixLen(fe80::1, fe80::2) is 64". The two share 127
// bits; the answer is 64 because the length is measured "up to the length of S's prefix (i.e., the
// portion of the address not including the interface ID)".
void test_sec2_2_worked_common_prefix_len(void)
{
    Ip6Select.clear(work_a);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.addr = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.peer = A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u);
    Ip6Select.common_prefix(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(64u, IDEMIP_IP6_SELECT_IO(work_a)->common);
}

void test_common_prefix_len_counts_the_leading_bits(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectQueryArgs *q = &IDEMIP_IP6_SELECT_IO(work_a)->query_args;

    // 2001:db8:1::2 against 2001:db8:3::2 differ in bit 46.
    q->addr = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    q->peer = A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 2u);
    Ip6Select.common_prefix(work_a);
    TEST_ASSERT_EQUAL_UINT8(46u, IDEMIP_IP6_SELECT_IO(work_a)->common);

    // Nothing in common at all.
    q->addr = A(0x2001u, 0, 0, 0, 0, 0, 0, 0);
    q->peer = A(0xFE80u, 0, 0, 0, 0, 0, 0, 0);
    Ip6Select.common_prefix(work_a);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_SELECT_IO(work_a)->common);
}

// --- RFC 6724 sec 3, address properties --------------------------------------

// sec 3.2: "IPv4 auto-configuration addresses [RFC3927], which have the prefix 169.254/16, are
// assigned link-local scope. IPv4 loopback addresses ... which have the prefix 127/8, are assigned
// link-local scope ... Other IPv4 addresses ... are assigned global scope."
void test_sec3_2_ipv4_scopes(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectQueryArgs *q = &IDEMIP_IP6_SELECT_IO(work_a)->query_args;

    q->addr = V4(169u, 254u, 13u, 78u);
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_LINK_LOCAL, IDEMIP_IP6_SELECT_IO(work_a)->scope);

    q->addr = V4(127u, 0u, 0u, 1u);
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_LINK_LOCAL, IDEMIP_IP6_SELECT_IO(work_a)->scope);

    // sec 3.2 names RFC 1918 private addresses among the "other" ones that take global scope.
    q->addr = V4(10u, 1u, 2u, 3u);
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_GLOBAL, IDEMIP_IP6_SELECT_IO(work_a)->scope);

    q->addr = V4(198u, 51u, 100u, 121u);
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_GLOBAL, IDEMIP_IP6_SELECT_IO(work_a)->scope);
}

// sec 3.4: "The loopback address MUST be treated as having link-local scope", and sec 3.1 keeps a
// site-local unicast scope for the deprecated prefix.
void test_sec3_1_and_3_4_ipv6_scopes(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectQueryArgs *q = &IDEMIP_IP6_SELECT_IO(work_a)->query_args;

    q->addr = A(0, 0, 0, 0, 0, 0, 0, 1u);
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_LINK_LOCAL, IDEMIP_IP6_SELECT_IO(work_a)->scope);

    q->addr = A(0xFEC0u, 0, 0, 0, 0, 0, 0, 1u);
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_SITE_LOCAL, IDEMIP_IP6_SELECT_IO(work_a)->scope);

    // sec 3.1: "ULAs are considered as global, not site-local, scope but are handled via the prefix
    // policy table". lwIP's ip6.c:268 says it "deliberately deviate[s]" from this.
    q->addr = A(0xFD00u, 0, 0, 0, 0, 0, 0, 1u);
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_GLOBAL, IDEMIP_IP6_SELECT_IO(work_a)->scope);
}

// --- RFC 6724 sec 4, the candidate set ---------------------------------------

// sec 4: "In any case, multicast addresses and the unspecified address MUST NOT be included in a
// candidate set." ERR and not BUSY: no later tick makes either eligible.
void test_sec4_refuses_multicast_and_the_unspecified_address(void)
{
    Ip6Select.clear(work_a);
    IDEMIP_IP6_SELECT_IO(work_a)->source_args.addr = A(0xFF02u, 0, 0, 0, 0, 0, 0, 1u);
    Ip6Select.source_add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);

    IDEMIP_IP6_SELECT_IO(work_a)->source_args.addr = A(0, 0, 0, 0, 0, 0, 0, 0);
    Ip6Select.source_add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_SELECT_IO(work_a)->sources);
}

// sec 4: "For all multicast and link-local destination addresses, the set of candidate source
// addresses MUST only include addresses assigned to interfaces belonging to the same link as the
// outgoing interface." RFC 4007 sec 6's default assignment makes the same link the same interface.
void test_sec4_link_local_destination_keeps_to_the_outgoing_interface(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *near = A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u);
    const uint8_t *far = A(0xFE80u, 0, 0, 0, 0, 0, 0, 3u);
    src_add(work_a, far, 1u, 0, 0, 0, 0, 0);
    src_add(work_a, near, 0u, 0, 0, 0, 0, 0);

    const uint8_t *d = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.addr = d;
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.netif = 0u;
    Ip6Select.source_select(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP6_SELECT_IO(work_a)->found);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(near, IDEMIP_IP6_SELECT_IO(work_a)->source, IDEMIP_IP6_ADDR_LEN);
}

// sec 6: "We say that Source(D) is undefined if there is no source address available for
// destination D." That is an answer, not a fault, so the call reports OK with found clear.
void test_no_candidate_is_ok_with_source_undefined(void)
{
    Ip6Select.clear(work_a);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.addr = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    Ip6Select.source_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_SELECT_IO(work_a)->found);
    TEST_ASSERT_NULL(IDEMIP_IP6_SELECT_IO(work_a)->source);
}

// A full candidate set is ERR and never BUSY, for the same reason the policy table is.
void test_a_full_candidate_set_is_err_not_busy(void)
{
    Ip6Select.clear(work_a);
    for (uint16_t i = 0; i < IDEMIP_IP6_SELECT_SOURCES; i++)
    {
        IDEMIP_IP6_SELECT_IO(work_a)->source_args.addr = A(0x2001u, 0x0DB8u, i, 0, 0, 0, 0, 1u);
        Ip6Select.source_add(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
        pool_n = 0;
    }
    IDEMIP_IP6_SELECT_IO(work_a)->source_args.addr = A(0x2001u, 0x0DB8u, 0xFFFFu, 0, 0, 0, 0, 1u);
    Ip6Select.source_add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
}

// --- RFC 6724 sec 5, the source rules, against sec 10.1 ----------------------

// sec 10.1, third: "Destination: 2001:db8:1::1 / Candidate Source Addresses: 2001:db8:1::1
// (deprecated) or 2001:db8:2::1 / Result: 2001:db8:1::1 (prefer same address)". Rule 1 beats
// Rule 3, which would otherwise drop the deprecated one.
void test_rule1_prefer_same_address(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *same = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    const uint8_t *other = A(0x2001u, 0x0DB8u, 2u, 0, 0, 0, 0, 1u);
    src_add(work_a, same, 0u, 1, 0, 0, 0, 0);
    src(work_a, other);
    select_is(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), same, 1u);
}

// sec 10.1, first: "Destination: 2001:db8:1::1 / Candidate Source Addresses: 2001:db8:3::1 or
// fe80::1 / Result: 2001:db8::1 (prefer appropriate scope)". The printed result is a typo: it names
// an address that is not among the candidates, and the candidate it means is 2001:db8:3::1.
void test_rule2_prefer_appropriate_scope_for_a_global_destination(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *global = A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 1u);
    const uint8_t *ll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    src(work_a, global);
    src(work_a, ll);
    select_is(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), global, 2u);
}

// sec 10.1, second: "Destination: ff05::1 / Candidate Source Addresses: 2001:db8:3::1 or fe80::1 /
// Result: 2001:db8:3::1 (prefer appropriate scope)". Scope(fe80::1) is link-local, below the
// destination's site-local scope, so Rule 2 discards it.
void test_rule2_prefer_appropriate_scope_for_a_multicast_destination(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *global = A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 1u);
    const uint8_t *ll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    src(work_a, global);
    src(work_a, ll);
    select_is(work_a, A(0xFF05u, 0, 0, 0, 0, 0, 0, 1u), global, 2u);
}

// sec 10.1, fourth: "Destination: fe80::1 / Candidate Source Addresses: fe80::2 (deprecated) or
// 2001:db8:1::1 / Result: fe80::2 (prefer appropriate scope)". Rule 2 settles it before Rule 3 can
// look at the deprecated flag.
void test_rule2_beats_rule3_for_a_link_local_destination(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *ll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u);
    const uint8_t *global = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    src_add(work_a, ll, 0u, 1, 0, 0, 0, 0);
    src(work_a, global);
    select_is(work_a, A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u), ll, 2u);
}

// Rule 3: "If one of the two source addresses is 'preferred' and one of them is 'deprecated' (in the
// RFC 4862 sense), then prefer the one that is 'preferred'."
void test_rule3_avoid_deprecated_addresses(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *old = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *fresh = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 3u);
    src_add(work_a, old, 0u, 1, 0, 0, 0, 0);
    src(work_a, fresh);
    select_is(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), fresh, 3u);
}

// sec 10.1, sixth: "Candidate Source Addresses: 2001:db8:1::2 (care-of address) or 2001:db8:3::2
// (home address) / Result: 2001:db8:3::2 (prefer home address)". Rule 4 decides before Rule 8's
// longest matching prefix, which would have chosen the other one.
void test_rule4_prefer_home_addresses(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *care_of = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *home = A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 2u);
    src_add(work_a, care_of, 0u, 0, 0, 0, 1, 0);
    src_add(work_a, home, 0u, 0, 0, 1, 0, 0);
    select_is(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), home, 4u);
}

// Rule 4's first clause: "If SA is simultaneously a home address and care-of address and SB is not,
// then prefer SA", which sec 2 calls the mobile node being "at home" for that address.
void test_rule4_prefers_an_address_that_is_both(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *home_only = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *both = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 3u);
    src_add(work_a, home_only, 0u, 0, 0, 1, 0, 0);
    src_add(work_a, both, 0u, 0, 0, 1, 1, 0);
    select_is(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), both, 4u);
}

// Rule 5: "If SA is assigned to the interface that will be used to send to D and SB is assigned to a
// different interface, then prefer SA."
void test_rule5_prefer_the_outgoing_interface(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *other_if = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *out_if = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 3u);
    src_add(work_a, other_if, 1u, 0, 0, 0, 0, 0);
    src_add(work_a, out_if, 0u, 0, 0, 0, 0, 0);
    select_is(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), out_if, 5u);
}

// Rule 5.5: "If SA or SA's prefix is assigned by the selected next-hop that will be used to send to
// D and SB or SB's prefix is assigned by a different next-hop, then prefer SA."
void test_rule5_5_prefer_a_prefix_from_the_next_hop(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *elsewhere = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *from_hop = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 3u);
    src_add(work_a, elsewhere, 0u, 0, 0, 0, 0, 0);
    src_add(work_a, from_hop, 0u, 0, 0, 0, 0, 1);
    select_is(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), from_hop, IDEMIP_IP6_SELECT_RULE_5_5);
}

// sec 10.1, seventh: "Destination: 2002:c633:6401::1 / Candidate Source Addresses:
// 2002:c633:6401::d5e3:7953:13eb:22e8 (temporary) or 2001:db8:1::2 / Result:
// 2002:c633:6401::d5e3:7953:13eb:22e8 (prefer matching label)". Label(D) is 2 from the 2002::/16
// row, and Rule 6 runs before Rule 7's temporary preference.
void test_rule6_prefer_matching_label(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *sixtofour = A(0x2002u, 0xC633u, 0x6401u, 0, 0xD5E3u, 0x7953u, 0x13EBu, 0x22E8u);
    const uint8_t *native = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    src_add(work_a, sixtofour, 0u, 0, 1, 0, 0, 0);
    src(work_a, native);
    select_is(work_a, A(0x2002u, 0xC633u, 0x6401u, 0, 0, 0, 0, 1u), sixtofour, 6u);
}

// sec 10.1, eighth: "Destination: 2001:db8:1::d5e3:0:0:1 / Candidate Source Addresses:
// 2001:db8:1::2 (public) or 2001:db8:1::d5e3:7953:13eb:22e8 (temporary) / Result:
// 2001:db8:1::d5e3:7953:13eb:22e8 (prefer temporary address)".
void test_rule7_prefer_temporary_addresses(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *public_addr = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *temp = A(0x2001u, 0x0DB8u, 1u, 0, 0xD5E3u, 0x7953u, 0x13EBu, 0x22E8u);
    src(work_a, public_addr);
    src_add(work_a, temp, 0u, 0, 1, 0, 0, 0);
    select_is(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0xD5E3u, 0, 0, 1u), temp, 7u);
}

// sec 10.1, fifth: "Destination: 2001:db8:1::1 / Candidate Source Addresses: 2001:db8:1::2 or
// 2001:db8:3::2 / Result: 2001:db8:1:::2 (longest matching prefix)". The printed result carries a
// third colon; the candidate it names is 2001:db8:1::2.
void test_rule8_use_longest_matching_prefix(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *near = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *far = A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 2u);
    src(work_a, far);
    src(work_a, near);
    select_is(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), near, 8u);
}

// sec 5: "If the eight rules fail to choose a single address, the tiebreaker is
// implementation-specific." Here the incumbent keeps its place, so the answer repeats.
void test_a_tie_keeps_the_candidate_that_was_added_first(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *first = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *second = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 3u);
    src(work_a, first);
    src(work_a, second);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.addr = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 9u);
    Ip6Select.source_select(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP6_SELECT_IO(work_a)->found);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_IP6_SELECT_IO(work_a)->source, IDEMIP_IP6_ADDR_LEN);
    Ip6Select.source_select(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_IP6_SELECT_IO(work_a)->source, IDEMIP_IP6_ADDR_LEN);
}

// --- RFC 6724 sec 6, the destination rules, against sec 10.2 -----------------

// sec 10.2, first: "Candidate Source Addresses: 2001:db8:1::2 or fe80::1 or 169.254.13.78 /
// Destination Address List: 2001:db8:1::1 or 198.51.100.121 / Result: 2001:db8:1::1
// (src 2001:db8:1::2) then 198.51.100.121 (src 169.254.13.78) (prefer matching scope)".
void test_sec10_2_first_prefer_matching_scope(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *s6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *sll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    const uint8_t *s4 = V4(169u, 254u, 13u, 78u);
    src(work_a, s6);
    src(work_a, sll);
    src(work_a, s4);

    const uint8_t *d6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    const uint8_t *d4 = V4(198u, 51u, 100u, 121u);
    dst(work_a, d6);
    dst(work_a, d4);

    Ip6Select.dest_sort(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
    sorted_is(work_a, 0u, d6, s6);
    sorted_is(work_a, 1u, d4, s4);
}

// sec 10.2, second: "Candidate Source Addresses: fe80::1 or 198.51.100.117 / Destination Address
// List: 2001:db8:1::1 or 198.51.100.121 / Result: 198.51.100.121 (src 198.51.100.117) then
// 2001:db8:1::1 (src fe80::1) (prefer matching scope)". Here the sort reverses the given order.
void test_sec10_2_second_matching_scope_reverses_the_list(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *sll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    const uint8_t *s4 = V4(198u, 51u, 100u, 117u);
    src(work_a, sll);
    src(work_a, s4);

    const uint8_t *d6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    const uint8_t *d4 = V4(198u, 51u, 100u, 121u);
    dst(work_a, d6);
    dst(work_a, d4);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, d4, s4);
    sorted_is(work_a, 1u, d6, sll);
}

// sec 10.2, third: "Candidate Source Addresses: 2001:db8:1::2 or fe80::1 or 10.1.2.4 / Destination
// Address List: 2001:db8:1::1 or 10.1.2.3 / Result: 2001:db8:1::1 (src 2001:db8:1::2) then 10.1.2.3
// (src 10.1.2.4) (prefer higher precedence)". Both pairs match on scope and on label, so Rule 6
// decides on ::/0's 40 against ::ffff:0:0/96's 35.
void test_sec10_2_third_prefer_higher_precedence(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *s6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *sll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    const uint8_t *s4 = V4(10u, 1u, 2u, 4u);
    src(work_a, s6);
    src(work_a, sll);
    src(work_a, s4);

    const uint8_t *d6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    const uint8_t *d4 = V4(10u, 1u, 2u, 3u);
    dst(work_a, d6);
    dst(work_a, d4);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, d6, s6);
    sorted_is(work_a, 1u, d4, s4);
}

// sec 10.2, fourth: "Candidate Source Addresses: 2001:db8:1::2 or fe80::2 / Destination Address
// List: 2001:db8:1::1 or fe80::1 / Result: fe80::1 (src fe80::2) then 2001:db8:1::1
// (src 2001:db8:1::2) (prefer smaller scope)".
void test_sec10_2_fourth_prefer_smaller_scope(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *s6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *sll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u);
    src(work_a, s6);
    src(work_a, sll);

    const uint8_t *d6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    const uint8_t *dll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    dst(work_a, d6);
    dst(work_a, dll);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, dll, sll);
    sorted_is(work_a, 1u, d6, s6);
}

// sec 10.2, fifth: "Candidate Source Addresses: 2001:db8:1::2 (care-of address) or 2001:db8:3::1
// (home address) or fe80::2 (care-of address) / Destination Address List: 2001:db8:1::1 or fe80::1 /
// Result: 2001:db8:1::1 (src 2001:db8:3::1) then fe80::1 (src fe80::2) (prefer home address)".
void test_sec10_2_fifth_prefer_home_address(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *care = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    const uint8_t *home = A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 1u);
    const uint8_t *ll_care = A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u);
    src_add(work_a, care, 0u, 0, 0, 0, 1, 0);
    src_add(work_a, home, 0u, 0, 0, 1, 0, 0);
    src_add(work_a, ll_care, 0u, 0, 0, 0, 1, 0);

    const uint8_t *d6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    const uint8_t *dll = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    dst(work_a, d6);
    dst(work_a, dll);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, d6, home);
    sorted_is(work_a, 1u, dll, ll_care);
}

// Rule 1: "If DB is known to be unreachable or if Source(DB) is undefined, then prefer DA."
void test_dest_rule1_avoid_unusable_destinations(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *s6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    src(work_a, s6);

    const uint8_t *dead = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    const uint8_t *live = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 5u);
    dst_add(work_a, dead, 0u, 1, 0);
    dst_add(work_a, live, 0u, 0, 0);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, live, s6);
    sorted_is(work_a, 1u, dead, s6);
}

// sec 6: "The pair-wise comparison of destination addresses consists of ten rules, which MUST be
// applied in order. If a rule determines a result, then the remaining rules are not relevant and
// MUST be ignored. Subsequent rules act as tiebreakers for earlier rules." Rule 1 ties when both
// destinations are unreachable, and sec 6 makes Rules 2 through 5 and Rule 9 inapplicable only when
// "there is no source address available for destination D", so a tie is broken by Rule 2 next.
void test_dest_rule1_ties_and_rule2_breaks_it(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *site_src = A(0xFEC0u, 0, 0, 0, 0, 0, 0, 2u);
    src(work_a, site_src);

    const uint8_t *site_dst = A(0xFEC0u, 0, 0, 0, 0, 0, 0, 9u);              // Scope(DA) = site-local
    const uint8_t *global_dst = A(0x2001u, 0x0DB8u, 9u, 0, 0, 0, 0, 1u);     // Scope(DB) = global
    dst_add(work_a, site_dst, 0u, 1, 0);                               // both unreachable, so Rule 1 ties
    dst_add(work_a, global_dst, 0u, 1, 0);

    Ip6Select.dest_sort(work_a);
    // Rule 2: "If Scope(DA) = Scope(Source(DA)) and Scope(DB) <> Scope(Source(DB)), then prefer DA."
    sorted_is(work_a, 0u, site_dst, site_src);
    sorted_is(work_a, 1u, global_dst, site_src);
}

// Rule 3: "Avoid deprecated addresses. If Source(DA) is deprecated and Source(DB) is not, then prefer
// DB." RFC 4862 is what deprecates one, and calls it "An address assigned to an interface whose use
// is discouraged, but not forbidden".
void test_dest_rule3_avoids_a_deprecated_source(void)
{
    Ip6Select.clear(work_a);
    // sec 4 confines a link-local destination's candidates to its own link, so each destination has
    // exactly one source and sec 5's own Rule 3 cannot pick the other one first.
    const uint8_t *old = A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u);
    const uint8_t *fresh = A(0xFE80u, 0, 0, 0, 0, 0, 0, 3u);
    src_add(work_a, old, 1u, 1, 0, 0, 0, 0); // deprecated, on interface 1
    src_add(work_a, fresh, 0u, 0, 0, 0, 0, 0);

    const uint8_t *da = A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u);  // on interface 1, so Source(DA) is deprecated
    const uint8_t *db = A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xAu); // on interface 0
    dst_add(work_a, da, 1u, 0, 0);
    dst_add(work_a, db, 0u, 0, 0);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, db, fresh);
    sorted_is(work_a, 1u, da, old);
}

// Rule 5: "Prefer matching label. If Label(Source(DA)) = Label(DA) and Label(Source(DB)) <>
// Label(DB), then prefer DA." sec 2.1's table is what assigns a label to each.
void test_dest_rule5_prefers_a_matching_label(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectPolicyArgs *p = &IDEMIP_IP6_SELECT_IO(work_a)->policy_args;
    // Two rows on the same precedence, so Rule 6 cannot decide and Rule 5 is what is left.
    p->prefix = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 0);
    p->zone = 0u;
    p->prefix_len = 48u;
    p->precedence = 40u;
    p->label = 11u;
    Ip6Select.policy_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
    p->prefix = A(0x2001u, 0x0DB8u, 2u, 0, 0, 0, 0, 0);
    p->zone = 0u;
    p->prefix_len = 48u;
    p->precedence = 40u;
    p->label = 12u;
    Ip6Select.policy_set(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);

    const uint8_t *s_lab11 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    src(work_a, s_lab11);

    const uint8_t *da = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 9u); // Label(DA) = 11 = Label(Source(DA))
    const uint8_t *db = A(0x2001u, 0x0DB8u, 2u, 0, 0, 0, 0, 9u); // Label(DB) = 12 <> 11
    dst(work_a, db);
    dst(work_a, da);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, da, s_lab11);
    sorted_is(work_a, 1u, db, s_lab11);
}

// RFC 6724 sec 4: "For site-local unicast destination addresses, the set of candidate source
// addresses MUST only include addresses assigned to interfaces belonging to the same site as the
// outgoing interface." RFC 4007 sec 6 numbers the zones, so a source in a different site zone is not
// a candidate at all.
void test_sec4_a_site_local_destination_only_takes_a_source_from_its_own_site(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *near_site = A(0xFEC0u, 0, 0, 0, 0, 0, 0, 2u);
    const uint8_t *far_site = A(0xFEC0u, 0, 0, 0, 0, 0, 0, 3u);
    Ip6SelectSourceArgs *s = &IDEMIP_IP6_SELECT_IO(work_a)->source_args;

    s->addr = far_site;
    s->zone = 9u; // a different site
    s->netif = 0u;
    s->deprecated = IDEMIP_FALSE;
    s->temporary = IDEMIP_FALSE;
    s->home = IDEMIP_FALSE;
    s->care_of = IDEMIP_FALSE;
    s->next_hop = IDEMIP_FALSE;
    Ip6Select.source_add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);

    s->addr = near_site;
    s->zone = 4u; // the destination's site
    s->netif = 0u;
    Ip6Select.source_add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);

    IDEMIP_IP6_SELECT_IO(work_a)->query_args.addr = A(0xFEC0u, 0, 0, 0, 0, 0, 0, 9u);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.zone = 4u;
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.netif = 0u;
    Ip6Select.source_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IP6_SELECT_IO(work_a)->found);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(near_site, IDEMIP_IP6_SELECT_IO(work_a)->source, IDEMIP_IP6_ADDR_LEN,
                                          "a source outside the destination's site is not a candidate");

    // With only the far-site source in the set there is no candidate at all.
    Ip6Select.clear(work_a);
    s = &IDEMIP_IP6_SELECT_IO(work_a)->source_args;
    s->addr = far_site;
    s->zone = 9u;
    s->netif = 0u;
    s->deprecated = IDEMIP_FALSE;
    s->temporary = IDEMIP_FALSE;
    s->home = IDEMIP_FALSE;
    s->care_of = IDEMIP_FALSE;
    s->next_hop = IDEMIP_FALSE;
    Ip6Select.source_add(work_a);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.addr = A(0xFEC0u, 0, 0, 0, 0, 0, 0, 9u);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.zone = 4u;
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.netif = 0u;
    Ip6Select.source_select(work_a);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP6_SELECT_IO(work_a)->found, "sec 4's candidate set is empty here");
}

// Rule 7: "If DA is reached via an encapsulating transition mechanism (e.g., IPv6 in IPv4) and DB is
// not, then prefer DB."
void test_dest_rule7_prefer_native_transport(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *s6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    src(work_a, s6);

    const uint8_t *tunneled = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    const uint8_t *native = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 5u);
    dst_add(work_a, tunneled, 0u, 0, 1);
    dst_add(work_a, native, 0u, 0, 0);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, native, s6);
    sorted_is(work_a, 1u, tunneled, s6);
}

// Rule 9: "If CommonPrefixLen(Source(DA), DA) > CommonPrefixLen(Source(DB), DB), then prefer DA",
// applied only "When DA and DB belong to the same address family".
void test_dest_rule9_use_longest_matching_prefix(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *s6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    src(work_a, s6);

    const uint8_t *far = A(0x2001u, 0x0DB8u, 9u, 0, 0, 0, 0, 1u);
    const uint8_t *near = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    dst(work_a, far);
    dst(work_a, near);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, near, s6);
    sorted_is(work_a, 1u, far, s6);
}

// Rule 10: "If DA preceded DB in the original list, prefer DA." Two identical destinations tie every
// earlier rule, so the given order survives.
void test_dest_rule10_leaves_the_order_unchanged(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *s6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    src(work_a, s6);

    const uint8_t *first = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    const uint8_t *second = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    dst(work_a, first);
    dst(work_a, second);

    Ip6Select.dest_sort(work_a);
    TEST_ASSERT_EQUAL_UINT8(0u, (IDEMIP_IP6_SELECT_IO(work_a)->query_args.index = 0u,
                                Ip6Select.dest_at(work_a), IDEMIP_IP6_SELECT_IO(work_a)->index));
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.index = 1u;
    Ip6Select.dest_at(work_a);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_SELECT_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(second, IDEMIP_IP6_SELECT_IO(work_a)->dest, IDEMIP_IP6_ADDR_LEN);
}

// A destination with no source is still in the list, at the back, and reports no source.
void test_a_destination_with_no_source_sorts_last(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *s6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
    src_add(work_a, s6, 0u, 0, 0, 0, 0, 0);

    // A link-local destination on another interface has no candidate sec 4 admits.
    const uint8_t *orphan = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    const uint8_t *reachable = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    dst_add(work_a, orphan, 1u, 0, 0);
    dst_add(work_a, reachable, 0u, 0, 0);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, reachable, s6);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.index = 1u;
    Ip6Select.dest_at(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(orphan, IDEMIP_IP6_SELECT_IO(work_a)->dest, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_FALSE(IDEMIP_IP6_SELECT_IO(work_a)->found);
    TEST_ASSERT_NULL(IDEMIP_IP6_SELECT_IO(work_a)->source);
}

// A list no sort has run over, and a place past its end, are both ERR and never BUSY: neither
// becomes readable on a later tick without a call the caller makes.
void test_dest_at_refuses_before_a_sort_and_past_the_end(void)
{
    Ip6Select.clear(work_a);
    dst(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u));

    IDEMIP_IP6_SELECT_IO(work_a)->query_args.index = 0u;
    Ip6Select.dest_at(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);

    Ip6Select.dest_sort(work_a);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.index = 0u;
    Ip6Select.dest_at(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);

    IDEMIP_IP6_SELECT_IO(work_a)->query_args.index = 1u;
    Ip6Select.dest_at(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
}

// Adding to either list after a sort clears the sorted mark, so a stale order is never read back.
void test_adding_after_a_sort_invalidates_it(void)
{
    Ip6Select.clear(work_a);
    src(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u));
    dst(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u));
    Ip6Select.dest_sort(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP6_SELECT_IO(work_a)->sorted);

    dst(work_a, A(0x2001u, 0x0DB8u, 2u, 0, 0, 0, 0, 1u));
    TEST_ASSERT_FALSE(IDEMIP_IP6_SELECT_IO(work_a)->sorted);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.index = 0u;
    Ip6Select.dest_at(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_SELECT_IO(work_a)->status);
}

// Nothing here defers, so no entry ever reports BUSY on a well-formed call.
void test_no_entry_ever_reports_busy(void)
{
    Ip6Select.clear(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP6_SELECT_IO(work_a)->status);
    src(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u));
    dst(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u));
    Ip6Select.dest_sort(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
    IDEMIP_IP6_SELECT_IO(work_a)->query_args.index = 0u;
    Ip6Select.dest_at(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
}
