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

// --- sec 5, read from both ends ----------------------------------------------

// Each rule above was driven with the winner in one position only. ip6_select_best_source compares
// every new candidate against the incumbent, so the position decides which arm of the rule runs: with
// the winner added first the rule has to keep the incumbent, with it added second the rule has to
// replace it. Both arms are the same rule and neither had been read.
//
// sec 5 states each rule as a preference over a pair, twice over - "If SA is simultaneously a home
// address and care-of address and SB is not, then prefer SA. Similarly, if SB is simultaneously a
// home address and care-of address and SA is not, then prefer SB" is rule 4 written both ways - so
// the answer is a property of the pair. A comparator that agreed only when the candidates arrived in
// one order would still pass every case above.

typedef struct
{
    const uint8_t *addr;
    uint8_t netif;
    int deprecated;
    int temporary;
    int home;
    int care_of;
    int next_hop;
} Cand;

static void add_cand(uint8_t *w, const Cand *c)
{
    src_add(w, c->addr, c->netif, c->deprecated, c->temporary, c->home, c->care_of, c->next_hop);
}

static void wins_either_order(const Cand *win, const Cand *lose, const uint8_t *d, uint8_t rule)
{
    Ip6Select.clear(work_a);
    add_cand(work_a, win);
    add_cand(work_a, lose);
    select_is(work_a, d, win->addr, rule);

    Ip6Select.clear(work_a);
    add_cand(work_a, lose);
    add_cand(work_a, win);
    select_is(work_a, d, win->addr, rule);
}

void test_rule1_decides_the_same_pair_either_way_round(void)
{
    const Cand same = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 0u, 1, 0, 0, 0, 0};
    const Cand other = {A(0x2001u, 0x0DB8u, 2u, 0, 0, 0, 0, 1u), 0u, 0, 0, 0, 0, 0};
    wins_either_order(&same, &other, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 1u);
}

void test_rule2_decides_the_same_pair_either_way_round(void)
{
    const Cand global = {A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 1u), 0u, 0, 0, 0, 0, 0};
    const Cand ll = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u), 0u, 0, 0, 0, 0, 0};
    wins_either_order(&global, &ll, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 2u);
}

void test_rule3_decides_the_same_pair_either_way_round(void)
{
    const Cand fresh = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 3u), 0u, 0, 0, 0, 0, 0};
    const Cand old = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 1, 0, 0, 0, 0};
    wins_either_order(&fresh, &old, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 3u);
}

void test_rule4_decides_the_same_pair_either_way_round(void)
{
    const Cand home = {A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 2u), 0u, 0, 0, 1, 0, 0};
    const Cand care_of = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 1, 0};
    wins_either_order(&home, &care_of, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 4u);
}

void test_rule4_both_decides_the_same_pair_either_way_round(void)
{
    const Cand both = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 3u), 0u, 0, 0, 1, 1, 0};
    const Cand home_only = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 0, 0, 1, 0, 0};
    wins_either_order(&both, &home_only, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 4u);
}

// Rule 4 names two pairs and no others: both-against-not-both, and just-home-against-just-care-of. A
// home address against a plain one is neither of those, so the rule abstains and rule 8 decides. The
// plain address is the near one here, so a rule 4 that reached further than sec 5 lets it would show
// up as the wrong winner and not merely a different rule number.
void test_rule4_abstains_on_the_pairs_sec5_does_not_name(void)
{
    const Cand plain_near = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 0, 0};
    const Cand home_far = {A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 2u), 0u, 0, 0, 1, 0, 0};
    const Cand care_far = {A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 3u), 0u, 0, 0, 0, 1, 0};
    const uint8_t *d = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    wins_either_order(&plain_near, &home_far, d, 8u);
    wins_either_order(&plain_near, &care_far, d, 8u);
}

void test_rule5_decides_the_same_pair_either_way_round(void)
{
    const Cand out_if = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 3u), 0u, 0, 0, 0, 0, 0};
    const Cand other_if = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 1u, 0, 0, 0, 0, 0};
    wins_either_order(&out_if, &other_if, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 5u);
}

void test_rule5_5_decides_the_same_pair_either_way_round(void)
{
    const Cand from_hop = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 3u), 0u, 0, 0, 0, 0, 1};
    const Cand elsewhere = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 0, 0};
    wins_either_order(&from_hop, &elsewhere, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), IDEMIP_IP6_SELECT_RULE_5_5);
}

void test_rule6_decides_the_same_pair_either_way_round(void)
{
    const Cand sixtofour = {A(0x2002u, 0xC633u, 0x6401u, 0, 0xD5E3u, 0x7953u, 0x13EBu, 0x22E8u), 0u, 0, 1, 0, 0, 0};
    const Cand native = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 0, 0};
    wins_either_order(&sixtofour, &native, A(0x2002u, 0xC633u, 0x6401u, 0, 0, 0, 0, 1u), 6u);
}

void test_rule7_decides_the_same_pair_either_way_round(void)
{
    const Cand temp = {A(0x2001u, 0x0DB8u, 1u, 0, 0xD5E3u, 0x7953u, 0x13EBu, 0x22E8u), 0u, 0, 1, 0, 0, 0};
    const Cand public_addr = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 0, 0};
    wins_either_order(&temp, &public_addr, A(0x2001u, 0x0DB8u, 1u, 0, 0xD5E3u, 0, 0, 1u), 7u);
}

void test_rule8_decides_the_same_pair_either_way_round(void)
{
    const Cand near = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 0, 0};
    const Cand far = {A(0x2001u, 0x0DB8u, 3u, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 0, 0};
    wins_either_order(&near, &far, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 8u);
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

// --- sec 6, read from both ends ----------------------------------------------

// The same argument as sec 5's above, on the other comparator. dest_sort compares each destination
// against the ones already placed, so which of a pair arrives first decides which arm of each rule
// runs. sec 6 states its rules as a comparison over a pair - "If DB is known to be unreachable ...
// then prefer DA" - so the sorted order is a property of the set and not of the order it was given in.

typedef struct
{
    const uint8_t *addr;
    uint8_t netif;
    int unreachable;
    int encapsulated;
} Dest;

static void sorts_either_order(const Cand *s1, const Cand *s2, const Dest *win, const Dest *lose)
{
    for (int swapped = 0; swapped < 2; swapped++)
    {
        Ip6Select.clear(work_a);
        add_cand(work_a, s1);
        if (s2 != NULL)
        {
            add_cand(work_a, s2);
        }
        const Dest *first = swapped ? lose : win;
        const Dest *second = swapped ? win : lose;
        dst_add(work_a, first->addr, first->netif, first->unreachable, first->encapsulated);
        dst_add(work_a, second->addr, second->netif, second->unreachable, second->encapsulated);
        Ip6Select.dest_sort(work_a);
        sorted_is(work_a, 0u, win->addr, NULL);
        sorted_is(work_a, 1u, lose->addr, NULL);
    }
}

void test_dest_rule1_sorts_the_same_pair_either_way_round(void)
{
    const Cand s6 = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 0, 0};
    const Dest live = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 5u), 0u, 0, 0};
    const Dest dead = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 0u, 1, 0};
    sorts_either_order(&s6, NULL, &live, &dead);
}

// sec 4 confines a link-local destination's candidates to its own link, so each destination below has
// exactly one source and sec 5 cannot settle the pair before sec 6 sees it. That is what lets rule 3
// and rule 4 be read on the destination side at all: both are about Source(D), not about D.
void test_dest_rule3_sorts_the_same_pair_either_way_round(void)
{
    const Cand old = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u), 1u, 1, 0, 0, 0, 0};
    const Cand fresh = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 3u), 0u, 0, 0, 0, 0, 0};
    const Dest by_fresh = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xAu), 0u, 0, 0};
    const Dest by_old = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u), 1u, 0, 0};
    sorts_either_order(&old, &fresh, &by_fresh, &by_old);
}

// Rule 4: "Prefer home addresses. If Source(DA) is simultaneously a home address and care-of address
// and Source(DB) is not, then prefer DA. ... If Source(DA) is just a home address and Source(DB) is
// just a care-of address, then prefer DA." The same two pairs sec 5 rule 4 names, read off the
// sources the destinations resolved to.
void test_dest_rule4_prefers_the_destination_whose_source_is_home(void)
{
    const Cand home = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u), 1u, 0, 0, 1, 0, 0};
    const Cand care_of = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 3u), 0u, 0, 0, 0, 1, 0};
    const Dest by_home = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u), 1u, 0, 0};
    const Dest by_care_of = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xAu), 0u, 0, 0};
    sorts_either_order(&home, &care_of, &by_home, &by_care_of);
}

// The other pair rule 4 names, on the same side: an address that is both beats one that is only one of
// the two.
void test_dest_rule4_prefers_the_destination_whose_source_is_both(void)
{
    const Cand both = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u), 1u, 0, 0, 1, 1, 0};
    const Cand home_only = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 3u), 0u, 0, 0, 1, 0, 0};
    const Dest by_both = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u), 1u, 0, 0};
    const Dest by_home_only = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xAu), 0u, 0, 0};
    sorts_either_order(&both, &home_only, &by_both, &by_home_only);
}

void test_dest_rule7_sorts_the_same_pair_either_way_round(void)
{
    const Cand s6 = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 0, 0};
    const Dest native = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 5u), 0u, 0, 0};
    const Dest tunneled = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 0u, 0, 1};
    sorts_either_order(&s6, NULL, &native, &tunneled);
}

void test_dest_rule9_sorts_the_same_pair_either_way_round(void)
{
    const Cand s6 = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 0, 0};
    const Dest near = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 0u, 0, 0};
    const Dest far = {A(0x2001u, 0x0DB8u, 9u, 0, 0, 0, 0, 1u), 0u, 0, 0};
    sorts_either_order(&s6, NULL, &near, &far);
}

// Rule 10: "If DA preceded DB in the original list, prefer DA." Two identical destinations tie every
// earlier rule, so the given order survives.
// Rule 2: "If Scope(DA) = Scope(Source(DA)) and Scope(DB) <> Scope(Source(DB)), then prefer DA."
// One destination matches the scope of the source it resolved to and the other does not, and which of
// them arrives first decides nothing.
void test_dest_rule2_sorts_the_same_pair_either_way_round(void)
{
    const Cand ll = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u), 0u, 0, 0, 0, 0, 0};
    // The link-local destination is reached from the link-local source, so the scopes match; the
    // global one is reached from the same source and they do not.
    const Dest matched = {A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u), 0u, 0, 0};
    const Dest crossed = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 9u), 0u, 0, 0};
    sorts_either_order(&ll, NULL, &matched, &crossed);
}

// Rule 5: "Prefer matching label", either way round. Two policy rows on one precedence, so Rule 6
// cannot decide the pair and Rule 5 is what is left.
void test_dest_rule5_sorts_the_same_pair_either_way_round(void)
{
    for (int swapped = 0; swapped < 2; swapped++)
    {
        Ip6Select.clear(work_a);
        Ip6SelectPolicyArgs *p = &IDEMIP_IP6_SELECT_IO(work_a)->policy_args;
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
        const uint8_t *win = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 9u);
        const uint8_t *lose = A(0x2001u, 0x0DB8u, 2u, 0, 0, 0, 0, 9u);
        dst(work_a, swapped ? win : lose);
        dst(work_a, swapped ? lose : win);

        Ip6Select.dest_sort(work_a);
        sorted_is(work_a, 0u, win, s_lab11);
        sorted_is(work_a, 1u, lose, s_lab11);
    }
}

// Rule 6: "If Precedence(DA) > Precedence(DB), then prefer DA", either way round. Two policy rows on
// one label, so Rule 5 cannot decide the pair.
void test_dest_rule6_sorts_the_same_pair_either_way_round(void)
{
    for (int swapped = 0; swapped < 2; swapped++)
    {
        Ip6Select.clear(work_a);
        Ip6SelectPolicyArgs *p = &IDEMIP_IP6_SELECT_IO(work_a)->policy_args;
        p->prefix = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 0);
        p->zone = 0u;
        p->prefix_len = 48u;
        p->precedence = 50u;
        p->label = 7u;
        Ip6Select.policy_set(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
        p->prefix = A(0x2001u, 0x0DB8u, 2u, 0, 0, 0, 0, 0);
        p->zone = 0u;
        p->prefix_len = 48u;
        p->precedence = 20u;
        p->label = 7u;
        Ip6Select.policy_set(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);

        const uint8_t *s6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u);
        src(work_a, s6);
        const uint8_t *high = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 9u);
        const uint8_t *low = A(0x2001u, 0x0DB8u, 2u, 0, 0, 0, 0, 9u);
        dst(work_a, swapped ? high : low);
        dst(work_a, swapped ? low : high);

        Ip6Select.dest_sort(work_a);
        sorted_is(work_a, 0u, high, NULL);
        sorted_is(work_a, 1u, low, NULL);
    }
}

// Rule 8: "If Scope(DA) < Scope(DB), then prefer DA", either way round. Both destinations resolve to
// the same source, so the rules that read Source(D) tie and the smaller scope is what is left.
void test_dest_rule8_sorts_the_same_pair_either_way_round(void)
{
    for (int swapped = 0; swapped < 2; swapped++)
    {
        Ip6Select.clear(work_a);
        // A link-local source and a global one on the same interface, so each destination has a
        // source of its own scope and Rule 2 ties.
        src(work_a, A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u));
        src(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u));
        const uint8_t *smaller = A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u);
        const uint8_t *larger = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 9u);
        dst(work_a, swapped ? smaller : larger);
        dst(work_a, swapped ? larger : smaller);

        Ip6Select.dest_sort(work_a);
        sorted_is(work_a, 0u, smaller, NULL);
        sorted_is(work_a, 1u, larger, NULL);
    }
}

// RFC 6724 sec 5 rule 4 and sec 6 rule 4 both compare a home address against a care-of address, and
// both say nothing about a pair that is alike: two addresses that are each simultaneously a home
// address and a care-of address are equal under the rule, and so are two that are neither. What
// decides them is a later rule, which is what "If a rule determines a result, then the remaining
// rules are not relevant" leaves for the cases the rule does not determine.
void test_rule4_decides_nothing_between_two_alike_sources(void)
{
    // Both simultaneously home and care-of, so the first half of the rule ties; rule 8's longest
    // common prefix with the destination is what settles them.
    const Cand near_both = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 0u, 0, 0, 1, 1, 0};
    const Cand far_both = {A(0x2001u, 0x0DB8u, 9u, 0, 0, 0, 0, 1u), 0u, 0, 0, 1, 1, 0};
    wins_either_order(&near_both, &far_both, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 5u), 8u);

    // One a home address alone and one neither, which is the other arm of the same sentence: a home
    // address is preferred over a care-of address and over nothing in particular it is not.
    const Cand home_far = {A(0x2001u, 0x0DB8u, 9u, 0, 0, 0, 0, 1u), 0u, 0, 0, 1, 0, 0};
    const Cand plain_near = {A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u), 0u, 0, 0, 0, 0, 0};
    wins_either_order(&plain_near, &home_far, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 5u), 8u);
}

// The sec 6 twin of the sec 5 case above: two destinations whose sources are alike under rule 4
// decide nothing there, and a later rule settles them. Both sources are simultaneously a home address
// and a care-of address, which is the mobile node "at home" for that address.
void test_dest_rule4_decides_nothing_between_two_alike_sources(void)
{
    Ip6Select.clear(work_a);
    // sec 4 confines a link-local destination's candidates to its own link, so each destination has
    // exactly one source and sec 5 cannot settle the pair before sec 6 sees it.
    src_add(work_a, A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u), 0u, 0, 0, 1, 1, 0);
    src_add(work_a, A(0xFE80u, 0, 0, 0, 0, 0, 0, 3u), 1u, 0, 0, 1, 1, 0);
    const uint8_t *first = A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u);
    const uint8_t *second = A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xAu);
    dst_add(work_a, first, 0u, 0, 0);
    dst_add(work_a, second, 1u, 0, 0);

    Ip6Select.dest_sort(work_a);
    // Nothing above rule 10 tells them apart, so the order they arrived in stands.
    sorted_is(work_a, 0u, first, NULL);
    sorted_is(work_a, 1u, second, NULL);
}

// The other arm of sec 6 rule 4's sentence: a home address is preferred over a care-of address, and
// over a source that is neither it is not. Both pairs are read, so the rule's two tests each have a
// case that fails if it is removed.
void test_dest_rule4_prefers_home_over_care_of_and_not_over_neither(void)
{
    Ip6Select.clear(work_a);
    src_add(work_a, A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u), 0u, 0, 0, 1, 0, 0); // home alone
    src_add(work_a, A(0xFE80u, 0, 0, 0, 0, 0, 0, 3u), 1u, 0, 0, 0, 0, 0); // neither
    const uint8_t *by_home = A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u);
    const uint8_t *by_plain = A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xAu);
    dst_add(work_a, by_plain, 1u, 0, 0);
    dst_add(work_a, by_home, 0u, 0, 0);

    Ip6Select.dest_sort(work_a);
    // The rule says nothing about home against neither, so rule 10 leaves them as they arrived.
    sorted_is(work_a, 0u, by_plain, NULL);
    sorted_is(work_a, 1u, by_home, NULL);
}

// sec 6 rule 1: "If DB is known to be unreachable or if Source(DB) is undefined, then prefer DA."
// The second half is a destination with no candidate on its link at all, which sec 4 leaves without a
// source, and it is a different thing from one flagged unreachable.
void test_dest_rule1_avoids_a_destination_with_no_source_at_all(void)
{
    Ip6Select.clear(work_a);
    const uint8_t *only = A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u);
    src_add(work_a, only, 0u, 0, 0, 0, 0, 0);

    // The second destination is on an interface no candidate is on, so sec 4 finds it none.
    const uint8_t *sourced = A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u);
    const uint8_t *unsourced = A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xAu);
    dst_add(work_a, unsourced, 3u, 0, 0);
    dst_add(work_a, sourced, 0u, 0, 0);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, sourced, only);
    sorted_is(work_a, 1u, unsourced, NULL);
}

// Every entry takes the address it works on as a pointer, and a caller can have none to give: an
// option read out of a message that stopped short, a socket call with no address behind it. RFC 6724
// keys every table and every rule on an address, so an entry given none has nothing to work on and
// refuses rather than reading the sixteen octets that are not there.
void test_every_entry_that_takes_an_address_refuses_a_null_one(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectIo *io = IDEMIP_IP6_SELECT_IO(work_a);

    io->policy_args.prefix = NULL;
    io->policy_args.zone = 0u;
    io->policy_args.prefix_len = 48u;
    io->policy_args.precedence = 40u;
    io->policy_args.label = 1u;
    Ip6Select.policy_set(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "policy_set keyed a row on no prefix");

    io->query_args.addr = NULL;
    io->query_args.zone = 0u;
    Ip6Select.policy_lookup(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "policy_lookup looked under no address");

    io->query_args.addr = NULL;
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "scope_of read the scope of no address");

    io->source_args.addr = NULL;
    io->source_args.netif = 0u;
    Ip6Select.source_add(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "source_add held no address");

    io->dest_args.addr = NULL;
    io->dest_args.netif = 0u;
    Ip6Select.dest_add(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "dest_add held no address");

    io->query_args.addr = NULL;
    io->query_args.peer = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 5u);
    Ip6Select.source_select(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "source_select selected for no destination");
}

// RFC 6724 sec 3.1: "IPv4 addresses MUST be represented as IPv4-mapped addresses", and sec 2.1's
// table gives ::ffff:0:0/96 a scope of its own reading: RFC 3927's 169.254/16 is link-local and
// 127/8 is the loopback, so the mapped form of each carries the scope its IPv4 form has.
void test_a_mapped_ipv4_link_local_address_has_link_local_scope(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectIo *io = IDEMIP_IP6_SELECT_IO(work_a);

    io->query_args.addr = V4(169u, 254u, 13u, 78u);
    io->query_args.zone = 0u;
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP6_SCOPE_LINK_LOCAL, (int)io->scope,
                                  "a mapped 169.254/16 address is not link-local");

    // 169.253 is not in that prefix, and neither is 170.254: both octets are read.
    io->query_args.addr = V4(169u, 253u, 13u, 78u);
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP6_SCOPE_GLOBAL, (int)io->scope, "169.253/16 was taken as link-local");
    io->query_args.addr = V4(170u, 254u, 13u, 78u);
    Ip6Select.scope_of(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP6_SCOPE_GLOBAL, (int)io->scope, "170.254/16 was taken as link-local");
}

// sec 2.2: "the length of the longest prefix (looking at the most significant, or leftmost, bits)
// that the two addresses have in common, up to the length of S's prefix (i.e., the portion of the
// address not including the interface ID)". Two addresses that are the same have every bit in
// common, and the length reported is still the cap, because the interface ID is not part of it.
void test_the_common_prefix_of_an_address_with_itself_is_the_whole_prefix(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectIo *io = IDEMIP_IP6_SELECT_IO(work_a);
    io->query_args.addr = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    io->query_args.peer = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    Ip6Select.common_prefix(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)IDEMIP_IP6_SELECT_COMMON_PREFIX_MAX, io->common,
                                    "an address matching itself reported fewer bits than the prefix has");
}

// sec 5 rule 1: "Prefer same address. If SA = D, then prefer SA." RFC 4007 sec 6 makes a non-global
// address the same address only in the same zone, and reserves index zero to "use the default zone",
// which matches whatever zone the other names. A link-local candidate equal to the destination is the
// same address; the same octets in another zone are not.
void test_rule1_reads_the_zone_of_a_non_global_address(void)
{
    const uint8_t *same = A(0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    const uint8_t *other = A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u);

    // Both in zone 2, so rule 1 takes the one that is the destination.
    Ip6Select.clear(work_a);
    Ip6SelectSourceArgs *sa = &IDEMIP_IP6_SELECT_IO(work_a)->source_args;
    sa->addr = same;
    sa->zone = 2u;
    sa->netif = 0u;
    sa->deprecated = IDEMIP_FALSE;
    sa->temporary = IDEMIP_FALSE;
    sa->home = IDEMIP_FALSE;
    sa->care_of = IDEMIP_FALSE;
    sa->next_hop = IDEMIP_FALSE;
    Ip6Select.source_add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
    sa->addr = other;
    sa->zone = 2u;
    sa->netif = 0u;
    Ip6Select.source_add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);

    Ip6SelectIo *io = IDEMIP_IP6_SELECT_IO(work_a);
    io->query_args.addr = same;
    io->query_args.zone = 2u;
    io->query_args.peer = NULL;
    io->query_args.netif = 0u;
    Ip6Select.source_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(same, io->source, IDEMIP_IP6_ADDR_LEN, "rule 1 did not take the same address");
    TEST_ASSERT_EQUAL_UINT8(1u, io->rule);

    // The same octets in another zone are another address, so rule 1 has nothing to take and a later
    // rule decides.
    io->query_args.zone = 3u;
    Ip6Select.source_select(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(1u, io->rule, "an address in another zone was taken as the same address");
}

// sec 4: "For site-local unicast destination addresses, the set of candidate source addresses MUST
// only include addresses assigned to interfaces belonging to the same site as the outgoing
// interface." RFC 4007 sec 5 leaves a site zone to be "defined and configured by network
// administrators", so the index the caller supplies is what says which site, and index zero is the
// default the same section reserves - which admits either side.
void test_a_site_local_destination_takes_a_candidate_of_its_own_site(void)
{
    static const uint8_t site_d[IDEMIP_IP6_ADDR_LEN] = {0xFEu, 0xC0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09u};
    static const uint8_t site_s[IDEMIP_IP6_ADDR_LEN] = {0xFEu, 0xC0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02u};

    Ip6Select.clear(work_a);
    Ip6SelectSourceArgs *sa = &IDEMIP_IP6_SELECT_IO(work_a)->source_args;
    sa->addr = site_s;
    sa->zone = 5u;
    sa->netif = 0u;
    sa->deprecated = IDEMIP_FALSE;
    sa->temporary = IDEMIP_FALSE;
    sa->home = IDEMIP_FALSE;
    sa->care_of = IDEMIP_FALSE;
    sa->next_hop = IDEMIP_FALSE;
    Ip6Select.source_add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);

    Ip6SelectIo *io = IDEMIP_IP6_SELECT_IO(work_a);
    io->query_args.addr = site_d;
    io->query_args.peer = NULL;
    io->query_args.netif = 0u;

    io->query_args.zone = 5u;
    Ip6Select.source_select(work_a);
    TEST_ASSERT_TRUE_MESSAGE(io->found, "a candidate in the destination's own site was refused");

    io->query_args.zone = 6u;
    Ip6Select.source_select(work_a);
    TEST_ASSERT_FALSE_MESSAGE(io->found, "a candidate in another site was admitted");
}

// RFC 4007 sec 6 reserves zone index zero to "use the default zone", so an address left at it names
// whatever zone the other side names. Both halves of the pair are read for it: a candidate at the
// default index is the destination's address whatever zone the destination is in, and a destination
// at the default index is matched by a candidate in any zone.
void test_the_default_zone_index_matches_whatever_zone_the_other_names(void)
{
    static const uint8_t ll[IDEMIP_IP6_ADDR_LEN] = {0xFEu, 0x80u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01u};
    static const struct
    {
        uint32_t src_zone;
        uint32_t dst_zone;
        const char *why;
    } rows[] = {
        {0u, 3u, "a candidate at the default index was not the destination's address"},
        {3u, 0u, "a destination at the default index was not matched by a candidate in a zone"},
        {3u, 3u, "the same zone on both sides was not the same address"},
    };

    for (size_t r = 0u; r < (sizeof rows / sizeof rows[0]); r++)
    {
        Ip6Select.clear(work_a);
        Ip6SelectSourceArgs *sa = &IDEMIP_IP6_SELECT_IO(work_a)->source_args;
        sa->addr = ll;
        sa->zone = rows[r].src_zone;
        sa->netif = 0u;
        sa->deprecated = IDEMIP_FALSE;
        sa->temporary = IDEMIP_FALSE;
        sa->home = IDEMIP_FALSE;
        sa->care_of = IDEMIP_FALSE;
        sa->next_hop = IDEMIP_FALSE;
        Ip6Select.source_add(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);
        sa->addr = A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u);
        sa->zone = rows[r].src_zone;
        sa->netif = 0u;
        Ip6Select.source_add(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);

        Ip6SelectIo *io = IDEMIP_IP6_SELECT_IO(work_a);
        io->query_args.addr = ll;
        io->query_args.zone = rows[r].dst_zone;
        io->query_args.peer = NULL;
        io->query_args.netif = 0u;
        Ip6Select.source_select(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, io->rule, rows[r].why);
    }
}

// The same reserved index on sec 4's site test: a site-local destination admits a candidate whose
// zone is the default one, and a candidate admits a destination left at it.
void test_a_site_local_destination_admits_a_candidate_at_the_default_zone(void)
{
    static const uint8_t site_d[IDEMIP_IP6_ADDR_LEN] = {0xFEu, 0xC0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09u};
    static const uint8_t site_s[IDEMIP_IP6_ADDR_LEN] = {0xFEu, 0xC0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02u};
    static const struct
    {
        uint32_t src_zone;
        uint32_t dst_zone;
    } rows[] = {{0u, 6u}, {6u, 0u}};

    for (size_t r = 0u; r < (sizeof rows / sizeof rows[0]); r++)
    {
        Ip6Select.clear(work_a);
        Ip6SelectSourceArgs *sa = &IDEMIP_IP6_SELECT_IO(work_a)->source_args;
        sa->addr = site_s;
        sa->zone = rows[r].src_zone;
        sa->netif = 0u;
        sa->deprecated = IDEMIP_FALSE;
        sa->temporary = IDEMIP_FALSE;
        sa->home = IDEMIP_FALSE;
        sa->care_of = IDEMIP_FALSE;
        sa->next_hop = IDEMIP_FALSE;
        Ip6Select.source_add(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_SELECT_IO(work_a)->status);

        Ip6SelectIo *io = IDEMIP_IP6_SELECT_IO(work_a);
        io->query_args.addr = site_d;
        io->query_args.zone = rows[r].dst_zone;
        io->query_args.peer = NULL;
        io->query_args.netif = 0u;
        Ip6Select.source_select(work_a);
        TEST_ASSERT_TRUE_MESSAGE(io->found, "the default zone index refused a candidate on one side");
    }
}

// sec 6 rule 1 reads "Source(DB) is undefined" of each destination on its own, so a pair that both
// have none is a tie there, and rules 2 through 5 and rule 9 - which all read Source(D) - are the
// ones sec 6 makes inapplicable. Both destinations below are link-local on an interface no candidate
// is on, which sec 4 leaves without a source, and everything above rule 10 ties: the same precedence
// under sec 2.1's ::/0 row, neither encapsulated, the same scope. Rule 10 is what is left: "If DA
// preceded DB in the original list, prefer DA."
void test_two_destinations_with_no_source_fall_through_to_the_original_order(void)
{
    Ip6Select.clear(work_a);
    // A candidate on interface 0 alone, so neither destination has one on its link.
    src(work_a, A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u));

    const uint8_t *first = A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u);
    const uint8_t *second = A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xAu);
    dst_add(work_a, first, 3u, 0, 0);
    dst_add(work_a, second, 3u, 0, 0);

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, first, NULL);
    sorted_is(work_a, 1u, second, NULL);
}

// sec 6 rule 9 applies "When DA and DB belong to the same address family (both are IPv6 or both are
// IPv4)", so a pair that is one of each is not compared on their common prefixes at all, and rule 10
// leaves them where they were.
void test_rule9_does_not_compare_a_v4_destination_against_a_v6_one(void)
{
    Ip6Select.clear(work_a);
    src(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u));
    src(work_a, V4(192u, 0u, 2u, 1u));

    // Same precedence and label under sec 2.1 would settle them; these differ in family alone as far
    // as rule 9 is concerned, so a rule above it decides and rule 9 is passed over.
    const uint8_t *v6 = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 9u);
    const uint8_t *v4 = V4(192u, 0u, 2u, 9u);
    dst(work_a, v4);
    dst(work_a, v6);

    Ip6Select.dest_sort(work_a);
    // sec 2.1 gives ::/0 precedence 40 and ::ffff:0:0/96 precedence 35, so rule 6 is what decides.
    sorted_is(work_a, 0u, v6, NULL);
    sorted_is(work_a, 1u, v4, NULL);
}

// The tables are the borrow's, and they are finite. sec 2.1 keys a row on a prefix of an IPv6
// address, so a length past IDEMIP_IP6_ADDR_BITS names more bits than there are; a destination list
// with no room takes nothing more, and only clear empties it.
void test_the_entries_refuse_what_no_retry_fixes(void)
{
    Ip6Select.clear(work_a);
    Ip6SelectIo *io = IDEMIP_IP6_SELECT_IO(work_a);

    io->policy_args.prefix = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 0);
    io->policy_args.zone = 0u;
    io->policy_args.prefix_len = (uint8_t)(IDEMIP_IP6_ADDR_BITS + 1u);
    io->policy_args.precedence = 40u;
    io->policy_args.label = 1u;
    Ip6Select.policy_set(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "a prefix longer than an address was taken");

    // sec 2.2's CommonPrefixLen takes two addresses, and either of them can be the one the caller has
    // none of.
    io->query_args.addr = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    io->query_args.peer = NULL;
    Ip6Select.common_prefix(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "a common prefix was measured against nothing");
    io->query_args.addr = NULL;
    io->query_args.peer = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 1u);
    Ip6Select.common_prefix(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "a common prefix was measured for nothing");

    for (unsigned int i = 0u; i < (unsigned int)IDEMIP_IP6_SELECT_DESTS; i++)
    {
        dst(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, (uint16_t)(0x20u + i)));
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    }
    io->dest_args.addr = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 0x99u);
    io->dest_args.netif = 0u;
    io->dest_args.zone = 0u;
    io->dest_args.unreachable = IDEMIP_FALSE;
    io->dest_args.encapsulated = IDEMIP_FALSE;
    Ip6Select.dest_add(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "a full destination list took another one");
}

// sec 6 rule 10, "If DA preceded DB in the original list, prefer DA", read from both sides. A pair
// that ties everywhere above it is decided by the places they came in at, and the sort compares the
// entry it is looking at against the best it has found so far - which, once something has moved, is
// not always the later of the two. Three destinations: the third beats both of the others on rule 1,
// which moves it to the front, and the two that are left tie all the way down to rule 10.
void test_rule10_is_read_from_both_sides_of_a_pair(void)
{
    Ip6Select.clear(work_a);
    src(work_a, A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 2u));

    const uint8_t *first = A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u);
    const uint8_t *second = A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xAu);
    const uint8_t *sourced = A(0x2001u, 0x0DB8u, 1u, 0, 0, 0, 0, 9u);
    dst_add(work_a, first, 3u, 0, 0);   // link-local on an interface no candidate is on
    dst_add(work_a, second, 3u, 0, 0);  // the same, so the two of them tie
    dst_add(work_a, sourced, 0u, 0, 0); // rule 1 puts this one in front of both

    Ip6Select.dest_sort(work_a);
    sorted_is(work_a, 0u, sourced, NULL);
    sorted_is(work_a, 1u, first, NULL);
    sorted_is(work_a, 2u, second, NULL);
}

// sec 6 rule 4's second sentence is written twice over - "If Source(DA) is just a home address and
// Source(DB) is just a care-of address, then prefer DA. Similarly, if Source(DA) is just a care-of
// address and Source(DB) is just a home address, then prefer DB" - and the pair is read from
// whichever side the sort reaches first. A source that is neither is not a care-of address, so the
// rule says nothing about it either way round.
void test_dest_rule4_reads_its_pair_from_both_sides(void)
{
    for (int swapped = 0; swapped < 2; swapped++)
    {
        Ip6Select.clear(work_a);
        src_add(work_a, A(0xFE80u, 0, 0, 0, 0, 0, 0, 2u), 0u, 0, 0, 1, 0, 0); // home alone
        src_add(work_a, A(0xFE80u, 0, 0, 0, 0, 0, 0, 3u), 1u, 0, 0, 0, 1, 0); // care-of alone
        src_add(work_a, A(0xFE80u, 0, 0, 0, 0, 0, 0, 4u), 2u, 0, 0, 0, 0, 0); // neither

        const uint8_t *by_home = A(0xFE80u, 0, 0, 0, 0, 0, 0, 9u);
        const uint8_t *by_care = A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xAu);
        const uint8_t *by_plain = A(0xFE80u, 0, 0, 0, 0, 0, 0, 0xBu);
        // The home one is put where the sort meets it second in one pass and first in the other.
        dst_add(work_a, swapped ? by_home : by_plain, swapped ? 0u : 2u, 0, 0);
        dst_add(work_a, by_care, 1u, 0, 0);
        dst_add(work_a, swapped ? by_plain : by_home, swapped ? 2u : 0u, 0, 0);

        Ip6Select.dest_sort(work_a);
        // The home address is preferred over the care-of one wherever each of them came in.
        Ip6SelectIo *io = IDEMIP_IP6_SELECT_IO(work_a);
        uint8_t home_at = 0xFFu;
        uint8_t care_at = 0xFFu;
        for (uint8_t place = 0u; place < 3u; place++)
        {
            io->query_args.index = place;
            Ip6Select.dest_at(work_a);
            TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
            if (idemip_bytes_eq(io->dest, by_home, IDEMIP_IP6_ADDR_LEN))
            {
                home_at = place;
            }
            if (idemip_bytes_eq(io->dest, by_care, IDEMIP_IP6_ADDR_LEN))
            {
                care_at = place;
            }
        }
        TEST_ASSERT_TRUE_MESSAGE(home_at < care_at, "a care-of address was preferred over a home address");
    }
}

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
