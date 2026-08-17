// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for mld6, modeled on test_phy. It tests the CONTRACT and nothing else:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_MLD6_BORROW is intact after every case
//   5. the published offset map is ordered, aligned, and does not overlap
//   6. clear zeroes the regions, and a borrow no one cleared is refused
//
// No case here asserts what an entry reports once its RFC 2710 logic exists, so none of them has to
// be inverted when it does.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/mld/mld6.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each so
// a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(IDEMIP_ALIGN) uint8_t work_a[IDEMIP_MLD6_BORROW + 16];
static _Alignas(IDEMIP_ALIGN) uint8_t work_b[IDEMIP_MLD6_BORROW + 16];

// The span clear owns: the context and the group table.
#define STATE_OFF ((size_t)IDEMIP_MLD6_OFF_CTX)
#define TABLE_OFF ((size_t)IDEMIP_MLD6_OFF_GROUPS)
#define STATE_END ((size_t)IDEMIP_MLD6_OFF_END)

// RFC 4291 sec 2.7.1: the link-local scope all-nodes address, which RFC 2710 sec 4 excludes from the
// delay timers a General Query sets, and one solicited-node address a node does listen to.
static const uint8_t g_all_nodes[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_group[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0,    0,    0,   0,
                                                     0,    0,    0, 1, 0xFF, 0x00, 0x00, 0x01};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_MLD6_BORROW, CANARY, cap - IDEMIP_MLD6_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_MLD6_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_MLD6_BORROW");
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

// Every entry, in namespace order, so a new one added to Mld6Ns is added here too.
static void call_every_entry(uint8_t *w)
{
    Mld6.clear(w);
    Mld6.join(w);
    Mld6.leave(w);
    Mld6.find(w);
    Mld6.query_in(w);
    Mld6.report_in(w);
    Mld6.tick(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the instance, and the operand block is in it, so two tables share no byte at all.
// This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    Mld6.clear(work_a);
    Mld6.clear(work_b);

    IDEMIP_MLD6_IO(work_a)->group_args.group = g_group;
    IDEMIP_MLD6_IO(work_a)->query_args.max_resp_ms = 10000u;
    IDEMIP_MLD6_IO(work_b)->group_args.group = g_all_nodes;
    IDEMIP_MLD6_IO(work_b)->query_args.max_resp_ms = 1u;

    TEST_ASSERT_EQUAL_PTR(g_group, IDEMIP_MLD6_IO(work_a)->group_args.group);
    TEST_ASSERT_EQUAL_UINT32(10000u, IDEMIP_MLD6_IO(work_a)->query_args.max_resp_ms);
    TEST_ASSERT_EQUAL_PTR(g_all_nodes, IDEMIP_MLD6_IO(work_b)->group_args.group);
    TEST_ASSERT_EQUAL_UINT32(1u, IDEMIP_MLD6_IO(work_b)->query_args.max_resp_ms);
}

// A call on one borrow reaches no byte of another, clear included, which is the widest-reaching entry
// this module has.
void test_clear_on_one_borrow_leaves_the_other_untouched(void)
{
    memset(work_b + STATE_OFF, 0xC3, STATE_END - STATE_OFF);
    IDEMIP_MLD6_IO(work_b)->group_args.netif = 1u;

    Mld6.clear(work_a);

    for (size_t i = STATE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[i], "clear on one borrow wrote into another");
    }
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_MLD6_IO(work_b)->group_args.netif);
}

// --- the published map -------------------------------------------------------

// The map is public so a reader can place every region without opening the .c. The table starts where
// the context region ends, so nothing overlaps and nothing is unreachable.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_MLD6_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_MLD6_OFF_CTX >= sizeof(Mld6Io),
                             "the context starts inside the operand block");
    TEST_ASSERT_TRUE_MESSAGE(TABLE_OFF >= (size_t)IDEMIP_MLD6_OFF_CTX, "the group table starts before the context");
    TEST_ASSERT_EQUAL_size_t(TABLE_OFF + ((size_t)IDEMIP_MLD6_GROUPS << IDEMIP_MLD6_ENTRY_SHIFT), STATE_END);
    TEST_ASSERT_TRUE_MESSAGE(STATE_END <= (size_t)IDEMIP_MLD6_BORROW, "the map runs past IDEMIP_MLD6_BORROW");
}

// The table starts at the end of the context region, so a misaligned offset would misalign every
// entry behind it.
void test_every_published_offset_is_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_MLD6_OFF_CTX & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, TABLE_OFF & (IDEMIP_ALIGN - 1u));
}

// The operand block is reached at its published offset and nowhere else.
void test_the_io_macro_reaches_the_operand_block(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_MLD6_OFF_IO, (uint8_t *)IDEMIP_MLD6_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_MLD6_OFF_IO, (uint8_t *)IDEMIP_MLD6_IO(work_b));
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_MLD6_IO(work_a)->status);
}

// The table comes out of clear zeroed whatever was in it, which puts every group in the RFC 2710
// sec 5 Non-Listener state that "requires no storage in the node".
void test_clear_zeroes_the_table(void)
{
    memset(work_a, 0xFF, IDEMIP_MLD6_BORROW);
    Mld6.clear(work_a);
    for (size_t i = TABLE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00u, work_a[i], "clear left a table byte set");
    }
}

// The context comes out zeroed too, apart from the one octet mld6.h says clear leaves as the mark that
// these bytes were cleared.
void test_clear_zeroes_the_context_apart_from_the_cleared_mark(void)
{
    memset(work_a, 0xFF, IDEMIP_MLD6_BORROW);
    Mld6.clear(work_a);
    size_t set = 0;
    for (size_t i = STATE_OFF; i < TABLE_OFF; i++)
    {
        if (work_a[i] != 0x00u)
        {
            set++;
        }
    }
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1u, set, "clear must zero the context apart from the cleared mark");
}

// A zeroed entry is Non-Listener, which is the state RFC 2710 sec 5 calls "the initial state for all
// multicast addresses on all interfaces".
void test_the_zeroed_state_is_non_listener(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_MLD6_NON_LISTENER);
}

// The operand block is the caller's, so clear does not touch what the caller put there.
void test_clear_leaves_the_operand_block_alone(void)
{
    Mld6.clear(work_a);
    IDEMIP_MLD6_IO(work_a)->group_args.group = g_group;
    IDEMIP_MLD6_IO(work_a)->query_args.max_resp_ms = 1234u;
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_group, IDEMIP_MLD6_IO(work_a)->group_args.group);
    TEST_ASSERT_EQUAL_UINT32(1234u, IDEMIP_MLD6_IO(work_a)->query_args.max_resp_ms);
}

// An entry is a function of its borrow alone, so clearing twice leaves the same bytes as clearing
// once.
void test_clear_is_idempotent(void)
{
    memset(work_a, 0xFF, IDEMIP_MLD6_BORROW);
    Mld6.clear(work_a);
    memcpy(work_b, work_a, IDEMIP_MLD6_BORROW);
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(work_b + STATE_OFF, work_a + STATE_OFF, STATE_END - STATE_OFF);
}

// A borrow no one cleared is not this module's, so every entry that reads the table refuses it rather
// than reading whatever the caller's memory held.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_MLD6_IO(work_a)->group_args.group = g_group;
    IDEMIP_MLD6_IO(work_a)->query_args.group = g_group;

    Mld6.join(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_MLD6_IO(work_a)->status);
    Mld6.leave(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_MLD6_IO(work_a)->status);
    Mld6.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_MLD6_IO(work_a)->status);
    Mld6.query_in(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_MLD6_IO(work_a)->status);
    Mld6.report_in(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_MLD6_IO(work_a)->status);
    Mld6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_MLD6_IO(work_a)->status);
}

// Clearing one borrow does not make another one cleared: the mark is in the borrow, not in the module.
void test_clearing_one_borrow_does_not_ready_the_other(void)
{
    Mld6.clear(work_a);
    Mld6.tick(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_MLD6_IO(work_b)->status);
}

// --- the contract's own constants --------------------------------------------

// The index a result member carries is one octet, so the table may not be as wide as the value that
// means "no group".
void test_none_is_outside_the_table(void)
{
    TEST_ASSERT_TRUE(IDEMIP_MLD6_GROUPS < IDEMIP_MLD6_NONE);
}

// RFC 2710 sec 5 gives a group on an interface one of three states, and they fit one octet so an entry
// can hold one.
void test_the_three_node_states_are_distinct_and_one_octet(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_MLD6_NON_LISTENER);
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_MLD6_DELAYING_LISTENER);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_MLD6_IDLE_LISTENER);
    TEST_ASSERT_EQUAL_size_t(1u, sizeof(IdemIpMld6State));
}

// RFC 2710 sec 3.7: an implementation "MUST NOT send an MLD message longer than 24 octets", which is
// the Type, Code, Checksum, Maximum Response Delay and Reserved fields of sec 3 plus the 16-octet
// Multicast Address.
void test_the_message_is_twenty_four_octets(void)
{
    TEST_ASSERT_EQUAL_UINT32(24u, IDEMIP_MLD6_MSG_LEN);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_MLD6_MSG_LEN, 8u + IDEMIP_IP6_ADDR_LEN);
}

// RFC 2710 sec 3 puts every MLD message at "an IPv6 Hop Limit of 1".
void test_the_hop_limit_is_one(void)
{
    TEST_ASSERT_EQUAL_UINT32(1u, IDEMIP_MLD6_HL);
}

// sec 3.4 states Maximum Response Delay "in units of milliseconds", and every deadline here is a
// millisecond, so the tick period divides nothing.
void test_the_delays_are_milliseconds(void)
{
    TEST_ASSERT_EQUAL_UINT32(100u, IDEMIP_MLD6_TMR_INTERVAL_MS);
    TEST_ASSERT_EQUAL_UINT32(500u, IDEMIP_MLD6_JOIN_DELAY_MS);
}
