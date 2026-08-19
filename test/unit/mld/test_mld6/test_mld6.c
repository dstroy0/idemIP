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

#include "src/mld/mld6.h"

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

// =============================================================================
// The RFC 2710 membership machine
// =============================================================================
//
// RFC 2710 prints no byte vector and no worked numeric example for the node machine: sec 3 draws the
// message format, sec 4 and sec 5 state the behavior in prose and in a state diagram, and sec 7 prints
// the timer defaults. So the vectors below are (a) the addresses RFC 4291 sec 2.7.1 pre-defines and the
// scope encoding of RFC 4291 sec 2.7, and (b) the Maximum Response Delay values RFC 2710 sec 7 prints
// as defaults. Everything else is asserted as the property the text states, cited at the case.

// RFC 2710 sec 7.3 Query Response Interval, "the Maximum Response Delay inserted into the periodic
// General Queries. Default: 10000 (10 seconds)".
#define QUERY_RESPONSE_INTERVAL_MS 10000u

// RFC 2710 sec 7.8 Last Listener Query Interval, the Maximum Response Delay of the Multicast-Address-
// Specific Queries a Querier sends after a Done. "Default: 1000 (1 second)".
#define LAST_LISTENER_QUERY_INTERVAL_MS 1000u

// RFC 4291 sec 2.7.1 Solicited-Node Address FF02:0:0:0:0:1:FFXX:XXXX, two of them, and the All Routers
// Address FF02:0:0:0:0:0:0:2 that RFC 2710 sec 4 sends a Done to.
static const uint8_t g_group2[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0,    0,    0,    0,
                                                      0,    0,    0, 1, 0xFF, 0x00, 0x00, 0x02};
static const uint8_t g_group3[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0,    0,    0,    0,
                                                      0,    0,    0, 1, 0xFF, 0x0A, 0x0B, 0x0C};
static const uint8_t g_all_routers[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

// RFC 4291 sec 2.7: the low nibble of octet 1 is the 4-bit scop field. 0 is reserved and 1 is
// Interface-Local, which RFC 2710 sec 5 sends no MLD message for; E is Global scope, which it does.
static const uint8_t g_scope0[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34};
static const uint8_t g_scope1[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34};
static const uint8_t g_global[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x0E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34};

// A non-multicast address, which RFC 4291 sec 2.7 marks by the absence of 11111111 in octet 0.
static const uint8_t g_unicast[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};

static IdemIpStatus do_join(uint8_t *w, const uint8_t *grp, uint8_t netif)
{
    IDEMIP_MLD6_IO(w)->group_args.group = grp;
    IDEMIP_MLD6_IO(w)->group_args.netif = netif;
    Mld6.join(w);
    return IDEMIP_MLD6_IO(w)->status;
}

static IdemIpStatus do_leave(uint8_t *w, const uint8_t *grp, uint8_t netif)
{
    IDEMIP_MLD6_IO(w)->group_args.group = grp;
    IDEMIP_MLD6_IO(w)->group_args.netif = netif;
    Mld6.leave(w);
    return IDEMIP_MLD6_IO(w)->status;
}

static IdemIpStatus do_find(uint8_t *w, const uint8_t *grp, uint8_t netif)
{
    IDEMIP_MLD6_IO(w)->group_args.group = grp;
    IDEMIP_MLD6_IO(w)->group_args.netif = netif;
    Mld6.find(w);
    return IDEMIP_MLD6_IO(w)->status;
}

static IdemIpStatus do_report_in(uint8_t *w, const uint8_t *grp, uint8_t netif)
{
    IDEMIP_MLD6_IO(w)->group_args.group = grp;
    IDEMIP_MLD6_IO(w)->group_args.netif = netif;
    Mld6.report_in(w);
    return IDEMIP_MLD6_IO(w)->status;
}

static IdemIpStatus do_general_query(uint8_t *w, uint8_t netif, uint32_t max_resp, uint32_t now, uint32_t rand)
{
    IDEMIP_MLD6_IO(w)->query_args.group = NULL;
    IDEMIP_MLD6_IO(w)->query_args.general = 1u;
    IDEMIP_MLD6_IO(w)->query_args.netif = netif;
    IDEMIP_MLD6_IO(w)->query_args.max_resp_ms = max_resp;
    IDEMIP_MLD6_IO(w)->query_args.now_ms = now;
    IDEMIP_MLD6_IO(w)->query_args.rand = rand;
    Mld6.query_in(w);
    return IDEMIP_MLD6_IO(w)->status;
}

static IdemIpStatus do_specific_query(uint8_t *w, const uint8_t *grp, uint8_t netif, uint32_t max_resp, uint32_t now,
                                      uint32_t rand)
{
    IDEMIP_MLD6_IO(w)->query_args.group = grp;
    IDEMIP_MLD6_IO(w)->query_args.general = 0u;
    IDEMIP_MLD6_IO(w)->query_args.netif = netif;
    IDEMIP_MLD6_IO(w)->query_args.max_resp_ms = max_resp;
    IDEMIP_MLD6_IO(w)->query_args.now_ms = now;
    IDEMIP_MLD6_IO(w)->query_args.rand = rand;
    Mld6.query_in(w);
    return IDEMIP_MLD6_IO(w)->status;
}

// One sweep at that clock. Returns nonzero when it fired a timer and asked for a Report.
static int sweep(uint8_t *w, uint32_t now)
{
    IDEMIP_MLD6_IO(w)->tick_args.now_ms = now;
    Mld6.tick(w);
    return IDEMIP_MLD6_IO(w)->send_report ? 1 : 0;
}

// Sweeps until nothing is due, the way core/tick.h drives it. Returns how many Reports it asked for.
static int drain(uint8_t *w, uint32_t now)
{
    int n = 0;
    while (sweep(w, now))
    {
        n++;
    }
    return n;
}

// The deadline a group holds, read back through find.
static uint32_t deadline_of(uint8_t *w, const uint8_t *grp, uint8_t netif)
{
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(w, grp, netif));
    return IDEMIP_MLD6_IO(w)->deadline_ms;
}

static IdemIpMld6State state_of(uint8_t *w, const uint8_t *grp, uint8_t netif)
{
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(w, grp, netif));
    return IDEMIP_MLD6_IO(w)->state;
}

// --- start listening ---------------------------------------------------------

// RFC 2710 sec 4: "When a node starts listening to a multicast address on an interface, it should
// immediately transmit an unsolicited Report for that address on that interface". sec 5 draws the same
// transition as start listening "(send report, set flag, start timer)" into Delaying Listener.
void test_join_sends_a_report_sets_the_flag_and_starts_the_timer(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_report, "sec 5 start listening sends a report");
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_MLD6_IO(work_a)->last_reporter, "sec 5 start listening sets the flag");
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, IDEMIP_MLD6_IO(work_a)->state);
    TEST_ASSERT_NOT_EQUAL_UINT8(IDEMIP_MLD6_NONE, IDEMIP_MLD6_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_group, IDEMIP_MLD6_IO(work_a)->group, IDEMIP_IP6_ADDR_LEN);
}

// sec 4 repeats the initial Report "after short delays [Unsolicited Report Interval]", so the timer the
// join starts is measured from the clock in milliseconds. The clock a sweep left in the borrow is the
// one it is measured from, since Mld6GroupArgs carries none.
void test_the_join_timer_is_the_join_delay_from_the_last_sweeps_clock(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 40000u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_UINT32(40000u + IDEMIP_MLD6_JOIN_DELAY_MS, IDEMIP_MLD6_IO(work_a)->deadline_ms);
}

// sec 5: "start listening ... may occur only in the Non-Listener state", so a group already listened to
// transitions nothing and sends no second unsolicited Report.
void test_joining_a_group_twice_transitions_nothing(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    uint32_t first = IDEMIP_MLD6_IO(work_a)->deadline_ms;
    uint8_t index = IDEMIP_MLD6_IO(work_a)->index;

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_report, "a second join reported again");
    TEST_ASSERT_EQUAL_UINT8(index, IDEMIP_MLD6_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT32(first, IDEMIP_MLD6_IO(work_a)->deadline_ms);
}

// sec 5 keeps one state "with respect to any single IPv6 multicast address on any single interface", so
// the same address on two interfaces is two entries with two timers.
void test_the_same_group_on_two_interfaces_is_two_entries(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    uint8_t first = IDEMIP_MLD6_IO(work_a)->index;
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 1u));
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_report, "the second interface did not report");
    TEST_ASSERT_NOT_EQUAL_UINT8(first, IDEMIP_MLD6_IO(work_a)->index);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_leave(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(work_a, g_group, 1u));
}

// A full table is BUSY, since an entry frees when the node stops listening, and the retry after a leave
// succeeds. Reported as ERR the caller would abandon a healthy table.
void test_a_full_table_is_busy_and_the_retry_after_a_leave_succeeds(void)
{
    Mld6.clear(work_a);
    for (uint8_t i = 0; i < IDEMIP_MLD6_GROUPS; i++)
    {
        uint8_t grp[IDEMIP_IP6_ADDR_LEN];
        memcpy(grp, g_group, sizeof grp);
        grp[IDEMIP_IP6_ADDR_LEN - 1u] = (uint8_t)(0x10u + i);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, grp, 0u));
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, do_join(work_a, g_group3, 0u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_MLD6_NONE, IDEMIP_MLD6_IO(work_a)->index);

    uint8_t freed[IDEMIP_IP6_ADDR_LEN];
    memcpy(freed, g_group, sizeof freed);
    freed[IDEMIP_IP6_ADDR_LEN - 1u] = 0x10u;
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_leave(work_a, freed, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group3, 0u));
}

// RFC 4291 sec 2.7 marks a multicast address by 11111111 in octet 0, and RFC 2710 sec 3.6 carries only a
// multicast address in the Multicast Address field. A unicast address can never become one, so it is ERR
// and not BUSY.
void test_join_refuses_a_non_multicast_address(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_join(work_a, g_unicast, 0u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_MLD6_NONE, IDEMIP_MLD6_IO(work_a)->index);
    TEST_ASSERT_FALSE(IDEMIP_MLD6_IO(work_a)->send_report);
}

// An interface that does not exist can never come into range, so it is ERR and not BUSY.
void test_join_and_leave_refuse_an_interface_out_of_range(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_join(work_a, g_group, (uint8_t)IDEMIP_NETIF_COUNT));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_leave(work_a, g_group, (uint8_t)IDEMIP_NETIF_COUNT));
}

// RFC 2710 sec 5: "The link-scope all-nodes address (FF02::1) is handled as a special case. The node
// starts in Idle Listener state for that address on every interface, never transitions to another state,
// and never sends a Report or Done for that address."
void test_the_all_nodes_address_starts_idle_and_never_reports(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_all_nodes, 0u));
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_report, "sec 5 never sends a Report for FF02::1");
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, IDEMIP_MLD6_IO(work_a)->state);
    TEST_ASSERT_FALSE(IDEMIP_MLD6_IO(work_a)->last_reporter);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_leave(work_a, g_all_nodes, 0u));
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_done, "sec 5 never sends a Done for FF02::1");
}

// RFC 2710 sec 5: "MLD messages are never sent for multicast addresses whose scope is 0 (reserved) or 1
// (node-local)." RFC 4291 sec 2.7 puts the scop nibble in the low half of octet 1.
void test_scope_zero_and_node_local_groups_never_report(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_scope0, 0u));
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_report, "sec 5 sends nothing for scope 0");
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, IDEMIP_MLD6_IO(work_a)->state);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_scope1, 0u));
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_report, "sec 5 sends nothing for scope 1");
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, IDEMIP_MLD6_IO(work_a)->state);
}

// sec 5: "MLD messages ARE sent for multicast addresses whose scope is 2 (link-local), including
// Solicited-Node multicast addresses [ADDR-ARCH], except for the link-scope, all-nodes address."
// Everything above scope 1 reports, the RFC 4291 sec 2.7 Global scope included.
void test_link_local_and_global_groups_do_report(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_report, "a solicited-node address must report");
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_global, 0u));
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_report, "a global-scope group must report");
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_all_routers, 0u));
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_report, "FF02::2 is not the FF02::1 special case");
}

// --- stop listening ----------------------------------------------------------

// RFC 2710 sec 4: a node ceasing to listen "SHOULD send a single Done message to the link-scope
// all-routers multicast address (FF02::2)". sec 5 draws it as stop listening "(send done if flag set)"
// into Non-Listener, which "requires no storage in the node", so the entry frees.
void test_leave_sends_a_done_when_the_flag_is_set_and_frees_the_entry(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_leave(work_a, g_group, 0u));
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_done, "sec 5 sends done when the flag is set");
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_NON_LISTENER, IDEMIP_MLD6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_group, IDEMIP_MLD6_IO(work_a)->group, IDEMIP_IP6_ADDR_LEN);

    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, g_group, 0u));
}

// sec 4: "If the node's most recent Report message was suppressed by hearing another Report message, it
// MAY send nothing, as it is highly likely that there is another listener for that address still present
// on the same link." sec 5 makes that "send done if flag set" over a flag report received cleared.
void test_leave_after_a_suppressed_report_sends_no_done(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_report_in(work_a, g_group, 0u));
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_MLD6_IO(work_a)->last_reporter, "sec 5 report received clears the flag");

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_leave(work_a, g_group, 0u));
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_MLD6_IO(work_a)->send_done, "a suppressed report must send no done");
}

// sec 5 puts stop listening "only in the Delaying Listener and Idle Listener states", so a group in
// Non-Listener state holds nothing to stop. No retry brings the entry into being, so it is ERR.
void test_leaving_a_group_that_is_not_listened_to_is_refused(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_leave(work_a, g_group, 0u));
    TEST_ASSERT_FALSE(IDEMIP_MLD6_IO(work_a)->send_done);

    // Listened to on interface 0 only, so interface 1 is still Non-Listener for it.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_leave(work_a, g_group, 1u));
}

// --- find --------------------------------------------------------------------

// sec 5 holds one state per address per interface, and find reports it with the running timer.
void test_find_reports_the_state_and_the_deadline(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 1000u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, IDEMIP_MLD6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(1000u + IDEMIP_MLD6_JOIN_DELAY_MS, IDEMIP_MLD6_IO(work_a)->deadline_ms);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_MLD6_IO(work_a)->netif);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_group, IDEMIP_MLD6_IO(work_a)->group, IDEMIP_IP6_ADDR_LEN);
}

// A group in the sec 5 Non-Listener state holds nothing, so find reports ERR and names no entry.
void test_find_on_a_group_that_is_not_listened_to_is_refused(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_MLD6_NONE, IDEMIP_MLD6_IO(work_a)->index);
    TEST_ASSERT_NULL(IDEMIP_MLD6_IO(work_a)->group);
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_NON_LISTENER, IDEMIP_MLD6_IO(work_a)->state);
}

// --- query received ----------------------------------------------------------

// RFC 2710 sec 4: on a General Query a node "sets a delay timer for each multicast address to which it is
// listening on the interface from which it received the Query", each within [0, Maximum Response Delay].
void test_a_general_query_arms_every_listened_group_on_that_interface(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group2, 0u));
    TEST_ASSERT_EQUAL_INT(2, drain(work_a, 5000u)); // one Report per join, so both fall due at once

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group3, 0u));
    TEST_ASSERT_EQUAL_INT(1, drain(work_a, 6000u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_group2, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_group3, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_a, 0u, QUERY_RESPONSE_INTERVAL_MS, 6000u, 0xC0FFEEu));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group2, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group3, 0u));
}

// sec 4 sets the timers only for the addresses listened to "on the interface from which it received the
// Query", so another interface's groups keep the state they had.
void test_a_general_query_does_not_reach_another_interface(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 1u));
    TEST_ASSERT_EQUAL_INT(2, drain(work_a, 5000u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_a, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x1234u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_group, 1u),
                                  "a General Query armed a group on another interface");
}

// sec 4 sets a timer for each listened address "EXCLUDING the link-scope all-nodes address and any
// multicast addresses of scope 0 (reserved) or 1 (node-local)".
void test_a_general_query_excludes_all_nodes_and_scope_zero_and_one(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_all_nodes, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_scope0, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_scope1, 0u));
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 5000u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_a, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0xABCDEFu));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_all_nodes, 0u),
                                  "sec 4 excludes the link-scope all-nodes address");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_scope0, 0u),
                                  "sec 4 excludes scope 0");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_scope1, 0u),
                                  "sec 4 excludes scope 1");
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 20000u));
}

// sec 4: "Each timer is set to a different random value, using the highest clock granularity available on
// the node, selected from the range [0, Maximum Response Delay]". Three groups, three distinct deadlines.
void test_a_general_query_sets_a_different_value_per_group(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group2, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group3, 0u));
    TEST_ASSERT_EQUAL_INT(3, drain(work_a, 5000u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_a, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x5EEDu));
    uint32_t d1 = deadline_of(work_a, g_group, 0u);
    uint32_t d2 = deadline_of(work_a, g_group2, 0u);
    uint32_t d3 = deadline_of(work_a, g_group3, 0u);
    TEST_ASSERT_TRUE_MESSAGE(d1 != d2 && d2 != d3 && d1 != d3, "sec 4 sets each timer to a different value");
}

// "A different random value" per group has to hold for every random word, not one lucky one. Three draws
// from [0, 10000] collide about three times in ten thousand if they are independent, so a run of 512
// words that collides more than 16 times means the draws are sharing a value rather than drawing one.
void test_the_per_group_draws_do_not_share_a_value(void)
{
    int collided = 0;
    for (uint32_t r = 1u; r <= 512u; r++)
    {
        Mld6.clear(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group2, 0u));
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group3, 0u));
        TEST_ASSERT_EQUAL_INT(3, drain(work_a, 5000u));

        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_a, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, r * 2654435761u));
        uint32_t d1 = deadline_of(work_a, g_group, 0u);
        uint32_t d2 = deadline_of(work_a, g_group2, 0u);
        uint32_t d3 = deadline_of(work_a, g_group3, 0u);
        if (d1 == d2 || d2 == d3 || d1 == d3)
        {
            collided++;
        }
    }
    TEST_ASSERT_LESS_OR_EQUAL_INT_MESSAGE(16, collided, "sec 4 needs a different random value per group");
}

// sec 4 selects each delay "from the range [0, Maximum Response Delay]", so the deadline never lands
// before the clock and never past it by more than the sec 7.3 default the Query carried. Swept over many
// random words, since the RFC prints no draw to reproduce.
void test_every_drawn_delay_lies_within_the_maximum_response_delay(void)
{
    for (uint32_t r = 0u; r < 4000u; r += 37u)
    {
        Mld6.clear(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
        TEST_ASSERT_EQUAL_INT(1, drain(work_a, 5000u));
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_a, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, r));
        uint32_t delay = deadline_of(work_a, g_group, 0u) - 5000u;
        TEST_ASSERT_TRUE_MESSAGE(delay <= QUERY_RESPONSE_INTERVAL_MS, "a drawn delay ran past Maximum Response Delay");
    }
}

// The same sweep over the sec 7.8 Last Listener Query Interval default, and over the range's own edges:
// a bound of 0 draws only 0, and a bound of 1 draws 0 or 1.
void test_the_drawn_delay_holds_at_the_range_edges(void)
{
    for (uint32_t r = 0u; r < 2000u; r += 13u)
    {
        Mld6.clear(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
        TEST_ASSERT_EQUAL_INT(1, drain(work_a, 8000u));

        TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                              do_specific_query(work_a, g_group, 0u, LAST_LISTENER_QUERY_INTERVAL_MS, 8000u, r));
        TEST_ASSERT_TRUE(deadline_of(work_a, g_group, 0u) - 8000u <= LAST_LISTENER_QUERY_INTERVAL_MS);

        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_specific_query(work_a, g_group, 0u, 1u, 8000u, r));
        TEST_ASSERT_TRUE(deadline_of(work_a, g_group, 0u) - 8000u <= 1u);

        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_specific_query(work_a, g_group, 0u, 0u, 8000u, r));
        TEST_ASSERT_EQUAL_UINT32(8000u, deadline_of(work_a, g_group, 0u));
    }
}

// sec 4: "If a timer for any address is already running, it is reset to the new random value only if the
// requested Maximum Response Delay is less than the remaining value of the running timer." A larger
// requested delay therefore leaves the running timer exactly where it was.
void test_a_larger_requested_delay_does_not_reset_a_running_timer(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(1, drain(work_a, 5000u));

    // A short Query starts the timer, 1000 ms of headroom at most.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          do_specific_query(work_a, g_group, 0u, LAST_LISTENER_QUERY_INTERVAL_MS, 5000u, 0x99u));
    uint32_t running = deadline_of(work_a, g_group, 0u);

    // A Query asking for 10000 ms cannot be less than what remains of a 1000 ms timer.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          do_specific_query(work_a, g_group, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x7777u));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(running, deadline_of(work_a, g_group, 0u),
                                     "sec 4 resets only when the requested delay is less than the remaining value");
}

// The other half of the same sentence: a requested delay less than what remains does reset the timer, and
// the new deadline is inside the shorter range.
void test_a_smaller_requested_delay_resets_a_running_timer(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(1, drain(work_a, 5000u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          do_specific_query(work_a, g_group, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x3333u));
    uint32_t before = deadline_of(work_a, g_group, 0u);
    TEST_ASSERT_TRUE_MESSAGE(before - 5000u > LAST_LISTENER_QUERY_INTERVAL_MS,
                             "pick a random word whose 10000 ms draw exceeds 1000 ms");

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          do_specific_query(work_a, g_group, 0u, LAST_LISTENER_QUERY_INTERVAL_MS, 5000u, 0x4444u));
    uint32_t after = deadline_of(work_a, g_group, 0u);
    TEST_ASSERT_TRUE_MESSAGE(after != before, "sec 4 must reset a timer a shorter delay undercuts");
    TEST_ASSERT_TRUE(after - 5000u <= LAST_LISTENER_QUERY_INTERVAL_MS);
}

// sec 4: "If the Query packet specifies a Maximum Response Delay of zero, the timer is effectively set to
// zero, and the action specified below for timer expiration is performed immediately." The deadline lands
// on the clock the Query carried, so the sweep that follows in the same tick pass fires it.
void test_a_maximum_response_delay_of_zero_is_due_at_once(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(1, drain(work_a, 5000u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_specific_query(work_a, g_group, 0u, 0u, 5000u, 0xDEADBEEFu));
    TEST_ASSERT_EQUAL_UINT32(5000u, deadline_of(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group, 0u));

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, drain(work_a, 5000u), "a zero Maximum Response Delay must fire at that clock");
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_group, 0u));
}

// A zero Maximum Response Delay overrides the reset rule too: nothing running can have less than zero
// remaining, so every applicable timer collapses onto the clock.
void test_a_zero_maximum_response_delay_overrides_a_running_timer(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group2, 0u));
    TEST_ASSERT_EQUAL_INT(2, drain(work_a, 5000u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_a, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x2468u));
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 5000u)); // both timers are still running

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_a, 0u, 0u, 5000u, 0x2468u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, drain(work_a, 5000u), "a zero Maximum Response Delay must collapse both timers");
}

// sec 4 on a Multicast-Address-Specific Query: "if it is listening to the queried Multicast Address on
// the interface from which the Query was received, it sets a delay timer for that address". Only that one.
void test_a_specific_query_arms_only_the_queried_group(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group2, 0u));
    TEST_ASSERT_EQUAL_INT(2, drain(work_a, 5000u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          do_specific_query(work_a, g_group, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x8181u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_group2, 0u),
                                  "a Multicast-Address-Specific Query armed a group it did not name");
}

// sec 5: "Queries are ignored for addresses in the Non-Listener state." No retry brings the address into
// a listening state, so it is ERR and not BUSY.
void test_a_specific_query_for_a_group_not_listened_to_is_refused(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR,
                          do_specific_query(work_a, g_group, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x11u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_MLD6_NONE, IDEMIP_MLD6_IO(work_a)->index);

    // Listened to on interface 0, queried on interface 1: sec 4 keys the timer to the interface the Query
    // arrived on, so interface 1 is Non-Listener for it.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR,
                          do_specific_query(work_a, g_group, 1u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x11u));
}

// A General Query is valid on an interface with nothing listened to: sec 5 ignores it per address, which
// leaves nothing to do rather than a fault.
void test_a_general_query_with_nothing_listened_to_is_ok(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_a, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x1u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_MLD6_NONE, IDEMIP_MLD6_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 60000u));
}

// A Multicast-Address-Specific Query names a group, so a null one is a bad argument. An interface out of
// range is one too.
void test_query_in_refuses_a_bad_argument(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_specific_query(work_a, NULL, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x1u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_general_query(work_a, (uint8_t)IDEMIP_NETIF_COUNT,
                                                       QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x1u));
}

// sec 5's FF02::1 special case holds against a Query naming it directly, not only against a General Query.
void test_a_specific_query_for_all_nodes_arms_nothing(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_all_nodes, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          do_specific_query(work_a, g_all_nodes, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0x22u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_all_nodes, 0u),
                                  "sec 5 never transitions FF02::1 to another state");
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 60000u));
}

// --- report received ---------------------------------------------------------

// sec 4: "If a node receives another node's Report from an interface for a multicast address while it has
// a timer running for that same address on that interface, it stops its timer and does not send a Report
// for that address, thus suppressing duplicate reports on the link." sec 5: "(stop timer, clear flag)".
void test_a_report_stops_the_timer_and_clears_the_flag(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_report_in(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, IDEMIP_MLD6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_MLD6_IO(work_a)->deadline_ms);
    TEST_ASSERT_FALSE(IDEMIP_MLD6_IO(work_a)->last_reporter);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, drain(work_a, 60000u), "a suppressed timer must never fire");
}

// sec 5: a Report "is ignored in the Non-Listener or Idle Listener state", so one arriving with no timer
// running changes nothing, the flag included.
void test_a_report_in_idle_listener_changes_nothing(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(1, drain(work_a, 5000u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_group, 0u));
    TEST_ASSERT_TRUE(IDEMIP_MLD6_IO(work_a)->last_reporter);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_report_in(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, IDEMIP_MLD6_IO(work_a)->state);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_MLD6_IO(work_a)->last_reporter,
                             "sec 5 ignores a report in Idle Listener, so the flag stands");
}

// sec 5: a Report "applies only to the address identified in the Multicast Address field of the Report, on
// the interface from which the Report is received", so it suppresses nothing on another interface.
void test_a_report_on_another_interface_suppresses_nothing(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_report_in(work_a, g_group, 1u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group, 0u),
                                  "a Report on interface 1 suppressed interface 0's timer");
}

// A Report for an address in the sec 5 Non-Listener state holds no entry to suppress, and no retry
// creates one.
void test_a_report_for_a_group_not_listened_to_is_refused(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_report_in(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_MLD6_NONE, IDEMIP_MLD6_IO(work_a)->index);
}

// --- timer expired -----------------------------------------------------------

// sec 4: "If a node's timer for a particular multicast address on a particular interface expires, the node
// transmits a Report to that address via that interface". sec 5: timer expired "(send report, set flag)"
// into Idle Listener.
void test_an_expiring_timer_sends_a_report_and_sets_the_flag(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 1000u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_report_in(work_a, g_group, 0u)); // clears the flag the join set
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          do_specific_query(work_a, g_group, 0u, LAST_LISTENER_QUERY_INTERVAL_MS, 1000u, 0x55u));

    TEST_ASSERT_EQUAL_INT(1, sweep(work_a, 1000u + LAST_LISTENER_QUERY_INTERVAL_MS));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_group, IDEMIP_MLD6_IO(work_a)->group, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_MLD6_IO(work_a)->netif);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_MLD6_IO(work_a)->last_reporter, "sec 5 timer expired sets the flag");
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, IDEMIP_MLD6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_MLD6_IO(work_a)->expired);
}

// sec 5 puts timer expired "only in the Delaying Listener state", and only once the deadline has passed.
void test_a_sweep_before_the_deadline_fires_nothing(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 1000u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));

    TEST_ASSERT_EQUAL_INT(0, sweep(work_a, 1000u + IDEMIP_MLD6_JOIN_DELAY_MS - 1u));
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_MLD6_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group, 0u));

    TEST_ASSERT_EQUAL_INT(1, sweep(work_a, 1000u + IDEMIP_MLD6_JOIN_DELAY_MS));
}

// Mld6Io names one group and carries one send_report, so a sweep fires the first due timer and counts every
// timer due at that clock into expired. The caller sweeps again while send_report is set.
void test_a_sweep_counts_every_due_timer_and_fires_one_per_call(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group2, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group3, 0u));

    TEST_ASSERT_EQUAL_INT(1, sweep(work_a, IDEMIP_MLD6_JOIN_DELAY_MS));
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_MLD6_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT(1, sweep(work_a, IDEMIP_MLD6_JOIN_DELAY_MS));
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_MLD6_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT(1, sweep(work_a, IDEMIP_MLD6_JOIN_DELAY_MS));
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_MLD6_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT(0, sweep(work_a, IDEMIP_MLD6_JOIN_DELAY_MS));
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_MLD6_IO(work_a)->expired);
}

// Nothing here blocks and nothing here waits: a sweep with no timer due is OK with nothing to send, not
// BUSY, since there is no resource to come back for.
void test_a_sweep_with_nothing_due_is_ok_and_not_busy(void)
{
    Mld6.clear(work_a);
    Mld6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_MLD6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_MLD6_IO(work_a)->expired);
    TEST_ASSERT_FALSE(IDEMIP_MLD6_IO(work_a)->send_report);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_MLD6_NONE, IDEMIP_MLD6_IO(work_a)->index);
    TEST_ASSERT_NULL(IDEMIP_MLD6_IO(work_a)->group);
}

// sec 3.4 states the delay in milliseconds and the clock compared against is a 32-bit millisecond clock,
// which wraps. A deadline the wrap carries past zero is still due at the right moment and not before.
void test_a_deadline_survives_the_millisecond_clocks_wrap(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 0xFFFFFF00u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_UINT32(0xFFFFFF00u + IDEMIP_MLD6_JOIN_DELAY_MS, IDEMIP_MLD6_IO(work_a)->deadline_ms);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, sweep(work_a, 0xFFFFFFF0u), "a wrapped deadline fired before its time");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, sweep(work_a, 0x00000100u), "a wrapped deadline never came due");
}

// --- the whole sec 5 walk ----------------------------------------------------

// Non-Listener to Delaying Listener to Idle Listener and back, over the five events sec 5 names.
void test_the_state_diagram_walks_end_to_end(void)
{
    Mld6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(0, drain(work_a, 1000u));

    // start listening (send report, set flag, start timer)
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group, 0u));

    // timer expired (send report, set flag) into Idle Listener
    TEST_ASSERT_EQUAL_INT(1, sweep(work_a, 1000u + IDEMIP_MLD6_JOIN_DELAY_MS));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_group, 0u));

    // query received (start timer) back into Delaying Listener
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          do_general_query(work_a, 0u, QUERY_RESPONSE_INTERVAL_MS, 2000u, 0xFACEu));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_a, g_group, 0u));

    // report received (stop timer, clear flag) into Idle Listener
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_report_in(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_group, 0u));

    // stop listening (send done if flag set) into Non-Listener, with the flag cleared
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_leave(work_a, g_group, 0u));
    TEST_ASSERT_FALSE(IDEMIP_MLD6_IO(work_a)->send_done);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, g_group, 0u));
}

// An entry is a function of its borrow alone, so the same membership machine driven on two borrows keeps
// two answers. This is the determinism the design is named for.
void test_the_machine_on_two_borrows_stays_independent(void)
{
    Mld6.clear(work_a);
    Mld6.clear(work_b);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_b, g_group2, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, g_group2, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_b, g_group, 0u));

    // Draining a leaves b's timer exactly where it was.
    TEST_ASSERT_EQUAL_INT(1, drain(work_a, IDEMIP_MLD6_JOIN_DELAY_MS));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, state_of(work_b, g_group2, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_IDLE_LISTENER, state_of(work_a, g_group, 0u));
}

// The same call on the same bytes repeats: two borrows given the same Query and the same random word draw
// the same deadline.
void test_the_same_query_on_two_identical_borrows_draws_the_same_delay(void)
{
    Mld6.clear(work_a);
    Mld6.clear(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_a, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_join(work_b, g_group, 0u));
    TEST_ASSERT_EQUAL_INT(1, drain(work_a, 5000u));
    TEST_ASSERT_EQUAL_INT(1, drain(work_b, 5000u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_a, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0xBEEFu));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_general_query(work_b, 0u, QUERY_RESPONSE_INTERVAL_MS, 5000u, 0xBEEFu));
    TEST_ASSERT_EQUAL_UINT32(deadline_of(work_a, g_group, 0u), deadline_of(work_b, g_group, 0u));
}
