// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for igmp, modeled on test_phy. It tests the CONTRACT and nothing else:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_IGMP_BORROW is intact after every case
//   5. the published offset map is ordered, aligned, and does not overlap
//   6. clear zeroes the context and the table, and a borrow no one cleared is refused
//
// No case here asserts what an entry reports once its RFC 2236 logic exists, so none of them has to be
// inverted when it does.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/igmp/igmp.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each so a
// write past the map is visible.
#define CANARY 0x5Au
static _Alignas(IDEMIP_ALIGN) uint8_t work_a[IDEMIP_IGMP_BORROW + 16];
static _Alignas(IDEMIP_ALIGN) uint8_t work_b[IDEMIP_IGMP_BORROW + 16];

// The span clear owns: the context and the group table.
#define STATE_OFF ((size_t)IDEMIP_IGMP_OFF_CTX)
#define TABLE_OFF ((size_t)IDEMIP_IGMP_OFF_GROUPS)
#define STATE_END ((size_t)IDEMIP_IGMP_OFF_END)

// Two class D addresses (RFC 1112 sec 4), and the all-systems group RFC 2236 sec 3 excludes from the
// memberships a host reports.
#define GROUP_A 0xE0000009u
#define GROUP_B 0xEFFFFFFAu

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IGMP_BORROW, CANARY, cap - IDEMIP_IGMP_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IGMP_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IGMP_BORROW");
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

// Every entry, in namespace order, so a new one added to IgmpNs is added here too.
static void call_every_entry(uint8_t *w)
{
    Igmp.clear(w);
    Igmp.join(w);
    Igmp.leave(w);
    Igmp.find(w);
    Igmp.query_in(w);
    Igmp.report_in(w);
    Igmp.tick(w);
}

static void arm_group(uint8_t *w, uint32_t group, uint8_t netif)
{
    IDEMIP_IGMP_IO(w)->group_args.group = group;
    IDEMIP_IGMP_IO(w)->group_args.netif = netif;
    IDEMIP_IGMP_IO(w)->group_args.rand = 0x1234u;
    IDEMIP_IGMP_IO(w)->group_args.now_ms = 1000u;
}

// --- the borrow --------------------------------------------------------------

static void join_at(uint8_t *w, uint32_t group, uint8_t netif, uint32_t now_ms, uint32_t rand)
{
    IDEMIP_IGMP_IO(w)->group_args.group = group;
    IDEMIP_IGMP_IO(w)->group_args.netif = netif;
    IDEMIP_IGMP_IO(w)->group_args.now_ms = now_ms;
    IDEMIP_IGMP_IO(w)->group_args.rand = rand;
    Igmp.join(w);
}

static void join_ok(uint8_t *w, uint32_t group, uint8_t netif, uint32_t now_ms, uint32_t rand)
{
    join_at(w, group, netif, now_ms, rand);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_IGMP_IO(w)->status, "a join of a free group was refused");
}

static void leave_at(uint8_t *w, uint32_t group, uint8_t netif)
{
    IDEMIP_IGMP_IO(w)->group_args.group = group;
    IDEMIP_IGMP_IO(w)->group_args.netif = netif;
    Igmp.leave(w);
}

typedef struct
{
    uint8_t *w;
    uint8_t netif;
    idemip_bool general;
    uint32_t group;
    uint32_t max_resp_ms;
    uint32_t now_ms;
    uint32_t rand;
    idemip_bool v1;
} QueryAtArgs;

static void query_at_ctx(const QueryAtArgs *args)
{
    IDEMIP_IGMP_IO(args->w)->query_args.netif = args->netif;
    IDEMIP_IGMP_IO(args->w)->query_args.general = args->general;
    IDEMIP_IGMP_IO(args->w)->query_args.group = args->group;
    IDEMIP_IGMP_IO(args->w)->query_args.max_resp_ms = args->max_resp_ms;
    IDEMIP_IGMP_IO(args->w)->query_args.now_ms = args->now_ms;
    IDEMIP_IGMP_IO(args->w)->query_args.rand = args->rand;
    IDEMIP_IGMP_IO(args->w)->query_args.v1 = args->v1;
    Igmp.query_in(args->w);
}

#define query_at(...) IDEMIP_CALL(query_at_ctx, QueryAtArgs, __VA_ARGS__)

static void report_at(uint8_t *w, uint32_t group, uint8_t netif)
{
    IDEMIP_IGMP_IO(w)->report_args.group = group;
    IDEMIP_IGMP_IO(w)->report_args.netif = netif;
    Igmp.report_in(w);
}

static void tick_at(uint8_t *w, uint32_t now_ms)
{
    IDEMIP_IGMP_IO(w)->tick_args.now_ms = now_ms;
    Igmp.tick(w);
}

// find, with the entry it reported left in the operand block for the caller to read.
static void find_at(uint8_t *w, uint32_t group, uint8_t netif)
{
    IDEMIP_IGMP_IO(w)->group_args.group = group;
    IDEMIP_IGMP_IO(w)->group_args.netif = netif;
    Igmp.find(w);
}

static uint32_t deadline_of(uint8_t *w, uint32_t group, uint8_t netif)
{
    find_at(w, group, netif);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_IGMP_IO(w)->status, "find could not reach a joined group");
    return IDEMIP_IGMP_IO(w)->deadline_ms;
}

static IdemIpIgmpState state_of(uint8_t *w, uint32_t group, uint8_t netif)
{
    find_at(w, group, netif);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_IGMP_IO(w)->status, "find could not reach a joined group");
    return IDEMIP_IGMP_IO(w)->state;
}

// Drive a Delaying Member to Idle Member by letting its report delay timer fire.
static void run_timer_out(uint8_t *w, uint32_t now_ms)
{
    tick_at(w, now_ms);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(w)->status);
}

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the instance, and the group table is in it, so two tables share no byte at all. This
// is the property the whole storage model rests on: RFC 2236 sec 6 holds a state "with respect to any
// single IP multicast group on any single network interface", and each borrow holds its own.
void test_two_borrows_share_no_byte(void)
{
    Igmp.clear(work_a);
    Igmp.clear(work_b);

    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    join_ok(work_b, GROUP_B, 1u, 0u, 0u);

    // Each borrow holds only its own membership.
    find_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    find_at(work_a, GROUP_B, 1u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status, "b's membership reached a's table");
    find_at(work_b, GROUP_B, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_b)->status);
    find_at(work_b, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_b)->status, "a's membership reached b's table");

    // And a leave on one leaves the other where it was.
    leave_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    find_at(work_b, GROUP_B, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_b)->status);
}

// A call on one borrow reaches no byte of another, clear included, which is the widest-reaching entry
// this module has.
void test_clear_on_one_borrow_leaves_the_other_untouched(void)
{
    memset(work_b + STATE_OFF, 0xC3, STATE_END - STATE_OFF);
    IDEMIP_IGMP_IO(work_b)->group_args.group = GROUP_B;

    Igmp.clear(work_a);

    for (size_t i = STATE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[i], "clear on one borrow wrote into another");
    }
    TEST_ASSERT_EQUAL_HEX32(GROUP_B, IDEMIP_IGMP_IO(work_b)->group_args.group);
}

// Every entry reads the context, so a call on one borrow cannot make another one's calls answer
// differently.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    Igmp.clear(work_a);
    Igmp.clear(work_b);
    join_ok(work_a, GROUP_A, 0u, 1000u, 0x40000000u);

    find_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    const uint8_t index = IDEMIP_IGMP_IO(work_a)->index;
    const uint32_t group = IDEMIP_IGMP_IO(work_a)->group;
    const uint32_t deadline = IDEMIP_IGMP_IO(work_a)->deadline_ms;
    const IdemIpIgmpState state = IDEMIP_IGMP_IO(work_a)->state;

    // A whole join and a whole tick on the other borrow, both of which write its table and context.
    join_ok(work_b, GROUP_B, 1u, 0u, 0u);
    tick_at(work_b, 100000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_b)->status);

    find_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(index, IDEMIP_IGMP_IO(work_a)->index);
    TEST_ASSERT_EQUAL_HEX32(group, IDEMIP_IGMP_IO(work_a)->group);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(deadline, IDEMIP_IGMP_IO(work_a)->deadline_ms,
                                     "a tick on another borrow moved this one's timer");
    TEST_ASSERT_EQUAL_INT(state, IDEMIP_IGMP_IO(work_a)->state);
}

// RFC 2236 sec 6 binds "send leave" to the "leave group" event, which "may occur only in the Delaying
// Member and Idle Member states", and sec 3 makes the Leave Group message the report of an actual
// departure: "When a Querier receives a Leave Group message for a group that has group members on the
// reception interface, it sends [Last Member Query Count] Group-Specific Queries". All seven entries
// share one operand block, so a flag left standing from an earlier leave would be read alongside a
// later call's group.
void test_no_entry_leaves_a_stale_send_leave_behind(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    join_ok(work_a, GROUP_B, 0u, 0u, 0u);

    leave_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->send_leave);
    TEST_ASSERT_EQUAL_HEX32(GROUP_A, IDEMIP_IGMP_IO(work_a)->group);

    // A find on the surviving group rewrites io->group; the flag must not still name it.
    find_at(work_a, GROUP_B, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(GROUP_B, IDEMIP_IGMP_IO(work_a)->group);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_leave,
                              "a find must not carry an earlier leave's flag onto its own group");

    // The same through a tick that reports the surviving group's unsolicited report.
    leave_at(work_a, GROUP_B, 0u);
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    join_ok(work_a, GROUP_B, 0u, 0u, 0u);
    leave_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->send_leave);
    tick_at(work_a, 100000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_report, "the surviving group's timer expired");
    TEST_ASSERT_EQUAL_HEX32(GROUP_B, IDEMIP_IGMP_IO(work_a)->group);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_leave,
                              "a tick must not carry an earlier leave's flag onto its own group");

    // And a query does not either.
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    join_ok(work_a, GROUP_B, 0u, 0u, 0u);
    leave_at(work_a, GROUP_A, 0u);
    query_at(work_a, 0u, IDEMIP_TRUE, 0u, 10000u, 0u, 0u, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IGMP_IO(work_a)->send_leave);
}

// --- the published map -------------------------------------------------------

// The map is public so a reader can place every region without opening the .c. The table starts where
// the context region ends, so nothing overlaps and nothing is unreachable.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IGMP_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE(STATE_OFF >= sizeof(IgmpIo), "the context starts inside the operand block");
    TEST_ASSERT_TRUE_MESSAGE(TABLE_OFF >= STATE_OFF, "the group table starts before the context");
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_IGMP_CTX_BYTES, TABLE_OFF);
    TEST_ASSERT_EQUAL_size_t(TABLE_OFF + ((size_t)IDEMIP_IGMP_GROUPS << IDEMIP_IGMP_ENTRY_SHIFT), STATE_END);
    TEST_ASSERT_TRUE_MESSAGE(STATE_END <= (size_t)IDEMIP_IGMP_BORROW, "the map runs past IDEMIP_IGMP_BORROW");
}

// The table starts at the end of the context region, so a misaligned offset would misalign every entry
// behind it.
void test_every_published_offset_is_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, STATE_OFF & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, TABLE_OFF & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_TRUE_MESSAGE((1u << IDEMIP_IGMP_ENTRY_SHIFT) >= IDEMIP_ALIGN,
                             "an entry narrower than IDEMIP_ALIGN misaligns the entry behind it");
}

// The operand block is reached at its published offset and nowhere else.
void test_the_io_macro_reaches_the_operand_block(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_IGMP_OFF_IO, (uint8_t *)IDEMIP_IGMP_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_IGMP_OFF_IO, (uint8_t *)IDEMIP_IGMP_IO(work_b));
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Igmp.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
}

// The table comes out of clear zeroed whatever was in it, which puts every group in the RFC 2236 sec 6
// Non-Member state that "requires no storage in the host".
void test_clear_zeroes_the_table(void)
{
    memset(work_a, 0xFF, IDEMIP_IGMP_BORROW);
    Igmp.clear(work_a);
    for (size_t i = TABLE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00u, work_a[i], "clear left a table byte set");
    }
}

// The context comes out zeroed too, apart from the mark igmp.h says clear leaves as what tells a
// cleared borrow from one no one cleared.
void test_clear_zeroes_the_context_apart_from_the_mark(void)
{
    memset(work_a, 0xFF, IDEMIP_IGMP_BORROW);
    Igmp.clear(work_a);
    size_t set = 0;
    for (size_t i = STATE_OFF; i < TABLE_OFF; i++)
    {
        if (work_a[i] != 0x00u)
        {
            set++;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(set >= 1u, "clear left no mark, so an uncleared borrow cannot be told apart");
    TEST_ASSERT_TRUE_MESSAGE(set <= IDEMIP_ALIGN, "clear must zero the context apart from the mark");
}

// Whatever the region held, clear takes it to one state, so no stale membership survives.
void test_clear_takes_the_regions_to_one_state(void)
{
    memset(work_a, 0x00, IDEMIP_IGMP_BORROW);
    memset(work_b, 0xFF, IDEMIP_IGMP_BORROW);
    Igmp.clear(work_a);
    Igmp.clear(work_b);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(work_a + STATE_OFF, work_b + STATE_OFF, STATE_END - STATE_OFF);
}

// The operand block is the caller's, so clear does not touch what the caller put there.
void test_clear_leaves_the_operand_block_alone(void)
{
    Igmp.clear(work_a);
    arm_group(work_a, GROUP_A, 0u);
    Igmp.clear(work_a);
    TEST_ASSERT_EQUAL_HEX32(GROUP_A, IDEMIP_IGMP_IO(work_a)->group_args.group);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_IGMP_IO(work_a)->group_args.now_ms);
}

// An entry is a function of its borrow alone, so clearing twice leaves the same bytes as clearing once.
void test_clear_is_idempotent(void)
{
    memset(work_a, 0xFF, IDEMIP_IGMP_BORROW);
    Igmp.clear(work_a);
    memcpy(work_b, work_a, IDEMIP_IGMP_BORROW);
    Igmp.clear(work_a);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(work_b + STATE_OFF, work_a + STATE_OFF, STATE_END - STATE_OFF);
}

// A borrow no one cleared is not this module's, so every entry that reads the table refuses it rather
// than reading whatever the caller's memory held.
void test_an_uncleared_borrow_is_refused(void)
{
    arm_group(work_a, GROUP_A, 0u);
    IDEMIP_IGMP_IO(work_a)->query_args.group = GROUP_A;
    IDEMIP_IGMP_IO(work_a)->report_args.group = GROUP_A;

    Igmp.join(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
    Igmp.leave(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
    Igmp.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
    Igmp.query_in(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
    Igmp.report_in(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
    Igmp.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
}

// Clearing one borrow does not make another one cleared: the mark is in the borrow, not in the module.
void test_clearing_one_borrow_does_not_ready_the_other(void)
{
    Igmp.clear(work_a);
    Igmp.tick(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_b)->status);
}

// A call that found nothing says so with the published value that names no entry, not with entry zero.
void test_a_refused_call_reports_no_entry(void)
{
    Igmp.clear(work_a);
    arm_group(work_a, 0u, 0u); // not a class D address, so no entry can hold it
    Igmp.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IGMP_NONE, IDEMIP_IGMP_IO(work_a)->index);
}

// RFC 1112 sec 4: "Host groups are identified by class D IP addresses, i.e., those with '1110' as their
// high-order four bits", so nothing else can be joined.
void test_a_membership_needs_a_class_d_address(void)
{
    Igmp.clear(work_a);
    arm_group(work_a, 0x0A000001u, 0u); // 10.0.0.1, a unicast address
    Igmp.join(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
}

// RFC 2236 sec 3 sets delay timers "for each group (excluding the all-systems group) of which it is a
// member", and RFC 1112 Appendix I is stronger still: "a report delay timer is never set for a host's
// membership in the all-hosts group (224.0.0.1), and that membership is never reported."
void test_the_all_systems_group_is_never_a_membership(void)
{
    Igmp.clear(work_a);
    arm_group(work_a, IDEMIP_IGMP_ALL_SYSTEMS, 0u);
    Igmp.join(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
}

// A membership is a group on an interface, so an interface this build does not carry has no membership
// to hold.
void test_a_membership_needs_an_interface_this_build_carries(void)
{
    Igmp.clear(work_a);
    arm_group(work_a, GROUP_A, (uint8_t)IDEMIP_NETIF_COUNT);
    Igmp.join(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
}

// --- the contract's own constants --------------------------------------------

// RFC 2236 sec 2.1 names the three types "of concern to the host-router interaction" plus the one "for
// backwards-compatibility with IGMPv1", RFC 1112 Appendix I's type 2 Host Membership Report.
void test_the_message_types_are_the_ones_rfc_2236_prints(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x11u, IDEMIP_IGMP_TYPE_QUERY);
    TEST_ASSERT_EQUAL_HEX8(0x12u, IDEMIP_IGMP_TYPE_REPORT_V1);
    TEST_ASSERT_EQUAL_HEX8(0x16u, IDEMIP_IGMP_TYPE_REPORT_V2);
    TEST_ASSERT_EQUAL_HEX8(0x17u, IDEMIP_IGMP_TYPE_LEAVE);
}

// sec 2 draws Type, Max Resp Time and Checksum above the 32-bit Group Address, and sec 2.5 bounds what
// this version processes at "the first 8 octets".
void test_the_message_is_eight_octets_at_the_offsets_rfc_2236_draws(void)
{
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_IGMP_OFF_TYPE);
    TEST_ASSERT_EQUAL_UINT32(1u, IDEMIP_IGMP_OFF_MAX_RESP);
    TEST_ASSERT_EQUAL_UINT32(2u, IDEMIP_IGMP_OFF_CKSUM);
    TEST_ASSERT_EQUAL_UINT32(4u, IDEMIP_IGMP_OFF_GROUP);
    TEST_ASSERT_EQUAL_UINT32(8u, IDEMIP_IGMP_MSG_LEN);
}

// sec 2: "IGMP messages are encapsulated in IP datagrams, with an IP protocol number of 2", and "All
// IGMP messages described in this document are sent with IP TTL 1".
void test_the_datagram_carries_protocol_two_at_ttl_one(void)
{
    TEST_ASSERT_EQUAL_UINT32(2u, IDEMIP_IGMP_IP_PROTO);
    TEST_ASSERT_EQUAL_UINT32(1u, IDEMIP_IGMP_TTL);
}

// sec 9: a General Query to ALL-SYSTEMS (224.0.0.1), a Leave Message to ALL-ROUTERS (224.0.0.2).
void test_the_well_known_groups_are_the_ones_rfc_2236_prints(void)
{
    TEST_ASSERT_EQUAL_HEX32(0xE0000001u, IDEMIP_IGMP_ALL_SYSTEMS);
    TEST_ASSERT_EQUAL_HEX32(0xE0000002u, IDEMIP_IGMP_ALL_ROUTERS);
}

// sec 2.2: the Max Response Time field "specifies the maximum allowed time before sending a responding
// report in units of 1/10 second". A field value reaches milliseconds by multiplying, so nothing
// divides, and sec 4's reading of a zero field as "a value of 100 (10 seconds)" comes out at 10000.
void test_max_response_time_is_tenths_of_a_second(void)
{
    TEST_ASSERT_EQUAL_UINT32(100u, IDEMIP_IGMP_MAX_RESP_UNIT_MS);
    TEST_ASSERT_EQUAL_UINT32(100u, IDEMIP_IGMP_V1_MAX_RESP);
    TEST_ASSERT_EQUAL_UINT32(10000u, IDEMIP_IGMP_V1_MAX_RESP * IDEMIP_IGMP_MAX_RESP_UNIT_MS);
}

// RFC 2113 sec 2.1 draws the option as |10010100|00000100| 2 octet value |, with "Copied flag: 1",
// "Option class: 0 (control)", "Option number: 20 (decimal)", "Length: 4" and value "0 - Router shall
// examine packet". RFC 2236 sec 2 puts it in the IP header of every IGMP message.
void test_the_router_alert_option_is_the_one_rfc_2113_prints(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x94u, IDEMIP_IGMP_RA_TYPE);
    TEST_ASSERT_EQUAL_HEX8(0x80u, IDEMIP_IGMP_RA_TYPE & 0x80u); // copied flag set
    TEST_ASSERT_EQUAL_HEX8(0x00u, IDEMIP_IGMP_RA_TYPE & 0x60u); // option class 0
    TEST_ASSERT_EQUAL_HEX8(20u, IDEMIP_IGMP_RA_TYPE & 0x1Fu);   // option number 20
    TEST_ASSERT_EQUAL_UINT32(4u, IDEMIP_IGMP_RA_LEN);
    TEST_ASSERT_EQUAL_HEX16(0x0000u, IDEMIP_IGMP_RA_VALUE);
}

// RFC 2236 sec 6 gives a group on an interface one of three states, and they fit one octet so an entry
// can hold one. Non-Member is zero because clear zeroes the table.
void test_the_three_host_states_are_distinct_and_one_octet(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_IGMP_NON_MEMBER);
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_IGMP_DELAYING_MEMBER);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_IGMP_IDLE_MEMBER);
    TEST_ASSERT_EQUAL_size_t(1u, sizeof(IdemIpIgmpState));
}

// The index a result member carries is one octet, so the table may not be as wide as the value that
// means "no entry".
void test_none_is_outside_the_table(void)
{
    TEST_ASSERT_TRUE(IDEMIP_IGMP_GROUPS < IDEMIP_IGMP_NONE);
}

// RFC 2236 sec 8, the host-side defaults as printed: sec 8.1 Robustness Variable "Default: 2",
// sec 8.10 Unsolicited Report Interval "Default: 10 seconds", sec 8.11 Version 1 Router Present Timeout
// "Value: 400 seconds". Every one is held in milliseconds, so the tick period scales nothing.
void test_the_host_timers_are_the_ones_rfc_2236_prints(void)
{
    TEST_ASSERT_EQUAL_UINT32(2u, IDEMIP_IGMP_ROBUSTNESS);
    TEST_ASSERT_EQUAL_UINT32(10u * 1000u, IDEMIP_IGMP_UNSOLICITED_REPORT_MS);
    TEST_ASSERT_EQUAL_UINT32(400u * 1000u, IDEMIP_IGMP_V1_ROUTER_PRESENT_MS);
    TEST_ASSERT_EQUAL_UINT32(100u, IDEMIP_IGMP_TMR_INTERVAL_MS);
}

// =============================================================================
// The RFC 2236 behavior cases.
//
// RFC 2236 prints no numbered packet vectors for the host state machine, so every case below asserts
// a property its text or its sec 6 diagram states, using the field values the RFC itself prints: the
// sec 8.3 Query Response Interval "Default: 100 (10 seconds)", the sec 8.8 Last Member Query Interval
// "Default: 10 (1 second)", the sec 8.10 Unsolicited Report Interval "Default: 10 seconds", the
// sec 8.11 Version 1 Router Present Timeout "Value: 400 seconds", and sec 4's reading of a zero Max
// Response Time "as a value of 100 (10 seconds)".
// =============================================================================

// A second interface has to be a second interface for the sec 4 and sec 6 per-interface cases below.
static_assert(IDEMIP_NETIF_COUNT >= 2u, "test_igmp's per-interface cases need IDEMIP_NETIF_COUNT >= 2");

// The RFC 2236 sec 2.2 field values the RFC prints, in milliseconds.
#define MAXRESP_10S (100u * IDEMIP_IGMP_MAX_RESP_UNIT_MS)    // sec 8.3 Query Response Interval
#define MAXRESP_1S (10u * IDEMIP_IGMP_MAX_RESP_UNIT_MS)      // sec 8.8 Last Member Query Interval
#define MAXRESP_WIDEST (255u * IDEMIP_IGMP_MAX_RESP_UNIT_MS) // the widest an 8-bit field carries

// Four more class D groups, so the table can be filled.
#define GROUP_C 0xE0000010u
#define GROUP_D 0xE0000011u
#define GROUP_E 0xE0000012u

// --- sec 6 join group --------------------------------------------------------

// sec 6's join group arc out of Non-Member runs "send report, set flag, start timer", and sec 3 says a
// joining host "should immediately transmit an unsolicited Version 2 Membership Report for that group".
void test_join_sends_a_report_sets_the_flag_and_starts_a_timer(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 5000u, 0xFFFFFFFFu);

    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_report, "sec 6 join group must send a report");
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IGMP_IO(work_a)->last_reporter, "sec 6 join group must set the flag");
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, IDEMIP_IGMP_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(GROUP_A, IDEMIP_IGMP_IO(work_a)->group);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IGMP_IO(work_a)->netif);
    TEST_ASSERT_NOT_EQUAL_UINT8(IDEMIP_IGMP_NONE, IDEMIP_IGMP_IO(work_a)->index);
}

// sec 6's start timer: "If this is an unsolicited Report, the timer is set to a delay value chosen
// uniformly from the interval (0, [Unsolicited Report Interval] ]", which sec 8.10 defaults to 10 s.
void test_join_arms_the_timer_inside_the_unsolicited_report_interval(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 5000u, 0x8000000u);
    uint32_t deadline = IDEMIP_IGMP_IO(work_a)->deadline_ms;
    TEST_ASSERT_GREATER_THAN_UINT32(5000u, deadline);
    TEST_ASSERT_LESS_OR_EQUAL_UINT32(5000u + IDEMIP_IGMP_UNSOLICITED_REPORT_MS, deadline);
}

// RFC 1112 sec 7.1: "It is also permissible for more than one upper-layer protocol to request
// membership in the same group", and "LeaveHostGroup may succeed, but the membership persist, if more
// than one upper-layer protocol has requested membership in the same group". sec 7.2 requires "an
// associated reference count or similar mechanism to handle multiple requests to join and leave the
// same group", and notifies the network module only "On the first request to join and the last
// request to leave a group on a given interface", so RFC 2236 sec 6's "join group" event, which "may
// occur only in the Non-Member state", fires on the first join alone.
void test_a_second_join_of_the_same_group_takes_a_reference(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    uint8_t index = IDEMIP_IGMP_IO(work_a)->index;
    uint32_t deadline = IDEMIP_IGMP_IO(work_a)->deadline_ms;
    IdemIpIgmpState state = IDEMIP_IGMP_IO(work_a)->state;

    join_at(work_a, GROUP_A, 0u, 5000u, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(index, IDEMIP_IGMP_IO(work_a)->index, "the second request joins the same entry");
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_report,
                              "only the first request to join notifies the network module");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(deadline, IDEMIP_IGMP_IO(work_a)->deadline_ms,
                                     "the sec 6 timer is not restarted by a second reference");
    TEST_ASSERT_EQUAL_INT(state, IDEMIP_IGMP_IO(work_a)->state);

    // The first leave drops a reference and the membership stands, so a datagram for the group is
    // still delivered.
    leave_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_leave,
                              "only the last request to leave notifies the network module");
    find_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(index, IDEMIP_IGMP_IO(work_a)->index);

    // The last leave runs the sec 6 leave-group arc.
    leave_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->send_leave);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_NON_MEMBER, IDEMIP_IGMP_IO(work_a)->state);
    find_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status, "the membership is gone");
}

// sec 6 holds a state "with respect to any single IP multicast group on any single network interface",
// so the same group on two interfaces is two memberships with two timers.
void test_the_same_group_on_two_interfaces_is_two_memberships(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0xFFFFFFFFu);
    uint8_t first = IDEMIP_IGMP_IO(work_a)->index;
    join_ok(work_a, GROUP_A, 1u, 0u, 0u);
    uint8_t second = IDEMIP_IGMP_IO(work_a)->index;

    TEST_ASSERT_NOT_EQUAL_UINT8(first, second);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_IGMP_UNSOLICITED_REPORT_MS, deadline_of(work_a, GROUP_A, 0u));
    TEST_ASSERT_EQUAL_UINT32(1u, deadline_of(work_a, GROUP_A, 1u));
}

// A table with no free entry is BUSY, not ERR: leave frees an entry, so the retry succeeds. Reported
// as ERR a caller would abandon a healthy table.
void test_a_full_table_is_busy_and_a_leave_makes_the_retry_succeed(void)
{
    Igmp.clear(work_a);
    for (uint32_t i = 0u; i < IDEMIP_IGMP_GROUPS; i++)
    {
        join_ok(work_a, GROUP_C + i, 0u, 0u, 0u);
    }
    join_at(work_a, GROUP_A, 0u, 0u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_IGMP_IO(work_a)->status, "a full table must be BUSY");
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IGMP_NONE, IDEMIP_IGMP_IO(work_a)->index);

    leave_at(work_a, GROUP_C, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    join_at(work_a, GROUP_A, 0u, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
}

// --- sec 6 start timer, the draw over (0, Max Response Time] -----------------

// sec 6's start timer draws "a delay value chosen uniformly from the interval (0, Max Response Time]".
// The interval is closed at the top, so the top value must be producible. lwIP's
// lwip_ref/src/core/ipv4/igmp.c:695 draws LWIP_RAND() % max_time, which cannot ever produce max_time.
void test_the_delay_draw_reaches_the_top_of_the_interval(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(IDEMIP_IGMP_UNSOLICITED_REPORT_MS, IDEMIP_IGMP_IO(work_a)->deadline_ms,
                                     "the top of (0, Max Response Time] must be reachable");
}

// The interval is open at zero, so no draw may be zero: a zero delay would fire the report inside the
// same tick the timer started.
void test_the_delay_draw_never_yields_zero(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, IDEMIP_IGMP_IO(work_a)->deadline_ms, "zero is outside (0, Max Response Time]");
}

// Every draw lands inside (0, [Unsolicited Report Interval] ], and both ends of the closed-open
// interval are actually produced. This walks the whole 16-bit word the draw reads.
void test_the_delay_draw_covers_the_interval_and_leaves_it_at_neither_end(void)
{
    uint32_t low = 0xFFFFFFFFu;
    uint32_t high = 0u;
    Igmp.clear(work_a);
    for (uint32_t hi = 0u; hi <= 0xFFFFu; hi++)
    {
        join_ok(work_a, GROUP_A, 0u, 0u, hi << 16);
        uint32_t drawn = IDEMIP_IGMP_IO(work_a)->deadline_ms;
        TEST_ASSERT_GREATER_THAN_UINT32(0u, drawn);
        TEST_ASSERT_LESS_OR_EQUAL_UINT32(IDEMIP_IGMP_UNSOLICITED_REPORT_MS, drawn);
        low = (drawn < low) ? drawn : low;
        high = (drawn > high) ? drawn : high;
        leave_at(work_a, GROUP_A, 0u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    }
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, low, "the smallest draw must be one, not zero");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(IDEMIP_IGMP_UNSOLICITED_REPORT_MS, high, "the top must be reachable");
}

// --- sec 3 and sec 6 query received ------------------------------------------

// sec 3: on a General Query a host "sets delay timers for each group (excluding the all-systems group)
// of which it is a member on the interface from which it received the query". A membership on another
// interface is not one of them.
void test_a_general_query_arms_every_membership_on_its_own_interface_only(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    join_ok(work_a, GROUP_B, 0u, 0u, 0u);
    join_ok(work_a, GROUP_C, 1u, 0u, 0u);
    run_timer_out(work_a, 100u); // A
    run_timer_out(work_a, 100u); // B
    run_timer_out(work_a, 100u); // C
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_a, GROUP_A, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_a, GROUP_B, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_a, GROUP_C, 1u));

    query_at(work_a, 0u, IDEMIP_TRUE, 0u, MAXRESP_10S, 1000u, 0xA5A5A5A5u, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);

    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, state_of(work_a, GROUP_A, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, state_of(work_a, GROUP_B, 0u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_a, GROUP_C, 1u),
                                  "a General Query armed a membership on another interface");
}

// sec 3: on a Group-Specific Query a host "sets a delay timer ... for the group being queried if it is
// a member on the interface from which it received the query", and no other membership.
void test_a_group_specific_query_arms_only_the_group_it_names(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    join_ok(work_a, GROUP_B, 0u, 0u, 0u);
    run_timer_out(work_a, 100u);
    run_timer_out(work_a, 100u);

    query_at(work_a, 0u, IDEMIP_FALSE, GROUP_B, MAXRESP_1S, 1000u, 0xFFFFFFFFu, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(GROUP_B, IDEMIP_IGMP_IO(work_a)->group);

    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_a, GROUP_A, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, state_of(work_a, GROUP_B, 0u));
    TEST_ASSERT_EQUAL_UINT32(1000u + MAXRESP_1S, deadline_of(work_a, GROUP_B, 0u));
}

// sec 3 draws a Query's timer "from the range (0, Max Response Time] with Max Response Time as
// specified in the Query packet", so the Query path covers the same closed-top interval the join path
// does. This walks the whole word the first armed timer reads, at the sec 8.3 default of 10 seconds.
void test_a_query_draws_over_the_whole_max_response_time(void)
{
    uint32_t low = 0xFFFFFFFFu;
    uint32_t high = 0u;
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    for (uint32_t hi = 0u; hi <= 0xFFFFu; hi++)
    {
        report_at(work_a, GROUP_A, 0u); // another host's Report returns it to Idle Member
        TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, IDEMIP_IGMP_IO(work_a)->state);
        query_at(work_a, 0u, IDEMIP_FALSE, GROUP_A, MAXRESP_10S, 4000u, hi << 16, IDEMIP_FALSE);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
        uint32_t drawn = deadline_of(work_a, GROUP_A, 0u) - 4000u;
        TEST_ASSERT_GREATER_THAN_UINT32(0u, drawn);
        TEST_ASSERT_LESS_OR_EQUAL_UINT32(MAXRESP_10S, drawn);
        low = (drawn < low) ? drawn : low;
        high = (drawn > high) ? drawn : high;
    }
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, low, "the smallest draw must be one, not zero");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(MAXRESP_10S, high, "the top of (0, Max Response Time] must be reachable");
}

// sec 3: "Each timer is set to a different random value, using the highest clock granularity available
// on the host". One General Query over two memberships must not arm both to the same millisecond.
void test_a_general_query_gives_each_timer_a_different_value(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    join_ok(work_a, GROUP_B, 0u, 0u, 0u);
    run_timer_out(work_a, 100u);
    run_timer_out(work_a, 100u);

    query_at(work_a, 0u, IDEMIP_TRUE, 0u, MAXRESP_10S, 1000u, 0x12345678u, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_NOT_EQUAL_UINT32_MESSAGE(deadline_of(work_a, GROUP_A, 0u), deadline_of(work_a, GROUP_B, 0u),
                                         "sec 3 sets each timer to a different random value");
}

// sec 3: "If a timer for the group is already running, it is reset to the random value only if the
// requested Max Response Time is less than the remaining value of the running timer."
void test_a_running_timer_is_reset_only_by_a_shorter_max_response_time(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_IGMP_UNSOLICITED_REPORT_MS, deadline_of(work_a, GROUP_A, 0u));

    // 10 s requested against 10 s remaining is not less, so the running timer stands.
    query_at(work_a, 0u, IDEMIP_TRUE, 0u, MAXRESP_10S, 0u, 0x1u, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(IDEMIP_IGMP_UNSOLICITED_REPORT_MS, deadline_of(work_a, GROUP_A, 0u),
                                     "a timer was reset by a Max Response Time that was not shorter");

    // 1 s requested against 10 s remaining is less, so it is reset inside the shorter interval.
    query_at(work_a, 0u, IDEMIP_TRUE, 0u, MAXRESP_1S, 0u, 0xFFFFFFFFu, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_UINT32(MAXRESP_1S, deadline_of(work_a, GROUP_A, 0u));
}

// sec 6's query received arc has one action, "start timer". No Report leaves the host on the Query
// itself; the timer firing is what sends it.
void test_a_query_never_sends_a_report_itself(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    run_timer_out(work_a, 100u);

    query_at(work_a, 0u, IDEMIP_TRUE, 0u, MAXRESP_10S, 1000u, 0xFFFFFFFFu, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_report, "sec 6 query received only starts a timer");
}

// sec 6: "Queries are ignored for memberships in the Non-Member state." Ignoring is a call that
// completed and changed nothing, not a refusal, so it is OK with no entry named.
void test_a_query_for_a_group_the_host_has_not_joined_changes_nothing(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0xFFFFFFFFu);

    query_at(work_a, 0u, IDEMIP_FALSE, GROUP_B, MAXRESP_1S, 0u, 0xFFFFFFFFu, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IGMP_NONE, IDEMIP_IGMP_IO(work_a)->index);

    find_at(work_a, GROUP_B, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_IGMP_UNSOLICITED_REPORT_MS, deadline_of(work_a, GROUP_A, 0u));
}

// sec 2.2 gives Max Response Time 8 bits "in units of 1/10 second", so 255 units is the widest a Query
// can carry and anything past it never arrived on the wire: ERR, since no retry makes it legal.
void test_a_max_response_time_wider_than_the_field_can_carry_is_refused(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    run_timer_out(work_a, 100u);

    query_at(work_a, 0u, IDEMIP_TRUE, 0u, MAXRESP_WIDEST, 1000u, 0xFFFFFFFFu, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(1000u + MAXRESP_WIDEST, deadline_of(work_a, GROUP_A, 0u));

    query_at(work_a, 0u, IDEMIP_TRUE, 0u, MAXRESP_WIDEST + 1u, 1000u, 0xFFFFFFFFu, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
}

// A Query is received on an interface, so an interface this build does not carry has no membership for
// it to apply to.
void test_a_query_needs_an_interface_this_build_carries(void)
{
    Igmp.clear(work_a);
    query_at(work_a, (uint8_t)IDEMIP_NETIF_COUNT, IDEMIP_TRUE, 0u, MAXRESP_10S, 0u, 1u, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
}

// sec 2.4: a Group-Specific Query carries "the group address being queried", so a Query that is not
// general and names something that is not a group address is refused.
void test_a_group_specific_query_needs_a_class_d_group(void)
{
    Igmp.clear(work_a);
    query_at(work_a, 0u, IDEMIP_FALSE, 0x0A000001u, MAXRESP_10S, 0u, 1u, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
}

// --- sec 4 and sec 6, the IGMPv1 Router Present state ------------------------

// sec 4: "The IGMPv1 router will send General Queries with the Max Response Time set to 0. This MUST
// be interpreted as a value of 100 (10 seconds)." lwIP substitutes 1 second instead
// (lwip_ref/src/include/lwip/igmp.h:56, used at lwip_ref/src/core/ipv4/igmp.c:376).
void test_a_v1_query_arms_the_ten_second_interval_sec_4_prints(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    run_timer_out(work_a, 100u);

    query_at(work_a, 0u, IDEMIP_TRUE, 0u, 0u, 1000u, 0xFFFFFFFFu, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1000u + (IDEMIP_IGMP_V1_MAX_RESP * IDEMIP_IGMP_MAX_RESP_UNIT_MS),
                                     deadline_of(work_a, GROUP_A, 0u),
                                     "sec 4 reads a zero Max Response Time as 100 units, 10 seconds");
}

// sec 4: "a state variable MUST be kept for each interface, describing whether the multicast Querier on
// that interface is running IGMPv1 or IGMPv2 ... This state variable MUST be used to decide what type
// of Membership Reports to send for unsolicited Membership Reports as well as Membership Reports in
// response to Queries." lwIP keeps no such variable and always sends Version 2
// (lwip_ref/src/core/ipv4/igmp.c:374).
void test_a_v1_query_makes_the_reports_version_one_reports(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->report_v1, "no IGMPv1 Query was heard yet");

    query_at(work_a, 0u, IDEMIP_TRUE, 0u, 0u, 0u, 1u, IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);

    // an unsolicited Report, and a Report a timer fired, are both Version 1 now
    join_ok(work_a, GROUP_B, 0u, 0u, 0u);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IGMP_IO(work_a)->report_v1, "sec 4 decides the report type from the variable");
    tick_at(work_a, 100u);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->send_report);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->report_v1);
}

// sec 4: the variable "MUST be based upon whether or not an IGMPv1 query was heard in the last
// [Version 1 Router Present Timeout] seconds", which sec 8.11 fixes at 400 seconds. sec 6 falls back
// to "No IGMPv1 Router Present" when that timer expires.
void test_the_v1_router_record_ages_out_after_the_sec_8_11_timeout(void)
{
    Igmp.clear(work_a);
    query_at(work_a, 0u, IDEMIP_TRUE, 0u, 0u, 0u, 1u, IDEMIP_TRUE);

    tick_at(work_a, IDEMIP_IGMP_V1_ROUTER_PRESENT_MS - 1u);
    join_ok(work_a, GROUP_A, 0u, IDEMIP_IGMP_V1_ROUTER_PRESENT_MS - 1u, 0u);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IGMP_IO(work_a)->report_v1, "the record expired one millisecond early");

    tick_at(work_a, IDEMIP_IGMP_V1_ROUTER_PRESENT_MS);
    join_ok(work_a, GROUP_B, 0u, IDEMIP_IGMP_V1_ROUTER_PRESENT_MS, 0u);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->report_v1, "the record outlived the sec 8.11 timeout");
}

// sec 4 keeps the variable "for each interface", so an IGMPv1 Querier on one interface says nothing
// about the other.
void test_the_v1_router_record_is_per_interface(void)
{
    Igmp.clear(work_a);
    query_at(work_a, 0u, IDEMIP_TRUE, 0u, 0u, 0u, 1u, IDEMIP_TRUE);

    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->report_v1);
    join_ok(work_a, GROUP_A, 1u, 0u, 0u);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->report_v1, "an IGMPv1 Querier leaked to another interface");
}

// sec 6's send leave: "If the interface state says the Querier is running IGMPv1, this action SHOULD be
// skipped." sec 4 grants the same: "An IGMPv2 host MAY suppress Leave Group messages on a network
// where the Querier is using IGMPv1." lwIP has no such state and sends the Leave regardless
// (lwip_ref/src/core/ipv4/igmp.c:608).
void test_a_v1_querier_suppresses_the_leave_message(void)
{
    Igmp.clear(work_a);
    query_at(work_a, 0u, IDEMIP_TRUE, 0u, 0u, 0u, 1u, IDEMIP_TRUE);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u); // last reporter flag set
    join_ok(work_a, GROUP_A, 1u, 0u, 0u); // the interface with no IGMPv1 Querier

    leave_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_leave, "sec 6 skips send leave under an IGMPv1 Querier");

    leave_at(work_a, GROUP_A, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_leave, "an IGMPv2 Querier must not suppress the Leave");
}

// --- sec 3, sec 5 and sec 6 report received ----------------------------------

// sec 3: "If the host receives another host's Report (version 1 or 2) while it has a timer running, it
// stops its timer for the specified group and does not send a Report". sec 6's arc runs "stop timer,
// clear flag" into Idle Member.
void test_another_hosts_report_stops_the_timer_and_clears_the_flag(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0xFFFFFFFFu);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->last_reporter);

    report_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, IDEMIP_IGMP_IO(work_a)->state);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->last_reporter, "sec 6 report received clears the flag");
    TEST_ASSERT_EQUAL_UINT32(0u, deadline_of(work_a, GROUP_A, 0u));

    // the timer was stopped, so no Report leaves the host however far the clock runs
    tick_at(work_a, 0xFFFFu);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IGMP_IO(work_a)->expired);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_report, "a suppressed Report was still sent");
}

// sec 6: a report received "is ignored for memberships in the Non-Member or Idle Member state".
void test_a_report_is_ignored_in_the_idle_member_state(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    run_timer_out(work_a, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_a, GROUP_A, 0u));
    find_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IGMP_IO(work_a)->last_reporter, "the fired timer must set the flag");

    report_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, IDEMIP_IGMP_IO(work_a)->state);
    find_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IGMP_IO(work_a)->last_reporter,
                             "a Report in the Idle Member state cleared the flag");
}

// sec 6: a Report "applies only to the membership in the group identified by the Membership Report, on
// the interface from which the Membership Report is received".
void test_a_report_on_another_interface_does_not_suppress_this_one(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0xFFFFFFFFu);

    report_at(work_a, GROUP_A, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IGMP_NONE, IDEMIP_IGMP_IO(work_a)->index);

    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, state_of(work_a, GROUP_A, 0u));
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_IGMP_UNSOLICITED_REPORT_MS, deadline_of(work_a, GROUP_A, 0u));
}

// A Report for a group the host is not a member of is the Non-Member case sec 6 ignores, so it is OK
// with no entry named rather than a refusal.
void test_a_report_for_a_group_the_host_has_not_joined_is_ignored(void)
{
    Igmp.clear(work_a);
    report_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IGMP_NONE, IDEMIP_IGMP_IO(work_a)->index);
}

// --- sec 3 and sec 6 timer expired -------------------------------------------

// sec 3: "When a group's timer expires, the host multicasts a Version 2 Membership Report to the
// group, with IP TTL of 1." sec 6's arc runs "send report, set flag" into Idle Member.
void test_an_expired_timer_sends_a_report_and_sets_the_flag(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u); // deadline 1
    report_at(work_a, GROUP_A, 0u);       // clears the flag, so the tick has to set it again
    query_at(work_a, 0u, IDEMIP_FALSE, GROUP_A, MAXRESP_1S, 0u, 0u, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, state_of(work_a, GROUP_A, 0u));

    tick_at(work_a, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IGMP_IO(work_a)->expired);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->send_report);
    TEST_ASSERT_EQUAL_HEX32(GROUP_A, IDEMIP_IGMP_IO(work_a)->group);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, IDEMIP_IGMP_IO(work_a)->state);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IGMP_IO(work_a)->last_reporter, "sec 6 timer expired sets the flag");
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->report_v1, "no IGMPv1 Querier was heard");
}

// sec 6's timer expired event "may occur only in the Delaying Member state", and only once the deadline
// is reached. A millisecond short of it, nothing fires.
void test_a_timer_that_has_not_expired_is_left_running(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0xFFFFFFFFu);
    tick_at(work_a, IDEMIP_IGMP_UNSOLICITED_REPORT_MS - 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IGMP_IO(work_a)->expired);
    TEST_ASSERT_FALSE(IDEMIP_IGMP_IO(work_a)->send_report);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, state_of(work_a, GROUP_A, 0u));

    tick_at(work_a, IDEMIP_IGMP_UNSOLICITED_REPORT_MS);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IGMP_IO(work_a)->expired);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->send_report);
}

// Every timer that came due is counted, and one Report per call is handed out, so a caller ticks again
// while expired is non-zero and sends exactly one Report each time. A group never fires twice.
void test_a_sweep_counts_every_due_timer_and_hands_out_one_report_per_call(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    join_ok(work_a, GROUP_B, 0u, 0u, 0u);
    join_ok(work_a, GROUP_C, 0u, 0u, 0u);

    uint32_t seen[3] = {0u, 0u, 0u};
    for (uint32_t n = 0u; n < 3u; n++)
    {
        tick_at(work_a, 10u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)(3u - n), IDEMIP_IGMP_IO(work_a)->expired,
                                        "expired must count every timer this sweep found due");
        TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->send_report);
        seen[n] = IDEMIP_IGMP_IO(work_a)->group;
    }
    tick_at(work_a, 10u);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_IGMP_IO(work_a)->expired, "a timer fired twice");
    TEST_ASSERT_FALSE(IDEMIP_IGMP_IO(work_a)->send_report);

    TEST_ASSERT_TRUE_MESSAGE(seen[0] != seen[1] && seen[1] != seen[2] && seen[0] != seen[2],
                             "one group was reported twice while another was never reported");
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_a, GROUP_A, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_a, GROUP_B, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_a, GROUP_C, 0u));
}

// Deadlines are milliseconds in 32 bits, so the clock wraps. A deadline the wrap carried past zero is
// still in the future before the wrap and due after it.
void test_a_deadline_the_clock_wrapped_past_still_fires_once(void)
{
    const uint32_t start = 0xFFFFF000u;
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, start, 0xFFFFFFFFu);
    const uint32_t deadline = deadline_of(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE((uint32_t)(start + IDEMIP_IGMP_UNSOLICITED_REPORT_MS), deadline,
                                     "the deadline must be the wrapped sum");
    TEST_ASSERT_TRUE_MESSAGE(deadline < start, "this case needs a deadline the wrap carried past zero");

    tick_at(work_a, 0xFFFFFFFFu); // still before the wrap, so nothing is due
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_IGMP_IO(work_a)->expired, "a wrapped deadline fired early");

    tick_at(work_a, deadline); // the wrapped deadline, reached
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IGMP_IO(work_a)->expired);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->send_report);
}

// --- sec 6 leave group -------------------------------------------------------

// sec 6's leave group arc out of Idle Member runs "send leave if flag set" and lands in Non-Member,
// which "requires no storage in the host", so the entry is gone afterward.
void test_leave_from_idle_member_sends_a_leave_and_frees_the_entry(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    run_timer_out(work_a, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_a, GROUP_A, 0u));

    leave_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_leave, "sec 3 sends a Leave when we were the last to report");
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_NON_MEMBER, IDEMIP_IGMP_IO(work_a)->state);
    TEST_ASSERT_NOT_EQUAL_UINT8(IDEMIP_IGMP_NONE, IDEMIP_IGMP_IO(work_a)->index);

    find_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status, "leave left the entry behind");
}

// sec 6's leave group arc out of Delaying Member runs "stop timer, send leave if flag set", so the
// stopped timer never fires afterward.
void test_leave_from_delaying_member_stops_the_timer(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, state_of(work_a, GROUP_A, 0u));

    leave_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->send_leave);

    tick_at(work_a, IDEMIP_IGMP_UNSOLICITED_REPORT_MS);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_IGMP_IO(work_a)->expired, "a stopped timer still fired");
    TEST_ASSERT_FALSE(IDEMIP_IGMP_IO(work_a)->send_report);
}

// sec 3: "If it was not the last host to reply to a Query, it MAY send nothing as there must be another
// member on the subnet", which sec 6 states as "If the flag saying we were the last host to report is
// cleared, this action MAY be skipped".
void test_leave_sends_nothing_when_the_last_reporter_flag_is_clear(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0xFFFFFFFFu);
    report_at(work_a, GROUP_A, 0u); // another host reported, so the flag is cleared
    TEST_ASSERT_FALSE(IDEMIP_IGMP_IO(work_a)->last_reporter);

    leave_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IGMP_IO(work_a)->send_leave, "a Leave was sent with the flag cleared");
}

// sec 6: leave group "may occur only in the Delaying Member and Idle Member states". A group the table
// does not hold is in Non-Member, so the event cannot occur and no retry changes that.
void test_leave_of_a_group_that_was_never_joined_is_refused(void)
{
    Igmp.clear(work_a);
    leave_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IGMP_NONE, IDEMIP_IGMP_IO(work_a)->index);
    TEST_ASSERT_FALSE(IDEMIP_IGMP_IO(work_a)->send_leave);
}

// A membership is a group on an interface, so leaving it on the other interface leaves nothing.
void test_leave_on_the_wrong_interface_is_refused(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 0u, 0u, 0u);
    leave_at(work_a, GROUP_A, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, state_of(work_a, GROUP_A, 0u));
}

// --- find --------------------------------------------------------------------

// sec 6 holds one state per group per interface, and find reports that state with its running timer.
void test_find_reports_the_state_the_deadline_and_the_flag(void)
{
    Igmp.clear(work_a);
    join_ok(work_a, GROUP_A, 1u, 2000u, 0xFFFFFFFFu);

    find_at(work_a, GROUP_A, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(GROUP_A, IDEMIP_IGMP_IO(work_a)->group);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IGMP_IO(work_a)->netif);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, IDEMIP_IGMP_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(2000u + IDEMIP_IGMP_UNSOLICITED_REPORT_MS, IDEMIP_IGMP_IO(work_a)->deadline_ms);
    TEST_ASSERT_TRUE(IDEMIP_IGMP_IO(work_a)->last_reporter);

    find_at(work_a, GROUP_A, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status,
                                  "a membership was found on an interface it is not on");
}

// The borrow IS the instance, so two tables run the same state machine over disjoint memberships.
void test_two_borrows_run_independent_state_machines(void)
{
    Igmp.clear(work_a);
    Igmp.clear(work_b);
    join_ok(work_a, GROUP_A, 0u, 0u, 0xFFFFFFFFu);
    join_ok(work_b, GROUP_A, 0u, 0u, 0u);

    TEST_ASSERT_EQUAL_UINT32(IDEMIP_IGMP_UNSOLICITED_REPORT_MS, deadline_of(work_a, GROUP_A, 0u));
    TEST_ASSERT_EQUAL_UINT32(1u, deadline_of(work_b, GROUP_A, 0u));

    tick_at(work_b, 1u);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IGMP_IO(work_b)->expired);
    tick_at(work_a, 1u);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_IGMP_IO(work_a)->expired,
                                    "a tick on one borrow fired the other's timer");
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_DELAYING_MEMBER, state_of(work_a, GROUP_A, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IGMP_IDLE_MEMBER, state_of(work_b, GROUP_A, 0u));
}

// Each entry that names a group reads the interface out of the operand block and uses it to reach
// one, so each holds it against IDEMIP_NETIF_COUNT first - and RFC 1112 sec 4 gives a group "a class
// D IP address", so an address outside that is not one to join, leave, look up or report on.
void test_the_group_entries_refuse_an_interface_past_the_table(void)
{
    Igmp.clear(work_a);

    arm_group(work_a, GROUP_A, (uint8_t)IDEMIP_NETIF_COUNT);
    Igmp.leave(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status,
                                  "a leave took an interface past the table");
    Igmp.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status,
                                  "a lookup took an interface past the table");

    IDEMIP_IGMP_IO(work_a)->report_args.group = GROUP_A;
    IDEMIP_IGMP_IO(work_a)->report_args.netif = (uint8_t)IDEMIP_NETIF_COUNT;
    Igmp.report_in(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status,
                                  "a report took an interface past the table");

    // And a group address that is not one: the leave and the lookup read it too.
    arm_group(work_a, 0xC0000201u, 0u);
    Igmp.leave(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status,
                                  "a leave took an address that is no group");
    Igmp.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status,
                                  "a lookup took an address that is no group");
}

// RFC 1112 sec 7.2 has a host join a group once "for each interface" whatever asks for it, so the
// count of what asked is a count the application can raise. It holds at the top of its own width,
// and a join past that is BUSY: a leave gives one back.
void test_the_count_of_what_joined_a_group_holds_at_the_top_of_its_width(void)
{
    Igmp.clear(work_a);

    for (uint32_t k = 0; k < 255u; k++)
    {
        join_at(work_a, GROUP_A, 0u, 1000u, 0x1234u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_IGMP_IO(work_a)->status, "a join of a held group was refused");
    }

    join_at(work_a, GROUP_A, 0u, 1000u, 0x1234u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_IGMP_IO(work_a)->status, "the count of what joined turned over");
}

// RFC 2236 sec 3: a Membership Report is about a group, so a report naming an address that is not
// one is not a report this host suppresses anything for.
void test_a_report_about_an_address_that_is_no_group_is_refused(void)
{
    Igmp.clear(work_a);
    IDEMIP_IGMP_IO(work_a)->report_args.group = 0xC0000201u;
    IDEMIP_IGMP_IO(work_a)->report_args.netif = 0u;
    Igmp.report_in(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IGMP_IO(work_a)->status,
                                  "a report about an address that is no group was taken");
}
