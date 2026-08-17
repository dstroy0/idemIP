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

#include "idemIP/igmp/igmp.h"

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

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the instance, and the operand block is in it, so two tables share no byte at all. This
// is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    Igmp.clear(work_a);
    Igmp.clear(work_b);

    arm_group(work_a, GROUP_A, 0u);
    arm_group(work_b, GROUP_B, 1u);
    IDEMIP_IGMP_IO(work_a)->query_args.max_resp_ms = 10000u;
    IDEMIP_IGMP_IO(work_b)->query_args.max_resp_ms = 100u;

    TEST_ASSERT_EQUAL_HEX32(GROUP_A, IDEMIP_IGMP_IO(work_a)->group_args.group);
    TEST_ASSERT_EQUAL_HEX32(GROUP_B, IDEMIP_IGMP_IO(work_b)->group_args.group);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IGMP_IO(work_a)->group_args.netif);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IGMP_IO(work_b)->group_args.netif);
    TEST_ASSERT_EQUAL_UINT32(10000u, IDEMIP_IGMP_IO(work_a)->query_args.max_resp_ms);
    TEST_ASSERT_EQUAL_UINT32(100u, IDEMIP_IGMP_IO(work_b)->query_args.max_resp_ms);
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
    arm_group(work_a, GROUP_A, 0u);

    Igmp.find(work_a);
    IdemIpStatus first = IDEMIP_IGMP_IO(work_a)->status;

    // work_b was never cleared, so its calls take the other path through every entry.
    arm_group(work_b, GROUP_B, 1u);
    Igmp.join(work_b);
    Igmp.tick(work_b);

    Igmp.find(work_a);
    TEST_ASSERT_EQUAL_INT(first, IDEMIP_IGMP_IO(work_a)->status);
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

// RFC 1112 sec 4: "Host groups are identified by class D IP addresses, i.e., those with "1110" as their
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
