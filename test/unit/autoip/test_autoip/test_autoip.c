// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for autoip, modeled on test_phy. It tests the CONTRACT and nothing else:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_AUTOIP_BORROW is intact after every case
//   5. the published offset map is ordered, aligned, and does not overlap
//   6. clear zeroes the context, and a borrow no one cleared is refused
//
// No case here asserts what an entry reports once its RFC 3927 logic exists, so none of them has to be
// inverted when it does.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/autoip/autoip.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the interface. A canary follows each so
// a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(IDEMIP_ALIGN) uint8_t work_a[IDEMIP_AUTOIP_BORROW + 16];
static _Alignas(IDEMIP_ALIGN) uint8_t work_b[IDEMIP_AUTOIP_BORROW + 16];

// The span clear owns: the context, behind the operand block.
#define STATE_OFF ((size_t)IDEMIP_AUTOIP_OFF_CTX)
#define STATE_END ((size_t)IDEMIP_AUTOIP_OFF_END)

// RFC 3927 sec 2.1 seeds the draw from "persistent information that is different for each host, such
// as its IEEE 802 MAC address".
static const uint8_t g_mac[IDEMIP_ARP_HLN_ETHERNET] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_AUTOIP_BORROW, CANARY, cap - IDEMIP_AUTOIP_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_AUTOIP_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_AUTOIP_BORROW");
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

// Every entry, in namespace order, so a new one added to AutoIpNs is added here too.
static void call_every_entry(uint8_t *w)
{
    AutoIp.clear(w);
    AutoIp.start(w);
    AutoIp.conflict(w);
    AutoIp.bound(w);
    AutoIp.stop(w);
    AutoIp.tick(w);
}

static void arm_start(uint8_t *w, uint32_t rand)
{
    IDEMIP_AUTOIP_IO(w)->start_args.mac = g_mac;
    IDEMIP_AUTOIP_IO(w)->start_args.rand = rand;
    IDEMIP_AUTOIP_IO(w)->start_args.now_ms = 1000u;
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the interface, and the operand block is in it, so two interfaces share no byte at all.
// This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    AutoIp.clear(work_a);
    AutoIp.clear(work_b);

    arm_start(work_a, 0x1111u);
    arm_start(work_b, 0x2222u);
    IDEMIP_AUTOIP_IO(work_b)->start_args.now_ms = 5000u;

    TEST_ASSERT_EQUAL_UINT32(0x1111u, IDEMIP_AUTOIP_IO(work_a)->start_args.rand);
    TEST_ASSERT_EQUAL_UINT32(0x2222u, IDEMIP_AUTOIP_IO(work_b)->start_args.rand);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_AUTOIP_IO(work_a)->start_args.now_ms);
    TEST_ASSERT_EQUAL_UINT32(5000u, IDEMIP_AUTOIP_IO(work_b)->start_args.now_ms);
}

// A call on one borrow reaches no byte of another, clear included, which is the widest-reaching entry
// this module has.
void test_clear_on_one_borrow_leaves_the_other_untouched(void)
{
    memset(work_b + STATE_OFF, 0xC3, STATE_END - STATE_OFF);
    IDEMIP_AUTOIP_IO(work_b)->start_args.rand = 0x2222u;

    AutoIp.clear(work_a);

    for (size_t i = STATE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[i], "clear on one borrow wrote into another");
    }
    TEST_ASSERT_EQUAL_UINT32(0x2222u, IDEMIP_AUTOIP_IO(work_b)->start_args.rand);
}

// Every entry reads the context, so a call on one borrow cannot make another one's calls answer
// differently.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    AutoIp.clear(work_a);
    arm_start(work_a, 0x1111u);

    AutoIp.start(work_a);
    IdemIpStatus first = IDEMIP_AUTOIP_IO(work_a)->status;

    // work_b was never cleared, so its calls take the other path through every entry.
    arm_start(work_b, 0x2222u);
    AutoIp.start(work_b);
    AutoIp.tick(work_b);

    AutoIp.start(work_a);
    TEST_ASSERT_EQUAL_INT(first, IDEMIP_AUTOIP_IO(work_a)->status);
}

// --- the published map -------------------------------------------------------

// The map is public so a reader can place every region without opening the .c. The context starts
// where the operand block ends, so nothing overlaps and nothing is unreachable.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_AUTOIP_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE(STATE_OFF >= sizeof(AutoIpIo), "the context starts inside the operand block");
    TEST_ASSERT_TRUE_MESSAGE(STATE_END > STATE_OFF, "the context region has no room in it");
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_AUTOIP_CTX_BYTES, STATE_END);
    TEST_ASSERT_TRUE_MESSAGE(STATE_END <= (size_t)IDEMIP_AUTOIP_BORROW, "the map runs past IDEMIP_AUTOIP_BORROW");
}

// The context is reached at a constant offset from the borrow the caller took at IDEMIP_ALIGN, so a
// misaligned offset would misalign every word in it.
void test_every_published_offset_is_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, STATE_OFF & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, STATE_END & (IDEMIP_ALIGN - 1u));
}

// The operand block is reached at its published offset and nowhere else.
void test_the_io_macro_reaches_the_operand_block(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_AUTOIP_OFF_IO, (uint8_t *)IDEMIP_AUTOIP_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_AUTOIP_OFF_IO, (uint8_t *)IDEMIP_AUTOIP_IO(work_b));
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    AutoIp.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_AUTOIP_IO(work_a)->status);
}

// Whatever the region held, clear takes it to one state, so no stale address survives into an
// interface that is about to draw one.
void test_clear_takes_the_context_to_one_state(void)
{
    memset(work_a, 0x00, IDEMIP_AUTOIP_BORROW);
    memset(work_b, 0xFF, IDEMIP_AUTOIP_BORROW);
    AutoIp.clear(work_a);
    AutoIp.clear(work_b);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(work_a + STATE_OFF, work_b + STATE_OFF, STATE_END - STATE_OFF);
}

// The context comes out zeroed apart from the mark autoip.h says clear leaves, which is what makes an
// uncleared borrow tell itself apart from a cleared one.
void test_clear_zeroes_the_context_apart_from_the_mark(void)
{
    memset(work_a, 0xFF, IDEMIP_AUTOIP_BORROW);
    AutoIp.clear(work_a);
    size_t set = 0;
    for (size_t i = STATE_OFF; i < STATE_END; i++)
    {
        if (work_a[i] != 0x00u)
        {
            set++;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(set >= 1u, "clear left no mark, so an uncleared borrow cannot be told apart");
    TEST_ASSERT_TRUE_MESSAGE(set <= IDEMIP_ALIGN, "clear must zero the context apart from the mark");
}

// The operand block is the caller's, so clear does not touch what the caller put there.
void test_clear_leaves_the_operand_block_alone(void)
{
    AutoIp.clear(work_a);
    arm_start(work_a, 0x1111u);
    AutoIp.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_mac, IDEMIP_AUTOIP_IO(work_a)->start_args.mac);
    TEST_ASSERT_EQUAL_UINT32(0x1111u, IDEMIP_AUTOIP_IO(work_a)->start_args.rand);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_AUTOIP_IO(work_a)->start_args.now_ms);
}

// An entry is a function of its borrow alone, so clearing twice leaves the same bytes as clearing once.
void test_clear_is_idempotent(void)
{
    memset(work_a, 0xFF, IDEMIP_AUTOIP_BORROW);
    AutoIp.clear(work_a);
    memcpy(work_b, work_a, IDEMIP_AUTOIP_BORROW);
    AutoIp.clear(work_a);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(work_b + STATE_OFF, work_a + STATE_OFF, STATE_END - STATE_OFF);
}

// A borrow no one cleared is not this module's, so every entry that reads the context refuses it rather
// than binding whatever address the caller's memory held.
void test_an_uncleared_borrow_is_refused(void)
{
    arm_start(work_a, 0x1111u);

    AutoIp.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_AUTOIP_IO(work_a)->status);
    AutoIp.conflict(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_AUTOIP_IO(work_a)->status);
    AutoIp.bound(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_AUTOIP_IO(work_a)->status);
    AutoIp.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_AUTOIP_IO(work_a)->status);
    AutoIp.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_AUTOIP_IO(work_a)->status);
}

// Clearing one borrow does not make another one cleared: the mark is in the borrow, not in the module.
void test_clearing_one_borrow_does_not_ready_the_other(void)
{
    AutoIp.clear(work_a);
    AutoIp.tick(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_AUTOIP_IO(work_b)->status);
}

// RFC 3927 sec 2.1 seeds the draw from a per-host value, so start has nothing to seed from without one.
void test_start_refuses_no_hardware_address(void)
{
    AutoIp.clear(work_a);
    arm_start(work_a, 0x1111u);
    IDEMIP_AUTOIP_IO(work_a)->start_args.mac = NULL;
    AutoIp.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_AUTOIP_IO(work_a)->status);
}

// --- the contract's own constants --------------------------------------------

// RFC 3927 sec 2.1: "a uniform distribution in the range from 169.254.1.0 to 169.254.254.255
// inclusive", the prefix being 169.254/16.
void test_the_range_is_the_one_rfc_3927_prints(void)
{
    TEST_ASSERT_EQUAL_HEX32(0xA9FE0000u, IDEMIP_AUTOIP_PREFIX); // 169.254.0.0
    TEST_ASSERT_EQUAL_HEX32(0xA9FE0100u, IDEMIP_AUTOIP_FIRST);  // 169.254.1.0
    TEST_ASSERT_EQUAL_HEX32(0xA9FEFEFFu, IDEMIP_AUTOIP_LAST);   // 169.254.254.255
}

// sec 2.1: "The first 256 and last 256 addresses in the 169.254/16 prefix are reserved for future use
// and MUST NOT be selected by a host using this dynamic configuration mechanism", which leaves the
// 254 * 256 addresses lwIP counts as well.
void test_the_reserved_ends_are_outside_the_range(void)
{
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_AUTOIP_PREFIX + 256u, IDEMIP_AUTOIP_FIRST);
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_AUTOIP_PREFIX + 0xFFFFu - 256u, IDEMIP_AUTOIP_LAST);
    TEST_ASSERT_EQUAL_UINT32(254u * 256u, IDEMIP_AUTOIP_LAST - IDEMIP_AUTOIP_FIRST + 1u);
}

// sec 2.8: "The 169.254/16 address prefix MUST NOT be subnetted", so the mask is the prefix length and
// sec 2.6.2's "169.254.255.255, which is the broadcast address for the Link-Local prefix" follows from
// it.
void test_the_prefix_is_never_subnetted(void)
{
    TEST_ASSERT_EQUAL_HEX32(0xFFFF0000u, IDEMIP_AUTOIP_NETMASK);
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_AUTOIP_PREFIX, IDEMIP_AUTOIP_PREFIX & IDEMIP_AUTOIP_NETMASK);
    TEST_ASSERT_EQUAL_HEX32(0xA9FEFFFFu, IDEMIP_AUTOIP_BROADCAST);
    TEST_ASSERT_TRUE(IDEMIP_AUTOIP_BROADCAST > IDEMIP_AUTOIP_LAST);
}

// The phases sec 2.2 and sec 2.4 name, each distinct and each holdable in one octet of the context.
// IDEMIP_AUTOIP_STATE_OFF is zero because clear zeroes the context.
void test_the_states_are_distinct_and_one_octet(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_AUTOIP_STATE_OFF);
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_AUTOIP_STATE_CHECKING);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_AUTOIP_STATE_BOUND);
    TEST_ASSERT_EQUAL_size_t(1u, sizeof(IdemIpAutoIpState));
}

// RFC 3927 sec 9 prints the same timing constants RFC 5227 sec 1.1 does, so this unit takes acd's and
// declares none of its own.
void test_the_timing_constants_are_shared_with_rfc_5227(void)
{
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_ACD_PROBE_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT32(3u, IDEMIP_ACD_PROBE_NUM);
    TEST_ASSERT_EQUAL_UINT32(2u, IDEMIP_ACD_ANNOUNCE_NUM);
    TEST_ASSERT_EQUAL_UINT32(10u, IDEMIP_ACD_MAX_CONFLICTS);
    TEST_ASSERT_EQUAL_UINT32(60000u, IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS);
    TEST_ASSERT_EQUAL_UINT32(10000u, IDEMIP_ACD_DEFEND_INTERVAL_MS);
}
