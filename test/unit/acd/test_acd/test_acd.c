// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for acd, modeled on test_phy. It tests the CONTRACT and nothing else:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_ACD_BORROW is intact after every case
//   5. the published offset map is ordered, aligned, and does not overlap
//   6. clear zeroes the context, and a borrow no one cleared is refused
//
// No case here asserts what an entry reports once its RFC 5227 logic exists, so none of them has to be
// inverted when it does.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/acd/acd.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the interface. A canary follows each so
// a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(IDEMIP_ALIGN) uint8_t work_a[IDEMIP_ACD_BORROW + 16];
static _Alignas(IDEMIP_ALIGN) uint8_t work_b[IDEMIP_ACD_BORROW + 16];

// The span clear owns: the context, behind the operand block.
#define STATE_OFF ((size_t)IDEMIP_ACD_OFF_CTX)
#define STATE_END ((size_t)IDEMIP_ACD_OFF_END)

// Two addresses out of the RFC 3927 sec 2.1 link-local range, which is where RFC 5227's probing is
// most used, and one 48-bit address for the 'sender hardware address' of a probe.
#define ADDR_A 0xA9FE0102u
#define ADDR_B 0xA9FE0203u
static const uint8_t g_mac[IDEMIP_ARP_HLN_ETHERNET] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_ACD_BORROW, CANARY, cap - IDEMIP_ACD_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_ACD_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_ACD_BORROW");
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

// Every entry, in namespace order, so a new one added to AcdNs is added here too.
static void call_every_entry(uint8_t *w)
{
    Acd.clear(w);
    Acd.start(w);
    Acd.stop(w);
    Acd.arp_in(w);
    Acd.tick(w);
}

// The operands a started machine needs, so a case exercises the path rather than the argument checks.
static void arm_start(uint8_t *w, uint32_t addr)
{
    IDEMIP_ACD_IO(w)->start_args.mac = g_mac;
    IDEMIP_ACD_IO(w)->start_args.ipaddr = addr;
    IDEMIP_ACD_IO(w)->start_args.rand = 0x1234u;
    IDEMIP_ACD_IO(w)->start_args.now_ms = 1000u;
    IDEMIP_ACD_IO(w)->start_args.defense = IDEMIP_ACD_DEFEND_ONCE;
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the interface, and the operand block is in it, so two machines share no byte at all.
// This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    Acd.clear(work_a);
    Acd.clear(work_b);

    arm_start(work_a, ADDR_A);
    arm_start(work_b, ADDR_B);
    IDEMIP_ACD_IO(work_b)->start_args.defense = IDEMIP_ACD_DEFEND_ALWAYS;

    TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->start_args.ipaddr);
    TEST_ASSERT_EQUAL_HEX32(ADDR_B, IDEMIP_ACD_IO(work_b)->start_args.ipaddr);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_DEFEND_ONCE, IDEMIP_ACD_IO(work_a)->start_args.defense);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_DEFEND_ALWAYS, IDEMIP_ACD_IO(work_b)->start_args.defense);
}

// A call on one borrow reaches no byte of another, clear included, which is the widest-reaching entry
// this module has.
void test_clear_on_one_borrow_leaves_the_other_untouched(void)
{
    memset(work_b + STATE_OFF, 0xC3, STATE_END - STATE_OFF);
    IDEMIP_ACD_IO(work_b)->start_args.ipaddr = ADDR_B;

    Acd.clear(work_a);

    for (size_t i = STATE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[i], "clear on one borrow wrote into another");
    }
    TEST_ASSERT_EQUAL_HEX32(ADDR_B, IDEMIP_ACD_IO(work_b)->start_args.ipaddr);
}

// Every entry reads the context, so a call on one borrow cannot make another one's calls answer
// differently.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    Acd.clear(work_a);
    arm_start(work_a, ADDR_A);

    Acd.start(work_a);
    IdemIpStatus first = IDEMIP_ACD_IO(work_a)->status;

    // work_b was never cleared, so its calls take the other path through every entry.
    arm_start(work_b, ADDR_B);
    Acd.start(work_b);
    Acd.tick(work_b);

    Acd.start(work_a);
    TEST_ASSERT_EQUAL_INT(first, IDEMIP_ACD_IO(work_a)->status);
}

// --- the published map -------------------------------------------------------

// The map is public so a reader can place every region without opening the .c. The context starts
// where the operand block ends, so nothing overlaps and nothing is unreachable.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ACD_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE(STATE_OFF >= sizeof(AcdIo), "the context starts inside the operand block");
    TEST_ASSERT_TRUE_MESSAGE(STATE_END > STATE_OFF, "the context region has no room in it");
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_ACD_CTX_BYTES, STATE_END);
    TEST_ASSERT_TRUE_MESSAGE(STATE_END <= (size_t)IDEMIP_ACD_BORROW, "the map runs past IDEMIP_ACD_BORROW");
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
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_ACD_OFF_IO, (uint8_t *)IDEMIP_ACD_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_ACD_OFF_IO, (uint8_t *)IDEMIP_ACD_IO(work_b));
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Acd.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
}

// Whatever the region held, clear takes it to one state, so no stale byte survives into a machine that
// is about to probe an address.
void test_clear_takes_the_context_to_one_state(void)
{
    memset(work_a, 0x00, IDEMIP_ACD_BORROW);
    memset(work_b, 0xFF, IDEMIP_ACD_BORROW);
    Acd.clear(work_a);
    Acd.clear(work_b);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(work_a + STATE_OFF, work_b + STATE_OFF, STATE_END - STATE_OFF);
}

// The context comes out zeroed apart from the mark acd.h says clear leaves, which is what makes an
// uncleared borrow tell itself apart from a cleared one.
void test_clear_zeroes_the_context_apart_from_the_mark(void)
{
    memset(work_a, 0xFF, IDEMIP_ACD_BORROW);
    Acd.clear(work_a);
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
    Acd.clear(work_a);
    arm_start(work_a, ADDR_A);
    Acd.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_mac, IDEMIP_ACD_IO(work_a)->start_args.mac);
    TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->start_args.ipaddr);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_ACD_IO(work_a)->start_args.now_ms);
}

// An entry is a function of its borrow alone, so clearing twice leaves the same bytes as clearing once.
void test_clear_is_idempotent(void)
{
    memset(work_a, 0xFF, IDEMIP_ACD_BORROW);
    Acd.clear(work_a);
    memcpy(work_b, work_a, IDEMIP_ACD_BORROW);
    Acd.clear(work_a);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(work_b + STATE_OFF, work_a + STATE_OFF, STATE_END - STATE_OFF);
}

// A borrow no one cleared is not this module's, so every entry that reads the context refuses it rather
// than running a machine over whatever the caller's memory held.
void test_an_uncleared_borrow_is_refused(void)
{
    arm_start(work_a, ADDR_A);
    IDEMIP_ACD_IO(work_a)->arp_in_args.packet = work_b; // any IDEMIP_ARP_LEN octets will do

    Acd.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_a)->status);
    Acd.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_a)->status);
    Acd.arp_in(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_a)->status);
    Acd.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_a)->status);
}

// Clearing one borrow does not make another one cleared: the mark is in the borrow, not in the module.
void test_clearing_one_borrow_does_not_ready_the_other(void)
{
    Acd.clear(work_a);
    Acd.tick(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_b)->status);
}

// A machine with no address in it is what a cleared borrow holds, and start is what puts one there, so
// an address of zero is refused rather than probed for.
void test_start_refuses_no_address_and_no_hardware_address(void)
{
    Acd.clear(work_a);
    arm_start(work_a, ADDR_A);
    IDEMIP_ACD_IO(work_a)->start_args.ipaddr = 0u;
    Acd.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_a)->status);

    arm_start(work_a, ADDR_A);
    IDEMIP_ACD_IO(work_a)->start_args.mac = NULL;
    Acd.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_a)->status);
}

// RFC 5227 sec 1.2 leaves RFC 826 alone and adds a test "performed on each received ARP packet", so
// arp_in has nothing to test without one.
void test_arp_in_refuses_no_packet(void)
{
    Acd.clear(work_a);
    IDEMIP_ACD_IO(work_a)->arp_in_args.packet = NULL;
    Acd.arp_in(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_a)->status);
}

// --- the contract's own constants --------------------------------------------

// RFC 5227 sec 1.1, the timing constants as printed, seconds turned into the milliseconds every
// deadline in this tree is held in. sec 1.1: "the values listed here are fixed constants; they are not
// intended to be modifiable by implementers, operators, or end users."
void test_the_timing_constants_are_the_ones_rfc_5227_prints(void)
{
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_ACD_PROBE_WAIT_MS);        // 1 second
    TEST_ASSERT_EQUAL_UINT32(3u, IDEMIP_ACD_PROBE_NUM);               // 3 probe packets
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_ACD_PROBE_MIN_MS);         // 1 second
    TEST_ASSERT_EQUAL_UINT32(2000u, IDEMIP_ACD_PROBE_MAX_MS);         // 2 seconds
    TEST_ASSERT_EQUAL_UINT32(2000u, IDEMIP_ACD_ANNOUNCE_WAIT_MS);     // 2 seconds
    TEST_ASSERT_EQUAL_UINT32(2u, IDEMIP_ACD_ANNOUNCE_NUM);            // 2 Announcement packets
    TEST_ASSERT_EQUAL_UINT32(2000u, IDEMIP_ACD_ANNOUNCE_INTERVAL_MS); // 2 seconds
    TEST_ASSERT_EQUAL_UINT32(10u, IDEMIP_ACD_MAX_CONFLICTS);          // 10 conflicts
    TEST_ASSERT_EQUAL_UINT32(60000u, IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS); // 60 seconds
    TEST_ASSERT_EQUAL_UINT32(10000u, IDEMIP_ACD_DEFEND_INTERVAL_MS);     // 10 seconds
}

// sec 2.1.1 spaces each probe "randomly and uniformly, PROBE_MIN to PROBE_MAX seconds apart", so the
// two bound a range rather than naming one delay.
void test_the_probe_delay_has_a_range_to_draw_from(void)
{
    TEST_ASSERT_TRUE(IDEMIP_ACD_PROBE_MAX_MS > IDEMIP_ACD_PROBE_MIN_MS);
}

// The phases sec 2.1.1, sec 2.3 and sec 2.4 name, each distinct and each holdable in one octet of an
// entry. IDEMIP_ACD_STATE_OFF is zero because clear zeroes the context.
void test_the_states_are_distinct_and_one_octet(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_ACD_STATE_OFF);
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_ACD_STATE_PROBE_WAIT);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_ACD_STATE_PROBING);
    TEST_ASSERT_EQUAL_INT(3, IDEMIP_ACD_STATE_ANNOUNCE_WAIT);
    TEST_ASSERT_EQUAL_INT(4, IDEMIP_ACD_STATE_ANNOUNCING);
    TEST_ASSERT_EQUAL_INT(5, IDEMIP_ACD_STATE_ONGOING);
    TEST_ASSERT_EQUAL_INT(6, IDEMIP_ACD_STATE_RATE_LIMIT);
    TEST_ASSERT_EQUAL_size_t(1u, sizeof(IdemIpAcdState));
}

// RFC 5227 sec 2.4: "a host MUST respond to a conflicting ARP packet as described in either (a), (b),
// or (c) below", so the three are what an address can be configured to do.
void test_the_three_conflict_responses_are_distinct_and_one_octet(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_ACD_DEFEND_NEVER);
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_ACD_DEFEND_ONCE);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_ACD_DEFEND_ALWAYS);
    TEST_ASSERT_EQUAL_size_t(1u, sizeof(IdemIpAcdDefense));
}

// sec 1.1 states every constant in seconds, and this tree holds every deadline in milliseconds, so
// each one is a whole number of seconds scaled by a thousand and nothing converts at runtime.
void test_every_deadline_is_seconds_scaled_to_milliseconds(void)
{
    TEST_ASSERT_EQUAL_UINT32(1u * 1000u, IDEMIP_ACD_PROBE_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT32(2u * 1000u, IDEMIP_ACD_ANNOUNCE_INTERVAL_MS);
    TEST_ASSERT_EQUAL_UINT32(60u * 1000u, IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS);
    TEST_ASSERT_EQUAL_UINT32(10u * 1000u, IDEMIP_ACD_DEFEND_INTERVAL_MS);
}
