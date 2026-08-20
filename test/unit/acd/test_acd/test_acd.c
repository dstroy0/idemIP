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

#include "src/acd/acd.h"

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
// This is the property the whole storage model rests on, so an entry runs on each borrow between the
// stores and the reads: without one this asserts only that two distinct C objects do not alias.
void test_two_borrows_share_no_byte(void)
{
    Acd.clear(work_a);
    Acd.clear(work_b);

    arm_start(work_a, ADDR_A);
    arm_start(work_b, ADDR_B);
    IDEMIP_ACD_IO(work_b)->start_args.defense = IDEMIP_ACD_DEFEND_ALWAYS;

    Acd.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    Acd.start(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_b)->status);

    // Each borrow publishes its own address and its own state, neither reaching the other.
    TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_HEX32(ADDR_B, IDEMIP_ACD_IO(work_b)->ipaddr);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_b)->state);

    // A second start on one borrow republishes only that one.
    IDEMIP_ACD_IO(work_a)->start_args.ipaddr = ADDR_B;
    Acd.start(work_a);
    TEST_ASSERT_EQUAL_HEX32(ADDR_B, IDEMIP_ACD_IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(ADDR_B, IDEMIP_ACD_IO(work_b)->ipaddr, "a start on one borrow reached the other");
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

// =============================================================================
// The behavior suite: RFC 5227 sec 2.1.1, sec 2.3 and sec 2.4.
//
// RFC 5227 prints no packet figures and no worked numeric example anywhere in sec 1.1 through sec 2.6,
// so there is no wire vector to lift. Every case below asserts a property the text states, quoting the
// sentence it comes from, and the timing cases are built from the sec 1.1 constant table alone.
// =============================================================================

// A second 48-bit address, so a packet can carry a 'sender hardware address' that is not this host's.
static const uint8_t g_other_mac[IDEMIP_ARP_HLN_ETHERNET] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

// One ARP packet, IDEMIP_ARP_LEN octets, built by arp.h.
static uint8_t g_pkt[IDEMIP_ARP_LEN];

// sec 1.1: an 'ARP Probe' is "an ARP Request packet, broadcast on the local link, with an all-zero
// 'sender IP address'", its 'target IP address' set to the address being probed.
static void mk_probe(const uint8_t *sha, uint32_t tpa)
{
    idemip_arp_build_request(g_pkt, sha, 0u, tpa);
}

// A plain ARP Request, with whatever sender and target addresses a case needs. sec 1.1's 'ARP
// Announcement' is this with spa == tpa == the address being announced.
static void mk_request(const uint8_t *sha, uint32_t spa, uint32_t tpa)
{
    idemip_arp_build_request(g_pkt, sha, spa, tpa);
}

static void mk_reply(const uint8_t *sha, uint32_t spa, uint32_t tpa)
{
    idemip_arp_build_reply(g_pkt, sha, spa, g_mac, tpa);
}

// --- driving the machine -----------------------------------------------------

static void start_at(uint8_t *w, uint32_t addr, IdemIpAcdDefense defense, uint32_t now, uint32_t rand)
{
    IDEMIP_ACD_IO(w)->start_args.mac = g_mac;
    IDEMIP_ACD_IO(w)->start_args.ipaddr = addr;
    IDEMIP_ACD_IO(w)->start_args.rand = rand;
    IDEMIP_ACD_IO(w)->start_args.now_ms = now;
    IDEMIP_ACD_IO(w)->start_args.defense = defense;
    Acd.start(w);
}

static void clear_and_start(uint8_t *w, uint32_t addr, IdemIpAcdDefense defense, uint32_t now, uint32_t rand)
{
    Acd.clear(w);
    start_at(w, addr, defense, now, rand);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(w)->status);
}

static void tick_at(uint8_t *w, uint32_t now, uint32_t rand)
{
    IDEMIP_ACD_IO(w)->tick_args.now_ms = now;
    IDEMIP_ACD_IO(w)->tick_args.rand = rand;
    Acd.tick(w);
}

// Fire whatever deadline the machine is holding, exactly on it.
static void tick_due(uint8_t *w, uint32_t rand)
{
    tick_at(w, IDEMIP_ACD_IO(w)->deadline_ms, rand);
}

static void arp_at(uint8_t *w, uint32_t now)
{
    IDEMIP_ACD_IO(w)->arp_in_args.packet = g_pkt;
    IDEMIP_ACD_IO(w)->arp_in_args.now_ms = now;
    IDEMIP_ACD_IO(w)->arp_in_args.rand = 0u;
    Acd.arp_in(w);
}

// Run sec 2.1.1's PROBE_NUM probes, its ANNOUNCE_WAIT, and sec 2.3's ANNOUNCE_NUM announcements, firing
// every deadline exactly. The bound is a multiple of the two counts, so a machine that never settles
// fails rather than spinning.
static void drive_to(uint8_t *w, IdemIpAcdState want)
{
    int guard = 4 * (int)(IDEMIP_ACD_PROBE_NUM + IDEMIP_ACD_ANNOUNCE_NUM) + 8;
    while (IDEMIP_ACD_IO(w)->state != want && guard-- > 0)
    {
        tick_due(w, 0u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(w)->status);
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(want, IDEMIP_ACD_IO(w)->state, "the machine never reached the state");
}

// --- sec 2.1.1, the initial random delay -------------------------------------

// sec 2.1.1: "the host should then wait for a random time interval selected uniformly in the range zero
// to PROBE_WAIT seconds".
void test_start_waits_out_a_delay_inside_probe_wait(void)
{
    for (uint32_t r = 0; r < 0x10000u; r += 0x101u)
    {
        clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 5000u, r);
        uint32_t delay = IDEMIP_ACD_IO(work_a)->deadline_ms - 5000u;
        TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_a)->state);
        TEST_ASSERT_TRUE_MESSAGE(delay <= IDEMIP_ACD_PROBE_WAIT_MS, "the initial delay ran past PROBE_WAIT");
    }
}

// "in the range zero to PROBE_WAIT" is closed at both ends, so both are reachable. lwIP's
// ACD_RANDOM_PROBE_WAIT is a modulo (src/core/ipv4/acd.c:95) and can never return PROBE_WAIT itself.
void test_the_initial_delay_reaches_zero_and_probe_wait(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_ACD_IO(work_a)->deadline_ms);

    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0xFFFFu);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_ACD_PROBE_WAIT_MS, IDEMIP_ACD_IO(work_a)->deadline_ms);
}

// The address, the state and the counts a fresh claim starts from.
void test_start_puts_the_address_in_the_machine(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ALWAYS, 0u, 0u);
    TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ACD_IO(work_a)->sent);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ACD_IO(work_a)->conflicts);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);
}

// sec 2.1 applies probing again "when a network interface transitions from an inactive to an active
// state, when a computer awakes from sleep, when a link-state change signals that an Ethernet cable has
// been connected", so a start over a running machine re-claims from the initial delay.
void test_start_over_a_running_machine_reclaims_from_the_delay(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    tick_due(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBING, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ACD_IO(work_a)->sent);

    start_at(work_a, ADDR_B, IDEMIP_ACD_DEFEND_ONCE, 9000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ACD_IO(work_a)->sent);
    TEST_ASSERT_EQUAL_HEX32(ADDR_B, IDEMIP_ACD_IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_UINT32(9000u, IDEMIP_ACD_IO(work_a)->deadline_ms);
}

// --- sec 2.1.1, the probes ---------------------------------------------------

// A deadline still ahead is BUSY, since the same call on a later tick fires it, and nothing goes out.
void test_a_tick_before_the_deadline_is_busy_and_sends_nothing(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0xFFFFu);
    tick_at(work_a, IDEMIP_ACD_PROBE_WAIT_MS - 1u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_a)->state);
}

// sec 2.1.1: after the initial delay the host "should then send PROBE_NUM probe packets".
void test_the_tick_on_the_deadline_sends_the_first_probe(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0xFFFFu);
    tick_at(work_a, IDEMIP_ACD_PROBE_WAIT_MS, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_probe);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBING, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ACD_IO(work_a)->sent);
    TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->ipaddr);
}

// sec 2.1.1: the probes are "spaced randomly and uniformly, PROBE_MIN to PROBE_MAX seconds apart".
void test_every_probe_gap_lies_between_probe_min_and_probe_max(void)
{
    for (uint32_t r = 0; r < 0x10000u; r += 0x101u)
    {
        clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
        tick_at(work_a, 0u, r);
        TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBING, IDEMIP_ACD_IO(work_a)->state);
        uint32_t gap = IDEMIP_ACD_IO(work_a)->deadline_ms;
        TEST_ASSERT_TRUE_MESSAGE(gap >= IDEMIP_ACD_PROBE_MIN_MS, "a probe gap fell under PROBE_MIN");
        TEST_ASSERT_TRUE_MESSAGE(gap <= IDEMIP_ACD_PROBE_MAX_MS, "a probe gap ran past PROBE_MAX");
    }
}

// "PROBE_MIN to PROBE_MAX seconds apart" is closed at both ends. lwIP's ACD_RANDOM_PROBE_INTERVAL is a
// modulo plus PROBE_MIN (src/core/ipv4/acd.c:98) and can never return PROBE_MAX itself.
void test_the_probe_gap_reaches_probe_min_and_probe_max(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    tick_at(work_a, 0u, 0u);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_ACD_PROBE_MIN_MS, IDEMIP_ACD_IO(work_a)->deadline_ms);

    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    tick_at(work_a, 0u, 0xFFFFu);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_ACD_PROBE_MAX_MS, IDEMIP_ACD_IO(work_a)->deadline_ms);
}

// sec 2.1.1: PROBE_NUM probe packets go out, then "by ANNOUNCE_WAIT seconds after the transmission of
// the last ARP Probe" the address may be used. Each probe is counted, so the count is exactly the one
// sec 1.1 prints.
void test_exactly_probe_num_probes_go_out_then_announce_wait(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    uint32_t probes = 0;
    uint32_t last_probe_ms = 0;
    while (IDEMIP_ACD_IO(work_a)->state != IDEMIP_ACD_STATE_ANNOUNCE_WAIT)
    {
        uint32_t due = IDEMIP_ACD_IO(work_a)->deadline_ms;
        tick_at(work_a, due, 0u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
        TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_probe);
        last_probe_ms = due;
        probes++;
        TEST_ASSERT_TRUE_MESSAGE(probes <= IDEMIP_ACD_PROBE_NUM, "more probes went out than PROBE_NUM");
    }
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_ACD_PROBE_NUM, probes);
    TEST_ASSERT_EQUAL_UINT32(last_probe_ms + IDEMIP_ACD_ANNOUNCE_WAIT_MS, IDEMIP_ACD_IO(work_a)->deadline_ms);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ACD_IO(work_a)->sent);
}

// --- sec 2.3, the announcements ----------------------------------------------

// sec 2.3: the host "MUST then announce that it is commencing to use this address by broadcasting
// ANNOUNCE_NUM ARP Announcements, spaced ANNOUNCE_INTERVAL seconds apart".
void test_exactly_announce_num_announcements_go_out_announce_interval_apart(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ANNOUNCE_WAIT);

    uint32_t announcements = 0;
    uint32_t prev_ms = 0;
    while (IDEMIP_ACD_IO(work_a)->state != IDEMIP_ACD_STATE_ONGOING)
    {
        uint32_t due = IDEMIP_ACD_IO(work_a)->deadline_ms;
        // One millisecond short of the deadline nothing goes out. A caller sweeping at
        // IDEMIP_ACD_TMR_INTERVAL_MS would otherwise emit the next Announcement 100 ms after the
        // last, where sec 2.3 spaces them ANNOUNCE_INTERVAL apart.
        tick_at(work_a, due - 1u, 0u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_ACD_IO(work_a)->status,
                                      "a tick before the deadline was not BUSY");
        TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ACD_IO(work_a)->send_announce, "an Announcement went out early");
        TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);

        tick_at(work_a, due, 0u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
        TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_announce);
        TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);
        if (announcements > 0)
        {
            TEST_ASSERT_EQUAL_UINT32(IDEMIP_ACD_ANNOUNCE_INTERVAL_MS, due - prev_ms);
        }
        prev_ms = due;
        announcements++;
        TEST_ASSERT_TRUE_MESSAGE(announcements <= IDEMIP_ACD_ANNOUNCE_NUM,
                                 "more announcements went out than ANNOUNCE_NUM");
    }
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_ACD_ANNOUNCE_NUM, announcements);
    TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->ipaddr);
}

// sec 2.4's detection is packet-driven, so ONGOING carries no deadline and a tick in it has nothing to
// fire. Same for OFF, which holds no address at all.
void test_a_tick_with_no_deadline_reports_ok_and_sends_nothing(void)
{
    Acd.clear(work_a);
    tick_at(work_a, 12345u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);

    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);
    tick_at(work_a, 999999u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_ONGOING, IDEMIP_ACD_IO(work_a)->state);
}

// Every deadline is held as a millisecond of the same wrapping 32-bit clock the caller reads, so one
// that crosses 2^32 is still fired once and not before.
void test_a_deadline_survives_the_clock_wrap(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0xFFFFFF00u, 0xFFFFu);
    TEST_ASSERT_EQUAL_UINT32(0xFFFFFF00u + IDEMIP_ACD_PROBE_WAIT_MS, IDEMIP_ACD_IO(work_a)->deadline_ms);

    tick_at(work_a, 0xFFFFFFF0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);

    tick_at(work_a, (uint32_t)(0xFFFFFF00u + IDEMIP_ACD_PROBE_WAIT_MS), 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_probe);
}

// --- sec 2.1.1, the conflict tests over the probing window -------------------

// sec 2.1.1: "if during this period ... the host receives any ARP packet (Request *or* Reply) ... where
// the packet's 'sender IP address' is the address being probed for, then the host MUST treat this
// address as being in use by some other host". A Reply carries the field just as a Request does.
void test_a_reply_whose_sender_ip_is_the_probed_address_is_a_conflict(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    mk_reply(g_other_mac, ADDR_A, ADDR_B);
    arp_at(work_a, 500u);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->abandon);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_ACD_IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ACD_IO(work_a)->conflicts);
}

void test_a_request_whose_sender_ip_is_the_probed_address_is_a_conflict(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    mk_request(g_other_mac, ADDR_A, ADDR_B);
    arp_at(work_a, 500u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
}

// sec 2.1.1 puts no hardware-address test on the 'sender IP address' clause: the sentence ends at "is
// the address being probed for". While probing, this host's own packets are ARP Probes with an all-zero
// 'sender IP address', so none of them can reach this clause.
void test_the_sender_ip_clause_carries_no_hardware_address_test(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    mk_request(g_mac, ADDR_A, ADDR_B); // this host's own 48-bit address in ar$sha
    arp_at(work_a, 500u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
}

// sec 2.1.1: "if during this period the host receives any ARP Probe where the packet's 'target IP
// address' is the address being probed for, and the packet's 'sender hardware address' is not the
// hardware address of any of the host's interfaces, then the host SHOULD similarly treat this as an
// address conflict".
void test_a_foreign_probe_for_the_same_address_is_a_conflict(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    mk_probe(g_other_mac, ADDR_A);
    arp_at(work_a, 500u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->abandon);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
}

// The sec 2.1.1 NOTE: "Some kinds of Ethernet hub ... may 'rebroadcast' any received broadcast packets
// to all recipients, including the original sender itself. For this reason, the precaution described
// above is necessary to ensure that a host is not confused when it sees its own ARP packets echoed
// back."
void test_this_hosts_own_probe_echoed_back_is_not_a_conflict(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    tick_due(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBING, IDEMIP_ACD_IO(work_a)->state);

    mk_probe(g_mac, ADDR_A);
    arp_at(work_a, 500u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->abandon);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBING, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ACD_IO(work_a)->conflicts);
}

// Both sec 2.1.1 clauses name the address being probed for, so a probe for a different address touches
// neither.
void test_a_foreign_probe_for_another_address_is_not_a_conflict(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    mk_probe(g_other_mac, ADDR_B);
    arp_at(work_a, 500u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_a)->state);
}

// sec 1.1 defines an 'ARP Probe' as "an ARP Request packet ... with an all-zero 'sender IP address'", so
// the second sec 2.1.1 clause reaches Requests only. A Reply with an all-zero 'sender IP address' is not
// an ARP Probe and matches neither clause. lwIP tests only ip4_addr_isany_val(sipaddr) and never ar$op
// (src/core/ipv4/acd.c:397-401), so it counts such a Reply as a conflict.
void test_a_reply_with_an_all_zero_sender_ip_is_not_a_probe(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    mk_reply(g_other_mac, 0u, ADDR_A);
    arp_at(work_a, 500u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_a)->state);
}

// sec 2.1.1 runs the window "from the beginning of the probing process until ANNOUNCE_WAIT seconds after
// the last probe packet is sent", so ANNOUNCE_WAIT is inside it.
void test_the_probing_window_reaches_through_announce_wait(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ANNOUNCE_WAIT);

    mk_probe(g_other_mac, ADDR_A);
    arp_at(work_a, IDEMIP_ACD_IO(work_a)->deadline_ms - 1u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->abandon);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
}

// --- sec 2.4, the ongoing test -----------------------------------------------

// sec 2.3: "The host may begin legitimately using the IP address immediately after sending the first of
// the two ARP Announcements", and sec 2.4 runs "for as long as a host is using an address". So from
// ANNOUNCING onward the sec 2.4 test applies and the sec 2.1.1 probe clause does not: a foreign ARP
// Probe for this address is no longer a conflict, because its 'sender IP address' is all zeroes.
void test_announcing_takes_the_section_2_4_test_and_not_the_probe_test(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ANNOUNCING);

    mk_probe(g_other_mac, ADDR_A);
    arp_at(work_a, 5000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_ANNOUNCING, IDEMIP_ACD_IO(work_a)->state);

    mk_request(g_other_mac, ADDR_A, ADDR_A);
    arp_at(work_a, 5000u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
}

// sec 2.4 opens "At any time, if a host receives an ARP packet (Request *or* Reply) where the
// 'sender IP address' is (one of) the host's own IP address(es) configured on that interface". The
// Reply half is not decorative: RFC 3927 sec 2.5 makes the broadcast Reply the primary conflict
// signal for link-local addresses, "All ARP packets (replies as well as requests) that contain a
// Link-Local 'sender IP address' MUST be sent using link-layer broadcast".
void test_an_ongoing_conflict_is_taken_from_a_reply_as_well_as_a_request(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_reply(g_other_mac, ADDR_A, ADDR_B);
    arp_at(work_a, 20000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_ACD_IO(work_a)->conflict, "a conflicting Reply was not a conflict");
    // DEFEND_ONCE is sec 2.4 (b): one Announcement per DEFEND_INTERVAL, and the address is kept.
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->ipaddr);

    // The 'sender hardware address' half holds for a Reply too: this host's own is no conflict.
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);
    mk_reply(g_mac, ADDR_A, ADDR_B);
    arp_at(work_a, 20000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ACD_IO(work_a)->conflict, "this host's own Reply was a conflict");
}

// The same over ANNOUNCING, which sec 2.4 covers from the first Announcement onward.
void test_an_announcing_conflict_is_taken_from_a_reply(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ANNOUNCING);

    mk_reply(g_other_mac, ADDR_A, ADDR_B);
    arp_at(work_a, 5000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
}

// sec 2.4: a conflicting ARP packet needs both halves, "the 'sender IP address' is (one of) the host's
// own IP address(es) ... but the 'sender hardware address' does not match any of the host's own
// interface addresses". This host's own Announcement echoed back fails the second half.
void test_an_ongoing_conflict_needs_a_foreign_sender_hardware_address(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_mac, ADDR_A, ADDR_A);
    arp_at(work_a, 20000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_ONGOING, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ACD_IO(work_a)->conflicts);
}

void test_an_ongoing_packet_for_another_address_is_not_a_conflict(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_other_mac, ADDR_B, ADDR_B);
    arp_at(work_a, 20000u);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_ONGOING, IDEMIP_ACD_IO(work_a)->state);
}

// --- sec 2.4 (a) --------------------------------------------------------------

// sec 2.4 (a): "Upon receiving a conflicting ARP packet, a host MAY elect to immediately cease using the
// address, and signal an error to the configuring agent as described above."
void test_defend_never_ceases_on_the_first_conflict(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_NEVER, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_other_mac, ADDR_A, ADDR_A);
    arp_at(work_a, 20000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->abandon);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ACD_IO(work_a)->send_announce, "(a) ceases rather than defending");
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_ACD_IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ACD_IO(work_a)->conflicts);
}

// --- sec 2.4 (b) --------------------------------------------------------------

// sec 2.4 (b): with no conflicting ARP packet "within the last DEFEND_INTERVAL seconds" the host "MAY
// elect to attempt to defend its address by recording the time that the conflicting ARP packet was
// received, and then broadcasting one single ARP Announcement ... the host can then continue to use the
// address normally".
void test_defend_once_announces_and_keeps_the_address(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_other_mac, ADDR_A, ADDR_A);
    arp_at(work_a, 20000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->abandon);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_ONGOING, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->ipaddr);
}

// sec 2.4 (b): "if this is not the first conflicting ARP packet the host has seen, and the time recorded
// for the previous conflicting ARP packet is recent, within DEFEND_INTERVAL seconds, then the host MUST
// immediately cease using this address".
void test_defend_once_ceases_on_a_second_conflict_inside_defend_interval(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_other_mac, ADDR_A, ADDR_A);
    arp_at(work_a, 20000u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_announce);

    arp_at(work_a, 20000u + IDEMIP_ACD_DEFEND_INTERVAL_MS - 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->abandon);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_ACD_IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_ACD_IO(work_a)->conflicts);
}

// DEFEND_INTERVAL is the "minimum interval between defensive ARPs" (sec 1.1), so a conflict a full
// interval after the recorded one is defended again rather than ceded.
void test_defend_once_announces_again_a_full_defend_interval_later(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_other_mac, ADDR_A, ADDR_A);
    arp_at(work_a, 20000u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_announce);

    arp_at(work_a, 20000u + IDEMIP_ACD_DEFEND_INTERVAL_MS);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->abandon);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_ONGOING, IDEMIP_ACD_IO(work_a)->state);
}

// --- sec 2.4 (c) --------------------------------------------------------------

// sec 2.4 (c): a host "configured such that it should not give up its address under any circumstances
// ... MAY elect to defend its address indefinitely". lwIP models only (a) and (b): its comment at
// src/core/ipv4/acd.c:441-458 says "We use option b) ... We use option a)", and no state defends
// indefinitely.
void test_defend_always_announces_and_never_ceases(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ALWAYS, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_other_mac, ADDR_A, ADDR_A);
    for (uint32_t k = 0; k < 5u; k++)
    {
        arp_at(work_a, 20000u + k * IDEMIP_ACD_DEFEND_INTERVAL_MS);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
        TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
        TEST_ASSERT_TRUE_MESSAGE(IDEMIP_ACD_IO(work_a)->send_announce, "(c) defends every interval");
        TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ACD_IO(work_a)->abandon, "(c) never gives up the address");
        TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_ONGOING, IDEMIP_ACD_IO(work_a)->state);
        TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->ipaddr);
    }
}

// sec 2.4 (c): "if this is not the first conflicting ARP packet the host has seen, and the time recorded
// for the previous conflicting ARP packet is within DEFEND_INTERVAL seconds, then the host MUST NOT send
// another defensive ARP Announcement."
void test_defend_always_sends_nothing_on_a_second_conflict_inside_the_interval(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ALWAYS, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_other_mac, ADDR_A, ADDR_A);
    arp_at(work_a, 20000u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_announce);

    arp_at(work_a, 20000u + IDEMIP_ACD_DEFEND_INTERVAL_MS - 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ACD_IO(work_a)->send_announce, "(c) MUST NOT send a second defense");
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->abandon);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_ONGOING, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_ACD_IO(work_a)->conflicts);
}

// --- sec 2.1.1, the rate limit -----------------------------------------------

// Ten probe-phase conflicts, one per attempt, so the counter walks to MAX_CONFLICTS.
static uint32_t run_conflicts_to_the_limit(uint8_t *w)
{
    Acd.clear(w);
    uint32_t at = 0;
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        at = i * 1000u;
        start_at(w, ADDR_A, IDEMIP_ACD_DEFEND_NEVER, at, 0u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(w)->status);
        mk_reply(g_other_mac, ADDR_A, ADDR_B);
        arp_at(w, at);
        TEST_ASSERT_TRUE(IDEMIP_ACD_IO(w)->conflict);
        TEST_ASSERT_TRUE(IDEMIP_ACD_IO(w)->abandon);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(i + 1u), IDEMIP_ACD_IO(w)->conflicts);
    }
    return at;
}

// sec 2.1.1: "if the host experiences MAX_CONFLICTS or more address conflicts on a given interface, then
// the host MUST limit the rate at which it probes for new addresses on this interface to no more than
// one attempted new address per RATE_LIMIT_INTERVAL".
void test_max_conflicts_enters_the_rate_limit(void)
{
    uint32_t at = run_conflicts_to_the_limit(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_RATE_LIMIT, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ACD_MAX_CONFLICTS, IDEMIP_ACD_IO(work_a)->conflicts);
    TEST_ASSERT_EQUAL_UINT32(at + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS, IDEMIP_ACD_IO(work_a)->deadline_ms);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_ACD_IO(work_a)->ipaddr);
}

// The conflict below MAX_CONFLICTS leaves the machine off with no interval to wait out, so a caller may
// try the next address at once.
void test_a_conflict_below_max_conflicts_does_not_rate_limit(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_NEVER, 0u, 0u);
    mk_reply(g_other_mac, ADDR_A, ADDR_B);
    arp_at(work_a, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_ACD_IO(work_a)->deadline_ms);

    start_at(work_a, ADDR_B, IDEMIP_ACD_DEFEND_NEVER, 100u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_a)->state);
}

// sec 2.1.1: "This rate-limiting rule applies not only to conflicts experienced during the initial
// probing phase, but also to conflicts experienced later, as described in Section 2.4 'Ongoing Address
// Conflict Detection and Address Defense'."
//
// A conflict sec 2.4 (c) defends raises the count and leaves the machine ONGOING, holding its address,
// so the count reaches MAX_CONFLICTS without the machine ever entering RATE_LIMIT. The limit reads the
// count, not the state, or a host under a defended conflict storm probes a new address as fast as it
// is asked to - the ARP storm sec 2.1.1 exists to prevent.
void test_defended_conflicts_reach_the_rate_limit_without_an_abandon(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ALWAYS, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_other_mac, ADDR_A, ADDR_A);
    uint32_t at = 20000u;
    for (uint32_t k = 0; k < IDEMIP_ACD_MAX_CONFLICTS; k++)
    {
        at = 20000u + (k * IDEMIP_ACD_DEFEND_INTERVAL_MS);
        arp_at(work_a, at);
        TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
        TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ACD_IO(work_a)->abandon, "(c) never gives up the address");
    }
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ACD_MAX_CONFLICTS, IDEMIP_ACD_IO(work_a)->conflicts);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ACD_STATE_ONGOING, IDEMIP_ACD_IO(work_a)->state,
                                  "a defended machine keeps its address, so it never enters RATE_LIMIT");

    uint32_t ends = at + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS;
    start_at(work_a, ADDR_B, IDEMIP_ACD_DEFEND_NEVER, ends - 1u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_ACD_IO(work_a)->status,
                                  "a host past MAX_CONFLICTS probed a new address inside the interval");

    start_at(work_a, ADDR_B, IDEMIP_ACD_DEFEND_NEVER, ends, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(ADDR_B, IDEMIP_ACD_IO(work_a)->ipaddr);

    // "no more than one attempted new address per RATE_LIMIT_INTERVAL", so the attempt after it waits
    // out an interval of its own.
    start_at(work_a, ADDR_A, IDEMIP_ACD_DEFEND_NEVER, ends + 1u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_ACD_IO(work_a)->status,
                                  "two new addresses were attempted inside one RATE_LIMIT_INTERVAL");
}

// A claim inside the interval is BUSY, not ERR: the interval ends and the same call then claims the
// address. Reported as ERR a caller would abandon a healthy address for good.
void test_a_claim_inside_the_rate_limit_interval_is_busy(void)
{
    uint32_t at = run_conflicts_to_the_limit(work_a);
    uint32_t ends = at + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS;

    start_at(work_a, ADDR_B, IDEMIP_ACD_DEFEND_NEVER, ends - 1u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_RATE_LIMIT, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_ACD_IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_UINT32(ends, IDEMIP_ACD_IO(work_a)->deadline_ms);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);

    start_at(work_a, ADDR_B, IDEMIP_ACD_DEFEND_NEVER, ends, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(ADDR_B, IDEMIP_ACD_IO(work_a)->ipaddr);
}

// A tick inside the interval is BUSY, and the tick on it ends the wait with no packet due.
void test_a_tick_ends_the_rate_limit_interval(void)
{
    uint32_t at = run_conflicts_to_the_limit(work_a);
    uint32_t ends = at + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS;

    tick_at(work_a, ends - 1u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_RATE_LIMIT, IDEMIP_ACD_IO(work_a)->state);

    tick_at(work_a, ends, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ACD_MAX_CONFLICTS, IDEMIP_ACD_IO(work_a)->conflicts);
}

// sec 2.1.1's count is of "address conflicts on a given interface", and the rule "applies not only to
// conflicts experienced during the initial probing phase, but also to conflicts experienced later". The
// RFC nowhere authorizes clearing it on a successful claim, so start does not. lwIP zeroes
// acd->num_conflicts on entering ANNOUNCING (src/core/ipv4/acd.c:288), which makes the count per attempt
// rather than per interface.
void test_a_claim_does_not_clear_the_conflict_count(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_NEVER, 0u, 0u);
    mk_reply(g_other_mac, ADDR_A, ADDR_B);
    arp_at(work_a, 100u);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ACD_IO(work_a)->conflicts);

    start_at(work_a, ADDR_B, IDEMIP_ACD_DEFEND_NEVER, 200u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IDEMIP_ACD_IO(work_a)->conflicts, "a claim reset the interface count");

    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IDEMIP_ACD_IO(work_a)->conflicts,
                                    "announcing an address reset the interface count");
}

// sec 2.4 names exactly three responses, "either (a), (b), or (c) below", so a fourth is a bad operand
// and no retry makes it one of the three.
void test_start_refuses_a_defense_that_is_none_of_a_b_or_c(void)
{
    Acd.clear(work_a);
    start_at(work_a, ADDR_A, (IdemIpAcdDefense)(IDEMIP_ACD_DEFEND_ALWAYS + 1), 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);
}

// sec 2.4 (c) defends "indefinitely", so a machine under it counts conflicts for as long as it runs. The
// count is one octet and holds at its ceiling rather than wrapping back under MAX_CONFLICTS.
void test_the_conflict_count_holds_at_its_ceiling(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ALWAYS, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_other_mac, ADDR_A, ADDR_A);
    for (uint32_t k = 0; k < 400u; k++)
    {
        arp_at(work_a, 20000u + k * IDEMIP_ACD_DEFEND_INTERVAL_MS);
        TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
        TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_ONGOING, IDEMIP_ACD_IO(work_a)->state);
    }
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xFFu, IDEMIP_ACD_IO(work_a)->conflicts, "the conflict count wrapped");
    TEST_ASSERT_EQUAL_HEX32(ADDR_A, IDEMIP_ACD_IO(work_a)->ipaddr);
}

// Only clear takes the count back to zero, since clear is what makes the borrow this module's again.
void test_clear_takes_the_conflict_count_back_to_zero(void)
{
    run_conflicts_to_the_limit(work_a);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ACD_MAX_CONFLICTS, IDEMIP_ACD_IO(work_a)->conflicts);
    Acd.clear(work_a);
    start_at(work_a, ADDR_A, IDEMIP_ACD_DEFEND_NEVER, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ACD_IO(work_a)->conflicts);
}

// --- stop ---------------------------------------------------------------------

// sec 2.4 (a) lets a host "immediately cease using the address" at any time. The count sec 2.1.1 rate
// limits by is a property of the interface and survives.
void test_stop_ceases_and_keeps_the_conflict_count(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ALWAYS, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);
    mk_request(g_other_mac, ADDR_A, ADDR_A);
    arp_at(work_a, 20000u);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ACD_IO(work_a)->conflicts);

    Acd.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_ACD_IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ACD_IO(work_a)->conflicts);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_probe);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_announce);
}

// A stop on a machine that holds no address is the state it is already in, so it repeats.
void test_stop_is_idempotent(void)
{
    Acd.clear(work_a);
    Acd.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    Acd.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
}

// A standing RATE_LIMIT holds no address, so a stop has nothing to cease and must not hand the caller a
// second attempt inside one RATE_LIMIT_INTERVAL, which is exactly what sec 2.1.1 forbids.
void test_stop_does_not_clear_a_standing_rate_limit(void)
{
    uint32_t at = run_conflicts_to_the_limit(work_a);
    uint32_t ends = at + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS;

    Acd.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_RATE_LIMIT, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(ends, IDEMIP_ACD_IO(work_a)->deadline_ms);

    start_at(work_a, ADDR_B, IDEMIP_ACD_DEFEND_NEVER, ends - 1u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ACD_IO(work_a)->status);
}

// --- what arp_in refuses and what it merely finds nothing in -------------------

// sec 1.1 reads 'sender IP address' and 'target IP address' as RFC 826's ar$spa and ar$tpa holding an
// IPv4 address. A packet with another ar$pln has neither field where this test would read it, so it is a
// bad argument rather than a packet with no conflict in it.
void test_arp_in_refuses_a_packet_that_is_not_ethernet_ipv4(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    mk_reply(g_other_mac, ADDR_A, ADDR_B);
    g_pkt[IDEMIP_ARP_OFF_PLN] = 16u; // an IPv6-width protocol address
    arp_at(work_a, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    // A refused arp_in returns before acd_publish, so io->state still holds the start's own output
    // and reading it here proves nothing. A tick republishes what the context actually holds: the
    // machine is still the one PROBE_WAIT left, so the next due tick sends the first Probe.
    tick_due(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_ACD_IO(work_a)->send_probe, "the refused packet moved the machine");
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBING, IDEMIP_ACD_IO(work_a)->state);

    mk_reply(g_other_mac, ADDR_A, ADDR_B);
    g_pkt[IDEMIP_ARP_OFF_HLN] = 8u;
    arp_at(work_a, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ACD_IO(work_a)->status);
}

// sec 2.1.1 and sec 2.4 both test "any ARP packet (Request *or* Reply)", so no other ar$op is under a
// rule of this specification: the test ran and found nothing.
void test_an_opcode_that_is_neither_request_nor_reply_holds_no_conflict(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    mk_reply(g_other_mac, ADDR_A, ADDR_B);
    idemip_wr16(g_pkt + IDEMIP_ARP_OFF_OP, 3u); // RARP Request
    arp_at(work_a, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_a)->state);
}

// A machine holding no address matches neither the sec 2.1.1 clauses nor the sec 2.4 one, so the sec 1.2
// test "performed on each received ARP packet" runs and answers rather than refusing.
void test_off_and_rate_limit_find_no_conflict_in_any_packet(void)
{
    Acd.clear(work_a);
    mk_request(g_other_mac, ADDR_A, ADDR_A);
    arp_at(work_a, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->abandon);

    uint32_t at = run_conflicts_to_the_limit(work_a);
    mk_request(g_other_mac, ADDR_A, ADDR_A);
    arp_at(work_a, at + 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_RATE_LIMIT, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ACD_MAX_CONFLICTS, IDEMIP_ACD_IO(work_a)->conflicts);
}

// --- the operand block is a result of one call and never of the last ----------

// An entry is a function of its borrow alone, so every result member reports what this call found. A
// send_probe left standing by an earlier tick would make the caller broadcast a second probe.
void test_an_entry_clears_every_result_member_it_did_not_set(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    tick_due(work_a, 0u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_probe);

    mk_probe(g_other_mac, ADDR_B); // no conflict in it
    arp_at(work_a, 100u);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ACD_IO(work_a)->send_probe, "arp_in left a tick's send_probe standing");
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->send_announce);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->abandon);

    mk_probe(g_other_mac, ADDR_A); // a conflict, so abandon and conflict are set
    arp_at(work_a, 200u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->abandon);

    // The conflict took the machine off, so the next tick has no deadline and clears both.
    tick_at(work_a, 300u, 0u);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ACD_IO(work_a)->conflict, "tick left an arp_in's conflict standing");
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ACD_IO(work_a)->abandon, "tick left an arp_in's abandon standing");

    start_at(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 400u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    mk_probe(g_other_mac, ADDR_A);
    arp_at(work_a, 400u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->abandon);
    Acd.stop(work_a);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ACD_IO(work_a)->abandon, "stop left an arp_in's abandon standing");
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_a)->conflict);
}

// --- two machines -------------------------------------------------------------

// The borrow IS the interface, so two machines draw their own delays, hold their own deadlines, and
// answer their own packets. Neither call touches the other's byte.
void test_two_machines_probe_and_conflict_independently(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    clear_and_start(work_b, ADDR_B, IDEMIP_ACD_DEFEND_ALWAYS, 0u, 0xFFFFu);

    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_ACD_IO(work_a)->deadline_ms);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_ACD_PROBE_WAIT_MS, IDEMIP_ACD_IO(work_b)->deadline_ms);

    tick_at(work_a, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ACD_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_probe);
    tick_at(work_b, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ACD_IO(work_b)->status);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_b)->send_probe);

    // A conflict over A's address ends A and leaves B claiming B's.
    mk_reply(g_other_mac, ADDR_A, ADDR_B);
    arp_at(work_a, 100u);
    arp_at(work_b, 100u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->conflict);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_OFF, IDEMIP_ACD_IO(work_a)->state);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_b)->conflict);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_PROBE_WAIT, IDEMIP_ACD_IO(work_b)->state);
    TEST_ASSERT_EQUAL_HEX32(ADDR_B, IDEMIP_ACD_IO(work_b)->ipaddr);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ACD_IO(work_b)->conflicts);
}

// A defense the two run at the same millisecond is recorded in each borrow, so B's DEFEND_INTERVAL is
// not started by A's conflict.
void test_a_defense_on_one_borrow_does_not_arm_the_others_interval(void)
{
    clear_and_start(work_a, ADDR_A, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    clear_and_start(work_b, ADDR_B, IDEMIP_ACD_DEFEND_ONCE, 0u, 0u);
    drive_to(work_a, IDEMIP_ACD_STATE_ONGOING);
    drive_to(work_b, IDEMIP_ACD_STATE_ONGOING);

    mk_request(g_other_mac, ADDR_A, ADDR_A);
    arp_at(work_a, 20000u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_a)->send_announce);

    // B's first conflict, inside the interval A recorded, is still B's first.
    mk_request(g_other_mac, ADDR_B, ADDR_B);
    arp_at(work_b, 20001u);
    TEST_ASSERT_TRUE(IDEMIP_ACD_IO(work_b)->send_announce);
    TEST_ASSERT_FALSE(IDEMIP_ACD_IO(work_b)->abandon);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ACD_STATE_ONGOING, IDEMIP_ACD_IO(work_b)->state);
}
