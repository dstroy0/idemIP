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

// =============================================================================
// The behavior cases.
//
// RFC 3927 prints no example address, no seed and no generator, so there is no vector in the document
// to replay. What it does state is asserted instead: the range a draw lands in, the ends it must never
// land on, the per-host seeding, the retained first candidate, the new address a conflict draws, the
// rate limit past MAX_CONFLICTS, and the mask sec 2.8 fixes.
// =============================================================================

// A second interface address, differing from g_mac in the last octet.
static const uint8_t g_mac2[IDEMIP_ARP_HLN_ETHERNET] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

#define IO(w) IDEMIP_AUTOIP_IO(w)

static void start_at(uint8_t *w, const uint8_t *mac, uint32_t rand, uint32_t now_ms)
{
    IO(w)->start_args.mac = mac;
    IO(w)->start_args.rand = rand;
    IO(w)->start_args.now_ms = now_ms;
    AutoIp.start(w);
}

static void fresh_start(uint8_t *w, const uint8_t *mac, uint32_t rand)
{
    AutoIp.clear(w);
    start_at(w, mac, rand, 1000u);
}

static void conflict_at(uint8_t *w, uint32_t rand, uint32_t now_ms)
{
    IO(w)->conflict_args.rand = rand;
    IO(w)->conflict_args.now_ms = now_ms;
    AutoIp.conflict(w);
}

static void tick_at(uint8_t *w, uint32_t now_ms, uint32_t rand)
{
    IO(w)->tick_args.now_ms = now_ms;
    IO(w)->tick_args.rand = rand;
    AutoIp.tick(w);
}

// RFC 3927 sec 2.1: "a uniform distribution in the range from 169.254.1.0 to 169.254.254.255
// inclusive", the first and last 256 of the prefix being reserved.
static void assert_in_range(uint32_t addr)
{
    TEST_ASSERT_TRUE_MESSAGE(addr >= IDEMIP_AUTOIP_FIRST, "a draw landed in the reserved first 256");
    TEST_ASSERT_TRUE_MESSAGE(addr <= IDEMIP_AUTOIP_LAST, "a draw landed in the reserved last 256");
    TEST_ASSERT_TRUE_MESSAGE(addr != IDEMIP_AUTOIP_BROADCAST, "a draw landed on the sec 2.6.2 broadcast");
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(IDEMIP_AUTOIP_PREFIX, addr & IDEMIP_AUTOIP_NETMASK, "a draw left 169.254/16");
}

// --- sec 2.1, the draw -------------------------------------------------------

// sec 2.2: after selecting, a host "MUST test to see if the IPv4 Link-Local address is already in use
// before beginning to use it", which is the claim the caller hands to acd. No mask until sec 2.4.
void test_start_draws_a_candidate_and_asks_for_the_claim(void)
{
    fresh_start(work_a, g_mac, 0x12345678u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->claim);
    TEST_ASSERT_EQUAL_INT(IDEMIP_AUTOIP_STATE_CHECKING, IO(work_a)->state);
    assert_in_range(IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_HEX32(0u, IO(work_a)->netmask);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->tried);
}

// sec 2.1 reserves "The first 256 and last 256 addresses in the 169.254/16 prefix", so no seed and no
// step of the generator may produce one. Every draw a start and eight conflicts take, over 512 seeds.
void test_no_draw_lands_on_a_reserved_address(void)
{
    for (uint32_t r = 0; r < 512u; r++)
    {
        uint32_t seed = r * 2654435761u;
        fresh_start(work_a, g_mac, seed);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        assert_in_range(IO(work_a)->ipaddr);
        for (uint32_t k = 0; k < 8u; k++)
        {
            conflict_at(work_a, seed ^ k, 1000u);
            TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
            assert_in_range(IO(work_a)->ipaddr);
        }
    }
}

// sec 2.2.1: a conflict means the host "MUST select a new pseudo-random address and repeat the
// process", so the address the other host answered for is not the one drawn next.
void test_a_conflict_draws_a_new_address(void)
{
    fresh_start(work_a, g_mac, 0x0BADC0DEu);
    uint32_t first = IO(work_a)->ipaddr;

    conflict_at(work_a, 0x11111111u, 2000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->claim);
    TEST_ASSERT_EQUAL_INT(IDEMIP_AUTOIP_STATE_CHECKING, IO(work_a)->state);
    assert_in_range(IO(work_a)->ipaddr);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(first, IO(work_a)->ipaddr, "sec 2.2.1 requires a new address");
    TEST_ASSERT_EQUAL_UINT8(2u, IO(work_a)->tried);
}

// sec 2.1: the generator is seeded from per-host information, so the same interface address and the
// same word draw the same address. "a host will usually select the same IPv4 Link-Local address each
// time it is booted".
void test_one_interface_draws_the_same_address_every_time(void)
{
    fresh_start(work_a, g_mac, 0xA5A5A5A5u);
    fresh_start(work_b, g_mac, 0xA5A5A5A5u);
    TEST_ASSERT_EQUAL_HEX32(IO(work_a)->ipaddr, IO(work_b)->ipaddr);
}

// sec 2.1: "The pseudo-random number generation algorithm MUST be chosen so that different hosts do not
// generate the same sequence of numbers." Two interface addresses, the same word, four draws each.
void test_two_interfaces_do_not_walk_the_same_sequence(void)
{
    uint32_t a[4];
    uint32_t b[4];
    fresh_start(work_a, g_mac, 0xA5A5A5A5u);
    fresh_start(work_b, g_mac2, 0xA5A5A5A5u);
    a[0] = IO(work_a)->ipaddr;
    b[0] = IO(work_b)->ipaddr;
    for (int i = 1; i < 4; i++)
    {
        conflict_at(work_a, 0u, 2000u);
        conflict_at(work_b, 0u, 2000u);
        a[i] = IO(work_a)->ipaddr;
        b[i] = IO(work_b)->ipaddr;
    }
    int same = 1;
    for (int i = 0; i < 4; i++)
    {
        if (a[i] != b[i])
        {
            same = 0;
        }
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, same, "two interface addresses walked the same sec 2.1 sequence");
}

// sec 2.1 seeds from "its IEEE 802 MAC address", so every octet of it reaches the draw: changing any
// one of the six changes the address selected.
void test_every_octet_of_the_interface_address_reaches_the_draw(void)
{
    uint8_t mac[IDEMIP_ARP_HLN_ETHERNET];
    memcpy(mac, g_mac, sizeof mac);
    fresh_start(work_a, mac, 0x5EEDu);
    uint32_t base = IO(work_a)->ipaddr;

    for (size_t i = 0; i < sizeof mac; i++)
    {
        memcpy(mac, g_mac, sizeof mac);
        mac[i] = (uint8_t)(mac[i] ^ 0x40u);
        fresh_start(work_b, mac, 0x5EEDu);
        TEST_ASSERT_NOT_EQUAL_MESSAGE(base, IO(work_b)->ipaddr, "an octet of the interface address is not seeded in");
    }
}

// sec 2.1: "hosts with a previously recorded address SHOULD use that address as their first candidate
// when probing", so the address held through a stop is the one the next start claims.
void test_a_held_address_is_the_first_candidate_after_a_stop(void)
{
    fresh_start(work_a, g_mac, 0xFEEDFACEu);
    uint32_t first = IO(work_a)->ipaddr;
    AutoIp.bound(work_a);
    AutoIp.stop(work_a);

    start_at(work_a, g_mac, 0x00000000u, 9000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->claim);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(first, IO(work_a)->ipaddr, "sec 2.1's first candidate was redrawn");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IO(work_a)->tried, "a reused candidate is not a new draw");
}

// --- sec 2.4 and sec 2.8, the bound address ----------------------------------

// sec 2.4 puts the announced address in use, and sec 2.8's "The 169.254/16 address prefix MUST NOT be
// subnetted" fixes the mask at the prefix length.
void test_bound_configures_the_address_with_the_prefix_mask(void)
{
    fresh_start(work_a, g_mac, 0x1234u);
    uint32_t addr = IO(work_a)->ipaddr;

    AutoIp.bound(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_AUTOIP_STATE_BOUND, IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(addr, IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_HEX32(0xFFFF0000u, IO(work_a)->netmask);
    TEST_ASSERT_FALSE(IO(work_a)->claim);
}

// sec 2.5: conflict detection "is an ongoing process that is in effect for as long as a host is using
// an IPv4 Link-Local address", and (a) permits the host to "immediately configure a new IPv4 Link-Local
// address", so a bound address leaves the interface and a new one is drawn.
void test_a_conflict_on_a_bound_address_replaces_it(void)
{
    fresh_start(work_a, g_mac, 0xC0FFEEu);
    AutoIp.bound(work_a);
    uint32_t bound_addr = IO(work_a)->ipaddr;

    conflict_at(work_a, 0x77u, 4000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->claim);
    TEST_ASSERT_EQUAL_INT(IDEMIP_AUTOIP_STATE_CHECKING, IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0u, IO(work_a)->netmask, "the mask stayed on a conflicting address");
    TEST_ASSERT_NOT_EQUAL(bound_addr, IO(work_a)->ipaddr);
}

// sec 1.9: a host "SHOULD NOT have both an operable routable address and an IPv4 Link-Local address
// configured on the same interface", so stop leaves the interface with neither address nor mask.
void test_stop_leaves_no_address_on_the_interface(void)
{
    fresh_start(work_a, g_mac, 0x99u);
    AutoIp.bound(work_a);

    AutoIp.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_AUTOIP_STATE_OFF, IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_HEX32(0u, IO(work_a)->netmask);
    TEST_ASSERT_FALSE(IO(work_a)->claim);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IO(work_a)->tried, "stop dropped the count of addresses drawn");
}

// --- sec 2.2.1, the rate limit -----------------------------------------------

// sec 2.2.1 limits the rate only once the count "exceeds MAX_CONFLICTS", so MAX_CONFLICTS conflicts are
// each answered with a new address at once.
void test_max_conflicts_are_each_answered_at_once(void)
{
    fresh_start(work_a, g_mac, 0x2222u);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u + i);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status, "a conflict at or under MAX_CONFLICTS was held");
        TEST_ASSERT_TRUE(IO(work_a)->claim);
        assert_in_range(IO(work_a)->ipaddr);
        TEST_ASSERT_EQUAL_HEX32(0u, IO(work_a)->deadline_ms);
    }
    TEST_ASSERT_EQUAL_UINT8(1u + IDEMIP_ACD_MAX_CONFLICTS, IO(work_a)->tried);
}

// sec 2.2.1: once the count "exceeds MAX_CONFLICTS then the host MUST limit the rate at which it probes
// for new addresses to no more than one new address per RATE_LIMIT_INTERVAL". The conflict past the
// count asks for no claim and reports BUSY, which a later tick makes progress on.
void test_the_conflict_past_max_conflicts_is_rate_limited(void)
{
    fresh_start(work_a, g_mac, 0x3333u);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    conflict_at(work_a, 0xABCDu, 50000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->claim, "a rate limited draw was handed out anyway");
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0u, IO(work_a)->ipaddr, "a taken address stayed on the interface");
    TEST_ASSERT_EQUAL_UINT8(1u + IDEMIP_ACD_MAX_CONFLICTS, IO(work_a)->tried);
}

// The deadline is a millisecond clock plus RATE_LIMIT_INTERVAL in milliseconds, so no conversion
// happens anywhere on the path.
void test_the_rate_limit_deadline_is_one_interval_in_milliseconds(void)
{
    fresh_start(work_a, g_mac, 0x4444u);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    conflict_at(work_a, 0u, 50000u);
    TEST_ASSERT_EQUAL_HEX32(50000u + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS, IO(work_a)->deadline_ms);
}

// A held draw inside the interval reports BUSY, and at the deadline it is taken and handed over. The
// address another host answered for is not the one drawn.
void test_the_held_draw_is_released_at_the_deadline(void)
{
    fresh_start(work_a, g_mac, 0x5555u);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    uint32_t taken = IO(work_a)->ipaddr;
    conflict_at(work_a, 0u, 50000u);
    uint32_t due = IO(work_a)->deadline_ms;

    tick_at(work_a, due - 1u, 0x77u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IO(work_a)->status, "the hold ended before RATE_LIMIT_INTERVAL");
    TEST_ASSERT_FALSE(IO(work_a)->claim);

    tick_at(work_a, due, 0x77u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->claim);
    assert_in_range(IO(work_a)->ipaddr);
    TEST_ASSERT_NOT_EQUAL(taken, IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_UINT8(2u + IDEMIP_ACD_MAX_CONFLICTS, IO(work_a)->tried);
    TEST_ASSERT_EQUAL_HEX32(0u, IO(work_a)->deadline_ms);
}

// One new address per RATE_LIMIT_INTERVAL: the conflict after a released draw is held again.
void test_every_draw_past_max_conflicts_waits_an_interval(void)
{
    fresh_start(work_a, g_mac, 0x6666u);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    conflict_at(work_a, 0u, 50000u);
    tick_at(work_a, IO(work_a)->deadline_ms, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    conflict_at(work_a, 0u, 200000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->claim);
    TEST_ASSERT_EQUAL_HEX32(200000u + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS, IO(work_a)->deadline_ms);
}

// The deadline is compared as a signed difference, so a millisecond clock that rolls over past
// 0xFFFFFFFF still holds the draw for the whole interval and releases it after.
void test_the_rate_limit_survives_a_clock_rollover(void)
{
    fresh_start(work_a, g_mac, 0x7777u);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    conflict_at(work_a, 0u, 0xFFFFF000u);
    uint32_t due = IO(work_a)->deadline_ms;
    TEST_ASSERT_TRUE_MESSAGE(due < 0xFFFFF000u, "the deadline did not roll over");

    tick_at(work_a, 0xFFFFF001u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IO(work_a)->status, "a rolled over deadline read as passed");
    tick_at(work_a, due, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->claim);
}

// sec 2.2.1 counts conflicts "in the process of trying to acquire an address", which sec 2.4's
// announcement ends, so the count starts over and MAX_CONFLICTS more are answered at once.
void test_binding_the_address_starts_the_conflict_count_over(void)
{
    fresh_start(work_a, g_mac, 0x8888u);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    AutoIp.bound(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 2000u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status, "the count did not start over at sec 2.4");
    }
    conflict_at(work_a, 0u, 3000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
}

// --- the states that refuse ---------------------------------------------------

// An interface with no address out has nothing acd could have answered for or announced, and calling
// again cannot change that, so both are ERR rather than BUSY.
void test_a_conflict_and_a_bind_with_no_address_out_are_refused(void)
{
    AutoIp.clear(work_a);
    conflict_at(work_a, 0u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    AutoIp.bound(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// The same holds while a draw waits out sec 2.2.1's rate limit: no address is on the interface, so a
// conflict or an announcement over one is refused.
void test_a_conflict_and_a_bind_inside_the_rate_limit_are_refused(void)
{
    fresh_start(work_a, g_mac, 0x9999u);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    conflict_at(work_a, 0u, 50000u);
    uint32_t due = IO(work_a)->deadline_ms;

    conflict_at(work_a, 0u, 50001u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    AutoIp.bound(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(due, IO(work_a)->deadline_ms, "a refused call moved the deadline");
}

// An interface already claiming an address is left as it stands, and no second claim is asked for: the
// address is already with acd.
void test_a_second_start_asks_for_no_second_claim(void)
{
    fresh_start(work_a, g_mac, 0xAAAAu);
    uint32_t addr = IO(work_a)->ipaddr;

    start_at(work_a, g_mac, 0xBBBBu, 2000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->claim, "a second start asked acd to claim the address again");
    TEST_ASSERT_EQUAL_HEX32(addr, IO(work_a)->ipaddr);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->tried);
}

// A start on an interface whose draw is behind sec 2.2.1's rate limit reports BUSY: the same call on a
// later tick makes progress.
void test_a_start_inside_the_rate_limit_reports_busy(void)
{
    fresh_start(work_a, g_mac, 0xCCCCu);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    conflict_at(work_a, 0u, 50000u);

    start_at(work_a, g_mac, 0u, 50001u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->claim);
}

// A start over the count draws no address at once either: sec 2.2.1's limit counts new addresses, so a
// stop and a start do not buy one.
void test_a_start_after_a_stop_over_the_count_is_still_rate_limited(void)
{
    fresh_start(work_a, g_mac, 0xDDDDu);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    uint32_t taken = IO(work_a)->ipaddr;
    conflict_at(work_a, 0u, 50000u);
    AutoIp.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    start_at(work_a, g_mac, 0u, 60000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->claim);
    TEST_ASSERT_EQUAL_HEX32(60000u + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS, IO(work_a)->deadline_ms);

    tick_at(work_a, IO(work_a)->deadline_ms, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->claim);
    assert_in_range(IO(work_a)->ipaddr);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(taken, IO(work_a)->ipaddr, "a taken address came back as the candidate");
}

// --- the tick -----------------------------------------------------------------

// A sweep with no draw held ran and found nothing due, on a claiming interface and on a stopped one
// alike, and it asks for no claim.
void test_a_tick_with_nothing_due_is_ok_and_asks_for_no_claim(void)
{
    AutoIp.clear(work_a);
    tick_at(work_a, 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->claim);
    TEST_ASSERT_EQUAL_INT(IDEMIP_AUTOIP_STATE_OFF, IO(work_a)->state);

    start_at(work_a, g_mac, 0xEEEEu, 1000u);
    tick_at(work_a, 100000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->claim);
    TEST_ASSERT_EQUAL_INT(IDEMIP_AUTOIP_STATE_CHECKING, IO(work_a)->state);
}

// A tick is a function of the borrow, so a sweep with nothing due repeats: the same bytes go in and the
// same bytes come out.
void test_a_tick_with_nothing_due_repeats(void)
{
    fresh_start(work_a, g_mac, 0x0F0Fu);
    tick_at(work_a, 5000u, 0x11u);
    memcpy(work_b, work_a, IDEMIP_AUTOIP_BORROW);
    tick_at(work_a, 5000u, 0x11u);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(work_b, work_a, IDEMIP_AUTOIP_BORROW);
}

// An interface stopped while a draw was held stays stopped: a tick does not put an address back on it.
void test_a_tick_does_not_restart_a_stopped_interface(void)
{
    fresh_start(work_a, g_mac, 0x1F1Fu);
    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    conflict_at(work_a, 0u, 50000u);
    uint32_t due = IO(work_a)->deadline_ms;
    AutoIp.stop(work_a);

    tick_at(work_a, due + 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->claim, "a tick claimed an address on a stopped interface");
    TEST_ASSERT_EQUAL_INT(IDEMIP_AUTOIP_STATE_OFF, IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IO(work_a)->ipaddr);
}

// --- the borrow is the interface, with the logic in place ---------------------

// The rate limit, the conflict count and the candidate all live in the borrow, so a rogue host on one
// interface does not hold back the interface next to it.
void test_a_conflict_storm_on_one_borrow_leaves_the_other_running(void)
{
    fresh_start(work_a, g_mac, 0x2F2Fu);
    fresh_start(work_b, g_mac2, 0x3F3Fu);
    uint32_t b_addr = IO(work_b)->ipaddr;

    for (uint32_t i = 0; i < IDEMIP_ACD_MAX_CONFLICTS; i++)
    {
        conflict_at(work_a, i, 1000u);
    }
    conflict_at(work_a, 0u, 50000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);

    conflict_at(work_b, 0u, 50000u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_b)->status, "one interface's conflicts held back another");
    TEST_ASSERT_TRUE(IO(work_b)->claim);
    TEST_ASSERT_EQUAL_UINT8(2u, IO(work_b)->tried);
    TEST_ASSERT_NOT_EQUAL(b_addr, IO(work_b)->ipaddr);

    AutoIp.bound(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_b)->status);
    TEST_ASSERT_EQUAL_HEX32(0xFFFF0000u, IO(work_b)->netmask);
    TEST_ASSERT_EQUAL_INT(IDEMIP_AUTOIP_STATE_CHECKING, IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IO(work_a)->netmask);
}
