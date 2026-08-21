// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for dad, modeled on test_phy. It tests two things and nothing else:
//
//   the contract
//     1. the borrow is the caller's, so the suite declares it and passes it to every entry
//     2. every entry is called with a null borrow and must refuse
//     3. the borrow IS the interface, so two interfaces share not one byte
//     4. a canary past IDEMIP_DAD_BORROW is intact after every case
//     5. the published offset map is ordered, aligned, and does not overlap
//     6. clear zeroes the regions, and a borrow no one cleared is refused
//     7. BUSY and ERR are separated by whether retrying can ever succeed
//
//   RFC 4862 sec 5.4
//     every test the section states, each case naming the sentence it holds to.
//
// RFC 4862 prints no byte vectors: it states rules in prose, so what is asserted here is the property
// each sentence states. The one printed vector this unit touches is RFC 4291 sec 2.7.1's
// solicited-node range, FF02:0:0:0:0:1:FF00:0000 through FF02:0:0:0:0:1:FFFF:FFFF, which is asserted
// directly.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/nd/dad.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because RFC 4862 sec 5 performs autoconfiguration "on a
// per-interface basis". A canary follows each so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(IDEMIP_ALIGN) uint8_t work_a[IDEMIP_DAD_BORROW + 16];
static _Alignas(IDEMIP_ALIGN) uint8_t work_b[IDEMIP_DAD_BORROW + 16];

#define STATE_OFF ((size_t)IDEMIP_DAD_OFF_CTX)
#define TABLE_OFF ((size_t)IDEMIP_DAD_OFF_ENTRIES)
#define STATE_END ((size_t)IDEMIP_DAD_OFF_END)

#define IO(w) IDEMIP_DAD_IO(w)

// RFC 2464 sec 4 prints the interface identifier for the Ethernet address 34-56-78-9A-BC-DE as
// 36-56-78-FF-FE-9A-BC-DE, and sec 5 appends it to FE80::/64.
static const uint8_t g_ll_hw[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0x80, 0,    0,    0,    0,    0,    0,
                                                     0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE};
static const uint8_t g_ll_other[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
// RFC 3849 reserves 2001:DB8::/32 for documentation.
static const uint8_t g_global[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_global2[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};
static const uint8_t g_multicast[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_unspecified[IDEMIP_IP6_ADDR_LEN] = {0};

// RFC 4862 sec 5.1: DupAddrDetectTransmits, "Default: 1", and a value of zero turns the procedure off.
static const IdemIpDadCfg g_cfg_one = {1u, IDEMIP_FALSE};
static const IdemIpDadCfg g_cfg_three = {3u, IDEMIP_FALSE};
static const IdemIpDadCfg g_cfg_off = {0u, IDEMIP_FALSE};
static const IdemIpDadCfg g_cfg_loopback = {1u, IDEMIP_TRUE};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_DAD_BORROW, CANARY, cap - IDEMIP_DAD_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_DAD_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_DAD_BORROW");
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

// Every entry, in namespace order, so a new one added to DadNs is added here too.
static void call_every_entry(uint8_t *w)
{
    Dad.clear(w);
    Dad.bind(w);
    Dad.start(w);
    Dad.stop(w);
    Dad.find(w);
    Dad.ns_in(w);
    Dad.na_in(w);
    Dad.tick(w);
}

static void bind_cfg(uint8_t *w, const IdemIpDadCfg *cfg)
{
    Dad.clear(w);
    IO(w)->bind_args.cfg = cfg;
    Dad.bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(w)->status);
}

static void start_at(uint8_t *w, const uint8_t *addr, uint32_t now_ms, idemip_bool delay, idemip_bool hw_derived,
                     uint32_t retrans_ms, uint32_t rand)
{
    IO(w)->start_args.addr = addr;
    IO(w)->start_args.now_ms = now_ms;
    IO(w)->start_args.delay = delay;
    IO(w)->start_args.hw_derived = hw_derived;
    IO(w)->start_args.retrans_ms = retrans_ms;
    IO(w)->start_args.rand = rand;
    Dad.start(w);
}

static void tick_at(uint8_t *w, uint32_t now_ms)
{
    IO(w)->tick_args.now_ms = now_ms;
    Dad.tick(w);
}

static void ns_in(uint8_t *w, const uint8_t *target, idemip_bool unspecified)
{
    IO(w)->ns_in_args.target = target;
    IO(w)->ns_in_args.unspecified = unspecified;
    Dad.ns_in(w);
}

static void na_in(uint8_t *w, const uint8_t *target)
{
    IO(w)->na_in_args.target = target;
    Dad.na_in(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the interface, and the operand block is in it, so two interfaces share no byte at
// all. This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    bind_cfg(work_a, &g_cfg_one);
    bind_cfg(work_b, &g_cfg_three);

    start_at(work_a, g_ll_hw, 0u, IDEMIP_FALSE, IDEMIP_TRUE, 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    start_at(work_b, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_b)->status);

    // a's machine is still a's after b's call.
    IO(work_a)->addr_args.addr = g_ll_hw;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_b)->addr_args.addr = g_ll_hw;
    Dad.find(work_b);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_b)->status, "one borrow found the other's address");
}

// A call on one borrow reaches no byte of another, clear included, which is the widest-reaching entry
// this module has.
void test_clear_on_one_borrow_leaves_the_other_untouched(void)
{
    memset(work_b + STATE_OFF, 0xC3, STATE_END - STATE_OFF);
    Dad.clear(work_a);
    for (size_t i = STATE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[i], "clear on one borrow wrote into another");
    }
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports. This is the determinism the design is named for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    bind_cfg(work_a, &g_cfg_three);
    bind_cfg(work_b, &g_cfg_three);
    start_at(work_a, g_global, 100u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    start_at(work_b, g_global, 100u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);

    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    IdemIpMs first = IO(work_a)->deadline;
    tick_at(work_b, 100u);
    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_UINT32(first, IO(work_a)->deadline);
}

// --- the published map -------------------------------------------------------

void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DAD_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_DAD_OFF_CTX >= sizeof(DadIo),
                             "the context starts inside the operand block");
    TEST_ASSERT_TRUE_MESSAGE(TABLE_OFF >= (size_t)IDEMIP_DAD_OFF_CTX, "the table starts before the context");
    TEST_ASSERT_EQUAL_size_t(TABLE_OFF + ((size_t)IDEMIP_IP6_ADDRESSES << IDEMIP_DAD_ENTRY_SHIFT), STATE_END);
    TEST_ASSERT_TRUE_MESSAGE(STATE_END <= (size_t)IDEMIP_DAD_BORROW, "the map runs past IDEMIP_DAD_BORROW");
}

void test_every_published_offset_is_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DAD_OFF_CTX & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, TABLE_OFF & (IDEMIP_ALIGN - 1u));
}

void test_the_io_macro_reaches_the_operand_block(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_DAD_OFF_IO, (uint8_t *)IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_DAD_OFF_IO, (uint8_t *)IO(work_b));
}

// --- clear and bind ----------------------------------------------------------

void test_clear_reports_ok(void)
{
    Dad.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

void test_clear_zeroes_the_table(void)
{
    memset(work_a, 0xFF, IDEMIP_DAD_BORROW);
    Dad.clear(work_a);
    for (size_t i = TABLE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00u, work_a[i], "clear left a table byte set");
    }
}

// The context comes out zeroed apart from the four octets of the mark that says these bytes were
// cleared, so no bound configuration survives into the next use of the borrow.
void test_clear_zeroes_the_context_apart_from_the_mark(void)
{
    memset(work_a, 0xFF, IDEMIP_DAD_BORROW);
    Dad.clear(work_a);
    size_t set = 0;
    for (size_t i = STATE_OFF; i < TABLE_OFF; i++)
    {
        if (work_a[i] != 0x00u)
        {
            set++;
        }
    }
    TEST_ASSERT_EQUAL_size_t_MESSAGE(4u, set, "clear must zero the context apart from the cleared mark");
}

// The operand block is the caller's, so clear does not touch what the caller put there.
void test_clear_leaves_the_operand_block_alone(void)
{
    Dad.clear(work_a);
    IO(work_a)->start_args.addr = g_global;
    IO(work_a)->start_args.now_ms = 0x1234u;
    Dad.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_global, IO(work_a)->start_args.addr);
    TEST_ASSERT_EQUAL_UINT32(0x1234u, IO(work_a)->start_args.now_ms);
}

// A borrow no one cleared holds no mark, so every entry but clear refuses it. Retrying cannot help,
// so it is ERR.
void test_an_uncleared_borrow_is_refused(void)
{
    IO(work_a)->bind_args.cfg = &g_cfg_one;
    Dad.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    tick_at(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    ns_in(work_a, g_global, IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    na_in(work_a, g_global);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

void test_bind_refuses_a_null_configuration(void)
{
    Dad.clear(work_a);
    IO(work_a)->bind_args.cfg = NULL;
    Dad.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// sec 5.1 makes the variables a per-interface setting, so nothing runs until one is bound.
void test_start_refuses_an_unbound_borrow(void)
{
    Dad.clear(work_a);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// --- opening a machine, sec 5.4 ----------------------------------------------

// sec 5.4: the procedure runs "on all unicast addresses prior to assigning them to an interface". A
// multicast address is not one being assigned, so no retry can make it one.
void test_start_refuses_a_multicast_address(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_multicast, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// sec 5.4: "Duplicate Address Detection MUST NOT be performed on anycast addresses (note that anycast
// addresses cannot syntactically be distinguished from unicast addresses)." The octets cannot say
// which it is, so the caller does, and the same address is taken as a unicast one.
void test_start_refuses_an_anycast_address(void)
{
    bind_cfg(work_a, &g_cfg_one);
    IO(work_a)->start_args.addr = g_global;
    IO(work_a)->start_args.retrans_ms = 0u;
    IO(work_a)->start_args.rand = 0u;
    IO(work_a)->start_args.now_ms = 0u;
    IO(work_a)->start_args.delay = IDEMIP_FALSE;
    IO(work_a)->start_args.hw_derived = IDEMIP_FALSE;
    IO(work_a)->start_args.anycast = IDEMIP_TRUE;
    Dad.start(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "DAD was started on an anycast address");
    // No slot was taken, so the same address opens as a unicast one.
    IO(work_a)->start_args.anycast = IDEMIP_FALSE;
    Dad.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// RFC 4861 sec 6.3.4: "The RetransTimer variable SHOULD be copied from the Retrans Timer field, if
// the received value is non-zero." A router may put any 32-bit millisecond value there, and the wait
// sec 5.4 measures with it is that value, not a bound.
void test_a_retrans_timer_past_a_32_bit_deadline_is_served_whole(void)
{
    const uint32_t retrans = 0xFFFFFFFFu; // 49.7 days, past what a 32-bit deadline could arm

    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, retrans, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    // The first tick sends the solicitation and arms the wait at the advertised RetransTimer.
    tick_at(work_a, 0u);
    TEST_ASSERT_TRUE(IO(work_a)->send_ns);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE((IdemIpMs)retrans, IO(work_a)->deadline,
                                     "the advertised Retrans Timer was held at a bound");

    // Half way through it the address is still tentative, where a clamped deadline would have passed.
    tick_at(work_a, 0x7FFFFFFFu);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->unique, "the wait ended at half the advertised Retrans Timer");
}

void test_start_refuses_the_unspecified_address(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_unspecified, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

void test_start_refuses_a_null_address(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, NULL, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// One address is in the machine once. A second open on it is the wrong state, and a retry stays
// wrong, so it is ERR.
void test_start_refuses_an_address_already_in_the_table(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// A table with no free slot is BUSY, because a stop frees one and the same call then succeeds.
void test_a_full_table_is_busy_and_a_stop_frees_a_slot(void)
{
    bind_cfg(work_a, &g_cfg_one);
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    memcpy(addr, g_global, sizeof addr);
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_IP6_ADDRESSES; i++)
    {
        addr[15] = (uint8_t)(0x10u + i);
        start_at(work_a, addr, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }
    addr[15] = 0xEE;
    start_at(work_a, addr, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);

    uint8_t freed[IDEMIP_IP6_ADDR_LEN];
    memcpy(freed, g_global, sizeof freed);
    freed[15] = 0x10u;
    IO(work_a)->addr_args.addr = freed;
    Dad.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    addr[15] = 0xEE;
    start_at(work_a, addr, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

void test_stop_refuses_an_address_that_is_not_in_the_table(void)
{
    bind_cfg(work_a, &g_cfg_one);
    IO(work_a)->addr_args.addr = g_global;
    Dad.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

void test_find_refuses_an_address_that_is_not_in_the_table(void)
{
    bind_cfg(work_a, &g_cfg_one);
    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// sec 5.4: "An interface whose DupAddrDetectTransmits variable is set to zero does not perform
// Duplicate Address Detection."
void test_zero_transmits_skips_the_procedure(void)
{
    bind_cfg(work_a, &g_cfg_off);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->unique, "a zero DupAddrDetectTransmits leaves the address unique at once");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DAD_STATE_UNIQUE, IO(work_a)->state);
    TEST_ASSERT_FALSE(IO(work_a)->send_ns);

    // And no tick has anything to fire for it.
    tick_at(work_a, 100000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
}

// --- soliciting, sec 5.4.2 ---------------------------------------------------

// sec 5.4.2: "Before sending a Neighbor Solicitation, an interface MUST join the all-nodes multicast
// address and the solicited-node multicast address of the tentative address."
void test_the_first_tick_joins_and_solicits(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_ll_hw, 0u, IDEMIP_FALSE, IDEMIP_TRUE, 1000u, 0u);
    tick_at(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->join, "sec 5.4.2 joins before the first solicitation");
    TEST_ASSERT_TRUE(IO(work_a)->send_ns);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->sent);
}

// sec 5.4.2: "the solicitation's Target Address is set to the address being checked".
void test_the_solicitation_target_is_the_address_being_checked(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_ll_hw, 0u, IDEMIP_FALSE, IDEMIP_TRUE, 1000u, 0u);
    tick_at(work_a, 0u);
    TEST_ASSERT_NOT_NULL(IO(work_a)->target);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ll_hw, IO(work_a)->target, IDEMIP_IP6_ADDR_LEN);
}

// RFC 4291 sec 2.7.1: a solicited-node address "is formed by taking the low-order 24 bits of an
// address (unicast or anycast) and appending those bits to the prefix FF02:0:0:0:0:1:FF00::/104".
// sec 5.4.2 sets the solicitation's "IP destination ... to the solicited-node multicast address of
// the target address".
void test_the_solicited_node_address_is_the_prefix_and_the_low_24_bits(void)
{
    static const uint8_t expected[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0,    0,    0,    0,
                                                          0,    0,    0, 1, 0xFF, 0x9A, 0xBC, 0xDE};
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_ll_hw, 0u, IDEMIP_FALSE, IDEMIP_TRUE, 1000u, 0u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, IO(work_a)->solicited, IDEMIP_IP6_ADDR_LEN);
}

// The same section prints the range the result must lie in: FF02:0:0:0:0:1:FF00:0000 through
// FF02:0:0:0:0:1:FFFF:FFFF.
void test_the_solicited_node_address_lies_in_the_printed_range(void)
{
    static const uint8_t low[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xFF, 0, 0, 0};
    static const uint8_t high[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF};
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    TEST_ASSERT_TRUE(memcmp(IO(work_a)->solicited, low, IDEMIP_IP6_ADDR_LEN) >= 0);
    TEST_ASSERT_TRUE(memcmp(IO(work_a)->solicited, high, IDEMIP_IP6_ADDR_LEN) <= 0);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(low, IO(work_a)->solicited, 13);
}

// sec 5.4.2: the node "SHOULD delay joining the solicited-node multicast address by a random delay
// between 0 and MAX_RTR_SOLICITATION_DELAY", which RFC 4861 sec 10 puts at 1 second.
void test_the_delay_is_drawn_between_zero_and_max_rtr_solicitation_delay(void)
{
    bind_cfg(work_a, &g_cfg_one);
    for (uint32_t r = 0; r < 0x10000u; r += 0x0400u)
    {
        Dad.clear(work_a);
        IO(work_a)->bind_args.cfg = &g_cfg_one;
        Dad.bind(work_a);
        start_at(work_a, g_global, 1000u, IDEMIP_TRUE, IDEMIP_FALSE, 1000u, r);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->deadline >= 1000u, "the delay ran backwards");
        TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->deadline <= 1000u + IDEMIP_ND6_MAX_RTR_SOLICITATION_DELAY_MS,
                                 "the delay ran past MAX_RTR_SOLICITATION_DELAY");
    }
}

// The delay holds the join and the solicitation back until it is due, and nothing else is due
// meanwhile, which is BUSY and not a fault.
void test_the_delay_holds_the_first_solicitation_back(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_TRUE, IDEMIP_FALSE, 1000u, 0xFFFFu);
    // The deadline is a 64-bit stamp; tick takes the 32-bit clock the API is stated in, and this
    // one was computed from a 32-bit now_ms, so the narrowing is exact and is spelled out.
    IdemIpMs due = IO(work_a)->deadline;
    TEST_ASSERT_TRUE(due > 0u);
    tick_at(work_a, (uint32_t)(due - 1u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->send_ns);
    tick_at(work_a, (uint32_t)due);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->send_ns);
}

// Without the sec 5.4.2 delay the first solicitation is due on the next tick.
void test_no_delay_solicits_on_the_next_tick(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 500u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0xFFFFu);
    TEST_ASSERT_EQUAL_UINT32(500u, IO(work_a)->deadline);
    tick_at(work_a, 500u);
    TEST_ASSERT_TRUE(IO(work_a)->send_ns);
}

// sec 5.4.2: "a node sends DupAddrDetectTransmits Neighbor Solicitations, each separated by
// RetransTimer milliseconds".
void test_solicitations_are_spaced_by_retrans_timer(void)
{
    bind_cfg(work_a, &g_cfg_three);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 700u, 0u);
    for (uint8_t i = 1; i <= 3u; i++)
    {
        // A millisecond before the deadline nothing is due, so the spacing is a floor and not just
        // the value the deadline was armed with.
        if (i > 1u)
        {
            tick_at(work_a, (uint32_t)(i - 1u) * 700u - 1u);
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IO(work_a)->status,
                                          "a solicitation went out before RetransTimer had passed");
            TEST_ASSERT_FALSE(IO(work_a)->send_ns);
        }
        tick_at(work_a, (uint32_t)(i - 1u) * 700u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->send_ns, "a solicitation was not due when RetransTimer had passed");
        TEST_ASSERT_EQUAL_UINT8(i, IO(work_a)->sent);
        TEST_ASSERT_EQUAL_UINT32((uint32_t)i * 700u, IO(work_a)->deadline);

        // sec 5.4.2: "Before sending a Neighbor Solicitation, an interface MUST join the all-nodes
        // multicast address and the solicited-node multicast address of the tentative address." The
        // join is the first solicitation's, the delay above having held it back, and a later one
        // joins nothing it is not already in.
        if (i == 1u)
        {
            TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->join, "the first solicitation did not join the groups");
        }
        else
        {
            TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->join, "a group was joined again mid-procedure");
        }

        // The state each solicitation leaves. Without this the suite cannot tell PROBING from WAIT,
        // and a procedure that ended one RetransTimer early would read the same.
        if (i < 3u)
        {
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DAD_STATE_PROBING, IO(work_a)->state,
                                          "solicitations remain, so the procedure is still probing");
        }
        else
        {
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DAD_STATE_WAIT, IO(work_a)->state,
                                          "the last solicitation begins sec 5.1's wait, not another probe");
        }
        TEST_ASSERT_FALSE(IO(work_a)->unique);

        // sec 5.4: the address stays tentative for the whole procedure, which is what makes
        // sec 5.4.3's "MUST NOT respond to a Neighbor Solicitation for a tentative address" hold
        // through every one of the three. tick does not report it, find does.
        IO(work_a)->addr_args.addr = g_global;
        Dad.find(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->tentative, "the address is tentative until the procedure ends");
    }

    // sec 5.4: unique when nothing fires "within RetransTimer milliseconds after having sent
    // DupAddrDetectTransmits Neighbor Solicitations". Three were sent, so that is one RetransTimer
    // past the third and no sooner, and no fourth solicitation goes out.
    tick_at(work_a, 2100u - 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->unique);

    tick_at(work_a, 2100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->unique, "the procedure did not end one RetransTimer after the last NS");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DAD_STATE_UNIQUE, IO(work_a)->state);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->send_ns, "a fourth solicitation went out past DupAddrDetectTransmits");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(3u, IO(work_a)->sent, "the count must stop at DupAddrDetectTransmits");

    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->tentative, "an address the procedure passed is no longer tentative");
}

// sec 5.4: the address is unique when no test fires "within RetransTimer milliseconds after having
// sent DupAddrDetectTransmits Neighbor Solicitations", which sec 5.1 states as "the time a node waits
// after sending the last Neighbor Solicitation before ending the Duplicate Address Detection
// process".
void test_the_procedure_ends_one_retrans_timer_after_the_last_solicitation(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 700u, 0u);
    tick_at(work_a, 0u);
    TEST_ASSERT_TRUE(IO(work_a)->send_ns);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DAD_STATE_WAIT, IO(work_a)->state);

    tick_at(work_a, 699u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->unique);

    tick_at(work_a, 700u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->unique, "the address was not declared unique after RetransTimer");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DAD_STATE_UNIQUE, IO(work_a)->state);
}

// The same wait, with a RetransTimer no deadline can hold. RFC 4861 sec 6.3.4 lets a Router
// Advertisement set that timer, so the value reaching start is a remote party's. A deadline is an
// absolute stamp read as a span below half the clock's range, so a value past that bound arms one
// already due and sec 5.4's "within RetransTimer milliseconds after having sent
// DupAddrDetectTransmits Neighbor Solicitations" collapses to the next tick - the address is
// declared unique a millisecond after the single solicitation, before any defence could arrive.
void test_a_retrans_timer_past_the_deadline_span_still_waits(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0xFFFFFFFFu, 0u);
    tick_at(work_a, 0u);
    TEST_ASSERT_TRUE(IO(work_a)->send_ns);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DAD_STATE_WAIT, IO(work_a)->state);

    tick_at(work_a, 1u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IO(work_a)->status, "the wait ended on the tick after the NS");
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->unique,
                              "a RetransTimer past the deadline span ended the wait on the next tick");
}

// RFC 4861 sec 6.3.4: an unspecified field "should be ignored and the host should continue using
// whatever value it is already using", so a zero RetransTimer takes RFC 4861 sec 10's 1,000 ms.
void test_a_zero_retrans_timer_takes_the_rfc_4861_default(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 0u, 0u);
    tick_at(work_a, 0u);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_ND6_RETRANS_TIMER_MS, IO(work_a)->deadline);
}

// A tick with no deadline reached is BUSY: nothing is wrong, and a later tick makes progress.
void test_a_tick_with_nothing_due_is_busy(void)
{
    bind_cfg(work_a, &g_cfg_one);
    tick_at(work_a, 5000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
}

// One event per call, so two machines due at once take two ticks and neither is lost.
void test_a_tick_reports_one_event_per_call(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    start_at(work_a, g_global2, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);

    tick_at(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_global, IO(work_a)->target, IDEMIP_IP6_ADDR_LEN);
    tick_at(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_global2, IO(work_a)->target, IDEMIP_IP6_ADDR_LEN);
    tick_at(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
}

// --- receiving a solicitation, sec 5.4.3 -------------------------------------

// sec 5.4.3: "If a Neighbor Solicitation for a tentative address is received before one is sent, the
// tentative address is a duplicate."
void test_a_solicitation_received_before_one_is_sent_is_a_duplicate(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    ns_in(work_a, g_global, IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->duplicate, "a solicitation before one was sent is a duplicate");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DAD_STATE_DUPLICATE, IO(work_a)->state);
}

// sec 5.4.3: "If the actual number of Neighbor Solicitations received exceeds the number expected
// based on the loopback semantics (e.g., the interface does not loop back the packet, yet one or more
// solicitations was received), the tentative address is a duplicate."
void test_a_solicitation_beyond_the_loopback_expectation_is_a_duplicate(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    tick_at(work_a, 0u);
    TEST_ASSERT_TRUE(IO(work_a)->send_ns);

    // This interface does not loop back, so one received solicitation is one too many.
    ns_in(work_a, g_global, IDEMIP_TRUE);
    TEST_ASSERT_TRUE(IO(work_a)->duplicate);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->received);
}

// The same rule the other way: an interface that loops its own multicast back expects the ones it
// sent, so the first one is not a duplicate and the one past it is.
void test_a_looped_back_solicitation_is_not_a_duplicate(void)
{
    bind_cfg(work_a, &g_cfg_loopback);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    tick_at(work_a, 0u);
    TEST_ASSERT_TRUE(IO(work_a)->send_ns);

    ns_in(work_a, g_global, IDEMIP_TRUE);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->duplicate, "the node's own looped-back solicitation is not a duplicate");
    TEST_ASSERT_TRUE(IO(work_a)->tentative);

    ns_in(work_a, g_global, IDEMIP_TRUE);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->duplicate, "a second solicitation exceeds what loopback explains");
}

// sec 5.4.3: "If the target address is tentative, and the source address is a unicast address, the
// solicitation's sender is performing address resolution on the target; the solicitation should be
// silently ignored."
void test_a_solicitation_from_a_unicast_source_is_ignored(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    tick_at(work_a, 0u);
    ns_in(work_a, g_global, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->duplicate, "a unicast-sourced solicitation is not a duplicate test");
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->received);
    TEST_ASSERT_TRUE(IO(work_a)->tentative);
}

// sec 5.4.3: "If the target address is not tentative (i.e., it is assigned to the receiving
// interface), the solicitation is processed as described in [RFC4861]", which is what a false
// tentative reports.
void test_a_solicitation_for_an_unknown_target_is_not_tentative(void)
{
    bind_cfg(work_a, &g_cfg_one);
    ns_in(work_a, g_global, IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->tentative);
    TEST_ASSERT_FALSE(IO(work_a)->duplicate);
}

// An address the procedure already declared unique is assigned, so a solicitation for it is
// RFC 4861's to process and not a sec 5.4.3 test.
void test_a_solicitation_for_a_unique_address_is_not_tentative(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 700u, 0u);
    tick_at(work_a, 0u);
    tick_at(work_a, 700u);
    TEST_ASSERT_TRUE(IO(work_a)->unique);
    ns_in(work_a, g_global, IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->tentative);
    TEST_ASSERT_FALSE(IO(work_a)->duplicate);
}

// --- receiving an advertisement, sec 5.4.4 -----------------------------------

// sec 5.4.4 (1): "If the target address is tentative, the tentative address is not unique."
void test_an_advertisement_for_a_tentative_address_is_a_duplicate(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    tick_at(work_a, 0u);
    na_in(work_a, g_global);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->duplicate);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DAD_STATE_DUPLICATE, IO(work_a)->state);
}

// sec 5.4.4 (3): "Otherwise, the advertisement is processed as described in [RFC4861]."
void test_an_advertisement_for_an_unknown_target_is_not_tentative(void)
{
    bind_cfg(work_a, &g_cfg_one);
    na_in(work_a, g_global);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->tentative);
    TEST_ASSERT_FALSE(IO(work_a)->duplicate);
}

// --- when detection fails, sec 5.4.5 -----------------------------------------

// sec 5.4.5: "If the address is a link-local address formed from an interface identifier based on the
// hardware address, which is supposed to be uniquely assigned (e.g., EUI-64 for an Ethernet
// interface), IP operation on the interface SHOULD be disabled."
void test_a_duplicate_hardware_derived_link_local_disables_ip(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_ll_hw, 0u, IDEMIP_FALSE, IDEMIP_TRUE, 1000u, 0u);
    na_in(work_a, g_ll_hw);
    TEST_ASSERT_TRUE(IO(work_a)->duplicate);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->disable_ip, "sec 5.4.5 disables IP operation on this one");
}

// sec 5.4.5: "if the duplicate link-local address is not formed from an interface identifier based on
// the hardware address, which is supposed to be uniquely assigned, IP operation on the interface MAY
// be continued."
void test_a_duplicate_link_local_that_is_not_hardware_derived_leaves_ip_up(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_ll_other, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    na_in(work_a, g_ll_other);
    TEST_ASSERT_TRUE(IO(work_a)->duplicate);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->disable_ip, "only a hardware-derived link-local disables IP operation");
}

// The rule is about a link-local address, so a duplicate global address formed from the same
// hardware identifier does not disable IP operation.
void test_a_duplicate_global_address_does_not_disable_ip(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_TRUE, 1000u, 0u);
    na_in(work_a, g_global);
    TEST_ASSERT_TRUE(IO(work_a)->duplicate);
    TEST_ASSERT_FALSE(IO(work_a)->disable_ip);
}

// sec 5.4.5: a duplicate "MUST NOT be assigned to an interface", so no later tick ever declares it
// unique.
void test_a_duplicate_never_becomes_unique(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 700u, 0u);
    tick_at(work_a, 0u);
    na_in(work_a, g_global);
    TEST_ASSERT_TRUE(IO(work_a)->duplicate);
    for (uint32_t t = 700u; t <= 7000u; t += 700u)
    {
        tick_at(work_a, t);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IO(work_a)->status, "a duplicate still had a deadline to fire");
        TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->unique, "a duplicate address was declared unique");
    }
}

// A duplicate holds its slot until the caller stops it, so find keeps reporting the same answer.
void test_a_duplicate_holds_its_answer_until_it_is_stopped(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 700u, 0u);
    na_in(work_a, g_global);
    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DAD_STATE_DUPLICATE, IO(work_a)->state);
    TEST_ASSERT_FALSE(IO(work_a)->tentative);

    IO(work_a)->addr_args.addr = g_global;
    Dad.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// Two interfaces run their own machines: a duplicate on one says nothing about the other.
void test_two_borrows_run_independent_machines(void)
{
    bind_cfg(work_a, &g_cfg_one);
    bind_cfg(work_b, &g_cfg_one);
    start_at(work_a, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 700u, 0u);
    start_at(work_b, g_global, 0u, IDEMIP_FALSE, IDEMIP_FALSE, 700u, 0u);

    na_in(work_a, g_global);
    TEST_ASSERT_TRUE(IO(work_a)->duplicate);

    IO(work_b)->addr_args.addr = g_global;
    Dad.find(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_b)->status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DAD_STATE_DELAY, IO(work_b)->state,
                                  "a duplicate on one interface moved the other's machine");

    tick_at(work_b, 0u);
    tick_at(work_b, 700u);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_b)->unique, "the second interface's address was held back by the first's");
}

// --- the operands an entry cannot work from -------------------------------------

// Every entry works over an address the caller holds, and one naming none has nothing to look up. A
// borrow clear has not run on is not a table either, and neither is one nobody bound a configuration
// to: RFC 4862 sec 5.4 counts the solicitations by DupAddrDetectTransmits, which the configuration
// carries.
void test_the_entries_refuse_a_call_that_names_no_address(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 1000u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->addr_args.addr = NULL;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "a lookup for no address was answered");
    Dad.stop(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "a stop of no address was made");

    ns_in(work_a, NULL, IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "a solicitation for no target was taken");
    na_in(work_a, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "an advertisement for no target was taken");

    // Bytes clear has not run on.
    memset(work_b, 0xFF, IDEMIP_DAD_BORROW);
    IO(work_b)->addr_args.addr = g_global;
    Dad.find(work_b);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_b)->status, "find read an uncleared borrow");
    Dad.stop(work_b);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_b)->status, "stop read an uncleared borrow");
    ns_in(work_b, g_global, IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_b)->status, "ns_in read an uncleared borrow");
    na_in(work_b, g_global);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_b)->status, "na_in read an uncleared borrow");
    tick_at(work_b, 1000u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_b)->status, "tick read an uncleared borrow");

    // Cleared, and with no configuration bound to it.
    Dad.clear(work_b);
    tick_at(work_b, 1000u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_b)->status, "a tick ran with no configuration bound");
}

// RFC 4291 sec 2.5.6: the link-local prefix is ten bits, so FEC0::/10 shares the first octet and is
// not link-local. RFC 4862 sec 5.4.5 stops an interface whose link-local address is a duplicate, and
// that is the address the rule reads.
void test_the_link_local_test_is_the_first_ten_bits(void)
{
    static const uint8_t site_local[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, site_local, 1000u, IDEMIP_FALSE, IDEMIP_TRUE, 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    na_in(work_a, site_local);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->disable_ip,
                              "an address sharing the link-local first octet stopped the interface");
}

// RFC 4862 sec 5.4.3: an advertisement whose Target Address is one this node holds is a duplicate
// only while that address is tentative. Once sec 5.4.4 has made it unique the advertisement says
// nothing about it - the two hosts are the same host, or the neighbour is confused - and RFC 4861
// sec 7.2.5 is where a reply to it belongs.
void test_an_advertisement_about_an_address_already_unique_is_not_a_duplicate(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 1000u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    tick_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    tick_at(work_a, 3000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DAD_STATE_UNIQUE, IO(work_a)->state, "the address never became unique");

    na_in(work_a, g_global);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->tentative, "a unique address was reported as tentative");
    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DAD_STATE_UNIQUE, IO(work_a)->state,
                                  "an advertisement made a unique address a duplicate");
}

// RFC 4862 sec 5.4.3's second test is on "the actual number of Neighbor Solicitations received
// exceeds the number expected based on the loopback semantics", so an interface that loops its own
// back expects every one it sent. DupAddrDetectTransmits is one octet, so an interface can be asked
// for as many solicitations as the count of received ones can hold - and the count holds there
// rather than turning over and reading as fewer than were sent.
void test_the_count_of_looped_back_solicitations_holds_at_the_top_of_its_width(void)
{
    static const IdemIpDadCfg cfg_many = {0xFFu, IDEMIP_TRUE};
    bind_cfg(work_a, &cfg_many);
    start_at(work_a, g_global, 1000u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    // One solicitation out and the same one back, as many times as the octet holds.
    uint32_t now = 1000u;
    for (uint32_t k = 0; k < 0xFFu; k++)
    {
        tick_at(work_a, now);
        now += 1000u;
        ns_in(work_a, g_global, IDEMIP_TRUE);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }

    // The count is at the top of its octet now, and the address is still waiting out the last
    // solicitation. Two more loopbacks land on a count that cannot rise, and do not read as
    // solicitations from somebody else.
    ns_in(work_a, g_global, IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    ns_in(work_a, g_global, IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    // Every solicitation it saw was one of its own, so the address is still tentative and not a
    // duplicate: the count never rose above the number sent.
    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(IDEMIP_DAD_STATE_DUPLICATE, IO(work_a)->state,
                                      "the count of loopbacks turned over and read as another node's");
}

// RFC 4862 sec 5.4.5: an address the detection found a duplicate for "MUST NOT be assigned to an
// interface", and the sweep that runs the detection has nothing left to do for it - the same way it
// has nothing left for one already unique. Both are passed over, and the entry behind them is not.
void test_the_sweep_passes_over_an_address_it_has_already_decided(void)
{
    bind_cfg(work_a, &g_cfg_one);

    // One address made a duplicate by an advertisement while it was tentative.
    start_at(work_a, g_global, 1000u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    tick_at(work_a, 1000u);
    na_in(work_a, g_global);
    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DAD_STATE_DUPLICATE, IO(work_a)->state,
                                  "the advertisement was not a duplicate");

    // A second address behind it, which the sweep does reach.
    start_at(work_a, g_global2, 1000u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    tick_at(work_a, 2000u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status,
                                  "the sweep stopped at the address it had already decided");
    IO(work_a)->addr_args.addr = g_global2;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1u, IO(work_a)->sent, "the second address never had its solicitation sent");
}

// RFC 4862 sec 5.4.4: the address is unique once "no Neighbor Advertisement is received" over the
// whole of the detection, which includes the interval after the last solicitation goes out. An
// advertisement arriving inside that interval is still about a tentative address.
void test_an_advertisement_inside_the_last_interval_is_still_about_a_tentative_address(void)
{
    bind_cfg(work_a, &g_cfg_one);
    start_at(work_a, g_global, 1000u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    tick_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    // The one solicitation this configuration asks for has gone out and the wait is running.
    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DAD_STATE_WAIT, IO(work_a)->state, "the solicitation did not start the wait");

    na_in(work_a, g_global);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->tentative, "an address inside its last interval was not tentative");
    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DAD_STATE_DUPLICATE, IO(work_a)->state,
                                  "an advertisement inside the last interval did not make the address a duplicate");
}

// RFC 4862 sec 5.4 sends DupAddrDetectTransmits solicitations, and the address is tentative for all
// of them: an advertisement arriving between two of them is about a tentative address as much as one
// arriving after the last.
void test_an_advertisement_between_two_solicitations_is_about_a_tentative_address(void)
{
    bind_cfg(work_a, &g_cfg_three);
    start_at(work_a, g_global, 1000u, IDEMIP_FALSE, IDEMIP_FALSE, 1000u, 0u);
    tick_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DAD_STATE_PROBING, IO(work_a)->state,
                                  "the first of three solicitations did not leave the address probing");

    na_in(work_a, g_global);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->tentative, "an address between two solicitations was not tentative");
    IO(work_a)->addr_args.addr = g_global;
    Dad.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DAD_STATE_DUPLICATE, IO(work_a)->state);
}
