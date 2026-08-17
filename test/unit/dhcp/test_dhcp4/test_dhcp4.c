// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for dhcp4, modeled on test_phy. It tests the CONTRACT, not the protocol:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two lease machines share not one byte
//   4. a canary past IDEMIP_DHCP4_BORROW proves nothing wrote outside the map
//   5. the published offsets are ordered, aligned and inside the borrow
//   6. clear leaves every region zeroed, and an unbound borrow is refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/dhcp/dhcp4.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_DHCP4_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_DHCP4_BORROW + 16];

static const uint8_t g_mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
static const uint8_t g_mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};

// RFC 2131 sec 2, Table 1: 'htype' is an ARP hardware type, '1' = 10mb ethernet, and 'hlen' is 6 for
// it.
static const IdemIpDhcp4Cfg g_cfg_a = {
    .chaddr = g_mac_a, .lease_s = 7200u, .netif = 0u, .htype = 1u, .hlen = 6u, .broadcast = IDEMIP_TRUE};
static const IdemIpDhcp4Cfg g_cfg_b = {
    .chaddr = g_mac_b, .lease_s = 3600u, .netif = 1u, .htype = 1u, .hlen = 6u, .broadcast = IDEMIP_FALSE};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_DHCP4_BORROW, CANARY, cap - IDEMIP_DHCP4_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_DHCP4_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_DHCP4_BORROW");
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

static void bind_ok(uint8_t *w, const IdemIpDhcp4Cfg *cfg)
{
    IDEMIP_DHCP4_IO(w)->bind_args.cfg = cfg;
    Dhcp4.bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(w)->status);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Dhcp4.clear(NULL);
    Dhcp4.bind(NULL);
    Dhcp4.start(NULL);
    Dhcp4.stop(NULL);
    Dhcp4.input(NULL);
    Dhcp4.build(NULL);
    Dhcp4.tick(NULL);
    Dhcp4.release(NULL);
    Dhcp4.decline(NULL);
    Dhcp4.inform(NULL);
    TEST_PASS();
}

// The map is public, so a reader can see every region without opening the .c. It has to be ordered,
// aligned, and inside the borrow.
void test_the_published_offsets_are_ordered_and_fit(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DHCP4_OFF_IO);
    TEST_ASSERT_TRUE(IDEMIP_DHCP4_OFF_IO + sizeof(Dhcp4Io) <= IDEMIP_DHCP4_OFF_CTX);
    TEST_ASSERT_TRUE(IDEMIP_DHCP4_OFF_CTX < IDEMIP_DHCP4_BORROW);
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DHCP4_OFF_CTX & 7u);
}

// The operand block is at its published offset in the caller's bytes and nowhere else.
void test_the_io_macro_lands_on_the_published_offset(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_DHCP4_OFF_IO, IDEMIP_DHCP4_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_DHCP4_OFF_IO, IDEMIP_DHCP4_IO(work_b));
}

// clear zeroes the whole borrow, so a machine restarts from the INIT of RFC 2131 sec 4.4.1.
void test_clear_zeroes_the_regions(void)
{
    memset(work_a, 0xA5, IDEMIP_DHCP4_BORROW);
    Dhcp4.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);

    for (size_t i = IDEMIP_DHCP4_OFF_CTX; i < IDEMIP_DHCP4_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[i], "clear left a byte of the context set");
    }
    TEST_ASSERT_NULL(IDEMIP_DHCP4_IO(work_a)->bind_args.cfg);
    TEST_ASSERT_NULL(IDEMIP_DHCP4_IO(work_a)->input_args.msg);
    TEST_ASSERT_NULL(IDEMIP_DHCP4_IO(work_a)->build_args.out);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_DHCP4_IO(work_a)->xid);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_DHCP4_IO(work_a)->offered_ip);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_DHCP4_IO(work_a)->len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);
}

// Clearing one machine does not touch the other's bytes.
void test_clear_touches_one_borrow_only(void)
{
    memset(work_a, 0xA5, IDEMIP_DHCP4_BORROW);
    memset(work_b, 0xA5, IDEMIP_DHCP4_BORROW);
    Dhcp4.clear(work_a);

    for (size_t i = 0; i < IDEMIP_DHCP4_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xA5u, work_b[i], "clearing one borrow wrote into the other");
    }
}

// The borrow IS the interface, and the operand block is in it, so two lease machines share no byte at
// all. This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_DHCP4_IO(work_a)->bind_args.cfg = &g_cfg_a;
    IDEMIP_DHCP4_IO(work_b)->bind_args.cfg = &g_cfg_b;
    IDEMIP_DHCP4_IO(work_a)->start_args.xid = 0x11223344u;
    IDEMIP_DHCP4_IO(work_b)->start_args.xid = 0x55667788u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_PTR(&g_cfg_a, IDEMIP_DHCP4_IO(work_a)->bind_args.cfg);
    TEST_ASSERT_EQUAL_HEX32(0x11223344u, IDEMIP_DHCP4_IO(work_a)->start_args.xid);
    TEST_ASSERT_EQUAL_PTR(&g_cfg_b, IDEMIP_DHCP4_IO(work_b)->bind_args.cfg);
    TEST_ASSERT_EQUAL_HEX32(0x55667788u, IDEMIP_DHCP4_IO(work_b)->start_args.xid);

    Dhcp4.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    Dhcp4.bind(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_b)->status);

    // And a's result is still a's after b's call.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(0x11223344u, IDEMIP_DHCP4_IO(work_a)->start_args.xid);
}

// An entry is a function of its borrow alone, so a call that fails on one borrow cannot change what
// the other reports. This is the determinism the design is named for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    bind_ok(work_a, &g_cfg_a);

    IDEMIP_DHCP4_IO(work_b)->bind_args.cfg = NULL;
    Dhcp4.bind(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_b)->status);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(&g_cfg_a, IDEMIP_DHCP4_IO(work_a)->bind_args.cfg);

    // Binding a again, on the same bytes, reports the same thing.
    Dhcp4.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
}

// Zeroed, never bound: every entry that needs the configuration must refuse rather than run without
// one.
void test_unbound_borrow_refuses_work(void)
{
    Dhcp4.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    Dhcp4.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    Dhcp4.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    Dhcp4.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    Dhcp4.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    Dhcp4.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    Dhcp4.decline(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    Dhcp4.inform(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
}

// A cleared borrow is not a bound one: clear reports OK and leaves the machine unconfigured.
void test_clear_does_not_bind(void)
{
    Dhcp4.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    Dhcp4.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
}

// --- bind --------------------------------------------------------------------

void test_bind_refuses_null_cfg(void)
{
    IDEMIP_DHCP4_IO(work_a)->bind_args.cfg = NULL;
    Dhcp4.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
}

// RFC 2131 sec 2 gives 'chaddr' 16 octets and 'hlen' counts how many carry the address, so 0 and 17
// are both outside it, and the address itself has to be there.
void test_bind_refuses_an_unusable_cfg(void)
{
    IdemIpDhcp4Cfg bad = g_cfg_a;
    bad.chaddr = NULL;
    IDEMIP_DHCP4_IO(work_a)->bind_args.cfg = &bad;
    Dhcp4.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status, "a cfg with no chaddr was accepted");

    bad = g_cfg_a;
    bad.hlen = 0u;
    Dhcp4.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status, "hlen 0 was accepted");

    bad = g_cfg_a;
    bad.hlen = (uint8_t)(IDEMIP_DHCP4_CHADDR_LEN + 1u);
    Dhcp4.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status, "hlen past chaddr was accepted");

    bad = g_cfg_a;
    bad.netif = (uint8_t)IDEMIP_NETIF_COUNT;
    Dhcp4.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status, "an interface index past the count was accepted");
}

void test_bind_accepts_a_complete_cfg(void)
{
    bind_ok(work_a, &g_cfg_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);
}

// --- the wire constants ------------------------------------------------------

// The states of RFC 2131 sec 4.4, Figure 5, are distinct and INIT is the zero one, so a cleared
// borrow is in the state sec 4.4.1 begins in.
void test_the_states_of_figure_5_are_distinct(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_DHCP4_INIT);
    TEST_ASSERT_TRUE(IDEMIP_DHCP4_SELECTING != IDEMIP_DHCP4_REQUESTING);
    TEST_ASSERT_TRUE(IDEMIP_DHCP4_BOUND != IDEMIP_DHCP4_RENEWING);
    TEST_ASSERT_TRUE(IDEMIP_DHCP4_RENEWING != IDEMIP_DHCP4_REBINDING);
    TEST_ASSERT_TRUE(IDEMIP_DHCP4_INIT_REBOOT != IDEMIP_DHCP4_REBOOTING);
}

// RFC 2132 sec 9.6 prints the option 53 values, and RFC 2131 sec 4.1 the two ports.
void test_the_message_types_and_ports_are_as_the_rfc_prints_them(void)
{
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_DHCP4_DISCOVER);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_DHCP4_OFFER);
    TEST_ASSERT_EQUAL_INT(3, IDEMIP_DHCP4_REQUEST);
    TEST_ASSERT_EQUAL_INT(4, IDEMIP_DHCP4_DECLINE);
    TEST_ASSERT_EQUAL_INT(5, IDEMIP_DHCP4_ACK);
    TEST_ASSERT_EQUAL_INT(6, IDEMIP_DHCP4_NAK);
    TEST_ASSERT_EQUAL_INT(7, IDEMIP_DHCP4_RELEASE);
    TEST_ASSERT_EQUAL_INT(8, IDEMIP_DHCP4_INFORM);
    TEST_ASSERT_EQUAL_UINT(67u, IDEMIP_DHCP4_PORT_SERVER);
    TEST_ASSERT_EQUAL_UINT(68u, IDEMIP_DHCP4_PORT_CLIENT);
    TEST_ASSERT_EQUAL_HEX32(0x63825363u, IDEMIP_DHCP4_MAGIC_COOKIE);
    TEST_ASSERT_EQUAL_UINT(240u, IDEMIP_DHCP4_FIXED_LEN);
}
