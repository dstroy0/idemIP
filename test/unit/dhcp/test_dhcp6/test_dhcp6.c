// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for dhcp6, modeled on test_phy. It tests the CONTRACT, not the protocol:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two clients share not one byte
//   4. a canary past IDEMIP_DHCP6_BORROW proves nothing wrote outside the map
//   5. the published offsets are ordered, aligned, non-overlapping and inside the borrow
//   6. clear leaves every region zeroed, and an unbound borrow is refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/dhcp/dhcp6.h"

#include <string.h>
#include <unity.h>

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_DHCP6_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_DHCP6_BORROW + 16];

// A DUID-LL (RFC 8415 sec 11.4): the 2-octet type 3, a 2-octet hardware type, then a link-layer
// address.
static const uint8_t g_duid_a[10] = {0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
static const uint8_t g_duid_b[10] = {0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};

static const IdemIpDhcp6Cfg g_cfg_a = {.duid = g_duid_a,
                                       .iaid = 0x0A0A0A0Au,
                                       .duid_len = (uint16_t)sizeof g_duid_a,
                                       .netif = 0u,
                                       .stateless = IDEMIP_FALSE,
                                       .rapid_commit = IDEMIP_FALSE};
static const IdemIpDhcp6Cfg g_cfg_b = {.duid = g_duid_b,
                                       .iaid = 0x0B0B0B0Bu,
                                       .duid_len = (uint16_t)sizeof g_duid_b,
                                       .netif = 1u,
                                       .stateless = IDEMIP_TRUE,
                                       .rapid_commit = IDEMIP_TRUE};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_DHCP6_BORROW, CANARY, cap - IDEMIP_DHCP6_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_DHCP6_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_DHCP6_BORROW");
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

static void bind_ok(uint8_t *w, const IdemIpDhcp6Cfg *cfg)
{
    IDEMIP_DHCP6_IO(w)->bind_args.cfg = cfg;
    Dhcp6.bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(w)->status);
}

// --- the borrow --------------------------------------------------------------

void test_every_entry_survives_a_null_borrow(void)
{
    Dhcp6.clear(NULL);
    Dhcp6.bind(NULL);
    Dhcp6.start(NULL);
    Dhcp6.stop(NULL);
    Dhcp6.input(NULL);
    Dhcp6.build(NULL);
    Dhcp6.tick(NULL);
    Dhcp6.confirm(NULL);
    Dhcp6.release(NULL);
    Dhcp6.decline(NULL);
    TEST_PASS();
}

// Three regions, so the map has to be ordered and non-overlapping as well as inside the borrow.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DHCP6_OFF_IO);
    TEST_ASSERT_TRUE(IDEMIP_DHCP6_OFF_IO + sizeof(Dhcp6Io) <= IDEMIP_DHCP6_OFF_CTX);
    TEST_ASSERT_TRUE(IDEMIP_DHCP6_OFF_CTX < IDEMIP_DHCP6_OFF_SERVER_DUID);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_DHCP6_BORROW,
                             (size_t)IDEMIP_DHCP6_OFF_SERVER_DUID + IDEMIP_DHCP6_SERVER_DUID_BYTES);
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DHCP6_OFF_CTX & 7u);
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DHCP6_OFF_SERVER_DUID & 7u);
}

// RFC 8415 sec 11.1 bounds a DUID at 128 octets behind its 2-octet type code, so the region carries a
// whole one.
void test_the_duid_region_holds_the_longest_duid(void)
{
    TEST_ASSERT_TRUE(IDEMIP_DHCP6_SERVER_DUID_BYTES >= IDEMIP_DHCP6_DUID_MAX);
    TEST_ASSERT_TRUE(IDEMIP_DHCP6_DUID_MAX >= 130u);
}

void test_the_io_macro_lands_on_the_published_offset(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_DHCP6_OFF_IO, IDEMIP_DHCP6_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_DHCP6_OFF_IO, IDEMIP_DHCP6_IO(work_b));
}

// clear zeroes the whole borrow, the DUID region included, so a client restarts from IDLE.
void test_clear_zeroes_the_regions(void)
{
    memset(work_a, 0xA5, IDEMIP_DHCP6_BORROW);
    Dhcp6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);

    for (size_t i = IDEMIP_DHCP6_OFF_CTX; i < IDEMIP_DHCP6_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[i], "clear left a byte of the context or the DUID set");
    }
    TEST_ASSERT_NULL(IDEMIP_DHCP6_IO(work_a)->bind_args.cfg);
    TEST_ASSERT_NULL(IDEMIP_DHCP6_IO(work_a)->input_args.msg);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_DHCP6_IO(work_a)->xid);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_DHCP6_IO(work_a)->len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_IDLE, IDEMIP_DHCP6_IO(work_a)->state);
    for (size_t i = 0; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0u, IDEMIP_DHCP6_IO(work_a)->addr[i]);
        TEST_ASSERT_EQUAL_HEX8(0u, IDEMIP_DHCP6_IO(work_a)->dst[i]);
    }
}

void test_clear_touches_one_borrow_only(void)
{
    memset(work_a, 0xA5, IDEMIP_DHCP6_BORROW);
    memset(work_b, 0xA5, IDEMIP_DHCP6_BORROW);
    Dhcp6.clear(work_a);

    for (size_t i = 0; i < IDEMIP_DHCP6_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xA5u, work_b[i], "clearing one borrow wrote into the other");
    }
}

// The borrow IS the interface, so two clients share no byte at all.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_DHCP6_IO(work_a)->bind_args.cfg = &g_cfg_a;
    IDEMIP_DHCP6_IO(work_b)->bind_args.cfg = &g_cfg_b;
    IDEMIP_DHCP6_IO(work_a)->start_args.xid = 0x00ABCDEFu;
    IDEMIP_DHCP6_IO(work_b)->start_args.xid = 0x00123456u;

    TEST_ASSERT_EQUAL_PTR(&g_cfg_a, IDEMIP_DHCP6_IO(work_a)->bind_args.cfg);
    TEST_ASSERT_EQUAL_HEX32(0x00ABCDEFu, IDEMIP_DHCP6_IO(work_a)->start_args.xid);
    TEST_ASSERT_EQUAL_PTR(&g_cfg_b, IDEMIP_DHCP6_IO(work_b)->bind_args.cfg);
    TEST_ASSERT_EQUAL_HEX32(0x00123456u, IDEMIP_DHCP6_IO(work_b)->start_args.xid);

    Dhcp6.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.bind(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_b)->status);

    // Each machine reports its own IAID, from its own configuration.
    TEST_ASSERT_EQUAL_HEX32(0x0A0A0A0Au, IDEMIP_DHCP6_IO(work_a)->iaid);
    TEST_ASSERT_EQUAL_HEX32(0x0B0B0B0Bu, IDEMIP_DHCP6_IO(work_b)->iaid);
    TEST_ASSERT_EQUAL_HEX32(0x00ABCDEFu, IDEMIP_DHCP6_IO(work_a)->start_args.xid);
}

void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    bind_ok(work_a, &g_cfg_a);

    IDEMIP_DHCP6_IO(work_b)->bind_args.cfg = NULL;
    Dhcp6.bind(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_b)->status);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(0x0A0A0A0Au, IDEMIP_DHCP6_IO(work_a)->iaid);

    Dhcp6.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
}

void test_unbound_borrow_refuses_work(void)
{
    Dhcp6.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.confirm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.decline(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
}

void test_clear_does_not_bind(void)
{
    Dhcp6.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
}

// --- bind --------------------------------------------------------------------

void test_bind_refuses_null_cfg(void)
{
    IDEMIP_DHCP6_IO(work_a)->bind_args.cfg = NULL;
    Dhcp6.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
}

// RFC 8415 sec 11.1: "The length of the DUID (not including the type code) is at least 1 octet and at
// most 128 octets", so a DUID under three octets or past IDEMIP_DHCP6_DUID_MAX is outside it.
void test_bind_refuses_an_unusable_cfg(void)
{
    IdemIpDhcp6Cfg bad = g_cfg_a;
    IDEMIP_DHCP6_IO(work_a)->bind_args.cfg = &bad;

    bad.duid = NULL;
    Dhcp6.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status, "a cfg with no DUID was accepted");

    bad = g_cfg_a;
    bad.duid_len = 2u;
    Dhcp6.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status, "a DUID of type code alone was accepted");

    bad = g_cfg_a;
    bad.duid_len = (uint16_t)(IDEMIP_DHCP6_DUID_MAX + 1u);
    Dhcp6.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status, "a DUID past the maximum was accepted");

    bad = g_cfg_a;
    bad.netif = (uint8_t)IDEMIP_NETIF_COUNT;
    Dhcp6.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status,
                                  "an interface index past the count was accepted");
}

void test_bind_accepts_a_complete_cfg(void)
{
    bind_ok(work_a, &g_cfg_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_IDLE, IDEMIP_DHCP6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0x0A0A0A0Au, IDEMIP_DHCP6_IO(work_a)->iaid);
}

// --- the wire constants ------------------------------------------------------

// RFC 8415 sec 7.3 prints the numeric encoding of each message type.
void test_the_message_types_are_as_the_rfc_prints_them(void)
{
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_DHCP6_SOLICIT);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_DHCP6_ADVERTISE);
    TEST_ASSERT_EQUAL_INT(3, IDEMIP_DHCP6_REQUEST);
    TEST_ASSERT_EQUAL_INT(4, IDEMIP_DHCP6_CONFIRM);
    TEST_ASSERT_EQUAL_INT(5, IDEMIP_DHCP6_RENEW);
    TEST_ASSERT_EQUAL_INT(6, IDEMIP_DHCP6_REBIND);
    TEST_ASSERT_EQUAL_INT(7, IDEMIP_DHCP6_REPLY);
    TEST_ASSERT_EQUAL_INT(8, IDEMIP_DHCP6_RELEASE);
    TEST_ASSERT_EQUAL_INT(9, IDEMIP_DHCP6_DECLINE);
    TEST_ASSERT_EQUAL_INT(10, IDEMIP_DHCP6_RECONFIGURE);
    TEST_ASSERT_EQUAL_INT(11, IDEMIP_DHCP6_INFORMATION_REQUEST);
    TEST_ASSERT_EQUAL_INT(12, IDEMIP_DHCP6_RELAY_FORW);
    TEST_ASSERT_EQUAL_INT(13, IDEMIP_DHCP6_RELAY_REPL);
}

// RFC 8415 sec 7.2 the ports, sec 7.1 the multicast address, sec 21.13 Table 3 the status codes, and
// sec 8 the three-octet transaction-id.
void test_the_constants_are_as_the_rfc_prints_them(void)
{
    TEST_ASSERT_EQUAL_UINT(546u, IDEMIP_DHCP6_PORT_CLIENT);
    TEST_ASSERT_EQUAL_UINT(547u, IDEMIP_DHCP6_PORT_SERVER);
    TEST_ASSERT_EQUAL_HEX32(0x00FFFFFFu, IDEMIP_DHCP6_XID_MASK);
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_DHCP6_FIXED_LEN);
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_DHCP6_STATUS_SUCCESS);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_DHCP6_STATUS_NO_ADDRS_AVAIL);
    TEST_ASSERT_EQUAL_INT(4, IDEMIP_DHCP6_STATUS_NOT_ON_LINK);
    TEST_ASSERT_EQUAL_INT(5, IDEMIP_DHCP6_STATUS_USE_MULTICAST);

    static const uint8_t all_agents[IDEMIP_IP6_ADDR_LEN] = IDEMIP_DHCP6_ALL_RELAY_AGENTS_AND_SERVERS;
    TEST_ASSERT_EQUAL_HEX8(0xffu, all_agents[0]);
    TEST_ASSERT_EQUAL_HEX8(0x02u, all_agents[1]);
    TEST_ASSERT_EQUAL_HEX8(0x01u, all_agents[13]);
    TEST_ASSERT_EQUAL_HEX8(0x02u, all_agents[15]);
}
