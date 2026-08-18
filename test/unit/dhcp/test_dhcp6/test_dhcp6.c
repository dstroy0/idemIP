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
// The behavior half below drives the RFC 8415 exchanges. RFC 8415 prints no byte-level example
// message anywhere, so there is no capture to replay: the vectors here are the field layouts of
// sec 8 Figure 2 and sec 21 Figures 12 through 25, the sec 7.6 Table 1 timeouts, the sec 21.13
// Table 3 status codes, and the properties sec 15, sec 16 and sec 18.2 state in prose.
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

// =============================================================================
// The behavior half: the RFC 8415 exchanges
// =============================================================================

static _Alignas(8) uint8_t probe[IDEMIP_DHCP6_BORROW];
static uint8_t g_msg[512];
static size_t g_msg_len;
static uint8_t g_out[512];
static size_t g_out_len;

// RFC 3849 sec 4 sets 2001:db8::/32 aside for documentation, so the leases here are inside it.
static const uint8_t g_src[IDEMIP_IP6_ADDR_LEN] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_lease[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a};
static const uint8_t g_lease2[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
static const uint8_t g_sduid[8] = {0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd};
static const uint8_t g_sduid2[8] = {0x00, 0x03, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44};

// A stateful client that asks for the sec 21.14 two-message exchange.
static const IdemIpDhcp6Cfg g_cfg_rc = {.duid = g_duid_a,
                                        .iaid = 0x0A0A0A0Au,
                                        .duid_len = (uint16_t)sizeof g_duid_a,
                                        .netif = 0u,
                                        .stateless = IDEMIP_FALSE,
                                        .rapid_commit = IDEMIP_TRUE};

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)((v >> 16) & 0xFFu);
    p[2] = (uint8_t)((v >> 8) & 0xFFu);
    p[3] = (uint8_t)(v & 0xFFu);
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// RFC 8415 sec 8, Figure 2: msg-type then the 3-octet transaction-id.
static void msg_begin(uint8_t type, uint32_t xid)
{
    memset(g_msg, 0, sizeof g_msg);
    g_msg[IDEMIP_DHCP6_MSG_OFF_TYPE] = type;
    g_msg[IDEMIP_DHCP6_MSG_OFF_XID] = (uint8_t)(xid >> 16);
    g_msg[IDEMIP_DHCP6_MSG_OFF_XID + 1u] = (uint8_t)(xid >> 8);
    g_msg[IDEMIP_DHCP6_MSG_OFF_XID + 2u] = (uint8_t)xid;
    g_msg_len = IDEMIP_DHCP6_FIXED_LEN;
}

// RFC 8415 sec 21.1, Figure 12: option-code, option-len, then option-len octets.
static uint8_t *msg_opt(uint16_t code, uint16_t len)
{
    put16(g_msg + g_msg_len, code);
    put16(g_msg + g_msg_len + 2u, len);
    uint8_t *d = g_msg + g_msg_len + IDEMIP_DHCP6_OPT_HDR_LEN;
    g_msg_len += (size_t)IDEMIP_DHCP6_OPT_HDR_LEN + len;
    return d;
}

static void msg_clientid(const IdemIpDhcp6Cfg *cfg)
{
    memcpy(msg_opt(IDEMIP_DHCP6_OPT_CLIENTID, cfg->duid_len), cfg->duid, cfg->duid_len);
}

static void msg_serverid(const uint8_t *duid, uint16_t len)
{
    memcpy(msg_opt(IDEMIP_DHCP6_OPT_SERVERID, len), duid, len);
}

static void msg_pref(uint8_t value)
{
    msg_opt(IDEMIP_DHCP6_OPT_PREFERENCE, IDEMIP_DHCP6_PREFERENCE_LEN)[0] = value;
}

static void msg_status(uint16_t code)
{
    put16(msg_opt(IDEMIP_DHCP6_OPT_STATUS_CODE, IDEMIP_DHCP6_STATUS_LEN), code);
}

// RFC 8415 sec 21.4, Figure 15, with the sec 21.6 Figure 17 IA Address inside it when @p addr is
// given, and an optional IA_NA-options Status Code when @p status is not Success.
static void msg_ia_na(uint32_t iaid, uint32_t t1, uint32_t t2, const uint8_t *addr, uint32_t preferred,
                      uint32_t valid, int with_status, uint16_t status)
{
    uint16_t body = IDEMIP_DHCP6_IA_NA_FIXED_LEN;
    if (addr != NULL)
    {
        body = (uint16_t)(body + IDEMIP_DHCP6_OPT_HDR_LEN + IDEMIP_DHCP6_IAADDR_FIXED_LEN);
    }
    if (with_status)
    {
        body = (uint16_t)(body + IDEMIP_DHCP6_OPT_HDR_LEN + IDEMIP_DHCP6_STATUS_LEN);
    }
    uint8_t *ia = msg_opt(IDEMIP_DHCP6_OPT_IA_NA, body);
    put32(ia, iaid);
    put32(ia + 4u, t1);
    put32(ia + 8u, t2);
    uint8_t *sub = ia + IDEMIP_DHCP6_IA_NA_FIXED_LEN;
    if (with_status)
    {
        put16(sub, IDEMIP_DHCP6_OPT_STATUS_CODE);
        put16(sub + 2u, IDEMIP_DHCP6_STATUS_LEN);
        put16(sub + IDEMIP_DHCP6_OPT_HDR_LEN, status);
        sub += IDEMIP_DHCP6_OPT_HDR_LEN + IDEMIP_DHCP6_STATUS_LEN;
    }
    if (addr != NULL)
    {
        put16(sub, IDEMIP_DHCP6_OPT_IAADDR);
        put16(sub + 2u, IDEMIP_DHCP6_IAADDR_FIXED_LEN);
        uint8_t *a = sub + IDEMIP_DHCP6_OPT_HDR_LEN;
        memcpy(a, addr, IDEMIP_IP6_ADDR_LEN);
        put32(a + IDEMIP_IP6_ADDR_LEN, preferred);
        put32(a + IDEMIP_IP6_ADDR_LEN + 4u, valid);
    }
}

static void feed(uint8_t *w)
{
    IDEMIP_DHCP6_IO(w)->input_args.msg = g_msg;
    IDEMIP_DHCP6_IO(w)->input_args.len = g_msg_len;
    IDEMIP_DHCP6_IO(w)->input_args.src = g_src;
    Dhcp6.input(w);
}

static void tick(uint8_t *w, uint32_t now_ms, uint32_t rand)
{
    IDEMIP_DHCP6_IO(w)->tick_args.now_ms = now_ms;
    IDEMIP_DHCP6_IO(w)->tick_args.rand = rand;
    Dhcp6.tick(w);
}

static size_t build(uint8_t *w)
{
    memset(g_out, 0, sizeof g_out);
    IDEMIP_DHCP6_IO(w)->build_args.out = g_out;
    IDEMIP_DHCP6_IO(w)->build_args.cap = sizeof g_out;
    Dhcp6.build(w);
    g_out_len = IDEMIP_DHCP6_IO(w)->len;
    return g_out_len;
}

// One option out of the built message, by code.
static const uint8_t *out_opt(uint16_t code, uint16_t *len)
{
    size_t at = IDEMIP_DHCP6_MSG_OFF_OPTIONS;
    while (at + IDEMIP_DHCP6_OPT_HDR_LEN <= g_out_len)
    {
        uint16_t c = rd16(g_out + at);
        uint16_t l = rd16(g_out + at + 2u);
        if (c == code)
        {
            *len = l;
            return g_out + at + IDEMIP_DHCP6_OPT_HDR_LEN;
        }
        at += (size_t)IDEMIP_DHCP6_OPT_HDR_LEN + l;
    }
    return NULL;
}

// bind, start with a zero delay draw, then the tick that arms the first message.
static void arm_start(uint8_t *w, const IdemIpDhcp6Cfg *cfg, uint32_t xid)
{
    bind_ok(w, cfg);
    IDEMIP_DHCP6_IO(w)->start_args.xid = xid;
    IDEMIP_DHCP6_IO(w)->start_args.now_ms = 0u;
    IDEMIP_DHCP6_IO(w)->start_args.rand = 0u;
    Dhcp6.start(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(w)->status);
    tick(w, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(w)->status);
}

// Does a tick at @p now move the client on? Run on a copy of the borrow, so the real one is untouched.
static int owes_at(const uint8_t *w, uint32_t now, uint32_t rand)
{
    memcpy(probe, w, IDEMIP_DHCP6_BORROW);
    tick(probe, now, rand);
    return (IDEMIP_DHCP6_IO(probe)->status == IDEMIP_OK) ? 1 : 0;
}

// The smallest clock value at which the client owes its next message, by bisection over copies.
static uint32_t due_at(const uint8_t *w, uint32_t hi, uint32_t rand)
{
    uint32_t lo = 0u;
    while (lo < hi)
    {
        uint32_t mid = lo + ((hi - lo) >> 1);
        if (owes_at(w, mid, rand))
        {
            hi = mid;
        }
        else
        {
            lo = mid + 1u;
        }
    }
    return lo;
}

// The sec 15 RAND bound as this unit quantizes it: the term never passes k_max/1024 of x.
static uint32_t rand_bound(uint32_t x)
{
    return (uint32_t)(((uint64_t)x * IDEMIP_DHCP6_RAND_K_MAX) >> IDEMIP_DHCP6_RAND_SHIFT);
}

// The whole sec 18.2.1 to sec 18.2.10.1 run: Solicit, an Advertise of preference 255, a Request, and
// a Reply that assigns the lease at the given times.
static void to_bound(uint8_t *w, const IdemIpDhcp6Cfg *cfg, uint32_t t1, uint32_t t2, uint32_t preferred,
                     uint32_t valid)
{
    arm_start(w, cfg, 0x00ABCDEFu);
    build(w);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(cfg);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(cfg->iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(w)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_REQUESTING, IDEMIP_DHCP6_IO(w)->state);
    tick(w, 0u, 0u);
    build(w);
    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, IDEMIP_DHCP6_IO(w)->xid);
    msg_clientid(cfg);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_ia_na(cfg->iaid, t1, t2, g_lease, preferred, valid, 0, 0u);
    feed(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(w)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_BOUND, IDEMIP_DHCP6_IO(w)->state);
}

// --- sec 7.6 Table 1 ---------------------------------------------------------

// The parameters as Table 1 prints them, converted to the milliseconds this unit holds.
void test_the_sec_7_6_parameters_are_as_the_rfc_prints_them(void)
{
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_DHCP6_SOL_MAX_DELAY_MS);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_DHCP6_SOL_TIMEOUT_MS);
    TEST_ASSERT_EQUAL_UINT32(3600u * 1000u, IDEMIP_DHCP6_SOL_MAX_RT_MS);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_DHCP6_REQ_TIMEOUT_MS);
    TEST_ASSERT_EQUAL_UINT32(30u * 1000u, IDEMIP_DHCP6_REQ_MAX_RT_MS);
    TEST_ASSERT_EQUAL_UINT32(10u, IDEMIP_DHCP6_REQ_MAX_RC);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_DHCP6_CNF_MAX_DELAY_MS);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_DHCP6_CNF_TIMEOUT_MS);
    TEST_ASSERT_EQUAL_UINT32(4u * 1000u, IDEMIP_DHCP6_CNF_MAX_RT_MS);
    TEST_ASSERT_EQUAL_UINT32(10u * 1000u, IDEMIP_DHCP6_CNF_MAX_RD_MS);
    TEST_ASSERT_EQUAL_UINT32(10u * 1000u, IDEMIP_DHCP6_REN_TIMEOUT_MS);
    TEST_ASSERT_EQUAL_UINT32(600u * 1000u, IDEMIP_DHCP6_REN_MAX_RT_MS);
    TEST_ASSERT_EQUAL_UINT32(10u * 1000u, IDEMIP_DHCP6_REB_TIMEOUT_MS);
    TEST_ASSERT_EQUAL_UINT32(600u * 1000u, IDEMIP_DHCP6_REB_MAX_RT_MS);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_DHCP6_INF_MAX_DELAY_MS);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_DHCP6_INF_TIMEOUT_MS);
    TEST_ASSERT_EQUAL_UINT32(3600u * 1000u, IDEMIP_DHCP6_INF_MAX_RT_MS);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_DHCP6_REL_TIMEOUT_MS);
    TEST_ASSERT_EQUAL_UINT32(4u, IDEMIP_DHCP6_REL_MAX_RC);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_DHCP6_DEC_TIMEOUT_MS);
    TEST_ASSERT_EQUAL_UINT32(4u, IDEMIP_DHCP6_DEC_MAX_RC);
    TEST_ASSERT_EQUAL_UINT32(60u * 1000u, IDEMIP_DHCP6_MAX_WAIT_TIME_MS);
    TEST_ASSERT_EQUAL_UINT32(86400u, IDEMIP_DHCP6_IRT_DEFAULT_S);
    TEST_ASSERT_EQUAL_UINT32(600u, IDEMIP_DHCP6_IRT_MINIMUM_S);
}

// sec 15: RAND is "a random number chosen with a uniform distribution between -0.1 and +0.1". The
// quantized magnitude must be strictly inside that, which is what k*10 < 1024 states.
void test_the_quantized_rand_stays_inside_the_sec_15_tenth(void)
{
    TEST_ASSERT_EQUAL_UINT32(1024u, 1u << IDEMIP_DHCP6_RAND_SHIFT);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_DHCP6_RAND_K_MAX * 10u < (1u << IDEMIP_DHCP6_RAND_SHIFT),
                             "the quantized RAND magnitude leaves RFC 8415 sec 15's 0.1 bound");
    // The shift-only approximation x>>3 minus x>>7 is 0.1171875, which is outside the bound.
    TEST_ASSERT_TRUE(((1000000u >> 3u) - (1000000u >> 7u)) > ((1000000u * 10u) >> IDEMIP_DHCP6_RAND_SHIFT) * 10u);
}

// sec 21.9: elapsed-time is in hundredths of a second. The reciprocal multiply this unit uses has to
// be floor(ms/100) over every value the 2-octet field can carry.
void test_the_elapsed_time_reciprocal_is_exact_over_the_whole_field(void)
{
    uint32_t bad = 0u;
    uint32_t first_bad = 0u;
    for (uint32_t ms = 0u; ms <= IDEMIP_DHCP6_ELAPSED_MAX_MS; ms++)
    {
        uint32_t got = (uint32_t)(((uint64_t)ms * (uint64_t)IDEMIP_DHCP6_CS_RECIP) >> IDEMIP_DHCP6_CS_SHIFT);
        if (got != ms / 100u)
        {
            if (bad == 0u)
            {
                first_bad = ms;
            }
            bad++;
        }
    }
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, bad, "the sec 21.9 reciprocal does not land on floor(ms/100)");
    TEST_ASSERT_EQUAL_UINT32(0u, first_bad);
}

// --- sec 18.2.1 Solicit ------------------------------------------------------

// sec 18.2.1: the Solicit carries a Client Identifier, an IA option, an Elapsed Time option and an
// Option Request option, and sec 16.2 has a server discard one that carries a Server Identifier.
void test_the_solicit_carries_the_options_sec_18_2_1_names(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_size_t(50u, build(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);

    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DHCP6_SOLICIT, g_out[IDEMIP_DHCP6_MSG_OFF_TYPE]);
    TEST_ASSERT_EQUAL_HEX8(0xABu, g_out[IDEMIP_DHCP6_MSG_OFF_XID]);
    TEST_ASSERT_EQUAL_HEX8(0xCDu, g_out[IDEMIP_DHCP6_MSG_OFF_XID + 1u]);
    TEST_ASSERT_EQUAL_HEX8(0xEFu, g_out[IDEMIP_DHCP6_MSG_OFF_XID + 2u]);

    uint16_t l = 0u;
    const uint8_t *d = out_opt(IDEMIP_DHCP6_OPT_CLIENTID, &l);
    TEST_ASSERT_NOT_NULL_MESSAGE(d, "sec 18.2.1 makes the Client Identifier a MUST");
    TEST_ASSERT_EQUAL_UINT16((uint16_t)sizeof g_duid_a, l);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_duid_a, d, sizeof g_duid_a);

    d = out_opt(IDEMIP_DHCP6_OPT_ELAPSED_TIME, &l);
    TEST_ASSERT_NOT_NULL_MESSAGE(d, "sec 18.2.1 makes the Elapsed Time option a MUST");
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_ELAPSED_LEN, l);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, rd16(d), "sec 21.9 sets elapsed-time to 0 in the first message");

    d = out_opt(IDEMIP_DHCP6_OPT_IA_NA, &l);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(IDEMIP_DHCP6_IA_NA_FIXED_LEN, l, "sec 18.2.1 makes an address hint a MAY");
    TEST_ASSERT_EQUAL_HEX32(0x0A0A0A0Au, rd32(d));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, rd32(d + 4u), "sec 21.4 has a client send T1 as 0");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, rd32(d + 8u), "sec 21.4 has a client send T2 as 0");

    d = out_opt(IDEMIP_DHCP6_OPT_ORO, &l);
    TEST_ASSERT_NOT_NULL_MESSAGE(d, "sec 18.2.1 makes the Option Request option a MUST");
    TEST_ASSERT_EQUAL_UINT16(6u, l);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(IDEMIP_DHCP6_OPT_SOL_MAX_RT, rd16(d),
                                     "sec 21.24 makes the SOL_MAX_RT code a MUST in a Solicit's ORO");
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_OPT_DNS_SERVERS, rd16(d + 2u));
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_OPT_DOMAIN_LIST, rd16(d + 4u));

    TEST_ASSERT_NULL_MESSAGE(out_opt(IDEMIP_DHCP6_OPT_SERVERID, &l),
                             "sec 16.2 has a server discard a Solicit that carries a Server Identifier");
    TEST_ASSERT_NULL_MESSAGE(out_opt(IDEMIP_DHCP6_OPT_RAPID_COMMIT, &l),
                             "sec 21.14 is only sent when the client asks for the two-message exchange");
}

// sec 21.14, option-len 0, in a Solicit from a client configured for the two-message exchange.
void test_the_solicit_carries_rapid_commit_when_configured(void)
{
    arm_start(work_a, &g_cfg_rc, 0x00000001u);
    TEST_ASSERT_EQUAL_size_t(54u, build(work_a));
    uint16_t l = 0xFFFFu;
    TEST_ASSERT_NOT_NULL(out_opt(IDEMIP_DHCP6_OPT_RAPID_COMMIT, &l));
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, l, "sec 21.14 gives the Rapid Commit option option-len 0");
}

// sec 18.2.6 with sec 16.12: an Information-request carries no IA option, and its ORO carries the
// INF_MAX_RT code sec 21.25 requires and the Information Refresh Time code sec 21.23 requires.
void test_a_stateless_client_sends_an_information_request(void)
{
    arm_start(work_b, &g_cfg_b, 0x00112233u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_INFO_REQUESTING, IDEMIP_DHCP6_IO(work_b)->state);
    TEST_ASSERT_EQUAL_size_t(36u, build(work_b));
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DHCP6_INFORMATION_REQUEST, g_out[IDEMIP_DHCP6_MSG_OFF_TYPE]);

    uint16_t l = 0u;
    TEST_ASSERT_NULL_MESSAGE(out_opt(IDEMIP_DHCP6_OPT_IA_NA, &l),
                             "sec 16.12 has a server discard an Information-request that includes an IA option");
    TEST_ASSERT_NOT_NULL(out_opt(IDEMIP_DHCP6_OPT_CLIENTID, &l));
    TEST_ASSERT_NOT_NULL(out_opt(IDEMIP_DHCP6_OPT_ELAPSED_TIME, &l));
    const uint8_t *d = out_opt(IDEMIP_DHCP6_OPT_ORO, &l);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_UINT16(8u, l);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(IDEMIP_DHCP6_OPT_INF_MAX_RT, rd16(d),
                                     "sec 21.25 makes the INF_MAX_RT code a MUST in this ORO");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(IDEMIP_DHCP6_OPT_INFO_REFRESH, rd16(d + 2u),
                                     "sec 21.23 makes the Information Refresh Time code a MUST in this ORO");
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_OPT_DNS_SERVERS, rd16(d + 4u));
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_OPT_DOMAIN_LIST, rd16(d + 6u));
}

// sec 21.23 forbids the Information Refresh Time code in any ORO but an Information-request's.
void test_only_the_information_request_asks_for_the_refresh_time(void)
{
    arm_start(work_a, &g_cfg_a, 0x00000002u);
    build(work_a);
    uint16_t l = 0u;
    const uint8_t *d = out_opt(IDEMIP_DHCP6_OPT_ORO, &l);
    TEST_ASSERT_NOT_NULL(d);
    for (uint16_t i = 0u; i + 1u < l; i = (uint16_t)(i + 2u))
    {
        TEST_ASSERT_TRUE_MESSAGE(rd16(d + i) != IDEMIP_DHCP6_OPT_INFO_REFRESH,
                                 "sec 21.23 forbids this code outside an Information-request's ORO");
    }
}

// sec 7.1 and sec 7.2: the message goes to All_DHCP_Relay_Agents_and_Servers on port 547, from 546.
void test_the_message_goes_to_the_all_agents_multicast_address(void)
{
    static const uint8_t expect[IDEMIP_IP6_ADDR_LEN] = IDEMIP_DHCP6_ALL_RELAY_AGENTS_AND_SERVERS;
    arm_start(work_a, &g_cfg_a, 0x00000003u);
    build(work_a);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expect, IDEMIP_DHCP6_IO(work_a)->dst, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_PORT_SERVER, IDEMIP_DHCP6_IO(work_a)->dst_port);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_PORT_CLIENT, IDEMIP_DHCP6_IO(work_a)->src_port);
}

// Nothing is owed until a tick arms it, and a message is handed out once. Both are BUSY, since the
// next tick can produce one.
void test_build_is_busy_until_a_tick_arms_a_message(void)
{
    bind_ok(work_a, &g_cfg_a);
    IDEMIP_DHCP6_IO(work_a)->start_args.xid = 0x00000004u;
    IDEMIP_DHCP6_IO(work_a)->start_args.now_ms = 0u;
    IDEMIP_DHCP6_IO(work_a)->start_args.rand = 0u;
    Dhcp6.start(work_a);
    TEST_ASSERT_EQUAL_size_t(0u, build(work_a));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DHCP6_IO(work_a)->status, "nothing is owed before a tick");
    tick(work_a, 0u, 0u);
    TEST_ASSERT_TRUE(build(work_a) > 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, build(work_a));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DHCP6_IO(work_a)->status, "the message is handed out once");
}

// A buffer shorter than the message cannot ever hold it, so it is ERR and not BUSY.
void test_a_buffer_too_short_for_the_message_is_refused(void)
{
    arm_start(work_a, &g_cfg_a, 0x00000005u);
    IDEMIP_DHCP6_IO(work_a)->build_args.out = g_out;
    IDEMIP_DHCP6_IO(work_a)->build_args.cap = 20u;
    Dhcp6.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_DHCP6_IO(work_a)->len);
}

// --- sec 15 and sec 18.2.1, the retransmission schedule -----------------------

// sec 18.2.1: "The first Solicit message from the client on the interface SHOULD be delayed by a
// random amount of time between 0 and SOL_MAX_DELAY."
void test_the_first_solicit_delay_stays_inside_sol_max_delay(void)
{
    for (uint32_t seed = 0u; seed < 64u; seed++)
    {
        uint32_t rand = (seed * 2654435761u) ^ 0x5A5A1234u;
        bind_ok(work_a, &g_cfg_a);
        IDEMIP_DHCP6_IO(work_a)->start_args.xid = 0x00000006u;
        IDEMIP_DHCP6_IO(work_a)->start_args.now_ms = 0u;
        IDEMIP_DHCP6_IO(work_a)->start_args.rand = rand;
        Dhcp6.start(work_a);
        uint32_t d = due_at(work_a, 4u * IDEMIP_DHCP6_SOL_MAX_DELAY_MS, 0u);
        TEST_ASSERT_TRUE_MESSAGE(d <= IDEMIP_DHCP6_SOL_MAX_DELAY_MS,
                                 "the first Solicit went out past SOL_MAX_DELAY");
        Dhcp6.clear(work_a);
    }
}

// sec 15: "RT = IRT + RAND*IRT". sec 18.2.1 adds that for the first Solicit "the first RT MUST be
// selected to be strictly greater than IRT by choosing RAND to be strictly greater than 0".
void test_the_first_solicit_rt_is_strictly_greater_than_sol_timeout(void)
{
    for (uint32_t seed = 0u; seed < 64u; seed++)
    {
        uint32_t rand = (seed * 40503u) ^ 0x0F1E2D3Cu;
        arm_start(work_a, &g_cfg_a, 0x00000007u);
        uint32_t rt = due_at(work_a, 4u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, rand);
        TEST_ASSERT_TRUE_MESSAGE(rt > IDEMIP_DHCP6_SOL_TIMEOUT_MS,
                                 "sec 18.2.1 needs the first Solicit RT strictly past SOL_TIMEOUT");
        TEST_ASSERT_TRUE_MESSAGE(rt <= IDEMIP_DHCP6_SOL_TIMEOUT_MS + rand_bound(IDEMIP_DHCP6_SOL_TIMEOUT_MS),
                                 "the first Solicit RT left the sec 15 RAND bound");
        Dhcp6.clear(work_a);
    }
}

// sec 15: "RT = 2*RTprev + RAND*RTprev" for each later transmission.
void test_each_later_rt_doubles_inside_the_sec_15_bound(void)
{
    arm_start(work_a, &g_cfg_a, 0x00000008u);
    uint32_t now = 0u;
    uint32_t prev = due_at(work_a, 4u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, 0x13579BDFu) - now;
    for (uint32_t step = 0u; step < 6u; step++)
    {
        uint32_t rand = 0x13579BDFu + (step * 0x01010101u);
        now += prev;
        tick(work_a, now, rand);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
        uint32_t next = due_at(work_a, now + (8u * prev), rand) - now;
        TEST_ASSERT_TRUE_MESSAGE(next >= (2u * prev) - rand_bound(prev), "RT fell under 2*RTprev minus RAND*RTprev");
        TEST_ASSERT_TRUE_MESSAGE(next <= (2u * prev) + rand_bound(prev), "RT rose past 2*RTprev plus RAND*RTprev");
        prev = next;
    }
}

// sec 15: "MRT specifies an upper bound on the value of RT ... if (RT > MRT) RT = MRT + RAND*MRT".
void test_the_retransmission_timeout_stops_at_mrt(void)
{
    arm_start(work_a, &g_cfg_a, 0x00000009u);
    uint32_t now = 0u;
    uint32_t rt = due_at(work_a, 4u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, 0x2468ACE0u) - now;
    for (uint32_t step = 0u; step < 20u; step++)
    {
        uint32_t rand = 0x2468ACE0u + (step * 0x11111111u);
        now += rt;
        tick(work_a, now, rand);
        rt = due_at(work_a, now + (4u * IDEMIP_DHCP6_SOL_MAX_RT_MS), rand) - now;
        TEST_ASSERT_TRUE_MESSAGE(rt <= IDEMIP_DHCP6_SOL_MAX_RT_MS + rand_bound(IDEMIP_DHCP6_SOL_MAX_RT_MS),
                                 "RT rose past MRT plus RAND*MRT");
    }
    TEST_ASSERT_TRUE_MESSAGE(rt >= IDEMIP_DHCP6_SOL_MAX_RT_MS - rand_bound(IDEMIP_DHCP6_SOL_MAX_RT_MS),
                             "RT settled under MRT minus RAND*MRT");
}

// sec 21.9: elapsed-time is "measured from the time at which the client sent the first message in the
// message exchange", in hundredths of a second, and 0xffff stands for anything longer than the field.
void test_the_elapsed_time_counts_from_the_first_message(void)
{
    static const uint32_t at[6] = {0u, 99u, 100u, 12345u, IDEMIP_DHCP6_ELAPSED_MAX_MS - 1u,
                                   IDEMIP_DHCP6_ELAPSED_MAX_MS};
    for (uint32_t i = 0u; i < 6u; i++)
    {
        arm_start(work_a, &g_cfg_a, 0x0000000Au);
        tick(work_a, at[i], 0u); // under the first RT, so the message stays owed
        build(work_a);
        uint16_t l = 0u;
        const uint8_t *d = out_opt(IDEMIP_DHCP6_OPT_ELAPSED_TIME, &l);
        TEST_ASSERT_NOT_NULL(d);
        uint16_t want = (at[i] >= IDEMIP_DHCP6_ELAPSED_MAX_MS) ? 0xFFFFu : (uint16_t)(at[i] / 100u);
        TEST_ASSERT_EQUAL_UINT16(want, rd16(d));
        Dhcp6.clear(work_a);
    }
}

// --- sec 16, message validation ----------------------------------------------

// sec 16: "A client or server MUST discard any received DHCP messages with an unknown message type",
// and sec 16.2 and sec 16.4 through sec 16.14 name every type a client discards outright.
void test_the_client_discards_every_type_it_must(void)
{
    static const uint8_t reject[12] = {(uint8_t)IDEMIP_DHCP6_SOLICIT,
                                       (uint8_t)IDEMIP_DHCP6_REQUEST,
                                       (uint8_t)IDEMIP_DHCP6_CONFIRM,
                                       (uint8_t)IDEMIP_DHCP6_RENEW,
                                       (uint8_t)IDEMIP_DHCP6_REBIND,
                                       (uint8_t)IDEMIP_DHCP6_RELEASE,
                                       (uint8_t)IDEMIP_DHCP6_DECLINE,
                                       (uint8_t)IDEMIP_DHCP6_RECONFIGURE,
                                       (uint8_t)IDEMIP_DHCP6_INFORMATION_REQUEST,
                                       (uint8_t)IDEMIP_DHCP6_RELAY_FORW,
                                       (uint8_t)IDEMIP_DHCP6_RELAY_REPL,
                                       200u};
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    for (uint32_t i = 0u; i < 12u; i++)
    {
        msg_begin(reject[i], 0x00ABCDEFu);
        msg_clientid(&g_cfg_a);
        msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
        msg_ia_na(g_cfg_a.iaid, 100u, 200u, g_lease, 300u, 400u, 0, 0u);
        feed(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status,
                                      "a type sec 16 has the client discard was accepted");
        TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
    }
}

// sec 16.3 and sec 16.10: the transaction-id "does not match the value the client used" is a discard.
void test_a_message_with_the_wrong_transaction_id_is_discarded(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEEu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
}

// sec 16.3 and sec 16.10: no Server Identifier option is a discard.
void test_a_message_with_no_server_identifier_is_discarded(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
}

// sec 16.3: "the contents of the Client Identifier option do not match the client's DUID" is a
// discard, and so is the option being absent.
void test_a_message_whose_client_identifier_is_not_ours_is_discarded(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_b);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);

    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
}

// sec 21.1 sizes an option by its own option-len, so one that runs past the message is malformed.
void test_an_option_length_past_the_end_of_the_message_is_refused(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    put16(g_msg + g_msg_len + 2u, 0xFFFFu); // the last option claims more than the message carries
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
}

// sec 16: "Clients, relay agents, and servers MUST NOT discard messages that contain unknown options
// ... These should be ignored as if they were not present."
void test_an_unknown_option_does_not_discard_the_message(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    (void)msg_opt(0x7FFFu, 5u);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_REQUESTING, IDEMIP_DHCP6_IO(work_a)->state);
}

// --- sec 18.2.9, Advertise selection ----------------------------------------

// sec 18.2.1: "If the client receives a valid Advertise message that includes a Preference option with
// a preference value of 255, the client immediately begins a client-initiated message exchange."
void test_a_preference_of_255_requests_at_once(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_REQUESTING, IDEMIP_DHCP6_IO(work_a)->state);
}

// sec 18.2.1: a lesser preference keeps the client collecting, and "If the first RT elapses and the
// client has received a valid Advertise message, the client SHOULD continue with a client-initiated
// message exchange by sending a Request message."
void test_a_lesser_preference_waits_for_the_first_rt(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    build(work_a);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(10u);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state,
                                  "sec 18.2.1 collects Advertise messages until the first RT elapses");
    tick(work_a, 2u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_REQUESTING, IDEMIP_DHCP6_IO(work_a)->state);
}

// sec 18.2.9: "Those Advertise messages with the highest server preference value SHOULD be preferred
// over all other Advertise messages", and sec 21.8 gives one without the option a preference of 0.
void test_the_highest_preference_advertise_wins(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    build(work_a);

    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(10u);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lease, IDEMIP_DHCP6_IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);

    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid2, (uint16_t)sizeof g_sduid2);
    msg_pref(20u);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease2, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(g_lease2, IDEMIP_DHCP6_IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN,
                                         "the better preference did not replace the earlier Advertise");

    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(5u);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(g_lease2, IDEMIP_DHCP6_IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN,
                                         "a worse preference replaced the recorded Advertise");

    tick(work_a, 2u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, 0u); // the first RT elapses, so the Request begins
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_REQUESTING, IDEMIP_DHCP6_IO(work_a)->state);
    tick(work_a, 2u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, 0u); // and this one arms its first transmission
    TEST_ASSERT_TRUE(build(work_a) > 0u);
    uint16_t l = 0u;
    const uint8_t *d = out_opt(IDEMIP_DHCP6_OPT_SERVERID, &l);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(g_sduid2, d, sizeof g_sduid2,
                                         "the Request went to a server other than the preferred one");
}

// sec 18.2.9: "The client MUST ignore any Advertise message that contains no addresses ... with the
// exception that the client MUST process an included SOL_MAX_RT option."
void test_an_advertise_with_no_address_is_ignored(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, NULL, 0u, 0u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
    for (uint32_t i = 0u; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0u, IDEMIP_DHCP6_IO(work_a)->addr[i]);
    }
    tick(work_a, 2u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state,
                                  "an ignored Advertise still started a Request exchange");
}

// sec 18.2.9 and sec 21.24: the SOL_MAX_RT option is taken "even if ... the Advertise message will be
// discarded by the client", and sec 21.24 has the client "ignore any SOL_MAX_RT option values that are
// less than 60 or more than 86400".
void test_sol_max_rt_is_taken_from_a_discarded_advertise(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    put32(msg_opt(IDEMIP_DHCP6_OPT_SOL_MAX_RT, IDEMIP_DHCP6_MAX_RT_LEN), IDEMIP_DHCP6_MAX_RT_MIN_S);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, NULL, 0u, 0u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status, "sec 18.2.9 ignores this Advertise");

    uint32_t bound = IDEMIP_DHCP6_MAX_RT_MIN_S * 1000u;
    uint32_t now = 0u;
    uint32_t rt = due_at(work_a, 4u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, 0u) - now;
    for (uint32_t step = 0u; step < 12u; step++)
    {
        now += rt;
        tick(work_a, now, 0u);
        rt = due_at(work_a, now + (4u * IDEMIP_DHCP6_SOL_MAX_RT_MS), 0u) - now;
    }
    TEST_ASSERT_TRUE_MESSAGE(rt <= bound + rand_bound(bound),
                             "the sec 21.24 override was not applied to the Solicit MRT");
}

// sec 21.24: an override outside 60 through 86400 is ignored, so the default MRT stands.
void test_a_sol_max_rt_outside_its_range_is_ignored(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    put32(msg_opt(IDEMIP_DHCP6_OPT_SOL_MAX_RT, IDEMIP_DHCP6_MAX_RT_LEN), IDEMIP_DHCP6_MAX_RT_MIN_S - 1u);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, NULL, 0u, 0u, 0, 0u);
    feed(work_a);

    uint32_t now = 0u;
    uint32_t rt = due_at(work_a, 4u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, 0u) - now;
    for (uint32_t step = 0u; step < 12u; step++)
    {
        now += rt;
        tick(work_a, now, 0u);
        rt = due_at(work_a, now + (4u * IDEMIP_DHCP6_SOL_MAX_RT_MS), 0u) - now;
    }
    TEST_ASSERT_TRUE_MESSAGE(rt > IDEMIP_DHCP6_MAX_RT_MIN_S * 1000u,
                             "a SOL_MAX_RT under sec 21.24's floor of 60 seconds was applied");
}

// --- sec 21.4 and sec 21.6, the lease ---------------------------------------

// sec 18.2.10.1 with sec 21.4 and sec 21.6: the Reply's IA_NA and IA Address set T1, T2 and the two
// lifetimes, and the client lands in BOUND.
void test_a_reply_assigns_the_lease_from_the_ia_na(void)
{
    to_bound(work_a, &g_cfg_a, 100u, 200u, 300u, 400u);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lease, IDEMIP_DHCP6_IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT32(100u, IDEMIP_DHCP6_IO(work_a)->t1_s);
    TEST_ASSERT_EQUAL_UINT32(200u, IDEMIP_DHCP6_IO(work_a)->t2_s);
    TEST_ASSERT_EQUAL_UINT32(300u, IDEMIP_DHCP6_IO(work_a)->preferred_s);
    TEST_ASSERT_EQUAL_UINT32(400u, IDEMIP_DHCP6_IO(work_a)->valid_s);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_STATUS_SUCCESS, IDEMIP_DHCP6_IO(work_a)->status_code);
}

// sec 21.4: "If a client receives an IA_NA with T1 greater than T2 and both T1 and T2 are greater
// than 0, the client discards the IA_NA option."
void test_an_ia_na_with_t1_past_t2_is_discarded(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 300u, 200u, g_lease, 100u, 400u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
}

// sec 21.6: "The client MUST discard any addresses for which the preferred lifetime is greater than
// the valid lifetime", and sec 18.2.10.1 discards a lease whose valid lifetime is 0.
void test_an_unusable_address_is_discarded(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 100u, 200u, g_lease, 500u, 400u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status,
                                  "a preferred lifetime past the valid lifetime was accepted");

    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 100u, 200u, g_lease, 0u, 0u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status,
                                  "a valid lifetime of 0 was taken as a lease");
}

// sec 21.4: an IA_NA whose IAID is not this client's is not this client's binding.
void test_an_ia_na_with_another_iaid_is_not_taken(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid ^ 0xFFFFFFFFu, 100u, 200u, g_lease, 300u, 400u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
}

// sec 21.4 and sec 21.13: "The status of any operations involving this IA_NA is indicated in a Status
// Code option ... in the IA_NA-options field", and NoAddrsAvail leaves the client without a lease.
void test_a_no_addrs_avail_status_inside_the_ia_na_stops_the_lease(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, NULL, 0u, 0u, 1, (uint16_t)IDEMIP_DHCP6_STATUS_NO_ADDRS_AVAIL);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_STATUS_NO_ADDRS_AVAIL, IDEMIP_DHCP6_IO(work_a)->status_code);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
}

// sec 14.2 and sec 21.4: T1 or T2 of 0 leaves the time to the client. sec 21.4 recommends 0.5 and 0.8
// of the shortest preferred lifetime, taken here as x>>1 and (x>>1)+(x>>2)+(x>>5).
void test_a_zero_t1_and_t2_are_chosen_by_the_client(void)
{
    to_bound(work_a, &g_cfg_a, 0u, 0u, 1000u, 2000u);
    TEST_ASSERT_EQUAL_UINT32(1000u >> 1u, IDEMIP_DHCP6_IO(work_a)->t1_s);
    TEST_ASSERT_EQUAL_UINT32((1000u >> 1u) + (1000u >> 2u) + (1000u >> 5u), IDEMIP_DHCP6_IO(work_a)->t2_s);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_DHCP6_IO(work_a)->t1_s <= IDEMIP_DHCP6_IO(work_a)->t2_s,
                             "the client-picked T1 landed past T2");
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_DHCP6_IO(work_a)->t2_s != 0u, "sec 14.2 forbids transmitting immediately");
}

// sec 21.4: "If the 'shortest' preferred lifetime is 0xffffffff ('infinity'), the recommended T1 and
// T2 values are also 0xffffffff", and sec 7.7 has such a client never renew or rebind.
void test_an_infinite_preferred_lifetime_makes_t1_and_t2_infinite(void)
{
    to_bound(work_a, &g_cfg_a, 0u, 0u, IDEMIP_DHCP6_INFINITY, IDEMIP_DHCP6_INFINITY);
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_DHCP6_INFINITY, IDEMIP_DHCP6_IO(work_a)->t1_s);
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_DHCP6_INFINITY, IDEMIP_DHCP6_IO(work_a)->t2_s);
    tick(work_a, 0xF0000000u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP6_BOUND, IDEMIP_DHCP6_IO(work_a)->state,
                                  "sec 7.7 never renews an IA with T1 at infinity");
}

// --- sec 18.2.2 Request ------------------------------------------------------

// sec 18.2.2 and sec 21.3: the Request names the destination server, carries the client's DUID, an
// Elapsed Time option, an IA option and an ORO, and sec 21.6 has the client send zeroed lifetimes.
void test_the_request_names_the_server_and_the_offered_address(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    build(work_a);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    tick(work_a, 0u, 0u);
    // 4 header, 12 Server Identifier, 14 Client Identifier, 6 Elapsed Time, 44 IA_NA with its IA
    // Address, 10 Option Request.
    TEST_ASSERT_EQUAL_size_t(90u, build(work_a));
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DHCP6_REQUEST, g_out[IDEMIP_DHCP6_MSG_OFF_TYPE]);

    uint16_t l = 0u;
    const uint8_t *d = out_opt(IDEMIP_DHCP6_OPT_SERVERID, &l);
    TEST_ASSERT_NOT_NULL_MESSAGE(d, "sec 18.2.2 makes the Server Identifier a MUST");
    TEST_ASSERT_EQUAL_UINT16((uint16_t)sizeof g_sduid, l);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_sduid, d, sizeof g_sduid);
    TEST_ASSERT_NOT_NULL(out_opt(IDEMIP_DHCP6_OPT_CLIENTID, &l));
    TEST_ASSERT_NOT_NULL(out_opt(IDEMIP_DHCP6_OPT_ELAPSED_TIME, &l));
    TEST_ASSERT_NOT_NULL(out_opt(IDEMIP_DHCP6_OPT_ORO, &l));

    d = out_opt(IDEMIP_DHCP6_OPT_IA_NA, &l);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_IA_NA_FIXED_LEN + IDEMIP_DHCP6_OPT_HDR_LEN + IDEMIP_DHCP6_IAADDR_FIXED_LEN,
                             l);
    const uint8_t *sub = d + IDEMIP_DHCP6_IA_NA_FIXED_LEN;
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_OPT_IAADDR, rd16(sub));
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP6_IAADDR_FIXED_LEN, rd16(sub + 2u));
    const uint8_t *a = sub + IDEMIP_DHCP6_OPT_HDR_LEN;
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lease, a, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, rd32(a + IDEMIP_IP6_ADDR_LEN),
                                     "sec 21.6 has a client send preferred-lifetime as 0");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, rd32(a + IDEMIP_IP6_ADDR_LEN + 4u),
                                     "sec 21.6 has a client send valid-lifetime as 0");
}

// sec 16.1: "A client MUST leave the transaction ID unchanged in retransmissions of a message", and
// each new exchange gets a new one.
void test_the_transaction_id_holds_across_retransmissions(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    build(work_a);
    TEST_ASSERT_EQUAL_HEX8(0xABu, g_out[IDEMIP_DHCP6_MSG_OFF_XID]);
    tick(work_a, 2u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, 0x99u);
    build(work_a);
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xABu, g_out[IDEMIP_DHCP6_MSG_OFF_XID], "the retransmission changed the xid");
    TEST_ASSERT_EQUAL_HEX8(0xCDu, g_out[IDEMIP_DHCP6_MSG_OFF_XID + 1u]);
    TEST_ASSERT_EQUAL_HEX8(0xEFu, g_out[IDEMIP_DHCP6_MSG_OFF_XID + 2u]);

    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    tick(work_a, 2u * IDEMIP_DHCP6_SOL_TIMEOUT_MS, 0x00778899u);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x00778899u, IDEMIP_DHCP6_IO(work_a)->xid,
                                    "sec 16.1 wants a new transaction-id for a new exchange");
}

// sec 15 with sec 18.2.2's MRC of REQ_MAX_RC: "the message exchange fails once the client has
// transmitted the message MRC times", and sec 18.2.2 then takes an action, here the sec 18 discovery.
void test_the_request_gives_up_after_req_max_rc_transmissions(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    build(work_a);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);

    uint32_t now = 0u;
    uint32_t sent = 0u;
    for (uint32_t step = 0u; step < 40u; step++)
    {
        tick(work_a, now, 0u);
        if (build(work_a) > 0u && g_out[IDEMIP_DHCP6_MSG_OFF_TYPE] == (uint8_t)IDEMIP_DHCP6_REQUEST)
        {
            sent++;
        }
        if (IDEMIP_DHCP6_IO(work_a)->state != IDEMIP_DHCP6_REQUESTING)
        {
            break;
        }
        now = due_at(work_a, now + (4u * IDEMIP_DHCP6_REQ_MAX_RT_MS), 0u);
    }
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(IDEMIP_DHCP6_REQ_MAX_RC, sent,
                                     "the Request exchange did not stop at sec 7.6's REQ_MAX_RC");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state,
                                  "sec 18.2.2's failed exchange did not restart sec 18 discovery");
}

// --- sec 18.2.10, Reply handling --------------------------------------------

// sec 18.2.10: "If the client receives a Reply message with a status code of UseMulticast ... The
// client resends the original message using multicast."
void test_use_multicast_resends_the_original_message(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    build(work_a);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    tick(work_a, 0u, 0u);
    build(work_a);
    TEST_ASSERT_EQUAL_size_t(0u, build(work_a));

    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, IDEMIP_DHCP6_IO(work_a)->xid);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_status((uint16_t)IDEMIP_DHCP6_STATUS_USE_MULTICAST);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_REQUESTING, IDEMIP_DHCP6_IO(work_a)->state);
    TEST_ASSERT_TRUE_MESSAGE(build(work_a) > 0u, "sec 18.2.10 resends the original message");
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DHCP6_REQUEST, g_out[IDEMIP_DHCP6_MSG_OFF_TYPE]);
}

// sec 18.2.10.1: "If the client receives a NotOnLink status from the server in response to ... a
// Request, the client can either reissue the message without specifying any addresses or restart the
// DHCP server discovery process."
void test_not_on_link_restarts_the_discovery_process(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    build(work_a);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    tick(work_a, 0u, 0u);
    build(work_a);

    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, IDEMIP_DHCP6_IO(work_a)->xid);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_status((uint16_t)IDEMIP_DHCP6_STATUS_NOT_ON_LINK);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
    for (uint32_t i = 0u; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0u, IDEMIP_DHCP6_IO(work_a)->addr[i]);
    }
}

// sec 18.2.1: a Rapid Commit Solicit takes a Reply that carries a Rapid Commit option, and "will
// discard any Reply messages that do not contain the Rapid Commit option".
void test_a_rapid_commit_reply_binds_straight_from_soliciting(void)
{
    arm_start(work_a, &g_cfg_rc, 0x00ABCDEFu);
    build(work_a);

    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, 0x00ABCDEFu);
    msg_clientid(&g_cfg_rc);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_ia_na(g_cfg_rc.iaid, 100u, 200u, g_lease, 300u, 400u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status,
                                  "a Reply without a Rapid Commit option was accepted");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);

    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, 0x00ABCDEFu);
    msg_clientid(&g_cfg_rc);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    (void)msg_opt(IDEMIP_DHCP6_OPT_RAPID_COMMIT, 0u);
    msg_ia_na(g_cfg_rc.iaid, 100u, 200u, g_lease, 300u, 400u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_BOUND, IDEMIP_DHCP6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lease, IDEMIP_DHCP6_IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
}

// sec 18.2.1: a client that did not ask for the two-message exchange discards the Rapid Commit Reply.
void test_a_client_without_rapid_commit_discards_the_reply(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    (void)msg_opt(IDEMIP_DHCP6_OPT_RAPID_COMMIT, 0u);
    msg_ia_na(g_cfg_a.iaid, 100u, 200u, g_lease, 300u, 400u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
}

// --- sec 18.2.4 and sec 18.2.5, Renew and Rebind ----------------------------

// sec 18.2.4: "At time T1, the client initiates a Renew/Reply message exchange", and sec 18.2.5 has
// the exchange "terminated when the earliest time T2 is reached, at which point the client begins the
// Rebind message exchange". sec 18.2.5 drops the Server Identifier from the Rebind.
void test_t1_starts_the_renew_and_t2_the_rebind(void)
{
    to_bound(work_a, &g_cfg_a, 10u, 20u, 300u, 400u);
    tick(work_a, 9999u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP6_BOUND, IDEMIP_DHCP6_IO(work_a)->state, "the Renew started before T1");
    tick(work_a, 10000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_RENEWING, IDEMIP_DHCP6_IO(work_a)->state);
    tick(work_a, 10000u, 0u);
    TEST_ASSERT_EQUAL_size_t(90u, build(work_a));
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DHCP6_RENEW, g_out[IDEMIP_DHCP6_MSG_OFF_TYPE]);
    uint16_t l = 0u;
    TEST_ASSERT_NOT_NULL_MESSAGE(out_opt(IDEMIP_DHCP6_OPT_SERVERID, &l),
                                 "sec 18.2.4 makes the Server Identifier a MUST in a Renew");

    tick(work_a, 20000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_REBINDING, IDEMIP_DHCP6_IO(work_a)->state);
    tick(work_a, 20000u, 0u);
    TEST_ASSERT_TRUE(build(work_a) > 0u);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DHCP6_REBIND, g_out[IDEMIP_DHCP6_MSG_OFF_TYPE]);
    TEST_ASSERT_NULL_MESSAGE(out_opt(IDEMIP_DHCP6_OPT_SERVERID, &l),
                             "sec 18.2.5 does not include the Server Identifier in a Rebind");
    TEST_ASSERT_NOT_NULL(out_opt(IDEMIP_DHCP6_OPT_IA_NA, &l));
}

// sec 18.2.5: the Rebind "is terminated when the valid lifetimes of all leases across all IAs have
// expired, at which time the client uses the Solicit message to locate a new DHCP server".
void test_the_rebind_ends_when_the_valid_lifetime_expires(void)
{
    to_bound(work_a, &g_cfg_a, 10u, 20u, 300u, 400u);
    tick(work_a, 10000u, 0u);
    tick(work_a, 20000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_REBINDING, IDEMIP_DHCP6_IO(work_a)->state);
    tick(work_a, 400000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
    for (uint32_t i = 0u; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0u, IDEMIP_DHCP6_IO(work_a)->addr[i]);
    }
}

// sec 18.2.10.1: a Reply to a Renew updates the lifetimes and the client is BOUND again.
void test_a_reply_to_the_renew_extends_the_lease(void)
{
    to_bound(work_a, &g_cfg_a, 10u, 20u, 300u, 400u);
    tick(work_a, 10000u, 0u);
    tick(work_a, 10000u, 0u);
    build(work_a);
    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, IDEMIP_DHCP6_IO(work_a)->xid);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_ia_na(g_cfg_a.iaid, 500u, 800u, g_lease, 900u, 1000u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_BOUND, IDEMIP_DHCP6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(500u, IDEMIP_DHCP6_IO(work_a)->t1_s);
    TEST_ASSERT_EQUAL_UINT32(800u, IDEMIP_DHCP6_IO(work_a)->t2_s);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_DHCP6_IO(work_a)->valid_s);
    tick(work_a, 10000u + 499999u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP6_BOUND, IDEMIP_DHCP6_IO(work_a)->state,
                                  "sec 21.4 counts T1 from the reception of the Reply");
}

// --- sec 18.2.3 Confirm, sec 18.2.7 Release, sec 18.2.8 Decline -------------

// sec 18.2.3: the Confirm carries the client's IAs with T1, T2 and both lifetimes at 0, no Server
// Identifier per sec 16.5, and the exchange ends at CNF_MAX_RD with the leases kept.
void test_the_confirm_zeroes_its_times_and_ends_at_cnf_max_rd(void)
{
    to_bound(work_a, &g_cfg_a, 100u, 200u, 300u, 400u);
    Dhcp6.confirm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_CONFIRMING, IDEMIP_DHCP6_IO(work_a)->state);
    tick(work_a, 0u, 0u);
    TEST_ASSERT_TRUE(build(work_a) > 0u);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DHCP6_CONFIRM, g_out[IDEMIP_DHCP6_MSG_OFF_TYPE]);

    uint16_t l = 0u;
    TEST_ASSERT_NULL_MESSAGE(out_opt(IDEMIP_DHCP6_OPT_SERVERID, &l),
                             "sec 16.5 has a server discard a Confirm that includes a Server Identifier");
    const uint8_t *d = out_opt(IDEMIP_DHCP6_OPT_IA_NA, &l);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_UINT32(0u, rd32(d + 4u));
    TEST_ASSERT_EQUAL_UINT32(0u, rd32(d + 8u));
    const uint8_t *a = d + IDEMIP_DHCP6_IA_NA_FIXED_LEN + IDEMIP_DHCP6_OPT_HDR_LEN;
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lease, a, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT32(0u, rd32(a + IDEMIP_IP6_ADDR_LEN));
    TEST_ASSERT_EQUAL_UINT32(0u, rd32(a + IDEMIP_IP6_ADDR_LEN + 4u));

    tick(work_a, IDEMIP_DHCP6_CNF_MAX_RD_MS, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP6_BOUND, IDEMIP_DHCP6_IO(work_a)->state,
                                  "sec 18.2.3 keeps the leases when the Confirm exchange runs out of time");
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lease, IDEMIP_DHCP6_IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
}

// sec 18.2.10.3: "When the client only receives one or more Reply messages with the NotOnLink status
// in response to a Confirm message, the client performs DHCP server discovery."
void test_a_not_on_link_confirm_reply_restarts_discovery(void)
{
    to_bound(work_a, &g_cfg_a, 100u, 200u, 300u, 400u);
    Dhcp6.confirm(work_a);
    tick(work_a, 0u, 0u);
    build(work_a);
    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, IDEMIP_DHCP6_IO(work_a)->xid);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_status((uint16_t)IDEMIP_DHCP6_STATUS_NOT_ON_LINK);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
}

// sec 18.2.7: the Release names the allocating server, carries the leases being released, and
// sec 18.2.10.2 completes the event "regardless of the Status Code option returned by the server".
void test_the_release_names_the_server_and_the_lease(void)
{
    to_bound(work_a, &g_cfg_a, 100u, 200u, 300u, 400u);
    Dhcp6.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_RELEASING, IDEMIP_DHCP6_IO(work_a)->state);
    tick(work_a, 0u, 0u);
    TEST_ASSERT_TRUE(build(work_a) > 0u);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DHCP6_RELEASE, g_out[IDEMIP_DHCP6_MSG_OFF_TYPE]);
    uint16_t l = 0u;
    TEST_ASSERT_NOT_NULL(out_opt(IDEMIP_DHCP6_OPT_SERVERID, &l));
    TEST_ASSERT_NOT_NULL(out_opt(IDEMIP_DHCP6_OPT_ELAPSED_TIME, &l));
    const uint8_t *d = out_opt(IDEMIP_DHCP6_OPT_IA_NA, &l);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lease, d + IDEMIP_DHCP6_IA_NA_FIXED_LEN + IDEMIP_DHCP6_OPT_HDR_LEN,
                                 IDEMIP_IP6_ADDR_LEN);

    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, IDEMIP_DHCP6_IO(work_a)->xid);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_status((uint16_t)IDEMIP_DHCP6_STATUS_NO_BINDING);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP6_IDLE, IDEMIP_DHCP6_IO(work_a)->state,
                                  "sec 18.2.10.2 completes the Release whatever the status code");
    for (uint32_t i = 0u; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0u, IDEMIP_DHCP6_IO(work_a)->addr[i]);
    }
}

// sec 15 with sec 18.2.7's REL_MAX_RC and sec 18.2.8's DEC_MAX_RC: the exchange fails once the client
// has transmitted the message MRC times.
void test_release_and_decline_stop_at_their_retry_counts(void)
{
    to_bound(work_a, &g_cfg_a, 100u, 200u, 300u, 400u);
    Dhcp6.release(work_a);
    uint32_t now = 0u;
    uint32_t sent = 0u;
    for (uint32_t step = 0u; step < 20u; step++)
    {
        tick(work_a, now, 0u);
        if (build(work_a) > 0u)
        {
            sent++;
        }
        if (IDEMIP_DHCP6_IO(work_a)->state != IDEMIP_DHCP6_RELEASING)
        {
            break;
        }
        now = due_at(work_a, now + (64u * IDEMIP_DHCP6_REL_TIMEOUT_MS), 0u);
    }
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_DHCP6_REL_MAX_RC, sent);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_IDLE, IDEMIP_DHCP6_IO(work_a)->state);

    to_bound(work_b, &g_cfg_rc, 100u, 200u, 300u, 400u);
    Dhcp6.decline(work_b);
    now = 0u;
    sent = 0u;
    for (uint32_t step = 0u; step < 20u; step++)
    {
        tick(work_b, now, 0u);
        if (build(work_b) > 0u)
        {
            sent++;
        }
        if (IDEMIP_DHCP6_IO(work_b)->state != IDEMIP_DHCP6_DECLINING)
        {
            break;
        }
        now = due_at(work_b, now + (64u * IDEMIP_DHCP6_DEC_TIMEOUT_MS), 0u);
    }
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_DHCP6_DEC_MAX_RC, sent);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_IDLE, IDEMIP_DHCP6_IO(work_b)->state);
}

// sec 18.2.3, sec 18.2.7 and sec 18.2.8 each need leases to name, so without one the entry is ERR:
// calling it again cannot produce a lease.
void test_confirm_release_and_decline_refuse_without_a_lease(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    Dhcp6.confirm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    Dhcp6.decline(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);

    arm_start(work_b, &g_cfg_b, 0x00112233u);
    Dhcp6.confirm(work_b);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_b)->status,
                                  "sec 18.2.3 confirms addresses, and a stateless client holds none");
}

// --- RFC 3646 and sec 21.23, the stateless configuration --------------------

// RFC 3646 sec 3: the DNS Recursive Name Server option lists one 16-octet address per server, in the
// caller's own message octets, and its option-len "must be a multiple of 16".
void test_the_dns_servers_option_is_read_out_of_the_message(void)
{
    arm_start(work_b, &g_cfg_b, 0x00112233u);
    build(work_b);
    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, 0x00112233u);
    msg_clientid(&g_cfg_b);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    uint8_t *dns = msg_opt(IDEMIP_DHCP6_OPT_DNS_SERVERS, 2u * IDEMIP_IP6_ADDR_LEN);
    memcpy(dns, g_lease, IDEMIP_IP6_ADDR_LEN);
    memcpy(dns + IDEMIP_IP6_ADDR_LEN, g_lease2, IDEMIP_IP6_ADDR_LEN);
    feed(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_b)->status);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_DHCP6_IO(work_b)->dns_count);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(dns, IDEMIP_DHCP6_IO(work_b)->dns, "the servers are read where the caller left them");
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lease, IDEMIP_DHCP6_IO(work_b)->dns, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_lease2, IDEMIP_DHCP6_IO(work_b)->dns + IDEMIP_IP6_ADDR_LEN, IDEMIP_IP6_ADDR_LEN);
}

// RFC 3646 sec 3: an option-len that is not a multiple of 16 carries no whole address.
void test_a_dns_servers_option_of_a_ragged_length_is_ignored(void)
{
    arm_start(work_b, &g_cfg_b, 0x00112233u);
    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, 0x00112233u);
    msg_clientid(&g_cfg_b);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    memcpy(msg_opt(IDEMIP_DHCP6_OPT_DNS_SERVERS, IDEMIP_IP6_ADDR_LEN - 1u), g_lease, IDEMIP_IP6_ADDR_LEN - 1u);
    feed(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_b)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_DHCP6_IO(work_b)->dns_count);
    TEST_ASSERT_NULL(IDEMIP_DHCP6_IO(work_b)->dns);
}

// sec 21.23: the refresh time schedules the next Information-request, an absent option means
// IRT_DEFAULT, and "The option value MUST NOT be smaller than IRT_MINIMUM".
void test_the_information_refresh_time_schedules_the_next_request(void)
{
    arm_start(work_b, &g_cfg_b, 0x00112233u);
    build(work_b);
    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, 0x00112233u);
    msg_clientid(&g_cfg_b);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    feed(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_BOUND, IDEMIP_DHCP6_IO(work_b)->state);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(IDEMIP_DHCP6_IRT_DEFAULT_S, IDEMIP_DHCP6_IO(work_b)->t1_s,
                                     "an absent Information Refresh Time option must read as IRT_DEFAULT");

    Dhcp6.clear(work_b);
    arm_start(work_b, &g_cfg_b, 0x00112233u);
    build(work_b);
    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, 0x00112233u);
    msg_clientid(&g_cfg_b);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    put32(msg_opt(IDEMIP_DHCP6_OPT_INFO_REFRESH, IDEMIP_DHCP6_INFO_REFRESH_LEN), 100u);
    feed(work_b);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(IDEMIP_DHCP6_IRT_MINIMUM_S, IDEMIP_DHCP6_IO(work_b)->t1_s,
                                     "a refresh time under IRT_MINIMUM was taken as sent");

    tick(work_b, (IDEMIP_DHCP6_IRT_MINIMUM_S * 1000u) - 1u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_BOUND, IDEMIP_DHCP6_IO(work_b)->state);
    tick(work_b, IDEMIP_DHCP6_IRT_MINIMUM_S * 1000u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP6_INFO_REQUESTING, IDEMIP_DHCP6_IO(work_b)->state,
                                  "the sec 21.23 refresh did not start another Information-request");
}

// sec 21.25: an INF_MAX_RT override outside 60 through 86400 is ignored, and one inside it is taken.
void test_inf_max_rt_is_taken_only_inside_its_range(void)
{
    arm_start(work_b, &g_cfg_b, 0x00112233u);
    msg_begin((uint8_t)IDEMIP_DHCP6_REPLY, 0x00112233u);
    msg_clientid(&g_cfg_b);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    put32(msg_opt(IDEMIP_DHCP6_OPT_INF_MAX_RT, IDEMIP_DHCP6_MAX_RT_LEN), IDEMIP_DHCP6_MAX_RT_MAX_S + 1u);
    msg_status((uint16_t)IDEMIP_DHCP6_STATUS_UNSPEC_FAIL);
    feed(work_b);

    uint32_t now = 0u;
    uint32_t rt = due_at(work_b, 4u * IDEMIP_DHCP6_INF_TIMEOUT_MS, 0u) - now;
    for (uint32_t step = 0u; step < 14u; step++)
    {
        now += rt;
        tick(work_b, now, 0u);
        rt = due_at(work_b, now + (4u * IDEMIP_DHCP6_INF_MAX_RT_MS), 0u) - now;
    }
    TEST_ASSERT_TRUE_MESSAGE(rt <= IDEMIP_DHCP6_INF_MAX_RT_MS + rand_bound(IDEMIP_DHCP6_INF_MAX_RT_MS),
                             "an INF_MAX_RT past sec 21.25's ceiling of 86400 was applied");
    TEST_ASSERT_TRUE_MESSAGE(rt >= IDEMIP_DHCP6_INF_MAX_RT_MS - rand_bound(IDEMIP_DHCP6_INF_MAX_RT_MS),
                             "RT settled under the sec 7.6 INF_MAX_RT default");
}

// --- the borrow is the instance ---------------------------------------------

// Two clients on two borrows run different exchanges at the same time and share not one byte.
void test_two_clients_run_independent_exchanges(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    arm_start(work_b, &g_cfg_b, 0x00112233u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_SOLICITING, IDEMIP_DHCP6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_INFO_REQUESTING, IDEMIP_DHCP6_IO(work_b)->state);

    build(work_a);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DHCP6_SOLICIT, g_out[IDEMIP_DHCP6_MSG_OFF_TYPE]);
    build(work_b);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DHCP6_INFORMATION_REQUEST, g_out[IDEMIP_DHCP6_MSG_OFF_TYPE]);

    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    msg_clientid(&g_cfg_a);
    msg_serverid(g_sduid, (uint16_t)sizeof g_sduid);
    msg_pref(IDEMIP_DHCP6_PREF_IMMEDIATE);
    msg_ia_na(g_cfg_a.iaid, 0u, 0u, g_lease, 100u, 200u, 0, 0u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_REQUESTING, IDEMIP_DHCP6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP6_INFO_REQUESTING, IDEMIP_DHCP6_IO(work_b)->state,
                                  "one client's Advertise moved the other client");
    TEST_ASSERT_EQUAL_HEX32(0x00112233u, IDEMIP_DHCP6_IO(work_b)->xid);
}

// stop ends the running exchange and gives up the lease without a message.
void test_stop_ends_the_exchange_and_drops_the_lease(void)
{
    to_bound(work_a, &g_cfg_a, 100u, 200u, 300u, 400u);
    Dhcp6.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_IDLE, IDEMIP_DHCP6_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_DHCP6_IO(work_a)->valid_s);
    for (uint32_t i = 0u; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0u, IDEMIP_DHCP6_IO(work_a)->addr[i]);
    }
    TEST_ASSERT_EQUAL_size_t(0u, build(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DHCP6_IO(work_a)->status);
    tick(work_a, 1000000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP6_IDLE, IDEMIP_DHCP6_IO(work_a)->state);
}

// start belongs to an idle client. A second one while an exchange runs is ERR, since repeating it
// cannot make the running exchange go away.
void test_start_refuses_a_running_client(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    IDEMIP_DHCP6_IO(work_a)->start_args.xid = 0x00000011u;
    Dhcp6.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(0x00ABCDEFu, IDEMIP_DHCP6_IO(work_a)->xid);
    Dhcp6.stop(work_a);
    Dhcp6.start(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(0x00000011u, IDEMIP_DHCP6_IO(work_a)->xid);
}

// A message shorter than the sec 8 fixed header is not a message, and a null one is not either.
void test_a_short_or_absent_message_is_refused(void)
{
    arm_start(work_a, &g_cfg_a, 0x00ABCDEFu);
    msg_begin((uint8_t)IDEMIP_DHCP6_ADVERTISE, 0x00ABCDEFu);
    IDEMIP_DHCP6_IO(work_a)->input_args.msg = g_msg;
    IDEMIP_DHCP6_IO(work_a)->input_args.src = g_src;
    IDEMIP_DHCP6_IO(work_a)->input_args.len = IDEMIP_DHCP6_FIXED_LEN - 1u;
    Dhcp6.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);

    IDEMIP_DHCP6_IO(work_a)->input_args.msg = NULL;
    IDEMIP_DHCP6_IO(work_a)->input_args.len = 64u;
    Dhcp6.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);

    IDEMIP_DHCP6_IO(work_a)->input_args.msg = g_msg;
    IDEMIP_DHCP6_IO(work_a)->input_args.src = NULL;
    Dhcp6.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP6_IO(work_a)->status);
}
