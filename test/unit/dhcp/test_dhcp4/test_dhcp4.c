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
// The behavior cases below it walk the RFC 2131 sec 4.4 Figure 5 machine. Neither RFC 2131 nor
// RFC 2132 prints a byte vector for a whole DHCP message: RFC 2131 Figure 1 is a field layout,
// Figures 3, 4 and 5 are timelines, and Tables 1, 2, 4 and 5 name fields and options rather than
// octets. What both RFCs do print in octets is the magic cookie ("63.82.53.63", RFC 2132 sec 2) and
// every option's Code/Len diagram (sec 3.3, sec 3.5, sec 3.8, sec 9.1 through sec 9.14), so those are
// the vectors used here and the rest are the properties the text states.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/dhcp/dhcp4.h"

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

// =============================================================================
// The RFC 2131 sec 4.4 machine
// =============================================================================

// One received message, built the way a server would. RFC 2131 sec 2, Table 1: 'op' 2 is BOOTREPLY,
// 'htype' 1 is 10mb ethernet and 'hlen' is 6 for it.
static uint8_t g_msg[IDEMIP_DHCP4_MSG_MIN];
static size_t g_msg_at;  // where the next option goes
static size_t g_msg_len; // what input is told the message spans

// The buffer build writes into, and a canary past what a message may span.
static uint8_t g_out[IDEMIP_DHCP4_MSG_MIN];

#define XID_A 0x3903F326u    // an arbitrary transaction id, the same in every message of one exchange
#define IP_OFFER 0xC0A80164u // 192.168.1.100
#define IP_MASK 0xFFFFFF00u  // 255.255.255.0
#define IP_ROUTER 0xC0A80101u
#define IP_SERVER 0xC0A801FEu
#define IP_DNS1 0xC0A80102u
#define IP_DNS2 0x08080808u
#define IP_BROADCAST 0xFFFFFFFFu

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

// The fixed part of a reply, then the RFC 2132 sec 9.6 message type option.
static void msg_begin(uint32_t xid, uint32_t yiaddr, uint8_t type, const uint8_t *chaddr)
{
    memset(g_msg, 0, sizeof g_msg);
    g_msg[IDEMIP_DHCP4_MSG_OFF_OP] = IDEMIP_DHCP4_OP_BOOTREPLY;
    g_msg[IDEMIP_DHCP4_MSG_OFF_HTYPE] = 1u;
    g_msg[IDEMIP_DHCP4_MSG_OFF_HLEN] = 6u;
    put32(g_msg + IDEMIP_DHCP4_MSG_OFF_XID, xid);
    put32(g_msg + IDEMIP_DHCP4_MSG_OFF_YIADDR, yiaddr);
    memcpy(g_msg + IDEMIP_DHCP4_MSG_OFF_CHADDR, chaddr, 6);
    put32(g_msg + IDEMIP_DHCP4_MSG_OFF_COOKIE, IDEMIP_DHCP4_MAGIC_COOKIE);
    g_msg_at = IDEMIP_DHCP4_MSG_OFF_OPTIONS;
    g_msg[g_msg_at++] = IDEMIP_DHCP4_OPT_MSG_TYPE;
    g_msg[g_msg_at++] = 1u;
    g_msg[g_msg_at++] = type;
    g_msg_len = IDEMIP_DHCP4_MSG_BOOTP_MIN;
}

// RFC 2132 sec 2: a tag octet, a length octet, then that many data octets.
static void msg_opt(uint8_t code, uint8_t len, const uint8_t *v)
{
    g_msg[g_msg_at++] = code;
    g_msg[g_msg_at++] = len;
    memcpy(g_msg + g_msg_at, v, len);
    g_msg_at += len;
}

static void msg_opt32(uint8_t code, uint32_t v)
{
    uint8_t b[4];
    put32(b, v);
    msg_opt(code, 4u, b);
}

static void msg_end(void)
{
    g_msg[g_msg_at++] = IDEMIP_DHCP4_OPT_END;
}

static void feed(uint8_t *w)
{
    IDEMIP_DHCP4_IO(w)->input_args.msg = g_msg;
    IDEMIP_DHCP4_IO(w)->input_args.len = g_msg_len;
    IDEMIP_DHCP4_IO(w)->input_args.src = IP_SERVER;
    Dhcp4.input(w);
}

// One option of a built message, or NULL. Walks it the way RFC 2132 sec 2 describes.
static const uint8_t *opt_find(const uint8_t *m, size_t len, uint8_t code, uint8_t *olen)
{
    size_t i = IDEMIP_DHCP4_MSG_OFF_OPTIONS;
    while (i < len)
    {
        uint8_t c = m[i];
        if (c == IDEMIP_DHCP4_OPT_END)
        {
            return NULL;
        }
        if (c == IDEMIP_DHCP4_OPT_PAD)
        {
            i++;
            continue;
        }
        if ((i + 2u) > len)
        {
            return NULL;
        }
        uint8_t n = m[i + 1u];
        if (c == code)
        {
            if (olen)
            {
                *olen = n;
            }
            return m + i + 2u;
        }
        i += 2u + (size_t)n;
    }
    return NULL;
}

static void tick_at(uint8_t *w, uint32_t now, uint32_t rand)
{
    IDEMIP_DHCP4_IO(w)->tick_args.now_ms = now;
    IDEMIP_DHCP4_IO(w)->tick_args.rand = rand;
    Dhcp4.tick(w);
}

static void build_ok(uint8_t *w)
{
    memset(g_out, 0, sizeof g_out);
    IDEMIP_DHCP4_IO(w)->build_args.out = g_out;
    IDEMIP_DHCP4_IO(w)->build_args.cap = sizeof g_out;
    Dhcp4.build(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(w)->status);
}

static void start_at(uint8_t *w, uint32_t now, uint32_t rand)
{
    IDEMIP_DHCP4_IO(w)->start_args.xid = XID_A;
    IDEMIP_DHCP4_IO(w)->start_args.now_ms = now;
    IDEMIP_DHCP4_IO(w)->start_args.rand = rand;
    Dhcp4.start(w);
}

// bind, start, let the sec 4.4.1 delay pass, and send the DHCPDISCOVER. rand 0 draws the shortest
// delay the section allows, one second, so the timeline below is exact.
static void to_selecting(uint8_t *w)
{
    bind_ok(w, &g_cfg_a);
    start_at(w, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(w)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(w)->state);
    tick_at(w, 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(w)->status);
    build_ok(w);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_DISCOVER, IDEMIP_DHCP4_IO(w)->msg_type);
}

// A DHCPOFFER carrying the sec 3.1 parameters, which moves SELECTING to REQUESTING.
static void offer_in(uint8_t *w, uint32_t lease_s)
{
    uint8_t dns[8];
    put32(dns, IP_DNS1);
    put32(dns + 4, IP_DNS2);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SUBNET_MASK, IP_MASK);
    msg_opt32(IDEMIP_DHCP4_OPT_ROUTER, IP_ROUTER);
    msg_opt(IDEMIP_DHCP4_OPT_DNS_SERVER, 8u, dns);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, lease_s);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(w);
}

// --- RFC 2132 sec 2, the option encoding -------------------------------------

// A DHCPOFFER carrying everything sec 3.1 asks for, and one more option the caller chose.
static void offer_with(uint8_t *w, uint8_t code, uint8_t len, const uint8_t *v)
{
    uint8_t dns[8];
    put32(dns, IP_DNS1);
    put32(dns + 4, IP_DNS2);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt(code, len, v);
    msg_opt32(IDEMIP_DHCP4_OPT_SUBNET_MASK, IP_MASK);
    msg_opt32(IDEMIP_DHCP4_OPT_ROUTER, IP_ROUTER);
    msg_opt(IDEMIP_DHCP4_OPT_DNS_SERVER, 8u, dns);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, 600u);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(w);
}

// RFC 2132 gives each option this client reads a length it must have: sec 3.3's mask is "4 octets",
// sec 3.5's router list and sec 3.8's server list are each "a multiple of 4" and hold at least one
// address, sec 9.2's lease time, sec 9.7's server identifier and sec 9.11 and sec 9.12's T1 and T2 are
// four octets, sec 9.3's overload and sec 9.6's message type are one. An option of any other length is
// not one this client can read, and dhcp4_walk refuses the message rather than the option: half a
// message is not a configuration.
void test_an_option_of_the_wrong_length_discards_the_message(void)
{
    static const struct
    {
        uint8_t code;
        uint8_t len;
        const char *why;
    } rows[] = {
        {IDEMIP_DHCP4_OPT_SUBNET_MASK, 3u, "sec 3.3 makes the subnet mask four octets"},
        {IDEMIP_DHCP4_OPT_ROUTER, 6u, "sec 3.5 makes the router list a multiple of four"},
        {IDEMIP_DHCP4_OPT_ROUTER, 0u, "sec 3.5 lists at least one router"},
        {IDEMIP_DHCP4_OPT_DNS_SERVER, 6u, "sec 3.8 makes the server list a multiple of four"},
        {IDEMIP_DHCP4_OPT_DNS_SERVER, 0u, "sec 3.8 lists at least one server"},
        {IDEMIP_DHCP4_OPT_LEASE_TIME, 3u, "sec 9.2 makes the lease time four octets"},
        {IDEMIP_DHCP4_OPT_OVERLOAD, 2u, "sec 9.3 makes the overload one octet"},
        {IDEMIP_DHCP4_OPT_OVERLOAD, 1u, "sec 9.3 leaves 0 out of the legal values"},
        {IDEMIP_DHCP4_OPT_MSG_TYPE, 2u, "sec 9.6 makes the message type one octet"},
        {IDEMIP_DHCP4_OPT_SERVER_ID, 3u, "sec 9.7 makes the server identifier four octets"},
        {IDEMIP_DHCP4_OPT_T1, 3u, "sec 9.11 makes T1 four octets"},
        {IDEMIP_DHCP4_OPT_T2, 3u, "sec 9.12 makes T2 four octets"},
    };

    for (size_t r = 0; r < sizeof rows / sizeof rows[0]; r++)
    {
        uint8_t v[8];
        memset(v, 0, sizeof v);
        if (rows[r].code == IDEMIP_DHCP4_OPT_OVERLOAD && rows[r].len == 1u)
        {
            v[0] = 0u; // sec 9.3's legal values are 1, 2 and 3
        }
        Dhcp4.clear(work_a);
        to_selecting(work_a);
        offer_with(work_a, rows[r].code, rows[r].len, v);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state, rows[r].why);
    }
}

// sec 3.1: "The pad option can be used to cause subsequent fields to align on word boundaries", and
// "The code for the pad option is 0, and its length is 1 octet" - one octet in all, so no length or
// value follows it. sec 2 skips an option this client does not read by that option's own length
// octet. Both leave the message readable, so the Offer is taken.
void test_a_pad_and_an_unread_option_are_stepped_over(void)
{
    const uint8_t junk[3] = {0xAAu, 0xBBu, 0xCCu};

    Dhcp4.clear(work_a);
    to_selecting(work_a);
    offer_with(work_a, IDEMIP_DHCP4_OPT_PAD, 0u, junk); // len 0 writes no value: a bare pad tag
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP4_REQUESTING, IDEMIP_DHCP4_IO(work_a)->state,
                                  "a pad octet stopped the walk");

    Dhcp4.clear(work_a);
    to_selecting(work_a);
    offer_with(work_a, 250u, 3u, junk); // 250 is site-specific, and nothing here reads it
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DHCP4_REQUESTING, IDEMIP_DHCP4_IO(work_a)->state,
                                  "an option this client does not read stopped the walk");
}

// bind through BOUND on a lease of @p lease_s seconds, the DHCPREQUEST going out at 1000 ms so every
// sec 4.4.5 deadline below is measured from there.
static void to_bound(uint8_t *w, uint32_t lease_s)
{
    to_selecting(w);
    offer_in(w, lease_s);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(w)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_REQUESTING, IDEMIP_DHCP4_IO(w)->state);
    build_ok(w);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_REQUEST, IDEMIP_DHCP4_IO(w)->msg_type);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_ACK, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SUBNET_MASK, IP_MASK);
    msg_opt32(IDEMIP_DHCP4_OPT_ROUTER, IP_ROUTER);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, lease_s);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(w)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_BOUND, IDEMIP_DHCP4_IO(w)->state);
}

// --- sec 4.4.1, INIT to SELECTING --------------------------------------------

// sec 4.4.1: "The client SHOULD wait a random time between one and ten seconds to desynchronize the
// use of DHCP at startup." Nothing is owed until it passes, so build has nothing to give.
void test_start_owes_nothing_until_the_section_441_delay_passes(void)
{
    bind_ok(work_a, &g_cfg_a);
    start_at(work_a, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);

    IDEMIP_DHCP4_IO(work_a)->build_args.out = g_out;
    IDEMIP_DHCP4_IO(work_a)->build_args.cap = sizeof g_out;
    Dhcp4.build(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status,
                                  "a message was owed before the sec 4.4.1 delay passed");
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_DHCP4_IO(work_a)->len);

    tick_at(work_a, 999u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status);
    tick_at(work_a, 1000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    build_ok(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_DISCOVER, IDEMIP_DHCP4_IO(work_a)->msg_type);
}

// The delay lands inside the one-to-ten-second span for every word it is drawn from: a tick one
// millisecond before one second never fires it, and a tick at ten seconds always has.
void test_the_start_delay_lands_between_one_and_ten_seconds(void)
{
    for (uint32_t i = 0; i < 64u; i++)
    {
        uint32_t rand = (i * 0x9E3779B9u) ^ (i << 17);
        arm(work_a, sizeof work_a);
        bind_ok(work_a, &g_cfg_a);
        start_at(work_a, 0u, rand);
        tick_at(work_a, IDEMIP_DHCP4_START_DELAY_MIN_MS - 1u, 0u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status,
                                      "the sec 4.4.1 delay fired inside one second");
        tick_at(work_a, IDEMIP_DHCP4_START_DELAY_MAX_MS, 0u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status,
                                      "the sec 4.4.1 delay outlasted ten seconds");
    }
}

// A machine already running an exchange is not restarted by start: sec 4.4 gives every state its own
// exchange, and stop is what returns one to INIT.
void test_start_is_refused_while_a_transaction_runs(void)
{
    to_selecting(work_a);
    start_at(work_a, 2000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);
}

// --- sec 4.1 and Table 5, what a DHCPDISCOVER carries ------------------------

// Table 5's DHCPDISCOVER column: 'op' BOOTREQUEST, 'hops' 0, 'yiaddr', 'siaddr' and 'giaddr' 0,
// 'ciaddr' 0, 'chaddr' the client's hardware address, and the server identifier MUST NOT appear.
void test_the_discover_carries_the_table_5_fields(void)
{
    to_selecting(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_OP_BOOTREQUEST, g_out[IDEMIP_DHCP4_MSG_OFF_OP]);
    TEST_ASSERT_EQUAL_UINT8(1u, g_out[IDEMIP_DHCP4_MSG_OFF_HTYPE]);
    TEST_ASSERT_EQUAL_UINT8(6u, g_out[IDEMIP_DHCP4_MSG_OFF_HLEN]);
    TEST_ASSERT_EQUAL_UINT8(0u, g_out[IDEMIP_DHCP4_MSG_OFF_HOPS]);
    TEST_ASSERT_EQUAL_HEX32(XID_A, get32(g_out + IDEMIP_DHCP4_MSG_OFF_XID));
    TEST_ASSERT_EQUAL_HEX32(0u, get32(g_out + IDEMIP_DHCP4_MSG_OFF_CIADDR));
    TEST_ASSERT_EQUAL_HEX32(0u, get32(g_out + IDEMIP_DHCP4_MSG_OFF_YIADDR));
    TEST_ASSERT_EQUAL_HEX32(0u, get32(g_out + IDEMIP_DHCP4_MSG_OFF_SIADDR));
    TEST_ASSERT_EQUAL_HEX32(0u, get32(g_out + IDEMIP_DHCP4_MSG_OFF_GIADDR));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_mac_a, g_out + IDEMIP_DHCP4_MSG_OFF_CHADDR, 6);

    // RFC 2132 sec 2 prints the cookie as "the 4 octet dotted decimal 99.130.83.99 (or hexadecimal
    // number 63.82.53.63) in network byte order".
    TEST_ASSERT_EQUAL_HEX8(0x63u, g_out[IDEMIP_DHCP4_MSG_OFF_COOKIE + 0u]);
    TEST_ASSERT_EQUAL_HEX8(0x82u, g_out[IDEMIP_DHCP4_MSG_OFF_COOKIE + 1u]);
    TEST_ASSERT_EQUAL_HEX8(0x53u, g_out[IDEMIP_DHCP4_MSG_OFF_COOKIE + 2u]);
    TEST_ASSERT_EQUAL_HEX8(0x63u, g_out[IDEMIP_DHCP4_MSG_OFF_COOKIE + 3u]);

    uint8_t n = 0;
    const uint8_t *v = opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_MSG_TYPE, &n);
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT_EQUAL_UINT8(1u, n); // sec 9.6, "its length is 1"
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_DISCOVER, v[0]);

    // sec 3.5: the client SHOULD say how large a message it accepts, and sec 9.10's minimum legal
    // value is 576.
    v = opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_MAX_MSG_SIZE, &n);
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT_EQUAL_UINT8(2u, n);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP4_MSG_MIN, get16(v));

    // sec 9.8: one octet per requested code, which are the options this client reads.
    v = opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_PARAM_LIST, &n);
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT_EQUAL_UINT8(3u, n);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_OPT_SUBNET_MASK, v[0]);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_OPT_ROUTER, v[1]);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_OPT_DNS_SERVER, v[2]);

    // sec 9.2: the lease the client asks for, which g_cfg_a sets to 7200 seconds.
    v = opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_LEASE_TIME, &n);
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT_EQUAL_UINT8(4u, n);
    TEST_ASSERT_EQUAL_UINT32(7200u, get32(v));

    // Table 5: "Server identifier ... MUST NOT" in a DHCPDISCOVER.
    TEST_ASSERT_NULL(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_SERVER_ID, &n));
}

// RFC 1542 sec 2.1: every BOOTP entity checks that the message is "large enough to contain the
// minimal BOOTP header of 300 octets (in the UDP data field)", and RFC 2132 sec 3.2 fills the octets
// past the end option with pad options.
void test_a_built_message_spans_the_minimal_bootp_header(void)
{
    to_selecting(work_a);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_DHCP4_MSG_BOOTP_MIN, IDEMIP_DHCP4_IO(work_a)->len);

    size_t end = 0;
    for (size_t i = IDEMIP_DHCP4_MSG_OFF_OPTIONS; i < IDEMIP_DHCP4_IO(work_a)->len; i++)
    {
        if (g_out[i] == IDEMIP_DHCP4_OPT_END)
        {
            end = i;
            break;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(end != 0u, "the built message carries no sec 3.2 end option");
    for (size_t i = end + 1u; i < IDEMIP_DHCP4_IO(work_a)->len; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(IDEMIP_DHCP4_OPT_PAD, g_out[i], "an octet past the end option is not a pad");
    }
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP4_PORT_SERVER, IDEMIP_DHCP4_IO(work_a)->dst_port);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DHCP4_PORT_CLIENT, IDEMIP_DHCP4_IO(work_a)->src_port);
    TEST_ASSERT_EQUAL_HEX32(IP_BROADCAST, IDEMIP_DHCP4_IO(work_a)->dst);
}

// sec 4.1: "A client that cannot receive unicast IP datagrams until its protocol software has been
// configured with an IP address SHOULD set the BROADCAST bit in the 'flags' field to 1 ... A client
// that can receive unicast IP datagrams before its protocol software has been configured SHOULD clear
// the BROADCAST bit to 0." g_cfg_a sets it, g_cfg_b does not.
void test_the_broadcast_flag_follows_the_configuration(void)
{
    to_selecting(work_a);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_DHCP4_FLAG_BROADCAST, get16(g_out + IDEMIP_DHCP4_MSG_OFF_FLAGS));

    bind_ok(work_b, &g_cfg_b);
    start_at(work_b, 0u, 0u);
    tick_at(work_b, 1000u, 0u);
    build_ok(work_b);
    TEST_ASSERT_EQUAL_HEX16(0u, get16(g_out + IDEMIP_DHCP4_MSG_OFF_FLAGS));
}

// --- sec 4.4.1, SELECTING to REQUESTING --------------------------------------

// sec 3.1: the DHCPREQUEST "MUST include the 'server identifier' option to indicate which server it
// has selected", so an offer that names no server cannot be the one selected.
void test_an_offer_without_a_server_identifier_is_not_selected(void)
{
    to_selecting(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SUBNET_MASK, IP_MASK);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->offered_ip);
}

// sec 4.4.1: the client "extracts the server address from the 'server identifier' option in the
// DHCPOFFER message", and 'yiaddr' carries "an available network address". Figure 5's "Select offer/
// send DHCPREQUEST" moves SELECTING to REQUESTING.
void test_an_offer_records_the_parameters_and_moves_to_requesting(void)
{
    to_selecting(work_a);
    offer_in(work_a, 7200u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_OFFER, IDEMIP_DHCP4_IO(work_a)->msg_type);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_REQUESTING, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, IDEMIP_DHCP4_IO(work_a)->offered_ip);
    TEST_ASSERT_EQUAL_HEX32(IP_MASK, IDEMIP_DHCP4_IO(work_a)->subnet_mask);
    TEST_ASSERT_EQUAL_HEX32(IP_ROUTER, IDEMIP_DHCP4_IO(work_a)->router);
    TEST_ASSERT_EQUAL_HEX32(IP_SERVER, IDEMIP_DHCP4_IO(work_a)->server_id);
    TEST_ASSERT_EQUAL_UINT32(7200u, IDEMIP_DHCP4_IO(work_a)->lease_s);
}

// RFC 2132 sec 3.8 lists the name servers "in order of preference", every one of them, and they stay
// in the caller's message octets rather than being copied into the borrow.
void test_the_dns_option_reports_every_address_where_it_lies(void)
{
    to_selecting(work_a);
    offer_in(work_a, 7200u);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_DHCP4_IO(work_a)->dns_count);
    TEST_ASSERT_NOT_NULL(IDEMIP_DHCP4_IO(work_a)->dns);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_DHCP4_IO(work_a)->dns > g_msg &&
                                 IDEMIP_DHCP4_IO(work_a)->dns < (g_msg + sizeof g_msg),
                             "the option 6 addresses were copied out of the caller's octets");
    TEST_ASSERT_EQUAL_HEX32(IP_DNS1, get32(IDEMIP_DHCP4_IO(work_a)->dns));
    TEST_ASSERT_EQUAL_HEX32(IP_DNS2, get32(IDEMIP_DHCP4_IO(work_a)->dns + 4));
}

// Table 4's SELECTING column: broadcast, server-ip MUST, requested-ip MUST, 'ciaddr' zero. sec 4.4.1:
// "The DHCPREQUEST message contains the same 'xid' as the DHCPOFFER message."
void test_the_request_out_of_selecting_names_the_server_and_the_address(void)
{
    to_selecting(work_a);
    offer_in(work_a, 7200u);
    build_ok(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_REQUEST, IDEMIP_DHCP4_IO(work_a)->msg_type);
    TEST_ASSERT_EQUAL_HEX32(IP_BROADCAST, IDEMIP_DHCP4_IO(work_a)->dst);
    TEST_ASSERT_EQUAL_HEX32(XID_A, get32(g_out + IDEMIP_DHCP4_MSG_OFF_XID));
    TEST_ASSERT_EQUAL_HEX32(0u, get32(g_out + IDEMIP_DHCP4_MSG_OFF_CIADDR));

    uint8_t n = 0;
    const uint8_t *v = opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_SERVER_ID, &n);
    TEST_ASSERT_NOT_NULL_MESSAGE(v, "Table 4 makes the server identifier a MUST out of SELECTING");
    TEST_ASSERT_EQUAL_UINT8(4u, n);
    TEST_ASSERT_EQUAL_HEX32(IP_SERVER, get32(v));

    v = opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_REQUESTED_IP, &n);
    TEST_ASSERT_NOT_NULL_MESSAGE(v, "sec 3.1 makes the requested address the offer's 'yiaddr'");
    TEST_ASSERT_EQUAL_UINT8(4u, n);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, get32(v));
}

// --- sec 4.4.5, the lease and its two times ----------------------------------

// sec 4.4.5: "T1 defaults to (0.5 * duration_of_lease). T2 defaults to (0.875 * duration_of_lease)."
// A 7200-second lease therefore gives T1 3600 and T2 6300.
void test_an_ack_with_no_t1_or_t2_takes_the_section_445_defaults(void)
{
    to_bound(work_a, 7200u);
    TEST_ASSERT_EQUAL_UINT32(7200u, IDEMIP_DHCP4_IO(work_a)->lease_s);
    TEST_ASSERT_EQUAL_UINT32(3600u, IDEMIP_DHCP4_IO(work_a)->t1_s);
    TEST_ASSERT_EQUAL_UINT32(6300u, IDEMIP_DHCP4_IO(work_a)->t2_s);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, IDEMIP_DHCP4_IO(work_a)->offered_ip);
}

// RFC 2132 sec 9.11 and sec 9.12 let the server name T1 and T2, and sec 4.4.5 requires "T1 MUST be
// earlier than T2, which, in turn, MUST be earlier than the time at which the client's lease will
// expire", so a pair that satisfies it is taken.
void test_an_ordered_t1_and_t2_from_the_server_are_taken(void)
{
    to_selecting(work_a);
    offer_in(work_a, 7200u);
    build_ok(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_ACK, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, 7200u);
    msg_opt32(IDEMIP_DHCP4_OPT_T1, 1800u);
    msg_opt32(IDEMIP_DHCP4_OPT_T2, 3000u);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(1800u, IDEMIP_DHCP4_IO(work_a)->t1_s);
    TEST_ASSERT_EQUAL_UINT32(3000u, IDEMIP_DHCP4_IO(work_a)->t2_s);
}

// The same MUST refuses the pair the other way around: T1 at 5000 is not earlier than T2 at 1000, so
// the sec 4.4.5 defaults stand instead.
void test_a_t1_after_t2_falls_back_to_the_section_445_defaults(void)
{
    to_selecting(work_a);
    offer_in(work_a, 7200u);
    build_ok(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_ACK, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, 7200u);
    msg_opt32(IDEMIP_DHCP4_OPT_T1, 5000u);
    msg_opt32(IDEMIP_DHCP4_OPT_T2, 1000u);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(3600u, IDEMIP_DHCP4_IO(work_a)->t1_s);
    TEST_ASSERT_EQUAL_UINT32(6300u, IDEMIP_DHCP4_IO(work_a)->t2_s);
}

// A T2 at or past the lease fails the same MUST, the lease having to expire last.
void test_a_t2_past_the_lease_falls_back_to_the_section_445_defaults(void)
{
    to_selecting(work_a);
    offer_in(work_a, 7200u);
    build_ok(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_ACK, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, 7200u);
    msg_opt32(IDEMIP_DHCP4_OPT_T1, 1800u);
    msg_opt32(IDEMIP_DHCP4_OPT_T2, 9000u);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_UINT32(3600u, IDEMIP_DHCP4_IO(work_a)->t1_s);
    TEST_ASSERT_EQUAL_UINT32(6300u, IDEMIP_DHCP4_IO(work_a)->t2_s);
}

// sec 4.4.5: "At time T1 the client moves to RENEWING state and sends (via unicast) a DHCPREQUEST
// message to the server to extend its lease. The client sets the 'ciaddr' field in the DHCPREQUEST to
// its current network address. ... The client MUST NOT include a 'server identifier'." Table 4 also
// makes the requested address a MUST NOT there. The DHCPREQUEST went out at 1000 ms, so T1 of 3600
// seconds falls at 3601000 ms.
void test_t1_moves_bound_to_renewing_and_unicasts_to_the_leasing_server(void)
{
    to_bound(work_a, 7200u);
    tick_at(work_a, 3600999u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_BOUND, IDEMIP_DHCP4_IO(work_a)->state);

    tick_at(work_a, 3601000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_RENEWING, IDEMIP_DHCP4_IO(work_a)->state);

    build_ok(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_REQUEST, IDEMIP_DHCP4_IO(work_a)->msg_type);
    TEST_ASSERT_EQUAL_HEX32(IP_SERVER, IDEMIP_DHCP4_IO(work_a)->dst);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, get32(g_out + IDEMIP_DHCP4_MSG_OFF_CIADDR));
    TEST_ASSERT_NULL_MESSAGE(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_SERVER_ID, NULL),
                             "sec 4.4.5 forbids a server identifier in a renewing DHCPREQUEST");
    TEST_ASSERT_NULL_MESSAGE(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_REQUESTED_IP, NULL),
                             "Table 4 forbids a requested address in a renewing DHCPREQUEST");
    // sec 4.1's BROADCAST bit is for a client without an address, and this one has 'ciaddr'.
    TEST_ASSERT_EQUAL_HEX16(0u, get16(g_out + IDEMIP_DHCP4_MSG_OFF_FLAGS));
}

// sec 4.4.5: "If no DHCPACK arrives before time T2, the client moves to REBINDING state and sends (via
// broadcast) a DHCPREQUEST message to extend its lease." T2 of 6300 seconds falls at 6301000 ms.
void test_t2_moves_to_rebinding_and_broadcasts(void)
{
    to_bound(work_a, 7200u);
    tick_at(work_a, 6301000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_REBINDING, IDEMIP_DHCP4_IO(work_a)->state);
    build_ok(work_a);
    TEST_ASSERT_EQUAL_HEX32(IP_BROADCAST, IDEMIP_DHCP4_IO(work_a)->dst);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, get32(g_out + IDEMIP_DHCP4_MSG_OFF_CIADDR));
    TEST_ASSERT_NULL(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_SERVER_ID, NULL));
}

// sec 4.4.5: "When the client receives a DHCPACK from the server ... The client has successfully
// reacquired its network address, returns to BOUND state."
void test_an_ack_in_renewing_returns_the_machine_to_bound(void)
{
    to_bound(work_a, 7200u);
    tick_at(work_a, 3601000u, 0u);
    build_ok(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_ACK, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, 7200u);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_BOUND, IDEMIP_DHCP4_IO(work_a)->state);
    // The lease is measured from the renewal, so T1 is 3600 seconds past 3601000 ms.
    tick_at(work_a, 7200999u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status);
    tick_at(work_a, 7201000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_RENEWING, IDEMIP_DHCP4_IO(work_a)->state);
}

// sec 4.4.5: "If the lease expires before the client receives a DHCPACK, the client moves to INIT
// state, MUST immediately stop any other network processing." The lease of 7200 seconds ends at
// 7201000 ms, measured from the DHCPREQUEST at 1000.
void test_the_lease_expiry_returns_the_machine_to_init_with_no_address(void)
{
    to_bound(work_a, 7200u);
    tick_at(work_a, 7201000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->offered_ip);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_DHCP4_IO(work_a)->lease_s);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->server_id);
}

// sec 3.3: "The time value of 0xffffffff is reserved to represent 'infinity'", so no deadline runs
// over such a lease.
void test_an_infinite_lease_runs_no_deadline(void)
{
    to_bound(work_a, IDEMIP_DHCP4_TIME_INFINITE);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_DHCP4_TIME_INFINITE, IDEMIP_DHCP4_IO(work_a)->lease_s);
    tick_at(work_a, 0xF0000000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_BOUND, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, IDEMIP_DHCP4_IO(work_a)->offered_ip);
}

// sec 4.4.5: in RENEWING the client "SHOULD wait one-half of the remaining time until T2 ... down to a
// minimum of 60 seconds, before retransmitting the DHCPREQUEST message". At T1 of 3601000 ms with T2
// at 6301000 the half is 1350000 ms, which is above the floor, so the retransmission waits it out.
void test_a_renewing_retransmission_waits_half_the_time_left_to_t2(void)
{
    to_bound(work_a, 7200u);
    tick_at(work_a, 3601000u, 0u); // T1
    build_ok(work_a);
    // The jitter is drawn over [-1, +1] seconds, so the earliest the deadline can fall is one second
    // below half the span and the latest one second above it.
    tick_at(work_a, 3601000u + 1350000u - 1001u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status,
                                  "a renewing retransmission fired before half the time to T2");
    tick_at(work_a, 3601000u + 1350000u + 1001u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_RENEWING, IDEMIP_DHCP4_IO(work_a)->state);
}

// --- sec 4.1, the retransmission backoff -------------------------------------

// sec 4.1: "the delay before the first retransmission SHOULD be 4 seconds randomized by the value of
// a uniform random number chosen from the range -1 to +1 ... The delay before the next retransmission
// SHOULD be 8 seconds ... The retransmission delay SHOULD be doubled with subsequent retransmissions
// up to a maximum of 64 seconds." A random word of 0 draws the low end of each span.
void test_the_discover_backoff_doubles_from_four_seconds_to_sixty_four(void)
{
    to_selecting(work_a);
    uint32_t now = 1000u;
    uint32_t expect[6] = {4000u, 8000u, 16000u, 32000u, 64000u, 64000u};
    for (unsigned k = 0; k < 6u; k++)
    {
        uint32_t low = expect[k] - IDEMIP_DHCP4_JITTER_MS;
        tick_at(work_a, now + low - 1u, 0u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status,
                                      "a retransmission fired before its sec 4.1 delay");
        tick_at(work_a, now + low, 0u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status,
                                      "a retransmission did not fire at its sec 4.1 delay");
        now += low;
        build_ok(work_a);
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_DISCOVER, IDEMIP_DHCP4_IO(work_a)->msg_type);
    }
}

// The same delay drawn from the top of the range: the jitter never puts the deadline more than one
// second past the doubled value. The first DHCPDISCOVER went out at 1000 ms with the low word, so its
// retransmission falls at 4000 and the one after it doubles 4 seconds to 8.
void test_the_backoff_jitter_stays_inside_one_second(void)
{
    to_selecting(work_a);
    tick_at(work_a, 4000u, IDEMIP_DHCP4_JITTER_MS << 1u); // draws the high end of [-1, +1] seconds
    build_ok(work_a);
    uint32_t high = 4000u + (IDEMIP_DHCP4_RETRY_BASE_MS << 1u) + IDEMIP_DHCP4_JITTER_MS;
    tick_at(work_a, high - 1u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status,
                                  "the sec 4.1 jitter fired the retransmission early");
    tick_at(work_a, high, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status,
                                  "the sec 4.1 jitter put the retransmission past one second");
}

// sec 3.1: a client "might retransmit the DHCPREQUEST message four times ... before restarting the
// initialization procedure. If the client receives neither a DHCPACK or a DHCPNAK message after
// employing the retransmission algorithm, the client reverts to INIT state."
void test_a_request_that_is_never_answered_reverts_to_init(void)
{
    to_selecting(work_a);
    offer_in(work_a, 7200u);
    uint32_t now = 1000u;
    for (unsigned k = 0; k < IDEMIP_DHCP4_REQUEST_TRIES; k++)
    {
        build_ok(work_a);
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_REQUEST, IDEMIP_DHCP4_IO(work_a)->msg_type);
        now += 70000u; // past any sec 4.1 delay, the longest being 64 seconds plus a second of jitter
        tick_at(work_a, now, 0u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->offered_ip);
}

// --- sec 4.4, what each state discards ---------------------------------------

// sec 4.4.1: "If the 'xid' of an arriving DHCPOFFER message does not match the 'xid' of the most
// recent DHCPDISCOVER message, the DHCPOFFER message must be silently discarded."
void test_a_message_with_a_foreign_xid_is_discarded(void)
{
    to_selecting(work_a);
    msg_begin(XID_A ^ 0xFFFFFFFFu, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);
}

// RFC 2132 sec 2: the cookie "identifies the mode in which the succeeding data is to be interpreted",
// so options behind anything else are not DHCP options at all.
void test_a_message_with_the_wrong_cookie_is_discarded(void)
{
    to_selecting(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    put32(g_msg + IDEMIP_DHCP4_MSG_OFF_COOKIE, 0x63825364u);
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);
}

// RFC 2131 sec 4.2: with no 'client identifier' option "the server MUST use the contents of the
// 'chaddr' field to identify the client", so a reply carrying another client's is not this one's.
void test_a_message_with_a_foreign_chaddr_is_discarded(void)
{
    to_selecting(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_b);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);
}

// RFC 1542 sec 2.1: "The 'op' (opcode) field of the message must contain either the code for a
// BOOTREQUEST (1) or the code for a BOOTREPLY (2)", and a client's own op is not a reply.
void test_a_message_that_is_not_a_bootreply_is_discarded(void)
{
    to_selecting(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    g_msg[IDEMIP_DHCP4_MSG_OFF_OP] = IDEMIP_DHCP4_OP_BOOTREQUEST;
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
}

// sec 4.4.1: in SELECTING "Any arriving DHCPACK messages must be silently discarded."
void test_an_ack_in_selecting_is_discarded(void)
{
    to_selecting(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_ACK, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, 7200u);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->offered_ip);
}

// Figure 5: BOUND answers "DHCPOFFER, DHCPACK, DHCPNAK/Discard", so a lease already held is not
// disturbed by any of the three.
void test_bound_discards_an_offer_an_ack_and_a_nak(void)
{
    to_bound(work_a, 7200u);
    msg_begin(XID_A, 0x0A000001u, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);

    msg_begin(XID_A, 0x0A000001u, (uint8_t)IDEMIP_DHCP4_ACK, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, 60u);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);

    msg_begin(XID_A, 0u, (uint8_t)IDEMIP_DHCP4_NAK, g_mac_a);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_BOUND, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, IDEMIP_DHCP4_IO(work_a)->offered_ip);
    TEST_ASSERT_EQUAL_UINT32(7200u, IDEMIP_DHCP4_IO(work_a)->lease_s);
}

// Figure 5: REQUESTING answers "DHCPNAK/Restart", and sec 3.1 point 5 says "If the client receives a
// DHCPNAK message, the client restarts the configuration process", which is INIT with no address.
void test_a_nak_in_requesting_returns_the_machine_to_init(void)
{
    to_selecting(work_a);
    offer_in(work_a, 7200u);
    build_ok(work_a);
    msg_begin(XID_A, 0u, (uint8_t)IDEMIP_DHCP4_NAK, g_mac_a);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_NAK, IDEMIP_DHCP4_IO(work_a)->msg_type);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->offered_ip);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->server_id);
}

// Figure 5: RENEWING answers "DHCPNAK/Halt network", which gives the address up.
void test_a_nak_in_renewing_halts_the_network(void)
{
    to_bound(work_a, 7200u);
    tick_at(work_a, 3601000u, 0u);
    build_ok(work_a);
    msg_begin(XID_A, 0u, (uint8_t)IDEMIP_DHCP4_NAK, g_mac_a);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->offered_ip);
}

// sec 4.4: "A client can receive the following messages from a server: DHCPOFFER, DHCPACK, DHCPNAK."
// A client's own message type is not one of them.
void test_a_client_message_type_from_a_server_is_discarded(void)
{
    to_selecting(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_DISCOVER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);
}

// --- RFC 2132, the option walk ----------------------------------------------

// RFC 2132 sec 2: "The length octet is followed by 'length' octets of data", so an option whose data
// runs past the message is not one and the message is discarded.
void test_an_option_running_past_the_message_is_discarded(void)
{
    to_selecting(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    g_msg_len = g_msg_at - 1u; // the last option's data is one octet short
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);
}

// RFC 2132 sec 3.3: the subnet mask option's "length is 4 octets". A different length is not that
// option.
void test_an_option_with_the_wrong_length_is_discarded(void)
{
    to_selecting(work_a);
    uint8_t three[3] = {0xFFu, 0xFFu, 0xFFu};
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt(IDEMIP_DHCP4_OPT_SUBNET_MASK, 3u, three);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->subnet_mask);
}

// RFC 2132 sec 3.5: the router option's "length MUST always be a multiple of 4".
void test_a_router_option_that_is_not_a_multiple_of_four_is_discarded(void)
{
    to_selecting(work_a);
    uint8_t six[6] = {1u, 2u, 3u, 4u, 5u, 6u};
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt(IDEMIP_DHCP4_OPT_ROUTER, 6u, six);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
}

// RFC 2131 sec 4.1: "Options may appear only once, unless otherwise specified in the options
// document", so the first of a repeated option is the one that counts.
void test_a_repeated_option_takes_the_first(void)
{
    to_selecting(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SUBNET_MASK, IP_MASK);
    msg_opt32(IDEMIP_DHCP4_OPT_SUBNET_MASK, 0xFF000000u);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(IP_MASK, IDEMIP_DHCP4_IO(work_a)->subnet_mask);
}

// RFC 2132 sec 9.3: option 52 value 3 means "both fields are used to hold options", and RFC 2131
// sec 4.1 reads 'options' first, then 'file', then 'sname'. The mask goes in 'file' and the server
// identifier in 'sname', so a message is only accepted when both regions are walked.
void test_options_overloaded_into_file_and_sname_are_read(void)
{
    to_selecting(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    uint8_t both = 3u;
    msg_opt(IDEMIP_DHCP4_OPT_OVERLOAD, 1u, &both);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, 600u);
    msg_end();

    size_t at = IDEMIP_DHCP4_MSG_OFF_FILE;
    g_msg[at++] = IDEMIP_DHCP4_OPT_SUBNET_MASK;
    g_msg[at++] = 4u;
    put32(g_msg + at, IP_MASK);
    at += 4u;
    g_msg[at] = IDEMIP_DHCP4_OPT_END;

    at = IDEMIP_DHCP4_MSG_OFF_SNAME;
    g_msg[at++] = IDEMIP_DHCP4_OPT_SERVER_ID;
    g_msg[at++] = 4u;
    put32(g_msg + at, IP_SERVER);
    at += 4u;
    g_msg[at] = IDEMIP_DHCP4_OPT_END;

    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(IP_MASK, IDEMIP_DHCP4_IO(work_a)->subnet_mask);
    TEST_ASSERT_EQUAL_HEX32(IP_SERVER, IDEMIP_DHCP4_IO(work_a)->server_id);
    TEST_ASSERT_EQUAL_UINT32(600u, IDEMIP_DHCP4_IO(work_a)->lease_s);
}

// RFC 2132 sec 9.3: "Legal values for this option are:" 1, 2 and 3, so anything else is not that
// option.
void test_an_illegal_overload_value_is_discarded(void)
{
    to_selecting(work_a);
    uint8_t bad = 4u;
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt(IDEMIP_DHCP4_OPT_OVERLOAD, 1u, &bad);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
}

// RFC 2131 sec 4.1: the type is an option, so a message carrying none says nothing a client can act
// on.
void test_a_message_with_no_message_type_option_is_discarded(void)
{
    to_selecting(work_a);
    memset(g_msg, 0, sizeof g_msg);
    g_msg[IDEMIP_DHCP4_MSG_OFF_OP] = IDEMIP_DHCP4_OP_BOOTREPLY;
    g_msg[IDEMIP_DHCP4_MSG_OFF_HTYPE] = 1u;
    g_msg[IDEMIP_DHCP4_MSG_OFF_HLEN] = 6u;
    put32(g_msg + IDEMIP_DHCP4_MSG_OFF_XID, XID_A);
    memcpy(g_msg + IDEMIP_DHCP4_MSG_OFF_CHADDR, g_mac_a, 6);
    put32(g_msg + IDEMIP_DHCP4_MSG_OFF_COOKIE, IDEMIP_DHCP4_MAGIC_COOKIE);
    g_msg[IDEMIP_DHCP4_MSG_OFF_OPTIONS] = IDEMIP_DHCP4_OPT_END;
    g_msg_len = IDEMIP_DHCP4_MSG_BOOTP_MIN;
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_DHCP4_IO(work_a)->msg_type);
}

// RFC 2131 sec 2, Table 1 puts 240 octets ahead of the first option, so a shorter datagram is not a
// DHCP message.
void test_a_message_shorter_than_the_fixed_part_is_discarded(void)
{
    to_selecting(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    g_msg_len = IDEMIP_DHCP4_FIXED_LEN - 1u;
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
}

// --- sec 4.4.2, INIT-REBOOT --------------------------------------------------

// sec 4.4.2: "The client begins in INIT-REBOOT state and sends a DHCPREQUEST message. The client MUST
// insert its known network address as a 'requested IP address' option ... The client MUST NOT include
// a 'server identifier' in the DHCPREQUEST message. The client then broadcasts the DHCPREQUEST."
void test_a_known_address_reboots_with_a_broadcast_request(void)
{
    bind_ok(work_a, &g_cfg_a);
    IDEMIP_DHCP4_IO(work_a)->offered_ip = IP_OFFER;
    start_at(work_a, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT_REBOOT, IDEMIP_DHCP4_IO(work_a)->state);

    tick_at(work_a, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_REBOOTING, IDEMIP_DHCP4_IO(work_a)->state);

    build_ok(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_REQUEST, IDEMIP_DHCP4_IO(work_a)->msg_type);
    TEST_ASSERT_EQUAL_HEX32(IP_BROADCAST, IDEMIP_DHCP4_IO(work_a)->dst);
    TEST_ASSERT_EQUAL_HEX32(0u, get32(g_out + IDEMIP_DHCP4_MSG_OFF_CIADDR)); // Table 4, "zero"
    uint8_t n = 0;
    const uint8_t *v = opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_REQUESTED_IP, &n);
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, get32(v));
    TEST_ASSERT_NULL_MESSAGE(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_SERVER_ID, NULL),
                             "sec 4.4.2 forbids a server identifier out of INIT-REBOOT");
}

// sec 4.4.2: "Once a DHCPACK message with an 'xid' field matching that in the client's DHCPREQUEST
// message arrives from any server, the client is initialized and moves to BOUND state." An ACK from a
// server this machine never heard an offer from is one such.
void test_a_rebooting_ack_from_any_server_binds_the_lease(void)
{
    bind_ok(work_a, &g_cfg_a);
    IDEMIP_DHCP4_IO(work_a)->offered_ip = IP_OFFER;
    start_at(work_a, 0u, 0u);
    tick_at(work_a, 0u, 0u);
    build_ok(work_a);
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_ACK, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_LEASE_TIME, 1200u);
    msg_opt32(IDEMIP_DHCP4_OPT_SUBNET_MASK, IP_MASK);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_BOUND, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(1200u, IDEMIP_DHCP4_IO(work_a)->lease_s);
    TEST_ASSERT_EQUAL_UINT32(600u, IDEMIP_DHCP4_IO(work_a)->t1_s);  // sec 4.4.5, 0.5 of the lease
    TEST_ASSERT_EQUAL_UINT32(1050u, IDEMIP_DHCP4_IO(work_a)->t2_s); // sec 4.4.5, 0.875 of the lease
}

// --- sec 4.4.6 and sec 4.4.1, giving an address up ---------------------------

// sec 4.4.6 with Table 5: a DHCPRELEASE carries 'ciaddr' and the server identifier, no requested
// address, 'secs' 0 and no flags, and sec 4.4.4 says "The client unicasts DHCPRELEASE messages to the
// server."
void test_a_release_unicasts_to_the_server_and_ends_the_lease(void)
{
    to_bound(work_a, 7200u);
    Dhcp4.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    build_ok(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_RELEASE, IDEMIP_DHCP4_IO(work_a)->msg_type);
    TEST_ASSERT_EQUAL_HEX32(IP_SERVER, IDEMIP_DHCP4_IO(work_a)->dst);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, get32(g_out + IDEMIP_DHCP4_MSG_OFF_CIADDR));
    TEST_ASSERT_EQUAL_HEX16(0u, get16(g_out + IDEMIP_DHCP4_MSG_OFF_SECS));
    TEST_ASSERT_EQUAL_HEX16(0u, get16(g_out + IDEMIP_DHCP4_MSG_OFF_FLAGS));
    uint8_t n = 0;
    const uint8_t *v = opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_SERVER_ID, &n);
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT_EQUAL_HEX32(IP_SERVER, get32(v));
    TEST_ASSERT_NULL_MESSAGE(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_REQUESTED_IP, NULL),
                             "Table 5 forbids a requested address in a DHCPRELEASE");
    TEST_ASSERT_NULL_MESSAGE(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_LEASE_TIME, NULL),
                             "Table 5 forbids a lease time in a DHCPRELEASE");

    // The address is given up, and nothing is retransmitted.
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->offered_ip);
}

// sec 4.4.6 releases "its assigned network address", so a machine holding none has nothing to release.
void test_a_release_without_a_lease_is_refused(void)
{
    to_selecting(work_a);
    Dhcp4.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);
}

// sec 3.1 point 5 with Table 5: a DHCPDECLINE carries the requested address and the server
// identifier, 'ciaddr' zero and 'secs' 0, and sec 4.4.4 broadcasts it.
void test_a_decline_names_the_address_already_in_use(void)
{
    to_bound(work_a, 7200u);
    Dhcp4.decline(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    build_ok(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_DECLINE, IDEMIP_DHCP4_IO(work_a)->msg_type);
    TEST_ASSERT_EQUAL_HEX32(IP_BROADCAST, IDEMIP_DHCP4_IO(work_a)->dst);
    TEST_ASSERT_EQUAL_HEX32(0u, get32(g_out + IDEMIP_DHCP4_MSG_OFF_CIADDR));
    TEST_ASSERT_EQUAL_HEX16(0u, get16(g_out + IDEMIP_DHCP4_MSG_OFF_SECS));
    uint8_t n = 0;
    const uint8_t *v = opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_REQUESTED_IP, &n);
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, get32(v));
    v = opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_SERVER_ID, &n);
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT_EQUAL_HEX32(IP_SERVER, get32(v));
    TEST_ASSERT_NULL_MESSAGE(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_MAX_MSG_SIZE, NULL),
                             "sec 9.10 says the message size option should not appear in a DHCPDECLINE");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);
}

// sec 3.1 point 5: the client "SHOULD wait a minimum of ten seconds before restarting the
// configuration process to avoid excessive network traffic in case of looping". A restart before then
// is BUSY, since a later call makes progress.
void test_a_restart_after_a_decline_waits_ten_seconds(void)
{
    to_bound(work_a, 7200u);
    Dhcp4.decline(work_a);
    build_ok(work_a);
    // The decline went out on the clock the last tick supplied, which to_bound left at 1000 ms.
    start_at(work_a, 1000u + IDEMIP_DHCP4_DECLINE_WAIT_MS - 1u, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status,
                                  "the configuration process restarted inside the sec 3.1 ten seconds");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);

    start_at(work_a, 1000u + IDEMIP_DHCP4_DECLINE_WAIT_MS, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_a)->state);
}

// sec 3.1 point 5 puts the check after the DHCPACK, so a machine that holds no acked address has
// nothing to decline.
void test_a_decline_before_the_ack_is_refused(void)
{
    to_selecting(work_a);
    offer_in(work_a, 7200u);
    Dhcp4.decline(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_REQUESTING, IDEMIP_DHCP4_IO(work_a)->state);
}

// --- sec 4.4.3, DHCPINFORM ---------------------------------------------------

// sec 4.4.3: "The client places its own network address in the 'ciaddr' field. The client SHOULD NOT
// request lease time parameters", and Table 5 makes the requested address and the server identifier
// both MUST NOT for a DHCPINFORM.
void test_an_inform_carries_the_external_address_and_no_lease_options(void)
{
    bind_ok(work_a, &g_cfg_a);
    IDEMIP_DHCP4_IO(work_a)->offered_ip = IP_OFFER;
    IDEMIP_DHCP4_IO(work_a)->start_args.xid = XID_A;
    IDEMIP_DHCP4_IO(work_a)->start_args.now_ms = 0u;
    Dhcp4.inform(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);

    build_ok(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_INFORM, IDEMIP_DHCP4_IO(work_a)->msg_type);
    TEST_ASSERT_EQUAL_HEX32(IP_BROADCAST, IDEMIP_DHCP4_IO(work_a)->dst);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, get32(g_out + IDEMIP_DHCP4_MSG_OFF_CIADDR));
    TEST_ASSERT_EQUAL_HEX32(0u, get32(g_out + IDEMIP_DHCP4_MSG_OFF_YIADDR));
    TEST_ASSERT_NULL_MESSAGE(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_LEASE_TIME, NULL),
                             "sec 4.4.3 asks for no lease time in a DHCPINFORM");
    TEST_ASSERT_NULL_MESSAGE(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_REQUESTED_IP, NULL),
                             "Table 5 forbids a requested address in a DHCPINFORM");
    TEST_ASSERT_NULL_MESSAGE(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_SERVER_ID, NULL),
                             "Table 5 forbids a server identifier in a DHCPINFORM");
    TEST_ASSERT_NOT_NULL(opt_find(g_out, IDEMIP_DHCP4_IO(work_a)->len, IDEMIP_DHCP4_OPT_PARAM_LIST, NULL));
}

// sec 4.4.3: "Once a DHCPACK message with an 'xid' field matching that in the client's DHCPINFORM
// message arrives from any server, the client is initialized." No lease comes with it, so no address
// and no T1 or T2 are recorded.
void test_the_ack_answering_an_inform_sets_parameters_and_no_lease(void)
{
    bind_ok(work_a, &g_cfg_a);
    IDEMIP_DHCP4_IO(work_a)->offered_ip = IP_OFFER;
    IDEMIP_DHCP4_IO(work_a)->start_args.xid = XID_A;
    IDEMIP_DHCP4_IO(work_a)->start_args.now_ms = 0u;
    Dhcp4.inform(work_a);
    build_ok(work_a);

    msg_begin(XID_A, 0u, (uint8_t)IDEMIP_DHCP4_ACK, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SUBNET_MASK, IP_MASK);
    msg_opt32(IDEMIP_DHCP4_OPT_ROUTER, IP_ROUTER);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(IP_MASK, IDEMIP_DHCP4_IO(work_a)->subnet_mask);
    TEST_ASSERT_EQUAL_HEX32(IP_ROUTER, IDEMIP_DHCP4_IO(work_a)->router);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, IDEMIP_DHCP4_IO(work_a)->offered_ip);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_DHCP4_IO(work_a)->lease_s);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_DHCP4_IO(work_a)->t1_s);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_DHCP4_IO(work_a)->t2_s);
}

// sec 4.4.3: "If the client does not receive a DHCPACK within a reasonable period of time (60 seconds
// or 4 tries if using timeout suggested in section 4.1)", it gives up and nothing more is owed.
void test_an_inform_gives_up_after_four_tries(void)
{
    bind_ok(work_a, &g_cfg_a);
    IDEMIP_DHCP4_IO(work_a)->offered_ip = IP_OFFER;
    IDEMIP_DHCP4_IO(work_a)->start_args.xid = XID_A;
    IDEMIP_DHCP4_IO(work_a)->start_args.now_ms = 0u;
    Dhcp4.inform(work_a);
    uint32_t now = 0u;
    for (unsigned k = 0; k < IDEMIP_DHCP4_INFORM_TRIES; k++)
    {
        build_ok(work_a);
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_DHCP4_INFORM, IDEMIP_DHCP4_IO(work_a)->msg_type);
        now += 70000u;
        tick_at(work_a, now, 0u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    }
    IDEMIP_DHCP4_IO(work_a)->build_args.out = g_out;
    IDEMIP_DHCP4_IO(work_a)->build_args.cap = sizeof g_out;
    Dhcp4.build(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status,
                                  "a fifth DHCPINFORM was owed after the sec 4.4.3 four tries");
    now += 70000u;
    tick_at(work_a, now, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status);
}

// sec 4.4.3 informs about an address "obtained ... through some other means", so there has to be one.
void test_an_inform_without_an_address_is_refused(void)
{
    bind_ok(work_a, &g_cfg_a);
    IDEMIP_DHCP4_IO(work_a)->offered_ip = 0u;
    Dhcp4.inform(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
}

// --- sec 4.4.5, halting ------------------------------------------------------

// sec 4.4.5's "Halt network" leaves the machine in INIT holding no address, and the same call again
// does the same thing.
void test_stop_halts_the_machine_and_repeats(void)
{
    to_bound(work_a, 7200u);
    Dhcp4.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_DHCP4_IO(work_a)->offered_ip);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_DHCP4_IO(work_a)->lease_s);

    Dhcp4.stop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_INIT, IDEMIP_DHCP4_IO(work_a)->state);

    IDEMIP_DHCP4_IO(work_a)->build_args.out = g_out;
    IDEMIP_DHCP4_IO(work_a)->build_args.cap = sizeof g_out;
    Dhcp4.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status);
}

// --- build's own refusals ----------------------------------------------------

// A buffer that cannot hold RFC 1542 sec 2.1's 300-octet minimal BOOTP header can never hold a
// message, so retrying it can never succeed: that is ERR and not BUSY.
void test_build_refuses_a_buffer_shorter_than_the_bootp_minimum(void)
{
    to_selecting(work_a);
    IDEMIP_DHCP4_IO(work_a)->build_args.out = g_out;
    IDEMIP_DHCP4_IO(work_a)->build_args.cap = IDEMIP_DHCP4_MSG_BOOTP_MIN - 1u;
    Dhcp4.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_DHCP4_IO(work_a)->len);

    IDEMIP_DHCP4_IO(work_a)->build_args.out = NULL;
    IDEMIP_DHCP4_IO(work_a)->build_args.cap = sizeof g_out;
    Dhcp4.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_a)->status);
}

// Nothing owed is BUSY, which is a later tick and not a fault. This is the case a bool return could
// not express: OK would claim a message that is not there.
void test_build_with_nothing_owed_is_busy(void)
{
    to_bound(work_a, 7200u);
    IDEMIP_DHCP4_IO(work_a)->build_args.out = g_out;
    IDEMIP_DHCP4_IO(work_a)->build_args.cap = sizeof g_out;
    Dhcp4.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DHCP4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_DHCP4_IO(work_a)->len);
}

// --- two machines ------------------------------------------------------------

// The borrow IS the interface, so two machines run two exchanges: sec 3.6, "A client with multiple
// network interfaces must use DHCP through each interface independently."
void test_two_borrows_run_independent_exchanges(void)
{
    to_bound(work_a, 7200u);

    bind_ok(work_b, &g_cfg_b);
    start_at(work_b, 0u, 0u);
    tick_at(work_b, 1000u, 0u);
    build_ok(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_b)->state);

    // b's exchange left a's lease and state alone.
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_BOUND, IDEMIP_DHCP4_IO(work_a)->state);
    TEST_ASSERT_EQUAL_HEX32(IP_OFFER, IDEMIP_DHCP4_IO(work_a)->offered_ip);
    TEST_ASSERT_EQUAL_UINT32(7200u, IDEMIP_DHCP4_IO(work_a)->lease_s);

    // And a message for a is not b's: b matches on its own 'xid' and hardware address.
    msg_begin(XID_A, IP_OFFER, (uint8_t)IDEMIP_DHCP4_OFFER, g_mac_a);
    msg_opt32(IDEMIP_DHCP4_OPT_SERVER_ID, IP_SERVER);
    msg_end();
    feed(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DHCP4_IO(work_b)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DHCP4_SELECTING, IDEMIP_DHCP4_IO(work_b)->state);
}
