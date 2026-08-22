// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 8201 Path MTU Discovery for IPv6, checked the way test_phy checks a golden module:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. BUSY and ERR are separated by whether retrying can ever succeed
//
// RFC 8201 prints no example message and no hex vector: its Packet Too Big is RFC 4443 sec 3.2's
// figure, and every rule here is a sentence of sec 4, sec 5.2 or sec 5.3 rather than a table. Those
// sentences are what is asserted.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/pmtu/pmtu6.h"

#include <string.h>
#include <unity.h>
#include "src/common_defines.h"
#include "src/ip/ipv6_defines.h"

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_PMTU6_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_PMTU6_BORROW + 16];

// A Packet Too Big: RFC 4443 sec 3.2's Type 2, its 32-bit MTU, then the invoking packet.
static uint8_t g_msg[192];

// 2001:db8::1 and 2001:db8::2, the RFC 3849 documentation prefix.
static const uint8_t dst_one[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t dst_two[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};
static const uint8_t dst_last[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF};

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFFu);
}

// Type, Code, checksum, MTU, then an invoking IPv6 header addressed to dst with next header nh.
// Returns the octets built through that header; an extension header is appended by the caller.
static size_t build(uint8_t type, uint8_t code, uint32_t mtu, uint8_t nh, const uint8_t *dst)
{
    memset(g_msg, 0, sizeof g_msg);
    g_msg[0] = type;
    g_msg[1] = code;
    put32(g_msg + 4, mtu);
    uint8_t *p = g_msg + 8;
    put32(p, 0x60000000u); // version 6, traffic class 0, flow label 0
    p[6] = nh;
    p[7] = 64u; // hop limit
    memcpy(p + 24, dst, 16);
    return (size_t)8u + 40u;
}

static size_t packet_too_big(uint32_t mtu, const uint8_t *dst)
{
    return build(2u, 0u, mtu, 59u, dst); // next header 59, RFC 8200 sec 4.7 "No Next Header"
}

// A Routing header at `at`, carrying one address, with the given Segments Left. RFC 8200 sec 4.4:
// Next Header, Hdr Ext Len in 8-octet units past the first eight, Routing Type, Segments Left.
static size_t routing_header(size_t at, uint8_t segments_left, const uint8_t *address)
{
    g_msg[at + 0] = 59u; // no next header
    g_msg[at + 1] = 2u;  // 24 octets in all
    g_msg[at + 2] = 4u;  // Routing Type, unread here
    g_msg[at + 3] = segments_left;
    memcpy(g_msg + at + 8, address, 16);
    return at + 24u;
}

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_PMTU6_BORROW, CANARY, cap - IDEMIP_PMTU6_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_PMTU6_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_PMTU6_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_msg, 0, sizeof g_msg);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

static void ready(uint8_t *w)
{
    Pmtu6.clear(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(w)->status);
}

// One message through the unit, on a path whose cache row holds `held` and whose first hop is
// `link`. sec 5.2 takes the PMTU of a path with no row to be "the (known) MTU of the first-hop
// link", so `link` is the ceiling whenever `held` is zero.
static void deliver_on_link(uint8_t *w, uint32_t mtu, const uint8_t *dst, uint16_t held, uint16_t link, uint32_t now_ms)
{
    IDEMIP_PMTU6_IO(w)->too_big_args.msg = g_msg;
    IDEMIP_PMTU6_IO(w)->too_big_args.len = packet_too_big(mtu, dst);
    IDEMIP_PMTU6_IO(w)->too_big_args.held = held;
    IDEMIP_PMTU6_IO(w)->too_big_args.link_mtu = link;
    IDEMIP_PMTU6_IO(w)->now_ms = now_ms;
    Pmtu6.too_big(w);
}

// The same with no first hop named, which is what a caller that does not know it passes.
static void deliver(uint8_t *w, uint32_t mtu, const uint8_t *dst, uint16_t held, uint32_t now_ms)
{
    deliver_on_link(w, mtu, dst, held, 0u, now_ms);
}

// --- the borrow --------------------------------------------------------------

void test_every_entry_survives_a_null_borrow(void)
{
    Pmtu6.clear(NULL);
    Pmtu6.too_big(NULL);
    Pmtu6.tick(NULL);
    Pmtu6.forget(NULL);
    TEST_PASS();
}

void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = packet_too_big(1400u, dst_one);
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);
    IDEMIP_PMTU6_IO(work_a)->probe_args.link_mtu = 1500u;
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);
    IDEMIP_PMTU6_IO(work_a)->path_args.dst = dst_one;
    Pmtu6.forget(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);
}

// sec 5.2: "For nodes with multiple interfaces, Path MTU information should be maintained for each
// IPv6 link", so the borrow is the interface and two of them share no byte: a path stamped on one
// is unknown to the other.
void test_two_borrows_share_no_byte(void)
{
    ready(work_a);
    ready(work_b);
    deliver(work_a, 1400u, dst_one, 1500u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_PMTU6_IO(work_a)->decreased);

    IDEMIP_PMTU6_IO(work_b)->path_args.dst = dst_one;
    Pmtu6.forget(work_b);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_b)->status, "b holds a's stamp");

    IDEMIP_PMTU6_IO(work_a)->path_args.dst = dst_one;
    Pmtu6.forget(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
}

void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    ready(work_a);
    ready(work_b);
    deliver(work_a, 1400u, dst_one, 1500u, 1000u);
    uint16_t first = IDEMIP_PMTU6_IO(work_a)->mtu;
    deliver(work_b, 1300u, dst_one, 1500u, 1000u);
    deliver(work_a, 1400u, dst_one, 1500u, 1000u);
    TEST_ASSERT_EQUAL_UINT16(1400u, first);
    TEST_ASSERT_EQUAL_UINT16(first, IDEMIP_PMTU6_IO(work_a)->mtu);
}

// --- the Packet Too Big ------------------------------------------------------

// RFC 4443 sec 3.2: "MTU  The Maximum Transmission Unit of the next-hop link", and RFC 8201 sec 5.2:
// "If the tentative PMTU is less than the existing PMTU estimate, the tentative PMTU replaces the
// existing PMTU as the PMTU value for the path."
void test_the_mtu_field_is_the_estimate(void)
{
    ready(work_a);
    deliver(work_a, 1400u, dst_one, 1500u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(1400u, IDEMIP_PMTU6_IO(work_a)->reported_mtu);
    TEST_ASSERT_EQUAL_UINT16(1400u, IDEMIP_PMTU6_IO(work_a)->mtu);
    TEST_ASSERT_TRUE(IDEMIP_PMTU6_IO(work_a)->decreased);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dst_one, IDEMIP_PMTU6_IO(work_a)->dst, 16);
}

// RFC 4443 sec 3.2: "Code  Set to 0 (zero) by the originator and ignored by the receiver."
void test_the_code_is_ignored(void)
{
    ready(work_a);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = build(2u, 0x7Fu, 1400u, 59u, dst_one);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.held = 1500u;
    IDEMIP_PMTU6_IO(work_a)->now_ms = 1000u;
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1400u, IDEMIP_PMTU6_IO(work_a)->mtu);
}

// Only RFC 4443 sec 3.2's Type 2 moves a path MTU.
void test_another_type_is_refused(void)
{
    ready(work_a);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = build(1u, 0u, 1400u, 59u, dst_one); // Destination Unreachable
    IDEMIP_PMTU6_IO(work_a)->too_big_args.held = 1500u;
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);
}

// The invoking IPv6 header names the path, so a message short of it, or one whose invoking packet is
// not an IPv6 header, cannot be applied.
void test_a_message_without_the_invoking_header_is_refused(void)
{
    ready(work_a);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.held = 1500u;

    (void)packet_too_big(1400u, dst_one);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = (size_t)IDEMIP_PMTU6_MSG_MIN - 1u;
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);

    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = packet_too_big(1400u, dst_one);
    g_msg[8] = 0x40u; // version 4 in the invoking header
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);
}

// sec 4: "If a node receives a Packet Too Big message reporting a next-hop MTU that is less than the
// IPv6 minimum link MTU, it must discard it. A node must not reduce its estimate of the Path MTU
// below the IPv6 minimum link MTU on receipt of a Packet Too Big message." Discarded is ERR: the
// same message can never be applied.
void test_an_mtu_below_the_minimum_link_mtu_is_discarded(void)
{
    ready(work_a);
    deliver(work_a, (uint32_t)IDEMIP_IPV6_MIN_MTU - 1u, dst_one, 1500u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_PMTU6_IO(work_a)->mtu);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1279u, IDEMIP_PMTU6_IO(work_a)->reported_mtu, "the field is reported as it came");

    deliver(work_a, 0u, dst_one, 1500u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);

    // 1280 itself is RFC 8200 sec 5's minimum link MTU and is accepted.
    deliver(work_a, (uint32_t)IDEMIP_IPV6_MIN_MTU, dst_one, 1500u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1280u, IDEMIP_PMTU6_IO(work_a)->mtu);
}

// sec 4: "A node must not increase its estimate of the Path MTU in response to the contents of a
// Packet Too Big message. A message purporting to announce an increase in the Path MTU might be a
// stale packet... a false packet injected as part of a denial-of-service (DoS) attack".
void test_a_message_never_raises_the_estimate(void)
{
    ready(work_a);
    deliver(work_a, 9000u, dst_one, 1400u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(9000u, IDEMIP_PMTU6_IO(work_a)->reported_mtu);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(1400u, IDEMIP_PMTU6_IO(work_a)->mtu, "the held estimate must stand");
    TEST_ASSERT_FALSE(IDEMIP_PMTU6_IO(work_a)->decreased);

    // Nothing decreased, so sec 5.3's clock was not restarted and no stamp exists to forget.
    IDEMIP_PMTU6_IO(work_a)->path_args.dst = dst_one;
    Pmtu6.forget(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);

    // Equal is not a decrease either.
    deliver(work_a, 1400u, dst_one, 1400u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_PMTU6_IO(work_a)->decreased);
}

// sec 5.2 puts the estimate "with the corresponding entry in the destination cache", whose row holds
// it in sixteen bits, so a link wider than that is carried at the widest the row can hold.
void test_an_mtu_wider_than_the_row_is_carried_at_its_ceiling(void)
{
    ready(work_a);
    deliver(work_a, 0x1FFFFu, dst_one, 0u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(0x1FFFFu, IDEMIP_PMTU6_IO(work_a)->reported_mtu);
    TEST_ASSERT_EQUAL_UINT16(0xFFFFu, IDEMIP_PMTU6_IO(work_a)->mtu);
}

// sec 4: "A node must not increase its estimate of the Path MTU in response to the contents of a
// Packet Too Big message." sec 5.2 says a path with no Destination Cache row already has an
// estimate, "the (known) MTU of the first-hop link", so the first message for a path cannot raise it.
void test_an_empty_cache_row_is_still_bounded_by_the_first_hop(void)
{
    ready(work_a);
    deliver_on_link(work_a, 9000u, dst_one, 0u, 1500u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(1500u, IDEMIP_PMTU6_IO(work_a)->mtu, "the estimate rose past the first hop");
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_PMTU6_IO(work_a)->decreased, "a raise was reported as a decrease");

    // A message at the first hop's own MTU is not a decrease either.
    ready(work_a);
    deliver_on_link(work_a, 1500u, dst_one, 0u, 1500u, 1000u);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_PMTU6_IO(work_a)->mtu);
    TEST_ASSERT_FALSE(IDEMIP_PMTU6_IO(work_a)->decreased);

    // One below it is, and it is the reported value that lands.
    ready(work_a);
    deliver_on_link(work_a, 1400u, dst_one, 0u, 1500u, 1000u);
    TEST_ASSERT_EQUAL_UINT16(1400u, IDEMIP_PMTU6_IO(work_a)->mtu);
    TEST_ASSERT_TRUE(IDEMIP_PMTU6_IO(work_a)->decreased);
}

// --- the path ----------------------------------------------------------------

// sec 5.2's Note: "If Segments Left is greater than zero, the destination address is the last
// address (Address[n]) in the Routing header."
void test_a_routing_header_with_segments_left_names_the_path(void)
{
    ready(work_a);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = g_msg;
    size_t len = build(2u, 0u, 1400u, 43u, dst_one);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = routing_header(len, 1u, dst_last);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.held = 1500u;
    IDEMIP_PMTU6_IO(work_a)->now_ms = 1000u;
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dst_last, IDEMIP_PMTU6_IO(work_a)->dst, 16);
}

// sec 5.2's Note: "If Segments Left is equal to zero, the destination address is in the Destination
// Address field in the IPv6 header."
void test_a_routing_header_without_segments_left_leaves_the_path_alone(void)
{
    ready(work_a);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = g_msg;
    size_t len = build(2u, 0u, 1400u, 43u, dst_one);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = routing_header(len, 0u, dst_last);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.held = 1500u;
    IDEMIP_PMTU6_IO(work_a)->now_ms = 1000u;
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dst_one, IDEMIP_PMTU6_IO(work_a)->dst, 16);
}

// RFC 8200 sec 4.5 fixes the Fragment header at eight octets rather than sizing it from a Hdr Ext
// Len, so the walk steps over one to reach the Routing header behind it.
void test_the_walk_steps_over_a_fragment_header(void)
{
    ready(work_a);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = g_msg;
    size_t at = build(2u, 0u, 1400u, 44u, dst_one);
    g_msg[at + 0] = 43u; // the Routing header follows
    g_msg[at + 1] = 0u;  // reserved
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = routing_header(at + 8u, 2u, dst_last);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.held = 1500u;
    IDEMIP_PMTU6_IO(work_a)->now_ms = 1000u;
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dst_last, IDEMIP_PMTU6_IO(work_a)->dst, 16);
}

// RFC 4443 sec 3.2 carries only "as much of invoking packet as possible without the ICMPv6 packet
// exceeding the minimum IPv6 MTU", so a Routing header the message cut short is not read and the
// Destination Address field stands.
void test_a_truncated_routing_header_leaves_the_path_alone(void)
{
    ready(work_a);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = g_msg;
    size_t at = build(2u, 0u, 1400u, 43u, dst_one);
    size_t end = routing_header(at, 1u, dst_last);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = end - 8u; // the last address is not there
    IDEMIP_PMTU6_IO(work_a)->too_big_args.held = 1500u;
    IDEMIP_PMTU6_IO(work_a)->now_ms = 1000u;
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dst_one, IDEMIP_PMTU6_IO(work_a)->dst, 16);
}

// --- aging -------------------------------------------------------------------

// sec 5.3: "When a PMTU value has not been decreased for a while (on the order of 10 minutes), it
// should probe to find if a larger PMTU is supported", and sec 4 floors the wait at five minutes.
// One millisecond short is BUSY; the interval itself is due.
void test_the_probe_waits_out_the_interval(void)
{
    ready(work_a);
    deliver(work_a, 1400u, dst_one, 1500u, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);

    IDEMIP_PMTU6_IO(work_a)->probe_args.link_mtu = 1500u;
    IDEMIP_PMTU6_IO(work_a)->now_ms = 1000u + (uint32_t)IDEMIP_PMTU6_PROBE_MS - 1u;
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_PMTU6_IO(work_a)->probe);

    IDEMIP_PMTU6_IO(work_a)->now_ms = 1000u + (uint32_t)IDEMIP_PMTU6_PROBE_MS;
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_PMTU6_IO(work_a)->probe);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dst_one, IDEMIP_PMTU6_IO(work_a)->dst, 16);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(1500u, IDEMIP_PMTU6_IO(work_a)->mtu, "sec 5.2 probes at the first-hop link MTU");

    // Asked for once: the clock is gone with the report.
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_PMTU6_IO(work_a)->status);
}

// A later Packet Too Big restarts the clock, sec 5.3 measuring from the last decrease.
void test_a_later_decrease_restarts_the_clock(void)
{
    ready(work_a);
    deliver(work_a, 1400u, dst_one, 1500u, 1000u);
    deliver(work_a, 1300u, dst_one, 1400u, 500000u);
    TEST_ASSERT_TRUE(IDEMIP_PMTU6_IO(work_a)->decreased);

    IDEMIP_PMTU6_IO(work_a)->probe_args.link_mtu = 1500u;
    IDEMIP_PMTU6_IO(work_a)->now_ms = 1000u + (uint32_t)IDEMIP_PMTU6_PROBE_MS;
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_PMTU6_IO(work_a)->status, "the second decrease reset the clock");

    IDEMIP_PMTU6_IO(work_a)->now_ms = 500000u + (uint32_t)IDEMIP_PMTU6_PROBE_MS;
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
}

// RFC 8200 sec 5: "IPv6 requires that every link in the Internet have an MTU of 1280 octets or
// greater", so a link under it is not one a probe can be sized to, now or later: ERR, not BUSY.
void test_a_link_mtu_below_the_minimum_is_refused(void)
{
    ready(work_a);
    deliver(work_a, 1300u, dst_one, 1500u, 1000u);
    IDEMIP_PMTU6_IO(work_a)->probe_args.link_mtu = (uint16_t)(IDEMIP_IPV6_MIN_MTU - 1u);
    IDEMIP_PMTU6_IO(work_a)->now_ms = 1000u + (uint32_t)IDEMIP_PMTU6_PROBE_MS;
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);
}

// Nothing stamped and nothing due are both BUSY: a Packet Too Big or a later tick makes one.
void test_an_empty_table_is_busy(void)
{
    ready(work_a);
    IDEMIP_PMTU6_IO(work_a)->probe_args.link_mtu = 1500u;
    IDEMIP_PMTU6_IO(work_a)->now_ms = (uint32_t)IDEMIP_PMTU6_PROBE_MS * 4u;
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_PMTU6_NONE, IDEMIP_PMTU6_IO(work_a)->index);
}

// RFC 4861 sec 5.1's Destination Cache entry going takes the clock aging its estimate with it. A
// path that holds no stamp is ERR: this table cannot grow that row on its own.
void test_forget_drops_one_stamp(void)
{
    ready(work_a);
    deliver(work_a, 1400u, dst_one, 1500u, 1000u);
    deliver(work_a, 1400u, dst_two, 1500u, 1000u);

    IDEMIP_PMTU6_IO(work_a)->path_args.dst = dst_one;
    Pmtu6.forget(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    Pmtu6.forget(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status);

    // The other path kept its clock.
    IDEMIP_PMTU6_IO(work_a)->probe_args.link_mtu = 1500u;
    IDEMIP_PMTU6_IO(work_a)->now_ms = 1000u + (uint32_t)IDEMIP_PMTU6_PROBE_MS;
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dst_two, IDEMIP_PMTU6_IO(work_a)->dst, 16);
}

// A second message on a path already stamped moves that path's clock rather than taking another row.
void test_a_second_decrease_reuses_the_same_stamp(void)
{
    ready(work_a);
    deliver(work_a, 1400u, dst_one, 1500u, 1000u);
    uint8_t first = IDEMIP_PMTU6_IO(work_a)->index;
    deliver(work_a, 1300u, dst_one, 1400u, 2000u);
    TEST_ASSERT_EQUAL_UINT8(first, IDEMIP_PMTU6_IO(work_a)->index);

    IDEMIP_PMTU6_IO(work_a)->path_args.dst = dst_one;
    Pmtu6.forget(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    Pmtu6.forget(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status, "a second row was taken");
}

// One stamp per row the Destination Cache can hold, so a path past that count takes the row whose
// clock has run longest: that one is nearest sec 5.3's interval, so its probe is already overdue.
void test_a_full_table_takes_the_longest_running_clock(void)
{
    ready(work_a);
    uint8_t dst[16];
    memcpy(dst, dst_one, sizeof dst);
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_PMTU6_PATHS; i++)
    {
        dst[15] = (uint8_t)(0x10u + i);
        deliver(work_a, 1400u, dst, 1500u, (uint32_t)(1000u + (uint32_t)i * 1000u));
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT8(i, IDEMIP_PMTU6_IO(work_a)->index);
    }

    // One more path than the table holds: the row stamped first goes.
    deliver(work_a, 1400u, dst_last, 1500u, 100000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_PMTU6_IO(work_a)->index);

    dst[15] = 0x10u;
    IDEMIP_PMTU6_IO(work_a)->path_args.dst = dst;
    Pmtu6.forget(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status, "the oldest clock was kept");

    dst[15] = 0x11u;
    IDEMIP_PMTU6_IO(work_a)->path_args.dst = dst;
    Pmtu6.forget(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status, "a younger clock was dropped");
}

// The clock is a wrapping millisecond count, so an interval that straddles the wrap is still one
// interval.
void test_the_interval_survives_a_clock_wrap(void)
{
    ready(work_a);
    deliver(work_a, 1400u, dst_one, 1500u, 0xFFFFFFFFu - 1000u);
    IDEMIP_PMTU6_IO(work_a)->probe_args.link_mtu = 1500u;
    IDEMIP_PMTU6_IO(work_a)->now_ms = (uint32_t)(0xFFFFFFFFu - 1000u + (uint32_t)IDEMIP_PMTU6_PROBE_MS - 1u);
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_PMTU6_IO(work_a)->status);

    IDEMIP_PMTU6_IO(work_a)->now_ms = (uint32_t)(0xFFFFFFFFu - 1000u + (uint32_t)IDEMIP_PMTU6_PROBE_MS);
    Pmtu6.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
}

// The same call on the same bytes reports the same thing, however often it runs.
void test_the_same_message_repeats(void)
{
    ready(work_a);
    deliver(work_a, 1350u, dst_two, 1500u, 4000u);
    uint16_t first = IDEMIP_PMTU6_IO(work_a)->mtu;
    uint8_t index = IDEMIP_PMTU6_IO(work_a)->index;
    deliver(work_a, 1350u, dst_two, 1500u, 4000u);
    TEST_ASSERT_EQUAL_UINT16(first, IDEMIP_PMTU6_IO(work_a)->mtu);
    TEST_ASSERT_EQUAL_UINT8(index, IDEMIP_PMTU6_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(1350u, first);
}

// A message and a path are each read out of the operand block, so a call naming neither has nothing
// to read: RFC 8201 sec 4 takes the estimate from "the Packet Too Big message" and sec 5.2 keys the
// entry on the destination it names.
void test_the_entries_refuse_a_call_that_names_nothing(void)
{
    ready(work_a);

    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = NULL;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = 64u;
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status, "a call with no message was taken");

    IDEMIP_PMTU6_IO(work_a)->path_args.dst = NULL;
    Pmtu6.forget(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PMTU6_IO(work_a)->status,
                                  "a lookup for no destination was answered");
}

// RFC 8200 sec 4 gives every extension header at least eight octets, and sec 4.4's Routing header
// carries its addresses behind that. A quoted packet with fewer octets left than a header needs, or
// a Routing header too short to hold an address, names no destination past the one in the fixed
// header - so the estimate is keyed on that one.
void test_a_quoted_packet_too_short_for_the_header_it_claims_keys_on_the_fixed_destination(void)
{
    ready(work_a);

    // A Routing header claimed by the fixed header, with four octets behind it: fewer than one is.
    size_t len = build(2u, 0u, 1280u, (uint8_t)IDEMIP_IP6_NH_ROUTING, dst_one);
    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = len + 4u;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.held = 0u;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.link_mtu = 1500u;
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(dst_one, IDEMIP_PMTU6_IO(work_a)->dst, IDEMIP_IP6_ADDR_LEN,
                                         "a header the packet could not hold moved the destination");

    // A Routing header that is there and too short to carry an address: Segments Left is nonzero,
    // and there is no address behind it to be the final destination.
    len = build(2u, 0u, 1280u, (uint8_t)IDEMIP_IP6_NH_ROUTING, dst_one);
    g_msg[len + 0] = 59u; // no next header
    g_msg[len + 1] = 0u;  // Hdr Ext Len zero: eight octets in all, with no room for an address
    g_msg[len + 2] = 4u;  // Routing Type, unread here
    g_msg[len + 3] = 1u;  // Segments Left
    IDEMIP_PMTU6_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.len = len + 8u;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.held = 0u;
    IDEMIP_PMTU6_IO(work_a)->too_big_args.link_mtu = 1500u;
    Pmtu6.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(dst_one, IDEMIP_PMTU6_IO(work_a)->dst, IDEMIP_IP6_ADDR_LEN,
                                         "a Routing header with no address in it was read for one");
}
