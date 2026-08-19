// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ip4_addr against RFC 791 sec 3.2, RFC 1122 sec 3.2.1.3, RFC 1112 sec 4 and sec 6.4, RFC 919
// sec 7 and RFC 3927 sec 2.1.
//
// Same six checks every unit's suite carries:
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. the vectors are the RFCs' own printed examples where they print any
//   6. BUSY and ERR are separated by whether retrying can ever succeed
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ip/ip4_addr.h"

#include <string.h>
#include <unity.h>

#define IP4(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_IP4_ADDR_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_IP4_ADDR_BORROW + 16];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP4_ADDR_BORROW, CANARY, cap - IDEMIP_IP4_ADDR_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP4_ADDR_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP4_ADDR_BORROW");
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

static void classify(uint8_t *w, uint32_t addr)
{
    IDEMIP_IP4_ADDR_IO(w)->classify_args.addr = addr;
    Ip4Addr.classify(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ADDR_IO(w)->status);
}

static void match(uint8_t *w, uint32_t addr, uint32_t net, uint32_t mask)
{
    IDEMIP_IP4_ADDR_IO(w)->match_args.addr = addr;
    IDEMIP_IP4_ADDR_IO(w)->match_args.net = net;
    IDEMIP_IP4_ADDR_IO(w)->match_args.mask = mask;
    Ip4Addr.match(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ADDR_IO(w)->status);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Ip4Addr.clear(NULL);
    Ip4Addr.classify(NULL);
    Ip4Addr.match(NULL);
    Ip4Addr.mcast_mac(NULL);
    TEST_PASS();
}

// The borrow IS the instance, and the operand block is in it, so two callers share no byte at all.
// This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    Ip4Addr.clear(work_a);
    Ip4Addr.clear(work_b);

    IDEMIP_IP4_ADDR_IO(work_a)->classify_args.addr = IP4(10, 0, 0, 1);
    IDEMIP_IP4_ADDR_IO(work_b)->classify_args.addr = IP4(224, 0, 0, 1);
    TEST_ASSERT_EQUAL_HEX32(IP4(10, 0, 0, 1), IDEMIP_IP4_ADDR_IO(work_a)->classify_args.addr);
    TEST_ASSERT_EQUAL_HEX32(IP4(224, 0, 0, 1), IDEMIP_IP4_ADDR_IO(work_b)->classify_args.addr);

    Ip4Addr.classify(work_a);
    Ip4Addr.classify(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_UNICAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_MULTICAST, IDEMIP_IP4_ADDR_IO(work_b)->type);
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports. This is the determinism the design is named for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    Ip4Addr.clear(work_a);
    Ip4Addr.clear(work_b);

    IDEMIP_IP4_ADDR_IO(work_a)->mcast_args.group = IP4(224, 0, 0, 1);
    IDEMIP_IP4_ADDR_IO(work_b)->mcast_args.group = IP4(239, 255, 255, 250);

    Ip4Addr.mcast_mac(work_a);
    uint8_t first[IDEMIP_MAC_LEN];
    memcpy(first, IDEMIP_IP4_ADDR_IO(work_a)->mac, IDEMIP_MAC_LEN);
    Ip4Addr.mcast_mac(work_b);
    Ip4Addr.mcast_mac(work_a);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_IP4_ADDR_IO(work_a)->mac, IDEMIP_MAC_LEN);
}

// Zeroed, never cleared: every entry must refuse rather than answer out of whatever was in the
// bytes. ERR and not BUSY, because no later tick clears the borrow for the caller.
void test_uncleared_borrow_refuses_work(void)
{
    Ip4Addr.classify(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ADDR_IO(work_a)->status);
    Ip4Addr.match(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ADDR_IO(work_a)->status);
    Ip4Addr.mcast_mac(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_ADDR_IO(work_a)->status);
}

void test_clear_admits_the_borrow(void)
{
    Ip4Addr.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ADDR_IO(work_a)->status);
    classify(work_a, IP4(192, 0, 2, 1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_UNICAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
}

// --- RFC 791 sec 3.2 "Address Formats" ---------------------------------------
// The table prints "0" for class a, "10" for b, "110" for c and "111 escape to extended addressing
// mode". RFC 1122 sec 3.2.1.3 splits that escape into D and E.

void test_rfc791_class_a_is_the_leading_zero_bit(void)
{
    Ip4Addr.clear(work_a);
    classify(work_a, IP4(0, 0, 0, 1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_A, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
    classify(work_a, IP4(10, 0, 0, 1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_A, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
    classify(work_a, IP4(127, 255, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_A, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
}

void test_rfc791_class_b_is_the_leading_10_bits(void)
{
    Ip4Addr.clear(work_a);
    classify(work_a, IP4(128, 0, 0, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_B, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
    classify(work_a, IP4(191, 255, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_B, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
}

void test_rfc791_class_c_is_the_leading_110_bits(void)
{
    Ip4Addr.clear(work_a);
    classify(work_a, IP4(192, 0, 0, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_C, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
    classify(work_a, IP4(223, 255, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_C, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
}

// RFC 1122 sec 3.2.1.3: "There are now five classes of IP addresses: Class A through Class E."
void test_rfc1122_splits_the_791_escape_into_class_d_and_e(void)
{
    Ip4Addr.clear(work_a);
    classify(work_a, IP4(224, 0, 0, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_D, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
    classify(work_a, IP4(239, 255, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_D, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
    classify(work_a, IP4(240, 0, 0, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_E, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
    classify(work_a, IP4(255, 255, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_E, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
}

// RFC 1112 sec 4: "host group addresses range from 224.0.0.0 to 239.255.255.255", and 224.0.0.1 "is
// assigned to the permanent group of all IP hosts".
void test_rfc1112_class_d_spans_224_through_239(void)
{
    Ip4Addr.clear(work_a);
    classify(work_a, IP4(223, 255, 255, 255));
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_IP4_TYPE_MULTICAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(224, 0, 0, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_MULTICAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(224, 0, 0, 1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_MULTICAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(239, 255, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_MULTICAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(240, 0, 0, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_RESERVED, IDEMIP_IP4_ADDR_IO(work_a)->type);
}

// --- RFC 1122 sec 3.2.1.3, the special cases ---------------------------------

// Case (c) "{ -1, -1 } Limited broadcast" carries class E's high-order bits and must not be reported
// as reserved space.
void test_limited_broadcast_is_its_own_type_inside_class_e(void)
{
    Ip4Addr.clear(work_a);
    classify(work_a, IP4(255, 255, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_BROADCAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_E, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
}

// Case (a) "{ 0, 0 } This host on this network" and case (b) "{ 0, <Host-number> }".
void test_case_a_and_case_b_are_separate(void)
{
    Ip4Addr.clear(work_a);
    classify(work_a, IP4(0, 0, 0, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_UNSPECIFIED, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(0, 0, 0, 7));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_THIS_NETWORK, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(0, 255, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_THIS_NETWORK, IDEMIP_IP4_ADDR_IO(work_a)->type);
}

// Case (g) "{ 127, <any> } Internal host loopback address", which sits inside class A.
void test_case_g_loopback_is_127_slash_8(void)
{
    Ip4Addr.clear(work_a);
    classify(work_a, IP4(126, 255, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_UNICAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(127, 0, 0, 1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_LOOPBACK, IDEMIP_IP4_ADDR_IO(work_a)->type);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_CLASS_A, IDEMIP_IP4_ADDR_IO(work_a)->addr_class);
    classify(work_a, IP4(127, 255, 255, 254));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_LOOPBACK, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(128, 0, 0, 1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_UNICAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
}

// --- RFC 3927 sec 2.1 --------------------------------------------------------
// "The IPv4 prefix 169.254/16 is registered with the IANA for this purpose", the selection range
// being "169.254.1.0 to 169.254.254.255 inclusive". The whole /16 is link-local; only the draw is
// narrowed.

void test_rfc3927_link_local_is_the_whole_169_254_slash_16(void)
{
    Ip4Addr.clear(work_a);
    classify(work_a, IP4(169, 253, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_UNICAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(169, 254, 0, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_LINK_LOCAL, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(169, 254, 1, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_LINK_LOCAL, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(169, 254, 254, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_LINK_LOCAL, IDEMIP_IP4_ADDR_IO(work_a)->type);
    classify(work_a, IP4(169, 255, 0, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_UNICAST, IDEMIP_IP4_ADDR_IO(work_a)->type);
}

// sec 2.6.2 names 169.254.255.255 "the broadcast address for the Link-Local prefix", so the address
// classifies link-local and the netmask test calls it that prefix's directed broadcast.
void test_rfc3927_link_local_broadcast(void)
{
    Ip4Addr.clear(work_a);
    classify(work_a, IP4(169, 254, 255, 255));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_TYPE_LINK_LOCAL, IDEMIP_IP4_ADDR_IO(work_a)->type);

    match(work_a, IP4(169, 254, 255, 255), IDEMIP_AUTOIP_PREFIX, IP4(255, 255, 0, 0));
    TEST_ASSERT_TRUE(IDEMIP_IP4_ADDR_IO(work_a)->is_broadcast);
    TEST_ASSERT_EQUAL_HEX32(IP4(169, 254, 255, 255), IDEMIP_IP4_ADDR_IO(work_a)->broadcast);
}

// --- RFC 919 sec 7, the netmask test -----------------------------------------

// The RFC's own worked example: "a host on net 36, for example, may ... broadcast to all of net 36
// by using 36.255.255.255", and "36.0.0.0 means 'network number 36'".
void test_rfc919_directed_broadcast_of_net_36(void)
{
    Ip4Addr.clear(work_a);
    match(work_a, IP4(36, 255, 255, 255), IP4(36, 40, 0, 1), IP4(255, 0, 0, 0));
    TEST_ASSERT_EQUAL_HEX32(IP4(36, 0, 0, 0), IDEMIP_IP4_ADDR_IO(work_a)->network);
    TEST_ASSERT_EQUAL_HEX32(IP4(36, 255, 255, 255), IDEMIP_IP4_ADDR_IO(work_a)->broadcast);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ADDR_IO(work_a)->on_subnet);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ADDR_IO(work_a)->is_broadcast);
    TEST_ASSERT_EQUAL_UINT8(8u, IDEMIP_IP4_ADDR_IO(work_a)->prefix_len);
}

// The limited broadcast of case (c) is a broadcast against any subnet at all.
void test_limited_broadcast_is_a_broadcast_under_every_mask(void)
{
    Ip4Addr.clear(work_a);
    match(work_a, IP4(255, 255, 255, 255), IP4(10, 0, 0, 1), IP4(255, 255, 255, 0));
    TEST_ASSERT_TRUE(IDEMIP_IP4_ADDR_IO(work_a)->is_broadcast);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ADDR_IO(work_a)->on_subnet);
}

void test_match_reports_network_host_and_prefix_len(void)
{
    Ip4Addr.clear(work_a);
    match(work_a, IP4(192, 0, 2, 37), IP4(192, 0, 2, 1), IP4(255, 255, 255, 0));
    TEST_ASSERT_EQUAL_HEX32(IP4(192, 0, 2, 0), IDEMIP_IP4_ADDR_IO(work_a)->network);
    TEST_ASSERT_EQUAL_HEX32(IP4(0, 0, 0, 37), IDEMIP_IP4_ADDR_IO(work_a)->host);
    TEST_ASSERT_EQUAL_HEX32(IP4(192, 0, 2, 255), IDEMIP_IP4_ADDR_IO(work_a)->broadcast);
    TEST_ASSERT_EQUAL_UINT8(24u, IDEMIP_IP4_ADDR_IO(work_a)->prefix_len);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ADDR_IO(work_a)->on_subnet);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ADDR_IO(work_a)->contiguous);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ADDR_IO(work_a)->is_broadcast);
}

void test_match_reports_an_address_off_the_subnet(void)
{
    Ip4Addr.clear(work_a);
    match(work_a, IP4(192, 0, 3, 37), IP4(192, 0, 2, 1), IP4(255, 255, 255, 0));
    TEST_ASSERT_FALSE(IDEMIP_IP4_ADDR_IO(work_a)->on_subnet);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ADDR_IO(work_a)->is_broadcast);
}

// RFC 1122 sec 3.2.1.3: each of the host, network and subnet fields "will be at least two bits
// long", so a mask with no host field leaves no directed broadcast.
void test_a_slash_32_has_no_directed_broadcast(void)
{
    Ip4Addr.clear(work_a);
    match(work_a, IP4(192, 0, 2, 37), IP4(192, 0, 2, 37), IP4(255, 255, 255, 255));
    TEST_ASSERT_TRUE(IDEMIP_IP4_ADDR_IO(work_a)->on_subnet);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ADDR_IO(work_a)->is_broadcast);
    TEST_ASSERT_EQUAL_UINT8(32u, IDEMIP_IP4_ADDR_IO(work_a)->prefix_len);
}

// A mask of all zeros puts every address on the subnet, and its directed broadcast is the limited
// one.
void test_a_slash_0_covers_everything(void)
{
    Ip4Addr.clear(work_a);
    match(work_a, IP4(8, 8, 8, 8), IP4(192, 0, 2, 1), 0u);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ADDR_IO(work_a)->on_subnet);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP4_ADDR_IO(work_a)->prefix_len);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ADDR_IO(work_a)->contiguous);
    TEST_ASSERT_EQUAL_HEX32(IP4(255, 255, 255, 255), IDEMIP_IP4_ADDR_IO(work_a)->broadcast);
}

// RFC 1122 sec 3.2.1.3: the notation "is not intended to imply that the 1-bits in an address mask
// need be contiguous", so a mask with a hole is tested and reported rather than refused.
void test_a_non_contiguous_mask_is_reported_not_refused(void)
{
    Ip4Addr.clear(work_a);
    match(work_a, IP4(192, 0, 2, 37), IP4(192, 0, 2, 1), IP4(255, 0, 255, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ADDR_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP4_ADDR_IO(work_a)->contiguous);
    TEST_ASSERT_EQUAL_UINT8(16u, IDEMIP_IP4_ADDR_IO(work_a)->prefix_len);
    TEST_ASSERT_TRUE(IDEMIP_IP4_ADDR_IO(work_a)->on_subnet);
}

// --- RFC 1112 sec 6.4, the Ethernet map --------------------------------------
// sec 6.4 prints no worked example, so these assert the properties its sentence states: the three
// fixed octets, the low-order 23 bits carried across, the 24th left clear, and the aliasing that
// 28 significant bits into 23 forces.

void test_rfc1112_map_places_the_low_23_bits_under_01_00_5e(void)
{
    Ip4Addr.clear(work_a);
    IDEMIP_IP4_ADDR_IO(work_a)->mcast_args.group = IP4(224, 0, 0, 1);
    Ip4Addr.mcast_mac(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ADDR_IO(work_a)->status);
    static const uint8_t want[IDEMIP_MAC_LEN] = {0x01u, 0x00u, 0x5Eu, 0x00u, 0x00u, 0x01u};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, IDEMIP_IP4_ADDR_IO(work_a)->mac, IDEMIP_MAC_LEN);
}

void test_rfc1112_map_keeps_the_24th_bit_clear(void)
{
    Ip4Addr.clear(work_a);
    // 239.255.255.255 has every one of its 28 significant bits set; only 23 of them survive, so the
    // fourth octet reads 0x7F rather than 0xFF.
    IDEMIP_IP4_ADDR_IO(work_a)->mcast_args.group = IP4(239, 255, 255, 255);
    Ip4Addr.mcast_mac(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ADDR_IO(work_a)->status);
    static const uint8_t want[IDEMIP_MAC_LEN] = {0x01u, 0x00u, 0x5Eu, 0x7Fu, 0xFFu, 0xFFu};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, IDEMIP_IP4_ADDR_IO(work_a)->mac, IDEMIP_MAC_LEN);
}

// sec 6.4: "Because there are 28 significant bits in an IP host group address, more than one host
// group address may map to the same Ethernet multicast address."
void test_rfc1112_map_aliases_groups_that_differ_above_23_bits(void)
{
    Ip4Addr.clear(work_a);
    IDEMIP_IP4_ADDR_IO(work_a)->mcast_args.group = IP4(224, 0, 0, 1);
    Ip4Addr.mcast_mac(work_a);
    uint8_t first[IDEMIP_MAC_LEN];
    memcpy(first, IDEMIP_IP4_ADDR_IO(work_a)->mac, IDEMIP_MAC_LEN);

    // 224.128.0.1 and 225.0.0.1 differ from 224.0.0.1 only above the low 23 bits.
    IDEMIP_IP4_ADDR_IO(work_a)->mcast_args.group = IP4(224, 128, 0, 1);
    Ip4Addr.mcast_mac(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_IP4_ADDR_IO(work_a)->mac, IDEMIP_MAC_LEN);

    IDEMIP_IP4_ADDR_IO(work_a)->mcast_args.group = IP4(225, 0, 0, 1);
    Ip4Addr.mcast_mac(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_IP4_ADDR_IO(work_a)->mac, IDEMIP_MAC_LEN);
}

// sec 6.4 maps "an IP host group address", which sec 4 fixes at class D. An address outside it has
// no mapping at all, so it is ERR and not BUSY: no later tick gives it one.
void test_map_refuses_an_address_outside_class_d(void)
{
    Ip4Addr.clear(work_a);
    static const uint32_t outside[] = {IP4(223, 255, 255, 255), IP4(240, 0, 0, 1), IP4(10, 0, 0, 1),
                                       IP4(0, 0, 0, 0), IP4(255, 255, 255, 255)};
    for (size_t i = 0; i < sizeof outside / sizeof outside[0]; i++)
    {
        IDEMIP_IP4_ADDR_IO(work_a)->mcast_args.group = outside[i];
        Ip4Addr.mcast_mac(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_IP4_ADDR_IO(work_a)->status,
                                      "an address outside class D was mapped");
        TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_IP4_ADDR_IO(work_a)->status,
                                          "a refusal a retry cannot fix must not be BUSY");
        static const uint8_t zero[IDEMIP_MAC_LEN] = {0u, 0u, 0u, 0u, 0u, 0u};
        TEST_ASSERT_EQUAL_UINT8_ARRAY(zero, IDEMIP_IP4_ADDR_IO(work_a)->mac, IDEMIP_MAC_LEN);
    }
}

// Nothing here defers, so no entry ever reports BUSY on a well-formed call.
void test_no_entry_ever_reports_busy(void)
{
    Ip4Addr.clear(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_ADDR_IO(work_a)->status);
    classify(work_a, IP4(10, 0, 0, 1));
    match(work_a, IP4(10, 0, 0, 1), IP4(10, 0, 0, 0), IP4(255, 255, 255, 0));
    IDEMIP_IP4_ADDR_IO(work_a)->mcast_args.group = IP4(224, 0, 0, 2);
    Ip4Addr.mcast_mac(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_ADDR_IO(work_a)->status);
}
