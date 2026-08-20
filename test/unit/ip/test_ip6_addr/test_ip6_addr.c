// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ip6_addr against RFC 4291 sec 2 and RFC 4007 sec 4 through sec 6.
//
// The vectors are the RFCs' own printed addresses: sec 2.2's four text-representation examples,
// sec 2.4's type table, sec 2.7's four NTP-server scopes, and sec 2.7.1's worked solicited-node
// example. Where a section prints no example the case asserts the property its text states.
//
// Same six checks every unit's suite carries:
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. the vectors are the RFC's own
//   6. BUSY and ERR are separated by whether retrying can ever succeed
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ip/ip6_addr.h"

#include <string.h>
#include <unity.h>

// Eight 16-bit pieces, the "preferred form" of RFC 4291 sec 2.2.
typedef struct
{
    uint8_t *out;
    uint16_t g0;
    uint16_t g1;
    uint16_t g2;
    uint16_t g3;
    uint16_t g4;
    uint16_t g5;
    uint16_t g6;
    uint16_t g7;
} A6Args;

static void a6_ctx(const A6Args *args)
{
    const uint16_t g[8] = {args->g0, args->g1, args->g2, args->g3, args->g4, args->g5, args->g6, args->g7};
    for (int i = 0; i < 8; i++)
    {
        args->out[i * 2] = (uint8_t)(g[i] >> 8);
        args->out[i * 2 + 1] = (uint8_t)(g[i] & 0xFFu);
    }
}

#define a6(...) IDEMIP_CALL(a6_ctx, A6Args, __VA_ARGS__)

static uint8_t addr_a[IDEMIP_IP6_ADDR_LEN];
static uint8_t addr_b[IDEMIP_IP6_ADDR_LEN];
static uint8_t want[IDEMIP_IP6_ADDR_LEN];

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_IP6_ADDR_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_IP6_ADDR_BORROW + 16];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP6_ADDR_BORROW, CANARY, cap - IDEMIP_IP6_ADDR_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP6_ADDR_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP6_ADDR_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(addr_a, 0, sizeof addr_a);
    memset(addr_b, 0, sizeof addr_b);
    memset(want, 0, sizeof want);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

static void classify(uint8_t *w, const uint8_t *addr)
{
    IDEMIP_IP6_ADDR_IO(w)->classify_args.addr = addr;
    Ip6Addr.classify(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(w)->status);
}

static void zone_of(uint8_t *w, const uint8_t *addr, uint8_t netif)
{
    IDEMIP_IP6_ADDR_IO(w)->zone_args.addr = addr;
    IDEMIP_IP6_ADDR_IO(w)->zone_args.netif = netif;
    Ip6Addr.zone(w);
}

// --- the borrow --------------------------------------------------------------

void test_every_entry_survives_a_null_borrow(void)
{
    Ip6Addr.clear(NULL);
    Ip6Addr.classify(NULL);
    Ip6Addr.solicited(NULL);
    Ip6Addr.zone(NULL);
    Ip6Addr.match(NULL);
    TEST_PASS();
}

void test_two_borrows_share_no_byte(void)
{
    Ip6Addr.clear(work_a);
    Ip6Addr.clear(work_b);
    a6(addr_a, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    a6(addr_b, 0xFF02u, 0, 0, 0, 0, 0, 0, 1u);

    IDEMIP_IP6_ADDR_IO(work_a)->classify_args.addr = addr_a;
    IDEMIP_IP6_ADDR_IO(work_b)->classify_args.addr = addr_b;
    TEST_ASSERT_EQUAL_PTR(addr_a, IDEMIP_IP6_ADDR_IO(work_a)->classify_args.addr);
    TEST_ASSERT_EQUAL_PTR(addr_b, IDEMIP_IP6_ADDR_IO(work_b)->classify_args.addr);

    Ip6Addr.classify(work_a);
    Ip6Addr.classify(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_LINK_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->type);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_MULTICAST, IDEMIP_IP6_ADDR_IO(work_b)->type);
}

void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    Ip6Addr.clear(work_a);
    Ip6Addr.clear(work_b);
    a6(addr_a, 0x4037u, 0, 0, 0, 0x0001u, 0x0800u, 0x200Eu, 0x8C6Cu);
    a6(addr_b, 0x2001u, 0x0DB8u, 0, 0, 0, 0, 0, 1u);

    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = addr_a;
    IDEMIP_IP6_ADDR_IO(work_b)->solicited_args.addr = addr_b;

    Ip6Addr.solicited(work_a);
    uint8_t first[IDEMIP_IP6_ADDR_LEN];
    memcpy(first, IDEMIP_IP6_ADDR_IO(work_a)->solicited, IDEMIP_IP6_ADDR_LEN);
    Ip6Addr.solicited(work_b);
    Ip6Addr.solicited(work_a);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_IP6_ADDR_IO(work_a)->solicited, IDEMIP_IP6_ADDR_LEN);
}

// Zeroed, never cleared: every entry must refuse rather than answer out of whatever was in the
// bytes. ERR and not BUSY, because no later tick clears the borrow for the caller.
void test_uncleared_borrow_refuses_work(void)
{
    a6(addr_a, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_ADDR_IO(work_a)->classify_args.addr = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->zone_args.addr = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b = addr_a;

    Ip6Addr.classify(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);
    Ip6Addr.solicited(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);
    Ip6Addr.zone(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);
    Ip6Addr.match(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);
}

void test_a_null_address_is_refused(void)
{
    Ip6Addr.clear(work_a);
    IDEMIP_IP6_ADDR_IO(work_a)->classify_args.addr = NULL;
    Ip6Addr.classify(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);
    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = NULL;
    Ip6Addr.solicited(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);
}

// --- RFC 4291 sec 2.4, the type table ----------------------------------------

// "Unspecified 00...0 (128 bits) ::/128" and "Loopback 00...1 (128 bits) ::1/128", which sec 2.2
// prints as 0:0:0:0:0:0:0:0 and 0:0:0:0:0:0:0:1.
void test_sec2_4_unspecified_and_loopback(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0, 0, 0, 0, 0, 0, 0, 0);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_UNSPECIFIED, IDEMIP_IP6_ADDR_IO(work_a)->type);

    a6(addr_a, 0, 0, 0, 0, 0, 0, 0, 1u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_LOOPBACK, IDEMIP_IP6_ADDR_IO(work_a)->type);
}

// "Multicast 11111111 FF00::/8" and "Link-Local unicast 1111111010 FE80::/10".
void test_sec2_4_multicast_and_link_local(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFF00u, 0, 0, 0, 0, 0, 0, 0);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_MULTICAST, IDEMIP_IP6_ADDR_IO(work_a)->type);

    a6(addr_a, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_LINK_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->type);

    // The tenth bit is what ends the prefix: FEBF:: is still link-local, FEC0:: is not.
    a6(addr_a, 0xFEBFu, 0, 0, 0, 0, 0, 0, 1u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_LINK_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->type);
}

// "Global Unicast (everything else)", with sec 2.2's own example 2001:DB8:0:0:8:800:200C:417A.
void test_sec2_4_global_unicast_is_everything_else(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0x2001u, 0x0DB8u, 0, 0, 0x0008u, 0x0800u, 0x200Cu, 0x417Au);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_GLOBAL, IDEMIP_IP6_ADDR_IO(work_a)->type);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_GLOBAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);
}

// sec 2.5.7 "Site-Local addresses have the following format: 1111111011", the prefix new
// implementations "must treat ... as Global Unicast" and RFC 6724 sec 3.1 still gives site-local
// scope.
void test_sec2_5_7_site_local_is_fec0_slash_10(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFEC0u, 0, 0, 0, 0, 0, 0, 1u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_SITE_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->type);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_SITE_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);

    a6(addr_a, 0xFEFFu, 0, 0, 0, 0, 0, 0, 1u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_SITE_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->type);
}

// sec 2.2 prints ::13.1.68.3 and ::FFFF:129.144.52.38 as its mixed-notation examples, which are
// sec 2.5.5.1's IPv4-compatible and sec 2.5.5.2's IPv4-mapped forms.
void test_sec2_5_5_embedded_ipv4_forms(void)
{
    Ip6Addr.clear(work_a);
    // ::13.1.68.3
    a6(addr_a, 0, 0, 0, 0, 0, 0, 0x0D01u, 0x4403u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_V4_COMPAT, IDEMIP_IP6_ADDR_IO(work_a)->type);

    // ::FFFF:129.144.52.38
    a6(addr_a, 0, 0, 0, 0, 0, 0xFFFFu, 0x8190u, 0x3426u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_V4_MAPPED, IDEMIP_IP6_ADDR_IO(work_a)->type);

    // sec 2.5.5 puts both in Global Unicast space, so both carry global scope.
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_GLOBAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);
}

// --- RFC 4291 sec 2.7, scope and flags ---------------------------------------

// sec 2.7's own worked set: "if the 'NTP servers group' is assigned a permanent multicast address
// with a group ID of 101 (hex)", then FF01::101 is interface-local, FF02::101 link-local,
// FF05::101 site-local and FF0E::101 global.
void test_sec2_7_ntp_group_scopes(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFF01u, 0, 0, 0, 0, 0, 0, 0x0101u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_INTERFACE_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);

    a6(addr_a, 0xFF02u, 0, 0, 0, 0, 0, 0, 0x0101u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_LINK_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);

    a6(addr_a, 0xFF05u, 0, 0, 0, 0, 0, 0, 0x0101u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_SITE_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);

    a6(addr_a, 0xFF0Eu, 0, 0, 0, 0, 0, 0, 0x0101u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_GLOBAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);
}

// sec 2.7: "T = 0 indicates a permanently-assigned ('well-known') multicast address ... T = 1
// indicates a non-permanently-assigned ('transient' ...) multicast address." sec 2.7's own
// transient example is FF15:0:0:0:0:0:0:101.
void test_sec2_7_transient_flag(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFF05u, 0, 0, 0, 0, 0, 0, 0x0101u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_ADDR_IO(work_a)->flags & IDEMIP_IP6_MCAST_FLAG_T);

    a6(addr_a, 0xFF15u, 0, 0, 0, 0, 0, 0, 0x0101u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_MCAST_FLAG_T,
                            IDEMIP_IP6_ADDR_IO(work_a)->flags & IDEMIP_IP6_MCAST_FLAG_T);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_SITE_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);
}

// A unicast address has no flgs nibble at all.
void test_a_unicast_address_reports_no_multicast_flags(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_ADDR_IO(work_a)->flags);
}

// --- RFC 4291 sec 2.7.1, the solicited-node address --------------------------

// The section's own worked example: "the Solicited-Node multicast address corresponding to the IPv6
// address 4037::01:800:200E:8C6C is FF02::1:FF0E:8C6C".
void test_sec2_7_1_worked_example(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0x4037u, 0, 0, 0, 0x0001u, 0x0800u, 0x200Eu, 0x8C6Cu);
    a6(want, 0xFF02u, 0, 0, 0, 0, 0x0001u, 0xFF0Eu, 0x8C6Cu);

    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = addr_a;
    Ip6Addr.solicited(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, IDEMIP_IP6_ADDR_IO(work_a)->solicited, IDEMIP_IP6_ADDR_LEN);
}

// sec 2.7.1 bounds the result "in the range FF02:0:0:0:0:1:FF00:0000 to FF02:0:0:0:0:1:FFFF:FFFF".
void test_sec2_7_1_range_endpoints(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0x2001u, 0x0DB8u, 0, 0, 0, 0, 0xFF00u, 0x0000u);
    a6(want, 0xFF02u, 0, 0, 0, 0, 0x0001u, 0xFF00u, 0x0000u);
    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = addr_a;
    Ip6Addr.solicited(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, IDEMIP_IP6_ADDR_IO(work_a)->solicited, IDEMIP_IP6_ADDR_LEN);

    a6(addr_a, 0x2001u, 0x0DB8u, 0, 0, 0, 0, 0x00FFu, 0xFFFFu);
    a6(want, 0xFF02u, 0, 0, 0, 0, 0x0001u, 0xFFFFu, 0xFFFFu);
    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = addr_a;
    Ip6Addr.solicited(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, IDEMIP_IP6_ADDR_IO(work_a)->solicited, IDEMIP_IP6_ADDR_LEN);
}

// sec 2.7.1: "IPv6 addresses that differ only in the high-order bits ... will map to the same
// Solicited-Node address, thereby reducing the number of multicast addresses a node must join."
void test_sec2_7_1_high_order_bits_alias(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0x4037u, 0, 0, 0, 0x0001u, 0x0800u, 0x200Eu, 0x8C6Cu);
    a6(addr_b, 0x2001u, 0x0DB8u, 0x1234u, 0, 0, 0, 0x110Eu, 0x8C6Cu);

    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = addr_a;
    Ip6Addr.solicited(work_a);
    memcpy(want, IDEMIP_IP6_ADDR_IO(work_a)->solicited, IDEMIP_IP6_ADDR_LEN);

    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = addr_b;
    Ip6Addr.solicited(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, IDEMIP_IP6_ADDR_IO(work_a)->solicited, IDEMIP_IP6_ADDR_LEN);
}

// sec 2.7.1 forms the address from "a node's unicast and anycast addresses". A multicast address is
// neither, and sec 2.5.2 says the unspecified address "must never be assigned to any node". Both
// are ERR and not BUSY: no later tick gives either one a solicited-node form.
void test_solicited_refuses_a_multicast_or_unspecified_address(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFF02u, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = addr_a;
    Ip6Addr.solicited(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);

    a6(addr_a, 0, 0, 0, 0, 0, 0, 0, 0);
    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = addr_a;
    Ip6Addr.solicited(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);
}

// --- RFC 4007 sec 5 and sec 6, zones -----------------------------------------

// sec 5: "Each link and the interfaces attached to that link comprise a single zone of link-local
// scope", and sec 6's default assignment gives "A unique link index for each interface". sec 6 also
// reserves index zero, "the index value zero at each scope SHOULD be reserved to mean 'use the
// default zone'", so a derived index is one past the interface it came from.
void test_rfc4007_link_local_takes_the_interface_index(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    zone_of(work_a, addr_a, 3u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(4u, IDEMIP_IP6_ADDR_IO(work_a)->zone);
    TEST_ASSERT_TRUE(IDEMIP_IP6_ADDR_IO(work_a)->zone_derived);

    // Two interfaces derive two different zones, which is what keeps sec 5's "two different physical
    // links may each contain a node with the link-local address fe80::1" distinct.
    zone_of(work_a, addr_a, 4u);
    TEST_ASSERT_EQUAL_UINT32(5u, IDEMIP_IP6_ADDR_IO(work_a)->zone);
}

// Interface zero is a real interface here, and sec 6 reserves zone index zero for the default zone,
// so a derived index must never land on it. sec 5 is what breaks if it does: "addresses of a given
// (non-global) scope may be re-used in different zones of that scope."
void test_rfc4007_interface_zero_does_not_derive_the_default_zone(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    zone_of(work_a, addr_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IP6_ADDR_IO(work_a)->zone_derived);
    uint32_t zone0 = IDEMIP_IP6_ADDR_IO(work_a)->zone;
    TEST_ASSERT_NOT_EQUAL_MESSAGE(IDEMIP_IP6_ZONE_DEFAULT, zone0,
                                  "interface zero must not derive the reserved default-zone index");

    // The same fe80::1 on interface 0 and on interface 2 names two different interfaces.
    zone_of(work_a, addr_a, 2u);
    uint32_t zone2 = IDEMIP_IP6_ADDR_IO(work_a)->zone;
    Ip6Addr.clear(work_a);
    a6(addr_b, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b = addr_b;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a_zone = zone0;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b_zone = zone2;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.prefix_len = 128u;
    Ip6Addr.match(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP6_ADDR_IO(work_a)->equal,
                              "one link-local address on two links is two addresses");
}

// sec 5: "Each interface on a node comprises a single zone of interface-local scope (for multicast
// only)."
void test_rfc4007_interface_local_multicast_takes_the_interface_index(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFF01u, 0, 0, 0, 0, 0, 0, 1u);
    zone_of(work_a, addr_a, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(3u, IDEMIP_IP6_ADDR_IO(work_a)->zone);
    TEST_ASSERT_TRUE(IDEMIP_IP6_ADDR_IO(work_a)->zone_derived);
}

// RFC 4291 sec 2.7: "Nodes should not originate a packet to a multicast address whose scop field
// contains the reserved value F; if such a packet is sent or received, it must be treated the same
// as packets destined to a global (scop E) multicast address." RFC 6724 sec 3.1 enumerates only
// "interface-local (0x1), link-local (0x2), admin-local (0x4), site-local (0x5),
// organization-local (0x8), and global (0xE) scopes", so nothing above global exists to compare.
void test_rfc4291_a_scop_f_multicast_address_has_global_scope(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFF1Fu, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_ADDR_IO(work_a)->classify_args.addr = addr_a;
    Ip6Addr.classify(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_TYPE_MULTICAST, IDEMIP_IP6_ADDR_IO(work_a)->type);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP6_SCOPE_GLOBAL, IDEMIP_IP6_ADDR_IO(work_a)->scope,
                                  "scop F is treated the same as scop E");

    // The scop-E address it must be indistinguishable from.
    a6(addr_b, 0xFF1Eu, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_ADDR_IO(work_a)->classify_args.addr = addr_b;
    Ip6Addr.classify(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_GLOBAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);

    // And scop E's neighbour below it still reads as itself.
    a6(addr_b, 0xFF08u, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_ADDR_IO(work_a)->classify_args.addr = addr_b;
    Ip6Addr.classify(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_ORG_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);
}

// sec 5: "There is a single zone of global scope", so the default index names it whatever interface
// the address is used on.
void test_rfc4007_global_scope_is_the_default_zone(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0x2001u, 0x0DB8u, 0, 0, 0, 0, 0, 1u);
    zone_of(work_a, addr_a, 7u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_IP6_ZONE_DEFAULT, IDEMIP_IP6_ADDR_IO(work_a)->zone);
    TEST_ASSERT_TRUE(IDEMIP_IP6_ADDR_IO(work_a)->zone_derived);
}

// sec 5: "The boundaries of zones of a scope other than interface-local, link-local, and global must
// be defined and configured by network administrators", so no index is derived for one.
void test_rfc4007_a_site_zone_is_not_derived(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFF05u, 0, 0, 0, 0, 0, 0, 1u);
    zone_of(work_a, addr_a, 4u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_IP6_ZONE_DEFAULT, IDEMIP_IP6_ADDR_IO(work_a)->zone);
    TEST_ASSERT_FALSE(IDEMIP_IP6_ADDR_IO(work_a)->zone_derived);
}

// RFC 4291 sec 2.7: "Nodes must not originate a packet to a multicast address whose scop field
// contains the reserved value 0; if such a packet is received, it must be silently dropped." So it
// has no zone. ERR and not BUSY: a later tick does not give scop 0 a meaning.
void test_a_reserved_scop_of_zero_has_no_zone(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFF00u, 0, 0, 0, 0, 0, 0, 1u);
    zone_of(work_a, addr_a, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_ADDR_IO(work_a)->zone_derived);
}

// sec 2.7: a packet to scop F "must be treated the same as packets destined to a global (scop E)
// multicast address", so it takes the single global zone.
void test_a_reserved_scop_of_f_takes_the_global_zone(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFF0Fu, 0, 0, 0, 0, 0, 0, 1u);
    zone_of(work_a, addr_a, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_IP6_ZONE_DEFAULT, IDEMIP_IP6_ADDR_IO(work_a)->zone);
    TEST_ASSERT_TRUE(IDEMIP_IP6_ADDR_IO(work_a)->zone_derived);
}

// RFC 4007 sec 4: the unspecified address "does not have any scope because it must never be
// assigned to any node".
void test_the_unspecified_address_has_no_scope(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0, 0, 0, 0, 0, 0, 0, 0);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_RESERVED, IDEMIP_IP6_ADDR_IO(work_a)->scope);
    zone_of(work_a, addr_a, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);
}

// RFC 4007 sec 4: "The IPv6 unicast loopback address, ::1, is treated as having link-local scope
// within an imaginary link".
void test_the_loopback_address_has_link_local_scope(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0, 0, 0, 0, 0, 0, 0, 1u);
    classify(work_a, addr_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_SCOPE_LINK_LOCAL, IDEMIP_IP6_ADDR_IO(work_a)->scope);
}

// --- RFC 4007 sec 5, the same address in two zones ---------------------------

// sec 5's own example: "two different physical links may each contain a node with the link-local
// address fe80::1", so the address alone does not name an interface.
void test_the_same_link_local_address_in_two_zones_is_not_one_interface(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    a6(addr_b, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);

    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b = addr_b;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a_zone = 1u;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b_zone = 2u;
    Ip6Addr.match(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_ADDR_IO(work_a)->equal);

    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b_zone = 1u;
    Ip6Addr.match(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP6_ADDR_IO(work_a)->equal);
}

// sec 6: "the index value zero at each scope SHOULD be reserved to mean 'use the default zone'."
void test_the_default_zone_matches_whatever_the_other_names(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    a6(addr_b, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b = addr_b;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a_zone = IDEMIP_IP6_ZONE_DEFAULT;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b_zone = 9u;
    Ip6Addr.match(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP6_ADDR_IO(work_a)->equal);
}

// sec 5: "There is a single zone of global scope", so two equal global addresses are the same one
// whatever indices accompany them.
void test_a_global_address_ignores_zone_indices(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0x2001u, 0x0DB8u, 0, 0, 0, 0, 0, 1u);
    a6(addr_b, 0x2001u, 0x0DB8u, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b = addr_b;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a_zone = 1u;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b_zone = 2u;
    Ip6Addr.match(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP6_ADDR_IO(work_a)->equal);
}

// RFC 4291 sec 2.3 writes a prefix as "how many of the leftmost contiguous bits of the address
// comprise the prefix", which the comparison reads over.
void test_prefix_equality_over_the_leading_bits(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    a6(addr_b, 0xFE80u, 0, 0, 0, 0, 0, 0, 2u);
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b = addr_b;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.prefix_len = 64u;
    Ip6Addr.match(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP6_ADDR_IO(work_a)->prefix_equal);
    TEST_ASSERT_FALSE(IDEMIP_IP6_ADDR_IO(work_a)->equal);

    IDEMIP_IP6_ADDR_IO(work_a)->match_args.prefix_len = 128u;
    Ip6Addr.match(work_a);
    TEST_ASSERT_FALSE(IDEMIP_IP6_ADDR_IO(work_a)->prefix_equal);

    // The tenth bit, which sec 2.5.6 ends the link-local prefix at.
    a6(addr_b, 0xFEC0u, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.prefix_len = 9u;
    Ip6Addr.match(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP6_ADDR_IO(work_a)->prefix_equal);
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.prefix_len = 10u;
    Ip6Addr.match(work_a);
    TEST_ASSERT_FALSE(IDEMIP_IP6_ADDR_IO(work_a)->prefix_equal);
}

// An address is 128 bits, so a longer prefix names nothing. ERR and not BUSY.
void test_a_prefix_longer_than_the_address_is_refused(void)
{
    Ip6Addr.clear(work_a);
    a6(addr_a, 0xFE80u, 0, 0, 0, 0, 0, 0, 1u);
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.a = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.b = addr_a;
    IDEMIP_IP6_ADDR_IO(work_a)->match_args.prefix_len = 129u;
    Ip6Addr.match(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_ADDR_IO(work_a)->status);
}

// Nothing here defers, so no entry ever reports BUSY on a well-formed call.
void test_no_entry_ever_reports_busy(void)
{
    Ip6Addr.clear(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP6_ADDR_IO(work_a)->status);
    a6(addr_a, 0x2001u, 0x0DB8u, 0, 0, 0, 0, 0, 1u);
    classify(work_a, addr_a);
    IDEMIP_IP6_ADDR_IO(work_a)->solicited_args.addr = addr_a;
    Ip6Addr.solicited(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
    zone_of(work_a, addr_a, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_ADDR_IO(work_a)->status);
}
