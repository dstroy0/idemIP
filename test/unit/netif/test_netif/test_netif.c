// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for netif, shaped on test/unit/ethernet/test_phy. Every case here tests the
// CONTRACT and stays valid however the logic behind it is written:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_NETIF_BORROW is intact after every case
//   5. the published offsets are ordered and do not overlap
//   6. clear zeroes the table regions, and a borrow it has not run on is refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/netif/netif.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_NETIF_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_NETIF_BORROW + 16];

static const uint8_t g_mac_a[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t g_mac_b[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

// Two phy borrows, only ever compared as addresses by this unit.
static _Alignas(8) uint8_t phy_a[IDEMIP_PHY_BORROW];
static _Alignas(8) uint8_t phy_b[IDEMIP_PHY_BORROW];

#if IDEMIP_ENABLE_IPV6
static const uint8_t g_addr6_a[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_addr6_b[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};
#endif

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_NETIF_BORROW, CANARY, cap - IDEMIP_NETIF_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_NETIF_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_NETIF_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(phy_a, 0, sizeof phy_a);
    memset(phy_b, 0, sizeof phy_b);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// Every entry, so a case that walks the whole namespace cannot miss one.
static void call_every_entry(uint8_t *w)
{
    Netif.clear(w);
    Netif.bind(w);
    Netif.unbind(w);
    Netif.set_addr4(w);
    Netif.set_mtu(w);
    Netif.set_flags(w);
    Netif.set_offload(w);
    Netif.get(w);
    Netif.find4(w);
    Netif.local4(w);
#if IDEMIP_ENABLE_IPV6
    Netif.add_addr6(w);
    Netif.remove_addr6(w);
    Netif.find_addr6(w);
    Netif.get_addr6(w);
    Netif.tick(w);
#endif
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the table, and the operand block is in it, so two tables share no byte at all. This
// is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    Netif.clear(work_a);
    Netif.clear(work_b);

    IDEMIP_NETIF_IO(work_a)->bind_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->bind_args.phy = phy_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.hwaddr = g_mac_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.mtu = 1500u;

    IDEMIP_NETIF_IO(work_b)->bind_args.index = 1u;
    IDEMIP_NETIF_IO(work_b)->bind_args.phy = phy_b;
    IDEMIP_NETIF_IO(work_b)->bind_args.hwaddr = g_mac_b;
    IDEMIP_NETIF_IO(work_b)->bind_args.mtu = 1280u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->bind_args.index);
    TEST_ASSERT_EQUAL_PTR(phy_a, IDEMIP_NETIF_IO(work_a)->bind_args.phy);
    TEST_ASSERT_EQUAL_PTR(g_mac_a, IDEMIP_NETIF_IO(work_a)->bind_args.hwaddr);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_NETIF_IO(work_a)->bind_args.mtu);

    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_NETIF_IO(work_b)->bind_args.index);
    TEST_ASSERT_EQUAL_PTR(phy_b, IDEMIP_NETIF_IO(work_b)->bind_args.phy);
    TEST_ASSERT_EQUAL_PTR(g_mac_b, IDEMIP_NETIF_IO(work_b)->bind_args.hwaddr);
    TEST_ASSERT_EQUAL_UINT16(1280u, IDEMIP_NETIF_IO(work_b)->bind_args.mtu);

    // And running every entry on b leaves a's operands where a left them.
    call_every_entry(work_b);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->bind_args.index);
    TEST_ASSERT_EQUAL_PTR(phy_a, IDEMIP_NETIF_IO(work_a)->bind_args.phy);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_NETIF_IO(work_a)->bind_args.mtu);
}

// The two operand blocks are at the same offset in different borrows, so they are different bytes.
void test_the_two_operand_blocks_are_different_bytes(void)
{
    TEST_ASSERT_TRUE(IDEMIP_NETIF_IO(work_a) != IDEMIP_NETIF_IO(work_b));
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_NETIF_OFF_IO, IDEMIP_NETIF_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_NETIF_OFF_IO, IDEMIP_NETIF_IO(work_b));
}

// An entry writing its own borrow never reaches the next one. The canary is checked in tearDown,
// so this case only has to do the writing.
void test_no_entry_writes_past_the_borrow(void)
{
    Netif.clear(work_a);
    IDEMIP_NETIF_IO(work_a)->bind_args.index = (uint8_t)(IDEMIP_NETIF_COUNT - 1u);
    IDEMIP_NETIF_IO(work_a)->bind_args.phy = phy_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.hwaddr = g_mac_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.mtu = 1500u;
    IDEMIP_NETIF_IO(work_a)->if_args.index = (uint8_t)(IDEMIP_NETIF_COUNT - 1u);
    IDEMIP_NETIF_IO(work_a)->addr4_args.index = (uint8_t)(IDEMIP_NETIF_COUNT - 1u);
    IDEMIP_NETIF_IO(work_a)->route_args.index = (uint8_t)(IDEMIP_NETIF_COUNT - 1u);
#if IDEMIP_ENABLE_IPV6
    IDEMIP_NETIF_IO(work_a)->addr6_args.index = (uint8_t)(IDEMIP_NETIF_COUNT - 1u);
    IDEMIP_NETIF_IO(work_a)->addr6_args.slot = (uint8_t)(IDEMIP_IP6_ADDRESSES - 1u);
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = g_addr6_a;
    IDEMIP_NETIF_IO(work_a)->addr6_args.state = IDEMIP_NETIF_ADDR6_TENTATIVE;
#endif
    call_every_entry(work_a);
    TEST_PASS();
}

// --- the map -----------------------------------------------------------------

// The published offsets are in order, each region ends where the next begins, and the last one ends
// inside IDEMIP_NETIF_BORROW.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_NETIF_OFF_IO);
    TEST_ASSERT_TRUE(IDEMIP_NETIF_OFF_IO + sizeof(NetifIo) <= (size_t)IDEMIP_NETIF_OFF_CTX);
    TEST_ASSERT_TRUE((size_t)IDEMIP_NETIF_OFF_CTX < (size_t)IDEMIP_NETIF_OFF_TAB);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_NETIF_OFF_TAB + (IDEMIP_NETIF_COUNT << IDEMIP_NETIF_ENTRY_SHIFT),
                             (size_t)IDEMIP_NETIF_OFF_ADDR6);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_NETIF_OFF_ADDR6 + ((IDEMIP_NETIF_COUNT * IDEMIP_IP6_ADDRESSES)
                                                               << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT),
                             (size_t)IDEMIP_NETIF_OFF_END);
    TEST_ASSERT_TRUE((size_t)IDEMIP_NETIF_OFF_END <= (size_t)IDEMIP_NETIF_BORROW);
}

// A table starts at the end of the context, and entry i sits at i << SHIFT from it, so both tables
// have to start on IDEMIP_ALIGN.
void test_both_tables_start_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_NETIF_OFF_TAB & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_NETIF_OFF_ADDR6 & (IDEMIP_ALIGN - 1u));
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Netif.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
}

// Both table regions are zero after clear, whatever was in them before. A zeroed interface entry
// holds a null link and a zeroed address entry holds IDEMIP_NETIF_ADDR6_INVALID, which is the state
// every other entry reads as empty.
void test_clear_zeroes_the_table_regions(void)
{
    memset(work_a, 0xFF, IDEMIP_NETIF_BORROW);
    Netif.clear(work_a);
    for (size_t i = (size_t)IDEMIP_NETIF_OFF_TAB; i < (size_t)IDEMIP_NETIF_OFF_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[i], "clear left a table byte set");
    }
}

// clear is the caller's, so it does not touch the operands the caller put in the borrow.
void test_clear_leaves_the_operands_alone(void)
{
    IDEMIP_NETIF_IO(work_a)->bind_args.mtu = 1500u;
    IDEMIP_NETIF_IO(work_a)->addr4_args.addr = 0x0A000001u;
    Netif.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_NETIF_IO(work_a)->bind_args.mtu);
    TEST_ASSERT_EQUAL_HEX32(0x0A000001u, IDEMIP_NETIF_IO(work_a)->addr4_args.addr);
}

// Clearing one borrow does not clear the other.
void test_clear_reaches_one_borrow_only(void)
{
    memset(work_b, 0xFF, IDEMIP_NETIF_BORROW);
    Netif.clear(work_a);
    for (size_t i = (size_t)IDEMIP_NETIF_OFF_TAB; i < (size_t)IDEMIP_NETIF_OFF_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xFFu, work_b[i], "clear on one borrow reached another");
    }
}

// --- what is refused ---------------------------------------------------------

// Bytes clear has not run on are not a table, so every entry refuses them rather than reading an
// interface record out of whatever was there.
void test_an_uncleared_borrow_is_refused(void)
{
    memset(work_a, 0xFF, IDEMIP_NETIF_BORROW);
    IDEMIP_NETIF_IO(work_a)->bind_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->bind_args.phy = phy_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.hwaddr = g_mac_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.mtu = 1500u;
    Netif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    memset(work_a, 0xFF, IDEMIP_NETIF_BORROW);
    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    Netif.get(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    memset(work_a, 0xFF, IDEMIP_NETIF_BORROW);
    IDEMIP_NETIF_IO(work_a)->route_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->route_args.dst = 0x0A000002u;
    Netif.local4(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// An index past the table would reach outside the region the map published for it.
void test_an_index_past_the_table_is_refused(void)
{
    Netif.clear(work_a);

    IDEMIP_NETIF_IO(work_a)->bind_args.index = (uint8_t)IDEMIP_NETIF_COUNT;
    IDEMIP_NETIF_IO(work_a)->bind_args.phy = phy_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.hwaddr = g_mac_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.mtu = 1500u;
    Netif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->if_args.index = (uint8_t)IDEMIP_NETIF_COUNT;
    Netif.get(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    Netif.set_mtu(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    Netif.unbind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->addr4_args.index = (uint8_t)IDEMIP_NETIF_COUNT;
    Netif.set_addr4(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->route_args.index = (uint8_t)IDEMIP_NETIF_COUNT;
    Netif.local4(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// A driver-less interface has no link to send through, so bind takes both the borrow and the
// hardware address or nothing.
void test_bind_refuses_a_missing_link_or_address(void)
{
    Netif.clear(work_a);

    IDEMIP_NETIF_IO(work_a)->bind_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->bind_args.phy = NULL;
    IDEMIP_NETIF_IO(work_a)->bind_args.hwaddr = g_mac_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.mtu = 1500u;
    Netif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->bind_args.phy = phy_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.hwaddr = NULL;
    Netif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// A bit outside IDEMIP_NETIF_FLAG_MASK names no flag, so storing it would report a state the header
// does not define.
void test_set_flags_refuses_a_reserved_bit(void)
{
    Netif.clear(work_a);
    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->if_args.set = (uint16_t)~IDEMIP_NETIF_FLAG_MASK;
    IDEMIP_NETIF_IO(work_a)->if_args.clear = 0u;
    Netif.set_flags(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->if_args.set = 0u;
    IDEMIP_NETIF_IO(work_a)->if_args.clear = (uint16_t)~IDEMIP_NETIF_FLAG_MASK;
    Netif.set_flags(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// The same for the offload mask: a bit outside it names no header.
void test_set_offload_refuses_a_reserved_bit(void)
{
    Netif.clear(work_a);
    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->if_args.chksum = (uint16_t)~IDEMIP_NETIF_CHKSUM_MASK;
    Netif.set_offload(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// An interface with no link bound is not an interface a route decision can read.
void test_an_unbound_interface_is_refused(void)
{
    Netif.clear(work_a);
    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    Netif.get(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_NETIF_IO(work_a)->phy);
    TEST_ASSERT_NULL(IDEMIP_NETIF_IO(work_a)->hwaddr);
}

#if IDEMIP_ENABLE_IPV6

// A slot past IDEMIP_IP6_ADDRESSES would reach outside the interface's own run of the address table.
void test_an_addr6_slot_past_the_table_is_refused(void)
{
    Netif.clear(work_a);
    IDEMIP_NETIF_IO(work_a)->addr6_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->addr6_args.slot = (uint8_t)IDEMIP_IP6_ADDRESSES;
    Netif.get_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_NETIF_IO(work_a)->addr6);
}

// RFC 4862 sec 2: "The valid lifetime must be greater than or equal to the preferred lifetime."
void test_add_addr6_refuses_a_valid_lifetime_under_the_preferred_one(void)
{
    Netif.clear(work_a);
    IDEMIP_NETIF_IO(work_a)->addr6_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = g_addr6_a;
    IDEMIP_NETIF_IO(work_a)->addr6_args.state = IDEMIP_NETIF_ADDR6_TENTATIVE;
    IDEMIP_NETIF_IO(work_a)->addr6_args.preferred_s = 600u;
    IDEMIP_NETIF_IO(work_a)->addr6_args.valid_s = 300u;
    Netif.add_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 4862 sec 2 names an invalid address one "that is not assigned to any interface", so it is the
// free slot rather than a state a caller assigns.
void test_add_addr6_refuses_the_invalid_state(void)
{
    Netif.clear(work_a);
    IDEMIP_NETIF_IO(work_a)->addr6_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = g_addr6_a;
    IDEMIP_NETIF_IO(work_a)->addr6_args.state = IDEMIP_NETIF_ADDR6_INVALID;
    IDEMIP_NETIF_IO(work_a)->addr6_args.preferred_s = 300u;
    IDEMIP_NETIF_IO(work_a)->addr6_args.valid_s = 600u;
    Netif.add_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

void test_addr6_entries_refuse_a_null_address(void)
{
    Netif.clear(work_a);
    IDEMIP_NETIF_IO(work_a)->addr6_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = NULL;
    IDEMIP_NETIF_IO(work_a)->addr6_args.state = IDEMIP_NETIF_ADDR6_TENTATIVE;
    Netif.add_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    Netif.remove_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// The two IPv6 operand blocks are the two borrows' own, so the addresses named in them do not mix.
void test_addr6_operands_on_two_borrows_are_independent(void)
{
    Netif.clear(work_a);
    Netif.clear(work_b);
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = g_addr6_a;
    IDEMIP_NETIF_IO(work_b)->addr6_args.addr = g_addr6_b;
    Netif.find_addr6(work_b);
    TEST_ASSERT_EQUAL_PTR(g_addr6_a, IDEMIP_NETIF_IO(work_a)->addr6_args.addr);
    TEST_ASSERT_EQUAL_PTR(g_addr6_b, IDEMIP_NETIF_IO(work_b)->addr6_args.addr);
}

// RFC 4861 sec 4.6.2 of both lifetimes: "A value of all one bits (0xffffffff) represents infinity."
void test_the_infinite_lifetime_is_all_one_bits(void)
{
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, IDEMIP_NETIF_LIFETIME_INFINITE);
}

// (test_a_lifetime_past_the_millisecond_clocks_range_still_expires lives past the helpers it needs.)

#endif // IDEMIP_ENABLE_IPV6

// --- the shape ---------------------------------------------------------------

// The namespace holds only const function pointers, so it costs no RAM and nothing can swap an
// entry at runtime. Every member being present is what a caller compiles against.
void test_every_entry_is_present(void)
{
    TEST_ASSERT_NOT_NULL(Netif.clear);
    TEST_ASSERT_NOT_NULL(Netif.bind);
    TEST_ASSERT_NOT_NULL(Netif.unbind);
    TEST_ASSERT_NOT_NULL(Netif.set_addr4);
    TEST_ASSERT_NOT_NULL(Netif.set_mtu);
    TEST_ASSERT_NOT_NULL(Netif.set_flags);
    TEST_ASSERT_NOT_NULL(Netif.set_offload);
    TEST_ASSERT_NOT_NULL(Netif.get);
    TEST_ASSERT_NOT_NULL(Netif.find4);
    TEST_ASSERT_NOT_NULL(Netif.local4);
#if IDEMIP_ENABLE_IPV6
    TEST_ASSERT_NOT_NULL(Netif.add_addr6);
    TEST_ASSERT_NOT_NULL(Netif.remove_addr6);
    TEST_ASSERT_NOT_NULL(Netif.find_addr6);
    TEST_ASSERT_NOT_NULL(Netif.get_addr6);
    TEST_ASSERT_NOT_NULL(Netif.tick);
#endif
}

// The flag and offload masks name every bit their enums define, so a caller can test a whole word.
void test_the_masks_cover_their_enums(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x003Fu, IDEMIP_NETIF_FLAG_MASK);
    TEST_ASSERT_EQUAL_HEX16(0x007Fu, IDEMIP_NETIF_CHKSUM_MASK);
}

// =============================================================================
// Behavior. Vectors are the RFCs' own where they print any; where they print none the case asserts
// the property the text states, and says so.
// =============================================================================

// --- the vectors -------------------------------------------------------------

// RFC 1122 sec 3.2.1.3 case (c) { -1, -1 }, "Limited broadcast".
#define V4_LIMITED_BROADCAST 0xFFFFFFFFu
// RFC 1112 sec 4: "host group addresses range from 224.0.0.0 to 239.255.255.255. The address
// 224.0.0.0 is guaranteed not to be assigned to any group, and 224.0.0.1 is assigned to the
// permanent group of all IP hosts".
#define V4_MCAST_LOW 0xE0000000u
#define V4_MCAST_ALL_HOSTS 0xE0000001u
#define V4_MCAST_HIGH 0xEFFFFFFFu
// RFC 1122 sec 3.2.1.3 case (g) { 127, <any> }, "Internal host loopback address".
#define V4_LOOPBACK 0x7F000001u

// RFC 1122 prints no numeric unicast example in sec 3.3.1.1 or sec 3.3.1.6, so these are the
// notation of sec 3.2.1.3 filled in: { <Network-number>, <Subnet-number>, <Host-number> } with a
// {-1, -1, 0} mask.
#define V4_HOST 0x0A000005u     // 10.0.0.5
#define V4_MASK 0xFFFFFF00u     // 255.255.255.0
#define V4_GW 0x0A0000FEu       // 10.0.0.254
#define V4_ON_LINK 0x0A000063u  // 10.0.0.99, same {net, subnet}
#define V4_OFF_LINK 0x0A000163u // 10.0.1.99, a different {subnet}
#define V4_DIRECTED 0x0A0000FFu // 10.0.0.255, case (e) under V4_MASK
#define V4_ZERO_HOST 0x0A000000u // 10.0.0.0, <Host-number> all zeros under V4_MASK

#if IDEMIP_ENABLE_IPV6
// RFC 4291 sec 2.2 prints these two as its examples of the preferred text form.
static const uint8_t v6_rfc4291_a[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0,    0,    0,
                                                          0x00, 0x08, 0x08, 0x00, 0x20, 0x0C, 0x41, 0x7A};
static const uint8_t v6_rfc4291_b[IDEMIP_IP6_ADDR_LEN] = {0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
                                                          0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89};
// RFC 4291 sec 2.5.2, the unspecified address 0:0:0:0:0:0:0:0.
static const uint8_t v6_unspecified[IDEMIP_IP6_ADDR_LEN] = {0};
// RFC 4291 sec 2.5.3, the loopback address 0:0:0:0:0:0:0:1.
static const uint8_t v6_loopback[IDEMIP_IP6_ADDR_LEN] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
// RFC 4291 sec 2.7.1 prints FF02:0:0:0:0:0:0:1 as the All Nodes link-local multicast address.
static const uint8_t v6_multicast[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
// Four distinct addresses, to fill one interface's IDEMIP_IP6_ADDRESSES slots.
static const uint8_t v6_fill[4][IDEMIP_IP6_ADDR_LEN] = {
    {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11},
    {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12},
    {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x13},
    {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14},
};
#endif

// --- the drivers -------------------------------------------------------------

static void up(uint8_t *w, uint8_t index, uint8_t *phy, const uint8_t *mac, uint16_t mtu)
{
    IDEMIP_NETIF_IO(w)->bind_args.index = index;
    IDEMIP_NETIF_IO(w)->bind_args.phy = phy;
    IDEMIP_NETIF_IO(w)->bind_args.hwaddr = mac;
    IDEMIP_NETIF_IO(w)->bind_args.mtu = mtu;
    Netif.bind(w);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_NETIF_IO(w)->status, "bind was refused");
}

static void addr4(uint8_t *w, uint8_t index, uint32_t addr, uint32_t mask, uint32_t gw)
{
    IDEMIP_NETIF_IO(w)->addr4_args.index = index;
    IDEMIP_NETIF_IO(w)->addr4_args.addr = addr;
    IDEMIP_NETIF_IO(w)->addr4_args.mask = mask;
    IDEMIP_NETIF_IO(w)->addr4_args.gw = gw;
    Netif.set_addr4(w);
}

static void flags(uint8_t *w, uint8_t index, uint16_t set, uint16_t clear)
{
    IDEMIP_NETIF_IO(w)->if_args.index = index;
    IDEMIP_NETIF_IO(w)->if_args.set = set;
    IDEMIP_NETIF_IO(w)->if_args.clear = clear;
    Netif.set_flags(w);
}

static void get(uint8_t *w, uint8_t index)
{
    IDEMIP_NETIF_IO(w)->if_args.index = index;
    Netif.get(w);
}

static void local4(uint8_t *w, uint8_t index, uint32_t dst)
{
    IDEMIP_NETIF_IO(w)->route_args.index = index;
    IDEMIP_NETIF_IO(w)->route_args.dst = dst;
    Netif.local4(w);
}

static void find4(uint8_t *w, uint32_t dst)
{
    IDEMIP_NETIF_IO(w)->route_args.dst = dst;
    Netif.find4(w);
}

#if IDEMIP_ENABLE_IPV6
static void add6(uint8_t *w, uint8_t index, const uint8_t *a, IdemIpNetifAddr6State state, uint32_t pref_s,
                 uint32_t valid_s)
{
    IDEMIP_NETIF_IO(w)->addr6_args.index = index;
    IDEMIP_NETIF_IO(w)->addr6_args.addr = a;
    IDEMIP_NETIF_IO(w)->addr6_args.state = state;
    IDEMIP_NETIF_IO(w)->addr6_args.preferred_s = pref_s;
    IDEMIP_NETIF_IO(w)->addr6_args.valid_s = valid_s;
    Netif.add_addr6(w);
}

static void tick(uint8_t *w, uint32_t now_ms)
{
    IDEMIP_NETIF_IO(w)->tick_args.now_ms = now_ms;
    Netif.tick(w);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_NETIF_IO(w)->status, "tick was refused");
}

static uint8_t state_at(uint8_t *w, uint8_t index, uint8_t slot)
{
    IDEMIP_NETIF_IO(w)->addr6_args.index = index;
    IDEMIP_NETIF_IO(w)->addr6_args.slot = slot;
    Netif.get_addr6(w);
    if (IDEMIP_NETIF_IO(w)->status != IDEMIP_OK)
    {
        return (uint8_t)IDEMIP_NETIF_ADDR6_INVALID;
    }
    return (uint8_t)IDEMIP_NETIF_IO(w)->addr6_state;
}

// RFC 1122 sec 3.2.1.3 case (g): a 127 address "MUST NOT appear outside a host", and RFC 4291 sec
// 2.5.3: the loopback address "must not be assigned to any physical interface". The loopback flag is
// what admitted them, so lowering it while they are held is refused rather than leaving an interface
// with a link holding an address it may not have.
void test_lowering_the_loopback_flag_is_refused_while_a_loopback_address_is_held(void)
{
    // IPv4: 127.0.0.1 goes on only because the flag is up, and the flag cannot then come down.
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    flags(work_a, 0u, (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    addr4(work_a, 0u, 0x7F000001u, 0xFF000000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    flags(work_a, 0u, 0u, (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status,
                                  "127/8 was left on an interface that is not the loopback");
    get(work_a, 0u);
    TEST_ASSERT_TRUE((IDEMIP_NETIF_IO(work_a)->flags & (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK) != 0u);

#if IDEMIP_ENABLE_IPV6
    // IPv6: the same for ::1.
    static const uint8_t lo6[IDEMIP_IP6_ADDR_LEN] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    flags(work_a, 0u, (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK, 0u);
    add6(work_a, 0u, lo6, IDEMIP_NETIF_ADDR6_PREFERRED, 600u, 600u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    flags(work_a, 0u, 0u, (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status,
                                  "::1 was left assigned to a physical interface");

    // The near miss. RFC 4291 sec 2.5.3 names one address, so an address agreeing with it on the
    // leading eight octets and the last is still not it. A test that reads only as far as the first
    // word would call this ::1 and refuse to lower the flag; nothing above would catch that, because
    // every other case here differs from ::1 inside those first eight octets.
    static const uint8_t near6[IDEMIP_IP6_ADDR_LEN] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 1};
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    flags(work_a, 0u, (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK, 0u);
    add6(work_a, 0u, near6, IDEMIP_NETIF_ADDR6_PREFERRED, 600u, 600u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    flags(work_a, 0u, 0u, (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status,
                                  "an address that is not ::1 held the loopback flag up");
#endif

    // The positive control: with no barred address held, the flag comes down.
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    flags(work_a, 0u, (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK, 0u);
    flags(work_a, 0u, 0u, (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 4862 sec 5.4.5: a duplicate address "MUST NOT be assigned to an interface", and sec 5.4 says a
// tentative one "is not considered 'assigned to an interface' in the traditional sense" with packets
// addressed to it "silently discarded". Neither answers an ordinary lookup; the sec 5.4.3 Target
// Address match asks for the tentative one and gets it.
void test_find_addr6_reports_neither_a_duplicate_nor_a_tentative_address(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);

    add6(work_a, 0u, g_addr6_a, IDEMIP_NETIF_ADDR6_DUPLICATE, 600u, 600u);
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = g_addr6_a;
    IDEMIP_NETIF_IO(work_a)->addr6_args.tentative = IDEMIP_FALSE;
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status,
                                  "an address DAD found duplicate answered as the interface's own");
    // Not even the Target Address match takes a duplicate.
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = g_addr6_a;
    IDEMIP_NETIF_IO(work_a)->addr6_args.tentative = IDEMIP_TRUE;
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    add6(work_a, 0u, g_addr6_a, IDEMIP_NETIF_ADDR6_TENTATIVE, 600u, 600u);
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = g_addr6_a;
    IDEMIP_NETIF_IO(work_a)->addr6_args.tentative = IDEMIP_FALSE;
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status,
                                  "a tentative address answered an ordinary lookup");
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = g_addr6_a;
    IDEMIP_NETIF_IO(work_a)->addr6_args.tentative = IDEMIP_TRUE;
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status,
                                  "the sec 5.4.3 Target Address match cannot see its own tentative address");

    // The positive control: a preferred address answers both.
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    add6(work_a, 0u, g_addr6_a, IDEMIP_NETIF_ADDR6_PREFERRED, 600u, 600u);
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = g_addr6_a;
    IDEMIP_NETIF_IO(work_a)->addr6_args.tentative = IDEMIP_FALSE;
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 4862 sec 5.5.4: "An address (and its association with an interface) becomes invalid when its
// valid lifetime expires." RFC 4861 sec 4.6.2 makes only 0xffffffff infinite, so a lifetime past
// what a 32-bit millisecond count spans is still finite and must still expire. This one is 194 days,
// which is about four wraps of the caller's clock.
void test_a_lifetime_past_the_millisecond_clocks_range_still_expires(void)
{
    const uint32_t valid_s = 16777216u; // 0x01000000 s, a legal Prefix Information lifetime
    const IdemIpMs valid_ms = (IdemIpMs)valid_s * 1000u;
    const uint32_t step = 0x40000000u; // 12.4 days a tick, so the 32-bit clock wraps four times

    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    add6(work_a, 0u, g_addr6_a, IDEMIP_NETIF_ADDR6_PREFERRED, valid_s, valid_s);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    IdemIpMs elapsed = 0;
    uint32_t now = 0u;
    while ((elapsed + step) < valid_ms)
    {
        now += step; // wraps in 32 bits, which the interface clock carries across
        elapsed += step;
        tick(work_a, now);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)IDEMIP_NETIF_ADDR6_PREFERRED, state_at(work_a, 0u, 0u),
                                        "the address went invalid before its valid lifetime");
    }

    // The tick that reaches the lifetime retires it.
    now += (uint32_t)(valid_ms - elapsed);
    tick(work_a, now);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)IDEMIP_NETIF_ADDR6_INVALID, state_at(work_a, 0u, 0u),
                                    "a 194-day lifetime never expired");
}
#endif

// --- bind --------------------------------------------------------------------

// The record a route decision reads is what bind put there, hwaddr pointing at the copy in this
// borrow rather than at the caller's octets.
void test_bind_then_get_reports_the_link_the_address_and_the_mtu(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    get(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(phy_a, IDEMIP_NETIF_IO(work_a)->phy);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_NETIF_IO(work_a)->mtu);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_NETIF_IO(work_a)->mtu6);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_mac_a, IDEMIP_NETIF_IO(work_a)->hwaddr, IDEMIP_MAC_LEN);
    TEST_ASSERT_TRUE(IDEMIP_NETIF_IO(work_a)->hwaddr != g_mac_a);
    TEST_ASSERT_TRUE((const uint8_t *)IDEMIP_NETIF_IO(work_a)->hwaddr >= work_a);
    TEST_ASSERT_TRUE((const uint8_t *)IDEMIP_NETIF_IO(work_a)->hwaddr < work_a + IDEMIP_NETIF_BORROW);
}

// RFC 894: "the maximum length of an IP datagram sent over an Ethernet is 1500 octets". One octet
// past that is ERR, not BUSY: no descriptor freeing later makes a frame carry it.
void test_bind_refuses_an_mtu_no_ethernet_frame_carries(void)
{
    Netif.clear(work_a);
    IDEMIP_NETIF_IO(work_a)->bind_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->bind_args.phy = phy_a;
    IDEMIP_NETIF_IO(work_a)->bind_args.hwaddr = g_mac_a;

    IDEMIP_NETIF_IO(work_a)->bind_args.mtu = (uint16_t)(IDEMIP_ETH_MAX_PAYLOAD + 1u);
    Netif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->bind_args.mtu = 0u;
    Netif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->bind_args.mtu = (uint16_t)IDEMIP_ETH_MAX_PAYLOAD;
    Netif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
}

// An entry is a function of its operands, so a second bind leaves the interface holding exactly what
// the second call named and nothing the first one left.
void test_a_rebind_lands_where_its_operands_name(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_HOST, V4_MASK, V4_GW);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    up(work_a, 0u, phy_b, g_mac_b, 1280u);
    get(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(phy_b, IDEMIP_NETIF_IO(work_a)->phy);
    TEST_ASSERT_EQUAL_UINT16(1280u, IDEMIP_NETIF_IO(work_a)->mtu);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_mac_b, IDEMIP_NETIF_IO(work_a)->hwaddr, IDEMIP_MAC_LEN);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_NETIF_IO(work_a)->addr);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_NETIF_IO(work_a)->mask);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_NETIF_IO(work_a)->gw);
}

// --- unbind ------------------------------------------------------------------

void test_unbind_drops_the_link_and_the_record(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_HOST, V4_MASK, V4_GW);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    Netif.unbind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    get(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_NETIF_IO(work_a)->phy);

    find4(work_a, V4_HOST);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// The postcondition is "this interface holds no link", so an interface that already held none is
// already there and the call reports OK.
void test_unbind_is_ok_on_an_interface_that_held_no_link(void)
{
    Netif.clear(work_a);
    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    Netif.unbind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    Netif.unbind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
}

// Unbinding one interface leaves the other one where it was.
void test_unbind_reaches_one_interface_only(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    up(work_a, 1u, phy_b, g_mac_b, 1500u);

    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    Netif.unbind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    get(work_a, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(phy_b, IDEMIP_NETIF_IO(work_a)->phy);
}

// --- the IPv4 record ---------------------------------------------------------

// RFC 1122 sec 3.3.1.6 makes all three configurable, and sec 3.3.1.1 reads the first two back.
void test_set_addr4_round_trips_through_get(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_HOST, V4_MASK, V4_GW);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    get(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(V4_HOST, IDEMIP_NETIF_IO(work_a)->addr);
    TEST_ASSERT_EQUAL_HEX32(V4_MASK, IDEMIP_NETIF_IO(work_a)->mask);
    TEST_ASSERT_EQUAL_HEX32(V4_GW, IDEMIP_NETIF_IO(work_a)->gw);
}

// An interface with no link is not an interface an address belongs to.
void test_set_addr4_refuses_an_unbound_interface(void)
{
    Netif.clear(work_a);
    addr4(work_a, 0u, V4_HOST, V4_MASK, V4_GW);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 1122 sec 3.2.1.3 case (c) { -1, -1 }: "Limited broadcast. It MUST NOT be used as a source
// address." ERR, because "When a host sends any datagram, the IP source address MUST be one of its
// own IP addresses (but not a broadcast or multicast address)" is not a condition a retry changes.
void test_set_addr4_refuses_the_limited_broadcast(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_LIMITED_BROADCAST, V4_MASK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 1122 sec 3.2.1.3 case (e) { <Network-number>, <Subnet-number>, -1 }: "Directed broadcast to
// the specified subnet. It MUST NOT be used as a source address."
void test_set_addr4_refuses_the_directed_broadcast_its_mask_names(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_DIRECTED, V4_MASK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 1122 sec 3.2.1.3: "IP addresses are not permitted to have the value 0 or -1 for any of the
// <Host-number>, <Network-number>, or <Subnet-number> fields (except in the special cases listed
// above)". 10.0.0.0 under a 255.255.255.0 mask has <Host-number> zero and is not one of those cases.
void test_set_addr4_refuses_a_zero_host_number(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_ZERO_HOST, V4_MASK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 1112 sec 4: host groups are the class D addresses, "those with '1110' as their high-order four
// bits", 224.0.0.0 through 239.255.255.255. None is an interface's own address.
void test_set_addr4_refuses_a_class_d_multicast(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_MCAST_LOW, V4_MASK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    addr4(work_a, 0u, V4_MCAST_ALL_HOSTS, V4_MASK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    addr4(work_a, 0u, V4_MCAST_HIGH, V4_MASK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 1122 sec 3.2.1.3 case (g) { 127, <any> }: "Internal host loopback address. Addresses of this
// form MUST NOT appear outside a host." An interface flagged IDEMIP_NETIF_FLAG_LOOPBACK puts nothing
// outside the host, so it is the one that may hold the form.
void test_set_addr4_refuses_the_loopback_net_off_a_loopback_interface(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_LOOPBACK, 0xFF000000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    flags(work_a, 0u, (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    addr4(work_a, 0u, V4_LOOPBACK, 0xFF000000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 1122 sec 3.2.1.3 case (a) { 0, 0 } may be sent "as a source address as part of an
// initialization procedure by which the host learns its own IP address", so it is the one all-zero
// form an interface may hold.
void test_set_addr4_accepts_the_initialization_address(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, 0u, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    addr4(work_a, 0u, 0u, V4_MASK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    get(work_a, 0u);
    TEST_ASSERT_EQUAL_HEX32(0u, IDEMIP_NETIF_IO(work_a)->addr);
}

// --- the MTU -----------------------------------------------------------------

// RFC 4861 sec 6.3.4: "hosts SHOULD copy the option's value into LinkMTU so long as the value is
// greater than or equal to the minimum link MTU [IPv6] and does not exceed the maximum LinkMTU value
// specified in the link-type-specific document". The floor is RFC 8200 sec 5's 1280 octets.
void test_set_mtu_takes_a_value_between_the_ipv6_minimum_and_the_link_mtu(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);

    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->if_args.mtu = (uint16_t)IDEMIP_IPV6_MIN_MTU;
    Netif.set_mtu(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    get(work_a, 0u);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_IPV6_MIN_MTU, IDEMIP_NETIF_IO(work_a)->mtu6);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_NETIF_IO(work_a)->mtu);

    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->if_args.mtu = 1500u;
    Netif.set_mtu(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
}

// One octet under the RFC 8200 sec 5 minimum, and one octet over the link MTU bind took, are both
// outside the RFC 4861 sec 6.3.4 condition.
void test_set_mtu_refuses_a_value_outside_the_rfc_4861_condition(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);

    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->if_args.mtu = (uint16_t)(IDEMIP_IPV6_MIN_MTU - 1u);
    Netif.set_mtu(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->if_args.mtu = 1501u;
    Netif.set_mtu(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    get(work_a, 0u);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_NETIF_IO(work_a)->mtu6);
}

// --- the flags and the offload mask ------------------------------------------

// The raised bits go up, then the cleared bits come down, so a bit named in both ends down.
void test_set_flags_raises_then_lowers(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);

    flags(work_a, 0u, (uint16_t)(IDEMIP_NETIF_FLAG_UP | IDEMIP_NETIF_FLAG_BROADCAST | IDEMIP_NETIF_FLAG_ETHARP), 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    get(work_a, 0u);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)(IDEMIP_NETIF_FLAG_UP | IDEMIP_NETIF_FLAG_BROADCAST | IDEMIP_NETIF_FLAG_ETHARP),
                            IDEMIP_NETIF_IO(work_a)->flags);

    flags(work_a, 0u, (uint16_t)IDEMIP_NETIF_FLAG_MULTICAST, (uint16_t)IDEMIP_NETIF_FLAG_BROADCAST);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    get(work_a, 0u);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)(IDEMIP_NETIF_FLAG_UP | IDEMIP_NETIF_FLAG_ETHARP | IDEMIP_NETIF_FLAG_MULTICAST),
                            IDEMIP_NETIF_IO(work_a)->flags);

    // Named in both: raised first, lowered after, so it ends down.
    flags(work_a, 0u, (uint16_t)IDEMIP_NETIF_FLAG_BROADCAST, (uint16_t)IDEMIP_NETIF_FLAG_BROADCAST);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    get(work_a, 0u);
    TEST_ASSERT_EQUAL_HEX16(0u, (uint16_t)(IDEMIP_NETIF_IO(work_a)->flags & (uint16_t)IDEMIP_NETIF_FLAG_BROADCAST));
}

// A header whose bit is set is left to the MAC, so the mask is read back exactly as it was written.
void test_set_offload_round_trips(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->if_args.chksum =
        (uint16_t)(IDEMIP_NETIF_CHKSUM_IP4 | IDEMIP_NETIF_CHKSUM_TCP4 | IDEMIP_NETIF_CHKSUM_ICMP6);
    Netif.set_offload(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    get(work_a, 0u);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)(IDEMIP_NETIF_CHKSUM_IP4 | IDEMIP_NETIF_CHKSUM_TCP4 | IDEMIP_NETIF_CHKSUM_ICMP6),
                            IDEMIP_NETIF_IO(work_a)->chksum);
}

// --- find4 -------------------------------------------------------------------

// RFC 1122 sec 3.2.1.3: "the IP source address MUST be one of its own IP addresses". The interface
// holding it is the one reported.
void test_find4_reports_the_interface_holding_the_address(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    up(work_a, 1u, phy_b, g_mac_b, 1500u);
    addr4(work_a, 0u, V4_HOST, V4_MASK, V4_GW);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    addr4(work_a, 1u, 0xC0A80107u, V4_MASK, 0u); // 192.168.1.7
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    find4(work_a, V4_HOST);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->index);

    find4(work_a, 0xC0A80107u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_NETIF_IO(work_a)->index);
}

// No interface holds it, and no later tick puts it on one, so the miss is ERR rather than BUSY. A
// caller told BUSY would retry a lookup that can never answer differently.
void test_find4_reports_err_on_an_address_no_interface_holds(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_HOST, V4_MASK, V4_GW);
    find4(work_a, V4_ON_LINK);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// A zeroed entry holds address 0, so an interface would answer a search for 0.0.0.0 that is not its
// own. RFC 1122 sec 3.2.1.3 (a): "{ 0, 0 } This host on this network. MUST NOT be sent, except as a
// source address as part of an initialization procedure by which the host learns its own IP
// address." That is the address a host does not have yet, so neither an unbound interface, nor a
// bound one still waiting on a DHCP lease, nor a configured one holds it.
void test_find4_never_answers_for_the_unspecified_address(void)
{
    Netif.clear(work_a);
    find4(work_a, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status,
                                  "an unbound interface answered for 0.0.0.0");

    up(work_a, 1u, phy_b, g_mac_b, 1500u);
    find4(work_a, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status,
                                  "an interface bound but not yet addressed answered for 0.0.0.0");

    addr4(work_a, 1u, V4_HOST, V4_MASK, V4_GW);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    find4(work_a, V4_HOST);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_NETIF_IO(work_a)->index);
    find4(work_a, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status,
                                  "a configured interface answered for 0.0.0.0");
}

// The same zeroed entry carries mask 0, and RFC 1122 sec 3.3.1.1 (b) extracts with the mask, so
// every destination would match one that has none. Only sec 3.3.1.1's two special cases, "For a
// limited broadcast or a multicast address, simply pass the datagram to the link layer for the
// appropriate interface", stay on the link - which is what lets a host that has not learned its
// address reach a DHCP server.
void test_local4_puts_only_broadcast_and_multicast_on_an_unaddressed_link(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);

    local4(work_a, 0u, V4_ON_LINK);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_NETIF_IO(work_a)->local,
                              "an interface with no address claimed a host was on its link");
    local4(work_a, 0u, V4_OFF_LINK);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_NETIF_IO(work_a)->local,
                              "an interface with no address claimed a remote host was on its link");

    local4(work_a, 0u, V4_LIMITED_BROADCAST);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_NETIF_IO(work_a)->local, "the limited broadcast is always on link");
    local4(work_a, 0u, V4_MCAST_ALL_HOSTS);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_NETIF_IO(work_a)->local, "a multicast group is always on link");
}

// --- local4 ------------------------------------------------------------------

// RFC 1122 sec 3.3.1.1 (b): "If the IP destination address bits extracted by the address mask match
// the IP source address bits extracted by the same mask, then the destination is on the
// corresponding connected network". 10.0.0.99 and 10.0.0.5 match under 255.255.255.0; 10.0.1.99 does
// not. RFC 1122 prints no numeric example, so these are its notation filled in.
void test_local4_extracts_both_addresses_with_the_mask(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_HOST, V4_MASK, V4_GW);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    local4(work_a, 0u, V4_ON_LINK);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_NETIF_IO(work_a)->local);

    // (c) "the destination is accessible only through a gateway", and the decision itself is still
    // an answer, so the status is OK either way.
    local4(work_a, 0u, V4_OFF_LINK);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_NETIF_IO(work_a)->local);
}

// A wider mask puts the same pair on one network: 10.0.1.99 and 10.0.0.5 match under 255.255.0.0.
void test_local4_follows_the_mask_it_was_given(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_HOST, 0xFFFF0000u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    local4(work_a, 0u, V4_OFF_LINK);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_NETIF_IO(work_a)->local);
}

// RFC 1122 sec 3.3.1.1: "For a limited broadcast or a multicast address, simply pass the datagram to
// the link layer for the appropriate interface", so neither is routed through a gateway whatever the
// mask extracts.
void test_local4_passes_a_limited_broadcast_and_a_multicast_to_the_link(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    addr4(work_a, 0u, V4_HOST, V4_MASK, V4_GW);

    local4(work_a, 0u, V4_LIMITED_BROADCAST);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_NETIF_IO(work_a)->local);

    local4(work_a, 0u, V4_MCAST_ALL_HOSTS);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_NETIF_IO(work_a)->local);
}

// RFC 1122 sec 3.3.4 is the multihomed case: two interfaces, each with its own mask, each answering
// for its own connected network.
void test_local4_answers_per_interface_on_a_multihomed_host(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    up(work_a, 1u, phy_b, g_mac_b, 1500u);
    addr4(work_a, 0u, V4_HOST, V4_MASK, V4_GW);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    addr4(work_a, 1u, 0xC0A80107u, V4_MASK, 0u); // 192.168.1.7
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    local4(work_a, 0u, 0xC0A80109u); // 192.168.1.9
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_NETIF_IO(work_a)->local);

    local4(work_a, 1u, 0xC0A80109u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_NETIF_IO(work_a)->local);
}

// --- two borrows, at the record level ----------------------------------------

// Two stacks are two borrows. The same index in each holds its own interface, and a call on one
// reports its own record however the other one was driven in between.
void test_the_interface_records_of_two_borrows_are_independent(void)
{
    Netif.clear(work_a);
    Netif.clear(work_b);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    up(work_b, 0u, phy_b, g_mac_b, 1280u);
    addr4(work_a, 0u, V4_HOST, V4_MASK, V4_GW);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    addr4(work_b, 0u, 0xC0A80107u, V4_MASK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_b)->status);

    get(work_a, 0u);
    TEST_ASSERT_EQUAL_HEX32(V4_HOST, IDEMIP_NETIF_IO(work_a)->addr);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_NETIF_IO(work_a)->mtu);

    // Drive b, then read a again: identical both times.
    IDEMIP_NETIF_IO(work_b)->if_args.index = 0u;
    Netif.unbind(work_b);
    get(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(V4_HOST, IDEMIP_NETIF_IO(work_a)->addr);
    TEST_ASSERT_EQUAL_PTR(phy_a, IDEMIP_NETIF_IO(work_a)->phy);
}

#if IDEMIP_ENABLE_IPV6

// --- the IPv6 address list ---------------------------------------------------

// RFC 4291 sec 2.2's own example address, assigned and read back with the RFC 4862 sec 2 state and
// the RFC 4861 sec 4.6.2 lifetimes it was given.
void test_add_addr6_then_get_addr6_round_trips(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    add6(work_a, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_TENTATIVE, 604800u, 2592000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    uint8_t slot = IDEMIP_NETIF_IO(work_a)->slot;

    IDEMIP_NETIF_IO(work_a)->addr6_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->addr6_args.slot = slot;
    Netif.get_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(v6_rfc4291_a, IDEMIP_NETIF_IO(work_a)->addr6, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_INT(IDEMIP_NETIF_ADDR6_TENTATIVE, IDEMIP_NETIF_IO(work_a)->addr6_state);
    TEST_ASSERT_EQUAL_UINT32(604800u, IDEMIP_NETIF_IO(work_a)->preferred_s);
    TEST_ASSERT_EQUAL_UINT32(2592000u, IDEMIP_NETIF_IO(work_a)->valid_s);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->index);

    // The octets reported are the borrow's own copy, not the caller's.
    TEST_ASSERT_TRUE(IDEMIP_NETIF_IO(work_a)->addr6 != v6_rfc4291_a);
    TEST_ASSERT_TRUE(IDEMIP_NETIF_IO(work_a)->addr6 >= work_a);
    TEST_ASSERT_TRUE(IDEMIP_NETIF_IO(work_a)->addr6 < work_a + IDEMIP_NETIF_BORROW);
}

// RFC 4291 sec 2.1: "A single interface may also have multiple IPv6 addresses". The interface takes
// IDEMIP_IP6_ADDRESSES of them, and the one past that is BUSY, not ERR: RFC 4862 sec 5.5.4
// invalidates a slot when its valid lifetime expires, so a later tick frees one.
void test_add_addr6_fills_the_slots_then_reports_busy(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    for (uint8_t i = 0u; i < IDEMIP_IP6_ADDRESSES; i++)
    {
        add6(work_a, 0u, v6_fill[i], IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status, "a free slot was refused");
        TEST_ASSERT_EQUAL_UINT8(i, IDEMIP_NETIF_IO(work_a)->slot);
    }
    add6(work_a, 0u, v6_rfc4291_b, IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_NETIF_IO(work_a)->status);

    // The tick that invalidates one frees the slot the BUSY was about.
    tick(work_a, 60u * 1000u);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_IP6_ADDRESSES, IDEMIP_NETIF_IO(work_a)->aged);
    add6(work_a, 0u, v6_rfc4291_b, IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 4862 sec 5.5.3 e) resets the lifetimes of an address the interface already holds rather than
// taking a second slot for it.
void test_add_addr6_rewrites_an_address_the_interface_already_holds(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    add6(work_a, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_TENTATIVE, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->slot);

    add6(work_a, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_PREFERRED, 300u, 600u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->slot);
    TEST_ASSERT_EQUAL_INT(IDEMIP_NETIF_ADDR6_PREFERRED, IDEMIP_NETIF_IO(work_a)->addr6_state);
    TEST_ASSERT_EQUAL_UINT32(300u, IDEMIP_NETIF_IO(work_a)->preferred_s);
    TEST_ASSERT_EQUAL_UINT32(600u, IDEMIP_NETIF_IO(work_a)->valid_s);

    // Slot 1 is still free, so the rewrite took no second slot.
    IDEMIP_NETIF_IO(work_a)->addr6_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->addr6_args.slot = 1u;
    Netif.get_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 4291 sec 2.5.2, of 0:0:0:0:0:0:0:0: "It must never be assigned to any node."
void test_add_addr6_refuses_the_unspecified_address(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    add6(work_a, 0u, v6_unspecified, IDEMIP_NETIF_ADDR6_TENTATIVE, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 4291 sec 2.7: "binary 11111111 at the start of the address identifies the address as being a
// multicast address." The slots carry the RFC 4862 sec 2 states, which sec 5.4 reaches through
// Duplicate Address Detection, "performed on all unicast addresses", so a group address has no state
// here to hold.
void test_add_addr6_refuses_a_multicast_address(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    add6(work_a, 0u, v6_multicast, IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 4291 sec 2.5.3, of 0:0:0:0:0:0:0:1: "It must not be assigned to any physical interface. ... may
// be thought of as the Link-Local unicast address of a virtual interface (typically called the
// 'loopback interface')".
void test_add_addr6_refuses_the_loopback_address_off_a_loopback_interface(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    add6(work_a, 0u, v6_loopback, IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    flags(work_a, 0u, (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    add6(work_a, 0u, v6_loopback, IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
}

// An interface with no link is not an interface RFC 4291 sec 2.1 assigns an address to.
void test_add_addr6_refuses_an_unbound_interface(void)
{
    Netif.clear(work_a);
    add6(work_a, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_TENTATIVE, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 4862 sec 2, an invalid address "is not assigned to any interface", which is what the slot
// holds after the remove.
void test_remove_addr6_frees_the_slot(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    add6(work_a, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = v6_rfc4291_a;
    Netif.remove_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->slot);

    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_INVALID, state_at(work_a, 0u, 0u));

    // Gone, and no tick brings it back, so a second remove is ERR.
    IDEMIP_NETIF_IO(work_a)->addr6_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = v6_rfc4291_a;
    Netif.remove_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 4862 sec 5.4.3 matches a Target Address against the interface's own addresses. The search runs
// over every interface, so it reports which one as well as which slot.
void test_find_addr6_reports_the_interface_and_the_slot(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    up(work_a, 1u, phy_b, g_mac_b, 1500u);
    add6(work_a, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    add6(work_a, 1u, v6_fill[0], IDEMIP_NETIF_ADDR6_TENTATIVE, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    add6(work_a, 1u, v6_rfc4291_b, IDEMIP_NETIF_ADDR6_DEPRECATED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = v6_rfc4291_b;
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_NETIF_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_NETIF_IO(work_a)->slot);
    TEST_ASSERT_EQUAL_INT(IDEMIP_NETIF_ADDR6_DEPRECATED, IDEMIP_NETIF_IO(work_a)->addr6_state);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(v6_rfc4291_b, IDEMIP_NETIF_IO(work_a)->addr6, IDEMIP_IP6_ADDR_LEN);

    // No interface holds it, and no retry changes that.
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = v6_fill[3];
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_NETIF_IO(work_a)->addr6);
}

// A free slot holds RFC 4862 sec 2's invalid address, which carries neither a state nor a lifetime.
void test_get_addr6_refuses_a_free_slot(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    IDEMIP_NETIF_IO(work_a)->addr6_args.index = 0u;
    IDEMIP_NETIF_IO(work_a)->addr6_args.slot = 0u;
    Netif.get_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_NETIF_IO(work_a)->addr6);
}

// --- the lifetime sweep ------------------------------------------------------

// RFC 4862 sec 5.5.4: "A preferred address becomes deprecated when its preferred lifetime expires."
// The lifetime is seconds (RFC 4861 sec 4.6.2) and the sweep runs on milliseconds, so 30 seconds is
// reached at 30000 ms after the address was taken.
void test_tick_deprecates_a_preferred_address_when_its_preferred_lifetime_expires(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    tick(work_a, 1000u);
    add6(work_a, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    // One millisecond short of the preferred lifetime: still preferred, nothing moved.
    tick(work_a, 1000u + (30u * 1000u) - 1u);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->aged);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_PREFERRED, state_at(work_a, 0u, 0u));

    tick(work_a, 1000u + (30u * 1000u));
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_NETIF_IO(work_a)->aged);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_DEPRECATED, state_at(work_a, 0u, 0u));

    // Deprecated is not preferred, so the same sweep does not move it again.
    tick(work_a, 1000u + (40u * 1000u));
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->aged);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_DEPRECATED, state_at(work_a, 0u, 0u));
}

// RFC 4862 sec 5.5.4: "An address (and its association with an interface) becomes invalid when its
// valid lifetime expires." The slot returns to the free state, so the address is gone from the
// interface.
void test_tick_invalidates_an_address_when_its_valid_lifetime_expires(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    tick(work_a, 0u);
    add6(work_a, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    tick(work_a, 60u * 1000u);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_INVALID, state_at(work_a, 0u, 0u));

    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = v6_rfc4291_a;
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);
}

// RFC 4862 sec 5.4: a tentative address "is not considered assigned to an interface in the usual
// sense", and its valid lifetime still runs, so the sweep retires it as well.
void test_tick_invalidates_a_tentative_address_whose_valid_lifetime_expired(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    tick(work_a, 0u);
    add6(work_a, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_TENTATIVE, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    // The preferred lifetime does not deprecate an address the RFC does not call preferred.
    tick(work_a, 30u * 1000u);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->aged);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_TENTATIVE, state_at(work_a, 0u, 0u));

    tick(work_a, 60u * 1000u);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_NETIF_IO(work_a)->aged);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_INVALID, state_at(work_a, 0u, 0u));
}

// RFC 4861 sec 4.6.2, of both lifetimes: "A value of all one bits (0xffffffff) represents infinity."
// RFC 4862 sec 5.4 adds that "A link-local address has an infinite preferred and valid lifetime".
void test_tick_leaves_an_infinite_lifetime_where_it_is(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    tick(work_a, 0u);
    add6(work_a, 0u, v6_fill[0], IDEMIP_NETIF_ADDR6_PREFERRED, IDEMIP_NETIF_LIFETIME_INFINITE,
         IDEMIP_NETIF_LIFETIME_INFINITE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    tick(work_a, 0x7FFFFFFFu);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_NETIF_IO(work_a)->aged);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_PREFERRED, state_at(work_a, 0u, 0u));
}

// The sweep is the whole table, so it counts every address it moved, across interfaces.
void test_tick_counts_every_address_it_moved(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    up(work_a, 1u, phy_b, g_mac_b, 1500u);
    tick(work_a, 0u);
    add6(work_a, 0u, v6_fill[0], IDEMIP_NETIF_ADDR6_PREFERRED, 10u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    add6(work_a, 0u, v6_fill[1], IDEMIP_NETIF_ADDR6_PREFERRED, 10u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    add6(work_a, 1u, v6_fill[2], IDEMIP_NETIF_ADDR6_PREFERRED, 10u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    add6(work_a, 1u, v6_fill[3], IDEMIP_NETIF_ADDR6_PREFERRED, IDEMIP_NETIF_LIFETIME_INFINITE,
         IDEMIP_NETIF_LIFETIME_INFINITE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    tick(work_a, 10u * 1000u);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_NETIF_IO(work_a)->aged);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_DEPRECATED, state_at(work_a, 0u, 0u));
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_DEPRECATED, state_at(work_a, 0u, 1u));
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_DEPRECATED, state_at(work_a, 1u, 0u));
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_NETIF_ADDR6_PREFERRED, state_at(work_a, 1u, 1u));
}

// Unbinding an interface drops every address on it, RFC 4862 sec 2's invalid address being "not
// assigned to any interface".
void test_unbind_drops_every_address_on_the_interface(void)
{
    Netif.clear(work_a);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    up(work_a, 1u, phy_b, g_mac_b, 1500u);
    add6(work_a, 0u, v6_fill[0], IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    add6(work_a, 1u, v6_fill[1], IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->if_args.index = 0u;
    Netif.unbind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);

    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = v6_fill[0];
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_NETIF_IO(work_a)->status);

    // The other interface's address is untouched.
    IDEMIP_NETIF_IO(work_a)->addr6_args.addr = v6_fill[1];
    Netif.find_addr6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_NETIF_IO(work_a)->index);
}

// Two borrows hold two address tables. The same address in each is two different slots' octets, and
// a sweep on one moves nothing in the other.
void test_the_addr6_tables_of_two_borrows_are_independent(void)
{
    Netif.clear(work_a);
    Netif.clear(work_b);
    up(work_a, 0u, phy_a, g_mac_a, 1500u);
    up(work_b, 0u, phy_b, g_mac_b, 1500u);
    tick(work_a, 0u);
    tick(work_b, 0u);
    add6(work_a, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_PREFERRED, 30u, 60u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_a)->status);
    add6(work_b, 0u, v6_rfc4291_a, IDEMIP_NETIF_ADDR6_PREFERRED, IDEMIP_NETIF_LIFETIME_INFINITE,
         IDEMIP_NETIF_LIFETIME_INFINITE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_b)->status);

    tick(work_a, 60u * 1000u);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_NETIF_IO(work_a)->aged);

    IDEMIP_NETIF_IO(work_b)->addr6_args.addr = v6_rfc4291_a;
    Netif.find_addr6(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(work_b)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_NETIF_ADDR6_PREFERRED, IDEMIP_NETIF_IO(work_b)->addr6_state);
}

#endif // IDEMIP_ENABLE_IPV6
