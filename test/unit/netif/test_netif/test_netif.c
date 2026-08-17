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

#include "idemIP/netif/netif.h"

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
