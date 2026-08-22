// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for loopif, shaped on test/unit/ethernet/test_phy. Every case here tests the
// CONTRACT and stays valid however the logic behind it is written:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_LOOPIF_BORROW is intact after every case
//   5. the published offsets are ordered and do not overlap
//   6. clear zeroes the frame regions, and a borrow it has not run on is refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/netif/loopif.h"

#include <string.h>
#include <unity.h>
#include "src/common_defines.h"
#include "src/ethernet/ethernet_defines.h"
#include "src/ip/ipv6_defines.h"

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_LOOPIF_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_LOOPIF_BORROW + 16];

// A frame to loop. RFC 1122 sec 3.2.1.3 case (g) keeps it inside the host, so nothing about its
// contents matters here beyond its length.
static uint8_t g_frame[64];

// RFC 1122 sec 3.2.1.3 case (g), "{ 127, <any> }".
#define LO4 0x7F000001u

#if IDEMIP_ENABLE_IPV6
// RFC 4291 sec 2.5.3, "The unicast address 0:0:0:0:0:0:0:1 is called the loopback address."
static const uint8_t g_lo6[IDEMIP_IP6_ADDR_LEN] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_other6[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
#endif

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_LOOPIF_BORROW, CANARY, cap - IDEMIP_LOOPIF_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_LOOPIF_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_LOOPIF_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_frame, 0xA5, sizeof g_frame);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// Every entry, so a case that walks the whole namespace cannot miss one.
static void call_every_entry(uint8_t *w)
{
    Loopif.clear(w);
    Loopif.bind(w);
    Loopif.output(w);
    Loopif.claim(w);
    Loopif.release(w);
    Loopif.owns4(w);
#if IDEMIP_ENABLE_IPV6
    Loopif.owns6(w);
#endif
}

static void set_bind_args(uint8_t *w)
{
    IDEMIP_LOOPIF_IO(w)->bind_args.addr4 = LO4;
    IDEMIP_LOOPIF_IO(w)->bind_args.mtu = 1500u;
    IDEMIP_LOOPIF_IO(w)->bind_args.index = 0u;
#if IDEMIP_ENABLE_IPV6
    IDEMIP_LOOPIF_IO(w)->bind_args.addr6 = g_lo6;
#endif
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the interface, and the operand block is in it, so two loopback interfaces share no
// byte at all. This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    Loopif.clear(work_a);
    Loopif.clear(work_b);

    IDEMIP_LOOPIF_IO(work_a)->bind_args.addr4 = LO4;
    IDEMIP_LOOPIF_IO(work_a)->bind_args.mtu = 1500u;
    IDEMIP_LOOPIF_IO(work_b)->bind_args.addr4 = 0x7F0000FFu;
    IDEMIP_LOOPIF_IO(work_b)->bind_args.mtu = 1280u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_HEX32(LO4, IDEMIP_LOOPIF_IO(work_a)->bind_args.addr4);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_LOOPIF_IO(work_a)->bind_args.mtu);
    TEST_ASSERT_EQUAL_HEX32(0x7F0000FFu, IDEMIP_LOOPIF_IO(work_b)->bind_args.addr4);
    TEST_ASSERT_EQUAL_UINT16(1280u, IDEMIP_LOOPIF_IO(work_b)->bind_args.mtu);

    // And running every entry on b leaves a's operands where a left them.
    call_every_entry(work_b);
    TEST_ASSERT_EQUAL_HEX32(LO4, IDEMIP_LOOPIF_IO(work_a)->bind_args.addr4);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_LOOPIF_IO(work_a)->bind_args.mtu);
}

// The two operand blocks are at the same offset in different borrows, so they are different bytes.
void test_the_two_operand_blocks_are_different_bytes(void)
{
    TEST_ASSERT_TRUE(IDEMIP_LOOPIF_IO(work_a) != IDEMIP_LOOPIF_IO(work_b));
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_LOOPIF_OFF_IO, IDEMIP_LOOPIF_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_LOOPIF_OFF_IO, IDEMIP_LOOPIF_IO(work_b));
}

// An entry writing its own borrow never reaches the next one. The canary is checked in tearDown, so
// this case only has to do the writing.
void test_no_entry_writes_past_the_borrow(void)
{
    Loopif.clear(work_a);
    set_bind_args(work_a);
    IDEMIP_LOOPIF_IO(work_a)->output_args.frame = g_frame;
    IDEMIP_LOOPIF_IO(work_a)->output_args.len = sizeof g_frame;
    IDEMIP_LOOPIF_IO(work_a)->match_args.addr4 = LO4;
#if IDEMIP_ENABLE_IPV6
    IDEMIP_LOOPIF_IO(work_a)->match_args.addr6 = g_lo6;
#endif
    call_every_entry(work_a);
    TEST_PASS();
}

// --- the map -----------------------------------------------------------------

// The published offsets are in order, each region ends where the next begins, and the last one ends
// inside IDEMIP_LOOPIF_BORROW.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_LOOPIF_OFF_IO);
    TEST_ASSERT_TRUE(IDEMIP_LOOPIF_OFF_IO + sizeof(LoopifIo) <= (size_t)IDEMIP_LOOPIF_OFF_CTX);
    TEST_ASSERT_TRUE((size_t)IDEMIP_LOOPIF_OFF_CTX < (size_t)IDEMIP_LOOPIF_OFF_FRAMES);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_LOOPIF_OFF_FRAMES + (IDEMIP_LOOPIF_FRAMES << IDEMIP_LOOPIF_FRAME_SHIFT),
                             (size_t)IDEMIP_LOOPIF_OFF_END);
    TEST_ASSERT_TRUE((size_t)IDEMIP_LOOPIF_OFF_END <= (size_t)IDEMIP_LOOPIF_BORROW);
}

// Region i sits at i << IDEMIP_LOOPIF_FRAME_SHIFT from the first, so the run has to start aligned.
void test_the_frame_regions_start_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_LOOPIF_OFF_FRAMES & (IDEMIP_ALIGN - 1u));
}

// A looped frame is held in the borrow, so a region carries a whole one (RFC 894's maximum).
void test_a_frame_region_holds_a_whole_frame(void)
{
    TEST_ASSERT_TRUE((1u << IDEMIP_LOOPIF_FRAME_SHIFT) >= IDEMIP_ETH_FRAME_MAX);
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Loopif.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
}

// Every frame region is zero after clear, whatever was in it before.
void test_clear_zeroes_the_frame_regions(void)
{
    memset(work_a, 0xFF, IDEMIP_LOOPIF_BORROW);
    Loopif.clear(work_a);
    for (size_t i = (size_t)IDEMIP_LOOPIF_OFF_FRAMES; i < (size_t)IDEMIP_LOOPIF_OFF_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[i], "clear left a frame byte set");
    }
}

// clear is the caller's, so it does not touch the operands the caller put in the borrow.
void test_clear_leaves_the_operands_alone(void)
{
    IDEMIP_LOOPIF_IO(work_a)->output_args.frame = g_frame;
    IDEMIP_LOOPIF_IO(work_a)->output_args.len = 42u;
    Loopif.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_frame, IDEMIP_LOOPIF_IO(work_a)->output_args.frame);
    TEST_ASSERT_EQUAL_size_t(42u, IDEMIP_LOOPIF_IO(work_a)->output_args.len);
}

// Clearing one borrow does not clear the other.
void test_clear_reaches_one_borrow_only(void)
{
    memset(work_b, 0xFF, IDEMIP_LOOPIF_BORROW);
    Loopif.clear(work_a);
    for (size_t i = (size_t)IDEMIP_LOOPIF_OFF_FRAMES; i < (size_t)IDEMIP_LOOPIF_OFF_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xFFu, work_b[i], "clear on one borrow reached another");
    }
}

// --- what is refused ---------------------------------------------------------

// Bytes clear has not run on are not a queue, so every entry refuses them rather than reading a
// frame length out of whatever was there.
void test_an_uncleared_borrow_is_refused(void)
{
    memset(work_a, 0xFF, IDEMIP_LOOPIF_BORROW);
    set_bind_args(work_a);
    Loopif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);

    memset(work_a, 0xFF, IDEMIP_LOOPIF_BORROW);
    IDEMIP_LOOPIF_IO(work_a)->output_args.frame = g_frame;
    IDEMIP_LOOPIF_IO(work_a)->output_args.len = sizeof g_frame;
    Loopif.output(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);

    memset(work_a, 0xFF, IDEMIP_LOOPIF_BORROW);
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);

    memset(work_a, 0xFF, IDEMIP_LOOPIF_BORROW);
    Loopif.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);

    memset(work_a, 0xFF, IDEMIP_LOOPIF_BORROW);
    IDEMIP_LOOPIF_IO(work_a)->match_args.addr4 = LO4;
    Loopif.owns4(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);
}

// A frame no Ethernet II frame can carry (RFC 894) will not fit a region either, and no retry makes
// it fit, so it is ERR and not BUSY. Bound at the full IDEMIP_ETH_MAX_PAYLOAD, so what refuses this
// frame is its length and not a narrower MTU.
void test_output_refuses_a_frame_no_region_can_hold(void)
{
    Loopif.clear(work_a);
    set_bind_args(work_a);
    Loopif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    IDEMIP_LOOPIF_IO(work_a)->output_args.frame = g_frame;
    IDEMIP_LOOPIF_IO(work_a)->output_args.len = (size_t)IDEMIP_ETH_FRAME_MAX + 1u;
    Loopif.output(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);
}

void test_output_refuses_a_null_frame_and_a_zero_length(void)
{
    Loopif.clear(work_a);
    IDEMIP_LOOPIF_IO(work_a)->output_args.frame = NULL;
    IDEMIP_LOOPIF_IO(work_a)->output_args.len = 16u;
    Loopif.output(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);

    IDEMIP_LOOPIF_IO(work_a)->output_args.frame = g_frame;
    IDEMIP_LOOPIF_IO(work_a)->output_args.len = 0u;
    Loopif.output(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);
}

// An MTU no Ethernet II link can carry, and one that carries nothing at all, are both refused at
// bind. What the accepted figure then bounds is
// test_output_refuses_a_frame_the_bound_mtu_cannot_carry, below.
void test_bind_refuses_an_unusable_mtu(void)
{
    Loopif.clear(work_a);
    set_bind_args(work_a);
    IDEMIP_LOOPIF_IO(work_a)->bind_args.mtu = 0u;
    Loopif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);

    IDEMIP_LOOPIF_IO(work_a)->bind_args.mtu = (uint16_t)(IDEMIP_ETH_MAX_PAYLOAD + 1u);
    Loopif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);
}

// The loopback interface occupies one record in the netif table, so an index past that table is
// refused.
void test_bind_refuses_an_index_past_the_netif_table(void)
{
    Loopif.clear(work_a);
    set_bind_args(work_a);
    IDEMIP_LOOPIF_IO(work_a)->bind_args.index = (uint8_t)IDEMIP_NETIF_COUNT;
    Loopif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);
}

// A claim on a queue nothing has been put in reports no frame, whichever way it reports the state.
void test_a_claim_that_found_nothing_reports_no_frame(void)
{
    Loopif.clear(work_a);
    Loopif.claim(work_a);
    TEST_ASSERT_NULL(IDEMIP_LOOPIF_IO(work_a)->frame);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_LOOPIF_IO(work_a)->len);
}

#if IDEMIP_ENABLE_IPV6

void test_owns6_refuses_a_null_address(void)
{
    Loopif.clear(work_a);
    IDEMIP_LOOPIF_IO(work_a)->match_args.addr6 = NULL;
    Loopif.owns6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);
}

void test_bind_refuses_a_missing_ipv6_address(void)
{
    Loopif.clear(work_a);
    set_bind_args(work_a);
    IDEMIP_LOOPIF_IO(work_a)->bind_args.addr6 = NULL;
    Loopif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);
}

// The two operand blocks are the two borrows' own, so the addresses named in them do not mix.
void test_match_operands_on_two_borrows_are_independent(void)
{
    Loopif.clear(work_a);
    Loopif.clear(work_b);
    IDEMIP_LOOPIF_IO(work_a)->match_args.addr6 = g_lo6;
    IDEMIP_LOOPIF_IO(work_b)->match_args.addr6 = g_other6;
    Loopif.owns6(work_b);
    TEST_ASSERT_EQUAL_PTR(g_lo6, IDEMIP_LOOPIF_IO(work_a)->match_args.addr6);
    TEST_ASSERT_EQUAL_PTR(g_other6, IDEMIP_LOOPIF_IO(work_b)->match_args.addr6);
}

#endif // IDEMIP_ENABLE_IPV6

// --- bind: the two address forms ---------------------------------------------

static void bind_ok(uint8_t *w)
{
    Loopif.clear(w);
    set_bind_args(w);
    Loopif.bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(w)->status);
}

void test_bind_accepts_the_loopback_addresses(void)
{
    bind_ok(work_a);
}

// RFC 1122 sec 3.2.1.3 case (g) is "{ 127, <any> }", so the host part is unconstrained: the network
// number alone decides. RFC 1122 prints no address vectors, so these walk the form the text states,
// including the two host parts the same section excludes everywhere else ("IP addresses are not
// permitted to have the value 0 or -1 ... except in the special cases listed above", and (g) is one
// of those cases).
void test_bind_accepts_any_host_part_on_network_127(void)
{
    static const uint32_t forms[] = {0x7F000000u, 0x7F000001u, 0x7F0000FFu, 0x7F010203u, 0x7FFFFFFFu};
    for (size_t i = 0; i < sizeof forms / sizeof forms[0]; i++)
    {
        Loopif.clear(work_a);
        set_bind_args(work_a);
        IDEMIP_LOOPIF_IO(work_a)->bind_args.addr4 = forms[i];
        Loopif.bind(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status,
                                      "a { 127, <any> } address was refused");
    }
}

// An address off network 127 is not the internal host loopback address, and the same operands
// retried are the same address, so it is ERR and not BUSY. 126.255.255.255 and 128.0.0.1 sit either
// side of the network number.
void test_bind_refuses_an_address_off_network_127(void)
{
    static const uint32_t forms[] = {0x00000000u, 0x0A000001u, 0x7EFFFFFFu, 0x80000001u, 0xC0A80001u, 0xFFFFFFFFu};
    for (size_t i = 0; i < sizeof forms / sizeof forms[0]; i++)
    {
        Loopif.clear(work_a);
        set_bind_args(work_a);
        IDEMIP_LOOPIF_IO(work_a)->bind_args.addr4 = forms[i];
        Loopif.bind(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status,
                                      "an address outside network 127 was bound");
    }
}

#if IDEMIP_ENABLE_IPV6

// RFC 4291 sec 2.5.3 names exactly one address, 0:0:0:0:0:0:0:1. The unspecified address of sec
// 2.5.2 and an address carrying the 1 one octet early are both refused.
void test_bind_refuses_an_ipv6_address_that_is_not_the_loopback(void)
{
    static const uint8_t forms[][IDEMIP_IP6_ADDR_LEN] = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},          // sec 2.5.2, the unspecified address
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0},       // the 1 one octet early
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02},       // ::2
        {0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},    // 100::1
        {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}, // fe80::1
    };
    for (size_t i = 0; i < sizeof forms / sizeof forms[0]; i++)
    {
        Loopif.clear(work_a);
        set_bind_args(work_a);
        IDEMIP_LOOPIF_IO(work_a)->bind_args.addr6 = forms[i];
        Loopif.bind(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status,
                                      "an address that is not ::1 was bound");
    }
}

#endif // IDEMIP_ENABLE_IPV6

// --- owns4 and owns6 ---------------------------------------------------------

// RFC 1122 sec 3.2.1.3 case (g), "{ 127, <any> } Internal host loopback address". The network
// number is the whole test, so 127.0.0.1 and 127.255.255.255 answer alike.
void test_owns4_answers_for_every_host_part_on_network_127(void)
{
    static const uint32_t forms[] = {0x7F000000u, 0x7F000001u, 0x7F0000FFu, 0x7F010203u, 0x7FFFFFFFu};
    Loopif.clear(work_a);
    for (size_t i = 0; i < sizeof forms / sizeof forms[0]; i++)
    {
        IDEMIP_LOOPIF_IO(work_a)->match_args.addr4 = forms[i];
        Loopif.owns4(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status, "owns4 did not finish");
        TEST_ASSERT_TRUE_MESSAGE(IDEMIP_LOOPIF_IO(work_a)->owned, "a { 127, <any> } address was not owned");
    }
}

// The two addresses either side of network 127 are not loopback, and neither is any other network.
// The call still finishes, so the status is OK and the answer is in owned.
void test_owns4_disowns_addresses_off_network_127(void)
{
    static const uint32_t forms[] = {0x00000000u, 0x0A000001u, 0x7EFFFFFFu, 0x80000000u, 0xC0A80001u, 0xFFFFFFFFu};
    Loopif.clear(work_a);
    for (size_t i = 0; i < sizeof forms / sizeof forms[0]; i++)
    {
        IDEMIP_LOOPIF_IO(work_a)->match_args.addr4 = forms[i];
        Loopif.owns4(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status, "owns4 did not finish");
        TEST_ASSERT_FALSE_MESSAGE(IDEMIP_LOOPIF_IO(work_a)->owned, "an address outside network 127 was owned");
    }
}

// The bound address does not narrow the test: case (g) makes the whole network the host's own, so a
// borrow bound to 127.0.0.1 still owns 127.9.9.9.
void test_owns4_is_not_narrowed_by_the_bound_address(void)
{
    bind_ok(work_a);
    IDEMIP_LOOPIF_IO(work_a)->match_args.addr4 = 0x7F090909u;
    Loopif.owns4(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_LOOPIF_IO(work_a)->owned);
}

#if IDEMIP_ENABLE_IPV6

// RFC 4291 sec 2.5.3, "The unicast address 0:0:0:0:0:0:0:1 is called the loopback address."
void test_owns6_answers_for_the_one_loopback_address(void)
{
    Loopif.clear(work_a);
    IDEMIP_LOOPIF_IO(work_a)->match_args.addr6 = g_lo6;
    Loopif.owns6(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_LOOPIF_IO(work_a)->owned);
}

// Sec 2.5.3 names one address, so every other one is disowned: the unspecified address of sec
// 2.5.2, the 1 one octet early, ::2, and a link-local address.
void test_owns6_disowns_every_other_address(void)
{
    static const uint8_t forms[][IDEMIP_IP6_ADDR_LEN] = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02},
        {0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
        {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
    };
    Loopif.clear(work_a);
    for (size_t i = 0; i < sizeof forms / sizeof forms[0]; i++)
    {
        IDEMIP_LOOPIF_IO(work_a)->match_args.addr6 = forms[i];
        Loopif.owns6(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status, "owns6 did not finish");
        TEST_ASSERT_FALSE_MESSAGE(IDEMIP_LOOPIF_IO(work_a)->owned, "an address that is not ::1 was owned");
    }
}

// Every one of the 128 bits is walked: setting any single bit other than the last makes the address
// something other than ::1.
void test_owns6_disowns_an_address_one_bit_off(void)
{
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    Loopif.clear(work_a);
    for (size_t bit = 0; bit < (IDEMIP_IP6_ADDR_LEN * 8u); bit++)
    {
        memcpy(addr, g_lo6, sizeof addr);
        addr[bit >> 3] ^= (uint8_t)(0x80u >> (bit & 7u));
        IDEMIP_LOOPIF_IO(work_a)->match_args.addr6 = addr;
        Loopif.owns6(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status, "owns6 did not finish");
        TEST_ASSERT_FALSE_MESSAGE(IDEMIP_LOOPIF_IO(work_a)->owned, "an address one bit off ::1 was owned");
    }
}

#endif // IDEMIP_ENABLE_IPV6

// --- the queue ---------------------------------------------------------------

// A frame whose every octet names which frame it is, so the order they come back in is visible.
static void fill(uint8_t *buf, size_t len, uint8_t tag)
{
    for (size_t i = 0; i < len; i++)
    {
        buf[i] = (uint8_t)(tag + (uint8_t)i);
    }
}

static void output_ok(uint8_t *w, const uint8_t *frame, size_t len)
{
    IDEMIP_LOOPIF_IO(w)->output_args.frame = frame;
    IDEMIP_LOOPIF_IO(w)->output_args.len = len;
    Loopif.output(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(w)->status);
}

// RFC 1122 sec 3.2.1.3 case (g): the frame the host sent to itself comes back to this host's own
// input path, octet for octet.
void test_a_frame_written_comes_back_on_the_next_claim(void)
{
    uint8_t sent[64];
    fill(sent, sizeof sent, 0x10u);
    bind_ok(work_a);
    output_ok(work_a, sent, sizeof sent);

    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(sizeof sent, IDEMIP_LOOPIF_IO(work_a)->len);
    TEST_ASSERT_NOT_NULL(IDEMIP_LOOPIF_IO(work_a)->frame);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sent, IDEMIP_LOOPIF_IO(work_a)->frame, sizeof sent);

    Loopif.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
}

// The frame is handed back where it lies, which is a frame region of this borrow and nowhere else.
void test_the_frame_comes_back_inside_the_borrow(void)
{
    uint8_t sent[32];
    fill(sent, sizeof sent, 0x20u);
    bind_ok(work_a);
    output_ok(work_a, sent, sizeof sent);
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);

    const uint8_t *got = IDEMIP_LOOPIF_IO(work_a)->frame;
    TEST_ASSERT_TRUE(got >= work_a + IDEMIP_LOOPIF_OFF_FRAMES);
    TEST_ASSERT_TRUE(got + sizeof sent <= work_a + IDEMIP_LOOPIF_OFF_END);
    TEST_ASSERT_EQUAL_PTR(
        work_a + IDEMIP_LOOPIF_OFF_FRAMES + ((size_t)IDEMIP_LOOPIF_IO(work_a)->slot << IDEMIP_LOOPIF_FRAME_SHIFT), got);
}

// The caller's buffer is the caller's: output takes a copy, so overwriting the source after the call
// does not change what comes back.
void test_the_looped_frame_does_not_follow_the_callers_buffer(void)
{
    uint8_t sent[48];
    uint8_t expect[48];
    fill(sent, sizeof sent, 0x30u);
    memcpy(expect, sent, sizeof expect);

    bind_ok(work_a);
    output_ok(work_a, sent, sizeof sent);
    memset(sent, 0xEE, sizeof sent);

    // Nothing reads sent after the overwrite, so a compiler may drop the memset as a dead store, and
    // a dropped one leaves sent holding what it was written with: the case would then pass whether
    // output copied the frame or kept a pointer into it, which is the one thing it exists to tell
    // apart. Reading the overwrite back is what makes it observable, and what makes the case mean
    // anything.
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xEEu, sent[0], "the caller's buffer was not overwritten");
    TEST_ASSERT_EQUAL_UINT8(0xEEu, sent[sizeof sent - 1u]);

    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, IDEMIP_LOOPIF_IO(work_a)->frame, sizeof expect);
}

// The oldest waiting frame is the one claim reports, so the order out is the order in.
void test_frames_come_back_in_the_order_they_were_written(void)
{
    uint8_t sent[IDEMIP_LOOPIF_FRAMES][32];
    bind_ok(work_a);
    for (unsigned i = 0; i < IDEMIP_LOOPIF_FRAMES; i++)
    {
        fill(sent[i], sizeof sent[i], (uint8_t)(0x40u + (i << 4)));
        output_ok(work_a, sent[i], sizeof sent[i]);
    }
    for (unsigned i = 0; i < IDEMIP_LOOPIF_FRAMES; i++)
    {
        Loopif.claim(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(sent[i], IDEMIP_LOOPIF_IO(work_a)->frame, sizeof sent[i],
                                              "a frame came back out of order");
        Loopif.release(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    }
}

// Every region full is BUSY, not ERR: a claim and a release free one, so the retry succeeds. ERR
// here would abandon a healthy queue.
void test_every_region_full_is_busy_and_a_release_frees_one(void)
{
    uint8_t sent[16];
    fill(sent, sizeof sent, 0x50u);
    bind_ok(work_a);
    for (unsigned i = 0; i < IDEMIP_LOOPIF_FRAMES; i++)
    {
        output_ok(work_a, sent, sizeof sent);
        TEST_ASSERT_EQUAL_UINT8(i + 1u, IDEMIP_LOOPIF_IO(work_a)->held);
    }

    IDEMIP_LOOPIF_IO(work_a)->output_args.frame = sent;
    IDEMIP_LOOPIF_IO(work_a)->output_args.len = sizeof sent;
    Loopif.output(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_LOOPIF_FRAMES, IDEMIP_LOOPIF_IO(work_a)->held);

    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    Loopif.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);

    Loopif.output(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
}

// Nothing waiting is BUSY, not OK and not ERR: OK would claim a frame that is not there, ERR would
// call an empty queue broken. The caller comes back after the next output.
void test_nothing_waiting_is_busy_and_the_retry_succeeds(void)
{
    uint8_t sent[16];
    fill(sent, sizeof sent, 0x60u);
    bind_ok(work_a);

    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_LOOPIF_IO(work_a)->frame);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_LOOPIF_IO(work_a)->len);

    output_ok(work_a, sent, sizeof sent);
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
}

// A second claim would hand out a region release has not stepped past, and no retry changes that
// while the first claim is out, so it is ERR.
void test_a_second_claim_before_release_is_refused(void)
{
    uint8_t sent[16];
    fill(sent, sizeof sent, 0x70u);
    bind_ok(work_a);
    output_ok(work_a, sent, sizeof sent);
    output_ok(work_a, sent, sizeof sent);

    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_LOOPIF_IO(work_a)->frame);
}

// A release with nothing out would free a region twice, so it is ERR both before any claim and
// after the claim it belongs to.
void test_release_without_a_claim_is_refused(void)
{
    uint8_t sent[16];
    fill(sent, sizeof sent, 0x80u);
    bind_ok(work_a);

    Loopif.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);

    output_ok(work_a, sent, sizeof sent);
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    Loopif.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    Loopif.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status);
}

// head and tail wrap on IDEMIP_LOOPIF_FRAMES, so a run several times longer than the queue still
// hands every frame back intact.
void test_the_queue_wraps(void)
{
    uint8_t sent[24];
    bind_ok(work_a);
    for (unsigned round = 0; round < (IDEMIP_LOOPIF_FRAMES * 4u) + 1u; round++)
    {
        fill(sent, sizeof sent, (uint8_t)(0x90u + round));
        output_ok(work_a, sent, sizeof sent);
        Loopif.claim(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(sent, IDEMIP_LOOPIF_IO(work_a)->frame, sizeof sent,
                                              "a frame came back wrong after the queue wrapped");
        TEST_ASSERT_TRUE(IDEMIP_LOOPIF_IO(work_a)->slot < IDEMIP_LOOPIF_FRAMES);
        Loopif.release(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    }
}

// output copies the octets it was given and no more, so the region past the frame is as clear left
// it.
void test_output_writes_no_octet_past_the_frame(void)
{
    uint8_t sent[8];
    fill(sent, sizeof sent, 0xA0u);
    Loopif.clear(work_a);
    set_bind_args(work_a);
    Loopif.bind(work_a);
    output_ok(work_a, sent, sizeof sent);
    for (size_t i = (size_t)IDEMIP_LOOPIF_OFF_FRAMES + sizeof sent;
         i < (size_t)IDEMIP_LOOPIF_OFF_FRAMES + (1u << IDEMIP_LOOPIF_FRAME_SHIFT); i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[i], "output wrote past the frame it was given");
    }
}

// A region carries a whole Ethernet II frame (RFC 894's maximum), so the longest one round trips.
void test_the_longest_frame_round_trips(void)
{
    static uint8_t sent[IDEMIP_ETH_FRAME_MAX];
    fill(sent, sizeof sent, 0xB0u);
    bind_ok(work_a);
    output_ok(work_a, sent, sizeof sent);
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(sizeof sent, IDEMIP_LOOPIF_IO(work_a)->len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sent, IDEMIP_LOOPIF_IO(work_a)->frame, sizeof sent);
}

// The MTU bind takes is the octets of payload one looped frame may carry, so the frame it bounds is
// that many plus the RFC 894 header. bind validated the figure, stored it, and then no entry read
// it: a loopback bound at the RFC 8200 sec 5 minimum of 1280 looped a full 1514-octet frame without
// a word. The bound is checked here at the octet either side of it.
void test_output_refuses_a_frame_the_bound_mtu_cannot_carry(void)
{
    static uint8_t sent[IDEMIP_ETH_FRAME_MAX];
    fill(sent, sizeof sent, 0xD0u);

    Loopif.clear(work_a);
    set_bind_args(work_a);
    IDEMIP_LOOPIF_IO(work_a)->bind_args.mtu = (uint16_t)IDEMIP_IPV6_MIN_MTU;
    Loopif.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);

    // One past the MTU is ERR and not BUSY: no retry shortens that frame.
    IDEMIP_LOOPIF_IO(work_a)->output_args.frame = sent;
    IDEMIP_LOOPIF_IO(work_a)->output_args.len = (size_t)IDEMIP_IPV6_MIN_MTU + IDEMIP_ETH_HDR_LEN + 1u;
    Loopif.output(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status,
                                  "a frame past the bound MTU was looped");

    // A full MTU of payload behind its header is exactly what the link carries.
    output_ok(work_a, sent, (size_t)IDEMIP_IPV6_MIN_MTU + IDEMIP_ETH_HDR_LEN);
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_IPV6_MIN_MTU + IDEMIP_ETH_HDR_LEN, IDEMIP_LOOPIF_IO(work_a)->len);
}

// An interface no bind has run on has no address and no MTU, so there is nothing for a frame to be
// within. clear alone leaves the borrow usable, not the interface configured.
void test_output_before_a_bind_loops_nothing(void)
{
    uint8_t sent[64];
    fill(sent, sizeof sent, 0xE0u);
    Loopif.clear(work_a);
    IDEMIP_LOOPIF_IO(work_a)->output_args.frame = sent;
    IDEMIP_LOOPIF_IO(work_a)->output_args.len = sizeof sent;
    Loopif.output(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status,
                                  "a frame was looped on an interface with no MTU");
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_LOOPIF_IO(work_a)->status);
}

// The queue is in the borrow, so a frame written to one loopback interface is not waiting on the
// other. This is the storage model applied to held state.
void test_two_borrows_queue_independently(void)
{
    uint8_t sent[16];
    fill(sent, sizeof sent, 0xC0u);
    bind_ok(work_a);
    bind_ok(work_b);
    output_ok(work_a, sent, sizeof sent);

    Loopif.claim(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_LOOPIF_IO(work_b)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_LOOPIF_IO(work_b)->held);

    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_LOOPIF_IO(work_a)->held);

    // b has claimed nothing, so releasing b is refused even though a holds one.
    Loopif.release(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_b)->status);
    Loopif.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
}

// clear takes the queue back to empty, claim included, so a frame written before it is gone.
void test_clear_empties_the_queue(void)
{
    uint8_t sent[16];
    fill(sent, sizeof sent, 0xD0u);
    bind_ok(work_a);
    output_ok(work_a, sent, sizeof sent);
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);

    Loopif.clear(work_a);
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_LOOPIF_IO(work_a)->held);
}

// held is what is waiting, counted up by output and down by release, and it is reported on the busy
// paths too.
void test_held_counts_the_frames_waiting(void)
{
    uint8_t sent[16];
    fill(sent, sizeof sent, 0xE0u);
    bind_ok(work_a);
    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_LOOPIF_IO(work_a)->held);

    output_ok(work_a, sent, sizeof sent);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_LOOPIF_IO(work_a)->held);

    Loopif.claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_LOOPIF_IO(work_a)->held);

    Loopif.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_LOOPIF_IO(work_a)->held);
}

// An entry is a function of its borrow alone, so the same claim on the same bytes reports the same
// frame every time. This is the determinism the design is named for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    uint8_t sent_a[16];
    uint8_t sent_b[16];
    fill(sent_a, sizeof sent_a, 0xF0u);
    fill(sent_b, sizeof sent_b, 0x11u);
    bind_ok(work_a);
    bind_ok(work_b);
    output_ok(work_a, sent_a, sizeof sent_a);
    output_ok(work_b, sent_b, sizeof sent_b);

    // Interleave: a, then b, then a again. a's answer must be identical both times.
    Loopif.claim(work_a);
    const uint8_t *first = IDEMIP_LOOPIF_IO(work_a)->frame;
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_a)->status);
    Loopif.claim(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_LOOPIF_IO(work_b)->status);

    TEST_ASSERT_EQUAL_PTR(first, IDEMIP_LOOPIF_IO(work_a)->frame);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sent_a, IDEMIP_LOOPIF_IO(work_a)->frame, sizeof sent_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sent_b, IDEMIP_LOOPIF_IO(work_b)->frame, sizeof sent_b);

    // Each frame came out of its own borrow's regions, so the two queues are different bytes.
    TEST_ASSERT_TRUE(IDEMIP_LOOPIF_IO(work_a)->frame >= work_a + IDEMIP_LOOPIF_OFF_FRAMES);
    TEST_ASSERT_TRUE(IDEMIP_LOOPIF_IO(work_a)->frame < work_a + IDEMIP_LOOPIF_OFF_END);
    TEST_ASSERT_TRUE(IDEMIP_LOOPIF_IO(work_b)->frame >= work_b + IDEMIP_LOOPIF_OFF_FRAMES);
    TEST_ASSERT_TRUE(IDEMIP_LOOPIF_IO(work_b)->frame < work_b + IDEMIP_LOOPIF_OFF_END);
}

// --- the shape ---------------------------------------------------------------

// RFC 1122 sec 3.2.1.3 case (g) writes the loopback form as "{ 127, <any> }", so the mask selects
// the network number alone.
void test_the_published_loopback_network_is_127(void)
{
    TEST_ASSERT_EQUAL_HEX32(0x7F000000u, IDEMIP_LOOPIF_NET4);
    TEST_ASSERT_EQUAL_HEX32(0xFF000000u, IDEMIP_LOOPIF_NET4_MASK);
    TEST_ASSERT_EQUAL_HEX32(IDEMIP_LOOPIF_NET4, LO4 & IDEMIP_LOOPIF_NET4_MASK);
}

// The namespace holds only const function pointers, so it costs no RAM and nothing can swap an
// entry at runtime.
void test_every_entry_is_present(void)
{
    TEST_ASSERT_NOT_NULL(Loopif.clear);
    TEST_ASSERT_NOT_NULL(Loopif.bind);
    TEST_ASSERT_NOT_NULL(Loopif.output);
    TEST_ASSERT_NOT_NULL(Loopif.claim);
    TEST_ASSERT_NOT_NULL(Loopif.release);
    TEST_ASSERT_NOT_NULL(Loopif.owns4);
#if IDEMIP_ENABLE_IPV6
    TEST_ASSERT_NOT_NULL(Loopif.owns6);
#endif
}

// The match works over an address the caller holds, so a call naming none has nothing to compare
// against RFC 4291 sec 2.5.3's loopback address.
void test_a_match_that_names_no_address_is_refused(void)
{
    Loopif.clear(work_a);
    IDEMIP_LOOPIF_IO(work_a)->match_args.addr6 = NULL;
    Loopif.owns6(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status, "a match was made against no address");

    // And bytes clear has not run on are not an interface to match against either.
    memset(work_a, 0xFF, IDEMIP_LOOPIF_BORROW);
    IDEMIP_LOOPIF_IO(work_a)->match_args.addr6 = g_lo6;
    Loopif.owns6(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_LOOPIF_IO(work_a)->status, "owns6 read an uncleared borrow");
}
