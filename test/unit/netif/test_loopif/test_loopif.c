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

#include "idemIP/netif/loopif.h"

#include <string.h>
#include <unity.h>

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
// it fit, so it is ERR and not BUSY.
void test_output_refuses_a_frame_no_region_can_hold(void)
{
    Loopif.clear(work_a);
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

// A frame longer than the MTU cannot be looped, and neither can a zero MTU be bound.
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
