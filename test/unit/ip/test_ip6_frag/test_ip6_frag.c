// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 8200 sec 4.5 prints two block diagrams of a packet and its fragments and no numeric example of
// either, so there is no octet vector here to replay. What the section states, and what this suite
// asserts instead, is:
//
//   "The Per-Fragment headers must consist of the IPv6 header plus any extension headers that must
//   be processed by nodes en route to the destination, that is, all headers up to and including the
//   Routing header if present, else the Hop-by-Hop Options header if present, else no extension
//   headers."
//   "(1) The Per-Fragment headers of the original packet, with the Payload Length of the original
//   IPv6 header changed to contain the length of this fragment packet only (excluding the length of
//   the IPv6 header itself), and the Next Header field of the last header of the Per-Fragment
//   headers changed to 44."
//   "(2) A Fragment header containing: The Next Header value that identifies the first header after
//   the Per-Fragment headers of the original packet. A Fragment Offset containing the offset of the
//   fragment, in 8-octet units... An M flag value of 0 if the fragment is the last ("rightmost")
//   one, else an M flag value of 1. The Identification value generated for the original packet."
//   "Each complete fragment, except possibly the last ("rightmost") one, is an integer multiple of 8
//   octets long."
//   "PL.orig = PL.first - FL.first - 8 + (8 * FO.last) + FL.last"
//   sec 5: "IPv6 requires that every link in the Internet have an MTU of 1280 octets or greater."
//
// Plus the four things every unit's suite checks: the borrow is the caller's, every entry refuses a
// null borrow, two borrows share not one byte, and an entry is a function of its borrow alone.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ip/ip6_frag.h"

#include <string.h>
#include <unity.h>

// --- the borrow, the caller's ------------------------------------------------

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_IP6_FRAG_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_IP6_FRAG_BORROW + 16];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP6_FRAG_BORROW, CANARY, cap - IDEMIP_IP6_FRAG_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP6_FRAG_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP6_FRAG_BORROW");
    }
}

// --- a packet to divide ------------------------------------------------------

#define PKT_MAX 8192u
#define OUT_MAX 4096u
#define FRAGS_MAX 64
#define IDENT 0xDEADBEEFu

static uint8_t g_pkt[PKT_MAX];
static uint16_t g_pkt_len;
static size_t g_build;    // where the next extension header goes
static uint8_t g_first_nh;

static uint8_t g_out[OUT_MAX];
static uint8_t g_frag[FRAGS_MAX][OUT_MAX];
static uint16_t g_frag_len[FRAGS_MAX];
static int g_frags;

static const uint8_t g_src[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_dst[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

static void pkt_start(uint8_t first_nh)
{
    memset(g_pkt, 0, sizeof g_pkt);
    g_build = IDEMIP_IPV6_HDR_LEN;
    g_first_nh = first_nh;
}

// One extension header carrying the common two octets: its own Next Header, then its Hdr Ext Len in
// 8-octet units "not including the first 8 octets" (RFC 8200 sec 4.3).
static void pkt_ext(uint8_t next_nh, uint8_t hdr_ext_len)
{
    g_pkt[g_build + IDEMIP_IP6_EXT_OFF_NEXT_HDR] = next_nh;
    g_pkt[g_build + IDEMIP_IP6_EXT_OFF_LEN] = hdr_ext_len;
    g_build += IDEMIP_IP6_EXT_BYTES(hdr_ext_len);
}

// A Fragment header, which sec 4.5 fixes at eight octets rather than sizing by a length field.
static void pkt_frag_hdr(uint8_t next_nh)
{
    idemip_ip6_frag_build(g_pkt + g_build, next_nh, 0u, IDEMIP_FALSE, IDENT);
    g_build += IDEMIP_IP6_FRAG_HDR_LEN;
}

static uint16_t pkt_finish(uint16_t data_len)
{
    for (uint16_t i = 0; i < data_len; i++)
    {
        g_pkt[g_build + i] = (uint8_t)(i & 0xFFu);
    }
    const uint16_t payload = (uint16_t)(g_build + data_len - IDEMIP_IPV6_HDR_LEN);
    IdemIpIp6BuildArgs a;
    memset(&a, 0, sizeof a);
    a.src = g_src;
    a.dst = g_dst;
    a.flow_label = 0x12345u;
    a.payload_len = payload;
    a.traffic_class = 0x20u;
    a.next_hdr = g_first_nh;
    a.hop_limit = 64u;
    idemip_ip6_build(g_pkt, &a);
    g_pkt_len = (uint16_t)(IDEMIP_IPV6_HDR_LEN + payload);
    return g_pkt_len;
}

// The commonest shape: no extension headers at all, the upper-layer header first.
static uint16_t make_plain(uint16_t data_len)
{
    pkt_start(IDEMIP_IP6_NH_UDP);
    return pkt_finish(data_len);
}

static void begin_ok(uint8_t *w, uint16_t mtu)
{
    IDEMIP_IP6_FRAG_IO(w)->begin_args.pkt = g_pkt;
    IDEMIP_IP6_FRAG_IO(w)->begin_args.len = g_pkt_len;
    IDEMIP_IP6_FRAG_IO(w)->begin_args.mtu = mtu;
    IDEMIP_IP6_FRAG_IO(w)->begin_args.ident = IDENT;
    Ip6Frag.begin(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_FRAG_IO(w)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_NONE, IDEMIP_IP6_FRAG_IO(w)->err);
}

static IdemIpIp6FragError begin_err(uint8_t *w, uint16_t mtu)
{
    IDEMIP_IP6_FRAG_IO(w)->begin_args.pkt = g_pkt;
    IDEMIP_IP6_FRAG_IO(w)->begin_args.len = g_pkt_len;
    IDEMIP_IP6_FRAG_IO(w)->begin_args.mtu = mtu;
    IDEMIP_IP6_FRAG_IO(w)->begin_args.ident = IDENT;
    Ip6Frag.begin(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FRAG_IO(w)->status);
    return IDEMIP_IP6_FRAG_IO(w)->err;
}

static void drain(uint8_t *w)
{
    g_frags = 0;
    for (;;)
    {
        IDEMIP_IP6_FRAG_IO(w)->next_args.out = g_out;
        IDEMIP_IP6_FRAG_IO(w)->next_args.cap = sizeof g_out;
        Ip6Frag.next(w);
        if (IDEMIP_IP6_FRAG_IO(w)->status != IDEMIP_OK)
        {
            break;
        }
        TEST_ASSERT_LESS_THAN_INT(FRAGS_MAX, g_frags);
        g_frag_len[g_frags] = IDEMIP_IP6_FRAG_IO(w)->len;
        memcpy(g_frag[g_frags], g_out, g_frag_len[g_frags]);
        g_frags++;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_DONE, IDEMIP_IP6_FRAG_IO(w)->err);
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_pkt, 0, sizeof g_pkt);
    memset(g_out, 0, sizeof g_out);
    g_pkt_len = 0;
    g_build = IDEMIP_IPV6_HDR_LEN;
    g_frags = 0;
    Ip6Frag.clear(work_a);
    Ip6Frag.clear(work_b);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- the borrow --------------------------------------------------------------

void test_every_entry_survives_a_null_borrow(void)
{
    Ip6Frag.clear(NULL);
    Ip6Frag.begin(NULL);
    Ip6Frag.next(NULL);
    TEST_PASS();
}

void test_an_uncleared_borrow_refuses_work(void)
{
    make_plain(64u);
    arm(work_a, sizeof work_a); // zeroed, so the mark clear leaves is absent
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.pkt = g_pkt;
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.len = g_pkt_len;
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.mtu = IDEMIP_IPV6_MIN_MTU;
    Ip6Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_STATE, IDEMIP_IP6_FRAG_IO(work_a)->err);
    Ip6Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_STATE, IDEMIP_IP6_FRAG_IO(work_a)->err);
}

void test_clear_reports_ok(void)
{
    Ip6Frag.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_FRAG_IO(work_a)->status);
}

void test_two_borrows_share_no_byte(void)
{
    make_plain(2000u);
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.ident = 0x11111111u;
    IDEMIP_IP6_FRAG_IO(work_b)->begin_args.ident = 0x22222222u;
    TEST_ASSERT_EQUAL_HEX32(0x11111111u, IDEMIP_IP6_FRAG_IO(work_a)->begin_args.ident);
    TEST_ASSERT_EQUAL_HEX32(0x22222222u, IDEMIP_IP6_FRAG_IO(work_b)->begin_args.ident);

    begin_ok(work_a, 4000u);
    begin_ok(work_b, IDEMIP_IPV6_MIN_MTU);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FRAG_IO(work_a)->split); // 2040 octets fit an MTU of 4000
    TEST_ASSERT_TRUE(IDEMIP_IP6_FRAG_IO(work_b)->split);  // and do not fit one of 1280
}

void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    make_plain(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    begin_ok(work_b, IDEMIP_IPV6_MIN_MTU);

    IDEMIP_IP6_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip6Frag.next(work_a);
    const uint16_t first_len = IDEMIP_IP6_FRAG_IO(work_a)->data_len;

    IDEMIP_IP6_FRAG_IO(work_b)->next_args.out = g_out;
    IDEMIP_IP6_FRAG_IO(work_b)->next_args.cap = sizeof g_out;
    Ip6Frag.next(work_b);
    Ip6Frag.next(work_b);

    IDEMIP_IP6_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip6Frag.next(work_a);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_IP6_FRAG_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(first_len, IDEMIP_IP6_FRAG_IO(work_a)->offset);
}

void test_clear_drops_an_open_split(void)
{
    make_plain(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    Ip6Frag.clear(work_a);
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip6Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_STATE, IDEMIP_IP6_FRAG_IO(work_a)->err);
}

// --- what is refused ---------------------------------------------------------

// sec 5: "IPv6 requires that every link in the Internet have an MTU of 1280 octets or greater."
void test_an_mtu_below_the_minimum_link_mtu_is_refused(void)
{
    make_plain(4000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_MTU, begin_err(work_a, (uint16_t)(IDEMIP_IPV6_MIN_MTU - 1u)));
}

void test_a_malformed_packet_is_refused(void)
{
    make_plain(4000u);
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.pkt = NULL;
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.len = g_pkt_len;
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.mtu = IDEMIP_IPV6_MIN_MTU;
    Ip6Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_HEADER, IDEMIP_IP6_FRAG_IO(work_a)->err);

    // a span shorter than the fixed header
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.pkt = g_pkt;
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.len = 20u;
    Ip6Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_HEADER, IDEMIP_IP6_FRAG_IO(work_a)->err);

    // a Payload Length reaching past what is readable
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.len = (size_t)g_pkt_len - 1u;
    Ip6Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_HEADER, IDEMIP_IP6_FRAG_IO(work_a)->err);

    // a version other than 6
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.len = g_pkt_len;
    g_pkt[0] = 0x45u;
    Ip6Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_HEADER, IDEMIP_IP6_FRAG_IO(work_a)->err);
}

// A chain that already carries a Fragment header is not an "original packet", so it is refused
// rather than divided again.
void test_a_packet_already_fragmented_is_refused(void)
{
    pkt_start(IDEMIP_IP6_NH_FRAGMENT);
    pkt_frag_hdr(IDEMIP_IP6_NH_UDP);
    pkt_finish(4000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_FRAGMENTED, begin_err(work_a, IDEMIP_IPV6_MIN_MTU));
}

// sec 4.1: the Hop-by-Hop Options header "restricted to appear immediately after an IPv6 header only".
void test_a_hop_by_hop_header_out_of_place_is_refused(void)
{
    pkt_start(IDEMIP_IP6_NH_DSTOPTS);
    pkt_ext(IDEMIP_IP6_NH_HOPOPT, 0u);
    pkt_ext(IDEMIP_IP6_NH_UDP, 0u);
    pkt_finish(4000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_HEADER, begin_err(work_a, IDEMIP_IPV6_MIN_MTU));
}

// An extension header claiming more octets than the packet holds stops the walk.
void test_an_extension_header_past_the_packet_is_refused(void)
{
    pkt_start(IDEMIP_IP6_NH_DSTOPTS);
    pkt_ext(IDEMIP_IP6_NH_UDP, 0u);
    pkt_finish(1300u);
    g_pkt[IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_EXT_OFF_LEN] = 0xFFu; // 2048 octets, past the 1348 held
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_HEADER, begin_err(work_a, IDEMIP_IPV6_MIN_MTU));
}

// Per-Fragment headers so wide that no whole 8-octet fragment fits behind them and the Fragment
// header cannot be made to fit the MTU.
void test_per_fragment_headers_that_leave_no_room_are_refused(void)
{
    pkt_start(IDEMIP_IP6_NH_ROUTING);
    pkt_ext(IDEMIP_IP6_NH_UDP, 153u); // 1232 octets, so the headers span 1272 of a 1280 MTU
    pkt_finish(4000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_HEADERS, begin_err(work_a, IDEMIP_IPV6_MIN_MTU));
}

// "(3) Extension headers, if any, and the Upper-Layer header. These headers must be in the first
// fragment." Headers wider than one fragment can carry cannot be split to.
void test_extension_headers_wider_than_a_fragment_are_refused(void)
{
    pkt_start(IDEMIP_IP6_NH_DSTOPTS);
    pkt_ext(IDEMIP_IP6_NH_UDP, 154u); // 1240 octets behind a 40-octet Per-Fragment part
    pkt_finish(4000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_HEADERS, begin_err(work_a, IDEMIP_IPV6_MIN_MTU));
}

// The boundary between the two above: extension headers that fill the first fragment exactly, so it
// would carry every extension header and not one octet of the Upper-Layer header. Item (3) puts both
// in the first fragment, so this is refused too.
void test_extension_headers_that_fill_the_fragment_exactly_are_refused(void)
{
    pkt_start(IDEMIP_IP6_NH_DSTOPTS);
    pkt_ext(IDEMIP_IP6_NH_UDP, 153u); // 1232 octets, exactly the 1280 MTU less the 48-octet head
    pkt_finish(4000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_HEADERS, begin_err(work_a, IDEMIP_IPV6_MIN_MTU));
}

// One octet of room past the extension headers is enough for the split to be accepted, and a caller
// that names the Upper-Layer header's own length is held to that instead.
void test_the_first_fragment_must_reach_into_the_upper_layer_header(void)
{
    pkt_start(IDEMIP_IP6_NH_DSTOPTS);
    pkt_ext(IDEMIP_IP6_NH_UDP, 152u); // 1224 octets, leaving 8 of the first fragment past them
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);

    // The same packet with the UDP header's 8 octets named still fits, exactly.
    pkt_start(IDEMIP_IP6_NH_DSTOPTS);
    pkt_ext(IDEMIP_IP6_NH_UDP, 152u);
    pkt_finish(4000u);
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.upper_hdr_len = 8u;
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);

    // One octet more of upper-layer header than there is room for is refused.
    pkt_start(IDEMIP_IP6_NH_DSTOPTS);
    pkt_ext(IDEMIP_IP6_NH_UDP, 152u);
    pkt_finish(4000u);
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.upper_hdr_len = 9u;
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_HEADERS, begin_err(work_a, IDEMIP_IPV6_MIN_MTU));
    IDEMIP_IP6_FRAG_IO(work_a)->begin_args.upper_hdr_len = 0u;
}

// --- the Per-Fragment headers ------------------------------------------------

// "else no extension headers": a chain with none puts the whole payload in the fragmentable part.
void test_a_chain_with_no_extension_headers_has_a_forty_octet_per_fragment_part(void)
{
    make_plain(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV6_HDR_LEN, IDEMIP_IP6_FRAG_IO(work_a)->unfrag_len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_UDP, IDEMIP_IP6_FRAG_IO(work_a)->next_hdr);
}

// "all headers up to and including the Routing header if present".
void test_the_per_fragment_headers_reach_through_a_routing_header(void)
{
    pkt_start(IDEMIP_IP6_NH_ROUTING);
    pkt_ext(IDEMIP_IP6_NH_UDP, 2u); // 24 octets
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV6_HDR_LEN + 24u, IDEMIP_IP6_FRAG_IO(work_a)->unfrag_len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_UDP, IDEMIP_IP6_FRAG_IO(work_a)->next_hdr);
}

// "all headers up to and including the Routing header", so a Destination Options header ahead of one
// is inside the Per-Fragment part too.
void test_a_destination_options_header_before_the_routing_header_is_per_fragment(void)
{
    pkt_start(IDEMIP_IP6_NH_DSTOPTS);
    pkt_ext(IDEMIP_IP6_NH_ROUTING, 0u); // 8 octets
    pkt_ext(IDEMIP_IP6_NH_UDP, 1u);     // 16 octets
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV6_HDR_LEN + 24u, IDEMIP_IP6_FRAG_IO(work_a)->unfrag_len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_UDP, IDEMIP_IP6_FRAG_IO(work_a)->next_hdr);
}

// "else the Hop-by-Hop Options header if present".
void test_the_per_fragment_headers_reach_through_a_hop_by_hop_header(void)
{
    pkt_start(IDEMIP_IP6_NH_HOPOPT);
    pkt_ext(IDEMIP_IP6_NH_DSTOPTS, 0u); // 8 octets, and this one is not per-fragment
    pkt_ext(IDEMIP_IP6_NH_UDP, 0u);
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV6_HDR_LEN + 8u, IDEMIP_IP6_FRAG_IO(work_a)->unfrag_len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_DSTOPTS, IDEMIP_IP6_FRAG_IO(work_a)->next_hdr);
}

// A Routing header behind a Hop-by-Hop one moves the boundary out to the Routing header.
void test_a_routing_header_behind_a_hop_by_hop_header_wins(void)
{
    pkt_start(IDEMIP_IP6_NH_HOPOPT);
    pkt_ext(IDEMIP_IP6_NH_ROUTING, 0u); // 8 octets
    pkt_ext(IDEMIP_IP6_NH_UDP, 0u);     // 8 octets
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV6_HDR_LEN + 16u, IDEMIP_IP6_FRAG_IO(work_a)->unfrag_len);
}

// A Destination Options header with neither a Routing nor a Hop-by-Hop header ahead of it stays in
// the fragmentable part, so the Per-Fragment part is the fixed header alone.
void test_a_destination_options_header_alone_is_not_per_fragment(void)
{
    pkt_start(IDEMIP_IP6_NH_DSTOPTS);
    pkt_ext(IDEMIP_IP6_NH_UDP, 0u);
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV6_HDR_LEN, IDEMIP_IP6_FRAG_IO(work_a)->unfrag_len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_DSTOPTS, IDEMIP_IP6_FRAG_IO(work_a)->next_hdr);
}

// --- the division ------------------------------------------------------------

// A packet that fits carries no Fragment header at all.
void test_a_packet_at_or_under_the_mtu_is_written_unchanged(void)
{
    const uint16_t len = make_plain(1000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FRAG_IO(work_a)->split);
    drain(work_a);
    TEST_ASSERT_EQUAL_INT(1, g_frags);
    TEST_ASSERT_EQUAL_UINT16(len, g_frag_len[0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_pkt, g_frag[0], len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_UDP, idemip_ip6_next_hdr(g_frag[0]));
}

void test_the_mtu_boundary_is_where_the_division_starts(void)
{
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV6_MIN_MTU, make_plain((uint16_t)(IDEMIP_IPV6_MIN_MTU - IDEMIP_IPV6_HDR_LEN)));
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FRAG_IO(work_a)->split);

    make_plain((uint16_t)(IDEMIP_IPV6_MIN_MTU - IDEMIP_IPV6_HDR_LEN + 1u));
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    TEST_ASSERT_TRUE(IDEMIP_IP6_FRAG_IO(work_a)->split);
    drain(work_a);
    TEST_ASSERT_EQUAL_INT(2, g_frags);
}

// "Each complete fragment, except possibly the last ("rightmost") one, is an integer multiple of 8
// octets long", and the M flag is "1 = more fragments; 0 = last fragment".
void test_every_fragment_but_the_last_is_a_multiple_of_eight_with_m_set(void)
{
    make_plain(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    drain(work_a);
    TEST_ASSERT_GREATER_THAN_INT(2, g_frags);
    for (int i = 0; i < g_frags; i++)
    {
        const uint8_t *f = g_frag[i] + IDEMIP_IPV6_HDR_LEN;
        const uint16_t data = (uint16_t)(g_frag_len[i] - IDEMIP_IPV6_HDR_LEN - IDEMIP_IP6_FRAG_HDR_LEN);
        if (i + 1 < g_frags)
        {
            TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, data % IDEMIP_IP6_EXT_UNIT,
                                             "a fragment before the last is not a multiple of 8 octets");
            TEST_ASSERT_TRUE_MESSAGE(idemip_ip6_frag_more(f), "a fragment before the last cleared the M flag");
        }
        else
        {
            TEST_ASSERT_FALSE(idemip_ip6_frag_more(f));
        }
        TEST_ASSERT_LESS_OR_EQUAL_UINT16(IDEMIP_IPV6_MIN_MTU, g_frag_len[i]);
    }
}

// "A Fragment Offset containing the offset of the fragment, in 8-octet units, relative to the start
// of the Fragmentable Part of the original packet. The Fragment Offset of the first ("leftmost")
// fragment is 0."
void test_offsets_are_contiguous_from_zero(void)
{
    make_plain(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    drain(work_a);
    uint32_t expect = 0u;
    for (int i = 0; i < g_frags; i++)
    {
        const uint8_t *f = g_frag[i] + IDEMIP_IPV6_HDR_LEN;
        TEST_ASSERT_EQUAL_UINT16(expect, idemip_ip6_frag_offset_bytes(f));
        expect += (uint32_t)(g_frag_len[i] - IDEMIP_IPV6_HDR_LEN - IDEMIP_IP6_FRAG_HDR_LEN);
    }
    TEST_ASSERT_EQUAL_UINT32(g_pkt_len - IDEMIP_IPV6_HDR_LEN, expect);
}

// "the Next Header field of the last header of the Per-Fragment headers changed to 44", and the
// Fragment header carries "The Next Header value that identifies the first header after the
// Per-Fragment headers of the original packet".
void test_the_next_header_chain_is_rewritten_around_the_fragment_header(void)
{
    pkt_start(IDEMIP_IP6_NH_ROUTING);
    pkt_ext(IDEMIP_IP6_NH_UDP, 0u); // 8 octets
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    drain(work_a);
    for (int i = 0; i < g_frags; i++)
    {
        // the IPv6 header still names the Routing header
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_ROUTING, idemip_ip6_next_hdr(g_frag[i]));
        // the Routing header, last of the Per-Fragment headers, now names the Fragment header
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_FRAGMENT, g_frag[i][IDEMIP_IPV6_HDR_LEN]);
        // and the Fragment header names what followed the Routing header in the original
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_UDP, g_frag[i][IDEMIP_IPV6_HDR_LEN + 8u]);
    }
}

// With no extension headers the IPv6 header itself is the last Per-Fragment header.
void test_the_fixed_header_alone_names_the_fragment_header(void)
{
    make_plain(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    drain(work_a);
    for (int i = 0; i < g_frags; i++)
    {
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_FRAGMENT, idemip_ip6_next_hdr(g_frag[i]));
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_UDP, g_frag[i][IDEMIP_IPV6_HDR_LEN]);
    }
}

// "with the Payload Length of the original IPv6 header changed to contain the length of this
// fragment packet only (excluding the length of the IPv6 header itself)".
void test_each_fragment_carries_its_own_payload_length(void)
{
    pkt_start(IDEMIP_IP6_NH_ROUTING);
    pkt_ext(IDEMIP_IP6_NH_UDP, 1u); // 16 octets
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    drain(work_a);
    for (int i = 0; i < g_frags; i++)
    {
        TEST_ASSERT_EQUAL_UINT16((uint16_t)(g_frag_len[i] - IDEMIP_IPV6_HDR_LEN), idemip_ip6_payload_len(g_frag[i]));
    }
}

// "The Identification value generated for the original packet", on every fragment of it.
void test_every_fragment_carries_the_identification(void)
{
    make_plain(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    drain(work_a);
    for (int i = 0; i < g_frags; i++)
    {
        TEST_ASSERT_EQUAL_HEX32(IDENT, idemip_ip6_frag_ident(g_frag[i] + IDEMIP_IPV6_HDR_LEN));
    }
}

// The Per-Fragment headers themselves are copied to every fragment, byte for byte apart from the
// Payload Length and the one Next Header field.
void test_the_per_fragment_headers_are_repeated_on_every_fragment(void)
{
    pkt_start(IDEMIP_IP6_NH_ROUTING);
    pkt_ext(IDEMIP_IP6_NH_UDP, 0u);
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    drain(work_a);
    for (int i = 0; i < g_frags; i++)
    {
        TEST_ASSERT_EQUAL_UINT8_ARRAY(idemip_ip6_src(g_pkt), idemip_ip6_src(g_frag[i]), IDEMIP_IP6_ADDR_LEN);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(idemip_ip6_dst(g_pkt), idemip_ip6_dst(g_frag[i]), IDEMIP_IP6_ADDR_LEN);
        TEST_ASSERT_EQUAL_UINT32(idemip_ip6_flow_label(g_pkt), idemip_ip6_flow_label(g_frag[i]));
        TEST_ASSERT_EQUAL_UINT8(idemip_ip6_traffic_class(g_pkt), idemip_ip6_traffic_class(g_frag[i]));
        TEST_ASSERT_EQUAL_UINT8(idemip_ip6_hop_limit(g_pkt), idemip_ip6_hop_limit(g_frag[i]));
        // the Routing header's own octets, past its rewritten Next Header
        TEST_ASSERT_EQUAL_UINT8_ARRAY(g_pkt + IDEMIP_IPV6_HDR_LEN + 1u, g_frag[i] + IDEMIP_IPV6_HDR_LEN + 1u, 7u);
    }
}

// The fragments carry the whole fragmentable part, in order and entire.
void test_the_fragments_carry_the_whole_fragmentable_part(void)
{
    pkt_start(IDEMIP_IP6_NH_ROUTING);
    pkt_ext(IDEMIP_IP6_NH_UDP, 0u);
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    const uint16_t unfrag = IDEMIP_IP6_FRAG_IO(work_a)->unfrag_len;
    drain(work_a);

    static uint8_t rebuilt[PKT_MAX];
    memset(rebuilt, 0, sizeof rebuilt);
    uint32_t total = 0u;
    for (int i = 0; i < g_frags; i++)
    {
        const uint8_t *f = g_frag[i] + unfrag;
        const uint16_t off = idemip_ip6_frag_offset_bytes(f);
        const uint16_t data = (uint16_t)(g_frag_len[i] - unfrag - IDEMIP_IP6_FRAG_HDR_LEN);
        memcpy(rebuilt + off, f + IDEMIP_IP6_FRAG_HDR_LEN, data);
        total += data;
    }
    TEST_ASSERT_EQUAL_UINT32((uint32_t)(g_pkt_len - unfrag), total);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_pkt + unfrag, rebuilt, g_pkt_len - unfrag);
}

// "PL.orig = PL.first - FL.first - 8 + (8 * FO.last) + FL.last", the section's own reassembly
// formula, run over what this fragmenter produced.
void test_the_reassembly_formula_recovers_the_original_payload_length(void)
{
    pkt_start(IDEMIP_IP6_NH_ROUTING);
    pkt_ext(IDEMIP_IP6_NH_UDP, 1u);
    pkt_finish(4000u);
    const uint16_t pl_orig = idemip_ip6_payload_len(g_pkt);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    const uint16_t unfrag = IDEMIP_IP6_FRAG_IO(work_a)->unfrag_len;
    drain(work_a);

    const uint16_t pl_first = idemip_ip6_payload_len(g_frag[0]);
    const uint16_t fl_first = (uint16_t)(g_frag_len[0] - unfrag - IDEMIP_IP6_FRAG_HDR_LEN);
    const int last = g_frags - 1;
    const uint16_t fo_last = idemip_ip6_frag_offset_bytes(g_frag[last] + unfrag);
    const uint16_t fl_last = (uint16_t)(g_frag_len[last] - unfrag - IDEMIP_IP6_FRAG_HDR_LEN);

    TEST_ASSERT_EQUAL_UINT16(pl_orig, (uint16_t)(pl_first - fl_first - IDEMIP_IP6_FRAG_HDR_LEN + fo_last + fl_last));
}

// --- the walk ----------------------------------------------------------------

void test_next_before_begin_is_refused(void)
{
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip6Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_STATE, IDEMIP_IP6_FRAG_IO(work_a)->err);
}

// The division is finished, and no repeat of the call can produce another fragment, so it is ERR and
// never BUSY: a caller told to come back on a later tick would come back forever.
void test_next_past_the_last_fragment_is_refused(void)
{
    make_plain(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    drain(work_a);
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip6Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_DONE, IDEMIP_IP6_FRAG_IO(work_a)->err);
}

void test_a_short_buffer_is_refused_and_consumes_nothing(void)
{
    make_plain(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.cap = (size_t)IDEMIP_IPV6_MIN_MTU - 1u;
    Ip6Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_ROOM, IDEMIP_IP6_FRAG_IO(work_a)->err);

    IDEMIP_IP6_FRAG_IO(work_a)->next_args.out = NULL;
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip6Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FRAG_ERR_ROOM, IDEMIP_IP6_FRAG_IO(work_a)->err);

    IDEMIP_IP6_FRAG_IO(work_a)->next_args.out = g_out;
    Ip6Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP6_FRAG_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP6_FRAG_IO(work_a)->offset);
}

void test_begin_restarts_an_open_split(void)
{
    make_plain(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP6_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip6Frag.next(work_a);
    Ip6Frag.next(work_a);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_IP6_FRAG_IO(work_a)->index);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    Ip6Frag.next(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP6_FRAG_IO(work_a)->index);
}

// What a call reports about the fragment packet it just wrote agrees with the packet's own headers.
void test_the_report_agrees_with_the_fragment(void)
{
    pkt_start(IDEMIP_IP6_NH_ROUTING);
    pkt_ext(IDEMIP_IP6_NH_UDP, 1u);
    pkt_finish(4000u);
    begin_ok(work_a, IDEMIP_IPV6_MIN_MTU);
    for (int i = 0;; i++)
    {
        IDEMIP_IP6_FRAG_IO(work_a)->next_args.out = g_out;
        IDEMIP_IP6_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
        Ip6Frag.next(work_a);
        if (IDEMIP_IP6_FRAG_IO(work_a)->status != IDEMIP_OK)
        {
            break;
        }
        const Ip6FragIo *io = IDEMIP_IP6_FRAG_IO(work_a);
        const uint8_t *f = g_out + io->unfrag_len;
        TEST_ASSERT_EQUAL_UINT16((uint16_t)i, io->index);
        TEST_ASSERT_EQUAL_UINT16((uint16_t)(io->unfrag_len + IDEMIP_IP6_FRAG_HDR_LEN), io->hdr_len);
        TEST_ASSERT_EQUAL_UINT16((uint16_t)(io->hdr_len + io->data_len), io->len);
        TEST_ASSERT_EQUAL_UINT16((uint16_t)(io->len - IDEMIP_IPV6_HDR_LEN), idemip_ip6_payload_len(g_out));
        TEST_ASSERT_EQUAL_UINT16(idemip_ip6_frag_offset_bytes(f), io->offset);
        TEST_ASSERT_EQUAL_INT(idemip_ip6_frag_more(f) ? 1 : 0, io->more ? 1 : 0);
        TEST_ASSERT_EQUAL_UINT8(io->next_hdr, f[IDEMIP_IP6_FRAG_OFF_NEXT_HDR]);
    }
}
