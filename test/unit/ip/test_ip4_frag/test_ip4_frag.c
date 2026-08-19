// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 791 sec 3.2 prints its fragmentation procedure as pseudo code and prints no numeric example of
// a split datagram anywhere in the document, so there is no figure here to replay. What the section
// does state, and what this suite asserts instead, is:
//
//   "IF TL =< MTU THEN Submit this datagram to the next step in datagram processing ELSE IF DF = 1
//   THEN discard the datagram ELSE ..."
//   "(3) NFB <- (MTU-IHL*4)/8; (4) Attach the first NFB*8 data octets;"
//   "(5) Correct the header: MF <- 1; TL <- (IHL*4)+(NFB*8); Recompute Checksum;"
//   "(7) Selectively copy the internet header (some options are not copied ...)"
//   "(9) IHL <- (((OIHL*4)-(length of options not copied))+3)/4; TL <- OTL - NFB*8 - (OIHL-IHL)*4);
//        FO <- OFO + NFB; MF <- OMF; Recompute Checksum;"
//   "If an internet datagram is fragmented, its data portion must be broken on 8 octet boundaries."
//   sec 3.1, of the option-type octet: "The copied flag indicates that this option is copied into
//   all fragments on fragmentation. 0 = not copied, 1 = copied."
//
// Plus the four things every unit's suite checks: the borrow is the caller's, every entry refuses a
// null borrow, two borrows share not one byte, and an entry is a function of its borrow alone.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ip/ip4_frag.h"

#include <string.h>
#include <unity.h>

// --- the borrow, the caller's ------------------------------------------------

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_IP4_FRAG_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_IP4_FRAG_BORROW + 16];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP4_FRAG_BORROW, CANARY, cap - IDEMIP_IP4_FRAG_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP4_FRAG_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP4_FRAG_BORROW");
    }
}

// --- a datagram to cut -------------------------------------------------------

#define DGRAM_MAX 2048u
#define OUT_MAX 2048u
#define FRAGS_MAX 64

static uint8_t g_dgram[DGRAM_MAX];
static uint16_t g_dgram_len;
static uint16_t g_dgram_hdr;
static uint16_t g_dgram_data;

static uint8_t g_out[OUT_MAX];
static uint8_t g_frag[FRAGS_MAX][OUT_MAX];
static uint16_t g_frag_len[FRAGS_MAX];
static int g_frags;

// The options a copied-flag test uses. Loose Source and Record Route is type 131, the copied flag
// set; Record Route is type 7, clear; Stream Identifier is type 136, set (RFC 791 sec 3.1).
static const uint8_t g_opts[16] = {
    131u, 7u, 4u, 10u, 0u, 0u, 1u,      // LSRR, 7 octets, one route address
    7u,   7u, 4u, 0u,  0u, 0u, 0u,      // Record Route, 7 octets, empty route area
    0u,   0u                            // two End of Option List octets, padding to 16
};

// A datagram with @p data_len octets of data behind @p opt_len octets of options, flags and fragment
// offset as given. The data is a ramp, so a round trip is checked octet by octet.
static uint16_t make_dgram(uint16_t data_len, const uint8_t *opts, size_t opt_len, uint16_t flags_frag)
{
    const uint8_t ihl = (uint8_t)(IDEMIP_IP4_IHL_MIN + opt_len / 4u);
    const uint16_t hdr = (uint16_t)(ihl * 4u);
    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.tos = 0x10u;
    f.total_len = (uint16_t)(hdr + data_len);
    f.id = 0xBEEFu;
    f.flags_frag = flags_frag;
    f.ttl = 64u;
    f.proto = IDEMIP_IP4_PROTO_UDP;
    f.src = 0xC0A80001u;
    f.dst = 0xC0A800FEu;
    idemip_ip4_build(g_dgram, &f);
    if (opt_len != 0u)
    {
        memcpy(g_dgram + IDEMIP_IPV4_HDR_LEN, opts, opt_len);
    }
    idemip_ip4_set_ver_ihl(g_dgram, ihl);
    idemip_ip4_recksum(g_dgram);
    for (uint16_t i = 0; i < data_len; i++)
    {
        g_dgram[hdr + i] = (uint8_t)(i & 0xFFu);
    }
    g_dgram_hdr = hdr;
    g_dgram_data = data_len;
    g_dgram_len = (uint16_t)(hdr + data_len);
    return g_dgram_len;
}

static void begin_ok(uint8_t *w, uint16_t mtu)
{
    IDEMIP_IP4_FRAG_IO(w)->begin_args.dgram = g_dgram;
    IDEMIP_IP4_FRAG_IO(w)->begin_args.len = g_dgram_len;
    IDEMIP_IP4_FRAG_IO(w)->begin_args.mtu = mtu;
    Ip4Frag.begin(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_FRAG_IO(w)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_NONE, IDEMIP_IP4_FRAG_IO(w)->err);
}

// Take every fragment the open split has, into g_frag.
static void drain(uint8_t *w)
{
    g_frags = 0;
    for (;;)
    {
        IDEMIP_IP4_FRAG_IO(w)->next_args.out = g_out;
        IDEMIP_IP4_FRAG_IO(w)->next_args.cap = sizeof g_out;
        Ip4Frag.next(w);
        if (IDEMIP_IP4_FRAG_IO(w)->status != IDEMIP_OK)
        {
            break;
        }
        TEST_ASSERT_LESS_THAN_INT(FRAGS_MAX, g_frags);
        g_frag_len[g_frags] = IDEMIP_IP4_FRAG_IO(w)->len;
        memcpy(g_frag[g_frags], g_out, g_frag_len[g_frags]);
        g_frags++;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_DONE, IDEMIP_IP4_FRAG_IO(w)->err);
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_dgram, 0, sizeof g_dgram);
    memset(g_out, 0, sizeof g_out);
    g_frags = 0;
    g_dgram_len = 0;
    g_dgram_hdr = 0;
    g_dgram_data = 0;
    Ip4Frag.clear(work_a);
    Ip4Frag.clear(work_b);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- the borrow --------------------------------------------------------------

void test_every_entry_survives_a_null_borrow(void)
{
    Ip4Frag.clear(NULL);
    Ip4Frag.begin(NULL);
    Ip4Frag.next(NULL);
    TEST_PASS();
}

void test_an_uncleared_borrow_refuses_work(void)
{
    arm(work_a, sizeof work_a); // zeroed, so the mark clear leaves is absent
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.dgram = g_dgram;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.len = 20u;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.mtu = 576u;
    Ip4Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_STATE, IDEMIP_IP4_FRAG_IO(work_a)->err);
    Ip4Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_STATE, IDEMIP_IP4_FRAG_IO(work_a)->err);
}

void test_clear_reports_ok(void)
{
    Ip4Frag.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_FRAG_IO(work_a)->status);
}

// The borrow IS the split, and the operand block is in it, so two splits share no byte at all.
void test_two_borrows_share_no_byte(void)
{
    make_dgram(400u, NULL, 0u, 0u);
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.mtu = 576u;
    IDEMIP_IP4_FRAG_IO(work_b)->begin_args.mtu = 68u;
    TEST_ASSERT_EQUAL_UINT16(576u, IDEMIP_IP4_FRAG_IO(work_a)->begin_args.mtu);
    TEST_ASSERT_EQUAL_UINT16(68u, IDEMIP_IP4_FRAG_IO(work_b)->begin_args.mtu);

    begin_ok(work_a, 576u);
    begin_ok(work_b, 68u);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FRAG_IO(work_a)->split); // 420 octets fit an MTU of 576
    TEST_ASSERT_TRUE(IDEMIP_IP4_FRAG_IO(work_b)->split);  // and do not fit one of 68
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    make_dgram(200u, NULL, 0u, 0u);
    begin_ok(work_a, 68u);
    begin_ok(work_b, 68u);

    IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip4Frag.next(work_a);
    const uint16_t first_units = IDEMIP_IP4_FRAG_IO(work_a)->units;
    const uint16_t first_len = IDEMIP_IP4_FRAG_IO(work_a)->len;

    IDEMIP_IP4_FRAG_IO(work_b)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(work_b)->next_args.cap = sizeof g_out;
    Ip4Frag.next(work_b);
    Ip4Frag.next(work_b);

    IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip4Frag.next(work_a);
    // a's second fragment follows a's first, not b's
    TEST_ASSERT_EQUAL_UINT16(0u, first_units);
    TEST_ASSERT_EQUAL_UINT16(68u, first_len);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_IP4_FRAG_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(48u / IDEMIP_IP4_FRAG_UNIT, IDEMIP_IP4_FRAG_IO(work_a)->units);
}

void test_clear_drops_an_open_split(void)
{
    make_dgram(200u, NULL, 0u, 0u);
    begin_ok(work_a, 68u);
    Ip4Frag.clear(work_a);
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip4Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_STATE, IDEMIP_IP4_FRAG_IO(work_a)->err);
}

// --- the fragmentation test (RFC 791 sec 3.2) --------------------------------

// "IF TL =< MTU THEN Submit this datagram to the next step in datagram processing".
void test_a_datagram_at_or_under_the_mtu_is_written_unchanged(void)
{
    const uint16_t len = make_dgram(100u, NULL, 0u, 0u);
    begin_ok(work_a, 576u);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FRAG_IO(work_a)->split);
    drain(work_a);
    TEST_ASSERT_EQUAL_INT(1, g_frags);
    TEST_ASSERT_EQUAL_UINT16(len, g_frag_len[0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_dgram, g_frag[0], len);
}

// The boundary of the same test: Total Length exactly the MTU is still "=< MTU", and one octet over
// it is not.
void test_the_mtu_boundary_is_where_the_cut_starts(void)
{
    TEST_ASSERT_EQUAL_UINT16(68u, make_dgram(48u, NULL, 0u, 0u));
    begin_ok(work_a, 68u);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FRAG_IO(work_a)->split);
    drain(work_a);
    TEST_ASSERT_EQUAL_INT(1, g_frags);

    TEST_ASSERT_EQUAL_UINT16(69u, make_dgram(49u, NULL, 0u, 0u));
    begin_ok(work_a, 68u);
    TEST_ASSERT_TRUE(IDEMIP_IP4_FRAG_IO(work_a)->split);
    drain(work_a);
    TEST_ASSERT_EQUAL_INT(2, g_frags);
    // NFB = (68 - 20) / 8 = 6, so 48 octets ride the first fragment and one octet the last
    TEST_ASSERT_EQUAL_UINT16(48u, idemip_ip4_payload_len(g_frag[0]));
    TEST_ASSERT_EQUAL_UINT16(1u, idemip_ip4_payload_len(g_frag[1]));
    TEST_ASSERT_EQUAL_UINT16(6u, idemip_ip4_frag_units(g_frag[1]));
}

// "ELSE IF DF = 1 THEN discard the datagram". RFC 1191 sec 4 is what the caller answers with.
void test_df_on_an_oversized_datagram_is_refused(void)
{
    make_dgram(200u, NULL, 0u, IDEMIP_IP4_FLAG_DF);
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.dgram = g_dgram;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.len = g_dgram_len;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.mtu = 68u;
    Ip4Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_DF, IDEMIP_IP4_FRAG_IO(work_a)->err);

    // and the refusal opened nothing, so next has no split to walk
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip4Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_STATE, IDEMIP_IP4_FRAG_IO(work_a)->err);
}

// The MTU test comes first in the procedure, so DF on a datagram that fits changes nothing.
void test_df_on_a_datagram_that_fits_is_carried_through(void)
{
    const uint16_t len = make_dgram(100u, NULL, 0u, IDEMIP_IP4_FLAG_DF);
    begin_ok(work_a, 576u);
    drain(work_a);
    TEST_ASSERT_EQUAL_INT(1, g_frags);
    TEST_ASSERT_EQUAL_UINT16(len, g_frag_len[0]);
    TEST_ASSERT_TRUE(idemip_ip4_df(g_frag[0]));
}

// "Every internet module must be able to forward a datagram of 68 octets without further
// fragmentation", so an MTU under that floor cannot be split to.
void test_an_mtu_below_the_68_octet_floor_is_refused(void)
{
    make_dgram(200u, NULL, 0u, 0u);
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.dgram = g_dgram;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.len = g_dgram_len;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.mtu = (uint16_t)(IDEMIP_IP4_MIN_FORWARD_MTU - 1u);
    Ip4Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_MTU, IDEMIP_IP4_FRAG_IO(work_a)->err);
}

void test_a_malformed_datagram_is_refused(void)
{
    make_dgram(200u, NULL, 0u, 0u);
    g_dgram[IDEMIP_IP4_OFF_CKSUM] = (uint8_t)(g_dgram[IDEMIP_IP4_OFF_CKSUM] ^ 0xFFu);
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.dgram = g_dgram;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.len = g_dgram_len;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.mtu = 68u;
    Ip4Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_HEADER, IDEMIP_IP4_FRAG_IO(work_a)->err);

    // a null datagram, and a span shorter than the header, are the same refusal
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.dgram = NULL;
    Ip4Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_HEADER, IDEMIP_IP4_FRAG_IO(work_a)->err);
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.dgram = g_dgram;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.len = 10u;
    Ip4Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_HEADER, IDEMIP_IP4_FRAG_IO(work_a)->err);
}

// RFC 894 pads a short frame and that padding "is not included in the total length field", so a span
// longer than Total Length is still the same datagram.
void test_a_span_longer_than_total_length_is_accepted(void)
{
    const uint16_t len = make_dgram(100u, NULL, 0u, 0u);
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.dgram = g_dgram;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.len = (size_t)len + 46u;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.mtu = 576u;
    Ip4Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_FRAG_IO(work_a)->status);
    drain(work_a);
    TEST_ASSERT_EQUAL_INT(1, g_frags);
    TEST_ASSERT_EQUAL_UINT16(len, g_frag_len[0]); // the padding is not carried
}

// --- the cut -----------------------------------------------------------------

// "(3) NFB <- (MTU-IHL*4)/8; (4) Attach the first NFB*8 data octets; (5) MF <- 1;
// TL <- (IHL*4)+(NFB*8)".
void test_the_first_fragment_is_nfb_times_eight_octets_with_mf_set(void)
{
    make_dgram(200u, NULL, 0u, 0u);
    begin_ok(work_a, 100u);
    drain(work_a);
    // NFB = (100 - 20) / 8 = 10, so 80 data octets and a Total Length of 100
    TEST_ASSERT_EQUAL_UINT16(100u, g_frag_len[0]);
    TEST_ASSERT_EQUAL_UINT16(100u, idemip_ip4_total_len(g_frag[0]));
    TEST_ASSERT_EQUAL_UINT16(80u, idemip_ip4_payload_len(g_frag[0]));
    TEST_ASSERT_TRUE(idemip_ip4_mf(g_frag[0]));
    TEST_ASSERT_EQUAL_UINT16(0u, idemip_ip4_frag_units(g_frag[0]));
}

// "If an internet datagram is fragmented, its data portion must be broken on 8 octet boundaries."
// The MTU is one that "NFB <- (MTU-IHL*4)/8" then "NFB*8" has to round down, so a fragmenter that
// filled the MTU instead would be caught here: 301 - 20 is 281, and NFB*8 is 280.
void test_every_fragment_but_the_last_carries_a_multiple_of_eight(void)
{
    make_dgram(1000u, NULL, 0u, 0u);
    begin_ok(work_a, 301u);
    drain(work_a);
    TEST_ASSERT_EQUAL_UINT16(280u, idemip_ip4_payload_len(g_frag[0]));
    TEST_ASSERT_GREATER_THAN_INT(2, g_frags);
    for (int i = 0; i < g_frags - 1; i++)
    {
        const uint16_t data = idemip_ip4_payload_len(g_frag[i]);
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, data % IDEMIP_IP4_FRAG_UNIT,
                                         "a fragment before the last is not a multiple of 8 octets");
        TEST_ASSERT_TRUE_MESSAGE(idemip_ip4_mf(g_frag[i]), "a fragment before the last cleared More Fragments");
    }
    TEST_ASSERT_FALSE(idemip_ip4_mf(g_frag[g_frags - 1]));
}

// "FO <- OFO + NFB": each fragment starts where the one before it ended, in units of eight octets.
void test_offsets_are_contiguous_in_units_of_eight(void)
{
    make_dgram(1000u, NULL, 0u, 0u);
    begin_ok(work_a, 301u);
    drain(work_a);
    uint32_t expect = 0u;
    for (int i = 0; i < g_frags; i++)
    {
        TEST_ASSERT_EQUAL_UINT32(expect, idemip_ip4_frag_offset_bytes(g_frag[i]));
        expect += idemip_ip4_payload_len(g_frag[i]);
    }
    TEST_ASSERT_EQUAL_UINT32(g_dgram_data, expect);
}

// Every fragment is a datagram in its own right, so every one of them verifies.
void test_every_fragment_verifies_and_fits_the_mtu(void)
{
    make_dgram(1000u, g_opts, sizeof g_opts, 0u);
    begin_ok(work_a, 300u);
    drain(work_a);
    for (int i = 0; i < g_frags; i++)
    {
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, idemip_ip4_verify(g_frag[i], g_frag_len[i]),
                                      "a fragment did not verify");
        TEST_ASSERT_LESS_OR_EQUAL_UINT16(300u, idemip_ip4_total_len(g_frag[i]));
    }
}

// The fragments carry the original data, in order and entire.
void test_the_fragments_carry_the_whole_datagram(void)
{
    make_dgram(1000u, g_opts, sizeof g_opts, 0u);
    begin_ok(work_a, 300u);
    drain(work_a);
    uint8_t rebuilt[DGRAM_MAX];
    memset(rebuilt, 0, sizeof rebuilt);
    for (int i = 0; i < g_frags; i++)
    {
        const size_t hdr = idemip_ip4_hdr_len(g_frag[i]);
        const uint32_t off = idemip_ip4_frag_offset_bytes(g_frag[i]);
        memcpy(rebuilt + off, g_frag[i] + hdr, idemip_ip4_payload_len(g_frag[i]));
    }
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_dgram + g_dgram_hdr, rebuilt, g_dgram_data);
}

// The fixed fields the fragmentation does not touch stay as they were.
void test_the_untouched_header_fields_are_carried(void)
{
    make_dgram(500u, NULL, 0u, 0u);
    begin_ok(work_a, 200u);
    drain(work_a);
    for (int i = 0; i < g_frags; i++)
    {
        TEST_ASSERT_EQUAL_HEX16(idemip_ip4_id(g_dgram), idemip_ip4_id(g_frag[i]));
        TEST_ASSERT_EQUAL_HEX32(idemip_ip4_src(g_dgram), idemip_ip4_src(g_frag[i]));
        TEST_ASSERT_EQUAL_HEX32(idemip_ip4_dst(g_dgram), idemip_ip4_dst(g_frag[i]));
        TEST_ASSERT_EQUAL_UINT8(idemip_ip4_ttl(g_dgram), idemip_ip4_ttl(g_frag[i]));
        TEST_ASSERT_EQUAL_UINT8(idemip_ip4_proto(g_dgram), idemip_ip4_proto(g_frag[i]));
        TEST_ASSERT_EQUAL_UINT8(idemip_ip4_tos(g_dgram), idemip_ip4_tos(g_frag[i]));
        TEST_ASSERT_FALSE_MESSAGE(idemip_ip4_reserved(g_frag[i]), "RFC 791 sec 3.1 reserves flags bit 0 and it must be zero");
    }
}

// A datagram that is itself a fragment keeps where it sat: "FO <- OFO + NFB; MF <- OMF".
void test_a_fragment_of_a_fragment_carries_ofo_and_omf(void)
{
    const uint16_t ofo = 100u;
    make_dgram(400u, NULL, 0u, (uint16_t)(IDEMIP_IP4_FLAG_MF | ofo));
    begin_ok(work_a, 200u);
    drain(work_a);
    TEST_ASSERT_GREATER_THAN_INT(1, g_frags);
    TEST_ASSERT_EQUAL_UINT16(ofo, idemip_ip4_frag_units(g_frag[0]));
    uint32_t expect = (uint32_t)ofo * IDEMIP_IP4_FRAG_UNIT;
    for (int i = 0; i < g_frags; i++)
    {
        TEST_ASSERT_EQUAL_UINT32(expect, idemip_ip4_frag_offset_bytes(g_frag[i]));
        expect += idemip_ip4_payload_len(g_frag[i]);
        // OMF was set, so even the last fragment still says more follow
        TEST_ASSERT_TRUE(idemip_ip4_mf(g_frag[i]));
    }
}

// "This format allows 2**13 = 8192 fragments of 8 octets each": a split that would run the Fragment
// Offset past its 13 bits is refused rather than wrapped.
void test_a_split_past_the_thirteen_bit_offset_is_refused(void)
{
    make_dgram(2000u, NULL, 0u, (uint16_t)(IDEMIP_IP4_FLAG_MF | 8000u));
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.dgram = g_dgram;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.len = g_dgram_len;
    IDEMIP_IP4_FRAG_IO(work_a)->begin_args.mtu = 576u;
    Ip4Frag.begin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_OFFSET, IDEMIP_IP4_FRAG_IO(work_a)->err);
}

// The 68-octet floor against the 60-octet maximal header leaves exactly one 8-octet unit.
void test_the_widest_header_at_the_floor_still_advances(void)
{
    uint8_t wide[40];
    memset(wide, IDEMIP_IP4_FRAG_OPT_EOL, sizeof wide);
    make_dgram(64u, wide, sizeof wide, 0u);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IP4_HDR_MAX, g_dgram_hdr);
    begin_ok(work_a, IDEMIP_IP4_MIN_FORWARD_MTU);
    drain(work_a);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IP4_FRAG_UNIT, idemip_ip4_payload_len(g_frag[0]));
    // every option was End of Option List, so the reduced header carries none of them
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_IHL_MIN, idemip_ip4_ihl(g_frag[1]));
}

// --- the options (RFC 791 sec 3.1) -------------------------------------------

// "(1) Copy the original internet header": the first fragment keeps every option it had.
void test_the_first_fragment_keeps_the_whole_option_area(void)
{
    make_dgram(400u, g_opts, sizeof g_opts, 0u);
    begin_ok(work_a, 200u);
    drain(work_a);
    TEST_ASSERT_EQUAL_size_t(g_dgram_hdr, idemip_ip4_hdr_len(g_frag[0]));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_dgram + IDEMIP_IPV4_HDR_LEN, g_frag[0] + IDEMIP_IPV4_HDR_LEN, sizeof g_opts);
}

// "The copied flag indicates that this option is copied into all fragments on fragmentation", and
// "(9) IHL <- (((OIHL*4)-(length of options not copied))+3)/4".
void test_only_copied_options_reach_the_later_fragments(void)
{
    make_dgram(400u, g_opts, sizeof g_opts, 0u);
    begin_ok(work_a, 200u);
    drain(work_a);
    TEST_ASSERT_GREATER_THAN_INT(1, g_frags);

    // LSRR is 7 octets and copied; Record Route is 7 and not; the two End of Option List octets are
    // not. So 20 + 7 rounded up to a whole word is 28 octets, an IHL of 7.
    for (int i = 1; i < g_frags; i++)
    {
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(7u, idemip_ip4_ihl(g_frag[i]), "the reduced IHL is not 20 + 7 rounded up");
        TEST_ASSERT_EQUAL_size_t(28u, idemip_ip4_hdr_len(g_frag[i]));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(g_opts, g_frag[i] + IDEMIP_IPV4_HDR_LEN, 7u);
        // the octet between the copied option and the end of the header is End of Option List
        TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP4_FRAG_OPT_EOL, g_frag[i][IDEMIP_IPV4_HDR_LEN + 7u]);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(g_frag[i], g_frag_len[i]));
    }
}

// An option area of nothing but not-copied options leaves the twenty fixed octets alone.
void test_a_header_of_only_uncopied_options_reduces_to_twenty(void)
{
    // Record Route, type 7, eleven octets, padded with No Operation to a whole word. Neither type
    // carries the copied flag.
    const uint8_t opts[12] = {7u, 11u, 4u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u};
    make_dgram(400u, opts, sizeof opts, 0u);
    begin_ok(work_a, 200u);
    drain(work_a);
    TEST_ASSERT_GREATER_THAN_INT(1, g_frags);
    for (int i = 1; i < g_frags; i++)
    {
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_IHL_MIN, idemip_ip4_ihl(g_frag[i]));
        TEST_ASSERT_EQUAL_size_t(IDEMIP_IPV4_HDR_LEN, idemip_ip4_hdr_len(g_frag[i]));
    }
}

// A copied option whose length octet runs past the header stops the walk rather than reading on.
void test_an_option_length_past_the_header_is_not_followed(void)
{
    const uint8_t opts[8] = {131u, 200u, 0u, 0u, 0u, 0u, 0u, 0u}; // LSRR claiming 200 octets
    make_dgram(400u, opts, sizeof opts, 0u);
    begin_ok(work_a, 200u);
    drain(work_a);
    TEST_ASSERT_GREATER_THAN_INT(1, g_frags);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_IHL_MIN, idemip_ip4_ihl(g_frag[1]));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(g_frag[1], g_frag_len[1]));
}

// End of Option List ends the walk, so a copied option behind one is not carried.
void test_an_option_behind_end_of_option_list_is_not_copied(void)
{
    const uint8_t opts[8] = {0u, 136u, 4u, 0u, 1u, 0u, 0u, 0u}; // EOL, then a Stream Identifier
    make_dgram(400u, opts, sizeof opts, 0u);
    begin_ok(work_a, 200u);
    drain(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_IHL_MIN, idemip_ip4_ihl(g_frag[1]));
}

// Stream Identifier, type 136, "Must be copied on fragmentation".
void test_a_four_octet_copied_option_needs_no_padding(void)
{
    const uint8_t opts[4] = {136u, 4u, 0x12u, 0x34u};
    make_dgram(400u, opts, sizeof opts, 0u);
    begin_ok(work_a, 200u);
    drain(work_a);
    TEST_ASSERT_GREATER_THAN_INT(1, g_frags);
    TEST_ASSERT_EQUAL_UINT8(6u, idemip_ip4_ihl(g_frag[1]));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(opts, g_frag[1] + IDEMIP_IPV4_HDR_LEN, sizeof opts);
}

// --- the walk ----------------------------------------------------------------

void test_next_before_begin_is_refused(void)
{
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip4Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_STATE, IDEMIP_IP4_FRAG_IO(work_a)->err);
}

// The split is finished, and no repeat of the call can produce another fragment, so it is ERR and
// never BUSY: a caller told to come back on a later tick would come back forever.
void test_next_past_the_last_fragment_is_refused(void)
{
    make_dgram(200u, NULL, 0u, 0u);
    begin_ok(work_a, 100u);
    drain(work_a);
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip4Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_DONE, IDEMIP_IP4_FRAG_IO(work_a)->err);
}

// A buffer that cannot hold the fragment is refused, and the cursor does not move: the same call on
// a wide enough buffer still hands back the fragment that was refused.
void test_a_short_buffer_is_refused_and_consumes_nothing(void)
{
    make_dgram(200u, NULL, 0u, 0u);
    begin_ok(work_a, 100u);
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.cap = 99u;
    Ip4Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_ROOM, IDEMIP_IP4_FRAG_IO(work_a)->err);

    IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = NULL;
    Ip4Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FRAG_ERR_ROOM, IDEMIP_IP4_FRAG_IO(work_a)->err);

    IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip4Frag.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_FRAG_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_FRAG_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_FRAG_IO(work_a)->units);
}

// A second begin restarts the walk from the first fragment.
void test_begin_restarts_an_open_split(void)
{
    make_dgram(200u, NULL, 0u, 0u);
    begin_ok(work_a, 100u);
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
    Ip4Frag.next(work_a);
    Ip4Frag.next(work_a);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_IP4_FRAG_IO(work_a)->index);
    begin_ok(work_a, 100u);
    Ip4Frag.next(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_FRAG_IO(work_a)->index);
}

// What a call reports about the fragment it just wrote agrees with the fragment's own header.
void test_the_report_agrees_with_the_fragment(void)
{
    make_dgram(500u, g_opts, sizeof g_opts, 0u);
    begin_ok(work_a, 200u);
    for (int i = 0;; i++)
    {
        IDEMIP_IP4_FRAG_IO(work_a)->next_args.out = g_out;
        IDEMIP_IP4_FRAG_IO(work_a)->next_args.cap = sizeof g_out;
        Ip4Frag.next(work_a);
        if (IDEMIP_IP4_FRAG_IO(work_a)->status != IDEMIP_OK)
        {
            break;
        }
        const Ip4FragIo *io = IDEMIP_IP4_FRAG_IO(work_a);
        TEST_ASSERT_EQUAL_UINT16((uint16_t)i, io->index);
        TEST_ASSERT_EQUAL_UINT16(idemip_ip4_total_len(g_out), io->len);
        TEST_ASSERT_EQUAL_size_t(idemip_ip4_hdr_len(g_out), io->hdr_len);
        TEST_ASSERT_EQUAL_UINT16(idemip_ip4_payload_len(g_out), io->data_len);
        TEST_ASSERT_EQUAL_UINT16(idemip_ip4_frag_units(g_out), io->units);
        TEST_ASSERT_EQUAL_UINT32(idemip_ip4_frag_offset_bytes(g_out), io->offset);
        TEST_ASSERT_EQUAL_INT(idemip_ip4_mf(g_out) ? 1 : 0, io->more ? 1 : 0);
        TEST_ASSERT_EQUAL_UINT16((uint16_t)(io->hdr_len + io->data_len), io->len);
    }
}
