// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 8200, the IPv6 specification. The document carries no hex dump, so every vector here is laid
// out octet by octet from the figures themselves:
//
//   sec 3     the header figure, which fixes Version, Traffic Class and Flow Label in the first
//             word and the two 128-bit addresses at 8 and 24
//   sec 4     the three packet illustrations - IPv6+TCP, IPv6+Routing+TCP, and
//             IPv6+Routing+Fragment+TCP - used verbatim as the chain walk cases
//   sec 4.2   the Pad1 and PadN figures and the three high-order Option Type bits
//   sec 4.3   "Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8
//             octets"
//   sec 4.4   the Routing header figure
//   sec 4.5   the Fragment header figure, its 13-bit offset "in 8-octet units", the 2-bit Res and
//             the M flag
//   sec 8.1   the pseudo-header figure, summed here as bytes and compared against the accumulator
//
// Addresses use the RFC 3849 documentation prefix; only their positions and widths come from RFC
// 8200.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/checksum.h"
#include "src/ip/ipv6.h"

#include <string.h>
#include <unity.h>

// --- the caller's bytes, each with a canary past the end ----------------------

#define CANARY 0x5Au
#define PKT_USED 128u

static uint8_t pkt[PKT_USED + 16u];
static uint8_t built[IDEMIP_IPV6_HDR_LEN + 16u];
static uint8_t fragbuf[IDEMIP_IP6_FRAG_HDR_LEN + 16u];

static void arm(uint8_t *b, size_t used, size_t cap)
{
    memset(b, 0, used);
    memset(b + used, CANARY, cap - used);
}

static void check_canary(const uint8_t *b, size_t used, size_t cap)
{
    for (size_t i = used; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, b[i], "a write landed past the header");
    }
}

void setUp(void)
{
    arm(pkt, PKT_USED, sizeof pkt);
    arm(built, IDEMIP_IPV6_HDR_LEN, sizeof built);
    arm(fragbuf, IDEMIP_IP6_FRAG_HDR_LEN, sizeof fragbuf);
}

void tearDown(void)
{
    check_canary(pkt, PKT_USED, sizeof pkt);
    check_canary(built, IDEMIP_IPV6_HDR_LEN, sizeof built);
    check_canary(fragbuf, IDEMIP_IP6_FRAG_HDR_LEN, sizeof fragbuf);
}

// --- the sec 3 header, octet by octet ----------------------------------------
// Version 6, Traffic Class 2f, Flow Label 12345 pack into 62 f1 23 45. Payload Length 20, Next
// Header 6 (TCP), Hop Limit 64, then the two addresses.

static const uint8_t g_src[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_dst[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

static const uint8_t g_hdr[IDEMIP_IPV6_HDR_LEN] = {
    0x62, 0xf1, 0x23, 0x45,                                        // ver/tc/flow
    0x00, 0x14,                                                    // payload len
    0x06,                                                          // next header
    0x40,                                                          // hop limit
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // source
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, // destination
};

// Lay the fixed header into pkt and return the offset of the payload.
static size_t lay_hdr(uint8_t next_hdr, uint16_t payload_len)
{
    memcpy(pkt, g_hdr, sizeof g_hdr);
    pkt[IDEMIP_IP6_OFF_NEXT_HDR] = next_hdr;
    idemip_wr16(pkt + IDEMIP_IP6_OFF_PAYLOAD_LEN, payload_len);
    return IDEMIP_IP6_OFF_PAYLOAD;
}

// One 8-octet extension header carrying the common two octets: Next Header, Hdr Ext Len, then
// whatever the variant puts in the remaining six.
static void lay_ext(size_t at, uint8_t next_hdr, uint8_t hdr_ext_len)
{
    pkt[at + IDEMIP_IP6_EXT_OFF_NEXT_HDR] = next_hdr;
    pkt[at + IDEMIP_IP6_EXT_OFF_LEN] = hdr_ext_len;
}

// --- sec 3, the fixed header --------------------------------------------------

// The first word holds three fields at three widths, and each accessor takes only its own bits.
void test_version_traffic_class_and_flow_label_split_the_first_word(void)
{
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_VERSION, idemip_ip6_version(g_hdr));
    TEST_ASSERT_EQUAL_HEX8(0x2fu, idemip_ip6_traffic_class(g_hdr));
    TEST_ASSERT_EQUAL_HEX32(0x12345u, idemip_ip6_flow_label(g_hdr));
}

// The remaining sec 3 fields, at the offsets the figure fixes.
void test_the_fixed_fields_sit_where_the_section_3_figure_puts_them(void)
{
    TEST_ASSERT_EQUAL_UINT16(20u, idemip_ip6_payload_len(g_hdr));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, idemip_ip6_next_hdr(g_hdr));
    TEST_ASSERT_EQUAL_UINT8(64u, idemip_ip6_hop_limit(g_hdr));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_src, idemip_ip6_src(g_hdr), IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_dst, idemip_ip6_dst(g_hdr), IDEMIP_IP6_ADDR_LEN);
}

// sec 3: "Length of the IPv6 payload, i.e., the rest of the packet following this IPv6 header". The
// twenty octets here are the TCP header alone, the forty of the fixed header uncounted.
void test_payload_length_excludes_the_fixed_header(void)
{
    TEST_ASSERT_EQUAL_UINT16(20u, idemip_ip6_payload_len(g_hdr));
    TEST_ASSERT_EQUAL_UINT(40u, IDEMIP_IPV6_HDR_LEN);
}

// A header lands 14 bytes into an Ethernet frame and at odd offsets inside a tunnel, so no accessor
// may read through a wider type. The same octets read the same at 0, 1 and 14.
void test_every_field_reads_the_same_at_an_odd_offset(void)
{
    for (size_t at = 0u; at <= 14u; at += 7u)
    {
        memcpy(pkt + at, g_hdr, sizeof g_hdr);
        const uint8_t *h = pkt + at;
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_VERSION, idemip_ip6_version(h));
        TEST_ASSERT_EQUAL_HEX8(0x2fu, idemip_ip6_traffic_class(h));
        TEST_ASSERT_EQUAL_HEX32(0x12345u, idemip_ip6_flow_label(h));
        TEST_ASSERT_EQUAL_UINT16(20u, idemip_ip6_payload_len(h));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(g_src, idemip_ip6_src(h), IDEMIP_IP6_ADDR_LEN);
    }
}

// --- sec 3, build -------------------------------------------------------------

void test_build_writes_the_section_3_figure(void)
{
    IdemIpIp6BuildArgs a;
    a.src = g_src;
    a.dst = g_dst;
    a.flow_label = 0x12345u;
    a.payload_len = 20u;
    a.traffic_class = 0x2fu;
    a.next_hdr = IDEMIP_IP6_NH_TCP;
    a.hop_limit = 64u;
    idemip_ip6_build(built, &a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_hdr, built, IDEMIP_IPV6_HDR_LEN);
}

// Version is the standard's, not the caller's: sec 3 fixes it at 6.
void test_build_forces_version_six(void)
{
    IdemIpIp6BuildArgs a;
    a.src = g_src;
    a.dst = g_dst;
    a.flow_label = 0u;
    a.payload_len = 0u;
    a.traffic_class = 0u;
    a.next_hdr = IDEMIP_IP6_NH_NONE;
    a.hop_limit = 1u;
    idemip_ip6_build(built, &a);
    TEST_ASSERT_EQUAL_UINT8(6u, idemip_ip6_version(built));
    TEST_ASSERT_EQUAL_HEX8(0x60u, built[0]);
}

// A Flow Label wider than twenty bits and a Traffic Class wider than eight cannot reach the version
// nibble: each is masked to the width sec 3 gives it.
void test_build_masks_each_packed_field_to_its_width(void)
{
    IdemIpIp6BuildArgs a;
    a.src = g_src;
    a.dst = g_dst;
    a.flow_label = 0xFFFFFFFFu;
    a.payload_len = 0u;
    a.traffic_class = 0xFFu;
    a.next_hdr = IDEMIP_IP6_NH_TCP;
    a.hop_limit = 255u;
    idemip_ip6_build(built, &a);
    TEST_ASSERT_EQUAL_UINT8(6u, idemip_ip6_version(built));
    TEST_ASSERT_EQUAL_HEX8(0xFFu, idemip_ip6_traffic_class(built));
    TEST_ASSERT_EQUAL_HEX32(0x000FFFFFu, idemip_ip6_flow_label(built));
    TEST_ASSERT_EQUAL_HEX32(0x6FFFFFFFu, idemip_rd32(built));
}

void test_build_round_trips_through_the_accessors(void)
{
    IdemIpIp6BuildArgs a;
    a.src = g_dst;
    a.dst = g_src;
    a.flow_label = 0x0abcdu;
    a.payload_len = 1280u;
    a.traffic_class = 0x88u;
    a.next_hdr = IDEMIP_IP6_NH_UDP;
    a.hop_limit = 255u;
    idemip_ip6_build(built, &a);
    TEST_ASSERT_EQUAL_HEX32(0x0abcdu, idemip_ip6_flow_label(built));
    TEST_ASSERT_EQUAL_UINT16(1280u, idemip_ip6_payload_len(built));
    TEST_ASSERT_EQUAL_HEX8(0x88u, idemip_ip6_traffic_class(built));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_UDP, idemip_ip6_next_hdr(built));
    TEST_ASSERT_EQUAL_UINT8(255u, idemip_ip6_hop_limit(built));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_dst, idemip_ip6_src(built), IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_src, idemip_ip6_dst(built), IDEMIP_IP6_ADDR_LEN);
}

// sec 4.5 step (1): a fragment packet carries the original per-fragment headers with the Payload
// Length rewritten and the last Next Header changed to 44. Both are single-field writes.
void test_the_field_writers_touch_only_their_own_field(void)
{
    memcpy(built, g_hdr, sizeof g_hdr);
    idemip_ip6_set_payload_len(built, 1234u);
    idemip_ip6_set_next_hdr(built, IDEMIP_IP6_NH_FRAGMENT);
    idemip_ip6_set_hop_limit(built, 1u);
    TEST_ASSERT_EQUAL_UINT16(1234u, idemip_ip6_payload_len(built));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_FRAGMENT, idemip_ip6_next_hdr(built));
    TEST_ASSERT_EQUAL_UINT8(1u, idemip_ip6_hop_limit(built));
    // The first word and both addresses are untouched.
    TEST_ASSERT_EQUAL_HEX32(0x62f12345u, idemip_rd32(built));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_src, idemip_ip6_src(built), IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_dst, idemip_ip6_dst(built), IDEMIP_IP6_ADDR_LEN);
}

// --- sec 4, Next Header values ------------------------------------------------

// Each value is the one the section that defines the header states.
void test_next_header_values_match_the_defining_sections(void)
{
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_NH_HOPOPT);    // sec 4.3
    TEST_ASSERT_EQUAL_UINT8(6u, IDEMIP_IP6_NH_TCP);       // sec 8.1, "6 for TCP"
    TEST_ASSERT_EQUAL_UINT8(17u, IDEMIP_IP6_NH_UDP);      // sec 8.1, "17 for UDP"
    TEST_ASSERT_EQUAL_UINT8(43u, IDEMIP_IP6_NH_ROUTING);  // sec 4.4
    TEST_ASSERT_EQUAL_UINT8(44u, IDEMIP_IP6_NH_FRAGMENT); // sec 4.5
    TEST_ASSERT_EQUAL_UINT8(58u, IDEMIP_IP6_NH_ICMPV6);   // sec 8.1, "the value 58"
    TEST_ASSERT_EQUAL_UINT8(59u, IDEMIP_IP6_NH_NONE);     // sec 4.7
    TEST_ASSERT_EQUAL_UINT8(60u, IDEMIP_IP6_NH_DSTOPTS);  // sec 4.6
}

// sec 4 names six extension headers and specifies four. The four are stepped; Authentication (51)
// and Encapsulating Security Payload (50) are sized by RFC 4302 and RFC 4303, not by sec 4's
// 8-octet rule, so they end the walk instead.
void test_only_the_four_headers_this_document_specifies_are_extensions(void)
{
    TEST_ASSERT_TRUE(idemip_ip6_nh_is_ext(IDEMIP_IP6_NH_HOPOPT));
    TEST_ASSERT_TRUE(idemip_ip6_nh_is_ext(IDEMIP_IP6_NH_ROUTING));
    TEST_ASSERT_TRUE(idemip_ip6_nh_is_ext(IDEMIP_IP6_NH_FRAGMENT));
    TEST_ASSERT_TRUE(idemip_ip6_nh_is_ext(IDEMIP_IP6_NH_DSTOPTS));
    TEST_ASSERT_FALSE(idemip_ip6_nh_is_ext(IDEMIP_IP6_NH_TCP));
    TEST_ASSERT_FALSE(idemip_ip6_nh_is_ext(IDEMIP_IP6_NH_UDP));
    TEST_ASSERT_FALSE(idemip_ip6_nh_is_ext(IDEMIP_IP6_NH_ICMPV6));
    TEST_ASSERT_FALSE(idemip_ip6_nh_is_ext(IDEMIP_IP6_NH_NONE));
    TEST_ASSERT_FALSE(idemip_ip6_nh_is_ext(50u));
    TEST_ASSERT_FALSE(idemip_ip6_nh_is_ext(51u));
}

// --- sec 4.3, the Hdr Ext Len unit rule ---------------------------------------

// "in 8-octet units, not including the first 8 octets", so a field of zero is a header of eight.
void test_hdr_ext_len_of_zero_is_eight_octets(void)
{
    TEST_ASSERT_EQUAL_size_t(8u, IDEMIP_IP6_EXT_BYTES(0u));
    lay_ext(0u, IDEMIP_IP6_NH_TCP, 0u);
    TEST_ASSERT_EQUAL_size_t(8u, idemip_ip6_ext_len(pkt));
}

// Each further unit is eight more octets, the first eight still implied.
void test_hdr_ext_len_counts_units_past_the_first_eight(void)
{
    TEST_ASSERT_EQUAL_size_t(16u, IDEMIP_IP6_EXT_BYTES(1u));
    TEST_ASSERT_EQUAL_size_t(24u, IDEMIP_IP6_EXT_BYTES(2u));
    TEST_ASSERT_EQUAL_size_t(2048u, IDEMIP_IP6_EXT_BYTES(255u));
    TEST_ASSERT_EQUAL_size_t(2048u, IDEMIP_IP6_EXT_BYTES_MAX);
    lay_ext(0u, IDEMIP_IP6_NH_UDP, 3u);
    TEST_ASSERT_EQUAL_size_t(32u, idemip_ip6_ext_len(pkt));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_UDP, idemip_ip6_ext_next_hdr(pkt));
}

// --- sec 4.2, options ---------------------------------------------------------

// "the format of the Pad1 option is a special case -- it does not have length and value fields."
void test_pad1_is_one_octet_with_no_length(void)
{
    pkt[0] = IDEMIP_IP6_OPT_PAD1;
    pkt[1] = 0xFFu; // whatever follows is the next option, never this one's length
    TEST_ASSERT_EQUAL_size_t(1u, idemip_ip6_opt_len(pkt));
}

// "For N octets of padding, the Opt Data Len field contains the value N-2", so the option occupies
// its two header octets plus that many.
void test_padn_occupies_its_length_plus_two(void)
{
    pkt[0] = IDEMIP_IP6_OPT_PADN;
    pkt[1] = 4u;
    TEST_ASSERT_EQUAL_size_t(6u, idemip_ip6_opt_len(pkt));
    pkt[1] = 0u;
    TEST_ASSERT_EQUAL_size_t(2u, idemip_ip6_opt_len(pkt));
    pkt[1] = 255u;
    TEST_ASSERT_EQUAL_size_t(257u, idemip_ip6_opt_len(pkt));
}

// The highest-order 2 bits carry the four answers sec 4.2 tabulates, and the third-highest is the
// change-en-route bit. Together they are the three high bits of the Option Type.
void test_the_three_high_option_type_bits_decode_as_section_4_2_states(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x00u, 0x1Fu & IDEMIP_IP6_OPT_ACT_MASK);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP6_OPT_ACT_SKIP, IDEMIP_IP6_OPT_PAD1 & IDEMIP_IP6_OPT_ACT_MASK);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP6_OPT_ACT_SKIP, IDEMIP_IP6_OPT_PADN & IDEMIP_IP6_OPT_ACT_MASK);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP6_OPT_ACT_DISCARD, 0x5Au & IDEMIP_IP6_OPT_ACT_MASK);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP6_OPT_ACT_DISCARD_ICMP, 0x9Au & IDEMIP_IP6_OPT_ACT_MASK);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP6_OPT_ACT_DISCARD_UNI, 0xC2u & IDEMIP_IP6_OPT_ACT_MASK);
    // 0x20 is bit 5, the third highest, and it is disjoint from the action pair.
    TEST_ASSERT_EQUAL_HEX8(0x20u, IDEMIP_IP6_OPT_CHG_MASK);
    TEST_ASSERT_EQUAL_HEX8(0u, IDEMIP_IP6_OPT_CHG_MASK & IDEMIP_IP6_OPT_ACT_MASK);

    // What acts on those bits: an option stream carrying only skip actions is walked through, and one
    // carrying any other action stops the packet at the offending Option Type. The change-en-route
    // bit is not part of the decision, so setting it does not alter either answer.
    // PadN, then an option whose action bits are 00 and whose change-en-route bit is set.
    static const uint8_t stream_skip[6] = {IDEMIP_IP6_OPT_PADN, 2u, 0u, 0u, IDEMIP_IP6_OPT_CHG_MASK, 0u};
    memcpy(pkt, stream_skip, sizeof stream_skip);
    size_t bad = 0xFFFFu;
    TEST_ASSERT_FALSE(idemip_ip6_opts_refused(pkt, 0u, 6u, &bad));

    static const uint8_t acts[3] = {IDEMIP_IP6_OPT_ACT_DISCARD, IDEMIP_IP6_OPT_ACT_DISCARD_ICMP,
                                    IDEMIP_IP6_OPT_ACT_DISCARD_UNI};
    for (size_t i = 0; i < 3u; i++)
    {
        pkt[0] = IDEMIP_IP6_OPT_PADN;
        pkt[1] = 2u;
        pkt[2] = 0u;
        pkt[3] = 0u;
        pkt[4] = (uint8_t)(acts[i] | IDEMIP_IP6_OPT_CHG_MASK | 0x0Au);
        pkt[5] = 0u;
        bad = 0xFFFFu;
        TEST_ASSERT_TRUE_MESSAGE(idemip_ip6_opts_refused(pkt, 0u, 6u, &bad), "an action above skip refuses");
        TEST_ASSERT_EQUAL_size_t_MESSAGE(4u, bad, "the pointer names the unrecognized Option Type");
    }
}

// --- sec 4.5, the fragment header ---------------------------------------------

// The offset is a 13-bit field "in 8-octet units" sitting three bits up, so masking off Res and M
// leaves the byte position already multiplied by eight.
void test_fragment_offset_is_the_field_scaled_by_eight(void)
{
    // Field value 1 is bits 15..3 = 0x0008, which is eight octets in.
    idemip_wr16(pkt + IDEMIP_IP6_FRAG_OFF_OFFS_M, 0x0008u);
    TEST_ASSERT_EQUAL_UINT16(8u, idemip_ip6_frag_offset_bytes(pkt));
    // Field value 175 is 175 << 3 = 0x0578, which is 1400 octets in.
    idemip_wr16(pkt + IDEMIP_IP6_FRAG_OFF_OFFS_M, 0x0578u);
    TEST_ASSERT_EQUAL_UINT16(1400u, idemip_ip6_frag_offset_bytes(pkt));
}

// "M flag  1 = more fragments; 0 = last fragment", the low bit of the field.
void test_fragment_more_flag_is_the_low_bit(void)
{
    idemip_wr16(pkt + IDEMIP_IP6_FRAG_OFF_OFFS_M, 0x0578u);
    TEST_ASSERT_FALSE(idemip_ip6_frag_more(pkt));
    idemip_wr16(pkt + IDEMIP_IP6_FRAG_OFF_OFFS_M, 0x0579u);
    TEST_ASSERT_TRUE(idemip_ip6_frag_more(pkt));
    TEST_ASSERT_EQUAL_UINT16(1400u, idemip_ip6_frag_offset_bytes(pkt));
}

// "Res  2-bit reserved field ... ignored on reception", so neither reserved bit may leak into the
// offset or into the M flag.
void test_fragment_reserved_bits_reach_neither_the_offset_nor_the_flag(void)
{
    idemip_wr16(pkt + IDEMIP_IP6_FRAG_OFF_OFFS_M, (uint16_t)(0x0578u | IDEMIP_IP6_FRAG_RES_MASK));
    TEST_ASSERT_EQUAL_UINT16(1400u, idemip_ip6_frag_offset_bytes(pkt));
    TEST_ASSERT_FALSE(idemip_ip6_frag_more(pkt));
}

// "Identification  32 bits", at offset 4, read a byte at a time.
void test_fragment_identification_is_thirty_two_bits(void)
{
    pkt[IDEMIP_IP6_FRAG_OFF_IDENT + 0u] = 0xDEu;
    pkt[IDEMIP_IP6_FRAG_OFF_IDENT + 1u] = 0xADu;
    pkt[IDEMIP_IP6_FRAG_OFF_IDENT + 2u] = 0xBEu;
    pkt[IDEMIP_IP6_FRAG_OFF_IDENT + 3u] = 0xEFu;
    TEST_ASSERT_EQUAL_HEX32(0xDEADBEEFu, idemip_ip6_frag_ident(pkt));
}

// sec 4.5 (2): the first fragment's offset is zero with M set. Reserved is "Initialized to zero for
// transmission", so build writes it as zero whatever was there before.
void test_fragment_build_writes_the_first_fragment(void)
{
    memset(fragbuf, 0xFFu, IDEMIP_IP6_FRAG_HDR_LEN);
    idemip_ip6_frag_build(fragbuf, IDEMIP_IP6_NH_TCP, 0u, IDEMIP_TRUE, 0x01020304u);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, fragbuf[IDEMIP_IP6_FRAG_OFF_NEXT_HDR]);
    TEST_ASSERT_EQUAL_HEX8(0u, fragbuf[IDEMIP_IP6_FRAG_OFF_RESERVED]);
    TEST_ASSERT_EQUAL_HEX16(0x0001u, idemip_rd16(fragbuf + IDEMIP_IP6_FRAG_OFF_OFFS_M));
    TEST_ASSERT_EQUAL_UINT16(0u, idemip_ip6_frag_offset_bytes(fragbuf));
    TEST_ASSERT_TRUE(idemip_ip6_frag_more(fragbuf));
    TEST_ASSERT_EQUAL_HEX32(0x01020304u, idemip_ip6_frag_ident(fragbuf));
}

// sec 4.5 (2) for the rightmost fragment: M clear, offset in 8-octet units, and the Res bits stay
// zero because the mask clears them.
void test_fragment_build_writes_the_last_fragment(void)
{
    idemip_ip6_frag_build(fragbuf, IDEMIP_IP6_NH_UDP, 1400u, IDEMIP_FALSE, 0xA5A5A5A5u);
    TEST_ASSERT_EQUAL_HEX16(0x0578u, idemip_rd16(fragbuf + IDEMIP_IP6_FRAG_OFF_OFFS_M));
    TEST_ASSERT_EQUAL_UINT16(1400u, idemip_ip6_frag_offset_bytes(fragbuf));
    TEST_ASSERT_FALSE(idemip_ip6_frag_more(fragbuf));
    TEST_ASSERT_EQUAL_HEX8(0u, (uint8_t)(idemip_rd16(fragbuf + IDEMIP_IP6_FRAG_OFF_OFFS_M) & IDEMIP_IP6_FRAG_RES_MASK));
    TEST_ASSERT_EQUAL_HEX32(0xA5A5A5A5u, idemip_ip6_frag_ident(fragbuf));
}

// The field is thirteen bits of 8-octet units, so the largest byte offset it carries is 8191 * 8.
void test_fragment_offset_field_reaches_65528(void)
{
    idemip_ip6_frag_build(fragbuf, IDEMIP_IP6_NH_TCP, 65528u, IDEMIP_FALSE, 0u);
    TEST_ASSERT_EQUAL_HEX16(0xFFF8u, idemip_rd16(fragbuf + IDEMIP_IP6_FRAG_OFF_OFFS_M));
    TEST_ASSERT_EQUAL_UINT16(65528u, idemip_ip6_frag_offset_bytes(fragbuf));
}

// --- sec 4.4, the routing header ---------------------------------------------

// Routing Type at 2 and Segments Left at 3, the two octets that decide how an unrecognized variant
// is answered.
void test_routing_type_and_segments_left_sit_at_two_and_three(void)
{
    lay_ext(0u, IDEMIP_IP6_NH_TCP, 1u);
    pkt[IDEMIP_IP6_RT_OFF_TYPE] = 4u;
    pkt[IDEMIP_IP6_RT_OFF_SEGS_LEFT] = 3u;
    TEST_ASSERT_EQUAL_UINT8(4u, idemip_ip6_rt_type(pkt));
    TEST_ASSERT_EQUAL_UINT8(3u, idemip_ip6_rt_segs_left(pkt));
    TEST_ASSERT_EQUAL_size_t(16u, idemip_ip6_ext_len(pkt));
}

// --- sec 4, the chain walk ---------------------------------------------------

// The first illustration: IPv6 header, Next Header = TCP. No extension header, so the upper-layer
// header begins at 40.
void test_walk_with_no_extension_header_lands_on_the_upper_layer(void)
{
    lay_hdr(IDEMIP_IP6_NH_TCP, 20u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, IDEMIP_IP6_OFF_PAYLOAD + 20u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_IP6_OFF_PAYLOAD, c.offset);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, c.next_hdr);
    TEST_ASSERT_EQUAL_UINT16(0u, c.hops);
    TEST_ASSERT_FALSE(c.fragmented);
    TEST_ASSERT_EQUAL_size_t(0u, idemip_ip6_chain_ext_bytes(&c));
}

// The second illustration: IPv6 header (Next Header = Routing), Routing header (Next Header = TCP),
// TCP. One 8-octet step.
void test_walk_steps_over_a_routing_header(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_ROUTING, 28u);
    lay_ext(at, IDEMIP_IP6_NH_TCP, 0u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 28u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_size_t(48u, c.offset);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, c.next_hdr);
    TEST_ASSERT_EQUAL_UINT16(1u, c.hops);
    TEST_ASSERT_FALSE(c.fragmented);
    TEST_ASSERT_EQUAL_size_t(8u, idemip_ip6_chain_ext_bytes(&c));
}

// The third illustration: IPv6 header (Routing), Routing header (Fragment), Fragment header (TCP),
// fragment of TCP header + data. Two steps, and the Fragment header is located for reassembly.
void test_walk_steps_over_routing_then_fragment(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_ROUTING, 36u);
    lay_ext(at, IDEMIP_IP6_NH_FRAGMENT, 0u);
    idemip_ip6_frag_build(pkt + at + 8u, IDEMIP_IP6_NH_TCP, 0u, IDEMIP_TRUE, 0x11223344u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 36u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_size_t(56u, c.offset);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, c.next_hdr);
    TEST_ASSERT_EQUAL_UINT16(2u, c.hops);
    TEST_ASSERT_TRUE(c.fragmented);
    TEST_ASSERT_EQUAL_size_t(48u, c.frag_hdr);
    TEST_ASSERT_EQUAL_HEX32(0x11223344u, idemip_ip6_frag_ident(pkt + c.frag_hdr));
    TEST_ASSERT_EQUAL_size_t(16u, idemip_ip6_chain_ext_bytes(&c));
}

// sec 4.5 puts Reserved where every other extension header puts Hdr Ext Len, so the walk must size
// a Fragment header at eight from the standard. A Reserved of ff read as a length would claim 2048.
void test_walk_sizes_a_fragment_header_at_eight_not_by_the_second_octet(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_FRAGMENT, 28u);
    idemip_ip6_frag_build(pkt + at, IDEMIP_IP6_NH_TCP, 0u, IDEMIP_TRUE, 0u);
    pkt[at + IDEMIP_IP6_FRAG_OFF_RESERVED] = 0xFFu;
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 28u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_size_t(48u, c.offset);
    TEST_ASSERT_EQUAL_UINT16(1u, c.hops);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, c.next_hdr);
}

// sec 4.5 lays a fragment packet out as "(1) The Per-Fragment headers ... (2) A Fragment header ...
// (3) The fragment itself", and puts "(3) Extension headers, if any, and the Upper-Layer header.
// These headers must be in the first fragment." Past a non-zero Fragment Offset the bytes are data,
// so the walk ends at the Fragment header rather than reading them as headers.
void test_walk_stops_at_a_fragment_header_carrying_a_non_zero_offset(void)
{
    // Next Header 60 on the Fragment header, then eight octets that would decode as a Destination
    // Options header with an option whose action bits are 10, "discard the packet and ... send an
    // ICMP Parameter Problem, Code 2".
    size_t at = lay_hdr(IDEMIP_IP6_NH_FRAGMENT, 16u);
    idemip_ip6_frag_build(pkt + at, IDEMIP_IP6_NH_DSTOPTS, 8u, IDEMIP_FALSE, 0x55667788u);
    pkt[at + 8u] = 0x06u;
    pkt[at + 9u] = 0x00u;
    pkt[at + 10u] = 0x80u;
    for (size_t i = 11u; i < 16u; i++)
    {
        pkt[at + i] = 0u;
    }
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 16u);
    TEST_ASSERT_TRUE_MESSAGE(c.ok, "the fragment is queued for reassembly, not refused");
    TEST_ASSERT_TRUE(c.fragmented);
    TEST_ASSERT_EQUAL_size_t(at, c.frag_hdr);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(at + 8u, c.offset, "the walk ends one Fragment header past its start");
    TEST_ASSERT_EQUAL_UINT16(1u, c.hops);
    TEST_ASSERT_FALSE_MESSAGE(c.refused, "fragment data is not an option stream");
    TEST_ASSERT_EQUAL_HEX32(0x55667788u, idemip_ip6_frag_ident(pkt + c.frag_hdr));

    // The offset-zero fragment is where those headers really are, so the walk does follow them.
    at = lay_hdr(IDEMIP_IP6_NH_FRAGMENT, 16u);
    idemip_ip6_frag_build(pkt + at, IDEMIP_IP6_NH_DSTOPTS, 0u, IDEMIP_TRUE, 0x55667788u);
    pkt[at + 8u] = IDEMIP_IP6_NH_TCP;
    pkt[at + 9u] = 0u;
    pkt[at + 10u] = IDEMIP_IP6_OPT_PADN;
    pkt[at + 11u] = 4u;
    for (size_t i = 12u; i < 16u; i++)
    {
        pkt[at + i] = 0u;
    }
    c = idemip_ip6_walk(pkt, at + 16u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_TRUE(c.fragmented);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, c.next_hdr);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(2u, c.hops, "the first fragment carries the Extension headers");
}

// sec 4.4: "If Segments Left is non-zero, the node must discard the packet and send an ICMP Parameter
// Problem, Code 0, message to the packet's Source Address, pointing to the unrecognized Routing
// Type." Segments Left zero is the case the same section ignores, so the walk records only the first
// Routing header above zero.
void test_walk_records_a_routing_header_with_segments_left(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_ROUTING, 36u);
    lay_ext(at, IDEMIP_IP6_NH_ROUTING, 0u);
    pkt[at + IDEMIP_IP6_RT_OFF_TYPE] = 99u; // a Routing Type this library executes none of
    pkt[at + IDEMIP_IP6_RT_OFF_SEGS_LEFT] = 3u;
    lay_ext(at + 8u, IDEMIP_IP6_NH_TCP, 0u);
    pkt[at + 8u + IDEMIP_IP6_RT_OFF_SEGS_LEFT] = 1u;
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 36u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_TRUE_MESSAGE(c.routed, "a non-zero Segments Left is what sec 4.4 acts on");
    TEST_ASSERT_EQUAL_size_t_MESSAGE(at, c.routing_hdr, "the first such header is the one reported");
    TEST_ASSERT_EQUAL_UINT8(3u, idemip_ip6_rt_segs_left(pkt + c.routing_hdr));

    // Segments Left zero: "ignore the Routing header and proceed to process the next header".
    at = lay_hdr(IDEMIP_IP6_NH_ROUTING, 28u);
    lay_ext(at, IDEMIP_IP6_NH_TCP, 0u);
    pkt[at + IDEMIP_IP6_RT_OFF_SEGS_LEFT] = 0u;
    c = idemip_ip6_walk(pkt, at + 28u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_FALSE(c.routed);
}

// sec 4.2, the highest-order two bits of an Option Type: "00 - skip over this option", "01 - discard
// the packet", "10 - discard the packet and, regardless of whether or not the packet's Destination
// Address was a multicast address, send an ICMP Parameter Problem, Code 2, message to the packet's
// Source Address, pointing to the unrecognized Option Type", "11 - ... only if the packet's
// Destination Address was not a multicast address".
void test_walk_refuses_an_option_whose_action_bits_are_not_skip(void)
{
    static const uint8_t act[3] = {0x40u, 0x80u, 0xC0u}; // 01, 10, 11
    for (size_t i = 0; i < 3u; i++)
    {
        size_t at = lay_hdr(IDEMIP_IP6_NH_DSTOPTS, 16u);
        lay_ext(at, IDEMIP_IP6_NH_TCP, 0u);
        pkt[at + 2u] = (uint8_t)(act[i] | 0x1Fu); // an Option Type this library recognizes none of
        pkt[at + 3u] = 4u;
        for (size_t j = 4u; j < 8u; j++)
        {
            pkt[at + j] = 0u;
        }
        IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 16u);
        TEST_ASSERT_TRUE(c.ok);
        TEST_ASSERT_TRUE_MESSAGE(c.refused, "an action above 00 stops the packet");
        TEST_ASSERT_EQUAL_size_t_MESSAGE(at + 2u, c.opt_hdr, "the pointer names the unrecognized Option Type");
    }

    // "00 - skip over this option and continue processing the header", which PadN carries.
    size_t at = lay_hdr(IDEMIP_IP6_NH_DSTOPTS, 16u);
    lay_ext(at, IDEMIP_IP6_NH_TCP, 0u);
    pkt[at + 2u] = IDEMIP_IP6_OPT_PADN;
    pkt[at + 3u] = 4u;
    for (size_t j = 4u; j < 8u; j++)
    {
        pkt[at + j] = 0u;
    }
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 16u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_FALSE(c.refused);

    // An option whose length runs past its header is a header the walk could not step at all.
    at = lay_hdr(IDEMIP_IP6_NH_DSTOPTS, 16u);
    lay_ext(at, IDEMIP_IP6_NH_TCP, 0u);
    pkt[at + 2u] = IDEMIP_IP6_OPT_PADN;
    pkt[at + 3u] = 200u;
    c = idemip_ip6_walk(pkt, at + 16u);
    TEST_ASSERT_FALSE_MESSAGE(c.ok, "an option running past its header is malformed, not refused");
}

// sec 4.3: Hop-by-Hop Options is "identified by a Next Header value of 0 in the IPv6 header", and
// sec 4.1 restricts it to appear "immediately after an IPv6 header only". First is legal.
void test_walk_steps_over_hop_by_hop_options_when_it_is_first(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_HOPOPT, 16u);
    lay_ext(at, IDEMIP_IP6_NH_ICMPV6, 0u);
    pkt[at + 2u] = IDEMIP_IP6_OPT_PADN;
    pkt[at + 3u] = 4u;
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 16u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_size_t(48u, c.offset);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_ICMPV6, c.next_hdr);
    TEST_ASSERT_EQUAL_UINT16(1u, c.hops);
}

// sec 4: "The same action should be taken if a node encounters a Next Header value of zero in any
// header other than an IPv6 header." The walk stops at the offending header rather than stepping it.
void test_walk_refuses_hop_by_hop_options_below_the_ipv6_header(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_DSTOPTS, 36u);
    lay_ext(at, IDEMIP_IP6_NH_HOPOPT, 0u);
    lay_ext(at + 8u, IDEMIP_IP6_NH_TCP, 0u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 36u);
    TEST_ASSERT_FALSE(c.ok);
    TEST_ASSERT_EQUAL_size_t(48u, c.offset);
    TEST_ASSERT_EQUAL_UINT16(1u, c.hops);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_HOPOPT, c.next_hdr);
}

// sec 4.7: "The value 59 ... indicates that there is nothing following that header." It is not an
// extension header, so the walk completes and reports it.
void test_walk_stops_at_no_next_header(void)
{
    lay_hdr(IDEMIP_IP6_NH_NONE, 0u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, IDEMIP_IP6_OFF_PAYLOAD);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_NONE, c.next_hdr);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_IP6_OFF_PAYLOAD, c.offset);
    TEST_ASSERT_EQUAL_UINT16(0u, c.hops);
}

// A chain of the four in the sec 4.1 recommended order, each one unit long.
void test_walk_steps_the_recommended_order(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_HOPOPT, 52u);
    lay_ext(at, IDEMIP_IP6_NH_DSTOPTS, 0u);
    lay_ext(at + 8u, IDEMIP_IP6_NH_ROUTING, 0u);
    lay_ext(at + 16u, IDEMIP_IP6_NH_FRAGMENT, 0u);
    idemip_ip6_frag_build(pkt + at + 24u, IDEMIP_IP6_NH_TCP, 0u, IDEMIP_TRUE, 7u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 52u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_UINT16(4u, c.hops);
    TEST_ASSERT_EQUAL_size_t(72u, c.offset);
    TEST_ASSERT_EQUAL_size_t(64u, c.frag_hdr);
    TEST_ASSERT_TRUE(c.fragmented);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, c.next_hdr);
    TEST_ASSERT_EQUAL_size_t(32u, idemip_ip6_chain_ext_bytes(&c));
}

// A span too short to hold the two octets an extension header begins with cannot be stepped.
void test_walk_refuses_a_chain_truncated_inside_a_header(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_ROUTING, 8u);
    lay_ext(at, IDEMIP_IP6_NH_TCP, 0u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 4u);
    TEST_ASSERT_FALSE(c.ok);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_IP6_OFF_PAYLOAD, c.offset);
    TEST_ASSERT_EQUAL_UINT16(0u, c.hops);
}

// A Hdr Ext Len claiming more octets than the span holds is refused rather than walked past the end.
void test_walk_refuses_a_header_longer_than_the_span(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_DSTOPTS, 8u);
    lay_ext(at, IDEMIP_IP6_NH_TCP, 5u); // claims 48 octets
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 8u);
    TEST_ASSERT_FALSE(c.ok);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_IP6_OFF_PAYLOAD, c.offset);
}

// Fewer than the forty octets of sec 3 is not a header at all.
void test_walk_refuses_a_span_shorter_than_the_fixed_header(void)
{
    lay_hdr(IDEMIP_IP6_NH_TCP, 20u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, IDEMIP_IPV6_HDR_LEN - 1u);
    TEST_ASSERT_FALSE(c.ok);
    TEST_ASSERT_EQUAL_size_t(0u, c.offset);
    TEST_ASSERT_EQUAL_UINT16(0u, c.hops);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_NONE, c.next_hdr);
}

// The walk reads and never writes, so the packet is unchanged afterwards.
void test_walk_does_not_write_the_packet(void)
{
    uint8_t before[PKT_USED];
    size_t at = lay_hdr(IDEMIP_IP6_NH_ROUTING, 28u);
    lay_ext(at, IDEMIP_IP6_NH_TCP, 0u);
    memcpy(before, pkt, PKT_USED);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 28u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(before, pkt, PKT_USED);
}

// --- sec 8.1, the pseudo-header ----------------------------------------------

// "the length used in the pseudo-header is the Payload Length from the IPv6 header, minus the length
// of any extension headers present between the IPv6 header and the upper-layer header."
void test_upper_layer_length_subtracts_the_extension_headers(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_ROUTING, 28u);
    lay_ext(at, IDEMIP_IP6_NH_TCP, 0u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 28u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_UINT32(20u, idemip_ip6_upper_len(pkt, &c));
}

// With no extension header the two are the same number.
void test_upper_layer_length_is_the_payload_length_with_no_extensions(void)
{
    lay_hdr(IDEMIP_IP6_NH_UDP, 1000u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, IDEMIP_IP6_OFF_PAYLOAD + 1000u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_UINT32(1000u, idemip_ip6_upper_len(pkt, &c));
}

// A Payload Length shorter than the headers already stepped is a sender's claim, not a fact, so the
// subtraction floors at zero instead of wrapping.
void test_upper_layer_length_floors_at_zero(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_ROUTING, 4u);
    lay_ext(at, IDEMIP_IP6_NH_TCP, 0u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 8u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_EQUAL_UINT32(0u, idemip_ip6_upper_len(pkt, &c));
}

// "The Next Header value in the pseudo-header identifies the upper-layer protocol ... It will differ
// from the Next Header value in the IPv6 header if there are extension headers between".
void test_the_pseudo_header_next_header_is_the_upper_layer_not_the_packets(void)
{
    size_t at = lay_hdr(IDEMIP_IP6_NH_ROUTING, 28u);
    lay_ext(at, IDEMIP_IP6_NH_TCP, 0u);
    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 28u);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_ROUTING, idemip_ip6_next_hdr(pkt));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, c.next_hdr);
}

// The figure is 16 octets of source, 16 of destination, a 32-bit Upper-Layer Packet Length, 24 zero
// bits and the Next Header. Summed as those forty bytes, it must equal what the accumulator reaches.
void test_pseudo_header_sum_matches_the_section_8_1_figure(void)
{
    uint8_t ph[40];
    memcpy(ph, g_src, IDEMIP_IP6_ADDR_LEN);
    memcpy(ph + 16, g_dst, IDEMIP_IP6_ADDR_LEN);
    idemip_wr32(ph + 32, 20u);
    ph[36] = 0u;
    ph[37] = 0u;
    ph[38] = 0u;
    ph[39] = IDEMIP_IP6_NH_TCP;

    uint16_t laid = idemip_cksum_final(idemip_cksum_accum(0u, ph, sizeof ph));
    uint16_t accumulated = idemip_cksum_final(idemip_ip6_pseudo_accum(0u, g_src, g_dst, 20u, IDEMIP_IP6_NH_TCP));
    TEST_ASSERT_EQUAL_HEX16(laid, accumulated);
}

// The 32-bit length spans two 16-bit words, so a length above 65535 has to contribute its high half.
void test_pseudo_header_sums_both_halves_of_the_length(void)
{
    uint8_t ph[40];
    memcpy(ph, g_src, IDEMIP_IP6_ADDR_LEN);
    memcpy(ph + 16, g_dst, IDEMIP_IP6_ADDR_LEN);
    idemip_wr32(ph + 32, 0x00012345u);
    ph[36] = 0u;
    ph[37] = 0u;
    ph[38] = 0u;
    ph[39] = IDEMIP_IP6_NH_ICMPV6;

    uint16_t laid = idemip_cksum_final(idemip_cksum_accum(0u, ph, sizeof ph));
    uint16_t accumulated =
        idemip_cksum_final(idemip_ip6_pseudo_accum(0u, g_src, g_dst, 0x00012345u, IDEMIP_IP6_NH_ICMPV6));
    TEST_ASSERT_EQUAL_HEX16(laid, accumulated);
}

// RFC 8200 sec 4.2: every option but Pad1 is "Option Type, Opt Data Len, Option Data", so an option
// area that ends before the length octet has no length to read, and one whose length runs past the
// area is not inside it. Both are a header this walk could not step, which it reports without
// naming an Option Type - the caller tells the two apart by whether the pointer moved.
void test_an_option_area_that_ends_inside_an_option_is_malformed(void)
{
    uint8_t opts[8];
    size_t bad;

    // An Option Type at the last octet of the area, with no length octet behind it.
    memset(opts, 0, sizeof opts);
    opts[0] = IDEMIP_IP6_OPT_PADN;
    opts[1] = 0u;
    opts[2] = IDEMIP_IP6_OPT_PADN;
    bad = 0xFFFFu;
    TEST_ASSERT_TRUE_MESSAGE(idemip_ip6_opts_refused(opts, 0u, 3u, &bad),
                             "an area ending before an option's length octet was walked through");
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0xFFFFu, bad, "a malformed area named an Option Type");

    // An option whose length runs past the area it stands in.
    memset(opts, 0, sizeof opts);
    opts[0] = IDEMIP_IP6_OPT_PADN;
    opts[1] = 6u;
    bad = 0xFFFFu;
    TEST_ASSERT_TRUE_MESSAGE(idemip_ip6_opts_refused(opts, 0u, 4u, &bad),
                             "an option claiming more octets than the area holds was walked through");
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0xFFFFu, bad, "an option past the area named an Option Type");

    // A Pad1 at the last octet is one octet and needs no length, so the area is walked to its end.
    memset(opts, 0, sizeof opts);
    opts[0] = IDEMIP_IP6_OPT_PAD1;
    opts[1] = IDEMIP_IP6_OPT_PAD1;
    bad = 0xFFFFu;
    TEST_ASSERT_FALSE_MESSAGE(idemip_ip6_opts_refused(opts, 0u, 2u, &bad),
                              "an area of Pad1 options was read as malformed");
}

// RFC 8200 sec 4.2: an option the node does not recognize with action bits above 00 stops the packet,
// and the Parameter Problem it answers with points at "the unrecognized Option Type". Only the first
// such option is pointed at: a packet carrying two headers of options is stopped by the first one,
// and the second is not walked for another.
void test_the_first_refused_option_is_the_one_the_walk_keeps(void)
{
    // A Hop-by-Hop header carrying a refused option, then a Destination Options header carrying one.
    size_t at = lay_hdr(IDEMIP_IP6_NH_HOPOPT, 36u);
    lay_ext(at, IDEMIP_IP6_NH_DSTOPTS, 0u);
    pkt[at + 2u] = (uint8_t)(IDEMIP_IP6_OPT_ACT_DISCARD | 0x0Au);
    pkt[at + 3u] = 4u;
    const size_t second = at + 8u;
    lay_ext(second, IDEMIP_IP6_NH_TCP, 0u);
    pkt[second + 2u] = (uint8_t)(IDEMIP_IP6_OPT_ACT_DISCARD_ICMP | 0x0Bu);
    pkt[second + 3u] = 4u;

    IdemIpIp6Chain c = idemip_ip6_walk(pkt, at + 36u);
    TEST_ASSERT_TRUE(c.ok);
    TEST_ASSERT_TRUE_MESSAGE(c.refused, "an option above skip did not stop the packet");
    TEST_ASSERT_EQUAL_size_t_MESSAGE(at + 2u, c.opt_hdr,
                                     "the walk pointed at an option behind the first one it refused");
}
