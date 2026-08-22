// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 791, the internet header. The vectors are the RFC's own figures:
//
//   Figure 4  (sec 3.1)     the field map: which octet every field starts at
//   Figure 5  (Appendix A)  Example 1, the minimal data carrying datagram, TL 21
//   Figure 6  (Appendix A)  Example 2, a 452-octet datagram, TL 472
//   Figure 7  (Appendix A)  Example 2's first fragment, TL 276, MF set, FO 0
//   Figure 8  (Appendix A)  Example 2's second fragment, TL 216, MF clear, FO 32
//   Figure 9  (Appendix A)  Example 3, a datagram with options, IHL 8, TL 576
//
// The figures leave Type of Service and both addresses unspecified, so the suite names them. The
// two header checksums are computed by hand from RFC 791 sec 3.1's algorithm, in the comments where
// they are used, so they check idemip_ip4_recksum rather than repeat it.
//
// RFC 1122 sec 3.2.1.1 and sec 3.2.1.2 are the receive checks: version and header checksum.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/checksum.h"
#include "src/ip/ipv4.h"

#include <string.h>
#include <unity.h>
#include "src/common_defines.h"
#include "src/ip/ipv4_defines.h"

// The figures leave the addresses unspecified. 10.0.0.1 and 10.0.0.2.
#define VEC_SRC 0x0A000001u
#define VEC_DST 0x0A000002u

// RFC 791 Appendix A gives Identification = 111 in every example.
#define VEC_ID 111u

#define CANARY 0x5Au

static void arm(uint8_t *b, size_t cap, size_t used)
{
    memset(b, 0, used);
    memset(b + used, CANARY, cap - used);
}

static void check_canary(const uint8_t *b, size_t cap, size_t used)
{
    for (size_t i = used; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, b[i], "a write landed past the header");
    }
}

// Figure 5: Ver 4, IHL 5, TL 21, ID 111, Flg 0, FO 0, Time 123, Protocol 1.
static void build_figure5(uint8_t *h)
{
    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.tos = 0u;
    f.total_len = 21u;
    f.id = VEC_ID;
    f.flags_frag = 0u;
    f.ttl = 123u;
    f.proto = IDEMIP_IP4_PROTO_ICMP;
    f.src = VEC_SRC;
    f.dst = VEC_DST;
    idemip_ip4_build(h, &f);
}

// Figure 6: Ver 4, IHL 5, TL 472, ID 111, Flg 0, FO 0, Time 123, Protocol 6.
static void build_figure6(uint8_t *h)
{
    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.total_len = 472u;
    f.id = VEC_ID;
    f.ttl = 123u;
    f.proto = IDEMIP_IP4_PROTO_TCP;
    f.src = VEC_SRC;
    f.dst = VEC_DST;
    idemip_ip4_build(h, &f);
}

// Figure 7: TL 276, Flg 1 (MF), FO 0, Time 119, Protocol 6.
static void build_figure7(uint8_t *h)
{
    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.total_len = 276u;
    f.id = VEC_ID;
    f.flags_frag = IDEMIP_IP4_FLAG_MF;
    f.ttl = 119u;
    f.proto = IDEMIP_IP4_PROTO_TCP;
    f.src = VEC_SRC;
    f.dst = VEC_DST;
    idemip_ip4_build(h, &f);
}

// Figure 8: TL 216, Flg 0, FO 32, Time 119, Protocol 6.
static void build_figure8(uint8_t *h)
{
    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.total_len = 216u;
    f.id = VEC_ID;
    f.flags_frag = 32u;
    f.ttl = 119u;
    f.proto = IDEMIP_IP4_PROTO_TCP;
    f.src = VEC_SRC;
    f.dst = VEC_DST;
    idemip_ip4_build(h, &f);
}

void setUp(void)
{
    // Nothing to arrange: every case builds the state it needs.
}
void tearDown(void)
{
    // Nothing to release: this suite holds no allocation, only file-scope storage.
}

// --- the field map, RFC 791 sec 3.1 Figure 4 ---------------------------------

// Figure 4's rows are four octets each: Version/IHL, Type of Service, Total Length in the first;
// Identification, Flags/Fragment Offset in the second; Time to Live, Protocol, Header Checksum in
// the third; then the two addresses; then the options.
void test_rfc791_figure4_offsets(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_IP4_OFF_VER_IHL);
    TEST_ASSERT_EQUAL_size_t(1u, IDEMIP_IP4_OFF_TOS);
    TEST_ASSERT_EQUAL_size_t(2u, IDEMIP_IP4_OFF_TOTAL_LEN);
    TEST_ASSERT_EQUAL_size_t(4u, IDEMIP_IP4_OFF_ID);
    TEST_ASSERT_EQUAL_size_t(6u, IDEMIP_IP4_OFF_FLAGS_FRAG);
    TEST_ASSERT_EQUAL_size_t(8u, IDEMIP_IP4_OFF_TTL);
    TEST_ASSERT_EQUAL_size_t(9u, IDEMIP_IP4_OFF_PROTO);
    TEST_ASSERT_EQUAL_size_t(10u, IDEMIP_IP4_OFF_CKSUM);
    TEST_ASSERT_EQUAL_size_t(12u, IDEMIP_IP4_OFF_SRC);
    TEST_ASSERT_EQUAL_size_t(16u, IDEMIP_IP4_OFF_DST);
    TEST_ASSERT_EQUAL_size_t(20u, IDEMIP_IP4_OFF_OPTIONS);
    TEST_ASSERT_EQUAL_size_t(20u, IDEMIP_IPV4_HDR_LEN);
}

// Each accessor reads its own octets and no others: one field is set in an otherwise zero header
// and every other accessor must still read zero.
void test_each_accessor_reads_only_its_own_field(void)
{
    uint8_t h[24];

    memset(h, 0, sizeof h);
    idemip_ip4_set_total_len(h, 0xFFFFu);
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu, idemip_ip4_total_len(h));
    TEST_ASSERT_EQUAL_UINT8(0u, h[IDEMIP_IP4_OFF_VER_IHL]);
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_ip4_tos(h));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_ip4_id(h));

    memset(h, 0, sizeof h);
    idemip_ip4_set_id(h, 0xFFFFu);
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu, idemip_ip4_id(h));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_ip4_total_len(h));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_ip4_flags_frag(h));

    memset(h, 0, sizeof h);
    idemip_ip4_set_flags_frag(h, 0xFFFFu);
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu, idemip_ip4_flags_frag(h));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_ip4_id(h));
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_ip4_ttl(h));

    memset(h, 0, sizeof h);
    idemip_ip4_set_ttl(h, 0xFFu);
    TEST_ASSERT_EQUAL_UINT8(0xFFu, idemip_ip4_ttl(h));
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_ip4_proto(h));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_ip4_flags_frag(h));

    memset(h, 0, sizeof h);
    idemip_ip4_set_proto(h, 0xFFu);
    TEST_ASSERT_EQUAL_UINT8(0xFFu, idemip_ip4_proto(h));
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_ip4_ttl(h));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_ip4_cksum(h));

    memset(h, 0, sizeof h);
    idemip_ip4_set_cksum(h, 0xFFFFu);
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu, idemip_ip4_cksum(h));
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_ip4_proto(h));
    TEST_ASSERT_EQUAL_HEX32(0u, idemip_ip4_src(h));

    memset(h, 0, sizeof h);
    idemip_ip4_set_src(h, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, idemip_ip4_src(h));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_ip4_cksum(h));
    TEST_ASSERT_EQUAL_HEX32(0u, idemip_ip4_dst(h));

    memset(h, 0, sizeof h);
    idemip_ip4_set_dst(h, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, idemip_ip4_dst(h));
    TEST_ASSERT_EQUAL_HEX32(0u, idemip_ip4_src(h));
    TEST_ASSERT_EQUAL_UINT8(0u, h[IDEMIP_IP4_OFF_OPTIONS]);
}

// Version 4 in the high nibble and IHL in the low one, so 0x45 is the option-free header and 0x48
// is Figure 9's eight-word one.
void test_version_and_ihl_share_the_first_octet(void)
{
    uint8_t h[20];

    memset(h, 0, sizeof h);
    idemip_ip4_set_ver_ihl(h, 5u);
    TEST_ASSERT_EQUAL_HEX8(0x45u, h[IDEMIP_IP4_OFF_VER_IHL]);
    TEST_ASSERT_EQUAL_UINT8(4u, idemip_ip4_version(h));
    TEST_ASSERT_EQUAL_UINT8(5u, idemip_ip4_ihl(h));
    TEST_ASSERT_EQUAL_size_t(20u, idemip_ip4_hdr_len(h));

    idemip_ip4_set_ver_ihl(h, 8u);
    TEST_ASSERT_EQUAL_HEX8(0x48u, h[IDEMIP_IP4_OFF_VER_IHL]);
    TEST_ASSERT_EQUAL_UINT8(4u, idemip_ip4_version(h));
    TEST_ASSERT_EQUAL_UINT8(8u, idemip_ip4_ihl(h));
    TEST_ASSERT_EQUAL_size_t(32u, idemip_ip4_hdr_len(h));

    idemip_ip4_set_ver_ihl(h, 15u);
    TEST_ASSERT_EQUAL_HEX8(0x4Fu, h[IDEMIP_IP4_OFF_VER_IHL]);
    TEST_ASSERT_EQUAL_size_t(60u, idemip_ip4_hdr_len(h));
}

// RFC 791 sec 3.1: "the minimum value for a correct header is 5", and IHL is 4 bits so 15 is the
// most. RFC 791 sec 3.2 fixes the byte figure: "an internet header may be up to 60 octets".
void test_ihl_bounds_are_five_through_fifteen(void)
{
    uint8_t h[20];
    memset(h, 0, sizeof h);

    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_IP4_IHL_MIN);
    TEST_ASSERT_EQUAL_UINT8(15u, IDEMIP_IP4_IHL_MAX);
    TEST_ASSERT_EQUAL_size_t(60u, IDEMIP_IP4_HDR_MAX);

    for (uint8_t ihl = 0u; ihl <= 15u; ihl++)
    {
        idemip_ip4_set_ver_ihl(h, ihl);
        if (ihl < IDEMIP_IP4_IHL_MIN)
        {
            TEST_ASSERT_FALSE_MESSAGE(idemip_ip4_ihl_ok(h), "an IHL below 5 was accepted");
        }
        else
        {
            TEST_ASSERT_TRUE_MESSAGE(idemip_ip4_ihl_ok(h), "an IHL of 5 through 15 was refused");
        }
    }
}

// RFC 791 sec 3.1: the header is measured "in 32 bit words", so the byte count is the word count
// shifted up by two, and the shift is exactly the multiply.
void test_ihl_word_count_scales_by_a_shift_of_two(void)
{
    for (unsigned ihl = 0u; ihl <= 15u; ihl++)
    {
        TEST_ASSERT_EQUAL_size_t(ihl * 4u, IDEMIP_IP4_HDR_BYTES(ihl));
        TEST_ASSERT_EQUAL_size_t(ihl << IDEMIP_IP4_IHL_SHIFT, IDEMIP_IP4_HDR_BYTES(ihl));
    }
    TEST_ASSERT_EQUAL_size_t(20u, IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN));
    TEST_ASSERT_EQUAL_size_t(60u, IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MAX));
}

// --- flags and fragment offset, RFC 791 sec 3.1 ------------------------------

// "Bit 0: reserved, must be zero. Bit 1: (DF)... Bit 2: (MF)..." Bit 0 is the most significant of
// the 16-bit field, so the three land on 0x8000, 0x4000 and 0x2000 and the offset keeps 13 bits.
void test_flag_bit_positions(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x8000u, IDEMIP_IP4_FLAG_RESERVED);
    TEST_ASSERT_EQUAL_HEX16(0x4000u, IDEMIP_IP4_FLAG_DF);
    TEST_ASSERT_EQUAL_HEX16(0x2000u, IDEMIP_IP4_FLAG_MF);
    TEST_ASSERT_EQUAL_HEX16(0x1FFFu, IDEMIP_IP4_FRAG_OFF_MASK);
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu, (uint16_t)(IDEMIP_IP4_FLAG_RESERVED | IDEMIP_IP4_FLAG_DF | IDEMIP_IP4_FLAG_MF |
                                                IDEMIP_IP4_FRAG_OFF_MASK));
    TEST_ASSERT_EQUAL_HEX16(0u, (uint16_t)(IDEMIP_IP4_FRAG_OFF_MASK &
                                           (IDEMIP_IP4_FLAG_RESERVED | IDEMIP_IP4_FLAG_DF | IDEMIP_IP4_FLAG_MF)));
}

// Each flag predicate reads its own bit: one bit set at a time, and the offset stays zero.
void test_each_flag_predicate_reads_its_own_bit(void)
{
    uint8_t h[20];
    memset(h, 0, sizeof h);

    idemip_ip4_set_flags_frag(h, IDEMIP_IP4_FLAG_RESERVED);
    TEST_ASSERT_TRUE(idemip_ip4_reserved(h));
    TEST_ASSERT_FALSE(idemip_ip4_df(h));
    TEST_ASSERT_FALSE(idemip_ip4_mf(h));
    TEST_ASSERT_EQUAL_UINT16(0u, idemip_ip4_frag_units(h));

    idemip_ip4_set_flags_frag(h, IDEMIP_IP4_FLAG_DF);
    TEST_ASSERT_FALSE(idemip_ip4_reserved(h));
    TEST_ASSERT_TRUE(idemip_ip4_df(h));
    TEST_ASSERT_FALSE(idemip_ip4_mf(h));
    TEST_ASSERT_EQUAL_UINT16(0u, idemip_ip4_frag_units(h));

    idemip_ip4_set_flags_frag(h, IDEMIP_IP4_FLAG_MF);
    TEST_ASSERT_FALSE(idemip_ip4_reserved(h));
    TEST_ASSERT_FALSE(idemip_ip4_df(h));
    TEST_ASSERT_TRUE(idemip_ip4_mf(h));
    TEST_ASSERT_EQUAL_UINT16(0u, idemip_ip4_frag_units(h));

    // The whole offset set leaves every flag clear.
    idemip_ip4_set_flags_frag(h, IDEMIP_IP4_FRAG_OFF_MASK);
    TEST_ASSERT_FALSE(idemip_ip4_reserved(h));
    TEST_ASSERT_FALSE(idemip_ip4_df(h));
    TEST_ASSERT_FALSE(idemip_ip4_mf(h));
    TEST_ASSERT_EQUAL_UINT16(0x1FFFu, idemip_ip4_frag_units(h));
}

// RFC 791 sec 3.1: the offset "is measured in units of 8 octets (64 bits)". RFC 791 sec 3.2: "2**13
// = 8192 fragments of 8 octets each for a total of 65,536 octets."
void test_fragment_offset_is_units_of_eight_octets(void)
{
    uint8_t h[20];
    memset(h, 0, sizeof h);

    TEST_ASSERT_EQUAL_size_t(8u, IDEMIP_IP4_FRAG_UNIT);
    TEST_ASSERT_EQUAL_size_t(8u, (size_t)1u << IDEMIP_IP4_FRAG_SHIFT);
    TEST_ASSERT_EQUAL_size_t(8192u, IDEMIP_IP4_FRAG_MAX_UNITS);
    TEST_ASSERT_EQUAL_size_t(65536u, (size_t)IDEMIP_IP4_FRAG_MAX_UNITS * IDEMIP_IP4_FRAG_UNIT);

    idemip_ip4_set_flags_frag(h, 0u);
    TEST_ASSERT_EQUAL_UINT32(0u, idemip_ip4_frag_offset_bytes(h));

    idemip_ip4_set_flags_frag(h, 1u);
    TEST_ASSERT_EQUAL_UINT32(8u, idemip_ip4_frag_offset_bytes(h));

    // Every flag set must not leak into the offset.
    idemip_ip4_set_flags_frag(h, (uint16_t)(IDEMIP_IP4_FLAG_RESERVED | IDEMIP_IP4_FLAG_DF | IDEMIP_IP4_FLAG_MF | 1u));
    TEST_ASSERT_EQUAL_UINT32(8u, idemip_ip4_frag_offset_bytes(h));

    idemip_ip4_set_flags_frag(h, IDEMIP_IP4_FRAG_OFF_MASK);
    TEST_ASSERT_EQUAL_UINT32(65528u, idemip_ip4_frag_offset_bytes(h));
    TEST_ASSERT_EQUAL_UINT32(8191u * 8u, idemip_ip4_frag_offset_bytes(h));
}

// RFC 791 sec 3.2: "an unfragmented datagram has all zero fragmentation information (MF = 0,
// fragment offset = 0)", so either one nonzero makes a fragment and DF alone does not.
void test_unfragmented_has_all_zero_fragmentation_information(void)
{
    uint8_t h[20];
    memset(h, 0, sizeof h);

    idemip_ip4_set_flags_frag(h, 0u);
    TEST_ASSERT_FALSE(idemip_ip4_is_fragment(h));

    idemip_ip4_set_flags_frag(h, IDEMIP_IP4_FLAG_DF);
    TEST_ASSERT_FALSE_MESSAGE(idemip_ip4_is_fragment(h), "DF alone is not fragmentation information");

    idemip_ip4_set_flags_frag(h, IDEMIP_IP4_FLAG_MF);
    TEST_ASSERT_TRUE(idemip_ip4_is_fragment(h));

    idemip_ip4_set_flags_frag(h, 1u);
    TEST_ASSERT_TRUE(idemip_ip4_is_fragment(h));
}

// --- Appendix A, Figure 5: the minimal data carrying datagram ----------------

// "the internet header consists of five 32 bit words, and the total length of the datagram is 21
// octets. This datagram is a complete datagram (not a fragment)."
//
// The checksum, by RFC 791 sec 3.1's algorithm over the ten words with the field zero:
//   4500 + 0015 + 006f + 0000 + 7b01 + 0000 + 0a00 + 0001 + 0a00 + 0002 = d488, ~d488 = 2b77
void test_rfc791_figure5_minimal_datagram(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 21u);
    build_figure5(buf);

    TEST_ASSERT_EQUAL_UINT8(4u, idemip_ip4_version(buf));
    TEST_ASSERT_EQUAL_UINT8(5u, idemip_ip4_ihl(buf));
    TEST_ASSERT_EQUAL_size_t(20u, idemip_ip4_hdr_len(buf));
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_ip4_tos(buf));
    TEST_ASSERT_EQUAL_UINT16(21u, idemip_ip4_total_len(buf));
    TEST_ASSERT_EQUAL_UINT16(111u, idemip_ip4_id(buf));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_ip4_flags_frag(buf));
    TEST_ASSERT_EQUAL_UINT8(123u, idemip_ip4_ttl(buf));
    TEST_ASSERT_EQUAL_UINT8(1u, idemip_ip4_proto(buf));
    TEST_ASSERT_EQUAL_HEX32(VEC_SRC, idemip_ip4_src(buf));
    TEST_ASSERT_EQUAL_HEX32(VEC_DST, idemip_ip4_dst(buf));

    // "a complete datagram (not a fragment)"
    TEST_ASSERT_FALSE(idemip_ip4_is_fragment(buf));
    TEST_ASSERT_EQUAL_UINT32(0u, idemip_ip4_frag_offset_bytes(buf));

    // One data octet: 21 total less the 20-octet header.
    TEST_ASSERT_EQUAL_UINT16(1u, idemip_ip4_payload_len(buf));

    TEST_ASSERT_EQUAL_HEX16(0x2B77u, idemip_ip4_cksum(buf));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(buf, 21u));

    // The build wrote the twenty header octets and nothing else.
    check_canary(buf, sizeof buf, 21u);
    TEST_ASSERT_EQUAL_UINT8(0u, buf[20]);
}

// --- Appendix A, Figures 6, 7 and 8: fragmentation ---------------------------

// Figure 6: 452 data octets in a datagram of total length 472.
void test_rfc791_figure6_moderate_datagram(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 20u);
    build_figure6(buf);

    TEST_ASSERT_EQUAL_UINT8(5u, idemip_ip4_ihl(buf));
    TEST_ASSERT_EQUAL_UINT16(472u, idemip_ip4_total_len(buf));
    TEST_ASSERT_EQUAL_UINT16(111u, idemip_ip4_id(buf));
    TEST_ASSERT_EQUAL_UINT8(123u, idemip_ip4_ttl(buf));
    TEST_ASSERT_EQUAL_UINT8(6u, idemip_ip4_proto(buf));
    TEST_ASSERT_FALSE(idemip_ip4_is_fragment(buf));

    // "a moderate size internet datagram (452 data octets)"
    TEST_ASSERT_EQUAL_UINT16(452u, idemip_ip4_payload_len(buf));
    check_canary(buf, sizeof buf, 20u);
}

// Figure 7: "the first fragment that results from splitting the datagram after 256 data octets."
// Flg=1 is the 3-bit flags field carrying MF alone, TL 276, FO 0, Time 119.
//
// The checksum, by RFC 791 sec 3.1's algorithm with the field zero:
//   4500 + 0114 + 006f + 2000 + 7706 + 0000 + 0a00 + 0001 + 0a00 + 0002 = f18c, ~f18c = 0e73
void test_rfc791_figure7_first_fragment(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 20u);
    build_figure7(buf);

    TEST_ASSERT_EQUAL_UINT16(276u, idemip_ip4_total_len(buf));
    TEST_ASSERT_EQUAL_UINT16(111u, idemip_ip4_id(buf));
    TEST_ASSERT_EQUAL_UINT8(119u, idemip_ip4_ttl(buf));
    TEST_ASSERT_EQUAL_UINT8(6u, idemip_ip4_proto(buf));

    TEST_ASSERT_TRUE(idemip_ip4_mf(buf));
    TEST_ASSERT_FALSE(idemip_ip4_df(buf));
    TEST_ASSERT_FALSE(idemip_ip4_reserved(buf));
    TEST_ASSERT_EQUAL_UINT16(0u, idemip_ip4_frag_units(buf));
    TEST_ASSERT_EQUAL_UINT32(0u, idemip_ip4_frag_offset_bytes(buf));
    TEST_ASSERT_TRUE(idemip_ip4_is_fragment(buf));

    // 256 data octets
    TEST_ASSERT_EQUAL_UINT16(256u, idemip_ip4_payload_len(buf));

    TEST_ASSERT_EQUAL_HEX16(0x0E73u, idemip_ip4_cksum(buf));
    check_canary(buf, sizeof buf, 20u);
}

// Figure 8: the second fragment. Flg=0, "Fragment Offset = 32", TL 216. The offset counts eight-
// octet units, so 32 units is byte 256, exactly where the first fragment's data ended.
void test_rfc791_figure8_second_fragment(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 20u);
    build_figure8(buf);

    TEST_ASSERT_EQUAL_UINT16(216u, idemip_ip4_total_len(buf));
    TEST_ASSERT_EQUAL_UINT16(111u, idemip_ip4_id(buf));
    TEST_ASSERT_EQUAL_UINT8(119u, idemip_ip4_ttl(buf));

    TEST_ASSERT_FALSE(idemip_ip4_mf(buf));
    TEST_ASSERT_EQUAL_UINT16(32u, idemip_ip4_frag_units(buf));
    TEST_ASSERT_EQUAL_UINT32(256u, idemip_ip4_frag_offset_bytes(buf));
    TEST_ASSERT_TRUE_MESSAGE(idemip_ip4_is_fragment(buf), "a nonzero offset is fragmentation information");

    // 196 data octets
    TEST_ASSERT_EQUAL_UINT16(196u, idemip_ip4_payload_len(buf));
    check_canary(buf, sizeof buf, 20u);
}

// The two fragments account for Figure 6's data exactly: 256 + 196 = 452, and the second starts
// where the first ended.
void test_rfc791_appendix_a_fragments_cover_the_original(void)
{
    uint8_t whole[32];
    uint8_t first[32];
    uint8_t second[32];
    memset(whole, 0, sizeof whole);
    memset(first, 0, sizeof first);
    memset(second, 0, sizeof second);
    build_figure6(whole);
    build_figure7(first);
    build_figure8(second);

    TEST_ASSERT_EQUAL_UINT16(idemip_ip4_payload_len(whole),
                             (uint16_t)(idemip_ip4_payload_len(first) + idemip_ip4_payload_len(second)));
    TEST_ASSERT_EQUAL_UINT32(idemip_ip4_payload_len(first), idemip_ip4_frag_offset_bytes(second));

    // One Identification ties the fragments to the datagram (RFC 791 sec 3.2).
    TEST_ASSERT_EQUAL_UINT16(idemip_ip4_id(whole), idemip_ip4_id(first));
    TEST_ASSERT_EQUAL_UINT16(idemip_ip4_id(whole), idemip_ip4_id(second));
    TEST_ASSERT_EQUAL_HEX32(idemip_ip4_src(whole), idemip_ip4_src(second));
    TEST_ASSERT_EQUAL_HEX32(idemip_ip4_dst(whole), idemip_ip4_dst(second));
    TEST_ASSERT_EQUAL_UINT8(idemip_ip4_proto(whole), idemip_ip4_proto(second));
}

// RFC 791 sec 3.2's example fragmentation procedure, for Figure 6 split at MTU 280:
//   NFB <- (MTU-IHL*4)/8;  TL <- (IHL*4)+(NFB*8);  FO <- OFO + NFB;  TL <- OTL - NFB*8 - 0
// The divide by 8 and the multiply by 8 are exactly the shift by three.
void test_rfc791_example_fragmentation_procedure(void)
{
    const unsigned mtu = 280u;
    const unsigned ihl = 5u;
    const unsigned nfb = (mtu - (ihl << IDEMIP_IP4_IHL_SHIFT)) >> IDEMIP_IP4_FRAG_SHIFT;

    TEST_ASSERT_EQUAL_UINT((mtu - ihl * 4u) / 8u, nfb);
    TEST_ASSERT_EQUAL_UINT(32u, nfb);

    // Figure 7's Total Length.
    TEST_ASSERT_EQUAL_UINT(276u, (ihl << IDEMIP_IP4_IHL_SHIFT) + (nfb << IDEMIP_IP4_FRAG_SHIFT));
    // Figure 8's Total Length and Fragment Offset.
    TEST_ASSERT_EQUAL_UINT(216u, 472u - (nfb << IDEMIP_IP4_FRAG_SHIFT));
    TEST_ASSERT_EQUAL_UINT(32u, 0u + nfb);

    // RFC 791 sec 3.2: "If an internet datagram is fragmented, its data portion must be broken on 8
    // octet boundaries", so the first fragment's data is a whole number of units.
    uint8_t first[32];
    memset(first, 0, sizeof first);
    build_figure7(first);
    TEST_ASSERT_EQUAL_UINT16(0u, (uint16_t)(idemip_ip4_payload_len(first) & (IDEMIP_IP4_FRAG_UNIT - 1u)));
}

// --- Appendix A, Figure 9: a datagram with options ---------------------------

// "Ver= 4 |IHL= 8 ... Total Length = 576", then twelve option octets: a 3-octet option, a 4-octet
// option, No Operation (Opt. Code = 1), a 3-octet option, End of Option list (Opt. Code = 0). The
// figure leaves the other two codes unspecified; the suite writes Record Route (class 0 number 7)
// and Internet Timestamp (class 2 number 4) from RFC 791 sec 3.1's option table.
void test_rfc791_figure9_options_datagram(void)
{
    static const uint8_t opts[12] = {0x07u, 3u, 0x00u, 0x07u, 4u, 0x00u, 0x00u, 1u, 0x44u, 3u, 0x00u, 0u};
    uint8_t buf[584];
    arm(buf, sizeof buf, 576u);

    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.total_len = 576u;
    f.id = VEC_ID;
    f.ttl = 123u;
    f.proto = IDEMIP_IP4_PROTO_TCP;
    f.src = VEC_SRC;
    f.dst = VEC_DST;
    idemip_ip4_build(buf, &f);

    // The options raise IHL from 5 to 8 words, and the checksum is taken again over all of it.
    memcpy(buf + IDEMIP_IP4_OFF_OPTIONS, opts, sizeof opts);
    idemip_ip4_set_ver_ihl(buf, 8u);
    idemip_ip4_recksum(buf);

    TEST_ASSERT_EQUAL_UINT8(4u, idemip_ip4_version(buf));
    TEST_ASSERT_EQUAL_UINT8(8u, idemip_ip4_ihl(buf));
    TEST_ASSERT_EQUAL_size_t(32u, idemip_ip4_hdr_len(buf));
    TEST_ASSERT_EQUAL_size_t(12u, idemip_ip4_options_len(buf));
    TEST_ASSERT_EQUAL_PTR(buf + 20, idemip_ip4_options(buf));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(opts, idemip_ip4_options(buf), 12);

    TEST_ASSERT_EQUAL_UINT16(576u, idemip_ip4_total_len(buf));
    TEST_ASSERT_EQUAL_UINT16(544u, idemip_ip4_payload_len(buf));

    // The checksum covers the options, so it holds over 32 octets and not over 20.
    TEST_ASSERT_TRUE(idemip_cksum_valid(buf, 32u));
    TEST_ASSERT_FALSE(idemip_cksum_valid(buf, 20u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(buf, 576u));

    check_canary(buf, sizeof buf, 576u);
}

// An option-free header has no option area at all.
void test_five_word_header_has_no_options(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 21u);
    build_figure5(buf);
    TEST_ASSERT_EQUAL_size_t(0u, idemip_ip4_options_len(buf));
    TEST_ASSERT_EQUAL_PTR(buf + IDEMIP_IPV4_HDR_LEN, idemip_ip4_options(buf));
}

// --- the header checksum, RFC 791 sec 3.1 ------------------------------------

// "The checksum field is the 16 bit one's complement of the one's complement sum of all 16 bit
// words in the header. For purposes of computing the checksum, the value of the checksum field is
// zero." Zeroing the field and summing must reproduce what recksum stored.
void test_recksum_computes_with_the_field_zero(void)
{
    uint8_t buf[32];
    uint8_t zeroed[32];
    arm(buf, sizeof buf, 21u);
    build_figure5(buf);

    memcpy(zeroed, buf, sizeof zeroed);
    idemip_ip4_set_cksum(zeroed, 0u);
    TEST_ASSERT_EQUAL_HEX16(idemip_cksum(zeroed, 20u), idemip_ip4_cksum(buf));
}

// RFC 1071 sec 1: summing a span that carries its own checksum gives all ones, so the complement is
// zero. RFC 1122 sec 3.2.1.2 is what makes a receiver run it on every datagram.
void test_a_built_header_checks_out_over_itself(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 21u);
    build_figure5(buf);
    TEST_ASSERT_TRUE(idemip_cksum_valid(buf, 20u));
    TEST_ASSERT_TRUE(idemip_ip4_cksum_ok(buf));
}

// RFC 1122 sec 3.2.1.2: "silently discard every datagram that has a bad checksum." Every single-bit
// flip in the twenty header octets must be caught.
void test_verify_rejects_every_single_bit_flip(void)
{
    uint8_t good[32];
    arm(good, sizeof good, 21u);
    build_figure5(good);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(good, 21u));

    for (size_t i = 0u; i < 20u; i++)
    {
        for (unsigned b = 0u; b < 8u; b++)
        {
            uint8_t bad[32];
            memcpy(bad, good, sizeof bad);
            bad[i] ^= (uint8_t)(1u << b);
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, idemip_ip4_verify(bad, 21u),
                                          "a one-bit change in the header was accepted");
        }
    }
}

// A recomputed checksum tracks an edited field, which is what RFC 791 sec 3.2 lists among "the
// fields which may be affected by fragmentation".
void test_recksum_after_a_field_edit(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 21u);
    build_figure5(buf);

    idemip_ip4_set_ttl(buf, 122u);
    TEST_ASSERT_FALSE_MESSAGE(idemip_ip4_cksum_ok(buf), "the stale checksum still held after an edit");
    idemip_ip4_recksum(buf);
    TEST_ASSERT_TRUE(idemip_ip4_cksum_ok(buf));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(buf, 21u));
}

// --- verify, RFC 1122 sec 3.2.1 ----------------------------------------------

// RFC 1122 sec 3.2.1.1: "A datagram whose version number is not 4 MUST be silently discarded."
void test_verify_rejects_a_version_other_than_four(void)
{
    uint8_t buf[32];
    for (unsigned v = 0u; v < 16u; v++)
    {
        arm(buf, sizeof buf, 21u);
        build_figure5(buf);
        buf[IDEMIP_IP4_OFF_VER_IHL] = (uint8_t)((v << IDEMIP_IP4_VER_SHIFT) | 5u);
        idemip_ip4_recksum(buf); // a good checksum, so version is the only fault
        if (v == 4u)
        {
            TEST_ASSERT_TRUE(idemip_ip4_version_ok(buf));
            TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(buf, 21u));
        }
        else
        {
            TEST_ASSERT_FALSE(idemip_ip4_version_ok(buf));
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, idemip_ip4_verify(buf, 21u),
                                          "a version other than 4 was accepted");
        }
    }
}

// RFC 791 sec 3.1: "the minimum value for a correct header is 5". A shorter one is refused even
// with a checksum that holds over the twenty octets present.
void test_verify_rejects_an_ihl_below_five(void)
{
    uint8_t buf[32];
    for (uint8_t ihl = 0u; ihl < IDEMIP_IP4_IHL_MIN; ihl++)
    {
        arm(buf, sizeof buf, 21u);
        build_figure5(buf);
        idemip_ip4_set_ver_ihl(buf, ihl);
        idemip_ip4_set_cksum(buf, 0u);
        idemip_ip4_set_cksum(buf, idemip_cksum(buf, 20u));
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, idemip_ip4_verify(buf, 21u), "an IHL below 5 was accepted");
    }
}

// Fewer than twenty readable octets is not a header at all.
void test_verify_rejects_a_buffer_shorter_than_the_fixed_header(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 21u);
    build_figure5(buf);
    for (size_t avail = 0u; avail < IDEMIP_IPV4_HDR_LEN; avail++)
    {
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, idemip_ip4_verify(buf, avail), "a short buffer was accepted");
    }
}

// An IHL that claims more octets than the caller holds is refused.
void test_verify_rejects_a_header_longer_than_the_buffer(void)
{
    uint8_t buf[64];
    arm(buf, sizeof buf, 40u);
    build_figure5(buf);
    idemip_ip4_set_ver_ihl(buf, 8u); // 32 octets of header
    idemip_ip4_set_total_len(buf, 40u);
    idemip_ip4_recksum(buf);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(buf, 40u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, idemip_ip4_verify(buf, 24u),
                                  "a 32-octet header was accepted in 24 readable octets");
}

// RFC 791 sec 3.1 counts Total Length "including internet header and data", so a value below the
// header is not interpretable.
void test_verify_rejects_total_length_below_the_header(void)
{
    uint8_t buf[32];
    for (uint16_t tl = 0u; tl < IDEMIP_IPV4_HDR_LEN; tl++)
    {
        arm(buf, sizeof buf, 21u);
        build_figure5(buf);
        idemip_ip4_set_total_len(buf, tl);
        idemip_ip4_recksum(buf);
        TEST_ASSERT_FALSE(idemip_ip4_len_ok(buf, 21u));
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, idemip_ip4_verify(buf, 21u),
                                      "a Total Length below the header was accepted");
    }
}

// A Total Length past what the caller holds cannot be read.
void test_verify_rejects_total_length_past_the_buffer(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 21u);
    build_figure5(buf);
    idemip_ip4_set_total_len(buf, 22u);
    idemip_ip4_recksum(buf);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, idemip_ip4_verify(buf, 21u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(buf, 22u));
}

// RFC 894: a short frame is padded and the padding "is not included in the total length field of
// the IP header", so more readable octets than Total Length is a good datagram.
void test_verify_accepts_a_buffer_longer_than_total_length(void)
{
    uint8_t buf[64];
    arm(buf, sizeof buf, 21u);
    build_figure5(buf);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(buf, 21u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(buf, 46u));
    TEST_ASSERT_EQUAL_UINT16(21u, idemip_ip4_total_len(buf));
}

// RFC 791 sec 3.1 requires a sender to zero Flags bit 0. Neither RFC 791 nor RFC 1122 sec 3.2.1
// makes a receiver discard a datagram carrying it set, and RFC 791 sec 3.2 says an implementation
// "must be conservative in its sending behavior, and liberal in its receiving behavior", so verify
// reads it and passes.
void test_reserved_flag_is_readable_and_does_not_fail_verify(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 21u);
    build_figure5(buf);
    idemip_ip4_set_flags_frag(buf, IDEMIP_IP4_FLAG_RESERVED);
    idemip_ip4_recksum(buf);

    TEST_ASSERT_TRUE(idemip_ip4_reserved(buf));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, idemip_ip4_verify(buf, 21u));
}

// --- build ------------------------------------------------------------------

// The same fields give the same octets, in any buffer and however often.
void test_build_is_a_function_of_its_fields_alone(void)
{
    uint8_t a[32];
    uint8_t b[32];
    arm(a, sizeof a, 21u);
    arm(b, sizeof b, 21u);

    build_figure5(a);
    build_figure5(b);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(a, b, 20);

    build_figure5(a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(b, a, 20);
    check_canary(a, sizeof a, 21u);
    check_canary(b, sizeof b, 21u);
}

// Every field the build takes lands where Figure 4 puts it, read back through the accessors.
void test_build_round_trips_every_field(void)
{
    uint8_t buf[32];
    arm(buf, sizeof buf, 20u);

    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.tos = 0xB8u;
    f.total_len = 1500u;
    f.id = 0xBEEFu;
    f.flags_frag = (uint16_t)(IDEMIP_IP4_FLAG_DF | IDEMIP_IP4_FLAG_MF | 0x0123u);
    f.ttl = IDEMIP_IP_DEFAULT_TTL;
    f.proto = IDEMIP_IP4_PROTO_UDP;
    f.src = 0xC0A80001u;
    f.dst = 0xC0A800C7u;
    idemip_ip4_build(buf, &f);

    TEST_ASSERT_EQUAL_UINT8(4u, idemip_ip4_version(buf));
    TEST_ASSERT_EQUAL_UINT8(5u, idemip_ip4_ihl(buf));
    TEST_ASSERT_EQUAL_HEX8(0xB8u, idemip_ip4_tos(buf));
    TEST_ASSERT_EQUAL_UINT16(1500u, idemip_ip4_total_len(buf));
    TEST_ASSERT_EQUAL_HEX16(0xBEEFu, idemip_ip4_id(buf));
    TEST_ASSERT_TRUE(idemip_ip4_df(buf));
    TEST_ASSERT_TRUE(idemip_ip4_mf(buf));
    TEST_ASSERT_FALSE(idemip_ip4_reserved(buf));
    TEST_ASSERT_EQUAL_UINT16(0x0123u, idemip_ip4_frag_units(buf));
    TEST_ASSERT_EQUAL_UINT32(0x0123u * 8u, idemip_ip4_frag_offset_bytes(buf));
    TEST_ASSERT_EQUAL_UINT8(255u, idemip_ip4_ttl(buf));
    TEST_ASSERT_EQUAL_UINT8(17u, idemip_ip4_proto(buf));
    TEST_ASSERT_EQUAL_HEX32(0xC0A80001u, idemip_ip4_src(buf));
    TEST_ASSERT_EQUAL_HEX32(0xC0A800C7u, idemip_ip4_dst(buf));
    TEST_ASSERT_TRUE(idemip_ip4_cksum_ok(buf));

    check_canary(buf, sizeof buf, 20u);
}

// --- the constants sec 3.1 and sec 3.2 fix -----------------------------------

// "This field allows the length of a datagram to be up to 65,535 octets." "The maximal internet
// header is 60 octets, and a typical internet header is 20 octets."
void test_length_constants(void)
{
    TEST_ASSERT_EQUAL_UINT32(65535u, IDEMIP_IP4_TOTAL_LEN_MAX);
    TEST_ASSERT_EQUAL_UINT32(60u, IDEMIP_IP4_HDR_MAX);
    TEST_ASSERT_EQUAL_UINT32(20u, IDEMIP_IPV4_HDR_LEN);
}

// RFC 791 sec 3.2: "Every internet module must be able to forward a datagram of 68 octets without
// further fragmentation. This is because an internet header may be up to 60 octets, and the minimum
// fragment is 8 octets."
void test_minimum_forwardable_datagram_is_sixty_eight_octets(void)
{
    TEST_ASSERT_EQUAL_UINT32(68u, IDEMIP_IP4_MIN_FORWARD_MTU);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_IP4_HDR_MAX + IDEMIP_IP4_FRAG_UNIT, IDEMIP_IP4_MIN_FORWARD_MTU);
}

// RFC 791 sec 3.1: "All hosts must be prepared to accept datagrams of up to 576 octets (whether
// they arrive whole or in fragments)", which is Figure 9's Total Length and common.h's EMTU_R.
void test_five_hundred_seventy_six_is_the_required_reassembly_size(void)
{
    TEST_ASSERT_EQUAL_UINT32(576u, IDEMIP_IPV4_MIN_MTU);
}

// --- the subnet mask ---------------------------------------------------------
// Two units read these: ip4_addr reports what a mask says about an address, and ip4_route needs RFC
// 1812 sec 5.2.4.3's route.length for every row it prunes. They were tested only through the entry
// that reports them, at five prefix lengths. They are pure arithmetic over 33 legal masks, so every
// one of them fits in a case.

// RFC 1812 sec 5.2.4.3 reads a mask as "the most significant route.length bits", so counting its
// ones has to answer route.length at every length such a mask can have.
void test_mask_ones_counts_every_prefix_length(void)
{
    for (unsigned len = 0; len <= 32u; len++)
    {
        const uint32_t mask = (len == 0u) ? 0u : (uint32_t)(0xFFFFFFFFu << (32u - len));
        TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)len, idemip_ip4_addr_mask_ones(mask),
                                        "a contiguous mask must count as its own prefix length");
    }
}

// The count is a population count, so it answers for a mask with holes too - it is
// idemip_ip4_addr_mask_contiguous that says whether the mask is one RFC 1812 can use.
void test_mask_ones_counts_a_mask_with_holes(void)
{
    TEST_ASSERT_EQUAL_UINT8(16u, idemip_ip4_addr_mask_ones(0xFF00FF00u));
    TEST_ASSERT_EQUAL_UINT8(1u, idemip_ip4_addr_mask_ones(0x00000001u));
    TEST_ASSERT_EQUAL_UINT8(32u, idemip_ip4_addr_mask_ones(0xFFFFFFFFu));
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_ip4_addr_mask_ones(0u));
}

// RFC 1122 sec 3.2.1.3: the "-1" notation "is not intended to imply that the 1-bits in an address
// mask need be contiguous", so a holed mask is a thing that exists and has to be recognised. Every
// mask whose ones are its leading bits passes, including the two ends.
void test_every_leading_run_of_ones_is_contiguous(void)
{
    for (unsigned len = 0; len <= 32u; len++)
    {
        const uint32_t mask = (len == 0u) ? 0u : (uint32_t)(0xFFFFFFFFu << (32u - len));
        TEST_ASSERT_TRUE_MESSAGE(idemip_ip4_addr_mask_contiguous(mask),
                                 "a mask that is a leading run of ones must read as contiguous");
    }
}

void test_a_mask_with_a_hole_is_not_contiguous(void)
{
    TEST_ASSERT_FALSE(idemip_ip4_addr_mask_contiguous(0xFF00FF00u));
    TEST_ASSERT_FALSE(idemip_ip4_addr_mask_contiguous(0x80000001u));
    TEST_ASSERT_FALSE(idemip_ip4_addr_mask_contiguous(0xFFFFFFFDu)); // a /32 with bit 1 punched out
    TEST_ASSERT_FALSE(idemip_ip4_addr_mask_contiguous(0x00000001u)); // ones, but not leading ones
}

// The two answer about the same mask, so a mask the second rejects still has a count and a mask it
// accepts counts to a length that reconstructs it. That round trip is what ip4_route relies on when
// it stores route.length beside the mask rather than recomputing it.
void test_a_contiguous_mask_is_rebuilt_from_its_own_count(void)
{
    for (unsigned len = 0; len <= 32u; len++)
    {
        const uint32_t mask = (len == 0u) ? 0u : (uint32_t)(0xFFFFFFFFu << (32u - len));
        const uint8_t ones = idemip_ip4_addr_mask_ones(mask);
        const uint32_t rebuilt = (ones == 0u) ? 0u : (uint32_t)(0xFFFFFFFFu << (32u - ones));
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(mask, rebuilt, "route.length must name the mask it came from");
    }
}

// RFC 791 sec 3.1: "the minimum value for a correct header is 5", so an Internet Header Length below
// that names a header shorter than the fixed fields it is made of, and one at the top of its four
// bits is the longest header the field can name.
void test_a_header_length_below_the_minimum_is_not_a_header(void)
{
    uint8_t h[IDEMIP_IPV4_HDR_LEN];
    memset(h, 0, sizeof h);

    for (uint8_t ihl = 0u; ihl < (uint8_t)IDEMIP_IP4_IHL_MIN; ihl++)
    {
        idemip_ip4_set_ver_ihl(h, ihl);
        TEST_ASSERT_FALSE_MESSAGE(idemip_ip4_ihl_ok(h), "a header length below the minimum was taken as one");
    }

    idemip_ip4_set_ver_ihl(h, (uint8_t)IDEMIP_IP4_IHL_MIN);
    TEST_ASSERT_TRUE(idemip_ip4_ihl_ok(h));
    idemip_ip4_set_ver_ihl(h, (uint8_t)IDEMIP_IP4_IHL_MAX);
    TEST_ASSERT_TRUE_MESSAGE(idemip_ip4_ihl_ok(h), "the longest header the field can name was refused");
}
