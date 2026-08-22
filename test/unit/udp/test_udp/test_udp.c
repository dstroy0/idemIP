// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 768 and RFC 3828 sec 3.1, over the caller's bytes. udp.h holds no state, so there is no
// borrow to share and the storage cases the golden suite carries do not apply. What is checked
// instead:
//
//   1. the field offsets are the ones RFC 768's figure draws
//   2. every accessor reads its own field and nothing else, at an odd address
//   3. Length's minimum of eight, and that a shorter one cannot wrap into a payload length
//   4. both RFC 768 checksum special cases: all zero means none, a computed zero goes out all ones
//   5. RFC 3828's Checksum Coverage: the discard rules, and that octets past the coverage do not
//      enter the sum
//
// The checksum vectors are byte strings built to RFC 768's figure. RFC 768 prints no worked
// example, so each expected value was produced outside this suite: once by a Python
// implementation of RFC 1071's sum, then cross-checked against scapy 2.7.0, which emits the same
// value for every one of the four UDP cases including the all-ones one.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/udp/udp.h"

#include <string.h>
#include <unity.h>
#include "src/udp/udp_defines.h"

// 192.168.0.1 and 192.168.0.2, the addresses every vector below was summed with.
#define SRC 0xC0A80001u
#define DST 0xC0A80002u

// RFC 768's figure, five data octets. An odd payload is the [Z,0] pad case.
static const uint8_t v_hello[] = {0x12, 0x34, 0x56, 0x78, 0x00, 0x0D, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o'};
#define V_HELLO_CKSUM 0xD201u

// Even payload.
static const uint8_t v_even[] = {0x00, 0x35, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00,
                                 'i',  'd',  'e',  'm',  'I',  'P',  0x00, 0x00};
#define V_EVEN_CKSUM 0x5623u

// Two data octets chosen so the sum before complementing is all ones, which complements to zero.
static const uint8_t v_zero[] = {0x08, 0x01, 0x08, 0x02, 0x00, 0x0A, 0x00, 0x00, 0x6E, 0x83};

// Length exactly eight: the header alone, no data.
static const uint8_t v_bare[] = {0x00, 0x09, 0x00, 0x09, 0x00, 0x08, 0x00, 0x00};
#define V_BARE_CKSUM 0x7E78u

// RFC 3828 figure 1: the third field is Checksum Coverage. Sixteen payload octets follow, so the
// IP payload is 24.
static const uint8_t v_lite[] = {0xAB, 0xCD, 0x10, 0x00, 0x00, 0x08, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
                                 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
#define V_LITE_IPL 24u
#define V_LITE_COV8_CKSUM 0xC235u
#define V_LITE_COV12_CKSUM 0xA00Du
#define V_LITE_COV0_CKSUM 0x097Du

// A working header, plus a canary past it so a write past IDEMIP_UDP_HDR_LEN is visible.
#define CANARY 0x5Au
static uint8_t buf[64];
static uint8_t buf_b[64];

static void arm(uint8_t *b, size_t cap)
{
    memset(b, CANARY, cap);
}

void setUp(void)
{
    arm(buf, sizeof buf);
    arm(buf_b, sizeof buf_b);
}

void tearDown(void)
{
    // Nothing to release: this suite holds no allocation, only file-scope storage.
}

// --- the field map -----------------------------------------------------------

// RFC 768, Format: Source Port at bits 0-15, Destination Port at 16-31, then Length and Checksum
// in the second 32-bit word. Eight octets, four fields, none packed.
void test_field_offsets_are_the_rfc_768_figure(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_UDP_OFF_SRC_PORT);
    TEST_ASSERT_EQUAL_UINT(2u, IDEMIP_UDP_OFF_DST_PORT);
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_UDP_OFF_LEN);
    TEST_ASSERT_EQUAL_UINT(6u, IDEMIP_UDP_OFF_CKSUM);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_UDP_HDR_LEN);
}

void test_accessors_read_the_figure_fields(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x1234u, idemip_udp_src_port(v_hello));
    TEST_ASSERT_EQUAL_HEX16(0x5678u, idemip_udp_dst_port(v_hello));
    TEST_ASSERT_EQUAL_UINT16(13u, idemip_udp_len(v_hello));
    TEST_ASSERT_EQUAL_HEX16(0x0000u, idemip_udp_cksum(v_hello));
}

// The header sits 20 bytes into an option-free IPv4 header that itself starts 14 bytes into an
// Ethernet frame, so it is read at an odd address in the frame it arrived in.
void test_accessors_read_at_an_odd_address(void)
{
    memcpy(buf + 1u, v_hello, sizeof v_hello);
    const uint8_t *h = buf + 1u;
    TEST_ASSERT_EQUAL_HEX16(0x1234u, idemip_udp_src_port(h));
    TEST_ASSERT_EQUAL_HEX16(0x5678u, idemip_udp_dst_port(h));
    TEST_ASSERT_EQUAL_UINT16(13u, idemip_udp_len(h));
    TEST_ASSERT_EQUAL_HEX16(V_HELLO_CKSUM, idemip_udp_cksum_compute(h, sizeof v_hello, SRC, DST));
}

// Two datagrams back to back: each accessor reads its own eight octets and never the next one's.
void test_two_headers_side_by_side_do_not_read_each_other(void)
{
    memcpy(buf, v_hello, sizeof v_hello);
    memcpy(buf + sizeof v_hello, v_even, sizeof v_even);
    const uint8_t *a = buf;
    const uint8_t *b = buf + sizeof v_hello;
    TEST_ASSERT_EQUAL_HEX16(0x1234u, idemip_udp_src_port(a));
    TEST_ASSERT_EQUAL_HEX16(0x0035u, idemip_udp_src_port(b));
    TEST_ASSERT_EQUAL_UINT16(13u, idemip_udp_len(a));
    TEST_ASSERT_EQUAL_UINT16(16u, idemip_udp_len(b));
}

// --- Length ------------------------------------------------------------------

// RFC 768: "This means the minimum value of the length is eight."
void test_length_of_eight_is_the_minimum(void)
{
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_UDP_LEN_MIN);
    TEST_ASSERT_TRUE(idemip_udp_len_valid(v_bare));
    TEST_ASSERT_EQUAL_UINT16(0u, idemip_udp_payload_len(v_bare));
}

void test_length_below_eight_is_refused(void)
{
    idemip_udp_build(buf, 1u, 2u, 7u);
    TEST_ASSERT_FALSE(idemip_udp_len_valid(buf));
    idemip_udp_build(buf, 1u, 2u, 0u);
    TEST_ASSERT_FALSE(idemip_udp_len_valid(buf));
    idemip_udp_build(buf, 1u, 2u, 8u);
    TEST_ASSERT_TRUE(idemip_udp_len_valid(buf));
}

void test_payload_len_is_length_less_the_header(void)
{
    TEST_ASSERT_EQUAL_UINT16(5u, idemip_udp_payload_len(v_hello));
    TEST_ASSERT_EQUAL_UINT16(8u, idemip_udp_payload_len(v_even));
    TEST_ASSERT_EQUAL_UINT16(2u, idemip_udp_payload_len(v_zero));
}

// A Length of one would underflow to 65529 if the subtraction were unguarded.
void test_a_short_length_cannot_wrap_the_payload_len(void)
{
    for (uint16_t len = 0u; len < IDEMIP_UDP_LEN_MIN; len++)
    {
        idemip_udp_build(buf, 1u, 2u, len);
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, idemip_udp_payload_len(buf), "a Length under eight wrapped");
    }
}

// --- build -------------------------------------------------------------------

void test_build_writes_the_four_fields_and_clears_the_checksum(void)
{
    idemip_udp_build(buf, 0x1234u, 0x5678u, 13u);
    static const uint8_t want[] = {0x12, 0x34, 0x56, 0x78, 0x00, 0x0D, 0x00, 0x00};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, buf, sizeof want);
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, buf[IDEMIP_UDP_HDR_LEN], "build wrote past the header");
}

void test_build_round_trips_through_the_accessors(void)
{
    idemip_udp_build(buf, 0xFFFFu, 0x0000u, 0x8001u);
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu, idemip_udp_src_port(buf));
    TEST_ASSERT_EQUAL_HEX16(0x0000u, idemip_udp_dst_port(buf));
    TEST_ASSERT_EQUAL_HEX16(0x8001u, idemip_udp_len(buf));
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_UDP_CKSUM_NONE, idemip_udp_cksum(buf));
}

// Each setter writes two octets at its own offset and leaves the other three fields alone.
void test_each_setter_writes_only_its_own_field(void)
{
    idemip_udp_build(buf, 0x1111u, 0x2222u, 0x3333u);
    idemip_udp_set_cksum(buf, 0x4444u);

    idemip_udp_set_src_port(buf, 0xAAAAu);
    TEST_ASSERT_EQUAL_HEX16(0xAAAAu, idemip_udp_src_port(buf));
    TEST_ASSERT_EQUAL_HEX16(0x2222u, idemip_udp_dst_port(buf));
    TEST_ASSERT_EQUAL_HEX16(0x3333u, idemip_udp_len(buf));
    TEST_ASSERT_EQUAL_HEX16(0x4444u, idemip_udp_cksum(buf));

    idemip_udp_set_dst_port(buf, 0xBBBBu);
    idemip_udp_set_len(buf, 0xCCCCu);
    idemip_udp_set_cksum(buf, 0xDDDDu);
    TEST_ASSERT_EQUAL_HEX16(0xAAAAu, idemip_udp_src_port(buf));
    TEST_ASSERT_EQUAL_HEX16(0xBBBBu, idemip_udp_dst_port(buf));
    TEST_ASSERT_EQUAL_HEX16(0xCCCCu, idemip_udp_len(buf));
    TEST_ASSERT_EQUAL_HEX16(0xDDDDu, idemip_udp_cksum(buf));
    TEST_ASSERT_EQUAL_HEX8(CANARY, buf[IDEMIP_UDP_HDR_LEN]);
}

// RFC 768: Source Port is optional, "If not used, a value of zero is inserted."
void test_an_unused_source_port_is_zero(void)
{
    idemip_udp_build(buf, 0u, 53u, 8u);
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_udp_src_port(buf));
    TEST_ASSERT_EQUAL_HEX16(53u, idemip_udp_dst_port(buf));
}

// --- the checksum ------------------------------------------------------------

// Odd payload: RFC 768's "padded with zero octets at the end (if necessary) to make a multiple of
// two octets" is the pad, and it is summed rather than sent.
void test_checksum_over_an_odd_length_datagram(void)
{
    TEST_ASSERT_EQUAL_HEX16(V_HELLO_CKSUM, idemip_udp_cksum_compute(v_hello, sizeof v_hello, SRC, DST));
}

void test_checksum_over_an_even_length_datagram(void)
{
    TEST_ASSERT_EQUAL_HEX16(V_EVEN_CKSUM, idemip_udp_cksum_compute(v_even, sizeof v_even, SRC, DST));
}

void test_checksum_over_a_bare_header(void)
{
    TEST_ASSERT_EQUAL_HEX16(V_BARE_CKSUM, idemip_udp_cksum_compute(v_bare, sizeof v_bare, SRC, DST));
}

// RFC 768: "If the computed checksum is zero, it is transmitted as all ones (the equivalent in
// one's complement arithmetic)." Without that substitution this datagram would go out claiming no
// checksum at all.
void test_a_computed_zero_is_transmitted_as_all_ones(void)
{
    // The raw sum, taken here rather than through the helper, is the value the substitution hides.
    uint32_t sum = idemip_udp_pseudo_accum(0u, SRC, DST, (uint16_t)sizeof v_zero, IDEMIP_UDP_PROTO);
    TEST_ASSERT_EQUAL_HEX16(0x0000u, idemip_cksum_final(idemip_cksum_accum(sum, v_zero, sizeof v_zero)));

    TEST_ASSERT_EQUAL_HEX16(IDEMIP_UDP_CKSUM_ZERO_AS,
                            idemip_udp_cksum_compute(v_zero, sizeof v_zero, SRC, DST));
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu, IDEMIP_UDP_CKSUM_ZERO_AS);
}

// RFC 768: "An all zero transmitted checksum value means that the transmitter generated no
// checksum." So the two representations of zero are not interchangeable on the wire.
void test_all_zero_means_no_checksum_was_generated(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x0000u, IDEMIP_UDP_CKSUM_NONE);
    idemip_udp_build(buf, 1u, 2u, 8u);
    TEST_ASSERT_FALSE(idemip_udp_cksum_present(buf));
    idemip_udp_set_cksum(buf, IDEMIP_UDP_CKSUM_ZERO_AS);
    TEST_ASSERT_TRUE(idemip_udp_cksum_present(buf));
    idemip_udp_set_cksum(buf, 0x0001u);
    TEST_ASSERT_TRUE(idemip_udp_cksum_present(buf));
}

// A computed checksum never comes back as the value that means "none", so the two cases can never
// collide however the datagram is built.
void test_compute_never_returns_the_no_checksum_value(void)
{
    for (uint16_t n = 0u; n < 512u; n++)
    {
        idemip_udp_build(buf, n, (uint16_t)(0xFFFFu - n), 10u);
        buf[8] = (uint8_t)(n >> 8);
        buf[9] = (uint8_t)n;
        uint16_t c = idemip_udp_cksum_compute(buf, 10u, SRC, DST);
        TEST_ASSERT_NOT_EQUAL_MESSAGE(IDEMIP_UDP_CKSUM_NONE, c, "a computed checksum claimed there was none");
    }
}

// RFC 768: the pseudo-header "contains the source address, the destination address, the protocol,
// and the UDP length. This information gives protection against misrouted datagrams." Each of the
// four therefore has to move the result.
void test_the_pseudo_header_covers_the_addresses_the_protocol_and_the_length(void)
{
    uint16_t base = idemip_udp_cksum_compute(v_hello, sizeof v_hello, SRC, DST);
    TEST_ASSERT_NOT_EQUAL(base, idemip_udp_cksum_compute(v_hello, sizeof v_hello, SRC + 1u, DST));
    TEST_ASSERT_NOT_EQUAL(base, idemip_udp_cksum_compute(v_hello, sizeof v_hello, SRC, DST + 1u));

    uint32_t with_udp = idemip_udp_pseudo_accum(0u, SRC, DST, 13u, IDEMIP_UDP_PROTO);
    uint32_t with_lite = idemip_udp_pseudo_accum(0u, SRC, DST, 13u, IDEMIP_UDPLITE_PROTO);
    TEST_ASSERT_EQUAL_UINT32(with_udp + (IDEMIP_UDPLITE_PROTO - IDEMIP_UDP_PROTO), with_lite);

    uint32_t len13 = idemip_udp_pseudo_accum(0u, SRC, DST, 13u, IDEMIP_UDP_PROTO);
    uint32_t len14 = idemip_udp_pseudo_accum(0u, SRC, DST, 14u, IDEMIP_UDP_PROTO);
    TEST_ASSERT_EQUAL_UINT32(len13 + 1u, len14);
}

// RFC 768: "This is protocol 17 (21 octal) when used in the Internet Protocol."
void test_udp_is_protocol_seventeen(void)
{
    TEST_ASSERT_EQUAL_UINT8(17u, IDEMIP_UDP_PROTO);
    TEST_ASSERT_EQUAL_UINT8(021u, IDEMIP_UDP_PROTO);
}

void test_cksum_write_stores_what_compute_returned(void)
{
    memcpy(buf, v_hello, sizeof v_hello);
    idemip_udp_cksum_write(buf, sizeof v_hello, SRC, DST);
    TEST_ASSERT_EQUAL_HEX16(V_HELLO_CKSUM, idemip_udp_cksum(buf));
    TEST_ASSERT_EQUAL_HEX8(CANARY, buf[sizeof v_hello]);
}

// The field is cleared before the sum, so writing it a second time over an already-checksummed
// datagram lands on the same value rather than folding the old one in.
void test_cksum_write_repeats(void)
{
    memcpy(buf, v_hello, sizeof v_hello);
    idemip_udp_cksum_write(buf, sizeof v_hello, SRC, DST);
    idemip_udp_cksum_write(buf, sizeof v_hello, SRC, DST);
    TEST_ASSERT_EQUAL_HEX16(V_HELLO_CKSUM, idemip_udp_cksum(buf));
}

// RFC 1071 sec 1: a span that already carries its checksum sums to all ones, which complements to
// zero. One flipped bit anywhere in the datagram breaks it.
void test_a_carried_checksum_verifies_and_a_flipped_bit_does_not(void)
{
    memcpy(buf, v_hello, sizeof v_hello);
    idemip_udp_cksum_write(buf, sizeof v_hello, SRC, DST);
    TEST_ASSERT_TRUE(idemip_udp_cksum_valid(buf, sizeof v_hello, SRC, DST));

    for (size_t i = 0; i < sizeof v_hello; i++)
    {
        memcpy(buf_b, buf, sizeof v_hello);
        buf_b[i] ^= 0x01u;
        TEST_ASSERT_FALSE_MESSAGE(idemip_udp_cksum_valid(buf_b, sizeof v_hello, SRC, DST),
                                  "a flipped bit still verified");
    }
}

// A datagram delivered to the wrong address fails on the pseudo-header alone, which is the
// protection RFC 768 names.
void test_a_misrouted_datagram_does_not_verify(void)
{
    memcpy(buf, v_hello, sizeof v_hello);
    idemip_udp_cksum_write(buf, sizeof v_hello, SRC, DST);
    TEST_ASSERT_FALSE(idemip_udp_cksum_valid(buf, sizeof v_hello, SRC, DST + 1u));
    TEST_ASSERT_FALSE(idemip_udp_cksum_valid(buf, sizeof v_hello, SRC + 1u, DST));
}

// The all-ones substitution has to verify too, or the sender's own datagram would be dropped.
void test_the_all_ones_substitution_verifies(void)
{
    memcpy(buf, v_zero, sizeof v_zero);
    idemip_udp_cksum_write(buf, sizeof v_zero, SRC, DST);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_UDP_CKSUM_ZERO_AS, idemip_udp_cksum(buf));
    TEST_ASSERT_TRUE(idemip_udp_cksum_valid(buf, sizeof v_zero, SRC, DST));
}

// --- UDP-Lite, RFC 3828 sec 3.1 ---------------------------------------------

// RFC 3828 sec 3: "Its format differs from UDP in that the Length field has been replaced with a
// Checksum Coverage field." Same offset, same width, same eight-octet header.
void test_coverage_replaces_length_in_place(void)
{
    TEST_ASSERT_EQUAL_UINT(IDEMIP_UDP_OFF_LEN, IDEMIP_UDPLITE_OFF_COV);
    TEST_ASSERT_EQUAL_UINT(IDEMIP_UDP_HDR_LEN, IDEMIP_UDPLITE_HDR_LEN);
    TEST_ASSERT_EQUAL_UINT16(8u, idemip_udplite_cov(v_lite));
    TEST_ASSERT_EQUAL_HEX16(0xABCDu, idemip_udp_src_port(v_lite));
    TEST_ASSERT_EQUAL_HEX16(0x1000u, idemip_udp_dst_port(v_lite));
}

// RFC 3828 sec 7: "A new IP protocol number, 136 has been assigned for UDP-Lite."
void test_udplite_is_protocol_one_hundred_thirty_six(void)
{
    TEST_ASSERT_EQUAL_UINT8(136u, IDEMIP_UDPLITE_PROTO);
    TEST_ASSERT_NOT_EQUAL(IDEMIP_UDP_PROTO, IDEMIP_UDPLITE_PROTO);
}

// RFC 3828 sec 3.1: "A Checksum Coverage of zero indicates that the entire UDP-Lite packet is
// covered by the checksum."
void test_coverage_of_zero_covers_the_whole_packet(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_UDPLITE_COV_ALL);
    TEST_ASSERT_EQUAL_size_t(V_LITE_IPL, idemip_udplite_cov_bytes(IDEMIP_UDPLITE_COV_ALL, V_LITE_IPL));
    TEST_ASSERT_EQUAL_size_t(8u, idemip_udplite_cov_bytes(8u, V_LITE_IPL));
    TEST_ASSERT_EQUAL_size_t(12u, idemip_udplite_cov_bytes(12u, V_LITE_IPL));
}

// RFC 3828 sec 3.1: "the value of the Checksum Coverage field MUST be either 0 or at least 8. A
// UDP-Lite packet with a Checksum Coverage value of 1 to 7 MUST be discarded by the receiver."
void test_coverage_of_one_through_seven_is_discarded(void)
{
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_UDPLITE_COV_MIN);
    for (uint16_t cov = 1u; cov < IDEMIP_UDPLITE_COV_MIN; cov++)
    {
        TEST_ASSERT_FALSE_MESSAGE(idemip_udplite_cov_valid(cov, V_LITE_IPL),
                                  "a Coverage of 1 through 7 was accepted");
    }
    TEST_ASSERT_TRUE(idemip_udplite_cov_valid(IDEMIP_UDPLITE_COV_ALL, V_LITE_IPL));
    TEST_ASSERT_TRUE(idemip_udplite_cov_valid(8u, V_LITE_IPL));
}

// RFC 3828 sec 3.1: "UDP-Lite packets with a Checksum Coverage greater than the IP length MUST
// also be discarded."
void test_coverage_past_the_ip_length_is_discarded(void)
{
    TEST_ASSERT_TRUE(idemip_udplite_cov_valid(V_LITE_IPL, V_LITE_IPL));
    TEST_ASSERT_FALSE(idemip_udplite_cov_valid((uint16_t)(V_LITE_IPL + 1u), V_LITE_IPL));
    TEST_ASSERT_FALSE(idemip_udplite_cov_valid(0xFFFFu, V_LITE_IPL));
}

// RFC 3828 sec 3.1: "The UDP-Lite header MUST always be covered by the checksum." A payload
// shorter than the header cannot satisfy that at any Coverage, zero included.
void test_a_payload_shorter_than_the_header_is_discarded(void)
{
    for (uint16_t ipl = 0u; ipl < IDEMIP_UDPLITE_COV_MIN; ipl++)
    {
        TEST_ASSERT_FALSE_MESSAGE(idemip_udplite_cov_valid(IDEMIP_UDPLITE_COV_ALL, ipl),
                                  "a packet shorter than the header was accepted at full coverage");
        TEST_ASSERT_FALSE_MESSAGE(idemip_udplite_cov_valid(8u, ipl),
                                  "a packet shorter than the header was accepted at Coverage 8");
    }
    TEST_ASSERT_TRUE(idemip_udplite_cov_valid(IDEMIP_UDPLITE_COV_ALL, IDEMIP_UDPLITE_COV_MIN));
}

void test_udplite_build_writes_coverage_and_clears_the_checksum(void)
{
    idemip_udplite_build(buf, 0xABCDu, 0x1000u, 8u);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(v_lite, buf, IDEMIP_UDPLITE_HDR_LEN);
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, buf[IDEMIP_UDPLITE_HDR_LEN], "build wrote past the header");

    idemip_udplite_set_cov(buf, IDEMIP_UDPLITE_COV_ALL);
    TEST_ASSERT_EQUAL_UINT16(0u, idemip_udplite_cov(buf));
    TEST_ASSERT_EQUAL_HEX16(0xABCDu, idemip_udp_src_port(buf));
}

// Coverage 8 covers the header and nothing else.
void test_checksum_at_coverage_eight(void)
{
    TEST_ASSERT_EQUAL_HEX16(V_LITE_COV8_CKSUM, idemip_udplite_cksum_compute(v_lite, 8u, V_LITE_IPL, SRC, DST));
}

// The whole point of the field: octets past the coverage are not summed, so corrupting them leaves
// the checksum where it was.
void test_octets_past_the_coverage_do_not_enter_the_sum(void)
{
    memcpy(buf, v_lite, sizeof v_lite);
    uint16_t base = idemip_udplite_cksum_compute(buf, 8u, V_LITE_IPL, SRC, DST);
    TEST_ASSERT_EQUAL_HEX16(V_LITE_COV8_CKSUM, base);

    memset(buf + 8u, 0x00u, sizeof v_lite - 8u);
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(base, idemip_udplite_cksum_compute(buf, 8u, V_LITE_IPL, SRC, DST),
                                    "a payload octet outside the coverage moved the checksum");

    memset(buf + 8u, 0xFFu, sizeof v_lite - 8u);
    TEST_ASSERT_EQUAL_HEX16(base, idemip_udplite_cksum_compute(buf, 8u, V_LITE_IPL, SRC, DST));
}

// Coverage 12 pulls the first four payload octets in, so those do move it and the rest still do
// not.
void test_coverage_of_twelve_covers_four_payload_octets(void)
{
    memcpy(buf, v_lite, sizeof v_lite);
    idemip_udplite_set_cov(buf, 12u);
    TEST_ASSERT_EQUAL_HEX16(V_LITE_COV12_CKSUM, idemip_udplite_cksum_compute(buf, 12u, V_LITE_IPL, SRC, DST));

    buf[9] ^= 0xFFu; // inside the coverage
    TEST_ASSERT_NOT_EQUAL(V_LITE_COV12_CKSUM, idemip_udplite_cksum_compute(buf, 12u, V_LITE_IPL, SRC, DST));

    buf[9] ^= 0xFFu;
    buf[20] ^= 0xFFu; // outside it
    TEST_ASSERT_EQUAL_HEX16(V_LITE_COV12_CKSUM, idemip_udplite_cksum_compute(buf, 12u, V_LITE_IPL, SRC, DST));
}

void test_checksum_at_full_coverage(void)
{
    memcpy(buf, v_lite, sizeof v_lite);
    idemip_udplite_set_cov(buf, IDEMIP_UDPLITE_COV_ALL);
    TEST_ASSERT_EQUAL_HEX16(V_LITE_COV0_CKSUM,
                            idemip_udplite_cksum_compute(buf, IDEMIP_UDPLITE_COV_ALL, V_LITE_IPL, SRC, DST));

    // Full coverage sums every octet, so any payload octet moves it.
    buf[23] ^= 0xFFu;
    TEST_ASSERT_NOT_EQUAL(V_LITE_COV0_CKSUM,
                          idemip_udplite_cksum_compute(buf, IDEMIP_UDPLITE_COV_ALL, V_LITE_IPL, SRC, DST));
}

// RFC 3828 sec 3.2: the pseudo-header Length "is not taken from the UDP-Lite header, but rather
// from information provided by the IP module". So it moves the checksum while the coverage stays
// at eight.
void test_the_pseudo_header_length_comes_from_the_ip_module(void)
{
    TEST_ASSERT_EQUAL_HEX16(0xC235u, idemip_udplite_cksum_compute(v_lite, 8u, 24u, SRC, DST));
    TEST_ASSERT_EQUAL_HEX16(0xC22Du, idemip_udplite_cksum_compute(v_lite, 8u, 32u, SRC, DST));
}

// RFC 3828 sec 3.1: "If the computed checksum is 0, it is transmitted as all ones."
void test_a_computed_zero_at_partial_coverage_is_all_ones(void)
{
    // Same payload, a destination port chosen so the covered eight octets sum to all ones.
    static const uint8_t v[] = {0xAB, 0xCD, 0xD2, 0x35, 0x00, 0x08, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
                                0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    uint32_t sum = idemip_udp_pseudo_accum(0u, SRC, DST, V_LITE_IPL, IDEMIP_UDPLITE_PROTO);
    TEST_ASSERT_EQUAL_HEX16(0x0000u, idemip_cksum_final(idemip_cksum_accum(sum, v, 8u)));
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_UDP_CKSUM_ZERO_AS, idemip_udplite_cksum_compute(v, 8u, V_LITE_IPL, SRC, DST));
}

void test_udplite_cksum_write_stores_what_compute_returned(void)
{
    memcpy(buf, v_lite, sizeof v_lite);
    idemip_udplite_cksum_write(buf, 8u, V_LITE_IPL, SRC, DST);
    TEST_ASSERT_EQUAL_HEX16(V_LITE_COV8_CKSUM, idemip_udp_cksum(buf));
    TEST_ASSERT_EQUAL_HEX8(CANARY, buf[sizeof v_lite]);
}

// A received UDP-Lite datagram verifies over its coverage: a bit flipped inside fails, the same
// flip outside is delivered as RFC 3828 intends.
void test_udplite_verifies_over_its_coverage_only(void)
{
    memcpy(buf, v_lite, sizeof v_lite);
    idemip_udplite_set_cov(buf, 12u);
    idemip_udplite_cksum_write(buf, 12u, V_LITE_IPL, SRC, DST);
    TEST_ASSERT_TRUE(idemip_udplite_cksum_valid(buf, 12u, V_LITE_IPL, SRC, DST));

    for (size_t i = 0; i < 12u; i++)
    {
        memcpy(buf_b, buf, sizeof v_lite);
        buf_b[i] ^= 0x01u;
        TEST_ASSERT_FALSE_MESSAGE(idemip_udplite_cksum_valid(buf_b, 12u, V_LITE_IPL, SRC, DST),
                                  "a flipped bit inside the coverage still verified");
    }
    for (size_t i = 12u; i < sizeof v_lite; i++)
    {
        memcpy(buf_b, buf, sizeof v_lite);
        buf_b[i] ^= 0x01u;
        TEST_ASSERT_TRUE_MESSAGE(idemip_udplite_cksum_valid(buf_b, 12u, V_LITE_IPL, SRC, DST),
                                 "a flipped bit outside the coverage broke the checksum");
    }
}

// RFC 3828 sec 3.1: "Since the transmitted checksum MUST NOT be all zeroes", a UDP-Lite datagram
// never carries the value UDP uses for "no checksum".
void test_udplite_never_transmits_an_all_zero_checksum(void)
{
    for (uint16_t dp = 0u; dp < 512u; dp++)
    {
        memcpy(buf, v_lite, sizeof v_lite);
        idemip_udp_set_dst_port(buf, dp);
        uint16_t c = idemip_udplite_cksum_compute(buf, 8u, V_LITE_IPL, SRC, DST);
        TEST_ASSERT_NOT_EQUAL_MESSAGE(IDEMIP_UDP_CKSUM_NONE, c, "UDP-Lite transmitted an all-zero checksum");
    }
}

// RFC 3828 sec 3.1: an application wanting no payload protection "should use a Checksum Coverage
// value of 8", which still covers the header including the Coverage field itself.
void test_coverage_eight_still_covers_the_coverage_field(void)
{
    memcpy(buf, v_lite, sizeof v_lite);
    uint16_t base = idemip_udplite_cksum_compute(buf, 8u, V_LITE_IPL, SRC, DST);
    idemip_udplite_set_cov(buf, 9u);
    TEST_ASSERT_NOT_EQUAL(base, idemip_udplite_cksum_compute(buf, 8u, V_LITE_IPL, SRC, DST));
}

// RFC 3828 sec 3.5: "The Checksum Coverage field is 16 bits and can represent a Checksum Coverage
// value of up to 65535 octets."
void test_coverage_is_sixteen_bits(void)
{
    idemip_udplite_set_cov(buf, 0xFFFFu);
    TEST_ASSERT_EQUAL_UINT16(0xFFFFu, idemip_udplite_cov(buf));
    TEST_ASSERT_EQUAL_size_t(0xFFFFu, idemip_udplite_cov_bytes(0xFFFFu, 0xFFFFu));
    TEST_ASSERT_TRUE(idemip_udplite_cov_valid(0xFFFFu, 0xFFFFu));
}
