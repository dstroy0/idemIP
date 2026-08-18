// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 3828, the partial-coverage checksum, as a golden module. The reference suite's six claims are
// carried first:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. the RFC 3828 sec 3.1 discard rules are exercised one at a time
//   6. BUSY and ERR are separated by whether retrying can ever succeed, and nothing here is BUSY
//
// Then the subtlety this unit exists for: RFC 3828 sec 3.2 puts the IP payload length in the
// pseudo-header while the Checksum Coverage bounds only the octets summed, so the two lengths are
// moved independently and both are shown to matter.
//
// VECTORS. RFC 3828 prints no worked checksum example: figure 1 is a field layout and sections 3.1
// through 3.5 state properties in prose. So the properties are asserted directly, and the numbers
// below come from outside this suite:
//
//   - RFC 1071 sec 3 does print one. Its octet string 00 01 f2 03 f4 f5 f6 f7 sums to ddf2, and
//     that anchors the sum this unit runs (test_rfc_1071_prints_the_one_worked_sum).
//   - the four IPv4 UDP-Lite values are the ones test/unit/udp/test_udp already carries, produced
//     there by a Python implementation of RFC 1071 and cross-checked against scapy 2.7.0.
//   - the IPv6 values were produced by a Python implementation of RFC 1071 sec 1 with the RFC 8200
//     sec 8.1 pseudo-header, written from the RFC text rather than from this tree. That same
//     script reproduces RFC 1071 sec 3's printed sum and all four IPv4 values above, which is what
//     makes its IPv6 output usable here.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/udp/udplite.h"

#include <string.h>
#include <unity.h>

// --- the vectors -------------------------------------------------------------

// 192.168.0.1 and 192.168.0.2, the addresses every IPv4 vector was summed with. Four octets, which
// is the width RFC 791 sec 3.1 gives an address.
static const uint8_t src4[4] = {192, 168, 0, 1};
static const uint8_t dst4[4] = {192, 168, 0, 2};

// 2001:db8::1 and 2001:db8::2, the RFC 3849 documentation prefix. Sixteen octets (RFC 4291 sec 2).
static const uint8_t src6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t dst6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

// RFC 3828 figure 1: Source Port, Destination Port, Checksum Coverage, Checksum, then the payload.
// Sixteen payload octets follow the eight-octet header, so the IP payload is 24.
static const uint8_t v_lite[] = {0xAB, 0xCD, 0x10, 0x00, 0x00, 0x08, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
                                 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
#define V_IPL 24u
#define V_SRC_PORT 0xABCDu
#define V_DST_PORT 0x1000u

// IPv4, ip_payload_len 24.
#define V4_COV0_CKSUM 0x097Du
#define V4_COV8_CKSUM 0xC235u
#define V4_COV12_CKSUM 0xA00Du
#define V4_COV24_CKSUM 0x0965u
// The same Coverage of 8, with the IP module reporting 32 octets of payload instead of 24.
#define V4_COV8_IPL32_CKSUM 0xC22Du

// IPv6, ip_payload_len 24.
#define V6_COV0_CKSUM 0x2F5Cu
#define V6_COV8_CKSUM 0xE814u
#define V6_COV12_CKSUM 0xC5ECu
#define V6_COV24_CKSUM 0x2F44u
#define V6_COV8_IPL32_CKSUM 0xE80Cu

// RFC 1071 sec 3's printed example.
static const uint8_t v_rfc1071[8] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};

// --- the borrow --------------------------------------------------------------
// Two of them, because the borrow is the instance. A canary follows each so a write past the map is
// visible.

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_UDPLITE_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_UDPLITE_BORROW + 16];

// The datagram buffers, the caller's, outside the borrow. A canary follows each.
static uint8_t buf[64];
static uint8_t buf_b[64];

// RFC 3828 sec 3.5: the Checksum Coverage field is 16 bits, so a Jumbogram is covered whole only
// through the zero value. 66000 octets is past what that field can name.
#define JUMBO_IPL 66000u
static uint8_t jumbo[JUMBO_IPL + 16u];

static void arm_work(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_UDPLITE_BORROW, CANARY, cap - IDEMIP_UDPLITE_BORROW);
}

static void check_work_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_UDPLITE_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_UDPLITE_BORROW");
    }
}

void setUp(void)
{
    arm_work(work_a, sizeof work_a);
    arm_work(work_b, sizeof work_b);
    memset(buf, CANARY, sizeof buf);
    memset(buf_b, CANARY, sizeof buf_b);
    memcpy(buf, v_lite, sizeof v_lite);
    memcpy(buf_b, v_lite, sizeof v_lite);
}

void tearDown(void)
{
    check_work_canary(work_a, sizeof work_a);
    check_work_canary(work_b, sizeof work_b);
}

// --- helpers -----------------------------------------------------------------

static void ready(uint8_t *w)
{
    UdpLite.clear(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(w)->status);
}

// Fill check_args for an IPv4 datagram at d.
static void set_check4(uint8_t *w, const uint8_t *d, uint32_t ipl)
{
    IDEMIP_UDPLITE_IO(w)->check_args.dgram = d;
    IDEMIP_UDPLITE_IO(w)->check_args.src = src4;
    IDEMIP_UDPLITE_IO(w)->check_args.dst = dst4;
    IDEMIP_UDPLITE_IO(w)->check_args.ip_payload_len = ipl;
    IDEMIP_UDPLITE_IO(w)->check_args.ip_version = 4u;
}

static void set_check6(uint8_t *w, const uint8_t *d, uint32_t ipl)
{
    IDEMIP_UDPLITE_IO(w)->check_args.dgram = d;
    IDEMIP_UDPLITE_IO(w)->check_args.src = src6;
    IDEMIP_UDPLITE_IO(w)->check_args.dst = dst6;
    IDEMIP_UDPLITE_IO(w)->check_args.ip_payload_len = ipl;
    IDEMIP_UDPLITE_IO(w)->check_args.ip_version = 6u;
}

static void set_build(uint8_t *w, uint8_t *d, uint32_t ipl, uint16_t cov, uint8_t version)
{
    IDEMIP_UDPLITE_IO(w)->build_args.dgram = d;
    IDEMIP_UDPLITE_IO(w)->build_args.src = (version == 6u) ? src6 : src4;
    IDEMIP_UDPLITE_IO(w)->build_args.dst = (version == 6u) ? dst6 : dst4;
    IDEMIP_UDPLITE_IO(w)->build_args.ip_payload_len = ipl;
    IDEMIP_UDPLITE_IO(w)->build_args.src_port = V_SRC_PORT;
    IDEMIP_UDPLITE_IO(w)->build_args.dst_port = V_DST_PORT;
    IDEMIP_UDPLITE_IO(w)->build_args.cov = cov;
    IDEMIP_UDPLITE_IO(w)->build_args.ip_version = version;
}

static uint16_t build_v4(uint8_t *w, uint8_t *d, uint32_t ipl, uint16_t cov)
{
    set_build(w, d, ipl, cov, 4u);
    UdpLite.build(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(w)->status);
    return IDEMIP_UDPLITE_IO(w)->res.cksum;
}

static uint16_t build_v6(uint8_t *w, uint8_t *d, uint32_t ipl, uint16_t cov)
{
    set_build(w, d, ipl, cov, 6u);
    UdpLite.build(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(w)->status);
    return IDEMIP_UDPLITE_IO(w)->res.cksum;
}

// --- the borrow contract -----------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    UdpLite.clear(NULL);
    UdpLite.cover(NULL);
    UdpLite.check(NULL);
    UdpLite.build(NULL);
    TEST_PASS();
}

// A borrow that was never cleared carries no mark, so every entry refuses it rather than reading
// bytes nothing wrote.
void test_an_uncleared_borrow_refuses_work(void)
{
    set_check4(work_a, buf, V_IPL);
    UdpLite.cover(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    set_build(work_a, buf, V_IPL, 8u, 4u);
    UdpLite.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
}

void test_clear_zeroes_the_operand_block(void)
{
    set_check4(work_a, buf, V_IPL);
    set_build(work_a, buf, V_IPL, 12u, 4u);
    ready(work_a);
    TEST_ASSERT_NULL(IDEMIP_UDPLITE_IO(work_a)->check_args.dgram);
    TEST_ASSERT_NULL(IDEMIP_UDPLITE_IO(work_a)->build_args.dgram);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_UDPLITE_IO(work_a)->build_args.cov);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_UDPLITE_IO(work_a)->check_args.ip_payload_len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_NONE, IDEMIP_UDPLITE_IO(work_a)->reason);
}

// The borrow IS the instance, and the operand block is in it, so two of these share no byte at all.
void test_two_borrows_share_no_byte(void)
{
    ready(work_a);
    ready(work_b);
    set_check4(work_a, buf, V_IPL);
    set_check6(work_b, buf_b, V_IPL);

    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_UDPLITE_IO(work_a)->check_args.ip_version);
    TEST_ASSERT_EQUAL_UINT8(6u, IDEMIP_UDPLITE_IO(work_b)->check_args.ip_version);
    TEST_ASSERT_EQUAL_PTR(buf, IDEMIP_UDPLITE_IO(work_a)->check_args.dgram);
    TEST_ASSERT_EQUAL_PTR(buf_b, IDEMIP_UDPLITE_IO(work_b)->check_args.dgram);
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports. This is the determinism the design is named for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    ready(work_a);
    ready(work_b);
    (void)build_v4(work_a, buf, V_IPL, 8u);
    (void)build_v6(work_b, buf_b, V_IPL, 12u);

    set_check4(work_a, buf, V_IPL);
    set_check6(work_b, buf_b, V_IPL);

    UdpLite.check(work_a);
    uint16_t first = IDEMIP_UDPLITE_IO(work_a)->res.cksum;
    IdemIpStatus first_status = IDEMIP_UDPLITE_IO(work_a)->status;
    UdpLite.check(work_b);
    UdpLite.check(work_a);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, first_status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(V4_COV8_CKSUM, first);
    TEST_ASSERT_EQUAL_HEX16(first, IDEMIP_UDPLITE_IO(work_a)->res.cksum);
    TEST_ASSERT_EQUAL_HEX16(V6_COV12_CKSUM, IDEMIP_UDPLITE_IO(work_b)->res.cksum);
}

// The same call on the same bytes repeats, so a check may run twice with no difference.
void test_check_repeats_on_the_same_bytes(void)
{
    ready(work_a);
    (void)build_v4(work_a, buf, V_IPL, 12u);
    set_check4(work_a, buf, V_IPL);
    UdpLite.check(work_a);
    uint16_t c1 = IDEMIP_UDPLITE_IO(work_a)->res.cksum;
    uint32_t s1 = IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes;
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(c1, IDEMIP_UDPLITE_IO(work_a)->res.cksum);
    TEST_ASSERT_EQUAL_UINT32(s1, IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes);
}

// --- RFC 3828 sec 3.1, the Checksum Coverage rules ---------------------------

// "A Checksum Coverage of zero indicates that the entire UDP-Lite packet is covered by the
// checksum."
void test_coverage_of_zero_covers_the_entire_packet(void)
{
    ready(work_a);
    idemip_udplite_set_cov(buf, IDEMIP_UDPLITE_COV_ALL);
    set_check4(work_a, buf, V_IPL);
    UdpLite.cover(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_UDPLITE_IO(work_a)->res.cov);
    TEST_ASSERT_EQUAL_UINT32(V_IPL, IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes);
    TEST_ASSERT_TRUE(IDEMIP_UDPLITE_IO(work_a)->res.covered);
}

// "A UDP-Lite packet with a Checksum Coverage value of 1 to 7 MUST be discarded by the receiver."
void test_coverage_one_to_seven_is_discarded(void)
{
    ready(work_a);
    for (uint16_t cov = 1u; cov < IDEMIP_UDPLITE_COV_MIN; cov++)
    {
        idemip_udplite_set_cov(buf, cov);
        set_check4(work_a, buf, V_IPL);
        UdpLite.cover(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status,
                                      "a Checksum Coverage of 1 to 7 was kept");
        TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_COV_ILLEGAL, IDEMIP_UDPLITE_IO(work_a)->reason);
        UdpLite.check(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
        TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_COV_ILLEGAL, IDEMIP_UDPLITE_IO(work_a)->reason);
    }
}

// "the value of the Checksum Coverage field MUST be either 0 or at least 8", eight being the header
// that "MUST always be covered by the checksum".
void test_coverage_of_eight_is_the_smallest_one_kept(void)
{
    ready(work_a);
    idemip_udplite_set_cov(buf, IDEMIP_UDPLITE_COV_MIN);
    set_check4(work_a, buf, V_IPL);
    UdpLite.cover(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(8u, IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes);
    TEST_ASSERT_FALSE(IDEMIP_UDPLITE_IO(work_a)->res.covered);
}

// "UDP-Lite packets with a Checksum Coverage greater than the IP length MUST also be discarded."
void test_coverage_past_the_ip_length_is_discarded(void)
{
    ready(work_a);
    idemip_udplite_set_cov(buf, (uint16_t)(V_IPL + 1u));
    set_check4(work_a, buf, V_IPL);
    UdpLite.cover(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_COV_PAST_LEN, IDEMIP_UDPLITE_IO(work_a)->reason);

    idemip_udplite_set_cov(buf, 0xFFFFu);
    UdpLite.cover(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_COV_PAST_LEN, IDEMIP_UDPLITE_IO(work_a)->reason);
}

// "The UDP-Lite header MUST always be covered by the checksum", which an IP payload shorter than the
// header cannot satisfy at any Coverage, the zero value included.
void test_an_ip_payload_under_the_header_is_discarded(void)
{
    ready(work_a);
    for (uint32_t ipl = 0u; ipl < IDEMIP_UDPLITE_HDR_LEN; ipl++)
    {
        idemip_udplite_set_cov(buf, IDEMIP_UDPLITE_COV_ALL);
        set_check4(work_a, buf, ipl);
        UdpLite.cover(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status,
                                      "an IP payload under eight octets was kept");
        TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_SHORT, IDEMIP_UDPLITE_IO(work_a)->reason);

        idemip_udplite_set_cov(buf, IDEMIP_UDPLITE_COV_MIN);
        UdpLite.cover(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
        TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_SHORT, IDEMIP_UDPLITE_IO(work_a)->reason);
    }
}

// An IP payload of exactly the header is the shortest one kept, and it carries no payload octet.
void test_an_ip_payload_of_exactly_the_header_is_kept(void)
{
    ready(work_a);
    idemip_udplite_set_cov(buf, IDEMIP_UDPLITE_COV_ALL);
    set_check4(work_a, buf, IDEMIP_UDPLITE_HDR_LEN);
    UdpLite.cover(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(8u, IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_UDPLITE_IO(work_a)->res.payload_len);
    TEST_ASSERT_EQUAL_PTR(buf + IDEMIP_UDPLITE_HDR_LEN, IDEMIP_UDPLITE_IO(work_a)->res.payload);
}

// RFC 3828 sec 3.3 recommends the default "have the Checksum Coverage field match the length of the
// UDP-Lite packet". That reaches the same octets as sec 3.1's zero, so both report full coverage,
// and they are two different datagrams because the field itself is inside the span.
void test_coverage_equal_to_the_ip_length_covers_the_whole_packet(void)
{
    ready(work_a);
    idemip_udplite_set_cov(buf, (uint16_t)V_IPL);
    set_check4(work_a, buf, V_IPL);
    UdpLite.cover(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(V_IPL, IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes);
    TEST_ASSERT_TRUE(IDEMIP_UDPLITE_IO(work_a)->res.covered);

    TEST_ASSERT_EQUAL_HEX16(V4_COV24_CKSUM, build_v4(work_a, buf, V_IPL, (uint16_t)V_IPL));
    TEST_ASSERT_EQUAL_HEX16(V4_COV0_CKSUM, build_v4(work_a, buf, V_IPL, IDEMIP_UDPLITE_COV_ALL));
}

// RFC 3828 sec 3 puts Checksum Coverage where RFC 768 puts Length, so a check reads it out of the
// datagram rather than being told it.
void test_cover_reads_the_coverage_out_of_the_datagram(void)
{
    ready(work_a);
    TEST_ASSERT_EQUAL_UINT(IDEMIP_UDP_OFF_LEN, IDEMIP_UDPLITE_OFF_COV);
    idemip_udplite_set_cov(buf, 16u);
    set_check4(work_a, buf, V_IPL);
    UdpLite.cover(work_a);
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_UDPLITE_IO(work_a)->res.cov);
    TEST_ASSERT_EQUAL_UINT32(16u, IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes);
}

// cover applies the sec 3.1 rules alone: no address is read and no sum is run, so a datagram whose
// Checksum is wrong still passes it.
void test_cover_runs_no_sum_and_needs_no_addresses(void)
{
    ready(work_a);
    idemip_udplite_set_cov(buf, 12u);
    idemip_udp_set_cksum(buf, 0xDEADu);
    IDEMIP_UDPLITE_IO(work_a)->check_args.dgram = buf;
    IDEMIP_UDPLITE_IO(work_a)->check_args.src = NULL;
    IDEMIP_UDPLITE_IO(work_a)->check_args.dst = NULL;
    IDEMIP_UDPLITE_IO(work_a)->check_args.ip_payload_len = V_IPL;
    IDEMIP_UDPLITE_IO(work_a)->check_args.ip_version = 0u;
    UdpLite.cover(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(12u, IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes);

    // check runs the sum, so the same datagram is refused there.
    set_check4(work_a, buf, V_IPL);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_CKSUM_BAD, IDEMIP_UDPLITE_IO(work_a)->reason);
}

// --- the checksum, RFC 3828 sec 3.1 and sec 3.2 ------------------------------

// The one worked sum any of these RFCs prints. RFC 1071 sec 3 lists the octets 00 01 f2 03 f4 f5 f6
// f7 and carries them to Sum2 dd f2, the end-around carries folded in. This is the arithmetic every
// case below rests on: the checksum is that sum complemented.
void test_rfc_1071_prints_the_one_worked_sum(void)
{
    uint16_t c = idemip_cksum(v_rfc1071, sizeof v_rfc1071);
    TEST_ASSERT_EQUAL_HEX16(0xDDF2u, (uint16_t)~c);
    TEST_ASSERT_EQUAL_HEX16(0x220Du, c);
}

void test_build_matches_the_independent_ipv4_vectors(void)
{
    ready(work_a);
    TEST_ASSERT_EQUAL_HEX16(V4_COV0_CKSUM, build_v4(work_a, buf, V_IPL, IDEMIP_UDPLITE_COV_ALL));
    memcpy(buf, v_lite, sizeof v_lite);
    TEST_ASSERT_EQUAL_HEX16(V4_COV8_CKSUM, build_v4(work_a, buf, V_IPL, 8u));
    memcpy(buf, v_lite, sizeof v_lite);
    TEST_ASSERT_EQUAL_HEX16(V4_COV12_CKSUM, build_v4(work_a, buf, V_IPL, 12u));
    memcpy(buf, v_lite, sizeof v_lite);
    TEST_ASSERT_EQUAL_HEX16(V4_COV24_CKSUM, build_v4(work_a, buf, V_IPL, (uint16_t)V_IPL));
}

void test_build_matches_the_independent_ipv6_vectors(void)
{
    ready(work_a);
    TEST_ASSERT_EQUAL_HEX16(V6_COV0_CKSUM, build_v6(work_a, buf, V_IPL, IDEMIP_UDPLITE_COV_ALL));
    memcpy(buf, v_lite, sizeof v_lite);
    TEST_ASSERT_EQUAL_HEX16(V6_COV8_CKSUM, build_v6(work_a, buf, V_IPL, 8u));
    memcpy(buf, v_lite, sizeof v_lite);
    TEST_ASSERT_EQUAL_HEX16(V6_COV12_CKSUM, build_v6(work_a, buf, V_IPL, 12u));
    memcpy(buf, v_lite, sizeof v_lite);
    TEST_ASSERT_EQUAL_HEX16(V6_COV24_CKSUM, build_v6(work_a, buf, V_IPL, (uint16_t)V_IPL));
}

// THE SUBTLETY. RFC 3828 sec 3.2: "The value of the Length field of the pseudo header is not taken
// from the UDP-Lite header, but rather from information provided by the IP module." So holding the
// Coverage at eight and moving only the IP payload length moves the checksum, which it could not do
// if the pseudo-header carried the Coverage instead.
void test_the_pseudo_header_length_is_the_ip_payload_not_the_coverage(void)
{
    ready(work_a);
    uint16_t at24 = build_v4(work_a, buf, V_IPL, 8u);
    memcpy(buf, v_lite, sizeof v_lite);
    uint16_t at32 = build_v4(work_a, buf, 32u, 8u);

    TEST_ASSERT_EQUAL_HEX16(V4_COV8_CKSUM, at24);
    TEST_ASSERT_EQUAL_HEX16(V4_COV8_IPL32_CKSUM, at32);
    TEST_ASSERT_NOT_EQUAL_HEX16_MESSAGE(at24, at32,
                                        "the pseudo-header took the Coverage rather than the IP payload length");

    // The two differ by exactly the eight octets the length moved, in one's complement: the sum
    // before complementing rose by 8, so the complement fell by 8.
    TEST_ASSERT_EQUAL_HEX16((uint16_t)(at24 - 8u), at32);
}

void test_the_pseudo_header_length_is_the_ip_payload_over_ipv6_too(void)
{
    ready(work_a);
    uint16_t at24 = build_v6(work_a, buf, V_IPL, 8u);
    memcpy(buf, v_lite, sizeof v_lite);
    uint16_t at32 = build_v6(work_a, buf, 32u, 8u);

    TEST_ASSERT_EQUAL_HEX16(V6_COV8_CKSUM, at24);
    TEST_ASSERT_EQUAL_HEX16(V6_COV8_IPL32_CKSUM, at32);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)(at24 - 8u), at32);
}

// The same reading from the receive side: a datagram built at one IP payload length does not verify
// when the IP module reports another, even though the Coverage is untouched.
void test_check_refuses_a_datagram_summed_at_another_ip_payload_length(void)
{
    ready(work_a);
    (void)build_v4(work_a, buf, V_IPL, 8u);
    set_check4(work_a, buf, V_IPL);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);

    set_check4(work_a, buf, 32u);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_CKSUM_BAD, IDEMIP_UDPLITE_IO(work_a)->reason);
}

// RFC 3828 sec 5 and sec 7: "UDP-Lite has been allocated a separate IP protocol identifier, 136
// (UDPLite)". The pseudo-header carries that rather than RFC 768's 17, so a datagram summed as UDP
// does not verify as UDP-Lite even with identical octets, addresses and length.
void test_the_pseudo_header_protocol_is_one_hundred_thirty_six(void)
{
    TEST_ASSERT_EQUAL_UINT(136u, IDEMIP_UDPLITE_PROTO);
    ready(work_a);

    // An RFC 768 datagram: the same eight-octet header, Length 24 where UDP-Lite reads Coverage 24,
    // summed over the whole datagram with protocol 17.
    idemip_udp_build(buf, V_SRC_PORT, V_DST_PORT, (uint16_t)V_IPL);
    idemip_udp_cksum_write(buf, V_IPL, 0xC0A80001u, 0xC0A80002u);
    TEST_ASSERT_TRUE(idemip_udp_cksum_valid(buf, V_IPL, 0xC0A80001u, 0xC0A80002u));

    set_check4(work_a, buf, V_IPL);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_CKSUM_BAD, IDEMIP_UDPLITE_IO(work_a)->reason);
}

// What build wrote, check accepts, at every Coverage and over both IP versions.
void test_check_accepts_what_build_wrote(void)
{
    ready(work_a);
    static const uint16_t covs[4] = {IDEMIP_UDPLITE_COV_ALL, 8u, 12u, (uint16_t)V_IPL};
    for (size_t i = 0; i < 4; i++)
    {
        memcpy(buf, v_lite, sizeof v_lite);
        (void)build_v4(work_a, buf, V_IPL, covs[i]);
        set_check4(work_a, buf, V_IPL);
        UdpLite.check(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status, "an IPv4 round trip failed");
        TEST_ASSERT_EQUAL_UINT16(covs[i], IDEMIP_UDPLITE_IO(work_a)->res.cov);

        memcpy(buf, v_lite, sizeof v_lite);
        (void)build_v6(work_a, buf, V_IPL, covs[i]);
        set_check6(work_a, buf, V_IPL);
        UdpLite.check(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status, "an IPv6 round trip failed");
    }
}

// RFC 3828 sec 1: "Errors in the insensitive part will not cause the packet to be discarded by the
// transport layer at the receiving end host." A flip inside the coverage is caught; the same flip
// past it is delivered.
void test_a_flip_inside_the_coverage_is_caught_and_one_past_it_is_delivered(void)
{
    ready(work_a);
    (void)build_v4(work_a, buf, V_IPL, 12u);

    for (size_t i = 0; i < 12u; i++)
    {
        memcpy(buf_b, buf, sizeof v_lite);
        buf_b[i] ^= 0x01u;
        set_check4(work_a, buf_b, V_IPL);
        UdpLite.check(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status,
                                      "a flipped bit inside the coverage still verified");
    }
    for (size_t i = 12u; i < sizeof v_lite; i++)
    {
        memcpy(buf_b, buf, sizeof v_lite);
        buf_b[i] ^= 0x01u;
        set_check4(work_a, buf_b, V_IPL);
        UdpLite.check(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status,
                                      "a flipped bit outside the coverage broke the checksum");
    }
}

// RFC 3828 sec 3.1: "If the computed checksum is 0, it is transmitted as all ones (the equivalent in
// one's complement arithmetic)." The Destination Port below was searched for so the covered eight
// octets and the IPv6 pseudo-header sum to all ones.
void test_a_computed_zero_is_transmitted_as_all_ones(void)
{
    ready(work_a);
    IDEMIP_UDPLITE_IO(work_a)->build_args.dgram = buf;
    IDEMIP_UDPLITE_IO(work_a)->build_args.src = src6;
    IDEMIP_UDPLITE_IO(work_a)->build_args.dst = dst6;
    IDEMIP_UDPLITE_IO(work_a)->build_args.ip_payload_len = V_IPL;
    IDEMIP_UDPLITE_IO(work_a)->build_args.src_port = V_SRC_PORT;
    IDEMIP_UDPLITE_IO(work_a)->build_args.dst_port = 0xF814u;
    IDEMIP_UDPLITE_IO(work_a)->build_args.cov = 8u;
    IDEMIP_UDPLITE_IO(work_a)->build_args.ip_version = 6u;
    UdpLite.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_UDP_CKSUM_ZERO_AS, idemip_udp_cksum(buf));
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_UDP_CKSUM_ZERO_AS, IDEMIP_UDPLITE_IO(work_a)->res.cksum);

    // All ones is what verifies, so the datagram is a good one.
    set_check6(work_a, buf, V_IPL);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
}

// RFC 3828 sec 3.1: "Since the transmitted checksum MUST NOT be all zeroes". No conforming sender
// emits one, so a datagram carrying it is refused before the sum runs.
void test_an_all_zero_checksum_is_refused(void)
{
    ready(work_a);
    (void)build_v4(work_a, buf, V_IPL, 8u);
    idemip_udp_set_cksum(buf, IDEMIP_UDP_CKSUM_NONE);
    set_check4(work_a, buf, V_IPL);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_CKSUM_ZERO, IDEMIP_UDPLITE_IO(work_a)->reason);
}

// --- what a call reports -----------------------------------------------------

// RFC 3828 sec 3.4: "the length of the UDP-Lite payload delivered to the receiver depends on the
// length of the IP payload", and sec 3.3 has an application make no assumption "beyond the position
// indicated by the Checksum Coverage field".
void test_check_reports_how_far_the_coverage_reaches(void)
{
    ready(work_a);
    (void)build_v4(work_a, buf, V_IPL, 12u);
    set_check4(work_a, buf, V_IPL);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(buf + IDEMIP_UDPLITE_HDR_LEN, IDEMIP_UDPLITE_IO(work_a)->res.payload);
    TEST_ASSERT_EQUAL_UINT32(V_IPL - IDEMIP_UDPLITE_HDR_LEN, IDEMIP_UDPLITE_IO(work_a)->res.payload_len);
    TEST_ASSERT_EQUAL_UINT32(12u, IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes);
    TEST_ASSERT_FALSE(IDEMIP_UDPLITE_IO(work_a)->res.covered);

    memcpy(buf, v_lite, sizeof v_lite);
    (void)build_v4(work_a, buf, V_IPL, IDEMIP_UDPLITE_COV_ALL);
    set_check4(work_a, buf, V_IPL);
    UdpLite.check(work_a);
    TEST_ASSERT_TRUE(IDEMIP_UDPLITE_IO(work_a)->res.covered);
}

// RFC 3828 sec 3.1 keeps RFC 768's two ports and puts Coverage in the third field, so a build writes
// exactly those eight octets and no payload octet.
void test_build_writes_the_header_and_no_payload_octet(void)
{
    ready(work_a);
    (void)build_v4(work_a, buf, V_IPL, 12u);
    TEST_ASSERT_EQUAL_HEX16(V_SRC_PORT, idemip_udp_src_port(buf));
    TEST_ASSERT_EQUAL_HEX16(V_DST_PORT, idemip_udp_dst_port(buf));
    TEST_ASSERT_EQUAL_UINT16(12u, idemip_udplite_cov(buf));
    TEST_ASSERT_EQUAL_HEX16(V4_COV12_CKSUM, idemip_udp_cksum(buf));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(v_lite + IDEMIP_UDPLITE_HDR_LEN, buf + IDEMIP_UDPLITE_HDR_LEN,
                                  sizeof v_lite - IDEMIP_UDPLITE_HDR_LEN);
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, buf[sizeof v_lite], "a build wrote past the IP payload");
}

// --- refusals: every one is ERR, none is BUSY --------------------------------

// Nothing here holds a resource a later call frees, so no refusal is a retry. Every rule above,
// gathered: the status is ERR each time and IDEMIP_BUSY appears nowhere.
void test_no_refusal_is_ever_busy(void)
{
    ready(work_a);

    // 1 to 7
    idemip_udplite_set_cov(buf, 3u);
    set_check4(work_a, buf, V_IPL);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);

    // past the IP length
    idemip_udplite_set_cov(buf, 0xFFFFu);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);

    // an IP payload under the header
    idemip_udplite_set_cov(buf, IDEMIP_UDPLITE_COV_ALL);
    set_check4(work_a, buf, 4u);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);

    // a bad sum
    set_check4(work_a, buf, V_IPL);
    idemip_udp_set_cksum(buf, 0x1234u);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);

    // a null datagram
    IDEMIP_UDPLITE_IO(work_a)->check_args.dgram = NULL;
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    UdpLite.cover(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);

    // a null buffer on the build side
    set_build(work_a, NULL, V_IPL, 8u, 4u);
    UdpLite.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_ARG, IDEMIP_UDPLITE_IO(work_a)->reason);
}

// RFC 3828 sec 3.2: "This pseudo header is different for IPv4 and IPv6." A version that is neither
// names no pseudo-header, and no later call makes one appear.
void test_a_version_that_names_no_pseudo_header_is_refused(void)
{
    ready(work_a);
    static const uint8_t bad[4] = {0u, 1u, 5u, 7u};
    for (size_t i = 0; i < sizeof bad; i++)
    {
        set_check4(work_a, buf, V_IPL);
        IDEMIP_UDPLITE_IO(work_a)->check_args.ip_version = bad[i];
        UdpLite.check(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status, "an unknown IP version was taken");
        TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_ARG, IDEMIP_UDPLITE_IO(work_a)->reason);

        set_build(work_a, buf, V_IPL, 8u, bad[i]);
        UdpLite.build(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    }
}

// A refused build writes nothing: the datagram is left exactly as it arrived.
void test_a_refused_build_leaves_the_datagram_alone(void)
{
    ready(work_a);
    set_build(work_a, buf, V_IPL, 3u, 4u); // RFC 3828 sec 3.1: 1 to 7 is not a Coverage
    UdpLite.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_COV_ILLEGAL, IDEMIP_UDPLITE_IO(work_a)->reason);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(v_lite, buf, sizeof v_lite);
}

// RFC 791 sec 3.1 Total Length is 16 bits, so an IPv4 payload past 65535 cannot exist and the
// pseudo-header has no field to carry it.
void test_an_ipv4_payload_past_the_total_length_field_is_refused(void)
{
    ready(work_a);
    set_check4(work_a, buf, 0x10000u);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_ARG, IDEMIP_UDPLITE_IO(work_a)->reason);
}

// --- RFC 3828 sec 3.5, Jumbograms --------------------------------------------

// "The Checksum Coverage field is 16 bits and can represent a Checksum Coverage value of up to 65535
// octets... For Jumbograms, the checksum can cover either the entire payload (when the Checksum
// Coverage field has the value zero), or else at most the initial 65535 octets of the UDP-Lite
// packet." The IPv6 pseudo-header's Upper-Layer Packet Length is 32 bits (RFC 8200 sec 8.1), so the
// whole payload is summable while the field itself is not wide enough to name it.
void test_a_jumbogram_is_covered_whole_only_through_the_zero_value(void)
{
    ready(work_a);
    memset(jumbo, 0x5Au, sizeof jumbo);
    memcpy(jumbo, v_lite, sizeof v_lite);

    // Zero covers all 66000 octets.
    (void)build_v6(work_a, jumbo, JUMBO_IPL, IDEMIP_UDPLITE_COV_ALL);
    TEST_ASSERT_EQUAL_UINT32(JUMBO_IPL, IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes);
    TEST_ASSERT_TRUE(IDEMIP_UDPLITE_IO(work_a)->res.covered);
    set_check6(work_a, jumbo, JUMBO_IPL);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(JUMBO_IPL - IDEMIP_UDPLITE_HDR_LEN, IDEMIP_UDPLITE_IO(work_a)->res.payload_len);

    // The widest value the field can name is 65535, which leaves the tail uncovered.
    (void)build_v6(work_a, jumbo, JUMBO_IPL, 0xFFFFu);
    TEST_ASSERT_EQUAL_UINT32(0xFFFFu, IDEMIP_UDPLITE_IO(work_a)->res.cov_bytes);
    TEST_ASSERT_FALSE(IDEMIP_UDPLITE_IO(work_a)->res.covered);
    set_check6(work_a, jumbo, JUMBO_IPL);
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);

    // An octet past 65535 is outside the coverage, so it is delivered damaged.
    jumbo[65535] ^= 0xFFu;
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDPLITE_IO(work_a)->status);

    // The last octet inside it is not.
    jumbo[65534] ^= 0xFFu;
    UdpLite.check(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDPLITE_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_UDPLITE_REASON_CKSUM_BAD, IDEMIP_UDPLITE_IO(work_a)->reason);
}

// --- the borrow map ----------------------------------------------------------

// The map is public and every offset is a constant, so a reader sees where each region sits without
// opening the .c.
void test_the_borrow_map_is_compile_time(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_UDPLITE_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(sizeof(UdpLiteIo), IDEMIP_UDPLITE_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_UDPLITE_OFF_CTX < IDEMIP_UDPLITE_BORROW,
                             "the operand block filled the whole borrow, leaving no context");
    TEST_ASSERT_EQUAL_PTR(work_a, (uint8_t *)IDEMIP_UDPLITE_IO(work_a));
}
