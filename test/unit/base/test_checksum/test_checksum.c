// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 1071, the internet checksum. The worked example in section 3 is the vector.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/checksum.h"
#include "src/endian.h"

#include <unity.h>

void setUp(void)
{
}
void tearDown(void)
{
}

// The octets RFC 1071 sec 3 tabulates.
static const uint8_t rfc1071_example[8] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};

// RFC 1071 sec 3, the "Normal Order" column: Sum1 is 2ddf0 before the carries fold, Sum2 is ddf2
// after. The accumulator holds Sum1, the fold produces Sum2, and the checksum is its complement.
void test_rfc1071_section3_example(void)
{
    uint32_t sum1 = idemip_cksum_accum(0u, rfc1071_example, sizeof rfc1071_example);
    TEST_ASSERT_EQUAL_HEX32(0x2ddf0u, sum1);

    // idemip_cksum_final folds and complements in one step, so Sum2 is recovered by undoing the
    // complement.
    uint16_t final = idemip_cksum_final(sum1);
    TEST_ASSERT_EQUAL_HEX16(0xddf2u, (uint16_t)~final);
    TEST_ASSERT_EQUAL_HEX16(0x220du, final);
    TEST_ASSERT_EQUAL_HEX16(0x220du, idemip_cksum(rfc1071_example, sizeof rfc1071_example));
}

// RFC 1071 sec 3 also sums the same octets byte-swapped and reaches f2dd, whose final swap is
// ddf2 again. Section 2(B): "consistently swapping bytes simply rotates the bits within the sum".
void test_rfc1071_byte_order_independence(void)
{
    const uint8_t swapped[8] = {0x01, 0x00, 0x03, 0xf2, 0xf5, 0xf4, 0xf7, 0xf6};
    uint16_t a = (uint16_t)~idemip_cksum_final(idemip_cksum_accum(0u, rfc1071_example, 8u));
    uint16_t b = (uint16_t)~idemip_cksum_final(idemip_cksum_accum(0u, swapped, 8u));
    TEST_ASSERT_EQUAL_HEX16(0xddf2u, a);
    TEST_ASSERT_EQUAL_HEX16(0xf2ddu, b);
    // The final swap of f2dd is ddf2, which is the same sum.
    TEST_ASSERT_EQUAL_HEX16(a, (uint16_t)((b >> 8) | (b << 8)));
}

// RFC 1071 sec 1: a span carrying its own checksum sums to all ones, whose complement is zero.
void test_checksum_over_itself_is_zero(void)
{
    uint8_t buf[10];
    memcpy(buf, rfc1071_example, sizeof rfc1071_example);
    idemip_wr16(buf + 8, idemip_cksum(rfc1071_example, sizeof rfc1071_example));
    TEST_ASSERT_TRUE(idemip_cksum_valid(buf, sizeof buf));
}

// RFC 1071 sec 1: an odd count takes the final byte as [Z,0]. The pad completes the word and is
// never sent, so a trailing zero byte cannot change the result.
void test_odd_length_pads_high_half(void)
{
    const uint8_t odd[3] = {0x12, 0x34, 0x56};
    const uint8_t padded[4] = {0x12, 0x34, 0x56, 0x00};
    TEST_ASSERT_EQUAL_HEX16(idemip_cksum(padded, sizeof padded), idemip_cksum(odd, sizeof odd));
}

// The sum is order independent over 16-bit words (RFC 1071 sec 1, "byte order independence" and
// the associativity of the one's complement add), so accumulating in two calls matches one.
void test_accumulation_splits(void)
{
    uint32_t whole = idemip_cksum_accum(0u, rfc1071_example, 8u);
    uint32_t split = idemip_cksum_accum(idemip_cksum_accum(0u, rfc1071_example, 4u), rfc1071_example + 4u, 4u);
    TEST_ASSERT_EQUAL_HEX32(whole, split);
}

// An empty span contributes nothing, so the complement of zero is all ones.
void test_empty_span(void)
{
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu, idemip_cksum(rfc1071_example, 0u));
}
