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
// after, and the checksum is Sum2's complement. sec 1 applies the end-around carry "until none
// remains", so the two are one number written two ways; the accumulator reports it folded, which is
// what makes the value the same however a span was split or whichever route a call took through it.
void test_rfc1071_section3_example(void)
{
    uint32_t sum = idemip_cksum_accum(0u, rfc1071_example, sizeof rfc1071_example);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0xddf2u, sum, "the accumulator reports the section 3 Sum2");

    // The table's own arithmetic: Sum1 with its carries folded is Sum2.
    uint32_t sum1 = 0x2ddf0u;
    TEST_ASSERT_EQUAL_HEX32(0xddf2u, (sum1 & 0xFFFFu) + (sum1 >> 16));

    // idemip_cksum_final folds and complements in one step, so Sum2 is recovered by undoing the
    // complement. Folding an already-folded sum is the same sum, which is what lets it run on both.
    uint16_t final = idemip_cksum_final(sum);
    TEST_ASSERT_EQUAL_HEX16(0xddf2u, (uint16_t)~final);
    TEST_ASSERT_EQUAL_HEX16(0x220du, final);
    TEST_ASSERT_EQUAL_HEX16(0x220du, idemip_cksum_final(sum1));
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

// --- the word path against the definition ------------------------------------

// RFC 1071 sec 1 written out on its own terms, with nothing shared with the unit under test: "the
// 16-bit 1's complement of the 1's complement sum of all 16-bit words", the words being [A,B] and an
// odd count taking the last byte as [Z,0]. Every carry is applied as it goes, so the value is the
// folded one whatever the length.
static uint16_t reference_sum(const uint8_t *p, size_t len)
{
    uint32_t sum = 0u;
    size_t i = 0u;
    while (i + 1u < len)
    {
        sum += (uint32_t)(((uint32_t)p[i] << 8) | (uint32_t)p[i + 1u]);
        sum = (sum & 0xFFFFu) + (sum >> 16);
        i += 2u;
    }
    if (i < len)
    {
        sum += (uint32_t)((uint32_t)p[i] << 8);
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)sum;
}

// sec 2 (C)'s parallel sum is only the same number if it agrees with sec 1 for every length and at
// every address a span can begin at. A word covers eight octets at most, so a run of nine start
// offsets crosses every alignment a word load can meet, and lengths through 96 cross the word loop's
// entry, its body and its tail. The bytes are a fixed pattern with a 0xFF run and a zero run in it,
// so a carry lands inside the loop rather than only at the fold.
void test_the_word_path_matches_the_section_1_definition(void)
{
    static uint8_t buf[128];
    for (size_t i = 0; i < sizeof buf; i++)
    {
        buf[i] = (uint8_t)((i * 37u) ^ 0xA5u);
    }
    buf[16] = 0xFFu;
    buf[17] = 0xFFu;
    buf[18] = 0xFFu;
    buf[19] = 0xFFu;
    buf[32] = 0x00u;
    buf[33] = 0x00u;

    for (size_t off = 0; off <= 8u; off++)
    {
        for (size_t len = 0; len + off <= 96u; len++)
        {
            const uint8_t *p = buf + off;
            uint16_t want = reference_sum(p, len);
            uint32_t got = idemip_cksum_accum(0u, p, len);
            TEST_ASSERT_EQUAL_HEX32_MESSAGE(want, got, "the word path disagreed with RFC 1071 sec 1");
            // sec 1: the checksum is that sum complemented.
            TEST_ASSERT_EQUAL_HEX16((uint16_t)~want, idemip_cksum_final(got));
        }
    }
}

// A running sum is the same number however the span was cut, which is what lets a pseudo-header and
// a payload be summed in two calls. Every cut point of a span is taken, so a cut that lands mid-word
// is covered as well as one that lands on a word boundary.
void test_a_split_sum_matches_a_whole_one_at_every_cut(void)
{
    static uint8_t buf[80];
    for (size_t i = 0; i < sizeof buf; i++)
    {
        buf[i] = (uint8_t)(0xF0u - (uint8_t)(i * 11u));
    }

    for (size_t len = 0; len <= sizeof buf; len += 2u) // a cut is only defined on a 16-bit boundary
    {
        uint32_t whole = idemip_cksum_accum(0u, buf, len);
        for (size_t cut = 0; cut <= len; cut += 2u)
        {
            uint32_t split = idemip_cksum_accum(idemip_cksum_accum(0u, buf, cut), buf + cut, len - cut);
            TEST_ASSERT_EQUAL_HEX32_MESSAGE(whole, split, "a split sum differed from the whole one");
        }
    }
}

// sec 1: a span carrying its own checksum sums to all ones, whose complement is zero. Run over every
// length the word path takes, so a sealed span verifies whichever route the sum went.
void test_a_sealed_span_verifies_at_every_length(void)
{
    static uint8_t buf[72];
    for (size_t len = 4u; len <= sizeof buf; len++)
    {
        for (size_t i = 0; i < len; i++)
        {
            buf[i] = (uint8_t)((i * 29u) + (uint8_t)len);
        }
        buf[2] = 0u;
        buf[3] = 0u;
        idemip_wr16(buf + 2u, idemip_cksum(buf, len));
        TEST_ASSERT_TRUE_MESSAGE(idemip_cksum_valid(buf, len), "a span carrying its own sum did not verify");
    }
}
