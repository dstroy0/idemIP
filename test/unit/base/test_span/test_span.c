// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// common.h's two span tests, which run over the machine's word.
//
// Nine call sites read them: RFC 4291 sec 2.5.2's unspecified address in icmp6_in, ip6_forward, dad,
// rdnss and netif, sec 2.5.3's ::1 in loopif, RFC 1122 sec 3.2.1.3 (a)'s "{ 0, 0 }" in the three pcb
// tables, and RFC 4291 sec 2.3's prefix match in ip6_addr. A word covers eight octets at most, so
// every case below crosses the word loop's entry, its body and its tail, and every alignment a word
// load can meet.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/common.h"

#include <string.h>
#include <unity.h>

#define SPAN 96u
#define ALIGNS 9u

// Aligned to IDEMIP_ALIGN and a word longer than the longest span either helper is asked for, which
// is what a borrow is: idemip.h declares every one of them `static _Alignas(IDEMIP_ALIGN) uint8_t`.
// The base being aligned is what makes the nine offsets below mean anything - they are then every
// alignment a word load can meet, rather than nine offsets from wherever the linker happened to put
// the array.
//
// The slack is for the tail. It is taken as one whole word and masked, so a span ending short of a
// word boundary is read out to the end of that word. In the library those octets are inside the
// caller's own borrow; here the slack is what makes that true of these two arrays. The cases below
// still set the octet immediately past each span, which the mask has to discard, so the slack
// widens the buffer without weakening anything the suite proves.
static _Alignas(IDEMIP_ALIGN) uint8_t buf[SPAN + ALIGNS + sizeof(IdemIpWord)];
static _Alignas(IDEMIP_ALIGN) uint8_t other[SPAN + ALIGNS + sizeof(IdemIpWord)];

void setUp(void)
{
    memset(buf, 0, sizeof buf);
    memset(other, 0, sizeof other);
}

void tearDown(void)
{
    // Nothing to release: this suite holds no allocation, only file-scope storage.
}

// The definition each helper is meant to compute, written out on its own terms so nothing is shared
// with the code under test.
static int reference_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        if (p[i] != 0u)
        {
            return 0;
        }
    }
    return 1;
}

static int reference_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        if (a[i] != b[i])
        {
            return 0;
        }
    }
    return 1;
}

// --- the word path against the definition ------------------------------------

// A zeroed span is zero at every length and from every address a span can begin at.
void test_a_zeroed_span_reads_zero_at_every_length_and_alignment(void)
{
    for (size_t off = 0; off < ALIGNS; off++)
    {
        for (size_t n = 0; n <= SPAN; n++)
        {
            TEST_ASSERT_TRUE_MESSAGE(idemip_bytes_zero(buf + off, n), "a zeroed span did not read zero");
        }
    }
}

// One octet set anywhere in a span is what makes it not zero, wherever the span begins and whichever
// side of the word loop's boundary that octet falls on. The octet outside the span must not be read.
void test_one_set_octet_anywhere_makes_a_span_not_zero(void)
{
    for (size_t off = 0; off < ALIGNS; off++)
    {
        for (size_t n = 1u; n <= 40u; n++)
        {
            for (size_t at = 0; at < n; at++)
            {
                memset(buf, 0, sizeof buf);
                buf[off + at] = 0x80u;
                TEST_ASSERT_FALSE_MESSAGE(idemip_bytes_zero(buf + off, n), "a set octet was not seen");
                TEST_ASSERT_EQUAL_INT(reference_zero(buf + off, n), (int)idemip_bytes_zero(buf + off, n));
            }
            // One octet past the end belongs to nobody, so it cannot change the answer.
            memset(buf, 0, sizeof buf);
            buf[off + n] = 0xFFu;
            TEST_ASSERT_TRUE_MESSAGE(idemip_bytes_zero(buf + off, n), "an octet past the end was read");
        }
    }
}

// Two spans are the same exactly when every octet is, and one octet apart anywhere is what makes
// them differ.
void test_equality_matches_the_definition_at_every_length_and_alignment(void)
{
    for (size_t off = 0; off < ALIGNS; off++)
    {
        for (size_t n = 0; n <= 40u; n++)
        {
            memset(buf, 0, sizeof buf);
            memset(other, 0, sizeof other);
            for (size_t i = 0; i < sizeof buf; i++)
            {
                buf[i] = (uint8_t)((i * 37u) ^ 0xA5u);
                other[i] = buf[i];
            }
            TEST_ASSERT_TRUE_MESSAGE(idemip_bytes_eq(buf + off, other + off, n), "equal spans did not compare equal");

            for (size_t at = 0; at < n; at++)
            {
                other[off + at] = (uint8_t)(buf[off + at] ^ 0x01u);
                TEST_ASSERT_FALSE_MESSAGE(idemip_bytes_eq(buf + off, other + off, n), "a differing octet was not seen");
                TEST_ASSERT_EQUAL_INT(reference_eq(buf + off, other + off, n),
                                      (int)idemip_bytes_eq(buf + off, other + off, n));
                other[off + at] = buf[off + at];
            }
            // One octet past the end belongs to nobody.
            other[off + n] = (uint8_t)(buf[off + n] ^ 0xFFu);
            TEST_ASSERT_TRUE_MESSAGE(idemip_bytes_eq(buf + off, other + off, n), "an octet past the end was read");
        }
    }
}

// An empty span holds no octet that could differ, so it is zero and it equals anything.
void test_an_empty_span_is_zero_and_equal(void)
{
    memset(buf, 0xFFu, sizeof buf);
    memset(other, 0x00u, sizeof other);
    TEST_ASSERT_TRUE(idemip_bytes_zero(buf, 0u));
    TEST_ASSERT_TRUE(idemip_bytes_eq(buf, other, 0u));
}

// The two spans a stack actually hands them: RFC 4291 sec 2 addresses are sixteen octets and RFC 791
// sec 3.1 ones are four, and both are what a word loop plus its tail has to cover exactly.
void test_the_address_widths_the_call_sites_use(void)
{
    // Each carries the slack the two fixtures above carry, and for the reason written there: the
    // tail is read out to the end of its word, and in the library those octets are inside the
    // caller's own borrow. A width is passed as the width itself, so the slack is never in a span.
    uint8_t a6[16u + sizeof(IdemIpWord)];
    uint8_t b6[16u + sizeof(IdemIpWord)];
    memset(a6, 0, sizeof a6);
    memset(b6, 0, sizeof b6);
    TEST_ASSERT_TRUE(idemip_bytes_zero(a6, 16u));
    TEST_ASSERT_TRUE(idemip_bytes_eq(a6, b6, 16u));

    // RFC 4291 sec 2.5.3's ::1 is fifteen zero octets and a low octet of one, which loopif reads as
    // a zero test over the leading fifteen.
    a6[15] = 0x01u;
    TEST_ASSERT_FALSE(idemip_bytes_zero(a6, 16u));
    TEST_ASSERT_TRUE_MESSAGE(idemip_bytes_zero(a6, 15u), "::1 is zero over its leading fifteen octets");
    TEST_ASSERT_FALSE(idemip_bytes_eq(a6, b6, 16u));

    uint8_t a4[4u + sizeof(IdemIpWord)];
    uint8_t b4[4u + sizeof(IdemIpWord)];
    memset(a4, 0, sizeof a4);
    memset(b4, 0, sizeof b4);
    b4[3] = 1u;
    TEST_ASSERT_TRUE_MESSAGE(idemip_bytes_zero(a4, 4u), "RFC 1122 sec 3.2.1.3 (a) is four zero octets");
    TEST_ASSERT_FALSE(idemip_bytes_zero(b4, 4u));
    TEST_ASSERT_FALSE(idemip_bytes_eq(a4, b4, 4u));
    TEST_ASSERT_TRUE(idemip_bytes_eq(a4, b4, 3u));
}
