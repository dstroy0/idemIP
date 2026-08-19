// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 1191 Path MTU Discovery, checked the way test_phy checks a golden module:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. BUSY and ERR are separated by whether retrying can ever succeed
//
// RFC 1191 prints no example message and no hex vector. What it does print is Table 7-1, the
// plateau column verbatim, and a set of stated properties: the sec 4 field layout, the sec 3
// bounds, the sec 5 search and its Note, and sec 6.3's aging. Those are what is asserted here.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/pmtu/pmtu4.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_PMTU4_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_PMTU4_BORROW + 16];

// RFC 1191 Table 7-1, the Plateau column as printed, largest first. The suite carries its own copy
// so a change to the module's table has to be made twice to go unnoticed.
static const uint16_t table_7_1[] = {65535u, 32000u, 17914u, 8166u, 4352u, 2002u, 1492u, 1006u, 508u, 296u, 68u};
#define TABLE_ROWS (sizeof table_7_1 / sizeof table_7_1[0])

// A Datagram Too Big: RFC 792 Type 3 Code 4, the sec 4 unused word carrying the Next-Hop MTU in its
// low half, then the internet header of the datagram that was too big.
static uint8_t g_msg[64];

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

// type, code, the whole unused word, then a quoted header of ihl words carrying dst, tos and total.
static size_t build(uint8_t type, uint8_t code, uint32_t unused, uint8_t ihl, uint8_t tos, uint16_t total,
                    uint32_t dst)
{
    memset(g_msg, 0, sizeof g_msg);
    g_msg[0] = type;
    g_msg[1] = code;
    put16(g_msg + 2, 0u); // checksum, not this module's
    put16(g_msg + 4, (uint16_t)(unused >> 16));
    put16(g_msg + 6, (uint16_t)(unused & 0xFFFFu));
    uint8_t *q = g_msg + 8;
    q[0] = (uint8_t)(0x40u | (ihl & 0x0Fu));
    q[1] = tos;
    put16(q + 2, total);
    q[9] = 1u; // protocol ICMP, unread here
    q[16] = (uint8_t)(dst >> 24);
    q[17] = (uint8_t)(dst >> 16);
    q[18] = (uint8_t)(dst >> 8);
    q[19] = (uint8_t)(dst & 0xFFu);
    return (size_t)8u + ((size_t)ihl * 4u);
}

// The common case: a modified router (sec 4) reporting its next-hop MTU for a 20-octet-header
// datagram of `total` octets bound for 10.0.0.1.
static size_t datagram_too_big(uint16_t next_hop_mtu, uint16_t total)
{
    return build(3u, 4u, (uint32_t)next_hop_mtu, 5u, 0u, total, 0x0A000001u);
}

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_PMTU4_BORROW, CANARY, cap - IDEMIP_PMTU4_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_PMTU4_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_PMTU4_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_msg, 0, sizeof g_msg);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

static void ready(uint8_t *w)
{
    Pmtu4.clear(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(w)->status);
}

static uint16_t below(uint8_t *w, uint16_t size)
{
    IDEMIP_PMTU4_IO(w)->plateau_args.size = size;
    Pmtu4.plateau_below(w);
    return IDEMIP_PMTU4_IO(w)->mtu;
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Pmtu4.clear(NULL);
    Pmtu4.too_big(NULL);
    Pmtu4.plateau_below(NULL);
    Pmtu4.plateau_above(NULL);
    Pmtu4.age(NULL);
    TEST_PASS();
}

// Every entry but clear refuses a borrow that was never cleared.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_PMTU4_IO(work_a)->plateau_args.size = 1500u;
    Pmtu4.plateau_below(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
    Pmtu4.plateau_above(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
    Pmtu4.age(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(1006u, 1500u);
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
}

// The borrow IS the instance, and the operand block is in it, so two of them share no byte at all.
void test_two_borrows_share_no_byte(void)
{
    ready(work_a);
    ready(work_b);
    IDEMIP_PMTU4_IO(work_a)->plateau_args.size = 4352u;
    IDEMIP_PMTU4_IO(work_b)->plateau_args.size = 1500u;
    TEST_ASSERT_EQUAL_UINT16(4352u, IDEMIP_PMTU4_IO(work_a)->plateau_args.size);

    Pmtu4.plateau_below(work_a);
    TEST_ASSERT_EQUAL_UINT16(2002u, IDEMIP_PMTU4_IO(work_a)->mtu);
    Pmtu4.plateau_below(work_b);
    TEST_ASSERT_EQUAL_UINT16(1492u, IDEMIP_PMTU4_IO(work_b)->mtu);
    TEST_ASSERT_EQUAL_UINT16(2002u, IDEMIP_PMTU4_IO(work_a)->mtu);
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports. This is the determinism the design is named for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    ready(work_a);
    ready(work_b);
    IDEMIP_PMTU4_IO(work_a)->plateau_args.size = 8166u;
    IDEMIP_PMTU4_IO(work_b)->plateau_args.size = 300u;

    Pmtu4.plateau_below(work_a);
    uint16_t first = IDEMIP_PMTU4_IO(work_a)->mtu;
    Pmtu4.plateau_below(work_b);
    Pmtu4.plateau_below(work_a);
    uint16_t second = IDEMIP_PMTU4_IO(work_a)->mtu;

    TEST_ASSERT_EQUAL_UINT16(4352u, first);
    TEST_ASSERT_EQUAL_UINT16(first, second);
}

// --- Table 7-1 ---------------------------------------------------------------

// sec 5's search is "the greatest plateau value that is less than the returned Total Length field",
// so asking one above each row hands that row back. RFC 791 sec 3.1 gives Total Length sixteen bits
// and Table 7-1's first row is 65535, so no length reaches over it: the search can never choose that
// row, and sec 7.1's raise is the only way to it. Every other row is walked here.
void test_every_row_of_table_7_1_is_searched(void)
{
    ready(work_a);
    for (size_t i = 1; i < TABLE_ROWS; i++)
    {
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(table_7_1[i], below(work_a, (uint16_t)(table_7_1[i] + 1u)),
                                         "a plateau of RFC 1191 Table 7-1 is missing or out of order");
    }
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(table_7_1[1], below(work_a, 65535u),
                                     "the widest Total Length still searches under the first row");
}

// The search is strict, so a length equal to a row lands on the row under it. This is the step the
// discovery process takes each round.
void test_a_length_on_a_row_steps_to_the_row_below(void)
{
    ready(work_a);
    for (size_t i = 0; i + 1 < TABLE_ROWS; i++)
    {
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(table_7_1[i + 1], below(work_a, table_7_1[i]),
                                         "the search did not step to the next plateau down");
    }
}

// sec 3: "A host MUST never reduce its estimate of the Path MTU below 68 octets", and Table 7-1 ends
// there, so nothing lies below it.
void test_no_plateau_lies_below_the_last_row(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->plateau_args.size = 68u;
    Pmtu4.plateau_below(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_PMTU4_IO(work_a)->mtu);

    IDEMIP_PMTU4_IO(work_a)->plateau_args.size = 20u;
    Pmtu4.plateau_below(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
}

// sec 5: "it takes only two round-trip times to go from an FDDI MTU to an Ethernet MTU". Table 7-1
// puts FDDI at 4352 and Ethernet at 1500, and two searches land at or under 1500.
void test_fddi_reaches_ethernet_in_two_searches(void)
{
    ready(work_a);
    uint16_t first = below(work_a, 4352u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(2002u, first);
    uint16_t second = below(work_a, first);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1492u, second);
    TEST_ASSERT_TRUE_MESSAGE(second <= 1500u, "two searches did not reach the RFC 894 Ethernet MTU");
}

// sec 7.1: "periodically increase the PMTU estimate to the next-highest value in the plateau table".
void test_the_raise_steps_up_the_table(void)
{
    ready(work_a);
    for (size_t i = TABLE_ROWS; i-- > 1;)
    {
        IDEMIP_PMTU4_IO(work_a)->plateau_args.size = table_7_1[i];
        IDEMIP_PMTU4_IO(work_a)->plateau_args.first_hop_mtu = 0u;
        Pmtu4.plateau_above(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(table_7_1[i - 1], IDEMIP_PMTU4_IO(work_a)->mtu,
                                         "the raise did not step to the next plateau up");
    }
}

// sec 7.1: "(or the first-hop MTU, if that is smaller)".
void test_the_raise_stops_at_the_first_hop_mtu(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->plateau_args.size = 1006u;
    IDEMIP_PMTU4_IO(work_a)->plateau_args.first_hop_mtu = 1500u;
    Pmtu4.plateau_above(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1492u, IDEMIP_PMTU4_IO(work_a)->mtu);

    // The next plateau over 1492 is 2002, which the first hop cannot carry, so the raise stops at
    // the link itself.
    IDEMIP_PMTU4_IO(work_a)->plateau_args.size = 1492u;
    Pmtu4.plateau_above(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_PMTU4_IO(work_a)->mtu);

    // And at the link's own MTU there is nothing left to raise to.
    IDEMIP_PMTU4_IO(work_a)->plateau_args.size = 1500u;
    Pmtu4.plateau_above(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
}

// Table 7-1's first row is RFC 791's "Official maximum MTU", so nothing lies above it.
void test_no_plateau_lies_above_the_first_row(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->plateau_args.size = 65535u;
    IDEMIP_PMTU4_IO(work_a)->plateau_args.first_hop_mtu = 0u;
    Pmtu4.plateau_above(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
}

// --- the Datagram Too Big ----------------------------------------------------

// sec 4: the router "MUST include the MTU of that next-hop network in the low-order 16 bits of the
// ICMP header field that is labelled unused".
void test_the_next_hop_mtu_is_the_estimate(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(1006u, 1500u);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 1500u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1006u, IDEMIP_PMTU4_IO(work_a)->next_hop_mtu);
    TEST_ASSERT_EQUAL_UINT16(1006u, IDEMIP_PMTU4_IO(work_a)->mtu);
    TEST_ASSERT_TRUE(IDEMIP_PMTU4_IO(work_a)->decreased);
    TEST_ASSERT_FALSE(IDEMIP_PMTU4_IO(work_a)->old_style);
}

// sec 4: "The high-order 16 bits remain unused, and MUST be set to zero." A sender that ignored that
// must not move the estimate, so only the low half is read.
void test_only_the_low_half_of_the_unused_word_is_read(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = build(3u, 4u, 0xDEAD03F6u, 5u, 0u, 1500u, 0x0A000001u);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 1500u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1014u, IDEMIP_PMTU4_IO(work_a)->mtu); // 0x03F6
}

// sec 6.2: "A path is identified by a source address, a destination address and an IP
// type-of-service", and sec 5: the message "contain[s] the IP header of the original datagram".
void test_the_path_comes_from_the_quoted_header(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = build(3u, 4u, 296u, 5u, 0x10u, 1500u, 0xC0A80105u);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 1500u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32(0xC0A80105u, IDEMIP_PMTU4_IO(work_a)->dst);
    TEST_ASSERT_EQUAL_HEX8(0x10u, IDEMIP_PMTU4_IO(work_a)->tos);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_PMTU4_IO(work_a)->total_len);
}

// sec 4: "This field will never contain a value less than 68, since every router must be able to
// forward a datagram of 68 octets without fragmentation", and sec 3 forbids reducing below it. A
// message claiming less can never be applied, so it is ERR and not BUSY.
void test_a_next_hop_mtu_below_68_is_refused(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(67u, 1500u);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 1500u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_PMTU4_IO(work_a)->mtu);

    // 68 itself is RFC 791's minimum and is accepted.
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(68u, 1500u);
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(68u, IDEMIP_PMTU4_IO(work_a)->mtu);
}

// sec 2 names one message: Destination Unreachable with "a code meaning fragmentation needed and DF
// set", RFC 792's Type 3 Code 4. Nothing else moves a path MTU.
void test_another_type_or_code_is_refused(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 1500u;

    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = build(3u, 1u, 1006u, 5u, 0u, 1500u, 0x0A000001u);
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status, "code 1 is host unreachable");

    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = build(11u, 4u, 1006u, 5u, 0u, 1500u, 0x0A000001u);
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status, "type 11 is time exceeded");
}

// The quoted internet header is where the path and the Total Length are, so a message short of it,
// or one whose quote is not an internet header, is refused.
void test_a_message_without_a_whole_quoted_header_is_refused(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 1500u;

    (void)datagram_too_big(1006u, 1500u);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = (size_t)IDEMIP_PMTU4_MSG_MIN - 1u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);

    // An IHL of 8 words needs 32 quoted octets, and only 20 are here.
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = build(3u, 4u, 1006u, 8u, 0u, 1500u, 0x0A000001u) - 12u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);

    // Version 6 in the quote, and an IHL below RFC 791's five words.
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(1006u, 1500u);
    g_msg[8] = 0x65u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
    g_msg[8] = 0x44u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
}

// sec 3: "A Datagram Too Big message from an unmodified router can be recognized by the presence of
// a zero in the (newly-defined) Next-Hop MTU field", and sec 5 then searches Table 7-1 from the
// returned Total Length.
void test_an_old_style_message_searches_the_plateau_table(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(0u, 4000u);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 4352u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_PMTU4_IO(work_a)->old_style);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_PMTU4_IO(work_a)->next_hop_mtu);
    TEST_ASSERT_EQUAL_UINT16(2002u, IDEMIP_PMTU4_IO(work_a)->mtu); // the greatest plateau under 4000
    TEST_ASSERT_TRUE(IDEMIP_PMTU4_IO(work_a)->decreased);
}

// sec 5's Note on 4.2BSD-derived routers: "If the Total Length field returned is not less than the
// current PMTU estimate, it must be reduced by 4 times the value of the returned Header Length
// field." A quoted length of 1500 against an estimate of 1500 is corrected to 1480, whose greatest
// plateau is 1006 rather than the 1492 an uncorrected length would have chosen.
void test_the_returned_total_length_is_corrected(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(0u, 1500u);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 1500u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1480u, IDEMIP_PMTU4_IO(work_a)->total_len);
    TEST_ASSERT_EQUAL_UINT16(1006u, IDEMIP_PMTU4_IO(work_a)->mtu);

    // A length already under the estimate is used as it stands.
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(0u, 1499u);
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1499u, IDEMIP_PMTU4_IO(work_a)->total_len);
    TEST_ASSERT_EQUAL_UINT16(1492u, IDEMIP_PMTU4_IO(work_a)->mtu);
}

// sec 3: "A host MUST not increase its estimate of the Path MTU in response to the contents of a
// Datagram Too Big message. A message purporting to announce an increase in the Path MTU might be a
// stale datagram... a false packet injected as part of a denial-of-service attack".
void test_a_message_never_raises_the_estimate(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(4352u, 1500u);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 1006u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(4352u, IDEMIP_PMTU4_IO(work_a)->next_hop_mtu, "the field is reported as it came");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(1006u, IDEMIP_PMTU4_IO(work_a)->mtu, "the held estimate must stand");
    TEST_ASSERT_FALSE(IDEMIP_PMTU4_IO(work_a)->decreased);

    // The same message, exactly at the held estimate, is not a decrease either.
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(1006u, 1500u);
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1006u, IDEMIP_PMTU4_IO(work_a)->mtu);
    TEST_ASSERT_FALSE(IDEMIP_PMTU4_IO(work_a)->decreased);
}

// sec 6.2: a row carrying no estimate has never been changed, so the first message that names the
// path decreases it.
void test_a_path_with_no_estimate_takes_the_first_message(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(296u, 1500u);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 0u;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(296u, IDEMIP_PMTU4_IO(work_a)->mtu);
    TEST_ASSERT_TRUE(IDEMIP_PMTU4_IO(work_a)->decreased);
}

// --- aging -------------------------------------------------------------------

// sec 6.3 initializes the timestamp "to a reserved value, indicating that the PMTU has never been
// changed", which is a row carrying no estimate. Nothing to raise now, and a Datagram Too Big makes
// something to raise, so it is BUSY and not ERR.
void test_a_row_that_was_never_decreased_is_busy(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->age_args.pmtu = 0u;
    IDEMIP_PMTU4_IO(work_a)->age_args.stamp_ms = 0u;
    IDEMIP_PMTU4_IO(work_a)->age_args.first_hop_mtu = 1500u;
    IDEMIP_PMTU4_IO(work_a)->now_ms = 10u * 60u * 1000u;
    Pmtu4.age(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_PMTU4_IO(work_a)->mtu);
}

// sec 3: an increase attempt "MUST NOT be done less than 5 minutes after a Datagram Too Big message
// has been received for the given destination", and IDEMIP_PMTU4_INCREASE_MS is the recommended
// twice that. One millisecond short is BUSY; the interval itself is due.
void test_the_raise_waits_out_the_interval(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->age_args.pmtu = 1006u;
    IDEMIP_PMTU4_IO(work_a)->age_args.stamp_ms = 1000u;
    IDEMIP_PMTU4_IO(work_a)->age_args.first_hop_mtu = 1500u;

    IDEMIP_PMTU4_IO(work_a)->now_ms = 1000u + (uint32_t)IDEMIP_PMTU4_INCREASE_MS - 1u;
    Pmtu4.age(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_PMTU4_IO(work_a)->status);

    IDEMIP_PMTU4_IO(work_a)->now_ms = 1000u + (uint32_t)IDEMIP_PMTU4_INCREASE_MS;
    Pmtu4.age(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1492u, IDEMIP_PMTU4_IO(work_a)->mtu);
}

// sec 6.3: "the PMTU estimate is set to the MTU of the associated first hop", reached by sec 7.1's
// step. Two ages take 1006 to 1492 and then to the link's own 1500.
void test_the_raise_climbs_to_the_first_hop_mtu(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->age_args.pmtu = 1006u;
    IDEMIP_PMTU4_IO(work_a)->age_args.stamp_ms = 0u;
    IDEMIP_PMTU4_IO(work_a)->age_args.first_hop_mtu = 1500u;
    IDEMIP_PMTU4_IO(work_a)->now_ms = (uint32_t)IDEMIP_PMTU4_INCREASE_MS;
    Pmtu4.age(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1492u, IDEMIP_PMTU4_IO(work_a)->mtu);

    IDEMIP_PMTU4_IO(work_a)->age_args.pmtu = 1492u;
    Pmtu4.age(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1500u, IDEMIP_PMTU4_IO(work_a)->mtu);

    // At the first hop's MTU there is nothing left to raise: BUSY, since a later decrease makes
    // room for another climb.
    IDEMIP_PMTU4_IO(work_a)->age_args.pmtu = 1500u;
    Pmtu4.age(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_PMTU4_IO(work_a)->status);
}

// A first hop that cannot carry the 68 octets RFC 791 requires of every router is not a link an
// estimate can be raised to, and no later call changes that: ERR, not BUSY.
void test_a_first_hop_below_68_is_refused(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->age_args.pmtu = 296u;
    IDEMIP_PMTU4_IO(work_a)->age_args.stamp_ms = 0u;
    IDEMIP_PMTU4_IO(work_a)->age_args.first_hop_mtu = 67u;
    IDEMIP_PMTU4_IO(work_a)->now_ms = (uint32_t)IDEMIP_PMTU4_INCREASE_MS;
    Pmtu4.age(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PMTU4_IO(work_a)->status);
}

// The clock is a wrapping millisecond count, so an interval that straddles the wrap is still one
// interval.
void test_the_interval_survives_a_clock_wrap(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->age_args.pmtu = 1006u;
    IDEMIP_PMTU4_IO(work_a)->age_args.stamp_ms = 0xFFFFFFFFu - 1000u;
    IDEMIP_PMTU4_IO(work_a)->age_args.first_hop_mtu = 1500u;
    IDEMIP_PMTU4_IO(work_a)->now_ms = (uint32_t)(0xFFFFFFFFu - 1000u + (uint32_t)IDEMIP_PMTU4_INCREASE_MS);
    Pmtu4.age(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PMTU4_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1492u, IDEMIP_PMTU4_IO(work_a)->mtu);
}

// The same call on the same bytes reports the same thing, however often it runs.
void test_the_same_message_repeats(void)
{
    ready(work_a);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.msg = g_msg;
    IDEMIP_PMTU4_IO(work_a)->too_big_args.len = datagram_too_big(0u, 8166u);
    IDEMIP_PMTU4_IO(work_a)->too_big_args.held = 17914u;
    Pmtu4.too_big(work_a);
    uint16_t first = IDEMIP_PMTU4_IO(work_a)->mtu;
    uint32_t dst = IDEMIP_PMTU4_IO(work_a)->dst;
    Pmtu4.too_big(work_a);
    TEST_ASSERT_EQUAL_UINT16(first, IDEMIP_PMTU4_IO(work_a)->mtu);
    TEST_ASSERT_EQUAL_HEX32(dst, IDEMIP_PMTU4_IO(work_a)->dst);
    TEST_ASSERT_EQUAL_UINT16(4352u, first);
}
