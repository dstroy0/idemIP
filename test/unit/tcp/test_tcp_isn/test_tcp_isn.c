// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for the RFC 6528 sec 3 ISN generator. It tests the contract, not the PRF:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two generators share not one byte
//   4. the published offsets are ordered, non-overlapping, and inside IDEMIP_TCP_ISN_BORROW
//   5. reset zeroes the connection-id block and the working set, so no key octet survives it, and a
//      borrow that was never reset is refused
//   6. a key shorter than IDEMIP_TCP_ISN_SECRET_BYTES and a generate before a seed are refused
//
// Phase 3 added the behavior half below "the RFC equation". Neither RFC 6528 sec 3 nor RFC 9293 sec
// 3.4.1 prints a test vector, a figure, or an example ISN: both state only the expression and its
// properties. So the pinned digests here were computed by an independent SHA-256 (Python hashlib)
// over the RFC 6528 sec 3 concatenation, and every other case asserts a property the RFC text states.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/tcp/tcp_isn.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each so
// a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_TCP_ISN_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_TCP_ISN_BORROW + 16];

static const uint8_t g_key[IDEMIP_TCP_ISN_SECRET_BYTES] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u,
                                                           0x66u, 0x77u, 0x88u, 0x99u, 0xAAu, 0xBBu,
                                                           0xCCu, 0xDDu, 0xEEu, 0xFFu};
static const uint8_t g_local[IDEMIP_TCP_ISN_ADDR_BYTES] = {192u, 0u, 2u, 1u};
static const uint8_t g_remote[IDEMIP_TCP_ISN_ADDR_BYTES] = {192u, 0u, 2u, 9u};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_TCP_ISN_BORROW, CANARY, cap - IDEMIP_TCP_ISN_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_TCP_ISN_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_TCP_ISN_BORROW");
    }
}

static void check_zero(const uint8_t *w, size_t off, size_t len, const char *what)
{
    for (size_t i = 0; i < len; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, w[off + i], what);
    }
}

static void aim(uint8_t *w)
{
    IDEMIP_TCP_ISN_IO(w)->gen_args.local_ip = g_local;
    IDEMIP_TCP_ISN_IO(w)->gen_args.remote_ip = g_remote;
    IDEMIP_TCP_ISN_IO(w)->gen_args.local_port = 40000u;
    IDEMIP_TCP_ISN_IO(w)->gen_args.remote_port = 80u;
    IDEMIP_TCP_ISN_IO(w)->gen_args.ip_version = 4u;
    IDEMIP_TCP_ISN_IO(w)->gen_args.now_ms = 1000u;
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    TcpIsn.reset(NULL);
    TcpIsn.seed(NULL);
    TcpIsn.generate(NULL);
    TEST_PASS();
}

// The map is public, so a reader can place all four regions without opening the .c. Each starts where
// the one before it ends, and the last ends inside the borrow.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_TCP_ISN_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_TCP_ISN_OFF_IO + sizeof(TcpIsnIo), (size_t)IDEMIP_TCP_ISN_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_TCP_ISN_OFF_BLOCK >= (size_t)IDEMIP_TCP_ISN_OFF_CTX,
                             "the connection-id block overlaps the context");
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_TCP_ISN_OFF_BLOCK + IDEMIP_TCP_ISN_BLOCK_BYTES,
                             (size_t)IDEMIP_TCP_ISN_OFF_HASH);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_TCP_ISN_OFF_HASH + IDEMIP_TCP_ISN_HASH_BYTES <=
                                 (size_t)IDEMIP_TCP_ISN_BORROW,
                             "the working set runs past IDEMIP_TCP_ISN_BORROW");
    TEST_ASSERT_TRUE_MESSAGE(sizeof(TcpIsnIo) <= (size_t)IDEMIP_TCP_ISN_CTX_BYTES,
                             "the operand block runs into the connection-id block");
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_TCP_ISN_OFF_IO, IDEMIP_TCP_ISN_IO(work_a));
}

// RFC 6528 sec 3 feeds the PRF localip, localport, remoteip, remoteport and secretkey, so the block
// holds two addresses, two ports and the key.
void test_the_connection_id_block_holds_the_prf_inputs(void)
{
    TEST_ASSERT_TRUE_MESSAGE((2u * IDEMIP_TCP_ISN_ADDR_BYTES) + 4u + IDEMIP_TCP_ISN_SECRET_BYTES <=
                                 IDEMIP_TCP_ISN_BLOCK_BYTES,
                             "the connection-id block is short of RFC 6528 sec 3's inputs");
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TCP_ISN_SECRET_BYTES >= 16u,
                             "RFC 6528 sec 3: \"Key lengths of 128 bits should be adequate\"");
}

// RFC 6528 sec 3: "M is the 4 microsecond timer", and the caller's clock counts milliseconds.
void test_the_four_microsecond_timer_scales_from_milliseconds(void)
{
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_TCP_ISN_TICKS_PER_MS * 4u);
}

// Zeroed, never reset: every entry must refuse rather than hash a key that was never set.
void test_an_unreset_borrow_is_refused(void)
{
    aim(work_a);
    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key = g_key;
    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key_len = sizeof g_key;

    TcpIsn.seed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status);
    TcpIsn.generate(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_ISN_IO(work_a)->isn);
}

// --- reset -------------------------------------------------------------------

// A former key is in the block and in the working set as well as the context, so reset zeroes all
// three.
void test_reset_zeroes_the_block_and_the_working_set(void)
{
    memset(work_a + IDEMIP_TCP_ISN_OFF_CTX, 0xEE, (size_t)IDEMIP_TCP_ISN_BORROW - IDEMIP_TCP_ISN_OFF_CTX);
    TcpIsn.reset(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_ISN_IO(work_a)->status);
    check_zero(work_a, IDEMIP_TCP_ISN_OFF_BLOCK, IDEMIP_TCP_ISN_BLOCK_BYTES,
               "reset left an octet of the connection-id block");
    check_zero(work_a, IDEMIP_TCP_ISN_OFF_HASH, IDEMIP_TCP_ISN_HASH_BYTES,
               "reset left an octet of the working set");
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_ISN_IO(work_a)->isn);
}

// A second reset is the same call on the same bytes, so it reports the same thing.
void test_reset_repeats(void)
{
    TcpIsn.reset(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_ISN_IO(work_a)->status);
    TcpIsn.reset(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_ISN_IO(work_a)->status);
}

// The operand block is the caller's. reset reports through the result member and leaves the operands
// where they were.
void test_reset_leaves_the_operands_alone(void)
{
    aim(work_a);
    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key = g_key;
    TcpIsn.reset(work_a);
    TEST_ASSERT_EQUAL_PTR(g_key, IDEMIP_TCP_ISN_IO(work_a)->seed_args.key);
    TEST_ASSERT_EQUAL_PTR(g_local, IDEMIP_TCP_ISN_IO(work_a)->gen_args.local_ip);
    TEST_ASSERT_EQUAL_UINT16(80u, IDEMIP_TCP_ISN_IO(work_a)->gen_args.remote_port);
}

// --- two borrows -------------------------------------------------------------

// The borrow IS the generator, and the operand block is in it, so two generators share no byte at
// all. One connection's connection-id never reaches another's.
void test_two_borrows_share_no_byte(void)
{
    aim(work_a);
    aim(work_b);
    IDEMIP_TCP_ISN_IO(work_a)->gen_args.local_port = 40000u;
    IDEMIP_TCP_ISN_IO(work_b)->gen_args.local_port = 40001u;

    TEST_ASSERT_EQUAL_UINT16(40000u, IDEMIP_TCP_ISN_IO(work_a)->gen_args.local_port);
    TEST_ASSERT_EQUAL_UINT16(40001u, IDEMIP_TCP_ISN_IO(work_b)->gen_args.local_port);

    TcpIsn.reset(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_ISN_IO(work_a)->status);

    TEST_ASSERT_EQUAL_UINT16(40001u, IDEMIP_TCP_ISN_IO(work_b)->gen_args.local_port);
    TEST_ASSERT_EQUAL_UINT16(40000u, IDEMIP_TCP_ISN_IO(work_a)->gen_args.local_port);
}

// A reset on one borrow reaches no byte of the other's regions.
void test_a_reset_on_one_borrow_leaves_the_other_regions_untouched(void)
{
    const size_t span = (size_t)IDEMIP_TCP_ISN_BORROW - IDEMIP_TCP_ISN_OFF_BLOCK;
    memset(work_b + IDEMIP_TCP_ISN_OFF_BLOCK, 0xC3, span);
    TcpIsn.reset(work_a);
    for (size_t i = 0; i < span; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[IDEMIP_TCP_ISN_OFF_BLOCK + i], "a reset crossed into b");
    }
    TcpIsn.reset(work_b);
    check_zero(work_b, IDEMIP_TCP_ISN_OFF_BLOCK, span, "reset left an octet behind");
}

// --- the bounds on an operand ------------------------------------------------

// RFC 6528 sec 3: "The result of F() is no more secure than the secret key... Key lengths of 128 bits
// should be adequate." A shorter key is refused, and a retry with the same key can never succeed.
void test_a_key_shorter_than_the_secret_is_refused(void)
{
    TcpIsn.reset(work_a);
    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key = g_key;
    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key_len = IDEMIP_TCP_ISN_SECRET_BYTES - 1u;
    TcpIsn.seed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status);

    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key = NULL;
    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key_len = sizeof g_key;
    TcpIsn.seed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status);
}

// F() is a function of the connection-id and the key, so with no key there is nothing to compute and
// no retry can produce one.
void test_generate_before_a_seed_is_refused(void)
{
    TcpIsn.reset(work_a);
    aim(work_a);
    TcpIsn.generate(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_ISN_IO(work_a)->isn);
}

// localip and remoteip are read from the operand, so a null one is refused rather than dereferenced.
void test_a_missing_address_operand_is_refused(void)
{
    TcpIsn.reset(work_a);
    aim(work_a);
    IDEMIP_TCP_ISN_IO(work_a)->gen_args.local_ip = NULL;
    TcpIsn.generate(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status);

    aim(work_a);
    IDEMIP_TCP_ISN_IO(work_a)->gen_args.remote_ip = NULL;
    TcpIsn.generate(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status);
}

// =============================================================================
// The RFC equation
// =============================================================================
// RFC 6528 sec 3 and RFC 9293 sec 3.4.1 both state:
//
//   ISN = M + F(localip, localport, remoteip, remoteport, secretkey)
//
// "where M is the 4 microsecond timer, and F() is a pseudorandom function (PRF) of the connection-id.
// F() MUST NOT be computable from the outside" (RFC 9293 numbers that MUST-9).

// RFC 3849 sec 4 records 2001:DB8::/32 "as a documentation-only prefix in the IPv6 address registry",
// so a v6 pair comes from it. The pair below carries the same host numbers as the v4 pair declared
// above, which is out of RFC 5737 sec 3's 192.0.2.0/24 (TEST-NET-1).
static const uint8_t g_local6[IDEMIP_TCP_ISN_ADDR_BYTES] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0u, 0u, 0u, 0u,
                                                            0u,    0u,    0u,    0u,    0u, 0u, 0u, 1u};
static const uint8_t g_remote6[IDEMIP_TCP_ISN_ADDR_BYTES] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0u, 0u, 0u, 0u,
                                                             0u,    0u,    0u,    0u,    0u, 0u, 0u, 9u};

static const uint8_t g_key2[IDEMIP_TCP_ISN_SECRET_BYTES] = {0xA5u, 0xA5u, 0xA5u, 0xA5u, 0xA5u, 0xA5u,
                                                            0xA5u, 0xA5u, 0xA5u, 0xA5u, 0xA5u, 0xA5u,
                                                            0xA5u, 0xA5u, 0xA5u, 0xA5u};
static const uint8_t g_key_zero[IDEMIP_TCP_ISN_SECRET_BYTES] = {0};

// reset, take a key at a base, and aim at the v4 documentation pair.
static void ready(uint8_t *w, const uint8_t *key, size_t key_len, uint32_t base)
{
    TcpIsn.reset(w);
    IDEMIP_TCP_ISN_IO(w)->seed_args.key = key;
    IDEMIP_TCP_ISN_IO(w)->seed_args.key_len = key_len;
    IDEMIP_TCP_ISN_IO(w)->seed_args.base = base;
    TcpIsn.seed(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_ISN_IO(w)->status);
    aim(w);
}

static uint32_t gen(uint8_t *w)
{
    TcpIsn.generate(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_ISN_IO(w)->status);
    return IDEMIP_TCP_ISN_IO(w)->isn;
}

static uint32_t gen_at(uint8_t *w, uint32_t now_ms)
{
    IDEMIP_TCP_ISN_IO(w)->gen_args.now_ms = now_ms;
    return gen(w);
}

// Does @p needle appear anywhere in w[off .. off+len)?
static int carries(const uint8_t *w, size_t off, size_t len, const uint8_t *needle, size_t nlen)
{
    if (len < nlen)
    {
        return 0;
    }
    for (size_t i = 0; i + nlen <= len; i++)
    {
        if (memcmp(w + off + i, needle, nlen) == 0)
        {
            return 1;
        }
    }
    return 0;
}

// The connection-id is localip, localport, remoteip, remoteport, secretkey concatenated in that order
// (RFC 6528 sec 3). For the v4 pair that is c00002019c40c0000209005000112233445566778899aabbccddeeff,
// 28 octets, whose SHA-256 begins 7f9fa667. M is base 0 plus 1000 ms at 250 ticks each, so
// ISN = 250000 + 0x7F9FA667 = 0x7FA376F7. The digest is an independent SHA-256's, not this code's, so
// the case pins the byte layout and the hash together.
void test_the_isn_is_m_plus_f_over_the_connection_id(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    TEST_ASSERT_EQUAL_HEX32(0x7FA376F7u, gen(work_a));
}

// The same expression over an RFC 8200 sec 3 pair: all sixteen octets of each address enter, so the
// connection-id is 52 octets and its SHA-256 begins c72df26c.
void test_the_isn_is_m_plus_f_over_an_ipv6_connection_id(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    IDEMIP_TCP_ISN_IO(work_a)->gen_args.local_ip = g_local6;
    IDEMIP_TCP_ISN_IO(work_a)->gen_args.remote_ip = g_remote6;
    IDEMIP_TCP_ISN_IO(work_a)->gen_args.ip_version = 6u;
    TEST_ASSERT_EQUAL_HEX32(0xC731C2FCu, gen(work_a));
}

// F is fixed by the connection-id, so the whole difference between two ISNs of one tuple is M. RFC
// 6528 sec 3: "M is the 4 microsecond timer", which is 250 ticks in each of the caller's milliseconds.
void test_m_advances_two_hundred_fifty_ticks_per_millisecond(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t at0 = gen_at(work_a, 0u);
    uint32_t at1 = gen_at(work_a, 1u);
    uint32_t at4 = gen_at(work_a, 4u);
    TEST_ASSERT_EQUAL_UINT32(250u, at1 - at0);
    TEST_ASSERT_EQUAL_UINT32(1000u, at4 - at0);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_TCP_ISN_TICKS_PER_MS, at1 - at0);
}

// RFC 6528 sec 3 changes the key on events including "The system is being bootstrapped (e.g., the
// secret key could be a combination of some secret and the boot time of the machine)", so M counts
// from the base a seed took rather than from zero.
void test_m_counts_from_the_seeded_base(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t from_zero = gen_at(work_a, 0u);
    TEST_ASSERT_EQUAL_HEX32(0x7F9FA667u, from_zero);

    ready(work_b, g_key, sizeof g_key, 7u);
    TEST_ASSERT_EQUAL_HEX32(0x7F9FA66Eu, gen_at(work_b, 0u));
    TEST_ASSERT_EQUAL_UINT32(7u, gen_at(work_b, 0u) - from_zero);
}

// RFC 9293 sec 3.4.1: "This clock is a 32-bit counter that typically increments at least once every
// roughly 4 microseconds". A counter that wide wraps, and the sum wraps with it.
void test_m_wraps_as_a_thirty_two_bit_counter(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t at_zero = gen_at(work_a, 0u);

    ready(work_b, g_key, sizeof g_key, 0xFFFFFFFFu);
    uint32_t wrapped = gen_at(work_b, 0u);
    TEST_ASSERT_EQUAL_UINT32(at_zero, wrapped + 1u);
    TEST_ASSERT_NOT_EQUAL_UINT32(at_zero, wrapped);
}

// An entry is a function of its borrow alone, so the same call on the same bytes reports the same ISN.
void test_generate_repeats_on_the_same_borrow(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t first = gen(work_a);
    TEST_ASSERT_EQUAL_HEX32(first, gen(work_a));
    TEST_ASSERT_EQUAL_HEX32(first, gen(work_a));
}

// =============================================================================
// F is a PRF of the connection-id
// =============================================================================

// RFC 6528 sec 2: "We can prevent sequence number guessing attacks by giving each connection -- that
// is, each four-tuple of (localip, localport, remoteip, remoteport) -- a separate sequence number
// space." Each of the four legs is an input, so moving any one of them alone moves the ISN, and no two
// of the five spaces coincide.
void test_each_leg_of_the_four_tuple_changes_the_isn(void)
{
    static const uint8_t local_alt[IDEMIP_TCP_ISN_ADDR_BYTES] = {192u, 0u, 2u, 2u};
    static const uint8_t remote_alt[IDEMIP_TCP_ISN_ADDR_BYTES] = {192u, 0u, 2u, 10u};

    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t base = gen(work_a);

    ready(work_a, g_key, sizeof g_key, 0u);
    IDEMIP_TCP_ISN_IO(work_a)->gen_args.local_port = 40001u;
    uint32_t moved_lport = gen(work_a);

    ready(work_a, g_key, sizeof g_key, 0u);
    IDEMIP_TCP_ISN_IO(work_a)->gen_args.remote_port = 81u;
    uint32_t moved_rport = gen(work_a);

    ready(work_a, g_key, sizeof g_key, 0u);
    IDEMIP_TCP_ISN_IO(work_a)->gen_args.local_ip = local_alt;
    uint32_t moved_lip = gen(work_a);

    ready(work_a, g_key, sizeof g_key, 0u);
    IDEMIP_TCP_ISN_IO(work_a)->gen_args.remote_ip = remote_alt;
    uint32_t moved_rip = gen(work_a);

    TEST_ASSERT_NOT_EQUAL_UINT32(base, moved_lport);
    TEST_ASSERT_NOT_EQUAL_UINT32(base, moved_rport);
    TEST_ASSERT_NOT_EQUAL_UINT32(base, moved_lip);
    TEST_ASSERT_NOT_EQUAL_UINT32(base, moved_rip);
    TEST_ASSERT_NOT_EQUAL_UINT32(moved_lport, moved_rport);
    TEST_ASSERT_NOT_EQUAL_UINT32(moved_lip, moved_rip);
    TEST_ASSERT_NOT_EQUAL_UINT32(moved_lport, moved_lip);
    TEST_ASSERT_NOT_EQUAL_UINT32(moved_rport, moved_rip);
}

// The v4 pair contributes four octets and the v6 pair sixteen, so a v6 tuple whose leading four octets
// are the v4 tuple's is still a separate space: the connection-ids differ in length, and FIPS 180-4
// sec 5.1.1 digests the length along with the message.
void test_the_ipv4_and_ipv6_spaces_are_disjoint(void)
{
    static const uint8_t local_lead[IDEMIP_TCP_ISN_ADDR_BYTES] = {192u, 0u, 2u, 1u};
    static const uint8_t remote_lead[IDEMIP_TCP_ISN_ADDR_BYTES] = {192u, 0u, 2u, 9u};

    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t v4 = gen_at(work_a, 0u);
    TEST_ASSERT_EQUAL_HEX32(0x7F9FA667u, v4);

    ready(work_b, g_key, sizeof g_key, 0u);
    IDEMIP_TCP_ISN_IO(work_b)->gen_args.local_ip = local_lead;
    IDEMIP_TCP_ISN_IO(work_b)->gen_args.remote_ip = remote_lead;
    IDEMIP_TCP_ISN_IO(work_b)->gen_args.ip_version = 6u;
    uint32_t v6 = gen_at(work_b, 0u);

    TEST_ASSERT_EQUAL_HEX32(0x265F2932u, v6);
    TEST_ASSERT_NOT_EQUAL_UINT32(v4, v6);
}

// RFC 6528 sec 4: "the offset between a fake connection and a given real connection will be more or
// less constant for the lifetime of the secret". M is common to both spaces, so the offset is F(A) -
// F(B) and does not move with the clock.
void test_two_tuples_keep_a_constant_offset_across_time(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    ready(work_b, g_key, sizeof g_key, 0u);
    IDEMIP_TCP_ISN_IO(work_b)->gen_args.remote_port = 443u;

    uint32_t offset_early = gen_at(work_a, 1000u) - gen_at(work_b, 1000u);
    uint32_t offset_late = gen_at(work_a, 900000u) - gen_at(work_b, 900000u);

    TEST_ASSERT_EQUAL_HEX32(offset_early, offset_late);
    TEST_ASSERT_NOT_EQUAL_UINT32(0u, offset_early);
}

// =============================================================================
// F is keyed, and the key does not come back out
// =============================================================================

// RFC 6528 sec 3: "Note that changing the secret would change the ISN space used for reincarnated
// connections". Same tuple, same M, a different secret: a different space. The pinned value is the
// independent SHA-256 of the same connection-id under the second key.
void test_a_different_secret_moves_the_isn_space(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t under_key1 = gen(work_a);

    ready(work_b, g_key2, sizeof g_key2, 0u);
    uint32_t under_key2 = gen(work_b);

    TEST_ASSERT_EQUAL_HEX32(0x7FA376F7u, under_key1);
    TEST_ASSERT_EQUAL_HEX32(0x89249192u, under_key2);
    TEST_ASSERT_NOT_EQUAL_UINT32(under_key1, under_key2);
}

// RFC 9293 sec 3.4.1 MUST-9: "F() MUST NOT be computable from the outside". An attacker knows the
// four-tuple, so an F over the tuple alone would be computable. The all-zero key stands in for that:
// it produces a different ISN, so the secret is an input and not decoration. Both run at M zero, where
// the ISN is F itself.
void test_the_isn_is_not_the_connection_id_alone(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t keyed = gen_at(work_a, 0u);

    ready(work_b, g_key_zero, sizeof g_key_zero, 0u);
    uint32_t unkeyed = gen_at(work_b, 0u);

    TEST_ASSERT_EQUAL_HEX32(0x7F9FA667u, keyed);
    TEST_ASSERT_EQUAL_HEX32(0x398E2F21u, unkeyed);
    TEST_ASSERT_NOT_EQUAL_UINT32(keyed, unkeyed);
}

// The ISN is 32 bits and goes on the wire, so a PRF that passed key octets through would hand an
// eavesdropper the secret four octets at a time. No window of the key, read either way, appears in it.
// Non-invertibility of SHA-256 is not something a unit suite can assert; a passthrough is.
void test_the_isn_carries_no_window_of_the_secret(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t isn = gen(work_a);

    for (size_t i = 0; i + 4u <= sizeof g_key; i++)
    {
        uint32_t be = ((uint32_t)g_key[i] << 24) | ((uint32_t)g_key[i + 1] << 16) | ((uint32_t)g_key[i + 2] << 8) |
                      (uint32_t)g_key[i + 3];
        uint32_t le = ((uint32_t)g_key[i + 3] << 24) | ((uint32_t)g_key[i + 2] << 16) | ((uint32_t)g_key[i + 1] << 8) |
                      (uint32_t)g_key[i];
        TEST_ASSERT_NOT_EQUAL_UINT32_MESSAGE(be, isn, "the ISN is a window of the secret key, read big-endian");
        TEST_ASSERT_NOT_EQUAL_UINT32_MESSAGE(le, isn, "the ISN is a window of the secret key, read little-endian");
    }
}

// The connection-id RFC 6528 sec 3 hashes carries the secret, so the block holds a copy of it while
// the PRF runs. Once F is read the block and the working set are scratch, and generate leaves no octet
// of the key in either. The context still holds the key, which is where a seed put it.
void test_generate_leaves_no_octet_of_the_secret_in_the_working_regions(void)
{
    const size_t span = (size_t)IDEMIP_TCP_ISN_BORROW - IDEMIP_TCP_ISN_OFF_BLOCK;

    ready(work_a, g_key, sizeof g_key, 0u);
    (void)gen(work_a);

    TEST_ASSERT_FALSE_MESSAGE(carries(work_a, IDEMIP_TCP_ISN_OFF_BLOCK, span, g_key, sizeof g_key),
                              "generate left the whole secret key in the block or the working set");
    TEST_ASSERT_FALSE_MESSAGE(carries(work_a, IDEMIP_TCP_ISN_OFF_BLOCK, span, g_key, 8u),
                              "generate left half the secret key in the block or the working set");
    check_zero(work_a, IDEMIP_TCP_ISN_OFF_BLOCK, span, "generate left an octet of scratch behind");
}

// RFC 6528 sec 3 changes the key "whenever one of the following events occur", and the third is "The
// secret key has been used sufficiently often that it should be regarded as insecure". A reseed on a
// running generator takes the new key and leaves M counting, so the new space still advances 250 ticks
// per millisecond.
void test_a_reseed_leaves_m_rising(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t old_space = gen_at(work_a, 1000u);

    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key = g_key2;
    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key_len = sizeof g_key2;
    TcpIsn.seed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_ISN_IO(work_a)->status);

    uint32_t new_space = gen_at(work_a, 1000u);
    TEST_ASSERT_NOT_EQUAL_UINT32(old_space, new_space);
    TEST_ASSERT_EQUAL_HEX32(0x89249192u, new_space);
    TEST_ASSERT_EQUAL_UINT32(250u, gen_at(work_a, 1001u) - new_space);
}

// The context holds IDEMIP_TCP_ISN_SECRET_BYTES, so a longer key contributes its leading octets and a
// key that agrees with a shorter one over those octets reaches the same space.
void test_a_longer_key_contributes_its_leading_octets(void)
{
    static const uint8_t long_key[IDEMIP_TCP_ISN_SECRET_BYTES + 8u] = {
        0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu, 0xDEu, 0xADu, 0xBEu, 0xEFu, 0xDEu, 0xADu, 0xBEu, 0xEFu};

    ready(work_a, g_key, sizeof g_key, 0u);
    uint32_t from_short = gen(work_a);

    ready(work_b, long_key, sizeof long_key, 0u);
    TEST_ASSERT_EQUAL_HEX32(from_short, gen(work_b));
}

// reset zeroes the context, so the mark a seed set is gone with it and the generator refuses again
// rather than hashing whatever the borrow now holds.
void test_reset_unkeys_the_generator(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    (void)gen(work_a);

    TcpIsn.reset(work_a);
    aim(work_a);
    TcpIsn.generate(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_ISN_IO(work_a)->isn);
}

// =============================================================================
// The bounds, and the line between BUSY and ERR
// =============================================================================

// An address is RFC 791 sec 3.1's four octets or RFC 8200 sec 3's sixteen. Any other version names no
// width to read, so the call is refused and no retry on the same operand can succeed.
void test_an_unknown_ip_version_is_refused(void)
{
    static const uint8_t versions[4] = {0u, 5u, 7u, 255u};

    for (size_t i = 0; i < sizeof versions; i++)
    {
        ready(work_a, g_key, sizeof g_key, 0u);
        IDEMIP_TCP_ISN_IO(work_a)->gen_args.ip_version = versions[i];
        TcpIsn.generate(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status,
                                      "an IP version that is neither 4 nor 6 must be refused");
        TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_ISN_IO(work_a)->isn);
    }
}

// Nothing here waits on hardware, on a peer, or on a timer: the PRF runs to completion on the operands
// it was handed. So no path reports BUSY, and every refusal is one that a retry cannot mend.
void test_no_entry_ever_reports_busy(void)
{
    TcpIsn.reset(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TCP_ISN_IO(work_a)->status);

    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key = NULL;
    TcpIsn.seed(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TCP_ISN_IO(work_a)->status);

    aim(work_a);
    TcpIsn.generate(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TCP_ISN_IO(work_a)->status);

    ready(work_a, g_key, sizeof g_key, 0u);
    TcpIsn.generate(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TCP_ISN_IO(work_a)->status);

    IDEMIP_TCP_ISN_IO(work_a)->gen_args.ip_version = 9u;
    TcpIsn.generate(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TCP_ISN_IO(work_a)->status);
}

// A refused seed writes no key, so the generator is still unkeyed and a good seed after it takes
// normally rather than mixing the two.
void test_a_refused_seed_leaves_the_generator_unkeyed(void)
{
    TcpIsn.reset(work_a);
    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key = g_key2;
    IDEMIP_TCP_ISN_IO(work_a)->seed_args.key_len = IDEMIP_TCP_ISN_SECRET_BYTES - 1u;
    TcpIsn.seed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status);

    aim(work_a);
    TcpIsn.generate(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_ISN_IO(work_a)->status);

    ready(work_a, g_key, sizeof g_key, 0u);
    TEST_ASSERT_EQUAL_HEX32(0x7FA376F7u, gen(work_a));
}

// The operand block is the caller's. generate reports through status and isn and leaves every operand
// where it found it, so nothing it read is disturbed and nothing of the key reaches the operands.
void test_generate_reports_only_through_status_and_isn(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    (void)gen(work_a);

    TEST_ASSERT_EQUAL_PTR(g_key, IDEMIP_TCP_ISN_IO(work_a)->seed_args.key);
    TEST_ASSERT_EQUAL_size_t(sizeof g_key, IDEMIP_TCP_ISN_IO(work_a)->seed_args.key_len);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_ISN_IO(work_a)->seed_args.base);
    TEST_ASSERT_EQUAL_PTR(g_local, IDEMIP_TCP_ISN_IO(work_a)->gen_args.local_ip);
    TEST_ASSERT_EQUAL_PTR(g_remote, IDEMIP_TCP_ISN_IO(work_a)->gen_args.remote_ip);
    TEST_ASSERT_EQUAL_UINT16(40000u, IDEMIP_TCP_ISN_IO(work_a)->gen_args.local_port);
    TEST_ASSERT_EQUAL_UINT16(80u, IDEMIP_TCP_ISN_IO(work_a)->gen_args.remote_port);
    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_TCP_ISN_IO(work_a)->gen_args.ip_version);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_TCP_ISN_IO(work_a)->gen_args.now_ms);
}

// The borrow IS the generator, so two generators on two borrows keyed differently produce their own
// spaces at the same instant with nothing crossing between them.
void test_two_borrows_generate_in_their_own_spaces(void)
{
    ready(work_a, g_key, sizeof g_key, 0u);
    ready(work_b, g_key2, sizeof g_key2, 0u);

    uint32_t a1 = gen_at(work_a, 1000u);
    uint32_t b1 = gen_at(work_b, 1000u);
    uint32_t a2 = gen_at(work_a, 1000u);

    TEST_ASSERT_EQUAL_HEX32(0x7FA376F7u, a1);
    TEST_ASSERT_EQUAL_HEX32(0x89249192u, b1);
    TEST_ASSERT_EQUAL_HEX32(a1, a2);
}
