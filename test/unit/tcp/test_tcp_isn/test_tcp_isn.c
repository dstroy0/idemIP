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
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/tcp/tcp_isn.h"

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
