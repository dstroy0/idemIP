// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for ip6_reass, modeled on test_phy. It tests the CONTRACT and nothing else:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_IP6_REASS_BORROW is intact after every case
//   5. the published offset map is ordered, aligned, and does not overlap
//   6. clear zeroes the regions, and a borrow no one cleared is refused
//
// No case here asserts what an entry reports once its RFC 8200 sec 4.5 logic exists, so none of them
// has to be inverted when it does.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/ip/ip6_reass.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(IDEMIP_ALIGN) uint8_t work_a[IDEMIP_IP6_REASS_BORROW + 16];
static _Alignas(IDEMIP_ALIGN) uint8_t work_b[IDEMIP_IP6_REASS_BORROW + 16];

// The span clear owns: the context and the three tables.
#define STATE_OFF ((size_t)IDEMIP_IP6_REASS_OFF_CTX)
#define TABLE_OFF ((size_t)IDEMIP_IP6_REASS_OFF_DATAGRAMS)
#define STATE_END ((size_t)IDEMIP_IP6_REASS_OFF_END)

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP6_REASS_BORROW, CANARY, cap - IDEMIP_IP6_REASS_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP6_REASS_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP6_REASS_BORROW");
    }
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

// Every entry, in namespace order, so a new one added to Ip6ReassNs is added here too.
static void call_every_entry(uint8_t *w)
{
    Ip6Reass.clear(w);
    Ip6Reass.input(w);
    Ip6Reass.frag_at(w);
    Ip6Reass.drop(w);
    Ip6Reass.tick(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the instance, and the operand block is in it, so two reassemblers share no byte at
// all. This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    Ip6Reass.clear(work_a);
    Ip6Reass.clear(work_b);

    IDEMIP_IP6_REASS_IO(work_a)->input_args.desc = 0x1111u;
    IDEMIP_IP6_REASS_IO(work_a)->input_args.now_ms = 1000u;
    IDEMIP_IP6_REASS_IO(work_b)->input_args.desc = 0x2222u;
    IDEMIP_IP6_REASS_IO(work_b)->input_args.now_ms = 2000u;

    TEST_ASSERT_EQUAL_HEX16(0x1111u, IDEMIP_IP6_REASS_IO(work_a)->input_args.desc);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_IP6_REASS_IO(work_a)->input_args.now_ms);
    TEST_ASSERT_EQUAL_HEX16(0x2222u, IDEMIP_IP6_REASS_IO(work_b)->input_args.desc);
    TEST_ASSERT_EQUAL_UINT32(2000u, IDEMIP_IP6_REASS_IO(work_b)->input_args.now_ms);
}

// A call on one borrow reaches no byte of another, clear included, which is the widest-reaching entry
// this module has.
void test_clear_on_one_borrow_leaves_the_other_untouched(void)
{
    memset(work_b + STATE_OFF, 0xC3, STATE_END - STATE_OFF);
    IDEMIP_IP6_REASS_IO(work_b)->input_args.desc = 0x7777u;

    Ip6Reass.clear(work_a);

    for (size_t i = STATE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[i], "clear on one borrow wrote into another");
    }
    TEST_ASSERT_EQUAL_HEX16(0x7777u, IDEMIP_IP6_REASS_IO(work_b)->input_args.desc);
}

// --- the published map -------------------------------------------------------

// The map is public so a reader can place every region without opening the .c. Each region starts
// where the one before it ends, so nothing overlaps and nothing is unreachable.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP6_REASS_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_IP6_REASS_OFF_CTX >= sizeof(Ip6ReassIo),
                             "the context starts inside the operand block");
    TEST_ASSERT_TRUE_MESSAGE(TABLE_OFF >= (size_t)IDEMIP_IP6_REASS_OFF_CTX,
                             "the datagram table starts before the context");
    TEST_ASSERT_EQUAL_size_t(TABLE_OFF + ((size_t)IDEMIP_IP6_REASS_DATAGRAMS
                                          << IDEMIP_IP6_REASS_DATAGRAM_ENTRY_SHIFT),
                             (size_t)IDEMIP_IP6_REASS_OFF_FRAGS);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_IP6_REASS_OFF_FRAGS +
                                 ((size_t)IDEMIP_IP6_REASS_FRAGS << IDEMIP_IP6_REASS_FRAG_ENTRY_SHIFT),
                             (size_t)IDEMIP_IP6_REASS_OFF_HOLES);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_IP6_REASS_OFF_HOLES +
                                 ((size_t)IDEMIP_IP6_REASS_HOLES << IDEMIP_IP6_REASS_HOLE_ENTRY_SHIFT),
                             STATE_END);
    TEST_ASSERT_TRUE_MESSAGE(STATE_END <= (size_t)IDEMIP_IP6_REASS_BORROW,
                             "the map runs past IDEMIP_IP6_REASS_BORROW");
}

// Every table starts at the end of the region before it, so a misaligned offset would misalign the
// whole table behind it.
void test_every_published_offset_is_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP6_REASS_OFF_CTX & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, TABLE_OFF & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP6_REASS_OFF_FRAGS & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP6_REASS_OFF_HOLES & (IDEMIP_ALIGN - 1u));
}

// The operand block is reached at its published offset and nowhere else.
void test_the_io_macro_reaches_the_operand_block(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_IP6_REASS_OFF_IO, (uint8_t *)IDEMIP_IP6_REASS_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_IP6_REASS_OFF_IO, (uint8_t *)IDEMIP_IP6_REASS_IO(work_b));
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Ip6Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
}

// The three tables come out of clear zeroed whatever was in them, so no stale datagram, fragment or
// hole survives into the next use of the borrow.
void test_clear_zeroes_the_tables(void)
{
    memset(work_a, 0xFF, IDEMIP_IP6_REASS_BORROW);
    Ip6Reass.clear(work_a);
    for (size_t i = TABLE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00u, work_a[i], "clear left a table byte set");
    }
}

// The context comes out zeroed too, apart from the one octet ip6_reass.h says clear leaves as the
// mark that these bytes were cleared.
void test_clear_zeroes_the_context_apart_from_the_cleared_mark(void)
{
    memset(work_a, 0xFF, IDEMIP_IP6_REASS_BORROW);
    Ip6Reass.clear(work_a);
    size_t set = 0;
    for (size_t i = STATE_OFF; i < TABLE_OFF; i++)
    {
        if (work_a[i] != 0x00u)
        {
            set++;
        }
    }
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1u, set, "clear must zero the context apart from the cleared mark");
}

// The operand block is the caller's, so clear does not touch what the caller put there.
void test_clear_leaves_the_operand_block_alone(void)
{
    Ip6Reass.clear(work_a);
    IDEMIP_IP6_REASS_IO(work_a)->input_args.desc = 0x4242u;
    IDEMIP_IP6_REASS_IO(work_a)->frag_args.datagram = 3u;
    Ip6Reass.clear(work_a);
    TEST_ASSERT_EQUAL_HEX16(0x4242u, IDEMIP_IP6_REASS_IO(work_a)->input_args.desc);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_IP6_REASS_IO(work_a)->frag_args.datagram);
}

// An entry is a function of its borrow alone, so clearing twice leaves the same bytes as clearing
// once.
void test_clear_is_idempotent(void)
{
    memset(work_a, 0xFF, IDEMIP_IP6_REASS_BORROW);
    Ip6Reass.clear(work_a);
    memcpy(work_b, work_a, IDEMIP_IP6_REASS_BORROW);
    Ip6Reass.clear(work_a);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(work_b + STATE_OFF, work_a + STATE_OFF, STATE_END - STATE_OFF);
}

// A borrow no one cleared is not this module's, so every entry that reads the tables refuses it
// rather than reading whatever the caller's memory held.
void test_an_uncleared_borrow_is_refused(void)
{
    Ip6Reass.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    Ip6Reass.frag_at(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    Ip6Reass.drop(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    Ip6Reass.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
}

// Clearing one borrow does not make another one cleared: the mark is in the borrow, not in the
// module.
void test_clearing_one_borrow_does_not_ready_the_other(void)
{
    Ip6Reass.clear(work_a);
    Ip6Reass.tick(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_b)->status);
}

// --- the contract's own constants --------------------------------------------

// Every index a result member carries is one octet, so no table may be as wide as the value that
// means "none of them".
void test_none_is_outside_every_table(void)
{
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_DATAGRAMS < IDEMIP_IP6_REASS_NONE);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_FRAGS < IDEMIP_IP6_REASS_NONE);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_HOLES < IDEMIP_IP6_REASS_NONE);
}

// RFC 8200 sec 4.5: "If insufficient fragments are received to complete reassembly of a packet within
// 60 seconds of the reception of the first-arriving fragment of that packet, reassembly of that packet
// must be abandoned". Held in milliseconds, so the tick needs no conversion.
void test_the_reassembly_bound_is_the_rfc_8200_sixty_seconds(void)
{
    TEST_ASSERT_EQUAL_UINT32(60000u, IDEMIP_IP6_REASS_MAXAGE_MS);
}
