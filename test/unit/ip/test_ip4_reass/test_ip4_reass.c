// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for ip4_reass. It tests the CONTRACT, not the RFC 791 sec 3.2 or RFC 815
// behavior:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_IP4_REASS_BORROW is intact after every case
//   5. the published offsets are ordered, sized and non-overlapping across all three tables
//   6. clear leaves the tables zeroed, and a borrow clear has not run on is refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ip/ip4_reass.h"

#include <string.h>
#include <unity.h>

#define CANARY 0x5Au
#define DIRT 0xCCu
static _Alignas(8) uint8_t work_a[IDEMIP_IP4_REASS_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_IP4_REASS_BORROW + 16];

// A fragment header for the operands to point at. The suite never asks the unit to read it.
static uint8_t g_hdr[IDEMIP_IP4_HDR_MAX];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP4_REASS_BORROW, CANARY, cap - IDEMIP_IP4_REASS_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP4_REASS_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP4_REASS_BORROW");
    }
}

// Every byte the three tables span, so a case can dirty them and see clear take them back.
static void dirty_tables(uint8_t *w)
{
    memset(w + IDEMIP_IP4_REASS_OFF_DGRAM, DIRT,
           (size_t)IDEMIP_IP4_REASS_BORROW - (size_t)IDEMIP_IP4_REASS_OFF_DGRAM);
}

static void assert_tables_zero(const uint8_t *w)
{
    for (size_t i = IDEMIP_IP4_REASS_OFF_DGRAM; i < (size_t)IDEMIP_IP4_REASS_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, w[i], "clear left a byte of the tables set");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_hdr, 0, sizeof g_hdr);
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
    Ip4Reass.clear(NULL);
    Ip4Reass.hold(NULL);
    Ip4Reass.next(NULL);
    Ip4Reass.release(NULL);
    Ip4Reass.reclaim(NULL);
    Ip4Reass.tick(NULL);
    TEST_PASS();
}

// The borrow IS the reassembler, and the operand block is in it, so two of them share no byte.
void test_two_borrows_share_no_byte(void)
{
    Ip4Reass.clear(work_a);
    Ip4Reass.clear(work_b);

    IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr = g_hdr;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc = 3u;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.len = 100u;
    IDEMIP_IP4_REASS_IO(work_a)->now_ms = 1000u;

    IDEMIP_IP4_REASS_IO(work_b)->hold_args.hdr = NULL;
    IDEMIP_IP4_REASS_IO(work_b)->hold_args.desc = 9u;
    IDEMIP_IP4_REASS_IO(work_b)->hold_args.len = 200u;
    IDEMIP_IP4_REASS_IO(work_b)->now_ms = 2000u;

    TEST_ASSERT_EQUAL_PTR(g_hdr, IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr);
    TEST_ASSERT_EQUAL_UINT16(3u, IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc);
    TEST_ASSERT_EQUAL_UINT16(100u, IDEMIP_IP4_REASS_IO(work_a)->hold_args.len);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_IP4_REASS_IO(work_a)->now_ms);

    // A call on b leaves a's operands as they were.
    Ip4Reass.hold(work_b);
    TEST_ASSERT_EQUAL_PTR(g_hdr, IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr);
    TEST_ASSERT_EQUAL_UINT16(3u, IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_IP4_REASS_IO(work_a)->now_ms);
}

// clear writes every byte of one borrow's context and tables, and still reaches no byte of the other.
void test_clear_on_one_borrow_leaves_the_other_alone(void)
{
    dirty_tables(work_b);
    Ip4Reass.clear(work_a);

    for (size_t i = IDEMIP_IP4_REASS_OFF_DGRAM; i < (size_t)IDEMIP_IP4_REASS_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(DIRT, work_b[i], "clear on one borrow reached into the other");
    }
    assert_tables_zero(work_a);
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_REASS_IO(work_a)->status);
}

// Every datagram row, every held fragment and every hole descriptor is the zero state.
void test_clear_zeroes_the_tables(void)
{
    dirty_tables(work_a);
    Ip4Reass.clear(work_a);
    assert_tables_zero(work_a);
}

void test_clear_leaves_the_operand_block_alone(void)
{
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr = g_hdr;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc = 7u;
    IDEMIP_IP4_REASS_IO(work_a)->now_ms = 4242u;
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_hdr, IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr);
    TEST_ASSERT_EQUAL_UINT16(7u, IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc);
    TEST_ASSERT_EQUAL_UINT32(4242u, IDEMIP_IP4_REASS_IO(work_a)->now_ms);
}

// A zeroed borrow is not an empty reassembler: every list link in it reads as row zero rather than as
// IDEMIP_IP4_REASS_INDEX_NONE, so an entry that has not seen clear must refuse rather than walk it.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr = g_hdr;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.len = 100u;

    Ip4Reass.hold(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
    Ip4Reass.next(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
    Ip4Reass.release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
    Ip4Reass.reclaim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
    Ip4Reass.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
}

// (test_a_refused_hold_reports_no_row lives past the fragment builders, which it needs.)

// --- the published map -------------------------------------------------------

void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_REASS_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(sizeof(Ip4ReassIo), (size_t)IDEMIP_IP4_REASS_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_IP4_REASS_OFF_CTX < (size_t)IDEMIP_IP4_REASS_OFF_DGRAM,
                             "the context must sit between the operand block and the datagram rows");
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_IP4_REASS_OFF_DGRAM +
                                 (IDEMIP_IP4_REASS_DATAGRAMS << IDEMIP_IP4_REASS_DATAGRAM_ENTRY_SHIFT),
                             (size_t)IDEMIP_IP4_REASS_OFF_FRAG);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_IP4_REASS_OFF_FRAG +
                                 (IDEMIP_IP4_REASS_FRAGS << IDEMIP_IP4_REASS_FRAG_ENTRY_SHIFT),
                             (size_t)IDEMIP_IP4_REASS_OFF_HOLE);
}

void test_the_borrow_covers_the_published_map(void)
{
    size_t end = (size_t)IDEMIP_IP4_REASS_OFF_HOLE + (IDEMIP_IP4_REASS_HOLES << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT);
    TEST_ASSERT_TRUE_MESSAGE(end <= (size_t)IDEMIP_IP4_REASS_BORROW, "IDEMIP_IP4_REASS_BORROW is short of the map");
}

void test_a_row_index_fits_the_published_terminator(void)
{
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_DATAGRAMS < IDEMIP_IP4_REASS_INDEX_NONE);
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_FRAGS < IDEMIP_IP4_REASS_INDEX_NONE);
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_HOLES < IDEMIP_IP4_REASS_INDEX_NONE);
}

void test_every_region_starts_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_REASS_OFF_DGRAM & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_REASS_OFF_FRAG & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_REASS_OFF_HOLE & (IDEMIP_ALIGN - 1u));
}

// RFC 815 sec 3 opens a datagram with one hole reaching to infinity, and RFC 815 sec 4 sizes a hole
// descriptor at eight octets.
void test_the_hole_table_matches_rfc_815(void)
{
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_HOLES >= IDEMIP_IP4_REASS_DATAGRAMS + IDEMIP_IP4_REASS_FRAGS);
    TEST_ASSERT_TRUE((1u << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT) >= 8u);
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_INFINITY >= IDEMIP_IP4_TOTAL_LEN_MAX - 1u);
}

// =============================================================================
// Behavior: RFC 791 sec 3.2 and RFC 815
// =============================================================================
// Neither RFC prints a reassembly byte vector. RFC 791 sec 3.2 prints the example procedure's
// nineteen numbered steps and RFC 815 sec 3 prints the eight steps, both as pseudocode over named
// header fields, so every fragment below is built with idemip_ip4_build from the RFC 791 sec 3.1
// field values and the assertions are the properties those two texts state.

#define FRAG_BUF 96
#define FRAG_SLOTS 16
static uint8_t g_frags[FRAG_SLOTS][FRAG_BUF];

// The RFC 791 sec 3.2 buffer identifier this suite reuses, "the concatenation of the source,
// destination, protocol, and identification fields".
#define SRC 0x0A000001u
#define DST 0x0A000002u
#define PROTO IDEMIP_IP4_PROTO_UDP
#define ID 0x1234u

// A Time to Live under IDEMIP_IP_REASS_MAXAGE_S, so RFC 791 sec 3.2 step (17)'s MAX(TIMER,TTL) leaves
// the deadline at step (7)'s lower bound unless a case raises it on purpose.
#define TTL_LOW 8u

// One fragment header. ihl is in 32-bit words, so 5 is the option-free header of RFC 791 sec 3.1 and
// 6 carries one word of options, which RFC 815 sec 6 says only the first fragment need carry.
typedef struct
{
    int slot;
    uint32_t src;
    uint32_t dst;
    uint8_t proto;
    uint16_t id;
    uint16_t off_units;
    uint16_t data_len;
    int mf;
    uint8_t ttl;
    uint8_t ihl;
} FragFullArgs;

static uint8_t * frag_full_ctx(const FragFullArgs *args)
{
    uint8_t *h = g_frags[args->slot];
    IdemIpIp4Fields f;
    memset(h, 0, FRAG_BUF);
    memset(&f, 0, sizeof f);
    f.tos = 0u;
    f.total_len = (uint16_t)((uint16_t)(args->ihl * 4u) + args->data_len);
    f.id = args->id;
    f.flags_frag = (uint16_t)((args->mf ? IDEMIP_IP4_FLAG_MF : 0u) | args->off_units);
    f.ttl = args->ttl;
    f.proto = args->proto;
    f.src = args->src;
    f.dst = args->dst;
    idemip_ip4_build(h, &f);
    if (args->ihl != IDEMIP_IP4_IHL_MIN)
    {
        idemip_ip4_set_ver_ihl(h, args->ihl);
        idemip_ip4_recksum(h);
    }
    return h;
}

#define frag_full(...) IDEMIP_CALL(frag_full_ctx, FragFullArgs, __VA_ARGS__)

// A fragment of the suite's buffer identifier, offset in RFC 791 sec 3.1's eight-octet units.
static uint8_t *fr(int slot, uint16_t off_units, uint16_t data_len, int mf)
{
    return frag_full(slot, SRC, DST, PROTO, ID, off_units, data_len, mf, TTL_LOW, (uint8_t)IDEMIP_IP4_IHL_MIN);
}

static uint8_t *fr_id(int slot, uint16_t id, uint16_t off_units, uint16_t data_len, int mf)
{
    return frag_full(slot, SRC, DST, PROTO, id, off_units, data_len, mf, TTL_LOW, (uint8_t)IDEMIP_IP4_IHL_MIN);
}

static IdemIpStatus hold_at(uint8_t *w, const uint8_t *h, uint16_t desc, uint32_t now_ms)
{
    IDEMIP_IP4_REASS_IO(w)->now_ms = now_ms;
    IDEMIP_IP4_REASS_IO(w)->hold_args.hdr = h;
    IDEMIP_IP4_REASS_IO(w)->hold_args.desc = desc;
    IDEMIP_IP4_REASS_IO(w)->hold_args.len = idemip_ip4_total_len(h);
    Ip4Reass.hold(w);
    return IDEMIP_IP4_REASS_IO(w)->status;
}

#define T0 1000u

static IdemIpStatus hold_frag(uint8_t *w, const uint8_t *h, uint16_t desc)
{
    return hold_at(w, h, desc, T0);
}

static IdemIpStatus tick_at(uint8_t *w, uint32_t now_ms)
{
    IDEMIP_IP4_REASS_IO(w)->now_ms = now_ms;
    Ip4Reass.tick(w);
    return IDEMIP_IP4_REASS_IO(w)->status;
}

static IdemIpStatus reclaim_one(uint8_t *w)
{
    Ip4Reass.reclaim(w);
    return IDEMIP_IP4_REASS_IO(w)->status;
}

static IdemIpStatus next_one(uint8_t *w, uint8_t index)
{
    IDEMIP_IP4_REASS_IO(w)->next_args.index = index;
    Ip4Reass.next(w);
    return IDEMIP_IP4_REASS_IO(w)->status;
}

// A hold that took nothing in says so with the published terminator, and claims no completion. The
// borrow is cleared first and the fragment is a real one, so the refusal comes from the hold logic
// and not from the ready gate: RFC 791 sec 3.2 counts fragments "in units of 8 octets", so a
// non-final fragment of nine octets fills no whole unit and cannot be placed.
void test_a_refused_hold_reports_no_row(void)
{
    Ip4Reass.clear(work_a);
    // The positive control: the same shape with a legal length is taken.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 61u));

    Ip4Reass.clear(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 9u, 1), 62u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_REASS_INDEX_NONE, IDEMIP_IP4_REASS_IO(work_a)->index);
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// RFC 1122 sec 3.3.2: "EMTU_R MUST be greater than or equal to 576". RFC 791 sec 3.2 puts the
// smallest link an internet module must forward at 68 octets, so those 556 data octets can arrive as
// twelve fragments of 48, and every one of them must be held.
void test_a_576_octet_datagram_reassembles_from_its_smallest_fragments(void)
{
    Ip4Reass.clear(work_a);
    const uint16_t chunk = 48u; // 68-octet link less a twenty-octet header
    uint16_t off = 0u;
    unsigned int slot = 0u;
    while (off < 556u)
    {
        const uint16_t left = (uint16_t)(556u - off);
        const uint16_t len = (left > chunk) ? chunk : left;
        const int mf = ((uint16_t)(off + len) < 556u) ? 1 : 0;
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK,
                                      hold_frag(work_a, fr((int)slot, (uint16_t)(off >> 3), len, mf),
                                                (uint16_t)(300u + slot)),
                                      "a legal 576-octet datagram was refused");
        off = (uint16_t)(off + len);
        slot++;
    }
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP4_REASS_IO(work_a)->complete, "the datagram never completed");
    TEST_ASSERT_EQUAL_UINT16(556u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

static IdemIpStatus release_row(uint8_t *w, uint8_t index)
{
    IDEMIP_IP4_REASS_IO(w)->release_args.index = index;
    Ip4Reass.release(w);
    return IDEMIP_IP4_REASS_IO(w)->status;
}

// The deadline RFC 791 sec 3.2 step (7) sets, "TIMER <- TLB", with the lower bound the section puts at
// 15 seconds and idemip_config.h names IDEMIP_IP_REASS_MAXAGE_S.
#define MAXAGE_MS (T0 + (IDEMIP_IP_REASS_MAXAGE_S * 1000u))

// --- RFC 815 sec 3: the eight steps ------------------------------------------

// The two-fragment case, in order. The list opens at one hole from zero to infinity, the first
// fragment leaves a hole reaching to infinity because More Fragments is set, and the last fragment
// empties the list, which is step 8: "the datagram is now complete".
void test_two_fragments_in_order_complete_the_datagram(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 11u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_HOLDING, IDEMIP_IP4_REASS_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;
    TEST_ASSERT_NOT_EQUAL_UINT8(IDEMIP_IP4_REASS_INDEX_NONE, row);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 1u, 8u, 0), 12u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT8(row, IDEMIP_IP4_REASS_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_COMPLETE, IDEMIP_IP4_REASS_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// RFC 815 sec 1: the algorithm "can reassemble a datagram from any number of fragments arriving in
// any order". The last fragment first, then the first.
void test_fragments_out_of_order_complete_the_datagram(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 1u, 8u, 0), 21u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    // RFC 791 sec 3.2 step (10) fixes TDL on the last fragment whatever its arrival order.
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP4_REASS_IO(work_a)->total_len);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 0u, 8u, 1), 22u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// RFC 815 sec 3 step 5 makes a hole for "the first part of the original hole [that] is not filled by
// this fragment", so a last fragment at a nonzero offset leaves the list non-empty.
void test_the_last_fragment_alone_leaves_the_leading_hole(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 2u, 8u, 0), 31u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(24u, IDEMIP_IP4_REASS_IO(work_a)->total_len);

    // Fills octets 0 through 7, leaving 8 through 15.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 0u, 8u, 1), 32u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(2, 1u, 8u, 1), 33u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(24u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// RFC 815 sec 3: a fragment "can lie in the middle of an existing hole, breaking the hole in half and
// leaving a smaller hole at each end". Steps 5 and 6 both fire on the one hole, and neither of the two
// pieces alone completes the datagram.
void test_a_fragment_in_the_middle_of_a_hole_leaves_a_hole_at_each_end(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 1u, 8u, 1), 41u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);

    // The leading piece, 0 through 7. The trailing hole 16 to infinity is still there.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 0u, 8u, 1), 42u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(2, 2u, 8u, 0), 43u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(24u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// RFC 815 sec 3 step 6 tests More Fragments so that the hole "from the end of the datagram to
// infinity" is never created. Without that test the list never empties, so this is the case that
// separates a datagram that completes from one that hangs.
void test_step_six_makes_no_hole_past_the_last_fragment(void)
{
    Ip4Reass.clear(work_a);
    // A last fragment reaching to octet 7, well short of IDEMIP_IP4_REASS_INFINITY.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 1u, 8u, 0), 51u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 0u, 8u, 1), 52u));
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP4_REASS_IO(work_a)->complete,
                             "RFC 815 step 6 must not thread a hole from the last octet to infinity");
}

// RFC 815 sec 3 steps 2 and 3: a fragment that "does not overlap with the hole in any way" leaves the
// list alone. A fragment overlapping no hole at all is octets the row already holds, so it pins
// nothing and cannot be made to fit by a retry.
void test_a_duplicate_fragment_is_refused_and_pins_nothing(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 61u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(1, 0u, 8u, 1), 62u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);

    // The row is untouched, so the real last fragment still completes it.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(2, 1u, 8u, 0), 63u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);

    // Exactly two descriptors were pinned: the duplicate took no fragment slot.
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, release_row(work_a, row));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));
}

// A fragment that fills some of a hole and rewrites octets the row already holds is RFC 1858 sec 3.2's
// overlapping fragment. A sender that fragmented one datagram produces disjoint pieces, so two pieces
// that disagree about an octet did not come from one datagram, and there is no reading of the pair
// that IS the datagram - the caller walks the fragments in ascending offset, so the one that arrived
// last would decide the octets both name, up to and including the transport header at offset zero.
// The row is abandoned instead. RFC 8200 sec 4.5 reaches the same disposition for the IPv6 twin.
void test_a_partially_overlapping_fragment_abandons_the_datagram(void)
{
    Ip4Reass.clear(work_a);
    // The last fragment first: octets 8 through 15, so TDL is 16 and hole 0 through 7 remains.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 1u, 8u, 0), 71u));
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;

    // Octets 0 through 15: eight of them fill the hole and eight rewrite what is held.
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, hold_frag(work_a, fr(1, 0u, 16u, 1), 72u),
                                  "an overlapping fragment must not be held");
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_ABANDONED, IDEMIP_IP4_REASS_IO(work_a)->state);
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);

    // Nothing of it is reassembled, however the missing octets arrive afterwards.
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(2, 0u, 8u, 1), 73u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP4_REASS_ABANDONED, IDEMIP_IP4_REASS_IO(work_a)->state,
                                  "the abandoned row must keep its buffer identifier");
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, next_one(work_a, row),
                                  "an abandoned row must hand on no datagram, and no retry changes it");

    // The one descriptor it did pin comes back, and only that one: neither overlapping fragment took
    // a slot.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, release_row(work_a, row));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));
}

// The other order, which is the one an attacker has: the row is gathering, and the fragment that
// arrives reaches back over octets already held. Same answer.
void test_an_overlap_reaching_back_over_held_octets_abandons_the_datagram(void)
{
    Ip4Reass.clear(work_a);
    // Octets 8 through 15, more to come, so the holes are 0 through 7 and 16 to infinity.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 1u, 8u, 1), 74u));
    // Octets 8 through 23: half of it is held already and half is new.
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(1, 1u, 16u, 1), 75u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_ABANDONED, IDEMIP_IP4_REASS_IO(work_a)->state);
}

// The abandoned row is retired by its own deadline, and RFC 1122 sec 3.3.2's Time Exceeded is not
// owed for it: the message is owed to reassembly that failed, in RFC 792's words, "due to missing
// fragments",
// and this datagram was not missing any - it was told two different things about the same octets.
void test_an_abandoned_row_times_out_without_an_icmp_answer(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 1u, 8u, 1), 76u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(1, 1u, 16u, 1), 77u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, MAXAGE_MS - 1u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, MAXAGE_MS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, IDEMIP_IP4_REASS_IO(work_a)->src,
                                     "an abandoned row owes no Time Exceeded, so it names no source");
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP4_REASS_IO(work_a)->frag_zero,
                              "an abandoned row owes no Time Exceeded, so fragment zero is not reported");

    // Its descriptor still comes back, and the key it held is free again.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_at(work_a, fr(2, 0u, 8u, 1), 78u, MAXAGE_MS));
}

// A fragment that repeats octets already held exactly, filling no hole, is neither an overlap nor an
// error: RFC 815 sec 3 steps 2 and 3 pass over every hole and nothing is pinned for it.
void test_an_exactly_repeated_fragment_is_not_an_overlap(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 81u));
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, hold_frag(work_a, fr(1, 0u, 8u, 1), 82u));
    // The row still stands, and the datagram completes when the missing octets arrive.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(2, 1u, 8u, 0), 83u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// --- RFC 791 sec 3.2: the buffer identifier ----------------------------------

// "For each datagram the buffer identifier is computed as the concatenation of the source,
// destination, protocol, and identification fields", so a fragment differing in any one of the four
// belongs to a different datagram and opens its own row.
void test_each_field_of_the_buffer_identifier_selects_the_row(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 81u));
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;

    // Same offsets, one field of the identifier changed each time. None may complete row zero, and
    // each must land on a row of its own.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, frag_full(1, SRC + 1u, DST, PROTO, ID, 1u, 8u, 0, TTL_LOW,
                                                                 (uint8_t)IDEMIP_IP4_IHL_MIN),
                                               82u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_NOT_EQUAL_UINT8(row, IDEMIP_IP4_REASS_IO(work_a)->index);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, frag_full(2, SRC, DST + 1u, PROTO, ID, 1u, 8u, 0, TTL_LOW,
                                                                 (uint8_t)IDEMIP_IP4_IHL_MIN),
                                               83u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          hold_frag(work_a, frag_full(3, SRC, DST, IDEMIP_IP4_PROTO_TCP, ID, 1u, 8u, 0, TTL_LOW,
                                                      (uint8_t)IDEMIP_IP4_IHL_MIN),
                                    84u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr_id(4, ID + 1u, 1u, 8u, 0), 85u));
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_a)->complete);

    // And the matching last fragment does complete it.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(5, 1u, 8u, 0), 86u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT8(row, IDEMIP_IP4_REASS_IO(work_a)->index);
}

// RFC 791 sec 3.2 steps (2) through (5): "IF FO = 0 AND MF = 0 THEN IF buffer with BUFID is allocated
// THEN flush all reassembly for this BUFID". The whole datagram itself is the caller's to submit, so
// nothing of it is held and the pinned fragments of the flushed row go to reclaim.
void test_a_whole_datagram_flushes_its_buffer_identifier(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 91u));
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;

    // Fragment Offset zero and More Fragments clear: RFC 791 sec 3.2's "whole datagram".
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(1, 0u, 64u, 0), 92u));
    TEST_ASSERT_EQUAL_UINT8(row, IDEMIP_IP4_REASS_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_RECLAIM, IDEMIP_IP4_REASS_IO(work_a)->state);

    // The flushed row's one descriptor comes back, and the whole datagram's own does not, because it
    // was never pinned.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(91u, IDEMIP_IP4_REASS_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));
}

// The same whole datagram against a table holding no such identifier flushes nothing and names no row.
void test_a_whole_datagram_with_no_row_names_none(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(0, 0u, 64u, 0), 101u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_REASS_INDEX_NONE, IDEMIP_IP4_REASS_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));
}

// RFC 791 sec 3.2 step (10): "IF MF = 0 THEN TDL <- TL-(IHL*4)+(FO*8)". Fragment Offset 2 units is 16
// octets and the last fragment carries 24, so the total data length is 40.
void test_total_len_is_the_rfc_791_total_data_length(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 2u, 24u, 0), 111u));
    TEST_ASSERT_EQUAL_UINT16(40u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 0u, 16u, 1), 112u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(40u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// --- RFC 791 sec 3.2 step (15): handing the datagram on ----------------------

// The completed datagram comes back one held fragment at a time, in ascending Fragment Offset, each
// with the descriptor its octets are pinned in. BUSY ends the walk and the walk then starts over.
void test_next_reports_every_fragment_in_ascending_offset(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 2u, 8u, 0), 123u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 0u, 8u, 1), 121u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(2, 1u, 8u, 1), 122u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, next_one(work_a, row));
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_REASS_IO(work_a)->off);
    TEST_ASSERT_EQUAL_UINT16(8u, IDEMIP_IP4_REASS_IO(work_a)->len);
    TEST_ASSERT_EQUAL_UINT16(121u, IDEMIP_IP4_REASS_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IPV4_HDR_LEN, IDEMIP_IP4_REASS_IO(work_a)->hdr_len);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, next_one(work_a, row));
    TEST_ASSERT_EQUAL_UINT16(8u, IDEMIP_IP4_REASS_IO(work_a)->off);
    TEST_ASSERT_EQUAL_UINT16(122u, IDEMIP_IP4_REASS_IO(work_a)->desc);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, next_one(work_a, row));
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP4_REASS_IO(work_a)->off);
    TEST_ASSERT_EQUAL_UINT16(123u, IDEMIP_IP4_REASS_IO(work_a)->desc);

    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, next_one(work_a, row));

    // The walk restarts, so the same row reports the same first fragment again.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, next_one(work_a, row));
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_REASS_IO(work_a)->off);
    TEST_ASSERT_EQUAL_UINT16(121u, IDEMIP_IP4_REASS_IO(work_a)->desc);
}

// RFC 815 sec 6: options "are put in the first fragment only", and "until one receives the first
// fragment of the datagram, one cannot tell how big the internet header will be", so each fragment
// reports its own header length.
void test_next_reports_the_header_length_of_each_fragment(void)
{
    Ip4Reass.clear(work_a);
    // IHL 6: twenty fixed octets and one 32-bit word of options.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, frag_full(0, SRC, DST, PROTO, ID, 0u, 8u, 1, TTL_LOW, 6u), 131u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 1u, 8u, 0), 132u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, next_one(work_a, row));
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP4_REASS_IO(work_a)->off);
    TEST_ASSERT_EQUAL_UINT8(24u, IDEMIP_IP4_REASS_IO(work_a)->hdr_len);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, next_one(work_a, row));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IPV4_HDR_LEN, IDEMIP_IP4_REASS_IO(work_a)->hdr_len);
}

// A row with holes left has nothing to hand on yet, and a later fragment can change that, so it is
// BUSY. A row past a row that exists at all is ERR, because no fragment ever lands there.
void test_next_on_a_gathering_row_is_busy_and_past_the_table_is_refused(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 141u));
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, next_one(work_a, row));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_HOLDING, IDEMIP_IP4_REASS_IO(work_a)->state);

    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, next_one(work_a, (uint8_t)IDEMIP_IP4_REASS_DATAGRAMS));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_REASS_INDEX_NONE, IDEMIP_IP4_REASS_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, next_one(work_a, (uint8_t)IDEMIP_IP4_REASS_INDEX_NONE));
}

// --- RFC 791 sec 3.2 step (16): release, then the pins come back -------------

// "free all reassembly resources for this BUFID". The row stops carrying a datagram at once and its
// descriptors come back one call at a time, after which the row is free again.
void test_release_then_reclaim_hands_every_descriptor_back(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 151u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 1u, 8u, 0), 152u));
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, release_row(work_a, row));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_RECLAIM, IDEMIP_IP4_REASS_IO(work_a)->state);

    // Nothing to hand on any more.
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, next_one(work_a, row));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(151u, IDEMIP_IP4_REASS_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_UINT16(8u, IDEMIP_IP4_REASS_IO(work_a)->len);
    TEST_ASSERT_EQUAL_UINT8(row, IDEMIP_IP4_REASS_IO(work_a)->index);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(152u, IDEMIP_IP4_REASS_IO(work_a)->desc);

    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));

    // The row is free, so the whole datagram can be reassembled again on it.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(2, 0u, 8u, 1), 153u));
    TEST_ASSERT_EQUAL_UINT8(row, IDEMIP_IP4_REASS_IO(work_a)->index);
}

// A row that carries nothing cannot be freed, and one already on its way back cannot be freed twice:
// neither becomes possible on a retry.
void test_release_of_a_free_or_already_released_row_is_refused(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, release_row(work_a, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, release_row(work_a, (uint8_t)IDEMIP_IP4_REASS_DATAGRAMS));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 161u));
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, release_row(work_a, row));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, release_row(work_a, row));
}

// A partly gathered row can be given up on, which is the same step (16) release.
void test_a_gathering_row_can_be_released(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 171u));
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, release_row(work_a, row));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(171u, IDEMIP_IP4_REASS_IO(work_a)->desc);
}

// Nothing waiting to be handed back is BUSY: a released or timed-out row will produce one, so the
// caller comes back on a later tick.
void test_reclaim_with_nothing_waiting_is_busy(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_REASS_INDEX_NONE, IDEMIP_IP4_REASS_IO(work_a)->index);
}

// --- RFC 791 sec 3.2 steps (7), (17) and (19): the timer ---------------------

// Step (19): "timer expires: flush all reassembly with this BUFID", with step (7)'s "TIMER <- TLB"
// putting the lower bound at IDEMIP_IP_REASS_MAXAGE_S. One millisecond short of it, nothing goes.
void test_a_partial_datagram_times_out_at_the_lower_bound(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 181u));
    const uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;

    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, MAXAGE_MS - 1u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_REASS_INDEX_NONE, IDEMIP_IP4_REASS_IO(work_a)->index);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, MAXAGE_MS));
    TEST_ASSERT_EQUAL_UINT8(row, IDEMIP_IP4_REASS_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_RECLAIM, IDEMIP_IP4_REASS_IO(work_a)->state);

    // And the pin comes back, which is what PLAN sec 3.5 requires of a timeout.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(181u, IDEMIP_IP4_REASS_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, MAXAGE_MS + 1u));
}

// RFC 1122 sec 3.3.2: "The reassembly timeout value SHOULD be a fixed value, not set from the
// remaining TTL." Two fragments whose Time to Live differs by 195 seconds expire at the same instant.
void test_the_deadline_does_not_come_from_the_time_to_live(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          hold_frag(work_a, frag_full(0, SRC, DST, PROTO, ID, 0u, 8u, 1, 60u,
                                                      (uint8_t)IDEMIP_IP4_IHL_MIN),
                                    191u));
    Ip4Reass.clear(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          hold_frag(work_b, frag_full(0, SRC, DST, PROTO, ID, 0u, 8u, 1, 255u,
                                                      (uint8_t)IDEMIP_IP4_IHL_MIN),
                                    192u));
    // One millisecond short of the fixed timeout neither has gone, and at it both have.
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, MAXAGE_MS - 1u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_b, MAXAGE_MS - 1u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, MAXAGE_MS));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_b, MAXAGE_MS));
}

// The same rule from the other side: a later fragment does not move a fixed deadline, in either
// direction, whatever Time to Live it carries.
void test_a_later_fragment_does_not_move_the_deadline(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          hold_frag(work_a, frag_full(0, SRC, DST, PROTO, ID, 0u, 8u, 1, 60u,
                                                      (uint8_t)IDEMIP_IP4_IHL_MIN),
                                    201u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          hold_frag(work_a, frag_full(1, SRC, DST, PROTO, ID, 1u, 8u, 1, 1u,
                                                      (uint8_t)IDEMIP_IP4_IHL_MIN),
                                    202u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, MAXAGE_MS - 1u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, MAXAGE_MS));
}

// RFC 1122 sec 3.3.2: "the partially-reassembled datagram MUST be discarded and an ICMP Time Exceeded
// message sent to the source host (if fragment zero has been received)". A timeout reports both the
// source it is owed to and whether fragment zero was among the fragments held.
void test_a_timeout_reports_the_source_and_whether_fragment_zero_arrived(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          hold_frag(work_a, frag_full(0, SRC, DST, PROTO, ID, 0u, 8u, 1, 60u,
                                                      (uint8_t)IDEMIP_IP4_IHL_MIN),
                                    251u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, MAXAGE_MS));
    TEST_ASSERT_EQUAL_UINT32(SRC, IDEMIP_IP4_REASS_IO(work_a)->src);
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->frag_zero);

    // A datagram whose fragment zero never arrived is discarded with no ICMP owed.
    Ip4Reass.clear(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK,
                          hold_frag(work_b, frag_full(0, SRC, DST, PROTO, ID, 1u, 8u, 1, 60u,
                                                      (uint8_t)IDEMIP_IP4_IHL_MIN),
                                    252u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_b, MAXAGE_MS));
    TEST_ASSERT_EQUAL_UINT32(SRC, IDEMIP_IP4_REASS_IO(work_b)->src);
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_b)->frag_zero);
}

// A completed row the caller never released still pins descriptors, and PLAN sec 3.5 requires that
// "no pin outlives its unit's own bound", so the sweep reaches it too.
void test_a_completed_row_the_caller_left_also_times_out(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 211u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 1u, 8u, 0), 212u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, MAXAGE_MS));
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_RECLAIM, IDEMIP_IP4_REASS_IO(work_a)->state);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));
}

// One timed-out row per call, each named, so RFC 1122 sec 3.3.2's ICMP Time Exceeded can be built for
// every one of them. The sweep is done when a call reports BUSY.
void test_the_sweep_names_every_reached_row_one_at_a_time(void)
{
    Ip4Reass.clear(work_a);
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr_id((int)i, (uint16_t)(0x300u + i), 0u, 8u, 1),
                                                   (uint16_t)(220u + i)));
    }
    int seen[IDEMIP_IP4_REASS_DATAGRAMS] = {0};
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, MAXAGE_MS));
        uint8_t row = IDEMIP_IP4_REASS_IO(work_a)->index;
        TEST_ASSERT_TRUE(row < IDEMIP_IP4_REASS_DATAGRAMS);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, seen[row], "the same row was timed out twice");
        seen[row] = 1;
        TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->frag_zero);
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, MAXAGE_MS));
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));
}

// The deadline lives on a clock that wraps, so a comparison taken in the clock's own width still
// reaches a deadline the clock has passed.
void test_the_deadline_survives_the_clock_wrapping(void)
{
    Ip4Reass.clear(work_a);
    const uint32_t late = 0xFFFFF000u;
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_at(work_a, fr(0, 0u, 8u, 1), 231u, late));
    // The deadline is IDEMIP_IP_REASS_MAXAGE_S past `late`, which is past the wrap.
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, 0x00000100u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, late + (IDEMIP_IP_REASS_MAXAGE_S * 1000u)));
}

// --- capacity: BUSY where a retry can succeed --------------------------------

// The row table full is BUSY, not ERR, because the timeout sweep frees a row and the same fragment
// then lands.
void test_a_full_datagram_table_is_busy_and_the_retry_succeeds(void)
{
    Ip4Reass.clear(work_a);
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr_id((int)i, (uint16_t)(0x400u + i), 0u, 8u, 1),
                                                   (uint16_t)(240u + i)));
    }
    const uint8_t *extra = fr_id(FRAG_SLOTS - 1, 0x4FFu, 0u, 8u, 1);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, hold_frag(work_a, extra, 249u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_REASS_INDEX_NONE, IDEMIP_IP4_REASS_IO(work_a)->index);

    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, MAXAGE_MS));
    }
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, extra, 249u));
}

// The fragment table full is BUSY for the same reason: it is IDEMIP_MAX_PINNED_FRAMES' share of the
// receive ring, and reclaim gives one back.
void test_a_full_fragment_table_is_busy_and_the_retry_succeeds(void)
{
    Ip4Reass.clear(work_a);
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_FRAGS; i++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr((int)i, (uint16_t)i, 8u, 1), (uint16_t)(250u + i)));
    }
    const uint8_t *extra = fr(FRAG_SLOTS - 1, (uint16_t)IDEMIP_IP4_REASS_FRAGS, 8u, 1);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, hold_frag(work_a, extra, 259u));

    const uint8_t row = 0u;
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, release_row(work_a, row));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, extra, 259u));
}

// --- malformed fragments: ERR where a retry can never succeed ----------------

// RFC 791 sec 3.2: "the minimum fragment is 8 octets", so a fragment carrying no data at all fills
// no hole and never will.
void test_a_fragment_with_no_data_is_refused(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(0, 1u, 0u, 1), 261u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(1, 1u, 0u, 0), 262u));
}

// RFC 791 sec 3.2: "If an internet datagram is fragmented, its data portion must be broken on 8 octet
// boundaries", which binds every fragment but the last.
void test_a_non_final_fragment_off_the_eight_octet_boundary_is_refused(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(0, 0u, 9u, 1), 271u));
    // The last fragment carries whatever is left, so any length is in order there.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(1, 1u, 9u, 0), 272u));
    TEST_ASSERT_EQUAL_UINT16(17u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// RFC 791 sec 3.2 step (14), "TL <- TDL+(IHL*4)": the reassembled Total Length is a 16-bit field, so a
// fragment whose last octet would carry it past 65,535 cannot belong to any datagram.
void test_a_fragment_past_the_total_length_field_is_refused(void)
{
    Ip4Reass.clear(work_a);
    // Fragment Offset at the top of its 13 bits is octet 65,528.
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(0, (uint16_t)IDEMIP_IP4_FRAG_OFF_MASK, 8u, 0), 281u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_REASS_INDEX_NONE, IDEMIP_IP4_REASS_IO(work_a)->index);
}

// Once step (10) has fixed TDL, no octet of the datagram lies at or past it, so a fragment reaching
// beyond it is not part of this datagram.
void test_a_fragment_past_the_total_data_length_is_refused(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 1u, 8u, 0), 291u));
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
    // Octets 8 through 23, past the total data length of 16.
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(1, 1u, 16u, 1), 292u));
}

// Two last fragments naming different total data lengths cannot both be right, and neither becomes
// right on a retry.
void test_a_second_last_fragment_of_a_different_length_is_refused(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 1u, 8u, 0), 301u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(1, 2u, 8u, 0), 302u));
    // The row is untouched: its total data length is still the first one's.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(2, 0u, 8u, 1), 303u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// A last fragment cannot name a total data length below octets the row already holds.
void test_a_last_fragment_below_what_is_held_is_refused(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 2u, 8u, 1), 311u));
    // Claims the datagram ends at octet 16, under the fragment already held out to 24.
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(1, 1u, 8u, 0), 312u));
}

// The header carries the fields the row is keyed and indexed on, so it goes through the RFC 1122
// sec 3.2.1 checks first. A header the caller says is shorter than its own Total Length, and one
// whose checksum does not hold, are both refused.
void test_a_malformed_header_is_refused(void)
{
    Ip4Reass.clear(work_a);
    uint8_t *h = fr(0, 0u, 8u, 1);
    IDEMIP_IP4_REASS_IO(work_a)->now_ms = T0;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr = h;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.desc = 321u;
    IDEMIP_IP4_REASS_IO(work_a)->hold_args.len = (uint16_t)(idemip_ip4_total_len(h) - 1u);
    Ip4Reass.hold(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);

    IDEMIP_IP4_REASS_IO(work_a)->hold_args.len = idemip_ip4_total_len(h);
    idemip_ip4_set_cksum(h, (uint16_t)(idemip_ip4_cksum(h) ^ 0x0100u));
    Ip4Reass.hold(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);

    IDEMIP_IP4_REASS_IO(work_a)->hold_args.hdr = NULL;
    Ip4Reass.hold(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_REASS_IO(work_a)->status);
}

// A refused fragment takes no row, no fragment slot and no hole, so the whole table is still there
// afterwards.
void test_a_refused_fragment_consumes_nothing(void)
{
    Ip4Reass.clear(work_a);
    for (unsigned int i = 0u; i < 32u; i++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, hold_frag(work_a, fr(0, 0u, 9u, 1), 331u));
    }
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_FRAGS; i++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr((int)i, (uint16_t)i, 8u, 1), (uint16_t)(340u + i)));
    }
}

// --- the borrow is the instance ----------------------------------------------

// Two reassemblers over the same buffer identifier: the fragment that completes one leaves the other
// exactly where it was.
void test_two_borrows_reassemble_independently(void)
{
    Ip4Reass.clear(work_a);
    Ip4Reass.clear(work_b);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 351u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_b, fr(1, 0u, 8u, 1), 352u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(2, 1u, 8u, 0), 353u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_FALSE(IDEMIP_IP4_REASS_IO(work_b)->complete);

    // b still holds one fragment and no completed datagram.
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, next_one(work_b, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, next_one(work_a, 0u));
    TEST_ASSERT_EQUAL_UINT16(351u, IDEMIP_IP4_REASS_IO(work_a)->desc);
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports. This is the determinism the design is named for.
void test_a_hold_is_a_function_of_its_borrow_alone(void)
{
    Ip4Reass.clear(work_a);
    Ip4Reass.clear(work_b);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 361u));
    const uint8_t row_a = IDEMIP_IP4_REASS_IO(work_a)->index;

    // b takes the same identifier and the same offsets, and finishes its datagram.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_b, fr(1, 0u, 8u, 1), 362u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_b, fr(2, 1u, 8u, 0), 363u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_b)->complete);

    // a's own last fragment reports exactly what it would have without b's calls.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(3, 1u, 8u, 0), 364u));
    TEST_ASSERT_TRUE(IDEMIP_IP4_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT8(row_a, IDEMIP_IP4_REASS_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP4_REASS_IO(work_a)->total_len);
}

// clear takes a borrow mid-reassembly back to empty, so nothing of the old datagram survives.
void test_clear_drops_a_reassembly_in_progress(void)
{
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, hold_frag(work_a, fr(0, 0u, 8u, 1), 371u));
    Ip4Reass.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, reclaim_one(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, MAXAGE_MS));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, next_one(work_a, 0u));
}
