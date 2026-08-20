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

#include "src/ip/ip6_reass.h"

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

// =============================================================================
// The behavior suite: RFC 8200 sec 4.5
// =============================================================================
// Section 4.5 prints figures and one formula, and no numeric packet dumps, so there is no wire vector
// in it to copy. Every case below either drives the formula the section prints, or asserts a property
// the section's own text states, quoted at the case.

#define A_SRC 0x20u
#define A_DST 0x30u
#define B_SRC 0x21u

static uint8_t addr_a_src[IDEMIP_IP6_ADDR_LEN];
static uint8_t addr_a_dst[IDEMIP_IP6_ADDR_LEN];
static uint8_t addr_b_src[IDEMIP_IP6_ADDR_LEN];

// One fragment packet, built where a test can hand its address to input. The unit reads it during the
// call and keeps no pointer into it, so every fragment of a test is built in the same buffer. The cap
// spans the widest RFC 8200 sec 3 Payload Length plus the fixed header, which the cases driving the
// 65,535 bound of sec 4.5 need in full.
#define PKT_CAP (IDEMIP_IPV6_HDR_LEN + 65536u)
static uint8_t pkt[PKT_CAP];

static void fill_addr(uint8_t *a, uint8_t tag)
{
    memset(a, 0, IDEMIP_IP6_ADDR_LEN);
    a[0] = 0xFEu;
    a[1] = 0x80u;
    a[IDEMIP_IP6_ADDR_LEN - 1] = tag;
}

// An IPv6 header, ext octets of per-fragment Destination Options, a sec 4.5 Fragment header, and data
// octets of fragment data. Returns the octets written; the Fragment header sits at 40 + ext.
static size_t build(const uint8_t *src, const uint8_t *dst, uint32_t ident, uint16_t off, int more, uint8_t nh,
                    size_t ext, size_t data)
{
    memset(pkt, 0, PKT_CAP);
    IdemIpIp6BuildArgs a;
    a.src = src;
    a.dst = dst;
    a.flow_label = 0u;
    a.traffic_class = 0u;
    a.hop_limit = 64u;
    a.payload_len = (uint16_t)(ext + IDEMIP_IP6_FRAG_HDR_LEN + data);
    a.next_hdr = (ext != 0u) ? IDEMIP_IP6_NH_DSTOPTS : IDEMIP_IP6_NH_FRAGMENT;
    idemip_ip6_build(pkt, &a);
    if (ext != 0u)
    {
        pkt[IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_EXT_OFF_NEXT_HDR] = IDEMIP_IP6_NH_FRAGMENT;
        pkt[IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_EXT_OFF_LEN] = (uint8_t)((ext >> 3) - 1u);
    }
    idemip_ip6_frag_build(pkt + IDEMIP_IPV6_HDR_LEN + ext, nh, off, more ? IDEMIP_TRUE : IDEMIP_FALSE, ident);
    for (size_t i = 0; i < data; i++)
    {
        pkt[IDEMIP_IPV6_HDR_LEN + ext + IDEMIP_IP6_FRAG_HDR_LEN + i] = (uint8_t)(0xA0u + i);
    }
    return IDEMIP_IPV6_HDR_LEN + ext + IDEMIP_IP6_FRAG_HDR_LEN + data;
}

static void feed(uint8_t *w, size_t len, size_t frag_hdr, uint32_t now, uint16_t desc)
{
    IDEMIP_IP6_REASS_IO(w)->input_args.pkt = pkt;
    IDEMIP_IP6_REASS_IO(w)->input_args.len = len;
    IDEMIP_IP6_REASS_IO(w)->input_args.frag_hdr = frag_hdr;
    IDEMIP_IP6_REASS_IO(w)->input_args.now_ms = now;
    IDEMIP_IP6_REASS_IO(w)->input_args.desc = desc;
    Ip6Reass.input(w);
}

// A fragment with no per-fragment extension headers, which is where the Fragment header then sits.
static void feed_plain(uint8_t *w, uint32_t ident, uint16_t off, int more, uint8_t nh, size_t data, uint32_t now,
                       uint16_t desc)
{
    size_t len = build(addr_a_src, addr_a_dst, ident, off, more, nh, 0u, data);
    feed(w, len, IDEMIP_IPV6_HDR_LEN, now, desc);
}

static void ready(void)
{
    fill_addr(addr_a_src, A_SRC);
    fill_addr(addr_a_dst, A_DST);
    fill_addr(addr_b_src, B_SRC);
    Ip6Reass.clear(work_a);
}

static void tick_at(uint8_t *w, uint32_t now)
{
    IDEMIP_IP6_REASS_IO(w)->tick_args.now_ms = now;
    Ip6Reass.tick(w);
}

static void frag_at(uint8_t *w, uint8_t datagram, uint8_t index)
{
    IDEMIP_IP6_REASS_IO(w)->frag_args.datagram = datagram;
    IDEMIP_IP6_REASS_IO(w)->frag_args.index = index;
    Ip6Reass.frag_at(w);
}

static void drop(uint8_t *w, uint8_t datagram)
{
    IDEMIP_IP6_REASS_IO(w)->drop_args.datagram = datagram;
    Ip6Reass.drop(w);
}

// --- the whole datagram ------------------------------------------------------

// RFC 8200 sec 4.5: "If the fragment is a whole datagram (that is, both the Fragment Offset field and
// the M flag are zero), then it does not need any further reassembly".
void test_a_whole_datagram_completes_on_arrival(void)
{
    ready();
    feed_plain(work_a, 0x11223344u, 0u, 0, IDEMIP_IP6_NH_UDP, 16u, 1000u, 7u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_REASS_IO(work_a)->frag_count);
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP6_REASS_IO(work_a)->total_len);
}

// sec 4.5: "The Next Header field of the last header of the Per-Fragment headers is obtained from the
// Next Header field of the first fragment's Fragment header."
void test_the_next_header_is_the_offset_zero_fragments(void)
{
    ready();
    feed_plain(work_a, 1u, 0u, 0, IDEMIP_IP6_NH_TCP, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, IDEMIP_IP6_REASS_IO(work_a)->next_hdr);
}

// sec 4.5: "The Next Header values in the Fragment headers of different fragments of the same original
// packet may differ. Only the value from the Offset zero fragment packet is used for reassembly."
void test_a_later_fragments_next_header_is_ignored(void)
{
    ready();
    feed_plain(work_a, 2u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    feed_plain(work_a, 2u, 0u, 1, IDEMIP_IP6_NH_TCP, 8u, 1001u, 2u);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_TCP, IDEMIP_IP6_REASS_IO(work_a)->next_hdr);
}

// --- the hole list, RFC 815 sec 3 --------------------------------------------

void test_two_fragments_in_order_reassemble(void)
{
    ready();
    feed_plain(work_a, 3u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    feed_plain(work_a, 3u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP6_REASS_IO(work_a)->frag_count);
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP6_REASS_IO(work_a)->total_len);
}

// RFC 815 sec 3 reassembles "from any number of fragments arriving in any order", so the last fragment
// first leaves the head of the datagram as the one hole.
void test_two_fragments_out_of_order_reassemble(void)
{
    ready();
    feed_plain(work_a, 4u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    feed_plain(work_a, 4u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP6_REASS_IO(work_a)->total_len);
}

// RFC 815 sec 3 steps five and six together: the arriving fragment "can lie in the middle of an
// existing hole, breaking the hole in half and leaving a smaller hole at each end". The middle
// fragment then closes both.
void test_a_fragment_splits_a_hole_in_two(void)
{
    ready();
    feed_plain(work_a, 5u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    feed_plain(work_a, 5u, 32u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    // one hole, [8, 31]. This fragment lands in the middle of it and leaves [8, 15] and [24, 31].
    feed_plain(work_a, 5u, 16u, 1, IDEMIP_IP6_NH_UDP, 8u, 1002u, 3u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    feed_plain(work_a, 5u, 8u, 1, IDEMIP_IP6_NH_UDP, 8u, 1003u, 4u);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    feed_plain(work_a, 5u, 24u, 1, IDEMIP_IP6_NH_UDP, 8u, 1004u, 5u);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_IP6_REASS_IO(work_a)->frag_count);
    TEST_ASSERT_EQUAL_UINT16(40u, IDEMIP_IP6_REASS_IO(work_a)->total_len);
}

// RFC 815 sec 3 step eight: the datagram is complete only when "the hole descriptor list is now
// empty", so a gap in the middle keeps it open however many fragments have landed.
void test_a_gap_keeps_the_datagram_open(void)
{
    ready();
    feed_plain(work_a, 6u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    feed_plain(work_a, 6u, 16u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    tick_at(work_a, 1002u);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_REASS_IO(work_a)->expired);
}

// RFC 815 sec 3 step six's reason for testing more fragments: the hole "which reaches from the last
// octet of the buffer to infinity can be discarded". A last fragment carrying no data still fixes
// that end.
void test_a_zero_length_last_fragment_closes_the_datagram(void)
{
    ready();
    feed_plain(work_a, 7u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    feed_plain(work_a, 7u, 8u, 0, IDEMIP_IP6_NH_UDP, 0u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(8u, IDEMIP_IP6_REASS_IO(work_a)->total_len);
}

// --- the sec 4.5 Payload Length formula --------------------------------------

// sec 4.5: "PL.orig = PL.first - FL.first - 8 + (8 * FO.last) + FL.last". The per-fragment headers of
// the offset-zero fragment are the whole of PL.first - FL.first - 8, and sec 4.5 allows the later
// fragments to carry different ones, so the formula is driven with eight octets of Destination Options
// in front of the first fragment's Fragment header and none in front of the last.
void test_the_reassembled_payload_length_is_the_sec_4_5_formula(void)
{
    ready();
    size_t len = build(addr_a_src, addr_a_dst, 8u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 8u);
    uint16_t pl_first = idemip_ip6_payload_len(pkt);
    uint16_t fl_first = 8u;
    feed(work_a, len, IDEMIP_IPV6_HDR_LEN + 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);

    uint16_t fo_last = 1u; // the Fragment Offset field, in 8-octet units
    uint16_t fl_last = 16u;
    feed_plain(work_a, 8u, (uint16_t)(fo_last * 8u), 0, IDEMIP_IP6_NH_UDP, fl_last, 1001u, 2u);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);

    uint16_t pl_orig = (uint16_t)(pl_first - fl_first - 8u + (8u * fo_last) + fl_last);
    TEST_ASSERT_EQUAL_UINT16(pl_orig, IDEMIP_IP6_REASS_IO(work_a)->total_len);
    TEST_ASSERT_EQUAL_UINT16(32u, IDEMIP_IP6_REASS_IO(work_a)->total_len);
}

// The same formula with no per-fragment extension headers, where PL.first - FL.first - 8 is zero and
// the reassembled Payload Length is the Fragmentable Part alone.
void test_the_payload_length_of_a_headerless_reassembly_is_the_fragmentable_part(void)
{
    ready();
    feed_plain(work_a, 9u, 0u, 1, IDEMIP_IP6_NH_UDP, 24u, 1000u, 1u);
    feed_plain(work_a, 9u, 24u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(32u, IDEMIP_IP6_REASS_IO(work_a)->total_len);
}

// --- sec 4.5's error conditions ----------------------------------------------

// sec 4.5: "If the length of a fragment ... is not a multiple of 8 octets and the M flag of that
// fragment is 1, then that fragment must be discarded and an ICMP Parameter Problem, Code 0, message
// should be sent to the source of the fragment, pointing to the Payload Length field".
void test_a_short_fragment_with_more_set_is_a_payload_length_problem(void)
{
    ready();
    feed_plain(work_a, 10u, 0u, 1, IDEMIP_IP6_NH_UDP, 12u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_PAYLOAD_LEN, IDEMIP_IP6_REASS_IO(work_a)->err);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_REASS_NONE, IDEMIP_IP6_REASS_IO(work_a)->datagram);
}

// sec 4.5: "Each complete fragment, except possibly the last ("rightmost") one, is an integer multiple
// of 8 octets long", and the error condition above names only the M flag of 1. A last fragment of
// twelve octets is therefore taken.
void test_a_short_last_fragment_is_taken(void)
{
    ready();
    feed_plain(work_a, 11u, 0u, 0, IDEMIP_IP6_NH_UDP, 12u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(12u, IDEMIP_IP6_REASS_IO(work_a)->total_len);
}

// sec 4.5: "If the length and offset of a fragment are such that the Payload Length of the packet
// reassembled from that fragment would exceed 65,535 octets, then that fragment must be discarded and
// an ICMP Parameter Problem, Code 0, message should be sent ... pointing to the Fragment Offset field".
// The widest Fragment Offset the 13-bit field carries is 8191, which is 65528 octets, so eight octets
// of data behind it already pass 65535.
void test_an_offset_and_length_past_the_payload_field_is_a_fragment_offset_problem(void)
{
    ready();
    feed_plain(work_a, 12u, 65528u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_FRAG_OFFSET, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// The same bullet, where the offset-zero fragment's per-fragment headers are what pushes the
// reassembled Payload Length past 65,535: the formula adds PL.first - FL.first - 8 to the offset and
// length of every later fragment. 16 octets of Destination Options plus 65520 of offset and 8 of data
// is 65544, past the field, while the offset and length alone are 65528 and inside it.
void test_the_per_fragment_headers_count_toward_the_sixty_five_thousand_bound(void)
{
    ready();
    size_t len = build(addr_a_src, addr_a_dst, 13u, 0u, 1, IDEMIP_IP6_NH_UDP, 16u, 8u);
    feed(work_a, len, IDEMIP_IPV6_HDR_LEN + 16u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    feed_plain(work_a, 13u, 65520u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_FRAG_OFFSET, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// The same offset and length behind an offset-zero fragment carrying no per-fragment headers reaches
// exactly 65528 and is taken, so the refusal above is the headers and not the offset.
void test_the_same_offset_without_per_fragment_headers_is_taken(void)
{
    ready();
    feed_plain(work_a, 33u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    feed_plain(work_a, 33u, 65520u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// The same bullet once more, on the fragment that completes the packet. A fragment at a high offset
// that arrives before the offset-zero one is measured against nothing but the field, so the
// per-fragment headers of the offset-zero fragment can still carry the total past 65,535 later: 24
// octets of Destination Options plus a Fragmentable Part reaching 65512 is 65536.
void test_a_completed_packet_past_the_payload_field_is_a_fragment_offset_problem(void)
{
    ready();
    feed_plain(work_a, 34u, 65504u, 0, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;

    size_t len = build(addr_a_src, addr_a_dst, 34u, 0u, 1, IDEMIP_IP6_NH_UDP, 24u, 65496u);
    feed(work_a, len, IDEMIP_IPV6_HDR_LEN + 24u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);

    feed_plain(work_a, 34u, 65496u, 1, IDEMIP_IP6_NH_UDP, 8u, 1002u, 3u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_FRAG_OFFSET, IDEMIP_IP6_REASS_IO(work_a)->err);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_IP6_REASS_IO(work_a)->frag_count);
}

// The same three fragments with eight octets of Destination Options instead of twenty-four reach
// exactly 65520 and reassemble, so the refusal above is the total and not the shape.
void test_a_completed_packet_at_the_payload_field_is_taken(void)
{
    ready();
    feed_plain(work_a, 35u, 65504u, 0, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    size_t len = build(addr_a_src, addr_a_dst, 35u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 65496u);
    feed(work_a, len, IDEMIP_IPV6_HDR_LEN + 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    feed_plain(work_a, 35u, 65496u, 1, IDEMIP_IP6_NH_UDP, 8u, 1002u, 3u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT16(65520u, IDEMIP_IP6_REASS_IO(work_a)->total_len);
}

// sec 4.5: "If the first fragment does not include all headers through an Upper-Layer header, then
// that fragment should be discarded and an ICMP Parameter Problem, Code 3, message should be sent to
// the source of the fragment, with the Pointer field set to zero." Here the Fragment header names TCP
// and carries not one octet of it.
void test_a_first_fragment_without_its_upper_layer_header_is_a_header_chain_problem(void)
{
    ready();
    feed_plain(work_a, 14u, 0u, 1, IDEMIP_IP6_NH_TCP, 0u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_HEADER_CHAIN, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// The same bullet where the chain does not end inside the fragment: the Destination Options header
// behind the Fragment header claims 32 octets and only 8 are there.
void test_a_first_fragment_whose_chain_runs_off_the_end_is_a_header_chain_problem(void)
{
    ready();
    size_t len = build(addr_a_src, addr_a_dst, 15u, 0u, 1, IDEMIP_IP6_NH_DSTOPTS, 0u, 8u);
    pkt[IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_FRAG_HDR_LEN + IDEMIP_IP6_EXT_OFF_NEXT_HDR] = IDEMIP_IP6_NH_TCP;
    pkt[IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_FRAG_HDR_LEN + IDEMIP_IP6_EXT_OFF_LEN] = 3u; // 32 octets
    feed(work_a, len, IDEMIP_IPV6_HDR_LEN, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_HEADER_CHAIN, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// sec 4.7 makes a chain that ends in No Next Header legal, so an offset-zero fragment with no
// upper-layer header at all is not the error above.
void test_a_first_fragment_ending_in_no_next_header_is_taken(void)
{
    ready();
    feed_plain(work_a, 16u, 0u, 1, IDEMIP_IP6_NH_NONE, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// The offset-zero fragment is the only one sec 4.5 requires the headers of, so a fragment at a
// nonzero offset whose data begins with nothing recognizable is taken.
void test_a_later_fragment_needs_no_upper_layer_header(void)
{
    ready();
    feed_plain(work_a, 17u, 8u, 1, IDEMIP_IP6_NH_TCP, 0u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// sec 4.5: "If any of the fragments being reassembled overlap with any other fragments being
// reassembled for the same packet, reassembly of that packet must be abandoned and all the fragments
// that have been received for that packet must be discarded, and no ICMP error messages should be
// sent."
void test_overlapping_fragments_abandon_the_packet(void)
{
    ready();
    feed_plain(work_a, 18u, 0u, 1, IDEMIP_IP6_NH_UDP, 16u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    feed_plain(work_a, 18u, 8u, 0, IDEMIP_IP6_NH_UDP, 16u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_OVERLAP, IDEMIP_IP6_REASS_IO(work_a)->err);
    TEST_ASSERT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    // the fragments already received are still reachable, so the caller can unpin every descriptor
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_REASS_IO(work_a)->frag_count);
    frag_at(work_a, d, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(1u, IDEMIP_IP6_REASS_IO(work_a)->frag_desc);
}

// RFC 815 sec 3 step six creates the hole behind a fragment only "if fragment.more fragments is
// true", which discards "that hole descriptor which reaches from the last octet of the buffer to
// infinity". A hole whose last is finite was cut by a fragment lying beyond it, so a last fragment
// landing inside one leaves octets still missing.
//
// RFC 8200 sec 4.5 computes the Payload Length from "the length and offset of the last fragment", so
// a fragment held past the end this one fixes cannot belong to the same packet: the reassembly is
// abandoned rather than declared complete. Without this the datagram completes with the octets
// between them never received, and the stack delivers a packet containing bytes it never got.
void test_a_last_fragment_does_not_complete_a_packet_with_data_beyond_it(void)
{
    ready();
    // 1000..1096, so the hole list becomes [0, 999] and [1096, infinity).
    feed_plain(work_a, 40u, 1000u, 1, IDEMIP_IP6_NH_UDP, 96u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;

    // 0..8, so the first hole becomes [8, 999] - finite, because 1000..1096 cut it.
    feed_plain(work_a, 40u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);

    // 8..16 with the M flag clear. It starts where the hole starts and ends inside it, so RFC 815
    // step six with the M test alone puts nothing back and the hole [8, 999] is dropped whole.
    feed_plain(work_a, 40u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 1002u, 3u);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP6_REASS_IO(work_a)->complete,
                              "octets 16 through 999 were never received, and the packet was completed");
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_OVERLAP, IDEMIP_IP6_REASS_IO(work_a)->err);
    TEST_ASSERT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    // every fragment already received is still reachable, so the caller unpins each descriptor
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP6_REASS_IO(work_a)->frag_count);
    frag_at(work_a, d, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
}

// The same rule the other way round: the end is fixed, so a fragment arriving past it is the same
// contradiction.
void test_a_fragment_past_the_end_a_last_fragment_fixed_abandons_the_packet(void)
{
    ready();
    feed_plain(work_a, 41u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);

    feed_plain(work_a, 41u, 64u, 1, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_OVERLAP, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// Two last fragments naming different ends cannot both be the sec 4.5 "last fragment packet".
void test_two_last_fragments_naming_different_ends_abandon_the_packet(void)
{
    ready();
    feed_plain(work_a, 42u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    feed_plain(work_a, 42u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP6_REASS_IO(work_a)->complete, "0 through 16 arrived whole");

    ready();
    feed_plain(work_a, 43u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    feed_plain(work_a, 43u, 24u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_OVERLAP, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// RFC 8200 sec 4.5: "If the fragment is a whole datagram (that is, both the Fragment Offset field and
// the M flag are zero), then it does not need any further reassembly and should be processed as a
// fully reassembled packet ... Any other fragments that match this packet (i.e., the same IPv6 Source
// Address, IPv6 Destination Address, and Fragment Identification) should be processed independently."
//
// RFC 6946 is why this matters: an attacker who guesses a reassembly's {Source, Destination,
// Identification} sends one atomic fragment, and if it were filed into that reassembly it would either
// overlap the offset-zero fragment already held and abandon the whole packet, or displace it.
void test_an_atomic_fragment_is_processed_independently_of_a_reassembly_it_matches(void)
{
    ready();
    feed_plain(work_a, 44u, 0u, 1, IDEMIP_IP6_NH_UDP, 1000u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    uint8_t held = IDEMIP_IP6_REASS_IO(work_a)->datagram;

    // The same {src, dst, ident}, offset zero, M zero: a whole datagram of its own.
    feed_plain(work_a, 44u, 0u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP6_REASS_IO(work_a)->complete,
                             "a whole datagram needs no further reassembly");
    TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(held, IDEMIP_IP6_REASS_IO(work_a)->datagram,
                                        "the atomic fragment was filed into the reassembly it matched");

    // The reassembly it shares a key with is untouched, and its fragment still reachable to unpin.
    frag_at(work_a, held, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status,
                                  "the atomic fragment disturbed the reassembly it matched");
    TEST_ASSERT_EQUAL_HEX16(1u, IDEMIP_IP6_REASS_IO(work_a)->frag_desc);
}

// RFC 5722 sec 4: the overlap discards "the entire datagram (and any constituent fragments,
// including those not yet received)", so a later fragment bearing the poisoned key is discarded and
// must not open a fresh reassembly for the same datagram.
void test_an_abandoned_packet_takes_no_more_fragments(void)
{
    ready();
    feed_plain(work_a, 19u, 0u, 1, IDEMIP_IP6_NH_UDP, 16u, 1000u, 1u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    feed_plain(work_a, 19u, 8u, 1, IDEMIP_IP6_NH_UDP, 16u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_OVERLAP, IDEMIP_IP6_REASS_IO(work_a)->err);

    // A fragment that would have completed a replacement datagram is dropped instead.
    feed_plain(work_a, 19u, 32u, 1, IDEMIP_IP6_NH_UDP, 8u, 1002u, 3u);
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status,
                                      "a fragment of a poisoned key opened a fresh reassembly");
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);

    // And the offset-zero fragment of a replacement cannot restart it either.
    feed_plain(work_a, 19u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1003u, 4u);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    (void)d;
}

// sec 4.5's overlap bullet says "no ICMP error messages should be sent", so the sweep that finds an
// abandoned packet owes nothing, unlike the one that finds a timed-out packet.
void test_an_abandoned_packet_owes_no_icmp(void)
{
    ready();
    feed_plain(work_a, 20u, 0u, 1, IDEMIP_IP6_NH_UDP, 16u, 1000u, 1u);
    feed_plain(work_a, 20u, 8u, 1, IDEMIP_IP6_NH_UDP, 16u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_OVERLAP, IDEMIP_IP6_REASS_IO(work_a)->err);
    tick_at(work_a, 1002u);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_REASS_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// sec 4.5: "Instead of treating these exact duplicate fragments as overlapping fragments, an
// implementation may choose to detect this case and drop exact duplicate fragments while keeping the
// other fragments belonging to the same packet." A network that duplicates a packet delivers the
// same fragment twice, so taking that exception is what keeps reassembly working under duplication.
void test_an_exact_duplicate_is_dropped_and_the_packet_kept(void)
{
    ready();
    feed_plain(work_a, 21u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    feed_plain(work_a, 21u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
    // the packet is untouched, so the fragment that follows completes it
    feed_plain(work_a, 21u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 1002u, 3u);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    TEST_ASSERT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP6_REASS_IO(work_a)->frag_count);
}

// A fragment at a held fragment's offset with a different length is not an exact duplicate, so sec
// 4.5's overlap rule takes it rather than the duplicate exception.
void test_the_same_offset_with_a_different_length_overlaps(void)
{
    ready();
    feed_plain(work_a, 22u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    feed_plain(work_a, 22u, 0u, 1, IDEMIP_IP6_NH_UDP, 16u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_OVERLAP, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// --- the sec 4.5 key --------------------------------------------------------

// sec 4.5: "An original packet is reassembled only from fragment packets that have the same Source
// Address, Destination Address, and Fragment Identification."
void test_a_different_identification_is_a_different_packet(void)
{
    ready();
    feed_plain(work_a, 23u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    feed_plain(work_a, 24u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_NOT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
}

void test_a_different_source_address_is_a_different_packet(void)
{
    ready();
    feed_plain(work_a, 25u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    size_t len = build(addr_b_src, addr_a_dst, 25u, 8u, 0, IDEMIP_IP6_NH_UDP, 0u, 8u);
    feed(work_a, len, IDEMIP_IPV6_HDR_LEN, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_NOT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
}

void test_a_different_destination_address_is_a_different_packet(void)
{
    ready();
    feed_plain(work_a, 26u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    size_t len = build(addr_a_src, addr_b_src, 26u, 8u, 0, IDEMIP_IP6_NH_UDP, 0u, 8u);
    feed(work_a, len, IDEMIP_IPV6_HDR_LEN, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_NOT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
}

// sec 4.5, on a whole datagram: "Any other fragments that match this packet (i.e., the same IPv6
// Source Address, IPv6 Destination Address, and Fragment Identification) should be processed
// independently."
void test_a_completed_packet_takes_no_more_fragments(void)
{
    ready();
    feed_plain(work_a, 27u, 0u, 0, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    feed_plain(work_a, 27u, 8u, 1, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_NOT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
}

// --- walking the held fragments ----------------------------------------------

// sec 4.5: each fragment's "relative position in Fragmentable Part is computed from its Fragment
// Offset value", so the walk hands them back in that order whatever order they arrived in.
void test_the_walk_reports_fragments_in_rising_offset_order(void)
{
    ready();
    feed_plain(work_a, 28u, 16u, 0, IDEMIP_IP6_NH_UDP, 8u, 1000u, 0x33u);
    feed_plain(work_a, 28u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1001u, 0x11u);
    feed_plain(work_a, 28u, 8u, 1, IDEMIP_IP6_NH_UDP, 8u, 1002u, 0x22u);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;

    frag_at(work_a, d, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_IP6_REASS_IO(work_a)->frag_offset);
    TEST_ASSERT_EQUAL_HEX16(0x11u, IDEMIP_IP6_REASS_IO(work_a)->frag_desc);
    TEST_ASSERT_EQUAL_UINT16(8u, IDEMIP_IP6_REASS_IO(work_a)->frag_len);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_FRAG_HDR_LEN, IDEMIP_IP6_REASS_IO(work_a)->frag_hdr_len);

    frag_at(work_a, d, 1u);
    TEST_ASSERT_EQUAL_UINT16(8u, IDEMIP_IP6_REASS_IO(work_a)->frag_offset);
    TEST_ASSERT_EQUAL_HEX16(0x22u, IDEMIP_IP6_REASS_IO(work_a)->frag_desc);

    frag_at(work_a, d, 2u);
    TEST_ASSERT_EQUAL_UINT16(16u, IDEMIP_IP6_REASS_IO(work_a)->frag_offset);
    TEST_ASSERT_EQUAL_HEX16(0x33u, IDEMIP_IP6_REASS_IO(work_a)->frag_desc);
}

// The walk names a place in one datagram, so an index at or past what it holds names nothing.
void test_the_walk_refuses_an_index_past_the_datagram(void)
{
    ready();
    feed_plain(work_a, 29u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    frag_at(work_a, d, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(0u, IDEMIP_IP6_REASS_IO(work_a)->frag_desc);
}

// A datagram no entry holds names nothing either.
void test_the_walk_refuses_a_datagram_no_entry_holds(void)
{
    ready();
    frag_at(work_a, 0u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
}

// The per-fragment headers differ between fragments, and sec 4.5 says they may: the walk reports each
// fragment's own distance from its IPv6 header to its data, which is what a copy out needs.
void test_the_walk_reports_each_fragments_own_header_length(void)
{
    ready();
    size_t len = build(addr_a_src, addr_a_dst, 30u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 8u);
    feed(work_a, len, IDEMIP_IPV6_HDR_LEN + 8u, 1000u, 1u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    feed_plain(work_a, 30u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
    TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);

    frag_at(work_a, d, 0u);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV6_HDR_LEN + 8u + IDEMIP_IP6_FRAG_HDR_LEN,
                             IDEMIP_IP6_REASS_IO(work_a)->frag_hdr_len);
    frag_at(work_a, d, 1u);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_FRAG_HDR_LEN, IDEMIP_IP6_REASS_IO(work_a)->frag_hdr_len);
}

// --- giving a datagram up ----------------------------------------------------

// sec 4.5: "all the fragments that have been received for that packet must be discarded".
void test_drop_releases_the_datagram_and_its_fragments(void)
{
    ready();
    feed_plain(work_a, 31u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    drop(work_a, d);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    frag_at(work_a, d, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
}

void test_drop_of_a_datagram_no_entry_holds_is_refused(void)
{
    ready();
    drop(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
}

void test_drop_of_an_index_past_the_table_is_refused(void)
{
    ready();
    drop(work_a, IDEMIP_IP6_REASS_DATAGRAMS);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
}

// A dropped datagram gives its fragment entries and its hole descriptors back, so the tables come
// round again however many partial packets have passed through them.
void test_dropped_datagrams_give_their_entries_back(void)
{
    ready();
    for (uint32_t round = 0; round < 4u; round++)
    {
        feed_plain(work_a, 40u + round, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
        uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
        feed_plain(work_a, 40u + round, 16u, 0, IDEMIP_IP6_NH_UDP, 8u, 1001u, 2u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
        feed_plain(work_a, 40u + round, 8u, 1, IDEMIP_IP6_NH_UDP, 8u, 1002u, 3u);
        TEST_ASSERT_TRUE(IDEMIP_IP6_REASS_IO(work_a)->complete);
        drop(work_a, d);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    }
}

// --- the sec 4.5 sixty-second bound ------------------------------------------

// sec 4.5: "If insufficient fragments are received to complete reassembly of a packet within 60
// seconds of the reception of the first-arriving fragment of that packet, reassembly of that packet
// must be abandoned ... If the first fragment (i.e., the one with a Fragment Offset of zero) has been
// received, an ICMP Time Exceeded -- Fragment Reassembly Time Exceeded message should be sent".
void test_a_timed_out_packet_with_its_first_fragment_is_answered_with_time_exceeded(void)
{
    ready();
    feed_plain(work_a, 50u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 9u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    tick_at(work_a, 1000u + IDEMIP_IP6_REASS_MAXAGE_MS);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_REASS_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_TIMEOUT, IDEMIP_IP6_REASS_IO(work_a)->err);
    // the held fragments are still reachable, so the caller can answer the source and unpin
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_REASS_IO(work_a)->frag_count);
    frag_at(work_a, d, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(9u, IDEMIP_IP6_REASS_IO(work_a)->frag_desc);
}

// One millisecond inside the bound is not past it.
void test_a_sweep_inside_the_bound_expires_nothing(void)
{
    ready();
    feed_plain(work_a, 51u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    tick_at(work_a, 1000u + IDEMIP_IP6_REASS_MAXAGE_MS - 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_REASS_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_REASS_NONE, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// The bound runs from "the reception of the first-arriving fragment of that packet", so a later
// fragment does not push it out.
void test_the_bound_runs_from_the_first_arriving_fragment(void)
{
    ready();
    feed_plain(work_a, 52u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    feed_plain(work_a, 52u, 16u, 0, IDEMIP_IP6_NH_UDP, 8u, 30000u, 2u);
    tick_at(work_a, 1000u + IDEMIP_IP6_REASS_MAXAGE_MS - 1u);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_REASS_IO(work_a)->expired);
    tick_at(work_a, 1000u + IDEMIP_IP6_REASS_MAXAGE_MS);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_REASS_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_TIMEOUT, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// sec 4.5 owes the Time Exceeded only "If the first fragment (i.e., the one with a Fragment Offset of
// zero) has been received", so a packet that never got one is dropped silently.
void test_a_timed_out_packet_without_its_first_fragment_owes_no_icmp(void)
{
    ready();
    feed_plain(work_a, 53u, 8u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    tick_at(work_a, 1000u + IDEMIP_IP6_REASS_MAXAGE_MS);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_REASS_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// A timed-out packet takes no more fragments: its reassembly is abandoned, so a matching fragment
// starts a new one.
void test_a_timed_out_packet_takes_no_more_fragments(void)
{
    ready();
    feed_plain(work_a, 54u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    uint8_t d = IDEMIP_IP6_REASS_IO(work_a)->datagram;
    tick_at(work_a, 1000u + IDEMIP_IP6_REASS_MAXAGE_MS);
    feed_plain(work_a, 54u, 8u, 0, IDEMIP_IP6_NH_UDP, 8u, 61001u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_NOT_EQUAL_UINT8(d, IDEMIP_IP6_REASS_IO(work_a)->datagram);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);
}

// The sweep reports one at a time and keeps reporting until the caller drops them, so a caller that
// walks and drops in a loop reaches every one.
void test_a_sweep_names_each_expired_packet_in_turn(void)
{
    ready();
    feed_plain(work_a, 61u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    feed_plain(work_a, 62u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 2u);
    feed_plain(work_a, 63u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 3u);
    for (uint8_t left = 3u; left > 0u; left--)
    {
        tick_at(work_a, 1000u + IDEMIP_IP6_REASS_MAXAGE_MS);
        TEST_ASSERT_EQUAL_UINT8(left, IDEMIP_IP6_REASS_IO(work_a)->expired);
        TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_TIMEOUT, IDEMIP_IP6_REASS_IO(work_a)->err);
        drop(work_a, IDEMIP_IP6_REASS_IO(work_a)->datagram);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    }
    tick_at(work_a, 1000u + IDEMIP_IP6_REASS_MAXAGE_MS);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_REASS_IO(work_a)->expired);
}

// The millisecond clock wraps at 2^32, so a deadline stamped just before the wrap lands just after
// it. The sec 4.5 bound is still 60 seconds across the seam.
void test_the_bound_holds_across_a_clock_wrap(void)
{
    ready();
    uint32_t first = 0xFFFFFFFFu - 1000u; // the deadline lands 59000 ms past the wrap
    feed_plain(work_a, 55u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, first, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    tick_at(work_a, first + IDEMIP_IP6_REASS_MAXAGE_MS - 1u);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_REASS_IO(work_a)->expired);
    tick_at(work_a, first + IDEMIP_IP6_REASS_MAXAGE_MS);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_REASS_IO(work_a)->expired);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_TIMEOUT, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// A sweep that has nothing to age still reports the sweep ran.
void test_a_sweep_of_an_empty_table_reports_ok(void)
{
    ready();
    tick_at(work_a, 12345u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_REASS_IO(work_a)->expired);
}

// --- the tables are full -----------------------------------------------------

// A table with no free entry is BUSY, not ERR: an entry frees when a datagram is dropped, so the same
// fragment lands on a later tick.
void test_a_full_datagram_table_reports_busy(void)
{
    ready();
    for (uint32_t i = 0; i < IDEMIP_IP6_REASS_DATAGRAMS; i++)
    {
        feed_plain(work_a, 100u + i, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, (uint16_t)i);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    }
    feed_plain(work_a, 200u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 99u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_REASS_NONE, IDEMIP_IP6_REASS_IO(work_a)->datagram);
}

// The same fragment lands once a datagram is dropped, which is what BUSY promised.
void test_a_busy_fragment_lands_after_a_drop(void)
{
    ready();
    for (uint32_t i = 0; i < IDEMIP_IP6_REASS_DATAGRAMS; i++)
    {
        feed_plain(work_a, 100u + i, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, (uint16_t)i);
    }
    feed_plain(work_a, 200u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 99u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP6_REASS_IO(work_a)->status);
    drop(work_a, 0u);
    feed_plain(work_a, 200u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 99u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_REASS_IO(work_a)->datagram);
}

// A fragment table with no free entry is BUSY too, and the fragments it already holds are untouched.
void test_a_full_fragment_table_reports_busy(void)
{
    ready();
    for (uint32_t i = 0; i < IDEMIP_IP6_REASS_FRAGS; i++)
    {
        feed_plain(work_a, 300u, (uint16_t)(i * 8u), 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, (uint16_t)i);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    }
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_REASS_FRAGS, IDEMIP_IP6_REASS_IO(work_a)->frag_count);
    feed_plain(work_a, 300u, (uint16_t)(IDEMIP_IP6_REASS_FRAGS * 8u), 0, IDEMIP_IP6_NH_UDP, 8u, 1000u, 77u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP6_REASS_IO(work_a)->status);
}

// A refused fragment takes no entry with it. Every one of the four refusals below is a full datagram
// table, so if one leaked a fragment entry the three free ones would be gone and the four fragments
// added after the drop could not all land.
void test_a_busy_input_leaks_no_fragment_entry(void)
{
    ready();
    for (uint32_t i = 0; i < IDEMIP_IP6_REASS_DATAGRAMS; i++)
    {
        feed_plain(work_a, 100u + i, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, (uint16_t)i);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    }
    for (uint32_t i = 0; i < 4u; i++)
    {
        feed_plain(work_a, 400u + i, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 88u);
        TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP6_REASS_IO(work_a)->status);
    }
    drop(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    for (uint32_t i = 1u; i <= 4u; i++)
    {
        feed_plain(work_a, 101u, (uint16_t)(i * 8u), 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, (uint16_t)i);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    }
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_IP6_REASS_IO(work_a)->frag_count);
}

// --- what input refuses outright ---------------------------------------------

// The Fragment header the caller names must lie behind the fixed header of sec 3 and wholly inside the
// packet, or there is nothing to read the sec 4.5 fields from.
void test_a_fragment_header_outside_the_packet_is_refused(void)
{
    ready();
    size_t len = build(addr_a_src, addr_a_dst, 60u, 0u, 1, IDEMIP_IP6_NH_UDP, 0u, 8u);
    feed(work_a, len, len - 4u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
    feed(work_a, len, IDEMIP_IPV6_HDR_LEN - 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
}

// sec 3's Payload Length is "the rest of the packet following this IPv6 header", so a field naming
// more octets than the buffer holds is refused rather than read past.
void test_a_payload_length_past_the_buffer_is_refused(void)
{
    ready();
    size_t len = build(addr_a_src, addr_a_dst, 61u, 0u, 1, IDEMIP_IP6_NH_UDP, 0u, 8u);
    idemip_ip6_set_payload_len(pkt, (uint16_t)(len - IDEMIP_IPV6_HDR_LEN + 8u));
    feed(work_a, len, IDEMIP_IPV6_HDR_LEN, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_REASS_ERR_NONE, IDEMIP_IP6_REASS_IO(work_a)->err);
}

// A packet shorter than the forty octets of sec 3 carries no addresses to key on.
void test_a_packet_shorter_than_the_fixed_header_is_refused(void)
{
    ready();
    size_t len = build(addr_a_src, addr_a_dst, 62u, 0u, 1, IDEMIP_IP6_NH_UDP, 0u, 8u);
    (void)len;
    feed(work_a, IDEMIP_IPV6_HDR_LEN - 1u, IDEMIP_IPV6_HDR_LEN, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
}

// A null packet has no header at all.
void test_a_null_packet_is_refused(void)
{
    ready();
    IDEMIP_IP6_REASS_IO(work_a)->input_args.pkt = NULL;
    IDEMIP_IP6_REASS_IO(work_a)->input_args.len = 64u;
    IDEMIP_IP6_REASS_IO(work_a)->input_args.frag_hdr = IDEMIP_IPV6_HDR_LEN;
    Ip6Reass.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_REASS_IO(work_a)->status);
}

// --- two borrows -------------------------------------------------------------

// The borrow IS the reassembler, so the same fragments filed into two of them reach two independent
// sets of tables.
void test_two_borrows_reassemble_independently(void)
{
    ready();
    Ip6Reass.clear(work_b);
    feed_plain(work_a, 70u, 0u, 1, IDEMIP_IP6_NH_UDP, 8u, 1000u, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_a)->complete);

    size_t len = build(addr_a_src, addr_a_dst, 70u, 8u, 0, IDEMIP_IP6_NH_UDP, 0u, 8u);
    feed(work_b, len, IDEMIP_IPV6_HDR_LEN, 1000u, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(work_b)->status);
    TEST_ASSERT_FALSE(IDEMIP_IP6_REASS_IO(work_b)->complete);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_REASS_IO(work_b)->frag_count);

    // borrow a still holds only its own fragment, and its sweep ages only its own datagram
    tick_at(work_a, 1000u + IDEMIP_IP6_REASS_MAXAGE_MS);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP6_REASS_IO(work_a)->expired);
    tick_at(work_b, 1000u);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_IP6_REASS_IO(work_b)->expired);
}
