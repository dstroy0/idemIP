// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for RFC 9293 sec 3.10.7 SEGMENT ARRIVES. It tests the contract and the protocol:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. the sequence-number traces printed in RFC 9293 sec 3.5 Figures 6, 7 and 8, sec 3.5.1 Figures
//      10 and 11, sec 3.6 Figures 12 and 13, and RFC 1337 Figure 1 are the vectors, quoted where they
//      are used
//   5. every security check has a case that fails if the check is removed
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/tcp/tcp_in.h"

#include <string.h>
#include <unity.h>

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_TCP_IN_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_TCP_IN_BORROW + 16];

#define IO(w) IDEMIP_TCP_IN_IO(w)

static const uint8_t g_local[IDEMIP_TCP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 1u};
static const uint8_t g_remote[IDEMIP_TCP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 9u};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_TCP_IN_BORROW, CANARY, cap - IDEMIP_TCP_IN_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_TCP_IN_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_TCP_IN_BORROW");
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

static void call_every_entry(uint8_t *w)
{
    TcpIn.parse(w);
    TcpIn.acceptable(w);
    TcpIn.closed(w);
    TcpIn.listen(w);
    TcpIn.syn_sent(w);
    TcpIn.segment(w);
}

// A connection at rest, with the four variables every check below reads.
static void conn(uint8_t *w, IdemIpTcpState st, uint32_t una, uint32_t nxt, uint32_t rcv_nxt, uint32_t rcv_wnd)
{
    TcpIn.clear(w);
    memset(&IO(w)->vars, 0, sizeof IO(w)->vars);
    memset(&IO(w)->ctl, 0, sizeof IO(w)->ctl);
    memset(&IO(w)->seg, 0, sizeof IO(w)->seg);
    IO(w)->vars.snd_una = una;
    IO(w)->vars.snd_nxt = nxt;
    IO(w)->vars.snd_wnd = 4096u;
    IO(w)->vars.rcv_nxt = rcv_nxt;
    IO(w)->vars.rcv_wnd = rcv_wnd;
    IO(w)->ctl.max_snd_wnd = 4096u;
    IO(w)->state = st;
    IO(w)->listener = IDEMIP_TCP_PCB_NONE;
    IO(w)->now_ms = 0u;
}

// One arriving segment's RFC 9293 sec 3.3.1 Table 4 variables.
static void seg(uint8_t *w, uint32_t s, uint32_t a, uint32_t len, uint16_t data, uint8_t flags)
{
    IO(w)->seg.seq = s;
    IO(w)->seg.ack = a;
    IO(w)->seg.len = len;
    IO(w)->seg.data_len = data;
    IO(w)->seg.wnd = 4096u;
    IO(w)->seg.up = 0u;
    IO(w)->seg.flags = flags;
}

// A segment on the wire, its checksum over the RFC 9293 sec 3.1 pseudo-header, in the caller's bytes.
static uint8_t g_wire[128];

static uint16_t wire(uint32_t s, uint32_t a, uint8_t flags, uint16_t win, const uint8_t *opts, uint16_t opts_len,
                     const uint8_t *data, uint16_t data_len)
{
    memset(g_wire, 0, sizeof g_wire);
    uint16_t hdr = (uint16_t)(IDEMIP_TCP_HDR_LEN + opts_len);
    idemip_wr16(g_wire + IDEMIP_TCP_OFF_SRC_PORT, 40000u);
    idemip_wr16(g_wire + IDEMIP_TCP_OFF_DST_PORT, 80u);
    idemip_wr32(g_wire + IDEMIP_TCP_OFF_SEQ, s);
    idemip_wr32(g_wire + IDEMIP_TCP_OFF_ACK, a);
    idemip_wr16(g_wire + IDEMIP_TCP_OFF_OFFS_FLAGS,
                (uint16_t)(((uint16_t)IDEMIP_TCP_DOFF_FROM_BYTES(hdr) << IDEMIP_TCP_DOFF_SHIFT) | flags));
    idemip_wr16(g_wire + IDEMIP_TCP_OFF_WINDOW, win);
    idemip_wr16(g_wire + IDEMIP_TCP_OFF_CKSUM, 0u);
    idemip_wr16(g_wire + IDEMIP_TCP_OFF_URGENT, 0u);
    if (opts_len != 0)
    {
        memcpy(g_wire + IDEMIP_TCP_OFF_OPTIONS, opts, opts_len);
    }
    if (data_len != 0)
    {
        memcpy(g_wire + hdr, data, data_len);
    }
    uint16_t total = (uint16_t)(hdr + data_len);
    idemip_wr16(g_wire + IDEMIP_TCP_OFF_CKSUM,
                idemip_tcp_cksum_compute(g_wire, total, idemip_rd32(g_remote), idemip_rd32(g_local)));
    return total;
}

static void aim_parse(uint8_t *w, uint16_t total, uint8_t scale)
{
    IO(w)->parse_args.seg = g_wire;
    IO(w)->parse_args.local_ip = g_local;
    IO(w)->parse_args.remote_ip = g_remote;
    IO(w)->parse_args.len = total;
    IO(w)->parse_args.ip_version = 4u;
    IO(w)->parse_args.snd_scale = scale;
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    TcpIn.clear(NULL);
    call_every_entry(NULL);
    TEST_PASS();
}

// The map is public, so a reader can place both regions without opening the .c.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_TCP_IN_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(sizeof(TcpInIo), (size_t)IDEMIP_TCP_IN_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_TCP_IN_OFF_CTX < (size_t)IDEMIP_TCP_IN_BORROW,
                             "the context starts past IDEMIP_TCP_IN_BORROW");
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_TCP_IN_OFF_IO, IO(work_a));
}

// Zeroed, never cleared: every entry must refuse rather than run on a context that was never marked.
void test_an_uncleared_borrow_is_refused(void)
{
    IO(work_a)->parse_args.seg = g_wire;
    IO(work_a)->parse_args.local_ip = g_local;
    IO(work_a)->parse_args.remote_ip = g_remote;
    IO(work_a)->parse_args.len = (uint16_t)IDEMIP_TCP_HDR_LEN;
    IO(work_a)->parse_args.ip_version = 4u;
    call_every_entry(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// An entry is a function of its borrow alone, so the same call on the same bytes repeats.
void test_clear_repeats(void)
{
    TcpIn.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint8_t first[IDEMIP_TCP_IN_BORROW];
    memcpy(first, work_a, sizeof first);
    TcpIn.clear(work_a);
    TEST_ASSERT_EQUAL_MEMORY(first, work_a, sizeof first);
}

// The borrow IS the instance, so a call on one leaves the other untouched.
void test_two_borrows_share_no_byte(void)
{
    TcpIn.clear(work_a);
    uint8_t before[IDEMIP_TCP_IN_BORROW];
    memcpy(before, work_b, sizeof before);
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 100u, 300u, 4096u);
    seg(work_a, 300u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_MEMORY(before, work_b, sizeof before);
}

// --- the parse (RFC 9293 sec 3.1, sec 3.2) -----------------------------------

// RFC 9293 sec 3.5 Figure 6 line 3: "<SEQ=300><ACK=101><CTL=SYN,ACK>". Every field comes back where
// the figure puts it.
void test_parse_reads_the_section_3_1_header_fields(void)
{
    TcpIn.clear(work_a);
    uint16_t total = wire(300u, 101u, (uint8_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK), 4096u, NULL, 0u, NULL, 0u);
    aim_parse(work_a, total, 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(300u, IO(work_a)->seg.seq);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->seg.ack);
    TEST_ASSERT_EQUAL_UINT32(4096u, IO(work_a)->seg.wnd);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK), IO(work_a)->seg.flags);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_HDR_LEN, IO(work_a)->opts.hdr_len);
}

// RFC 9293 sec 3.4: "SEG.LEN = the number of octets occupied by the data in the segment (counting SYN
// and FIN)".
void test_parse_counts_the_syn_and_fin_in_seg_len(void)
{
    static const uint8_t data[10] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u};
    TcpIn.clear(work_a);

    uint16_t total = wire(100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 4096u, NULL, 0u, NULL, 0u);
    aim_parse(work_a, total, 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_UINT32(1u, IO(work_a)->seg.len);
    TEST_ASSERT_EQUAL_UINT16(0u, IO(work_a)->seg.data_len);

    total = wire(100u, 300u, (uint8_t)(IDEMIP_TCP_FIN | IDEMIP_TCP_ACK), 4096u, NULL, 0u, data, 10u);
    aim_parse(work_a, total, 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_UINT32(11u, IO(work_a)->seg.len);
    TEST_ASSERT_EQUAL_UINT16(10u, IO(work_a)->seg.data_len);

    total = wire(100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 4096u, NULL, 0u, data, 10u);
    aim_parse(work_a, total, 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_UINT32(10u, IO(work_a)->seg.len);
}

// RFC 9293 sec 3.1: "The checksum field is the 16-bit ones' complement of the ones' complement sum of
// all 16-bit words in the header and text." One flipped bit and the segment is not read.
void test_parse_refuses_a_segment_whose_checksum_does_not_check_out(void)
{
    TcpIn.clear(work_a);
    uint16_t total = wire(100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 4096u, NULL, 0u, NULL, 0u);
    aim_parse(work_a, total, 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    g_wire[IDEMIP_TCP_OFF_SEQ] ^= 0x01u;
    aim_parse(work_a, total, 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->seg.seq);
}

// RFC 9293 sec 3.1: an option-free header is five 32-bit words, and the Data Offset "indicates where
// the data begins", so one naming fewer words or more octets than arrived names no header.
void test_parse_refuses_a_data_offset_that_names_no_header(void)
{
    TcpIn.clear(work_a);
    uint16_t total = wire(100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 4096u, NULL, 0u, NULL, 0u);
    idemip_wr16(g_wire + IDEMIP_TCP_OFF_OFFS_FLAGS,
                (uint16_t)((4u << IDEMIP_TCP_DOFF_SHIFT) | (uint16_t)IDEMIP_TCP_SYN));
    aim_parse(work_a, total, 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    idemip_wr16(g_wire + IDEMIP_TCP_OFF_OFFS_FLAGS,
                (uint16_t)((10u << IDEMIP_TCP_DOFF_SHIFT) | (uint16_t)IDEMIP_TCP_SYN));
    aim_parse(work_a, total, 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    aim_parse(work_a, (uint16_t)(IDEMIP_TCP_HDR_LEN - 1u), 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// RFC 9293 sec 3.2's kind 2, RFC 7323 sec 2.2's kind 3 and sec 3.2's kind 8, and RFC 2018 sec 2's
// kind 4, read where the Data Offset puts them.
void test_parse_reads_the_section_3_2_options(void)
{
    static const uint8_t opts[24] = {
        2u, 4u, 0x05u, 0xB4u,               // kind 2, length 4, MSS 1460
        4u, 2u,                             // kind 4, length 2
        1u, 3u, 3u, 7u,                     // NOP, kind 3, length 3, shift.cnt 7
        1u, 1u,                             // NOP, NOP
        8u, 10u,                            // kind 8, length 10
        0x11u, 0x22u, 0x33u, 0x44u,         // TSval
        0x55u, 0x66u, 0x77u, 0x88u,         // TSecr
        0u, 0u};                            // End of Option List, then padding of zeros
    TcpIn.clear(work_a);
    uint16_t total = wire(100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 4096u, opts, 24u, NULL, 0u);
    aim_parse(work_a, total, 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)(IDEMIP_TCP_IN_OPT_MSS | IDEMIP_TCP_IN_OPT_WS | IDEMIP_TCP_IN_OPT_TS |
                                      IDEMIP_TCP_IN_OPT_SACK_PERM),
                            IO(work_a)->opts.present);
    TEST_ASSERT_EQUAL_UINT16(1460u, IO(work_a)->opts.mss);
    TEST_ASSERT_EQUAL_UINT8(7u, IO(work_a)->opts.ws);
    TEST_ASSERT_EQUAL_UINT32(0x11223344u, IO(work_a)->opts.tsval);
}

// RFC 9293 sec 3.1 MUST-7: "TCP implementations MUST be prepared to handle an illegal option length
// (e.g., zero)." The walk stops on one and the parse says so.
void test_parse_refuses_an_illegal_option_length(void)
{
    static const uint8_t opts[4] = {2u, 0u, 0u, 0u}; // kind 2 with option-length zero
    TcpIn.clear(work_a);
    uint16_t total = wire(100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 4096u, opts, 4u, NULL, 0u);
    aim_parse(work_a, total, 0u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// RFC 7323 sec 2.3: "The window field (SEG.WND) in the header of every incoming segment, with the
// exception of <SYN> segments, MUST be left-shifted by Snd.Wind.Shift bits before updating SND.WND."
void test_parse_scales_every_window_but_a_syn_segments(void)
{
    TcpIn.clear(work_a);
    uint16_t total = wire(100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 1000u, NULL, 0u, NULL, 0u);
    aim_parse(work_a, total, 7u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_UINT32(1000u, IO(work_a)->seg.wnd);

    total = wire(100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 1000u, NULL, 0u, NULL, 0u);
    aim_parse(work_a, total, 7u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_UINT32(1000u << 7, IO(work_a)->seg.wnd);

    // sec 2.3 caps the shift: "the shift count MUST be limited to 14".
    aim_parse(work_a, total, 30u);
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_UINT32(1000u << IDEMIP_TCP_WS_MAX, IO(work_a)->seg.wnd);
}

// --- the acceptability test (RFC 9293 sec 3.4, sec 3.10.7.4 Table 6) ----------

// The four rows of Table 6, each driven at its edges.
void test_the_four_acceptability_cases_of_table_6(void)
{
    // Row 1: SEG.LEN 0, RCV.WND 0 - "SEG.SEQ = RCV.NXT"
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 100u, 500u, 0u);
    seg(work_a, 500u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.acceptable);
    seg(work_a, 501u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.acceptable);

    // Row 2: SEG.LEN 0, RCV.WND > 0 - "RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND"
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 100u, 500u, 100u);
    seg(work_a, 500u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.acceptable);
    seg(work_a, 599u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.acceptable);
    seg(work_a, 600u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.acceptable);
    seg(work_a, 499u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.acceptable);

    // Row 3: SEG.LEN > 0, RCV.WND 0 - "not acceptable"
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 100u, 500u, 0u);
    seg(work_a, 500u, 100u, 1u, 1u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.acceptable);

    // Row 4: SEG.LEN > 0, RCV.WND > 0 - either edge inside the window
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 100u, 500u, 100u);
    seg(work_a, 490u, 100u, 20u, 20u, (uint8_t)IDEMIP_TCP_ACK); // ends inside
    TcpIn.acceptable(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.acceptable);
    seg(work_a, 590u, 100u, 20u, 20u, (uint8_t)IDEMIP_TCP_ACK); // begins inside
    TcpIn.acceptable(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.acceptable);
    seg(work_a, 470u, 100u, 20u, 20u, (uint8_t)IDEMIP_TCP_ACK); // entirely behind
    TcpIn.acceptable(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.acceptable);
    seg(work_a, 600u, 100u, 20u, 20u, (uint8_t)IDEMIP_TCP_ACK); // entirely ahead
    TcpIn.acceptable(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.acceptable);
}

// RFC 9293 sec 3.4: "all arithmetic dealing with sequence numbers must be performed modulo 2^32. This
// unsigned arithmetic preserves the relationship of sequence numbers as they cycle from 2^32 - 1 to 0
// again." A window straddling the wrap accepts what lies inside it on both sides.
void test_the_acceptability_test_holds_across_the_sequence_space_wrap(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 100u, 0xFFFFFF00u, 512u);
    seg(work_a, 0xFFFFFF00u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.acceptable);
    seg(work_a, 0x00000010u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.acceptable);
    seg(work_a, 0x00000100u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.acceptable(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.acceptable);
}

// RFC 9293 sec 3.10.7.4 first: "If an incoming segment is not acceptable, an acknowledgment should be
// sent in reply ... <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>".
void test_an_unacceptable_segment_draws_an_acknowledgment(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 140u, 500u, 100u);
    seg(work_a, 900u, 100u, 4u, 4u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->res.acceptable);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK);
    TEST_ASSERT_EQUAL_UINT32(140u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(500u, IO(work_a)->reply.ack);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_ACK, IO(work_a)->reply.flags);
    TEST_ASSERT_FALSE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_TEXT);
}

// "(unless the RST bit is set, if so drop the segment and return)". An out-of-window reset draws
// nothing at all, which is also RFC 5961 sec 3.2 step 1.
void test_an_unacceptable_reset_is_dropped_without_an_acknowledgment(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 140u, 500u, 100u);
    seg(work_a, 900u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.act);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_ESTABLISHED, (int)IO(work_a)->state);
}

// --- RFC 5961 sec 3, the blind reset attack using the RST bit -----------------

// RFC 5961 sec 3.2 step 3: "If the RST bit is set and the sequence number does not exactly match the
// next expected sequence value, yet is within the current receive window (RCV.NXT < SEG.SEQ <
// RCV.NXT+RCV.WND), TCP MUST send an acknowledgment (challenge ACK): <SEQ=SND.NXT><ACK=RCV.NXT>
// <CTL=ACK>. After sending the challenge ACK, TCP MUST drop the unacceptable segment and stop
// processing the incoming packet further."
//
// Remove that step and this connection is torn down by a reset whose sequence number was guessed
// rather than known, which is the blind reset attack of sec 3.1 and CVE-2004-0230.
void test_an_in_window_reset_that_is_not_rcv_nxt_draws_a_challenge_ack(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 140u, 500u, 100u);
    seg(work_a, 550u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_CHALLENGE,
                             "an in-window reset that is not RCV.NXT must draw RFC 5961 sec 3.2's challenge ACK");
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK);
    TEST_ASSERT_EQUAL_UINT32(140u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(500u, IO(work_a)->reply.ack);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_ACK, IO(work_a)->reply.flags);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)IDEMIP_TCP_STATE_ESTABLISHED, (int)IO(work_a)->state,
                                  "a guessed in-window reset must not tear the connection down");
    TEST_ASSERT_FALSE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_DELETE);
}

// RFC 5961 sec 3.2 step 2: "If the RST bit is set and the sequence number exactly matches the next
// expected sequence number (RCV.NXT), then TCP MUST reset the connection."
void test_a_reset_at_rcv_nxt_resets_the_connection(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 140u, 500u, 100u);
    seg(work_a, 500u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_CLOSED, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_RESET);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_DELETE);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_FLUSH);
    TEST_ASSERT_FALSE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK);
}

// RFC 5961 sec 3.2 step 1: "If the RST bit is set and the sequence number is outside the current
// receive window, silently drop the segment." Not even a challenge ACK goes out, so the exchange sec
// 10 warns about cannot be provoked from outside the window.
void test_a_reset_outside_the_window_is_silently_dropped(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 140u, 500u, 100u);
    seg(work_a, 700u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.act);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_ESTABLISHED, (int)IO(work_a)->state);
}

// RFC 9293 sec 3.10.7.4 second, SYN-RECEIVED: "If this connection was initiated with a passive OPEN
// (i.e., came from the LISTEN state), then return this connection to LISTEN state and return."
void test_a_reset_in_syn_received_from_a_passive_open_returns_to_listen(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_RECEIVED, 300u, 301u, 101u, 4096u);
    IO(work_a)->listener = 2u;
    seg(work_a, 101u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_LISTEN, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_LISTEN);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_FLUSH);
    TEST_ASSERT_FALSE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_DELETE);
}

// "If this connection was initiated with an active OPEN (i.e., came from SYN-SENT state), then the
// connection was refused ... enter the CLOSED state and delete the TCB, and return."
void test_a_reset_in_syn_received_from_an_active_open_refuses_the_connection(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_RECEIVED, 300u, 301u, 101u, 4096u);
    seg(work_a, 101u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_CLOSED, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_REFUSED);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_DELETE);
}

// --- RFC 5961 sec 4, the blind reset attack using the SYN bit ------------------

// RFC 5961 sec 4.2: "If the SYN bit is set, irrespective of the sequence number, TCP MUST send an ACK
// (also referred to as challenge ACK) to the remote peer ... After sending the acknowledgment, TCP
// MUST drop the unacceptable segment and stop processing further."
//
// Remove the challenge and the RFC 793 behavior sec 4.2 replaces takes over: an in-window SYN is
// answered with a reset, which is the tear-down sec 4.1 describes an attacker reaching by guessing.
void test_a_syn_in_a_synchronized_state_draws_a_challenge_ack_not_a_reset(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 140u, 500u, 100u);
    seg(work_a, 550u, 0u, 1u, 0u, (uint8_t)IDEMIP_TCP_SYN);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_CHALLENGE,
                             "an in-window SYN must draw RFC 5961 sec 4.2's challenge ACK");
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_RST,
                              "RFC 5961 sec 4.2 replaces the RFC 793 reset with a challenge ACK");
    TEST_ASSERT_EQUAL_UINT32(140u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(500u, IO(work_a)->reply.ack);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_ESTABLISHED, (int)IO(work_a)->state);
}

// "irrespective of the sequence number": a SYN outside the window is challenged too.
void test_a_syn_outside_the_window_draws_a_challenge_ack_too(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 140u, 500u, 100u);
    seg(work_a, 9000u, 0u, 1u, 0u, (uint8_t)IDEMIP_TCP_SYN);
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_CHALLENGE);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_ESTABLISHED, (int)IO(work_a)->state);
}

// RFC 9293 sec 3.10.7.4 fourth, SYN-RECEIVED: "If the connection was initiated with a passive OPEN,
// then return this connection to the LISTEN state and return."
void test_a_syn_in_syn_received_from_a_passive_open_returns_to_listen(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_RECEIVED, 300u, 301u, 101u, 4096u);
    IO(work_a)->listener = 0u;
    seg(work_a, 101u, 0u, 1u, 0u, (uint8_t)IDEMIP_TCP_SYN);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_LISTEN, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_LISTEN);
}

// That bullet sits under sec 3.10.7.4 fourth, and sec 3.10.7.4 first stops an unacceptable segment
// before that step is reached: "After sending the acknowledgment, drop the unacceptable segment and
// return." RFC 5961 sec 4.2's "irrespective of the sequence number" is written for the synchronized
// states, which SYN-RECEIVED is not, so a SYN outside the window draws the challenge and leaves the
// half-open connection standing. Without the window test, an off-path attacker who knows only the
// four-tuple tears down a pending passive open with one packet.
void test_a_syn_outside_the_window_does_not_return_syn_received_to_listen(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_RECEIVED, 300u, 301u, 101u, 4096u);
    IO(work_a)->listener = 0u;
    seg(work_a, 90000u, 0u, 1u, 0u, (uint8_t)IDEMIP_TCP_SYN);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->res.acceptable, "the segment under test must be out of window");
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)IDEMIP_TCP_STATE_SYN_RECEIVED, (int)IO(work_a)->state,
                                  "a blind SYN tore down a half-open connection");
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_LISTEN,
                              "a blind SYN returned a passive open to LISTEN");
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_CHALLENGE,
                             "an out-of-window SYN must draw RFC 5961 sec 4.2's challenge ACK");
}

// RFC 5961 sec 7: "in any 5 second window, no more than 10 challenge ACKs should be sent" and "no
// timer is needed to implement the above mechanism, instead a timestamp and a counter can be used."
void test_the_challenge_ack_throttle_bounds_them_per_window(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 140u, 500u, 100u);
    unsigned sent = 0;
    for (unsigned i = 0; i < IDEMIP_TCP_CHALLENGE_ACKS + 4u; i++)
    {
        IO(work_a)->now_ms = 1u;
        seg(work_a, 550u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
        TcpIn.segment(work_a);
        TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_CHALLENGE);
        if (IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK)
        {
            sent++;
        }
        else
        {
            TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_THROTTLED);
        }
    }
    TEST_ASSERT_EQUAL_UINT(IDEMIP_TCP_CHALLENGE_ACKS, sent);

    // The window moves on and the count starts over.
    IO(work_a)->now_ms = 1u + IDEMIP_TCP_CHALLENGE_WINDOW_MS;
    seg(work_a, 550u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK);
    TEST_ASSERT_FALSE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_THROTTLED);
}

// --- RFC 5961 sec 5, the blind data injection attack --------------------------

// RFC 5961 sec 5.2: "The ACK value is considered acceptable only if it is in the range of
// ((SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT). All incoming segments whose ACK value doesn't
// satisfy the above condition MUST be discarded and an ACK sent back."
//
// Remove that range and RFC 793's own rule takes over, under which "the ACK value of any data segment
// is considered valid as long as it does not acknowledge data ahead of the next segment to send"
// (sec 5.1), so an attacker has to guess only the sequence number and the data lands in the window.
void test_an_ack_outside_the_max_snd_wnd_range_is_discarded_and_acknowledged(void)
{
    static const char *why = "RFC 5961 sec 5.2's ACK range must reject an ACK below SND.UNA - MAX.SND.WND";
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100000u, 100000u, 500u, 1000u);
    IO(work_a)->ctl.max_snd_wnd = 4096u;
    seg(work_a, 500u, 100000u - 4097u, 4u, 4u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->res.acceptable);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK, why);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_TEXT, why);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(500u, IO(work_a)->vars.rcv_nxt, why);
}

// The other edge of the same range: an ACK exactly at SND.UNA - MAX.SND.WND is inside it, and the
// segment is processed.
void test_an_ack_inside_the_max_snd_wnd_range_is_processed(void)
{
    static const uint8_t data[4] = {1u, 2u, 3u, 4u};
    (void)data;
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100000u, 100000u, 500u, 1000u);
    IO(work_a)->ctl.max_snd_wnd = 4096u;
    seg(work_a, 500u, 100000u - 4096u, 4u, 4u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_TEXT);
    TEST_ASSERT_EQUAL_UINT32(504u, IO(work_a)->vars.rcv_nxt);
}

// RFC 5961 sec 5.2: "A new state variable MAX.SND.WND is defined as the largest window that the local
// sender has ever received from its peer." It rises with the windows this connection took and never
// falls back.
void test_max_snd_wnd_keeps_the_largest_window_ever_received(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 140u, 500u, 1000u);
    IO(work_a)->ctl.max_snd_wnd = 0u;
    seg(work_a, 500u, 120u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    IO(work_a)->seg.wnd = 8000u;
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_UINT32(8000u, IO(work_a)->ctl.max_snd_wnd);
    TEST_ASSERT_EQUAL_UINT32(8000u, IO(work_a)->vars.snd_wnd);

    seg(work_a, 501u, 130u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    IO(work_a)->seg.wnd = 2000u;
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_UINT32(2000u, IO(work_a)->vars.snd_wnd);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(8000u, IO(work_a)->ctl.max_snd_wnd,
                                     "MAX.SND.WND is the largest window ever received, so it does not fall back");
}

// --- RFC 1337, TIME-WAIT assassination ----------------------------------------

// RFC 1337 sec 3 fix F1: "Ignore RST segments in TIME-WAIT state. If the 2 minute MSL is enforced,
// this fix avoids all three hazards", and sec 4: "of the three fixes described in the previous
// section, fix (F1) ... seems like the best short-term solution."
//
// Remove it and RFC 9293 sec 3.10.7.4 second's TIME-WAIT rule deletes the TCB, which is exactly the
// premature termination RFC 1337 sec 1 names: "TIME-WAIT state can be prematurely terminated
// ('assassinated') by an old duplicate data or ACK segment".
void test_a_reset_in_time_wait_is_ignored_per_rfc_1337_fix_f1(void)
{
    conn(work_a, IDEMIP_TCP_STATE_TIME_WAIT, 101u, 101u, 301u, 4096u);
    seg(work_a, 301u, 101u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)IDEMIP_TCP_STATE_TIME_WAIT, (int)IO(work_a)->state,
                                  "RFC 1337 fix F1 ignores a RST in TIME-WAIT, so the state must not move");
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_DELETE,
                              "RFC 1337 fix F1 must not let a RST delete the TCB in TIME-WAIT");
}

// RFC 1337 Figure 1, the whole assassination, run as the figure prints it. Segments 1 through 5 are
// "copied exactly from Figure 13 of RFC-793"; 5.1 is "any old segment that is unacceptable to TCP A",
// 5.2 is the acknowledgment A sends for it, and 5.3 is the RST that "assassinates the TIME-WAIT state
// at A". With F1 in place the state survives 5.3.
void test_the_time_wait_assassination_of_rfc_1337_figure_1_does_not_fire(void)
{
    // 4. "TIME-WAIT <-- <SEQ=300><ACK=101><CTL=FIN,ACK> <-- LAST-ACK", reached from FIN-WAIT-2.
    conn(work_a, IDEMIP_TCP_STATE_FIN_WAIT_2, 101u, 101u, 300u, 4096u);
    seg(work_a, 300u, 101u, 1u, 0u, (uint8_t)(IDEMIP_TCP_FIN | IDEMIP_TCP_ACK));
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_TIME_WAIT, (int)IO(work_a)->state);
    // 5. "TIME-WAIT --> <SEQ=101><ACK=301><CTL=ACK> --> CLOSED"
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->reply.ack);

    // 5.1 "TIME-WAIT <-- <SEQ=255><ACK=33> ... old duplicate"
    seg(work_a, 255u, 33u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.acceptable);
    // 5.2 "TIME-WAIT --> <SEQ=101><ACK=301><CTL=ACK> --> ????"
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->reply.ack);

    // 5.3 "CLOSED <-- <SEQ=301><CTL=RST> <-- ????  (prematurely)"
    seg(work_a, 301u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)IDEMIP_TCP_STATE_TIME_WAIT, (int)IO(work_a)->state,
                                  "RFC 1337 Figure 1 segment 5.3 must not close TIME-WAIT");
}

// --- RFC 9293 sec 3.10.7.1, the CLOSED state ----------------------------------

// RFC 9293 sec 3.5.1 Figure 10 lines 2 and 3: TCP Peer A rebooted, so "the data arriving at TCP Peer A
// from TCP Peer B (line 2) is unacceptable because no such connection exists, so TCP Peer A sends a
// RST". <SEQ=300><ACK=100><DATA=10><CTL=ACK> is answered with <SEQ=100><CTL=RST>.
void test_the_closed_state_answers_the_segment_of_figure_10_with_a_reset(void)
{
    TcpIn.clear(work_a);
    memset(&IO(work_a)->seg, 0, sizeof IO(work_a)->seg);
    seg(work_a, 300u, 100u, 10u, 10u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.closed(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_RST);
    TEST_ASSERT_EQUAL_UINT32(100u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_RST, IO(work_a)->reply.flags);
}

// "If the ACK bit is off, sequence number zero is used, <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>".
void test_the_closed_state_answers_a_segment_without_an_ack_from_sequence_zero(void)
{
    TcpIn.clear(work_a);
    seg(work_a, 100u, 0u, 1u, 0u, (uint8_t)IDEMIP_TCP_SYN);
    TcpIn.closed(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_RST);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.ack);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)(IDEMIP_TCP_RST | IDEMIP_TCP_ACK), IO(work_a)->reply.flags);
}

// "An incoming segment containing a RST is discarded."
void test_the_closed_state_discards_a_reset(void)
{
    TcpIn.clear(work_a);
    seg(work_a, 300u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.closed(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.act);
}

// --- RFC 9293 sec 3.10.7.2, the LISTEN state ----------------------------------

// RFC 9293 sec 3.5 Figure 6 lines 2 and 3: "<SEQ=100><CTL=SYN>" arrives and "<SEQ=300><ACK=101>
// <CTL=SYN,ACK>" goes back, the listener taking ISS 300.
void test_listen_answers_the_syn_of_figure_6(void)
{
    conn(work_a, IDEMIP_TCP_STATE_LISTEN, 0u, 0u, 0u, 4096u);
    IO(work_a)->vars.iss = 300u;
    seg(work_a, 100u, 0u, 1u, 0u, (uint8_t)IDEMIP_TCP_SYN);
    TcpIn.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_SYN_RECEIVED, (int)IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(100u, IO(work_a)->vars.irs);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->vars.snd_nxt);
    TEST_ASSERT_EQUAL_UINT32(300u, IO(work_a)->vars.snd_una);
    TEST_ASSERT_EQUAL_UINT32(300u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.ack);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK), IO(work_a)->reply.flags);
}

// RFC 9293 sec 3.5.1 Figure 11 lines 3 and 4: a SYN,ACK reaches a socket in LISTEN, and "Any
// acknowledgment is bad if it arrives on a connection still in the LISTEN state. An acceptable reset
// segment should be formed for any arriving ACK-bearing segment ... <SEQ=SEG.ACK><CTL=RST>".
void test_listen_answers_the_acknowledgment_of_figure_11_with_a_reset(void)
{
    conn(work_a, IDEMIP_TCP_STATE_LISTEN, 0u, 0u, 0u, 4096u);
    // Z is the old duplicate's sequence number, so the ACK field is Z+1 and the reset takes it.
    seg(work_a, 5000u, 777u, 1u, 0u, (uint8_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK));
    TcpIn.listen(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_RST);
    TEST_ASSERT_EQUAL_UINT32(777u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_RST, IO(work_a)->reply.flags);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_LISTEN, (int)IO(work_a)->state);
}

// "An incoming RST segment could not be valid since it could not have been sent in response to
// anything sent by this incarnation of the connection. An incoming RST should be ignored."
void test_listen_ignores_a_reset(void)
{
    conn(work_a, IDEMIP_TCP_STATE_LISTEN, 0u, 0u, 0u, 4096u);
    seg(work_a, 5000u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.listen(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.act);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_LISTEN, (int)IO(work_a)->state);
}

// "Fourth, other data or control: This should not be reached. Drop the segment and return."
void test_listen_drops_a_segment_with_neither_syn_nor_ack_nor_rst(void)
{
    conn(work_a, IDEMIP_TCP_STATE_LISTEN, 0u, 0u, 0u, 4096u);
    seg(work_a, 5000u, 0u, 4u, 4u, 0u);
    TcpIn.listen(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.act);
}

// --- RFC 9293 sec 3.10.7.3, the SYN-SENT state --------------------------------

// RFC 9293 sec 3.5 Figure 6 lines 2, 3 and 4: A sent "<SEQ=100><CTL=SYN>", so ISS is 100 and SND.NXT
// 101; "<SEQ=300><ACK=101><CTL=SYN,ACK>" arrives and A answers "<SEQ=101><ACK=301><CTL=ACK>".
void test_syn_sent_reaches_established_on_the_syn_ack_of_figure_6(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_SENT, 100u, 101u, 0u, 4096u);
    IO(work_a)->vars.iss = 100u;
    seg(work_a, 300u, 101u, 1u, 0u, (uint8_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK));
    TcpIn.syn_sent(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_ESTABLISHED, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ESTABLISHED);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(300u, IO(work_a)->vars.irs);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.snd_una);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->reply.ack);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_ACK, IO(work_a)->reply.flags);
}

// RFC 9293 sec 3.5 Figure 8 lines 4 and 5: an old duplicate SYN made B answer "<SEQ=300><ACK=91>
// <CTL=SYN,ACK>", and "TCP Peer A detects that the ACK field is incorrect and returns a RST with its
// SEQ field selected to make the segment believable": "<SEQ=91><CTL=RST>".
void test_syn_sent_resets_the_old_duplicate_of_figure_8(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_SENT, 100u, 101u, 0u, 4096u);
    IO(work_a)->vars.iss = 100u;
    seg(work_a, 300u, 91u, 1u, 0u, (uint8_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK));
    TcpIn.syn_sent(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_RST);
    TEST_ASSERT_EQUAL_UINT32(91u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_RST, IO(work_a)->reply.flags);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_SYN_SENT, (int)IO(work_a)->state);
}

// RFC 9293 sec 3.5 Figure 7 lines 2 and 3, the simultaneous open: A sent "<SEQ=100><CTL=SYN>" and
// "<SEQ=300><CTL=SYN>" arrives carrying no acknowledgment, so A enters SYN-RECEIVED and forms
// "<SEQ=100><ACK=301><CTL=SYN,ACK>".
void test_syn_sent_enters_syn_received_on_the_simultaneous_open_of_figure_7(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_SENT, 100u, 101u, 0u, 4096u);
    IO(work_a)->vars.iss = 100u;
    seg(work_a, 300u, 0u, 1u, 0u, (uint8_t)IDEMIP_TCP_SYN);
    TcpIn.syn_sent(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_SYN_RECEIVED, (int)IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(100u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->reply.ack);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK), IO(work_a)->reply.flags);
}

// "If the ACK was acceptable, then signal to the user 'error: connection reset', drop the segment,
// enter CLOSED state, delete TCB, and return. Otherwise (no ACK), drop the segment and return."
void test_syn_sent_closes_only_on_a_reset_that_acknowledges_the_syn(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_SENT, 100u, 101u, 0u, 4096u);
    IO(work_a)->vars.iss = 100u;
    seg(work_a, 0u, 0u, 0u, 0u, (uint8_t)IDEMIP_TCP_RST);
    TcpIn.syn_sent(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_SYN_SENT, (int)IO(work_a)->state);

    conn(work_a, IDEMIP_TCP_STATE_SYN_SENT, 100u, 101u, 0u, 4096u);
    IO(work_a)->vars.iss = 100u;
    seg(work_a, 0u, 101u, 0u, 0u, (uint8_t)(IDEMIP_TCP_RST | IDEMIP_TCP_ACK));
    TcpIn.syn_sent(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_CLOSED, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_RESET);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_DELETE);
}

// "If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit is set, if so drop the
// segment and return)".
void test_syn_sent_drops_a_reset_with_an_unacceptable_acknowledgment(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_SENT, 100u, 101u, 0u, 4096u);
    IO(work_a)->vars.iss = 100u;
    seg(work_a, 0u, 90u, 0u, 0u, (uint8_t)(IDEMIP_TCP_RST | IDEMIP_TCP_ACK));
    TcpIn.syn_sent(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.act);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_SYN_SENT, (int)IO(work_a)->state);
}

// "Fifth, if neither of the SYN or RST bits is set, then drop the segment and return."
void test_syn_sent_drops_a_segment_with_neither_syn_nor_rst(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_SENT, 100u, 101u, 0u, 4096u);
    IO(work_a)->vars.iss = 100u;
    seg(work_a, 300u, 101u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.syn_sent(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.act);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_SYN_SENT, (int)IO(work_a)->state);
}

// --- RFC 9293 sec 3.10.7.4 fifth, the ACK field -------------------------------

// RFC 9293 sec 3.5 Figure 6 line 4: "<SEQ=101><ACK=301><CTL=ACK>" reaches B in SYN-RECEIVED, whose
// ISS was 300, so "If SND.UNA < SEG.ACK =< SND.NXT, then enter ESTABLISHED state and continue
// processing with the variables below set to: SND.WND <- SEG.WND, SND.WL1 <- SEG.SEQ, SND.WL2 <-
// SEG.ACK".
void test_syn_received_reaches_established_on_the_acknowledgment_of_figure_6(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_RECEIVED, 300u, 301u, 101u, 4096u);
    IO(work_a)->vars.iss = 300u;
    seg(work_a, 101u, 301u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    IO(work_a)->seg.wnd = 8192u;
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_ESTABLISHED, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ESTABLISHED);
    TEST_ASSERT_EQUAL_UINT32(8192u, IO(work_a)->vars.snd_wnd);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.snd_wl1);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->vars.snd_wl2);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->vars.snd_una);
}

// "If the segment acknowledgment is not acceptable, form a reset segment <SEQ=SEG.ACK><CTL=RST> and
// send it."
void test_syn_received_resets_an_unacceptable_acknowledgment(void)
{
    conn(work_a, IDEMIP_TCP_STATE_SYN_RECEIVED, 300u, 301u, 101u, 4096u);
    IO(work_a)->ctl.max_snd_wnd = 65535u;
    seg(work_a, 101u, 250u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_RST);
    TEST_ASSERT_EQUAL_UINT32(250u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_SYN_RECEIVED, (int)IO(work_a)->state);
}

// "If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK."
void test_an_acknowledgment_of_new_data_advances_snd_una(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    seg(work_a, 500u, 160u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACKED);
    TEST_ASSERT_EQUAL_UINT32(60u, IO(work_a)->res.acked);
    TEST_ASSERT_EQUAL_UINT32(160u, IO(work_a)->vars.snd_una);
}

// "If the ACK is a duplicate (SEG.ACK =< SND.UNA), it can be ignored", so SND.UNA does not move and
// processing goes on.
void test_a_duplicate_acknowledgment_is_reported_and_leaves_snd_una_alone(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    seg(work_a, 500u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_DUPACK);
    TEST_ASSERT_FALSE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACKED);
    TEST_ASSERT_EQUAL_UINT32(100u, IO(work_a)->vars.snd_una);
}

// "If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND ...
// The check here prevents using old segments to update the window."
void test_an_old_segment_does_not_update_the_send_window(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    IO(work_a)->vars.snd_wl1 = 600u;
    IO(work_a)->vars.snd_wl2 = 200u;
    IO(work_a)->vars.snd_wnd = 4096u;
    seg(work_a, 550u, 150u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    IO(work_a)->seg.wnd = 99u;
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(4096u, IO(work_a)->vars.snd_wnd, "an old segment must not update SND.WND");
    TEST_ASSERT_FALSE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_WND);

    // The same acknowledgment on a newer SEG.SEQ does update it.
    seg(work_a, 700u, 160u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    IO(work_a)->vars.rcv_wnd = 1000u;
    IO(work_a)->vars.rcv_nxt = 700u;
    IO(work_a)->seg.wnd = 99u;
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_UINT32(99u, IO(work_a)->vars.snd_wnd);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_WND);
}

// "if the ACK bit is off, drop the segment and return"
void test_a_segment_without_an_ack_is_dropped(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    seg(work_a, 500u, 0u, 4u, 4u, 0u);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.act);
    TEST_ASSERT_EQUAL_UINT32(500u, IO(work_a)->vars.rcv_nxt);
}

// --- RFC 9293 sec 3.10.7.4 sixth and seventh ----------------------------------

// "If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and signal the user that the remote side has
// urgent data". sec 3.1 makes the Urgent Pointer "a positive offset from the sequence number in this
// segment".
void test_the_urgent_pointer_advances_rcv_up_and_never_retreats(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    seg(work_a, 500u, 100u, 8u, 8u, (uint8_t)(IDEMIP_TCP_ACK | IDEMIP_TCP_URG));
    IO(work_a)->seg.up = 100u;
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_URGENT);
    TEST_ASSERT_EQUAL_UINT32(600u, IO(work_a)->vars.rcv_up);
    TEST_ASSERT_EQUAL_UINT32(508u, IO(work_a)->vars.rcv_nxt);

    // A later segment whose pointer names an earlier octet, RCV.UP still being in advance of the data
    // consumed. max(RCV.UP,SEG.UP) keeps the one already held.
    seg(work_a, 508u, 100u, 8u, 8u, (uint8_t)(IDEMIP_TCP_ACK | IDEMIP_TCP_URG));
    IO(work_a)->seg.up = 2u;
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(600u, IO(work_a)->vars.rcv_up, "RCV.UP is the max, so it moves forward only");
}

// "Once the TCP endpoint takes responsibility for the data, it advances RCV.NXT over the data
// accepted, and adjusts RCV.WND as appropriate ... The total of RCV.NXT and RCV.WND should not be
// reduced." Then "Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>".
void test_the_segment_text_advances_rcv_nxt_and_draws_an_acknowledgment(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    uint32_t edge = IO(work_a)->vars.rcv_nxt + IO(work_a)->vars.rcv_wnd;
    seg(work_a, 500u, 100u, 40u, 40u, (uint8_t)(IDEMIP_TCP_ACK | IDEMIP_TCP_PSH));
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_TEXT);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_PUSH);
    TEST_ASSERT_EQUAL_UINT16(0u, IO(work_a)->res.text_off);
    TEST_ASSERT_EQUAL_UINT16(40u, IO(work_a)->res.text_len);
    TEST_ASSERT_EQUAL_UINT32(500u, IO(work_a)->res.text_seq);
    TEST_ASSERT_EQUAL_UINT32(540u, IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(960u, IO(work_a)->vars.rcv_wnd);
    TEST_ASSERT_EQUAL_UINT32(edge, IO(work_a)->vars.rcv_nxt + IO(work_a)->vars.rcv_wnd);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK);
    TEST_ASSERT_EQUAL_UINT32(540u, IO(work_a)->reply.ack);
}

// "If a segment's contents straddle the boundary between old and new, only the new parts are
// processed." A segment starting ten octets behind RCV.NXT contributes only what lies past it.
void test_text_straddling_the_left_edge_is_trimmed_to_the_new_part(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    seg(work_a, 490u, 100u, 40u, 40u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_TEXT);
    TEST_ASSERT_EQUAL_UINT16(10u, IO(work_a)->res.text_off);
    TEST_ASSERT_EQUAL_UINT16(30u, IO(work_a)->res.text_len);
    TEST_ASSERT_EQUAL_UINT32(530u, IO(work_a)->vars.rcv_nxt);
}

// "Segments with higher beginning sequence numbers SHOULD be held for later processing (SHLD-31)."
void test_text_beyond_the_left_edge_is_held_and_rcv_nxt_stays_put(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    seg(work_a, 540u, 100u, 40u, 40u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_HOLD);
    TEST_ASSERT_FALSE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_TEXT);
    TEST_ASSERT_EQUAL_UINT32(500u, IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(540u, IO(work_a)->res.text_seq);
    TEST_ASSERT_EQUAL_UINT16(40u, IO(work_a)->res.text_len);
    // "A TCP implementation MAY send an ACK segment acknowledging RCV.NXT when a valid segment arrives
    // that is in the window but not at the left window edge (MAY-13)."
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK);
    TEST_ASSERT_EQUAL_UINT32(500u, IO(work_a)->reply.ack);
}

// The window bounds what is taken: octets past RCV.NXT+RCV.WND are left for later.
void test_text_past_the_right_window_edge_is_left(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 16u);
    seg(work_a, 500u, 100u, 40u, 40u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_UINT16(16u, IO(work_a)->res.text_len);
    TEST_ASSERT_EQUAL_UINT32(516u, IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->vars.rcv_wnd);
}

// --- RFC 9293 sec 3.10.7.4 eighth, the FIN bit --------------------------------

// RFC 9293 sec 3.6 Figure 12 line 2 from the closed-upon side: "<SEQ=100><ACK=300><CTL=FIN,ACK>"
// arrives on an ESTABLISHED connection, "advance RCV.NXT over the FIN, and send an acknowledgment for
// the FIN", and "Enter the CLOSE-WAIT state".
void test_the_fin_of_figure_12_moves_established_to_close_wait(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 300u, 300u, 100u, 4096u);
    seg(work_a, 100u, 300u, 1u, 0u, (uint8_t)(IDEMIP_TCP_FIN | IDEMIP_TCP_ACK));
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_CLOSE_WAIT, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_CLOSING);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.rcv_nxt);
    // 3. "FIN-WAIT-2 <-- <SEQ=300><ACK=101><CTL=ACK> <-- CLOSE-WAIT"
    TEST_ASSERT_EQUAL_UINT32(300u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.ack);
}

// RFC 9293 sec 3.6 Figure 12 line 4 from the closing side: A is in FIN-WAIT-2 and
// "<SEQ=300><ACK=101><CTL=FIN,ACK>"
// arrives, so "Enter the TIME-WAIT state. Start the time-wait timer, turn off the other timers", and
// line 5 sends "<SEQ=101><ACK=301><CTL=ACK>".
void test_the_fin_of_figure_12_moves_fin_wait_2_to_time_wait(void)
{
    conn(work_a, IDEMIP_TCP_STATE_FIN_WAIT_2, 101u, 101u, 300u, 4096u);
    seg(work_a, 300u, 101u, 1u, 0u, (uint8_t)(IDEMIP_TCP_FIN | IDEMIP_TCP_ACK));
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_TIME_WAIT, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_2MSL);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->reply.ack);
}

// RFC 9293 sec 3.6 Figure 12 from the closing side, both segments in order: A sends its FIN (SND.NXT
// 101), line 3's
// bare ACK moves FIN-WAIT-1 to FIN-WAIT-2, and line 4's FIN,ACK moves it to TIME-WAIT.
void test_the_normal_close_of_figure_12_from_the_closing_side(void)
{
    conn(work_a, IDEMIP_TCP_STATE_FIN_WAIT_1, 100u, 101u, 300u, 4096u);
    seg(work_a, 300u, 101u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_FIN_WAIT_2, (int)IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.snd_una);

    seg(work_a, 300u, 101u, 1u, 0u, (uint8_t)(IDEMIP_TCP_FIN | IDEMIP_TCP_ACK));
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_TIME_WAIT, (int)IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->reply.ack);
}

// "FIN-WAIT-1 STATE: If our FIN has been ACKed (perhaps in this segment), then enter TIME-WAIT ...
// otherwise, enter the CLOSING state." RFC 9293 sec 3.6 Figure 13, the simultaneous close: A's FIN is
// not yet acknowledged when B's FIN arrives, so A goes to CLOSING, and line 3's ACK takes it on to
// TIME-WAIT.
void test_the_simultaneous_close_of_figure_13_reaches_time_wait_through_closing(void)
{
    conn(work_a, IDEMIP_TCP_STATE_FIN_WAIT_1, 100u, 101u, 300u, 4096u);
    // 2. "<-- <SEQ=300><ACK=100><CTL=FIN,ACK> <--", which does not acknowledge A's FIN at 100.
    seg(work_a, 300u, 100u, 1u, 0u, (uint8_t)(IDEMIP_TCP_FIN | IDEMIP_TCP_ACK));
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_CLOSING, (int)IO(work_a)->state);
    // 3. "CLOSING --> <SEQ=101><ACK=301><CTL=ACK>"
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->reply.ack);

    // 3. "<-- <SEQ=301><ACK=101><CTL=ACK> <--", which does acknowledge it.
    seg(work_a, 301u, 101u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_TIME_WAIT, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_2MSL);
}

// "LAST-ACK STATE: The only thing that can arrive in this state is an acknowledgment of our FIN. If
// our FIN is now acknowledged, delete the TCB, enter the CLOSED state, and return."
void test_last_ack_deletes_the_tcb_when_its_fin_is_acknowledged(void)
{
    conn(work_a, IDEMIP_TCP_STATE_LAST_ACK, 300u, 301u, 101u, 4096u);
    seg(work_a, 101u, 300u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_LAST_ACK, (int)IO(work_a)->state);
    TEST_ASSERT_FALSE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_DELETE);

    seg(work_a, 101u, 301u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_CLOSED, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_DELETE);
}

// "TIME-WAIT STATE: The only thing that can arrive in this state is a retransmission of the remote
// FIN. Acknowledge it, and restart the 2 MSL timeout." That is the fifth check, so it is reached by a
// segment the first check accepted.
void test_an_acceptable_segment_in_time_wait_restarts_the_2msl(void)
{
    conn(work_a, IDEMIP_TCP_STATE_TIME_WAIT, 101u, 101u, 301u, 4096u);
    seg(work_a, 301u, 101u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.acceptable);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_TIME_WAIT, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_2MSL);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->reply.ack);
}

// The peer's own retransmission of its FIN carries the FIN's sequence number, which RCV.NXT has
// already passed, so the sec 3.4 Table 6 test makes it unacceptable and the first check answers it:
// "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>". That acknowledgment is what brings the peer out of LAST-ACK.
void test_a_retransmitted_fin_in_time_wait_is_out_of_window_and_drawn_an_acknowledgment(void)
{
    conn(work_a, IDEMIP_TCP_STATE_TIME_WAIT, 101u, 101u, 301u, 4096u);
    seg(work_a, 300u, 101u, 1u, 0u, (uint8_t)(IDEMIP_TCP_FIN | IDEMIP_TCP_ACK));
    TcpIn.segment(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.acceptable);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_TIME_WAIT, (int)IO(work_a)->state);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_ACK);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->reply.ack);
}

// "Do not process the FIN if the state is CLOSED, LISTEN, or SYN-SENT since the SEG.SEQ cannot be
// validated", and a segment held for later has octets before the FIN still missing, so its FIN waits
// too.
void test_a_fin_behind_missing_octets_is_not_processed(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    seg(work_a, 540u, 100u, 41u, 40u, (uint8_t)(IDEMIP_TCP_FIN | IDEMIP_TCP_ACK));
    TcpIn.segment(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_HOLD);
    TEST_ASSERT_FALSE(IO(work_a)->res.act & IDEMIP_TCP_IN_ACT_CLOSING);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATE_ESTABLISHED, (int)IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(500u, IO(work_a)->vars.rcv_nxt);
}

// --- what the entries refuse --------------------------------------------------

// sec 3.10.7.4 covers SYN-RECEIVED through TIME-WAIT; sec 3.10.7.1, sec 3.10.7.2 and sec 3.10.7.3
// hold the other three states, so segment refuses them rather than guessing.
void test_segment_refuses_the_three_states_the_other_sections_hold(void)
{
    conn(work_a, IDEMIP_TCP_STATE_CLOSED, 100u, 100u, 500u, 100u);
    seg(work_a, 500u, 100u, 0u, 0u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->state = IDEMIP_TCP_STATE_LISTEN;
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->state = IDEMIP_TCP_STATE_SYN_SENT;
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->state = (IdemIpTcpState)((int)IDEMIP_TCP_STATE_TIME_WAIT + 1);
    TcpIn.segment(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// listen and syn_sent each hold one state and refuse every other.
void test_listen_and_syn_sent_each_hold_one_state(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 100u, 500u, 100u);
    TcpIn.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TcpIn.syn_sent(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->state = IDEMIP_TCP_STATE_LISTEN;
    TcpIn.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TcpIn.syn_sent(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->state = IDEMIP_TCP_STATE_SYN_SENT;
    TcpIn.syn_sent(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// A parse that names no address family reads nothing: no later call turns 5 into a pseudo-header.
void test_parse_refuses_a_version_that_names_no_pseudo_header(void)
{
    TcpIn.clear(work_a);
    uint16_t total = wire(100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 4096u, NULL, 0u, NULL, 0u);
    aim_parse(work_a, total, 0u);
    IO(work_a)->parse_args.ip_version = 5u;
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->parse_args.ip_version = 4u;
    IO(work_a)->parse_args.seg = NULL;
    TcpIn.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// An entry is a function of its borrow alone, so the same segment on the same variables decides the
// same way however often it is run. The throttle counter is the one thing a repeat moves, and it is
// in the borrow, so a fresh borrow repeats exactly.
void test_the_same_segment_on_the_same_variables_decides_the_same_way(void)
{
    conn(work_a, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    seg(work_a, 500u, 160u, 40u, 40u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_a);
    uint32_t act = IO(work_a)->res.act;
    uint32_t nxt = IO(work_a)->vars.rcv_nxt;
    uint32_t una = IO(work_a)->vars.snd_una;

    conn(work_b, IDEMIP_TCP_STATE_ESTABLISHED, 100u, 200u, 500u, 1000u);
    seg(work_b, 500u, 160u, 40u, 40u, (uint8_t)IDEMIP_TCP_ACK);
    TcpIn.segment(work_b);
    TEST_ASSERT_EQUAL_UINT32(act, IO(work_b)->res.act);
    TEST_ASSERT_EQUAL_UINT32(nxt, IO(work_b)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(una, IO(work_b)->vars.snd_una);
}
