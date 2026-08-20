// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for the send path: the RFC 9293 sec 3.1 build, the sec 3.8.6.2.1 sender's algorithm with
// the sec 3.7.4 Nagle condition, the RFC 6298 retransmission timer, and the RFC 5681 congestion
// window with RFC 3465 byte counting.
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a built segment is read back with tcp_in's parse, so the two halves agree on the wire form
//   5. the RFC's own numbers are the vectors, quoted where they are used
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ip/ipv6.h"
#include "src/tcp/tcp_in.h"
#include "src/tcp/tcp_out.h"

#include <string.h>
#include <unity.h>

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_TCP_OUT_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_TCP_OUT_BORROW + 16];
static _Alignas(8) uint8_t work_in[IDEMIP_TCP_IN_BORROW];

#define IO(w) IDEMIP_TCP_OUT_IO(w)

static uint8_t g_buf[256];

static const uint8_t g_local[IDEMIP_TCP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 1u};
static const uint8_t g_remote[IDEMIP_TCP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 9u};
static const uint8_t g_local6[IDEMIP_TCP_PCB_ADDR_BYTES] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0u, 0u, 0u, 0u,
                                                            0u,    0u,    0u,    0u,    0u, 0u, 0u, 1u};
static const uint8_t g_remote6[IDEMIP_TCP_PCB_ADDR_BYTES] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0u, 0u, 0u, 0u,
                                                             0u,    0u,    0u,    0u,    0u, 0u, 0u, 2u};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_TCP_OUT_BORROW, CANARY, cap - IDEMIP_TCP_OUT_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_TCP_OUT_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_TCP_OUT_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_buf, 0xEE, sizeof g_buf);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

static void call_every_entry(uint8_t *w)
{
    TcpOut.build(w);
    TcpOut.send(w);
    TcpOut.ack(w);
    TcpOut.rst(w);
    TcpOut.rtt(w);
    TcpOut.rtx_arm(w);
    TcpOut.rtx_stop(w);
    TcpOut.rtx_restart(w);
    TcpOut.rtx_expire(w);
    TcpOut.cc_init(w);
    TcpOut.cc_ack(w);
    TcpOut.cc_dupack(w);
    TcpOut.cc_recover(w);
}

// Every entry, with the status read between each pair. One read after the whole run would only ever
// observe the last call's, so a regression in any of the other twelve would pass unnoticed.
#define REFUSED(call, name)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        call;                                                                                                          \
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(w)->status, name);                                                \
    } while (0)

static void every_entry_is_refused(uint8_t *w)
{
    REFUSED(TcpOut.build(w), "build");
    REFUSED(TcpOut.send(w), "send");
    REFUSED(TcpOut.ack(w), "ack");
    REFUSED(TcpOut.rst(w), "rst");
    REFUSED(TcpOut.rtt(w), "rtt");
    REFUSED(TcpOut.rtx_arm(w), "rtx_arm");
    REFUSED(TcpOut.rtx_stop(w), "rtx_stop");
    REFUSED(TcpOut.rtx_restart(w), "rtx_restart");
    REFUSED(TcpOut.rtx_expire(w), "rtx_expire");
    REFUSED(TcpOut.cc_init(w), "cc_init");
    REFUSED(TcpOut.cc_ack(w), "cc_ack");
    REFUSED(TcpOut.cc_dupack(w), "cc_dupack");
    REFUSED(TcpOut.cc_recover(w), "cc_recover");
}

// A build aimed at the suite's buffer over IPv4, with nothing optional set.
static void aim_build(uint8_t *w, uint32_t seq, uint32_t ack, uint8_t flags, uint16_t len, const uint8_t *data)
{
    TcpOut.clear(w);
    memset(&IO(w)->build_args, 0, sizeof IO(w)->build_args);
    memset(&IO(w)->ctl, 0, sizeof IO(w)->ctl);
    IO(w)->build_args.buf = g_buf;
    IO(w)->build_args.cap = (uint16_t)sizeof g_buf;
    IO(w)->build_args.local_ip = g_local;
    IO(w)->build_args.remote_ip = g_remote;
    IO(w)->build_args.local_port = 40000u;
    IO(w)->build_args.remote_port = 80u;
    IO(w)->build_args.seq = seq;
    IO(w)->build_args.ack = ack;
    IO(w)->build_args.flags = flags;
    IO(w)->build_args.len = len;
    IO(w)->build_args.data = data;
    IO(w)->build_args.wnd = 4096u;
    IO(w)->build_args.ip_version = 4u;
}

// One connection's variables, for the send rule and the congestion entries.
static void conn(uint8_t *w, uint32_t una, uint32_t nxt, uint32_t snd_wnd)
{
    TcpOut.clear(w);
    memset(&IO(w)->vars, 0, sizeof IO(w)->vars);
    memset(&IO(w)->ctl, 0, sizeof IO(w)->ctl);
    memset(&IO(w)->send_args, 0, sizeof IO(w)->send_args);
    memset(&IO(w)->timer_args, 0, sizeof IO(w)->timer_args);
    IO(w)->vars.snd_una = una;
    IO(w)->vars.snd_nxt = nxt;
    IO(w)->vars.snd_wnd = snd_wnd;
    IO(w)->ctl.cwnd = 0xFFFFFFFFu; // out of the way unless a case sets it
    IO(w)->state = IDEMIP_TCP_STATE_ESTABLISHED;
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    TcpOut.clear(NULL);
    call_every_entry(NULL);
    TEST_PASS();
}

// The map is public, so a reader can place both regions without opening the .c.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_TCP_OUT_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(sizeof(TcpOutIo), (size_t)IDEMIP_TCP_OUT_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_TCP_OUT_OFF_CTX < (size_t)IDEMIP_TCP_OUT_BORROW,
                             "the context starts past IDEMIP_TCP_OUT_BORROW");
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_TCP_OUT_OFF_IO, IO(work_a));
}

// Zeroed, never cleared: every entry must refuse rather than run on a context that was never marked.
void test_an_uncleared_borrow_is_refused(void)
{
    IO(work_a)->build_args.buf = g_buf;
    IO(work_a)->build_args.cap = (uint16_t)sizeof g_buf;
    IO(work_a)->build_args.local_ip = g_local;
    IO(work_a)->build_args.remote_ip = g_remote;
    IO(work_a)->build_args.ip_version = 4u;
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->timer_args.smss = 536u;
    IO(work_a)->timer_args.sample_ms = 100u;
    every_entry_is_refused(work_a);
}

// An entry is a function of its borrow alone, so the same call on the same bytes repeats.
void test_clear_repeats(void)
{
    TcpOut.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint8_t first[IDEMIP_TCP_OUT_BORROW];
    memcpy(first, work_a, sizeof first);
    TcpOut.clear(work_a);
    TEST_ASSERT_EQUAL_MEMORY(first, work_a, sizeof first);
}

// The borrow IS the instance, so a call on one leaves the other untouched.
void test_two_borrows_share_no_byte(void)
{
    TcpOut.clear(work_a);
    uint8_t before[IDEMIP_TCP_OUT_BORROW];
    memcpy(before, work_b, sizeof before);
    aim_build(work_a, 100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 0u, NULL);
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_MEMORY(before, work_b, sizeof before);
}

// --- the build (RFC 9293 sec 3.1, sec 3.2) ------------------------------------

// RFC 9293 sec 3.5 Figure 6 line 4: "<SEQ=101><ACK=301><CTL=ACK>". The built segment is read back
// through tcp_in's parse, so the two halves agree on the wire form and the checksum checks out.
void test_a_built_segment_reads_back_through_the_parse(void)
{
    static const uint8_t data[8] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u};
    aim_build(work_a, 101u, 301u, (uint8_t)(IDEMIP_TCP_ACK | IDEMIP_TCP_PSH), 8u, data);
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_HDR_LEN, IO(work_a)->res.hdr_len);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)(IDEMIP_TCP_HDR_LEN + 8u), IO(work_a)->res.built);

    TcpIn.clear(work_in);
    IDEMIP_TCP_IN_IO(work_in)->parse_args.seg = g_buf;
    IDEMIP_TCP_IN_IO(work_in)->parse_args.local_ip = g_remote; // the receiver's local is our remote
    IDEMIP_TCP_IN_IO(work_in)->parse_args.remote_ip = g_local;
    IDEMIP_TCP_IN_IO(work_in)->parse_args.len = IO(work_a)->res.built;
    IDEMIP_TCP_IN_IO(work_in)->parse_args.ip_version = 4u;
    IDEMIP_TCP_IN_IO(work_in)->parse_args.snd_scale = 0u;
    TcpIn.parse(work_in);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_IN_IO(work_in)->status);
    TEST_ASSERT_EQUAL_UINT32(101u, IDEMIP_TCP_IN_IO(work_in)->seg.seq);
    TEST_ASSERT_EQUAL_UINT32(301u, IDEMIP_TCP_IN_IO(work_in)->seg.ack);
    TEST_ASSERT_EQUAL_UINT32(8u, IDEMIP_TCP_IN_IO(work_in)->seg.len);
    TEST_ASSERT_EQUAL_UINT32(4096u, IDEMIP_TCP_IN_IO(work_in)->seg.wnd);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)(IDEMIP_TCP_ACK | IDEMIP_TCP_PSH), IDEMIP_TCP_IN_IO(work_in)->seg.flags);
    TEST_ASSERT_EQUAL_MEMORY(data, g_buf + IDEMIP_TCP_HDR_LEN, 8u);
    TEST_ASSERT_EQUAL_UINT16(40000u, idemip_tcp_src_port(g_buf));
    TEST_ASSERT_EQUAL_UINT16(80u, idemip_tcp_dst_port(g_buf));
}

// RFC 9293 sec 3.1: Data Offset is "The number of 32-bit words in the TCP header", and Reserved "Must
// be zero in generated segments".
void test_the_data_offset_counts_the_header_words_and_reserved_is_zero(void)
{
    aim_build(work_a, 100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 0u, NULL);
    IO(work_a)->build_args.opts = (uint16_t)(IDEMIP_TCP_OUT_OPT_MSS | IDEMIP_TCP_OUT_OPT_WS);
    IO(work_a)->build_args.mss = 1460u;
    IO(work_a)->build_args.ws = 7u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    // kind 2 is four octets, one NOP and kind 3 are four more, so the header is seven words.
    TEST_ASSERT_EQUAL_UINT16(28u, IO(work_a)->res.hdr_len);
    TEST_ASSERT_EQUAL_UINT8(7u, idemip_tcp_doff(g_buf));
    TEST_ASSERT_EQUAL_UINT16(0u, (uint16_t)(idemip_rd16(g_buf + IDEMIP_TCP_OFF_OFFS_FLAGS) & IDEMIP_TCP_RSRVD_MASK));
}

// RFC 9293 sec 3.2's kind 2, RFC 7323 sec 2.2's kind 3 and sec 3.2's kind 8, and RFC 2018 sec 2's
// kind 4, all read back by the walk tcp.h publishes.
void test_the_options_a_syn_carries_read_back(void)
{
    aim_build(work_a, 100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 0u, NULL);
    IO(work_a)->build_args.opts = (uint16_t)(IDEMIP_TCP_OUT_OPT_MSS | IDEMIP_TCP_OUT_OPT_WS | IDEMIP_TCP_OUT_OPT_TS |
                                             IDEMIP_TCP_OUT_OPT_SACK_PERM);
    IO(work_a)->build_args.mss = 1460u;
    IO(work_a)->build_args.ws = 7u;
    IO(work_a)->build_args.tsval = 0x11223344u;
    IO(work_a)->build_args.tsecr = 0x55667788u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    int saw_mss = 0, saw_ws = 0, saw_ts = 0, saw_perm = 0;
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, g_buf);
    while (idemip_tcp_opt_next(&w))
    {
        if (w.kind == IDEMIP_TCP_OPT_MSS)
        {
            saw_mss = 1;
            TEST_ASSERT_EQUAL_UINT16(1460u, idemip_tcp_opt_mss(w.opt));
        }
        else if (w.kind == IDEMIP_TCP_OPT_WS)
        {
            saw_ws = 1;
            TEST_ASSERT_EQUAL_UINT8(7u, idemip_tcp_opt_ws(w.opt));
        }
        else if (w.kind == IDEMIP_TCP_OPT_TS)
        {
            saw_ts = 1;
            TEST_ASSERT_EQUAL_UINT32(0x11223344u, idemip_tcp_opt_tsval(w.opt));
            // RFC 7323 sec 3.2: "If the ACK bit is not set in the outgoing TCP header, the sender of
            // that segment SHOULD set the TSecr field to zero." This segment is a SYN with no ACK.
            TEST_ASSERT_EQUAL_UINT32(0u, idemip_tcp_opt_tsecr(w.opt));
        }
        else if (w.kind == IDEMIP_TCP_OPT_SACK_PERM)
        {
            saw_perm = 1;
        }
    }
    TEST_ASSERT_FALSE(w.bad);
    TEST_ASSERT_TRUE(saw_mss && saw_ws && saw_ts && saw_perm);
}

// RFC 9293 sec 3.2 (MUST-65) puts kind 2 "in segments with the SYN control bit set" and "MUST NOT be
// sent in other segments"; RFC 2018 sec 2 says kind 4 "MUST NOT be sent on non-SYN segments"; RFC
// 7323 sec 2.2 puts kind 3 in a <SYN>. A segment without SYN carries none of the three.
void test_the_syn_only_options_are_left_off_a_segment_without_syn(void)
{
    aim_build(work_a, 100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 0u, NULL);
    IO(work_a)->build_args.opts = (uint16_t)(IDEMIP_TCP_OUT_OPT_MSS | IDEMIP_TCP_OUT_OPT_WS | IDEMIP_TCP_OUT_OPT_TS |
                                             IDEMIP_TCP_OUT_OPT_SACK_PERM);
    IO(work_a)->build_args.mss = 1460u;
    IO(work_a)->build_args.ws = 7u;
    IO(work_a)->build_args.tsval = 0x11223344u;
    IO(work_a)->build_args.tsecr = 0x55667788u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    int saw_ts = 0;
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, g_buf);
    while (idemip_tcp_opt_next(&w))
    {
        TEST_ASSERT_NOT_EQUAL_UINT8(IDEMIP_TCP_OPT_MSS, w.kind);
        TEST_ASSERT_NOT_EQUAL_UINT8(IDEMIP_TCP_OPT_WS, w.kind);
        TEST_ASSERT_NOT_EQUAL_UINT8(IDEMIP_TCP_OPT_SACK_PERM, w.kind);
        if (w.kind == IDEMIP_TCP_OPT_TS)
        {
            saw_ts = 1;
            TEST_ASSERT_EQUAL_UINT32(0x11223344u, idemip_tcp_opt_tsval(w.opt));
            // The ACK bit is set here, so RFC 7323 sec 3.2 makes TSecr valid and it carries the echo.
            TEST_ASSERT_EQUAL_UINT32(0x55667788u, idemip_tcp_opt_tsecr(w.opt));
        }
    }
    TEST_ASSERT_FALSE(w.bad);
    // sec 3.2: "Once TSopt has been successfully negotiated ... the TSopt MUST be sent in every
    // non-<RST> segment for the duration of the connection", which is the steady-state segment.
    TEST_ASSERT_TRUE_MESSAGE(saw_ts, "kind 8 is absent from a non-SYN segment that asked for it");
}

// RFC 9293 sec 3.1: "The TCP header (even one including options) is an integer multiple of 32 bits
// long", and MUST-69: "The content of the header beyond the End of Option List Option MUST be header
// padding of zeros."
void test_the_options_are_padded_to_a_word_with_zeros(void)
{
    aim_build(work_a, 100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 0u, NULL);
    IO(work_a)->build_args.opts = (uint16_t)IDEMIP_TCP_OUT_OPT_SACK_PERM;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    // Two octets of option in a four-octet word: the two behind them are zeros.
    TEST_ASSERT_EQUAL_UINT16(24u, IO(work_a)->res.hdr_len);
    TEST_ASSERT_EQUAL_UINT8(0u, g_buf[IDEMIP_TCP_OFF_OPTIONS + 2u]);
    TEST_ASSERT_EQUAL_UINT8(0u, g_buf[IDEMIP_TCP_OFF_OPTIONS + 3u]);
    TEST_ASSERT_EQUAL_UINT16(0u, (uint16_t)(IO(work_a)->res.hdr_len & 3u));
}

// RFC 2018 sec 3: "A SACK option that specifies n blocks will have a length of 8*n+2 bytes", each
// block "the first sequence number of this block" and "the sequence number immediately following the
// last sequence number of this block".
void test_the_sack_option_carries_the_blocks_the_control_state_holds(void)
{
    aim_build(work_a, 100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 0u, NULL);
    IO(work_a)->build_args.opts = (uint16_t)IDEMIP_TCP_OUT_OPT_SACK;
    IO(work_a)->build_args.sack_blocks = 2u;
    IO(work_a)->ctl.sack_left[0] = 1000u;
    IO(work_a)->ctl.sack_right[0] = 1500u;
    IO(work_a)->ctl.sack_left[1] = 2000u;
    IO(work_a)->ctl.sack_right[1] = 2500u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    int saw = 0;
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, g_buf);
    while (idemip_tcp_opt_next(&w))
    {
        if (w.kind == IDEMIP_TCP_OPT_SACK)
        {
            saw = 1;
            TEST_ASSERT_EQUAL_UINT8(18u, w.len); // 8*2+2
            TEST_ASSERT_EQUAL_UINT8(2u, idemip_tcp_opt_sack_blocks(w.opt));
            TEST_ASSERT_EQUAL_UINT32(1000u, idemip_tcp_opt_sack_left(w.opt, 0u));
            TEST_ASSERT_EQUAL_UINT32(1500u, idemip_tcp_opt_sack_right(w.opt, 0u));
            TEST_ASSERT_EQUAL_UINT32(2000u, idemip_tcp_opt_sack_left(w.opt, 1u));
            TEST_ASSERT_EQUAL_UINT32(2500u, idemip_tcp_opt_sack_right(w.opt, 1u));
        }
    }
    TEST_ASSERT_TRUE(saw);
    TEST_ASSERT_FALSE(w.bad);

    // RFC 2018 sec 3: "the 40 bytes available for TCP options can specify a maximum of 4 blocks."
    IO(work_a)->build_args.sack_blocks = (uint8_t)(IDEMIP_TCP_SACK_BLOCKS_MAX + 1u);
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// RFC 7323 sec 2.3: "The window field (SEG.WND) of every outgoing segment, with the exception of
// <SYN> segments, MUST be right-shifted by Rcv.Wind.Shift bits: SEG.WND = RCV.WND >> Rcv.Wind.Shift"
void test_the_window_field_is_shifted_on_every_segment_but_a_syn(void)
{
    aim_build(work_a, 100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 0u, NULL);
    IO(work_a)->build_args.wnd = 128000u;
    IO(work_a)->build_args.rcv_scale = 7u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)(128000u >> 7), idemip_tcp_window(g_buf));

    aim_build(work_a, 100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 0u, NULL);
    IO(work_a)->build_args.wnd = 60000u;
    IO(work_a)->build_args.rcv_scale = 7u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_UINT16(60000u, idemip_tcp_window(g_buf));

    // A window past what the 16-bit field holds is written as the largest it holds.
    aim_build(work_a, 100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 0u, NULL);
    IO(work_a)->build_args.wnd = 200000u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_UINT16(0xFFFFu, idemip_tcp_window(g_buf));
}

// The Acknowledgment Number and the Urgent Pointer are "significant only when" their control bit is
// set (RFC 9293 sec 3.1), so a segment carrying neither sends zeros.
void test_the_acknowledgment_and_urgent_fields_go_out_zero_without_their_bits(void)
{
    aim_build(work_a, 100u, 999u, (uint8_t)IDEMIP_TCP_SYN, 0u, NULL);
    IO(work_a)->build_args.up = 42u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, idemip_tcp_ack(g_buf));
    TEST_ASSERT_EQUAL_UINT16(0u, idemip_tcp_urgent(g_buf));

    aim_build(work_a, 100u, 999u, (uint8_t)(IDEMIP_TCP_ACK | IDEMIP_TCP_URG), 0u, NULL);
    IO(work_a)->build_args.up = 42u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_UINT32(999u, idemip_tcp_ack(g_buf));
    TEST_ASSERT_EQUAL_UINT16(42u, idemip_tcp_urgent(g_buf));
}

// RFC 8200 sec 8.1's pseudo-header, "the two 128-bit addresses, a 32-bit Upper-Layer Packet Length,
// twenty-four zero bits, and the Next Header". A span that already carries its checksum sums to all
// ones, whose complement is zero.
void test_a_built_ipv6_segment_checks_out_against_the_rfc_8200_pseudo_header(void)
{
    static const uint8_t data[4] = {9u, 8u, 7u, 6u};
    aim_build(work_a, 100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 4u, data);
    IO(work_a)->build_args.local_ip = g_local6;
    IO(work_a)->build_args.remote_ip = g_remote6;
    IO(work_a)->build_args.ip_version = 6u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint32_t sum = idemip_ip6_pseudo_accum(0u, g_local6, g_remote6, (uint32_t)IO(work_a)->res.built,
                                           (uint8_t)IDEMIP_IP6_NH_TCP);
    TEST_ASSERT_EQUAL_UINT16(0u, idemip_cksum_final(idemip_cksum_accum(sum, g_buf, IO(work_a)->res.built)));
}

// A buffer that cannot hold the segment, a segment with octets that names none, and a version that
// names no pseudo-header are each ERR: no later call changes any of them.
void test_the_build_refuses_what_no_retry_fixes(void)
{
    static const uint8_t data[8] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u};
    aim_build(work_a, 100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 8u, data);
    IO(work_a)->build_args.cap = (uint16_t)(IDEMIP_TCP_HDR_LEN + 7u);
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IO(work_a)->res.built);

    aim_build(work_a, 100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 8u, NULL);
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    aim_build(work_a, 100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 0u, data);
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    aim_build(work_a, 100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 0u, NULL);
    IO(work_a)->build_args.ip_version = 5u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    aim_build(work_a, 100u, 300u, (uint8_t)IDEMIP_TCP_ACK, 0u, NULL);
    IO(work_a)->build_args.buf = NULL;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// --- the sender's algorithm (RFC 9293 sec 3.8.6.2.1, sec 3.7.4) ---------------

// "The 'usable window' is: U = SND.UNA + SND.WND - SND.NXT, i.e., the offered window less the amount
// of data sent but not acknowledged."
void test_the_usable_window_is_the_offered_window_less_what_is_in_flight(void)
{
    conn(work_a, 1000u, 1400u, 2000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->send_args.queued = 0u;
    TcpOut.send(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(1600u, IO(work_a)->res.usable);

    // SND.NXT past the right edge of the offered window leaves none of it usable.
    conn(work_a, 1000u, 3200u, 2000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    TcpOut.send(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.usable);
}

// Rule (1): "if a maximum-sized segment can be sent, i.e., if: min(D,U) >= Eff.snd.MSS". Nagle does
// not gate this one, so it fires with data still unacknowledged.
void test_rule_1_sends_a_maximum_sized_segment_even_with_data_unacknowledged(void)
{
    conn(work_a, 1000u, 1400u, 4000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->send_args.queued = 2000u;
    TcpOut.send(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.send_now);
    TEST_ASSERT_EQUAL_UINT32(536u, IO(work_a)->res.send_len);
}

// RFC 9293 sec 3.7.4: "If there is unacknowledged data (i.e., SND.NXT > SND.UNA), then the sending TCP
// endpoint buffers all user data (regardless of the PSH bit) until the outstanding data has been
// acknowledged or until the TCP endpoint can send a full-sized segment (Eff.snd.MSS bytes)." That is
// the bracketed "[SND.NXT = SND.UNA and]" on rules (2) and (3).
void test_nagle_holds_a_short_pushed_segment_while_data_is_unacknowledged(void)
{
    conn(work_a, 1000u, 1400u, 4000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->send_args.queued = 20u;
    IO(work_a)->send_args.push = IDEMIP_TRUE;
    IO(work_a)->ctl.max_snd_wnd = 4000u;
    TcpOut.send(work_a);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->res.send_now, "Nagle buffers short data while SND.NXT > SND.UNA");

    // With nothing outstanding, rule (2) fires: "PUSHed and D <= U".
    conn(work_a, 1400u, 1400u, 4000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->send_args.queued = 20u;
    IO(work_a)->send_args.push = IDEMIP_TRUE;
    IO(work_a)->ctl.max_snd_wnd = 4000u;
    TcpOut.send(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.send_now);
    TEST_ASSERT_EQUAL_UINT32(20u, IO(work_a)->res.send_len);
}

// RFC 9293 sec 3.7.4 (MUST-17): "there MUST be a way for an application to disable the Nagle
// algorithm on an individual connection."
void test_nagle_can_be_disabled_on_the_connection(void)
{
    conn(work_a, 1000u, 1400u, 4000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->send_args.queued = 20u;
    IO(work_a)->send_args.push = IDEMIP_TRUE;
    IO(work_a)->send_args.nodelay = IDEMIP_TRUE;
    TcpOut.send(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.send_now);
    TEST_ASSERT_EQUAL_UINT32(20u, IO(work_a)->res.send_len);
}

// Rule (3): "or if at least a fraction Fs of the maximum window can be sent, i.e., if: [SND.NXT =
// SND.UNA and] min(D,U) >= Fs * Max(SND.WND)", Fs "a fraction whose recommended value is 1/2".
void test_rule_3_sends_at_half_the_largest_window_ever_seen(void)
{
    // Below Eff.snd.MSS throughout, so rule (1) never fires and only rule (3) can.
    conn(work_a, 1000u, 1000u, 4000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->ctl.max_snd_wnd = 800u;
    IO(work_a)->send_args.queued = 399u; // one short of half of 800
    TcpOut.send(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.send_now);

    IO(work_a)->send_args.queued = 400u;
    TcpOut.send(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.send_now);
    TEST_ASSERT_EQUAL_UINT32(400u, IO(work_a)->res.send_len);

    // The same 400 octets with data outstanding: sec 3.7.4's bracketed condition holds them.
    conn(work_a, 1000u, 1400u, 4000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->ctl.max_snd_wnd = 800u;
    IO(work_a)->send_args.queued = 400u;
    TcpOut.send(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.send_now);
}

// Rule (4): "or if the override timeout occurs", which sec 3.8.6.2.1 says is "necessary to have ...
// to force transmission of data, overriding the SWS avoidance algorithm."
void test_rule_4_the_override_timeout_sends_what_is_there(void)
{
    conn(work_a, 1000u, 1400u, 4000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->ctl.max_snd_wnd = 4000u;
    IO(work_a)->send_args.queued = 10u;
    TcpOut.send(work_a);
    TEST_ASSERT_FALSE(IO(work_a)->res.send_now);

    IO(work_a)->send_args.force = IDEMIP_TRUE;
    TcpOut.send(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.send_now);
    TEST_ASSERT_EQUAL_UINT32(10u, IO(work_a)->res.send_len);
}

// RFC 5681 sec 3.1: "The minimum of cwnd and rwnd governs data transmission", and RFC 9293 sec 3.7.4:
// "In all cases, sending data is also subject to the limitation imposed by the slow start algorithm".
void test_the_congestion_window_holds_the_usable_window_down(void)
{
    conn(work_a, 1000u, 1400u, 8000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->send_args.queued = 8000u;
    IO(work_a)->ctl.cwnd = 1000u; // 400 of it already in flight
    TcpOut.send(work_a);
    TEST_ASSERT_EQUAL_UINT32(600u, IO(work_a)->res.usable);
    TEST_ASSERT_TRUE(IO(work_a)->res.send_now);
    TEST_ASSERT_EQUAL_UINT32(536u, IO(work_a)->res.send_len);

    // A congestion window already filled leaves nothing usable at all.
    IO(work_a)->ctl.cwnd = 400u;
    TcpOut.send(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.usable);
    TEST_ASSERT_FALSE(IO(work_a)->res.send_now);
}

// A zero offered window sends nothing: RFC 9293 sec 3.8.6.1's zero-window probe is a separate path.
void test_a_zero_offered_window_sends_nothing(void)
{
    conn(work_a, 1000u, 1000u, 0u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->send_args.queued = 4000u;
    IO(work_a)->send_args.push = IDEMIP_TRUE;
    IO(work_a)->send_args.force = IDEMIP_TRUE;
    TcpOut.send(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.usable);
    TEST_ASSERT_FALSE(IO(work_a)->res.send_now);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->res.send_len);
}

// A send with no maximum segment size names no segment at all, and no retry changes that.
void test_send_refuses_a_zero_maximum_segment_size(void)
{
    conn(work_a, 1000u, 1000u, 4000u);
    IO(work_a)->send_args.eff_snd_mss = 0u;
    TcpOut.send(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// --- the retransmission timer (RFC 6298) --------------------------------------

// RFC 6298 (2.2): "When the first RTT measurement R is made, the host MUST set SRTT <- R,
// RTTVAR <- R/2, RTO <- SRTT + max (G, K*RTTVAR) where K = 4."
void test_the_first_measurement_takes_rule_2_2(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->timer_args.sample_ms = 1600u;
    TcpOut.rtt(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(1600u, IO(work_a)->ctl.srtt);
    TEST_ASSERT_EQUAL_UINT32(800u, IO(work_a)->ctl.rttvar);
    TEST_ASSERT_EQUAL_UINT32(1600u + (800u * 4u), IO(work_a)->ctl.rto);
}

// RFC 6298 (2.3): "RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|" then "SRTT <- (1 - alpha) *
// SRTT + alpha * R'", "computed using alpha=1/8 and beta=1/4", and in that order.
void test_a_later_measurement_takes_rule_2_3_in_the_stated_order(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->timer_args.sample_ms = 1600u;
    TcpOut.rtt(work_a);
    // SRTT 1600, RTTVAR 800. A second sample of 2400: |1600-2400| = 800.
    // RTTVAR <- 800 - 200 + 200 = 800; SRTT <- 1600 - 200 + 300 = 1700.
    IO(work_a)->timer_args.sample_ms = 2400u;
    TcpOut.rtt(work_a);
    TEST_ASSERT_EQUAL_UINT32(800u, IO(work_a)->ctl.rttvar);
    TEST_ASSERT_EQUAL_UINT32(1700u, IO(work_a)->ctl.srtt);
    TEST_ASSERT_EQUAL_UINT32(1700u + (800u * 4u), IO(work_a)->ctl.rto);
}

// RFC 6298 (2.4): "Whenever RTO is computed, if it is less than 1 second, then the RTO SHOULD be
// rounded up to 1 second", and (2.5): "A maximum value MAY be placed on RTO provided it is at least
// 60 seconds."
void test_the_rto_is_floored_at_a_second_and_capped_at_the_maximum(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->timer_args.sample_ms = 4u;
    TcpOut.rtt(work_a);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_TCP_RTO_MIN_MS, IO(work_a)->ctl.rto);

    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->timer_args.sample_ms = 400000u;
    TcpOut.rtt(work_a);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_TCP_RTO_MAX_MS, IO(work_a)->ctl.rto);
}

// RFC 6298 sec 4: "if the K*RTTVAR term in the RTO calculation equals zero, the variance term MUST be
// rounded to G seconds."
void test_a_zero_variance_term_is_rounded_to_the_clock_granularity(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.srtt = 40000u;
    IO(work_a)->ctl.rttvar = 0u;
    IO(work_a)->timer_args.sample_ms = 40000u; // |SRTT - R'| is zero, so RTTVAR stays zero
    TcpOut.rtt(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->ctl.rttvar);
    TEST_ASSERT_EQUAL_UINT32(40000u + (uint32_t)IDEMIP_TCP_RTO_G_MS, IO(work_a)->ctl.rto);
}

// RFC 6298 (5.1): "Every time a packet containing data is sent (including a retransmission), if the
// timer is not running, start it running so that it will expire after RTO seconds."
void test_rtx_arm_starts_the_timer_only_when_it_is_not_running(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.rto = 3000u;
    IO(work_a)->timer_args.now_ms = 10000u;
    TcpOut.rtx_arm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(13000u, IO(work_a)->ctl.rtx_deadline);

    IO(work_a)->timer_args.now_ms = 11000u;
    TcpOut.rtx_arm(work_a);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(13000u, IO(work_a)->ctl.rtx_deadline,
                                     "a timer already running is not restarted by rule 5.1");
}

// RFC 6298 (2.1): "Until a round-trip time (RTT) measurement has been made for a segment sent between
// the sender and receiver, the sender SHOULD set RTO <- 1 second."
void test_an_unmeasured_connection_arms_at_the_initial_rto(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->timer_args.now_ms = 500u;
    TcpOut.rtx_arm(work_a);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_TCP_RTO_INIT_MS, IO(work_a)->ctl.rto);
    TEST_ASSERT_EQUAL_UINT32(500u + (uint32_t)IDEMIP_TCP_RTO_INIT_MS, IO(work_a)->ctl.rtx_deadline);
}

// RFC 6298 (5.2): "When all outstanding data has been acknowledged, turn off the retransmission
// timer." (5.3): "When an ACK is received that acknowledges new data, restart the retransmission
// timer so that it will expire after RTO seconds (for the current value of RTO)."
void test_rtx_stop_turns_the_timer_off_and_rtx_restart_restarts_it(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.rto = 2000u;
    IO(work_a)->ctl.rtx_deadline = 12000u;
    IO(work_a)->ctl.nrtx = 3u;
    IO(work_a)->ctl.backoff = 3u;
    TcpOut.rtx_stop(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->ctl.rtx_deadline);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->ctl.nrtx);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->ctl.backoff);

    IO(work_a)->ctl.rtx_deadline = 12000u;
    IO(work_a)->ctl.nrtx = 2u;
    IO(work_a)->timer_args.now_ms = 20000u;
    TcpOut.rtx_restart(work_a);
    TEST_ASSERT_EQUAL_UINT32(22000u, IO(work_a)->ctl.rtx_deadline);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->ctl.nrtx);
}

// RFC 6298 (5.5): "The host MUST set RTO <- RTO * 2 ('back off the timer')." and (5.6): "Start the
// retransmission timer, such that it expires after RTO seconds (for the value of RTO after the
// doubling operation outlined in 5.5)."
void test_the_timeout_doubles_the_rto_and_restarts_from_the_doubled_value(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.rto = 2000u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->timer_args.smss = 536u;
    IO(work_a)->timer_args.flight = 10000u;
    IO(work_a)->timer_args.now_ms = 5000u;
    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(4000u, IO(work_a)->ctl.rto, "RFC 6298 (5.5): the host MUST set RTO <- RTO * 2");
    TEST_ASSERT_EQUAL_UINT32(9000u, IO(work_a)->ctl.rtx_deadline);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->ctl.backoff);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->ctl.nrtx);

    IO(work_a)->timer_args.now_ms = 9000u;
    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_EQUAL_UINT32(8000u, IO(work_a)->ctl.rto);
    TEST_ASSERT_EQUAL_UINT32(17000u, IO(work_a)->ctl.rtx_deadline);
    TEST_ASSERT_EQUAL_UINT8(2u, IO(work_a)->ctl.backoff);
}

// RFC 9293 sec 3.8.3 (c): "When the number of transmissions of the same segment reaches a threshold
// R2 greater than R1, close the connection." Clause (a) lets R2 be "a count of retransmissions".
void test_the_retransmission_count_reaching_r2_asks_the_caller_to_close(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.rto = 1000u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->ctl.r2 = 3u;
    IO(work_a)->ctl.r2_syn = 8u;
    IO(work_a)->timer_args.smss = 536u;
    for (uint8_t n = 1u; n < 3u; n++)
    {
        TcpOut.rtx_expire(work_a);
        TEST_ASSERT_EQUAL_UINT8(n, IO(work_a)->ctl.nrtx);
        TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->res.r2, "R2 is not reached yet");
    }
    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_EQUAL_UINT8(3u, IO(work_a)->ctl.nrtx);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->res.r2, "reaching R2 closes the connection");
}

// "the values of R1 and R2 may be different for SYN and data segments", so an unacknowledged SYN is
// counted against r2_syn instead.
void test_an_unacknowledged_syn_is_counted_against_the_syn_threshold(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->state = IDEMIP_TCP_STATE_SYN_SENT;
    IO(work_a)->ctl.rto = 1000u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->ctl.r2 = 3u;
    IO(work_a)->ctl.r2_syn = 5u;
    IO(work_a)->timer_args.smss = 536u;
    for (uint8_t n = 1u; n < 5u; n++)
    {
        TcpOut.rtx_expire(work_a);
        TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->res.r2, "the data threshold must not bound a SYN");
    }
    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.r2);
}

// Clause (d): "For example, an interactive application might set R2 to 'infinity', giving the user
// control over when to disconnect." A threshold of zero never fires, and nrtx saturates rather than
// wrapping past it.
void test_an_r2_of_infinity_never_closes_the_connection(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.rto = 1000u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->ctl.r2 = 0u;
    IO(work_a)->ctl.r2_syn = 0u;
    IO(work_a)->timer_args.smss = 536u;
    for (uint16_t n = 0u; n < 300u; n++)
    {
        TcpOut.rtx_expire(work_a);
        TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->res.r2, "an R2 of infinity must never fire");
    }
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xFFu, IO(work_a)->ctl.nrtx, "the count saturates rather than wrapping");
}

// "The maximum value discussed in (2.5) above may be used to provide an upper bound to this doubling
// operation."
void test_the_doubling_is_bounded_by_the_maximum_rto(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.rto = (uint32_t)IDEMIP_TCP_RTO_MAX_MS;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->timer_args.smss = 536u;
    IO(work_a)->timer_args.now_ms = 0u;
    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_TCP_RTO_MAX_MS, IO(work_a)->ctl.rto);
}

// RFC 5681 sec 3.1: "the value of ssthresh MUST be set to no more than the value given in equation
// (4): ssthresh = max (FlightSize / 2, 2*SMSS)", and "upon a timeout ... cwnd MUST be set to no more
// than the loss window, LW, which equals 1 full-sized segment".
void test_the_timeout_halves_ssthresh_and_drops_cwnd_to_one_segment(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.rto = 1000u;
    IO(work_a)->ctl.cwnd = 20000u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->timer_args.smss = 536u;
    IO(work_a)->timer_args.flight = 10000u;
    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_EQUAL_UINT32(5000u, IO(work_a)->ctl.ssthresh);
    TEST_ASSERT_EQUAL_UINT32(536u, IO(work_a)->ctl.cwnd);

    // "ssthresh = max (FlightSize / 2, 2*SMSS)": the floor holds when little was outstanding.
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.rto = 1000u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->timer_args.smss = 536u;
    IO(work_a)->timer_args.flight = 400u;
    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_EQUAL_UINT32(1072u, IO(work_a)->ctl.ssthresh);
}

// "when a TCP sender detects segment loss using the retransmission timer and the given segment has
// already been retransmitted by way of the retransmission timer at least once, the value of ssthresh
// is held constant."
void test_a_segment_already_retransmitted_holds_ssthresh_constant(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.rto = 1000u;
    IO(work_a)->ctl.ssthresh = 4000u;
    IO(work_a)->timer_args.smss = 536u;
    IO(work_a)->timer_args.flight = 10000u;
    IO(work_a)->timer_args.resent = IDEMIP_TRUE;
    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_EQUAL_UINT32(4000u, IO(work_a)->ctl.ssthresh);
    TEST_ASSERT_EQUAL_UINT32(536u, IO(work_a)->ctl.cwnd);
}

// --- congestion control (RFC 5681 sec 3, RFC 3465) ----------------------------

// RFC 5681 sec 3.1 equation (2): "cwnd += min (N, SMSS) where N is the number of previously
// unacknowledged bytes acknowledged in the incoming ACK", used "when cwnd < ssthresh".
void test_slow_start_grows_cwnd_by_the_lesser_of_n_and_smss(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.cwnd = 1072u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->timer_args.smss = 536u;
    IO(work_a)->timer_args.acked = 536u;
    TcpOut.cc_ack(work_a);
    TEST_ASSERT_EQUAL_UINT32(1608u, IO(work_a)->ctl.cwnd);

    IO(work_a)->timer_args.acked = 2000u; // more than a segment: the increase is still one
    TcpOut.cc_ack(work_a);
    TEST_ASSERT_EQUAL_UINT32(2144u, IO(work_a)->ctl.cwnd);
}

// The same equation is what sec 3.1 says "provides robustness against misbehaving receivers that may
// attempt to induce a sender to artificially inflate cwnd using a mechanism known as 'ACK Division'
// ... a receiver sending multiple ACKs for a single TCP data segment, each acknowledging only a
// portion of its data." Ten ACKs of a tenth each open cwnd by the segment, not by ten of them.
void test_slow_start_resists_the_ack_division_of_rfc_5681_section_3_1(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.cwnd = 1072u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->timer_args.smss = 500u;
    for (int i = 0; i < 10; i++)
    {
        IO(work_a)->timer_args.acked = 50u;
        TcpOut.cc_ack(work_a);
    }
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1072u + 500u, IO(work_a)->ctl.cwnd,
                                     "byte counting must open cwnd by the octets acknowledged, not by the ACKs");
}

// RFC 3465 sec 2.1: "When bytes_acked becomes greater than or equal to the value of the congestion
// window, bytes_acked is reduced by the value of cwnd. Next, cwnd is incremented by a full-sized
// segment (SMSS)."
void test_congestion_avoidance_counts_bytes_acked_per_rfc_3465(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.cwnd = 4000u;
    IO(work_a)->ctl.ssthresh = 2000u; // cwnd is past ssthresh, so congestion avoidance
    IO(work_a)->timer_args.smss = 500u;
    for (int i = 0; i < 7; i++)
    {
        IO(work_a)->timer_args.acked = 500u;
        TcpOut.cc_ack(work_a);
        TEST_ASSERT_EQUAL_UINT32(4000u, IO(work_a)->ctl.cwnd);
    }
    IO(work_a)->timer_args.acked = 500u; // the eighth brings bytes_acked to cwnd
    TcpOut.cc_ack(work_a);
    TEST_ASSERT_EQUAL_UINT32(4500u, IO(work_a)->ctl.cwnd);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->ctl.bytes_acked);
}

// RFC 5681 sec 3.2 steps 2 and 3: "When the third duplicate ACK is received, a TCP MUST set ssthresh
// to no more than the value given in equation (4) ... The lost segment starting at SND.UNA MUST be
// retransmitted and cwnd set to ssthresh plus 3*SMSS."
void test_the_third_duplicate_ack_sets_ssthresh_and_inflates_cwnd(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.cwnd = 10000u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->timer_args.smss = 500u;
    IO(work_a)->timer_args.flight = 8000u;
    TcpOut.cc_dupack(work_a);
    TcpOut.cc_dupack(work_a);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(10000u, IO(work_a)->ctl.cwnd, "the first two duplicates must not change cwnd");
    TcpOut.cc_dupack(work_a);
    TEST_ASSERT_EQUAL_UINT32(4000u, IO(work_a)->ctl.ssthresh);
    TEST_ASSERT_EQUAL_UINT32(4000u + 1500u, IO(work_a)->ctl.cwnd);
    TEST_ASSERT_EQUAL_UINT8(3u, IO(work_a)->ctl.dupacks);
}

// Step 4: "For each additional duplicate ACK received (after the third), cwnd MUST be incremented by
// SMSS."
void test_each_duplicate_ack_after_the_third_inflates_cwnd_by_one_segment(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.cwnd = 10000u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->timer_args.smss = 500u;
    IO(work_a)->timer_args.flight = 8000u;
    for (int i = 0; i < 3; i++)
    {
        TcpOut.cc_dupack(work_a);
    }
    uint32_t at = IO(work_a)->ctl.cwnd;
    TcpOut.cc_dupack(work_a);
    TEST_ASSERT_EQUAL_UINT32(at + 500u, IO(work_a)->ctl.cwnd);
    TcpOut.cc_dupack(work_a);
    TEST_ASSERT_EQUAL_UINT32(at + 1000u, IO(work_a)->ctl.cwnd);
}

// Step 6: "When the next ACK arrives that acknowledges previously unacknowledged data, a TCP MUST set
// cwnd to ssthresh (the value set in step 2). This is termed 'deflating' the window."
void test_the_recovering_acknowledgment_deflates_cwnd_to_ssthresh(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.cwnd = 10000u;
    IO(work_a)->ctl.ssthresh = 65535u;
    IO(work_a)->timer_args.smss = 500u;
    IO(work_a)->timer_args.flight = 8000u;
    for (int i = 0; i < 5; i++)
    {
        TcpOut.cc_dupack(work_a);
    }
    TcpOut.cc_recover(work_a);
    TEST_ASSERT_EQUAL_UINT32(4000u, IO(work_a)->ctl.cwnd);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->ctl.dupacks);

    // Fewer than three duplicates was never a recovery, so cwnd is left where it was.
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->ctl.cwnd = 10000u;
    IO(work_a)->ctl.ssthresh = 2000u;
    IO(work_a)->timer_args.smss = 500u;
    TcpOut.cc_dupack(work_a);
    TcpOut.cc_recover(work_a);
    TEST_ASSERT_EQUAL_UINT32(10000u, IO(work_a)->ctl.cwnd);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->ctl.dupacks);
}

// A congestion entry with no segment size names no window step, and no retry changes that.
void test_the_congestion_entries_refuse_a_zero_segment_size(void)
{
    conn(work_a, 0u, 0u, 0u);
    IO(work_a)->timer_args.smss = 0u;
    TcpOut.cc_ack(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TcpOut.cc_dupack(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// --- the acknowledgment and the reset -----------------------------------------

// RFC 9293 sec 3.10.7.4 first: "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>", which is also the challenge ACK
// of RFC 5961 sec 3.2 and sec 4.2 that tcp_in asks for.
void test_the_acknowledgment_is_the_challenge_ack_tcp_in_asks_for(void)
{
    conn(work_a, 100u, 140u, 4096u);
    IO(work_a)->vars.rcv_nxt = 500u;
    TcpOut.ack(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(140u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(500u, IO(work_a)->reply.ack);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_ACK, IO(work_a)->reply.flags);

    // The same fields tcp_in reports for an in-window reset that is not RCV.NXT.
    TcpIn.clear(work_in);
    memset(&IDEMIP_TCP_IN_IO(work_in)->vars, 0, sizeof(IdemIpTcpVars));
    memset(&IDEMIP_TCP_IN_IO(work_in)->ctl, 0, sizeof(TcpPcbCtl));
    IDEMIP_TCP_IN_IO(work_in)->vars.snd_una = 100u;
    IDEMIP_TCP_IN_IO(work_in)->vars.snd_nxt = 140u;
    IDEMIP_TCP_IN_IO(work_in)->vars.rcv_nxt = 500u;
    IDEMIP_TCP_IN_IO(work_in)->vars.rcv_wnd = 100u;
    IDEMIP_TCP_IN_IO(work_in)->state = IDEMIP_TCP_STATE_ESTABLISHED;
    IDEMIP_TCP_IN_IO(work_in)->listener = IDEMIP_TCP_PCB_NONE;
    memset(&IDEMIP_TCP_IN_IO(work_in)->seg, 0, sizeof(TcpInSegArgs));
    IDEMIP_TCP_IN_IO(work_in)->seg.seq = 550u;
    IDEMIP_TCP_IN_IO(work_in)->seg.flags = (uint8_t)IDEMIP_TCP_RST;
    TcpIn.segment(work_in);
    TEST_ASSERT_TRUE(IDEMIP_TCP_IN_IO(work_in)->res.act & IDEMIP_TCP_IN_ACT_CHALLENGE);
    TEST_ASSERT_EQUAL_UINT32(IO(work_a)->reply.seq, IDEMIP_TCP_IN_IO(work_in)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(IO(work_a)->reply.ack, IDEMIP_TCP_IN_IO(work_in)->reply.ack);
    TEST_ASSERT_EQUAL_UINT16(IO(work_a)->reply.flags, IDEMIP_TCP_IN_IO(work_in)->reply.flags);
}

// RFC 9293 sec 3.5.1 Figure 10 line 3: the segment "<SEQ=300><ACK=100><DATA=10><CTL=ACK>" is answered
// with "<SEQ=100><CTL=RST>", "the reset takes its sequence number from the ACK field of the segment".
void test_the_reset_of_figure_10_takes_its_sequence_from_the_ack_field(void)
{
    TcpOut.clear(work_a);
    memset(&IO(work_a)->seg_args, 0, sizeof IO(work_a)->seg_args);
    IO(work_a)->seg_args.seq = 300u;
    IO(work_a)->seg_args.ack = 100u;
    IO(work_a)->seg_args.len = 10u;
    IO(work_a)->seg_args.flags = (uint8_t)IDEMIP_TCP_ACK;
    TcpOut.rst(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(100u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_RST, IO(work_a)->reply.flags);
}

// "otherwise, the reset has sequence number zero and the ACK field is set to the sum of the sequence
// number and segment length of the incoming segment": <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>.
void test_the_reset_for_a_segment_without_an_ack_takes_sequence_zero(void)
{
    TcpOut.clear(work_a);
    memset(&IO(work_a)->seg_args, 0, sizeof IO(work_a)->seg_args);
    IO(work_a)->seg_args.seq = 100u;
    IO(work_a)->seg_args.len = 1u; // a SYN occupies one sequence number
    IO(work_a)->seg_args.flags = (uint8_t)IDEMIP_TCP_SYN;
    TcpOut.rst(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->reply.ack);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)(IDEMIP_TCP_RST | IDEMIP_TCP_ACK), IO(work_a)->reply.flags);
}

// A reset built into a buffer and read back: sec 3.5.2's fields survive the wire form.
void test_a_reset_built_onto_the_wire_reads_back(void)
{
    TcpOut.clear(work_a);
    memset(&IO(work_a)->seg_args, 0, sizeof IO(work_a)->seg_args);
    IO(work_a)->seg_args.seq = 300u;
    IO(work_a)->seg_args.ack = 100u;
    IO(work_a)->seg_args.flags = (uint8_t)IDEMIP_TCP_ACK;
    TcpOut.rst(work_a);
    uint32_t seq = IO(work_a)->reply.seq;
    uint16_t flags = IO(work_a)->reply.flags;

    aim_build(work_a, seq, 0u, (uint8_t)flags, 0u, NULL);
    IO(work_a)->build_args.wnd = 0u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(100u, idemip_tcp_seq(g_buf));
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_TCP_RST, idemip_tcp_flags(g_buf));

    TcpIn.clear(work_in);
    IDEMIP_TCP_IN_IO(work_in)->parse_args.seg = g_buf;
    IDEMIP_TCP_IN_IO(work_in)->parse_args.local_ip = g_remote;
    IDEMIP_TCP_IN_IO(work_in)->parse_args.remote_ip = g_local;
    IDEMIP_TCP_IN_IO(work_in)->parse_args.len = IO(work_a)->res.built;
    IDEMIP_TCP_IN_IO(work_in)->parse_args.ip_version = 4u;
    IDEMIP_TCP_IN_IO(work_in)->parse_args.snd_scale = 0u;
    TcpIn.parse(work_in);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_IN_IO(work_in)->status);
    TEST_ASSERT_EQUAL_UINT32(100u, IDEMIP_TCP_IN_IO(work_in)->seg.seq);
}

// RFC 7323 sec 3.2: "The TSecr field is valid if the ACK bit is set in the TCP header." A <SYN,ACK>
// carries the echo the pure SYN above must leave at zero.
void test_a_syn_ack_carries_the_timestamp_echo(void)
{
    aim_build(work_a, 100u, 300u, (uint8_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK), 0u, NULL);
    IO(work_a)->build_args.opts = (uint16_t)IDEMIP_TCP_OUT_OPT_TS;
    IO(work_a)->build_args.tsval = 0x11223344u;
    IO(work_a)->build_args.tsecr = 0x55667788u;
    TcpOut.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    int saw_ts = 0;
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, g_buf);
    while (idemip_tcp_opt_next(&w))
    {
        if (w.kind == IDEMIP_TCP_OPT_TS)
        {
            saw_ts = 1;
            TEST_ASSERT_EQUAL_UINT32(0x11223344u, idemip_tcp_opt_tsval(w.opt));
            TEST_ASSERT_EQUAL_UINT32(0x55667788u, idemip_tcp_opt_tsecr(w.opt));
        }
    }
    TEST_ASSERT_FALSE(w.bad);
    TEST_ASSERT_TRUE(saw_ts);
}

// RFC 5681 sec 3.1's table: "If SMSS > 2190 bytes: IW = 2 * SMSS", "If (SMSS > 1095 bytes) and
// (SMSS <= 2190 bytes): IW = 3 * SMSS", "if SMSS <= 1095 bytes: IW = 4 * SMSS".
void test_the_initial_window_takes_the_three_way_table(void)
{
    conn(work_a, 1000u, 1000u, 65535u);
    IO(work_a)->timer_args.smss = 1000u;
    TcpOut.cc_init(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(4000u, IO(work_a)->ctl.cwnd);

    IO(work_a)->timer_args.smss = 1460u;
    TcpOut.cc_init(work_a);
    TEST_ASSERT_EQUAL_UINT32(4380u, IO(work_a)->ctl.cwnd);

    IO(work_a)->timer_args.smss = 2500u;
    TcpOut.cc_init(work_a);
    TEST_ASSERT_EQUAL_UINT32(5000u, IO(work_a)->ctl.cwnd);

    // The boundaries the table names, which are inclusive on the low side of each band.
    IO(work_a)->timer_args.smss = 1095u;
    TcpOut.cc_init(work_a);
    TEST_ASSERT_EQUAL_UINT32(4380u, IO(work_a)->ctl.cwnd);
    IO(work_a)->timer_args.smss = 2190u;
    TcpOut.cc_init(work_a);
    TEST_ASSERT_EQUAL_UINT32(6570u, IO(work_a)->ctl.cwnd);
}

// RFC 5681 sec 3.1: "The initial value of ssthresh SHOULD be set arbitrarily high (e.g., to the size
// of the largest possible advertised window)", so a new connection is in slow start, not congestion
// avoidance, and a connection straight out of a zeroed control block can release data.
void test_a_new_connection_starts_in_slow_start_and_can_send(void)
{
    conn(work_a, 1000u, 1000u, 65535u);
    memset(&IO(work_a)->ctl, 0, sizeof IO(work_a)->ctl); // what TcpPcb.load hands over
    IO(work_a)->timer_args.smss = 1460u;
    TcpOut.cc_init(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->ctl.cwnd < IO(work_a)->ctl.ssthresh, "not in slow start");

    IO(work_a)->send_args.eff_snd_mss = 1460u;
    IO(work_a)->send_args.queued = 4000u;
    TcpOut.send(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(4380u, IO(work_a)->res.usable);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->res.send_now, "a fresh connection sent nothing");
    TEST_ASSERT_EQUAL_UINT32(1460u, IO(work_a)->res.send_len);

    // The first ACK opens the window by a segment, which is slow start and not the byte counter.
    uint32_t was = IO(work_a)->ctl.cwnd;
    IO(work_a)->timer_args.acked = 1460u;
    TcpOut.cc_ack(work_a);
    TEST_ASSERT_EQUAL_UINT32(was + 1460u, IO(work_a)->ctl.cwnd);
}

// RFC 5681 sec 3.1: "As specified in [RFC3390], the SYN/ACK and the acknowledgment of the SYN/ACK
// MUST NOT increase the size of the congestion window."
void test_the_handshake_acknowledgment_does_not_open_the_window(void)
{
    conn(work_a, 1000u, 1000u, 65535u);
    IO(work_a)->timer_args.smss = 1460u;
    TcpOut.cc_init(work_a);
    uint32_t iw = IO(work_a)->ctl.cwnd;

    IO(work_a)->state = IDEMIP_TCP_STATE_SYN_RECEIVED;
    IO(work_a)->timer_args.acked = 1u;
    TcpOut.cc_ack(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(iw, IO(work_a)->ctl.cwnd);

    IO(work_a)->state = IDEMIP_TCP_STATE_SYN_SENT;
    TcpOut.cc_ack(work_a);
    TEST_ASSERT_EQUAL_UINT32(iw, IO(work_a)->ctl.cwnd);
}

// RFC 6298 (5.7): "If the timer expires awaiting the ACK of a SYN segment and the TCP implementation
// is using an RTO less than 3 seconds, the RTO MUST be re-initialized to 3 seconds when data
// transmission begins (i.e., after the three-way handshake completes)."
void test_a_syn_timeout_floors_the_rto_at_three_seconds_once_data_begins(void)
{
    conn(work_a, 1000u, 1000u, 65535u);
    IO(work_a)->state = IDEMIP_TCP_STATE_SYN_SENT;
    IO(work_a)->timer_args.smss = 1460u;
    IO(work_a)->timer_args.now_ms = 1000u;
    TcpOut.rtx_arm(work_a);
    TEST_ASSERT_EQUAL_UINT32(1000u, IO(work_a)->ctl.rto); // (2.1)'s initial value

    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(2000u, IO(work_a)->ctl.rto); // (5.5)'s doubling, still under 3 s

    // The handshake completes and the first data segment is armed.
    IO(work_a)->state = IDEMIP_TCP_STATE_ESTABLISHED;
    IO(work_a)->ctl.rtx_deadline = 0u;
    TcpOut.rtx_arm(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(3000u, IO(work_a)->ctl.rto);

    // The floor is applied once, not on every later arm.
    IO(work_a)->ctl.rto = 1200u;
    IO(work_a)->ctl.rtx_deadline = 0u;
    TcpOut.rtx_arm(work_a);
    TEST_ASSERT_EQUAL_UINT32(1200u, IO(work_a)->ctl.rto);
}

// RFC 6298 sec 3: "RTT samples MUST NOT be made using segments that were retransmitted (and thus for
// which it is ambiguous whether the reply was for the first instance of the packet or a later
// instance)." The estimator resumes once an ACK of new data ends the ambiguity.
void test_a_sample_taken_across_a_retransmission_is_refused(void)
{
    conn(work_a, 1000u, 1000u, 65535u);
    IO(work_a)->timer_args.smss = 1460u;
    IO(work_a)->timer_args.sample_ms = 1600u;
    TcpOut.rtt(work_a);
    TEST_ASSERT_EQUAL_UINT32(1600u, IO(work_a)->ctl.srtt); // (2.2), the clean first sample

    IO(work_a)->timer_args.now_ms = 5000u;
    TcpOut.rtx_expire(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->ctl.backoff != 0u);

    uint32_t srtt = IO(work_a)->ctl.srtt;
    uint32_t rttvar = IO(work_a)->ctl.rttvar;
    IO(work_a)->timer_args.sample_ms = 9000u; // the ambiguous ACK of the retransmission
    TcpOut.rtt(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(srtt, IO(work_a)->ctl.srtt);
    TEST_ASSERT_EQUAL_UINT32(rttvar, IO(work_a)->ctl.rttvar);

    // (5.3)'s ACK of new data ends the ambiguity, and the next sample is taken again.
    TcpOut.rtx_restart(work_a);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->ctl.backoff);
    IO(work_a)->timer_args.sample_ms = 3200u;
    TcpOut.rtt(work_a);
    // (2.3) "SRTT <- (1 - alpha) * SRTT + alpha * R'" with alpha 1/8: 1600 - 200 + 400.
    TEST_ASSERT_EQUAL_UINT32(1800u, IO(work_a)->ctl.srtt);
}

// RFC 5681 sec 4.1: "a TCP SHOULD set cwnd to no more than RW before beginning transmission if the
// TCP has not sent data in an interval exceeding the retransmission timeout", RW being "min(IW,cwnd)".
void test_an_idle_connection_restarts_at_the_restart_window(void)
{
    conn(work_a, 1000u, 1000u, 65535u);
    IO(work_a)->timer_args.smss = 1460u;
    TcpOut.cc_init(work_a);
    IO(work_a)->ctl.cwnd = 64000u; // grown by a bulk transfer
    IO(work_a)->ctl.rto = 1000u;
    IO(work_a)->send_args.eff_snd_mss = 1460u;
    IO(work_a)->send_args.queued = 64000u;

    IO(work_a)->send_args.now_ms = 10000u;
    TcpOut.send(work_a);
    TEST_ASSERT_TRUE(IO(work_a)->res.send_now);
    TEST_ASSERT_EQUAL_UINT32(10000u, IO(work_a)->ctl.last_send_ms);
    TEST_ASSERT_EQUAL_UINT32(64000u, IO(work_a)->res.usable); // not idle, the full window stands

    // 30 seconds of silence, far beyond the 1 s retransmission timeout.
    IO(work_a)->send_args.now_ms = 40000u;
    TcpOut.send(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(4380u, IO(work_a)->ctl.cwnd); // min(IW, cwnd) with SMSS 1460
    TEST_ASSERT_EQUAL_UINT32(4380u, IO(work_a)->res.usable);
}

// An entry is a function of its borrow alone, so the same operands on two borrows decide alike.
void test_the_same_operands_on_two_borrows_decide_alike(void)
{
    conn(work_a, 1000u, 1400u, 4000u);
    IO(work_a)->send_args.eff_snd_mss = 536u;
    IO(work_a)->send_args.queued = 2000u;
    TcpOut.send(work_a);

    conn(work_b, 1000u, 1400u, 4000u);
    IO(work_b)->send_args.eff_snd_mss = 536u;
    IO(work_b)->send_args.queued = 2000u;
    TcpOut.send(work_b);

    TEST_ASSERT_EQUAL_UINT32(IO(work_a)->res.usable, IO(work_b)->res.usable);
    TEST_ASSERT_EQUAL_UINT32(IO(work_a)->res.send_len, IO(work_b)->res.send_len);
    TEST_ASSERT_EQUAL_INT((int)IO(work_a)->res.send_now, (int)IO(work_b)->res.send_now);
}
