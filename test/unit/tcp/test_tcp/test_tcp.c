// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The TCP header, RFC 9293 sec 3.1 Figure 1 and sec 3.2, with the options RFC 7323 sec 2.2 and
// sec 3.2 and RFC 2018 sec 2 and sec 3 add. Every vector is laid out from the figure in the RFC
// that names the field, so a moved offset or a swapped bit fails here.
//
// tcp.h holds no state, so the four properties test_phy checks over a borrow are checked here over
// the caller's bytes: nothing is written outside the span the build helpers report, a walk keeps its
// position in the caller's own object, two walks over two segments do not interfere, and an illegal
// option length is refused rather than read past.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/tcp/tcp.h"

#include <string.h>
#include <unity.h>

// --- the caller's bytes ------------------------------------------------------

// A segment is at most a 60-byte header (Data Offset 15) plus data. A canary follows so a build
// helper writing past the octets it reported is visible.
#define CANARY 0x5Au
#define SEG_CAP 64u
static uint8_t seg[SEG_CAP + 16u];
static uint8_t seg_b[SEG_CAP + 16u];

static void arm(uint8_t *s)
{
    memset(s, 0, SEG_CAP);
    memset(s + SEG_CAP, CANARY, 16u);
}

static void check_canary(const uint8_t *s)
{
    for (size_t i = SEG_CAP; i < SEG_CAP + 16u; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, s[i], "a write landed past the segment");
    }
}

void setUp(void)
{
    arm(seg);
    arm(seg_b);
}

void tearDown(void)
{
    check_canary(seg);
    check_canary(seg_b);
}

// The word at offset 12: Data Offset in the high nibble, Reserved next, the control bits low.
static void put_offs_flags(uint8_t *h, uint8_t doff, uint8_t flags)
{
    idemip_wr16(h + IDEMIP_TCP_OFF_OFFS_FLAGS, (uint16_t)(((uint16_t)doff << IDEMIP_TCP_DOFF_SHIFT) | flags));
}

// Options into a segment, and the Data Offset that names them. The length must be a whole number of
// 32-bit words, which is what RFC 9293 sec 3.1's "integer multiple of 32 bits" means.
static void put_opts(uint8_t *h, const uint8_t *opts, size_t len)
{
    memcpy(h + IDEMIP_TCP_OFF_OPTIONS, opts, len);
    put_offs_flags(h, (uint8_t)(IDEMIP_TCP_DOFF_MIN + (len >> IDEMIP_TCP_WORD_SHIFT)), 0u);
}

// An independent one's complement sum, written as its own loop, so the checksum case is not the
// header's arithmetic checking itself.
static uint16_t ref_cksum(const uint8_t *p, size_t len, uint32_t src, uint32_t dst, uint16_t seg_len)
{
    uint32_t sum = 0u;
    for (size_t i = 0; i + 1u < len; i += 2u)
    {
        sum += ((uint32_t)p[i] << 8) | (uint32_t)p[i + 1u];
    }
    if (len & 1u)
    {
        sum += (uint32_t)p[len - 1u] << 8;
    }
    sum += (src >> 16) & 0xFFFFu;
    sum += src & 0xFFFFu;
    sum += (dst >> 16) & 0xFFFFu;
    sum += dst & 0xFFFFu;
    sum += 6u; // PTCL, with the zero octet above it (RFC 9293 sec 3.1 Figure 2)
    sum += seg_len;
    while (sum >> 16)
    {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

// --- the header, RFC 9293 sec 3.1 Figure 1 -----------------------------------

// The field positions the figure fixes, as octets. Source and destination ports are the first two
// 16-bit fields, the sequence and acknowledgment numbers the next two 32-bit ones, then the packed
// Data Offset / Reserved / control bits word, the window, the checksum and the urgent pointer.
static const uint8_t rfc9293_fig1[IDEMIP_TCP_HDR_LEN] = {
    0x00, 0x50,             // Source Port 80
    0xC0, 0x01,             // Destination Port 49153
    0x01, 0x02, 0x03, 0x04, // Sequence Number
    0x05, 0x06, 0x07, 0x08, // Acknowledgment Number
    0x50, 0x12,             // Data Offset 5, Reserved 0, SYN and ACK
    0x20, 0x00,             // Window 8192
    0xBE, 0xEF,             // Checksum
    0x00, 0x01,             // Urgent Pointer
};

void test_figure_1_field_offsets(void)
{
    const uint8_t *h = rfc9293_fig1;
    TEST_ASSERT_EQUAL_HEX16(0x0050u, idemip_tcp_src_port(h));
    TEST_ASSERT_EQUAL_HEX16(0xC001u, idemip_tcp_dst_port(h));
    TEST_ASSERT_EQUAL_HEX32(0x01020304u, idemip_tcp_seq(h));
    TEST_ASSERT_EQUAL_HEX32(0x05060708u, idemip_tcp_ack(h));
    TEST_ASSERT_EQUAL_UINT8(5u, idemip_tcp_doff(h));
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK, idemip_tcp_flags(h));
    TEST_ASSERT_EQUAL_HEX16(0x2000u, idemip_tcp_window(h));
    TEST_ASSERT_EQUAL_HEX16(0xBEEFu, idemip_tcp_cksum(h));
    TEST_ASSERT_EQUAL_HEX16(0x0001u, idemip_tcp_urgent(h));

    // The offsets are the figure's, and the last field ends the option-free header.
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_TCP_OFF_SRC_PORT);
    TEST_ASSERT_EQUAL_size_t(2u, (size_t)IDEMIP_TCP_OFF_DST_PORT);
    TEST_ASSERT_EQUAL_size_t(4u, (size_t)IDEMIP_TCP_OFF_SEQ);
    TEST_ASSERT_EQUAL_size_t(8u, (size_t)IDEMIP_TCP_OFF_ACK);
    TEST_ASSERT_EQUAL_size_t(12u, (size_t)IDEMIP_TCP_OFF_OFFS_FLAGS);
    TEST_ASSERT_EQUAL_size_t(14u, (size_t)IDEMIP_TCP_OFF_WINDOW);
    TEST_ASSERT_EQUAL_size_t(16u, (size_t)IDEMIP_TCP_OFF_CKSUM);
    TEST_ASSERT_EQUAL_size_t(18u, (size_t)IDEMIP_TCP_OFF_URGENT);
    TEST_ASSERT_EQUAL_size_t(20u, (size_t)IDEMIP_TCP_OFF_OPTIONS);
    TEST_ASSERT_EQUAL_size_t(20u, (size_t)IDEMIP_TCP_HDR_LEN);
}

// RFC 9293 sec 3.1: "The currently assigned control bits are CWR, ECE, URG, ACK, PSH, RST, SYN, and
// FIN", and Figure 1 lays them |C|E|U|A|P|R|S|F| across the low octet of the word at offset 12. So
// CWR is the top bit of that octet and FIN the bottom.
void test_control_bits_are_the_figure_order(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x80u, IDEMIP_TCP_CWR);
    TEST_ASSERT_EQUAL_HEX8(0x40u, IDEMIP_TCP_ECE);
    TEST_ASSERT_EQUAL_HEX8(0x20u, IDEMIP_TCP_URG);
    TEST_ASSERT_EQUAL_HEX8(0x10u, IDEMIP_TCP_ACK);
    TEST_ASSERT_EQUAL_HEX8(0x08u, IDEMIP_TCP_PSH);
    TEST_ASSERT_EQUAL_HEX8(0x04u, IDEMIP_TCP_RST);
    TEST_ASSERT_EQUAL_HEX8(0x02u, IDEMIP_TCP_SYN);
    TEST_ASSERT_EQUAL_HEX8(0x01u, IDEMIP_TCP_FIN);
}

// One bit at a time, read out of the octet the figure puts it in. A swapped pair passes the OR test
// above and fails this one.
void test_each_control_bit_reads_alone(void)
{
    static const uint8_t bit[8] = {IDEMIP_TCP_CWR, IDEMIP_TCP_ECE, IDEMIP_TCP_URG, IDEMIP_TCP_ACK,
                                   IDEMIP_TCP_PSH, IDEMIP_TCP_RST, IDEMIP_TCP_SYN, IDEMIP_TCP_FIN};
    for (int i = 0; i < 8; i++)
    {
        put_offs_flags(seg, IDEMIP_TCP_DOFF_MIN, bit[i]);
        TEST_ASSERT_EQUAL_HEX8(bit[i], idemip_tcp_flags(seg));
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_DOFF_MIN, idemip_tcp_doff(seg));
        // The figure puts CWR at bit 7 of the octet and FIN at bit 0.
        TEST_ASSERT_EQUAL_HEX8((uint8_t)(0x80u >> i), bit[i]);
    }
}

// RFC 9293 sec 3.1: Data Offset is 4 bits, Reserved the 4 below it. A set Reserved nibble must not
// reach either the Data Offset or the control bits.
void test_reserved_nibble_sits_between_data_offset_and_the_control_bits(void)
{
    idemip_wr16(seg + IDEMIP_TCP_OFF_OFFS_FLAGS, 0x5F12u);
    TEST_ASSERT_EQUAL_UINT8(5u, idemip_tcp_doff(seg));
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK, idemip_tcp_flags(seg));
    TEST_ASSERT_EQUAL_HEX16(0x0F00u, (uint16_t)(idemip_rd16(seg + IDEMIP_TCP_OFF_OFFS_FLAGS) & IDEMIP_TCP_RSRVD_MASK));
    TEST_ASSERT_EQUAL_HEX16(0u, (uint16_t)(IDEMIP_TCP_RSRVD_MASK & 0xFFu));
}

// RFC 9293 sec 3.1: Data Offset is "The number of 32-bit words in the TCP header", five words with
// no options and fifteen at most, so the header is 20 to 60 octets.
void test_data_offset_scales_by_four(void)
{
    put_offs_flags(seg, IDEMIP_TCP_DOFF_MIN, 0u);
    TEST_ASSERT_EQUAL_UINT8(5u, idemip_tcp_doff(seg));
    TEST_ASSERT_EQUAL_size_t(20u, idemip_tcp_hdr_len(seg));
    TEST_ASSERT_EQUAL_size_t(0u, idemip_tcp_opts_len(seg));

    put_offs_flags(seg, IDEMIP_TCP_DOFF_MAX, 0u);
    TEST_ASSERT_EQUAL_UINT8(15u, idemip_tcp_doff(seg));
    TEST_ASSERT_EQUAL_size_t(60u, idemip_tcp_hdr_len(seg));
    TEST_ASSERT_EQUAL_size_t(40u, idemip_tcp_opts_len(seg));
    TEST_ASSERT_EQUAL_size_t(40u, (size_t)IDEMIP_TCP_OPTS_MAX);

    // "size(Options) == (DOffset-5)*32", so each word past the fifth is four more octets.
    for (uint8_t doff = IDEMIP_TCP_DOFF_MIN; doff <= IDEMIP_TCP_DOFF_MAX; doff++)
    {
        put_offs_flags(seg, doff, 0u);
        TEST_ASSERT_EQUAL_size_t((size_t)(doff - 5u) * 4u, idemip_tcp_opts_len(seg));
        TEST_ASSERT_EQUAL_UINT8(doff, IDEMIP_TCP_DOFF_FROM_BYTES(idemip_tcp_hdr_len(seg)));
    }
}

// A Data Offset below the five-word minimum names no options: it is malformed, and reading a
// negative option length out of it would run backwards through the header.
void test_a_data_offset_below_the_minimum_names_no_options(void)
{
    for (uint8_t doff = 0u; doff < IDEMIP_TCP_DOFF_MIN; doff++)
    {
        put_offs_flags(seg, doff, 0u);
        TEST_ASSERT_EQUAL_size_t(0u, idemip_tcp_opts_len(seg));
        IdemIpTcpOptWalk w;
        idemip_tcp_opt_walk(&w, seg);
        TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
        TEST_ASSERT_FALSE(w.bad);
    }
}

// --- option kinds, RFC 9293 sec 3.2, RFC 7323, RFC 2018 ----------------------

// The kind numbers each RFC prints, and the lengths beside them. RFC 9293 sec 3.2 Table 1 gives 0,
// 1 and 2; RFC 7323 sec 2.2 "Kind: 3" and sec 3.2 "Kind: 8"; RFC 2018 sec 2 "Kind: 4" and sec 3
// "Kind: 5".
void test_option_kind_numbers(void)
{
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_TCP_OPT_END);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_TCP_OPT_NOP);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_TCP_OPT_MSS);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_TCP_OPT_WS);
    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_TCP_OPT_SACK_PERM);
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_TCP_OPT_SACK);
    TEST_ASSERT_EQUAL_UINT8(8u, IDEMIP_TCP_OPT_TS);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_TCP_MSS_KIND);

    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_TCP_OPT_MSS_LEN);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_TCP_OPT_WS_LEN);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_TCP_OPT_SACK_PERM_LEN);
    TEST_ASSERT_EQUAL_UINT8(10u, IDEMIP_TCP_OPT_TS_LEN);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_TCP_OPT_LEN_MIN);
}

// --- the option walk ---------------------------------------------------------

void test_walk_over_a_header_with_no_options(void)
{
    put_offs_flags(seg, IDEMIP_TCP_DOFF_MIN, IDEMIP_TCP_ACK);
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    TEST_ASSERT_EQUAL_PTR(seg + IDEMIP_TCP_OFF_OPTIONS, w.opts);
    TEST_ASSERT_EQUAL_size_t(0u, w.end);
    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_NULL(w.opt);
    TEST_ASSERT_FALSE(w.bad);
}

// RFC 9293 sec 3.1 Case 1: "A single octet of option-kind." Kind 1 is the whole option, so the walk
// steps one octet and does not read a length that is not there.
void test_walk_steps_single_octet_no_operation(void)
{
    static const uint8_t opts[4] = {IDEMIP_TCP_OPT_NOP, IDEMIP_TCP_OPT_NOP, IDEMIP_TCP_OPT_NOP,
                                    IDEMIP_TCP_OPT_NOP};
    put_opts(seg, opts, sizeof opts);
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    for (int i = 0; i < 4; i++)
    {
        TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_NOP, w.kind);
        TEST_ASSERT_EQUAL_UINT8(1u, w.len);
        TEST_ASSERT_EQUAL_PTR(seg + IDEMIP_TCP_OFF_OPTIONS + i, w.opt);
    }
    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_FALSE(w.bad);
}

// RFC 9293 sec 3.2 on kind 0: "This option code indicates the end of the option list." sec 3.1
// MUST-69: "The content of the header beyond the End of Option List Option MUST be header padding
// of zeros", so the walk reports kind 0 and stops rather than reporting the padding as options.
void test_walk_stops_at_end_of_option_list(void)
{
    static const uint8_t opts[4] = {IDEMIP_TCP_OPT_NOP, IDEMIP_TCP_OPT_END, 0x00u, 0x00u};
    put_opts(seg, opts, sizeof opts);
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);

    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_NOP, w.kind);

    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_END, w.kind);
    TEST_ASSERT_EQUAL_UINT8(1u, w.len);
    TEST_ASSERT_EQUAL_PTR(seg + IDEMIP_TCP_OFF_OPTIONS + 1, w.opt);

    // The two padding octets are not options.
    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_FALSE(w.bad);
}

// RFC 9293 sec 3.2's MSS figure: |2|Length|MSS|, with "Length == 4". 536 is the IPv4 default send
// MSS of sec 3.7.1 MUST-15.
void test_walk_steps_the_maximum_segment_size_option(void)
{
    static const uint8_t opts[4] = {0x02u, 0x04u, 0x02u, 0x18u};
    put_opts(seg, opts, sizeof opts);
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_MSS, w.kind);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_MSS_LEN, w.len);
    TEST_ASSERT_EQUAL_UINT16(536u, idemip_tcp_opt_mss(w.opt));
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_IPV4_DEFAULT_SEND_MSS, idemip_tcp_opt_mss(w.opt));
    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
}

// RFC 9293 sec 3.1 MUST-6: a TCP "MUST ignore without error any TCP Option it does not implement,
// assuming that the option has a length field". The walk steps such an option by its length and
// lands on the next one.
void test_walk_steps_past_an_unimplemented_kind(void)
{
    static const uint8_t opts[12] = {
        0xFDu, 0x06u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, // some kind this stack does not implement
        0x02u, 0x04u, 0x05u, 0xB4u,               // MSS 1460
        IDEMIP_TCP_OPT_NOP, IDEMIP_TCP_OPT_END,
    };
    put_opts(seg, opts, sizeof opts);
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);

    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(0xFDu, w.kind);
    TEST_ASSERT_EQUAL_UINT8(6u, w.len);

    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_MSS, w.kind);
    TEST_ASSERT_EQUAL_UINT16(1460u, idemip_tcp_opt_mss(w.opt));

    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_NOP, w.kind);

    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_END, w.kind);

    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_FALSE(w.bad);
}

// RFC 9293 sec 3.1 MUST-7: "TCP implementations MUST be prepared to handle an illegal option length
// (e.g., zero)". Zero and one are both below the two octets the length field itself counts, and
// either would leave a walk standing still.
void test_walk_refuses_an_illegal_option_length(void)
{
    static const uint8_t bad_len[2] = {0x00u, 0x01u};
    for (int i = 0; i < 2; i++)
    {
        uint8_t opts[4] = {IDEMIP_TCP_OPT_MSS, bad_len[i], 0x05u, 0xB4u};
        put_opts(seg, opts, sizeof opts);
        IdemIpTcpOptWalk w;
        idemip_tcp_opt_walk(&w, seg);
        TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
        TEST_ASSERT_TRUE_MESSAGE(w.bad, "an option length below two was accepted");
        TEST_ASSERT_NULL(w.opt);
        // And it stays ended, rather than spinning on the same octet.
        TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
    }
}

// A length reaching past the octets the Data Offset gives the options would read the data beyond
// them. RFC 9293 sec 3.1 sizes the options at "(DOffset-5)*32" bits and nothing more.
void test_walk_refuses_a_length_past_the_options(void)
{
    static const uint8_t opts[4] = {IDEMIP_TCP_OPT_TS, IDEMIP_TCP_OPT_TS_LEN, 0x00u, 0x00u};
    put_opts(seg, opts, sizeof opts);
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_TRUE(w.bad);
}

// A Case 2 kind in the last octet of the region has no length octet to read at all.
void test_walk_refuses_a_truncated_length_octet(void)
{
    static const uint8_t opts[4] = {IDEMIP_TCP_OPT_NOP, IDEMIP_TCP_OPT_NOP, IDEMIP_TCP_OPT_NOP,
                                    IDEMIP_TCP_OPT_MSS};
    put_opts(seg, opts, sizeof opts);
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    for (int i = 0; i < 3; i++)
    {
        TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_NOP, w.kind);
    }
    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_TRUE(w.bad);
}

// The walk keeps its position in the caller's own object, so two segments walked at once do not
// interfere. This is the stateless-header form of test_phy's two-borrow property.
void test_two_walks_do_not_interfere(void)
{
    static const uint8_t a[4] = {0x02u, 0x04u, 0x05u, 0xB4u};                                  // MSS 1460
    static const uint8_t b[8] = {IDEMIP_TCP_OPT_SACK_PERM, 0x02u, 0x03u, 0x03u, 0x07u, 0x00u,   // and WS 7
                                 0x00u, 0x00u};
    put_opts(seg, a, sizeof a);
    put_opts(seg_b, b, sizeof b);

    IdemIpTcpOptWalk wa;
    IdemIpTcpOptWalk wb;
    idemip_tcp_opt_walk(&wa, seg);
    idemip_tcp_opt_walk(&wb, seg_b);

    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&wa));
    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&wb));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_MSS, wa.kind);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_SACK_PERM, wb.kind);

    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&wb));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_WS, wb.kind);
    TEST_ASSERT_EQUAL_UINT8(7u, idemip_tcp_opt_ws(wb.opt));

    // a's walk is where a left it, not where b's is.
    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&wa));
    TEST_ASSERT_EQUAL_UINT16(1460u, idemip_tcp_opt_mss(seg + IDEMIP_TCP_OFF_OPTIONS));
}

// A walk over the same bytes twice reports the same options, since it reads the segment and writes
// nothing.
void test_a_walk_repeats(void)
{
    static const uint8_t opts[8] = {0x02u, 0x04u, 0x05u, 0xB4u, IDEMIP_TCP_OPT_SACK_PERM, 0x02u,
                                    IDEMIP_TCP_OPT_NOP, IDEMIP_TCP_OPT_END};
    put_opts(seg, opts, sizeof opts);
    uint8_t first[8];
    uint8_t second[8];
    size_t n = 0;
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    while (idemip_tcp_opt_next(&w))
    {
        first[n++] = w.kind;
    }
    size_t m = 0;
    idemip_tcp_opt_walk(&w, seg);
    while (idemip_tcp_opt_next(&w))
    {
        second[m++] = w.kind;
    }
    TEST_ASSERT_EQUAL_size_t(4u, n);
    TEST_ASSERT_EQUAL_size_t(n, m);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, second, n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(opts, seg + IDEMIP_TCP_OFF_OPTIONS, sizeof opts);
}

// --- RFC 7323 sec 2.2, Window Scale -----------------------------------------

// "+---------+---------+---------+ | Kind=3 |Length=3 |shift.cnt| +---------+---------+---------+"
void test_window_scale_option_figure(void)
{
    static const uint8_t opts[4] = {0x03u, 0x03u, 0x07u, IDEMIP_TCP_OPT_END};
    put_opts(seg, opts, sizeof opts);
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_WS, w.kind);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_WS_LEN, w.len);
    TEST_ASSERT_EQUAL_UINT8(7u, idemip_tcp_opt_ws(w.opt));
}

// RFC 7323 sec 2.3: "If a Window Scale option is received with a shift.cnt value larger than 14,
// the TCP SHOULD log the error but MUST use 14 instead of the specified value."
void test_window_scale_over_fourteen_reads_as_fourteen(void)
{
    TEST_ASSERT_EQUAL_UINT8(14u, IDEMIP_TCP_WS_MAX);
    for (uint16_t s = 0u; s <= 255u; s++)
    {
        uint8_t opts[4] = {IDEMIP_TCP_OPT_WS, IDEMIP_TCP_OPT_WS_LEN, (uint8_t)s, IDEMIP_TCP_OPT_END};
        put_opts(seg, opts, sizeof opts);
        uint8_t got = idemip_tcp_opt_ws(seg + IDEMIP_TCP_OFF_OPTIONS);
        TEST_ASSERT_EQUAL_UINT8((s > 14u) ? 14u : (uint8_t)s, got);
    }
}

// RFC 7323 sec 2.2: 14 gives "a maximum permissible receive window size of 1 GiB (2^(14+16))", and
// sec 2.3's model applies the shift to the 16-bit window field.
void test_window_scale_reaches_one_gibibyte(void)
{
    put_offs_flags(seg, IDEMIP_TCP_DOFF_MIN, 0u);
    idemip_wr16(seg + IDEMIP_TCP_OFF_WINDOW, 0xFFFFu);
    uint32_t scaled = (uint32_t)idemip_tcp_window(seg) << IDEMIP_TCP_WS_MAX;
    TEST_ASSERT_TRUE(scaled < 0x40000000u);
    TEST_ASSERT_EQUAL_HEX32(0x40000000u, (uint32_t)1u << (IDEMIP_TCP_WS_MAX + 16u));
}

// --- RFC 7323 sec 3.2, Timestamps -------------------------------------------

// "|Kind=8 | 10 | TS Value (TSval) |TS Echo Reply (TSecr)|", four octets each.
void test_timestamps_option_figure(void)
{
    static const uint8_t opts[12] = {0x08u, 0x0Au, 0x11u, 0x22u, 0x33u, 0x44u,
                                     0x55u, 0x66u, 0x77u, 0x88u, IDEMIP_TCP_OPT_NOP, IDEMIP_TCP_OPT_END};
    put_opts(seg, opts, sizeof opts);
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_TS, w.kind);
    TEST_ASSERT_EQUAL_UINT8(10u, w.len);
    TEST_ASSERT_EQUAL_HEX32(0x11223344u, idemip_tcp_opt_tsval(w.opt));
    TEST_ASSERT_EQUAL_HEX32(0x55667788u, idemip_tcp_opt_tsecr(w.opt));
}

// --- RFC 2018, selective acknowledgment -------------------------------------

// sec 2: "+---------+---------+ | Kind=4 | Length=2| +---------+---------+", two octets and no data.
void test_sack_permitted_option_figure(void)
{
    static const uint8_t opts[4] = {0x04u, 0x02u, IDEMIP_TCP_OPT_NOP, IDEMIP_TCP_OPT_END};
    put_opts(seg, opts, sizeof opts);
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_SACK_PERM, w.kind);
    TEST_ASSERT_EQUAL_UINT8(2u, w.len);
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_tcp_opt_sack_blocks(w.opt));

    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_NOP, w.kind);
}

// sec 3: "Kind: 5", a Left Edge and a Right Edge per block, and "A SACK option that specifies n
// blocks will have a length of 8*n+2 bytes". Four blocks is 34, the most the 40 option bytes hold.
void test_sack_option_blocks(void)
{
    uint8_t opts[40];
    memset(opts, IDEMIP_TCP_OPT_NOP, sizeof opts);
    opts[0] = IDEMIP_TCP_OPT_SACK;
    opts[1] = 34u;
    for (uint8_t i = 0; i < 4u; i++)
    {
        idemip_wr32(opts + 2u + (size_t)i * 8u, 0x1000u * (uint32_t)(i + 1u));
        idemip_wr32(opts + 6u + (size_t)i * 8u, 0x2000u * (uint32_t)(i + 1u));
    }
    put_opts(seg, opts, sizeof opts);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_DOFF_MAX, idemip_tcp_doff(seg));

    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_SACK, w.kind);
    TEST_ASSERT_EQUAL_UINT8(34u, w.len);
    TEST_ASSERT_EQUAL_UINT8(4u, idemip_tcp_opt_sack_blocks(w.opt));
    TEST_ASSERT_EQUAL_size_t(34u, IDEMIP_TCP_SACK_BYTES(4u));
    for (uint8_t i = 0; i < 4u; i++)
    {
        TEST_ASSERT_EQUAL_HEX32(0x1000u * (uint32_t)(i + 1u), idemip_tcp_opt_sack_left(w.opt, i));
        TEST_ASSERT_EQUAL_HEX32(0x2000u * (uint32_t)(i + 1u), idemip_tcp_opt_sack_right(w.opt, i));
    }

    // The six octets after the option are the padding this vector filled with NOPs.
    for (int i = 0; i < 6; i++)
    {
        TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_NOP, w.kind);
    }
    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_FALSE(w.bad);
}

// sec 3: "the 40 bytes available for TCP options can specify a maximum of 4 blocks", and "a maximum
// of 3 SACK blocks will be allowed" alongside the 10-byte Timestamps option and its two pad octets.
void test_sack_block_count_bounds(void)
{
    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_TCP_SACK_BLOCKS_MAX);
    TEST_ASSERT_EQUAL_size_t(34u, IDEMIP_TCP_SACK_BYTES(IDEMIP_TCP_SACK_BLOCKS_MAX));
    TEST_ASSERT_TRUE(IDEMIP_TCP_SACK_BYTES(4u) <= IDEMIP_TCP_OPTS_MAX);
    TEST_ASSERT_TRUE(IDEMIP_TCP_SACK_BYTES(5u) > IDEMIP_TCP_OPTS_MAX);
    // Timestamps at 10 octets plus two NOPs leaves 28, which is three blocks and no more.
    TEST_ASSERT_TRUE(IDEMIP_TCP_SACK_BYTES(3u) + 12u <= IDEMIP_TCP_OPTS_MAX);
    TEST_ASSERT_TRUE(IDEMIP_TCP_SACK_BYTES(4u) + 12u > IDEMIP_TCP_OPTS_MAX);
}

// --- the build helpers -------------------------------------------------------

// Each option built from its own RFC's figure, laid end to end, then read back by the walk. The
// twenty octets make a Data Offset of ten words.
void test_build_a_syn_option_list(void)
{
    uint8_t *o = seg + IDEMIP_TCP_OFF_OPTIONS;
    size_t n = 0;
    n += idemip_tcp_opt_put_mss(o + n, 1460u);
    n += idemip_tcp_opt_put_sack_perm(o + n);
    n += idemip_tcp_opt_put_ts(o + n, 0x00000001u, 0x00000000u);
    n += idemip_tcp_opt_put_nop(o + n);
    n += idemip_tcp_opt_put_ws(o + n, 7u);
    TEST_ASSERT_EQUAL_size_t(20u, n);

    static const uint8_t want[20] = {
        0x02u, 0x04u, 0x05u, 0xB4u,                                    // MSS 1460
        0x04u, 0x02u,                                                  // SACK-permitted
        0x08u, 0x0Au, 0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x00u, // TSval 1, TSecr 0
        0x01u,                                                         // NOP
        0x03u, 0x03u, 0x07u,                                           // WS shift 7
    };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, o, sizeof want);

    put_offs_flags(seg, IDEMIP_TCP_DOFF_FROM_BYTES(IDEMIP_TCP_HDR_LEN + n), IDEMIP_TCP_SYN);
    TEST_ASSERT_EQUAL_UINT8(10u, idemip_tcp_doff(seg));
    TEST_ASSERT_EQUAL_size_t(20u, idemip_tcp_opts_len(seg));

    static const uint8_t want_kind[5] = {IDEMIP_TCP_OPT_MSS, IDEMIP_TCP_OPT_SACK_PERM, IDEMIP_TCP_OPT_TS,
                                         IDEMIP_TCP_OPT_NOP, IDEMIP_TCP_OPT_WS};
    static const uint8_t want_len[5] = {4u, 2u, 10u, 1u, 3u};
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    for (int i = 0; i < 5; i++)
    {
        TEST_ASSERT_TRUE(idemip_tcp_opt_next(&w));
        TEST_ASSERT_EQUAL_UINT8(want_kind[i], w.kind);
        TEST_ASSERT_EQUAL_UINT8(want_len[i], w.len);
    }
    TEST_ASSERT_FALSE(idemip_tcp_opt_next(&w));
    TEST_ASSERT_FALSE(w.bad);
}

// Each helper writes exactly the octets it reports and not one more, so a list is built by
// advancing the pointer by each return. Each is written into a filled region and the fill past the
// reported length must survive.
void test_build_helpers_write_only_what_they_report(void)
{
    uint8_t *o = seg + IDEMIP_TCP_OFF_OPTIONS;
    size_t n = 0;

    memset(o, 0xFFu, 16u);
    n = idemip_tcp_opt_put_end(o);
    TEST_ASSERT_EQUAL_size_t(1u, n);
    TEST_ASSERT_EQUAL_HEX8(0x00u, o[0]);
    TEST_ASSERT_EQUAL_HEX8(0xFFu, o[n]);

    memset(o, 0xFFu, 16u);
    n = idemip_tcp_opt_put_nop(o);
    TEST_ASSERT_EQUAL_size_t(1u, n);
    TEST_ASSERT_EQUAL_HEX8(0x01u, o[0]);
    TEST_ASSERT_EQUAL_HEX8(0xFFu, o[n]);

    memset(o, 0xFFu, 16u);
    n = idemip_tcp_opt_put_mss(o, 536u);
    TEST_ASSERT_EQUAL_size_t(4u, n);
    TEST_ASSERT_EQUAL_UINT16(536u, idemip_tcp_opt_mss(o));
    TEST_ASSERT_EQUAL_HEX8(0xFFu, o[n]);

    memset(o, 0xFFu, 16u);
    n = idemip_tcp_opt_put_ws(o, 0u);
    TEST_ASSERT_EQUAL_size_t(3u, n);
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_tcp_opt_ws(o));
    TEST_ASSERT_EQUAL_HEX8(0xFFu, o[n]);

    memset(o, 0xFFu, 16u);
    n = idemip_tcp_opt_put_sack_perm(o);
    TEST_ASSERT_EQUAL_size_t(2u, n);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_OPT_SACK_PERM, o[IDEMIP_TCP_OPT_OFF_KIND]);
    TEST_ASSERT_EQUAL_UINT8(2u, o[IDEMIP_TCP_OPT_OFF_LEN]);
    TEST_ASSERT_EQUAL_HEX8(0xFFu, o[n]);

    memset(o, 0xFFu, 16u);
    n = idemip_tcp_opt_put_ts(o, 0x11223344u, 0x55667788u);
    TEST_ASSERT_EQUAL_size_t(10u, n);
    TEST_ASSERT_EQUAL_HEX32(0x11223344u, idemip_tcp_opt_tsval(o));
    TEST_ASSERT_EQUAL_HEX32(0x55667788u, idemip_tcp_opt_tsecr(o));
    TEST_ASSERT_EQUAL_HEX8(0xFFu, o[n]);
    TEST_ASSERT_EQUAL_HEX8(0xFFu, o[n + 1u]);
}

// RFC 7323 sec 2.3: the shift count "MUST be limited to 14", so a build never emits a larger one.
void test_build_clamps_the_window_scale_shift(void)
{
    uint8_t *o = seg + IDEMIP_TCP_OFF_OPTIONS;
    TEST_ASSERT_EQUAL_size_t(3u, idemip_tcp_opt_put_ws(o, 14u));
    TEST_ASSERT_EQUAL_UINT8(14u, o[IDEMIP_TCP_OPT_OFF_WS_SHIFT]);
    TEST_ASSERT_EQUAL_size_t(3u, idemip_tcp_opt_put_ws(o, 15u));
    TEST_ASSERT_EQUAL_UINT8(14u, o[IDEMIP_TCP_OPT_OFF_WS_SHIFT]);
    TEST_ASSERT_EQUAL_size_t(3u, idemip_tcp_opt_put_ws(o, 255u));
    TEST_ASSERT_EQUAL_UINT8(14u, o[IDEMIP_TCP_OPT_OFF_WS_SHIFT]);
}

// A list built to the option maximum still has a legal Data Offset, and the walk covers all of it.
void test_build_fills_the_option_maximum(void)
{
    uint8_t *o = seg + IDEMIP_TCP_OFF_OPTIONS;
    size_t n = 0;
    n += idemip_tcp_opt_put_mss(o + n, 1460u);   // 4
    n += idemip_tcp_opt_put_ts(o + n, 1u, 2u);   // 10
    n += idemip_tcp_opt_put_sack_perm(o + n);    // 2
    n += idemip_tcp_opt_put_ws(o + n, 7u);       // 3
    while (n < IDEMIP_TCP_OPTS_MAX)
    {
        n += idemip_tcp_opt_put_nop(o + n);
    }
    TEST_ASSERT_EQUAL_size_t(40u, n);

    put_offs_flags(seg, IDEMIP_TCP_DOFF_FROM_BYTES(IDEMIP_TCP_HDR_LEN + n), IDEMIP_TCP_SYN);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_DOFF_MAX, idemip_tcp_doff(seg));
    TEST_ASSERT_EQUAL_size_t(60u, idemip_tcp_hdr_len(seg));

    size_t stepped = 0;
    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, seg);
    while (idemip_tcp_opt_next(&w))
    {
        stepped += w.len;
    }
    TEST_ASSERT_EQUAL_size_t(40u, stepped);
    TEST_ASSERT_FALSE(w.bad);
}

// --- the checksum, RFC 9293 sec 3.1 Figure 2 --------------------------------

// "zero | PTCL | TCP Length" after the two addresses, and the length "does not count the 12 octets
// of the pseudo-header". Checked against a sum written separately in this file.
void test_pseudo_header_checksum(void)
{
    const uint32_t src = 0x0A000001u; // 10.0.0.1
    const uint32_t dst = 0x0A000002u; // 10.0.0.2
    memcpy(seg, rfc9293_fig1, IDEMIP_TCP_HDR_LEN);
    idemip_wr16(seg + IDEMIP_TCP_OFF_CKSUM, 0u);
    seg[20] = 0xDEu;
    seg[21] = 0xADu;
    seg[22] = 0xBEu;
    seg[23] = 0xEFu;
    const size_t len = 24u;

    uint16_t want = ref_cksum(seg, len, src, dst, (uint16_t)len);
    uint16_t got = idemip_tcp_cksum_compute(seg, len, src, dst);
    TEST_ASSERT_EQUAL_HEX16(want, got);

    // RFC 1071 sec 1: the segment carrying its own checksum sums to all ones, so the complement is
    // zero. Unlike UDP there is no "no checksum" encoding, so the value is written as computed.
    idemip_wr16(seg + IDEMIP_TCP_OFF_CKSUM, got);
    uint32_t sum = idemip_tcp_pseudo_accum(0u, src, dst, (uint16_t)len);
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_cksum_final(idemip_cksum_accum(sum, seg, len)));
}

// RFC 9293 sec 3.1: an odd count is padded "with zeros on its right to form a 16-bit word for
// checksum purposes. The pad is not transmitted as part of the segment." So the span sum over the
// odd length matches the sum over the same span with the zero pad byte counted.
void test_checksum_pads_an_odd_length(void)
{
    const uint32_t src = 0x0A000001u;
    const uint32_t dst = 0x0A000002u;
    memcpy(seg, rfc9293_fig1, IDEMIP_TCP_HDR_LEN);
    idemip_wr16(seg + IDEMIP_TCP_OFF_CKSUM, 0u);
    seg[20] = 0x41u;
    seg[21] = 0x00u; // the pad, which the sum supplies and the wire does not carry

    TEST_ASSERT_EQUAL_HEX32(idemip_cksum_accum(0u, seg, 21u), idemip_cksum_accum(0u, seg, 22u));
    TEST_ASSERT_EQUAL_HEX16(ref_cksum(seg, 21u, src, dst, 21u), idemip_tcp_cksum_compute(seg, 21u, src, dst));
}
