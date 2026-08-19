// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// icmp6_in against RFC 4443 sec 2.4, sec 3 and sec 4.
//
// The shape checks are test_phy's, in the same order:
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. BUSY and ERR are separated by whether retrying can ever succeed, which sec 2.4 (e) and
//      sec 2.4 (f) split exactly: a rule refuses forever, an empty token bucket refills
//
// RFC 4443 prints field diagrams and no numeric example, so there is no vector to copy. Every case
// below asserts a property the text states, quoted at the case.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/icmp/icmp6_in.h"

#include <string.h>
#include <unity.h>

// --- the borrow, the caller's ------------------------------------------------

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_ICMP6_IN_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_ICMP6_IN_BORROW + 16];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_ICMP6_IN_BORROW, CANARY, cap - IDEMIP_ICMP6_IN_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_ICMP6_IN_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_ICMP6_IN_BORROW");
    }
}

// --- the wire ----------------------------------------------------------------
// RFC 3849 reserves 2001:db8::/32 for documentation, so the unicast addresses come out of it.

static const uint8_t HOST6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05};
static const uint8_t PEER6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t IFADDR6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09};
// RFC 4291 sec 2.7.1 link-local all-nodes.
static const uint8_t MCAST6[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t UNSPEC6[16] = {0};

static uint8_t pkt[1600];
static size_t pkt_len;
static uint8_t out[1600];

// One fixed header with the message already placed at pkt + IDEMIP_IPV6_HDR_LEN.
static void put_ip6(const uint8_t *src, const uint8_t *dst, uint8_t nh, size_t payload)
{
    IdemIpIp6BuildArgs a;
    memset(&a, 0, sizeof a);
    a.src = src;
    a.dst = dst;
    a.payload_len = (uint16_t)payload;
    a.next_hdr = nh;
    a.hop_limit = 64u;
    idemip_ip6_build(pkt, &a);
    pkt_len = IDEMIP_IPV6_HDR_LEN + payload;
}

// Seal an ICMPv6 message of @p len octets at pkt + IDEMIP_IPV6_HDR_LEN with the sec 2.3 checksum.
static void seal(size_t len)
{
    uint8_t *m = pkt + IDEMIP_IPV6_HDR_LEN;
    idemip_wr16(m + IDEMIP_ICMP6_OFF_CKSUM, 0u);
    idemip_wr16(m + IDEMIP_ICMP6_OFF_CKSUM,
                idemip_icmp6_cksum_compute(m, len, idemip_ip6_src(pkt), idemip_ip6_dst(pkt)));
}

// An RFC 4443 sec 4.1 Echo Request or sec 4.2 Echo Reply carrying @p data_len octets of 0xA5.
static size_t put_echo6(const uint8_t *src, const uint8_t *dst, uint8_t type, uint16_t id, uint16_t seq,
                        size_t data_len)
{
    uint8_t *m = pkt + IDEMIP_IPV6_HDR_LEN;
    const size_t len = IDEMIP_ICMP6_ECHO_HDR_LEN + data_len;
    idemip_icmp6_hdr_write(m, type, IDEMIP_ICMP6_CODE_ECHO);
    idemip_wr16(m + IDEMIP_ICMP6_OFF_ID, id);
    idemip_wr16(m + IDEMIP_ICMP6_OFF_SEQ, seq);
    memset(m + IDEMIP_ICMP6_ECHO_HDR_LEN, 0xA5, data_len);
    put_ip6(src, dst, IDEMIP_IP6_NH_ICMPV6, len);
    seal(len);
    return len;
}

// An arriving sec 3 error message whose body is a UDP packet, so sec 2.4 (d) retrieves 17.
static size_t put_error6(uint8_t type, uint8_t code, uint32_t word)
{
    uint8_t *m = pkt + IDEMIP_IPV6_HDR_LEN;
    uint8_t *body = m + IDEMIP_ICMP6_ERR_HDR_LEN;
    IdemIpIp6BuildArgs a;
    memset(&a, 0, sizeof a);
    a.src = HOST6;
    a.dst = PEER6;
    a.payload_len = 8u;
    a.next_hdr = IDEMIP_IP6_NH_UDP;
    a.hop_limit = 64u;
    idemip_ip6_build(body, &a);
    memset(body + IDEMIP_IPV6_HDR_LEN, 0x11, 8u);
    const size_t len = IDEMIP_ICMP6_ERR_HDR_LEN + IDEMIP_IPV6_HDR_LEN + 8u;
    idemip_icmp6_hdr_write(m, type, code);
    idemip_wr32(m + IDEMIP_ICMP6_OFF_BODY, word);
    put_ip6(PEER6, HOST6, IDEMIP_IP6_NH_ICMPV6, len);
    seal(len);
    return len;
}

// A whole packet to originate an error about: a UDP one from PEER6 to HOST6.
static void put_victim6(const uint8_t *src, const uint8_t *dst)
{
    memset(pkt + IDEMIP_IPV6_HDR_LEN, 0x33, 16u);
    put_ip6(src, dst, IDEMIP_IP6_NH_UDP, 16u);
}

static void load_recv(uint8_t *w)
{
    Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(w);
    io->recv_args.packet = pkt;
    io->recv_args.len = pkt_len;
    io->recv_args.out = out;
    io->recv_args.out_cap = sizeof out;
    io->recv_args.if_addr = IFADDR6;
    io->recv_args.dst_anycast = IDEMIP_FALSE;
}

// The invoking packet went to one of this node's own unicast addresses, which is RFC 4443 sec 2.2
// (a). Every case sec 2.2 (b) lists is loaded with load_error_foreign below.
static void load_error(uint8_t *w, uint8_t type, uint8_t code)
{
    Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(w);
    io->err_args.invoking = pkt;
    io->err_args.len = pkt_len;
    io->err_args.out = out;
    io->err_args.out_cap = sizeof out;
    io->err_args.if_addr = IFADDR6;
    io->err_args.word = 0u;
    io->err_args.now_ms = 0u;
    io->err_args.type = type;
    io->err_args.code = code;
    io->err_args.link_mcast = IDEMIP_FALSE;
    io->err_args.link_bcast = IDEMIP_FALSE;
    io->err_args.src_anycast = IDEMIP_FALSE;
    io->err_args.dst_local_unicast = IDEMIP_TRUE;
}

// The invoking packet went somewhere sec 2.2 (b) covers: a multicast group, an anycast address the
// node implements, or a unicast address that is not the node's at all.
static void load_error_foreign(uint8_t *w, uint8_t type, uint8_t code)
{
    load_error(w, type, code);
    IDEMIP_ICMP6_IN_IO(w)->err_args.dst_local_unicast = IDEMIP_FALSE;
}

static uint8_t suppress_of(uint8_t *w)
{
    load_error(w, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    Icmp6In.error(w);
    return IDEMIP_ICMP6_IN_IO(w)->suppress;
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(pkt, 0, sizeof pkt);
    memset(out, 0, sizeof out);
    pkt_len = 0;
    Icmp6In.clear(work_a);
    Icmp6In.clear(work_b);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- the borrow --------------------------------------------------------------

void test_every_entry_survives_a_null_borrow(void)
{
    Icmp6In.clear(NULL);
    Icmp6In.recv(NULL);
    Icmp6In.error(NULL);
    TEST_PASS();
}

void test_uncleared_borrow_refuses_work(void)
{
    arm(work_a, sizeof work_a);
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 8u);
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);

    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

// RFC 4443 sec 2.4 (f) allows "up to B error messages to be transmitted in a burst", so a cleared
// borrow starts with a full bucket.
void test_clear_fills_the_token_bucket(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_ERR_BUCKET - 1u, IDEMIP_ICMP6_IN_IO(work_a)->tokens);
}

void test_two_borrows_share_no_byte(void)
{
    IDEMIP_ICMP6_IN_IO(work_a)->recv_args.if_addr = HOST6;
    IDEMIP_ICMP6_IN_IO(work_b)->recv_args.if_addr = PEER6;
    TEST_ASSERT_EQUAL_PTR(HOST6, IDEMIP_ICMP6_IN_IO(work_a)->recv_args.if_addr);
    TEST_ASSERT_EQUAL_PTR(PEER6, IDEMIP_ICMP6_IN_IO(work_b)->recv_args.if_addr);

    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 0x1234u, 7u, 8u);
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(0x1234u, IDEMIP_ICMP6_IN_IO(work_a)->id);

    Icmp6In.recv(work_b); // b was given no packet, so its call is refused
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_b)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(0x1234u, IDEMIP_ICMP6_IN_IO(work_a)->id);
}

// The sec 2.4 (f) bucket lives in the borrow, so draining one leaves the other's full.
void test_the_token_bucket_is_per_borrow(void)
{
    put_victim6(PEER6, HOST6);
    for (unsigned i = 0; i < IDEMIP_ICMP6_ERR_BUCKET; i++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
        Icmp6In.error(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
    }
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ICMP6_IN_IO(work_a)->status);

    load_error(work_b, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    Icmp6In.error(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_b)->status);
}

void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 0xBEEFu, 3u, 16u);
    load_recv(work_a);
    load_recv(work_b);

    Icmp6In.recv(work_a);
    const size_t first = IDEMIP_ICMP6_IN_IO(work_a)->out_len;
    const uint8_t *first_src = IDEMIP_ICMP6_IN_IO(work_a)->src;
    Icmp6In.recv(work_b);
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_size_t(first, IDEMIP_ICMP6_IN_IO(work_a)->out_len);
    TEST_ASSERT_EQUAL_PTR(first_src, IDEMIP_ICMP6_IN_IO(work_a)->src);
}

// --- RFC 4443 sec 4, the echo pair -------------------------------------------

// sec 4.1: "Every node MUST implement an ICMPv6 Echo responder function that receives Echo Requests
// and originates corresponding Echo Replies." sec 4.2 gives the reply Type 129.
void test_an_echo_request_is_answered_with_an_echo_reply(void)
{
    const size_t len = put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 0x0102u, 0x0304u, 20u);
    load_recv(work_a);
    Icmp6In.recv(work_a);

    const Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_REPLY, io->act);
    TEST_ASSERT_EQUAL_size_t(len, io->out_len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_ECHO_REPLY, idemip_icmp6_type(out));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_CODE_ECHO, idemip_icmp6_code(out));
    TEST_ASSERT_EQUAL_HEX16(0x0102u, idemip_icmp6_id(out));
    TEST_ASSERT_EQUAL_HEX16(0x0304u, idemip_icmp6_seq(out));
}

// sec 4.2: "The data received in the ICMPv6 Echo Request message MUST be returned entirely and
// unmodified in the ICMPv6 Echo Reply message."
void test_the_echo_reply_returns_the_data_entirely_and_unmodified(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 64u);
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pkt + IDEMIP_IPV6_HDR_LEN + IDEMIP_ICMP6_ECHO_HDR_LEN,
                                  out + IDEMIP_ICMP6_ECHO_HDR_LEN, 64u);
}

// sec 4.1: "Data: Zero or more octets of arbitrary data."
void test_an_echo_request_with_no_data_is_answered(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 5u, 6u, 0u);
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_REPLY, IDEMIP_ICMP6_IN_IO(work_a)->act);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ECHO_HDR_LEN, IDEMIP_ICMP6_IN_IO(work_a)->out_len);
}

// sec 2.3 prepends the RFC 8200 sec 8.1 pseudo-header, so the reply's checksum only verifies against
// the addresses the reply will carry.
void test_the_echo_reply_checksum_covers_the_pseudo_header(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 13u);
    load_recv(work_a);
    Icmp6In.recv(work_a);

    const Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(work_a);
    uint32_t sum = idemip_ip6_pseudo_accum(0u, io->src, io->dst, (uint32_t)io->out_len, IDEMIP_IP6_NH_ICMPV6);
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_cksum_final(idemip_cksum_accum(sum, out, io->out_len)));
}

// sec 4.2: "The source address of an Echo Reply sent in response to a unicast Echo Request message
// MUST be the same as the destination address of that Echo Request message."
void test_the_reply_to_a_unicast_request_takes_its_destination_as_the_source(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 4u);
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(HOST6, IDEMIP_ICMP6_IN_IO(work_a)->src, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(PEER6, IDEMIP_ICMP6_IN_IO(work_a)->dst, IDEMIP_IP6_ADDR_LEN);
}

// sec 4.2: "An Echo Reply SHOULD be sent in response to an Echo Request message sent to an IPv6
// multicast or anycast address. In this case, the source address of the reply MUST be a unicast
// address belonging to the interface on which the Echo Request message was received."
void test_a_multicast_echo_request_is_answered_from_the_interface_address(void)
{
    put_echo6(PEER6, MCAST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 4u);
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_REPLY, IDEMIP_ICMP6_IN_IO(work_a)->act);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(IFADDR6, IDEMIP_ICMP6_IN_IO(work_a)->src, IDEMIP_IP6_ADDR_LEN);
}

void test_an_anycast_echo_request_is_answered_from_the_interface_address(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 4u);
    load_recv(work_a);
    IDEMIP_ICMP6_IN_IO(work_a)->recv_args.dst_anycast = IDEMIP_TRUE;
    Icmp6In.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_REPLY, IDEMIP_ICMP6_IN_IO(work_a)->act);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(IFADDR6, IDEMIP_ICMP6_IN_IO(work_a)->src, IDEMIP_IP6_ADDR_LEN);
}

// sec 4.2: "Echo Reply messages MUST be passed to the process that originated an Echo Request
// message."
void test_an_arriving_echo_reply_goes_to_the_user(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REPLY, 0x55AAu, 4u, 8u);
    load_recv(work_a);
    Icmp6In.recv(work_a);

    const Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_USER, io->act);
    TEST_ASSERT_EQUAL_size_t(0u, io->out_len);
    TEST_ASSERT_EQUAL_HEX16(0x55AAu, io->id);
}

// sec 4.2 states no truncation, so a buffer that cannot return the data entirely builds nothing, and
// no later call on the same operands succeeds.
void test_recv_refuses_an_out_buffer_short_of_the_whole_reply(void)
{
    const size_t len = put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 64u);
    load_recv(work_a);
    IDEMIP_ICMP6_IN_IO(work_a)->recv_args.out_cap = len - 1u;
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_ICMP6_IN_IO(work_a)->out_len);
}

// sec 2.3 covers the message and the pseudo-header, so a message that does not sum is not the one
// that was sent.
void test_a_bad_checksum_is_discarded(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 8u);
    pkt[IDEMIP_IPV6_HDR_LEN + IDEMIP_ICMP6_OFF_CKSUM] ^= 0xFFu;
    load_recv(work_a);
    Icmp6In.recv(work_a);

    const Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_FALSE(io->cksum_ok);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_DISCARD, io->act);
}

// sec 2.4 (b): "If an ICMPv6 informational message of unknown type is received, it MUST be silently
// discarded."
void test_an_informational_message_of_unknown_type_is_discarded(void)
{
    put_echo6(PEER6, HOST6, 200u, 1u, 1u, 8u); // sec 2.1 reserves 200 for private experimentation
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_DISCARD, IDEMIP_ICMP6_IN_IO(work_a)->act);
    TEST_ASSERT_EQUAL_UINT8(200u, IDEMIP_ICMP6_IN_IO(work_a)->type);
}

// sec 2.4 (a): "If an ICMPv6 error message of unknown type is received at its destination, it MUST be
// passed to the upper-layer process that originated the packet that caused the error".
void test_an_error_message_of_unknown_type_reaches_the_upper_layer(void)
{
    put_error6(100u, 0u, 0u); // sec 2.1 reserves 100 for private experimentation, an error type
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_TRANSPORT, IDEMIP_ICMP6_IN_IO(work_a)->act);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_UDP, IDEMIP_ICMP6_IN_IO(work_a)->proto);
}

// sec 2.4 (d): "the upper-layer protocol type is extracted from the original packet (contained in the
// body of the ICMPv6 error message) and used to select the appropriate upper-layer process".
void test_destination_unreachable_reaches_the_upper_layer_protocol(void)
{
    put_error6((uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH, 0u);
    load_recv(work_a);
    Icmp6In.recv(work_a);

    const Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_TRANSPORT, io->act);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_NH_UDP, io->proto);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_DU_PORT_UNREACH, io->code);
}

// sec 2.4 (d): "In cases where it is not possible to retrieve the upper-layer protocol type from the
// ICMPv6 message, the ICMPv6 message is silently dropped after any IPv6-layer processing."
void test_an_error_whose_body_names_no_upper_layer_is_discarded(void)
{
    uint8_t *m = pkt + IDEMIP_IPV6_HDR_LEN;
    const size_t len = IDEMIP_ICMP6_ERR_HDR_LEN + 4u; // less of the invoking packet than a header
    memset(m + IDEMIP_ICMP6_ERR_HDR_LEN, 0x60, 4u);
    idemip_icmp6_hdr_write(m, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_NO_ROUTE);
    idemip_wr32(m + IDEMIP_ICMP6_OFF_BODY, 0u);
    put_ip6(PEER6, HOST6, IDEMIP_IP6_NH_ICMPV6, len);
    seal(len);
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_DISCARD, IDEMIP_ICMP6_IN_IO(work_a)->act);
}

// sec 3.2: "MTU: The Maximum Transmission Unit of the next-hop link."
void test_packet_too_big_reports_the_mtu(void)
{
    put_error6((uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG, IDEMIP_ICMP6_CODE_PTB, 1400u);
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_UINT32(1400u, IDEMIP_ICMP6_IN_IO(work_a)->mtu);
}

// sec 3.4: "Pointer: Identifies the octet offset within the invoking packet where the error was
// detected."
void test_parameter_problem_reports_the_pointer(void)
{
    put_error6((uint8_t)IDEMIP_ICMP6_PARAMETER_PROBLEM, IDEMIP_ICMP6_PP_UNREC_NEXT_HDR, 40u);
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_UINT32(40u, IDEMIP_ICMP6_IN_IO(work_a)->pointer);
}

// RFC 8200 sec 4: "the first one that is not an extension header indicates that the next item in the
// packet is the corresponding upper-layer header", so the message is found behind the chain.
void test_the_message_is_found_behind_an_extension_header(void)
{
    uint8_t *hop = pkt + IDEMIP_IPV6_HDR_LEN;
    hop[0] = IDEMIP_IP6_NH_ICMPV6;
    hop[1] = 0u; // one 8-octet unit
    hop[2] = IDEMIP_IP6_OPT_PADN;
    hop[3] = 4u;
    uint8_t *m = pkt + IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_EXT_UNIT;
    const size_t msg_len = IDEMIP_ICMP6_ECHO_HDR_LEN + 8u;
    idemip_icmp6_hdr_write(m, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, IDEMIP_ICMP6_CODE_ECHO);
    idemip_wr16(m + IDEMIP_ICMP6_OFF_ID, 0x77u);
    idemip_wr16(m + IDEMIP_ICMP6_OFF_SEQ, 0x88u);
    memset(m + IDEMIP_ICMP6_ECHO_HDR_LEN, 0xA5, 8u);
    put_ip6(PEER6, HOST6, IDEMIP_IP6_NH_HOPOPT, IDEMIP_IP6_EXT_UNIT + msg_len);
    idemip_wr16(m + IDEMIP_ICMP6_OFF_CKSUM, 0u);
    idemip_wr16(m + IDEMIP_ICMP6_OFF_CKSUM,
                idemip_icmp6_cksum_compute(m, msg_len, idemip_ip6_src(pkt), idemip_ip6_dst(pkt)));
    load_recv(work_a);
    Icmp6In.recv(work_a);

    const Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_EXT_UNIT, io->msg_off);
    TEST_ASSERT_EQUAL_size_t(msg_len, io->msg_len);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP6_IN_ACT_REPLY, io->act);
    TEST_ASSERT_EQUAL_HEX16(0x77u, io->id);
}

void test_recv_refuses_a_packet_that_is_not_version_six(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 8u);
    pkt[0] = (uint8_t)(pkt[0] & 0x0Fu); // version 0
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

void test_recv_refuses_a_packet_whose_next_header_is_not_icmpv6(void)
{
    put_victim6(PEER6, HOST6);
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

void test_recv_refuses_a_null_packet_and_a_null_out(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 8u);
    load_recv(work_a);
    IDEMIP_ICMP6_IN_IO(work_a)->recv_args.packet = NULL;
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);

    load_recv(work_a);
    IDEMIP_ICMP6_IN_IO(work_a)->recv_args.out = NULL;
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

// A Payload Length naming more than the caller can read is a truncated packet, not a message.
void test_recv_refuses_a_payload_length_past_the_readable_octets(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 8u);
    idemip_ip6_set_payload_len(pkt, (uint16_t)(IDEMIP_ICMP6_ECHO_HDR_LEN + 200u));
    load_recv(work_a);
    Icmp6In.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

// --- originating an error message --------------------------------------------

// sec 3.1: "A destination node SHOULD originate a Destination Unreachable message with Code 4 in
// response to a packet for which the transport protocol (e.g., UDP) has no listener".
void test_a_port_unreachable_is_built(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    Icmp6In.error(work_a);

    const Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_NONE, io->suppress);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_DEST_UNREACHABLE, idemip_icmp6_type(out));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_DU_PORT_UNREACH, idemip_icmp6_code(out));
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_HDR_LEN + pkt_len, io->out_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pkt, out + IDEMIP_ICMP6_ERR_HDR_LEN, pkt_len);
}

// sec 3.1: "Destination Address: Copied from the Source Address field of the invoking packet", and
// sec 2.2 (a) takes the invoking packet's own destination as the Source Address.
void test_an_error_goes_back_to_the_invoking_source(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_TIME_EXCEEDED, IDEMIP_ICMP6_TE_REASSEMBLY);
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(PEER6, IDEMIP_ICMP6_IN_IO(work_a)->dst, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(HOST6, IDEMIP_ICMP6_IN_IO(work_a)->src, IDEMIP_IP6_ADDR_LEN);
}

// sec 2.2 (b): "If the message is a response to a message sent to any other address, such as - a
// multicast group address, - an anycast address implemented by the node, or - a unicast address that
// does not belong to the node ... the Source Address of the ICMPv6 packet MUST be a unicast address
// belonging to the node."
//
// The last of those three is the one that matters most: a packet this node only forwards toward
// carries a Destination Address that is somebody else's, and copying it into the Source Address of an
// error the node originates puts that party's address on a packet they did not send.
void test_an_error_for_a_destination_that_is_not_the_nodes_uses_the_interface_address(void)
{
    static const uint8_t elsewhere[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x99,
                                                           0,    0,    0,    0,    0, 0, 0, 0x77};
    put_victim6(PEER6, elsewhere);
    load_error_foreign(work_a, (uint8_t)IDEMIP_ICMP6_TIME_EXCEEDED, IDEMIP_ICMP6_TE_HOP_LIMIT);
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(PEER6, IDEMIP_ICMP6_IN_IO(work_a)->dst, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(IFADDR6, IDEMIP_ICMP6_IN_IO(work_a)->src, IDEMIP_IP6_ADDR_LEN,
                                          "sec 2.2 (b) requires a unicast address belonging to the node");
}

// The same rule over the anycast case sec 2.2 (b) names in its own words. An anycast address the node
// implements is reachable at this node, so the destination is not "somebody else's" - and sec 2.2 (b)
// still bars it, because the Source Address must be a unicast address.
void test_an_error_for_an_anycast_destination_uses_the_interface_address(void)
{
    static const uint8_t anycast[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                                         0,    0,    0,    0,    0, 0, 0, 0};
    put_victim6(PEER6, anycast);
    load_error_foreign(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_ADDR_UNREACH);
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(IFADDR6, IDEMIP_ICMP6_IN_IO(work_a)->src, IDEMIP_IP6_ADDR_LEN,
                                          "an anycast address is not a unicast address of the node");
}

// sec 2.3, over the message the caller will send between those two addresses.
void test_an_error_checksum_covers_the_pseudo_header(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_ADDR_UNREACH);
    Icmp6In.error(work_a);

    const Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(work_a);
    uint32_t sum = idemip_ip6_pseudo_accum(0u, io->src, io->dst, (uint32_t)io->out_len, IDEMIP_IP6_NH_ICMPV6);
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_cksum_final(idemip_cksum_accum(sum, out, io->out_len)));
}

// sec 2.4 (c): "Every ICMPv6 error message (type < 128) MUST include as much of the IPv6 offending
// (invoking) packet ... as possible without making the error message packet exceed the minimum IPv6
// MTU".
void test_the_quote_is_clamped_to_the_minimum_ipv6_mtu(void)
{
    memset(pkt + IDEMIP_IPV6_HDR_LEN, 0x33, 1400u);
    put_ip6(PEER6, HOST6, IDEMIP_IP6_NH_UDP, 1400u);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG, IDEMIP_ICMP6_CODE_PTB);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.word = 1280u;
    Icmp6In.error(work_a);

    const Icmp6InIo *io = IDEMIP_ICMP6_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_HDR_LEN + IDEMIP_ICMP6_ERR_QUOTE_MAX, io->out_len);
    TEST_ASSERT_TRUE(IDEMIP_IPV6_HDR_LEN + io->out_len <= IDEMIP_IPV6_MIN_MTU);
}

// A type outside sec 3 is a bad argument rather than a suppression.
void test_error_refuses_a_type_outside_section_three(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 0u);
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_NONE, IDEMIP_ICMP6_IN_IO(work_a)->suppress);
}

void test_error_refuses_a_buffer_short_of_the_message(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.out_cap = IDEMIP_ICMP6_ERR_HDR_LEN + 4u;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_ICMP6_IN_IO(work_a)->out_len);
}

void test_error_refuses_a_null_invoking_packet_and_a_null_out(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.invoking = NULL;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);

    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.out = NULL;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

// --- RFC 4443 sec 2.4 (e), one case per rule ---------------------------------

// (e.1) "An ICMPv6 error message."
void test_no_error_about_an_icmpv6_error_message(void)
{
    put_error6((uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_NO_ROUTE, 0u);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_ERROR, suppress_of(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_ICMP6_IN_IO(work_a)->out_len);
}

// sec 2.1 sorts the two classes by the high-order bit, so an informational message is not an error
// and (e.1) does not reach it.
void test_an_error_about_an_icmpv6_echo_request_is_allowed(void)
{
    put_echo6(PEER6, HOST6, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, 1u, 1u, 8u);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_NONE, suppress_of(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

// (e.2) "An ICMPv6 redirect message [IPv6-DISC].", which RFC 4861 sec 4.5 gives Type 137.
void test_no_error_about_a_redirect(void)
{
    put_echo6(PEER6, HOST6, IDEMIP_ICMP6_IN_ND_REDIRECT, 0u, 0u, 32u);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_REDIRECT, suppress_of(work_a));
}

// (e.3) "A packet destined to an IPv6 multicast address."
void test_no_error_about_a_multicast_destination(void)
{
    put_victim6(PEER6, MCAST6);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_DST_MCAST, suppress_of(work_a));
}

// (e.3) exception (1): "the Packet Too Big Message (Section 3.2) to allow Path MTU discovery to work
// for IPv6 multicast".
void test_packet_too_big_is_allowed_to_a_multicast_destination(void)
{
    put_victim6(PEER6, MCAST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG, IDEMIP_ICMP6_CODE_PTB);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.word = 1280u;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_NONE, IDEMIP_ICMP6_IN_IO(work_a)->suppress);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

// sec 2.2 (b): a reply to a packet sent to a multicast address takes "a unicast address belonging to
// the node" as its Source Address.
void test_the_multicast_exception_sources_the_error_from_the_interface(void)
{
    put_victim6(PEER6, MCAST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG, IDEMIP_ICMP6_CODE_PTB);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.word = 1280u;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(IFADDR6, IDEMIP_ICMP6_IN_IO(work_a)->src, IDEMIP_IP6_ADDR_LEN);
}

// One hop-by-hop option whose Option Type carries the action bits @p action, and a Pointer naming its
// Option Type octet, which is what (e.3) exception (2) reads.
static void put_option_victim(const uint8_t *dst, uint8_t action)
{
    uint8_t *hop = pkt + IDEMIP_IPV6_HDR_LEN;
    hop[0] = IDEMIP_IP6_NH_NONE;
    hop[1] = 0u;
    hop[2] = action;
    hop[3] = 4u;
    memset(hop + 4, 0, 4u);
    put_ip6(PEER6, dst, IDEMIP_IP6_NH_HOPOPT, IDEMIP_IP6_EXT_UNIT);
}

// (e.3) exception (2): "the Parameter Problem Message, Code 2 (Section 3.4) reporting an unrecognized
// IPv6 option (see Section 4.2 of [IPv6]) that has the Option Type highest-order two bits set to 10".
void test_parameter_problem_code_two_is_allowed_for_an_option_typed_ten(void)
{
    put_option_victim(MCAST6, IDEMIP_IP6_OPT_ACT_DISCARD_ICMP);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_PARAMETER_PROBLEM, IDEMIP_ICMP6_PP_UNREC_OPTION);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.word = IDEMIP_IPV6_HDR_LEN + 2u;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_NONE, IDEMIP_ICMP6_IN_IO(work_a)->suppress);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

// RFC 8200 sec 4.2's "11" action sends the same message "only if the packet's Destination Address was
// not a multicast address", so the exception is not this one and (e.3) stands.
void test_parameter_problem_code_two_is_refused_for_an_option_typed_eleven(void)
{
    put_option_victim(MCAST6, IDEMIP_IP6_OPT_ACT_DISCARD_UNI);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_PARAMETER_PROBLEM, IDEMIP_ICMP6_PP_UNREC_OPTION);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.word = IDEMIP_IPV6_HDR_LEN + 2u;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_DST_MCAST, IDEMIP_ICMP6_IN_IO(work_a)->suppress);
}

// The same option to a unicast destination is answered whatever the action bits are.
void test_parameter_problem_code_two_is_allowed_to_a_unicast_destination(void)
{
    put_option_victim(HOST6, IDEMIP_IP6_OPT_ACT_DISCARD_UNI);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_PARAMETER_PROBLEM, IDEMIP_ICMP6_PP_UNREC_OPTION);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.word = IDEMIP_IPV6_HDR_LEN + 2u;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_NONE, IDEMIP_ICMP6_IN_IO(work_a)->suppress);
}

// (e.4) "A packet sent as a link-layer multicast"
void test_no_error_about_a_link_layer_multicast(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.link_mcast = IDEMIP_TRUE;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_LINK_MCAST, IDEMIP_ICMP6_IN_IO(work_a)->suppress);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

// (e.5) "A packet sent as a link-layer broadcast"
void test_no_error_about_a_link_layer_broadcast(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.link_bcast = IDEMIP_TRUE;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_LINK_BCAST, IDEMIP_ICMP6_IN_IO(work_a)->suppress);
}

// "(the exceptions from e.3 apply to this case, too)", stated for both (e.4) and (e.5).
void test_the_link_layer_exceptions_carry_from_e3(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG, IDEMIP_ICMP6_CODE_PTB);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.word = 1280u;
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.link_mcast = IDEMIP_TRUE;
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.link_bcast = IDEMIP_TRUE;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_NONE, IDEMIP_ICMP6_IN_IO(work_a)->suppress);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

// (e.6) "the IPv6 Unspecified Address"
void test_no_error_about_an_unspecified_source(void)
{
    put_victim6(UNSPEC6, HOST6);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_SRC, suppress_of(work_a));
}

// (e.6) "an IPv6 multicast address"
void test_no_error_about_a_multicast_source(void)
{
    put_victim6(MCAST6, HOST6);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_SRC, suppress_of(work_a));
}

// (e.6) "an address known by the ICMP message originator to be an IPv6 anycast address"
void test_no_error_about_a_known_anycast_source(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.src_anycast = IDEMIP_TRUE;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_SRC, IDEMIP_ICMP6_IN_IO(work_a)->suppress);
}

// The (e) rules refuse forever, so a retry with the same operands never becomes OK, and never BUSY.
void test_a_suppressed_error_never_becomes_ok_or_busy_on_a_retry(void)
{
    put_victim6(PEER6, MCAST6);
    for (int i = 0; i < 4; i++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
        IDEMIP_ICMP6_IN_IO(work_a)->err_args.now_ms = (uint32_t)(i * 1000);
        Icmp6In.error(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP6_IN_IO(work_a)->status);
    }
}

// A rule refusal never spends a token: sec 2.4 (f) limits what is originated, and nothing was.
void test_a_suppressed_error_spends_no_token(void)
{
    put_victim6(PEER6, MCAST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_ERR_BUCKET, IDEMIP_ICMP6_IN_IO(work_a)->tokens);
}

// --- RFC 4443 sec 2.4 (f), the rate limit ------------------------------------

// "allowing up to B error messages to be transmitted in a burst, as long as the long-term average is
// not exceeded", so the B+1st in the same millisecond makes no progress now.
void test_the_bucket_allows_a_burst_of_b_and_then_reports_busy(void)
{
    put_victim6(PEER6, HOST6);
    for (unsigned i = 0; i < IDEMIP_ICMP6_ERR_BUCKET; i++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
        Icmp6In.error(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status,
                                      "the burst RFC 4443 sec 2.4 (f) allows was cut short");
    }
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_IN_SUPPRESS_RATE, IDEMIP_ICMP6_IN_IO(work_a)->suppress);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ICMP6_IN_IO(work_a)->tokens);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_ICMP6_IN_IO(work_a)->out_len);
}

// BUSY means a retry can succeed later, and the clock is what makes it so: one token lands every
// IDEMIP_ICMP6_ERR_TOKEN_MS. This is the line between BUSY and ERR.
void test_a_token_refills_and_the_retry_succeeds(void)
{
    put_victim6(PEER6, HOST6);
    for (unsigned i = 0; i <= IDEMIP_ICMP6_ERR_BUCKET; i++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
        Icmp6In.error(work_a);
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ICMP6_IN_IO(work_a)->status);

    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.now_ms = IDEMIP_ICMP6_ERR_TOKEN_MS - 1u;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ICMP6_IN_IO(work_a)->status);

    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.now_ms = IDEMIP_ICMP6_ERR_TOKEN_MS;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
}

// A gap of a whole bucket or longer refills it, and the count stops at B rather than running past it.
void test_a_long_gap_refills_the_bucket_to_b_and_no_further(void)
{
    put_victim6(PEER6, HOST6);
    for (unsigned i = 0; i <= IDEMIP_ICMP6_ERR_BUCKET; i++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
        Icmp6In.error(work_a);
    }
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    IDEMIP_ICMP6_IN_IO(work_a)->err_args.now_ms = 1000000u;
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_ERR_BUCKET - 1u, IDEMIP_ICMP6_IN_IO(work_a)->tokens);
}

// The average sec 2.4 (f) holds to is N per second: ten tokens over ten intervals is one burst again.
void test_the_long_term_average_is_n_per_second(void)
{
    put_victim6(PEER6, HOST6);
    for (unsigned i = 0; i <= IDEMIP_ICMP6_ERR_BUCKET; i++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
        Icmp6In.error(work_a);
    }
    // One token per interval, and no more than one.
    for (unsigned i = 1; i <= IDEMIP_ICMP6_ERR_BUCKET; i++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
        IDEMIP_ICMP6_IN_IO(work_a)->err_args.now_ms = i * IDEMIP_ICMP6_ERR_TOKEN_MS;
        Icmp6In.error(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP6_IN_IO(work_a)->status);

        load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
        IDEMIP_ICMP6_IN_IO(work_a)->err_args.now_ms = i * IDEMIP_ICMP6_ERR_TOKEN_MS;
        Icmp6In.error(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ICMP6_IN_IO(work_a)->status);
    }
}

// An error the rules allow is built the same way however many times it is asked for, once a token is
// there for it.
void test_a_built_error_repeats(void)
{
    put_victim6(PEER6, HOST6);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    Icmp6In.error(work_a);
    const size_t first = IDEMIP_ICMP6_IN_IO(work_a)->out_len;
    uint8_t copy[128];
    memcpy(copy, out, first);

    memset(out, 0, sizeof out);
    load_error(work_a, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH);
    Icmp6In.error(work_a);
    TEST_ASSERT_EQUAL_size_t(first, IDEMIP_ICMP6_IN_IO(work_a)->out_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(copy, out, first);
}
