// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for ip6_forward. The storage half tests the CONTRACT, not the RFC 8200 behavior:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_IP6_FORWARD_BORROW is intact after every case
//   5. the published offsets are ordered, sized and non-overlapping
//   6. a borrow clear has not run on is refused, and clear leaves the operand block alone
//
// The behavior half drives the addresses the RFCs print. RFC 8200 prints none, so its Hop Limit and
// packet size rules are asserted as the properties sec 3 and sec 5 state. RFC 4291 does print:
//
//   sec 2.5.2 "The address 0:0:0:0:0:0:0:0 is called the unspecified address"
//   sec 2.5.3 "The unicast address 0:0:0:0:0:0:0:1 is called the loopback address"
//   sec 2.5.6 the Link-Local format, 1111111010 then 54 zero bits then the interface ID
//   sec 2.7.1 the NTP servers group example, FF01:0:0:0:0:0:0:101, FF02::101, FF05::101 and
//             FF0E::101, which is a printed vector for every multicast scope this unit separates
//
// The unicast addresses are RFC 3849's 2001:DB8::/32, "a reserved prefix for use in documentation".
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/ip/ip6_forward.h"

#include <string.h>
#include <unity.h>

#define CANARY 0x5Au
#define DIRT 0xCCu

static _Alignas(8) uint8_t work_a[IDEMIP_IP6_FORWARD_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_IP6_FORWARD_BORROW + 16];

// One packet, built where the suite can reach it. 1500 octets is an Ethernet payload, so a case that
// claims a long packet is claiming octets that are really there.
static uint8_t g_pkt[1500];

// RFC 3849 sec 4: 2001:DB8::/32, "for use in documentation".
static const uint8_t DOC_HOST_A[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x10};
static const uint8_t DOC_HOST_B[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0x05};
static const uint8_t DOC_ROUTER[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x01};

// RFC 4291 sec 2.5.2 and sec 2.5.3.
static const uint8_t UNSPECIFIED[16] = {0};
static const uint8_t LOOPBACK[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

// RFC 4291 sec 2.5.6, FE80::/10.
static const uint8_t LINK_LOCAL_A[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t LINK_LOCAL_B[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

// RFC 4291 sec 2.7.1's NTP servers group at each scope, plus the sec 2.7 reserved scope 0.
static const uint8_t MCAST_SCOP0[16] = {0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01};
static const uint8_t MCAST_IFACE[16] = {0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01};
static const uint8_t MCAST_LINK[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01};
static const uint8_t MCAST_SITE[16] = {0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01};
static const uint8_t MCAST_GLOBAL[16] = {0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01};

// RFC 4861 sec 4.5: the Redirect Message Type, which RFC 4443 sec 2.4 (e.2) suppresses errors for.
#define ICMP6_REDIRECT 137u

// RFC 8200 sec 3 gives the Hop Limit eight bits; 64 is the value the RFC 1812 sec 4.2.2.9 discussion
// calls common, and nothing in RFC 8200 revises it.
#define HOP_COMMON 64u

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP6_FORWARD_BORROW, CANARY, cap - IDEMIP_IP6_FORWARD_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP6_FORWARD_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP6_FORWARD_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_pkt, 0, sizeof g_pkt);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- building a packet --------------------------------------------------------

// An RFC 8200 sec 3 header and @p payload_len octets after it. Returns the whole packet length.
static size_t build6(const uint8_t *src, const uint8_t *dst, uint8_t hop, uint8_t next_hdr, uint16_t payload_len)
{
    IdemIpIp6BuildArgs a;
    a.src = src;
    a.dst = dst;
    a.flow_label = 0u;
    a.payload_len = payload_len;
    a.traffic_class = 0u;
    a.next_hdr = next_hdr;
    a.hop_limit = hop;
    idemip_ip6_build(g_pkt, &a);
    return (size_t)IDEMIP_IPV6_HDR_LEN + (size_t)payload_len;
}

static size_t build_plain(const uint8_t *src, const uint8_t *dst, uint8_t hop)
{
    return build6(src, dst, hop, (uint8_t)IDEMIP_IP6_NH_TCP, 0u);
}

// A packet whose upper layer is ICMPv6, with @p type in the Type octet RFC 4443 sec 2.1 puts first.
static size_t build_icmp6(const uint8_t *src, const uint8_t *dst, uint8_t hop, uint8_t type)
{
    size_t len = build6(src, dst, hop, (uint8_t)IDEMIP_IP6_NH_ICMPV6, (uint16_t)IDEMIP_ICMP6_HDR_LEN);
    g_pkt[IDEMIP_IP6_OFF_PAYLOAD + IDEMIP_ICMP6_OFF_TYPE] = type;
    return len;
}

// The default operand set: a routed unicast leaving a second interface, so no scope rule and no
// Redirect condition is in play unless a case sets one.
static void args_default(uint8_t *w, size_t len)
{
    Ip6ForwardArgs *a = &IDEMIP_IP6_FORWARD_IO(w)->fwd_args;
    memset(a, 0, sizeof *a);
    a->hdr = g_pkt;
    a->len = len;
    a->next_hop = DOC_ROUTER;
    a->out_mtu = 1500u;
    a->in_netif = 0u;
    a->out_netif = 1u;
    a->routed = IDEMIP_TRUE;
}

static void clear_ok(uint8_t *w)
{
    Ip6Forward.clear(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_FORWARD_IO(w)->status);
}

// --- the borrow ---------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Ip6Forward.clear(NULL);
    Ip6Forward.decide(NULL);
    TEST_PASS();
}

// The borrow IS the forwarder, and the operand block is in it, so two forwarders share no byte.
void test_two_borrows_share_no_byte(void)
{
    clear_ok(work_a);
    // b is never cleared, so it refuses while a works, on the same packet and the same operands.
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    args_default(work_b, len);

    Ip6Forward.decide(work_a);
    Ip6Forward.decide(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_FORWARD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FORWARD_IO(work_b)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, IDEMIP_IP6_FORWARD_IO(work_a)->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_DISCARD, IDEMIP_IP6_FORWARD_IO(work_b)->action);
}

// A decision is a function of its borrow alone, so a call interleaved on another borrow cannot
// change what this one reports.
void test_a_decision_is_a_function_of_its_borrow_alone(void)
{
    clear_ok(work_a);
    clear_ok(work_b);

    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    uint8_t first = IDEMIP_IP6_FORWARD_IO(work_a)->hop_limit;

    (void)build_plain(DOC_HOST_B, DOC_HOST_A, 3u);
    args_default(work_b, IDEMIP_IPV6_HDR_LEN);
    Ip6Forward.decide(work_b);

    (void)build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_UINT8(first, IDEMIP_IP6_FORWARD_IO(work_a)->hop_limit);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_IP6_FORWARD_IO(work_b)->hop_limit);
}

// A borrow clear has not run on carries no mark, so decide refuses it.
void test_an_uncleared_borrow_is_refused(void)
{
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FORWARD_IO(work_a)->status);
}

// The operand block is the caller's, so clear touches nothing in it but the status.
void test_clear_leaves_the_operand_block_alone(void)
{
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_pkt, IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.hdr);
    TEST_ASSERT_EQUAL_size_t(len, IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.len);
    TEST_ASSERT_EQUAL_PTR(DOC_ROUTER, IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.next_hop);
}

// clear works on a borrow full of anything, so a second run leaves the same usable state.
void test_clear_reclaims_a_dirty_borrow(void)
{
    memset(work_a, DIRT, IDEMIP_IP6_FORWARD_BORROW);
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, IDEMIP_IP6_FORWARD_IO(work_a)->action);
}

// The published map is ordered, the context lies past the operand block, and the whole map fits.
void test_the_offset_map_is_ordered_and_fits(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP6_FORWARD_OFF_IO);
    TEST_ASSERT_TRUE((size_t)IDEMIP_IP6_FORWARD_OFF_CTX >= sizeof(Ip6ForwardIo));
    TEST_ASSERT_TRUE((size_t)IDEMIP_IP6_FORWARD_OFF_CTX < (size_t)IDEMIP_IP6_FORWARD_BORROW);
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP6_FORWARD_OFF_CTX & 7u);
    TEST_ASSERT_EQUAL_PTR(work_a, IDEMIP_IP6_FORWARD_IO(work_a));
}

// --- the forward --------------------------------------------------------------

void test_a_routed_packet_is_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);

    Ip6ForwardIo *io = IDEMIP_IP6_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_OK, io->reason);
    TEST_ASSERT_EQUAL_PTR(DOC_ROUTER, io->next_hop);
    TEST_ASSERT_EQUAL_UINT8(1u, io->netif);
    TEST_ASSERT_FALSE(io->icmp);
    TEST_ASSERT_FALSE(io->redirect);
}

// RFC 8200 sec 3 of the Hop Limit: "Decremented by 1 by each node that forwards the packet."
void test_the_hop_limit_is_decremented_by_one(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)(HOP_COMMON - 1u), IDEMIP_IP6_FORWARD_IO(work_a)->hop_limit);

    // And the packet itself is untouched: this unit reports the value, the caller writes it.
    TEST_ASSERT_EQUAL_UINT8((uint8_t)HOP_COMMON, idemip_ip6_hop_limit(g_pkt));
}

// RFC 8200 sec 3: "the packet is discarded if ... [the Hop Limit] is decremented to zero." RFC 4443
// sec 3.3: the router "MUST discard the packet and originate an ICMPv6 Time Exceeded message with
// Code 0".
void test_a_hop_limit_of_one_expires_with_time_exceeded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, 1u);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);

    Ip6ForwardIo *io = IDEMIP_IP6_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_HOP_LIMIT, io->reason);
    TEST_ASSERT_TRUE(io->icmp);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP6_TIME_EXCEEDED, io->icmp_type);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP6_TE_HOP_LIMIT, io->icmp_code);
}

// RFC 8200 sec 3: "the packet is discarded if Hop Limit was zero when received". RFC 4443 sec 3.3
// answers it the same way: "If a router receives a packet with a Hop Limit of zero ... it MUST
// discard the packet and originate an ICMPv6 Time Exceeded message with Code 0."
void test_a_hop_limit_of_zero_expires_too(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, 0u);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);

    Ip6ForwardIo *io = IDEMIP_IP6_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_HOP_LIMIT, io->reason);
    TEST_ASSERT_EQUAL_UINT8(0u, io->hop_limit);
    TEST_ASSERT_TRUE(io->icmp);
}

// RFC 4443 sec 3.1 Code 0, "No route to destination".
void test_no_route_answers_destination_unreachable_code_zero(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.routed = IDEMIP_FALSE;
    Ip6Forward.decide(work_a);

    Ip6ForwardIo *io = IDEMIP_IP6_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_NO_ROUTE, io->reason);
    TEST_ASSERT_TRUE(io->icmp);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, io->icmp_type);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP6_DU_NO_ROUTE, io->icmp_code);
}

// --- the packet size, RFC 8200 sec 4.5 and sec 5 ------------------------------

// RFC 8200 sec 4.5: "fragmentation in IPv6 is performed only by source nodes, not by routers along a
// packet's delivery path". RFC 4443 sec 3.2: "A Packet Too Big MUST be sent by a router in response
// to a packet that it cannot forward because the packet is larger than the MTU of the outgoing
// link", and its MTU field is "The Maximum Transmission Unit of the next-hop link".
void test_a_packet_larger_than_the_link_answers_packet_too_big(void)
{
    clear_ok(work_a);
    size_t len = build6(DOC_HOST_A, DOC_HOST_B, HOP_COMMON, (uint8_t)IDEMIP_IP6_NH_TCP, 1400u);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.out_mtu = (uint16_t)IDEMIP_IPV6_MIN_MTU;
    Ip6Forward.decide(work_a);

    Ip6ForwardIo *io = IDEMIP_IP6_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_TOO_BIG, io->reason);
    TEST_ASSERT_TRUE(io->icmp);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG, io->icmp_type);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP6_CODE_PTB, io->icmp_code);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_IPV6_MIN_MTU, io->mtu);
}

// A packet exactly the size of the link's MTU is not too big.
void test_a_packet_the_size_of_the_link_mtu_is_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build6(DOC_HOST_A, DOC_HOST_B, HOP_COMMON, (uint8_t)IDEMIP_IP6_NH_TCP,
                        (uint16_t)(IDEMIP_IPV6_MIN_MTU - IDEMIP_IPV6_HDR_LEN));
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.out_mtu = (uint16_t)IDEMIP_IPV6_MIN_MTU;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, IDEMIP_IP6_FORWARD_IO(work_a)->action);
}

// RFC 4443 sec 3.2: "Originating a Packet Too Big Message makes an exception to one of the rules as
// to when to originate an ICMPv6 error message. Unlike other messages, it is sent in response to a
// packet received with an IPv6 multicast destination address, or with a link-layer multicast or
// link-layer broadcast address."
void test_packet_too_big_is_sent_even_to_a_multicast_destination(void)
{
    clear_ok(work_a);
    size_t len = build6(DOC_HOST_A, MCAST_GLOBAL, HOP_COMMON, (uint8_t)IDEMIP_IP6_NH_TCP, 1400u);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.out_mtu = (uint16_t)IDEMIP_IPV6_MIN_MTU;
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.ll_multicast = IDEMIP_TRUE;
    Ip6Forward.decide(work_a);

    Ip6ForwardIo *io = IDEMIP_IP6_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_TOO_BIG, io->reason);
    TEST_ASSERT_TRUE(io->icmp);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG, io->icmp_type);
}

// RFC 4443 sec 2.4 (e.3): the same multicast destination suppresses every other error.
void test_a_multicast_destination_gets_no_time_exceeded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, MCAST_GLOBAL, 1u);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);

    Ip6ForwardIo *io = IDEMIP_IP6_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_HOP_LIMIT, io->reason);
    TEST_ASSERT_FALSE(io->icmp);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP6_FORWARD_ICMP_NONE, io->icmp_type);
}

// RFC 4443 sec 2.4 (e.4): "A packet sent as a link-layer multicast."
void test_a_link_layer_multicast_gets_no_time_exceeded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, 1u);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.ll_multicast = IDEMIP_TRUE;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_HOP_LIMIT, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FORWARD_IO(work_a)->icmp);
}

// RFC 4443 sec 2.4 (e.5): "A packet sent as a link-layer broadcast."
void test_a_link_layer_broadcast_gets_no_time_exceeded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, 1u);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.ll_broadcast = IDEMIP_TRUE;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FORWARD_IO(work_a)->icmp);
}

// --- the addresses, RFC 4291 --------------------------------------------------

// sec 2.5.2: "An IPv6 packet with a source address of unspecified must never be forwarded by an IPv6
// router."
void test_an_unspecified_source_is_never_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(UNSPECIFIED, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_DISCARD, IDEMIP_IP6_FORWARD_IO(work_a)->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_SRC_UNSPEC, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
}

// sec 2.7: "Multicast addresses must not be used as source addresses in IPv6 packets."
void test_a_multicast_source_is_never_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(MCAST_GLOBAL, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_SRC_MCAST, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
}

// sec 2.5.3: "The loopback address must not be used as the source address in IPv6 packets that are
// sent outside of a single node."
void test_a_loopback_source_is_never_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(LOOPBACK, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_SRC_LOOP, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
}

// sec 2.5.2: "The unspecified address must not be used as the destination address of IPv6 packets."
void test_an_unspecified_destination_is_never_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, UNSPECIFIED, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_DST_UNSPEC, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
}

// sec 2.5.3: "An IPv6 packet with a destination address of loopback ... must never be forwarded by an
// IPv6 router."
void test_a_loopback_destination_is_never_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, LOOPBACK, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_DST_LOOP, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
}

// sec 2.5.6: "Routers must not forward any packets with Link-Local source or destination addresses to
// other links."
void test_a_link_local_destination_is_not_forwarded_to_another_link(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, LINK_LOCAL_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_DISCARD, IDEMIP_IP6_FORWARD_IO(work_a)->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_LINK_LOCAL, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
}

void test_a_link_local_source_is_not_forwarded_to_another_link(void)
{
    clear_ok(work_a);
    size_t len = build_plain(LINK_LOCAL_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_LINK_LOCAL, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
}

// The same sentence bars only "other links", so a packet leaving the interface it arrived on is not
// crossing one.
void test_a_link_local_packet_stays_on_its_own_link(void)
{
    clear_ok(work_a);
    size_t len = build_plain(LINK_LOCAL_A, LINK_LOCAL_B, HOP_COMMON);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.out_netif = 0u;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, IDEMIP_IP6_FORWARD_IO(work_a)->action);
}

// --- multicast scope, RFC 4291 sec 2.7 ----------------------------------------

// "Nodes must not originate a packet to a multicast address whose scop field contains the reserved
// value 0; if such a packet is received, it must be silently dropped."
void test_a_reserved_scope_multicast_is_silently_dropped(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, MCAST_SCOP0, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_DISCARD, IDEMIP_IP6_FORWARD_IO(work_a)->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_SCOPE, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FORWARD_IO(work_a)->icmp);
}

// sec 2.7.1's FF01::101 means "all NTP servers on the same interface (i.e., the same node) as the
// sender", and sec 2.7: "Interface-Local scope spans only a single interface on a node".
void test_an_interface_local_multicast_is_never_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, MCAST_IFACE, HOP_COMMON);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.out_netif = 0u;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_SCOPE, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
}

// sec 2.7.1's FF02::101 means "all NTP servers on the same link as the sender", so it does not cross
// to another link.
void test_a_link_local_multicast_does_not_cross_a_link(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, MCAST_LINK, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_SCOPE, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
}

// sec 2.7.1's FF05::101 means "all NTP servers in the same site as the sender", which spans more than
// one link.
void test_a_site_local_multicast_crosses_a_link(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, MCAST_SITE, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, IDEMIP_IP6_FORWARD_IO(work_a)->action);
}

// sec 2.7.1's FF0E::101 means "all NTP servers in the Internet".
void test_a_global_multicast_crosses_a_link(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, MCAST_GLOBAL, HOP_COMMON);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, IDEMIP_IP6_FORWARD_IO(work_a)->action);
}

// --- when no ICMPv6 may be sent, RFC 4443 sec 2.4 (e) -------------------------

// (e.1) "An ICMPv6 error message." sec 2.1 makes every type below 128 one.
void test_an_icmpv6_error_draws_no_icmpv6_error(void)
{
    clear_ok(work_a);
    size_t len = build_icmp6(DOC_HOST_A, DOC_HOST_B, 1u, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_HOP_LIMIT, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FORWARD_IO(work_a)->icmp);
}

// (e.2) "An ICMPv6 redirect message", which RFC 4861 sec 4.5 numbers 137, above the sec 2.1 error
// range and so needing its own bullet.
void test_an_icmpv6_redirect_draws_no_icmpv6_error(void)
{
    clear_ok(work_a);
    size_t len = build_icmp6(DOC_HOST_A, DOC_HOST_B, 1u, ICMP6_REDIRECT);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FORWARD_IO(work_a)->icmp);
}

// An informational message that is not a redirect is not on the list, so the error is still sent.
void test_an_icmpv6_echo_still_draws_the_error(void)
{
    clear_ok(work_a);
    size_t len = build_icmp6(DOC_HOST_A, DOC_HOST_B, 1u, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP6_FORWARD_IO(work_a)->icmp);
}

// --- the header ---------------------------------------------------------------

// RFC 8200 sec 3: "Version 4-bit Internet Protocol version number = 6."
void test_a_wrong_version_is_discarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    g_pkt[0] = (uint8_t)((g_pkt[0] & 0x0Fu) | 0x40u);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_FORWARD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_HEADER, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FORWARD_IO(work_a)->icmp);
}

// RFC 8200 sec 3: the Payload Length is "the rest of the packet following this header, in octets", so
// one naming more octets than the link delivered is not a packet this router can act on.
void test_a_payload_length_past_the_span_is_discarded(void)
{
    clear_ok(work_a);
    (void)build6(DOC_HOST_A, DOC_HOST_B, HOP_COMMON, (uint8_t)IDEMIP_IP6_NH_TCP, 100u);
    args_default(work_a, IDEMIP_IPV6_HDR_LEN + 8u);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_R_HEADER, IDEMIP_IP6_FORWARD_IO(work_a)->reason);
}

// A span longer than the Payload Length is fine: the link layer may have padded the frame.
void test_a_span_longer_than_the_payload_length_is_forwarded(void)
{
    clear_ok(work_a);
    (void)build6(DOC_HOST_A, DOC_HOST_B, HOP_COMMON, (uint8_t)IDEMIP_IP6_NH_TCP, 8u);
    args_default(work_a, IDEMIP_IPV6_HDR_LEN + 64u);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, IDEMIP_IP6_FORWARD_IO(work_a)->action);
}

// --- the Redirect, RFC 4861 sec 8.2 -------------------------------------------

// All three conditions met: "the Source Address field of the packet identifies a neighbor", a better
// first hop "resides on the same link as the sending node", which is the packet leaving the interface
// it arrived on, and "the Destination Address of the packet is not a multicast address".
void test_a_redirect_is_owed_when_the_source_is_a_neighbor_on_the_same_link(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    Ip6ForwardArgs *a = &IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args;
    a->out_netif = 0u;
    a->src_neighbor = IDEMIP_TRUE;
    a->next_hop = LINK_LOCAL_B;
    Ip6Forward.decide(work_a);

    Ip6ForwardIo *io = IDEMIP_IP6_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, io->action);
    TEST_ASSERT_TRUE(io->redirect);
    TEST_ASSERT_EQUAL_PTR(LINK_LOCAL_B, io->redirect_target);
}

void test_no_redirect_across_interfaces(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.src_neighbor = IDEMIP_TRUE;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, IDEMIP_IP6_FORWARD_IO(work_a)->action);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FORWARD_IO(work_a)->redirect);
}

void test_no_redirect_to_a_multicast_destination(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, MCAST_SITE, HOP_COMMON);
    args_default(work_a, len);
    Ip6ForwardArgs *a = &IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args;
    a->out_netif = 0u;
    a->src_neighbor = IDEMIP_TRUE;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP6_FORWARD_SEND, IDEMIP_IP6_FORWARD_IO(work_a)->action);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FORWARD_IO(work_a)->redirect);
}

void test_no_redirect_when_the_source_is_not_a_neighbor(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.out_netif = 0u;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_FALSE(IDEMIP_IP6_FORWARD_IO(work_a)->redirect);
}

// --- the operands -------------------------------------------------------------

// RFC 8200 sec 5: "IPv6 requires that every link in the Internet have an MTU of 1280 octets or
// greater." A link under that cannot carry IPv6 at all, so it is ERR and not BUSY.
void test_an_mtu_below_the_ipv6_minimum_is_refused(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.out_mtu = (uint16_t)(IDEMIP_IPV6_MIN_MTU - 1u);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FORWARD_IO(work_a)->status);

    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.out_mtu = (uint16_t)IDEMIP_IPV6_MIN_MTU;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_FORWARD_IO(work_a)->status);
}

void test_a_null_packet_is_refused(void)
{
    clear_ok(work_a);
    args_default(work_a, IDEMIP_IPV6_HDR_LEN);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.hdr = NULL;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FORWARD_IO(work_a)->status);
}

// A route was found but no address was handed over, so there is nowhere to send the frame and no
// later call can supply one for this datagram.
void test_a_routed_call_with_no_next_hop_is_refused(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.next_hop = NULL;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FORWARD_IO(work_a)->status);
}

void test_an_interface_index_past_the_count_is_refused(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, HOP_COMMON);
    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.in_netif = (uint8_t)IDEMIP_NETIF_COUNT;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FORWARD_IO(work_a)->status);

    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.out_netif = (uint8_t)IDEMIP_NETIF_COUNT;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP6_FORWARD_IO(work_a)->status);
}

// A decision is a function of the operands it was handed, so no shape of it can succeed on a later
// tick. Reporting BUSY would spin the caller on a packet the RFC already decided.
void test_nothing_is_ever_busy(void)
{
    clear_ok(work_a);
    size_t len = build_plain(DOC_HOST_A, DOC_HOST_B, 1u);
    args_default(work_a, len);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP6_FORWARD_IO(work_a)->status);

    args_default(work_a, len);
    IDEMIP_IP6_FORWARD_IO(work_a)->fwd_args.routed = IDEMIP_FALSE;
    Ip6Forward.decide(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP6_FORWARD_IO(work_a)->status);

    args_default(work_a, IDEMIP_IPV6_HDR_LEN - 1u);
    Ip6Forward.decide(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP6_FORWARD_IO(work_a)->status);
}
