// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for ip4_forward. The storage half tests the CONTRACT, not the RFC 1812 behavior:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_IP4_FORWARD_BORROW is intact after every case
//   5. the published offsets are ordered, sized and non-overlapping
//   6. a borrow clear has not run on is refused, and clear leaves the operand block alone
//
// The behavior half drives what RFC 1812 prints. That document prints no forwarding vectors: its
// only printed addresses are the special forms of sec 4.2.2.11 and the broadcast forms of sec 5.3.5,
// which are driven here directly:
//
//   sec 4.2.2.11 (c) "{ -1, -1 } Limited broadcast", 255.255.255.255
//   sec 4.2.2.11 (d) "{ <Network-prefix>, -1 } Directed Broadcast"
//   sec 4.2.2.11 (e) "{ 127, <any> } Internal host loopback address"
//   sec 5.3.5 "a Class C net broadcast address is net.net.net.255"
//   sec 4.2.2.9 "a default TTL value in excess of 40, and 64 is a common value"
//   RFC 791 sec 3.2 "Every internet module must be able to forward a datagram of 68 octets"
//
// Everything else the section states as text is asserted as a property. The unicast addresses are
// RFC 5737's TEST-NET-1 192.0.2.0/24, TEST-NET-2 198.51.100.0/24 and TEST-NET-3 203.0.113.0/24,
// which that RFC reserves "for use in documentation".
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ip/ip4_forward.h"

#include <string.h>
#include <unity.h>
#include "src/common_defines.h"
#include "src/ip/ipv4_defines.h"
#include "src/icmp/icmp_defines.h"

#define CANARY 0x5Au
#define DIRT 0xCCu

static _Alignas(8) uint8_t work_a[IDEMIP_IP4_FORWARD_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_IP4_FORWARD_BORROW + 16];

// One datagram, built where the suite can reach it. 1500 octets is an Ethernet payload, so a case
// that claims a long datagram is claiming octets that are really there.
static uint8_t g_pkt[1500];

#define IP4(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

// RFC 5737 sec 3: the three blocks "provided for use in documentation".
#define TEST_NET_1_HOST IP4(192, 0, 2, 10)
#define TEST_NET_1_GW IP4(192, 0, 2, 1)
#define TEST_NET_1_BCAST IP4(192, 0, 2, 255)
#define TEST_NET_2_HOST IP4(198, 51, 100, 5)
#define TEST_NET_3_HOST IP4(203, 0, 113, 9)
#define MASK24 IP4(255, 255, 255, 0)

// RFC 1812 sec 4.2.2.9: "64 is a common value".
#define TTL_COMMON 64u

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_IP4_FORWARD_BORROW, CANARY, cap - IDEMIP_IP4_FORWARD_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_IP4_FORWARD_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_IP4_FORWARD_BORROW");
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

// --- building a datagram ------------------------------------------------------

// An option-free datagram of exactly its header, RFC 791 sec 3.1.
static size_t build(uint32_t src, uint32_t dst, uint8_t ttl, uint16_t flags_frag, uint8_t proto, uint16_t total_len)
{
    IdemIpIp4Fields f;
    f.tos = 0u;
    f.total_len = total_len;
    f.id = 0x1234u;
    f.flags_frag = flags_frag;
    f.ttl = ttl;
    f.proto = proto;
    f.src = src;
    f.dst = dst;
    idemip_ip4_build(g_pkt, &f);
    return (size_t)total_len;
}

static size_t build_plain(uint32_t src, uint32_t dst, uint8_t ttl)
{
    return build(src, dst, ttl, 0u, (uint8_t)IDEMIP_IP4_PROTO_TCP, (uint16_t)IDEMIP_IPV4_HDR_LEN);
}

// A datagram whose option area carries one option, padded to the 32-bit boundary RFC 791 sec 3.1
// requires of the internet header.
static size_t build_with_option(uint32_t src, uint32_t dst, uint8_t ttl, const uint8_t *opt, size_t optlen)
{
    size_t padded = (optlen + 3u) & ~(size_t)3u;
    size_t hdr = IDEMIP_IPV4_HDR_LEN + padded;
    (void)build(src, dst, ttl, 0u, (uint8_t)IDEMIP_IP4_PROTO_TCP, (uint16_t)hdr);
    memset(g_pkt + IDEMIP_IP4_OFF_OPTIONS, 0, padded);
    memcpy(g_pkt + IDEMIP_IP4_OFF_OPTIONS, opt, optlen);
    idemip_ip4_set_ver_ihl(g_pkt, (uint8_t)(hdr >> IDEMIP_IP4_IHL_SHIFT));
    idemip_ip4_recksum(g_pkt);
    return hdr;
}

// The default operand set: a routed unicast leaving a second interface, so no broadcast, no
// link-layer broadcast and no Redirect condition is in play unless a case sets one.
static void args_default(uint8_t *w, size_t len)
{
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(w)->fwd_args;
    memset(a, 0, sizeof *a);
    a->hdr = g_pkt;
    a->len = len;
    a->next_hop = TEST_NET_1_GW;
    a->out_mtu = 1500u;
    a->in_netif = 0u;
    a->out_netif = 1u;
    a->routed = IDEMIP_TRUE;
}

static void clear_ok(uint8_t *w)
{
    Ip4Forward.clear(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_FORWARD_IO(w)->status);
}

// --- the borrow ---------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Ip4Forward.clear(NULL);
    Ip4Forward.set_policy(NULL);
    Ip4Forward.decide(NULL);
    TEST_PASS();
}

// The borrow IS the forwarder, and the operand block is in it, so two forwarders share no byte.
void test_two_borrows_share_no_byte(void)
{
    clear_ok(work_a);
    clear_ok(work_b);

    IDEMIP_IP4_FORWARD_IO(work_b)->policy_args.set = 0u;
    IDEMIP_IP4_FORWARD_IO(work_b)->policy_args.clear = IDEMIP_IP4_FORWARD_P_DIRECTED;
    Ip4Forward.set_policy(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_FORWARD_IO(work_b)->status);

    // b lowered a switch; a still holds both.
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP4_FORWARD_P_MASK, IDEMIP_IP4_FORWARD_IO(work_a)->policy);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP4_FORWARD_P_MARTIAN, IDEMIP_IP4_FORWARD_IO(work_b)->policy);
}

// A decision is a function of its borrow alone, so a call interleaved on another borrow cannot
// change what this one reports.
void test_a_decision_is_a_function_of_its_borrow_alone(void)
{
    clear_ok(work_a);
    clear_ok(work_b);

    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    uint8_t first = IDEMIP_IP4_FORWARD_IO(work_a)->ttl;
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);

    // b decides a different datagram, then a decides its own again.
    (void)build_plain(TEST_NET_3_HOST, TEST_NET_1_HOST, 2u);
    args_default(work_b, IDEMIP_IPV4_HDR_LEN);
    Ip4Forward.decide(work_b);

    (void)build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_UINT8(first, IDEMIP_IP4_FORWARD_IO(work_a)->ttl);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_IP4_FORWARD_IO(work_b)->ttl);
}

// A borrow clear has not run on carries no switches, so every entry but clear refuses it.
void test_an_uncleared_borrow_is_refused(void)
{
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FORWARD_IO(work_a)->status);
    Ip4Forward.set_policy(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FORWARD_IO(work_a)->status);
}

// RFC 1812 sec 5.3.7 of the address checks and sec 5.3.5.2 of the directed broadcast both require
// their switch to default to on, so clear raises both.
void test_clear_raises_both_switches_the_rfc_defaults_on(void)
{
    memset(work_a, DIRT, IDEMIP_IP4_FORWARD_BORROW);
    clear_ok(work_a);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP4_FORWARD_P_MASK, IDEMIP_IP4_FORWARD_IO(work_a)->policy);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP4_FORWARD_P_MARTIAN | IDEMIP_IP4_FORWARD_P_DIRECTED,
                           IDEMIP_IP4_FORWARD_IO(work_a)->policy);
}

// The operand block is the caller's, so clear touches nothing in it but the status.
void test_clear_leaves_the_operand_block_alone(void)
{
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_pkt, IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.hdr);
    TEST_ASSERT_EQUAL_size_t(len, IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.len);
    TEST_ASSERT_EQUAL_HEX32(TEST_NET_1_GW, IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.next_hop);
}

// The published map is ordered, the context lies past the operand block, and the whole map fits.
void test_the_offset_map_is_ordered_and_fits(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_FORWARD_OFF_IO);
    TEST_ASSERT_TRUE((size_t)IDEMIP_IP4_FORWARD_OFF_CTX >= sizeof(Ip4ForwardIo));
    TEST_ASSERT_TRUE((size_t)IDEMIP_IP4_FORWARD_OFF_CTX < (size_t)IDEMIP_IP4_FORWARD_BORROW);
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_IP4_FORWARD_OFF_CTX & 7u);
    TEST_ASSERT_EQUAL_PTR(work_a, IDEMIP_IP4_FORWARD_IO(work_a));
}

// --- the forward --------------------------------------------------------------

// RFC 1812 sec 5.2.1.2: with a next hop from step (5), the checks of steps (6), (7) and (9) all pass
// and the datagram is queued for output on the interface step (5) chose.
void test_a_routed_datagram_is_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_OK, io->reason);
    TEST_ASSERT_EQUAL_HEX32(TEST_NET_1_GW, io->next_hop);
    TEST_ASSERT_EQUAL_UINT8(1u, io->netif);
    TEST_ASSERT_FALSE(io->icmp);
    TEST_ASSERT_FALSE(io->fragment);
}

// RFC 1812 sec 5.3.1: "Each router (or other module) that handles a packet MUST decrement the TTL by
// at least one." One hop, one decrement.
void test_the_ttl_is_decremented_by_one(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)(TTL_COMMON - 1u), IDEMIP_IP4_FORWARD_IO(work_a)->ttl);

    // And the datagram itself is untouched: this unit reports the value, the caller writes it.
    TEST_ASSERT_EQUAL_UINT8((uint8_t)TTL_COMMON, idemip_ip4_ttl(g_pkt));
}

// RFC 1812 sec 5.3.1: "If the TTL is reduced to zero (or less), the packet MUST be discarded, and if
// the destination is not a multicast address the router MUST send an ICMP Time Exceeded message,
// Code 0 (TTL Exceeded in Transit)."
void test_a_ttl_of_one_expires_with_time_exceeded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, 1u);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, io->reason);
    TEST_ASSERT_TRUE(io->icmp);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_TIME_EXCEEDED, io->icmp_type);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_TE_TTL, io->icmp_code);
}

// RFC 1812 sec 4.2.2.9: "A router MUST NOT originate or forward a datagram with a Time-to-Live (TTL)
// value of zero", which sec 5.3.1's "reduced to zero (or less)" covers.
void test_a_ttl_of_zero_is_never_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, 0u);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, io->reason);
    TEST_ASSERT_EQUAL_UINT8(0u, io->ttl);
}

// RFC 1812 sec 5.3.1 sends Time Exceeded only "if the destination is not a multicast address", and
// sec 4.3.2.7 forbids any ICMP error to "A packet destined to an IP broadcast or IP multicast
// address". Class D is 224.0.0.0 upward, sec 4.2.2.11.
void test_a_multicast_destination_gets_no_time_exceeded(void)
{
    clear_ok(work_a);
    // A group outside RFC 1812 sec 5.2.3's never-forwarded set, which the caller holds back.
    size_t len = build_plain(TEST_NET_1_HOST, IP4(239, 1, 2, 3), 1u);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, io->reason);
    TEST_ASSERT_FALSE(io->icmp);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_FORWARD_ICMP_NONE, io->icmp_type);
}

// RFC 1812 sec 4.3.3.1: "If a router cannot forward a packet because it has no routes at all
// (including no default route) to the destination specified in the packet, then the router MUST
// generate a Destination Unreachable, Code 0 (Network Unreachable) ICMP message."
void test_no_route_answers_network_unreachable(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.routed = IDEMIP_FALSE;
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_NO_ROUTE, io->reason);
    TEST_ASSERT_TRUE(io->icmp);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, io->icmp_type);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_DU_NET, io->icmp_code);
}

// RFC 791 sec 3.1 Don't Fragment with a datagram past the outgoing MTU, which RFC 1191 sec 4 answers
// with Destination Unreachable Code 4 carrying "the MTU of that next-hop network".
void test_oversize_with_df_answers_fragmentation_needed_and_the_next_hop_mtu(void)
{
    clear_ok(work_a);
    size_t len = build(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON, (uint16_t)IDEMIP_IP4_FLAG_DF,
                       (uint8_t)IDEMIP_IP4_PROTO_TCP, 1400u);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.len = 1400u;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_mtu = 1280u;
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_DF, io->reason);
    TEST_ASSERT_TRUE(io->icmp);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, io->icmp_type);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_DU_FRAG_NEEDED, io->icmp_code);
    TEST_ASSERT_EQUAL_UINT16(1280u, io->mtu);
}

// RFC 1812 sec 5.2.1.2 step (9): "The forwarder performs any necessary IP fragmentation." With Don't
// Fragment clear the datagram is still forwarded, and the fragmentation step is reported.
void test_oversize_without_df_asks_for_fragmentation(void)
{
    clear_ok(work_a);
    size_t len = build(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON, 0u, (uint8_t)IDEMIP_IP4_PROTO_TCP, 1400u);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.len = 1400u;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_mtu = 1280u;
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, io->action);
    TEST_ASSERT_TRUE(io->fragment);
    TEST_ASSERT_FALSE(io->icmp);
}

// A datagram that exactly fills the outgoing MTU is not oversized.
void test_a_datagram_the_size_of_the_mtu_is_not_fragmented(void)
{
    clear_ok(work_a);
    size_t len = build(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON, 0u, (uint8_t)IDEMIP_IP4_PROTO_TCP, 1280u);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.len = 1280u;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_mtu = 1280u;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->fragment);
}

// --- the header ---------------------------------------------------------------

// RFC 1812 sec 5.2.2 test (3): "The IP version number must be 4." A failing header "MUST be silently
// discarded", and sec 4.3.2.7 forbids an ICMP error in answer to it.
void test_a_wrong_version_is_silently_discarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    g_pkt[IDEMIP_IP4_OFF_VER_IHL] = (uint8_t)(0x60u | IDEMIP_IP4_IHL_MIN);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_HEADER, io->reason);
    TEST_ASSERT_FALSE(io->icmp);
}

// RFC 1812 sec 5.2.2 test (2): "The IP checksum must be correct."
void test_a_bad_checksum_is_silently_discarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    idemip_ip4_set_cksum(g_pkt, (uint16_t)(idemip_ip4_cksum(g_pkt) ^ 0xFFFFu));
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_HEADER, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp);
}

// RFC 1812 sec 5.2.2 test (1): "The packet length reported by the Link Layer must be large enough to
// hold the minimum length legal IP datagram (20 bytes)."
void test_a_truncated_datagram_is_silently_discarded(void)
{
    clear_ok(work_a);
    (void)build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, IDEMIP_IPV4_HDR_LEN - 1u);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_HEADER, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
}

// --- the link layer -----------------------------------------------------------

// RFC 1812 sec 5.3.4: "A router MUST NOT forward any packet that the router received as a Link Layer
// broadcast, unless it is directed to an IP Multicast address."
void test_a_link_layer_broadcast_is_not_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.ll_broadcast = IDEMIP_TRUE;
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_LINK_BCAST, io->reason);
    TEST_ASSERT_FALSE(io->icmp);
}

// The same sentence's exception: "unless it is directed to an IP Multicast address. In this latter
// case, one would presume that link layer broadcast was used due to the lack of an effective
// multicast service."
void test_a_link_layer_broadcast_to_a_multicast_destination_passes_the_check(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, IP4(239, 1, 2, 3), TTL_COMMON);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.ll_broadcast = IDEMIP_TRUE;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
}

// RFC 1812 sec 5.3.4: "A router MUST NOT forward any packet which the router received as a Link Layer
// multicast unless the packet's destination address is an IP multicast address."
void test_a_link_layer_multicast_to_a_unicast_destination_is_not_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.ll_multicast = IDEMIP_TRUE;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_LINK_BCAST, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
}

// --- martian filtering, sec 5.3.7 ---------------------------------------------

// "A router SHOULD NOT forward any packet that has an invalid IP source address or a source address
// on network 0." sec 4.2.2.11 (a) is { 0, 0 } and (b) is { 0, <Host-number> }.
void test_a_source_on_network_zero_is_not_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(IP4(0, 0, 0, 7), TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_SRC, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
}

// "A router SHOULD NOT forward, except over a loopback interface, any packet that has a source
// address on network 127." sec 4.2.2.11 (e): "{ 127, <any> } Internal host loopback address.
// Addresses of this form MUST NOT appear outside a host."
void test_a_source_on_network_127_is_not_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(IP4(127, 0, 0, 1), TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_SRC, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
}

// RFC 1812 sec 5.3.7: "An IP source address is invalid if ... or is not a unicast address." Class D
// is multicast,
// sec 4.2.2.11.
void test_a_multicast_source_is_not_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(IP4(224, 0, 0, 9), TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_SRC, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
}

// sec 4.2.2.11 (c): "{ -1, -1 } Limited broadcast. It MUST NOT be used as a source address."
void test_the_limited_broadcast_as_a_source_is_not_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(IP4(255, 255, 255, 255), TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_SRC, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
}

// "A router SHOULD NOT forward any packet that has an invalid IP destination address or a destination
// address on network 0." sec 4.2.3.1 (2) makes 0.0.0.0 "an obsolete form of the limited broadcast
// address".
void test_a_destination_on_network_zero_is_not_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, IP4(0, 0, 0, 0), TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_DST, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
}

// "An IP destination address is invalid if it is ... a Class E address (except 255.255.255.255)."
void test_a_class_e_destination_is_not_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, IP4(240, 0, 0, 1), TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_DST, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
}

// The same parenthesis: 255.255.255.255 is Class E and is NOT an invalid destination. It is stopped
// one rule later, by sec 5.3.5.1, so the reason separates the two.
void test_the_limited_broadcast_destination_is_not_a_martian(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, IP4(255, 255, 255, 255), TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_LIMITED, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
}

// sec 5.3.7: "A router MAY have a switch that allows the network manager to disable these checks."
void test_the_martian_switch_can_be_lowered(void)
{
    clear_ok(work_a);
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.set = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.clear = IDEMIP_IP4_FORWARD_P_MARTIAN;
    Ip4Forward.set_policy(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_FORWARD_IO(work_a)->status);

    size_t len = build_plain(IP4(127, 0, 0, 1), TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
}

// --- broadcasts, sec 5.3.5 ----------------------------------------------------

// sec 5.3.5.1: "Limited broadcasts MUST NOT be forwarded." The second half of that sentence,
// "Limited broadcasts MUST NOT be discarded", is the caller's local delivery and is not this
// decision.
void test_the_limited_broadcast_is_not_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, IP4(255, 255, 255, 255), TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_LIMITED, io->reason);
    TEST_ASSERT_FALSE(io->icmp);
}

// sec 5.3.5.2: "Given a route and no overriding policy, then, a router MUST forward network-
// prefix-directed broadcasts." sec 5.3.5 forms one as "{ <Network-prefix>, -1 }", which for the
// Class C sized TEST-NET-1 is 192.0.2.255.
void test_a_directed_broadcast_is_forwarded_by_default(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_2_HOST, TEST_NET_1_BCAST, TTL_COMMON);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->direct = IDEMIP_TRUE;
    a->next_hop = TEST_NET_1_BCAST;
    a->out_addr = TEST_NET_1_GW;
    a->out_mask = MASK24;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
}

// The same section: "a router ... MUST have an option to disable forwarding network-prefix-directed
// broadcasts."
void test_the_directed_broadcast_switch_stops_it(void)
{
    clear_ok(work_a);
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.set = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.clear = IDEMIP_IP4_FORWARD_P_DIRECTED;
    Ip4Forward.set_policy(work_a);

    size_t len = build_plain(TEST_NET_2_HOST, TEST_NET_1_BCAST, TTL_COMMON);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->direct = IDEMIP_TRUE;
    a->next_hop = TEST_NET_1_BCAST;
    a->out_addr = TEST_NET_1_GW;
    a->out_mask = MASK24;
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_DIRECTED, io->reason);
    TEST_ASSERT_FALSE(io->icmp);
}

// sec 5.3.5.2: the forwarding decision "is by definition only possible in the last hop router", so a
// route through a gateway does not put the same address under that section's switch. sec 4.2.3.1 (1)
// carries no such condition though: a router "MUST treat as IP broadcasts packets addressed to
// 255.255.255.255 or { <Network-prefix>, -1 }" whenever it holds the prefix, so sec 4.3.2.7 still
// forbids "An ICMP error message ... as the result of receiving ... A packet destined to an IP
// broadcast or IP multicast address".
void test_a_broadcast_form_through_a_gateway_is_forwarded_but_draws_no_icmp_error(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_2_HOST, TEST_NET_1_BCAST, 1u);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->direct = IDEMIP_FALSE;
    a->out_addr = TEST_NET_1_GW;
    a->out_mask = MASK24;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp,
                              "sec 4.2.3.1 (1) is unconditional, so sec 4.3.2.7 suppresses the error");

    // sec 5.3.5.2's switch, lowered, does not hold the packet, because the router is not the last hop.
    clear_ok(work_a);
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.set = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.clear = (uint8_t)IDEMIP_IP4_FORWARD_P_DIRECTED;
    Ip4Forward.set_policy(work_a);
    len = build_plain(TEST_NET_2_HOST, TEST_NET_1_BCAST, 64u);
    args_default(work_a, len);
    a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->direct = IDEMIP_FALSE;
    a->out_addr = TEST_NET_1_GW;
    a->out_mask = MASK24;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);

    // A destination on a prefix the router has no interface on is an ordinary unicast, and the sec
    // 4.2.3.1 DISCUSSION says the router "cannot recognize addresses of the form { <Network-prefix>,
    // 0 } if the router has no interface to that network prefix".
    clear_ok(work_a);
    len = build_plain(TEST_NET_2_HOST, TEST_NET_1_BCAST, 1u);
    args_default(work_a, len);
    a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->direct = IDEMIP_FALSE;
    a->out_addr = 0u;
    a->out_mask = 0u;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp,
                             "the router understands no prefix here, so the address is an ordinary unicast");
}

// sec 4.3.2.7 forbids an ICMP error to "A packet destined to an IP broadcast or IP multicast
// address", and a directed broadcast is one.
void test_a_directed_broadcast_gets_no_icmp_error(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_2_HOST, TEST_NET_1_BCAST, 1u);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->direct = IDEMIP_TRUE;
    a->next_hop = TEST_NET_1_BCAST;
    a->out_addr = TEST_NET_1_GW;
    a->out_mask = MASK24;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp);
}

// RFC 3927 sec 7: "A router MUST NOT forward a packet with an IPv4 Link-Local source or destination
// address, irrespective of the router's default route configuration or routes obtained from dynamic
// routing protocols", and sec 2.7 repeats it "regardless of the TTL in the IPv4 header". RFC 6890
// Table 5 records 169.254.0.0/16 as "Forwardable | False".
void test_a_link_local_source_or_destination_is_never_forwarded(void)
{
    clear_ok(work_a);
    size_t len = build_plain(IP4(169, 254, 1, 2), TEST_NET_2_HOST, 64u);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_LINK_LOCAL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);

    clear_ok(work_a);
    len = build_plain(TEST_NET_2_HOST, IP4(169, 254, 200, 30), 64u);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_LINK_LOCAL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);

    // "Irrespective of the router's ... configuration", so lowering the sec 5.3.7 martian switch
    // does not let it through.
    clear_ok(work_a);
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.set = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.clear = (uint8_t)IDEMIP_IP4_FORWARD_P_MARTIAN;
    Ip4Forward.set_policy(work_a);
    len = build_plain(IP4(169, 254, 1, 2), TEST_NET_2_HOST, 64u);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_LINK_LOCAL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);

    // The address one octet outside 169.254/16 is an ordinary unicast.
    clear_ok(work_a);
    len = build_plain(IP4(169, 253, 1, 2), TEST_NET_2_HOST, 64u);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
}

// RFC 1812 sec 4.2.2.11 (d), of { <Network-prefix>, -1 }: "It MUST NOT be used as a source address",
// and the section closes "A router MUST silently discard any received datagram containing an IP
// source address that is invalid by the rules of this section". sec 4.3.2.7's note, "THESE
// RESTRICTIONS TAKE PRECEDENCE OVER ANY REQUIREMENT ELSEWHERE IN THIS DOCUMENT FOR SENDING ICMP ERROR
// MESSAGES", forbids answering it.
void test_a_directed_broadcast_source_is_discarded_and_draws_no_icmp_error(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_BCAST, TEST_NET_3_HOST, 1u);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->in_addr = TEST_NET_1_GW;
    a->in_mask = MASK24;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp,
                              "sec 4.3.2.7 forbids an error to an invalid source address");

    // The obsolete { <Network-prefix>, 0 } form of the same, sec 4.2.2.11 (b).
    clear_ok(work_a);
    len = build_plain(IP4(192, 0, 2, 0), TEST_NET_3_HOST, 64u);
    args_default(work_a, len);
    a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->in_addr = TEST_NET_1_GW;
    a->in_mask = MASK24;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_SRC_BCAST, IDEMIP_IP4_FORWARD_IO(work_a)->reason);

    // RFC 3021 sec 3.1 rewrites RFC 1122 sec 3.2.1.3 (e) to permit the all-ones host part as a source
    // "when the originator is one of the endpoints of a point-to-point link with a 31-bit mask".
    clear_ok(work_a);
    len = build_plain(IP4(10, 0, 0, 1), TEST_NET_3_HOST, 64u);
    args_default(work_a, len);
    a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->in_addr = IP4(10, 0, 0, 0);
    a->in_mask = IP4(255, 255, 255, 254);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action,
                                  "a 31-bit prefix endpoint is a host address, not a broadcast");

    // A host address on the receiving prefix is an ordinary source.
    clear_ok(work_a);
    len = build_plain(TEST_NET_1_HOST, TEST_NET_3_HOST, 64u);
    args_default(work_a, len);
    a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->in_addr = TEST_NET_1_GW;
    a->in_mask = MASK24;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
}

// RFC 1812 sec 5.3.5, of the obsolete form: "{ <Network-prefix>, 0 } is an obsolete form of a
// network-prefix-directed broadcast address ... packets addressed to any of these addresses SHOULD be
// silently discarded, but if they are not, they MUST be treated according to the same rules that
// apply to packets addressed to the non-obsolete forms."
void test_the_obsolete_broadcast_destination_is_treated_as_a_broadcast(void)
{
    clear_ok(work_a);
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.set = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.clear = (uint8_t)IDEMIP_IP4_FORWARD_P_DIRECTED;
    Ip4Forward.set_policy(work_a);
    size_t len = build_plain(TEST_NET_3_HOST, IP4(192, 0, 2, 0), 64u);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->direct = IDEMIP_TRUE;
    a->out_addr = TEST_NET_1_GW;
    a->out_mask = MASK24;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP4_FORWARD_R_DIRECTED, IDEMIP_IP4_FORWARD_IO(work_a)->reason,
                                  "the obsolete form is held by the same sec 5.3.5.2 switch");

    // sec 4.3.2.7 suppresses the error for it the same way.
    clear_ok(work_a);
    len = build_plain(TEST_NET_3_HOST, IP4(192, 0, 2, 0), 1u);
    args_default(work_a, len);
    a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->direct = IDEMIP_TRUE;
    a->out_addr = TEST_NET_1_GW;
    a->out_mask = MASK24;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp);
}

// RFC 3021 sec 2.2.1: a directed broadcast to a 31-bit prefix "is not possible", sec 3.3 adding that
// { <Network-prefix>, -1 } on such a link "MUST be treated as directed to the router on which the
// address is applied". The far endpoint is an ordinary unicast destination.
void test_a_31_bit_prefix_endpoint_is_not_a_directed_broadcast(void)
{
    clear_ok(work_a);
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.set = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.clear = (uint8_t)IDEMIP_IP4_FORWARD_P_DIRECTED;
    Ip4Forward.set_policy(work_a);
    size_t len = build_plain(TEST_NET_2_HOST, IP4(10, 0, 0, 1), 64u);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->direct = IDEMIP_TRUE;
    a->next_hop = IP4(10, 0, 0, 1);
    a->out_addr = IP4(10, 0, 0, 0);
    a->out_mask = IP4(255, 255, 255, 254);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action,
                                  "the odd endpoint of a 31-bit prefix is a host, not a broadcast");
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_OK, IDEMIP_IP4_FORWARD_IO(work_a)->reason);

    // And an ICMP error to it is not suppressed, because it is not a broadcast destination.
    clear_ok(work_a);
    len = build_plain(TEST_NET_2_HOST, IP4(10, 0, 0, 1), 1u);
    args_default(work_a, len);
    a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->direct = IDEMIP_TRUE;
    a->out_addr = IP4(10, 0, 0, 0);
    a->out_mask = IP4(255, 255, 255, 254);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp);
}

// RFC 1812 sec 4.3.3.1: Code 0 when the router "has no routes at all (including no default route) to
// the destination", Code 11 when "the router does have routes to the destination network specified in
// the packet but the TOS specified for the routes is neither the default TOS (0000) nor the TOS of the
// packet", and Code 12 for the same on "a network that is directly connected to the router".
void test_an_unusable_type_of_service_draws_the_unreachable_for_tos_codes(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_2_HOST, TEST_NET_3_HOST, 64u);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->routed = IDEMIP_FALSE;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_NO_ROUTE, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_IP4_FORWARD_IO(work_a)->icmp_type);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_DU_NET, IDEMIP_IP4_FORWARD_IO(work_a)->icmp_code);

    clear_ok(work_a);
    args_default(work_a, len);
    a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->routed = IDEMIP_FALSE;
    a->tos_blocked = IDEMIP_TRUE;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_NO_ROUTE_TOS, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)IDEMIP_ICMP_DU_NET_TOS, IDEMIP_IP4_FORWARD_IO(work_a)->icmp_code,
                                    "routes exist but none carries a usable TOS");

    clear_ok(work_a);
    args_default(work_a, len);
    a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->routed = IDEMIP_FALSE;
    a->tos_blocked = IDEMIP_TRUE;
    a->direct = IDEMIP_TRUE;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_DU_HOST_TOS, IDEMIP_IP4_FORWARD_IO(work_a)->icmp_code);
}

// --- source route options, sec 5.2.2 ------------------------------------------

// sec 5.2.2: "if the destination address in the IP header is not one of the addresses of the router,
// the router SHOULD verify that the packet does not contain a Strict Source and Record Route option.
// If a packet fails this test ... SHOULD respond with an ICMP Parameter Problem error with the
// pointer pointing at the offending packet's IP destination address." RFC 791 sec 3.1 numbers the
// option 137.
void test_a_strict_source_route_answers_parameter_problem(void)
{
    clear_ok(work_a);
    const uint8_t opt[7] = {137u, 7u, 4u, 203u, 0u, 113u, 9u};
    size_t len = build_with_option(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON, opt, sizeof opt);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, io->action);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_STRICT, io->reason);
    TEST_ASSERT_TRUE(io->icmp);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_PARAMETER_PROBLEM, io->icmp_type);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP_PP_POINTER, io->icmp_code);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_IP4_OFF_DST, io->icmp_ptr);
}

// RFC 791 sec 3.1 numbers Loose Source Routing 131. sec 5.2.2 names only the strict form, so a loose
// source route is forwarded; sec 5.2.7.2's third condition still stops the Redirect.
void test_a_loose_source_route_is_forwarded_and_suppresses_the_redirect(void)
{
    clear_ok(work_a);
    const uint8_t opt[7] = {131u, 7u, 4u, 203u, 0u, 113u, 9u};
    size_t len = build_with_option(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON, opt, sizeof opt);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->out_netif = 0u;
    a->in_mask = MASK24;
    a->next_hop = TEST_NET_1_GW;
    Ip4Forward.decide(work_a);

    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->redirect);
}

// --- the Redirect, sec 5.2.7.2 ------------------------------------------------

// All three conditions met: forwarded out the interface it arrived on, the source on the same logical
// subnet as the next hop, and no source route option. "Routers MUST be able to generate the Redirect
// for Host message (Code 1)."
void test_a_redirect_is_owed_when_the_next_hop_shares_the_source_subnet(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->out_netif = 0u;
    a->in_mask = MASK24;
    a->in_addr = TEST_NET_1_GW;
    a->next_hop = TEST_NET_1_GW;
    Ip4Forward.decide(work_a);

    const Ip4ForwardIo *io = IDEMIP_IP4_FORWARD_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, io->action);
    TEST_ASSERT_TRUE(io->redirect);
    TEST_ASSERT_EQUAL_HEX32(TEST_NET_1_GW, io->redirect_gw);
}

// First condition: "The packet is being forwarded out the same physical interface that it was
// received from."
void test_no_redirect_when_the_datagram_leaves_another_interface(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->out_netif = 1u;
    a->in_mask = MASK24;
    a->next_hop = TEST_NET_1_GW;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->redirect);
}

// Second condition: "The IP source address in the packet is on the same Logical IP (sub)network as
// the next-hop IP address."
void test_no_redirect_when_the_next_hop_is_off_the_source_subnet(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    Ip4ForwardArgs *a = &IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args;
    a->out_netif = 0u;
    a->in_mask = MASK24;
    a->next_hop = TEST_NET_3_HOST;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->redirect);
}

// --- when no ICMP may be sent, sec 4.3.2.7 ------------------------------------

// "An ICMP error message MUST NOT be sent as the result of receiving ... An ICMP error message."
// RFC 1122 sec 3.2.2 counts Time Exceeded among them.
void test_an_icmp_error_draws_no_icmp_error(void)
{
    clear_ok(work_a);
    size_t len = build(TEST_NET_1_HOST, TEST_NET_2_HOST, 1u, 0u, (uint8_t)IDEMIP_IP4_PROTO_ICMP,
                       (uint16_t)(IDEMIP_IPV4_HDR_LEN + 1u));
    g_pkt[IDEMIP_IPV4_HDR_LEN] = (uint8_t)IDEMIP_ICMP_TIME_EXCEEDED;
    args_default(work_a, len);
    Ip4Forward.decide(work_a);

    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp);
}

// An ICMP query is not an error message, so the answer is not suppressed. RFC 1122 sec 3.2.2 puts
// Echo among the queries.
void test_an_icmp_echo_still_draws_the_error(void)
{
    clear_ok(work_a);
    size_t len = build(TEST_NET_1_HOST, TEST_NET_2_HOST, 1u, 0u, (uint8_t)IDEMIP_IP4_PROTO_ICMP,
                       (uint16_t)(IDEMIP_IPV4_HDR_LEN + 1u));
    g_pkt[IDEMIP_IPV4_HDR_LEN] = (uint8_t)IDEMIP_ICMP_ECHO;
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp);
}

// "Any fragment of a datagram other then the first fragment (i.e., a packet for which the fragment
// offset in the IP header is nonzero)."
void test_a_later_fragment_draws_no_icmp_error(void)
{
    clear_ok(work_a);
    size_t len = build(TEST_NET_1_HOST, TEST_NET_2_HOST, 1u, (uint16_t)(IDEMIP_IP4_FLAG_MF | 1u),
                       (uint8_t)IDEMIP_IP4_PROTO_TCP, (uint16_t)(IDEMIP_IPV4_HDR_LEN + 8u));
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp);
}

// The first fragment carries offset zero, so it is not suppressed.
void test_the_first_fragment_still_draws_the_error(void)
{
    clear_ok(work_a);
    size_t len = build(TEST_NET_1_HOST, TEST_NET_2_HOST, 1u, (uint16_t)IDEMIP_IP4_FLAG_MF,
                       (uint8_t)IDEMIP_IP4_PROTO_TCP, (uint16_t)(IDEMIP_IPV4_HDR_LEN + 8u));
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_TRUE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp);
}

// "A packet sent as a Link Layer broadcast or multicast." The datagram here is an IP multicast, so
// sec 5.3.4 lets it through and only the ICMP is stopped.
void test_a_link_layer_broadcast_draws_no_icmp_error(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, IP4(224, 0, 0, 1), 1u);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.ll_broadcast = IDEMIP_TRUE;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp);
}

// "A packet whose source address ... is an invalid source address (as defined in Section [5.3.7])."
// Reached with the martian switch lowered, so the datagram is still forwarded far enough to hit the
// TTL rule.
void test_an_invalid_source_draws_no_icmp_error(void)
{
    clear_ok(work_a);
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.set = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.clear = IDEMIP_IP4_FORWARD_P_MARTIAN;
    Ip4Forward.set_policy(work_a);

    size_t len = build_plain(IP4(0, 0, 0, 7), TEST_NET_2_HOST, 1u);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_R_TTL, IDEMIP_IP4_FORWARD_IO(work_a)->reason);
    TEST_ASSERT_FALSE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp);
}

// --- the operands -------------------------------------------------------------

// RFC 791 sec 3.2: "Every internet module must be able to forward a datagram of 68 octets without
// further fragmentation." A link under that can never carry a forwarded datagram, so it is ERR and
// not BUSY: no retry makes it fit.
void test_an_mtu_below_the_minimum_forward_size_is_refused(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_mtu = (uint16_t)(IDEMIP_IP4_MIN_FORWARD_MTU - 1u);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FORWARD_IO(work_a)->status);

    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_mtu = (uint16_t)IDEMIP_IP4_MIN_FORWARD_MTU;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_FORWARD_IO(work_a)->status);
}

void test_a_null_datagram_is_refused(void)
{
    clear_ok(work_a);
    args_default(work_a, IDEMIP_IPV4_HDR_LEN);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.hdr = NULL;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FORWARD_IO(work_a)->status);
}

void test_an_interface_index_past_the_count_is_refused(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, TTL_COMMON);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_netif = (uint8_t)IDEMIP_NETIF_COUNT;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FORWARD_IO(work_a)->status);

    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_netif = (uint8_t)IDEMIP_NETIF_COUNT;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FORWARD_IO(work_a)->status);
}

// A bit outside IDEMIP_IP4_FORWARD_P_MASK names no switch, so no later call gives it one.
void test_set_policy_refuses_a_reserved_bit(void)
{
    clear_ok(work_a);
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.set = (uint8_t)~IDEMIP_IP4_FORWARD_P_MASK;
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.clear = 0u;
    Ip4Forward.set_policy(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_IP4_FORWARD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP4_FORWARD_P_MASK, IDEMIP_IP4_FORWARD_IO(work_a)->policy);
}

// set_policy raises first and lowers second, so a bit in both ends lowered.
void test_set_policy_lowers_after_it_raises(void)
{
    clear_ok(work_a);
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.set = IDEMIP_IP4_FORWARD_P_MASK;
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.clear = IDEMIP_IP4_FORWARD_P_MARTIAN;
    Ip4Forward.set_policy(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP4_FORWARD_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_IP4_FORWARD_P_DIRECTED, IDEMIP_IP4_FORWARD_IO(work_a)->policy);
}

// A decision is a function of the operands it was handed, so no shape of it can succeed on a later
// tick. Reporting BUSY would spin the caller on a datagram the RFC already decided.
void test_nothing_is_ever_busy(void)
{
    clear_ok(work_a);
    size_t len = build_plain(TEST_NET_1_HOST, TEST_NET_2_HOST, 1u);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_FORWARD_IO(work_a)->status);

    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.routed = IDEMIP_FALSE;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_FORWARD_IO(work_a)->status);

    args_default(work_a, IDEMIP_IPV4_HDR_LEN - 1u);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_FORWARD_IO(work_a)->status);

    Ip4Forward.set_policy(work_a);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_IP4_FORWARD_IO(work_a)->status);
}

// --- the prefixes a classification is made under --------------------------------

// RFC 1812 sec 5.3.7 makes "a destination address on network 127" invalid, the same way network 0 is.
void test_a_destination_on_the_loopback_network_is_not_forwarded(void)
{
    clear_ok(work_a);
    const size_t len = build_plain(TEST_NET_1_HOST, IP4(127, 0, 0, 1), TTL_COMMON);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP4_FORWARD_R_DST, IDEMIP_IP4_FORWARD_IO(work_a)->reason,
                                  "a destination on network 127 was forwarded");
}

// RFC 1812 sec 5.3.5.2 classifies a broadcast under "the router's understanding (if any) of the
// subnet structure of the destination network", and a router with no understanding of it has none to
// make: a mask of zero, a mask of all ones, and RFC 3021 sec 3.1's 31-bit prefix, where "the two
// addresses above MUST be interpreted as host addresses", each leave it a host address. So does one
// outside the prefix the mask names.
void test_a_directed_broadcast_needs_a_prefix_to_be_directed_under(void)
{
    const uint32_t masks[3] = {0u, IP4(255, 255, 255, 255), IP4(255, 255, 255, 254)};
    for (int i = 0; i < 3; i++)
    {
        clear_ok(work_a);
        const size_t len = build_plain(TEST_NET_2_HOST, TEST_NET_1_BCAST, TTL_COMMON);
        args_default(work_a, len);
        IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_addr = TEST_NET_1_GW;
        IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_mask = masks[i];
        IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.direct = IDEMIP_TRUE;
        Ip4Forward.decide(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action,
                                      "an address was read as a directed broadcast under no prefix");
    }

    // An ordinary host address inside the prefix is neither form.
    clear_ok(work_a);
    const size_t host = build_plain(TEST_NET_2_HOST, TEST_NET_1_HOST, TTL_COMMON);
    args_default(work_a, host);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.next_hop = TEST_NET_1_HOST;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_addr = TEST_NET_1_GW;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_mask = MASK24;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.direct = IDEMIP_TRUE;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action,
                                  "a host address inside the prefix was read as its broadcast");

    // Under a prefix that does not contain it, it is not that prefix's broadcast either.
    clear_ok(work_a);
    const size_t len = build_plain(TEST_NET_2_HOST, TEST_NET_1_BCAST, TTL_COMMON);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_addr = TEST_NET_3_HOST;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_mask = MASK24;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.direct = IDEMIP_TRUE;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action,
                                  "an address outside the prefix was read as its broadcast");

    // "{ <Network-prefix>, 0 } is an obsolete form of a network-prefix-directed broadcast address",
    // which the same section treats by the same rules as the all-ones form.
    clear_ok(work_a);
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.set = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->policy_args.clear = IDEMIP_IP4_FORWARD_P_DIRECTED;
    Ip4Forward.set_policy(work_a);
    const size_t obsolete = build_plain(TEST_NET_2_HOST, IP4(192, 0, 2, 0), TTL_COMMON);
    args_default(work_a, obsolete);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.next_hop = IP4(192, 0, 2, 0);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_addr = TEST_NET_1_GW;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_mask = MASK24;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.direct = IDEMIP_TRUE;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP4_FORWARD_R_DIRECTED, IDEMIP_IP4_FORWARD_IO(work_a)->reason,
                                  "the obsolete form of a directed broadcast was not treated as one");
}

// The same classification on the receiving side, which sec 5.3.7 makes a source test: a source
// address is invalid where it is that interface's broadcast, and where the interface has no prefix
// to make it one it is a source like any other.
void test_a_source_broadcast_needs_a_prefix_on_the_receiving_side_too(void)
{
    const uint32_t masks[3] = {0u, IP4(255, 255, 255, 255), IP4(255, 255, 255, 254)};
    for (int i = 0; i < 3; i++)
    {
        clear_ok(work_a);
        const size_t len = build_plain(TEST_NET_1_BCAST, TEST_NET_3_HOST, TTL_COMMON);
        args_default(work_a, len);
        IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_addr = TEST_NET_1_GW;
        IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_mask = masks[i];
        Ip4Forward.decide(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action,
                                      "a source was read as a broadcast under no prefix");
    }
}

// RFC 791 sec 3.1: type 1 "occupies only 1 octet" and has no length behind it, type 0 "indicates the
// end of the option list", and every other option carries "the option length which includes the
// option type code and the length octet". A walk over the area has to take each of those, and stop
// where the area cannot carry what the option claims. What the walk found is read by RFC 1812 sec
// 5.2.7.2's third condition, "The packet does not contain an IP source route option", so the
// Redirect is where the finding shows.
void test_the_option_walk_takes_each_form_the_area_can_carry(void)
{
    // The three sec 5.2.7.2 conditions, so a Redirect is owed unless an option is what stops it.
    static const uint32_t SAME_NET_SRC = IP4(192, 0, 2, 20);

    // A No Operation before a Loose Source Route: the walk steps one octet and finds the route.
    static const uint8_t nop_then_lsrr[] = {1u, 131u, 7u, 4u, 192u, 0u, 2u, 1u};
    clear_ok(work_a);
    size_t len = build_with_option(SAME_NET_SRC, TEST_NET_3_HOST, TTL_COMMON, nop_then_lsrr, sizeof nop_then_lsrr);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_netif = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_mask = MASK24;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_addr = TEST_NET_1_GW;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->redirect,
                              "a source route behind a No Operation was not seen");

    // An option area whose last octet is a type with no length behind it: the walk stops there, and
    // what stands before it is all there is.
    clear_ok(work_a);
    len = build(SAME_NET_SRC, TEST_NET_3_HOST, TTL_COMMON, 0u, (uint8_t)IDEMIP_IP4_PROTO_TCP,
                (uint16_t)(IDEMIP_IPV4_HDR_LEN + 4u));
    g_pkt[IDEMIP_IP4_OFF_OPTIONS] = 1u; // No Operation
    g_pkt[IDEMIP_IP4_OFF_OPTIONS + 1u] = 1u;
    g_pkt[IDEMIP_IP4_OFF_OPTIONS + 2u] = 1u;
    g_pkt[IDEMIP_IP4_OFF_OPTIONS + 3u] = 131u; // a source route with nothing behind its type octet
    idemip_ip4_set_ver_ihl(g_pkt, (uint8_t)((IDEMIP_IPV4_HDR_LEN + 4u) >> IDEMIP_IP4_IHL_SHIFT));
    idemip_ip4_recksum(g_pkt);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_netif = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_mask = MASK24;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_addr = TEST_NET_1_GW;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->redirect,
                             "a source route was read out of an option area that ends mid-option");

    // An option whose length runs past the area it stands in.
    static const uint8_t over_len[] = {131u, 20u, 0u, 0u};
    clear_ok(work_a);
    len = build_with_option(SAME_NET_SRC, TEST_NET_3_HOST, TTL_COMMON, over_len, sizeof over_len);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_netif = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_mask = MASK24;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_addr = TEST_NET_1_GW;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->redirect,
                             "an option claiming more octets than the area holds was walked");

    // An option length below the two octets an option is at minimum.
    static const uint8_t short_len[] = {131u, 1u, 0u, 0u};
    clear_ok(work_a);
    len = build_with_option(SAME_NET_SRC, TEST_NET_3_HOST, TTL_COMMON, short_len, sizeof short_len);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_netif = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_mask = MASK24;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_addr = TEST_NET_1_GW;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->redirect,
                             "an option shorter than its own two fixed octets was walked");
}

// RFC 1122 sec 3.2.2's five error types are what sec 4.3.2.7 keeps a router from answering with
// another error. A datagram carrying one of them is that; one carrying a query, one that is not
// ICMP at all, a later fragment of one, and one with no octet to read the Type from are not.
void test_the_icmp_error_test_reads_the_type_the_datagram_carries(void)
{
    const uint8_t types[6] = {(uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE,  (uint8_t)IDEMIP_ICMP_SOURCE_QUENCH,
                              (uint8_t)IDEMIP_ICMP_REDIRECT,          (uint8_t)IDEMIP_ICMP_TIME_EXCEEDED,
                              (uint8_t)IDEMIP_ICMP_PARAMETER_PROBLEM, (uint8_t)IDEMIP_ICMP_ECHO};
    for (int i = 0; i < 6; i++)
    {
        clear_ok(work_a);
        const size_t len = build(TEST_NET_1_HOST, TEST_NET_3_HOST, 1u, 0u, (uint8_t)IDEMIP_IP4_PROTO_ICMP,
                                 (uint16_t)(IDEMIP_IPV4_HDR_LEN + 8u));
        g_pkt[IDEMIP_IPV4_HDR_LEN + IDEMIP_ICMP_OFF_TYPE] = types[i];
        args_default(work_a, len);
        Ip4Forward.decide(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_DISCARD, IDEMIP_IP4_FORWARD_IO(work_a)->action);
        if (i == 5)
        {
            // sec 3.2.2 groups the queries apart from the errors, so an Echo is answerable.
            TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp,
                                     "a datagram carrying a query was read as carrying an error");
        }
        else
        {
            TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp,
                                      "a router answered an ICMP error with another one");
        }
    }

    // A later fragment of an ICMP datagram is refused an answer by sec 4.3.2.7's own clause about
    // "Any fragment of a datagram other then the first fragment", before the Type is looked for.
    clear_ok(work_a);
    size_t len = build(TEST_NET_1_HOST, TEST_NET_3_HOST, 1u, 2u, (uint8_t)IDEMIP_IP4_PROTO_ICMP,
                       (uint16_t)(IDEMIP_IPV4_HDR_LEN + 8u));
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp, "a later fragment was answered with an ICMP error");

    // A datagram of exactly its header has no Type octet to read, and is not an error message.
    clear_ok(work_a);
    len =
        build(TEST_NET_1_HOST, TEST_NET_3_HOST, 1u, 0u, (uint8_t)IDEMIP_IP4_PROTO_ICMP, (uint16_t)IDEMIP_IPV4_HDR_LEN);
    args_default(work_a, len);
    Ip4Forward.decide(work_a);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->icmp, "a datagram with no payload was read for a Type");
}

// RFC 1812 sec 5.2.7.2's conditions for a Redirect are all three at once, and sec 4.3.2.7 keeps the
// router from sending one about a datagram carrying an ICMP error. An interface with no prefix of
// its own cannot say whether the source is "on the same Logical IP (sub)network as the next-hop IP
// address", so there is nothing to redirect against.
void test_a_redirect_needs_every_one_of_its_conditions(void)
{
    static const uint32_t SAME_NET_SRC = IP4(192, 0, 2, 20);

    // Everything but a prefix on the receiving interface.
    clear_ok(work_a);
    size_t len = build_plain(SAME_NET_SRC, TEST_NET_3_HOST, TTL_COMMON);
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_netif = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_mask = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_addr = TEST_NET_1_GW;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->redirect,
                              "a Redirect went out over an interface with no prefix of its own");

    // Everything but the datagram: this one carries an ICMP error, and sec 4.3.2.7 answers those
    // with nothing at all.
    clear_ok(work_a);
    len = build(SAME_NET_SRC, TEST_NET_3_HOST, TTL_COMMON, 0u, (uint8_t)IDEMIP_IP4_PROTO_ICMP,
                (uint16_t)(IDEMIP_IPV4_HDR_LEN + 8u));
    g_pkt[IDEMIP_IPV4_HDR_LEN + IDEMIP_ICMP_OFF_TYPE] = (uint8_t)IDEMIP_ICMP_TIME_EXCEEDED;
    args_default(work_a, len);
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.out_netif = 0u;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_mask = MASK24;
    IDEMIP_IP4_FORWARD_IO(work_a)->fwd_args.in_addr = TEST_NET_1_GW;
    Ip4Forward.decide(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_FORWARD_SEND, IDEMIP_IP4_FORWARD_IO(work_a)->action);
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_IP4_FORWARD_IO(work_a)->redirect,
                              "a Redirect was sent about a datagram carrying an ICMP error");
}
