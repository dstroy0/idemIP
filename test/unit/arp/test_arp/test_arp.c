// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 826, the Ethernet Address Resolution Protocol. The vectors are the RFC's own "An Example":
// machine X broadcasts a request for IPA(Y), and machine Y answers with a reply. RFC 826 states
// that example in symbols (EA(X), IPA(X), ET(IP)), not octets, so each symbol is bound to a
// concrete value here and the two wire vectors below are laid out by hand in the order "Packet
// format" lists the fields. The code is then checked against those literals, never against itself.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/arp/arp.h"

#include <string.h>
#include <unity.h>

// The RFC's symbols, bound. EA is a 48-bit Ethernet address, IPA a 32-bit DOD Internet address.
static const uint8_t EA_X[6] = {0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
static const uint8_t EA_Y[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
#define IPA_X 0x0A000001u // 10.0.0.1
#define IPA_Y 0x0A000002u // 10.0.0.2
#define ET_IP 0x0800u     // ether_type$DOD_INTERNET

// X's request, field by field per RFC 826 "Packet format" and the values "An Example" gives:
// ar$hrd ares_hrd$Ethernet, ar$pro ET(IP), ar$hln length(EA(X)), ar$pln length(IPA(X)),
// ar$op ares_op$REQUEST, ar$sha EA(X), ar$spa IPA(X), ar$tha don't care, ar$tpa IPA(Y).
static const uint8_t REQ[28] = {
    0x00, 0x01,                         // ar$hrd = 1
    0x08, 0x00,                         // ar$pro = ET(IP)
    0x06,                               // ar$hln = 6
    0x04,                               // ar$pln = 4
    0x00, 0x01,                         // ar$op  = ares_op$REQUEST, high byte first
    0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // ar$sha = EA(X)
    0x0A, 0x00, 0x00, 0x01,             // ar$spa = IPA(X)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ar$tha = don't care
    0x0A, 0x00, 0x00, 0x02,             // ar$tpa = IPA(Y)
};

// Y's reply: the sender fields hold Y's own addresses, the target fields hold X's.
static const uint8_t REP[28] = {
    0x00, 0x01,                         // ar$hrd = 1
    0x08, 0x00,                         // ar$pro = ET(IP)
    0x06,                               // ar$hln = 6
    0x04,                               // ar$pln = 4
    0x00, 0x02,                         // ar$op  = ares_op$REPLY
    0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // ar$sha = EA(Y)
    0x0A, 0x00, 0x00, 0x02,             // ar$spa = IPA(Y)
    0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // ar$tha = EA(X)
    0x0A, 0x00, 0x00, 0x01,             // ar$tpa = IPA(X)
};

// The caller's bytes, with a canary past the payload so a build that writes long is visible.
#define CANARY 0x5Au
#define PAD 8u
static uint8_t buf[IDEMIP_ARP_LEN + PAD];
static uint8_t alt[IDEMIP_ARP_LEN + PAD];

static void arm(uint8_t *p)
{
    memset(p, 0xC3, IDEMIP_ARP_LEN);
    memset(p + IDEMIP_ARP_LEN, CANARY, PAD);
}

static void check_canary(const uint8_t *p)
{
    for (size_t i = IDEMIP_ARP_LEN; i < IDEMIP_ARP_LEN + PAD; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, p[i], "a write landed past IDEMIP_ARP_LEN");
    }
}

void setUp(void)
{
    arm(buf);
    arm(alt);
}
void tearDown(void)
{
    check_canary(buf);
    check_canary(alt);
}

// --- the constants -----------------------------------------------------------

// RFC 826 "Definitions": "ares_op$REQUEST (= 1, high byte transmitted first) and ares_op$REPLY
// (= 2)", and "ares_hrd$Ethernet (= 1)". "Packet Generation" sets ar$hln to 6; DOD Internet
// addresses are 32.bits, so ar$pln is 4.
void test_constants_match_rfc826_definitions(void)
{
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_ARP_HRD_ETHERNET);
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_ARP_OP_REQUEST);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_ARP_OP_REPLY);
    TEST_ASSERT_EQUAL_UINT8(6u, IDEMIP_ARP_HLN_ETHERNET);
    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_ARP_PLN_IPV4);
}

// RFC 826 "Packet format": "For Ethernet hardware, this is from the set of type fields
// ether_typ$<protocol>", so ar$pro for Internet is the Ethernet type of Internet.
void test_protocol_address_space_is_the_ethernet_type(void)
{
    TEST_ASSERT_EQUAL_HEX16(ET_IP, IDEMIP_ARP_PRO_IPV4);
}

// The field order of RFC 826 "Packet format": two 16-bit words, two bytes, one 16-bit word, then
// the four addresses at ar$hln 6 and ar$pln 4.
void test_field_offsets_match_rfc826_packet_format(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_ARP_OFF_HRD);
    TEST_ASSERT_EQUAL_UINT(2u, IDEMIP_ARP_OFF_PRO);
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ARP_OFF_HLN);
    TEST_ASSERT_EQUAL_UINT(5u, IDEMIP_ARP_OFF_PLN);
    TEST_ASSERT_EQUAL_UINT(6u, IDEMIP_ARP_OFF_OP);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ARP_OFF_SHA);
    TEST_ASSERT_EQUAL_UINT(14u, IDEMIP_ARP_OFF_SPA);
    TEST_ASSERT_EQUAL_UINT(18u, IDEMIP_ARP_OFF_THA);
    TEST_ASSERT_EQUAL_UINT(24u, IDEMIP_ARP_OFF_TPA);
    TEST_ASSERT_EQUAL_UINT(28u, IDEMIP_ARP_LEN);
}

// RFC 826 "Why is it done this way??": "There are no padding bytes between addresses." Each address
// field ends where the next begins, so the four of them fill offsets 8 through 27.
void test_no_padding_between_the_addresses(void)
{
    TEST_ASSERT_EQUAL_PTR(REQ + 8, idemip_arp_sha(REQ));
    TEST_ASSERT_EQUAL_PTR(REQ + 18, idemip_arp_tha(REQ));
    TEST_ASSERT_EQUAL_UINT(IDEMIP_ARP_OFF_SPA, IDEMIP_ARP_OFF_SHA + IDEMIP_ARP_HLN_ETHERNET);
    TEST_ASSERT_EQUAL_UINT(IDEMIP_ARP_OFF_THA, IDEMIP_ARP_OFF_SPA + IDEMIP_ARP_PLN_IPV4);
    TEST_ASSERT_EQUAL_UINT(IDEMIP_ARP_OFF_TPA, IDEMIP_ARP_OFF_THA + IDEMIP_ARP_HLN_ETHERNET);
    TEST_ASSERT_EQUAL_UINT(IDEMIP_ARP_LEN, IDEMIP_ARP_OFF_TPA + IDEMIP_ARP_PLN_IPV4);
}

// RFC 826 Notes: "Numbers here are in the Ethernet standard, which is high byte first ... Therefore,
// special care must be taken with the opcode field (ar$op)." A request is 00 01 on the wire, so a
// low-byte-first read would report 256.
void test_the_three_words_are_high_byte_first(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x00, REQ[IDEMIP_ARP_OFF_OP]);
    TEST_ASSERT_EQUAL_HEX8(0x01, REQ[IDEMIP_ARP_OFF_OP + 1u]);
    TEST_ASSERT_EQUAL_HEX16(1u, idemip_arp_op(REQ));
    TEST_ASSERT_EQUAL_HEX16(1u, idemip_arp_hrd(REQ));
    TEST_ASSERT_EQUAL_HEX16(0x0800u, idemip_arp_pro(REQ));
}

// --- parsing the RFC's example ----------------------------------------------

void test_request_vector_parses(void)
{
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ARP_HRD_ETHERNET, idemip_arp_hrd(REQ));
    TEST_ASSERT_EQUAL_HEX16(ET_IP, idemip_arp_pro(REQ));
    TEST_ASSERT_EQUAL_UINT8(6u, idemip_arp_hln(REQ));
    TEST_ASSERT_EQUAL_UINT8(4u, idemip_arp_pln(REQ));
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ARP_OP_REQUEST, idemip_arp_op(REQ));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EA_X, idemip_arp_sha(REQ), 6);
    TEST_ASSERT_EQUAL_HEX32(IPA_X, idemip_arp_spa(REQ));
    TEST_ASSERT_EQUAL_HEX32(IPA_Y, idemip_arp_tpa(REQ));
    TEST_ASSERT_TRUE(idemip_arp_is_request(REQ));
    TEST_ASSERT_FALSE(idemip_arp_is_reply(REQ));
    TEST_ASSERT_TRUE(idemip_arp_is_ethernet_ipv4(REQ));
}

void test_reply_vector_parses(void)
{
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ARP_OP_REPLY, idemip_arp_op(REP));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EA_Y, idemip_arp_sha(REP), 6);
    TEST_ASSERT_EQUAL_HEX32(IPA_Y, idemip_arp_spa(REP));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EA_X, idemip_arp_tha(REP), 6);
    TEST_ASSERT_EQUAL_HEX32(IPA_X, idemip_arp_tpa(REP));
    TEST_ASSERT_TRUE(idemip_arp_is_reply(REP));
    TEST_ASSERT_FALSE(idemip_arp_is_request(REP));
    TEST_ASSERT_TRUE(idemip_arp_is_ethernet_ipv4(REP));
}

// RFC 826 "Why is it done this way??" on ar$tha: "It has no meaning in the request form, since it is
// this number that the machine is requesting." "Its meaning in the reply form is the address of the
// machine making the request."
void test_target_hardware_address_is_unset_in_a_request_and_the_requester_in_a_reply(void)
{
    for (int i = 0; i < 6; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0x00, idemip_arp_tha(REQ)[i]);
    }
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EA_X, idemip_arp_tha(REP), 6);
}

// RFC 826 "Packet Reception": "?Am I the target protocol address?" Y is, X is not.
void test_is_target_answers_the_reception_question(void)
{
    TEST_ASSERT_TRUE(idemip_arp_is_target(REQ, IPA_Y));
    TEST_ASSERT_FALSE(idemip_arp_is_target(REQ, IPA_X));
    TEST_ASSERT_TRUE(idemip_arp_is_target(REP, IPA_X));
    TEST_ASSERT_FALSE(idemip_arp_is_target(REP, IPA_Y));
}

// RFC 826 "Packet Reception" discards on a negative conditional: the hardware type, the protocol,
// and the two lengths each disqualify the packet on their own, because the offsets above hold only
// for <ar$hrd, ar$pro, ar$hln, ar$pln> = <1, 0x0800, 6, 4>.
void test_is_ethernet_ipv4_rejects_any_other_pairing(void)
{
    memcpy(buf, REQ, IDEMIP_ARP_LEN);
    TEST_ASSERT_TRUE(idemip_arp_is_ethernet_ipv4(buf));

    buf[IDEMIP_ARP_OFF_HRD + 1u] = 3u; // a packet radio net, not Ethernet
    TEST_ASSERT_FALSE(idemip_arp_is_ethernet_ipv4(buf));
    memcpy(buf, REQ, IDEMIP_ARP_LEN);

    buf[IDEMIP_ARP_OFF_PRO + 1u] = 0x35u; // some other ether_type$
    TEST_ASSERT_FALSE(idemip_arp_is_ethernet_ipv4(buf));
    memcpy(buf, REQ, IDEMIP_ARP_LEN);

    buf[IDEMIP_ARP_OFF_HLN] = 8u;
    TEST_ASSERT_FALSE(idemip_arp_is_ethernet_ipv4(buf));
    memcpy(buf, REQ, IDEMIP_ARP_LEN);

    buf[IDEMIP_ARP_OFF_PLN] = 16u;
    TEST_ASSERT_FALSE(idemip_arp_is_ethernet_ipv4(buf));
}

// --- building the RFC's example ---------------------------------------------

void test_build_request_matches_the_vector(void)
{
    idemip_arp_build_request(buf, EA_X, IPA_X, IPA_Y);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(REQ, buf, IDEMIP_ARP_LEN);
}

void test_build_reply_matches_the_vector(void)
{
    idemip_arp_build_reply(buf, EA_Y, IPA_Y, EA_X, IPA_X);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(REP, buf, IDEMIP_ARP_LEN);
}

// RFC 826 "Packet Reception": "Swap hardware and protocol fields, putting the local hardware and
// protocol addresses in the sender fields. Set the ar$op field to ares_op$REPLY". "This format
// allows the packet buffer to be reused if a reply is generated", so the request's own bytes become
// the reply's, byte for byte.
void test_reply_in_place_turns_the_request_into_the_reply(void)
{
    memcpy(buf, REQ, IDEMIP_ARP_LEN);
    idemip_arp_reply_in_place(buf, EA_Y);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(REP, buf, IDEMIP_ARP_LEN);
}

// The request arrives with ar$tha set to the hardware broadcast address rather than zeros, which
// RFC 826 "Packet Generation" also permits: "It could set ar$tha to the broadcast address for the
// hardware (all ones in the case of the 10Mbit Ethernet)". The reply is the same either way, since
// the swap overwrites ar$tha with the requester's ar$sha.
void test_reply_in_place_ignores_whatever_ar_tha_arrived_as(void)
{
    memcpy(buf, REQ, IDEMIP_ARP_LEN);
    memset(buf + IDEMIP_ARP_OFF_THA, 0xFF, IDEMIP_ARP_HLN_ETHERNET);
    idemip_arp_reply_in_place(buf, EA_Y);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(REP, buf, IDEMIP_ARP_LEN);
}

// The same call on the same arguments writes the same bytes, whatever the buffer held before, and
// two buffers do not differ.
void test_a_build_is_a_function_of_its_arguments(void)
{
    idemip_arp_build_request(buf, EA_X, IPA_X, IPA_Y);
    memset(alt, 0x00, IDEMIP_ARP_LEN);
    idemip_arp_build_request(alt, EA_X, IPA_X, IPA_Y);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(buf, alt, IDEMIP_ARP_LEN);

    // And again over its own output.
    idemip_arp_build_request(buf, EA_X, IPA_X, IPA_Y);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(REQ, buf, IDEMIP_ARP_LEN);
}

// A probe carries a zero sender protocol address, which is an argument value and not a special
// case: every field is written from what the caller passed.
void test_build_request_carries_a_zero_sender_protocol_address(void)
{
    idemip_arp_build_request(buf, EA_X, 0u, IPA_Y);
    TEST_ASSERT_EQUAL_HEX32(0u, idemip_arp_spa(buf));
    TEST_ASSERT_EQUAL_HEX32(IPA_Y, idemip_arp_tpa(buf));
    TEST_ASSERT_TRUE(idemip_arp_is_ethernet_ipv4(buf));
    TEST_ASSERT_TRUE(idemip_arp_is_request(buf));
}

// --- the frame the payload rides in -----------------------------------------

// RFC 894 pads the data field to 46 octets, and an ARP payload is 28. The pad is not part of the
// packet, so every field still reads at its offset and the parse never takes a length from the
// frame.
void test_a_padded_frame_still_parses(void)
{
    uint8_t padded[IDEMIP_ETH_MIN_PAYLOAD];
    memset(padded, 0, sizeof padded);
    memcpy(padded, REQ, IDEMIP_ARP_LEN);
    TEST_ASSERT_TRUE(IDEMIP_ARP_LEN < IDEMIP_ETH_MIN_PAYLOAD);
    TEST_ASSERT_TRUE(idemip_arp_is_ethernet_ipv4(padded));
    TEST_ASSERT_EQUAL_HEX32(IPA_Y, idemip_arp_tpa(padded));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EA_X, idemip_arp_sha(padded), 6);
}

// RFC 826 "Why is it done this way??": "a reply has the same length as a request". Both builders
// write IDEMIP_ARP_LEN bytes and neither touches the byte after; tearDown checks the canary on
// every case, and this one names the claim.
void test_a_build_writes_exactly_the_payload(void)
{
    idemip_arp_build_request(buf, EA_X, IPA_X, IPA_Y);
    check_canary(buf);
    idemip_arp_build_reply(alt, EA_Y, IPA_Y, EA_X, IPA_X);
    check_canary(alt);
    TEST_ASSERT_EQUAL_UINT(IDEMIP_ARP_LEN, sizeof REQ);
    TEST_ASSERT_EQUAL_UINT(sizeof REQ, sizeof REP);
}
