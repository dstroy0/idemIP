// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 894, Ethernet II framing for IP. RFC 894 prints no octet figure, so the byte values it
// actually fixes are the IPv4 type code 0800 ("Frame Format"), the broadcast address
// FF-FF-FF-FF-FF-FF ("Address Mappings"), and the two data field bounds 46 and 1500. The header
// layout itself comes from RFC 2464 sec 3, whose figure draws the two 48-bit addresses and the
// 16-bit type code; the ARP type code comes from RFC 1042 "Frame Format and MAC Level Issues",
// which prints the Assigned Numbers values in decimal. The addresses in the frame vectors below are
// arbitrary locally administered ones: only their positions are asserted, never their values.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ethernet/ethernet.h"

#include <string.h>
#include <unity.h>
#include "src/ethernet/ethernet_defines.h"

// A frame, and a canary past the longest one RFC 894 allows so a write off the end is visible.
#define CANARY 0x5Au
#define FRAME_CAP ((size_t)IDEMIP_ETH_FRAME_MAX)
static uint8_t frame[IDEMIP_ETH_FRAME_MAX + 8];

static const uint8_t vec_dst[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
static const uint8_t vec_src[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t vec_broadcast[IDEMIP_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// The 14 octets an IPv4 frame carries with those two addresses: dst, src, then 08 00.
static const uint8_t vec_ip4_header[IDEMIP_ETH_HDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02,
                                                           0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00};

void setUp(void)
{
    memset(frame, 0, FRAME_CAP);
    memset(frame + FRAME_CAP, CANARY, sizeof frame - FRAME_CAP);
}

void tearDown(void)
{
    for (size_t i = FRAME_CAP; i < sizeof frame; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, frame[i], "a write landed past IDEMIP_ETH_FRAME_MAX");
    }
}

// --- the type codes ----------------------------------------------------------

// RFC 894 "Frame Format": "The type field of the Ethernet frame must contain the value hexadecimal
// 0800."
void test_rfc894_ipv4_type_code_is_0800(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x0800u, IDEMIP_ETHERTYPE_IPV4);
    idemip_eth_build(frame, vec_dst, vec_src, IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_EQUAL_HEX8(0x08u, frame[IDEMIP_ETH_OFF_TYPE]);
    TEST_ASSERT_EQUAL_HEX8(0x00u, frame[IDEMIP_ETH_OFF_TYPE + 1u]);
    TEST_ASSERT_EQUAL_HEX16(0x0800u, idemip_eth_type(frame));
}

// RFC 1042 "Frame Format and MAC Level Issues": "the remaining 16 bits are the EtherType from
// Assigned Numbers [7] (IP = 2048, ARP = 2054)". RFC 826 itself names the value only symbolically,
// as ether_type$ADDRESS_RESOLUTION, so this is where the number comes from.
void test_rfc1042_assigned_type_codes_in_decimal(void)
{
    TEST_ASSERT_EQUAL_UINT16(2048u, IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_EQUAL_UINT16(2054u, IDEMIP_ETHERTYPE_ARP);
    TEST_ASSERT_EQUAL_HEX16(0x0806u, IDEMIP_ETHERTYPE_ARP);

    idemip_eth_build(frame, vec_broadcast, vec_src, IDEMIP_ETHERTYPE_ARP);
    TEST_ASSERT_EQUAL_HEX8(0x08u, frame[IDEMIP_ETH_OFF_TYPE]);
    TEST_ASSERT_EQUAL_HEX8(0x06u, frame[IDEMIP_ETH_OFF_TYPE + 1u]);
}

// RFC 2464 sec 3 prints the type code as a bit figure: 1 0 0 0 0 1 1 0 1 1 0 1 1 1 0 1. Assembled
// most significant bit first, that is the 86DD the same section states in hex.
void test_rfc2464_ipv6_type_code_bit_figure(void)
{
    const uint8_t bits[16] = {1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1};
    uint16_t assembled = 0u;
    for (size_t i = 0; i < 16; i++)
    {
        assembled = (uint16_t)((assembled << 1) | bits[i]);
    }
    TEST_ASSERT_EQUAL_HEX16(0x86DDu, assembled);
    TEST_ASSERT_EQUAL_HEX16(assembled, IDEMIP_ETHERTYPE_IPV6);

    idemip_eth_build(frame, vec_dst, vec_src, IDEMIP_ETHERTYPE_IPV6);
    TEST_ASSERT_EQUAL_HEX8(0x86u, frame[IDEMIP_ETH_OFF_TYPE]);
    TEST_ASSERT_EQUAL_HEX8(0xDDu, frame[IDEMIP_ETH_OFF_TYPE + 1u]);
    TEST_ASSERT_EQUAL_HEX16(0x86DDu, idemip_eth_type(frame));
}

// --- the layout --------------------------------------------------------------

// RFC 2464 sec 3: "The Ethernet header contains the Destination and Source Ethernet addresses and
// the Ethernet type code", two 48-bit addresses then one 16-bit code, 14 octets in all.
void test_header_is_two_addresses_then_a_type_code(void)
{
    TEST_ASSERT_EQUAL_UINT(14u, IDEMIP_ETH_HDR_LEN);
    TEST_ASSERT_EQUAL_UINT(6u, IDEMIP_MAC_LEN);
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_ETH_OFF_DST);
    TEST_ASSERT_EQUAL_UINT(6u, IDEMIP_ETH_OFF_SRC);
    TEST_ASSERT_EQUAL_UINT(12u, IDEMIP_ETH_OFF_TYPE);
    TEST_ASSERT_EQUAL_UINT(14u, IDEMIP_ETH_OFF_PAYLOAD);
}

// An accessor hands back a pointer into the frame, so a field is read where it lies and nothing is
// copied out of the DMA buffer.
void test_addresses_are_read_in_place(void)
{
    memcpy(frame, vec_ip4_header, sizeof vec_ip4_header);
    TEST_ASSERT_EQUAL_PTR(frame + 0, idemip_eth_dst(frame));
    TEST_ASSERT_EQUAL_PTR(frame + 6, idemip_eth_src(frame));
    TEST_ASSERT_EQUAL_PTR(frame + 14, idemip_eth_payload(frame));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(vec_dst, idemip_eth_dst(frame), IDEMIP_MAC_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(vec_src, idemip_eth_src(frame), IDEMIP_MAC_LEN);
    TEST_ASSERT_EQUAL_HEX16(0x0800u, idemip_eth_type(frame));
}

// The engine puts a frame wherever its descriptor points, so the type code is assembled from its
// two octets and reads the same at every address, aligned or not.
void test_type_code_reads_the_same_at_any_frame_address(void)
{
    for (size_t off = 0; off < 4; off++)
    {
        memset(frame, 0, FRAME_CAP);
        memcpy(frame + off, vec_ip4_header, sizeof vec_ip4_header);
        TEST_ASSERT_EQUAL_HEX16(0x0800u, idemip_eth_type(frame + off));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(vec_src, idemip_eth_src(frame + off), IDEMIP_MAC_LEN);
    }
}

// --- build -------------------------------------------------------------------

void test_build_writes_exactly_the_header(void)
{
    memset(frame, 0xC3, FRAME_CAP);
    idemip_eth_build(frame, vec_dst, vec_src, IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(vec_ip4_header, frame, IDEMIP_ETH_HDR_LEN);
    // The data field is the caller's, so build did not touch the first octet of it.
    TEST_ASSERT_EQUAL_HEX8(0xC3u, frame[IDEMIP_ETH_OFF_PAYLOAD]);
}

void test_build_then_parse_round_trips(void)
{
    idemip_eth_build(frame, vec_src, vec_dst, IDEMIP_ETHERTYPE_ARP);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(vec_src, idemip_eth_dst(frame), IDEMIP_MAC_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(vec_dst, idemip_eth_src(frame), IDEMIP_MAC_LEN);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ETHERTYPE_ARP, idemip_eth_type(frame));
}

// --- the broadcast address ---------------------------------------------------

// RFC 894 "Address Mappings", Broadcast Address: "the broadcast Ethernet address (of all binary
// ones, FF-FF-FF-FF-FF-FF hex)".
void test_broadcast_address_is_all_ones(void)
{
    TEST_ASSERT_TRUE(idemip_eth_is_broadcast(vec_broadcast));
    TEST_ASSERT_FALSE(idemip_eth_is_broadcast(vec_dst));

    // One octet short of all ones is not the broadcast address, at any of the six positions.
    for (size_t i = 0; i < IDEMIP_MAC_LEN; i++)
    {
        uint8_t mac[IDEMIP_MAC_LEN];
        memcpy(mac, vec_broadcast, sizeof mac);
        mac[i] = 0xFEu;
        TEST_ASSERT_FALSE_MESSAGE(idemip_eth_is_broadcast(mac), "an address with one clear bit read as broadcast");
    }

    // A multicast address with the group bit set is not the broadcast address either.
    const uint8_t ip4_multicast[IDEMIP_MAC_LEN] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
    TEST_ASSERT_FALSE(idemip_eth_is_broadcast(ip4_multicast));
}

void test_a_broadcast_destination_is_recognized_in_a_frame(void)
{
    idemip_eth_build(frame, vec_broadcast, vec_src, IDEMIP_ETHERTYPE_ARP);
    TEST_ASSERT_TRUE(idemip_eth_is_broadcast(idemip_eth_dst(frame)));
    TEST_ASSERT_FALSE(idemip_eth_is_broadcast(idemip_eth_src(frame)));
}

// --- the data field bounds ---------------------------------------------------

// RFC 894: "The minimum length of the data field of a packet sent over an Ethernet is 46 octets."
void test_min_payload_is_46_octets(void)
{
    TEST_ASSERT_EQUAL_UINT(46u, IDEMIP_ETH_MIN_PAYLOAD);
    TEST_ASSERT_EQUAL_UINT(60u, IDEMIP_ETH_FRAME_MIN);
    TEST_ASSERT_EQUAL_size_t(46u, idemip_eth_padded_payload(0u));
    TEST_ASSERT_EQUAL_size_t(46u, idemip_eth_padded_payload(45u));
    TEST_ASSERT_EQUAL_size_t(46u, idemip_eth_padded_payload(46u));
    TEST_ASSERT_EQUAL_size_t(47u, idemip_eth_padded_payload(47u));
    TEST_ASSERT_EQUAL_size_t(60u, idemip_eth_frame_len(0u));
    TEST_ASSERT_EQUAL_size_t(60u, idemip_eth_frame_len(46u));
    TEST_ASSERT_EQUAL_size_t(61u, idemip_eth_frame_len(47u));
}

// RFC 894: "the maximum length of an IP datagram sent over an Ethernet is 1500 octets."
void test_max_payload_is_1500_octets(void)
{
    TEST_ASSERT_EQUAL_UINT(1500u, IDEMIP_ETH_MAX_PAYLOAD);
    TEST_ASSERT_EQUAL_UINT(1514u, IDEMIP_ETH_FRAME_MAX);
    TEST_ASSERT_EQUAL_size_t(1514u, idemip_eth_frame_len(1500u));
}

// RFC 894: "If necessary, the data field should be padded (with octets of zero) to meet the
// Ethernet minimum frame size."
void test_pad_zeroes_the_shortfall(void)
{
    memset(frame, 0xFF, FRAME_CAP);
    idemip_eth_build(frame, vec_dst, vec_src, IDEMIP_ETHERTYPE_IPV4);
    memset(frame + IDEMIP_ETH_OFF_PAYLOAD, 0xAA, 4u);

    TEST_ASSERT_EQUAL_size_t(46u, idemip_eth_pad(frame, 4u));

    // The four data octets survived, the 42 pad octets are zero, and nothing past 60 moved.
    for (size_t i = 0; i < 4u; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0xAAu, frame[IDEMIP_ETH_OFF_PAYLOAD + i]);
    }
    for (size_t i = 4u; i < IDEMIP_ETH_MIN_PAYLOAD; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00u, frame[IDEMIP_ETH_OFF_PAYLOAD + i], "the pad is not zero");
    }
    TEST_ASSERT_EQUAL_HEX8(0xFFu, frame[IDEMIP_ETH_FRAME_MIN]);
}

// A data field already at or past 46 octets needs no pad, so nothing is written.
void test_a_full_length_payload_is_not_padded(void)
{
    memset(frame, 0xC3, FRAME_CAP);
    idemip_eth_build(frame, vec_dst, vec_src, IDEMIP_ETHERTYPE_IPV4);

    TEST_ASSERT_EQUAL_size_t(46u, idemip_eth_pad(frame, 46u));
    for (size_t i = 0; i < IDEMIP_ETH_MIN_PAYLOAD; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, frame[IDEMIP_ETH_OFF_PAYLOAD + i], "pad wrote over the data field");
    }

    TEST_ASSERT_EQUAL_size_t(1500u, idemip_eth_pad(frame, 1500u));
    TEST_ASSERT_EQUAL_HEX8(0xC3u, frame[IDEMIP_ETH_FRAME_MAX - 1u]);
}

// RFC 894: "The data field contains the IP header followed immediately by the IP data", so the
// datagram starts at the fifteenth octet of the frame.
void test_payload_follows_the_header(void)
{
    idemip_eth_build(frame, vec_dst, vec_src, IDEMIP_ETHERTYPE_IPV4);
    frame[IDEMIP_ETH_OFF_PAYLOAD] = 0x45u; // an IPv4 version and IHL, RFC 791 sec 3.1
    TEST_ASSERT_EQUAL_PTR(frame + IDEMIP_ETH_HDR_LEN, idemip_eth_payload(frame));
    TEST_ASSERT_EQUAL_HEX8(0x45u, *idemip_eth_payload(frame));
}

// RFC 1042 puts an EtherType behind eight octets: "the assigned global SAP value for SNAP" in both
// SAP fields, the "Unnumbered Information format, control code 3", and a zero Organization Code. A
// header differing in any one of those six octets is not that header, so each is read.
void test_the_snap_header_is_read_octet_by_octet(void)
{
    uint8_t llc[8];
    static const uint8_t good[8] = {0xAAu, 0xAAu, 0x03u, 0u, 0u, 0u, 0x08u, 0x00u};
    memcpy(llc, good, sizeof llc);
    TEST_ASSERT_TRUE_MESSAGE(idemip_llc_is_snap(llc), "the header RFC 1042 gives was not read as one");

    // One octet at a time, each of the six the test reads.
    static const uint8_t at[6] = {IDEMIP_LLC_OFF_DSAP, IDEMIP_LLC_OFF_SSAP,     IDEMIP_LLC_OFF_CONTROL,
                                  IDEMIP_LLC_OFF_ORG,  IDEMIP_LLC_OFF_ORG + 1u, IDEMIP_LLC_OFF_ORG + 2u};
    for (unsigned k = 0; k < 6u; k++)
    {
        memcpy(llc, good, sizeof llc);
        llc[at[k]] = (uint8_t)(llc[at[k]] + 1u);
        TEST_ASSERT_FALSE_MESSAGE(idemip_llc_is_snap(llc), "a header differing from RFC 1042's was read as one");
    }
}
