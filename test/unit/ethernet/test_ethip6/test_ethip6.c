// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 2464, IPv6 over Ethernet. The suite checks the four things every unit's suite checks:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//
// VECTORS. RFC 2464 prints exactly one numeric example, in sec 4: an interface whose built-in
// address is 34-56-78-9A-BC-DE has the Interface Identifier 36-56-78-FF-FE-9A-BC-DE. That vector is
// asserted verbatim below. sec 5 and sec 7 print figures and no numbers, so the addresses those two
// cases carry are composed here from the rule each section states, and are marked where they are.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ethernet/ethip6.h"

#include <string.h>
#include <unity.h>
#include "src/ethernet/ethernet_defines.h"
#include "src/ip/ipv6_defines.h"

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_ETHIP6_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_ETHIP6_BORROW + 16];

// RFC 2464 sec 4, the printed example: "the Interface Identifier for an Ethernet interface whose
// built-in address is, in hexadecimal, 34-56-78-9A-BC-DE would be 36-56-78-FF-FE-9A-BC-DE."
static const uint8_t rfc2464_mac[6] = {0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE};
static const uint8_t rfc2464_iid[8] = {0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE};

// Composed here, not printed by the RFC: sec 5 appends that identifier to the prefix FE80::/64.
static const uint8_t rfc2464_linklocal[16] = {0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                              0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE};

// A locally administered address: RFC 2464 sec 4's U/L bit is already one, and complementing it
// gives zero.
static const uint8_t local_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

// RFC 4291 sec 2.7.1 All Nodes Address FF02::1. Composed here; RFC 2464 sec 7 prints no number.
static const uint8_t all_nodes[16] = {0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

// A solicited-node address, FF02::1:FF9A:BCDE for the built-in address above. Composed here.
static const uint8_t solicited_node[16] = {0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0x01, 0xFF, 0x9A, 0xBC, 0xDE};

// A unicast destination, which sec 7 does not map.
static const uint8_t unicast[16] = {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_ETHIP6_BORROW, CANARY, cap - IDEMIP_ETHIP6_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_ETHIP6_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_ETHIP6_BORROW");
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

static void ready(uint8_t *w)
{
    Ethip6.clear(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ETHIP6_IO(w)->status);
}

static void eui64_of(uint8_t *w, const uint8_t *mac)
{
    IDEMIP_ETHIP6_IO(w)->mac_args.mac = mac;
    Ethip6.eui64(w);
}

static void linklocal_of(uint8_t *w, const uint8_t *mac)
{
    IDEMIP_ETHIP6_IO(w)->mac_args.mac = mac;
    Ethip6.linklocal(w);
}

static void map_of(uint8_t *w, const uint8_t *dst)
{
    IDEMIP_ETHIP6_IO(w)->multicast_args.dst = dst;
    Ethip6.multicast_map(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Ethip6.clear(NULL);
    Ethip6.multicast_map(NULL);
    Ethip6.eui64(NULL);
    Ethip6.linklocal(NULL);
    TEST_PASS();
}

// The borrow IS the instance, and the operand block is in it, so two derivations share no byte.
void test_two_borrows_share_no_byte(void)
{
    ready(work_a);
    ready(work_b);
    IDEMIP_ETHIP6_IO(work_a)->mac_args.mac = rfc2464_mac;
    IDEMIP_ETHIP6_IO(work_b)->mac_args.mac = local_mac;

    TEST_ASSERT_EQUAL_PTR(rfc2464_mac, IDEMIP_ETHIP6_IO(work_a)->mac_args.mac);
    TEST_ASSERT_EQUAL_PTR(local_mac, IDEMIP_ETHIP6_IO(work_b)->mac_args.mac);

    Ethip6.eui64(work_a);
    Ethip6.eui64(work_b);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(rfc2464_iid, IDEMIP_ETHIP6_IO(work_a)->iid, 8);
    TEST_ASSERT_EQUAL_HEX8(0x00, IDEMIP_ETHIP6_IO(work_b)->iid[0]);
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    ready(work_a);
    ready(work_b);

    eui64_of(work_a, rfc2464_mac);
    uint8_t first[8];
    memcpy(first, IDEMIP_ETHIP6_IO(work_a)->iid, sizeof first);

    eui64_of(work_b, local_mac);
    eui64_of(work_a, rfc2464_mac);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(rfc2464_iid, first, 8);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_ETHIP6_IO(work_a)->iid, 8);
}

// Repeating a call on the same bytes repeats its answer.
void test_repeating_a_call_repeats_its_answer(void)
{
    ready(work_a);
    map_of(work_a, solicited_node);
    uint8_t first[6];
    memcpy(first, IDEMIP_ETHIP6_IO(work_a)->mac, sizeof first);
    map_of(work_a, solicited_node);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_ETHIP6_IO(work_a)->mac, 6);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ETHIP6_IO(work_a)->status);
}

// Zeroed, never cleared: every entry must refuse rather than answer out of bytes no one gave it.
void test_an_uncleared_borrow_refuses_work(void)
{
    map_of(work_a, all_nodes);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ETHIP6_IO(work_a)->status);
    eui64_of(work_a, rfc2464_mac);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ETHIP6_IO(work_a)->status);
    linklocal_of(work_a, rfc2464_mac);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ETHIP6_IO(work_a)->status);
}

void test_clear_reports_ok_and_opens_the_borrow(void)
{
    ready(work_a);
    eui64_of(work_a, rfc2464_mac);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ETHIP6_IO(work_a)->status);
}

// Nothing here waits on hardware or a peer, so a call that cannot finish now cannot finish later.
// Every refusal is ERR and BUSY never appears.
void test_no_entry_ever_reports_busy(void)
{
    ready(work_a);
    map_of(work_a, unicast);
    TEST_ASSERT_NOT_EQUAL(IDEMIP_BUSY, IDEMIP_ETHIP6_IO(work_a)->status);
    map_of(work_a, NULL);
    TEST_ASSERT_NOT_EQUAL(IDEMIP_BUSY, IDEMIP_ETHIP6_IO(work_a)->status);
    eui64_of(work_a, NULL);
    TEST_ASSERT_NOT_EQUAL(IDEMIP_BUSY, IDEMIP_ETHIP6_IO(work_a)->status);
    linklocal_of(work_a, NULL);
    TEST_ASSERT_NOT_EQUAL(IDEMIP_BUSY, IDEMIP_ETHIP6_IO(work_a)->status);
}

// The published map must be the layout the module actually uses.
void test_the_published_map_covers_the_private_layout(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ETHIP6_OFF_IO);
    TEST_ASSERT_TRUE(sizeof(Ethip6Io) <= (size_t)IDEMIP_ETHIP6_OFF_CTX);
    TEST_ASSERT_TRUE((size_t)IDEMIP_ETHIP6_OFF_CTX < (size_t)IDEMIP_ETHIP6_OFF_END);
    TEST_ASSERT_TRUE((size_t)IDEMIP_ETHIP6_OFF_END <= (size_t)IDEMIP_ETHIP6_BORROW);
    TEST_ASSERT_EQUAL_PTR(work_a, IDEMIP_ETHIP6_IO(work_a));
}

// --- sec 4, the interface identifier -----------------------------------------

// The one vector RFC 2464 prints: 34-56-78-9A-BC-DE becomes 36-56-78-FF-FE-9A-BC-DE.
void test_rfc2464_sec4_printed_example(void)
{
    ready(work_a);
    eui64_of(work_a, rfc2464_mac);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ETHIP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(rfc2464_iid, IDEMIP_ETHIP6_IO(work_a)->iid, IDEMIP_ETHIP6_IID_LEN);
}

// "The fourth and fifth octets of the EUI are set to the fixed value FFFE hexadecimal."
void test_eui64_sets_the_fourth_and_fifth_octets_to_fffe(void)
{
    ready(work_a);
    eui64_of(work_a, local_mac);
    TEST_ASSERT_EQUAL_HEX8(0xFF, IDEMIP_ETHIP6_IO(work_a)->iid[3]);
    TEST_ASSERT_EQUAL_HEX8(0xFE, IDEMIP_ETHIP6_IO(work_a)->iid[4]);
}

// "The OUI of the Ethernet address (the first three octets) becomes the company_id of the EUI-64",
// the U/L bit of the first apart.
void test_eui64_carries_the_oui_into_the_company_id(void)
{
    ready(work_a);
    eui64_of(work_a, rfc2464_mac);
    const uint8_t *iid = IDEMIP_ETHIP6_IO(work_a)->iid;
    TEST_ASSERT_EQUAL_HEX8(rfc2464_mac[0] ^ 0x02u, iid[0]);
    TEST_ASSERT_EQUAL_HEX8(rfc2464_mac[1], iid[1]);
    TEST_ASSERT_EQUAL_HEX8(rfc2464_mac[2], iid[2]);
}

// "The last three octets of the Ethernet address become the last three octets of the EUI-64."
void test_eui64_carries_the_last_three_octets(void)
{
    ready(work_a);
    eui64_of(work_a, rfc2464_mac);
    const uint8_t *iid = IDEMIP_ETHIP6_IO(work_a)->iid;
    TEST_ASSERT_EQUAL_HEX8(rfc2464_mac[3], iid[5]);
    TEST_ASSERT_EQUAL_HEX8(rfc2464_mac[4], iid[6]);
    TEST_ASSERT_EQUAL_HEX8(rfc2464_mac[5], iid[7]);
}

// "complementing the 'Universal/Local' (U/L) bit, which is the next-to-lowest order bit of the
// first octet". A one becomes a zero as surely as a zero becomes a one.
void test_eui64_complements_the_ul_bit_in_both_directions(void)
{
    ready(work_a);
    eui64_of(work_a, rfc2464_mac); // U/L bit zero in the built-in address
    TEST_ASSERT_EQUAL_HEX8(0x02u, IDEMIP_ETHIP6_IO(work_a)->iid[0] & 0x02u);
    eui64_of(work_a, local_mac); // U/L bit one in the built-in address
    TEST_ASSERT_EQUAL_HEX8(0x00u, IDEMIP_ETHIP6_IO(work_a)->iid[0] & 0x02u);
}

// The complement touches that one bit and no other bit of the first octet.
void test_eui64_touches_only_the_ul_bit_of_the_first_octet(void)
{
    ready(work_a);
    for (unsigned v = 0; v < 256u; v++)
    {
        uint8_t mac[6] = {(uint8_t)v, 0x11, 0x22, 0x33, 0x44, 0x55};
        eui64_of(work_a, mac);
        uint8_t got = IDEMIP_ETHIP6_IO(work_a)->iid[0];
        TEST_ASSERT_EQUAL_HEX8_MESSAGE((uint8_t)(v & 0xFDu), (uint8_t)(got & 0xFDu),
                                       "a bit outside the U/L bit moved");
        TEST_ASSERT_EQUAL_HEX8_MESSAGE((uint8_t)((v ^ 0x02u) & 0x02u), (uint8_t)(got & 0x02u),
                                       "the U/L bit was not complemented");
    }
}

// "A universally administered IEEE 802 address ... is signified by a 0 in the U/L bit position,
// while a globally unique IPv6 Interface Identifier is signified by a 1."
void test_eui64_reports_a_universally_administered_address(void)
{
    ready(work_a);
    eui64_of(work_a, rfc2464_mac);
    TEST_ASSERT_TRUE(IDEMIP_ETHIP6_IO(work_a)->universal);
    eui64_of(work_a, local_mac);
    TEST_ASSERT_FALSE(IDEMIP_ETHIP6_IO(work_a)->universal);
}

void test_eui64_refuses_a_null_address(void)
{
    ready(work_a);
    eui64_of(work_a, NULL);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ETHIP6_IO(work_a)->status);
}

// A refused call leaves no stale identifier behind.
void test_eui64_zeroes_its_answer_when_refused(void)
{
    ready(work_a);
    eui64_of(work_a, rfc2464_mac);
    eui64_of(work_a, NULL);
    for (unsigned i = 0; i < IDEMIP_ETHIP6_IID_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0x00, IDEMIP_ETHIP6_IO(work_a)->iid[i]);
    }
    TEST_ASSERT_FALSE(IDEMIP_ETHIP6_IO(work_a)->universal);
}

// --- sec 5, the link-local address -------------------------------------------

// "formed by appending the Interface Identifier ... to the prefix FE80::/64", drawn as 1111111010
// then 54 zero bits.
void test_linklocal_prefix_is_fe80_and_fifty_four_zero_bits(void)
{
    ready(work_a);
    linklocal_of(work_a, rfc2464_mac);
    const uint8_t *addr = IDEMIP_ETHIP6_IO(work_a)->addr;
    TEST_ASSERT_EQUAL_HEX8(0xFE, addr[0]);
    TEST_ASSERT_EQUAL_HEX8(0x80, addr[1]);
    for (unsigned i = 2; i < IDEMIP_ETHIP6_LINKLOCAL_PREFIX_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, addr[i], "a bit of the 54 zeros was set");
    }
}

// The low 64 bits are exactly what sec 4 derives.
void test_linklocal_appends_the_sec4_identifier(void)
{
    ready(work_a);
    eui64_of(work_a, rfc2464_mac);
    uint8_t iid[8];
    memcpy(iid, IDEMIP_ETHIP6_IO(work_a)->iid, sizeof iid);
    linklocal_of(work_a, rfc2464_mac);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(iid, IDEMIP_ETHIP6_IO(work_a)->addr + IDEMIP_ETHIP6_LINKLOCAL_PREFIX_LEN, 8);
}

// Composed from sec 4's printed example and sec 5's rule: FE80::3656:78FF:FE9A:BCDE.
void test_linklocal_of_the_sec4_printed_example(void)
{
    ready(work_a);
    linklocal_of(work_a, rfc2464_mac);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ETHIP6_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(rfc2464_linklocal, IDEMIP_ETHIP6_IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
}

// The identifier it appended is reported too, so a caller needs one call rather than two.
void test_linklocal_also_reports_the_identifier(void)
{
    ready(work_a);
    linklocal_of(work_a, rfc2464_mac);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(rfc2464_iid, IDEMIP_ETHIP6_IO(work_a)->iid, IDEMIP_ETHIP6_IID_LEN);
    TEST_ASSERT_TRUE(IDEMIP_ETHIP6_IO(work_a)->universal);
}

void test_linklocal_refuses_a_null_address(void)
{
    ready(work_a);
    linklocal_of(work_a, NULL);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ETHIP6_IO(work_a)->status);
}

void test_linklocal_zeroes_its_answer_when_refused(void)
{
    ready(work_a);
    linklocal_of(work_a, rfc2464_mac);
    linklocal_of(work_a, NULL);
    for (unsigned i = 0; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0x00, IDEMIP_ETHIP6_IO(work_a)->addr[i]);
    }
}

// Two interfaces get two link-local addresses, and neither call disturbs the other.
void test_two_borrows_derive_two_link_local_addresses(void)
{
    ready(work_a);
    ready(work_b);
    linklocal_of(work_a, rfc2464_mac);
    linklocal_of(work_b, local_mac);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(rfc2464_linklocal, IDEMIP_ETHIP6_IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_HEX8(0x00, IDEMIP_ETHIP6_IO(work_b)->addr[8]);
    TEST_ASSERT_EQUAL_HEX8(0xFE, IDEMIP_ETHIP6_IO(work_b)->addr[0]);
}

// --- sec 7, the multicast mapping ---------------------------------------------

// "whose first two octets are the value 3333 hexadecimal and whose last four octets are the last
// four octets of DST", the figure naming those DST[13] through DST[16].
void test_multicast_map_writes_3333_then_the_last_four_octets(void)
{
    ready(work_a);
    map_of(work_a, solicited_node);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ETHIP6_IO(work_a)->status);
    const uint8_t *mac = IDEMIP_ETHIP6_IO(work_a)->mac;
    TEST_ASSERT_EQUAL_HEX8(0x33, mac[0]);
    TEST_ASSERT_EQUAL_HEX8(0x33, mac[1]);
    TEST_ASSERT_EQUAL_HEX8(solicited_node[12], mac[2]);
    TEST_ASSERT_EQUAL_HEX8(solicited_node[13], mac[3]);
    TEST_ASSERT_EQUAL_HEX8(solicited_node[14], mac[4]);
    TEST_ASSERT_EQUAL_HEX8(solicited_node[15], mac[5]);
}

// Composed here, RFC 2464 sec 7 printing no number: FF02::1 maps to 33-33-00-00-00-01.
void test_multicast_map_of_the_all_nodes_address(void)
{
    static const uint8_t want[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
    ready(work_a);
    map_of(work_a, all_nodes);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, IDEMIP_ETHIP6_IO(work_a)->mac, IDEMIP_MAC_LEN);
}

// Composed here: FF02::1:FF9A:BCDE maps to 33-33-FF-9A-BC-DE.
void test_multicast_map_of_a_solicited_node_address(void)
{
    static const uint8_t want[6] = {0x33, 0x33, 0xFF, 0x9A, 0xBC, 0xDE};
    ready(work_a);
    map_of(work_a, solicited_node);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(want, IDEMIP_ETHIP6_IO(work_a)->mac, IDEMIP_MAC_LEN);
}

// sec 7 reads the last four octets and nothing else, so two destinations differing only above them
// map to one Ethernet address.
void test_multicast_map_reads_only_the_last_four_octets(void)
{
    uint8_t one[16];
    uint8_t two[16];
    memcpy(one, all_nodes, sizeof one);
    memcpy(two, all_nodes, sizeof two);
    two[1] = 0x05;
    two[8] = 0xAB;
    two[11] = 0xCD;

    ready(work_a);
    map_of(work_a, one);
    uint8_t first[6];
    memcpy(first, IDEMIP_ETHIP6_IO(work_a)->mac, sizeof first);
    map_of(work_a, two);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_ETHIP6_IO(work_a)->mac, IDEMIP_MAC_LEN);
}

// Every one of the 2^32 tails reaches its own Ethernet address, so a change in any of the four
// octets changes the answer.
void test_multicast_map_carries_every_one_of_the_four_octets(void)
{
    ready(work_a);
    for (unsigned i = 12; i < 16u; i++)
    {
        uint8_t dst[16];
        memcpy(dst, all_nodes, sizeof dst);
        dst[i] = (uint8_t)(0xA0u + i);
        map_of(work_a, dst);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE((uint8_t)(0xA0u + i), IDEMIP_ETHIP6_IO(work_a)->mac[i - 10u],
                                       "an octet of DST did not reach the mapped address");
    }
}

// sec 7 states the mapping for "an IPv6 packet with a multicast destination address DST". RFC 4291
// sec 2.7 identifies one by its leading 11111111, and no retry turns a unicast address into one.
void test_multicast_map_refuses_a_unicast_destination(void)
{
    ready(work_a);
    map_of(work_a, unicast);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ETHIP6_IO(work_a)->status);
    for (unsigned i = 0; i < IDEMIP_MAC_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, IDEMIP_ETHIP6_IO(work_a)->mac[i],
                                       "a refused mapping left an address behind");
    }
}

// One octet below the multicast prefix is still not multicast.
void test_multicast_map_refuses_a_first_octet_one_short_of_ff(void)
{
    uint8_t dst[16];
    memcpy(dst, all_nodes, sizeof dst);
    dst[0] = 0xFE;
    ready(work_a);
    map_of(work_a, dst);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ETHIP6_IO(work_a)->status);
}

void test_multicast_map_refuses_a_null_destination(void)
{
    ready(work_a);
    map_of(work_a, NULL);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ETHIP6_IO(work_a)->status);
}

// Every scope and flag combination above the prefix octet is mapped, sec 7 naming none of them.
void test_multicast_map_accepts_every_scope(void)
{
    ready(work_a);
    for (unsigned scope = 0; scope < 16u; scope++)
    {
        uint8_t dst[16];
        memcpy(dst, all_nodes, sizeof dst);
        dst[1] = (uint8_t)scope;
        map_of(work_a, dst);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_ETHIP6_IO(work_a)->status, "a scope was refused");
    }
}

// --- the constants -------------------------------------------------------------

// RFC 2464 sec 2: "The default MTU size for IPv6 packets on an Ethernet is 1500 octets."
void test_sec2_default_mtu_is_1500(void)
{
    TEST_ASSERT_EQUAL_UINT16(1500u, (uint16_t)IDEMIP_ETHIP6_MTU);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_ETH_MAX_PAYLOAD, (uint16_t)IDEMIP_ETHIP6_MTU);
}

// RFC 2464 sec 3: the Ethernet type code "must contain the value 86DD hexadecimal".
void test_sec3_type_code_is_86dd(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x86DD, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
}

// The field widths sec 4, sec 5 and sec 7 state.
void test_the_field_widths_are_the_stated_ones(void)
{
    TEST_ASSERT_EQUAL_UINT8(8u, (uint8_t)IDEMIP_ETHIP6_IID_LEN);
    TEST_ASSERT_EQUAL_UINT8(3u, (uint8_t)IDEMIP_ETHIP6_OUI_LEN);
    TEST_ASSERT_EQUAL_UINT8(3u, (uint8_t)IDEMIP_ETHIP6_TAIL_LEN);
    TEST_ASSERT_EQUAL_UINT8(8u, (uint8_t)IDEMIP_ETHIP6_LINKLOCAL_PREFIX_LEN);
    TEST_ASSERT_EQUAL_UINT8(2u, (uint8_t)IDEMIP_ETHIP6_MCAST_PREFIX_LEN);
    TEST_ASSERT_EQUAL_UINT8(4u, (uint8_t)IDEMIP_ETHIP6_MCAST_TAIL_LEN);
    TEST_ASSERT_EQUAL_HEX8(0x02, (uint8_t)IDEMIP_ETHIP6_UL_BIT);
}
