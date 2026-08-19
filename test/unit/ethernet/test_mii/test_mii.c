// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// mii.h holds no state, so there is no borrow to test. What there is to test is whether every
// constant matches an outside source and whether the resolve helper walks the base page in the
// order those sources walk it.
//
// IEEE 802.3 Clause 22 could not be obtained (see the report), so the vectors below are the literal
// hex from three open transcriptions, typed out here a second time rather than referenced, so that
// a change to mii.h has to disagree with a number in this file to pass:
//
//   L  Linux include/uapi/linux/mii.h            MII_*, BMCR_*, BMSR_*, ADVERTISE_*, LPA_*
//   B  FreeBSD sys/dev/mii/mii.h                 MII_*, BMCR_*, BMSR_*, ANAR_*, ANLPAR_*
//   R  FreeBSD sys/dev/mii/ukphy_subr.c ukphy_status(), Linux include/linux/mii.h
//      mii_nway_result(), for the resolution order
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ethernet/mii.h"
#include "src/ethernet/phy.h"

#include <string.h>
#include <unity.h>

void setUp(void)
{
}
void tearDown(void)
{
}

// --- register addresses ------------------------------------------------------

// L MII_BMCR 0x00, MII_BMSR 0x01, MII_PHYSID1 0x02, MII_PHYSID2 0x03, MII_ADVERTISE 0x04,
// MII_LPA 0x05, MII_EXPANSION 0x06, MII_MMD_CTRL 0x0d, MII_MMD_DATA 0x0e.
// B MII_BMCR 0x00, MII_BMSR 0x01, MII_PHYIDR1 0x02, MII_PHYIDR2 0x03, MII_ANAR 0x04,
// MII_ANLPAR 0x05, MII_ANER 0x06, MII_MMDACR 0x0d, MII_MMDAADR 0x0e.
void test_register_addresses_match_both_sources(void)
{
    TEST_ASSERT_EQUAL_HEX8(0x00, IDEMIP_MII_BMCR);
    TEST_ASSERT_EQUAL_HEX8(0x01, IDEMIP_MII_BMSR);
    TEST_ASSERT_EQUAL_HEX8(0x02, IDEMIP_MII_PHYID1);
    TEST_ASSERT_EQUAL_HEX8(0x03, IDEMIP_MII_PHYID2);
    TEST_ASSERT_EQUAL_HEX8(0x04, IDEMIP_MII_ANAR);
    TEST_ASSERT_EQUAL_HEX8(0x05, IDEMIP_MII_ANLPAR);
    TEST_ASSERT_EQUAL_HEX8(0x06, IDEMIP_MII_ANER);
    TEST_ASSERT_EQUAL_HEX8(0x0D, IDEMIP_MII_MMDCTRL);
    TEST_ASSERT_EQUAL_HEX8(0x0E, IDEMIP_MII_MMDAD);
}

// Every address fits the 5-bit register field, and the whole standard set is below 16.
void test_register_addresses_fit_the_five_bit_field(void)
{
    TEST_ASSERT_EQUAL_UINT(32u, IDEMIP_MII_REG_MAX);
    TEST_ASSERT_EQUAL_UINT(32u, IDEMIP_MII_PHY_ADDR_MAX);
    TEST_ASSERT_TRUE(IDEMIP_MII_MMDAD < 16u);
    TEST_ASSERT_TRUE(IDEMIP_MII_MMDAD < IDEMIP_MII_REG_MAX);
}

// --- register 0, Basic Mode Control ------------------------------------------

// L BMCR_RESET 0x8000, BMCR_LOOPBACK 0x4000, BMCR_SPEED100 0x2000, BMCR_ANENABLE 0x1000,
// BMCR_PDOWN 0x0800, BMCR_ISOLATE 0x0400, BMCR_ANRESTART 0x0200, BMCR_FULLDPLX 0x0100,
// BMCR_CTST 0x0080, BMCR_SPEED1000 0x0040.
// B BMCR_RESET, BMCR_LOOP, BMCR_SPEED0, BMCR_AUTOEN, BMCR_PDOWN, BMCR_ISO, BMCR_STARTNEG,
// BMCR_FDX, BMCR_CTEST, BMCR_SPEED1, same values.
void test_bmcr_bits_match_both_sources(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x8000, IDEMIP_BMCR_RESET);
    TEST_ASSERT_EQUAL_HEX16(0x4000, IDEMIP_BMCR_LOOPBACK);
    TEST_ASSERT_EQUAL_HEX16(0x2000, IDEMIP_BMCR_SPEED_100);
    TEST_ASSERT_EQUAL_HEX16(0x1000, IDEMIP_BMCR_ANEG_ENABLE);
    TEST_ASSERT_EQUAL_HEX16(0x0800, IDEMIP_BMCR_POWER_DOWN);
    TEST_ASSERT_EQUAL_HEX16(0x0400, IDEMIP_BMCR_ISOLATE);
    TEST_ASSERT_EQUAL_HEX16(0x0200, IDEMIP_BMCR_ANEG_RESTART);
    TEST_ASSERT_EQUAL_HEX16(0x0100, IDEMIP_BMCR_FULL_DUPLEX);
    TEST_ASSERT_EQUAL_HEX16(0x0080, IDEMIP_BMCR_COLLISION_TEST);
    TEST_ASSERT_EQUAL_HEX16(0x0040, IDEMIP_BMCR_SPEED_1000);
}

// The ten named bits are the whole of register 0: bits 5:0 other than bit 6 are named by neither
// source, L calling them BMCR_RESV 0x003f.
void test_bmcr_names_no_bit_the_sources_call_reserved(void)
{
    uint16_t named = (uint16_t)(IDEMIP_BMCR_RESET | IDEMIP_BMCR_LOOPBACK | IDEMIP_BMCR_SPEED_100 |
                               IDEMIP_BMCR_ANEG_ENABLE | IDEMIP_BMCR_POWER_DOWN | IDEMIP_BMCR_ISOLATE |
                               IDEMIP_BMCR_ANEG_RESTART | IDEMIP_BMCR_FULL_DUPLEX | IDEMIP_BMCR_COLLISION_TEST |
                               IDEMIP_BMCR_SPEED_1000);
    TEST_ASSERT_EQUAL_HEX16(0xFFC0, named);
    TEST_ASSERT_EQUAL_HEX16(0x0000, (uint16_t)(named & 0x003Fu));
}

// L BMCR_SPEED10 0x0000, BMCR_SPEED100 0x2000, BMCR_SPEED1000 0x0040; B BMCR_S10, BMCR_S100,
// BMCR_S1000 and BMCR_SPEED(x) masking bits 13 and 6 together. 1000 Mb/s is the MSB alone, so a
// word with both speed bits set is not 1000.
void test_bmcr_speed_select_is_one_field_split_across_two_bits(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x2040, IDEMIP_BMCR_SPEED_MASK);
    TEST_ASSERT_EQUAL_HEX16(0x0000, IDEMIP_BMCR_SPEED_SEL_10);
    TEST_ASSERT_EQUAL_HEX16(0x2000, IDEMIP_BMCR_SPEED_SEL_100);
    TEST_ASSERT_EQUAL_HEX16(0x0040, IDEMIP_BMCR_SPEED_SEL_1000);
    TEST_ASSERT_NOT_EQUAL_UINT16(IDEMIP_BMCR_SPEED_SEL_1000, IDEMIP_BMCR_SPEED_MASK);
}

// --- register 1, Basic Mode Status -------------------------------------------

// L BMSR_100BASE4 0x8000, BMSR_100FULL 0x4000, BMSR_100HALF 0x2000, BMSR_10FULL 0x1000,
// BMSR_10HALF 0x0800, BMSR_100FULL2 0x0400, BMSR_100HALF2 0x0200, BMSR_ESTATEN 0x0100,
// BMSR_ANEGCOMPLETE 0x0020, BMSR_RFAULT 0x0010, BMSR_ANEGCAPABLE 0x0008, BMSR_LSTATUS 0x0004,
// BMSR_JCD 0x0002, BMSR_ERCAP 0x0001. B BMSR_100T4 .. BMSR_EXTCAP, same values.
void test_bmsr_bits_match_both_sources(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x8000, IDEMIP_BMSR_100BASE_T4);
    TEST_ASSERT_EQUAL_HEX16(0x4000, IDEMIP_BMSR_100BASE_TX_FD);
    TEST_ASSERT_EQUAL_HEX16(0x2000, IDEMIP_BMSR_100BASE_TX_HD);
    TEST_ASSERT_EQUAL_HEX16(0x1000, IDEMIP_BMSR_10BASE_T_FD);
    TEST_ASSERT_EQUAL_HEX16(0x0800, IDEMIP_BMSR_10BASE_T_HD);
    TEST_ASSERT_EQUAL_HEX16(0x0400, IDEMIP_BMSR_100BASE_T2_FD);
    TEST_ASSERT_EQUAL_HEX16(0x0200, IDEMIP_BMSR_100BASE_T2_HD);
    TEST_ASSERT_EQUAL_HEX16(0x0100, IDEMIP_BMSR_EXT_STATUS);
    TEST_ASSERT_EQUAL_HEX16(0x0020, IDEMIP_BMSR_ANEG_COMPLETE);
    TEST_ASSERT_EQUAL_HEX16(0x0010, IDEMIP_BMSR_REMOTE_FAULT);
    TEST_ASSERT_EQUAL_HEX16(0x0008, IDEMIP_BMSR_ANEG_ABLE);
    TEST_ASSERT_EQUAL_HEX16(0x0004, IDEMIP_BMSR_LINK_UP);
    TEST_ASSERT_EQUAL_HEX16(0x0002, IDEMIP_BMSR_JABBER);
    TEST_ASSERT_EQUAL_HEX16(0x0001, IDEMIP_BMSR_EXT_CAPABILITY);
}

// B BMSR_MFPS 0x0040 is the only source that names bit 6; L folds bits 7 and 6 into BMSR_RESV
// 0x00c0. Bit 7 stays unnamed here, matching both.
void test_bmsr_preamble_suppression_is_bit_six_only(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x0040, IDEMIP_BMSR_MF_PREAMBLE_SUPP);
    TEST_ASSERT_EQUAL_HEX16(0x0000, (uint16_t)(IDEMIP_BMSR_MF_PREAMBLE_SUPP & 0x0080u));
}

// B BMSR_MEDIAMASK is the seven ability bits, 15:9.
void test_bmsr_ability_bits_are_the_top_seven(void)
{
    uint16_t media = (uint16_t)(IDEMIP_BMSR_100BASE_T4 | IDEMIP_BMSR_100BASE_TX_FD | IDEMIP_BMSR_100BASE_TX_HD |
                                IDEMIP_BMSR_10BASE_T_FD | IDEMIP_BMSR_10BASE_T_HD | IDEMIP_BMSR_100BASE_T2_FD |
                                IDEMIP_BMSR_100BASE_T2_HD);
    TEST_ASSERT_EQUAL_HEX16(0xFE00, media);
}

// B BMSR_MEDIA_TO_ANAR(x) is ((x) & BMSR_MEDIAMASK) >> 6, so the five base-page abilities sit six
// bits lower in register 4 than in register 1. Both tables have to agree for this to hold, so this
// checks one against the other rather than either against itself.
void test_bmsr_ability_bits_are_six_above_the_register_four_bits(void)
{
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_100BASE_T4, IDEMIP_BMSR_100BASE_T4 >> 6);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_100BASE_TX_FD, IDEMIP_BMSR_100BASE_TX_FD >> 6);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_100BASE_TX_HD, IDEMIP_BMSR_100BASE_TX_HD >> 6);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_10BASE_T_FD, IDEMIP_BMSR_10BASE_T_FD >> 6);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_10BASE_T_HD, IDEMIP_BMSR_10BASE_T_HD >> 6);
}

// The two 100BASE-T2 bits shifted down by six land in the selector field, so the register 1 to
// register 4 shift covers the five base-page abilities and nothing else.
void test_the_two_t2_ability_bits_have_no_base_page_bit(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x0010, IDEMIP_BMSR_100BASE_T2_FD >> 6);
    TEST_ASSERT_EQUAL_HEX16(0x0008, IDEMIP_BMSR_100BASE_T2_HD >> 6);
    TEST_ASSERT_TRUE((IDEMIP_BMSR_100BASE_T2_FD >> 6) & IDEMIP_MII_SELECTOR_MASK);
    TEST_ASSERT_TRUE((IDEMIP_BMSR_100BASE_T2_HD >> 6) & IDEMIP_MII_SELECTOR_MASK);
    TEST_ASSERT_EQUAL_HEX16(0x0000, (uint16_t)((IDEMIP_BMSR_100BASE_T2_FD >> 6) & IDEMIP_MII_TECH_MASK));
    TEST_ASSERT_EQUAL_HEX16(0x0000, (uint16_t)((IDEMIP_BMSR_100BASE_T2_HD >> 6) & IDEMIP_MII_TECH_MASK));
}

// --- register 4, Auto-Negotiation Advertisement ------------------------------

// L ADVERTISE_NPAGE 0x8000, ADVERTISE_LPACK 0x4000, ADVERTISE_RFAULT 0x2000,
// ADVERTISE_PAUSE_ASYM 0x0800, ADVERTISE_PAUSE_CAP 0x0400, ADVERTISE_100BASE4 0x0200,
// ADVERTISE_100FULL 0x0100, ADVERTISE_100HALF 0x0080, ADVERTISE_10FULL 0x0040,
// ADVERTISE_10HALF 0x0020, ADVERTISE_CSMA 0x0001, ADVERTISE_SLCT 0x001f.
// B ANAR_NP, ANAR_ACK, ANAR_RF, ANAR_PAUSE_ASYM (2 << 10), ANAR_FC, ANAR_T4, ANAR_TX_FD, ANAR_TX,
// ANAR_10_FD, ANAR_10, ANAR_CSMA, same values.
void test_anar_bits_match_both_sources(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x8000, IDEMIP_ANAR_NEXT_PAGE);
    TEST_ASSERT_EQUAL_HEX16(0x4000, IDEMIP_ANAR_ACK);
    TEST_ASSERT_EQUAL_HEX16(0x2000, IDEMIP_ANAR_REMOTE_FAULT);
    TEST_ASSERT_EQUAL_HEX16(0x0800, IDEMIP_ANAR_PAUSE_ASYM);
    TEST_ASSERT_EQUAL_HEX16(0x0400, IDEMIP_ANAR_PAUSE);
    TEST_ASSERT_EQUAL_HEX16(0x0200, IDEMIP_ANAR_100BASE_T4);
    TEST_ASSERT_EQUAL_HEX16(0x0100, IDEMIP_ANAR_100BASE_TX_FD);
    TEST_ASSERT_EQUAL_HEX16(0x0080, IDEMIP_ANAR_100BASE_TX_HD);
    TEST_ASSERT_EQUAL_HEX16(0x0040, IDEMIP_ANAR_10BASE_T_FD);
    TEST_ASSERT_EQUAL_HEX16(0x0020, IDEMIP_ANAR_10BASE_T_HD);
    TEST_ASSERT_EQUAL_HEX16(0x0001, IDEMIP_ANAR_SELECTOR_802_3);
    TEST_ASSERT_EQUAL_HEX16(0x001F, IDEMIP_MII_SELECTOR_MASK);
}

// B encodes pause as a two-bit field at 11:10: NONE 0, SYM 1 << 10, ASYM 2 << 10, TOWARDS 3 << 10.
// The two named bits have to reproduce all four codes.
void test_anar_pause_is_a_two_bit_field(void)
{
    TEST_ASSERT_EQUAL_HEX16(1u << 10, IDEMIP_ANAR_PAUSE);
    TEST_ASSERT_EQUAL_HEX16(2u << 10, IDEMIP_ANAR_PAUSE_ASYM);
    TEST_ASSERT_EQUAL_HEX16(3u << 10, IDEMIP_ANAR_PAUSE | IDEMIP_ANAR_PAUSE_ASYM);
}

void test_tech_ability_field_is_bits_nine_through_five(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x03E0, IDEMIP_MII_TECH_MASK);
    TEST_ASSERT_EQUAL_HEX16(0x0000, (uint16_t)(IDEMIP_MII_TECH_MASK & IDEMIP_MII_SELECTOR_MASK));
}

// --- register 5, Auto-Negotiation Link Partner Ability -----------------------

// L LPA_NPAGE 0x8000, LPA_LPACK 0x4000, LPA_RFAULT 0x2000, LPA_PAUSE_ASYM 0x0800,
// LPA_PAUSE_CAP 0x0400, LPA_100BASE4 0x0200, LPA_100FULL 0x0100, LPA_100HALF 0x0080,
// LPA_10FULL 0x0040, LPA_10HALF 0x0020, LPA_SLCT 0x001f.
// B ANLPAR_NP, ANLPAR_ACK, ANLPAR_RF, ANLPAR_PAUSE_ASYM (2 << 10), ANLPAR_FC, ANLPAR_T4,
// ANLPAR_TX_FD, ANLPAR_TX, ANLPAR_10_FD, ANLPAR_10, ANLPAR_CSMA, same values.
void test_anlpar_bits_match_both_sources(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x8000, IDEMIP_ANLPAR_NEXT_PAGE);
    TEST_ASSERT_EQUAL_HEX16(0x4000, IDEMIP_ANLPAR_ACK);
    TEST_ASSERT_EQUAL_HEX16(0x2000, IDEMIP_ANLPAR_REMOTE_FAULT);
    TEST_ASSERT_EQUAL_HEX16(0x0800, IDEMIP_ANLPAR_PAUSE_ASYM);
    TEST_ASSERT_EQUAL_HEX16(0x0400, IDEMIP_ANLPAR_PAUSE);
    TEST_ASSERT_EQUAL_HEX16(0x0200, IDEMIP_ANLPAR_100BASE_T4);
    TEST_ASSERT_EQUAL_HEX16(0x0100, IDEMIP_ANLPAR_100BASE_TX_FD);
    TEST_ASSERT_EQUAL_HEX16(0x0080, IDEMIP_ANLPAR_100BASE_TX_HD);
    TEST_ASSERT_EQUAL_HEX16(0x0040, IDEMIP_ANLPAR_10BASE_T_FD);
    TEST_ASSERT_EQUAL_HEX16(0x0020, IDEMIP_ANLPAR_10BASE_T_HD);
}

// L LPA_SLCT is documented as "Same as advertise selector", and the header's AND of registers 4 and
// 5 is only the common ability set while the technology bits line up too.
void test_register_five_holds_register_four_bit_positions(void)
{
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_100BASE_T4, IDEMIP_ANLPAR_100BASE_T4);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_100BASE_TX_FD, IDEMIP_ANLPAR_100BASE_TX_FD);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_100BASE_TX_HD, IDEMIP_ANLPAR_100BASE_TX_HD);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_10BASE_T_FD, IDEMIP_ANLPAR_10BASE_T_FD);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_10BASE_T_HD, IDEMIP_ANLPAR_10BASE_T_HD);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_PAUSE, IDEMIP_ANLPAR_PAUSE);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_PAUSE_ASYM, IDEMIP_ANLPAR_PAUSE_ASYM);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_NEXT_PAGE, IDEMIP_ANLPAR_NEXT_PAGE);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_ACK, IDEMIP_ANLPAR_ACK);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_REMOTE_FAULT, IDEMIP_ANLPAR_REMOTE_FAULT);
}

// --- the ANLPAR decode -------------------------------------------------------

// A partner advertising everything a base page can carry: selector 802.3, both pause codes, all
// five abilities, next page and ack set. 0xFFE1 with bit 12 clear, since neither source names it.
void test_anlpar_decode_of_a_fully_able_partner(void)
{
    uint16_t anlpar = (uint16_t)(IDEMIP_ANLPAR_NEXT_PAGE | IDEMIP_ANLPAR_ACK | IDEMIP_ANLPAR_REMOTE_FAULT |
                                 IDEMIP_ANLPAR_PAUSE_ASYM | IDEMIP_ANLPAR_PAUSE | IDEMIP_MII_TECH_MASK |
                                 IDEMIP_ANAR_SELECTOR_802_3);
    IdemIpMiiPartner p = idemip_mii_anlpar_decode(anlpar);

    TEST_ASSERT_EQUAL_HEX16(0xEFE1, anlpar);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ANAR_SELECTOR_802_3, p.selector);
    TEST_ASSERT_TRUE(p.next_page);
    TEST_ASSERT_TRUE(p.ack);
    TEST_ASSERT_TRUE(p.remote_fault);
    TEST_ASSERT_TRUE(p.pause_asym);
    TEST_ASSERT_TRUE(p.pause);
    TEST_ASSERT_TRUE(p.t4);
    TEST_ASSERT_TRUE(p.tx_fd);
    TEST_ASSERT_TRUE(p.tx_hd);
    TEST_ASSERT_TRUE(p.t_fd);
    TEST_ASSERT_TRUE(p.t_hd);
}

// A 10BASE-T half duplex only partner: register 5 is 0x0021.
void test_anlpar_decode_of_a_ten_half_only_partner(void)
{
    IdemIpMiiPartner p = idemip_mii_anlpar_decode(0x0021u);

    TEST_ASSERT_EQUAL_UINT8(0x01, p.selector);
    TEST_ASSERT_TRUE(p.t_hd);
    TEST_ASSERT_FALSE(p.t_fd);
    TEST_ASSERT_FALSE(p.tx_hd);
    TEST_ASSERT_FALSE(p.tx_fd);
    TEST_ASSERT_FALSE(p.t4);
    TEST_ASSERT_FALSE(p.pause);
    TEST_ASSERT_FALSE(p.pause_asym);
    TEST_ASSERT_FALSE(p.ack);
    TEST_ASSERT_FALSE(p.next_page);
    TEST_ASSERT_FALSE(p.remote_fault);
}

void test_anlpar_decode_of_a_silent_partner_reports_nothing(void)
{
    IdemIpMiiPartner p = idemip_mii_anlpar_decode(0x0000u);

    TEST_ASSERT_EQUAL_UINT8(0x00, p.selector);
    TEST_ASSERT_FALSE(p.t_hd);
    TEST_ASSERT_FALSE(p.t_fd);
    TEST_ASSERT_FALSE(p.tx_hd);
    TEST_ASSERT_FALSE(p.tx_fd);
    TEST_ASSERT_FALSE(p.t4);
    TEST_ASSERT_FALSE(p.ack);
}

// The selector is 5 bits, so a set bit 5 belongs to the technology field and never to the selector.
void test_selector_takes_only_the_low_five_bits(void)
{
    TEST_ASSERT_EQUAL_UINT8(0x1F, idemip_mii_selector(0xFFFFu));
    TEST_ASSERT_EQUAL_UINT8(0x00, idemip_mii_selector(IDEMIP_ANLPAR_10BASE_T_HD));
    TEST_ASSERT_EQUAL_UINT8(0x01, idemip_mii_selector(0x0021u));
}

// --- the common ability set --------------------------------------------------

// R takes the AND of registers 4 and 5: ukphy_subr.c reads
// `PHY_READ(phy, MII_ANAR) & PHY_READ(phy, MII_ANLPAR)`, and mii_nway_result is documented as
// taking "value of MII ANAR and'd with ANLPAR".
void test_common_ability_is_the_and_of_the_two_words(void)
{
    uint16_t anar = (uint16_t)(IDEMIP_ANAR_100BASE_TX_FD | IDEMIP_ANAR_10BASE_T_FD | IDEMIP_ANAR_10BASE_T_HD |
                               IDEMIP_ANAR_SELECTOR_802_3);
    uint16_t anlpar = (uint16_t)(IDEMIP_ANLPAR_100BASE_TX_HD | IDEMIP_ANLPAR_10BASE_T_HD | IDEMIP_ANLPAR_ACK |
                                 IDEMIP_ANAR_SELECTOR_802_3);

    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_10BASE_T_HD, idemip_mii_common_tech(anar, anlpar));
}

// The selector, ack, pause and next page bits are outside bits 9:5, so none of them can be mistaken
// for a technology both ends offered.
void test_common_ability_ignores_everything_outside_bits_nine_through_five(void)
{
    uint16_t both = (uint16_t)(IDEMIP_ANAR_NEXT_PAGE | IDEMIP_ANAR_ACK | IDEMIP_ANAR_REMOTE_FAULT |
                               IDEMIP_ANAR_PAUSE_ASYM | IDEMIP_ANAR_PAUSE | IDEMIP_ANAR_SELECTOR_802_3);
    TEST_ASSERT_EQUAL_HEX16(0x0000, idemip_mii_common_tech(both, both));
}

// --- resolve -----------------------------------------------------------------

#define BMSR_NEGOTIATED_LINK (IDEMIP_BMSR_LINK_UP | IDEMIP_BMSR_ANEG_COMPLETE | IDEMIP_BMSR_ANEG_ABLE)

// R walks 100BASE-TX full duplex first. Both ends offering everything therefore resolves to it.
void test_resolve_picks_hundred_full_first(void)
{
    IdemIpMiiResolved r = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, IDEMIP_MII_TECH_MASK, IDEMIP_MII_TECH_MASK);

    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_100BASE_TX_FD, r.tech);
    TEST_ASSERT_EQUAL_UINT16(100u, r.speed_mbps);
    TEST_ASSERT_TRUE(r.full_duplex);
    TEST_ASSERT_TRUE(r.up);
    TEST_ASSERT_TRUE(r.aneg_complete);
}

// R places 100BASE-T4 next, above 100BASE-TX half duplex, and gives it half duplex.
void test_resolve_picks_t4_over_hundred_half(void)
{
    uint16_t common = (uint16_t)(IDEMIP_ANAR_100BASE_T4 | IDEMIP_ANAR_100BASE_TX_HD | IDEMIP_ANAR_10BASE_T_FD |
                                 IDEMIP_ANAR_10BASE_T_HD);
    IdemIpMiiResolved r = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, common, common);

    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_100BASE_T4, r.tech);
    TEST_ASSERT_EQUAL_UINT16(100u, r.speed_mbps);
    TEST_ASSERT_FALSE(r.full_duplex);
}

void test_resolve_picks_hundred_half_over_ten(void)
{
    uint16_t common = (uint16_t)(IDEMIP_ANAR_100BASE_TX_HD | IDEMIP_ANAR_10BASE_T_FD | IDEMIP_ANAR_10BASE_T_HD);
    IdemIpMiiResolved r = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, common, common);

    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_100BASE_TX_HD, r.tech);
    TEST_ASSERT_EQUAL_UINT16(100u, r.speed_mbps);
    TEST_ASSERT_FALSE(r.full_duplex);
}

void test_resolve_picks_ten_full_over_ten_half(void)
{
    uint16_t common = (uint16_t)(IDEMIP_ANAR_10BASE_T_FD | IDEMIP_ANAR_10BASE_T_HD);
    IdemIpMiiResolved r = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, common, common);

    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_10BASE_T_FD, r.tech);
    TEST_ASSERT_EQUAL_UINT16(10u, r.speed_mbps);
    TEST_ASSERT_TRUE(r.full_duplex);
}

void test_resolve_falls_to_ten_half(void)
{
    IdemIpMiiResolved r =
        idemip_mii_resolve(BMSR_NEGOTIATED_LINK, IDEMIP_ANAR_10BASE_T_HD, IDEMIP_ANLPAR_10BASE_T_HD);

    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_10BASE_T_HD, r.tech);
    TEST_ASSERT_EQUAL_UINT16(10u, r.speed_mbps);
    TEST_ASSERT_FALSE(r.full_duplex);
}

// The whole point of the AND: a 100 Mb/s partner and a 10 Mb/s node run at 10.
void test_resolve_is_bounded_by_the_weaker_end(void)
{
    uint16_t anar = (uint16_t)(IDEMIP_ANAR_10BASE_T_FD | IDEMIP_ANAR_10BASE_T_HD);
    uint16_t anlpar = IDEMIP_MII_TECH_MASK;
    IdemIpMiiResolved r = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, anar, anlpar);

    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ANAR_10BASE_T_FD, r.tech);
    TEST_ASSERT_EQUAL_UINT16(10u, r.speed_mbps);
    TEST_ASSERT_TRUE(r.full_duplex);
}

// R returns IFM_NONE when the ANLPAR walk falls through every case.
void test_resolve_reports_no_rate_when_the_ends_share_nothing(void)
{
    IdemIpMiiResolved r =
        idemip_mii_resolve(BMSR_NEGOTIATED_LINK, IDEMIP_ANAR_100BASE_TX_FD, IDEMIP_ANLPAR_10BASE_T_HD);

    TEST_ASSERT_EQUAL_HEX16(0x0000, r.tech);
    TEST_ASSERT_EQUAL_UINT16(0u, r.speed_mbps);
    TEST_ASSERT_FALSE(r.full_duplex);
    TEST_ASSERT_TRUE(r.up);
    TEST_ASSERT_TRUE(r.aneg_complete);
}

// R checks BMSR_ACOMP before reading the ability words: ukphy_status returns IFM_NONE while
// `(bmsr & BMSR_ACOMP) == 0`.
void test_resolve_reports_no_rate_while_negotiation_is_unfinished(void)
{
    IdemIpMiiResolved r = idemip_mii_resolve(IDEMIP_BMSR_LINK_UP | IDEMIP_BMSR_ANEG_ABLE, IDEMIP_MII_TECH_MASK,
                                             IDEMIP_MII_TECH_MASK);

    TEST_ASSERT_EQUAL_HEX16(0x0000, r.tech);
    TEST_ASSERT_EQUAL_UINT16(0u, r.speed_mbps);
    TEST_ASSERT_FALSE(r.full_duplex);
    TEST_ASSERT_TRUE(r.up);
    TEST_ASSERT_FALSE(r.aneg_complete);
}

// A down link leaves stale ability words behind, and phy.h documents the rate as NONE while the
// link is down.
void test_resolve_reports_no_rate_while_the_link_is_down(void)
{
    IdemIpMiiResolved r =
        idemip_mii_resolve(IDEMIP_BMSR_ANEG_COMPLETE | IDEMIP_BMSR_ANEG_ABLE, IDEMIP_MII_TECH_MASK, IDEMIP_MII_TECH_MASK);

    TEST_ASSERT_EQUAL_HEX16(0x0000, r.tech);
    TEST_ASSERT_EQUAL_UINT16(0u, r.speed_mbps);
    TEST_ASSERT_FALSE(r.up);
    TEST_ASSERT_TRUE(r.aneg_complete);
}

// Register 1 bit 8 is set by every PHY able to run above 100 Mb/s, so it is reported rather than
// swallowed: the base page carries no bit for those rates and the resolved 100 is a floor.
void test_resolve_reports_that_the_base_page_is_not_the_whole_story(void)
{
    IdemIpMiiResolved r = idemip_mii_resolve(BMSR_NEGOTIATED_LINK | IDEMIP_BMSR_EXT_STATUS, IDEMIP_MII_TECH_MASK,
                                             IDEMIP_MII_TECH_MASK);

    TEST_ASSERT_TRUE(r.ext_status);
    TEST_ASSERT_EQUAL_UINT16(100u, r.speed_mbps);

    IdemIpMiiResolved plain = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, IDEMIP_MII_TECH_MASK, IDEMIP_MII_TECH_MASK);
    TEST_ASSERT_FALSE(plain.ext_status);
}

// resolve reads its three arguments and nothing else, so the same words give the same answer.
void test_resolve_is_a_function_of_its_three_arguments(void)
{
    IdemIpMiiResolved a = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, 0x01E1u, 0x41E1u);
    IdemIpMiiResolved unrelated = idemip_mii_resolve(0x0000u, 0x0000u, 0x0000u);
    IdemIpMiiResolved b = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, 0x01E1u, 0x41E1u);

    (void)unrelated;
    TEST_ASSERT_EQUAL_HEX16(a.tech, b.tech);
    TEST_ASSERT_EQUAL_UINT16(a.speed_mbps, b.speed_mbps);
    TEST_ASSERT_EQUAL_UINT8(a.full_duplex, b.full_duplex);
    TEST_ASSERT_EQUAL_UINT8(a.up, b.up);
}

// --- the seam onto phy.h -----------------------------------------------------

// phy.h names the rates IdemIpPhySpeed, and mii.h cannot name that type without including phy.h,
// which includes mii.h. The rates are therefore plain megabit counts, and this is what pins them to
// the enum the netif will assign them into.
void test_the_resolved_rates_are_the_phy_speed_values(void)
{
    TEST_ASSERT_EQUAL_INT(IDEMIP_PHY_SPEED_NONE, (int)IDEMIP_MII_SPEED_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_PHY_SPEED_10, (int)IDEMIP_MII_SPEED_10);
    TEST_ASSERT_EQUAL_INT(IDEMIP_PHY_SPEED_100, (int)IDEMIP_MII_SPEED_100);

    IdemIpMiiResolved r = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, IDEMIP_MII_TECH_MASK, IDEMIP_MII_TECH_MASK);
    IdemIpPhyLink link;
    link.speed = (IdemIpPhySpeed)r.speed_mbps;
    link.full_duplex = r.full_duplex;
    link.up = r.up;

    TEST_ASSERT_EQUAL_INT(IDEMIP_PHY_SPEED_100, link.speed);
    TEST_ASSERT_TRUE(link.full_duplex);
    TEST_ASSERT_TRUE(link.up);
}

// The header holds no state, so there is no borrow and nothing that two callers could share.
void test_the_unit_has_no_storage_to_share(void)
{
    IdemIpMiiResolved a = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, IDEMIP_MII_TECH_MASK, IDEMIP_MII_TECH_MASK);
    IdemIpMiiResolved b = idemip_mii_resolve(BMSR_NEGOTIATED_LINK, IDEMIP_ANAR_10BASE_T_HD, IDEMIP_ANLPAR_10BASE_T_HD);

    TEST_ASSERT_EQUAL_UINT16(100u, a.speed_mbps);
    TEST_ASSERT_EQUAL_UINT16(10u, b.speed_mbps);
}
