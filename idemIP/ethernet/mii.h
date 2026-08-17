// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file mii.h
 * @brief The MII management register set, IEEE 802.3 Clause 22.
 *
 * Clause 22.2.4 fixes registers 0 through 15 for every PHY; 16 through 31 are the vendor's. A
 * management frame carries 16 bits of data, so every register here is 16 bits wide.
 *
 * Written as masks and shifts rather than bitfields: the bit order of a C bitfield is
 * implementation-defined, so a struct that matches on one toolchain silently reverses on another.
 *
 * IEEE 802.3 is not obtainable here, so every value below is stated against the open transcriptions
 * that were read instead, and each is named where it is not corroborated by all of them:
 *
 *   L  Linux include/uapi/linux/mii.h  (MII_*, BMCR_*, BMSR_*, ADVERTISE_*, LPA_*)
 *   B  FreeBSD sys/dev/mii/mii.h       (MII_*, BMCR_*, BMSR_*, ANAR_*, ANLPAR_*)
 *   R  FreeBSD sys/dev/mii/ukphy_subr.c and Linux include/linux/mii.h mii_nway_result(),
 *      for the order the base page resolves in
 *
 * A register value arrives as a 16-bit word from a management read, not as bytes in a frame, so
 * every accessor here takes a uint16_t and none of them reads memory.
 */

#ifndef IDEMIP_MII_H
#define IDEMIP_MII_H

#include "idemIP/ethernet/ethernet.h"

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/** @brief PHY addresses a management interface can reach (Clause 22.2.4.5: 5 bits). */
#define IDEMIP_MII_PHY_ADDR_MAX 32u

/** @brief Registers per PHY (Clause 22.2.4: 5 bits of register address). */
#define IDEMIP_MII_REG_MAX 32u

// Both fields are 5 bits wide, so each count is 1 << 5 and a bound test is a mask. B MII_NPHY 32.
static_assert(IDEMIP_MII_PHY_ADDR_MAX == (1u << 5), "the management address field is 5 bits");
static_assert(IDEMIP_MII_REG_MAX == (1u << 5), "the register address field is 5 bits");

// ---------------------------------------------------------------------------
// Register addresses (Clause 22.2.4)
// ---------------------------------------------------------------------------

#define IDEMIP_MII_BMCR 0x00u    ///< Basic Mode Control (22.2.4.1)
#define IDEMIP_MII_BMSR 0x01u    ///< Basic Mode Status (22.2.4.2)
#define IDEMIP_MII_PHYID1 0x02u  ///< PHY Identifier 1 (22.2.4.3)
#define IDEMIP_MII_PHYID2 0x03u  ///< PHY Identifier 2 (22.2.4.3)
#define IDEMIP_MII_ANAR 0x04u    ///< Auto-Negotiation Advertisement (22.2.4.4)
#define IDEMIP_MII_ANLPAR 0x05u  ///< Auto-Negotiation Link Partner Ability (22.2.4.5)
#define IDEMIP_MII_ANER 0x06u    ///< Auto-Negotiation Expansion (22.2.4.6)
#define IDEMIP_MII_MMDCTRL 0x0Du ///< MMD Access Control (22.2.4.14)
#define IDEMIP_MII_MMDAD 0x0Eu   ///< MMD Access Address/Data (22.2.4.15)

// ---------------------------------------------------------------------------
// Basic Mode Control, register 0 (Clause 22.2.4.1)
// ---------------------------------------------------------------------------

#define IDEMIP_BMCR_RESET (1u << 15)         ///< Reset the PHY; self-clearing.
#define IDEMIP_BMCR_LOOPBACK (1u << 14)      ///< Route transmit data to the receive path.
#define IDEMIP_BMCR_SPEED_100 (1u << 13)     ///< Speed select LSB.
#define IDEMIP_BMCR_ANEG_ENABLE (1u << 12)   ///< Enable auto-negotiation.
#define IDEMIP_BMCR_POWER_DOWN (1u << 11)    ///< Power down all but the management interface.
#define IDEMIP_BMCR_ISOLATE (1u << 10)       ///< Isolate the PHY from the MII.
#define IDEMIP_BMCR_ANEG_RESTART (1u << 9)   ///< Restart auto-negotiation; self-clearing.
#define IDEMIP_BMCR_FULL_DUPLEX (1u << 8)    ///< Full duplex when set, half when clear.
#define IDEMIP_BMCR_COLLISION_TEST (1u << 7) ///< Enable the collision test.
#define IDEMIP_BMCR_SPEED_1000 (1u << 6)     ///< Speed select MSB.

// Speed select is one two-bit field split across bits 6 and 13, MSB at 6. L BMCR_SPEED10 0x0000,
// BMCR_SPEED100 0x2000, BMCR_SPEED1000 0x0040; B BMCR_S10, BMCR_S100, BMCR_S1000 and
// BMCR_SPEED(x) masking both bits. Both bits set is not a rate either source names.

#define IDEMIP_BMCR_SPEED_MASK (IDEMIP_BMCR_SPEED_1000 | IDEMIP_BMCR_SPEED_100) ///< the whole field
#define IDEMIP_BMCR_SPEED_SEL_10 0u                       ///< both bits clear
#define IDEMIP_BMCR_SPEED_SEL_100 IDEMIP_BMCR_SPEED_100   ///< LSB alone
#define IDEMIP_BMCR_SPEED_SEL_1000 IDEMIP_BMCR_SPEED_1000 ///< MSB alone

// ---------------------------------------------------------------------------
// Basic Mode Status, register 1 (Clause 22.2.4.2)
// ---------------------------------------------------------------------------

#define IDEMIP_BMSR_100BASE_T4 (1u << 15)      ///< 100BASE-T4 able.
#define IDEMIP_BMSR_100BASE_TX_FD (1u << 14)   ///< 100BASE-X full duplex able.
#define IDEMIP_BMSR_100BASE_TX_HD (1u << 13)   ///< 100BASE-X half duplex able.
#define IDEMIP_BMSR_10BASE_T_FD (1u << 12)     ///< 10 Mb/s full duplex able.
#define IDEMIP_BMSR_10BASE_T_HD (1u << 11)     ///< 10 Mb/s half duplex able.
#define IDEMIP_BMSR_100BASE_T2_FD (1u << 10)   ///< 100BASE-T2 full duplex able.
#define IDEMIP_BMSR_100BASE_T2_HD (1u << 9)    ///< 100BASE-T2 half duplex able.
// Bit 8 is also set by every PHY able to run above 100 Mb/s, per the note at B mii.h BMSR_EXTSTAT,
// so a rate resolved from the base page alone is incomplete while it is set.
#define IDEMIP_BMSR_EXT_STATUS (1u << 8) ///< Extended status in register 15.

// B BMSR_MFPS 0x0040. L folds bits 7 and 6 into BMSR_RESV 0x00c0 and names neither, so this bit
// carries one corroborating source, not two.
#define IDEMIP_BMSR_MF_PREAMBLE_SUPP (1u << 6) ///< Accepts management frames with preamble suppressed.
#define IDEMIP_BMSR_ANEG_COMPLETE (1u << 5)    ///< Auto-negotiation process completed.
#define IDEMIP_BMSR_REMOTE_FAULT (1u << 4)     ///< Remote fault detected; latching.
#define IDEMIP_BMSR_ANEG_ABLE (1u << 3)        ///< Able to auto-negotiate.
#define IDEMIP_BMSR_LINK_UP (1u << 2)          ///< Link is up; latching low.
#define IDEMIP_BMSR_JABBER (1u << 1)           ///< Jabber condition detected; latching.
#define IDEMIP_BMSR_EXT_CAPABILITY (1u << 0)   ///< Extended register set present.

// ---------------------------------------------------------------------------
// Auto-Negotiation Advertisement, register 4 (Clause 22.2.4.4)
// ---------------------------------------------------------------------------
// The technology ability field carries the same bit positions in the link partner's register 5,
// which is what makes a negotiated result readable as the AND of the two.

#define IDEMIP_ANAR_NEXT_PAGE (1u << 15)    ///< Next page able.
#define IDEMIP_ANAR_ACK (1u << 14)          ///< Received the link partner's ability word.
#define IDEMIP_ANAR_REMOTE_FAULT (1u << 13) ///< Signal a remote fault to the link partner.
#define IDEMIP_ANAR_PAUSE_ASYM (1u << 11)   ///< Asymmetric pause.
#define IDEMIP_ANAR_PAUSE (1u << 10)        ///< Symmetric pause.
#define IDEMIP_ANAR_100BASE_T4 (1u << 9)
#define IDEMIP_ANAR_100BASE_TX_FD (1u << 8)
#define IDEMIP_ANAR_100BASE_TX_HD (1u << 7)
#define IDEMIP_ANAR_10BASE_T_FD (1u << 6)
#define IDEMIP_ANAR_10BASE_T_HD (1u << 5)
#define IDEMIP_ANAR_SELECTOR_802_3 0x0001u ///< Selector field: IEEE 802.3.

/** @brief The selector field, bits 4:0 (L ADVERTISE_SLCT 0x001f, B ANAR_CSMA at bit 0). */
#define IDEMIP_MII_SELECTOR_MASK 0x001Fu

/** @brief The technology ability field, bits 9:5: the five base-page abilities. */
#define IDEMIP_MII_TECH_MASK                                                                                           \
    (IDEMIP_ANAR_100BASE_T4 | IDEMIP_ANAR_100BASE_TX_FD | IDEMIP_ANAR_100BASE_TX_HD | IDEMIP_ANAR_10BASE_T_FD |        \
     IDEMIP_ANAR_10BASE_T_HD)

// ---------------------------------------------------------------------------
// Auto-Negotiation Link Partner Ability, register 5 (Clause 22.2.4.5)
// ---------------------------------------------------------------------------
// The base page the partner sent, in register 4's bit positions. L LPA_*, B ANLPAR_*. Bit 12 is
// named by neither and is left undefined.

#define IDEMIP_ANLPAR_NEXT_PAGE (1u << 15)    ///< The partner has more pages to send.
#define IDEMIP_ANLPAR_ACK (1u << 14)          ///< The partner received this node's ability word.
#define IDEMIP_ANLPAR_REMOTE_FAULT (1u << 13) ///< The partner reports a fault.
#define IDEMIP_ANLPAR_PAUSE_ASYM (1u << 11)   ///< The partner supports asymmetric pause.
#define IDEMIP_ANLPAR_PAUSE (1u << 10)        ///< The partner supports symmetric pause.
#define IDEMIP_ANLPAR_100BASE_T4 (1u << 9)
#define IDEMIP_ANLPAR_100BASE_TX_FD (1u << 8)
#define IDEMIP_ANLPAR_100BASE_TX_HD (1u << 7)
#define IDEMIP_ANLPAR_10BASE_T_FD (1u << 6)
#define IDEMIP_ANLPAR_10BASE_T_HD (1u << 5)

// The AND of registers 4 and 5 is the common ability set only while both carry a field in the same
// place. Asserted rather than assumed.
static_assert(IDEMIP_ANLPAR_100BASE_T4 == IDEMIP_ANAR_100BASE_T4,
              "register 5 must hold 100BASE-T4 where register 4 does");
static_assert(IDEMIP_ANLPAR_100BASE_TX_FD == IDEMIP_ANAR_100BASE_TX_FD,
              "register 5 must hold 100BASE-TX full duplex where register 4 does");
static_assert(IDEMIP_ANLPAR_100BASE_TX_HD == IDEMIP_ANAR_100BASE_TX_HD,
              "register 5 must hold 100BASE-TX half duplex where register 4 does");
static_assert(IDEMIP_ANLPAR_10BASE_T_FD == IDEMIP_ANAR_10BASE_T_FD,
              "register 5 must hold 10BASE-T full duplex where register 4 does");
static_assert(IDEMIP_ANLPAR_10BASE_T_HD == IDEMIP_ANAR_10BASE_T_HD,
              "register 5 must hold 10BASE-T half duplex where register 4 does");
static_assert(IDEMIP_ANLPAR_PAUSE == IDEMIP_ANAR_PAUSE, "register 5 must hold symmetric pause where register 4 does");
static_assert(IDEMIP_ANLPAR_PAUSE_ASYM == IDEMIP_ANAR_PAUSE_ASYM,
              "register 5 must hold asymmetric pause where register 4 does");

static_assert(IDEMIP_MII_TECH_MASK == 0x03E0u, "the technology ability field is bits 9:5");
static_assert((IDEMIP_MII_TECH_MASK & IDEMIP_MII_SELECTOR_MASK) == 0u,
              "the technology ability field and the selector field must not overlap");
static_assert(IDEMIP_ANAR_SELECTOR_802_3 == (IDEMIP_ANAR_SELECTOR_802_3 & IDEMIP_MII_SELECTOR_MASK),
              "the 802.3 selector value must fit the selector field");

// ---------------------------------------------------------------------------
// Decoding a register value
// ---------------------------------------------------------------------------

// Rates the base page can resolve to, in megabits per second. The numbers are the rates themselves,
// so a caller assigns one into phy.h's IdemIpPhySpeed without a table. phy.h includes this header,
// so that enum cannot be named here.

#define IDEMIP_MII_SPEED_NONE 0u ///< no rate resolved
#define IDEMIP_MII_SPEED_10 10u  ///< 10BASE-T
#define IDEMIP_MII_SPEED_100 100u ///< 100BASE-TX or 100BASE-T4

/**
 * @brief What register 5 says the link partner can do.
 *
 * @var IdemIpMiiPartner::selector     the selector field, bits 4:0
 * @var IdemIpMiiPartner::next_page    bit 15
 * @var IdemIpMiiPartner::ack          bit 14
 * @var IdemIpMiiPartner::remote_fault bit 13
 * @var IdemIpMiiPartner::pause_asym   bit 11
 * @var IdemIpMiiPartner::pause        bit 10
 * @var IdemIpMiiPartner::t4           bit 9, 100BASE-T4
 * @var IdemIpMiiPartner::tx_fd        bit 8, 100BASE-TX full duplex
 * @var IdemIpMiiPartner::tx_hd        bit 7, 100BASE-TX half duplex
 * @var IdemIpMiiPartner::t_fd         bit 6, 10BASE-T full duplex
 * @var IdemIpMiiPartner::t_hd         bit 5, 10BASE-T half duplex
 */
typedef struct
{
    uint8_t selector;
    idemip_bool next_page;
    idemip_bool ack;
    idemip_bool remote_fault;
    idemip_bool pause_asym;
    idemip_bool pause;
    idemip_bool t4;
    idemip_bool tx_fd;
    idemip_bool tx_hd;
    idemip_bool t_fd;
    idemip_bool t_hd;
} IdemIpMiiPartner;

/**
 * @brief What registers 1, 4 and 5 together settle.
 *
 * @var IdemIpMiiResolved::tech          the winning technology ability bit, 0 when none is common
 * @var IdemIpMiiResolved::speed_mbps    10 or 100 once resolved, IDEMIP_MII_SPEED_NONE otherwise
 * @var IdemIpMiiResolved::full_duplex   set only by the two full duplex abilities
 * @var IdemIpMiiResolved::up            register 1 bit 2
 * @var IdemIpMiiResolved::aneg_complete register 1 bit 5
 * @var IdemIpMiiResolved::ext_status    register 1 bit 8, so rates above 100 Mb/s are settled in
 *                                       registers 10 and 15, which this header does not carry
 */
typedef struct
{
    uint16_t tech;
    uint16_t speed_mbps;
    idemip_bool full_duplex;
    idemip_bool up;
    idemip_bool aneg_complete;
    idemip_bool ext_status;
} IdemIpMiiResolved;

/** @brief Whether every bit of @p mask is set in @p reg. */
IDEMIP_INLINE idemip_bool idemip_mii_bit(uint16_t reg, uint16_t mask)
{
    return (idemip_bool)(((reg & mask) == mask) ? IDEMIP_TRUE : IDEMIP_FALSE);
}

/** @brief The selector field of register 4 or 5, bits 4:0. */
IDEMIP_INLINE uint8_t idemip_mii_selector(uint16_t reg)
{
    return (uint8_t)(reg & IDEMIP_MII_SELECTOR_MASK);
}

/** @brief Register 5, field by field. */
IDEMIP_INLINE IdemIpMiiPartner idemip_mii_anlpar_decode(uint16_t anlpar)
{
    IdemIpMiiPartner p;
    p.selector = idemip_mii_selector(anlpar);
    p.next_page = idemip_mii_bit(anlpar, IDEMIP_ANLPAR_NEXT_PAGE);
    p.ack = idemip_mii_bit(anlpar, IDEMIP_ANLPAR_ACK);
    p.remote_fault = idemip_mii_bit(anlpar, IDEMIP_ANLPAR_REMOTE_FAULT);
    p.pause_asym = idemip_mii_bit(anlpar, IDEMIP_ANLPAR_PAUSE_ASYM);
    p.pause = idemip_mii_bit(anlpar, IDEMIP_ANLPAR_PAUSE);
    p.t4 = idemip_mii_bit(anlpar, IDEMIP_ANLPAR_100BASE_T4);
    p.tx_fd = idemip_mii_bit(anlpar, IDEMIP_ANLPAR_100BASE_TX_FD);
    p.tx_hd = idemip_mii_bit(anlpar, IDEMIP_ANLPAR_100BASE_TX_HD);
    p.t_fd = idemip_mii_bit(anlpar, IDEMIP_ANLPAR_10BASE_T_FD);
    p.t_hd = idemip_mii_bit(anlpar, IDEMIP_ANLPAR_10BASE_T_HD);
    return p;
}

/** @brief The abilities both ends advertised: register 4 AND register 5, over bits 9:5. */
IDEMIP_INLINE uint16_t idemip_mii_common_tech(uint16_t anar, uint16_t anlpar)
{
    return (uint16_t)(anar & anlpar & IDEMIP_MII_TECH_MASK);
}

/**
 * @brief Speed and duplex from registers 1, 4 and 5.
 *
 * Takes the common ability set and walks it highest first: 100BASE-TX full duplex, 100BASE-T4,
 * 100BASE-TX half duplex, 10BASE-T full duplex, 10BASE-T half duplex. That is the order R resolves
 * in, and 100BASE-T4 is half duplex only. The rate stays NONE while the link is down, while
 * auto-negotiation has not completed, or when the two ability words share no technology bit.
 */
IDEMIP_INLINE IdemIpMiiResolved idemip_mii_resolve(uint16_t bmsr, uint16_t anar, uint16_t anlpar)
{
    IdemIpMiiResolved r;
    uint16_t common = idemip_mii_common_tech(anar, anlpar);

    r.tech = 0u;
    r.speed_mbps = IDEMIP_MII_SPEED_NONE;
    r.full_duplex = IDEMIP_FALSE;
    r.up = idemip_mii_bit(bmsr, IDEMIP_BMSR_LINK_UP);
    r.aneg_complete = idemip_mii_bit(bmsr, IDEMIP_BMSR_ANEG_COMPLETE);
    r.ext_status = idemip_mii_bit(bmsr, IDEMIP_BMSR_EXT_STATUS);

    if ((r.up == IDEMIP_FALSE) || (r.aneg_complete == IDEMIP_FALSE))
    {
        return r;
    }

    if ((common & IDEMIP_ANAR_100BASE_TX_FD) != 0u)
    {
        r.tech = IDEMIP_ANAR_100BASE_TX_FD;
        r.speed_mbps = IDEMIP_MII_SPEED_100;
        r.full_duplex = IDEMIP_TRUE;
    }
    else if ((common & IDEMIP_ANAR_100BASE_T4) != 0u)
    {
        r.tech = IDEMIP_ANAR_100BASE_T4;
        r.speed_mbps = IDEMIP_MII_SPEED_100;
    }
    else if ((common & IDEMIP_ANAR_100BASE_TX_HD) != 0u)
    {
        r.tech = IDEMIP_ANAR_100BASE_TX_HD;
        r.speed_mbps = IDEMIP_MII_SPEED_100;
    }
    else if ((common & IDEMIP_ANAR_10BASE_T_FD) != 0u)
    {
        r.tech = IDEMIP_ANAR_10BASE_T_FD;
        r.speed_mbps = IDEMIP_MII_SPEED_10;
        r.full_duplex = IDEMIP_TRUE;
    }
    else if ((common & IDEMIP_ANAR_10BASE_T_HD) != 0u)
    {
        r.tech = IDEMIP_ANAR_10BASE_T_HD;
        r.speed_mbps = IDEMIP_MII_SPEED_10;
    }

    return r;
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_MII_H
