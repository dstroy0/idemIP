// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file mii.c
 * @brief Decoding the Clause 22 base page: registers 1, 4 and 5.
 *
 * Every entry below takes one parameter, a pointer to MiiCtx. A decode is the register values it
 * reads and the mask it tests, so those are one context.
 *
 * Written as masks and shifts rather than bitfields: the bit order of a C bitfield is
 * implementation-defined, so a struct that matches on one toolchain silently reverses on another.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ethernet/mii.h"
#include "src/ethernet/mii_defines.h" // the Clause 22 register set, which this file is the first user of

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/** @brief One decode. */
typedef struct
{
    uint16_t reg;    /**< The register a bit test or a selector read looks at. */
    uint16_t mask;   /**< The mask a bit test asks about. */
    uint16_t bmsr;   /**< Register 1, Basic Mode Status. */
    uint16_t anar;   /**< Register 4, this end's advertised abilities. */
    uint16_t anlpar; /**< Register 5, the link partner's. */
} MiiCtx;

/** @brief Whether every bit of the mask is set in the register. */
IDEMIP_INLINE idemip_bool mii_bit(const MiiCtx *c)
{
    return (idemip_bool)(((c->reg & c->mask) == c->mask) ? IDEMIP_TRUE : IDEMIP_FALSE);
}

/** @brief The selector field of register 4 or 5, bits 4:0. */
IDEMIP_INLINE uint8_t mii_selector(const MiiCtx *c)
{
    return (uint8_t)(c->reg & IDEMIP_MII_SELECTOR_MASK);
}

/** @brief Register 5, field by field. */
IDEMIP_INLINE IdemIpMiiPartner mii_anlpar_decode(const MiiCtx *c)
{
    const uint16_t anlpar = c->anlpar;
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
IDEMIP_INLINE uint16_t mii_common_tech(const MiiCtx *c)
{
    return (uint16_t)(c->anar & c->anlpar & IDEMIP_MII_TECH_MASK);
}

/**
 * @brief Speed and duplex from registers 1, 4 and 5.
 *
 * Takes the common ability set and walks it highest first: 100BASE-TX full duplex, 100BASE-T4,
 * 100BASE-TX half duplex, 10BASE-T full duplex, 10BASE-T half duplex. That is the order the base
 * page resolves in, and 100BASE-T4 is half duplex only. The rate stays NONE while the link is down,
 * while auto-negotiation has not completed, or when the two ability words share no technology bit.
 */
IDEMIP_INLINE IdemIpMiiResolved mii_resolve(const MiiCtx *c)
{
    IdemIpMiiResolved r;
    uint16_t common = idemip_mii_common_tech(c->anar, c->anlpar);

    r.tech = 0u;
    r.speed_mbps = IDEMIP_MII_SPEED_NONE;
    r.full_duplex = IDEMIP_FALSE;
    r.up = idemip_mii_bit(c->bmsr, IDEMIP_BMSR_LINK_UP);
    r.aneg_complete = idemip_mii_bit(c->bmsr, IDEMIP_BMSR_ANEG_COMPLETE);
    r.ext_status = idemip_mii_bit(c->bmsr, IDEMIP_BMSR_EXT_STATUS);

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

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so these are what it points at. Each builds the context and hands it to the body above. */

idemip_bool idemip_mii_bit(uint16_t reg, uint16_t mask)
{
    return IDEMIP_CALL(mii_bit, MiiCtx, .reg = reg, .mask = mask);
}

uint8_t idemip_mii_selector(uint16_t reg)
{
    return IDEMIP_CALL(mii_selector, MiiCtx, .reg = reg);
}

IdemIpMiiPartner idemip_mii_anlpar_decode(uint16_t anlpar)
{
    return IDEMIP_CALL(mii_anlpar_decode, MiiCtx, .anlpar = anlpar);
}

uint16_t idemip_mii_common_tech(uint16_t anar, uint16_t anlpar)
{
    return IDEMIP_CALL(mii_common_tech, MiiCtx, .anar = anar, .anlpar = anlpar);
}

IdemIpMiiResolved idemip_mii_resolve(uint16_t bmsr, uint16_t anar, uint16_t anlpar)
{
    return IDEMIP_CALL(mii_resolve, MiiCtx, .bmsr = bmsr, .anar = anar, .anlpar = anlpar);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET
