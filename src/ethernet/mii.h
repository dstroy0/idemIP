// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file mii.h
 * @brief The MII management register set, IEEE 802.3 Clause 22: what registers 1, 4 and 5 settle.
 *
 * A management frame carries 16 bits of data, so every register is 16 bits wide. The register
 * addresses, the bit masks and the provenance of every value are mii_defines.h, which a .c includes
 * when it genuinely needs the numbers. A caller that wants a register decoded asks for it here.
 *
 * The table is the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_MII_H
#define IDEMIP_MII_H

#include "src/ethernet/ethernet.h"

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

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

/** @brief Decoding the Clause 22 base page: registers 1, 4 and 5. */
typedef struct
{
    idemip_bool (*bit)(uint16_t reg, uint16_t mask);
    uint8_t (*selector)(uint16_t reg);
    IdemIpMiiPartner (*anlpar_decode)(uint16_t anlpar);
    uint16_t (*common_tech)(uint16_t anar, uint16_t anlpar);
    IdemIpMiiResolved (*resolve)(uint16_t bmsr, uint16_t anar, uint16_t anlpar);
} MiiNs;
IDEMIP_NS_LAYOUT(MiiNs, bit, selector, anlpar_decode, common_tech, resolve);

/** @name The entries the table points at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The table is
 *         still the whole surface: call through it.
 *  @{ */
idemip_bool idemip_mii_bit(uint16_t reg, uint16_t mask);
uint8_t idemip_mii_selector(uint16_t reg);
IdemIpMiiPartner idemip_mii_anlpar_decode(uint16_t anlpar);
uint16_t idemip_mii_common_tech(uint16_t anar, uint16_t anlpar);
IdemIpMiiResolved idemip_mii_resolve(uint16_t bmsr, uint16_t anar, uint16_t anlpar);
/** @} */

/**
 * @brief Module namespace.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS MiiNs mii IDEMIP_UNUSED = {
    .bit = idemip_mii_bit,
    .selector = idemip_mii_selector,
    .anlpar_decode = idemip_mii_anlpar_decode,
    .common_tech = idemip_mii_common_tech,
    .resolve = idemip_mii_resolve,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_MII_H
