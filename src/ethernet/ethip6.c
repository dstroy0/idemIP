// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ethip6.c
 * @brief The RFC 2464 address derivations, over the caller's borrow.
 *
 * Every entry is a function of the one pointer it is handed: the operand block and the context are
 * both regions of that borrow, at compile-time offsets, and no entry reads or writes a byte outside
 * it or the octets an operand points at. The module holds no address between calls.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ethernet/ethip6.h"

IDEMIP_BEGIN_DECLS

// The running context. ready is the mark clear leaves, so a borrow no one cleared is refused.
typedef struct
{
    idemip_bool ready;
    uint8_t pad[7];
} Ethip6Ctx;

// The caller's borrow, split: the operand block, then the context. ethip6.h publishes the offsets;
// these two asserts prove the span covers them before anything runs.
static_assert(IDEMIP_ETHIP6_OFF_CTX + sizeof(Ethip6Ctx) <= IDEMIP_ETHIP6_OFF_END,
              "IDEMIP_ETHIP6_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_ETHIP6_OFF_END <= IDEMIP_ETHIP6_BORROW,
              "IDEMIP_ETHIP6_BORROW is short of the map - raise IDEMIP_ETHIP6_CTX_BYTES in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define ETHIP6_IO(w) IDEMIP_ETHIP6_IO(w)
#define ETHIP6_CTX(w) ((Ethip6Ctx *)(void *)((w) + IDEMIP_ETHIP6_OFF_CTX))

// Octets the context spans, which is what clear zeroes.
#define ETHIP6_STATE_BYTES (IDEMIP_ETHIP6_OFF_END - IDEMIP_ETHIP6_OFF_CTX)

// --- the derivations -------------------------------------------------------

// RFC 2464 sec 4: the OUI becomes the company_id, the fourth and fifth octets are FFFE, the last
// three octets of the Ethernet address become the last three, and the U/L bit is complemented.
static void ethip6_iid_from_mac(uint8_t *iid, const uint8_t *mac)
{
    memcpy(iid, mac, IDEMIP_ETHIP6_OUI_LEN);
    iid[0] = (uint8_t)(iid[0] ^ IDEMIP_ETHIP6_UL_BIT);
    iid[IDEMIP_ETHIP6_OFF_FFFE] = IDEMIP_ETHIP6_EUI64_FF;
    iid[IDEMIP_ETHIP6_OFF_FFFE + 1u] = IDEMIP_ETHIP6_EUI64_FE;
    memcpy(iid + IDEMIP_ETHIP6_IID_LEN - IDEMIP_ETHIP6_TAIL_LEN, mac + IDEMIP_ETHIP6_OUI_LEN,
           IDEMIP_ETHIP6_TAIL_LEN);
}

// RFC 2464 sec 4: a zero U/L bit in the built-in address signifies "a universally administered IEEE
// 802 address", which the complement turns into the one a globally unique identifier carries.
static idemip_bool ethip6_is_universal(const uint8_t *mac)
{
    return ((mac[0] & IDEMIP_ETHIP6_UL_BIT) == 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- the entries -----------------------------------------------------------

static void ethip6_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_ETHIP6_OFF_CTX, 0, ETHIP6_STATE_BYTES);
    ETHIP6_CTX(work)->ready = IDEMIP_TRUE;
    ETHIP6_IO(work)->status = IDEMIP_OK;
}

// RFC 2464 sec 7: "An IPv6 packet with a multicast destination address DST ... is transmitted to
// the Ethernet multicast address whose first two octets are the value 3333 hexadecimal and whose
// last four octets are the last four octets of DST." A destination that is not multicast (RFC 4291
// sec 2.7) is ERR: the mapping is stated for a multicast DST alone, and no retry changes an
// address.
static void ethip6_multicast_map(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ethip6Io *io = ETHIP6_IO(work);
    io->status = IDEMIP_ERR;
    memset(io->mac, 0, IDEMIP_MAC_LEN);
    if (!ETHIP6_CTX(work)->ready || io->multicast_args.dst == NULL)
    {
        return;
    }
    const uint8_t *dst = io->multicast_args.dst;
    if (dst[0] != IDEMIP_ETHIP6_MULTICAST_PREFIX)
    {
        return;
    }
    io->mac[0] = IDEMIP_ETHIP6_MCAST_0;
    io->mac[1] = IDEMIP_ETHIP6_MCAST_1;
    memcpy(io->mac + IDEMIP_ETHIP6_MCAST_PREFIX_LEN, dst + IDEMIP_IP6_ADDR_LEN - IDEMIP_ETHIP6_MCAST_TAIL_LEN,
           IDEMIP_ETHIP6_MCAST_TAIL_LEN);
    io->status = IDEMIP_OK;
}

// RFC 2464 sec 4, the EUI-64 interface identifier of a built-in 48-bit address.
static void ethip6_eui64(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ethip6Io *io = ETHIP6_IO(work);
    io->status = IDEMIP_ERR;
    memset(io->iid, 0, IDEMIP_ETHIP6_IID_LEN);
    io->universal = IDEMIP_FALSE;
    if (!ETHIP6_CTX(work)->ready || io->mac_args.mac == NULL)
    {
        return;
    }
    ethip6_iid_from_mac(io->iid, io->mac_args.mac);
    io->universal = ethip6_is_universal(io->mac_args.mac);
    io->status = IDEMIP_OK;
}

// RFC 2464 sec 5: "The IPv6 link-local address for an Ethernet interface is formed by appending the
// Interface Identifier, as defined above, to the prefix FE80::/64." The prefix is the 1111111010
// and 54 zero bits the sec 5 figure prints.
static void ethip6_linklocal(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ethip6Io *io = ETHIP6_IO(work);
    io->status = IDEMIP_ERR;
    memset(io->addr, 0, IDEMIP_IP6_ADDR_LEN);
    io->universal = IDEMIP_FALSE;
    if (!ETHIP6_CTX(work)->ready || io->mac_args.mac == NULL)
    {
        return;
    }
    io->addr[0] = IDEMIP_ETHIP6_LINKLOCAL_0;
    io->addr[1] = IDEMIP_ETHIP6_LINKLOCAL_1;
    ethip6_iid_from_mac(io->addr + IDEMIP_ETHIP6_LINKLOCAL_PREFIX_LEN, io->mac_args.mac);
    memcpy(io->iid, io->addr + IDEMIP_ETHIP6_LINKLOCAL_PREFIX_LEN, IDEMIP_ETHIP6_IID_LEN);
    io->universal = ethip6_is_universal(io->mac_args.mac);
    io->status = IDEMIP_OK;
}

const Ethip6Ns Ethip6 = {.clear = ethip6_clear,
                         .multicast_map = ethip6_multicast_map,
                         .eui64 = ethip6_eui64,
                         .linklocal = ethip6_linklocal};

IDEMIP_END_DECLS
