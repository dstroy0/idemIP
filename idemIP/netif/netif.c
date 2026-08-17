// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file netif.c
 * @brief The interface table, and the IPv6 address table behind it.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block, the context and both tables are regions of that borrow, at compile-time offsets, and no
 * entry reads or writes a byte outside it. Two borrows therefore share nothing, and the same call on
 * the same borrow does the same thing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_ETHERNET

#include "idemIP/netif/netif.h"

IDEMIP_BEGIN_DECLS

// The stamp clear writes into the context. Every other entry refuses a borrow without it, so bytes
// that were never cleared are refused rather than read as a table.
#define NETIF_READY 0x4E544946u

// The one definition, private to this TU.
typedef struct
{
    uint32_t ready;   // NETIF_READY once clear has run
    uint32_t tick_ms; // the millisecond the last lifetime sweep ran at
} NetifCtx;

// One interface. RFC 1122 sec 3.3.1.1 routes by addr and mask, sec 3.3.1.2 by gw. hwaddr is the
// RFC 894 48-bit address, phy is the borrow this interface's link was bound in, mtu6 is what an
// RFC 4861 sec 4.6.4 MTU option revised the link MTU to.
typedef struct
{
    uint8_t *phy;
    uint32_t addr;
    uint32_t mask;
    uint32_t gw;
    uint16_t mtu;
    uint16_t mtu6;
    uint16_t flags;
    uint16_t chksum;
    uint8_t hwaddr[IDEMIP_MAC_LEN];
    uint8_t pad[(1u << IDEMIP_NETIF_ENTRY_SHIFT) - (sizeof(uint8_t *) + (3u * 4u) + (4u * 2u) + IDEMIP_MAC_LEN)];
} NetifEntry;

static_assert(sizeof(NetifEntry) == (1u << IDEMIP_NETIF_ENTRY_SHIFT),
              "a NetifEntry is not 1 << IDEMIP_NETIF_ENTRY_SHIFT octets wide - raise the shift in idemip_config.h");

#if IDEMIP_ENABLE_IPV6

// One IPv6 address on one interface. state holds an IdemIpNetifAddr6State, INVALID being the free
// slot. The two lifetimes are the RFC 4861 sec 4.6.2 fields in seconds, and set_ms is the
// millisecond they were taken at, which is what RFC 4862 sec 5.5.4 ages them from.
typedef struct
{
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    uint32_t preferred_s;
    uint32_t valid_s;
    uint32_t set_ms;
    uint8_t state;
    uint8_t pad[(1u << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT) - (IDEMIP_IP6_ADDR_LEN + (3u * 4u) + 1u)];
} NetifAddr6Entry;

static_assert(sizeof(NetifAddr6Entry) == (1u << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT),
              "a NetifAddr6Entry is not 1 << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT octets wide - raise the shift in "
              "idemip_config.h");

#endif // IDEMIP_ENABLE_IPV6

// The caller's borrow, split: the operand block, the context, the interface table, then the IPv6
// addresses. netif.h publishes the offsets; the asserts below prove the span covers them and that
// each table starts aligned before anything runs.
static_assert(IDEMIP_NETIF_OFF_CTX + sizeof(NetifCtx) <= IDEMIP_NETIF_CTX_BYTES,
              "IDEMIP_NETIF_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_NETIF_OFF_END <= IDEMIP_NETIF_BORROW,
              "IDEMIP_NETIF_BORROW is short of the operand block, the context and both tables - raise "
              "IDEMIP_NETIF_CTX_BYTES in idemip_config.h");
static_assert(((IDEMIP_NETIF_OFF_TAB | IDEMIP_NETIF_OFF_ADDR6) & (IDEMIP_ALIGN - 1u)) == 0u,
              "a table does not start on IDEMIP_ALIGN: entry i sits at (i << SHIFT) from it");

// The regions, at their offsets in the caller's borrow.
#define NETIF_IO(w) IDEMIP_NETIF_IO(w)
#define NETIF_CTX(w) ((NetifCtx *)(void *)((w) + IDEMIP_NETIF_OFF_CTX))
#define NETIF_AT(w, i) ((NetifEntry *)(void *)((w) + IDEMIP_NETIF_OFF_TAB + ((size_t)(i) << IDEMIP_NETIF_ENTRY_SHIFT)))
#if IDEMIP_ENABLE_IPV6
#define NETIF_ADDR6_AT(w, i, s)                                                                                        \
    ((NetifAddr6Entry *)(void *)((w) + IDEMIP_NETIF_OFF_ADDR6 +                                                         \
                                 ((((size_t)(i) * IDEMIP_IP6_ADDRESSES) + (size_t)(s))                                 \
                                  << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT)))
#endif

// --- the entries -----------------------------------------------------------

// Zeroes the context and both tables, then stamps the context. A zeroed interface holds a null phy
// and a zeroed address table holds IDEMIP_NETIF_ADDR6_INVALID in every slot, which is the state
// every other entry reads as empty. The operand block is the caller's and is left alone.
static void netif_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_NETIF_OFF_CTX, 0, (size_t)IDEMIP_NETIF_OFF_END - (size_t)IDEMIP_NETIF_OFF_CTX);
    NETIF_CTX(work)->ready = NETIF_READY;
    NETIF_IO(work)->status = IDEMIP_OK;
}

static void netif_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->bind_args.index >= IDEMIP_NETIF_COUNT ||
        io->bind_args.hwaddr == NULL || io->bind_args.phy == NULL)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.3.1.6 makes the address, the mask and the gateway list configurable.
    io->status = IDEMIP_ERR;
}

static void netif_unbind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->if_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 4862 sec 2, an invalid address "is not assigned to any interface".
    io->status = IDEMIP_ERR;
}

static void netif_set_addr4(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->addr4_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.2.1.3 bars the broadcast and loopback forms from an interface's own address.
    io->status = IDEMIP_ERR;
}

static void netif_set_mtu(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->if_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 4861 sec 4.6.4 MTU option, bounded below by RFC 8200 sec 5's 1280 octets.
    io->status = IDEMIP_ERR;
}

static void netif_set_flags(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->if_args.index >= IDEMIP_NETIF_COUNT ||
        (io->if_args.set & (uint16_t)~IDEMIP_NETIF_FLAG_MASK) != 0u ||
        (io->if_args.clear & (uint16_t)~IDEMIP_NETIF_FLAG_MASK) != 0u)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.2.1.3 broadcast forms and RFC 1112 group membership run per interface.
    io->status = IDEMIP_ERR;
}

static void netif_set_offload(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->if_args.index >= IDEMIP_NETIF_COUNT ||
        (io->if_args.chksum & (uint16_t)~IDEMIP_NETIF_CHKSUM_MASK) != 0u)
    {
        return;
    }
    // PHASE 3: a header whose bit is set here is left to the MAC, so RFC 1071 is not run over it.
    io->status = IDEMIP_ERR;
}

static void netif_get(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    io->phy = NULL;
    io->hwaddr = NULL;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->if_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.3.1.1 names the record a route decision reads.
    io->status = IDEMIP_ERR;
}

static void netif_find4(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.2.1.3, "the IP source address MUST be one of its own IP addresses".
    io->status = IDEMIP_ERR;
}

static void netif_local4(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    io->local = IDEMIP_FALSE;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->route_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.3.1.1 extracts both addresses with the mask and compares them.
    io->status = IDEMIP_ERR;
}

#if IDEMIP_ENABLE_IPV6

static void netif_add_addr6(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->addr6_args.index >= IDEMIP_NETIF_COUNT ||
        io->addr6_args.addr == NULL || io->addr6_args.state == IDEMIP_NETIF_ADDR6_INVALID ||
        io->addr6_args.valid_s < io->addr6_args.preferred_s)
    {
        return;
    }
    // PHASE 3: RFC 4862 sec 5.4 starts an address tentative, sec 2 orders the two lifetimes.
    io->status = IDEMIP_ERR;
}

static void netif_remove_addr6(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->addr6_args.index >= IDEMIP_NETIF_COUNT ||
        io->addr6_args.addr == NULL)
    {
        return;
    }
    // PHASE 3: RFC 4862 sec 2, an invalid address "is not assigned to any interface".
    io->status = IDEMIP_ERR;
}

static void netif_find_addr6(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    io->addr6 = NULL;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->addr6_args.addr == NULL)
    {
        return;
    }
    // PHASE 3: RFC 4862 sec 5.4.3 matches a Target Address against the interface's own addresses.
    io->status = IDEMIP_ERR;
}

static void netif_get_addr6(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    io->addr6 = NULL;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->addr6_args.index >= IDEMIP_NETIF_COUNT ||
        io->addr6_args.slot >= IDEMIP_IP6_ADDRESSES)
    {
        return;
    }
    // PHASE 3: RFC 4862 sec 2 names the state and the two lifetimes an assigned address carries.
    io->status = IDEMIP_ERR;
}

static void netif_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    io->aged = 0u;
    if (NETIF_CTX(work)->ready != NETIF_READY)
    {
        return;
    }
    // PHASE 3: RFC 4862 sec 5.5.4, "A preferred address becomes deprecated when its preferred lifetime expires".
    io->status = IDEMIP_ERR;
}

#endif // IDEMIP_ENABLE_IPV6

const NetifNs Netif = {.clear = netif_clear,
                       .bind = netif_bind,
                       .unbind = netif_unbind,
                       .set_addr4 = netif_set_addr4,
                       .set_mtu = netif_set_mtu,
                       .set_flags = netif_set_flags,
                       .set_offload = netif_set_offload,
                       .get = netif_get,
                       .find4 = netif_find4,
                       .local4 = netif_local4,
#if IDEMIP_ENABLE_IPV6
                       .add_addr6 = netif_add_addr6,
                       .remove_addr6 = netif_remove_addr6,
                       .find_addr6 = netif_find_addr6,
                       .get_addr6 = netif_get_addr6,
                       .tick = netif_tick
#endif
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET
