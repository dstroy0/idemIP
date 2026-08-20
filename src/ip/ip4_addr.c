// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_addr.c
 * @brief The RFC 1122 sec 3.2.1.3 special cases, the RFC 791 sec 3.2 classes, and the sec 6.4 map.
 *
 * Every entry is a function of the one pointer it is handed: the operand block and the context are
 * both regions of that borrow, at compile-time offsets, and no entry reads or writes a byte outside
 * it. Two borrows therefore share nothing, and the same call on the same borrow does the same thing.
 *
 * The tests are ip4_addr.h's inline ones. This file carries the borrow, not a second copy of them.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip4_addr.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. ready is the mark clear leaves, so a borrow no one
// cleared is refused rather than answered out of whatever was in those bytes.
typedef struct
{
    idemip_bool ready;
} Ip4AddrCtx;

// The caller's borrow, split: the operand block, then the context. ip4_addr.h publishes the
// offsets; these two asserts prove the span covers them before anything runs.
static_assert(IDEMIP_IP4_ADDR_OFF_CTX + sizeof(Ip4AddrCtx) <= IDEMIP_IP4_ADDR_OFF_END,
              "IDEMIP_IP4_ADDR_CTX_BYTES is short of the operand block and the context - raise it in "
              "idemip_config.h");
static_assert(IDEMIP_IP4_ADDR_OFF_END <= IDEMIP_IP4_ADDR_BORROW,
              "IDEMIP_IP4_ADDR_BORROW is short of the map - raise IDEMIP_IP4_ADDR_CTX_BYTES in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define IP4_ADDR_IO(w) IDEMIP_IP4_ADDR_IO(w)
#define IP4_ADDR_CTX(w) ((Ip4AddrCtx *)(void *)((w) + IDEMIP_IP4_ADDR_OFF_CTX))

// Octets the context spans, which is what clear zeroes.
#define IP4_ADDR_STATE_BYTES (IDEMIP_IP4_ADDR_OFF_END - IDEMIP_IP4_ADDR_OFF_CTX)

// --- the entries -----------------------------------------------------------

void idemip_ip4_addr_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP4_ADDR_OFF_CTX, 0, IP4_ADDR_STATE_BYTES);
    IP4_ADDR_CTX(work)->ready = IDEMIP_TRUE;
    IP4_ADDR_IO(work)->status = IDEMIP_OK;
}

void idemip_ip4_addr_classify(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4AddrIo *io = IP4_ADDR_IO(work);
    io->status = IDEMIP_ERR;
    if (!IP4_ADDR_CTX(work)->ready)
    {
        return;
    }
    uint32_t addr = io->classify_args.addr;
    io->addr_class = idemip_ip4_addr_class(addr);
    io->type = idemip_ip4_addr_type(addr);
    io->status = IDEMIP_OK;
}

// RFC 1122 sec 3.2.1.3 case (e), "{ <Network-number>, <Subnet-number>, -1 } Directed broadcast to
// the specified subnet", is the network number with every masked-off bit set. A mask of all ones
// leaves no host field, and the same section requires each field "will be at least two bits long",
// so a /32 has no directed broadcast and only the limited one of case (c) answers.
void idemip_ip4_addr_match(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4AddrIo *io = IP4_ADDR_IO(work);
    io->status = IDEMIP_ERR;
    io->network = 0u;
    io->broadcast = 0u;
    io->host = 0u;
    io->prefix_len = 0u;
    io->on_subnet = IDEMIP_FALSE;
    io->is_broadcast = IDEMIP_FALSE;
    io->contiguous = IDEMIP_FALSE;
    if (!IP4_ADDR_CTX(work)->ready)
    {
        return;
    }
    uint32_t addr = io->match_args.addr;
    uint32_t mask = io->match_args.mask;
    io->network = io->match_args.net & mask;
    // RFC 3021 sec 2.2.1: on a 31-bit prefix a directed broadcast "is not possible", sec 2.1 making
    // both of the link's addresses host addresses. A 32-bit prefix names one host and no subnet.
    idemip_bool has_bcast = (mask != 0xFFFFFFFFu && mask != 0xFFFFFFFEu) ? IDEMIP_TRUE : IDEMIP_FALSE;
    io->broadcast = has_bcast ? (io->network | (uint32_t)(~mask)) : 0u;
    io->host = addr & (uint32_t)(~mask);
    io->prefix_len = idemip_ip4_addr_mask_ones(mask);
    io->contiguous = idemip_ip4_addr_mask_contiguous(mask);
    io->on_subnet = (((addr ^ io->match_args.net) & mask) == 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
    io->is_broadcast =
        (addr == IDEMIP_IP4_BROADCAST || (has_bcast && io->on_subnet && addr == io->broadcast))
            ? IDEMIP_TRUE
            : IDEMIP_FALSE;
    io->status = IDEMIP_OK;
}

// RFC 1112 sec 6.4 maps a host group address, which sec 4 fixes at class D. An address outside it
// has no mapping at all, so it is ERR: no later call maps it either.
void idemip_ip4_addr_mcast_mac_io(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4AddrIo *io = IP4_ADDR_IO(work);
    io->status = IDEMIP_ERR;
    memset(io->mac, 0, IDEMIP_MAC_LEN);
    if (!IP4_ADDR_CTX(work)->ready)
    {
        return;
    }
    uint32_t group = io->mcast_args.group;
    if (!idemip_ip4_addr_is_mcast(group))
    {
        return;
    }
    idemip_ip4_addr_mcast_mac(io->mac, group);
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
