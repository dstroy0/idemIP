// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_route.c
 * @brief The rows of the RFC 1122 sec 3.3.1 routing table.
 *
 * The row type is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block, the context and the table are regions of that borrow, at compile-time offsets, and no entry
 * reads or writes a byte outside it.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV4

#include "idemIP/ip/ip4_route.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and every
// entry refuses it.
#define IP4_ROUTE_READY 0x52543400u

// One row: the four fields RFC 1122 sec 3.3.1.3 names, the mask sec 3.3.1.1 compares against, the
// flags and metric, and the RFC 1191 sec 6.6 path MTU with the millisecond it was stamped. Padded to
// 1 << IDEMIP_IP4_ROUTE_ENTRY_SHIFT so row i sits at (i << IDEMIP_IP4_ROUTE_ENTRY_SHIFT).
typedef struct
{
    uint32_t dst;
    uint32_t mask;
    uint32_t gw;
    uint32_t pmtu_ms;
    uint16_t pmtu;
    uint16_t metric;
    uint8_t netif;
    uint8_t tos;
    uint8_t flags;
    uint8_t state;
    uint8_t reserved[8];
} Ip4RouteEntry;

// The context: the mark, and the millisecond of the last aging sweep.
typedef struct
{
    uint32_t ready;
    uint32_t tick_ms;
} Ip4RouteCtx;

// Row i is at (i << SHIFT), so the width has to be exactly the shift.
static_assert(sizeof(Ip4RouteEntry) == (1u << IDEMIP_IP4_ROUTE_ENTRY_SHIFT),
              "an Ip4RouteEntry must be exactly 1 << IDEMIP_IP4_ROUTE_ENTRY_SHIFT wide - pad it, or raise the shift");

// The head region carries the operand block and the context, both outside the table.
static_assert(IDEMIP_IP4_ROUTE_OFF_CTX + sizeof(Ip4RouteCtx) <= IDEMIP_IP4_ROUTE_CTX_BYTES,
              "IDEMIP_IP4_ROUTE_CTX_BYTES is short of the operand block and the context - raise it in "
              "idemip_config.h");

// The caller's borrow, split: the head region, then the rows. ip4_route.h publishes the offsets; the
// assert proves the span covers them before anything runs.
static_assert(IDEMIP_IP4_ROUTE_OFF_TAB + (IDEMIP_IP4_ROUTES << IDEMIP_IP4_ROUTE_ENTRY_SHIFT) <=
                  IDEMIP_IP4_ROUTE_BORROW,
              "IDEMIP_IP4_ROUTE_BORROW is short of the head region and the table - raise it in idemip_config.h");

// clear zeroes the table, so the empty row is the zero state.
static_assert(IDEMIP_IP4_ROUTE_FREE == 0, "IDEMIP_IP4_ROUTE_FREE must be zero: clear zeroes the table");

// The regions, at their offsets in the caller's borrow.
#define IP4_ROUTE_IO(w) IDEMIP_IP4_ROUTE_IO(w)
#define IP4_ROUTE_CTX(w) ((Ip4RouteCtx *)(void *)((w) + IDEMIP_IP4_ROUTE_OFF_CTX))
#define IP4_ROUTE_AT(w, i)                                                                                             \
    ((Ip4RouteEntry *)(void *)((w) + IDEMIP_IP4_ROUTE_OFF_TAB + ((size_t)(i) << IDEMIP_IP4_ROUTE_ENTRY_SHIFT)))

// A borrow clear has not run on carries no table, so every entry but clear refuses it.
static idemip_bool ip4_route_ready(uint8_t *restrict work)
{
    return (idemip_bool)(IP4_ROUTE_CTX(work)->ready == IP4_ROUTE_READY);
}

// --- the entries -----------------------------------------------------------

// The context and the table, zeroed, then the mark. The operand block is the caller's and is left as
// it stands.
static void ip4_route_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP4_ROUTE_OFF_CTX, 0,
           (size_t)IDEMIP_IP4_ROUTE_BORROW - (size_t)IDEMIP_IP4_ROUTE_OFF_CTX);
    IP4_ROUTE_CTX(work)->ready = IP4_ROUTE_READY;
    IP4_ROUTE_IO(work)->status = IDEMIP_OK;
}

static void ip4_route_add(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.3.1.3, the row fields (1) through (4), and sec 3.3.1.2's static route flag.
    io->status = IDEMIP_ERR;
}

static void ip4_route_remove(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.3.1.2, dropping a route and the RFC 1191 sec 6.6 PMTU cached on it.
    io->status = IDEMIP_ERR;
}

static void ip4_route_lookup(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->next_hop = 0;
    io->pmtu = 0;
    io->netif = 0;
    io->direct = IDEMIP_FALSE;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.3.1.1 (a) through (c), the local/remote decision, then sec 3.3.1.2 gateway selection.
    io->status = IDEMIP_ERR;
}

static void ip4_route_redirect(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.3.1.2 (c), a Redirect moving a row's next-hop gateway, Network treated as Host.
    io->status = IDEMIP_ERR;
}

static void ip4_route_set_pmtu(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->pmtu = 0;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 1191 sec 6.6, the PMTU stamped on the row "in response to a Datagram Too Big message".
    io->status = IDEMIP_ERR;
}

static void ip4_route_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4RouteIo *io = IP4_ROUTE_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_ROUTE_INDEX_NONE;
    if (!ip4_route_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 1191 sec 6.6, a row whose PMTU "has not been decreased for a while" going back to the link MTU.
    io->status = IDEMIP_ERR;
}

const Ip4RouteNs Ip4Route = {.clear = ip4_route_clear,
                             .add = ip4_route_add,
                             .remove = ip4_route_remove,
                             .lookup = ip4_route_lookup,
                             .redirect = ip4_route_redirect,
                             .set_pmtu = ip4_route_set_pmtu,
                             .tick = ip4_route_tick};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4
