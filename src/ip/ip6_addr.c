// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip6_addr.c
 * @brief The RFC 4291 sec 2 address types and scopes, and the RFC 4007 zone an address sits in.
 *
 * Every entry is a function of the one pointer it is handed: the operand block and the context are
 * both regions of that borrow, at compile-time offsets, and no entry reads or writes a byte outside
 * it. Two borrows therefore share nothing, and the same call on the same borrow does the same thing.
 *
 * The tests are ip6_addr.h's inline ones. This file carries the borrow, not a second copy of them.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip6_addr.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. ready is the mark clear leaves, so a borrow no one
// cleared is refused rather than answered out of whatever was in those bytes.
typedef struct
{
    idemip_bool ready;
} Ip6AddrCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_IP6_ADDR_OFF_CTX, sizeof(Ip6AddrCtx), IDEMIP_IP6_ADDR_OFF_END, "ip6_addr's context");

// The caller's borrow, split: the operand block, then the context. ip6_addr.h publishes the
// offsets; these two asserts prove the span covers them before anything runs.
static_assert(IDEMIP_IP6_ADDR_OFF_CTX + sizeof(Ip6AddrCtx) <= IDEMIP_IP6_ADDR_OFF_END,
              "IDEMIP_IP6_ADDR_CTX_BYTES is short of the operand block and the context - raise it in "
              "idemip_config.h");
static_assert(IDEMIP_IP6_ADDR_OFF_END <= IDEMIP_IP6_ADDR_BORROW,
              "IDEMIP_IP6_ADDR_BORROW is short of the map - raise IDEMIP_IP6_ADDR_CTX_BYTES in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define IP6_ADDR_IO(w) IDEMIP_IP6_ADDR_IO(w)
#define IP6_ADDR_CTX(w) ((Ip6AddrCtx *)(void *)((w) + IDEMIP_IP6_ADDR_OFF_CTX))

// Octets the context spans, which is what clear zeroes.
#define IP6_ADDR_STATE_BYTES (IDEMIP_IP6_ADDR_OFF_END - IDEMIP_IP6_ADDR_OFF_CTX)

// --- the entries -----------------------------------------------------------

void idemip_ip6_addr_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP6_ADDR_OFF_CTX, 0, IP6_ADDR_STATE_BYTES);
    IP6_ADDR_CTX(work)->ready = IDEMIP_TRUE;
    IP6_ADDR_IO(work)->status = IDEMIP_OK;
}

void idemip_ip6_addr_classify(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip6AddrIo *io = IP6_ADDR_IO(work);
    io->status = IDEMIP_ERR;
    io->type = IDEMIP_IP6_TYPE_UNSPECIFIED;
    io->scope = IDEMIP_IP6_SCOPE_RESERVED;
    io->flags = 0u;
    const uint8_t *addr = io->classify_args.addr;
    if (!IP6_ADDR_CTX(work)->ready || addr == NULL)
    {
        return;
    }
    io->type = idemip_ip6_addr_type(addr);
    io->scope = idemip_ip6_addr_scope_of(addr, io->type);
    io->flags = idemip_ip6_addr_mcast_flags(addr);
    io->status = IDEMIP_OK;
}

// RFC 4291 sec 2.7.1 forms the address from "the low-order 24 bits of an address (unicast or
// anycast)". A multicast address is neither, and sec 2.5.2 says of the unspecified address that "it
// must never be assigned to any node", so neither has a solicited-node form. Both are ERR: no later
// call gives them one.
void idemip_ip6_addr_solicited_io(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip6AddrIo *io = IP6_ADDR_IO(work);
    io->status = IDEMIP_ERR;
    memset(io->solicited, 0, IDEMIP_IP6_ADDR_LEN);
    const uint8_t *addr = io->solicited_args.addr;
    if (!IP6_ADDR_CTX(work)->ready || addr == NULL)
    {
        return;
    }
    IdemIpIp6Type type = idemip_ip6_addr_type(addr);
    if (type == IDEMIP_IP6_TYPE_MULTICAST || type == IDEMIP_IP6_TYPE_UNSPECIFIED)
    {
        return;
    }
    idemip_ip6_addr_solicited(io->solicited, addr);
    io->status = IDEMIP_OK;
}

// RFC 4007 sec 5 instantiates three scopes without configuration: "Each interface on a node
// comprises a single zone of interface-local scope", "Each link and the interfaces attached to that
// link comprise a single zone of link-local scope", and "There is a single zone of global scope".
// sec 6's default assignment gives each of the first two the interface's own index: "A unique
// interface index for each interface. A unique link index for each interface." Every other scope
// "must be defined and configured by network administrators" (sec 5), so it is left at the default
// index, which sec 6 reserves to mean "use the default zone", and zone_derived says so.
//
// RFC 4291 sec 2.7 drops a multicast scop of 0 outright, so that is ERR, and treats scop F "the same
// as packets destined to a global (scop E)", so that takes the single global zone. The unspecified
// address has no scope (RFC 4007 sec 4) and so no zone either.
void idemip_ip6_addr_zone(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip6AddrIo *io = IP6_ADDR_IO(work);
    io->status = IDEMIP_ERR;
    io->zone = IDEMIP_IP6_ZONE_DEFAULT;
    io->zone_derived = IDEMIP_FALSE;
    const uint8_t *addr = io->zone_args.addr;
    if (!IP6_ADDR_CTX(work)->ready || addr == NULL)
    {
        return;
    }
    IdemIpIp6Type type = idemip_ip6_addr_type(addr);
    IdemIpIp6Scope scope = idemip_ip6_addr_scope_of(addr, type);
    io->type = type;
    io->scope = scope;
    if (scope == IDEMIP_IP6_SCOPE_RESERVED)
    {
        return;
    }
    switch (scope)
    {
    case IDEMIP_IP6_SCOPE_INTERFACE_LOCAL:
    case IDEMIP_IP6_SCOPE_LINK_LOCAL:
        // RFC 4007 sec 6 assigns "A unique interface index for each interface. A unique link index
        // for each interface", and the same section reserves index zero: "the index value zero at
        // each scope SHOULD be reserved to mean 'use the default zone'". Interface zero is a real
        // interface here, so the derived index is biased off the reserved one.
        io->zone = (uint32_t)io->zone_args.netif + 1u;
        io->zone_derived = IDEMIP_TRUE;
        break;
    case IDEMIP_IP6_SCOPE_GLOBAL:
    case IDEMIP_IP6_SCOPE_RESERVED_F:
        io->zone = IDEMIP_IP6_ZONE_DEFAULT;
        io->zone_derived = IDEMIP_TRUE;
        break;
    default:
        io->zone = IDEMIP_IP6_ZONE_DEFAULT;
        io->zone_derived = IDEMIP_FALSE;
        break;
    }
    io->status = IDEMIP_OK;
}

// RFC 4007 sec 5: "addresses of a given (non-global) scope may be re-used in different zones of that
// scope. For example, two different physical links may each contain a node with the link-local
// address fe80::1." So two equal non-global addresses name the same interface only when their zones
// agree. sec 6 reserves index zero to "use the default zone", so a default index matches whatever
// zone the other address names.
void idemip_ip6_addr_match(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip6AddrIo *io = IP6_ADDR_IO(work);
    io->status = IDEMIP_ERR;
    io->equal = IDEMIP_FALSE;
    io->prefix_equal = IDEMIP_FALSE;
    const uint8_t *a = io->match_args.a;
    const uint8_t *b = io->match_args.b;
    if (!IP6_ADDR_CTX(work)->ready || a == NULL || b == NULL || io->match_args.prefix_len > IDEMIP_IP6_ADDR_BITS)
    {
        return;
    }
    io->prefix_equal = idemip_ip6_addr_prefix_eq(a, b, io->match_args.prefix_len);
    if (idemip_bytes_eq(a, b, IDEMIP_IP6_ADDR_LEN))
    {
        IdemIpIp6Scope scope = idemip_ip6_addr_scope(a);
        io->equal = (scope == IDEMIP_IP6_SCOPE_GLOBAL || io->match_args.a_zone == io->match_args.b_zone ||
                     io->match_args.a_zone == IDEMIP_IP6_ZONE_DEFAULT ||
                     io->match_args.b_zone == IDEMIP_IP6_ZONE_DEFAULT)
                        ? IDEMIP_TRUE
                        : IDEMIP_FALSE;
    }
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
