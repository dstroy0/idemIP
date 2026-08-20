// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_route.h
 * @brief The IPv4 routing table, RFC 1122 sec 3.3.1: the next hop for an outbound datagram.
 *
 * RFC 1122 sec 3.3.1.3 names what one row carries: "(1) Local IP address (for a multihomed host)",
 * "(2) Destination IP address", "(3) Type(s)-of-Service", "(4) Next-hop gateway IP address". Field
 * (1) is the interface index here, the address itself being the netif's. sec 3.3.1.2 adds the static
 * route and "a flag specifying whether it may be overridden by ICMP Redirects", and sec 3.3.1.3
 * calls a row "a natural place to cache data on the properties of the path. Examples of such
 * properties might be the maximum unfragmented datagram size", which is the RFC 1191 sec 6.2 path MTU
 * and the timestamp RFC 1191 sec 6.3 ages it by.
 *
 * The local/remote decision of sec 3.3.1.1 is a mask compare, so each row carries the address mask
 * "that selects the network number and subnet number fields".
 *
 * Which row a destination selects is RFC 1812 sec 5.2.4.3's pruning rules, in the order that section
 * prints them: (1) Basic Match, (2) Longest Match, (3) Weak TOS, (4) Best Metric, the lowest row
 * breaking a remaining tie.
 */

#ifndef IDEMIP_IP4_ROUTE_H
#define IDEMIP_IP4_ROUTE_H

#include "src/ip/ipv4.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/** @brief No row. Every index result reads this when the table held nothing. */
#define IDEMIP_IP4_ROUTE_INDEX_NONE 0xFFu

/**
 * @brief What a row is, RFC 1122 sec 3.3.1.
 *
 * IDEMIP_IP4_ROUTE_USED is not RFC 1122's: a row is either carrying one of the RFC's routes or it is
 * not, and clear leaves every row FREE.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP4_ROUTE_FREE = 0, ///< no route in this row
    IDEMIP_IP4_ROUTE_USED,     ///< the row carries a route
} IdemIpIp4RouteState;

/**
 * @brief The flags one row carries.
 *
 * RFC 1122 sec 3.3.1.2: "a host IP layer MAY implement a table of 'static routes'. Each such static
 * route MAY include a flag specifying whether it may be overridden by ICMP Redirects." sec 3.3.1.3
 * field (2) "MAY be the full IP address of the destination host, or only the destination network
 * number", which HOST distinguishes. GATEWAY separates sec 3.3.1.1 (b), "the datagram is to be
 * transmitted directly to the destination host", from (c), "the destination is accessible only
 * through a gateway".
 */
#define IDEMIP_IP4_ROUTE_F_GATEWAY (1u << 0)     ///< the next hop is @c gw, not the destination
#define IDEMIP_IP4_ROUTE_F_STATIC (1u << 1)      ///< a preset route, sec 3.3.1.2
#define IDEMIP_IP4_ROUTE_F_REDIRECT_OK (1u << 2) ///< an ICMP Redirect may override it, sec 3.3.1.2
#define IDEMIP_IP4_ROUTE_F_HOST (1u << 3)        ///< keyed on the full destination address, sec 3.3.1.3

// IDEMIP_IP4_ROUTE_F_HOST follows the mask that add was given: field (2) is the full destination
// address exactly when every one of its bits is significant.

/**
 * @brief What add takes.
 *
 * A default gateway is a row whose destination and mask are both zero. RFC 1122 sec 3.3.1.2: "The IP
 * layer MUST support multiple default gateways", so they are separate rows rather than one field, and
 * @c gw is part of the row key: two defaults differ in nothing else. sec 3.3.1.6 (3) configures "a list
 * of default gateways, with a preference level", which is @c metric.
 */
typedef struct
{
    uint32_t dst;    ///< the destination, RFC 1122 sec 3.3.1.3 field (2)
    uint32_t mask;   ///< the address mask, sec 3.3.1.1 (a)
    uint32_t gw;     ///< the next-hop gateway, field (4)
    uint16_t metric; ///< which of two rows matching the same destination is preferred
    uint8_t netif;   ///< the interface whose address is field (1)
    uint8_t tos;     ///< the Type of Service, field (3)
    uint8_t flags;   ///< IDEMIP_IP4_ROUTE_F_*
} Ip4RouteAddArgs;

/**
 * @brief What remove takes: the destination and mask of the row to drop.
 *
 * No type of service, so every row carrying this destination and mask goes, whatever field (3) each
 * holds.
 */
typedef struct
{
    uint32_t dst;
    uint32_t mask;
} Ip4RouteRemoveArgs;

/**
 * @brief What lookup takes.
 *
 * RFC 1122 sec 3.3.1.3: "Field (3), the TOS, SHOULD be included", so the type of service is part of
 * the key rather than of the answer.
 */
typedef struct
{
    uint32_t dst;
    uint8_t tos;
} Ip4RouteLookupArgs;

/**
 * @brief What redirect takes.
 *
 * RFC 1122 sec 3.3.1.2 (c): "When it receives a Redirect, the host updates the next-hop gateway in
 * the appropriate route cache entry", and "a Network Redirect message SHOULD be treated identically
 * to a Host Redirect message", so both carry the destination host address.
 */
typedef struct
{
    uint32_t dst;
    uint32_t gw;
} Ip4RouteRedirectArgs;

/**
 * @brief What set_pmtu takes.
 *
 * RFC 1191 sec 6.2 caches the path MTU on the route, and sec 6.3 stamps it: "Whenever the PMTU is
 * decreased in response to a Datagram Too Big message, the timestamp is set to the current time."
 */
typedef struct
{
    uint32_t dst;
    uint16_t mtu;
} Ip4RoutePmtuArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Ip4RouteIo::add_args      the row add writes
 * @var Ip4RouteIo::remove_args   the row remove drops
 * @var Ip4RouteIo::lookup_args   the destination and type of service lookup routes
 * @var Ip4RouteIo::redirect_args what an ICMP Redirect said
 * @var Ip4RouteIo::pmtu_args     the path MTU set_pmtu records
 * @var Ip4RouteIo::now_ms        the millisecond clock the caller read before the call. Every stamp
 *                                this unit writes and every age it compares comes from it.
 * @var Ip4RouteIo::status        what the call reports: OK, BUSY, or ERR
 * @var Ip4RouteIo::next_hop      where the datagram goes: the destination itself under sec 3.3.1.1
 *                                (b), or the gateway of the matched row under (c)
 * @var Ip4RouteIo::pmtu          the RFC 1191 path MTU cached on the matched row, 0 when none is
 * @var Ip4RouteIo::index         the row the call touched, or IDEMIP_IP4_ROUTE_INDEX_NONE
 * @var Ip4RouteIo::netif         the interface that row routes through
 * @var Ip4RouteIo::direct        the destination is on a connected network, sec 3.3.1.1 (b). On the
 *                               BUSY path it says the same of the rows that matched but carried no
 *                               usable TOS, which RFC 1812 sec 4.3.3.1 reads to pick Code 12 over 11.
 * @var Ip4RouteIo::tos_blocked  a lookup found rows for the destination but none whose route.tos is
 *                               the packet's or the default, which RFC 1812 sec 4.3.3.1 answers with
 *                               Destination Unreachable Code 11 or 12 rather than Code 0
 */
typedef struct
{
    Ip4RouteAddArgs add_args;
    Ip4RouteRemoveArgs remove_args;
    Ip4RouteLookupArgs lookup_args;
    Ip4RouteRedirectArgs redirect_args;
    Ip4RoutePmtuArgs pmtu_args;

    uint32_t now_ms;

    uint32_t next_hop;
    uint16_t pmtu;
    IdemIpStatus status;
    uint8_t index;
    uint8_t netif;
    idemip_bool direct;
    idemip_bool tos_blocked;
} Ip4RouteIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. IDEMIP_IP4_ROUTE_CTX_BYTES covers
// everything outside the table, which is the operand block and this module's private context.

/** @brief The operand and result block. */
#define IDEMIP_IP4_ROUTE_OFF_IO 0u

/** @brief The private context, right behind the operand block. */
#define IDEMIP_IP4_ROUTE_OFF_CTX (IDEMIP_IP4_ROUTE_OFF_IO + IDEMIP_ROUND_UP(sizeof(Ip4RouteIo), IDEMIP_ALIGN))

/** @brief IDEMIP_IP4_ROUTES rows, at the end of the head region. */
#define IDEMIP_IP4_ROUTE_OFF_TAB IDEMIP_IP4_ROUTE_CTX_BYTES

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IP4_ROUTE_IO(w) ((Ip4RouteIo *)(void *)((w) + IDEMIP_IP4_ROUTE_OFF_IO))

// A row index is one octet, so a count at or above the terminator is unaddressable.
static_assert(IDEMIP_IP4_ROUTES < IDEMIP_IP4_ROUTE_INDEX_NONE,
              "IDEMIP_IP4_ROUTES must stay below IDEMIP_IP4_ROUTE_INDEX_NONE: a row index is one octet");

/**
 * @brief The routing table.
 *
 *   Ip4Route.clear(work);
 *   IDEMIP_IP4_ROUTE_IO(work)->add_args.dst = 0u;   // the default route
 *   IDEMIP_IP4_ROUTE_IO(work)->add_args.mask = 0u;
 *   IDEMIP_IP4_ROUTE_IO(work)->add_args.gw = gateway;
 *   IDEMIP_IP4_ROUTE_IO(work)->add_args.flags = IDEMIP_IP4_ROUTE_F_GATEWAY;
 *   Ip4Route.add(work);
 *
 * @c work is IDEMIP_IP4_ROUTE_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the table, so two
 * routing tables are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick. A borrow that clear has not run on is refused.
 *
 * @var Ip4RouteNs::clear     zero the context and the table, and mark the borrow usable
 * @var Ip4RouteNs::add       write one row, rewriting the row holding the same destination, mask, type
 *                            of service and gateway. BUSY when every row is taken, which frees when
 *                            one is removed.
 * @var Ip4RouteNs::remove    drop every row holding a destination and mask
 * @var Ip4RouteNs::lookup    the sec 3.3.1.1 local/remote decision, then the sec 3.3.1.2 gateway
 *                            selection, over the RFC 1812 sec 5.2.4.3 pruning rules, into @ref
 *                            Ip4RouteIo::next_hop. BUSY when the table holds no route to the
 *                            destination and no default gateway, which an added route fixes.
 * @var Ip4RouteNs::redirect  move the host row's next hop to the gateway an ICMP Redirect named, and
 *                            create that row when none holds the destination, sec 3.3.1.2 (c)
 * @var Ip4RouteNs::set_pmtu  record a path MTU on the host row a destination matches, creating it
 *                            from the row that routes the destination today, RFC 1191 sec 6.2
 * @var Ip4RouteNs::tick      age the path MTU estimates, RFC 1191 sec 6.3
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const add)(uint8_t *work);
    void (*const remove)(uint8_t *work);
    void (*const lookup)(uint8_t *work);
    void (*const redirect)(uint8_t *work);
    void (*const set_pmtu)(uint8_t *work);
    void (*const tick)(uint8_t *work);
} Ip4RouteNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_ip4_route_clear(uint8_t *work);
void idemip_ip4_route_add(uint8_t *work);
void idemip_ip4_route_remove(uint8_t *work);
void idemip_ip4_route_lookup(uint8_t *work);
void idemip_ip4_route_redirect(uint8_t *work);
void idemip_ip4_route_set_pmtu(uint8_t *work);
void idemip_ip4_route_tick(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Ip4Route.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Ip4RouteNs Ip4Route IDEMIP_UNUSED = {
    .clear = idemip_ip4_route_clear,
    .add = idemip_ip4_route_add,
    .remove = idemip_ip4_route_remove,
    .lookup = idemip_ip4_route_lookup,
    .redirect = idemip_ip4_route_redirect,
    .set_pmtu = idemip_ip4_route_set_pmtu,
    .tick = idemip_ip4_route_tick};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_IP4_ROUTE_H
