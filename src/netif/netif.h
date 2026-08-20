// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file netif.h
 * @brief The interface record: the addresses an outbound datagram is routed by, and the link it
 *        leaves through.
 *
 * RFC 1122 sec 3.3.1.1 routes by the pair an interface holds, "The address mask (particular to a
 * local IP address for a multihomed host)... If the IP destination address bits extracted by the
 * address mask match the IP source address bits extracted by the same mask, then the destination is
 * on the corresponding connected network". RFC 1122 sec 3.3.1.6 makes the IP address, the address
 * mask and the gateway list configurable.
 *
 * The IPv6 addresses are a second table, IDEMIP_IP6_ADDRESSES per interface, each carrying the
 * RFC 4862 sec 2 state and the preferred and valid lifetimes RFC 4862 sec 5.5.4 ages it by.
 *
 * An interface reaches its link through the phy borrow it was bound to. Nothing here touches that
 * borrow: it is an address this table carries, and phy's own entries are called with it.
 */

#ifndef IDEMIP_NETIF_H
#define IDEMIP_NETIF_H

#include "src/ethernet/ethernet.h" // IDEMIP_MAC_LEN, and through it the config
#include "src/ip/ipv6.h"           // IDEMIP_IP6_ADDR_LEN, under the IPv6 gate

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/**
 * @brief What an interface reports about itself, one bit each.
 *
 * @var IDEMIP_NETIF_FLAG_UP        the interface is administratively enabled
 * @var IDEMIP_NETIF_FLAG_LINK_UP   the phy reports the link usable
 * @var IDEMIP_NETIF_FLAG_BROADCAST the link carries the RFC 1122 sec 3.2.1.3 broadcast forms
 * @var IDEMIP_NETIF_FLAG_LOOPBACK  the interface is the RFC 1122 sec 3.2.1.3 case (g) loopback
 * @var IDEMIP_NETIF_FLAG_MULTICAST the link carries group traffic (RFC 1112, RFC 2710)
 * @var IDEMIP_NETIF_FLAG_ETHARP    RFC 826 resolution runs on this interface
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_NETIF_FLAG_UP = 0x0001,
    IDEMIP_NETIF_FLAG_LINK_UP = 0x0002,
    IDEMIP_NETIF_FLAG_BROADCAST = 0x0004,
    IDEMIP_NETIF_FLAG_LOOPBACK = 0x0008,
    IDEMIP_NETIF_FLAG_MULTICAST = 0x0010,
    IDEMIP_NETIF_FLAG_ETHARP = 0x0020,
} IdemIpNetifFlag;

/** @brief Every flag a caller may set, so a reserved bit is refused rather than stored. */
#define IDEMIP_NETIF_FLAG_MASK                                                                                         \
    ((uint16_t)(IDEMIP_NETIF_FLAG_UP | IDEMIP_NETIF_FLAG_LINK_UP | IDEMIP_NETIF_FLAG_BROADCAST |                       \
                IDEMIP_NETIF_FLAG_LOOPBACK | IDEMIP_NETIF_FLAG_MULTICAST | IDEMIP_NETIF_FLAG_ETHARP))

/**
 * @brief Which header's checksum the MAC computes, so this stack does not.
 *
 * One bit per header a checksum covers: RFC 791 sec 3.1 Header Checksum, RFC 768 the UDP checksum,
 * RFC 9293 sec 3.1 the TCP checksum, RFC 792 the ICMP checksum, and RFC 4443 sec 2.3 the ICMPv6
 * checksum, which is computed over the RFC 8200 pseudo-header.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_NETIF_CHKSUM_IP4 = 0x0001,
    IDEMIP_NETIF_CHKSUM_UDP4 = 0x0002,
    IDEMIP_NETIF_CHKSUM_TCP4 = 0x0004,
    IDEMIP_NETIF_CHKSUM_ICMP4 = 0x0008,
    IDEMIP_NETIF_CHKSUM_UDP6 = 0x0010,
    IDEMIP_NETIF_CHKSUM_TCP6 = 0x0020,
    IDEMIP_NETIF_CHKSUM_ICMP6 = 0x0040,
} IdemIpNetifChksum;

/** @brief Every offload bit a caller may set. */
#define IDEMIP_NETIF_CHKSUM_MASK                                                                                       \
    ((uint16_t)(IDEMIP_NETIF_CHKSUM_IP4 | IDEMIP_NETIF_CHKSUM_UDP4 | IDEMIP_NETIF_CHKSUM_TCP4 |                        \
                IDEMIP_NETIF_CHKSUM_ICMP4 | IDEMIP_NETIF_CHKSUM_UDP6 | IDEMIP_NETIF_CHKSUM_TCP6 |                      \
                IDEMIP_NETIF_CHKSUM_ICMP6))

/**
 * @brief What an address on an interface is, in the RFC 4862 sec 2 words.
 *
 * @var IDEMIP_NETIF_ADDR6_INVALID    "an address that is not assigned to any interface"; the free
 *                                    slot, so a zeroed table holds none
 * @var IDEMIP_NETIF_ADDR6_TENTATIVE  "an address whose uniqueness on a link is being verified,
 *                                    prior to its assignment to an interface"
 * @var IDEMIP_NETIF_ADDR6_PREFERRED  "an address assigned to an interface whose use by upper-layer
 *                                    protocols is unrestricted"
 * @var IDEMIP_NETIF_ADDR6_DEPRECATED "an address assigned to an interface whose use is discouraged,
 *                                    but not forbidden"
 * @var IDEMIP_NETIF_ADDR6_DUPLICATE  RFC 4862 sec 5.4.5, a tentative address Duplicate Address
 *                                    Detection found in use
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_NETIF_ADDR6_INVALID = 0,
    IDEMIP_NETIF_ADDR6_TENTATIVE,
    IDEMIP_NETIF_ADDR6_PREFERRED,
    IDEMIP_NETIF_ADDR6_DEPRECATED,
    IDEMIP_NETIF_ADDR6_DUPLICATE,
} IdemIpNetifAddr6State;

/**
 * @brief A lifetime that never expires.
 *
 * RFC 4861 sec 4.6.2, of both the Valid Lifetime and the Preferred Lifetime: "A value of all one
 * bits (0xffffffff) represents infinity."
 */
#define IDEMIP_NETIF_LIFETIME_INFINITE 0xFFFFFFFFu

/**
 * @brief What bind takes: the link an interface leaves through.
 *
 * @var NetifBindArgs::phy    the IDEMIP_PHY_BORROW bytes this interface's link was bound in, an
 *                            address this table carries and never dereferences
 * @var NetifBindArgs::hwaddr IDEMIP_MAC_LEN octets, the RFC 894 48-bit address, copied in
 * @var NetifBindArgs::mtu    the octets the link carries in one frame
 * @var NetifBindArgs::index  which interface, 0 through IDEMIP_NETIF_COUNT - 1
 */
typedef struct
{
    uint8_t *phy;
    const uint8_t *hwaddr;
    uint16_t mtu;
    uint8_t index;
} NetifBindArgs;

/**
 * @brief What an IPv4 assignment takes (RFC 1122 sec 3.3.1.6).
 *
 * @var NetifAddr4Args::addr  this interface's local IP address, host order
 * @var NetifAddr4Args::mask  the RFC 1122 sec 3.3.1.1 address mask, host order
 * @var NetifAddr4Args::gw    the RFC 1122 sec 3.3.1.2 default gateway, host order
 * @var NetifAddr4Args::index which interface
 */
typedef struct
{
    uint32_t addr;
    uint32_t mask;
    uint32_t gw;
    uint8_t index;
} NetifAddr4Args;

/**
 * @brief What the per-interface settings take, and what a read names.
 *
 * @var NetifIfArgs::mtu    what set_mtu writes; unread by the others
 * @var NetifIfArgs::set    the flags set_flags raises, IDEMIP_NETIF_FLAG_MASK
 * @var NetifIfArgs::clear  the flags set_flags lowers, applied after @ref NetifIfArgs::set
 * @var NetifIfArgs::chksum what set_offload writes, IDEMIP_NETIF_CHKSUM_MASK
 * @var NetifIfArgs::index  which interface
 */
typedef struct
{
    uint16_t mtu;
    uint16_t set;
    uint16_t clear;
    uint16_t chksum;
    uint8_t index;
} NetifIfArgs;

/**
 * @brief What a route decision takes (RFC 1122 sec 3.3.1.1).
 *
 * @var NetifRouteArgs::dst   the destination address the local/remote decision is made on, host
 *                            order
 * @var NetifRouteArgs::index which interface local4 asks; unread by find4, which asks every one
 */
typedef struct
{
    uint32_t dst;
    uint8_t index;
} NetifRouteArgs;

#if IDEMIP_ENABLE_IPV6

/**
 * @brief What an IPv6 address operation takes.
 *
 * @var NetifAddr6Args::addr        IDEMIP_IP6_ADDR_LEN octets, copied in by add and matched by find
 * @var NetifAddr6Args::preferred_s the RFC 4861 sec 4.6.2 Preferred Lifetime, seconds
 * @var NetifAddr6Args::valid_s     the RFC 4861 sec 4.6.2 Valid Lifetime, seconds
 * @var NetifAddr6Args::state       the RFC 4862 sec 2 state add assigns
 * @var NetifAddr6Args::index       which interface
 * @var NetifAddr6Args::slot        which of that interface's IDEMIP_IP6_ADDRESSES, read by get_addr6
 * @var NetifAddr6Args::tentative   find_addr6 only: match a tentative address as well. RFC 4862 sec
 *                                  5.4 says a tentative address "is not considered 'assigned to an
 *                                  interface' in the traditional sense" and that packets addressed
 *                                  to it "should be silently discarded", so an ordinary input lookup
 *                                  leaves this false. The sec 5.4.3 Target Address match of a
 *                                  Neighbor Solicitation or Advertisement is the case that sets it.
 *                                  A duplicate address is never matched either way, sec 5.4.5
 *                                  barring it from being assigned at all
 */
typedef struct
{
    const uint8_t *addr;
    uint32_t preferred_s;
    uint32_t valid_s;
    IdemIpNetifAddr6State state;
    uint8_t index;
    uint8_t slot;
    idemip_bool tentative;
} NetifAddr6Args;

#endif // IDEMIP_ENABLE_IPV6

// The clock is not a tick operand. It was, and add_addr6 read the one the last tick left behind
// rather than the caller's own, so an address added before the first tick was stamped against a
// clock still at zero and the first real tick retired it. See NetifIo::now_ms.

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var NetifIo::bind_args   the link, the hardware address and the MTU bind takes
 * @var NetifIo::addr4_args  the address, mask and gateway set_addr4 takes
 * @var NetifIo::if_args     the MTU, flags and offload mask the setters take, and the index a read
 *                           names
 * @var NetifIo::route_args  the destination on_link and find4 decide on
 * @var NetifIo::addr6_args  the address, state and lifetimes the IPv6 entries take
 * @var NetifIo::now_ms      the millisecond clock the caller read before the call. Every deadline
 *                           this unit stamps and every age it compares comes from it, so no entry
 *                           reads a clock of its own and none reads the one another entry left.
 * @var NetifIo::status      what the call reports: OK, BUSY, or ERR
 * @var NetifIo::phy         the phy borrow the named interface is bound through
 * @var NetifIo::hwaddr      IDEMIP_MAC_LEN octets in this borrow, the named interface's address
 * @var NetifIo::addr        the named interface's local IP address, host order
 * @var NetifIo::mask        its address mask, host order
 * @var NetifIo::gw          its default gateway, host order
 * @var NetifIo::mtu         the octets its link carries in one frame
 * @var NetifIo::mtu6        the MTU an RFC 4861 sec 4.6.4 MTU option revised it to, or 0
 * @var NetifIo::flags       its IdemIpNetifFlag set
 * @var NetifIo::chksum      its IdemIpNetifChksum offload set
 * @var NetifIo::index       which interface find4 found, or which one a read named
 * @var NetifIo::local       what the RFC 1122 sec 3.3.1.1 local/remote decision answered
 * @var NetifIo::addr6       IDEMIP_IP6_ADDR_LEN octets in this borrow, what the IPv6 read reports
 * @var NetifIo::preferred_s its RFC 4861 sec 4.6.2 Preferred Lifetime, seconds
 * @var NetifIo::valid_s     its RFC 4861 sec 4.6.2 Valid Lifetime, seconds
 * @var NetifIo::addr6_state its RFC 4862 sec 2 state
 * @var NetifIo::slot        which of the interface's IDEMIP_IP6_ADDRESSES the IPv6 entry reached
 * @var NetifIo::aged        addresses the tick moved to a later RFC 4862 sec 5.5.4 state
 */
typedef struct
{
    NetifBindArgs bind_args;
    NetifAddr4Args addr4_args;
    NetifIfArgs if_args;
    NetifRouteArgs route_args;
#if IDEMIP_ENABLE_IPV6
    NetifAddr6Args addr6_args;
#endif

    uint32_t now_ms;
    IdemIpStatus status;
    uint8_t *phy;
    const uint8_t *hwaddr;
    uint32_t addr;
    uint32_t mask;
    uint32_t gw;
    uint16_t mtu;
    uint16_t mtu6;
    uint16_t flags;
    uint16_t chksum;
    uint8_t index;
    idemip_bool local;
#if IDEMIP_ENABLE_IPV6
    const uint8_t *addr6;
    uint32_t preferred_s;
    uint32_t valid_s;
    IdemIpNetifAddr6State addr6_state;
    uint8_t slot;
    uint8_t aged;
#endif
} NetifIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The operand block and the context share the
// IDEMIP_NETIF_CTX_BYTES ahead of the tables, so the two tables sit at offsets no struct layout can
// move.

#define IDEMIP_NETIF_OFF_IO 0u ///< the operand and result block
#define IDEMIP_NETIF_OFF_CTX IDEMIP_ROUND_UP(IDEMIP_NETIF_OFF_IO + sizeof(NetifIo), IDEMIP_ALIGN)
#define IDEMIP_NETIF_OFF_TAB IDEMIP_NETIF_CTX_BYTES ///< IDEMIP_NETIF_COUNT entries
#define IDEMIP_NETIF_OFF_ADDR6                                                                                         \
    (IDEMIP_NETIF_OFF_TAB + (IDEMIP_NETIF_COUNT << IDEMIP_NETIF_ENTRY_SHIFT)) ///< IDEMIP_IP6_ADDRESSES per interface
#define IDEMIP_NETIF_OFF_END                                                                                           \
    (IDEMIP_NETIF_OFF_ADDR6 + ((IDEMIP_NETIF_COUNT * IDEMIP_IP6_ADDRESSES) << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_NETIF_IO(w) ((NetifIo *)(void *)((w) + IDEMIP_NETIF_OFF_IO))

/**
 * @brief The interface table.
 *
 *   Netif.clear(work);
 *   IDEMIP_NETIF_IO(work)->bind_args.index = 0u;
 *   IDEMIP_NETIF_IO(work)->bind_args.phy = phy_work;
 *   IDEMIP_NETIF_IO(work)->bind_args.hwaddr = mac;
 *   IDEMIP_NETIF_IO(work)->bind_args.mtu = 1500u;
 *   Netif.bind(work);
 *
 * @c work is IDEMIP_NETIF_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the table, so two
 * stacks are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick. A table with no free slot is BUSY; a bad index, a reserved
 * flag or an unbound interface is ERR.
 *
 * @var NetifNs::clear        zero the context and both tables, which every other entry refuses until
 *                            it has run. The operand block is the caller's and is left alone.
 * @var NetifNs::bind         take the phy borrow, the hardware address and the MTU for one interface
 * @var NetifNs::unbind       drop one interface's link and every address on it
 * @var NetifNs::set_addr4    take the RFC 1122 sec 3.3.1.6 address, mask and gateway
 * @var NetifNs::set_mtu      revise the MTU, as an RFC 4861 sec 4.6.4 MTU option does
 * @var NetifNs::set_flags    raise @ref NetifIfArgs::set, then lower @ref NetifIfArgs::clear
 * @var NetifNs::set_offload  take the checksum mask the MAC computes
 * @var NetifNs::get          report one interface's whole record
 * @var NetifNs::find4        report which interface holds @ref NetifRouteArgs::dst as its own
 *                            address (RFC 1122 sec 3.2.1.3, "the IP source address MUST be one of
 *                            its own IP addresses"). An interface with no address holds none, so
 *                            0.0.0.0 is never found: sec 3.2.1.3 (a) makes { 0, 0 } the address a
 *                            host has not learned yet. ERR when no interface holds it, a miss no
 *                            retry can turn into a hit.
 * @var NetifNs::local4       the RFC 1122 sec 3.3.1.1 local/remote decision for one interface,
 *                            reported in @ref NetifIo::local. An interface with no address extracts
 *                            no bits, so only the limited broadcast and a multicast group are on its
 *                            link. OK whichever way it went.
 * @var NetifNs::add_addr6    assign an IPv6 address with its RFC 4862 sec 2 state and lifetimes.
 *                            BUSY when the interface's IDEMIP_IP6_ADDRESSES slots are all taken.
 * @var NetifNs::remove_addr6 return an IPv6 address to IDEMIP_NETIF_ADDR6_INVALID
 * @var NetifNs::find_addr6   report which slot on which interface holds an IPv6 address. ERR when
 *                            none does.
 * @var NetifNs::get_addr6    report one slot's address, state and lifetimes. ERR on a slot holding
 *                            IDEMIP_NETIF_ADDR6_INVALID.
 * @var NetifNs::tick         age every IPv6 lifetime (RFC 4862 sec 5.5.4)
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const bind)(uint8_t *work);
    void (*const unbind)(uint8_t *work);
    void (*const set_addr4)(uint8_t *work);
    void (*const set_mtu)(uint8_t *work);
    void (*const set_flags)(uint8_t *work);
    void (*const set_offload)(uint8_t *work);
    void (*const get)(uint8_t *work);
    void (*const find4)(uint8_t *work);
    void (*const local4)(uint8_t *work);
#if IDEMIP_ENABLE_IPV6
    void (*const add_addr6)(uint8_t *work);
    void (*const remove_addr6)(uint8_t *work);
    void (*const find_addr6)(uint8_t *work);
    void (*const get_addr6)(uint8_t *work);
    void (*const tick)(uint8_t *work);
#endif
} NetifNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_netif_clear(uint8_t *work);
void idemip_netif_bind(uint8_t *work);
void idemip_netif_unbind(uint8_t *work);
void idemip_netif_set_addr4(uint8_t *work);
void idemip_netif_set_mtu(uint8_t *work);
void idemip_netif_set_flags(uint8_t *work);
void idemip_netif_set_offload(uint8_t *work);
void idemip_netif_get(uint8_t *work);
void idemip_netif_find4(uint8_t *work);
void idemip_netif_local4(uint8_t *work);
#if IDEMIP_ENABLE_IPV6
void idemip_netif_add_addr6(uint8_t *work);
void idemip_netif_remove_addr6(uint8_t *work);
void idemip_netif_find_addr6(uint8_t *work);
void idemip_netif_get_addr6(uint8_t *work);
void idemip_netif_tick(uint8_t *work);
#endif

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Netif.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const NetifNs Netif IDEMIP_UNUSED = {
    .clear = idemip_netif_clear,
    .bind = idemip_netif_bind,
    .unbind = idemip_netif_unbind,
    .set_addr4 = idemip_netif_set_addr4,
    .set_mtu = idemip_netif_set_mtu,
    .set_flags = idemip_netif_set_flags,
    .set_offload = idemip_netif_set_offload,
    .get = idemip_netif_get,
    .find4 = idemip_netif_find4,
    .local4 = idemip_netif_local4,
#if IDEMIP_ENABLE_IPV6
    .add_addr6 = idemip_netif_add_addr6,
    .remove_addr6 = idemip_netif_remove_addr6,
    .find_addr6 = idemip_netif_find_addr6,
    .get_addr6 = idemip_netif_get_addr6,
    .tick = idemip_netif_tick,
#endif
};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_NETIF_H
