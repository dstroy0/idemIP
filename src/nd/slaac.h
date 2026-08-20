// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file slaac.h
 * @brief Stateless address autoconfiguration, RFC 4862 sec 5.3 and sec 5.5: the addresses an
 *        interface forms, and the lifetimes they age by.
 *
 * sec 5.5: "Global addresses are formed by appending an interface identifier to a prefix of
 * appropriate length. Prefixes are obtained from Prefix Information options contained in Router
 * Advertisements." sec 5.5.3 (a) through (e) is what one such option does to the list, sec 5.5.3 (e)
 * carrying the two-hour rule that keeps a bogus advertisement from expiring a live address. sec 5.5.4
 * ages the list.
 *
 * sec 5 runs autoconfiguration "on a per-interface basis", so the borrow IS the interface and holds
 * IDEMIP_IP6_ADDRESSES of them.
 *
 * Every deadline here is a millisecond. RFC 4861 sec 4.6.2 states both lifetimes in seconds, which
 * are multiplied to milliseconds once on arrival, so the clock a deadline is compared against needs
 * no conversion and no divide exists.
 *
 * Nothing here parses a Router Advertisement or runs Duplicate Address Detection: sec 5.4 is dad.h's,
 * and an address formed here is tentative until dad reports it unique.
 */

#ifndef IDEMIP_SLAAC_H
#define IDEMIP_SLAAC_H

#include "src/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/** @brief No entry. Every index below is a table slot, so this names none of them. */
#define IDEMIP_SLAAC_NONE 0xFFu

/**
 * @brief RFC 4861 sec 4.6.2: a lifetime "of all one bits (0xffffffff) represents infinity".
 *
 * RFC 4862 sec 5.3 gives a link-local address "an infinite preferred and valid lifetime; it is never
 * timed out".
 */
#define IDEMIP_SLAAC_LIFETIME_INFINITE 0xFFFFFFFFu

/**
 * @brief What one address in the list is (RFC 4862 sec 2).
 *
 * sec 2: a "preferred address" is one "whose use by upper-layer protocols is unrestricted"; a
 * "deprecated address" is one "whose use is discouraged, but not forbidden"; and an "invalid address"
 * is "an address that is not assigned to any interface", which is what a freed slot is.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_SLAAC_ADDR_FREE = 0,   ///< the slot holds no address, which is what clear leaves
    IDEMIP_SLAAC_ADDR_PREFERRED,  ///< inside its preferred lifetime
    IDEMIP_SLAAC_ADDR_DEPRECATED, ///< the preferred lifetime expired, the valid one has not
} IdemIpSlaacAddrState;

/**
 * @brief What link_local takes (RFC 4862 sec 5.3).
 *
 * sec 5.3 forms the address in three steps: "The left-most 'prefix length' bits of the address are
 * those of the link-local prefix", "The bits in the address to the right of the link-local prefix are
 * set to all zeroes", and "If the length of the interface identifier is N bits, the right-most N bits
 * of the address are replaced by the interface identifier."
 *
 * @var SlaacLinkLocalArgs::iid      the interface identifier, @ref SlaacLinkLocalArgs::iid_bits bits
 *                                   in (iid_bits >> 3) octets. RFC 2464 sec 4 derives an Ethernet
 *                                   interface's from the EUI-64 of its 48-bit address.
 * @var SlaacLinkLocalArgs::iid_bits N. RFC 2464 sec 5 appends a 64-bit one to FE80::/64. sec 5.3:
 *                                   "If the sum of the link-local prefix length and N is larger than
 *                                   128, autoconfiguration fails".
 */
typedef struct
{
    const uint8_t *iid;
    uint8_t iid_bits;
} SlaacLinkLocalArgs;

/**
 * @brief What one Prefix Information option takes (RFC 4861 sec 4.6.2, RFC 4862 sec 5.5.3).
 *
 * @var SlaacPrefixArgs::prefix        the option's Prefix field, IDEMIP_IP6_ADDR_LEN octets, its bits
 *                                     past @ref SlaacPrefixArgs::prefix_len "reserved and MUST be
 *                                     initialized to zero by the sender and ignored by the receiver"
 * @var SlaacPrefixArgs::iid           the interface identifier the address is formed with
 * @var SlaacPrefixArgs::valid_s       the option's Valid Lifetime in seconds;
 *                                     IDEMIP_SLAAC_LIFETIME_INFINITE is infinity
 * @var SlaacPrefixArgs::preferred_s   the option's Preferred Lifetime in seconds, which sec 4.6.2
 *                                     says "MUST NOT exceed the Valid Lifetime field"
 * @var SlaacPrefixArgs::now_ms        the millisecond clock both deadlines are stamped from
 * @var SlaacPrefixArgs::prefix_len    the option's Prefix Length, "from 0 to 128"
 * @var SlaacPrefixArgs::iid_bits      N, which sec 5.5.3 (d) requires sum with the prefix length to
 *                                     exactly 128
 * @var SlaacPrefixArgs::autonomous    the option's A flag, sec 5.5.3 (a) ignoring the option without
 *                                     it
 * @var SlaacPrefixArgs::authenticated the Router Advertisement this option came from "has been
 *                                     authenticated (e.g., via Secure Neighbor Discovery)", which
 *                                     sec 5.5.3 (e) 2 is the one exception to the two-hour rule
 */
typedef struct
{
    const uint8_t *prefix;
    const uint8_t *iid;
    uint32_t valid_s;
    uint32_t preferred_s;
    uint32_t now_ms;
    uint8_t prefix_len;
    uint8_t iid_bits;
    idemip_bool autonomous;
    idemip_bool authenticated;
} SlaacPrefixArgs;

/**
 * @brief What a call keyed on an address or a slot takes.
 *
 * @var SlaacAddrArgs::addr  the address a find or a remove names, IDEMIP_IP6_ADDR_LEN octets
 * @var SlaacAddrArgs::index the slot a get names, below IDEMIP_IP6_ADDRESSES
 */
typedef struct
{
    const uint8_t *addr;
    uint8_t index;
} SlaacAddrArgs;

/** @brief What a tick takes: the clock every deadline is compared against. */
typedef struct
{
    uint32_t now_ms;
} SlaacTickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var SlaacIo::link_local_args the interface identifier a link-local address is formed from
 * @var SlaacIo::prefix_args     one Prefix Information option
 * @var SlaacIo::addr_args       the address a find or a remove names
 * @var SlaacIo::tick_args       the clock a tick ages the list against
 * @var SlaacIo::status          what the call reports: OK, BUSY, or ERR
 * @var SlaacIo::addr            the address the call formed, matched or aged, IDEMIP_IP6_ADDR_LEN
 *                               octets. Copied rather than pointed at, so an invalidated address is
 *                               still readable after its slot is freed.
 * @var SlaacIo::valid_at        the millisecond on the 64-bit clock the valid lifetime expires at,
 *                               after which the address is invalid
 * @var SlaacIo::preferred_at    the millisecond the preferred lifetime expires at, after which the
 *                               address is deprecated
 * @var SlaacIo::entry           the table slot the call touched, or IDEMIP_SLAAC_NONE
 * @var SlaacIo::state           what that address is: preferred or deprecated
 * @var SlaacIo::prefix_len      the prefix length it was formed with
 * @var SlaacIo::addresses       addresses the list holds
 * @var SlaacIo::valid_infinite  the valid lifetime is the all-ones infinity, so @ref SlaacIo::valid_at
 *                               is not a deadline
 * @var SlaacIo::preferred_infinite the preferred lifetime is that infinity
 * @var SlaacIo::created         sec 5.5.3 (d) formed an address and added it to the list
 * @var SlaacIo::updated         sec 5.5.3 (e) reset a lifetime of an address already in the list
 * @var SlaacIo::ignored         sec 5.5.3 (a), (b), (c) or (d) ignored the option
 * @var SlaacIo::two_hour        sec 5.5.3 (e) 2 or (e) 3 held the valid lifetime back: the advertised
 *                               one was not taken
 * @var SlaacIo::deprecated      a tick found a preferred lifetime expired, so the address "SHOULD NOT
 *                               be used to initiate new communications" (sec 5.5.4)
 * @var SlaacIo::invalidated     a tick found a valid lifetime expired, so the address "MUST NOT be
 *                               used as a source address in outgoing communications and MUST NOT be
 *                               recognized as a destination on a receiving interface" (sec 5.5.4)
 */
typedef struct
{
    SlaacLinkLocalArgs link_local_args;
    SlaacPrefixArgs prefix_args;
    SlaacAddrArgs addr_args;
    SlaacTickArgs tick_args;

    IdemIpMs valid_at;
    IdemIpMs preferred_at;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    IdemIpStatus status;
    uint8_t entry;
    IdemIpSlaacAddrState state;
    uint8_t prefix_len;
    uint8_t addresses;
    idemip_bool valid_infinite;
    idemip_bool preferred_infinite;
    idemip_bool created;
    idemip_bool updated;
    idemip_bool ignored;
    idemip_bool two_hour;
    idemip_bool deprecated;
    idemip_bool invalidated;
} SlaacIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only the
// map is public.
//
// IDEMIP_SLAAC_CTX_BYTES spans the operand block and the context together, the way IDEMIP_PHY_BORROW
// covers both, so the table starts at a constant that no growth in either moves.

#define IDEMIP_SLAAC_OFF_IO 0u ///< the operand and result block
#define IDEMIP_SLAAC_OFF_CTX (IDEMIP_SLAAC_OFF_IO + IDEMIP_ROUND_UP(sizeof(SlaacIo), IDEMIP_ALIGN))
#define IDEMIP_SLAAC_OFF_ENTRIES (IDEMIP_SLAAC_OFF_IO + IDEMIP_SLAAC_CTX_BYTES)
#define IDEMIP_SLAAC_OFF_END (IDEMIP_SLAAC_OFF_ENTRIES + (IDEMIP_IP6_ADDRESSES << IDEMIP_SLAAC_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_SLAAC_IO(w) ((SlaacIo *)(void *)((w) + IDEMIP_SLAAC_OFF_IO))

/**
 * @brief One interface's autoconfigured addresses, RFC 4862 sec 5.2's "list of addresses together
 *        with their corresponding lifetimes".
 *
 *   Slaac.clear(work);
 *   IDEMIP_SLAAC_IO(work)->link_local_args.iid = eui64;
 *   IDEMIP_SLAAC_IO(work)->link_local_args.iid_bits = 64u;
 *   Slaac.link_local(work);
 *   IDEMIP_SLAAC_IO(work)->prefix_args.prefix = pio_prefix;
 *   IDEMIP_SLAAC_IO(work)->prefix_args.prefix_len = 64u;
 *   Slaac.prefix_in(work);
 *   if (IDEMIP_SLAAC_IO(work)->created) { ... }
 *
 * @c work is IDEMIP_SLAAC_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the interface, so two
 * interfaces share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * A borrow is refused until @ref SlaacNs::clear has run on it: clear zeroes the context and the table
 * and leaves the mark that says these bytes are this module's. It does not touch the operand block.
 *
 * Nothing here blocks. A list with no free slot reports IDEMIP_BUSY, a slot freeing when a valid
 * lifetime expires or the caller removes an address, and a tick with nothing due reports IDEMIP_BUSY.
 * A bad argument, an uncleared borrow, and an address that is not in the list report IDEMIP_ERR. An
 * option sec 5.5.3 says to "silently ignore" is not a fault: the call reports IDEMIP_OK with
 * @ref SlaacIo::ignored set.
 *
 * @var SlaacNs::clear      zero the context and the list, and mark the borrow cleared
 * @var SlaacNs::link_local form the sec 5.3 link-local address, which has "an infinite preferred and
 *                          valid lifetime"
 * @var SlaacNs::prefix_in  one Prefix Information option, through sec 5.5.3 (a) to (e)
 * @var SlaacNs::find       report the list entry holding an address
 * @var SlaacNs::get        report the list entry at @ref SlaacIo::entry, so a caller walks the list
 * @var SlaacNs::remove     drop an address from the list, freeing its slot
 * @var SlaacNs::tick       age the list per sec 5.5.4: one deprecation or one invalidation per call,
 *                          and IDEMIP_BUSY when nothing was due
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const link_local)(uint8_t *work);
    void (*const prefix_in)(uint8_t *work);
    void (*const find)(uint8_t *work);
    void (*const get)(uint8_t *work);
    void (*const remove)(uint8_t *work);
    void (*const tick)(uint8_t *work);
} SlaacNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_slaac_clear(uint8_t *work);
void idemip_slaac_link_local(uint8_t *work);
void idemip_slaac_prefix_in(uint8_t *work);
void idemip_slaac_find(uint8_t *work);
void idemip_slaac_get(uint8_t *work);
void idemip_slaac_remove(uint8_t *work);
void idemip_slaac_tick(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Slaac.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const SlaacNs Slaac IDEMIP_UNUSED = {
    .clear = idemip_slaac_clear,
    .link_local = idemip_slaac_link_local,
    .prefix_in = idemip_slaac_prefix_in,
    .find = idemip_slaac_find,
    .get = idemip_slaac_get,
    .remove = idemip_slaac_remove,
    .tick = idemip_slaac_tick};
// Every slot index counts the addresses the borrow holds, so IDEMIP_SLAAC_NONE names none of them.
static_assert(IDEMIP_IP6_ADDRESSES < IDEMIP_SLAAC_NONE,
              "the list is wider than the index a result member carries");

// RFC 4862 sec 5.5.3 (e) 3: "reset the valid lifetime of the corresponding address to 2 hours".
static_assert(IDEMIP_SLAAC_TWO_HOURS_MS == 7200u * 1000u,
              "RFC 4862 sec 5.5.3 (e) states two hours: 7200 seconds of milliseconds");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_SLAAC_H
