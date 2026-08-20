// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file rdnss.h
 * @brief The Recursive DNS Server option, RFC 8106 sec 5.1, and the DNS Server List it fills.
 *
 * sec 4: "The existing ND message (i.e., RA) is used to carry this information. An IPv6 host can
 * configure the IPv6 addresses of one or more RDNSSes via RA messages."
 *
 * sec 6.1 names the structure this borrow holds: "the DNS Server List, which keeps the list of RDNSS
 * addresses", each entry "a pair of an RDNSS address ... and Expiration-time", where
 * "Expiration-time is set to the value of the Lifetime field of the RDNSS option ... plus the current
 * time". sec 6.2 keeps it in the order the option carried, so the caller copies it into the resolver
 * with @ref RdnssNs::get and dns.h's set_server, first slot first.
 *
 * Every deadline here is a millisecond. sec 5.1 states the Lifetime in seconds, multiplied once on
 * arrival, so the clock an expiration is compared against needs no conversion and no divide exists.
 *
 * RFC 8106 obsoletes RFC 6106, which is the number lwIP cites.
 */

#ifndef IDEMIP_RDNSS_H
#define IDEMIP_RDNSS_H

#include "src/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/** @brief No entry. Every index below is a table slot, so this names none of them. */
#define IDEMIP_RDNSS_NONE 0xFFu

// ---------------------------------------------------------------------------
// The option, RFC 8106 sec 5.1 Figure 1
// ---------------------------------------------------------------------------

/** @brief Type: "8-bit identifier of the RDNSS option type as assigned by IANA: 25". */
#define IDEMIP_RDNSS_OPT_TYPE 25u

#define IDEMIP_RDNSS_OPT_OFF_TYPE 0u     ///< 8-bit Type
#define IDEMIP_RDNSS_OPT_OFF_LEN 1u      ///< 8-bit Length, in units of 8 octets
#define IDEMIP_RDNSS_OPT_OFF_RESERVED 2u ///< 16-bit Reserved
#define IDEMIP_RDNSS_OPT_OFF_LIFETIME 4u ///< 32-bit Lifetime, seconds
#define IDEMIP_RDNSS_OPT_OFF_ADDRS 8u    ///< the "Addresses of IPv6 Recursive DNS Servers"

/**
 * @brief Octets one Length unit spans.
 *
 * RFC 4861 sec 4.6 states every Neighbor Discovery option's Length "in units of 8 octets", and
 * RFC 8106 sec 5.1 repeats it: "The length of the option (including the Type and Length fields) is in
 * units of 8 octets."
 */
#define IDEMIP_RDNSS_OPT_UNIT 8u

/**
 * @brief The smallest Length a well-formed option carries.
 *
 * sec 5.1: "The minimum value is 3 if one IPv6 address is contained in the option. Every additional
 * RDNSS address increases the length by 2."
 */
#define IDEMIP_RDNSS_OPT_LEN_MIN 3u

/**
 * @brief RFC 8106 sec 5.1: "A value of all one bits (0xffffffff) represents infinity."
 */
#define IDEMIP_RDNSS_LIFETIME_INFINITE 0xFFFFFFFFu

/**
 * @brief What option_in takes: one Recursive DNS Server option, where it lies.
 *
 * @var RdnssOptionArgs::option the option, from its Type octet
 * @var RdnssOptionArgs::len    octets readable at @ref RdnssOptionArgs::option, which the option's
 *                              own Length field must fit inside
 * @var RdnssOptionArgs::now_ms the millisecond clock sec 6.1's Expiration-time is stamped from
 */
typedef struct
{
    const uint8_t *option;
    size_t len;
    uint32_t now_ms;
} RdnssOptionArgs;

/**
 * @brief What a call keyed on an address or a slot takes.
 *
 * @var RdnssAddrArgs::addr  the server a find or a remove names, IDEMIP_IP6_ADDR_LEN octets
 * @var RdnssAddrArgs::index the slot a get names, below IDEMIP_RDNSS_SERVERS
 */
typedef struct
{
    const uint8_t *addr;
    uint8_t index;
} RdnssAddrArgs;

/** @brief What a tick takes: the clock every Expiration-time is compared against. */
typedef struct
{
    uint32_t now_ms;
} RdnssTickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var RdnssIo::option_args  one arriving RDNSS option
 * @var RdnssIo::addr_args    the server a get, a find or a remove names
 * @var RdnssIo::tick_args    the clock a tick expires entries against
 * @var RdnssIo::status       what the call reports: OK, BUSY, or ERR
 * @var RdnssIo::addr         the server the call reported or expired, IDEMIP_IP6_ADDR_LEN octets.
 *                            Copied rather than pointed at, so an expired one is still readable after
 *                            its slot is freed.
 * @var RdnssIo::expire_at    sec 6.1's Expiration-time, "the time when this entry becomes invalid"
 * @var RdnssIo::lifetime_s   the Lifetime the option carried, in seconds
 * @var RdnssIo::entry        the slot the call touched, or IDEMIP_RDNSS_NONE
 * @var RdnssIo::servers      entries the DNS Server List holds
 * @var RdnssIo::added        addresses sec 6.2 step (d) registered from this option
 * @var RdnssIo::updated      addresses sec 6.2 step (c) refreshed the Expiration-time of
 * @var RdnssIo::deleted      addresses sec 6.2 step (b) deleted, its Lifetime being zero
 * @var RdnssIo::evicted      entries step (d) dropped to make room, "the entry with the shortest
 *                            Expiration-time"
 * @var RdnssIo::expired      a tick found an Expiration-time reached, so the entry "is deleted from
 *                            the DNS Server List" (sec 6.2)
 * @var RdnssIo::ignored      the option failed sec 5.3.1's validity check, so it is discarded whole
 * @var RdnssIo::infinite     the reported entry's Lifetime was the all-ones infinity, so
 *                            @ref RdnssIo::expire_at is not a deadline
 */
typedef struct
{
    RdnssOptionArgs option_args;
    RdnssAddrArgs addr_args;
    RdnssTickArgs tick_args;

    IdemIpMs expire_at;
    uint32_t lifetime_s;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    IdemIpStatus status;
    uint8_t entry;
    uint8_t servers;
    uint8_t added;
    uint8_t updated;
    uint8_t deleted;
    uint8_t evicted;
    idemip_bool expired;
    idemip_bool ignored;
    idemip_bool infinite;
} RdnssIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only the
// map is public.
//
// IDEMIP_RDNSS_CTX_BYTES spans the operand block and the context together, the way IDEMIP_PHY_BORROW
// covers both, so the table starts at a constant that no growth in either moves.

#define IDEMIP_RDNSS_OFF_IO 0u ///< the operand and result block
#define IDEMIP_RDNSS_OFF_CTX (IDEMIP_RDNSS_OFF_IO + IDEMIP_ROUND_UP(sizeof(RdnssIo), IDEMIP_ALIGN))
#define IDEMIP_RDNSS_OFF_ENTRIES (IDEMIP_RDNSS_OFF_IO + IDEMIP_RDNSS_CTX_BYTES)
#define IDEMIP_RDNSS_OFF_END (IDEMIP_RDNSS_OFF_ENTRIES + (IDEMIP_RDNSS_SERVERS << IDEMIP_RDNSS_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_RDNSS_IO(w) ((RdnssIo *)(void *)((w) + IDEMIP_RDNSS_OFF_IO))

/**
 * @brief One interface's RFC 8106 sec 6.1 DNS Server List.
 *
 *   Rdnss.clear(work);
 *   IDEMIP_RDNSS_IO(work)->option_args.option = opt;
 *   IDEMIP_RDNSS_IO(work)->option_args.len = remaining;
 *   IDEMIP_RDNSS_IO(work)->option_args.now_ms = now;
 *   Rdnss.option_in(work);
 *   for (i = 0; i < IDEMIP_RDNSS_SERVERS; i++) { IDEMIP_RDNSS_IO(work)->addr_args.index = i;
 *                                                Rdnss.get(work); ... }
 *
 * @c work is IDEMIP_RDNSS_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. sec 6.1 keys an entry's refresh on
 * "the same interface", and sec 5.3.2 warns that "different DNS information ... provided on different
 * network interfaces ... can lead to inconsistent behavior", so the borrow IS the interface and two
 * interfaces share not one byte.
 *
 * Nothing here writes into the resolver's borrow. The list is walked with @ref RdnssNs::get and each
 * entry handed to dns.h's set_server, in slot order, which is the order sec 6.2 requires: "position
 * the first RDNSS address in the RDNSS option as the first one in the Resolver Repository, the second
 * RDNSS address in the option as the second one in the repository, and so on."
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * A borrow is refused until @ref RdnssNs::clear has run on it: clear zeroes the context and the table
 * and leaves the mark that says these bytes are this module's. It does not touch the operand block.
 *
 * Nothing here blocks. A full list evicts rather than refusing, so no entry reports IDEMIP_BUSY but
 * the tick, which reports it when no Expiration-time was reached. A null borrow, a null option, a
 * length shorter than the option's own header and a slot that holds nothing report IDEMIP_ERR. An
 * option sec 5.3.1 says to discard is not a fault: the call reports IDEMIP_OK with
 * @ref RdnssIo::ignored set.
 *
 * @var RdnssNs::clear     zero the context and the list, and mark the borrow cleared
 * @var RdnssNs::option_in one RDNSS option, through sec 6.2 steps (a) to (d)
 * @var RdnssNs::get       report the entry at @ref RdnssAddrArgs::index, so a caller walks the list
 * @var RdnssNs::find      report the entry holding an address
 * @var RdnssNs::remove    delete one entry, as sec 6.2 step (b) does on a zero Lifetime
 * @var RdnssNs::tick      delete the entry whose Expiration-time has been reached, one per call, and
 *                         report IDEMIP_BUSY when none has
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const option_in)(uint8_t *restrict work);
    void (*const get)(uint8_t *restrict work);
    void (*const find)(uint8_t *restrict work);
    void (*const remove)(uint8_t *restrict work);
    void (*const tick)(uint8_t *restrict work);
} RdnssNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_rdnss_clear(uint8_t *restrict work);
void idemip_rdnss_option_in(uint8_t *restrict work);
void idemip_rdnss_get(uint8_t *restrict work);
void idemip_rdnss_find(uint8_t *restrict work);
void idemip_rdnss_remove(uint8_t *restrict work);
void idemip_rdnss_tick(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Rdnss.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const RdnssNs Rdnss IDEMIP_UNUSED = {
    .clear = idemip_rdnss_clear,
    .option_in = idemip_rdnss_option_in,
    .get = idemip_rdnss_get,
    .find = idemip_rdnss_find,
    .remove = idemip_rdnss_remove,
    .tick = idemip_rdnss_tick};
// Every slot index counts the entries the borrow holds, so IDEMIP_RDNSS_NONE names none of them.
static_assert(IDEMIP_RDNSS_SERVERS < IDEMIP_RDNSS_NONE,
              "the list is wider than the index a result member carries");

// sec 5.1: the minimum Length of 3 covers the Type, Length, Reserved and Lifetime fields and one
// 16-octet address.
static_assert(IDEMIP_RDNSS_OPT_LEN_MIN * IDEMIP_RDNSS_OPT_UNIT == IDEMIP_RDNSS_OPT_OFF_ADDRS + IDEMIP_IP6_ADDR_LEN,
              "RFC 8106 sec 5.1: Length 3 is the header and exactly one address");

// sec 5.1: "Every additional RDNSS address increases the length by 2", so one address is two units.
static_assert(IDEMIP_IP6_ADDR_LEN == 2u * IDEMIP_RDNSS_OPT_UNIT,
              "RFC 8106 sec 5.1: one RDNSS address is two Length units");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_RDNSS_H
