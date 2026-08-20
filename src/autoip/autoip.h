// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file autoip.h
 * @brief IPv4 Link-Local addressing, RFC 3927: draw an address out of 169.254/16, claim it, and draw
 *        another when it turns out to be taken.
 *
 * One address on one interface, so the borrow IS the interface and two interfaces are two borrows.
 * RFC 3927 sec 2.1 selects the address, sec 2.2 claims it, and sec 2.5 watches it while it is in use.
 *
 * The probing, announcing and defending is acd.h's: RFC 5227 carries the same PROBE_WAIT, PROBE_NUM,
 * PROBE_MIN, PROBE_MAX, ANNOUNCE_WAIT, ANNOUNCE_NUM, ANNOUNCE_INTERVAL, MAX_CONFLICTS,
 * RATE_LIMIT_INTERVAL and DEFEND_INTERVAL that RFC 3927 sec 9 prints, and the two documents state the
 * probe and announcement packets identically. So this unit selects and holds the address, and the acd
 * borrow runs the machine over it.
 */

#ifndef IDEMIP_AUTOIP_H
#define IDEMIP_AUTOIP_H

#include "src/acd/acd.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/**
 * @brief The mask a link-local address is configured with.
 *
 * RFC 3927 sec 2.1 registers "The IPv4 prefix 169.254/16" and sec 2.8 fixes its length: "The
 * 169.254/16 address prefix MUST NOT be subnetted." So the prefix length is the mask.
 */
#define IDEMIP_AUTOIP_NETMASK 0xFFFF0000u

/**
 * @brief The broadcast address of the link-local prefix.
 *
 * RFC 3927 sec 2.6.2: "the address 169.254.255.255, which is the broadcast address for the Link-Local
 * prefix".
 */
#define IDEMIP_AUTOIP_BROADCAST 0xA9FEFFFFu

/**
 * @brief Where this interface is over its link-local address.
 *
 * RFC 3927 names no states. It names the phases these follow: sec 2.2 "a host MUST test to see if the
 * IPv4 Link-Local address is already in use before beginning to use it", and sec 2.4, after which
 * "the host MUST then announce its claimed address" and may use it.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_AUTOIP_STATE_OFF = 0,  ///< no address selected, which is what clear leaves
    IDEMIP_AUTOIP_STATE_CHECKING, ///< sec 2.2, the selected address is being claimed through acd
    IDEMIP_AUTOIP_STATE_BOUND,    ///< sec 2.4, the address is announced and in use
} IdemIpAutoIpState;

/**
 * @brief What start takes: what the address is drawn from, and when.
 *
 * RFC 3927 sec 2.1: "If the host has access to persistent information that is different for each
 * host, such as its IEEE 802 MAC address, then the pseudo-random number generator SHOULD be seeded
 * using a value derived from this information", and "Seeding the pseudo-random number generator using
 * the real-time clock or any other information which is (or may be) identical in every host is NOT
 * suitable for this purpose".
 *
 * @var AutoIpStartArgs::mac    this interface's 48-bit address, IDEMIP_ARP_HLN_ETHERNET octets, the
 *                              per-host value the draw is seeded from
 * @var AutoIpStartArgs::rand   a random word the draw over the sec 2.1 range is taken from
 * @var AutoIpStartArgs::now_ms the millisecond clock a deadline is stamped from
 */
typedef struct
{
    const uint8_t *mac;
    uint32_t rand;
    uint32_t now_ms;
} AutoIpStartArgs;

/**
 * @brief What a reported conflict takes.
 *
 * RFC 3927 sec 2.2.1: on a conflict the host "MUST select a new pseudo-random address and repeat the
 * process", and once "the number of conflicts exceeds MAX_CONFLICTS then the host MUST limit the rate
 * at which it probes for new addresses to no more than one new address per RATE_LIMIT_INTERVAL".
 *
 * @var AutoIpConflictArgs::rand   a random word the next address is drawn from
 * @var AutoIpConflictArgs::now_ms the millisecond clock the next attempt is timed from
 */
typedef struct
{
    uint32_t rand;
    uint32_t now_ms;
} AutoIpConflictArgs;

/** @brief What a sweep takes: the millisecond clock every deadline is compared against. */
typedef struct
{
    uint32_t now_ms;
    uint32_t rand;
} AutoIpTickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var AutoIpIo::start_args    what the first draw is seeded from
 * @var AutoIpIo::conflict_args what the next draw is taken from
 * @var AutoIpIo::tick_args     the clock a sweep fires deadlines against
 * @var AutoIpIo::status        what the call reports: OK, BUSY, or ERR
 * @var AutoIpIo::ipaddr        the selected address, out of the sec 2.1 range
 * @var AutoIpIo::netmask       IDEMIP_AUTOIP_NETMASK once the address is bound, zero before
 * @var AutoIpIo::deadline_ms   when the next attempt is due, sec 2.2.1's RATE_LIMIT_INTERVAL apart
 * @var AutoIpIo::state         where this interface is over its address
 * @var AutoIpIo::tried         addresses drawn on this interface so far
 * @var AutoIpIo::claim         the caller hands @ref AutoIpIo::ipaddr to Acd.start, which is the
 *                              sec 2.2 test "before beginning to use it"
 */
typedef struct
{
    AutoIpStartArgs start_args;
    AutoIpConflictArgs conflict_args;
    AutoIpTickArgs tick_args;

    uint32_t ipaddr;
    uint32_t netmask;
    uint32_t deadline_ms;
    IdemIpStatus status;
    IdemIpAutoIpState state;
    uint8_t tried;
    idemip_bool claim;
} AutoIpIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only the
// map is public.
//
// This unit holds no table, so IDEMIP_AUTOIP_CTX_BYTES is the whole borrow and covers the operand
// block and the context together, the way IDEMIP_PHY_BORROW covers both.

#define IDEMIP_AUTOIP_OFF_IO 0u ///< the operand and result block
#define IDEMIP_AUTOIP_OFF_CTX (IDEMIP_AUTOIP_OFF_IO + IDEMIP_ROUND_UP(sizeof(AutoIpIo), IDEMIP_ALIGN))
#define IDEMIP_AUTOIP_OFF_END (IDEMIP_AUTOIP_OFF_IO + IDEMIP_AUTOIP_CTX_BYTES)

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_AUTOIP_IO(w) ((AutoIpIo *)(void *)((w) + IDEMIP_AUTOIP_OFF_IO))

/**
 * @brief The link-local address of one interface.
 *
 *   AutoIp.clear(work);
 *   IDEMIP_AUTOIP_IO(work)->start_args.mac = link_mac;
 *   IDEMIP_AUTOIP_IO(work)->start_args.rand = seed;
 *   AutoIp.start(work);
 *   if (IDEMIP_AUTOIP_IO(work)->claim) { ... Acd.start(acd_work) ... }
 *
 * @c work is IDEMIP_AUTOIP_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the interface, so two
 * interfaces are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * A borrow is refused until @ref AutoIpNs::clear has run on it: clear zeroes the context and leaves
 * the mark that says these bytes are this module's. It does not touch the operand block.
 *
 * Nothing here blocks. An attempt held back by sec 2.2.1's RATE_LIMIT_INTERVAL reports IDEMIP_BUSY,
 * since the same call on a later tick makes progress. A bad argument, an uncleared borrow or the
 * wrong state reports IDEMIP_ERR.
 *
 * @var AutoIpNs::clear    zero the context and mark the borrow cleared
 * @var AutoIpNs::start    draw an address out of the sec 2.1 range and hand it to acd to claim
 * @var AutoIpNs::conflict acd found the address taken: sec 2.2.1 draws another and repeats
 * @var AutoIpNs::bound    acd announced the address: sec 2.4 puts it in use with the /16 mask
 * @var AutoIpNs::stop     give up the address, leaving no link-local address on the interface
 * @var AutoIpNs::tick     release the sec 2.2.1 rate limit once RATE_LIMIT_INTERVAL has passed
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const start)(uint8_t *restrict work);
    void (*const conflict)(uint8_t *restrict work);
    void (*const bound)(uint8_t *restrict work);
    void (*const stop)(uint8_t *restrict work);
    void (*const tick)(uint8_t *restrict work);
} AutoIpNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_autoip_clear(uint8_t *restrict work);
void idemip_autoip_start(uint8_t *restrict work);
void idemip_autoip_conflict(uint8_t *restrict work);
void idemip_autoip_bound(uint8_t *restrict work);
void idemip_autoip_stop(uint8_t *restrict work);
void idemip_autoip_tick(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `AutoIp.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const AutoIpNs AutoIp IDEMIP_UNUSED = {
    .clear = idemip_autoip_clear,
    .start = idemip_autoip_start,
    .conflict = idemip_autoip_conflict,
    .bound = idemip_autoip_bound,
    .stop = idemip_autoip_stop,
    .tick = idemip_autoip_tick};
// RFC 3927 sec 2.1: "a uniform distribution in the range from 169.254.1.0 to 169.254.254.255
// inclusive", and "The first 256 and last 256 addresses in the 169.254/16 prefix are reserved for
// future use and MUST NOT be selected by a host using this dynamic configuration mechanism."
static_assert(IDEMIP_AUTOIP_FIRST == IDEMIP_AUTOIP_PREFIX + 256u,
              "RFC 3927 sec 2.1 reserves the first 256 addresses of 169.254/16");
static_assert(IDEMIP_AUTOIP_LAST == IDEMIP_AUTOIP_PREFIX + 0xFFFFu - 256u,
              "RFC 3927 sec 2.1 reserves the last 256 addresses of 169.254/16");
static_assert(IDEMIP_AUTOIP_LAST - IDEMIP_AUTOIP_FIRST + 1u == 254u * 256u,
              "RFC 3927 sec 2.1: 169.254.1.0 through 169.254.254.255 is 254 * 256 addresses");

// sec 2.8 forbids subnetting the prefix, so the mask covers exactly the 16 prefix bits and the prefix
// itself has no host bits set.
static_assert((IDEMIP_AUTOIP_PREFIX & IDEMIP_AUTOIP_NETMASK) == IDEMIP_AUTOIP_PREFIX,
              "IDEMIP_AUTOIP_NETMASK must cover the whole 169.254/16 prefix (RFC 3927 sec 2.8)");
static_assert(IDEMIP_AUTOIP_BROADCAST == (IDEMIP_AUTOIP_PREFIX | ~IDEMIP_AUTOIP_NETMASK),
              "RFC 3927 sec 2.6.2: 169.254.255.255 is the broadcast address of the link-local prefix");

// sec 2.2.1 counts conflicts against MAX_CONFLICTS, and the count of addresses drawn is one octet.
static_assert(IDEMIP_ACD_MAX_CONFLICTS <= 0xFFu, "the count of drawn addresses is one octet");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_AUTOIP_H
