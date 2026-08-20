// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pmtu4.h
 * @brief Path MTU Discovery for IPv4, RFC 1191: what a Datagram Too Big says the path now carries.
 *
 * RFC 1191 sec 2 names the message: a router that cannot forward a datagram "will discard them and
 * return ICMP Destination Unreachable messages with a code meaning 'fragmentation needed and DF
 * set'", which the memo calls "a Datagram Too Big message". sec 4 puts the constricting hop's MTU
 * "in the low-order 16 bits of the ICMP header field that is labelled 'unused'", and sec 3 makes a
 * zero there the mark of a router that predates the field: "A Datagram Too Big message from an
 * unmodified router can be recognized by the presence of a zero in the (newly-defined) Next-Hop MTU
 * field."
 *
 * With that zero, sec 5's search runs instead: "use as the next PMTU estimate the greatest plateau
 * value that is less than the returned Total Length field", over Table 7-1 of sec 7, which this
 * module carries verbatim.
 *
 * The estimate itself lives in the routing table, sec 6.2: "The obvious place to store this
 * association is as a field in the routing table entries", which is ip4_route's row and its
 * @ref Ip4RouteNs::set_pmtu. Nothing here holds one, and nothing here calls that unit: an entry
 * decides and reports, and the caller writes the row.
 */

#ifndef IDEMIP_PMTU4_H
#define IDEMIP_PMTU4_H

#include "src/icmp/icmp.h"    // the RFC 792 message this reads, and through it ipv4.h
#include "src/ip/ip4_route.h" // the row RFC 1191 sec 6.2 caches the estimate in

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/**
 * @brief The Next-Hop MTU field, RFC 1191 sec 4.
 *
 * "the router MUST include the MTU of that next-hop network in the low-order 16 bits of the ICMP
 * header field that is labelled 'unused' in the ICMP specification. The high-order 16 bits remain
 * unused, and MUST be set to zero." That field is icmp.h's IDEMIP_ICMP_OFF_UNUSED, so the low half
 * of it starts two octets in.
 */
#define IDEMIP_PMTU4_OFF_NEXT_HOP_MTU (IDEMIP_ICMP_OFF_UNUSED + 2u)

/** @brief Octets a Datagram Too Big spans through the quoted internet header. */
#define IDEMIP_PMTU4_MSG_MIN (IDEMIP_ICMP_OFF_QUOTE + IDEMIP_IPV4_HDR_LEN)

/**
 * @brief What too_big takes.
 *
 * @var Pmtu4TooBigArgs::msg  the ICMP message, from its Type octet
 * @var Pmtu4TooBigArgs::len  octets of it, quote included
 * @var Pmtu4TooBigArgs::held the estimate the routing table holds for this path now, which
 *                            @ref Ip4RouteNs::lookup reports in @ref Ip4RouteIo::pmtu. Zero when the
 *                            row carries none, which sec 6.3 calls the "reserved" state, "indicating
 *                            that the PMTU has never been changed". sec 6.2 initializes such a row
 *                            to "the MTU of the associated first-hop data link", so a caller holding
 *                            that MTU passes it here rather than zero, and sec 5's correction of the
 *                            quoted Total Length then has the estimate it compares against.
 * @var Pmtu4TooBigArgs::first_hop_mtu the MTU of the associated first-hop data link, which sec 6.2
 *                            initializes a row with no estimate to. It stands in for
 *                            @ref Pmtu4TooBigArgs::held when that is zero, so sec 3's non-increase
 *                            rule has a ceiling on a path no message has been seen for yet.
 */
typedef struct
{
    const uint8_t *msg;
    size_t len;
    uint16_t held;
    uint16_t first_hop_mtu;
} Pmtu4TooBigArgs;

/**
 * @brief What a plateau search takes (RFC 1191 sec 5, sec 7.1).
 *
 * @var Pmtu4PlateauArgs::size          the length a plateau is sought below, or the estimate one is
 *                                      sought above
 * @var Pmtu4PlateauArgs::first_hop_mtu the ceiling sec 7.1 puts on a raise, "the next-highest value
 *                                      in the plateau table (or the first-hop MTU, if that is
 *                                      smaller)". Zero leaves the raise unbounded.
 */
typedef struct
{
    uint16_t size;
    uint16_t first_hop_mtu;
} Pmtu4PlateauArgs;

/**
 * @brief What age takes: one routing table row's RFC 1191 sec 6.3 pair, and its first hop.
 *
 * sec 6.3 keeps "a timestamp field to the routing table entry... Whenever the PMTU is decreased in
 * response to a Datagram Too Big message, the timestamp is set to the current time", which is
 * ip4_route's own @c pmtu and @c pmtu_ms.
 *
 * @var Pmtu4AgeArgs::stamp_ms      the millisecond the estimate was last decreased
 * @var Pmtu4AgeArgs::raise_ms      the millisecond the last successful increase was attempted at,
 *                                  which sec 3 measures its second minimum interval from, "or less
 *                                  than 1 minute after a previous, successful attempted increase".
 *                                  Zero names a row that has never been raised.
 * @var Pmtu4AgeArgs::pmtu          the estimate the row holds, zero for sec 6.3's "reserved"
 * @var Pmtu4AgeArgs::first_hop_mtu the MTU of the associated first hop
 */
typedef struct
{
    uint32_t stamp_ms;
    uint32_t raise_ms;
    uint16_t pmtu;
    uint16_t first_hop_mtu;
} Pmtu4AgeArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Pmtu4Io::too_big_args the message a Datagram Too Big arrived in
 * @var Pmtu4Io::plateau_args the length a Table 7-1 search runs from
 * @var Pmtu4Io::age_args     one routing row's estimate, its timestamp and its first hop
 * @var Pmtu4Io::now_ms       the millisecond clock the caller read before the call, which sec 6.3
 *                            compares its timestamps against
 * @var Pmtu4Io::dst          the path: the Destination Address of the quoted datagram, sec 6.2
 * @var Pmtu4Io::mtu          the estimate the call reports, which the caller writes through
 *                            @ref Ip4RouteNs::set_pmtu
 * @var Pmtu4Io::total_len    the quoted Total Length, corrected by sec 5's Note where that applied
 * @var Pmtu4Io::next_hop_mtu the sec 4 field as it arrived, zero for a message sec 3 calls old-style
 * @var Pmtu4Io::status       what the call reports: OK, BUSY, or ERR
 * @var Pmtu4Io::tos          the quoted Type of Service, sec 6.2's third component of a path
 * @var Pmtu4Io::decreased    the estimate is below what @ref Pmtu4TooBigArgs::held carried, which is
 *                            the only case sec 3 lets a Datagram Too Big change
 * @var Pmtu4Io::old_style    the sec 4 field read zero, so the sec 5 plateau search ran
 */
typedef struct
{
    Pmtu4TooBigArgs too_big_args;
    Pmtu4PlateauArgs plateau_args;
    Pmtu4AgeArgs age_args;

    uint32_t now_ms;
    uint32_t dst;
    uint16_t mtu;
    uint16_t total_len;
    uint16_t next_hop_mtu;
    IdemIpStatus status;
    uint8_t tos;
    idemip_bool decreased;
    idemip_bool old_style;
} Pmtu4Io;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The estimate is the routing table's, so
// this borrow carries only the operand block and the mark clear leaves.

#define IDEMIP_PMTU4_OFF_IO 0u ///< the operand and result block
#define IDEMIP_PMTU4_OFF_CTX (IDEMIP_PMTU4_OFF_IO + IDEMIP_ROUND_UP(sizeof(Pmtu4Io), IDEMIP_ALIGN))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_PMTU4_IO(w) ((Pmtu4Io *)(void *)((w) + IDEMIP_PMTU4_OFF_IO))

/**
 * @brief RFC 1191 Path MTU Discovery over IPv4.
 *
 *   Pmtu4.clear(work);
 *   IDEMIP_PMTU4_IO(work)->too_big_args.msg = icmp;
 *   IDEMIP_PMTU4_IO(work)->too_big_args.len = icmp_len;
 *   IDEMIP_PMTU4_IO(work)->too_big_args.held = IDEMIP_IP4_ROUTE_IO(route)->pmtu;
 *   Pmtu4.too_big(work);
 *   if (IDEMIP_PMTU4_IO(work)->status == IDEMIP_OK && IDEMIP_PMTU4_IO(work)->decreased)
 *   {
 *       IDEMIP_IP4_ROUTE_IO(route)->pmtu_args.dst = IDEMIP_PMTU4_IO(work)->dst;
 *       IDEMIP_IP4_ROUTE_IO(route)->pmtu_args.mtu = IDEMIP_PMTU4_IO(work)->mtu;
 *       Ip4Route.set_pmtu(route);
 *   }
 *
 * @c work is IDEMIP_PMTU4_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the discovery
 * process, so two of them share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick. A borrow that clear has not run on is refused.
 *
 * @var Pmtu4Ns::clear         mark the borrow usable
 * @var Pmtu4Ns::too_big       read a Datagram Too Big and report the estimate for its path: the sec
 *                             4 Next-Hop MTU where the router filled it, the sec 5 plateau search
 *                             where it read zero. A message that is not Type 3 Code 4, that is short
 *                             of its quoted header, or that reports a next-hop MTU below the 68
 *                             octets sec 4 states the field never falls under, is ERR.
 * @var Pmtu4Ns::plateau_below the greatest Table 7-1 plateau strictly under
 *                             @ref Pmtu4PlateauArgs::size, which is sec 5's search. A size at or
 *                             under the lowest plateau is ERR: no plateau lies below it.
 * @var Pmtu4Ns::plateau_above the next Table 7-1 plateau strictly over that size, bounded by
 *                             @ref Pmtu4PlateauArgs::first_hop_mtu, which is sec 7.1's raise. A size
 *                             already at that bound or at the top of the table is ERR.
 * @var Pmtu4Ns::age           sec 6.3's aging, over one row: an estimate that has not been decreased
 *                             for IDEMIP_PMTU4_INCREASE_MS is raised, by sec 7.1's step, toward the
 *                             first hop's MTU. BUSY while the row carries no estimate, while that
 *                             interval has not elapsed, and once the estimate has reached the first
 *                             hop: each is a state a later Datagram Too Big or a later tick changes.
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const too_big)(uint8_t *restrict work);
    void (*const plateau_below)(uint8_t *restrict work);
    void (*const plateau_above)(uint8_t *restrict work);
    void (*const age)(uint8_t *restrict work);
} Pmtu4Ns;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_pmtu4_clear(uint8_t *restrict work);
void idemip_pmtu4_too_big(uint8_t *restrict work);
void idemip_pmtu4_plateau_below(uint8_t *restrict work);
void idemip_pmtu4_plateau_above(uint8_t *restrict work);
void idemip_pmtu4_age(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Pmtu4.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Pmtu4Ns Pmtu4 IDEMIP_UNUSED = {
    .clear = idemip_pmtu4_clear,
    .too_big = idemip_pmtu4_too_big,
    .plateau_below = idemip_pmtu4_plateau_below,
    .plateau_above = idemip_pmtu4_plateau_above,
    .age = idemip_pmtu4_age};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_PMTU4_H
