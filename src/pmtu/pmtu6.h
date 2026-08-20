// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pmtu6.h
 * @brief Path MTU Discovery for IPv6, RFC 8201: what a Packet Too Big says the path now carries.
 *
 * RFC 8201 sec 3: "If any of the packets sent on that path are too large to be forwarded by some
 * node along the path, that node will discard them and return ICMPv6 Packet Too Big messages. Upon
 * receipt of such a message, the source node reduces its assumed PMTU for the path based on the MTU
 * of the constricting hop as reported in the Packet Too Big message." The message is RFC 4443 sec
 * 3.2's Type 2, whose 32-bit MTU field is "The Maximum Transmission Unit of the next-hop link" and
 * whose Code is "Set to 0 (zero) by the originator and ignored by the receiver".
 *
 * sec 4 bounds it twice: "If a node receives a Packet Too Big message reporting a next-hop MTU that
 * is less than the IPv6 minimum link MTU, it must discard it. A node must not reduce its estimate of
 * the Path MTU below the IPv6 minimum link MTU on receipt of a Packet Too Big message", and "A node
 * must not increase its estimate of the Path MTU in response to the contents of a Packet Too Big
 * message." The minimum link MTU is RFC 8200 sec 5's 1280 octets, common.h's IDEMIP_IPV6_MIN_MTU.
 *
 * No plateau table appears here. RFC 8201 Appendix A, on what RFC 1191 carries that this does not:
 * "MTU plateau tables  not needed because there are no old-style messages."
 *
 * The estimate itself lives in the Destination Cache, sec 5.2: "a PMTU value could be stored with
 * the corresponding entry in the destination cache", which is nd6's row and its
 * @ref Nd6Ns::dest_set. Nothing here holds one, and nothing here calls that unit: an entry decides
 * and reports, and the caller writes the row.
 *
 * What this borrow does hold is the clock sec 5.3 ages by, one stamp per path: "When a PMTU value
 * has not been decreased for a while (on the order of 10 minutes), it should probe to find if a
 * larger PMTU is supported." The nd6 Destination Cache row carries the estimate and no timestamp
 * for it, so the millisecond of the last decrease is kept here, keyed on the same address.
 *
 * sec 4 also asks that "Nodes should appropriately validate the payload of ICMPv6 PTB messages to
 * ensure these are received in response to transmitted traffic". That check reads the sender's own
 * connection state and is the caller's; what arrives here is already known to be a message this
 * node solicited.
 */

#ifndef IDEMIP_PMTU6_H
#define IDEMIP_PMTU6_H

#include "src/icmp/icmpv6.h" // the RFC 4443 sec 3.2 message this reads, and through it ipv6.h
#include "src/nd/nd6.h"      // the Destination Cache RFC 8201 sec 5.2 caches the estimate in

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/** @brief No stamp. Every index result reads this when no path matched. */
#define IDEMIP_PMTU6_NONE 0xFFu

/**
 * @brief Segments Left, RFC 8200 sec 4.4.
 *
 * The Routing header runs Next Header, Hdr Ext Len, Routing Type, then "Segments Left  8-bit
 * unsigned integer. Number of route segments remaining". RFC 8201 sec 5.2 reads it to find the path
 * a Packet Too Big names: "If Segments Left is equal to zero, the destination address is in the
 * Destination Address field in the IPv6 header. If Segments Left is greater than zero, the
 * destination address is the last address (Address[n]) in the Routing header."
 */
#define IDEMIP_PMTU6_RH_OFF_SEGMENTS_LEFT 3u

/** @brief Octets a Packet Too Big spans through the quoted IPv6 header. */
#define IDEMIP_PMTU6_MSG_MIN (IDEMIP_ICMP6_ERR_HDR_LEN + IDEMIP_IPV6_HDR_LEN)

/**
 * @brief What too_big takes.
 *
 * @var Pmtu6TooBigArgs::msg  the ICMPv6 message, from its Type octet
 * @var Pmtu6TooBigArgs::len  octets of it, the invoking packet included
 * @var Pmtu6TooBigArgs::held the estimate the Destination Cache holds for this path now, which
 *                            @ref Nd6Ns::dest_find reports in @ref Nd6Io::pmtu. Zero when the row
 *                            carries none, sec 5.2 taking the PMTU of a path to be "the (known) MTU
 *                            of the first-hop link" until a message lowers it.
 * @var Pmtu6TooBigArgs::link_mtu the MTU of that first-hop link, which stands in for
 *                            @ref Pmtu6TooBigArgs::held when the row carries none, so sec 4's
 *                            non-increase rule has a ceiling on a path no message has named yet.
 */
typedef struct
{
    const uint8_t *msg;
    size_t len;
    uint16_t held;
    uint16_t link_mtu;
} Pmtu6TooBigArgs;

/**
 * @brief What forget takes: the path whose stamp goes.
 *
 * @var Pmtu6PathArgs::dst the destination, IDEMIP_IP6_ADDR_LEN octets
 */
typedef struct
{
    const uint8_t *dst;
} Pmtu6PathArgs;

/**
 * @brief What a probe sweep takes.
 *
 * @var Pmtu6ProbeArgs::link_mtu the first-hop link's MTU, which sec 5.2 makes the initial estimate
 *                               of every path and which sec 5.3's probe rises back to
 */
typedef struct
{
    uint16_t link_mtu;
} Pmtu6ProbeArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Pmtu6Io::too_big_args the message a Packet Too Big arrived in
 * @var Pmtu6Io::path_args    the path forget drops
 * @var Pmtu6Io::probe_args   the link MTU a due path is probed at
 * @var Pmtu6Io::now_ms       the millisecond clock the caller read before the call, which every
 *                            stamp is written from and every sec 5.3 interval is measured against
 * @var Pmtu6Io::dst          the path the call names, IDEMIP_IP6_ADDR_LEN octets where they lie:
 *                            inside the caller's message after too_big, inside this borrow after a
 *                            sweep, where they stand until another call writes that stamp
 * @var Pmtu6Io::reported_mtu the RFC 4443 sec 3.2 MTU field as it arrived, all 32 bits of it
 * @var Pmtu6Io::mtu          the estimate the call reports, which the caller writes through
 *                            @ref Nd6Ns::dest_set
 * @var Pmtu6Io::status       what the call reports: OK, BUSY, or ERR
 * @var Pmtu6Io::index        the stamp the call touched, or IDEMIP_PMTU6_NONE
 * @var Pmtu6Io::decreased    the estimate is below what @ref Pmtu6TooBigArgs::held carried, which is
 *                            the only case sec 4 lets a Packet Too Big change
 * @var Pmtu6Io::probe        a sweep found this path due for the larger-PMTU probe of sec 5.3
 */
typedef struct
{
    Pmtu6TooBigArgs too_big_args;
    Pmtu6PathArgs path_args;
    Pmtu6ProbeArgs probe_args;

    uint32_t now_ms;
    const uint8_t *dst;
    uint32_t reported_mtu;
    uint16_t mtu;
    IdemIpStatus status;
    uint8_t index;
    idemip_bool decreased;
    idemip_bool probe;
} Pmtu6Io;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. IDEMIP_PMTU6_CTX_BYTES spans the operand
// block and the context together, so the stamp table starts at a constant no growth in either moves.

#define IDEMIP_PMTU6_OFF_IO 0u ///< the operand and result block
#define IDEMIP_PMTU6_OFF_CTX (IDEMIP_PMTU6_OFF_IO + IDEMIP_ROUND_UP(sizeof(Pmtu6Io), IDEMIP_ALIGN))
#define IDEMIP_PMTU6_OFF_STAMPS (IDEMIP_PMTU6_OFF_IO + IDEMIP_PMTU6_CTX_BYTES)
#define IDEMIP_PMTU6_OFF_END (IDEMIP_PMTU6_OFF_STAMPS + (IDEMIP_PMTU6_PATHS << IDEMIP_PMTU6_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_PMTU6_IO(w) ((Pmtu6Io *)(void *)((w) + IDEMIP_PMTU6_OFF_IO))

// A stamp index is one octet, so a count at or above the terminator is unaddressable.
static_assert(IDEMIP_PMTU6_PATHS < IDEMIP_PMTU6_NONE,
              "IDEMIP_PMTU6_PATHS must stay below IDEMIP_PMTU6_NONE: a stamp index is one octet");

/**
 * @brief RFC 8201 Path MTU Discovery over IPv6.
 *
 *   Pmtu6.clear(work);
 *   IDEMIP_PMTU6_IO(work)->too_big_args.msg = icmp6;
 *   IDEMIP_PMTU6_IO(work)->too_big_args.len = icmp6_len;
 *   IDEMIP_PMTU6_IO(work)->too_big_args.held = IDEMIP_ND6_IO(nd)->pmtu;
 *   IDEMIP_PMTU6_IO(work)->now_ms = now;
 *   Pmtu6.too_big(work);
 *   if (IDEMIP_PMTU6_IO(work)->status == IDEMIP_OK && IDEMIP_PMTU6_IO(work)->decreased)
 *   {
 *       IDEMIP_ND6_IO(nd)->dest_args.dst = IDEMIP_PMTU6_IO(work)->dst;
 *       IDEMIP_ND6_IO(nd)->dest_args.pmtu = IDEMIP_PMTU6_IO(work)->mtu;
 *       Nd6.dest_set(nd);
 *   }
 *
 * @c work is IDEMIP_PMTU6_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. sec 5.2: "For nodes with multiple
 * interfaces, Path MTU information should be maintained for each IPv6 link", so the borrow IS the
 * interface and the caller takes IDEMIP_NETIF_COUNT of them; two interfaces share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick. A borrow that clear has not run on is refused.
 *
 * @var Pmtu6Ns::clear   zero the context and the stamps, and mark the borrow usable
 * @var Pmtu6Ns::too_big read a Packet Too Big and report the estimate for the path its invoking
 *                       packet names, stamping that path with @ref Pmtu6Io::now_ms when the estimate
 *                       fell. A message that is not Type 2, one short of its invoking IPv6 header,
 *                       and one reporting an MTU under the IPv6 minimum link MTU, which sec 4 says
 *                       "it must discard", are ERR.
 * @var Pmtu6Ns::tick    sec 5.3's aging: report one path whose estimate has not been decreased for
 *                       IDEMIP_PMTU6_PROBE_MS, and drop its stamp so it is reported once. BUSY when
 *                       no path is due, which a later tick or a later Packet Too Big changes.
 * @var Pmtu6Ns::forget  drop a path's stamp, as the caller does when its Destination Cache entry
 *                       goes. A path carrying no stamp is ERR.
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const too_big)(uint8_t *restrict work);
    void (*const tick)(uint8_t *restrict work);
    void (*const forget)(uint8_t *restrict work);
} Pmtu6Ns;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_pmtu6_clear(uint8_t *restrict work);
void idemip_pmtu6_too_big(uint8_t *restrict work);
void idemip_pmtu6_tick(uint8_t *restrict work);
void idemip_pmtu6_forget(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Pmtu6.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Pmtu6Ns Pmtu6 IDEMIP_UNUSED = {
    .clear = idemip_pmtu6_clear,
    .too_big = idemip_pmtu6_too_big,
    .tick = idemip_pmtu6_tick,
    .forget = idemip_pmtu6_forget};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_PMTU6_H
