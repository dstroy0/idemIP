// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ethip6.h
 * @brief IPv6 over Ethernet, RFC 2464: the three addresses this link layer derives.
 *
 * sec 7 maps a multicast destination onto an Ethernet multicast address, sec 4 derives the
 * interface identifier from the built-in 48-bit address, and sec 5 appends that identifier to
 * FE80::/64. Every entry reads the caller's octets and writes its answer into the operand block;
 * nothing here holds an address or touches a frame.
 *
 * The Ethernet II framing RFC 2464 sec 3 shares with RFC 894, and the 86DD type code, are
 * ethernet.h's.
 */

#ifndef IDEMIP_ETHIP6_H
#define IDEMIP_ETHIP6_H

#include "src/ethernet/ethernet.h"
#include "src/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// sec 2, the link's MTU
// ---------------------------------------------------------------------------

/** @brief RFC 2464 sec 2: "The default MTU size for IPv6 packets on an Ethernet is 1500 octets." */
#define IDEMIP_ETHIP6_MTU 1500u

// ---------------------------------------------------------------------------
// sec 4, the interface identifier
// ---------------------------------------------------------------------------

/**
 * @brief Octets the interface identifier spans.
 *
 * RFC 2464 sec 8: "the Interface Identifier, which is 64 bits in length and based on the EUI-64
 * format", the sec 5 figure drawing those 64 bits behind the prefix.
 */
#define IDEMIP_ETHIP6_IID_LEN 8u

/**
 * @brief Octets of the Ethernet address that become the company_id (RFC 2464 sec 4).
 *
 * "The OUI of the Ethernet address (the first three octets) becomes the company_id of the EUI-64
 * (the first three octets)."
 */
#define IDEMIP_ETHIP6_OUI_LEN 3u

/**
 * @brief The two octets RFC 2464 sec 4 inserts in the middle of the EUI-64.
 *
 * "The fourth and fifth octets of the EUI are set to the fixed value FFFE hexadecimal."
 */
#define IDEMIP_ETHIP6_EUI64_FF 0xFFu
#define IDEMIP_ETHIP6_EUI64_FE 0xFEu

/** @brief Where those two octets sit in the identifier (RFC 2464 sec 4, "fourth and fifth"). */
#define IDEMIP_ETHIP6_OFF_FFFE IDEMIP_ETHIP6_OUI_LEN

/** @brief Octets of the Ethernet address that follow them (RFC 2464 sec 4, "the last three"). */
#define IDEMIP_ETHIP6_TAIL_LEN 3u

/**
 * @brief The bit RFC 2464 sec 4 complements: "the 'Universal/Local' (U/L) bit, which is the
 * next-to-lowest order bit of the first octet of the EUI-64".
 *
 * RFC 4291 sec 2.5.1 draws that octet as `cccc ccug` in Internet standard bit order, so the U/L bit
 * carries the value 2 and the individual/group bit the value 1.
 */
#define IDEMIP_ETHIP6_UL_BIT 0x02u

// ---------------------------------------------------------------------------
// sec 5, the link-local address
// ---------------------------------------------------------------------------

/**
 * @brief The two leading octets of the FE80::/64 prefix (RFC 2464 sec 5).
 *
 * The sec 5 figure prints 1111111010 then 54 zeros, which RFC 4291 sec 2.5.6 draws identically.
 */
#define IDEMIP_ETHIP6_LINKLOCAL_0 0xFEu
#define IDEMIP_ETHIP6_LINKLOCAL_1 0x80u

/** @brief Octets the prefix spans: RFC 2464 sec 5 appends the identifier to FE80::/64. */
#define IDEMIP_ETHIP6_LINKLOCAL_PREFIX_LEN 8u

// ---------------------------------------------------------------------------
// sec 7, the multicast address mapping
// ---------------------------------------------------------------------------

/**
 * @brief The first two octets of the mapped Ethernet address (RFC 2464 sec 7).
 *
 * "is transmitted to the Ethernet multicast address whose first two octets are the value 3333
 * hexadecimal".
 */
#define IDEMIP_ETHIP6_MCAST_0 0x33u
#define IDEMIP_ETHIP6_MCAST_1 0x33u

/** @brief Octets of the prefix those two make. */
#define IDEMIP_ETHIP6_MCAST_PREFIX_LEN 2u

/**
 * @brief Octets of DST the mapping carries (RFC 2464 sec 7).
 *
 * "whose last four octets are the last four octets of DST", which the sec 7 figure names DST[13]
 * through DST[16].
 */
#define IDEMIP_ETHIP6_MCAST_TAIL_LEN 4u

/**
 * @brief RFC 4291 sec 2.7: "binary 11111111 at the start of the address identifies the address as
 * being a multicast address."
 */
#define IDEMIP_ETHIP6_MULTICAST_PREFIX 0xFFu

// ---------------------------------------------------------------------------
// What a call takes
// ---------------------------------------------------------------------------

/**
 * @brief What the sec 7 mapping takes.
 *
 * @var Ethip6MulticastArgs::dst the multicast destination address DST, IDEMIP_IP6_ADDR_LEN octets
 */
typedef struct
{
    const uint8_t *dst;
} Ethip6MulticastArgs;

/**
 * @brief What the sec 4 and sec 5 derivations take.
 *
 * RFC 2464 sec 4 derives from "the interface's built-in 48-bit IEEE 802 address", and adds "A
 * different MAC address set manually or by software should not be used to derive the Interface
 * Identifier. If such a MAC address must be used, its global uniqueness property should be
 * reflected in the value of the U/L bit."
 *
 * @var Ethip6MacArgs::mac the built-in 48-bit address, IDEMIP_MAC_LEN octets
 */
typedef struct
{
    const uint8_t *mac;
} Ethip6MacArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Ethip6Io::multicast_args the sec 7 destination address
 * @var Ethip6Io::mac_args       the sec 4 built-in address
 * @var Ethip6Io::status         what the call reports: OK or ERR
 * @var Ethip6Io::mac            what the sec 7 mapping wrote, IDEMIP_MAC_LEN octets
 * @var Ethip6Io::iid            what the sec 4 derivation wrote, IDEMIP_ETHIP6_IID_LEN octets
 * @var Ethip6Io::addr           what the sec 5 derivation wrote, IDEMIP_IP6_ADDR_LEN octets
 * @var Ethip6Io::universal      the built-in address carried a zero U/L bit, which RFC 2464 sec 4
 *                               calls "a universally administered IEEE 802 address" and which
 *                               becomes a one in @ref Ethip6Io::iid
 */
typedef struct
{
    Ethip6MulticastArgs multicast_args;
    Ethip6MacArgs mac_args;

    IdemIpStatus status;
    uint8_t mac[IDEMIP_MAC_LEN];
    uint8_t iid[IDEMIP_ETHIP6_IID_LEN];
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    idemip_bool universal;
} Ethip6Io;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only
// the map is public.

#define IDEMIP_ETHIP6_OFF_IO 0u ///< the operand and result block
#define IDEMIP_ETHIP6_OFF_CTX (IDEMIP_ETHIP6_OFF_IO + IDEMIP_ROUND_UP(sizeof(Ethip6Io), IDEMIP_ALIGN))
#define IDEMIP_ETHIP6_OFF_END (IDEMIP_ETHIP6_OFF_IO + IDEMIP_ETHIP6_CTX_BYTES)

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_ETHIP6_IO(w) ((Ethip6Io *)(void *)((w) + IDEMIP_ETHIP6_OFF_IO))

/**
 * @brief The RFC 2464 address derivations.
 *
 *   Ethip6.clear(work);
 *   IDEMIP_ETHIP6_IO(work)->mac_args.mac = hwaddr;
 *   Ethip6.linklocal(work);
 *   if (IDEMIP_ETHIP6_IO(work)->status == IDEMIP_OK) { ... IDEMIP_ETHIP6_IO(work)->addr ... }
 *
 * @c work is IDEMIP_ETHIP6_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. The borrow IS the
 * instance, so two derivations in flight are two borrows and share not one byte.
 *
 * A borrow is refused until @ref Ethip6Ns::clear has run on it: clear zeroes the context region and
 * leaves one nonzero octet in it, the mark that says these bytes are this module's. It does not
 * touch the operand block.
 *
 * Nothing here blocks, and nothing here ever reports IDEMIP_BUSY. Every entry is a function of the
 * octets the caller supplied, so a call that cannot finish now cannot finish on a later tick
 * either: a null borrow, a null address, a borrow no one cleared, and a destination that is not
 * multicast are all IDEMIP_ERR.
 *
 * @var Ethip6Ns::clear         zero the context and mark the borrow cleared
 * @var Ethip6Ns::multicast_map sec 7: 3333 hexadecimal, then the last four octets of DST
 * @var Ethip6Ns::eui64         sec 4: the EUI-64 interface identifier, U/L bit complemented
 * @var Ethip6Ns::linklocal     sec 5: that identifier appended to FE80::/64
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const multicast_map)(uint8_t *restrict work);
    void (*const eui64)(uint8_t *restrict work);
    void (*const linklocal)(uint8_t *restrict work);
} Ethip6Ns;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_ethip6_clear(uint8_t *restrict work);
void idemip_ethip6_multicast_map(uint8_t *restrict work);
void idemip_ethip6_eui64(uint8_t *restrict work);
void idemip_ethip6_linklocal(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Ethip6.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Ethip6Ns Ethip6 IDEMIP_UNUSED = {
    .clear = idemip_ethip6_clear,
    .multicast_map = idemip_ethip6_multicast_map,
    .eui64 = idemip_ethip6_eui64,
    .linklocal = idemip_ethip6_linklocal};
// RFC 2464 sec 7 fills a 48-bit Ethernet address with a two-octet prefix and four octets of DST.
static_assert(IDEMIP_ETHIP6_MCAST_PREFIX_LEN + IDEMIP_ETHIP6_MCAST_TAIL_LEN == IDEMIP_MAC_LEN,
              "the RFC 2464 sec 7 mapping must fill a 48-bit Ethernet address");

// RFC 2464 sec 4 builds the identifier from the OUI, the fixed FFFE, and the last three octets.
static_assert(IDEMIP_ETHIP6_OUI_LEN + 2u + IDEMIP_ETHIP6_TAIL_LEN == IDEMIP_ETHIP6_IID_LEN,
              "the RFC 2464 sec 4 fields must sum to the 64-bit interface identifier");

// The OUI and the last three octets together are the whole 48-bit address sec 4 reads.
static_assert(IDEMIP_ETHIP6_OUI_LEN + IDEMIP_ETHIP6_TAIL_LEN == IDEMIP_MAC_LEN,
              "the RFC 2464 sec 4 derivation must read every octet of the built-in address");

// RFC 2464 sec 5 appends a 64-bit identifier to a 64-bit prefix, which RFC 4291 sec 2.5.6 draws as
// 10 bits of 1111111010, 54 zero bits, then the interface ID.
static_assert(IDEMIP_ETHIP6_LINKLOCAL_PREFIX_LEN + IDEMIP_ETHIP6_IID_LEN == IDEMIP_IP6_ADDR_LEN,
              "the RFC 2464 sec 5 prefix and identifier must sum to a 128-bit address");

// RFC 2464 sec 2 states the same 1500 octets RFC 894 gives an IPv4 datagram over Ethernet.
static_assert(IDEMIP_ETHIP6_MTU == IDEMIP_ETH_MAX_PAYLOAD,
              "RFC 2464 sec 2 puts the default IPv6 MTU at the RFC 894 maximum data field");

// RFC 8200 sec 5 requires every link to carry 1280 octets.
static_assert(IDEMIP_ETHIP6_MTU >= IDEMIP_IPV6_MIN_MTU,
              "RFC 2464 sec 2's default MTU is short of the RFC 8200 sec 5 minimum link MTU");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_ETHIP6_H
