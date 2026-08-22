// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip6_addr.h
 * @brief What an IPv6 address is: RFC 4291 sec 2, and the zones of RFC 4007.
 *
 * The type identification of RFC 4291 sec 2.4, the multicast scope field of sec 2.7, the
 * solicited-node form of sec 2.7.1, and the zone index RFC 4007 sec 6 qualifies a non-global
 * address with. Addresses are sixteen octets where they lie, the way ipv6.h's idemip_ip6_src and
 * idemip_ip6_dst hand them back.
 *
 * The tests themselves are inline over the caller's bytes, so a unit that already holds a different
 * borrow reads them without taking this one; ip6_select.c does. The namespace below is the same
 * tests reached through a borrow, which is what carries their operands and results.
 *
 * The RFC 6724 comparisons that read these answers are ip6_select.h's. Nothing here sorts anything.
 */

#ifndef IDEMIP_IP6_ADDR_H
#define IDEMIP_IP6_ADDR_H

#include "src/ip/ipv6.h"
#include "src/ip/ipv6_defines.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// Address type identification (RFC 4291 sec 2.4)
// ---------------------------------------------------------------------------
// sec 2.4 prints the whole table:
//
//   Address type         Binary prefix        IPv6 notation   Section
//   Unspecified          00...0  (128 bits)   ::/128          2.5.2
//   Loopback             00...1  (128 bits)   ::1/128         2.5.3
//   Multicast            11111111             FF00::/8        2.7
//   Link-Local unicast   1111111010           FE80::/10       2.5.6
//   Global Unicast       (everything else)

/** @brief RFC 4291 sec 2.7: "binary 11111111 at the start of the address identifies ... multicast". */
#define IDEMIP_IP6_MULTICAST_TAG 0xFFu

/** @brief RFC 4291 sec 2.5.6: the first ten bits of a Link-Local address are 1111111010. */
#define IDEMIP_IP6_LINK_LOCAL_TAG0 0xFEu
#define IDEMIP_IP6_LINK_LOCAL_MASK1 0xC0u
#define IDEMIP_IP6_LINK_LOCAL_TAG1 0x80u

/** @brief RFC 4291 sec 2.5.7: the first ten bits of a Site-Local address are 1111111011. */
#define IDEMIP_IP6_SITE_LOCAL_TAG0 0xFEu
#define IDEMIP_IP6_SITE_LOCAL_MASK1 0xC0u
#define IDEMIP_IP6_SITE_LOCAL_TAG1 0xC0u

/** @brief Octets of leading zeros an address with an embedded IPv4 address carries (sec 2.5.5). */
#define IDEMIP_IP6_V4_EMBED_ZEROS 10u

/** @brief RFC 4291 sec 2.5.5.2: the two octets FFFF that mark an IPv4-mapped address. */
#define IDEMIP_IP6_V4_MAPPED_TAG 0xFFu

/** @brief Where an embedded IPv4 address starts, the low-order 32 bits (sec 2.5.5). */
#define IDEMIP_IP6_V4_EMBED_OFF 12u

/** @brief RFC 4291 sec 2.3 bounds a prefix length at the width of an address. */
#define IDEMIP_IP6_ADDR_BITS 128u

/**
 * @brief What the high-order bits of an address name.
 *
 * RFC 4291 sec 2.5.7 says of the Site-Local prefix that "new implementations must treat this prefix
 * as Global Unicast". It is reported here all the same, because RFC 6724 sec 3.1 keeps a site-local
 * unicast scope in its comparisons: "some existing implementations and deployments may still use
 * these addresses; they are therefore included in the procedures in this specification". A caller
 * that routes treats SITE_LOCAL as global.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP6_TYPE_UNSPECIFIED = 0, ///< ::/128 (sec 2.5.2)
    IDEMIP_IP6_TYPE_LOOPBACK,        ///< ::1/128 (sec 2.5.3)
    IDEMIP_IP6_TYPE_V4_COMPAT,       ///< ::a.b.c.d, deprecated (sec 2.5.5.1)
    IDEMIP_IP6_TYPE_V4_MAPPED,       ///< ::FFFF:a.b.c.d (sec 2.5.5.2)
    IDEMIP_IP6_TYPE_LINK_LOCAL,      ///< FE80::/10 (sec 2.5.6)
    IDEMIP_IP6_TYPE_SITE_LOCAL,      ///< FEC0::/10, deprecated (sec 2.5.7)
    IDEMIP_IP6_TYPE_MULTICAST,       ///< FF00::/8 (sec 2.7)
    IDEMIP_IP6_TYPE_GLOBAL,          ///< everything else (sec 2.4)
} IdemIpIp6Type;

// ---------------------------------------------------------------------------
// Multicast flags and scope (RFC 4291 sec 2.7)
// ---------------------------------------------------------------------------
// sec 2.7 draws the address as 8 bits of ones, a 4-bit flgs, a 4-bit scop, then 112 bits of group
// ID, so both nibbles come out of the second octet.

#define IDEMIP_IP6_MCAST_FLAGS_SHIFT 4u
#define IDEMIP_IP6_MCAST_FLAGS_MASK 0x0Fu
#define IDEMIP_IP6_MCAST_SCOP_MASK 0x0Fu

/** @brief sec 2.7: "flgs is a set of 4 flags: |0|R|P|T|". */
#define IDEMIP_IP6_MCAST_FLAG_T 0x1u ///< 1 is "transient", 0 is "permanently-assigned"
#define IDEMIP_IP6_MCAST_FLAG_P 0x2u ///< "The P flag's definition and usage can be found in [RFC3306]"
#define IDEMIP_IP6_MCAST_FLAG_R 0x4u ///< "The R flag's definition and usage can be found in [RFC3956]"
#define IDEMIP_IP6_MCAST_FLAG_RESERVED 0x8u ///< "The high-order flag is reserved, and must be initialized to 0"

/**
 * @brief The scope values RFC 4291 sec 2.7 lists for the scop field.
 *
 * RFC 4007 sec 4 gives unicast two of them: "Link-local scope" and "Global scope", with "The IPv6
 * unicast loopback address, ::1 ... treated as having link-local scope". RFC 6724 sec 3.1 maps the
 * rest: "We map unicast link-local to multicast link-local, unicast site-local to multicast
 * site-local, and unicast global scope to multicast global scope."
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP6_SCOPE_RESERVED = 0x0, ///< "0 reserved"
    IDEMIP_IP6_SCOPE_INTERFACE_LOCAL = 0x1,
    IDEMIP_IP6_SCOPE_LINK_LOCAL = 0x2,
    IDEMIP_IP6_SCOPE_ADMIN_LOCAL = 0x4,
    IDEMIP_IP6_SCOPE_SITE_LOCAL = 0x5,
    IDEMIP_IP6_SCOPE_ORG_LOCAL = 0x8,  ///< "8 Organization-Local scope"
    IDEMIP_IP6_SCOPE_GLOBAL = 0xE,
    IDEMIP_IP6_SCOPE_RESERVED_F = 0xF, ///< "F reserved"
} IdemIpIp6Scope;

// ---------------------------------------------------------------------------
// The solicited-node address (RFC 4291 sec 2.7.1)
// ---------------------------------------------------------------------------

/**
 * @brief Octets of the prefix a solicited-node address is built on.
 *
 * RFC 4291 sec 2.7.1: "A Solicited-Node multicast address is formed by taking the low-order 24 bits
 * of an address (unicast or anycast) and appending those bits to the prefix
 * FF02:0:0:0:0:1:FF00::/104".
 */
#define IDEMIP_IP6_SOLICITED_PREFIX_LEN 104u
#define IDEMIP_IP6_SOLICITED_PREFIX_BYTES 13u
#define IDEMIP_IP6_SOLICITED_SUFFIX_BYTES 3u

// ---------------------------------------------------------------------------
// Zones (RFC 4007 sec 5, sec 6)
// ---------------------------------------------------------------------------

/**
 * @brief RFC 4007 sec 6: "the index value zero at each scope SHOULD be reserved to mean 'use the
 * default zone'."
 */
#define IDEMIP_IP6_ZONE_DEFAULT 0u

// ---------------------------------------------------------------------------
// The tests, over the caller's bytes
// ---------------------------------------------------------------------------
// Inline and stateless, the way ipv6.h's accessors are. The namespace below is these reached
// through a borrow; nothing implements one of them twice.

/** @brief True when the leading @p n octets are zero, which sec 2.5.2, 2.5.3 and 2.5.5 all key on. */
IDEMIP_INLINE idemip_bool idemip_ip6_addr_leading_zero(const uint8_t *addr, size_t n)
{
    return idemip_bytes_zero(addr, n);
}

/**
 * @brief Which row of the RFC 4291 sec 2.4 table an address falls in.
 *
 * Longest tag first. The ten leading zero octets of sec 2.5.5 cover the unspecified address, the
 * loopback address and both embedded-IPv4 forms, so those four are split apart inside that branch:
 * sec 2.5.2's all-zero address and sec 2.5.3's ::1 both also match sec 2.5.5.1's shape and are taken
 * before it.
 */
IDEMIP_INLINE IdemIpIp6Type idemip_ip6_addr_type(const uint8_t *addr)
{
    if (addr[0] == IDEMIP_IP6_MULTICAST_TAG)
    {
        return IDEMIP_IP6_TYPE_MULTICAST;
    }
    if (addr[0] == IDEMIP_IP6_LINK_LOCAL_TAG0 &&
        (uint8_t)(addr[1] & IDEMIP_IP6_LINK_LOCAL_MASK1) == IDEMIP_IP6_LINK_LOCAL_TAG1)
    {
        return IDEMIP_IP6_TYPE_LINK_LOCAL;
    }
    if (addr[0] == IDEMIP_IP6_SITE_LOCAL_TAG0 &&
        (uint8_t)(addr[1] & IDEMIP_IP6_SITE_LOCAL_MASK1) == IDEMIP_IP6_SITE_LOCAL_TAG1)
    {
        return IDEMIP_IP6_TYPE_SITE_LOCAL;
    }
    if (idemip_ip6_addr_leading_zero(addr, IDEMIP_IP6_V4_EMBED_ZEROS))
    {
        if (addr[10] == IDEMIP_IP6_V4_MAPPED_TAG && addr[11] == IDEMIP_IP6_V4_MAPPED_TAG)
        {
            return IDEMIP_IP6_TYPE_V4_MAPPED;
        }
        if (addr[10] == 0u && addr[11] == 0u)
        {
            if (idemip_ip6_addr_leading_zero(addr + IDEMIP_IP6_V4_EMBED_OFF, 3u) && addr[15] == 1u)
            {
                return IDEMIP_IP6_TYPE_LOOPBACK;
            }
            if (idemip_ip6_addr_leading_zero(addr + IDEMIP_IP6_V4_EMBED_OFF, 4u))
            {
                return IDEMIP_IP6_TYPE_UNSPECIFIED;
            }
            return IDEMIP_IP6_TYPE_V4_COMPAT;
        }
    }
    return IDEMIP_IP6_TYPE_GLOBAL;
}

/**
 * @brief The scope of an address whose type is already known.
 *
 * RFC 4291 sec 2.7 puts scop in the low nibble of the second octet, for a multicast address.
 * RFC 4007 sec 4 gives unicast link-local and global, and puts ::1 in link-local; RFC 6724 sec 3.1
 * maps unicast site-local onto multicast site-local. The unspecified address "does not have any
 * scope" (RFC 4007 sec 4), which is the reserved value here.
 */
IDEMIP_INLINE IdemIpIp6Scope idemip_ip6_addr_scope_of(const uint8_t *addr, IdemIpIp6Type type)
{
    switch (type)
    {
    case IDEMIP_IP6_TYPE_MULTICAST:
    {
        // RFC 4291 sec 2.7: "Nodes should not originate a packet to a multicast address whose scop
        // field contains the reserved value F; if such a packet is sent or received, it must be
        // treated the same as packets destined to a global (scop E) multicast address."
        uint8_t scop = (uint8_t)(addr[1] & IDEMIP_IP6_MCAST_SCOP_MASK);
        return (scop == (uint8_t)IDEMIP_IP6_SCOPE_RESERVED_F) ? IDEMIP_IP6_SCOPE_GLOBAL : (IdemIpIp6Scope)scop;
    }
    case IDEMIP_IP6_TYPE_LINK_LOCAL:
    case IDEMIP_IP6_TYPE_LOOPBACK:
        return IDEMIP_IP6_SCOPE_LINK_LOCAL;
    case IDEMIP_IP6_TYPE_SITE_LOCAL:
        return IDEMIP_IP6_SCOPE_SITE_LOCAL;
    case IDEMIP_IP6_TYPE_UNSPECIFIED:
        return IDEMIP_IP6_SCOPE_RESERVED;
    default:
        return IDEMIP_IP6_SCOPE_GLOBAL;
    }
}

/** @brief The scope of an address, its type derived first. */
IDEMIP_INLINE IdemIpIp6Scope idemip_ip6_addr_scope(const uint8_t *addr)
{
    return idemip_ip6_addr_scope_of(addr, idemip_ip6_addr_type(addr));
}

/** @brief The sec 2.7 flgs nibble of a multicast address, and zero for anything else. */
IDEMIP_INLINE uint8_t idemip_ip6_addr_mcast_flags(const uint8_t *addr)
{
    return (addr[0] == IDEMIP_IP6_MULTICAST_TAG)
               ? (uint8_t)((addr[1] >> IDEMIP_IP6_MCAST_FLAGS_SHIFT) & IDEMIP_IP6_MCAST_FLAGS_MASK)
               : 0u;
}

/**
 * @brief True when two addresses agree over their first @p len bits.
 *
 * (len >> 3) whole octets compare exactly, and the remaining (len & 7) bits compare under a mask of
 * that many leading bits, which is the longest prefix match RFC 4291 sec 2.3 writes.
 */
IDEMIP_INLINE idemip_bool idemip_ip6_addr_prefix_eq(const uint8_t *a, const uint8_t *b, uint8_t len)
{
    size_t whole = (size_t)(len >> 3);
    uint8_t bits = (uint8_t)(len & 7u);
    if (whole != 0u && !idemip_bytes_eq(a, b, whole))
    {
        return IDEMIP_FALSE;
    }
    if (bits != 0u)
    {
        uint8_t mask = (uint8_t)(0xFFu << (8u - bits));
        if ((uint8_t)((a[whole] ^ b[whole]) & mask) != 0u)
        {
            return IDEMIP_FALSE;
        }
    }
    return IDEMIP_TRUE;
}

/**
 * @brief Write the RFC 4291 sec 2.7.1 solicited-node address of @p addr into @p out.
 *
 * The prefix FF02:0:0:0:0:1:FF00::/104 is thirteen octets, and the low-order 24 bits of @p addr are
 * the three that follow.
 */
IDEMIP_INLINE void idemip_ip6_addr_solicited(uint8_t *out, const uint8_t *addr)
{
    memset(out, 0, IDEMIP_IP6_ADDR_LEN);
    out[0] = 0xFFu;
    out[1] = 0x02u;
    out[11] = 0x01u;
    out[12] = 0xFFu;
    out[13] = addr[13];
    out[14] = addr[14];
    out[15] = addr[15];
}

/**
 * @brief True for either address RFC 4291 sec 2.7.1 lists under "All Nodes Addresses".
 *
 * sec 2.7.1: "FF01:0:0:0:0:0:0:1 FF02:0:0:0:0:0:0:1. The above multicast addresses identify the
 * group of all IPv6 nodes, within scope 1 (interface-local) or 2 (link-local)." sec 2.8 puts both
 * on the list "a host is required to recognize ... as identifying itself", so neither needs a group
 * table entry to be this host's, the way a solicited-node address does not.
 */
IDEMIP_INLINE idemip_bool idemip_ip6_addr_is_all_nodes(const uint8_t *addr)
{
    if (addr[0] != IDEMIP_IP6_MULTICAST_TAG || idemip_ip6_addr_mcast_flags(addr) != 0u)
    {
        return IDEMIP_FALSE;
    }
    uint8_t scope = addr[1] & IDEMIP_IP6_MCAST_SCOP_MASK;
    if (scope != IDEMIP_IP6_SCOPE_INTERFACE_LOCAL && scope != IDEMIP_IP6_SCOPE_LINK_LOCAL)
    {
        return IDEMIP_FALSE;
    }
    return (idemip_ip6_addr_leading_zero(addr + 2u, IDEMIP_IP6_ADDR_LEN - 3u) &&
            addr[IDEMIP_IP6_ADDR_LEN - 1u] == 0x01u)
               ? IDEMIP_TRUE
               : IDEMIP_FALSE;
}

// ---------------------------------------------------------------------------
// Operands
// ---------------------------------------------------------------------------

/** @brief What a classify takes. */
typedef struct
{
    const uint8_t *addr; ///< IDEMIP_IP6_ADDR_LEN octets
} Ip6AddrClassifyArgs;

/** @brief What the RFC 4291 sec 2.7.1 form takes. */
typedef struct
{
    const uint8_t *addr; ///< the unicast or anycast address whose low-order 24 bits are taken
} Ip6AddrSolicitedArgs;

/**
 * @brief What a zone derivation takes (RFC 4007 sec 5, sec 6).
 *
 * @var Ip6AddrZoneArgs::addr  IDEMIP_IP6_ADDR_LEN octets
 * @var Ip6AddrZoneArgs::netif the index of the interface the address is used on, which sec 6's
 *                             default assignment makes both the interface index and the link index
 */
typedef struct
{
    const uint8_t *addr;
    uint8_t netif;
} Ip6AddrZoneArgs;

/**
 * @brief What a scoped comparison takes (RFC 4007 sec 5, sec 6).
 *
 * @var Ip6AddrMatchArgs::a          the first address, IDEMIP_IP6_ADDR_LEN octets
 * @var Ip6AddrMatchArgs::b          the second
 * @var Ip6AddrMatchArgs::a_zone     the first address's zone index, or IDEMIP_IP6_ZONE_DEFAULT
 * @var Ip6AddrMatchArgs::b_zone     the second's
 * @var Ip6AddrMatchArgs::prefix_len leading bits @ref Ip6AddrIo::prefix_equal compares, "from 0 to
 *                                   128" as RFC 4291 sec 2.3 writes a prefix
 */
typedef struct
{
    const uint8_t *a;
    const uint8_t *b;
    uint32_t a_zone;
    uint32_t b_zone;
    uint8_t prefix_len;
} Ip6AddrMatchArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Ip6AddrIo::classify_args  the address a classify reads
 * @var Ip6AddrIo::solicited_args the address the sec 2.7.1 form is taken from
 * @var Ip6AddrIo::zone_args      the address and interface a zone derivation reads
 * @var Ip6AddrIo::match_args     the two addresses and their zones a comparison reads
 * @var Ip6AddrIo::status         what the call reports: OK or ERR
 * @var Ip6AddrIo::zone           the zone index sec 6 gives the address on that interface
 * @var Ip6AddrIo::solicited      the sixteen octets of the sec 2.7.1 address
 * @var Ip6AddrIo::type           which row of the sec 2.4 table the address falls in
 * @var Ip6AddrIo::scope          its scope, the scop field for multicast and the RFC 6724 sec 3.1
 *                                mapping for unicast
 * @var Ip6AddrIo::flags          the sec 2.7 flgs nibble, zero for a unicast address
 * @var Ip6AddrIo::equal          the two addresses name the same interface in the same zone
 * @var Ip6AddrIo::prefix_equal   they agree over @ref Ip6AddrMatchArgs::prefix_len leading bits
 * @var Ip6AddrIo::zone_derived   the zone was derived rather than left at the default, which sec 5
 *                                requires of every scope between link-local and global
 */
typedef struct
{
    Ip6AddrClassifyArgs classify_args;
    Ip6AddrSolicitedArgs solicited_args;
    Ip6AddrZoneArgs zone_args;
    Ip6AddrMatchArgs match_args;

    IdemIpStatus status;
    uint32_t zone;
    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    IdemIpIp6Type type;
    IdemIpIp6Scope scope;
    uint8_t flags;
    idemip_bool equal;
    idemip_bool prefix_equal;
    idemip_bool zone_derived;
} Ip6AddrIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. This unit holds no table, so the map is the
// operand block and the context behind it, and IDEMIP_IP6_ADDR_CTX_BYTES spans both.

#define IDEMIP_IP6_ADDR_OFF_IO 0u ///< the operand and result block
#define IDEMIP_IP6_ADDR_OFF_CTX (IDEMIP_IP6_ADDR_OFF_IO + IDEMIP_ROUND_UP(sizeof(Ip6AddrIo), IDEMIP_ALIGN))
#define IDEMIP_IP6_ADDR_OFF_END (IDEMIP_IP6_ADDR_OFF_IO + IDEMIP_IP6_ADDR_CTX_BYTES)

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IP6_ADDR_IO(w) ((Ip6AddrIo *)(void *)((w) + IDEMIP_IP6_ADDR_OFF_IO))

/**
 * @brief What an IPv6 address is, RFC 4291 sec 2, in the zone RFC 4007 sec 6 qualifies it with.
 *
 *   Ip6Addr.clear(work);
 *   IDEMIP_IP6_ADDR_IO(work)->classify_args.addr = idemip_ip6_dst(hdr);
 *   Ip6Addr.classify(work);
 *   if (IDEMIP_IP6_ADDR_IO(work)->type == IDEMIP_IP6_TYPE_MULTICAST) { ... }
 *
 * @c work is IDEMIP_IP6_ADDR_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. The borrow IS the
 * instance, so two callers are two borrows and share not one byte.
 *
 * A borrow is refused until @ref Ip6AddrNs::clear has run on it: clear zeroes the context and
 * leaves one nonzero octet in it, the mark that says these bytes are this module's.
 *
 * Nothing here blocks and nothing here defers, so no entry ever reports IDEMIP_BUSY: every answer
 * is a function of the operands alone and is available on the call that asks for it. A null borrow,
 * a borrow no clear has run on, a null address, an address with no solicited-node form and a prefix
 * longer than 128 bits report IDEMIP_ERR, none of which a retry changes.
 *
 * @var Ip6AddrNs::clear     zero the context and mark the borrow cleared
 * @var Ip6AddrNs::classify  the sec 2.4 type, the sec 2.7 flags and the scope of one address
 * @var Ip6AddrNs::solicited the sec 2.7.1 solicited-node address of one unicast or anycast address
 * @var Ip6AddrNs::zone      the sec 6 zone index one address takes on one interface
 * @var Ip6AddrNs::match     whether two addresses name the same interface, zones included
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const classify)(uint8_t *work);
    void (*const solicited)(uint8_t *work);
    void (*const zone)(uint8_t *work);
    void (*const match)(uint8_t *work);
} Ip6AddrNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_ip6_addr_clear(uint8_t *work);
void idemip_ip6_addr_classify(uint8_t *work);
void idemip_ip6_addr_solicited_io(uint8_t *work);
void idemip_ip6_addr_zone(uint8_t *work);
void idemip_ip6_addr_match(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Ip6Addr.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Ip6AddrNs Ip6Addr IDEMIP_UNUSED = {
    .clear = idemip_ip6_addr_clear,
    .classify = idemip_ip6_addr_classify,
    .solicited = idemip_ip6_addr_solicited_io,
    .zone = idemip_ip6_addr_zone,
    .match = idemip_ip6_addr_match};
// RFC 4291 sec 2.7.1 appends 24 bits to a 104-bit prefix, and the two fill an address.
static_assert(IDEMIP_IP6_SOLICITED_PREFIX_BYTES + IDEMIP_IP6_SOLICITED_SUFFIX_BYTES == IDEMIP_IP6_ADDR_LEN,
              "the RFC 4291 sec 2.7.1 prefix and its 24 bits must fill an address");
static_assert(IDEMIP_IP6_SOLICITED_PREFIX_LEN == (IDEMIP_IP6_SOLICITED_PREFIX_BYTES << 3),
              "FF02:0:0:0:0:1:FF00::/104 is thirteen whole octets (RFC 4291 sec 2.7.1)");

// sec 2.7 splits the second octet into flgs and scop, and the two fill it.
static_assert(((IDEMIP_IP6_MCAST_FLAGS_MASK << IDEMIP_IP6_MCAST_FLAGS_SHIFT) | IDEMIP_IP6_MCAST_SCOP_MASK) == 0xFFu,
              "flgs and scop must fill the octet below the FF tag (RFC 4291 sec 2.7)");
static_assert((IDEMIP_IP6_MCAST_FLAG_T | IDEMIP_IP6_MCAST_FLAG_P | IDEMIP_IP6_MCAST_FLAG_R |
               IDEMIP_IP6_MCAST_FLAG_RESERVED) == IDEMIP_IP6_MCAST_FLAGS_MASK,
              "the four sec 2.7 flags must fill flgs");

// sec 2.5.6 and sec 2.5.7 share ten bits, differing in the tenth.
static_assert(IDEMIP_IP6_LINK_LOCAL_TAG0 == IDEMIP_IP6_SITE_LOCAL_TAG0 &&
                  IDEMIP_IP6_LINK_LOCAL_TAG1 != IDEMIP_IP6_SITE_LOCAL_TAG1,
              "FE80::/10 and FEC0::/10 differ only in the tenth bit (RFC 4291 sec 2.5.6, sec 2.5.7)");

// sec 2.5.5 puts the embedded IPv4 address in "the low-order 32 bits of the address".
static_assert(IDEMIP_IP6_V4_EMBED_OFF + 4u == IDEMIP_IP6_ADDR_LEN,
              "an embedded IPv4 address is the low-order 32 bits (RFC 4291 sec 2.5.5)");
static_assert(IDEMIP_IP6_ADDR_BITS == (IDEMIP_IP6_ADDR_LEN << 3), "an address is 128 bits (RFC 4291 sec 2)");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_IP6_ADDR_H
