// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_addr.h
 * @brief What an IPv4 address is, RFC 791 sec 3.2 and RFC 1122 sec 3.2.1.3, and its Ethernet map.
 *
 * Three answers: which of the five classes an address falls in, which special case of RFC 1122
 * sec 3.2.1.3 it is, and how a class D group maps onto an Ethernet multicast address by RFC 1112
 * sec 6.4. A netmask test reports the network, the directed broadcast and the host part of one
 * address against one subnet.
 *
 * Nothing here reads a packet. The operands are addresses in host order, the way ipv4.h's
 * idemip_ip4_src and idemip_ip4_dst hand them back.
 */

#ifndef IDEMIP_IP4_ADDR_H
#define IDEMIP_IP4_ADDR_H

#include "src/ethernet/ethernet.h" // IDEMIP_MAC_LEN, the address RFC 1112 sec 6.4 maps onto
#include "src/ip/ipv4.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// The classes (RFC 791 sec 3.2, RFC 1122 sec 3.2.1.3)
// ---------------------------------------------------------------------------
// RFC 791 sec 3.2 "Address Formats" prints the first three and an escape:
//
//   High Order Bits   Format                           Class
//         0            7 bits of net, 24 bits of host    a
//         10          14 bits of net, 16 bits of host    b
//         110         21 bits of net,  8 bits of host    c
//         111         escape to extended addressing mode
//
// RFC 1122 sec 3.2.1.3 splits that escape: "There are now five classes of IP addresses: Class A
// through Class E. Class D addresses are used for IP multicasting, while Class E addresses are
// reserved for experimental use."

#define IDEMIP_IP4_CLASS_A_MASK 0x80000000u ///< 0
#define IDEMIP_IP4_CLASS_A_TAG 0x00000000u
#define IDEMIP_IP4_CLASS_B_MASK 0xC0000000u ///< 10
#define IDEMIP_IP4_CLASS_B_TAG 0x80000000u
#define IDEMIP_IP4_CLASS_C_MASK 0xE0000000u ///< 110
#define IDEMIP_IP4_CLASS_C_TAG 0xC0000000u
#define IDEMIP_IP4_CLASS_D_MASK 0xF0000000u ///< 1110 (RFC 1112 sec 4)
#define IDEMIP_IP4_CLASS_D_TAG 0xE0000000u
#define IDEMIP_IP4_CLASS_E_MASK 0xF0000000u ///< 1111 (RFC 1112 sec 4)
#define IDEMIP_IP4_CLASS_E_TAG 0xF0000000u

/** @brief Which of the five classes the high-order bits name. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP4_CLASS_A = 0, ///< 0, "7 bits of net, 24 bits of host"
    IDEMIP_IP4_CLASS_B,     ///< 10, "14 bits of net, 16 bits of host"
    IDEMIP_IP4_CLASS_C,     ///< 110, "21 bits of net, 8 bits of host"
    IDEMIP_IP4_CLASS_D,     ///< 1110, the host group addresses of RFC 1112 sec 4
    IDEMIP_IP4_CLASS_E,     ///< 1111, "reserved for future addressing modes" (RFC 1112 sec 4)
} IdemIpIp4Class;

// ---------------------------------------------------------------------------
// The special cases (RFC 1122 sec 3.2.1.3, RFC 3927 sec 2.1)
// ---------------------------------------------------------------------------

/** @brief RFC 1122 sec 3.2.1.3 case (g): "{ 127, <any> } Internal host loopback address." */
#define IDEMIP_IP4_LOOPBACK_MASK 0xFF000000u
#define IDEMIP_IP4_LOOPBACK_TAG 0x7F000000u

/**
 * @brief RFC 3927 sec 2.1: "The IPv4 prefix 169.254/16 is registered with the IANA for this
 * purpose."
 */
#define IDEMIP_IP4_LINK_LOCAL_MASK 0xFFFF0000u
#define IDEMIP_IP4_LINK_LOCAL_TAG 0xA9FE0000u

/**
 * @brief RFC 1122 sec 3.2.1.3 case (c): "{ -1, -1 } Limited broadcast."
 *
 * RFC 919 sec 7: "The address 255.255.255.255 denotes a broadcast on a local hardware network,
 * which must not be forwarded."
 */
#define IDEMIP_IP4_BROADCAST 0xFFFFFFFFu

/** @brief RFC 1122 sec 3.2.1.3 case (a): "{ 0, 0 } This host on this network." */
#define IDEMIP_IP4_ANY 0x00000000u

/** @brief The network field of cases (a) and (b), "A value of zero ... means this network" (RFC 791 sec 3.2). */
#define IDEMIP_IP4_THIS_NET_MASK 0xFF000000u
#define IDEMIP_IP4_THIS_NET_TAG 0x00000000u

/**
 * @brief What an address is, once the special cases of RFC 1122 sec 3.2.1.3 are taken out.
 *
 * The limited broadcast is tested before the classes, since 255.255.255.255 also carries class E's
 * high-order bits, and 127/8 and 169.254/16 before them, since both sit inside class A and class B
 * unicast space.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_IP4_TYPE_UNSPECIFIED = 0, ///< 0.0.0.0, case (a) "{ 0, 0 }"
    IDEMIP_IP4_TYPE_THIS_NETWORK,    ///< 0/8 with a host part, case (b) "{ 0, <Host-number> }"
    IDEMIP_IP4_TYPE_LOOPBACK,        ///< 127/8, case (g) "{ 127, <any> }"
    IDEMIP_IP4_TYPE_LINK_LOCAL,      ///< 169.254/16 (RFC 3927 sec 2.1)
    IDEMIP_IP4_TYPE_MULTICAST,       ///< 224/4, a class D host group (RFC 1112 sec 4)
    IDEMIP_IP4_TYPE_RESERVED,        ///< 240/4, class E (RFC 1112 sec 4)
    IDEMIP_IP4_TYPE_BROADCAST,       ///< 255.255.255.255, case (c) "{ -1, -1 }"
    IDEMIP_IP4_TYPE_UNICAST,         ///< everything else
} IdemIpIp4AddrType;

// ---------------------------------------------------------------------------
// The Ethernet multicast map (RFC 1112 sec 6.4)
// ---------------------------------------------------------------------------

/**
 * @brief The three fixed octets a group address is placed into.
 *
 * RFC 1112 sec 6.4: "An IP host group address is mapped to an Ethernet multicast address by placing
 * the low-order 23-bits of the IP address into the low-order 23 bits of the Ethernet multicast
 * address 01-00-5E-00-00-00 (hex)."
 */
#define IDEMIP_IP4_MCAST_MAC_0 0x01u
#define IDEMIP_IP4_MCAST_MAC_1 0x00u
#define IDEMIP_IP4_MCAST_MAC_2 0x5Eu

/** @brief The low-order 23 bits sec 6.4 carries across, the 24th staying zero. */
#define IDEMIP_IP4_MCAST_MAC_MASK 0x007FFFFFu

/**
 * @brief RFC 1112 sec 6.4: "Because there are 28 significant bits in an IP host group address, more
 * than one host group address may map to the same Ethernet multicast address."
 */
#define IDEMIP_IP4_MCAST_GROUP_BITS 28u

// ---------------------------------------------------------------------------
// The tests, over the caller's addresses
// ---------------------------------------------------------------------------
// Inline and stateless, the way ipv4.h's accessors are. The namespace below is these reached
// through a borrow; nothing implements one of them twice.

/** @brief True when the address carries @p tag everywhere @p mask is set. */
IDEMIP_INLINE idemip_bool idemip_ip4_addr_tagged(uint32_t addr, uint32_t mask, uint32_t tag)
{
    return ((addr & mask) == tag) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

/**
 * @brief Which class the high-order bits name (RFC 791 sec 3.2, RFC 1122 sec 3.2.1.3).
 *
 * Tested longest tag first, so 1110 is taken before the 110 and 10 tags can match.
 */
IDEMIP_INLINE IdemIpIp4Class idemip_ip4_addr_class(uint32_t addr)
{
    if (idemip_ip4_addr_tagged(addr, IDEMIP_IP4_CLASS_A_MASK, IDEMIP_IP4_CLASS_A_TAG))
    {
        return IDEMIP_IP4_CLASS_A;
    }
    if (idemip_ip4_addr_tagged(addr, IDEMIP_IP4_CLASS_B_MASK, IDEMIP_IP4_CLASS_B_TAG))
    {
        return IDEMIP_IP4_CLASS_B;
    }
    if (idemip_ip4_addr_tagged(addr, IDEMIP_IP4_CLASS_C_MASK, IDEMIP_IP4_CLASS_C_TAG))
    {
        return IDEMIP_IP4_CLASS_C;
    }
    if (idemip_ip4_addr_tagged(addr, IDEMIP_IP4_CLASS_D_MASK, IDEMIP_IP4_CLASS_D_TAG))
    {
        return IDEMIP_IP4_CLASS_D;
    }
    return IDEMIP_IP4_CLASS_E;
}

/** @brief True for a class D host group address (RFC 1112 sec 4). */
IDEMIP_INLINE idemip_bool idemip_ip4_addr_is_mcast(uint32_t addr)
{
    return idemip_ip4_addr_tagged(addr, IDEMIP_IP4_CLASS_D_MASK, IDEMIP_IP4_CLASS_D_TAG);
}

/**
 * @brief Which special case of RFC 1122 sec 3.2.1.3 an address is.
 *
 * The limited broadcast is taken first because 255.255.255.255 also carries class E's high-order
 * bits, and 127/8 and 169.254/16 before the classes because both sit inside unicast space.
 */
IDEMIP_INLINE IdemIpIp4AddrType idemip_ip4_addr_type(uint32_t addr)
{
    if (addr == IDEMIP_IP4_BROADCAST)
    {
        return IDEMIP_IP4_TYPE_BROADCAST;
    }
    if (addr == IDEMIP_IP4_ANY)
    {
        return IDEMIP_IP4_TYPE_UNSPECIFIED;
    }
    if (idemip_ip4_addr_tagged(addr, IDEMIP_IP4_THIS_NET_MASK, IDEMIP_IP4_THIS_NET_TAG))
    {
        return IDEMIP_IP4_TYPE_THIS_NETWORK;
    }
    if (idemip_ip4_addr_tagged(addr, IDEMIP_IP4_LOOPBACK_MASK, IDEMIP_IP4_LOOPBACK_TAG))
    {
        return IDEMIP_IP4_TYPE_LOOPBACK;
    }
    if (idemip_ip4_addr_tagged(addr, IDEMIP_IP4_LINK_LOCAL_MASK, IDEMIP_IP4_LINK_LOCAL_TAG))
    {
        return IDEMIP_IP4_TYPE_LINK_LOCAL;
    }
    if (idemip_ip4_addr_is_mcast(addr))
    {
        return IDEMIP_IP4_TYPE_MULTICAST;
    }
    if (idemip_ip4_addr_tagged(addr, IDEMIP_IP4_CLASS_E_MASK, IDEMIP_IP4_CLASS_E_TAG))
    {
        return IDEMIP_IP4_TYPE_RESERVED;
    }
    return IDEMIP_IP4_TYPE_UNICAST;
}

// idemip_ip4_addr_mask_ones and idemip_ip4_addr_mask_contiguous were here. They are arithmetic over
// a mask rather than anything about classifying an address, and ip4_route needs both - it has no
// reason to include a header about address types, so it carried its own copy of each. They are in
// ipv4.h now, which both units already take, and which this header includes.

/**
 * @brief Write the RFC 1112 sec 6.4 Ethernet address of a class D group into @p out.
 *
 * sec 6.4: "An IP host group address is mapped to an Ethernet multicast address by placing the
 * low-order 23-bits of the IP address into the low-order 23 bits of the Ethernet multicast address
 * 01-00-5E-00-00-00 (hex)."
 */
IDEMIP_INLINE void idemip_ip4_addr_mcast_mac(uint8_t *out, uint32_t group)
{
    uint32_t low = group & IDEMIP_IP4_MCAST_MAC_MASK;
    out[0] = IDEMIP_IP4_MCAST_MAC_0;
    out[1] = IDEMIP_IP4_MCAST_MAC_1;
    out[2] = IDEMIP_IP4_MCAST_MAC_2;
    out[3] = (uint8_t)((low >> 16) & 0xFFu);
    out[4] = (uint8_t)((low >> 8) & 0xFFu);
    out[5] = (uint8_t)(low & 0xFFu);
}

// ---------------------------------------------------------------------------
// Operands
// ---------------------------------------------------------------------------

/** @brief What a classify takes. */
typedef struct
{
    uint32_t addr; ///< the address, host order
} Ip4AddrClassifyArgs;

/**
 * @brief What a netmask test takes.
 *
 * RFC 1122 sec 3.2.1.3: "there will be an address mask of the form: {-1, -1, 0} associated with
 * each of the host's local IP addresses". The same section adds that the notation "is not intended
 * to imply that the 1-bits in an address mask need be contiguous", so a mask with holes is tested
 * rather than refused, and @ref Ip4AddrIo::contiguous says which kind arrived.
 *
 * @var Ip4AddrMatchArgs::addr an address to place against the subnet
 * @var Ip4AddrMatchArgs::net  any address on the subnet, its host part unread
 * @var Ip4AddrMatchArgs::mask that subnet's address mask
 */
typedef struct
{
    uint32_t addr;
    uint32_t net;
    uint32_t mask;
} Ip4AddrMatchArgs;

/** @brief What the RFC 1112 sec 6.4 map takes. */
typedef struct
{
    uint32_t group; ///< a class D host group address, host order
} Ip4AddrMcastArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var Ip4AddrIo::classify_args the address a classify reads
 * @var Ip4AddrIo::match_args    the address, subnet and mask a test reads
 * @var Ip4AddrIo::mcast_args    the group the RFC 1112 sec 6.4 map reads
 * @var Ip4AddrIo::status        what the call reports: OK or ERR
 * @var Ip4AddrIo::network       the subnet's network number, @c net masked
 * @var Ip4AddrIo::broadcast     that subnet's directed broadcast, case (e) "{ <Network-number>,
 *                               <Subnet-number>, -1 }"
 * @var Ip4AddrIo::host          the tested address's host part
 * @var Ip4AddrIo::mac           the six octets sec 6.4 maps a group onto
 * @var Ip4AddrIo::type          which special case of RFC 1122 sec 3.2.1.3 the address is
 * @var Ip4AddrIo::addr_class    which of the five classes its high-order bits name
 * @var Ip4AddrIo::prefix_len    ones in the mask
 * @var Ip4AddrIo::on_subnet     the address and @c net agree everywhere the mask is set
 * @var Ip4AddrIo::is_broadcast  the address is the limited broadcast, or that subnet's directed one
 * @var Ip4AddrIo::contiguous    the mask's ones are the leading bits, with no hole below them
 */
typedef struct
{
    Ip4AddrClassifyArgs classify_args;
    Ip4AddrMatchArgs match_args;
    Ip4AddrMcastArgs mcast_args;

    IdemIpStatus status;
    uint32_t network;
    uint32_t broadcast;
    uint32_t host;
    uint8_t mac[IDEMIP_MAC_LEN];
    IdemIpIp4AddrType type;
    IdemIpIp4Class addr_class;
    uint8_t prefix_len;
    idemip_bool on_subnet;
    idemip_bool is_broadcast;
    idemip_bool contiguous;
} Ip4AddrIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. This unit holds no table, so the map is the
// operand block and the context behind it, and IDEMIP_IP4_ADDR_CTX_BYTES spans both.

#define IDEMIP_IP4_ADDR_OFF_IO 0u ///< the operand and result block
#define IDEMIP_IP4_ADDR_OFF_CTX (IDEMIP_IP4_ADDR_OFF_IO + IDEMIP_ROUND_UP(sizeof(Ip4AddrIo), IDEMIP_ALIGN))
#define IDEMIP_IP4_ADDR_OFF_END (IDEMIP_IP4_ADDR_OFF_IO + IDEMIP_IP4_ADDR_CTX_BYTES)

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_IP4_ADDR_IO(w) ((Ip4AddrIo *)(void *)((w) + IDEMIP_IP4_ADDR_OFF_IO))

/**
 * @brief What an IPv4 address is, and what Ethernet address a group reaches.
 *
 *   Ip4Addr.clear(work);
 *   IDEMIP_IP4_ADDR_IO(work)->classify_args.addr = idemip_ip4_dst(hdr);
 *   Ip4Addr.classify(work);
 *   if (IDEMIP_IP4_ADDR_IO(work)->type == IDEMIP_IP4_TYPE_MULTICAST) { ... }
 *
 * @c work is IDEMIP_IP4_ADDR_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. The borrow IS the
 * instance, so two callers are two borrows and share not one byte.
 *
 * A borrow is refused until @ref Ip4AddrNs::clear has run on it: clear zeroes the context and
 * leaves one nonzero octet in it, the mark that says these bytes are this module's.
 *
 * Nothing here blocks and nothing here defers, so no entry ever reports IDEMIP_BUSY: every answer
 * is a function of the operands alone and is available on the call that asks for it. A null borrow,
 * a borrow no clear has run on, and a group outside class D report IDEMIP_ERR, none of which a
 * retry changes.
 *
 * @var Ip4AddrNs::clear      zero the context and mark the borrow cleared
 * @var Ip4AddrNs::classify   the special case of RFC 1122 sec 3.2.1.3 and the class of RFC 791
 *                            sec 3.2 that one address falls in
 * @var Ip4AddrNs::match      place one address against one subnet, and report that subnet's network
 *                            number and directed broadcast
 * @var Ip4AddrNs::mcast_mac  map a class D group onto its Ethernet address (RFC 1112 sec 6.4)
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const classify)(uint8_t *restrict work);
    void (*const match)(uint8_t *restrict work);
    void (*const mcast_mac)(uint8_t *restrict work);
} Ip4AddrNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_ip4_addr_clear(uint8_t *restrict work);
void idemip_ip4_addr_classify(uint8_t *restrict work);
void idemip_ip4_addr_match(uint8_t *restrict work);
void idemip_ip4_addr_mcast_mac_io(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Ip4Addr.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Ip4AddrNs Ip4Addr IDEMIP_UNUSED = {
    .clear = idemip_ip4_addr_clear,
    .classify = idemip_ip4_addr_classify,
    .match = idemip_ip4_addr_match,
    .mcast_mac = idemip_ip4_addr_mcast_mac_io};
// The class tags and their masks agree with the bit patterns RFC 791 sec 3.2 prints.
static_assert((IDEMIP_IP4_CLASS_A_TAG & ~IDEMIP_IP4_CLASS_A_MASK) == 0u &&
                  (IDEMIP_IP4_CLASS_B_TAG & ~IDEMIP_IP4_CLASS_B_MASK) == 0u &&
                  (IDEMIP_IP4_CLASS_C_TAG & ~IDEMIP_IP4_CLASS_C_MASK) == 0u &&
                  (IDEMIP_IP4_CLASS_D_TAG & ~IDEMIP_IP4_CLASS_D_MASK) == 0u &&
                  (IDEMIP_IP4_CLASS_E_TAG & ~IDEMIP_IP4_CLASS_E_MASK) == 0u,
              "a class tag must lie inside its own mask (RFC 791 sec 3.2)");

// RFC 1112 sec 4: host group addresses "range from 224.0.0.0 to 239.255.255.255".
static_assert(IDEMIP_IP4_CLASS_D_TAG == 0xE0000000u && (IDEMIP_IP4_CLASS_D_TAG | ~IDEMIP_IP4_CLASS_D_MASK) == 0xEFFFFFFFu,
              "class D must span 224.0.0.0 through 239.255.255.255 (RFC 1112 sec 4)");

// RFC 1112 sec 6.4 carries 23 bits, so the mask is 23 ones.
static_assert(IDEMIP_IP4_MCAST_MAC_MASK == 0x7FFFFFu, "RFC 1112 sec 6.4 maps the low-order 23 bits");

// sec 6.4: "there are 28 significant bits in an IP host group address", which is what the class D
// tag leaves free.
static_assert((0xFFFFFFFFu & ~IDEMIP_IP4_CLASS_D_MASK) == 0x0FFFFFFFu &&
                  IDEMIP_IP4_MCAST_GROUP_BITS == 28u,
              "a class D group carries 28 significant bits (RFC 1112 sec 6.4)");

// RFC 3927 sec 2.1 registers a /16, and sec 2.6.2 names 169.254.255.255 "the broadcast address for
// the Link-Local prefix", which is inside it.
static_assert((IDEMIP_IP4_LINK_LOCAL_TAG & ~IDEMIP_IP4_LINK_LOCAL_MASK) == 0u &&
                  IDEMIP_IP4_LINK_LOCAL_TAG == IDEMIP_AUTOIP_PREFIX,
              "the RFC 3927 sec 2.1 link-local prefix must be 169.254/16");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_IP4_ADDR_H
