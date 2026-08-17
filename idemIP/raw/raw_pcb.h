// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file raw_pcb.h
 * @brief The raw IP bindings, one table entry per binding onto an IP protocol number.
 *
 * RFC 1122 sec 3.4 states the interface between IP and the layer above it: it "MUST provide full
 * access to all the mechanisms of the IP layer, including options, Type-of-Service, and
 * Time-to-Live", through "SEND(src, dst, prot, TOS, TTL, BufPTR, len, Id, DF, opt => result )" and
 * "RECV(BufPTR, prot => result, src, dst, SpecDest, TOS, len, opt)". An entry holds the src, dst,
 * prot, TOS and TTL of one binding. BufPTR and len are the caller's, so no datagram octet is copied
 * into a binding.
 *
 * A binding over IPv6 also carries the RFC 3542 sec 3.1 IPV6_CHECKSUM offset, "an integer offset
 * into the user data of where the checksum is located".
 */

#ifndef IDEMIP_RAW_PCB_H
#define IDEMIP_RAW_PCB_H

#include "idemIP/idemip_config.h"

#if IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/**
 * @brief Octets an address operand and an address in an entry span.
 *
 * RFC 4291 sec 2: "IPv6 addresses are 128-bit identifiers for interfaces and sets of interfaces".
 * An RFC 791 sec 3.1 address is the first four of them.
 */
#define IDEMIP_RAW_PCB_ADDR_BYTES 16u

/** @brief The index that names no entry. Reported when nothing matched and nothing was free. */
#define IDEMIP_RAW_PCB_NONE 0xFFFFu

/**
 * @brief What an open takes.
 *
 * @var RawPcbOpenArgs::proto      the RFC 1122 sec 3.4 SEND parameter @c prot, the RFC 791 sec 3.1
 *                                 Protocol field a received datagram is matched on
 * @var RawPcbOpenArgs::ip_version 4 for an RFC 791 sec 3.1 Version 4 binding, 6 for an RFC 8200
 *                                 sec 3 Version 6 one
 */
typedef struct
{
    uint8_t proto;
    uint8_t ip_version;
} RawPcbOpenArgs;

/**
 * @brief What a bind and a connect take: one endpoint of the RFC 1122 sec 3.4 SEND address pair.
 *
 * @var RawPcbAddrArgs::ip    IDEMIP_RAW_PCB_ADDR_BYTES octets in the caller's storage, the first
 *                            four read when the binding's version is 4
 * @var RawPcbAddrArgs::index the entry an open reported
 * @var RawPcbAddrArgs::zone  the RFC 4007 sec 6 zone index qualifying a non-global IPv6 address
 * @var RawPcbAddrArgs::netif the interface this endpoint is pinned to, 0 for none
 */
typedef struct
{
    const uint8_t *ip;
    uint16_t index;
    uint8_t zone;
    uint8_t netif;
} RawPcbAddrArgs;

/**
 * @brief What a close, a disconnect and a load take.
 *
 * @var RawPcbPcbArgs::index the entry an open reported
 */
typedef struct
{
    uint16_t index;
} RawPcbPcbArgs;

/**
 * @brief What a set_opts takes: the RFC 1122 sec 3.4 mechanisms the layer above may set.
 *
 * @var RawPcbOptArgs::index         the entry an open reported
 * @var RawPcbOptArgs::cksum_offset  RFC 3542 sec 3.1 IPV6_CHECKSUM, an even offset into the user
 *                                   data, or -1: "Setting the offset to -1 also disables the
 *                                   option."
 * @var RawPcbOptArgs::tos           RFC 791 sec 3.1 Type of Service
 * @var RawPcbOptArgs::ttl           RFC 791 sec 3.1 Time to Live, the RFC 8200 sec 3 Hop Limit over
 *                                   IPv6
 * @var RawPcbOptArgs::flags         the binding's option bits
 */
typedef struct
{
    uint16_t index;
    int16_t cksum_offset;
    uint8_t tos;
    uint8_t ttl;
    uint8_t flags;
} RawPcbOptArgs;

/**
 * @brief What a find takes: the RFC 1122 sec 3.4 RECV parameters of one received datagram.
 *
 * @var RawPcbFindArgs::local_ip    the datagram's RFC 791 sec 3.1 Destination Address
 * @var RawPcbFindArgs::remote_ip   its Source Address
 * @var RawPcbFindArgs::proto       its Protocol field, the RECV parameter @c prot
 * @var RawPcbFindArgs::ip_version  4 or 6
 * @var RawPcbFindArgs::local_zone  the RFC 4007 sec 6 zone index of the destination
 * @var RawPcbFindArgs::remote_zone the zone index of the source
 * @var RawPcbFindArgs::netif       the interface it arrived on
 */
typedef struct
{
    const uint8_t *local_ip;
    const uint8_t *remote_ip;
    uint8_t proto;
    uint8_t ip_version;
    uint8_t local_zone;
    uint8_t remote_zone;
    uint8_t netif;
} RawPcbFindArgs;

/**
 * @brief What a load reports: every RFC 1122 sec 3.4 SEND parameter one binding carries.
 *
 * The two addresses point into the entry, which is the caller's own borrow, and stay valid until
 * the next call that writes that entry.
 *
 * @var RawPcbInfo::local_ip     the SEND parameter @c src
 * @var RawPcbInfo::remote_ip    the SEND parameter @c dst
 * @var RawPcbInfo::cksum_offset the RFC 3542 sec 3.1 IPV6_CHECKSUM offset, or -1 when disabled
 * @var RawPcbInfo::local_zone   the RFC 4007 sec 6 zone index of @c src
 * @var RawPcbInfo::remote_zone  the zone index of @c dst
 * @var RawPcbInfo::netif        the interface the binding is pinned to, 0 for none
 * @var RawPcbInfo::proto        the SEND parameter @c prot
 * @var RawPcbInfo::tos          the SEND parameter @c TOS
 * @var RawPcbInfo::ttl          the SEND parameter @c TTL
 * @var RawPcbInfo::flags        the binding's option bits
 * @var RawPcbInfo::ip_version   4 or 6
 * @var RawPcbInfo::connected    a remote address was set, so @c dst is significant
 */
typedef struct
{
    const uint8_t *local_ip;
    const uint8_t *remote_ip;
    int16_t cksum_offset;
    uint8_t local_zone;
    uint8_t remote_zone;
    uint8_t netif;
    uint8_t proto;
    uint8_t tos;
    uint8_t ttl;
    uint8_t flags;
    uint8_t ip_version;
    idemip_bool connected;
} RawPcbInfo;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns. Two workers on two borrows share no
 * byte of this.
 *
 * @var RawPcbIo::open_args    the protocol and version an open binds
 * @var RawPcbIo::bind_args    the local address a bind sets
 * @var RawPcbIo::connect_args the remote address a connect sets
 * @var RawPcbIo::pcb_args     the entry a close, a disconnect and a load name
 * @var RawPcbIo::opt_args     the Type-of-Service, Time-to-Live and checksum offset a set_opts sets
 * @var RawPcbIo::find_args    the received datagram a find matches
 * @var RawPcbIo::status       what the call reports: OK, BUSY, or ERR
 * @var RawPcbIo::index        the entry an open took or a find matched, IDEMIP_RAW_PCB_NONE for
 *                             neither
 * @var RawPcbIo::info         what a load read
 */
typedef struct
{
    RawPcbOpenArgs open_args;
    RawPcbAddrArgs bind_args;
    RawPcbAddrArgs connect_args;
    RawPcbPcbArgs pcb_args;
    RawPcbOptArgs opt_args;
    RawPcbFindArgs find_args;

    IdemIpStatus status;
    uint16_t index;
    RawPcbInfo info;
} RawPcbIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The table starts at
// IDEMIP_RAW_PCB_CTX_BYTES, which idemip_config.h asserts is a multiple of IDEMIP_ALIGN, so the
// operand block and the context growing does not move an entry.

#define IDEMIP_RAW_PCB_OFF_IO 0u ///< the operand and result block
#define IDEMIP_RAW_PCB_OFF_CTX (IDEMIP_RAW_PCB_OFF_IO + sizeof(RawPcbIo)) ///< the running context
#define IDEMIP_RAW_PCB_OFF_TAB IDEMIP_RAW_PCB_CTX_BYTES ///< IDEMIP_RAW_PCBS entries follow

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_RAW_PCB_IO(w) ((RawPcbIo *)(void *)((w) + IDEMIP_RAW_PCB_OFF_IO))

/**
 * @brief The RFC 1122 sec 3.4 raw bindings.
 *
 *   RawPcb.clear(work);
 *   IDEMIP_RAW_PCB_IO(work)->open_args.proto = 253u;
 *   IDEMIP_RAW_PCB_IO(work)->open_args.ip_version = 4u;
 *   RawPcb.open(work);
 *   if (IDEMIP_RAW_PCB_IO(work)->status == IDEMIP_OK) { ... }
 *
 * @c work is IDEMIP_RAW_PCB_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * tables are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick. A table with no free entry is BUSY, since a close frees one. A
 * borrow that was never cleared, an index past the table, and an entry that is not open are ERR.
 *
 * @var RawPcbNs::clear      zero the context and the table, and mark the borrow usable
 * @var RawPcbNs::open       take a free entry for @ref RawPcbOpenArgs::proto, reporting it in
 *                           @ref RawPcbIo::index. BUSY when every entry is open.
 * @var RawPcbNs::close      release the entry @ref RawPcbPcbArgs::index names
 * @var RawPcbNs::bind       set the SEND parameter @c src on that entry
 * @var RawPcbNs::connect    set the SEND parameter @c dst on that entry
 * @var RawPcbNs::disconnect clear that @c dst, leaving the binding unconnected
 * @var RawPcbNs::set_opts   set that entry's Type-of-Service, Time-to-Live, option bits and RFC
 *                           3542 sec 3.1 checksum offset
 * @var RawPcbNs::load       read that entry into @ref RawPcbIo::info
 * @var RawPcbNs::find       match a received datagram to a binding, reporting it in
 *                           @ref RawPcbIo::index. BUSY is never reported: no binding is ERR.
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const open)(uint8_t *restrict work);
    void (*const close)(uint8_t *restrict work);
    void (*const bind)(uint8_t *restrict work);
    void (*const connect)(uint8_t *restrict work);
    void (*const disconnect)(uint8_t *restrict work);
    void (*const set_opts)(uint8_t *restrict work);
    void (*const load)(uint8_t *restrict work);
    void (*const find)(uint8_t *restrict work);
} RawPcbNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const RawPcbNs RawPcb;

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6

#endif // IDEMIP_RAW_PCB_H
