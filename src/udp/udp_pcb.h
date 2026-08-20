// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file udp_pcb.h
 * @brief The UDP bindings, one table entry per bound port pair.
 *
 * RFC 768 states the user interface a binding serves: "the creation of new receive ports", "receive
 * operations on the receive ports that return the data octets and an indication of source port and
 * source address", and "an operation that allows a datagram to be sent, specifying the data, source
 * and destination ports and addresses to be sent". So an entry holds the Source Port and
 * Destination Port of one binding with the addresses they belong to. The data octets are the
 * caller's and no datagram octet is copied into a binding.
 *
 * RFC 1122 sec 4.1.4 adds that "The application interface to UDP MUST provide the full services of
 * the IP/transport interface described in Section 3.4", so an entry carries that interface's
 * Type-of-Service and Time-to-Live too, with the RFC 1112 sec 6.1 multicast time-to-live and
 * outgoing interface, and the two RFC 3828 sec 3.1 Checksum Coverage lengths a UDP-Lite binding
 * sends with and accepts.
 */

#ifndef IDEMIP_UDP_PCB_H
#define IDEMIP_UDP_PCB_H

#include "src/udp/udp.h"

#if IDEMIP_ENABLE_UDP

IDEMIP_BEGIN_DECLS

/**
 * @brief Octets an address operand and an address in an entry span.
 *
 * RFC 4291 sec 2: "IPv6 addresses are 128-bit identifiers for interfaces and sets of interfaces".
 * An RFC 791 sec 3.1 address is the first four of them.
 */
#define IDEMIP_UDP_PCB_ADDR_BYTES 16u

/** @brief The index that names no entry. Reported when nothing matched and nothing was free. */
#define IDEMIP_UDP_PCB_NONE 0xFFFFu

/**
 * @brief RFC 768: Source Port "If not used, a value of zero is inserted."
 *
 * A bind of zero is the request for an unused port rather than a bind of port zero.
 */
#define IDEMIP_UDP_PCB_PORT_ANY 0u

/**
 * @brief The range a bind of IDEMIP_UDP_PCB_PORT_ANY settles inside.
 *
 * RFC 6335 sec 6: "the Dynamic Ports, also known as the Private or Ephemeral Ports, from 49152-65535
 * (never assigned)". The two bounds span a power of two, so a candidate is the base ORed with the
 * masked low bits of a running count.
 */
#define IDEMIP_UDP_PCB_PORT_FIRST 0xC000u
#define IDEMIP_UDP_PCB_PORT_LAST 0xFFFFu

/**
 * @brief What an open takes.
 *
 * @var UdpPcbOpenArgs::ip_version 4 for an RFC 791 sec 3.1 Version 4 binding, 6 for an RFC 8200
 *                                 sec 3 Version 6 one
 * @var UdpPcbOpenArgs::lite       RFC 3828: the binding is UDP-Lite, protocol 136, and its header
 *                                 carries a Checksum Coverage where RFC 768 carries a Length
 */
typedef struct
{
    uint8_t ip_version;
    idemip_bool lite;
} UdpPcbOpenArgs;

/**
 * @brief What a bind and a connect take: one address and port of the RFC 768 pair.
 *
 * @var UdpPcbAddrArgs::ip    IDEMIP_UDP_PCB_ADDR_BYTES octets in the caller's storage, the first
 *                            four read when the binding's version is 4
 * @var UdpPcbAddrArgs::index the entry an open reported
 * @var UdpPcbAddrArgs::port  the RFC 768 Source Port on a bind, Destination Port on a connect,
 *                            IDEMIP_UDP_PCB_PORT_ANY to be assigned one
 * @var UdpPcbAddrArgs::zone  the RFC 4007 sec 6 zone index qualifying a non-global IPv6 address
 * @var UdpPcbAddrArgs::netif the interface this endpoint is pinned to, 0 for none
 * @var UdpPcbAddrArgs::rand  a random word, read only on a bind of IDEMIP_UDP_PCB_PORT_ANY. RFC 6056
 *                            sec 3.3: "Ephemeral port selection algorithms SHOULD obfuscate the
 *                            selection of their ephemeral ports, since this helps to mitigate a
 *                            number of attacks that depend on the attacker's ability to guess or know
 *                            the five-tuple that identifies the transport-protocol instance to be
 *                            attacked", and sec 1 names UDP and UDP-Lite among the protocols it
 *                            applies to. This is sec 3.3.1 Algorithm 1's random() and is what places
 *                            the first candidate.
 */
typedef struct
{
    const uint8_t *ip;
    uint32_t rand;
    uint16_t index;
    uint16_t port;
    uint8_t zone;
    uint8_t netif;
} UdpPcbAddrArgs;

/**
 * @brief What a close, a disconnect and a load take.
 *
 * @var UdpPcbPcbArgs::index the entry an open reported
 */
typedef struct
{
    uint16_t index;
} UdpPcbPcbArgs;

/**
 * @brief What a set_opts takes: the RFC 1122 sec 3.4 and RFC 1112 sec 6.1 mechanisms of one binding.
 *
 * @var UdpPcbOptArgs::index        the entry an open reported
 * @var UdpPcbOptArgs::cksum_len_tx RFC 3828 sec 3.1 Checksum Coverage a sent datagram carries,
 *                                  "the number of octets, counting from the first octet of the
 *                                  UDP-Lite header, that are covered by the checksum". Zero covers
 *                                  the whole datagram.
 * @var UdpPcbOptArgs::cksum_len_rx the least coverage a received datagram is accepted with, RFC
 *                                  3828 sec 3.3 letting an application "block delivery of packets
 *                                  with coverage values less than a value provided by the
 *                                  application"
 * @var UdpPcbOptArgs::tos          RFC 791 sec 3.1 Type of Service
 * @var UdpPcbOptArgs::ttl          RFC 791 sec 3.1 Time to Live, the RFC 8200 sec 3 Hop Limit over
 *                                  IPv6
 * @var UdpPcbOptArgs::mcast_ttl    RFC 1112 sec 6.1: the "time-to-live of an outgoing multicast
 *                                  datagram", which "should default to 1"
 * @var UdpPcbOptArgs::mcast_netif  RFC 1112 sec 6.1: "which network interface is be used for the
 *                                  multicast transmission", 0 for the default
 * @var UdpPcbOptArgs::flags        the binding's option bits, one of them the RFC 1112 sec 6.1
 *                                  inhibit on looping a multicast datagram back
 */
typedef struct
{
    uint16_t index;
    uint16_t cksum_len_tx;
    uint16_t cksum_len_rx;
    uint8_t tos;
    uint8_t ttl;
    uint8_t mcast_ttl;
    uint8_t mcast_netif;
    uint8_t flags;
} UdpPcbOptArgs;

/**
 * @brief What a find takes: the RFC 768 header and addresses of one received datagram.
 *
 * @var UdpPcbFindArgs::local_ip    the datagram's destination address, the RFC 1122 sec 4.1.3.5
 *                                  specific-destination address
 * @var UdpPcbFindArgs::remote_ip   its source address
 * @var UdpPcbFindArgs::local_port  its RFC 768 Destination Port
 * @var UdpPcbFindArgs::remote_port its RFC 768 Source Port
 * @var UdpPcbFindArgs::cksum_len   the RFC 3828 sec 3.1 Checksum Coverage it arrived with, 0 for a
 *                                  full-coverage RFC 768 datagram
 * @var UdpPcbFindArgs::ip_version  4 or 6
 * @var UdpPcbFindArgs::local_zone  the RFC 4007 sec 6 zone index of the destination
 * @var UdpPcbFindArgs::remote_zone the zone index of the source
 * @var UdpPcbFindArgs::netif       the interface it arrived on
 */
typedef struct
{
    const uint8_t *local_ip;
    const uint8_t *remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint16_t cksum_len;
    uint8_t ip_version;
    uint8_t local_zone;
    uint8_t remote_zone;
    uint8_t netif;
} UdpPcbFindArgs;

/**
 * @brief What a load reports: everything one binding carries.
 *
 * The two addresses point into the entry, which is the caller's own borrow, and stay valid until the
 * next call that writes that entry.
 *
 * @var UdpPcbInfo::local_ip     the address the Source Port belongs to
 * @var UdpPcbInfo::remote_ip    the address the Destination Port belongs to
 * @var UdpPcbInfo::local_port   RFC 768 Source Port
 * @var UdpPcbInfo::remote_port  RFC 768 Destination Port
 * @var UdpPcbInfo::cksum_len_tx RFC 3828 sec 3.1 Checksum Coverage sent
 * @var UdpPcbInfo::cksum_len_rx the least coverage accepted
 * @var UdpPcbInfo::local_zone   the RFC 4007 sec 6 zone index of the local address
 * @var UdpPcbInfo::remote_zone  the zone index of the remote address
 * @var UdpPcbInfo::netif        the interface the binding is pinned to, 0 for none
 * @var UdpPcbInfo::tos          RFC 791 sec 3.1 Type of Service
 * @var UdpPcbInfo::ttl          RFC 791 sec 3.1 Time to Live
 * @var UdpPcbInfo::mcast_ttl    RFC 1112 sec 6.1 multicast time-to-live
 * @var UdpPcbInfo::mcast_netif  RFC 1112 sec 6.1 outgoing multicast interface
 * @var UdpPcbInfo::flags        the binding's option bits
 * @var UdpPcbInfo::ip_version   4 or 6
 * @var UdpPcbInfo::lite         RFC 3828 UDP-Lite rather than RFC 768 UDP
 * @var UdpPcbInfo::connected    a remote address and port were set, so both are significant
 */
typedef struct
{
    const uint8_t *local_ip;
    const uint8_t *remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint16_t cksum_len_tx;
    uint16_t cksum_len_rx;
    uint8_t local_zone;
    uint8_t remote_zone;
    uint8_t netif;
    uint8_t tos;
    uint8_t ttl;
    uint8_t mcast_ttl;
    uint8_t mcast_netif;
    uint8_t flags;
    uint8_t ip_version;
    idemip_bool lite;
    idemip_bool connected;
} UdpPcbInfo;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns. Two workers on two borrows share no
 * byte of this.
 *
 * @var UdpPcbIo::open_args    the version an open binds, and whether it is UDP-Lite
 * @var UdpPcbIo::bind_args    the local address and RFC 768 Source Port a bind sets
 * @var UdpPcbIo::connect_args the remote address and Destination Port a connect sets
 * @var UdpPcbIo::pcb_args     the entry a close, a disconnect and a load name
 * @var UdpPcbIo::opt_args     the options a set_opts sets
 * @var UdpPcbIo::find_args    the received datagram a find matches
 * @var UdpPcbIo::status       what the call reports: OK, BUSY, or ERR
 * @var UdpPcbIo::index        the entry an open took or a find matched, IDEMIP_UDP_PCB_NONE for
 *                             neither
 * @var UdpPcbIo::port         the port a bind settled on, which is the one it was given unless that
 *                             was IDEMIP_UDP_PCB_PORT_ANY
 * @var UdpPcbIo::info         what a load read
 */
typedef struct
{
    UdpPcbOpenArgs open_args;
    UdpPcbAddrArgs bind_args;
    UdpPcbAddrArgs connect_args;
    UdpPcbPcbArgs pcb_args;
    UdpPcbOptArgs opt_args;
    UdpPcbFindArgs find_args;

    IdemIpStatus status;
    uint16_t index;
    uint16_t port;
    UdpPcbInfo info;
} UdpPcbIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The table starts at
// IDEMIP_UDP_PCB_CTX_BYTES, which idemip_config.h asserts is a multiple of IDEMIP_ALIGN, so the
// operand block and the context growing does not move an entry.

#define IDEMIP_UDP_PCB_OFF_IO 0u ///< the operand and result block
#define IDEMIP_UDP_PCB_OFF_CTX (IDEMIP_UDP_PCB_OFF_IO + IDEMIP_ROUND_UP(sizeof(UdpPcbIo), IDEMIP_ALIGN)) ///< the running context
#define IDEMIP_UDP_PCB_OFF_TAB IDEMIP_UDP_PCB_CTX_BYTES ///< IDEMIP_UDP_PCBS entries follow

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_UDP_PCB_IO(w) ((UdpPcbIo *)(void *)((w) + IDEMIP_UDP_PCB_OFF_IO))

/**
 * @brief The RFC 768 bindings.
 *
 *   UdpPcb.clear(work);
 *   IDEMIP_UDP_PCB_IO(work)->open_args.ip_version = 4u;
 *   UdpPcb.open(work);
 *   if (IDEMIP_UDP_PCB_IO(work)->status == IDEMIP_OK) { ... }
 *
 * @c work is IDEMIP_UDP_PCB_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * tables are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick. A table with no free entry, and a bind with no free port, are
 * BUSY, since a close frees both. A borrow that was never cleared, an index past the table, an entry
 * that is not open, and a port another entry holds are ERR.
 *
 * @var UdpPcbNs::clear      zero the context and the table, and mark the borrow usable
 * @var UdpPcbNs::open       take a free entry, reporting it in @ref UdpPcbIo::index. BUSY when every
 *                           entry is open.
 * @var UdpPcbNs::close      release the entry @ref UdpPcbPcbArgs::index names
 * @var UdpPcbNs::bind       set that entry's local address and Source Port, reporting the port it
 *                           settled on in @ref UdpPcbIo::port
 * @var UdpPcbNs::connect    set that entry's remote address and Destination Port
 * @var UdpPcbNs::disconnect clear that remote address and port, leaving the binding unconnected
 * @var UdpPcbNs::set_opts   set that entry's Type-of-Service, Time-to-Live, multicast options,
 *                           option bits and RFC 3828 coverage lengths
 * @var UdpPcbNs::load       read that entry into @ref UdpPcbIo::info
 * @var UdpPcbNs::find       match a received datagram to a binding, reporting it in
 *                           @ref UdpPcbIo::index. BUSY is never reported: no binding is ERR, which
 *                           is the RFC 1122 sec 4.1.3.1 case where "UDP SHOULD send an ICMP Port
 *                           Unreachable message".
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
} UdpPcbNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_udp_pcb_clear(uint8_t *restrict work);
void idemip_udp_pcb_open(uint8_t *restrict work);
void idemip_udp_pcb_close(uint8_t *restrict work);
void idemip_udp_pcb_bind(uint8_t *restrict work);
void idemip_udp_pcb_connect(uint8_t *restrict work);
void idemip_udp_pcb_disconnect(uint8_t *restrict work);
void idemip_udp_pcb_set_opts(uint8_t *restrict work);
void idemip_udp_pcb_load(uint8_t *restrict work);
void idemip_udp_pcb_find(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `UdpPcb.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const UdpPcbNs UdpPcb IDEMIP_UNUSED = {
    .clear = idemip_udp_pcb_clear,
    .open = idemip_udp_pcb_open,
    .close = idemip_udp_pcb_close,
    .bind = idemip_udp_pcb_bind,
    .connect = idemip_udp_pcb_connect,
    .disconnect = idemip_udp_pcb_disconnect,
    .set_opts = idemip_udp_pcb_set_opts,
    .load = idemip_udp_pcb_load,
    .find = idemip_udp_pcb_find};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_UDP

#endif // IDEMIP_UDP_PCB_H
