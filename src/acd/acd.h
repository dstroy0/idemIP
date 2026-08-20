// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file acd.h
 * @brief IPv4 Address Conflict Detection, RFC 5227: probe an address, announce it, then watch for a
 *        conflict for as long as it is in use.
 *
 * One machine over one address on one interface, so the borrow IS the interface and two interfaces
 * are two borrows. RFC 5227 sec 2.1 probes, sec 2.3 announces, and sec 2.4 detects and defends.
 *
 * Every deadline here is a millisecond. RFC 5227 sec 1.1 states its constants in seconds, and
 * idemip_config.h holds each as milliseconds, so the clock a deadline is compared against needs no
 * conversion and no divide exists.
 *
 * Nothing here builds or parses an ARP packet: arp.h does that. This unit reports which packet is due
 * and reads the fields of one that arrived.
 */

#ifndef IDEMIP_ACD_H
#define IDEMIP_ACD_H

#include "src/arp/arp.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/**
 * @brief Where the machine is over its address.
 *
 * RFC 5227 names no states. It names the phases these follow: sec 2.1.1 the initial random delay
 * over [0, PROBE_WAIT], the PROBE_NUM probes spaced PROBE_MIN to PROBE_MAX apart, and the
 * ANNOUNCE_WAIT after the last probe; sec 2.3 the ANNOUNCE_NUM announcements ANNOUNCE_INTERVAL
 * apart; sec 2.4 the ongoing detection that runs "for as long as a host is using an address"; and
 * sec 2.1.1's rate limit of "one attempted new address per RATE_LIMIT_INTERVAL" once MAX_CONFLICTS
 * conflicts are counted.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ACD_STATE_OFF = 0,        ///< no address in the machine, which is what clear leaves
    IDEMIP_ACD_STATE_PROBE_WAIT,     ///< sec 2.1.1, waiting out the initial delay over [0, PROBE_WAIT]
    IDEMIP_ACD_STATE_PROBING,        ///< sec 2.1.1, sending PROBE_NUM ARP Probes
    IDEMIP_ACD_STATE_ANNOUNCE_WAIT,  ///< sec 2.1.1, waiting ANNOUNCE_WAIT after the last probe
    IDEMIP_ACD_STATE_ANNOUNCING,     ///< sec 2.3, sending ANNOUNCE_NUM ARP Announcements
    IDEMIP_ACD_STATE_ONGOING,        ///< sec 2.4, the address is in use and every ARP packet is checked
    IDEMIP_ACD_STATE_RATE_LIMIT,     ///< sec 2.1.1, MAX_CONFLICTS reached, one attempt per RATE_LIMIT_INTERVAL
} IdemIpAcdState;

/**
 * @brief Which of the three responses RFC 5227 sec 2.4 permits this address takes on a conflict.
 *
 * sec 2.4: "a host MUST respond to a conflicting ARP packet as described in either (a), (b), or (c)
 * below", and "A host wishing to provide reliable network operation MUST respond to conflicting ARP
 * packets as described in (a), (b), or (c) above." Which one is a property of the address the
 * configuring agent chose, so it is an operand of start rather than a state of the machine.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ACD_DEFEND_NEVER = 0, ///< (a) "immediately cease using the address, and signal an error"
    IDEMIP_ACD_DEFEND_ONCE,      ///< (b) one Announcement per DEFEND_INTERVAL, then cease
    IDEMIP_ACD_DEFEND_ALWAYS,    ///< (c) "defend its address indefinitely", and never cease
} IdemIpAcdDefense;

/**
 * @brief What start takes: the address to claim, and how it is defended.
 *
 * RFC 5227 sec 2.1.1 fills an ARP Probe's 'sender hardware address' with "the hardware address of
 * the interface through which it is sending the packet", and this machine is one interface's: sec
 * 2.1 scopes the whole claim to one, "if the host experiences MAX_CONFLICTS or more address
 * conflicts on a given interface, then the host MUST limit the rate at which it probes for new
 * addresses on this interface", and RFC 3927 sec 3.4 says to "run the algorithm independently on
 * each interface". So the comparison an arriving packet is tested against is this interface's own
 * address, and a second interface is a second borrow.
 *
 * @var AcdStartArgs::mac     this interface's 48-bit address, IDEMIP_ARP_HLN_ETHERNET octets
 * @var AcdStartArgs::ipaddr  the address being claimed, which becomes an ARP Probe's 'target IP
 *                            address'
 * @var AcdStartArgs::rand    a random word the delay over [0, PROBE_WAIT] is drawn from
 * @var AcdStartArgs::now_ms  the millisecond clock that delay is added to
 * @var AcdStartArgs::defense which of sec 2.4's (a), (b) and (c) this address answers a conflict with
 */
typedef struct
{
    const uint8_t *mac;
    uint32_t ipaddr;
    uint32_t rand;
    uint32_t now_ms;
    IdemIpAcdDefense defense;
} AcdStartArgs;

/**
 * @brief What an arriving ARP packet takes.
 *
 * RFC 5227 sec 1.2 leaves RFC 826's reception rules alone and adds "an additional trivial test that
 * should be performed on each received ARP packet", so every ARP packet on this interface, Request
 * and Reply alike, comes through here.
 *
 * @var AcdArpInArgs::packet  IDEMIP_ARP_LEN octets, the payload behind the Ethernet header
 * @var AcdArpInArgs::now_ms  the millisecond clock a defense is timed against
 * @var AcdArpInArgs::rand    a random word a restarted probe delay is drawn from
 */
typedef struct
{
    const uint8_t *packet;
    uint32_t now_ms;
    uint32_t rand;
} AcdArpInArgs;

/**
 * @brief What a tick takes: the clock every deadline is compared against, and a random word.
 *
 * RFC 5227 sec 2.1.1 spaces each probe "randomly and uniformly, PROBE_MIN to PROBE_MAX seconds
 * apart", so a tick that sends a probe also draws the next gap.
 */
typedef struct
{
    uint32_t now_ms;
    uint32_t rand;
} AcdTickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var AcdIo::start_args   the address start claims and how it is defended
 * @var AcdIo::arp_in_args  the arriving ARP packet
 * @var AcdIo::tick_args    the clock a tick fires deadlines against
 * @var AcdIo::status       what the call reports: OK, BUSY, or ERR
 * @var AcdIo::ipaddr       the address in the machine, sec 2.1.1's 'target IP address' of a Probe
 * @var AcdIo::deadline_ms  when the next probe, announcement or attempt is due
 * @var AcdIo::state        where the machine is over that address
 * @var AcdIo::sent         probes or announcements sent in this state, against PROBE_NUM or
 *                          ANNOUNCE_NUM
 * @var AcdIo::conflicts    conflicts counted on this interface, against MAX_CONFLICTS
 * @var AcdIo::send_probe   an ARP Probe is due: sec 1.1 an ARP Request with an all-zero 'sender IP
 *                          address' and @ref AcdIo::ipaddr as the 'target IP address'
 * @var AcdIo::send_announce an ARP Announcement is due: sec 1.1 the same packet with both the sender
 *                          and target IP address fields holding @ref AcdIo::ipaddr
 * @var AcdIo::conflict     the packet was a conflicting ARP packet as sec 2.4 defines one
 * @var AcdIo::abandon      sec 2.4 requires the address be given up and the configuring agent told
 */
typedef struct
{
    AcdStartArgs start_args;
    AcdArpInArgs arp_in_args;
    AcdTickArgs tick_args;

    uint32_t ipaddr;
    uint32_t deadline_ms;
    IdemIpStatus status;
    IdemIpAcdState state;
    uint8_t sent;
    uint8_t conflicts;
    idemip_bool send_probe;
    idemip_bool send_announce;
    idemip_bool conflict;
    idemip_bool abandon;
} AcdIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only the
// map is public.
//
// This unit holds no table, so IDEMIP_ACD_CTX_BYTES is the whole borrow and covers the operand block
// and the context together, the way IDEMIP_PHY_BORROW covers both.

#define IDEMIP_ACD_OFF_IO 0u ///< the operand and result block
#define IDEMIP_ACD_OFF_CTX (IDEMIP_ACD_OFF_IO + IDEMIP_ROUND_UP(sizeof(AcdIo), IDEMIP_ALIGN))
#define IDEMIP_ACD_OFF_END (IDEMIP_ACD_OFF_IO + IDEMIP_ACD_CTX_BYTES)

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_ACD_IO(w) ((AcdIo *)(void *)((w) + IDEMIP_ACD_OFF_IO))

/**
 * @brief The RFC 5227 probe, announce and defend machine.
 *
 *   Acd.clear(work);
 *   IDEMIP_ACD_IO(work)->start_args.mac = link_mac;
 *   IDEMIP_ACD_IO(work)->start_args.ipaddr = candidate;
 *   IDEMIP_ACD_IO(work)->start_args.defense = IDEMIP_ACD_DEFEND_ONCE;
 *   Acd.start(work);
 *   if (IDEMIP_ACD_IO(work)->send_probe) { ... }
 *
 * @c work is IDEMIP_ACD_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the interface, so two
 * interfaces are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * A borrow is refused until @ref AcdNs::clear has run on it: clear zeroes the context and leaves the
 * mark that says these bytes are this module's. It does not touch the operand block.
 *
 * Nothing here blocks. An entry whose deadline has not arrived reports IDEMIP_BUSY, since the same
 * call on a later tick makes progress. A bad argument, an uncleared borrow or the wrong state reports
 * IDEMIP_ERR.
 *
 * @var AcdNs::clear   zero the context and mark the borrow cleared
 * @var AcdNs::start   claim an address: sec 2.1 "MUST test to see if the address is already in use,
 *                     by broadcasting ARP Probe packets"
 * @var AcdNs::stop    cease using the address, which sec 2.4 (a) permits at any time
 * @var AcdNs::arp_in  one received ARP packet against sec 2.1.1's probe tests and sec 2.4's ongoing
 *                     test
 * @var AcdNs::tick    fire the deadline that has passed: the next probe, the next announcement, or
 *                     the end of a RATE_LIMIT_INTERVAL wait
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const start)(uint8_t *restrict work);
    void (*const stop)(uint8_t *restrict work);
    void (*const arp_in)(uint8_t *restrict work);
    void (*const tick)(uint8_t *restrict work);
} AcdNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const AcdNs Acd;

// RFC 5227 sec 1.1 prints PROBE_MIN 1 second and PROBE_MAX 2 seconds, and sec 2.1.1 spaces each probe
// "randomly and uniformly, PROBE_MIN to PROBE_MAX seconds apart", so the span between them is what a
// random word is masked against.
static_assert(IDEMIP_ACD_PROBE_MAX_MS > IDEMIP_ACD_PROBE_MIN_MS,
              "RFC 5227 sec 1.1 puts PROBE_MAX above PROBE_MIN: each probe gap is drawn between them");

// sec 2.1.1 counts probes against PROBE_NUM and sec 2.3 announcements against ANNOUNCE_NUM, both held
// in one octet of the operand block.
static_assert(IDEMIP_ACD_PROBE_NUM <= 0xFFu && IDEMIP_ACD_ANNOUNCE_NUM <= 0xFFu,
              "PROBE_NUM and ANNOUNCE_NUM are counted in one octet");

// sec 2.1.1 counts conflicts against MAX_CONFLICTS, which is also one octet.
static_assert(IDEMIP_ACD_MAX_CONFLICTS <= 0xFFu, "MAX_CONFLICTS is counted in one octet");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_ACD_H
