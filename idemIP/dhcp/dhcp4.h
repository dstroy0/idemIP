// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dhcp4.h
 * @brief The RFC 2131 lease machine: the sec 4.4 client states, and what each entry takes.
 *
 * The message octets are never in this borrow. An arriving message is read where the engine left
 * it, and an outgoing one is built into the buffer the caller claimed, so what lives here is the
 * sec 4.4 state, the sec 4.1 'xid' replies are matched on, and the sec 4.4.5 lease times.
 *
 * The randomness RFC 2131 sec 4.1 requires of 'xid' and of the retransmission delay arrives as an
 * operand, so an entry stays a function of the borrow alone.
 */

#ifndef IDEMIP_DHCP4_H
#define IDEMIP_DHCP4_H

#include "idemIP/ip/ipv4.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// The message on the wire (RFC 2131 sec 2, Figure 1 and Table 1)
// ---------------------------------------------------------------------------

#define IDEMIP_DHCP4_MSG_OFF_OP 0u      ///< op (1): 1 = BOOTREQUEST, 2 = BOOTREPLY
#define IDEMIP_DHCP4_MSG_OFF_HTYPE 1u   ///< htype (1): hardware address type
#define IDEMIP_DHCP4_MSG_OFF_HLEN 2u    ///< hlen (1): hardware address length
#define IDEMIP_DHCP4_MSG_OFF_HOPS 3u    ///< hops (1): zero from a client
#define IDEMIP_DHCP4_MSG_OFF_XID 4u     ///< xid (4): transaction ID
#define IDEMIP_DHCP4_MSG_OFF_SECS 8u    ///< secs (2): seconds since acquisition began
#define IDEMIP_DHCP4_MSG_OFF_FLAGS 10u  ///< flags (2): the Figure 2 BROADCAST bit and MBZ
#define IDEMIP_DHCP4_MSG_OFF_CIADDR 12u ///< ciaddr (4): client IP address
#define IDEMIP_DHCP4_MSG_OFF_YIADDR 16u ///< yiaddr (4): 'your' (client) IP address
#define IDEMIP_DHCP4_MSG_OFF_SIADDR 20u ///< siaddr (4): next server in bootstrap
#define IDEMIP_DHCP4_MSG_OFF_GIADDR 24u ///< giaddr (4): relay agent IP address
#define IDEMIP_DHCP4_MSG_OFF_CHADDR 28u ///< chaddr (16): client hardware address
#define IDEMIP_DHCP4_MSG_OFF_SNAME 44u  ///< sname (64): optional server host name
#define IDEMIP_DHCP4_MSG_OFF_FILE 108u  ///< file (128): boot file name
#define IDEMIP_DHCP4_MSG_OFF_COOKIE 236u  ///< the four-octet magic cookie opening 'options'
#define IDEMIP_DHCP4_MSG_OFF_OPTIONS 240u ///< the first option, after the cookie

/** @brief Octets of chaddr the message carries (RFC 2131 sec 2, Table 1). */
#define IDEMIP_DHCP4_CHADDR_LEN 16u

/** @brief Octets before the first option, the cookie included. */
#define IDEMIP_DHCP4_FIXED_LEN IDEMIP_DHCP4_MSG_OFF_OPTIONS

/**
 * @brief RFC 2132 sec 3: the cookie is "dotted decimal 99.130.83.99 (or hexadecimal number
 * 63.82.53.63)".
 */
#define IDEMIP_DHCP4_MAGIC_COOKIE 0x63825363u

/** @brief op (1). RFC 2131 sec 2, Table 1: "1 = BOOTREQUEST, 2 = BOOTREPLY". */
#define IDEMIP_DHCP4_OP_BOOTREQUEST 1u
#define IDEMIP_DHCP4_OP_BOOTREPLY 2u

/** @brief flags (2). RFC 2131 sec 2, Figure 2: "The leftmost bit is defined as the BROADCAST (B) flag". */
#define IDEMIP_DHCP4_FLAG_BROADCAST 0x8000u

/**
 * @brief The ports. RFC 2131 sec 4.1: messages to a server go to "the 'DHCP server' port (67)",
 * and from a server to "the 'DHCP client' port (68)".
 */
#define IDEMIP_DHCP4_PORT_SERVER 67u
#define IDEMIP_DHCP4_PORT_CLIENT 68u

/**
 * @brief RFC 2131 sec 2: "a DHCP client must be prepared to receive a message of up to 576 octets",
 * which is also RFC 2132 sec 9.10's "minimum legal value" for the maximum message size option.
 */
#define IDEMIP_DHCP4_MSG_MIN 576u

// ---------------------------------------------------------------------------
// Options (RFC 2132)
// ---------------------------------------------------------------------------

#define IDEMIP_DHCP4_OPT_PAD 0u           ///< sec 3.1, length 1
#define IDEMIP_DHCP4_OPT_SUBNET_MASK 1u   ///< sec 3.3, length 4
#define IDEMIP_DHCP4_OPT_ROUTER 3u        ///< sec 3.5, a multiple of 4
#define IDEMIP_DHCP4_OPT_DNS_SERVER 6u    ///< sec 3.8, a multiple of 4
#define IDEMIP_DHCP4_OPT_REQUESTED_IP 50u ///< sec 9.1, length 4
#define IDEMIP_DHCP4_OPT_LEASE_TIME 51u   ///< sec 9.2, length 4, seconds
#define IDEMIP_DHCP4_OPT_OVERLOAD 52u     ///< sec 9.3, 'sname' and 'file' carry options
#define IDEMIP_DHCP4_OPT_MSG_TYPE 53u     ///< sec 9.6, length 1
#define IDEMIP_DHCP4_OPT_SERVER_ID 54u    ///< sec 9.7, length 4
#define IDEMIP_DHCP4_OPT_PARAM_LIST 55u   ///< sec 9.8, one octet per requested code
#define IDEMIP_DHCP4_OPT_MESSAGE 56u      ///< sec 9.9, NVT ASCII text
#define IDEMIP_DHCP4_OPT_MAX_MSG_SIZE 57u ///< sec 9.10, length 2
#define IDEMIP_DHCP4_OPT_T1 58u           ///< sec 9.11, length 4, seconds
#define IDEMIP_DHCP4_OPT_T2 59u           ///< sec 9.12, length 4, seconds
#define IDEMIP_DHCP4_OPT_CLIENT_ID 61u    ///< sec 9.14, a type octet then the identifier
#define IDEMIP_DHCP4_OPT_END 255u         ///< sec 3.2, length 1

/** @brief The option 53 values, RFC 2132 sec 9.6. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DHCP4_DISCOVER = 1,
    IDEMIP_DHCP4_OFFER = 2,
    IDEMIP_DHCP4_REQUEST = 3,
    IDEMIP_DHCP4_DECLINE = 4,
    IDEMIP_DHCP4_ACK = 5,
    IDEMIP_DHCP4_NAK = 6,
    IDEMIP_DHCP4_RELEASE = 7,
    IDEMIP_DHCP4_INFORM = 8,
} IdemIpDhcp4MsgType;

/**
 * @brief The client states of RFC 2131 sec 4.4, Figure 5, named as the figure names them.
 *
 * A zeroed borrow is in INIT, which sec 4.4.1 states the client begins in.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DHCP4_INIT = 0,    ///< sec 4.4.1: "The client begins in INIT state"
    IDEMIP_DHCP4_SELECTING,   ///< DHCPDISCOVER sent, DHCPOFFER replies collected
    IDEMIP_DHCP4_REQUESTING,  ///< an offer selected, DHCPREQUEST sent
    IDEMIP_DHCP4_BOUND,       ///< lease recorded, timers T1 and T2 set
    IDEMIP_DHCP4_RENEWING,    ///< T1 expired, DHCPREQUEST unicast to the leasing server
    IDEMIP_DHCP4_REBINDING,   ///< T2 expired, DHCPREQUEST broadcast to any server
    IDEMIP_DHCP4_INIT_REBOOT, ///< sec 4.4.2, a known address to verify
    IDEMIP_DHCP4_REBOOTING,   ///< DHCPREQUEST sent from INIT-REBOOT
} IdemIpDhcp4State;

/**
 * @brief What one lease machine is configured with, in the caller's rodata.
 *
 * @var IdemIpDhcp4Cfg::chaddr    'chaddr', @ref IdemIpDhcp4Cfg::hlen octets (RFC 2131 sec 2)
 * @var IdemIpDhcp4Cfg::lease_s   the option 51 lease the client asks for, 0 to ask for none
 * @var IdemIpDhcp4Cfg::netif     the interface index this machine configures
 * @var IdemIpDhcp4Cfg::htype     'htype', an ARP hardware type
 * @var IdemIpDhcp4Cfg::hlen      'hlen', octets of 'chaddr'
 * @var IdemIpDhcp4Cfg::broadcast sets the sec 4.1 BROADCAST bit in 'flags'
 */
typedef struct
{
    const uint8_t *chaddr;
    uint32_t lease_s;
    uint8_t netif;
    uint8_t htype;
    uint8_t hlen;
    idemip_bool broadcast;
} IdemIpDhcp4Cfg;

/** @brief What bind takes. */
typedef struct
{
    const IdemIpDhcp4Cfg *cfg;
} Dhcp4BindArgs;

/**
 * @brief What start takes.
 *
 * @var Dhcp4StartArgs::xid    the sec 4.1 'xid', "a random number chosen by the client"
 * @var Dhcp4StartArgs::now_ms the millisecond clock deadlines are measured against
 * @var Dhcp4StartArgs::rand   the word the sec 4.4.1 one-to-ten-second first delay is drawn from
 */
typedef struct
{
    uint32_t xid;
    uint32_t now_ms;
    uint32_t rand;
} Dhcp4StartArgs;

/**
 * @brief What input takes: one received message, where it lies.
 *
 * @var Dhcp4InputArgs::msg the message octets, IDEMIP_DHCP4_FIXED_LEN or more
 * @var Dhcp4InputArgs::len how many of them there are
 * @var Dhcp4InputArgs::src the IPv4 source address the datagram carried
 */
typedef struct
{
    const uint8_t *msg;
    size_t len;
    uint32_t src;
} Dhcp4InputArgs;

/**
 * @brief What build takes: the caller's buffer to write the next message into.
 *
 * @var Dhcp4BuildArgs::out the buffer, IDEMIP_DHCP4_FIXED_LEN or more
 * @var Dhcp4BuildArgs::cap octets of it
 */
typedef struct
{
    uint8_t *out;
    size_t cap;
} Dhcp4BuildArgs;

/**
 * @brief What tick takes.
 *
 * @var Dhcp4TickArgs::now_ms the millisecond clock
 * @var Dhcp4TickArgs::rand   the word the sec 4.1 retransmission jitter is drawn from
 */
typedef struct
{
    uint32_t now_ms;
    uint32_t rand;
} Dhcp4TickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns, and two interfaces share no byte of it.
 *
 * @var Dhcp4Io::bind_args   the configuration this machine runs on
 * @var Dhcp4Io::start_args  the transaction id, the clock, and the first delay's random word
 * @var Dhcp4Io::input_args  one received message
 * @var Dhcp4Io::build_args  the buffer the next message is built into
 * @var Dhcp4Io::tick_args   the clock, and the backoff's random word
 * @var Dhcp4Io::status      what the call reports: OK, BUSY, or ERR
 * @var Dhcp4Io::state       the sec 4.4 state the machine is in
 * @var Dhcp4Io::msg_type    the option 53 value input read, or build wrote, 0 when none
 * @var Dhcp4Io::xid         the 'xid' replies are matched against
 * @var Dhcp4Io::offered_ip  'yiaddr' from the offer or the ack
 * @var Dhcp4Io::subnet_mask option 1
 * @var Dhcp4Io::router      option 3, the first address
 * @var Dhcp4Io::server_id   option 54, the server a unicast request goes to
 * @var Dhcp4Io::lease_s     option 51, seconds
 * @var Dhcp4Io::t1_s        option 58, seconds, sec 4.4.5's T1
 * @var Dhcp4Io::t2_s        option 59, seconds, sec 4.4.5's T2
 * @var Dhcp4Io::dns         option 6, in the caller's message octets, 4 per address
 * @var Dhcp4Io::dns_count   addresses in option 6
 * @var Dhcp4Io::len         octets build wrote
 * @var Dhcp4Io::dst         where build's message goes: 0xFFFFFFFF, or the server
 * @var Dhcp4Io::dst_port    IDEMIP_DHCP4_PORT_SERVER
 * @var Dhcp4Io::src_port    IDEMIP_DHCP4_PORT_CLIENT
 */
typedef struct
{
    Dhcp4BindArgs bind_args;
    Dhcp4StartArgs start_args;
    Dhcp4InputArgs input_args;
    Dhcp4BuildArgs build_args;
    Dhcp4TickArgs tick_args;

    IdemIpStatus status;
    IdemIpDhcp4State state;
    uint8_t msg_type;
    uint32_t xid;
    uint32_t offered_ip;
    uint32_t subnet_mask;
    uint32_t router;
    uint32_t server_id;
    uint32_t lease_s;
    uint32_t t1_s;
    uint32_t t2_s;
    const uint8_t *dns;
    uint8_t dns_count;
    size_t len;
    uint32_t dst;
    uint16_t dst_port;
    uint16_t src_port;
} Dhcp4Io;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The operand block and the context share the
// IDEMIP_DHCP4_CTX_BYTES octets this unit keeps, there being no table.

#define IDEMIP_DHCP4_OFF_IO 0u ///< the operand and result block
#define IDEMIP_DHCP4_OFF_CTX IDEMIP_ROUND_UP(IDEMIP_DHCP4_OFF_IO + sizeof(Dhcp4Io), IDEMIP_ALIGN)

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_DHCP4_IO(w) ((Dhcp4Io *)(void *)((w) + IDEMIP_DHCP4_OFF_IO))

/**
 * @brief One RFC 2131 lease machine.
 *
 *   Dhcp4.clear(work);
 *   IDEMIP_DHCP4_IO(work)->bind_args.cfg = &my_cfg;
 *   Dhcp4.bind(work);
 *   IDEMIP_DHCP4_IO(work)->start_args.xid = my_random_word;
 *   Dhcp4.start(work);
 *   Dhcp4.build(work);
 *   if (IDEMIP_DHCP4_IO(work)->status == IDEMIP_OK) { send IDEMIP_DHCP4_IO(work)->len octets }
 *
 * @c work is IDEMIP_DHCP4_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. RFC 2131 runs one machine per
 * interface, so the borrow IS the interface and two of them share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata
 * and the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry with no message to give or nothing yet to act on reports
 * IDEMIP_BUSY and returns, and the caller comes back on a later tick.
 *
 * @var Dhcp4Ns::clear   zero every byte of the borrow, so it runs before the operands are set
 * @var Dhcp4Ns::bind    take the configuration, after checking every member is present
 * @var Dhcp4Ns::start   leave INIT and form a DHCPDISCOVER (sec 4.4.1)
 * @var Dhcp4Ns::stop    halt the machine and return to INIT (sec 4.4.5)
 * @var Dhcp4Ns::input   take one received message, matched on 'xid' (sec 4.1)
 * @var Dhcp4Ns::build   write the message the state owes into the caller's buffer. BUSY when
 *                       nothing is owed.
 * @var Dhcp4Ns::tick    run the retransmission, T1, T2 and lease deadlines (sec 4.1, sec 4.4.5)
 * @var Dhcp4Ns::release give the lease up (sec 4.4.6)
 * @var Dhcp4Ns::decline report the offered address already in use (sec 4.4.1)
 * @var Dhcp4Ns::inform  ask for parameters for an externally configured address (sec 4.4.3)
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const bind)(uint8_t *restrict work);
    void (*const start)(uint8_t *restrict work);
    void (*const stop)(uint8_t *restrict work);
    void (*const input)(uint8_t *restrict work);
    void (*const build)(uint8_t *restrict work);
    void (*const tick)(uint8_t *restrict work);
    void (*const release)(uint8_t *restrict work);
    void (*const decline)(uint8_t *restrict work);
    void (*const inform)(uint8_t *restrict work);
} Dhcp4Ns;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const Dhcp4Ns Dhcp4;

// The field chain of RFC 2131 sec 2, Figure 1, each field starting where the one before it ends.
static_assert(IDEMIP_DHCP4_MSG_OFF_CHADDR + IDEMIP_DHCP4_CHADDR_LEN == IDEMIP_DHCP4_MSG_OFF_SNAME,
              "chaddr is 16 octets and sname follows it (RFC 2131 sec 2, Figure 1)");
static_assert(IDEMIP_DHCP4_MSG_OFF_SNAME + 64u == IDEMIP_DHCP4_MSG_OFF_FILE,
              "sname is 64 octets and file follows it (RFC 2131 sec 2, Figure 1)");
static_assert(IDEMIP_DHCP4_MSG_OFF_FILE + 128u == IDEMIP_DHCP4_MSG_OFF_COOKIE,
              "file is 128 octets and the cookie follows it (RFC 2131 sec 2, Figure 1)");
static_assert(IDEMIP_DHCP4_MSG_OFF_COOKIE + 4u == IDEMIP_DHCP4_MSG_OFF_OPTIONS,
              "the magic cookie is four octets and the options follow it (RFC 2131 sec 4.1)");
static_assert(IDEMIP_DHCP4_MSG_MIN > IDEMIP_DHCP4_FIXED_LEN,
              "a 576-octet message must hold the fixed part and options (RFC 2131 sec 2)");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_DHCP4_H
