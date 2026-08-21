// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dhcp6.h
 * @brief The RFC 8415 client: the sec 18.2 exchanges, the sec 21.4 IA_NA, and the server's DUID.
 *
 * The message octets are never in this borrow. An arriving message is read where the engine left
 * it, and an outgoing one is built into the buffer the caller claimed, so what lives here is the
 * exchange state, the sec 8 transaction-id, the sec 21.4 T1 and T2, the sec 21.6 address with its
 * lifetimes, and the sec 11.1 DUID of the server the lease came from.
 *
 * The randomness RFC 8415 sec 16.1 requires of the transaction-id and sec 15 requires of RAND
 * arrives as an operand, so an entry stays a function of the borrow alone.
 */

#ifndef IDEMIP_DHCP6_H
#define IDEMIP_DHCP6_H

#include "src/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// The message on the wire (RFC 8415 sec 8, Figure 2, and sec 21.1, Figure 12)
// ---------------------------------------------------------------------------

#define IDEMIP_DHCP6_MSG_OFF_TYPE 0u    ///< msg-type, a 1-octet field
#define IDEMIP_DHCP6_MSG_OFF_XID 1u     ///< transaction-id, a 3-octet field
#define IDEMIP_DHCP6_MSG_OFF_OPTIONS 4u ///< the first option

/** @brief Octets before the first option. */
#define IDEMIP_DHCP6_FIXED_LEN IDEMIP_DHCP6_MSG_OFF_OPTIONS

/** @brief The sec 8 transaction-id is three octets, so it counts up to this and no further. */
#define IDEMIP_DHCP6_XID_MASK 0x00FFFFFFu

#define IDEMIP_DHCP6_OPT_OFF_CODE 0u ///< option-code, a 2-octet field (sec 21.1)
#define IDEMIP_DHCP6_OPT_OFF_LEN 2u  ///< option-len, the octets of option-data
#define IDEMIP_DHCP6_OPT_OFF_DATA 4u ///< option-data
#define IDEMIP_DHCP6_OPT_HDR_LEN 4u  ///< option-code and option-len together

/**
 * @brief The ports. RFC 8415 sec 7.2: "Clients listen for DHCP messages on UDP port 546.  Servers
 * and relay agents listen for DHCP messages on UDP port 547."
 */
#define IDEMIP_DHCP6_PORT_CLIENT 546u
#define IDEMIP_DHCP6_PORT_SERVER 547u

/**
 * @brief RFC 8415 sec 7.1: "All_DHCP_Relay_Agents_and_Servers (ff02::1:2)".
 *
 * The octets, as an initializer for a caller-placed or file-scope const array of
 * IDEMIP_IP6_ADDR_LEN.
 */
#define IDEMIP_DHCP6_ALL_RELAY_AGENTS_AND_SERVERS                                                                      \
    {                                                                                                                  \
        0xffu, 0x02u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0x01u, 0u, 0x02u                                      \
    }

/** @brief RFC 8415 sec 7.1: "All_DHCP_Servers (ff05::1:3)". */
#define IDEMIP_DHCP6_ALL_SERVERS                                                                                       \
    {                                                                                                                  \
        0xffu, 0x05u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0x01u, 0u, 0x03u                                      \
    }

/**
 * @brief RFC 8415 sec 7.7: "The value 0xffffffff is taken to mean 'infinity' when used as a lifetime
 * ... or a value for T1 or T2."
 */
#define IDEMIP_DHCP6_INFINITY 0xFFFFFFFFu

// ---------------------------------------------------------------------------
// Options (RFC 8415 sec 21, RFC 3646)
// ---------------------------------------------------------------------------

#define IDEMIP_DHCP6_OPT_CLIENTID 1u      ///< sec 21.2, the client's DUID
#define IDEMIP_DHCP6_OPT_SERVERID 2u      ///< sec 21.3, the server's DUID
#define IDEMIP_DHCP6_OPT_IA_NA 3u         ///< sec 21.4, IAID, T1, T2, then IA_NA-options
#define IDEMIP_DHCP6_OPT_IA_TA 4u         ///< sec 21.5, temporary addresses
#define IDEMIP_DHCP6_OPT_IAADDR 5u        ///< sec 21.6, an address with its two lifetimes
#define IDEMIP_DHCP6_OPT_ORO 6u           ///< sec 21.7, the option codes the client requests
#define IDEMIP_DHCP6_OPT_PREFERENCE 7u    ///< sec 21.8, one octet
#define IDEMIP_DHCP6_OPT_ELAPSED_TIME 8u  ///< sec 21.9, hundredths of a second
#define IDEMIP_DHCP6_OPT_STATUS_CODE 13u  ///< sec 21.13, a 2-octet code then text
#define IDEMIP_DHCP6_OPT_RAPID_COMMIT 14u ///< sec 21.14, option-len zero
#define IDEMIP_DHCP6_OPT_DNS_SERVERS 23u  ///< RFC 3646 sec 3, 16 octets per server
#define IDEMIP_DHCP6_OPT_DOMAIN_LIST 24u  ///< RFC 3646 sec 4, the search list
#define IDEMIP_DHCP6_OPT_INFO_REFRESH 32u ///< sec 21.23, seconds, Information-request only
#define IDEMIP_DHCP6_OPT_SOL_MAX_RT 82u   ///< sec 21.24, seconds
#define IDEMIP_DHCP6_OPT_INF_MAX_RT 83u   ///< sec 21.25, seconds

/** @brief Octets of the sec 21.9 elapsed-time, sec 21.13 status-code and sec 21.8 preference fields. */
#define IDEMIP_DHCP6_ELAPSED_LEN 2u
#define IDEMIP_DHCP6_STATUS_LEN 2u
#define IDEMIP_DHCP6_PREFERENCE_LEN 1u

/** @brief Octets of a sec 21.24 or sec 21.25 option-data, and of a sec 21.23 one. */
#define IDEMIP_DHCP6_MAX_RT_LEN 4u
#define IDEMIP_DHCP6_INFO_REFRESH_LEN 4u

/** @brief sec 21.8: "If the client receives a valid Advertise message that includes a Preference
 * option with a preference value of 255", it stops collecting and requests at once. */
#define IDEMIP_DHCP6_PREF_IMMEDIATE 255u

// ---------------------------------------------------------------------------
// Transmission and retransmission parameters (RFC 8415 sec 7.6, Table 1)
// ---------------------------------------------------------------------------
// Table 1 prints every timeout in seconds. Each is held here in milliseconds, so a deadline is the
// millisecond clock plus one of these and no conversion divide exists (PLAN sec 5.2).

#define IDEMIP_DHCP6_SOL_MAX_DELAY_MS 1000u    ///< Max delay of first Solicit, 1 sec
#define IDEMIP_DHCP6_SOL_TIMEOUT_MS 1000u      ///< Initial Solicit timeout, 1 sec
#define IDEMIP_DHCP6_SOL_MAX_RT_MS 3600000u    ///< Max Solicit timeout value, 3600 secs
#define IDEMIP_DHCP6_REQ_TIMEOUT_MS 1000u      ///< Initial Request timeout, 1 sec
#define IDEMIP_DHCP6_REQ_MAX_RT_MS 30000u      ///< Max Request timeout value, 30 secs
#define IDEMIP_DHCP6_REQ_MAX_RC 10u            ///< Max Request retry attempts
#define IDEMIP_DHCP6_CNF_MAX_DELAY_MS 1000u    ///< Max delay of first Confirm, 1 sec
#define IDEMIP_DHCP6_CNF_TIMEOUT_MS 1000u      ///< Initial Confirm timeout, 1 sec
#define IDEMIP_DHCP6_CNF_MAX_RT_MS 4000u       ///< Max Confirm timeout, 4 secs
#define IDEMIP_DHCP6_CNF_MAX_RD_MS 10000u      ///< Max Confirm duration, 10 secs
#define IDEMIP_DHCP6_REN_TIMEOUT_MS 10000u     ///< Initial Renew timeout, 10 secs
#define IDEMIP_DHCP6_REN_MAX_RT_MS 600000u     ///< Max Renew timeout value, 600 secs
#define IDEMIP_DHCP6_REB_TIMEOUT_MS 10000u     ///< Initial Rebind timeout, 10 secs
#define IDEMIP_DHCP6_REB_MAX_RT_MS 600000u     ///< Max Rebind timeout value, 600 secs
#define IDEMIP_DHCP6_INF_MAX_DELAY_MS 1000u    ///< Max delay of first Information-request, 1 sec
#define IDEMIP_DHCP6_INF_TIMEOUT_MS 1000u      ///< Initial Information-request timeout, 1 sec
#define IDEMIP_DHCP6_INF_MAX_RT_MS 3600000u    ///< Max Information-request timeout value, 3600 secs
#define IDEMIP_DHCP6_REL_TIMEOUT_MS 1000u      ///< Initial Release timeout, 1 sec
#define IDEMIP_DHCP6_REL_MAX_RC 4u             ///< Max Release retry attempts
#define IDEMIP_DHCP6_DEC_TIMEOUT_MS 1000u      ///< Initial Decline timeout, 1 sec
#define IDEMIP_DHCP6_DEC_MAX_RC 4u             ///< Max Decline retry attempts
#define IDEMIP_DHCP6_MAX_WAIT_TIME_MS 60000u   ///< Max required time to wait for a response, 60 secs
#define IDEMIP_DHCP6_IRT_DEFAULT_S 86400u      ///< Default information refresh time, 86400 secs
#define IDEMIP_DHCP6_IRT_MINIMUM_S 600u        ///< Min information refresh time, 600 secs

/**
 * @brief The bound a sec 21.24 or sec 21.25 override must sit inside.
 *
 * Both sections read "MUST be in this range: 60 <= 'value' <= 86400 (1 day)", and both add that a
 * client "MUST ignore any ... option values that are less than 60 or more than 86400".
 */
#define IDEMIP_DHCP6_MAX_RT_MIN_S 60u
#define IDEMIP_DHCP6_MAX_RT_MAX_S 86400u

/**
 * @brief The sec 15 RAND factor, quantized.
 *
 * sec 15 puts RAND at "a random number chosen with a uniform distribution between -0.1 and +0.1".
 * A tenth has no exact binary form, so RAND is held as a signed @c k >> IDEMIP_DHCP6_RAND_SHIFT with
 * @c k drawn over 0 through IDEMIP_DHCP6_RAND_K_MAX: the largest magnitude is 102/1024, which is
 * 0.099609375, and the term is @c (x*k)>>10 with no divide.
 */
#define IDEMIP_DHCP6_RAND_SHIFT 10u
#define IDEMIP_DHCP6_RAND_K_MAX 102u

/**
 * @brief The sec 21.9 elapsed-time unit, hundredths of a second, without a divide.
 *
 * floor(ms/100) is @c (ms*IDEMIP_DHCP6_CS_RECIP)>>IDEMIP_DHCP6_CS_SHIFT for every millisecond span
 * the 2-octet field can carry. sec 21.9 caps the field at 0xffff, so a span at or past
 * IDEMIP_DHCP6_ELAPSED_MAX_MS is sent as 0xffff and the identity is only needed below it.
 */
#define IDEMIP_DHCP6_CS_SHIFT 30u
#define IDEMIP_DHCP6_CS_RECIP 10737419u
#define IDEMIP_DHCP6_ELAPSED_MAX_MS 6553500u

/**
 * @brief The longest lifetime a millisecond deadline carries.
 *
 * sec 7.7 states every lifetime, T1 and T2 as an unsigned 32-bit count of seconds. A deadline here is
 * a 32-bit millisecond clock compared by signed difference, so a span stays under 2^31 milliseconds.
 * A longer lifetime is held at this value, which makes the client renew or rebind earlier than the
 * server asked and never later.
 */
#define IDEMIP_DHCP6_MAX_DEADLINE_S 2097151u

/** @brief Octets of the sec 21.4 IA_NA before its options: IAID, T1 and T2. */
#define IDEMIP_DHCP6_IA_NA_FIXED_LEN 12u

/** @brief Octets of the sec 21.6 IAADDR before its options: the address and its two lifetimes. */
#define IDEMIP_DHCP6_IAADDR_FIXED_LEN 24u

/** @brief The message types of RFC 8415 sec 7.3, "The numeric encoding for each message type". */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DHCP6_SOLICIT = 1,
    IDEMIP_DHCP6_ADVERTISE = 2,
    IDEMIP_DHCP6_REQUEST = 3,
    IDEMIP_DHCP6_CONFIRM = 4,
    IDEMIP_DHCP6_RENEW = 5,
    IDEMIP_DHCP6_REBIND = 6,
    IDEMIP_DHCP6_REPLY = 7,
    IDEMIP_DHCP6_RELEASE = 8,
    IDEMIP_DHCP6_DECLINE = 9,
    IDEMIP_DHCP6_RECONFIGURE = 10,
    IDEMIP_DHCP6_INFORMATION_REQUEST = 11,
    IDEMIP_DHCP6_RELAY_FORW = 12,
    IDEMIP_DHCP6_RELAY_REPL = 13,
} IdemIpDhcp6MsgType;

/** @brief The status codes of RFC 8415 sec 21.13, Table 3. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DHCP6_STATUS_SUCCESS = 0,
    IDEMIP_DHCP6_STATUS_UNSPEC_FAIL = 1,
    IDEMIP_DHCP6_STATUS_NO_ADDRS_AVAIL = 2,
    IDEMIP_DHCP6_STATUS_NO_BINDING = 3,
    IDEMIP_DHCP6_STATUS_NOT_ON_LINK = 4,
    IDEMIP_DHCP6_STATUS_USE_MULTICAST = 5,
    IDEMIP_DHCP6_STATUS_NO_PREFIX_AVAIL = 6,
} IdemIpDhcp6Status;

/**
 * @brief The exchange a client is in.
 *
 * RFC 8415 prints no state-transition diagram, so each state is named for the exchange the section
 * that governs it names: sec 18.2.1 Solicit, sec 18.2.2 Request, sec 18.2.3 Confirm, sec 18.2.4
 * Renew, sec 18.2.5 Rebind, sec 18.2.6 Information-request, sec 18.2.7 Release, sec 18.2.8 Decline.
 * BOUND is what sec 18.2.10.1 leaves a client in once a Reply assigns leases. A zeroed borrow is
 * IDLE, running no exchange.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DHCP6_IDLE = 0,        ///< no exchange running
    IDEMIP_DHCP6_SOLICITING,      ///< sec 18.2.1, locating servers
    IDEMIP_DHCP6_REQUESTING,      ///< sec 18.2.2, requesting leases from one server
    IDEMIP_DHCP6_CONFIRMING,      ///< sec 18.2.3, checking the addresses suit this link
    IDEMIP_DHCP6_RENEWING,        ///< sec 18.2.4, T1 reached, the assigning server contacted
    IDEMIP_DHCP6_REBINDING,       ///< sec 18.2.5, T2 reached, any server contacted
    IDEMIP_DHCP6_INFO_REQUESTING, ///< sec 18.2.6, configuration without leases
    IDEMIP_DHCP6_RELEASING,       ///< sec 18.2.7, giving leases up
    IDEMIP_DHCP6_DECLINING,       ///< sec 18.2.8, reporting an address already in use
    IDEMIP_DHCP6_BOUND,           ///< sec 18.2.10.1, leases assigned and lifetimes running; for a
                                  ///< stateless client, sec 18.2.10.4 configuration held with T1
                                  ///< carrying the sec 21.23 information-refresh-time
} IdemIpDhcp6State;

/**
 * @brief What one client is configured with, in the caller's rodata.
 *
 * @var IdemIpDhcp6Cfg::duid         the client's own DUID, sec 11.1, including the 2-octet type code
 * @var IdemIpDhcp6Cfg::iaid         the sec 21.4 IAID this client's IA_NA carries
 * @var IdemIpDhcp6Cfg::duid_len     octets of it, at most IDEMIP_DHCP6_DUID_MAX
 * @var IdemIpDhcp6Cfg::netif        the interface index this client configures
 * @var IdemIpDhcp6Cfg::stateless    sec 6.1, configuration by Information-request and no leases
 * @var IdemIpDhcp6Cfg::rapid_commit sec 21.14, the two-message Solicit and Reply exchange
 */
typedef struct
{
    const uint8_t *duid;
    uint32_t iaid;
    uint16_t duid_len;
    uint8_t netif;
    idemip_bool stateless;
    idemip_bool rapid_commit;
} IdemIpDhcp6Cfg;

/** @brief What bind takes. */
typedef struct
{
    const IdemIpDhcp6Cfg *cfg;
} Dhcp6BindArgs;

/**
 * @brief What start takes.
 *
 * @var Dhcp6StartArgs::xid    the sec 8 transaction-id, sec 16.1's "random number that cannot
 *                             easily be guessed or predicted", in the low 24 bits
 * @var Dhcp6StartArgs::now_ms the millisecond clock deadlines are measured against
 * @var Dhcp6StartArgs::rand   the word sec 18.2.1's SOL_MAX_DELAY draw is taken from
 */
typedef struct
{
    uint32_t xid;
    uint32_t now_ms;
    uint32_t rand;
} Dhcp6StartArgs;

/**
 * @brief What input takes: one received message, where it lies.
 *
 * @var Dhcp6InputArgs::msg the message octets, IDEMIP_DHCP6_FIXED_LEN or more
 * @var Dhcp6InputArgs::len how many of them there are
 * @var Dhcp6InputArgs::src the IDEMIP_IP6_ADDR_LEN octet source address the packet carried
 */
typedef struct
{
    const uint8_t *msg;
    size_t len;
    const uint8_t *src;
} Dhcp6InputArgs;

/**
 * @brief What build takes: the caller's buffer to write the next message into.
 *
 * @var Dhcp6BuildArgs::out the buffer, IDEMIP_DHCP6_FIXED_LEN or more
 * @var Dhcp6BuildArgs::cap octets of it
 */
typedef struct
{
    uint8_t *out;
    size_t cap;
} Dhcp6BuildArgs;

/**
 * @brief What tick takes.
 *
 * @var Dhcp6TickArgs::now_ms the millisecond clock
 * @var Dhcp6TickArgs::rand   the word the sec 15 RAND factor is drawn from
 */
typedef struct
{
    uint32_t now_ms;
    uint32_t rand;
} Dhcp6TickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns, and two interfaces share no byte of it.
 *
 * @var Dhcp6Io::bind_args    the configuration this client runs on
 * @var Dhcp6Io::start_args   the transaction-id, the clock, and the first delay's random word
 * @var Dhcp6Io::input_args   one received message
 * @var Dhcp6Io::build_args   the buffer the next message is built into
 * @var Dhcp6Io::tick_args    the clock, and the RAND word
 * @var Dhcp6Io::status       what the call reports: OK, BUSY, or ERR
 * @var Dhcp6Io::state        the exchange the client is in
 * @var Dhcp6Io::msg_type     the sec 7.3 type input read, or build wrote, 0 when none
 * @var Dhcp6Io::status_code  the sec 21.13 code the last Reply carried
 * @var Dhcp6Io::xid          the sec 8 transaction-id a Reply is matched against
 * @var Dhcp6Io::iaid         the sec 21.4 IAID of the IA_NA the lease is in
 * @var Dhcp6Io::addr         the sec 21.6 IPv6-address, IDEMIP_IP6_ADDR_LEN octets
 * @var Dhcp6Io::preferred_s  the sec 21.6 preferred-lifetime, seconds
 * @var Dhcp6Io::valid_s      the sec 21.6 valid-lifetime, seconds
 * @var Dhcp6Io::t1_s         the sec 21.4 T1, seconds
 * @var Dhcp6Io::t2_s         the sec 21.4 T2, seconds
 * @var Dhcp6Io::dns          the RFC 3646 sec 3 servers, in the caller's message octets, 16 each
 * @var Dhcp6Io::dns_count    servers in that option
 * @var Dhcp6Io::len          octets build wrote
 * @var Dhcp6Io::dst          where build's message goes, IDEMIP_IP6_ADDR_LEN octets
 * @var Dhcp6Io::dst_port     IDEMIP_DHCP6_PORT_SERVER
 * @var Dhcp6Io::src_port     IDEMIP_DHCP6_PORT_CLIENT
 */
typedef struct
{
    Dhcp6BindArgs bind_args;
    Dhcp6StartArgs start_args;
    Dhcp6InputArgs input_args;
    Dhcp6BuildArgs build_args;
    Dhcp6TickArgs tick_args;

    IdemIpStatus status;
    IdemIpDhcp6State state;
    uint8_t msg_type;
    uint16_t status_code;
    uint32_t xid;
    uint32_t iaid;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    uint32_t preferred_s;
    uint32_t valid_s;
    uint32_t t1_s;
    uint32_t t2_s;
    const uint8_t *dns;
    uint8_t dns_count;
    size_t len;
    uint8_t dst[IDEMIP_IP6_ADDR_LEN];
    uint16_t dst_port;
    uint16_t src_port;
} Dhcp6Io;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The operand block and the context share the
// first IDEMIP_DHCP6_CTX_BYTES octets, the region this unit keeps outside any table, and the DUID
// region follows them.

#define IDEMIP_DHCP6_OFF_IO 0u ///< the operand and result block
#define IDEMIP_DHCP6_OFF_CTX IDEMIP_ROUND_UP(IDEMIP_DHCP6_OFF_IO + sizeof(Dhcp6Io), IDEMIP_ALIGN)

/** @brief The server's DUID, opaque and up to IDEMIP_DHCP6_DUID_MAX octets (sec 11.1). */
#define IDEMIP_DHCP6_OFF_SERVER_DUID IDEMIP_DHCP6_CTX_BYTES

/** @brief Octets that region spans. */
#define IDEMIP_DHCP6_SERVER_DUID_BYTES IDEMIP_ROUND_UP(IDEMIP_DHCP6_DUID_MAX, IDEMIP_ALIGN)

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_DHCP6_IO(w) ((Dhcp6Io *)(void *)((w) + IDEMIP_DHCP6_OFF_IO))

/**
 * @brief One RFC 8415 client.
 *
 *   Dhcp6.clear(work);
 *   IDEMIP_DHCP6_IO(work)->bind_args.cfg = &my_cfg;
 *   Dhcp6.bind(work);
 *   IDEMIP_DHCP6_IO(work)->start_args.xid = my_random_word & IDEMIP_DHCP6_XID_MASK;
 *   Dhcp6.start(work);
 *   Dhcp6.build(work);
 *   if (IDEMIP_DHCP6_IO(work)->status == IDEMIP_OK) { send IDEMIP_DHCP6_IO(work)->len octets }
 *
 * @c work is IDEMIP_DHCP6_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. One client runs per interface, so
 * the borrow IS the interface and two of them share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata
 * and the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry with no message to give or nothing yet to act on reports
 * IDEMIP_BUSY and returns, and the caller comes back on a later tick.
 *
 * @var Dhcp6Ns::clear   zero every byte of the borrow, so it runs before the operands are set
 * @var Dhcp6Ns::bind    take the configuration, after checking every member is present
 * @var Dhcp6Ns::start   begin the exchange the mode calls for: Solicit (sec 18.2.1), or
 *                       Information-request when the configuration is stateless (sec 18.2.6)
 * @var Dhcp6Ns::stop    end every exchange and return to IDLE
 * @var Dhcp6Ns::input   take one received message, validated as sec 16 requires
 * @var Dhcp6Ns::build   write the message the state owes into the caller's buffer. BUSY when
 *                       nothing is owed.
 * @var Dhcp6Ns::tick    run the sec 15 retransmission timer and the sec 21.4 T1 and T2 deadlines
 * @var Dhcp6Ns::confirm ask whether the addresses still suit this link (sec 18.2.3)
 * @var Dhcp6Ns::release give the leases up (sec 18.2.7)
 * @var Dhcp6Ns::decline report an assigned address already in use (sec 18.2.8)
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const bind)(uint8_t *work);
    void (*const start)(uint8_t *work);
    void (*const stop)(uint8_t *work);
    void (*const input)(uint8_t *work);
    void (*const build)(uint8_t *work);
    void (*const tick)(uint8_t *work);
    void (*const confirm)(uint8_t *work);
    void (*const release)(uint8_t *work);
    void (*const decline)(uint8_t *work);
} Dhcp6Ns;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_dhcp6_clear(uint8_t *work);
void idemip_dhcp6_bind(uint8_t *work);
void idemip_dhcp6_start(uint8_t *work);
void idemip_dhcp6_stop(uint8_t *work);
void idemip_dhcp6_input(uint8_t *work);
void idemip_dhcp6_build(uint8_t *work);
void idemip_dhcp6_tick(uint8_t *work);
void idemip_dhcp6_confirm(uint8_t *work);
void idemip_dhcp6_release(uint8_t *work);
void idemip_dhcp6_decline(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Dhcp6.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const Dhcp6Ns Dhcp6 IDEMIP_UNUSED = {
    .clear = idemip_dhcp6_clear,
    .bind = idemip_dhcp6_bind,
    .start = idemip_dhcp6_start,
    .stop = idemip_dhcp6_stop,
    .input = idemip_dhcp6_input,
    .build = idemip_dhcp6_build,
    .tick = idemip_dhcp6_tick,
    .confirm = idemip_dhcp6_confirm,
    .release = idemip_dhcp6_release,
    .decline = idemip_dhcp6_decline};
// The field chain of RFC 8415 sec 8, Figure 2, and sec 21.1, Figure 12.
static_assert(IDEMIP_DHCP6_MSG_OFF_XID + 3u == IDEMIP_DHCP6_MSG_OFF_OPTIONS,
              "transaction-id is three octets and the options follow it (RFC 8415 sec 8)");
static_assert(IDEMIP_DHCP6_OPT_OFF_LEN + 2u == IDEMIP_DHCP6_OPT_OFF_DATA &&
                  IDEMIP_DHCP6_OPT_OFF_DATA == IDEMIP_DHCP6_OPT_HDR_LEN,
              "option-code and option-len are two octets each (RFC 8415 sec 21.1)");
// sec 21.4: "option-len 12 + length of IA_NA-options field", and sec 21.6: "24 + length of
// IAaddr-options field".
static_assert(IDEMIP_DHCP6_IA_NA_FIXED_LEN == 12u && IDEMIP_DHCP6_IAADDR_FIXED_LEN == 24u,
              "the IA_NA and IAADDR fixed parts are 12 and 24 octets (RFC 8415 sec 21.4, sec 21.6)");
static_assert(IDEMIP_DHCP6_IAADDR_FIXED_LEN == IDEMIP_IP6_ADDR_LEN + 8u,
              "an IAADDR is one address and two 4-octet lifetimes (RFC 8415 sec 21.6)");

// sec 15 bounds RAND at a tenth either way, so the quantized magnitude stays under it: k at its
// largest times ten is short of one whole 1 << IDEMIP_DHCP6_RAND_SHIFT.
static_assert(IDEMIP_DHCP6_RAND_K_MAX * 10u < (1u << IDEMIP_DHCP6_RAND_SHIFT),
              "the quantized RAND magnitude must stay inside RFC 8415 sec 15's 0.1");
// The reciprocal is the rounded-up 2^30/100, and the accumulated error over the whole elapsed-time
// range stays under one unit, so the shift lands on floor(ms/100) exactly.
static_assert(IDEMIP_DHCP6_CS_RECIP == ((1u << IDEMIP_DHCP6_CS_SHIFT) / 100u) + 1u,
              "IDEMIP_DHCP6_CS_RECIP is the rounded-up reciprocal of the sec 21.9 hundredth");
static_assert((uint64_t)((IDEMIP_DHCP6_CS_RECIP * 100u) - (1u << IDEMIP_DHCP6_CS_SHIFT)) *
                      (uint64_t)IDEMIP_DHCP6_ELAPSED_MAX_MS <=
                  ((uint64_t)1u << IDEMIP_DHCP6_CS_SHIFT),
              "the reciprocal multiply drifts off floor(ms/100) inside the sec 21.9 range");
static_assert(IDEMIP_DHCP6_ELAPSED_MAX_MS == 0xFFFFu * 100u,
              "sec 21.9 caps elapsed-time at 0xffff hundredths of a second");
// A deadline is compared by signed difference, so the widest span it holds stays under half the clock.
static_assert(IDEMIP_DHCP6_MAX_DEADLINE_S * 1000u < 0x80000000u,
              "IDEMIP_DHCP6_MAX_DEADLINE_S in milliseconds must stay under 2^31");
// sec 7.6 Table 1 in milliseconds, against the seconds it prints.
static_assert(IDEMIP_DHCP6_SOL_MAX_RT_MS == 3600u * 1000u && IDEMIP_DHCP6_REQ_MAX_RT_MS == 30u * 1000u &&
                  IDEMIP_DHCP6_CNF_MAX_RT_MS == 4u * 1000u && IDEMIP_DHCP6_CNF_MAX_RD_MS == 10u * 1000u &&
                  IDEMIP_DHCP6_REN_TIMEOUT_MS == 10u * 1000u && IDEMIP_DHCP6_REN_MAX_RT_MS == 600u * 1000u &&
                  IDEMIP_DHCP6_REB_TIMEOUT_MS == 10u * 1000u && IDEMIP_DHCP6_REB_MAX_RT_MS == 600u * 1000u &&
                  IDEMIP_DHCP6_INF_MAX_RT_MS == 3600u * 1000u && IDEMIP_DHCP6_MAX_WAIT_TIME_MS == 60u * 1000u,
              "the sec 7.6 Table 1 timeouts in milliseconds must match the seconds it prints");
// The largest RAND term is over a whole MRT, so the product stays inside 32 bits.
static_assert(IDEMIP_DHCP6_SOL_MAX_RT_MS <= (0xFFFFFFFFu / IDEMIP_DHCP6_RAND_K_MAX),
              "the sec 15 RAND product over the widest MRT must stay inside 32 bits");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_DHCP6_H
