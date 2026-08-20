// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dns.h
 * @brief The RFC 1035 stub resolver: the query table, the answer cache, the names, and the servers.
 *
 * The message octets are never in this borrow. An arriving response is read where the engine left
 * it, and a question is built into the buffer the caller claimed, so what lives here is the
 * outstanding questions, the answers with their TTLs, the names both index, and the servers.
 *
 * RFC 5452 sec 9.2 requires "an unpredictable query ID" and "an unpredictable source port". Both
 * arrive as operands the caller's generator fills, so an entry stays a function of the borrow alone
 * and the resolver holds no counter an attacker could step.
 */

#ifndef IDEMIP_DNS_H
#define IDEMIP_DNS_H

#include "src/idemip_config.h"

#if IDEMIP_ENABLE_UDP

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// The message header (RFC 1035 sec 4.1.1)
// ---------------------------------------------------------------------------

#define IDEMIP_DNS_HDR_OFF_ID 0u      ///< ID, "A 16 bit identifier"
#define IDEMIP_DNS_HDR_OFF_FLAGS 2u   ///< QR, Opcode, AA, TC, RD, RA, Z and RCODE
#define IDEMIP_DNS_HDR_OFF_QDCOUNT 4u ///< entries in the question section
#define IDEMIP_DNS_HDR_OFF_ANCOUNT 6u ///< resource records in the answer section
#define IDEMIP_DNS_HDR_OFF_NSCOUNT 8u ///< records in the authority section
#define IDEMIP_DNS_HDR_OFF_ARCOUNT 10u ///< records in the additional section
#define IDEMIP_DNS_HDR_LEN 12u         ///< the header, the question section follows

// The bits of the flags word, the diagram in sec 4.1.1 numbering bit 0 as the most significant.
#define IDEMIP_DNS_FLAG_QR 0x8000u     ///< query (0) or response (1)
#define IDEMIP_DNS_FLAG_OPCODE 0x7800u ///< "A four bit field that specifies kind of query"
#define IDEMIP_DNS_FLAG_AA 0x0400u     ///< Authoritative Answer
#define IDEMIP_DNS_FLAG_TC 0x0200u     ///< TrunCation
#define IDEMIP_DNS_FLAG_RD 0x0100u     ///< Recursion Desired
#define IDEMIP_DNS_FLAG_RA 0x0080u     ///< Recursion Available
#define IDEMIP_DNS_FLAG_Z 0x0070u      ///< "Reserved for future use.  Must be zero"
#define IDEMIP_DNS_FLAG_RCODE 0x000Fu  ///< Response code
#define IDEMIP_DNS_OPCODE_SHIFT 11u    ///< bits the Opcode sits above

/** @brief Opcode (RFC 1035 sec 4.1.1): "0 a standard query (QUERY)". */
#define IDEMIP_DNS_OPCODE_QUERY 0u

/** @brief RFC 1035 sec 3.2.4: "IN 1 the Internet". */
#define IDEMIP_DNS_CLASS_IN 1u

/**
 * @brief RFC 1035 sec 4.1.4: a label length octet with both high bits set opens a pointer, and
 * "the OFFSET field specifies an offset from the start of the message".
 */
#define IDEMIP_DNS_LABEL_PTR 0xC0u
#define IDEMIP_DNS_LABEL_PTR_MASK 0x3FFFu

/** @brief RFC 1035 sec 2.3.4 size limits: "labels 63 octets or less". */
#define IDEMIP_DNS_LABEL_MAX 63u

/** @brief RFC 1035 sec 4.2.1: "Messages sent using UDP user server port 53 (decimal)." */
#define IDEMIP_DNS_PORT 53u

/**
 * @brief RFC 1035 sec 4.2.1: "Messages carried by UDP are restricted to 512 bytes (not counting the
 * IP or UDP headers)."
 */
#define IDEMIP_DNS_MSG_MAX 512u

/** @brief Octets of QTYPE and QCLASS behind a QNAME (RFC 1035 sec 4.1.2). */
#define IDEMIP_DNS_QFIXED_LEN 4u

/** @brief Octets of TYPE, CLASS, TTL and RDLENGTH behind a record's NAME (RFC 1035 sec 4.1.3). */
#define IDEMIP_DNS_RR_FIXED_LEN 10u

/** @brief Offsets of those fields from the end of a record's NAME (RFC 1035 sec 4.1.3). */
#define IDEMIP_DNS_RR_OFF_TYPE 0u
#define IDEMIP_DNS_RR_OFF_CLASS 2u
#define IDEMIP_DNS_RR_OFF_TTL 4u
#define IDEMIP_DNS_RR_OFF_RDLENGTH 8u

/**
 * @brief RFC 1035 sec 3.1: "the total length of a domain name (i.e., label octets and label length
 * octets) is restricted to 255 octets or less".
 */
#define IDEMIP_DNS_NAME_WIRE_MAX 255u

/**
 * @brief Octets of the dotted form whose sec 3.1 label encoding still fits
 * IDEMIP_DNS_NAME_WIRE_MAX: one length octet replaces each separator and one root octet is added.
 */
#define IDEMIP_DNS_NAME_TEXT_MAX (IDEMIP_DNS_NAME_WIRE_MAX - 2u)

/**
 * @brief Pointers one name may be assembled from before it is refused (RFC 1035 sec 4.1.4).
 *
 * A name spans at most IDEMIP_DNS_NAME_WIRE_MAX octets (sec 3.1) and a pointer hop yields at least
 * one length octet and one label octet, so a name needing more hops than half that bound cannot be
 * a name. A hop also has to land strictly below the pointer that made it, which sec 4.1.4's "a
 * pointer to a prior occurance of the same name" states.
 */
#define IDEMIP_DNS_PTR_HOPS_MAX (IDEMIP_DNS_NAME_WIRE_MAX >> 1)

/**
 * @brief RFC 2181 sec 8: a TTL "received with the most significant bit set" is taken as zero.
 */
#define IDEMIP_DNS_TTL_SIGN 0x80000000u

/**
 * @brief Seconds an answer is held at most.
 *
 * RFC 2181 sec 8: "Implementations are always free to place an upper bound on any TTL received, and
 * treat any larger values as if they were that upper bound." lwIP DNS_MAX_TTL is the same 604800.
 */
#ifndef IDEMIP_DNS_TTL_MAX_S
#define IDEMIP_DNS_TTL_MAX_S 604800u
#endif

/** @brief Milliseconds a second holds, the factor a TTL becomes a deadline by. */
#define IDEMIP_DNS_MS_PER_S 1000u

/**
 * @brief Milliseconds between two tries of one question.
 *
 * RFC 1035 sec 4.2.1: "the minimum retransmission interval should be 2-5 seconds".
 */
/**
 * @brief The upper bound RFC 1123 sec 6.1.3.3 (5) puts on the backoff.
 *
 * "the retry interval SHOULD be constrained by an exponential backoff algorithm, and SHOULD also
 * have upper and lower bounds." IDEMIP_DNS_RETRY_MS is the lower bound and this is the upper.
 */
#ifndef IDEMIP_DNS_RETRY_MAX_MS
#define IDEMIP_DNS_RETRY_MAX_MS 32000u
#endif

/**
 * @brief Seconds a negative response is held.
 *
 * RFC 1123 sec 6.1.3.3 (4) asks that a response saying the name, or data of the type, does not exist
 * be cached; item (3) of the same section gives the scale for the related case as "of the order of
 * minutes". A response carries an SOA MINIMUM this could take instead, which is not parsed here, so
 * this is the bounded default that stands in for it.
 */
#ifndef IDEMIP_DNS_NEG_TTL_S
#define IDEMIP_DNS_NEG_TTL_S 300u
#endif

#ifndef IDEMIP_DNS_RETRY_MS
#define IDEMIP_DNS_RETRY_MS 2000u
#endif

/**
 * @brief The lowest source port a question may leave from, port 53 aside.
 *
 * RFC 5452 sec 9.2: "Use an unpredictable source port for outgoing queries from the range of
 * available ports (53, or 1024 and above)".
 */
#define IDEMIP_DNS_SRC_PORT_MIN 1024u

/** @brief Octets one answer address spans: RFC 3596 sec 2.2's 128-bit AAAA is the widest. */
#define IDEMIP_DNS_ADDR_LEN 16u

/** @brief Octets of RDATA an A record carries (RFC 1035 sec 3.4.1). */
#define IDEMIP_DNS_A_RDLEN 4u

/** @brief Octets of RDATA an AAAA record carries (RFC 3596 sec 2.2). */
#define IDEMIP_DNS_AAAA_RDLEN 16u

/** @brief The TYPE values this resolver asks for and reads (RFC 1035 sec 3.2.2, RFC 3596 sec 2.1). */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DNS_TYPE_A = 1,      ///< sec 3.2.2: "A 1 a host address"
    IDEMIP_DNS_TYPE_NS = 2,     ///< sec 3.2.2: an authoritative name server
    IDEMIP_DNS_TYPE_CNAME = 5,  ///< sec 3.2.2: the canonical name for an alias
    IDEMIP_DNS_TYPE_PTR = 12,   ///< sec 3.2.2: a domain name pointer
    IDEMIP_DNS_TYPE_TXT = 16,   ///< sec 3.2.2: text strings
    IDEMIP_DNS_TYPE_AAAA = 28,  ///< RFC 3596 sec 2.1: "The IANA assigned value of the type is 28"
} IdemIpDnsType;

/** @brief RCODE, the response codes of RFC 1035 sec 4.1.1. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DNS_RCODE_NO_ERROR = 0,   ///< "No error condition"
    IDEMIP_DNS_RCODE_FORMAT_ERR = 1, ///< "Format error"
    IDEMIP_DNS_RCODE_SERVER_FAIL = 2,///< "Server failure"
    IDEMIP_DNS_RCODE_NAME_ERR = 3,   ///< "Name Error"
    IDEMIP_DNS_RCODE_NOT_IMPL = 4,   ///< "Not Implemented"
    IDEMIP_DNS_RCODE_REFUSED = 5,    ///< "Refused"
} IdemIpDnsRcode;

/** @brief What one outstanding question is doing. A zeroed entry is free. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DNS_QUERY_FREE = 0, ///< the slot holds no question
    IDEMIP_DNS_QUERY_NEW,      ///< registered, the question not yet on the wire
    IDEMIP_DNS_QUERY_SENT,     ///< asked, the response outstanding
    IDEMIP_DNS_QUERY_DONE,     ///< answered, and the answer cached
    IDEMIP_DNS_QUERY_FAILED,   ///< the RCODE refused it, or the retries ran out
} IdemIpDnsQueryState;

/** @brief What one cached answer is. A zeroed entry is free. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DNS_ENTRY_FREE = 0, ///< the slot holds no answer
    IDEMIP_DNS_ENTRY_VALID,    ///< an answer inside its TTL
    /** RFC 1123 sec 6.1.3.3 (4): "All DNS name servers and resolvers SHOULD cache negative responses
     *  that indicate the specified name, or data of the specified type, does not exist". The slot
     *  holds that outcome and its RCODE, inside IDEMIP_DNS_NEG_TTL_S. */
    IDEMIP_DNS_ENTRY_NEGATIVE,
} IdemIpDnsEntryState;

/**
 * @brief What the resolver is configured with, in the caller's rodata.
 *
 * @var IdemIpDnsCfg::netif   the interface index questions go out of
 * @var IdemIpDnsCfg::retries tries at one server before the next, RFC 1035 sec 4.2.1 asking a
 *                            resolver to "try other servers and server addresses before repeating a
 *                            query to a specific address of a server"
 */
typedef struct
{
    uint8_t netif;
    uint8_t retries;
} IdemIpDnsCfg;

/** @brief What bind takes. */
typedef struct
{
    const IdemIpDnsCfg *cfg;
} DnsBindArgs;

/**
 * @brief What set_server takes: one entry of the server table.
 *
 * @var DnsServerArgs::index the slot, below IDEMIP_DNS_SERVERS
 * @var DnsServerArgs::addr  the address, IDEMIP_DNS_ADDR_LEN octets when ipv6, else 4
 * @var DnsServerArgs::zone  the RFC 4007 sec 6 zone index a scoped address is qualified by
 * @var DnsServerArgs::port  the port to ask on, IDEMIP_DNS_PORT unless a build says otherwise
 * @var DnsServerArgs::ipv6  true when @ref DnsServerArgs::addr is 16 octets
 */
typedef struct
{
    uint8_t index;
    const uint8_t *addr;
    uint32_t zone;
    uint16_t port;
    idemip_bool ipv6;
} DnsServerArgs;

/**
 * @brief What query takes: one question, and the two unpredictable values RFC 5452 sec 9.2 requires.
 *
 * @var DnsQueryArgs::name     the name asked about, NUL terminated, under IDEMIP_DNS_NAME_MAX octets
 * @var DnsQueryArgs::type     the QTYPE, IDEMIP_DNS_TYPE_A or IDEMIP_DNS_TYPE_AAAA
 * @var DnsQueryArgs::xid      the sec 4.1.1 ID, drawn over the full 0 through 65535 range
 * @var DnsQueryArgs::src_port the source port the question goes out of, drawn unpredictably
 */
typedef struct
{
    const char *name;
    uint16_t type;
    uint16_t xid;
    uint16_t src_port;
} DnsQueryArgs;

/**
 * @brief What lookup takes: a name to answer from the cache alone.
 *
 * @var DnsLookupArgs::name the name, NUL terminated
 * @var DnsLookupArgs::type the QTYPE the answer must carry
 */
typedef struct
{
    const char *name;
    uint16_t type;
} DnsLookupArgs;

/**
 * @brief What build takes: the caller's buffer, and which question to write into it.
 *
 * @var DnsBuildArgs::out   the buffer, IDEMIP_DNS_HDR_LEN or more
 * @var DnsBuildArgs::cap   octets of it, at most IDEMIP_DNS_MSG_MAX reaching the wire
 * @var DnsBuildArgs::query the query slot, below IDEMIP_DNS_QUERIES
 * @var DnsBuildArgs::src   the local address the datagram will be sent from, which RFC 5452 sec 9.1
 *                          matches a response's destination address against. IDEMIP_DNS_ADDR_LEN
 *                          octets when the server is IPv6, else 4. Null leaves the question with no
 *                          source address recorded, and a response is then matched without it
 */
typedef struct
{
    uint8_t *out;
    size_t cap;
    const uint8_t *src;
    uint8_t query;
} DnsBuildArgs;

/**
 * @brief What input takes: one received message, and every attribute RFC 5452 sec 9.1 matches on.
 *
 * @var DnsInputArgs::msg      the message octets, IDEMIP_DNS_HDR_LEN or more
 * @var DnsInputArgs::len      how many of them there are
 * @var DnsInputArgs::src      the source address the datagram carried
 * @var DnsInputArgs::src_port the source port it carried, which must be the server's
 * @var DnsInputArgs::dst_port the port it arrived on, which must be the question's source port
 * @var DnsInputArgs::dst      the destination address it carried, which RFC 5452 sec 9.1 matches
 *                             "against query source address". Null skips that one comparison
 * @var DnsInputArgs::ipv6     true when @ref DnsInputArgs::src is 16 octets
 */
typedef struct
{
    const uint8_t *msg;
    size_t len;
    const uint8_t *src;
    const uint8_t *dst;
    uint16_t src_port;
    uint16_t dst_port;
    idemip_bool ipv6;
} DnsInputArgs;

/** @brief What cancel takes. */
typedef struct
{
    uint8_t query; ///< the query slot to drop, below IDEMIP_DNS_QUERIES
} DnsCancelArgs;

// The clock is not a tick operand. It was, and every other entry read the one the last tick left
// behind: build stamped a retry deadline with it, input stamped a cached answer's TTL with it, and
// lookup tested the cache against it. Before the first tick that clock is zero, so a question sent
// and an answer cached at boot were both stamped against zero and the first real tick retired them.
// See DnsIo::now_ms.

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns, and two resolvers share no byte of it.
 *
 * @var DnsIo::bind_args   the configuration
 * @var DnsIo::server_args one server table entry
 * @var DnsIo::query_args  one question, with its ID and source port
 * @var DnsIo::lookup_args a name to answer from the cache
 * @var DnsIo::build_args  the buffer a question is written into
 * @var DnsIo::input_args  one received message and its addressing
 * @var DnsIo::cancel_args the query to drop
 * @var DnsIo::now_ms      the millisecond clock the caller read before the call. Every deadline this
 *                         unit stamps and every one it tests comes from it, so no entry reads a clock
 *                         of its own and none reads the one another entry left. Set it on lookup,
 *                         build, input and tick; the rest do not read it
 * @var DnsIo::status      what the call reports: OK, BUSY, or ERR
 * @var DnsIo::addr        the answer, IDEMIP_DNS_ADDR_LEN octets, 4 of them used by an A record
 * @var DnsIo::ipv6        the family of @ref DnsIo::addr, and on build the family of @ref DnsIo::dst
 * @var DnsIo::type        the TYPE the answer carried, and on build the QTYPE it wrote
 * @var DnsIo::ttl_s       the RFC 1035 sec 4.1.3 TTL the answer was given, seconds, not the remainder
 * @var DnsIo::query       the slot query took, build wrote, or input matched, IDEMIP_DNS_QUERIES for
 *                         none, which is what lookup reports when no question is outstanding
 * @var DnsIo::rcode       the sec 4.1.1 RCODE the response carried, and on lookup the one the
 *                         outstanding question last got
 * @var DnsIo::answers     the sec 4.1.1 ANCOUNT it carried
 * @var DnsIo::len         octets build wrote
 * @var DnsIo::dst         the server build addressed, IDEMIP_DNS_ADDR_LEN octets
 * @var DnsIo::dst_zone    that server's RFC 4007 zone index
 * @var DnsIo::dst_port    that server's port
 * @var DnsIo::src_port    the port the question goes out of
 * @var DnsIo::xid         the ID build wrote, or input matched
 * @var DnsIo::failed      the question this lookup names gave up. RFC 1123 sec 6.1.3.3 (2): "After a
 *                         query has been retransmitted several times without a response, an
 *                         implementation MUST give up and return a soft error to the application."
 *                         The lookup reports ERR with this set and the slot goes back, so the same
 *                         name may be asked again
 */
typedef struct
{
    DnsBindArgs bind_args;
    DnsServerArgs server_args;
    DnsQueryArgs query_args;
    DnsLookupArgs lookup_args;
    DnsBuildArgs build_args;
    DnsInputArgs input_args;
    DnsCancelArgs cancel_args;

    uint32_t now_ms;
    IdemIpStatus status;
    uint8_t addr[IDEMIP_DNS_ADDR_LEN];
    idemip_bool ipv6;
    uint16_t type;
    uint32_t ttl_s;
    uint8_t query;
    uint8_t rcode;
    uint16_t answers;
    size_t len;
    uint8_t dst[IDEMIP_DNS_ADDR_LEN];
    uint32_t dst_zone;
    uint16_t dst_port;
    uint16_t src_port;
    uint16_t xid;
    idemip_bool failed;
} DnsIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant and every table entry is a power of two wide, so entry i of a table is
// at (i << SHIFT) from the table's offset and nothing is derived at runtime. The operand block and
// the context share the first IDEMIP_DNS_CTX_BYTES octets, the region this unit keeps outside its
// tables.

#define IDEMIP_DNS_OFF_IO 0u ///< the operand and result block
#define IDEMIP_DNS_OFF_CTX IDEMIP_ROUND_UP(IDEMIP_DNS_OFF_IO + sizeof(DnsIo), IDEMIP_ALIGN)

/** @brief The outstanding questions, IDEMIP_DNS_QUERIES of them. */
#define IDEMIP_DNS_OFF_QUERIES IDEMIP_DNS_CTX_BYTES

/** @brief The answer cache, IDEMIP_DNS_ENTRIES of them. */
#define IDEMIP_DNS_OFF_ENTRIES (IDEMIP_DNS_OFF_QUERIES + (IDEMIP_DNS_QUERIES << IDEMIP_DNS_QUERY_ENTRY_SHIFT))

/**
 * @brief The names, IDEMIP_DNS_NAMES of them, IDEMIP_DNS_NAME_MAX octets each.
 *
 * One per question and one per cached answer, at fixed indices: name i below IDEMIP_DNS_QUERIES is
 * question i's, and name IDEMIP_DNS_QUERIES + j is cached answer j's. So a name is reached by a shift
 * from an index the caller already has, and no slot is ever searched for.
 */
#define IDEMIP_DNS_OFF_NAMES (IDEMIP_DNS_OFF_ENTRIES + (IDEMIP_DNS_ENTRIES << IDEMIP_DNS_ENTRY_SHIFT))

/** @brief The servers, IDEMIP_DNS_SERVERS of them. */
#define IDEMIP_DNS_OFF_SERVERS (IDEMIP_DNS_OFF_NAMES + (IDEMIP_DNS_NAMES << IDEMIP_DNS_NAME_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_DNS_IO(w) ((DnsIo *)(void *)((w) + IDEMIP_DNS_OFF_IO))

/**
 * @brief The stub resolver.
 *
 *   Dns.clear(work);
 *   IDEMIP_DNS_IO(work)->bind_args.cfg = &my_cfg;
 *   Dns.bind(work);
 *   IDEMIP_DNS_IO(work)->server_args.index = 0; ... Dns.set_server(work);
 *   IDEMIP_DNS_IO(work)->query_args.name = "example.com";
 *   IDEMIP_DNS_IO(work)->query_args.type = IDEMIP_DNS_TYPE_A;
 *   IDEMIP_DNS_IO(work)->query_args.xid = my_random_word;
 *   IDEMIP_DNS_IO(work)->query_args.src_port = my_random_port;
 *   Dns.query(work);
 *
 * @c work is IDEMIP_DNS_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the resolver, so two
 * of them share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata
 * and the module occupies no RAM of its own.
 *
 * Nothing here blocks. A name that is not cached yet is IDEMIP_BUSY, never an error: the caller asks
 * again on a later tick, after the question has gone out and the answer has come back.
 *
 * The send loop is a walk over the query table, because a question needing the wire is one in the
 * IDEMIP_DNS_QUERY_NEW state and build is what puts it there:
 *
 *   IDEMIP_DNS_IO(work)->now_ms = now_ms;
 *   Dns.tick(work);
 *   for (i = 0; i < IDEMIP_DNS_QUERIES; i++) { build_args.query = i; Dns.build(work); if OK send }
 *
 * The clock is set once and read by every entry that stamps or tests a deadline, so a build, an
 * input or a lookup between two ticks measures against the millisecond the caller last read rather
 * than the one the last tick happened to leave behind.
 *
 * @var DnsNs::clear      zero every byte of the borrow, so it runs before the operands are set
 * @var DnsNs::bind       take the configuration, after checking every member is present
 * @var DnsNs::set_server put one server in the table
 * @var DnsNs::query      register one question. BUSY when every query slot is taken. A question for
 *                        the same name, type and class already outstanding is answered with that
 *                        slot rather than a second one, which is RFC 5452 sec 5's birthday case.
 * @var DnsNs::lookup     answer from the cache alone. BUSY when the name is not cached.
 * @var DnsNs::build      write a registered question into the caller's buffer (sec 4.1.2). ERR
 *                        unless the slot is IDEMIP_DNS_QUERY_NEW, BUSY while the server table is
 *                        empty, since DHCP option 6 or RFC 8106 RDNSS may still fill it.
 * @var DnsNs::input      take one response, matched on every attribute RFC 5452 sec 9.1 lists. ERR
 *                        leaves every question exactly as it was, which is what sec 9.1's "A
 *                        mismatch and the response MUST be considered invalid" requires of a forgery.
 * @var DnsNs::tick       run the retry deadlines and expire answers past their TTL, both against
 *                        @ref DnsIo::now_ms
 * @var DnsNs::cancel     drop one outstanding question
 * @var DnsNs::flush      empty the answer cache, leaving the servers and the questions alone
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const bind)(uint8_t *work);
    void (*const set_server)(uint8_t *work);
    void (*const query)(uint8_t *work);
    void (*const lookup)(uint8_t *work);
    void (*const build)(uint8_t *work);
    void (*const input)(uint8_t *work);
    void (*const tick)(uint8_t *work);
    void (*const cancel)(uint8_t *work);
    void (*const flush)(uint8_t *work);
} DnsNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_dns_clear(uint8_t *work);
void idemip_dns_bind(uint8_t *work);
void idemip_dns_set_server(uint8_t *work);
void idemip_dns_query(uint8_t *work);
void idemip_dns_lookup(uint8_t *work);
void idemip_dns_build(uint8_t *work);
void idemip_dns_input(uint8_t *work);
void idemip_dns_tick(uint8_t *work);
void idemip_dns_cancel(uint8_t *work);
void idemip_dns_flush(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Dns.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const DnsNs Dns IDEMIP_UNUSED = {
    .clear = idemip_dns_clear,
    .bind = idemip_dns_bind,
    .set_server = idemip_dns_set_server,
    .query = idemip_dns_query,
    .lookup = idemip_dns_lookup,
    .build = idemip_dns_build,
    .input = idemip_dns_input,
    .tick = idemip_dns_tick,
    .cancel = idemip_dns_cancel,
    .flush = idemip_dns_flush};
// The header of RFC 1035 sec 4.1.1: six 16-bit fields, the question section behind them.
static_assert(IDEMIP_DNS_HDR_OFF_ARCOUNT + 2u == IDEMIP_DNS_HDR_LEN,
              "the header is six 16-bit fields (RFC 1035 sec 4.1.1)");
// The flags word is partitioned, so no bit belongs to two fields and every bit belongs to one.
static_assert((IDEMIP_DNS_FLAG_QR | IDEMIP_DNS_FLAG_OPCODE | IDEMIP_DNS_FLAG_AA | IDEMIP_DNS_FLAG_TC |
               IDEMIP_DNS_FLAG_RD | IDEMIP_DNS_FLAG_RA | IDEMIP_DNS_FLAG_Z | IDEMIP_DNS_FLAG_RCODE) == 0xFFFFu,
              "the sec 4.1.1 flags word is fully partitioned");
static_assert((IDEMIP_DNS_FLAG_OPCODE >> IDEMIP_DNS_OPCODE_SHIFT) == 0xFu,
              "the Opcode is four bits at IDEMIP_DNS_OPCODE_SHIFT (RFC 1035 sec 4.1.1)");
// sec 2.3.4 bounds a label at 63 octets, which is what leaves the two high bits of a length octet
// free for the sec 4.1.4 pointer form.
static_assert(IDEMIP_DNS_LABEL_MAX == (uint8_t)~IDEMIP_DNS_LABEL_PTR,
              "a label length shares its octet with the sec 4.1.4 pointer bits");
static_assert(IDEMIP_DNS_ADDR_LEN == IDEMIP_DNS_AAAA_RDLEN,
              "an answer address holds an AAAA record's RDATA (RFC 3596 sec 2.2)");
// A record's fixed fields are TYPE, CLASS, TTL and RDLENGTH, in that order (RFC 1035 sec 4.1.3).
static_assert(IDEMIP_DNS_RR_OFF_RDLENGTH + 2u == IDEMIP_DNS_RR_FIXED_LEN,
              "the sec 4.1.3 fixed fields are two, two, four and two octets");
static_assert(IDEMIP_DNS_RR_OFF_TTL + 4u == IDEMIP_DNS_RR_OFF_RDLENGTH,
              "the sec 4.1.3 TTL is a 32 bit field");
// sec 4.2.1 caps a UDP message, so the shortest response is a header, a root QNAME and its fixed
// fields, and the longest question this resolver can ask has to fit under that cap.
static_assert(IDEMIP_DNS_HDR_LEN + 1u + IDEMIP_DNS_QFIXED_LEN < IDEMIP_DNS_MSG_MAX,
              "the sec 4.1.2 question does not fit a sec 4.2.1 UDP message");
static_assert(IDEMIP_DNS_HDR_LEN + IDEMIP_DNS_NAME_WIRE_MAX + IDEMIP_DNS_QFIXED_LEN <= IDEMIP_DNS_MSG_MAX,
              "the widest sec 3.1 name does not fit a sec 4.2.1 UDP message");
// The dotted form a question is given trades one separator for each length octet and adds the root.
static_assert(IDEMIP_DNS_NAME_TEXT_MAX + 2u == IDEMIP_DNS_NAME_WIRE_MAX,
              "the dotted bound is not the sec 3.1 wire bound less the length and root octets");
static_assert(IDEMIP_DNS_NAME_TEXT_MAX < IDEMIP_DNS_NAME_MAX,
              "a name and its terminator do not fit a name region: raise IDEMIP_DNS_NAME_SHIFT");
// A pointer hop yields a length octet and a label octet at least, so half the sec 3.1 name bound is
// more hops than any name can need.
static_assert(IDEMIP_DNS_PTR_HOPS_MAX < IDEMIP_DNS_NAME_WIRE_MAX,
              "the sec 4.1.4 hop bound exceeds the sec 3.1 name bound");
// RFC 1035 sec 4.2.1: "the minimum retransmission interval should be 2-5 seconds".
static_assert(IDEMIP_DNS_RETRY_MS >= 2000u && IDEMIP_DNS_RETRY_MS <= 5000u,
              "IDEMIP_DNS_RETRY_MS is outside RFC 1035 sec 4.2.1's 2 to 5 seconds");
// A TTL becomes a millisecond deadline by one multiply, so the ceiling has to leave that in 32 bits.
static_assert(IDEMIP_DNS_TTL_MAX_S <= (0xFFFFFFFFu / IDEMIP_DNS_MS_PER_S),
              "IDEMIP_DNS_TTL_MAX_S milliseconds overflows a 32 bit deadline");
// RFC 2181 sec 8: a TTL is "an unsigned number, with a minimum value of 0, and a maximum value of
// 2147483647".
static_assert(IDEMIP_DNS_TTL_MAX_S < IDEMIP_DNS_TTL_SIGN, "IDEMIP_DNS_TTL_MAX_S is past RFC 2181 sec 8's 2^31 - 1");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_UDP

#endif // IDEMIP_DNS_H
