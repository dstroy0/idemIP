// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmp.h
 * @brief Internet control messages, RFC 792.
 *
 * Every message begins Type, Code, Checksum; what follows depends on the type. Field offsets and
 * accessors over the caller's bytes.
 */

#ifndef IDEMIP_ICMP_H
#define IDEMIP_ICMP_H

#include "src/checksum.h"
#include "src/ip/ipv4.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// The common three fields, at the head of every message (RFC 792)
// ---------------------------------------------------------------------------

#define IDEMIP_ICMP_OFF_TYPE 0u  ///< 8-bit Type
#define IDEMIP_ICMP_OFF_CODE 1u  ///< 8-bit Code
#define IDEMIP_ICMP_OFF_CKSUM 2u ///< 16-bit Checksum
#define IDEMIP_ICMP_HDR_LEN 4u   ///< the part every type shares

/** @brief Message types RFC 792 assigns, as its "Summary of Message Types" lists them. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ICMP_ECHO_REPLY = 0, ///< "0 for echo reply message"
    IDEMIP_ICMP_DEST_UNREACHABLE = 3,
    IDEMIP_ICMP_SOURCE_QUENCH = 4,
    IDEMIP_ICMP_REDIRECT = 5,
    IDEMIP_ICMP_ECHO = 8, ///< "8 for echo message"
    IDEMIP_ICMP_TIME_EXCEEDED = 11,
    IDEMIP_ICMP_PARAMETER_PROBLEM = 12,
    IDEMIP_ICMP_TIMESTAMP = 13,
    IDEMIP_ICMP_TIMESTAMP_REPLY = 14,
    IDEMIP_ICMP_INFO_REQUEST = 15,
    IDEMIP_ICMP_INFO_REPLY = 16,
} IdemIpIcmpType;

// ---------------------------------------------------------------------------
// The error messages (RFC 792), which RFC 1122 sec 3.2.2 groups against the queries
// ---------------------------------------------------------------------------
// Destination Unreachable, Source Quench, Time Exceeded, Parameter Problem and Redirect share one
// shape: Type, Code, Checksum, one 32-bit field the type fixes, then the datagram that triggered
// the message. RFC 792: "Any field labeled 'unused' is reserved for later extensions and must be
// zero when sent".

#define IDEMIP_ICMP_OFF_UNUSED 4u     ///< 32-bit unused (types 3, 4 and 11)
#define IDEMIP_ICMP_OFF_POINTER 4u    ///< 8-bit Pointer, then 24 bits unused (type 12)
#define IDEMIP_ICMP_OFF_GATEWAY 4u    ///< 32-bit Gateway Internet Address (type 5)
#define IDEMIP_ICMP_ERR_HDR_LEN 8u    ///< through that field
#define IDEMIP_ICMP_OFF_QUOTE 8u      ///< "Internet Header + 64 bits of Original Data Datagram"
#define IDEMIP_ICMP_POINTER_SHIFT 24u ///< the Pointer is the top octet of the word at offset 4

/**
 * @brief Octets of the original datagram's data an error message carries after its header.
 *
 * RFC 792: "The internet header plus the first 64 bits of the original datagram's data."
 * RFC 1122 sec 3.2.2: "Every ICMP error message includes the Internet header and at least the first
 * 8 data octets of the datagram that triggered the error".
 */
#define IDEMIP_ICMP_ERR_QUOTE_DATA 8u

/**
 * @brief Destination Unreachable codes.
 *
 * RFC 792, type 3: "0 = net unreachable; 1 = host unreachable; 2 = protocol unreachable; 3 = port
 * unreachable; 4 = fragmentation needed and DF set; 5 = source route failed."
 * RFC 1122 sec 3.2.2.1 continues the run: "The following additional codes are hereby defined: 6 =
 * destination network unknown, 7 = destination host unknown, 8 = source host isolated, 9 =
 * communication with destination network administratively prohibited, 10 = communication with
 * destination host administratively prohibited, 11 = network unreachable for type of service, 12 =
 * host unreachable for type of service."
 */
#define IDEMIP_ICMP_DU_NET 0u
#define IDEMIP_ICMP_DU_HOST 1u
#define IDEMIP_ICMP_DU_PROTOCOL 2u
#define IDEMIP_ICMP_DU_PORT 3u
#define IDEMIP_ICMP_DU_FRAG_NEEDED 4u
#define IDEMIP_ICMP_DU_SRC_ROUTE_FAILED 5u
#define IDEMIP_ICMP_DU_NET_UNKNOWN 6u
#define IDEMIP_ICMP_DU_HOST_UNKNOWN 7u
#define IDEMIP_ICMP_DU_SRC_HOST_ISOLATED 8u
#define IDEMIP_ICMP_DU_NET_PROHIBITED 9u
#define IDEMIP_ICMP_DU_HOST_PROHIBITED 10u
#define IDEMIP_ICMP_DU_NET_TOS 11u
#define IDEMIP_ICMP_DU_HOST_TOS 12u

/**
 * @brief Time Exceeded codes. RFC 792, type 11: "0 = time to live exceeded in transit; 1 = fragment
 * reassembly time exceeded."
 */
#define IDEMIP_ICMP_TE_TTL 0u
#define IDEMIP_ICMP_TE_REASSEMBLY 1u

/**
 * @brief Redirect codes. RFC 792, type 5: "0 = Redirect datagrams for the Network. 1 = Redirect
 * datagrams for the Host. 2 = Redirect datagrams for the Type of Service and Network. 3 = Redirect
 * datagrams for the Type of Service and Host."
 */
#define IDEMIP_ICMP_RD_NET 0u
#define IDEMIP_ICMP_RD_HOST 1u
#define IDEMIP_ICMP_RD_TOS_NET 2u
#define IDEMIP_ICMP_RD_TOS_HOST 3u

/**
 * @brief Parameter Problem codes. RFC 792, type 12: "0 = pointer indicates the error."
 * RFC 1122 sec 3.2.2.5: "A new variant on the Parameter Problem message is hereby defined: Code 1 =
 * required option is missing."
 */
#define IDEMIP_ICMP_PP_POINTER 0u
#define IDEMIP_ICMP_PP_MISSING_OPTION 1u

/** @brief RFC 792, Source Quench, type 4: "Code 0". */
#define IDEMIP_ICMP_CODE_SOURCE_QUENCH 0u

// ---------------------------------------------------------------------------
// Echo or Echo Reply (RFC 792), the type this end answers
// ---------------------------------------------------------------------------
// Type, Code, Checksum, then Identifier and Sequence Number, then data.

#define IDEMIP_ICMP_OFF_ID 4u       ///< 16-bit Identifier
#define IDEMIP_ICMP_OFF_SEQ 6u      ///< 16-bit Sequence Number
#define IDEMIP_ICMP_ECHO_HDR_LEN 8u ///< through the sequence number; data follows

/** @brief RFC 792, Echo or Echo Reply: "Code 0". */
#define IDEMIP_ICMP_CODE_ECHO 0u

// ---------------------------------------------------------------------------
// Timestamp or Timestamp Reply (RFC 792)
// ---------------------------------------------------------------------------
// The echo fields, then three 32-bit timestamps. RFC 792: "The timestamp is 32 bits of milliseconds
// since midnight UT."

#define IDEMIP_ICMP_OFF_ORIG_TS 8u  ///< 32-bit Originate Timestamp
#define IDEMIP_ICMP_OFF_RECV_TS 12u ///< 32-bit Receive Timestamp
#define IDEMIP_ICMP_OFF_XMIT_TS 16u ///< 32-bit Transmit Timestamp
#define IDEMIP_ICMP_TS_LEN 20u      ///< the whole message

/** @brief RFC 792, Timestamp or Timestamp Reply: "Code 0". */
#define IDEMIP_ICMP_CODE_TIMESTAMP 0u

/**
 * @brief The bit a non-standard timestamp carries.
 *
 * RFC 792: "If the time is not available in miliseconds or cannot be provided with respect to
 * midnight UT then any time can be inserted in a timestamp provided the high order bit of the
 * timestamp is also set to indicate this non-standard value."
 */
#define IDEMIP_ICMP_TS_NONSTANDARD 0x80000000u

// ---------------------------------------------------------------------------
// Information Request or Information Reply (RFC 792)
// ---------------------------------------------------------------------------
// The echo fields and nothing after them.

#define IDEMIP_ICMP_INFO_LEN 8u ///< the whole message

/** @brief RFC 792, Information Request or Information Reply: "Code 0". */
#define IDEMIP_ICMP_CODE_INFO 0u

/** @brief Type. */
IDEMIP_INLINE uint8_t idemip_icmp_type(const uint8_t *m)
{
    return m[IDEMIP_ICMP_OFF_TYPE];
}

/** @brief Code; its meaning depends on the type. */
IDEMIP_INLINE uint8_t idemip_icmp_code(const uint8_t *m)
{
    return m[IDEMIP_ICMP_OFF_CODE];
}

/** @brief Checksum as carried. */
IDEMIP_INLINE uint16_t idemip_icmp_cksum(const uint8_t *m)
{
    return idemip_rd16(m + IDEMIP_ICMP_OFF_CKSUM);
}

/** @brief Identifier (echo and echo reply). */
IDEMIP_INLINE uint16_t idemip_icmp_id(const uint8_t *m)
{
    return idemip_rd16(m + IDEMIP_ICMP_OFF_ID);
}

/** @brief Sequence Number (echo and echo reply). */
IDEMIP_INLINE uint16_t idemip_icmp_seq(const uint8_t *m)
{
    return idemip_rd16(m + IDEMIP_ICMP_OFF_SEQ);
}

/** @brief Pointer: the octet of the original header the fault was found at (parameter problem). */
IDEMIP_INLINE uint8_t idemip_icmp_pointer(const uint8_t *m)
{
    return m[IDEMIP_ICMP_OFF_POINTER];
}

/** @brief Gateway Internet Address (redirect). */
IDEMIP_INLINE uint32_t idemip_icmp_gateway(const uint8_t *m)
{
    return idemip_rd32(m + IDEMIP_ICMP_OFF_GATEWAY);
}

/** @brief Originate Timestamp (timestamp and timestamp reply). */
IDEMIP_INLINE uint32_t idemip_icmp_orig_ts(const uint8_t *m)
{
    return idemip_rd32(m + IDEMIP_ICMP_OFF_ORIG_TS);
}

/** @brief Receive Timestamp (timestamp reply). */
IDEMIP_INLINE uint32_t idemip_icmp_recv_ts(const uint8_t *m)
{
    return idemip_rd32(m + IDEMIP_ICMP_OFF_RECV_TS);
}

/** @brief Transmit Timestamp (timestamp reply). */
IDEMIP_INLINE uint32_t idemip_icmp_xmit_ts(const uint8_t *m)
{
    return idemip_rd32(m + IDEMIP_ICMP_OFF_XMIT_TS);
}

/** @brief The quoted datagram an error message carries: its internet header, then its data. */
IDEMIP_INLINE const uint8_t *idemip_icmp_quote(const uint8_t *m)
{
    return m + IDEMIP_ICMP_OFF_QUOTE;
}

/**
 * @brief True for the five types RFC 1122 sec 3.2.2 groups as errors.
 *
 * "ICMP error messages: Destination Unreachable, Redirect, Source Quench, Time Exceeded, Parameter
 * Problem." The remaining types are queries. Unlike RFC 4443 no bit sorts them, so the type is
 * matched against the list.
 */
IDEMIP_INLINE idemip_bool idemip_icmp_is_error(const uint8_t *m)
{
    switch (m[IDEMIP_ICMP_OFF_TYPE])
    {
    case IDEMIP_ICMP_DEST_UNREACHABLE:
    case IDEMIP_ICMP_SOURCE_QUENCH:
    case IDEMIP_ICMP_REDIRECT:
    case IDEMIP_ICMP_TIME_EXCEEDED:
    case IDEMIP_ICMP_PARAMETER_PROBLEM:
        return IDEMIP_TRUE;
    default:
        return IDEMIP_FALSE;
    }
}

/**
 * @brief The checksum to write over @p len bytes of message at @p m.
 *
 * RFC 792: "The checksum is the 16-bit ones's complement of the one's complement sum of the ICMP
 * message starting with the ICMP Type. For computing the checksum, the checksum field should be
 * zero. If the total length is odd, the received data is padded with one octet of zeros for
 * computing the checksum."
 *
 * No pseudo-header: unlike UDP and TCP, this covers the message alone.
 */
IDEMIP_INLINE uint16_t idemip_icmp_cksum_compute(const uint8_t *m, size_t len)
{
    return idemip_cksum(m, len);
}

// ---------------------------------------------------------------------------
// Build helpers: write the caller's bytes, then the checksum over them
// ---------------------------------------------------------------------------
// Each takes the message the caller placed and the total length it occupies, writes the head, zeroes
// the checksum field, sums the whole message and writes the result back. Whatever follows the head,
// echo data or a quoted datagram, is already in place and is covered by that sum.

/**
 * @brief Write an echo or echo reply head at @p m, then its checksum over @p len bytes.
 *
 * RFC 792, Echo or Echo Reply: Type, Code 0, Checksum, Identifier, Sequence Number, then Data. The
 * data sits at IDEMIP_ICMP_ECHO_HDR_LEN and @p len counts it.
 */
IDEMIP_INLINE void idemip_icmp_build_echo(uint8_t *m, uint8_t type, uint16_t id, uint16_t seq, size_t len)
{
    m[IDEMIP_ICMP_OFF_TYPE] = type;
    m[IDEMIP_ICMP_OFF_CODE] = IDEMIP_ICMP_CODE_ECHO;
    idemip_wr16(m + IDEMIP_ICMP_OFF_CKSUM, 0u);
    idemip_wr16(m + IDEMIP_ICMP_OFF_ID, id);
    idemip_wr16(m + IDEMIP_ICMP_OFF_SEQ, seq);
    idemip_wr16(m + IDEMIP_ICMP_OFF_CKSUM, idemip_icmp_cksum_compute(m, len));
}

/**
 * @brief Turn the echo message at @p m into its reply, in place, over @p len bytes.
 *
 * RFC 792, Echo or Echo Reply: "To form an echo reply message, the source and destination addresses
 * are simply reversed, the type code changed to 0, and the checksum recomputed." The addresses are
 * the internet header's; this writes the ICMP message alone. The identifier, the sequence number and
 * the data are carried through, which is RFC 1122 sec 3.2.2.6: "Data received in an ICMP Echo
 * Request MUST be entirely included in the resulting Echo Reply."
 */
IDEMIP_INLINE void idemip_icmp_echo_reply(uint8_t *m, size_t len)
{
    idemip_icmp_build_echo(m, (uint8_t)IDEMIP_ICMP_ECHO_REPLY, idemip_icmp_id(m), idemip_icmp_seq(m), len);
}

/**
 * @brief Write an error message head at @p m, then its checksum over @p len bytes.
 *
 * @p word is the 32 bits at IDEMIP_ICMP_OFF_UNUSED: zero for the types RFC 792 labels the field
 * unused, the Pointer in the top octet for parameter problem, the Gateway Internet Address for
 * redirect. The quoted datagram sits at IDEMIP_ICMP_OFF_QUOTE and @p len counts it.
 */
IDEMIP_INLINE void idemip_icmp_build_error(uint8_t *m, uint8_t type, uint8_t code, uint32_t word, size_t len)
{
    m[IDEMIP_ICMP_OFF_TYPE] = type;
    m[IDEMIP_ICMP_OFF_CODE] = code;
    idemip_wr16(m + IDEMIP_ICMP_OFF_CKSUM, 0u);
    idemip_wr32(m + IDEMIP_ICMP_OFF_UNUSED, word);
    idemip_wr16(m + IDEMIP_ICMP_OFF_CKSUM, idemip_icmp_cksum_compute(m, len));
}

/**
 * @brief Write a destination unreachable message, type 3.
 *
 * RFC 1122 sec 3.2.2.1: "A host SHOULD generate Destination Unreachable messages with code: 2
 * (Protocol Unreachable), when the designated transport protocol is not supported; or 3 (Port
 * Unreachable), when the designated transport protocol (e.g., UDP) is unable to demultiplex the
 * datagram but has no protocol mechanism to inform the sender."
 */
IDEMIP_INLINE void idemip_icmp_build_dest_unreachable(uint8_t *m, uint8_t code, size_t len)
{
    idemip_icmp_build_error(m, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, code, 0u, len);
}

/**
 * @brief Write a time exceeded message, type 11.
 *
 * RFC 792: "If a host reassembling a fragmented datagram cannot complete the reassembly due to
 * missing fragments within its time limit it discards the datagram, and it may send a time exceeded
 * message", which is code 1.
 */
IDEMIP_INLINE void idemip_icmp_build_time_exceeded(uint8_t *m, uint8_t code, size_t len)
{
    idemip_icmp_build_error(m, (uint8_t)IDEMIP_ICMP_TIME_EXCEEDED, code, 0u, len);
}

/**
 * @brief Write a parameter problem message, type 12, faulting octet @p pointer.
 *
 * RFC 792: "The pointer identifies the octet of the original datagram's header where the error was
 * detected", and it is the top octet of the word at offset 4.
 */
IDEMIP_INLINE void idemip_icmp_build_parameter_problem(uint8_t *m, uint8_t code, uint8_t pointer, size_t len)
{
    idemip_icmp_build_error(m, (uint8_t)IDEMIP_ICMP_PARAMETER_PROBLEM, code,
                            (uint32_t)pointer << IDEMIP_ICMP_POINTER_SHIFT, len);
}

/**
 * @brief Write a source quench message, type 4, code 0.
 *
 * RFC 1122 sec 3.2.2.3: "A host MAY send a Source Quench message if it is approaching, or has
 * reached, the point at which it is forced to discard incoming datagrams due to a shortage of
 * reassembly buffers or other resources."
 */
IDEMIP_INLINE void idemip_icmp_build_source_quench(uint8_t *m, size_t len)
{
    idemip_icmp_build_error(m, (uint8_t)IDEMIP_ICMP_SOURCE_QUENCH, IDEMIP_ICMP_CODE_SOURCE_QUENCH, 0u, len);
}

/**
 * @brief Bytes an error message quoting the datagram whose internet header is at @p ip occupies.
 *
 * The error head, then the quoted header of IHL 32-bit words (RFC 791 sec 3.1), then eight octets of
 * its data.
 */
IDEMIP_INLINE size_t idemip_icmp_err_len(const uint8_t *ip)
{
    return (size_t)IDEMIP_ICMP_ERR_HDR_LEN + IDEMIP_IP4_HDR_BYTES(idemip_ip4_ihl(ip)) + IDEMIP_ICMP_ERR_QUOTE_DATA;
}

static_assert(IDEMIP_ICMP_OFF_CKSUM + 2u == IDEMIP_ICMP_HDR_LEN,
              "the fields every RFC 792 message shares must sum to the common header length");
static_assert(IDEMIP_ICMP_OFF_SEQ + 2u == IDEMIP_ICMP_ECHO_HDR_LEN,
              "the RFC 792 echo fields must sum to the echo header length");
static_assert(IDEMIP_ICMP_OFF_SEQ + 2u == IDEMIP_ICMP_INFO_LEN,
              "an RFC 792 information request or reply is the echo fields and nothing after them");
static_assert(IDEMIP_ICMP_OFF_UNUSED + 4u == IDEMIP_ICMP_ERR_HDR_LEN,
              "the RFC 792 error fields must sum to the error header length");
static_assert(IDEMIP_ICMP_OFF_QUOTE == IDEMIP_ICMP_ERR_HDR_LEN,
              "the quoted datagram starts where the RFC 792 error header ends");
static_assert(IDEMIP_ICMP_OFF_POINTER == IDEMIP_ICMP_OFF_UNUSED && IDEMIP_ICMP_OFF_GATEWAY == IDEMIP_ICMP_OFF_UNUSED,
              "RFC 792 puts the pointer, the gateway address and the unused word at the same offset");
static_assert(IDEMIP_ICMP_POINTER_SHIFT == 24u,
              "the RFC 792 pointer is the first octet of the word at offset 4");
static_assert(IDEMIP_ICMP_OFF_XMIT_TS + 4u == IDEMIP_ICMP_TS_LEN,
              "the RFC 792 timestamp fields must sum to the timestamp message length");
static_assert(IDEMIP_ICMP_ERR_QUOTE_DATA == 64u / 8u,
              "RFC 792 quotes 64 bits of the original datagram's data, which is eight octets");
static_assert(IDEMIP_ICMP_DU_NET_UNKNOWN == IDEMIP_ICMP_DU_SRC_ROUTE_FAILED + 1u,
              "RFC 1122 sec 3.2.2.1's added codes continue RFC 792's run at 6");
static_assert(IDEMIP_ICMP_DU_HOST_TOS == 12u, "RFC 1122 sec 3.2.2.1 ends the destination unreachable codes at 12");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_ICMP_H
