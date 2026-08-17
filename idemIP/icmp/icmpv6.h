// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmpv6.h
 * @brief Internet control messages for IPv6, RFC 4443.
 *
 * The same three leading fields as RFC 792, a renumbered type space, and a checksum that covers the
 * RFC 8200 sec 8.1 pseudo-header as well as the message. Read out of, and built into, the caller's
 * bytes; holds nothing.
 */

#ifndef IDEMIP_ICMPV6_H
#define IDEMIP_ICMPV6_H

#include "idemIP/checksum.h"
#include "idemIP/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// The common three fields, at the head of every message (RFC 4443 sec 2.1)
// ---------------------------------------------------------------------------

#define IDEMIP_ICMP6_OFF_TYPE 0u  ///< 8-bit Type
#define IDEMIP_ICMP6_OFF_CODE 1u  ///< 8-bit Code
#define IDEMIP_ICMP6_OFF_CKSUM 2u ///< 16-bit Checksum
#define IDEMIP_ICMP6_OFF_BODY 4u  ///< Message Body, its shape fixed by the type
#define IDEMIP_ICMP6_HDR_LEN 4u   ///< the part every type shares

/**
 * @brief The bit that sorts the two classes.
 *
 * RFC 4443 sec 2.1: "Error messages are identified as such by a zero in the high-order bit of their
 * message Type field values. Thus, error messages have message types from 0 to 127; informational
 * messages have message types from 128 to 255."
 */
#define IDEMIP_ICMP6_INFORMATIONAL 0x80u

/**
 * @brief Message types in the ICMPv6 space. Numbered apart from RFC 792's.
 *
 * RFC 4443 sec 2.1 assigns 1 through 4 and 128 through 129. Other documents assign into the same
 * space: RFC 2710 sec 3.1 takes 130 through 132 for MLD, which sec 3 calls "a sub-protocol of
 * ICMPv6, that is, MLD message types are a subset of the set of ICMPv6 messages".
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ICMP6_DEST_UNREACHABLE = 1,  ///< sec 3.1
    IDEMIP_ICMP6_PACKET_TOO_BIG = 2,    ///< sec 3.2
    IDEMIP_ICMP6_TIME_EXCEEDED = 3,     ///< sec 3.3
    IDEMIP_ICMP6_PARAMETER_PROBLEM = 4, ///< sec 3.4
    IDEMIP_ICMP6_ECHO_REQUEST = 128,    ///< sec 4.1
    IDEMIP_ICMP6_ECHO_REPLY = 129,      ///< sec 4.2
    IDEMIP_ICMP6_MLD_QUERY = 130,       ///< RFC 2710 sec 3.1, "Multicast Listener Query"
    IDEMIP_ICMP6_MLD_REPORT = 131,      ///< RFC 2710 sec 3.1, "Multicast Listener Report"
    IDEMIP_ICMP6_MLD_DONE = 132,        ///< RFC 2710 sec 3.1, "Multicast Listener Done"
} IdemIpIcmp6Type;

// ---------------------------------------------------------------------------
// Codes (RFC 4443 sec 3)
// ---------------------------------------------------------------------------

/** @brief Destination Unreachable, sec 3.1. Codes 5 and 6 are "more informative subsets of code 1". */
#define IDEMIP_ICMP6_DU_NO_ROUTE 0u
#define IDEMIP_ICMP6_DU_PROHIBITED 1u
#define IDEMIP_ICMP6_DU_BEYOND_SCOPE 2u
#define IDEMIP_ICMP6_DU_ADDR_UNREACH 3u
#define IDEMIP_ICMP6_DU_PORT_UNREACH 4u
#define IDEMIP_ICMP6_DU_SRC_POLICY 5u
#define IDEMIP_ICMP6_DU_REJECT_ROUTE 6u

/** @brief Time Exceeded, sec 3.3. */
#define IDEMIP_ICMP6_TE_HOP_LIMIT 0u
#define IDEMIP_ICMP6_TE_REASSEMBLY 1u

/** @brief Parameter Problem, sec 3.4. Codes 1 and 2 are "more informative subsets of Code 0". */
#define IDEMIP_ICMP6_PP_ERRONEOUS_HDR 0u
#define IDEMIP_ICMP6_PP_UNREC_NEXT_HDR 1u
#define IDEMIP_ICMP6_PP_UNREC_OPTION 2u

/** @brief Echo Request and Echo Reply, sec 4.1 and sec 4.2: "Code 0". */
#define IDEMIP_ICMP6_CODE_ECHO 0u

/** @brief Packet Too Big, sec 3.2: "Set to 0 (zero) by the originator and ignored by the receiver." */
#define IDEMIP_ICMP6_CODE_PTB 0u

// ---------------------------------------------------------------------------
// Message bodies
// ---------------------------------------------------------------------------
// Every type here puts one 32-bit field at offset 4, then as much of the invoking packet as fits.
// Which field it is depends on the type: unused for Destination Unreachable and Time Exceeded, the
// next-hop MTU for Packet Too Big, and the octet offset of the fault for Parameter Problem.

#define IDEMIP_ICMP6_OFF_MTU 4u     ///< 32-bit MTU (sec 3.2)
#define IDEMIP_ICMP6_OFF_POINTER 4u ///< 32-bit Pointer (sec 3.4)
#define IDEMIP_ICMP6_OFF_UNUSED 4u  ///< 32-bit Unused, zero on transmission (sec 3.1, sec 3.3)
#define IDEMIP_ICMP6_ERR_HDR_LEN 8u ///< through that field; the invoking packet follows

#define IDEMIP_ICMP6_OFF_ID 4u       ///< 16-bit Identifier (sec 4.1)
#define IDEMIP_ICMP6_OFF_SEQ 6u      ///< 16-bit Sequence Number (sec 4.1)
#define IDEMIP_ICMP6_ECHO_HDR_LEN 8u ///< through the sequence number; data follows

/**
 * @brief How much of the invoking packet an error message may carry.
 *
 * RFC 4443 sec 3.1: "As much of invoking packet as possible without the ICMPv6 packet exceeding the
 * minimum IPv6 MTU", which leaves the IPv6 header and these eight octets out of the 1280.
 */
#define IDEMIP_ICMP6_ERR_QUOTE_MAX (IDEMIP_IPV6_MIN_MTU - IDEMIP_IPV6_HDR_LEN - IDEMIP_ICMP6_ERR_HDR_LEN)

/** @brief Type. */
IDEMIP_INLINE uint8_t idemip_icmp6_type(const uint8_t *m)
{
    return m[IDEMIP_ICMP6_OFF_TYPE];
}

/** @brief Code; its meaning depends on the type. */
IDEMIP_INLINE uint8_t idemip_icmp6_code(const uint8_t *m)
{
    return m[IDEMIP_ICMP6_OFF_CODE];
}

/** @brief Checksum as carried. */
IDEMIP_INLINE uint16_t idemip_icmp6_cksum(const uint8_t *m)
{
    return idemip_rd16(m + IDEMIP_ICMP6_OFF_CKSUM);
}

/** @brief True for types 128 through 255, which are informational rather than errors. */
IDEMIP_INLINE idemip_bool idemip_icmp6_is_informational(const uint8_t *m)
{
    return (m[IDEMIP_ICMP6_OFF_TYPE] & IDEMIP_ICMP6_INFORMATIONAL) != 0u;
}

/** @brief Identifier (echo request and echo reply). */
IDEMIP_INLINE uint16_t idemip_icmp6_id(const uint8_t *m)
{
    return idemip_rd16(m + IDEMIP_ICMP6_OFF_ID);
}

/** @brief Sequence Number (echo request and echo reply). */
IDEMIP_INLINE uint16_t idemip_icmp6_seq(const uint8_t *m)
{
    return idemip_rd16(m + IDEMIP_ICMP6_OFF_SEQ);
}

/** @brief MTU of the next-hop link (Packet Too Big). */
IDEMIP_INLINE uint32_t idemip_icmp6_mtu(const uint8_t *m)
{
    return idemip_rd32(m + IDEMIP_ICMP6_OFF_MTU);
}

/** @brief Octet offset within the invoking packet where the fault was found (Parameter Problem). */
IDEMIP_INLINE uint32_t idemip_icmp6_pointer(const uint8_t *m)
{
    return idemip_rd32(m + IDEMIP_ICMP6_OFF_POINTER);
}

/**
 * @brief The checksum to write over @p len bytes of message at @p m, between @p src and @p dst.
 *
 * RFC 4443 sec 2.3: "the 16-bit one's complement of the one's complement sum of the entire ICMPv6
 * message, starting with the ICMPv6 message type field, and prepended with a 'pseudo-header' of
 * IPv6 header fields... The Next Header value used in the pseudo-header is 58."
 *
 * The caller zeroes the checksum field first. Unlike RFC 792, the addresses are covered, because
 * IPv6 carries no header checksum of its own.
 */
IDEMIP_INLINE uint16_t idemip_icmp6_cksum_compute(const uint8_t *m, size_t len, const uint8_t *src,
                                                     const uint8_t *dst)
{
    uint32_t sum = idemip_ip6_pseudo_accum(0u, src, dst, (uint32_t)len, IDEMIP_IP6_NH_ICMPV6);
    return idemip_cksum_final(idemip_cksum_accum(sum, m, len));
}

// ---------------------------------------------------------------------------
// Build (RFC 4443 sec 3 and sec 4)
// ---------------------------------------------------------------------------
// Each helper writes one message into the caller's bytes and returns how many it wrote. The buffer
// is the caller's and is not held past the call. The checksum field is left zero, so a caller
// finishes a message with
//
//   idemip_wr16(m + IDEMIP_ICMP6_OFF_CKSUM, idemip_icmp6_cksum_compute(m, len, src, dst));

/** @brief Type, Code, and a zero Checksum: the three fields sec 2.1 puts at the head of every message. */
IDEMIP_INLINE void idemip_icmp6_hdr_write(uint8_t *m, uint8_t type, uint8_t code)
{
    m[IDEMIP_ICMP6_OFF_TYPE] = type;
    m[IDEMIP_ICMP6_OFF_CODE] = code;
    idemip_wr16(m + IDEMIP_ICMP6_OFF_CKSUM, 0u);
}

/**
 * @brief Octets of an invoking packet of @p invoking_len that an error message carries.
 *
 * RFC 4443 sec 2.4 (c): "Every ICMPv6 error message (type < 128) MUST include as much of the IPv6
 * offending (invoking) packet (the packet that caused the error) as possible without making the
 * error message packet exceed the minimum IPv6 MTU". Anything longer is truncated to what is left
 * of the 1280 once the IPv6 header and these eight octets are counted.
 */
IDEMIP_INLINE size_t idemip_icmp6_err_quote_len(size_t invoking_len)
{
    return (invoking_len > (size_t)IDEMIP_ICMP6_ERR_QUOTE_MAX) ? (size_t)IDEMIP_ICMP6_ERR_QUOTE_MAX : invoking_len;
}

/**
 * @brief An error message: the three head fields, the type's 32-bit field, then the clamped quote.
 *
 * @p word is what sec 3 puts at offset 4 for this type: Unused for Destination Unreachable and Time
 * Exceeded, MTU for Packet Too Big, Pointer for Parameter Problem.
 *
 * @p invoking points at the IPv6 header of the packet that caused the error, and must not overlap
 * @p m.
 *
 * @return bytes written, IDEMIP_ICMP6_ERR_HDR_LEN plus the quote.
 */
IDEMIP_INLINE size_t idemip_icmp6_err_build(uint8_t *m, uint8_t type, uint8_t code, uint32_t word,
                                            const uint8_t *invoking, size_t invoking_len)
{
    size_t quote = idemip_icmp6_err_quote_len(invoking_len);
    idemip_icmp6_hdr_write(m, type, code);
    idemip_wr32(m + IDEMIP_ICMP6_OFF_BODY, word);
    if (quote != 0u)
    {
        memcpy(m + IDEMIP_ICMP6_ERR_HDR_LEN, invoking, quote);
    }
    return (size_t)IDEMIP_ICMP6_ERR_HDR_LEN + quote;
}

/** @brief Destination Unreachable, sec 3.1: Type 1, one of Codes 0 through 6, Unused zero. */
IDEMIP_INLINE size_t idemip_icmp6_dest_unreach_build(uint8_t *m, uint8_t code, const uint8_t *invoking,
                                                     size_t invoking_len)
{
    return idemip_icmp6_err_build(m, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, code, 0u, invoking, invoking_len);
}

/**
 * @brief Packet Too Big, sec 3.2: Type 2, Code 0, and @p mtu, "The Maximum Transmission Unit of the
 * next-hop link".
 */
IDEMIP_INLINE size_t idemip_icmp6_packet_too_big_build(uint8_t *m, uint32_t mtu, const uint8_t *invoking,
                                                       size_t invoking_len)
{
    return idemip_icmp6_err_build(m, (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG, IDEMIP_ICMP6_CODE_PTB, mtu, invoking,
                                  invoking_len);
}

/** @brief Time Exceeded, sec 3.3: Type 3, Code 0 or 1, Unused zero. */
IDEMIP_INLINE size_t idemip_icmp6_time_exceeded_build(uint8_t *m, uint8_t code, const uint8_t *invoking,
                                                      size_t invoking_len)
{
    return idemip_icmp6_err_build(m, (uint8_t)IDEMIP_ICMP6_TIME_EXCEEDED, code, 0u, invoking, invoking_len);
}

/**
 * @brief Parameter Problem, sec 3.4: Type 4, one of Codes 0 through 2, and @p pointer, which
 * "Identifies the octet offset within the invoking packet where the error was detected".
 */
IDEMIP_INLINE size_t idemip_icmp6_param_problem_build(uint8_t *m, uint8_t code, uint32_t pointer,
                                                      const uint8_t *invoking, size_t invoking_len)
{
    return idemip_icmp6_err_build(m, (uint8_t)IDEMIP_ICMP6_PARAMETER_PROBLEM, code, pointer, invoking, invoking_len);
}

/**
 * @brief Echo Reply, sec 4.2: Type 129, Code 0, the request's Identifier and Sequence Number, and
 * its data.
 *
 * RFC 4443 sec 4.2: the Identifier and Sequence Number are "from the invoking Echo Request message",
 * and "The data received in the ICMPv6 Echo Request message MUST be returned entirely and unmodified
 * in the ICMPv6 Echo Reply message". @p data is that data, IDEMIP_ICMP6_ECHO_HDR_LEN into the
 * request, and must not overlap @p m. Sec 4.1 allows "Zero or more octets", so @p data_len may be 0.
 *
 * @return bytes written, IDEMIP_ICMP6_ECHO_HDR_LEN plus @p data_len.
 */
IDEMIP_INLINE size_t idemip_icmp6_echo_reply_build(uint8_t *m, uint16_t id, uint16_t seq, const uint8_t *data,
                                                   size_t data_len)
{
    idemip_icmp6_hdr_write(m, (uint8_t)IDEMIP_ICMP6_ECHO_REPLY, IDEMIP_ICMP6_CODE_ECHO);
    idemip_wr16(m + IDEMIP_ICMP6_OFF_ID, id);
    idemip_wr16(m + IDEMIP_ICMP6_OFF_SEQ, seq);
    if (data_len != 0u)
    {
        memcpy(m + IDEMIP_ICMP6_ECHO_HDR_LEN, data, data_len);
    }
    return (size_t)IDEMIP_ICMP6_ECHO_HDR_LEN + data_len;
}

static_assert(IDEMIP_ICMP6_OFF_CKSUM + 2u == IDEMIP_ICMP6_HDR_LEN,
              "the fields every RFC 4443 message shares must sum to the common header length");
static_assert(IDEMIP_ICMP6_OFF_BODY == IDEMIP_ICMP6_HDR_LEN,
              "the RFC 4443 sec 2.1 Message Body starts where the common header ends");
static_assert(IDEMIP_ICMP6_OFF_BODY + 4u == IDEMIP_ICMP6_ERR_HDR_LEN,
              "the 32-bit field each RFC 4443 sec 3 error message carries must end the error header");
static_assert(IDEMIP_ICMP6_OFF_SEQ + 2u == IDEMIP_ICMP6_ECHO_HDR_LEN,
              "the RFC 4443 sec 4.1 echo fields must sum to the echo header length");
static_assert(IDEMIP_IPV6_HDR_LEN + IDEMIP_ICMP6_ERR_HDR_LEN + IDEMIP_ICMP6_ERR_QUOTE_MAX <= IDEMIP_IPV6_MIN_MTU,
              "RFC 4443 sec 2.4 (c): an error message carrying a full quote must not exceed the minimum IPv6 MTU");
static_assert(IDEMIP_ICMP6_ECHO_REQUEST >= IDEMIP_ICMP6_INFORMATIONAL,
              "RFC 4443 sec 2.1 puts the informational types at 128 and above");
static_assert(IDEMIP_ICMP6_PARAMETER_PROBLEM < IDEMIP_ICMP6_INFORMATIONAL,
              "RFC 4443 sec 2.1 puts the error types below 128");
static_assert(IDEMIP_ICMP6_MLD_QUERY >= IDEMIP_ICMP6_INFORMATIONAL,
              "the RFC 2710 sec 3.1 types sit in the RFC 4443 sec 2.1 informational range");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_ICMPV6_H
