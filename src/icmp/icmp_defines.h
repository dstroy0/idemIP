// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmp_defines.h
 * @brief The RFC 792 message layout: the common head, each type's fields, and the codes.
 *
 * Constants only. No entry, no table, no storage.
 *
 * Separate from icmp.h so that including the module does not drag the layout in with it. Included
 * by .c files that genuinely need the numbers, and by no surface header.
 */

#ifndef IDEMIP_ICMP_DEFINES_H
#define IDEMIP_ICMP_DEFINES_H

#include "src/ip/ipv4_defines.h" // an error message quotes an internet header, sized by its IHL

// ---------------------------------------------------------------------------
// The common three fields, at the head of every message (RFC 792)
// ---------------------------------------------------------------------------

#define IDEMIP_ICMP_OFF_TYPE 0u  ///< 8-bit Type
#define IDEMIP_ICMP_OFF_CODE 1u  ///< 8-bit Code
#define IDEMIP_ICMP_OFF_CKSUM 2u ///< 16-bit Checksum
#define IDEMIP_ICMP_HDR_LEN 4u   ///< the part every type shares

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

// ---------------------------------------------------------------------------
// The maps close on themselves
// ---------------------------------------------------------------------------

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

#endif // IDEMIP_ICMP_DEFINES_H
