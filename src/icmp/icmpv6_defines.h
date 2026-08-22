// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmpv6_defines.h
 * @brief The RFC 4443 message layout, the RFC 2710 MLD body, and the RFC 4861 Neighbor Discovery
 *        bodies and options.
 *
 * Constants only. No entry, no table, no storage.
 *
 * Separate from icmpv6.h so that including the module does not drag the layout in with it. Included
 * by .c files that genuinely need the numbers, and by no surface header.
 */

#ifndef IDEMIP_ICMPV6_DEFINES_H
#define IDEMIP_ICMPV6_DEFINES_H

#include "src/common_defines.h" // the minimum IPv6 MTU, which bounds an error message's quote
#include "src/ip/ipv6_defines.h" // IDEMIP_IP6_ADDR_LEN, which the message bodies are measured in

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

// ---------------------------------------------------------------------------
// Multicast Listener Discovery message body (RFC 2710 sec 3)
// ---------------------------------------------------------------------------
// One body shape for all three types. The delay is in milliseconds, not IGMP's tenths of a second:
// sec 3.4 reads "the maximum allowed delay before sending a responding Report, in units of
// milliseconds".

#define IDEMIP_ICMP6_OFF_MLD_MAX_RESP 4u ///< 16-bit Maximum Response Delay (sec 3.4)
#define IDEMIP_ICMP6_OFF_MLD_RESERVED 6u ///< 16-bit Reserved, "ignored by receivers" (sec 3.5)
#define IDEMIP_ICMP6_OFF_MLD_GROUP 8u    ///< 128-bit Multicast Address (sec 3.6)
#define IDEMIP_ICMP6_MLD_MSG_LEN 24u     ///< through the Multicast Address, which ends the message

// ---------------------------------------------------------------------------
// Neighbor Discovery message bodies (RFC 4861 sec 4.1 through sec 4.5)
// ---------------------------------------------------------------------------
// Every one carries its options at the offset its fixed part ends on, which is also the shortest a
// message of that type can be.

/**
 * @brief The Hop Limit every one of the five arrives with, RFC 4861 sec 6.1.1, sec 6.1.2, sec 7.1.1,
 *        sec 7.1.2 and sec 8.1: "The IP Hop Limit field has a value of 255, i.e., the packet could
 *        not possibly have been forwarded by a router."
 *
 * sec 11.2 is what it buys: "received packets containing a Hop Limit of 255 must have originated
 * from a neighbor". A message arriving with any other value is an off-link sender's.
 */
#define IDEMIP_ICMP6_ND_HOP_LIMIT 255u

#define IDEMIP_ICMP6_OFF_RS_RESERVED 4u ///< 32-bit Reserved (sec 4.1)
#define IDEMIP_ICMP6_RS_HDR_LEN 8u      ///< through it; options follow

#define IDEMIP_ICMP6_OFF_RA_CUR_HOP 4u   ///< 8-bit Cur Hop Limit (sec 4.2)
#define IDEMIP_ICMP6_OFF_RA_FLAGS 5u     ///< M, O, and a 6-bit Reserved (sec 4.2)
#define IDEMIP_ICMP6_OFF_RA_LIFETIME 6u  ///< 16-bit Router Lifetime, seconds (sec 4.2)
#define IDEMIP_ICMP6_OFF_RA_REACHABLE 8u ///< 32-bit Reachable Time, milliseconds (sec 4.2)
#define IDEMIP_ICMP6_OFF_RA_RETRANS 12u  ///< 32-bit Retrans Timer, milliseconds (sec 4.2)
#define IDEMIP_ICMP6_RA_HDR_LEN 16u      ///< through it; options follow

/** @brief sec 4.2: "1-bit 'Managed address configuration' flag." */
#define IDEMIP_ICMP6_RA_FLAG_M 0x80u
/** @brief sec 4.2: "1-bit 'Other configuration' flag." */
#define IDEMIP_ICMP6_RA_FLAG_O 0x40u

#define IDEMIP_ICMP6_OFF_NS_RESERVED 4u ///< 32-bit Reserved (sec 4.3)
#define IDEMIP_ICMP6_OFF_NS_TARGET 8u   ///< 128-bit Target Address (sec 4.3)
#define IDEMIP_ICMP6_NS_HDR_LEN 24u     ///< through it; options follow

#define IDEMIP_ICMP6_OFF_NA_FLAGS 4u  ///< R, S, O, and a 29-bit Reserved (sec 4.4)
#define IDEMIP_ICMP6_OFF_NA_TARGET 8u ///< 128-bit Target Address (sec 4.4)
#define IDEMIP_ICMP6_NA_HDR_LEN 24u   ///< through it; options follow

/** @brief sec 4.4: "When set, the R-bit indicates that the sender is a router." */
#define IDEMIP_ICMP6_NA_FLAG_R 0x80u
/** @brief sec 4.4: "the S-bit indicates that the advertisement was sent in response to a Neighbor
 *  Solicitation from the Destination address". */
#define IDEMIP_ICMP6_NA_FLAG_S 0x40u
/** @brief sec 4.4: "the O-bit indicates that the advertisement should override an existing cache
 *  entry and update the cached link-layer address". */
#define IDEMIP_ICMP6_NA_FLAG_O 0x20u

#define IDEMIP_ICMP6_OFF_RD_RESERVED 4u ///< 32-bit Reserved (sec 4.5)
#define IDEMIP_ICMP6_OFF_RD_TARGET 8u   ///< 128-bit Target Address (sec 4.5)
#define IDEMIP_ICMP6_OFF_RD_DEST 24u    ///< 128-bit Destination Address (sec 4.5)
#define IDEMIP_ICMP6_RD_HDR_LEN 40u     ///< through it; options follow

// ---------------------------------------------------------------------------
// Neighbor Discovery option format (RFC 4861 sec 4.6)
// ---------------------------------------------------------------------------
// sec 4.6: "Length: 8-bit unsigned integer. The length of the option (including the type and
// length fields) in units of 8 octets", so an option's octet count is its Length shifted up three.

#define IDEMIP_ICMP6_ND_OPT_OFF_TYPE 0u  ///< 8-bit Type
#define IDEMIP_ICMP6_ND_OPT_OFF_LEN 1u   ///< 8-bit Length, in units of 8 octets
#define IDEMIP_ICMP6_ND_OPT_OFF_VALUE 2u ///< the rest, its shape fixed by the type
#define IDEMIP_ICMP6_ND_OPT_HDR_LEN 2u   ///< the part every option shares
#define IDEMIP_ICMP6_ND_OPT_UNIT_SHIFT 3u ///< Length counts eight-octet units

/** @brief The option types RFC 4861 sec 4.6 assigns. */
#define IDEMIP_ICMP6_ND_OPT_SLLA 1u   ///< sec 4.6.1, Source Link-Layer Address
#define IDEMIP_ICMP6_ND_OPT_TLLA 2u   ///< sec 4.6.1, Target Link-Layer Address
#define IDEMIP_ICMP6_ND_OPT_PREFIX 3u ///< sec 4.6.2, Prefix Information
#define IDEMIP_ICMP6_ND_OPT_RD_HDR 4u ///< sec 4.6.3, Redirected Header
#define IDEMIP_ICMP6_ND_OPT_MTU 5u    ///< sec 4.6.4, MTU

#define IDEMIP_ICMP6_ND_OPT_OFF_LLADDR 2u ///< the Link-Layer Address (sec 4.6.1)

#define IDEMIP_ICMP6_ND_OPT_OFF_PREFIX_LEN 2u   ///< 8-bit Prefix Length (sec 4.6.2)
#define IDEMIP_ICMP6_ND_OPT_OFF_PREFIX_FLAGS 3u ///< L, A, and a 6-bit Reserved1 (sec 4.6.2)
#define IDEMIP_ICMP6_ND_OPT_OFF_VALID 4u        ///< 32-bit Valid Lifetime, seconds (sec 4.6.2)
#define IDEMIP_ICMP6_ND_OPT_OFF_PREFERRED 8u    ///< 32-bit Preferred Lifetime, seconds (sec 4.6.2)
#define IDEMIP_ICMP6_ND_OPT_OFF_RESERVED2 12u   ///< 32-bit Reserved2 (sec 4.6.2)
#define IDEMIP_ICMP6_ND_OPT_OFF_PREFIX 16u      ///< 128-bit Prefix (sec 4.6.2)
#define IDEMIP_ICMP6_ND_OPT_PREFIX_LEN 4u       ///< its Length field, so 32 octets

/** @brief sec 4.6.2: the "on-link" flag, "when set, indicates that this prefix can be used for
 *  on-link determination". */
#define IDEMIP_ICMP6_ND_PREFIX_FLAG_L 0x80u
/** @brief sec 4.6.2: the "autonomous address-configuration" flag. */
#define IDEMIP_ICMP6_ND_PREFIX_FLAG_A 0x40u

#define IDEMIP_ICMP6_ND_OPT_OFF_MTU 4u ///< 32-bit MTU (sec 4.6.4)
#define IDEMIP_ICMP6_ND_OPT_MTU_LEN 1u ///< its Length field, so 8 octets

#define IDEMIP_ICMP6_ND_OPT_OFF_RD_DATA 8u ///< the "IP header + data" a Redirected Header carries

/**
 * @brief How much of the invoking packet an error message may carry.
 *
 * RFC 4443 sec 3.1: "As much of invoking packet as possible without the ICMPv6 packet exceeding the
 * minimum IPv6 MTU", which leaves the IPv6 header and these eight octets out of the 1280.
 */
#define IDEMIP_ICMP6_ERR_QUOTE_MAX (IDEMIP_IPV6_MIN_MTU - IDEMIP_IPV6_HDR_LEN - IDEMIP_ICMP6_ERR_HDR_LEN)

#endif // IDEMIP_ICMPV6_DEFINES_H
