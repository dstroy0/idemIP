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

#include "src/checksum.h"
#include "src/ip/ipv6.h"

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
 * ICMPv6, that is, MLD message types are a subset of the set of ICMPv6 messages", and RFC 4861
 * sec 4.1 through sec 4.5 take 133 through 137 for Neighbor Discovery.
 *
 * A type listed here is one this library implements, so sec 2.4 (b), "If an ICMPv6 informational
 * message of unknown type is received, it MUST be silently discarded", does not reach it.
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
    IDEMIP_ICMP6_ROUTER_SOLICIT = 133,  ///< RFC 4861 sec 4.1, "Router Solicitation"
    IDEMIP_ICMP6_ROUTER_ADVERT = 134,   ///< RFC 4861 sec 4.2, "Router Advertisement"
    IDEMIP_ICMP6_NEIGHBOR_SOLICIT = 135, ///< RFC 4861 sec 4.3, "Neighbor Solicitation"
    IDEMIP_ICMP6_NEIGHBOR_ADVERT = 136,  ///< RFC 4861 sec 4.4, "Neighbor Advertisement"
    IDEMIP_ICMP6_REDIRECT = 137,         ///< RFC 4861 sec 4.5, "Redirect"
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

/** @brief Maximum Response Delay, milliseconds (RFC 2710 sec 3.4). */
IDEMIP_INLINE uint16_t idemip_icmp6_mld_max_resp(const uint8_t *m)
{
    return idemip_rd16(m + IDEMIP_ICMP6_OFF_MLD_MAX_RESP);
}

/** @brief The Multicast Address, where it lies (RFC 2710 sec 3.6). */
IDEMIP_INLINE const uint8_t *idemip_icmp6_mld_group(const uint8_t *m)
{
    return m + IDEMIP_ICMP6_OFF_MLD_GROUP;
}

/**
 * @brief The octets a message of this type carries before its options, and zero for a type that has
 * none.
 *
 * RFC 4861 sec 4.1 through sec 4.5 fix one length per type, which is also the shortest such a
 * message can be: sec 6.1.1 refuses a Router Solicitation under "8 or more octets" and sec 6.1.2 a
 * Router Advertisement under "16 or more octets".
 */
IDEMIP_INLINE size_t idemip_icmp6_nd_hdr_len(uint8_t type)
{
    switch (type)
    {
    case IDEMIP_ICMP6_ROUTER_SOLICIT:
        return IDEMIP_ICMP6_RS_HDR_LEN;
    case IDEMIP_ICMP6_ROUTER_ADVERT:
        return IDEMIP_ICMP6_RA_HDR_LEN;
    case IDEMIP_ICMP6_NEIGHBOR_SOLICIT:
        return IDEMIP_ICMP6_NS_HDR_LEN;
    case IDEMIP_ICMP6_NEIGHBOR_ADVERT:
        return IDEMIP_ICMP6_NA_HDR_LEN;
    case IDEMIP_ICMP6_REDIRECT:
        return IDEMIP_ICMP6_RD_HDR_LEN;
    default:
        return 0u;
    }
}

/** @brief True for the five types RFC 4861 sec 4 defines. */
IDEMIP_INLINE idemip_bool idemip_icmp6_is_nd(uint8_t type)
{
    return (type >= (uint8_t)IDEMIP_ICMP6_ROUTER_SOLICIT && type <= (uint8_t)IDEMIP_ICMP6_REDIRECT) ? IDEMIP_TRUE
                                                                                                    : IDEMIP_FALSE;
}

/** @brief True for the three types RFC 2710 sec 3.1 defines. */
IDEMIP_INLINE idemip_bool idemip_icmp6_is_mld(uint8_t type)
{
    return (type >= (uint8_t)IDEMIP_ICMP6_MLD_QUERY && type <= (uint8_t)IDEMIP_ICMP6_MLD_DONE) ? IDEMIP_TRUE
                                                                                               : IDEMIP_FALSE;
}

/**
 * @brief The Target Address of a Neighbor Solicitation, Neighbor Advertisement or Redirect, where it
 * lies.
 *
 * RFC 4861 sec 4.3, sec 4.4 and sec 4.5 all put it at the same offset.
 */
IDEMIP_INLINE const uint8_t *idemip_icmp6_nd_target(const uint8_t *m)
{
    return m + IDEMIP_ICMP6_OFF_NS_TARGET;
}

/** @brief The Destination Address a Redirect names (RFC 4861 sec 4.5). */
IDEMIP_INLINE const uint8_t *idemip_icmp6_rd_dest(const uint8_t *m)
{
    return m + IDEMIP_ICMP6_OFF_RD_DEST;
}

/** @brief The R, S and O bits of a Neighbor Advertisement (RFC 4861 sec 4.4). */
IDEMIP_INLINE uint8_t idemip_icmp6_na_flags(const uint8_t *m)
{
    return m[IDEMIP_ICMP6_OFF_NA_FLAGS];
}

/** @brief Cur Hop Limit (RFC 4861 sec 4.2). */
IDEMIP_INLINE uint8_t idemip_icmp6_ra_cur_hop(const uint8_t *m)
{
    return m[IDEMIP_ICMP6_OFF_RA_CUR_HOP];
}

/** @brief The M and O bits of a Router Advertisement (RFC 4861 sec 4.2). */
IDEMIP_INLINE uint8_t idemip_icmp6_ra_flags(const uint8_t *m)
{
    return m[IDEMIP_ICMP6_OFF_RA_FLAGS];
}

/** @brief Router Lifetime, seconds (RFC 4861 sec 4.2). */
IDEMIP_INLINE uint16_t idemip_icmp6_ra_lifetime(const uint8_t *m)
{
    return idemip_rd16(m + IDEMIP_ICMP6_OFF_RA_LIFETIME);
}

/** @brief Reachable Time, milliseconds (RFC 4861 sec 4.2). */
IDEMIP_INLINE uint32_t idemip_icmp6_ra_reachable(const uint8_t *m)
{
    return idemip_rd32(m + IDEMIP_ICMP6_OFF_RA_REACHABLE);
}

/** @brief Retrans Timer, milliseconds (RFC 4861 sec 4.2). */
IDEMIP_INLINE uint32_t idemip_icmp6_ra_retrans(const uint8_t *m)
{
    return idemip_rd32(m + IDEMIP_ICMP6_OFF_RA_RETRANS);
}

/** @brief An option's Type (RFC 4861 sec 4.6). */
IDEMIP_INLINE uint8_t idemip_icmp6_nd_opt_type(const uint8_t *o)
{
    return o[IDEMIP_ICMP6_ND_OPT_OFF_TYPE];
}

/**
 * @brief An option's length in octets, its Length field shifted up three.
 *
 * RFC 4861 sec 4.6: "The length of the option (including the type and length fields) in units of 8
 * octets." Zero for a Length of zero, which sec 4.6 makes the whole packet's fault.
 */
IDEMIP_INLINE size_t idemip_icmp6_nd_opt_len(const uint8_t *o)
{
    return (size_t)o[IDEMIP_ICMP6_ND_OPT_OFF_LEN] << IDEMIP_ICMP6_ND_OPT_UNIT_SHIFT;
}

/**
 * @brief Every option in @p len octets at @p opts closes inside them and none has Length zero.
 *
 * RFC 4861 sec 4.6: "Nodes MUST silently discard an ND packet that contains an option with length
 * zero." An option whose Length runs past the message end is the same refusal, since the octets it
 * names are not there to read.
 */
IDEMIP_INLINE idemip_bool idemip_icmp6_nd_opts_ok(const uint8_t *opts, size_t len)
{
    size_t at = 0u;
    while (at != len)
    {
        if (len - at < (size_t)IDEMIP_ICMP6_ND_OPT_HDR_LEN)
        {
            return IDEMIP_FALSE;
        }
        size_t step = idemip_icmp6_nd_opt_len(opts + at);
        if (step == 0u || step > len - at)
        {
            return IDEMIP_FALSE;
        }
        at += step;
    }
    return IDEMIP_TRUE;
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
static_assert(IDEMIP_ICMP6_ROUTER_SOLICIT >= IDEMIP_ICMP6_INFORMATIONAL,
              "the RFC 4861 sec 4 types sit in the RFC 4443 sec 2.1 informational range");
static_assert(IDEMIP_ICMP6_REDIRECT - IDEMIP_ICMP6_ROUTER_SOLICIT == 4,
              "RFC 4861 sec 4.1 through sec 4.5 assign five consecutive types");
static_assert(IDEMIP_ICMP6_OFF_MLD_GROUP + IDEMIP_IP6_ADDR_LEN == IDEMIP_ICMP6_MLD_MSG_LEN,
              "the RFC 2710 sec 3 Multicast Address must end the MLD message");
static_assert(IDEMIP_ICMP6_OFF_RS_RESERVED + 4u == IDEMIP_ICMP6_RS_HDR_LEN,
              "RFC 4861 sec 4.1 puts the options where the 32-bit Reserved ends");
static_assert(IDEMIP_ICMP6_OFF_RA_RETRANS + 4u == IDEMIP_ICMP6_RA_HDR_LEN,
              "RFC 4861 sec 4.2 puts the options where Retrans Timer ends");
static_assert(IDEMIP_ICMP6_OFF_NS_TARGET + IDEMIP_IP6_ADDR_LEN == IDEMIP_ICMP6_NS_HDR_LEN,
              "RFC 4861 sec 4.3 puts the options where the Target Address ends");
static_assert(IDEMIP_ICMP6_OFF_NA_TARGET + IDEMIP_IP6_ADDR_LEN == IDEMIP_ICMP6_NA_HDR_LEN,
              "RFC 4861 sec 4.4 puts the options where the Target Address ends");
static_assert(IDEMIP_ICMP6_OFF_RD_DEST + IDEMIP_IP6_ADDR_LEN == IDEMIP_ICMP6_RD_HDR_LEN,
              "RFC 4861 sec 4.5 puts the options where the Destination Address ends");
static_assert(IDEMIP_ICMP6_OFF_NS_TARGET == IDEMIP_ICMP6_OFF_NA_TARGET &&
                  IDEMIP_ICMP6_OFF_NS_TARGET == IDEMIP_ICMP6_OFF_RD_TARGET,
              "one Target Address accessor serves sec 4.3, sec 4.4 and sec 4.5 only while they agree");
static_assert(IDEMIP_ICMP6_ND_OPT_OFF_VALUE == IDEMIP_ICMP6_ND_OPT_HDR_LEN,
              "an RFC 4861 sec 4.6 option's value starts where its Type and Length end");
static_assert(IDEMIP_ICMP6_ND_OPT_OFF_PREFIX + IDEMIP_IP6_ADDR_LEN ==
                  (IDEMIP_ICMP6_ND_OPT_PREFIX_LEN << IDEMIP_ICMP6_ND_OPT_UNIT_SHIFT),
              "RFC 4861 sec 4.6.2 gives Prefix Information a Length of 4, which is 32 octets");
static_assert(IDEMIP_ICMP6_ND_OPT_OFF_MTU + 4u == (IDEMIP_ICMP6_ND_OPT_MTU_LEN << IDEMIP_ICMP6_ND_OPT_UNIT_SHIFT),
              "RFC 4861 sec 4.6.4 gives MTU a Length of 1, which is 8 octets");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_ICMPV6_H
