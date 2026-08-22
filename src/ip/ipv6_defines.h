// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ipv6_defines.h
 * @brief The IPv6 header's layout, RFC 8200 sec 3, and the headers that chain off it.
 *
 * Constants only. No entry, no table, no storage.
 *
 * Separate from ipv6.h so that including the module does not drag the layout in with it. Included
 * by .c files that genuinely need the numbers, and by no surface header.
 */

#ifndef IDEMIP_IPV6_DEFINES_H
#define IDEMIP_IPV6_DEFINES_H

#include "src/idemip_config.h"
#include "src/common_defines.h" // IDEMIP_IPV6_HDR_LEN, which the field map is asserted against

// ---------------------------------------------------------------------------
// Field offsets (RFC 8200 sec 3)
// ---------------------------------------------------------------------------

#define IDEMIP_IP6_OFF_VER_TC_FLOW 0u ///< 4-bit Version, 8-bit Traffic Class, 20-bit Flow Label
#define IDEMIP_IP6_OFF_PAYLOAD_LEN 4u ///< 16-bit Payload Length
#define IDEMIP_IP6_OFF_NEXT_HDR 6u    ///< 8-bit Next Header
#define IDEMIP_IP6_OFF_HOP_LIMIT 7u   ///< 8-bit Hop Limit
#define IDEMIP_IP6_OFF_SRC 8u         ///< 128-bit Source Address
#define IDEMIP_IP6_OFF_DST 24u        ///< 128-bit Destination Address
#define IDEMIP_IP6_OFF_PAYLOAD 40u    ///< extension headers, then the upper-layer header

/** @brief An address is sixteen octets (RFC 8200 sec 3). */
#define IDEMIP_IP6_ADDR_LEN 16u

// ---------------------------------------------------------------------------
// Version, Traffic Class and Flow Label, the first word
// ---------------------------------------------------------------------------
// RFC 8200 sec 3: a 4-bit version, an 8-bit traffic class and a 20-bit flow label, packed into one
// 32-bit word, so all three come out of a single read.

/** @brief RFC 8200 sec 3: "4-bit Internet Protocol version number = 6." */
#define IDEMIP_IP6_VERSION 6u

#define IDEMIP_IP6_VER_SHIFT 28u
#define IDEMIP_IP6_VER_MASK 0x0Fu
#define IDEMIP_IP6_TC_SHIFT 20u
#define IDEMIP_IP6_TC_MASK 0xFFu
#define IDEMIP_IP6_FLOW_MASK 0x000FFFFFu ///< the 20-bit flow label

/**
 * @brief Largest Payload Length the field carries.
 *
 * RFC 8200 sec 4.5: a fragment whose "length and offset ... are such that the Payload Length of the
 * packet reassembled from that fragment would exceed 65,535 octets" is discarded.
 */
#define IDEMIP_IP6_PAYLOAD_MAX 65535u

// ---------------------------------------------------------------------------
// Next Header values (RFC 8200 sec 4, assigned by IANA)
// ---------------------------------------------------------------------------
// The same numbering as the IPv4 Protocol field, extension headers included: sec 4 says "when
// processing a sequence of Next Header values in a packet, the first one that is not an extension
// header indicates that the next item in the packet is the corresponding upper-layer header".

#define IDEMIP_IP6_NH_HOPOPT 0u ///< Hop-by-Hop Options, and only immediately after the header
#define IDEMIP_IP6_NH_TCP 6u
#define IDEMIP_IP6_NH_UDP 17u
#define IDEMIP_IP6_NH_ROUTING 43u  ///< Routing header (sec 4.4)
#define IDEMIP_IP6_NH_FRAGMENT 44u ///< Fragment header (sec 4.5)
#define IDEMIP_IP6_NH_ICMPV6 58u   ///< ICMPv6 (RFC 4443)
#define IDEMIP_IP6_NH_NONE 59u     ///< No Next Header (sec 4.7)
#define IDEMIP_IP6_NH_DSTOPTS 60u  ///< Destination Options (sec 4.6)

// ---------------------------------------------------------------------------
// Extension headers (RFC 8200 sec 4)
// ---------------------------------------------------------------------------
// Hop-by-Hop Options, Routing and Destination Options all begin the same two octets: the next
// header, then the length of this one. Fragment does not, and is sized by the standard instead.

#define IDEMIP_IP6_EXT_OFF_NEXT_HDR 0u ///< 8-bit Next Header
#define IDEMIP_IP6_EXT_OFF_LEN 1u      ///< 8-bit Hdr Ext Len

/**
 * @brief RFC 8200 sec 4: "Each extension header is an integer multiple of 8 octets long, in order
 * to retain 8-octet alignment for subsequent headers."
 */
#define IDEMIP_IP6_EXT_UNIT 8u

/**
 * @brief Bytes of an extension header whose Hdr Ext Len field reads @p len.
 *
 * RFC 8200 sec 4.3: "Length of the Hop-by-Hop Options header in 8-octet units, not including the
 * first 8 octets", so the first unit is implied and a field of zero is a header of eight.
 */
#define IDEMIP_IP6_EXT_BYTES(len) (((size_t)(len) + 1u) * IDEMIP_IP6_EXT_UNIT)

/** @brief Bytes the widest Hdr Ext Len reaches, the field being eight bits. */
#define IDEMIP_IP6_EXT_BYTES_MAX IDEMIP_IP6_EXT_BYTES(0xFFu)

// ---------------------------------------------------------------------------
// Options (RFC 8200 sec 4.2)
// ---------------------------------------------------------------------------
// The Hop-by-Hop Options and Destination Options headers carry a type-length-value sequence. Pad1
// is the one type with no length octet.

#define IDEMIP_IP6_OPT_OFF_TYPE 0u ///< 8-bit Option Type
#define IDEMIP_IP6_OPT_OFF_LEN 1u  ///< 8-bit Opt Data Len
#define IDEMIP_IP6_OPT_PAD1 0u     ///< one octet of padding, no length and no value
#define IDEMIP_IP6_OPT_PADN 1u     ///< N octets of padding, the length field reading N-2

/**
 * @brief The two bits saying what to do with a type this node does not recognize.
 *
 * RFC 8200 sec 4.2: "The Option Type identifiers are internally encoded such that their
 * highest-order 2 bits specify the action that must be taken if the processing IPv6 node does not
 * recognize the Option Type".
 */
#define IDEMIP_IP6_OPT_ACT_MASK 0xC0u
#define IDEMIP_IP6_OPT_ACT_SKIP 0x00u         ///< 00, skip over this option and keep going
#define IDEMIP_IP6_OPT_ACT_DISCARD 0x40u      ///< 01, discard the packet
#define IDEMIP_IP6_OPT_ACT_DISCARD_ICMP 0x80u ///< 10, discard and always answer Parameter Problem
#define IDEMIP_IP6_OPT_ACT_DISCARD_UNI 0xC0u  ///< 11, discard, and answer only if not multicast

/**
 * @brief RFC 8200 sec 4.2: the third-highest bit "specifies whether or not the Option Data of that
 * option can change en route to the packet's final destination".
 */
#define IDEMIP_IP6_OPT_CHG_MASK 0x20u

// ---------------------------------------------------------------------------
// Fragment header (RFC 8200 sec 4.5)
// ---------------------------------------------------------------------------
// Eight octets, and the only extension header this document gives a fixed size. Fragmentation is
// the source node's alone: sec 4.5 notes it is "performed only by source nodes, not by routers
// along a packet's delivery path".

#define IDEMIP_IP6_FRAG_OFF_NEXT_HDR 0u ///< 8-bit Next Header
#define IDEMIP_IP6_FRAG_OFF_RESERVED 1u ///< 8-bit Reserved, zero on transmission
#define IDEMIP_IP6_FRAG_OFF_OFFS_M 2u   ///< 13-bit Fragment Offset, 2-bit Res, 1-bit M
#define IDEMIP_IP6_FRAG_OFF_IDENT 4u    ///< 32-bit Identification
#define IDEMIP_IP6_FRAG_HDR_LEN 8u

/**
 * @brief RFC 8200 sec 4.5: the offset is "in 8-octet units", and it sits three bits up in the
 * field, so masking off the reserved bits and the M flag leaves the byte position already scaled.
 */
#define IDEMIP_IP6_FRAG_OFF_MASK 0xFFF8u

/**
 * @brief RFC 8200 sec 4.5: the "2-bit reserved field" between the offset and the M flag,
 * "Initialized to zero for transmission; ignored on reception."
 */
#define IDEMIP_IP6_FRAG_RES_MASK 0x0006u

/** @brief RFC 8200 sec 4.5: "1 = more fragments; 0 = last fragment." */
#define IDEMIP_IP6_FRAG_M (1u << 0)

// ---------------------------------------------------------------------------
// Routing header (RFC 8200 sec 4.4)
// ---------------------------------------------------------------------------
// The common two octets, then the variant and how far along it is.

#define IDEMIP_IP6_RT_OFF_TYPE 2u      ///< 8-bit Routing Type
#define IDEMIP_IP6_RT_OFF_SEGS_LEFT 3u ///< 8-bit Segments Left

// ---------------------------------------------------------------------------
// The maps close on themselves
// ---------------------------------------------------------------------------

static_assert(IDEMIP_IP6_OFF_PAYLOAD == IDEMIP_IPV6_HDR_LEN,
              "the RFC 8200 field offsets must sum to the fixed header length");
static_assert(IDEMIP_IP6_OFF_DST + IDEMIP_IP6_ADDR_LEN == IDEMIP_IPV6_HDR_LEN,
              "the destination address must end the RFC 8200 sec 3 header");
static_assert(IDEMIP_IP6_EXT_BYTES(0u) == IDEMIP_IP6_EXT_UNIT,
              "a Hdr Ext Len of zero is one 8-octet unit (RFC 8200 sec 4.3)");
static_assert(IDEMIP_IP6_EXT_BYTES_MAX == 2048u,
              "an 8-bit Hdr Ext Len reaches 256 units of 8 octets (RFC 8200 sec 4.3)");
static_assert(IDEMIP_IP6_FRAG_OFF_IDENT + 4u == IDEMIP_IP6_FRAG_HDR_LEN,
              "the RFC 8200 sec 4.5 fields must sum to the fragment header length");

// The packed fields fill their word and do not overlap, as the sec 3 and sec 4.5 figures lay them out.
static_assert((((uint32_t)IDEMIP_IP6_VER_MASK << IDEMIP_IP6_VER_SHIFT) |
               ((uint32_t)IDEMIP_IP6_TC_MASK << IDEMIP_IP6_TC_SHIFT) | IDEMIP_IP6_FLOW_MASK) == 0xFFFFFFFFu,
              "Version, Traffic Class and Flow Label must fill the first word (RFC 8200 sec 3)");
static_assert((((uint32_t)IDEMIP_IP6_VER_MASK << IDEMIP_IP6_VER_SHIFT) &
               ((uint32_t)IDEMIP_IP6_TC_MASK << IDEMIP_IP6_TC_SHIFT)) == 0u,
              "Version must not overlap Traffic Class (RFC 8200 sec 3)");
static_assert((((uint32_t)IDEMIP_IP6_TC_MASK << IDEMIP_IP6_TC_SHIFT) & IDEMIP_IP6_FLOW_MASK) == 0u,
              "Traffic Class must not overlap the Flow Label (RFC 8200 sec 3)");
static_assert((IDEMIP_IP6_FRAG_OFF_MASK | IDEMIP_IP6_FRAG_RES_MASK | IDEMIP_IP6_FRAG_M) == 0xFFFFu,
              "the 13-bit Fragment Offset, the 2-bit Res and the M flag must fill the field "
              "(RFC 8200 sec 4.5)");
static_assert((IDEMIP_IP6_FRAG_OFF_MASK & (IDEMIP_IP6_FRAG_RES_MASK | IDEMIP_IP6_FRAG_M)) == 0u,
              "the Fragment Offset must not overlap Res or the M flag (RFC 8200 sec 4.5)");
static_assert((IDEMIP_IP6_OPT_ACT_MASK | IDEMIP_IP6_OPT_CHG_MASK) == 0xE0u,
              "the two action bits and the change bit are the three high-order bits of an Option Type "
              "(RFC 8200 sec 4.2)");
static_assert(IDEMIP_IP6_RT_OFF_SEGS_LEFT < IDEMIP_IP6_EXT_UNIT,
              "the four named Routing header octets lie in its first 8-octet unit (RFC 8200 sec 4.4)");

#endif // IDEMIP_IPV6_DEFINES_H
