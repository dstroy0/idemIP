// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ipv4_defines.h
 * @brief The internet header's layout, RFC 791 sec 3.1: field offsets and the masks that split the
 *        packed ones.
 *
 * Constants only. No entry, no table, no storage.
 *
 * Separate from ipv4.h so that including the module does not drag the layout in with it. Included
 * by .c files that genuinely need the numbers, and by no surface header.
 */

#ifndef IDEMIP_IPV4_DEFINES_H
#define IDEMIP_IPV4_DEFINES_H

#include "src/idemip_config.h"
#include "src/common_defines.h" // IDEMIP_IPV4_HDR_LEN, which the field map is asserted against

// ---------------------------------------------------------------------------
// Field offsets (RFC 791 sec 3.1, Figure 4)
// ---------------------------------------------------------------------------

#define IDEMIP_IP4_OFF_VER_IHL 0u    ///< 4-bit Version, 4-bit IHL
#define IDEMIP_IP4_OFF_TOS 1u        ///< 8-bit Type of Service
#define IDEMIP_IP4_OFF_TOTAL_LEN 2u  ///< 16-bit Total Length
#define IDEMIP_IP4_OFF_ID 4u         ///< 16-bit Identification
#define IDEMIP_IP4_OFF_FLAGS_FRAG 6u ///< 3-bit Flags, 13-bit Fragment Offset
#define IDEMIP_IP4_OFF_TTL 8u        ///< 8-bit Time to Live
#define IDEMIP_IP4_OFF_PROTO 9u      ///< 8-bit Protocol
#define IDEMIP_IP4_OFF_CKSUM 10u     ///< 16-bit Header Checksum
#define IDEMIP_IP4_OFF_SRC 12u       ///< 32-bit Source Address
#define IDEMIP_IP4_OFF_DST 16u       ///< 32-bit Destination Address
#define IDEMIP_IP4_OFF_OPTIONS 20u   ///< Options, then padding to a 32-bit boundary

// ---------------------------------------------------------------------------
// Version and IHL, the first octet
// ---------------------------------------------------------------------------

/** @brief RFC 791 sec 3.1: "This document describes version 4." */
#define IDEMIP_IP4_VERSION 4u

#define IDEMIP_IP4_VER_SHIFT 4u
#define IDEMIP_IP4_VER_MASK 0x0Fu
#define IDEMIP_IP4_IHL_MASK 0x0Fu

/**
 * @brief RFC 791 sec 3.1: "Internet Header Length is the length of the internet header in 32 bit
 * words... the minimum value for a correct header is 5."
 */
#define IDEMIP_IP4_IHL_MIN 5u

/** @brief IHL is 4 bits, so the header cannot exceed 15 words. */
#define IDEMIP_IP4_IHL_MAX 15u

/** @brief A 32-bit word is four octets, so a word count scales by a shift of two. */
#define IDEMIP_IP4_IHL_SHIFT 2u

/** @brief Header bytes for an IHL of @p ihl words. */
#define IDEMIP_IP4_HDR_BYTES(ihl) ((size_t)(ihl) << IDEMIP_IP4_IHL_SHIFT)

/** @brief RFC 791 sec 3.1: "The maximal internet header is 60 octets". */
#define IDEMIP_IP4_HDR_MAX 60u

// ---------------------------------------------------------------------------
// Total Length, the third and fourth octets
// ---------------------------------------------------------------------------

/**
 * @brief RFC 791 sec 3.1: "Total Length is the length of the datagram, measured in octets,
 * including internet header and data. This field allows the length of a datagram to be up to
 * 65,535 octets."
 */
#define IDEMIP_IP4_TOTAL_LEN_MAX 65535u

// ---------------------------------------------------------------------------
// Flags and Fragment Offset, the seventh and eighth octets
// ---------------------------------------------------------------------------
// RFC 791 sec 3.1: "Bit 0: reserved, must be zero. Bit 1: (DF) 0 = May Fragment, 1 = Don't
// Fragment. Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments." The three sit above a 13-bit
// fragment offset in one 16-bit field, so both come out of a single read.

#define IDEMIP_IP4_FLAG_RESERVED (1u << 15) ///< must be zero
#define IDEMIP_IP4_FLAG_DF (1u << 14)       ///< don't fragment
#define IDEMIP_IP4_FLAG_MF (1u << 13)       ///< more fragments
#define IDEMIP_IP4_FRAG_OFF_MASK 0x1FFFu    ///< the 13-bit fragment offset

/**
 * @brief RFC 791 sec 3.1: the fragment offset "is measured in units of 8 octets (64 bits)", so the
 * field counts eight-byte units and the byte position is the field shifted up by three.
 */
#define IDEMIP_IP4_FRAG_UNIT 8u
#define IDEMIP_IP4_FRAG_SHIFT 3u

/**
 * @brief RFC 791 sec 3.2: "This format allows 2**13 = 8192 fragments of 8 octets each for a total
 * of 65,536 octets."
 */
#define IDEMIP_IP4_FRAG_MAX_UNITS 8192u

/**
 * @brief RFC 791 sec 3.2: "Every internet module must be able to forward a datagram of 68 octets
 * without further fragmentation. This is because an internet header may be up to 60 octets, and the
 * minimum fragment is 8 octets."
 */
#define IDEMIP_IP4_MIN_FORWARD_MTU 68u

// ---------------------------------------------------------------------------
// Protocol numbers this tree carries (RFC 791 sec 3.1, assigned by IANA)
// ---------------------------------------------------------------------------

#define IDEMIP_IP4_PROTO_ICMP 1u
#define IDEMIP_IP4_PROTO_TCP 6u
#define IDEMIP_IP4_PROTO_UDP 17u

// ---------------------------------------------------------------------------
// The map closes on itself
// ---------------------------------------------------------------------------
// Each offset is the one before it plus that field's width, and the last lands on the option-free
// header length.

static_assert(IDEMIP_IP4_OFF_TOS == IDEMIP_IP4_OFF_VER_IHL + 1u, "Version and IHL share one octet");
static_assert(IDEMIP_IP4_OFF_TOTAL_LEN == IDEMIP_IP4_OFF_TOS + 1u, "Type of Service is 8 bits");
static_assert(IDEMIP_IP4_OFF_ID == IDEMIP_IP4_OFF_TOTAL_LEN + 2u, "Total Length is 16 bits");
static_assert(IDEMIP_IP4_OFF_FLAGS_FRAG == IDEMIP_IP4_OFF_ID + 2u, "Identification is 16 bits");
static_assert(IDEMIP_IP4_OFF_TTL == IDEMIP_IP4_OFF_FLAGS_FRAG + 2u, "Flags and Fragment Offset share 16 bits");
static_assert(IDEMIP_IP4_OFF_PROTO == IDEMIP_IP4_OFF_TTL + 1u, "Time to Live is 8 bits");
static_assert(IDEMIP_IP4_OFF_CKSUM == IDEMIP_IP4_OFF_PROTO + 1u, "Protocol is 8 bits");
static_assert(IDEMIP_IP4_OFF_SRC == IDEMIP_IP4_OFF_CKSUM + 2u, "Header Checksum is 16 bits");
static_assert(IDEMIP_IP4_OFF_DST == IDEMIP_IP4_OFF_SRC + 4u, "Source Address is 32 bits");
static_assert(IDEMIP_IP4_OFF_OPTIONS == IDEMIP_IP4_OFF_DST + 4u, "Destination Address is 32 bits");

static_assert(IDEMIP_IP4_OFF_OPTIONS == IDEMIP_IPV4_HDR_LEN,
              "the RFC 791 field offsets must sum to the option-free header length");
static_assert(IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN) == IDEMIP_IPV4_HDR_LEN,
              "the minimum IHL of 5 words is the option-free header (RFC 791 sec 3.1)");
static_assert(IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MAX) == IDEMIP_IP4_HDR_MAX,
              "RFC 791 sec 3.1: an IHL of 15 words is the 60-octet maximal internet header");
static_assert(IDEMIP_IP4_TOTAL_LEN_MAX == 0xFFFFu,
              "RFC 791 sec 3.1: Total Length is 16 bits, allowing up to 65,535 octets");

static_assert(IDEMIP_IP4_FLAG_RESERVED == 0x8000u && IDEMIP_IP4_FLAG_DF == 0x4000u && IDEMIP_IP4_FLAG_MF == 0x2000u,
              "RFC 791 sec 3.1 Flags: bit 0 reserved, bit 1 DF, bit 2 MF, most significant first");
static_assert((IDEMIP_IP4_FLAG_RESERVED | IDEMIP_IP4_FLAG_DF | IDEMIP_IP4_FLAG_MF | IDEMIP_IP4_FRAG_OFF_MASK) ==
                  0xFFFFu,
              "the three flags and the 13-bit Fragment Offset fill one 16-bit field");
static_assert((IDEMIP_IP4_FRAG_OFF_MASK & (IDEMIP_IP4_FLAG_RESERVED | IDEMIP_IP4_FLAG_DF | IDEMIP_IP4_FLAG_MF)) == 0u,
              "the Fragment Offset mask must not reach a flag bit");
static_assert(IDEMIP_IP4_FRAG_UNIT == (1u << IDEMIP_IP4_FRAG_SHIFT),
              "RFC 791 sec 3.1: the fragment offset is measured in units of 8 octets, so its shift is three");
static_assert(IDEMIP_IP4_FRAG_MAX_UNITS == IDEMIP_IP4_FRAG_OFF_MASK + 1u,
              "RFC 791 sec 3.2: 2**13 = 8192 fragments is the whole 13-bit field");
static_assert(IDEMIP_IP4_FRAG_MAX_UNITS * IDEMIP_IP4_FRAG_UNIT == 65536u,
              "RFC 791 sec 3.2: 8192 fragments of 8 octets each total 65,536 octets");
static_assert(IDEMIP_IP4_MIN_FORWARD_MTU == IDEMIP_IP4_HDR_MAX + IDEMIP_IP4_FRAG_UNIT,
              "RFC 791 sec 3.2: 68 octets is a 60-octet header plus the 8-octet minimum fragment");

#endif // IDEMIP_IPV4_DEFINES_H
