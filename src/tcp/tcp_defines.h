// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp_defines.h
 * @brief The TCP header's layout, RFC 9293 sec 3.1, and the options of sec 3.2, RFC 7323 and
 *        RFC 2018.
 *
 * Constants only. No entry, no table, no storage.
 *
 * Separate from tcp.h so that including the module does not drag the layout in with it. Included by
 * .c files that genuinely need the numbers, and by no surface header.
 */

#ifndef IDEMIP_TCP_DEFINES_H
#define IDEMIP_TCP_DEFINES_H

#include "src/common_defines.h" // IDEMIP_TCP_HDR_LEN, which the field map is asserted against

// ---------------------------------------------------------------------------
// Field offsets (RFC 9293 sec 3.1, Figure 1)
// ---------------------------------------------------------------------------

#define IDEMIP_TCP_OFF_SRC_PORT 0u    ///< 16-bit Source Port
#define IDEMIP_TCP_OFF_DST_PORT 2u    ///< 16-bit Destination Port
#define IDEMIP_TCP_OFF_SEQ 4u         ///< 32-bit Sequence Number
#define IDEMIP_TCP_OFF_ACK 8u         ///< 32-bit Acknowledgment Number
#define IDEMIP_TCP_OFF_OFFS_FLAGS 12u ///< 4-bit Data Offset, 4-bit Reserved, 8 control bits
#define IDEMIP_TCP_OFF_WINDOW 14u     ///< 16-bit Window
#define IDEMIP_TCP_OFF_CKSUM 16u      ///< 16-bit Checksum
#define IDEMIP_TCP_OFF_URGENT 18u     ///< 16-bit Urgent Pointer
#define IDEMIP_TCP_OFF_OPTIONS 20u    ///< Options, then data

// ---------------------------------------------------------------------------
// Data Offset (RFC 9293 sec 3.1)
// ---------------------------------------------------------------------------
// "The number of 32-bit words in the TCP header. This indicates where the data begins. The TCP
// header (even one including options) is an integer multiple of 32 bits long."

#define IDEMIP_TCP_DOFF_SHIFT 12u
#define IDEMIP_TCP_DOFF_MASK 0x0Fu

/** @brief An option-free header is five 32-bit words. */
#define IDEMIP_TCP_DOFF_MIN 5u

/** @brief Data Offset is 4 bits, so the header cannot exceed fifteen words. */
#define IDEMIP_TCP_DOFF_MAX 15u

/** @brief A Data Offset word is four octets, so words to octets is a shift by two. */
#define IDEMIP_TCP_WORD_SHIFT 2u

/** @brief Header bytes for a Data Offset of @p doff words. */
#define IDEMIP_TCP_HDR_BYTES(doff) ((size_t)(doff) << IDEMIP_TCP_WORD_SHIFT)

/** @brief The Data Offset a header of @p n bytes carries. */
#define IDEMIP_TCP_DOFF_FROM_BYTES(n) ((uint8_t)((n) >> IDEMIP_TCP_WORD_SHIFT))

/**
 * @brief Octets the options can occupy.
 *
 * RFC 9293 sec 3.1: "size(Options) == (DOffset-5)*32", so the largest Data Offset leaves ten words.
 * RFC 2018 sec 3 counts the same span as "the 40 bytes available for TCP options".
 */
#define IDEMIP_TCP_OPTS_MAX (IDEMIP_TCP_HDR_BYTES(IDEMIP_TCP_DOFF_MAX) - IDEMIP_TCP_HDR_LEN)

/**
 * @brief RFC 9293 sec 3.1: Reserved "Must be zero in generated segments and must be ignored in
 * received segments if the corresponding future features are not implemented".
 */
#define IDEMIP_TCP_RSRVD_MASK 0x0F00u

// ---------------------------------------------------------------------------
// Control bits (RFC 9293 sec 3.1)
// ---------------------------------------------------------------------------
// Assignment is IANA's; these are the eight currently assigned, in the order the figure lays them
// out above the window.

#define IDEMIP_TCP_CWR (1u << 7) ///< Congestion Window Reduced
#define IDEMIP_TCP_ECE (1u << 6) ///< ECN-Echo
#define IDEMIP_TCP_URG (1u << 5) ///< Urgent pointer field is significant
#define IDEMIP_TCP_ACK (1u << 4) ///< Acknowledgment field is significant
#define IDEMIP_TCP_PSH (1u << 3) ///< Push function
#define IDEMIP_TCP_RST (1u << 2) ///< Reset the connection
#define IDEMIP_TCP_SYN (1u << 1) ///< Synchronize sequence numbers
#define IDEMIP_TCP_FIN (1u << 0) ///< No more data from sender

// ---------------------------------------------------------------------------
// Options (RFC 9293 sec 3.2)
// ---------------------------------------------------------------------------
// Kind 0 and 1 are single octets; every other kind carries its own length octet, which is what
// lets a parser step past an option it does not implement. RFC 9293 sec 3.1 MUST-68: "All TCP
// Options except End of Option List Option (EOL) and No-Operation (NOP) MUST have length fields,
// including all future options".

#define IDEMIP_TCP_OPT_END 0u     ///< End of Option List
#define IDEMIP_TCP_OPT_NOP 1u     ///< No-Operation
#define IDEMIP_TCP_OPT_MSS 2u     ///< Maximum Segment Size
#define IDEMIP_TCP_OPT_MSS_LEN 4u ///< kind, length, and a 16-bit value

/**
 * @brief RFC 9293 sec 3.7.1 MUST-14: "TCP endpoints MUST implement both sending and receiving the
 * MSS Option."
 */
#define IDEMIP_TCP_MSS_KIND IDEMIP_TCP_OPT_MSS

// The two octets every option but kind 0 and kind 1 begins with, then its data.

#define IDEMIP_TCP_OPT_OFF_KIND 0u ///< 8-bit option-kind
#define IDEMIP_TCP_OPT_OFF_LEN 1u  ///< 8-bit option-length
#define IDEMIP_TCP_OPT_OFF_DATA 2u ///< the option-data octets

/**
 * @brief RFC 9293 sec 3.1: "The option-length counts the two octets of option-kind and
 * option-length as well as the option-data octets."
 *
 * So a length below two is illegal, which MUST-7 requires a parser to be ready for: "TCP
 * implementations MUST be prepared to handle an illegal option length (e.g., zero)".
 */
#define IDEMIP_TCP_OPT_LEN_MIN 2u

// ---------------------------------------------------------------------------
// Window Scale (RFC 7323 sec 2.2)
// ---------------------------------------------------------------------------
// "Kind: 3", "Length: 3 bytes", the third octet carrying shift.cnt.

#define IDEMIP_TCP_OPT_WS 3u           ///< Window Scale
#define IDEMIP_TCP_OPT_WS_LEN 3u       ///< kind, length, and shift.cnt
#define IDEMIP_TCP_OPT_OFF_WS_SHIFT 2u ///< 8-bit shift.cnt

/**
 * @brief RFC 7323 sec 2.2: "The maximum scale exponent is limited to 14 for a maximum permissible
 * receive window size of 1 GiB (2^(14+16))."
 *
 * sec 2.3: a larger shift.cnt received "MUST use 14 instead of the specified value".
 */
#define IDEMIP_TCP_WS_MAX 14u

// ---------------------------------------------------------------------------
// Timestamps (RFC 7323 sec 3.2)
// ---------------------------------------------------------------------------
// "Kind: 8", "Length: 10 bytes", carrying "two four-byte timestamp fields", TSval then TSecr.

#define IDEMIP_TCP_OPT_TS 8u        ///< Timestamps
#define IDEMIP_TCP_OPT_TS_LEN 10u   ///< kind, length, TSval and TSecr
#define IDEMIP_TCP_OPT_OFF_TSVAL 2u ///< 32-bit TS Value
#define IDEMIP_TCP_OPT_OFF_TSECR 6u ///< 32-bit TS Echo Reply

// ---------------------------------------------------------------------------
// Selective acknowledgment (RFC 2018 sec 2 and sec 3)
// ---------------------------------------------------------------------------
// sec 2: SACK-permitted is "Kind: 4" and "Length=2", sent only in a SYN. sec 3: the SACK option
// itself is "Kind: 5", "Length: Variable", a list of blocks each of two 32-bit edges.

#define IDEMIP_TCP_OPT_SACK_PERM 4u     ///< SACK-Permitted
#define IDEMIP_TCP_OPT_SACK_PERM_LEN 2u ///< kind and length, no data
#define IDEMIP_TCP_OPT_SACK 5u          ///< SACK

/** @brief A block is a Left Edge and a Right Edge, 32 bits each. */
#define IDEMIP_TCP_SACK_BLOCK_LEN 8u
#define IDEMIP_TCP_SACK_BLOCK_SHIFT 3u ///< block index to octet offset

/**
 * @brief RFC 2018 sec 3: "A SACK option that specifies n blocks will have a length of 8*n+2 bytes,
 * so the 40 bytes available for TCP options can specify a maximum of 4 blocks."
 */
#define IDEMIP_TCP_SACK_BLOCKS_MAX 4u

/** @brief Octets a SACK option carrying @p n blocks occupies, the 8*n+2 of sec 3. */
#define IDEMIP_TCP_SACK_BYTES(n) (IDEMIP_TCP_OPT_LEN_MIN + ((size_t)(n) << IDEMIP_TCP_SACK_BLOCK_SHIFT))

/**
 * @brief IANA Assigned Internet Protocol Numbers: TCP is 6.
 *
 * RFC 8200 sec 3 gives the IPv6 Next Header "the same values as the IPv4 Protocol field", so this
 * one number is what both pseudo-headers carry.
 */
#define IDEMIP_TCP_PROTO 6u

static_assert(IDEMIP_TCP_OFF_OPTIONS == IDEMIP_TCP_HDR_LEN,
              "the RFC 9293 field offsets must sum to the option-free header length");
static_assert(IDEMIP_TCP_HDR_BYTES(IDEMIP_TCP_DOFF_MIN) == IDEMIP_TCP_HDR_LEN,
              "the minimum Data Offset of 5 words is the option-free header (RFC 9293 sec 3.1)");
static_assert((1u << IDEMIP_TCP_WORD_SHIFT) == 4u,
              "Data Offset counts 32-bit words, so words to octets is a shift by two (RFC 9293 sec 3.1)");
static_assert(IDEMIP_TCP_DOFF_FROM_BYTES(IDEMIP_TCP_HDR_LEN) == IDEMIP_TCP_DOFF_MIN,
              "the option-free header is a Data Offset of five words (RFC 9293 sec 3.1)");
static_assert(IDEMIP_TCP_OPTS_MAX == 40u,
              "the largest Data Offset leaves ten words of options, RFC 2018 sec 3's \"40 bytes available\"");
static_assert((IDEMIP_TCP_CWR | IDEMIP_TCP_ECE | IDEMIP_TCP_URG | IDEMIP_TCP_ACK | IDEMIP_TCP_PSH | IDEMIP_TCP_RST |
               IDEMIP_TCP_SYN | IDEMIP_TCP_FIN) == 0xFFu,
              "the eight assigned control bits fill the low octet of the word at offset 12 (RFC 9293 sec 3.1 Fig 1)");
static_assert((((uint32_t)IDEMIP_TCP_DOFF_MASK << IDEMIP_TCP_DOFF_SHIFT) | IDEMIP_TCP_RSRVD_MASK | 0xFFu) == 0xFFFFu,
              "Data Offset, Reserved and the control bits fill the 16-bit word at offset 12 (RFC 9293 sec 3.1)");
static_assert((IDEMIP_TCP_RSRVD_MASK & 0xFFu) == 0u,
              "Reserved sits above the control bits and never overlaps one (RFC 9293 sec 3.1)");
static_assert(IDEMIP_TCP_OPT_OFF_DATA + 2u == IDEMIP_TCP_OPT_MSS_LEN,
              "kind 2 is two header octets and a 16-bit value (RFC 9293 sec 3.2)");
static_assert(IDEMIP_TCP_OPT_OFF_WS_SHIFT + 1u == IDEMIP_TCP_OPT_WS_LEN,
              "kind 3 is two header octets and shift.cnt (RFC 7323 sec 2.2)");
static_assert(IDEMIP_TCP_OPT_OFF_TSECR + 4u == IDEMIP_TCP_OPT_TS_LEN,
              "kind 8 is two header octets and two four-byte timestamps (RFC 7323 sec 3.2)");
static_assert(((uint32_t)1u << (IDEMIP_TCP_WS_MAX + 16u)) == 0x40000000u,
              "RFC 7323 sec 2.2 caps the scale exponent at 14 for a 1 GiB receive window, 2^(14+16)");
static_assert((1u << IDEMIP_TCP_SACK_BLOCK_SHIFT) == IDEMIP_TCP_SACK_BLOCK_LEN,
              "a SACK block is two 32-bit edges, so a block index is a shift by three (RFC 2018 sec 3)");
static_assert(IDEMIP_TCP_SACK_BYTES(IDEMIP_TCP_SACK_BLOCKS_MAX) <= IDEMIP_TCP_OPTS_MAX,
              "four SACK blocks fit the options, at 8*n+2 bytes (RFC 2018 sec 3)");
static_assert(IDEMIP_TCP_SACK_BYTES(IDEMIP_TCP_SACK_BLOCKS_MAX + 1u) > IDEMIP_TCP_OPTS_MAX,
              "four is the most 40 bytes of options hold, so a fifth block must not fit (RFC 2018 sec 3)");

#endif // IDEMIP_TCP_DEFINES_H
