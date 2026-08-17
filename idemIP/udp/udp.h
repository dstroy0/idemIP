// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file udp.h
 * @brief The user datagram header, RFC 768, and the UDP-Lite variant of it, RFC 3828.
 *
 * Field offsets, the pseudo-header the checksum covers, and the writes that build one, all in the
 * caller's bytes. Holds nothing.
 */

#ifndef IDEMIP_UDP_H
#define IDEMIP_UDP_H

#include "idemIP/checksum.h"
#include "idemIP/ip/ipv4.h"

#if IDEMIP_ENABLE_UDP

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// Field offsets (RFC 768, "Format")
// ---------------------------------------------------------------------------

#define IDEMIP_UDP_OFF_SRC_PORT 0u ///< 16-bit Source Port
#define IDEMIP_UDP_OFF_DST_PORT 2u ///< 16-bit Destination Port
#define IDEMIP_UDP_OFF_LEN 4u      ///< 16-bit Length
#define IDEMIP_UDP_OFF_CKSUM 6u    ///< 16-bit Checksum
#define IDEMIP_UDP_HDR_LEN 8u      ///< the header, data follows

/**
 * @brief RFC 768: Length "is the length in octets of this user datagram including this header and
 * the data. (This means the minimum value of the length is eight.)"
 */
#define IDEMIP_UDP_LEN_MIN IDEMIP_UDP_HDR_LEN

/**
 * @brief RFC 768: "An all zero transmitted checksum value means that the transmitter generated no
 * checksum (for debugging or for higher level protocols that don't care)."
 */
#define IDEMIP_UDP_CKSUM_NONE 0x0000u

/**
 * @brief RFC 768: "If the computed checksum is zero, it is transmitted as all ones (the equivalent
 * in one's complement arithmetic)."
 *
 * Zero already means "no checksum", so a real result of zero is sent as its other representation
 * rather than being mistaken for an absent one.
 */
#define IDEMIP_UDP_CKSUM_ZERO_AS 0xFFFFu

// ---------------------------------------------------------------------------
// Accessors: every field is 16 bits, assembled from its bytes
// ---------------------------------------------------------------------------
// The header starts 20 bytes into an option-free IPv4 header that itself starts 14 bytes into an
// Ethernet frame, so a field lands at an even offset from an odd address.

/** @brief Source Port. RFC 768: optional; "If not used, a value of zero is inserted." */
IDEMIP_INLINE uint16_t idemip_udp_src_port(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_UDP_OFF_SRC_PORT);
}

/** @brief Destination Port. */
IDEMIP_INLINE uint16_t idemip_udp_dst_port(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_UDP_OFF_DST_PORT);
}

/** @brief Length: this header plus the data. */
IDEMIP_INLINE uint16_t idemip_udp_len(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_UDP_OFF_LEN);
}

/** @brief Checksum as carried; IDEMIP_UDP_CKSUM_NONE means the sender computed none. */
IDEMIP_INLINE uint16_t idemip_udp_cksum(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_UDP_OFF_CKSUM);
}

/** @brief True when Length reaches the eight octets RFC 768 fixes as its minimum. */
IDEMIP_INLINE idemip_bool idemip_udp_len_valid(const uint8_t *h)
{
    return (idemip_udp_len(h) >= IDEMIP_UDP_LEN_MIN) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

/**
 * @brief Data octets: Length less this header.
 *
 * Zero when Length is below RFC 768's minimum of eight, so a short field cannot wrap into a large
 * payload.
 */
IDEMIP_INLINE uint16_t idemip_udp_payload_len(const uint8_t *h)
{
    uint16_t len = idemip_udp_len(h);
    return (len >= IDEMIP_UDP_LEN_MIN) ? (uint16_t)(len - IDEMIP_UDP_HDR_LEN) : 0u;
}

/** @brief True when the Checksum field carries one at all (RFC 768's all-zero value means none). */
IDEMIP_INLINE idemip_bool idemip_udp_cksum_present(const uint8_t *h)
{
    return (idemip_udp_cksum(h) != IDEMIP_UDP_CKSUM_NONE) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// ---------------------------------------------------------------------------
// Build: the same four fields, written
// ---------------------------------------------------------------------------

IDEMIP_INLINE void idemip_udp_set_src_port(uint8_t *h, uint16_t port)
{
    idemip_wr16(h + IDEMIP_UDP_OFF_SRC_PORT, port);
}

IDEMIP_INLINE void idemip_udp_set_dst_port(uint8_t *h, uint16_t port)
{
    idemip_wr16(h + IDEMIP_UDP_OFF_DST_PORT, port);
}

IDEMIP_INLINE void idemip_udp_set_len(uint8_t *h, uint16_t len)
{
    idemip_wr16(h + IDEMIP_UDP_OFF_LEN, len);
}

IDEMIP_INLINE void idemip_udp_set_cksum(uint8_t *h, uint16_t cksum)
{
    idemip_wr16(h + IDEMIP_UDP_OFF_CKSUM, cksum);
}

/**
 * @brief Write the eight header octets: the two ports, the Length, and a cleared Checksum.
 *
 * @p len is the whole datagram, this header plus the data, which is what RFC 768's Length carries.
 * The Checksum field goes out zeroed because the sum is taken over the datagram with it zero;
 * idemip_udp_cksum_write then fills it.
 */
IDEMIP_INLINE void idemip_udp_build(uint8_t *h, uint16_t src_port, uint16_t dst_port, uint16_t len)
{
    idemip_udp_set_src_port(h, src_port);
    idemip_udp_set_dst_port(h, dst_port);
    idemip_udp_set_len(h, len);
    idemip_udp_set_cksum(h, IDEMIP_UDP_CKSUM_NONE);
}

// ---------------------------------------------------------------------------
// The checksum (RFC 768, "Fields")
// ---------------------------------------------------------------------------

/**
 * @brief Accumulate the pseudo-header RFC 768 prefixes to the datagram for the checksum.
 *
 * "The pseudo header conceptually prefixed to the UDP header contains the source address, the
 * destination address, the protocol, and the UDP length. This information gives protection against
 * misrouted datagrams." It is a zero octet, the protocol, and the length, after the two addresses.
 *
 * @p proto is the IP header's Protocol field, IDEMIP_IP4_PROTO_UDP for RFC 768 and
 * IDEMIP_UDPLITE_PROTO for RFC 3828, whose pseudo-header is this same form (RFC 3828 sec 3.2).
 *
 * Not part of the datagram: it is summed, never sent, so this accumulates into a running sum the
 * caller then carries over the header and data.
 */
IDEMIP_INLINE uint32_t idemip_udp_pseudo_accum(uint32_t sum, uint32_t src, uint32_t dst, uint16_t udp_len,
                                               uint8_t proto)
{
    sum += (src >> 16) & 0xFFFFu;
    sum += src & 0xFFFFu;
    sum += (dst >> 16) & 0xFFFFu;
    sum += dst & 0xFFFFu;
    sum += (uint32_t)proto; // the zero octet leaves the protocol as the low half
    sum += (uint32_t)udp_len;
    return sum;
}

/**
 * @brief The checksum to write, over the pseudo-header and @p len bytes of datagram at @p h.
 *
 * The caller zeroes the checksum field first; RFC 1071's sum is over the datagram as it will be
 * sent, and the field is part of it. An odd @p len takes its last byte as [Z,0], which is RFC 768's
 * "padded with zero octets at the end (if necessary) to make a multiple of two octets".
 *
 * A computed zero comes back as all ones, per RFC 768.
 */
IDEMIP_INLINE uint16_t idemip_udp_cksum_compute(const uint8_t *h, size_t len, uint32_t src, uint32_t dst)
{
    uint32_t sum = idemip_udp_pseudo_accum(0u, src, dst, (uint16_t)len, (uint8_t)IDEMIP_IP4_PROTO_UDP);
    uint16_t c = idemip_cksum_final(idemip_cksum_accum(sum, h, len));
    return (c == 0u) ? (uint16_t)IDEMIP_UDP_CKSUM_ZERO_AS : c;
}

/** @brief Clear the Checksum field, sum the datagram with it clear, and store the result there. */
IDEMIP_INLINE void idemip_udp_cksum_write(uint8_t *h, size_t len, uint32_t src, uint32_t dst)
{
    idemip_udp_set_cksum(h, IDEMIP_UDP_CKSUM_NONE);
    idemip_udp_set_cksum(h, idemip_udp_cksum_compute(h, len, src, dst));
}

/**
 * @brief True when a received datagram's carried checksum checks out.
 *
 * RFC 1071 sec 1: summing a span that already holds its checksum yields all ones, whose complement
 * is zero. Says nothing about an absent checksum, which is idemip_udp_cksum_present.
 */
IDEMIP_INLINE idemip_bool idemip_udp_cksum_valid(const uint8_t *h, size_t len, uint32_t src, uint32_t dst)
{
    uint32_t sum = idemip_udp_pseudo_accum(0u, src, dst, (uint16_t)len, (uint8_t)IDEMIP_IP4_PROTO_UDP);
    return (idemip_cksum_final(idemip_cksum_accum(sum, h, len)) == 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// ---------------------------------------------------------------------------
// UDP-Lite (RFC 3828)
// ---------------------------------------------------------------------------
// RFC 3828 sec 3: "Its format differs from UDP in that the Length field has been replaced with a
// Checksum Coverage field." Ports and Checksum keep their offsets, so only the third field is
// named again here.

/** @brief 16-bit Checksum Coverage, where RFC 768 puts Length (RFC 3828 sec 3, Figure 1). */
#define IDEMIP_UDPLITE_OFF_COV IDEMIP_UDP_OFF_LEN

/** @brief The header is the same eight octets. */
#define IDEMIP_UDPLITE_HDR_LEN IDEMIP_UDP_HDR_LEN

/**
 * @brief RFC 3828 sec 3.1: "A Checksum Coverage of zero indicates that the entire UDP-Lite packet
 * is covered by the checksum."
 */
#define IDEMIP_UDPLITE_COV_ALL 0u

/**
 * @brief RFC 3828 sec 3.1: "the value of the Checksum Coverage field MUST be either 0 or at least
 * 8. A UDP-Lite packet with a Checksum Coverage value of 1 to 7 MUST be discarded by the receiver."
 *
 * Eight is this header, which "MUST always be covered by the checksum".
 */
#define IDEMIP_UDPLITE_COV_MIN IDEMIP_UDPLITE_HDR_LEN

/** @brief RFC 3828 sec 7: "A new IP protocol number, 136 has been assigned for UDP-Lite." */
#define IDEMIP_UDPLITE_PROTO 136u

/** @brief Checksum Coverage: octets from the first octet of this header that the checksum covers. */
IDEMIP_INLINE uint16_t idemip_udplite_cov(const uint8_t *h)
{
    return idemip_rd16(h + IDEMIP_UDPLITE_OFF_COV);
}

IDEMIP_INLINE void idemip_udplite_set_cov(uint8_t *h, uint16_t cov)
{
    idemip_wr16(h + IDEMIP_UDPLITE_OFF_COV, cov);
}

/**
 * @brief Write the eight header octets: the two ports, the Checksum Coverage, and a cleared
 * Checksum.
 *
 * RFC 3828 sec 3.1: "Prior to computation, the checksum field MUST be set to zero."
 */
IDEMIP_INLINE void idemip_udplite_build(uint8_t *h, uint16_t src_port, uint16_t dst_port, uint16_t cov)
{
    idemip_udp_set_src_port(h, src_port);
    idemip_udp_set_dst_port(h, dst_port);
    idemip_udplite_set_cov(h, cov);
    idemip_udp_set_cksum(h, IDEMIP_UDP_CKSUM_NONE);
}

/**
 * @brief Octets the checksum spans: @p ip_payload_len when Coverage is zero, else Coverage itself.
 *
 * RFC 3828 sec 3.4: the IP module supplies "the length of the IP payload", which is this header and
 * every octet after it.
 */
IDEMIP_INLINE size_t idemip_udplite_cov_bytes(uint16_t cov, uint16_t ip_payload_len)
{
    return (cov == IDEMIP_UDPLITE_COV_ALL) ? (size_t)ip_payload_len : (size_t)cov;
}

/**
 * @brief True when Coverage is one a receiver keeps (RFC 3828 sec 3.1).
 *
 * Three rules from that section: "MUST be either 0 or at least 8", "packets with a Checksum Coverage
 * greater than the IP length MUST also be discarded", and the header "MUST always be covered", which
 * a payload shorter than eight octets cannot satisfy at any Coverage.
 */
IDEMIP_INLINE idemip_bool idemip_udplite_cov_valid(uint16_t cov, uint16_t ip_payload_len)
{
    if (ip_payload_len < IDEMIP_UDPLITE_COV_MIN)
    {
        return IDEMIP_FALSE;
    }
    if (cov == IDEMIP_UDPLITE_COV_ALL)
    {
        return IDEMIP_TRUE;
    }
    return (cov >= IDEMIP_UDPLITE_COV_MIN && cov <= ip_payload_len) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

/**
 * @brief The checksum to write, over the UDP-Lite pseudo-header and the covered octets at @p h.
 *
 * RFC 3828 sec 3.1: "the 16-bit one's complement of the one's complement sum of a pseudo-header of
 * information collected from the IP header, the number of octets specified by the Checksum Coverage
 * (starting at the first octet in the UDP-Lite header), virtually padded with a zero octet at the
 * end (if necessary) to make a multiple of two octets".
 *
 * sec 3.2: the pseudo-header's Length "is not taken from the UDP-Lite header, but rather from
 * information provided by the IP module", so @p ip_payload_len goes into it while Coverage bounds
 * only the span summed. sec 3.1 again: "If the computed checksum is 0, it is transmitted as all
 * ones."
 */
IDEMIP_INLINE uint16_t idemip_udplite_cksum_compute(const uint8_t *h, uint16_t cov, uint16_t ip_payload_len,
                                                    uint32_t src, uint32_t dst)
{
    uint32_t sum = idemip_udp_pseudo_accum(0u, src, dst, ip_payload_len, (uint8_t)IDEMIP_UDPLITE_PROTO);
    uint16_t c = idemip_cksum_final(idemip_cksum_accum(sum, h, idemip_udplite_cov_bytes(cov, ip_payload_len)));
    return (c == 0u) ? (uint16_t)IDEMIP_UDP_CKSUM_ZERO_AS : c;
}

/** @brief Clear the Checksum field, sum the covered octets, and store the result there. */
IDEMIP_INLINE void idemip_udplite_cksum_write(uint8_t *h, uint16_t cov, uint16_t ip_payload_len, uint32_t src,
                                              uint32_t dst)
{
    idemip_udp_set_cksum(h, IDEMIP_UDP_CKSUM_NONE);
    idemip_udp_set_cksum(h, idemip_udplite_cksum_compute(h, cov, ip_payload_len, src, dst));
}

/**
 * @brief True when a received UDP-Lite datagram's carried checksum checks out over its coverage.
 *
 * Same sum as the sender's, with the field left as it arrived: RFC 1071 sec 1 makes that all ones,
 * whose complement is zero. RFC 3828 sec 3.1 forbids an all-zero transmitted checksum, so an absent
 * one is not a case here.
 */
IDEMIP_INLINE idemip_bool idemip_udplite_cksum_valid(const uint8_t *h, uint16_t cov, uint16_t ip_payload_len,
                                                     uint32_t src, uint32_t dst)
{
    uint32_t sum = idemip_udp_pseudo_accum(0u, src, dst, ip_payload_len, (uint8_t)IDEMIP_UDPLITE_PROTO);
    return (idemip_cksum_final(idemip_cksum_accum(sum, h, idemip_udplite_cov_bytes(cov, ip_payload_len))) == 0u)
               ? IDEMIP_TRUE
               : IDEMIP_FALSE;
}

static_assert(IDEMIP_UDP_OFF_SRC_PORT + 2u == IDEMIP_UDP_OFF_DST_PORT,
              "Source Port is 16 bits and Destination Port follows it (RFC 768, Format)");
static_assert(IDEMIP_UDP_OFF_DST_PORT + 2u == IDEMIP_UDP_OFF_LEN,
              "Destination Port is 16 bits and Length follows it (RFC 768, Format)");
static_assert(IDEMIP_UDP_OFF_LEN + 2u == IDEMIP_UDP_OFF_CKSUM,
              "Length is 16 bits and Checksum follows it (RFC 768, Format)");
static_assert(IDEMIP_UDP_OFF_CKSUM + 2u == IDEMIP_UDP_HDR_LEN,
              "the RFC 768 field offsets must sum to the header length");
static_assert(IDEMIP_UDP_LEN_MIN == 8u, "RFC 768: \"the minimum value of the length is eight\"");
static_assert(IDEMIP_UDP_CKSUM_NONE != IDEMIP_UDP_CKSUM_ZERO_AS,
              "RFC 768's two checksum special cases are the two representations of zero, not one");
static_assert(IDEMIP_UDPLITE_OFF_COV == IDEMIP_UDP_OFF_LEN,
              "RFC 3828 sec 3 replaces Length with Checksum Coverage in place");
static_assert(IDEMIP_UDPLITE_COV_MIN == IDEMIP_UDPLITE_HDR_LEN,
              "RFC 3828 sec 3.1: the smallest nonzero Coverage is the header it must always cover");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_UDP

#endif // IDEMIP_UDP_H
