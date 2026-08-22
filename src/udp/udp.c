// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file udp.c
 * @brief The user datagram header, RFC 768, and the UDP-Lite variant of it, RFC 3828.
 *
 * Every entry below takes one parameter, a pointer to UdpCtx. A datagram access is the octets and,
 * when it writes or sums, the fields and addresses going with them, so those are one context.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/udp/udp.h"
#include "src/udp/udp_defines.h" // the RFC 768 field map, which this file is the first user of

#if IDEMIP_ENABLE_UDP

IDEMIP_BEGIN_DECLS

/** @brief One datagram access. */
typedef struct
{
    const uint8_t *h;       /**< The datagram a read or a sum walks. */
    uint8_t *w;             /**< The datagram a write puts fields into. */
    size_t len;             /**< Octets the sum spans. */
    uint32_t sum;           /**< A running checksum. */
    uint32_t src;           /**< Source address, for the pseudo-header. */
    uint32_t dst;           /**< Destination address, the same. */
    uint16_t src_port;      /**< Source Port a build writes. */
    uint16_t dst_port;      /**< Destination Port a build writes. */
    uint16_t v16;           /**< A 16-bit field a write sends: Length, Checksum or Coverage. */
    uint16_t udp_len;       /**< The Length the pseudo-header carries. */
    uint16_t cov;           /**< RFC 3828 Checksum Coverage. */
    uint16_t ip_payload_len; /**< The IP payload length RFC 3828 sec 3.2 takes the length from. */
    uint8_t proto;          /**< The IANA protocol number the pseudo-header carries. */
} UdpCtx;

// --- reading a received datagram -------------------------------------------

/** @brief Source Port. RFC 768: optional; "If not used, a value of zero is inserted." */
IDEMIP_INLINE uint16_t udp_src_port(const UdpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_UDP_OFF_SRC_PORT);
}

/** @brief Destination Port. */
IDEMIP_INLINE uint16_t udp_dst_port(const UdpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_UDP_OFF_DST_PORT);
}

/** @brief Length: this header plus the data. */
IDEMIP_INLINE uint16_t udp_len(const UdpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_UDP_OFF_LEN);
}

/** @brief Checksum as carried; IDEMIP_UDP_CKSUM_NONE means the sender computed none. */
IDEMIP_INLINE uint16_t udp_cksum_field(const UdpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_UDP_OFF_CKSUM);
}

/** @brief True when Length reaches the eight octets RFC 768 fixes as its minimum. */
IDEMIP_INLINE idemip_bool udp_len_valid(const UdpCtx *c)
{
    return (udp_len(c) >= IDEMIP_UDP_LEN_MIN) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

/**
 * @brief Data octets: Length less this header.
 *
 * Zero when Length is below RFC 768's minimum of eight, so a short field cannot wrap into a large
 * payload.
 */
IDEMIP_INLINE uint16_t udp_payload_len(const UdpCtx *c)
{
    uint16_t len = udp_len(c);
    return (len >= IDEMIP_UDP_LEN_MIN) ? (uint16_t)(len - IDEMIP_UDP_HDR_LEN) : 0u;
}

/** @brief True when the Checksum field carries one at all (RFC 768's all-zero value means none). */
IDEMIP_INLINE idemip_bool udp_cksum_present(const UdpCtx *c)
{
    return (udp_cksum_field(c) != IDEMIP_UDP_CKSUM_NONE) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- writing the four fields -----------------------------------------------

/** @brief Source Port. */
IDEMIP_INLINE void udp_set_src_port(const UdpCtx *c)
{
    idemip_wr16(c->w + IDEMIP_UDP_OFF_SRC_PORT, c->v16);
}

/** @brief Destination Port. */
IDEMIP_INLINE void udp_set_dst_port(const UdpCtx *c)
{
    idemip_wr16(c->w + IDEMIP_UDP_OFF_DST_PORT, c->v16);
}

/** @brief Length. */
IDEMIP_INLINE void udp_set_len(const UdpCtx *c)
{
    idemip_wr16(c->w + IDEMIP_UDP_OFF_LEN, c->v16);
}

/** @brief Checksum. */
IDEMIP_INLINE void udp_set_cksum(const UdpCtx *c)
{
    idemip_wr16(c->w + IDEMIP_UDP_OFF_CKSUM, c->v16);
}

/**
 * @brief Write the eight header octets: the two ports, the Length, and a cleared Checksum.
 *
 * The length is the whole datagram, this header plus the data, which is what RFC 768's Length
 * carries. The Checksum field goes out zeroed because the sum is taken over the datagram with it
 * zero; idemip_udp_cksum_write then fills it.
 */
IDEMIP_INLINE void udp_build(const UdpCtx *c)
{
    idemip_udp_set_src_port(c->w, c->src_port);
    idemip_udp_set_dst_port(c->w, c->dst_port);
    idemip_udp_set_len(c->w, c->v16);
    idemip_udp_set_cksum(c->w, IDEMIP_UDP_CKSUM_NONE);
}

// --- the checksum (RFC 768, "Fields") --------------------------------------

/**
 * @brief Accumulate the pseudo-header RFC 768 prefixes to the datagram for the checksum.
 *
 * "The pseudo header conceptually prefixed to the UDP header contains the source address, the
 * destination address, the protocol, and the UDP length. This information gives protection against
 * misrouted datagrams." It is a zero octet, the protocol, and the length, after the two addresses.
 *
 * The protocol is the IP header's Protocol field, IDEMIP_UDP_PROTO for RFC 768 and
 * IDEMIP_UDPLITE_PROTO for RFC 3828, whose pseudo-header is this same form (RFC 3828 sec 3.2).
 *
 * Not part of the datagram: it is summed, never sent, so this accumulates into a running sum the
 * caller then carries over the header and data.
 */
IDEMIP_INLINE uint32_t udp_pseudo_accum(const UdpCtx *c)
{
    uint32_t sum = c->sum;
    sum += (c->src >> 16) & 0xFFFFu;
    sum += c->src & 0xFFFFu;
    sum += (c->dst >> 16) & 0xFFFFu;
    sum += c->dst & 0xFFFFu;
    sum += (uint32_t)c->proto; // the zero octet leaves the protocol as the low half
    sum += (uint32_t)c->udp_len;
    return sum;
}

/**
 * @brief The checksum to write, over the pseudo-header and the datagram.
 *
 * The caller zeroes the checksum field first; RFC 1071's sum is over the datagram as it will be
 * sent, and the field is part of it. An odd length takes its last byte as [Z,0], which is RFC 768's
 * "padded with zero octets at the end (if necessary) to make a multiple of two octets".
 *
 * A computed zero comes back as all ones, per RFC 768.
 */
IDEMIP_INLINE uint16_t udp_cksum_compute(const UdpCtx *c)
{
    uint32_t sum = idemip_udp_pseudo_accum(0u, c->src, c->dst, (uint16_t)c->len, (uint8_t)IDEMIP_UDP_PROTO);
    uint16_t v = idemip_cksum_final(idemip_cksum_accum(sum, c->h, c->len));
    return (v == 0u) ? (uint16_t)IDEMIP_UDP_CKSUM_ZERO_AS : v;
}

/** @brief Clear the Checksum field, sum the datagram with it clear, and store the result there. */
IDEMIP_INLINE void udp_cksum_write(const UdpCtx *c)
{
    idemip_udp_set_cksum(c->w, IDEMIP_UDP_CKSUM_NONE);
    idemip_udp_set_cksum(c->w, idemip_udp_cksum_compute(c->w, c->len, c->src, c->dst));
}

/**
 * @brief True when a received datagram's carried checksum checks out.
 *
 * RFC 1071 sec 1: summing a span that already holds its checksum yields all ones, whose complement
 * is zero. Says nothing about an absent checksum, which is idemip_udp_cksum_present.
 */
IDEMIP_INLINE idemip_bool udp_cksum_valid(const UdpCtx *c)
{
    uint32_t sum = idemip_udp_pseudo_accum(0u, c->src, c->dst, (uint16_t)c->len, (uint8_t)IDEMIP_UDP_PROTO);
    return (idemip_cksum_final(idemip_cksum_accum(sum, c->h, c->len)) == 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- UDP-Lite (RFC 3828) ---------------------------------------------------

/** @brief Checksum Coverage: octets from the first octet of this header that the checksum covers. */
IDEMIP_INLINE uint16_t udplite_cov(const UdpCtx *c)
{
    return idemip_rd16(c->h + IDEMIP_UDPLITE_OFF_COV);
}

/** @brief Write the Checksum Coverage. */
IDEMIP_INLINE void udplite_set_cov(const UdpCtx *c)
{
    idemip_wr16(c->w + IDEMIP_UDPLITE_OFF_COV, c->v16);
}

/**
 * @brief Write the eight header octets: the two ports, the Checksum Coverage, and a cleared
 * Checksum.
 *
 * RFC 3828 sec 3.1: "Prior to computation, the checksum field MUST be set to zero."
 */
IDEMIP_INLINE void udplite_build(const UdpCtx *c)
{
    idemip_udp_set_src_port(c->w, c->src_port);
    idemip_udp_set_dst_port(c->w, c->dst_port);
    idemip_udplite_set_cov(c->w, c->cov);
    idemip_udp_set_cksum(c->w, IDEMIP_UDP_CKSUM_NONE);
}

/**
 * @brief Octets the checksum spans: the IP payload length when Coverage is zero, else Coverage.
 *
 * RFC 3828 sec 3.4: the IP module supplies "the length of the IP payload", which is this header and
 * every octet after it.
 */
IDEMIP_INLINE size_t udplite_cov_bytes(const UdpCtx *c)
{
    return (c->cov == IDEMIP_UDPLITE_COV_ALL) ? (size_t)c->ip_payload_len : (size_t)c->cov;
}

/**
 * @brief True when Coverage is one a receiver keeps (RFC 3828 sec 3.1).
 *
 * Three rules from that section: "MUST be either 0 or at least 8", "packets with a Checksum Coverage
 * greater than the IP length MUST also be discarded", and the header "MUST always be covered", which
 * a payload shorter than eight octets cannot satisfy at any Coverage.
 */
IDEMIP_INLINE idemip_bool udplite_cov_valid(const UdpCtx *c)
{
    if (c->ip_payload_len < IDEMIP_UDPLITE_COV_MIN)
    {
        return IDEMIP_FALSE;
    }
    if (c->cov == IDEMIP_UDPLITE_COV_ALL)
    {
        return IDEMIP_TRUE;
    }
    return (c->cov >= IDEMIP_UDPLITE_COV_MIN && c->cov <= c->ip_payload_len) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

/**
 * @brief The checksum to write, over the UDP-Lite pseudo-header and the covered octets.
 *
 * RFC 3828 sec 3.1: "the 16-bit one's complement of the one's complement sum of a pseudo-header of
 * information collected from the IP header, the number of octets specified by the Checksum Coverage
 * (starting at the first octet in the UDP-Lite header), virtually padded with a zero octet at the
 * end (if necessary) to make a multiple of two octets".
 *
 * sec 3.2: the pseudo-header's Length "is not taken from the UDP-Lite header, but rather from
 * information provided by the IP module", so the IP payload length goes into it while Coverage
 * bounds only the span summed. sec 3.1 again: "If the computed checksum is 0, it is transmitted as
 * all ones."
 */
IDEMIP_INLINE uint16_t udplite_cksum_compute(const UdpCtx *c)
{
    uint32_t sum = idemip_udp_pseudo_accum(0u, c->src, c->dst, c->ip_payload_len, (uint8_t)IDEMIP_UDPLITE_PROTO);
    uint16_t v = idemip_cksum_final(
        idemip_cksum_accum(sum, c->h, idemip_udplite_cov_bytes(c->cov, c->ip_payload_len)));
    return (v == 0u) ? (uint16_t)IDEMIP_UDP_CKSUM_ZERO_AS : v;
}

/** @brief Clear the Checksum field, sum the covered octets, and store the result there. */
IDEMIP_INLINE void udplite_cksum_write(const UdpCtx *c)
{
    idemip_udp_set_cksum(c->w, IDEMIP_UDP_CKSUM_NONE);
    idemip_udp_set_cksum(c->w, idemip_udplite_cksum_compute(c->w, c->cov, c->ip_payload_len, c->src, c->dst));
}

/**
 * @brief True when a received UDP-Lite datagram's carried checksum checks out over its coverage.
 *
 * Same sum as the sender's, with the field left as it arrived: RFC 1071 sec 1 makes that all ones,
 * whose complement is zero. RFC 3828 sec 3.1 forbids an all-zero transmitted checksum, so an absent
 * one is not a case here.
 */
IDEMIP_INLINE idemip_bool udplite_cksum_valid(const UdpCtx *c)
{
    uint32_t sum = idemip_udp_pseudo_accum(0u, c->src, c->dst, c->ip_payload_len, (uint8_t)IDEMIP_UDPLITE_PROTO);
    return (idemip_cksum_final(idemip_cksum_accum(sum, c->h, idemip_udplite_cov_bytes(c->cov, c->ip_payload_len))) ==
            0u)
               ? IDEMIP_TRUE
               : IDEMIP_FALSE;
}

/* The namespaces are tables of function pointers with the caller's argument lists in their types,
   so these are what they point at. Each builds the context and hands it to the body above. */

uint16_t idemip_udp_src_port(const uint8_t *h)
{
    return IDEMIP_CALL(udp_src_port, UdpCtx, .h = h);
}

uint16_t idemip_udp_dst_port(const uint8_t *h)
{
    return IDEMIP_CALL(udp_dst_port, UdpCtx, .h = h);
}

uint16_t idemip_udp_len(const uint8_t *h)
{
    return IDEMIP_CALL(udp_len, UdpCtx, .h = h);
}

uint16_t idemip_udp_cksum(const uint8_t *h)
{
    return IDEMIP_CALL(udp_cksum_field, UdpCtx, .h = h);
}

idemip_bool idemip_udp_len_valid(const uint8_t *h)
{
    return IDEMIP_CALL(udp_len_valid, UdpCtx, .h = h);
}

uint16_t idemip_udp_payload_len(const uint8_t *h)
{
    return IDEMIP_CALL(udp_payload_len, UdpCtx, .h = h);
}

idemip_bool idemip_udp_cksum_present(const uint8_t *h)
{
    return IDEMIP_CALL(udp_cksum_present, UdpCtx, .h = h);
}

void idemip_udp_set_src_port(uint8_t *h, uint16_t port)
{
    IDEMIP_CALL(udp_set_src_port, UdpCtx, .w = h, .v16 = port);
}

void idemip_udp_set_dst_port(uint8_t *h, uint16_t port)
{
    IDEMIP_CALL(udp_set_dst_port, UdpCtx, .w = h, .v16 = port);
}

void idemip_udp_set_len(uint8_t *h, uint16_t len)
{
    IDEMIP_CALL(udp_set_len, UdpCtx, .w = h, .v16 = len);
}

void idemip_udp_set_cksum(uint8_t *h, uint16_t cksum)
{
    IDEMIP_CALL(udp_set_cksum, UdpCtx, .w = h, .v16 = cksum);
}

void idemip_udp_build(uint8_t *h, uint16_t src_port, uint16_t dst_port, uint16_t len)
{
    IDEMIP_CALL(udp_build, UdpCtx, .w = h, .src_port = src_port, .dst_port = dst_port, .v16 = len);
}

uint32_t idemip_udp_pseudo_accum(uint32_t sum, uint32_t src, uint32_t dst, uint16_t udp_len, uint8_t proto)
{
    return IDEMIP_CALL(udp_pseudo_accum, UdpCtx, .sum = sum, .src = src, .dst = dst, .udp_len = udp_len,
                       .proto = proto);
}

uint16_t idemip_udp_cksum_compute(const uint8_t *h, size_t len, uint32_t src, uint32_t dst)
{
    return IDEMIP_CALL(udp_cksum_compute, UdpCtx, .h = h, .len = len, .src = src, .dst = dst);
}

void idemip_udp_cksum_write(uint8_t *h, size_t len, uint32_t src, uint32_t dst)
{
    IDEMIP_CALL(udp_cksum_write, UdpCtx, .w = h, .len = len, .src = src, .dst = dst);
}

idemip_bool idemip_udp_cksum_valid(const uint8_t *h, size_t len, uint32_t src, uint32_t dst)
{
    return IDEMIP_CALL(udp_cksum_valid, UdpCtx, .h = h, .len = len, .src = src, .dst = dst);
}

uint16_t idemip_udplite_cov(const uint8_t *h)
{
    return IDEMIP_CALL(udplite_cov, UdpCtx, .h = h);
}

void idemip_udplite_set_cov(uint8_t *h, uint16_t cov)
{
    IDEMIP_CALL(udplite_set_cov, UdpCtx, .w = h, .v16 = cov);
}

void idemip_udplite_build(uint8_t *h, uint16_t src_port, uint16_t dst_port, uint16_t cov)
{
    IDEMIP_CALL(udplite_build, UdpCtx, .w = h, .src_port = src_port, .dst_port = dst_port, .cov = cov);
}

size_t idemip_udplite_cov_bytes(uint16_t cov, uint16_t ip_payload_len)
{
    return IDEMIP_CALL(udplite_cov_bytes, UdpCtx, .cov = cov, .ip_payload_len = ip_payload_len);
}

idemip_bool idemip_udplite_cov_valid(uint16_t cov, uint16_t ip_payload_len)
{
    return IDEMIP_CALL(udplite_cov_valid, UdpCtx, .cov = cov, .ip_payload_len = ip_payload_len);
}

uint16_t idemip_udplite_cksum_compute(const uint8_t *h, uint16_t cov, uint16_t ip_payload_len, uint32_t src,
                                      uint32_t dst)
{
    return IDEMIP_CALL(udplite_cksum_compute, UdpCtx, .h = h, .cov = cov, .ip_payload_len = ip_payload_len, .src = src,
                       .dst = dst);
}

void idemip_udplite_cksum_write(uint8_t *h, uint16_t cov, uint16_t ip_payload_len, uint32_t src, uint32_t dst)
{
    IDEMIP_CALL(udplite_cksum_write, UdpCtx, .w = h, .cov = cov, .ip_payload_len = ip_payload_len, .src = src,
                .dst = dst);
}

idemip_bool idemip_udplite_cksum_valid(const uint8_t *h, uint16_t cov, uint16_t ip_payload_len, uint32_t src,
                                       uint32_t dst)
{
    return IDEMIP_CALL(udplite_cksum_valid, UdpCtx, .h = h, .cov = cov, .ip_payload_len = ip_payload_len, .src = src,
                       .dst = dst);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_UDP
