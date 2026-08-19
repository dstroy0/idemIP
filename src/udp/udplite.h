// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file udplite.h
 * @brief The RFC 3828 partial-coverage checksum, over a datagram in the caller's bytes.
 *
 * RFC 3828 sec 3.1 states the Checksum Coverage rules a receiver discards on, and RFC 3828 sec 3.2
 * states that the pseudo-header's Length "is not taken from the UDP-Lite header, but rather from
 * information provided by the IP module". So a call takes the IP payload length and the Coverage
 * separately: the first goes into the pseudo-header, the second bounds the octets summed.
 *
 * The wire field map and the stateless helpers are udp.h's. This unit is the entry the input and
 * output paths call: it applies the sec 3.1 discard rules, runs the sum over the covered span with
 * the sec 3.2 pseudo-header of the IP version in hand, and reports how far the coverage reaches.
 */

#ifndef IDEMIP_UDPLITE_H
#define IDEMIP_UDPLITE_H

#include "src/udp/udp.h"

#if IDEMIP_ENABLE_UDP

IDEMIP_BEGIN_DECLS

/**
 * @brief Which rule a refused call broke. Diagnostic: no control flow here branches on it.
 *
 * @var IdemIpUdpLiteReason::IDEMIP_UDPLITE_REASON_NONE          the call finished
 * @var IdemIpUdpLiteReason::IDEMIP_UDPLITE_REASON_ARG           a null borrow or buffer, a borrow
 *                                                               that was never cleared, an IP
 *                                                               version that names no pseudo-header,
 *                                                               or a length that version cannot
 *                                                               carry
 * @var IdemIpUdpLiteReason::IDEMIP_UDPLITE_REASON_SHORT         the IP payload is under the eight
 *                                                               octets RFC 3828 sec 3.1 says "MUST
 *                                                               always be covered by the checksum"
 * @var IdemIpUdpLiteReason::IDEMIP_UDPLITE_REASON_COV_ILLEGAL   RFC 3828 sec 3.1: "A UDP-Lite packet
 *                                                               with a Checksum Coverage value of 1
 *                                                               to 7 MUST be discarded by the
 *                                                               receiver."
 * @var IdemIpUdpLiteReason::IDEMIP_UDPLITE_REASON_COV_PAST_LEN  RFC 3828 sec 3.1: "UDP-Lite packets
 *                                                               with a Checksum Coverage greater
 *                                                               than the IP length MUST also be
 *                                                               discarded."
 * @var IdemIpUdpLiteReason::IDEMIP_UDPLITE_REASON_CKSUM_ZERO    the Checksum field arrived all zero,
 *                                                               which RFC 3828 sec 3.1 forbids a
 *                                                               sender: "the transmitted checksum
 *                                                               MUST NOT be all zeroes"
 * @var IdemIpUdpLiteReason::IDEMIP_UDPLITE_REASON_CKSUM_BAD     the sum over the covered octets and
 *                                                               the sec 3.2 pseudo-header did not
 *                                                               come out zero (RFC 1071 sec 1)
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_UDPLITE_REASON_NONE = 0,
    IDEMIP_UDPLITE_REASON_ARG,
    IDEMIP_UDPLITE_REASON_SHORT,
    IDEMIP_UDPLITE_REASON_COV_ILLEGAL,
    IDEMIP_UDPLITE_REASON_COV_PAST_LEN,
    IDEMIP_UDPLITE_REASON_CKSUM_ZERO,
    IDEMIP_UDPLITE_REASON_CKSUM_BAD,
} IdemIpUdpLiteReason;

/**
 * @brief What a cover and a check take: one received datagram and what the IP module supplies.
 *
 * The Checksum Coverage is not here. RFC 3828 sec 3 puts it in the datagram where RFC 768 puts
 * Length, so a check reads it from @ref UdpLiteCheckArgs::dgram and reports it back.
 *
 * @var UdpLiteCheckArgs::dgram          the UDP-Lite datagram, from the first octet of its header
 * @var UdpLiteCheckArgs::src            the IP header's Source Address: four octets when
 *                                       @ref UdpLiteCheckArgs::ip_version is 4, sixteen when it is
 *                                       6. Unread by cover.
 * @var UdpLiteCheckArgs::dst            its Destination Address, the same widths. Unread by cover.
 * @var UdpLiteCheckArgs::ip_payload_len RFC 3828 sec 3.4: "the length of the IP payload, which is
 *                                       derived from the Length field in the IP header". Sec 3.2:
 *                                       it "includes the UDP-Lite header and all subsequent octets
 *                                       in the IP payload".
 * @var UdpLiteCheckArgs::ip_version     4 for an RFC 791 sec 3.1 header, 6 for an RFC 8200 sec 3 one
 */
typedef struct
{
    const uint8_t *dgram;
    const uint8_t *src;
    const uint8_t *dst;
    uint32_t ip_payload_len;
    uint8_t ip_version;
} UdpLiteCheckArgs;

/**
 * @brief What a build takes: the datagram to finish, and the Coverage to carry.
 *
 * The payload is already in @ref UdpLiteBuildArgs::dgram from octet eight on. A build writes the
 * eight header octets over the front of it and then the Checksum field, and touches nothing else.
 *
 * @var UdpLiteBuildArgs::dgram          the datagram, at least @ref UdpLiteBuildArgs::ip_payload_len
 *                                       octets of it writable
 * @var UdpLiteBuildArgs::src            the IP header's Source Address, four octets over IPv4 and
 *                                       sixteen over IPv6
 * @var UdpLiteBuildArgs::dst            its Destination Address, the same widths
 * @var UdpLiteBuildArgs::ip_payload_len what the sec 3.2 pseudo-header's Length carries, this header
 *                                       and every octet after it
 * @var UdpLiteBuildArgs::src_port       RFC 768 Source Port, which RFC 3828 sec 3.1 keeps
 * @var UdpLiteBuildArgs::dst_port       RFC 768 Destination Port
 * @var UdpLiteBuildArgs::cov            RFC 3828 sec 3.1 Checksum Coverage, "the number of octets,
 *                                       counting from the first octet of the UDP-Lite header, that
 *                                       are covered by the checksum". IDEMIP_UDPLITE_COV_ALL covers
 *                                       the whole datagram.
 * @var UdpLiteBuildArgs::ip_version     4 or 6
 */
typedef struct
{
    uint8_t *dgram;
    const uint8_t *src;
    const uint8_t *dst;
    uint32_t ip_payload_len;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t cov;
    uint8_t ip_version;
} UdpLiteBuildArgs;

/**
 * @brief What a call reports about the datagram.
 *
 * @var UdpLiteResult::payload     the octet after the eight-octet header, in the caller's datagram
 * @var UdpLiteResult::payload_len the IP payload less that header, which RFC 3828 sec 3.4 makes the
 *                                 length delivered: "the length of the UDP-Lite payload delivered to
 *                                 the receiver depends on the length of the IP payload"
 * @var UdpLiteResult::cov_bytes   octets the checksum spans, counting from the first octet of the
 *                                 header. The whole IP payload when Coverage is zero.
 * @var UdpLiteResult::cov         the Checksum Coverage field, as read by a check or as written by a
 *                                 build
 * @var UdpLiteResult::cksum       the Checksum field, as read or as written
 * @var UdpLiteResult::covered     true when @ref UdpLiteResult::cov_bytes reaches the whole IP
 *                                 payload. RFC 3828 sec 3.3 has an application make "no assumptions
 *                                 regarding the correctness of the received data beyond the position
 *                                 indicated by the Checksum Coverage field".
 */
typedef struct
{
    const uint8_t *payload;
    uint32_t payload_len;
    uint32_t cov_bytes;
    uint16_t cov;
    uint16_t cksum;
    idemip_bool covered;
} UdpLiteResult;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns. Two workers on two borrows share no byte
 * of this.
 *
 * @var UdpLiteIo::check_args the received datagram a cover and a check read
 * @var UdpLiteIo::build_args the datagram a build finishes
 * @var UdpLiteIo::status     what the call reports: OK or ERR
 * @var UdpLiteIo::reason     which RFC 3828 sec 3.1 rule a refusal broke
 * @var UdpLiteIo::res        the coverage, the checksum and the payload the call found
 */
typedef struct
{
    UdpLiteCheckArgs check_args;
    UdpLiteBuildArgs build_args;

    IdemIpStatus status;
    IdemIpUdpLiteReason reason;
    UdpLiteResult res;
} UdpLiteIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. This unit holds no table, so the map is the
// operand block and the context behind it.

#define IDEMIP_UDPLITE_OFF_IO 0u                                             ///< the operand and result block
#define IDEMIP_UDPLITE_OFF_CTX (IDEMIP_UDPLITE_OFF_IO + sizeof(UdpLiteIo))   ///< the running context

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_UDPLITE_IO(w) ((UdpLiteIo *)(void *)((w) + IDEMIP_UDPLITE_OFF_IO))

/**
 * @brief The RFC 3828 checksum with its optional partial coverage.
 *
 *   UdpLite.clear(work);
 *   IDEMIP_UDPLITE_IO(work)->check_args.dgram = h;
 *   IDEMIP_UDPLITE_IO(work)->check_args.src = ip + IDEMIP_IP4_OFF_SRC;
 *   IDEMIP_UDPLITE_IO(work)->check_args.dst = ip + IDEMIP_IP4_OFF_DST;
 *   IDEMIP_UDPLITE_IO(work)->check_args.ip_payload_len = 24u;
 *   IDEMIP_UDPLITE_IO(work)->check_args.ip_version = 4u;
 *   UdpLite.check(work);
 *   if (IDEMIP_UDPLITE_IO(work)->status == IDEMIP_OK) { ... res.payload, res.cov_bytes ... }
 *
 * @c work is IDEMIP_UDPLITE_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * of these are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks, and no entry ever reports IDEMIP_BUSY: this unit holds no resource a later
 * call frees, and every refusal is a property of the bytes handed in, so the same call on the same
 * bytes is refused again. A borrow that was never cleared, a null buffer, an IP version that names
 * no pseudo-header, an IP payload under eight octets, a Coverage of 1 to 7, a Coverage past the IP
 * payload, an all-zero Checksum field and a sum that did not come out zero are all ERR.
 *
 * @var UdpLiteNs::clear zero the context and mark the borrow usable
 * @var UdpLiteNs::cover apply the RFC 3828 sec 3.1 Coverage rules alone, reporting the span the
 *                       checksum covers. Reads no address and runs no sum.
 * @var UdpLiteNs::check the sec 3.1 rules and then the checksum, over the covered octets with the
 *                       sec 3.2 pseudo-header
 * @var UdpLiteNs::build write the eight header octets with the requested Coverage and then the
 *                       Checksum field, per sec 3.1: "Prior to computation, the checksum field MUST
 *                       be set to zero. If the computed checksum is 0, it is transmitted as all
 *                       ones."
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const cover)(uint8_t *restrict work);
    void (*const check)(uint8_t *restrict work);
    void (*const build)(uint8_t *restrict work);
} UdpLiteNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const UdpLiteNs UdpLite;

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_UDP

#endif // IDEMIP_UDPLITE_H
