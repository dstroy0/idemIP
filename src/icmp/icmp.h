// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmp.h
 * @brief Internet control messages, RFC 792.
 *
 * Every message begins Type, Code, Checksum; what follows depends on the type. The layout is
 * icmp_defines.h, which a .c includes when it genuinely needs the numbers. A caller that wants a
 * field asks for it here.
 *
 * The tables are the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_ICMP_H
#define IDEMIP_ICMP_H

#include "src/checksum.h"
#include "src/ip/ipv4.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/** @brief Message types RFC 792 assigns, as its "Summary of Message Types" lists them. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ICMP_ECHO_REPLY = 0, ///< "0 for echo reply message"
    IDEMIP_ICMP_DEST_UNREACHABLE = 3,
    IDEMIP_ICMP_SOURCE_QUENCH = 4,
    IDEMIP_ICMP_REDIRECT = 5,
    IDEMIP_ICMP_ECHO = 8, ///< "8 for echo message"
    IDEMIP_ICMP_TIME_EXCEEDED = 11,
    IDEMIP_ICMP_PARAMETER_PROBLEM = 12,
    IDEMIP_ICMP_TIMESTAMP = 13,
    IDEMIP_ICMP_TIMESTAMP_REPLY = 14,
    IDEMIP_ICMP_INFO_REQUEST = 15,
    IDEMIP_ICMP_INFO_REPLY = 16,
} IdemIpIcmpType;

/** @brief Reading a received message, and the checksum RFC 792 covers it with. */
typedef struct
{
    uint8_t (*type)(const uint8_t *m);
    uint8_t (*code)(const uint8_t *m);
    uint16_t (*cksum)(const uint8_t *m);
    uint16_t (*id)(const uint8_t *m);
    uint16_t (*seq)(const uint8_t *m);
    uint8_t (*pointer)(const uint8_t *m);
    uint32_t (*gateway)(const uint8_t *m);
    uint32_t (*orig_ts)(const uint8_t *m);
    uint32_t (*recv_ts)(const uint8_t *m);
    uint32_t (*xmit_ts)(const uint8_t *m);
    const uint8_t *(*quote)(const uint8_t *m);
    idemip_bool (*is_error)(const uint8_t *m);
    uint16_t (*cksum_compute)(const uint8_t *m, size_t len);
} IcmpReadNs;
IDEMIP_NS_LAYOUT(IcmpReadNs, type, code, cksum, id, seq, pointer, gateway, orig_ts, recv_ts, xmit_ts, quote, is_error,
                 cksum_compute);

/**
 * @brief Writing a message into the caller's bytes, then the checksum over it.
 *
 * Each entry takes the message the caller placed and the total length it occupies, writes the head,
 * zeroes the checksum field, sums the whole message and writes the result back. Whatever follows
 * the head, echo data or a quoted datagram, is already in place and is covered by that sum.
 */
typedef struct
{
    void (*echo)(uint8_t *m, uint8_t type, uint16_t id, uint16_t seq, size_t len);
    void (*echo_reply)(uint8_t *m, size_t len);
    void (*error)(uint8_t *m, uint8_t type, uint8_t code, uint32_t word, size_t len);
    void (*dest_unreachable)(uint8_t *m, uint8_t code, size_t len);
    void (*time_exceeded)(uint8_t *m, uint8_t code, size_t len);
    void (*parameter_problem)(uint8_t *m, uint8_t code, uint8_t pointer, size_t len);
    void (*source_quench)(uint8_t *m, size_t len);
    size_t (*err_len)(const uint8_t *ip);
} IcmpBuildNs;
IDEMIP_NS_LAYOUT(IcmpBuildNs, echo, echo_reply, error, dest_unreachable, time_exceeded, parameter_problem,
                 source_quench, err_len);

/** @name The entries the tables point at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The tables are
 *         still the whole surface: call through them.
 *  @{ */
uint8_t idemip_icmp_type(const uint8_t *m);
uint8_t idemip_icmp_code(const uint8_t *m);
uint16_t idemip_icmp_cksum(const uint8_t *m);
uint16_t idemip_icmp_id(const uint8_t *m);
uint16_t idemip_icmp_seq(const uint8_t *m);
uint8_t idemip_icmp_pointer(const uint8_t *m);
uint32_t idemip_icmp_gateway(const uint8_t *m);
uint32_t idemip_icmp_orig_ts(const uint8_t *m);
uint32_t idemip_icmp_recv_ts(const uint8_t *m);
uint32_t idemip_icmp_xmit_ts(const uint8_t *m);
const uint8_t *idemip_icmp_quote(const uint8_t *m);
idemip_bool idemip_icmp_is_error(const uint8_t *m);
uint16_t idemip_icmp_cksum_compute(const uint8_t *m, size_t len);

void idemip_icmp_build_echo(uint8_t *m, uint8_t type, uint16_t id, uint16_t seq, size_t len);
void idemip_icmp_echo_reply(uint8_t *m, size_t len);
void idemip_icmp_build_error(uint8_t *m, uint8_t type, uint8_t code, uint32_t word, size_t len);
void idemip_icmp_build_dest_unreachable(uint8_t *m, uint8_t code, size_t len);
void idemip_icmp_build_time_exceeded(uint8_t *m, uint8_t code, size_t len);
void idemip_icmp_build_parameter_problem(uint8_t *m, uint8_t code, uint8_t pointer, size_t len);
void idemip_icmp_build_source_quench(uint8_t *m, size_t len);
size_t idemip_icmp_err_len(const uint8_t *ip);
/** @} */

/**
 * @brief The module namespaces.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS IcmpReadNs icmp_read IDEMIP_UNUSED = {
    .type = idemip_icmp_type,
    .code = idemip_icmp_code,
    .cksum = idemip_icmp_cksum,
    .id = idemip_icmp_id,
    .seq = idemip_icmp_seq,
    .pointer = idemip_icmp_pointer,
    .gateway = idemip_icmp_gateway,
    .orig_ts = idemip_icmp_orig_ts,
    .recv_ts = idemip_icmp_recv_ts,
    .xmit_ts = idemip_icmp_xmit_ts,
    .quote = idemip_icmp_quote,
    .is_error = idemip_icmp_is_error,
    .cksum_compute = idemip_icmp_cksum_compute,
};

IDEMIP_NS IcmpBuildNs icmp_build IDEMIP_UNUSED = {
    .echo = idemip_icmp_build_echo,
    .echo_reply = idemip_icmp_echo_reply,
    .error = idemip_icmp_build_error,
    .dest_unreachable = idemip_icmp_build_dest_unreachable,
    .time_exceeded = idemip_icmp_build_time_exceeded,
    .parameter_problem = idemip_icmp_build_parameter_problem,
    .source_quench = idemip_icmp_build_source_quench,
    .err_len = idemip_icmp_err_len,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_ICMP_H
