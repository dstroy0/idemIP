// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmpv6.h
 * @brief Internet control messages for IPv6, RFC 4443.
 *
 * The same three leading fields as RFC 792, a renumbered type space, and a checksum that covers the
 * RFC 8200 sec 8.1 pseudo-header as well as the message. Read out of, and built into, the caller's
 * bytes; holds nothing.
 *
 * The message layouts are icmpv6_defines.h, which a .c includes when it genuinely needs the numbers.
 * A caller that wants a field asks for it here.
 *
 * The tables are the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_ICMPV6_H
#define IDEMIP_ICMPV6_H

#include "src/checksum.h"
#include "src/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

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

/** @brief Reading the fields every message, and the echo and error bodies, carry. */
typedef struct
{
    uint8_t (*type)(const uint8_t *m);
    uint8_t (*code)(const uint8_t *m);
    uint16_t (*cksum)(const uint8_t *m);
    idemip_bool (*is_informational)(const uint8_t *m);
    uint16_t (*id)(const uint8_t *m);
    uint16_t (*seq)(const uint8_t *m);
    uint32_t (*mtu)(const uint8_t *m);
    uint32_t (*pointer)(const uint8_t *m);
} Icmp6ReadNs;
IDEMIP_NS_LAYOUT(Icmp6ReadNs, type, code, cksum, is_informational, id, seq, mtu, pointer);

/** @brief Which sub-protocol a type belongs to, and how long its fixed part is. */
typedef struct
{
    idemip_bool (*is_nd)(uint8_t type);
    idemip_bool (*is_mld)(uint8_t type);
    size_t (*nd_hdr_len)(uint8_t type);
} Icmp6ClassNs;
IDEMIP_NS_LAYOUT(Icmp6ClassNs, is_nd, is_mld, nd_hdr_len);

/** @brief The Multicast Listener Discovery body, RFC 2710 sec 3. One shape for all three types. */
typedef struct
{
    uint16_t (*max_resp)(const uint8_t *m);
    const uint8_t *(*group)(const uint8_t *m);
} Icmp6MldNs;
IDEMIP_NS_LAYOUT(Icmp6MldNs, max_resp, group);

/** @brief The Neighbor Discovery bodies, RFC 4861 sec 4.1 through sec 4.5. */
typedef struct
{
    const uint8_t *(*target)(const uint8_t *m);
    const uint8_t *(*rd_dest)(const uint8_t *m);
    uint8_t (*na_flags)(const uint8_t *m);
    uint8_t (*ra_cur_hop)(const uint8_t *m);
    uint8_t (*ra_flags)(const uint8_t *m);
    uint16_t (*ra_lifetime)(const uint8_t *m);
    uint32_t (*ra_reachable)(const uint8_t *m);
    uint32_t (*ra_retrans)(const uint8_t *m);
} Icmp6NdNs;
IDEMIP_NS_LAYOUT(Icmp6NdNs, target, rd_dest, na_flags, ra_cur_hop, ra_flags, ra_lifetime, ra_reachable, ra_retrans);

/** @brief The Neighbor Discovery option format, RFC 4861 sec 4.6. */
typedef struct
{
    uint8_t (*type)(const uint8_t *o);
    size_t (*len)(const uint8_t *o);
    idemip_bool (*ok)(const uint8_t *opts, size_t len);
} Icmp6NdOptNs;
IDEMIP_NS_LAYOUT(Icmp6NdOptNs, type, len, ok);

/**
 * @brief Writing a message into the caller's bytes, and the checksum that seals it.
 *
 * Each build returns how many octets it wrote. The buffer is the caller's and is not held past the
 * call. The checksum field is left zero, so a caller finishes a message with cksum.
 */
typedef struct
{
    void (*hdr)(uint8_t *m, uint8_t type, uint8_t code);
    size_t (*quote_len)(size_t invoking_len);
    size_t (*err)(uint8_t *m, uint8_t type, uint8_t code, uint32_t word, const uint8_t *invoking, size_t invoking_len);
    size_t (*dest_unreach)(uint8_t *m, uint8_t code, const uint8_t *invoking, size_t invoking_len);
    size_t (*packet_too_big)(uint8_t *m, uint32_t mtu, const uint8_t *invoking, size_t invoking_len);
    size_t (*time_exceeded)(uint8_t *m, uint8_t code, const uint8_t *invoking, size_t invoking_len);
    size_t (*param_problem)(uint8_t *m, uint8_t code, uint32_t pointer, const uint8_t *invoking, size_t invoking_len);
    size_t (*echo_reply)(uint8_t *m, uint16_t id, uint16_t seq, const uint8_t *data, size_t data_len);
    uint16_t (*cksum)(const uint8_t *m, size_t len, const uint8_t *src, const uint8_t *dst);
} Icmp6BuildNs;
IDEMIP_NS_LAYOUT(Icmp6BuildNs, hdr, quote_len, err, dest_unreach, packet_too_big, time_exceeded, param_problem,
                 echo_reply, cksum);

/** @name The entries the tables point at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The tables are
 *         still the whole surface: call through them.
 *  @{ */
uint8_t idemip_icmp6_type(const uint8_t *m);
uint8_t idemip_icmp6_code(const uint8_t *m);
uint16_t idemip_icmp6_cksum(const uint8_t *m);
idemip_bool idemip_icmp6_is_informational(const uint8_t *m);
uint16_t idemip_icmp6_id(const uint8_t *m);
uint16_t idemip_icmp6_seq(const uint8_t *m);
uint32_t idemip_icmp6_mtu(const uint8_t *m);
uint32_t idemip_icmp6_pointer(const uint8_t *m);

idemip_bool idemip_icmp6_is_nd(uint8_t type);
idemip_bool idemip_icmp6_is_mld(uint8_t type);
size_t idemip_icmp6_nd_hdr_len(uint8_t type);

uint16_t idemip_icmp6_mld_max_resp(const uint8_t *m);
const uint8_t *idemip_icmp6_mld_group(const uint8_t *m);

const uint8_t *idemip_icmp6_nd_target(const uint8_t *m);
const uint8_t *idemip_icmp6_rd_dest(const uint8_t *m);
uint8_t idemip_icmp6_na_flags(const uint8_t *m);
uint8_t idemip_icmp6_ra_cur_hop(const uint8_t *m);
uint8_t idemip_icmp6_ra_flags(const uint8_t *m);
uint16_t idemip_icmp6_ra_lifetime(const uint8_t *m);
uint32_t idemip_icmp6_ra_reachable(const uint8_t *m);
uint32_t idemip_icmp6_ra_retrans(const uint8_t *m);

uint8_t idemip_icmp6_nd_opt_type(const uint8_t *o);
size_t idemip_icmp6_nd_opt_len(const uint8_t *o);
idemip_bool idemip_icmp6_nd_opts_ok(const uint8_t *opts, size_t len);

void idemip_icmp6_hdr_write(uint8_t *m, uint8_t type, uint8_t code);
size_t idemip_icmp6_err_quote_len(size_t invoking_len);
size_t idemip_icmp6_err_build(uint8_t *m, uint8_t type, uint8_t code, uint32_t word, const uint8_t *invoking,
                              size_t invoking_len);
size_t idemip_icmp6_dest_unreach_build(uint8_t *m, uint8_t code, const uint8_t *invoking, size_t invoking_len);
size_t idemip_icmp6_packet_too_big_build(uint8_t *m, uint32_t mtu, const uint8_t *invoking, size_t invoking_len);
size_t idemip_icmp6_time_exceeded_build(uint8_t *m, uint8_t code, const uint8_t *invoking, size_t invoking_len);
size_t idemip_icmp6_param_problem_build(uint8_t *m, uint8_t code, uint32_t pointer, const uint8_t *invoking,
                                        size_t invoking_len);
size_t idemip_icmp6_echo_reply_build(uint8_t *m, uint16_t id, uint16_t seq, const uint8_t *data, size_t data_len);
uint16_t idemip_icmp6_cksum_compute(const uint8_t *m, size_t len, const uint8_t *src, const uint8_t *dst);
/** @} */

/**
 * @brief The module namespaces.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS Icmp6ReadNs icmp6_read IDEMIP_UNUSED = {
    .type = idemip_icmp6_type,
    .code = idemip_icmp6_code,
    .cksum = idemip_icmp6_cksum,
    .is_informational = idemip_icmp6_is_informational,
    .id = idemip_icmp6_id,
    .seq = idemip_icmp6_seq,
    .mtu = idemip_icmp6_mtu,
    .pointer = idemip_icmp6_pointer,
};

IDEMIP_NS Icmp6ClassNs icmp6_class IDEMIP_UNUSED = {
    .is_nd = idemip_icmp6_is_nd,
    .is_mld = idemip_icmp6_is_mld,
    .nd_hdr_len = idemip_icmp6_nd_hdr_len,
};

IDEMIP_NS Icmp6MldNs icmp6_mld IDEMIP_UNUSED = {
    .max_resp = idemip_icmp6_mld_max_resp,
    .group = idemip_icmp6_mld_group,
};

IDEMIP_NS Icmp6NdNs icmp6_nd IDEMIP_UNUSED = {
    .target = idemip_icmp6_nd_target,
    .rd_dest = idemip_icmp6_rd_dest,
    .na_flags = idemip_icmp6_na_flags,
    .ra_cur_hop = idemip_icmp6_ra_cur_hop,
    .ra_flags = idemip_icmp6_ra_flags,
    .ra_lifetime = idemip_icmp6_ra_lifetime,
    .ra_reachable = idemip_icmp6_ra_reachable,
    .ra_retrans = idemip_icmp6_ra_retrans,
};

IDEMIP_NS Icmp6NdOptNs icmp6_nd_opt IDEMIP_UNUSED = {
    .type = idemip_icmp6_nd_opt_type,
    .len = idemip_icmp6_nd_opt_len,
    .ok = idemip_icmp6_nd_opts_ok,
};

IDEMIP_NS Icmp6BuildNs icmp6_build IDEMIP_UNUSED = {
    .hdr = idemip_icmp6_hdr_write,
    .quote_len = idemip_icmp6_err_quote_len,
    .err = idemip_icmp6_err_build,
    .dest_unreach = idemip_icmp6_dest_unreach_build,
    .packet_too_big = idemip_icmp6_packet_too_big_build,
    .time_exceeded = idemip_icmp6_time_exceeded_build,
    .param_problem = idemip_icmp6_param_problem_build,
    .echo_reply = idemip_icmp6_echo_reply_build,
    .cksum = idemip_icmp6_cksum_compute,
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_ICMPV6_H
