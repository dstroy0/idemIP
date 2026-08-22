// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmpv6.c
 * @brief Internet control messages for IPv6, RFC 4443, read out of and built into the caller's bytes.
 *
 * Every entry below takes one parameter, a pointer to Icmp6Ctx. A message access is the octets and,
 * when it writes, the fields and the invoking packet going with them, so those are one context.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/icmp/icmpv6.h"
#include "src/icmp/icmpv6_defines.h" // the message layouts, which this file is the first user of
#include "src/common_defines.h"
#include "src/ip/ipv6_defines.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

// The maps close on themselves. Here rather than in icmpv6_defines.h because several are stated
// against IdemIpIcmp6Type's constants and several against the defines, and this is the one
// translation unit that sees both.
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


/** @brief One message access. */
typedef struct
{
    const uint8_t *m;        /**< The message, option region or address a read walks. */
    uint8_t *w;              /**< The message a build writes into. */
    const uint8_t *invoking; /**< The packet that caused an error, quoted into the message. */
    const uint8_t *data;     /**< Echo data carried through into a reply. */
    const uint8_t *src;      /**< Source address, for the sec 8.1 pseudo-header. */
    const uint8_t *dst;      /**< Destination address, the same. */
    size_t len;              /**< Octets the sum spans, or the option region's length. */
    size_t invoking_len;     /**< Octets of the invoking packet offered for the quote. */
    size_t data_len;         /**< Octets of echo data. */
    uint32_t word;           /**< The 32 bits at offset 4: Unused, MTU or Pointer. */
    uint16_t id;             /**< Identifier a build writes. */
    uint16_t seq;            /**< Sequence Number a build writes. */
    uint8_t type;            /**< Type a build writes, or the one a class test asks about. */
    uint8_t code;            /**< Code a build writes. */
} Icmp6Ctx;

// --- reading a message -----------------------------------------------------

/** @brief Type. */
IDEMIP_INLINE uint8_t icmp6_type(const Icmp6Ctx *c)
{
    return c->m[IDEMIP_ICMP6_OFF_TYPE];
}

/** @brief Code; its meaning depends on the type. */
IDEMIP_INLINE uint8_t icmp6_code(const Icmp6Ctx *c)
{
    return c->m[IDEMIP_ICMP6_OFF_CODE];
}

/** @brief Checksum as carried. */
IDEMIP_INLINE uint16_t icmp6_cksum(const Icmp6Ctx *c)
{
    return idemip_rd16(c->m + IDEMIP_ICMP6_OFF_CKSUM);
}

/** @brief True for types 128 through 255, which are informational rather than errors. */
IDEMIP_INLINE idemip_bool icmp6_is_informational(const Icmp6Ctx *c)
{
    return (c->m[IDEMIP_ICMP6_OFF_TYPE] & IDEMIP_ICMP6_INFORMATIONAL) != 0u;
}

/** @brief Identifier (echo request and echo reply). */
IDEMIP_INLINE uint16_t icmp6_id(const Icmp6Ctx *c)
{
    return idemip_rd16(c->m + IDEMIP_ICMP6_OFF_ID);
}

/** @brief Sequence Number (echo request and echo reply). */
IDEMIP_INLINE uint16_t icmp6_seq(const Icmp6Ctx *c)
{
    return idemip_rd16(c->m + IDEMIP_ICMP6_OFF_SEQ);
}

/** @brief MTU of the next-hop link (Packet Too Big). */
IDEMIP_INLINE uint32_t icmp6_mtu(const Icmp6Ctx *c)
{
    return idemip_rd32(c->m + IDEMIP_ICMP6_OFF_MTU);
}

/** @brief Octet offset within the invoking packet where the fault was found (Parameter Problem). */
IDEMIP_INLINE uint32_t icmp6_pointer(const Icmp6Ctx *c)
{
    return idemip_rd32(c->m + IDEMIP_ICMP6_OFF_POINTER);
}

// --- which sub-protocol a type belongs to ----------------------------------

/** @brief True for the five types RFC 4861 sec 4 defines. */
IDEMIP_INLINE idemip_bool icmp6_is_nd(const Icmp6Ctx *c)
{
    return (c->type >= (uint8_t)IDEMIP_ICMP6_ROUTER_SOLICIT && c->type <= (uint8_t)IDEMIP_ICMP6_REDIRECT)
               ? IDEMIP_TRUE
               : IDEMIP_FALSE;
}

/** @brief True for the three types RFC 2710 sec 3.1 defines. */
IDEMIP_INLINE idemip_bool icmp6_is_mld(const Icmp6Ctx *c)
{
    return (c->type >= (uint8_t)IDEMIP_ICMP6_MLD_QUERY && c->type <= (uint8_t)IDEMIP_ICMP6_MLD_DONE) ? IDEMIP_TRUE
                                                                                                     : IDEMIP_FALSE;
}

/**
 * @brief The octets a message of this type carries before its options, and zero for a type that has
 * none.
 *
 * RFC 4861 sec 4.1 through sec 4.5 fix one length per type, which is also the shortest such a
 * message can be: sec 6.1.1 refuses a Router Solicitation under "8 or more octets" and sec 6.1.2 a
 * Router Advertisement under "16 or more octets".
 */
IDEMIP_INLINE size_t icmp6_nd_hdr_len(const Icmp6Ctx *c)
{
    switch (c->type)
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

// --- the MLD body (RFC 2710 sec 3) -----------------------------------------

/** @brief Maximum Response Delay, milliseconds (RFC 2710 sec 3.4). */
IDEMIP_INLINE uint16_t icmp6_mld_max_resp(const Icmp6Ctx *c)
{
    return idemip_rd16(c->m + IDEMIP_ICMP6_OFF_MLD_MAX_RESP);
}

/** @brief The Multicast Address, where it lies (RFC 2710 sec 3.6). */
IDEMIP_INLINE const uint8_t *icmp6_mld_group(const Icmp6Ctx *c)
{
    return c->m + IDEMIP_ICMP6_OFF_MLD_GROUP;
}

// --- the Neighbor Discovery bodies (RFC 4861 sec 4.1 through sec 4.5) ------

/**
 * @brief The Target Address of a Neighbor Solicitation, Neighbor Advertisement or Redirect, where it
 * lies.
 *
 * RFC 4861 sec 4.3, sec 4.4 and sec 4.5 all put it at the same offset.
 */
IDEMIP_INLINE const uint8_t *icmp6_nd_target(const Icmp6Ctx *c)
{
    return c->m + IDEMIP_ICMP6_OFF_NS_TARGET;
}

/** @brief The Destination Address a Redirect names (RFC 4861 sec 4.5). */
IDEMIP_INLINE const uint8_t *icmp6_rd_dest(const Icmp6Ctx *c)
{
    return c->m + IDEMIP_ICMP6_OFF_RD_DEST;
}

/** @brief The R, S and O bits of a Neighbor Advertisement (RFC 4861 sec 4.4). */
IDEMIP_INLINE uint8_t icmp6_na_flags(const Icmp6Ctx *c)
{
    return c->m[IDEMIP_ICMP6_OFF_NA_FLAGS];
}

/** @brief Cur Hop Limit (RFC 4861 sec 4.2). */
IDEMIP_INLINE uint8_t icmp6_ra_cur_hop(const Icmp6Ctx *c)
{
    return c->m[IDEMIP_ICMP6_OFF_RA_CUR_HOP];
}

/** @brief The M and O bits of a Router Advertisement (RFC 4861 sec 4.2). */
IDEMIP_INLINE uint8_t icmp6_ra_flags(const Icmp6Ctx *c)
{
    return c->m[IDEMIP_ICMP6_OFF_RA_FLAGS];
}

/** @brief Router Lifetime, seconds (RFC 4861 sec 4.2). */
IDEMIP_INLINE uint16_t icmp6_ra_lifetime(const Icmp6Ctx *c)
{
    return idemip_rd16(c->m + IDEMIP_ICMP6_OFF_RA_LIFETIME);
}

/** @brief Reachable Time, milliseconds (RFC 4861 sec 4.2). */
IDEMIP_INLINE uint32_t icmp6_ra_reachable(const Icmp6Ctx *c)
{
    return idemip_rd32(c->m + IDEMIP_ICMP6_OFF_RA_REACHABLE);
}

/** @brief Retrans Timer, milliseconds (RFC 4861 sec 4.2). */
IDEMIP_INLINE uint32_t icmp6_ra_retrans(const Icmp6Ctx *c)
{
    return idemip_rd32(c->m + IDEMIP_ICMP6_OFF_RA_RETRANS);
}

// --- the Neighbor Discovery option format (RFC 4861 sec 4.6) ---------------

/** @brief An option's Type (RFC 4861 sec 4.6). */
IDEMIP_INLINE uint8_t icmp6_nd_opt_type(const Icmp6Ctx *c)
{
    return c->m[IDEMIP_ICMP6_ND_OPT_OFF_TYPE];
}

/**
 * @brief An option's length in octets, its Length field shifted up three.
 *
 * RFC 4861 sec 4.6: "The length of the option (including the type and length fields) in units of 8
 * octets." Zero for a Length of zero, which sec 4.6 makes the whole packet's fault.
 */
IDEMIP_INLINE size_t icmp6_nd_opt_len(const Icmp6Ctx *c)
{
    return (size_t)c->m[IDEMIP_ICMP6_ND_OPT_OFF_LEN] << IDEMIP_ICMP6_ND_OPT_UNIT_SHIFT;
}

/**
 * @brief Every option in the region closes inside it and none has Length zero.
 *
 * RFC 4861 sec 4.6: "Nodes MUST silently discard an ND packet that contains an option with length
 * zero." An option whose Length runs past the message end is the same refusal, since the octets it
 * names are not there to read.
 */
IDEMIP_INLINE idemip_bool icmp6_nd_opts_ok(const Icmp6Ctx *c)
{
    const uint8_t *opts = c->m;
    const size_t len = c->len;
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

// --- building a message (RFC 4443 sec 3 and sec 4) -------------------------

/** @brief Type, Code, and a zero Checksum: the three fields sec 2.1 puts at the head of every message. */
IDEMIP_INLINE void icmp6_hdr_write(const Icmp6Ctx *c)
{
    c->w[IDEMIP_ICMP6_OFF_TYPE] = c->type;
    c->w[IDEMIP_ICMP6_OFF_CODE] = c->code;
    idemip_wr16(c->w + IDEMIP_ICMP6_OFF_CKSUM, 0u);
}

/**
 * @brief Octets of the invoking packet that an error message carries.
 *
 * RFC 4443 sec 2.4 (c): "Every ICMPv6 error message (type < 128) MUST include as much of the IPv6
 * offending (invoking) packet (the packet that caused the error) as possible without making the
 * error message packet exceed the minimum IPv6 MTU". Anything longer is truncated to what is left
 * of the 1280 once the IPv6 header and these eight octets are counted.
 */
IDEMIP_INLINE size_t icmp6_err_quote_len(const Icmp6Ctx *c)
{
    return (c->invoking_len > (size_t)IDEMIP_ICMP6_ERR_QUOTE_MAX) ? (size_t)IDEMIP_ICMP6_ERR_QUOTE_MAX
                                                                  : c->invoking_len;
}

/**
 * @brief An error message: the three head fields, the type's 32-bit field, then the clamped quote.
 * @param c The build. @c word is what sec 3 puts at offset 4 for this type: Unused for Destination
 *          Unreachable and Time Exceeded, MTU for Packet Too Big, Pointer for Parameter Problem.
 * @return Bytes written, IDEMIP_ICMP6_ERR_HDR_LEN plus the quote.
 *
 * The invoking packet points at the IPv6 header of the packet that caused the error, and must not
 * overlap the message being built.
 */
IDEMIP_INLINE size_t icmp6_err_build(const Icmp6Ctx *c)
{
    size_t quote = idemip_icmp6_err_quote_len(c->invoking_len);
    idemip_icmp6_hdr_write(c->w, c->type, c->code);
    idemip_wr32(c->w + IDEMIP_ICMP6_OFF_BODY, c->word);
    if (quote != 0u)
    {
        memcpy(c->w + IDEMIP_ICMP6_ERR_HDR_LEN, c->invoking, quote);
    }
    return (size_t)IDEMIP_ICMP6_ERR_HDR_LEN + quote;
}

/** @brief Destination Unreachable, sec 3.1: Type 1, one of Codes 0 through 6, Unused zero. */
IDEMIP_INLINE size_t icmp6_dest_unreach(const Icmp6Ctx *c)
{
    return idemip_icmp6_err_build(c->w, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, c->code, 0u, c->invoking,
                                  c->invoking_len);
}

/**
 * @brief Packet Too Big, sec 3.2: Type 2, Code 0, and the MTU, "The Maximum Transmission Unit of the
 * next-hop link".
 */
IDEMIP_INLINE size_t icmp6_packet_too_big(const Icmp6Ctx *c)
{
    return idemip_icmp6_err_build(c->w, (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG, IDEMIP_ICMP6_CODE_PTB, c->word,
                                  c->invoking, c->invoking_len);
}

/** @brief Time Exceeded, sec 3.3: Type 3, Code 0 or 1, Unused zero. */
IDEMIP_INLINE size_t icmp6_time_exceeded(const Icmp6Ctx *c)
{
    return idemip_icmp6_err_build(c->w, (uint8_t)IDEMIP_ICMP6_TIME_EXCEEDED, c->code, 0u, c->invoking,
                                  c->invoking_len);
}

/**
 * @brief Parameter Problem, sec 3.4: Type 4, one of Codes 0 through 2, and the pointer, which
 * "Identifies the octet offset within the invoking packet where the error was detected".
 */
IDEMIP_INLINE size_t icmp6_param_problem(const Icmp6Ctx *c)
{
    return idemip_icmp6_err_build(c->w, (uint8_t)IDEMIP_ICMP6_PARAMETER_PROBLEM, c->code, c->word, c->invoking,
                                  c->invoking_len);
}

/**
 * @brief Echo Reply, sec 4.2: Type 129, Code 0, the request's Identifier and Sequence Number, and
 * its data.
 * @return Bytes written, IDEMIP_ICMP6_ECHO_HDR_LEN plus the data length.
 *
 * RFC 4443 sec 4.2: the Identifier and Sequence Number are "from the invoking Echo Request message",
 * and "The data received in the ICMPv6 Echo Request message MUST be returned entirely and unmodified
 * in the ICMPv6 Echo Reply message". The data is IDEMIP_ICMP6_ECHO_HDR_LEN into the request and must
 * not overlap the message being built. Sec 4.1 allows "Zero or more octets", so it may be empty.
 */
IDEMIP_INLINE size_t icmp6_echo_reply(const Icmp6Ctx *c)
{
    idemip_icmp6_hdr_write(c->w, (uint8_t)IDEMIP_ICMP6_ECHO_REPLY, IDEMIP_ICMP6_CODE_ECHO);
    idemip_wr16(c->w + IDEMIP_ICMP6_OFF_ID, c->id);
    idemip_wr16(c->w + IDEMIP_ICMP6_OFF_SEQ, c->seq);
    if (c->data_len != 0u)
    {
        memcpy(c->w + IDEMIP_ICMP6_ECHO_HDR_LEN, c->data, c->data_len);
    }
    return (size_t)IDEMIP_ICMP6_ECHO_HDR_LEN + c->data_len;
}

/**
 * @brief The checksum to write over the message, between the two addresses.
 *
 * RFC 4443 sec 2.3: "the 16-bit one's complement of the one's complement sum of the entire ICMPv6
 * message, starting with the ICMPv6 message type field, and prepended with a 'pseudo-header' of
 * IPv6 header fields... The Next Header value used in the pseudo-header is 58."
 *
 * The caller zeroes the checksum field first. Unlike RFC 792, the addresses are covered, because
 * IPv6 carries no header checksum of its own.
 */
IDEMIP_INLINE uint16_t icmp6_cksum_compute(const Icmp6Ctx *c)
{
    uint32_t sum = idemip_ip6_pseudo_accum(0u, c->src, c->dst, (uint32_t)c->len, IDEMIP_IP6_NH_ICMPV6);
    return idemip_cksum_final(idemip_cksum_accum(sum, c->m, c->len));
}

/* The namespaces are tables of function pointers with the caller's argument lists in their types,
   so these are what they point at. Each builds the context and hands it to the body above. */

uint8_t idemip_icmp6_type(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_type, Icmp6Ctx, .m = m);
}

uint8_t idemip_icmp6_code(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_code, Icmp6Ctx, .m = m);
}

uint16_t idemip_icmp6_cksum(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_cksum, Icmp6Ctx, .m = m);
}

idemip_bool idemip_icmp6_is_informational(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_is_informational, Icmp6Ctx, .m = m);
}

uint16_t idemip_icmp6_id(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_id, Icmp6Ctx, .m = m);
}

uint16_t idemip_icmp6_seq(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_seq, Icmp6Ctx, .m = m);
}

uint32_t idemip_icmp6_mtu(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_mtu, Icmp6Ctx, .m = m);
}

uint32_t idemip_icmp6_pointer(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_pointer, Icmp6Ctx, .m = m);
}

idemip_bool idemip_icmp6_is_nd(uint8_t type)
{
    return IDEMIP_CALL(icmp6_is_nd, Icmp6Ctx, .type = type);
}

idemip_bool idemip_icmp6_is_mld(uint8_t type)
{
    return IDEMIP_CALL(icmp6_is_mld, Icmp6Ctx, .type = type);
}

size_t idemip_icmp6_nd_hdr_len(uint8_t type)
{
    return IDEMIP_CALL(icmp6_nd_hdr_len, Icmp6Ctx, .type = type);
}

uint16_t idemip_icmp6_mld_max_resp(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_mld_max_resp, Icmp6Ctx, .m = m);
}

const uint8_t *idemip_icmp6_mld_group(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_mld_group, Icmp6Ctx, .m = m);
}

const uint8_t *idemip_icmp6_nd_target(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_nd_target, Icmp6Ctx, .m = m);
}

const uint8_t *idemip_icmp6_rd_dest(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_rd_dest, Icmp6Ctx, .m = m);
}

uint8_t idemip_icmp6_na_flags(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_na_flags, Icmp6Ctx, .m = m);
}

uint8_t idemip_icmp6_ra_cur_hop(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_ra_cur_hop, Icmp6Ctx, .m = m);
}

uint8_t idemip_icmp6_ra_flags(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_ra_flags, Icmp6Ctx, .m = m);
}

uint16_t idemip_icmp6_ra_lifetime(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_ra_lifetime, Icmp6Ctx, .m = m);
}

uint32_t idemip_icmp6_ra_reachable(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_ra_reachable, Icmp6Ctx, .m = m);
}

uint32_t idemip_icmp6_ra_retrans(const uint8_t *m)
{
    return IDEMIP_CALL(icmp6_ra_retrans, Icmp6Ctx, .m = m);
}

uint8_t idemip_icmp6_nd_opt_type(const uint8_t *o)
{
    return IDEMIP_CALL(icmp6_nd_opt_type, Icmp6Ctx, .m = o);
}

size_t idemip_icmp6_nd_opt_len(const uint8_t *o)
{
    return IDEMIP_CALL(icmp6_nd_opt_len, Icmp6Ctx, .m = o);
}

idemip_bool idemip_icmp6_nd_opts_ok(const uint8_t *opts, size_t len)
{
    return IDEMIP_CALL(icmp6_nd_opts_ok, Icmp6Ctx, .m = opts, .len = len);
}

void idemip_icmp6_hdr_write(uint8_t *m, uint8_t type, uint8_t code)
{
    IDEMIP_CALL(icmp6_hdr_write, Icmp6Ctx, .w = m, .type = type, .code = code);
}

size_t idemip_icmp6_err_quote_len(size_t invoking_len)
{
    return IDEMIP_CALL(icmp6_err_quote_len, Icmp6Ctx, .invoking_len = invoking_len);
}

size_t idemip_icmp6_err_build(uint8_t *m, uint8_t type, uint8_t code, uint32_t word, const uint8_t *invoking,
                              size_t invoking_len)
{
    return IDEMIP_CALL(icmp6_err_build, Icmp6Ctx, .w = m, .type = type, .code = code, .word = word,
                       .invoking = invoking, .invoking_len = invoking_len);
}

size_t idemip_icmp6_dest_unreach_build(uint8_t *m, uint8_t code, const uint8_t *invoking, size_t invoking_len)
{
    return IDEMIP_CALL(icmp6_dest_unreach, Icmp6Ctx, .w = m, .code = code, .invoking = invoking,
                       .invoking_len = invoking_len);
}

size_t idemip_icmp6_packet_too_big_build(uint8_t *m, uint32_t mtu, const uint8_t *invoking, size_t invoking_len)
{
    return IDEMIP_CALL(icmp6_packet_too_big, Icmp6Ctx, .w = m, .word = mtu, .invoking = invoking,
                       .invoking_len = invoking_len);
}

size_t idemip_icmp6_time_exceeded_build(uint8_t *m, uint8_t code, const uint8_t *invoking, size_t invoking_len)
{
    return IDEMIP_CALL(icmp6_time_exceeded, Icmp6Ctx, .w = m, .code = code, .invoking = invoking,
                       .invoking_len = invoking_len);
}

size_t idemip_icmp6_param_problem_build(uint8_t *m, uint8_t code, uint32_t pointer, const uint8_t *invoking,
                                        size_t invoking_len)
{
    return IDEMIP_CALL(icmp6_param_problem, Icmp6Ctx, .w = m, .code = code, .word = pointer, .invoking = invoking,
                       .invoking_len = invoking_len);
}

size_t idemip_icmp6_echo_reply_build(uint8_t *m, uint16_t id, uint16_t seq, const uint8_t *data, size_t data_len)
{
    return IDEMIP_CALL(icmp6_echo_reply, Icmp6Ctx, .w = m, .id = id, .seq = seq, .data = data, .data_len = data_len);
}

uint16_t idemip_icmp6_cksum_compute(const uint8_t *m, size_t len, const uint8_t *src, const uint8_t *dst)
{
    return IDEMIP_CALL(icmp6_cksum_compute, Icmp6Ctx, .m = m, .len = len, .src = src, .dst = dst);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6
