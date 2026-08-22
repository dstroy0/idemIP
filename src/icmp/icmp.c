// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmp.c
 * @brief Internet control messages, RFC 792, read out of the caller's bytes and written into them.
 *
 * Every entry below takes one parameter, a pointer to IcmpCtx. A message access is the octets and,
 * when it writes, the fields going into them, so those are one context.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/icmp/icmp.h"
#include "src/icmp/icmp_defines.h" // the RFC 792 message layout, which this file is the first user of
#include "src/ip/ipv4_defines.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/** @brief One message access. */
typedef struct
{
    const uint8_t *m; /**< The message a read takes its fields out of, or an internet header. */
    uint8_t *w;       /**< The message a build writes into. */
    size_t len;       /**< Octets the whole message occupies, which the checksum covers. */
    uint32_t word;    /**< The 32 bits at IDEMIP_ICMP_OFF_UNUSED an error carries. */
    uint16_t id;      /**< Identifier a build writes. */
    uint16_t seq;     /**< Sequence Number a build writes. */
    uint8_t type;     /**< Type a build writes. */
    uint8_t code;     /**< Code a build writes. */
    uint8_t pointer;  /**< The faulting octet a parameter problem reports. */
} IcmpCtx;

// --- reading a received message --------------------------------------------

/** @brief Type. */
IDEMIP_INLINE uint8_t icmp_type(const IcmpCtx *c)
{
    return c->m[IDEMIP_ICMP_OFF_TYPE];
}

/** @brief Code; its meaning depends on the type. */
IDEMIP_INLINE uint8_t icmp_code(const IcmpCtx *c)
{
    return c->m[IDEMIP_ICMP_OFF_CODE];
}

/** @brief Checksum as carried. */
IDEMIP_INLINE uint16_t icmp_cksum(const IcmpCtx *c)
{
    return idemip_rd16(c->m + IDEMIP_ICMP_OFF_CKSUM);
}

/** @brief Identifier (echo and echo reply). */
IDEMIP_INLINE uint16_t icmp_id(const IcmpCtx *c)
{
    return idemip_rd16(c->m + IDEMIP_ICMP_OFF_ID);
}

/** @brief Sequence Number (echo and echo reply). */
IDEMIP_INLINE uint16_t icmp_seq(const IcmpCtx *c)
{
    return idemip_rd16(c->m + IDEMIP_ICMP_OFF_SEQ);
}

/** @brief Pointer: the octet of the original header the fault was found at (parameter problem). */
IDEMIP_INLINE uint8_t icmp_pointer(const IcmpCtx *c)
{
    return c->m[IDEMIP_ICMP_OFF_POINTER];
}

/** @brief Gateway Internet Address (redirect). */
IDEMIP_INLINE uint32_t icmp_gateway(const IcmpCtx *c)
{
    return idemip_rd32(c->m + IDEMIP_ICMP_OFF_GATEWAY);
}

/** @brief Originate Timestamp (timestamp and timestamp reply). */
IDEMIP_INLINE uint32_t icmp_orig_ts(const IcmpCtx *c)
{
    return idemip_rd32(c->m + IDEMIP_ICMP_OFF_ORIG_TS);
}

/** @brief Receive Timestamp (timestamp reply). */
IDEMIP_INLINE uint32_t icmp_recv_ts(const IcmpCtx *c)
{
    return idemip_rd32(c->m + IDEMIP_ICMP_OFF_RECV_TS);
}

/** @brief Transmit Timestamp (timestamp reply). */
IDEMIP_INLINE uint32_t icmp_xmit_ts(const IcmpCtx *c)
{
    return idemip_rd32(c->m + IDEMIP_ICMP_OFF_XMIT_TS);
}

/** @brief The quoted datagram an error message carries: its internet header, then its data. */
IDEMIP_INLINE const uint8_t *icmp_quote(const IcmpCtx *c)
{
    return c->m + IDEMIP_ICMP_OFF_QUOTE;
}

/**
 * @brief True for the five types RFC 1122 sec 3.2.2 groups as errors.
 *
 * "ICMP error messages: Destination Unreachable, Redirect, Source Quench, Time Exceeded, Parameter
 * Problem." The remaining types are queries. Unlike RFC 4443 no bit sorts them, so the type is
 * matched against the list.
 */
IDEMIP_INLINE idemip_bool icmp_is_error(const IcmpCtx *c)
{
    switch (c->m[IDEMIP_ICMP_OFF_TYPE])
    {
    case IDEMIP_ICMP_DEST_UNREACHABLE:
    case IDEMIP_ICMP_SOURCE_QUENCH:
    case IDEMIP_ICMP_REDIRECT:
    case IDEMIP_ICMP_TIME_EXCEEDED:
    case IDEMIP_ICMP_PARAMETER_PROBLEM:
        return IDEMIP_TRUE;
    default:
        return IDEMIP_FALSE;
    }
}

/**
 * @brief The checksum to write over the message.
 *
 * RFC 792: "The checksum is the 16-bit ones's complement of the one's complement sum of the ICMP
 * message starting with the ICMP Type. For computing the checksum, the checksum field should be
 * zero. If the total length is odd, the received data is padded with one octet of zeros for
 * computing the checksum."
 *
 * No pseudo-header: unlike UDP and TCP, this covers the message alone.
 */
IDEMIP_INLINE uint16_t icmp_cksum_compute(const IcmpCtx *c)
{
    return idemip_cksum(c->m, c->len);
}

// --- writing a message -----------------------------------------------------

/**
 * @brief Write an echo or echo reply head, then its checksum over the whole message.
 *
 * RFC 792, Echo or Echo Reply: Type, Code 0, Checksum, Identifier, Sequence Number, then Data. The
 * data sits at IDEMIP_ICMP_ECHO_HDR_LEN and the length counts it.
 */
IDEMIP_INLINE void icmp_build_echo(const IcmpCtx *c)
{
    c->w[IDEMIP_ICMP_OFF_TYPE] = c->type;
    c->w[IDEMIP_ICMP_OFF_CODE] = IDEMIP_ICMP_CODE_ECHO;
    idemip_wr16(c->w + IDEMIP_ICMP_OFF_CKSUM, 0u);
    idemip_wr16(c->w + IDEMIP_ICMP_OFF_ID, c->id);
    idemip_wr16(c->w + IDEMIP_ICMP_OFF_SEQ, c->seq);
    idemip_wr16(c->w + IDEMIP_ICMP_OFF_CKSUM, idemip_icmp_cksum_compute(c->w, c->len));
}

/**
 * @brief Turn the echo message into its reply, in place.
 *
 * RFC 792, Echo or Echo Reply: "To form an echo reply message, the source and destination addresses
 * are simply reversed, the type code changed to 0, and the checksum recomputed." The addresses are
 * the internet header's; this writes the ICMP message alone. The identifier, the sequence number and
 * the data are carried through, which is RFC 1122 sec 3.2.2.6: "Data received in an ICMP Echo
 * Request MUST be entirely included in the resulting Echo Reply."
 */
IDEMIP_INLINE void icmp_echo_reply(const IcmpCtx *c)
{
    idemip_icmp_build_echo(c->w, (uint8_t)IDEMIP_ICMP_ECHO_REPLY, idemip_icmp_id(c->w), idemip_icmp_seq(c->w), c->len);
}

/**
 * @brief Write an error message head, then its checksum over the whole message.
 *
 * The word is the 32 bits at IDEMIP_ICMP_OFF_UNUSED: zero for the types RFC 792 labels the field
 * unused, the Pointer in the top octet for parameter problem, the Gateway Internet Address for
 * redirect. The quoted datagram sits at IDEMIP_ICMP_OFF_QUOTE and the length counts it.
 */
IDEMIP_INLINE void icmp_build_error(const IcmpCtx *c)
{
    c->w[IDEMIP_ICMP_OFF_TYPE] = c->type;
    c->w[IDEMIP_ICMP_OFF_CODE] = c->code;
    idemip_wr16(c->w + IDEMIP_ICMP_OFF_CKSUM, 0u);
    idemip_wr32(c->w + IDEMIP_ICMP_OFF_UNUSED, c->word);
    idemip_wr16(c->w + IDEMIP_ICMP_OFF_CKSUM, idemip_icmp_cksum_compute(c->w, c->len));
}

/**
 * @brief Write a destination unreachable message, type 3.
 *
 * RFC 1122 sec 3.2.2.1: "A host SHOULD generate Destination Unreachable messages with code: 2
 * (Protocol Unreachable), when the designated transport protocol is not supported; or 3 (Port
 * Unreachable), when the designated transport protocol (e.g., UDP) is unable to demultiplex the
 * datagram but has no protocol mechanism to inform the sender."
 */
IDEMIP_INLINE void icmp_dest_unreachable(const IcmpCtx *c)
{
    idemip_icmp_build_error(c->w, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, c->code, 0u, c->len);
}

/**
 * @brief Write a time exceeded message, type 11.
 *
 * RFC 792: "If a host reassembling a fragmented datagram cannot complete the reassembly due to
 * missing fragments within its time limit it discards the datagram, and it may send a time exceeded
 * message", which is code 1.
 */
IDEMIP_INLINE void icmp_time_exceeded(const IcmpCtx *c)
{
    idemip_icmp_build_error(c->w, (uint8_t)IDEMIP_ICMP_TIME_EXCEEDED, c->code, 0u, c->len);
}

/**
 * @brief Write a parameter problem message, type 12, faulting the pointed octet.
 *
 * RFC 792: "The pointer identifies the octet of the original datagram's header where the error was
 * detected", and it is the top octet of the word at offset 4.
 */
IDEMIP_INLINE void icmp_parameter_problem(const IcmpCtx *c)
{
    idemip_icmp_build_error(c->w, (uint8_t)IDEMIP_ICMP_PARAMETER_PROBLEM, c->code,
                            (uint32_t)c->pointer << IDEMIP_ICMP_POINTER_SHIFT, c->len);
}

/**
 * @brief Write a source quench message, type 4, code 0.
 *
 * RFC 1122 sec 3.2.2.3: "A host MAY send a Source Quench message if it is approaching, or has
 * reached, the point at which it is forced to discard incoming datagrams due to a shortage of
 * reassembly buffers or other resources."
 */
IDEMIP_INLINE void icmp_source_quench(const IcmpCtx *c)
{
    idemip_icmp_build_error(c->w, (uint8_t)IDEMIP_ICMP_SOURCE_QUENCH, IDEMIP_ICMP_CODE_SOURCE_QUENCH, 0u, c->len);
}

/**
 * @brief Bytes an error message quoting the datagram whose internet header is given occupies.
 *
 * The error head, then the quoted header of IHL 32-bit words (RFC 791 sec 3.1), then eight octets of
 * its data.
 */
IDEMIP_INLINE size_t icmp_err_len(const IcmpCtx *c)
{
    return (size_t)IDEMIP_ICMP_ERR_HDR_LEN + IDEMIP_IP4_HDR_BYTES(idemip_ip4_ihl(c->m)) + IDEMIP_ICMP_ERR_QUOTE_DATA;
}

/* The namespaces are tables of function pointers with the caller's argument lists in their types,
   so these are what they point at. Each builds the context and hands it to the body above. */

uint8_t idemip_icmp_type(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_type, IcmpCtx, .m = m);
}

uint8_t idemip_icmp_code(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_code, IcmpCtx, .m = m);
}

uint16_t idemip_icmp_cksum(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_cksum, IcmpCtx, .m = m);
}

uint16_t idemip_icmp_id(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_id, IcmpCtx, .m = m);
}

uint16_t idemip_icmp_seq(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_seq, IcmpCtx, .m = m);
}

uint8_t idemip_icmp_pointer(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_pointer, IcmpCtx, .m = m);
}

uint32_t idemip_icmp_gateway(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_gateway, IcmpCtx, .m = m);
}

uint32_t idemip_icmp_orig_ts(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_orig_ts, IcmpCtx, .m = m);
}

uint32_t idemip_icmp_recv_ts(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_recv_ts, IcmpCtx, .m = m);
}

uint32_t idemip_icmp_xmit_ts(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_xmit_ts, IcmpCtx, .m = m);
}

const uint8_t *idemip_icmp_quote(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_quote, IcmpCtx, .m = m);
}

idemip_bool idemip_icmp_is_error(const uint8_t *m)
{
    return IDEMIP_CALL(icmp_is_error, IcmpCtx, .m = m);
}

uint16_t idemip_icmp_cksum_compute(const uint8_t *m, size_t len)
{
    return IDEMIP_CALL(icmp_cksum_compute, IcmpCtx, .m = m, .len = len);
}

void idemip_icmp_build_echo(uint8_t *m, uint8_t type, uint16_t id, uint16_t seq, size_t len)
{
    IDEMIP_CALL(icmp_build_echo, IcmpCtx, .w = m, .type = type, .id = id, .seq = seq, .len = len);
}

void idemip_icmp_echo_reply(uint8_t *m, size_t len)
{
    IDEMIP_CALL(icmp_echo_reply, IcmpCtx, .w = m, .len = len);
}

void idemip_icmp_build_error(uint8_t *m, uint8_t type, uint8_t code, uint32_t word, size_t len)
{
    IDEMIP_CALL(icmp_build_error, IcmpCtx, .w = m, .type = type, .code = code, .word = word, .len = len);
}

void idemip_icmp_build_dest_unreachable(uint8_t *m, uint8_t code, size_t len)
{
    IDEMIP_CALL(icmp_dest_unreachable, IcmpCtx, .w = m, .code = code, .len = len);
}

void idemip_icmp_build_time_exceeded(uint8_t *m, uint8_t code, size_t len)
{
    IDEMIP_CALL(icmp_time_exceeded, IcmpCtx, .w = m, .code = code, .len = len);
}

void idemip_icmp_build_parameter_problem(uint8_t *m, uint8_t code, uint8_t pointer, size_t len)
{
    IDEMIP_CALL(icmp_parameter_problem, IcmpCtx, .w = m, .code = code, .pointer = pointer, .len = len);
}

void idemip_icmp_build_source_quench(uint8_t *m, size_t len)
{
    IDEMIP_CALL(icmp_source_quench, IcmpCtx, .w = m, .len = len);
}

size_t idemip_icmp_err_len(const uint8_t *ip)
{
    return IDEMIP_CALL(icmp_err_len, IcmpCtx, .m = ip);
}

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4
