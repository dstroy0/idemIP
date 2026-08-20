// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file common.h
 * @brief The sizes and widths each standard fixes, for every layer here.
 *
 * Constants only. This tree parses and builds headers in a caller's bytes; it owns no storage,
 * moves nothing, and decides nothing about buffering. Anything that needs a buffer already has one
 * above, and a copy here would be a second one for no reason.
 */

#ifndef IDEMIP_COMMON_H
#define IDEMIP_COMMON_H

#include "src/endian.h" // the wire-integer accessors, and through them the fixed widths

IDEMIP_BEGIN_DECLS

/**
 * @brief Smallest datagram every IPv4 host must be able to reassemble.
 *
 * RFC 1122 sec 3.3.2: "We designate the largest datagram size that can be reassembled by EMTU_R
 * ("Effective MTU to receive")... EMTU_R MUST be greater than or equal to 576".
 */
#define IDEMIP_IPV4_MIN_MTU 576u

/** @brief Smallest IPv6 link MTU (RFC 8200 sec 5). */
#define IDEMIP_IPV6_MIN_MTU 1280u

/**
 * @brief Largest packet every IPv6 node must be able to reassemble.
 *
 * RFC 8200 sec 5: "A node must be able to accept a fragmented packet that, after reassembly, is as
 * large as 1500 octets."
 */
#define IDEMIP_IPV6_MIN_REASSEMBLY 1500u

/**
 * @brief Send MSS assumed when the peer sent no MSS Option.
 *
 * RFC 9293 sec 3.7.1 MUST-15: "If an MSS Option is not received at connection setup, TCP
 * implementations MUST assume a default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60)
 * for IPv6".
 */
#define IDEMIP_IPV4_DEFAULT_SEND_MSS 536u
#define IDEMIP_IPV6_DEFAULT_SEND_MSS 1220u

/** @brief Fixed TCP header, no options (RFC 9293 sec 3.1). */
#define IDEMIP_TCP_HDR_LEN 20u

/** @brief Fixed IPv4 header, no options (RFC 791 sec 3.1). */
#define IDEMIP_IPV4_HDR_LEN 20u

/** @brief Fixed IPv6 header, extension headers excluded (RFC 8200 sec 3). */
#define IDEMIP_IPV6_HDR_LEN 40u

/**
 * @brief RFC 8200 sec 8.3: over IPv6 "the MSS must be computed as the maximum packet size minus 60
 * octets", the minimum IPv6 header plus the minimum TCP header.
 */
static_assert(IDEMIP_IPV6_MIN_MTU - IDEMIP_IPV6_HDR_LEN - IDEMIP_TCP_HDR_LEN == IDEMIP_IPV6_DEFAULT_SEND_MSS,
              "RFC 9293 sec 3.7.1 MUST-15's IPv6 default of 1220 is the minimum link MTU less 60");
static_assert(IDEMIP_IPV4_MIN_MTU - IDEMIP_IPV4_HDR_LEN - IDEMIP_TCP_HDR_LEN == IDEMIP_IPV4_DEFAULT_SEND_MSS,
              "RFC 9293 sec 3.7.1 MUST-15's IPv4 default of 536 is EMTU_R less 40");

// ---------------------------------------------------------------------------
// Elapsed time
// ---------------------------------------------------------------------------

/** @brief Milliseconds in one second. */
#define IDEMIP_MS_PER_S 1000u

/**
 * @brief The clock everything is timed against: milliseconds, sixty-four bits.
 *
 * One word on a 64-bit target and two on a 32-bit one. Milliseconds throughout, so nothing is ever
 * rounded to a second, and a span of 584 million years, so a lifetime the RFCs state in a 32-bit
 * seconds field converts into it whole. It is one scalar, so an interval is one subtraction and a
 * correction is one addition.
 */
typedef uint64_t IdemIpMs;

/**
 * @brief Extend a caller's 32-bit millisecond clock across its wrap.
 *
 * The caller hands @p now_ms, and a module already keeps the stamp it last saw. When the new reading
 * is below the old one the clock has wrapped, which raises the high word. That is the two clocks a
 * module already has, widened, and no third one.
 *
 * @param last_ms the last reading this module saw, updated to @p now_ms
 * @param hi      the high word, raised on each wrap
 */
IDEMIP_INLINE IdemIpMs idemip_ms_extend(uint32_t *last_ms, uint32_t *hi, uint32_t now_ms)
{
    if (now_ms < *last_ms)
    {
        (*hi)++;
    }
    *last_ms = now_ms;
    return ((IdemIpMs)(*hi) << 32) | (IdemIpMs)now_ms;
}

/** @brief One RFC lifetime field, seconds, as milliseconds on the clock above. */
IDEMIP_INLINE IdemIpMs idemip_ms_from_s(uint32_t seconds)
{
    return (IdemIpMs)seconds * IDEMIP_MS_PER_S;
}

/**
 * @brief Whole seconds between @p last_ms and @p now_ms, advancing @p last_ms by exactly those.
 *
 * A module already holds the two millisecond clocks an elapsed time needs: the stamp it took last
 * and the @c now_ms it was handed. This adds no third one. Advancing the stamp by whole seconds
 * alone leaves the sub-second remainder in the gap between it and @p now_ms, so nothing is lost
 * across calls.
 *
 * What the seconds counter it feeds is for is range, never resolution. A 32-bit millisecond count
 * spans about 49.7 days; the RFCs state lifetimes in a 32-bit seconds field, which spans about 136
 * years. Neither unit alone both reaches that range and keeps millisecond resolution, so a timed
 * object stamps both and @ref idemip_elapsed_reached reads them together.
 */
IDEMIP_INLINE uint32_t idemip_elapsed_seconds(uint32_t *last_ms, uint32_t now_ms)
{
    uint32_t d_ms = now_ms - *last_ms;
    if (d_ms < IDEMIP_MS_PER_S)
    {
        return 0u;
    }
    uint32_t whole = d_ms / IDEMIP_MS_PER_S;
    *last_ms += whole * IDEMIP_MS_PER_S;
    return whole;
}

/**
 * @brief Has @p lifetime_ms passed since a stamp of (@p set_s, @p set_ms)?
 *
 * @p now_s and @p now_ms are the module's seconds counter and the caller's millisecond clock. The
 * seconds pair carries the range and the millisecond pair carries the resolution: while the two
 * stamps are inside the span a 32-bit millisecond count can express, the answer is the millisecond
 * difference exactly, and past that the seconds difference decides. Nothing here is rounded to a
 * second.
 */
IDEMIP_INLINE idemip_bool idemip_elapsed_reached(uint32_t set_s, uint32_t set_ms, uint32_t now_s, uint32_t now_ms,
                                                 uint32_t lifetime_ms)
{
    uint32_t d_s = now_s - set_s;
    // Past what a millisecond count can express, the millisecond difference has wrapped and only the
    // seconds difference is still meaningful.
    if (d_s > (0xFFFFFFFFu / IDEMIP_MS_PER_S))
    {
        return IDEMIP_TRUE;
    }
    return ((now_ms - set_ms) >= lifetime_ms) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

IDEMIP_END_DECLS

#endif // IDEMIP_COMMON_H
