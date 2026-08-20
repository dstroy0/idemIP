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
 * @brief The system's word: the width a load or a store is one instruction at.
 *
 * Every size below is a power of two multiple of it, so an access compiles to a plain load or store
 * and the lanes a SWAR operation packs are the ones the register already holds.
 */
#ifndef IDEMIP_WORD_BITS
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFu
#define IDEMIP_WORD_BITS 64u
#elif UINTPTR_MAX == 0xFFFFFFFFu
#define IDEMIP_WORD_BITS 32u
#else
#define IDEMIP_WORD_BITS 16u
#endif
#endif

#if IDEMIP_WORD_BITS == 64u
typedef uint64_t IdemIpWord;
#elif IDEMIP_WORD_BITS == 32u
typedef uint32_t IdemIpWord;
#else
typedef uint16_t IdemIpWord;
#endif

static_assert((IDEMIP_WORD_BITS & (IDEMIP_WORD_BITS - 1u)) == 0u, "IDEMIP_WORD_BITS must be a power of two");
static_assert(sizeof(IdemIpWord) * 8u == IDEMIP_WORD_BITS, "IdemIpWord must be IDEMIP_WORD_BITS wide");

// ---------------------------------------------------------------------------
// Spans of octets
// ---------------------------------------------------------------------------
// One test each, over the machine's word. An address is sixteen octets and a link-layer one is six,
// so the run a word covers is most of what either of them is, and the tail is what a word does not
// reach. The word is taken by copy and not through a cast, which is what lets it be taken from
// wherever a span begins: endian.h's rule is that "a cast to a wider type at an odd address is a
// fault on the parts in the target list that require natural alignment", and a copy of a constant
// width is defined at every address.
//
// Neither test needs to know the host's byte order. Both reduce the span to one accumulator and read
// only whether it is zero, and a word is zero exactly when the octets in it are, whichever lane each
// octet landed in.

/**
 * @brief True when the @p n octets at @p p are all zero.
 *
 * RFC 4291 sec 2.5.2's unspecified address is this over sixteen octets, "The address 0:0:0:0:0:0:0:0
 * is called the unspecified address", and RFC 1122 sec 3.2.1.3 (a)'s "{ 0, 0 } This host on this
 * network" is this over four. Every octet is read, so the answer takes the same work whatever the
 * span holds.
 */
IDEMIP_INLINE idemip_bool idemip_bytes_zero(const uint8_t *p, size_t n)
{
    IdemIpWord any = 0u;
    size_t i = 0u;
    while (i + sizeof(IdemIpWord) <= n)
    {
        IdemIpWord w;
        memcpy(&w, p + i, sizeof w);
        any |= w;
        i += sizeof w;
    }
    uint8_t tail = 0u;
    for (; i < n; i++)
    {
        tail = (uint8_t)(tail | p[i]);
    }
    return (idemip_bool)((any == 0u) && (tail == 0u));
}

/**
 * @brief True when the @p n octets at @p a and @p b are the same.
 *
 * The difference of the two spans is accumulated and read once, so the answer takes the same work
 * whether they differ in the first octet or the last.
 */
IDEMIP_INLINE idemip_bool idemip_bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    IdemIpWord diff = 0u;
    size_t i = 0u;
    while (i + sizeof(IdemIpWord) <= n)
    {
        IdemIpWord u;
        IdemIpWord v;
        memcpy(&u, a + i, sizeof u);
        memcpy(&v, b + i, sizeof v);
        diff |= (IdemIpWord)(u ^ v);
        i += sizeof u;
    }
    uint8_t tail = 0u;
    for (; i < n; i++)
    {
        tail = (uint8_t)(tail | (uint8_t)(a[i] ^ b[i]));
    }
    return (idemip_bool)((diff == 0u) && (tail == 0u));
}

/**
 * @brief The clock everything is timed against: milliseconds, sixty-four bits.
 *
 * One word on a 64-bit target, two on a 32-bit one, four on a 16-bit one, so it is always a whole
 * number of dumb loads. Milliseconds throughout, so nothing is ever rounded to a second, and a span
 * of 584 million years, so a lifetime the RFCs state in a 32-bit seconds field converts into it
 * whole. It is one scalar, so an interval is one subtraction and a correction for deterministic
 * timing is one addition.
 */
typedef uint64_t IdemIpMs;

static_assert((sizeof(IdemIpMs) % sizeof(IdemIpWord)) == 0u,
              "IdemIpMs must be a whole number of IdemIpWord, so an access is a plain load or store");

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

/**
 * @brief One RFC lifetime field, seconds, as milliseconds on the clock above.
 *
 * 1000 is 1024 - 16 - 8, so the scale is three shifts and two subtractions and no multiply. This is
 * for the moment a lifetime is taken, which turns it into a deadline; the sweep that reads that
 * deadline compares two clock values and scales nothing.
 */
IDEMIP_INLINE IdemIpMs idemip_ms_from_s(uint32_t seconds)
{
    IdemIpMs s = (IdemIpMs)seconds;
    return (s << 10) - (s << 4) - (s << 3);
}

/** @brief The high half of a clock value, for a target that carries it in two words. */
IDEMIP_INLINE uint32_t idemip_ms_hi(IdemIpMs t)
{
    return (uint32_t)(t >> 32);
}

/** @brief Its low half. */
IDEMIP_INLINE uint32_t idemip_ms_lo(IdemIpMs t)
{
    return (uint32_t)(t & 0xFFFFFFFFu);
}

/** @brief The two halves back into one clock value. */
IDEMIP_INLINE IdemIpMs idemip_ms_join(uint32_t hi, uint32_t lo)
{
    return ((IdemIpMs)hi << 32) | (IdemIpMs)lo;
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
