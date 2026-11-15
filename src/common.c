// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file common.c
 * @brief The two questions asked of a span of octets, and the tail a word does not reach.
 *
 * Every entry below takes one parameter, a pointer to SpanCtx. A span question is the octets and
 * how many of them, so those are one context.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/common.h"
#include "src/common_defines.h" // the sizes each standard fixes, which this file is the first user of

EMBED_BEGIN_DECLS

EMBED_STATIC_ASSERT((sizeof(IdemIpMs) % sizeof(embed_word)) == 0u,
                    "IdemIpMs must be a whole number of embed_word, so an access is a plain load or store");

// A unit puts one of these at the head of its context, so what follows it starts where this ends: a
// width that is not a whole number of the system's word puts the next region off the word and turns
// every access to it into a split load. Even, and a whole number of words.
EMBED_STATIC_ASSERT((sizeof(IdemIpClock) & 1u) == 0u, "IdemIpClock must be an even number of octets");
EMBED_STATIC_ASSERT((sizeof(IdemIpClock) % sizeof(embed_word)) == 0u,
                    "IdemIpClock must be a whole number of embed_word, so the region behind it starts on a word");

EMBED_STATIC_ASSERT((EMBED_WORD_BITS & (EMBED_WORD_BITS - 1u)) == 0u, "EMBED_WORD_BITS must be a power of two");
EMBED_STATIC_ASSERT(sizeof(embed_word) * 8u == EMBED_WORD_BITS, "embed_word must be EMBED_WORD_BITS wide");

// Every borrow is taken at IDEMIP_ALIGN and every region inside one starts on a multiple of it, so a
// word laid in a borrow is aligned for its own width only while the borrow's alignment covers it.
// The two are set apart - IDEMIP_ALIGN in idemip_config.h, the word from the target's pointer width -
// so a target that widened one past the other would otherwise under-align every one of them silently.
EMBED_STATIC_ASSERT(IDEMIP_ALIGN >= sizeof(embed_word), "IDEMIP_ALIGN must cover embed_word: a borrow holds words");
EMBED_STATIC_ASSERT((IDEMIP_ALIGN & (IDEMIP_ALIGN - 1u)) == 0u, "IDEMIP_ALIGN must be a power of two");

/** @brief One span question. */
typedef struct
{
    const uint8_t *p; /**< The span, or the first of two. */
    const uint8_t *q; /**< The second span, comparing. */
    size_t n;         /**< Octets of it, or the octets of a tail a word does not reach. */
} SpanCtx;

/**
 * @brief The @c n octets of a span's tail, as one word with every other octet zero.
 * @param c The tail.
 * @return The word.
 *
 * @note The tail is shorter than a word. proxim.read copies its n octets to the low addresses of a
 *       zeroed word, and reads no octet past the span. A span can be the caller's own object, as an
 *       address that a bind takes is, and so the read stays inside it.
 * @note The octets land at the low addresses of the word: the low ones of its value on a little-endian
 *       part and the high ones on a big-endian part. Both spans that span_eq compares land the same
 *       way, so the compare of the two words holds on either part.
 */
EMBED_INLINE embed_word span_tail(const SpanCtx *c)
{
    embed_word w = 0u;
    EMBED_CALL(proxim.read, ProximusCfg, .dst = &w, .at = c->p, .size = c->n);
    return w;
}

/**
 * @brief True when the octets of the span are all zero.
 * @param c The span.
 * @return EMBED_TRUE when every octet is zero.
 *
 * RFC 4291 sec 2.5.2's unspecified address is this over sixteen octets, "The address 0:0:0:0:0:0:0:0
 * is called the unspecified address", and RFC 1122 sec 3.2.1.3 (a)'s "{ 0, 0 } This host on this
 * network" is this over four. Every octet is read, so the answer takes the same work whatever the
 * span holds.
 */
EMBED_INLINE embed_bool span_zero(const SpanCtx *c)
{
    embed_word any = 0u;
    size_t i = 0u;
    while (i + sizeof(embed_word) <= c->n)
    {
        any |= EMBED_CALL(proxim.load, ProximusCfg, .at = c->p + i);
        i += sizeof(embed_word);
    }
    any |= idemip_span_tail(c->p + i, c->n - i);
    return (embed_bool)(any == 0u);
}

/**
 * @brief True when the two spans hold the same octets.
 * @param c The comparison.
 * @return EMBED_TRUE when they are the same.
 *
 * The difference of the two spans is accumulated and read once, so the answer takes the same work
 * whether they differ in the first octet or the last.
 */
EMBED_INLINE embed_bool span_eq(const SpanCtx *c)
{
    embed_word diff = 0u;
    size_t i = 0u;
    while (i + sizeof(embed_word) <= c->n)
    {
        const embed_word u = EMBED_CALL(proxim.load, ProximusCfg, .at = c->p + i);
        const embed_word v = EMBED_CALL(proxim.load, ProximusCfg, .at = c->q + i);
        diff |= (u ^ v);
        i += sizeof(embed_word);
    }
    // The same tail on both spans. Each is masked to the same octets before they are differenced, so
    // the octets past the span are zero on both sides and cancel, and a difference inside it cannot
    // cancel against one at another offset: the two words are aligned to the same position.
    diff |= (idemip_span_tail(c->p + i, c->n - i) ^ idemip_span_tail(c->q + i, c->n - i));
    return (embed_bool)(diff == 0u);
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so these are what it points at. Each builds the context and hands it to the body above. */

embed_word idemip_span_tail(const uint8_t *p, size_t r)
{
    return EMBED_CALL(span_tail, SpanCtx, .p = p, .n = r);
}

embed_bool idemip_bytes_zero(const uint8_t *p, size_t n)
{
    return EMBED_CALL(span_zero, SpanCtx, .p = p, .n = n);
}

embed_bool idemip_bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    return EMBED_CALL(span_eq, SpanCtx, .p = a, .q = b, .n = n);
}

EMBED_END_DECLS
