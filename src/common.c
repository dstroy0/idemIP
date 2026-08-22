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

IDEMIP_BEGIN_DECLS

static_assert((sizeof(IdemIpMs) % sizeof(IdemIpWord)) == 0u,
              "IdemIpMs must be a whole number of IdemIpWord, so an access is a plain load or store");

// A unit puts one of these at the head of its context, so what follows it starts where this ends: a
// width that is not a whole number of the system's word puts the next region off the word and turns
// every access to it into a split load. Even, and a whole number of words.
static_assert((sizeof(IdemIpClock) & 1u) == 0u, "IdemIpClock must be an even number of octets");
static_assert((sizeof(IdemIpClock) % sizeof(IdemIpWord)) == 0u,
              "IdemIpClock must be a whole number of IdemIpWord, so the region behind it starts on a word");

static_assert((IDEMIP_WORD_BITS & (IDEMIP_WORD_BITS - 1u)) == 0u, "IDEMIP_WORD_BITS must be a power of two");
static_assert(sizeof(IdemIpWord) * 8u == IDEMIP_WORD_BITS, "IdemIpWord must be IDEMIP_WORD_BITS wide");

// Every borrow is taken at IDEMIP_ALIGN and every region inside one starts on a multiple of it, so a
// word laid in a borrow is aligned for its own width only while the borrow's alignment covers it.
// The two are set apart - IDEMIP_ALIGN in idemip_config.h, the word from the target's pointer width -
// so a target that widened one past the other would otherwise under-align every one of them silently.
static_assert(IDEMIP_ALIGN >= sizeof(IdemIpWord), "IDEMIP_ALIGN must cover IdemIpWord: a borrow holds words");
static_assert((IDEMIP_ALIGN & (IDEMIP_ALIGN - 1u)) == 0u, "IDEMIP_ALIGN must be a power of two");

/** @brief One span question. */
typedef struct
{
    const uint8_t *p; /**< The span, or the first of two. */
    const uint8_t *q; /**< The second span, comparing. */
    size_t n;         /**< Octets of it, or the octets of a tail a word does not reach. */
} SpanCtx;

/**
 * @brief One word from the span, and the mask that keeps @c n of its octets.
 * @param c The tail.
 * @return The word with the octets past the tail masked away.
 *
 * The tail of a span is shorter than a word, and the two ways to take it are both worse than this
 * one: a loop pays a compare and an increment per octet, and a switch over the seven remainders pays
 * a dispatch and still reads at three widths. Both distil to a load and a mask.
 *
 * The load is a whole word wherever the span ends, so it reads up to sizeof(IdemIpWord) - 1 octets
 * past it. Every span this tree passes lies inside a borrow the caller took, sized by a published
 * IDEMIP_*_BORROW and mapped for the largest one, so those octets are the caller's own memory. They
 * are read and then masked away, and never reach the answer.
 *
 * An analyser that reads this function without that map reports the load as an out-of-bounds access:
 * SonarCloud c:S3519, at blocker. The NOSONAR on the line answers it. Suppressing it is not a claim
 * that the read does not happen - it does, and the paragraph above is the argument that the octets it
 * reaches are the caller's own. A borrow that is ever sized for less than the largest span mapped in
 * it would make the analyser right, which is what the IDEMIP_*_BORROW sizes exist to prevent.
 *
 * The mask is where byte order enters, and it is the only place it does: the octets of the tail are
 * the low ones of the word on a little-endian part and the high ones on a big-endian part. Both arms
 * shift by less than the width at every count a tail can hold, which is zero through
 * sizeof(IdemIpWord) - 1: the little-endian shift reaches 8 * (sizeof - 1), and the big-endian one
 * is split in two so that a count of zero shifts the top octet out rather than shifting by the
 * width, which C11 sec 6.5.7p3 leaves undefined.
 */
IDEMIP_INLINE IdemIpWord span_tail(const SpanCtx *c)
{
    IdemIpWord w;
    memcpy(&w, c->p, sizeof w); // NOSONAR c:S3519 - the read past the span is the design, and @brief is why
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    const IdemIpWord mask =
        (IdemIpWord) ~(((((IdemIpWord)1u) << (8u * (sizeof(IdemIpWord) - c->n - 1u))) << 8u) - 1u);
#else
    // The cast is NOT redundant, whatever an analyser reading this at one word width reports. The
    // shift promotes to unsigned int, and on a 16-bit IdemIpWord the result of (1 << 8r) - 1 does
    // not fit the word for r >= 2, so this is a narrowing and is spelled as one. gcc's -Wconversion
    // agrees only at IDEMIP_WORD_BITS=16, which is why a build on a 64-bit host cannot see it.
    const IdemIpWord mask = (IdemIpWord)((((IdemIpWord)1u) << (8u * c->n)) - 1u);
#endif
    return (w & mask);
}

/**
 * @brief True when the octets of the span are all zero.
 * @param c The span.
 * @return IDEMIP_TRUE when every octet is zero.
 *
 * RFC 4291 sec 2.5.2's unspecified address is this over sixteen octets, "The address 0:0:0:0:0:0:0:0
 * is called the unspecified address", and RFC 1122 sec 3.2.1.3 (a)'s "{ 0, 0 } This host on this
 * network" is this over four. Every octet is read, so the answer takes the same work whatever the
 * span holds.
 */
IDEMIP_INLINE idemip_bool span_zero(const SpanCtx *c)
{
    IdemIpWord any = 0u;
    size_t i = 0u;
    while (i + sizeof(IdemIpWord) <= c->n)
    {
        IdemIpWord w;
        memcpy(&w, c->p + i, sizeof w);
        any |= w;
        i += sizeof w;
    }
    any |= idemip_span_tail(c->p + i, c->n - i);
    return (idemip_bool)(any == 0u);
}

/**
 * @brief True when the two spans hold the same octets.
 * @param c The comparison.
 * @return IDEMIP_TRUE when they are the same.
 *
 * The difference of the two spans is accumulated and read once, so the answer takes the same work
 * whether they differ in the first octet or the last.
 */
IDEMIP_INLINE idemip_bool span_eq(const SpanCtx *c)
{
    IdemIpWord diff = 0u;
    size_t i = 0u;
    while (i + sizeof(IdemIpWord) <= c->n)
    {
        IdemIpWord u;
        IdemIpWord v;
        memcpy(&u, c->p + i, sizeof u);
        memcpy(&v, c->q + i, sizeof v);
        diff |= (u ^ v);
        i += sizeof u;
    }
    // The same tail on both spans. Each is masked to the same octets before they are differenced, so
    // the octets past the span are zero on both sides and cancel, and a difference inside it cannot
    // cancel against one at another offset: the two words are aligned to the same position.
    diff |= (idemip_span_tail(c->p + i, c->n - i) ^ idemip_span_tail(c->q + i, c->n - i));
    return (idemip_bool)(diff == 0u);
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so these are what it points at. Each builds the context and hands it to the body above. */

IdemIpWord idemip_span_tail(const uint8_t *p, size_t r)
{
    return IDEMIP_CALL(span_tail, SpanCtx, .p = p, .n = r);
}

idemip_bool idemip_bytes_zero(const uint8_t *p, size_t n)
{
    return IDEMIP_CALL(span_zero, SpanCtx, .p = p, .n = n);
}

idemip_bool idemip_bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    return IDEMIP_CALL(span_eq, SpanCtx, .p = a, .q = b, .n = n);
}

IDEMIP_END_DECLS
