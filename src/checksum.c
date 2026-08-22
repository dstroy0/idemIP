// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file checksum.c
 * @brief The internet checksum, RFC 1071.
 *
 * Every entry below takes one parameter, a pointer to ChecksumCtx. A checksum is a running sum and
 * the span being carried into it, so those are one context.
 */

#include "src/idemip_config.h" // the entry point: the widths

#include "src/checksum.h"

/**
 * @brief Whether the word path of RFC 1071 sec 2 (C) can be taken on this build.
 *
 * sec 2 (C) sums the message in the machine's own word and folds afterwards, and sec 2 (B) says of
 * the result that "consistently swapping bytes simply rotates the bits within the sum, but does not
 * affect their internal ordering" - so a native-word sum lands in the byte order of the host and is
 * swapped back at the fold. Which swap that is, is the host's byte order, so a build whose compiler
 * does not state it takes the sec 1 pair loop instead. Guessing it would be a silently wrong
 * checksum on every packet, and the pair loop is what this file did before the word path existed.
 * A build may set IDEMIP_CKSUM_WORD itself to force either route.
 */
#ifndef IDEMIP_CKSUM_WORD
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define IDEMIP_CKSUM_WORD 1
#define IDEMIP_CKSUM_WORD_SWAP 1
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define IDEMIP_CKSUM_WORD 1
#define IDEMIP_CKSUM_WORD_SWAP 0
#else
#define IDEMIP_CKSUM_WORD 0
#define IDEMIP_CKSUM_WORD_SWAP 0
#endif
#elif defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM) || defined(_M_ARM64))
#define IDEMIP_CKSUM_WORD 1
#define IDEMIP_CKSUM_WORD_SWAP 1
#else
#define IDEMIP_CKSUM_WORD 0
#define IDEMIP_CKSUM_WORD_SWAP 0
#endif
#endif

#ifndef IDEMIP_CKSUM_WORD_SWAP
#define IDEMIP_CKSUM_WORD_SWAP 0
#endif

IDEMIP_BEGIN_DECLS

/** @brief One sum over one span. */
typedef struct
{
    uint32_t sum;     /**< The running sum coming in, or 0 to begin. */
    const uint8_t *p; /**< The span being summed. */
    size_t len;       /**< How many octets of it. */
} ChecksumCtx;

#if IDEMIP_CKSUM_WORD

/**
 * @brief Fold a word-wide 1's complement sum down to sixteen bits, in the host's byte order.
 *
 * RFC 1071 sec 2 (C): "When the sum has been computed, we 'fold' the long sum into 16 bits by adding
 * the 16-bit segments. Each 16-bit addition may produce new end-around carries that must be added."
 * Each step halves the width and the carries it makes are folded by the step after it, so the last
 * pair of adds is what settles the sixteen bits.
 *
 * Not an entry: it is the word path's own arithmetic and no caller has a use for it.
 */
IDEMIP_INLINE uint16_t cksum_fold_word(IdemIpWord acc)
{
#if IDEMIP_WORD_BITS == 64u
    acc = (acc & 0xFFFFFFFFu) + (acc >> 32);
#endif
#if IDEMIP_WORD_BITS >= 32u
    acc = (acc & 0xFFFFu) + (acc >> 16);
#endif
    uint32_t s = (uint32_t)(acc & 0xFFFFu) + (uint32_t)(acc >> 16);
    s = (s & 0xFFFFu) + (s >> 16);
    return (uint16_t)s;
}

#endif // IDEMIP_CKSUM_WORD

/**
 * @brief Accumulate the span into the running 1's complement sum.
 * @param c The sum.
 * @return The sum with the span carried into it, folded.
 *
 * RFC 1071 sec 1: the words are [A,B] +' [C,D] +' ... , and an odd count is the final byte taken
 * as [Z,0] - the pad is not sent, it only completes the last word. The span begins on a 16-bit
 * boundary of its own, so two calls over the halves of an even-length span make the same sum as one
 * call over the whole of it.
 *
 * The carries are folded once at the end of a call rather than per word: RFC 1071 sec 1 notes "any
 * overflows from the most significant bits are added into the least significant bits", and sec 2
 * that the sum may be accumulated deferred and folded afterwards, which is the same value in fewer
 * steps. A 32-bit accumulator cannot overflow before that fold for any length this stack carries.
 * The fold is what makes the reported sum canonical: two calls over the halves of a span and one
 * call over the whole of it report the same number, whichever route each took through it.
 *
 * sec 2 (C) Parallel Summation takes the whole run a word at a time: "Because addition is
 * associative, we do not have to sum the integers in the order they appear in the message. Instead
 * we can add them in 'parallel' by exploiting the larger word size ... simply do a 1's complement
 * addition of the message using the native word size of the machine." One word covers
 * sizeof(IdemIpWord) octets, so the loop runs that many times fewer. The word is taken by copy and
 * not through a cast, which is what lets it be taken from wherever the span begins: endian.h's rule
 * is that "a cast to a wider type at an odd address is a fault on the parts in the target list that
 * require natural alignment", and a copy of a constant width is defined at every address. A target
 * whose loads must be aligned gets the byte sequence its compiler emits for that copy, which is the
 * work the pair loop below does anyway; one whose loads need not be gets a single load.
 *
 * The accumulator carries end-around on every add, per sec 1's "any overflows from the most
 * significant bits are added into the least significant bits", so no length can overflow it and the
 * run needs no bound.
 */
IDEMIP_INLINE uint32_t cksum_accum(const ChecksumCtx *c)
{
    uint32_t sum = c->sum;
    size_t i = 0;

#if IDEMIP_CKSUM_WORD
    if (c->len >= sizeof(IdemIpWord))
    {
        IdemIpWord acc = 0u;
        do
        {
            IdemIpWord w;
            memcpy(&w, c->p + i, sizeof w);
            acc += w;
            acc += (IdemIpWord)(acc < w); // sec 1's end-around carry, applied as it goes
            i += sizeof w;
        } while (i + sizeof(IdemIpWord) <= c->len);
        uint16_t folded = cksum_fold_word(acc);
#if IDEMIP_CKSUM_WORD_SWAP
        // sec 2 (B): the sum came out with its bytes swapped, "except the bytes are swapped in the
        // sum", so it is swapped back into the order the pair loop and the caller's running sum use.
        folded = (uint16_t)((uint16_t)(folded << 8) | (uint16_t)(folded >> 8));
#endif
        sum += (uint32_t)folded;
    }
#endif

    while (i + 1u < c->len)
    {
        sum += (((uint32_t)c->p[i] << 8) | (uint32_t)c->p[i + 1u]);
        i += 2u;
    }
    if (i < c->len)
    {
        sum += ((uint32_t)c->p[i] << 8); // [Z,0]: the odd byte is the high half
    }
    // sec 1's end-around carry, applied before the sum is handed back, so the value a call reports
    // is the same whatever route it took through the span: RFC 1071 sec 3 tabulates the deferred sum
    // and the folded one as Sum1 and Sum2 of one number, and this is always Sum2.
    sum = (sum & 0xFFFFu) + (sum >> 16);
    sum = (sum & 0xFFFFu) + (sum >> 16);
    return sum;
}

/**
 * @brief Fold the carries and complement, giving the value that goes in the header.
 * @param c The sum.
 * @return The sixteen bits the field carries.
 *
 * RFC 1071 sec 1: the end-around carry is applied until none remains, then the sum is complemented.
 * Two folds are enough - the first can produce at most one new carry.
 */
IDEMIP_INLINE uint16_t cksum_final(const ChecksumCtx *c)
{
    uint32_t sum = c->sum;
    sum = (sum & 0xFFFFu) + (sum >> 16);
    sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

/**
 * @brief The checksum over one span.
 * @param c The span.
 * @return The sixteen bits the field carries.
 */
IDEMIP_INLINE uint16_t cksum_over(const ChecksumCtx *c)
{
    const uint32_t sum = cksum_accum(c);
    return IDEMIP_CALL(cksum_final, ChecksumCtx, .sum = sum);
}

/**
 * @brief True when a received span checks out.
 * @param c The span.
 * @return IDEMIP_TRUE when it does.
 *
 * RFC 1071 sec 1: summing a span that already carries its checksum yields all ones, whose
 * complement is zero. A verifier therefore runs the same sum and tests for zero rather than
 * clearing the field and recomputing.
 */
IDEMIP_INLINE idemip_bool cksum_valid(const ChecksumCtx *c)
{
    return (idemip_bool)(cksum_over(c) == 0u);
}

/* The namespace is a table of function pointers with the caller's argument lists in their types,
   so these are what it points at. Each builds the context and hands it to the body above. */

uint32_t idemip_cksum_accum(uint32_t sum, const uint8_t *p, size_t len)
{
    return IDEMIP_CALL(cksum_accum, ChecksumCtx, .sum = sum, .p = p, .len = len);
}

uint16_t idemip_cksum_final(uint32_t sum)
{
    return IDEMIP_CALL(cksum_final, ChecksumCtx, .sum = sum);
}

uint16_t idemip_cksum(const uint8_t *p, size_t len)
{
    return IDEMIP_CALL(cksum_over, ChecksumCtx, .p = p, .len = len);
}

idemip_bool idemip_cksum_valid(const uint8_t *p, size_t len)
{
    return IDEMIP_CALL(cksum_valid, ChecksumCtx, .p = p, .len = len);
}

IDEMIP_END_DECLS
