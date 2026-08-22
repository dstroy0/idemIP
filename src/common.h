// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file common.h
 * @brief The system's word, and the two questions asked of a span of octets.
 *
 * This tree parses and builds headers in a caller's bytes; it owns no storage, moves nothing, and
 * decides nothing about buffering. Anything that needs a buffer already has one above, and a copy
 * here would be a second one for no reason.
 *
 * The sizes each standard fixes are common_defines.h, which a .c includes when it needs them.
 *
 * The table is the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_COMMON_H
#define IDEMIP_COMMON_H

#include "src/endian.h" // the wire-integer accessors, and through them the fixed widths

/**
 * @brief The system's word: the width a load or a store is one instruction at.
 *
 * Every size below is a power of two multiple of it, so an access compiles to a plain load or store
 * and the lanes a SWAR operation packs are the ones the register already holds.
 *
 * Here rather than in common_defines.h because the typedef under it is what this header declares,
 * and a type cannot be declared against a width it cannot see.
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

IDEMIP_BEGIN_DECLS

#if IDEMIP_WORD_BITS == 64u
typedef uint64_t IdemIpWord;
#elif IDEMIP_WORD_BITS == 32u
typedef uint32_t IdemIpWord;
#else
typedef uint16_t IdemIpWord;
#endif

// Time is its own header, and is included from here rather than beside endian.h because its epoch
// is asserted against the word declared just above. clock.h tells the readings apart: now(), stamp()
// and epoch(); the fourth, determinism_pad(), is time_determinism.h.
#include "src/clock.h"

/**
 * @brief One test each, over the machine's word, for the two questions asked of a span of octets.
 *
 * An address is sixteen octets and a link-layer one is six, so the run a word covers is most of what
 * either of them is, and the tail is what a word does not reach. The word is taken by copy and not
 * through a cast, which is what lets it be taken from wherever a span begins: endian.h's rule is
 * that "a cast to a wider type at an odd address is a fault on the parts in the target list that
 * require natural alignment", and a copy of a constant width is defined at every address.
 *
 * Neither test needs to know the host's byte order. Both reduce the span to one accumulator and read
 * only whether it is zero, and a word is zero exactly when the octets in it are, whichever lane each
 * octet landed in.
 */
typedef struct
{
    IdemIpWord (*tail)(const uint8_t *p, size_t r);
    idemip_bool (*zero)(const uint8_t *p, size_t n);
    idemip_bool (*eq)(const uint8_t *a, const uint8_t *b, size_t n);
} SpanNs;
IDEMIP_NS_LAYOUT(SpanNs, tail, zero, eq);

/** @name The entries the table points at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The table is
 *         still the whole surface: call through it.
 *  @{ */
IdemIpWord idemip_span_tail(const uint8_t *p, size_t r);
idemip_bool idemip_bytes_zero(const uint8_t *p, size_t n);
idemip_bool idemip_bytes_eq(const uint8_t *a, const uint8_t *b, size_t n);
/** @} */

/**
 * @brief Module namespace.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS SpanNs span IDEMIP_UNUSED = {
    .tail = idemip_span_tail,
    .zero = idemip_bytes_zero,
    .eq = idemip_bytes_eq,
};

IDEMIP_END_DECLS

#endif // IDEMIP_COMMON_H
