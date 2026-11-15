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

// embed_word is the system word, and EMBED_WORD_BITS is its width. embed_types.h gets both from
// UINTPTR_MAX, and a build can set EMBED_WORD_BITS on the command line. Each size below is a power
// of two multiple of the word, so an access is one plain load or store.

EMBED_BEGIN_DECLS

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
    embed_word (*tail)(const uint8_t *p, size_t r);
    embed_bool (*zero)(const uint8_t *p, size_t n);
    embed_bool (*eq)(const uint8_t *a, const uint8_t *b, size_t n);
} SpanNs;
EMBED_TABLE_LAYOUT(SpanNs, tail, zero, eq);

/** @name The entries the table points at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The table is
 *         still the whole surface: call through it.
 *  @{ */
embed_word idemip_span_tail(const uint8_t *p, size_t r);
embed_bool idemip_bytes_zero(const uint8_t *p, size_t n);
embed_bool idemip_bytes_eq(const uint8_t *a, const uint8_t *b, size_t n);
/** @} */

/**
 * @brief Module namespace.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
EMBED_TABLE_STORAGE SpanNs span EMBED_UNUSED = {
    .tail = idemip_span_tail,
    .zero = idemip_bytes_zero,
    .eq = idemip_bytes_eq,
};

EMBED_END_DECLS

#endif // IDEMIP_COMMON_H
