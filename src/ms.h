// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ms.h
 * @brief The epoch everything is timed against, and the arithmetic over it.
 *
 * Milliseconds, sixty-four bits. One RFC lifetime field scales into it, and a target whose
 * registers do not hold 64 bits splits it in two halves and joins them back.
 *
 * Nothing here reads a clock. These are functions of their operands: what supplies the reading is
 * clock.h, which is built on this.
 *
 * The table is the whole surface. There are no free functions to call.
 */

#ifndef IDEMIP_MS_H
#define IDEMIP_MS_H

#include "src/idemip_config.h"

IDEMIP_BEGIN_DECLS

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

// The assert that this is a whole number of IdemIpWord sits in common.h, where that type is
// declared: this header is under it and cannot see it.

/** @brief Dispatch table. Addressed by offset, so the layout is asserted below. */
typedef struct
{
    IdemIpMs (*from_s)(uint32_t seconds);
    uint32_t (*hi)(IdemIpMs t);
    uint32_t (*lo)(IdemIpMs t);
    IdemIpMs (*join)(uint32_t hi, uint32_t lo);
    IdemIpMs (*extend)(uint32_t *last_ms, uint32_t *hi, uint32_t now_ms);
} MsNs;
IDEMIP_NS_LAYOUT(MsNs, from_s, hi, lo, join, extend);

/** @name The entries the table points at.
 *  @brief Nameable so a static const table can name them, and for no other reason. The table is
 *         still the whole surface: call through it.
 *  @{ */
IdemIpMs idemip_ms_from_s(uint32_t seconds);
uint32_t idemip_ms_hi(IdemIpMs t);
uint32_t idemip_ms_lo(IdemIpMs t);
IdemIpMs idemip_ms_join(uint32_t hi, uint32_t lo);
IdemIpMs idemip_ms_extend(uint32_t *last_ms, uint32_t *hi, uint32_t now_ms);
/** @} */

/**
 * @brief Module namespace.
 *
 * static const, like every other module's. gcc devirtualizes a call through one down to the
 * inlined body and cannot do that through an extern one, where the table is in another
 * translation unit and every call is a load and an indirect jump.
 */
IDEMIP_NS MsNs ms IDEMIP_UNUSED = {
    .from_s = idemip_ms_from_s,
    .hi = idemip_ms_hi,
    .lo = idemip_ms_lo,
    .join = idemip_ms_join,
    .extend = idemip_ms_extend,
};

IDEMIP_END_DECLS

#endif // IDEMIP_MS_H
