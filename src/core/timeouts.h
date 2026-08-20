// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file timeouts.h
 * @brief The deadline list, keyed by the unit whose tick owns the work, and the tick that drains it.
 *
 * A deadline is an absolute millisecond, compared against the count the caller hands @ref
 * TimeoutsNs::tick. Deadlines are held in milliseconds throughout this tree, so no tick period
 * scales one and no conversion exists.
 *
 * The count wraps at 2^32. Every comparison here is the unsigned difference of two counts, so a
 * deadline whose count is numerically below the clock's is still ahead of it, and a deadline reads as
 * ahead of the recorded count for up to 0x80000000 milliseconds. One past that reads as behind it and
 * is due at once, which bounds a deadline to 24.8 days out.
 *
 * No entry holds a function pointer. An entry names the unit whose own tick owns the work and an
 * index into that unit's own table, and @ref TimeoutsNs::expire hands the pair back to the caller.
 * The order those units run in is core/tick.h's IdemIpTickUnit, which is where the dependency order
 * is enforced; nothing here orders anything but deadlines.
 *
 * Nothing under src/ arms one. Every service carries its own deadlines in its own table - a TCB its
 * RFC 6298 retransmission, an ARP row its age, a reassembly row its RFC 1122 sec 3.3.2 timer - and
 * its own tick walks them, so this list is not how the library keeps time. It is the caller's, for
 * deadlines the caller wants handed back to it on the tick that reaches them, and TickNs::service
 * drains it into TickIo::timeout_unit and TickIo::timeout_arg once the units it does drive are
 * through. IDEMIP_TIMEOUTS is sized for one deadline per service on that basis, so a caller wanting
 * one per row of a unit's table raises it.
 */

#ifndef IDEMIP_TIMEOUTS_H
#define IDEMIP_TIMEOUTS_H

#include "src/idemip_config.h"

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/**
 * @brief The unit a deadline belongs to, which is the unit whose tick runs the work.
 *
 * One per service that defers work: TCP; reassembly, ARP and IGMP under IPv4; ND, reassembly, MLD
 * and DAD under IPv6; DNS; and ACD, AutoIP, DHCPv4 and DHCPv6 on each interface. That sum is what
 * IDEMIP_TIMEOUTS counts.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_TIMEOUT_UNIT_NONE = 0, ///< the slot holds no deadline
    IDEMIP_TIMEOUT_UNIT_TCP,
    IDEMIP_TIMEOUT_UNIT_ARP,
    IDEMIP_TIMEOUT_UNIT_IP4_REASS,
    IDEMIP_TIMEOUT_UNIT_IGMP,
    IDEMIP_TIMEOUT_UNIT_ND6,
    IDEMIP_TIMEOUT_UNIT_IP6_REASS,
    IDEMIP_TIMEOUT_UNIT_MLD6,
    IDEMIP_TIMEOUT_UNIT_DAD,
    IDEMIP_TIMEOUT_UNIT_DNS,
    IDEMIP_TIMEOUT_UNIT_ACD,
    IDEMIP_TIMEOUT_UNIT_AUTOIP,
    IDEMIP_TIMEOUT_UNIT_DHCP4,
    IDEMIP_TIMEOUT_UNIT_DHCP6,
    IDEMIP_TIMEOUT_UNIT_COUNT, ///< one past the last unit, so a bad id is one compare
} IdemIpTimeoutUnit;

/** @brief What a slot carries besides its deadline. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_TIMEOUT_FLAG_NONE = 0,
    IDEMIP_TIMEOUT_FLAG_ARMED = 1u, ///< the slot holds a deadline; clear means the slot is free
} IdemIpTimeoutFlag;

/** @brief What @ref TimeoutsNs::tick reports in @ref TimeoutsIo::until_ms for an empty list. */
#define IDEMIP_TIMEOUT_FOREVER 0xFFFFFFFFu

/** @brief What arming a deadline takes. */
typedef struct
{
    uint32_t deadline_ms;    ///< the millisecond the deadline expires at
    IdemIpTimeoutUnit unit;  ///< whose tick runs the work
    uint8_t arg;             ///< index into that unit's own table
    IdemIpTimeoutFlag flags; ///< IDEMIP_TIMEOUT_FLAG_* bits the slot keeps
} TimeoutArmArgs;

/** @brief What cancelling a deadline takes, which is the pair that named it. */
typedef struct
{
    IdemIpTimeoutUnit unit;
    uint8_t arg;
} TimeoutCancelArgs;

/** @brief What a tick takes. */
typedef struct
{
    uint32_t now_ms; ///< the caller's monotonic millisecond count
} TimeoutTickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var TimeoutsIo::arm_args     the deadline, its unit, its argument index and its flags
 * @var TimeoutsIo::cancel_args  the unit and argument index a cancel names
 * @var TimeoutsIo::tick_args    the millisecond count a tick advances the list to
 * @var TimeoutsIo::status       what the call reports: OK, BUSY, or ERR
 * @var TimeoutsIo::unit         whose deadline expire took
 * @var TimeoutsIo::arg          the index into that unit's table expire took
 * @var TimeoutsIo::armed        deadlines the list holds
 * @var TimeoutsIo::deadline_ms  the millisecond the deadline expire took was set for
 * @var TimeoutsIo::until_ms     milliseconds from the last tick to the earliest deadline, 0 when one
 *                               is due and IDEMIP_TIMEOUT_FOREVER when the list is empty
 */
typedef struct
{
    TimeoutArmArgs arm_args;
    TimeoutCancelArgs cancel_args;
    TimeoutTickArgs tick_args;

    IdemIpStatus status;
    IdemIpTimeoutUnit unit;
    uint8_t arg;
    uint8_t armed;
    uint32_t deadline_ms;
    uint32_t until_ms;
} TimeoutsIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The table sits at the end of the context
// region, whose width IDEMIP_TIMEOUTS_CTX_BYTES fixes, so the operand block and the context both
// land before it and the table's own offset is a literal.

#define IDEMIP_TIMEOUTS_OFF_IO 0u ///< the operand and result block
#define IDEMIP_TIMEOUTS_OFF_CTX IDEMIP_ROUND_UP(IDEMIP_TIMEOUTS_OFF_IO + sizeof(TimeoutsIo), IDEMIP_ALIGN)
#define IDEMIP_TIMEOUTS_OFF_TAB IDEMIP_TIMEOUTS_CTX_BYTES ///< IDEMIP_TIMEOUTS slots, 1 << IDEMIP_TIMEOUT_ENTRY_SHIFT each

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_TIMEOUTS_IO(w) ((TimeoutsIo *)(void *)((w) + IDEMIP_TIMEOUTS_OFF_IO))

/**
 * @brief The deadline list.
 *
 *   Timeouts.clear(work);
 *   IDEMIP_TIMEOUTS_IO(work)->arm_args.unit = IDEMIP_TIMEOUT_UNIT_ARP;
 *   IDEMIP_TIMEOUTS_IO(work)->arm_args.arg = 0u;
 *   IDEMIP_TIMEOUTS_IO(work)->arm_args.deadline_ms = now + IDEMIP_ARP_TMR_INTERVAL_MS;
 *   Timeouts.arm(work);
 *   IDEMIP_TIMEOUTS_IO(work)->tick_args.now_ms = now;
 *   Timeouts.tick(work);
 *   while (Timeouts.expire(work), IDEMIP_TIMEOUTS_IO(work)->status == IDEMIP_OK) { ... }
 *
 * @c work is IDEMIP_TIMEOUTS_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the list, so two
 * lists are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata
 * and the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick.
 *
 * @var TimeoutsNs::clear   zero the list and mark the borrow bound. Every other entry refuses a
 *                          borrow this has not run on.
 * @var TimeoutsNs::arm     hold @ref TimeoutArmArgs::deadline_ms for its unit, replacing the
 *                          deadline already held for the same unit and argument index. BUSY when
 *                          every slot is armed.
 * @var TimeoutsNs::cancel  drop the deadline @ref TimeoutCancelArgs names. BUSY when no slot holds
 *                          it.
 * @var TimeoutsNs::tick    advance the list to @ref TimeoutTickArgs::now_ms and report
 *                          @ref TimeoutsIo::until_ms
 * @var TimeoutsNs::expire  take the earliest deadline at or before the millisecond the last tick
 *                          recorded, into @ref TimeoutsIo::unit and @ref TimeoutsIo::arg, and drop
 *                          it from the list. BUSY when none is due.
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const arm)(uint8_t *work);
    void (*const cancel)(uint8_t *work);
    void (*const tick)(uint8_t *work);
    void (*const expire)(uint8_t *work);
} TimeoutsNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_timeouts_clear(uint8_t *work);
void idemip_timeouts_arm(uint8_t *work);
void idemip_timeouts_cancel(uint8_t *work);
void idemip_timeouts_tick(uint8_t *work);
void idemip_timeouts_expire(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Timeouts.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const TimeoutsNs Timeouts IDEMIP_UNUSED = {
    .clear = idemip_timeouts_clear,
    .arm = idemip_timeouts_arm,
    .cancel = idemip_timeouts_cancel,
    .tick = idemip_timeouts_tick,
    .expire = idemip_timeouts_expire};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_TIMEOUTS_H
