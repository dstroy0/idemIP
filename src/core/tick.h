// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tick.h
 * @brief The scheduler: the only thing in this tree that decides what runs when.
 *
 * Nothing here blocks, so something has to drive progress, and this is it. PLAN.md sec 3.4b fixes the
 * order and it is not a preference: a later phase consumes what an earlier one produced.
 *
 *   1. DRAIN   take frames off the receive rings while one reports OK, dispatching each and either
 *              releasing its descriptor or leaving it where a unit pinned it
 *   2. SERVICE run each service's own tick, in dependency order: the resolvers (ARP, ND) before the
 *              queues that wait on resolution, reassembly before the protocols that read a completed
 *              datagram
 *   3. FLUSH   hand back what the services released, and send what an earlier tick deferred
 *
 * The order is enforced rather than described. The context holds the phase, @ref TickNs::open puts it
 * at DRAIN, and each phase entry advances it when it reports IDEMIP_BUSY. An entry called out of its
 * phase is IDEMIP_ERR, so a caller cannot silently run the services before the ring is drained.
 *
 * Deadlines are absolute milliseconds and the count wraps at 2^32, so every comparison here and in
 * the units this drives is the difference of two counts and never a plain less-than.
 *
 * A descriptor a flush step reports stays pinned until the step after it, so the caller reads the
 * frame between the two calls. The last call of the phase, the one reporting BUSY, drops the last
 * pin.
 */

#ifndef IDEMIP_TICK_H
#define IDEMIP_TICK_H

#include "src/core/dispatch.h"
#include "src/core/timeouts.h"

#if IDEMIP_ENABLE_IPV6
#include "src/nd/nd6.h"
#endif

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/**
 * @brief Which phase of the fixed order the tick has reached.
 *
 * @var IDEMIP_TICK_PHASE_IDLE    no tick is open; only @ref TickNs::open is accepted
 * @var IDEMIP_TICK_PHASE_DRAIN   receive, until the rings report nothing waiting
 * @var IDEMIP_TICK_PHASE_SERVICE each service's own tick, in dependency order
 * @var IDEMIP_TICK_PHASE_FLUSH   the deferred work the services released
 * @var IDEMIP_TICK_PHASE_DONE    the tick is through; the next @ref TickNs::open starts another
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_TICK_PHASE_IDLE = 0,
    IDEMIP_TICK_PHASE_DRAIN,
    IDEMIP_TICK_PHASE_SERVICE,
    IDEMIP_TICK_PHASE_FLUSH,
    IDEMIP_TICK_PHASE_DONE,
} IdemIpTickPhase;

/**
 * @brief Which unit a service or flush step ran, so a caller can see the order it ran them in.
 *
 * The order of the constants IS the order of the phase, which is what makes the dependency claim
 * readable: a resolver runs before the queue that waits on it, and a reassembler before whatever
 * reads a completed datagram.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_TICK_UNIT_NONE = 0,
    IDEMIP_TICK_UNIT_ARP,       ///< RFC 826 resolution, before the queues that wait on it
    IDEMIP_TICK_UNIT_ND6,       ///< RFC 4861 sec 7.3 resolution, per interface, for the same reason
    IDEMIP_TICK_UNIT_IP4_REASS, ///< RFC 791 sec 3.2, before the protocols that read a datagram
    IDEMIP_TICK_UNIT_IP6_REASS, ///< RFC 8200 sec 4.5
    IDEMIP_TICK_UNIT_IGMP,      ///< RFC 2236 report delays
    IDEMIP_TICK_UNIT_MLD6,      ///< RFC 2710 report delays
    IDEMIP_TICK_UNIT_NETIF,     ///< RFC 4862 sec 5.5.4 address lifetimes
    IDEMIP_TICK_UNIT_TIMEOUTS,  ///< the deadline list, whose expiries name the units above and below
    IDEMIP_TICK_UNIT_ARP_HOLD,  ///< a frame ARP held until resolution finished
    IDEMIP_TICK_UNIT_IP4_RECLAIM, ///< a descriptor IPv4 reassembly is done with
    IDEMIP_TICK_UNIT_IP6_DROP,    ///< a datagram IPv6 reassembly gave up, and the descriptors it held
    IDEMIP_TICK_UNIT_TCP_ACK,     ///< the aggregate acknowledgment of RFC 9293 sec 3.10.7.4 MUST-58
    IDEMIP_TICK_UNIT_COUNT,       ///< one past the last, so a cursor is bounded by a constant
} IdemIpTickUnit;

/**
 * @brief The borrows the scheduler drives, each the caller's own.
 *
 * A null one is not a fault: the step that would have run it is skipped, so a build without a
 * resolver or a group table still ticks everything else.
 *
 * @var TickBindArgs::dispatch  the receive path, which the drain phase hands each frame to
 * @var TickBindArgs::timeouts  the deadline list every service registers into
 * @var TickBindArgs::stats     the RFC 1213 counters, for the drops the drain phase accounts
 * @var TickBindArgs::arp       the RFC 826 table, whose tick ages rows and whose dequeue releases
 *                              the frames held for resolution
 * @var TickBindArgs::ip4_reass the RFC 791 sec 3.2 reassembler
 * @var TickBindArgs::igmp      the RFC 2236 group table
 * @var TickBindArgs::ip6_reass the RFC 8200 sec 4.5 reassembler
 * @var TickBindArgs::mld6      the RFC 2710 group table
 * @var TickBindArgs::netif     the interface table, whose tick ages the RFC 4862 sec 5.5.4 lifetimes
 */
typedef struct
{
    uint8_t *dispatch;
    uint8_t *timeouts;
    uint8_t *stats;
#if IDEMIP_ENABLE_IPV4
    uint8_t *arp;
    uint8_t *ip4_reass;
    uint8_t *igmp;
#endif
#if IDEMIP_ENABLE_IPV6
    uint8_t *ip6_reass;
    uint8_t *mld6;
#endif
    uint8_t *netif;
} TickBindArgs;

/**
 * @brief What one interface's row takes.
 *
 * @var TickIfArgs::dma   the IDEMIP_DMA_BORROW bytes this interface's rings run in, which the drain
 *                        phase takes frames from. Null on an interface with no rings.
 * @var TickIfArgs::nd6   the IDEMIP_ND6_BORROW bytes this interface's neighbor machine runs in,
 *                        RFC 4861 sec 5.1 keeping those structures per interface
 * @var TickIfArgs::out   a transmit buffer the receive path builds replies into, @c out_cap octets
 * @var TickIfArgs::out_cap octets available at @c out
 * @var TickIfArgs::index which interface
 */
typedef struct
{
    uint8_t *dma;
#if IDEMIP_ENABLE_IPV6
    uint8_t *nd6;
#endif
    uint8_t *out;
    size_t out_cap;
    uint8_t index;
} TickIfArgs;

/** @brief What opening a tick takes. */
typedef struct
{
    uint32_t now_ms; ///< the caller's monotonic millisecond count
} TickOpenArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var TickIo::bind_args  the borrows the scheduler drives
 * @var TickIo::if_args    one interface's rings, neighbor machine and transmit buffer
 * @var TickIo::open_args  the millisecond a tick is opened at
 * @var TickIo::status     what the call reports: OK, BUSY, or ERR
 * @var TickIo::phase      the phase the fixed order has reached
 * @var TickIo::unit       which unit the step just run belongs to
 * @var TickIo::netif      the interface it worked on, IDEMIP_DISPATCH_NETIF_NONE for a shared unit
 * @var TickIo::desc       the receive descriptor a flush step handed back, which stays pinned until
 *                         the step after this one
 * @var TickIo::len        octets of frame in it
 * @var TickIo::ip         the protocol address a released hold was waiting on
 * @var TickIo::until_ms   milliseconds from the millisecond this tick opened at to the earliest
 *                         deadline, 0 when one is due and IDEMIP_TIMEOUT_FOREVER when none is armed
 * @var TickIo::timeout_unit the unit an expired deadline named, for the services this does not drive
 * @var TickIo::timeout_arg  the index into that unit's own table
 * @var TickIo::frames     frames the drain phase dispatched this tick
 * @var TickIo::steps      steps the service phase ran this tick
 * @var TickIo::reasm_timeout the step reports a reassembly row the clock reached, not one a caller
 *                         released. RFC 1122 sec 3.3.2: "If this timeout expires, the
 *                         partially-reassembled datagram MUST be discarded and an ICMP Time Exceeded
 *                         message sent to the source host (if fragment zero has been received)", and
 *                         RFC 8200 sec 4.5: "If the first fragment (i.e., the one with a Fragment
 *                         Offset of zero) has been received, an ICMP Time Exceeded -- Fragment
 *                         Reassembly Time Exceeded message should be sent to the source of that
 *                         fragment." @ref TickIo::desc is that fragment and stays pinned for this one
 *                         step, so the header it carries is readable while the message is built.
 * @var TickIo::reasm_frag_zero the offset-zero fragment was among the ones the row held, which is the
 *                         condition both sections put the message behind
 * @var TickIo::reasm_src  the RFC 791 sec 3.1 Source Address of the timed-out IPv4 row, host order,
 *                         which is the destination of the ICMP Time Exceeded. Zero on the IPv6 path,
 *                         where the address is the sixteen octets @ref TickIo::desc carries.
 */
typedef struct
{
    TickBindArgs bind_args;
    TickIfArgs if_args;
    TickOpenArgs open_args;

    IdemIpStatus status;
    IdemIpTickPhase phase;
    IdemIpTickUnit unit;
    IdemIpTimeoutUnit timeout_unit;
    uint8_t timeout_arg;
    uint8_t netif;
    uint16_t desc;
    uint16_t len;
    uint32_t ip;
    uint32_t until_ms;
    uint16_t frames;
    uint16_t steps;
    uint32_t reasm_src;
    idemip_bool reasm_timeout;
    idemip_bool reasm_frag_zero;
} TickIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The operand block and the context share the
// IDEMIP_TICK_CTX_BYTES ahead of the table, so the table does not move when either grows.

#define IDEMIP_TICK_OFF_IO 0u ///< the operand and result block
#define IDEMIP_TICK_OFF_CTX IDEMIP_ROUND_UP(IDEMIP_TICK_OFF_IO + sizeof(TickIo), IDEMIP_ALIGN)
#define IDEMIP_TICK_OFF_IF IDEMIP_TICK_CTX_BYTES ///< IDEMIP_NETIF_COUNT interface rows
#define IDEMIP_TICK_OFF_END (IDEMIP_TICK_OFF_IF + (IDEMIP_NETIF_COUNT << IDEMIP_TICK_IF_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_TICK_IO(w) ((TickIo *)(void *)((w) + IDEMIP_TICK_OFF_IO))

/**
 * @brief The tick, and the fixed order it runs.
 *
 *   Tick.clear(work);
 *   IDEMIP_TICK_IO(work)->bind_args.dispatch = dispatch_mem;
 *   Tick.bind(work);
 *   IDEMIP_TICK_IO(work)->open_args.now_ms = now;
 *   Tick.open(work);
 *   while (Tick.drain(work), IDEMIP_TICK_IO(work)->status == IDEMIP_OK) { ... read the dispatch io }
 *   while (Tick.service(work), IDEMIP_TICK_IO(work)->status == IDEMIP_OK) { }
 *   while (Tick.flush(work), IDEMIP_TICK_IO(work)->status == IDEMIP_OK) { ... send it }
 *
 * @c work is IDEMIP_TICK_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * schedulers are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. BUSY means the phase is through and the next one may start, which is progress
 * and not a fault; ERR is a null borrow, a borrow no clear has run on, an index past the table, and
 * an entry called out of its phase, none of which a retry changes.
 *
 * @var TickNs::clear   zero the context and the table, and mark the borrow usable. Every other entry
 *                      refuses a borrow this has not run on.
 * @var TickNs::bind    take the borrows the scheduler drives
 * @var TickNs::if_bind take one interface's rings, neighbor machine and transmit buffer
 * @var TickNs::open    open a tick at @ref TickOpenArgs::now_ms, advance the deadline list to it, and
 *                      report the millisecond the earliest deadline falls due in
 * @var TickNs::drain   take one frame off a receive ring and dispatch it. BUSY once every ring is
 *                      empty, which moves the phase on.
 * @var TickNs::service run one step of one service's tick, in the dependency order above. BUSY once
 *                      the order is through.
 * @var TickNs::flush   take one piece of deferred work: a frame a resolver released, a descriptor a
 *                      reassembler is done with, or the aggregate acknowledgment a connection owes.
 *                      BUSY once nothing is left.
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const bind)(uint8_t *restrict work);
    void (*const if_bind)(uint8_t *restrict work);
    void (*const open)(uint8_t *restrict work);
    void (*const drain)(uint8_t *restrict work);
    void (*const service)(uint8_t *restrict work);
    void (*const flush)(uint8_t *restrict work);
} TickNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const TickNs Tick;

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_TICK_H
