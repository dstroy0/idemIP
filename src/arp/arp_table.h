// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file arp_table.h
 * @brief The RFC 826 translation table, and the frames held while a triplet is missing from it.
 *
 * RFC 826 "Why is it done this way??" on ar$sha and ar$spa: "It is these fields that get put in a
 * translation table." The table holds that triplet, <protocol type, sender protocol address, sender
 * hardware address>, one row per <ar$pro, ar$spa> pair, and RFC 1122 sec 2.3.2.1 ages it.
 *
 * A frame with no translation is not dropped here: RFC 826 "Packet Generation" has the resolver
 * "informs the caller that it is throwing the packet away (on the assumption the packet will be
 * retransmitted by a higher network layer)", and this unit instead holds the frame's receive
 * descriptor pinned until the REPLY lands or its deadline passes.
 *
 * The descriptor rings are dma.h's borrow, not this one, so the pin is the caller's: it pins through
 * Dma.pin before queue and unpins every descriptor dequeue or tick hands back. Each descriptor queue
 * took comes back exactly once, through dequeue when its address resolves or through tick when its
 * deadline passes, its row is flushed, or its row ages out, and IDEMIP_ARP_PENDING of them are
 * outstanding at most, which is what IDEMIP_MAX_PINNED_FRAMES counts for this unit.
 *
 * The ARP packet itself is arp.h's. arp.h's IDEMIP_ARP_OFF_* name fields inside a packet; the
 * IDEMIP_ARP_OFF_* below name regions inside the caller's borrow.
 */

#ifndef IDEMIP_ARP_TABLE_H
#define IDEMIP_ARP_TABLE_H

#include "src/arp/arp.h"

#if IDEMIP_ENABLE_IPV4

IDEMIP_BEGIN_DECLS

/**
 * @brief What one row of the translation table is.
 *
 * RFC 826 names no state. It names one table operation, merging a triplet, and one reason a row can
 * be short of a hardware address: "It does not set ar$tha to anything in particular, because it is
 * this value that it is trying to determine." A row is therefore absent, waiting for the REPLY that
 * carries ar$sha, or complete. lwIP etharp.c spells the same three ETHARP_STATE_EMPTY, _PENDING and
 * _STABLE.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_ARP_STATE_FREE = 0, ///< no triplet in this row
    IDEMIP_ARP_STATE_PENDING,  ///< ar$spa is known, ar$sha is not, and a REQUEST is out for it
    IDEMIP_ARP_STATE_STABLE,   ///< the whole triplet is in the row
} IdemIpArpState;

/** @brief No row and no list link. Every index result and every list terminator reads this. */
#define IDEMIP_ARP_INDEX_NONE 0xFFu

/**
 * @brief What add takes: the RFC 826 triplet, and the interface it was seen on.
 *
 * RFC 826 "Packet Reception": "add the triplet <protocol type, sender protocol address, sender
 * hardware address> to the translation table."
 */
typedef struct
{
    uint32_t spa;       ///< ar$spa, the sender protocol address
    const uint8_t *sha; ///< ar$sha, IDEMIP_ARP_HLN_ETHERNET bytes
    uint16_t pro;       ///< ar$pro, the protocol address space the pair is keyed in
    uint8_t netif;      ///< the interface index the packet arrived on
} ArpAddArgs;

/** @brief What find takes: the <protocol type, protocol address> pair RFC 826 keys the table on. */
typedef struct
{
    uint32_t spa;
    uint16_t pro;
} ArpFindArgs;

/**
 * @brief What remove takes.
 *
 * RFC 1122 sec 2.3.2.1 lists "Link-Layer Advice -- If the link-layer driver detects a delivery
 * problem, flush the corresponding ARP cache entry" and the higher-layer form of the same call.
 */
typedef struct
{
    uint32_t spa;
    uint16_t pro;
} ArpRemoveArgs;

/**
 * @brief What input takes: a received ARP payload, and this end's protocol address.
 *
 * RFC 826 "Packet Reception" asks "?Am I the target protocol address?", so the local address is an
 * operand of the reception algorithm rather than state this unit keeps.
 */
typedef struct
{
    const uint8_t *packet; ///< IDEMIP_ARP_LEN bytes, the payload behind the Ethernet header
    uint32_t local_pa;     ///< this end's protocol address, what ar$tpa is tested against
    uint8_t netif;         ///< the interface index the packet arrived on
} ArpInputArgs;

/**
 * @brief What queue takes: a pinned receive descriptor to hold until @c ip resolves.
 *
 * The frame octets stay in the buffer the DMA engine wrote them to, so what is held is the
 * descriptor index, never a copy and never a pointer into a buffer the engine may recycle.
 */
typedef struct
{
    uint32_t ip;   ///< the protocol address being resolved
    uint16_t desc; ///< the pinned receive descriptor
    uint16_t len;  ///< octets of frame in it
} ArpQueueArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var ArpTableIo::add_args     the triplet add merges
 * @var ArpTableIo::find_args    the pair find looks up
 * @var ArpTableIo::remove_args  the pair remove drops
 * @var ArpTableIo::input_args   the received packet and this end's protocol address
 * @var ArpTableIo::queue_args   the descriptor queue holds
 * @var ArpTableIo::now_ms       the millisecond clock the caller read before the call. Every
 *                               deadline this unit stamps and every age it compares comes from it,
 *                               so no entry reads a clock of its own.
 * @var ArpTableIo::status       what the call reports: OK, BUSY, or ERR
 * @var ArpTableIo::mac          ar$sha of the row find matched or dequeue released a hold from,
 *                               IDEMIP_ARP_HLN_ETHERNET bytes in the table region of this borrow
 * @var ArpTableIo::ip           the protocol address a REQUEST is due for, or the one a released
 *                               hold was waiting on
 * @var ArpTableIo::desc         the pinned descriptor dequeue or tick hands back
 * @var ArpTableIo::len          octets of frame in it, never zero, so a tick report carrying a
 *                               nonzero len is a descriptor to hand back and one carrying zero is an
 *                               address a REQUEST is due for
 * @var ArpTableIo::index        the row add, find or input touched, or IDEMIP_ARP_INDEX_NONE
 * @var ArpTableIo::state        that row's state
 * @var ArpTableIo::netif        the interface that row's triplet was seen on
 * @var ArpTableIo::merged       RFC 826 "Packet Reception" Merge_flag: the pair was already in the
 *                               table and its hardware address was updated
 * @var ArpTableIo::reply_owed   the packet was a REQUEST for this end's protocol address, so RFC 826
 *                               "Packet Reception" owes a REPLY on the interface it arrived on
 * @var ArpTableIo::conflict     RFC 5227 sec 2.4: the packet's sender IP address is this end's own,
 *                               which is a conflicting ARP packet. No row is keyed on it and no
 *                               REPLY is owed for it; the caller answers it through sec 2.4's (a),
 *                               (b) or (c), which is what src/acd implements
 */
typedef struct
{
    ArpAddArgs add_args;
    ArpFindArgs find_args;
    ArpRemoveArgs remove_args;
    ArpInputArgs input_args;
    ArpQueueArgs queue_args;

    uint32_t now_ms;

    const uint8_t *mac;
    uint32_t ip;
    uint16_t desc;
    uint16_t len;
    IdemIpStatus status;
    IdemIpArpState state;
    uint8_t index;
    uint8_t netif;
    idemip_bool merged;
    idemip_bool reply_owed;
    idemip_bool conflict;
} ArpTableIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. IDEMIP_ARP_CTX_BYTES covers everything
// outside the two tables, which is the operand block and this module's private context.

/** @brief The operand and result block. */
#define IDEMIP_ARP_OFF_IO 0u

/** @brief The private context, right behind the operand block. */
#define IDEMIP_ARP_OFF_CTX (IDEMIP_ARP_OFF_IO + sizeof(ArpTableIo))

/** @brief IDEMIP_ARP_ENTRIES rows, one RFC 826 triplet each, at the end of the head region. */
#define IDEMIP_ARP_OFF_TAB IDEMIP_ARP_CTX_BYTES

/** @brief IDEMIP_ARP_PENDING holds, one pinned receive descriptor each. */
#define IDEMIP_ARP_OFF_PENDING (IDEMIP_ARP_OFF_TAB + (IDEMIP_ARP_ENTRIES << IDEMIP_ARP_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_ARP_IO(w) ((ArpTableIo *)(void *)((w) + IDEMIP_ARP_OFF_IO))

// A row index and a list link are one octet, so a count at or above the terminator is unaddressable.
static_assert(IDEMIP_ARP_ENTRIES < IDEMIP_ARP_INDEX_NONE,
              "IDEMIP_ARP_ENTRIES must stay below IDEMIP_ARP_INDEX_NONE: a row index is one octet");
static_assert(IDEMIP_ARP_PENDING < IDEMIP_ARP_INDEX_NONE,
              "IDEMIP_ARP_PENDING must stay below IDEMIP_ARP_INDEX_NONE: a list link is one octet");

/**
 * @brief The translation table.
 *
 *   ArpTable.clear(work);
 *   IDEMIP_ARP_IO(work)->now_ms = tick_ms;
 *   IDEMIP_ARP_IO(work)->add_args.pro = IDEMIP_ARP_PRO_IPV4;
 *   IDEMIP_ARP_IO(work)->add_args.spa = spa;
 *   IDEMIP_ARP_IO(work)->add_args.sha = idemip_arp_sha(packet);
 *   ArpTable.add(work);
 *
 * @c work is IDEMIP_ARP_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the table, so two
 * tables are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick. A borrow that clear has not run on is refused: a zeroed borrow
 * reads every list link as row zero rather than as IDEMIP_ARP_INDEX_NONE.
 *
 * @var ArpTableNs::clear    zero the context and both tables, and mark the borrow usable
 * @var ArpTableNs::add      merge one RFC 826 triplet, replacing the hardware address of a row that
 *                           already holds the pair. BUSY when every row carries pinned holds, since a
 *                           hold's deadline frees one.
 * @var ArpTableNs::find     the hardware address behind a pair, into @ref ArpTableIo::mac. BUSY
 *                           while the row is IDEMIP_ARP_PENDING, so the caller comes back rather
 *                           than treating an unresolved address as absent. ERR when no row holds the
 *                           pair: calling find again cannot put one there, so the caller queues the
 *                           frame, which opens the row and starts the REQUESTs.
 * @var ArpTableNs::remove   drop the row holding a pair. Whatever it held becomes reclaimable, so
 *                           tick hands each pinned descriptor back.
 * @var ArpTableNs::input    the RFC 826 "Packet Reception" algorithm over one received payload: the
 *                           merge, then the target test, then the opcode
 * @var ArpTableNs::queue    hold a pinned descriptor until its address resolves. BUSY when every
 *                           hold is taken. ERR when the address is already resolved, because the
 *                           frame goes out now and a hold on it would pin a descriptor for nothing.
 * @var ArpTableNs::dequeue  the next held descriptor whose row went IDEMIP_ARP_STABLE, for
 *                           transmission, oldest hold on that row first, with @ref ArpTableIo::mac
 *                           the hardware address to send it to. BUSY when nothing is resolved.
 * @var ArpTableNs::tick     age rows past IDEMIP_ARP_MAXAGE_S and IDEMIP_ARP_PENDING rows past
 *                           IDEMIP_ARP_MAXPENDING_S, expire holds past their deadline, and report the
 *                           address a REQUEST is due for. One report per call, so a caller loops
 *                           until BUSY. The row sweep runs once per IDEMIP_ARP_TMR_INTERVAL_MS, which
 *                           is the granularity of both row bounds; the holds and the REQUESTs are
 *                           looked at on every call. BUSY when the sweep found nothing to report.
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const add)(uint8_t *restrict work);
    void (*const find)(uint8_t *restrict work);
    void (*const remove)(uint8_t *restrict work);
    void (*const input)(uint8_t *restrict work);
    void (*const queue)(uint8_t *restrict work);
    void (*const dequeue)(uint8_t *restrict work);
    void (*const tick)(uint8_t *restrict work);
} ArpTableNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_arp_clear(uint8_t *restrict work);
void idemip_arp_add(uint8_t *restrict work);
void idemip_arp_find(uint8_t *restrict work);
void idemip_arp_remove(uint8_t *restrict work);
void idemip_arp_input(uint8_t *restrict work);
void idemip_arp_queue(uint8_t *restrict work);
void idemip_arp_dequeue(uint8_t *restrict work);
void idemip_arp_tick(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `ArpTable.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const ArpTableNs ArpTable IDEMIP_UNUSED = {
    .clear = idemip_arp_clear,
    .add = idemip_arp_add,
    .find = idemip_arp_find,
    .remove = idemip_arp_remove,
    .input = idemip_arp_input,
    .queue = idemip_arp_queue,
    .dequeue = idemip_arp_dequeue,
    .tick = idemip_arp_tick};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4

#endif // IDEMIP_ARP_TABLE_H
