// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file arp_table.c
 * @brief The rows of the RFC 826 translation table, and the holds waiting on them.
 *
 * The row and hold types are this file's. Every entry is a function of the one pointer it is handed:
 * the operand block, the context and both tables are regions of that borrow, at compile-time
 * offsets, and no entry reads or writes a byte outside it.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV4

#include "idemIP/arp/arp_table.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and every
// entry refuses it, because a zeroed borrow reads each list link as row zero and not as
// IDEMIP_ARP_INDEX_NONE.
#define ARP_READY 0x41525054u

// One row: the RFC 826 triplet <ar$pro, ar$spa, ar$sha>, the interface it was seen on, the head of
// the holds waiting on it, and the two millisecond stamps RFC 1122 sec 2.3.2.1 ages and rate limits
// by. Padded to 1 << IDEMIP_ARP_ENTRY_SHIFT so row i sits at (i << IDEMIP_ARP_ENTRY_SHIFT).
typedef struct
{
    uint32_t spa;
    uint32_t used_ms;
    uint32_t req_ms;
    uint16_t pro;
    uint8_t sha[IDEMIP_ARP_HLN_ETHERNET];
    uint8_t state;
    uint8_t netif;
    uint8_t pending;
    uint8_t tries;
    uint8_t reserved[8];
} ArpEntry;

// One hold: the pinned receive descriptor, its frame length, the row it waits on, its deadline, and
// the next hold on that row. Padded to 1 << IDEMIP_ARP_PENDING_ENTRY_SHIFT.
typedef struct
{
    uint32_t deadline_ms;
    uint16_t desc;
    uint16_t len;
    uint8_t entry;
    uint8_t next;
    uint8_t state;
    uint8_t reserved[5];
} ArpPending;

// The context: the mark, the millisecond of the last sweep, and how many descriptors are held.
typedef struct
{
    uint32_t ready;
    uint32_t tick_ms;
    uint8_t held;
    uint8_t reserved[3];
} ArpCtx;

// Row i is at (i << SHIFT), so the width has to be exactly the shift.
static_assert(sizeof(ArpEntry) == (1u << IDEMIP_ARP_ENTRY_SHIFT),
              "an ArpEntry must be exactly 1 << IDEMIP_ARP_ENTRY_SHIFT wide - pad it, or raise the shift");
static_assert(sizeof(ArpPending) == (1u << IDEMIP_ARP_PENDING_ENTRY_SHIFT),
              "an ArpPending must be exactly 1 << IDEMIP_ARP_PENDING_ENTRY_SHIFT wide - pad it, or raise the shift");

// The head region carries the operand block and the context, both outside either table.
static_assert(IDEMIP_ARP_OFF_CTX + sizeof(ArpCtx) <= IDEMIP_ARP_CTX_BYTES,
              "IDEMIP_ARP_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");

// The caller's borrow, split: the head region, then the rows, then the holds. arp_table.h publishes
// the offsets; the assert proves the span covers them before anything runs.
static_assert(IDEMIP_ARP_OFF_PENDING + (IDEMIP_ARP_PENDING << IDEMIP_ARP_PENDING_ENTRY_SHIFT) <= IDEMIP_ARP_BORROW,
              "IDEMIP_ARP_BORROW is short of the head region and both tables - raise it in idemip_config.h");

// clear zeroes both tables, so the empty row and the empty hold are the zero state.
static_assert(IDEMIP_ARP_STATE_FREE == 0, "IDEMIP_ARP_STATE_FREE must be zero: clear zeroes the tables");

// The regions, at their offsets in the caller's borrow.
#define ARP_IO(w) IDEMIP_ARP_IO(w)
#define ARP_CTX(w) ((ArpCtx *)(void *)((w) + IDEMIP_ARP_OFF_CTX))
#define ARP_AT(w, i) ((ArpEntry *)(void *)((w) + IDEMIP_ARP_OFF_TAB + ((size_t)(i) << IDEMIP_ARP_ENTRY_SHIFT)))
#define ARP_PENDING_AT(w, i)                                                                                           \
    ((ArpPending *)(void *)((w) + IDEMIP_ARP_OFF_PENDING + ((size_t)(i) << IDEMIP_ARP_PENDING_ENTRY_SHIFT)))

// A borrow clear has not run on holds no list terminator, so every entry but clear refuses it.
static idemip_bool arp_ready(uint8_t *restrict work)
{
    return (idemip_bool)(ARP_CTX(work)->ready == ARP_READY);
}

// --- the entries -----------------------------------------------------------

// The context and both tables, zeroed, then the mark. The operand block is the caller's and is left
// as it stands.
static void arp_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_ARP_OFF_CTX, 0, (size_t)IDEMIP_ARP_BORROW - (size_t)IDEMIP_ARP_OFF_CTX);
    ARP_CTX(work)->ready = ARP_READY;
    ARP_IO(work)->status = IDEMIP_OK;
}

static void arp_add(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_ARP_INDEX_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 826 "Packet Reception", merging the <ar$pro, ar$spa, ar$sha> triplet into the table.
    io->status = IDEMIP_ERR;
}

static void arp_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->mac = NULL;
    io->index = (uint8_t)IDEMIP_ARP_INDEX_NONE;
    io->state = IDEMIP_ARP_STATE_FREE;
    io->netif = 0;
    if (!arp_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 826 "Packet Generation", the <protocol type, target protocol address> pair found in the table.
    io->status = IDEMIP_ERR;
}

static void arp_remove(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_ARP_INDEX_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 2.3.2.1, flushing an out-of-date cache entry on link-layer or higher-layer advice.
    io->status = IDEMIP_ERR;
}

static void arp_input(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->merged = IDEMIP_FALSE;
    io->reply_owed = IDEMIP_FALSE;
    io->index = (uint8_t)IDEMIP_ARP_INDEX_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 826 "Packet Reception", Merge_flag then "?Am I the target protocol address?" then the opcode.
    io->status = IDEMIP_ERR;
}

static void arp_queue(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_ARP_INDEX_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 826 "Packet Generation", holding the frame whose <ar$pro, ar$tpa> pair is not in the table.
    io->status = IDEMIP_ERR;
}

static void arp_dequeue(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->desc = 0;
    io->len = 0;
    io->index = (uint8_t)IDEMIP_ARP_INDEX_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 826 "Packet Generation", releasing a held frame once the table carries its triplet.
    io->status = IDEMIP_ERR;
}

static void arp_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->ip = 0;
    io->desc = 0;
    io->len = 0;
    io->index = (uint8_t)IDEMIP_ARP_INDEX_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 2.3.2.1, the IDEMIP_ARP_MAXAGE_S timeout and the one REQUEST per second flood limit.
    io->status = IDEMIP_ERR;
}

const ArpTableNs ArpTable = {.clear = arp_clear,
                             .add = arp_add,
                             .find = arp_find,
                             .remove = arp_remove,
                             .input = arp_input,
                             .queue = arp_queue,
                             .dequeue = arp_dequeue,
                             .tick = arp_tick};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4
