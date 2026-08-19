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

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/arp/arp_table.h"

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

// One hold: the pinned receive descriptor, its frame length, the address it waits on, the row it
// waits on, its deadline, and the next hold on that row. Padded to
// 1 << IDEMIP_ARP_PENDING_ENTRY_SHIFT.
typedef struct
{
    uint32_t deadline_ms;
    uint32_t spa;
    uint16_t desc;
    uint16_t len;
    uint8_t entry;
    uint8_t next;
    uint8_t state;
    uint8_t reserved[1];
} ArpPending;

// The context: the mark, the millisecond of the last sweep, and how many descriptors are held.
typedef struct
{
    uint32_t ready;
    uint32_t tick_ms;
    uint8_t held;
    uint8_t reserved[3];
} ArpCtx;

// What a hold is doing. A hold off every row list still pins a descriptor, so it stays taken until
// tick hands the descriptor back.
typedef enum IDEMIP_ENUM_PACKED
{
    ARP_HOLD_FREE = 0,  ///< no descriptor in this hold
    ARP_HOLD_WAIT,      ///< linked on row ArpPending::entry, waiting for its triplet
    ARP_HOLD_RECLAIM,   ///< off every row, its descriptor waiting to be handed back
} ArpHoldState;

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
static_assert(ARP_HOLD_FREE == 0, "ARP_HOLD_FREE must be zero: clear zeroes the tables");

// A hold count is the one octet of ArpCtx::held.
static_assert(IDEMIP_ARP_PENDING <= 0xFFu, "IDEMIP_ARP_PENDING exceeds the one-octet ArpCtx::held");

// Every deadline is milliseconds (PLAN sec 5.2), and each span is compared as (now - stamp), so a
// span has to stay under half the range of the 32-bit stamp for the compare to survive a wrap.
#define ARP_MAXAGE_MS (IDEMIP_ARP_MAXAGE_S * 1000u)
#define ARP_MAXPENDING_MS (IDEMIP_ARP_MAXPENDING_S * 1000u)

// RFC 1122 sec 2.3.2.1: "A mechanism to prevent ARP flooding (repeatedly sending an ARP Request for
// the same IP address, at a high rate) MUST be included. The recommended maximum rate is 1 per
// second per destination."
#define ARP_REQUEST_MIN_MS 1000u

static_assert(ARP_MAXAGE_MS < 0x80000000u, "IDEMIP_ARP_MAXAGE_S past half the millisecond range breaks the wrap compare");
static_assert(ARP_MAXPENDING_MS < 0x80000000u,
              "IDEMIP_ARP_MAXPENDING_S past half the millisecond range breaks the wrap compare");

// The regions, at their offsets in the caller's borrow.
#define ARP_IO(w) IDEMIP_ARP_IO(w)
#define ARP_CTX(w) ((ArpCtx *)(void *)((w) + IDEMIP_ARP_OFF_CTX))
#define ARP_AT(w, i) ((ArpEntry *)(void *)((w) + IDEMIP_ARP_OFF_TAB + ((size_t)(i) << IDEMIP_ARP_ENTRY_SHIFT)))
#define ARP_PENDING_AT(w, i)                                                                                           \
    ((ArpPending *)(void *)((w) + IDEMIP_ARP_OFF_PENDING + ((size_t)(i) << IDEMIP_ARP_PENDING_ENTRY_SHIFT)))

#define ARP_NONE ((uint8_t)IDEMIP_ARP_INDEX_NONE)

// A borrow clear has not run on holds no list terminator, so every entry but clear refuses it.
static idemip_bool arp_ready(uint8_t *restrict work)
{
    return (idemip_bool)(ARP_CTX(work)->ready == ARP_READY);
}

// True when @p now_ms is at or past @p deadline_ms. The difference is read in the low half of the
// 32-bit range, so a clock that wrapped past the deadline still reads as due.
static idemip_bool arp_due(uint32_t now_ms, uint32_t deadline_ms)
{
    return (idemip_bool)((uint32_t)(now_ms - deadline_ms) < 0x80000000u);
}

// --- the statics -----------------------------------------------------------

// The row holding the RFC 826 key <ar$pro, ar$spa>, or ARP_NONE. RFC 826 "Packet Reception" keys on
// that pair alone, so a row matches whatever interface it was learned on. The walk is bounded by
// IDEMIP_ARP_ENTRIES.
static uint8_t arp_row_find(uint8_t *restrict work, uint16_t pro, uint32_t spa)
{
    for (uint8_t i = 0u; i < (uint8_t)IDEMIP_ARP_ENTRIES; i++)
    {
        ArpEntry *e = ARP_AT(work, i);
        if (e->state != (uint8_t)IDEMIP_ARP_STATE_FREE && e->pro == pro && e->spa == spa)
        {
            return i;
        }
    }
    return ARP_NONE;
}

// Every hold waiting on row @p i stops waiting and becomes reclaimable, so tick hands its pinned
// descriptor back; then the row is the zero state with a terminated list. The walk is bounded by
// IDEMIP_ARP_PENDING.
static void arp_row_free(uint8_t *restrict work, uint8_t i)
{
    ArpEntry *e = ARP_AT(work, i);
    uint8_t h = e->pending;
    for (uint8_t n = 0u; n < (uint8_t)IDEMIP_ARP_PENDING && h != ARP_NONE; n++)
    {
        ArpPending *p = ARP_PENDING_AT(work, h);
        uint8_t next = p->next;
        p->entry = ARP_NONE;
        p->next = ARP_NONE;
        p->state = (uint8_t)ARP_HOLD_RECLAIM;
        h = next;
    }
    memset(e, 0, sizeof *e);
    e->pending = ARP_NONE;
}

// A row for a triplet that is not in the table yet: a free one, else the row whose triplet has gone
// longest without being seen. A row carrying holds is never taken, because its pinned descriptors are
// handed back through tick and not through a row that vanished. ARP_NONE when every row carries holds.
//
// RFC 826 "Related issue": "if no packets are received from a host for a suitable length of time, the
// address resolution entry is forgotten."
static uint8_t arp_row_take(uint8_t *restrict work, uint32_t now_ms)
{
    for (uint8_t i = 0u; i < (uint8_t)IDEMIP_ARP_ENTRIES; i++)
    {
        if (ARP_AT(work, i)->state == (uint8_t)IDEMIP_ARP_STATE_FREE)
        {
            return i;
        }
    }
    uint8_t victim = ARP_NONE;
    uint32_t oldest = 0u;
    for (uint8_t i = 0u; i < (uint8_t)IDEMIP_ARP_ENTRIES; i++)
    {
        ArpEntry *e = ARP_AT(work, i);
        uint32_t age = (uint32_t)(now_ms - e->used_ms);
        if (e->pending == ARP_NONE && age >= oldest)
        {
            oldest = age;
            victim = i;
        }
    }
    if (victim != ARP_NONE)
    {
        arp_row_free(work, victim);
    }
    return victim;
}

// The row, keyed and stamped, with no hardware address and no holds.
static void arp_row_open(uint8_t *restrict work, uint8_t i, uint16_t pro, uint32_t spa, uint32_t now_ms)
{
    ArpEntry *e = ARP_AT(work, i);
    memset(e, 0, sizeof *e);
    e->pro = pro;
    e->spa = spa;
    e->used_ms = now_ms;
    e->pending = ARP_NONE;
}

// RFC 826 "Packet Reception": "If the pair <protocol type, sender protocol address> is already in my
// translation table, update the sender hardware address field of the entry with the new information
// in the packet and set Merge_flag to true", then "If Merge_flag is false, add the triplet".
//
// @p add_absent is that second step's condition, "?Am I the target protocol address?". False leaves a
// pair that is not in the table out of it, which is what keeps a REQUEST for a third party from
// creating a row. Reports the row, or ARP_NONE when nothing was merged and nothing was added.
static uint8_t arp_learn(uint8_t *restrict work, uint16_t pro, uint32_t spa, const uint8_t *sha, uint8_t netif,
                         uint32_t now_ms, idemip_bool add_absent, idemip_bool *merged)
{
    uint8_t i = arp_row_find(work, pro, spa);
    *merged = (idemip_bool)(i != ARP_NONE);
    if (i == ARP_NONE)
    {
        if (!add_absent)
        {
            return ARP_NONE;
        }
        i = arp_row_take(work, now_ms);
        if (i == ARP_NONE)
        {
            return ARP_NONE;
        }
        arp_row_open(work, i, pro, spa, now_ms);
    }
    ArpEntry *e = ARP_AT(work, i);
    memcpy(e->sha, sha, IDEMIP_ARP_HLN_ETHERNET);
    e->state = (uint8_t)IDEMIP_ARP_STATE_STABLE;
    e->netif = netif;
    e->used_ms = now_ms; // RFC 1122 sec 2.3.2.1: the timeout restarts when the entry is refreshed
    e->req_ms = 0u;
    e->tries = 0u;
    return i;
}

// The first hold in the zero state, or ARP_NONE. Nothing is claimed here, so a caller that cannot go
// on leaves the table as it found it.
static uint8_t arp_hold_free(uint8_t *restrict work)
{
    for (uint8_t h = 0u; h < (uint8_t)IDEMIP_ARP_PENDING; h++)
    {
        if (ARP_PENDING_AT(work, h)->state == (uint8_t)ARP_HOLD_FREE)
        {
            return h;
        }
    }
    return ARP_NONE;
}

// Hold @p h at the tail of row @p i's list, so holds come off in the order they went on. The walk is
// bounded by IDEMIP_ARP_PENDING.
static void arp_hold_link(uint8_t *restrict work, uint8_t i, uint8_t h)
{
    ArpEntry *e = ARP_AT(work, i);
    ARP_PENDING_AT(work, h)->next = ARP_NONE;
    if (e->pending == ARP_NONE)
    {
        e->pending = h;
        return;
    }
    uint8_t cur = e->pending;
    for (uint8_t n = 0u; n < (uint8_t)IDEMIP_ARP_PENDING; n++)
    {
        ArpPending *p = ARP_PENDING_AT(work, cur);
        if (p->next == ARP_NONE)
        {
            p->next = h;
            return;
        }
        cur = p->next;
    }
}

// Hold @p h off row @p i's list, the list left terminated either way. The walk is bounded by
// IDEMIP_ARP_PENDING.
static void arp_hold_unlink(uint8_t *restrict work, uint8_t i, uint8_t h)
{
    ArpEntry *e = ARP_AT(work, i);
    uint8_t cur = e->pending;
    uint8_t prev = ARP_NONE;
    for (uint8_t n = 0u; n < (uint8_t)IDEMIP_ARP_PENDING && cur != ARP_NONE; n++)
    {
        ArpPending *p = ARP_PENDING_AT(work, cur);
        if (cur == h)
        {
            if (prev == ARP_NONE)
            {
                e->pending = p->next;
            }
            else
            {
                ARP_PENDING_AT(work, prev)->next = p->next;
            }
            p->next = ARP_NONE;
            return;
        }
        prev = cur;
        cur = p->next;
    }
}

// Rows past their bound go free, their holds becoming reclaimable. A row RFC 1122 sec 2.3.2.1
// mechanism (1) timed out is one that has gone IDEMIP_ARP_MAXAGE_S without its triplet being seen;
// IDEMIP_ARP_STATE_PENDING carries the shorter IDEMIP_ARP_MAXPENDING_S, past which the REQUESTs
// stop.
static void arp_age_rows(uint8_t *restrict work, uint32_t now_ms)
{
    for (uint8_t i = 0u; i < (uint8_t)IDEMIP_ARP_ENTRIES; i++)
    {
        ArpEntry *e = ARP_AT(work, i);
        if (e->state == (uint8_t)IDEMIP_ARP_STATE_FREE)
        {
            continue;
        }
        uint32_t age = (uint32_t)(now_ms - e->used_ms);
        uint32_t bound = (e->state == (uint8_t)IDEMIP_ARP_STATE_PENDING) ? ARP_MAXPENDING_MS : ARP_MAXAGE_MS;
        if (age >= bound)
        {
            arp_row_free(work, i);
        }
    }
}

// Holds past their deadline stop waiting and become reclaimable, their descriptors still pinned.
static void arp_expire_holds(uint8_t *restrict work, uint32_t now_ms)
{
    for (uint8_t h = 0u; h < (uint8_t)IDEMIP_ARP_PENDING; h++)
    {
        ArpPending *p = ARP_PENDING_AT(work, h);
        if (p->state != (uint8_t)ARP_HOLD_WAIT || !arp_due(now_ms, p->deadline_ms))
        {
            continue;
        }
        if (p->entry != ARP_NONE)
        {
            arp_hold_unlink(work, p->entry, h);
        }
        p->entry = ARP_NONE;
        p->state = (uint8_t)ARP_HOLD_RECLAIM;
    }
}

// One reclaimable hold's descriptor, into the operand block, and the hold goes free. len is the
// octets of a frame, never zero, so it is what tells a handed-back descriptor from a REQUEST report.
static idemip_bool arp_report_reclaim(uint8_t *restrict work)
{
    ArpTableIo *io = ARP_IO(work);
    for (uint8_t h = 0u; h < (uint8_t)IDEMIP_ARP_PENDING; h++)
    {
        ArpPending *p = ARP_PENDING_AT(work, h);
        if (p->state != (uint8_t)ARP_HOLD_RECLAIM)
        {
            continue;
        }
        io->desc = p->desc;
        io->len = p->len;
        io->ip = p->spa;
        memset(p, 0, sizeof *p);
        if (ARP_CTX(work)->held != 0u)
        {
            ARP_CTX(work)->held--;
        }
        return IDEMIP_TRUE;
    }
    return IDEMIP_FALSE;
}

// The address of one row a REQUEST is due for, into the operand block. RFC 1122 sec 2.3.2.1 holds the
// rate to one per second per destination, so a row that has had one inside ARP_REQUEST_MIN_MS is
// passed over; a row that has had none is due at once.
static idemip_bool arp_report_request(uint8_t *restrict work, uint32_t now_ms)
{
    ArpTableIo *io = ARP_IO(work);
    for (uint8_t i = 0u; i < (uint8_t)IDEMIP_ARP_ENTRIES; i++)
    {
        ArpEntry *e = ARP_AT(work, i);
        if (e->state != (uint8_t)IDEMIP_ARP_STATE_PENDING)
        {
            continue;
        }
        if (e->tries != 0u && (uint32_t)(now_ms - e->req_ms) < ARP_REQUEST_MIN_MS)
        {
            continue;
        }
        e->req_ms = now_ms;
        if (e->tries != 0xFFu)
        {
            e->tries++;
        }
        io->ip = e->spa;
        io->index = i;
        io->state = IDEMIP_ARP_STATE_PENDING;
        io->netif = e->netif;
        return IDEMIP_TRUE;
    }
    return IDEMIP_FALSE;
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

// RFC 826 "Packet Reception", the merge and the add over one triplet the caller already trusts. A
// full table whose every row carries pinned holds is BUSY, because a hold's deadline frees one; a
// triplet this end cannot key is ERR, because no retry changes the operands.
static void arp_add(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = ARP_NONE;
    io->merged = IDEMIP_FALSE;
    if (!arp_ready(work))
    {
        return;
    }
    // RFC 826 "?Do I speak the protocol in ar$pro?": this end speaks IPv4, and a row keyed on
    // {0,0} names no host (RFC 1122 sec 3.2.1.3 (a)).
    if (io->add_args.sha == NULL || io->add_args.pro != (uint16_t)IDEMIP_ARP_PRO_IPV4 || io->add_args.spa == 0u)
    {
        return;
    }
    idemip_bool merged = IDEMIP_FALSE;
    uint8_t i = arp_learn(work, io->add_args.pro, io->add_args.spa, io->add_args.sha, io->add_args.netif, io->now_ms,
                          IDEMIP_TRUE, &merged);
    if (i == ARP_NONE)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    io->index = i;
    io->state = IDEMIP_ARP_STATE_STABLE;
    io->netif = ARP_AT(work, i)->netif;
    io->merged = merged;
    io->status = IDEMIP_OK;
}

// RFC 826 "Packet Generation": "The Address Resolution module tries to find this pair in a table. If
// it finds the pair, it gives the corresponding 48.bit Ethernet address back to the caller."
//
// A row still waiting for ar$sha is BUSY: the REPLY that completes it can land on a later tick. A
// pair with no row at all is ERR, because calling find again cannot put one there - the caller has to
// queue the frame, which opens the row and starts the REQUESTs. The timeout is not restarted here:
// RFC 1122 sec 2.3.2.1 mechanism (1) times an entry out "even if they are in use", and restarts only
// on observing the peer's own ARP.
static void arp_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->mac = NULL;
    io->index = ARP_NONE;
    io->state = IDEMIP_ARP_STATE_FREE;
    io->netif = 0;
    if (!arp_ready(work))
    {
        return;
    }
    if (io->find_args.pro != (uint16_t)IDEMIP_ARP_PRO_IPV4 || io->find_args.spa == 0u)
    {
        return;
    }
    uint8_t i = arp_row_find(work, io->find_args.pro, io->find_args.spa);
    if (i == ARP_NONE)
    {
        return;
    }
    ArpEntry *e = ARP_AT(work, i);
    io->index = i;
    io->state = (IdemIpArpState)e->state;
    io->netif = e->netif;
    if (e->state == (uint8_t)IDEMIP_ARP_STATE_PENDING)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    io->mac = e->sha;
    io->status = IDEMIP_OK;
}

// RFC 1122 sec 2.3.2.1 mechanisms (3) and (4), the link-layer and higher-layer flush. The row goes,
// and whatever it held becomes reclaimable so tick hands each pinned descriptor back. A pair with no
// row is ERR: there is nothing to flush and no retry puts one there.
static void arp_remove(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = ARP_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    if (io->remove_args.pro != (uint16_t)IDEMIP_ARP_PRO_IPV4 || io->remove_args.spa == 0u)
    {
        return;
    }
    uint8_t i = arp_row_find(work, io->remove_args.pro, io->remove_args.spa);
    if (i == ARP_NONE)
    {
        return;
    }
    io->index = i;
    io->state = IDEMIP_ARP_STATE_FREE;
    arp_row_free(work, i);
    io->status = IDEMIP_OK;
}

// RFC 826 "Packet Reception", in the order it states: the merge, then "?Am I the target protocol
// address?", then "(NOW look at the opcode!!)".
//
// The merge runs whoever the packet was for, and the add runs only for a packet whose ar$tpa is this
// end's, so a REQUEST between two other stations updates a row this end already has and creates
// none. A packet that is not the <Ethernet, IPv4> pairing is ERR: RFC 826 ends processing on a
// negative conditional, and the same octets stay the same pairing on a retry.
//
// A triplet that found no row reads as index IDEMIP_ARP_INDEX_NONE with merged false, and the call is
// still OK: the REPLY the packet may owe does not depend on the table, so reporting BUSY here would
// have the caller run the same packet again and answer it twice.
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
    io->index = ARP_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    const uint8_t *packet = io->input_args.packet;
    if (packet == NULL)
    {
        return;
    }
    // "?Do I have the hardware type in ar$hrd?", "?Do I speak the protocol in ar$pro?", and both
    // length checks the same paragraph offers.
    if (!idemip_arp_is_ethernet_ipv4(packet))
    {
        return;
    }
    // "?Am I the target protocol address?" RFC 1122 sec 3.2.1.3 (a) makes {0,0} no host's address,
    // so an end without one is the target of nothing.
    uint32_t local_pa = io->input_args.local_pa;
    idemip_bool target = (idemip_bool)(local_pa != 0u && idemip_arp_is_target(packet, local_pa));
    uint32_t spa = idemip_arp_spa(packet);
    if (spa != 0u)
    {
        idemip_bool merged = IDEMIP_FALSE;
        uint8_t i = arp_learn(work, idemip_arp_pro(packet), spa, idemip_arp_sha(packet), io->input_args.netif,
                              io->now_ms, target, &merged);
        io->merged = merged;
        io->index = i;
        if (i != ARP_NONE)
        {
            io->state = IDEMIP_ARP_STATE_STABLE;
            io->netif = io->input_args.netif;
        }
    }
    // An all-zero ar$spa is an RFC 5227 sec 2.1.1 ARP Probe, "set to all zeroes; this is to avoid
    // polluting ARP caches in other hosts", so no row is keyed on it. RFC 5227 sec 2.5 still owes it
    // a REPLY: the obligation "applies equally for both standard ARP Requests with non-zero sender
    // IP addresses and Probe Requests with all-zero sender IP addresses."
    io->reply_owed = (idemip_bool)(target && idemip_arp_is_request(packet));
    io->status = IDEMIP_OK;
}

// RFC 826 "Packet Generation" throws a frame away when the pair is missing from the table, "on the
// assumption the packet will be retransmitted by a higher network layer". RFC 1122 sec 2.3.2.2 holds
// it instead: "The link layer SHOULD save (rather than discard) at least one (the latest) packet of
// each set of packets destined to the same unresolved IP address, and transmit the saved packet when
// the address has been resolved."
//
// What is held is the descriptor the caller pinned, so the octets stay in the engine's buffer. Every
// hold taken is BUSY, because a deadline or a REPLY frees one. A resolved address is ERR: the frame
// needs no hold and the caller transmits it, and holding it would pin a descriptor for nothing.
static void arp_queue(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    ArpTableIo *io = ARP_IO(work);
    io->status = IDEMIP_ERR;
    io->index = ARP_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    if (io->queue_args.ip == 0u || io->queue_args.len == 0u || io->queue_args.len > (uint16_t)IDEMIP_ETH_FRAME_MAX)
    {
        return;
    }
    uint8_t i = arp_row_find(work, (uint16_t)IDEMIP_ARP_PRO_IPV4, io->queue_args.ip);
    if (i != ARP_NONE && ARP_AT(work, i)->state == (uint8_t)IDEMIP_ARP_STATE_STABLE)
    {
        io->index = i;
        io->state = IDEMIP_ARP_STATE_STABLE;
        return;
    }
    ArpCtx *ctx = ARP_CTX(work);
    uint8_t h = arp_hold_free(work);
    if (h == ARP_NONE || ctx->held >= (uint8_t)IDEMIP_ARP_PENDING)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    if (i == ARP_NONE)
    {
        i = arp_row_take(work, io->now_ms);
        if (i == ARP_NONE)
        {
            io->status = IDEMIP_BUSY;
            return;
        }
        arp_row_open(work, i, (uint16_t)IDEMIP_ARP_PRO_IPV4, io->queue_args.ip, io->now_ms);
        ARP_AT(work, i)->state = (uint8_t)IDEMIP_ARP_STATE_PENDING;
    }
    ArpPending *p = ARP_PENDING_AT(work, h);
    p->deadline_ms = io->now_ms + ARP_MAXPENDING_MS;
    p->spa = io->queue_args.ip;
    p->desc = io->queue_args.desc;
    p->len = io->queue_args.len;
    p->entry = i;
    p->state = (uint8_t)ARP_HOLD_WAIT;
    arp_hold_link(work, i, h);
    ctx->held++;
    io->index = i;
    io->state = IDEMIP_ARP_STATE_PENDING;
    io->status = IDEMIP_OK;
}

// RFC 1122 sec 2.3.2.2, "transmit the saved packet when the address has been resolved": one hold
// whose row now carries ar$sha, oldest first. Its descriptor and the hardware address to send it to
// go in the operand block, and the hold goes free. Nothing resolved is BUSY, because a REPLY can land
// on a later tick.
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
    io->index = ARP_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    io->status = IDEMIP_BUSY;
    for (uint8_t i = 0u; i < (uint8_t)IDEMIP_ARP_ENTRIES; i++)
    {
        ArpEntry *e = ARP_AT(work, i);
        if (e->state != (uint8_t)IDEMIP_ARP_STATE_STABLE || e->pending == ARP_NONE)
        {
            continue;
        }
        uint8_t h = e->pending;
        ArpPending *p = ARP_PENDING_AT(work, h);
        arp_hold_unlink(work, i, h);
        io->desc = p->desc;
        io->len = p->len;
        io->ip = p->spa;
        io->index = i;
        io->state = IDEMIP_ARP_STATE_STABLE;
        io->netif = e->netif;
        io->mac = e->sha;
        memset(p, 0, sizeof *p);
        if (ARP_CTX(work)->held != 0u)
        {
            ARP_CTX(work)->held--;
        }
        io->status = IDEMIP_OK;
        return;
    }
}

// The sweep: RFC 1122 sec 2.3.2.1 mechanism (1) ages the rows, holds past their deadline give their
// descriptors up, and one row a REQUEST is due for is reported. One report per call, so a caller
// loops until BUSY.
//
// A report carrying a nonzero len is a pinned descriptor to hand back, in desc and len, with ip the
// address it was waiting on. A report with len zero is an address a REQUEST is due for, in ip, with
// index and netif naming its row. The row sweep runs at most once per IDEMIP_ARP_TMR_INTERVAL_MS,
// which is the interval lwIP's etharp_tmr is documented to run on; the holds and the REQUESTs are
// looked at on every call.
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
    io->index = ARP_NONE;
    if (!arp_ready(work))
    {
        return;
    }
    ArpCtx *ctx = ARP_CTX(work);
    uint32_t now_ms = io->now_ms;
    if (ctx->tick_ms == 0u || (uint32_t)(now_ms - ctx->tick_ms) >= IDEMIP_ARP_TMR_INTERVAL_MS)
    {
        ctx->tick_ms = now_ms;
        arp_age_rows(work, now_ms);
    }
    arp_expire_holds(work, now_ms);
    if (arp_report_reclaim(work))
    {
        io->status = IDEMIP_OK;
        return;
    }
    if (arp_report_request(work, now_ms))
    {
        io->status = IDEMIP_OK;
        return;
    }
    io->status = IDEMIP_BUSY;
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
