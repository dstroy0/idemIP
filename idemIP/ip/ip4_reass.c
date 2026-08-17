// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_reass.c
 * @brief The rows of the RFC 791 sec 3.2 reassembler and the RFC 815 hole descriptor list.
 *
 * The three row types are this file's. Every entry is a function of the one pointer it is handed: the
 * operand block, the context and all three tables are regions of that borrow, at compile-time
 * offsets, and no entry reads or writes a byte outside it.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV4

#include "idemIP/ip/ip4_reass.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and every
// entry refuses it, because a zeroed borrow reads each list link as row zero and not as
// IDEMIP_IP4_REASS_INDEX_NONE.
#define IP4_REASS_READY 0x52415334u

// One datagram: the RFC 791 sec 3.2 buffer identifier, "the concatenation of the source, destination,
// protocol, and identification fields", with TDL, the deadline, the heads of its fragment and hole
// lists, the fragment carrying octet zero and so the header, and the cursor next walks by. Padded to
// 1 << IDEMIP_IP4_REASS_DATAGRAM_ENTRY_SHIFT.
typedef struct
{
    uint32_t src;
    uint32_t dst;
    uint32_t deadline_ms;
    uint16_t id;
    uint16_t total_len;
    uint8_t proto;
    uint8_t frag_head;
    uint8_t hole_head;
    uint8_t first_frag;
    uint8_t cursor;
    uint8_t state;
    uint8_t reserved[10];
} Ip4ReassDatagram;

// One held fragment: the pinned receive descriptor, where its data starts and how much of it there
// is, the header in front of it, the datagram it belongs to, and the next fragment of that datagram.
// Padded to 1 << IDEMIP_IP4_REASS_FRAG_ENTRY_SHIFT.
typedef struct
{
    uint16_t desc;
    uint16_t off;
    uint16_t len;
    uint8_t hdr_len;
    uint8_t next;
    uint8_t datagram;
    uint8_t state;
    uint8_t reserved[6];
} Ip4ReassFrag;

// One hole, RFC 815 sec 4: "To store hole.first and hole.last will presumably require two octets
// each. An additional two octets will be required to thread together the entries on the hole
// descriptor list." Padded to 1 << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT.
typedef struct
{
    uint16_t first;
    uint16_t last;
    uint8_t next;
    uint8_t datagram;
    uint8_t state;
    uint8_t reserved[1];
} Ip4ReassHole;

// The context: the mark, the millisecond of the last timeout sweep, and how many descriptors are
// pinned across the fragment table.
typedef struct
{
    uint32_t ready;
    uint32_t tick_ms;
    uint8_t held;
    uint8_t reserved[3];
} Ip4ReassCtx;

// Row i of each table is at (i << SHIFT), so each width has to be exactly its shift.
static_assert(sizeof(Ip4ReassDatagram) == (1u << IDEMIP_IP4_REASS_DATAGRAM_ENTRY_SHIFT),
              "an Ip4ReassDatagram must be exactly 1 << IDEMIP_IP4_REASS_DATAGRAM_ENTRY_SHIFT wide - pad it, or raise "
              "the shift");
static_assert(sizeof(Ip4ReassFrag) == (1u << IDEMIP_IP4_REASS_FRAG_ENTRY_SHIFT),
              "an Ip4ReassFrag must be exactly 1 << IDEMIP_IP4_REASS_FRAG_ENTRY_SHIFT wide - pad it, or raise the "
              "shift");
static_assert(sizeof(Ip4ReassHole) == (1u << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT),
              "an Ip4ReassHole must be exactly 1 << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT wide - pad it, or raise the "
              "shift");

// The head region carries the operand block and the context, both outside all three tables.
static_assert(IDEMIP_IP4_REASS_OFF_CTX + sizeof(Ip4ReassCtx) <= IDEMIP_IP4_REASS_CTX_BYTES,
              "IDEMIP_IP4_REASS_CTX_BYTES is short of the operand block and the context - raise it in "
              "idemip_config.h");

// The caller's borrow, split: the head region, then the datagrams, the fragments and the holes.
// ip4_reass.h publishes the offsets; the assert proves the span covers them before anything runs.
static_assert(IDEMIP_IP4_REASS_OFF_HOLE + (IDEMIP_IP4_REASS_HOLES << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT) <=
                  IDEMIP_IP4_REASS_BORROW,
              "IDEMIP_IP4_REASS_BORROW is short of the head region and the three tables - raise it in "
              "idemip_config.h");

// clear zeroes all three tables, so the empty row is the zero state.
static_assert(IDEMIP_IP4_REASS_FREE == 0, "IDEMIP_IP4_REASS_FREE must be zero: clear zeroes the tables");

// The regions, at their offsets in the caller's borrow.
#define IP4_REASS_IO(w) IDEMIP_IP4_REASS_IO(w)
#define IP4_REASS_CTX(w) ((Ip4ReassCtx *)(void *)((w) + IDEMIP_IP4_REASS_OFF_CTX))
#define IP4_REASS_DGRAM_AT(w, i)                                                                                       \
    ((Ip4ReassDatagram *)(void *)((w) + IDEMIP_IP4_REASS_OFF_DGRAM +                                                   \
                                  ((size_t)(i) << IDEMIP_IP4_REASS_DATAGRAM_ENTRY_SHIFT)))
#define IP4_REASS_FRAG_AT(w, i)                                                                                        \
    ((Ip4ReassFrag *)(void *)((w) + IDEMIP_IP4_REASS_OFF_FRAG + ((size_t)(i) << IDEMIP_IP4_REASS_FRAG_ENTRY_SHIFT)))
#define IP4_REASS_HOLE_AT(w, i)                                                                                        \
    ((Ip4ReassHole *)(void *)((w) + IDEMIP_IP4_REASS_OFF_HOLE + ((size_t)(i) << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT)))

// A borrow clear has not run on holds no list terminator, so every entry but clear refuses it.
static idemip_bool ip4_reass_ready(uint8_t *restrict work)
{
    return (idemip_bool)(IP4_REASS_CTX(work)->ready == IP4_REASS_READY);
}

// --- the entries -----------------------------------------------------------

// The context and all three tables, zeroed, then the mark. The operand block is the caller's and is
// left as it stands.
static void ip4_reass_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP4_REASS_OFF_CTX, 0,
           (size_t)IDEMIP_IP4_REASS_BORROW - (size_t)IDEMIP_IP4_REASS_OFF_CTX);
    IP4_REASS_CTX(work)->ready = IP4_REASS_READY;
    IP4_REASS_IO(work)->status = IDEMIP_OK;
}

static void ip4_reass_hold(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4ReassIo *io = IP4_REASS_IO(work);
    io->status = IDEMIP_ERR;
    io->complete = IDEMIP_FALSE;
    io->total_len = 0;
    io->index = (uint8_t)IDEMIP_IP4_REASS_INDEX_NONE;
    io->state = IDEMIP_IP4_REASS_FREE;
    if (!ip4_reass_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 791 sec 3.2 steps (1) through (13), and the RFC 815 sec 3 eight steps over the hole list.
    io->status = IDEMIP_ERR;
}

static void ip4_reass_next(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4ReassIo *io = IP4_REASS_IO(work);
    io->status = IDEMIP_ERR;
    io->off = 0;
    io->len = 0;
    io->desc = 0;
    io->hdr_len = 0;
    io->index = (uint8_t)IDEMIP_IP4_REASS_INDEX_NONE;
    io->state = IDEMIP_IP4_REASS_FREE;
    if (!ip4_reass_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 791 sec 3.2 step (15), the completed datagram handed on one held fragment at a time.
    io->status = IDEMIP_ERR;
}

static void ip4_reass_release(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4ReassIo *io = IP4_REASS_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_REASS_INDEX_NONE;
    io->state = IDEMIP_IP4_REASS_FREE;
    if (!ip4_reass_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 791 sec 3.2 step (16), "free all reassembly resources for this BUFID".
    io->status = IDEMIP_ERR;
}

static void ip4_reass_reclaim(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4ReassIo *io = IP4_REASS_IO(work);
    io->status = IDEMIP_ERR;
    io->desc = 0;
    io->len = 0;
    io->index = (uint8_t)IDEMIP_IP4_REASS_INDEX_NONE;
    if (!ip4_reass_ready(work))
    {
        return;
    }
    // PHASE 3: PLAN.md sec 3.5, a pin released once the unit holding it is done with the fragment.
    io->status = IDEMIP_ERR;
}

static void ip4_reass_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4ReassIo *io = IP4_REASS_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_REASS_INDEX_NONE;
    io->state = IDEMIP_IP4_REASS_FREE;
    if (!ip4_reass_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 791 sec 3.2 step (19), "timer expires: flush all reassembly with this BUFID".
    io->status = IDEMIP_ERR;
}

const Ip4ReassNs Ip4Reass = {.clear = ip4_reass_clear,
                             .hold = ip4_reass_hold,
                             .next = ip4_reass_next,
                             .release = ip4_reass_release,
                             .reclaim = ip4_reass_reclaim,
                             .tick = ip4_reass_tick};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4
