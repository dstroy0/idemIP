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

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip4_reass.h"
#include "src/common_defines.h"
#include "src/ip/ipv4_defines.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and every
// entry refuses it, because a zeroed borrow reads each list link as row zero and not as
// IDEMIP_IP4_REASS_INDEX_NONE.
#define IP4_REASS_READY 0x52415334u

// The list terminator and the "no row" result, as the octet a link field holds.
#define IP4_REASS_NONE ((uint8_t)IDEMIP_IP4_REASS_INDEX_NONE)

// RFC 791 sec 3.2 states the reassembly timer in seconds and PLAN sec 5.2 holds every deadline in
// milliseconds, so a seconds value scales by this and no conversion divide exists.
#define IP4_REASS_MS_PER_S 1000u

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
    uint8_t state;
    uint8_t reserved[7];
} Ip4ReassFrag;

// One hole, RFC 815 sec 4: "To store hole.first and hole.last will presumably require two octets
// each. An additional two octets will be required to thread together the entries on the hole
// descriptor list." Padded to 1 << IDEMIP_IP4_REASS_HOLE_ENTRY_SHIFT.
typedef struct
{
    uint16_t first;
    uint16_t last;
    uint8_t next;
    uint8_t state;
    uint8_t reserved[2];
} Ip4ReassHole;

// The context: the mark, and how many descriptors are pinned across the fragment table. No sweep
// clock: every row carries its own RFC 1122 sec 3.3.2 deadline and the sweep compares against that,
// so there is nothing a last-sweep millisecond would decide. ip4_route keeps one because its PMTU
// sweep ages every route on a period and has no per-row deadline to compare.
typedef struct
{
    uint32_t ready;
    uint8_t held;
    uint8_t reserved[3];
} Ip4ReassCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_IP4_REASS_OFF_CTX, sizeof(Ip4ReassCtx), IDEMIP_IP4_REASS_BORROW, "ip4_reass's context");

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

// ip4_reass_holes reports the holes RFC 815 sec 3 step 4 deleted, and IP4_REASS_NONE when the table
// ran out, so the whole table must stay below that value.
static_assert(IDEMIP_IP4_REASS_HOLES < IDEMIP_IP4_REASS_INDEX_NONE,
              "a deleted-hole count shares its octet with IDEMIP_IP4_REASS_INDEX_NONE");

// RFC 815 sec 3 opens hole.last at infinity, and step 6 stores fragment.last plus one into a hole,
// so the largest fragment.last RFC 791's Total Length permits must stay below that value.
static_assert(IDEMIP_IP4_TOTAL_LEN_MAX - IDEMIP_IPV4_HDR_LEN < IDEMIP_IP4_REASS_INFINITY,
              "RFC 815 sec 3 step 6 stores fragment.last plus one: infinity must stay above every fragment");

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
static idemip_bool ip4_reass_ready(uint8_t *work)
{
    return (idemip_bool)(IP4_REASS_CTX(work)->ready == IP4_REASS_READY);
}

// --- the tables ------------------------------------------------------------

// True once the millisecond clock has reached the deadline. The difference is taken in the clock's
// own width and read against a half span, so a clock that wrapped past the deadline still compares
// as reached.
static idemip_bool ip4_reass_reached(uint32_t now_ms, uint32_t deadline_ms)
{
    return (idemip_bool)((now_ms - deadline_ms) < 0x80000000u);
}

// The row still gathering fragments under this RFC 791 sec 3.2 buffer identifier, "the concatenation
// of the source, destination, protocol, and identification fields".
static uint8_t ip4_reass_find(uint8_t *work, uint32_t src, uint32_t dst, uint8_t proto, uint16_t id)
{
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        const Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, i);
        // An abandoned row is matched as well as a gathering one: it holds its buffer identifier so
        // a later fragment of the datagram it gave up on cannot start the reassembly over.
        if ((row->state == (uint8_t)IDEMIP_IP4_REASS_HOLDING ||
             row->state == (uint8_t)IDEMIP_IP4_REASS_ABANDONED) &&
            row->src == src && row->dst == dst && row->proto == proto && row->id == id)
        {
            return (uint8_t)i;
        }
    }
    return IP4_REASS_NONE;
}

// The first row in the zero state, claimed as gathering so a second call cannot reach it.
static uint8_t ip4_reass_row_alloc(uint8_t *work)
{
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, i);
        if (row->state == (uint8_t)IDEMIP_IP4_REASS_FREE)
        {
            row->state = (uint8_t)IDEMIP_IP4_REASS_HOLDING;
            row->frag_head = IP4_REASS_NONE;
            row->hole_head = IP4_REASS_NONE;
            row->first_frag = IP4_REASS_NONE;
            row->cursor = IP4_REASS_NONE;
            row->total_len = 0u;
            return (uint8_t)i;
        }
    }
    return IP4_REASS_NONE;
}

// The failure is written out because a caller must be able to read what an empty table reports, and
// it is not measured, because no call can produce it: ctx->held counts the entries not in the free
// state - one up at the link, one down at reclaim, and nowhere else - and ip4_reass_take answers BUSY
// at ctx->held >= IDEMIP_IP4_REASS_FRAGS before it asks for one. The search is empty only when the
// count it mirrors is already at the bound.
static uint8_t ip4_reass_frag_alloc(uint8_t *work)
{
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_FRAGS; i++) // GCOVR_EXCL_BR_LINE
    {
        Ip4ReassFrag *frag = IP4_REASS_FRAG_AT(work, i);
        if (frag->state == (uint8_t)IDEMIP_IP4_REASS_FREE)
        {
            frag->state = (uint8_t)IDEMIP_IP4_REASS_HOLDING;
            frag->next = IP4_REASS_NONE;
            return (uint8_t)i;
        }
    }
    return IP4_REASS_NONE; // GCOVR_EXCL_LINE
}

// The failure is written out for the same reason, and is not measured for the reason idemip_config.h
// states beside IDEMIP_IP4_REASS_HOLES: RFC 815 opens a datagram with one hole and steps 4 through 6
// leave at most one more per fragment, so D datagrams holding N fragments reach at most D + N
// descriptors, and the static_assert there holds the table at or above that. Both bounds are enforced
// ahead of every call - a row by IDEMIP_IP4_REASS_DATAGRAMS, a fragment by ctx->held - so the search
// has an entry every time it is made.
static uint8_t ip4_reass_hole_alloc(uint8_t *work, uint32_t first, uint32_t last)
{
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_HOLES; i++) // GCOVR_EXCL_BR_LINE
    {
        Ip4ReassHole *hole = IP4_REASS_HOLE_AT(work, i);
        if (hole->state == (uint8_t)IDEMIP_IP4_REASS_FREE)
        {
            hole->first = (uint16_t)first;
            hole->last = (uint16_t)last;
            hole->next = IP4_REASS_NONE;
            hole->state = (uint8_t)IDEMIP_IP4_REASS_HOLDING;
            return (uint8_t)i;
        }
    }
    return IP4_REASS_NONE; // GCOVR_EXCL_LINE
}

// RFC 791 sec 3.2 step (16), "free all reassembly resources for this BUFID": the hole list goes back
// to the table, and the row waits on reclaim while its fragments still pin receive descriptors.
static void ip4_reass_free_holes(uint8_t *work, Ip4ReassDatagram *row)
{
    uint8_t h = row->hole_head;
    while (h != IP4_REASS_NONE)
    {
        Ip4ReassHole *hole = IP4_REASS_HOLE_AT(work, h);
        const uint8_t next = hole->next;
        hole->state = (uint8_t)IDEMIP_IP4_REASS_FREE;
        hole->next = IP4_REASS_NONE;
        h = next;
    }
    row->hole_head = IP4_REASS_NONE;
    row->cursor = IP4_REASS_NONE;
}

// A flushed row goes free if it holds nothing and waits on reclaim if it does. Only the second is
// measured: every state a flush is reached from - gathering, complete, abandoned - has taken at least
// one fragment, and the one place a row exists without one is the pair of table-exhausted arms in
// ip4_reass_take, which open a row and give it back unfilled. Those cannot be reached either, for the
// reasons written beside them, so the free arm is here to serve them and is never walked.
static void ip4_reass_flush(uint8_t *work, uint8_t index)
{
    Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, index);
    ip4_reass_free_holes(work, row);
    row->state = (row->frag_head == IP4_REASS_NONE) ? (uint8_t)IDEMIP_IP4_REASS_FREE // GCOVR_EXCL_BR_LINE
                                                    : (uint8_t)IDEMIP_IP4_REASS_RECLAIM;
}

// Give up on a datagram without giving up its buffer identifier. The hole list goes back, because
// nothing can complete a row whose fragments disagree, but the row keeps its key so a further
// fragment of the same datagram lands on the dead row rather than opening a fresh one - which is the
// disposition RFC 5722 sec 4 states for the IPv6 twin, "any constituent fragments, including those
// not yet received". The fragments stay pinned until release and reclaim hand their descriptors back.
static void ip4_reass_abandon(uint8_t *work, uint8_t index)
{
    Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, index);
    ip4_reass_free_holes(work, row);
    row->state = (uint8_t)IDEMIP_IP4_REASS_ABANDONED;
}

// Octets of [first, last] that lie in a hole, which is what this fragment would contribute. RFC 815
// sec 2 keeps the holes disjoint and ascending, so summing the intersections counts every octet once
// and the answer is between zero and the fragment's own length.
static uint32_t ip4_reass_fills(uint8_t *work, uint8_t index, uint32_t first, uint32_t last)
{
    uint32_t fills = 0u;
    uint8_t h = IP4_REASS_DGRAM_AT(work, index)->hole_head;
    while (h != IP4_REASS_NONE)
    {
        const Ip4ReassHole *hole = IP4_REASS_HOLE_AT(work, h);
        const uint32_t lo = (first > hole->first) ? first : hole->first;
        const uint32_t hi = (last < hole->last) ? last : (uint32_t)hole->last;
        if (lo <= hi)
        {
            fills += (hi - lo) + 1u;
        }
        h = hole->next;
    }
    return fills;
}

// The fragment list in ascending fragment offset, which is the order next reports it in.
static void ip4_reass_frag_link(uint8_t *work, uint8_t index, uint8_t frag)
{
    Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, index);
    Ip4ReassFrag *added = IP4_REASS_FRAG_AT(work, frag);
    uint8_t prev = IP4_REASS_NONE;
    uint8_t cur = row->frag_head;
    while (cur != IP4_REASS_NONE && IP4_REASS_FRAG_AT(work, cur)->off <= added->off)
    {
        prev = cur;
        cur = IP4_REASS_FRAG_AT(work, cur)->next;
    }
    added->next = cur;
    if (prev == IP4_REASS_NONE)
    {
        row->frag_head = frag;
    }
    else
    {
        IP4_REASS_FRAG_AT(work, prev)->next = frag;
    }
}

// The octet past the last one any held fragment of this row covers.
//
// The walk is written as a maximum because that is what it means, and only one arm of it is measured:
// ip4_reass_frag_link keeps the list in ascending Fragment Offset, and a fragment is only linked
// after the measure above found every octet of it missing, so no two held fragments share an octet
// and their ends ascend with their offsets. Each is past the one before it.
static uint32_t ip4_reass_end(uint8_t *work, uint8_t index)
{
    uint32_t end = 0u;
    uint8_t f = IP4_REASS_DGRAM_AT(work, index)->frag_head;
    while (f != IP4_REASS_NONE)
    {
        const Ip4ReassFrag *frag = IP4_REASS_FRAG_AT(work, f);
        const uint32_t frag_end = (uint32_t)frag->off + (uint32_t)frag->len;
        if (frag_end > end) // GCOVR_EXCL_BR_LINE
        {
            end = frag_end;
        }
        f = frag->next;
    }
    return end;
}

// RFC 815 sec 4 threads the hole descriptors onto a list, so the entry after @p at is whatever @p to
// names, and an empty @p at is the head of the row's list.
static void ip4_reass_hole_thread(uint8_t *work, uint8_t index, uint8_t at, uint8_t to)
{
    if (at == IP4_REASS_NONE)
    {
        IP4_REASS_DGRAM_AT(work, index)->hole_head = to;
    }
    else
    {
        IP4_REASS_HOLE_AT(work, at)->next = to;
    }
}

// RFC 815 sec 3, the eight steps over one datagram's hole descriptor list, with the arriving fragment
// "described by fragment.first, the first octet of the fragment, and fragment.last, the last octet of
// the fragment". Reports the holes step 4 deleted, so zero means steps 2 and 3 passed over every
// hole and the fragment covers nothing missing, and IP4_REASS_NONE means the hole table ran out.
// Step 8 is the caller's: it reads hole_head.
static uint8_t ip4_reass_holes(uint8_t *work, uint8_t index, uint32_t first, uint32_t last, idemip_bool mf)
{
    uint8_t prev = IP4_REASS_NONE;
    uint8_t h = IP4_REASS_DGRAM_AT(work, index)->hole_head;
    uint8_t deleted = 0u;
    while (h != IP4_REASS_NONE) // step 1, and step 7 returns here
    {
        Ip4ReassHole *hole = IP4_REASS_HOLE_AT(work, h);
        const uint8_t next = hole->next;
        const uint32_t hole_first = hole->first;
        const uint32_t hole_last = hole->last;
        if (first > hole_last || last < hole_first) // steps 2 and 3
        {
            prev = h;
            h = next;
            continue;
        }
        hole->state = (uint8_t)IDEMIP_IP4_REASS_FREE; // step 4
        hole->next = IP4_REASS_NONE;
        deleted++;
        uint8_t tail = prev;
        if (first > hole_first) // step 5
        {
            const uint8_t piece = ip4_reass_hole_alloc(work, hole_first, first - 1u);
            // Neither piece can fail to be made, for the reason written at ip4_reass_hole_alloc: the
            // table is sized for one hole per datagram and one more per fragment, and both bounds are
            // enforced before this walk is entered. The arms are here because a walk that hands the
            // list to a caller must not hand back a list it has torn, and they are not measured.
            if (piece == IP4_REASS_NONE) // GCOVR_EXCL_BR_LINE
            {
                // GCOVR_EXCL_START
                ip4_reass_hole_thread(work, index, prev, next); // the rest of the list stays reachable
                return IP4_REASS_NONE;
                // GCOVR_EXCL_STOP
            }
            IP4_REASS_HOLE_AT(work, piece)->next = next;
            ip4_reass_hole_thread(work, index, tail, piece);
            tail = piece;
        }
        if (last < hole_last && mf) // step 6
        {
            const uint8_t piece = ip4_reass_hole_alloc(work, last + 1u, hole_last);
            if (piece == IP4_REASS_NONE) // GCOVR_EXCL_BR_LINE
            {
                // GCOVR_EXCL_START
                if (tail == prev)
                {
                    ip4_reass_hole_thread(work, index, prev, next);
                }
                return IP4_REASS_NONE;
                // GCOVR_EXCL_STOP
            }
            IP4_REASS_HOLE_AT(work, piece)->next = next;
            ip4_reass_hole_thread(work, index, tail, piece);
            tail = piece;
        }
        if (tail == prev) // neither piece was made, so the deleted hole leaves the thread
        {
            ip4_reass_hole_thread(work, index, prev, next);
        }
        prev = tail;
        h = next;
    }
    return deleted;
}

// --- the bodies ------------------------------------------------------------

// RFC 791 sec 3.2 steps (3) and (4): every row carrying this buffer identifier is flushed, and its
// pinned descriptors go to reclaim. Reports the first row flushed.
static uint8_t ip4_reass_flush_bufid(uint8_t *work, uint32_t src, uint32_t dst, uint8_t proto, uint16_t id)
{
    uint8_t first = IP4_REASS_NONE;
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        const Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, i);
        if (row->state == (uint8_t)IDEMIP_IP4_REASS_FREE || row->state == (uint8_t)IDEMIP_IP4_REASS_RECLAIM)
        {
            continue;
        }
        if (row->src != src || row->dst != dst || row->proto != proto || row->id != id)
        {
            continue;
        }
        ip4_reass_flush(work, (uint8_t)i);
        if (first == IP4_REASS_NONE)
        {
            first = (uint8_t)i;
        }
    }
    return first;
}

// One fragment into its datagram's row. The RFC 791 sec 3.2 buffer identifier picks the row, the
// RFC 815 sec 3 eight steps run over its hole list, and the receive descriptor stays pinned in the
// fragment table until reclaim hands it back. The operand block arrives with status ERR set, so
// every refusal is a return.
static void ip4_reass_take(uint8_t *work)
{
    Ip4ReassIo *io = IP4_REASS_IO(work);
    Ip4ReassCtx *ctx = IP4_REASS_CTX(work);
    const uint8_t *hdr = io->hold_args.hdr;

    // The unit indexes on IHL, Total Length and the Fragment Offset, so the header carrying them is
    // put through RFC 1122 sec 3.2.1's checks over the octets the caller says are readable.
    if (hdr == NULL || idemip_ip4_verify(hdr, (size_t)io->hold_args.len) != IDEMIP_OK)
    {
        return;
    }
    const uint8_t hdr_len = (uint8_t)idemip_ip4_hdr_len(hdr);
    const uint32_t data_len = (uint32_t)idemip_ip4_payload_len(hdr);
    const uint32_t off = idemip_ip4_frag_offset_bytes(hdr);
    const idemip_bool mf = idemip_ip4_mf(hdr);
    const uint32_t src = idemip_ip4_src(hdr);
    const uint32_t dst = idemip_ip4_dst(hdr);
    const uint8_t proto = idemip_ip4_proto(hdr);
    const uint16_t id = idemip_ip4_id(hdr);

    // RFC 791 sec 3.2 steps (2) through (5): "IF FO = 0 AND MF = 0 THEN IF buffer with BUFID is
    // allocated THEN flush all reassembly for this BUFID; Submit datagram to next step". The submit
    // is the caller's, and nothing of a whole datagram is held here, so its descriptor is not pinned
    // and the report is ERR: a datagram that is not a fragment never becomes one on a retry.
    if (off == 0u && !mf)
    {
        io->index = ip4_reass_flush_bufid(work, src, dst, proto, id);
        if (io->index != IP4_REASS_NONE)
        {
            io->state = (IdemIpIp4ReassState)IP4_REASS_DGRAM_AT(work, io->index)->state;
        }
        return;
    }

    // RFC 791 sec 3.2: "the minimum fragment is 8 octets", and "If an internet datagram is
    // fragmented, its data portion must be broken on 8 octet boundaries", so a fragment that is not
    // the last carries a nonzero multiple of eight octets. Neither can be met on a retry.
    if (data_len == 0u || (mf && (data_len & (IDEMIP_IP4_FRAG_UNIT - 1u)) != 0u))
    {
        return;
    }
    // RFC 791 sec 3.2 step (14), "TL <- TDL+(IHL*4)": the reassembled Total Length is 16 bits.
    if (off + data_len + (uint32_t)hdr_len > (uint32_t)IDEMIP_IP4_TOTAL_LEN_MAX)
    {
        return;
    }
    // Every fragment pins a receive descriptor, and IDEMIP_MAX_PINNED_FRAMES counts
    // IDEMIP_IP4_REASS_FRAGS of them. BUSY, because reclaim and the timeout sweep free one.
    if (ctx->held >= IDEMIP_IP4_REASS_FRAGS)
    {
        io->status = IDEMIP_BUSY;
        return;
    }

    idemip_bool opened = IDEMIP_FALSE;
    uint8_t index = ip4_reass_find(work, src, dst, proto, id);
    if (index == IP4_REASS_NONE)
    {
        // RFC 791 sec 3.2 step (7): "allocate reassembly resources with BUFID; TIMER <- TLB;
        // TDL <- 0". BUSY on a full table, which the timeout sweep frees.
        index = ip4_reass_row_alloc(work);
        if (index == IP4_REASS_NONE)
        {
            io->status = IDEMIP_BUSY;
            return;
        }
        // RFC 815 sec 3: the first entry "describes the datagram as being completely missing. In this
        // case, hole.first equals zero, and hole.last equals infinity".
        Ip4ReassDatagram *fresh = IP4_REASS_DGRAM_AT(work, index);
        fresh->hole_head = ip4_reass_hole_alloc(work, 0u, IDEMIP_IP4_REASS_INFINITY);
        // Not measured, for the reason written at ip4_reass_hole_alloc: the row this call just took
        // is one of IDEMIP_IP4_REASS_DATAGRAMS, and the table holds one opening hole for every one of
        // them on top of one per fragment. The row is given back rather than left half-open.
        if (fresh->hole_head == IP4_REASS_NONE) // GCOVR_EXCL_BR_LINE
        {
            // GCOVR_EXCL_START
            fresh->state = (uint8_t)IDEMIP_IP4_REASS_FREE;
            io->status = IDEMIP_BUSY;
            return;
            // GCOVR_EXCL_STOP
        }
        fresh->src = src;
        fresh->dst = dst;
        fresh->proto = proto;
        fresh->id = id;
        fresh->deadline_ms = io->now_ms + ((uint32_t)IDEMIP_IP_REASS_MAXAGE_S * IP4_REASS_MS_PER_S);
        opened = IDEMIP_TRUE;
    }

    Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, index);
    const uint32_t frag_end = off + data_len;

    // The row gave up on this datagram. Its buffer identifier is held until the deadline retires it,
    // so this fragment goes no further and opens nothing.
    if (row->state == (uint8_t)IDEMIP_IP4_REASS_ABANDONED)
    {
        io->index = index;
        io->state = IDEMIP_IP4_REASS_ABANDONED;
        return;
    }

    // RFC 791 sec 3.2 step (10) fixes TDL, so no octet of this datagram lies at or past it, and a
    // second last fragment naming a different TDL contradicts the first. A last fragment also cannot
    // name a TDL below what is already held. None of the three changes on a retry.
    //
    // The middle line is not measured. Its TDL test is the same row->total_len != 0u the line above
    // makes, and the code generated for a short-circuit chain reaches the second test only along the
    // first one's true path, so the arm where a row has no TDL yet is answered on the line above and
    // never on this one. Each of the three contradictions has a case that fails if it is removed.
    if ((row->total_len != 0u && frag_end > (uint32_t)row->total_len) ||
        (!mf && row->total_len != 0u && frag_end != (uint32_t)row->total_len) || // GCOVR_EXCL_BR_LINE
        (!mf && frag_end < ip4_reass_end(work, index)))
    {
        // A row this call opened holds one hole from zero to infinity and no TDL, so none of the
        // three contradictions above can be its first fragment's answer and the flush is not
        // measured. It is here because a row must not be left open by a fragment that was refused.
        if (opened) // GCOVR_EXCL_BR_LINE
        {
            ip4_reass_flush(work, index); // GCOVR_EXCL_LINE
        }
        return;
    }

    // What this fragment contributes, against what it would rewrite. The hole list is what the row
    // is missing, so octets of the fragment that fall in a hole are new and the rest are octets the
    // row already holds and would be written over.
    //
    // Nothing new is a duplicate: a network that duplicates a packet delivers the same fragment
    // twice, and RFC 815 sec 3 steps 2 and 3 pass over every hole for it. It is dropped and the row
    // stands, which is what RFC 8200 sec 4.5 permits its IPv6 twin as "drop exact duplicate
    // fragments while keeping the other fragments".
    //
    // Some new and the rest a rewrite is the RFC 1858 sec 3.2 overlapping fragment: a sender that
    // fragmented one datagram produces disjoint pieces, so two pieces that disagree about an octet
    // did not come from one datagram, and there is no reading of the pair that is the datagram. The
    // row is abandoned rather than reassembled from whichever piece the walk reports last. RFC 5722
    // sec 4 reaches the same disposition for IPv6 and RFC 8200 sec 4.5 carries it: "reassembly of
    // that packet must be abandoned and all the fragments that have been received for that packet
    // must be discarded". No IPv4 RFC requires it, and none forbids it either; what an IPv4 receiver
    // is left to choose is which of two contradicting fragments to believe, and this believes
    // neither.
    //
    // A row opened by this fragment holds one hole spanning the whole datagram, so it always takes
    // the first branch below and neither of the other two can be its first fragment's answer.
    const uint32_t fills = ip4_reass_fills(work, index, off, frag_end - 1u);
    if (fills == 0u)
    {
        io->index = index;
        io->state = (IdemIpIp4ReassState)row->state;
        return;
    }
    if (fills != data_len)
    {
        ip4_reass_abandon(work, index);
        io->index = index;
        io->state = IDEMIP_IP4_REASS_ABANDONED;
        return;
    }

    const uint8_t frag = ip4_reass_frag_alloc(work);
    // Not measured, for the reason written at ip4_reass_frag_alloc: ctx->held answered BUSY at the
    // bound before this call was made. The arm is here because a table that can be full must be read
    // as though it is.
    if (frag == IP4_REASS_NONE) // GCOVR_EXCL_BR_LINE
    {
        // GCOVR_EXCL_START
        if (opened)
        {
            ip4_reass_flush(work, index);
        }
        io->status = IDEMIP_BUSY;
        return;
        // GCOVR_EXCL_STOP
    }

    const uint8_t deleted = ip4_reass_holes(work, index, off, frag_end - 1u, mf);
    if (deleted == IP4_REASS_NONE) // GCOVR_EXCL_BR_LINE
    {
        // GCOVR_EXCL_START
        // The hole table ran out inside the eight steps, which the IDEMIP_IP4_REASS_HOLES bound in
        // idemip_config.h rules out. The list no longer describes what is missing, so the row is
        // flushed and its descriptors go back. BUSY, because a freed row lets the fragment land.
        IP4_REASS_FRAG_AT(work, frag)->state = (uint8_t)IDEMIP_IP4_REASS_FREE;
        ip4_reass_flush(work, index);
        io->status = IDEMIP_BUSY;
        return;
        // GCOVR_EXCL_STOP
    }
    // A fragment reaching here fills a hole, because the measure above admitted only fragments
    // wholly inside them and no fragment is zero octets long, so at least one hole was reached.

    Ip4ReassFrag *held = IP4_REASS_FRAG_AT(work, frag);
    held->desc = io->hold_args.desc;
    held->off = (uint16_t)off;
    held->len = (uint16_t)data_len;
    held->hdr_len = hdr_len;
    ip4_reass_frag_link(work, index, frag);
    ctx->held++;

    if (!mf)
    {
        row->total_len = (uint16_t)frag_end; // step (10): "IF MF = 0 THEN TDL <- TL-(IHL*4)+(FO*8)"
    }
    if (off == 0u)
    {
        row->first_frag = frag; // step (11): "IF FO = 0 THEN put header in header buffer"
    }
    // RFC 1122 sec 3.3.2 supersedes RFC 791 sec 3.2 step (17)'s "TIMER <- MAX(TIMER,TTL)": "The
    // reassembly timeout value SHOULD be a fixed value, not set from the remaining TTL." The deadline
    // is the one stamped when the row was opened, and no fragment moves it.

    // RFC 815 sec 3 step 8: "If the hole descriptor list is now empty, the datagram is now complete."
    // The header comes with octet zero, so step (11) has run by then - which is why the second test
    // is not measured. The list opens at a hole starting at zero, step 5 leaves a piece starting at
    // zero behind every fragment that does not begin there, and only a fragment at Fragment Offset
    // zero can delete it. An empty list has taken octet zero, and taking it set first_frag.
    if (row->hole_head == IP4_REASS_NONE && row->first_frag != IP4_REASS_NONE) // GCOVR_EXCL_BR_LINE
    {
        row->state = (uint8_t)IDEMIP_IP4_REASS_COMPLETE;
        row->cursor = row->frag_head;
        io->complete = IDEMIP_TRUE;
    }
    io->index = index;
    io->state = (IdemIpIp4ReassState)row->state;
    io->total_len = row->total_len;
    io->status = IDEMIP_OK;
}

// RFC 791 sec 3.2 step (15), "Submit datagram to next step": one held fragment per call, in ascending
// fragment offset, so the caller reads the octets out of the buffers the engine wrote them to. The
// walk starts over once every fragment has been reported.
static void ip4_reass_report(uint8_t *work)
{
    Ip4ReassIo *io = IP4_REASS_IO(work);
    const uint8_t index = io->next_args.index;
    if (index >= IDEMIP_IP4_REASS_DATAGRAMS)
    {
        return;
    }
    Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, index);
    io->index = index;
    io->state = (IdemIpIp4ReassState)row->state;
    if (row->state == (uint8_t)IDEMIP_IP4_REASS_HOLDING)
    {
        io->status = IDEMIP_BUSY; // holes remain, and a later fragment fills them
        return;
    }
    if (row->state != (uint8_t)IDEMIP_IP4_REASS_COMPLETE)
    {
        // A free row, an abandoned one and one waiting on reclaim carry no datagram to hand on, and
        // none of the three becomes a datagram on a retry.
        return;
    }
    const uint8_t frag = row->cursor;
    if (frag == IP4_REASS_NONE)
    {
        row->cursor = row->frag_head;
        io->status = IDEMIP_BUSY; // every fragment has been reported
        return;
    }
    const Ip4ReassFrag *held = IP4_REASS_FRAG_AT(work, frag);
    io->off = held->off;
    io->len = held->len;
    io->desc = held->desc;
    io->hdr_len = held->hdr_len;
    row->cursor = held->next;
    io->status = IDEMIP_OK;
}

// RFC 791 sec 3.2 step (16), "free all reassembly resources for this BUFID". The hole list goes back
// and the row waits on reclaim, because its fragments still pin receive descriptors.
static void ip4_reass_done(uint8_t *work)
{
    Ip4ReassIo *io = IP4_REASS_IO(work);
    const uint8_t index = io->release_args.index;
    if (index >= IDEMIP_IP4_REASS_DATAGRAMS)
    {
        return;
    }
    const Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, index);
    if (row->state != (uint8_t)IDEMIP_IP4_REASS_HOLDING && row->state != (uint8_t)IDEMIP_IP4_REASS_COMPLETE &&
        row->state != (uint8_t)IDEMIP_IP4_REASS_ABANDONED)
    {
        return; // a free row holds nothing, and one already released is on its way back
    }
    ip4_reass_flush(work, index);
    io->index = index;
    io->state = (IdemIpIp4ReassState)row->state;
    io->status = IDEMIP_OK;
}

// PLAN sec 3.5: "A pinned descriptor is released when the retaining unit is done with it: reassembly
// on completion or timeout". One descriptor per call, off the front of a released or timed-out row's
// fragment list, and the row is free once its last one has gone back.
static void ip4_reass_unpin(uint8_t *work)
{
    Ip4ReassIo *io = IP4_REASS_IO(work);
    Ip4ReassCtx *ctx = IP4_REASS_CTX(work);
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, i);
        // The second test is not measured: a row reaches the reclaim state out of ip4_reass_flush,
        // which puts it there only when it still holds a fragment, and the last one going back below
        // takes the row free in the same breath. A row waiting on reclaim always has one to hand.
        if (row->state != (uint8_t)IDEMIP_IP4_REASS_RECLAIM || row->frag_head == IP4_REASS_NONE) // GCOVR_EXCL_BR_LINE
        {
            continue;
        }
        Ip4ReassFrag *held = IP4_REASS_FRAG_AT(work, row->frag_head);
        io->desc = held->desc;
        io->len = held->len;
        io->index = (uint8_t)i;
        row->frag_head = held->next;
        held->state = (uint8_t)IDEMIP_IP4_REASS_FREE;
        held->next = IP4_REASS_NONE;
        // The count is what ip4_reass_take reads to answer BUSY, so it is never let below zero. It
        // cannot reach here at zero - the entry just freed was counted when it was linked - and the
        // floor is not measured.
        if (ctx->held != 0u) // GCOVR_EXCL_BR_LINE
        {
            ctx->held--;
        }
        if (row->frag_head == IP4_REASS_NONE)
        {
            row->state = (uint8_t)IDEMIP_IP4_REASS_FREE;
            row->first_frag = IP4_REASS_NONE;
            row->total_len = 0u;
        }
        io->status = IDEMIP_OK;
        return;
    }
    io->status = IDEMIP_BUSY; // no row is waiting to hand a descriptor back
}

// RFC 791 sec 3.2 step (19), "timer expires: flush all reassembly with this BUFID". One row per call,
// so RFC 1122 sec 3.3.2's "an ICMP Time Exceeded message sent to the source host (if fragment zero has
// been received)" can be built for each: the source and the fragment-zero mark are read out of the
// row before the flush clears it. BUSY once no row the clock has reached is left.
static void ip4_reass_expire(uint8_t *work)
{
    Ip4ReassIo *io = IP4_REASS_IO(work);
    for (unsigned int i = 0u; i < IDEMIP_IP4_REASS_DATAGRAMS; i++)
    {
        const Ip4ReassDatagram *row = IP4_REASS_DGRAM_AT(work, i);
        const idemip_bool abandoned = (idemip_bool)(row->state == (uint8_t)IDEMIP_IP4_REASS_ABANDONED);
        if (row->state != (uint8_t)IDEMIP_IP4_REASS_HOLDING && row->state != (uint8_t)IDEMIP_IP4_REASS_COMPLETE &&
            !abandoned)
        {
            continue;
        }
        if (!ip4_reass_reached(io->now_ms, row->deadline_ms))
        {
            continue;
        }
        // RFC 1122 sec 3.3.2 owes the Time Exceeded to a datagram the timer ran out on, which RFC 792
        // states as "If a host reassembling a fragmented datagram cannot complete the reassembly due
        // to missing fragments within its time limit it discards the datagram, and it may send a time
        // exceeded message". An abandoned row is not missing fragments - it was told
        // two different things about the same octets - so it is retired without an answer, which is
        // the disposition RFC 8200 sec 4.5 states for its IPv6 twin: "no ICMP error messages should
        // be sent". Its buffer identifier goes back here, and only here.
        io->src = abandoned ? 0u : row->src;
        io->frag_zero = (idemip_bool)(!abandoned && row->first_frag != IP4_REASS_NONE);
        ip4_reass_flush(work, (uint8_t)i);
        io->state = (IdemIpIp4ReassState)row->state;
        io->index = (uint8_t)i;
        io->status = IDEMIP_OK;
        return;
    }
    io->status = IDEMIP_BUSY; // the sweep found nothing to time out
}

// --- the entries -----------------------------------------------------------

// The context and all three tables, zeroed, then the mark. The operand block is the caller's and is
// left as it stands.
void idemip_ip4_reass_clear(uint8_t *work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP4_REASS_OFF_CTX, 0,
           (size_t)IDEMIP_IP4_REASS_BORROW - IDEMIP_IP4_REASS_OFF_CTX);
    IP4_REASS_CTX(work)->ready = IP4_REASS_READY;
    IP4_REASS_IO(work)->status = IDEMIP_OK;
}

void idemip_ip4_reass_hold(uint8_t *work)
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
    ip4_reass_take(work);
}

void idemip_ip4_reass_next(uint8_t *work)
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
    ip4_reass_report(work);
}

void idemip_ip4_reass_release(uint8_t *work)
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
    ip4_reass_done(work);
}

void idemip_ip4_reass_reclaim(uint8_t *work)
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
    ip4_reass_unpin(work);
}

void idemip_ip4_reass_tick(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip4ReassIo *io = IP4_REASS_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_IP4_REASS_INDEX_NONE;
    io->state = IDEMIP_IP4_REASS_FREE;
    io->src = 0u;
    io->frag_zero = IDEMIP_FALSE;
    if (!ip4_reass_ready(work))
    {
        return;
    }
    ip4_reass_expire(work);
}

IDEMIP_END_DECLS
