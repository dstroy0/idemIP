// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip6_reass.c
 * @brief The RFC 8200 sec 4.5 reassembly tables, in the caller's borrow.
 *
 * Three tables: one datagram entry per packet being reassembled, one fragment entry per held
 * fragment, and the RFC 815 hole list that says which octets are still missing. Every entry is a
 * function of the one pointer it is handed: the operand block, the context and the tables are all
 * regions of that borrow, at compile-time offsets, and no entry reads or writes a byte outside it.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip6_reass.h"
#include "src/common_defines.h"
#include "src/ip/ipv6_defines.h"

IDEMIP_BEGIN_DECLS

// What a datagram entry is doing. Only HOLDING takes fragments; the other three take none and hold
// their pinned descriptors until the caller walks them out and drops the entry. RFC 8200 sec 4.5
// makes the last three distinct: a completed packet's further fragments "should be processed
// independently", an aged-out one is answered with Time Exceeded, and an overlapped one with nothing.
#define IP6_REASS_HOLDING 0u   ///< fragments are held and the hole list is not empty
#define IP6_REASS_COMPLETE 1u  ///< the hole list emptied, RFC 815 sec 3 step eight
#define IP6_REASS_EXPIRED 2u   ///< past the RFC 8200 sec 4.5 60-second bound
#define IP6_REASS_ABANDONED 3u ///< sec 4.5's fifth error condition, or a completed packet aged out

// What a scan of a datagram's held fragments found the arriving one to be.
#define IP6_REASS_SCAN_CLEAR 0u   ///< it reaches no held fragment
#define IP6_REASS_SCAN_DUP 1u     ///< same Fragment Offset and same length as one already held
#define IP6_REASS_SCAN_OVERLAP 2u ///< it reaches into one, which sec 4.5 abandons the packet for

// RFC 815 sec 3: "hole.last equals infinity. (Infinity is presumably implemented by a very large
// integer ... of the implementor's choice.)" The Fragmentable Part reaches at most the Payload
// Length RFC 8200 sec 3 carries, so the last octet a hole can name is inside sixteen bits.
#define IP6_REASS_INFINITY 0xFFFFu

// One packet being reassembled. RFC 8200 sec 4.5 keys it on "the same IPv6 Source Address, IPv6
// Destination Address, and Fragment Identification", and holds it for 60 seconds from the first
// arriving fragment. next_hdr and total_len come from the offset-zero fragment, which sec 4.5 makes
// the reassembled packet's.
typedef struct
{
    uint32_t ident;
    uint32_t deadline_ms;
    uint8_t src[IDEMIP_IP6_ADDR_LEN];
    uint8_t dst[IDEMIP_IP6_ADDR_LEN];
    uint16_t total_len;
    uint16_t frag_end; ///< where the M flag zero fragment put the end of the Fragmentable Part
    uint8_t frag_head;
    uint8_t hole_head;
    uint8_t frag_count;
    uint8_t next_hdr;
    idemip_bool first_seen; ///< the Fragment Offset zero fragment has arrived
    idemip_bool last_seen;  ///< the M flag zero fragment has arrived, so frag_end stands
    idemip_bool used;
    uint8_t state; ///< IP6_REASS_HOLDING, COMPLETE, EXPIRED or ABANDONED
    uint8_t pad[12];
} Ip6ReassDatagram;

// One held fragment. The octets stay in the buffer the engine wrote them to, pinned by desc.
typedef struct
{
    uint16_t desc;
    uint16_t offset;  ///< Fragment Offset, in octets (RFC 8200 sec 4.5)
    uint16_t len;     ///< octets of fragment data following the Fragment header
    uint16_t hdr_len; ///< octets from the fragment packet's IPv6 header to its fragment data
    uint8_t next;
    idemip_bool used;
    uint8_t pad[6];
} Ip6ReassFrag;

// One hole descriptor, at RFC 815 sec 3's own eight octets: "To store hole.first and hole.last will
// presumably require two octets each. An additional two octets will be required to thread together
// the entries on the hole descriptor list."
typedef struct
{
    uint16_t first;
    uint16_t last;
    uint8_t next;
    idemip_bool used;
    uint8_t pad[2];
} Ip6ReassHole;

// The running context. ready is the mark clear leaves, so a borrow no one cleared is refused.
typedef struct
{
    uint32_t now_ms;
    uint8_t datagrams;
    uint8_t frags;
    uint8_t holes;
    idemip_bool ready;
} Ip6ReassCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_IP6_REASS_OFF_CTX, sizeof(Ip6ReassCtx), IDEMIP_IP6_REASS_OFF_END, "ip6_reass's context");

// An index is (i << SHIFT), so each entry is exactly its width.
static_assert(sizeof(Ip6ReassDatagram) == (1u << IDEMIP_IP6_REASS_DATAGRAM_ENTRY_SHIFT),
              "a datagram entry must be 1 << IDEMIP_IP6_REASS_DATAGRAM_ENTRY_SHIFT wide");
static_assert(sizeof(Ip6ReassFrag) == (1u << IDEMIP_IP6_REASS_FRAG_ENTRY_SHIFT),
              "a fragment entry must be 1 << IDEMIP_IP6_REASS_FRAG_ENTRY_SHIFT wide");
static_assert(sizeof(Ip6ReassHole) == (1u << IDEMIP_IP6_REASS_HOLE_ENTRY_SHIFT),
              "a hole entry must be 1 << IDEMIP_IP6_REASS_HOLE_ENTRY_SHIFT wide (RFC 815 sec 3)");
// The caller's borrow, split: the operand block, the context, then the three tables. ip6_reass.h
// publishes the offsets; these two asserts prove the span covers them before anything runs. The first
// keeps the context inside the region ahead of the datagram table, the second the whole map inside
// the borrow.
static_assert(IDEMIP_IP6_REASS_OFF_CTX + sizeof(Ip6ReassCtx) <= IDEMIP_IP6_REASS_OFF_DATAGRAMS,
              "IDEMIP_IP6_REASS_CTX_BYTES is short of the operand block and the context - raise it in "
              "idemip_config.h");
static_assert(IDEMIP_IP6_REASS_OFF_END <= IDEMIP_IP6_REASS_BORROW,
              "IDEMIP_IP6_REASS_BORROW is short of the map - raise IDEMIP_IP6_REASS_CTX_BYTES in "
              "idemip_config.h");

// Every table index counts the entries the borrow holds, so IDEMIP_IP6_REASS_NONE names none of them.
static_assert(IDEMIP_IP6_REASS_DATAGRAMS < IDEMIP_IP6_REASS_NONE && IDEMIP_IP6_REASS_FRAGS < IDEMIP_IP6_REASS_NONE &&
                  IDEMIP_IP6_REASS_HOLES < IDEMIP_IP6_REASS_NONE,
              "a table is wider than the index a result member carries");

// A datagram opens with one hole and each fragment splits at most one hole in two, so the list holds
// at most one descriptor per datagram plus one per fragment. The carve below writes the first
// replacement where the hole was, so that count is the peak and not a step below it.
static_assert(IDEMIP_IP6_REASS_HOLES >= IDEMIP_IP6_REASS_DATAGRAMS + IDEMIP_IP6_REASS_FRAGS,
              "the hole table must hold one descriptor per datagram plus one per fragment (RFC 815 sec 3)");

// The regions, at their offsets in the caller's borrow.
#define IP6_REASS_IO(w) IDEMIP_IP6_REASS_IO(w)
#define IP6_REASS_CTX(w) ((Ip6ReassCtx *)(void *)((w) + IDEMIP_IP6_REASS_OFF_CTX))
#define IP6_REASS_DATAGRAM_AT(w, i)                                                                                    \
    ((Ip6ReassDatagram *)(void *)((w) + IDEMIP_IP6_REASS_OFF_DATAGRAMS +                                               \
                                 ((size_t)(i) << IDEMIP_IP6_REASS_DATAGRAM_ENTRY_SHIFT)))
#define IP6_REASS_FRAG_AT(w, i)                                                                                        \
    ((Ip6ReassFrag *)(void *)((w) + IDEMIP_IP6_REASS_OFF_FRAGS + ((size_t)(i) << IDEMIP_IP6_REASS_FRAG_ENTRY_SHIFT)))
#define IP6_REASS_HOLE_AT(w, i)                                                                                        \
    ((Ip6ReassHole *)(void *)((w) + IDEMIP_IP6_REASS_OFF_HOLES + ((size_t)(i) << IDEMIP_IP6_REASS_HOLE_ENTRY_SHIFT)))

// Octets the context and the three tables span, which is what clear zeroes.
#define IP6_REASS_STATE_BYTES (IDEMIP_IP6_REASS_OFF_END - IDEMIP_IP6_REASS_OFF_CTX)

// Octets from a fragment packet's IPv6 header to its fragment data, less the unfragmentable part:
// the fixed header of RFC 8200 sec 3 and the Fragment header of sec 4.5.
#define IP6_REASS_FIXED (IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_FRAG_HDR_LEN)

// --- the tables ------------------------------------------------------------

// The first free entry of a table, or IDEMIP_IP6_REASS_NONE. The context's count answers a full table
// without a walk, and otherwise the walk is bounded by the compile-time count.
static uint8_t ip6_reass_take_datagram(uint8_t *work)
{
    if (IP6_REASS_CTX(work)->datagrams >= IDEMIP_IP6_REASS_DATAGRAMS)
    {
        return IDEMIP_IP6_REASS_NONE;
    }
    // The empty search is written out because a caller must be able to read a table with nothing left
    // in it, and it is not measured: ip6_reass_input answers BUSY at the count before it asks, and the
    // count and the table are the same thing.
    for (uint8_t i = 0u; i < IDEMIP_IP6_REASS_DATAGRAMS; i++) // GCOVR_EXCL_BR_LINE
    {
        if (!IP6_REASS_DATAGRAM_AT(work, i)->used)
        {
            memset(IP6_REASS_DATAGRAM_AT(work, i), 0, sizeof(Ip6ReassDatagram));
            IP6_REASS_DATAGRAM_AT(work, i)->used = IDEMIP_TRUE;
            IP6_REASS_DATAGRAM_AT(work, i)->frag_head = IDEMIP_IP6_REASS_NONE;
            IP6_REASS_DATAGRAM_AT(work, i)->hole_head = IDEMIP_IP6_REASS_NONE;
            IP6_REASS_CTX(work)->datagrams++;
            return i;
        }
    }
    return IDEMIP_IP6_REASS_NONE; // GCOVR_EXCL_LINE
}

static uint8_t ip6_reass_take_frag(uint8_t *work)
{
    if (IP6_REASS_CTX(work)->frags >= IDEMIP_IP6_REASS_FRAGS)
    {
        return IDEMIP_IP6_REASS_NONE;
    }
    // Not measured, for the reason written at the datagram search above.
    for (uint8_t i = 0u; i < IDEMIP_IP6_REASS_FRAGS; i++) // GCOVR_EXCL_BR_LINE
    {
        if (!IP6_REASS_FRAG_AT(work, i)->used)
        {
            memset(IP6_REASS_FRAG_AT(work, i), 0, sizeof(Ip6ReassFrag));
            IP6_REASS_FRAG_AT(work, i)->used = IDEMIP_TRUE;
            IP6_REASS_FRAG_AT(work, i)->next = IDEMIP_IP6_REASS_NONE;
            IP6_REASS_CTX(work)->frags++;
            return i;
        }
    }
    return IDEMIP_IP6_REASS_NONE; // GCOVR_EXCL_LINE
}

static uint8_t ip6_reass_take_hole(uint8_t *work)
{
    // Not measured, for the reason idemip_config.h states beside IDEMIP_IP6_REASS_HOLES: RFC 815 opens
    // a packet with one hole and steps four through six leave at most one more per fragment, so D
    // packets holding N fragments reach at most D + N descriptors, and the table is sized at or above
    // that. Both bounds are enforced ahead of every call. The count is written because a table that
    // can be full must be read as though it is.
    if (IP6_REASS_CTX(work)->holes >= IDEMIP_IP6_REASS_HOLES) // GCOVR_EXCL_BR_LINE
    {
        return IDEMIP_IP6_REASS_NONE; // GCOVR_EXCL_LINE
    }
    for (uint8_t i = 0u; i < IDEMIP_IP6_REASS_HOLES; i++) // GCOVR_EXCL_BR_LINE
    {
        if (!IP6_REASS_HOLE_AT(work, i)->used)
        {
            memset(IP6_REASS_HOLE_AT(work, i), 0, sizeof(Ip6ReassHole));
            IP6_REASS_HOLE_AT(work, i)->used = IDEMIP_TRUE;
            IP6_REASS_HOLE_AT(work, i)->next = IDEMIP_IP6_REASS_NONE;
            IP6_REASS_CTX(work)->holes++;
            return i;
        }
    }
    return IDEMIP_IP6_REASS_NONE; // GCOVR_EXCL_LINE
}

// RFC 8200 sec 4.5: "all the fragments that have been received for that packet must be discarded".
// The fragment and hole entries go back to their tables and the datagram entry goes free.
static void ip6_reass_put_datagram(uint8_t *work, uint8_t d)
{
    Ip6ReassDatagram *dg = IP6_REASS_DATAGRAM_AT(work, d);
    Ip6ReassCtx *ctx = IP6_REASS_CTX(work);
    uint8_t i = dg->frag_head;
    while (i != IDEMIP_IP6_REASS_NONE)
    {
        uint8_t next = IP6_REASS_FRAG_AT(work, i)->next;
        IP6_REASS_FRAG_AT(work, i)->used = IDEMIP_FALSE;
        ctx->frags--;
        i = next;
    }
    i = dg->hole_head;
    while (i != IDEMIP_IP6_REASS_NONE)
    {
        uint8_t next = IP6_REASS_HOLE_AT(work, i)->next;
        IP6_REASS_HOLE_AT(work, i)->used = IDEMIP_FALSE;
        ctx->holes--;
        i = next;
    }
    memset(dg, 0, sizeof(Ip6ReassDatagram));
    ctx->datagrams--;
}

// RFC 8200 sec 4.5: "An original packet is reassembled only from fragment packets that have the same
// Source Address, Destination Address, and Fragment Identification." An abandoned entry still matches
// its key, because RFC 5722 sec 4 discards "any constituent fragments, including those not yet
// received", so a later fragment of a poisoned datagram must not open a fresh reassembly.
static uint8_t ip6_reass_match(uint8_t *work, const uint8_t *src, const uint8_t *dst, uint32_t ident)
{
    for (uint8_t i = 0u; i < IDEMIP_IP6_REASS_DATAGRAMS; i++)
    {
        const Ip6ReassDatagram *dg = IP6_REASS_DATAGRAM_AT(work, i);
        if (dg->used && (dg->state == IP6_REASS_HOLDING || dg->state == IP6_REASS_ABANDONED) && dg->ident == ident &&
            idemip_bytes_eq(dg->src, src, IDEMIP_IP6_ADDR_LEN) && idemip_bytes_eq(dg->dst, dst, IDEMIP_IP6_ADDR_LEN))
        {
            return i;
        }
    }
    return IDEMIP_IP6_REASS_NONE;
}

// What the arriving fragment [first, end) is against the ones already held, and where it belongs in
// the list. RFC 8200 sec 4.5 abandons the packet when fragments "overlap with any other fragments
// being reassembled for the same packet", and permits the one exception: "an implementation may
// choose to detect this case and drop exact duplicate fragments while keeping the other fragments".
// A network that duplicates a packet delivers the same fragment twice, so taking that exception is
// what keeps reassembly working under ordinary duplication.
static uint8_t ip6_reass_scan(uint8_t *work, uint8_t d, uint16_t offset, uint16_t frag_len, uint8_t *prev_out)
{
    const Ip6ReassDatagram *dg = IP6_REASS_DATAGRAM_AT(work, d);
    uint32_t first = offset;
    uint32_t end = (uint32_t)offset + (uint32_t)frag_len;
    uint8_t prev = IDEMIP_IP6_REASS_NONE;
    uint8_t cur = dg->frag_head;
    while (cur != IDEMIP_IP6_REASS_NONE)
    {
        const Ip6ReassFrag *fr = IP6_REASS_FRAG_AT(work, cur);
        if (fr->offset == offset && fr->len == frag_len)
        {
            return IP6_REASS_SCAN_DUP;
        }
        if (first < (uint32_t)fr->offset + (uint32_t)fr->len && (uint32_t)fr->offset < end)
        {
            return IP6_REASS_SCAN_OVERLAP;
        }
        if (fr->offset < offset)
        {
            prev = cur; // the list rises with Fragment Offset, so the new entry goes behind this one
        }
        cur = fr->next;
    }
    *prev_out = prev;
    return IP6_REASS_SCAN_CLEAR;
}

// RFC 815 sec 3 steps one through seven, over one datagram's hole list. A hole the fragment reaches
// is deleted, and step five puts back the part in front of the fragment and step six the part behind
// it, the second only if "fragment.more fragments is true". The fragment is [first, end), so RFC
// 815's fragment.last is end - 1 and its two tests read as end <= hole.first and end <= hole.last.
// Returns false when the second replacement has no free descriptor.
static idemip_bool ip6_reass_carve(uint8_t *work, uint8_t d, uint32_t first, uint32_t end, idemip_bool more)
{
    Ip6ReassDatagram *dg = IP6_REASS_DATAGRAM_AT(work, d);
    uint8_t prev = IDEMIP_IP6_REASS_NONE;
    uint8_t cur = dg->hole_head;
    while (cur != IDEMIP_IP6_REASS_NONE)
    {
        Ip6ReassHole *h = IP6_REASS_HOLE_AT(work, cur);
        uint8_t next = h->next;
        uint32_t hole_first = h->first;
        uint32_t hole_last = h->last;
        if (first > hole_last || end <= hole_first)
        {
            prev = cur; // steps two and three: no reach, so the hole stands
            cur = next;
            continue;
        }
        idemip_bool head = (first > hole_first) ? IDEMIP_TRUE : IDEMIP_FALSE;  // step five
        idemip_bool tail = (end <= hole_last && more) ? IDEMIP_TRUE : IDEMIP_FALSE; // step six
        if (head)
        {
            h->first = (uint16_t)hole_first;
            h->last = (uint16_t)(first - 1u);
        }
        else if (tail)
        {
            h->first = (uint16_t)end;
            h->last = (uint16_t)hole_last;
        }
        if (head && tail)
        {
            uint8_t h2 = ip6_reass_take_hole(work);
            // Not measured, for the reason written at ip6_reass_take_hole: the table is sized for one
            // hole per packet and one more per fragment, and both bounds are enforced before this
            // walk is entered. The arm is here because a walk that hands the list back must not hand
            // back one it has torn.
            if (h2 == IDEMIP_IP6_REASS_NONE) // GCOVR_EXCL_BR_LINE
            {
                return IDEMIP_FALSE; // GCOVR_EXCL_LINE
            }
            IP6_REASS_HOLE_AT(work, h2)->first = (uint16_t)end;
            IP6_REASS_HOLE_AT(work, h2)->last = (uint16_t)hole_last;
            IP6_REASS_HOLE_AT(work, h2)->next = next;
            IP6_REASS_HOLE_AT(work, cur)->next = h2;
            prev = h2;
        }
        else if (head || tail)
        {
            prev = cur;
        }
        else
        {
            // step four with nothing to put back: the fragment covers the hole whole
            if (prev == IDEMIP_IP6_REASS_NONE)
            {
                dg->hole_head = next;
            }
            else
            {
                IP6_REASS_HOLE_AT(work, prev)->next = next;
            }
            h->used = IDEMIP_FALSE;
            IP6_REASS_CTX(work)->holes--;
        }
        cur = next;
    }
    return IDEMIP_TRUE;
}

// RFC 815 sec 3 step six's reason for testing more fragments: "that hole descriptor which reaches
// from the last octet of the buffer to infinity can be discarded". The last fragment fixes the end
// of the Fragmentable Part at end, so no hole survives at or past it and none crosses it.
static void ip6_reass_trim(uint8_t *work, uint8_t d, uint32_t end)
{
    Ip6ReassDatagram *dg = IP6_REASS_DATAGRAM_AT(work, d);
    uint8_t prev = IDEMIP_IP6_REASS_NONE;
    uint8_t cur = dg->hole_head;
    while (cur != IDEMIP_IP6_REASS_NONE)
    {
        Ip6ReassHole *h = IP6_REASS_HOLE_AT(work, cur);
        uint8_t next = h->next;
        // A hole left past the reassembled length is the trailing one, and there is only ever the one:
        // every other hole lies between fragments that arrived, so it ends before the last of them.
        // That makes it the head of what is left by the time the trim walks, and the unlink from
        // further down the list is not measured. Neither is the clip below it: a hole that straddles
        // the end was reached by the last fragment's own carve, which cut it back to the piece in
        // front of the fragment - the last fragment sets no tail. Both are written because the trim
        // reads a list it did not build.
        if ((uint32_t)h->first >= end)
        {
            if (prev == IDEMIP_IP6_REASS_NONE) // GCOVR_EXCL_BR_LINE
            {
                dg->hole_head = next;
            }
            else
            {
                IP6_REASS_HOLE_AT(work, prev)->next = next; // GCOVR_EXCL_LINE
            }
            h->used = IDEMIP_FALSE;
            IP6_REASS_CTX(work)->holes--;
        }
        else
        {
            if ((uint32_t)h->last >= end) // GCOVR_EXCL_BR_LINE
            {
                h->last = (uint16_t)(end - 1u); // GCOVR_EXCL_LINE
            }
            prev = cur;
        }
        cur = next;
    }
}

// RFC 8200 sec 4.5: "PL.orig = PL.first - FL.first - 8 + (8 * FO.last) + FL.last", where "FO.last =
// Fragment Offset field of Fragment header of last fragment packet" and "FL.last = length of fragment
// following Fragment header of last fragment packet". The head of the list is the Fragment Offset
// zero fragment, whose hdr_len is PL.first - FL.first plus the fixed header, and frag_end is
// 8 * FO.last + FL.last, taken from the fragment that carried the M flag clear rather than from
// whichever entry the list ends on.
static uint32_t ip6_reass_payload_len(uint8_t *work, uint8_t d)
{
    const Ip6ReassDatagram *dg = IP6_REASS_DATAGRAM_AT(work, d);
    const Ip6ReassFrag *head = IP6_REASS_FRAG_AT(work, dg->frag_head);
    return (uint32_t)(head->hdr_len - IP6_REASS_FIXED) + (uint32_t)dg->frag_end;
}

// Whether any fragment already held reaches past @p end. RFC 8200 sec 4.5 computes the reassembled
// Payload Length from "the length and offset of the last fragment", so the M flag zero fragment fixes
// where the Fragmentable Part ends and nothing of the same packet can lie beyond it.
static idemip_bool ip6_reass_past_end(uint8_t *work, uint8_t d, uint32_t end)
{
    uint8_t cur = IP6_REASS_DATAGRAM_AT(work, d)->frag_head;
    while (cur != IDEMIP_IP6_REASS_NONE)
    {
        const Ip6ReassFrag *fr = IP6_REASS_FRAG_AT(work, cur);
        if ((uint32_t)fr->offset + (uint32_t)fr->len > end)
        {
            return IDEMIP_TRUE;
        }
        cur = fr->next;
    }
    return IDEMIP_FALSE;
}

// --- the arriving fragment -------------------------------------------------

// The sec 4.5 fields of one fragment packet, read once where the engine left it.
typedef struct
{
    uint32_t ident;
    uint32_t end;      ///< one past the last octet of this fragment in the Fragmentable Part
    uint16_t offset;   ///< Fragment Offset, in octets
    uint16_t frag_len; ///< FL, the fragment data following the Fragment header
    uint16_t hdr_len;  ///< octets from the IPv6 header to that data
    uint8_t next_hdr;  ///< Next Header of the Fragment header
    idemip_bool more;  ///< the M flag
} Ip6ReassFields;

// Reads the RFC 8200 sec 4.5 Fragment header and derives the fragment length "as derived from the
// fragment packet's Payload Length field". False when the packet cannot carry the header the caller
// named, or names more octets than the buffer holds, or seats its fragment data past sixteen bits.
static idemip_bool ip6_reass_fields(const uint8_t *pkt, size_t len, size_t fh, Ip6ReassFields *f)
{
    // The third test is not measured: sec 3's Payload Length is sixteen bits, so a packet cannot
    // carry the octets a Fragment header seated past IP6_REASS_INFINITY would need, and the second
    // test refuses it against the caller's own length first. It is written because the offsets this
    // unit holds are sixteen bits wide and a caller's offset is not.
    if (fh < IDEMIP_IPV6_HDR_LEN || fh + IDEMIP_IP6_FRAG_HDR_LEN > len ||
        fh + IDEMIP_IP6_FRAG_HDR_LEN > IP6_REASS_INFINITY) // GCOVR_EXCL_BR_LINE
    {
        return IDEMIP_FALSE;
    }
    size_t pl = (size_t)idemip_ip6_payload_len(pkt);
    if (pl + IDEMIP_IPV6_HDR_LEN > len)
    {
        return IDEMIP_FALSE;
    }
    size_t unfrag = fh - IDEMIP_IPV6_HDR_LEN; // the per-fragment headers between the two
    if (pl < unfrag + IDEMIP_IP6_FRAG_HDR_LEN)
    {
        return IDEMIP_FALSE;
    }
    const uint8_t *hdr = pkt + fh;
    f->frag_len = (uint16_t)(pl - unfrag - IDEMIP_IP6_FRAG_HDR_LEN);
    f->hdr_len = (uint16_t)(fh + IDEMIP_IP6_FRAG_HDR_LEN);
    f->offset = idemip_ip6_frag_offset_bytes(hdr);
    f->more = idemip_ip6_frag_more(hdr);
    f->ident = idemip_ip6_frag_ident(hdr);
    f->next_hdr = hdr[IDEMIP_IP6_FRAG_OFF_NEXT_HDR];
    f->end = (uint32_t)f->offset + (uint32_t)f->frag_len;
    return IDEMIP_TRUE;
}

// The whole of RFC 8200 sec 4.5 input: the three error conditions a fragment carries on its own, the
// match, the overlap rule, the RFC 815 hole list, and the completed packet's Payload Length.
static void ip6_reass_file(uint8_t *work)
{
    Ip6ReassIo *io = IP6_REASS_IO(work);
    const uint8_t *pkt = io->input_args.pkt;
    size_t len = io->input_args.len;
    Ip6ReassFields f;

    if (!ip6_reass_fields(pkt, len, io->input_args.frag_hdr, &f))
    {
        return; // the caller named a Fragment header this packet does not carry
    }

    // sec 4.5: "If the length of a fragment ... is not a multiple of 8 octets and the M flag of that
    // fragment is 1, then that fragment must be discarded and an ICMP Parameter Problem, Code 0,
    // message should be sent ... pointing to the Payload Length field".
    if (f.more && (f.frag_len & 7u) != 0u)
    {
        io->err = IDEMIP_IP6_REASS_ERR_PAYLOAD_LEN;
        return;
    }

    // sec 4.5: "If the length and offset of a fragment are such that the Payload Length of the packet
    // reassembled from that fragment would exceed 65,535 octets, then that fragment must be
    // discarded", pointing at the Fragment Offset field. The per-fragment headers only add to it.
    if (f.end > IDEMIP_IP6_PAYLOAD_MAX)
    {
        io->err = IDEMIP_IP6_REASS_ERR_FRAG_OFFSET;
        return;
    }

    // sec 4.5: "If the first fragment does not include all headers through an Upper-Layer header,
    // then that fragment should be discarded and an ICMP Parameter Problem, Code 3, message should be
    // sent ... with the Pointer field set to zero." The chain walk of sec 4 answers both halves: it
    // stops short when a header runs past the packet, and it ends on the upper-layer header.
    if (f.offset == 0u)
    {
        size_t bound = (size_t)idemip_ip6_payload_len(pkt) + IDEMIP_IPV6_HDR_LEN;
        IdemIpIp6Chain chain = idemip_ip6_walk(pkt, bound);
        if (!chain.ok || (chain.next_hdr != IDEMIP_IP6_NH_NONE && chain.offset >= bound))
        {
            io->err = IDEMIP_IP6_REASS_ERR_HEADER_CHAIN;
            return;
        }
    }

    const uint8_t *src = idemip_ip6_src(pkt);
    const uint8_t *dst = idemip_ip6_dst(pkt);
    // sec 4.5: "If the fragment is a whole datagram (that is, both the Fragment Offset field and the M
    // flag are zero), then it does not need any further reassembly and should be processed as a fully
    // reassembled packet ... Any other fragments that match this packet (i.e., the same IPv6 Source
    // Address, IPv6 Destination Address, and Fragment Identification) should be processed
    // independently." It joins nothing already held, so one of these cannot reach into a reassembly it
    // shares a key with.
    const idemip_bool atomic = (idemip_bool)(f.offset == 0u && !f.more);
    uint8_t d = atomic ? (uint8_t)IDEMIP_IP6_REASS_NONE : ip6_reass_match(work, src, dst, f.ident);
    uint8_t prev = IDEMIP_IP6_REASS_NONE;

    if (d != IDEMIP_IP6_REASS_NONE)
    {
        if (IP6_REASS_DATAGRAM_AT(work, d)->state == IP6_REASS_ABANDONED)
        {
            // RFC 5722 sec 4: the overlap discards "the entire datagram (and any constituent
            // fragments, including those not yet received)", so a later fragment of this key is
            // dropped rather than allowed to open a fresh reassembly. The entry holds the key until
            // its deadline retires it.
            return;
        }
        uint8_t scan = ip6_reass_scan(work, d, f.offset, f.frag_len, &prev);
        if (scan == IP6_REASS_SCAN_DUP)
        {
            return; // an exact duplicate is dropped and the rest of the packet kept, sec 4.5
        }
        if (scan == IP6_REASS_SCAN_OVERLAP)
        {
            // sec 4.5: "reassembly of that packet must be abandoned and all the fragments that have
            // been received for that packet must be discarded, and no ICMP error messages should be
            // sent". The entry holds its pinned descriptors until the caller walks and drops it.
            IP6_REASS_DATAGRAM_AT(work, d)->state = IP6_REASS_ABANDONED;
            io->err = IDEMIP_IP6_REASS_ERR_OVERLAP;
            io->datagram = d;
            io->frag_count = IP6_REASS_DATAGRAM_AT(work, d)->frag_count;
            return;
        }
        // The M flag zero fragment fixes where the Fragmentable Part ends, so a fragment held past
        // that end, a fragment arriving past it, or a second last fragment naming a different one is a
        // packet that cannot be reassembled. sec 4.5's disposition for that is the one it gives
        // overlap: "reassembly of that packet must be abandoned and all the fragments that have been
        // received for that packet must be discarded, and no ICMP error messages should be sent."
        Ip6ReassDatagram *dg = IP6_REASS_DATAGRAM_AT(work, d);
        idemip_bool inconsistent = IDEMIP_FALSE;
        //
        // The second last fragment naming a different end is written out because sec 4.5 fixes the
        // length there and two fragments cannot fix it twice, and the equal case is not measured: a
        // second M-zero fragment ending where the first one did begins at a multiple of eight below
        // that end, so it is either the same fragment again, which the duplicate above drops, or one
        // covering octets already held, which the overlap above abandons. Neither reaches here.
        if (!f.more)
        {
            inconsistent = (idemip_bool)(ip6_reass_past_end(work, d, f.end) ||
                                         (dg->last_seen &&                            // GCOVR_EXCL_BR_LINE
                                          (uint32_t)dg->frag_end != f.end)); // GCOVR_EXCL_BR_LINE
        }
        else if (dg->last_seen && f.end > (uint32_t)dg->frag_end)
        {
            inconsistent = IDEMIP_TRUE;
        }
        if (inconsistent)
        {
            dg->state = IP6_REASS_ABANDONED;
            io->err = IDEMIP_IP6_REASS_ERR_OVERLAP;
            io->datagram = d;
            io->frag_count = dg->frag_count;
            return;
        }
        // the same test against the Fragment Offset zero fragment's per-fragment headers, which fix
        // the reassembled Payload Length the formula in sec 4.5 computes
        if (dg->first_seen)
        {
            uint32_t unfrag = (uint32_t)(IP6_REASS_FRAG_AT(work, dg->frag_head)->hdr_len - IP6_REASS_FIXED);
            if (unfrag + f.end > IDEMIP_IP6_PAYLOAD_MAX)
            {
                io->err = IDEMIP_IP6_REASS_ERR_FRAG_OFFSET;
                return;
            }
        }
    }

    uint8_t fi = ip6_reass_take_frag(work);
    if (fi == IDEMIP_IP6_REASS_NONE)
    {
        io->status = IDEMIP_BUSY; // an entry frees when a datagram is dropped, so a retry can land
        return;
    }
    if (d == IDEMIP_IP6_REASS_NONE)
    {
        d = ip6_reass_take_datagram(work);
        if (d == IDEMIP_IP6_REASS_NONE)
        {
            IP6_REASS_FRAG_AT(work, fi)->used = IDEMIP_FALSE;
            IP6_REASS_CTX(work)->frags--;
            io->status = IDEMIP_BUSY;
            return;
        }
        uint8_t h = ip6_reass_take_hole(work);
        // Not measured, for the reason written at ip6_reass_take_hole: the table holds one opening
        // hole for every packet on top of one per fragment. The packet and the fragment entry it just
        // took both go back rather than being left half-open.
        if (h == IDEMIP_IP6_REASS_NONE) // GCOVR_EXCL_BR_LINE
        {
            // GCOVR_EXCL_START
            IP6_REASS_FRAG_AT(work, fi)->used = IDEMIP_FALSE;
            IP6_REASS_CTX(work)->frags--;
            ip6_reass_put_datagram(work, d);
            io->status = IDEMIP_BUSY;
            return;
            // GCOVR_EXCL_STOP
        }
        // RFC 815 sec 3: "one entry in its hole descriptor list, the entry which describes the
        // datagram as being completely missing"
        IP6_REASS_HOLE_AT(work, h)->first = 0u;
        IP6_REASS_HOLE_AT(work, h)->last = IP6_REASS_INFINITY;
        Ip6ReassDatagram *fresh = IP6_REASS_DATAGRAM_AT(work, d);
        fresh->hole_head = h;
        fresh->ident = f.ident;
        memcpy(fresh->src, src, IDEMIP_IP6_ADDR_LEN);
        memcpy(fresh->dst, dst, IDEMIP_IP6_ADDR_LEN);
        // sec 4.5: 60 seconds "of the reception of the first-arriving fragment of that packet"
        fresh->deadline_ms = IP6_REASS_CTX(work)->now_ms + IDEMIP_IP6_REASS_MAXAGE_MS;
    }

    Ip6ReassDatagram *dg = IP6_REASS_DATAGRAM_AT(work, d);
    Ip6ReassFrag *fr = IP6_REASS_FRAG_AT(work, fi);
    fr->desc = io->input_args.desc;
    fr->offset = f.offset;
    fr->len = f.frag_len;
    fr->hdr_len = f.hdr_len;
    if (prev == IDEMIP_IP6_REASS_NONE)
    {
        fr->next = dg->frag_head;
        dg->frag_head = fi;
    }
    else
    {
        fr->next = IP6_REASS_FRAG_AT(work, prev)->next;
        IP6_REASS_FRAG_AT(work, prev)->next = fi;
    }
    dg->frag_count++;

    // sec 4.5: "Only those headers in the Offset zero fragment packet are retained", and "The Next
    // Header field of the last header of the Per-Fragment headers is obtained from the Next Header
    // field of the first fragment's Fragment header."
    if (f.offset == 0u)
    {
        dg->next_hdr = f.next_hdr;
        dg->first_seen = IDEMIP_TRUE;
    }
    // "FO.last" and "FL.last" come from the fragment packet whose M flag is zero, so that is where the
    // Fragmentable Part ends and what the sec 4.5 Payload Length formula reads.
    if (!f.more)
    {
        dg->frag_end = (uint16_t)f.end;
        dg->last_seen = IDEMIP_TRUE;
    }

    io->datagram = d;
    io->frag_count = dg->frag_count;
    io->next_hdr = dg->next_hdr;

    // Not measured, for the reason written at ip6_reass_take_hole: the walk cannot run the table out.
    // The arm is here because a torn hole list describes a packet that can never be told apart from a
    // complete one, so the packet is given up rather than reassembled from a list that lies.
    if (!ip6_reass_carve(work, d, (uint32_t)f.offset, f.end, f.more)) // GCOVR_EXCL_BR_LINE
    {
        // GCOVR_EXCL_START
        dg->state = IP6_REASS_ABANDONED;
        return;
        // GCOVR_EXCL_STOP
    }
    if (!f.more)
    {
        ip6_reass_trim(work, d, f.end);
    }

    if (dg->hole_head == IDEMIP_IP6_REASS_NONE) // RFC 815 sec 3 step eight
    {
        uint32_t total = ip6_reass_payload_len(work, d);
        if (total > IDEMIP_IP6_PAYLOAD_MAX)
        {
            dg->state = IP6_REASS_ABANDONED;
            io->err = IDEMIP_IP6_REASS_ERR_FRAG_OFFSET;
            return;
        }
        dg->total_len = (uint16_t)total;
        dg->state = IP6_REASS_COMPLETE;
        io->total_len = dg->total_len;
        io->complete = IDEMIP_TRUE;
    }
    io->status = IDEMIP_OK;
}

// --- the entries -----------------------------------------------------------

// Zeroes the context and the three tables, then marks the borrow this module's. The operand block is
// the caller's and is left alone.
void idemip_ip6_reass_clear(uint8_t *work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    Ip6ReassIo *io = IP6_REASS_IO(work);
    memset(work + IDEMIP_IP6_REASS_OFF_CTX, 0, IP6_REASS_STATE_BYTES);
    IP6_REASS_CTX(work)->ready = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

// A table with no free entry is BUSY: one frees when a datagram is dropped after completing or
// ageing out, so the same fragment lands on a later tick. Everything sec 4.5 says to discard is ERR
// with err naming the ICMP answer, since no retry of that fragment can ever be taken.
void idemip_ip6_reass_input(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6ReassIo *io = IP6_REASS_IO(work);
    Ip6ReassCtx *ctx = IP6_REASS_CTX(work);
    io->status = IDEMIP_ERR;
    io->err = IDEMIP_IP6_REASS_ERR_NONE;
    io->complete = IDEMIP_FALSE;
    io->datagram = IDEMIP_IP6_REASS_NONE;
    io->frag_count = 0u;
    io->next_hdr = 0u;
    io->total_len = 0u;
    if (!ctx->ready || io->input_args.pkt == NULL || io->input_args.len < IDEMIP_IPV6_HDR_LEN)
    {
        return;
    }
    ctx->now_ms = io->input_args.now_ms;
    ip6_reass_file(work);
}

// RFC 8200 sec 4.5, whose Fragmentable Part "is constructed from the fragments following the Fragment
// headers", each fragment's "relative position in Fragmentable Part is computed from its Fragment
// Offset value". The list rises with Fragment Offset, so index is that position.
void idemip_ip6_reass_frag_at(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6ReassIo *io = IP6_REASS_IO(work);
    const Ip6ReassCtx *ctx = IP6_REASS_CTX(work);
    io->status = IDEMIP_ERR;
    io->frag_desc = 0u;
    io->frag_offset = 0u;
    io->frag_len = 0u;
    io->frag_hdr_len = 0u;
    if (!ctx->ready || io->frag_args.datagram >= IDEMIP_IP6_REASS_DATAGRAMS ||
        io->frag_args.index >= IDEMIP_IP6_REASS_FRAGS)
    {
        return;
    }
    const Ip6ReassDatagram *dg = IP6_REASS_DATAGRAM_AT(work, io->frag_args.datagram);
    if (!dg->used || io->frag_args.index >= dg->frag_count)
    {
        return;
    }
    uint8_t cur = dg->frag_head;
    for (uint8_t i = 0u; i < io->frag_args.index; i++)
    {
        cur = IP6_REASS_FRAG_AT(work, cur)->next;
    }
    const Ip6ReassFrag *fr = IP6_REASS_FRAG_AT(work, cur);
    io->frag_desc = fr->desc;
    io->frag_offset = fr->offset;
    io->frag_len = fr->len;
    io->frag_hdr_len = fr->hdr_len;
    io->status = IDEMIP_OK;
}

// RFC 8200 sec 4.5, which discards "all the fragments that have been received for that packet" when
// reassembly is abandoned. A datagram no entry holds is ERR: it names nothing to give up.
void idemip_ip6_reass_drop(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6ReassIo *io = IP6_REASS_IO(work);
    const Ip6ReassCtx *ctx = IP6_REASS_CTX(work);
    io->status = IDEMIP_ERR;
    if (!ctx->ready || io->drop_args.datagram >= IDEMIP_IP6_REASS_DATAGRAMS)
    {
        return;
    }
    if (!IP6_REASS_DATAGRAM_AT(work, io->drop_args.datagram)->used)
    {
        return;
    }
    ip6_reass_put_datagram(work, io->drop_args.datagram);
    io->status = IDEMIP_OK;
}

// RFC 8200 sec 4.5's 60-second bound. The sweep ages every entry and reports the first one waiting to
// be given up, with the Time Exceeded sec 4.5 answers it with when "the first fragment (i.e., the one
// with a Fragment Offset of zero) has been received". Nothing is freed here: the caller walks the
// fragments out to unpin them and calls drop, and the next sweep names the next one.
void idemip_ip6_reass_tick(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip6ReassIo *io = IP6_REASS_IO(work);
    Ip6ReassCtx *ctx = IP6_REASS_CTX(work);
    io->status = IDEMIP_ERR;
    io->expired = 0u;
    io->err = IDEMIP_IP6_REASS_ERR_NONE;
    io->datagram = IDEMIP_IP6_REASS_NONE;
    io->frag_count = 0u;
    if (!ctx->ready)
    {
        return;
    }
    ctx->now_ms = io->tick_args.now_ms;
    for (uint8_t i = 0u; i < IDEMIP_IP6_REASS_DATAGRAMS; i++)
    {
        Ip6ReassDatagram *dg = IP6_REASS_DATAGRAM_AT(work, i);
        if (!dg->used)
        {
            continue;
        }
        // the clock wraps, so the deadline is compared as a signed difference
        if ((int32_t)(ctx->now_ms - dg->deadline_ms) >= 0)
        {
            if (dg->state == IP6_REASS_HOLDING)
            {
                dg->state = IP6_REASS_EXPIRED; // "insufficient fragments", so sec 4.5 answers it
            }
            else if (dg->state == IP6_REASS_COMPLETE)
            {
                dg->state = IP6_REASS_ABANDONED; // reassembled, so no sec 4.5 error is owed
            }
        }
        if (dg->state == IP6_REASS_EXPIRED || dg->state == IP6_REASS_ABANDONED)
        {
            if (io->expired == 0u)
            {
                io->datagram = i;
                io->frag_count = dg->frag_count;
                io->err = (dg->state == IP6_REASS_EXPIRED && dg->first_seen) ? IDEMIP_IP6_REASS_ERR_TIMEOUT
                                                                            : IDEMIP_IP6_REASS_ERR_NONE;
            }
            io->expired++;
        }
    }
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
