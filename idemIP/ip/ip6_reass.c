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

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV6

#include "idemIP/ip/ip6_reass.h"

IDEMIP_BEGIN_DECLS

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
    uint8_t frag_head;
    uint8_t hole_head;
    uint8_t frag_count;
    uint8_t next_hdr;
    idemip_bool first_seen; ///< the Fragment Offset zero fragment has arrived
    idemip_bool used;
    uint8_t pad[16];
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

// --- the entries -----------------------------------------------------------

// Zeroes the context and the three tables, then marks the borrow this module's. The operand block is
// the caller's and is left alone.
static void ip6_reass_clear(uint8_t *restrict work)
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

static void ip6_reass_input(uint8_t *restrict work)
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
    if (!ctx->ready || io->input_args.pkt == NULL || io->input_args.len < IDEMIP_IPV6_HDR_LEN)
    {
        return;
    }
    // PHASE 3: RFC 8200 sec 4.5 reassembly, matching a fragment on Source Address, Destination
    // Address and Fragment Identification, threading it into the RFC 815 hole list, and answering
    // the five sec 4.5 error conditions.
    io->status = IDEMIP_ERR;
}

static void ip6_reass_frag_at(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip6ReassIo *io = IP6_REASS_IO(work);
    Ip6ReassCtx *ctx = IP6_REASS_CTX(work);
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
    // PHASE 3: RFC 8200 sec 4.5, whose Fragmentable Part "is constructed from the fragments
    // following the Fragment headers", each fragment's "relative position in Fragmentable Part
    // computed from its Fragment Offset value".
    io->status = IDEMIP_ERR;
}

static void ip6_reass_drop(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip6ReassIo *io = IP6_REASS_IO(work);
    Ip6ReassCtx *ctx = IP6_REASS_CTX(work);
    io->status = IDEMIP_ERR;
    if (!ctx->ready || io->drop_args.datagram >= IDEMIP_IP6_REASS_DATAGRAMS)
    {
        return;
    }
    // PHASE 3: RFC 8200 sec 4.5, which discards "all the fragments that have been received for that
    // packet" when reassembly is abandoned.
    io->status = IDEMIP_ERR;
}

static void ip6_reass_tick(uint8_t *restrict work)
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
    if (!ctx->ready)
    {
        return;
    }
    // PHASE 3: RFC 8200 sec 4.5's 60-second bound, and the Time Exceeded it answers a datagram whose
    // Fragment Offset zero fragment had arrived with.
    io->status = IDEMIP_ERR;
}

const Ip6ReassNs Ip6Reass = {.clear = ip6_reass_clear,
                             .input = ip6_reass_input,
                             .frag_at = ip6_reass_frag_at,
                             .drop = ip6_reass_drop,
                             .tick = ip6_reass_tick};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6
