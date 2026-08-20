// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip6_frag.c
 * @brief The cursor RFC 8200 sec 4.5 walks a packet's Fragmentable Part with.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block and the context are both regions of that borrow, at compile-time offsets, and no entry reads
 * or writes a byte outside it and the caller's own two buffers.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip6_frag.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and every
// entry but clear refuses it.
#define IP6_FRAG_READY 0x49503646u

// The low three bits of an octet count, which the "8-octet units" of the Fragment Offset clears.
#define IP6_FRAG_UNIT_MASK ((uint16_t)(IDEMIP_IP6_EXT_UNIT - 1u))

// The split in progress: where the packet lies, what the chain walk found once, and how far the
// cursor has walked the Fragmentable Part.
typedef struct
{
    uint32_t ready;
    const uint8_t *pkt;
    uint32_t ident;
    uint16_t data_len;
    uint16_t cursor;
    uint16_t chunk;
    uint16_t unfrag_len;
    uint16_t nh_off;
    uint16_t index;
    uint8_t next_hdr;
    idemip_bool split;
    idemip_bool open;
    idemip_bool done;
} Ip6FragCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_IP6_FRAG_OFF_CTX, sizeof(Ip6FragCtx), IDEMIP_IP6_FRAG_BORROW, "ip6_frag's context");

// The head region carries the operand block and the context, and this unit holds no table, so the
// pair is the whole borrow. ip6_frag.h publishes the offsets; the assert proves the span covers them
// before anything runs.
static_assert(IDEMIP_IP6_FRAG_OFF_CTX + sizeof(Ip6FragCtx) <= IDEMIP_IP6_FRAG_BORROW,
              "IDEMIP_IP6_FRAG_BORROW is short of the operand block and the context - raise it in "
              "idemip_config.h");

// The context starts at the end of the operand block, so its offset carries the borrow's alignment.
static_assert((IDEMIP_IP6_FRAG_CTX_BYTES & (IDEMIP_ALIGN - 1u)) == 0u,
              "IDEMIP_IP6_FRAG_CTX_BYTES must be a multiple of IDEMIP_ALIGN");

// The regions, at their offsets in the caller's borrow.
#define IP6_FRAG_IO(w) IDEMIP_IP6_FRAG_IO(w)
#define IP6_FRAG_CTX(w) ((Ip6FragCtx *)(void *)((w) + IDEMIP_IP6_FRAG_OFF_CTX))

// A borrow clear has not run on holds no mark, so every entry but clear refuses it.
static idemip_bool ip6_frag_ready(uint8_t *restrict work)
{
    return (idemip_bool)(IP6_FRAG_CTX(work)->ready == IP6_FRAG_READY);
}

// --- the chain walk (RFC 8200 sec 4.5) -------------------------------------

// Where the Per-Fragment headers end and where the Next Header field of the last of them sits.
typedef struct
{
    size_t unfrag;  ///< octets the Per-Fragment headers span, the fixed header included
    size_t nh_off;  ///< the Next Header octet of the last of them, which becomes 44
    size_t ext_end; ///< octets to the upper-layer header, so ext_end - unfrag is what must ride along
    idemip_bool fragmented;
    idemip_bool ok;
} Ip6FragChain;

// "The Per-Fragment headers must consist of the IPv6 header plus any extension headers that must be
// processed by nodes en route to the destination, that is, all headers up to and including the
// Routing header if present, else the Hop-by-Hop Options header if present, else no extension
// headers." The walk therefore records the end of the last Routing header it steps, or of a
// Hop-by-Hop Options header when no Routing header follows, and keeps going to the upper-layer
// header so the caller can be told what must ride in the first fragment.
//
// idemip_ip6_walk reports where the chain ends and whether a Fragment header is in it, but not where
// the Routing header sat, which is the one thing this split turns on, so the chain is stepped here.
static Ip6FragChain ip6_frag_walk(const uint8_t *pkt, size_t len)
{
    Ip6FragChain c;
    c.unfrag = IDEMIP_IPV6_HDR_LEN;
    c.nh_off = IDEMIP_IP6_OFF_NEXT_HDR;
    c.ext_end = IDEMIP_IPV6_HDR_LEN;
    c.fragmented = IDEMIP_FALSE;
    c.ok = IDEMIP_FALSE;

    size_t off = IDEMIP_IPV6_HDR_LEN;
    uint8_t nh = idemip_ip6_next_hdr(pkt);
    uint16_t hops = 0u;
    while (idemip_ip6_nh_is_ext(nh))
    {
        if (nh == IDEMIP_IP6_NH_FRAGMENT)
        {
            c.fragmented = IDEMIP_TRUE;
            return c;
        }
        // sec 4.1: the Hop-by-Hop Options header "must appear immediately after an IPv6 header only".
        if (nh == IDEMIP_IP6_NH_HOPOPT && hops != 0u)
        {
            return c;
        }
        if (off + IDEMIP_IP6_EXT_UNIT > len)
        {
            return c;
        }
        const size_t step = idemip_ip6_ext_len(pkt + off);
        if (off + step > len)
        {
            return c;
        }
        if (nh == IDEMIP_IP6_NH_ROUTING || (nh == IDEMIP_IP6_NH_HOPOPT && hops == 0u))
        {
            c.unfrag = off + step;
            c.nh_off = off;
        }
        nh = idemip_ip6_ext_next_hdr(pkt + off);
        off += step;
        hops = (uint16_t)(hops + 1u);
    }
    c.ext_end = off;
    c.ok = IDEMIP_TRUE;
    return c;
}

// --- the split -------------------------------------------------------------

// A packet that fits the path MTU is sent as it is: sec 4.5 inserts a Fragment header only "In order
// to send a packet that is too large to fit in the MTU of the path to its destination". One that does
// not is cut, and everything the cut needs is measured here once.
static void ip6_frag_take(uint8_t *restrict work)
{
    Ip6FragIo *io = IP6_FRAG_IO(work);
    Ip6FragCtx *ctx = IP6_FRAG_CTX(work);
    const uint8_t *pkt = io->begin_args.pkt;
    const uint16_t mtu = io->begin_args.mtu;

    ctx->open = IDEMIP_FALSE;
    ctx->done = IDEMIP_FALSE;
    ctx->pkt = NULL;

    if (pkt == NULL || io->begin_args.len < IDEMIP_IPV6_HDR_LEN || idemip_ip6_version(pkt) != IDEMIP_IP6_VERSION)
    {
        io->err = IDEMIP_IP6_FRAG_ERR_HEADER;
        return;
    }
    const size_t pkt_len = (size_t)IDEMIP_IPV6_HDR_LEN + idemip_ip6_payload_len(pkt);
    if (pkt_len > io->begin_args.len)
    {
        io->err = IDEMIP_IP6_FRAG_ERR_HEADER;
        return;
    }
    if (mtu < IDEMIP_IPV6_MIN_MTU)
    {
        io->err = IDEMIP_IP6_FRAG_ERR_MTU;
        return;
    }

    ctx->pkt = pkt;
    ctx->ident = io->begin_args.ident;
    ctx->unfrag_len = IDEMIP_IPV6_HDR_LEN;
    ctx->nh_off = IDEMIP_IP6_OFF_NEXT_HDR;
    ctx->next_hdr = idemip_ip6_next_hdr(pkt);
    ctx->data_len = (uint16_t)(pkt_len - IDEMIP_IPV6_HDR_LEN);
    ctx->cursor = 0u;
    ctx->index = 0u;
    ctx->chunk = ctx->data_len;
    ctx->split = IDEMIP_FALSE;

    if (pkt_len > (size_t)mtu)
    {
        const Ip6FragChain c = ip6_frag_walk(pkt, pkt_len);
        if (c.fragmented)
        {
            ctx->pkt = NULL;
            io->err = IDEMIP_IP6_FRAG_ERR_FRAGMENTED;
            return;
        }
        if (!c.ok)
        {
            ctx->pkt = NULL;
            io->err = IDEMIP_IP6_FRAG_ERR_HEADER;
            return;
        }

        const size_t head = c.unfrag + IDEMIP_IP6_FRAG_HDR_LEN;
        if (head + IDEMIP_IP6_EXT_UNIT > (size_t)mtu)
        {
            ctx->pkt = NULL;
            io->err = IDEMIP_IP6_FRAG_ERR_HEADERS;
            return;
        }
        // "The lengths of the fragments must be chosen such that the resulting fragment packets fit
        // within the MTU", and each but the last "is an integer multiple of 8 octets long".
        const uint16_t chunk = (uint16_t)(((size_t)mtu - head) & ~(size_t)IP6_FRAG_UNIT_MASK);
        // "(3) Extension headers, if any, and the Upper-Layer header. These headers must be in the
        // first fragment." Their octets lead the Fragmentable Part, so the first fragment has to
        // reach past them and into the upper-layer header, never stop on the boundary between them.
        // A caller that knows the upper-layer header's own length names it; one that does not still
        // gets the octet that makes the difference between reaching it and not.
        const size_t upper = (io->begin_args.upper_hdr_len != 0u) ? (size_t)io->begin_args.upper_hdr_len : 1u;
        if ((size_t)chunk < (c.ext_end - c.unfrag) + upper)
        {
            ctx->pkt = NULL;
            io->err = IDEMIP_IP6_FRAG_ERR_HEADERS;
            return;
        }

        ctx->unfrag_len = (uint16_t)c.unfrag;
        ctx->nh_off = (uint16_t)c.nh_off;
        ctx->next_hdr = pkt[c.nh_off];
        ctx->data_len = (uint16_t)(pkt_len - c.unfrag);
        ctx->chunk = chunk;
        ctx->split = IDEMIP_TRUE;
    }

    ctx->open = IDEMIP_TRUE;
    io->split = ctx->split;
    io->unfrag_len = ctx->unfrag_len;
    io->next_hdr = ctx->next_hdr;
    io->status = IDEMIP_OK;
}

// --- one fragment packet ---------------------------------------------------

// "The Per-Fragment headers of the original packet, with the Payload Length of the original IPv6
// header changed to contain the length of this fragment packet only (excluding the length of the
// IPv6 header itself), and the Next Header field of the last header of the Per-Fragment headers
// changed to 44", then the Fragment header, then the fragment.
static void ip6_frag_emit(const Ip6FragCtx *ctx, uint8_t *out, uint16_t chunk, idemip_bool more)
{
    memcpy(out, ctx->pkt, ctx->unfrag_len);
    out[ctx->nh_off] = IDEMIP_IP6_NH_FRAGMENT;
    idemip_ip6_set_payload_len(
        out, (uint16_t)((ctx->unfrag_len - IDEMIP_IPV6_HDR_LEN) + IDEMIP_IP6_FRAG_HDR_LEN + chunk));
    idemip_ip6_frag_build(out + ctx->unfrag_len, ctx->next_hdr, ctx->cursor, more, ctx->ident);
    memcpy(out + ctx->unfrag_len + IDEMIP_IP6_FRAG_HDR_LEN, ctx->pkt + ctx->unfrag_len + ctx->cursor, chunk);
}

// The fragment packet the cursor stands on, into the caller's buffer.
static void ip6_frag_write(uint8_t *restrict work)
{
    Ip6FragIo *io = IP6_FRAG_IO(work);
    Ip6FragCtx *ctx = IP6_FRAG_CTX(work);
    uint8_t *out = io->next_args.out;

    if (!ctx->open)
    {
        io->err = IDEMIP_IP6_FRAG_ERR_STATE;
        return;
    }
    if (ctx->done)
    {
        io->err = IDEMIP_IP6_FRAG_ERR_DONE;
        return;
    }

    const uint16_t left = (uint16_t)(ctx->data_len - ctx->cursor);
    const uint16_t chunk = (uint16_t)((left > ctx->chunk) ? ctx->chunk : left);
    const uint16_t hdr_len =
        (uint16_t)(ctx->split ? (ctx->unfrag_len + IDEMIP_IP6_FRAG_HDR_LEN) : IDEMIP_IPV6_HDR_LEN);
    const uint16_t len = (uint16_t)(hdr_len + chunk);
    if (out == NULL || io->next_args.cap < (size_t)len)
    {
        io->err = IDEMIP_IP6_FRAG_ERR_ROOM;
        return;
    }

    const idemip_bool more = (idemip_bool)(((uint32_t)ctx->cursor + chunk < ctx->data_len) ? IDEMIP_TRUE : IDEMIP_FALSE);

    if (!ctx->split)
    {
        memcpy(out, ctx->pkt, len);
    }
    else
    {
        ip6_frag_emit(ctx, out, chunk, more);
    }

    io->index = ctx->index;
    io->offset = ctx->cursor;
    io->more = more;
    io->len = len;
    io->hdr_len = hdr_len;
    io->data_len = chunk;
    io->unfrag_len = ctx->unfrag_len;
    io->next_hdr = ctx->next_hdr;
    io->status = IDEMIP_OK;

    ctx->cursor = (uint16_t)(ctx->cursor + chunk);
    ctx->index = (uint16_t)(ctx->index + 1u);
    ctx->done = (idemip_bool)(ctx->cursor >= ctx->data_len);
}

// --- the entries -----------------------------------------------------------

void idemip_ip6_frag_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP6_FRAG_OFF_CTX, 0, (size_t)IDEMIP_IP6_FRAG_BORROW - (size_t)IDEMIP_IP6_FRAG_OFF_CTX);
    IP6_FRAG_CTX(work)->ready = IP6_FRAG_READY;
    IP6_FRAG_IO(work)->status = IDEMIP_OK;
}

void idemip_ip6_frag_begin(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip6FragIo *io = IP6_FRAG_IO(work);
    io->status = IDEMIP_ERR;
    io->err = IDEMIP_IP6_FRAG_ERR_STATE;
    io->split = IDEMIP_FALSE;
    io->more = IDEMIP_FALSE;
    io->index = 0u;
    io->offset = 0u;
    io->len = 0u;
    io->hdr_len = 0u;
    io->data_len = 0u;
    io->unfrag_len = 0u;
    io->next_hdr = IDEMIP_IP6_NH_NONE;
    if (!ip6_frag_ready(work))
    {
        return;
    }
    io->err = IDEMIP_IP6_FRAG_ERR_NONE;
    ip6_frag_take(work);
}

void idemip_ip6_frag_next(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip6FragIo *io = IP6_FRAG_IO(work);
    io->status = IDEMIP_ERR;
    io->err = IDEMIP_IP6_FRAG_ERR_STATE;
    io->more = IDEMIP_FALSE;
    io->index = 0u;
    io->offset = 0u;
    io->len = 0u;
    io->hdr_len = 0u;
    io->data_len = 0u;
    if (!ip6_frag_ready(work))
    {
        return;
    }
    io->err = IDEMIP_IP6_FRAG_ERR_NONE;
    ip6_frag_write(work);
}

IDEMIP_END_DECLS
