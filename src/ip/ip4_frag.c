// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_frag.c
 * @brief The cursor the RFC 791 sec 3.2 fragmentation procedure walks a datagram with.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block and the context are both regions of that borrow, at compile-time offsets, and no entry reads
 * or writes a byte outside it and the caller's own two buffers.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip4_frag.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and every
// entry but clear refuses it.
#define IP4_FRAG_READY 0x49503446u

// The low three bits of an octet count, which "NFB <- (MTU-IHL*4)/8" then "NFB*8" clears
// (RFC 791 sec 3.2). Masking them off is that pair of operations with no divide.
#define IP4_FRAG_UNIT_MASK ((uint16_t)(IDEMIP_IP4_FRAG_UNIT - 1u))

// The split in progress: where the datagram lies, what the header procedure computed once, and how
// far the cursor has walked its data.
typedef struct
{
    uint32_t ready;
    const uint8_t *dgram;
    uint16_t data_len;
    uint16_t cursor;
    uint16_t chunk0;
    uint16_t chunk;
    uint16_t units;
    uint16_t index;
    uint8_t hdr_len;
    uint8_t hdr2_len;
    idemip_bool omf;
    idemip_bool split;
    idemip_bool open;
    idemip_bool done;
} Ip4FragCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_IP4_FRAG_OFF_CTX, sizeof(Ip4FragCtx), IDEMIP_IP4_FRAG_BORROW, "ip4_frag's context");

// The head region carries the operand block and the context, and this unit holds no table, so the
// pair is the whole borrow. ip4_frag.h publishes the offsets; the assert proves the span covers them
// before anything runs.
static_assert(IDEMIP_IP4_FRAG_OFF_CTX + sizeof(Ip4FragCtx) <= IDEMIP_IP4_FRAG_BORROW,
              "IDEMIP_IP4_FRAG_BORROW is short of the operand block and the context - raise it in "
              "idemip_config.h");

// The context starts at the end of the operand block, so its offset carries the borrow's alignment.
static_assert((IDEMIP_IP4_FRAG_CTX_BYTES & (IDEMIP_ALIGN - 1u)) == 0u,
              "IDEMIP_IP4_FRAG_CTX_BYTES must be a multiple of IDEMIP_ALIGN");

// The regions, at their offsets in the caller's borrow.
#define IP4_FRAG_IO(w) IDEMIP_IP4_FRAG_IO(w)
#define IP4_FRAG_CTX(w) ((Ip4FragCtx *)(void *)((w) + IDEMIP_IP4_FRAG_OFF_CTX))

// A borrow clear has not run on holds no mark, so every entry but clear refuses it.
static idemip_bool ip4_frag_ready(uint8_t *work)
{
    return (idemip_bool)(IP4_FRAG_CTX(work)->ready == IP4_FRAG_READY);
}

// --- the option area (RFC 791 sec 3.1) -------------------------------------

// Walk the option area and copy the options the copied flag marks, returning how many octets they
// span. A null @p out counts them without writing, which is what step (9)'s "length of options not
// copied" is measured with.
//
// "There are two cases for the format of an option: Case 1: A single octet of option-type. Case 2:
// An option-type octet, an option-length octet, and the actual option-data octets. The option-length
// octet counts the option-type octet and the option-length octet as well as the option-data octets."
// End of Option List ends the walk and No Operation is the one other single-octet type; both read
// with the copied flag clear, so neither is ever copied.
static uint16_t ip4_frag_copy_options(const uint8_t *dgram, size_t hdr_len, uint8_t *out)
{
    uint16_t copied = 0u;
    size_t i = IDEMIP_IPV4_HDR_LEN;
    while (i < hdr_len)
    {
        const uint8_t type = dgram[i];
        if (type == IDEMIP_IP4_FRAG_OPT_EOL)
        {
            break;
        }
        size_t step = 1u;
        if (type != IDEMIP_IP4_FRAG_OPT_NOP)
        {
            if (i + 1u >= hdr_len)
            {
                break; // a length octet past the header, so nothing further is readable
            }
            step = (size_t)dgram[i + 1u];
            if (step < IDEMIP_IP4_FRAG_OPT_MIN_LEN || i + step > hdr_len)
            {
                break;
            }
        }
        if ((type & IDEMIP_IP4_FRAG_OPT_COPIED) != 0u)
        {
            if (out != NULL)
            {
                memcpy(out + copied, dgram + i, step);
            }
            copied = (uint16_t)(copied + step);
        }
        i += step;
    }
    return copied;
}

// --- the fragmentation test (RFC 791 sec 3.2) ------------------------------

// "IF TL =< MTU THEN Submit this datagram to the next step in datagram processing ELSE IF DF = 1
// THEN discard the datagram ELSE" cut it. Everything the cut needs is computed once here: the
// reduced header of step (9), and the "NFB*8" data octets of steps (3) and (4) for the first
// fragment and for every one after it.
static void ip4_frag_take(uint8_t *work)
{
    Ip4FragIo *io = IP4_FRAG_IO(work);
    Ip4FragCtx *ctx = IP4_FRAG_CTX(work);
    const uint8_t *dgram = io->begin_args.dgram;
    const uint16_t mtu = io->begin_args.mtu;

    ctx->open = IDEMIP_FALSE;
    ctx->done = IDEMIP_FALSE;
    ctx->dgram = NULL;

    if (dgram == NULL || io->begin_args.len < IDEMIP_IPV4_HDR_LEN ||
        idemip_ip4_verify(dgram, io->begin_args.len) != IDEMIP_OK)
    {
        io->err = IDEMIP_IP4_FRAG_ERR_HEADER;
        return;
    }
    if (mtu < IDEMIP_IP4_MIN_FORWARD_MTU)
    {
        io->err = IDEMIP_IP4_FRAG_ERR_MTU;
        return;
    }

    const uint16_t total_len = idemip_ip4_total_len(dgram);
    const uint8_t hdr_len = (uint8_t)idemip_ip4_hdr_len(dgram);

    // "If an internet datagram is fragmented, its data portion must be broken on 8 octet
    // boundaries." A datagram that already carries MF is one such portion, so its own data length is
    // a nonzero multiple of eight; the tail this would otherwise emit with MF set cannot be named by
    // the 13-bit Fragment Offset. The reassembler refuses the same shape.
    const uint16_t in_data_len = (uint16_t)(total_len - hdr_len);
    if (idemip_ip4_mf(dgram) && (in_data_len == 0u || (in_data_len & IP4_FRAG_UNIT_MASK) != 0u))
    {
        io->err = IDEMIP_IP4_FRAG_ERR_HEADER;
        return;
    }

    ctx->dgram = dgram;
    ctx->hdr_len = hdr_len;
    ctx->hdr2_len = hdr_len;
    ctx->data_len = (uint16_t)(total_len - hdr_len);
    ctx->units = idemip_ip4_frag_units(dgram);
    ctx->omf = idemip_ip4_mf(dgram);
    ctx->cursor = 0u;
    ctx->index = 0u;
    ctx->chunk0 = ctx->data_len;
    ctx->chunk = ctx->data_len;
    ctx->split = IDEMIP_FALSE;

    if (total_len > mtu)
    {
        if (idemip_ip4_df(dgram))
        {
            // "If the Don't Fragment flag (DF) bit is set, then internet fragmentation of this
            // datagram is NOT permitted, although it may be discarded." RFC 1191 sec 4 answers it.
            ctx->dgram = NULL;
            io->err = IDEMIP_IP4_FRAG_ERR_DF;
            return;
        }

        // step (9): "IHL <- (((OIHL*4)-(length of options not copied))+3)/4", which is the twenty
        // fixed octets plus the copied options, rounded up to a whole 32-bit word.
        const uint16_t kept = ip4_frag_copy_options(dgram, hdr_len, NULL);
        const uint8_t ihl2 =
            (uint8_t)((IDEMIP_IPV4_HDR_LEN + kept + ((1u << IDEMIP_IP4_IHL_SHIFT) - 1u)) >> IDEMIP_IP4_IHL_SHIFT);

        ctx->hdr2_len = (uint8_t)(ihl2 << IDEMIP_IP4_IHL_SHIFT);
        // steps (3) and (4): "NFB <- (MTU-IHL*4)/8" then "Attach the first NFB*8 data octets".
        ctx->chunk0 = (uint16_t)((mtu - hdr_len) & (uint16_t)~IP4_FRAG_UNIT_MASK);
        ctx->chunk = (uint16_t)((mtu - ctx->hdr2_len) & (uint16_t)~IP4_FRAG_UNIT_MASK);
        ctx->split = IDEMIP_TRUE;

        // "This format allows 2**13 = 8192 fragments of 8 octets each for a total of 65,536 octets."
        // The last fragment's "FO <- OFO + NFB" has to land inside that field.
        if ((uint32_t)ctx->units + ((uint32_t)ctx->data_len >> IDEMIP_IP4_FRAG_SHIFT) > IDEMIP_IP4_FRAG_OFF_MASK)
        {
            ctx->dgram = NULL;
            ctx->split = IDEMIP_FALSE;
            io->err = IDEMIP_IP4_FRAG_ERR_OFFSET;
            return;
        }
    }

    ctx->open = IDEMIP_TRUE;
    io->split = ctx->split;
    io->status = IDEMIP_OK;
}

// --- one fragment ----------------------------------------------------------

// Steps (1) and (5): "Copy the original internet header", then "MF <- 1; TL <- (IHL*4)+(NFB*8);
// Recompute Checksum". The Fragment Offset is the datagram's own, so a fragment of a fragment keeps
// where it already sat.
static void ip4_frag_emit_first(const Ip4FragCtx *ctx, uint8_t *out, uint16_t chunk)
{
    memcpy(out, ctx->dgram, ctx->hdr_len);
    idemip_ip4_set_total_len(out, (uint16_t)(ctx->hdr_len + chunk));
    idemip_ip4_set_flags_frag(out, (uint16_t)(IDEMIP_IP4_FLAG_MF | ctx->units));
    idemip_ip4_recksum(out);
    memcpy(out + ctx->hdr_len, ctx->dgram + ctx->hdr_len, chunk);
}

// Steps (7) through (9): "Selectively copy the internet header (some options are not copied)",
// "Append the remaining data", then correct IHL, Total Length, "FO <- OFO + NFB; MF <- OMF" and the
// checksum. The octets between the last copied option and the end of the reduced header are End of
// Option List, which sec 3.1 uses "if the end of the options would not otherwise coincide with the
// end of the internet header".
static void ip4_frag_emit_rest(const Ip4FragCtx *ctx, uint8_t *out, uint16_t chunk, uint16_t units, idemip_bool more)
{
    memcpy(out, ctx->dgram, IDEMIP_IPV4_HDR_LEN);
    const uint16_t kept = ip4_frag_copy_options(ctx->dgram, ctx->hdr_len, out + IDEMIP_IPV4_HDR_LEN);
    memset(out + IDEMIP_IPV4_HDR_LEN + kept, IDEMIP_IP4_FRAG_OPT_EOL,
           (size_t)ctx->hdr2_len - IDEMIP_IPV4_HDR_LEN - kept);
    idemip_ip4_set_ver_ihl(out, (uint8_t)(ctx->hdr2_len >> IDEMIP_IP4_IHL_SHIFT));
    idemip_ip4_set_total_len(out, (uint16_t)(ctx->hdr2_len + chunk));
    idemip_ip4_set_flags_frag(out, (uint16_t)((more ? IDEMIP_IP4_FLAG_MF : 0u) | units));
    idemip_ip4_recksum(out);
    memcpy(out + ctx->hdr2_len, ctx->dgram + ctx->hdr_len + ctx->cursor, chunk);
}

// The fragment the cursor stands on, into the caller's buffer. A datagram that passed the sec 3.2
// test whole is written unchanged, which is the section's "Submit this datagram to the next step in
// datagram processing".
static void ip4_frag_write(uint8_t *work)
{
    Ip4FragIo *io = IP4_FRAG_IO(work);
    Ip4FragCtx *ctx = IP4_FRAG_CTX(work);
    uint8_t *out = io->next_args.out;

    if (!ctx->open)
    {
        io->err = IDEMIP_IP4_FRAG_ERR_STATE;
        return;
    }
    if (ctx->done)
    {
        io->err = IDEMIP_IP4_FRAG_ERR_DONE;
        return;
    }

    const idemip_bool first = (idemip_bool)(ctx->index == 0u);
    const uint8_t hdr_len = (uint8_t)((!ctx->split || first) ? ctx->hdr_len : ctx->hdr2_len);
    uint16_t chunk = ctx->data_len;
    if (ctx->split)
    {
        const uint16_t room = (uint16_t)(first ? ctx->chunk0 : ctx->chunk);
        const uint16_t left = (uint16_t)(ctx->data_len - ctx->cursor);
        chunk = (uint16_t)((left > room) ? room : left);
    }
    const uint16_t len = (uint16_t)(hdr_len + chunk);
    if (out == NULL || io->next_args.cap < (size_t)len)
    {
        io->err = IDEMIP_IP4_FRAG_ERR_ROOM;
        return;
    }

    const uint16_t units = (uint16_t)(ctx->units + (ctx->cursor >> IDEMIP_IP4_FRAG_SHIFT));
    const idemip_bool more =
        (idemip_bool)(((uint32_t)ctx->cursor + chunk < ctx->data_len) ? IDEMIP_TRUE : ctx->omf);

    if (!ctx->split)
    {
        memcpy(out, ctx->dgram, len);
    }
    else if (first)
    {
        ip4_frag_emit_first(ctx, out, chunk);
    }
    else
    {
        ip4_frag_emit_rest(ctx, out, chunk, units, more);
    }

    io->index = ctx->index;
    io->units = units;
    io->offset = (uint16_t)(units << IDEMIP_IP4_FRAG_SHIFT);
    io->more = more;
    io->len = len;
    io->hdr_len = hdr_len;
    io->data_len = chunk;
    io->status = IDEMIP_OK;

    ctx->cursor = (uint16_t)(ctx->cursor + chunk);
    ctx->index = (uint16_t)(ctx->index + 1u);
    ctx->done = (idemip_bool)(ctx->cursor >= ctx->data_len);
}

// --- the entries -----------------------------------------------------------

void idemip_ip4_frag_clear(uint8_t *work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP4_FRAG_OFF_CTX, 0, (size_t)IDEMIP_IP4_FRAG_BORROW - IDEMIP_IP4_FRAG_OFF_CTX);
    IP4_FRAG_CTX(work)->ready = IP4_FRAG_READY;
    IP4_FRAG_IO(work)->status = IDEMIP_OK;
}

void idemip_ip4_frag_begin(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip4FragIo *io = IP4_FRAG_IO(work);
    io->status = IDEMIP_ERR;
    io->err = IDEMIP_IP4_FRAG_ERR_STATE;
    io->split = IDEMIP_FALSE;
    io->more = IDEMIP_FALSE;
    io->index = 0u;
    io->units = 0u;
    io->offset = 0u;
    io->len = 0u;
    io->hdr_len = 0u;
    io->data_len = 0u;
    if (!ip4_frag_ready(work))
    {
        return;
    }
    io->err = IDEMIP_IP4_FRAG_ERR_NONE;
    ip4_frag_take(work);
}

void idemip_ip4_frag_next(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    Ip4FragIo *io = IP4_FRAG_IO(work);
    io->status = IDEMIP_ERR;
    io->err = IDEMIP_IP4_FRAG_ERR_STATE;
    io->more = IDEMIP_FALSE;
    io->index = 0u;
    io->units = 0u;
    io->offset = 0u;
    io->len = 0u;
    io->hdr_len = 0u;
    io->data_len = 0u;
    if (!ip4_frag_ready(work))
    {
        return;
    }
    io->err = IDEMIP_IP4_FRAG_ERR_NONE;
    ip4_frag_write(work);
}

IDEMIP_END_DECLS
