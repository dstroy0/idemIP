// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file raw_pcb.c
 * @brief The RFC 1122 sec 3.4 raw binding table, in the caller's borrow.
 *
 * The context and the table are regions of the one pointer each entry is handed, at compile-time
 * offsets, and no entry reads or writes a byte outside it. Two borrows therefore share nothing, and
 * the same call on the same borrow does the same thing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6

#include "idemIP/raw/raw_pcb.h"

IDEMIP_BEGIN_DECLS

// One binding: the RFC 1122 sec 3.4 SEND parameters src, dst, prot, TOS and TTL, the RFC 4007 sec 6
// zone of each address, the interface it is pinned to, its option bits, and the RFC 3542 sec 3.1
// IPV6_CHECKSUM offset.
typedef struct
{
    uint8_t local_ip[IDEMIP_RAW_PCB_ADDR_BYTES];
    uint8_t remote_ip[IDEMIP_RAW_PCB_ADDR_BYTES];
    int16_t cksum_offset;
    uint8_t local_zone;
    uint8_t remote_zone;
    uint8_t netif;
    uint8_t proto;
    uint8_t tos;
    uint8_t ttl;
    uint8_t flags;
    uint8_t ip_version;
    idemip_bool connected;
    idemip_bool in_use;
} RawPcbFields;

// Entry i sits at (i << IDEMIP_RAW_PCB_ENTRY_SHIFT), so the entry is exactly that wide.
typedef union
{
    RawPcbFields f;
    uint8_t raw[1u << IDEMIP_RAW_PCB_ENTRY_SHIFT];
} RawPcbEntry;

static_assert(sizeof(RawPcbEntry) == (1u << IDEMIP_RAW_PCB_ENTRY_SHIFT),
              "a raw binding must be 1 << IDEMIP_RAW_PCB_ENTRY_SHIFT wide - raise the shift in idemip_config.h");
static_assert(sizeof(RawPcbFields) <= sizeof(RawPcbEntry),
              "the RFC 1122 sec 3.4 field set outgrew one entry - raise IDEMIP_RAW_PCB_ENTRY_SHIFT");

// The one definition, private to this TU. A borrow that was never cleared carries no mark, so every
// entry refuses it rather than reading a table that was never zeroed.
typedef struct
{
    uint32_t ready;
} RawPcbCtx;

// The mark clear leaves.
#define RAW_PCB_READY 0x52415750u

// The caller's borrow, split: the operand block, the context, then the table. raw_pcb.h publishes
// the offsets; the asserts below prove the span covers them before anything runs.
static_assert(IDEMIP_RAW_PCB_OFF_CTX + sizeof(RawPcbCtx) <= IDEMIP_RAW_PCB_CTX_BYTES,
              "IDEMIP_RAW_PCB_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_RAW_PCB_OFF_TAB + (IDEMIP_RAW_PCBS << IDEMIP_RAW_PCB_ENTRY_SHIFT) <= IDEMIP_RAW_PCB_BORROW,
              "IDEMIP_RAW_PCB_BORROW is short of the context and the table - raise it in idemip_config.h");

// Every index reported through the operand block is 16 bits, so the table may hold no more entries
// than that, and IDEMIP_RAW_PCB_NONE must name none of them.
static_assert(IDEMIP_RAW_PCBS < IDEMIP_RAW_PCB_NONE,
              "the table outgrew the 16-bit index the operand block reports");

// The regions, at their offsets in the caller's borrow.
#define RAW_PCB_CTX(w) ((RawPcbCtx *)(void *)((w) + IDEMIP_RAW_PCB_OFF_CTX))
#define RAW_PCB_IO(w) IDEMIP_RAW_PCB_IO(w)
#define RAW_PCB_AT(w, i)                                                                                               \
    ((RawPcbEntry *)(void *)((w) + IDEMIP_RAW_PCB_OFF_TAB + ((size_t)(i) << IDEMIP_RAW_PCB_ENTRY_SHIFT)))

// --- the entries -----------------------------------------------------------

// The context and the table are contiguous from IDEMIP_RAW_PCB_OFF_CTX to the end of the borrow, so
// one store covers both. The operand block is the caller's and is left as it was found, except for
// the members a call reports through.
static void raw_pcb_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    memset(work + IDEMIP_RAW_PCB_OFF_CTX, 0, (size_t)IDEMIP_RAW_PCB_BORROW - IDEMIP_RAW_PCB_OFF_CTX);
    RAW_PCB_CTX(work)->ready = RAW_PCB_READY;
    memset(&io->info, 0, sizeof io->info);
    io->index = IDEMIP_RAW_PCB_NONE;
    io->status = IDEMIP_OK;
}

static void raw_pcb_open(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_RAW_PCB_NONE;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.4 SEND(src, dst, prot, ...), the prot one binding answers on
    io->status = IDEMIP_ERR;
}

static void raw_pcb_close(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->pcb_args.index >= IDEMIP_RAW_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.4, releasing the binding a prot was opened on
    io->status = IDEMIP_ERR;
}

static void raw_pcb_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->bind_args.index >= IDEMIP_RAW_PCBS ||
        io->bind_args.ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.4 SEND's src, and RFC 1122 sec 3.2.1.3 on which addresses are the
    // host's own
    io->status = IDEMIP_ERR;
}

static void raw_pcb_connect(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->connect_args.index >= IDEMIP_RAW_PCBS ||
        io->connect_args.ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.4 SEND's dst
    io->status = IDEMIP_ERR;
}

static void raw_pcb_disconnect(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->pcb_args.index >= IDEMIP_RAW_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.4 SEND's dst, cleared so the binding sends to any destination
    io->status = IDEMIP_ERR;
}

static void raw_pcb_set_opts(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->opt_args.index >= IDEMIP_RAW_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.4 TOS and TTL, and RFC 3542 sec 3.1's even IPV6_CHECKSUM offset
    io->status = IDEMIP_ERR;
}

static void raw_pcb_load(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    memset(&io->info, 0, sizeof io->info);
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->pcb_args.index >= IDEMIP_RAW_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.4, reporting one binding's SEND parameters
    io->status = IDEMIP_ERR;
}

static void raw_pcb_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_RAW_PCB_NONE;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->find_args.local_ip == NULL ||
        io->find_args.remote_ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.4 RECV(BufPTR, prot => result, src, dst, SpecDest, TOS, len, opt)
    io->status = IDEMIP_ERR;
}

const RawPcbNs RawPcb = {.clear = raw_pcb_clear,
                         .open = raw_pcb_open,
                         .close = raw_pcb_close,
                         .bind = raw_pcb_bind,
                         .connect = raw_pcb_connect,
                         .disconnect = raw_pcb_disconnect,
                         .set_opts = raw_pcb_set_opts,
                         .load = raw_pcb_load,
                         .find = raw_pcb_find};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6
