// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dma.c
 * @brief One interface's descriptor rings, and the pin count on each receive descriptor.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block, the context and both rings are regions of that borrow, at compile-time offsets, and no entry
 * reads or writes a byte outside it. Two borrows therefore share nothing, and the same call on the
 * same borrow does the same thing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_ETHERNET

#include "idemIP/netif/dma.h"

IDEMIP_BEGIN_DECLS

// The stamp clear writes into the context. Every other entry refuses a borrow without it, so bytes
// that were never cleared are refused rather than read as a ring.
#define DMA_READY 0x444D4131u

// The one definition, private to this TU. Each index counts descriptors handled and is masked to a
// ring position, both counts being powers of two. rx_tail is the one word the ISR stores and the tick
// loads.
typedef struct
{
    const IdemIpPhyDriver *drv;
    uint32_t ready;   // DMA_READY once clear has run
    uint32_t rx_head; // the receive descriptor the tick takes next
    uint32_t rx_tail; // the receive descriptor the engine fills next
    uint32_t tx_head; // the transmit descriptor tx_take hands out next
    uint32_t tx_tail; // the transmit descriptor tx_reap takes back next
    uint16_t pinned;  // receive descriptors pinned, bounded by IDEMIP_MAX_PINNED_FRAMES
} DmaCtx;

// One descriptor. buf is the driver's frame buffer, len the octets in it, flags the IdemIpDmaFlag
// set, and pins the retaining units holding it.
typedef struct
{
    uint8_t *buf;
    uint16_t len;
    uint16_t flags;
    uint8_t pins;
    uint8_t pad[(1u << IDEMIP_DMA_DESC_ENTRY_SHIFT) - (sizeof(uint8_t *) + (2u * 2u) + 1u)];
} DmaDesc;

static_assert(sizeof(DmaDesc) == (1u << IDEMIP_DMA_DESC_ENTRY_SHIFT),
              "a DmaDesc is not 1 << IDEMIP_DMA_DESC_ENTRY_SHIFT octets wide - raise the shift in idemip_config.h");

// The caller's borrow, split: the operand block, the context, the receive ring, then the transmit
// ring. dma.h publishes the offsets; the asserts below prove the span covers them and that each ring
// starts aligned before anything runs.
static_assert(IDEMIP_DMA_OFF_CTX + sizeof(DmaCtx) <= IDEMIP_DMA_CTX_BYTES,
              "IDEMIP_DMA_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_DMA_OFF_END <= IDEMIP_DMA_BORROW,
              "IDEMIP_DMA_BORROW is short of the operand block, the context and both rings - raise "
              "IDEMIP_DMA_CTX_BYTES in idemip_config.h");
static_assert(((IDEMIP_DMA_OFF_RX | IDEMIP_DMA_OFF_TX) & (IDEMIP_ALIGN - 1u)) == 0u,
              "a ring does not start on IDEMIP_ALIGN: descriptor i sits at (i << SHIFT) from it");

// A pin count is one octet, so the descriptors every retaining unit can hold at once has to fit in
// one.
static_assert(IDEMIP_MAX_PINNED_FRAMES <= 0xFFu,
              "IDEMIP_MAX_PINNED_FRAMES exceeds a one-octet pin count: widen DmaDesc::pins");

// The regions, at their offsets in the caller's borrow.
#define DMA_IO(w) IDEMIP_DMA_IO(w)
#define DMA_CTX(w) ((DmaCtx *)(void *)((w) + IDEMIP_DMA_OFF_CTX))
#define DMA_RX_AT(w, i) ((DmaDesc *)(void *)((w) + IDEMIP_DMA_OFF_RX + ((size_t)(i) << IDEMIP_DMA_DESC_ENTRY_SHIFT)))
#define DMA_TX_AT(w, i) ((DmaDesc *)(void *)((w) + IDEMIP_DMA_OFF_TX + ((size_t)(i) << IDEMIP_DMA_DESC_ENTRY_SHIFT)))

// --- the entries -----------------------------------------------------------

// Zeroes the context and both rings, then stamps the context. A zeroed descriptor holds a null
// buffer, no flags and no pins, which is the state every other entry reads as the engine not owning
// it. The operand block is the caller's and is left alone.
static void dma_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_DMA_OFF_CTX, 0, (size_t)IDEMIP_DMA_OFF_END - (size_t)IDEMIP_DMA_OFF_CTX);
    DMA_CTX(work)->ready = DMA_READY;
    DMA_IO(work)->status = IDEMIP_OK;
}

// Both cache hooks are called without a null test on the frame path, so an incomplete driver is
// refused here rather than faulting at the first frame.
static void dma_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    if (DMA_CTX(work)->ready != DMA_READY || io->bind_args.drv == NULL || io->bind_args.rx_base == NULL ||
        io->bind_args.tx_base == NULL || io->bind_args.drv->cache_invalidate == NULL ||
        io->bind_args.drv->cache_clean == NULL)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.5, descriptor i points at its base plus i strides of IDEMIP_DMA_BUF_STRIDE.
    io->status = IDEMIP_ERR;
}

static void dma_rx_take(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    io->buf = NULL;
    io->len = 0u;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.5, cache_invalidate discards the stale copy before the frame is read.
    io->status = IDEMIP_ERR;
}

static void dma_rx_post(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL ||
        io->desc_args.index >= IDEMIP_RX_DESCRIPTORS)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.5, the field writes are ordered before the ownership store.
    io->status = IDEMIP_ERR;
}

static void dma_pin(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    io->pins = 0u;
    if (DMA_CTX(work)->ready != DMA_READY || io->desc_args.index >= IDEMIP_RX_DESCRIPTORS)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.5, the pins over the ring are bounded by IDEMIP_MAX_PINNED_FRAMES.
    io->status = IDEMIP_ERR;
}

static void dma_unpin(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    io->pins = 0u;
    if (DMA_CTX(work)->ready != DMA_READY || io->desc_args.index >= IDEMIP_RX_DESCRIPTORS)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.5, the descriptor returns to the engine when the last pin goes.
    io->status = IDEMIP_ERR;
}

static void dma_tx_take(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    io->buf = NULL;
    io->len = 0u;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.5, a descriptor the engine still owns is not handed out.
    io->status = IDEMIP_ERR;
}

static void dma_tx_post(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL ||
        io->desc_args.index >= IDEMIP_TX_DESCRIPTORS || io->desc_args.len == 0u ||
        io->desc_args.len > IDEMIP_ETH_FRAME_MAX)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.5, cache_clean writes back the build before the ownership store.
    io->status = IDEMIP_ERR;
}

static void dma_tx_reap(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.5, a descriptor the engine released is free to build into again.
    io->status = IDEMIP_ERR;
}

static void dma_pinned(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    io->pinned = 0u;
    if (DMA_CTX(work)->ready != DMA_READY)
    {
        return;
    }
    // PHASE 3: PLAN sec 3.5, the pins over the whole receive ring.
    io->status = IDEMIP_ERR;
}

const DmaNs Dma = {.clear = dma_clear,
                   .bind = dma_bind,
                   .rx_take = dma_rx_take,
                   .rx_post = dma_rx_post,
                   .pin = dma_pin,
                   .unpin = dma_unpin,
                   .tx_take = dma_tx_take,
                   .tx_post = dma_tx_post,
                   .tx_reap = dma_tx_reap,
                   .pinned = dma_pinned};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET
