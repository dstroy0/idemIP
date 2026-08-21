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

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/netif/dma.h"

IDEMIP_BEGIN_DECLS

// The stamp clear writes into the context. Every other entry refuses a borrow without it, so bytes
// that were never cleared are refused rather than read as a ring.
#define DMA_READY 0x444D4131u

// The one definition, private to this TU. Each index is masked to a ring position, both counts being
// powers of two, and each names where the next walk over its ring starts.
typedef struct
{
    const IdemIpPhyDriver *drv;
    uint32_t ready;   // DMA_READY once clear has run
    uint32_t rx_head; // one past the receive descriptor last taken
    uint32_t tx_head; // one past the transmit descriptor last handed out
    uint32_t tx_tail; // transmit descriptors taken back from the engine
    uint16_t pinned;  // receive descriptors pinned, bounded by IDEMIP_MAX_PINNED_FRAMES
} DmaCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_DMA_OFF_CTX, sizeof(DmaCtx), IDEMIP_DMA_OFF_END, "dma's context");

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

// A descriptor index is the one octet of DmaDescArgs::index, and the entries refuse the first index
// past a ring, so both counts and the count itself have to fit in one.
static_assert(IDEMIP_RX_DESCRIPTORS <= 0xFFu && IDEMIP_TX_DESCRIPTORS <= 0xFFu,
              "a ring count exceeds a one-octet descriptor index: widen DmaDescArgs::index");

// A descriptor length is the 16-bit DmaDesc::len, and tx_post bounds a build against RFC 894's frame
// while tx_take claims IDEMIP_DMA_FRAME_MAX octets to build into.
static_assert(IDEMIP_DMA_FRAME_MAX <= 0xFFFFu, "a frame is longer than the 16-bit DmaDesc::len");
static_assert(IDEMIP_ETH_FRAME_MAX <= IDEMIP_DMA_FRAME_MAX,
              "tx_post admits a length past the buffer tx_take claimed: raise IDEMIP_DMA_FRAME_MAX");

// A ring position is the low bits of a monotone count, both counts being powers of two.
#define DMA_RX_MASK ((uint32_t)IDEMIP_RX_DESCRIPTORS - 1u)
#define DMA_TX_MASK ((uint32_t)IDEMIP_TX_DESCRIPTORS - 1u)

// The regions, at their offsets in the caller's borrow.
#define DMA_IO(w) IDEMIP_DMA_IO(w)
#define DMA_CTX(w) ((DmaCtx *)(void *)((w) + IDEMIP_DMA_OFF_CTX))
#define DMA_AT(w, off, i) ((DmaDesc *)(void *)((w) + (off) + ((size_t)(i) << IDEMIP_DMA_DESC_ENTRY_SHIFT)))
#define DMA_RX_AT(w, i) DMA_AT(w, IDEMIP_DMA_OFF_RX, i)
#define DMA_TX_AT(w, i) DMA_AT(w, IDEMIP_DMA_OFF_TX, i)

// --- the statics -----------------------------------------------------------

// The descriptor of the ring at @p off whose buffer is @p addr, or @p count when no descriptor in it
// was pointed at that address. bind gave descriptor i the address base + i strides, so the address
// the driver hands back names the descriptor. The walk starts at @p start, where the last one left
// off, is bounded by the count and wraps with a mask.
static uint32_t dma_slot_of(uint8_t *work, size_t off, uint32_t count, uint32_t start, const uint8_t *addr)
{
    for (uint32_t n = 0u; n < count; n++)
    {
        uint32_t i = (start + n) & (count - 1u);
        if (DMA_AT(work, off, i)->buf == addr)
        {
            return i;
        }
    }
    return count;
}

// Hands one receive descriptor back to the engine: the driver's release, then the length, then the
// ownership store, which is the order PLAN sec 3.5 states for the fields and the OWN bit.
static void dma_rx_give_back(uint8_t *work, DmaDesc *d)
{
    const DmaCtx *ctx = DMA_CTX(work);
    ctx->drv->rx_release();
    d->len = 0u;
    d->flags = (uint16_t)IDEMIP_DMA_FLAG_OWN;
}

// --- the entries -----------------------------------------------------------

// Zeroes the context and both rings, then stamps the context. A zeroed descriptor holds a null
// buffer, no flags and no pins, which is the state every other entry reads as the engine not owning
// it. The operand block is the caller's and is left alone.
void idemip_dma_clear(uint8_t *work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_DMA_OFF_CTX, 0, (size_t)IDEMIP_DMA_OFF_END - IDEMIP_DMA_OFF_CTX);
    DMA_CTX(work)->ready = DMA_READY;
    DMA_IO(work)->status = IDEMIP_OK;
}

// Both cache hooks are called without a null test on the frame path, so an incomplete driver is
// refused here rather than faulting at the first frame.
void idemip_dma_bind(uint8_t *work)
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
    // The frame path calls these four as well, so a driver missing one is refused here too.
    if (io->bind_args.drv->rx_claim == NULL || io->bind_args.drv->rx_release == NULL ||
        io->bind_args.drv->tx_claim == NULL || io->bind_args.drv->tx_commit == NULL)
    {
        return;
    }
    // PLAN sec 3.5: a buffer starts on a cache line, because invalidating a partial line discards
    // whatever shares it. No retry moves the array, so a misplaced one is ERR.
    if ((((uintptr_t)io->bind_args.rx_base | (uintptr_t)io->bind_args.tx_base) &
         ((uintptr_t)IDEMIP_CACHE_LINE_BYTES - 1u)) != 0u)
    {
        return;
    }

    // PLAN sec 3.5: descriptor i points at its base plus i strides of IDEMIP_DMA_BUF_STRIDE. A
    // receive descriptor is the engine's from here, a transmit descriptor is this side's.
    for (uint32_t i = 0u; i < (uint32_t)IDEMIP_RX_DESCRIPTORS; i++)
    {
        DmaDesc *d = DMA_RX_AT(work, i);
        d->buf = io->bind_args.rx_base + ((size_t)i * IDEMIP_DMA_BUF_STRIDE);
        d->len = 0u;
        d->flags = (uint16_t)IDEMIP_DMA_FLAG_OWN;
        d->pins = 0u;
    }
    for (uint32_t i = 0u; i < (uint32_t)IDEMIP_TX_DESCRIPTORS; i++)
    {
        DmaDesc *d = DMA_TX_AT(work, i);
        d->buf = io->bind_args.tx_base + ((size_t)i * IDEMIP_DMA_BUF_STRIDE);
        d->len = 0u;
        d->flags = 0u;
        d->pins = 0u;
    }

    DmaCtx *ctx = DMA_CTX(work);
    ctx->drv = io->bind_args.drv;
    ctx->rx_head = 0u;
    ctx->tx_head = 0u;
    ctx->tx_tail = 0u;
    ctx->pinned = 0u;
    io->status = IDEMIP_OK;
}

// The engine wrote the buffer, so any cached copy of it is discarded before the frame is read: the
// driver's claim, then cache_invalidate, then the operand block. Nothing waiting is BUSY, because a
// later tick finds a frame. A frame longer than one buffer goes straight back to the engine, and a
// buffer this ring never handed out or one whose descriptor this side still holds is left where it
// is: all three are ERR, and no retry makes any of them right.
void idemip_dma_rx_take(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    io->buf = NULL;
    io->len = 0u;
    io->flags = 0u;
    io->pins = 0u;
    io->index = 0u;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL)
    {
        return;
    }
    DmaCtx *ctx = DMA_CTX(work);
    const uint8_t *frame = NULL;
    size_t len = ctx->drv->rx_claim(&frame);
    if (len == 0u || frame == NULL)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    if (len > IDEMIP_DMA_FRAME_MAX)
    {
        ctx->drv->rx_release();
        io->flags = (uint16_t)IDEMIP_DMA_FLAG_ERR;
        return;
    }
    uint32_t slot =
        dma_slot_of(work, IDEMIP_DMA_OFF_RX, (uint32_t)IDEMIP_RX_DESCRIPTORS, ctx->rx_head & DMA_RX_MASK, frame);
    if (slot >= (uint32_t)IDEMIP_RX_DESCRIPTORS)
    {
        return;
    }
    DmaDesc *d = DMA_RX_AT(work, slot);
    // A descriptor this side holds or a unit pinned was never given back, so a frame in its buffer
    // would be written over a retained one. The claim stays with the engine rather than releasing a
    // descriptor that is still out.
    if ((d->flags & (uint16_t)IDEMIP_DMA_FLAG_OWN) == 0u)
    {
        return;
    }
    ctx->drv->cache_invalidate(frame, len);
    d->len = (uint16_t)len;
    d->flags = (uint16_t)((uint16_t)IDEMIP_DMA_FLAG_HELD | (uint16_t)IDEMIP_DMA_FLAG_LAST);
    ctx->rx_head = slot + 1u;
    io->buf = d->buf;
    io->len = d->len;
    io->flags = d->flags;
    io->pins = d->pins;
    io->index = (uint8_t)slot;
    io->pinned = ctx->pinned;
    io->status = IDEMIP_OK;
}

// A descriptor still pinned stays out of the engine's hands: the hold ends, the pin does not, and
// the last unpin returns it. A descriptor the engine already owns carries no hold, so a second post
// and a post of a descriptor never taken are both ERR: neither becomes right on a retry.
void idemip_dma_rx_post(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL || io->desc_args.index >= IDEMIP_RX_DESCRIPTORS)
    {
        return;
    }
    DmaDesc *d = DMA_RX_AT(work, io->desc_args.index);
    if ((d->flags & (uint16_t)IDEMIP_DMA_FLAG_HELD) == 0u)
    {
        return;
    }
    if (d->pins > 0u)
    {
        d->flags = (uint16_t)(d->flags & (uint16_t)~(uint16_t)IDEMIP_DMA_FLAG_HELD);
    }
    else
    {
        dma_rx_give_back(work, d);
    }
    io->index = io->desc_args.index;
    io->flags = d->flags;
    io->pins = d->pins;
    io->pinned = DMA_CTX(work)->pinned;
    io->buf = NULL;
    io->len = 0u;
    io->status = IDEMIP_OK;
}

// Raises the pin count on a descriptor this side holds. A pin past IDEMIP_MAX_PINNED_FRAMES is BUSY,
// because every retaining unit drops its pins on its own timer and the retry then succeeds. A
// descriptor the engine owns was never taken, and no retry makes it retainable, so that is ERR.
void idemip_dma_pin(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    io->pins = 0u;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL || io->desc_args.index >= IDEMIP_RX_DESCRIPTORS)
    {
        return;
    }
    DmaCtx *ctx = DMA_CTX(work);
    DmaDesc *d = DMA_RX_AT(work, io->desc_args.index);
    io->pinned = ctx->pinned;
    if ((d->flags & (uint16_t)IDEMIP_DMA_FLAG_HELD) == 0u && d->pins == 0u)
    {
        return;
    }
    // idemip_config.h asserts IDEMIP_MAX_PINNED_FRAMES below IDEMIP_RX_DESCRIPTORS, so the ring
    // cannot starve. The count is held anyway, and a pin past it is refused rather than believed.
    if (ctx->pinned >= IDEMIP_MAX_PINNED_FRAMES)
    {
        io->pins = d->pins;
        io->status = IDEMIP_BUSY;
        return;
    }
    d->pins++;
    ctx->pinned++;
    io->index = io->desc_args.index;
    io->flags = d->flags;
    io->pins = d->pins;
    io->pinned = ctx->pinned;
    io->status = IDEMIP_OK;
}

// Lowers it, and the descriptor goes back to the engine when the last pin goes and the hold is
// already over. An unpin of a descriptor no unit holds is ERR: no retry gives it a pin to drop.
void idemip_dma_unpin(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    io->pins = 0u;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL || io->desc_args.index >= IDEMIP_RX_DESCRIPTORS)
    {
        return;
    }
    DmaCtx *ctx = DMA_CTX(work);
    DmaDesc *d = DMA_RX_AT(work, io->desc_args.index);
    io->pinned = ctx->pinned;
    if (d->pins == 0u)
    {
        return;
    }
    d->pins--;
    ctx->pinned--;
    if (d->pins == 0u && (d->flags & (uint16_t)IDEMIP_DMA_FLAG_HELD) == 0u)
    {
        dma_rx_give_back(work, d);
    }
    io->index = io->desc_args.index;
    io->flags = d->flags;
    io->pins = d->pins;
    io->pinned = ctx->pinned;
    io->status = IDEMIP_OK;
}

// The buffer is claimed for the longest frame a descriptor can carry, because the build picks its
// length afterwards and tx_post bounds it against RFC 894 then. A driver with no room is BUSY: a
// later tick finds a freed descriptor. A buffer outside the array bind was handed, and one already
// handed out, are ERR.
void idemip_dma_tx_take(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    io->buf = NULL;
    io->len = 0u;
    io->flags = 0u;
    io->pins = 0u;
    io->index = 0u;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL)
    {
        return;
    }
    DmaCtx *ctx = DMA_CTX(work);
    const uint8_t *buf = ctx->drv->tx_claim((size_t)IDEMIP_DMA_FRAME_MAX);
    if (buf == NULL)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    uint32_t slot =
        dma_slot_of(work, IDEMIP_DMA_OFF_TX, (uint32_t)IDEMIP_TX_DESCRIPTORS, ctx->tx_head & DMA_TX_MASK, buf);
    if (slot >= (uint32_t)IDEMIP_TX_DESCRIPTORS)
    {
        return;
    }
    DmaDesc *d = DMA_TX_AT(work, slot);
    // A buffer already handed out is a driver handing the same storage to two builds.
    if ((d->flags & (uint16_t)((uint16_t)IDEMIP_DMA_FLAG_OWN | (uint16_t)IDEMIP_DMA_FLAG_HELD)) != 0u)
    {
        return;
    }
    d->len = 0u;
    d->flags = (uint16_t)IDEMIP_DMA_FLAG_HELD;
    ctx->tx_head = slot + 1u;
    io->buf = d->buf;
    io->index = (uint8_t)slot;
    io->flags = d->flags;
    io->status = IDEMIP_OK;
}

// The engine reads the buffer, so what the build left in cache is written back before the descriptor
// is handed over: the length, then cache_clean, then the driver's commit, then the ownership store.
// A driver that could not queue it leaves the hold in place, so the same descriptor is posted again
// on a later tick, which is BUSY. A length no frame can carry (RFC 894) and a descriptor never taken
// are ERR.
void idemip_dma_tx_post(uint8_t *work)
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
    const DmaCtx *ctx = DMA_CTX(work);
    DmaDesc *d = DMA_TX_AT(work, io->desc_args.index);
    // Not measured on the buffer: idemip_dma_bind gives every transmit descriptor its buffer out of
    // the array the caller declared, and nothing clears it, so a descriptor the caller holds has one.
    // It is written because the buffer is what the frame was written into and what is handed to the
    // engine, and neither may be done through a null.
    if ((d->flags & (uint16_t)IDEMIP_DMA_FLAG_HELD) == 0u || d->buf == NULL) // GCOVR_EXCL_BR_LINE
    {
        return;
    }
    d->len = io->desc_args.len;
    ctx->drv->cache_clean(d->buf, (size_t)d->len);
    io->index = io->desc_args.index;
    io->buf = d->buf;
    io->len = d->len;
    if (!ctx->drv->tx_commit((size_t)d->len))
    {
        io->flags = d->flags;
        io->status = IDEMIP_BUSY;
        return;
    }
    d->flags = (uint16_t)((uint16_t)IDEMIP_DMA_FLAG_OWN | (uint16_t)IDEMIP_DMA_FLAG_LAST);
    io->flags = d->flags;
    io->status = IDEMIP_OK;
}

// Walks the whole transmit ring from tx_tail, clearing every descriptor the engine owns back to a
// buffer this side may build into. Nothing to take back is BUSY, the same answer a full ring gives:
// the caller comes back on a later tick.
void idemip_dma_tx_reap(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    DmaIo *io = DMA_IO(work);
    io->status = IDEMIP_ERR;
    io->buf = NULL;
    io->len = 0u;
    io->flags = 0u;
    io->pins = 0u;
    io->index = 0u;
    if (DMA_CTX(work)->ready != DMA_READY || DMA_CTX(work)->drv == NULL)
    {
        return;
    }
    DmaCtx *ctx = DMA_CTX(work);
    uint32_t taken = 0u;
    for (uint32_t n = 0u; n < (uint32_t)IDEMIP_TX_DESCRIPTORS; n++)
    {
        uint32_t slot = (ctx->tx_tail + n) & DMA_TX_MASK;
        DmaDesc *d = DMA_TX_AT(work, slot);
        if ((d->flags & (uint16_t)IDEMIP_DMA_FLAG_OWN) == 0u)
        {
            continue;
        }
        d->len = 0u;
        d->flags = 0u;
        io->index = (uint8_t)slot;
        taken++;
    }
    ctx->tx_tail += taken;
    io->status = (taken > 0u) ? IDEMIP_OK : IDEMIP_BUSY;
}

// The pins over the whole receive ring, which is the count IDEMIP_MAX_PINNED_FRAMES bounds.
void idemip_dma_pinned(uint8_t *work)
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
    io->pinned = DMA_CTX(work)->pinned;
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
