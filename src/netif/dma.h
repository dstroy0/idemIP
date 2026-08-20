// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dma.h
 * @brief The descriptor rings, and the pin protocol that keeps a retained receive buffer out of the
 *        engine's hands.
 *
 * One ring pair belongs to one MAC, so one borrow is one interface's rings. A descriptor carries the
 * address of a frame buffer the DRIVER owns, the octets in it, the ownership and status flags, and
 * the pin count. No frame octet is in this borrow: the buffers are reached through the addresses
 * bind was handed.
 *
 * Receive is take, then either post or pin. A unit that holds a frame past dispatch pins the
 * descriptor, and the descriptor returns to the engine when the last pin is dropped. Every retaining
 * capacity is a compile-time constant, so IDEMIP_MAX_PINNED_FRAMES bounds the pins and the
 * static_assert in idemip_config.h proves the ring cannot starve.
 *
 * The engine wrote a received buffer, so a cached copy of it is discarded before the frame is read;
 * the engine reads a transmit buffer, so what the build left in cache is written back before the
 * descriptor is handed over. Both hooks are the driver's, in phy.h's IdemIpPhyDriver.
 */

#ifndef IDEMIP_DMA_H
#define IDEMIP_DMA_H

#include "src/ethernet/phy.h" // IdemIpPhyDriver, for the cache hooks and the frame bound

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/**
 * @brief What a descriptor says about itself, one bit each.
 *
 * @var IDEMIP_DMA_FLAG_OWN  the engine owns the descriptor, so nothing here may touch its buffer
 * @var IDEMIP_DMA_FLAG_HELD the tick took the descriptor and has not posted it back
 * @var IDEMIP_DMA_FLAG_ERR  the engine reported an error on the frame in it
 * @var IDEMIP_DMA_FLAG_LAST the descriptor holds the last octets of a frame
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DMA_FLAG_OWN = 0x0001,
    IDEMIP_DMA_FLAG_HELD = 0x0002,
    IDEMIP_DMA_FLAG_ERR = 0x0004,
    IDEMIP_DMA_FLAG_LAST = 0x0008,
} IdemIpDmaFlag;

/** @brief Every flag a descriptor may carry. */
#define IDEMIP_DMA_FLAG_MASK                                                                                           \
    ((uint16_t)(IDEMIP_DMA_FLAG_OWN | IDEMIP_DMA_FLAG_HELD | IDEMIP_DMA_FLAG_ERR | IDEMIP_DMA_FLAG_LAST))

/**
 * @brief What bind takes: the driver, and the two buffer arrays it owns.
 *
 * Descriptor i of a ring points at its base plus i strides of IDEMIP_DMA_BUF_STRIDE, which rounds
 * IDEMIP_DMA_FRAME_MAX up to whole cache lines so that invalidating one buffer cannot reach another.
 *
 * @var DmaBindArgs::drv     the link driver: rx_claim, rx_release, tx_claim and tx_commit on the
 *                           frame path, cache_invalidate and cache_clean around it
 * @var DmaBindArgs::rx_base the first of IDEMIP_RX_DESCRIPTORS receive buffers
 * @var DmaBindArgs::tx_base the first of IDEMIP_TX_DESCRIPTORS transmit buffers
 */
typedef struct
{
    const IdemIpPhyDriver *drv;
    uint8_t *rx_base;
    uint8_t *tx_base;
} DmaBindArgs;

/**
 * @brief What a descriptor operation takes.
 *
 * @var DmaDescArgs::len   the octets tx_post hands to the engine; unread by the others
 * @var DmaDescArgs::index which descriptor pin, unpin and post name
 */
typedef struct
{
    uint16_t len;
    uint8_t index;
} DmaDescArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var DmaIo::bind_args the driver and the two buffer arrays
 * @var DmaIo::desc_args the descriptor a call names, and the length a transmit post commits
 * @var DmaIo::status    what the call reports: OK, BUSY, or ERR
 * @var DmaIo::buf       the frame buffer the reached descriptor points at, the driver's storage
 * @var DmaIo::len       octets in it, or 0 when nothing was waiting
 * @var DmaIo::flags     the reached descriptor's IdemIpDmaFlag set
 * @var DmaIo::pinned    receive descriptors pinned right now, at most IDEMIP_MAX_PINNED_FRAMES
 * @var DmaIo::index     which descriptor the call reached
 * @var DmaIo::pins      the pin count on it
 */
typedef struct
{
    DmaBindArgs bind_args;
    DmaDescArgs desc_args;

    IdemIpStatus status;
    uint8_t *buf;
    uint16_t len;
    uint16_t flags;
    uint16_t pinned;
    uint8_t index;
    uint8_t pins;
} DmaIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The operand block and the context share the
// IDEMIP_DMA_CTX_BYTES ahead of the rings, so the two rings sit at offsets no struct layout can move.

#define IDEMIP_DMA_OFF_IO 0u ///< the operand and result block
#define IDEMIP_DMA_OFF_CTX IDEMIP_ROUND_UP(IDEMIP_DMA_OFF_IO + sizeof(DmaIo), IDEMIP_ALIGN)
#define IDEMIP_DMA_OFF_RX IDEMIP_DMA_CTX_BYTES ///< IDEMIP_RX_DESCRIPTORS entries
#define IDEMIP_DMA_OFF_TX                                                                                              \
    (IDEMIP_DMA_OFF_RX + (IDEMIP_RX_DESCRIPTORS << IDEMIP_DMA_DESC_ENTRY_SHIFT)) ///< IDEMIP_TX_DESCRIPTORS entries
#define IDEMIP_DMA_OFF_END (IDEMIP_DMA_OFF_TX + (IDEMIP_TX_DESCRIPTORS << IDEMIP_DMA_DESC_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_DMA_IO(w) ((DmaIo *)(void *)((w) + IDEMIP_DMA_OFF_IO))

/**
 * @brief One interface's descriptor rings.
 *
 *   Dma.clear(work);
 *   IDEMIP_DMA_IO(work)->bind_args.drv = &my_driver;
 *   IDEMIP_DMA_IO(work)->bind_args.rx_base = rx_buffers;
 *   IDEMIP_DMA_IO(work)->bind_args.tx_base = tx_buffers;
 *   Dma.bind(work);
 *   Dma.rx_take(work);
 *   if (IDEMIP_DMA_IO(work)->status == IDEMIP_OK) { ... Dma.rx_post(work); }
 *
 * @c work is IDEMIP_DMA_BORROW bytes the CALLER took, at an address it knows. It arrives @c restrict
 * and is not held past the call, so nothing here aliases it. How those bytes are carved is this
 * module's and is never named here beyond the map above. The borrow IS the ring pair, so two
 * interfaces are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. A receive ring with nothing filled, a transmit ring with no free descriptor,
 * and a pin at IDEMIP_MAX_PINNED_FRAMES are all BUSY, and the caller comes back on a later tick: a
 * frame arrives, a descriptor frees, a retaining unit drops a pin on its own timer. A descriptor
 * index past the ring, a post of a descriptor the engine already owns, a pin on a descriptor the
 * engine owns, and an unpin of an unpinned descriptor are ERR.
 *
 * @var DmaNs::clear    zero the context and both rings, which every other entry refuses until it has
 *                      run. The operand block is the caller's and is left alone.
 * @var DmaNs::bind     take the driver and point every descriptor at its buffer
 * @var DmaNs::rx_take  the next descriptor the engine filled, its cache lines discarded first. BUSY
 *                      when nothing is waiting.
 * @var DmaNs::rx_post  give a taken descriptor back to the engine
 * @var DmaNs::pin      raise a taken receive descriptor's pin count, so posting it back waits
 * @var DmaNs::unpin    lower it, and post the descriptor back when the last pin goes
 * @var DmaNs::tx_take  a free transmit descriptor to build into. BUSY when the ring is full.
 * @var DmaNs::tx_post  clean the buffer's cache lines and hand the descriptor to the engine
 * @var DmaNs::tx_reap  take back every transmit descriptor the engine has finished with
 * @var DmaNs::pinned   report the receive descriptors pinned right now
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const bind)(uint8_t *restrict work);
    void (*const rx_take)(uint8_t *restrict work);
    void (*const rx_post)(uint8_t *restrict work);
    void (*const pin)(uint8_t *restrict work);
    void (*const unpin)(uint8_t *restrict work);
    void (*const tx_take)(uint8_t *restrict work);
    void (*const tx_post)(uint8_t *restrict work);
    void (*const tx_reap)(uint8_t *restrict work);
    void (*const pinned)(uint8_t *restrict work);
} DmaNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_dma_clear(uint8_t *restrict work);
void idemip_dma_bind(uint8_t *restrict work);
void idemip_dma_rx_take(uint8_t *restrict work);
void idemip_dma_rx_post(uint8_t *restrict work);
void idemip_dma_pin(uint8_t *restrict work);
void idemip_dma_unpin(uint8_t *restrict work);
void idemip_dma_tx_take(uint8_t *restrict work);
void idemip_dma_tx_post(uint8_t *restrict work);
void idemip_dma_tx_reap(uint8_t *restrict work);
void idemip_dma_pinned(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Dma.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const DmaNs Dma IDEMIP_UNUSED = {
    .clear = idemip_dma_clear,
    .bind = idemip_dma_bind,
    .rx_take = idemip_dma_rx_take,
    .rx_post = idemip_dma_rx_post,
    .pin = idemip_dma_pin,
    .unpin = idemip_dma_unpin,
    .tx_take = idemip_dma_tx_take,
    .tx_post = idemip_dma_tx_post,
    .tx_reap = idemip_dma_tx_reap,
    .pinned = idemip_dma_pinned};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_DMA_H
