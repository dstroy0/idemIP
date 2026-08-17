// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file loopif.c
 * @brief The loopback interface's addresses, and the frame regions a looped frame waits in.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block, the context and the frame regions are all regions of that borrow, at compile-time offsets,
 * and no entry reads or writes a byte outside it. Two borrows therefore share nothing, and the same
 * call on the same borrow does the same thing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_ETHERNET

#include "idemIP/netif/loopif.h"

IDEMIP_BEGIN_DECLS

// The stamp clear writes into the context. Every other entry refuses a borrow without it, so bytes
// that were never cleared are refused rather than read as a queue.
#define LOOPIF_READY 0x4C4F4F50u

// The one definition, private to this TU. head is the region claim reads next, tail the one output
// writes next, and both wrap on IDEMIP_LOOPIF_FRAMES. len holds the octets in each region.
typedef struct
{
    uint32_t ready;                     // LOOPIF_READY once clear has run
    uint32_t addr4;                     // RFC 1122 sec 3.2.1.3 case (g), "{ 127, <any> }"
    uint16_t len[IDEMIP_LOOPIF_FRAMES]; // octets waiting in each region
    uint16_t mtu;
    uint8_t index;   // the netif record this interface occupies
    uint8_t head;    // the region claim reads next
    uint8_t tail;    // the region output writes next
    uint8_t held;    // regions holding a frame
    uint8_t claimed; // whether a region is out on claim
#if IDEMIP_ENABLE_IPV6
    uint8_t addr6[IDEMIP_IP6_ADDR_LEN]; // RFC 4291 sec 2.5.3, "0:0:0:0:0:0:0:1"
#endif
} LoopifCtx;

// The caller's borrow, split: the operand block, the context, then the frame regions. loopif.h
// publishes the offsets; the asserts below prove the span covers them and that a region holds a
// whole frame before anything runs.
static_assert(IDEMIP_LOOPIF_OFF_CTX + sizeof(LoopifCtx) <= IDEMIP_LOOPIF_CTX_BYTES,
              "IDEMIP_LOOPIF_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_LOOPIF_OFF_END <= IDEMIP_LOOPIF_BORROW,
              "IDEMIP_LOOPIF_BORROW is short of the operand block, the context and the frame regions - raise "
              "IDEMIP_LOOPIF_CTX_BYTES in idemip_config.h");
static_assert((1u << IDEMIP_LOOPIF_FRAME_SHIFT) >= IDEMIP_ETH_FRAME_MAX,
              "a frame region is narrower than the RFC 894 maximum frame - raise IDEMIP_LOOPIF_FRAME_SHIFT");
static_assert((IDEMIP_LOOPIF_OFF_FRAMES & (IDEMIP_ALIGN - 1u)) == 0u,
              "the frame regions do not start on IDEMIP_ALIGN: region i sits at (i << SHIFT) from there");

// The regions, at their offsets in the caller's borrow.
#define LOOPIF_IO(w) IDEMIP_LOOPIF_IO(w)
#define LOOPIF_CTX(w) ((LoopifCtx *)(void *)((w) + IDEMIP_LOOPIF_OFF_CTX))
#define LOOPIF_FRAME(w, i) ((w) + IDEMIP_LOOPIF_OFF_FRAMES + ((size_t)(i) << IDEMIP_LOOPIF_FRAME_SHIFT))

// --- the entries -----------------------------------------------------------

// Zeroes the context and every frame region, then stamps the context. A zeroed context holds no
// address, an empty queue and no claim, which is the state every other entry reads as unbound. The
// operand block is the caller's and is left alone.
static void loopif_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_LOOPIF_OFF_CTX, 0, (size_t)IDEMIP_LOOPIF_OFF_END - (size_t)IDEMIP_LOOPIF_OFF_CTX);
    LOOPIF_CTX(work)->ready = LOOPIF_READY;
    LOOPIF_IO(work)->status = IDEMIP_OK;
}

static void loopif_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    LoopifIo *io = LOOPIF_IO(work);
    io->status = IDEMIP_ERR;
    if (LOOPIF_CTX(work)->ready != LOOPIF_READY || io->bind_args.mtu == 0u ||
        io->bind_args.mtu > IDEMIP_ETH_MAX_PAYLOAD || io->bind_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
#if IDEMIP_ENABLE_IPV6
    if (io->bind_args.addr6 == NULL)
    {
        return;
    }
#endif
    // PHASE 3: RFC 1122 sec 3.2.1.3 case (g) admits "{ 127, <any> }", RFC 4291 sec 2.5.3 "0:0:0:0:0:0:0:1".
    io->status = IDEMIP_ERR;
}

static void loopif_output(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    LoopifIo *io = LOOPIF_IO(work);
    io->status = IDEMIP_ERR;
    if (LOOPIF_CTX(work)->ready != LOOPIF_READY || io->output_args.frame == NULL || io->output_args.len == 0u ||
        io->output_args.len > IDEMIP_ETH_FRAME_MAX)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.2.1.3 case (g), a loopback frame "MUST NOT appear outside a host".
    io->status = IDEMIP_ERR;
}

static void loopif_claim(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    LoopifIo *io = LOOPIF_IO(work);
    io->status = IDEMIP_ERR;
    io->frame = NULL;
    io->len = 0u;
    if (LOOPIF_CTX(work)->ready != LOOPIF_READY)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.2.1.3 case (g), the frame is delivered to this host's own input path.
    io->status = IDEMIP_ERR;
}

static void loopif_release(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    LoopifIo *io = LOOPIF_IO(work);
    io->status = IDEMIP_ERR;
    if (LOOPIF_CTX(work)->ready != LOOPIF_READY)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.2.1.3 case (g), the region frees once the input path has read it.
    io->status = IDEMIP_ERR;
}

static void loopif_owns4(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    LoopifIo *io = LOOPIF_IO(work);
    io->status = IDEMIP_ERR;
    io->owned = IDEMIP_FALSE;
    if (LOOPIF_CTX(work)->ready != LOOPIF_READY)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.2.1.3 case (g), "{ 127, <any> } Internal host loopback address".
    io->status = IDEMIP_ERR;
}

#if IDEMIP_ENABLE_IPV6

static void loopif_owns6(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    LoopifIo *io = LOOPIF_IO(work);
    io->status = IDEMIP_ERR;
    io->owned = IDEMIP_FALSE;
    if (LOOPIF_CTX(work)->ready != LOOPIF_READY || io->match_args.addr6 == NULL)
    {
        return;
    }
    // PHASE 3: RFC 4291 sec 2.5.3, "The unicast address 0:0:0:0:0:0:0:1 is called the loopback address".
    io->status = IDEMIP_ERR;
}

#endif // IDEMIP_ENABLE_IPV6

const LoopifNs Loopif = {.clear = loopif_clear,
                         .bind = loopif_bind,
                         .output = loopif_output,
                         .claim = loopif_claim,
                         .release = loopif_release,
                         .owns4 = loopif_owns4,
#if IDEMIP_ENABLE_IPV6
                         .owns6 = loopif_owns6
#endif
};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET
