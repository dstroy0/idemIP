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

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/netif/loopif.h"

IDEMIP_BEGIN_DECLS

// The stamp clear writes into the context. Every other entry refuses a borrow without it, so bytes
// that were never cleared are refused rather than read as a queue.
#define LOOPIF_READY 0x4C4F4F50u

// The one definition, private to this TU. head is the region claim reads next, tail the one output
// writes next, and both wrap on IDEMIP_LOOPIF_FRAMES. len holds the octets in each region.
//
// Neither address bind takes is kept. bind is where they are TESTED - an address off network 127 or
// an IPv6 address that is not ::1 is refused there - and no entry needs them afterwards: owns4
// answers for RFC 1122 sec 3.2.1.3 case (g)'s whole "{ 127, <any> }" network rather than for the one
// address bound, which test_owns4_is_not_narrowed_by_the_bound_address states, and RFC 4291
// sec 2.5.3 leaves owns6 exactly one address to answer for, which is the only one bind accepts. The
// interface index is the same: it is bounds-checked at bind and this unit reads no netif table.
typedef struct
{
    uint32_t ready;                     // LOOPIF_READY once clear has run
    uint16_t len[IDEMIP_LOOPIF_FRAMES]; // octets waiting in each region
    uint16_t mtu;                       // payload octets one looped frame may carry
    uint8_t head;                       // the region claim reads next
    uint8_t tail;                       // the region output writes next
    uint8_t held;                       // regions holding a frame
    uint8_t claimed;                    // whether a region is out on claim
} LoopifCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_LOOPIF_OFF_CTX, sizeof(LoopifCtx), IDEMIP_LOOPIF_OFF_END, "loopif's context");

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
static_assert(IDEMIP_LOOPIF_FRAMES >= 1u, "IDEMIP_LOOPIF_FRAMES holds no frame - raise it in idemip_config.h");
static_assert((IDEMIP_LOOPIF_FRAMES & (IDEMIP_LOOPIF_FRAMES - 1u)) == 0u,
              "IDEMIP_LOOPIF_FRAMES is not a power of two: head and tail wrap with an AND");
static_assert(IDEMIP_ETH_FRAME_MAX <= UINT16_MAX, "a frame length does not fit LoopifCtx::len");

// The regions, at their offsets in the caller's borrow.
#define LOOPIF_IO(w) IDEMIP_LOOPIF_IO(w)
#define LOOPIF_CTX(w) ((LoopifCtx *)(void *)((w) + IDEMIP_LOOPIF_OFF_CTX))
#define LOOPIF_FRAME(w, i) ((w) + IDEMIP_LOOPIF_OFF_FRAMES + ((size_t)(i) << IDEMIP_LOOPIF_FRAME_SHIFT))

// head and tail step by one and wrap on IDEMIP_LOOPIF_FRAMES, which is a power of two.
#define LOOPIF_WRAP (IDEMIP_LOOPIF_FRAMES - 1u)

// --- the address forms -----------------------------------------------------

// RFC 1122 sec 3.2.1.3 case (g), "{ 127, <any> } Internal host loopback address": the network
// number is the whole test, so every host part on network 127 answers.
static idemip_bool loopif_is_lo4(uint32_t addr)
{
    return ((addr & IDEMIP_LOOPIF_NET4_MASK) == IDEMIP_LOOPIF_NET4) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

#if IDEMIP_ENABLE_IPV6

// RFC 4291 sec 2.5.3, "The unicast address 0:0:0:0:0:0:0:1 is called the loopback address": one
// address, so the leading IDEMIP_IP6_ADDR_LEN - 1 octets are zero and the last is one.
static idemip_bool loopif_is_lo6(const uint8_t *addr)
{
    return (idemip_bytes_zero(addr, IDEMIP_IP6_ADDR_LEN - 1u) &&
            addr[IDEMIP_IP6_ADDR_LEN - 1u] == 0x01u)
               ? IDEMIP_TRUE
               : IDEMIP_FALSE;
}

#endif // IDEMIP_ENABLE_IPV6

// --- the queue -------------------------------------------------------------

// Copies the frame into the region tail names, records its length there, and steps tail.
static void loopif_push(uint8_t *restrict work, const uint8_t *frame, size_t len)
{
    LoopifCtx *ctx = LOOPIF_CTX(work);
    LoopifIo *io = LOOPIF_IO(work);
    uint8_t slot = ctx->tail;
    memcpy(LOOPIF_FRAME(work, slot), frame, len);
    ctx->len[slot] = (uint16_t)len;
    ctx->tail = (uint8_t)((slot + 1u) & LOOPIF_WRAP);
    ctx->held++;
    io->slot = slot;
    io->held = ctx->held;
}

// Reports the region head names where it lies and marks it out, so a second claim is refused until
// release steps head past it.
static void loopif_peek(uint8_t *restrict work)
{
    LoopifCtx *ctx = LOOPIF_CTX(work);
    LoopifIo *io = LOOPIF_IO(work);
    ctx->claimed = 1u;
    io->frame = LOOPIF_FRAME(work, ctx->head);
    io->len = (size_t)ctx->len[ctx->head];
    io->slot = ctx->head;
    io->held = ctx->held;
}

// Drops the claimed region's length, steps head past it and ends the claim.
static void loopif_pop(uint8_t *restrict work)
{
    LoopifCtx *ctx = LOOPIF_CTX(work);
    LoopifIo *io = LOOPIF_IO(work);
    uint8_t slot = ctx->head;
    ctx->len[slot] = 0u;
    ctx->head = (uint8_t)((slot + 1u) & LOOPIF_WRAP);
    ctx->held--;
    ctx->claimed = 0u;
    io->slot = slot;
    io->held = ctx->held;
    io->frame = NULL;
    io->len = 0u;
}

// --- the entries -----------------------------------------------------------

// Zeroes the context and every frame region, then stamps the context. A zeroed context holds no
// address, an empty queue and no claim, which is the state every other entry reads as unbound. The
// operand block is the caller's and is left alone.
void idemip_loopif_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_LOOPIF_OFF_CTX, 0, (size_t)IDEMIP_LOOPIF_OFF_END - (size_t)IDEMIP_LOOPIF_OFF_CTX);
    LOOPIF_CTX(work)->ready = LOOPIF_READY;
    LOOPIF_IO(work)->status = IDEMIP_OK;
}

void idemip_loopif_bind(uint8_t *restrict work)
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
    // RFC 1122 sec 3.2.1.3 case (g) admits "{ 127, <any> }", RFC 4291 sec 2.5.3 "0:0:0:0:0:0:0:1".
    // Any other address is ERR: the same operands retried are the same address.
    if (!loopif_is_lo4(io->bind_args.addr4))
    {
        return;
    }
#if IDEMIP_ENABLE_IPV6
    if (!loopif_is_lo6(io->bind_args.addr6))
    {
        return;
    }
#endif
    // The MTU is the one thing bind keeps: output measures against it. The addresses and the index
    // were tested above, which is all this unit ever needed them for.
    LOOPIF_CTX(work)->mtu = io->bind_args.mtu;
    io->status = IDEMIP_OK;
}

void idemip_loopif_output(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    LoopifIo *io = LOOPIF_IO(work);
    LoopifCtx *ctx = LOOPIF_CTX(work);
    io->status = IDEMIP_ERR;
    io->slot = 0u;
    io->held = 0u;
    if (ctx->ready != LOOPIF_READY || io->output_args.frame == NULL || io->output_args.len == 0u)
    {
        return;
    }
    // The MTU bind took, which is the octets of PAYLOAD one looped frame may carry, so the frame it
    // bounds is that many plus the RFC 894 header. bind refuses an MTU above IDEMIP_ETH_MAX_PAYLOAD,
    // so this is at or under IDEMIP_ETH_FRAME_MAX and the region assert above covers the copy. An
    // interface no bind has run on has an MTU of zero and carries nothing, which is the right answer
    // for a frame looped on an interface that has no address and no MTU either.
    if (io->output_args.len > (size_t)ctx->mtu + (size_t)IDEMIP_ETH_HDR_LEN)
    {
        return;
    }
    io->held = ctx->held;
    // RFC 1122 sec 3.2.1.3 case (g), a loopback frame "MUST NOT appear outside a host": it is copied
    // into a region of this borrow and handed back on the next dispatch pass. Every region full is
    // BUSY, since a claim and a release free one.
    if (ctx->held >= IDEMIP_LOOPIF_FRAMES)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    loopif_push(work, io->output_args.frame, io->output_args.len);
    io->status = IDEMIP_OK;
}

void idemip_loopif_claim(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    LoopifIo *io = LOOPIF_IO(work);
    LoopifCtx *ctx = LOOPIF_CTX(work);
    io->status = IDEMIP_ERR;
    io->frame = NULL;
    io->len = 0u;
    io->slot = 0u;
    io->held = 0u;
    if (ctx->ready != LOOPIF_READY)
    {
        return;
    }
    io->held = ctx->held;
    if (ctx->claimed)
    {
        return; // ERR: a second claim hands out a region release has not stepped past
    }
    // RFC 1122 sec 3.2.1.3 case (g), the frame is delivered to this host's own input path: the
    // oldest region is reported where it lies. Nothing waiting is BUSY, since output fills one.
    if (ctx->held == 0u)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    loopif_peek(work);
    io->status = IDEMIP_OK;
}

void idemip_loopif_release(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    LoopifIo *io = LOOPIF_IO(work);
    LoopifCtx *ctx = LOOPIF_CTX(work);
    io->status = IDEMIP_ERR;
    io->slot = 0u;
    io->held = 0u;
    if (ctx->ready != LOOPIF_READY)
    {
        return;
    }
    io->held = ctx->held;
    if (!ctx->claimed)
    {
        return; // ERR: nothing is out, so a release frees a region twice
    }
    // RFC 1122 sec 3.2.1.3 case (g), the region frees once the input path has read it.
    loopif_pop(work);
    io->status = IDEMIP_OK;
}

void idemip_loopif_owns4(uint8_t *restrict work)
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
    // RFC 1122 sec 3.2.1.3 case (g), "{ 127, <any> } Internal host loopback address". Either answer
    // is a finished call, so both are OK.
    io->owned = loopif_is_lo4(io->match_args.addr4);
    io->status = IDEMIP_OK;
}

#if IDEMIP_ENABLE_IPV6

void idemip_loopif_owns6(uint8_t *restrict work)
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
    // RFC 4291 sec 2.5.3, "The unicast address 0:0:0:0:0:0:0:1 is called the loopback address".
    // Either answer is a finished call, so both are OK.
    io->owned = loopif_is_lo6(io->match_args.addr6);
    io->status = IDEMIP_OK;
}

#endif // IDEMIP_ENABLE_IPV6

IDEMIP_END_DECLS
