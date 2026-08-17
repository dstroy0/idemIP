// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp_isn.c
 * @brief The RFC 6528 sec 3 ISN generator, in the caller's borrow.
 *
 * The context, the connection-id block and the PRF's working set are regions of the one pointer each
 * entry is handed, at compile-time offsets, and no entry reads or writes a byte outside it. Two
 * borrows therefore share nothing, and the same call on the same borrow does the same thing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_TCP

#include "idemIP/tcp/tcp_isn.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. A borrow that was never reset carries no mark, so every
// entry refuses it rather than hashing a key that was never set. base is the tick M is counted from,
// so a reseed leaves M rising across a key change.
typedef struct
{
    uint32_t ready;
    uint32_t base;
    uint8_t secret[IDEMIP_TCP_ISN_SECRET_BYTES];
    idemip_bool keyed;
} TcpIsnCtx;

// The mark reset leaves.
#define TCP_ISN_READY 0x54494E31u

// The caller's borrow, split: the operand block, the context, the connection-id block, then the PRF's
// working set. tcp_isn.h publishes the offsets; the asserts below prove the span covers them before
// anything runs.
static_assert(IDEMIP_TCP_ISN_OFF_CTX + sizeof(TcpIsnCtx) <= IDEMIP_TCP_ISN_CTX_BYTES,
              "IDEMIP_TCP_ISN_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_TCP_ISN_OFF_HASH + IDEMIP_TCP_ISN_HASH_BYTES <= IDEMIP_TCP_ISN_BORROW,
              "IDEMIP_TCP_ISN_BORROW is short of the context, the connection-id block and the PRF's working set - "
              "raise it in idemip_config.h");

// RFC 6528 sec 3 concatenates localip, localport, remoteip, remoteport and secretkey.
static_assert(IDEMIP_TCP_ISN_BLOCK_BYTES >=
                  (2u * IDEMIP_TCP_ISN_ADDR_BYTES) + 4u + IDEMIP_TCP_ISN_SECRET_BYTES,
              "the connection-id block is short of two addresses, two ports and the key (RFC 6528 sec 3)");

// The regions, at their offsets in the caller's borrow.
#define TCP_ISN_CTX(w) ((TcpIsnCtx *)(void *)((w) + IDEMIP_TCP_ISN_OFF_CTX))
#define TCP_ISN_IO(w) IDEMIP_TCP_ISN_IO(w)
#define TCP_ISN_BLOCK(w) ((uint8_t *)((w) + IDEMIP_TCP_ISN_OFF_BLOCK))
#define TCP_ISN_HASH(w) ((uint8_t *)((w) + IDEMIP_TCP_ISN_OFF_HASH))

// --- the entries -----------------------------------------------------------

// The context, the connection-id block and the working set are contiguous from
// IDEMIP_TCP_ISN_OFF_CTX to the end of the borrow, so one store covers them all and no octet of a
// former key survives. The operand block is the caller's and is left as it was found, except for the
// members a call reports through.
static void tcp_isn_reset(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    TcpIsnIo *io = TCP_ISN_IO(work);
    memset(work + IDEMIP_TCP_ISN_OFF_CTX, 0, (size_t)IDEMIP_TCP_ISN_BORROW - IDEMIP_TCP_ISN_OFF_CTX);
    TCP_ISN_CTX(work)->ready = TCP_ISN_READY;
    io->isn = 0u;
    io->status = IDEMIP_OK;
}

static void tcp_isn_seed(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpIsnIo *io = TCP_ISN_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_ISN_CTX(work)->ready != TCP_ISN_READY || io->seed_args.key == NULL ||
        io->seed_args.key_len < IDEMIP_TCP_ISN_SECRET_BYTES)
    {
        return;
    }
    // PHASE 3: RFC 6528 sec 3's secretkey, of which "Key lengths of 128 bits should be adequate"
    io->status = IDEMIP_ERR;
}

static void tcp_isn_generate(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpIsnIo *io = TCP_ISN_IO(work);
    io->status = IDEMIP_ERR;
    io->isn = 0u;
    if (TCP_ISN_CTX(work)->ready != TCP_ISN_READY || !TCP_ISN_CTX(work)->keyed || io->gen_args.local_ip == NULL ||
        io->gen_args.remote_ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 6528 sec 3's ISN = M + F(localip, localport, remoteip, remoteport, secretkey)
    io->status = IDEMIP_ERR;
}

const TcpIsnNs TcpIsn = {.reset = tcp_isn_reset, .seed = tcp_isn_seed, .generate = tcp_isn_generate};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TCP
