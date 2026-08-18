// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp_isn.c
 * @brief The RFC 6528 sec 3 ISN generator, in the caller's borrow.
 *
 * The context, the connection-id block and the PRF's working set are regions of the one pointer each
 * entry is handed, at compile-time offsets, and no entry reads or writes a byte outside it. Two
 * borrows therefore share nothing, and the same call on the same borrow does the same thing.
 *
 * The PRF is FIPS 180-4 SHA-256, taken over the connection-id block. RFC 6528 sec 3: "The PRF could
 * be implemented as a cryptographic hash of the concatenation of the connection-id and some secret
 * data; MD5 would be a good choice for the hash function... However, implementations should consider
 * the trade-offs involved in using functions with stronger security properties, and employ them if
 * it is deemed appropriate."
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_TCP

#include "idemIP/endian.h" // the connection-id's ports and the digest's words, byte at a time
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

// ---------------------------------------------------------------------------
// The PRF: FIPS 180-4 SHA-256, working out of the borrow
// ---------------------------------------------------------------------------
// The working set tcp_isn.h publishes at IDEMIP_TCP_ISN_OFF_HASH carves into the eight running hash
// words of FIPS 180-4 sec 5.3.3, the sixteen-word message schedule window of sec 6.2.2, and the
// padded last block of sec 5.1.1. No array here has automatic storage duration, so all three are
// regions of the caller's borrow.

#define TCP_ISN_SHA_WORDS 8u                            ///< H(0) through H(7), FIPS 180-4 sec 5.3.3
#define TCP_ISN_SHA_BLOCK 64u                           ///< the 512-bit block of FIPS 180-4 sec 5.1.1
#define TCP_ISN_SHA_WINDOW 16u                          ///< the schedule words a round reaches back over
#define TCP_ISN_SHA_LEN_OFF (TCP_ISN_SHA_BLOCK - 8u)    ///< where the 64-bit length sits, sec 5.1.1

#define TCP_ISN_OFF_STATE 0u
#define TCP_ISN_OFF_SCHED (TCP_ISN_OFF_STATE + (TCP_ISN_SHA_WORDS * 4u))
#define TCP_ISN_OFF_PAD (TCP_ISN_OFF_SCHED + (TCP_ISN_SHA_WINDOW * 4u))

static_assert(TCP_ISN_OFF_PAD + TCP_ISN_SHA_BLOCK <= IDEMIP_TCP_ISN_HASH_BYTES,
              "IDEMIP_TCP_ISN_HASH_BYTES is short of the state, the schedule window and the padded block - "
              "raise it in idemip_config.h");
static_assert((IDEMIP_TCP_ISN_OFF_HASH & (IDEMIP_ALIGN - 1u)) == 0u,
              "the working set must start on IDEMIP_ALIGN: the state and the schedule are read as words");
static_assert((TCP_ISN_SHA_WINDOW & (TCP_ISN_SHA_WINDOW - 1u)) == 0u,
              "the schedule window must be a power of two: a round reaches it with a mask");

#define TCP_ISN_STATE(w) ((uint32_t *)(void *)(TCP_ISN_HASH(w) + TCP_ISN_OFF_STATE))
#define TCP_ISN_SCHED(w) ((uint32_t *)(void *)(TCP_ISN_HASH(w) + TCP_ISN_OFF_SCHED))
#define TCP_ISN_PAD(w) (TCP_ISN_HASH(w) + TCP_ISN_OFF_PAD)

// FIPS 180-4 sec 4.2.2, the sixty-four K constants.
static const uint32_t tcp_isn_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

// FIPS 180-4 sec 5.3.3, H(0).
static const uint32_t tcp_isn_h0[TCP_ISN_SHA_WORDS] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

static uint32_t tcp_isn_rotr(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32u - n));
}

// The six functions of FIPS 180-4 sec 4.1.2 the rounds are built from.
static uint32_t tcp_isn_ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}
static uint32_t tcp_isn_maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}
static uint32_t tcp_isn_bsig0(uint32_t x)
{
    return tcp_isn_rotr(x, 2u) ^ tcp_isn_rotr(x, 13u) ^ tcp_isn_rotr(x, 22u);
}
static uint32_t tcp_isn_bsig1(uint32_t x)
{
    return tcp_isn_rotr(x, 6u) ^ tcp_isn_rotr(x, 11u) ^ tcp_isn_rotr(x, 25u);
}
static uint32_t tcp_isn_ssig0(uint32_t x)
{
    return tcp_isn_rotr(x, 7u) ^ tcp_isn_rotr(x, 18u) ^ (x >> 3u);
}
static uint32_t tcp_isn_ssig1(uint32_t x)
{
    return tcp_isn_rotr(x, 17u) ^ tcp_isn_rotr(x, 19u) ^ (x >> 10u);
}

// Compress one 512-bit block into the running hash words, FIPS 180-4 sec 6.2.2. The schedule keeps
// sixteen words rather than sixty-four: round r reads W[r] and the four places it needs are r-16,
// r-15, r-7 and r-2, all inside a sixteen-wide window, so the slot being written still holds W[r-16]
// when the other three are read. The window is a power of two, so a place is reached with a mask.
static void tcp_isn_sha_block(uint8_t *restrict work, const uint8_t *blk)
{
    uint32_t *h = TCP_ISN_STATE(work);
    uint32_t *sched = TCP_ISN_SCHED(work);

    for (uint32_t i = 0u; i < TCP_ISN_SHA_WINDOW; i++)
    {
        sched[i] = idemip_rd32(blk + (i << 2));
    }

    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    uint32_t f = h[5];
    uint32_t g = h[6];
    uint32_t hh = h[7];

    for (uint32_t r = 0u; r < 64u; r++)
    {
        uint32_t j = r & (TCP_ISN_SHA_WINDOW - 1u);
        if (r >= TCP_ISN_SHA_WINDOW)
        {
            sched[j] += tcp_isn_ssig0(sched[(j + 1u) & (TCP_ISN_SHA_WINDOW - 1u)]) +
                        sched[(j + 9u) & (TCP_ISN_SHA_WINDOW - 1u)] +
                        tcp_isn_ssig1(sched[(j + 14u) & (TCP_ISN_SHA_WINDOW - 1u)]);
        }
        uint32_t t1 = hh + tcp_isn_bsig1(e) + tcp_isn_ch(e, f, g) + tcp_isn_k[r] + sched[j];
        uint32_t t2 = tcp_isn_bsig0(a) + tcp_isn_maj(a, b, c);
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

// Digest @p len octets of the connection-id block. Whole blocks compress where they lie, and the
// tail is composed in the padded block: what is left, the mark, zeros, and the message length in
// bits as the last eight octets (FIPS 180-4 sec 5.1.1). A tail that leaves no room for the length
// takes a block of its own.
static void tcp_isn_prf(uint8_t *restrict work, size_t len)
{
    uint32_t *h = TCP_ISN_STATE(work);
    uint8_t *pad = TCP_ISN_PAD(work);
    const uint8_t *msg = TCP_ISN_BLOCK(work);
    size_t left = len;

    memcpy(h, tcp_isn_h0, sizeof tcp_isn_h0);

    while (left >= TCP_ISN_SHA_BLOCK)
    {
        tcp_isn_sha_block(work, msg);
        msg += TCP_ISN_SHA_BLOCK;
        left -= TCP_ISN_SHA_BLOCK;
    }

    memset(pad, 0, TCP_ISN_SHA_BLOCK);
    memcpy(pad, msg, left);
    pad[left] = (uint8_t)0x80u;
    if (left >= TCP_ISN_SHA_LEN_OFF)
    {
        tcp_isn_sha_block(work, pad);
        memset(pad, 0, TCP_ISN_SHA_BLOCK);
    }

    uint64_t bits = (uint64_t)len << 3u;
    idemip_wr32(pad + TCP_ISN_SHA_LEN_OFF, (uint32_t)(bits >> 32u));
    idemip_wr32(pad + TCP_ISN_SHA_LEN_OFF + 4u, (uint32_t)(bits & 0xFFFFFFFFu));
    tcp_isn_sha_block(work, pad);
}

// ---------------------------------------------------------------------------
// The connection-id
// ---------------------------------------------------------------------------

// RFC 791 sec 3.1's Source Address is four octets, RFC 8200 sec 3's is sixteen. Any other version is
// not an address this generator can read, so 0 and the call is refused.
static size_t tcp_isn_addr_len(uint8_t ip_version)
{
    if (ip_version == 4u)
    {
        return 4u;
    }
    if (ip_version == 6u)
    {
        return (size_t)IDEMIP_TCP_ISN_ADDR_BYTES;
    }
    return 0u;
}

// Lay localip, localport, remoteip, remoteport and secretkey into the connection-id block in that
// order (RFC 6528 sec 3), and report the octets they span. A port goes in as the two octets RFC 9293
// sec 3.1 puts on the wire. The two families span different lengths, and FIPS 180-4 sec 5.1.1 digests
// the length with the message, so a four-octet pair and a sixteen-octet pair sharing leading octets
// still reach different digests.
static size_t tcp_isn_lay(uint8_t *restrict work, size_t addr_len)
{
    const TcpIsnIo *io = TCP_ISN_IO(work);
    const TcpIsnCtx *ctx = TCP_ISN_CTX(work);
    uint8_t *blk = TCP_ISN_BLOCK(work);
    size_t at = 0u;

    memcpy(blk + at, io->gen_args.local_ip, addr_len);
    at += addr_len;
    idemip_wr16(blk + at, io->gen_args.local_port);
    at += 2u;
    memcpy(blk + at, io->gen_args.remote_ip, addr_len);
    at += addr_len;
    idemip_wr16(blk + at, io->gen_args.remote_port);
    at += 2u;
    memcpy(blk + at, ctx->secret, (size_t)IDEMIP_TCP_ISN_SECRET_BYTES);
    at += (size_t)IDEMIP_TCP_ISN_SECRET_BYTES;
    return at;
}

// RFC 6528 sec 3: "ISN = M + F(localip, localport, remoteip, remoteport, secretkey) where M is the 4
// microsecond timer, and F() is a pseudorandom function (PRF) of the connection-id." M is the seeded
// base plus the caller's millisecond count at IDEMIP_TCP_ISN_TICKS_PER_MS ticks each, and it wraps:
// RFC 9293 sec 3.4.1's clock "is a 32-bit counter". F is the leading thirty-two bits of the SHA-256
// digest, which after the feed-forward of FIPS 180-4 sec 6.2.2 is H(0) itself.
//
// The concatenated key and the compression state are scratch, so both are zeroed once F is read and
// nothing of either is left in the borrow.
static uint32_t tcp_isn_derive(uint8_t *restrict work, size_t addr_len)
{
    size_t len = tcp_isn_lay(work, addr_len);
    tcp_isn_prf(work, len);

    uint32_t f = TCP_ISN_STATE(work)[0];
    uint32_t m = TCP_ISN_CTX(work)->base +
                 (TCP_ISN_IO(work)->gen_args.now_ms * (uint32_t)IDEMIP_TCP_ISN_TICKS_PER_MS);

    memset(work + IDEMIP_TCP_ISN_OFF_BLOCK, 0,
           (size_t)IDEMIP_TCP_ISN_BORROW - IDEMIP_TCP_ISN_OFF_BLOCK);
    return m + f;
}

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
    // RFC 6528 sec 3's secretkey, of which "Key lengths of 128 bits should be adequate": the leading
    // IDEMIP_TCP_ISN_SECRET_BYTES octets of what the caller offered. base is the 4-microsecond tick M
    // counts from, so a key change on a running system leaves M rising. A short or absent key is ERR
    // above: the same operands can never produce a key, so a retry cannot succeed.
    TcpIsnCtx *ctx = TCP_ISN_CTX(work);
    memcpy(ctx->secret, io->seed_args.key, (size_t)IDEMIP_TCP_ISN_SECRET_BYTES);
    ctx->base = io->seed_args.base;
    ctx->keyed = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

// RFC 6528 sec 3's ISN = M + F(localip, localport, remoteip, remoteport, secretkey). Nothing here
// waits on anything, so there is no BUSY: the PRF runs to completion on the operands it was given,
// and every refusal above is a state or an operand the same call can never fix.
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
    size_t addr_len = tcp_isn_addr_len(io->gen_args.ip_version);
    if (addr_len == 0u)
    {
        return;
    }
    io->isn = tcp_isn_derive(work, addr_len);
    io->status = IDEMIP_OK;
}

const TcpIsnNs TcpIsn = {.reset = tcp_isn_reset, .seed = tcp_isn_seed, .generate = tcp_isn_generate};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TCP
