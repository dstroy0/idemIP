// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp_isn.h
 * @brief The RFC 6528 initial sequence number generator.
 *
 * RFC 6528 sec 3: "TCP SHOULD generate its Initial Sequence Numbers with the expression:
 * ISN = M + F(localip, localport, remoteip, remoteport, secretkey) where M is the 4 microsecond timer,
 * and F() is a pseudorandom function (PRF) of the connection-id. F() MUST NOT be computable from the
 * outside, or an attacker could still guess at sequence numbers from the ISN used for some other
 * connection."
 *
 * The connection-id is concatenated into one region of the borrow and the PRF works in another, so
 * no array here has automatic storage duration. The secret key is IDEMIP_TCP_ISN_SECRET_BYTES octets
 * in the context: sec 3 says "Key lengths of 128 bits should be adequate."
 */

#ifndef IDEMIP_TCP_ISN_H
#define IDEMIP_TCP_ISN_H

#include "src/idemip_config.h"

#if IDEMIP_ENABLE_TCP

IDEMIP_BEGIN_DECLS

/**
 * @brief Octets an address operand spans.
 *
 * RFC 4291 sec 2: "IPv6 addresses are 128-bit identifiers for interfaces and sets of interfaces".
 * An RFC 791 sec 3.1 address is the first four of them, and only those four enter the connection-id.
 */
#define IDEMIP_TCP_ISN_ADDR_BYTES 16u

/**
 * @brief Ticks of RFC 6528 sec 3's M in one millisecond.
 *
 * "M is the 4 microsecond timer", and the caller's clock counts milliseconds, so M advances 250 per
 * millisecond.
 */
#define IDEMIP_TCP_ISN_TICKS_PER_MS 250u

static_assert(IDEMIP_TCP_ISN_TICKS_PER_MS * 4u == 1000u,
              "RFC 6528 sec 3's M advances once per 4 microseconds, so a millisecond is 250 ticks");

/**
 * @brief What a seed takes.
 *
 * RFC 6528 sec 3: "The secret key can either be a true random number [RFC4086] or some per-host
 * secret", and it "could be changed" when "The system is being bootstrapped", when "Some
 * predefined/random time has expired", or when "The secret key has been used sufficiently often that
 * it should be regarded as insecure at that point." One entry serves all four.
 *
 * The same section states what a rekey costs, and this entry does not enforce it: "changing the
 * secret would change the ISN space used for reincarnated connections, and thus could cause the
 * 4.4BSD heuristics to fail; to maintain safety, either dead connection state could be kept or a
 * quiet time observed for two maximum segment lifetimes before such a change." @c base carries M
 * across a rekey, and nothing carries F: every four-tuple lands in a new space at the instant the
 * key changes. The caller owns that timing, and IDEMIP_TCP_MSL_MS is the MSL the rest of the stack
 * counts in.
 *
 * @var TcpIsnSeedArgs::key     the secret, in the caller's storage, read and not held
 * @var TcpIsnSeedArgs::key_len its octets, at least IDEMIP_TCP_ISN_SECRET_BYTES
 * @var TcpIsnSeedArgs::base    the tick M is counted from, so a reseed can leave M rising
 */
typedef struct
{
    const uint8_t *key;
    size_t key_len;
    uint32_t base;
} TcpIsnSeedArgs;

/**
 * @brief What a generate takes: the connection-id of RFC 6528 sec 3, and the clock M is read from.
 *
 * @var TcpIsnGenArgs::local_ip    localip, IDEMIP_TCP_ISN_ADDR_BYTES octets in the caller's storage,
 *                                 the first four read when @c ip_version is 4
 * @var TcpIsnGenArgs::remote_ip   remoteip, the same width
 * @var TcpIsnGenArgs::now_ms      the caller's monotonic millisecond count, scaled by
 *                                 IDEMIP_TCP_ISN_TICKS_PER_MS to reach M
 * @var TcpIsnGenArgs::local_port  localport, the RFC 9293 sec 3.1 Source Port this end will send
 * @var TcpIsnGenArgs::remote_port remoteport, the Destination Port it will send to
 * @var TcpIsnGenArgs::ip_version  4 for an RFC 791 sec 3.1 address pair, 6 for an RFC 8200 sec 3 one
 */
typedef struct
{
    const uint8_t *local_ip;
    const uint8_t *remote_ip;
    uint32_t now_ms;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t ip_version;
} TcpIsnGenArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns. Two workers on two borrows share no byte
 * of this.
 *
 * @var TcpIsnIo::seed_args the secret key a seed takes, and the tick M is counted from
 * @var TcpIsnIo::gen_args  the connection-id a generate hashes, and the clock it reads M from
 * @var TcpIsnIo::status    what the call reports: OK, BUSY, or ERR
 * @var TcpIsnIo::isn       what a generate produced: M + F(localip, localport, remoteip, remoteport,
 *                          secretkey)
 */
typedef struct
{
    TcpIsnSeedArgs seed_args;
    TcpIsnGenArgs gen_args;

    IdemIpStatus status;
    uint32_t isn;
} TcpIsnIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The two working regions start at
// IDEMIP_TCP_ISN_CTX_BYTES, which idemip_config.h asserts is a multiple of IDEMIP_ALIGN, so the
// operand block and the context growing does not move either.

#define IDEMIP_TCP_ISN_OFF_IO 0u ///< the operand and result block
#define IDEMIP_TCP_ISN_OFF_CTX (IDEMIP_TCP_ISN_OFF_IO + IDEMIP_ROUND_UP(sizeof(TcpIsnIo), IDEMIP_ALIGN)) ///< the secret key and M's base

/**
 * @brief The connection-id the PRF is fed, IDEMIP_TCP_ISN_BLOCK_BYTES octets.
 *
 * RFC 6528 sec 3 concatenates localip, localport, remoteip, remoteport and secretkey, in that order.
 */
#define IDEMIP_TCP_ISN_OFF_BLOCK IDEMIP_TCP_ISN_CTX_BYTES

/**
 * @brief The PRF's own working set, IDEMIP_TCP_ISN_HASH_BYTES octets.
 *
 * RFC 6528 sec 3: "The PRF could be implemented as a cryptographic hash of the concatenation of the
 * connection-id and some secret data".
 */
#define IDEMIP_TCP_ISN_OFF_HASH (IDEMIP_TCP_ISN_OFF_BLOCK + IDEMIP_TCP_ISN_BLOCK_BYTES)

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_TCP_ISN_IO(w) ((TcpIsnIo *)(void *)((w) + IDEMIP_TCP_ISN_OFF_IO))

/**
 * @brief The RFC 6528 sec 3 ISN generator.
 *
 *   TcpIsn.reset(work);
 *   IDEMIP_TCP_ISN_IO(work)->seed_args.key = my_secret;
 *   IDEMIP_TCP_ISN_IO(work)->seed_args.key_len = sizeof my_secret;
 *   TcpIsn.seed(work);
 *   IDEMIP_TCP_ISN_IO(work)->gen_args.local_ip = src;
 *   TcpIsn.generate(work);
 *   if (IDEMIP_TCP_ISN_IO(work)->status == IDEMIP_OK) { iss = IDEMIP_TCP_ISN_IO(work)->isn; }
 *
 * @c work is IDEMIP_TCP_ISN_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * generators are two borrows and share not one byte, which is what keeps one connection's
 * connection-id out of another's.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. A borrow that was never reset, a generate before a seed, a key shorter than
 * IDEMIP_TCP_ISN_SECRET_BYTES, and an unknown IP version are all ERR: none of them succeeds on a
 * retry.
 *
 * @var TcpIsnNs::reset    zero the context and both working regions, so no key is left in the borrow
 * @var TcpIsnNs::seed     take the secret key and the tick M is counted from
 * @var TcpIsnNs::generate build the connection-id, run the PRF over it, and report
 *                        M + F(...) in @ref TcpIsnIo::isn
 */
typedef struct
{
    void (*const reset)(uint8_t *work);
    void (*const seed)(uint8_t *work);
    void (*const generate)(uint8_t *work);
} TcpIsnNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_tcp_isn_reset(uint8_t *work);
void idemip_tcp_isn_seed(uint8_t *work);
void idemip_tcp_isn_generate(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `TcpIsn.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const TcpIsnNs TcpIsn IDEMIP_UNUSED = {
    .reset = idemip_tcp_isn_reset,
    .seed = idemip_tcp_isn_seed,
    .generate = idemip_tcp_isn_generate};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TCP

#endif // IDEMIP_TCP_ISN_H
