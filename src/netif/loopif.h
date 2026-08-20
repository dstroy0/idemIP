// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file loopif.h
 * @brief The loopback interface: a frame the host sent to itself, held until the next dispatch pass.
 *
 * RFC 1122 sec 3.2.1.3 case (g) gives it the IPv4 form, "{ 127, <any> } Internal host loopback
 * address. Addresses of this form MUST NOT appear outside a host." RFC 4291 sec 2.5.3 gives it the
 * IPv6 one, "The unicast address 0:0:0:0:0:0:0:1 is called the loopback address... It must not be
 * assigned to any physical interface."
 *
 * There is no DMA engine behind this interface and no driver buffer to sit in, so the frame regions
 * are in the caller's borrow: output copies a frame into a free one, claim hands the oldest back
 * where it lies, and release frees it. The shape is phy's receive contract over the caller's own
 * bytes.
 */

#ifndef IDEMIP_LOOPIF_H
#define IDEMIP_LOOPIF_H

#include "src/ethernet/ethernet.h" // IDEMIP_ETH_FRAME_MAX, and through it the config
#include "src/ip/ipv6.h"           // IDEMIP_IP6_ADDR_LEN, under the IPv6 gate

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/**
 * @brief The IPv4 loopback network, and the mask that selects it.
 *
 * RFC 1122 sec 3.2.1.3 case (g) writes it as "{ 127, <any> }", so the network number is the whole
 * test: any host part on network 127 is the internal host loopback address.
 */
#define IDEMIP_LOOPIF_NET4 0x7F000000u
#define IDEMIP_LOOPIF_NET4_MASK 0xFF000000u

/**
 * @brief What bind takes: which interface this is, and the addresses it answers to.
 *
 * @var LoopifBindArgs::addr4 the RFC 1122 sec 3.2.1.3 case (g) address, host order
 * @var LoopifBindArgs::addr6 IDEMIP_IP6_ADDR_LEN octets, the RFC 4291 sec 2.5.3 loopback address
 * @var LoopifBindArgs::mtu   the octets of payload one looped frame may carry, at most
 *                            IDEMIP_ETH_MAX_PAYLOAD. output refuses a frame past it plus the
 *                            RFC 894 header, so an interface no bind has run on loops nothing.
 * @var LoopifBindArgs::index which interface record in the netif table this one occupies
 */
typedef struct
{
    uint32_t addr4;
#if IDEMIP_ENABLE_IPV6
    const uint8_t *addr6;
#endif
    uint16_t mtu;
    uint8_t index;
} LoopifBindArgs;

/**
 * @brief What output takes: the frame to loop.
 *
 * @var LoopifOutputArgs::frame the octets to copy into a free region, header included
 * @var LoopifOutputArgs::len   how many, at most IDEMIP_ETH_FRAME_MAX
 */
typedef struct
{
    const uint8_t *frame;
    size_t len;
} LoopifOutputArgs;

/**
 * @brief What an address test takes.
 *
 * @var LoopifMatchArgs::addr4 what owns4 tests, host order
 * @var LoopifMatchArgs::addr6 IDEMIP_IP6_ADDR_LEN octets, what owns6 tests
 */
typedef struct
{
    uint32_t addr4;
#if IDEMIP_ENABLE_IPV6
    const uint8_t *addr6;
#endif
} LoopifMatchArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var LoopifIo::bind_args   the addresses and the MTU bind takes
 * @var LoopifIo::output_args the frame output copies in
 * @var LoopifIo::match_args  the address owns4 and owns6 test
 * @var LoopifIo::status      what the call reports: OK, BUSY, or ERR
 * @var LoopifIo::frame       what claim found, in this borrow's frame region, valid until release
 * @var LoopifIo::len         how long that frame is, or 0 when nothing was waiting
 * @var LoopifIo::slot        which frame region the call reached
 * @var LoopifIo::held        frames waiting, at most IDEMIP_LOOPIF_FRAMES
 * @var LoopifIo::owned       whether the tested address is this interface's
 */
typedef struct
{
    LoopifBindArgs bind_args;
    LoopifOutputArgs output_args;
    LoopifMatchArgs match_args;

    IdemIpStatus status;
    const uint8_t *frame;
    size_t len;
    uint8_t slot;
    uint8_t held;
    idemip_bool owned;
} LoopifIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The operand block and the context share the
// IDEMIP_LOOPIF_CTX_BYTES ahead of the frame regions, so those regions sit at offsets no struct
// layout can move.

#define IDEMIP_LOOPIF_OFF_IO 0u ///< the operand and result block
#define IDEMIP_LOOPIF_OFF_CTX IDEMIP_ROUND_UP(IDEMIP_LOOPIF_OFF_IO + sizeof(LoopifIo), IDEMIP_ALIGN)
#define IDEMIP_LOOPIF_OFF_FRAMES IDEMIP_LOOPIF_CTX_BYTES ///< IDEMIP_LOOPIF_FRAMES regions, one frame each
#define IDEMIP_LOOPIF_OFF_END                                                                                          \
    (IDEMIP_LOOPIF_OFF_FRAMES + (IDEMIP_LOOPIF_FRAMES << IDEMIP_LOOPIF_FRAME_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_LOOPIF_IO(w) ((LoopifIo *)(void *)((w) + IDEMIP_LOOPIF_OFF_IO))

/**
 * @brief The loopback interface.
 *
 *   Loopif.clear(work);
 *   IDEMIP_LOOPIF_IO(work)->bind_args.addr4 = 0x7F000001u;
 *   IDEMIP_LOOPIF_IO(work)->bind_args.addr6 = lo6;
 *   IDEMIP_LOOPIF_IO(work)->bind_args.mtu = 1500u;
 *   Loopif.bind(work);
 *   IDEMIP_LOOPIF_IO(work)->output_args.frame = f;
 *   IDEMIP_LOOPIF_IO(work)->output_args.len = n;
 *   Loopif.output(work);
 *
 * @c work is IDEMIP_LOOPIF_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the interface, so two
 * loopback interfaces are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. Every region full is BUSY, and so is nothing waiting: the caller comes back
 * on a later tick. A frame the bound MTU cannot carry, a claim already out, or a release with
 * nothing claimed is ERR.
 *
 * @var LoopifNs::clear   zero the context and every frame region, which every other entry refuses
 *                        until it has run. The operand block is the caller's and is left alone.
 * @var LoopifNs::bind    take the two loopback addresses, the MTU and the interface index
 * @var LoopifNs::output  copy a frame into a free region. BUSY when every region is full.
 * @var LoopifNs::claim   the oldest frame waiting, where it lies. BUSY when none is.
 * @var LoopifNs::release free the claimed region
 * @var LoopifNs::owns4   whether an IPv4 address is this interface's (RFC 1122 sec 3.2.1.3 case (g)),
 *                        reported in @ref LoopifIo::owned. OK whichever way it went.
 * @var LoopifNs::owns6   whether an IPv6 address is this interface's (RFC 4291 sec 2.5.3), reported
 *                        the same way
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const bind)(uint8_t *work);
    void (*const output)(uint8_t *work);
    void (*const claim)(uint8_t *work);
    void (*const release)(uint8_t *work);
    void (*const owns4)(uint8_t *work);
#if IDEMIP_ENABLE_IPV6
    void (*const owns6)(uint8_t *work);
#endif
} LoopifNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_loopif_clear(uint8_t *work);
void idemip_loopif_bind(uint8_t *work);
void idemip_loopif_output(uint8_t *work);
void idemip_loopif_claim(uint8_t *work);
void idemip_loopif_release(uint8_t *work);
void idemip_loopif_owns4(uint8_t *work);
#if IDEMIP_ENABLE_IPV6
void idemip_loopif_owns6(uint8_t *work);
#endif

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Loopif.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const LoopifNs Loopif IDEMIP_UNUSED = {
    .clear = idemip_loopif_clear,
    .bind = idemip_loopif_bind,
    .output = idemip_loopif_output,
    .claim = idemip_loopif_claim,
    .release = idemip_loopif_release,
    .owns4 = idemip_loopif_owns4,
#if IDEMIP_ENABLE_IPV6
    .owns6 = idemip_loopif_owns6,
#endif
};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_LOOPIF_H
