// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file phy.h
 * @brief The PHY contract: what a link driver supplies, and what the layers above it may ask.
 *
 * Frames move by DMA, so nothing here copies one. A receiver claims the buffer the engine wrote
 * into, reads it where it lies, and releases the descriptor back. A sender claims a buffer the
 * engine will read from, builds into it, and commits.
 *
 * The MII management register map (IEEE 802.3 Clause 22) is in mii.h. No vendor register appears
 * here or there.
 */

#ifndef IDEMIP_PHY_H
#define IDEMIP_PHY_H

#include "src/ethernet/mii.h"

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

/** @brief Negotiated line rate, in megabits per second. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_PHY_SPEED_NONE = 0, ///< no link
    IDEMIP_PHY_SPEED_10 = 10,
    IDEMIP_PHY_SPEED_100 = 100,
    IDEMIP_PHY_SPEED_1000 = 1000,
} IdemIpPhySpeed;

/** @brief What the link reports about itself. */
typedef struct
{
    IdemIpPhySpeed speed;    ///< negotiated rate; NONE while the link is down
    idemip_bool full_duplex; ///< true when the link negotiated full duplex
    idemip_bool up;          ///< true once the link is usable
} IdemIpPhyLink;

/**
 * @brief What a link driver supplies. Every call runs in the driver's own context.
 *
 * @var IdemIpPhyDriver::link       the link's current state
 * @var IdemIpPhyDriver::mac        this interface's 48-bit address (RFC 894)
 * @var IdemIpPhyDriver::rx_claim   the next frame the engine filled, in place. Writes the buffer
 *                                  to @p frame and returns its length, or 0 when the ring is
 *                                  empty. The buffer stays valid until rx_release.
 * @var IdemIpPhyDriver::rx_release give the descriptor back to the engine.
 * @var IdemIpPhyDriver::tx_claim   a buffer of at least @p len bytes the engine reads from, or
 *                                  null when the ring is full
 * @var IdemIpPhyDriver::tx_commit  hand the claimed buffer to the MAC, @p len bytes of it
 * @var IdemIpPhyDriver::cache_invalidate  discard any cached copy of a span the engine wrote
 * @var IdemIpPhyDriver::cache_clean       write back any cached copy of a span the engine reads
 * @var IdemIpPhyDriver::mdio_read  read one MII management register (IEEE 802.3 Clause 22)
 * @var IdemIpPhyDriver::mdio_write write one MII management register (IEEE 802.3 Clause 22)
 */
typedef struct
{
    IdemIpPhyLink (*link)(void);
    const uint8_t *(*mac)(void);

    size_t (*rx_claim)(const uint8_t **frame);
    void (*rx_release)(void);
    uint8_t *(*tx_claim)(size_t len);
    idemip_bool (*tx_commit)(size_t len);

    // No-ops on a part without a data cache. Both are required: a null one is refused at bind
    // rather than tested on every frame.
    void (*cache_invalidate)(const void *p, size_t len);
    void (*cache_clean)(const void *p, size_t len);

    // Clause 22 management. The driver owns the MDC/MDIO timing, this layer owns what the
    // registers mean. Both address fields are 5 bits on the wire.
    idemip_bool (*mdio_read)(uint8_t phy_addr, uint8_t reg, uint16_t *out);
    idemip_bool (*mdio_write)(uint8_t phy_addr, uint8_t reg, uint16_t val);
} IdemIpPhyDriver;

/** @brief What bind takes. */
typedef struct
{
    const IdemIpPhyDriver *drv;
    uint8_t addr; ///< the Clause 22 management address, 0 through 31
} PhyBindArgs;

/** @brief What a transmit claim takes. */
typedef struct
{
    size_t len;
} PhyTxArgs;

/** @brief What a register access takes. */
typedef struct
{
    uint8_t reg;
    uint16_t val; ///< what write sends; unread by read
} PhyRegArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns. Two workers on two borrows share no
 * byte of this, which is what makes the same call on the same borrow do the same thing.
 *
 * @var PhyIo::bind_args  the driver and its management address
 * @var PhyIo::tx_args    the length a transmit claim asks for, and the length it commits
 * @var PhyIo::reg_args   the register a management access names, and the value a write sends
 * @var PhyIo::status     what the call reports: OK, BUSY, or ERR
 * @var PhyIo::link       what poll_link read
 * @var PhyIo::mac        what poll_link reports, IDEMIP_MAC_LEN bytes in the driver's storage
 * @var PhyIo::frame      what rx_claim found, in the engine's buffer, valid until rx_release
 * @var PhyIo::len        how long that frame is, or 0 when the ring was empty
 * @var PhyIo::tx         what tx_claim handed back, or null when the ring was full. It stays until
 *                        the MAC takes it, so a commit that reported BUSY leaves it to retry with.
 * @var PhyIo::reg        what mdio_read returned
 */
typedef struct
{
    PhyBindArgs bind_args;
    PhyTxArgs tx_args;
    PhyRegArgs reg_args;

    IdemIpStatus status;
    IdemIpPhyLink link;
    const uint8_t *mac;
    const uint8_t *frame;
    size_t len;
    uint8_t *tx;
    uint16_t reg;
} PhyIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime.

#define IDEMIP_PHY_OFF_IO 0u ///< the operand and result block
#define IDEMIP_PHY_OFF_CTX (IDEMIP_PHY_OFF_IO + IDEMIP_ROUND_UP(sizeof(PhyIo), IDEMIP_ALIGN))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_PHY_IO(w) ((PhyIo *)(void *)((w) + IDEMIP_PHY_OFF_IO))

/**
 * @brief The bound link.
 *
 *   IDEMIP_PHY_IO(work)->bind_args.drv = &my_driver;
 *   IDEMIP_PHY_IO(work)->bind_args.addr = 1;
 *   Phy.bind(work);
 *   Phy.rx_claim(work);
 *   if (IDEMIP_PHY_IO(work)->status == IDEMIP_OK) { ... Phy.rx_release(work); }
 *
 * @c work is IDEMIP_PHY_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are
 * carved is this module's and is never named here beyond the map above. The borrow IS the
 * interface, so two links are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata
 * and the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick.
 *
 * @var PhyNs::bind       take the driver, after checking every member is present
 * @var PhyNs::poll_link  read the link state into @ref PhyNs::link
 * @var PhyNs::rx_claim   claim the next received frame, invalidating its cache lines first.
 *                       BUSY when the ring is empty.
 * @var PhyNs::rx_release give the claimed descriptor back
 * @var PhyNs::tx_claim   claim a transmit buffer of @ref PhyTxArgs::len bytes. BUSY when the ring
 *                       is full, which is a retry and not a fault.
 * @var PhyNs::tx_commit  clean the buffer's cache lines and hand it to the MAC. BUSY when the MAC
 *                        would not take it, and the claim stands so the retry commits the same
 *                        buffer; @ref PhyIo::tx is cleared only once the MAC has it.
 * @var PhyNs::mdio_read  read one management register into @ref PhyNs::reg
 * @var PhyNs::mdio_write write one management register
 */
typedef struct
{
    void (*const bind)(uint8_t *work);
    void (*const poll_link)(uint8_t *work);
    void (*const rx_claim)(uint8_t *work);
    void (*const rx_release)(uint8_t *work);
    void (*const tx_claim)(uint8_t *work);
    void (*const tx_commit)(uint8_t *work);
    void (*const mdio_read)(uint8_t *work);
    void (*const mdio_write)(uint8_t *work);
} PhyNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_phy_bind(uint8_t *work);
void idemip_phy_poll_link(uint8_t *work);
void idemip_phy_rx_claim(uint8_t *work);
void idemip_phy_rx_release(uint8_t *work);
void idemip_phy_tx_claim(uint8_t *work);
void idemip_phy_tx_commit(uint8_t *work);
void idemip_phy_mdio_read(uint8_t *work);
void idemip_phy_mdio_write(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Phy.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const PhyNs Phy IDEMIP_UNUSED = {
    .bind = idemip_phy_bind,
    .poll_link = idemip_phy_poll_link,
    .rx_claim = idemip_phy_rx_claim,
    .rx_release = idemip_phy_rx_release,
    .tx_claim = idemip_phy_tx_claim,
    .tx_commit = idemip_phy_tx_commit,
    .mdio_read = idemip_phy_mdio_read,
    .mdio_write = idemip_phy_mdio_write};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_PHY_H
