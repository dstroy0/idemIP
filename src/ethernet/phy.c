// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file phy.c
 * @brief The bound link driver, and the claim/release frame path over it.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the
 * operand block and the context are both regions of that borrow, at compile-time offsets, and no
 * entry reads or writes a byte outside it. Two borrows therefore share nothing, and the same call
 * on the same borrow does the same thing.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ethernet/phy.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. A claimed descriptor is tracked so a release without a
// claim, and a second claim before a release, are both refused rather than handed to the engine.
typedef struct
{
    const IdemIpPhyDriver *drv;
    uint8_t addr;
    idemip_bool claimed;
} PhyCtx;

// The caller's borrow, split: the operand block, then the context. phy.h publishes the offsets; the
// assert below proves the span covers them before anything runs.
static_assert(IDEMIP_PHY_OFF_CTX + sizeof(PhyCtx) <= IDEMIP_PHY_BORROW,
              "IDEMIP_PHY_BORROW is short of the operand block and the context - raise it in idemip_config.h");

// The region, at its offset in the caller's borrow.
#define PHY_CTX(w) ((PhyCtx *)(void *)((w) + IDEMIP_PHY_OFF_CTX))
#define PHY_IO(w) IDEMIP_PHY_IO(w)

// --- the entries -----------------------------------------------------------

// Every member is called without a null test on the frame path, so an incomplete driver is
// refused here rather than faulting at the first frame.
static void phy_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    PhyIo *io = PHY_IO(work);
    io->status = IDEMIP_ERR;
    const IdemIpPhyDriver *drv = io->bind_args.drv;
    if (drv == NULL || io->bind_args.addr >= IDEMIP_MII_PHY_ADDR_MAX)
    {
        return;
    }
    if (drv->link == NULL || drv->mac == NULL || drv->rx_claim == NULL || drv->rx_release == NULL ||
        drv->tx_claim == NULL || drv->tx_commit == NULL || drv->cache_invalidate == NULL || drv->cache_clean == NULL ||
        drv->mdio_read == NULL || drv->mdio_write == NULL)
    {
        return;
    }
    PhyCtx *ctx = PHY_CTX(work);
    ctx->drv = drv;
    ctx->addr = io->bind_args.addr;
    ctx->claimed = IDEMIP_FALSE;
    io->status = IDEMIP_OK;
}

static void phy_poll_link(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    PhyIo *io = PHY_IO(work);
    PhyCtx *ctx = PHY_CTX(work);
    io->status = IDEMIP_ERR;
    if (ctx->drv == NULL)
    {
        return;
    }
    io->link = ctx->drv->link();
    io->mac = ctx->drv->mac();
    io->status = IDEMIP_OK;
}

// The engine wrote the buffer, so any cached copy of it is stale and is discarded before the
// frame is read. An empty ring is BUSY: the caller comes back on a later tick.
static void phy_rx_claim(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    PhyIo *io = PHY_IO(work);
    PhyCtx *ctx = PHY_CTX(work);
    io->status = IDEMIP_ERR;
    io->frame = NULL;
    io->len = 0;
    if (ctx->drv == NULL || ctx->claimed)
    {
        return;
    }
    const uint8_t *frame = NULL;
    size_t len = ctx->drv->rx_claim(&frame);
    if (len == 0 || frame == NULL)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    ctx->drv->cache_invalidate(frame, len);
    ctx->claimed = IDEMIP_TRUE;
    io->frame = frame;
    io->len = len;
    io->status = IDEMIP_OK;
}

static void phy_rx_release(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    PhyIo *io = PHY_IO(work);
    PhyCtx *ctx = PHY_CTX(work);
    io->status = IDEMIP_ERR;
    if (ctx->drv == NULL || !ctx->claimed)
    {
        return;
    }
    ctx->drv->rx_release();
    ctx->claimed = IDEMIP_FALSE;
    io->frame = NULL;
    io->len = 0;
    io->status = IDEMIP_OK;
}

// A full ring is BUSY, which is a retry on a later tick. A length no frame can ever carry (RFC 894)
// is ERR, which is not: the driver answers both with a null buffer, so the length is bounded here
// rather than letting a request that can never fit be retried forever.
static void phy_tx_claim(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    PhyIo *io = PHY_IO(work);
    PhyCtx *ctx = PHY_CTX(work);
    io->status = IDEMIP_ERR;
    io->tx = NULL;
    if (ctx->drv == NULL || io->tx_args.len == 0 || io->tx_args.len > IDEMIP_ETH_FRAME_MAX)
    {
        return;
    }
    io->tx = ctx->drv->tx_claim(io->tx_args.len);
    io->status = (io->tx != NULL) ? IDEMIP_OK : IDEMIP_BUSY;
}

// The engine reads the buffer, so what the build left in cache is written back before the
// descriptor is handed over. A driver that could not queue it reports BUSY.
static void phy_tx_commit(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    PhyIo *io = PHY_IO(work);
    PhyCtx *ctx = PHY_CTX(work);
    io->status = IDEMIP_ERR;
    if (ctx->drv == NULL || io->tx == NULL || io->tx_args.len == 0)
    {
        return;
    }
    ctx->drv->cache_clean(io->tx, io->tx_args.len);
    io->status = ctx->drv->tx_commit(io->tx_args.len) ? IDEMIP_OK : IDEMIP_BUSY;
    io->tx = NULL;
}

static void phy_mdio_read(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    PhyIo *io = PHY_IO(work);
    PhyCtx *ctx = PHY_CTX(work);
    io->status = IDEMIP_ERR;
    io->reg = 0;
    if (ctx->drv == NULL || io->reg_args.reg >= IDEMIP_MII_REG_MAX)
    {
        return;
    }
    io->status = ctx->drv->mdio_read(ctx->addr, io->reg_args.reg, &io->reg) ? IDEMIP_OK : IDEMIP_BUSY;
}

static void phy_mdio_write(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    PhyIo *io = PHY_IO(work);
    PhyCtx *ctx = PHY_CTX(work);
    io->status = IDEMIP_ERR;
    if (ctx->drv == NULL || io->reg_args.reg >= IDEMIP_MII_REG_MAX)
    {
        return;
    }
    io->status = ctx->drv->mdio_write(ctx->addr, io->reg_args.reg, io->reg_args.val) ? IDEMIP_OK : IDEMIP_BUSY;
}

const PhyNs Phy = {.bind = phy_bind,
                   .poll_link = phy_poll_link,
                   .rx_claim = phy_rx_claim,
                   .rx_release = phy_rx_release,
                   .tx_claim = phy_tx_claim,
                   .tx_commit = phy_tx_commit,
                   .mdio_read = phy_mdio_read,
                   .mdio_write = phy_mdio_write};

IDEMIP_END_DECLS
