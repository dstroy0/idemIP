// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A link driver for the host: an IdemIpPhyDriver over storage the test owns, so a case injects a
// frame and reads back what was transmitted.
//
// Modeled on the recording driver in test/unit/ethernet/test_phy/test_phy.c and on ProtoCore's
// host DMA rig, core_setup/hal/host/protocore_dma_host.h. Its engine advances only inside
// protocore_dma_hw_poll(), and this one advances only inside idemip_fake_phy_poll(), so a test
// decides when a transfer completes. Egress completes first, which is the order that rig uses: a
// poll finishes every committed frame, up to IDEMIP_TX_DESCRIPTORS in flight, then lands at most
// one ingress in a receive buffer.
//
// A transmit buffer a claim handed out and no post committed stays out of the ring, because
// IdemIpPhyDriver has no entry that gives an unposted one back. The claim cursor therefore only
// advances, and a caller that abandons IDEMIP_TX_DESCRIPTORS claims sees every later claim refused.
//
// The receive and transmit buffers are the CALLER's arrays, the same two Dma.bind is handed, and
// this rig claims out of them: dma.c maps the address a claim returns back to a descriptor by
// comparing it against base + i * IDEMIP_DMA_BUF_STRIDE, so a driver handing back storage of its
// own would name no descriptor.
//
// The cache hook order is recorded. phy.c invalidates a receive buffer before the frame is
// readable and cleans a transmit buffer before the descriptor is handed over, and dma.c does the
// same, so the event log is what a case asserts that ordering on.
//
// IdemIpPhyDriver carries no context argument, so one port's ten entries are one macro expansion
// over one row of g_idemip_fake_phy. A test writes IDEMIP_FAKE_PHY_DRIVER(0) and
// IDEMIP_FAKE_PHY_DRIVER(1) and gets two independent links.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#ifndef IDEMIP_TEST_FAKE_PHY_H
#define IDEMIP_TEST_FAKE_PHY_H

#include "src/ethernet/ethernet.h"
#include "src/ethernet/phy.h"
#include "src/ethernet/mii_defines.h" // the Clause 22 register set this fake answers with

#include <string.h>

// Frames the wire holds in each direction. A power of two, so the index is a mask.
#ifndef IDEMIP_FAKE_PHY_SLOTS
#define IDEMIP_FAKE_PHY_SLOTS 16u
#endif
#define IDEMIP_FAKE_PHY_SLOT_MASK (IDEMIP_FAKE_PHY_SLOTS - 1u)

// Driver calls one case records before the log wraps.
#ifndef IDEMIP_FAKE_PHY_EVENTS
#define IDEMIP_FAKE_PHY_EVENTS 512u
#endif

// Ports one test binary defines drivers for.
#ifndef IDEMIP_FAKE_PHY_PORTS
#define IDEMIP_FAKE_PHY_PORTS 2u
#endif

#define IDEMIP_FAKE_PHY_RX_MASK (IDEMIP_RX_DESCRIPTORS - 1u)
#define IDEMIP_FAKE_PHY_TX_MASK (IDEMIP_TX_DESCRIPTORS - 1u)

// What the driver was asked to do, in the order it was asked.
#define IDEMIP_FAKE_PHY_EV_RX_CLAIM 1
#define IDEMIP_FAKE_PHY_EV_INVALIDATE 2
#define IDEMIP_FAKE_PHY_EV_RX_RELEASE 3
#define IDEMIP_FAKE_PHY_EV_TX_CLAIM 4
#define IDEMIP_FAKE_PHY_EV_CLEAN 5
#define IDEMIP_FAKE_PHY_EV_TX_COMMIT 6

// One link's whole state. The two buffer arrays are the caller's; everything else is this rig's.
//
// Three monotone counters run the receive ring: fill is what the engine wrote, read is what
// rx_claim handed out, free is what rx_release gave back. The engine may write while
// fill - free stays below IDEMIP_RX_DESCRIPTORS, and a slot index is a counter masked.
typedef struct
{
    uint8_t *rx_base; // IDEMIP_RX_DESCRIPTORS buffers of IDEMIP_DMA_BUF_STRIDE
    uint8_t *tx_base; // IDEMIP_TX_DESCRIPTORS buffers of the same stride

    uint8_t in[IDEMIP_FAKE_PHY_SLOTS][IDEMIP_DMA_FRAME_MAX]; // fed, waiting for the engine
    uint16_t in_len[IDEMIP_FAKE_PHY_SLOTS];
    uint32_t in_head;
    uint32_t in_tail;

    uint16_t rx_len[IDEMIP_RX_DESCRIPTORS];
    uint32_t rx_fill;
    uint32_t rx_read;
    uint32_t rx_free;

    uint32_t tx_head;                               // the next transmit buffer tx_claim hands out
    uint32_t tx_flight_slot[IDEMIP_TX_DESCRIPTORS]; // committed, waiting for the engine
    uint16_t tx_flight_len[IDEMIP_TX_DESCRIPTORS];
    uint32_t tx_flight_head;
    uint32_t tx_flight_tail;

    uint8_t out[IDEMIP_FAKE_PHY_SLOTS][IDEMIP_DMA_FRAME_MAX]; // transmitted, waiting to be read
    uint16_t out_len[IDEMIP_FAKE_PHY_SLOTS];
    uint32_t out_head;
    uint32_t out_tail;

    uint8_t mac[IDEMIP_MAC_LEN];
    uint16_t regs[IDEMIP_MII_REG_MAX];
    IdemIpPhyLink link;

    int tx_full;  // a case forces a transmit ring with no room
    int tx_fails; // a case forces a commit the driver could not queue

    uint8_t ev[IDEMIP_FAKE_PHY_EVENTS];
    uint32_t ev_n;

    uint32_t rx_claims;
    uint32_t rx_releases;
    uint32_t tx_claims;
    uint32_t tx_commits;
    uint32_t invalidates;
    uint32_t cleans;
    const void *last_invalidate;
    size_t last_invalidate_len;
    const void *last_clean;
    size_t last_clean_len;
    uint32_t dropped_feeds; // frames the wire had no room for
} IdemIpFakePhy;

// The rows the generated entries run over, defined by the one translation unit that expands
// IDEMIP_FAKE_PHY_STORAGE. Unity's generator copies a suite's includes into the runner, so a
// definition here would be a second one in that translation unit.
extern IdemIpFakePhy g_idemip_fake_phy[IDEMIP_FAKE_PHY_PORTS];

/** @brief The rig's storage. One expansion per test binary. */
#define IDEMIP_FAKE_PHY_STORAGE IdemIpFakePhy g_idemip_fake_phy[IDEMIP_FAKE_PHY_PORTS]

static inline void idemip_fake_phy_ev(IdemIpFakePhy *f, uint8_t what)
{
    if (f->ev_n < IDEMIP_FAKE_PHY_EVENTS)
    {
        f->ev[f->ev_n++] = what;
    }
}

// Zero the rig and take the caller's two buffer arrays and hardware address. The link comes up at
// 100 Mbit full duplex, which is what a case that does not drive the link reads.
static inline void idemip_fake_phy_attach(IdemIpFakePhy *f, uint8_t *rx_base, uint8_t *tx_base, const uint8_t *mac)
{
    memset(f, 0, sizeof *f);
    f->rx_base = rx_base;
    f->tx_base = tx_base;
    memcpy(f->mac, mac, IDEMIP_MAC_LEN);
    f->link.speed = IDEMIP_PHY_SPEED_100;
    f->link.full_duplex = IDEMIP_TRUE;
    f->link.up = IDEMIP_TRUE;
}

// Put @p len octets on the wire, as if the far end had just sent them. They reach a receive buffer
// on the next poll, never before it.
static inline idemip_bool idemip_fake_phy_feed(IdemIpFakePhy *f, const uint8_t *bytes, size_t len)
{
    if (bytes == NULL || len == 0u || len > IDEMIP_DMA_FRAME_MAX ||
        (f->in_head - f->in_tail) >= IDEMIP_FAKE_PHY_SLOTS)
    {
        f->dropped_feeds++;
        return IDEMIP_FALSE;
    }
    uint32_t slot = f->in_head & IDEMIP_FAKE_PHY_SLOT_MASK;
    memcpy(f->in[slot], bytes, len);
    f->in_len[slot] = (uint16_t)len;
    f->in_head++;
    return IDEMIP_TRUE;
}

// Transmitted frames waiting to be read back.
static inline size_t idemip_fake_phy_tx_count(const IdemIpFakePhy *f)
{
    return (size_t)(f->out_head - f->out_tail);
}

// Frames on the wire that no poll has moved into a receive buffer yet.
static inline size_t idemip_fake_phy_in_count(const IdemIpFakePhy *f)
{
    return (size_t)(f->in_head - f->in_tail);
}

// The oldest transmitted frame, where it lies. Null when nothing was transmitted.
static inline const uint8_t *idemip_fake_phy_tx_peek(const IdemIpFakePhy *f, size_t *len)
{
    if (f->out_head == f->out_tail)
    {
        *len = 0u;
        return NULL;
    }
    uint32_t slot = f->out_tail & IDEMIP_FAKE_PHY_SLOT_MASK;
    *len = f->out_len[slot];
    return f->out[slot];
}

// Drop the oldest transmitted frame.
static inline void idemip_fake_phy_tx_drop(IdemIpFakePhy *f)
{
    if (f->out_head != f->out_tail)
    {
        f->out_tail++;
    }
}

// Copy the oldest transmitted frame out and drop it. 0 when nothing was transmitted or @p cap is
// short of the whole frame, which is never a truncation.
static inline size_t idemip_fake_phy_capture(IdemIpFakePhy *f, uint8_t *out, size_t cap)
{
    size_t len = 0u;
    const uint8_t *frame = idemip_fake_phy_tx_peek(f, &len);
    if (frame == NULL || out == NULL || cap < len)
    {
        return 0u;
    }
    memcpy(out, frame, len);
    idemip_fake_phy_tx_drop(f);
    return len;
}

// The back-to-back link: move one frame @p from transmitted onto @p to's wire. 0 when there was
// nothing to move or the far wire had no room, in which case the frame stays put.
static inline size_t idemip_fake_phy_wire(IdemIpFakePhy *from, IdemIpFakePhy *to)
{
    size_t len = 0u;
    const uint8_t *frame = idemip_fake_phy_tx_peek(from, &len);
    if (frame == NULL || !idemip_fake_phy_feed(to, frame, len))
    {
        return 0u;
    }
    idemip_fake_phy_tx_drop(from);
    return len;
}

// The engine, one step. Egress completes first, so a frame committed this pass is readable in the
// same pass, then at most one ingress lands in a receive buffer. Nothing else in this rig moves a
// frame.
static inline void idemip_fake_phy_poll(IdemIpFakePhy *f)
{
    while (f->tx_flight_head != f->tx_flight_tail && (f->out_head - f->out_tail) < IDEMIP_FAKE_PHY_SLOTS)
    {
        uint32_t from = f->tx_flight_tail & IDEMIP_FAKE_PHY_TX_MASK;
        uint32_t slot = f->out_head & IDEMIP_FAKE_PHY_SLOT_MASK;
        memcpy(f->out[slot], f->tx_base + ((size_t)f->tx_flight_slot[from] * IDEMIP_DMA_BUF_STRIDE),
               f->tx_flight_len[from]);
        f->out_len[slot] = f->tx_flight_len[from];
        f->out_head++;
        f->tx_flight_tail++;
    }

    if (f->in_head != f->in_tail && (f->rx_fill - f->rx_free) < IDEMIP_RX_DESCRIPTORS)
    {
        uint32_t src = f->in_tail & IDEMIP_FAKE_PHY_SLOT_MASK;
        uint32_t dst = f->rx_fill & IDEMIP_FAKE_PHY_RX_MASK;
        memcpy(f->rx_base + ((size_t)dst * IDEMIP_DMA_BUF_STRIDE), f->in[src], f->in_len[src]);
        f->rx_len[dst] = f->in_len[src];
        f->rx_fill++;
        f->in_tail++;
    }
}

// --- the ten entries, one port each -------------------------------------------------------------
// rx_claim advances the read cursor, because a ring engine hands out the next descriptor it filled
// rather than the same one until it is given back. rx_release returns one buffer to the refill
// pool. IdemIpPhyDriver::rx_release names no descriptor, so this rig cannot know WHICH buffer came
// back; the two cursors therefore only count, and a case asserts fill - free stays below
// IDEMIP_RX_DESCRIPTORS so no refill lands on a buffer a unit still pins.

#define IDEMIP_FAKE_PHY_DRIVER(port)                                                                                   \
    static IdemIpPhyLink idemip_fake_phy_link_##port(void)                                                             \
    {                                                                                                                  \
        return g_idemip_fake_phy[port].link;                                                                           \
    }                                                                                                                  \
    static const uint8_t *idemip_fake_phy_mac_##port(void)                                                             \
    {                                                                                                                  \
        return g_idemip_fake_phy[port].mac;                                                                            \
    }                                                                                                                  \
    static size_t idemip_fake_phy_rx_claim_##port(const uint8_t **frame)                                               \
    {                                                                                                                  \
        IdemIpFakePhy *f = &g_idemip_fake_phy[port];                                                                   \
        idemip_fake_phy_ev(f, IDEMIP_FAKE_PHY_EV_RX_CLAIM);                                                            \
        if (f->rx_read == f->rx_fill)                                                                                  \
        {                                                                                                              \
            return 0u;                                                                                                 \
        }                                                                                                              \
        uint32_t slot = f->rx_read & IDEMIP_FAKE_PHY_RX_MASK;                                                          \
        *frame = f->rx_base + ((size_t)slot * IDEMIP_DMA_BUF_STRIDE);                                                  \
        f->rx_read++;                                                                                                  \
        f->rx_claims++;                                                                                                \
        return (size_t)f->rx_len[slot];                                                                                \
    }                                                                                                                  \
    static void idemip_fake_phy_rx_release_##port(void)                                                                \
    {                                                                                                                  \
        IdemIpFakePhy *f = &g_idemip_fake_phy[port];                                                                   \
        idemip_fake_phy_ev(f, IDEMIP_FAKE_PHY_EV_RX_RELEASE);                                                          \
        f->rx_releases++;                                                                                              \
        if (f->rx_free < f->rx_read)                                                                                   \
        {                                                                                                              \
            f->rx_free++;                                                                                              \
        }                                                                                                              \
    }                                                                                                                  \
    static uint8_t *idemip_fake_phy_tx_claim_##port(size_t len)                                                        \
    {                                                                                                                  \
        IdemIpFakePhy *f = &g_idemip_fake_phy[port];                                                                   \
        idemip_fake_phy_ev(f, IDEMIP_FAKE_PHY_EV_TX_CLAIM);                                                            \
        if (f->tx_full || len == 0u || len > IDEMIP_DMA_FRAME_MAX ||                                                   \
            (f->tx_head - f->tx_flight_tail) >= IDEMIP_TX_DESCRIPTORS)                                                 \
        {                                                                                                              \
            return NULL;                                                                                               \
        }                                                                                                              \
        uint32_t slot = f->tx_head & IDEMIP_FAKE_PHY_TX_MASK;                                                          \
        f->tx_head++;                                                                                                  \
        f->tx_claims++;                                                                                                \
        return f->tx_base + ((size_t)slot * IDEMIP_DMA_BUF_STRIDE);                                                    \
    }                                                                                                                  \
    static idemip_bool idemip_fake_phy_tx_commit_##port(size_t len)                                                    \
    {                                                                                                                  \
        IdemIpFakePhy *f = &g_idemip_fake_phy[port];                                                                   \
        idemip_fake_phy_ev(f, IDEMIP_FAKE_PHY_EV_TX_COMMIT);                                                           \
        if (f->tx_fails || len == 0u || len > IDEMIP_DMA_FRAME_MAX ||                                                  \
            (f->tx_flight_head - f->tx_flight_tail) >= IDEMIP_TX_DESCRIPTORS)                                          \
        {                                                                                                              \
            return IDEMIP_FALSE;                                                                                       \
        }                                                                                                              \
        uint32_t at = f->tx_flight_head & IDEMIP_FAKE_PHY_TX_MASK;                                                     \
        f->tx_flight_slot[at] = (f->tx_head - 1u) & IDEMIP_FAKE_PHY_TX_MASK;                                           \
        f->tx_flight_len[at] = (uint16_t)len;                                                                          \
        f->tx_flight_head++;                                                                                           \
        f->tx_commits++;                                                                                               \
        return IDEMIP_TRUE;                                                                                            \
    }                                                                                                                  \
    static void idemip_fake_phy_invalidate_##port(const void *p, size_t len)                                           \
    {                                                                                                                  \
        IdemIpFakePhy *f = &g_idemip_fake_phy[port];                                                                   \
        idemip_fake_phy_ev(f, IDEMIP_FAKE_PHY_EV_INVALIDATE);                                                          \
        f->invalidates++;                                                                                              \
        f->last_invalidate = p;                                                                                        \
        f->last_invalidate_len = len;                                                                                  \
    }                                                                                                                  \
    static void idemip_fake_phy_clean_##port(const void *p, size_t len)                                                \
    {                                                                                                                  \
        IdemIpFakePhy *f = &g_idemip_fake_phy[port];                                                                   \
        idemip_fake_phy_ev(f, IDEMIP_FAKE_PHY_EV_CLEAN);                                                               \
        f->cleans++;                                                                                                   \
        f->last_clean = p;                                                                                             \
        f->last_clean_len = len;                                                                                       \
    }                                                                                                                  \
    static idemip_bool idemip_fake_phy_mdio_read_##port(uint8_t addr, uint8_t reg, uint16_t *out)                       \
    {                                                                                                                  \
        (void)addr;                                                                                                    \
        *out = g_idemip_fake_phy[port].regs[reg];                                                                      \
        return IDEMIP_TRUE;                                                                                            \
    }                                                                                                                  \
    static idemip_bool idemip_fake_phy_mdio_write_##port(uint8_t addr, uint8_t reg, uint16_t val)                       \
    {                                                                                                                  \
        (void)addr;                                                                                                    \
        g_idemip_fake_phy[port].regs[reg] = val;                                                                       \
        return IDEMIP_TRUE;                                                                                            \
    }                                                                                                                  \
    static const IdemIpPhyDriver idemip_fake_phy_drv_##port = {                                                        \
        .link = idemip_fake_phy_link_##port,                                                                           \
        .mac = idemip_fake_phy_mac_##port,                                                                             \
        .rx_claim = idemip_fake_phy_rx_claim_##port,                                                                   \
        .rx_release = idemip_fake_phy_rx_release_##port,                                                               \
        .tx_claim = idemip_fake_phy_tx_claim_##port,                                                                   \
        .tx_commit = idemip_fake_phy_tx_commit_##port,                                                                 \
        .cache_invalidate = idemip_fake_phy_invalidate_##port,                                                         \
        .cache_clean = idemip_fake_phy_clean_##port,                                                                   \
        .mdio_read = idemip_fake_phy_mdio_read_##port,                                                                 \
        .mdio_write = idemip_fake_phy_mdio_write_##port}

#endif // IDEMIP_TEST_FAKE_PHY_H
