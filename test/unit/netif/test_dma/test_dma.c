// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for dma, shaped on test/unit/ethernet/test_phy. Every case here tests the
// CONTRACT and stays valid however the logic behind it is written:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two ring pairs share not one byte
//   4. a canary past IDEMIP_DMA_BORROW is intact after every case
//   5. the published offsets are ordered and do not overlap
//   6. clear zeroes both rings, and a borrow it has not run on is refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/netif/dma.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_DMA_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_DMA_BORROW + 16];

// The frame buffers are the DRIVER's storage, not the borrow's, so the suite owns them here the way
// a board's driver would.
static _Alignas(IDEMIP_CACHE_LINE_BYTES) uint8_t rx_bufs[IDEMIP_RX_DESCRIPTORS * IDEMIP_DMA_BUF_STRIDE];
static _Alignas(IDEMIP_CACHE_LINE_BYTES) uint8_t tx_bufs[IDEMIP_TX_DESCRIPTORS * IDEMIP_DMA_BUF_STRIDE];

// What the driver was asked to do, in the order it was asked.
#define EV_INVALIDATE 1
#define EV_CLEAN 2
static int g_ev[16];
static int g_ev_n;

static void ev(int what)
{
    if (g_ev_n < (int)(sizeof g_ev / sizeof g_ev[0]))
    {
        g_ev[g_ev_n++] = what;
    }
}

static const uint8_t g_mac[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

static IdemIpPhyLink fake_link(void)
{
    IdemIpPhyLink l = {IDEMIP_PHY_SPEED_100, 1u, 1u};
    return l;
}
static const uint8_t *fake_mac(void)
{
    return g_mac;
}
static size_t fake_rx_claim(const uint8_t **frame)
{
    (void)frame;
    return 0;
}
static void fake_rx_release(void)
{
}
static uint8_t *fake_tx_claim(size_t len)
{
    (void)len;
    return tx_bufs;
}
static idemip_bool fake_tx_commit(size_t len)
{
    (void)len;
    return IDEMIP_TRUE;
}
static void fake_invalidate(const void *p, size_t len)
{
    (void)p;
    (void)len;
    ev(EV_INVALIDATE);
}
static void fake_clean(const void *p, size_t len)
{
    (void)p;
    (void)len;
    ev(EV_CLEAN);
}
static idemip_bool fake_mdio_read(uint8_t addr, uint8_t reg, uint16_t *out)
{
    (void)addr;
    (void)reg;
    *out = 0u;
    return IDEMIP_TRUE;
}
static idemip_bool fake_mdio_write(uint8_t addr, uint8_t reg, uint16_t val)
{
    (void)addr;
    (void)reg;
    (void)val;
    return IDEMIP_TRUE;
}

static const IdemIpPhyDriver g_drv = {
    .link = fake_link,
    .mac = fake_mac,
    .rx_claim = fake_rx_claim,
    .rx_release = fake_rx_release,
    .tx_claim = fake_tx_claim,
    .tx_commit = fake_tx_commit,
    .cache_invalidate = fake_invalidate,
    .cache_clean = fake_clean,
    .mdio_read = fake_mdio_read,
    .mdio_write = fake_mdio_write,
};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_DMA_BORROW, CANARY, cap - IDEMIP_DMA_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_DMA_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_DMA_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(rx_bufs, 0xA5, sizeof rx_bufs);
    memset(tx_bufs, 0, sizeof tx_bufs);
    g_ev_n = 0;
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// Every entry, so a case that walks the whole namespace cannot miss one.
static void call_every_entry(uint8_t *w)
{
    Dma.clear(w);
    Dma.bind(w);
    Dma.rx_take(w);
    Dma.rx_post(w);
    Dma.pin(w);
    Dma.unpin(w);
    Dma.tx_take(w);
    Dma.tx_post(w);
    Dma.tx_reap(w);
    Dma.pinned(w);
}

static void set_bind_args(uint8_t *w)
{
    IDEMIP_DMA_IO(w)->bind_args.drv = &g_drv;
    IDEMIP_DMA_IO(w)->bind_args.rx_base = rx_bufs;
    IDEMIP_DMA_IO(w)->bind_args.tx_base = tx_bufs;
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the ring pair, and the operand block is in it, so two interfaces share no byte at
// all. This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    Dma.clear(work_a);
    Dma.clear(work_b);

    IDEMIP_DMA_IO(work_a)->bind_args.rx_base = rx_bufs;
    IDEMIP_DMA_IO(work_a)->desc_args.index = 3u;
    IDEMIP_DMA_IO(work_a)->desc_args.len = 64u;
    IDEMIP_DMA_IO(work_b)->bind_args.rx_base = tx_bufs;
    IDEMIP_DMA_IO(work_b)->desc_args.index = 7u;
    IDEMIP_DMA_IO(work_b)->desc_args.len = 128u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_PTR(rx_bufs, IDEMIP_DMA_IO(work_a)->bind_args.rx_base);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_DMA_IO(work_a)->desc_args.index);
    TEST_ASSERT_EQUAL_UINT16(64u, IDEMIP_DMA_IO(work_a)->desc_args.len);
    TEST_ASSERT_EQUAL_PTR(tx_bufs, IDEMIP_DMA_IO(work_b)->bind_args.rx_base);
    TEST_ASSERT_EQUAL_UINT8(7u, IDEMIP_DMA_IO(work_b)->desc_args.index);
    TEST_ASSERT_EQUAL_UINT16(128u, IDEMIP_DMA_IO(work_b)->desc_args.len);

    // And running every entry on b leaves a's operands where a left them.
    call_every_entry(work_b);
    TEST_ASSERT_EQUAL_PTR(rx_bufs, IDEMIP_DMA_IO(work_a)->bind_args.rx_base);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_DMA_IO(work_a)->desc_args.index);
    TEST_ASSERT_EQUAL_UINT16(64u, IDEMIP_DMA_IO(work_a)->desc_args.len);
}

// The two operand blocks are at the same offset in different borrows, so they are different bytes.
void test_the_two_operand_blocks_are_different_bytes(void)
{
    TEST_ASSERT_TRUE(IDEMIP_DMA_IO(work_a) != IDEMIP_DMA_IO(work_b));
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_DMA_OFF_IO, IDEMIP_DMA_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_DMA_OFF_IO, IDEMIP_DMA_IO(work_b));
}

// An entry writing its own borrow never reaches the next one. The canary is checked in tearDown, so
// this case only has to do the writing.
void test_no_entry_writes_past_the_borrow(void)
{
    Dma.clear(work_a);
    set_bind_args(work_a);
    IDEMIP_DMA_IO(work_a)->desc_args.index = (uint8_t)(IDEMIP_TX_DESCRIPTORS - 1u);
    IDEMIP_DMA_IO(work_a)->desc_args.len = 64u;
    call_every_entry(work_a);
    TEST_PASS();
}

// --- the map -----------------------------------------------------------------

// The published offsets are in order, each region ends where the next begins, and the last one ends
// inside IDEMIP_DMA_BORROW.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DMA_OFF_IO);
    TEST_ASSERT_TRUE(IDEMIP_DMA_OFF_IO + sizeof(DmaIo) <= (size_t)IDEMIP_DMA_OFF_CTX);
    TEST_ASSERT_TRUE((size_t)IDEMIP_DMA_OFF_CTX < (size_t)IDEMIP_DMA_OFF_RX);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_DMA_OFF_RX + (IDEMIP_RX_DESCRIPTORS << IDEMIP_DMA_DESC_ENTRY_SHIFT),
                             (size_t)IDEMIP_DMA_OFF_TX);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_DMA_OFF_TX + (IDEMIP_TX_DESCRIPTORS << IDEMIP_DMA_DESC_ENTRY_SHIFT),
                             (size_t)IDEMIP_DMA_OFF_END);
    TEST_ASSERT_TRUE((size_t)IDEMIP_DMA_OFF_END <= (size_t)IDEMIP_DMA_BORROW);
}

// Descriptor i sits at i << IDEMIP_DMA_DESC_ENTRY_SHIFT from its ring, so both rings start aligned.
void test_both_rings_start_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DMA_OFF_RX & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DMA_OFF_TX & (IDEMIP_ALIGN - 1u));
}

// A ring index is masked rather than divided, so each count has to be a power of two, and the
// receive ring has to outlast every retaining unit being full at once.
void test_the_ring_counts_hold_the_pin_bound(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_RX_DESCRIPTORS & (IDEMIP_RX_DESCRIPTORS - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_TX_DESCRIPTORS & (IDEMIP_TX_DESCRIPTORS - 1u));
    TEST_ASSERT_TRUE(IDEMIP_RX_DESCRIPTORS > IDEMIP_MAX_PINNED_FRAMES);
}

// A buffer spans whole cache lines, because invalidating a partial line discards whatever shares it.
void test_the_buffer_stride_spans_whole_cache_lines(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_DMA_BUF_STRIDE & (IDEMIP_CACHE_LINE_BYTES - 1u));
    TEST_ASSERT_TRUE(IDEMIP_DMA_BUF_STRIDE >= IDEMIP_DMA_FRAME_MAX);
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Dma.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
}

// Both rings are zero after clear, whatever was in them before. A zeroed descriptor holds a null
// buffer, no flags and no pins, which is the state every other entry reads as the engine not owning
// it.
void test_clear_zeroes_both_rings(void)
{
    memset(work_a, 0xFF, IDEMIP_DMA_BORROW);
    Dma.clear(work_a);
    for (size_t i = (size_t)IDEMIP_DMA_OFF_RX; i < (size_t)IDEMIP_DMA_OFF_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[i], "clear left a descriptor byte set");
    }
}

// clear is the caller's, so it does not touch the operands the caller put in the borrow.
void test_clear_leaves_the_operands_alone(void)
{
    IDEMIP_DMA_IO(work_a)->bind_args.rx_base = rx_bufs;
    IDEMIP_DMA_IO(work_a)->desc_args.len = 64u;
    Dma.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(rx_bufs, IDEMIP_DMA_IO(work_a)->bind_args.rx_base);
    TEST_ASSERT_EQUAL_UINT16(64u, IDEMIP_DMA_IO(work_a)->desc_args.len);
}

// Clearing one borrow does not clear the other.
void test_clear_reaches_one_borrow_only(void)
{
    memset(work_b, 0xFF, IDEMIP_DMA_BORROW);
    Dma.clear(work_a);
    for (size_t i = (size_t)IDEMIP_DMA_OFF_RX; i < (size_t)IDEMIP_DMA_OFF_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xFFu, work_b[i], "clear on one borrow reached another");
    }
}

// --- what is refused ---------------------------------------------------------

// Bytes clear has not run on are not a ring, so every entry refuses them rather than handing the
// engine a descriptor built out of whatever was there.
void test_an_uncleared_borrow_is_refused(void)
{
    memset(work_a, 0xFF, IDEMIP_DMA_BORROW);
    set_bind_args(work_a);
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    memset(work_a, 0xFF, IDEMIP_DMA_BORROW);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    memset(work_a, 0xFF, IDEMIP_DMA_BORROW);
    Dma.tx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    memset(work_a, 0xFF, IDEMIP_DMA_BORROW);
    Dma.pinned(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
}

// A ring with no driver behind it has no cache maintenance and no buffers, so nothing may be taken
// from it or handed to it.
void test_an_unbound_ring_is_refused(void)
{
    Dma.clear(work_a);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_DMA_IO(work_a)->buf);
    Dma.tx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_DMA_IO(work_a)->buf);
    Dma.tx_reap(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
}

// Both cache hooks are called without a null test on the frame path, so a driver missing either one
// is refused at bind rather than faulting at the first frame.
void test_bind_refuses_a_driver_without_the_cache_hooks(void)
{
    IdemIpPhyDriver partial;

    Dma.clear(work_a);
    memcpy(&partial, &g_drv, sizeof partial);
    partial.cache_invalidate = NULL;
    set_bind_args(work_a);
    IDEMIP_DMA_IO(work_a)->bind_args.drv = &partial;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    memcpy(&partial, &g_drv, sizeof partial);
    partial.cache_clean = NULL;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
}

// The buffers are the driver's storage, so a ring with none named has nothing to point its
// descriptors at.
void test_bind_refuses_a_missing_driver_or_buffer_array(void)
{
    Dma.clear(work_a);
    set_bind_args(work_a);
    IDEMIP_DMA_IO(work_a)->bind_args.drv = NULL;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    set_bind_args(work_a);
    IDEMIP_DMA_IO(work_a)->bind_args.rx_base = NULL;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    set_bind_args(work_a);
    IDEMIP_DMA_IO(work_a)->bind_args.tx_base = NULL;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
}

// An index past a ring would reach outside the region the map published for it. The two rings have
// different counts, so each entry is bounded by its own.
void test_a_descriptor_index_past_its_ring_is_refused(void)
{
    Dma.clear(work_a);

    IDEMIP_DMA_IO(work_a)->desc_args.index = (uint8_t)IDEMIP_RX_DESCRIPTORS;
    Dma.rx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    Dma.pin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    Dma.unpin(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    IDEMIP_DMA_IO(work_a)->desc_args.index = (uint8_t)IDEMIP_TX_DESCRIPTORS;
    IDEMIP_DMA_IO(work_a)->desc_args.len = 64u;
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
}

// A length no Ethernet frame can carry (RFC 894) cannot be posted, and no retry makes it fit, so it
// is ERR and not BUSY.
void test_tx_post_refuses_a_length_no_frame_can_carry(void)
{
    Dma.clear(work_a);
    IDEMIP_DMA_IO(work_a)->desc_args.index = 0u;
    IDEMIP_DMA_IO(work_a)->desc_args.len = (uint16_t)(IDEMIP_ETH_FRAME_MAX + 1u);
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    IDEMIP_DMA_IO(work_a)->desc_args.len = 0u;
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
}

// A take that found nothing reports no buffer, whichever way it reports the state.
void test_a_take_that_found_nothing_reports_no_buffer(void)
{
    Dma.clear(work_a);
    Dma.rx_take(work_a);
    TEST_ASSERT_NULL(IDEMIP_DMA_IO(work_a)->buf);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DMA_IO(work_a)->len);
    Dma.tx_take(work_a);
    TEST_ASSERT_NULL(IDEMIP_DMA_IO(work_a)->buf);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DMA_IO(work_a)->len);
}

// --- the shape ---------------------------------------------------------------

// The namespace holds only const function pointers, so it costs no RAM and nothing can swap an entry
// at runtime.
void test_every_entry_is_present(void)
{
    TEST_ASSERT_NOT_NULL(Dma.clear);
    TEST_ASSERT_NOT_NULL(Dma.bind);
    TEST_ASSERT_NOT_NULL(Dma.rx_take);
    TEST_ASSERT_NOT_NULL(Dma.rx_post);
    TEST_ASSERT_NOT_NULL(Dma.pin);
    TEST_ASSERT_NOT_NULL(Dma.unpin);
    TEST_ASSERT_NOT_NULL(Dma.tx_take);
    TEST_ASSERT_NOT_NULL(Dma.tx_post);
    TEST_ASSERT_NOT_NULL(Dma.tx_reap);
    TEST_ASSERT_NOT_NULL(Dma.pinned);
}

// The flag mask names every bit the enum defines, so a caller can test a whole word.
void test_the_flag_mask_covers_the_enum(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x000Fu, IDEMIP_DMA_FLAG_MASK);
}
