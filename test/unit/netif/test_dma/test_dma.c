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

#include "src/netif/dma.h"

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
#define EV_RX_CLAIM 3
#define EV_RX_RELEASE 4
#define EV_TX_CLAIM 5
#define EV_TX_COMMIT 6
static int g_ev[16];
static int g_ev_n;

static void ev(int what)
{
    if (g_ev_n < (int)(sizeof g_ev / sizeof g_ev[0]))
    {
        g_ev[g_ev_n++] = what;
    }
}

// The engine, modelled on ProtoCore's host DMA rig: it advances only when a case says so, so a test
// decides which buffer a frame lands in and when it arrives.
#define ENGINE_Q 8u
static unsigned g_eng_idx[ENGINE_Q];
static uint16_t g_eng_len[ENGINE_Q];
static unsigned g_eng_head;
static unsigned g_eng_tail;
static const uint8_t *g_eng_addr; // when set, the address rx_claim reports instead of the buffer's
static int g_released;

static uint8_t *rx_buf_at(unsigned i)
{
    return rx_bufs + ((size_t)i * IDEMIP_DMA_BUF_STRIDE);
}
static uint8_t *tx_buf_at(unsigned i)
{
    return tx_bufs + ((size_t)i * IDEMIP_DMA_BUF_STRIDE);
}

// One frame into buffer i, stamped so a later case can prove the octets are still there.
static void engine_fill(unsigned i, uint16_t len, uint8_t stamp)
{
    if (len <= IDEMIP_DMA_BUF_STRIDE)
    {
        memset(rx_buf_at(i), stamp, len);
    }
    g_eng_idx[g_eng_head & (ENGINE_Q - 1u)] = i;
    g_eng_len[g_eng_head & (ENGINE_Q - 1u)] = len;
    g_eng_head++;
}

// The transmit side: a buffer is out from the claim until the engine reports the frame gone.
static int g_tx_out[IDEMIP_TX_DESCRIPTORS];
static unsigned g_tx_cursor;
static int g_tx_full;
static int g_tx_commit_fails;
static int g_committed;
static size_t g_commit_len;
static uint8_t *g_tx_addr; // when set, the address tx_claim reports instead of a buffer's

static void engine_tx_done(void)
{
    for (unsigned i = 0; i < IDEMIP_TX_DESCRIPTORS; i++)
    {
        g_tx_out[i] = 0;
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
    ev(EV_RX_CLAIM);
    if (g_eng_tail == g_eng_head)
    {
        return 0;
    }
    unsigned k = g_eng_tail & (ENGINE_Q - 1u);
    g_eng_tail++;
    *frame = (g_eng_addr != NULL) ? g_eng_addr : rx_buf_at(g_eng_idx[k]);
    return g_eng_len[k];
}
static void fake_rx_release(void)
{
    ev(EV_RX_RELEASE);
    g_released++;
}
static uint8_t *fake_tx_claim(size_t len)
{
    ev(EV_TX_CLAIM);
    if (g_tx_full || len > IDEMIP_DMA_BUF_STRIDE)
    {
        return NULL;
    }
    if (g_tx_addr != NULL)
    {
        return g_tx_addr;
    }
    for (unsigned n = 0; n < IDEMIP_TX_DESCRIPTORS; n++)
    {
        unsigned i = (g_tx_cursor + n) & (IDEMIP_TX_DESCRIPTORS - 1u);
        if (!g_tx_out[i])
        {
            g_tx_out[i] = 1;
            g_tx_cursor = i + 1u;
            return tx_buf_at(i);
        }
    }
    return NULL;
}
static idemip_bool fake_tx_commit(size_t len)
{
    ev(EV_TX_COMMIT);
    if (g_tx_commit_fails)
    {
        return IDEMIP_FALSE;
    }
    g_committed++;
    g_commit_len = len;
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
    g_eng_head = 0;
    g_eng_tail = 0;
    g_eng_addr = NULL;
    g_released = 0;
    engine_tx_done();
    g_tx_cursor = 0;
    g_tx_full = 0;
    g_tx_commit_fails = 0;
    g_committed = 0;
    g_commit_len = 0;
    g_tx_addr = NULL;
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

// --- the frame path ----------------------------------------------------------

static void bind_ok(uint8_t *w)
{
    Dma.clear(w);
    set_bind_args(w);
    Dma.bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(w)->status);
}

static void post_rx(uint8_t *w, uint8_t index)
{
    IDEMIP_DMA_IO(w)->desc_args.index = index;
    Dma.rx_post(w);
}

static void pin_rx(uint8_t *w, uint8_t index)
{
    IDEMIP_DMA_IO(w)->desc_args.index = index;
    Dma.pin(w);
}

static void unpin_rx(uint8_t *w, uint8_t index)
{
    IDEMIP_DMA_IO(w)->desc_args.index = index;
    Dma.unpin(w);
}

// The frame path calls four more driver members, so a driver missing any of them is refused at bind
// rather than faulting on the first frame.
void test_bind_refuses_a_driver_without_the_frame_path(void)
{
    IdemIpPhyDriver partial;

    Dma.clear(work_a);
    set_bind_args(work_a);

    memcpy(&partial, &g_drv, sizeof partial);
    partial.rx_claim = NULL;
    IDEMIP_DMA_IO(work_a)->bind_args.drv = &partial;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    memcpy(&partial, &g_drv, sizeof partial);
    partial.rx_release = NULL;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    memcpy(&partial, &g_drv, sizeof partial);
    partial.tx_claim = NULL;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    memcpy(&partial, &g_drv, sizeof partial);
    partial.tx_commit = NULL;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
}

// PLAN sec 3.5: a buffer starts on a cache line, because invalidating a partial line discards
// whatever shares it. No retry moves the array, so a misplaced one is ERR.
void test_bind_refuses_a_buffer_array_off_the_cache_line(void)
{
    Dma.clear(work_a);
    set_bind_args(work_a);
    IDEMIP_DMA_IO(work_a)->bind_args.rx_base = rx_bufs + 1;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    set_bind_args(work_a);
    IDEMIP_DMA_IO(work_a)->bind_args.tx_base = tx_bufs + 1;
    Dma.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
}

// The engine wrote the buffer, so the stale cached copy is discarded before the frame is readable.
// Ordering is the whole claim: the driver's claim, then invalidate, then the frame is reported.
void test_rx_take_invalidates_before_the_frame_is_readable(void)
{
    bind_ok(work_a);
    engine_fill(0u, 100u, 0x11u);
    g_ev_n = 0;
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(2, g_ev_n);
    TEST_ASSERT_EQUAL_INT(EV_RX_CLAIM, g_ev[0]);
    TEST_ASSERT_EQUAL_INT(EV_INVALIDATE, g_ev[1]);
}

// bind gave descriptor i the address base + i strides, so the address the engine filled names the
// descriptor the frame is reported on.
void test_rx_take_reports_the_descriptor_the_engine_filled(void)
{
    bind_ok(work_a);
    engine_fill(3u, 100u, 0x22u);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_DMA_IO(work_a)->index);
    TEST_ASSERT_EQUAL_PTR(rx_buf_at(3u), IDEMIP_DMA_IO(work_a)->buf);
    TEST_ASSERT_EQUAL_UINT16(100u, IDEMIP_DMA_IO(work_a)->len);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)(IDEMIP_DMA_FLAG_HELD | IDEMIP_DMA_FLAG_LAST),
                            IDEMIP_DMA_IO(work_a)->flags);
    TEST_ASSERT_EQUAL_HEX8(0x22u, IDEMIP_DMA_IO(work_a)->buf[0]);
}

// Nothing filled is BUSY, not OK and not ERR: a later tick finds a frame.
void test_an_empty_engine_is_busy(void)
{
    bind_ok(work_a);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_DMA_IO(work_a)->buf);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DMA_IO(work_a)->len);
}

// A take and a post are one round trip: the descriptor goes back to the engine and the same buffer
// carries the next frame.
void test_rx_take_and_post_round_trip(void)
{
    bind_ok(work_a);
    engine_fill(2u, 64u, 0x33u);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    g_ev_n = 0;
    post_rx(work_a, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(1, g_released);
    TEST_ASSERT_EQUAL_INT(1, g_ev_n);
    TEST_ASSERT_EQUAL_INT(EV_RX_RELEASE, g_ev[0]);

    engine_fill(2u, 32u, 0x44u);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_DMA_IO(work_a)->index);
}

// A second post would hand the engine the same descriptor twice.
void test_a_second_rx_post_is_refused(void)
{
    bind_ok(work_a);
    engine_fill(1u, 64u, 0x55u);
    Dma.rx_take(work_a);
    post_rx(work_a, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    post_rx(work_a, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(1, g_released);
}

// A post of a descriptor never taken would return one the engine already owns.
void test_rx_post_without_a_take_is_refused(void)
{
    bind_ok(work_a);
    post_rx(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(0, g_released);
}

// A frame at an address this ring never handed the engine belongs to no descriptor, so it is not
// reported and nothing is released.
void test_rx_take_refuses_a_frame_outside_the_bound_buffers(void)
{
    static _Alignas(IDEMIP_CACHE_LINE_BYTES) uint8_t foreign[64];
    bind_ok(work_a);
    g_eng_addr = foreign;
    engine_fill(0u, 64u, 0x66u);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_DMA_IO(work_a)->buf);
    TEST_ASSERT_EQUAL_INT(0, g_released);
}

// RFC 894 bounds an Ethernet frame, so a longer one is the engine's error: the descriptor goes back
// and the call is ERR, because no retry shortens that frame.
void test_rx_take_refuses_a_frame_longer_than_one_buffer(void)
{
    bind_ok(work_a);
    engine_fill(0u, (uint16_t)(IDEMIP_DMA_FRAME_MAX + 1u), 0x77u);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)IDEMIP_DMA_FLAG_ERR, IDEMIP_DMA_IO(work_a)->flags);
    TEST_ASSERT_EQUAL_INT(1, g_released);
}

// A refill of a buffer whose descriptor this side still holds would write over a frame in use.
void test_rx_take_refuses_a_refill_of_a_descriptor_this_side_holds(void)
{
    bind_ok(work_a);
    engine_fill(4u, 64u, 0x88u);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    engine_fill(4u, 64u, 0x99u);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(0, g_released);
}

// --- the pin protocol --------------------------------------------------------

// A pinned descriptor is not returned to the engine when the hold ends. The last unpin returns it.
void test_a_pin_holds_the_descriptor_past_the_post(void)
{
    bind_ok(work_a);
    engine_fill(6u, 64u, 0xAAu);
    Dma.rx_take(work_a);
    pin_rx(work_a, 6u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_DMA_IO(work_a)->pins);

    post_rx(work_a, 6u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_released, "a pinned descriptor went back to the engine");

    // Still out of the engine's hands: a refill of its buffer is refused.
    engine_fill(6u, 64u, 0xBBu);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);

    unpin_rx(work_a, 6u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_DMA_IO(work_a)->pins);
    TEST_ASSERT_EQUAL_INT(1, g_released);

    engine_fill(6u, 48u, 0xCCu);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(6u, IDEMIP_DMA_IO(work_a)->index);
}

// Two units retaining one frame are two pins, and the descriptor returns once, on the last one.
void test_the_last_unpin_returns_the_descriptor_once(void)
{
    bind_ok(work_a);
    engine_fill(0u, 64u, 0xDDu);
    Dma.rx_take(work_a);
    pin_rx(work_a, 0u);
    pin_rx(work_a, 0u);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_DMA_IO(work_a)->pins);
    post_rx(work_a, 0u);

    unpin_rx(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_DMA_IO(work_a)->pins);
    TEST_ASSERT_EQUAL_INT(0, g_released);

    unpin_rx(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_DMA_IO(work_a)->pins);
    TEST_ASSERT_EQUAL_INT(1, g_released);
}

// A descriptor the engine owns was never taken, so there is nothing to retain and no retry changes
// that.
void test_a_pin_on_a_descriptor_the_engine_owns_is_refused(void)
{
    bind_ok(work_a);
    pin_rx(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    Dma.pinned(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DMA_IO(work_a)->pinned);
}

// An unpin with no pin to drop would return a descriptor twice.
void test_an_unpin_without_a_pin_is_refused(void)
{
    bind_ok(work_a);
    engine_fill(0u, 64u, 0xEEu);
    Dma.rx_take(work_a);
    unpin_rx(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(0, g_released);
}

// IDEMIP_MAX_PINNED_FRAMES bounds the pins over the ring. The pin past it is BUSY, not ERR: every
// retaining unit drops its pins on its own timer, so the retry succeeds. ERR would abandon a healthy
// frame, and the ring is asserted wider than the bound so it never starves.
void test_pin_exhaustion_is_busy_and_an_unpin_frees_it(void)
{
    bind_ok(work_a);
    for (unsigned i = 0; i < IDEMIP_MAX_PINNED_FRAMES; i++)
    {
        engine_fill(i, 64u, (uint8_t)i);
        Dma.rx_take(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)i, IDEMIP_DMA_IO(work_a)->index);
        pin_rx(work_a, (uint8_t)i);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    }
    Dma.pinned(work_a);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_MAX_PINNED_FRAMES, IDEMIP_DMA_IO(work_a)->pinned);

    engine_fill(IDEMIP_MAX_PINNED_FRAMES, 64u, 0xF0u);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    pin_rx(work_a, (uint8_t)IDEMIP_MAX_PINNED_FRAMES);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DMA_IO(work_a)->status,
                                  "a pin past the budget must be BUSY, because an unpin makes it fit");

    unpin_rx(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    pin_rx(work_a, (uint8_t)IDEMIP_MAX_PINNED_FRAMES);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    Dma.pinned(work_a);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_MAX_PINNED_FRAMES, IDEMIP_DMA_IO(work_a)->pinned);
}

// The retained frame stays where the engine wrote it. The ring runs twice around while it is pinned,
// and neither the octets nor the descriptor move.
void test_a_pinned_frame_survives_the_ring_wrapping_past_it(void)
{
    const unsigned held = 5u;
    bind_ok(work_a);
    engine_fill(held, 100u, 0x5Au);
    Dma.rx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    uint8_t *pinned_buf = IDEMIP_DMA_IO(work_a)->buf;
    pin_rx(work_a, (uint8_t)held);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    post_rx(work_a, (uint8_t)held);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);

    int expect_released = 0;
    for (int round = 0; round < 2; round++)
    {
        for (unsigned i = 0; i < IDEMIP_RX_DESCRIPTORS; i++)
        {
            if (i == held)
            {
                continue;
            }
            engine_fill(i, 64u, 0xC3u);
            Dma.rx_take(work_a);
            TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
            TEST_ASSERT_EQUAL_UINT8((uint8_t)i, IDEMIP_DMA_IO(work_a)->index);
            TEST_ASSERT_TRUE_MESSAGE(IDEMIP_DMA_IO(work_a)->buf != pinned_buf,
                                     "a pinned buffer was handed out again");
            post_rx(work_a, (uint8_t)i);
            TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
            expect_released++;
        }
    }

    for (unsigned j = 0; j < 100u; j++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x5Au, pinned_buf[j], "a pinned frame's octets were written over");
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(expect_released, g_released, "a pinned descriptor went back to the engine");
    Dma.pinned(work_a);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_DMA_IO(work_a)->pinned);

    unpin_rx(work_a, (uint8_t)held);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(expect_released + 1, g_released);
}

// The pin count is the ring's, and the ring is the borrow, so pinning on one interface leaves the
// other's count where it was.
void test_pins_on_two_borrows_are_independent(void)
{
    bind_ok(work_a);
    bind_ok(work_b);
    engine_fill(0u, 64u, 0x0Fu);
    Dma.rx_take(work_a);
    pin_rx(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);

    Dma.pinned(work_a);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_DMA_IO(work_a)->pinned);
    Dma.pinned(work_b);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DMA_IO(work_b)->pinned);

    unpin_rx(work_b, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_b)->status);
    Dma.pinned(work_a);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_DMA_IO(work_a)->pinned);
}

// --- the transmit path -------------------------------------------------------

// The buffer the driver handed out names its descriptor, and the descriptor is this side's to build
// into until it is posted.
void test_tx_take_reports_the_claimed_buffer_and_its_descriptor(void)
{
    bind_ok(work_a);
    Dma.tx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(tx_buf_at(0u), IDEMIP_DMA_IO(work_a)->buf);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_DMA_IO(work_a)->index);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)IDEMIP_DMA_FLAG_HELD, IDEMIP_DMA_IO(work_a)->flags);

    Dma.tx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_DMA_IO(work_a)->index);
}

// The engine reads the buffer, so what the build left in cache is written back first. Ordering
// again: clean must precede commit.
void test_tx_post_cleans_before_it_commits(void)
{
    bind_ok(work_a);
    Dma.tx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    g_ev_n = 0;
    IDEMIP_DMA_IO(work_a)->desc_args.index = 0u;
    IDEMIP_DMA_IO(work_a)->desc_args.len = 60u;
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(2, g_ev_n);
    TEST_ASSERT_EQUAL_INT(EV_CLEAN, g_ev[0]);
    TEST_ASSERT_EQUAL_INT(EV_TX_COMMIT, g_ev[1]);
    TEST_ASSERT_EQUAL_size_t(60u, g_commit_len);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)(IDEMIP_DMA_FLAG_OWN | IDEMIP_DMA_FLAG_LAST), IDEMIP_DMA_IO(work_a)->flags);
}

// A post of a descriptor never taken would hand the engine whatever was in that buffer.
void test_tx_post_without_a_take_is_refused(void)
{
    bind_ok(work_a);
    IDEMIP_DMA_IO(work_a)->desc_args.index = 0u;
    IDEMIP_DMA_IO(work_a)->desc_args.len = 60u;
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(0, g_committed);
}

// A second post would transmit the same buffer twice.
void test_a_second_tx_post_is_refused(void)
{
    bind_ok(work_a);
    Dma.tx_take(work_a);
    IDEMIP_DMA_IO(work_a)->desc_args.index = 0u;
    IDEMIP_DMA_IO(work_a)->desc_args.len = 60u;
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(1, g_committed);
}

// A driver that could not queue the frame leaves the descriptor held, so the same one is posted
// again on a later tick. That is BUSY, and the retry succeeds.
void test_a_commit_that_could_not_queue_is_busy_and_the_retry_succeeds(void)
{
    bind_ok(work_a);
    Dma.tx_take(work_a);
    g_tx_commit_fails = 1;
    IDEMIP_DMA_IO(work_a)->desc_args.index = 0u;
    IDEMIP_DMA_IO(work_a)->desc_args.len = 60u;
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(0, g_committed);

    g_tx_commit_fails = 0;
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(1, g_committed);
}

// Every descriptor out is BUSY, because a reaped descriptor frees one. ERR would abandon a healthy
// ring.
void test_a_full_transmit_ring_is_busy(void)
{
    bind_ok(work_a);
    for (unsigned i = 0; i < IDEMIP_TX_DESCRIPTORS; i++)
    {
        Dma.tx_take(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    }
    Dma.tx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_DMA_IO(work_a)->buf);
}

// A committed descriptor is the engine's until reap takes it back. Nothing to take back is BUSY.
void test_tx_reap_frees_a_committed_descriptor(void)
{
    bind_ok(work_a);
    Dma.tx_reap(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DMA_IO(work_a)->status);

    Dma.tx_take(work_a);
    IDEMIP_DMA_IO(work_a)->desc_args.index = 0u;
    IDEMIP_DMA_IO(work_a)->desc_args.len = 60u;
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);

    Dma.tx_reap(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_DMA_IO(work_a)->index);
    Dma.tx_reap(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DMA_IO(work_a)->status);

    engine_tx_done();
    Dma.tx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(tx_buf_at(IDEMIP_DMA_IO(work_a)->index), IDEMIP_DMA_IO(work_a)->buf);
}

// A buffer at an address this ring never handed out belongs to no descriptor.
void test_tx_take_refuses_a_buffer_outside_the_bound_array(void)
{
    static _Alignas(IDEMIP_CACHE_LINE_BYTES) uint8_t foreign[64];
    bind_ok(work_a);
    g_tx_addr = foreign;
    Dma.tx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_DMA_IO(work_a)->buf);
}

// A driver handing the same storage to two builds is refused rather than transmitted twice.
void test_tx_take_refuses_a_buffer_already_handed_out(void)
{
    bind_ok(work_a);
    Dma.tx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    g_tx_addr = tx_buf_at(0u);
    Dma.tx_take(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DMA_IO(work_a)->status);
}

// An entry is a function of its borrow alone, so the same call on the same bytes reports the same
// thing however the other borrow is driven between them. This is the determinism the design is named
// for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    bind_ok(work_a);
    bind_ok(work_b);

    Dma.tx_take(work_a);
    uint8_t first = IDEMIP_DMA_IO(work_a)->index;
    uint8_t *first_buf = IDEMIP_DMA_IO(work_a)->buf;
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);

    Dma.pinned(work_b);
    Dma.tx_reap(work_b);

    Dma.pinned(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DMA_IO(work_a)->pinned);

    IDEMIP_DMA_IO(work_a)->desc_args.index = first;
    IDEMIP_DMA_IO(work_a)->desc_args.len = 60u;
    Dma.tx_post(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(first_buf, IDEMIP_DMA_IO(work_a)->buf);
}
