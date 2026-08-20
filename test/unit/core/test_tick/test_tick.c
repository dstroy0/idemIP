// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for the scheduler, shaped on test/unit/ethernet/test_phy. Every case tests the CONTRACT
// and stays valid however the logic behind it is written:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two schedulers share not one byte
//   4. a canary past IDEMIP_TICK_BORROW is intact after every case
//   5. the published offsets are ordered and do not overlap
//   6. the ORDER of the three phases is enforced, not described: an entry called out of its phase is
//      refused, and the units a phase runs are reported in their dependency order
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/core/tick.h"

#include "src/arp/arp.h"
#include "src/ip/ipv4.h"
#if IDEMIP_ENABLE_IPV6
#include "src/ip/ipv6.h"
#endif

#include <string.h>
#include <unity.h>

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_TICK_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_TICK_BORROW + 16];

// The borrows the scheduler drives, and the ones the receive path under it drives.
static _Alignas(8) uint8_t dispatch_mem[IDEMIP_DISPATCH_BORROW];
static _Alignas(8) uint8_t timeouts_mem[IDEMIP_TIMEOUTS_BORROW];
static _Alignas(8) uint8_t stats_mem[IDEMIP_STATS_BORROW];
static _Alignas(8) uint8_t netif_mem[IDEMIP_NETIF_BORROW];
static _Alignas(8) uint8_t loopif_mem[IDEMIP_LOOPIF_BORROW];
static _Alignas(8) uint8_t vlan_mem[IDEMIP_VLAN_BORROW];
static _Alignas(8) uint8_t arp_mem[IDEMIP_ARP_BORROW];
static _Alignas(8) uint8_t ip4_addr_mem[IDEMIP_IP4_ADDR_BORROW];
static _Alignas(8) uint8_t ip4_reass_mem[IDEMIP_IP4_REASS_BORROW];
static _Alignas(8) uint8_t igmp_mem[IDEMIP_IGMP_BORROW];
#if IDEMIP_ENABLE_IPV6
static _Alignas(8) uint8_t ip6_reass_mem[IDEMIP_IP6_REASS_BORROW];
static _Alignas(8) uint8_t mld6_mem[IDEMIP_MLD6_BORROW];
static _Alignas(8) uint8_t nd6_mem[IDEMIP_ND6_BORROW];
#endif
static _Alignas(8) uint8_t dma_mem[IDEMIP_DMA_BORROW];
static _Alignas(8) uint8_t dma1_mem[IDEMIP_DMA_BORROW]; // the second interface's ring
static _Alignas(8) uint8_t phy_mem[IDEMIP_PHY_BORROW];
static uint8_t out_buf[256];

// The frame buffers are the DRIVER's storage, the way a board's driver owns them.
static _Alignas(IDEMIP_CACHE_LINE_BYTES) uint8_t rx_bufs[IDEMIP_RX_DESCRIPTORS * IDEMIP_DMA_BUF_STRIDE];
static _Alignas(IDEMIP_CACHE_LINE_BYTES) uint8_t tx_bufs[IDEMIP_TX_DESCRIPTORS * IDEMIP_DMA_BUF_STRIDE];

#define LOCAL_IP4 0xC0000201u
#define REMOTE_IP4 0xC0000209u
#define NETMASK4 0xFFFFFF00u

static const uint8_t g_local_mac[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t g_remote_mac[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x09};

// --- the engine, which advances only when a case says so ---------------------

#define ENGINE_Q 8u
static unsigned g_eng_idx[ENGINE_Q];
static uint16_t g_eng_len[ENGINE_Q];
static unsigned g_eng_head;
static unsigned g_eng_tail;
static int g_released;
static int g_committed;

static uint8_t *rx_buf_at(unsigned i)
{
    return rx_bufs + ((size_t)i * IDEMIP_DMA_BUF_STRIDE);
}

static void engine_queue(unsigned i, uint16_t len)
{
    g_eng_idx[g_eng_head & (ENGINE_Q - 1u)] = i;
    g_eng_len[g_eng_head & (ENGINE_Q - 1u)] = len;
    g_eng_head++;
}

static IdemIpPhyLink fake_link(void)
{
    IdemIpPhyLink l = {IDEMIP_PHY_SPEED_100, 1u, 1u};
    return l;
}
static const uint8_t *fake_mac(void)
{
    return g_local_mac;
}
static size_t fake_rx_claim(const uint8_t **frame)
{
    if (g_eng_tail == g_eng_head)
    {
        return 0;
    }
    unsigned k = g_eng_tail & (ENGINE_Q - 1u);
    g_eng_tail++;
    *frame = rx_buf_at(g_eng_idx[k]);
    return g_eng_len[k];
}
static void fake_rx_release(void)
{
    g_released++;
}
static uint8_t *fake_tx_claim(size_t len)
{
    return (len > IDEMIP_DMA_BUF_STRIDE) ? NULL : tx_bufs;
}
static idemip_bool fake_tx_commit(size_t len)
{
    (void)len;
    g_committed++;
    return IDEMIP_TRUE;
}
static void fake_invalidate(const void *p, size_t len)
{
    (void)p;
    (void)len;
}
static void fake_clean(const void *p, size_t len)
{
    (void)p;
    (void)len;
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
    memset(w + IDEMIP_TICK_BORROW, CANARY, cap - IDEMIP_TICK_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_TICK_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_TICK_BORROW");
    }
}

static void wire_units(void)
{
    Stats.clear(stats_mem);
    Vlan.clear(vlan_mem);
    ArpTable.clear(arp_mem);
    Ip4Addr.clear(ip4_addr_mem);
    Ip4Reass.clear(ip4_reass_mem);
    Igmp.clear(igmp_mem);
#if IDEMIP_ENABLE_IPV6
    Ip6Reass.clear(ip6_reass_mem);
    Mld6.clear(mld6_mem);
    Nd6.clear(nd6_mem);
#endif
    Timeouts.clear(timeouts_mem);

    Loopif.clear(loopif_mem);
    Dma.clear(dma_mem);
    IDEMIP_DMA_IO(dma_mem)->bind_args.drv = &g_drv;
    IDEMIP_DMA_IO(dma_mem)->bind_args.rx_base = rx_bufs;
    IDEMIP_DMA_IO(dma_mem)->bind_args.tx_base = tx_bufs;
    Dma.bind(dma_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(dma_mem)->status);

    Netif.clear(netif_mem);
    NetifIo *ni = IDEMIP_NETIF_IO(netif_mem);
    ni->bind_args.index = 0u;
    ni->bind_args.phy = phy_mem;
    ni->bind_args.hwaddr = g_local_mac;
    ni->bind_args.mtu = 1500u;
    Netif.bind(netif_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ni->status);
    ni->addr4_args.index = 0u;
    ni->addr4_args.addr = LOCAL_IP4;
    ni->addr4_args.mask = NETMASK4;
    ni->addr4_args.gw = REMOTE_IP4;
    Netif.set_addr4(netif_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ni->status);

    Dispatch.clear(dispatch_mem);
    DispatchIo *di = IDEMIP_DISPATCH_IO(dispatch_mem);
    di->bind_args.stats = stats_mem;
    di->bind_args.netif = netif_mem;
    di->bind_args.loopif = loopif_mem;
    di->bind_args.vlan = vlan_mem;
    di->bind_args.arp = arp_mem;
    di->bind_args.ip4_addr = ip4_addr_mem;
    di->bind_args.ip4_reass = ip4_reass_mem;
    di->bind_args.igmp = igmp_mem;
#if IDEMIP_ENABLE_IPV6
    di->bind_args.ip6_reass = ip6_reass_mem;
#endif
    Dispatch.bind(dispatch_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, di->status);
    di->if_args.index = 0u;
    di->if_args.dma = dma_mem;
    di->if_args.vid = 0u;
    di->if_args.tagged = IDEMIP_FALSE;
    Dispatch.if_bind(dispatch_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, di->status);
}

static void bind_tick(uint8_t *w)
{
    TickIo *io = IDEMIP_TICK_IO(w);
    io->bind_args.dispatch = dispatch_mem;
    io->bind_args.timeouts = timeouts_mem;
    io->bind_args.stats = stats_mem;
    io->bind_args.arp = arp_mem;
    io->bind_args.ip4_reass = ip4_reass_mem;
    io->bind_args.igmp = igmp_mem;
#if IDEMIP_ENABLE_IPV6
    io->bind_args.ip6_reass = ip6_reass_mem;
    io->bind_args.mld6 = mld6_mem;
#endif
    io->bind_args.netif = netif_mem;
    Tick.bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);

    io->if_args.index = 0u;
    io->if_args.dma = dma_mem;
#if IDEMIP_ENABLE_IPV6
    io->if_args.nd6 = nd6_mem;
#endif
    io->if_args.out = out_buf;
    io->if_args.out_cap = sizeof out_buf;
    Tick.if_bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
}

// Runs one phase to exhaustion, capped. False when it kept reporting steps past any real count,
// which is a phase whose cursor never advances.
#define TICK_PHASE_STEP_MAX 64
static idemip_bool run_phase(uint8_t *w, void (*const phase)(uint8_t *restrict work))
{
    for (int i = 0; i < TICK_PHASE_STEP_MAX; i++)
    {
        phase(w);
        if (IDEMIP_TICK_IO(w)->status != IDEMIP_OK)
        {
            return IDEMIP_TRUE;
        }
    }
    return IDEMIP_FALSE;
}

// The random word a tick opens with. Deliberately not derivable from the now_ms beside it, so a
// path that reached for the clock instead reads a different value here.
static uint32_t g_open_rand = 0xA5A5A5A5u;

static void open_tick(uint8_t *w, uint32_t now_ms)
{
    IDEMIP_TICK_IO(w)->open_args.now_ms = now_ms;
    IDEMIP_TICK_IO(w)->open_args.rand = g_open_rand;
    Tick.open(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(w)->status);
}

// One IPv4 datagram into receive buffer @p slot, and its length. RFC 1700 leaves protocol 253 to
// "use for experimentation and testing", so nothing here claims it and the receive path is visible
// through RFC 1213 ipInUnknownProtos without any transport binding.
#define TICK_TEST_PROTO 253u
#define TICK_TEST_DATA 8u
// RFC 1122 sec 3.3.2: "The reassembly timeout value SHOULD be a fixed value, not set from the
// remaining TTL. It is recommended that the value lie between 60 seconds and 120 seconds." The
// fragment's Time to Live is deliberately large here, so a timeout taken from it would not be
// IDEMIP_IP_REASS_MAXAGE_S.
#define TICK_TEST_TTL 200u

// The fixed bound the sweep runs on, in milliseconds.
#define TICK_REASS_MS ((uint32_t)IDEMIP_IP_REASS_MAXAGE_S * 1000u)

static uint16_t fill_ip4(unsigned slot, uint32_t dst, uint16_t flags_frag)
{
    uint8_t *f = rx_buf_at(slot);
    memset(f, 0, IDEMIP_DMA_BUF_STRIDE);
    idemip_eth_build(f, g_local_mac, g_remote_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    IdemIpIp4Fields fields;
    memset(&fields, 0, sizeof fields);
    fields.total_len = (uint16_t)(IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN) + TICK_TEST_DATA);
    fields.id = 0x4242u;
    fields.flags_frag = flags_frag;
    fields.ttl = TICK_TEST_TTL;
    fields.proto = TICK_TEST_PROTO;
    fields.src = REMOTE_IP4;
    fields.dst = dst;
    idemip_ip4_build(f + IDEMIP_ETH_OFF_PAYLOAD, &fields);
    memset(f + IDEMIP_ETH_OFF_PAYLOAD + IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN), 0x5A, TICK_TEST_DATA);
    return (uint16_t)(IDEMIP_ETH_OFF_PAYLOAD + IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN) + TICK_TEST_DATA);
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(rx_bufs, 0, sizeof rx_bufs);
    memset(tx_bufs, 0, sizeof tx_bufs);
    memset(out_buf, 0, sizeof out_buf);
    memset(phy_mem, 0, sizeof phy_mem);
    g_eng_head = 0u;
    g_eng_tail = 0u;
    g_released = 0;
    g_committed = 0;
    wire_units();
    Tick.clear(work_a);
    Tick.clear(work_b);
    bind_tick(work_a);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- the borrow --------------------------------------------------------------

void test_every_entry_survives_a_null_borrow(void)
{
    Tick.clear(NULL);
    Tick.bind(NULL);
    Tick.if_bind(NULL);
    Tick.open(NULL);
    Tick.drain(NULL);
    Tick.service(NULL);
    Tick.flush(NULL);
    TEST_PASS();
}

void test_every_entry_refuses_an_uncleared_borrow(void)
{
    static _Alignas(8) uint8_t raw[IDEMIP_TICK_BORROW];
    memset(raw, 0, sizeof raw);
    Tick.bind(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(raw)->status);
    Tick.if_bind(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(raw)->status);
    Tick.open(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(raw)->status);
    Tick.drain(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(raw)->status);
    Tick.service(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(raw)->status);
    Tick.flush(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(raw)->status);
}

// The borrow IS the instance, so one scheduler's phase is not the other's.
void test_two_borrows_share_no_byte(void)
{
    bind_tick(work_b);
    open_tick(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TICK_PHASE_DRAIN, IDEMIP_TICK_IO(work_a)->phase);

    // b was never opened, so its phase is still IDLE and its drain is out of phase.
    Tick.drain(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(work_b)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TICK_PHASE_IDLE, IDEMIP_TICK_IO(work_b)->phase);

    // And a is still where a was.
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TICK_IO(work_a)->status);
}

void test_the_published_offsets_are_ordered_and_fit(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_TICK_OFF_IO);
    TEST_ASSERT_TRUE(IDEMIP_TICK_OFF_CTX >= sizeof(TickIo));
    TEST_ASSERT_TRUE(IDEMIP_TICK_OFF_IF >= IDEMIP_TICK_OFF_CTX);
    TEST_ASSERT_TRUE(IDEMIP_TICK_OFF_END > IDEMIP_TICK_OFF_IF);
    TEST_ASSERT_TRUE(IDEMIP_TICK_OFF_END <= IDEMIP_TICK_BORROW);
}

void test_if_bind_refuses_an_index_past_the_table(void)
{
    IDEMIP_TICK_IO(work_a)->if_args.index = (uint8_t)IDEMIP_NETIF_COUNT;
    Tick.if_bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(work_a)->status);
}

// --- the order, which is enforced and not described --------------------------

// PLAN.md sec 3.4b fixes the order because a later phase consumes what an earlier one produced, so a
// phase entry called before its turn is refused rather than quietly running early.
void test_a_phase_entry_before_its_turn_is_refused(void)
{
    open_tick(work_a, 1000u);
    // The tick is at DRAIN, so neither of the later phases may run.
    Tick.service(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(work_a)->status);
    Tick.flush(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(work_a)->status);
}

// A phase entry called after its phase is through is refused the same way.
void test_a_phase_entry_after_its_turn_is_refused(void)
{
    open_tick(work_a, 1000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_TICK_PHASE_SERVICE, IDEMIP_TICK_IO(work_a)->phase);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(work_a)->status);
}

// Nothing may run before a tick is opened: the clock every deadline is measured from arrives there.
void test_no_phase_runs_before_the_tick_is_opened(void)
{
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(work_a)->status);
    Tick.service(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(work_a)->status);
    Tick.flush(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TICK_IO(work_a)->status);
}

// The three phases run through to DONE, and each reports BUSY when its own work is finished. BUSY
// here is progress, not a fault: it is what moves the order on.
void test_the_three_phases_run_in_order_to_done(void)
{
    open_tick(work_a, 1000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TICK_PHASE_SERVICE, IDEMIP_TICK_IO(work_a)->phase);
    while (Tick.service(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_TICK_PHASE_FLUSH, IDEMIP_TICK_IO(work_a)->phase);
    while (Tick.flush(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_TICK_PHASE_DONE, IDEMIP_TICK_IO(work_a)->phase);
}

// A second open starts another tick from the beginning.
void test_opening_again_starts_the_order_over(void)
{
    open_tick(work_a, 1000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    while (Tick.service(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    while (Tick.flush(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    open_tick(work_a, 2000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TICK_PHASE_DRAIN, IDEMIP_TICK_IO(work_a)->phase);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TICK_IO(work_a)->status);
}

// The units a service phase reports come in one fixed order: the resolvers before the queues that
// wait on them, reassembly before the protocols that read a completed datagram.
void test_the_service_phase_reports_its_units_in_dependency_order(void)
{
    // A group joined and a Query heard leaves IGMP with a report due, so a later unit than ARP has
    // work and the order is visible across more than one unit.
    IgmpIo *ig = IDEMIP_IGMP_IO(igmp_mem);
    ig->group_args.group = 0xE0000105u;
    ig->group_args.netif = 0u;
    ig->group_args.rand = 7u;
    ig->group_args.now_ms = 1000u;
    Igmp.join(igmp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ig->status);

    open_tick(work_a, 100000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    int last = 0;
    int steps = 0;
    while (Tick.service(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
        int unit = (int)IDEMIP_TICK_IO(work_a)->unit;
        TEST_ASSERT_TRUE_MESSAGE(unit >= last, "a service step ran out of the fixed dependency order");
        last = unit;
        steps++;
        if (steps > 64)
        {
            TEST_FAIL_MESSAGE("the service phase did not finish");
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(steps > 0, "no service reported work when IGMP had a report due");
}

// --- the clock and the deadline list ----------------------------------------

// An empty list has no next deadline, which is what IDEMIP_TIMEOUT_FOREVER says.
void test_an_empty_deadline_list_reports_forever(void)
{
    open_tick(work_a, 1000u);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_TIMEOUT_FOREVER, IDEMIP_TICK_IO(work_a)->until_ms);
}

// A deadline ahead of the clock is reported as the milliseconds until it.
void test_a_deadline_ahead_is_reported_as_the_wait(void)
{
    TimeoutsIo *to = IDEMIP_TIMEOUTS_IO(timeouts_mem);
    to->arm_args.unit = IDEMIP_TIMEOUT_UNIT_DNS;
    to->arm_args.arg = 2u;
    to->arm_args.deadline_ms = 1500u;
    to->arm_args.flags = IDEMIP_TIMEOUT_FLAG_ARMED;
    Timeouts.arm(timeouts_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, to->status);

    open_tick(work_a, 1000u);
    TEST_ASSERT_EQUAL_UINT32(500u, IDEMIP_TICK_IO(work_a)->until_ms);
}

// A deadline the clock has reached is handed back in the service phase, naming the unit and the
// index into that unit's own table. The units this scheduler drives ran above it; the rest are the
// caller's to run.
void test_an_expired_deadline_is_reported_with_its_unit(void)
{
    TimeoutsIo *to = IDEMIP_TIMEOUTS_IO(timeouts_mem);
    to->arm_args.unit = IDEMIP_TIMEOUT_UNIT_DHCP4;
    to->arm_args.arg = 1u;
    to->arm_args.deadline_ms = 900u;
    to->arm_args.flags = IDEMIP_TIMEOUT_FLAG_ARMED;
    Timeouts.arm(timeouts_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, to->status);

    open_tick(work_a, 1000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    int found = 0;
    while (Tick.service(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
        if (IDEMIP_TICK_IO(work_a)->unit == IDEMIP_TICK_UNIT_TIMEOUTS)
        {
            TEST_ASSERT_EQUAL_INT(IDEMIP_TIMEOUT_UNIT_DHCP4, IDEMIP_TICK_IO(work_a)->timeout_unit);
            TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_TICK_IO(work_a)->timeout_arg);
            found = 1;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(found, "an expired deadline was not handed back");
}

// The millisecond count wraps at 2^32, so a deadline whose count is numerically below the clock's is
// still ahead of it. A plain less-than would fire it at once and every timer would die at the
// rollover.
void test_a_deadline_across_the_wrap_is_still_ahead(void)
{
    TimeoutsIo *to = IDEMIP_TIMEOUTS_IO(timeouts_mem);
    to->arm_args.unit = IDEMIP_TIMEOUT_UNIT_DNS;
    to->arm_args.arg = 0u;
    // The clock is 1001 ms below 2^32 and the deadline is 999 ms above the wrap, so the deadline is
    // 2000 ms ahead of the clock while its count reads far below it.
    to->arm_args.deadline_ms = 999u;
    to->arm_args.flags = IDEMIP_TIMEOUT_FLAG_ARMED;
    Timeouts.arm(timeouts_mem);

    open_tick(work_a, 0xFFFFFC17u);
    TEST_ASSERT_EQUAL_UINT32(2000u, IDEMIP_TICK_IO(work_a)->until_ms);
}

// --- the drain, and what happens to the descriptor ---------------------------

// An empty ring is BUSY, which moves the phase on rather than looking like a fault.
void test_an_empty_ring_drains_busy(void)
{
    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_TICK_IO(work_a)->frames);
}

// One frame in the ring is taken, dispatched, and its descriptor given back, nothing having retained
// it.
void test_a_frame_is_dispatched_and_its_descriptor_returned(void)
{
    uint16_t len = fill_ip4(0u, LOCAL_IP4, 0u);
    engine_queue(0u, len);

    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_TICK_IO(work_a)->frames);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_TICK_IO(work_a)->netif);

    // The receive path saw it: nothing claims the protocol, so ipInUnknownProtos counts it.
    IDEMIP_STATS_IO(stats_mem)->ctr_args.id = IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS;
    Stats.read(stats_mem);
    TEST_ASSERT_EQUAL_UINT32(1u, IDEMIP_STATS_IO(stats_mem)->value);

    // And the descriptor went back to the engine, nothing having pinned it.
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DMA_IO(dma_mem)->pinned);
    TEST_ASSERT_EQUAL_INT(1, g_released);

    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TICK_IO(work_a)->status);
}

// A tick opens with two words and hands both to every frame it drains. The clock is the one every
// deadline is measured from; the random word is the one a drawn deadline comes out of, and
// dispatch.h names the draw that needs it - RFC 2236 sec 3's Report timer, "a different random
// value ... selected from the range (0, Max Response Time]". They are not interchangeable, so a
// tick that carried only the clock would leave the receive path drawing from a monotonic counter.
void test_a_tick_hands_the_random_word_it_opened_with_to_every_frame_it_drains(void)
{
    uint16_t len = fill_ip4(0u, LOCAL_IP4, 0u);
    engine_queue(0u, len);

    g_open_rand = 0x3C69A17Bu;
    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x3C69A17Bu, IDEMIP_DISPATCH_IO(dispatch_mem)->input_args.rand,
                                    "the word the tick opened with did not reach the frame");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1000u, IDEMIP_DISPATCH_IO(dispatch_mem)->input_args.now_ms,
                                     "the clock beside it is still the clock");
    g_open_rand = 0xA5A5A5A5u;
}

// A fragment is held by the reassembler, which pins the buffer the engine wrote it to. The
// descriptor must NOT go back to the ring, or the engine writes a later frame over a held one.
void test_a_retained_frame_keeps_its_descriptor_out_of_the_ring(void)
{
    uint16_t len = fill_ip4(0u, LOCAL_IP4, (uint16_t)IDEMIP_IP4_FLAG_MF);
    engine_queue(0u, len);

    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(dispatch_mem)->act & IDEMIP_DISPATCH_ACT_PINNED) != 0u,
                             "a held fragment was not reported as pinned");
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_DMA_IO(dma_mem)->pinned);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_released, "a pinned descriptor was handed back to the engine");
}

// RFC 791 sec 3.2 step (19): "if the timer runs out, the all reassembly resources for this BUFID are
// released". Each of those fragments pinned a receive descriptor, so releasing them is the only
// thing that hands the buffers back. This suite bound the ip4_reass borrow to the tick and drove it
// only through whole datagrams, so the sweep and the reclaim that follows it had never run.
void test_an_expired_datagram_returns_every_descriptor_it_pinned(void)
{
    uint16_t len = fill_ip4(0u, LOCAL_IP4, IDEMIP_IP4_FLAG_MF);
    engine_queue(0u, len);
    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(dispatch_mem)->drop,
                                  "the fragment did not reach the reassembler");
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(dispatch_mem)->act & IDEMIP_DISPATCH_ACT_PINNED) != 0u,
                             "a held fragment was not reported as pinned");
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_DMA_IO(dma_mem)->pinned);

    // sec 3.3.2's fixed timeout run out, with the fragment that would fill the hole never arriving.
    // The fragment's TTL is 200, so a timeout taken from it would still be far off here. Each phase
    // loop is capped: a phase that reports a step it did not take would otherwise never end.
    open_tick(work_a, 1000u + TICK_REASS_MS);
    TEST_ASSERT_TRUE(run_phase(work_a, Tick.drain));
    TEST_ASSERT_TRUE_MESSAGE(run_phase(work_a, Tick.service),
                             "the service phase never stopped reporting steps for the expired datagram");
    TEST_ASSERT_TRUE(run_phase(work_a, Tick.flush));
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_DMA_IO(dma_mem)->pinned,
                                     "a timed-out datagram kept the descriptors its fragments pinned");
    // A pin count of zero is not a descriptor back in the ring, and this case is about the second.
    // rx_release is the driver call that returns one, so it is the only thing that says so.
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_released, "the descriptor was unpinned and never handed back");

    // The reassembler's own state: the row is gone, not merely unpinned. A row the sweep can still
    // find is one the service phase reports a step for on every later tick.
    IDEMIP_IP4_REASS_IO(ip4_reass_mem)->now_ms = 1000u + TICK_REASS_MS;
    Ip4Reass.tick(ip4_reass_mem);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_IP4_REASS_IO(ip4_reass_mem)->status,
                                  "the timed-out row was never freed");
}

// What a descriptor that never comes back costs, said in the only terms that matter: the interface
// goes deaf. The ring holds IDEMIP_RX_DESCRIPTORS of them and a retained frame takes one, so a
// release that does not return it takes it for good. rx_take refuses a descriptor the engine does
// not own and the drain steps that interface over without a word, so the frame is claimed off the
// engine, dropped, and counted nowhere.
void test_the_ring_still_receives_after_a_retained_frame_is_released(void)
{
    uint16_t len = fill_ip4(0u, LOCAL_IP4, IDEMIP_IP4_FLAG_MF);
    engine_queue(0u, len);
    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(dispatch_mem)->act & IDEMIP_DISPATCH_ACT_PINNED) != 0u,
                             "the fragment was not retained, so this case proves nothing");

    // The reassembly timeout frees the row, which drops the pin the fragment held.
    open_tick(work_a, 1000u + TICK_REASS_MS);
    TEST_ASSERT_TRUE(run_phase(work_a, Tick.drain));
    TEST_ASSERT_TRUE(run_phase(work_a, Tick.service));
    TEST_ASSERT_TRUE(run_phase(work_a, Tick.flush));

    // The same buffer, filled again. The engine writes it only if the descriptor is its own again.
    len = fill_ip4(0u, LOCAL_IP4, 0u);
    engine_queue(0u, len);
    open_tick(work_a, 2000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status,
                                  "the ring never got back the descriptor the released fragment took");
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_TICK_IO(work_a)->frames);
}

// The same datagram, completed instead of timed out: the descriptors stay pinned, because the caller
// has not yet read the reassembled datagram out of them.
void test_a_completed_datagram_still_holds_its_descriptors(void)
{
    uint16_t len = fill_ip4(0u, LOCAL_IP4, IDEMIP_IP4_FLAG_MF);
    engine_queue(0u, len);
    // TICK_TEST_DATA octets in, which is where the first fragment's data ended, and MF clear.
    len = fill_ip4(1u, LOCAL_IP4, (uint16_t)(TICK_TEST_DATA / 8u));
    engine_queue(1u, len);

    open_tick(work_a, 1000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(dispatch_mem)->act & IDEMIP_DISPATCH_ACT_REASSEMBLED) != 0u,
                             "the last fragment did not complete the datagram");
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16(2u, IDEMIP_DMA_IO(dma_mem)->pinned);
}

#if IDEMIP_ENABLE_IPV6

// RFC 8200 sec 4.5: "If insufficient fragments are received to complete reassembly of a packet
// within 60 seconds of the reception of the first-arriving fragment of that packet, reassembly of
// that packet must be abandoned and all the fragments that have been received for that packet must
// be discarded." Every one of those fragments pinned a receive descriptor, so that discard is the
// only thing that returns them to the ring. This suite bound the ip6_reass borrow to the tick and
// never sent an IPv6 packet, so the loop that walks the fragments and unpins each had never run.

// RFC 3849: 2001:DB8::/32 is "for use in documentation".
static const uint8_t g_tick_ip6[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_tick_ip6_far[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0,    0,
                                                            0,    0,    0,    0,    0, 0, 0x09, 0x09};

static void give_the_interface_an_ipv6_address(void)
{
    NetifIo *ni = IDEMIP_NETIF_IO(netif_mem);
    ni->addr6_args.index = 0u;
    ni->addr6_args.slot = 0u;
    ni->addr6_args.addr = g_tick_ip6;
    ni->addr6_args.state = IDEMIP_NETIF_ADDR6_PREFERRED;
    ni->addr6_args.preferred_s = 3600u;
    ni->addr6_args.valid_s = 7200u;
    Netif.add_addr6(netif_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ni->status);
}

// One IPv6 fragment into receive buffer @p slot. TICK_TEST_DATA is eight octets, so a fragment
// carrying M is the multiple of 8 sec 4.5 requires of one.
static uint16_t fill_ip6_fragment(unsigned slot, uint16_t frag_off, idemip_bool more)
{
    uint8_t *f = rx_buf_at(slot);
    memset(f, 0, IDEMIP_DMA_BUF_STRIDE);
    idemip_eth_build(f, g_local_mac, g_remote_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);

    uint8_t *ip = f + IDEMIP_ETH_OFF_PAYLOAD;
    IdemIpIp6BuildArgs a;
    memset(&a, 0, sizeof a);
    a.src = g_tick_ip6_far;
    a.dst = g_tick_ip6;
    a.payload_len = (uint16_t)(IDEMIP_IP6_FRAG_HDR_LEN + TICK_TEST_DATA);
    a.next_hdr = IDEMIP_IP6_NH_FRAGMENT;
    a.hop_limit = 64u;
    idemip_ip6_build(ip, &a);

    uint8_t *fh = ip + IDEMIP_IPV6_HDR_LEN;
    idemip_ip6_frag_build(fh, TICK_TEST_PROTO, frag_off, more, 0x4242u);
    memset(fh + IDEMIP_IP6_FRAG_HDR_LEN, 0x5A, TICK_TEST_DATA);
    return (uint16_t)(IDEMIP_ETH_OFF_PAYLOAD + IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_FRAG_HDR_LEN + TICK_TEST_DATA);
}

void test_an_expired_ipv6_datagram_returns_every_descriptor_it_pinned(void)
{
    give_the_interface_an_ipv6_address();

    uint16_t len = fill_ip6_fragment(0u, 0u, IDEMIP_TRUE);
    engine_queue(0u, len);
    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(dispatch_mem)->drop,
                                  "the fragment did not reach the reassembler");
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(dispatch_mem)->act & IDEMIP_DISPATCH_ACT_PINNED) != 0u,
                             "a held IPv6 fragment was not reported as pinned");
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_DMA_IO(dma_mem)->pinned);

    // 60 seconds on, with the second fragment never arriving. The three phases run in order. Each
    // loop is capped: a phase that reports a step it did not take would otherwise never end, and a
    // test that hangs says less than one that fails.
    open_tick(work_a, 1000u + IDEMIP_IP6_REASS_MAXAGE_MS);
    TEST_ASSERT_TRUE(run_phase(work_a, Tick.drain));
    TEST_ASSERT_TRUE_MESSAGE(run_phase(work_a, Tick.service),
                             "the service phase never stopped reporting steps for the expired datagram");
    TEST_ASSERT_TRUE(run_phase(work_a, Tick.flush));
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_DMA_IO(dma_mem)->pinned,
                                     "an abandoned datagram kept the descriptors its fragments pinned");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_released, "the descriptor was unpinned and never handed back");

    // The reassembler's own state: the row is freed, not merely unpinned. A row left expired is one
    // the flush phase reports again on every later tick.
    IDEMIP_IP6_REASS_IO(ip6_reass_mem)->tick_args.now_ms = 1000u + IDEMIP_IP6_REASS_MAXAGE_MS;
    Ip6Reass.tick(ip6_reass_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_IP6_REASS_IO(ip6_reass_mem)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_IP6_REASS_IO(ip6_reass_mem)->expired,
                                    "the abandoned datagram's row was never freed");
}

// The same datagram, completed instead of abandoned: the descriptors stay pinned, because the
// caller has not yet read the reassembled packet out of them.
void test_a_completed_ipv6_datagram_still_holds_its_descriptors(void)
{
    give_the_interface_an_ipv6_address();

    uint16_t len = fill_ip6_fragment(0u, 0u, IDEMIP_TRUE);
    engine_queue(0u, len);
    len = fill_ip6_fragment(1u, TICK_TEST_DATA, IDEMIP_FALSE);
    engine_queue(1u, len);

    open_tick(work_a, 1000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(dispatch_mem)->act & IDEMIP_DISPATCH_ACT_REASSEMBLED) != 0u,
                             "the last fragment did not complete the datagram");
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16(2u, IDEMIP_DMA_IO(dma_mem)->pinned);
}

// RFC 2710 sec 3: a node that has joined a group sends its Report after a delay, and the service
// phase is what runs that clock down. This suite bound the mld6 borrow to the tick and never joined
// a group, so t_service_mld6 was reached only with an empty table, where every path reports nothing.
void test_the_service_phase_runs_the_mld_report_delay_down(void)
{
    static const uint8_t group[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09};

    Mld6Io *ml = IDEMIP_MLD6_IO(mld6_mem);
    ml->group_args.group = group;
    ml->group_args.netif = 0u;
    Mld6.join(mld6_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ml->status);
    TEST_ASSERT_TRUE_MESSAGE(ml->send_report, "a join owes an unsolicited Report");
    TEST_ASSERT_EQUAL_INT(IDEMIP_MLD6_DELAYING_LISTENER, ml->state);

    // Past IDEMIP_MLD6_JOIN_DELAY_MS, measured from the clock the unit last read, which is zero
    // until a tick sets it.
    open_tick(work_a, 100000u);
    TEST_ASSERT_TRUE(run_phase(work_a, Tick.drain));
    TEST_ASSERT_TRUE_MESSAGE(run_phase(work_a, Tick.service),
                             "the service phase never stopped reporting steps for the delayed Report");

    // The unit's own state: the timer fired, the group is listening with no timer running, and a
    // second sweep at the same clock finds nothing due. A row left DELAYING is one the service
    // phase reports a step for on every later tick.
    ml->group_args.group = group;
    ml->group_args.netif = 0u;
    Mld6.find(mld6_mem);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, ml->status, "the joined group left the table");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_MLD6_IDLE_LISTENER, ml->state, "the report delay timer never fired");

    ml->tick_args.now_ms = 100000u;
    Mld6.tick(mld6_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ml->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, ml->expired, "a report delay timer is still due after the sweep");
}

#endif // IDEMIP_ENABLE_IPV6

// Every ring is drained before the phase moves on, so two frames are two steps.
void test_the_drain_takes_every_waiting_frame(void)
{
    uint16_t len = fill_ip4(0u, LOCAL_IP4, 0u);
    engine_queue(0u, len);
    len = fill_ip4(1u, LOCAL_IP4, 0u);
    engine_queue(1u, len);

    open_tick(work_a, 1000u);
    int taken = 0;
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
        taken++;
    }
    TEST_ASSERT_EQUAL_INT(2, taken);
    TEST_ASSERT_EQUAL_UINT16(2u, IDEMIP_TICK_IO(work_a)->frames);
}

// RFC 1122 sec 3.2.1.3 case (e), the directed broadcast of the receiving interface's own subnet, is
// this host's. Every other drain case here addresses the interface's unicast address, which the
// route lookup answers on its own, so the drain had never reached the unit that knows this one.
void test_the_drain_takes_a_frame_addressed_to_our_directed_broadcast(void)
{
    uint16_t len = fill_ip4(0u, LOCAL_IP4 | ~NETMASK4, 0u);
    engine_queue(0u, len);

    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    // TICK_TEST_PROTO is unclaimed, so a destination this host accepted reaches the protocol
    // dispatch and stops there. What it is not is IDEMIP_DISPATCH_DROP_IP_ADDRESS.
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_IP_PROTO, IDEMIP_DISPATCH_IO(dispatch_mem)->drop,
                                  "the subnet's directed broadcast was not taken as this host's");
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(dispatch_mem)->act & IDEMIP_DISPATCH_ACT_FORWARD) == 0u,
                             "the subnet's directed broadcast was reported for forwarding");

    // The control: the same address one subnet over is not this host's, and is forwarded.
    len = fill_ip4(1u, (LOCAL_IP4 + 0x100u) | ~NETMASK4, 0u);
    engine_queue(1u, len);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(dispatch_mem)->act & IDEMIP_DISPATCH_ACT_FORWARD) != 0u,
                             "another subnet's directed broadcast was taken as this host's");

    // The rule that decision rests on, in the unit that owns it.
    Ip4AddrIo *ia = IDEMIP_IP4_ADDR_IO(ip4_addr_mem);
    ia->match_args.addr = LOCAL_IP4 | ~NETMASK4;
    ia->match_args.net = LOCAL_IP4;
    ia->match_args.mask = NETMASK4;
    Ip4Addr.match(ip4_addr_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ia->status);
    TEST_ASSERT_TRUE_MESSAGE(ia->is_broadcast, "the all-ones host part is the subnet's directed broadcast");
}

// IEEE 802.1Q: an untagged interface accepts every frame and reads the payload behind whatever tag
// it carries. Every frame this suite queued was untagged, so the drain had never read a payload at
// the shifted offset, and the unit that finds that offset was bound and never questioned.
void test_the_drain_reads_a_tagged_frame_behind_its_tag(void)
{
    uint8_t *f = rx_buf_at(0u);
    memset(f, 0, IDEMIP_DMA_BUF_STRIDE);
    idemip_eth_build(f, g_local_mac, g_remote_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    VlanIo *v = IDEMIP_VLAN_IO(vlan_mem);
    v->build_args.frame = f;
    v->build_args.type = (uint16_t)IDEMIP_ETHERTYPE_IPV4;
    v->tag_args.vid = 100u;
    v->tag_args.pcp = 0u;
    v->tag_args.dei = IDEMIP_FALSE;
    Vlan.build(vlan_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, v->status);

    IdemIpIp4Fields fields;
    memset(&fields, 0, sizeof fields);
    fields.total_len = (uint16_t)(IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN) + TICK_TEST_DATA);
    fields.id = 0x4242u;
    fields.ttl = TICK_TEST_TTL;
    fields.proto = TICK_TEST_PROTO;
    fields.src = REMOTE_IP4;
    fields.dst = LOCAL_IP4;
    idemip_ip4_build(f + IDEMIP_VLAN_OFF_PAYLOAD, &fields);
    uint16_t len = (uint16_t)(IDEMIP_VLAN_OFF_PAYLOAD + IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN) + TICK_TEST_DATA);
    engine_queue(0u, len);

    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    DispatchIo *di = IDEMIP_DISPATCH_IO(dispatch_mem);
    TEST_ASSERT_TRUE_MESSAGE(di->tagged, "the tag was not seen");
    TEST_ASSERT_EQUAL_UINT16(100u, di->vid);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_ETHERTYPE_IPV4, di->type);
    // The header was found behind the tag, so the datagram reached the protocol dispatch, which is
    // where TICK_TEST_PROTO stops. A payload read at the untagged offset lands in the tag itself and
    // reports a header error instead.
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_IP_PROTO, di->drop,
                                  "the IPv4 header was not read from behind the tag");

    // The unit's own reading of the same frame.
    v->parse_args.frame = f;
    v->parse_args.len = len;
    Vlan.parse(vlan_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, v->status);
    TEST_ASSERT_TRUE(v->tagged);
    TEST_ASSERT_EQUAL_UINT16(100u, v->vid);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_VLAN_OFF_PAYLOAD, (uint16_t)v->payload_off);
    TEST_ASSERT_FALSE(v->vid_reserved);
}

// RFC 1122 sec 3.2.1.3 case (g): "{ 127, <any> } Internal host loopback address. Addresses of this
// form MUST NOT appear outside a host." RFC 6890 Table 4 records 127.0.0.0/8 with Destination False.
// A frame off a wire carrying one is therefore not a datagram destined for this host, whatever the
// loopback interface owns, and the drain discards it rather than delivering it to a transport.
void test_the_drain_discards_a_wire_frame_addressed_to_the_loopback_range(void)
{
    uint16_t len = fill_ip4(0u, 0x7F000001u, 0u);
    engine_queue(0u, len);

    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_IP_ADDRESS, IDEMIP_DISPATCH_IO(dispatch_mem)->drop,
                                  "case (g) bars a loopback address from the wire");
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(dispatch_mem)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u,
                             "a loopback destination off a wire must reach no transport");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(dispatch_mem)->act & IDEMIP_DISPATCH_ACT_FORWARD) == 0u);

    // The unit's own reading, which is what the loopback interface answers with: the whole of 127/8
    // and nothing outside it. The address is this host's; the interface it arrived on is what bars it.
    LoopifIo *lo = IDEMIP_LOOPIF_IO(loopif_mem);
    lo->match_args.addr4 = 0x7F000001u;
    Loopif.owns4(loopif_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, lo->status);
    TEST_ASSERT_TRUE(lo->owned);

    lo->match_args.addr4 = 0x7FFFFFFEu;
    Loopif.owns4(loopif_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, lo->status);
    TEST_ASSERT_TRUE_MESSAGE(lo->owned, "case (g) is { 127, <any> }, not 127.0.0.1 alone");

    lo->match_args.addr4 = LOCAL_IP4;
    Loopif.owns4(loopif_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, lo->status);
    TEST_ASSERT_FALSE_MESSAGE(lo->owned, "an address outside 127/8 is not the loopback's");
}

// --- the flush, and the frames a resolver released ---------------------------

// RFC 826's pending queue holds a frame until the REPLY arrives. The flush phase hands it back, and
// its descriptor stays pinned until the step after, so the caller reads the frame in between.
void test_a_resolved_hold_is_reported_and_unpinned_one_step_later(void)
{
    // A frame in descriptor 2, pinned the way the receive path pins a retained one.
    uint16_t len = fill_ip4(2u, LOCAL_IP4, 0u);
    engine_queue(2u, len);
    Dma.rx_take(dma_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(dma_mem)->status);
    uint8_t desc = IDEMIP_DMA_IO(dma_mem)->index;
    IDEMIP_DMA_IO(dma_mem)->desc_args.index = desc;
    Dma.pin(dma_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(dma_mem)->status);

    ArpTableIo *ar = IDEMIP_ARP_IO(arp_mem);
    ar->now_ms = 1000u;
    ar->queue_args.ip = REMOTE_IP4;
    ar->queue_args.desc = desc;
    ar->queue_args.len = len;
    ArpTable.queue(arp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ar->status);

    // The REPLY arrives, so the row goes stable and the hold is releasable.
    ar->now_ms = 1000u;
    ar->add_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    ar->add_args.spa = REMOTE_IP4;
    ar->add_args.sha = g_remote_mac;
    ar->add_args.netif = 0u;
    ArpTable.add(arp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ar->status);

    open_tick(work_a, 1000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    while (Tick.service(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    Tick.flush(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TICK_UNIT_ARP_HOLD, IDEMIP_TICK_IO(work_a)->unit);
    TEST_ASSERT_EQUAL_UINT16(desc, IDEMIP_TICK_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_UINT16(len, IDEMIP_TICK_IO(work_a)->len);
    TEST_ASSERT_EQUAL_UINT32(REMOTE_IP4, IDEMIP_TICK_IO(work_a)->ip);

    // Still pinned right now, which is what lets the caller read the frame it was just handed.
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(1u, IDEMIP_DMA_IO(dma_mem)->pinned,
                                     "the reported frame was unpinned before the caller could read it");

    // The next step drops that pin.
    Tick.flush(work_a);
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_DMA_IO(dma_mem)->pinned,
                                     "the pin outlived the step after the one that reported it");
}

// The flush phase reports its units in the fixed order too. A tick with nothing deferred reports no
// step at all, so the order can only be seen on one that has work: a partial IPv4 datagram and a
// partial IPv6 one, both left to time out, so IDEMIP_TICK_UNIT_IP4_RECLAIM and
// IDEMIP_TICK_UNIT_IP6_DROP both have something to report in the same tick.
void test_the_flush_phase_reports_its_units_in_order(void)
{
    give_the_interface_an_ipv6_address();
    uint16_t len4 = fill_ip4(0u, LOCAL_IP4, IDEMIP_IP4_FLAG_MF);
    engine_queue(0u, len4);
    uint16_t len6 = fill_ip6_fragment(1u, 0u, IDEMIP_TRUE);
    engine_queue(1u, len6);
    open_tick(work_a, 1000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }

    // Past both fixed bounds, so both rows are reached by one sweep.
    const uint32_t at = 1000u + TICK_REASS_MS + (uint32_t)IDEMIP_IP6_REASS_MAXAGE_MS;
    open_tick(work_a, at);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    while (Tick.service(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    int last = 0;
    int steps = 0;
    int saw_ip4 = 0;
    int saw_ip6 = 0;
    while (Tick.flush(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
        int unit = (int)IDEMIP_TICK_IO(work_a)->unit;
        TEST_ASSERT_TRUE_MESSAGE(unit >= last, "a flush step ran out of the fixed order");
        last = unit;
        steps++;
        if (unit == (int)IDEMIP_TICK_UNIT_IP4_RECLAIM)
        {
            saw_ip4++;
        }
        if (unit == (int)IDEMIP_TICK_UNIT_IP6_DROP)
        {
            saw_ip6++;
        }
        if (steps > 64)
        {
            TEST_FAIL_MESSAGE("the flush phase did not finish");
        }
    }
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, steps, "the flush phase reported no step, so no order was seen");
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, saw_ip4, "the IPv4 reclaim step never ran");
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, saw_ip6, "the IPv6 drop step never ran");
    TEST_ASSERT_TRUE_MESSAGE((int)IDEMIP_TICK_UNIT_IP4_RECLAIM < (int)IDEMIP_TICK_UNIT_IP6_DROP,
                             "the two units the case walked are in the order it asserted");
    TEST_ASSERT_EQUAL_INT(IDEMIP_TICK_PHASE_DONE, IDEMIP_TICK_IO(work_a)->phase);
}

// RFC 1122 sec 3.3.2: "If this timeout expires, the partially-reassembled datagram MUST be discarded
// and an ICMP Time Exceeded message sent to the source host (if fragment zero has been received)",
// and the same section saves the first fragment's header "for inclusion in a possible ICMP Time
// Exceeded (Reassembly Timeout) message". The reclaim step names the timed-out row and reports the
// fragment with the octets it holds, still pinned, so that message can be built.
void test_an_expired_ipv4_datagram_is_reported_for_a_time_exceeded(void)
{
    uint16_t len = fill_ip4(0u, LOCAL_IP4, IDEMIP_IP4_FLAG_MF);
    engine_queue(0u, len);
    open_tick(work_a, 1000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }

    open_tick(work_a, 1000u + TICK_REASS_MS);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    // The sweep reports the source the message goes to and the fragment-zero mark it is gated on.
    int saw_sweep = 0;
    while (Tick.service(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
        if (IDEMIP_TICK_IO(work_a)->unit == IDEMIP_TICK_UNIT_IP4_REASS)
        {
            TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TICK_IO(work_a)->reasm_timeout, "the sweep reached a timed-out row");
            TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TICK_IO(work_a)->reasm_frag_zero,
                                     "the offset-zero fragment was the one held");
            TEST_ASSERT_EQUAL_HEX32_MESSAGE(REMOTE_IP4, IDEMIP_TICK_IO(work_a)->reasm_src,
                                            "the message goes to the source host");
            saw_sweep++;
        }
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, saw_sweep, "the sweep never reported the expired row");

    int saw_reclaim = 0;
    while (Tick.flush(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
        if (IDEMIP_TICK_IO(work_a)->unit != IDEMIP_TICK_UNIT_IP4_RECLAIM)
        {
            continue;
        }
        if (saw_reclaim == 0)
        {
            TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TICK_IO(work_a)->reasm_timeout,
                                     "the reclaim did not say the row timed out");
            TEST_ASSERT_GREATER_THAN_UINT16_MESSAGE(0u, IDEMIP_TICK_IO(work_a)->len,
                                                    "the quoted header cannot be read out of a zero length");
            TEST_ASSERT_NOT_EQUAL_UINT16(IDEMIP_DISPATCH_DESC_NONE, IDEMIP_TICK_IO(work_a)->desc);
        }
        saw_reclaim++;
    }
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, saw_reclaim, "the reclaim step never ran");
}

// RFC 8200 sec 4.5: "If the first fragment (i.e., the one with a Fragment Offset of zero) has been
// received, an ICMP Time Exceeded -- Fragment Reassembly Time Exceeded message should be sent to the
// source of that fragment." That source is sixteen octets of the fragment's own header, so the
// offset-zero fragment stays pinned for the step that reports the abandon.
void test_an_abandoned_ipv6_datagram_is_reported_for_a_time_exceeded(void)
{
    give_the_interface_an_ipv6_address();
    uint16_t len = fill_ip6_fragment(0u, 0u, IDEMIP_TRUE);
    engine_queue(0u, len);
    open_tick(work_a, 1000u);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }

    open_tick(work_a, 1000u + (uint32_t)IDEMIP_IP6_REASS_MAXAGE_MS);
    while (Tick.drain(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    while (Tick.service(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
    }
    int saw = 0;
    while (Tick.flush(work_a), IDEMIP_TICK_IO(work_a)->status == IDEMIP_OK)
    {
        if (IDEMIP_TICK_IO(work_a)->unit != IDEMIP_TICK_UNIT_IP6_DROP)
        {
            continue;
        }
        if (saw == 0)
        {
            TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TICK_IO(work_a)->reasm_timeout, "the abandon was a timeout");
            TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TICK_IO(work_a)->reasm_frag_zero,
                                     "the offset-zero fragment was among the ones held");
            TEST_ASSERT_NOT_EQUAL_MESSAGE(IDEMIP_DISPATCH_DESC_NONE, IDEMIP_TICK_IO(work_a)->desc,
                                          "the source address cannot be read from a dropped descriptor");
        }
        saw++;
    }
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, saw, "the IPv6 drop step never ran");

    // sec 4.5's "all the fragments that have been received for that packet must be discarded" still
    // holds: the pin the report kept goes back on the step after it.
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_DMA_IO(dma_mem)->pinned,
                                     "an abandoned datagram kept the descriptors its fragments pinned");
}

// An interface with no ring bound is stepped over rather than faulting the drain.
void test_an_interface_with_no_ring_is_stepped_over(void)
{
    IDEMIP_TICK_IO(work_a)->if_args.index = 0u;
    IDEMIP_TICK_IO(work_a)->if_args.dma = NULL;
#if IDEMIP_ENABLE_IPV6
    IDEMIP_TICK_IO(work_a)->if_args.nd6 = NULL;
#endif
    IDEMIP_TICK_IO(work_a)->if_args.out = NULL;
    IDEMIP_TICK_IO(work_a)->if_args.out_cap = 0u;
    Tick.if_bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TICK_IO(work_a)->status);

    open_tick(work_a, 1000u);
    Tick.drain(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_TICK_IO(work_a)->status);
}

// --- two interfaces ----------------------------------------------------------
// Every case above binds exactly one ring, which is why a descriptor that could not name its own
// ring went back to nothing for a whole phase. IDEMIP_NETIF_COUNT is 2 by default, so the shipped
// build is the one that was broken.

#if IDEMIP_ENABLE_IPV4

// A descriptor a shared unit hands back carries the interface it arrived on, so it returns to that
// ring and not to whichever one happens to be first. With a bare index the second interface's
// descriptors were reported and left pinned, and the ring emptied one frame at a time until
// IDEMIP_MAX_PINNED_FRAMES was reached and receive stopped.
void test_a_descriptor_from_the_second_interface_goes_back_to_it(void)
{
    // Two rings, so the case can tell "returned to the right one" from "returned to the only one".
    Dma.clear(dma1_mem);
    IDEMIP_DMA_IO(dma1_mem)->bind_args.drv = &g_drv;
    IDEMIP_DMA_IO(dma1_mem)->bind_args.rx_base = rx_bufs;
    IDEMIP_DMA_IO(dma1_mem)->bind_args.tx_base = tx_bufs;
    Dma.bind(dma1_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(dma1_mem)->status);

    TickIo *io = IDEMIP_TICK_IO(work_a);
    io->if_args.index = 1u;
    io->if_args.dma = dma1_mem;
#if IDEMIP_ENABLE_IPV6
    io->if_args.nd6 = nd6_mem;
#endif
    io->if_args.out = out_buf;
    io->if_args.out_cap = sizeof out_buf;
    Tick.if_bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);

    // Claim a descriptor first: pinning one the engine still owns is refused, which is the whole
    // point of the pin protocol. Then pin it the way dispatch does before handing it to a
    // retaining unit, and post it back so only the pin keeps it out of the ring.
    engine_queue(3u, 64u);
    Dma.rx_take(dma1_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(dma1_mem)->status);
    uint8_t held = IDEMIP_DMA_IO(dma1_mem)->index;
    IDEMIP_DMA_IO(dma1_mem)->desc_args.index = held;
    Dma.pin(dma1_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(dma1_mem)->status);
    IDEMIP_DMA_IO(dma1_mem)->desc_args.index = held;
    Dma.rx_post(dma1_mem);

    Dma.pinned(dma1_mem);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_DMA_IO(dma1_mem)->pinned);
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DMA_IO(dma_mem)->pinned);

    // Queue it on ARP for an address nothing answers, so the pending deadline hands it back.
    ArpTableIo *ar = IDEMIP_ARP_IO(arp_mem);
    ar->queue_args.ip = REMOTE_IP4;
    ar->queue_args.desc = IDEMIP_DISPATCH_DESC_HANDLE(1u, held);
    ar->queue_args.len = 64u;
    ar->now_ms = 0u;
    ArpTable.queue(arp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ar->status);

    // Run whole ticks until the service phase reports the timed-out hold, then one more step so the
    // deferred unpin lands (tick.h: the descriptor stays pinned until the step after the report).
    idemip_bool reported = IDEMIP_FALSE;
    for (uint32_t t = 1000u; t <= 1000u + (IDEMIP_ARP_MAXPENDING_S * 2000u) && !reported; t += 1000u)
    {
        open_tick(work_a, t);
        while (Tick.drain(work_a), io->status == IDEMIP_OK)
        {
        }
        while (Tick.service(work_a), io->status == IDEMIP_OK)
        {
            if (io->len != 0u && io->desc != IDEMIP_DISPATCH_DESC_NONE)
            {
                TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, io->netif, "the hold was reported on the wrong interface");
                reported = IDEMIP_TRUE;
            }
        }
        while (Tick.flush(work_a), io->status == IDEMIP_OK)
        {
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(reported, "the ARP hold was never reported at all");

    Dma.pinned(dma1_mem);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_DMA_IO(dma1_mem)->pinned,
                                     "the descriptor never came back to interface 1's ring");
    Dma.pinned(dma_mem);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_DMA_IO(dma_mem)->pinned,
                                     "interface 0's ring was touched by interface 1's descriptor");
}

// The two halves of a handle come apart as they went together, over every index and interface the
// build can hold. A handle can never collide with the sentinel, which is what keeps "no descriptor"
// distinguishable from descriptor zero on the last interface.
void test_a_descriptor_handle_round_trips(void)
{
    for (uint8_t n = 0u; n < (uint8_t)IDEMIP_NETIF_COUNT; n++)
    {
        for (uint16_t d = 0u; d < (uint16_t)IDEMIP_RX_DESCRIPTORS; d++)
        {
            uint16_t h = IDEMIP_DISPATCH_DESC_HANDLE(n, d);
            TEST_ASSERT_EQUAL_UINT8(n, IDEMIP_DISPATCH_DESC_NETIF(h));
            TEST_ASSERT_EQUAL_UINT8((uint8_t)d, IDEMIP_DISPATCH_DESC_INDEX(h));
            TEST_ASSERT_TRUE(h != IDEMIP_DISPATCH_DESC_NONE);
        }
    }
}

#endif // IDEMIP_ENABLE_IPV4

// A build with a borrow left unbound still ticks: the step that would have driven it is skipped.
void test_an_unbound_service_is_skipped(void)
{
    Tick.clear(work_b);
    TickIo *io = IDEMIP_TICK_IO(work_b);
    io->bind_args.dispatch = NULL;
    io->bind_args.timeouts = NULL;
    io->bind_args.stats = NULL;
    io->bind_args.arp = NULL;
    io->bind_args.ip4_reass = NULL;
    io->bind_args.igmp = NULL;
#if IDEMIP_ENABLE_IPV6
    io->bind_args.ip6_reass = NULL;
    io->bind_args.mld6 = NULL;
#endif
    io->bind_args.netif = NULL;
    Tick.bind(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);

    open_tick(work_b, 1000u);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_TIMEOUT_FOREVER, io->until_ms);
    Tick.drain(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, io->status);
    Tick.service(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, io->status);
    Tick.flush(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, io->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TICK_PHASE_DONE, io->phase);
}
