// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The reference suite for a golden module. Every unit in this tree is tested the same way:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. the DMA contract is an ordering claim, so ordering is recorded and asserted
//   6. BUSY and ERR are separated by whether retrying can ever succeed
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ethernet/phy.h"

#include <string.h>
#include <unity.h>
#include "src/ethernet/ethernet_defines.h"
#include "src/ethernet/mii_defines.h"

// --- a recording driver ------------------------------------------------------

static uint8_t g_frame[64];
static size_t g_frame_len;
// Wide enough for the full-length RFC 894 frame phy_tx_claim must admit, so the bound can be driven
// from the accepting side and not only from the rejecting one.
static uint8_t g_txbuf[IDEMIP_ETH_FRAME_MAX];
static int g_released;
static int g_committed;
static size_t g_commit_len;

// A driver answers a full ring and an impossible length the same way, with a null buffer. Both are
// driven here so the suite can show phy separates them.
static int g_tx_full;
static int g_tx_commit_fails;

// What the driver was asked to do, in the order it was asked.
#define EV_INVALIDATE 1
#define EV_CLEAN 2
#define EV_RX_CLAIM 3
#define EV_RX_RELEASE 4
#define EV_TX_COMMIT 5
static int g_ev[16];
static int g_ev_n;

static void ev(int what)
{
    if (g_ev_n < (int)(sizeof g_ev / sizeof g_ev[0]))
    {
        g_ev[g_ev_n++] = what;
    }
}

static const uint8_t g_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

static IdemIpPhyLink fake_link(void)
{
    IdemIpPhyLink l = {IDEMIP_PHY_SPEED_100, 1u, 1u};
    return l;
}
static const uint8_t *fake_mac(void)
{
    return g_mac;
}
static int g_claim_no_addr; // when set, rx_claim reports a length and no address at all

static size_t fake_rx_claim(const uint8_t **frame)
{
    ev(EV_RX_CLAIM);
    if (g_frame_len == 0)
    {
        return 0;
    }
    *frame = g_claim_no_addr ? NULL : g_frame;
    return g_frame_len;
}
static void fake_rx_release(void)
{
    ev(EV_RX_RELEASE);
    g_released++;
    g_frame_len = 0;
}
static uint8_t *fake_tx_claim(size_t len)
{
    if (g_tx_full || len > sizeof g_txbuf)
    {
        return NULL;
    }
    return g_txbuf;
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
static uint16_t g_regs[32];
static idemip_bool fake_mdio_read(uint8_t addr, uint8_t reg, uint16_t *out)
{
    (void)addr;
    *out = g_regs[reg];
    return IDEMIP_TRUE;
}
static idemip_bool fake_mdio_write(uint8_t addr, uint8_t reg, uint16_t val)
{
    (void)addr;
    g_regs[reg] = val;
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

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_PHY_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_PHY_BORROW + 16];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_PHY_BORROW, CANARY, cap - IDEMIP_PHY_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_PHY_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_PHY_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_frame, 0xA5, sizeof g_frame);
    g_frame_len = 0;
    g_released = 0;
    g_committed = 0;
    g_commit_len = 0;
    g_ev_n = 0;
    g_tx_full = 0;
    g_tx_commit_fails = 0;
    memset(g_regs, 0, sizeof g_regs);
}
void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

static void bind_ok(uint8_t *w)
{
    IDEMIP_PHY_IO(w)->bind_args.drv = &g_drv;
    IDEMIP_PHY_IO(w)->bind_args.addr = 1u;
    Phy.bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(w)->status);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Phy.bind(NULL);
    Phy.poll_link(NULL);
    Phy.rx_claim(NULL);
    Phy.rx_release(NULL);
    Phy.tx_claim(NULL);
    Phy.tx_commit(NULL);
    Phy.mdio_read(NULL);
    Phy.mdio_write(NULL);
    TEST_PASS();
}

// The borrow IS the interface, and the operand block is in it, so two links share no byte at all.
// This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_PHY_IO(work_a)->bind_args.drv = &g_drv;
    IDEMIP_PHY_IO(work_a)->bind_args.addr = 1u;
    IDEMIP_PHY_IO(work_b)->bind_args.drv = &g_drv;
    IDEMIP_PHY_IO(work_b)->bind_args.addr = 7u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_PHY_IO(work_a)->bind_args.addr);
    TEST_ASSERT_EQUAL_UINT8(7u, IDEMIP_PHY_IO(work_b)->bind_args.addr);

    Phy.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    Phy.bind(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_b)->status);

    // And a's result is still a's after b's call.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot
// change what this one reports. This is the determinism the design is named for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    bind_ok(work_a);
    bind_ok(work_b);

    g_regs[IDEMIP_MII_BMSR] = 0x1234u;
    IDEMIP_PHY_IO(work_a)->reg_args.reg = IDEMIP_MII_BMSR;
    IDEMIP_PHY_IO(work_b)->reg_args.reg = IDEMIP_MII_BMCR;

    // Interleave: a, then b, then a again. a's answer must be identical both times.
    Phy.mdio_read(work_a);
    uint16_t first = IDEMIP_PHY_IO(work_a)->reg;
    Phy.mdio_read(work_b);
    Phy.mdio_read(work_a);
    uint16_t second = IDEMIP_PHY_IO(work_a)->reg;

    TEST_ASSERT_EQUAL_HEX16(0x1234u, first);
    TEST_ASSERT_EQUAL_HEX16(first, second);
}

void test_unbound_borrow_refuses_work(void)
{
    // Zeroed, never bound: every entry must refuse rather than call through a null driver.
    Phy.poll_link(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
    Phy.rx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
    Phy.tx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
}

// --- bind --------------------------------------------------------------------

void test_bind_refuses_null_driver(void)
{
    IDEMIP_PHY_IO(work_a)->bind_args.drv = NULL;
    Phy.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
}

// Clause 22 gives the management address 5 bits, so 32 and above is not addressable.
void test_bind_refuses_out_of_range_address(void)
{
    IDEMIP_PHY_IO(work_a)->bind_args.drv = &g_drv;
    IDEMIP_PHY_IO(work_a)->bind_args.addr = (uint8_t)IDEMIP_MII_PHY_ADDR_MAX;
    Phy.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
}

// Every member is called without a null test on the frame path, so an incomplete driver has to be
// refused at bind. Each member is nulled in turn.
void test_bind_refuses_an_incomplete_driver(void)
{
    IdemIpPhyDriver partial;
    const size_t members = sizeof(IdemIpPhyDriver) / sizeof(void (*)(void));
    for (size_t i = 0; i < members; i++)
    {
        memcpy(&partial, &g_drv, sizeof partial);
        ((void **)&partial)[i] = NULL;
        IDEMIP_PHY_IO(work_a)->bind_args.drv = &partial;
        IDEMIP_PHY_IO(work_a)->bind_args.addr = 1u;
        Phy.bind(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status,
                                      "a driver missing a member was accepted");
    }
}

void test_bind_accepts_a_complete_driver(void)
{
    bind_ok(work_a);
    Phy.poll_link(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_PHY_SPEED_100, IDEMIP_PHY_IO(work_a)->link.speed);
    TEST_ASSERT_TRUE(IDEMIP_PHY_IO(work_a)->link.up);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_mac, IDEMIP_PHY_IO(work_a)->mac, 6);
}

// --- the receive contract ----------------------------------------------------

// Nothing waiting is BUSY, not OK and not ERR. This is the case a bool return could not express:
// OK would claim a frame that is not there, ERR would call a healthy empty ring broken.
void test_empty_ring_is_busy(void)
{
    bind_ok(work_a);
    g_frame_len = 0;
    Phy.rx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_PHY_IO(work_a)->len);
    TEST_ASSERT_NULL(IDEMIP_PHY_IO(work_a)->frame);
}

// The engine wrote the buffer, so the stale cached copy is discarded before the frame is read.
// Ordering is the whole claim: invalidate must precede the frame becoming readable.
void test_claim_invalidates_before_the_frame_is_readable(void)
{
    bind_ok(work_a);
    g_frame_len = 32u;
    g_ev_n = 0;
    Phy.rx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(32u, IDEMIP_PHY_IO(work_a)->len);
    TEST_ASSERT_EQUAL_PTR(g_frame, IDEMIP_PHY_IO(work_a)->frame);

    TEST_ASSERT_EQUAL_INT(2, g_ev_n);
    TEST_ASSERT_EQUAL_INT(EV_RX_CLAIM, g_ev[0]);
    TEST_ASSERT_EQUAL_INT(EV_INVALIDATE, g_ev[1]);
}

void test_claim_and_release_round_trip(void)
{
    bind_ok(work_a);
    g_frame_len = 16u;
    Phy.rx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    Phy.rx_release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(1, g_released);
    TEST_ASSERT_NULL(IDEMIP_PHY_IO(work_a)->frame);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_PHY_IO(work_a)->len);
}

// A second claim before a release would hand out a descriptor the engine still owns.
void test_double_claim_is_refused(void)
{
    bind_ok(work_a);
    g_frame_len = 16u;
    Phy.rx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    Phy.rx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
}

// A release with nothing claimed would return a descriptor twice.
void test_release_without_claim_is_refused(void)
{
    bind_ok(work_a);
    Phy.rx_release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(0, g_released);
}

// Two borrows claim independently: a's claim does not make b's ring look busy, and releasing a
// does not release b.
void test_claims_on_two_borrows_are_independent(void)
{
    bind_ok(work_a);
    bind_ok(work_b);
    g_frame_len = 8u;
    Phy.rx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);

    // b has claimed nothing, so releasing b is refused even though a holds one.
    Phy.rx_release(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_b)->status);
    TEST_ASSERT_EQUAL_INT(0, g_released);

    Phy.rx_release(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(1, g_released);
}

// --- the transmit contract ---------------------------------------------------

// The engine reads the buffer, so what the build left in cache is written back first. Ordering
// again: clean must precede commit.
void test_commit_cleans_before_handing_over(void)
{
    bind_ok(work_a);
    IDEMIP_PHY_IO(work_a)->tx_args.len = 24u;
    Phy.tx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(g_txbuf, IDEMIP_PHY_IO(work_a)->tx);

    g_ev_n = 0;
    Phy.tx_commit(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(2, g_ev_n);
    TEST_ASSERT_EQUAL_INT(EV_CLEAN, g_ev[0]);
    TEST_ASSERT_EQUAL_INT(EV_TX_COMMIT, g_ev[1]);
    TEST_ASSERT_EQUAL_size_t(24u, g_commit_len);
}

// A length no Ethernet frame can ever carry (RFC 894) is ERR, because retrying it can never
// succeed. Reported as BUSY the caller would spin forever.
void test_tx_claim_refuses_a_length_no_frame_can_carry(void)
{
    bind_ok(work_a);
    IDEMIP_PHY_IO(work_a)->tx_args.len = (size_t)IDEMIP_ETH_FRAME_MAX + 1u;
    Phy.tx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_PHY_IO(work_a)->tx);
}

// The other side of the same bound. RFC 894: "thus the maximum length of an IP datagram sent over an
// Ethernet is 1500 octets. Implementations are encouraged to support full-length packets." The wire
// length of that datagram is IDEMIP_ETH_FRAME_MAX, which must be admitted.
void test_tx_claim_admits_a_full_length_frame(void)
{
    bind_ok(work_a);
    IDEMIP_PHY_IO(work_a)->tx_args.len = (size_t)IDEMIP_ETH_FRAME_MAX;
    Phy.tx_claim(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status, "a full-length RFC 894 frame was refused");
    TEST_ASSERT_NOT_NULL(IDEMIP_PHY_IO(work_a)->tx);
}

// A ring with no room is BUSY, because retrying will succeed once a descriptor frees. The service
// knows which of the two it is; the caller only needs to know whether to come back.
void test_full_ring_is_busy_and_the_retry_succeeds(void)
{
    bind_ok(work_a);
    g_tx_full = 1;
    IDEMIP_PHY_IO(work_a)->tx_args.len = 24u;
    Phy.tx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_NULL(IDEMIP_PHY_IO(work_a)->tx);

    g_tx_full = 0;
    Phy.tx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(g_txbuf, IDEMIP_PHY_IO(work_a)->tx);
}

// A driver that could not queue a committed frame is BUSY for the same reason.
// BUSY is a retry and not a fault, and a retry needs the buffer the claim holds. tx_commit cleared
// PhyIo::tx whichever way the MAC answered, so the retry the contract asks for arrived with nothing
// to commit and reported ERR - on a frame already built and already cleaned, and ERR is not a status
// a caller retries. The claim stands until the MAC takes it.
void test_commit_that_could_not_queue_is_busy_and_the_retry_succeeds(void)
{
    bind_ok(work_a);
    IDEMIP_PHY_IO(work_a)->tx_args.len = 24u;
    Phy.tx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    uint8_t *claimed = IDEMIP_PHY_IO(work_a)->tx;
    TEST_ASSERT_NOT_NULL(claimed);

    g_tx_commit_fails = 1;
    Phy.tx_commit(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(claimed, IDEMIP_PHY_IO(work_a)->tx,
                                  "the buffer went with the refusal, so there is nothing to retry");
    TEST_ASSERT_EQUAL_INT(0, g_committed);

    g_tx_commit_fails = 0;
    Phy.tx_commit(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status,
                                  "the retry BUSY asked for had no buffer left to commit");
    TEST_ASSERT_EQUAL_INT(1, g_committed);

    // And once the MAC has it the claim is over, so a third commit is ERR rather than a double send.
    Phy.tx_commit(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(1, g_committed);
}

void test_commit_without_claim_is_refused(void)
{
    bind_ok(work_a);
    IDEMIP_PHY_IO(work_a)->tx = NULL;
    IDEMIP_PHY_IO(work_a)->tx_args.len = 8u;
    Phy.tx_commit(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(0, g_committed);
}

// --- management --------------------------------------------------------------

// Clause 22 gives the register address 5 bits.
void test_mdio_refuses_an_out_of_range_register(void)
{
    bind_ok(work_a);
    IDEMIP_PHY_IO(work_a)->reg_args.reg = (uint8_t)IDEMIP_MII_REG_MAX;
    Phy.mdio_read(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
    Phy.mdio_write(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status);
}

void test_mdio_write_then_read(void)
{
    bind_ok(work_a);
    IDEMIP_PHY_IO(work_a)->reg_args.reg = IDEMIP_MII_BMCR;
    IDEMIP_PHY_IO(work_a)->reg_args.val = IDEMIP_BMCR_ANEG_ENABLE | IDEMIP_BMCR_FULL_DUPLEX;
    Phy.mdio_write(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);

    Phy.mdio_read(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_BMCR_ANEG_ENABLE | IDEMIP_BMCR_FULL_DUPLEX, IDEMIP_PHY_IO(work_a)->reg);
}

// A link with no driver behind it has nothing to claim from, nothing to release to and no management
// interface, so every entry that reaches through the driver refuses the call.
void test_an_unbound_link_is_refused(void)
{
    memset(work_a, 0, IDEMIP_PHY_BORROW);

    Phy.rx_release(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status, "a release ran with no driver");

    IDEMIP_PHY_IO(work_a)->tx_args.len = 64u;
    Phy.tx_claim(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status, "a claim ran with no driver");

    IDEMIP_PHY_IO(work_a)->tx = g_frame;
    IDEMIP_PHY_IO(work_a)->tx_args.len = 64u;
    Phy.tx_commit(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status, "a commit ran with no driver");

    IDEMIP_PHY_IO(work_a)->reg_args.reg = 0u;
    Phy.mdio_read(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status, "a register read ran with no driver");
    IDEMIP_PHY_IO(work_a)->reg_args.val = 0u;
    Phy.mdio_write(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status, "a register write ran with no driver");
}

// A frame of no octets is not a frame: there is nothing to claim a buffer for and nothing to hand to
// the engine. And a claim that reports a length with no address behind it is no frame either - it is
// BUSY, the same as no frame at all, since the next claim may bring one.
void test_a_frame_of_no_octets_and_a_claim_with_no_address(void)
{
    bind_ok(work_a);

    IDEMIP_PHY_IO(work_a)->tx_args.len = 0u;
    Phy.tx_claim(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status, "a buffer was claimed for no octets");

    IDEMIP_PHY_IO(work_a)->tx_args.len = 64u;
    Phy.tx_claim(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(work_a)->status);
    IDEMIP_PHY_IO(work_a)->tx_args.len = 0u;
    Phy.tx_commit(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_PHY_IO(work_a)->status, "a frame of no octets was committed");

    g_frame_len = 100u;
    g_claim_no_addr = 1;
    Phy.rx_claim(work_a);
    g_claim_no_addr = 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_PHY_IO(work_a)->status,
                                  "a claim with no address behind it was taken as a frame");
}
