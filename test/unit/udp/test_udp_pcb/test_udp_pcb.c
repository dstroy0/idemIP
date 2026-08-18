// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for the RFC 768 bindings. It tests the contract, not the protocol:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. the published offsets are ordered, non-overlapping, and inside IDEMIP_UDP_PCB_BORROW
//   5. clear zeroes the regions and marks the borrow, and a borrow that was never cleared is refused
//   6. an index past the table and a missing address operand are refused
//
// The behavior section below it drives the protocol: RFC 768's receive ports, RFC 1122 sec 4.1.3's
// demultiplex, RFC 1122 sec 3.2.1.7's Time-to-Live, RFC 1112 sec 6.1's multicast defaults, RFC 6335
// sec 6's dynamic port range and RFC 3828 sec 3.1's Checksum Coverage. RFC 768, RFC 1122 sec 4.1 and
// RFC 3828 print no numeric datagram, so those cases assert the properties their text states rather
// than a vector; addresses come from RFC 5737 sec 3's 192.0.2.0/24 and RFC 3849 sec 2's
// 2001:db8::/32.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/udp/udp_pcb.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each so
// a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_UDP_PCB_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_UDP_PCB_BORROW + 16];

#define TAB_BYTES ((size_t)IDEMIP_UDP_PCBS << IDEMIP_UDP_PCB_ENTRY_SHIFT)

static const uint8_t g_local[IDEMIP_UDP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 1u};
static const uint8_t g_remote[IDEMIP_UDP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 9u};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_UDP_PCB_BORROW, CANARY, cap - IDEMIP_UDP_PCB_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_UDP_PCB_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_UDP_PCB_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

static void call_every_entry(uint8_t *w)
{
    UdpPcb.open(w);
    UdpPcb.close(w);
    UdpPcb.bind(w);
    UdpPcb.connect(w);
    UdpPcb.disconnect(w);
    UdpPcb.set_opts(w);
    UdpPcb.load(w);
    UdpPcb.find(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    UdpPcb.clear(NULL);
    call_every_entry(NULL);
    TEST_PASS();
}

// The map is public, so a reader can place every region without opening the .c. Each region starts
// where the one before it ends, and the last one ends inside the borrow.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_UDP_PCB_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_UDP_PCB_OFF_IO + sizeof(UdpPcbIo), (size_t)IDEMIP_UDP_PCB_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_UDP_PCB_OFF_TAB >= (size_t)IDEMIP_UDP_PCB_OFF_CTX,
                             "the table overlaps the context");
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_UDP_PCB_OFF_TAB + TAB_BYTES <= (size_t)IDEMIP_UDP_PCB_BORROW,
                             "the table runs past IDEMIP_UDP_PCB_BORROW");
    TEST_ASSERT_TRUE_MESSAGE(sizeof(UdpPcbIo) <= (size_t)IDEMIP_UDP_PCB_CTX_BYTES,
                             "the operand block runs into the table");
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_UDP_PCB_OFF_IO, IDEMIP_UDP_PCB_IO(work_a));
}

// Zeroed, never cleared: every entry must refuse rather than read a table that was never zeroed.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_UDP_PCB_IO(work_a)->bind_args.ip = g_local;
    IDEMIP_UDP_PCB_IO(work_a)->connect_args.ip = g_remote;
    IDEMIP_UDP_PCB_IO(work_a)->find_args.local_ip = g_local;
    IDEMIP_UDP_PCB_IO(work_a)->find_args.remote_ip = g_remote;

    UdpPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    UdpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    UdpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    UdpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    UdpPcb.disconnect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    UdpPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    UdpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
}

// --- clear -------------------------------------------------------------------

void test_clear_zeroes_the_table(void)
{
    memset(work_a + IDEMIP_UDP_PCB_OFF_CTX, 0xEE, (size_t)IDEMIP_UDP_PCB_BORROW - IDEMIP_UDP_PCB_OFF_CTX);
    UdpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDP_PCB_IO(work_a)->status);
    for (size_t i = 0; i < TAB_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[IDEMIP_UDP_PCB_OFF_TAB + i], "clear left a binding unzeroed");
    }
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_NONE, IDEMIP_UDP_PCB_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_PORT_ANY, IDEMIP_UDP_PCB_IO(work_a)->port);
}

// A second clear is the same call on the same bytes, so it reports the same thing.
void test_clear_repeats(void)
{
    UdpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDP_PCB_IO(work_a)->status);
    UdpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDP_PCB_IO(work_a)->status);
}

// The operand block is the caller's. clear reports through the result members and leaves the operands
// where they were.
void test_clear_leaves_the_operands_alone(void)
{
    IDEMIP_UDP_PCB_IO(work_a)->bind_args.port = 68u;
    IDEMIP_UDP_PCB_IO(work_a)->bind_args.ip = g_local;
    IDEMIP_UDP_PCB_IO(work_a)->opt_args.cksum_len_tx = 8u;
    UdpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(68u, IDEMIP_UDP_PCB_IO(work_a)->bind_args.port);
    TEST_ASSERT_EQUAL_PTR(g_local, IDEMIP_UDP_PCB_IO(work_a)->bind_args.ip);
    TEST_ASSERT_EQUAL_UINT16(8u, IDEMIP_UDP_PCB_IO(work_a)->opt_args.cksum_len_tx);
}

// --- two borrows -------------------------------------------------------------

// The borrow IS the table, and the operand block is in it, so two tables share no byte at all. This
// is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_UDP_PCB_IO(work_a)->bind_args.port = 67u;
    IDEMIP_UDP_PCB_IO(work_a)->pcb_args.index = 1u;
    IDEMIP_UDP_PCB_IO(work_b)->bind_args.port = 68u;
    IDEMIP_UDP_PCB_IO(work_b)->pcb_args.index = 0u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_UINT16(67u, IDEMIP_UDP_PCB_IO(work_a)->bind_args.port);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_UDP_PCB_IO(work_a)->pcb_args.index);
    TEST_ASSERT_EQUAL_UINT16(68u, IDEMIP_UDP_PCB_IO(work_b)->bind_args.port);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_UDP_PCB_IO(work_b)->pcb_args.index);

    UdpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_UDP_PCB_IO(work_a)->status);

    // And b's operands are still b's after a's call.
    TEST_ASSERT_EQUAL_UINT16(68u, IDEMIP_UDP_PCB_IO(work_b)->bind_args.port);
    TEST_ASSERT_EQUAL_UINT16(67u, IDEMIP_UDP_PCB_IO(work_a)->bind_args.port);
}

// A clear on one borrow reaches no byte of the other's table.
void test_a_clear_on_one_borrow_leaves_the_other_table_untouched(void)
{
    memset(work_b + IDEMIP_UDP_PCB_OFF_TAB, 0xC3, TAB_BYTES);
    UdpPcb.clear(work_a);
    for (size_t i = 0; i < TAB_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[IDEMIP_UDP_PCB_OFF_TAB + i], "a clear crossed into b's table");
    }
    UdpPcb.clear(work_b);
    for (size_t i = 0; i < TAB_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_b[IDEMIP_UDP_PCB_OFF_TAB + i], "clear left a binding unzeroed");
    }
}

// --- the bounds on an operand ------------------------------------------------

// An index no entry has is refused, and reporting it as BUSY would have the caller retry a call that
// can never succeed.
void test_an_index_past_the_table_is_refused(void)
{
    UdpPcb.clear(work_a);
    IDEMIP_UDP_PCB_IO(work_a)->pcb_args.index = (uint16_t)IDEMIP_UDP_PCBS;
    UdpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    UdpPcb.disconnect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    UdpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);

    IDEMIP_UDP_PCB_IO(work_a)->bind_args.index = (uint16_t)IDEMIP_UDP_PCBS;
    IDEMIP_UDP_PCB_IO(work_a)->bind_args.ip = g_local;
    UdpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);

    IDEMIP_UDP_PCB_IO(work_a)->opt_args.index = (uint16_t)IDEMIP_UDP_PCBS;
    UdpPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
}

// A bind and a connect read IDEMIP_UDP_PCB_ADDR_BYTES from the operand, so a null one is refused
// rather than dereferenced.
void test_a_missing_address_operand_is_refused(void)
{
    UdpPcb.clear(work_a);
    IDEMIP_UDP_PCB_IO(work_a)->bind_args.index = 0u;
    IDEMIP_UDP_PCB_IO(work_a)->bind_args.ip = NULL;
    UdpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);

    IDEMIP_UDP_PCB_IO(work_a)->connect_args.index = 0u;
    IDEMIP_UDP_PCB_IO(work_a)->connect_args.ip = NULL;
    UdpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);

    IDEMIP_UDP_PCB_IO(work_a)->find_args.local_ip = NULL;
    IDEMIP_UDP_PCB_IO(work_a)->find_args.remote_ip = g_remote;
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_NONE, IDEMIP_UDP_PCB_IO(work_a)->index);
}

// A load that reports nothing leaves nothing of a former load behind.
void test_a_refused_load_reports_no_binding(void)
{
    UdpPcb.clear(work_a);
    IDEMIP_UDP_PCB_IO(work_a)->info.local_port = 53u;
    IDEMIP_UDP_PCB_IO(work_a)->info.local_ip = g_local;
    IDEMIP_UDP_PCB_IO(work_a)->pcb_args.index = (uint16_t)IDEMIP_UDP_PCBS;
    UdpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_UDP_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_UDP_PCB_IO(work_a)->info.local_port);
    TEST_ASSERT_NULL(IDEMIP_UDP_PCB_IO(work_a)->info.local_ip);
}

// =============================================================================
// The behavior: RFC 768's receive ports and RFC 1122 sec 4.1.3's demultiplex
// =============================================================================

// A second address on the same RFC 5737 sec 3 documentation network, and a second source.
static const uint8_t g_local2[IDEMIP_UDP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 2u};
static const uint8_t g_remote2[IDEMIP_UDP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 10u};

// The wild local address: RFC 1122 sec 3.2.1.3's "{ 0, 0 }", which RFC 1122 sec 4.1.3.5 leaves
// unspecified.
static const uint8_t g_any[IDEMIP_UDP_PCB_ADDR_BYTES] = {0u};

// 192.0.2.1 with a tail no version-4 compare may read.
static const uint8_t g_local_tail[IDEMIP_UDP_PCB_ADDR_BYTES] = {192u,  0u,   2u,   1u,   0xAAu, 0xBBu, 0xCCu, 0xDDu,
                                                                0xEEu, 0xFFu, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u};

// RFC 3849 sec 2's documentation prefix. The first two differ in the last octet only, so a compare
// that stops short of sixteen octets cannot tell them apart.
static const uint8_t g_v6_a[IDEMIP_UDP_PCB_ADDR_BYTES] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0u, 0u, 0u, 0u,
                                                          0u,    0u,    0u,    0u,    0u, 0u, 0u, 0x01u};
static const uint8_t g_v6_b[IDEMIP_UDP_PCB_ADDR_BYTES] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0u, 0u, 0u, 0u,
                                                          0u,    0u,    0u,    0u,    0u, 0u, 0u, 0x02u};
static const uint8_t g_v6_r[IDEMIP_UDP_PCB_ADDR_BYTES] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0u, 0u, 0u, 0u,
                                                          0u,    0u,    0u,    0u,    0u, 0u, 0u, 0x09u};

static uint16_t open_binding(uint8_t *w, uint8_t version, idemip_bool lite)
{
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(w);
    io->open_args.ip_version = version;
    io->open_args.lite = lite;
    UdpPcb.open(w);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, io->status, "an open of a cleared table was refused");
    TEST_ASSERT_NOT_EQUAL_UINT16(IDEMIP_UDP_PCB_NONE, io->index);
    return io->index;
}

static void bind_ok(uint8_t *w, uint16_t index, const uint8_t *ip, uint16_t port, uint8_t zone, uint8_t netif)
{
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(w);
    io->bind_args.index = index;
    io->bind_args.ip = ip;
    io->bind_args.port = port;
    io->bind_args.zone = zone;
    io->bind_args.netif = netif;
    UdpPcb.bind(w);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, io->status, "a bind of a free port was refused");
}

static void connect_ok(uint8_t *w, uint16_t index, const uint8_t *ip, uint16_t port)
{
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(w);
    io->connect_args.index = index;
    io->connect_args.ip = ip;
    io->connect_args.port = port;
    io->connect_args.zone = 0u;
    io->connect_args.netif = 0u;
    UdpPcb.connect(w);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, io->status, "a connect to a real destination was refused");
}

static void load_ok(uint8_t *w, uint16_t index)
{
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(w);
    io->pcb_args.index = index;
    UdpPcb.load(w);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, io->status, "a load of an open entry was refused");
}

// The datagram a find matches: destination address and RFC 768 Destination Port, source address and
// Source Port, the RFC 3828 Checksum Coverage it arrived with, and the interface it arrived on.
static void set_datagram(uint8_t *w, uint8_t version, const uint8_t *local_ip, uint16_t local_port,
                         const uint8_t *remote_ip, uint16_t remote_port, uint16_t cksum_len, uint8_t netif)
{
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(w);
    io->find_args.ip_version = version;
    io->find_args.local_ip = local_ip;
    io->find_args.local_port = local_port;
    io->find_args.remote_ip = remote_ip;
    io->find_args.remote_port = remote_port;
    io->find_args.cksum_len = cksum_len;
    io->find_args.local_zone = 0u;
    io->find_args.remote_zone = 0u;
    io->find_args.netif = netif;
}

// --- open and close ----------------------------------------------------------

// RFC 768's user interface allows "the creation of new receive ports". Each open takes a different
// entry, and reports which.
void test_open_takes_a_free_entry_and_reports_it(void)
{
    UdpPcb.clear(work_a);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t b = open_binding(work_a, 4u, IDEMIP_FALSE);
    TEST_ASSERT_NOT_EQUAL_UINT16(a, b);
    TEST_ASSERT_TRUE(a < (uint16_t)IDEMIP_UDP_PCBS);
    TEST_ASSERT_TRUE(b < (uint16_t)IDEMIP_UDP_PCBS);
}

// RFC 791 sec 3.1's Version is 4 and RFC 8200 sec 3's is 6. No other value is a binding, and no
// retry makes it one, so it is ERR.
void test_open_refuses_a_version_that_is_not_4_or_6(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    for (uint8_t v = 0u; v < 8u; v++)
    {
        if (v == 4u || v == 6u)
        {
            continue;
        }
        io->open_args.ip_version = v;
        io->open_args.lite = IDEMIP_FALSE;
        UdpPcb.open(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "a version that is neither 4 nor 6 was opened");
        TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_NONE, io->index);
    }
}

// RFC 1112 sec 6.1: a multicast time-to-live "should default to 1 for all multicast IP datagrams".
// RFC 3828 sec 3.3 recommends UDP-Lite default to "mimic UDP", which sec 3.1 makes a Checksum
// Coverage of zero.
void test_open_stamps_the_rfc1112_multicast_ttl_default_of_one(void)
{
    UdpPcb.clear(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_TRUE);
    load_ok(work_a, i);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    TEST_ASSERT_EQUAL_UINT8(1u, io->info.mcast_ttl);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_IP_DEFAULT_TTL, io->info.ttl);
    TEST_ASSERT_EQUAL_UINT16(0u, io->info.cksum_len_tx);
    TEST_ASSERT_EQUAL_UINT16(0u, io->info.cksum_len_rx);
    TEST_ASSERT_TRUE(io->info.lite);
    TEST_ASSERT_FALSE(io->info.connected);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_PORT_ANY, io->info.local_port);
}

// Every entry open is BUSY, not ERR: a close frees one and the same call then succeeds. Reported as
// ERR the caller would abandon a table that is about to have room.
void test_a_full_table_is_busy_and_a_close_makes_the_retry_succeed(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t last = IDEMIP_UDP_PCB_NONE;
    for (uint16_t n = 0u; n < (uint16_t)IDEMIP_UDP_PCBS; n++)
    {
        last = open_binding(work_a, 4u, IDEMIP_FALSE);
    }
    io->open_args.ip_version = 4u;
    UdpPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, io->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_NONE, io->index);

    io->pcb_args.index = last;
    UdpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);

    io->open_args.ip_version = 4u;
    UdpPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(last, io->index);
}

void test_close_frees_the_entry_and_a_load_then_refuses_it(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_local, 53u, 0u, 0u);

    io->pcb_args.index = i;
    UdpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);

    io->pcb_args.index = i;
    UdpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
    TEST_ASSERT_EQUAL_UINT16(0u, io->info.local_port);
}

// An entry no open took is ERR everywhere: no retry opens it.
void test_an_entry_that_is_not_open_is_refused(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    io->pcb_args.index = 0u;
    UdpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
    UdpPcb.disconnect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
    UdpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    io->bind_args.index = 0u;
    io->bind_args.ip = g_local;
    io->bind_args.port = 53u;
    UdpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    io->connect_args.index = 0u;
    io->connect_args.ip = g_remote;
    io->connect_args.port = 53u;
    UdpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    io->opt_args.index = 0u;
    io->opt_args.ttl = 64u;
    UdpPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// --- bind --------------------------------------------------------------------

// RFC 768's Source Port, as given. A load reports it back with the address it belongs to.
void test_bind_reports_the_port_it_was_given(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_local, 69u, 0u, 3u);
    TEST_ASSERT_EQUAL_UINT16(69u, io->port);

    load_ok(work_a, i);
    TEST_ASSERT_EQUAL_UINT16(69u, io->info.local_port);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_local, io->info.local_ip, 4);
    TEST_ASSERT_EQUAL_UINT8(3u, io->info.netif);
}

// RFC 768: a Source Port of zero is "not used", so a bind of it asks for one. RFC 6335 sec 6 names
// the range it comes out of: "the Dynamic Ports ... from 49152-65535".
void test_bind_of_port_any_settles_in_the_rfc6335_dynamic_range(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_any, IDEMIP_UDP_PCB_PORT_ANY, 0u, 0u);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT16((uint16_t)IDEMIP_UDP_PCB_PORT_FIRST, io->port);
    TEST_ASSERT_LESS_OR_EQUAL_UINT16((uint16_t)IDEMIP_UDP_PCB_PORT_LAST, io->port);

    uint16_t settled = io->port;
    load_ok(work_a, i);
    TEST_ASSERT_EQUAL_UINT16(settled, io->info.local_port);
}

void test_two_binds_of_port_any_settle_on_different_ports(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t b = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, a, g_any, IDEMIP_UDP_PCB_PORT_ANY, 0u, 0u);
    uint16_t first = io->port;
    bind_ok(work_a, b, g_any, IDEMIP_UDP_PCB_PORT_ANY, 0u, 0u);
    TEST_ASSERT_NOT_EQUAL_UINT16(first, io->port);
}

// An endpoint another binding already carries is ERR: no retry frees it, and reported as BUSY the
// caller would spin on a port that is not coming back.
void test_bind_refuses_an_endpoint_another_binding_carries(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t b = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, a, g_local, 161u, 0u, 0u);

    io->bind_args.index = b;
    io->bind_args.ip = g_local;
    io->bind_args.port = 161u;
    io->bind_args.zone = 0u;
    io->bind_args.netif = 0u;
    UdpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_PORT_ANY, io->port);
}

// RFC 768: a Destination Port "has a meaning within the context of a particular internet destination
// address", so the same port on two addresses is two bindings.
void test_bind_admits_the_same_port_on_two_different_addresses(void)
{
    UdpPcb.clear(work_a);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t b = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, a, g_local, 161u, 0u, 0u);
    bind_ok(work_a, b, g_local2, 161u, 0u, 0u);
}

// The wild address of RFC 1122 sec 4.1.3.5 and a named one are two local endpoints on one port, and a
// find ranks them, so both binds stand.
void test_a_wildcard_and_a_named_address_are_two_bindings_of_one_port(void)
{
    UdpPcb.clear(work_a);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t b = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, a, g_any, 514u, 0u, 0u);
    bind_ok(work_a, b, g_local, 514u, 0u, 0u);
}

// Two wild binds of one port are the same endpoint, and nothing in a find separates them.
void test_two_wildcard_binds_of_one_port_are_refused(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t b = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, a, g_any, 514u, 0u, 0u);

    io->bind_args.index = b;
    io->bind_args.ip = g_any;
    io->bind_args.port = 514u;
    io->bind_args.zone = 0u;
    io->bind_args.netif = 0u;
    UdpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// One endpoint on two interfaces is two bindings; one of them pinned to none overlaps both.
void test_one_endpoint_on_two_interfaces_is_two_bindings(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t b = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t c = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, a, g_any, 68u, 0u, 1u);
    bind_ok(work_a, b, g_any, 68u, 0u, 2u);

    io->bind_args.index = c;
    io->bind_args.ip = g_any;
    io->bind_args.port = 68u;
    io->bind_args.zone = 0u;
    io->bind_args.netif = 0u;
    UdpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// Two connects to different destinations off one local endpoint are two bindings; a second connect to
// a destination another binding already names is refused.
void test_two_connects_off_one_local_endpoint_are_two_bindings(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t b = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, a, g_local, 4444u, 0u, 0u);
    connect_ok(work_a, a, g_remote, 53u);
    bind_ok(work_a, b, g_local, 4444u, 0u, 0u);
    connect_ok(work_a, b, g_remote2, 53u);

    uint16_t c = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, c, g_local, 4444u, 0u, 0u);
    io->connect_args.index = c;
    io->connect_args.ip = g_remote;
    io->connect_args.port = 53u;
    io->connect_args.zone = 0u;
    io->connect_args.netif = 0u;
    UdpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// A version-4 binding and a version-6 one share no address space, so they share no port.
void test_two_versions_do_not_conflict_on_one_port(void)
{
    UdpPcb.clear(work_a);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t b = open_binding(work_a, 6u, IDEMIP_FALSE);
    bind_ok(work_a, a, g_local, 546u, 0u, 0u);
    bind_ok(work_a, b, g_v6_a, 546u, 0u, 0u);
}

// --- connect and disconnect --------------------------------------------------

void test_connect_sets_the_remote_pair(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_local, 1024u, 0u, 0u);
    connect_ok(work_a, i, g_remote, 53u);

    load_ok(work_a, i);
    TEST_ASSERT_TRUE(io->info.connected);
    TEST_ASSERT_EQUAL_UINT16(53u, io->info.remote_port);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_remote, io->info.remote_ip, 4);
    TEST_ASSERT_EQUAL_UINT16(1024u, io->info.local_port);
}

// RFC 768 gives the "not used, a value of zero" reading to the Source Port alone. A Destination Port
// of zero names no port, and no retry changes the operand, so it is ERR.
void test_connect_refuses_a_destination_port_of_zero(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    io->connect_args.index = i;
    io->connect_args.ip = g_remote;
    io->connect_args.port = IDEMIP_UDP_PCB_PORT_ANY;
    UdpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    load_ok(work_a, i);
    TEST_ASSERT_FALSE(io->info.connected);
}

// RFC 4291 sec 2.5.2: the unspecified address "must not be used as the destination address of IPv6
// packets". RFC 1122 sec 3.2.1.3 gives { 0, 0 } the same reading over version 4.
void test_connect_refuses_an_unspecified_destination_address(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    io->connect_args.index = i;
    io->connect_args.ip = g_any;
    io->connect_args.port = 53u;
    UdpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    load_ok(work_a, i);
    TEST_ASSERT_FALSE(io->info.connected);
}

void test_disconnect_clears_the_remote_pair_and_keeps_the_local_one(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_local, 1025u, 0u, 7u);
    connect_ok(work_a, i, g_remote, 53u);

    io->pcb_args.index = i;
    UdpPcb.disconnect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);

    load_ok(work_a, i);
    TEST_ASSERT_FALSE(io->info.connected);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_PORT_ANY, io->info.remote_port);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_any, io->info.remote_ip, IDEMIP_UDP_PCB_ADDR_BYTES);
    TEST_ASSERT_EQUAL_UINT16(1025u, io->info.local_port);
    TEST_ASSERT_EQUAL_UINT8(7u, io->info.netif);
}

// --- set_opts ----------------------------------------------------------------

// RFC 1122 sec 4.1.4: "An application-layer program MUST be able to set the TTL and TOS values".
// RFC 1112 sec 6.1 adds the multicast time-to-live and the outgoing interface.
void test_set_opts_stores_the_rfc1122_mechanisms(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    io->opt_args.index = i;
    io->opt_args.tos = 0xB8u;
    io->opt_args.ttl = 64u;
    io->opt_args.mcast_ttl = 32u;
    io->opt_args.mcast_netif = 2u;
    io->opt_args.flags = 0x01u;
    io->opt_args.cksum_len_tx = 0u;
    io->opt_args.cksum_len_rx = 0u;
    UdpPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);

    load_ok(work_a, i);
    TEST_ASSERT_EQUAL_HEX8(0xB8u, io->info.tos);
    TEST_ASSERT_EQUAL_UINT8(64u, io->info.ttl);
    TEST_ASSERT_EQUAL_UINT8(32u, io->info.mcast_ttl);
    TEST_ASSERT_EQUAL_UINT8(2u, io->info.mcast_netif);
    TEST_ASSERT_EQUAL_HEX8(0x01u, io->info.flags);
}

// RFC 1122 sec 3.2.1.7: "A host MUST NOT send a datagram with a Time-to-Live (TTL) value of zero."
void test_set_opts_refuses_a_time_to_live_of_zero(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    io->opt_args.index = i;
    io->opt_args.ttl = 0u;
    io->opt_args.tos = 0u;
    io->opt_args.mcast_ttl = 1u;
    io->opt_args.mcast_netif = 0u;
    io->opt_args.flags = 0u;
    io->opt_args.cksum_len_tx = 0u;
    io->opt_args.cksum_len_rx = 0u;
    UdpPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    load_ok(work_a, i);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_IP_DEFAULT_TTL, io->info.ttl);
}

// RFC 3828 sec 3.1: "the value of the Checksum Coverage field MUST be either 0 or at least 8".
void test_set_opts_refuses_a_coverage_of_one_through_seven(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_TRUE);
    for (uint16_t cov = 1u; cov < 8u; cov++)
    {
        io->opt_args.index = i;
        io->opt_args.ttl = 64u;
        io->opt_args.mcast_ttl = 1u;
        io->opt_args.tos = 0u;
        io->opt_args.mcast_netif = 0u;
        io->opt_args.flags = 0u;
        io->opt_args.cksum_len_tx = cov;
        io->opt_args.cksum_len_rx = 0u;
        UdpPcb.set_opts(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "a Checksum Coverage of 1 to 7 was accepted");

        io->opt_args.cksum_len_tx = 0u;
        io->opt_args.cksum_len_rx = cov;
        UdpPcb.set_opts(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "a Checksum Coverage of 1 to 7 was accepted");
    }
}

// Eight is the header RFC 3828 sec 3.1 says "MUST always be covered"; zero is the whole packet.
void test_set_opts_admits_a_coverage_of_zero_and_eight_on_a_lite_binding(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_TRUE);
    io->opt_args.index = i;
    io->opt_args.ttl = 64u;
    io->opt_args.mcast_ttl = 1u;
    io->opt_args.tos = 0u;
    io->opt_args.mcast_netif = 0u;
    io->opt_args.flags = 0u;
    io->opt_args.cksum_len_tx = (uint16_t)IDEMIP_UDPLITE_COV_MIN;
    io->opt_args.cksum_len_rx = (uint16_t)IDEMIP_UDPLITE_COV_ALL;
    UdpPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);

    load_ok(work_a, i);
    TEST_ASSERT_EQUAL_UINT16(8u, io->info.cksum_len_tx);
    TEST_ASSERT_EQUAL_UINT16(0u, io->info.cksum_len_rx);
}

// RFC 768 carries a Length in the octets RFC 3828 sec 3 replaces with a Checksum Coverage, so a
// binding that is not UDP-Lite has no coverage to set.
void test_set_opts_refuses_a_coverage_on_a_binding_that_is_not_lite(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    io->opt_args.index = i;
    io->opt_args.ttl = 64u;
    io->opt_args.mcast_ttl = 1u;
    io->opt_args.tos = 0u;
    io->opt_args.mcast_netif = 0u;
    io->opt_args.flags = 0u;
    io->opt_args.cksum_len_tx = 8u;
    io->opt_args.cksum_len_rx = 0u;
    UdpPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// --- find: the demultiplex ---------------------------------------------------

void test_find_delivers_to_the_only_binding(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_local, 69u, 0u, 0u);

    set_datagram(work_a, 4u, g_local, 69u, g_remote, 32000u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(i, io->index);
}

// RFC 1122 sec 4.1.3.5 has an application either name a local address or leave it unspecified. The
// named one is the more specific binding, so it takes the datagram.
void test_find_prefers_a_specific_local_address_over_the_wildcard(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t wild = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t spec = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, wild, g_any, 123u, 0u, 0u);
    bind_ok(work_a, spec, g_local, 123u, 0u, 0u);

    set_datagram(work_a, 4u, g_local, 123u, g_remote, 40000u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(spec, io->index);

    // A destination the specific binding does not name still reaches the wild one.
    set_datagram(work_a, 4u, g_local2, 123u, g_remote, 40000u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(wild, io->index);
}

// A connect names the RFC 768 Destination Port and the address it belongs to, which is two more
// constraints than the local pair, so a connected binding is the more specific one.
void test_find_prefers_a_connected_binding_over_an_unconnected_one(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t open_pcb = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t conn_pcb = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, conn_pcb, g_local, 500u, 0u, 0u);
    connect_ok(work_a, conn_pcb, g_remote, 4500u);
    bind_ok(work_a, open_pcb, g_local, 500u, 0u, 0u);

    set_datagram(work_a, 4u, g_local, 500u, g_remote, 4500u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(conn_pcb, io->index);
}

// A connected binding takes only the source its connect named. Another source falls to the
// unconnected binding on the same port.
void test_find_passes_over_a_connected_binding_whose_remote_pair_differs(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t open_pcb = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t conn_pcb = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, conn_pcb, g_local, 500u, 0u, 0u);
    connect_ok(work_a, conn_pcb, g_remote, 4500u);
    bind_ok(work_a, open_pcb, g_local, 500u, 0u, 0u);

    // Same source address, another Source Port.
    set_datagram(work_a, 4u, g_local, 500u, g_remote, 4501u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(open_pcb, io->index);

    // Same Source Port, another source address.
    set_datagram(work_a, 4u, g_local, 500u, g_remote2, 4500u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(open_pcb, io->index);
}

// No binding is ERR, not BUSY: nothing frees later, and RFC 1122 sec 4.1.3.1 makes it the case where
// "UDP SHOULD send an ICMP Port Unreachable message".
void test_find_reports_no_binding_when_the_port_is_unbound(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_local, 69u, 0u, 0u);

    set_datagram(work_a, 4u, g_local, 70u, g_remote, 32000u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_NONE, io->index);
}

// RFC 768 reads a Source Port of zero as "not used", so an open entry no bind has named is not a
// receive port and no datagram reaches it.
void test_find_passes_over_an_open_entry_that_was_never_bound(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    (void)open_binding(work_a, 4u, IDEMIP_FALSE);

    set_datagram(work_a, 4u, g_local, IDEMIP_UDP_PCB_PORT_ANY, g_remote, 32000u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_NONE, io->index);
}

// A binding pinned to an interface takes only what arrived on it; one pinned to none takes either.
void test_find_honors_the_interface_a_binding_is_pinned_to(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_any, 68u, 0u, 2u);

    set_datagram(work_a, 4u, g_local, 68u, g_remote, 67u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    set_datagram(work_a, 4u, g_local, 68u, g_remote, 67u, 0u, 2u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(i, io->index);
}

// RFC 3828 sec 3.1: "A UDP-Lite packet with a Checksum Coverage value of 1 to 7 MUST be discarded by
// the receiver."
void test_find_discards_a_coverage_of_one_through_seven(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_TRUE);
    bind_ok(work_a, i, g_any, 5004u, 0u, 0u);

    for (uint16_t cov = 1u; cov < 8u; cov++)
    {
        set_datagram(work_a, 4u, g_local, 5004u, g_remote, 40000u, cov, 1u);
        UdpPcb.find(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, io->status, "a Checksum Coverage of 1 to 7 was delivered");
        TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_NONE, io->index);
    }

    set_datagram(work_a, 4u, g_local, 5004u, g_remote, 40000u, 8u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(i, io->index);
}

// RFC 3828 sec 3.3: an application may "block delivery of packets with coverage values less than a
// value provided by the application". A coverage of zero is the whole packet (sec 3.1), so it always
// meets the minimum.
void test_find_blocks_a_coverage_under_the_bindings_minimum(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_TRUE);
    bind_ok(work_a, i, g_any, 5006u, 0u, 0u);
    io->opt_args.index = i;
    io->opt_args.ttl = 64u;
    io->opt_args.mcast_ttl = 1u;
    io->opt_args.tos = 0u;
    io->opt_args.mcast_netif = 0u;
    io->opt_args.flags = 0u;
    io->opt_args.cksum_len_tx = 0u;
    io->opt_args.cksum_len_rx = 16u;
    UdpPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);

    set_datagram(work_a, 4u, g_local, 5006u, g_remote, 40000u, 8u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    set_datagram(work_a, 4u, g_local, 5006u, g_remote, 40000u, 16u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);

    set_datagram(work_a, 4u, g_local, 5006u, g_remote, 40000u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(i, io->index);
}

// RFC 3828 sec 7 gives UDP-Lite protocol 136, its own protocol beside RFC 768's 17, so a partially
// covered datagram is not an RFC 768 binding's.
void test_find_keeps_a_partial_coverage_off_a_binding_that_is_not_lite(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_any, 5008u, 0u, 0u);

    set_datagram(work_a, 4u, g_local, 5008u, g_remote, 40000u, 8u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    set_datagram(work_a, 4u, g_local, 5008u, g_remote, 40000u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(i, io->index);
}

// An RFC 791 sec 3.1 address is four octets, so the twelve after it are no part of the compare and
// no part of what a bind stored.
void test_find_compares_four_octets_for_version_4(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_local_tail, 7u, 0u, 0u);

    load_ok(work_a, i);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_local, io->info.local_ip, IDEMIP_UDP_PCB_ADDR_BYTES);

    set_datagram(work_a, 4u, g_local, 7u, g_remote, 40000u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(i, io->index);

    set_datagram(work_a, 4u, g_local2, 7u, g_remote, 40000u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// An RFC 4291 sec 2 address is sixteen octets. Two that differ in the last one are two addresses.
void test_find_compares_sixteen_octets_for_version_6(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 6u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_v6_a, 546u, 0u, 0u);

    set_datagram(work_a, 6u, g_v6_a, 546u, g_v6_r, 547u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(i, io->index);

    set_datagram(work_a, 6u, g_v6_b, 546u, g_v6_r, 547u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// RFC 4007 sec 6 has "all internal uses of an address to be qualified by a zone index", so the same
// octets in two zones are two local endpoints.
void test_find_separates_two_zones_of_one_address(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t one = open_binding(work_a, 6u, IDEMIP_FALSE);
    uint16_t two = open_binding(work_a, 6u, IDEMIP_FALSE);
    bind_ok(work_a, one, g_v6_a, 5353u, 1u, 0u);
    bind_ok(work_a, two, g_v6_a, 5353u, 2u, 0u);

    set_datagram(work_a, 6u, g_v6_a, 5353u, g_v6_r, 5353u, 0u, 1u);
    io->find_args.local_zone = 2u;
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(two, io->index);

    io->find_args.local_zone = 1u;
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(one, io->index);

    io->find_args.local_zone = 3u;
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// A version-6 datagram is no version-4 binding's.
void test_find_refuses_a_version_the_binding_does_not_carry(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_any, 5060u, 0u, 0u);

    set_datagram(work_a, 6u, g_v6_a, 5060u, g_v6_r, 5060u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    // A version that is neither is refused before the walk.
    set_datagram(work_a, 5u, g_local, 5060u, g_remote, 5060u, 0u, 1u);
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_UDP_PCB_NONE, io->index);
}

// The same call on the same bytes reports the same binding.
void test_find_repeats(void)
{
    UdpPcb.clear(work_a);
    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(work_a);
    uint16_t i = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, i, g_local, 161u, 0u, 0u);

    set_datagram(work_a, 4u, g_local, 161u, g_remote, 40000u, 0u, 1u);
    UdpPcb.find(work_a);
    uint16_t first = io->index;
    UdpPcb.find(work_a);
    TEST_ASSERT_EQUAL_UINT16(first, io->index);
    TEST_ASSERT_EQUAL_UINT16(i, first);
}

// A table is a borrow, so a binding in one is no binding in the other, and a find interleaved on the
// second cannot change what the first reports.
void test_a_find_is_a_function_of_its_borrow_alone(void)
{
    UdpPcb.clear(work_a);
    UdpPcb.clear(work_b);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    bind_ok(work_a, a, g_local, 161u, 0u, 0u);
    uint16_t b0 = open_binding(work_b, 4u, IDEMIP_FALSE);
    uint16_t b1 = open_binding(work_b, 4u, IDEMIP_FALSE);
    bind_ok(work_b, b1, g_local, 161u, 0u, 0u);
    (void)b0;

    set_datagram(work_a, 4u, g_local, 161u, g_remote, 40000u, 0u, 1u);
    set_datagram(work_b, 4u, g_local, 161u, g_remote, 40000u, 0u, 1u);

    UdpPcb.find(work_a);
    uint16_t first = IDEMIP_UDP_PCB_IO(work_a)->index;
    UdpPcb.find(work_b);
    UdpPcb.find(work_a);

    TEST_ASSERT_EQUAL_UINT16(a, first);
    TEST_ASSERT_EQUAL_UINT16(first, IDEMIP_UDP_PCB_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(b1, IDEMIP_UDP_PCB_IO(work_b)->index);
    TEST_ASSERT_NOT_EQUAL_UINT16(IDEMIP_UDP_PCB_IO(work_a)->index, IDEMIP_UDP_PCB_IO(work_b)->index);
}

// A bind in one table leaves the other's ports free.
void test_two_tables_do_not_share_a_port(void)
{
    UdpPcb.clear(work_a);
    UdpPcb.clear(work_b);
    uint16_t a = open_binding(work_a, 4u, IDEMIP_FALSE);
    uint16_t b = open_binding(work_b, 4u, IDEMIP_FALSE);
    bind_ok(work_a, a, g_local, 161u, 0u, 0u);
    bind_ok(work_b, b, g_local, 161u, 0u, 0u);
}
