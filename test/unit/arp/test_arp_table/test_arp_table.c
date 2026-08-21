// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for arp_table. The first half tests the CONTRACT:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. a canary past IDEMIP_ARP_BORROW is intact after every case
//   5. the published offsets are ordered, sized and non-overlapping
//   6. clear leaves both tables zeroed, and a borrow clear has not run on is refused
//
// The second half tests the RFC 826 "Packet Reception" algorithm, the RFC 1122 sec 2.3.2.1 cache
// timeout and flood limit, and the RFC 1122 sec 2.3.2.2 packet queue. RFC 826 prints no numeric
// vectors: "An Example" names machines X and Y with symbolic EA(X), EA(Y), IPA(X), IPA(Y) and
// ET(IP), so the cases below play that example out with addresses of the suite's own choosing and
// assert the properties the text states, quoted at each case.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/arp/arp_table.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
#define DIRT 0xCCu
static _Alignas(8) uint8_t work_a[IDEMIP_ARP_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_ARP_BORROW + 16];

static const uint8_t g_sha[IDEMIP_ARP_HLN_ETHERNET] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t g_packet[IDEMIP_ARP_LEN];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_ARP_BORROW, CANARY, cap - IDEMIP_ARP_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_ARP_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_ARP_BORROW");
    }
}

// Every byte the two tables span, so a case can dirty them and see clear take them back.
static void dirty_tables(uint8_t *w)
{
    memset(w + IDEMIP_ARP_OFF_TAB, DIRT, (size_t)IDEMIP_ARP_BORROW - (size_t)IDEMIP_ARP_OFF_TAB);
}

static void assert_tables_zero(const uint8_t *w)
{
    for (size_t i = IDEMIP_ARP_OFF_TAB; i < (size_t)IDEMIP_ARP_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, w[i], "clear left a byte of the tables set");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_packet, 0, sizeof g_packet);
    idemip_arp_build_request(g_packet, g_sha, 0x0A000001u, 0x0A000002u);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    ArpTable.clear(NULL);
    ArpTable.add(NULL);
    ArpTable.find(NULL);
    ArpTable.remove(NULL);
    ArpTable.input(NULL);
    ArpTable.queue(NULL);
    ArpTable.dequeue(NULL);
    ArpTable.tick(NULL);
    TEST_PASS();
}

// The borrow IS the table, and the operand block is in it, so two tables share no byte at all. This
// is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    ArpTable.clear(work_a);
    ArpTable.clear(work_b);

    IDEMIP_ARP_IO(work_a)->add_args.pro = IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(work_a)->add_args.spa = 0x0A000001u;
    IDEMIP_ARP_IO(work_a)->add_args.sha = g_sha;
    IDEMIP_ARP_IO(work_a)->add_args.netif = 0u;
    IDEMIP_ARP_IO(work_a)->now_ms = 1000u;

    IDEMIP_ARP_IO(work_b)->add_args.pro = IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(work_b)->add_args.spa = 0x0A000002u;
    IDEMIP_ARP_IO(work_b)->add_args.sha = NULL;
    IDEMIP_ARP_IO(work_b)->add_args.netif = 1u;
    IDEMIP_ARP_IO(work_b)->now_ms = 2000u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_HEX32(0x0A000001u, IDEMIP_ARP_IO(work_a)->add_args.spa);
    TEST_ASSERT_EQUAL_PTR(g_sha, IDEMIP_ARP_IO(work_a)->add_args.sha);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ARP_IO(work_a)->add_args.netif);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_ARP_IO(work_a)->now_ms);

    // And a call on b leaves a's operands as they were.
    ArpTable.add(work_b);
    TEST_ASSERT_EQUAL_HEX32(0x0A000001u, IDEMIP_ARP_IO(work_a)->add_args.spa);
    TEST_ASSERT_EQUAL_PTR(g_sha, IDEMIP_ARP_IO(work_a)->add_args.sha);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_ARP_IO(work_a)->now_ms);
}

// clear writes every byte of one borrow's context and tables, so it is the widest write this module
// makes. It still reaches no byte of the other borrow.
void test_clear_on_one_borrow_leaves_the_other_alone(void)
{
    dirty_tables(work_b);
    ArpTable.clear(work_a);

    for (size_t i = IDEMIP_ARP_OFF_TAB; i < (size_t)IDEMIP_ARP_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(DIRT, work_b[i], "clear on one borrow reached into the other");
    }
    assert_tables_zero(work_a);
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    ArpTable.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ARP_IO(work_a)->status);
}

// Every row and every hold is the zero state, so a cleared table holds nothing.
void test_clear_zeroes_the_tables(void)
{
    dirty_tables(work_a);
    ArpTable.clear(work_a);
    assert_tables_zero(work_a);
}

// The operand block is the caller's. clear takes the context and the tables and leaves the operands
// where the caller put them.
void test_clear_leaves_the_operand_block_alone(void)
{
    IDEMIP_ARP_IO(work_a)->find_args.spa = 0x0A0000FEu;
    IDEMIP_ARP_IO(work_a)->find_args.pro = IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(work_a)->now_ms = 4242u;
    ArpTable.clear(work_a);
    TEST_ASSERT_EQUAL_HEX32(0x0A0000FEu, IDEMIP_ARP_IO(work_a)->find_args.spa);
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ARP_PRO_IPV4, IDEMIP_ARP_IO(work_a)->find_args.pro);
    TEST_ASSERT_EQUAL_UINT32(4242u, IDEMIP_ARP_IO(work_a)->now_ms);
}

// A zeroed borrow is not an empty table: every list link in it reads as row zero rather than as
// IDEMIP_ARP_INDEX_NONE, so an entry that has not seen clear must refuse rather than walk it.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_ARP_IO(work_a)->add_args.sha = g_sha;
    IDEMIP_ARP_IO(work_a)->input_args.packet = g_packet;

    ArpTable.add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.queue(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.dequeue(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    ArpTable.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
}

// An entry that found nothing says so with the published terminator, not with row zero.
void test_a_refused_call_reports_no_row(void)
{
    ArpTable.find(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ARP_INDEX_NONE, IDEMIP_ARP_IO(work_a)->index);
    TEST_ASSERT_NULL(IDEMIP_ARP_IO(work_a)->mac);
}

// --- the published map -------------------------------------------------------

// The map is public so a reader can see where every region sits. These are the claims it makes.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ARP_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(sizeof(ArpTableIo), (size_t)IDEMIP_ARP_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_ARP_OFF_CTX < (size_t)IDEMIP_ARP_OFF_TAB,
                             "the context must sit between the operand block and the rows");
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_ARP_OFF_TAB + (IDEMIP_ARP_ENTRIES << IDEMIP_ARP_ENTRY_SHIFT),
                             (size_t)IDEMIP_ARP_OFF_PENDING);
}

void test_the_borrow_covers_the_published_map(void)
{
    size_t end = (size_t)IDEMIP_ARP_OFF_PENDING + (IDEMIP_ARP_PENDING << IDEMIP_ARP_PENDING_ENTRY_SHIFT);
    TEST_ASSERT_TRUE_MESSAGE(end <= (size_t)IDEMIP_ARP_BORROW, "IDEMIP_ARP_BORROW is short of the map");
}

// An index is one octet, and the terminator is one of its values.
void test_a_row_index_fits_the_published_terminator(void)
{
    TEST_ASSERT_TRUE(IDEMIP_ARP_ENTRIES < IDEMIP_ARP_INDEX_NONE);
    TEST_ASSERT_TRUE(IDEMIP_ARP_PENDING < IDEMIP_ARP_INDEX_NONE);
}

// Each table starts on IDEMIP_ALIGN, so row i is reachable at (i << SHIFT) from the borrow the caller
// took at that alignment.
void test_every_region_starts_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ARP_OFF_TAB & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_ARP_OFF_PENDING & (IDEMIP_ALIGN - 1u));
}

// =============================================================================
// RFC 826 "Packet Reception", RFC 1122 sec 2.3.2.1 and sec 2.3.2.2
// =============================================================================

// RFC 826 "An Example": machines X and Y on one 10Mbit cable, with Ethernet addresses EA(X) and EA(Y)
// and DOD Internet addresses IPA(X) and IPA(Y). Z is a third station, for the packets that are for
// neither end. ET(IP) is IDEMIP_ARP_PRO_IPV4.
#define IPA_X 0x0A000001u
#define IPA_Y 0x0A000002u
#define IPA_Z 0x0A000003u
// A run of addresses that collides with none of the three, for filling the table.
#define FILLER 0x0A000100u
static const uint8_t EA_X[IDEMIP_ARP_HLN_ETHERNET] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t EA_Y[IDEMIP_ARP_HLN_ETHERNET] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
static const uint8_t EA_Z[IDEMIP_ARP_HLN_ETHERNET] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};

// IDEMIP_ARP_MAXAGE_S and IDEMIP_ARP_MAXPENDING_S, in the milliseconds every deadline is held in.
#define MAXAGE_MS ((uint32_t)IDEMIP_ARP_MAXAGE_S * 1000u)
#define MAXPENDING_MS ((uint32_t)IDEMIP_ARP_MAXPENDING_S * 1000u)

// RFC 1122 sec 2.3.2.1: "The recommended maximum rate is 1 per second per destination."
#define REQUEST_MIN_MS 1000u

static uint8_t pkt[IDEMIP_ARP_LEN];

static void ready_at(uint8_t *w, uint32_t now)
{
    ArpTable.clear(w);
    IDEMIP_ARP_IO(w)->now_ms = now;
}

static IdemIpStatus add_at(uint8_t *w, uint32_t now, uint32_t spa, const uint8_t *sha, uint8_t netif)
{
    IDEMIP_ARP_IO(w)->now_ms = now;
    IDEMIP_ARP_IO(w)->add_args.pro = IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(w)->add_args.spa = spa;
    IDEMIP_ARP_IO(w)->add_args.sha = sha;
    IDEMIP_ARP_IO(w)->add_args.netif = netif;
    ArpTable.add(w);
    return IDEMIP_ARP_IO(w)->status;
}

static IdemIpStatus find_ip(uint8_t *w, uint32_t spa)
{
    IDEMIP_ARP_IO(w)->find_args.pro = IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(w)->find_args.spa = spa;
    ArpTable.find(w);
    return IDEMIP_ARP_IO(w)->status;
}

static IdemIpStatus remove_ip(uint8_t *w, uint32_t spa)
{
    IDEMIP_ARP_IO(w)->remove_args.pro = IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(w)->remove_args.spa = spa;
    ArpTable.remove(w);
    return IDEMIP_ARP_IO(w)->status;
}

static IdemIpStatus input_at(uint8_t *w, uint32_t now, const uint8_t *packet, uint32_t local_pa, uint8_t netif)
{
    IDEMIP_ARP_IO(w)->now_ms = now;
    IDEMIP_ARP_IO(w)->input_args.packet = packet;
    IDEMIP_ARP_IO(w)->input_args.local_pa = local_pa;
    IDEMIP_ARP_IO(w)->input_args.netif = netif;
    ArpTable.input(w);
    return IDEMIP_ARP_IO(w)->status;
}

static IdemIpStatus queue_at(uint8_t *w, uint32_t now, uint32_t ip, uint16_t desc, uint16_t len)
{
    IDEMIP_ARP_IO(w)->now_ms = now;
    IDEMIP_ARP_IO(w)->queue_args.ip = ip;
    IDEMIP_ARP_IO(w)->queue_args.desc = desc;
    IDEMIP_ARP_IO(w)->queue_args.len = len;
    ArpTable.queue(w);
    return IDEMIP_ARP_IO(w)->status;
}

static IdemIpStatus tick_at(uint8_t *w, uint32_t now)
{
    IDEMIP_ARP_IO(w)->now_ms = now;
    ArpTable.tick(w);
    return IDEMIP_ARP_IO(w)->status;
}

static IdemIpStatus dequeue_one(uint8_t *w)
{
    ArpTable.dequeue(w);
    return IDEMIP_ARP_IO(w)->status;
}

// --- add: the merge itself ---------------------------------------------------

// RFC 826 "Packet Reception": "add the triplet <protocol type, sender protocol address, sender
// hardware address> to the translation table", and find gives "the corresponding 48.bit Ethernet
// address back to the caller".
void test_add_then_find_gives_the_hardware_address_back(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Y, EA_Y, 3u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_Y));
    TEST_ASSERT_NOT_NULL(IDEMIP_ARP_IO(work_a)->mac);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(EA_Y, IDEMIP_ARP_IO(work_a)->mac, IDEMIP_ARP_HLN_ETHERNET);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ARP_STATE_STABLE, IDEMIP_ARP_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_ARP_IO(work_a)->netif);
}

// RFC 826: "Merge_flag := false. If the pair <protocol type, sender protocol address> is already in
// my translation table, update the sender hardware address field of the entry with the new
// information in the packet and set Merge_flag to true."
void test_add_reports_merge_flag_only_when_the_pair_was_already_there(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Y, EA_Y, 0u));
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->merged);
    uint8_t first = IDEMIP_ARP_IO(work_a)->index;

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 2000u, IPA_Y, EA_Y, 0u));
    TEST_ASSERT_TRUE(IDEMIP_ARP_IO(work_a)->merged);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(first, IDEMIP_ARP_IO(work_a)->index, "a merge took a second row");
}

// RFC 826 "Packet Reception": "if an entry already exists for the <protocol type, sender protocol
// address> pair, then the new hardware address supersedes the old one."
void test_a_new_hardware_address_supersedes_the_old_one(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Y, EA_Y, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 2000u, IPA_Y, EA_Z, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_Y));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(EA_Z, IDEMIP_ARP_IO(work_a)->mac, IDEMIP_ARP_HLN_ETHERNET);
}

// RFC 826 asks "?Do I speak the protocol in ar$pro?" and ends processing when the answer is no. This
// end speaks IPv4, so another protocol address space is refused rather than keyed as one.
void test_add_refuses_a_protocol_this_end_does_not_speak(void)
{
    ready_at(work_a, 1000u);
    IDEMIP_ARP_IO(work_a)->add_args.pro = 0x0806u;
    IDEMIP_ARP_IO(work_a)->add_args.spa = IPA_Y;
    IDEMIP_ARP_IO(work_a)->add_args.sha = EA_Y;
    ArpTable.add(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ARP_INDEX_NONE, IDEMIP_ARP_IO(work_a)->index);
}

// RFC 1122 sec 3.2.1.3 (a) on { 0, 0 }: "This host on this network. MUST NOT be sent, except as a
// source address as part of an initialization procedure by which the host learns its own IP address."
// A row keyed on it names no host, and RFC 5227 sec 2.1.1 sends exactly that address to keep it out
// of caches.
void test_add_refuses_an_all_zero_sender_protocol_address(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, add_at(work_a, 1000u, 0u, EA_Y, 0u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ARP_INDEX_NONE, IDEMIP_ARP_IO(work_a)->index);
}

// There is no triplet without ar$sha, and a retry with the same operands has none either.
void test_add_refuses_a_null_hardware_address(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, add_at(work_a, 1000u, IPA_Y, NULL, 0u));
}

// --- find --------------------------------------------------------------------

// RFC 826 "Packet Generation": the module "tries to find this pair in a table ... If it does not, it
// probably informs the caller that it is throwing the packet away". Calling find again cannot put the
// pair there, so this is ERR and not BUSY: a caller spinning on it would never make progress. The
// caller queues the frame instead, which opens the row.
void test_find_on_a_pair_that_is_not_in_the_table_is_refused(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find_ip(work_a, IPA_Y));
    TEST_ASSERT_NULL(IDEMIP_ARP_IO(work_a)->mac);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ARP_INDEX_NONE, IDEMIP_ARP_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ARP_STATE_FREE, IDEMIP_ARP_IO(work_a)->state);
}

// RFC 826 on ar$tha in a REQUEST: "It does not set ar$tha to anything in particular, because it is
// this value that it is trying to determine." A row in that state has no address to give back, and
// the REPLY that completes it can land on a later tick, so this is BUSY.
void test_find_is_busy_while_the_row_is_still_waiting_for_the_hardware_address(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 7u, 64u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, find_ip(work_a, IPA_Y));
    TEST_ASSERT_NULL(IDEMIP_ARP_IO(work_a)->mac);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ARP_STATE_PENDING, IDEMIP_ARP_IO(work_a)->state);
}

// RFC 1122 sec 2.3.2.1 mechanism (1): "Periodically time out cache entries, even if they are in use.
// Note that this timeout should be restarted when the cache entry is 'refreshed' (by observing the
// source fields, regardless of target address, of an ARP broadcast from the system in question)."
// Looking a row up is not that observation, so find must not restart the timeout.
void test_find_does_not_restart_the_cache_timeout(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Y, EA_Y, 0u));
    // The clock advances across the lookups. Without this the finds all run at the millisecond the
    // row was added, and a find that did restart the timeout would write the same value back.
    for (uint32_t t = 1000u; t < 1000u + MAXAGE_MS; t += MAXAGE_MS / 4u)
    {
        IDEMIP_ARP_IO(work_a)->now_ms = t;
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_Y));
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, 1000u + MAXAGE_MS));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find_ip(work_a, IPA_Y), "a looked-up row outlived IDEMIP_ARP_MAXAGE_S");
}

// --- the RFC 826 reception algorithm ----------------------------------------

// RFC 826 "An Example", machine Y: "Machine Y gets this packet, and determines that it understands the
// hardware type (Ethernet), that it speaks the indicated protocol (Internet) and that the packet is
// for it ((ar$tpa)=IPA(Y)). It enters ... the information that <ET(IP), IPA(X)> maps to EA(X). It then
// notices that it is a request".
void test_a_request_for_this_end_is_added_and_owes_a_reply(void)
{
    ready_at(work_a, 1000u);
    idemip_arp_build_request(pkt, EA_X, IPA_X, IPA_Y);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Y, 2u));
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ARP_IO(work_a)->merged, "nothing was in the table to merge");
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_ARP_IO(work_a)->reply_owed, "a REQUEST for this end owes a REPLY");

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_X));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(EA_X, IDEMIP_ARP_IO(work_a)->mac, IDEMIP_ARP_HLN_ETHERNET);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_ARP_IO(work_a)->netif);
}

// RFC 1812 sec 3.3.2: "A router MUST not believe any ARP reply that claims that the Link Layer
// address of another host or router is a broadcast or multicast address." Neither the broadcast
// address nor a multicast group address may be keyed into the table or handed back as a next hop.
void test_a_group_sender_hardware_address_is_not_believed(void)
{
    static const uint8_t EA_BCAST[IDEMIP_ARP_HLN_ETHERNET] = {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu};
    static const uint8_t EA_MCAST[IDEMIP_ARP_HLN_ETHERNET] = {0x01u, 0x00u, 0x5Eu, 0x7Fu, 0x00u, 0x01u};

    // Through ArpTable.input, as a REPLY addressed to this end.
    ready_at(work_a, 1000u);
    idemip_arp_build_reply(pkt, EA_BCAST, IPA_X, EA_Y, IPA_Y);
    (void)input_at(work_a, 1000u, pkt, IPA_Y, 0u);
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->merged);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find_ip(work_a, IPA_X), "a broadcast ar$sha was installed as a next hop");

    // And as an unsolicited REQUEST, which merges before the opcode is read.
    ready_at(work_a, 1000u);
    idemip_arp_build_request(pkt, EA_MCAST, IPA_X, IPA_Y);
    (void)input_at(work_a, 1000u, pkt, IPA_Y, 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find_ip(work_a, IPA_X), "a multicast ar$sha was installed as a next hop");

    // Through ArpTable.add, which is the same learn.
    ready_at(work_a, 1000u);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_X, EA_BCAST, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find_ip(work_a, IPA_X));

    // The positive control: the same call with a unicast address is believed.
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_X, EA_X, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_X));

    // A row that already holds a unicast address is not overwritten by a group one either.
    idemip_arp_build_reply(pkt, EA_BCAST, IPA_X, EA_Y, IPA_Y);
    (void)input_at(work_a, 1000u, pkt, IPA_Y, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_X));
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(EA_X, IDEMIP_ARP_IO(work_a)->mac, IDEMIP_ARP_HLN_ETHERNET,
                                          "a broadcast ar$sha overwrote a known unicast row");
}

// RFC 5227 sec 2.4: an ARP packet whose sender IP address is this end's own is a conflicting ARP
// packet. It is reported to the caller, keyed into no row, and owed no REPLY: sec 2.5 says the REPLY
// obligation is for "an ARP Request, that's not a conflicting ARP packet as described above in
// Section 2.4".
void test_a_sender_claiming_this_ends_address_is_a_conflict(void)
{
    ready_at(work_a, 1000u);
    idemip_arp_build_request(pkt, EA_X, IPA_Y, IPA_Y); // another station claims IPA_Y, which is ours
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Y, 0u));
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_ARP_IO(work_a)->conflict, "a station claiming our address is a conflict");
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ARP_IO(work_a)->reply_owed, "a conflicting packet is owed no REPLY");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find_ip(work_a, IPA_Y),
                                  "this end's own address was keyed to a foreign hardware address");

    // A REPLY carrying the same claim is a conflict too.
    ready_at(work_a, 1000u);
    idemip_arp_build_reply(pkt, EA_X, IPA_Y, EA_Y, IPA_Y);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Y, 0u));
    TEST_ASSERT_TRUE(IDEMIP_ARP_IO(work_a)->conflict);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find_ip(work_a, IPA_Y));

    // The positive control: the same REQUEST from a different sender is not a conflict and is owed
    // a REPLY, and its sender is learned.
    ready_at(work_a, 1000u);
    idemip_arp_build_request(pkt, EA_X, IPA_X, IPA_Y);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Y, 0u));
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->conflict);
    TEST_ASSERT_TRUE(IDEMIP_ARP_IO(work_a)->reply_owed);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_X));
}

// RFC 826: "If Merge_flag is false, add the triplet ... to the translation table" sits under
// "?Am I the target protocol address? Yes:". A REQUEST between two other stations is therefore
// merged if the pair is already known and added never.
void test_a_request_for_someone_else_creates_no_entry(void)
{
    ready_at(work_a, 1000u);
    idemip_arp_build_request(pkt, EA_X, IPA_X, IPA_Z);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Y, 0u));
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->merged);
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->reply_owed);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(IDEMIP_ARP_INDEX_NONE, IDEMIP_ARP_IO(work_a)->index,
                                    "a REQUEST for a third party took a row");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find_ip(work_a, IPA_X),
                                  "a REQUEST for a third party put its sender in the table");
}

// The merge half of the same paragraph has no target test over it: "If the pair <protocol type, sender
// protocol address> is already in my translation table, update the sender hardware address field of
// the entry with the new information in the packet and set Merge_flag to true." So a packet for a
// third party still supersedes a row this end already has.
void test_a_request_for_someone_else_still_updates_a_row_that_exists(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_X, EA_Z, 0u));

    idemip_arp_build_request(pkt, EA_X, IPA_X, IPA_Z);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 2000u, pkt, IPA_Y, 0u));
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_ARP_IO(work_a)->merged, "the pair was in the table and was not merged");
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->reply_owed);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_X));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(EA_X, IDEMIP_ARP_IO(work_a)->mac, IDEMIP_ARP_HLN_ETHERNET);
}

// RFC 826: "Notice that the <protocol type, sender protocol address, sender hardware address> triplet
// is merged into the table before the opcode is looked at." A REPLY for this end lands in the table
// the same way a REQUEST does, and owes nothing back.
void test_a_reply_is_merged_before_the_opcode_is_looked_at(void)
{
    ready_at(work_a, 1000u);
    idemip_arp_build_reply(pkt, EA_Y, IPA_Y, EA_X, IPA_X);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_X, 0u));
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_ARP_IO(work_a)->reply_owed, "a REPLY owes no REPLY");
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_Y));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(EA_Y, IDEMIP_ARP_IO(work_a)->mac, IDEMIP_ARP_HLN_ETHERNET);
}

// The opcode is looked at last and only to ask "?Is the opcode ares_op$REQUEST?", so an opcode that
// is neither of RFC 826's two still merges and still owes nothing.
void test_an_unknown_opcode_still_merges_and_owes_no_reply(void)
{
    ready_at(work_a, 1000u);
    idemip_arp_build_request(pkt, EA_X, IPA_X, IPA_Y);
    idemip_wr16(pkt + IDEMIP_ARP_OFF_OP, 3u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Y, 0u));
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->reply_owed);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_X));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(EA_X, IDEMIP_ARP_IO(work_a)->mac, IDEMIP_ARP_HLN_ETHERNET);
}

// RFC 826: "?Do I have the hardware type in ar$hrd?" and "?Do I speak the protocol in ar$pro?", with
// both length checks. "Negative conditionals indicate an end of processing and a discarding of the
// packet", and the same octets read the same way on a retry, so this is ERR.
void test_a_packet_that_is_not_the_ethernet_ipv4_pairing_is_discarded(void)
{
    static const size_t off[4] = {IDEMIP_ARP_OFF_HRD, IDEMIP_ARP_OFF_PRO, IDEMIP_ARP_OFF_HLN, IDEMIP_ARP_OFF_PLN};
    for (size_t k = 0; k < 4; k++)
    {
        ready_at(work_a, 1000u);
        idemip_arp_build_request(pkt, EA_X, IPA_X, IPA_Y);
        pkt[off[k]] = (uint8_t)(pkt[off[k]] + 1u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, input_at(work_a, 1000u, pkt, IPA_Y, 0u),
                                      "a packet of another pairing was processed");
        TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->reply_owed);
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find_ip(work_a, IPA_X));
    }
}

// RFC 5227 sec 2.1.1: the 'sender IP address' of an ARP Probe "MUST be set to all zeroes; this is to
// avoid polluting ARP caches in other hosts on the same link". RFC 5227 sec 2.5 still owes it an
// answer: the duty to reply "applies equally for both standard ARP Requests with non-zero sender IP
// addresses and Probe Requests with all-zero sender IP addresses."
void test_an_arp_probe_owes_a_reply_and_pollutes_no_cache(void)
{
    ready_at(work_a, 1000u);
    idemip_arp_build_request(pkt, EA_X, 0u, IPA_Y);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Y, 0u));
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_ARP_IO(work_a)->reply_owed, "RFC 5227 sec 2.5 owes a probe a REPLY");
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->merged);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ARP_INDEX_NONE, IDEMIP_ARP_IO(work_a)->index);

    // A probe that took a row would push the next add onto a different row than the same add on a
    // table no probe ever reached.
    ready_at(work_b, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_b, 1000u, IPA_Y, EA_Y, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Y, EA_Y, 0u));
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(IDEMIP_ARP_IO(work_b)->index, IDEMIP_ARP_IO(work_a)->index,
                                    "an all-zero ar$spa took a row");
}

// RFC 1122 sec 3.2.1.3 (a) leaves { 0, 0 } naming no host, so an end without a protocol address is
// the target of nothing: the merge still runs, the add and the REPLY do not.
void test_an_end_with_no_protocol_address_is_the_target_of_nothing(void)
{
    ready_at(work_a, 1000u);
    idemip_arp_build_request(pkt, EA_X, IPA_X, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, 0u, 0u));
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->reply_owed);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find_ip(work_a, IPA_X), "an unconfigured end added a triplet");
}

// RFC 826 "An Example", played out on two borrows: X's table and Y's table. "At this point Y knows how
// to send to X, but X still doesn't know how to send to Y", and after the reply "Machine X gets the
// reply packet from Y, forms the map from <ET(IP), IPA(Y)> to EA(Y)".
void test_the_rfc826_example_end_to_end_on_two_tables(void)
{
    ready_at(work_a, 1000u); // machine Y's table
    ready_at(work_b, 1000u); // machine X's table

    // X broadcasts the REQUEST of the example: ar$sha EA(X), ar$spa IPA(X), ar$tha don't care,
    // ar$tpa IPA(Y).
    idemip_arp_build_request(pkt, EA_X, IPA_X, IPA_Y);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Y, 0u));
    TEST_ASSERT_TRUE(IDEMIP_ARP_IO(work_a)->reply_owed);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, find_ip(work_a, IPA_X), "Y did not learn how to send to X");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find_ip(work_b, IPA_Y), "X knew how to send to Y before the reply");

    // Y swaps the fields in the packet it received and sends it back.
    idemip_arp_reply_in_place(pkt, EA_Y);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_ARP_OP_REPLY, idemip_arp_op(pkt));
    TEST_ASSERT_EQUAL_HEX32(IPA_Y, idemip_arp_spa(pkt));
    TEST_ASSERT_EQUAL_HEX32(IPA_X, idemip_arp_tpa(pkt));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_b, 2000u, pkt, IPA_X, 0u));
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_b)->reply_owed);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_b, IPA_Y));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(EA_Y, IDEMIP_ARP_IO(work_b)->mac, IDEMIP_ARP_HLN_ETHERNET);
}

// --- RFC 1122 sec 2.3.2.1: the cache timeout --------------------------------

// "An implementation of the Address Resolution Protocol (ARP) MUST provide a mechanism to flush
// out-of-date cache entries", by mechanism (1) timeout here. The row survives every sweep before the
// bound and goes on the first sweep at or past it; the sweep runs once per
// IDEMIP_ARP_TMR_INTERVAL_MS, which is that flush's granularity.
void test_a_row_is_flushed_on_the_first_sweep_at_or_past_maxage(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Y, EA_Y, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, 1000u + MAXAGE_MS - 1u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, find_ip(work_a, IPA_Y), "a row went before IDEMIP_ARP_MAXAGE_S");

    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, 1000u + MAXAGE_MS - 1u + IDEMIP_ARP_TMR_INTERVAL_MS));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find_ip(work_a, IPA_Y), "a row outlived IDEMIP_ARP_MAXAGE_S");
}

// RFC 1122 sec 2.3.2.1 mechanism (1): "this timeout should be restarted when the cache entry is
// 'refreshed' (by observing the source fields, regardless of target address, of an ARP broadcast from
// the system in question)." The observation is an ARP packet from that system, whoever it was for.
void test_observing_the_source_fields_restarts_the_cache_timeout(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_X, EA_X, 0u));

    // A REQUEST from X to a third station, at almost the whole timeout later.
    idemip_arp_build_request(pkt, EA_X, IPA_X, IPA_Z);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u + MAXAGE_MS - 1u, pkt, IPA_Y, 0u));
    TEST_ASSERT_TRUE(IDEMIP_ARP_IO(work_a)->merged);

    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, 1000u + MAXAGE_MS));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, find_ip(work_a, IPA_X), "a refreshed row was aged on its old stamp");
}

// RFC 1122 sec 2.3.2.1 mechanisms (3) and (4): "If the link-layer driver detects a delivery problem,
// flush the corresponding ARP cache entry", and the higher-layer call whose "effect ... would be to
// invalidate the corresponding cache entry."
void test_remove_flushes_the_row_a_pair_names(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Y, EA_Y, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Z, EA_Z, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, remove_ip(work_a, IPA_Y));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find_ip(work_a, IPA_Y));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, find_ip(work_a, IPA_Z), "remove took a row it was not given");
}

// Nothing to flush, and no retry puts the row there.
void test_remove_of_a_pair_with_no_row_is_refused(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, remove_ip(work_a, IPA_Y));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ARP_INDEX_NONE, IDEMIP_ARP_IO(work_a)->index);
}

// --- RFC 1122 sec 2.3.2.1: the flood limit ----------------------------------

// "A mechanism to prevent ARP flooding (repeatedly sending an ARP Request for the same IP address, at
// a high rate) MUST be included. The recommended maximum rate is 1 per second per destination."
void test_the_request_rate_is_one_per_second_per_destination(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 5u, 64u));

    // The first REQUEST is due at once, and carries no descriptor.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, 1000u));
    TEST_ASSERT_EQUAL_HEX32(IPA_Y, IDEMIP_ARP_IO(work_a)->ip);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_ARP_IO(work_a)->len, "a REQUEST report carried a frame length");

    // Nothing more inside the second.
    for (uint32_t t = 1000u; t < 1000u + REQUEST_MIN_MS; t += 250u)
    {
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, tick_at(work_a, t), "a second REQUEST went inside one second");
    }

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, 1000u + REQUEST_MIN_MS));
    TEST_ASSERT_EQUAL_HEX32(IPA_Y, IDEMIP_ARP_IO(work_a)->ip);
}

// A row that has its triplet needs no REQUEST, so the sweep reports nothing.
void test_a_stable_table_asks_for_nothing(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Y, EA_Y, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, 2000u));
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_ARP_IO(work_a)->ip);
}

// RFC 826 "Related issue": "If a REPLY is not seen in a short amount of time, the entry is deleted."
// IDEMIP_ARP_MAXPENDING_S is that time, and the REQUESTs stop with the row.
void test_a_row_waiting_for_a_reply_stops_asking_after_maxpending(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 5u, 64u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, 1000u));

    // The row goes at the bound, handing its held descriptor back on the same call.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, 1000u + MAXPENDING_MS));
    TEST_ASSERT_EQUAL_UINT16(5u, IDEMIP_ARP_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_UINT16(64u, IDEMIP_ARP_IO(work_a)->len);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, tick_at(work_a, 1000u + MAXPENDING_MS),
                                  "a row past IDEMIP_ARP_MAXPENDING_S was still asking");
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find_ip(work_a, IPA_Y));
}

// --- RFC 1122 sec 2.3.2.2: the packet queue ---------------------------------

// "The link layer SHOULD save (rather than discard) at least one (the latest) packet of each set of
// packets destined to the same unresolved IP address, and transmit the saved packet when the address
// has been resolved."
void test_a_held_frame_comes_back_when_the_reply_resolves_its_address(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 9u, 74u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, dequeue_one(work_a), "an unresolved hold came back");

    idemip_arp_build_reply(pkt, EA_Y, IPA_Y, EA_X, IPA_X);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 2000u, pkt, IPA_X, 4u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, dequeue_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(9u, IDEMIP_ARP_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_UINT16(74u, IDEMIP_ARP_IO(work_a)->len);
    TEST_ASSERT_EQUAL_HEX32(IPA_Y, IDEMIP_ARP_IO(work_a)->ip);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(EA_Y, IDEMIP_ARP_IO(work_a)->mac, IDEMIP_ARP_HLN_ETHERNET);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, dequeue_one(work_a), "one hold came back twice");
}

// The holds on one row come off in the order they went on, so a stream of frames to one address keeps
// its order.
void test_holds_on_one_row_come_back_in_the_order_they_went_on(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 21u, 64u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1100u, IPA_Y, 22u, 65u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1200u, IPA_Y, 23u, 66u));

    idemip_arp_build_reply(pkt, EA_Y, IPA_Y, EA_X, IPA_X);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 2000u, pkt, IPA_X, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, dequeue_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(21u, IDEMIP_ARP_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, dequeue_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(22u, IDEMIP_ARP_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, dequeue_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(23u, IDEMIP_ARP_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, dequeue_one(work_a));
}

// Every hold taken is BUSY, because a hold frees when its row resolves or its deadline passes. The
// count is IDEMIP_ARP_PENDING, which is what IDEMIP_MAX_PINNED_FRAMES counts for this unit.
void test_a_queue_with_every_hold_taken_is_busy_and_the_retry_succeeds(void)
{
    ready_at(work_a, 1000u);
    for (uint16_t n = 0u; n < (uint16_t)IDEMIP_ARP_PENDING; n++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, (uint16_t)(30u + n), 64u));
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, queue_at(work_a, 1000u, IPA_Y, 99u, 64u),
                                  "a hold past IDEMIP_ARP_PENDING was taken");

    // A hold frees on its deadline, and the retry lands.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, 1000u + MAXPENDING_MS));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u + MAXPENDING_MS, IPA_Y, 99u, 64u));
}

// A frame whose address is resolved goes out now, so holding it would pin a descriptor for nothing and
// no retry changes that.
void test_a_queue_on_a_resolved_address_is_refused(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Y, EA_Y, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, queue_at(work_a, 1000u, IPA_Y, 8u, 64u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, dequeue_one(work_a), "a refused queue took a hold");
}

// A frame no Ethernet frame can carry (RFC 894) and a frame of no octets are both ERR, because no
// retry changes the operands.
void test_a_queue_of_an_impossible_length_is_refused(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, queue_at(work_a, 1000u, IPA_Y, 8u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, queue_at(work_a, 1000u, IPA_Y, 8u, (uint16_t)(IDEMIP_ETH_FRAME_MAX + 1u)));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, queue_at(work_a, 1000u, 0u, 8u, 64u));
}

// A hold on a row that resolved but was never dequeued still has a deadline, so a pinned descriptor
// cannot be held forever.
void test_a_hold_past_its_deadline_hands_its_descriptor_back(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 17u, 68u));
    idemip_arp_build_reply(pkt, EA_Y, IPA_Y, EA_X, IPA_X);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 2000u, pkt, IPA_X, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, 1000u + MAXPENDING_MS - 1u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, 1000u + MAXPENDING_MS));
    TEST_ASSERT_EQUAL_UINT16(17u, IDEMIP_ARP_IO(work_a)->desc);
    TEST_ASSERT_EQUAL_UINT16(68u, IDEMIP_ARP_IO(work_a)->len);
    TEST_ASSERT_EQUAL_HEX32(IPA_Y, IDEMIP_ARP_IO(work_a)->ip);

    // The row itself is stable and stays, and the hold is gone.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_Y));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, dequeue_one(work_a));
}

// A flush takes the row, and the descriptors it held come back through the sweep rather than staying
// pinned on a row that is gone.
void test_a_flush_hands_back_the_descriptors_the_row_held(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 41u, 64u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 42u, 65u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, remove_ip(work_a, IPA_Y));

    uint16_t seen = 0u;
    for (int n = 0; n < 2; n++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, 1100u));
        TEST_ASSERT_NOT_EQUAL_MESSAGE(0u, IDEMIP_ARP_IO(work_a)->len, "a flushed hold reported no frame");
        seen = (uint16_t)(seen | (uint16_t)(1u << (IDEMIP_ARP_IO(work_a)->desc - 41u)));
    }
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0x3u, seen, "a flushed row did not hand both descriptors back");
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, tick_at(work_a, 1100u));
}

// The pin protocol: every descriptor queue took comes back exactly once, whether its address resolved
// or its hold expired, so no pin outlives this unit's own bound (PLAN sec 3.5).
void test_every_pinned_descriptor_comes_back_exactly_once(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 51u, 64u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 52u, 65u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Z, 53u, 66u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Z, 54u, 67u));

    uint16_t seen = 0u;
    int back = 0;

    // IPA_Y resolves, so its two holds come back through dequeue.
    idemip_arp_build_reply(pkt, EA_Y, IPA_Y, EA_X, IPA_X);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1500u, pkt, IPA_X, 0u));
    while (dequeue_one(work_a) == IDEMIP_OK)
    {
        seen = (uint16_t)(seen | (uint16_t)(1u << (IDEMIP_ARP_IO(work_a)->desc - 51u)));
        back++;
    }

    // IPA_Z never answers, so its two come back through the sweep.
    while (tick_at(work_a, 1000u + MAXPENDING_MS) == IDEMIP_OK)
    {
        if (IDEMIP_ARP_IO(work_a)->len != 0u)
        {
            seen = (uint16_t)(seen | (uint16_t)(1u << (IDEMIP_ARP_IO(work_a)->desc - 51u)));
            back++;
        }
    }

    TEST_ASSERT_EQUAL_INT_MESSAGE(4, back, "a descriptor came back twice or not at all");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(0xFu, seen, "a pinned descriptor was never handed back");
}

// Two tables hold independently: a's holds are not b's, and neither sweep reaches the other.
void test_holds_on_two_borrows_are_independent(void)
{
    ready_at(work_a, 1000u);
    ready_at(work_b, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 61u, 64u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, dequeue_one(work_b));

    idemip_arp_build_reply(pkt, EA_Y, IPA_Y, EA_X, IPA_X);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_b, 2000u, pkt, IPA_X, 0u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, dequeue_one(work_b), "b released a hold it never took");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, dequeue_one(work_a), "b's reply resolved a's row");

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 2000u, pkt, IPA_X, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, dequeue_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(61u, IDEMIP_ARP_IO(work_a)->desc);
}

// --- the table under pressure ------------------------------------------------

// RFC 826 "Related issue": "if no packets are received from a host for a suitable length of time, the
// address resolution entry is forgotten." A table with no free row gives up the row whose triplet has
// gone longest without being seen, and keeps the rest.
void test_a_full_table_gives_up_the_row_longest_unseen(void)
{
    ready_at(work_a, 0u);
    for (uint32_t n = 0u; n < IDEMIP_ARP_ENTRIES; n++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 100u + (n * 100u), FILLER + n, EA_Y, 0u));
    }
    // Every row is taken, and the one added first has gone longest unseen.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 5000u, IPA_X, EA_X, 0u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find_ip(work_a, FILLER), "the row longest unseen survived a full table");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, find_ip(work_a, FILLER + 1u), "a newer row was given up");
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_X));
}

// A row carrying pinned holds is never given up, because its descriptors come back through the sweep
// and a row that vanished has none to report.
void test_a_row_carrying_holds_is_never_given_up(void)
{
    ready_at(work_a, 0u);
    // The oldest row is the one with a hold on it.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1u, IPA_Z, 71u, 64u));
    for (uint32_t n = 1u; n < IDEMIP_ARP_ENTRIES; n++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 100u + (n * 100u), FILLER + n, EA_Y, 0u));
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 5000u, IPA_X, EA_X, 0u));

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, find_ip(work_a, IPA_Z), "a row carrying a hold was given up");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find_ip(work_a, FILLER + 1u), "the oldest row without holds survived");
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_X));
}

// An entry is a function of its borrow alone, so the same call on the same bytes reports the same
// thing however many times it runs.
void test_a_repeated_find_reports_the_same_thing(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_Y, EA_Y, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_Y));
    uint8_t index = IDEMIP_ARP_IO(work_a)->index;
    const uint8_t *mac = IDEMIP_ARP_IO(work_a)->mac;
    for (int n = 0; n < 4; n++)
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_Y));
        TEST_ASSERT_EQUAL_UINT8(index, IDEMIP_ARP_IO(work_a)->index);
        TEST_ASSERT_EQUAL_PTR(mac, IDEMIP_ARP_IO(work_a)->mac);
    }
}

// The same packet, put in twice, leaves one row and merges the second time.
void test_the_same_packet_twice_leaves_one_row(void)
{
    ready_at(work_a, 1000u);
    idemip_arp_build_request(pkt, EA_X, IPA_X, IPA_Y);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Y, 0u));
    uint8_t first = IDEMIP_ARP_IO(work_a)->index;
    TEST_ASSERT_FALSE(IDEMIP_ARP_IO(work_a)->merged);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Y, 0u));
    TEST_ASSERT_TRUE(IDEMIP_ARP_IO(work_a)->merged);
    TEST_ASSERT_EQUAL_UINT8(first, IDEMIP_ARP_IO(work_a)->index);
}

// --- what the operands rule out ------------------------------------------------

// RFC 826's algorithm is over a <protocol type, sender protocol address> pair, and this table carries
// "the protocol in ar$pro" for IPv4 alone. A lookup naming another protocol names nothing this table
// holds, and RFC 1122 sec 3.2.1.3 makes 0.0.0.0 "this host on this network", which no neighbour
// answers for. Neither can become a row later, so both are ERR rather than a lookup that missed.
void test_a_lookup_outside_the_pair_this_table_holds_is_refused(void)
{
    ready_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, add_at(work_a, 1000u, IPA_X, EA_X, 0u));

    IDEMIP_ARP_IO(work_a)->find_args.pro = 0x86DDu;
    IDEMIP_ARP_IO(work_a)->find_args.spa = IPA_X;
    IDEMIP_ARP_IO(work_a)->now_ms = 1000u;
    ArpTable.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status,
                                  "a lookup for another protocol was answered from the IPv4 table");

    IDEMIP_ARP_IO(work_a)->find_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(work_a)->find_args.spa = 0u;
    ArpTable.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status,
                                  "a lookup for this-host-on-this-network was answered");

    IDEMIP_ARP_IO(work_a)->remove_args.pro = 0x86DDu;
    IDEMIP_ARP_IO(work_a)->remove_args.spa = IPA_X;
    ArpTable.remove(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status,
                                  "a row of another protocol was removed from the IPv4 table");

    IDEMIP_ARP_IO(work_a)->remove_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(work_a)->remove_args.spa = 0u;
    ArpTable.remove(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status,
                                  "a row for this-host-on-this-network was removed");

    // The row itself is untouched by any of the four.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find_ip(work_a, IPA_X));

    // And a reception with no packet is nothing to run the algorithm over.
    IDEMIP_ARP_IO(work_a)->input_args.packet = NULL;
    IDEMIP_ARP_IO(work_a)->input_args.local_pa = IPA_Z;
    IDEMIP_ARP_IO(work_a)->input_args.netif = 0u;
    IDEMIP_ARP_IO(work_a)->now_ms = 1000u;
    ArpTable.input(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_ARP_IO(work_a)->status,
                                  "the reception algorithm ran over no packet");
}

// RFC 1122 sec 2.3.2.2: "the link layer SHOULD save (rather than discard) at least one (the latest)
// packet of each set of packets destined to the same unresolved IP address". The saved packets of one
// address are a list, and a hold that leaves it is taken out of the list wherever it stands - the
// front of it or behind another. Which one a hold stands at is not the order it was allocated in: a
// hold freed by delivery is the next one allocated, and by then the list it joins already has a head.
void test_a_hold_is_taken_off_the_list_from_behind_its_head_as_well_as_from_the_front(void)
{
    ready_at(work_a, 1000u);

    // One hold on X and one on Y, in that order, so the first hold in the table belongs to X.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_X, 11u, 100u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 22u, 200u));

    // X answers, and its hold is delivered - which is the front of X's list and frees that hold.
    idemip_arp_build_reply(pkt, EA_X, IPA_X, g_sha, IPA_Z);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Z, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, dequeue_one(work_a));
    TEST_ASSERT_EQUAL_UINT16(11u, IDEMIP_ARP_IO(work_a)->desc);

    // A second packet for Y takes that freed hold, so Y's list now runs from the later hold to the
    // earlier one and the earlier one is no longer at its front.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, queue_at(work_a, 1000u, IPA_Y, 33u, 300u));

    // Y answers too, so its row stands and the two holds on it are deliverable - and nobody comes to
    // take them. Both go past sec 2.3.2.2's wait on a row that is not going anywhere, and the sweep
    // reaches the one standing behind the head before it reaches the head.
    idemip_arp_build_reply(pkt, EA_Y, IPA_Y, g_sha, IPA_Z);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, input_at(work_a, 1000u, pkt, IPA_Z, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tick_at(work_a, 1000u + (IDEMIP_ARP_MAXPENDING_S * 1000u) + 1u));

    // Neither is deliverable now, and the row they were held for is still in the table.
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, dequeue_one(work_a), "a hold outlived sec 2.3.2.2's wait");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, find_ip(work_a, IPA_Y),
                                  "the row went with the holds that were waiting on it");
}
