// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for dns, modeled on test_phy. It tests the CONTRACT, not the protocol:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two resolvers share not one byte
//   4. a canary past IDEMIP_DNS_BORROW proves nothing wrote outside the map
//   5. the four tables abut, each at its published offset, and the last one ends at the borrow
//   6. clear leaves every region zeroed, flush empties the cache alone, and an unbound borrow is
//      refused
//
// Nothing here reads a table entry's fields: those are the .c's, and only the offsets are public.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/dns/dns.h"

#include <string.h>
#include <unity.h>

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_DNS_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_DNS_BORROW + 16];

static const IdemIpDnsCfg g_cfg = {.netif = 0u, .retries = 3u};
static const IdemIpDnsCfg g_cfg_b = {.netif = 1u, .retries = 2u};

// One server of each family. RFC 1035 sec 4.2.1 puts the service on port 53.
static const uint8_t g_v4[4] = {192u, 0u, 2u, 53u};
static const uint8_t g_v6[IDEMIP_DNS_ADDR_LEN] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_DNS_BORROW, CANARY, cap - IDEMIP_DNS_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_DNS_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_DNS_BORROW");
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

static void bind_ok(uint8_t *w, const IdemIpDnsCfg *cfg)
{
    IDEMIP_DNS_IO(w)->bind_args.cfg = cfg;
    Dns.bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(w)->status);
}

// --- the borrow --------------------------------------------------------------

void test_every_entry_survives_a_null_borrow(void)
{
    Dns.clear(NULL);
    Dns.bind(NULL);
    Dns.set_server(NULL);
    Dns.query(NULL);
    Dns.lookup(NULL);
    Dns.build(NULL);
    Dns.input(NULL);
    Dns.tick(NULL);
    Dns.cancel(NULL);
    Dns.flush(NULL);
    TEST_PASS();
}

// Five regions, so each has to start where the one before it ends, and the last has to end at the
// borrow. A gap wastes bytes and an overlap corrupts a neighbor.
void test_the_published_offsets_abut_and_fill_the_borrow(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DNS_OFF_IO);
    TEST_ASSERT_TRUE(IDEMIP_DNS_OFF_IO + sizeof(DnsIo) <= IDEMIP_DNS_OFF_CTX);
    TEST_ASSERT_TRUE(IDEMIP_DNS_OFF_CTX < IDEMIP_DNS_OFF_QUERIES);

    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_DNS_OFF_ENTRIES,
                             (size_t)IDEMIP_DNS_OFF_QUERIES + (IDEMIP_DNS_QUERIES << IDEMIP_DNS_QUERY_ENTRY_SHIFT));
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_DNS_OFF_NAMES,
                             (size_t)IDEMIP_DNS_OFF_ENTRIES + (IDEMIP_DNS_ENTRIES << IDEMIP_DNS_ENTRY_SHIFT));
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_DNS_OFF_SERVERS,
                             (size_t)IDEMIP_DNS_OFF_NAMES + (IDEMIP_DNS_NAMES << IDEMIP_DNS_NAME_SHIFT));
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_DNS_BORROW,
                             (size_t)IDEMIP_DNS_OFF_SERVERS + (IDEMIP_DNS_SERVERS << IDEMIP_DNS_SERVER_ENTRY_SHIFT));
}

// Every region starts on IDEMIP_ALIGN, since a table entry is read through a struct pointer.
void test_every_published_offset_is_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DNS_OFF_CTX & 7u);
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DNS_OFF_QUERIES & 7u);
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DNS_OFF_ENTRIES & 7u);
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DNS_OFF_NAMES & 7u);
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DNS_OFF_SERVERS & 7u);
}

// One name per question and one per cached answer, at fixed indices, so a name region is reached by a
// shift and never searched for.
void test_the_name_table_holds_one_name_per_question_and_answer(void)
{
    TEST_ASSERT_EQUAL_UINT(IDEMIP_DNS_QUERIES + IDEMIP_DNS_ENTRIES, IDEMIP_DNS_NAMES);
    TEST_ASSERT_TRUE((1u << IDEMIP_DNS_NAME_SHIFT) >= IDEMIP_DNS_NAME_MAX);
    TEST_ASSERT_TRUE(IDEMIP_DNS_NAME_MAX >= 256u);
}

void test_the_io_macro_lands_on_the_published_offset(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_DNS_OFF_IO, IDEMIP_DNS_IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_DNS_OFF_IO, IDEMIP_DNS_IO(work_b));
}

// clear zeroes the whole borrow, so every question and every cached answer is free again.
void test_clear_zeroes_the_regions(void)
{
    memset(work_a, 0xA5, IDEMIP_DNS_BORROW);
    Dns.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    for (size_t i = IDEMIP_DNS_OFF_CTX; i < IDEMIP_DNS_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[i], "clear left a byte of a region set");
    }
    TEST_ASSERT_NULL(IDEMIP_DNS_IO(work_a)->bind_args.cfg);
    TEST_ASSERT_NULL(IDEMIP_DNS_IO(work_a)->query_args.name);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_DNS_IO(work_a)->len);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DNS_IO(work_a)->xid);
}

void test_clear_touches_one_borrow_only(void)
{
    memset(work_a, 0xA5, IDEMIP_DNS_BORROW);
    memset(work_b, 0xA5, IDEMIP_DNS_BORROW);
    Dns.clear(work_a);

    for (size_t i = 0; i < IDEMIP_DNS_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xA5u, work_b[i], "clearing one borrow wrote into the other");
    }
}

// The borrow IS the resolver. Every entry that writes is run against one borrow while the other is
// watched byte for byte, which is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_DNS_IO(work_a)->bind_args.cfg = &g_cfg;
    IDEMIP_DNS_IO(work_b)->bind_args.cfg = &g_cfg_b;
    TEST_ASSERT_EQUAL_PTR(&g_cfg, IDEMIP_DNS_IO(work_a)->bind_args.cfg);
    TEST_ASSERT_EQUAL_PTR(&g_cfg_b, IDEMIP_DNS_IO(work_b)->bind_args.cfg);

    // b is armed to zero and never handed to an entry.
    arm(work_b, sizeof work_b);

    Dns.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    IDEMIP_DNS_IO(work_a)->server_args.index = 0u;
    IDEMIP_DNS_IO(work_a)->server_args.addr = g_v4;
    IDEMIP_DNS_IO(work_a)->server_args.ipv6 = IDEMIP_FALSE;
    Dns.set_server(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    Dns.flush(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    for (size_t i = 0; i < IDEMIP_DNS_BORROW; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_b[i], "work on one borrow reached the other");
    }
}

void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    bind_ok(work_a, &g_cfg);

    IDEMIP_DNS_IO(work_b)->bind_args.cfg = NULL;
    Dns.bind(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_b)->status);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_PTR(&g_cfg, IDEMIP_DNS_IO(work_a)->bind_args.cfg);

    Dns.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

void test_unbound_borrow_refuses_work(void)
{
    Dns.set_server(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    Dns.lookup(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    Dns.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    Dns.tick(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    Dns.cancel(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    Dns.flush(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

void test_clear_does_not_bind(void)
{
    Dns.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// --- bind --------------------------------------------------------------------

void test_bind_refuses_an_unusable_cfg(void)
{
    IDEMIP_DNS_IO(work_a)->bind_args.cfg = NULL;
    Dns.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    IdemIpDnsCfg bad = g_cfg;
    IDEMIP_DNS_IO(work_a)->bind_args.cfg = &bad;

    bad.retries = 0u;
    Dns.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status, "a cfg that never asks was accepted");

    bad = g_cfg;
    bad.netif = (uint8_t)IDEMIP_NETIF_COUNT;
    Dns.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status,
                                  "an interface index past the count was accepted");
}

void test_bind_accepts_a_complete_cfg(void)
{
    bind_ok(work_a, &g_cfg);
}

// --- the server table --------------------------------------------------------

void test_set_server_refuses_a_slot_outside_the_table(void)
{
    bind_ok(work_a, &g_cfg);
    IDEMIP_DNS_IO(work_a)->server_args.index = (uint8_t)IDEMIP_DNS_SERVERS;
    IDEMIP_DNS_IO(work_a)->server_args.addr = g_v4;
    Dns.set_server(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

void test_set_server_refuses_a_null_address(void)
{
    bind_ok(work_a, &g_cfg);
    IDEMIP_DNS_IO(work_a)->server_args.index = 0u;
    IDEMIP_DNS_IO(work_a)->server_args.addr = NULL;
    Dns.set_server(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// Both families go in the same table, an IPv4 address occupying the first four octets of an entry.
void test_set_server_takes_both_families(void)
{
    bind_ok(work_a, &g_cfg);

    IDEMIP_DNS_IO(work_a)->server_args.index = 0u;
    IDEMIP_DNS_IO(work_a)->server_args.addr = g_v4;
    IDEMIP_DNS_IO(work_a)->server_args.ipv6 = IDEMIP_FALSE;
    IDEMIP_DNS_IO(work_a)->server_args.port = 0u;
    Dns.set_server(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    IDEMIP_DNS_IO(work_a)->server_args.index = (uint8_t)(IDEMIP_DNS_SERVERS - 1u);
    IDEMIP_DNS_IO(work_a)->server_args.addr = g_v6;
    IDEMIP_DNS_IO(work_a)->server_args.ipv6 = IDEMIP_TRUE;
    IDEMIP_DNS_IO(work_a)->server_args.zone = 1u;
    Dns.set_server(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// A server entry is written inside its own slot, so the slot beside it keeps whatever it held.
void test_set_server_writes_inside_its_own_slot(void)
{
    bind_ok(work_a, &g_cfg);
    const size_t stride = (size_t)1u << IDEMIP_DNS_SERVER_ENTRY_SHIFT;
    uint8_t *table = work_a + IDEMIP_DNS_OFF_SERVERS;
    memset(table, 0xC3, (size_t)IDEMIP_DNS_SERVERS << IDEMIP_DNS_SERVER_ENTRY_SHIFT);

    IDEMIP_DNS_IO(work_a)->server_args.index = 0u;
    IDEMIP_DNS_IO(work_a)->server_args.addr = g_v6;
    IDEMIP_DNS_IO(work_a)->server_args.ipv6 = IDEMIP_TRUE;
    Dns.set_server(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    for (size_t i = stride; i < ((size_t)IDEMIP_DNS_SERVERS << IDEMIP_DNS_SERVER_ENTRY_SHIFT); i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, table[i], "a server write reached the next slot");
    }
}

// --- cancel and flush --------------------------------------------------------

void test_cancel_refuses_a_slot_outside_the_table(void)
{
    bind_ok(work_a, &g_cfg);
    IDEMIP_DNS_IO(work_a)->cancel_args.query = (uint8_t)IDEMIP_DNS_QUERIES;
    Dns.cancel(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// A slot holding no question has nothing to drop, and asking again cannot change that, so it is ERR
// and not BUSY.
void test_cancel_of_a_free_slot_is_refused(void)
{
    bind_ok(work_a, &g_cfg);
    IDEMIP_DNS_IO(work_a)->cancel_args.query = 0u;
    Dns.cancel(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// flush empties the answers and the names those answers own, and leaves the questions and the servers
// exactly as they were.
void test_flush_empties_the_cache_alone(void)
{
    bind_ok(work_a, &g_cfg);

    const size_t queries = (size_t)IDEMIP_DNS_QUERIES << IDEMIP_DNS_QUERY_ENTRY_SHIFT;
    const size_t entries = (size_t)IDEMIP_DNS_ENTRIES << IDEMIP_DNS_ENTRY_SHIFT;
    const size_t servers = (size_t)IDEMIP_DNS_SERVERS << IDEMIP_DNS_SERVER_ENTRY_SHIFT;
    const size_t query_names = (size_t)IDEMIP_DNS_QUERIES << IDEMIP_DNS_NAME_SHIFT;
    const size_t answer_names = (size_t)IDEMIP_DNS_ENTRIES << IDEMIP_DNS_NAME_SHIFT;

    memset(work_a + IDEMIP_DNS_OFF_QUERIES, 0xC3, queries);
    memset(work_a + IDEMIP_DNS_OFF_ENTRIES, 0xC3, entries);
    memset(work_a + IDEMIP_DNS_OFF_NAMES, 0xC3, query_names + answer_names);
    memset(work_a + IDEMIP_DNS_OFF_SERVERS, 0xC3, servers);

    Dns.flush(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    for (size_t i = 0; i < entries; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[IDEMIP_DNS_OFF_ENTRIES + i], "flush left a cached answer");
    }
    for (size_t i = 0; i < answer_names; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[IDEMIP_DNS_OFF_NAMES + query_names + i],
                                       "flush left a cached answer's name");
    }
    for (size_t i = 0; i < queries; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_a[IDEMIP_DNS_OFF_QUERIES + i], "flush dropped a question");
    }
    for (size_t i = 0; i < query_names; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_a[IDEMIP_DNS_OFF_NAMES + i], "flush dropped a question's name");
    }
    for (size_t i = 0; i < servers; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_a[IDEMIP_DNS_OFF_SERVERS + i], "flush dropped a server");
    }
}

// --- the wire constants ------------------------------------------------------

// RFC 1035 sec 4.1.1: six 16-bit header fields, and a flags word every bit of which belongs to one
// field.
void test_the_header_map_is_as_the_rfc_prints_it(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_DNS_HDR_OFF_ID);
    TEST_ASSERT_EQUAL_UINT(2u, IDEMIP_DNS_HDR_OFF_FLAGS);
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_DNS_HDR_OFF_QDCOUNT);
    TEST_ASSERT_EQUAL_UINT(6u, IDEMIP_DNS_HDR_OFF_ANCOUNT);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_DNS_HDR_OFF_NSCOUNT);
    TEST_ASSERT_EQUAL_UINT(10u, IDEMIP_DNS_HDR_OFF_ARCOUNT);
    TEST_ASSERT_EQUAL_UINT(12u, IDEMIP_DNS_HDR_LEN);

    TEST_ASSERT_EQUAL_HEX16(0x8000u, IDEMIP_DNS_FLAG_QR);
    TEST_ASSERT_EQUAL_HEX16(0x7800u, IDEMIP_DNS_FLAG_OPCODE);
    TEST_ASSERT_EQUAL_HEX16(0x0400u, IDEMIP_DNS_FLAG_AA);
    TEST_ASSERT_EQUAL_HEX16(0x0200u, IDEMIP_DNS_FLAG_TC);
    TEST_ASSERT_EQUAL_HEX16(0x0100u, IDEMIP_DNS_FLAG_RD);
    TEST_ASSERT_EQUAL_HEX16(0x0080u, IDEMIP_DNS_FLAG_RA);
    TEST_ASSERT_EQUAL_HEX16(0x000Fu, IDEMIP_DNS_FLAG_RCODE);
}

// RFC 1035 sec 3.2.2 and sec 3.2.4 the TYPE and CLASS values, RFC 3596 sec 2.1 the AAAA type, and
// sec 2.3.4 with sec 4.2.1 the limits.
void test_the_type_and_class_values_are_as_the_rfc_prints_them(void)
{
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_DNS_TYPE_NS);
    TEST_ASSERT_EQUAL_INT(5, IDEMIP_DNS_TYPE_CNAME);
    TEST_ASSERT_EQUAL_INT(12, IDEMIP_DNS_TYPE_PTR);
    TEST_ASSERT_EQUAL_INT(16, IDEMIP_DNS_TYPE_TXT);
    TEST_ASSERT_EQUAL_INT(28, IDEMIP_DNS_TYPE_AAAA);
    TEST_ASSERT_EQUAL_UINT(1u, IDEMIP_DNS_CLASS_IN);
    TEST_ASSERT_EQUAL_UINT(53u, IDEMIP_DNS_PORT);
    TEST_ASSERT_EQUAL_UINT(512u, IDEMIP_DNS_MSG_MAX);
    TEST_ASSERT_EQUAL_UINT(63u, IDEMIP_DNS_LABEL_MAX);
    TEST_ASSERT_EQUAL_HEX8(0xC0u, IDEMIP_DNS_LABEL_PTR);
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_DNS_A_RDLEN);
    TEST_ASSERT_EQUAL_UINT(16u, IDEMIP_DNS_AAAA_RDLEN);
}

// RFC 1035 sec 4.1.1 prints the six response codes this resolver acts on.
void test_the_rcodes_are_as_the_rfc_prints_them(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_DNS_RCODE_NO_ERROR);
    TEST_ASSERT_EQUAL_INT(1, IDEMIP_DNS_RCODE_FORMAT_ERR);
    TEST_ASSERT_EQUAL_INT(2, IDEMIP_DNS_RCODE_SERVER_FAIL);
    TEST_ASSERT_EQUAL_INT(3, IDEMIP_DNS_RCODE_NAME_ERR);
    TEST_ASSERT_EQUAL_INT(4, IDEMIP_DNS_RCODE_NOT_IMPL);
    TEST_ASSERT_EQUAL_INT(5, IDEMIP_DNS_RCODE_REFUSED);
}
