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

// =============================================================================
// The behavior suite. Vectors come from RFC 1035 sec 4.1.1, 4.1.2, 4.1.3 and the sec 4.1.4 figure,
// from RFC 2181 sec 5.2, 5.4, 8 and 9, and from RFC 5452 sec 5, 6, 9.1 and 9.2.
// =============================================================================

#define XID 0x1234u
#define SPORT 0xC000u
#define NAME "example.com"
// "example.com" as sec 4.1.2 labels behind the sec 4.1.1 header: 12 is the QNAME, 20 the "com" label,
// 25 the QTYPE, 29 the first answer record.
#define OFF_QNAME 12u
#define OFF_COM 20u
#define OFF_QTYPE 25u
#define OFF_AN 29u

static uint8_t g_msg[600];
static const uint8_t g_ans4[4] = {192u, 0u, 2u, 10u};
static const uint8_t g_ans6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a};
static const uint8_t g_v4_other[4] = {198u, 51u, 100u, 53u};

static size_t w16(uint8_t *p, size_t at, uint16_t v)
{
    p[at] = (uint8_t)(v >> 8);
    p[at + 1u] = (uint8_t)(v & 0xFFu);
    return at + 2u;
}

static size_t w32(uint8_t *p, size_t at, uint32_t v)
{
    p[at] = (uint8_t)(v >> 24);
    p[at + 1u] = (uint8_t)((v >> 16) & 0xFFu);
    p[at + 2u] = (uint8_t)((v >> 8) & 0xFFu);
    p[at + 3u] = (uint8_t)(v & 0xFFu);
    return at + 4u;
}

// RFC 1035 sec 4.1.2 QNAME form: a length octet, that many octets, and a zero octet for the root.
static size_t wname(uint8_t *p, size_t at, const char *dotted)
{
    size_t k = 0;
    while (dotted[k] != '\0')
    {
        size_t n = 0;
        while ((dotted[k + n] != '\0') && (dotted[k + n] != '.'))
        {
            n++;
        }
        p[at++] = (uint8_t)n;
        memcpy(p + at, dotted + k, n);
        at += n;
        k += n;
        if (dotted[k] == '.')
        {
            k++;
        }
    }
    p[at++] = 0u;
    return at;
}

// RFC 1035 sec 4.1.4: "| 1  1|                OFFSET                   |"
static size_t wptr(uint8_t *p, size_t at, uint16_t target)
{
    p[at] = (uint8_t)(IDEMIP_DNS_LABEL_PTR | (uint8_t)(target >> 8));
    p[at + 1u] = (uint8_t)(target & 0xFFu);
    return at + 2u;
}

// RFC 1035 sec 4.1.3: TYPE, CLASS, TTL, RDLENGTH, RDATA behind a NAME the caller already wrote.
static size_t wrr(uint8_t *p, size_t at, uint16_t type, uint16_t cls, uint32_t ttl, const uint8_t *rd, size_t rdlen)
{
    at = w16(p, at, type);
    at = w16(p, at, cls);
    at = w32(p, at, ttl);
    at = w16(p, at, (uint16_t)rdlen);
    if (rdlen != 0u)
    {
        memcpy(p + at, rd, rdlen);
    }
    return at + rdlen;
}

static void mhdr(uint16_t id, uint16_t flags, uint16_t qd, uint16_t an)
{
    memset(g_msg, 0, sizeof g_msg);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_ID, id);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_FLAGS, flags);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_QDCOUNT, qd);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_ANCOUNT, an);
}

// The whole of a well-formed response: header, echoed question, and one answer record whose owner is
// a sec 4.1.4 pointer at the echoed QNAME, which is what a real server writes.
static size_t good_response(const char *name, uint16_t type, uint32_t ttl, const uint8_t *rd, size_t rdlen)
{
    mhdr(XID, (uint16_t)(IDEMIP_DNS_FLAG_QR | IDEMIP_DNS_FLAG_RD | IDEMIP_DNS_FLAG_RA), 1u, 1u);
    size_t at = wname(g_msg, IDEMIP_DNS_HDR_LEN, name);
    at = w16(g_msg, at, type);
    at = w16(g_msg, at, IDEMIP_DNS_CLASS_IN);
    at = wptr(g_msg, at, (uint16_t)IDEMIP_DNS_HDR_LEN);
    return wrr(g_msg, at, type, IDEMIP_DNS_CLASS_IN, ttl, rd, rdlen);
}

static void deliver(uint8_t *w, size_t len, const uint8_t *src, uint16_t sport, uint16_t dport)
{
    IDEMIP_DNS_IO(w)->input_args.msg = g_msg;
    IDEMIP_DNS_IO(w)->input_args.len = len;
    IDEMIP_DNS_IO(w)->input_args.src = src;
    IDEMIP_DNS_IO(w)->input_args.src_port = sport;
    IDEMIP_DNS_IO(w)->input_args.dst_port = dport;
    IDEMIP_DNS_IO(w)->input_args.ipv6 = IDEMIP_FALSE;
    Dns.input(w);
}

static void deliver_ok(uint8_t *w, size_t len)
{
    deliver(w, len, g_v4, IDEMIP_DNS_PORT, SPORT);
}

static void server_at(uint8_t *w, uint8_t index, const uint8_t *addr)
{
    IDEMIP_DNS_IO(w)->server_args.index = index;
    IDEMIP_DNS_IO(w)->server_args.addr = addr;
    IDEMIP_DNS_IO(w)->server_args.ipv6 = IDEMIP_FALSE;
    IDEMIP_DNS_IO(w)->server_args.port = 0u;
    IDEMIP_DNS_IO(w)->server_args.zone = 0u;
    Dns.set_server(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(w)->status);
}

// bind, one server, one registered question about NAME for the given type.
static uint8_t ask(uint8_t *w, const char *name, uint16_t type)
{
    bind_ok(w, &g_cfg);
    server_at(w, 0u, g_v4);
    IDEMIP_DNS_IO(w)->query_args.name = name;
    IDEMIP_DNS_IO(w)->query_args.type = type;
    IDEMIP_DNS_IO(w)->query_args.xid = (uint16_t)XID;
    IDEMIP_DNS_IO(w)->query_args.src_port = (uint16_t)SPORT;
    Dns.query(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(w)->status);
    return IDEMIP_DNS_IO(w)->query;
}

static uint8_t g_out[IDEMIP_DNS_MSG_MAX];

static void put_on_the_wire(uint8_t *w, uint8_t slot)
{
    memset(g_out, 0, sizeof g_out);
    IDEMIP_DNS_IO(w)->build_args.out = g_out;
    IDEMIP_DNS_IO(w)->build_args.cap = sizeof g_out;
    IDEMIP_DNS_IO(w)->build_args.query = slot;
    Dns.build(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(w)->status);
}

static void run_tick(uint8_t *w, uint32_t now_ms)
{
    IDEMIP_DNS_IO(w)->tick_args.now_ms = now_ms;
    Dns.tick(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(w)->status);
}

static void look(uint8_t *w, const char *name, uint16_t type)
{
    IDEMIP_DNS_IO(w)->lookup_args.name = name;
    IDEMIP_DNS_IO(w)->lookup_args.type = type;
    Dns.lookup(w);
}

// --- query registration ------------------------------------------------------

// RFC 5452 sec 9.2: a source port comes "from the range of available ports (53, or 1024 and above)".
// A port below that is predictable ground the section rules out, and it cannot become legal later, so
// it is ERR.
void test_query_refuses_a_source_port_the_rfc_forbids(void)
{
    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);
    IDEMIP_DNS_IO(work_a)->query_args.name = NAME;
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = (uint16_t)XID;

    IDEMIP_DNS_IO(work_a)->query_args.src_port = 0u;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)(IDEMIP_DNS_SRC_PORT_MIN - 1u);
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    // The section names 53 itself as available, so it is taken.
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)IDEMIP_DNS_PORT;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// RFC 5452 sec 9.2: "Use an unpredictable query ID for outgoing queries, utilizing the full range
// available (0-65535)", so no ID value may be refused, zero included.
void test_query_takes_any_id_in_the_full_range(void)
{
    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);
    IDEMIP_DNS_IO(work_a)->query_args.name = NAME;
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)SPORT;

    IDEMIP_DNS_IO(work_a)->query_args.xid = 0u;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DNS_IO(work_a)->xid);

    IDEMIP_DNS_IO(work_a)->cancel_args.query = IDEMIP_DNS_IO(work_a)->query;
    Dns.cancel(work_a);
    IDEMIP_DNS_IO(work_a)->query_args.xid = 0xFFFFu;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0xFFFFu, IDEMIP_DNS_IO(work_a)->xid);
}

// RFC 1035 sec 2.3.4 size limits: "labels 63 octets or less". A 64 octet label cannot be encoded,
// since sec 4.1.4 spends the two high bits of a length octet on the pointer form.
void test_query_refuses_a_label_past_sixty_three_octets(void)
{
    static char big[80];
    memset(big, 'a', 64);
    big[64] = '.';
    memcpy(big + 65, "com", 4);

    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);
    IDEMIP_DNS_IO(work_a)->query_args.name = big;
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = (uint16_t)XID;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)SPORT;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    // 63 is the limit itself, so it is taken.
    big[63] = '.';
    memcpy(big + 64, "com", 4);
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// RFC 1035 sec 3.1: "the total length of a domain name (i.e., label octets and label length octets) is
// restricted to 255 octets or less".
void test_query_refuses_a_name_past_the_wire_limit(void)
{
    // A length octet replaces each separator and the root adds one, so a dotted name of n octets
    // encodes to n + 2. 253 encodes to the limit itself and 254 encodes past it.
    static char big[320];
    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);
    IDEMIP_DNS_IO(work_a)->query_args.name = big;
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = (uint16_t)XID;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)SPORT;

    memset(big, 'a', sizeof big);
    big[63] = '.';
    big[127] = '.';
    big[191] = '.';

    big[IDEMIP_DNS_NAME_WIRE_MAX - 2u] = '\0'; // 253 octets, encoding to 255
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    IDEMIP_DNS_IO(work_a)->cancel_args.query = IDEMIP_DNS_IO(work_a)->query;
    Dns.cancel(work_a);

    big[IDEMIP_DNS_NAME_WIRE_MAX - 2u] = 'a';
    big[IDEMIP_DNS_NAME_WIRE_MAX - 1u] = '\0'; // 254 octets, encoding to 256
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// RFC 2181 sec 11: "The length of any one label is limited to between 1 and 63 octets", so an empty
// interior or leading label is not a name.
void test_query_refuses_an_empty_label(void)
{
    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = (uint16_t)XID;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)SPORT;

    IDEMIP_DNS_IO(work_a)->query_args.name = "example..com";
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    IDEMIP_DNS_IO(work_a)->query_args.name = ".example.com";
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    IDEMIP_DNS_IO(work_a)->query_args.name = "";
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    IDEMIP_DNS_IO(work_a)->query_args.name = NULL;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    // A single trailing separator is the root of sec 3.1, so it is taken.
    IDEMIP_DNS_IO(work_a)->query_args.name = "example.com.";
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// This resolver asks for a host address, so RFC 1035 sec 3.2.2's A and RFC 3596 sec 2.1's AAAA are
// the two QTYPEs it registers.
void test_query_refuses_a_type_it_cannot_ask(void)
{
    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);
    IDEMIP_DNS_IO(work_a)->query_args.name = NAME;
    IDEMIP_DNS_IO(work_a)->query_args.xid = (uint16_t)XID;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)SPORT;

    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_TXT;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_AAAA;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// RFC 5452 sec 5: an attacker gains "if it can force the target resolver to have multiple equivalent
// (identical QNAME, QTYPE, and QCLASS) outstanding queries at any one time to the same authoritative
// server". A second ask therefore lands on the slot already holding it, and the ID stays the one on
// the wire.
void test_query_coalesces_a_question_already_outstanding(void)
{
    uint8_t first = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);

    IDEMIP_DNS_IO(work_a)->query_args.xid = 0x9999u;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = 0xD000u;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(first, IDEMIP_DNS_IO(work_a)->query, "an equivalent question took a second slot");
    TEST_ASSERT_EQUAL_UINT16_MESSAGE((uint16_t)XID, IDEMIP_DNS_IO(work_a)->xid, "the ID on the wire was replaced");
    TEST_ASSERT_EQUAL_UINT16((uint16_t)SPORT, IDEMIP_DNS_IO(work_a)->src_port);

    // The same name for the other type is a different question, so it takes its own slot.
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_AAAA;
    IDEMIP_DNS_IO(work_a)->query_args.xid = 0x9999u;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = 0xD000u;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_NOT_EQUAL_UINT8(first, IDEMIP_DNS_IO(work_a)->query);
}

// RFC 1035 sec 2.3.3: "all comparisons between character strings (e.g., labels, domain names, etc.)
// are done in a case-insensitive manner", so a differently cased ask is the same question.
void test_query_matches_a_held_name_case_insensitively(void)
{
    uint8_t first = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    IDEMIP_DNS_IO(work_a)->query_args.name = "EXAMPLE.COM";
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(first, IDEMIP_DNS_IO(work_a)->query);
}

// Every slot holds a question, and one frees when a caller cancels it or an exchange completes, so
// this is BUSY: retrying later can succeed. ERR would tell a caller to stop asking for a name.
void test_query_is_busy_when_every_slot_is_taken(void)
{
    static const char *names[] = {"a.example.com", "b.example.com", "c.example.com", "d.example.com",
                                  "e.example.com", "f.example.com", "g.example.com", "h.example.com"};
    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = (uint16_t)XID;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)SPORT;

    for (unsigned i = 0; i < IDEMIP_DNS_QUERIES; i++)
    {
        IDEMIP_DNS_IO(work_a)->query_args.name = names[i];
        Dns.query(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    }
    IDEMIP_DNS_IO(work_a)->query_args.name = names[IDEMIP_DNS_QUERIES];
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DNS_QUERIES, IDEMIP_DNS_IO(work_a)->query);

    // Cancelling one frees it, which is what made the answer BUSY rather than ERR.
    IDEMIP_DNS_IO(work_a)->cancel_args.query = 0u;
    Dns.cancel(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    IDEMIP_DNS_IO(work_a)->query_args.name = names[IDEMIP_DNS_QUERIES];
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// --- build -------------------------------------------------------------------

// RFC 1035 sec 4.1.1 the header and sec 4.1.2 the question, field by field. QDCOUNT is one and the
// other three counts are zero, since a query carries no records.
void test_build_writes_the_header_and_question_the_rfc_prints(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    TEST_ASSERT_EQUAL_size_t(OFF_QTYPE + IDEMIP_DNS_QFIXED_LEN, IDEMIP_DNS_IO(work_a)->len);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)XID, (uint16_t)((g_out[0] << 8) | g_out[1]));
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_DNS_FLAG_RD, (uint16_t)((g_out[2] << 8) | g_out[3]));
    TEST_ASSERT_EQUAL_UINT16(1u, (uint16_t)((g_out[4] << 8) | g_out[5]));
    TEST_ASSERT_EQUAL_UINT16(0u, (uint16_t)((g_out[6] << 8) | g_out[7]));
    TEST_ASSERT_EQUAL_UINT16(0u, (uint16_t)((g_out[8] << 8) | g_out[9]));
    TEST_ASSERT_EQUAL_UINT16(0u, (uint16_t)((g_out[10] << 8) | g_out[11]));

    // QNAME: "a length octet followed by that number of octets", ending at "the zero length octet for
    // the null label of the root".
    TEST_ASSERT_EQUAL_UINT8(7u, g_out[OFF_QNAME]);
    TEST_ASSERT_EQUAL_MEMORY("example", g_out + OFF_QNAME + 1u, 7);
    TEST_ASSERT_EQUAL_UINT8(3u, g_out[OFF_COM]);
    TEST_ASSERT_EQUAL_MEMORY("com", g_out + OFF_COM + 1u, 3);
    TEST_ASSERT_EQUAL_UINT8(0u, g_out[OFF_COM + 4u]);

    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DNS_TYPE_A, (uint16_t)((g_out[OFF_QTYPE] << 8) | g_out[OFF_QTYPE + 1u]));
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DNS_CLASS_IN, (uint16_t)((g_out[OFF_QTYPE + 2u] << 8) | g_out[OFF_QTYPE + 3u]));
}

// RFC 1035 sec 4.1.1 RD: "If RD is set, it directs the name server to pursue the query recursively."
// A stub resolver gets no answer without it, and QR must be zero because this is a query.
void test_build_asks_for_recursion_and_is_not_a_response(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_AAAA);
    put_on_the_wire(work_a, slot);
    uint16_t flags = (uint16_t)((g_out[2] << 8) | g_out[3]);
    TEST_ASSERT_TRUE((flags & IDEMIP_DNS_FLAG_RD) != 0u);
    TEST_ASSERT_EQUAL_HEX16(0u, (uint16_t)(flags & IDEMIP_DNS_FLAG_QR));
    TEST_ASSERT_EQUAL_HEX16(0u, (uint16_t)(flags & IDEMIP_DNS_FLAG_OPCODE));
    TEST_ASSERT_EQUAL_HEX16(0u, (uint16_t)(flags & IDEMIP_DNS_FLAG_Z));
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DNS_TYPE_AAAA, (uint16_t)((g_out[OFF_QTYPE] << 8) | g_out[OFF_QTYPE + 1u]));
}

// The trailing separator is the root sec 4.1.2's zero octet already stands for, so both spellings
// encode to the same octets.
void test_build_encodes_a_trailing_separator_as_the_root_octet(void)
{
    uint8_t slot = ask(work_a, "example.com.", IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    TEST_ASSERT_EQUAL_size_t(OFF_QTYPE + IDEMIP_DNS_QFIXED_LEN, IDEMIP_DNS_IO(work_a)->len);
    TEST_ASSERT_EQUAL_UINT8(7u, g_out[OFF_QNAME]);
    TEST_ASSERT_EQUAL_UINT8(3u, g_out[OFF_COM]);
    TEST_ASSERT_EQUAL_UINT8(0u, g_out[OFF_COM + 4u]);
}

// A buffer that cannot hold the message is a caller fault the same call will hit again, so it is ERR.
void test_build_refuses_a_buffer_that_cannot_hold_the_question(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.query = slot;

    IDEMIP_DNS_IO(work_a)->build_args.cap = OFF_QTYPE + IDEMIP_DNS_QFIXED_LEN - 1u;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_DNS_IO(work_a)->len);

    IDEMIP_DNS_IO(work_a)->build_args.out = NULL;
    IDEMIP_DNS_IO(work_a)->build_args.cap = sizeof g_out;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    // One octet more than the question needs is enough.
    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.cap = OFF_QTYPE + IDEMIP_DNS_QFIXED_LEN;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// An empty server table is BUSY, not ERR: DHCP option 6 or an RFC 8106 RDNSS option can still fill
// it, and reported as ERR the caller would abandon a name it will be able to resolve.
void test_build_is_busy_while_no_server_is_known(void)
{
    bind_ok(work_a, &g_cfg);
    IDEMIP_DNS_IO(work_a)->query_args.name = NAME;
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = (uint16_t)XID;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)SPORT;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    uint8_t slot = IDEMIP_DNS_IO(work_a)->query;

    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.cap = sizeof g_out;
    IDEMIP_DNS_IO(work_a)->build_args.query = slot;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);

    server_at(work_a, 0u, g_v4);
    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.cap = sizeof g_out;
    IDEMIP_DNS_IO(work_a)->build_args.query = slot;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// RFC 1035 sec 4.2.1 puts the service on "UDP port 53 (decimal)", which is where a question goes when
// a server was given no port of its own.
void test_build_addresses_the_server_on_the_rfc_port(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DNS_PORT, IDEMIP_DNS_IO(work_a)->dst_port);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)SPORT, IDEMIP_DNS_IO(work_a)->src_port);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)XID, IDEMIP_DNS_IO(work_a)->xid);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_v4, IDEMIP_DNS_IO(work_a)->dst, 4);
    TEST_ASSERT_FALSE(IDEMIP_DNS_IO(work_a)->ipv6);
}

// build is what puts a question on the wire, so a slot already there, one already answered, and a free
// one are all refused: the sweep is what returns a question to the sendable state.
void test_build_refuses_a_slot_that_is_not_awaiting_the_wire(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.cap = sizeof g_out;
    IDEMIP_DNS_IO(work_a)->build_args.query = slot;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status, "a question already sent was sent again");

    IDEMIP_DNS_IO(work_a)->build_args.query = (uint8_t)(IDEMIP_DNS_QUERIES - 1u);
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status, "a free slot was sent");

    IDEMIP_DNS_IO(work_a)->build_args.query = (uint8_t)IDEMIP_DNS_QUERIES;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// --- RFC 5452 sec 9.1, the match rules ---------------------------------------

// "A resolver implementation MUST match responses to all of the following attributes of the query ...
// Query ID". A mismatch "MUST be considered invalid", and the question stays outstanding.
void test_a_response_with_another_id_is_invalid(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_ID, (uint16_t)(XID + 1u));
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status, "a forged ID reached the cache");

    // The real ID is still accepted, so the forgery did not retire the question.
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_ID, (uint16_t)XID);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// "Destination port against query source port". The port the question left from is the second half of
// the RFC 5452 sec 9.2 ID space, so a response to any other port is invalid.
void test_a_response_to_another_port_is_invalid(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);

    deliver(work_a, len, g_v4, IDEMIP_DNS_PORT, (uint16_t)(SPORT + 1u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status, "a response to another port was cached");

    deliver(work_a, len, g_v4, IDEMIP_DNS_PORT, (uint16_t)SPORT);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// "Source address against query destination address", and the source port has to be the port the
// question was sent to (RFC 1035 sec 4.2.1).
void test_a_response_from_another_address_or_port_is_invalid(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);

    deliver(work_a, len, g_v4_other, IDEMIP_DNS_PORT, (uint16_t)SPORT);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    deliver(work_a, len, g_v4, 5353u, (uint16_t)SPORT);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);

    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// "Query name". The echoed sec 4.1.2 QNAME has to be the one asked about.
void test_a_response_echoing_another_name_is_invalid(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    size_t len = good_response("example.net", IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    // One label longer, so the walk has to compare the whole name and not a prefix of it.
    len = good_response("www.example.com", IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    // The same name in another case is the same name (sec 2.3.3).
    len = good_response("EXAMPLE.COM", IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);
}

// "Query class and type".
void test_a_response_echoing_another_class_or_type_is_invalid(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);

    (void)w16(g_msg, OFF_QTYPE, (uint16_t)IDEMIP_DNS_TYPE_AAAA);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    (void)w16(g_msg, OFF_QTYPE, (uint16_t)IDEMIP_DNS_TYPE_A);
    (void)w16(g_msg, OFF_QTYPE + 2u, 3u); // CH, not IN
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    (void)w16(g_msg, OFF_QTYPE + 2u, (uint16_t)IDEMIP_DNS_CLASS_IN);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// RFC 1035 sec 4.1.1 QR: "whether this message is a query (0), or a response (1)". A query arriving on
// a resolver's port is not an answer to anything.
void test_a_message_that_is_not_a_response_is_refused(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);

    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_FLAGS, IDEMIP_DNS_FLAG_RD);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    // A non-zero sec 4.1.1 Opcode is not a standard query's answer either.
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_FLAGS,
              (uint16_t)(IDEMIP_DNS_FLAG_QR | (uint16_t)(1u << IDEMIP_DNS_OPCODE_SHIFT)));
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// One question was asked, so QDCOUNT has to be one: a response echoing none or several is not the
// answer to it.
void test_a_response_with_another_question_count_is_refused(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);

    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_QDCOUNT, 0u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_QDCOUNT, 2u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// RFC 1035 sec 4.2.1: "Messages carried by UDP are restricted to 512 bytes", and the shortest response
// is a header, a root QNAME and its sec 4.1.2 fixed fields.
void test_a_message_outside_the_rfc_length_bounds_is_refused(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);

    deliver_ok(work_a, IDEMIP_DNS_HDR_LEN + IDEMIP_DNS_QFIXED_LEN);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    deliver_ok(work_a, IDEMIP_DNS_MSG_MAX + 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    IDEMIP_DNS_IO(work_a)->input_args.msg = g_msg;
    IDEMIP_DNS_IO(work_a)->input_args.len = len;
    IDEMIP_DNS_IO(work_a)->input_args.src = NULL;
    Dns.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// A question that has not been sent has no ID on the wire to match, so a response arriving before the
// build cannot be its answer.
void test_a_response_to_a_question_not_yet_sent_is_refused(void)
{
    (void)ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// --- RFC 1035 sec 4.1.4, message compression ---------------------------------

// The figure prints "1  1|                20" as a pointer to the name at 20, so a record's owner
// written as a pointer at the echoed QNAME is that name.
void test_a_pointer_at_the_question_name_is_followed(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    TEST_ASSERT_EQUAL_HEX8(IDEMIP_DNS_LABEL_PTR, g_msg[OFF_AN]);
    TEST_ASSERT_EQUAL_HEX8(OFF_QNAME, g_msg[OFF_AN + 1u]);

    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);
    TEST_ASSERT_EQUAL_UINT32(300u, IDEMIP_DNS_IO(work_a)->ttl_s);
}

// The figure's FOO.F.ISI.ARPA at offset 40 "uses a pointer to concatenate a label for FOO to the
// previously defined F.ISI.ARPA", so a label sequence ending in a pointer is the whole name. Here the
// question is www.example.com and the owner is the label "www" followed by a pointer at the
// "example.com" inside the echoed QNAME.
void test_a_label_sequence_ending_in_a_pointer_concatenates(void)
{
    uint8_t slot = ask(work_a, "www.example.com", IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    // "www.example.com" at 12: 03 w w w at 12, 07 e..e at 16, 03 c o m at 24, 00 at 28.
    mhdr(XID, (uint16_t)(IDEMIP_DNS_FLAG_QR | IDEMIP_DNS_FLAG_RD), 1u, 1u);
    size_t at = wname(g_msg, IDEMIP_DNS_HDR_LEN, "www.example.com");
    TEST_ASSERT_EQUAL_size_t(29u, at);
    TEST_ASSERT_EQUAL_UINT8(7u, g_msg[16]); // the "example" length octet the pointer will name
    at = w16(g_msg, at, IDEMIP_DNS_TYPE_A);
    at = w16(g_msg, at, IDEMIP_DNS_CLASS_IN);

    g_msg[at++] = 3u;
    memcpy(g_msg + at, "www", 3);
    at += 3u;
    at = wptr(g_msg, at, 16u);
    at = wrr(g_msg, at, IDEMIP_DNS_TYPE_A, IDEMIP_DNS_CLASS_IN, 120u, g_ans4, 4u);

    deliver_ok(work_a, at);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);
    TEST_ASSERT_EQUAL_UINT32(120u, IDEMIP_DNS_IO(work_a)->ttl_s);
}

// The figure defines ARPA at 64 "using a pointer to the ARPA component of the name F.ISI.ARPA at 20",
// so a pointer at an interior label yields that suffix. Here a CNAME whose owner is the echoed QNAME
// names the "com" label inside it, and the A record whose owner is that same interior label answers.
void test_a_pointer_at_an_interior_label_yields_that_suffix(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    mhdr(XID, (uint16_t)(IDEMIP_DNS_FLAG_QR | IDEMIP_DNS_FLAG_RD), 1u, 2u);
    size_t at = wname(g_msg, IDEMIP_DNS_HDR_LEN, NAME);
    TEST_ASSERT_EQUAL_UINT8(3u, g_msg[OFF_COM]); // the "com" length octet
    at = w16(g_msg, at, IDEMIP_DNS_TYPE_A);
    at = w16(g_msg, at, IDEMIP_DNS_CLASS_IN);

    // sec 3.3.1: a CNAME's RDATA is one domain name, written here as a pointer at "com".
    at = wptr(g_msg, at, (uint16_t)OFF_QNAME);
    at = w16(g_msg, at, IDEMIP_DNS_TYPE_CNAME);
    at = w16(g_msg, at, IDEMIP_DNS_CLASS_IN);
    at = w32(g_msg, at, 60u);
    at = w16(g_msg, at, 2u);
    at = wptr(g_msg, at, (uint16_t)OFF_COM);

    at = wptr(g_msg, at, (uint16_t)OFF_COM);
    at = wrr(g_msg, at, IDEMIP_DNS_TYPE_A, IDEMIP_DNS_CLASS_IN, 90u, g_ans4, 4u);

    deliver_ok(work_a, at);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);

    // The answer is held under the name the caller asked about, not under the alias target.
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);
}

// sec 4.1.4 puts a pointer at "a prior occurance of the same name", so a pointer at itself is not one.
// The walk has to end rather than chase it, and the record it named cannot become an answer.
void test_a_pointer_at_itself_is_refused(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    (void)wptr(g_msg, OFF_AN, (uint16_t)OFF_AN);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, IDEMIP_DNS_IO(work_a)->ttl_s, "a self naming owner produced an answer");

    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status, "a self naming owner reached the cache");
}

// A pointer at a higher offset is not "a prior occurance" either, and a pair of them pointing at each
// other is the loop a malicious response is built from.
void test_a_forward_pointer_and_a_pointer_ring_are_refused(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    // The ring in the echoed question first, where a match failure has to leave the question alone.
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    (void)wptr(g_msg, OFF_QNAME, (uint16_t)(OFF_QNAME + 2u));
    (void)wptr(g_msg, OFF_QNAME + 2u, (uint16_t)OFF_QNAME);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    // The question is untouched, so the real answer is still accepted.
    len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    Dns.flush(work_a);

    // Now the ring in a record's owner: it names a higher offset, and that offset names it back.
    slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    (void)wptr(g_msg, OFF_AN, (uint16_t)(len + 4u));
    (void)wptr(g_msg, len + 4u, (uint16_t)OFF_AN);
    deliver_ok(work_a, len + 8u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status, "a pointer ring reached the cache");
}

// sec 4.1.4: "The 10 and 01 combinations are reserved for future use", so a length octet with one high
// bit set is neither a label nor a pointer.
void test_a_reserved_length_octet_is_refused(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    g_msg[OFF_QNAME] = 0x40u;
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    g_msg[OFF_QNAME] = 0x80u;
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// A name whose labels run past the message is not a name, and the walk must not read past the length
// the caller gave.
void test_a_name_running_past_the_message_is_refused(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    g_msg[OFF_COM] = 63u; // "com" claims sixty three octets, and the message has three
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// --- RFC 5452 sec 6, in-domain records ---------------------------------------

// "One very simple way to achieve this is to only accept data if it is part of the domain for which the
// query was intended", so a record whose owner is a name nobody asked about is not the answer.
void test_a_record_owned_by_another_name_is_not_an_answer(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    mhdr(XID, (uint16_t)(IDEMIP_DNS_FLAG_QR | IDEMIP_DNS_FLAG_RD), 1u, 1u);
    size_t at = wname(g_msg, IDEMIP_DNS_HDR_LEN, NAME);
    at = w16(g_msg, at, IDEMIP_DNS_TYPE_A);
    at = w16(g_msg, at, IDEMIP_DNS_CLASS_IN);
    at = wname(g_msg, at, "attacker.example.net"); // the owner, in full rather than as a pointer
    at = wrr(g_msg, at, IDEMIP_DNS_TYPE_A, IDEMIP_DNS_CLASS_IN, 300u, g_ans4, 4u);

    deliver_ok(work_a, at);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status,
                                  "an out of domain record was cached for the queried name");
}

// RFC 1035 sec 3.2.4 gives the class its own field, so a record of the right type in another class is
// not the answer either.
void test_a_record_of_another_class_is_not_an_answer(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    (void)w16(g_msg, OFF_AN + 2u + IDEMIP_DNS_RR_OFF_CLASS, 3u); // CH
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
}

// RFC 1035 sec 3.4.1 gives an A record four octets of RDATA and RFC 3596 sec 2.2 gives an AAAA sixteen,
// so a record of the right type carrying another RDLENGTH is not an address.
void test_a_record_of_the_wrong_rdlength_is_not_an_answer(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans6, 16u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
}

// A count larger than the section holds must not carry the walk past the message.
void test_an_ancount_past_the_message_reads_nothing_past_it(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_ANCOUNT, 40u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(40u, IDEMIP_DNS_IO(work_a)->answers);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);
}

// --- the answer, and the TTLs ------------------------------------------------

// RFC 1035 sec 3.4.1: an A record's RDATA "is a 4 octet ARPA Internet address", and sec 4.1.3's TTL is
// the seconds it may be cached for.
void test_an_a_answer_is_four_octets_with_its_ttl(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 3600u, g_ans4, 4u);
    deliver_ok(work_a, len);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DNS_TYPE_A, IDEMIP_DNS_IO(work_a)->type);
    TEST_ASSERT_FALSE(IDEMIP_DNS_IO(work_a)->ipv6);
    TEST_ASSERT_EQUAL_UINT32(3600u, IDEMIP_DNS_IO(work_a)->ttl_s);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_DNS_IO(work_a)->answers);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_DNS_IO(work_a)->rcode);
    TEST_ASSERT_EQUAL_UINT8(slot, IDEMIP_DNS_IO(work_a)->query);
}

// RFC 3596 sec 2.2: "A 128 bit IPv6 address is encoded in the data portion of an AAAA resource record",
// and sec 2.1 gives the type the value 28.
void test_an_aaaa_answer_is_sixteen_octets(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_AAAA);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_AAAA, 1800u, g_ans6, 16u);
    deliver_ok(work_a, len);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans6, IDEMIP_DNS_IO(work_a)->addr, IDEMIP_DNS_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DNS_TYPE_AAAA, IDEMIP_DNS_IO(work_a)->type);
    TEST_ASSERT_TRUE(IDEMIP_DNS_IO(work_a)->ipv6);

    look(work_a, NAME, IDEMIP_DNS_TYPE_AAAA);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans6, IDEMIP_DNS_IO(work_a)->addr, IDEMIP_DNS_ADDR_LEN);
    TEST_ASSERT_TRUE(IDEMIP_DNS_IO(work_a)->ipv6);
}

// RFC 1035 sec 4.1.3: "Zero values are interpreted to mean that the RR can only be used for the
// transaction in progress, and should not be cached", so the address is reported and no slot is taken.
void test_a_zero_ttl_answer_is_reported_and_not_cached(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 0u, g_ans4, 4u);
    deliver_ok(work_a, len);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_DNS_IO(work_a)->ttl_s);

    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status, "a zero TTL answer was cached");
}

// RFC 2181 sec 8: "Implementations should treat TTL values received with the most significant bit set
// as if the entire value received was zero." lwIP clamps such a value to DNS_MAX_TTL instead
// (lwip_ref/src/core/dns.c:1167).
void test_a_ttl_with_the_sign_bit_set_is_taken_as_zero(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 0x80000001u, g_ans4, 4u);
    deliver_ok(work_a, len);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, IDEMIP_DNS_IO(work_a)->ttl_s, "a signed TTL was held rather than zeroed");
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
}

// RFC 2181 sec 8: "Implementations are always free to place an upper bound on any TTL received, and
// treat any larger values as if they were that upper bound."
void test_a_ttl_past_the_ceiling_becomes_the_ceiling(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, IDEMIP_DNS_TTL_MAX_S + 1000u, g_ans4, 4u);
    deliver_ok(work_a, len);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_DNS_TTL_MAX_S, IDEMIP_DNS_IO(work_a)->ttl_s);
}

// RFC 2181 sec 5.2: on an RRSet with differing TTLs "the client should treat the RRs for all purposes
// as if all TTLs in the RRSet had been set to the value of the lowest TTL in the RRSet."
void test_the_lowest_ttl_of_an_rrset_is_the_one_held(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    static const uint8_t second[4] = {192u, 0u, 2u, 11u};
    static const uint8_t third[4] = {192u, 0u, 2u, 12u};
    mhdr(XID, (uint16_t)(IDEMIP_DNS_FLAG_QR | IDEMIP_DNS_FLAG_RD), 1u, 3u);
    size_t at = wname(g_msg, IDEMIP_DNS_HDR_LEN, NAME);
    at = w16(g_msg, at, IDEMIP_DNS_TYPE_A);
    at = w16(g_msg, at, IDEMIP_DNS_CLASS_IN);
    at = wptr(g_msg, at, (uint16_t)OFF_QNAME);
    at = wrr(g_msg, at, IDEMIP_DNS_TYPE_A, IDEMIP_DNS_CLASS_IN, 900u, g_ans4, 4u);
    at = wptr(g_msg, at, (uint16_t)OFF_QNAME);
    at = wrr(g_msg, at, IDEMIP_DNS_TYPE_A, IDEMIP_DNS_CLASS_IN, 30u, second, 4u);
    at = wptr(g_msg, at, (uint16_t)OFF_QNAME);
    at = wrr(g_msg, at, IDEMIP_DNS_TYPE_A, IDEMIP_DNS_CLASS_IN, 600u, third, 4u);

    deliver_ok(work_a, at);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(30u, IDEMIP_DNS_IO(work_a)->ttl_s, "an RRSet was held past its lowest TTL");
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);
}

// RFC 1035 sec 4.1.3 measures the TTL in seconds, and the deadline it becomes is in milliseconds, so
// the answer stands one second before its TTL and is gone one second after it.
void test_an_answer_expires_at_its_ttl(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 10u, g_ans4, 4u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    run_tick(work_a, 9000u);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(10u, IDEMIP_DNS_IO(work_a)->ttl_s);

    run_tick(work_a, 10001u);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status, "an answer outlived its TTL");
}

// RFC 2181 sec 5.4: "Servers must never merge RRs from a response with RRs in their cache to form an
// RRSet ... the server must either ignore the RRs in the response, or discard the entire RRSet
// currently in the cache". A second answer for the same name and type replaces the held one.
void test_a_second_answer_replaces_the_cached_one_rather_than_joining_it(void)
{
    static const uint8_t later[4] = {192u, 0u, 2u, 99u};
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    // The exchange finished, so the same ask is a fresh question on the same slot.
    IDEMIP_DNS_IO(work_a)->query_args.name = NAME;
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = 0x4321u;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = 0xC001u;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(slot, IDEMIP_DNS_IO(work_a)->query);
    put_on_the_wire(work_a, slot);

    len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, later, 4u);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_ID, 0x4321u);
    deliver(work_a, len, g_v4, IDEMIP_DNS_PORT, 0xC001u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(later, IDEMIP_DNS_IO(work_a)->addr, 4, "the cache kept the older RRSet");

    // One slot, not two: the answer for the other type is still absent.
    look(work_a, NAME, IDEMIP_DNS_TYPE_AAAA);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
}

// A cached answer is matched case insensitively (sec 2.3.3), and only for the type it was given.
void test_lookup_matches_the_name_case_insensitively_and_the_type_exactly(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    deliver_ok(work_a, len);

    look(work_a, "ExAmPlE.CoM", IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);

    look(work_a, NAME, IDEMIP_DNS_TYPE_AAAA);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);

    look(work_a, "example.co", IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status, "a prefix of the held name matched");

    look(work_a, "www.example.com", IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
}

// A name nobody has asked about is BUSY with no question named, and one being worked on is BUSY with
// its slot named, which is how a caller tells the two apart.
void test_lookup_names_the_question_working_on_the_name(void)
{
    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);

    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DNS_QUERIES, IDEMIP_DNS_IO(work_a)->query);

    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(slot, IDEMIP_DNS_IO(work_a)->query);

    look(work_a, NULL, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
}

// flush empties the answers, so a name that was cached goes back to BUSY.
void test_flush_drops_a_cached_answer(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    deliver_ok(work_a, len);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    Dns.flush(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
}

// --- the RCODEs and TC -------------------------------------------------------

// RFC 1035 sec 4.1.1 RCODE 3 is a "Name Error ... this code signifies that the domain name referenced
// in the query does not exist", and is "Meaningful only for responses from an authoritative name
// server", so a stub resolver has nowhere better to ask and the question is retired.
void test_a_name_error_retires_the_question(void)
{
    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);
    server_at(work_a, 1u, g_v4_other);
    IDEMIP_DNS_IO(work_a)->query_args.name = NAME;
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = (uint16_t)XID;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)SPORT;
    Dns.query(work_a);
    uint8_t slot = IDEMIP_DNS_IO(work_a)->query;
    put_on_the_wire(work_a, slot);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_FLAGS,
              (uint16_t)(IDEMIP_DNS_FLAG_QR | IDEMIP_DNS_FLAG_RD | IDEMIP_DNS_RCODE_NAME_ERR));
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DNS_RCODE_NAME_ERR, IDEMIP_DNS_IO(work_a)->rcode);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DNS_IO(work_a)->answers);

    // Retired, so there is nothing left to put on the wire even with a second server to hand.
    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.cap = sizeof g_out;
    IDEMIP_DNS_IO(work_a)->build_args.query = slot;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DNS_RCODE_NAME_ERR, IDEMIP_DNS_IO(work_a)->rcode);
}

// RFC 1035 sec 4.1.1 RCODE 2 is a "Server failure - The name server was unable to process this query
// due to a problem with the name server", so sec 4.2.1's "The client should try other servers" applies
// and the question goes back on the wire addressed to the other one.
void test_a_server_failure_moves_the_question_to_the_other_server(void)
{
    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);
    server_at(work_a, 1u, g_v4_other);
    IDEMIP_DNS_IO(work_a)->query_args.name = NAME;
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = (uint16_t)XID;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)SPORT;
    Dns.query(work_a);
    uint8_t slot = IDEMIP_DNS_IO(work_a)->query;
    put_on_the_wire(work_a, slot);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_v4, IDEMIP_DNS_IO(work_a)->dst, 4);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_FLAGS,
              (uint16_t)(IDEMIP_DNS_FLAG_QR | IDEMIP_DNS_FLAG_RD | IDEMIP_DNS_RCODE_SERVER_FAIL));
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DNS_RCODE_SERVER_FAIL, IDEMIP_DNS_IO(work_a)->rcode);

    put_on_the_wire(work_a, slot);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(g_v4_other, IDEMIP_DNS_IO(work_a)->dst, 4,
                                          "a failing server was asked again before the other one");
}

// RFC 2181 sec 9: "When a DNS client receives a reply with TC set, it should ignore that response, and
// query again, using a mechanism, such as a TCP connection, that will permit larger replies." There is
// no such mechanism here, so the response is refused and the question stays outstanding for the sweep.
void test_a_truncated_response_is_ignored_and_the_question_stays(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_FLAGS,
              (uint16_t)(IDEMIP_DNS_FLAG_QR | IDEMIP_DNS_FLAG_RD | IDEMIP_DNS_FLAG_TC));
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(slot, IDEMIP_DNS_IO(work_a)->query);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status, "a truncated response was cached");

    // Still outstanding, so the sweep puts it back on the wire.
    run_tick(work_a, IDEMIP_DNS_RETRY_MS);
    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.cap = sizeof g_out;
    IDEMIP_DNS_IO(work_a)->build_args.query = slot;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
}

// A response with no record of the type asked for is a definitive negative, so the exchange is over and
// nothing is cached.
void test_a_response_with_no_record_of_the_type_retires_the_question(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    mhdr(XID, (uint16_t)(IDEMIP_DNS_FLAG_QR | IDEMIP_DNS_FLAG_RD), 1u, 0u);
    size_t at = wname(g_msg, IDEMIP_DNS_HDR_LEN, NAME);
    at = w16(g_msg, at, IDEMIP_DNS_TYPE_A);
    at = w16(g_msg, at, IDEMIP_DNS_CLASS_IN);

    deliver_ok(work_a, at);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DNS_IO(work_a)->answers);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
}

// --- the retry sweep ---------------------------------------------------------

// RFC 1035 sec 4.2.1: "The client should try other servers and server addresses before repeating a
// query to a specific address of a server."
void test_a_timed_out_question_goes_to_the_other_server_first(void)
{
    bind_ok(work_a, &g_cfg);
    server_at(work_a, 0u, g_v4);
    server_at(work_a, 1u, g_v4_other);
    IDEMIP_DNS_IO(work_a)->query_args.name = NAME;
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = (uint16_t)XID;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = (uint16_t)SPORT;
    Dns.query(work_a);
    uint8_t slot = IDEMIP_DNS_IO(work_a)->query;

    put_on_the_wire(work_a, slot);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_v4, IDEMIP_DNS_IO(work_a)->dst, 4);

    // A sweep before the deadline changes nothing, so the question is still on the wire.
    run_tick(work_a, IDEMIP_DNS_RETRY_MS - 1u);
    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.cap = sizeof g_out;
    IDEMIP_DNS_IO(work_a)->build_args.query = slot;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    run_tick(work_a, IDEMIP_DNS_RETRY_MS);
    put_on_the_wire(work_a, slot);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(g_v4_other, IDEMIP_DNS_IO(work_a)->dst, 4,
                                          "the same server was asked again before the other one");

    run_tick(work_a, 2u * IDEMIP_DNS_RETRY_MS);
    put_on_the_wire(work_a, slot);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_v4, IDEMIP_DNS_IO(work_a)->dst, 4);
}

// The tries the configuration allows are counted, and the question is retired once they are spent
// rather than asked forever.
void test_the_retries_run_out(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    uint32_t now = 0;
    for (unsigned k = 0; k < g_cfg.retries; k++)
    {
        put_on_the_wire(work_a, slot);
        now += IDEMIP_DNS_RETRY_MS;
        run_tick(work_a, now);
    }
    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.cap = sizeof g_out;
    IDEMIP_DNS_IO(work_a)->build_args.query = slot;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status, "a question outlived its retries");

    // The slot is still the one holding that name, so a fresh ask reuses it.
    IDEMIP_DNS_IO(work_a)->query_args.name = NAME;
    IDEMIP_DNS_IO(work_a)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_a)->query_args.xid = 0x5555u;
    IDEMIP_DNS_IO(work_a)->query_args.src_port = 0xC002u;
    Dns.query(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(slot, IDEMIP_DNS_IO(work_a)->query);
    TEST_ASSERT_EQUAL_UINT16(0x5555u, IDEMIP_DNS_IO(work_a)->xid);
    put_on_the_wire(work_a, slot);
}

// RFC 1035 sec 4.2.1 asks for a "minimum retransmission interval" of "2-5 seconds", so the deadline a
// build arms is inside that window.
void test_the_retransmission_interval_is_inside_the_rfc_window(void)
{
    TEST_ASSERT_TRUE(IDEMIP_DNS_RETRY_MS >= 2000u);
    TEST_ASSERT_TRUE(IDEMIP_DNS_RETRY_MS <= 5000u);

    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    run_tick(work_a, 1000u);
    put_on_the_wire(work_a, slot);

    run_tick(work_a, 1000u + IDEMIP_DNS_RETRY_MS - 1u);
    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.cap = sizeof g_out;
    IDEMIP_DNS_IO(work_a)->build_args.query = slot;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    run_tick(work_a, 1000u + IDEMIP_DNS_RETRY_MS);
    put_on_the_wire(work_a, slot);
}

// The deadlines are millisecond counts that wrap, so a sweep across the wrap has to fire the deadline
// it passed and not the one still ahead of it.
void test_a_deadline_holds_across_the_millisecond_wrap(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    run_tick(work_a, 0xFFFFFFFFu - 100u);
    put_on_the_wire(work_a, slot);

    run_tick(work_a, 0xFFFFFFFFu - 50u); // still short of the deadline, past the wrap
    IDEMIP_DNS_IO(work_a)->build_args.out = g_out;
    IDEMIP_DNS_IO(work_a)->build_args.cap = sizeof g_out;
    IDEMIP_DNS_IO(work_a)->build_args.query = slot;
    Dns.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    run_tick(work_a, IDEMIP_DNS_RETRY_MS - 100u); // the wrapped deadline itself
    put_on_the_wire(work_a, slot);
}

// --- the whole exchange ------------------------------------------------------

// query, build, input, lookup, on two borrows at once, since the borrow is the resolver.
void test_the_exchange_runs_end_to_end_on_two_borrows_at_once(void)
{
    static const uint8_t b_answer[4] = {203u, 0u, 113u, 7u};

    uint8_t sa = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    bind_ok(work_b, &g_cfg_b);
    server_at(work_b, 0u, g_v4_other);
    IDEMIP_DNS_IO(work_b)->query_args.name = "other.example.net";
    IDEMIP_DNS_IO(work_b)->query_args.type = IDEMIP_DNS_TYPE_A;
    IDEMIP_DNS_IO(work_b)->query_args.xid = 0xBEEFu;
    IDEMIP_DNS_IO(work_b)->query_args.src_port = 0xD100u;
    Dns.query(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_b)->status);
    uint8_t sb = IDEMIP_DNS_IO(work_b)->query;

    put_on_the_wire(work_a, sa);
    put_on_the_wire(work_b, sb);

    // b's answer first, then a's: neither call may disturb the other borrow.
    size_t len = good_response("other.example.net", IDEMIP_DNS_TYPE_A, 60u, b_answer, 4u);
    (void)w16(g_msg, IDEMIP_DNS_HDR_OFF_ID, 0xBEEFu);
    deliver(work_b, len, g_v4_other, IDEMIP_DNS_PORT, 0xD100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_b)->status);

    len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_ans4, IDEMIP_DNS_IO(work_a)->addr, 4);

    look(work_b, "other.example.net", IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_b)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(b_answer, IDEMIP_DNS_IO(work_b)->addr, 4);

    // a's name is not b's, and b's is not a's.
    look(work_a, "other.example.net", IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
    look(work_b, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_b)->status);
}

// An entry is a function of its borrow alone, so the same input on the same bytes reports the same
// thing however many times it is repeated.
void test_input_on_the_same_bytes_repeats(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);
    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);

    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    uint8_t first[IDEMIP_DNS_ADDR_LEN];
    memcpy(first, IDEMIP_DNS_IO(work_a)->addr, sizeof first);
    uint32_t first_ttl = IDEMIP_DNS_IO(work_a)->ttl_s;

    // The question is answered now, so the same bytes no longer match one that is on the wire.
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);

    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_DNS_IO(work_a)->addr, IDEMIP_DNS_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT32(first_ttl, IDEMIP_DNS_IO(work_a)->ttl_s);

    // And a repeated lookup reports the same answer again.
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, IDEMIP_DNS_IO(work_a)->addr, IDEMIP_DNS_ADDR_LEN);
}

// cancel drops the question and its name, so the response that was on its way matches nothing.
void test_cancel_leaves_no_question_for_a_late_response(void)
{
    uint8_t slot = ask(work_a, NAME, IDEMIP_DNS_TYPE_A);
    put_on_the_wire(work_a, slot);

    IDEMIP_DNS_IO(work_a)->cancel_args.query = slot;
    Dns.cancel(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DNS_IO(work_a)->status);

    size_t len = good_response(NAME, IDEMIP_DNS_TYPE_A, 300u, g_ans4, 4u);
    deliver_ok(work_a, len);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DNS_IO(work_a)->status);
    look(work_a, NAME, IDEMIP_DNS_TYPE_A);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DNS_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_DNS_QUERIES, IDEMIP_DNS_IO(work_a)->query);
}
