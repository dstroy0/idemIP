// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for the RFC 1122 sec 3.4 raw bindings. It tests the contract, not the protocol:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. the published offsets are ordered, non-overlapping, and inside IDEMIP_RAW_PCB_BORROW
//   5. clear zeroes the regions and marks the borrow, and a borrow that was never cleared is refused
//   6. an index past the table and a missing address operand are refused
//
// The behavior cases follow it, from "--- open" down. RFC 1122 sec 3.4 states the IP/transport
// interface as a set of procedure calls and prints no numeric vector, so those cases assert the
// properties its text and sec 3.2.1.3, 3.2.1.6 and 3.2.1.7 state. RFC 3542 sec 3.1 does print one:
// "int offset = 2;".
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/raw/raw_pcb.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_RAW_PCB_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_RAW_PCB_BORROW + 16];

#define TAB_BYTES ((size_t)IDEMIP_RAW_PCBS << IDEMIP_RAW_PCB_ENTRY_SHIFT)

static const uint8_t g_local[IDEMIP_RAW_PCB_ADDR_BYTES] = {192u, 0u, 2u, 1u};
static const uint8_t g_remote[IDEMIP_RAW_PCB_ADDR_BYTES] = {192u, 0u, 2u, 9u};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_RAW_PCB_BORROW, CANARY, cap - IDEMIP_RAW_PCB_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_RAW_PCB_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_RAW_PCB_BORROW");
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
    RawPcb.open(w);
    RawPcb.close(w);
    RawPcb.bind(w);
    RawPcb.connect(w);
    RawPcb.disconnect(w);
    RawPcb.set_opts(w);
    RawPcb.load(w);
    RawPcb.find(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    RawPcb.clear(NULL);
    call_every_entry(NULL);
    TEST_PASS();
}

// The map is public, so a reader can place every region without opening the .c. Each region starts
// where the one before it ends, and the last one ends inside the borrow.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_RAW_PCB_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_RAW_PCB_OFF_IO + sizeof(RawPcbIo), (size_t)IDEMIP_RAW_PCB_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_RAW_PCB_OFF_TAB >= (size_t)IDEMIP_RAW_PCB_OFF_CTX,
                             "the table overlaps the context");
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_RAW_PCB_OFF_TAB + TAB_BYTES <= (size_t)IDEMIP_RAW_PCB_BORROW,
                             "the table runs past IDEMIP_RAW_PCB_BORROW");
    TEST_ASSERT_TRUE_MESSAGE(sizeof(RawPcbIo) <= (size_t)IDEMIP_RAW_PCB_CTX_BYTES,
                             "the operand block runs into the table");
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_RAW_PCB_OFF_IO, IDEMIP_RAW_PCB_IO(work_a));
}

// Zeroed, never cleared: every entry must refuse rather than read a table that was never zeroed.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_RAW_PCB_IO(work_a)->bind_args.ip = g_local;
    IDEMIP_RAW_PCB_IO(work_a)->connect_args.ip = g_remote;
    IDEMIP_RAW_PCB_IO(work_a)->find_args.local_ip = g_local;
    IDEMIP_RAW_PCB_IO(work_a)->find_args.remote_ip = g_remote;

    RawPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.disconnect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
}

// --- clear -------------------------------------------------------------------

void test_clear_zeroes_the_table(void)
{
    memset(work_a + IDEMIP_RAW_PCB_OFF_CTX, 0xEE, (size_t)IDEMIP_RAW_PCB_BORROW - IDEMIP_RAW_PCB_OFF_CTX);
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);
    for (size_t i = 0; i < TAB_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_a[IDEMIP_RAW_PCB_OFF_TAB + i], "clear left an entry unzeroed");
    }
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, IDEMIP_RAW_PCB_IO(work_a)->index);
}

// A second clear is the same call on the same bytes, so it reports the same thing.
void test_clear_repeats(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);
}

// The operand block is the caller's. clear reports through the result members and leaves the
// operands where they were.
void test_clear_leaves_the_operands_alone(void)
{
    IDEMIP_RAW_PCB_IO(work_a)->open_args.proto = 253u;
    IDEMIP_RAW_PCB_IO(work_a)->bind_args.ip = g_local;
    IDEMIP_RAW_PCB_IO(work_a)->opt_args.ttl = 64u;
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT8(253u, IDEMIP_RAW_PCB_IO(work_a)->open_args.proto);
    TEST_ASSERT_EQUAL_PTR(g_local, IDEMIP_RAW_PCB_IO(work_a)->bind_args.ip);
    TEST_ASSERT_EQUAL_UINT8(64u, IDEMIP_RAW_PCB_IO(work_a)->opt_args.ttl);
}

// --- two borrows -------------------------------------------------------------

// The borrow IS the table, and the operand block is in it, so two tables share no byte at all. This
// is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_RAW_PCB_IO(work_a)->open_args.proto = 253u;
    IDEMIP_RAW_PCB_IO(work_a)->pcb_args.index = 1u;
    IDEMIP_RAW_PCB_IO(work_b)->open_args.proto = 254u;
    IDEMIP_RAW_PCB_IO(work_b)->pcb_args.index = 0u;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_UINT8(253u, IDEMIP_RAW_PCB_IO(work_a)->open_args.proto);
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_RAW_PCB_IO(work_a)->pcb_args.index);
    TEST_ASSERT_EQUAL_UINT8(254u, IDEMIP_RAW_PCB_IO(work_b)->open_args.proto);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_RAW_PCB_IO(work_b)->pcb_args.index);

    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);

    // And b's operands are still b's after a's call.
    TEST_ASSERT_EQUAL_UINT8(254u, IDEMIP_RAW_PCB_IO(work_b)->open_args.proto);
    TEST_ASSERT_EQUAL_UINT8(253u, IDEMIP_RAW_PCB_IO(work_a)->open_args.proto);
}

// A clear on one borrow reaches no byte of the other's table.
void test_a_clear_on_one_borrow_leaves_the_other_table_untouched(void)
{
    memset(work_b + IDEMIP_RAW_PCB_OFF_TAB, 0xC3, TAB_BYTES);
    RawPcb.clear(work_a);
    for (size_t i = 0; i < TAB_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[IDEMIP_RAW_PCB_OFF_TAB + i], "a clear crossed into b's table");
    }
    RawPcb.clear(work_b);
    for (size_t i = 0; i < TAB_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, work_b[IDEMIP_RAW_PCB_OFF_TAB + i], "clear left an entry unzeroed");
    }
}

// --- the bounds on an operand ------------------------------------------------

// An index no entry has is refused, and reporting it as BUSY would have the caller retry a call that
// can never succeed.
void test_an_index_past_the_table_is_refused(void)
{
    RawPcb.clear(work_a);
    IDEMIP_RAW_PCB_IO(work_a)->pcb_args.index = (uint16_t)IDEMIP_RAW_PCBS;
    RawPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.disconnect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    RawPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);

    IDEMIP_RAW_PCB_IO(work_a)->bind_args.index = (uint16_t)IDEMIP_RAW_PCBS;
    IDEMIP_RAW_PCB_IO(work_a)->bind_args.ip = g_local;
    RawPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);

    IDEMIP_RAW_PCB_IO(work_a)->opt_args.index = (uint16_t)IDEMIP_RAW_PCBS;
    RawPcb.set_opts(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
}

// A bind and a connect read IDEMIP_RAW_PCB_ADDR_BYTES from the operand, so a null one is refused
// rather than dereferenced.
void test_a_missing_address_operand_is_refused(void)
{
    RawPcb.clear(work_a);
    IDEMIP_RAW_PCB_IO(work_a)->bind_args.index = 0u;
    IDEMIP_RAW_PCB_IO(work_a)->bind_args.ip = NULL;
    RawPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);

    IDEMIP_RAW_PCB_IO(work_a)->connect_args.index = 0u;
    IDEMIP_RAW_PCB_IO(work_a)->connect_args.ip = NULL;
    RawPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);

    IDEMIP_RAW_PCB_IO(work_a)->find_args.local_ip = g_local;
    IDEMIP_RAW_PCB_IO(work_a)->find_args.remote_ip = NULL;
    RawPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, IDEMIP_RAW_PCB_IO(work_a)->index);
}

// A load that reports nothing leaves nothing of a former load behind.
void test_a_refused_load_reports_no_binding(void)
{
    RawPcb.clear(work_a);
    IDEMIP_RAW_PCB_IO(work_a)->info.proto = 253u;
    IDEMIP_RAW_PCB_IO(work_a)->info.local_ip = g_local;
    IDEMIP_RAW_PCB_IO(work_a)->pcb_args.index = (uint16_t)IDEMIP_RAW_PCBS;
    RawPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_RAW_PCB_IO(work_a)->info.proto);
    TEST_ASSERT_NULL(IDEMIP_RAW_PCB_IO(work_a)->info.local_ip);
}

// =============================================================================
// The behavior cases
// =============================================================================

// RFC 3692 sec 2.1 reserves 253 and 254 for experimentation, so they are the protocol numbers here.
#define PROTO_A 253u
#define PROTO_B 254u
// RFC 4443 sec 2.3 numbers ICMPv6 58, the one protocol RFC 3542 sec 3.1 refuses IPV6_CHECKSUM on.
#define PROTO_ICMPV6 58u

// RFC 5737 sec 3 documentation addresses, and the two forms RFC 1122 sec 3.2.1.3 bars from a source.
static const uint8_t v4_any[IDEMIP_RAW_PCB_ADDR_BYTES] = {0};
static const uint8_t v4_a[IDEMIP_RAW_PCB_ADDR_BYTES] = {192u, 0u, 2u, 1u};
static const uint8_t v4_b[IDEMIP_RAW_PCB_ADDR_BYTES] = {192u, 0u, 2u, 2u};
static const uint8_t v4_peer[IDEMIP_RAW_PCB_ADDR_BYTES] = {192u, 0u, 2u, 9u};
static const uint8_t v4_other[IDEMIP_RAW_PCB_ADDR_BYTES] = {198u, 51u, 100u, 7u};
static const uint8_t v4_bcast[IDEMIP_RAW_PCB_ADDR_BYTES] = {255u, 255u, 255u, 255u};
static const uint8_t v4_mc_low[IDEMIP_RAW_PCB_ADDR_BYTES] = {224u, 0u, 0u, 1u};
static const uint8_t v4_mc_high[IDEMIP_RAW_PCB_ADDR_BYTES] = {239u, 255u, 255u, 250u};

// RFC 3849 sec 4 documentation prefix 2001:db8::/32, an RFC 4291 sec 2.5.6 link-local, and an
// RFC 4291 sec 2.7 multicast.
static const uint8_t v6_any[IDEMIP_RAW_PCB_ADDR_BYTES] = {0};
static const uint8_t v6_a[IDEMIP_RAW_PCB_ADDR_BYTES] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0, 0, 0, 0,
                                                        0,     0,     0,     0,     0, 0, 0, 0x01u};
static const uint8_t v6_peer[IDEMIP_RAW_PCB_ADDR_BYTES] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0, 0, 0, 0,
                                                           0,     0,     0,     0,     0, 0, 0, 0x09u};
static const uint8_t v6_ll[IDEMIP_RAW_PCB_ADDR_BYTES] = {0xFEu, 0x80u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01u};
static const uint8_t v6_mc[IDEMIP_RAW_PCB_ADDR_BYTES] = {0xFFu, 0x02u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01u};

// A build with no IPv6 layer has no version 6 to bind, so open refuses it and a v6 case stops there.
static int v6_absent(void)
{
#if IDEMIP_ENABLE_IPV6
    return 0;
#else
    return 1;
#endif
}

static uint16_t do_open(uint8_t *w, uint8_t proto, uint8_t ver)
{
    IDEMIP_RAW_PCB_IO(w)->open_args.proto = proto;
    IDEMIP_RAW_PCB_IO(w)->open_args.ip_version = ver;
    RawPcb.open(w);
    return IDEMIP_RAW_PCB_IO(w)->index;
}

static IdemIpStatus do_close(uint8_t *w, uint16_t idx)
{
    IDEMIP_RAW_PCB_IO(w)->pcb_args.index = idx;
    RawPcb.close(w);
    return IDEMIP_RAW_PCB_IO(w)->status;
}

static IdemIpStatus do_bind(uint8_t *w, uint16_t idx, const uint8_t *ip, uint8_t zone, uint8_t nif)
{
    IDEMIP_RAW_PCB_IO(w)->bind_args.index = idx;
    IDEMIP_RAW_PCB_IO(w)->bind_args.ip = ip;
    IDEMIP_RAW_PCB_IO(w)->bind_args.zone = zone;
    IDEMIP_RAW_PCB_IO(w)->bind_args.netif = nif;
    RawPcb.bind(w);
    return IDEMIP_RAW_PCB_IO(w)->status;
}

static IdemIpStatus do_connect(uint8_t *w, uint16_t idx, const uint8_t *ip, uint8_t zone)
{
    IDEMIP_RAW_PCB_IO(w)->connect_args.index = idx;
    IDEMIP_RAW_PCB_IO(w)->connect_args.ip = ip;
    IDEMIP_RAW_PCB_IO(w)->connect_args.zone = zone;
    IDEMIP_RAW_PCB_IO(w)->connect_args.netif = 0u;
    RawPcb.connect(w);
    return IDEMIP_RAW_PCB_IO(w)->status;
}

static IdemIpStatus do_disconnect(uint8_t *w, uint16_t idx)
{
    IDEMIP_RAW_PCB_IO(w)->pcb_args.index = idx;
    RawPcb.disconnect(w);
    return IDEMIP_RAW_PCB_IO(w)->status;
}

static IdemIpStatus do_opts(uint8_t *w, uint16_t idx, uint8_t tos, uint8_t ttl, uint8_t flags, int16_t cks)
{
    IDEMIP_RAW_PCB_IO(w)->opt_args.index = idx;
    IDEMIP_RAW_PCB_IO(w)->opt_args.tos = tos;
    IDEMIP_RAW_PCB_IO(w)->opt_args.ttl = ttl;
    IDEMIP_RAW_PCB_IO(w)->opt_args.flags = flags;
    IDEMIP_RAW_PCB_IO(w)->opt_args.cksum_offset = cks;
    RawPcb.set_opts(w);
    return IDEMIP_RAW_PCB_IO(w)->status;
}

static IdemIpStatus do_load(uint8_t *w, uint16_t idx)
{
    IDEMIP_RAW_PCB_IO(w)->pcb_args.index = idx;
    RawPcb.load(w);
    return IDEMIP_RAW_PCB_IO(w)->status;
}

// The RFC 1122 sec 3.4 RECV parameters of one received datagram: dst, src, prot, and the interface.
static IdemIpStatus do_find(uint8_t *w, uint8_t proto, uint8_t ver, const uint8_t *dst, const uint8_t *src,
                            uint8_t lzone, uint8_t rzone, uint8_t nif)
{
    IDEMIP_RAW_PCB_IO(w)->find_args.proto = proto;
    IDEMIP_RAW_PCB_IO(w)->find_args.ip_version = ver;
    IDEMIP_RAW_PCB_IO(w)->find_args.local_ip = dst;
    IDEMIP_RAW_PCB_IO(w)->find_args.remote_ip = src;
    IDEMIP_RAW_PCB_IO(w)->find_args.local_zone = lzone;
    IDEMIP_RAW_PCB_IO(w)->find_args.remote_zone = rzone;
    IDEMIP_RAW_PCB_IO(w)->find_args.netif = nif;
    RawPcb.find(w);
    return IDEMIP_RAW_PCB_IO(w)->status;
}

// A v4 datagram addressed to this host from its peer, on no particular interface.
static IdemIpStatus find4(uint8_t *w, uint8_t proto, const uint8_t *dst, const uint8_t *src)
{
    return do_find(w, proto, 4u, dst, src, 0u, 0u, 0u);
}

// --- open --------------------------------------------------------------------

// RFC 1122 sec 3.4 SEND(src, dst, prot, ...): an open names the prot and gets the entry that answers
// on it.
void test_open_takes_an_entry_and_reports_it(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_UINT8(PROTO_A, IDEMIP_RAW_PCB_IO(work_a)->info.proto);
    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_RAW_PCB_IO(work_a)->info.ip_version);
}

// A second open takes a different entry, so two protocol numbers coexist.
void test_two_opens_take_two_entries(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_UINT16(1u, do_open(work_a, PROTO_B, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 1u));
    TEST_ASSERT_EQUAL_UINT8(PROTO_B, IDEMIP_RAW_PCB_IO(work_a)->info.proto);
}

// RFC 1122 sec 3.2.1.6: TOS's "default is all zero bits". Sec 3.2.1.7: "A host MUST NOT send a
// datagram with a Time-to-Live (TTL) value of zero", so the default TTL is not zero. RFC 3542
// sec 3.1: "By default, this socket option is disabled", and -1 is how that is spelled.
void test_a_new_binding_carries_the_rfc_defaults(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_RAW_PCB_IO(work_a)->info.tos, "RFC 1122 sec 3.2.1.6 TOS default");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0u, IDEMIP_RAW_PCB_IO(work_a)->info.ttl, "RFC 1122 sec 3.2.1.7 bars a zero TTL");
    TEST_ASSERT_EQUAL_INT16_MESSAGE(-1, IDEMIP_RAW_PCB_IO(work_a)->info.cksum_offset,
                                    "RFC 3542 sec 3.1 disables IPV6_CHECKSUM by default");
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_FALSE, IDEMIP_RAW_PCB_IO(work_a)->info.connected);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_RAW_PCB_IO(work_a)->info.netif);
    TEST_ASSERT_EQUAL_MEMORY(v4_any, IDEMIP_RAW_PCB_IO(work_a)->info.local_ip, 4u);
}

// RFC 791 sec 3.1 is Version 4 and RFC 8200 sec 3 is Version 6. Nothing else has an IP layer here,
// and no later call gives it one, so it is ERR and never BUSY.
void test_open_refuses_a_version_that_is_not_4_or_6(void)
{
    RawPcb.clear(work_a);
    static const uint8_t bad[] = {0u, 1u, 2u, 3u, 5u, 7u, 8u, 15u, 255u};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
    {
        TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, do_open(work_a, PROTO_A, bad[i]));
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
    }
}

// A table with every entry held is BUSY, since a close frees one and the same call then succeeds.
void test_a_full_table_is_busy_and_a_close_frees_an_entry(void)
{
    RawPcb.clear(work_a);
    for (uint16_t i = 0; i < (uint16_t)IDEMIP_RAW_PCBS; i++)
    {
        TEST_ASSERT_EQUAL_UINT16(i, do_open(work_a, PROTO_A, 4u));
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);
    }
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_RAW_PCB_IO(work_a)->status,
                                  "a close frees an entry, so a full table is a retry and not a fault");

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_close(work_a, 0u));
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);
}

// --- close -------------------------------------------------------------------

// An entry no open holds cannot be released. Only another open changes that, so it is ERR.
void test_close_refuses_an_entry_no_open_holds(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_close(work_a, 0u));
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_close(work_a, 0u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, do_close(work_a, 0u), "a second close names an entry nothing holds");
}

// A closed entry answers no datagram, and reports nothing on a load.
void test_a_closed_binding_matches_nothing(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v4_a, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_close(work_a, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, IDEMIP_RAW_PCB_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_load(work_a, 0u));
}

// --- bind --------------------------------------------------------------------

// RFC 1122 sec 3.4 SEND's src, read back through load. The address the entry reports is the entry's
// own storage, so the octets survive the operand going away.
void test_bind_sets_the_send_src_and_load_reports_it(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v4_a, 0u, 3u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_MEMORY(v4_a, IDEMIP_RAW_PCB_IO(work_a)->info.local_ip, 4u);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_RAW_PCB_IO(work_a)->info.netif);

    // The address load reports is the entry's own storage inside this borrow, not the operand.
    const uint8_t *reported = IDEMIP_RAW_PCB_IO(work_a)->info.local_ip;
    TEST_ASSERT_TRUE_MESSAGE(reported >= work_a + IDEMIP_RAW_PCB_OFF_TAB, "load reported an address outside the table");
    TEST_ASSERT_TRUE_MESSAGE(reported < work_a + IDEMIP_RAW_PCB_BORROW, "load reported an address past the borrow");
}

// RFC 1122 sec 3.2.1.3 (a) { 0, 0 }: the all-zero address names none, and it is the wildcard a find
// matches against any destination.
void test_bind_accepts_the_all_zero_wildcard(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v4_any, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_MEMORY(v4_any, IDEMIP_RAW_PCB_IO(work_a)->info.local_ip, 4u);
}

// RFC 1122 sec 3.2.1.3: "the IP source address MUST be one of its own IP addresses (but not a
// broadcast or multicast address)". (c) { -1, -1 } "MUST NOT be used as a source address", and a
// Class D address is that section's multicast. No later call makes either sendable, so both are ERR.
void test_bind_refuses_a_broadcast_or_multicast_source(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, do_bind(work_a, 0u, v4_bcast, 0u, 0u),
                                  "RFC 1122 sec 3.2.1.3 (c) bars { -1, -1 } from a source address");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, do_bind(work_a, 0u, v4_mc_low, 0u, 0u),
                                  "224.0.0.1 is a Class D multicast address");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, do_bind(work_a, 0u, v4_mc_high, 0u, 0u),
                                  "239.255.255.250 is the top of Class D");
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v4_a, 0u, 0u));

    // A refused bind left the binding as it was, so the entry still holds nothing.
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_bind(work_a, 0u, v4_mc_low, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_MEMORY(v4_a, IDEMIP_RAW_PCB_IO(work_a)->info.local_ip, 4u);
}

// RFC 4291 sec 2.7: "Multicast addresses must not be used as source addresses in IPv6 packets",
// which that section's figure identifies by a leading 11111111.
void test_bind_refuses_an_ipv6_multicast_source(void)
{
    RawPcb.clear(work_a);
    do_open(work_a, PROTO_A, 6u);
    if (v6_absent())
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
        return;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_RAW_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_bind(work_a, 0u, v6_mc, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v6_a, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_MEMORY(v6_a, IDEMIP_RAW_PCB_IO(work_a)->info.local_ip, IDEMIP_RAW_PCB_ADDR_BYTES);
}

// An entry no open holds carries no version, so there is nothing to write a src into.
void test_bind_and_connect_refuse_an_entry_no_open_holds(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_bind(work_a, 0u, v4_a, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_connect(work_a, 0u, v4_peer, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_disconnect(work_a, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_opts(work_a, 0u, 0u, 64u, 0u, -1));
}

// --- connect and disconnect --------------------------------------------------

// RFC 1122 sec 3.4 SEND's dst, and the flag that says it is significant.
void test_connect_sets_the_send_dst_and_disconnect_clears_it(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_connect(work_a, 0u, v4_peer, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TRUE, IDEMIP_RAW_PCB_IO(work_a)->info.connected);
    TEST_ASSERT_EQUAL_MEMORY(v4_peer, IDEMIP_RAW_PCB_IO(work_a)->info.remote_ip, 4u);

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_disconnect(work_a, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_FALSE, IDEMIP_RAW_PCB_IO(work_a)->info.connected);
    TEST_ASSERT_EQUAL_MEMORY(v4_any, IDEMIP_RAW_PCB_IO(work_a)->info.remote_ip, 4u);
}

// A second disconnect on the same open entry is the same call on the same bytes, so it reports the
// same thing.
void test_disconnect_repeats(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_disconnect(work_a, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_disconnect(work_a, 0u));
}

// RFC 1122 sec 3.2.1.3 (a): { 0, 0 } "MUST NOT be sent, except as a source address". RFC 4291
// sec 2.5.2: "The unspecified address must not be used as the destination address of IPv6 packets."
// disconnect is the entry that leaves a binding with no dst.
void test_connect_refuses_the_unspecified_destination(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_connect(work_a, 0u, v4_any, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_FALSE, IDEMIP_RAW_PCB_IO(work_a)->info.connected);

    do_open(work_a, PROTO_B, 6u);
    if (v6_absent())
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
        return;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_connect(work_a, 1u, v6_any, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_connect(work_a, 1u, v6_peer, 0u));
}

// --- set_opts ----------------------------------------------------------------

// RFC 1122 sec 3.4: the interface "MUST provide full access to all the mechanisms of the IP layer,
// including options, Type-of-Service, and Time-to-Live".
void test_set_opts_writes_the_tos_ttl_and_flags(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 0u, 0x10u, 64u, 0x05u, -1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_UINT8(0x10u, IDEMIP_RAW_PCB_IO(work_a)->info.tos);
    TEST_ASSERT_EQUAL_UINT8(64u, IDEMIP_RAW_PCB_IO(work_a)->info.ttl);
    TEST_ASSERT_EQUAL_UINT8(0x05u, IDEMIP_RAW_PCB_IO(work_a)->info.flags);
}

// RFC 1122 sec 3.2.1.7: "A host MUST NOT send a datagram with a Time-to-Live (TTL) value of zero."
// The operand is what is wrong and the same operand fails on any later tick, so it is ERR.
void test_set_opts_refuses_a_zero_ttl(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 0u, 0u, 64u, 0u, -1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_opts(work_a, 0u, 0u, 0u, 0u, -1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(64u, IDEMIP_RAW_PCB_IO(work_a)->info.ttl, "a refused set_opts wrote nothing");
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 0u, 0u, 255u, 0u, -1));
}

// RFC 3542 sec 3.1 prints the one vector this unit has: "int offset = 2;". It "specifies an integer
// offset into the user data of where the checksum is located".
void test_set_opts_takes_the_rfc_3542_offset_of_two(void)
{
    RawPcb.clear(work_a);
    do_open(work_a, PROTO_A, 6u);
    if (v6_absent())
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
        return;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 0u, 0u, 64u, 0u, 2));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_INT16(2, IDEMIP_RAW_PCB_IO(work_a)->info.cksum_offset);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 0u, 0u, 64u, 0u, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_INT16(0, IDEMIP_RAW_PCB_IO(work_a)->info.cksum_offset);
}

// RFC 3542 sec 3.1: the option "assumes ... that the checksum field is aligned on a 16-bit
// boundary. Thus, specifying a positive odd value as offset is invalid".
void test_set_opts_refuses_an_odd_checksum_offset(void)
{
    RawPcb.clear(work_a);
    do_open(work_a, PROTO_A, 6u);
    if (v6_absent())
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
        return;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_opts(work_a, 0u, 0u, 64u, 0u, 1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_opts(work_a, 0u, 0u, 64u, 0u, 3));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_opts(work_a, 0u, 0u, 64u, 0u, 41));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 0u, 0u, 64u, 0u, 40));
}

// RFC 3542 sec 3.1: "Setting the offset to -1 also disables the option." No other negative value is
// an offset, so it is refused.
void test_minus_one_disables_the_checksum_and_no_other_negative_is_an_offset(void)
{
    RawPcb.clear(work_a);
    do_open(work_a, PROTO_A, 6u);
    if (v6_absent())
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
        return;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 0u, 0u, 64u, 0u, 2));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 0u, 0u, 64u, 0u, -1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_INT16(-1, IDEMIP_RAW_PCB_IO(work_a)->info.cksum_offset);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_opts(work_a, 0u, 0u, 64u, 0u, -2));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_opts(work_a, 0u, 0u, 64u, 0u, -100));
}

// RFC 3542 sec 3.1: "an attempt to set or get IPV6_CHECKSUM for a non-raw IPv6 socket will fail."
// An RFC 791 binding is not an IPv6 one, so only the disabling -1 is accepted on it.
void test_set_opts_refuses_a_checksum_offset_on_an_ipv4_binding(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_opts(work_a, 0u, 0u, 64u, 0u, 2));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_opts(work_a, 0u, 0u, 64u, 0u, 0));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 0u, 0u, 64u, 0u, -1));
}

// RFC 3542 sec 3.1: "An attempt to set IPV6_CHECKSUM for an ICMPv6 socket will fail", the kernel
// writing that checksum itself "since this checksum is mandatory".
void test_set_opts_refuses_a_checksum_offset_on_an_icmpv6_binding(void)
{
    RawPcb.clear(work_a);
    do_open(work_a, PROTO_ICMPV6, 6u);
    if (v6_absent())
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
        return;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_opts(work_a, 0u, 0u, 64u, 0u, 2));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 0u, 0u, 64u, 0u, -1));
    // The same offset on a binding that is not ICMPv6 is taken.
    TEST_ASSERT_EQUAL_UINT16(1u, do_open(work_a, PROTO_A, 6u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_opts(work_a, 1u, 0u, 64u, 0u, 2));
}

// --- find --------------------------------------------------------------------

// RFC 1122 sec 3.4 RECV(BufPTR, prot => ...): prot selects the binding. RFC 791 sec 3.1's Protocol
// field "indicates the next level protocol used in the data portion of the internet datagram".
void test_find_matches_on_the_protocol_number(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_RAW_PCB_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find4(work_a, PROTO_B, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, IDEMIP_RAW_PCB_IO(work_a)->index);
}

// RFC 1122 sec 3.2.1.3 (a) { 0, 0 } names no address, so the binding holding it answers whatever
// destination the datagram carried, including the section's broadcast forms.
void test_a_wildcard_binding_matches_any_local_address(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v4_any, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_RAW_PCB_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_other, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_bcast, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_mc_low, v4_peer));
}

// A binding that named a src answers only the datagram addressed to it.
void test_a_specific_binding_matches_only_its_own_local_address(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v4_a, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find4(work_a, PROTO_A, v4_b, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find4(work_a, PROTO_A, v4_other, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find4(work_a, PROTO_A, v4_bcast, v4_peer));
}

// Only four octets are an RFC 791 sec 3.1 address, so two addresses that agree on them match however
// the twelve behind them differ.
void test_a_v4_binding_compares_four_octets(void)
{
    RawPcb.clear(work_a);
    static uint8_t dirty[IDEMIP_RAW_PCB_ADDR_BYTES];
    memset(dirty, 0xA7, sizeof dirty);
    dirty[0] = 192u;
    dirty[1] = 0u;
    dirty[2] = 2u;
    dirty[3] = 1u;
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, dirty, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_load(work_a, 0u));
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v4_any, IDEMIP_RAW_PCB_IO(work_a)->info.local_ip + 4u,
                                     IDEMIP_RAW_PCB_ADDR_BYTES - 4u, "the twelve octets behind a v4 address are zero");
}

// A binding with a dst answers only a datagram from it, the condition lwIP states at
// src/core/raw.c:167-169.
void test_a_connected_binding_matches_only_its_own_remote_address(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_connect(work_a, 0u, v4_peer, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find4(work_a, PROTO_A, v4_a, v4_other));

    // Disconnected, it answers any source again.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_disconnect(work_a, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_other));
}

// lwIP src/core/udp.c:281-283 "prefer specific IPs over catch-all", and RFC 1122 sec 3.4 leaves the
// precedence unstated, so the more specific binding takes the datagram.
void test_a_specific_binding_outranks_a_wildcard(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_UINT16(1u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v4_any, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 1u, v4_a, 0u, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(1u, IDEMIP_RAW_PCB_IO(work_a)->index, "the specific binding takes it");
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_b, v4_peer));
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_RAW_PCB_IO(work_a)->index, "only the wildcard is left");
}

// lwIP src/core/udp.c:249-252: "'Perfect match' pcbs (connected to the remote port & ip address) are
// preferred. If no perfect match is found, the first unconnected pcb ... gets the datagram."
void test_a_connected_binding_outranks_an_unconnected_one(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_UINT16(1u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_connect(work_a, 1u, v4_peer, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(1u, IDEMIP_RAW_PCB_IO(work_a)->index, "the connected binding takes it");
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_other));
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_RAW_PCB_IO(work_a)->index,
                                     "the connected binding does not answer another source");
}

// Two candidates of equal rank go to the lower index, so the same table answers the same way twice.
void test_find_is_the_same_call_on_the_same_table(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_UINT16(1u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_RAW_PCB_IO(work_a)->index);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_RAW_PCB_IO(work_a)->index);
}

// RFC 791 sec 3.1 Version 4 and RFC 8200 sec 3 Version 6 are different address spaces, so a binding
// answers only the version it was opened on.
void test_find_matches_only_the_version_the_binding_was_opened_on(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, PROTO_A, 6u, v6_a, v6_peer, 0u, 0u, 0u));
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, IDEMIP_RAW_PCB_IO(work_a)->index);

    // The other way too: a version 6 binding answers no version 4 datagram.
    do_open(work_a, PROTO_B, 6u);
    if (v6_absent())
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
        return;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find4(work_a, PROTO_B, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(work_a, PROTO_B, 6u, v6_a, v6_peer, 0u, 0u, 0u));
    TEST_ASSERT_EQUAL_UINT16(1u, IDEMIP_RAW_PCB_IO(work_a)->index);
}

// A version with no IP layer in this build, and a version that is neither 4 nor 6, match nothing.
void test_find_refuses_a_version_that_is_not_4_or_6(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, PROTO_A, 0u, v4_a, v4_peer, 0u, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, PROTO_A, 5u, v4_a, v4_peer, 0u, 0u, 0u));
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, IDEMIP_RAW_PCB_IO(work_a)->index);
}

// The interface a binding is pinned to is a filter and not a rank, as lwIP applies it at
// src/core/raw.c:74-77. A binding pinned to none answers whatever interface the datagram arrived on.
void test_a_netif_pinned_binding_answers_only_that_interface(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v4_any, 0u, 2u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(work_a, PROTO_A, 4u, v4_a, v4_peer, 0u, 0u, 2u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, PROTO_A, 4u, v4_a, v4_peer, 0u, 0u, 3u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, PROTO_A, 4u, v4_a, v4_peer, 0u, 0u, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v4_any, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(work_a, PROTO_A, 4u, v4_a, v4_peer, 0u, 0u, 3u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(work_a, PROTO_A, 4u, v4_a, v4_peer, 0u, 0u, 0u));
}

// RFC 4007 sec 6: "the same non-global address may be in use in more than one zone of the same
// scope", so the zone index qualifies the address. Index zero is that section's default zone, which
// names no one zone.
void test_the_rfc_4007_zone_index_qualifies_a_link_local_address(void)
{
    RawPcb.clear(work_a);
    do_open(work_a, PROTO_A, 6u);
    if (v6_absent())
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
        return;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v6_ll, 2u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(work_a, PROTO_A, 6u, v6_ll, v6_peer, 2u, 0u, 0u));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, do_find(work_a, PROTO_A, 6u, v6_ll, v6_peer, 3u, 0u, 0u),
                                  "fe80::1 in zone 3 is not fe80::1 in zone 2");
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, PROTO_A, 6u, v6_ll, v6_peer, 0u, 0u, 0u));

    // Rebound with the default zone, the octets alone decide.
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v6_ll, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(work_a, PROTO_A, 6u, v6_ll, v6_peer, 3u, 0u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(work_a, PROTO_A, 6u, v6_ll, v6_peer, 0u, 0u, 0u));
}

// The zone of a connected dst qualifies it the same way.
void test_the_rfc_4007_zone_index_qualifies_a_connected_remote(void)
{
    RawPcb.clear(work_a);
    do_open(work_a, PROTO_A, 6u);
    if (v6_absent())
    {
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_RAW_PCB_IO(work_a)->status);
        return;
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_connect(work_a, 0u, v6_ll, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_find(work_a, PROTO_A, 6u, v6_a, v6_ll, 0u, 4u, 0u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_find(work_a, PROTO_A, 6u, v6_a, v6_ll, 0u, 5u, 0u));
}

// An empty table is ERR and never BUSY: the table is the whole answer, so waiting changes nothing.
void test_no_binding_is_err_and_not_busy(void)
{
    RawPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, find4(work_a, PROTO_A, v4_a, v4_peer),
                                  "a later tick reports the same, so retrying can never succeed");
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_RAW_PCB_NONE, IDEMIP_RAW_PCB_IO(work_a)->index);
}

// --- two borrows, two tables -------------------------------------------------

// The borrow IS the table, so a binding opened on one is invisible to the other.
void test_a_binding_on_one_borrow_matches_nothing_on_the_other(void)
{
    RawPcb.clear(work_a);
    RawPcb.clear(work_b);
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_a, PROTO_A, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, do_bind(work_a, 0u, v4_a, 0u, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_a, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find4(work_b, PROTO_A, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, do_load(work_b, 0u));

    // b's own binding answers on b and never on a.
    TEST_ASSERT_EQUAL_UINT16(0u, do_open(work_b, PROTO_B, 4u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, find4(work_b, PROTO_B, v4_a, v4_peer));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, find4(work_a, PROTO_B, v4_a, v4_peer));
}
