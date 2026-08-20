// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The storage suite for the RFC 9293 sec 3.3.1 Transmission Control Blocks. It tests the contract,
// not the protocol:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. the published offsets are ordered, non-overlapping, and inside IDEMIP_TCP_PCB_BORROW
//   5. clear zeroes the four tables and marks the borrow, and a borrow never cleared is refused
//   6. an index past a table, a missing address operand, and a state sec 3.3.2 does not name are
//      refused
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/tcp/tcp_pcb.h"

#include <stdio.h>
#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each so
// a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_TCP_PCB_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_TCP_PCB_BORROW + 16];

#define TCB_BYTES ((size_t)IDEMIP_TCP_PCBS << IDEMIP_TCP_PCB_ENTRY_SHIFT)
#define LISTEN_BYTES ((size_t)IDEMIP_TCP_LISTEN_PCBS << IDEMIP_TCP_LISTEN_ENTRY_SHIFT)
#define SEG_BYTES ((size_t)IDEMIP_TCP_SEGS << IDEMIP_TCP_SEG_ENTRY_SHIFT)
#define OOSEQ_ENTRIES ((size_t)IDEMIP_TCP_PCBS * IDEMIP_TCP_OOSEQ_SEGS)
#define OOSEQ_BYTES (OOSEQ_ENTRIES << IDEMIP_TCP_OOSEQ_ENTRY_SHIFT)
#define TABLES_BYTES (TCB_BYTES + LISTEN_BYTES + SEG_BYTES + OOSEQ_BYTES)

static const uint8_t g_local[IDEMIP_TCP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 1u};
static const uint8_t g_remote[IDEMIP_TCP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 9u};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_TCP_PCB_BORROW, CANARY, cap - IDEMIP_TCP_PCB_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_TCP_PCB_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_TCP_PCB_BORROW");
    }
}

static void check_zero(const uint8_t *w, size_t off, size_t len, const char *what)
{
    for (size_t i = 0; i < len; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0u, w[off + i], what);
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
    TcpPcb.open(w);
    TcpPcb.close(w);
    TcpPcb.bind(w);
    TcpPcb.connect(w);
    TcpPcb.load(w);
    TcpPcb.store(w);
    TcpPcb.accept(w);
    TcpPcb.listen(w);
    TcpPcb.unlisten(w);
    TcpPcb.find(w);
    TcpPcb.find_listener(w);
    TcpPcb.seg_alloc(w);
    TcpPcb.seg_load(w);
    TcpPcb.seg_sent(w);
    TcpPcb.seg_free(w);
    TcpPcb.oos_alloc(w);
    TcpPcb.oos_load(w);
    TcpPcb.oos_free(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    TcpPcb.clear(NULL);
    call_every_entry(NULL);
    TEST_PASS();
}

// The map is public, so a reader can place all five regions without opening the .c. Each starts where
// the one before it ends, and the last ends inside the borrow.
void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_TCP_PCB_OFF_IO);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_TCP_PCB_OFF_IO + sizeof(TcpPcbIo), (size_t)IDEMIP_TCP_PCB_OFF_CTX);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_TCP_PCB_OFF_TCB >= (size_t)IDEMIP_TCP_PCB_OFF_CTX,
                             "the TCB table overlaps the context");
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_TCP_PCB_OFF_TCB + TCB_BYTES, (size_t)IDEMIP_TCP_PCB_OFF_LISTEN);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_TCP_PCB_OFF_LISTEN + LISTEN_BYTES, (size_t)IDEMIP_TCP_PCB_OFF_SEG);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_TCP_PCB_OFF_SEG + SEG_BYTES, (size_t)IDEMIP_TCP_PCB_OFF_OOSEQ);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_TCP_PCB_OFF_OOSEQ + OOSEQ_BYTES <= (size_t)IDEMIP_TCP_PCB_BORROW,
                             "the out-of-order table runs past IDEMIP_TCP_PCB_BORROW");
    TEST_ASSERT_TRUE_MESSAGE(sizeof(TcpPcbIo) <= (size_t)IDEMIP_TCP_PCB_CTX_BYTES,
                             "the operand block runs into the TCB table");
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_TCP_PCB_OFF_IO, IDEMIP_TCP_PCB_IO(work_a));
}

// Zeroed, never cleared: every entry must refuse rather than read tables that were never zeroed.
void test_an_uncleared_borrow_is_refused(void)
{
    IDEMIP_TCP_PCB_IO(work_a)->bind_args.ip = g_local;
    IDEMIP_TCP_PCB_IO(work_a)->connect_args.ip = g_remote;
    IDEMIP_TCP_PCB_IO(work_a)->listen_args.ip = g_local;
    IDEMIP_TCP_PCB_IO(work_a)->find_args.local_ip = g_local;
    IDEMIP_TCP_PCB_IO(work_a)->find_args.remote_ip = g_remote;

    TcpPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.unlisten(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.find_listener(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.seg_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.seg_load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.seg_free(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.oos_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.oos_load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.oos_free(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
}

// --- clear -------------------------------------------------------------------

void test_clear_zeroes_the_four_tables(void)
{
    memset(work_a + IDEMIP_TCP_PCB_OFF_CTX, 0xEE, (size_t)IDEMIP_TCP_PCB_BORROW - IDEMIP_TCP_PCB_OFF_CTX);
    TcpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_PCB_IO(work_a)->status);
    check_zero(work_a, IDEMIP_TCP_PCB_OFF_TCB, TCB_BYTES, "clear left a TCB unzeroed");
    check_zero(work_a, IDEMIP_TCP_PCB_OFF_LISTEN, LISTEN_BYTES, "clear left a listener unzeroed");
    check_zero(work_a, IDEMIP_TCP_PCB_OFF_SEG, SEG_BYTES, "clear left a send-queue segment unzeroed");
    check_zero(work_a, IDEMIP_TCP_PCB_OFF_OOSEQ, OOSEQ_BYTES, "clear left a held segment unzeroed");
}

// A zeroed TCB is RFC 9293 sec 3.3.2's CLOSED, "the state when there is no TCB", so that is what a
// cleared borrow reports.
void test_clear_reports_no_connection(void)
{
    IDEMIP_TCP_PCB_IO(work_a)->state = IDEMIP_TCP_STATE_ESTABLISHED;
    IDEMIP_TCP_PCB_IO(work_a)->vars.snd_nxt = 0x11223344u;
    IDEMIP_TCP_PCB_IO(work_a)->ctl.cwnd = 4096u;
    TcpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_CLOSED, IDEMIP_TCP_PCB_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_PCB_IO(work_a)->vars.snd_nxt);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_PCB_IO(work_a)->ctl.cwnd);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IDEMIP_TCP_PCB_IO(work_a)->index);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_PORT_ANY, IDEMIP_TCP_PCB_IO(work_a)->port);
}

// A second clear is the same call on the same bytes, so it reports the same thing.
void test_clear_repeats(void)
{
    TcpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_PCB_IO(work_a)->status);
}

// The operand block is the caller's. clear reports through the result members and leaves the operands
// where they were.
void test_clear_leaves_the_operands_alone(void)
{
    IDEMIP_TCP_PCB_IO(work_a)->bind_args.port = 80u;
    IDEMIP_TCP_PCB_IO(work_a)->bind_args.ip = g_local;
    IDEMIP_TCP_PCB_IO(work_a)->seg_args.seq = 0xDEADBEEFu;
    TcpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_UINT16(80u, IDEMIP_TCP_PCB_IO(work_a)->bind_args.port);
    TEST_ASSERT_EQUAL_PTR(g_local, IDEMIP_TCP_PCB_IO(work_a)->bind_args.ip);
    TEST_ASSERT_EQUAL_HEX32(0xDEADBEEFu, IDEMIP_TCP_PCB_IO(work_a)->seg_args.seq);
}

#define IO(w) IDEMIP_TCP_PCB_IO(w)

static uint16_t open4(uint8_t *w)
{
    IO(w)->open_args.ip_version = 4u;
    TcpPcb.open(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(w)->status);
    TEST_ASSERT_NOT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(w)->index);
    return IO(w)->index;
}

// --- two borrows -------------------------------------------------------------

// The borrow IS the connection table, and the operand block is in it, so two tables share no byte at
// all. This is the property the whole storage model rests on: a call on one borrow reaches no byte
// of the other, and each holds its own RFC 9293 sec 3.3.1 TCBs.
void test_two_borrows_share_no_byte(void)
{
    TcpPcb.clear(work_a);
    TcpPcb.clear(work_b);

    // The same index in each borrow is a different TCB, so both can hold the same four-tuple.
    uint16_t a = open4(work_a);
    uint16_t b = open4(work_b);
    TEST_ASSERT_EQUAL_UINT16(a, b);

    IDEMIP_TCP_PCB_IO(work_a)->pcb_args.index = a;
    TcpPcb.load(work_a);
    IDEMIP_TCP_PCB_IO(work_a)->vars.snd_nxt = 1000u;
    IDEMIP_TCP_PCB_IO(work_a)->state = IDEMIP_TCP_STATE_SYN_SENT;
    IDEMIP_TCP_PCB_IO(work_a)->pcb_args.index = a;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_PCB_IO(work_a)->status);

    IDEMIP_TCP_PCB_IO(work_b)->pcb_args.index = b;
    TcpPcb.load(work_b);
    IDEMIP_TCP_PCB_IO(work_b)->vars.snd_nxt = 2000u;
    IDEMIP_TCP_PCB_IO(work_b)->state = IDEMIP_TCP_STATE_LISTEN;
    IDEMIP_TCP_PCB_IO(work_b)->pcb_args.index = b;
    TcpPcb.store(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_PCB_IO(work_b)->status);

    // b's store did not reach a's TCB.
    IDEMIP_TCP_PCB_IO(work_a)->pcb_args.index = a;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_TCP_PCB_IO(work_a)->vars.snd_nxt);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_SYN_SENT, IDEMIP_TCP_PCB_IO(work_a)->state);

    // And a whole clear on a leaves b's TCB where b put it.
    TcpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_PCB_IO(work_a)->status);
    IDEMIP_TCP_PCB_IO(work_b)->pcb_args.index = b;
    TcpPcb.load(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_PCB_IO(work_b)->status);
    TEST_ASSERT_EQUAL_UINT32(2000u, IDEMIP_TCP_PCB_IO(work_b)->vars.snd_nxt);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_LISTEN, IDEMIP_TCP_PCB_IO(work_b)->state);
}

// A clear on one borrow reaches no byte of the other's tables.
void test_a_clear_on_one_borrow_leaves_the_other_tables_untouched(void)
{
    memset(work_b + IDEMIP_TCP_PCB_OFF_TCB, 0xC3, TABLES_BYTES);
    TcpPcb.clear(work_a);
    for (size_t i = 0; i < TABLES_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[IDEMIP_TCP_PCB_OFF_TCB + i], "a clear crossed into b's tables");
    }
    TcpPcb.clear(work_b);
    check_zero(work_b, IDEMIP_TCP_PCB_OFF_TCB, TABLES_BYTES, "clear left an entry unzeroed");
}

// --- the RFC 9293 sec 3.3.2 states -------------------------------------------

// The eleven states, CLOSED first because it "represents the state when there is no TCB", which is
// what a zeroed entry holds.
void test_the_eleven_states_of_section_3_3_2(void)
{
    TEST_ASSERT_EQUAL_INT(0, (int)IDEMIP_TCP_STATE_CLOSED);
    TEST_ASSERT_EQUAL_INT(1, (int)IDEMIP_TCP_STATE_LISTEN);
    TEST_ASSERT_EQUAL_INT(2, (int)IDEMIP_TCP_STATE_SYN_SENT);
    TEST_ASSERT_EQUAL_INT(3, (int)IDEMIP_TCP_STATE_SYN_RECEIVED);
    TEST_ASSERT_EQUAL_INT(4, (int)IDEMIP_TCP_STATE_ESTABLISHED);
    TEST_ASSERT_EQUAL_INT(5, (int)IDEMIP_TCP_STATE_FIN_WAIT_1);
    TEST_ASSERT_EQUAL_INT(6, (int)IDEMIP_TCP_STATE_FIN_WAIT_2);
    TEST_ASSERT_EQUAL_INT(7, (int)IDEMIP_TCP_STATE_CLOSE_WAIT);
    TEST_ASSERT_EQUAL_INT(8, (int)IDEMIP_TCP_STATE_CLOSING);
    TEST_ASSERT_EQUAL_INT(9, (int)IDEMIP_TCP_STATE_LAST_ACK);
    TEST_ASSERT_EQUAL_INT(10, (int)IDEMIP_TCP_STATE_TIME_WAIT);
    TEST_ASSERT_EQUAL_INT((int)IDEMIP_TCP_STATES, (int)IDEMIP_TCP_STATE_TIME_WAIT + 1);
}

// A state no section 3.3.2 name maps to cannot be stored, and retrying it can never succeed.
void test_a_state_section_3_3_2_does_not_name_is_refused(void)
{
    TcpPcb.clear(work_a);
    IDEMIP_TCP_PCB_IO(work_a)->pcb_args.index = 0u;
    IDEMIP_TCP_PCB_IO(work_a)->state = (IdemIpTcpState)((int)IDEMIP_TCP_STATE_TIME_WAIT + 1);
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
}

// RFC 9293 sec 3.4: "the actual sequence number space is finite, though large. This space ranges from
// 0 to 2^32 - 1." Every one of the eleven sec 3.3.1 variables is that wide.
void test_the_section_3_3_1_variables_are_each_a_sequence_space_wide(void)
{
    TEST_ASSERT_EQUAL_size_t(11u * sizeof(uint32_t), sizeof(IdemIpTcpVars));
    IdemIpTcpVars *v = &IDEMIP_TCP_PCB_IO(work_a)->vars;
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->snd_una);
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->snd_nxt);
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->snd_wnd);
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->snd_up);
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->snd_wl1);
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->snd_wl2);
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->iss);
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->rcv_nxt);
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->rcv_wnd);
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->rcv_up);
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof v->irs);
}

// --- the bounds on an operand ------------------------------------------------

// An index no entry has is refused, and reporting it as BUSY would have the caller retry a call that
// can never succeed. Each of the four tables is bounded by its own count.
void test_an_index_past_a_table_is_refused(void)
{
    TcpPcb.clear(work_a);

    IDEMIP_TCP_PCB_IO(work_a)->pcb_args.index = (uint16_t)IDEMIP_TCP_PCBS;
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);

    IDEMIP_TCP_PCB_IO(work_a)->pcb_args.index = (uint16_t)IDEMIP_TCP_LISTEN_PCBS;
    TcpPcb.unlisten(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);

    IDEMIP_TCP_PCB_IO(work_a)->seg_args.index = (uint16_t)IDEMIP_TCP_SEGS;
    TcpPcb.seg_load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.seg_free(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);

    IDEMIP_TCP_PCB_IO(work_a)->oos_args.index = (uint16_t)OOSEQ_ENTRIES;
    TcpPcb.oos_load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.oos_free(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);

    // A queue entry names the TCB it belongs to, so that index is bounded too.
    IDEMIP_TCP_PCB_IO(work_a)->seg_args.pcb = (uint16_t)IDEMIP_TCP_PCBS;
    TcpPcb.seg_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    IDEMIP_TCP_PCB_IO(work_a)->oos_args.pcb = (uint16_t)IDEMIP_TCP_PCBS;
    TcpPcb.oos_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
}

// A bind, a connect and a listen read IDEMIP_TCP_PCB_ADDR_BYTES from the operand, so a null one is
// refused rather than dereferenced.
void test_a_missing_address_operand_is_refused(void)
{
    TcpPcb.clear(work_a);
    IDEMIP_TCP_PCB_IO(work_a)->bind_args.index = 0u;
    IDEMIP_TCP_PCB_IO(work_a)->bind_args.ip = NULL;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);

    IDEMIP_TCP_PCB_IO(work_a)->connect_args.index = 0u;
    IDEMIP_TCP_PCB_IO(work_a)->connect_args.ip = NULL;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);

    IDEMIP_TCP_PCB_IO(work_a)->listen_args.ip = NULL;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IDEMIP_TCP_PCB_IO(work_a)->index);

    IDEMIP_TCP_PCB_IO(work_a)->find_args.local_ip = g_local;
    IDEMIP_TCP_PCB_IO(work_a)->find_args.remote_ip = NULL;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);

    IDEMIP_TCP_PCB_IO(work_a)->find_args.local_ip = NULL;
    TcpPcb.find_listener(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
}

// A load that reports nothing leaves nothing of a former load behind.
void test_a_refused_load_reports_no_connection(void)
{
    TcpPcb.clear(work_a);
    IDEMIP_TCP_PCB_IO(work_a)->info.local_port = 80u;
    IDEMIP_TCP_PCB_IO(work_a)->info.local_ip = g_local;
    IDEMIP_TCP_PCB_IO(work_a)->vars.rcv_nxt = 7u;
    IDEMIP_TCP_PCB_IO(work_a)->ctl.rto = 3000u;
    IDEMIP_TCP_PCB_IO(work_a)->state = IDEMIP_TCP_STATE_ESTABLISHED;
    IDEMIP_TCP_PCB_IO(work_a)->pcb_args.index = (uint16_t)IDEMIP_TCP_PCBS;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_TCP_PCB_IO(work_a)->info.local_port);
    TEST_ASSERT_NULL(IDEMIP_TCP_PCB_IO(work_a)->info.local_ip);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_PCB_IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_PCB_IO(work_a)->ctl.rto);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_CLOSED, IDEMIP_TCP_PCB_IO(work_a)->state);
}

// A queue read that reports nothing leaves nothing of a former read behind.
void test_a_refused_queue_read_reports_no_segment(void)
{
    TcpPcb.clear(work_a);
    IDEMIP_TCP_PCB_IO(work_a)->seg.seq = 5u;
    IDEMIP_TCP_PCB_IO(work_a)->seg.len = 6u;
    IDEMIP_TCP_PCB_IO(work_a)->oos.seq = 7u;
    IDEMIP_TCP_PCB_IO(work_a)->oos.len = 8u;
    IDEMIP_TCP_PCB_IO(work_a)->seg_args.index = (uint16_t)IDEMIP_TCP_SEGS;
    IDEMIP_TCP_PCB_IO(work_a)->oos_args.index = (uint16_t)OOSEQ_ENTRIES;
    TcpPcb.seg_load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TcpPcb.oos_load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_TCP_PCB_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_PCB_IO(work_a)->seg.seq);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_TCP_PCB_IO(work_a)->seg.len);
    TEST_ASSERT_EQUAL_UINT32(0u, IDEMIP_TCP_PCB_IO(work_a)->oos.seq);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_TCP_PCB_IO(work_a)->oos.len);
}

// The out-of-order queue pins a receive descriptor per held segment, and idemip_config.h's
// IDEMIP_MAX_PINNED_FRAMES counts IDEMIP_TCP_PCBS times IDEMIP_TCP_OOSEQ_SEGS of them, so the table
// holds exactly that many.
void test_the_out_of_order_table_holds_what_the_pin_bound_counts(void)
{
    TEST_ASSERT_TRUE_MESSAGE(OOSEQ_ENTRIES <= IDEMIP_MAX_PINNED_FRAMES,
                             "the held-segment table outgrew the pin bound the receive ring is sized against");

    // What the module hands out, rather than what the macro says: every TCB fills its own hold, and
    // the next allocation on any of them is BUSY.
    TcpPcb.clear(work_a);
    size_t held = 0u;
    for (uint16_t p = 0u; p < (uint16_t)IDEMIP_TCP_PCBS; p++)
    {
        uint16_t idx = open4(work_a);
        TEST_ASSERT_NOT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, idx);
        for (uint16_t n = 0u; n < (uint16_t)IDEMIP_TCP_OOSEQ_SEGS; n++)
        {
            IDEMIP_TCP_PCB_IO(work_a)->oos_args.pcb = idx;
            IDEMIP_TCP_PCB_IO(work_a)->oos_args.seq = 1000u + (uint32_t)(n * 100u);
            IDEMIP_TCP_PCB_IO(work_a)->oos_args.len = 100u;
            IDEMIP_TCP_PCB_IO(work_a)->oos_args.desc = 0u;
            IDEMIP_TCP_PCB_IO(work_a)->oos_args.offset = 0u;
            TcpPcb.oos_alloc(work_a);
            TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_TCP_PCB_IO(work_a)->status,
                                          "a TCB refused a hold inside its own bound");
            held++;
        }
        // sec 3.10.7.4 SHLD-31 holds a segment for later processing; past the bound there is nowhere
        // to hold it, which is BUSY rather than ERR because an oos_free frees one.
        IDEMIP_TCP_PCB_IO(work_a)->oos_args.pcb = idx;
        IDEMIP_TCP_PCB_IO(work_a)->oos_args.seq = 9000u;
        TcpPcb.oos_alloc(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_TCP_PCB_IO(work_a)->status,
                                      "a TCB took a hold past IDEMIP_TCP_OOSEQ_SEGS");
    }
    TEST_ASSERT_EQUAL_size_t_MESSAGE(OOSEQ_ENTRIES, held, "the table handed out a different count than it holds");
}

// =============================================================================
// The behavior. Everything above tests the phase-2 contract; everything below
// tests the RFC 9293 logic, with the vectors the RFC's own figures print.
// =============================================================================


// A store carries the whole variable set, so a caller loads, adjusts and stores. That is the shape
// every behavior case below uses.
static IdemIpStatus put_state(uint8_t *w, uint16_t idx, IdemIpTcpState s)
{
    IO(w)->pcb_args.index = idx;
    TcpPcb.load(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(w)->status);
    IO(w)->state = s;
    IO(w)->pcb_args.index = idx;
    TcpPcb.store(w);
    return IO(w)->status;
}

static IdemIpTcpState get_state(uint8_t *w, uint16_t idx)
{
    IO(w)->pcb_args.index = idx;
    TcpPcb.load(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(w)->status);
    return IO(w)->state;
}

// The legal path into each of the eleven states, so an edge test starts from a state the TCB reached
// the way RFC 9293 says it is reached. CLOSED needs no step; the rest are walked in order.
static const IdemIpTcpState g_path[IDEMIP_TCP_STATES][4] = {
    /* CLOSED       */ {IDEMIP_TCP_STATE_CLOSED},
    /* LISTEN       */ {IDEMIP_TCP_STATE_LISTEN},
    /* SYN-SENT     */ {IDEMIP_TCP_STATE_SYN_SENT},
    /* SYN-RECEIVED */ {IDEMIP_TCP_STATE_SYN_RECEIVED},
    /* ESTABLISHED  */ {IDEMIP_TCP_STATE_SYN_SENT, IDEMIP_TCP_STATE_ESTABLISHED},
    /* FIN-WAIT-1   */ {IDEMIP_TCP_STATE_SYN_SENT, IDEMIP_TCP_STATE_ESTABLISHED, IDEMIP_TCP_STATE_FIN_WAIT_1},
    /* FIN-WAIT-2   */
    {IDEMIP_TCP_STATE_SYN_SENT, IDEMIP_TCP_STATE_ESTABLISHED, IDEMIP_TCP_STATE_FIN_WAIT_1,
     IDEMIP_TCP_STATE_FIN_WAIT_2},
    /* CLOSE-WAIT   */ {IDEMIP_TCP_STATE_SYN_SENT, IDEMIP_TCP_STATE_ESTABLISHED, IDEMIP_TCP_STATE_CLOSE_WAIT},
    /* CLOSING      */
    {IDEMIP_TCP_STATE_SYN_SENT, IDEMIP_TCP_STATE_ESTABLISHED, IDEMIP_TCP_STATE_FIN_WAIT_1,
     IDEMIP_TCP_STATE_CLOSING},
    /* LAST-ACK     */
    {IDEMIP_TCP_STATE_SYN_SENT, IDEMIP_TCP_STATE_ESTABLISHED, IDEMIP_TCP_STATE_CLOSE_WAIT,
     IDEMIP_TCP_STATE_LAST_ACK},
    /* TIME-WAIT    */
    {IDEMIP_TCP_STATE_SYN_SENT, IDEMIP_TCP_STATE_ESTABLISHED, IDEMIP_TCP_STATE_FIN_WAIT_1,
     IDEMIP_TCP_STATE_TIME_WAIT},
};

static const uint8_t g_path_len[IDEMIP_TCP_STATES] = {0u, 1u, 1u, 1u, 2u, 3u, 4u, 3u, 4u, 4u, 4u};

// A fresh borrow, one TCB, walked to the named state along the path above.
static uint16_t reach(uint8_t *w, IdemIpTcpState target)
{
    TcpPcb.clear(w);
    uint16_t idx = open4(w);
    for (uint8_t i = 0; i < g_path_len[target]; i++)
    {
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, put_state(w, idx, g_path[target][i]),
                                      "a step of the legal path into the state was refused");
    }
    TEST_ASSERT_EQUAL_INT((int)target, (int)get_state(w, idx));
    return idx;
}

// The RFC 9293 transition relation, written here from the document rather than from tcp_pcb.c. A '1'
// is a transition some section of RFC 9293 states; a '.' is one no section states. Columns and rows
// are in the sec 3.3.2 order the enum uses.
//
// row = the state the TCB is in, column = the state the store asks for
//
//                        CLOSED  LISTEN  SYNSENT SYNRCVD ESTAB   FW1     FW2     CLWAIT  CLOSING LASTACK TIMEWAIT
static const char *g_edges[IDEMIP_TCP_STATES] = {
    /* CLOSED       */ "1111.......", // sec 3.10.1 LISTEN and SYN-SENT; sec 3.10.7.2 SYN-RECEIVED
    /* LISTEN       */ "1111.......", // sec 3.10.1 SYN-SENT; sec 3.10.7.2; sec 3.10.4 CLOSED
    /* SYN-SENT     */ "1.111.....1", // sec 3.10.7.3 fourth; sec 3.10.7.3 second; sec 3.5.2 TIME-WAIT
    /* SYN-RECEIVED */ "11.111.1..1", // sec 3.10.7.4 second/fourth/fifth/eighth; sec 3.10.4; sec 3.5.2
    /* ESTABLISHED  */ "1...11.1..1", // Figure 5 CLOSE and rcv FIN; sec 3.10.5; sec 3.5.2
    /* FIN-WAIT-1   */ "1....11.1.1", // Figure 5 rcv ACK of FIN, rcv FIN; note 2 TIME-WAIT; sec 3.10.5
    /* FIN-WAIT-2   */ "1.....1...1", // Figure 5 rcv FIN TIME-WAIT; sec 3.10.5 CLOSED
    /* CLOSE-WAIT   */ "1......1.11", // Figure 5 CLOSE LAST-ACK; sec 3.10.5; sec 3.5.2
    /* CLOSING      */ "1.......1.1", // Figure 5 rcv ACK of FIN TIME-WAIT; sec 3.10.5
    /* LAST-ACK     */ "1........11", // Figure 5 rcv ACK of FIN CLOSED; sec 3.5.2
    /* TIME-WAIT    */ "1.........1", // Figure 5 Timeout=2MSL CLOSED, the one way out
};

// --- open --------------------------------------------------------------------

// RFC 9293 sec 3.10.1: "Create a new transmission control block (TCB) to hold connection state
// information." It is created in sec 3.3.2's CLOSED, which "represents the state when there is no
// TCB", with all three queues empty.
void test_open_creates_a_tcb_in_the_state_that_has_no_connection(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_CLOSED, IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8(4u, IO(work_a)->info.ip_version);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->info.unsent);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->info.unacked);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->info.ooseq);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->info.listener);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_IP_DEFAULT_TTL, IO(work_a)->info.ttl);
    TEST_ASSERT_EQUAL_UINT32(0u, IO(work_a)->vars.snd_nxt);
}

// A version naming neither RFC 791 sec 3.1 nor RFC 8200 sec 3 is refused, and no later call turns 5
// into an address family, so it is ERR rather than BUSY.
void test_open_refuses_a_version_that_names_no_address_family(void)
{
    TcpPcb.clear(work_a);
    IO(work_a)->open_args.ip_version = 0u;
    TcpPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    IO(work_a)->open_args.ip_version = 5u;
    TcpPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->index);
}

// A table with every TCB open is BUSY, since RFC 9293 sec 3.10.4's "Delete TCB" frees one. A close
// then makes the same call succeed, which is what separates BUSY from ERR.
void test_a_full_table_is_busy_and_a_close_makes_the_same_call_succeed(void)
{
    TcpPcb.clear(work_a);
    uint16_t first = open4(work_a);
    for (uint16_t i = 1u; i < IDEMIP_TCP_PCBS; i++)
    {
        (void)open4(work_a);
    }
    IO(work_a)->open_args.ip_version = 4u;
    TcpPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->index);

    IO(work_a)->pcb_args.index = first;
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->open_args.ip_version = 4u;
    TcpPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(first, IO(work_a)->index);
}

// Every open reports a TCB no other open reported, which is what makes the reported index a name.
void test_every_open_reports_a_different_tcb(void)
{
    TcpPcb.clear(work_a);
    uint16_t seen = 0u;
    for (uint16_t i = 0u; i < IDEMIP_TCP_PCBS; i++)
    {
        uint16_t idx = open4(work_a);
        TEST_ASSERT_TRUE_MESSAGE((seen & (uint16_t)(1u << idx)) == 0u, "open reported a TCB twice");
        seen = (uint16_t)(seen | (uint16_t)(1u << idx));
    }
}

// RFC 9293 sec 3.10.4 CLOSED STATE: "return 'error: connection does not exist'". A TCB that is not
// open is that case, and no retry creates it.
void test_a_call_on_a_tcb_that_is_not_open_is_refused(void)
{
    TcpPcb.clear(work_a);
    IO(work_a)->pcb_args.index = 0u;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    IO(work_a)->state = IDEMIP_TCP_STATE_CLOSED;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    IO(work_a)->bind_args.index = 0u;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = 80u;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    IO(work_a)->connect_args.index = 0u;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 80u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// --- bind and connect --------------------------------------------------------

// RFC 9293 sec 3.3.1's "local... IP address and port number", which sec 3.10.1's OPEN fills in.
void test_bind_sets_the_local_half_of_the_four_tuple(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->bind_args.index = idx;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = 80u;
    IO(work_a)->bind_args.zone = 0u;
    IO(work_a)->bind_args.netif = 3u;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(80u, IO(work_a)->port);

    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(80u, IO(work_a)->info.local_port);
    TEST_ASSERT_EQUAL_UINT8(3u, IO(work_a)->info.netif);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(g_local, IO(work_a)->info.local_ip, 4u);
    // A version 4 bind reads four octets, so the twelve past them stay zero.
    for (size_t i = 4u; i < IDEMIP_TCP_PCB_ADDR_BYTES; i++)
    {
        TEST_ASSERT_EQUAL_HEX8(0u, IO(work_a)->info.local_ip[i]);
    }
}

// RFC 6056 sec 3.2: "ephemeral port selection algorithms should use the whole range 1024-65535", and
// "Ephemeral port selection algorithms SHOULD use the largest possible port range, since this reduces
// the chances of an off-path attacker of guessing the selected port numbers." A bind of
// IDEMIP_TCP_PCB_PORT_ANY draws inside the pool and never below 1024.
void test_a_bind_of_port_any_draws_from_the_ephemeral_pool(void)
{
    TcpPcb.clear(work_a);
    uint16_t a = open4(work_a);
    uint16_t b = open4(work_a);

    IO(work_a)->bind_args.index = a;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = IDEMIP_TCP_PCB_PORT_ANY;
    IO(work_a)->bind_args.rand = 0x1234ABCDu;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint16_t p1 = IO(work_a)->port;

    IO(work_a)->bind_args.index = b;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = IDEMIP_TCP_PCB_PORT_ANY;
    IO(work_a)->bind_args.rand = 0x5678BEEFu;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint16_t p2 = IO(work_a)->port;

    TEST_ASSERT_TRUE_MESSAGE(p1 >= IDEMIP_TCP_PCB_PORT_EPH_FIRST, "a drawn port fell below the pool");
    TEST_ASSERT_TRUE_MESSAGE(p2 >= IDEMIP_TCP_PCB_PORT_EPH_FIRST, "a drawn port fell below the pool");
    TEST_ASSERT_TRUE_MESSAGE(p1 != p2, "two draws handed out the same local port");
    // sec 3.2 bounds the pool below at the first non-System Port, and above at the last port there is.
    TEST_ASSERT_TRUE_MESSAGE(p1 >= 1024u && p2 >= 1024u, "an ephemeral port must not fall in the System Ports");

    // The pool is wider than RFC 6335 sec 6's Dynamic Ports alone, which sec 3.2 says an ephemeral
    // algorithm should not confine itself to.
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_TCP_PCB_PORT_EPH_COUNT > (65535u - 49152u + 1u),
                             "the pool is no larger than the Dynamic Ports");
}

// RFC 6056 sec 3.1: "Port numbers that are currently in use by a TCP in the LISTEN state should not
// be allowed for use as ephemeral ports. If this rule is not complied with, an attacker could
// potentially 'steal' an incoming connection to a local server application in at least two different
// ways." A word that lands on a listener's port must step past it.
void test_the_ephemeral_draw_steps_over_a_port_a_listener_holds(void)
{
    TcpPcb.clear(work_a);
    // The port a zero word lands on, so the draw's first candidate is the one the listener holds.
    uint16_t served = (uint16_t)IDEMIP_TCP_PCB_PORT_EPH_FIRST;
    IO(work_a)->listen_args.ip = g_local;
    IO(work_a)->listen_args.port = served;
    IO(work_a)->listen_args.zone = 0u;
    IO(work_a)->listen_args.netif = 0u;
    IO(work_a)->listen_args.backlog = 1u;
    IO(work_a)->listen_args.ip_version = 4u;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    uint16_t idx = open4(work_a);
    IO(work_a)->bind_args.index = idx;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = IDEMIP_TCP_PCB_PORT_ANY;
    IO(work_a)->bind_args.rand = 0u;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(served, IO(work_a)->port,
                                  "the draw handed out a port a listener is serving");
    TEST_ASSERT_TRUE(IO(work_a)->port >= IDEMIP_TCP_PCB_PORT_EPH_FIRST);

    // RFC 9293 sec 3.9.1.1 MUST-42 is the converse and still holds: a named bind of that same port
    // stands, because a LISTEN must be possible alongside a connection on the same local port.
    uint16_t other = open4(work_a);
    IO(work_a)->bind_args.index = other;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = served;
    IO(work_a)->bind_args.rand = 0u;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status, "MUST-42's named bind must not be refused");
    TEST_ASSERT_EQUAL_UINT16(served, IO(work_a)->port);
}

// RFC 6056 sec 3.3: "Ephemeral port selection algorithms SHOULD obfuscate the selection of their
// ephemeral ports, since this helps to mitigate a number of attacks that depend on the attacker's
// ability to guess or know the five-tuple that identifies the transport-protocol instance to be
// attacked." sec 3.3.1 Algorithm 1 draws the first candidate as
// "min_ephemeral + (random() % num_ephemeral)", so the caller's word is what places it and two
// different words on an empty table place it differently. A cursor walked from the last draw would
// hand out the next port every time, which one observed port tells an attacker.
void test_the_ephemeral_draw_follows_the_callers_random_word(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->bind_args.index = idx;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = IDEMIP_TCP_PCB_PORT_ANY;
    IO(work_a)->bind_args.rand = 0x0F0F0F0Fu;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint16_t first = IO(work_a)->port;
    TEST_ASSERT_TRUE(first >= IDEMIP_TCP_PCB_PORT_EPH_FIRST);

    // The same empty table, a different word: a cursor would hand out the same next port either way.
    TcpPcb.clear(work_a);
    idx = open4(work_a);
    IO(work_a)->bind_args.index = idx;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = IDEMIP_TCP_PCB_PORT_ANY;
    IO(work_a)->bind_args.rand = 0xF0F0F0F0u;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint16_t second = IO(work_a)->port;
    TEST_ASSERT_TRUE(second >= IDEMIP_TCP_PCB_PORT_EPH_FIRST);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(first, second, "the draw did not follow the caller's word");

    // And the same word twice on an empty table places it the same way, so the draw is a function of
    // the word rather than of a cursor the last call moved.
    TcpPcb.clear(work_a);
    idx = open4(work_a);
    IO(work_a)->bind_args.index = idx;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = IDEMIP_TCP_PCB_PORT_ANY;
    IO(work_a)->bind_args.rand = 0x0F0F0F0Fu;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_UINT16(first, IO(work_a)->port);
}

// RFC 9293 sec 3.4.1: "A connection is defined by a pair of sockets." Two peers reaching one local
// socket are two connections, so both TCBs bind that port and the pair is what has to differ. A
// server that could not do this would serve one client per port for as long as that client stayed
// connected.
void test_two_connections_share_one_local_port_and_differ_by_the_remote_socket(void)
{
    static const uint8_t peer_b[IDEMIP_TCP_PCB_ADDR_BYTES] = {192u, 0u, 2u, 10u};
    TcpPcb.clear(work_a);
    uint16_t a = open4(work_a);
    uint16_t b = open4(work_a);

    IO(work_a)->bind_args.index = a;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = 80u;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->bind_args.index = b;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = 80u;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status,
                                  "a second connection could not take the local port the first holds");
    TEST_ASSERT_EQUAL_UINT16(80u, IO(work_a)->port);

    IO(work_a)->connect_args.index = a;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 40000u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->connect_args.index = b;
    IO(work_a)->connect_args.ip = peer_b;
    IO(work_a)->connect_args.port = 40001u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status,
                                  "two peers on one local socket are two connections");
}

// The pair is where uniqueness lives, so the same pair twice is BUSY: sec 3.10.4's "Delete TCB" frees
// it, and reporting ERR would abandon a four-tuple that is about to be free.
void test_the_same_pair_of_sockets_twice_is_busy(void)
{
    TcpPcb.clear(work_a);
    uint16_t a = open4(work_a);
    uint16_t b = open4(work_a);
    for (uint16_t idx = a; ; idx = b)
    {
        IO(work_a)->bind_args.index = idx;
        IO(work_a)->bind_args.ip = g_local;
        IO(work_a)->bind_args.port = 80u;
        TcpPcb.bind(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        if (idx == b)
        {
            break;
        }
    }

    IO(work_a)->connect_args.index = a;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 40000u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->connect_args.index = b;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 40000u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IO(work_a)->status, "one pair of sockets was held twice");

    IO(work_a)->pcb_args.index = a;
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->connect_args.index = b;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 40000u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// A rebind of the same TCB to the port it already holds is the same call on the same bytes, so it
// reports the same thing rather than colliding with itself.
void test_a_rebind_of_the_same_tcb_repeats(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    for (int i = 0; i < 2; i++)
    {
        IO(work_a)->bind_args.index = idx;
        IO(work_a)->bind_args.ip = g_local;
        IO(work_a)->bind_args.port = 443u;
        TcpPcb.bind(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT16(443u, IO(work_a)->port);
    }
}

// RFC 9293 sec 3.9.1.1 (MUST-45): "At all other times, a previous segment has either been sent or
// received on this connection, and TCP implementations MUST use the same local address that was used
// in those previous segments." The local socket is an OPEN parameter, so a TCB past sec 3.3.2's
// CLOSED refuses a bind and a connect, and no retry unsends that segment.
void test_the_local_socket_is_fixed_once_the_connection_left_closed(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_SYN_SENT));

    IO(work_a)->bind_args.index = idx;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = 80u;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->connect_args.index = idx;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 80u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// RFC 9293 sec 3.10.1: "if active and the remote socket is unspecified, return 'error: remote socket
// unspecified'". A remote port of zero is that, and no retry specifies it.
void test_connect_refuses_an_unspecified_remote_socket(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->connect_args.index = idx;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = IDEMIP_TCP_PCB_PORT_ANY;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// RFC 9293 sec 3.9.1.1 MUST-46: "A TCP implementation MUST reject as an error a local OPEN call for
// an invalid remote IP address (e.g., a broadcast or multicast address)". RFC 1122 sec 4.2.3.10
// carries the same sentence. RFC 1122 sec 3.2.1.3 adds the unspecified address, which "MUST NOT be
// used as a destination address".
void test_connect_refuses_an_invalid_remote_ip_address(void)
{
    static const uint8_t all_hosts[IDEMIP_TCP_PCB_ADDR_BYTES] = {224u, 0u, 0u, 1u};   // class D
    static const uint8_t limited[IDEMIP_TCP_PCB_ADDR_BYTES] = {255u, 255u, 255u, 255u}; // sec 3.2.1.3 (c)
    static const uint8_t unspec4[IDEMIP_TCP_PCB_ADDR_BYTES] = {0u, 0u, 0u, 0u};
    static const uint8_t *const bad4[3] = {all_hosts, limited, unspec4};

    for (size_t i = 0; i < 3u; i++)
    {
        TcpPcb.clear(work_a);
        uint16_t idx = open4(work_a);
        IO(work_a)->connect_args.index = idx;
        IO(work_a)->connect_args.ip = bad4[i];
        IO(work_a)->connect_args.port = 80u;
        TcpPcb.connect(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status,
                                      "MUST-46 rejects an invalid remote IP address");
    }

    // A unicast remote address at the same port is what MUST-46 leaves alone.
    TcpPcb.clear(work_a);
    uint16_t ok = open4(work_a);
    IO(work_a)->connect_args.index = ok;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 80u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// The same rule over RFC 4291: sec 2.7's FF00::/8 multicast and sec 2.5.2's unspecified address.
void test_connect_refuses_an_invalid_remote_ipv6_address(void)
{
    static const uint8_t all_nodes[IDEMIP_TCP_PCB_ADDR_BYTES] = {0xFFu, 0x02u, 0u, 0u, 0u, 0u, 0u, 0u,
                                                                 0u,    0u,    0u, 0u, 0u, 0u, 0u, 1u};
    static const uint8_t unspec6[IDEMIP_TCP_PCB_ADDR_BYTES] = {0u};
    static const uint8_t global6[IDEMIP_TCP_PCB_ADDR_BYTES] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0u, 0u, 0u, 0u,
                                                               0u,    0u,    0u,    0u,    0u, 0u, 0u, 1u};
    static const uint8_t *const bad6[2] = {all_nodes, unspec6};

    for (size_t i = 0; i < 2u; i++)
    {
        TcpPcb.clear(work_a);
        IO(work_a)->open_args.ip_version = 6u;
        TcpPcb.open(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        IO(work_a)->connect_args.index = IO(work_a)->index;
        IO(work_a)->connect_args.ip = bad6[i];
        IO(work_a)->connect_args.port = 80u;
        TcpPcb.connect(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status,
                                      "MUST-46 rejects an invalid remote IPv6 address");
    }

    TcpPcb.clear(work_a);
    IO(work_a)->open_args.ip_version = 6u;
    TcpPcb.open(work_a);
    IO(work_a)->connect_args.index = IO(work_a)->index;
    IO(work_a)->connect_args.ip = global6;
    IO(work_a)->connect_args.port = 80u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// RFC 9293 sec 3.4.1: "A connection is defined by a pair of sockets." Two TCBs holding one pair are
// two records for one connection, and that is BUSY rather than ERR because closing the first frees
// the pair.
void test_a_four_tuple_another_open_tcb_holds_is_busy(void)
{
    TcpPcb.clear(work_a);
    uint16_t a = open4(work_a);
    uint16_t b = open4(work_a);

    // Both are left on the unbound local socket, so the pair the connect completes is the same one.
    IO(work_a)->connect_args.index = a;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 80u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->connect_args.index = b;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 80u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);

    // Closing the first frees the pair, which is why the refusal was BUSY and not ERR.
    IO(work_a)->pcb_args.index = a;
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->connect_args.index = b;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 80u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    // A different remote port is a different pair, so it is not refused.
    uint16_t c = open4(work_a);
    IO(work_a)->connect_args.index = c;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 443u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// --- the sec 3.3.1 variables round trip --------------------------------------

// RFC 9293 sec 3.3.1 Table 2 and Table 3, and the estimator and congestion state beside them, move
// between one TCB and the operand block whole.
void test_a_store_and_a_load_round_trip_every_variable(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);

    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->vars.snd_una = 100u;
    IO(work_a)->vars.snd_nxt = 101u;
    IO(work_a)->vars.snd_wnd = 65535u * 4u;
    IO(work_a)->vars.snd_up = 7u;
    IO(work_a)->vars.snd_wl1 = 300u;
    IO(work_a)->vars.snd_wl2 = 101u;
    IO(work_a)->vars.iss = 100u;
    IO(work_a)->vars.rcv_nxt = 301u;
    IO(work_a)->vars.rcv_wnd = IDEMIP_TCP_WND;
    IO(work_a)->vars.rcv_up = 9u;
    IO(work_a)->vars.irs = 300u;
    IO(work_a)->ctl.rto = 3000u;
    IO(work_a)->ctl.cwnd = 2u * IDEMIP_TCP_MSS;
    IO(work_a)->ctl.ssthresh = IDEMIP_TCP_WND;
    IO(work_a)->ctl.mss = IDEMIP_TCP_MSS;
    IO(work_a)->ctl.snd_scale = 7u;
    IO(work_a)->ctl.rcv_scale = 2u;
    IO(work_a)->ctl.sack_left[0] = 1000u;
    IO(work_a)->ctl.sack_right[0] = 1500u;
    IO(work_a)->state = IDEMIP_TCP_STATE_SYN_SENT;
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    memset(&IO(work_a)->vars, 0, sizeof IO(work_a)->vars);
    memset(&IO(work_a)->ctl, 0, sizeof IO(work_a)->ctl);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(100u, IO(work_a)->vars.snd_una);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.snd_nxt);
    TEST_ASSERT_EQUAL_UINT32(65535u * 4u, IO(work_a)->vars.snd_wnd);
    TEST_ASSERT_EQUAL_UINT32(7u, IO(work_a)->vars.snd_up);
    TEST_ASSERT_EQUAL_UINT32(300u, IO(work_a)->vars.snd_wl1);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.snd_wl2);
    TEST_ASSERT_EQUAL_UINT32(100u, IO(work_a)->vars.iss);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_TCP_WND, IO(work_a)->vars.rcv_wnd);
    TEST_ASSERT_EQUAL_UINT32(9u, IO(work_a)->vars.rcv_up);
    TEST_ASSERT_EQUAL_UINT32(300u, IO(work_a)->vars.irs);
    TEST_ASSERT_EQUAL_UINT32(3000u, IO(work_a)->ctl.rto);
    TEST_ASSERT_EQUAL_UINT32(2u * IDEMIP_TCP_MSS, IO(work_a)->ctl.cwnd);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_TCP_WND, IO(work_a)->ctl.ssthresh);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_MSS, IO(work_a)->ctl.mss);
    TEST_ASSERT_EQUAL_UINT8(7u, IO(work_a)->ctl.snd_scale);
    TEST_ASSERT_EQUAL_UINT8(2u, IO(work_a)->ctl.rcv_scale);
    TEST_ASSERT_EQUAL_UINT32(1000u, IO(work_a)->ctl.sack_left[0]);
    TEST_ASSERT_EQUAL_UINT32(1500u, IO(work_a)->ctl.sack_right[0]);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_SYN_SENT, IO(work_a)->state);
}

// Every octet of TcpPcbCtl, not the handful the test above names. A store and a load are the only
// way the estimator, congestion, option and keepalive state of a TCB reaches a caller, so a field
// added to the struct or reordered inside it must still survive the trip.
void test_a_store_and_a_load_round_trip_every_octet_of_the_control_state(void)
{
    TcpPcbCtl want;
    for (size_t i = 0; i < sizeof want; i++)
    {
        ((uint8_t *)&want)[i] = (uint8_t)(0xA5u ^ (uint8_t)i); // distinct per octet, so a swap shows
    }
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    IO(work_a)->ctl = want;
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    memset(&IO(work_a)->ctl, 0, sizeof IO(work_a)->ctl);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&want, &IO(work_a)->ctl, sizeof want,
                                     "an octet of the control state did not survive a store and a load");
}

// RFC 9293 sec 3.8.3 MUST-21: "An application MUST be able to set the value for R2 for a particular
// connection", and sec 3.9.1.9 MUST-48: "The application layer MUST be able to specify the
// Differentiated Services field for segments that are sent on a connection." sec 3.10.1's OPEN fills
// both in.
void test_opt_sets_the_diffserv_field_and_the_r2_thresholds(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);

    // An open leaves R2 at the two bounds sec 3.8.3 asks for, and the Diffserv field at zero.
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_TCP_MAXRTX, IO(work_a)->ctl.r2);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_TCP_SYNMAXRTX, IO(work_a)->ctl.r2_syn);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->info.tos);

    IO(work_a)->opt_args.index = idx;
    IO(work_a)->opt_args.tos = 0xB8u; // RFC 2474 sec 4.2.1's EF codepoint in the six high bits
    IO(work_a)->opt_args.ttl = 32u;
    IO(work_a)->opt_args.r2 = 20u;
    IO(work_a)->opt_args.r2_syn = 10u;
    TcpPcb.opt(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xB8u, IO(work_a)->info.tos, "MUST-48's Diffserv field is settable");
    TEST_ASSERT_EQUAL_UINT8(32u, IO(work_a)->info.ttl);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(20u, IO(work_a)->ctl.r2, "MUST-21's R2 is settable per connection");
    TEST_ASSERT_EQUAL_UINT8(10u, IO(work_a)->ctl.r2_syn);

    // Clause (d): "an interactive application might set R2 to 'infinity'", which is a threshold of
    // zero here.
    IO(work_a)->opt_args.index = idx;
    IO(work_a)->opt_args.r2 = 0u;
    IO(work_a)->opt_args.r2_syn = 0u;
    TcpPcb.opt(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->ctl.r2);

    // An index that names no open TCB is ERR.
    IO(work_a)->opt_args.index = (uint16_t)IDEMIP_TCP_PCBS;
    TcpPcb.opt(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// RFC 9293 sec 3.8.3 MUST-23: "R2 for a SYN segment MUST be set large enough to provide
// retransmission of the segment for at least 3 minutes." RFC 6298 (5.5) doubles RTO on each expiry
// from IDEMIP_TCP_RTO_INIT_MS under the IDEMIP_TCP_RTO_MAX_MS bound, so the default threshold has to
// carry the schedule past 180000 milliseconds.
void test_the_default_syn_r2_carries_three_minutes_of_retransmission(void)
{
    uint32_t rto = (uint32_t)IDEMIP_TCP_RTO_INIT_MS;
    uint32_t at = 0u;
    for (uint8_t n = 0u; n < (uint8_t)IDEMIP_TCP_SYNMAXRTX; n++)
    {
        at += rto;
        rto <<= 1;
        if (rto > (uint32_t)IDEMIP_TCP_RTO_MAX_MS)
        {
            rto = (uint32_t)IDEMIP_TCP_RTO_MAX_MS;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(at >= 180000u, "MUST-23 wants at least 3 minutes before the SYN is given up on");

    // sec 3.8.3 SHLD-11: "The value of R2 SHOULD correspond to at least 100 seconds."
    rto = (uint32_t)IDEMIP_TCP_RTO_INIT_MS;
    at = 0u;
    for (uint8_t n = 0u; n < (uint8_t)IDEMIP_TCP_MAXRTX; n++)
    {
        at += rto;
        rto <<= 1;
        if (rto > (uint32_t)IDEMIP_TCP_RTO_MAX_MS)
        {
            rto = (uint32_t)IDEMIP_TCP_RTO_MAX_MS;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(at >= 100000u, "SHLD-11 wants R2 to correspond to at least 100 seconds");
}

// RFC 7323 sec 2.2 shifts the 16-bit Window field left by Snd.Wind.Shift, up to
// IDEMIP_TCP_WS_MAX, so SND.WND must carry a value wider than the field it came from.
void test_the_send_window_carries_a_shifted_window_field(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    uint32_t shifted = (uint32_t)0xFFFFu << IDEMIP_TCP_WS_MAX;
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    IO(work_a)->vars.snd_wnd = shifted;
    IO(work_a)->state = IDEMIP_TCP_STATE_CLOSED;
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_HEX32(shifted, IO(work_a)->vars.snd_wnd);
}

// A store whose state operand names none of the eleven is refused even on an open TCB, so the check
// on the operand is separate from the check on the entry.
void test_an_unnamed_state_is_refused_on_an_open_tcb(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->pcb_args.index = idx;
    IO(work_a)->state = (IdemIpTcpState)((int)IDEMIP_TCP_STATE_TIME_WAIT + 1);
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_CLOSED, (int)get_state(work_a, idx));
}

// --- the sec 3.3.2 state machine ---------------------------------------------

// The relation table is read by column index, so a row of the wrong length would silently shift
// every destination after the typo.
void test_the_transition_relation_table_is_square(void)
{
    for (int from = 0; from < (int)IDEMIP_TCP_STATES; from++)
    {
        TEST_ASSERT_EQUAL_size_t_MESSAGE((size_t)IDEMIP_TCP_STATES, strlen(g_edges[from]),
                                         "a row of the transition relation is not eleven wide");
        for (int to = 0; to < (int)IDEMIP_TCP_STATES; to++)
        {
            TEST_ASSERT_TRUE_MESSAGE(g_edges[from][to] == '1' || g_edges[from][to] == '.',
                                     "a cell of the transition relation is neither set nor clear");
        }
    }
}

// The whole eleven by eleven transition relation, checked against the table above, which was written
// from RFC 9293 rather than from the code. Figure 5 "is only a summary and must not be taken as the
// total specification", so the table also carries sec 3.5.2, sec 3.5.3 and sec 3.10 edges.
void test_every_transition_matches_the_relation_rfc_9293_states(void)
{
    for (int from = 0; from < (int)IDEMIP_TCP_STATES; from++)
    {
        for (int to = 0; to < (int)IDEMIP_TCP_STATES; to++)
        {
            uint16_t idx = reach(work_a, (IdemIpTcpState)from);
            IdemIpStatus got = put_state(work_a, idx, (IdemIpTcpState)to);
            char msg[96];
            snprintf(msg, sizeof msg, "transition %d -> %d", from, to);
            if (g_edges[from][to] == '1')
            {
                TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, got, msg);
                TEST_ASSERT_EQUAL_INT_MESSAGE(to, (int)get_state(work_a, idx), msg);
            }
            else
            {
                TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, got, msg);
                TEST_ASSERT_EQUAL_INT_MESSAGE(from, (int)get_state(work_a, idx), msg);
            }
        }
    }
}

// A store that does not change the state is a variable update, and RFC 9293 sec 3.10.7.4 updates
// variables in every one of the eight states it names, so it is permitted from all eleven.
void test_a_store_that_leaves_the_state_alone_is_permitted_everywhere(void)
{
    for (int s = 0; s < (int)IDEMIP_TCP_STATES; s++)
    {
        uint16_t idx = reach(work_a, (IdemIpTcpState)s);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, (IdemIpTcpState)s));
    }
}

// RFC 9293 sec 3.5 Figure 6, the "simplest 3WHS", from the active peer's side: A picks ISS 100 and
// sends <SEQ=100><CTL=SYN>, receives <SEQ=300><ACK=101><CTL=SYN,ACK>, and reaches ESTABLISHED with
// SND.NXT 101 and RCV.NXT 301.
void test_the_three_way_handshake_of_figure_6_from_the_active_side(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);

    // Line 2: sec 3.10.1 "Set SND.UNA to ISS, SND.NXT to ISS+1, enter SYN-SENT state".
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    IO(work_a)->vars.iss = 100u;
    IO(work_a)->vars.snd_una = 100u;
    IO(work_a)->vars.snd_nxt = 101u;
    IO(work_a)->state = IDEMIP_TCP_STATE_SYN_SENT;
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    // Line 3: sec 3.10.7.3 fourth "RCV.NXT is set to SEG.SEQ+1, IRS is set to SEG.SEQ. SND.UNA
    // should be advanced to equal SEG.ACK", then "change the connection state to ESTABLISHED".
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    IO(work_a)->vars.irs = 300u;
    IO(work_a)->vars.rcv_nxt = 301u;
    IO(work_a)->vars.snd_una = 101u;
    IO(work_a)->state = IDEMIP_TCP_STATE_ESTABLISHED;
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_ESTABLISHED, IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.snd_nxt);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(100u, IO(work_a)->vars.iss);
    TEST_ASSERT_EQUAL_UINT32(300u, IO(work_a)->vars.irs);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.snd_una);
}

// RFC 9293 sec 3.5 Figure 6 from the passive peer's side: B is reached through a listener, so its TCB
// enters the machine at SYN-RECEIVED per sec 3.10.7.2 "The connection state should be changed to
// SYN-RECEIVED", with "SND.NXT is set to ISS+1 and SND.UNA to ISS".
void test_the_three_way_handshake_of_figure_6_from_the_passive_side(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);

    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    IO(work_a)->vars.irs = 100u;
    IO(work_a)->vars.rcv_nxt = 101u;
    IO(work_a)->vars.iss = 300u;
    IO(work_a)->vars.snd_una = 300u;
    IO(work_a)->vars.snd_nxt = 301u;
    IO(work_a)->state = IDEMIP_TCP_STATE_SYN_RECEIVED;
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    // Line 4: sec 3.10.7.4 fifth SYN-RECEIVED "If SND.UNA < SEG.ACK =< SND.NXT, then enter
    // ESTABLISHED state and continue processing with ... SND.WND <- SEG.WND, SND.WL1 <- SEG.SEQ,
    // SND.WL2 <- SEG.ACK".
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    IO(work_a)->vars.snd_una = 301u;
    IO(work_a)->vars.snd_wnd = 4096u;
    IO(work_a)->vars.snd_wl1 = 101u;
    IO(work_a)->vars.snd_wl2 = 301u;
    IO(work_a)->state = IDEMIP_TCP_STATE_ESTABLISHED;
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_ESTABLISHED, IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->vars.snd_nxt);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT32(101u, IO(work_a)->vars.snd_wl1);
    TEST_ASSERT_EQUAL_UINT32(301u, IO(work_a)->vars.snd_wl2);
}

// RFC 9293 sec 3.5 Figure 7: "Each TCP peer's connection state cycles from CLOSED to SYN-SENT to
// SYN-RECEIVED to ESTABLISHED." A TCP implementation MUST support simultaneous open (MUST-10).
void test_the_simultaneous_open_of_figure_7(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_SYN_SENT));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_SYN_RECEIVED));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_ESTABLISHED));
}

// RFC 9293 sec 3.5 Figure 8 line 5: A sends <SEQ=91><CTL=RST> and B "on receiving the RST, returns to
// the LISTEN state", which sec 3.5.3 makes conditional on SYN-RECEIVED having come from LISTEN.
void test_the_old_duplicate_syn_recovery_of_figure_8(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    IO(work_a)->vars.irs = 90u;
    IO(work_a)->vars.rcv_nxt = 91u;
    IO(work_a)->vars.iss = 300u;
    IO(work_a)->vars.snd_nxt = 301u;
    IO(work_a)->state = IDEMIP_TCP_STATE_SYN_RECEIVED;
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_LISTEN));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_LISTEN, (int)get_state(work_a, idx));
}

// RFC 9293 sec 3.6 Figure 12: A closes, so FIN-WAIT-1, then FIN-WAIT-2 on the ACK of its FIN, then
// TIME-WAIT on B's FIN, then CLOSED after 2 MSL. Every step is one store, and the last is a close.
void test_the_normal_close_of_figure_12_from_the_closing_side(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_SYN_SENT));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_ESTABLISHED));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_FIN_WAIT_1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_FIN_WAIT_2));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_TIME_WAIT));
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// RFC 9293 sec 3.6 Figure 12 from B's side: CLOSE-WAIT on A's FIN, LAST-ACK on its own CLOSE, then
// CLOSED on "rcv ACK of FIN".
void test_the_normal_close_of_figure_12_from_the_closed_upon_side(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_SYN_RECEIVED));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_ESTABLISHED));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_CLOSE_WAIT));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_LAST_ACK));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_CLOSED));
}

// RFC 9293 sec 3.6 Figure 13: both peers close, so FIN-WAIT-1, CLOSING on the peer's FIN, TIME-WAIT
// on the ACK of the local FIN.
void test_the_simultaneous_close_of_figure_13(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_SYN_SENT));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_ESTABLISHED));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_FIN_WAIT_1));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_CLOSING));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_TIME_WAIT));
}

// RFC 9293 Figure 5 note 2: "The figure omits a transition from FIN-WAIT-1 to TIME-WAIT if a FIN is
// received and the local FIN is also acknowledged." sec 3.10.7.4 eighth states it.
void test_figure_5_note_2_reaches_time_wait_straight_from_fin_wait_1(void)
{
    uint16_t idx = reach(work_a, IDEMIP_TCP_STATE_FIN_WAIT_1);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_TIME_WAIT));
}

// RFC 9293 sec 3.5.2: "The side of a connection issuing a reset should enter the TIME-WAIT state."
// Every synchronized state of sec 3.5.2 group 3, and SYN-SENT and SYN-RECEIVED of group 2, can
// therefore be left for TIME-WAIT.
void test_issuing_a_reset_reaches_time_wait_from_every_state_that_has_a_peer(void)
{
    static const IdemIpTcpState from[] = {
        IDEMIP_TCP_STATE_SYN_SENT,    IDEMIP_TCP_STATE_SYN_RECEIVED, IDEMIP_TCP_STATE_ESTABLISHED,
        IDEMIP_TCP_STATE_FIN_WAIT_1,  IDEMIP_TCP_STATE_FIN_WAIT_2,   IDEMIP_TCP_STATE_CLOSE_WAIT,
        IDEMIP_TCP_STATE_CLOSING,     IDEMIP_TCP_STATE_LAST_ACK,     IDEMIP_TCP_STATE_TIME_WAIT,
    };
    for (size_t i = 0; i < sizeof from / sizeof from[0]; i++)
    {
        uint16_t idx = reach(work_a, from[i]);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_TIME_WAIT));
    }
}

// RFC 9293 sec 3.5.2 group 1: a reset sent from CLOSED means "The connection remains in the CLOSED
// state", and group 2 keeps LISTEN in "the same state", so neither reaches TIME-WAIT.
void test_a_reset_from_closed_or_listen_does_not_reach_time_wait(void)
{
    uint16_t idx = reach(work_a, IDEMIP_TCP_STATE_CLOSED);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, put_state(work_a, idx, IDEMIP_TCP_STATE_TIME_WAIT));
    idx = reach(work_a, IDEMIP_TCP_STATE_LISTEN);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, put_state(work_a, idx, IDEMIP_TCP_STATE_TIME_WAIT));
}

// RFC 9293 Figure 5: TIME-WAIT leaves for CLOSED on "Timeout=2MSL delete TCB" and nowhere else. That
// one exit is also why RFC 1337 sec 3 fix (F1), "Ignore RST segments in TIME-WAIT state", cannot be
// enforced here: the 2 MSL timeout and a RST would both ask for the same edge, and only the segment
// tells them apart.
void test_time_wait_leaves_only_for_closed(void)
{
    for (int to = 0; to < (int)IDEMIP_TCP_STATES; to++)
    {
        uint16_t idx = reach(work_a, IDEMIP_TCP_STATE_TIME_WAIT);
        IdemIpStatus got = put_state(work_a, idx, (IdemIpTcpState)to);
        if (to == (int)IDEMIP_TCP_STATE_TIME_WAIT || to == (int)IDEMIP_TCP_STATE_CLOSED)
        {
            TEST_ASSERT_EQUAL_INT(IDEMIP_OK, got);
        }
        else
        {
            TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, got);
        }
    }
}

// RFC 9293 sec 3.5.3: "If the receiver was in SYN-RECEIVED state and had previously been in the
// LISTEN state, then the receiver returns to the LISTEN state; otherwise, the receiver aborts the
// connection and goes to the CLOSED state." So SYN-RECEIVED is the only state that reaches LISTEN
// from inside the machine, which narrows Figure 5 note 3's "a transition to LISTEN or CLOSED".
void test_only_syn_received_returns_to_listen(void)
{
    for (int from = 0; from < (int)IDEMIP_TCP_STATES; from++)
    {
        uint16_t idx = reach(work_a, (IdemIpTcpState)from);
        IdemIpStatus got = put_state(work_a, idx, IDEMIP_TCP_STATE_LISTEN);
        if (from == (int)IDEMIP_TCP_STATE_SYN_RECEIVED || from == (int)IDEMIP_TCP_STATE_LISTEN ||
            from == (int)IDEMIP_TCP_STATE_CLOSED)
        {
            TEST_ASSERT_EQUAL_INT(IDEMIP_OK, got);
        }
        else
        {
            TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, got);
        }
    }
}

// RFC 9293 sec 3.10.5 ABORT reaches CLOSED from every state, so a store to CLOSED is permitted from
// all eleven and a close is too.
void test_abort_reaches_closed_from_every_state(void)
{
    for (int from = 0; from < (int)IDEMIP_TCP_STATES; from++)
    {
        uint16_t idx = reach(work_a, (IdemIpTcpState)from);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, put_state(work_a, idx, IDEMIP_TCP_STATE_CLOSED));
        idx = reach(work_a, (IdemIpTcpState)from);
        IO(work_a)->pcb_args.index = idx;
        TcpPcb.close(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }
}

// --- find --------------------------------------------------------------------

// RFC 9293 sec 3.3.1 keys a TCB on "the local and remote IP addresses and port numbers", and an
// arriving segment's own pair is swapped against it: its Destination Port is the local port.
void test_find_matches_the_swapped_four_tuple_of_a_segment(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->bind_args.index = idx;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = 1025u;
    IO(work_a)->bind_args.netif = 0u;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->connect_args.index = idx;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 80u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->find_args.local_ip = g_local;
    IO(work_a)->find_args.remote_ip = g_remote;
    IO(work_a)->find_args.local_port = 1025u;
    IO(work_a)->find_args.remote_port = 80u;
    IO(work_a)->find_args.ip_version = 4u;
    IO(work_a)->find_args.netif = 1u;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(idx, IO(work_a)->index);

    // One field off in each direction, and the segment names no TCB.
    IO(work_a)->find_args.remote_port = 81u;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    IO(work_a)->find_args.remote_port = 80u;
    IO(work_a)->find_args.local_port = 1026u;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    IO(work_a)->find_args.local_port = 1025u;
    IO(work_a)->find_args.remote_ip = g_local;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    IO(work_a)->find_args.remote_ip = g_remote;
    IO(work_a)->find_args.ip_version = 6u;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->index);
}

// A TCB pinned to an interface matches only segments that arrived on it; one pinned to none matches
// any. RFC 1122 sec 3.3.4.2 is what a multihomed host binds a connection to an interface for.
void test_find_honors_the_interface_a_connection_is_pinned_to(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->bind_args.index = idx;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = 1025u;
    IO(work_a)->bind_args.netif = 2u;
    TcpPcb.bind(work_a);
    IO(work_a)->connect_args.index = idx;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 80u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->find_args.local_ip = g_local;
    IO(work_a)->find_args.remote_ip = g_remote;
    IO(work_a)->find_args.local_port = 1025u;
    IO(work_a)->find_args.remote_port = 80u;
    IO(work_a)->find_args.ip_version = 4u;
    IO(work_a)->find_args.netif = 2u;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->find_args.netif = 3u;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// RFC 9293 sec 3.10.7.1: "If the state is CLOSED (i.e., TCB does not exist)". No TCB is that case,
// reported as ERR because the same segment matches no better on a later tick.
void test_a_segment_that_names_no_tcb_is_the_closed_case(void)
{
    TcpPcb.clear(work_a);
    IO(work_a)->find_args.local_ip = g_local;
    IO(work_a)->find_args.remote_ip = g_remote;
    IO(work_a)->find_args.local_port = 80u;
    IO(work_a)->find_args.remote_port = 1025u;
    IO(work_a)->find_args.ip_version = 4u;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->index);
}

// --- listeners ---------------------------------------------------------------

// RFC 9293 sec 3.9.1.1: "Every passive OPEN call either creates a new connection record in LISTEN
// state, or it returns an error; it MUST NOT affect any previously created connection record"
// (MUST-41).
void test_listen_creates_a_record_in_the_listen_state(void)
{
    TcpPcb.clear(work_a);
    IO(work_a)->listen_args.ip = g_local;
    IO(work_a)->listen_args.port = 80u;
    IO(work_a)->listen_args.zone = 0u;
    IO(work_a)->listen_args.netif = 0u;
    IO(work_a)->listen_args.backlog = 4u;
    IO(work_a)->listen_args.ip_version = 4u;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint16_t l = IO(work_a)->index;
    TEST_ASSERT_NOT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, l);

    IO(work_a)->find_args.local_ip = g_local;
    IO(work_a)->find_args.local_port = 80u;
    IO(work_a)->find_args.ip_version = 4u;
    IO(work_a)->find_args.netif = 1u;
    TcpPcb.find_listener(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(l, IO(work_a)->index);

    IO(work_a)->pcb_args.index = l;
    TcpPcb.unlisten(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TcpPcb.find_listener(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TcpPcb.unlisten(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// A passive OPEN names the local socket a segment must arrive on, so a port of zero names none and no
// retry names one. It is ERR, not BUSY.
void test_a_passive_open_on_port_zero_is_refused(void)
{
    TcpPcb.clear(work_a);
    IO(work_a)->listen_args.ip = g_local;
    IO(work_a)->listen_args.port = IDEMIP_TCP_PCB_PORT_ANY;
    IO(work_a)->listen_args.ip_version = 4u;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    IO(work_a)->listen_args.port = 80u;
    IO(work_a)->listen_args.ip_version = 5u;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// A second passive OPEN on one local socket is BUSY, since an unlisten frees it, and a table with
// every listener taken is BUSY for the same reason.
void test_a_second_passive_open_on_one_socket_is_busy(void)
{
    TcpPcb.clear(work_a);
    IO(work_a)->listen_args.ip = g_local;
    IO(work_a)->listen_args.port = 80u;
    IO(work_a)->listen_args.ip_version = 4u;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint16_t first = IO(work_a)->index;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);

    IO(work_a)->pcb_args.index = first;
    TcpPcb.unlisten(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->listen_args.ip = g_local;
    IO(work_a)->listen_args.port = 80u;
    IO(work_a)->listen_args.ip_version = 4u;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// A listener table with every record taken is BUSY.
void test_a_full_listener_table_is_busy(void)
{
    TcpPcb.clear(work_a);
    for (uint16_t i = 0u; i < IDEMIP_TCP_LISTEN_PCBS; i++)
    {
        IO(work_a)->listen_args.ip = g_local;
        IO(work_a)->listen_args.port = (uint16_t)(1000u + i);
        IO(work_a)->listen_args.ip_version = 4u;
        TcpPcb.listen(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }
    IO(work_a)->listen_args.port = 2000u;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->index);
}

// RFC 9293 sec 3.9.1.1: "If the parameter is unspecified, a passive OPEN will await an incoming
// connection request to any local IP address". An all-zero local address is that, and a listener
// bound to the destination is preferred over it.
void test_a_bound_listener_is_matched_before_an_unspecified_one(void)
{
    static const uint8_t any[IDEMIP_TCP_PCB_ADDR_BYTES] = {0};
    TcpPcb.clear(work_a);

    IO(work_a)->listen_args.ip = any;
    IO(work_a)->listen_args.port = 80u;
    IO(work_a)->listen_args.ip_version = 4u;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint16_t wild = IO(work_a)->index;

    IO(work_a)->find_args.local_ip = g_local;
    IO(work_a)->find_args.local_port = 80u;
    IO(work_a)->find_args.ip_version = 4u;
    TcpPcb.find_listener(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(wild, IO(work_a)->index);

    IO(work_a)->listen_args.ip = g_local;
    IO(work_a)->listen_args.port = 80u;
    IO(work_a)->listen_args.ip_version = 4u;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint16_t bound = IO(work_a)->index;
    TEST_ASSERT_TRUE(bound != wild);

    IO(work_a)->find_args.local_ip = g_local;
    IO(work_a)->find_args.local_port = 80u;
    IO(work_a)->find_args.ip_version = 4u;
    TcpPcb.find_listener(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(bound, IO(work_a)->index);

    // A destination the bound listener does not hold still reaches the unspecified one.
    IO(work_a)->find_args.local_ip = g_remote;
    TcpPcb.find_listener(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(wild, IO(work_a)->index);
}

// --- the send queue ----------------------------------------------------------

// RFC 9293 sec 3.3.1's "pointers to the retransmit queue and to the current segment". Segments queue
// in the order they were handed over, and a seg_load walks the queue by its next field.
void test_the_send_queue_keeps_the_order_segments_were_queued_in(void)
{
    static const uint8_t data[8] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u};
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    uint16_t got[3];
    const uint32_t seq[3] = {101u, 601u, 1101u};
    for (int i = 0; i < 3; i++)
    {
        IO(work_a)->seg_args.pcb = pcb;
        IO(work_a)->seg_args.data = data;
        IO(work_a)->seg_args.seq = seq[i];
        IO(work_a)->seg_args.len = 8u;
        IO(work_a)->seg_args.flags = IDEMIP_TCP_ACK;
        IO(work_a)->seg_args.opts = 0u;
        TcpPcb.seg_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        got[i] = IO(work_a)->index;
    }

    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_UINT16(got[0], IO(work_a)->info.unsent);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->info.unacked);

    uint16_t at = got[0];
    for (int i = 0; i < 3; i++)
    {
        IO(work_a)->seg_args.index = at;
        TcpPcb.seg_load(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT32(seq[i], IO(work_a)->seg.seq);
        TEST_ASSERT_EQUAL_UINT16(8u, IO(work_a)->seg.len);
        TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_ACK, IO(work_a)->seg.flags);
        TEST_ASSERT_EQUAL_PTR(data, IO(work_a)->seg.data);
        TEST_ASSERT_EQUAL_UINT16(pcb, IO(work_a)->seg.pcb);
        at = IO(work_a)->seg.next;
    }
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, at);
}

// RFC 9293 sec 3.3.1 Table 4 SEG.LEN counts the data octets, so a segment with octets must name them
// and a segment with none must not. Neither mistake becomes valid on a retry.
void test_a_segment_with_octets_must_name_them(void)
{
    static const uint8_t data[4] = {1u, 2u, 3u, 4u};
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);

    IO(work_a)->seg_args.pcb = pcb;
    IO(work_a)->seg_args.data = NULL;
    IO(work_a)->seg_args.len = 4u;
    TcpPcb.seg_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->seg_args.data = data;
    IO(work_a)->seg_args.len = 0u;
    TcpPcb.seg_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    // RFC 9293 sec 3.1: a segment that carries only control bits carries no data.
    IO(work_a)->seg_args.data = NULL;
    IO(work_a)->seg_args.len = 0u;
    IO(work_a)->seg_args.flags = IDEMIP_TCP_SYN;
    TcpPcb.seg_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// A table with every segment queued is BUSY, since RFC 9293 sec 3.4 case (b)'s removal from the
// retransmission queue frees one.
void test_a_full_segment_table_is_busy_and_a_free_makes_the_same_call_succeed(void)
{
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    uint16_t first = IDEMIP_TCP_PCB_NONE;
    for (uint16_t i = 0u; i < IDEMIP_TCP_SEGS; i++)
    {
        IO(work_a)->seg_args.pcb = pcb;
        IO(work_a)->seg_args.data = NULL;
        IO(work_a)->seg_args.len = 0u;
        IO(work_a)->seg_args.seq = i;
        TcpPcb.seg_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        if (i == 0u)
        {
            first = IO(work_a)->index;
        }
    }
    TcpPcb.seg_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->index);

    IO(work_a)->seg_args.index = first;
    TcpPcb.seg_free(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->seg_args.pcb = pcb;
    IO(work_a)->seg_args.data = NULL;
    IO(work_a)->seg_args.len = 0u;
    TcpPcb.seg_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// RFC 9293 sec 3.4 case (b), "to remove the segment from a retransmission queue". A segment taken out
// of the middle leaves the queue linked around it, and a second free of it is refused.
void test_a_segment_freed_from_the_middle_leaves_the_queue_linked(void)
{
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    uint16_t got[3];
    for (int i = 0; i < 3; i++)
    {
        IO(work_a)->seg_args.pcb = pcb;
        IO(work_a)->seg_args.data = NULL;
        IO(work_a)->seg_args.len = 0u;
        IO(work_a)->seg_args.seq = (uint32_t)(100 + i);
        TcpPcb.seg_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        got[i] = IO(work_a)->index;
    }

    IO(work_a)->seg_args.index = got[1];
    TcpPcb.seg_free(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TcpPcb.seg_free(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TcpPcb.seg_load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->seg_args.index = got[0];
    TcpPcb.seg_load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(got[2], IO(work_a)->seg.next);
    IO(work_a)->seg_args.index = got[2];
    TcpPcb.seg_load(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->seg.next);
}

// A close takes the TCB's whole send queue with it, so the segments return to the table.
void test_a_close_frees_every_segment_the_connection_queued(void)
{
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    for (uint16_t i = 0u; i < IDEMIP_TCP_SEGS; i++)
    {
        IO(work_a)->seg_args.pcb = pcb;
        IO(work_a)->seg_args.data = NULL;
        IO(work_a)->seg_args.len = 0u;
        IO(work_a)->seg_args.seq = i;
        TcpPcb.seg_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }
    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    uint16_t again = open4(work_a);
    for (uint16_t i = 0u; i < IDEMIP_TCP_SEGS; i++)
    {
        IO(work_a)->seg_args.pcb = again;
        IO(work_a)->seg_args.data = NULL;
        IO(work_a)->seg_args.len = 0u;
        TcpPcb.seg_alloc(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status, "a close leaked a send-queue segment");
    }
}

// --- the out-of-order queue --------------------------------------------------

// RFC 9293 sec 3.10.7.4: "Initial tests on arrival are used to discard old duplicates, but further
// processing is done in SEG.SEQ order." Held segments arriving out of order are linked in that order.
void test_held_segments_are_linked_in_seg_seq_order(void)
{
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.load(work_a);
    IO(work_a)->vars.rcv_nxt = 1000u;
    IO(work_a)->state = IDEMIP_TCP_STATE_CLOSED;
    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    const uint32_t arrival[4] = {3000u, 1500u, 4000u, 2000u};
    const uint32_t sorted[4] = {1500u, 2000u, 3000u, 4000u};
    for (int i = 0; i < 4; i++)
    {
        IO(work_a)->oos_args.pcb = pcb;
        IO(work_a)->oos_args.seq = arrival[i];
        IO(work_a)->oos_args.desc = (uint16_t)i;
        IO(work_a)->oos_args.offset = 54u;
        IO(work_a)->oos_args.len = 500u;
        TcpPcb.oos_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }

    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.load(work_a);
    uint16_t at = IO(work_a)->info.ooseq;
    for (int i = 0; i < 4; i++)
    {
        TEST_ASSERT_TRUE_MESSAGE(at < OOSEQ_ENTRIES, "the held queue ended early");
        IO(work_a)->oos_args.index = at;
        TcpPcb.oos_load(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT32(sorted[i], IO(work_a)->oos.seq);
        TEST_ASSERT_EQUAL_UINT16(500u, IO(work_a)->oos.len);
        TEST_ASSERT_EQUAL_UINT16(54u, IO(work_a)->oos.offset);
        TEST_ASSERT_EQUAL_UINT16(pcb, IO(work_a)->oos.pcb);
        at = IO(work_a)->oos.next;
    }
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, at);
}

// RFC 9293 sec 3.4: "the actual sequence number space is finite, though large. This space ranges from
// 0 to 2^32 - 1... all arithmetic dealing with sequence numbers must be performed modulo 2^32." Held
// segments straddling the wrap order by their distance forward from RCV.NXT, so a segment at
// 0x00000040 follows one at 0xFFFFFFC0.
void test_held_segments_order_across_the_sequence_space_wrap(void)
{
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.load(work_a);
    IO(work_a)->vars.rcv_nxt = 0xFFFFFF00u;
    IO(work_a)->state = IDEMIP_TCP_STATE_CLOSED;
    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    const uint32_t arrival[3] = {0x00000040u, 0xFFFFFF80u, 0xFFFFFFC0u};
    const uint32_t sorted[3] = {0xFFFFFF80u, 0xFFFFFFC0u, 0x00000040u};
    for (int i = 0; i < 3; i++)
    {
        IO(work_a)->oos_args.pcb = pcb;
        IO(work_a)->oos_args.seq = arrival[i];
        IO(work_a)->oos_args.len = 32u;
        IO(work_a)->oos_args.desc = (uint16_t)i;
        TcpPcb.oos_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }

    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.load(work_a);
    uint16_t at = IO(work_a)->info.ooseq;
    for (int i = 0; i < 3; i++)
    {
        IO(work_a)->oos_args.index = at;
        TcpPcb.oos_load(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        TEST_ASSERT_EQUAL_HEX32(sorted[i], IO(work_a)->oos.seq);
        at = IO(work_a)->oos.next;
    }
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, at);
}

// A held segment pins a receive descriptor, and PLAN sec 3.5 bounds the pins by
// IDEMIP_TCP_PCBS times IDEMIP_TCP_OOSEQ_SEGS, so one connection holds at most
// IDEMIP_TCP_OOSEQ_SEGS. Past that it is BUSY: an oos_free drops a pin and frees one.
void test_one_connection_holds_at_most_the_oos_bound_and_then_is_busy(void)
{
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    uint16_t first = IDEMIP_TCP_PCB_NONE;
    for (uint16_t i = 0u; i < IDEMIP_TCP_OOSEQ_SEGS; i++)
    {
        IO(work_a)->oos_args.pcb = pcb;
        IO(work_a)->oos_args.seq = (uint32_t)(1000u + (i * 100u));
        IO(work_a)->oos_args.len = 100u;
        IO(work_a)->oos_args.desc = i;
        TcpPcb.oos_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        if (i == 0u)
        {
            first = IO(work_a)->index;
        }
    }
    IO(work_a)->oos_args.seq = 9000u;
    TcpPcb.oos_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->index);

    IO(work_a)->oos_args.index = first;
    TcpPcb.oos_free(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TcpPcb.oos_free(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->oos_args.pcb = pcb;
    IO(work_a)->oos_args.seq = 9000u;
    IO(work_a)->oos_args.len = 100u;
    TcpPcb.oos_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// The hold is per connection, so a second connection still has its own IDEMIP_TCP_OOSEQ_SEGS.
void test_the_hold_bound_is_per_connection(void)
{
    TcpPcb.clear(work_a);
    uint16_t a = open4(work_a);
    uint16_t b = open4(work_a);
    for (uint16_t i = 0u; i < IDEMIP_TCP_OOSEQ_SEGS; i++)
    {
        IO(work_a)->oos_args.pcb = a;
        IO(work_a)->oos_args.seq = (uint32_t)(1000u + (i * 100u));
        IO(work_a)->oos_args.len = 100u;
        TcpPcb.oos_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }
    IO(work_a)->oos_args.pcb = a;
    TcpPcb.oos_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    IO(work_a)->oos_args.pcb = b;
    IO(work_a)->oos_args.seq = 500u;
    IO(work_a)->oos_args.len = 100u;
    TcpPcb.oos_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// A held segment with no octets holds nothing, so it is refused.
void test_a_held_segment_with_no_octets_is_refused(void)
{
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    IO(work_a)->oos_args.pcb = pcb;
    IO(work_a)->oos_args.seq = 1000u;
    IO(work_a)->oos_args.len = 0u;
    TcpPcb.oos_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// A close cannot take the hold with it. Every held segment names a receive descriptor the caller
// pinned, and RFC 9293 sec 3.10.7.4's release is the only thing that reports one back, so sec 3.10.4's
// "Delete TCB" is BUSY while the hold is not empty and leaves every entry standing.
void test_a_close_is_busy_while_the_hold_still_names_a_pinned_descriptor(void)
{
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    for (uint16_t i = 0u; i < IDEMIP_TCP_OOSEQ_SEGS; i++)
    {
        IO(work_a)->oos_args.pcb = pcb;
        IO(work_a)->oos_args.seq = (uint32_t)(1000u + (i * 100u));
        IO(work_a)->oos_args.len = 100u;
        IO(work_a)->oos_args.desc = (uint16_t)(i + 1u);
        TcpPcb.oos_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }
    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IO(work_a)->status, "a close discarded the pinned frames");

    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status, "a BUSY close deleted the TCB anyway");
    uint16_t at = IO(work_a)->info.ooseq;
    for (uint16_t i = 0u; i < IDEMIP_TCP_OOSEQ_SEGS; i++)
    {
        TEST_ASSERT_TRUE_MESSAGE(at < OOSEQ_ENTRIES, "a BUSY close shortened the hold");
        IO(work_a)->oos_args.index = at;
        TcpPcb.oos_load(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT16_MESSAGE((uint16_t)(i + 1u), IO(work_a)->oos.desc,
                                         "a held segment lost the descriptor it pins");
        at = IO(work_a)->oos.next;
    }
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, at);
}

// Draining the hold through oos_free reports every pinned descriptor back, one per call, and the
// close that was BUSY then completes sec 3.10.4's "Delete TCB" with the whole hold accounted for.
void test_a_close_succeeds_once_the_hold_is_drained(void)
{
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    for (uint16_t i = 0u; i < IDEMIP_TCP_OOSEQ_SEGS; i++)
    {
        IO(work_a)->oos_args.pcb = pcb;
        IO(work_a)->oos_args.seq = (uint32_t)(1000u + (i * 100u));
        IO(work_a)->oos_args.len = 100u;
        IO(work_a)->oos_args.desc = (uint16_t)(i + 1u);
        TcpPcb.oos_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }
    for (uint16_t i = 0u; i < IDEMIP_TCP_OOSEQ_SEGS; i++)
    {
        IO(work_a)->pcb_args.index = pcb;
        TcpPcb.load(work_a);
        uint16_t head = IO(work_a)->info.ooseq;
        TEST_ASSERT_TRUE_MESSAGE(head < OOSEQ_ENTRIES, "the hold ran out before every frame came back");
        IO(work_a)->oos_args.index = head;
        TcpPcb.oos_load(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT16_MESSAGE((uint16_t)(i + 1u), IO(work_a)->oos.desc,
                                         "the drain reported a descriptor that was never pinned");
        IO(work_a)->oos_args.index = head;
        IO(work_a)->oos_args.pcb = pcb;
        TcpPcb.oos_free(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }
    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status, "a drained connection would not close");
    for (uint16_t i = 0u; i < OOSEQ_ENTRIES; i++)
    {
        IO(work_a)->oos_args.index = i;
        TcpPcb.oos_load(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "a held segment outlived the close");
    }
}

// --- two borrows -------------------------------------------------------------

// The borrow IS the table, so a connection opened in one is invisible in the other. This is the
// property the storage model rests on, checked here against logic rather than against a memset.
void test_a_connection_in_one_borrow_is_invisible_in_the_other(void)
{
    TcpPcb.clear(work_a);
    TcpPcb.clear(work_b);

    uint16_t idx = open4(work_a);
    IO(work_a)->bind_args.index = idx;
    IO(work_a)->bind_args.ip = g_local;
    IO(work_a)->bind_args.port = 1025u;
    TcpPcb.bind(work_a);
    IO(work_a)->connect_args.index = idx;
    IO(work_a)->connect_args.ip = g_remote;
    IO(work_a)->connect_args.port = 80u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_b)->find_args.local_ip = g_local;
    IO(work_b)->find_args.remote_ip = g_remote;
    IO(work_b)->find_args.local_port = 1025u;
    IO(work_b)->find_args.remote_port = 80u;
    IO(work_b)->find_args.ip_version = 4u;
    TcpPcb.find(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_b)->status);

    IO(work_a)->find_args.local_ip = g_local;
    IO(work_a)->find_args.remote_ip = g_remote;
    IO(work_a)->find_args.local_port = 1025u;
    IO(work_a)->find_args.remote_port = 80u;
    IO(work_a)->find_args.ip_version = 4u;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(idx, IO(work_a)->index);

    // The same local port is free in b, so its bind is not refused by a's.
    uint16_t other = open4(work_b);
    IO(work_b)->bind_args.index = other;
    IO(work_b)->bind_args.ip = g_local;
    IO(work_b)->bind_args.port = 1025u;
    TcpPcb.bind(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_b)->status);
}

// --- an IPv6 connection ------------------------------------------------------

// RFC 4291 sec 2: "IPv6 addresses are 128-bit identifiers", so all sixteen octets are keyed on, and
// RFC 4007 sec 6 zone indices qualify a non-global one.
void test_an_ipv6_connection_keys_on_all_sixteen_octets_and_its_zone(void)
{
    static const uint8_t l6[IDEMIP_TCP_PCB_ADDR_BYTES] = {0xFEu, 0x80u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01u};
    static const uint8_t r6[IDEMIP_TCP_PCB_ADDR_BYTES] = {0xFEu, 0x80u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02u};
    static const uint8_t r6b[IDEMIP_TCP_PCB_ADDR_BYTES] = {0xFEu, 0x80u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03u};
    TcpPcb.clear(work_a);
    IO(work_a)->open_args.ip_version = 6u;
    TcpPcb.open(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint16_t idx = IO(work_a)->index;

    IO(work_a)->bind_args.index = idx;
    IO(work_a)->bind_args.ip = l6;
    IO(work_a)->bind_args.port = 1025u;
    IO(work_a)->bind_args.zone = 2u;
    TcpPcb.bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->connect_args.index = idx;
    IO(work_a)->connect_args.ip = r6;
    IO(work_a)->connect_args.port = 80u;
    IO(work_a)->connect_args.zone = 2u;
    TcpPcb.connect(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->find_args.local_ip = l6;
    IO(work_a)->find_args.remote_ip = r6;
    IO(work_a)->find_args.local_port = 1025u;
    IO(work_a)->find_args.remote_port = 80u;
    IO(work_a)->find_args.ip_version = 6u;
    IO(work_a)->find_args.local_zone = 2u;
    IO(work_a)->find_args.remote_zone = 2u;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(idx, IO(work_a)->index);

    // The sixteenth octet alone differs, so the segment names no TCB.
    IO(work_a)->find_args.remote_ip = r6b;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    // The zone alone differs, and RFC 4007 sec 6 makes that a different address.
    IO(work_a)->find_args.remote_ip = r6;
    IO(work_a)->find_args.remote_zone = 3u;
    TcpPcb.find(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// --- MAX.SND.WND, the listener writer and the sent mark ------------------------

// RFC 9293 sec 3.3.1 names eleven variables and no more. RFC 5961 sec 5.2's MAX.SND.WND is not one of
// them, so it rides in the control state and the eleven stay eleven.
void test_max_snd_wnd_is_not_one_of_the_eleven_section_3_3_1_variables(void)
{
    TEST_ASSERT_EQUAL_size_t(11u * sizeof(uint32_t), sizeof(IdemIpTcpVars));
    TEST_ASSERT_EQUAL_size_t(sizeof(uint32_t), sizeof IO(work_a)->ctl.max_snd_wnd);
}

// RFC 5961 sec 5.2: "A new state variable MAX.SND.WND is defined as the largest window that the local
// sender has ever received from its peer. This window may be scaled to a value larger than 65,535
// bytes", so it round-trips through a store at the full 32-bit width.
void test_max_snd_wnd_round_trips_a_scaled_window(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    IO(work_a)->ctl.max_snd_wnd = 0xFFFFu << 14; // RFC 7323 sec 2.2's largest scaled window
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.store(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    memset(&IO(work_a)->ctl, 0, sizeof IO(work_a)->ctl);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)0xFFFFu << 14, IO(work_a)->ctl.max_snd_wnd);
}

// RFC 9293 sec 3.5 (MUST-11): "a TCP implementation MUST keep track of whether a connection has
// reached SYN-RECEIVED state as the result of a passive OPEN or an active OPEN". A fresh TCB names no
// listener, an accept records one, and IDEMIP_TCP_PCB_NONE takes it back to the active OPEN.
void test_accept_records_the_listener_a_connection_came_through(void)
{
    TcpPcb.clear(work_a);
    IO(work_a)->listen_args.ip = g_local;
    IO(work_a)->listen_args.port = 80u;
    IO(work_a)->listen_args.ip_version = 4u;
    TcpPcb.listen(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    uint16_t lis = IO(work_a)->index;

    uint16_t idx = open4(work_a);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->info.listener);

    IO(work_a)->accept_args.index = idx;
    IO(work_a)->accept_args.listener = lis;
    TcpPcb.accept(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_UINT16(lis, IO(work_a)->info.listener);

    IO(work_a)->accept_args.index = idx;
    IO(work_a)->accept_args.listener = IDEMIP_TCP_PCB_NONE;
    TcpPcb.accept(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    IO(work_a)->pcb_args.index = idx;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->info.listener);
}

// A listener no passive OPEN took names nothing for the connection to have arrived through, and no
// retry makes it one.
void test_accept_refuses_a_listener_no_passive_open_took(void)
{
    TcpPcb.clear(work_a);
    uint16_t idx = open4(work_a);
    IO(work_a)->accept_args.index = idx;
    IO(work_a)->accept_args.listener = 0u;
    TcpPcb.accept(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->accept_args.listener = (uint16_t)IDEMIP_TCP_LISTEN_PCBS;
    TcpPcb.accept(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->accept_args.index = (uint16_t)IDEMIP_TCP_PCBS;
    IO(work_a)->accept_args.listener = IDEMIP_TCP_PCB_NONE;
    TcpPcb.accept(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// RFC 9293 sec 3.3.1's "pointers to the retransmit queue". A sent segment leaves the head of the
// unsent queue for the tail of the retransmission queue, and both keep their order.
void test_seg_sent_moves_the_head_of_unsent_onto_the_retransmit_queue(void)
{
    static const uint8_t data[4] = {9u, 9u, 9u, 9u};
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    uint16_t got[3];
    for (int i = 0; i < 3; i++)
    {
        IO(work_a)->seg_args.pcb = pcb;
        IO(work_a)->seg_args.data = data;
        IO(work_a)->seg_args.seq = (uint32_t)(100 + (i * 4));
        IO(work_a)->seg_args.len = 4u;
        IO(work_a)->seg_args.flags = IDEMIP_TCP_ACK;
        IO(work_a)->seg_args.opts = 0u;
        TcpPcb.seg_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        got[i] = IO(work_a)->index;
    }

    for (int i = 0; i < 2; i++)
    {
        IO(work_a)->seg_args.index = got[i];
        TcpPcb.seg_sent(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }

    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.load(work_a);
    TEST_ASSERT_EQUAL_UINT16(got[2], IO(work_a)->info.unsent);
    TEST_ASSERT_EQUAL_UINT16(got[0], IO(work_a)->info.unacked);

    IO(work_a)->seg_args.index = got[0];
    TcpPcb.seg_load(work_a);
    TEST_ASSERT_EQUAL_UINT16(got[1], IO(work_a)->seg.next);
    IO(work_a)->seg_args.index = got[1];
    TcpPcb.seg_load(work_a);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->seg.next);
    IO(work_a)->seg_args.index = got[2];
    TcpPcb.seg_load(work_a);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, IO(work_a)->seg.next);
}

// Segments leave the queue in the order they were built, so anything but the head is a broken link.
void test_seg_sent_refuses_a_segment_that_is_not_the_head_of_unsent(void)
{
    static const uint8_t data[4] = {1u, 1u, 1u, 1u};
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    uint16_t got[2];
    for (int i = 0; i < 2; i++)
    {
        IO(work_a)->seg_args.pcb = pcb;
        IO(work_a)->seg_args.data = data;
        IO(work_a)->seg_args.seq = (uint32_t)(200 + (i * 4));
        IO(work_a)->seg_args.len = 4u;
        IO(work_a)->seg_args.flags = 0u;
        IO(work_a)->seg_args.opts = 0u;
        TcpPcb.seg_alloc(work_a);
        got[i] = IO(work_a)->index;
    }

    IO(work_a)->seg_args.index = got[1];
    TcpPcb.seg_sent(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->seg_args.index = (uint16_t)IDEMIP_TCP_SEGS;
    TcpPcb.seg_sent(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    // A segment already marked sent is off the unsent queue, so a second mark is refused too.
    IO(work_a)->seg_args.index = got[0];
    TcpPcb.seg_sent(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TcpPcb.seg_sent(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// A close releases both queues, so a segment marked sent goes with the connection.
void test_a_close_frees_the_segments_on_the_retransmit_queue_too(void)
{
    static const uint8_t data[4] = {2u, 2u, 2u, 2u};
    TcpPcb.clear(work_a);
    uint16_t pcb = open4(work_a);
    for (int i = 0; i < (int)IDEMIP_TCP_SEGS; i++)
    {
        IO(work_a)->seg_args.pcb = pcb;
        IO(work_a)->seg_args.data = data;
        IO(work_a)->seg_args.seq = (uint32_t)(300 + (i * 4));
        IO(work_a)->seg_args.len = 4u;
        IO(work_a)->seg_args.flags = 0u;
        IO(work_a)->seg_args.opts = 0u;
        TcpPcb.seg_alloc(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        uint16_t seg = IO(work_a)->index;
        IO(work_a)->seg_args.index = seg;
        TcpPcb.seg_sent(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    }

    IO(work_a)->pcb_args.index = pcb;
    TcpPcb.close(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    uint16_t again = open4(work_a);
    IO(work_a)->seg_args.pcb = again;
    IO(work_a)->seg_args.data = data;
    IO(work_a)->seg_args.seq = 900u;
    IO(work_a)->seg_args.len = 4u;
    IO(work_a)->seg_args.flags = 0u;
    IO(work_a)->seg_args.opts = 0u;
    TcpPcb.seg_alloc(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}
