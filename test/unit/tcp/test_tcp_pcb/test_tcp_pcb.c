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

#include "idemIP/tcp/tcp_pcb.h"

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
    TcpPcb.listen(w);
    TcpPcb.unlisten(w);
    TcpPcb.find(w);
    TcpPcb.find_listener(w);
    TcpPcb.seg_alloc(w);
    TcpPcb.seg_load(w);
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

// --- two borrows -------------------------------------------------------------

// The borrow IS the connection table, and the operand block is in it, so two tables share no byte at
// all. This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_TCP_PCB_IO(work_a)->vars.snd_nxt = 1000u;
    IDEMIP_TCP_PCB_IO(work_a)->state = IDEMIP_TCP_STATE_SYN_SENT;
    IDEMIP_TCP_PCB_IO(work_b)->vars.snd_nxt = 2000u;
    IDEMIP_TCP_PCB_IO(work_b)->state = IDEMIP_TCP_STATE_LISTEN;

    // Setting b's operands did not disturb a's.
    TEST_ASSERT_EQUAL_UINT32(1000u, IDEMIP_TCP_PCB_IO(work_a)->vars.snd_nxt);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_SYN_SENT, IDEMIP_TCP_PCB_IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT32(2000u, IDEMIP_TCP_PCB_IO(work_b)->vars.snd_nxt);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_LISTEN, IDEMIP_TCP_PCB_IO(work_b)->state);

    TcpPcb.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_PCB_IO(work_a)->status);

    // And b's operands are still b's after a's call.
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
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_TCP_PCBS * IDEMIP_TCP_OOSEQ_SEGS, OOSEQ_ENTRIES);
    TEST_ASSERT_TRUE_MESSAGE(OOSEQ_ENTRIES <= IDEMIP_MAX_PINNED_FRAMES,
                             "the held-segment table outgrew the pin bound the receive ring is sized against");
}
