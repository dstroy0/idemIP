// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp_pcb.c
 * @brief The RFC 9293 sec 3.3.1 Transmission Control Blocks and their three queues, in the caller's
 *        borrow.
 *
 * The context and the four tables are regions of the one pointer each entry is handed, at
 * compile-time offsets, and no entry reads or writes a byte outside it. Two borrows therefore share
 * nothing, and the same call on the same borrow does the same thing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_TCP

#include "idemIP/tcp/tcp_pcb.h"

IDEMIP_BEGIN_DECLS

// One TCB: RFC 9293 sec 3.3.1's "local and remote IP addresses and port numbers", the Table 2 send
// variables and Table 3 receive variables, the sec 3.3.2 state, the estimator and congestion state,
// and the heads of the three queues this connection draws on.
typedef struct
{
    uint8_t local_ip[IDEMIP_TCP_PCB_ADDR_BYTES];
    uint8_t remote_ip[IDEMIP_TCP_PCB_ADDR_BYTES];
    IdemIpTcpVars vars;
    TcpPcbCtl ctl;
    uint16_t local_port;
    uint16_t remote_port;
    uint16_t listener;
    uint16_t unsent;
    uint16_t unacked;
    uint16_t ooseq;
    uint8_t local_zone;
    uint8_t remote_zone;
    uint8_t netif;
    uint8_t tos;
    uint8_t ttl;
    uint8_t ip_version;
    IdemIpTcpState state;
    idemip_bool in_use;
} TcpPcbTcbFields;

// One listener: the RFC 9293 sec 3.3.2 passive OPEN's address and port, and the connections it holds
// in SYN-RECEIVED.
typedef struct
{
    uint8_t local_ip[IDEMIP_TCP_PCB_ADDR_BYTES];
    uint16_t local_port;
    uint8_t local_zone;
    uint8_t netif;
    uint8_t backlog;
    uint8_t accepts_pending;
    uint8_t ip_version;
    IdemIpTcpState state;
    idemip_bool in_use;
} TcpPcbListenFields;

// One send-queue segment: the caller's data octets, their RFC 9293 sec 3.1 Sequence Number, the
// control bits and options the segment carries, and the next segment on the same queue.
typedef struct
{
    const uint8_t *data;
    uint32_t seq;
    uint16_t next;
    uint16_t pcb;
    uint16_t len;
    uint16_t flags;
    uint16_t opts;
    idemip_bool in_use;
} TcpPcbSegFields;

// One held out-of-order segment: the pinned receive descriptor, where in that frame the data starts,
// its Sequence Number and length, and the next held segment on the same queue.
typedef struct
{
    uint32_t seq;
    uint16_t next;
    uint16_t pcb;
    uint16_t desc;
    uint16_t offset;
    uint16_t len;
    idemip_bool in_use;
} TcpPcbOosFields;

// Entry i of each table sits at (i << SHIFT), so each entry is exactly that wide.
typedef union
{
    TcpPcbTcbFields f;
    uint8_t raw[1u << IDEMIP_TCP_PCB_ENTRY_SHIFT];
} TcpPcbTcbEntry;

typedef union
{
    TcpPcbListenFields f;
    uint8_t raw[1u << IDEMIP_TCP_LISTEN_ENTRY_SHIFT];
} TcpPcbListenEntry;

typedef union
{
    TcpPcbSegFields f;
    uint8_t raw[1u << IDEMIP_TCP_SEG_ENTRY_SHIFT];
} TcpPcbSegEntry;

typedef union
{
    TcpPcbOosFields f;
    uint8_t raw[1u << IDEMIP_TCP_OOSEQ_ENTRY_SHIFT];
} TcpPcbOosEntry;

static_assert(sizeof(TcpPcbTcbEntry) == (1u << IDEMIP_TCP_PCB_ENTRY_SHIFT),
              "a TCB must be 1 << IDEMIP_TCP_PCB_ENTRY_SHIFT wide - raise the shift in idemip_config.h");
static_assert(sizeof(TcpPcbTcbFields) <= sizeof(TcpPcbTcbEntry),
              "the RFC 9293 sec 3.3.1 field set outgrew one TCB - raise IDEMIP_TCP_PCB_ENTRY_SHIFT");
static_assert(sizeof(TcpPcbListenEntry) == (1u << IDEMIP_TCP_LISTEN_ENTRY_SHIFT),
              "a listener must be 1 << IDEMIP_TCP_LISTEN_ENTRY_SHIFT wide - raise the shift in idemip_config.h");
static_assert(sizeof(TcpPcbListenFields) <= sizeof(TcpPcbListenEntry),
              "the passive OPEN field set outgrew one listener - raise IDEMIP_TCP_LISTEN_ENTRY_SHIFT");
static_assert(sizeof(TcpPcbSegEntry) == (1u << IDEMIP_TCP_SEG_ENTRY_SHIFT),
              "a send-queue segment must be 1 << IDEMIP_TCP_SEG_ENTRY_SHIFT wide - raise the shift in "
              "idemip_config.h");
static_assert(sizeof(TcpPcbSegFields) <= sizeof(TcpPcbSegEntry),
              "the send-queue field set outgrew one segment - raise IDEMIP_TCP_SEG_ENTRY_SHIFT");
static_assert(sizeof(TcpPcbOosEntry) == (1u << IDEMIP_TCP_OOSEQ_ENTRY_SHIFT),
              "a held segment must be 1 << IDEMIP_TCP_OOSEQ_ENTRY_SHIFT wide - raise the shift in idemip_config.h");
static_assert(sizeof(TcpPcbOosFields) <= sizeof(TcpPcbOosEntry),
              "the out-of-order field set outgrew one entry - raise IDEMIP_TCP_OOSEQ_ENTRY_SHIFT");

// The one definition, private to this TU. A borrow that was never cleared carries no mark, so every
// entry refuses it rather than reading tables that were never zeroed. next_port is where a bind of
// IDEMIP_TCP_PCB_PORT_ANY starts looking.
typedef struct
{
    uint32_t ready;
    uint16_t next_port;
} TcpPcbCtx;

// The mark clear leaves.
#define TCP_PCB_READY 0x54435042u

// Held out-of-order segments across every TCB, which is what IDEMIP_MAX_PINNED_FRAMES counts.
#define TCP_PCB_OOSEQ_ENTRIES (IDEMIP_TCP_PCBS * IDEMIP_TCP_OOSEQ_SEGS)

// The caller's borrow, split: the operand block, the context, then the four tables. tcp_pcb.h
// publishes the offsets; the asserts below prove the span covers them before anything runs.
static_assert(IDEMIP_TCP_PCB_OFF_CTX + sizeof(TcpPcbCtx) <= IDEMIP_TCP_PCB_CTX_BYTES,
              "IDEMIP_TCP_PCB_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_TCP_PCB_OFF_OOSEQ + (TCP_PCB_OOSEQ_ENTRIES << IDEMIP_TCP_OOSEQ_ENTRY_SHIFT) <=
                  IDEMIP_TCP_PCB_BORROW,
              "IDEMIP_TCP_PCB_BORROW is short of the context and the four tables - raise it in idemip_config.h");

// Every index reported through the operand block is 16 bits, so no table may hold more entries than
// that, and IDEMIP_TCP_PCB_NONE must name none of them.
static_assert(IDEMIP_TCP_PCBS < IDEMIP_TCP_PCB_NONE && IDEMIP_TCP_LISTEN_PCBS < IDEMIP_TCP_PCB_NONE &&
                  IDEMIP_TCP_SEGS < IDEMIP_TCP_PCB_NONE && TCP_PCB_OOSEQ_ENTRIES < IDEMIP_TCP_PCB_NONE,
              "a table outgrew the 16-bit index the operand block reports");

// The regions, at their offsets in the caller's borrow.
#define TCP_PCB_CTX(w) ((TcpPcbCtx *)(void *)((w) + IDEMIP_TCP_PCB_OFF_CTX))
#define TCP_PCB_IO(w) IDEMIP_TCP_PCB_IO(w)
#define TCP_PCB_TCB_AT(w, i)                                                                                           \
    ((TcpPcbTcbEntry *)(void *)((w) + IDEMIP_TCP_PCB_OFF_TCB + ((size_t)(i) << IDEMIP_TCP_PCB_ENTRY_SHIFT)))
#define TCP_PCB_LISTEN_AT(w, i)                                                                                        \
    ((TcpPcbListenEntry *)(void *)((w) + IDEMIP_TCP_PCB_OFF_LISTEN + ((size_t)(i) << IDEMIP_TCP_LISTEN_ENTRY_SHIFT)))
#define TCP_PCB_SEG_AT(w, i)                                                                                           \
    ((TcpPcbSegEntry *)(void *)((w) + IDEMIP_TCP_PCB_OFF_SEG + ((size_t)(i) << IDEMIP_TCP_SEG_ENTRY_SHIFT)))
#define TCP_PCB_OOS_AT(w, i)                                                                                           \
    ((TcpPcbOosEntry *)(void *)((w) + IDEMIP_TCP_PCB_OFF_OOSEQ + ((size_t)(i) << IDEMIP_TCP_OOSEQ_ENTRY_SHIFT)))

// --- the entries -----------------------------------------------------------

// The context and the four tables are contiguous from IDEMIP_TCP_PCB_OFF_CTX to the end of the
// borrow, so one store covers them all. The operand block is the caller's and is left as it was
// found, except for the members a call reports through.
static void tcp_pcb_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    memset(work + IDEMIP_TCP_PCB_OFF_CTX, 0, (size_t)IDEMIP_TCP_PCB_BORROW - IDEMIP_TCP_PCB_OFF_CTX);
    TCP_PCB_CTX(work)->ready = TCP_PCB_READY;
    memset(&io->vars, 0, sizeof io->vars);
    memset(&io->ctl, 0, sizeof io->ctl);
    memset(&io->info, 0, sizeof io->info);
    memset(&io->seg, 0, sizeof io->seg);
    memset(&io->oos, 0, sizeof io->oos);
    io->state = IDEMIP_TCP_STATE_CLOSED;
    io->index = IDEMIP_TCP_PCB_NONE;
    io->port = IDEMIP_TCP_PCB_PORT_ANY;
    io->status = IDEMIP_OK;
}

static void tcp_pcb_open(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_TCP_PCB_NONE;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.3.2's active OPEN, which "create TCB" answers
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_close(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->pcb_args.index >= IDEMIP_TCP_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.3.2's "delete TCB", reached from CLOSED and from TIME-WAIT on
    // Timeout=2MSL
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->port = IDEMIP_TCP_PCB_PORT_ANY;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->bind_args.index >= IDEMIP_TCP_PCBS ||
        io->bind_args.ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.3.1's "local... IP address and port number" half of the four-tuple
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_connect(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->connect_args.index >= IDEMIP_TCP_PCBS ||
        io->connect_args.ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.3.1's "remote IP address and port number" half of the four-tuple
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_load(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    memset(&io->vars, 0, sizeof io->vars);
    memset(&io->ctl, 0, sizeof io->ctl);
    memset(&io->info, 0, sizeof io->info);
    io->state = IDEMIP_TCP_STATE_CLOSED;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->pcb_args.index >= IDEMIP_TCP_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.3.1, reporting one TCB's four-tuple, Table 2 and Table 3 variables and
    // sec 3.3.2 state
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_store(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->pcb_args.index >= IDEMIP_TCP_PCBS ||
        io->state > IDEMIP_TCP_STATE_TIME_WAIT)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.3.1, writing one TCB's Table 2 and Table 3 variables and sec 3.3.2
    // state back
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_listen(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_TCP_PCB_NONE;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->listen_args.ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.3.2's passive OPEN, which "means that the process wants to accept
    // incoming connection requests"
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_unlisten(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->pcb_args.index >= IDEMIP_TCP_LISTEN_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.3.2's CLOSE from LISTEN, which "delete TCB" answers
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_TCP_PCB_NONE;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->find_args.local_ip == NULL ||
        io->find_args.remote_ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.10.7, matching a segment to the TCB its four-tuple names
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_find_listener(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_TCP_PCB_NONE;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->find_args.local_ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.10.7.2, the LISTEN state's answer to an arriving segment
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_seg_alloc(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_TCP_PCB_NONE;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->seg_args.pcb >= IDEMIP_TCP_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.3.1's "pointers to the retransmit queue and to the current segment"
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_seg_load(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    memset(&io->seg, 0, sizeof io->seg);
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->seg_args.index >= IDEMIP_TCP_SEGS)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.3.1, reporting one queued segment's SEG.SEQ and SEG.LEN
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_seg_free(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->seg_args.index >= IDEMIP_TCP_SEGS)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.4 case (b), "all sequence numbers occupied by a segment have been
    // acknowledged (e.g., to remove the segment from a retransmission queue)"
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_oos_alloc(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_TCP_PCB_NONE;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->oos_args.pcb >= IDEMIP_TCP_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.10.7.4, where "further processing is done in SEG.SEQ order"
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_oos_load(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    memset(&io->oos, 0, sizeof io->oos);
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->oos_args.index >= TCP_PCB_OOSEQ_ENTRIES)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.10.7.4, reporting one held segment's SEG.SEQ and SEG.LEN
    io->status = IDEMIP_ERR;
}

static void tcp_pcb_oos_free(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->oos_args.index >= TCP_PCB_OOSEQ_ENTRIES)
    {
        return;
    }
    // PHASE 3: RFC 9293 sec 3.10.7.4, releasing a held segment once RCV.NXT has passed it
    io->status = IDEMIP_ERR;
}

const TcpPcbNs TcpPcb = {.clear = tcp_pcb_clear,
                         .open = tcp_pcb_open,
                         .close = tcp_pcb_close,
                         .bind = tcp_pcb_bind,
                         .connect = tcp_pcb_connect,
                         .load = tcp_pcb_load,
                         .store = tcp_pcb_store,
                         .listen = tcp_pcb_listen,
                         .unlisten = tcp_pcb_unlisten,
                         .find = tcp_pcb_find,
                         .find_listener = tcp_pcb_find_listener,
                         .seg_alloc = tcp_pcb_seg_alloc,
                         .seg_load = tcp_pcb_seg_load,
                         .seg_free = tcp_pcb_seg_free,
                         .oos_alloc = tcp_pcb_oos_alloc,
                         .oos_load = tcp_pcb_oos_load,
                         .oos_free = tcp_pcb_oos_free};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TCP
