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

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip4_addr.h"
#include "src/ip/ip6_addr.h"
#include "src/tcp/tcp_pcb.h"

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
// entry refuses it rather than reading tables that were never zeroed. A bind of
// IDEMIP_TCP_PCB_PORT_ANY starts looking where the caller's random word points, so no cursor is kept
// here: RFC 6056 sec 3.3.1 draws each port independently.
typedef struct
{
    uint32_t ready;
} TcpPcbCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_TCP_PCB_OFF_CTX, sizeof(TcpPcbCtx), IDEMIP_TCP_PCB_BORROW, "tcp_pcb's context");

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

// --- the sequence space ----------------------------------------------------

// RFC 9293 sec 3.4: "all arithmetic dealing with sequence numbers must be performed modulo 2^32.
// This unsigned arithmetic preserves the relationship of sequence numbers as they cycle from
// 2^32 - 1 to 0 again." A sequence number's distance forward from the left window edge, which sec
// 3.3.1 Figure 4 names RCV.NXT, is that subtraction, and those distances order the whole 2^32 space
// from that edge with no wrap ambiguity.
static uint32_t tcp_pcb_seq_from(uint32_t seq, uint32_t edge)
{
    return seq - edge;
}

// --- the address pair ------------------------------------------------------

// RFC 791 sec 3.1 addresses are four octets, RFC 8200 sec 3 addresses are sixteen. Any other version
// number names neither, and reports zero so the caller refuses the call.
//
// A version this build does not carry is one of those. The capability decides what the library can
// address, so a TCB opened on a family with no IP layer under it would hold an address nothing can
// route: the table refuses it here, at the one place both open and listen ask how wide the pair is,
// rather than accepting it and failing at the send.
static uint8_t tcp_pcb_addr_bytes(uint8_t ip_version)
{
#if IDEMIP_ENABLE_IPV4
    if (ip_version == 4u)
    {
        return 4u;
    }
#endif
#if IDEMIP_ENABLE_IPV6
    if (ip_version == 6u)
    {
        return 16u;
    }
#endif
    (void)ip_version;
    return 0u;
}

static idemip_bool tcp_pcb_addr_eq(const uint8_t *a, const uint8_t *b, uint8_t n)
{
    return (idemip_bytes_eq(a, b, (size_t)n)) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 9293 sec 3.9.1.1: a passive OPEN whose "local IP address" parameter is unspecified "will await
// an incoming connection request to any local IP address". An all-zero address is that parameter
// left unspecified.
static idemip_bool tcp_pcb_addr_unspecified(const uint8_t *a, uint8_t n)
{
    return idemip_bytes_zero(a, (size_t)n);
}

// The address operand is IDEMIP_TCP_PCB_ADDR_BYTES wide in the caller's storage and the entry holds
// that many, so the octets past the version's width are zeroed rather than left as they were found.
static void tcp_pcb_addr_set(uint8_t *dst, const uint8_t *src, uint8_t n)
{
    memcpy(dst, src, (size_t)n);
    memset(dst + n, 0, (size_t)IDEMIP_TCP_PCB_ADDR_BYTES - n);
}

// --- the RFC 9293 sec 3.3.2 state machine ----------------------------------

#define TCP_PCB_S(x) (1u << (unsigned)(IDEMIP_TCP_STATE_##x))

/*
 * The transitions RFC 9293 permits out of one state, as a bit per destination. The set is the union
 * of every transition the document states, and each edge below names the section that states it.
 * Figure 5 is a summary and "must not be taken as the total specification", so sec 3.5.2, sec 3.5.3
 * and sec 3.10 carry edges the figure omits.
 *
 * CLOSED       sec 3.10.1 passive OPEN "enter the LISTEN state", active OPEN "enter SYN-SENT state";
 *              sec 3.10.7.2 "The connection state should be changed to SYN-RECEIVED", which is where
 *              a connection accepted through a listener enters the machine
 * LISTEN       sec 3.10.1 OPEN active from LISTEN "Enter SYN-SENT state"; sec 3.10.7.2 SYN-RECEIVED;
 *              sec 3.10.4 and sec 3.10.5 "Delete TCB, enter CLOSED state"
 * SYN-SENT     sec 3.10.7.3 fourth "change the connection state to ESTABLISHED" and "Otherwise,
 *              enter SYN-RECEIVED"; sec 3.10.7.3 second RST "enter CLOSED state"; sec 3.5.2 "The
 *              side of a connection issuing a reset should enter the TIME-WAIT state"
 * SYN-RECEIVED sec 3.10.7.4 second and fourth "return this connection to LISTEN state";
 *              sec 3.10.7.4 fifth "enter ESTABLISHED state"; sec 3.10.4 CLOSE "enter FIN-WAIT-1
 *              state"; sec 3.10.7.4 eighth FIN "Enter the CLOSE-WAIT state"; sec 3.10.5 ABORT
 *              CLOSED; sec 3.5.2 TIME-WAIT
 * ESTABLISHED  Figure 5 CLOSE "snd FIN" FIN-WAIT-1 and "rcv FIN" CLOSE-WAIT; sec 3.10.5 CLOSED;
 *              sec 3.5.2 TIME-WAIT
 * FIN-WAIT-1   Figure 5 "rcv ACK of FIN" FIN-WAIT-2 and "rcv FIN" CLOSING; sec 3.10.7.4 eighth "If
 *              our FIN has been ACKed (perhaps in this segment), then enter TIME-WAIT", which is
 *              Figure 5 note 2; sec 3.10.5 CLOSED
 * FIN-WAIT-2   Figure 5 "rcv FIN" TIME-WAIT; sec 3.10.5 CLOSED
 * CLOSE-WAIT   Figure 5 CLOSE "snd FIN" LAST-ACK; sec 3.10.5 CLOSED; sec 3.5.2 TIME-WAIT
 * CLOSING      Figure 5 "rcv ACK of FIN" TIME-WAIT; sec 3.10.5 CLOSED
 * LAST-ACK     Figure 5 "rcv ACK of FIN" CLOSED; sec 3.5.2 TIME-WAIT
 * TIME-WAIT    Figure 5 "Timeout=2MSL delete TCB" CLOSED, the one way out
 *
 * LISTEN is a destination only from CLOSED and from SYN-RECEIVED: sec 3.5.3 narrows Figure 5 note 3
 * to "If the receiver was in SYN-RECEIVED state and had previously been in the LISTEN state, then
 * the receiver returns to the LISTEN state; otherwise, the receiver aborts the connection and goes
 * to the CLOSED state."
 */
static uint16_t tcp_pcb_transitions(IdemIpTcpState from)
{
    switch (from)
    {
    case IDEMIP_TCP_STATE_CLOSED:
        return (uint16_t)(TCP_PCB_S(CLOSED) | TCP_PCB_S(LISTEN) | TCP_PCB_S(SYN_SENT) | TCP_PCB_S(SYN_RECEIVED));
    case IDEMIP_TCP_STATE_LISTEN:
        return (uint16_t)(TCP_PCB_S(LISTEN) | TCP_PCB_S(CLOSED) | TCP_PCB_S(SYN_SENT) | TCP_PCB_S(SYN_RECEIVED));
    case IDEMIP_TCP_STATE_SYN_SENT:
        return (uint16_t)(TCP_PCB_S(SYN_SENT) | TCP_PCB_S(CLOSED) | TCP_PCB_S(SYN_RECEIVED) | TCP_PCB_S(ESTABLISHED) |
                          TCP_PCB_S(TIME_WAIT));
    case IDEMIP_TCP_STATE_SYN_RECEIVED:
        return (uint16_t)(TCP_PCB_S(SYN_RECEIVED) | TCP_PCB_S(CLOSED) | TCP_PCB_S(LISTEN) | TCP_PCB_S(ESTABLISHED) |
                          TCP_PCB_S(FIN_WAIT_1) | TCP_PCB_S(CLOSE_WAIT) | TCP_PCB_S(TIME_WAIT));
    case IDEMIP_TCP_STATE_ESTABLISHED:
        return (uint16_t)(TCP_PCB_S(ESTABLISHED) | TCP_PCB_S(CLOSED) | TCP_PCB_S(FIN_WAIT_1) | TCP_PCB_S(CLOSE_WAIT) |
                          TCP_PCB_S(TIME_WAIT));
    case IDEMIP_TCP_STATE_FIN_WAIT_1:
        return (uint16_t)(TCP_PCB_S(FIN_WAIT_1) | TCP_PCB_S(CLOSED) | TCP_PCB_S(FIN_WAIT_2) | TCP_PCB_S(CLOSING) |
                          TCP_PCB_S(TIME_WAIT));
    case IDEMIP_TCP_STATE_FIN_WAIT_2:
        return (uint16_t)(TCP_PCB_S(FIN_WAIT_2) | TCP_PCB_S(CLOSED) | TCP_PCB_S(TIME_WAIT));
    case IDEMIP_TCP_STATE_CLOSE_WAIT:
        return (uint16_t)(TCP_PCB_S(CLOSE_WAIT) | TCP_PCB_S(CLOSED) | TCP_PCB_S(LAST_ACK) | TCP_PCB_S(TIME_WAIT));
    case IDEMIP_TCP_STATE_CLOSING:
        return (uint16_t)(TCP_PCB_S(CLOSING) | TCP_PCB_S(CLOSED) | TCP_PCB_S(TIME_WAIT));
    case IDEMIP_TCP_STATE_LAST_ACK:
        return (uint16_t)(TCP_PCB_S(LAST_ACK) | TCP_PCB_S(CLOSED) | TCP_PCB_S(TIME_WAIT));
    case IDEMIP_TCP_STATE_TIME_WAIT:
        return (uint16_t)(TCP_PCB_S(TIME_WAIT) | TCP_PCB_S(CLOSED));
    default:
        return 0u;
    }
}

static idemip_bool tcp_pcb_transition_ok(IdemIpTcpState from, IdemIpTcpState to)
{
    if (from > IDEMIP_TCP_STATE_TIME_WAIT || to > IDEMIP_TCP_STATE_TIME_WAIT)
    {
        return IDEMIP_FALSE;
    }
    return ((tcp_pcb_transitions(from) >> (unsigned)to) & 1u) != 0u ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- the three queues ------------------------------------------------------

// Every segment on one TCB's two send queues, released. Each walk is bounded by the table's count,
// so a link cycle cannot spin it. A send-queue segment names the caller's octets through a pointer
// and pins nothing, so dropping it releases no descriptor. The out-of-order queue is left alone:
// each entry there names a pinned receive descriptor, and only idemip_tcp_pcb_oos_free reports one back.
static void tcp_pcb_send_queues_free(uint8_t *work, uint16_t pcb)
{
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, pcb)->f;
    for (uint8_t which = 0u; which < 2u; which++)
    {
        uint16_t at = (which == 0u) ? t->unsent : t->unacked;
        for (uint16_t n = 0u; n < (uint16_t)IDEMIP_TCP_SEGS && at < (uint16_t)IDEMIP_TCP_SEGS; n++)
        {
            uint16_t next = TCP_PCB_SEG_AT(work, at)->f.next;
            memset(TCP_PCB_SEG_AT(work, at)->raw, 0, sizeof(TcpPcbSegEntry));
            at = next;
        }
    }
    t->unsent = IDEMIP_TCP_PCB_NONE;
    t->unacked = IDEMIP_TCP_PCB_NONE;
}

// RFC 9293 sec 3.4 case (b), "all sequence numbers occupied by a segment have been acknowledged
// (e.g., to remove the segment from a retransmission queue)". The segment is on exactly one of the
// TCB's two send queues, so both heads are tried.
static idemip_bool tcp_pcb_seg_unlink(uint8_t *work, uint16_t pcb, uint16_t seg)
{
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, pcb)->f;
    for (uint8_t which = 0u; which < 2u; which++)
    {
        uint16_t *head = (which == 0u) ? &t->unsent : &t->unacked;
        if (*head == seg)
        {
            *head = TCP_PCB_SEG_AT(work, seg)->f.next;
            return IDEMIP_TRUE;
        }
        uint16_t at = *head;
        for (uint16_t n = 0u; n < (uint16_t)IDEMIP_TCP_SEGS && at < (uint16_t)IDEMIP_TCP_SEGS; n++)
        {
            TcpPcbSegFields *s = &TCP_PCB_SEG_AT(work, at)->f;
            if (s->next == seg)
            {
                s->next = TCP_PCB_SEG_AT(work, seg)->f.next;
                return IDEMIP_TRUE;
            }
            at = s->next;
        }
    }
    return IDEMIP_FALSE;
}

// RFC 9293 sec 3.10.7.4, releasing a held segment once RCV.NXT has passed it. The receive descriptor
// the entry names is unpinned by the caller that pinned it, through netif/dma.h.
static idemip_bool tcp_pcb_oos_unlink(uint8_t *work, uint16_t pcb, uint16_t oos)
{
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, pcb)->f;
    if (t->ooseq == oos)
    {
        t->ooseq = TCP_PCB_OOS_AT(work, oos)->f.next;
        return IDEMIP_TRUE;
    }
    uint16_t at = t->ooseq;
    for (uint16_t n = 0u; n < (uint16_t)TCP_PCB_OOSEQ_ENTRIES && at < (uint16_t)TCP_PCB_OOSEQ_ENTRIES; n++)
    {
        TcpPcbOosFields *o = &TCP_PCB_OOS_AT(work, at)->f;
        if (o->next == oos)
        {
            o->next = TCP_PCB_OOS_AT(work, oos)->f.next;
            return IDEMIP_TRUE;
        }
        at = o->next;
    }
    return IDEMIP_FALSE;
}

// --- the local port --------------------------------------------------------

// Whether any open TCB already holds this local port. This is RFC 6056 sec 3.3.1's
// check_suitable_port, which the ephemeral draw uses to pass over a port in use; it is not a rule
// about what may be bound. RFC 9293 sec 3.4.1 makes a connection "defined by a pair of sockets", so
// two peers reaching one local socket are two connections and idemip_tcp_pcb_connect is what keeps the pair
// unique.
//
// sec 3.9.1.1 (MUST-42) requires that a LISTEN on a port be possible "while a connection block with
// the same local port is in SYN-SENT or SYN-RECEIVED state", so a listener's port does not make one
// taken here and a TCB's does not make one taken for a listen.
static idemip_bool tcp_pcb_port_taken(uint8_t *work, uint16_t port, uint16_t except)
{
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_PCBS; i++)
    {
        const TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, i)->f;
        if (t->in_use && i != except && t->local_port == port)
        {
            return IDEMIP_TRUE;
        }
    }
    return IDEMIP_FALSE;
}

// RFC 6056 sec 3.1: "Port numbers that are currently in use by a TCP in the LISTEN state should not
// be allowed for use as ephemeral ports. If this rule is not complied with, an attacker could
// potentially 'steal' an incoming connection to a local server application". Only the ephemeral draw
// walks past a listening port; idemip_tcp_pcb_bind's named-port path is what MUST-42 protects.
static idemip_bool tcp_pcb_port_listening(uint8_t *work, uint16_t port)
{
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_LISTEN_PCBS; i++)
    {
        const TcpPcbListenFields *l = &TCP_PCB_LISTEN_AT(work, i)->f;
        if (l->in_use && l->local_port == port)
        {
            return IDEMIP_TRUE;
        }
    }
    return IDEMIP_FALSE;
}

// The ephemeral pool, drawn by RFC 6056 sec 3.3.1 Algorithm 1:
//
//   next_ephemeral = min_ephemeral + (random() % num_ephemeral);
//   count = num_ephemeral;
//   do { if (check_suitable_port(port)) return next_ephemeral;
//        if (next_ephemeral == max_ephemeral) next_ephemeral = min_ephemeral; else next_ephemeral++;
//        count--; } while (count > 0);
//
// They number a power of two, so the modulo is an AND and the wrap is an AND and an OR: no divide
// runs. sec 3.3 makes the obfuscation a SHOULD, "since this helps to mitigate a number of attacks
// that depend on the attacker's ability to guess or know the five-tuple", and a walk from where the
// last draw left off is guessable from one observed port.
static uint16_t tcp_pcb_port_draw(uint8_t *work, uint16_t except, uint32_t rand)
{
    uint16_t at = (uint16_t)(IDEMIP_TCP_PCB_PORT_EPH_FIRST | (uint16_t)(rand & IDEMIP_TCP_PCB_PORT_EPH_MASK));
    for (uint32_t n = 0u; n < (uint32_t)IDEMIP_TCP_PCB_PORT_EPH_COUNT; n++)
    {
        uint16_t port = at;
        at = (uint16_t)(IDEMIP_TCP_PCB_PORT_EPH_FIRST | (uint16_t)((port + 1u) & IDEMIP_TCP_PCB_PORT_EPH_MASK));
        if (!tcp_pcb_port_taken(work, port, except) && !tcp_pcb_port_listening(work, port))
        {
            return port;
        }
    }
    return IDEMIP_TCP_PCB_PORT_ANY;
}

// --- matching an arriving segment ------------------------------------------

// RFC 9293 sec 3.3.1 keys a TCB on "the local and remote IP addresses and port numbers". The
// segment's own pair is swapped against it: its Destination Port is the local port. RFC 4007 sec 6
// zone indices qualify a non-global IPv6 address, so they are compared only over IPv6.
static idemip_bool tcp_pcb_tcb_matches(const TcpPcbTcbFields *t, const TcpPcbFindArgs *a, uint8_t n)
{
    if (!t->in_use || t->ip_version != a->ip_version)
    {
        return IDEMIP_FALSE;
    }
    if (t->local_port != a->local_port || t->remote_port != a->remote_port)
    {
        return IDEMIP_FALSE;
    }
    if (t->netif != 0u && t->netif != a->netif)
    {
        return IDEMIP_FALSE;
    }
    if (!tcp_pcb_addr_eq(t->local_ip, a->local_ip, n) || !tcp_pcb_addr_eq(t->remote_ip, a->remote_ip, n))
    {
        return IDEMIP_FALSE;
    }
    if (a->ip_version == 6u && (t->local_zone != a->local_zone || t->remote_zone != a->remote_zone))
    {
        return IDEMIP_FALSE;
    }
    return IDEMIP_TRUE;
}

// A listener matches on the local half alone. RFC 9293 sec 3.9.1.1: "If the parameter is
// unspecified, a passive OPEN will await an incoming connection request to any local IP address", so
// an all-zero local address matches every destination. A listener bound to the destination is
// preferred over one that is not, which is the order lwIP walks in
// lwip_ref/src/core/tcp_in.c:353 "first try specific local IP".
static idemip_bool tcp_pcb_listener_matches(const TcpPcbListenFields *l, const TcpPcbFindArgs *a, uint8_t n,
                                            idemip_bool wildcard)
{
    if (!l->in_use || l->ip_version != a->ip_version || l->local_port != a->local_port)
    {
        return IDEMIP_FALSE;
    }
    if (l->netif != 0u && l->netif != a->netif)
    {
        return IDEMIP_FALSE;
    }
    if (wildcard)
    {
        return tcp_pcb_addr_unspecified(l->local_ip, n);
    }
    if (tcp_pcb_addr_unspecified(l->local_ip, n) || !tcp_pcb_addr_eq(l->local_ip, a->local_ip, n))
    {
        return IDEMIP_FALSE;
    }
    if (a->ip_version == 6u && l->local_zone != a->local_zone)
    {
        return IDEMIP_FALSE;
    }
    return IDEMIP_TRUE;
}

// --- the entries -----------------------------------------------------------

// The context and the four tables are contiguous from IDEMIP_TCP_PCB_OFF_CTX to the end of the
// borrow, so one store covers them all. The operand block is the caller's and is left as it was
// found, except for the members a call reports through.
void idemip_tcp_pcb_clear(uint8_t *work)
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

// RFC 9293 sec 3.10.1: "Create a new transmission control block (TCB) to hold connection state
// information." The TCB is taken in sec 3.3.2's CLOSED, which "represents the state when there is no
// TCB", and enters the machine when a store moves it to LISTEN, SYN-SENT or SYN-RECEIVED. A table
// with every TCB open is BUSY, since sec 3.10.4's "Delete TCB" frees one; a version that names
// neither RFC 791 sec 3.1 nor RFC 8200 sec 3 is ERR, since no later call makes 5 an address family.
void idemip_tcp_pcb_open(uint8_t *work)
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
    if (tcp_pcb_addr_bytes(io->open_args.ip_version) == 0u)
    {
        return;
    }
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_PCBS; i++)
    {
        TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, i)->f;
        if (t->in_use)
        {
            continue;
        }
        memset(TCP_PCB_TCB_AT(work, i)->raw, 0, sizeof(TcpPcbTcbEntry));
        t->listener = IDEMIP_TCP_PCB_NONE;
        t->unsent = IDEMIP_TCP_PCB_NONE;
        t->unacked = IDEMIP_TCP_PCB_NONE;
        t->ooseq = IDEMIP_TCP_PCB_NONE;
        t->ttl = (uint8_t)IDEMIP_IP_DEFAULT_TTL;
        // RFC 9293 sec 3.8.3's R2, which sec 3.10.1's OPEN fills in and TcpPcb.opt resets.
        t->ctl.r2 = (uint8_t)IDEMIP_TCP_MAXRTX;
        t->ctl.r2_syn = (uint8_t)IDEMIP_TCP_SYNMAXRTX;
        t->ip_version = io->open_args.ip_version;
        t->state = IDEMIP_TCP_STATE_CLOSED;
        t->in_use = IDEMIP_TRUE;
        io->index = i;
        io->status = IDEMIP_OK;
        return;
    }
    io->status = IDEMIP_BUSY; // every TCB open, and sec 3.10.4's "Delete TCB" frees one
}

// RFC 9293 sec 3.10.1's OPEN fills in "local socket identifier, remote socket, Diffserv field,
// security/compartment, and user timeout information". The sockets are bind and connect; the rest a
// TCB can hold are here. sec 3.9.1.9 MUST-48: "The application layer MUST be able to specify the
// Differentiated Services field for segments that are sent on a connection." sec 3.8.3 MUST-21: "An
// application MUST be able to set the value for R2 for a particular connection."
void idemip_tcp_pcb_opt(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->opt_args.index >= IDEMIP_TCP_PCBS)
    {
        return;
    }
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, io->opt_args.index)->f;
    if (!t->in_use)
    {
        return;
    }
    t->tos = io->opt_args.tos;
    t->ttl = io->opt_args.ttl;
    t->ctl.r2 = io->opt_args.r2;
    t->ctl.r2_syn = io->opt_args.r2_syn;
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.3.2's "delete TCB", which sec 3.10.4 CLOSE reaches from LISTEN and SYN-SENT, sec
// 3.10.5 ABORT reaches from every state, Figure 5 reaches from LAST-ACK on "rcv ACK of FIN", and
// Figure 5 reaches from TIME-WAIT on "Timeout=2MSL". Every segment on the TCB's two send queues goes
// with it. A TCB still holding an out-of-order segment is BUSY: each of those names a pinned receive
// descriptor, and an oos_free is what reports one back, so draining the hold makes this call succeed.
// A TCB that is not open is sec 3.10.4's CLOSED case, "error: connection does not exist", which no
// retry changes.
void idemip_tcp_pcb_close(uint8_t *work)
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
    const TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, io->pcb_args.index)->f;
    if (!t->in_use)
    {
        return;
    }
    if (t->ooseq != IDEMIP_TCP_PCB_NONE)
    {
        io->status = IDEMIP_BUSY; // held segments pin receive descriptors, and an oos_free returns each
        return;
    }
    tcp_pcb_send_queues_free(work, io->pcb_args.index);
    memset(TCP_PCB_TCB_AT(work, io->pcb_args.index)->raw, 0, sizeof(TcpPcbTcbEntry));
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.3.1's "local... IP address and port number" half of the four-tuple, which sec
// 3.10.1's OPEN fills in from its "local port" and "local IP address" parameters. Those are OPEN
// parameters, so a TCB past sec 3.3.2's CLOSED refuses the call: sec 3.9.1.1 (MUST-45) fixes the
// local address once "a previous segment has either been sent or received on this connection".
// A port already held by another open TCB is BUSY, since sec 3.10.4's "Delete TCB" frees it, and
// IDEMIP_TCP_PCB_PORT_ANY with none of RFC 6335 sec 6's Dynamic Ports free is BUSY for the same
// reason.
void idemip_tcp_pcb_bind(uint8_t *work)
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
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, io->bind_args.index)->f;
    uint8_t n = tcp_pcb_addr_bytes(t->ip_version);
    if (!t->in_use || n == 0u || t->state != IDEMIP_TCP_STATE_CLOSED)
    {
        return;
    }
    // A named port is taken as given. RFC 9293 sec 3.4.1: "A connection is defined by a pair of
    // sockets", so another TCB holding this local port is another connection, not a collision - a
    // listener serving many peers on one port is every one of them. idemip_tcp_pcb_connect is where the pair
    // is made unique.
    uint16_t port = io->bind_args.port;
    if (port == IDEMIP_TCP_PCB_PORT_ANY)
    {
        port = tcp_pcb_port_draw(work, io->bind_args.index, io->bind_args.rand);
        if (port == IDEMIP_TCP_PCB_PORT_ANY)
        {
            io->status = IDEMIP_BUSY;
            return;
        }
    }
    tcp_pcb_addr_set(t->local_ip, io->bind_args.ip, n);
    t->local_port = port;
    t->local_zone = io->bind_args.zone;
    t->netif = io->bind_args.netif;
    io->port = port;
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.9.1.1 (MUST-46): "A TCP implementation MUST reject as an error a local OPEN call for
// an invalid remote IP address (e.g., a broadcast or multicast address)". RFC 1122 sec 3.2.1.3 adds
// the unspecified address, case (a), which "MUST NOT be sent, except as a source address as part of an
// initialization procedure by which the host learns its own IP address". A directed broadcast is
// the network's own prefix with a host part of all ones, which is not derivable from the address
// alone, so it is not among these.
static idemip_bool tcp_pcb_remote_invalid(uint8_t ip_version, const uint8_t *ip)
{
#if IDEMIP_ENABLE_IPV4
    if (ip_version == 4u)
    {
        IdemIpIp4AddrType type = idemip_ip4_addr_type(idemip_rd32(ip));
        return (type == IDEMIP_IP4_TYPE_MULTICAST || type == IDEMIP_IP4_TYPE_BROADCAST ||
                type == IDEMIP_IP4_TYPE_UNSPECIFIED)
                   ? IDEMIP_TRUE
                   : IDEMIP_FALSE;
    }
#else
    (void)ip_version;
#endif
#if IDEMIP_ENABLE_IPV6
    // RFC 4291 sec 2.7: "Multicast addresses must not be used as source addresses in IPv6 packets or
    // appear in any Routing header", and sec 2.5.2 makes :: unusable as a destination.
    IdemIpIp6Type type = idemip_ip6_addr_type(ip);
    return (type == IDEMIP_IP6_TYPE_MULTICAST || type == IDEMIP_IP6_TYPE_UNSPECIFIED) ? IDEMIP_TRUE : IDEMIP_FALSE;
#else
    // A build without IPv6 has no address type to read here and nothing that opens a v6 connection,
    // so the arm is unreachable rather than permissive: an address this module cannot judge is
    // refused, not admitted.
    (void)ip;
    return IDEMIP_TRUE;
#endif
}

// RFC 9293 sec 3.3.1's "remote IP address and port number" half of the four-tuple. sec 3.10.1: "if
// active and the remote socket is unspecified, return 'error: remote socket unspecified'", so a
// remote port of zero is ERR. The pair completed here is what sec 3.4.1 calls a connection, "defined
// by a pair of sockets", so a pair another open TCB already holds is BUSY: closing that one frees it.
void idemip_tcp_pcb_connect(uint8_t *work)
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
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, io->connect_args.index)->f;
    uint8_t n = tcp_pcb_addr_bytes(t->ip_version);
    if (!t->in_use || n == 0u || t->state != IDEMIP_TCP_STATE_CLOSED)
    {
        return;
    }
    if (io->connect_args.port == IDEMIP_TCP_PCB_PORT_ANY)
    {
        return;
    }
    if (tcp_pcb_remote_invalid(t->ip_version, io->connect_args.ip))
    {
        return; // sec 3.9.1.1 MUST-46, "an invalid remote IP address"
    }
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_PCBS; i++)
    {
        const TcpPcbTcbFields *o = &TCP_PCB_TCB_AT(work, i)->f;
        if (!o->in_use || i == io->connect_args.index || o->ip_version != t->ip_version)
        {
            continue;
        }
        if (o->local_port == t->local_port && o->remote_port == io->connect_args.port &&
            tcp_pcb_addr_eq(o->local_ip, t->local_ip, n) && tcp_pcb_addr_eq(o->remote_ip, io->connect_args.ip, n))
        {
            io->status = IDEMIP_BUSY;
            return;
        }
    }
    tcp_pcb_addr_set(t->remote_ip, io->connect_args.ip, n);
    t->remote_port = io->connect_args.port;
    t->remote_zone = io->connect_args.zone;
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.3.1, reporting one TCB's four-tuple, Table 2 and Table 3 variables and sec 3.3.2
// state. The two addresses point into the entry, which is the caller's own borrow.
void idemip_tcp_pcb_load(uint8_t *work)
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
    const TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, io->pcb_args.index)->f;
    if (!t->in_use)
    {
        return;
    }
    io->vars = t->vars;
    io->ctl = t->ctl;
    io->state = t->state;
    io->info.local_ip = t->local_ip;
    io->info.remote_ip = t->remote_ip;
    io->info.local_port = t->local_port;
    io->info.remote_port = t->remote_port;
    io->info.listener = t->listener;
    io->info.unsent = t->unsent;
    io->info.unacked = t->unacked;
    io->info.ooseq = t->ooseq;
    io->info.local_zone = t->local_zone;
    io->info.remote_zone = t->remote_zone;
    io->info.netif = t->netif;
    io->info.tos = t->tos;
    io->info.ttl = t->ttl;
    io->info.ip_version = t->ip_version;
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.3.1, writing one TCB's Table 2 and Table 3 variables and sec 3.3.2 state back. The
// state is the one place the eleven-state machine is written, so the transition is checked against
// tcp_pcb_transitions: a state sec 3.3.2 does not name, and a transition no section of RFC 9293
// permits out of the state the TCB is in, are both ERR, since the same call on the same TCB can
// never succeed later.
void idemip_tcp_pcb_store(uint8_t *work)
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
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, io->pcb_args.index)->f;
    if (!t->in_use || !tcp_pcb_transition_ok(t->state, io->state))
    {
        return;
    }
    t->vars = io->vars;
    t->ctl = io->ctl;
    t->state = io->state;
    io->status = IDEMIP_OK;
}

// How many connections a listener is already holding in SYN-RECEIVED, which is what its backlog
// bounds. Counted over the table rather than tallied in the listener: a TCB names the listener its
// SYN arrived on and carries its own sec 3.3.2 state, so the number is a property of the table and
// not a running total some close path could fail to decrement. IDEMIP_TCP_PCBS TCBs is the whole
// scan, and the count cannot exceed it. @p except is left out so accepting one TCB twice counts the
// same as once.
static uint8_t tcp_pcb_syn_received_on(uint8_t *work, uint16_t listener, uint16_t except)
{
    uint8_t n = 0u;
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_PCBS; i++)
    {
        const TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, i)->f;
        if (i != except && t->in_use && t->listener == listener && t->state == IDEMIP_TCP_STATE_SYN_RECEIVED)
        {
            n = (uint8_t)(n + 1u);
        }
    }
    return n;
}

static_assert(IDEMIP_TCP_PCBS <= 255u, "tcp_pcb_syn_received_on counts TCBs in a uint8_t");

// RFC 9293 sec 3.5 (MUST-11): "a TCP implementation MUST keep track of whether a connection has
// reached SYN-RECEIVED state as the result of a passive OPEN or an active OPEN". sec 3.10.7.2 creates
// the connection out of the LISTEN state, so the listener it came through is recorded here and read
// by sec 3.10.7.4's second and fourth checks, which return a passive connection to LISTEN.
// IDEMIP_TCP_PCB_NONE is the active OPEN; any other index must name a taken listener.
//
// This is also the one place a connection is bound to a passive OPEN, so it is where that OPEN's
// backlog is applied. A listener already holding its backlog in SYN-RECEIVED reports BUSY: the SYN
// gets no connection, and the caller returns the TCB rather than making one the listener never
// agreed to hold. Without it the field was written at listen and read nowhere, and one listener
// could take every one of the IDEMIP_TCP_PCBS connections the whole build has.
void idemip_tcp_pcb_accept(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpPcbIo *io = TCP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_PCB_CTX(work)->ready != TCP_PCB_READY || io->accept_args.index >= IDEMIP_TCP_PCBS)
    {
        return;
    }
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, io->accept_args.index)->f;
    if (!t->in_use)
    {
        return;
    }
    if (io->accept_args.listener != IDEMIP_TCP_PCB_NONE)
    {
        if (io->accept_args.listener >= IDEMIP_TCP_LISTEN_PCBS ||
            !TCP_PCB_LISTEN_AT(work, io->accept_args.listener)->f.in_use)
        {
            return;
        }
        const TcpPcbListenFields *l = &TCP_PCB_LISTEN_AT(work, io->accept_args.listener)->f;
        if (tcp_pcb_syn_received_on(work, io->accept_args.listener, io->accept_args.index) >= l->backlog)
        {
            io->status = IDEMIP_BUSY;
            return;
        }
    }
    t->listener = io->accept_args.listener;
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.3.2's passive OPEN, which "means that the process wants to accept incoming
// connection requests". sec 3.9.1.1: "Every passive OPEN call either creates a new connection record
// in LISTEN state, or it returns an error", so the listener is taken in LISTEN. A port of zero names
// no socket for a segment to arrive on and is ERR; a port another listener holds is BUSY, since an
// unlisten frees it, and a table with every listener taken is BUSY for the same reason.
void idemip_tcp_pcb_listen(uint8_t *work)
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
    uint8_t n = tcp_pcb_addr_bytes(io->listen_args.ip_version);
    // A backlog of zero holds no connection in SYN-RECEIVED, so it is a passive OPEN that can never
    // accept one. Refused here rather than taken and left useless, the way a port of
    // IDEMIP_TCP_PCB_PORT_ANY is: both name a listener that cannot do the one thing a listener does.
    if (n == 0u || io->listen_args.port == IDEMIP_TCP_PCB_PORT_ANY || io->listen_args.backlog == 0u)
    {
        return;
    }
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_LISTEN_PCBS; i++)
    {
        const TcpPcbListenFields *l = &TCP_PCB_LISTEN_AT(work, i)->f;
        if (l->in_use && l->local_port == io->listen_args.port && l->ip_version == io->listen_args.ip_version &&
            tcp_pcb_addr_eq(l->local_ip, io->listen_args.ip, n))
        {
            io->status = IDEMIP_BUSY;
            return;
        }
    }
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_LISTEN_PCBS; i++)
    {
        TcpPcbListenFields *l = &TCP_PCB_LISTEN_AT(work, i)->f;
        if (l->in_use)
        {
            continue;
        }
        memset(TCP_PCB_LISTEN_AT(work, i)->raw, 0, sizeof(TcpPcbListenEntry));
        tcp_pcb_addr_set(l->local_ip, io->listen_args.ip, n);
        l->local_port = io->listen_args.port;
        l->local_zone = io->listen_args.zone;
        l->netif = io->listen_args.netif;
        l->backlog = io->listen_args.backlog;
        l->ip_version = io->listen_args.ip_version;
        l->state = IDEMIP_TCP_STATE_LISTEN;
        l->in_use = IDEMIP_TRUE;
        io->index = i;
        io->status = IDEMIP_OK;
        return;
    }
    io->status = IDEMIP_BUSY; // every listener taken, and an unlisten frees one
}

// RFC 9293 sec 3.10.4's CLOSE from LISTEN, "Delete TCB, enter CLOSED state". A listener that is not
// taken is "error: connection does not exist", which no retry changes.
void idemip_tcp_pcb_unlisten(uint8_t *work)
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
    const TcpPcbListenFields *l = &TCP_PCB_LISTEN_AT(work, io->pcb_args.index)->f;
    if (!l->in_use)
    {
        return;
    }
    memset(TCP_PCB_LISTEN_AT(work, io->pcb_args.index)->raw, 0, sizeof(TcpPcbListenEntry));
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.10.7, matching a segment to the TCB its four-tuple names. No TCB is sec 3.10.7.1's
// CLOSED case, "i.e., TCB does not exist", and is ERR: the same segment matches no better later.
void idemip_tcp_pcb_find(uint8_t *work)
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
    uint8_t n = tcp_pcb_addr_bytes(io->find_args.ip_version);
    if (n == 0u)
    {
        return;
    }
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_PCBS; i++)
    {
        if (tcp_pcb_tcb_matches(&TCP_PCB_TCB_AT(work, i)->f, &io->find_args, n))
        {
            io->index = i;
            io->status = IDEMIP_OK;
            return;
        }
    }
}

// RFC 9293 sec 3.10.7.2, the LISTEN state's answer to an arriving segment. A listener bound to the
// segment's destination is matched before one left unspecified, which sec 3.9.1.1 says "will await an
// incoming connection request to any local IP address".
void idemip_tcp_pcb_find_listener(uint8_t *work)
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
    uint8_t n = tcp_pcb_addr_bytes(io->find_args.ip_version);
    if (n == 0u)
    {
        return;
    }
    for (uint8_t pass = 0u; pass < 2u; pass++)
    {
        idemip_bool wildcard = (pass == 1u) ? IDEMIP_TRUE : IDEMIP_FALSE;
        for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_LISTEN_PCBS; i++)
        {
            if (tcp_pcb_listener_matches(&TCP_PCB_LISTEN_AT(work, i)->f, &io->find_args, n, wildcard))
            {
                io->index = i;
                io->status = IDEMIP_OK;
                return;
            }
        }
    }
}

// RFC 9293 sec 3.3.1's "pointers to the retransmit queue and to the current segment". The segment
// names the caller's octets rather than holding them, and goes on the tail of the TCB's unsent
// queue, so sec 3.10.7.4's "further processing is done in SEG.SEQ order" holds on a queue built in
// send order. A table with every segment queued is BUSY, since a seg_free returns one.
void idemip_tcp_pcb_seg_alloc(uint8_t *work)
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
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, io->seg_args.pcb)->f;
    if (!t->in_use)
    {
        return;
    }
    // RFC 9293 sec 3.3.1 Table 4 SEG.LEN counts data octets, and a segment with octets must name
    // them; a segment carrying only sec 3.1 control bits carries none.
    if ((io->seg_args.len != 0u) != (io->seg_args.data != NULL))
    {
        return;
    }
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_SEGS; i++)
    {
        TcpPcbSegFields *s = &TCP_PCB_SEG_AT(work, i)->f;
        if (s->in_use)
        {
            continue;
        }
        memset(TCP_PCB_SEG_AT(work, i)->raw, 0, sizeof(TcpPcbSegEntry));
        s->data = io->seg_args.data;
        s->seq = io->seg_args.seq;
        s->next = IDEMIP_TCP_PCB_NONE;
        s->pcb = io->seg_args.pcb;
        s->len = io->seg_args.len;
        s->flags = io->seg_args.flags;
        s->opts = io->seg_args.opts;
        s->in_use = IDEMIP_TRUE;
        if (t->unsent >= (uint16_t)IDEMIP_TCP_SEGS)
        {
            t->unsent = i;
        }
        else
        {
            uint16_t at = t->unsent;
            for (uint16_t n = 0u; n < (uint16_t)IDEMIP_TCP_SEGS; n++)
            {
                TcpPcbSegFields *tail = &TCP_PCB_SEG_AT(work, at)->f;
                if (tail->next >= (uint16_t)IDEMIP_TCP_SEGS)
                {
                    tail->next = i;
                    break;
                }
                at = tail->next;
            }
        }
        io->index = i;
        io->status = IDEMIP_OK;
        return;
    }
    io->status = IDEMIP_BUSY; // every segment queued, and a seg_free returns one
}

// RFC 9293 sec 3.3.1, reporting one queued segment's SEG.SEQ and SEG.LEN.
void idemip_tcp_pcb_seg_load(uint8_t *work)
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
    const TcpPcbSegFields *s = &TCP_PCB_SEG_AT(work, io->seg_args.index)->f;
    if (!s->in_use)
    {
        return;
    }
    io->seg.data = s->data;
    io->seg.seq = s->seq;
    io->seg.next = s->next;
    io->seg.pcb = s->pcb;
    io->seg.len = s->len;
    io->seg.flags = s->flags;
    io->seg.opts = s->opts;
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.3.1's "pointers to the retransmit queue", which sec 3.10.7.4 fifth removes a segment
// from once it is "entirely acknowledged". The segment leaves the head of the unsent queue and goes
// on the tail of that queue, so both stay in the sec 3.10.7.4 SEG.SEQ order they were built in. A
// segment that is not that head is a broken link rather than a busy resource, so it is ERR.
void idemip_tcp_pcb_seg_sent(uint8_t *work)
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
    TcpPcbSegFields *s = &TCP_PCB_SEG_AT(work, io->seg_args.index)->f;
    if (!s->in_use || s->pcb >= (uint16_t)IDEMIP_TCP_PCBS)
    {
        return;
    }
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, s->pcb)->f;
    if (t->unsent != io->seg_args.index)
    {
        return;
    }
    t->unsent = s->next;
    s->next = IDEMIP_TCP_PCB_NONE;
    if (t->unacked >= (uint16_t)IDEMIP_TCP_SEGS)
    {
        t->unacked = io->seg_args.index;
        io->status = IDEMIP_OK;
        return;
    }
    uint16_t at = t->unacked;
    for (uint16_t n = 0u; n < (uint16_t)IDEMIP_TCP_SEGS; n++)
    {
        TcpPcbSegFields *tail = &TCP_PCB_SEG_AT(work, at)->f;
        if (tail->next >= (uint16_t)IDEMIP_TCP_SEGS)
        {
            tail->next = io->seg_args.index;
            io->status = IDEMIP_OK;
            return;
        }
        at = tail->next;
    }
}

// RFC 9293 sec 3.4 case (b), "all sequence numbers occupied by a segment have been acknowledged
// (e.g., to remove the segment from a retransmission queue)". A segment not on the queue its own pcb
// field names is a broken link rather than a busy resource, so it is ERR.
void idemip_tcp_pcb_seg_free(uint8_t *work)
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
    const TcpPcbSegFields *s = &TCP_PCB_SEG_AT(work, io->seg_args.index)->f;
    if (!s->in_use || s->pcb >= (uint16_t)IDEMIP_TCP_PCBS)
    {
        return;
    }
    if (!tcp_pcb_seg_unlink(work, s->pcb, io->seg_args.index))
    {
        return;
    }
    memset(TCP_PCB_SEG_AT(work, io->seg_args.index)->raw, 0, sizeof(TcpPcbSegEntry));
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.10.7.4, where "Segments are processed in sequence. Initial tests on arrival are used
// to discard old duplicates, but further processing is done in SEG.SEQ order." The queue is kept in
// that order, measured from RCV.NXT, which sec 3.3.1 Figure 4 calls "the left or lower edge of the
// receive window", so the whole 2^32 space orders without a wrap ambiguity. A TCB already holding
// IDEMIP_TCP_OOSEQ_SEGS is BUSY, since delivery or an oos_free frees one; so is a full table.
void idemip_tcp_pcb_oos_alloc(uint8_t *work)
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
    TcpPcbTcbFields *t = &TCP_PCB_TCB_AT(work, io->oos_args.pcb)->f;
    if (!t->in_use || io->oos_args.len == 0u)
    {
        return;
    }
    uint16_t held = 0u;
    uint16_t at = t->ooseq;
    for (uint16_t n = 0u; n < (uint16_t)TCP_PCB_OOSEQ_ENTRIES && at < (uint16_t)TCP_PCB_OOSEQ_ENTRIES; n++)
    {
        held++;
        at = TCP_PCB_OOS_AT(work, at)->f.next;
    }
    if (held >= (uint16_t)IDEMIP_TCP_OOSEQ_SEGS)
    {
        io->status = IDEMIP_BUSY; // this TCB's hold is full, and delivery or an oos_free frees one
        return;
    }
    for (uint16_t i = 0u; i < (uint16_t)TCP_PCB_OOSEQ_ENTRIES; i++)
    {
        TcpPcbOosFields *o = &TCP_PCB_OOS_AT(work, i)->f;
        if (o->in_use)
        {
            continue;
        }
        memset(TCP_PCB_OOS_AT(work, i)->raw, 0, sizeof(TcpPcbOosEntry));
        o->seq = io->oos_args.seq;
        o->next = IDEMIP_TCP_PCB_NONE;
        o->pcb = io->oos_args.pcb;
        o->desc = io->oos_args.desc;
        o->offset = io->oos_args.offset;
        o->len = io->oos_args.len;
        o->in_use = IDEMIP_TRUE;
        uint16_t prev = IDEMIP_TCP_PCB_NONE;
        uint16_t cur = t->ooseq;
        for (uint16_t n = 0u; n < (uint16_t)TCP_PCB_OOSEQ_ENTRIES && cur < (uint16_t)TCP_PCB_OOSEQ_ENTRIES; n++)
        {
            const TcpPcbOosFields *c = &TCP_PCB_OOS_AT(work, cur)->f;
            if (tcp_pcb_seq_from(o->seq, t->vars.rcv_nxt) < tcp_pcb_seq_from(c->seq, t->vars.rcv_nxt))
            {
                break;
            }
            prev = cur;
            cur = c->next;
        }
        o->next = cur;
        if (prev >= (uint16_t)TCP_PCB_OOSEQ_ENTRIES)
        {
            t->ooseq = i;
        }
        else
        {
            TCP_PCB_OOS_AT(work, prev)->f.next = i;
        }
        io->index = i;
        io->status = IDEMIP_OK;
        return;
    }
    io->status = IDEMIP_BUSY; // every held-segment entry taken, and an oos_free returns one
}

// RFC 9293 sec 3.10.7.4, reporting one held segment's SEG.SEQ and SEG.LEN.
void idemip_tcp_pcb_oos_load(uint8_t *work)
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
    const TcpPcbOosFields *o = &TCP_PCB_OOS_AT(work, io->oos_args.index)->f;
    if (!o->in_use)
    {
        return;
    }
    io->oos.seq = o->seq;
    io->oos.next = o->next;
    io->oos.pcb = o->pcb;
    io->oos.desc = o->desc;
    io->oos.offset = o->offset;
    io->oos.len = o->len;
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.10.7.4, releasing a held segment once RCV.NXT has passed it. The entry names the
// receive descriptor rather than the octets, so the caller that pinned it through netif/dma.h drops
// the pin once this reports OK.
void idemip_tcp_pcb_oos_free(uint8_t *work)
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
    const TcpPcbOosFields *o = &TCP_PCB_OOS_AT(work, io->oos_args.index)->f;
    if (!o->in_use || o->pcb >= (uint16_t)IDEMIP_TCP_PCBS)
    {
        return;
    }
    if (!tcp_pcb_oos_unlink(work, o->pcb, io->oos_args.index))
    {
        return;
    }
    memset(TCP_PCB_OOS_AT(work, io->oos_args.index)->raw, 0, sizeof(TcpPcbOosEntry));
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
