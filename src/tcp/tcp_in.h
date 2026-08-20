// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp_in.h
 * @brief SEGMENT ARRIVES, RFC 9293 sec 3.10.7.
 *
 * One arriving segment is read into the operand block as the RFC 9293 sec 3.3.1 Table 4 current
 * segment variables plus the sec 3.1 control bits, the connection's sec 3.3.1 variables and sec 3.3.2
 * state arrive with it, and the call reports the variables it changed, the state it moved to, and
 * what the caller must send and signal. Nothing here holds a segment's octets, reaches a TCB table,
 * or sends anything: a caller loads the TCB through @ref TcpPcbNs::load, calls one entry, and stores
 * what came back.
 *
 * The security and compartment of RFC 9293 Appendix A.1 are not carried by a TCB here, so the third
 * check of sec 3.10.7.4 and the third of sec 3.10.7.3 have nothing to compare and are not made.
 *
 * RFC 7323 sec 5.3's PAWS rules R1 and R3 run ahead of the sec 3.10.7.4 first check, over
 * @ref TcpPcbCtl::ts_recent and @ref TcpPcbCtl::last_ack_sent, while @ref IDEMIP_TCP_CTL_TS_OK is
 * set. The caller sets that flag when the SYN exchange carried a Timestamps option both ways.
 */

#ifndef IDEMIP_TCP_IN_H
#define IDEMIP_TCP_IN_H

#include "src/tcp/tcp_pcb.h"

#if IDEMIP_ENABLE_TCP

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// What a call asks the caller to do
// ---------------------------------------------------------------------------
// One bit per action RFC 9293 sec 3.10.7 names. A caller acts on the set and nothing else: the
// entries here send no segment, signal no user, and free no queue.

#define IDEMIP_TCP_IN_ACT_ACK (1u << 0)  ///< send @ref TcpInReply, an acknowledgment
#define IDEMIP_TCP_IN_ACT_RST (1u << 1)  ///< send @ref TcpInReply, a reset (sec 3.5.2)
#define IDEMIP_TCP_IN_ACT_TEXT (1u << 2) ///< deliver @ref TcpInResult::text_len octets to the user
#define IDEMIP_TCP_IN_ACT_PUSH (1u << 3) ///< "carries a PUSH flag, then the user is informed"
#define IDEMIP_TCP_IN_ACT_URGENT (1u << 4)     ///< "signal the user that the remote side has urgent data"
#define IDEMIP_TCP_IN_ACT_ESTABLISHED (1u << 5) ///< the connection reached ESTABLISHED on this segment
#define IDEMIP_TCP_IN_ACT_CLOSING (1u << 6)    ///< signal the user "connection closing"
#define IDEMIP_TCP_IN_ACT_RESET (1u << 7)      ///< signal the user "connection reset"
#define IDEMIP_TCP_IN_ACT_REFUSED (1u << 8)    ///< signal the user "connection refused"
#define IDEMIP_TCP_IN_ACT_LISTEN (1u << 9)     ///< "return this connection to LISTEN state"
#define IDEMIP_TCP_IN_ACT_DELETE (1u << 10)    ///< "delete the TCB"
#define IDEMIP_TCP_IN_ACT_FLUSH (1u << 11)     ///< "the retransmission queue should be flushed"
#define IDEMIP_TCP_IN_ACT_ACKED (1u << 12)     ///< SND.UNA advanced by @ref TcpInResult::acked
#define IDEMIP_TCP_IN_ACT_HOLD (1u << 13)      ///< hold for later processing (sec 3.10.7.4, SHLD-31)
#define IDEMIP_TCP_IN_ACT_2MSL (1u << 14)      ///< "restart the 2 MSL time-wait timeout"
#define IDEMIP_TCP_IN_ACT_DUPACK (1u << 15)    ///< "If the ACK is a duplicate (SEG.ACK =< SND.UNA)"
#define IDEMIP_TCP_IN_ACT_WND (1u << 16)       ///< "the send window should be updated"

/**
 * @brief RFC 5961 sec 3.2 and sec 4.2's challenge ACK, which @ref IDEMIP_TCP_IN_ACT_ACK carries.
 */
#define IDEMIP_TCP_IN_ACT_CHALLENGE (1u << 17)

/**
 * @brief RFC 5961 sec 7's throttle suppressed the challenge ACK, so no segment goes out.
 *
 * "The system administrator can configure the number of challenge ACKs that can be sent out in a
 * given interval." Set with @ref IDEMIP_TCP_IN_ACT_CHALLENGE and without
 * @ref IDEMIP_TCP_IN_ACT_ACK.
 */
#define IDEMIP_TCP_IN_ACT_THROTTLED (1u << 18)

/**
 * @brief RFC 7323 sec 5.3 rule R1 rejected the segment: it carried a Timestamps option whose
 * SEG.TSval is behind TS.Recent while TS.Recent is valid.
 *
 * Set with @ref IDEMIP_TCP_IN_ACT_ACK, which R1's "Send an acknowledgment in reply ... and drop the
 * segment" forms. @ref TcpInResult::acceptable stays false, the Table 6 test never having run.
 */
#define IDEMIP_TCP_IN_ACT_PAWS (1u << 19)

// ---------------------------------------------------------------------------
// Options a parse found (RFC 9293 sec 3.2, RFC 7323, RFC 2018)
// ---------------------------------------------------------------------------

#define IDEMIP_TCP_IN_OPT_MSS (1u << 0)       ///< kind 2 was present
#define IDEMIP_TCP_IN_OPT_WS (1u << 1)        ///< kind 3 was present
#define IDEMIP_TCP_IN_OPT_TS (1u << 2)        ///< kind 8 was present
#define IDEMIP_TCP_IN_OPT_SACK_PERM (1u << 3) ///< kind 4 was present

/**
 * @brief What a parse takes: one segment as it lies, and the addresses its checksum covers.
 *
 * @var TcpInParseArgs::seg       the segment, its RFC 9293 sec 3.1 header first, in the caller's
 *                                storage
 * @var TcpInParseArgs::local_ip  the pseudo-header Destination Address, IDEMIP_TCP_PCB_ADDR_BYTES
 *                                octets
 * @var TcpInParseArgs::remote_ip its Source Address, the same width
 * @var TcpInParseArgs::len       the segment's octets, header and data
 * @var TcpInParseArgs::ip_version 4 for the RFC 9293 sec 3.1 pseudo-header, 6 for RFC 8200 sec 8.1's
 * @var TcpInParseArgs::snd_scale RFC 7323 sec 2.2 Snd.Wind.Shift, left-shifted onto every Window
 *                                field but a SYN's
 */
typedef struct
{
    const uint8_t *seg;
    const uint8_t *local_ip;
    const uint8_t *remote_ip;
    uint16_t len;
    uint8_t ip_version;
    uint8_t snd_scale;
} TcpInParseArgs;

/**
 * @brief The RFC 9293 sec 3.3.1 Table 4 current segment variables, and the sec 3.1 control bits.
 *
 * @var TcpInSegArgs::seq   SEG.SEQ, "segment sequence number"
 * @var TcpInSegArgs::ack   SEG.ACK, "segment acknowledgment number", significant only with ACK
 * @var TcpInSegArgs::wnd   SEG.WND, "segment window", already left-shifted by RFC 7323 sec 2.3's
 *                          Snd.Wind.Shift unless the segment carries SYN
 * @var TcpInSegArgs::len   SEG.LEN, "segment length", which sec 3.4 counts "counting SYN and FIN"
 * @var TcpInSegArgs::data_len the data octets alone, SEG.LEN less the SYN and FIN
 * @var TcpInSegArgs::up    SEG.UP, "segment urgent pointer", the sec 3.1 Urgent Pointer field, "a
 *                          positive offset from the sequence number in this segment"
 * @var TcpInSegArgs::flags the eight sec 3.1 control bits as carried
 */
typedef struct
{
    uint32_t seq;
    uint32_t ack;
    uint32_t wnd;
    uint32_t len;
    uint16_t data_len;
    uint16_t up;
    uint8_t flags;
} TcpInSegArgs;

/**
 * @brief What a parse read out of the options (RFC 9293 sec 3.2, RFC 7323 sec 2 and sec 3, RFC 2018).
 *
 * @var TcpInOpts::tsval   RFC 7323 sec 3.2 TSval, valid when IDEMIP_TCP_IN_OPT_TS is set
 * @var TcpInOpts::tsecr   RFC 7323 sec 3.2 TSecr, valid with TS and the ACK bit both set
 * @var TcpInOpts::mss     RFC 9293 sec 3.2 Maximum Segment Size, valid with IDEMIP_TCP_IN_OPT_MSS
 * @var TcpInOpts::hdr_len the header octets the Data Offset named
 * @var TcpInOpts::present which options were there
 * @var TcpInOpts::ws      RFC 7323 sec 2.2 shift.cnt, clamped to fourteen, read only from a segment
 *                         with the SYN bit: "A Window Scale option in a segment without a SYN bit
 *                         MUST be ignored"
 */
typedef struct
{
    uint32_t tsval;
    uint32_t tsecr;
    uint16_t mss;
    uint16_t hdr_len;
    uint8_t present;
    uint8_t ws;
} TcpInOpts;

/**
 * @brief The segment a call asks the caller to send.
 *
 * Every form RFC 9293 sec 3.10.7 emits is three fields: the acknowledgment
 * "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>", the two resets of sec 3.5.2, and the "<SEQ=ISS><ACK=RCV.NXT>
 * <CTL=SYN,ACK>" of sec 3.10.7.2.
 *
 * @var TcpInReply::seq   its Sequence Number
 * @var TcpInReply::ack   its Acknowledgment Number
 * @var TcpInReply::flags its control bits
 */
typedef struct
{
    uint32_t seq;
    uint32_t ack;
    uint16_t flags;
} TcpInReply;

/**
 * @brief What a call decided.
 *
 * @var TcpInResult::act        the actions above, ORed
 * @var TcpInResult::acked      octets SND.UNA advanced by, when IDEMIP_TCP_IN_ACT_ACKED is set
 * @var TcpInResult::text_seq   the Sequence Number of the first octet text_len covers
 * @var TcpInResult::text_off   octets from the segment's first data octet to that one, which is what
 *                              sec 3.10.7.4 trims: "If a segment's contents straddle the boundary
 *                              between old and new, only the new parts are processed."
 * @var TcpInResult::text_len   octets of that data inside the receive window
 * @var TcpInResult::acceptable the sec 3.4 Table 6 test's answer for this segment
 */
typedef struct
{
    uint32_t act;
    uint32_t acked;
    uint32_t text_seq;
    uint16_t text_off;
    uint16_t text_len;
    idemip_bool acceptable;
} TcpInResult;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var TcpInIo::parse_args the segment a parse reads
 * @var TcpInIo::seg        that segment's Table 4 variables and control bits, which a parse writes
 *                          and every other entry reads
 * @var TcpInIo::vars       the connection's RFC 9293 sec 3.3.1 variables, in and out
 * @var TcpInIo::ctl        its estimator, congestion and option state, in and out
 * @var TcpInIo::state      its RFC 9293 sec 3.3.2 state, in and out
 * @var TcpInIo::now_ms     the caller's monotonic millisecond count, which RFC 5961 sec 7's window is
 *                          measured on
 * @var TcpInIo::listener   the listener the connection was accepted through, IDEMIP_TCP_PCB_NONE for
 *                          an active OPEN. sec 3.5 (MUST-11).
 * @var TcpInIo::status     what the call reports: OK, BUSY, or ERR
 * @var TcpInIo::opts       what a parse read out of the options
 * @var TcpInIo::reply      the segment to send, when the actions ask for one
 * @var TcpInIo::res        what the call decided
 */
typedef struct
{
    TcpInParseArgs parse_args;
    TcpInSegArgs seg;

    IdemIpTcpVars vars;
    TcpPcbCtl ctl;
    IdemIpTcpState state;
    uint16_t listener;
    uint32_t now_ms;

    IdemIpStatus status;
    TcpInOpts opts;
    TcpInReply reply;
    TcpInResult res;
} TcpInIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime.

#define IDEMIP_TCP_IN_OFF_IO 0u ///< the operand and result block
#define IDEMIP_TCP_IN_OFF_CTX (IDEMIP_TCP_IN_OFF_IO + IDEMIP_ROUND_UP(sizeof(TcpInIo), IDEMIP_ALIGN)) ///< the running context

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_TCP_IN_IO(w) ((TcpInIo *)(void *)((w) + IDEMIP_TCP_IN_OFF_IO))

/**
 * @brief RFC 9293 sec 3.10.7 SEGMENT ARRIVES, over one connection's variables.
 *
 *   TcpIn.clear(work);
 *   IDEMIP_TCP_IN_IO(work)->parse_args.seg = frame + off;
 *   TcpIn.parse(work);
 *   IDEMIP_TCP_IN_IO(work)->vars = pcb_vars;
 *   TcpIn.segment(work);
 *   if (IDEMIP_TCP_IN_IO(work)->res.act & IDEMIP_TCP_IN_ACT_ACK) { ... }
 *
 * @c work is IDEMIP_TCP_IN_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * segment paths are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. A borrow that was never cleared, a state sec 3.3.2 does not name, a version
 * that names no address family, and a segment shorter than its own Data Offset are ERR: none of them
 * changes on a later tick. No entry reports BUSY, because none of them holds a resource that a later
 * call frees.
 *
 * @var TcpInNs::clear      zero the context and mark the borrow usable
 * @var TcpInNs::parse      read one segment's sec 3.1 header and sec 3.2 options into
 *                          @ref TcpInIo::seg and @ref TcpInIo::opts, after checking the Data Offset
 *                          and the checksum over the sec 3.1 pseudo-header
 * @var TcpInNs::acceptable the sec 3.4 Table 6 test alone, reported in
 *                          @ref TcpInResult::acceptable
 * @var TcpInNs::closed     sec 3.10.7.1 CLOSED STATE
 * @var TcpInNs::listen     sec 3.10.7.2 LISTEN STATE
 * @var TcpInNs::syn_sent   sec 3.10.7.3 SYN-SENT STATE
 * @var TcpInNs::segment    sec 3.10.7.4 Other States, all eight checks in the order it lists them,
 *                          with RFC 5961 sec 3.2's RST rule, sec 4.2's SYN rule, sec 5.2's ACK range
 *                          and RFC 1337's fix F1
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const parse)(uint8_t *work);
    void (*const acceptable)(uint8_t *work);
    void (*const closed)(uint8_t *work);
    void (*const listen)(uint8_t *work);
    void (*const syn_sent)(uint8_t *work);
    void (*const segment)(uint8_t *work);
} TcpInNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_tcp_in_clear(uint8_t *work);
void idemip_tcp_in_parse(uint8_t *work);
void idemip_tcp_in_acceptable(uint8_t *work);
void idemip_tcp_in_closed(uint8_t *work);
void idemip_tcp_in_listen(uint8_t *work);
void idemip_tcp_in_syn_sent(uint8_t *work);
void idemip_tcp_in_segment(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `TcpIn.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const TcpInNs TcpIn IDEMIP_UNUSED = {
    .clear = idemip_tcp_in_clear,
    .parse = idemip_tcp_in_parse,
    .acceptable = idemip_tcp_in_acceptable,
    .closed = idemip_tcp_in_closed,
    .listen = idemip_tcp_in_listen,
    .syn_sent = idemip_tcp_in_syn_sent,
    .segment = idemip_tcp_in_segment};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TCP

#endif // IDEMIP_TCP_IN_H
