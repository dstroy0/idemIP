// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp_out.h
 * @brief The send path: building a segment, deciding when to send it, and the timers and windows
 *        that govern that.
 *
 * A build writes one RFC 9293 sec 3.1 header, its sec 3.2 options and the caller's data octets into
 * the caller's own buffer and checksums the result over the sec 3.1 pseudo-header. The rest is
 * arithmetic on one connection's RFC 9293 sec 3.3.1 variables and control state, which arrive in the
 * operand block and go back out of it: the sec 3.8.6.2.1 sender's algorithm with the sec 3.7.4 Nagle
 * condition, the RFC 6298 retransmission timer, and the RFC 5681 congestion window with RFC 3465
 * byte counting.
 *
 * Nothing here claims a transmit buffer, sends a segment, or reaches a TCB table. A caller loads the
 * TCB through @ref TcpPcbNs::load, calls one entry, and stores what came back.
 */

#ifndef IDEMIP_TCP_OUT_H
#define IDEMIP_TCP_OUT_H

#include "src/tcp/tcp_pcb.h"

#if IDEMIP_ENABLE_TCP

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// Which options a build carries (RFC 9293 sec 3.2, RFC 7323, RFC 2018)
// ---------------------------------------------------------------------------

#define IDEMIP_TCP_OUT_OPT_MSS (1u << 0)       ///< kind 2, RFC 9293 sec 3.2, SYN segments only
#define IDEMIP_TCP_OUT_OPT_WS (1u << 1)        ///< kind 3, RFC 7323 sec 2.2, SYN segments only
#define IDEMIP_TCP_OUT_OPT_TS (1u << 2)        ///< kind 8, RFC 7323 sec 3.2
#define IDEMIP_TCP_OUT_OPT_SACK_PERM (1u << 3) ///< kind 4, RFC 2018 sec 2, SYN segments only
#define IDEMIP_TCP_OUT_OPT_SACK (1u << 4)      ///< kind 5, RFC 2018 sec 3

/**
 * @brief What a build takes: one segment, and the buffer to write it into.
 *
 * @var TcpOutBuildArgs::buf         the caller's bytes, which the segment is written into
 * @var TcpOutBuildArgs::data        the data octets, in the caller's storage, null for a segment
 *                                   carrying only control bits
 * @var TcpOutBuildArgs::local_ip    the pseudo-header Source Address, IDEMIP_TCP_PCB_ADDR_BYTES
 *                                   octets
 * @var TcpOutBuildArgs::remote_ip   its Destination Address, the same width
 * @var TcpOutBuildArgs::seq         the RFC 9293 sec 3.1 Sequence Number
 * @var TcpOutBuildArgs::ack         its Acknowledgment Number
 * @var TcpOutBuildArgs::wnd         RCV.WND, which RFC 7323 sec 2.3 right-shifts by Rcv.Wind.Shift
 *                                   onto the Window field of every segment but a SYN
 * @var TcpOutBuildArgs::tsval       RFC 7323 sec 3.2 TSval
 * @var TcpOutBuildArgs::tsecr       RFC 7323 sec 3.2 TSecr
 * @var TcpOutBuildArgs::cap         octets @ref TcpOutBuildArgs::buf holds
 * @var TcpOutBuildArgs::len         data octets
 * @var TcpOutBuildArgs::up          the Urgent Pointer field, significant only with URG
 * @var TcpOutBuildArgs::mss         the kind 2 option's value
 * @var TcpOutBuildArgs::local_port  the Source Port
 * @var TcpOutBuildArgs::remote_port the Destination Port
 * @var TcpOutBuildArgs::opts        which options to carry
 * @var TcpOutBuildArgs::flags       the eight sec 3.1 control bits
 * @var TcpOutBuildArgs::ws          the kind 3 option's shift.cnt, clamped to fourteen
 * @var TcpOutBuildArgs::rcv_scale   RFC 7323 sec 2.2 Rcv.Wind.Shift
 * @var TcpOutBuildArgs::sack_blocks blocks of @ref TcpPcbCtl::sack_left and
 *                                   @ref TcpPcbCtl::sack_right the kind 5 option carries
 * @var TcpOutBuildArgs::ip_version  4 for the RFC 9293 sec 3.1 pseudo-header, 6 for RFC 8200 sec
 *                                   8.1's
 */
typedef struct
{
    uint8_t *buf;
    const uint8_t *data;
    const uint8_t *local_ip;
    const uint8_t *remote_ip;
    uint32_t seq;
    uint32_t ack;
    uint32_t wnd;
    uint32_t tsval;
    uint32_t tsecr;
    uint16_t cap;
    uint16_t len;
    uint16_t up;
    uint16_t mss;
    uint16_t local_port;
    uint16_t remote_port;
    uint16_t opts;
    uint8_t flags;
    uint8_t ws;
    uint8_t rcv_scale;
    uint8_t sack_blocks;
    uint8_t ip_version;
} TcpOutBuildArgs;

/**
 * @brief What the RFC 9293 sec 3.8.6.2.1 sender's algorithm takes.
 *
 * @var TcpOutSendArgs::queued      D, "the amount of data queued in the sending TCP endpoint but not
 *                                  yet sent"
 * @var TcpOutSendArgs::eff_snd_mss Eff.snd.MSS, the largest segment this connection may send
 * @var TcpOutSendArgs::push        "the data is pushed"
 * @var TcpOutSendArgs::nodelay     the Nagle algorithm is off on this connection, which sec 3.7.4
 *                                  (MUST-17) requires be possible
 * @var TcpOutSendArgs::force       "or if the override timeout occurs", rule (4)
 * @var TcpOutSendArgs::now_ms      the caller's monotonic millisecond count, which RFC 5681 sec 4.1
 *                                  measures the idle interval against
 */
typedef struct
{
    uint32_t queued;
    uint32_t eff_snd_mss;
    uint32_t now_ms;
    idemip_bool push;
    idemip_bool nodelay;
    idemip_bool force;
} TcpOutSendArgs;

/**
 * @brief What the RFC 6298 sec 5 timer entries and the RFC 5681 congestion entries take.
 *
 * @var TcpOutTimerArgs::now_ms    the caller's monotonic millisecond count
 * @var TcpOutTimerArgs::sample_ms R, one round-trip time measurement, in milliseconds
 * @var TcpOutTimerArgs::flight    FlightSize, "the amount of outstanding data in the network"
 * @var TcpOutTimerArgs::acked     N, "the number of previously unacknowledged bytes acknowledged in
 *                                 the incoming ACK"
 * @var TcpOutTimerArgs::smss      SMSS, the sender maximum segment size
 * @var TcpOutTimerArgs::resent    the segment at the front of the retransmission queue "has already
 *                                 been retransmitted by way of the retransmission timer at least
 *                                 once", which holds ssthresh constant
 */
typedef struct
{
    uint32_t now_ms;
    uint32_t sample_ms;
    uint32_t flight;
    uint32_t acked;
    uint32_t smss;
    idemip_bool resent;
} TcpOutTimerArgs;

/**
 * @brief What a reset takes: the fields of the segment it answers (RFC 9293 sec 3.5.2).
 *
 * @var TcpOutSegArgs::seq   that segment's SEG.SEQ
 * @var TcpOutSegArgs::ack   its SEG.ACK
 * @var TcpOutSegArgs::len   its SEG.LEN, counting the SYN and FIN
 * @var TcpOutSegArgs::flags its control bits
 */
typedef struct
{
    uint32_t seq;
    uint32_t ack;
    uint32_t len;
    uint8_t flags;
} TcpOutSegArgs;

/**
 * @brief The segment an ack or a rst asks the caller to send.
 *
 * @var TcpOutReply::seq   its Sequence Number
 * @var TcpOutReply::ack   its Acknowledgment Number
 * @var TcpOutReply::flags its control bits
 */
typedef struct
{
    uint32_t seq;
    uint32_t ack;
    uint16_t flags;
} TcpOutReply;

/**
 * @brief What a call decided.
 *
 * @var TcpOutResult::built    octets a build wrote, header, options and data
 * @var TcpOutResult::hdr_len  the header octets of those, options included
 * @var TcpOutResult::usable   U, "SND.UNA + SND.WND - SND.NXT", already held down to what the RFC
 *                             5681 congestion window leaves
 * @var TcpOutResult::send_len octets the sec 3.8.6.2.1 rules say to send now
 * @var TcpOutResult::send_now whether any of those rules fired
 */
typedef struct
{
    uint16_t built;
    uint16_t hdr_len;
    uint32_t usable;
    uint32_t send_len;
    idemip_bool send_now;
} TcpOutResult;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var TcpOutIo::build_args the segment a build writes, and the buffer it writes into
 * @var TcpOutIo::send_args  what the sec 3.8.6.2.1 sender's algorithm takes
 * @var TcpOutIo::timer_args what the RFC 6298 and RFC 5681 entries take
 * @var TcpOutIo::seg_args   the segment a rst answers
 * @var TcpOutIo::vars       the connection's RFC 9293 sec 3.3.1 variables, in and out
 * @var TcpOutIo::ctl        its estimator, congestion and option state, in and out
 * @var TcpOutIo::state      its RFC 9293 sec 3.3.2 state
 * @var TcpOutIo::status     what the call reports: OK, BUSY, or ERR
 * @var TcpOutIo::reply      what an ack or a rst asks the caller to send
 * @var TcpOutIo::res        what the call decided
 */
typedef struct
{
    TcpOutBuildArgs build_args;
    TcpOutSendArgs send_args;
    TcpOutTimerArgs timer_args;
    TcpOutSegArgs seg_args;

    IdemIpTcpVars vars;
    TcpPcbCtl ctl;
    IdemIpTcpState state;

    IdemIpStatus status;
    TcpOutReply reply;
    TcpOutResult res;
} TcpOutIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime.

#define IDEMIP_TCP_OUT_OFF_IO 0u ///< the operand and result block
#define IDEMIP_TCP_OUT_OFF_CTX (IDEMIP_TCP_OUT_OFF_IO + sizeof(TcpOutIo)) ///< the running context

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_TCP_OUT_IO(w) ((TcpOutIo *)(void *)((w) + IDEMIP_TCP_OUT_OFF_IO))

/**
 * @brief The send path of RFC 9293 sec 3.7 and sec 3.8, over one connection's variables.
 *
 *   TcpOut.clear(work);
 *   IDEMIP_TCP_OUT_IO(work)->build_args.buf = tx;
 *   TcpOut.build(work);
 *   if (IDEMIP_TCP_OUT_IO(work)->status == IDEMIP_OK) { ... res.built octets ... }
 *
 * @c work is IDEMIP_TCP_OUT_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * send paths are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. A borrow that was never cleared, a null buffer, a version that names no
 * address family, and a buffer shorter than the segment asked for are ERR: none of them changes on a
 * later tick. No entry reports BUSY, because none holds a resource a later call frees; a transmit
 * ring with no room is phy's BUSY, on the buffer this builds into.
 *
 * @var TcpOutNs::clear       zero the context and mark the borrow usable
 * @var TcpOutNs::build       write one sec 3.1 header, its sec 3.2 options and the data into
 *                            @ref TcpOutBuildArgs::buf, and checksum it over the sec 3.1
 *                            pseudo-header
 * @var TcpOutNs::send        the sec 3.8.6.2.1 sender's algorithm with the sec 3.7.4 Nagle
 *                            condition, reporting U and how much to send now
 * @var TcpOutNs::ack         form "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>", which is both the sec
 *                            3.10.7.4 acknowledgment and RFC 5961's challenge ACK
 * @var TcpOutNs::rst         form the reset sec 3.5.2 sends for the segment in
 *                            @ref TcpOutIo::seg_args
 * @var TcpOutNs::rtt         RFC 6298 (2.2) and (2.3), the SRTT, RTTVAR and RTO update from one
 *                            measurement, with (2.4)'s floor and (2.5)'s ceiling, and sec 3's Karn
 *                            algorithm refusing a sample taken across a retransmission
 * @var TcpOutNs::rtx_arm     RFC 6298 (5.1), start the timer if it is not running
 * @var TcpOutNs::rtx_stop    RFC 6298 (5.2), turn it off, all outstanding data being acknowledged
 * @var TcpOutNs::rtx_restart RFC 6298 (5.3), restart it, an ACK having acknowledged new data
 * @var TcpOutNs::rtx_expire  RFC 6298 (5.5) "the host MUST set RTO <- RTO * 2" and (5.6), with RFC
 *                            5681 sec 3.1's ssthresh and loss window
 * @var TcpOutNs::cc_init     RFC 5681 sec 3.1's initial window IW from SMSS, and the ssthresh a
 *                            transfer starts at
 * @var TcpOutNs::cc_ack      RFC 5681 sec 3.1 slow start and congestion avoidance, by RFC 3465 sec
 *                            2.1 and sec 2.2 byte counting
 * @var TcpOutNs::cc_dupack   RFC 5681 sec 3.2 steps 2, 3 and 4, fast retransmit and fast recovery
 * @var TcpOutNs::cc_recover  RFC 5681 sec 3.2 step 6, deflating cwnd back to ssthresh
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const build)(uint8_t *restrict work);
    void (*const send)(uint8_t *restrict work);
    void (*const ack)(uint8_t *restrict work);
    void (*const rst)(uint8_t *restrict work);
    void (*const rtt)(uint8_t *restrict work);
    void (*const rtx_arm)(uint8_t *restrict work);
    void (*const rtx_stop)(uint8_t *restrict work);
    void (*const rtx_restart)(uint8_t *restrict work);
    void (*const rtx_expire)(uint8_t *restrict work);
    void (*const cc_init)(uint8_t *restrict work);
    void (*const cc_ack)(uint8_t *restrict work);
    void (*const cc_dupack)(uint8_t *restrict work);
    void (*const cc_recover)(uint8_t *restrict work);
} TcpOutNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const TcpOutNs TcpOut;

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TCP

#endif // IDEMIP_TCP_OUT_H
