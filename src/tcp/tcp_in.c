// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp_in.c
 * @brief RFC 9293 sec 3.10.7 SEGMENT ARRIVES, over the connection variables in the caller's borrow.
 *
 * The operand block and the context are regions of the one pointer each entry is handed, at
 * compile-time offsets, and no entry reads or writes a byte outside it or the segment the operand
 * block names. Two borrows therefore share nothing, and the same call on the same borrow does the
 * same thing.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/pseudo.h"
#include "src/tcp/tcp_in.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. A borrow that was never cleared carries no mark, so every
// entry refuses it. The two counters are RFC 5961 sec 7's throttle, which that section says needs "no
// timer ... instead a timestamp and a counter can be used".
typedef struct
{
    uint32_t ready;
    uint32_t challenge_at;
    uint32_t challenges;
} TcpInCtx;

// The mark clear leaves.
#define TCP_IN_READY 0x54435049u

// The caller's borrow, split: the operand block, then the context. tcp_in.h publishes the offsets;
// the assert below proves the span covers them before anything runs.
static_assert(IDEMIP_TCP_IN_OFF_CTX + sizeof(TcpInCtx) <= IDEMIP_TCP_IN_BORROW,
              "IDEMIP_TCP_IN_BORROW is short of the operand block and the context - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define TCP_IN_CTX(w) ((TcpInCtx *)(void *)((w) + IDEMIP_TCP_IN_OFF_CTX))
#define TCP_IN_IO(w) IDEMIP_TCP_IN_IO(w)

// --- the sequence space ----------------------------------------------------

// RFC 9293 sec 3.4: "all arithmetic dealing with sequence numbers must be performed modulo 2^32. This
// unsigned arithmetic preserves the relationship of sequence numbers as they cycle from 2^32 - 1 to 0
// again." A number's distance forward from an edge is that subtraction, and those distances order the
// whole space from that edge with no wrap ambiguity.
static uint32_t tcp_in_from(uint32_t seq, uint32_t edge)
{
    return seq - edge;
}

// RFC 9293 sec 3.4's "acceptable ack": "SND.UNA < SEG.ACK =< SND.NXT".
static idemip_bool tcp_in_ack_new(uint32_t ack, uint32_t una, uint32_t nxt)
{
    uint32_t at = tcp_in_from(ack, una);
    return (at != 0u && at <= tcp_in_from(nxt, una)) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 9293 sec 3.10.7.4 fifth's window-update guard, "SND.UNA =< SEG.ACK =< SND.NXT".
static idemip_bool tcp_in_ack_within(uint32_t ack, uint32_t una, uint32_t nxt)
{
    return (tcp_in_from(ack, una) <= tcp_in_from(nxt, una)) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 5961 sec 5.2: "The ACK value is considered acceptable only if it is in the range of
// ((SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT)", MAX.SND.WND being "the largest window that the
// local sender has ever received from its peer". The left edge is that subtraction modulo 2^32, and
// every comparison is a distance from it.
static idemip_bool tcp_in_ack_in_range(uint32_t ack, uint32_t una, uint32_t nxt, uint32_t max_snd_wnd)
{
    uint32_t left = una - max_snd_wnd;
    return (tcp_in_from(ack, left) <= tcp_in_from(nxt, left)) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 9293 sec 3.10.7.4 Table 6, all four cases of "the acceptability test for an incoming segment".
// SEG.LEN counts the SYN and FIN that occupy sequence space (sec 3.4).
static idemip_bool tcp_in_seg_acceptable(uint32_t seq, uint32_t len, uint32_t rcv_nxt, uint32_t rcv_wnd)
{
    if (len == 0u)
    {
        if (rcv_wnd == 0u)
        {
            return (seq == rcv_nxt) ? IDEMIP_TRUE : IDEMIP_FALSE; // SEG.SEQ = RCV.NXT
        }
        return (tcp_in_from(seq, rcv_nxt) < rcv_wnd) ? IDEMIP_TRUE : IDEMIP_FALSE;
    }
    if (rcv_wnd == 0u)
    {
        return IDEMIP_FALSE; // "not acceptable"
    }
    if (tcp_in_from(seq, rcv_nxt) < rcv_wnd)
    {
        return IDEMIP_TRUE; // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    }
    // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    return (tcp_in_from(seq + len - 1u, rcv_nxt) < rcv_wnd) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 5961 sec 3.2 step 3's "within the current receive window (RCV.NXT < SEG.SEQ <
// RCV.NXT+RCV.WND)", which is the span that earns a challenge ACK rather than a reset.
static idemip_bool tcp_in_rst_in_window(uint32_t seq, uint32_t rcv_nxt, uint32_t rcv_wnd)
{
    uint32_t at = tcp_in_from(seq, rcv_nxt);
    return (at != 0u && at < rcv_wnd) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- the replies -----------------------------------------------------------

// RFC 9293 sec 3.10.7.4 first: "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>". The same three fields carry
// sec 3.5.2 group 3's "empty acknowledgment segment ... containing the current send sequence number
// and an acknowledgment indicating the next sequence number expected to be received", RFC 5961 sec
// 3.2's challenge ACK and RFC 5961 sec 4.2's.
static void tcp_in_put_ack(TcpInIo *io)
{
    io->reply.seq = io->vars.snd_nxt;
    io->reply.ack = io->vars.rcv_nxt;
    io->reply.flags = (uint16_t)IDEMIP_TCP_ACK;
    io->res.act |= IDEMIP_TCP_IN_ACT_ACK;
}

// RFC 9293 sec 3.5.2 group 2: "If the incoming segment has an ACK field, the reset takes its sequence
// number from the ACK field of the segment; otherwise, the reset has sequence number zero and the ACK
// field is set to the sum of the sequence number and segment length of the incoming segment."
static void tcp_in_put_rst(TcpInIo *io)
{
    if ((io->seg.flags & IDEMIP_TCP_ACK) != 0u)
    {
        io->reply.seq = io->seg.ack;
        io->reply.ack = 0u;
        io->reply.flags = (uint16_t)IDEMIP_TCP_RST;
    }
    else
    {
        io->reply.seq = 0u;
        io->reply.ack = io->seg.seq + io->seg.len;
        io->reply.flags = (uint16_t)(IDEMIP_TCP_RST | IDEMIP_TCP_ACK);
    }
    io->res.act |= IDEMIP_TCP_IN_ACT_RST;
}

// RFC 5961 sec 7: "in any 5 second window, no more than 10 challenge ACKs should be sent", counted
// with "a timestamp and a counter". A challenge past the limit is reported and not sent, so the
// segment is still dropped and the exchange sec 10 warns about is bounded.
static void tcp_in_put_challenge(uint8_t *restrict work, TcpInIo *io)
{
    TcpInCtx *ctx = TCP_IN_CTX(work);
    io->res.act |= IDEMIP_TCP_IN_ACT_CHALLENGE;
    if (tcp_in_from(io->now_ms, ctx->challenge_at) >= (uint32_t)IDEMIP_TCP_CHALLENGE_WINDOW_MS)
    {
        ctx->challenge_at = io->now_ms;
        ctx->challenges = 0u;
    }
    if (ctx->challenges >= (uint32_t)IDEMIP_TCP_CHALLENGE_ACKS)
    {
        io->res.act |= IDEMIP_TCP_IN_ACT_THROTTLED;
        return;
    }
    ctx->challenges++;
    tcp_in_put_ack(io);
}

// The operand block's result members, before a call decides anything.
static void tcp_in_result_clear(TcpInIo *io)
{
    io->reply.seq = 0u;
    io->reply.ack = 0u;
    io->reply.flags = 0u;
    io->res.act = 0u;
    io->res.acked = 0u;
    io->res.text_seq = 0u;
    io->res.text_off = 0u;
    io->res.text_len = 0u;
    io->res.acceptable = IDEMIP_FALSE;
}

// --- the entries -----------------------------------------------------------

// The context is the whole borrow past the operand block, so one store covers it. The operand block
// is the caller's and is left as it was found, except for the members a call reports through.
static void tcp_in_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    TcpInIo *io = TCP_IN_IO(work);
    memset(work + IDEMIP_TCP_IN_OFF_CTX, 0, (size_t)IDEMIP_TCP_IN_BORROW - IDEMIP_TCP_IN_OFF_CTX);
    TCP_IN_CTX(work)->ready = TCP_IN_READY;
    memset(&io->seg, 0, sizeof io->seg);
    memset(&io->opts, 0, sizeof io->opts);
    tcp_in_result_clear(io);
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.1's header and sec 3.2's options, read where they lie. The checksum covers the
// pseudo-header of sec 3.1 over IPv4 and of RFC 8200 sec 8.1 over IPv6, and RFC 1071 sec 1 makes a
// span that already carries its checksum sum to all ones, so the verify is that sum against zero.
// SEG.LEN is the data octets "counting SYN and FIN" (sec 3.4). RFC 7323 sec 2.3: "The window field
// (SEG.WND) in the header of every incoming segment, with the exception of <SYN> segments, MUST be
// left-shifted by Snd.Wind.Shift bits."
static void tcp_in_parse(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpInIo *io = TCP_IN_IO(work);
    io->status = IDEMIP_ERR;
    memset(&io->seg, 0, sizeof io->seg);
    memset(&io->opts, 0, sizeof io->opts);
    if (TCP_IN_CTX(work)->ready != TCP_IN_READY || io->parse_args.seg == NULL || io->parse_args.local_ip == NULL ||
        io->parse_args.remote_ip == NULL)
    {
        return;
    }
    if (io->parse_args.len < (uint16_t)IDEMIP_TCP_HDR_LEN)
    {
        return;
    }
    const uint8_t *h = io->parse_args.seg;
    size_t hdr = idemip_tcp_hdr_len(h);
    if (hdr < (size_t)IDEMIP_TCP_HDR_LEN || hdr > (size_t)io->parse_args.len)
    {
        return;
    }
    uint32_t sum = 0u;
    if (!idemip_pseudo_accum(&sum, io->parse_args.ip_version, (uint8_t)IDEMIP_TCP_PROTO, io->parse_args.remote_ip,
                             io->parse_args.local_ip, (uint32_t)io->parse_args.len))
    {
        return; // a version that names no pseudo-header
    }
    if (idemip_cksum_final(idemip_cksum_accum(sum, h, (size_t)io->parse_args.len)) != 0u)
    {
        return;
    }

    uint8_t flags = idemip_tcp_flags(h);
    uint16_t data = (uint16_t)((size_t)io->parse_args.len - hdr);
    uint32_t len = (uint32_t)data;
    if ((flags & IDEMIP_TCP_SYN) != 0u)
    {
        len++;
    }
    if ((flags & IDEMIP_TCP_FIN) != 0u)
    {
        len++;
    }
    io->seg.seq = idemip_tcp_seq(h);
    io->seg.ack = idemip_tcp_ack(h);
    io->seg.len = len;
    io->seg.data_len = data;
    io->seg.up = idemip_tcp_urgent(h);
    io->seg.flags = flags;
    io->seg.wnd = (uint32_t)idemip_tcp_window(h);
    if ((flags & IDEMIP_TCP_SYN) == 0u)
    {
        uint8_t shift = io->parse_args.snd_scale;
        if (shift > (uint8_t)IDEMIP_TCP_WS_MAX)
        {
            shift = (uint8_t)IDEMIP_TCP_WS_MAX;
        }
        io->seg.wnd <<= shift;
    }
    io->opts.hdr_len = (uint16_t)hdr;

    IdemIpTcpOptWalk w;
    idemip_tcp_opt_walk(&w, h);
    while (idemip_tcp_opt_next(&w))
    {
        if (w.kind == (uint8_t)IDEMIP_TCP_OPT_MSS && w.len == (uint8_t)IDEMIP_TCP_OPT_MSS_LEN)
        {
            io->opts.mss = idemip_tcp_opt_mss(w.opt);
            io->opts.present |= (uint8_t)IDEMIP_TCP_IN_OPT_MSS;
        }
        else if (w.kind == (uint8_t)IDEMIP_TCP_OPT_WS && w.len == (uint8_t)IDEMIP_TCP_OPT_WS_LEN)
        {
            io->opts.ws = idemip_tcp_opt_ws(w.opt);
            io->opts.present |= (uint8_t)IDEMIP_TCP_IN_OPT_WS;
        }
        else if (w.kind == (uint8_t)IDEMIP_TCP_OPT_TS && w.len == (uint8_t)IDEMIP_TCP_OPT_TS_LEN)
        {
            io->opts.tsval = idemip_tcp_opt_tsval(w.opt);
            io->opts.tsecr = idemip_tcp_opt_tsecr(w.opt);
            io->opts.present |= (uint8_t)IDEMIP_TCP_IN_OPT_TS;
        }
        else if (w.kind == (uint8_t)IDEMIP_TCP_OPT_SACK_PERM && w.len == (uint8_t)IDEMIP_TCP_OPT_SACK_PERM_LEN)
        {
            io->opts.present |= (uint8_t)IDEMIP_TCP_IN_OPT_SACK_PERM;
        }
    }
    // RFC 9293 sec 3.1 MUST-7: "TCP implementations MUST be prepared to handle an illegal option
    // length (e.g., zero)". The walk stops on one and says so, and the options read before it stand.
    io->status = w.bad ? IDEMIP_ERR : IDEMIP_OK;
}

// RFC 9293 sec 3.4's "A segment is judged to occupy a portion of valid receive sequence space", in
// the four cases sec 3.10.7.4 Table 6 lays out.
static void tcp_in_acceptable(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpInIo *io = TCP_IN_IO(work);
    io->status = IDEMIP_ERR;
    tcp_in_result_clear(io);
    if (TCP_IN_CTX(work)->ready != TCP_IN_READY)
    {
        return;
    }
    io->res.acceptable = tcp_in_seg_acceptable(io->seg.seq, io->seg.len, io->vars.rcv_nxt, io->vars.rcv_wnd);
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.10.7.1: "If the state is CLOSED (i.e., TCB does not exist) ... An incoming segment
// containing a RST is discarded. An incoming segment not containing a RST causes a RST to be sent in
// response."
static void tcp_in_closed(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpInIo *io = TCP_IN_IO(work);
    io->status = IDEMIP_ERR;
    tcp_in_result_clear(io);
    if (TCP_IN_CTX(work)->ready != TCP_IN_READY)
    {
        return;
    }
    io->status = IDEMIP_OK;
    if ((io->seg.flags & IDEMIP_TCP_RST) != 0u)
    {
        return;
    }
    tcp_in_put_rst(io);
}

// RFC 9293 sec 3.10.7.2 LISTEN STATE, its four checks in order. The ISS the third needs is
// @ref IdemIpTcpVars::iss, which the caller draws through tcp_isn.h before the call.
static void tcp_in_listen(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpInIo *io = TCP_IN_IO(work);
    io->status = IDEMIP_ERR;
    tcp_in_result_clear(io);
    if (TCP_IN_CTX(work)->ready != TCP_IN_READY || io->state != IDEMIP_TCP_STATE_LISTEN)
    {
        return;
    }
    io->status = IDEMIP_OK;

    // First: "An incoming RST should be ignored. Return."
    if ((io->seg.flags & IDEMIP_TCP_RST) != 0u)
    {
        return;
    }
    // Second: "Any acknowledgment is bad if it arrives on a connection still in the LISTEN state."
    if ((io->seg.flags & IDEMIP_TCP_ACK) != 0u)
    {
        io->reply.seq = io->seg.ack;
        io->reply.ack = 0u;
        io->reply.flags = (uint16_t)IDEMIP_TCP_RST;
        io->res.act |= IDEMIP_TCP_IN_ACT_RST;
        return;
    }
    // Fourth: "This should not be reached. Drop the segment and return."
    if ((io->seg.flags & IDEMIP_TCP_SYN) == 0u)
    {
        return;
    }
    // Third: "Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ ... SND.NXT is set to ISS+1 and SND.UNA
    // to ISS. The connection state should be changed to SYN-RECEIVED."
    io->vars.rcv_nxt = io->seg.seq + 1u;
    io->vars.irs = io->seg.seq;
    io->vars.snd_nxt = io->vars.iss + 1u;
    io->vars.snd_una = io->vars.iss;
    io->vars.snd_wnd = io->seg.wnd;
    io->vars.snd_wl1 = io->seg.seq;
    io->vars.snd_wl2 = io->vars.iss;
    // RFC 5961 sec 5.2 defines MAX.SND.WND as "the largest window that the local sender has ever
    // received from its peer", so every window this connection takes raises it.
    if (io->seg.wnd > io->ctl.max_snd_wnd)
    {
        io->ctl.max_snd_wnd = io->seg.wnd;
    }
    io->state = IDEMIP_TCP_STATE_SYN_RECEIVED;
    io->reply.seq = io->vars.iss;
    io->reply.ack = io->vars.rcv_nxt;
    io->reply.flags = (uint16_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK);
    io->res.act |= IDEMIP_TCP_IN_ACT_ACK;
}

// RFC 9293 sec 3.10.7.3 SYN-SENT STATE, its five checks in order. The third, the security and
// compartment of Appendix A.1, has nothing in a TCB here to compare and is not made.
static void tcp_in_syn_sent(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpInIo *io = TCP_IN_IO(work);
    io->status = IDEMIP_ERR;
    tcp_in_result_clear(io);
    if (TCP_IN_CTX(work)->ready != TCP_IN_READY || io->state != IDEMIP_TCP_STATE_SYN_SENT)
    {
        return;
    }
    io->status = IDEMIP_OK;

    idemip_bool ack_ok = IDEMIP_FALSE;
    // First: "If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit is set, if so
    // drop the segment and return) ... If SND.UNA < SEG.ACK =< SND.NXT, then the ACK is acceptable."
    if ((io->seg.flags & IDEMIP_TCP_ACK) != 0u)
    {
        if (tcp_in_from(io->seg.ack, io->vars.iss) == 0u ||
            tcp_in_from(io->seg.ack, io->vars.iss) > tcp_in_from(io->vars.snd_nxt, io->vars.iss))
        {
            if ((io->seg.flags & IDEMIP_TCP_RST) != 0u)
            {
                return;
            }
            io->reply.seq = io->seg.ack;
            io->reply.ack = 0u;
            io->reply.flags = (uint16_t)IDEMIP_TCP_RST;
            io->res.act |= IDEMIP_TCP_IN_ACT_RST;
            return;
        }
        ack_ok = tcp_in_ack_new(io->seg.ack, io->vars.snd_una, io->vars.snd_nxt);
    }
    // Second: "If the ACK was acceptable, then signal to the user 'error: connection reset', drop the
    // segment, enter CLOSED state, delete TCB, and return. Otherwise (no ACK), drop the segment and
    // return." RFC 5961 sec 3.2's exact-RCV.NXT check is the synchronized-state rule and does not
    // apply here: in SYN-SENT no IRS has been taken, so RCV.NXT names nothing to match.
    if ((io->seg.flags & IDEMIP_TCP_RST) != 0u)
    {
        if (ack_ok)
        {
            io->state = IDEMIP_TCP_STATE_CLOSED;
            io->res.act |= IDEMIP_TCP_IN_ACT_RESET | IDEMIP_TCP_IN_ACT_FLUSH | IDEMIP_TCP_IN_ACT_DELETE;
        }
        return;
    }
    // Fifth: "if neither of the SYN or RST bits is set, then drop the segment and return."
    if ((io->seg.flags & IDEMIP_TCP_SYN) == 0u)
    {
        return;
    }
    // Fourth: "RCV.NXT is set to SEG.SEQ+1, IRS is set to SEG.SEQ. SND.UNA should be advanced to
    // equal SEG.ACK (if there is an ACK), and any segments on the retransmission queue that are
    // thereby acknowledged should be removed."
    io->vars.rcv_nxt = io->seg.seq + 1u;
    io->vars.irs = io->seg.seq;
    if (ack_ok)
    {
        io->res.acked = tcp_in_from(io->seg.ack, io->vars.snd_una);
        io->vars.snd_una = io->seg.ack;
        io->res.act |= IDEMIP_TCP_IN_ACT_ACKED;
    }
    io->vars.snd_wnd = io->seg.wnd;
    io->vars.snd_wl1 = io->seg.seq;
    io->vars.snd_wl2 = io->seg.ack;
    if (io->seg.wnd > io->ctl.max_snd_wnd)
    {
        io->ctl.max_snd_wnd = io->seg.wnd;
    }
    // "If SND.UNA > ISS (our SYN has been ACKed), change the connection state to ESTABLISHED, form an
    // ACK segment <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> and send it."
    if (tcp_in_from(io->vars.snd_una, io->vars.iss) != 0u)
    {
        io->state = IDEMIP_TCP_STATE_ESTABLISHED;
        io->res.act |= IDEMIP_TCP_IN_ACT_ESTABLISHED;
        tcp_in_put_ack(io);
        return;
    }
    // "Otherwise, enter SYN-RECEIVED, form a SYN,ACK segment <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK> and
    // send it."
    io->state = IDEMIP_TCP_STATE_SYN_RECEIVED;
    io->reply.seq = io->vars.iss;
    io->reply.ack = io->vars.rcv_nxt;
    io->reply.flags = (uint16_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK);
    io->res.act |= IDEMIP_TCP_IN_ACT_ACK;
}

// RFC 9293 sec 3.10.7.4 second, in the three steps that section takes from RFC 5961 sec 3.2. RFC 1337
// sec 3's fix F1, "Ignore RST segments in TIME-WAIT state", holds TIME-WAIT open for its full 2 MSL.
// Reports true when processing stops here.
static idemip_bool tcp_in_check_rst(uint8_t *restrict work, TcpInIo *io)
{
    if ((io->seg.flags & IDEMIP_TCP_RST) == 0u)
    {
        return IDEMIP_FALSE;
    }
    // 1) "If the RST bit is set and the sequence number is outside the current receive window,
    // silently drop the segment."
    if (io->seg.seq != io->vars.rcv_nxt && !tcp_in_rst_in_window(io->seg.seq, io->vars.rcv_nxt, io->vars.rcv_wnd))
    {
        return IDEMIP_TRUE;
    }
    // 3) "If the RST bit is set and the sequence number does not exactly match the next expected
    // sequence value, yet is within the current receive window, TCP endpoints MUST send an
    // acknowledgment (challenge ACK) ... After sending the challenge ACK, TCP endpoints MUST drop the
    // unacceptable segment and stop processing the incoming packet further."
    if (io->seg.seq != io->vars.rcv_nxt)
    {
        tcp_in_put_challenge(work, io);
        return IDEMIP_TRUE;
    }
    // 2) "If the RST bit is set and the sequence number exactly matches the next expected sequence
    // number (RCV.NXT), then TCP endpoints MUST reset the connection in the manner prescribed below
    // according to the connection state."
    switch (io->state)
    {
    case IDEMIP_TCP_STATE_SYN_RECEIVED:
        // "If this connection was initiated with a passive OPEN (i.e., came from the LISTEN state),
        // then return this connection to LISTEN state and return ... If this connection was initiated
        // with an active OPEN ... signal the user 'connection refused'. In either case, the
        // retransmission queue should be flushed. And in the active OPEN case, enter the CLOSED state
        // and delete the TCB, and return."
        io->res.act |= IDEMIP_TCP_IN_ACT_FLUSH;
        if (io->listener != IDEMIP_TCP_PCB_NONE)
        {
            io->state = IDEMIP_TCP_STATE_LISTEN;
            io->res.act |= IDEMIP_TCP_IN_ACT_LISTEN;
        }
        else
        {
            io->state = IDEMIP_TCP_STATE_CLOSED;
            io->res.act |= IDEMIP_TCP_IN_ACT_REFUSED | IDEMIP_TCP_IN_ACT_DELETE;
        }
        return IDEMIP_TRUE;
    case IDEMIP_TCP_STATE_ESTABLISHED:
    case IDEMIP_TCP_STATE_FIN_WAIT_1:
    case IDEMIP_TCP_STATE_FIN_WAIT_2:
    case IDEMIP_TCP_STATE_CLOSE_WAIT:
        // "any outstanding RECEIVEs and SEND should receive 'reset' responses. All segment queues
        // should be flushed. Users should also receive an unsolicited general 'connection reset'
        // signal. Enter the CLOSED state, delete the TCB, and return."
        io->state = IDEMIP_TCP_STATE_CLOSED;
        io->res.act |= IDEMIP_TCP_IN_ACT_RESET | IDEMIP_TCP_IN_ACT_FLUSH | IDEMIP_TCP_IN_ACT_DELETE;
        return IDEMIP_TRUE;
    case IDEMIP_TCP_STATE_CLOSING:
    case IDEMIP_TCP_STATE_LAST_ACK:
        // "If the RST bit is set, then enter the CLOSED state, delete the TCB, and return."
        io->state = IDEMIP_TCP_STATE_CLOSED;
        io->res.act |= IDEMIP_TCP_IN_ACT_FLUSH | IDEMIP_TCP_IN_ACT_DELETE;
        return IDEMIP_TRUE;
    default:
        // TIME-WAIT. RFC 1337 sec 4: "fix (F1), ignoring RST segments in TIME-WAIT state, seems like
        // the best short-term solution", which sec 3 says "avoids all three hazards" while the 2 MSL
        // is enforced. RFC 9293 sec 3.10.7.4 second would delete the TCB here; RFC 1337 sec 1 is why
        // that is the assassination.
        return IDEMIP_TRUE;
    }
}

// RFC 9293 sec 3.10.7.4 fourth, which takes RFC 5961 sec 4.2's rule: "If the SYN bit is set,
// irrespective of the sequence number, TCP MUST send an ACK (also referred to as challenge ACK) to
// the remote peer ... After sending the acknowledgment, TCP MUST drop the unacceptable segment and
// stop processing further." Reports true when processing stops here.
static idemip_bool tcp_in_check_syn(uint8_t *restrict work, TcpInIo *io)
{
    if ((io->seg.flags & IDEMIP_TCP_SYN) == 0u)
    {
        return IDEMIP_FALSE;
    }
    // "SYN-RECEIVED STATE: If the connection was initiated with a passive OPEN, then return this
    // connection to the LISTEN state and return. Otherwise, handle per the directions for
    // synchronized states below."
    //
    // That bullet sits under sec 3.10.7.4 fourth, which sec 3.10.7.4 first reaches only for a segment
    // that passed Table 6: "After sending the acknowledgment, drop the unacceptable segment and
    // return." RFC 5961 sec 4.2's "irrespective of the sequence number" is written for the
    // synchronized states, and SYN-RECEIVED is not one, so an out-of-window SYN takes the challenge
    // below and leaves the connection where it is.
    if (io->state == IDEMIP_TCP_STATE_SYN_RECEIVED && io->listener != IDEMIP_TCP_PCB_NONE &&
        io->res.acceptable)
    {
        io->state = IDEMIP_TCP_STATE_LISTEN;
        io->res.act |= IDEMIP_TCP_IN_ACT_LISTEN;
        return IDEMIP_TRUE;
    }
    tcp_in_put_challenge(work, io);
    return IDEMIP_TRUE;
}

// RFC 9293 sec 3.10.7.4 fifth, the ACK field, with RFC 5961 sec 5.2's range check ahead of it.
// Reports true when processing stops here.
static idemip_bool tcp_in_check_ack(TcpInIo *io)
{
    // "if the ACK bit is off, drop the segment and return"
    if ((io->seg.flags & IDEMIP_TCP_ACK) == 0u)
    {
        return IDEMIP_TRUE;
    }
    // RFC 5961 sec 5.2: "The ACK value is considered acceptable only if it is in the range of
    // ((SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT). All incoming segments whose ACK value doesn't
    // satisfy the above condition MUST be discarded and an ACK sent back."
    if (!tcp_in_ack_in_range(io->seg.ack, io->vars.snd_una, io->vars.snd_nxt, io->ctl.max_snd_wnd))
    {
        tcp_in_put_ack(io);
        return IDEMIP_TRUE;
    }
    if (io->state == IDEMIP_TCP_STATE_SYN_RECEIVED)
    {
        // "If SND.UNA < SEG.ACK =< SND.NXT, then enter ESTABLISHED state and continue processing with
        // the variables below set to: SND.WND <- SEG.WND, SND.WL1 <- SEG.SEQ, SND.WL2 <- SEG.ACK"
        if (!tcp_in_ack_new(io->seg.ack, io->vars.snd_una, io->vars.snd_nxt))
        {
            // "If the segment acknowledgment is not acceptable, form a reset segment
            // <SEQ=SEG.ACK><CTL=RST> and send it."
            io->reply.seq = io->seg.ack;
            io->reply.ack = 0u;
            io->reply.flags = (uint16_t)IDEMIP_TCP_RST;
            io->res.act |= IDEMIP_TCP_IN_ACT_RST;
            return IDEMIP_TRUE;
        }
        io->state = IDEMIP_TCP_STATE_ESTABLISHED;
        io->vars.snd_wnd = io->seg.wnd;
        io->vars.snd_wl1 = io->seg.seq;
        io->vars.snd_wl2 = io->seg.ack;
        if (io->seg.wnd > io->ctl.max_snd_wnd)
        {
            io->ctl.max_snd_wnd = io->seg.wnd;
        }
        io->res.act |= IDEMIP_TCP_IN_ACT_ESTABLISHED | IDEMIP_TCP_IN_ACT_WND;
    }

    // "ESTABLISHED STATE: If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK. Any segments
    // on the retransmission queue that are thereby entirely acknowledged are removed ... If the ACK
    // is a duplicate (SEG.ACK =< SND.UNA), it can be ignored. If the ACK acks something not yet sent
    // (SEG.ACK > SND.NXT), then send an ACK, drop the segment, and return." The last of the three is
    // reached above: RFC 5961 sec 5.2's range ends at SND.NXT, so an ACK past it fails that check and
    // draws the same acknowledgment.
    if (tcp_in_ack_new(io->seg.ack, io->vars.snd_una, io->vars.snd_nxt))
    {
        io->res.acked = tcp_in_from(io->seg.ack, io->vars.snd_una);
        io->vars.snd_una = io->seg.ack;
        io->res.act |= IDEMIP_TCP_IN_ACT_ACKED;
    }
    else
    {
        io->res.act |= IDEMIP_TCP_IN_ACT_DUPACK;
    }

    // "If SND.UNA =< SEG.ACK =< SND.NXT, the send window should be updated. If (SND.WL1 < SEG.SEQ or
    // (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ,
    // and set SND.WL2 <- SEG.ACK." RFC 7323 sec 2.3 puts the two ends of a connection within 2^31 of
    // each other, so "less than" over the sequence space is a distance below that half.
    if (tcp_in_ack_within(io->seg.ack, io->vars.snd_una, io->vars.snd_nxt))
    {
        uint32_t at = tcp_in_from(io->seg.seq, io->vars.snd_wl1);
        idemip_bool newer = (at != 0u && at < 0x80000000u) ? IDEMIP_TRUE : IDEMIP_FALSE;
        idemip_bool same = (io->seg.seq == io->vars.snd_wl1 &&
                            tcp_in_from(io->seg.ack, io->vars.snd_wl2) < 0x80000000u)
                               ? IDEMIP_TRUE
                               : IDEMIP_FALSE;
        if (newer || same)
        {
            io->vars.snd_wnd = io->seg.wnd;
            io->vars.snd_wl1 = io->seg.seq;
            io->vars.snd_wl2 = io->seg.ack;
            if (io->seg.wnd > io->ctl.max_snd_wnd)
            {
                io->ctl.max_snd_wnd = io->seg.wnd;
            }
            io->res.act |= IDEMIP_TCP_IN_ACT_WND;
        }
    }

    // Our FIN occupies the last sequence number this side sent, so it is acknowledged exactly when
    // SND.UNA has reached SND.NXT.
    idemip_bool fin_acked = (io->vars.snd_una == io->vars.snd_nxt) ? IDEMIP_TRUE : IDEMIP_FALSE;
    switch (io->state)
    {
    case IDEMIP_TCP_STATE_FIN_WAIT_1:
        // "In addition to the processing for the ESTABLISHED state, if the FIN segment is now
        // acknowledged, then enter FIN-WAIT-2 and continue processing in that state."
        if (fin_acked)
        {
            io->state = IDEMIP_TCP_STATE_FIN_WAIT_2;
        }
        return IDEMIP_FALSE;
    case IDEMIP_TCP_STATE_CLOSING:
        // "if the ACK acknowledges our FIN, then enter the TIME-WAIT state; otherwise, ignore the
        // segment."
        if (fin_acked)
        {
            io->state = IDEMIP_TCP_STATE_TIME_WAIT;
            io->res.act |= IDEMIP_TCP_IN_ACT_2MSL;
        }
        return IDEMIP_TRUE;
    case IDEMIP_TCP_STATE_LAST_ACK:
        // "The only thing that can arrive in this state is an acknowledgment of our FIN. If our FIN
        // is now acknowledged, delete the TCB, enter the CLOSED state, and return."
        if (fin_acked)
        {
            io->state = IDEMIP_TCP_STATE_CLOSED;
            io->res.act |= IDEMIP_TCP_IN_ACT_DELETE;
        }
        return IDEMIP_TRUE;
    case IDEMIP_TCP_STATE_TIME_WAIT:
        // "The only thing that can arrive in this state is a retransmission of the remote FIN.
        // Acknowledge it, and restart the 2 MSL timeout."
        tcp_in_put_ack(io);
        io->res.act |= IDEMIP_TCP_IN_ACT_2MSL;
        return IDEMIP_TRUE;
    default:
        return IDEMIP_FALSE;
    }
}

// RFC 9293 sec 3.10.7.4 sixth, the URG bit. sec 3.1 makes the Urgent Pointer "a positive offset from
// the sequence number in this segment", so the sequence number it names is SEG.SEQ+SEG.UP and
// "RCV.UP <- max(RCV.UP,SEG.UP)" is a comparison in that space.
static void tcp_in_check_urg(TcpInIo *io)
{
    if ((io->seg.flags & IDEMIP_TCP_URG) == 0u)
    {
        return;
    }
    if (io->state != IDEMIP_TCP_STATE_ESTABLISHED && io->state != IDEMIP_TCP_STATE_FIN_WAIT_1 &&
        io->state != IDEMIP_TCP_STATE_FIN_WAIT_2)
    {
        return; // "This should not occur since a FIN has been received from the remote side."
    }
    uint32_t up = io->seg.seq + (uint32_t)io->seg.up;
    uint32_t cur = tcp_in_from(io->vars.rcv_up, io->vars.rcv_nxt);
    // An RCV.UP behind RCV.NXT names data already consumed, which sec 3.10.7.4 sixth says is no
    // longer "in advance of the data consumed", so this segment's pointer takes its place. RFC 7323
    // sec 2.3 puts the two ends within 2^31 of each other, so behind is a distance above that half.
    if (cur >= 0x80000000u || tcp_in_from(up, io->vars.rcv_nxt) > cur)
    {
        io->vars.rcv_up = up;
    }
    io->res.act |= IDEMIP_TCP_IN_ACT_URGENT;
}

// RFC 9293 sec 3.10.7.4 seventh, the segment text. "In the following it is assumed that the segment
// is the idealized segment that begins at RCV.NXT and does not exceed the window. One could tailor
// actual segments to fit this assumption by trimming off any portions that lie outside the window
// (including SYN and FIN) and only processing further if the segment then begins at RCV.NXT. Segments
// with higher beginning sequence numbers SHOULD be held for later processing (SHLD-31)."
static void tcp_in_check_text(TcpInIo *io)
{
    if (io->seg.data_len == 0u)
    {
        return;
    }
    if (io->state != IDEMIP_TCP_STATE_ESTABLISHED && io->state != IDEMIP_TCP_STATE_FIN_WAIT_1 &&
        io->state != IDEMIP_TCP_STATE_FIN_WAIT_2)
    {
        return; // "This should not occur since a FIN has been received from the remote side."
    }
    uint32_t off = tcp_in_from(io->vars.rcv_nxt, io->seg.seq);
    if (off >= (uint32_t)io->seg.data_len)
    {
        // Every octet is older than RCV.NXT, or the segment begins past it. A segment that begins
        // past RCV.NXT is held; one entirely behind it is an old duplicate and only draws an ACK.
        if (tcp_in_from(io->seg.seq, io->vars.rcv_nxt) != 0u &&
            tcp_in_from(io->seg.seq, io->vars.rcv_nxt) < io->vars.rcv_wnd)
        {
            io->res.text_seq = io->seg.seq;
            io->res.text_off = 0u;
            io->res.text_len = io->seg.data_len;
            io->res.act |= IDEMIP_TCP_IN_ACT_HOLD;
        }
        tcp_in_put_ack(io);
        return;
    }
    uint32_t avail = (uint32_t)io->seg.data_len - off;
    if (avail > io->vars.rcv_wnd)
    {
        avail = io->vars.rcv_wnd;
    }
    io->res.text_seq = io->vars.rcv_nxt;
    io->res.text_off = (uint16_t)off;
    io->res.text_len = (uint16_t)avail;
    // "Once the TCP endpoint takes responsibility for the data, it advances RCV.NXT over the data
    // accepted, and adjusts RCV.WND as appropriate to the current buffer availability. The total of
    // RCV.NXT and RCV.WND should not be reduced."
    io->vars.rcv_nxt += avail;
    io->vars.rcv_wnd -= avail;
    io->res.act |= IDEMIP_TCP_IN_ACT_TEXT;
    if ((io->seg.flags & IDEMIP_TCP_PSH) != 0u)
    {
        io->res.act |= IDEMIP_TCP_IN_ACT_PUSH;
    }
    // "Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>"
    tcp_in_put_ack(io);
}

// RFC 9293 sec 3.10.7.4 eighth, the FIN bit. "If the FIN bit is set, signal the user 'connection
// closing' ... advance RCV.NXT over the FIN, and send an acknowledgment for the FIN."
static void tcp_in_check_fin(TcpInIo *io)
{
    if ((io->seg.flags & IDEMIP_TCP_FIN) == 0u)
    {
        return;
    }
    // The FIN occupies the sequence number after the segment's last data octet, so it is processed
    // only once every octet before it has been taken.
    if (io->vars.rcv_nxt != io->seg.seq + (uint32_t)io->seg.data_len)
    {
        return;
    }
    io->vars.rcv_nxt++;
    io->res.act |= IDEMIP_TCP_IN_ACT_CLOSING;
    tcp_in_put_ack(io);
    switch (io->state)
    {
    case IDEMIP_TCP_STATE_SYN_RECEIVED:
    case IDEMIP_TCP_STATE_ESTABLISHED:
        io->state = IDEMIP_TCP_STATE_CLOSE_WAIT; // "Enter the CLOSE-WAIT state."
        return;
    case IDEMIP_TCP_STATE_FIN_WAIT_1:
        // "If our FIN has been ACKed (perhaps in this segment), then enter TIME-WAIT, start the
        // time-wait timer, turn off the other timers; otherwise, enter the CLOSING state."
        if (io->vars.snd_una == io->vars.snd_nxt)
        {
            io->state = IDEMIP_TCP_STATE_TIME_WAIT;
            io->res.act |= IDEMIP_TCP_IN_ACT_2MSL;
        }
        else
        {
            io->state = IDEMIP_TCP_STATE_CLOSING;
        }
        return;
    case IDEMIP_TCP_STATE_FIN_WAIT_2:
        // "Enter the TIME-WAIT state. Start the time-wait timer, turn off the other timers."
        io->state = IDEMIP_TCP_STATE_TIME_WAIT;
        io->res.act |= IDEMIP_TCP_IN_ACT_2MSL;
        return;
    case IDEMIP_TCP_STATE_TIME_WAIT:
        // "Remain in the TIME-WAIT state. Restart the 2 MSL time-wait timeout."
        io->res.act |= IDEMIP_TCP_IN_ACT_2MSL;
        return;
    default:
        return; // CLOSE-WAIT, CLOSING and LAST-ACK each "Remain in the" state they are in.
    }
}

// RFC 9293 sec 3.10.7.4 Other States, its eight checks in the order that section lists them. The
// third, the security and compartment of Appendix A.1, has nothing in a TCB here to compare and is
// not made; every other check is.
static void tcp_in_segment(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    TcpInIo *io = TCP_IN_IO(work);
    io->status = IDEMIP_ERR;
    tcp_in_result_clear(io);
    if (TCP_IN_CTX(work)->ready != TCP_IN_READY)
    {
        return;
    }
    if (io->state < IDEMIP_TCP_STATE_SYN_RECEIVED || io->state > IDEMIP_TCP_STATE_TIME_WAIT)
    {
        return; // sec 3.10.7.1, sec 3.10.7.2 and sec 3.10.7.3 hold the other three states
    }
    io->status = IDEMIP_OK;

    // First: the sec 3.4 Table 6 acceptability test. "If an incoming segment is not acceptable, an
    // acknowledgment should be sent in reply (unless the RST bit is set, if so drop the segment and
    // return) ... After sending the acknowledgment, drop the unacceptable segment and return."
    io->res.acceptable = tcp_in_seg_acceptable(io->seg.seq, io->seg.len, io->vars.rcv_nxt, io->vars.rcv_wnd);
    if (!io->res.acceptable)
    {
        if ((io->seg.flags & IDEMIP_TCP_RST) != 0u)
        {
            (void)tcp_in_check_rst(work, io);
            return;
        }
        // sec 3.10.7.4 fourth takes RFC 5961 sec 4.2's rule "irrespective of the sequence number", so
        // a SYN outside the window is the challenge ACK rather than the plain one.
        if ((io->seg.flags & IDEMIP_TCP_SYN) != 0u)
        {
            (void)tcp_in_check_syn(work, io);
            return;
        }
        tcp_in_put_ack(io);
        return;
    }

    // Second: the RST bit.
    if (tcp_in_check_rst(work, io))
    {
        return;
    }
    // Fourth: the SYN bit.
    if (tcp_in_check_syn(work, io))
    {
        return;
    }
    // Fifth: the ACK field.
    if (tcp_in_check_ack(io))
    {
        return;
    }
    // Sixth, seventh and eighth: the URG bit, the segment text, the FIN bit.
    tcp_in_check_urg(io);
    tcp_in_check_text(io);
    if ((io->res.act & IDEMIP_TCP_IN_ACT_HOLD) == 0u)
    {
        tcp_in_check_fin(io);
    }
}

const TcpInNs TcpIn = {.clear = tcp_in_clear,
                       .parse = tcp_in_parse,
                       .acceptable = tcp_in_acceptable,
                       .closed = tcp_in_closed,
                       .listen = tcp_in_listen,
                       .syn_sent = tcp_in_syn_sent,
                       .segment = tcp_in_segment};

IDEMIP_END_DECLS
