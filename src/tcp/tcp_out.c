// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp_out.c
 * @brief The send path, over the connection variables in the caller's borrow.
 *
 * The operand block and the context are regions of the one pointer each entry is handed, at
 * compile-time offsets, and no entry reads or writes a byte outside it and the two buffers the
 * operand block names. Two borrows therefore share nothing, and the same call on the same borrow does
 * the same thing.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/pseudo.h"
#include "src/tcp/tcp_out.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. A borrow that was never cleared carries no mark, so every
// entry refuses it.
typedef struct
{
    uint32_t ready;
} TcpOutCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_TCP_OUT_OFF_CTX, sizeof(TcpOutCtx), IDEMIP_TCP_OUT_BORROW, "tcp_out's context");

// The mark clear leaves.
#define TCP_OUT_READY 0x5443504Fu

// The caller's borrow, split: the operand block, then the context. tcp_out.h publishes the offsets;
// the assert below proves the span covers them before anything runs.
static_assert(IDEMIP_TCP_OUT_OFF_CTX + sizeof(TcpOutCtx) <= IDEMIP_TCP_OUT_BORROW,
              "IDEMIP_TCP_OUT_BORROW is short of the operand block and the context - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define TCP_OUT_CTX(w) ((TcpOutCtx *)(void *)((w) + IDEMIP_TCP_OUT_OFF_CTX))
#define TCP_OUT_IO(w) IDEMIP_TCP_OUT_IO(w)

// A retransmission timer that is not running. RFC 6298 (5.2) turns it off and (5.1) asks whether it
// is, so one deadline value has to mean off; an arm that lands exactly there takes the next
// millisecond instead.
#define TCP_OUT_RTX_OFF 0u

// --- the sequence space ----------------------------------------------------

// RFC 9293 sec 3.4: "all arithmetic dealing with sequence numbers must be performed modulo 2^32."
static uint32_t tcp_out_from(uint32_t seq, uint32_t edge)
{
    return seq - edge;
}

// RFC 6298 (2.4) "if it is less than 1 second, then the RTO SHOULD be rounded up to 1 second" and
// (2.5) "A maximum value MAY be placed on RTO provided it is at least 60 seconds."
static uint32_t tcp_out_rto_bound(uint32_t rto)
{
    if (rto < (uint32_t)IDEMIP_TCP_RTO_MIN_MS)
    {
        return (uint32_t)IDEMIP_TCP_RTO_MIN_MS;
    }
    if (rto > (uint32_t)IDEMIP_TCP_RTO_MAX_MS)
    {
        return (uint32_t)IDEMIP_TCP_RTO_MAX_MS;
    }
    return rto;
}

// RFC 6298 (5.1) and (5.6), a deadline RTO milliseconds out. TCP_OUT_RTX_OFF names the timer that is
// not running, so a deadline that lands on it takes the next millisecond.
static uint32_t tcp_out_deadline(uint32_t now, uint32_t rto)
{
    uint32_t at = now + rto;
    return (at == TCP_OUT_RTX_OFF) ? (at + 1u) : at;
}

// RFC 5681 sec 3.1's three-way table for IW: "If SMSS > 2190 bytes: IW = 2 * SMSS bytes and MUST NOT
// be more than 2 segments. If (SMSS > 1095 bytes) and (SMSS <= 2190 bytes): IW = 3 * SMSS bytes and
// MUST NOT be more than 3 segments. if SMSS <= 1095 bytes: IW = 4 * SMSS bytes and MUST NOT be more
// than 4 segments."
static uint32_t tcp_out_iw(uint32_t smss)
{
    if (smss > (uint32_t)IDEMIP_TCP_IW_SMSS_HI)
    {
        return smss << 1;
    }
    if (smss > (uint32_t)IDEMIP_TCP_IW_SMSS_LO)
    {
        return smss + (smss << 1);
    }
    return smss << 2;
}

// --- the options -----------------------------------------------------------

// Octets the requested options occupy, the NOPs that word-align them included. RFC 9293 sec 3.2 puts
// kind 2 in a SYN only ("MUST NOT be sent in other segments"), RFC 7323 sec 2.2 puts kind 3 in a
// <SYN>, and RFC 2018 sec 2 says kind 4 "MUST NOT be sent on non-SYN segments", so the three are
// dropped from a segment without SYN rather than refused.
static uint16_t tcp_out_opts_len(const TcpOutBuildArgs *a)
{
    idemip_bool syn = ((a->flags & IDEMIP_TCP_SYN) != 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
    uint16_t n = 0u;
    if (syn && (a->opts & IDEMIP_TCP_OUT_OPT_MSS) != 0u)
    {
        n = (uint16_t)(n + IDEMIP_TCP_OPT_MSS_LEN);
    }
    if (syn && (a->opts & IDEMIP_TCP_OUT_OPT_SACK_PERM) != 0u)
    {
        n = (uint16_t)(n + IDEMIP_TCP_OPT_SACK_PERM_LEN);
    }
    if (syn && (a->opts & IDEMIP_TCP_OUT_OPT_WS) != 0u)
    {
        n = (uint16_t)(n + IDEMIP_TCP_OPT_WS_LEN + 1u); // one NOP aligns the three-octet option
    }
    if ((a->opts & IDEMIP_TCP_OUT_OPT_TS) != 0u)
    {
        n = (uint16_t)(n + IDEMIP_TCP_OPT_TS_LEN + 2u); // two NOPs align the ten-octet option
    }
    if ((a->opts & IDEMIP_TCP_OUT_OPT_SACK) != 0u && a->sack_blocks != 0u)
    {
        n = (uint16_t)(n + IDEMIP_TCP_SACK_BYTES(a->sack_blocks) + 2u);
    }
    // RFC 9293 sec 3.1: "The TCP header (even one including options) is an integer multiple of 32
    // bits long", and MUST-69 makes the rest of the header padding of zeros.
    return (uint16_t)((n + 3u) & ~3u);
}

// The options, written where the fixed fields end. Every write goes through tcp.h's builders, so the
// kinds and lengths are the ones its RFC-verified constants name.
static uint16_t tcp_out_put_opts(uint8_t *o, const TcpOutBuildArgs *a, const TcpPcbCtl *ctl, uint16_t room)
{
    idemip_bool syn = ((a->flags & IDEMIP_TCP_SYN) != 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
    uint16_t n = 0u;
    if (syn && (a->opts & IDEMIP_TCP_OUT_OPT_MSS) != 0u)
    {
        n = (uint16_t)(n + idemip_tcp_opt_put_mss(o + n, a->mss));
    }
    if (syn && (a->opts & IDEMIP_TCP_OUT_OPT_SACK_PERM) != 0u)
    {
        n = (uint16_t)(n + idemip_tcp_opt_put_sack_perm(o + n));
    }
    if (syn && (a->opts & IDEMIP_TCP_OUT_OPT_WS) != 0u)
    {
        n = (uint16_t)(n + idemip_tcp_opt_put_nop(o + n));
        n = (uint16_t)(n + idemip_tcp_opt_put_ws(o + n, a->ws));
    }
    if ((a->opts & IDEMIP_TCP_OUT_OPT_TS) != 0u)
    {
        // RFC 7323 sec 3.2: "If the ACK bit is not set in the outgoing TCP header, the sender of that
        // segment SHOULD set the TSecr field to zero."
        uint32_t tsecr = ((a->flags & IDEMIP_TCP_ACK) != 0u) ? a->tsecr : 0u;
        n = (uint16_t)(n + idemip_tcp_opt_put_nop(o + n));
        n = (uint16_t)(n + idemip_tcp_opt_put_nop(o + n));
        n = (uint16_t)(n + idemip_tcp_opt_put_ts(o + n, a->tsval, tsecr));
    }
    if ((a->opts & IDEMIP_TCP_OUT_OPT_SACK) != 0u && a->sack_blocks != 0u)
    {
        n = (uint16_t)(n + idemip_tcp_opt_put_nop(o + n));
        n = (uint16_t)(n + idemip_tcp_opt_put_nop(o + n));
        o[n + IDEMIP_TCP_OPT_OFF_KIND] = (uint8_t)IDEMIP_TCP_OPT_SACK;
        o[n + IDEMIP_TCP_OPT_OFF_LEN] = (uint8_t)IDEMIP_TCP_SACK_BYTES(a->sack_blocks);
        uint16_t at = (uint16_t)(n + IDEMIP_TCP_OPT_OFF_DATA);
        for (uint8_t i = 0u; i < a->sack_blocks; i++)
        {
            idemip_wr32(o + at, ctl->sack_left[i]);
            idemip_wr32(o + at + 4u, ctl->sack_right[i]);
            at = (uint16_t)(at + IDEMIP_TCP_SACK_BLOCK_LEN);
        }
        n = at;
    }
    // RFC 9293 sec 3.1 MUST-69: "The content of the header beyond the End of Option List Option MUST
    // be header padding of zeros."
    if (n < room)
    {
        memset(o + n, 0, (size_t)room - n);
    }
    return room;
}

// --- the entries -----------------------------------------------------------

// The context is the whole borrow past the operand block, so one store covers it. The operand block
// is the caller's and is left as it was found, except for the members a call reports through.
void idemip_tcp_out_clear(uint8_t *work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    memset(work + IDEMIP_TCP_OUT_OFF_CTX, 0, (size_t)IDEMIP_TCP_OUT_BORROW - IDEMIP_TCP_OUT_OFF_CTX);
    TCP_OUT_CTX(work)->ready = TCP_OUT_READY;
    memset(&io->reply, 0, sizeof io->reply);
    memset(&io->res, 0, sizeof io->res);
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.1's header, its options and the data, written into the caller's buffer, then the
// checksum over the pseudo-header of sec 3.1 over IPv4 or of RFC 8200 sec 8.1 over IPv6. The Checksum
// field goes out zeroed because sec 3.1 says "While computing the checksum, the checksum field itself
// is replaced with zeros."
void idemip_tcp_out_build(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    io->res.built = 0u;
    io->res.hdr_len = 0u;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY)
    {
        return;
    }
    TcpOutBuildArgs *a = &io->build_args;
    if (a->buf == NULL || a->local_ip == NULL || a->remote_ip == NULL)
    {
        return;
    }
    // RFC 9293 sec 3.3.1 Table 4 SEG.LEN counts data octets, and a segment with octets must name them.
    if ((a->len != 0u) != (a->data != NULL))
    {
        return;
    }
    if (a->sack_blocks > (uint8_t)IDEMIP_TCP_SACK_BLOCKS_MAX)
    {
        return;
    }
    uint16_t opts = tcp_out_opts_len(a);
    if (opts > (uint16_t)IDEMIP_TCP_OPTS_MAX)
    {
        return;
    }
    uint16_t hdr = (uint16_t)(IDEMIP_TCP_HDR_LEN + opts);
    uint32_t total = (uint32_t)hdr + (uint32_t)a->len;
    if (total > (uint32_t)a->cap)
    {
        return;
    }

    uint8_t *h = a->buf;
    idemip_wr16(h + IDEMIP_TCP_OFF_SRC_PORT, a->local_port);
    idemip_wr16(h + IDEMIP_TCP_OFF_DST_PORT, a->remote_port);
    idemip_wr32(h + IDEMIP_TCP_OFF_SEQ, a->seq);
    idemip_wr32(h + IDEMIP_TCP_OFF_ACK, ((a->flags & IDEMIP_TCP_ACK) != 0u) ? a->ack : 0u);
    // RFC 9293 sec 3.1: Data Offset is "The number of 32-bit words in the TCP header", and Reserved
    // "Must be zero in generated segments".
    uint16_t doff = (uint16_t)((uint16_t)IDEMIP_TCP_DOFF_FROM_BYTES(hdr) << IDEMIP_TCP_DOFF_SHIFT);
    idemip_wr16(h + IDEMIP_TCP_OFF_OFFS_FLAGS, (uint16_t)(doff | (uint16_t)a->flags));
    // RFC 7323 sec 2.3: "The window field (SEG.WND) of every outgoing segment, with the exception of
    // <SYN> segments, MUST be right-shifted by Rcv.Wind.Shift bits."
    uint32_t wnd = a->wnd;
    if ((a->flags & IDEMIP_TCP_SYN) == 0u)
    {
        uint8_t shift = a->rcv_scale;
        if (shift > (uint8_t)IDEMIP_TCP_WS_MAX)
        {
            shift = (uint8_t)IDEMIP_TCP_WS_MAX;
        }
        wnd >>= shift;
    }
    if (wnd > 0xFFFFu)
    {
        wnd = 0xFFFFu;
    }
    idemip_wr16(h + IDEMIP_TCP_OFF_WINDOW, (uint16_t)wnd);
    idemip_wr16(h + IDEMIP_TCP_OFF_CKSUM, 0u);
    idemip_wr16(h + IDEMIP_TCP_OFF_URGENT, ((a->flags & IDEMIP_TCP_URG) != 0u) ? a->up : 0u);
    if (opts != 0u)
    {
        (void)tcp_out_put_opts(h + IDEMIP_TCP_OFF_OPTIONS, a, &io->ctl, opts);
    }
    if (a->len != 0u)
    {
        memcpy(h + hdr, a->data, (size_t)a->len);
    }

    uint32_t sum = 0u;
    if (!idemip_pseudo_accum(&sum, a->ip_version, (uint8_t)IDEMIP_TCP_PROTO, a->local_ip, a->remote_ip, total))
    {
        return; // a version that names no pseudo-header
    }
    idemip_wr16(h + IDEMIP_TCP_OFF_CKSUM, idemip_cksum_final(idemip_cksum_accum(sum, h, (size_t)total)));
    io->res.hdr_len = hdr;
    io->res.built = (uint16_t)total;
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.8.6.2.1's four rules, with the sec 3.7.4 Nagle condition on rules (2) and (3).
//
// "The 'usable window' is: U = SND.UNA + SND.WND - SND.NXT, i.e., the offered window less the amount
// of data sent but not acknowledged." sec 3.7.4: "In all cases, sending data is also subject to the
// limitation imposed by the slow start algorithm", and RFC 5681 sec 3.1: "The minimum of cwnd and
// rwnd governs data transmission", so U is held down to what cwnd leaves outstanding.
void idemip_tcp_out_send(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    io->res.usable = 0u;
    io->res.send_len = 0u;
    io->res.send_now = IDEMIP_FALSE;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY || io->send_args.eff_snd_mss == 0u)
    {
        return;
    }
    io->status = IDEMIP_OK;

    // RFC 5681 sec 4.1: "a TCP SHOULD set cwnd to no more than RW before beginning transmission if
    // the TCP has not sent data in an interval exceeding the retransmission timeout", RW being
    // "min(IW,cwnd)". A connection that has never sent carries a zero stamp and is not idle.
    if (io->ctl.last_send_ms != 0u && io->ctl.rto != 0u &&
        (io->send_args.now_ms - io->ctl.last_send_ms) > io->ctl.rto)
    {
        uint32_t rw = tcp_out_iw(io->send_args.eff_snd_mss);
        if (io->ctl.cwnd < rw)
        {
            rw = io->ctl.cwnd;
        }
        io->ctl.cwnd = rw;
    }

    uint32_t flight = tcp_out_from(io->vars.snd_nxt, io->vars.snd_una);
    uint32_t edge = tcp_out_from(io->vars.snd_una + io->vars.snd_wnd, io->vars.snd_nxt);
    uint32_t u = (edge < 0x80000000u) ? edge : 0u; // SND.NXT past the offered window leaves none
    if (io->ctl.cwnd > flight)
    {
        uint32_t room = io->ctl.cwnd - flight;
        if (room < u)
        {
            u = room;
        }
    }
    else
    {
        u = 0u;
    }
    io->res.usable = u;

    uint32_t d = io->send_args.queued;
    uint32_t m = (d < u) ? d : u; // min(D,U)
    // The bracketed condition of rules (2) and (3), which sec 3.8.6.2.1 says "is imposed by the Nagle
    // algorithm". sec 3.7.4 (MUST-17) requires a way to turn that algorithm off.
    idemip_bool nagle_ok = (io->send_args.nodelay || flight == 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;

    // (1) "if a maximum-sized segment can be sent, i.e., if: min(D,U) >= Eff.snd.MSS"
    if (m >= io->send_args.eff_snd_mss)
    {
        io->res.send_now = IDEMIP_TRUE;
    }
    // (2) "or if the data is pushed and all queued data can be sent now, i.e., if:
    // [SND.NXT = SND.UNA and] PUSHed and D <= U"
    else if (nagle_ok && io->send_args.push && d != 0u && d <= u)
    {
        io->res.send_now = IDEMIP_TRUE;
    }
    // (3) "or if at least a fraction Fs of the maximum window can be sent, i.e., if:
    // [SND.NXT = SND.UNA and] min(D,U) >= Fs * Max(SND.WND)", Fs being "a fraction whose recommended
    // value is 1/2".
    else if (nagle_ok && m != 0u && m >= (io->ctl.max_snd_wnd >> IDEMIP_TCP_SWS_FS_SHIFT))
    {
        io->res.send_now = IDEMIP_TRUE;
    }
    // (4) "or if the override timeout occurs."
    else if (io->send_args.force && m != 0u)
    {
        io->res.send_now = IDEMIP_TRUE;
    }

    if (io->res.send_now)
    {
        io->res.send_len = (m > io->send_args.eff_snd_mss) ? io->send_args.eff_snd_mss : m;
        if (io->res.send_len == 0u)
        {
            io->res.send_now = IDEMIP_FALSE;
        }
        else
        {
            // The stamp sec 4.1's idle interval is measured from. Zero names the connection that has
            // never sent, so a now_ms of zero takes the next millisecond.
            io->ctl.last_send_ms = (io->send_args.now_ms == 0u) ? 1u : io->send_args.now_ms;
        }
    }
}

// RFC 9293 sec 3.10.7.4 first: "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>". The same three fields are RFC
// 5961 sec 3.2's and sec 4.2's challenge ACK, which tcp_in asks for.
void idemip_tcp_out_ack(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    memset(&io->reply, 0, sizeof io->reply);
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY)
    {
        return;
    }
    io->reply.seq = io->vars.snd_nxt;
    io->reply.ack = io->vars.rcv_nxt;
    io->reply.flags = (uint16_t)IDEMIP_TCP_ACK;
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.5.2: "If the incoming segment has the ACK bit set, the reset takes its sequence
// number from the ACK field of the segment; otherwise, the reset has sequence number zero and the ACK
// field is set to the sum of the sequence number and segment length of the incoming segment."
void idemip_tcp_out_rst(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    memset(&io->reply, 0, sizeof io->reply);
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY)
    {
        return;
    }
    if ((io->seg_args.flags & IDEMIP_TCP_ACK) != 0u)
    {
        io->reply.seq = io->seg_args.ack;
        io->reply.flags = (uint16_t)IDEMIP_TCP_RST;
    }
    else
    {
        io->reply.seq = 0u;
        io->reply.ack = io->seg_args.seq + io->seg_args.len;
        io->reply.flags = (uint16_t)(IDEMIP_TCP_RST | IDEMIP_TCP_ACK);
    }
    io->status = IDEMIP_OK;
}

// RFC 6298 sec 2. The first measurement takes (2.2), every later one (2.3), and both end with
// "RTO <- SRTT + max (G, K*RTTVAR)". alpha is 1/8, beta is 1/4 and K is 4, so each is a shift.
// A connection that has taken no measurement carries SRTT of zero, which (2.1) leaves at RTO of one
// second.
void idemip_tcp_out_rtt(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY || io->timer_args.sample_ms == 0u)
    {
        return;
    }
    // sec 3: "TCP MUST use Karn's algorithm [KP87] for taking RTT samples. That is, RTT samples MUST
    // NOT be made using segments that were retransmitted." A nonzero backoff is the retransmission
    // that made this ACK ambiguous; rtx_stop and rtx_restart clear it, so the next sample is taken.
    if (io->ctl.backoff != 0u)
    {
        io->status = IDEMIP_OK;
        return;
    }
    uint32_t r = io->timer_args.sample_ms;
    if (io->ctl.srtt == 0u)
    {
        // (2.2) "SRTT <- R, RTTVAR <- R/2"
        io->ctl.srtt = r;
        io->ctl.rttvar = r >> 1;
    }
    else
    {
        // (2.3) "RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|" then
        // "SRTT <- (1 - alpha) * SRTT + alpha * R'", in that order.
        uint32_t diff = (io->ctl.srtt > r) ? (io->ctl.srtt - r) : (r - io->ctl.srtt);
        io->ctl.rttvar = io->ctl.rttvar - (io->ctl.rttvar >> IDEMIP_TCP_RTO_BETA_SHIFT) +
                         (diff >> IDEMIP_TCP_RTO_BETA_SHIFT);
        io->ctl.srtt = io->ctl.srtt - (io->ctl.srtt >> IDEMIP_TCP_RTO_ALPHA_SHIFT) +
                       (r >> IDEMIP_TCP_RTO_ALPHA_SHIFT);
    }
    uint32_t k = io->ctl.rttvar << IDEMIP_TCP_RTO_K_SHIFT;
    if (k < (uint32_t)IDEMIP_TCP_RTO_G_MS)
    {
        k = (uint32_t)IDEMIP_TCP_RTO_G_MS; // sec 4: "the variance term MUST be rounded to G seconds"
    }
    io->ctl.rto = tcp_out_rto_bound(io->ctl.srtt + k);
    io->status = IDEMIP_OK;
}

// RFC 6298 (5.1): "Every time a packet containing data is sent (including a retransmission), if the
// timer is not running, start it running so that it will expire after RTO seconds."
void idemip_tcp_out_rtx_arm(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY)
    {
        return;
    }
    if (io->ctl.rto == 0u)
    {
        io->ctl.rto = (uint32_t)IDEMIP_TCP_RTO_INIT_MS; // (2.1) until a measurement has been made
    }
    // (5.7) "If the timer expires awaiting the ACK of a SYN segment and the TCP implementation is
    // using an RTO less than 3 seconds, the RTO MUST be re-initialized to 3 seconds when data
    // transmission begins (i.e., after the three-way handshake completes)." rtx_expire marks the SYN
    // timeout; this is the first arm past the handshake, so the floor lands here and the mark clears.
    if ((io->ctl.flags & IDEMIP_TCP_CTL_SYN_RTX) != 0u && io->state != IDEMIP_TCP_STATE_SYN_SENT &&
        io->state != IDEMIP_TCP_STATE_SYN_RECEIVED)
    {
        if (io->ctl.rto < (uint32_t)IDEMIP_TCP_RTO_SYN_FLOOR_MS)
        {
            io->ctl.rto = (uint32_t)IDEMIP_TCP_RTO_SYN_FLOOR_MS;
        }
        io->ctl.flags &= (uint16_t)~IDEMIP_TCP_CTL_SYN_RTX;
    }
    if (io->ctl.rtx_deadline == TCP_OUT_RTX_OFF)
    {
        io->ctl.rtx_deadline = tcp_out_deadline(io->timer_args.now_ms, io->ctl.rto);
    }
    io->status = IDEMIP_OK;
}

// RFC 6298 (5.2): "When all outstanding data has been acknowledged, turn off the retransmission
// timer."
void idemip_tcp_out_rtx_stop(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY)
    {
        return;
    }
    io->ctl.rtx_deadline = TCP_OUT_RTX_OFF;
    io->ctl.nrtx = 0u;
    io->ctl.backoff = 0u;
    io->status = IDEMIP_OK;
}

// RFC 6298 (5.3): "When an ACK is received that acknowledges new data, restart the retransmission
// timer so that it will expire after RTO seconds (for the current value of RTO)." The segment at the
// front of the queue is a different one now, so the retransmissions counted against it start over.
void idemip_tcp_out_rtx_restart(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY)
    {
        return;
    }
    if (io->ctl.rto == 0u)
    {
        io->ctl.rto = (uint32_t)IDEMIP_TCP_RTO_INIT_MS;
    }
    io->ctl.rtx_deadline = tcp_out_deadline(io->timer_args.now_ms, io->ctl.rto);
    io->ctl.nrtx = 0u;
    io->ctl.backoff = 0u; // sec 3, the transmission that ends the ambiguity Karn's algorithm names
    io->status = IDEMIP_OK;
}

// RFC 6298 (5.5) "The host MUST set RTO <- RTO * 2 ('back off the timer'). The maximum value
// discussed in (2.5) above may be used to provide an upper bound to this doubling operation." and
// (5.6) "Start the retransmission timer, such that it expires after RTO seconds (for the value of RTO
// after the doubling operation outlined in 5.5)."
//
// RFC 5681 sec 3.1 answers the same timeout: "ssthresh = max (FlightSize / 2, 2*SMSS)" unless "the
// given segment has already been retransmitted by way of the retransmission timer at least once", in
// which case "the value of ssthresh is held constant"; and "upon a timeout ... cwnd MUST be set to no
// more than the loss window, LW, which equals 1 full-sized segment".
void idemip_tcp_out_rtx_expire(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    io->res.r2 = IDEMIP_FALSE;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY || io->timer_args.smss == 0u)
    {
        return;
    }
    if (!io->timer_args.resent)
    {
        uint32_t half = io->timer_args.flight >> 1;
        uint32_t floor2 = io->timer_args.smss << 1;
        io->ctl.ssthresh = (half > floor2) ? half : floor2;
    }
    io->ctl.cwnd = io->timer_args.smss;
    io->ctl.bytes_acked = 0u;
    io->ctl.dupacks = 0u;
    if (io->ctl.rto == 0u)
    {
        io->ctl.rto = (uint32_t)IDEMIP_TCP_RTO_INIT_MS;
    }
    io->ctl.rto = tcp_out_rto_bound(io->ctl.rto << 1);
    io->ctl.rtx_deadline = tcp_out_deadline(io->timer_args.now_ms, io->ctl.rto);
    // (5.7)'s precondition, "the timer expires awaiting the ACK of a SYN segment", which rtx_arm
    // reads once the handshake has completed.
    if (io->state == IDEMIP_TCP_STATE_SYN_SENT || io->state == IDEMIP_TCP_STATE_SYN_RECEIVED)
    {
        io->ctl.flags |= (uint16_t)IDEMIP_TCP_CTL_SYN_RTX;
    }
    if (io->ctl.nrtx < 0xFFu)
    {
        io->ctl.nrtx++;
    }
    if (io->ctl.backoff < 0xFFu)
    {
        io->ctl.backoff++;
    }
    // RFC 9293 sec 3.8.3 (c): "When the number of transmissions of the same segment reaches a
    // threshold R2 greater than R1, close the connection." Clause (a) lets R2 be "a count of
    // retransmissions", which nrtx is, and clause (d)'s "infinity" is a threshold of zero. sec 3.8.3
    // separates the two: "the values of R1 and R2 may be different for SYN and data segments".
    uint8_t r2 = (io->state == IDEMIP_TCP_STATE_SYN_SENT || io->state == IDEMIP_TCP_STATE_SYN_RECEIVED)
                     ? io->ctl.r2_syn
                     : io->ctl.r2;
    if (r2 != 0u && io->ctl.nrtx >= r2)
    {
        io->res.r2 = IDEMIP_TRUE;
    }
    io->status = IDEMIP_OK;
}

// RFC 5681 sec 3.1, the congestion state a transfer starts in. "IW, the initial value of cwnd, MUST
// be set using the following guidelines as an upper bound", which tcp_out_iw applies, and "The
// initial value of ssthresh SHOULD be set arbitrarily high (e.g., to the size of the largest possible
// advertised window)", which puts the connection in slow start until the first loss.
void idemip_tcp_out_cc_init(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY || io->timer_args.smss == 0u)
    {
        return;
    }
    io->ctl.cwnd = tcp_out_iw(io->timer_args.smss);
    io->ctl.ssthresh = (uint32_t)IDEMIP_TCP_SSTHRESH_INIT;
    io->ctl.bytes_acked = 0u;
    io->ctl.dupacks = 0u;
    io->ctl.last_send_ms = 0u;
    io->status = IDEMIP_OK;
}

// RFC 5681 sec 3.1. "The slow start algorithm is used when cwnd < ssthresh, while the congestion
// avoidance algorithm is used when cwnd > ssthresh. When cwnd and ssthresh are equal, the sender may
// use either slow start or congestion avoidance."
//
// Slow start takes equation (2), "cwnd += min (N, SMSS)", which sec 3.1 says "is part of Appropriate
// Byte Counting [RFC3465] and provides robustness against misbehaving receivers that may attempt to
// induce a sender to artificially inflate cwnd using a mechanism known as 'ACK Division'".
//
// Congestion avoidance takes RFC 3465 sec 2.1: "store the number of bytes that have been ACKed in a
// 'bytes_acked' variable in the TCP control block. When bytes_acked becomes greater than or equal to
// the value of the congestion window, bytes_acked is reduced by the value of cwnd. Next, cwnd is
// incremented by a full-sized segment (SMSS)."
void idemip_tcp_out_cc_ack(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY || io->timer_args.smss == 0u)
    {
        return;
    }
    io->status = IDEMIP_OK;
    // RFC 5681 sec 3.1: "As specified in [RFC3390], the SYN/ACK and the acknowledgment of the SYN/ACK
    // MUST NOT increase the size of the congestion window."
    if (io->state == IDEMIP_TCP_STATE_SYN_SENT || io->state == IDEMIP_TCP_STATE_SYN_RECEIVED)
    {
        return;
    }
    uint32_t n = io->timer_args.acked;
    if (n == 0u)
    {
        return;
    }
    if (io->ctl.cwnd < io->ctl.ssthresh)
    {
        uint32_t step = (n < io->timer_args.smss) ? n : io->timer_args.smss;
        io->ctl.cwnd += step;
        return;
    }
    io->ctl.bytes_acked += n;
    if (io->ctl.bytes_acked >= io->ctl.cwnd)
    {
        io->ctl.bytes_acked -= io->ctl.cwnd;
        io->ctl.cwnd += io->timer_args.smss;
    }
}

// RFC 5681 sec 3.2 steps 2, 3 and 4. "When the third duplicate ACK is received, a TCP MUST set
// ssthresh to no more than the value given in equation (4)", which is "ssthresh = max (FlightSize /
// 2, 2*SMSS)". "The lost segment starting at SND.UNA MUST be retransmitted and cwnd set to ssthresh
// plus 3*SMSS." "For each additional duplicate ACK received (after the third), cwnd MUST be
// incremented by SMSS."
void idemip_tcp_out_cc_dupack(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY || io->timer_args.smss == 0u)
    {
        return;
    }
    io->status = IDEMIP_OK;
    if (io->ctl.dupacks < 0xFFu)
    {
        io->ctl.dupacks++;
    }
    if (io->ctl.dupacks < (uint8_t)IDEMIP_TCP_DUPACK_THRESH)
    {
        return;
    }
    if (io->ctl.dupacks == (uint8_t)IDEMIP_TCP_DUPACK_THRESH)
    {
        uint32_t half = io->timer_args.flight >> 1;
        uint32_t floor2 = io->timer_args.smss << 1;
        io->ctl.ssthresh = (half > floor2) ? half : floor2;
        io->ctl.cwnd = io->ctl.ssthresh + (io->timer_args.smss << 1) + io->timer_args.smss;
        return;
    }
    io->ctl.cwnd += io->timer_args.smss;
}

// RFC 5681 sec 3.2 step 6: "When the next ACK arrives that acknowledges previously unacknowledged
// data, a TCP MUST set cwnd to ssthresh (the value set in step 2). This is termed 'deflating' the
// window."
void idemip_tcp_out_cc_recover(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    TcpOutIo *io = TCP_OUT_IO(work);
    io->status = IDEMIP_ERR;
    if (TCP_OUT_CTX(work)->ready != TCP_OUT_READY)
    {
        return;
    }
    if (io->ctl.dupacks >= (uint8_t)IDEMIP_TCP_DUPACK_THRESH)
    {
        io->ctl.cwnd = io->ctl.ssthresh;
    }
    io->ctl.dupacks = 0u;
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
