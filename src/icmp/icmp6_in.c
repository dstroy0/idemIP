// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmp6_in.c
 * @brief RFC 4443 messages read and built, under the sec 2.4 processing rules.
 *
 * The operand block and the context are regions of the one pointer each entry is handed, at
 * compile-time offsets, and no entry reads or writes a byte outside it and the two buffers the
 * operand block names. Two borrows therefore share nothing, and the same call on the same borrow
 * does the same thing.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/icmp/icmp6_in.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. A borrow that was never cleared carries no mark, so every
// entry refuses it. The two counters behind it are RFC 4443 sec 2.4 (f)'s token bucket: what is left
// of the burst, and the millisecond the next token lands at.
typedef struct
{
    uint32_t ready;
    uint32_t refill_ms;
    uint8_t tokens;
} Icmp6InCtx;

// The mark clear leaves.
#define ICMP6_IN_READY 0x49434D36u

// The caller's borrow, split: the operand block, then the context. icmp6_in.h publishes the offsets;
// the assert below proves the span covers them before anything runs.
static_assert(IDEMIP_ICMP6_IN_OFF_CTX + sizeof(Icmp6InCtx) <= IDEMIP_ICMP6_IN_BORROW,
              "IDEMIP_ICMP6_IN_BORROW is short of the operand block and the context - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define ICMP6_IN_CTX(w) ((Icmp6InCtx *)(void *)((w) + IDEMIP_ICMP6_IN_OFF_CTX))
#define ICMP6_IN_IO(w) IDEMIP_ICMP6_IN_IO(w)

// --- the address forms RFC 4291 names --------------------------------------

// RFC 4291 sec 2.7: "binary 11111111 at the start of the address identifies the address as being a
// multicast address."
#define ICMP6_IN_MULTICAST_TAG 0xFFu

static idemip_bool icmp6_in_is_multicast(const uint8_t *addr)
{
    return (addr[0] == ICMP6_IN_MULTICAST_TAG) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 4291 sec 2.5.2: "The address 0:0:0:0:0:0:0:0 is called the unspecified address."
static idemip_bool icmp6_in_is_unspecified(const uint8_t *addr)
{
    for (size_t i = 0; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        if (addr[i] != 0u)
        {
            return IDEMIP_FALSE;
        }
    }
    return IDEMIP_TRUE;
}

// --- the checksum ----------------------------------------------------------

// RFC 4443 sec 2.3 sums the message and the RFC 8200 sec 8.1 pseudo-header, and RFC 1071 sec 1 makes
// a span carrying its own checksum sum to all ones, so the verify is that sum against zero.
static idemip_bool icmp6_in_cksum_ok(const uint8_t *p, const uint8_t *m, size_t len)
{
    uint32_t sum = idemip_ip6_pseudo_accum(0u, idemip_ip6_src(p), idemip_ip6_dst(p), (uint32_t)len,
                                           IDEMIP_IP6_NH_ICMPV6);
    return (idemip_cksum_final(idemip_cksum_accum(sum, m, len)) == 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- RFC 4443 sec 2.4 (f), the token bucket --------------------------------

// "A recommended method for implementing the rate-limiting function is a token bucket, limiting the
// average rate of transmission to N ... but allowing up to B error messages to be transmitted in a
// burst, as long as the long-term average is not exceeded." One token lands every
// IDEMIP_ICMP6_ERR_TOKEN_MS, the count stops at IDEMIP_ICMP6_ERR_BUCKET, and a gap of a whole bucket
// or more fills it in one step so the loop runs at most IDEMIP_ICMP6_ERR_BUCKET times.
#define ICMP6_IN_BUCKET_MS ((uint32_t)IDEMIP_ICMP6_ERR_BUCKET * (uint32_t)IDEMIP_ICMP6_ERR_TOKEN_MS)

static void icmp6_in_refill(Icmp6InCtx *ctx, uint32_t now_ms)
{
    if (ctx->tokens >= (uint8_t)IDEMIP_ICMP6_ERR_BUCKET)
    {
        ctx->tokens = (uint8_t)IDEMIP_ICMP6_ERR_BUCKET;
        ctx->refill_ms = now_ms;
        return;
    }
    uint32_t elapsed = now_ms - ctx->refill_ms;
    if (elapsed >= ICMP6_IN_BUCKET_MS)
    {
        ctx->tokens = (uint8_t)IDEMIP_ICMP6_ERR_BUCKET;
        ctx->refill_ms = now_ms;
        return;
    }
    while (elapsed >= (uint32_t)IDEMIP_ICMP6_ERR_TOKEN_MS && ctx->tokens < (uint8_t)IDEMIP_ICMP6_ERR_BUCKET)
    {
        ctx->tokens = (uint8_t)(ctx->tokens + 1u);
        ctx->refill_ms += (uint32_t)IDEMIP_ICMP6_ERR_TOKEN_MS;
        elapsed -= (uint32_t)IDEMIP_ICMP6_ERR_TOKEN_MS;
    }
}

// --- RFC 4443 sec 2.4 (e), the rules an error message is refused by --------

// The type at the head of the invoking packet's own ICMPv6 message, which (e.1) and (e.2) test. Only
// the first fragment carries that head (RFC 8200 sec 4.5), so a later one reports none.
static idemip_bool icmp6_in_invoking_type(const uint8_t *p, size_t len, uint8_t *type)
{
    const IdemIpIp6Chain c = idemip_ip6_walk(p, len);
    if (!c.ok || c.next_hdr != IDEMIP_IP6_NH_ICMPV6)
    {
        return IDEMIP_FALSE;
    }
    if (c.fragmented && idemip_ip6_frag_offset_bytes(p + c.frag_hdr) != 0u)
    {
        return IDEMIP_FALSE;
    }
    if (c.offset + IDEMIP_ICMP6_HDR_LEN > len)
    {
        return IDEMIP_FALSE;
    }
    *type = idemip_icmp6_type(p + c.offset);
    return IDEMIP_TRUE;
}

// "(There are two exceptions to this rule: (1) the Packet Too Big Message (Section 3.2) to allow Path
// MTU discovery to work for IPv6 multicast, and (2) the Parameter Problem Message, Code 2 (Section
// 3.4) reporting an unrecognized IPv6 option (see Section 4.2 of [IPv6]) that has the Option Type
// highest-order two bits set to 10)." The sec 3.4 Pointer "Identifies the octet offset within the
// invoking packet where the error was detected", which for Code 2 is that Option Type octet. The
// exceptions carry from (e.3) to (e.4) and (e.5).
static idemip_bool icmp6_in_mcast_exception(const Icmp6InErrArgs *a, size_t avail)
{
    if (a->type == (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG)
    {
        return IDEMIP_TRUE;
    }
    if (a->type == (uint8_t)IDEMIP_ICMP6_PARAMETER_PROBLEM && a->code == IDEMIP_ICMP6_PP_UNREC_OPTION &&
        (size_t)a->word < avail &&
        (a->invoking[a->word] & IDEMIP_IP6_OPT_ACT_MASK) == IDEMIP_IP6_OPT_ACT_DISCARD_ICMP)
    {
        return IDEMIP_TRUE;
    }
    return IDEMIP_FALSE;
}

// The six rules of sec 2.4 (e), in the order it lists them. "NOTE: THE RESTRICTIONS UNDER (e) AND (f)
// ABOVE TAKE PRECEDENCE OVER ANY REQUIREMENT ELSEWHERE IN THIS DOCUMENT FOR ORIGINATING ICMP ERROR
// MESSAGES."
static uint8_t icmp6_in_suppressed(const Icmp6InErrArgs *a, size_t avail)
{
    uint8_t invoked = 0u;
    if (icmp6_in_invoking_type(a->invoking, avail, &invoked))
    {
        // (e.1) "An ICMPv6 error message.", which sec 2.1 identifies "by a zero in the high-order bit"
        if ((invoked & IDEMIP_ICMP6_INFORMATIONAL) == 0u)
        {
            return IDEMIP_ICMP6_IN_SUPPRESS_ERROR;
        }
        // (e.2) "An ICMPv6 redirect message [IPv6-DISC]."
        if (invoked == IDEMIP_ICMP6_IN_ND_REDIRECT)
        {
            return IDEMIP_ICMP6_IN_SUPPRESS_REDIRECT;
        }
    }
    const idemip_bool exception = icmp6_in_mcast_exception(a, avail);
    // (e.3) "A packet destined to an IPv6 multicast address."
    if (icmp6_in_is_multicast(idemip_ip6_dst(a->invoking)) && !exception)
    {
        return IDEMIP_ICMP6_IN_SUPPRESS_DST_MCAST;
    }
    // (e.4) "A packet sent as a link-layer multicast"
    if (a->link_mcast && !exception)
    {
        return IDEMIP_ICMP6_IN_SUPPRESS_LINK_MCAST;
    }
    // (e.5) "A packet sent as a link-layer broadcast"
    if (a->link_bcast && !exception)
    {
        return IDEMIP_ICMP6_IN_SUPPRESS_LINK_BCAST;
    }
    // (e.6) "A packet whose source address does not uniquely identify a single node -- e.g., the IPv6
    // Unspecified Address, an IPv6 multicast address, or an address known by the ICMP message
    // originator to be an IPv6 anycast address."
    const uint8_t *src = idemip_ip6_src(a->invoking);
    if (icmp6_in_is_unspecified(src) || icmp6_in_is_multicast(src) || a->src_anycast)
    {
        return IDEMIP_ICMP6_IN_SUPPRESS_SRC;
    }
    return IDEMIP_ICMP6_IN_SUPPRESS_NONE;
}

// --- the arriving message --------------------------------------------------

// Everything a call reports, zeroed, so a refused call leaves no result of an earlier one behind.
static void icmp6_in_result_clear(Icmp6InIo *io)
{
    io->src = NULL;
    io->dst = NULL;
    io->out_len = 0u;
    io->msg_off = 0u;
    io->msg_len = 0u;
    io->mtu = 0u;
    io->pointer = 0u;
    io->id = 0u;
    io->seq = 0u;
    io->act = 0u;
    io->type = 0u;
    io->code = 0u;
    io->proto = 0u;
    io->suppress = IDEMIP_ICMP6_IN_SUPPRESS_NONE;
    io->cksum_ok = IDEMIP_FALSE;
}

// RFC 4443 sec 2.4 (d): "the upper-layer protocol type is extracted from the original packet
// (contained in the body of the ICMPv6 error message)". A body too short to walk, or one whose chain
// does not close, retrieves none, and sec 2.4 (d) then drops the message.
static void icmp6_in_error_arrived(Icmp6InIo *io, const uint8_t *msg, size_t msg_len)
{
    if (msg_len < (size_t)IDEMIP_ICMP6_ERR_HDR_LEN)
    {
        io->act = (uint8_t)(io->act | IDEMIP_ICMP6_IN_ACT_DISCARD);
        return;
    }
    if (io->type == (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG)
    {
        io->mtu = idemip_icmp6_mtu(msg);
    }
    if (io->type == (uint8_t)IDEMIP_ICMP6_PARAMETER_PROBLEM)
    {
        io->pointer = idemip_icmp6_pointer(msg);
    }
    const uint8_t *body = msg + IDEMIP_ICMP6_ERR_HDR_LEN;
    const size_t body_len = msg_len - IDEMIP_ICMP6_ERR_HDR_LEN;
    const IdemIpIp6Chain c = idemip_ip6_walk(body, body_len);
    if (!c.ok || c.next_hdr == IDEMIP_IP6_NH_NONE)
    {
        io->act = (uint8_t)(io->act | IDEMIP_ICMP6_IN_ACT_DISCARD);
        return;
    }
    io->proto = c.next_hdr;
    io->act = (uint8_t)(io->act | IDEMIP_ICMP6_IN_ACT_TRANSPORT);
}

// RFC 4443 sec 4.2: Type 129, "The identifier from the invoking Echo Request message", its Sequence
// Number, and "The data received in the ICMPv6 Echo Request message MUST be returned entirely and
// unmodified". The request lies in the caller's receive storage, so the reply is built out of it
// rather than over it, and sec 2.3's checksum is written last.
static void icmp6_in_build_echo_reply(Icmp6InIo *io, const uint8_t *msg, size_t msg_len)
{
    const size_t data_len = msg_len - IDEMIP_ICMP6_ECHO_HDR_LEN;
    const size_t n = idemip_icmp6_echo_reply_build(io->recv_args.out, io->id, io->seq,
                                                   msg + IDEMIP_ICMP6_ECHO_HDR_LEN, data_len);
    idemip_wr16(io->recv_args.out + IDEMIP_ICMP6_OFF_CKSUM,
                idemip_icmp6_cksum_compute(io->recv_args.out, n, io->src, io->dst));
    io->out_len = n;
    io->act = (uint8_t)(io->act | IDEMIP_ICMP6_IN_ACT_REPLY);
}

// --- the entries -----------------------------------------------------------

static void icmp6_in_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work, 0, (size_t)IDEMIP_ICMP6_IN_BORROW);
    Icmp6InCtx *ctx = ICMP6_IN_CTX(work);
    ctx->ready = ICMP6_IN_READY;
    ctx->tokens = (uint8_t)IDEMIP_ICMP6_ERR_BUCKET; // sec 2.4 (f): a full bucket allows the first burst
    ICMP6_IN_IO(work)->status = IDEMIP_OK;
}

// One message that arrived in an IPv6 packet, found by stepping the RFC 8200 sec 4 chain to it. A
// message the sec 2.3 checksum refuses, one shorter than its type needs, and an informational type
// this build does not implement are all discarded, which is sec 2.4 (b): "If an ICMPv6 informational
// message of unknown type is received, it MUST be silently discarded." The RFC 2710 and RFC 4861
// types are their own units' and reach those before this entry.
static void icmp6_in_recv(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Icmp6InIo *io = ICMP6_IN_IO(work);
    icmp6_in_result_clear(io);
    io->status = IDEMIP_ERR;
    if (ICMP6_IN_CTX(work)->ready != ICMP6_IN_READY)
    {
        return;
    }
    const Icmp6InRecvArgs *a = &io->recv_args;
    if (a->packet == NULL || a->out == NULL || a->if_addr == NULL || a->len < IDEMIP_IPV6_HDR_LEN)
    {
        return;
    }
    if (idemip_ip6_version(a->packet) != IDEMIP_IP6_VERSION)
    {
        return;
    }
    const IdemIpIp6Chain c = idemip_ip6_walk(a->packet, a->len);
    if (!c.ok || c.next_hdr != IDEMIP_IP6_NH_ICMPV6)
    {
        return;
    }
    const size_t msg_len = (size_t)idemip_ip6_upper_len(a->packet, &c);
    if (c.offset + msg_len > a->len)
    {
        return; // the Payload Length names more than the caller can read
    }
    const uint8_t *msg = a->packet + c.offset;
    const uint8_t *dst = idemip_ip6_dst(a->packet);

    io->msg_off = c.offset;
    io->msg_len = msg_len;
    // sec 2.2 (a): a reply to a message sent to one of the node's unicast addresses takes that same
    // address, and sec 4.2 sends one to a multicast or anycast request from "a unicast address
    // belonging to the interface on which the Echo Request message was received".
    io->src = (icmp6_in_is_multicast(dst) || a->dst_anycast) ? a->if_addr : dst;
    io->dst = idemip_ip6_src(a->packet);
    io->status = IDEMIP_OK;

    if (msg_len < (size_t)IDEMIP_ICMP6_HDR_LEN)
    {
        io->act = IDEMIP_ICMP6_IN_ACT_DISCARD;
        return;
    }
    io->type = idemip_icmp6_type(msg);
    io->code = idemip_icmp6_code(msg);
    io->cksum_ok = icmp6_in_cksum_ok(a->packet, msg, msg_len);
    if (!io->cksum_ok)
    {
        io->act = IDEMIP_ICMP6_IN_ACT_DISCARD;
        return;
    }
    // sec 2.4 (a): an error message of unknown type "MUST be passed to the upper-layer process that
    // originated the packet that caused the error", which is the same path the four sec 3 types take.
    if (!idemip_icmp6_is_informational(msg))
    {
        icmp6_in_error_arrived(io, msg, msg_len);
        return;
    }
    if (io->type != (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST && io->type != (uint8_t)IDEMIP_ICMP6_ECHO_REPLY)
    {
        io->act = IDEMIP_ICMP6_IN_ACT_DISCARD;
        return;
    }
    if (msg_len < (size_t)IDEMIP_ICMP6_ECHO_HDR_LEN)
    {
        io->act = IDEMIP_ICMP6_IN_ACT_DISCARD;
        return;
    }
    io->id = idemip_icmp6_id(msg);
    io->seq = idemip_icmp6_seq(msg);
    if (io->type == (uint8_t)IDEMIP_ICMP6_ECHO_REPLY)
    {
        io->act = IDEMIP_ICMP6_IN_ACT_USER;
        return;
    }
    if (a->out_cap < msg_len)
    {
        // sec 4.2 returns the data "entirely and unmodified" and states no truncation, so a buffer
        // that cannot hold it all builds nothing.
        icmp6_in_result_clear(io);
        io->status = IDEMIP_ERR;
        return;
    }
    icmp6_in_build_echo_reply(io, msg, msg_len);
}

// One sec 3 error message about a packet, its head and its clamped quote written by icmpv6.h. sec 2.4
// (c): "Every ICMPv6 error message (type < 128) MUST include as much of the IPv6 offending (invoking)
// packet (the packet that caused the error) as possible without making the error message packet
// exceed the minimum IPv6 MTU".
static void icmp6_in_error(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Icmp6InIo *io = ICMP6_IN_IO(work);
    icmp6_in_result_clear(io);
    io->status = IDEMIP_ERR;
    Icmp6InCtx *ctx = ICMP6_IN_CTX(work);
    if (ctx->ready != ICMP6_IN_READY)
    {
        return;
    }
    const Icmp6InErrArgs *a = &io->err_args;
    io->tokens = ctx->tokens;
    if (a->invoking == NULL || a->out == NULL || a->if_addr == NULL || a->len < IDEMIP_IPV6_HDR_LEN)
    {
        return;
    }
    if (idemip_ip6_version(a->invoking) != IDEMIP_IP6_VERSION)
    {
        return;
    }
    io->type = a->type;
    io->code = a->code;
    if (a->type < (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE || a->type > (uint8_t)IDEMIP_ICMP6_PARAMETER_PROBLEM)
    {
        return; // not one of the four types sec 3 defines
    }
    // RFC 8200 sec 3 Payload Length bounds the packet, and a frame carrying padding behind it reads
    // longer, so the quote runs to whichever ends first.
    const size_t pkt_len = (size_t)IDEMIP_IPV6_HDR_LEN + (size_t)idemip_ip6_payload_len(a->invoking);
    const size_t avail = (pkt_len < a->len) ? pkt_len : a->len;
    io->suppress = icmp6_in_suppressed(a, avail);
    if (io->suppress != IDEMIP_ICMP6_IN_SUPPRESS_NONE)
    {
        return; // the rule refused it, and no later call about this packet succeeds
    }
    const size_t quote = idemip_icmp6_err_quote_len(avail);
    const size_t out_len = (size_t)IDEMIP_ICMP6_ERR_HDR_LEN + quote;
    if (a->out_cap < out_len)
    {
        return;
    }
    // sec 2.4 (f) is answered last, so a token is spent only on a message that is actually built.
    icmp6_in_refill(ctx, a->now_ms);
    io->tokens = ctx->tokens;
    if (ctx->tokens == 0u)
    {
        io->suppress = IDEMIP_ICMP6_IN_SUPPRESS_RATE;
        io->status = IDEMIP_BUSY; // the clock refills the bucket, so a later tick succeeds
        return;
    }
    ctx->tokens = (uint8_t)(ctx->tokens - 1u);
    io->tokens = ctx->tokens;

    // sec 2.2 (a): "If the message is a response to a message sent to one of the node's unicast
    // addresses, the Source Address of the reply MUST be that same address." (b) covers every other
    // destination the invoking packet could carry - "a multicast group address, an anycast address
    // implemented by the node, or a unicast address that does not belong to the node" - and requires
    // "a unicast address belonging to the node", which is the interface's. A multicast destination is
    // never a node's unicast address, so it takes the interface's whatever the caller reports.
    const uint8_t *dst = idemip_ip6_dst(a->invoking);
    io->src = (a->dst_local_unicast && !icmp6_in_is_multicast(dst)) ? dst : a->if_addr;
    io->dst = idemip_ip6_src(a->invoking);
    io->out_len = idemip_icmp6_err_build(a->out, a->type, a->code, a->word, a->invoking, avail);
    idemip_wr16(a->out + IDEMIP_ICMP6_OFF_CKSUM,
                idemip_icmp6_cksum_compute(a->out, io->out_len, io->src, io->dst));
    io->status = IDEMIP_OK;
}

const Icmp6InNs Icmp6In = {.clear = icmp6_in_clear, .recv = icmp6_in_recv, .error = icmp6_in_error};

IDEMIP_END_DECLS
