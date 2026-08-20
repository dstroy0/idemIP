// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file icmp_in.c
 * @brief RFC 792 messages read and built, under the RFC 1122 sec 3.2.2 rules on originating an
 *        error.
 *
 * The operand block and the context are regions of the one pointer each entry is handed, at
 * compile-time offsets, and no entry reads or writes a byte outside it and the two buffers the
 * operand block names. Two borrows therefore share nothing, and the same call on the same borrow
 * does the same thing.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/icmp/icmp_in.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. A borrow that was never cleared carries no mark, so every
// entry refuses it.
typedef struct
{
    uint32_t ready;
    uint32_t refill_ms;
    uint8_t tokens;
} IcmpInCtx;

// The mark clear leaves.
#define ICMP_IN_READY 0x49434D34u

// The caller's borrow, split: the operand block, then the context. icmp_in.h publishes the offsets;
// the assert below proves the span covers them before anything runs.
static_assert(IDEMIP_ICMP_IN_OFF_CTX + sizeof(IcmpInCtx) <= IDEMIP_ICMP_IN_BORROW,
              "IDEMIP_ICMP_IN_BORROW is short of the operand block and the context - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define ICMP_IN_CTX(w) ((IcmpInCtx *)(void *)((w) + IDEMIP_ICMP_IN_OFF_CTX))
#define ICMP_IN_IO(w) IDEMIP_ICMP_IN_IO(w)

// --- the address forms RFC 1122 sec 3.2.1.3 names --------------------------

// The top four bits of an address, which RFC 1112 sec 4 sorts class D and class E on.
#define ICMP_IN_CLASS_SHIFT 28u
#define ICMP_IN_CLASS_D 0xEu
#define ICMP_IN_CLASS_E 0xFu

// RFC 1122 sec 3.2.1.3 (c): "{ -1, -1 } Limited broadcast."
#define ICMP_IN_ALL_ONES 0xFFFFFFFFu

// RFC 1122 sec 3.2.1.3 (g): "{ 127, <any> } Internal host loopback address."
#define ICMP_IN_LOOPBACK_NET 127u
#define ICMP_IN_NET_SHIFT 24u

// RFC 1112 sec 4: "Host groups are identified by class D IP addresses, i.e., those with "1110" as
// their high-order four bits."
static idemip_bool icmp_in_is_multicast(uint32_t addr)
{
    return ((addr >> ICMP_IN_CLASS_SHIFT) == ICMP_IN_CLASS_D) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 1112 sec 4: "Class E IP addresses, i.e., those with "1111" as their high-order four bits, are
// reserved for future addressing modes."
static idemip_bool icmp_in_is_class_e(uint32_t addr)
{
    return ((addr >> ICMP_IN_CLASS_SHIFT) == ICMP_IN_CLASS_E) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// The classful network mask RFC 791 sec 3.2 "Address Formats" gives an address: seven bits of net
// under a leading 0, fourteen under 10, twenty-one under 110. An address above that is class D or
// class E, which name no network, and reads as all ones so no host part is left.
static uint32_t icmp_in_classful_mask(uint32_t addr)
{
    if ((addr & 0x80000000u) == 0u)
    {
        return 0xFF000000u;
    }
    if ((addr & 0x40000000u) == 0u)
    {
        return 0xFFFF0000u;
    }
    if ((addr & 0x20000000u) == 0u)
    {
        return 0xFFFFFF00u;
    }
    return ICMP_IN_ALL_ONES;
}

// The four broadcast forms of RFC 1122 sec 3.2.1.3: (c) "{ -1, -1 } Limited broadcast", (d)
// "{ <Network-number>, -1 } Directed broadcast to the specified network", (e) "{ <Network-number>,
// <Subnet-number>, -1 } Directed broadcast to the specified subnet" and (f) "{ <Network-number>, -1,
// -1 } Directed broadcast to all subnets". Each is a host part of all ones under the mask that names
// it: the interface's for (e), the classful one for (d) and (f).
static idemip_bool icmp_in_is_broadcast(uint32_t addr, uint32_t if_mask)
{
    if (addr == ICMP_IN_ALL_ONES)
    {
        return IDEMIP_TRUE;
    }
    if (icmp_in_is_multicast(addr) || icmp_in_is_class_e(addr))
    {
        return IDEMIP_FALSE;
    }
    if (if_mask != ICMP_IN_ALL_ONES && (addr | if_mask) == ICMP_IN_ALL_ONES)
    {
        return IDEMIP_TRUE;
    }
    const uint32_t classful = icmp_in_classful_mask(addr);
    return ((addr | classful) == ICMP_IN_ALL_ONES) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 1122 sec 3.2.2's last MUST NOT: "a datagram whose source address does not define a single host
// -- e.g., a zero address, a loopback address, a broadcast address, a multicast address, or a Class
// E address."
static idemip_bool icmp_in_src_is_single_host(uint32_t src, uint32_t if_mask)
{
    if (src == 0u || (src >> ICMP_IN_NET_SHIFT) == ICMP_IN_LOOPBACK_NET)
    {
        return IDEMIP_FALSE;
    }
    if (icmp_in_is_multicast(src) || icmp_in_is_class_e(src))
    {
        return IDEMIP_FALSE;
    }
    return icmp_in_is_broadcast(src, if_mask) ? IDEMIP_FALSE : IDEMIP_TRUE;
}

// --- the arriving message --------------------------------------------------

// RFC 1122 sec 3.2.1.3: "the specific-destination is an IP address assigned to the physical
// interface on which the datagram arrived" when the header carries a broadcast or multicast address,
// and the header's own destination otherwise.
static uint32_t icmp_in_specific_dst(uint32_t dst, uint32_t if_addr, uint32_t if_mask)
{
    if (icmp_in_is_multicast(dst) || icmp_in_is_broadcast(dst, if_mask))
    {
        return if_addr;
    }
    return dst;
}

// RFC 792, Echo or Echo Reply: "To form an echo reply message, the source and destination addresses
// are simply reversed, the type code changed to 0, and the checksum recomputed", and RFC 1122
// sec 3.2.2.6: "Data received in an ICMP Echo Request MUST be entirely included in the resulting Echo
// Reply. However, if sending the Echo Reply requires intentional fragmentation that is not
// implemented, the datagram MUST be truncated to maximum transmission size ... and sent." The
// request lies in the caller's receive storage, so the reply is copied out before the type and the
// checksum are rewritten over it.
static void icmp_in_build_echo_reply(IcmpInIo *io, const uint8_t *msg, size_t msg_len)
{
    size_t len = msg_len;
    io->truncated = IDEMIP_FALSE;
    if (len > io->recv_args.out_cap)
    {
        len = io->recv_args.out_cap;
        io->truncated = IDEMIP_TRUE;
    }
    memcpy(io->recv_args.out, msg, len);
    idemip_icmp_echo_reply(io->recv_args.out, len);
    io->out_len = len;
    io->act |= IDEMIP_ICMP_IN_ACT_REPLY;
}

// The Protocol field of the internet header an error message quotes, which RFC 1122 sec 3.2.2 demuxes
// the error on. Present only when the quote carries a whole header.
static idemip_bool icmp_in_quoted_proto(const uint8_t *msg, size_t msg_len, uint8_t *proto)
{
    if (msg_len < (size_t)IDEMIP_ICMP_OFF_QUOTE + IDEMIP_IPV4_HDR_LEN)
    {
        return IDEMIP_FALSE;
    }
    const uint8_t *quote = idemip_icmp_quote(msg);
    if (!idemip_ip4_version_ok(quote) || !idemip_ip4_ihl_ok(quote))
    {
        return IDEMIP_FALSE;
    }
    *proto = idemip_ip4_proto(quote);
    return IDEMIP_TRUE;
}

// The five types RFC 1122 sec 3.2.2 groups as errors carry a quoted datagram, so each reports the
// transport demux of that section. RFC 1122 sec 3.2.2.2 makes a Redirect a routing update instead:
// "A host receiving a Redirect message MUST update its routing information accordingly."
static void icmp_in_error_arrived(IcmpInIo *io, const uint8_t *msg, size_t msg_len)
{
    if (io->type == (uint8_t)IDEMIP_ICMP_REDIRECT)
    {
        if (msg_len < (size_t)IDEMIP_ICMP_ERR_HDR_LEN)
        {
            io->bad_len = IDEMIP_TRUE;
            io->act |= IDEMIP_ICMP_IN_ACT_DISCARD;
            return;
        }
        io->gateway = idemip_icmp_gateway(msg);
        // RFC 1122 sec 3.2.2.2: "A Redirect message SHOULD be silently discarded if the new gateway
        // address it specifies is not on the same connected (sub-) net through which the Redirect
        // arrived", the sec 4.2.2 summary listing it as "Discard illegal Redirect". A broadcast or
        // multicast address on that subnet does not name a gateway either.
        const uint32_t mask = io->recv_args.if_mask;
        if (((io->gateway ^ io->recv_args.if_addr) & mask) != 0u || icmp_in_is_broadcast(io->gateway, mask) ||
            icmp_in_is_multicast(io->gateway))
        {
            io->suppress = IDEMIP_ICMP_IN_SUPPRESS_REDIRECT;
            io->act |= IDEMIP_ICMP_IN_ACT_DISCARD;
            return;
        }
        // The second half of sec 3.2.2.2, "or if the source of the Redirect is not the current
        // first-hop gateway for the specified destination", needs the route the caller holds, so the
        // quoted datagram's Destination Address is reported for it to test and to key its cache on.
        if (icmp_in_quoted_proto(msg, msg_len, &io->proto))
        {
            io->quoted_dst = idemip_ip4_dst(idemip_icmp_quote(msg));
        }
        io->act |= IDEMIP_ICMP_IN_ACT_ROUTE;
        return;
    }
    if (!icmp_in_quoted_proto(msg, msg_len, &io->proto))
    {
        io->bad_len = IDEMIP_TRUE;
        io->act |= IDEMIP_ICMP_IN_ACT_DISCARD;
        return;
    }
    io->act |= IDEMIP_ICMP_IN_ACT_TRANSPORT;
}

// RFC 792's query types. An Echo is answered here, an Echo Reply goes to the user, and the three
// RFC 1122 leaves unimplemented are discarded: sec 3.2.2.7 "A host SHOULD NOT implement these
// messages" for information request and reply, and sec 3.2.2.8's "A host MAY implement Timestamp and
// Timestamp Reply", which this build does not.
static void icmp_in_query_arrived(IcmpInIo *io, const uint8_t *msg, size_t msg_len, uint32_t dst)
{
    if (io->type != (uint8_t)IDEMIP_ICMP_ECHO && io->type != (uint8_t)IDEMIP_ICMP_ECHO_REPLY)
    {
        io->act |= IDEMIP_ICMP_IN_ACT_DISCARD;
        return;
    }
    if (msg_len < (size_t)IDEMIP_ICMP_ECHO_HDR_LEN)
    {
        io->bad_len = IDEMIP_TRUE;
        io->act |= IDEMIP_ICMP_IN_ACT_DISCARD;
        return;
    }
    io->id = idemip_icmp_id(msg);
    io->seq = idemip_icmp_seq(msg);
    if (io->type == (uint8_t)IDEMIP_ICMP_ECHO_REPLY)
    {
        io->act |= IDEMIP_ICMP_IN_ACT_USER;
        return;
    }
    // RFC 1122 sec 3.2.2.6: "An ICMP Echo Request destined to an IP broadcast or IP multicast address
    // MAY be silently discarded." IDEMIP_ICMP_ECHO_BROADCAST picks which of the two this build does.
    if (!IDEMIP_ICMP_ECHO_BROADCAST &&
        (icmp_in_is_multicast(dst) || icmp_in_is_broadcast(dst, io->recv_args.if_mask)))
    {
        io->act |= IDEMIP_ICMP_IN_ACT_DISCARD;
        return;
    }
    icmp_in_build_echo_reply(io, msg, msg_len);
}

// --- the entries -----------------------------------------------------------

void idemip_icmp_in_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work, 0, (size_t)IDEMIP_ICMP_IN_BORROW);
    IcmpInCtx *ctx = ICMP_IN_CTX(work);
    ctx->ready = ICMP_IN_READY;
    ctx->tokens = (uint8_t)IDEMIP_ICMP4_ERR_BUCKET; // sec 4.3.2.8: a full bucket allows the first burst
    ICMP_IN_IO(work)->status = IDEMIP_OK;
}

// Everything a call reports, zeroed, so a refused call leaves no result of an earlier one behind.
static void icmp_in_result_clear(IcmpInIo *io)
{
    io->out_len = 0u;
    io->src = 0u;
    io->dst = 0u;
    io->gateway = 0u;
    io->act = 0u;
    io->type = 0u;
    io->code = 0u;
    io->proto = 0u;
    io->id = 0u;
    io->seq = 0u;
    io->suppress = IDEMIP_ICMP_IN_SUPPRESS_NONE;
    io->tokens = 0u;
    io->quoted_dst = 0u;
    io->cksum_ok = IDEMIP_FALSE;
    io->bad_len = IDEMIP_FALSE;
    io->truncated = IDEMIP_FALSE;
}

// One message that arrived in a verified internet datagram. RFC 792 fixes the checksum as running
// over the message alone, "starting with the ICMP Type", and RFC 1071 sec 1 makes a span carrying its
// own checksum sum to all ones, so the verify is that sum against zero. A message the sum refuses,
// one shorter than its type needs, and one of a type RFC 1122 sec 3.2.2 does not name are all
// discarded: "If an ICMP message of unknown type is received, it MUST be silently discarded."
void idemip_icmp_in_recv(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IcmpInIo *io = ICMP_IN_IO(work);
    icmp_in_result_clear(io);
    io->status = IDEMIP_ERR;
    if (ICMP_IN_CTX(work)->ready != ICMP_IN_READY)
    {
        return;
    }
    const IcmpInRecvArgs *a = &io->recv_args;
    if (a->datagram == NULL || a->out == NULL || a->out_cap < (size_t)IDEMIP_ICMP_ECHO_HDR_LEN)
    {
        return;
    }
    if (idemip_ip4_verify(a->datagram, a->len) != IDEMIP_OK)
    {
        return;
    }
    const size_t hdr_len = idemip_ip4_hdr_len(a->datagram);
    const size_t msg_len = (size_t)idemip_ip4_total_len(a->datagram) - hdr_len;
    const uint8_t *msg = a->datagram + hdr_len;
    const uint32_t dst = idemip_ip4_dst(a->datagram);

    io->src = icmp_in_specific_dst(dst, a->if_addr, a->if_mask);
    io->dst = idemip_ip4_src(a->datagram);
    io->status = IDEMIP_OK;
    if (msg_len < (size_t)IDEMIP_ICMP_HDR_LEN)
    {
        io->bad_len = IDEMIP_TRUE;
        io->act = IDEMIP_ICMP_IN_ACT_DISCARD;
        return;
    }
    io->type = idemip_icmp_type(msg);
    io->code = idemip_icmp_code(msg);
    io->cksum_ok = idemip_cksum_valid(msg, msg_len);
    if (!io->cksum_ok)
    {
        io->act = IDEMIP_ICMP_IN_ACT_DISCARD;
        return;
    }
    if (idemip_icmp_is_error(msg))
    {
        icmp_in_error_arrived(io, msg, msg_len);
        return;
    }
    icmp_in_query_arrived(io, msg, msg_len, dst);
}

// The five RFC 1122 sec 3.2.2 MUST NOT rules, each answered before any octet is written. "NOTE:
// THESE RESTRICTIONS TAKE PRECEDENCE OVER ANY REQUIREMENT ELSEWHERE IN THIS DOCUMENT FOR SENDING
// ICMP ERROR MESSAGES."
static uint8_t icmp_in_suppressed(const IcmpInErrArgs *a)
{
    // "an ICMP error message". The Protocol field names ICMP and the type is one of the five that
    // section groups as errors; a query type is not one, so an error about an Echo is allowed. Only
    // fragment zero carries the message head, so only fragment zero is read for it.
    if (idemip_ip4_proto(a->datagram) == IDEMIP_IP4_PROTO_ICMP && idemip_ip4_frag_units(a->datagram) == 0u)
    {
        const size_t hdr_len = idemip_ip4_hdr_len(a->datagram);
        if ((size_t)idemip_ip4_total_len(a->datagram) >= hdr_len + IDEMIP_ICMP_HDR_LEN &&
            idemip_icmp_is_error(a->datagram + hdr_len))
        {
            return IDEMIP_ICMP_IN_SUPPRESS_ICMP_ERROR;
        }
    }
    // "a datagram destined to an IP broadcast or IP multicast address"
    const uint32_t dst = idemip_ip4_dst(a->datagram);
    if (icmp_in_is_multicast(dst))
    {
        return IDEMIP_ICMP_IN_SUPPRESS_DST_MCAST;
    }
    if (icmp_in_is_broadcast(dst, a->if_mask))
    {
        return IDEMIP_ICMP_IN_SUPPRESS_DST_BCAST;
    }
    // "a datagram sent as a link-layer broadcast"
    if (a->link_bcast)
    {
        return IDEMIP_ICMP_IN_SUPPRESS_LINK_BCAST;
    }
    // "a non-initial fragment", which RFC 792 states as "ICMP messages are only sent about errors in
    // handling fragment zero of fragemented datagrams. (Fragment zero has the fragment offeset equal
    // zero)".
    if (idemip_ip4_frag_units(a->datagram) != 0u)
    {
        return IDEMIP_ICMP_IN_SUPPRESS_FRAGMENT;
    }
    // "a datagram whose source address does not define a single host"
    if (!icmp_in_src_is_single_host(idemip_ip4_src(a->datagram), a->if_mask))
    {
        return IDEMIP_ICMP_IN_SUPPRESS_SRC;
    }
    return IDEMIP_ICMP_IN_SUPPRESS_NONE;
}

// --- RFC 1812 sec 4.3.2.8, the rate limit ----------------------------------

// "A router which sends ICMP Source Quench messages MUST be able to limit the rate at which the
// messages can be generated. A router SHOULD also be able to limit the rate at which it sends other
// sorts of ICMP error messages." The section names the shape: "Bucket-based - count 'credits' ...
// allowing a burst of messages to be sent". One token lands every IDEMIP_ICMP4_ERR_TOKEN_MS, the
// count stops at IDEMIP_ICMP4_ERR_BUCKET, and a gap of a whole bucket or more fills it in one step so
// the loop runs at most IDEMIP_ICMP4_ERR_BUCKET times.
#define ICMP_IN_BUCKET_MS ((uint32_t)IDEMIP_ICMP4_ERR_BUCKET * (uint32_t)IDEMIP_ICMP4_ERR_TOKEN_MS)

static void icmp_in_refill(IcmpInCtx *ctx, uint32_t now_ms)
{
    if (ctx->tokens >= (uint8_t)IDEMIP_ICMP4_ERR_BUCKET)
    {
        ctx->tokens = (uint8_t)IDEMIP_ICMP4_ERR_BUCKET;
        ctx->refill_ms = now_ms;
        return;
    }
    uint32_t elapsed = now_ms - ctx->refill_ms;
    if (elapsed >= ICMP_IN_BUCKET_MS)
    {
        ctx->tokens = (uint8_t)IDEMIP_ICMP4_ERR_BUCKET;
        ctx->refill_ms = now_ms;
        return;
    }
    while (elapsed >= (uint32_t)IDEMIP_ICMP4_ERR_TOKEN_MS && ctx->tokens < (uint8_t)IDEMIP_ICMP4_ERR_BUCKET)
    {
        ctx->tokens = (uint8_t)(ctx->tokens + 1u);
        ctx->refill_ms += (uint32_t)IDEMIP_ICMP4_ERR_TOKEN_MS;
        elapsed -= (uint32_t)IDEMIP_ICMP4_ERR_TOKEN_MS;
    }
}

// One error message about a datagram, its head written by icmp.h and the quote copied behind it.
// RFC 792 carries "The internet header plus the first 64 bits of the original datagram's data", and
// RFC 1122 sec 3.2.2 requires "the Internet header and at least the first 8 data octets of the
// datagram that triggered the error; ... this header and data MUST be unchanged from the received
// datagram."
void idemip_icmp_in_error(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    IcmpInIo *io = ICMP_IN_IO(work);
    icmp_in_result_clear(io);
    io->status = IDEMIP_ERR;
    if (ICMP_IN_CTX(work)->ready != ICMP_IN_READY)
    {
        return;
    }
    const IcmpInErrArgs *a = &io->err_args;
    if (a->datagram == NULL || a->out == NULL)
    {
        return;
    }
    if (idemip_ip4_verify(a->datagram, a->len) != IDEMIP_OK)
    {
        return;
    }
    io->type = a->type;
    io->code = a->code;
    // The type octet alone, which is what IDEMIP_ICMP_OFF_TYPE names at the head of a message.
    if (!idemip_icmp_is_error(&a->type))
    {
        return; // not one of the five types RFC 1122 sec 3.2.2 groups as errors
    }
    // RFC 1122 sec 3.2.2.2: "A host SHOULD NOT send an ICMP Redirect message; Redirects are to be
    // sent only by gateways."
    if (a->type == (uint8_t)IDEMIP_ICMP_REDIRECT)
    {
        io->suppress = IDEMIP_ICMP_IN_SUPPRESS_REDIRECT;
        return;
    }
    io->suppress = icmp_in_suppressed(a);
    if (io->suppress != IDEMIP_ICMP_IN_SUPPRESS_NONE)
    {
        return; // the rule refused it, and no later call about this datagram succeeds
    }
    const size_t hdr_len = idemip_ip4_hdr_len(a->datagram);
    const size_t total = (size_t)idemip_ip4_total_len(a->datagram);
    size_t quote = hdr_len + IDEMIP_ICMP_ERR_QUOTE_DATA;
    if (quote > total)
    {
        quote = total;
    }
    const size_t out_len = (size_t)IDEMIP_ICMP_ERR_HDR_LEN + quote;
    if (a->out_cap < out_len)
    {
        return; // the buffer cannot hold the head and the quote RFC 1122 sec 3.2.2 requires
    }
    // RFC 1812 sec 4.3.2.8 is answered last, so a token is spent only on a message actually built.
    IcmpInCtx *ctx = ICMP_IN_CTX(work);
    icmp_in_refill(ctx, a->now_ms);
    io->tokens = ctx->tokens;
    if (ctx->tokens == 0u)
    {
        io->suppress = IDEMIP_ICMP_IN_SUPPRESS_RATE;
        io->status = IDEMIP_BUSY; // the clock refills the bucket, so a later call succeeds
        return;
    }
    ctx->tokens = (uint8_t)(ctx->tokens - 1u);
    io->tokens = ctx->tokens;
    memcpy(a->out + IDEMIP_ICMP_OFF_QUOTE, a->datagram, quote);
    idemip_icmp_build_error(a->out, a->type, a->code, a->word, out_len);
    io->out_len = out_len;
    io->src = idemip_ip4_dst(a->datagram);
    io->dst = idemip_ip4_src(a->datagram);
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
