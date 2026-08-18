// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip6_forward.c
 * @brief The RFC 8200 sec 3 Hop Limit rule, the RFC 4291 address rules, and the RFC 4443 sec 3.2
 *        answer to a packet a router may not fragment.
 *
 * The mark is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block and the context are both regions of that borrow, at compile-time offsets, and no entry reads
 * or writes a byte outside it, nor a byte of the packet the operands point at.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV6

#include "idemIP/ip/ip6_forward.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and decide
// refuses it.
#define IP6_FORWARD_READY 0x46573600u

// RFC 4291 sec 2.7: "binary 11111111 at the start of the address identifies the address as being a
// multicast address."
#define IP6_FORWARD_MULTICAST_TAG 0xFFu

// RFC 4291 sec 2.7: the second octet carries "flgs" then "scop is a 4-bit multicast scope value".
#define IP6_FORWARD_SCOP_MASK 0x0Fu
#define IP6_FORWARD_SCOP_RESERVED 0u    ///< "0 reserved"
#define IP6_FORWARD_SCOP_INTERFACE 1u   ///< "1 Interface-Local scope"
#define IP6_FORWARD_SCOP_LINK 2u        ///< "2 Link-Local scope"

// RFC 4291 sec 2.5.6: the first ten bits of a link-local address are 1111111010.
#define IP6_FORWARD_LINK_LOCAL_HI 0xFEu
#define IP6_FORWARD_LINK_LOCAL_MASK 0xC0u
#define IP6_FORWARD_LINK_LOCAL_LO 0x80u

// RFC 4291 sec 2.5.3: "The unicast address 0:0:0:0:0:0:0:1 is called the loopback address."
#define IP6_FORWARD_LOOPBACK_LOW 1u

// RFC 4861 sec 4.5 assigns the Redirect Message Type. RFC 4443 sec 2.1 puts it above 127, so it is an
// informational message and the sec 2.4 (e) suppression list does not reach it.
#define IP6_FORWARD_TYPE_REDIRECT 137u

// The context: the mark alone. RFC 8200 and RFC 4291 give a router no switch over any rule here, so
// there is nothing else to hold.
typedef struct
{
    uint32_t ready;
} Ip6ForwardCtx;

// The caller's borrow, split: the operand block, then the context. ip6_forward.h publishes the
// offsets; the assert proves the span covers them before anything runs.
static_assert(IDEMIP_IP6_FORWARD_OFF_CTX + sizeof(Ip6ForwardCtx) <= IDEMIP_IP6_FORWARD_BORROW,
              "IDEMIP_IP6_FORWARD_BORROW is short of the operand block and the context - raise "
              "IDEMIP_IP6_FORWARD_CTX_BYTES in idemip_config.h");

// The borrow abuts the next one the caller placed, so its length keeps that one's alignment.
static_assert((IDEMIP_IP6_FORWARD_BORROW & (IDEMIP_ALIGN - 1u)) == 0u,
              "IDEMIP_IP6_FORWARD_BORROW must be a multiple of IDEMIP_ALIGN");

// clear zeroes the context, so the reason a passing decision reports is the zero state.
static_assert(IDEMIP_IP6_FORWARD_R_OK == 0, "IDEMIP_IP6_FORWARD_R_OK must be zero: it is the reason of a clean pass");

// The regions, at their offsets in the caller's borrow.
#define IP6_FORWARD_IO(w) IDEMIP_IP6_FORWARD_IO(w)
#define IP6_FORWARD_CTX(w) ((Ip6ForwardCtx *)(void *)((w) + IDEMIP_IP6_FORWARD_OFF_CTX))

// A borrow clear has not run on carries no mark, so decide refuses it.
static idemip_bool ip6_forward_ready(uint8_t *restrict work)
{
    return (idemip_bool)(IP6_FORWARD_CTX(work)->ready == IP6_FORWARD_READY);
}

// --- the addresses ---------------------------------------------------------

// RFC 4291 sec 2.7: FF00::/8.
static idemip_bool ip6_forward_is_multicast(const uint8_t *a)
{
    return (idemip_bool)(a[0] == IP6_FORWARD_MULTICAST_TAG);
}

// RFC 4291 sec 2.5.6: FE80::/10.
static idemip_bool ip6_forward_is_link_local(const uint8_t *a)
{
    return (idemip_bool)(a[0] == IP6_FORWARD_LINK_LOCAL_HI &&
                         (uint8_t)(a[1] & IP6_FORWARD_LINK_LOCAL_MASK) == IP6_FORWARD_LINK_LOCAL_LO);
}

// RFC 4291 sec 2.5.2: "The address 0:0:0:0:0:0:0:0 is called the unspecified address."
static idemip_bool ip6_forward_is_unspecified(const uint8_t *a)
{
    for (size_t i = 0; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        if (a[i] != 0u)
        {
            return IDEMIP_FALSE;
        }
    }
    return IDEMIP_TRUE;
}

// RFC 4291 sec 2.5.3: fifteen zero octets and a low octet of one.
static idemip_bool ip6_forward_is_loopback(const uint8_t *a)
{
    for (size_t i = 0; i + 1u < IDEMIP_IP6_ADDR_LEN; i++)
    {
        if (a[i] != 0u)
        {
            return IDEMIP_FALSE;
        }
    }
    return (idemip_bool)(a[IDEMIP_IP6_ADDR_LEN - 1u] == IP6_FORWARD_LOOPBACK_LOW);
}

// RFC 4291 sec 2.7's scop nibble, the low half of the second octet.
static uint8_t ip6_forward_scope(const uint8_t *a)
{
    return (uint8_t)(a[1] & IP6_FORWARD_SCOP_MASK);
}

// --- the header ------------------------------------------------------------

// RFC 8200 sec 3: the Version is 6, and the Payload Length is "the rest of the packet following this
// header, in octets", so the header and it together fit the span the link layer delivered.
static idemip_bool ip6_forward_header_ok(const uint8_t *h, size_t len)
{
    if (len < IDEMIP_IPV6_HDR_LEN)
    {
        return IDEMIP_FALSE;
    }
    if (idemip_ip6_version(h) != IDEMIP_IP6_VERSION)
    {
        return IDEMIP_FALSE;
    }
    return (idemip_bool)(((size_t)idemip_ip6_payload_len(h) + (size_t)IDEMIP_IPV6_HDR_LEN) <= len);
}

// --- when an ICMPv6 error may be sent --------------------------------------

// RFC 4443 sec 2.4 (e.1) an ICMPv6 error message and (e.2) an ICMPv6 redirect message. The chain is
// walked to the upper-layer header, which RFC 8200 sec 4 reaches by "the first one that is not an
// extension header". A packet carrying a Fragment header at a nonzero offset holds no upper-layer
// header to read, so nothing is claimed about it.
static idemip_bool ip6_forward_carries_icmp_error(const uint8_t *h, size_t len)
{
    IdemIpIp6Chain c = idemip_ip6_walk(h, len);
    if (!c.ok || c.next_hdr != (uint8_t)IDEMIP_IP6_NH_ICMPV6)
    {
        return IDEMIP_FALSE;
    }
    if (c.fragmented && idemip_ip6_frag_offset_bytes(h + c.frag_hdr) != 0u)
    {
        return IDEMIP_FALSE;
    }
    if (c.offset + (size_t)IDEMIP_ICMP6_OFF_TYPE + 1u > len)
    {
        return IDEMIP_FALSE;
    }
    uint8_t type = h[c.offset + IDEMIP_ICMP6_OFF_TYPE];
    return (idemip_bool)(type < IDEMIP_ICMP6_INFORMATIONAL || type == IP6_FORWARD_TYPE_REDIRECT);
}

// RFC 4443 sec 2.4 (e), the whole list. sec 3.2 makes Packet Too Big the exception to (e.3), (e.4)
// and (e.5): "Unlike other messages, it is sent in response to a packet received with an IPv6
// multicast destination address, or with a link-layer multicast or link-layer broadcast address."
// (e.6) has no exception, so a source that names no single node suppresses every message.
static idemip_bool ip6_forward_icmp_allowed(const uint8_t *h, size_t len, const Ip6ForwardArgs *a, idemip_bool too_big)
{
    const uint8_t *src = idemip_ip6_src(h);
    const uint8_t *dst = idemip_ip6_dst(h);
    if (ip6_forward_is_unspecified(src) || ip6_forward_is_multicast(src))
    {
        return IDEMIP_FALSE; // (e.6) "A packet whose source address does not uniquely identify a single node"
    }
    if (ip6_forward_carries_icmp_error(h, len))
    {
        return IDEMIP_FALSE; // (e.1) and (e.2)
    }
    if (!too_big && (ip6_forward_is_multicast(dst) || a->ll_multicast || a->ll_broadcast))
    {
        return IDEMIP_FALSE; // (e.3), (e.4) and (e.5)
    }
    return IDEMIP_TRUE;
}

// --- the decision ----------------------------------------------------------

// Every result member, back to the state a decision that reached no rule leaves.
static void ip6_forward_reset(Ip6ForwardIo *io)
{
    io->next_hop = NULL;
    io->redirect_target = NULL;
    io->mtu = 0;
    io->action = IDEMIP_IP6_FORWARD_DISCARD;
    io->reason = IDEMIP_IP6_FORWARD_R_OK;
    io->hop_limit = 0;
    io->netif = 0;
    io->icmp_type = IDEMIP_IP6_FORWARD_ICMP_NONE;
    io->icmp_code = 0;
    io->icmp = IDEMIP_FALSE;
    io->redirect = IDEMIP_FALSE;
}

// A discard the RFC names, with no message owed.
static void ip6_forward_drop(Ip6ForwardIo *io, IdemIpIp6ForwardReason reason)
{
    io->action = IDEMIP_IP6_FORWARD_DISCARD;
    io->reason = reason;
    io->status = IDEMIP_OK;
}

// A discard with a message owed, subject to the sec 2.4 (e) list.
static void ip6_forward_drop_icmp(Ip6ForwardIo *io, IdemIpIp6ForwardReason reason, uint8_t type, uint8_t code,
                                  idemip_bool allowed)
{
    ip6_forward_drop(io, reason);
    if (allowed)
    {
        io->icmp = IDEMIP_TRUE;
        io->icmp_type = type;
        io->icmp_code = code;
    }
}

// RFC 4291 sec 2.5.6 of the unicast link-local addresses and sec 2.7 of the multicast scopes: a
// packet leaving the interface it arrived on stays on one link, and every other case crosses to
// another link, which the scope forbids.
static idemip_bool ip6_forward_crosses_link(const Ip6ForwardArgs *a)
{
    return (idemip_bool)(a->out_netif != a->in_netif);
}

// --- the entries -----------------------------------------------------------

// The context, zeroed, then the mark. The operand block is the caller's and is left as it stands.
static void ip6_forward_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP6_FORWARD_OFF_CTX, 0,
           (size_t)IDEMIP_IP6_FORWARD_BORROW - (size_t)IDEMIP_IP6_FORWARD_OFF_CTX);
    IP6_FORWARD_CTX(work)->ready = IP6_FORWARD_READY;
    IP6_FORWARD_IO(work)->status = IDEMIP_OK;
}

// The RFC 4291 address rules, then the RFC 8200 sec 3 Hop Limit, then the sec 4.5 rule that a router
// does not fragment, then the RFC 4861 sec 8.2 Redirect.
//
// A packet the RFC discards is a decision that succeeded, so the status is OK and the action is
// DISCARD. ERR is the operands: no packet, a borrow clear has not run on, an interface index past
// IDEMIP_NETIF_COUNT, a routed call with no next hop, or an outgoing MTU under the 1280 octets RFC
// 8200 sec 5 requires of every link. Nothing here is BUSY: the same operands decide the same way
// forever, so a retry can never change the answer.
static void ip6_forward_decide(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip6ForwardIo *io = IP6_FORWARD_IO(work);
    io->status = IDEMIP_ERR;
    ip6_forward_reset(io);
    if (!ip6_forward_ready(work))
    {
        return;
    }
    const Ip6ForwardArgs *a = &io->fwd_args;
    const uint8_t *h = a->hdr;
    if (h == NULL || a->in_netif >= (uint8_t)IDEMIP_NETIF_COUNT)
    {
        return;
    }
    if (a->routed && (a->out_netif >= (uint8_t)IDEMIP_NETIF_COUNT || a->next_hop == NULL ||
                      a->out_mtu < IDEMIP_IPV6_MIN_MTU))
    {
        return;
    }

    // RFC 8200 sec 3 fixes the Version and the Payload Length, and nothing below reads a field until
    // both hold.
    if (!ip6_forward_header_ok(h, a->len))
    {
        ip6_forward_drop(io, IDEMIP_IP6_FORWARD_R_HEADER);
        return;
    }

    const uint8_t *src = idemip_ip6_src(h);
    const uint8_t *dst = idemip_ip6_dst(h);

    // RFC 4291 sec 2.5.2, sec 2.5.3 and sec 2.7 on the source: an unspecified source "must never be
    // forwarded by an IPv6 router", a loopback source "must not be used ... outside of a single
    // node", and a multicast source "must not be used as source addresses in IPv6 packets".
    if (ip6_forward_is_unspecified(src))
    {
        ip6_forward_drop(io, IDEMIP_IP6_FORWARD_R_SRC_UNSPEC);
        return;
    }
    if (ip6_forward_is_multicast(src))
    {
        ip6_forward_drop(io, IDEMIP_IP6_FORWARD_R_SRC_MCAST);
        return;
    }
    if (ip6_forward_is_loopback(src))
    {
        ip6_forward_drop(io, IDEMIP_IP6_FORWARD_R_SRC_LOOP);
        return;
    }

    // RFC 4291 sec 2.5.2: "The unspecified address must not be used as the destination address of
    // IPv6 packets." sec 2.5.3: a packet with a destination of loopback "must never be forwarded by
    // an IPv6 router".
    if (ip6_forward_is_unspecified(dst))
    {
        ip6_forward_drop(io, IDEMIP_IP6_FORWARD_R_DST_UNSPEC);
        return;
    }
    if (ip6_forward_is_loopback(dst))
    {
        ip6_forward_drop(io, IDEMIP_IP6_FORWARD_R_DST_LOOP);
        return;
    }

    // RFC 4291 sec 2.7 on the destination's scope: "Nodes must not originate a packet to a multicast
    // address whose scop field contains the reserved value 0; if such a packet is received, it must
    // be silently dropped", and "Routers must not forward any multicast packets beyond of the scope
    // indicated by the scop field", which stops interface-local at the node and link-local at the
    // link it arrived on.
    if (ip6_forward_is_multicast(dst))
    {
        uint8_t scop = ip6_forward_scope(dst);
        if (scop == IP6_FORWARD_SCOP_RESERVED || scop == IP6_FORWARD_SCOP_INTERFACE ||
            (scop == IP6_FORWARD_SCOP_LINK && ip6_forward_crosses_link(a)))
        {
            ip6_forward_drop(io, IDEMIP_IP6_FORWARD_R_SCOPE);
            return;
        }
    }

    // RFC 4291 sec 2.5.6: "Routers must not forward any packets with Link-Local source or destination
    // addresses to other links."
    if ((ip6_forward_is_link_local(src) || ip6_forward_is_link_local(dst)) && ip6_forward_crosses_link(a))
    {
        ip6_forward_drop(io, IDEMIP_IP6_FORWARD_R_LINK_LOCAL);
        return;
    }

    idemip_bool icmp_ok = ip6_forward_icmp_allowed(h, a->len, a, IDEMIP_FALSE);

    // RFC 4443 sec 3.1 Code 0, "No route to destination", which its Description gives as the answer
    // "in response to a packet that cannot be delivered to its destination address for reasons other
    // than congestion".
    if (!a->routed)
    {
        ip6_forward_drop_icmp(io, IDEMIP_IP6_FORWARD_R_NO_ROUTE, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE,
                              (uint8_t)IDEMIP_ICMP6_DU_NO_ROUTE, icmp_ok);
        return;
    }

    // RFC 8200 sec 3: "When forwarding, the packet is discarded if Hop Limit was zero when received or
    // is decremented to zero." RFC 4443 sec 3.3 answers both with Time Exceeded Code 0, "Hop limit
    // exceeded in transit".
    uint8_t hop = idemip_ip6_hop_limit(h);
    if (hop <= 1u)
    {
        ip6_forward_drop_icmp(io, IDEMIP_IP6_FORWARD_R_HOP_LIMIT, (uint8_t)IDEMIP_ICMP6_TIME_EXCEEDED,
                              (uint8_t)IDEMIP_ICMP6_TE_HOP_LIMIT, icmp_ok);
        return;
    }
    io->hop_limit = (uint8_t)(hop - 1u);

    // RFC 8200 sec 4.5: "fragmentation in IPv6 is performed only by source nodes, not by routers along
    // a packet's delivery path", so an oversized packet is discarded rather than split. RFC 4443
    // sec 3.2 carries "The Maximum Transmission Unit of the next-hop link", and its own suppression
    // exception applies, so the allowance is taken again with the Packet Too Big flag raised.
    size_t total = (size_t)idemip_ip6_payload_len(h) + (size_t)IDEMIP_IPV6_HDR_LEN;
    if (total > (size_t)a->out_mtu)
    {
        ip6_forward_drop_icmp(io, IDEMIP_IP6_FORWARD_R_TOO_BIG, (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG,
                              (uint8_t)IDEMIP_ICMP6_CODE_PTB,
                              ip6_forward_icmp_allowed(h, a->len, a, IDEMIP_TRUE));
        io->mtu = (uint32_t)a->out_mtu;
        return;
    }

    // RFC 4861 sec 8.2's three conditions: "the Source Address field of the packet identifies a
    // neighbor", "a better first-hop node resides on the same link as the sending node", which is the
    // packet leaving the interface it arrived on, and "the Destination Address of the packet is not a
    // multicast address". The Target Address is the sec 8.2 "address to which subsequent packets for
    // the destination should be sent", which the route named.
    if (a->src_neighbor && !ip6_forward_crosses_link(a) && !ip6_forward_is_multicast(dst))
    {
        io->redirect = IDEMIP_TRUE;
        io->redirect_target = a->next_hop;
    }

    io->action = IDEMIP_IP6_FORWARD_SEND;
    io->reason = IDEMIP_IP6_FORWARD_R_OK;
    io->next_hop = a->next_hop;
    io->netif = a->out_netif;
    io->status = IDEMIP_OK;
}

const Ip6ForwardNs Ip6Forward = {.clear = ip6_forward_clear, .decide = ip6_forward_decide};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6
