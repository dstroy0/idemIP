// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file ip4_forward.c
 * @brief The RFC 1812 sec 5.2.1.2 checks, in the order that section prints them.
 *
 * The switch word is this file's. Every entry is a function of the one pointer it is handed: the
 * operand block and the context are both regions of that borrow, at compile-time offsets, and no
 * entry reads or writes a byte outside it, nor a byte of the datagram the operands point at.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ip/ip4_forward.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and every
// entry but clear refuses it.
#define IP4_FORWARD_READY 0x46574434u

// RFC 1812 sec 4.2.2.11: "Class D addresses are used for IP multicasting, while Class E addresses
// are reserved for experimental use." Both are the top four bits of the address.
#define IP4_FORWARD_CLASS_MASK 0xF0000000u
#define IP4_FORWARD_CLASS_D 0xE0000000u
#define IP4_FORWARD_CLASS_E 0xF0000000u

// RFC 1812 sec 4.2.2.11 (c): "{ -1, -1 } Limited broadcast."
#define IP4_FORWARD_LIMITED_BCAST 0xFFFFFFFFu

// RFC 3021 sec 2.1, a 31-bit subnet mask, where "the two addresses above MUST be interpreted as host
// addresses" and sec 2.2.1 makes a directed broadcast to the link impossible.
#define IP4_FORWARD_MASK_31 0xFFFFFFFEu

// RFC 3927 sec 2.1's "169.254/16 prefix", the IPv4 Link-Local block.
#define IP4_FORWARD_LINK_LOCAL_MASK 0xFFFF0000u
#define IP4_FORWARD_LINK_LOCAL_TAG 0xA9FE0000u

// The high octet, which sec 5.3.7 reads as the network of the two addresses it filters on: "a source
// address on network 0" and "a source address on network 127".
#define IP4_FORWARD_NET_SHIFT 24u
#define IP4_FORWARD_NET_ZERO 0u
#define IP4_FORWARD_NET_LOOPBACK 127u

// RFC 791 sec 3.1 option types. The type octet carries a copied flag, a two-bit class and a five-bit
// number, so Loose Source Routing is 128 + 3 and Strict Source Routing is 128 + 9.
#define IP4_FORWARD_OPT_EOOL 0u
#define IP4_FORWARD_OPT_NOP 1u
#define IP4_FORWARD_OPT_LSRR 131u
#define IP4_FORWARD_OPT_SSRR 137u
#define IP4_FORWARD_OPT_MIN_LEN 2u

// What the option walk found.
#define IP4_FORWARD_SR_LOOSE (1u << 0)
#define IP4_FORWARD_SR_STRICT (1u << 1)

// The context: the mark, and the sec 5.3.5.2 and sec 5.3.7 switches.
typedef struct
{
    uint32_t ready;
    uint8_t policy;
} Ip4ForwardCtx;

// The caller's borrow, split: the operand block, then the context. ip4_forward.h publishes the
// offsets; the assert proves the span covers them before anything runs.
static_assert(IDEMIP_IP4_FORWARD_OFF_CTX + sizeof(Ip4ForwardCtx) <= IDEMIP_IP4_FORWARD_BORROW,
              "IDEMIP_IP4_FORWARD_BORROW is short of the operand block and the context - raise "
              "IDEMIP_IP4_FORWARD_CTX_BYTES in idemip_config.h");

// The borrow abuts the next one the caller placed, so its length keeps that one's alignment.
static_assert((IDEMIP_IP4_FORWARD_BORROW & (IDEMIP_ALIGN - 1u)) == 0u,
              "IDEMIP_IP4_FORWARD_BORROW must be a multiple of IDEMIP_ALIGN");

// clear zeroes the context, so the reason a passing decision reports is the zero state.
static_assert(IDEMIP_IP4_FORWARD_R_OK == 0, "IDEMIP_IP4_FORWARD_R_OK must be zero: it is the reason of a clean pass");

// The regions, at their offsets in the caller's borrow.
#define IP4_FORWARD_IO(w) IDEMIP_IP4_FORWARD_IO(w)
#define IP4_FORWARD_CTX(w) ((Ip4ForwardCtx *)(void *)((w) + IDEMIP_IP4_FORWARD_OFF_CTX))

// A borrow clear has not run on carries no switches, so every entry but clear refuses it.
static idemip_bool ip4_forward_ready(uint8_t *restrict work)
{
    return (idemip_bool)(IP4_FORWARD_CTX(work)->ready == IP4_FORWARD_READY);
}

// --- the addresses ---------------------------------------------------------

// RFC 1812 sec 4.2.2.11: Class D, the top four bits 1110.
static idemip_bool ip4_forward_is_multicast(uint32_t a)
{
    return (idemip_bool)((a & IP4_FORWARD_CLASS_MASK) == IP4_FORWARD_CLASS_D);
}

// RFC 1812 sec 4.2.2.11: Class E, the top four bits 1111, which holds the limited broadcast too.
static idemip_bool ip4_forward_is_class_e(uint32_t a)
{
    return (idemip_bool)((a & IP4_FORWARD_CLASS_MASK) == IP4_FORWARD_CLASS_E);
}

// RFC 1812 sec 5.3.7: "An IP source address is invalid if it is a special IP address, as defined in
// 4.2.2.11 or 5.3.7, or is not a unicast address", and the same section adds "a source address on
// network 0" and "a source address on network 127". sec 4.2.2.11 (c) and (d) make both broadcast
// forms illegal sources, and (e) the { 127, <any> } loopback which "MUST NOT appear outside a host".
static idemip_bool ip4_forward_src_invalid(uint32_t a)
{
    uint32_t net = a >> IP4_FORWARD_NET_SHIFT;
    if (net == IP4_FORWARD_NET_ZERO || net == IP4_FORWARD_NET_LOOPBACK)
    {
        return IDEMIP_TRUE;
    }
    return (idemip_bool)(ip4_forward_is_multicast(a) || ip4_forward_is_class_e(a));
}

// RFC 1812 sec 5.3.7: "An IP destination address is invalid if it is among those defined as illegal
// destinations in 4.2.3.1, or is a Class E address (except 255.255.255.255)", plus that section's own
// "a destination address on network 0" and "a destination address on network 127". sec 4.2.3.1 (2)
// makes 0.0.0.0 the obsolete limited broadcast, which network 0 covers.
static idemip_bool ip4_forward_dst_invalid(uint32_t a)
{
    uint32_t net = a >> IP4_FORWARD_NET_SHIFT;
    if (net == IP4_FORWARD_NET_ZERO || net == IP4_FORWARD_NET_LOOPBACK)
    {
        return IDEMIP_TRUE;
    }
    if (a == IP4_FORWARD_LIMITED_BCAST)
    {
        return IDEMIP_FALSE;
    }
    return ip4_forward_is_class_e(a);
}

// RFC 1812 sec 5.3.5: "A network-prefix-directed broadcast is composed of the network prefix of the
// IP address with a local part of all-ones or { <Network-prefix>, -1 }", and the same section on the
// obsolete form: "{ <Network-prefix>, 0 } is an obsolete form of a network-prefix-directed broadcast
// address ... packets addressed to any of these addresses SHOULD be silently discarded, but if they
// are not, they MUST be treated according to the same rules that apply to packets addressed to the
// non-obsolete forms". sec 5.3.5.2 puts the classification on "the router's understanding (if any) of
// the subnet structure of the destination network", which is the outgoing interface's mask, and only
// on the last hop, which is a route that transmits directly. RFC 3021 sec 2.2.1 says a directed
// broadcast to a 31-bit prefix "is not possible", both of its addresses being host addresses.
static idemip_bool ip4_forward_dst_is_bcast(const Ip4ForwardArgs *a, uint32_t dst)
{
    if (a->out_mask == 0u || a->out_mask == IP4_FORWARD_LIMITED_BCAST || a->out_mask == IP4_FORWARD_MASK_31)
    {
        return IDEMIP_FALSE;
    }
    if ((dst & a->out_mask) != (a->out_addr & a->out_mask))
    {
        return IDEMIP_FALSE;
    }
    return (idemip_bool)((dst | a->out_mask) == IP4_FORWARD_LIMITED_BCAST || (dst & ~a->out_mask) == 0u);
}

// The same classification under sec 5.3.5.2's own condition: the switch it requires applies "only in
// the last hop router", which is a route that transmits directly. sec 4.2.3.1 (1)'s "MUST treat as IP
// broadcasts" carries no such condition, so sec 4.3.2.7's ICMP suppression reads the helper above.
static idemip_bool ip4_forward_is_directed_bcast(const Ip4ForwardArgs *a, uint32_t dst)
{
    if (!a->routed || !a->direct)
    {
        return IDEMIP_FALSE;
    }
    return ip4_forward_dst_is_bcast(a, dst);
}

// RFC 3927 sec 7: "A router MUST NOT forward a packet with an IPv4 Link-Local source or destination
// address, irrespective of the router's default route configuration or routes obtained from dynamic
// routing protocols", and sec 2.7 repeats it "regardless of the TTL in the IPv4 header". RFC 6890
// Table 5 records 169.254.0.0/16 as "Forwardable | False". "Irrespective of ... configuration" puts
// this outside the sec 5.3.7 martian switch, which a set_policy can lower.
static idemip_bool ip4_forward_is_link_local(uint32_t a)
{
    return (idemip_bool)((a & IP4_FORWARD_LINK_LOCAL_MASK) == IP4_FORWARD_LINK_LOCAL_TAG);
}

// RFC 1812 sec 4.2.2.11 (d), of { <Network-prefix>, -1 }: "It MUST NOT be used as a source address",
// and sec 4.2.2.11 closes "A router MUST silently discard any received datagram containing an IP
// source address that is invalid by the rules of this section". The prefix the receiving interface
// holds is the one the router understands, the same way sec 5.3.5.2 reads the outgoing one. RFC 3021
// sec 3.1 rewrites RFC 1122 sec 3.2.1.3 (e) to permit the all-ones host part as a source "when the
// originator is one of the endpoints of a point-to-point link with a 31-bit mask".
static idemip_bool ip4_forward_src_is_bcast(const Ip4ForwardArgs *a, uint32_t src)
{
    if (a->in_mask == 0u || a->in_mask == IP4_FORWARD_LIMITED_BCAST || a->in_mask == IP4_FORWARD_MASK_31)
    {
        return IDEMIP_FALSE;
    }
    if ((src & a->in_mask) != (a->in_addr & a->in_mask))
    {
        return IDEMIP_FALSE;
    }
    return (idemip_bool)((src | a->in_mask) == IP4_FORWARD_LIMITED_BCAST || (src & ~a->in_mask) == 0u);
}

// --- the options -----------------------------------------------------------

// RFC 791 sec 3.1 option area: type 0 "indicates the end of the option list", type 1 "occupies only
// 1 octet" with no length, and every other option's second octet "is the option length which includes
// the option type code and the length octet". The walk stops on a length that runs past the header,
// which is the malformed area rather than an option.
static uint8_t ip4_forward_source_route(const uint8_t *h)
{
    const uint8_t *o = idemip_ip4_options(h);
    size_t n = idemip_ip4_options_len(h);
    size_t i = 0;
    uint8_t found = 0;
    while (i < n)
    {
        uint8_t type = o[i];
        if (type == IP4_FORWARD_OPT_EOOL)
        {
            break;
        }
        if (type == IP4_FORWARD_OPT_NOP)
        {
            i++;
            continue;
        }
        if (i + 1u >= n)
        {
            break;
        }
        size_t olen = (size_t)o[i + 1u];
        if (olen < IP4_FORWARD_OPT_MIN_LEN || i + olen > n)
        {
            break;
        }
        if (type == IP4_FORWARD_OPT_LSRR)
        {
            found = (uint8_t)(found | IP4_FORWARD_SR_LOOSE);
        }
        if (type == IP4_FORWARD_OPT_SSRR)
        {
            found = (uint8_t)(found | IP4_FORWARD_SR_STRICT);
        }
        i += olen;
    }
    return found;
}

// --- when an ICMP error may be sent ----------------------------------------

// RFC 1122 sec 3.2.2 splits RFC 792's types into errors and queries; the errors are Destination
// Unreachable, Source Quench, Redirect, Time Exceeded and Parameter Problem.
static idemip_bool ip4_forward_is_icmp_error(uint8_t type)
{
    return (idemip_bool)(type == (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE || type == (uint8_t)IDEMIP_ICMP_SOURCE_QUENCH ||
                         type == (uint8_t)IDEMIP_ICMP_REDIRECT || type == (uint8_t)IDEMIP_ICMP_TIME_EXCEEDED ||
                         type == (uint8_t)IDEMIP_ICMP_PARAMETER_PROBLEM);
}

// The datagram carries an RFC 792 error message: protocol 1, offset zero so the Type octet is in this
// fragment, and at least one octet of payload to read it from.
static idemip_bool ip4_forward_carries_icmp_error(const uint8_t *h)
{
    if (idemip_ip4_proto(h) != (uint8_t)IDEMIP_IP4_PROTO_ICMP || idemip_ip4_frag_units(h) != 0u)
    {
        return IDEMIP_FALSE;
    }
    size_t hdr = idemip_ip4_hdr_len(h);
    if ((size_t)idemip_ip4_total_len(h) <= hdr)
    {
        return IDEMIP_FALSE;
    }
    return ip4_forward_is_icmp_error(h[hdr + IDEMIP_ICMP_OFF_TYPE]);
}

// RFC 1812 sec 4.3.2.7, the whole list, whose note reads "THESE RESTRICTIONS TAKE PRECEDENCE OVER ANY
// REQUIREMENT ELSEWHERE IN THIS DOCUMENT FOR SENDING ICMP ERROR MESSAGES". The header validation
// bullet is answered by the caller of this helper, which only runs on a header sec 5.2.2 passed.
static idemip_bool ip4_forward_icmp_allowed(const uint8_t *h, const Ip4ForwardArgs *a)
{
    uint32_t src = idemip_ip4_src(h);
    uint32_t dst = idemip_ip4_dst(h);
    if (a->ll_broadcast || a->ll_multicast)
    {
        return IDEMIP_FALSE; // "A packet sent as a Link Layer broadcast or multicast"
    }
    // sec 4.2.3.1 (1): a router "MUST treat as IP broadcasts packets addressed to 255.255.255.255 or
    // { <Network-prefix>, -1 }", which the router understands whenever it holds the prefix, whether or
    // not this is the last hop.
    if (dst == IP4_FORWARD_LIMITED_BCAST || ip4_forward_dst_is_bcast(a, dst) || ip4_forward_is_multicast(dst))
    {
        return IDEMIP_FALSE; // "A packet destined to an IP broadcast or IP multicast address"
    }
    if (ip4_forward_src_invalid(src) || ip4_forward_src_is_bcast(a, src))
    {
        return IDEMIP_FALSE; // "a network prefix of zero or is an invalid source address"
    }
    if (idemip_ip4_frag_units(h) != 0u)
    {
        return IDEMIP_FALSE; // "Any fragment of a datagram other then the first fragment"
    }
    return (idemip_bool)!ip4_forward_carries_icmp_error(h); // "An ICMP error message"
}

// --- the decision ----------------------------------------------------------

// Every result member, back to the state a decision that reached no rule leaves.
static void ip4_forward_reset(Ip4ForwardIo *io)
{
    io->next_hop = 0;
    io->redirect_gw = 0;
    io->mtu = 0;
    io->action = IDEMIP_IP4_FORWARD_DISCARD;
    io->reason = IDEMIP_IP4_FORWARD_R_OK;
    io->ttl = 0;
    io->netif = 0;
    io->icmp_type = IDEMIP_IP4_FORWARD_ICMP_NONE;
    io->icmp_code = 0;
    io->icmp_ptr = 0;
    io->icmp = IDEMIP_FALSE;
    io->fragment = IDEMIP_FALSE;
    io->redirect = IDEMIP_FALSE;
}

// A discard the RFC names, with no message owed.
static void ip4_forward_drop(Ip4ForwardIo *io, IdemIpIp4ForwardReason reason)
{
    io->action = IDEMIP_IP4_FORWARD_DISCARD;
    io->reason = reason;
    io->status = IDEMIP_OK;
}

// A discard with a message owed, subject to the sec 4.3.2.7 list.
static void ip4_forward_drop_icmp(Ip4ForwardIo *io, IdemIpIp4ForwardReason reason, uint8_t type, uint8_t code,
                                  idemip_bool allowed)
{
    ip4_forward_drop(io, reason);
    if (allowed)
    {
        io->icmp = IDEMIP_TRUE;
        io->icmp_type = type;
        io->icmp_code = code;
    }
}

// --- the entries -----------------------------------------------------------

// The context, zeroed, then the mark and the two switches RFC 1812 defaults on: sec 5.3.7's address
// checks and sec 5.3.5.2's directed broadcast forwarding. The operand block is the caller's and is
// left as it stands.
void idemip_ip4_forward_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_IP4_FORWARD_OFF_CTX, 0,
           (size_t)IDEMIP_IP4_FORWARD_BORROW - (size_t)IDEMIP_IP4_FORWARD_OFF_CTX);
    Ip4ForwardCtx *ctx = IP4_FORWARD_CTX(work);
    ctx->ready = IP4_FORWARD_READY;
    ctx->policy = IDEMIP_IP4_FORWARD_P_MASK;
    IP4_FORWARD_IO(work)->policy = ctx->policy;
    IP4_FORWARD_IO(work)->status = IDEMIP_OK;
}

// The switches raised, then the switches lowered. A bit outside IDEMIP_IP4_FORWARD_P_MASK is ERR: it
// names no switch, so no later call gives it one.
void idemip_ip4_forward_set_policy(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4ForwardIo *io = IP4_FORWARD_IO(work);
    io->status = IDEMIP_ERR;
    if (!ip4_forward_ready(work))
    {
        return;
    }
    if (((io->policy_args.set | io->policy_args.clear) & (uint8_t)~IDEMIP_IP4_FORWARD_P_MASK) != 0u)
    {
        return;
    }
    Ip4ForwardCtx *ctx = IP4_FORWARD_CTX(work);
    ctx->policy = (uint8_t)((ctx->policy | io->policy_args.set) & (uint8_t)~io->policy_args.clear);
    io->policy = ctx->policy;
    io->status = IDEMIP_OK;
}

// RFC 1812 sec 5.2.1.2 steps (6), (7), (9) and (12) over one datagram, in that order. sec 5.2.1 fixes
// the order: (1) validate the header first, (3) the TTL check comes after the local delivery decision
// the caller already made, and (9) fragmentation comes after the outbound interface is chosen.
//
// A datagram the RFC discards is a decision that succeeded, so the status is OK and the action is
// DISCARD. ERR is the operands: no datagram, a borrow clear has not run on, an interface index past
// IDEMIP_NETIF_COUNT, or an outgoing MTU under the 68 octets RFC 791 sec 3.2 requires every internet
// module to forward. Nothing here is BUSY: the same operands decide the same way forever, so a retry
// can never change the answer.
void idemip_ip4_forward_decide(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Ip4ForwardIo *io = IP4_FORWARD_IO(work);
    io->status = IDEMIP_ERR;
    ip4_forward_reset(io);
    if (!ip4_forward_ready(work))
    {
        return;
    }
    io->policy = IP4_FORWARD_CTX(work)->policy;
    const Ip4ForwardArgs *a = &io->fwd_args;
    const uint8_t *h = a->hdr;
    if (h == NULL || a->in_netif >= (uint8_t)IDEMIP_NETIF_COUNT)
    {
        return;
    }
    if (a->routed && (a->out_netif >= (uint8_t)IDEMIP_NETIF_COUNT || a->out_mtu < IDEMIP_IP4_MIN_FORWARD_MTU))
    {
        return;
    }

    // sec 5.2.1 (1): "A router MUST verify the IP header ... before performing any actions based on
    // the contents of the header." sec 5.2.2: a header that fails "MUST be silently discarded", and
    // sec 4.3.2.7 forbids an ICMP error in answer to it.
    if (idemip_ip4_verify(h, a->len) != IDEMIP_OK)
    {
        ip4_forward_drop(io, IDEMIP_IP4_FORWARD_R_HEADER);
        return;
    }

    uint32_t src = idemip_ip4_src(h);
    uint32_t dst = idemip_ip4_dst(h);
    idemip_bool directed = ip4_forward_is_directed_bcast(a, dst);
    idemip_bool icmp_ok = ip4_forward_icmp_allowed(h, a);
    uint8_t policy = io->policy;

    // sec 5.3.4: "A router MUST NOT forward any packet that the router received as a Link Layer
    // broadcast, unless it is directed to an IP Multicast address", and the same for a link-layer
    // multicast.
    if ((a->ll_broadcast || a->ll_multicast) && !ip4_forward_is_multicast(dst))
    {
        ip4_forward_drop(io, IDEMIP_IP4_FORWARD_R_LINK_BCAST);
        return;
    }

    // RFC 3927 sec 7: "A router MUST NOT forward a packet with an IPv4 Link-Local source or
    // destination address, irrespective of the router's default route configuration or routes
    // obtained from dynamic routing protocols." "Irrespective of" puts it ahead of the sec 5.3.7
    // switch, which a set_policy can lower.
    if (ip4_forward_is_link_local(src) || ip4_forward_is_link_local(dst))
    {
        ip4_forward_drop(io, IDEMIP_IP4_FORWARD_R_LINK_LOCAL);
        return;
    }

    // sec 4.2.2.11: "A router MUST silently discard any received datagram containing an IP source
    // address that is invalid by the rules of this section", (d) naming { <Network-prefix>, -1 }.
    // sec 4.3.2.7's precedence note already suppressed the ICMP error for it.
    if (ip4_forward_src_is_bcast(a, src))
    {
        ip4_forward_drop(io, IDEMIP_IP4_FORWARD_R_SRC_BCAST);
        return;
    }

    // sec 5.3.7, under the switch that section requires to default on.
    if ((policy & (uint8_t)IDEMIP_IP4_FORWARD_P_MARTIAN) != 0u)
    {
        if (ip4_forward_src_invalid(src))
        {
            ip4_forward_drop(io, IDEMIP_IP4_FORWARD_R_SRC);
            return;
        }
        if (ip4_forward_dst_invalid(dst))
        {
            ip4_forward_drop(io, IDEMIP_IP4_FORWARD_R_DST);
            return;
        }
    }

    // sec 5.3.5.1: "Limited broadcasts MUST NOT be forwarded. Limited broadcasts MUST NOT be
    // discarded", the second half being the caller's local delivery, which this decision does not
    // touch.
    if (dst == IP4_FORWARD_LIMITED_BCAST)
    {
        ip4_forward_drop(io, IDEMIP_IP4_FORWARD_R_LIMITED);
        return;
    }

    // sec 5.3.5.2: a network-prefix-directed broadcast is forwarded "given a route and no overriding
    // policy", the policy being the switch that section requires.
    if (directed && (policy & (uint8_t)IDEMIP_IP4_FORWARD_P_DIRECTED) == 0u)
    {
        ip4_forward_drop(io, IDEMIP_IP4_FORWARD_R_DIRECTED);
        return;
    }

    // sec 5.2.2 last paragraph: a destination that "is not one of the addresses of the router"
    // carrying a strict source route option is discarded, and the router "SHOULD respond with an ICMP
    // Parameter Problem error with the pointer pointing at the offending packet's IP destination
    // address".
    uint8_t source_route = ip4_forward_source_route(h);
    if ((source_route & IP4_FORWARD_SR_STRICT) != 0u)
    {
        ip4_forward_drop_icmp(io, IDEMIP_IP4_FORWARD_R_STRICT, (uint8_t)IDEMIP_ICMP_PARAMETER_PROBLEM,
                              (uint8_t)IDEMIP_ICMP_PP_POINTER, icmp_ok);
        io->icmp_ptr = (uint8_t)IDEMIP_IP4_OFF_DST;
        return;
    }

    // sec 4.3.3.1: "If a router cannot forward a packet because it has no routes at all (including no
    // default route) to the destination specified in the packet, then the router MUST generate a
    // Destination Unreachable, Code 0 (Network Unreachable) ICMP message." Code 1 Host Unreachable is
    // the same section's answer once "the router has ascertained that there is no path to the
    // destination host", which is the resolution layer's finding rather than the table's.
    if (!a->routed)
    {
        // "If the router does have routes to the destination network specified in the packet but the
        // TOS specified for the routes is neither the default TOS (0000) nor the TOS of the packet
        // that the router is attempting to route, then the router MUST generate a Destination
        // Unreachable, Code 11 (Network Unreachable for TOS) ICMP message", and Code 12 when the
        // destination is "on a network that is directly connected to the router".
        uint8_t code = (uint8_t)IDEMIP_ICMP_DU_NET;
        IdemIpIp4ForwardReason why = IDEMIP_IP4_FORWARD_R_NO_ROUTE;
        if (a->tos_blocked)
        {
            code = a->direct ? (uint8_t)IDEMIP_ICMP_DU_HOST_TOS : (uint8_t)IDEMIP_ICMP_DU_NET_TOS;
            why = IDEMIP_IP4_FORWARD_R_NO_ROUTE_TOS;
        }
        ip4_forward_drop_icmp(io, why, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, code, icmp_ok);
        return;
    }

    // sec 5.3.1: "Each router (or other module) that handles a packet MUST decrement the TTL by at
    // least one", and "If the TTL is reduced to zero (or less), the packet MUST be discarded, and if
    // the destination is not a multicast address the router MUST send an ICMP Time Exceeded message,
    // Code 0". A Time to Live of one reduces to zero and one of zero reduces below it, so both
    // discard. The same section's "If it holds a packet for more than one second, it MAY decrement the
    // TTL by one for each second" is a MAY this unit does not take: one hop is one decrement.
    uint8_t ttl = idemip_ip4_ttl(h);
    if (ttl <= 1u)
    {
        ip4_forward_drop_icmp(io, IDEMIP_IP4_FORWARD_R_TTL, (uint8_t)IDEMIP_ICMP_TIME_EXCEEDED,
                              (uint8_t)IDEMIP_ICMP_TE_TTL, icmp_ok);
        return;
    }
    io->ttl = (uint8_t)(ttl - 1u);

    // sec 5.2.1.2 step (9): "The forwarder performs any necessary IP fragmentation". RFC 791 sec 3.1
    // Don't Fragment: "If the DF bit is set, the fragmentation of this datagram is not permitted", so
    // an oversized datagram carrying it is discarded and RFC 1191 sec 4 answers Destination
    // Unreachable Code 4 carrying "the MTU of that next-hop network".
    if ((size_t)idemip_ip4_total_len(h) > (size_t)a->out_mtu)
    {
        if (idemip_ip4_df(h))
        {
            ip4_forward_drop_icmp(io, IDEMIP_IP4_FORWARD_R_DF, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE,
                                  (uint8_t)IDEMIP_ICMP_DU_FRAG_NEEDED, icmp_ok);
            io->mtu = a->out_mtu;
            return;
        }
        io->fragment = IDEMIP_TRUE;
    }

    // sec 5.2.1.2 step (12), under sec 5.2.7.2's three conditions: "The packet is being forwarded out
    // the same physical interface that it was received from", "The IP source address in the packet is
    // on the same Logical IP (sub)network as the next-hop IP address", and "The packet does not
    // contain an IP source route option". The same section: "Routers MUST NOT generate the Redirect
    // for Network ... messages (Codes 0 and 2)", so the code is 1, Redirect for Host.
    if (a->out_netif == a->in_netif && a->in_mask != 0u && source_route == 0u && icmp_ok &&
        (src & a->in_mask) == (a->next_hop & a->in_mask))
    {
        io->redirect = IDEMIP_TRUE;
        io->redirect_gw = a->next_hop;
    }

    io->action = IDEMIP_IP4_FORWARD_SEND;
    io->reason = IDEMIP_IP4_FORWARD_R_OK;
    io->next_hop = a->next_hop;
    io->netif = a->out_netif;
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
