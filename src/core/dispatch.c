// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dispatch.c
 * @brief One frame, walked the five steps of RFC 1122 sec 3.1, to the pcb that owns it.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block, the context, the per-interface rows and the per-connection rows are all regions of that
 * borrow at compile-time offsets. The borrows this path calls into are addresses the context carries
 * and are not held past the call that uses them.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/core/dispatch.h"

#include "src/ip/pseudo.h"

#if IDEMIP_ENABLE_IPV4
#include "src/arp/arp.h"
#include "src/ip/ipv4.h"
#endif
#if IDEMIP_ENABLE_IPV6
#include "src/ip/ipv6.h"
#endif
#if IDEMIP_ENABLE_UDP
#include "src/udp/udp.h"
#endif
#if IDEMIP_ENABLE_TCP
#include "src/tcp/tcp.h"
#endif

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. The bound borrows are copied out of the operand block, so a
// later call does not read an operand some other caller overwrote.
typedef struct
{
    uint8_t *stats;
    uint8_t *netif;
    uint8_t *loopif;
    uint8_t *vlan;
#if IDEMIP_ENABLE_IPV4
    uint8_t *arp;
    uint8_t *ip4_addr;
    uint8_t *ip4_reass;
    uint8_t *icmp_in;
    uint8_t *igmp;
#endif
#if IDEMIP_ENABLE_IPV6
    uint8_t *ip6_addr;
    uint8_t *ip6_reass;
    uint8_t *icmp6_in;
    uint8_t *mld6;
#endif
#if IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6
    uint8_t *raw_pcb;
#endif
#if IDEMIP_ENABLE_UDP
    uint8_t *udp_pcb;
    uint8_t *udplite;
#endif
#if IDEMIP_ENABLE_TCP
    uint8_t *tcp_pcb;
    uint8_t *tcp_in;
    uint16_t hold_desc; ///< the descriptor a re-delivery reported, unpinned on the call after
    uint8_t hold_netif;
    uint8_t ack_cursor;
#endif
    uint32_t ready;
} DispatchCtx;

// The mark clear leaves.
#define DISPATCH_READY 0x44535043u

// One interface's row: its ring pair, its IEEE 802.1Q membership, and the Gauge holding the last
// VLAN ID a policy drop discarded.
typedef struct
{
    uint8_t *dma;
    uint16_t vid;
    uint16_t last_vid;
    uint8_t tagged;
    uint8_t pad[(1u << IDEMIP_DISPATCH_IF_ENTRY_SHIFT) - (sizeof(uint8_t *) + (2u * 2u) + 1u)];
} DispatchIfRow;

static_assert(sizeof(DispatchIfRow) == (1u << IDEMIP_DISPATCH_IF_ENTRY_SHIFT),
              "a DispatchIfRow is not 1 << IDEMIP_DISPATCH_IF_ENTRY_SHIFT octets wide - raise the shift in "
              "idemip_config.h");

// One connection's row: the RFC 9293 sec 3.10.7.4 MUST-58 aggregation bit, and the interface the
// segments held for it were pinned on, which is what an unpin has to be routed through.
typedef struct
{
    uint8_t ack_owed;
    uint8_t netif;
    uint8_t pad[(1u << IDEMIP_DISPATCH_PCB_ENTRY_SHIFT) - 2u];
} DispatchPcbRow;

static_assert(sizeof(DispatchPcbRow) == (1u << IDEMIP_DISPATCH_PCB_ENTRY_SHIFT),
              "a DispatchPcbRow is not 1 << IDEMIP_DISPATCH_PCB_ENTRY_SHIFT octets wide - raise the shift in "
              "idemip_config.h");

// The caller's borrow, split: the operand block, the context, then the two tables. dispatch.h
// publishes the offsets; the asserts below prove the span covers them before anything runs.
static_assert(IDEMIP_DISPATCH_OFF_CTX + sizeof(DispatchCtx) <= IDEMIP_DISPATCH_CTX_BYTES,
              "IDEMIP_DISPATCH_CTX_BYTES is short of the operand block and the context - raise it in "
              "idemip_config.h");
static_assert(IDEMIP_DISPATCH_OFF_END <= IDEMIP_DISPATCH_BORROW,
              "IDEMIP_DISPATCH_BORROW is short of the borrow map - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define D_IO(w) IDEMIP_DISPATCH_IO(w)
#define D_CTX(w) ((DispatchCtx *)(void *)((w) + IDEMIP_DISPATCH_OFF_CTX))
#define D_IF_AT(w, i)                                                                                                  \
    ((DispatchIfRow *)(void *)((w) + IDEMIP_DISPATCH_OFF_IF + ((size_t)(i) << IDEMIP_DISPATCH_IF_ENTRY_SHIFT)))
#define D_PCB_AT(w, i)                                                                                                 \
    ((DispatchPcbRow *)(void *)((w) + IDEMIP_DISPATCH_OFF_PCB + ((size_t)(i) << IDEMIP_DISPATCH_PCB_ENTRY_SHIFT)))

static idemip_bool d_ready(uint8_t *restrict work)
{
    return (idemip_bool)(D_CTX(work)->ready == DISPATCH_READY);
}

// --- the counters ----------------------------------------------------------
// RFC 1213 sec 6.4 and sec 6.6. A build with no counter set bound still dispatches; the count is
// simply not kept.

static void d_bump(uint8_t *restrict work, IdemIpStatsCounter id)
{
    DispatchCtx *ctx = D_CTX(work);
    if (ctx->stats == NULL)
    {
        return;
    }
    IDEMIP_STATS_IO(ctx->stats)->ctr_args.id = id;
    IDEMIP_STATS_IO(ctx->stats)->ctr_args.value = 1u;
    Stats.bump(ctx->stats);
}

static void d_if_bump(uint8_t *restrict work, uint8_t netif, IdemIpStatsIfCounter id, uint32_t value)
{
    DispatchCtx *ctx = D_CTX(work);
    if (ctx->stats == NULL || netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    IDEMIP_STATS_IO(ctx->stats)->if_args.netif = netif;
    IDEMIP_STATS_IO(ctx->stats)->if_args.id = id;
    IDEMIP_STATS_IO(ctx->stats)->if_args.value = value;
    Stats.if_bump(ctx->stats);
}

// The frame goes no further. IDEMIP_STAT_IF_COUNT names no counter, so a reason that is the caller's
// own configuration fault bumps none.
static void d_drop(uint8_t *restrict work, IdemIpDispatchDrop why, IdemIpStatsIfCounter if_ctr)
{
    DispatchIo *io = D_IO(work);
    io->drop = why;
    io->act |= IDEMIP_DISPATCH_ACT_DROP;
    if (if_ctr != IDEMIP_STAT_IF_COUNT)
    {
        d_if_bump(work, io->netif, if_ctr, 1u);
    }
}

// RFC 2011 gives one counter per ICMP Type it names, so a well-formed message is counted by its Type
// as well as by icmpInMsgs. A Type with no counter of its own - RFC 792's Information Request pair,
// and every unassigned value - is counted only in icmpInMsgs. RFC 950's Address Mask pair is not a
// type this library carries, RFC 1122 sec 3.2.2.9 leaving it optional, so those two counters have no
// Type to reach them.
#if IDEMIP_ENABLE_IPV4
static void d_icmp4_type_bump(uint8_t *restrict work, uint8_t type)
{
    switch (type)
    {
    case IDEMIP_ICMP_ECHO_REPLY:
        d_bump(work, IDEMIP_STAT_ICMP4_IN_ECHO_REPS);
        return;
    case IDEMIP_ICMP_DEST_UNREACHABLE:
        d_bump(work, IDEMIP_STAT_ICMP4_IN_DEST_UNREACHS);
        return;
    case IDEMIP_ICMP_SOURCE_QUENCH:
        d_bump(work, IDEMIP_STAT_ICMP4_IN_SRC_QUENCHS);
        return;
    case IDEMIP_ICMP_REDIRECT:
        d_bump(work, IDEMIP_STAT_ICMP4_IN_REDIRECTS);
        return;
    case IDEMIP_ICMP_ECHO:
        d_bump(work, IDEMIP_STAT_ICMP4_IN_ECHOS);
        return;
    case IDEMIP_ICMP_TIME_EXCEEDED:
        d_bump(work, IDEMIP_STAT_ICMP4_IN_TIME_EXCDS);
        return;
    case IDEMIP_ICMP_PARAMETER_PROBLEM:
        d_bump(work, IDEMIP_STAT_ICMP4_IN_PARM_PROBS);
        return;
    case IDEMIP_ICMP_TIMESTAMP:
        d_bump(work, IDEMIP_STAT_ICMP4_IN_TIMESTAMPS);
        return;
    case IDEMIP_ICMP_TIMESTAMP_REPLY:
        d_bump(work, IDEMIP_STAT_ICMP4_IN_TIMESTAMP_REPS);
        return;
    default:
        return;
    }
}
#endif

#if IDEMIP_ENABLE_IPV6
// The same table over RFC 4443's Types. It defines no Source Quench, Timestamp or Address Mask, so
// those counters have no ICMPv6 Type to reach them, and Packet Too Big and the RFC 4861 Neighbor
// Discovery messages have no counter of their own and are counted only in icmpInMsgs.
static void d_icmp6_type_bump(uint8_t *restrict work, uint8_t type)
{
    switch (type)
    {
    case IDEMIP_ICMP6_DEST_UNREACHABLE:
        d_bump(work, IDEMIP_STAT_ICMP6_IN_DEST_UNREACHS);
        return;
    case IDEMIP_ICMP6_TIME_EXCEEDED:
        d_bump(work, IDEMIP_STAT_ICMP6_IN_TIME_EXCDS);
        return;
    case IDEMIP_ICMP6_PARAMETER_PROBLEM:
        d_bump(work, IDEMIP_STAT_ICMP6_IN_PARM_PROBS);
        return;
    case IDEMIP_ICMP6_ECHO_REQUEST:
        d_bump(work, IDEMIP_STAT_ICMP6_IN_ECHOS);
        return;
    case IDEMIP_ICMP6_ECHO_REPLY:
        d_bump(work, IDEMIP_STAT_ICMP6_IN_ECHO_REPS);
        return;
    default:
        return;
    }
}
#endif

// RFC 1213 sec 6.4 counts a delivery and not an arrival: ifInUcastPkts is "the number of
// subnetwork-unicast packets delivered to a higher-layer protocol", ifInNUcastPkts the non-unicast
// ones. The subnetwork address decides which, so the Ethernet Destination Address is read: the low
// bit of its first octet is the group bit every multicast and the RFC 894 broadcast carry.
static void d_delivered(uint8_t *restrict work, const uint8_t *frame)
{
    DispatchIo *io = D_IO(work);
    const uint8_t *dst = idemip_eth_dst(frame);
    idemip_bool group = (idemip_bool)((dst[0] & 1u) != 0u);
    d_if_bump(work, io->netif, group ? IDEMIP_STAT_IF_IN_NUCAST_PKTS : IDEMIP_STAT_IF_IN_UCAST_PKTS, 1u);
}

// --- the pin protocol ------------------------------------------------------
// A unit that holds a frame past dispatch keeps the receive buffer out of the engine's hands, so the
// descriptor is pinned before the unit is handed it and unpinned when the unit gives it back.

// True when the frame may be held past this call. An interface with no ring bound here has none this
// module can reach, so the descriptor is the caller's own token: it is recorded and reported and
// nothing is pinned, the caller keeping it out of whatever holds it. A frame in no descriptor at all
// cannot be held either way.
static idemip_bool d_pin(uint8_t *restrict work, uint8_t netif, uint16_t desc)
{
    if (netif >= IDEMIP_NETIF_COUNT || desc == IDEMIP_DISPATCH_DESC_NONE)
    {
        return IDEMIP_FALSE;
    }
    DispatchIfRow *row = D_IF_AT(work, netif);
    if (row->dma == NULL)
    {
        return IDEMIP_TRUE;
    }
    IDEMIP_DMA_IO(row->dma)->desc_args.index = (uint8_t)desc;
    Dma.pin(row->dma);
    return (idemip_bool)(IDEMIP_DMA_IO(row->dma)->status == IDEMIP_OK);
}

static void d_unpin(uint8_t *restrict work, uint8_t netif, uint16_t desc)
{
    if (netif >= IDEMIP_NETIF_COUNT || desc == IDEMIP_DISPATCH_DESC_NONE)
    {
        return;
    }
    DispatchIfRow *row = D_IF_AT(work, netif);
    if (row->dma == NULL)
    {
        return;
    }
    IDEMIP_DMA_IO(row->dma)->desc_args.index = (uint8_t)desc;
    Dma.unpin(row->dma);
}

// --- the interface record --------------------------------------------------

// Reads one interface's own record into the netif operand block, which stays there until the next
// netif call. False when no interface table is bound or the index names none.
static idemip_bool d_netif_get(uint8_t *restrict work, uint8_t index)
{
    DispatchCtx *ctx = D_CTX(work);
    if (ctx->netif == NULL)
    {
        return IDEMIP_FALSE;
    }
    IDEMIP_NETIF_IO(ctx->netif)->if_args.index = index;
    Netif.get(ctx->netif);
    return (idemip_bool)(IDEMIP_NETIF_IO(ctx->netif)->status == IDEMIP_OK);
}

// --- the result ------------------------------------------------------------

static void d_reset(DispatchIo *io)
{
    io->act = 0u;
    io->drop = IDEMIP_DISPATCH_DROP_NONE;
    io->pcb_kind = IDEMIP_DISPATCH_PCB_NONE;
    io->pcb = 0u;
    io->type = 0u;
    io->vid = IDEMIP_DISPATCH_VID_NONE;
    io->last_vid = IDEMIP_DISPATCH_VID_NONE;
    io->pcp = 0u;
    io->tagged = IDEMIP_FALSE;
    io->ip_off = 0u;
    io->payload_off = 0u;
    io->payload_len = 0u;
    io->out_len = 0u;
    io->ip_version = 0u;
    io->proto = 0u;
    io->datagram = 0u;
    io->netif = IDEMIP_DISPATCH_NETIF_NONE;
    io->desc = IDEMIP_DISPATCH_DESC_NONE;
    io->err_ptr = 0u;
#if IDEMIP_ENABLE_TCP
    io->tcp_act = 0u;
    io->text_seq = 0u;
    io->acked = 0u;
    io->text_off = 0u;
    io->text_len = 0u;
    io->reply.seq = 0u;
    io->reply.ack = 0u;
    io->reply.flags = 0u;
#endif
}

// ===========================================================================
// The transports, which are the same call whichever IP version carried them
// ===========================================================================

#if IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6

// Which counter group the version's own counters live in. RFC 1213 sec 6.6 defines the IP group for
// IP version 4; stats.h carries the same field set once for each version.
static IdemIpStatsCounter d_ip_ctr(uint8_t ip_version, IdemIpStatsCounter v4, IdemIpStatsCounter v6)
{
    return (ip_version == 6u) ? v6 : v4;
}

// RFC 1122 sec 3.2's raw interface, which binds a protocol number rather than a port, so it is asked
// for every protocol no built-in module claimed.
static void d_raw(uint8_t *restrict work, const uint8_t *local_ip, const uint8_t *remote_ip, uint8_t ip_version)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);

    if (ctx->raw_pcb != NULL)
    {
        RawPcbIo *rp = IDEMIP_RAW_PCB_IO(ctx->raw_pcb);
        rp->find_args.local_ip = local_ip;
        rp->find_args.remote_ip = remote_ip;
        rp->find_args.proto = io->proto;
        rp->find_args.ip_version = ip_version;
        rp->find_args.local_zone = 0u;
        rp->find_args.remote_zone = 0u;
        rp->find_args.netif = io->netif;
        RawPcb.find(ctx->raw_pcb);
        if (rp->status == IDEMIP_OK)
        {
            io->pcb_kind = IDEMIP_DISPATCH_PCB_RAW;
            io->pcb = rp->index;
            io->act |= IDEMIP_DISPATCH_ACT_DELIVER;
            d_bump(work, d_ip_ctr(ip_version, IDEMIP_STAT_IP4_IN_DELIVERS, IDEMIP_STAT_IP6_IN_DELIVERS));
            d_delivered(work, io->input_args.frame);
            return;
        }
    }
    d_drop(work, IDEMIP_DISPATCH_DROP_IP_PROTO, IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS);
    d_bump(work, d_ip_ctr(ip_version, IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS, IDEMIP_STAT_IP6_IN_UNKNOWN_PROTOS));
}

#endif // IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6

#if IDEMIP_ENABLE_UDP

// RFC 768, over the binding table, and RFC 3828 where the same header field is a Checksum Coverage
// rather than a Length. RFC 1122 sec 4.1.3.1: with no binding, "UDP SHOULD send an ICMP Port
// Unreachable message", which is the caller's to send and udpNoPorts is what counts it.
// The RFC 768 checksum over the pseudo-header and the datagram, for whichever IP version carried
// it. RFC 1122 sec 4.1.3.4: a datagram whose checksum "is non-zero and invalid" is discarded
// silently, while an all-zero field means the sender computed none and the datagram is accepted.
// RFC 8200 sec 8.1 removes that exemption over IPv6: "IPv6 receivers must discard UDP packets
// containing a zero checksum", the IPv6 header carrying no checksum of its own.
static idemip_bool d_udp_cksum_ok(const uint8_t *udp, const uint8_t *local_ip, const uint8_t *remote_ip,
                                  uint8_t ip_version)
{
    size_t len = (size_t)idemip_udp_len(udp);

    if (!idemip_udp_cksum_present(udp))
    {
        return (ip_version == (uint8_t)IDEMIP_PSEUDO_V6) ? IDEMIP_FALSE : IDEMIP_TRUE;
    }
    uint32_t sum = 0u;
    if (!idemip_pseudo_accum(&sum, ip_version, (uint8_t)IDEMIP_UDP_PROTO, remote_ip, local_ip, (uint32_t)len))
    {
        return IDEMIP_FALSE; // a version that names no pseudo-header
    }
    return (idemip_cksum_final(idemip_cksum_accum(sum, udp, len)) == 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

static void d_udp(uint8_t *restrict work, const uint8_t *local_ip, const uint8_t *remote_ip, uint8_t ip_version,
                  idemip_bool lite)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    const uint8_t *udp = io->input_args.frame + io->payload_off;

    if (ctx->udp_pcb == NULL)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
        return;
    }
    if (io->payload_len < IDEMIP_UDP_HDR_LEN)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_UDP_IN_ERRORS);
        return;
    }
    // RFC 768 covers the whole datagram, so its Length field is not a coverage and the binding is
    // asked with IDEMIP_UDPLITE_COV_ALL. RFC 3828 sec 3.1 puts the Checksum Coverage in the same
    // sixteen bits, and udplite reads it and checks the sum over the octets it names.
    uint16_t cov = (uint16_t)IDEMIP_UDPLITE_COV_ALL;
    if (!lite)
    {
        // RFC 768: Length "is the length in octets of this user datagram including this header and
        // the data", minimum eight. A Length past the octets the IP layer delivered would take the
        // sum over bytes that are not the datagram's.
        if (!idemip_udp_len_valid(udp) || (size_t)idemip_udp_len(udp) > io->payload_len)
        {
            d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
            d_bump(work, IDEMIP_STAT_UDP_IN_ERRORS);
            return;
        }
        if (!d_udp_cksum_ok(udp, local_ip, remote_ip, ip_version))
        {
            d_drop(work, IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_STAT_IF_IN_ERRORS);
            d_bump(work, IDEMIP_STAT_UDP_IN_ERRORS);
            return;
        }
    }
    if (lite)
    {
        if (ctx->udplite == NULL)
        {
            d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
            return;
        }
        UdpLiteIo *ul = IDEMIP_UDPLITE_IO(ctx->udplite);
        ul->check_args.dgram = udp;
        ul->check_args.src = remote_ip;
        ul->check_args.dst = local_ip;
        ul->check_args.ip_payload_len = (uint32_t)io->payload_len;
        ul->check_args.ip_version = ip_version;
        UdpLite.check(ctx->udplite);
        if (ul->status != IDEMIP_OK)
        {
            d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
            d_bump(work, IDEMIP_STAT_UDP_IN_ERRORS);
            return;
        }
        cov = ul->res.cov;
    }
    UdpPcbIo *up = IDEMIP_UDP_PCB_IO(ctx->udp_pcb);
    up->find_args.local_ip = local_ip;
    up->find_args.remote_ip = remote_ip;
    up->find_args.local_port = idemip_udp_dst_port(udp);
    up->find_args.remote_port = idemip_udp_src_port(udp);
    up->find_args.cksum_len = cov;
    up->find_args.ip_version = ip_version;
    up->find_args.local_zone = 0u;
    up->find_args.remote_zone = 0u;
    up->find_args.netif = io->netif;
    UdpPcb.find(ctx->udp_pcb);
    if (up->status != IDEMIP_OK)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_STAT_IF_IN_DISCARDS);
        d_bump(work, IDEMIP_STAT_UDP_NO_PORTS);
        return;
    }
    io->pcb_kind = IDEMIP_DISPATCH_PCB_UDP;
    io->pcb = up->index;
    io->act |= IDEMIP_DISPATCH_ACT_DELIVER;
    d_bump(work, IDEMIP_STAT_UDP_IN_DATAGRAMS);
    d_bump(work, d_ip_ctr(ip_version, IDEMIP_STAT_IP4_IN_DELIVERS, IDEMIP_STAT_IP6_IN_DELIVERS));
    d_delivered(work, io->input_args.frame);
}

#endif // IDEMIP_ENABLE_UDP

#if IDEMIP_ENABLE_TCP

// RFC 9293 sec 3.4: "all arithmetic dealing with sequence numbers must be performed modulo 2^32",
// so a number's distance forward from an edge is that subtraction and no wrap is ambiguous.
static uint32_t d_seq_from(uint32_t seq, uint32_t edge)
{
    return seq - edge;
}

// Copy the connection's state between the two operand blocks. tcp_in reads a whole TCB's worth of
// RFC 9293 sec 3.3.1 variables and hands them back changed; tcp_pcb holds them.
static void d_tcp_load_in(uint8_t *restrict work, uint16_t listener, uint32_t now_ms)
{
    DispatchCtx *ctx = D_CTX(work);
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(ctx->tcp_pcb);
    TcpInIo *ti = IDEMIP_TCP_IN_IO(ctx->tcp_in);
    ti->vars = tp->vars;
    ti->ctl = tp->ctl;
    ti->state = tp->state;
    ti->listener = listener;
    ti->now_ms = now_ms;
}

static void d_tcp_store(uint8_t *restrict work, uint16_t pcb)
{
    DispatchCtx *ctx = D_CTX(work);
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(ctx->tcp_pcb);
    TcpInIo *ti = IDEMIP_TCP_IN_IO(ctx->tcp_in);
    tp->vars = ti->vars;
    tp->ctl = ti->ctl;
    tp->state = ti->state;
    tp->pcb_args.index = pcb;
    TcpPcb.store(ctx->tcp_pcb);
}

// RFC 9293 sec 3.10.7.4 SHLD-31: "Segments with higher beginning sequence numbers SHOULD be held for
// later processing." Holding one is pinning the receive descriptor it lies in and linking the entry
// into the connection's out-of-order queue in sequence order.
static void d_tcp_hold(uint8_t *restrict work, uint16_t pcb)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    TcpInIo *ti = IDEMIP_TCP_IN_IO(ctx->tcp_in);
    const DispatchInputArgs *a = &io->input_args;

    if (ti->res.text_len == 0u || a->desc == IDEMIP_DISPATCH_DESC_NONE)
    {
        // Retention is a pin on a descriptor. A segment carrying no text, and one that lies in no
        // descriptor, are dropped: the sender retransmits, which is what SHLD-31 leaves open.
        return;
    }
    if (!d_pin(work, io->netif, a->desc))
    {
        return;
    }
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(ctx->tcp_pcb);
    tp->oos_args.pcb = pcb;
    tp->oos_args.seq = ti->res.text_seq;
    tp->oos_args.desc = IDEMIP_DISPATCH_DESC_HANDLE(io->netif, a->desc);
    tp->oos_args.offset = (uint16_t)(io->payload_off + ti->res.text_off);
    tp->oos_args.len = ti->res.text_len;
    TcpPcb.oos_alloc(ctx->tcp_pcb);
    if (tp->status != IDEMIP_OK)
    {
        // The queue holds IDEMIP_TCP_OOSEQ_SEGS already, so the descriptor goes back to the ring and
        // the segment is dropped. RFC 9293 sec 3.10.7.4's hold is a SHOULD, and the sender's own
        // retransmission is what recovers it.
        d_unpin(work, io->netif, a->desc);
        return;
    }
    io->act |= IDEMIP_DISPATCH_ACT_PINNED;
    D_PCB_AT(work, pcb)->netif = io->netif;
}

// RFC 9293 sec 3.10.7.4 (MUST-58): "the processing of received segments MUST be implemented to
// aggregate ACK segments whenever possible", and (MUST-59) "if the TCP endpoint is processing a
// series of queued segments, it MUST process them all before sending any ACK segments." So an
// ordinary acknowledgment is recorded against the connection and taken once by tcp_ack; the RFC 5961
// challenge and every reset are not aggregated, each being an answer to one specific segment.
static void d_tcp_reply(uint8_t *restrict work, uint16_t pcb)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    TcpInIo *ti = IDEMIP_TCP_IN_IO(ctx->tcp_in);

    io->reply = ti->reply;
    io->tcp_act = ti->res.act;
    if ((ti->res.act & IDEMIP_TCP_IN_ACT_ACK) == 0u)
    {
        return;
    }
    if ((ti->res.act & (IDEMIP_TCP_IN_ACT_CHALLENGE | IDEMIP_TCP_IN_ACT_RST)) != 0u)
    {
        return;
    }
    io->tcp_act &= ~(uint32_t)IDEMIP_TCP_IN_ACT_ACK;
    io->act |= IDEMIP_DISPATCH_ACT_ACK_OWED;
    if (pcb < IDEMIP_TCP_PCBS)
    {
        D_PCB_AT(work, pcb)->ack_owed = 1u;
        D_PCB_AT(work, pcb)->netif = io->netif;
    }
}

// RFC 9293 sec 3.10.7, over the connection an arriving segment's four-tuple names.
static void d_tcp(uint8_t *restrict work, const uint8_t *local_ip, const uint8_t *remote_ip, uint8_t ip_version)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    const DispatchInputArgs *a = &io->input_args;
    const uint8_t *seg = a->frame + io->payload_off;

    if (ctx->tcp_pcb == NULL || ctx->tcp_in == NULL)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
        return;
    }
    if (io->payload_len < IDEMIP_TCP_HDR_LEN)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_TCP_IN_ERRS);
        return;
    }
    d_bump(work, IDEMIP_STAT_TCP_IN_SEGS);

    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(ctx->tcp_pcb);
    TcpInIo *ti = IDEMIP_TCP_IN_IO(ctx->tcp_in);
    tp->find_args.local_ip = local_ip;
    tp->find_args.remote_ip = remote_ip;
    tp->find_args.local_port = idemip_tcp_dst_port(seg);
    tp->find_args.remote_port = idemip_tcp_src_port(seg);
    tp->find_args.ip_version = ip_version;
    tp->find_args.local_zone = 0u;
    tp->find_args.remote_zone = 0u;
    tp->find_args.netif = io->netif;
    TcpPcb.find(ctx->tcp_pcb);

    uint16_t pcb = IDEMIP_TCP_PCB_NONE;
    uint16_t listener = IDEMIP_TCP_PCB_NONE;
    if (tp->status == IDEMIP_OK)
    {
        pcb = tp->index;
    }
    else
    {
        TcpPcb.find_listener(ctx->tcp_pcb);
        if (tp->status == IDEMIP_OK)
        {
            listener = tp->index;
        }
    }

    // The header and the sec 3.1 pseudo-header checksum, before any state is read.
    ti->parse_args.seg = seg;
    ti->parse_args.local_ip = local_ip;
    ti->parse_args.remote_ip = remote_ip;
    ti->parse_args.len = (uint16_t)io->payload_len;
    ti->parse_args.ip_version = ip_version;
    ti->parse_args.snd_scale = 0u;
    if (pcb != IDEMIP_TCP_PCB_NONE)
    {
        tp->pcb_args.index = pcb;
        TcpPcb.load(ctx->tcp_pcb);
        if (tp->status != IDEMIP_OK)
        {
            d_drop(work, IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_STAT_IF_IN_DISCARDS);
            return;
        }
        ti->parse_args.snd_scale = tp->ctl.snd_scale;
    }
    TcpIn.parse(ctx->tcp_in);
    if (ti->status != IDEMIP_OK)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_TCP_IN_ERRS);
        return;
    }

    if (pcb == IDEMIP_TCP_PCB_NONE && listener == IDEMIP_TCP_PCB_NONE)
    {
        // RFC 9293 sec 3.10.7.1 CLOSED STATE: "If the state is CLOSED (i.e., TCB does not exist)".
        ti->vars.snd_nxt = 0u;
        ti->vars.rcv_nxt = 0u;
        ti->state = IDEMIP_TCP_STATE_CLOSED;
        ti->listener = IDEMIP_TCP_PCB_NONE;
        ti->now_ms = a->now_ms;
        TcpIn.closed(ctx->tcp_in);
        io->pcb_kind = IDEMIP_DISPATCH_PCB_NONE;
        io->tcp_act = ti->res.act;
        io->reply = ti->reply;
        io->act |= IDEMIP_DISPATCH_ACT_TCP;
        d_drop(work, IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_STAT_IF_IN_DISCARDS);
        return;
    }

    if (pcb == IDEMIP_TCP_PCB_NONE)
    {
        // RFC 9293 sec 3.10.7.2 LISTEN STATE. The connection the SYN creates is a TCB of its own,
        // which sec 3.5 (MUST-11) records the listener on.
        tp->open_args.ip_version = ip_version;
        TcpPcb.open(ctx->tcp_pcb);
        if (tp->status != IDEMIP_OK)
        {
            d_drop(work, IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_STAT_IF_IN_DISCARDS);
            d_bump(work, IDEMIP_STAT_TCP_ATTEMPT_FAILS);
            return;
        }
        pcb = tp->index;
        tp->bind_args.index = pcb;
        tp->bind_args.ip = local_ip;
        tp->bind_args.port = idemip_tcp_dst_port(seg);
        tp->bind_args.zone = 0u;
        tp->bind_args.netif = io->netif;
        TcpPcb.bind(ctx->tcp_pcb);
        tp->connect_args.index = pcb;
        tp->connect_args.ip = remote_ip;
        tp->connect_args.port = idemip_tcp_src_port(seg);
        tp->connect_args.zone = 0u;
        tp->connect_args.netif = io->netif;
        TcpPcb.connect(ctx->tcp_pcb);
        tp->accept_args.index = pcb;
        tp->accept_args.listener = listener;
        TcpPcb.accept(ctx->tcp_pcb);
        tp->pcb_args.index = pcb;
        TcpPcb.load(ctx->tcp_pcb);
        d_tcp_load_in(work, listener, a->now_ms);
        ti->state = IDEMIP_TCP_STATE_LISTEN;
        TcpIn.listen(ctx->tcp_in);
        d_tcp_store(work, pcb);
        io->pcb_kind = IDEMIP_DISPATCH_PCB_TCP;
        io->pcb = pcb;
        io->tcp_act = ti->res.act;
        io->reply = ti->reply;
        io->act |= IDEMIP_DISPATCH_ACT_TCP;
        d_bump(work, IDEMIP_STAT_TCP_PASSIVE_OPENS);
        d_delivered(work, a->frame);
        d_bump(work, d_ip_ctr(ip_version, IDEMIP_STAT_IP4_IN_DELIVERS, IDEMIP_STAT_IP6_IN_DELIVERS));
        return;
    }

    d_tcp_load_in(work, tp->info.listener, a->now_ms);
    if (ti->state == IDEMIP_TCP_STATE_SYN_SENT)
    {
        TcpIn.syn_sent(ctx->tcp_in);
    }
    else if (ti->state == IDEMIP_TCP_STATE_CLOSED)
    {
        TcpIn.closed(ctx->tcp_in);
    }
    else
    {
        TcpIn.segment(ctx->tcp_in);
    }
    io->pcb_kind = IDEMIP_DISPATCH_PCB_TCP;
    io->pcb = pcb;
    io->act |= IDEMIP_DISPATCH_ACT_TCP;
    io->acked = ti->res.acked;
    io->text_seq = ti->res.text_seq;
    io->text_off = ti->res.text_off;
    io->text_len = ti->res.text_len;

    if ((ti->res.act & IDEMIP_TCP_IN_ACT_HOLD) != 0u)
    {
        d_tcp_hold(work, pcb);
    }
    if ((ti->res.act & IDEMIP_TCP_IN_ACT_TEXT) != 0u)
    {
        io->act |= IDEMIP_DISPATCH_ACT_DELIVER;
        d_delivered(work, a->frame);
        d_bump(work, d_ip_ctr(ip_version, IDEMIP_STAT_IP4_IN_DELIVERS, IDEMIP_STAT_IP6_IN_DELIVERS));
    }
    if ((ti->res.act & IDEMIP_TCP_IN_ACT_RST) != 0u)
    {
        d_bump(work, IDEMIP_STAT_TCP_OUT_RSTS);
    }
    d_tcp_store(work, pcb);
    d_tcp_reply(work, pcb);
}

#endif // IDEMIP_ENABLE_TCP

// ===========================================================================
// IPv4
// ===========================================================================

// Where a Destination Address put the datagram. Both families report it, so it stands outside either
// one's guard.
typedef enum
{
    D_DEST_LOCAL = 0, // RFC 1122 sec 3.1 (2), "destined to the local host"
    D_DEST_FORWARD,   // somewhere else, and the caller routes it
    D_DEST_DROP,      // an address this node makes nothing of
} DispatchDest;

#if IDEMIP_ENABLE_IPV4

// RFC 1122 sec 3.1 (2), over the forms sec 3.2.1.3 lists: case (c) "{ -1, -1 }" limited broadcast, a
// class D group this node joined (RFC 1112 sec 4), case (g) "{ 127, <any> }" loopback, any
// interface's own address, and case (e) "{ <Network-number>, <Subnet-number>, -1 }" directed
// broadcast on the receiving interface's subnet.
static DispatchDest d_ip4_dest(uint8_t *restrict work, uint32_t dst)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);

    if (idemip_ip4_addr_type(dst) == IDEMIP_IP4_TYPE_BROADCAST)
    {
        return D_DEST_LOCAL;
    }
    if (idemip_ip4_addr_is_mcast(dst))
    {
        // RFC 1112 sec 7.2: "every level 2 host must join the 'all-hosts' group (address 224.0.0.1)
        // on each network interface at initialization time and must remain a member for as long as
        // the host is active", and Appendix I starts it "in Idle Member state for that group on
        // every interface". It holds no table entry, the way igmp.c already keeps it out of every
        // Report, so the membership is read here.
        if (dst == IDEMIP_IGMP_ALL_SYSTEMS)
        {
            return D_DEST_LOCAL;
        }
        if (ctx->igmp == NULL)
        {
            return D_DEST_DROP;
        }
        IDEMIP_IGMP_IO(ctx->igmp)->group_args.group = dst;
        IDEMIP_IGMP_IO(ctx->igmp)->group_args.netif = io->netif;
        Igmp.find(ctx->igmp);
        return (IDEMIP_IGMP_IO(ctx->igmp)->status == IDEMIP_OK) ? D_DEST_LOCAL : D_DEST_DROP;
    }
    if (ctx->loopif != NULL)
    {
        IDEMIP_LOOPIF_IO(ctx->loopif)->match_args.addr4 = dst;
        Loopif.owns4(ctx->loopif);
        if (IDEMIP_LOOPIF_IO(ctx->loopif)->status == IDEMIP_OK && IDEMIP_LOOPIF_IO(ctx->loopif)->owned)
        {
            return D_DEST_LOCAL;
        }
    }
    if (ctx->netif == NULL)
    {
        return D_DEST_DROP;
    }
    IDEMIP_NETIF_IO(ctx->netif)->route_args.dst = dst;
    Netif.find4(ctx->netif);
    if (IDEMIP_NETIF_IO(ctx->netif)->status == IDEMIP_OK)
    {
        return D_DEST_LOCAL;
    }
    if (ctx->ip4_addr != NULL && d_netif_get(work, io->netif))
    {
        uint32_t addr = IDEMIP_NETIF_IO(ctx->netif)->addr;
        uint32_t mask = IDEMIP_NETIF_IO(ctx->netif)->mask;
        if (mask != 0u)
        {
            Ip4AddrIo *ia = IDEMIP_IP4_ADDR_IO(ctx->ip4_addr);
            ia->match_args.addr = dst;
            ia->match_args.net = addr;
            ia->match_args.mask = mask;
            Ip4Addr.match(ctx->ip4_addr);
            if (ia->status == IDEMIP_OK && ia->is_broadcast)
            {
                return D_DEST_LOCAL;
            }
        }
    }
    return D_DEST_FORWARD;
}

// RFC 792, over the caller's transmit buffer.
static void d_icmp4(uint8_t *restrict work, const uint8_t *ip4, size_t total_len)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    const DispatchInputArgs *a = &io->input_args;

    io->pcb_kind = IDEMIP_DISPATCH_PCB_ICMP;
    // RFC 2011 icmpInMsgs: "The total number of ICMP messages which the entity received. Note that
    // this counter includes all those counted by icmpInErrors." Counted before the message is read,
    // so one that turns out malformed is still counted here as well as in icmpInErrors.
    d_bump(work, IDEMIP_STAT_ICMP4_IN_MSGS);
    if (ctx->icmp_in == NULL)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
        return;
    }
    if (a->out == NULL || a->out_cap < (size_t)IDEMIP_ETH_FRAME_MIN)
    {
        // A reply with nowhere to be built is BUSY: a transmit buffer frees on a later tick, and the
        // same frame dispatched again then answers.
        io->status = IDEMIP_BUSY;
        return;
    }
    uint32_t if_addr = d_netif_get(work, io->netif) ? IDEMIP_NETIF_IO(ctx->netif)->addr : 0u;
    uint32_t if_mask = (ctx->netif != NULL) ? IDEMIP_NETIF_IO(ctx->netif)->mask : 0u;

    IcmpInIo *ic = IDEMIP_ICMP_IN_IO(ctx->icmp_in);
    ic->recv_args.datagram = ip4;
    ic->recv_args.len = total_len;
    ic->recv_args.out = a->out;
    ic->recv_args.out_cap = a->out_cap;
    ic->recv_args.if_addr = if_addr;
    ic->recv_args.if_mask = if_mask;
    ic->recv_args.link_bcast = idemip_eth_is_broadcast(idemip_eth_dst(a->frame));
    IcmpIn.recv(ctx->icmp_in);
    if (ic->status != IDEMIP_OK)
    {
        // icmpInErrors: "The number of ICMP messages which the entity received but determined as
        // having ICMP-specific errors (bad ICMP checksums, bad length, etc.)."
        d_bump(work, IDEMIP_STAT_ICMP4_IN_ERRORS);
        d_drop(work, IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_STAT_IF_IN_DISCARDS);
        d_bump(work, IDEMIP_STAT_IP4_IN_DISCARDS);
        return;
    }
    // The unit's own decision, which was set at eight sites in icmp_in.c and read at none. RFC 1122
    // sec 3.2.2: "If an ICMP message of unknown type is received, it MUST be silently discarded",
    // which icmp_in.h also raises for a message whose checksum does not hold, one shorter than its
    // type requires, and the types sec 3.2.2.7 and sec 3.2.2.8 leave unimplemented.
    // RFC 2011 icmpInErrors: "The number of ICMP messages which the entity received but determined as
    // having ICMP-specific errors (bad ICMP checksums, bad length, etc.)." Those are the unit's two
    // flags. A discard with neither is the silent one, and is no error.
    if ((ic->act & IDEMIP_ICMP_IN_ACT_DISCARD) != 0u)
    {
        if (ic->bad_len)
        {
            d_bump(work, IDEMIP_STAT_ICMP4_IN_ERRORS);
            d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        }
        else if (!ic->cksum_ok)
        {
            d_bump(work, IDEMIP_STAT_ICMP4_IN_ERRORS);
            d_drop(work, IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_STAT_IF_IN_ERRORS);
        }
        else
        {
            d_drop(work, IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_STAT_IF_IN_DISCARDS);
        }
        d_bump(work, IDEMIP_STAT_IP4_IN_DISCARDS);
        return;
    }
    d_icmp4_type_bump(work, idemip_icmp_type(ip4 + idemip_ip4_hdr_len(ip4)));
    if ((ic->act & IDEMIP_ICMP_IN_ACT_REPLY) != 0u)
    {
        io->out_len = ic->out_len;
        io->act |= IDEMIP_DISPATCH_ACT_SEND;
    }
    if ((ic->act & IDEMIP_ICMP_IN_ACT_USER) != 0u)
    {
        io->act |= IDEMIP_DISPATCH_ACT_USER;
    }
    io->act |= IDEMIP_DISPATCH_ACT_DELIVER;
    d_bump(work, IDEMIP_STAT_IP4_IN_DELIVERS);
    d_delivered(work, a->frame);
}

// RFC 2236, over the group table. sec 2.2: the Max Resp Time field is "in units of 1/10 second";
// sec 4 makes a Query carrying zero there a Version 1 Query.
static void d_igmp(uint8_t *restrict work, const uint8_t *msg)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    const DispatchInputArgs *a = &io->input_args;

    io->pcb_kind = IDEMIP_DISPATCH_PCB_GROUP;
    if (ctx->igmp == NULL)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
        return;
    }
    if (io->payload_len < IDEMIP_IGMP_MSG_LEN)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        return;
    }
    // RFC 2236 sec 2.3: "When receiving packets, the checksum MUST be verified before processing a
    // packet", and sec 6 repeats it for the Query and the Report. The sum covers the whole IGMP
    // message, no pseudo-header, so RFC 1071 sec 1's fold to zero is the whole test. Nothing else
    // on this path checks it: the IPv4 header checksum covers only the header.
    if (!idemip_cksum_valid(msg, IDEMIP_IGMP_MSG_LEN))
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_STAT_IF_IN_ERRORS);
        return;
    }
    IgmpIo *ig = IDEMIP_IGMP_IO(ctx->igmp);
    uint8_t type = msg[IDEMIP_IGMP_OFF_TYPE];
    uint8_t max_resp = msg[IDEMIP_IGMP_OFF_MAX_RESP];
    uint32_t group = idemip_rd32(msg + IDEMIP_IGMP_OFF_GROUP);

    if (type == (uint8_t)IDEMIP_IGMP_TYPE_QUERY)
    {
        ig->query_args.group = group;
        ig->query_args.max_resp_ms = (uint32_t)max_resp * IDEMIP_IGMP_MAX_RESP_UNIT_MS;
        ig->query_args.rand = a->now_ms;
        ig->query_args.now_ms = a->now_ms;
        ig->query_args.netif = io->netif;
        ig->query_args.general = (idemip_bool)(group == 0u);
        ig->query_args.v1 = (idemip_bool)(max_resp == 0u);
        Igmp.query_in(ctx->igmp);
    }
    else if (type == (uint8_t)IDEMIP_IGMP_TYPE_REPORT_V1 || type == (uint8_t)IDEMIP_IGMP_TYPE_REPORT_V2)
    {
        ig->report_args.group = group;
        ig->report_args.netif = io->netif;
        Igmp.report_in(ctx->igmp);
    }
    else
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_IP_PROTO, IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS);
        d_bump(work, IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS);
        return;
    }
    io->act |= IDEMIP_DISPATCH_ACT_DELIVER;
    d_bump(work, IDEMIP_STAT_IP4_IN_DELIVERS);
    d_delivered(work, a->frame);
}

// RFC 1122 sec 3.1 (5), "passes the encapsulated message to the appropriate transport-layer protocol
// module".
static void d_ip4_proto(uint8_t *restrict work, const uint8_t *ip4, size_t hdr_len, size_t total_len)
{
    DispatchIo *io = D_IO(work);
    const uint8_t *local_ip = ip4 + IDEMIP_IP4_OFF_DST;
    const uint8_t *remote_ip = ip4 + IDEMIP_IP4_OFF_SRC;

    io->proto = idemip_ip4_proto(ip4);
    io->payload_off = io->ip_off + hdr_len;
    io->payload_len = total_len - hdr_len;

    switch (io->proto)
    {
    case IDEMIP_IP4_PROTO_ICMP:
        d_icmp4(work, ip4, total_len);
        return;
    case IDEMIP_IGMP_IP_PROTO:
        d_igmp(work, ip4 + hdr_len);
        return;
#if IDEMIP_ENABLE_UDP
    case IDEMIP_IP4_PROTO_UDP:
        d_udp(work, local_ip, remote_ip, IDEMIP_IP4_VERSION, IDEMIP_FALSE);
        return;
    case IDEMIP_UDPLITE_PROTO:
        d_udp(work, local_ip, remote_ip, IDEMIP_IP4_VERSION, IDEMIP_TRUE);
        return;
#endif
#if IDEMIP_ENABLE_TCP
    case IDEMIP_IP4_PROTO_TCP:
        d_tcp(work, local_ip, remote_ip, IDEMIP_IP4_VERSION);
        return;
#endif
    default:
        break;
    }
    d_raw(work, local_ip, remote_ip, IDEMIP_IP4_VERSION);
}

// RFC 1122 sec 3.1 (4), "reassembles the datagram if necessary". A held fragment stays in the buffer
// the engine wrote it to, so its descriptor is pinned before the reassembler is handed it.
static void d_ip4_frag(uint8_t *restrict work, const uint8_t *ip4, size_t total_len)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    const DispatchInputArgs *a = &io->input_args;

    d_bump(work, IDEMIP_STAT_IP4_REASM_REQDS);
    if (ctx->ip4_reass == NULL)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
        return;
    }
    if (!d_pin(work, io->netif, a->desc))
    {
        // Retention is a pin on a descriptor, and a frame in none cannot be held past this call.
        d_drop(work, IDEMIP_DISPATCH_DROP_NO_DESC, IDEMIP_STAT_IF_IN_DISCARDS);
        d_bump(work, IDEMIP_STAT_IP4_REASM_FAILS);
        return;
    }
    Ip4ReassIo *re = IDEMIP_IP4_REASS_IO(ctx->ip4_reass);
    re->now_ms = a->now_ms;
    re->hold_args.hdr = ip4;
    re->hold_args.desc = IDEMIP_DISPATCH_DESC_HANDLE(io->netif, a->desc);
    re->hold_args.len = (uint16_t)total_len;
    Ip4Reass.hold(ctx->ip4_reass);
    if (re->status != IDEMIP_OK)
    {
        // RFC 1213 ipReasmFails, "The number of failures detected by the IP re-assembly algorithm
        // (for whatever reason: timed out, errors, etc)", which a refusal is. Not ipInDiscards:
        // "this counter does not include any datagrams discarded while awaiting re-assembly".
        d_unpin(work, io->netif, a->desc);
        d_drop(work, IDEMIP_DISPATCH_DROP_REASS, IDEMIP_STAT_IF_IN_DISCARDS);
        d_bump(work, IDEMIP_STAT_IP4_REASM_FAILS);
        return;
    }
    io->act |= IDEMIP_DISPATCH_ACT_PINNED;
    io->datagram = re->index;
    if (re->complete)
    {
        io->act |= IDEMIP_DISPATCH_ACT_REASSEMBLED;
        d_bump(work, IDEMIP_STAT_IP4_REASM_OKS);
    }
}

// RFC 1122 sec 3.2.1.3: "A host MUST silently discard an incoming datagram containing an IP source
// address that is invalid by the rules of this section. This validation could be done in either the
// IP layer or by each protocol in the transport layer." Case (c) "{ -1, -1 } Limited broadcast. It
// MUST NOT be used as a source address", cases (d), (e) and (f) say the same of every directed
// broadcast, case (g) "{ 127, <any> } ... MUST NOT appear outside a host", and the section's sending
// rule bars the rest: "the IP source address MUST be one of its own IP addresses (but not a
// broadcast or multicast address)."
//
// Cases (a) and (b) keep { 0, 0 } and { 0, <Host-number> } valid as a source, "as part of an
// initialization procedure by which the host learns its own IP address", which is what a DHCP
// client's first datagram carries. A directed broadcast is only recognizable against the receiving
// interface's own mask, so an interface with no address bars nothing but the forms above.
static idemip_bool d_ip4_src_invalid(uint8_t *restrict work, uint32_t src)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    IdemIpIp4AddrType type = idemip_ip4_addr_type(src);
    if (type == IDEMIP_IP4_TYPE_BROADCAST || type == IDEMIP_IP4_TYPE_MULTICAST)
    {
        return IDEMIP_TRUE;
    }
    idemip_bool have = d_netif_get(work, io->netif);
    if (type == IDEMIP_IP4_TYPE_LOOPBACK)
    {
        // Case (g) bars 127/8 from the wire and leaves it to the interface no wire reaches.
        uint16_t flags = have ? IDEMIP_NETIF_IO(ctx->netif)->flags : 0u;
        return ((flags & (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK) != 0u) ? IDEMIP_FALSE : IDEMIP_TRUE;
    }
    if (!have || ctx->ip4_addr == NULL)
    {
        return IDEMIP_FALSE;
    }
    uint32_t mask = IDEMIP_NETIF_IO(ctx->netif)->mask;
    if (mask == 0u)
    {
        return IDEMIP_FALSE;
    }
    Ip4AddrIo *ia = IDEMIP_IP4_ADDR_IO(ctx->ip4_addr);
    ia->match_args.addr = src;
    ia->match_args.net = IDEMIP_NETIF_IO(ctx->netif)->addr;
    ia->match_args.mask = mask;
    Ip4Addr.match(ctx->ip4_addr);
    return (ia->status == IDEMIP_OK && ia->is_broadcast) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 1122 sec 3.1, steps (1), (2), (4) and (5) over one IPv4 datagram.
static void d_ip4(uint8_t *restrict work, const uint8_t *ip4, size_t avail)
{
    DispatchIo *io = D_IO(work);
    io->ip_version = IDEMIP_IP4_VERSION;
    d_bump(work, IDEMIP_STAT_IP4_IN_RECEIVES);

    // (1) verifies that the datagram is correctly formatted
    if (idemip_ip4_verify(ip4, avail) != IDEMIP_OK)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_IP4_IN_HDR_ERRORS);
        return;
    }
    // RFC 894 pads a short data field, and "This padding is not part of the IP packet and is not
    // included in the total length field", so the length comes from the header and never the frame.
    size_t total_len = (size_t)idemip_ip4_total_len(ip4);
    size_t hdr_len = idemip_ip4_hdr_len(ip4);

    // sec 3.2.1.3's source-address rule, taken in the IP layer so every transport above it is covered
    // once.
    if (d_ip4_src_invalid(work, idemip_ip4_src(ip4)))
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_IP_SOURCE, IDEMIP_STAT_IF_IN_DISCARDS);
        d_bump(work, IDEMIP_STAT_IP4_IN_ADDR_ERRORS);
        return;
    }

    // (2) verifies that it is destined to the local host
    DispatchDest dest = d_ip4_dest(work, idemip_ip4_dst(ip4));
    if (dest == D_DEST_FORWARD)
    {
        io->act |= IDEMIP_DISPATCH_ACT_FORWARD;
        return;
    }
    if (dest == D_DEST_DROP)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_IP_ADDRESS, IDEMIP_STAT_IF_IN_DISCARDS);
        d_bump(work, IDEMIP_STAT_IP4_IN_ADDR_ERRORS);
        return;
    }

    // (4) reassembles the datagram if necessary
    if (idemip_ip4_is_fragment(ip4))
    {
        d_ip4_frag(work, ip4, total_len);
        return;
    }

    // (5) passes the encapsulated message to the appropriate transport-layer protocol module
    d_ip4_proto(work, ip4, hdr_len, total_len);
}

// RFC 826 "Packet Reception", over the address this interface holds. A REQUEST for it owes a REPLY,
// which is built into the caller's transmit buffer.
static void d_arp(uint8_t *restrict work, const uint8_t *packet, size_t avail)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    const DispatchInputArgs *a = &io->input_args;

    io->pcb_kind = IDEMIP_DISPATCH_PCB_ARP;
    if (ctx->arp == NULL)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
        return;
    }
    if (avail < IDEMIP_ARP_LEN)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        return;
    }
    if (!d_netif_get(work, io->netif))
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
        return;
    }
    uint32_t local_pa = IDEMIP_NETIF_IO(ctx->netif)->addr;
    const uint8_t *local_ha = IDEMIP_NETIF_IO(ctx->netif)->hwaddr;

    ArpTableIo *ar = IDEMIP_ARP_IO(ctx->arp);
    ar->now_ms = a->now_ms;
    ar->input_args.packet = packet;
    ar->input_args.local_pa = local_pa;
    ar->input_args.netif = io->netif;
    ArpTable.input(ctx->arp);
    if (ar->status != IDEMIP_OK)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_STAT_IF_IN_DISCARDS);
        return;
    }
    io->act |= IDEMIP_DISPATCH_ACT_DELIVER;
    d_delivered(work, a->frame);
    if (!ar->reply_owed || local_ha == NULL)
    {
        return;
    }
    size_t tag_len = io->tagged ? (size_t)IDEMIP_VLAN_TAG_LEN : 0u;
    size_t need = idemip_eth_frame_len(tag_len + IDEMIP_ARP_LEN);
    if (a->out == NULL || a->out_cap < need)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    idemip_eth_build(a->out, idemip_arp_sha(packet), local_ha, (uint16_t)IDEMIP_ETHERTYPE_ARP);
    if (tag_len != 0u && ctx->vlan != NULL)
    {
        VlanIo *v = IDEMIP_VLAN_IO(ctx->vlan);
        v->build_args.frame = a->out;
        v->build_args.type = (uint16_t)IDEMIP_ETHERTYPE_ARP;
        v->tag_args.vid = io->vid;
        v->tag_args.pcp = io->pcp;
        v->tag_args.dei = IDEMIP_FALSE;
        Vlan.build(ctx->vlan);
        if (v->status != IDEMIP_OK)
        {
            return;
        }
    }
    idemip_arp_build_reply(a->out + IDEMIP_ETH_OFF_PAYLOAD + tag_len, local_ha, local_pa, idemip_arp_sha(packet),
                           idemip_arp_spa(packet));
    io->out_len = IDEMIP_ETH_HDR_LEN + idemip_eth_pad(a->out, tag_len + IDEMIP_ARP_LEN);
    io->act |= IDEMIP_DISPATCH_ACT_SEND;
}

#endif // IDEMIP_ENABLE_IPV4

// ===========================================================================
// IPv6
// ===========================================================================

#if IDEMIP_ENABLE_IPV6

// RFC 1122 sec 3.1 (2) over the RFC 4291 forms: one of the interface's own addresses, a group MLD
// joined, the sec 2.7.1 solicited-node address of one of the interface's own, or sec 2.5.3 ::1.
//
// The three outcomes d_ip4_dest reports, for the same reason. RFC 2465 ipv6IfStatsInAddrErrors: "The
// number of input datagrams discarded because the IPv6 address in their IPv6 header's destination
// field was not a valid address to be received at this entity ... For entities which are not IPv6
// routers and therefore do not forward datagrams, this counter includes datagrams discarded because
// the destination address was not a local address." A multicast group this node does not hold is
// that address; a unicast address of some other node is a valid address elsewhere and forwards.
static DispatchDest d_ip6_dest(uint8_t *restrict work, const uint8_t *dst)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);

    if (ctx->netif != NULL)
    {
        IDEMIP_NETIF_IO(ctx->netif)->addr6_args.addr = dst;
        Netif.find_addr6(ctx->netif);
        if (IDEMIP_NETIF_IO(ctx->netif)->status == IDEMIP_OK)
        {
            return D_DEST_LOCAL;
        }
    }
    if (ctx->loopif != NULL)
    {
        IDEMIP_LOOPIF_IO(ctx->loopif)->match_args.addr6 = dst;
        Loopif.owns6(ctx->loopif);
        if (IDEMIP_LOOPIF_IO(ctx->loopif)->status == IDEMIP_OK && IDEMIP_LOOPIF_IO(ctx->loopif)->owned)
        {
            return D_DEST_LOCAL;
        }
    }
    if (idemip_ip6_addr_type(dst) != IDEMIP_IP6_TYPE_MULTICAST)
    {
        return D_DEST_FORWARD;
    }
    // RFC 4291 sec 2.8: "A host is required to recognize the following addresses as identifying
    // itself: ... The All-Nodes multicast addresses defined in Section 2.7.1." Both of them, and
    // without a group table entry, which is how the solicited-node addresses below are recognized.
    if (idemip_ip6_addr_is_all_nodes(dst))
    {
        return D_DEST_LOCAL;
    }
    if (ctx->mld6 != NULL)
    {
        IDEMIP_MLD6_IO(ctx->mld6)->group_args.group = dst;
        IDEMIP_MLD6_IO(ctx->mld6)->group_args.netif = io->netif;
        Mld6.find(ctx->mld6);
        if (IDEMIP_MLD6_IO(ctx->mld6)->status == IDEMIP_OK)
        {
            return D_DEST_LOCAL;
        }
    }
    // RFC 4291 sec 2.7.1: "A node is required to compute and join the associated Solicited-Node
    // multicast addresses for all unicast and anycast addresses that have been configured."
    if (ctx->ip6_addr == NULL || ctx->netif == NULL)
    {
        return D_DEST_DROP;
    }
    for (uint8_t slot = 0u; slot < (uint8_t)IDEMIP_IP6_ADDRESSES; slot++)
    {
        IDEMIP_NETIF_IO(ctx->netif)->addr6_args.index = io->netif;
        IDEMIP_NETIF_IO(ctx->netif)->addr6_args.slot = slot;
        Netif.get_addr6(ctx->netif);
        if (IDEMIP_NETIF_IO(ctx->netif)->status != IDEMIP_OK)
        {
            continue;
        }
        Ip6AddrIo *i6 = IDEMIP_IP6_ADDR_IO(ctx->ip6_addr);
        i6->solicited_args.addr = IDEMIP_NETIF_IO(ctx->netif)->addr6;
        Ip6Addr.solicited(ctx->ip6_addr);
        if (i6->status == IDEMIP_OK && memcmp(i6->solicited, dst, IDEMIP_IP6_ADDR_LEN) == 0)
        {
            return D_DEST_LOCAL;
        }
    }
    return D_DEST_DROP;
}

// RFC 4443, over the caller's transmit buffer.
// The RFC 4861 sec 4 and RFC 2710 sec 3 message types, which are ICMPv6 types this library
// implements, so RFC 4443 sec 2.4 (b), "If an ICMPv6 informational message of unknown type is
// received, it MUST be silently discarded", is not theirs. The message reaches its module the way
// an RFC 826 one does: this names where it lies and which module owns it, and the caller drives
// nd6, dad, slaac, rdnss or mld6 with it.
//
// RFC 4861 sec 6.1.1, sec 6.1.2, sec 7.1.1, sec 7.1.2 and sec 8.1 each open a MUST-silently-discard
// list, and five entries are on every one of the five: the Hop Limit, the checksum, the Code, a
// per-type minimum length, and every option's length being greater than zero. Those five hold
// whatever the type, so they are checked here beside the length this already held. What stays with
// the consuming module is the rest of each list, which reads fields only that module knows: the
// Target Address not being multicast, the source being link-local, the Solicited flag against a
// multicast destination, and the Redirect naming the current first-hop router. That is the division
// arp_table and d_arp already use.
static void d_icmp6_nd(uint8_t *restrict work, const uint8_t *ip6, const uint8_t *msg, size_t msg_len, uint8_t type)
{
    DispatchIo *io = D_IO(work);
    const DispatchInputArgs *a = &io->input_args;

    io->pcb_kind =
        idemip_icmp6_is_mld(type) ? IDEMIP_DISPATCH_PCB_GROUP : IDEMIP_DISPATCH_PCB_ND;

    // sec 11.2: "The protocol reduces the exposure to the above threats in the absence of
    // authentication by ignoring ND packets received from off-link senders. The Hop Limit field of
    // all received packets is verified to contain 255, the maximum legal value. Because routers
    // decrement the Hop Limit on all packets they forward, received packets containing a Hop Limit
    // of 255 must have originated from a neighbor." RFC 2710 states no such receive rule for its
    // three types, giving sec 3 only as a rule for what a node sends, so this is the five's.
    if (idemip_icmp6_is_nd(type))
    {
        if (idemip_ip6_hop_limit(ip6) != IDEMIP_ICMP6_ND_HOP_LIMIT || idemip_icmp6_code(msg) != 0u)
        {
            d_drop(work, IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_STAT_IF_IN_ERRORS);
            d_bump(work, IDEMIP_STAT_ICMP6_IN_ERRORS);
            d_bump(work, IDEMIP_STAT_IP6_IN_DISCARDS);
            return;
        }
    }

    // RFC 4443 sec 2.3: "an ICMPv6 message ... the checksum ... MUST be verified". icmp6_in keeps
    // this for the types it answers; these do not go through it.
    if (idemip_icmp6_cksum_compute(msg, msg_len, idemip_ip6_src(ip6), idemip_ip6_dst(ip6)) != 0u)
    {
        d_bump(work, IDEMIP_STAT_ICMP6_IN_ERRORS);
        d_drop(work, IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_IP6_IN_DISCARDS);
        return;
    }
    // RFC 2710 sec 3 ends an MLD message at its Multicast Address and gives it no options. RFC 4861
    // sec 4.1 through sec 4.5 fix one length per type, and sec 4.6 puts the options after it:
    // "Nodes MUST silently discard an ND packet that contains an option with length zero."
    // Both refusals below are RFC 2466 ipv6IfIcmpInErrors' "bad length", and the message was already
    // counted in ipv6IfIcmpInMsgs, which "includes all those counted by ipv6IfIcmpInErrors".
    size_t hdr_len = idemip_icmp6_is_mld(type) ? (size_t)IDEMIP_ICMP6_MLD_MSG_LEN : idemip_icmp6_nd_hdr_len(type);
    if (msg_len < hdr_len)
    {
        d_bump(work, IDEMIP_STAT_ICMP6_IN_ERRORS);
        d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_IP6_IN_DISCARDS);
        return;
    }
    if (!idemip_icmp6_is_mld(type) && !idemip_icmp6_nd_opts_ok(msg + hdr_len, msg_len - hdr_len))
    {
        d_bump(work, IDEMIP_STAT_ICMP6_IN_ERRORS);
        d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_IP6_IN_DISCARDS);
        return;
    }
    io->act |= IDEMIP_DISPATCH_ACT_DELIVER;
    d_bump(work, IDEMIP_STAT_IP6_IN_DELIVERS);
    d_delivered(work, a->frame);
}

static void d_icmp6(uint8_t *restrict work, const uint8_t *ip6, size_t total_len)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    const DispatchInputArgs *a = &io->input_args;

    io->pcb_kind = IDEMIP_DISPATCH_PCB_ICMP;
    d_bump(work, IDEMIP_STAT_ICMP6_IN_MSGS);
    const uint8_t *msg = ip6 + io->payload_off - io->ip_off;
    if (io->payload_len >= (size_t)IDEMIP_ICMP6_HDR_LEN)
    {
        uint8_t type = idemip_icmp6_type(msg);
        if (idemip_icmp6_is_nd(type) || idemip_icmp6_is_mld(type))
        {
            d_icmp6_nd(work, ip6, msg, io->payload_len, type);
            return;
        }
    }
    if (ctx->icmp6_in == NULL)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
        return;
    }
    if (a->out == NULL || a->out_cap < (size_t)IDEMIP_ETH_FRAME_MIN)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    const uint8_t *if_addr = NULL;
    if (ctx->netif != NULL)
    {
        for (uint8_t slot = 0u; slot < (uint8_t)IDEMIP_IP6_ADDRESSES; slot++)
        {
            IDEMIP_NETIF_IO(ctx->netif)->addr6_args.index = io->netif;
            IDEMIP_NETIF_IO(ctx->netif)->addr6_args.slot = slot;
            Netif.get_addr6(ctx->netif);
            if (IDEMIP_NETIF_IO(ctx->netif)->status == IDEMIP_OK &&
                IDEMIP_NETIF_IO(ctx->netif)->addr6_state == IDEMIP_NETIF_ADDR6_PREFERRED)
            {
                if_addr = IDEMIP_NETIF_IO(ctx->netif)->addr6;
                break;
            }
        }
    }
    Icmp6InIo *ic = IDEMIP_ICMP6_IN_IO(ctx->icmp6_in);
    ic->recv_args.packet = ip6;
    ic->recv_args.len = total_len;
    ic->recv_args.out = a->out;
    ic->recv_args.out_cap = a->out_cap;
    ic->recv_args.if_addr = if_addr;
    ic->recv_args.dst_anycast = IDEMIP_FALSE;
    Icmp6In.recv(ctx->icmp6_in);
    if (ic->status != IDEMIP_OK)
    {
        d_bump(work, IDEMIP_STAT_ICMP6_IN_ERRORS);
        d_drop(work, IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_STAT_IF_IN_DISCARDS);
        d_bump(work, IDEMIP_STAT_IP6_IN_DISCARDS);
        return;
    }
    // The same decision on the RFC 4443 side. sec 2.4 (b): "If an ICMPv6 informational message of
    // unknown type is received, it MUST be silently discarded", which icmp6_in also raises for a
    // message shorter than its own type requires and for one whose sec 2.3 checksum does not hold.
    // RFC 2466 ipv6IfIcmpInErrors, in the same words RFC 2011 uses for the twin: "determined as
    // having ICMP-specific errors (bad ICMP checksums, bad length, etc.)".
    if ((ic->act & IDEMIP_ICMP6_IN_ACT_DISCARD) != 0u)
    {
        if (ic->bad_len)
        {
            d_bump(work, IDEMIP_STAT_ICMP6_IN_ERRORS);
            d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        }
        else if (!ic->cksum_ok)
        {
            d_bump(work, IDEMIP_STAT_ICMP6_IN_ERRORS);
            d_drop(work, IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_STAT_IF_IN_ERRORS);
        }
        else
        {
            d_drop(work, IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_STAT_IF_IN_DISCARDS);
        }
        d_bump(work, IDEMIP_STAT_IP6_IN_DISCARDS);
        return;
    }
    d_icmp6_type_bump(work, idemip_icmp6_type(ip6 + io->payload_off - io->ip_off));
    if ((ic->act & IDEMIP_ICMP6_IN_ACT_REPLY) != 0u)
    {
        io->out_len = ic->out_len;
        io->act |= IDEMIP_DISPATCH_ACT_SEND;
    }
    if ((ic->act & IDEMIP_ICMP6_IN_ACT_USER) != 0u)
    {
        io->act |= IDEMIP_DISPATCH_ACT_USER;
    }
    io->act |= IDEMIP_DISPATCH_ACT_DELIVER;
    d_bump(work, IDEMIP_STAT_IP6_IN_DELIVERS);
    d_delivered(work, a->frame);
}

// RFC 8200 sec 4.5, over the reassembler. A held fragment pins its receive descriptor.
static void d_ip6_frag(uint8_t *restrict work, const uint8_t *ip6, size_t total_len, size_t frag_hdr)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    const DispatchInputArgs *a = &io->input_args;

    d_bump(work, IDEMIP_STAT_IP6_REASM_REQDS);
    if (ctx->ip6_reass == NULL)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
        return;
    }
    if (!d_pin(work, io->netif, a->desc))
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_NO_DESC, IDEMIP_STAT_IF_IN_DISCARDS);
        d_bump(work, IDEMIP_STAT_IP6_REASM_FAILS);
        return;
    }
    Ip6ReassIo *re = IDEMIP_IP6_REASS_IO(ctx->ip6_reass);
    re->input_args.pkt = ip6;
    re->input_args.len = total_len;
    re->input_args.frag_hdr = frag_hdr;
    re->input_args.desc = IDEMIP_DISPATCH_DESC_HANDLE(io->netif, a->desc);
    re->input_args.now_ms = a->now_ms;
    Ip6Reass.input(ctx->ip6_reass);
    if (re->status != IDEMIP_OK)
    {
        // RFC 2465 ipv6IfStatsReasmFails, "The number of failures detected by the IPv6 re-assembly
        // algorithm (for whatever reason: timed out, errors, etc.)". Not ipv6IfStatsInDiscards:
        // "this counter does not include any datagrams discarded while awaiting re-assembly".
        d_unpin(work, io->netif, a->desc);
        d_drop(work, IDEMIP_DISPATCH_DROP_REASS, IDEMIP_STAT_IF_IN_DISCARDS);
        d_bump(work, IDEMIP_STAT_IP6_REASM_FAILS);
        return;
    }
    io->act |= IDEMIP_DISPATCH_ACT_PINNED;
    io->datagram = re->datagram;
    if (re->complete)
    {
        io->act |= IDEMIP_DISPATCH_ACT_REASSEMBLED;
        d_bump(work, IDEMIP_STAT_IP6_REASM_OKS);
    }
}

// RFC 8200 sec 4: the chain is walked to the upper-layer header, then RFC 1122 sec 3.1 (5) hands the
// message to the module that owns it.
static void d_ip6(uint8_t *restrict work, const uint8_t *ip6, size_t avail)
{
    DispatchIo *io = D_IO(work);
    io->ip_version = IDEMIP_IP6_VERSION;
    d_bump(work, IDEMIP_STAT_IP6_IN_RECEIVES);

    if (avail < IDEMIP_IPV6_HDR_LEN || idemip_ip6_version(ip6) != IDEMIP_IP6_VERSION)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_IP6_IN_HDR_ERRORS);
        return;
    }
    size_t total_len = (size_t)IDEMIP_IPV6_HDR_LEN + (size_t)idemip_ip6_payload_len(ip6);
    if (total_len > avail)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_IP6_IN_HDR_ERRORS);
        return;
    }
    IdemIpIp6Chain chain = idemip_ip6_walk(ip6, total_len);
    if (!chain.ok)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_IP6_IN_HDR_ERRORS);
        return;
    }
    DispatchDest dest = d_ip6_dest(work, idemip_ip6_dst(ip6));
    if (dest == D_DEST_FORWARD)
    {
        io->act |= IDEMIP_DISPATCH_ACT_FORWARD;
        return;
    }
    if (dest == D_DEST_DROP)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_IP_ADDRESS, IDEMIP_STAT_IF_IN_DISCARDS);
        d_bump(work, IDEMIP_STAT_IP6_IN_ADDR_ERRORS);
        return;
    }
    // RFC 8200 sec 4.4: "If, while processing a received packet, a node encounters a Routing header
    // with an unrecognized Routing Type value ... If Segments Left is non-zero, the node must discard
    // the packet and send an ICMP Parameter Problem, Code 0, message to the packet's Source Address,
    // pointing to the unrecognized Routing Type." A node only processes the Routing header of a packet
    // addressed to it, so this sits behind the local test. The walk records nothing for a Segments
    // Left of zero, which the same section ignores.
    if (chain.routed)
    {
        io->err_ptr = (uint16_t)(chain.routing_hdr + IDEMIP_IP6_RT_OFF_TYPE);
        d_drop(work, IDEMIP_DISPATCH_DROP_IP6_ROUTING, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_IP6_IN_HDR_ERRORS);
        return;
    }
    // RFC 8200 sec 4.2, over an option this node does not recognize whose two high-order bits are not
    // 00: "01 - discard the packet", "10 - discard the packet and, regardless of whether or not the
    // packet's Destination Address was a multicast address, send an ICMP Parameter Problem, Code 2",
    // "11 - discard the packet and, only if the packet's Destination Address was not a multicast
    // address, send an ICMP Parameter Problem, Code 2". The discard is the same in all three.
    if (chain.refused)
    {
        io->err_ptr = (uint16_t)chain.opt_hdr;
        d_drop(work, IDEMIP_DISPATCH_DROP_IP6_OPTION, IDEMIP_STAT_IF_IN_ERRORS);
        d_bump(work, IDEMIP_STAT_IP6_IN_HDR_ERRORS);
        return;
    }
    if (chain.fragmented)
    {
        // RFC 6980 sec 5: "Nodes MUST silently ignore the following Neighbor Discovery and SEcure
        // Neighbor Discovery messages if the packets carrying them include an IPv6 Fragmentation
        // Header". The message type is readable on the fragment that carries the ICMPv6 header, which
        // is the one at Fragment Offset zero; dropping it leaves the rest of a multi-fragment message
        // with no first fragment to complete against, and an atomic fragment is refused outright.
        if (chain.next_hdr == IDEMIP_IP6_NH_ICMPV6 &&
            idemip_ip6_frag_offset_bytes(ip6 + chain.frag_hdr) == 0u && chain.offset < total_len &&
            idemip_icmp6_is_nd(ip6[chain.offset]))
        {
            d_drop(work, IDEMIP_DISPATCH_DROP_IP6_FRAG_ND, IDEMIP_STAT_IF_IN_DISCARDS);
            return;
        }
        d_ip6_frag(work, ip6, total_len, chain.frag_hdr);
        return;
    }
    io->proto = chain.next_hdr;
    io->payload_off = io->ip_off + chain.offset;
    io->payload_len = total_len - chain.offset;

    switch (chain.next_hdr)
    {
    case IDEMIP_IP6_NH_ICMPV6:
        d_icmp6(work, ip6, total_len);
        return;
#if IDEMIP_ENABLE_UDP
    case IDEMIP_IP6_NH_UDP:
        d_udp(work, ip6 + IDEMIP_IP6_OFF_DST, ip6 + IDEMIP_IP6_OFF_SRC, IDEMIP_IP6_VERSION, IDEMIP_FALSE);
        return;
    case IDEMIP_UDPLITE_PROTO:
        d_udp(work, ip6 + IDEMIP_IP6_OFF_DST, ip6 + IDEMIP_IP6_OFF_SRC, IDEMIP_IP6_VERSION, IDEMIP_TRUE);
        return;
#endif
#if IDEMIP_ENABLE_TCP
    case IDEMIP_IP6_NH_TCP:
        d_tcp(work, ip6 + IDEMIP_IP6_OFF_DST, ip6 + IDEMIP_IP6_OFF_SRC, IDEMIP_IP6_VERSION);
        return;
#endif
    default:
        break;
    }
    d_raw(work, ip6 + IDEMIP_IP6_OFF_DST, ip6 + IDEMIP_IP6_OFF_SRC, IDEMIP_IP6_VERSION);
}

#endif // IDEMIP_ENABLE_IPV6

// ===========================================================================
// The link layer, and the policy the tag decides nothing about
// ===========================================================================

// True when the frame goes on. A false answer has already bumped its counter and set the reason.
static idemip_bool d_link(uint8_t *restrict work, size_t *payload_off)
{
    DispatchCtx *ctx = D_CTX(work);
    DispatchIo *io = D_IO(work);
    const DispatchInputArgs *a = &io->input_args;
    DispatchIfRow *row = D_IF_AT(work, io->netif);

    if (a->len < IDEMIP_ETH_HDR_LEN)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        return IDEMIP_FALSE;
    }
    if (ctx->vlan == NULL)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_STAT_IF_COUNT);
        return IDEMIP_FALSE;
    }
    VlanIo *v = IDEMIP_VLAN_IO(ctx->vlan);
    v->parse_args.frame = a->frame;
    v->parse_args.len = a->len;
    Vlan.parse(ctx->vlan);
    if (v->status != IDEMIP_OK)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_STAT_IF_IN_ERRORS);
        return IDEMIP_FALSE;
    }
    io->type = v->type;
    io->tagged = v->tagged;
    io->pcp = v->pcp;
    *payload_off = v->payload_off;
    if (!v->tagged)
    {
        return IDEMIP_TRUE;
    }
    io->vid = v->vid;
    // RFC 6325 sec 4.1.1: "The VLAN ID 0xFFF MUST NOT be used", and a receiver "MUST discard any
    // frame" carrying it. A value the standard forbids on the wire is a malformed frame, not a
    // membership this interface declined.
    if (v->vid_reserved)
    {
        d_drop(work, IDEMIP_DISPATCH_DROP_VLAN_RESERVED, IDEMIP_STAT_IF_IN_ERRORS);
        return IDEMIP_FALSE;
    }
    // An untagged interface accepts every frame and reads the payload behind whatever tag it has.
    if (!row->tagged)
    {
        return IDEMIP_TRUE;
    }
    if (v->vid == row->vid)
    {
        return IDEMIP_TRUE;
    }
    // A tagged interface discards a frame outside its own VLAN. RFC 1213 ifInDiscards: "chosen to be
    // discarded even though no errors had been detected". The VLAN ID rises and falls rather than
    // accumulating, so it is assigned (RFC 1155 sec 3.2.3.4) and never bumped.
    row->last_vid = v->vid;
    io->last_vid = v->vid;
    d_drop(work, IDEMIP_DISPATCH_DROP_VLAN_POLICY, IDEMIP_STAT_IF_IN_DISCARDS);
    return IDEMIP_FALSE;
}

// --- the entries -----------------------------------------------------------

static void dispatch_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_DISPATCH_OFF_CTX, 0, IDEMIP_DISPATCH_OFF_END - IDEMIP_DISPATCH_OFF_CTX);
    for (uint8_t i = 0u; i < (uint8_t)IDEMIP_NETIF_COUNT; i++)
    {
        D_IF_AT(work, i)->last_vid = IDEMIP_DISPATCH_VID_NONE;
    }
    DispatchCtx *ctx = D_CTX(work);
#if IDEMIP_ENABLE_TCP
    ctx->hold_desc = IDEMIP_DISPATCH_DESC_NONE;
    ctx->hold_netif = IDEMIP_DISPATCH_NETIF_NONE;
#endif
    ctx->ready = DISPATCH_READY;
    D_IO(work)->status = IDEMIP_OK;
}

static void dispatch_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DispatchIo *io = D_IO(work);
    io->status = IDEMIP_ERR;
    if (!d_ready(work))
    {
        return;
    }
    DispatchCtx *ctx = D_CTX(work);
    const DispatchBindArgs *b = &io->bind_args;
    ctx->stats = b->stats;
    ctx->netif = b->netif;
    ctx->loopif = b->loopif;
    ctx->vlan = b->vlan;
#if IDEMIP_ENABLE_IPV4
    ctx->arp = b->arp;
    ctx->ip4_addr = b->ip4_addr;
    ctx->ip4_reass = b->ip4_reass;
    ctx->icmp_in = b->icmp_in;
    ctx->igmp = b->igmp;
#endif
#if IDEMIP_ENABLE_IPV6
    ctx->ip6_addr = b->ip6_addr;
    ctx->ip6_reass = b->ip6_reass;
    ctx->icmp6_in = b->icmp6_in;
    ctx->mld6 = b->mld6;
#endif
#if IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6
    ctx->raw_pcb = b->raw_pcb;
#endif
#if IDEMIP_ENABLE_UDP
    ctx->udp_pcb = b->udp_pcb;
    ctx->udplite = b->udplite;
#endif
#if IDEMIP_ENABLE_TCP
    ctx->tcp_pcb = b->tcp_pcb;
    ctx->tcp_in = b->tcp_in;
#endif
    io->status = IDEMIP_OK;
}

// An interface is a member of one VLAN or of none. RFC 6325 sec 4.1.1 runs the usable range 0x001
// through 0xFFE, so a membership outside it names no VLAN and is refused.
static void dispatch_if_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DispatchIo *io = D_IO(work);
    io->status = IDEMIP_ERR;
    if (!d_ready(work) || io->if_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    if (io->if_args.tagged &&
        (io->if_args.vid < IDEMIP_VLAN_VID_FIRST || io->if_args.vid > IDEMIP_VLAN_VID_LAST))
    {
        return;
    }
    DispatchIfRow *row = D_IF_AT(work, io->if_args.index);
    row->dma = io->if_args.dma;
    row->vid = io->if_args.vid;
    row->tagged = (uint8_t)(io->if_args.tagged ? 1u : 0u);
    io->status = IDEMIP_OK;
}

static void dispatch_if_get(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DispatchIo *io = D_IO(work);
    io->status = IDEMIP_ERR;
    if (!d_ready(work) || io->if_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    DispatchIfRow *row = D_IF_AT(work, io->if_args.index);
    io->netif = io->if_args.index;
    io->vid = row->vid;
    io->tagged = (idemip_bool)(row->tagged != 0u);
    io->last_vid = row->last_vid;
    io->status = IDEMIP_OK;
}

static void dispatch_input(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DispatchIo *io = D_IO(work);
    d_reset(io);
    io->status = IDEMIP_ERR;
    if (!d_ready(work))
    {
        return;
    }
    const DispatchInputArgs *a = &io->input_args;
    if (a->frame == NULL || a->len == 0u || a->netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    io->netif = a->netif;
    io->desc = a->desc;
    io->status = IDEMIP_OK;

    // RFC 1213 sec 6.4 ifInOctets: "The total number of octets received on the interface", whatever
    // becomes of the frame after this.
    d_if_bump(work, a->netif, IDEMIP_STAT_IF_IN_OCTETS, (uint32_t)a->len);

    size_t payload_off = IDEMIP_ETH_OFF_PAYLOAD;
    if (!d_link(work, &payload_off))
    {
        return;
    }
    io->ip_off = payload_off;
    size_t avail = a->len - payload_off;

    switch (io->type)
    {
#if IDEMIP_ENABLE_IPV4
    case IDEMIP_ETHERTYPE_IPV4:
        d_ip4(work, a->frame + payload_off, avail);
        return;
    case IDEMIP_ETHERTYPE_ARP:
        d_arp(work, a->frame + payload_off, avail);
        return;
#endif
#if IDEMIP_ENABLE_IPV6
    case IDEMIP_ETHERTYPE_IPV6:
        d_ip6(work, a->frame + payload_off, avail);
        return;
#endif
    default:
        break;
    }
    // RFC 1213 ifInUnknownProtos: "discarded because of an unknown or unsupported protocol". The
    // frame is intact and the protocol is not ours.
    d_drop(work, IDEMIP_DISPATCH_DROP_ETHERTYPE, IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS);
}

#if IDEMIP_ENABLE_TCP

// RFC 9293 sec 3.10.7.4: "Segments with higher beginning sequence numbers SHOULD be held for later
// processing (SHLD-31)." This is that later processing: the head of the out-of-order queue is
// delivered once RCV.NXT has reached it, RCV.NXT advances over it, and the entry is freed.
//
// The descriptor the delivery names stays pinned until the call after, so the caller reads the
// octets between the two calls.
static void dispatch_tcp_deliver(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DispatchIo *io = D_IO(work);
    d_reset(io);
    io->status = IDEMIP_ERR;
    if (!d_ready(work))
    {
        return;
    }
    DispatchCtx *ctx = D_CTX(work);
    if (ctx->tcp_pcb == NULL || io->tcp_args.pcb >= IDEMIP_TCP_PCBS)
    {
        return;
    }
    d_unpin(work, ctx->hold_netif, ctx->hold_desc);
    ctx->hold_desc = IDEMIP_DISPATCH_DESC_NONE;
    ctx->hold_netif = IDEMIP_DISPATCH_NETIF_NONE;

    uint16_t pcb = io->tcp_args.pcb;
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(ctx->tcp_pcb);
    tp->pcb_args.index = pcb;
    TcpPcb.load(ctx->tcp_pcb);
    if (tp->status != IDEMIP_OK)
    {
        return;
    }
    io->pcb_kind = IDEMIP_DISPATCH_PCB_TCP;
    io->pcb = pcb;
    io->netif = D_PCB_AT(work, pcb)->netif;
    if (tp->info.ooseq == IDEMIP_TCP_PCB_NONE)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    uint32_t rcv_nxt = tp->vars.rcv_nxt;
    uint16_t head = tp->info.ooseq;
    tp->oos_args.index = head;
    TcpPcb.oos_load(ctx->tcp_pcb);
    if (tp->status != IDEMIP_OK)
    {
        return;
    }
    TcpPcbOosInfo held = tp->oos;
    if (d_seq_from(held.seq, rcv_nxt) != 0u && d_seq_from(held.seq, rcv_nxt) < 0x80000000u)
    {
        // The head begins above RCV.NXT, so the gap in front of it is not filled yet.
        io->status = IDEMIP_BUSY;
        return;
    }
    uint32_t skip = d_seq_from(rcv_nxt, held.seq);
    io->desc = held.desc;
    io->text_seq = rcv_nxt;
    if (skip < (uint32_t)held.len)
    {
        // sec 3.10.7.4: "If a segment's contents straddle the boundary between old and new, only the
        // new parts are processed."
        io->text_off = (uint16_t)(held.offset + skip);
        io->text_len = (uint16_t)((uint32_t)held.len - skip);
        tp->vars.rcv_nxt = rcv_nxt + (uint32_t)io->text_len;
        tp->pcb_args.index = pcb;
        TcpPcb.store(ctx->tcp_pcb);
        io->act |= IDEMIP_DISPATCH_ACT_DELIVER | IDEMIP_DISPATCH_ACT_TCP;
        D_PCB_AT(work, pcb)->ack_owed = 1u;
        io->act |= IDEMIP_DISPATCH_ACT_ACK_OWED;
    }
    tp->oos_args.index = head;
    tp->oos_args.pcb = pcb;
    TcpPcb.oos_free(ctx->tcp_pcb);
    ctx->hold_desc = held.desc;
    ctx->hold_netif = io->netif;
    io->status = IDEMIP_OK;
}

// RFC 9293 sec 3.10.7.4 (MUST-58, MUST-59). One acknowledgment per connection per batch, of the
// sec 3.10.7.4 seventh form "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>".
static void dispatch_tcp_ack(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DispatchIo *io = D_IO(work);
    d_reset(io);
    io->status = IDEMIP_ERR;
    if (!d_ready(work))
    {
        return;
    }
    DispatchCtx *ctx = D_CTX(work);
    if (ctx->tcp_pcb == NULL)
    {
        return;
    }
    io->status = IDEMIP_BUSY;
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_TCP_PCBS; i++)
    {
        DispatchPcbRow *row = D_PCB_AT(work, i);
        if (row->ack_owed == 0u)
        {
            continue;
        }
        row->ack_owed = 0u;
        TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(ctx->tcp_pcb);
        tp->pcb_args.index = i;
        TcpPcb.load(ctx->tcp_pcb);
        if (tp->status != IDEMIP_OK)
        {
            continue; // the connection closed between the segment and the flush
        }
        io->pcb_kind = IDEMIP_DISPATCH_PCB_TCP;
        io->pcb = i;
        io->netif = row->netif;
        io->reply.seq = tp->vars.snd_nxt;
        io->reply.ack = tp->vars.rcv_nxt;
        io->reply.flags = IDEMIP_TCP_ACK;
        io->tcp_act = IDEMIP_TCP_IN_ACT_ACK;
        io->act |= IDEMIP_DISPATCH_ACT_TCP;
        io->status = IDEMIP_OK;
        return;
    }
}

#endif // IDEMIP_ENABLE_TCP

const DispatchNs Dispatch = {.clear = dispatch_clear,
                             .bind = dispatch_bind,
                             .if_bind = dispatch_if_bind,
                             .if_get = dispatch_if_get,
                             .input = dispatch_input,
#if IDEMIP_ENABLE_TCP
                             .tcp_deliver = dispatch_tcp_deliver,
                             .tcp_ack = dispatch_tcp_ack
#endif
};

IDEMIP_END_DECLS
