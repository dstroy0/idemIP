// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Two idemIP instances, wired back to back through test/support/fake_phy.h, driven by one tick
// loop. Each instance is its own set of borrows, and this suite exists to prove the property the
// whole storage model rests on: two instances share NOT ONE BYTE, and driving A changes nothing in
// B except through a frame on the wire.
//
// On top of that it runs the exchanges the stack exists for, end to end:
//   RFC 826  address resolution, with the third-party case that must create no entry
//   RFC 9293 sec 3.5 Figure 6 three-way handshake, data both directions, sec 3.6 Figure 12 four-way close
//   RFC 768  one datagram each way
//   RFC 792  an Echo and its Reply
//   RFC 791  sec 3.2 an oversized datagram fragmented and reassembled
// and writes every frame that crossed the wire to a .pcap through test/support/pcap.h.
//
// THE TICK LOOP IS THIS SUITE'S. src/core/tick.h and src/core/dispatch.h are not in this
// checkout, so the three stages are written here by hand: drain receive,
// run each service's timers, flush deferred transmit. With those two units present the loop moves
// into them and this file calls them instead.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/idemip.h"

#include "support/fake_phy.h"
#include "support/pcap.h"

#include <string.h>
#include <unity.h>

IDEMIP_FAKE_PHY_STORAGE;
IDEMIP_FAKE_PHY_DRIVER(0);
IDEMIP_FAKE_PHY_DRIVER(1);

// --- the two instances -------------------------------------------------------

#define CANARY 0x5Au
#define CANARY_LEN 16u

// Every borrow one instance takes, each followed by a canary so a write past a map is visible and
// so no unit's span can reach the next one's. The whole struct is one object, which is what a
// memcmp against the other instance compares.
typedef struct
{
    _Alignas(IDEMIP_ALIGN) uint8_t phy[IDEMIP_PHY_BORROW];
    uint8_t k_phy[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t dma[IDEMIP_DMA_BORROW];
    uint8_t k_dma[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t netif[IDEMIP_NETIF_BORROW];
    uint8_t k_netif[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t arp[IDEMIP_ARP_BORROW];
    uint8_t k_arp[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t reass[IDEMIP_IP4_REASS_BORROW];
    uint8_t k_reass[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t frag[IDEMIP_IP4_FRAG_BORROW];
    uint8_t k_frag[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t icmp[IDEMIP_ICMP_IN_BORROW];
    uint8_t k_icmp[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t udp[IDEMIP_UDP_PCB_BORROW];
    uint8_t k_udp[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t tpcb[IDEMIP_TCP_PCB_BORROW];
    uint8_t k_tpcb[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t tin[IDEMIP_TCP_IN_BORROW];
    uint8_t k_tin[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t tout[IDEMIP_TCP_OUT_BORROW];
    uint8_t k_tout[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t isn[IDEMIP_TCP_ISN_BORROW];
    uint8_t k_isn[CANARY_LEN];
    _Alignas(IDEMIP_ALIGN) uint8_t stats[IDEMIP_STATS_BORROW];
    uint8_t k_stats[CANARY_LEN];
} Borrows;

// The connection one node runs, which is the application's own state and no unit's.
typedef struct
{
    uint16_t tcb;
    uint16_t listener;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t remote_ip;
    IdemIpTcpState state;
    uint8_t rx[512];
    size_t rx_len;
    int established;
    int fin_seen;
    int deleted;
} TcpApp;

/** @brief What a descriptor index means when the octets are not in a pinned receive buffer. */
#define DESC_NONE 0xFFFFu

typedef struct
{
    Borrows b;
    IdemIpFakePhy *rig;
    const IdemIpPhyDriver *drv;
    uint8_t mac[IDEMIP_MAC_LEN];
    uint32_t ip;
    uint32_t mask;

    // A transmit descriptor is claimed only once there is something to post, because dma.h has no
    // entry that gives an unposted one back, so a build runs here first and the claim copies it.
    uint8_t scratch[IDEMIP_ETH_MAX_PAYLOAD];

    uint16_t udp_pcb;
    uint8_t udp_rx[2048];
    size_t udp_rx_len;
    uint16_t udp_rx_src_port;
    uint32_t udp_rx_src_ip;
    int udp_rx_count;
    int udp_no_binding;

    int icmp_echoes;
    int icmp_replies;
    uint16_t icmp_reply_id;
    uint16_t icmp_reply_seq;

    uint8_t big_rx[2048];
    size_t big_rx_len;
    int reassembled;
    int fragments_held;
    uint16_t max_pinned; // the most receive descriptors pinned at once, IDEMIP_MAX_PINNED_FRAMES bounds it

    int arp_requests_out;
    int arp_replies_out;

    // RFC 9293 sec 3.10.7.4 (MUST-58, MUST-59): a pure acknowledgment is held until every queued
    // segment has been processed, so a drain of several segments sends one ACK and not one each.
    int ack_owed;
    uint16_t ack_tcb;
    int acks_sent;
    int acks_aggregated;

    int oos_held;
    int oos_delivered;

    TcpApp tcp;
} Node;

// The driver's frame storage: not a borrow, so IDEMIP_TOTAL_BORROW does not count it. A base has to
// start on a cache line, which is what Dma.bind checks.
static _Alignas(IDEMIP_CACHE_LINE_BYTES) uint8_t g_rx_bufs[2][IDEMIP_RX_DESCRIPTORS * IDEMIP_DMA_BUF_STRIDE];
static _Alignas(IDEMIP_CACHE_LINE_BYTES) uint8_t g_tx_bufs[2][IDEMIP_TX_DESCRIPTORS * IDEMIP_DMA_BUF_STRIDE];

static Node g_a;
static Node g_b;
static Borrows g_snapshot;

static uint32_t g_now_ms;
static IdemIpPcap g_pcap;
static int g_pcap_open;

#define TICK_MS 10u

static const uint8_t MAC_A[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
static const uint8_t MAC_B[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};
static const uint8_t MAC_BCAST[IDEMIP_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define IP_A 0xC0A80102u  // 192.168.1.2
#define IP_B 0xC0A80103u  // 192.168.1.3
#define IP_C 0xC0A80109u  // 192.168.1.9, a third party neither end holds
#define IP_MASK 0xFFFFFF00u

#define UDP_PORT_A 4000u
#define UDP_PORT_B 4001u
#define TCP_PORT_B 7u

static const uint8_t ISN_SECRET_A[IDEMIP_TCP_ISN_SECRET_BYTES] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                                  0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01};
static const uint8_t ISN_SECRET_B[IDEMIP_TCP_ISN_SECRET_BYTES] = {0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6, 0x97, 0x88,
                                                                  0x79, 0x6A, 0x5B, 0x4C, 0x3D, 0x2E, 0x1F, 0x00};

// --- canaries ----------------------------------------------------------------

static void arm_canaries(Borrows *w)
{
    memset(w->k_phy, CANARY, CANARY_LEN);
    memset(w->k_dma, CANARY, CANARY_LEN);
    memset(w->k_netif, CANARY, CANARY_LEN);
    memset(w->k_arp, CANARY, CANARY_LEN);
    memset(w->k_reass, CANARY, CANARY_LEN);
    memset(w->k_frag, CANARY, CANARY_LEN);
    memset(w->k_icmp, CANARY, CANARY_LEN);
    memset(w->k_udp, CANARY, CANARY_LEN);
    memset(w->k_tpcb, CANARY, CANARY_LEN);
    memset(w->k_tin, CANARY, CANARY_LEN);
    memset(w->k_tout, CANARY, CANARY_LEN);
    memset(w->k_isn, CANARY, CANARY_LEN);
    memset(w->k_stats, CANARY, CANARY_LEN);
}

static void check_one_canary(const uint8_t *k, const char *what)
{
    for (size_t i = 0; i < CANARY_LEN; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, k[i], what);
    }
}

static void check_canaries(const Borrows *w)
{
    check_one_canary(w->k_phy, "a write landed past IDEMIP_PHY_BORROW");
    check_one_canary(w->k_dma, "a write landed past IDEMIP_DMA_BORROW");
    check_one_canary(w->k_netif, "a write landed past IDEMIP_NETIF_BORROW");
    check_one_canary(w->k_arp, "a write landed past IDEMIP_ARP_BORROW");
    check_one_canary(w->k_reass, "a write landed past IDEMIP_IP4_REASS_BORROW");
    check_one_canary(w->k_frag, "a write landed past IDEMIP_IP4_FRAG_BORROW");
    check_one_canary(w->k_icmp, "a write landed past IDEMIP_ICMP_IN_BORROW");
    check_one_canary(w->k_udp, "a write landed past IDEMIP_UDP_PCB_BORROW");
    check_one_canary(w->k_tpcb, "a write landed past IDEMIP_TCP_PCB_BORROW");
    check_one_canary(w->k_tin, "a write landed past IDEMIP_TCP_IN_BORROW");
    check_one_canary(w->k_tout, "a write landed past IDEMIP_TCP_OUT_BORROW");
    check_one_canary(w->k_isn, "a write landed past IDEMIP_TCP_ISN_BORROW");
    check_one_canary(w->k_stats, "a write landed past IDEMIP_STATS_BORROW");
}

// --- transmit ----------------------------------------------------------------

// A transmit descriptor to build into, with its index. Null when the ring had no room.
static uint8_t *node_tx_claim(Node *n, uint8_t *desc)
{
    Dma.tx_take(n->b.dma);
    if (IDEMIP_DMA_IO(n->b.dma)->status != IDEMIP_OK)
    {
        return NULL;
    }
    *desc = IDEMIP_DMA_IO(n->b.dma)->index;
    return IDEMIP_DMA_IO(n->b.dma)->buf;
}

static idemip_bool node_tx_post(Node *n, uint8_t desc, size_t frame_len)
{
    IDEMIP_DMA_IO(n->b.dma)->desc_args.index = desc;
    IDEMIP_DMA_IO(n->b.dma)->desc_args.len = (uint16_t)frame_len;
    Dma.tx_post(n->b.dma);
    return (idemip_bool)(IDEMIP_DMA_IO(n->b.dma)->status == IDEMIP_OK);
}

// Frame an IPv4 datagram already written at @p frame + IDEMIP_ETH_HDR_LEN and post it. Its Total
// Length is the datagram's own, RFC 894's pad being no part of it.
static idemip_bool node_send_frame(Node *n, uint8_t *frame, uint8_t desc, const uint8_t *dst_mac, uint16_t ethertype,
                                   size_t payload_len)
{
    idemip_eth_build(frame, dst_mac, n->mac, ethertype);
    size_t padded = idemip_eth_pad(frame, payload_len);
    return node_tx_post(n, desc, IDEMIP_ETH_HDR_LEN + padded);
}

// One RFC 791 datagram carrying @p plen octets of transport already at
// @p frame + IDEMIP_ETH_HDR_LEN + IDEMIP_IPV4_HDR_LEN.
typedef struct
{
    Node *n;
    uint8_t *frame;
    uint8_t desc;
    const uint8_t *dst_mac;
    uint32_t dst_ip;
    uint8_t proto;
    uint16_t id;
    size_t plen;
} NodeSendIp4Args;

static idemip_bool node_send_ip4_ctx(const NodeSendIp4Args *args)
{
    IdemIpIp4Fields f;

    memset(&f, 0, sizeof f);
    f.total_len = (uint16_t)(IDEMIP_IPV4_HDR_LEN + args->plen);
    f.id = args->id;
    f.ttl = (uint8_t)IDEMIP_IP_DEFAULT_TTL;
    f.proto = args->proto;
    f.src = args->n->ip;
    f.dst = args->dst_ip;
    idemip_ip4_build(args->frame + IDEMIP_ETH_HDR_LEN, &f);
    return node_send_frame(args->n, args->frame, args->desc, args->dst_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4, IDEMIP_IPV4_HDR_LEN + args->plen);
}

#define node_send_ip4(...) IDEMIP_CALL(node_send_ip4_ctx, NodeSendIp4Args, __VA_ARGS__)

// The RFC 826 REQUEST for @p tpa, broadcast, which "Packet Generation" sends when the pair is
// missing from the translation table.
static idemip_bool node_send_arp_request(Node *n, uint32_t tpa)
{
    uint8_t desc = 0;
    uint8_t *frame = node_tx_claim(n, &desc);

    if (frame == NULL)
    {
        return IDEMIP_FALSE;
    }
    idemip_arp_build_request(frame + IDEMIP_ETH_HDR_LEN, n->mac, n->ip, tpa);
    n->arp_requests_out++;
    return node_send_frame(n, frame, desc, MAC_BCAST, (uint16_t)IDEMIP_ETHERTYPE_ARP, IDEMIP_ARP_LEN);
}

// The hardware address behind @p ip, or null with a REQUEST on the wire. RFC 826 "Packet
// Generation": a caller with no translation is told the packet is thrown away, "on the assumption
// the packet will be retransmitted by a higher network layer".
static const uint8_t *node_resolve(Node *n, uint32_t ip)
{
    IDEMIP_ARP_IO(n->b.arp)->now_ms = g_now_ms;
    IDEMIP_ARP_IO(n->b.arp)->find_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(n->b.arp)->find_args.spa = ip;
    ArpTable.find(n->b.arp);
    if (IDEMIP_ARP_IO(n->b.arp)->status == IDEMIP_OK)
    {
        return IDEMIP_ARP_IO(n->b.arp)->mac;
    }
    (void)node_send_arp_request(n, ip);
    return NULL;
}

// --- receive: the four protocol paths ----------------------------------------

static void node_arp_in(Node *n, const uint8_t *packet)
{
    ArpTableIo *io = IDEMIP_ARP_IO(n->b.arp);

    io->now_ms = g_now_ms;
    io->input_args.packet = packet;
    io->input_args.local_pa = n->ip;
    io->input_args.netif = 0u;
    ArpTable.input(n->b.arp);
    if (io->status != IDEMIP_OK || !io->reply_owed)
    {
        return;
    }
    // RFC 826 "Packet Reception", the request branch: "Swap hardware and protocol fields ... Set the
    // ar$op field to ares_op$REPLY. Send the packet to the (new) target hardware address on the same
    // hardware on which the request was received."
    uint8_t desc = 0;
    uint8_t *frame = node_tx_claim(n, &desc);
    if (frame == NULL)
    {
        return;
    }
    memcpy(frame + IDEMIP_ETH_HDR_LEN, packet, IDEMIP_ARP_LEN);
    idemip_arp_reply_in_place(frame + IDEMIP_ETH_HDR_LEN, n->mac);
    n->arp_replies_out++;
    (void)node_send_frame(n, frame, desc, idemip_arp_sha(packet), (uint16_t)IDEMIP_ETHERTYPE_ARP, IDEMIP_ARP_LEN);
}

static void node_icmp_in(Node *n, const uint8_t *ip, size_t len)
{
    IcmpInIo *io = IDEMIP_ICMP_IN_IO(n->b.icmp);
    uint8_t desc = 0;

    io->recv_args.datagram = ip;
    io->recv_args.len = len;
    io->recv_args.out = n->scratch;
    io->recv_args.out_cap = IDEMIP_ETH_MAX_PAYLOAD - IDEMIP_IPV4_HDR_LEN;
    io->recv_args.if_addr = n->ip;
    io->recv_args.if_mask = n->mask;
    io->recv_args.link_bcast = IDEMIP_FALSE;
    IcmpIn.recv(n->b.icmp);
    if (io->status != IDEMIP_OK)
    {
        return;
    }
    if (io->type == (uint8_t)IDEMIP_ICMP_ECHO_REPLY)
    {
        n->icmp_replies++;
        n->icmp_reply_id = io->id;
        n->icmp_reply_seq = io->seq;
        return;
    }
    if ((io->act & IDEMIP_ICMP_IN_ACT_REPLY) == 0u)
    {
        return;
    }
    n->icmp_echoes++;
    const uint8_t *dst_mac = node_resolve(n, io->dst);
    if (dst_mac == NULL)
    {
        return;
    }
    size_t out_len = io->out_len;
    uint32_t dst = io->dst;
    uint8_t *frame = node_tx_claim(n, &desc);
    if (frame == NULL)
    {
        return;
    }
    memcpy(frame + IDEMIP_ETH_HDR_LEN + IDEMIP_IPV4_HDR_LEN, n->scratch, out_len);
    (void)node_send_ip4(n, frame, desc, dst_mac, dst, (uint8_t)IDEMIP_IP4_PROTO_ICMP, 0x1234u, out_len);
}

static void node_udp_in(Node *n, const uint8_t *ip, size_t len)
{
    const uint8_t *udp = ip + idemip_ip4_hdr_len(ip);
    uint16_t udp_len = idemip_ip4_payload_len(ip);
    uint8_t local16[IDEMIP_TCP_PCB_ADDR_BYTES];
    uint8_t remote16[IDEMIP_TCP_PCB_ADDR_BYTES];

    (void)len;
    if (udp_len < IDEMIP_UDP_HDR_LEN || !idemip_udp_len_valid(udp))
    {
        return;
    }
    if (idemip_udp_cksum_present(udp) &&
        !idemip_udp_cksum_valid(udp, udp_len, idemip_ip4_src(ip), idemip_ip4_dst(ip)))
    {
        return;
    }
    memset(local16, 0, sizeof local16);
    memset(remote16, 0, sizeof remote16);
    idemip_wr32(local16, idemip_ip4_dst(ip));
    idemip_wr32(remote16, idemip_ip4_src(ip));

    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(n->b.udp);
    io->find_args.local_ip = local16;
    io->find_args.remote_ip = remote16;
    io->find_args.local_port = idemip_udp_dst_port(udp);
    io->find_args.remote_port = idemip_udp_src_port(udp);
    io->find_args.cksum_len = 0u;
    io->find_args.ip_version = 4u;
    io->find_args.local_zone = 0u;
    io->find_args.remote_zone = 0u;
    io->find_args.netif = 0u;
    UdpPcb.find(n->b.udp);
    if (io->status != IDEMIP_OK)
    {
        // RFC 1122 sec 4.1.3.1: no binding is where "UDP SHOULD send an ICMP Port Unreachable".
        n->udp_no_binding++;
        return;
    }
    size_t plen = (size_t)idemip_udp_payload_len(udp);
    if (plen > sizeof n->udp_rx)
    {
        plen = sizeof n->udp_rx;
    }
    memcpy(n->udp_rx, udp + IDEMIP_UDP_HDR_LEN, plen);
    n->udp_rx_len = plen;
    n->udp_rx_src_port = idemip_udp_src_port(udp);
    n->udp_rx_src_ip = idemip_ip4_src(ip);
    n->udp_rx_count++;
}

// One segment, built into a transmit descriptor and framed. @p data may be null for a segment
// carrying only control bits.
typedef struct
{
    Node *n;
    uint32_t seq;
    uint32_t ack;
    uint8_t flags;
    uint16_t opts;
    uint32_t wnd;
    const uint8_t *data;
    uint16_t data_len;
} NodeTcpSendArgs;

static idemip_bool node_tcp_send_ctx(const NodeTcpSendArgs *args)
{
    uint8_t local16[IDEMIP_TCP_PCB_ADDR_BYTES];
    uint8_t remote16[IDEMIP_TCP_PCB_ADDR_BYTES];
    uint8_t desc = 0;
    const uint8_t *dst_mac = node_resolve(args->n, args->n->tcp.remote_ip);

    if (dst_mac == NULL)
    {
        return IDEMIP_FALSE;
    }
    memset(local16, 0, sizeof local16);
    memset(remote16, 0, sizeof remote16);
    idemip_wr32(local16, args->n->ip);
    idemip_wr32(remote16, args->n->tcp.remote_ip);

    TcpOutIo *io = IDEMIP_TCP_OUT_IO(args->n->b.tout);
    memset(&io->build_args, 0, sizeof io->build_args);
    io->build_args.buf = args->n->scratch;
    io->build_args.cap = (uint16_t)(IDEMIP_ETH_MAX_PAYLOAD - IDEMIP_IPV4_HDR_LEN);
    io->build_args.data = args->data;
    io->build_args.len = args->data_len;
    io->build_args.local_ip = local16;
    io->build_args.remote_ip = remote16;
    io->build_args.local_port = args->n->tcp.local_port;
    io->build_args.remote_port = args->n->tcp.remote_port;
    io->build_args.seq = args->seq;
    io->build_args.ack = args->ack;
    io->build_args.wnd = args->wnd;
    io->build_args.mss = (uint16_t)IDEMIP_TCP_MSS;
    io->build_args.opts = args->opts;
    io->build_args.flags = args->flags;
    io->build_args.ip_version = 4u;
    TcpOut.build(args->n->b.tout);
    if (io->status != IDEMIP_OK)
    {
        return IDEMIP_FALSE;
    }
    uint16_t built = io->res.built;
    uint8_t *frame = node_tx_claim(args->n, &desc);
    if (frame == NULL)
    {
        return IDEMIP_FALSE;
    }
    memcpy(frame + IDEMIP_ETH_HDR_LEN + IDEMIP_IPV4_HDR_LEN, args->n->scratch, built);
    return node_send_ip4(args->n, frame, desc, dst_mac, args->n->tcp.remote_ip, (uint8_t)IDEMIP_IP4_PROTO_TCP, 0x2000u, built);
}

#define node_tcp_send(...) IDEMIP_CALL(node_tcp_send_ctx, NodeTcpSendArgs, __VA_ARGS__)

// The ISS RFC 6528 sec 3 draws for this four-tuple.
static uint32_t node_isn(Node *n, uint32_t remote_ip, uint16_t local_port, uint16_t remote_port)
{
    uint8_t local16[IDEMIP_TCP_PCB_ADDR_BYTES];
    uint8_t remote16[IDEMIP_TCP_PCB_ADDR_BYTES];

    memset(local16, 0, sizeof local16);
    memset(remote16, 0, sizeof remote16);
    idemip_wr32(local16, n->ip);
    idemip_wr32(remote16, remote_ip);

    TcpIsnIo *io = IDEMIP_TCP_ISN_IO(n->b.isn);
    io->gen_args.local_ip = local16;
    io->gen_args.remote_ip = remote16;
    io->gen_args.local_port = local_port;
    io->gen_args.remote_port = remote_port;
    io->gen_args.ip_version = 4u;
    io->gen_args.now_ms = g_now_ms;
    TcpIsn.generate(n->b.isn);
    return (io->status == IDEMIP_OK) ? io->isn : 0x01000000u;
}

// Descriptor i of the receive ring points at rx_base + i strides, which dma.h states, so a
// retaining unit's caller reaches a held fragment's or a held segment's octets there.
static const uint8_t *node_rx_buf(const Node *n, uint16_t desc)
{
    return n->rig->rx_base + ((size_t)desc * IDEMIP_DMA_BUF_STRIDE);
}

// RFC 9293 sec 3.10.7.4 seventh, the segment that "begins past RCV.NXT": its octets stay in the
// receive buffer the engine wrote them to, so the descriptor is pinned and the queue entry names it.
static void node_tcp_hold(Node *n, uint16_t index, const uint8_t *ip, const uint8_t *seg, uint16_t desc, const TcpInIo *ti)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);

    if (desc >= IDEMIP_RX_DESCRIPTORS)
    {
        return; // a reassembled datagram is in this node's own storage and pins no descriptor
    }
    IDEMIP_DMA_IO(n->b.dma)->desc_args.index = (uint8_t)desc;
    Dma.pin(n->b.dma);
    if (IDEMIP_DMA_IO(n->b.dma)->status != IDEMIP_OK)
    {
        return;
    }
    tp->oos_args.pcb = index;
    tp->oos_args.index = 0u;
    tp->oos_args.seq = ti->res.text_seq;
    tp->oos_args.desc = desc;
    tp->oos_args.offset = (uint16_t)(IDEMIP_ETH_HDR_LEN + idemip_ip4_hdr_len(ip) + idemip_tcp_hdr_len(seg));
    tp->oos_args.len = ti->res.text_len;
    TcpPcb.oos_alloc(n->b.tpcb);
    if (tp->status != IDEMIP_OK)
    {
        IDEMIP_DMA_IO(n->b.dma)->desc_args.index = (uint8_t)desc;
        Dma.unpin(n->b.dma);
        return;
    }
    n->oos_held++;
}

// RCV.NXT advanced, so the head of the out-of-order queue may now be in order. Each one that is gets
// delivered, RCV.NXT advances over it, its entry is freed and its descriptor unpinned, and the walk
// looks again. Bounded by IDEMIP_TCP_OOSEQ_SEGS, which is what one TCB can hold.
// The head of @p index's out-of-order queue when it is the segment RCV.NXT now wants, and
// IDEMIP_TCP_PCB_NONE when the queue is empty, could not be read, or still begins ahead of RCV.NXT.
// The TCB it read comes back through @p vars, @p ctl and @p state, which the caller writes back.
static uint16_t node_tcp_oos_head_in_order(Node *n, uint16_t index, IdemIpTcpVars *vars, TcpPcbCtl *ctl,
                                           IdemIpTcpState *state)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);
    tp->pcb_args.index = index;
    TcpPcb.load(n->b.tpcb);
    if (tp->status != IDEMIP_OK || tp->info.ooseq == IDEMIP_TCP_PCB_NONE)
    {
        return IDEMIP_TCP_PCB_NONE;
    }
    const uint16_t at = tp->info.ooseq;
    *vars = tp->vars;
    *ctl = tp->ctl;
    *state = tp->state;

    tp->oos_args.index = at;
    TcpPcb.oos_load(n->b.tpcb);
    if (tp->status != IDEMIP_OK || tp->oos.seq != vars->rcv_nxt)
    {
        return IDEMIP_TCP_PCB_NONE;
    }
    return at;
}

static int node_tcp_deliver_oos(Node *n, uint16_t index)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);
    int moved = 0;

    for (unsigned guard = 0u; guard < IDEMIP_TCP_OOSEQ_SEGS; guard++)
    {
        IdemIpTcpVars vars;
        TcpPcbCtl ctl;
        IdemIpTcpState state;
        const uint16_t at = node_tcp_oos_head_in_order(n, index, &vars, &ctl, &state);
        if (at == IDEMIP_TCP_PCB_NONE)
        {
            break;
        }
        uint16_t desc = tp->oos.desc;
        uint16_t off = tp->oos.offset;
        uint16_t seg_len = tp->oos.len;

        size_t take = seg_len;
        if (n->tcp.rx_len + take > sizeof n->tcp.rx)
        {
            take = sizeof n->tcp.rx - n->tcp.rx_len;
        }
        memcpy(n->tcp.rx + n->tcp.rx_len, node_rx_buf(n, desc) + off, take);
        n->tcp.rx_len += take;

        vars.rcv_nxt += seg_len;
        tp->pcb_args.index = index;
        tp->vars = vars;
        tp->ctl = ctl;
        tp->state = state;
        TcpPcb.store(n->b.tpcb);

        tp->oos_args.pcb = index;
        tp->oos_args.index = at;
        TcpPcb.oos_free(n->b.tpcb);
        IDEMIP_DMA_IO(n->b.dma)->desc_args.index = (uint8_t)desc;
        Dma.unpin(n->b.dma);
        n->oos_held--;
        n->oos_delivered++;
        moved++;
    }
    return moved;
}

// Load the TCB, run the state's SEGMENT ARRIVES entry, act on what it asked for, store it back.
static void node_tcp_in(Node *n, const uint8_t *ip, size_t len, uint16_t desc)
{
    const uint8_t *seg = ip + idemip_ip4_hdr_len(ip);
    uint16_t seg_len = idemip_ip4_payload_len(ip);
    uint8_t local16[IDEMIP_TCP_PCB_ADDR_BYTES];
    uint8_t remote16[IDEMIP_TCP_PCB_ADDR_BYTES];

    (void)len;
    memset(local16, 0, sizeof local16);
    memset(remote16, 0, sizeof remote16);
    idemip_wr32(local16, idemip_ip4_dst(ip));
    idemip_wr32(remote16, idemip_ip4_src(ip));

    TcpInIo *ti = IDEMIP_TCP_IN_IO(n->b.tin);
    ti->parse_args.seg = seg;
    ti->parse_args.len = seg_len;
    ti->parse_args.local_ip = local16;
    ti->parse_args.remote_ip = remote16;
    ti->parse_args.ip_version = 4u;
    ti->parse_args.snd_scale = 0u;
    TcpIn.parse(n->b.tin);
    if (ti->status != IDEMIP_OK)
    {
        return;
    }

    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);
    tp->find_args.local_ip = local16;
    tp->find_args.remote_ip = remote16;
    tp->find_args.local_port = idemip_tcp_dst_port(seg);
    tp->find_args.remote_port = idemip_tcp_src_port(seg);
    tp->find_args.ip_version = 4u;
    tp->find_args.local_zone = 0u;
    tp->find_args.remote_zone = 0u;
    tp->find_args.netif = 0u;
    TcpPcb.find(n->b.tpcb);

    uint16_t index = IDEMIP_TCP_PCB_NONE;
    if (tp->status == IDEMIP_OK)
    {
        index = tp->index;
    }
    else
    {
        // RFC 9293 sec 3.10.7.2 creates the connection out of the LISTEN state.
        tp->find_args.local_ip = local16;
        tp->find_args.remote_ip = remote16;
        TcpPcb.find_listener(n->b.tpcb);
        if (tp->status != IDEMIP_OK)
        {
            return;
        }
        uint16_t listener = tp->index;
        tp->open_args.ip_version = 4u;
        TcpPcb.open(n->b.tpcb);
        if (tp->status != IDEMIP_OK)
        {
            return;
        }
        index = tp->index;
        tp->bind_args.index = index;
        tp->bind_args.ip = local16;
        tp->bind_args.port = idemip_tcp_dst_port(seg);
        tp->bind_args.zone = 0u;
        tp->bind_args.netif = 0u;
        TcpPcb.bind(n->b.tpcb);
        tp->connect_args.index = index;
        tp->connect_args.ip = remote16;
        tp->connect_args.port = idemip_tcp_src_port(seg);
        tp->connect_args.zone = 0u;
        tp->connect_args.netif = 0u;
        TcpPcb.connect(n->b.tpcb);
        tp->accept_args.index = index;
        tp->accept_args.listener = listener;
        TcpPcb.accept(n->b.tpcb);

        n->tcp.tcb = index;
        n->tcp.local_port = idemip_tcp_dst_port(seg);
        n->tcp.remote_port = idemip_tcp_src_port(seg);
        n->tcp.remote_ip = idemip_ip4_src(ip);
    }

    tp->pcb_args.index = index;
    TcpPcb.load(n->b.tpcb);
    if (tp->status != IDEMIP_OK)
    {
        return;
    }
    ti->vars = tp->vars;
    ti->ctl = tp->ctl;
    ti->state = tp->state;
    ti->listener = tp->info.listener;
    ti->now_ms = g_now_ms;

    if (tp->state == IDEMIP_TCP_STATE_CLOSED)
    {
        // A TCB just taken out of a listener starts the sec 3.10.7.2 LISTEN processing.
        ti->state = IDEMIP_TCP_STATE_LISTEN;
        ti->vars.iss = node_isn(n, idemip_ip4_src(ip), idemip_tcp_dst_port(seg), idemip_tcp_src_port(seg));
        ti->vars.rcv_wnd = (uint32_t)IDEMIP_TCP_WND;
        TcpIn.listen(n->b.tin);
    }
    else if (tp->state == IDEMIP_TCP_STATE_SYN_SENT)
    {
        TcpIn.syn_sent(n->b.tin);
    }
    else
    {
        TcpIn.segment(n->b.tin);
    }
    if (ti->status != IDEMIP_OK)
    {
        return;
    }

    idemip_bool advanced = IDEMIP_FALSE;
    if ((ti->res.act & IDEMIP_TCP_IN_ACT_TEXT) != 0u && ti->res.text_len > 0u)
    {
        size_t off = idemip_tcp_hdr_len(seg) + ti->res.text_off;
        size_t take = ti->res.text_len;
        if (n->tcp.rx_len + take > sizeof n->tcp.rx)
        {
            take = sizeof n->tcp.rx - n->tcp.rx_len;
        }
        memcpy(n->tcp.rx + n->tcp.rx_len, seg + off, take);
        n->tcp.rx_len += take;
        // sec 3.10.7.4 seventh: RCV.WND is adjusted "as appropriate to the current buffer
        // availability", and this user took the octets in the same call, so the window re-opens.
        ti->vars.rcv_wnd += ti->res.text_len;
        advanced = IDEMIP_TRUE;
    }
    if ((ti->res.act & IDEMIP_TCP_IN_ACT_ESTABLISHED) != 0u)
    {
        n->tcp.established++;
    }
    if ((ti->res.act & IDEMIP_TCP_IN_ACT_CLOSING) != 0u)
    {
        n->tcp.fin_seen++;
    }

    tp->pcb_args.index = index;
    tp->vars = ti->vars;
    tp->ctl = ti->ctl;
    tp->state = ti->state;
    TcpPcb.store(n->b.tpcb);
    n->tcp.state = ti->state;

    if ((ti->res.act & IDEMIP_TCP_IN_ACT_HOLD) != 0u)
    {
        node_tcp_hold(n, index, ip, seg, desc, ti);
    }
    if (advanced)
    {
        (void)node_tcp_deliver_oos(n, index);
    }

    if ((ti->res.act & IDEMIP_TCP_IN_ACT_RST) != 0u)
    {
        (void)node_tcp_send(n, ti->reply.seq, ti->reply.ack, (uint8_t)ti->reply.flags, 0u, ti->vars.rcv_wnd, NULL, 0u);
    }
    else if ((ti->res.act & IDEMIP_TCP_IN_ACT_ACK) != 0u)
    {
        uint8_t flags = (uint8_t)ti->reply.flags;
        if (flags != (uint8_t)IDEMIP_TCP_ACK)
        {
            // A SYN,ACK is not the pure acknowledgment MUST-58 aggregates: it carries a control bit
            // that occupies a sequence number, so holding it would hold the handshake.
            (void)node_tcp_send(n, ti->reply.seq, ti->reply.ack, flags,
                                ((flags & IDEMIP_TCP_SYN) != 0u) ? (uint16_t)IDEMIP_TCP_OUT_OPT_MSS : 0u,
                                ti->vars.rcv_wnd, NULL, 0u);
        }
        else
        {
            if (n->ack_owed)
            {
                n->acks_aggregated++;
            }
            n->ack_owed = 1;
            n->ack_tcb = index;
        }
    }
    if ((ti->res.act & IDEMIP_TCP_IN_ACT_DELETE) != 0u)
    {
        tp->pcb_args.index = index;
        TcpPcb.close(n->b.tpcb);
        n->tcp.deleted++;
        n->tcp.tcb = IDEMIP_TCP_PCB_NONE;
    }
}

// --- receive: one datagram, once it is whole ---------------------------------

static void node_deliver_ip4(Node *n, const uint8_t *ip, size_t len, uint16_t desc)
{
    switch (idemip_ip4_proto(ip))
    {
    case IDEMIP_IP4_PROTO_ICMP:
        node_icmp_in(n, ip, len);
        return;
    case IDEMIP_IP4_PROTO_UDP:
        node_udp_in(n, ip, len);
        return;
    case IDEMIP_IP4_PROTO_TCP:
        node_tcp_in(n, ip, len, desc);
        return;
    default:
        // RFC 1213 sec 6.6 ipInUnknownProtos, "locally-addressed datagrams received successfully but
        // discarded because of an unknown or unsupported protocol". The interface counter of sec 6.4
        // is the EtherType case and is not this one.
        IDEMIP_STATS_IO(n->b.stats)->ctr_args.id = IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS;
        IDEMIP_STATS_IO(n->b.stats)->ctr_args.value = 1u;
        Stats.bump(n->b.stats);
        return;
    }
}

// RFC 791 sec 3.2: hold the fragment, and when the hole list empties, copy every held fragment into
// one datagram and deliver it. Every held fragment pins its receive descriptor; reclaim hands each
// one back.
static void node_fragment_in(Node *n, const uint8_t *ip, size_t avail, uint8_t desc)
{
    Ip4ReassIo *io = IDEMIP_IP4_REASS_IO(n->b.reass);

    IDEMIP_DMA_IO(n->b.dma)->desc_args.index = desc;
    Dma.pin(n->b.dma);
    if (IDEMIP_DMA_IO(n->b.dma)->status != IDEMIP_OK)
    {
        return;
    }
    n->fragments_held++;
    if (IDEMIP_DMA_IO(n->b.dma)->pinned > n->max_pinned)
    {
        n->max_pinned = IDEMIP_DMA_IO(n->b.dma)->pinned;
    }

    io->now_ms = g_now_ms;
    io->hold_args.hdr = ip;
    io->hold_args.desc = desc;
    io->hold_args.len = (uint16_t)avail;
    Ip4Reass.hold(n->b.reass);
    if (io->status != IDEMIP_OK)
    {
        IDEMIP_DMA_IO(n->b.dma)->desc_args.index = desc;
        Dma.unpin(n->b.dma);
        n->fragments_held--;
        return;
    }
    if (!io->complete)
    {
        return;
    }

    uint8_t row = io->index;
    uint16_t total = io->total_len;
    size_t hdr_len = 0;

    memset(n->big_rx, 0, sizeof n->big_rx);
    for (;;)
    {
        io->next_args.index = row;
        Ip4Reass.next(n->b.reass);
        if (io->status != IDEMIP_OK)
        {
            break;
        }
        const uint8_t *frag = node_rx_buf(n, io->desc) + IDEMIP_ETH_HDR_LEN;
        if (io->off == 0u)
        {
            hdr_len = io->hdr_len;
            memcpy(n->big_rx, frag, hdr_len);
        }
        size_t at = (size_t)io->hdr_len + (size_t)0u;
        if (hdr_len + (size_t)io->off + (size_t)io->len <= sizeof n->big_rx)
        {
            memcpy(n->big_rx + hdr_len + io->off, frag + at, io->len);
        }
    }
    if (hdr_len == 0u)
    {
        hdr_len = IDEMIP_IPV4_HDR_LEN;
    }
    n->big_rx_len = hdr_len + total;
    idemip_ip4_set_total_len(n->big_rx, (uint16_t)n->big_rx_len);
    idemip_ip4_set_flags_frag(n->big_rx, 0u);
    idemip_ip4_recksum(n->big_rx);
    n->reassembled++;

    io->release_args.index = row;
    Ip4Reass.release(n->b.reass);
    for (;;)
    {
        Ip4Reass.reclaim(n->b.reass);
        if (io->status != IDEMIP_OK)
        {
            break;
        }
        IDEMIP_DMA_IO(n->b.dma)->desc_args.index = (uint8_t)io->desc;
        Dma.unpin(n->b.dma);
        n->fragments_held--;
    }
    node_deliver_ip4(n, n->big_rx, n->big_rx_len, DESC_NONE);
}

static void node_frame_in(Node *n, const uint8_t *frame, size_t len, uint8_t desc)
{
    StatsIo *st = IDEMIP_STATS_IO(n->b.stats);

    st->if_args.netif = 0u;
    st->if_args.value = 1u;
    if (len < IDEMIP_ETH_HDR_LEN)
    {
        st->if_args.id = IDEMIP_STAT_IF_IN_ERRORS;
        Stats.if_bump(n->b.stats);
        return;
    }
    st->if_args.id = IDEMIP_STAT_IF_IN_UCAST_PKTS;
    Stats.if_bump(n->b.stats);

    const uint8_t *payload = idemip_eth_payload(frame);
    size_t avail = len - IDEMIP_ETH_HDR_LEN;

    switch (idemip_eth_type(frame))
    {
    case IDEMIP_ETHERTYPE_ARP:
        if (avail >= IDEMIP_ARP_LEN)
        {
            node_arp_in(n, payload);
        }
        return;
    case IDEMIP_ETHERTYPE_IPV4:
        if (idemip_ip4_verify(payload, avail) != IDEMIP_OK)
        {
            st->if_args.id = IDEMIP_STAT_IF_IN_ERRORS;
            Stats.if_bump(n->b.stats);
            return;
        }
        if (idemip_ip4_dst(payload) != n->ip)
        {
            st->if_args.id = IDEMIP_STAT_IF_IN_DISCARDS;
            Stats.if_bump(n->b.stats);
            return;
        }
        if (idemip_ip4_is_fragment(payload))
        {
            node_fragment_in(n, payload, avail, desc);
            return;
        }
        node_deliver_ip4(n, payload, idemip_ip4_total_len(payload), desc);
        return;
    default:
        st->if_args.id = IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS;
        Stats.if_bump(n->b.stats);
        return;
    }
}

// --- the tick ----------------------------------------------------------------

// RFC 9293 sec 3.10.7.4 (MUST-59): "if the TCP endpoint is processing a series of queued segments,
// it MUST process them all before sending any ACK segments". The one acknowledgment carries the
// RCV.NXT and RCV.WND the whole drain left behind, in the sec 3.10.7.4 form
// "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>".
static void node_flush_ack(Node *n)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);

    if (!n->ack_owed)
    {
        return;
    }
    n->ack_owed = 0;
    if (n->ack_tcb >= IDEMIP_TCP_PCBS)
    {
        return;
    }
    tp->pcb_args.index = n->ack_tcb;
    TcpPcb.load(n->b.tpcb);
    if (tp->status != IDEMIP_OK)
    {
        return;
    }
    if (node_tcp_send(n, tp->vars.snd_nxt, tp->vars.rcv_nxt, (uint8_t)IDEMIP_TCP_ACK, 0u, tp->vars.rcv_wnd, NULL, 0u))
    {
        n->acks_sent++;
    }
}

// Stage 1, DRAIN: every frame the engine filled, dispatched and posted back. A frame a
// retaining unit pinned stays out of the ring until that unit drops its pin, which rx_post honors.
// The one acknowledgment the whole drain owes goes out once the loop is done, never inside it.
static void node_drain(Node *n)
{
    for (;;)
    {
        Dma.rx_take(n->b.dma);
        if (IDEMIP_DMA_IO(n->b.dma)->status != IDEMIP_OK)
        {
            break;
        }
        uint8_t desc = IDEMIP_DMA_IO(n->b.dma)->index;
        const uint8_t *frame = IDEMIP_DMA_IO(n->b.dma)->buf;
        size_t len = IDEMIP_DMA_IO(n->b.dma)->len;

        node_frame_in(n, frame, len, desc);

        IDEMIP_DMA_IO(n->b.dma)->desc_args.index = desc;
        Dma.rx_post(n->b.dma);
    }
    node_flush_ack(n);
}

// Stage 2: each service's timers, in dependency order. ARP first, because what waits on resolution
// runs behind it; reassembly before the protocols that read a completed datagram.
static void node_timers(Node *n)
{
    IDEMIP_ARP_IO(n->b.arp)->now_ms = g_now_ms;
    for (;;)
    {
        ArpTable.tick(n->b.arp);
        if (IDEMIP_ARP_IO(n->b.arp)->status != IDEMIP_OK)
        {
            break;
        }
        if (IDEMIP_ARP_IO(n->b.arp)->len == 0u && IDEMIP_ARP_IO(n->b.arp)->ip != 0u)
        {
            (void)node_send_arp_request(n, IDEMIP_ARP_IO(n->b.arp)->ip);
        }
    }
    IDEMIP_IP4_REASS_IO(n->b.reass)->now_ms = g_now_ms;
    for (;;)
    {
        Ip4Reass.tick(n->b.reass);
        if (IDEMIP_IP4_REASS_IO(n->b.reass)->status != IDEMIP_OK)
        {
            break;
        }
    }
    for (;;)
    {
        Ip4Reass.reclaim(n->b.reass);
        if (IDEMIP_IP4_REASS_IO(n->b.reass)->status != IDEMIP_OK)
        {
            break;
        }
        IDEMIP_DMA_IO(n->b.dma)->desc_args.index = (uint8_t)IDEMIP_IP4_REASS_IO(n->b.reass)->desc;
        Dma.unpin(n->b.dma);
        n->fragments_held--;
    }
}

// Stage 3: the engine's finished transmit descriptors, back to buffers this side may build into.
static void node_flush(Node *n)
{
    Dma.tx_reap(n->b.dma);
}

// Every frame that crossed the wire goes into the capture, in the order it crossed.
static void wire_all(Node *from, Node *to)
{
    for (unsigned guard = 0u; guard < IDEMIP_FAKE_PHY_SLOTS; guard++)
    {
        size_t len = 0;
        const uint8_t *frame = idemip_fake_phy_tx_peek(from->rig, &len);

        if (frame == NULL)
        {
            return;
        }
        if (g_pcap_open)
        {
            (void)idemip_pcap_frame(&g_pcap, frame, len, g_now_ms);
        }
        if (idemip_fake_phy_wire(from->rig, to->rig) == 0u)
        {
            return;
        }
    }
}

// Descriptors the engine fills between two ticks. More than one, so a drain sees a series of queued
// segments and MUST-59's one acknowledgment for the series is reachable.
#define POLLS_PER_TICK 4u

static void poll_engine(Node *n)
{
    for (unsigned i = 0u; i < POLLS_PER_TICK; i++)
    {
        idemip_fake_phy_poll(n->rig);
    }
}

// One pass of the loop: the engine, the wire, then the three stages on each node.
static void tick_once(void)
{
    poll_engine(&g_a);
    poll_engine(&g_b);

    wire_all(&g_a, &g_b);
    wire_all(&g_b, &g_a);

    node_drain(&g_a);
    node_drain(&g_b);
    node_timers(&g_a);
    node_timers(&g_b);
    node_flush(&g_a);
    node_flush(&g_b);

    g_now_ms += TICK_MS;
}

static void pump(unsigned n)
{
    for (unsigned i = 0; i < n; i++)
    {
        tick_once();
    }
}

// --- setup -------------------------------------------------------------------

typedef struct
{
    Node *n;
    IdemIpFakePhy *rig;
    const IdemIpPhyDriver *drv;
    const uint8_t *mac;
    uint32_t ip;
    uint8_t *rx_base;
    uint8_t *tx_base;
    const uint8_t *isn_secret;
} NodeSetupArgs;

static void node_setup_ctx(const NodeSetupArgs *args)
{
    memset(args->n, 0, sizeof *args->n);
    args->n->rig = args->rig;
    args->n->drv = args->drv;
    memcpy(args->n->mac, args->mac, IDEMIP_MAC_LEN);
    args->n->ip = args->ip;
    args->n->mask = IP_MASK;
    args->n->tcp.tcb = IDEMIP_TCP_PCB_NONE;
    args->n->tcp.listener = IDEMIP_TCP_PCB_NONE;
    args->n->ack_tcb = IDEMIP_TCP_PCB_NONE;
    arm_canaries(&args->n->b);

    idemip_fake_phy_attach(args->rig, args->rx_base, args->tx_base, args->mac);

    Dma.clear(args->n->b.dma);
    Netif.clear(args->n->b.netif);
    ArpTable.clear(args->n->b.arp);
    Ip4Reass.clear(args->n->b.reass);
    Ip4Frag.clear(args->n->b.frag);
    IcmpIn.clear(args->n->b.icmp);
    UdpPcb.clear(args->n->b.udp);
    TcpPcb.clear(args->n->b.tpcb);
    TcpIn.clear(args->n->b.tin);
    TcpOut.clear(args->n->b.tout);
    TcpIsn.reset(args->n->b.isn);
    Stats.clear(args->n->b.stats);

    IDEMIP_PHY_IO(args->n->b.phy)->bind_args.drv = args->drv;
    IDEMIP_PHY_IO(args->n->b.phy)->bind_args.addr = 1u;
    Phy.bind(args->n->b.phy);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_PHY_IO(args->n->b.phy)->status);

    IDEMIP_DMA_IO(args->n->b.dma)->bind_args.drv = args->drv;
    IDEMIP_DMA_IO(args->n->b.dma)->bind_args.rx_base = args->rx_base;
    IDEMIP_DMA_IO(args->n->b.dma)->bind_args.tx_base = args->tx_base;
    Dma.bind(args->n->b.dma);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(args->n->b.dma)->status);

    IDEMIP_NETIF_IO(args->n->b.netif)->bind_args.index = 0u;
    IDEMIP_NETIF_IO(args->n->b.netif)->bind_args.phy = args->n->b.phy;
    IDEMIP_NETIF_IO(args->n->b.netif)->bind_args.hwaddr = args->n->mac;
    IDEMIP_NETIF_IO(args->n->b.netif)->bind_args.mtu = (uint16_t)IDEMIP_ETH_MAX_PAYLOAD;
    Netif.bind(args->n->b.netif);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(args->n->b.netif)->status);

    IDEMIP_NETIF_IO(args->n->b.netif)->addr4_args.index = 0u;
    IDEMIP_NETIF_IO(args->n->b.netif)->addr4_args.addr = args->ip;
    IDEMIP_NETIF_IO(args->n->b.netif)->addr4_args.mask = IP_MASK;
    IDEMIP_NETIF_IO(args->n->b.netif)->addr4_args.gw = 0u;
    Netif.set_addr4(args->n->b.netif);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_NETIF_IO(args->n->b.netif)->status);

    IDEMIP_TCP_ISN_IO(args->n->b.isn)->seed_args.key = args->isn_secret;
    IDEMIP_TCP_ISN_IO(args->n->b.isn)->seed_args.key_len = IDEMIP_TCP_ISN_SECRET_BYTES;
    IDEMIP_TCP_ISN_IO(args->n->b.isn)->seed_args.base = 0u;
    TcpIsn.seed(args->n->b.isn);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_TCP_ISN_IO(args->n->b.isn)->status);
}

#define node_setup(...) IDEMIP_CALL(node_setup_ctx, NodeSetupArgs, __VA_ARGS__)

// One RFC 768 binding per node, so a datagram each way has somewhere to land.
static void node_open_udp(Node *n, uint16_t port)
{
    uint8_t local16[IDEMIP_TCP_PCB_ADDR_BYTES];

    memset(local16, 0, sizeof local16);
    idemip_wr32(local16, n->ip);

    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(n->b.udp);
    io->open_args.ip_version = 4u;
    io->open_args.lite = IDEMIP_FALSE;
    UdpPcb.open(n->b.udp);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    n->udp_pcb = io->index;
    io->bind_args.index = n->udp_pcb;
    io->bind_args.ip = local16;
    io->bind_args.port = port;
    io->bind_args.zone = 0u;
    io->bind_args.netif = 0u;
    UdpPcb.bind(n->b.udp);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
}

void setUp(void)
{
    g_now_ms = 1000u;
    g_pcap_open = 0;
    memset(&g_pcap, 0, sizeof g_pcap);
    memset(g_rx_bufs, 0, sizeof g_rx_bufs);
    memset(g_tx_bufs, 0, sizeof g_tx_bufs);
    node_setup(&g_a, &g_idemip_fake_phy[0], &idemip_fake_phy_drv_0, MAC_A, IP_A, g_rx_bufs[0], g_tx_bufs[0],
               ISN_SECRET_A);
    node_setup(&g_b, &g_idemip_fake_phy[1], &idemip_fake_phy_drv_1, MAC_B, IP_B, g_rx_bufs[1], g_tx_bufs[1],
               ISN_SECRET_B);
}

void tearDown(void)
{
    if (g_pcap_open)
    {
        idemip_pcap_close(&g_pcap);
        g_pcap_open = 0;
    }
    check_canaries(&g_a.b);
    check_canaries(&g_b.b);
}

// --- helpers the cases share -------------------------------------------------

// Send one RFC 768 datagram, resolving the destination first. False when the pair is not yet in the
// translation table, which puts a REQUEST on the wire instead.
static idemip_bool send_udp(Node *n, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t *data,
                            size_t len)
{
    const uint8_t *dst_mac = node_resolve(n, dst_ip);
    uint8_t desc = 0;

    if (dst_mac == NULL)
    {
        return IDEMIP_FALSE;
    }
    uint8_t *frame = node_tx_claim(n, &desc);
    if (frame == NULL)
    {
        return IDEMIP_FALSE;
    }
    uint8_t *udp = frame + IDEMIP_ETH_HDR_LEN + IDEMIP_IPV4_HDR_LEN;
    idemip_udp_build(udp, src_port, dst_port, (uint16_t)(IDEMIP_UDP_HDR_LEN + len));
    memcpy(udp + IDEMIP_UDP_HDR_LEN, data, len);
    idemip_udp_cksum_write(udp, IDEMIP_UDP_HDR_LEN + len, n->ip, dst_ip);
    return node_send_ip4(n, frame, desc, dst_mac, dst_ip, (uint8_t)IDEMIP_IP4_PROTO_UDP, 0x3000u,
                         IDEMIP_UDP_HDR_LEN + len);
}

// One RFC 792 Echo, Identifier and Sequence Number as given.
static idemip_bool send_echo(Node *n, uint32_t dst_ip, uint16_t id, uint16_t seq, size_t data_len)
{
    const uint8_t *dst_mac = node_resolve(n, dst_ip);
    uint8_t desc = 0;

    if (dst_mac == NULL)
    {
        return IDEMIP_FALSE;
    }
    uint8_t *frame = node_tx_claim(n, &desc);
    if (frame == NULL)
    {
        return IDEMIP_FALSE;
    }
    uint8_t *msg = frame + IDEMIP_ETH_HDR_LEN + IDEMIP_IPV4_HDR_LEN;
    size_t total = IDEMIP_ICMP_ECHO_HDR_LEN + data_len;
    for (size_t i = 0; i < data_len; i++)
    {
        msg[IDEMIP_ICMP_ECHO_HDR_LEN + i] = (uint8_t)(0x40u + i);
    }
    idemip_icmp_build_echo(msg, (uint8_t)IDEMIP_ICMP_ECHO, id, seq, total);
    return node_send_ip4(n, frame, desc, dst_mac, dst_ip, (uint8_t)IDEMIP_IP4_PROTO_ICMP, 0x4000u, total);
}

// Put both translation tables in the RFC 826 STABLE state, so a case that is not about resolution
// does not have to wait for it.
static void resolve_both(void)
{
    (void)node_resolve(&g_a, IP_B);
    pump(8);
    (void)node_resolve(&g_b, IP_A);
    pump(8);
}

// The RFC 9293 sec 3.5 active OPEN: a TCB in SYN-SENT and its SYN on the wire.
static void tcp_connect(Node *n, uint32_t remote_ip, uint16_t local_port, uint16_t remote_port)
{
    uint8_t local16[IDEMIP_TCP_PCB_ADDR_BYTES];
    uint8_t remote16[IDEMIP_TCP_PCB_ADDR_BYTES];

    memset(local16, 0, sizeof local16);
    memset(remote16, 0, sizeof remote16);
    idemip_wr32(local16, n->ip);
    idemip_wr32(remote16, remote_ip);

    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);
    tp->open_args.ip_version = 4u;
    TcpPcb.open(n->b.tpcb);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    n->tcp.tcb = tp->index;

    tp->bind_args.index = n->tcp.tcb;
    tp->bind_args.ip = local16;
    tp->bind_args.port = local_port;
    tp->bind_args.zone = 0u;
    tp->bind_args.netif = 0u;
    TcpPcb.bind(n->b.tpcb);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    n->tcp.local_port = tp->port;

    tp->connect_args.index = n->tcp.tcb;
    tp->connect_args.ip = remote16;
    tp->connect_args.port = remote_port;
    tp->connect_args.zone = 0u;
    tp->connect_args.netif = 0u;
    TcpPcb.connect(n->b.tpcb);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    n->tcp.remote_ip = remote_ip;
    n->tcp.remote_port = remote_port;

    tp->pcb_args.index = n->tcp.tcb;
    TcpPcb.load(n->b.tpcb);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    tp->vars.iss = node_isn(n, remote_ip, n->tcp.local_port, remote_port);
    tp->vars.snd_una = tp->vars.iss;
    tp->vars.snd_nxt = tp->vars.iss + 1u;
    tp->vars.rcv_wnd = (uint32_t)IDEMIP_TCP_WND;
    tp->state = IDEMIP_TCP_STATE_SYN_SENT;
    TcpPcb.store(n->b.tpcb);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    n->tcp.state = IDEMIP_TCP_STATE_SYN_SENT;

    TEST_ASSERT_TRUE(node_tcp_send(n, tp->vars.iss, 0u, (uint8_t)IDEMIP_TCP_SYN, (uint16_t)IDEMIP_TCP_OUT_OPT_MSS,
                                   tp->vars.rcv_wnd, NULL, 0u));
}

// The RFC 9293 sec 3.9.1.1 passive OPEN: a listener on one socket.
static void tcp_listen(Node *n, uint16_t port)
{
    uint8_t local16[IDEMIP_TCP_PCB_ADDR_BYTES];

    memset(local16, 0, sizeof local16);
    idemip_wr32(local16, n->ip);

    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);
    tp->listen_args.ip = local16;
    tp->listen_args.port = port;
    tp->listen_args.zone = 0u;
    tp->listen_args.netif = 0u;
    tp->listen_args.backlog = 1u;
    tp->listen_args.ip_version = 4u;
    TcpPcb.listen(n->b.tpcb);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    n->tcp.listener = tp->index;
    n->tcp.local_port = port;
}

// The state one node's TCB is in right now.
static IdemIpTcpState tcp_state(Node *n)
{
    if (n->tcp.tcb == IDEMIP_TCP_PCB_NONE)
    {
        return IDEMIP_TCP_STATE_CLOSED;
    }
    IDEMIP_TCP_PCB_IO(n->b.tpcb)->pcb_args.index = n->tcp.tcb;
    TcpPcb.load(n->b.tpcb);
    if (IDEMIP_TCP_PCB_IO(n->b.tpcb)->status != IDEMIP_OK)
    {
        return IDEMIP_TCP_STATE_CLOSED;
    }
    return IDEMIP_TCP_PCB_IO(n->b.tpcb)->state;
}

// One data segment on an established connection, with the PSH and ACK bits sec 3.7.4 sends it with.
static idemip_bool tcp_write(Node *n, const uint8_t *data, uint16_t len)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);

    tp->pcb_args.index = n->tcp.tcb;
    TcpPcb.load(n->b.tpcb);
    if (tp->status != IDEMIP_OK)
    {
        return IDEMIP_FALSE;
    }
    uint32_t seq = tp->vars.snd_nxt;
    uint32_t ack = tp->vars.rcv_nxt;
    if (!node_tcp_send(n, seq, ack, (uint8_t)(IDEMIP_TCP_PSH | IDEMIP_TCP_ACK), 0u, tp->vars.rcv_wnd, data, len))
    {
        return IDEMIP_FALSE;
    }
    tp->pcb_args.index = n->tcp.tcb;
    TcpPcb.load(n->b.tpcb);
    tp->vars.snd_nxt = seq + len;
    tp->state = tp->state;
    TcpPcb.store(n->b.tpcb);
    return (idemip_bool)(tp->status == IDEMIP_OK);
}

// One data segment at an explicit Sequence Number, leaving SND.NXT alone, so a case can put
// segments on the wire out of order.
static idemip_bool tcp_send_at(Node *n, uint32_t seq, const uint8_t *data, uint16_t len)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);

    tp->pcb_args.index = n->tcp.tcb;
    TcpPcb.load(n->b.tpcb);
    if (tp->status != IDEMIP_OK)
    {
        return IDEMIP_FALSE;
    }
    return node_tcp_send(n, seq, tp->vars.rcv_nxt, (uint8_t)(IDEMIP_TCP_PSH | IDEMIP_TCP_ACK), 0u, tp->vars.rcv_wnd,
                         data, len);
}

// Move SND.NXT on by @p n octets, which the segments above already put on the wire.
static void tcp_advance_snd(Node *n, uint32_t by)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);

    tp->pcb_args.index = n->tcp.tcb;
    TcpPcb.load(n->b.tpcb);
    if (tp->status != IDEMIP_OK)
    {
        return;
    }
    tp->vars.snd_nxt += by;
    tp->pcb_args.index = n->tcp.tcb;
    TcpPcb.store(n->b.tpcb);
}

// The connection's SND.NXT right now.
static uint32_t tcp_snd_nxt(Node *n)
{
    IDEMIP_TCP_PCB_IO(n->b.tpcb)->pcb_args.index = n->tcp.tcb;
    TcpPcb.load(n->b.tpcb);
    return IDEMIP_TCP_PCB_IO(n->b.tpcb)->vars.snd_nxt;
}

// RFC 9293 sec 3.10.4 CLOSE: the FIN, and the state it moves this end into.
static idemip_bool tcp_close(Node *n)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(n->b.tpcb);

    tp->pcb_args.index = n->tcp.tcb;
    TcpPcb.load(n->b.tpcb);
    if (tp->status != IDEMIP_OK)
    {
        return IDEMIP_FALSE;
    }
    IdemIpTcpState from = tp->state;
    uint32_t seq = tp->vars.snd_nxt;
    uint32_t ack = tp->vars.rcv_nxt;
    uint32_t wnd = tp->vars.rcv_wnd;
    if (!node_tcp_send(n, seq, ack, (uint8_t)(IDEMIP_TCP_FIN | IDEMIP_TCP_ACK), 0u, wnd, NULL, 0u))
    {
        return IDEMIP_FALSE;
    }
    tp->pcb_args.index = n->tcp.tcb;
    TcpPcb.load(n->b.tpcb);
    tp->vars.snd_nxt = seq + 1u; // the FIN occupies one sequence number
    tp->state = (from == IDEMIP_TCP_STATE_CLOSE_WAIT) ? IDEMIP_TCP_STATE_LAST_ACK : IDEMIP_TCP_STATE_FIN_WAIT_1;
    TcpPcb.store(n->b.tpcb);
    n->tcp.state = tp->state;
    return (idemip_bool)(tp->status == IDEMIP_OK);
}

// =============================================================================
// the borrow: two instances share not one byte
// =============================================================================

// Every borrow of one instance lies inside its own object, and the two objects do not overlap. The
// storage model rests on this, so it is asserted directly rather than assumed.
void test_two_instances_occupy_disjoint_storage(void)
{
    const uint8_t *a0 = (const uint8_t *)&g_a.b;
    const uint8_t *b0 = (const uint8_t *)&g_b.b;

    TEST_ASSERT_TRUE(a0 + sizeof(Borrows) <= b0 || b0 + sizeof(Borrows) <= a0);
    TEST_ASSERT_NOT_EQUAL(g_a.b.arp, g_b.b.arp);
    TEST_ASSERT_NOT_EQUAL(g_a.b.tpcb, g_b.b.tpcb);
    TEST_ASSERT_NOT_EQUAL(g_a.rig->rx_base, g_b.rig->rx_base);
    TEST_ASSERT_NOT_EQUAL(g_a.rig->tx_base, g_b.rig->tx_base);
}

// Driving A with nothing on the wire leaves B byte for byte as it was. This is the whole claim:
// two instances are two sets of borrows and share NOT ONE BYTE.
void test_driving_a_changes_no_byte_of_b(void)
{
    memcpy(&g_snapshot, &g_b.b, sizeof g_snapshot);

    (void)node_resolve(&g_a, IP_B);
    (void)send_echo(&g_a, IP_B, 1u, 1u, 8u);
    node_timers(&g_a);
    node_flush(&g_a);
    node_drain(&g_a);
    idemip_fake_phy_poll(g_a.rig);

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&g_snapshot, &g_b.b, sizeof g_snapshot,
                                     "driving A wrote into B's borrows without a frame");
}

// And a frame IS the one thing that changes it: the same drive, with the wire connected, does.
void test_a_frame_is_the_only_thing_that_reaches_b(void)
{
    memcpy(&g_snapshot, &g_b.b, sizeof g_snapshot);

    (void)node_resolve(&g_a, IP_B);
    pump(6);

    TEST_ASSERT_TRUE(memcmp(&g_snapshot, &g_b.b, sizeof g_snapshot) != 0);
}

// Every unit's writes stay inside its own IDEMIP_<UNIT>_BORROW, which the canary past each one
// proves. tearDown checks it after every case; a whole exchange is checked here too.
void test_no_unit_writes_past_its_borrow(void)
{
    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);
    check_canaries(&g_a.b);
    check_canaries(&g_b.b);
    TEST_PASS();
}

// =============================================================================
// the driver seam
// =============================================================================

// A fed frame reaches a receive buffer on a poll and never before it, which is what lets a case
// decide when a transfer completes.
void test_the_engine_advances_only_in_poll(void)
{
    uint8_t frame[64];

    memset(frame, 0, sizeof frame);
    idemip_eth_build(frame, MAC_A, MAC_B, (uint16_t)IDEMIP_ETHERTYPE_ARP);
    TEST_ASSERT_TRUE(idemip_fake_phy_feed(g_a.rig, frame, sizeof frame));

    TEST_ASSERT_EQUAL_size_t(1u, idemip_fake_phy_in_count(g_a.rig));
    Dma.rx_take(g_a.b.dma);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DMA_IO(g_a.b.dma)->status);

    idemip_fake_phy_poll(g_a.rig);
    TEST_ASSERT_EQUAL_size_t(0u, idemip_fake_phy_in_count(g_a.rig));
    Dma.rx_take(g_a.b.dma);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(g_a.b.dma)->status);
    TEST_ASSERT_EQUAL_size_t(sizeof frame, IDEMIP_DMA_IO(g_a.b.dma)->len);
}

// The engine wrote the buffer, so its stale cached copy is discarded before the frame is read.
// Ordering is the whole claim: the invalidate follows the claim and precedes the frame being
// readable.
void test_receive_invalidates_before_the_frame_is_readable(void)
{
    uint8_t frame[64];

    memset(frame, 0xA5, sizeof frame);
    TEST_ASSERT_TRUE(idemip_fake_phy_feed(g_a.rig, frame, sizeof frame));
    idemip_fake_phy_poll(g_a.rig);
    g_a.rig->ev_n = 0;

    Dma.rx_take(g_a.b.dma);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(g_a.b.dma)->status);
    TEST_ASSERT_EQUAL_UINT32(2u, g_a.rig->ev_n);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_FAKE_PHY_EV_RX_CLAIM, g_a.rig->ev[0]);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_FAKE_PHY_EV_INVALIDATE, g_a.rig->ev[1]);
    TEST_ASSERT_EQUAL_PTR(IDEMIP_DMA_IO(g_a.b.dma)->buf, g_a.rig->last_invalidate);
    TEST_ASSERT_EQUAL_size_t(sizeof frame, g_a.rig->last_invalidate_len);
}

// The engine reads the buffer, so what the build left in cache is written back before the
// descriptor is handed over: the clean precedes the commit.
void test_transmit_cleans_before_the_descriptor_is_handed_over(void)
{
    uint8_t desc = 0;
    uint8_t *frame = node_tx_claim(&g_a, &desc);

    TEST_ASSERT_NOT_NULL(frame);
    idemip_arp_build_request(frame + IDEMIP_ETH_HDR_LEN, g_a.mac, g_a.ip, IP_B);
    g_a.rig->ev_n = 0;
    TEST_ASSERT_TRUE(node_send_frame(&g_a, frame, desc, MAC_BCAST, (uint16_t)IDEMIP_ETHERTYPE_ARP, IDEMIP_ARP_LEN));

    TEST_ASSERT_EQUAL_UINT32(2u, g_a.rig->ev_n);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_FAKE_PHY_EV_CLEAN, g_a.rig->ev[0]);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_FAKE_PHY_EV_TX_COMMIT, g_a.rig->ev[1]);
    TEST_ASSERT_EQUAL_PTR(IDEMIP_DMA_IO(g_a.b.dma)->buf, g_a.rig->last_clean);
}

// A committed frame is readable back only after a poll, so egress completes on the case's clock
// too.
void test_a_committed_frame_is_readable_only_after_a_poll(void)
{
    TEST_ASSERT_TRUE(node_send_arp_request(&g_a, IP_B));
    TEST_ASSERT_EQUAL_size_t(0u, idemip_fake_phy_tx_count(g_a.rig));
    idemip_fake_phy_poll(g_a.rig);
    TEST_ASSERT_EQUAL_size_t(1u, idemip_fake_phy_tx_count(g_a.rig));
}

// A claim that no post commits keeps its transmit buffer out of the ring for good, because
// IdemIpPhyDriver has no entry that gives an unposted one back, so a whole exchange has to leave
// the ring where it found it.
void test_a_whole_exchange_leaks_no_transmit_descriptor(void)
{
    static const uint8_t msg[] = "no leak";

    resolve_both();
    node_open_udp(&g_a, UDP_PORT_A);
    node_open_udp(&g_b, UDP_PORT_B);
    (void)send_udp(&g_a, IP_B, UDP_PORT_A, UDP_PORT_B, msg, sizeof msg - 1u);
    pump(10);
    (void)send_echo(&g_a, IP_B, 0x2222u, 3u, 8u);
    pump(12);

    Dma.tx_take(g_a.b.dma);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_DMA_IO(g_a.b.dma)->status,
                                  "A's transmit ring did not come back after the exchange");
    Dma.tx_take(g_b.b.dma);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_DMA_IO(g_b.b.dma)->status,
                                  "B's transmit ring did not come back after the exchange");
    TEST_ASSERT_TRUE(g_a.rig->tx_claims - g_a.rig->tx_commits <= 1u);
    TEST_ASSERT_TRUE(g_b.rig->tx_claims - g_b.rig->tx_commits <= 1u);
}

// =============================================================================
// RFC 826 address resolution
// =============================================================================

// "generates an Ethernet packet with a type field of ether_type$ADDRESS_RESOLUTION ... It then
// causes this packet to be broadcast to all stations on the Ethernet cable."
void test_a_missing_pair_puts_a_broadcast_request_on_the_wire(void)
{
    uint8_t frame[IDEMIP_ETH_FRAME_MAX];

    TEST_ASSERT_NULL(node_resolve(&g_a, IP_B));
    idemip_fake_phy_poll(g_a.rig);
    size_t len = idemip_fake_phy_capture(g_a.rig, frame, sizeof frame);
    TEST_ASSERT_TRUE(len >= IDEMIP_ETH_FRAME_MIN);
    TEST_ASSERT_TRUE(idemip_eth_is_broadcast(idemip_eth_dst(frame)));
    TEST_ASSERT_EQUAL_HEX16(IDEMIP_ETHERTYPE_ARP, idemip_eth_type(frame));

    const uint8_t *arp = idemip_eth_payload(frame);
    TEST_ASSERT_TRUE(idemip_arp_is_ethernet_ipv4(arp));
    TEST_ASSERT_TRUE(idemip_arp_is_request(arp));
    TEST_ASSERT_EQUAL_HEX32(IP_A, idemip_arp_spa(arp));
    TEST_ASSERT_EQUAL_HEX32(IP_B, idemip_arp_tpa(arp));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(MAC_A, idemip_arp_sha(arp), IDEMIP_MAC_LEN);
}

// "Swap hardware and protocol fields, putting the local hardware and protocol addresses in the
// sender fields. Set the ar$op field to ares_op$REPLY."
void test_the_reply_resolves_the_pair_on_the_asking_side(void)
{
    (void)node_resolve(&g_a, IP_B);
    pump(8);

    TEST_ASSERT_EQUAL_INT(1, g_b.arp_replies_out);
    const uint8_t *mac = node_resolve(&g_a, IP_B);
    TEST_ASSERT_NOT_NULL(mac);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(MAC_B, mac, IDEMIP_MAC_LEN);
}

// "Notice that the <protocol type, sender protocol address, sender hardware address> triplet is
// merged into the table before the opcode is looked at", so the answering end learns the asker too.
void test_the_answering_side_learns_the_asker(void)
{
    (void)node_resolve(&g_a, IP_B);
    pump(8);

    IDEMIP_ARP_IO(g_b.b.arp)->now_ms = g_now_ms;
    IDEMIP_ARP_IO(g_b.b.arp)->find_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(g_b.b.arp)->find_args.spa = IP_A;
    ArpTable.find(g_b.b.arp);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ARP_IO(g_b.b.arp)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(MAC_A, IDEMIP_ARP_IO(g_b.b.arp)->mac, IDEMIP_MAC_LEN);
}

// "If Merge_flag is false, add the triplet ... to the translation table" sits INSIDE the "?Am I the
// target protocol address?" yes branch, so a request for a third party from a sender that is not
// already in the table adds nothing.
void test_a_request_for_a_third_party_creates_no_entry(void)
{
    uint8_t frame[IDEMIP_ETH_FRAME_MIN];

    memset(frame, 0, sizeof frame);
    idemip_eth_build(frame, MAC_BCAST, MAC_A, (uint16_t)IDEMIP_ETHERTYPE_ARP);
    idemip_arp_build_request(frame + IDEMIP_ETH_HDR_LEN, MAC_A, IP_A, IP_C);
    TEST_ASSERT_TRUE(idemip_fake_phy_feed(g_b.rig, frame, sizeof frame));
    pump(4);

    IDEMIP_ARP_IO(g_b.b.arp)->now_ms = g_now_ms;
    IDEMIP_ARP_IO(g_b.b.arp)->find_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(g_b.b.arp)->find_args.spa = IP_A;
    ArpTable.find(g_b.b.arp);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_ARP_IO(g_b.b.arp)->status,
                                  "RFC 826 adds the triplet only when this end is the target protocol address");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_b.arp_replies_out, "a request for a third party owes no REPLY");
}

// The merge itself is NOT inside that branch: "If the pair ... is already in my translation table,
// update the sender hardware address field of the entry", whoever the target is.
void test_a_request_for_a_third_party_still_updates_a_known_pair(void)
{
    const uint8_t other_mac[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0xEE};
    uint8_t frame[IDEMIP_ETH_FRAME_MIN];

    (void)node_resolve(&g_a, IP_B);
    pump(8);
    IDEMIP_ARP_IO(g_b.b.arp)->find_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(g_b.b.arp)->find_args.spa = IP_A;
    ArpTable.find(g_b.b.arp);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ARP_IO(g_b.b.arp)->status);

    memset(frame, 0, sizeof frame);
    idemip_eth_build(frame, MAC_BCAST, other_mac, (uint16_t)IDEMIP_ETHERTYPE_ARP);
    idemip_arp_build_request(frame + IDEMIP_ETH_HDR_LEN, other_mac, IP_A, IP_C);
    TEST_ASSERT_TRUE(idemip_fake_phy_feed(g_b.rig, frame, sizeof frame));
    pump(4);

    IDEMIP_ARP_IO(g_b.b.arp)->find_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(g_b.b.arp)->find_args.spa = IP_A;
    ArpTable.find(g_b.b.arp);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ARP_IO(g_b.b.arp)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(other_mac, IDEMIP_ARP_IO(g_b.b.arp)->mac, IDEMIP_MAC_LEN,
                                          "the new hardware address supersedes the old one");
}

// A's table and B's table are two borrows: what A learned is not in B's.
void test_the_two_translation_tables_are_two_borrows(void)
{
    (void)node_resolve(&g_a, IP_C);
    pump(6);

    IDEMIP_ARP_IO(g_a.b.arp)->find_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(g_a.b.arp)->find_args.spa = IP_C;
    ArpTable.find(g_a.b.arp);
    IdemIpStatus a_status = IDEMIP_ARP_IO(g_a.b.arp)->status;

    IDEMIP_ARP_IO(g_b.b.arp)->find_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(g_b.b.arp)->find_args.spa = IP_C;
    ArpTable.find(g_b.b.arp);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IDEMIP_ARP_IO(g_b.b.arp)->status,
                                  "B's table holds a row A opened");
    TEST_ASSERT_NOT_EQUAL(IDEMIP_OK, a_status); // A is still waiting on the REPLY that never comes
}

// =============================================================================
// what a drop is counted as (RFC 1213)
// =============================================================================

// RFC 1213 sec 6.4 ifInUnknownProtos: "packets received via the interface which were discarded
// because of an unknown or unsupported protocol", which is the EtherType case.
void test_an_unhandled_ethertype_is_an_interface_unknown_proto(void)
{
    uint8_t frame[IDEMIP_ETH_FRAME_MIN];

    memset(frame, 0, sizeof frame);
    idemip_eth_build(frame, MAC_B, MAC_A, 0x88CCu); // LLDP, which nothing here handles
    TEST_ASSERT_TRUE(idemip_fake_phy_feed(g_b.rig, frame, sizeof frame));
    pump(4);

    IDEMIP_STATS_IO(g_b.b.stats)->if_args.netif = 0u;
    IDEMIP_STATS_IO(g_b.b.stats)->if_args.id = IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS;
    Stats.if_read(g_b.b.stats);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(g_b.b.stats)->status);
    TEST_ASSERT_EQUAL_UINT32(1u, IDEMIP_STATS_IO(g_b.b.stats)->value);
}

// RFC 1213 sec 6.6 ipInUnknownProtos: "locally-addressed datagrams received successfully but
// discarded because of an unknown or unsupported protocol", which is the IP Protocol field case and
// is a different object from the interface one above.
void test_an_unhandled_ip_protocol_is_an_ip_unknown_proto(void)
{
    uint8_t frame[IDEMIP_ETH_FRAME_MIN];
    IdemIpIp4Fields f;

    memset(frame, 0, sizeof frame);
    idemip_eth_build(frame, MAC_B, MAC_A, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    memset(&f, 0, sizeof f);
    f.total_len = (uint16_t)(IDEMIP_IPV4_HDR_LEN + 8u);
    f.ttl = (uint8_t)IDEMIP_IP_DEFAULT_TTL;
    f.proto = 253u; // RFC 3692 experimentation, which nothing here handles
    f.src = IP_A;
    f.dst = IP_B;
    idemip_ip4_build(frame + IDEMIP_ETH_HDR_LEN, &f);
    TEST_ASSERT_TRUE(idemip_fake_phy_feed(g_b.rig, frame, sizeof frame));
    pump(4);

    IDEMIP_STATS_IO(g_b.b.stats)->ctr_args.id = IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS;
    Stats.read(g_b.b.stats);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_STATS_IO(g_b.b.stats)->status);
    TEST_ASSERT_EQUAL_UINT32(1u, IDEMIP_STATS_IO(g_b.b.stats)->value);

    IDEMIP_STATS_IO(g_b.b.stats)->if_args.netif = 0u;
    IDEMIP_STATS_IO(g_b.b.stats)->if_args.id = IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS;
    Stats.if_read(g_b.b.stats);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, IDEMIP_STATS_IO(g_b.b.stats)->value,
                                     "an unknown IP protocol was counted against the interface object");
}

// RFC 1213 sec 6.4 ifInDiscards: "chosen to be discarded even though no errors had been detected".
// A datagram for another address is intact and deliberately dropped, so it is not ifInErrors.
void test_a_datagram_for_another_address_is_an_interface_discard(void)
{
    uint8_t frame[IDEMIP_ETH_FRAME_MIN];
    IdemIpIp4Fields f;

    memset(frame, 0, sizeof frame);
    idemip_eth_build(frame, MAC_B, MAC_A, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    memset(&f, 0, sizeof f);
    f.total_len = (uint16_t)(IDEMIP_IPV4_HDR_LEN + 8u);
    f.ttl = (uint8_t)IDEMIP_IP_DEFAULT_TTL;
    f.proto = (uint8_t)IDEMIP_IP4_PROTO_UDP;
    f.src = IP_A;
    f.dst = IP_C;
    idemip_ip4_build(frame + IDEMIP_ETH_HDR_LEN, &f);
    TEST_ASSERT_TRUE(idemip_fake_phy_feed(g_b.rig, frame, sizeof frame));
    pump(4);

    IDEMIP_STATS_IO(g_b.b.stats)->if_args.netif = 0u;
    IDEMIP_STATS_IO(g_b.b.stats)->if_args.id = IDEMIP_STAT_IF_IN_DISCARDS;
    Stats.if_read(g_b.b.stats);
    TEST_ASSERT_EQUAL_UINT32(1u, IDEMIP_STATS_IO(g_b.b.stats)->value);

    IDEMIP_STATS_IO(g_b.b.stats)->if_args.id = IDEMIP_STAT_IF_IN_ERRORS;
    Stats.if_read(g_b.b.stats);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, IDEMIP_STATS_IO(g_b.b.stats)->value,
                                     "an intact datagram for another address was counted as an error");
}

// RFC 1213 sec 6.4 ifInErrors: "inbound packets that contained errors preventing them from being
// deliverable". A header idemip_ip4_verify refuses is one.
void test_a_bad_header_is_an_interface_error(void)
{
    uint8_t frame[IDEMIP_ETH_FRAME_MIN];
    IdemIpIp4Fields f;

    memset(frame, 0, sizeof frame);
    idemip_eth_build(frame, MAC_B, MAC_A, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    memset(&f, 0, sizeof f);
    f.total_len = (uint16_t)(IDEMIP_IPV4_HDR_LEN + 8u);
    f.ttl = (uint8_t)IDEMIP_IP_DEFAULT_TTL;
    f.proto = (uint8_t)IDEMIP_IP4_PROTO_UDP;
    f.src = IP_A;
    f.dst = IP_B;
    idemip_ip4_build(frame + IDEMIP_ETH_HDR_LEN, &f);
    // RFC 1122 sec 3.2.1.2 discards a datagram whose header checksum does not hold.
    frame[IDEMIP_ETH_HDR_LEN + IDEMIP_IP4_OFF_CKSUM] ^= 0xFFu;
    TEST_ASSERT_TRUE(idemip_fake_phy_feed(g_b.rig, frame, sizeof frame));
    pump(4);

    IDEMIP_STATS_IO(g_b.b.stats)->if_args.netif = 0u;
    IDEMIP_STATS_IO(g_b.b.stats)->if_args.id = IDEMIP_STAT_IF_IN_ERRORS;
    Stats.if_read(g_b.b.stats);
    TEST_ASSERT_EQUAL_UINT32(1u, IDEMIP_STATS_IO(g_b.b.stats)->value);
}

// =============================================================================
// RFC 792 echo
// =============================================================================

void test_an_echo_request_draws_an_echo_reply(void)
{
    resolve_both();
    TEST_ASSERT_TRUE(send_echo(&g_a, IP_B, 0xABCDu, 7u, 16u));
    pump(12);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_b.icmp_echoes, "B did not answer the Echo");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_a.icmp_replies, "A did not see the Echo Reply");
}

// RFC 792 Echo Reply: "The identifier and sequence number may be used by the echo sender to aid in
// matching the replies with the echo requests."
void test_the_echo_reply_carries_the_identifier_and_sequence(void)
{
    resolve_both();
    TEST_ASSERT_TRUE(send_echo(&g_a, IP_B, 0xABCDu, 7u, 16u));
    pump(12);

    TEST_ASSERT_EQUAL_HEX16(0xABCDu, g_a.icmp_reply_id);
    TEST_ASSERT_EQUAL_HEX16(7u, g_a.icmp_reply_seq);
}

// =============================================================================
// RFC 768 datagrams
// =============================================================================

void test_a_udp_datagram_reaches_b(void)
{
    static const uint8_t payload[] = "a to b";

    resolve_both();
    node_open_udp(&g_a, UDP_PORT_A);
    node_open_udp(&g_b, UDP_PORT_B);
    TEST_ASSERT_TRUE(send_udp(&g_a, IP_B, UDP_PORT_A, UDP_PORT_B, payload, sizeof payload - 1u));
    pump(10);

    TEST_ASSERT_EQUAL_INT(1, g_b.udp_rx_count);
    TEST_ASSERT_EQUAL_size_t(sizeof payload - 1u, g_b.udp_rx_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, g_b.udp_rx, sizeof payload - 1u);
    TEST_ASSERT_EQUAL_UINT16(UDP_PORT_A, g_b.udp_rx_src_port);
    TEST_ASSERT_EQUAL_HEX32(IP_A, g_b.udp_rx_src_ip);
}

void test_a_udp_datagram_reaches_a(void)
{
    static const uint8_t payload[] = "b to a";

    resolve_both();
    node_open_udp(&g_a, UDP_PORT_A);
    node_open_udp(&g_b, UDP_PORT_B);
    TEST_ASSERT_TRUE(send_udp(&g_b, IP_A, UDP_PORT_B, UDP_PORT_A, payload, sizeof payload - 1u));
    pump(10);

    TEST_ASSERT_EQUAL_INT(1, g_a.udp_rx_count);
    TEST_ASSERT_EQUAL_size_t(sizeof payload - 1u, g_a.udp_rx_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, g_a.udp_rx, sizeof payload - 1u);
}

// RFC 1122 sec 4.1.3.1: no binding is where "UDP SHOULD send an ICMP Port Unreachable message".
void test_a_datagram_to_an_unbound_port_finds_no_binding(void)
{
    static const uint8_t payload[] = "nobody home";

    resolve_both();
    node_open_udp(&g_a, UDP_PORT_A);
    TEST_ASSERT_TRUE(send_udp(&g_a, IP_B, UDP_PORT_A, 9999u, payload, sizeof payload - 1u));
    pump(10);

    TEST_ASSERT_EQUAL_INT(0, g_b.udp_rx_count);
    TEST_ASSERT_EQUAL_INT(1, g_b.udp_no_binding);
}

// The two binding tables are two borrows: A's binding is not in B's table.
void test_the_two_binding_tables_are_two_borrows(void)
{
    uint8_t local16[IDEMIP_TCP_PCB_ADDR_BYTES];
    uint8_t remote16[IDEMIP_TCP_PCB_ADDR_BYTES];

    node_open_udp(&g_a, UDP_PORT_A);
    memset(local16, 0, sizeof local16);
    memset(remote16, 0, sizeof remote16);
    idemip_wr32(local16, IP_A);
    idemip_wr32(remote16, IP_B);

    UdpPcbIo *io = IDEMIP_UDP_PCB_IO(g_b.b.udp);
    io->find_args.local_ip = local16;
    io->find_args.remote_ip = remote16;
    io->find_args.local_port = UDP_PORT_A;
    io->find_args.remote_port = UDP_PORT_B;
    io->find_args.cksum_len = 0u;
    io->find_args.ip_version = 4u;
    io->find_args.netif = 0u;
    UdpPcb.find(g_b.b.udp);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// =============================================================================
// RFC 9293 sec 3.5 Figure 6 and sec 3.6 Figure 12
// =============================================================================

// Line 2: "SYN-SENT --> <SEQ=100><CTL=SYN> --> SYN-RECEIVED".
void test_the_syn_moves_a_to_syn_sent_and_b_to_syn_received(void)
{
    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);

    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_SYN_SENT, tcp_state(&g_a));
    pump(4);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_TCP_STATE_SYN_RECEIVED, tcp_state(&g_b),
                                  "B did not reach SYN-RECEIVED on the SYN");
}

// Lines 3 and 4: "ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>" then
// "ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK> --> ESTABLISHED". Both TCBs are asserted.
void test_the_three_way_handshake_establishes_both_tcbs(void)
{
    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_TCP_STATE_ESTABLISHED, tcp_state(&g_a), "A is not ESTABLISHED");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_TCP_STATE_ESTABLISHED, tcp_state(&g_b), "B is not ESTABLISHED");
    TEST_ASSERT_EQUAL_INT(1, g_a.tcp.established);
    TEST_ASSERT_EQUAL_INT(1, g_b.tcp.established);
}

// sec 3.10.7.2 sets "RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ", and sec 3.10.7.3 the mirror, so
// each end's IRS is the other's ISS and each RCV.NXT is one past it.
void test_each_end_took_the_others_initial_sequence_number(void)
{
    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);

    IDEMIP_TCP_PCB_IO(g_a.b.tpcb)->pcb_args.index = g_a.tcp.tcb;
    TcpPcb.load(g_a.b.tpcb);
    IdemIpTcpVars av = IDEMIP_TCP_PCB_IO(g_a.b.tpcb)->vars;

    IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->pcb_args.index = g_b.tcp.tcb;
    TcpPcb.load(g_b.b.tpcb);
    IdemIpTcpVars bv = IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->vars;

    TEST_ASSERT_EQUAL_HEX32(av.iss, bv.irs);
    TEST_ASSERT_EQUAL_HEX32(bv.iss, av.irs);
    TEST_ASSERT_EQUAL_HEX32(av.iss + 1u, bv.rcv_nxt);
    TEST_ASSERT_EQUAL_HEX32(bv.iss + 1u, av.rcv_nxt);
    TEST_ASSERT_EQUAL_HEX32(av.iss + 1u, av.snd_nxt);
    TEST_ASSERT_EQUAL_HEX32(bv.iss + 1u, bv.snd_nxt);
}

// The two ISN generators are two borrows keyed with two secrets, so the same four-tuple does not
// draw the same initial send sequence number on both ends (RFC 6528 sec 3).
void test_the_two_ends_draw_different_initial_sequence_numbers(void)
{
    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);

    IDEMIP_TCP_PCB_IO(g_a.b.tpcb)->pcb_args.index = g_a.tcp.tcb;
    TcpPcb.load(g_a.b.tpcb);
    uint32_t a_iss = IDEMIP_TCP_PCB_IO(g_a.b.tpcb)->vars.iss;

    IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->pcb_args.index = g_b.tcp.tcb;
    TcpPcb.load(g_b.b.tpcb);
    uint32_t b_iss = IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->vars.iss;

    TEST_ASSERT_TRUE(a_iss != b_iss);
}

// Line 5: "ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED".
void test_data_reaches_b(void)
{
    static const uint8_t msg[] = "hello from a";

    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_ESTABLISHED, tcp_state(&g_a));

    TEST_ASSERT_TRUE(tcp_write(&g_a, msg, (uint16_t)(sizeof msg - 1u)));
    pump(12);

    TEST_ASSERT_EQUAL_size_t(sizeof msg - 1u, g_b.tcp.rx_len);
    TEST_ASSERT_EQUAL_MEMORY(msg, g_b.tcp.rx, sizeof msg - 1u);
}

void test_data_reaches_a(void)
{
    static const uint8_t msg[] = "hello from b";

    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_ESTABLISHED, tcp_state(&g_b));

    TEST_ASSERT_TRUE(tcp_write(&g_b, msg, (uint16_t)(sizeof msg - 1u)));
    pump(12);

    TEST_ASSERT_EQUAL_size_t(sizeof msg - 1u, g_a.tcp.rx_len);
    TEST_ASSERT_EQUAL_MEMORY(msg, g_a.tcp.rx, sizeof msg - 1u);
}

// Delivered data advances RCV.NXT by exactly the octets taken (sec 3.10.7.4 seventh).
void test_delivered_data_advances_the_receive_window(void)
{
    static const uint8_t msg[] = "0123456789";

    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);

    IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->pcb_args.index = g_b.tcp.tcb;
    TcpPcb.load(g_b.b.tpcb);
    uint32_t before = IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->vars.rcv_nxt;

    TEST_ASSERT_TRUE(tcp_write(&g_a, msg, (uint16_t)(sizeof msg - 1u)));
    pump(12);

    IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->pcb_args.index = g_b.tcp.tcb;
    TcpPcb.load(g_b.b.tpcb);
    TEST_ASSERT_EQUAL_HEX32(before + (sizeof msg - 1u), IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->vars.rcv_nxt);
}

// sec 3.6 Figure 12 line 2: "FIN-WAIT-1 --> <SEQ=100><ACK=300><CTL=FIN,ACK> --> CLOSE-WAIT".
void test_the_first_fin_moves_a_to_fin_wait_and_b_to_close_wait(void)
{
    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);

    TEST_ASSERT_TRUE(tcp_close(&g_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_FIN_WAIT_1, tcp_state(&g_a));
    pump(12);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_TCP_STATE_CLOSE_WAIT, tcp_state(&g_b), "B did not reach CLOSE-WAIT");
    TEST_ASSERT_EQUAL_INT(1, g_b.tcp.fin_seen);
}

// sec 3.6 Figure 12 line 3: "FIN-WAIT-2 <-- <SEQ=300><ACK=101><CTL=ACK> <-- CLOSE-WAIT".
void test_the_ack_of_the_first_fin_moves_a_to_fin_wait_2(void)
{
    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);
    TEST_ASSERT_TRUE(tcp_close(&g_a));
    pump(16);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_TCP_STATE_FIN_WAIT_2, tcp_state(&g_a), "A did not reach FIN-WAIT-2");
}

// sec 3.6 Figure 12 lines 4 and 5: "TIME-WAIT <-- <SEQ=300><ACK=101><CTL=FIN,ACK> <-- LAST-ACK" then
// "TIME-WAIT --> <SEQ=101><ACK=301><CTL=ACK> --> CLOSED". Both TCBs at each step.
void test_the_four_way_close_ends_in_time_wait_and_closed(void)
{
    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);

    TEST_ASSERT_TRUE(tcp_close(&g_a));
    pump(16);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_FIN_WAIT_2, tcp_state(&g_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_CLOSE_WAIT, tcp_state(&g_b));

    TEST_ASSERT_TRUE(tcp_close(&g_b));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_LAST_ACK, tcp_state(&g_b));
    pump(16);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_TCP_STATE_TIME_WAIT, tcp_state(&g_a), "A did not reach TIME-WAIT");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_b.tcp.deleted, "B did not delete the TCB on the ACK of its FIN");
    TEST_ASSERT_EQUAL_INT(2, g_a.tcp.fin_seen + g_b.tcp.fin_seen);
}

// =============================================================================
// the out-of-order queue, the ACK aggregation, and the re-delivery that joins them
// =============================================================================

// Put three ten-octet segments on the wire as 2, 3, 1, so the first two arrive past RCV.NXT.
static void tcp_three_out_of_order(void)
{
    static const uint8_t part1[10] = "AAAAAAAAAA";
    static const uint8_t part2[10] = "BBBBBBBBBB";
    static const uint8_t part3[10] = "CCCCCCCCCC";

    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_ESTABLISHED, tcp_state(&g_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_ESTABLISHED, tcp_state(&g_b));

    uint32_t base = tcp_snd_nxt(&g_a);
    TEST_ASSERT_TRUE(tcp_send_at(&g_a, base + 10u, part2, 10u));
    TEST_ASSERT_TRUE(tcp_send_at(&g_a, base + 20u, part3, 10u));
    TEST_ASSERT_TRUE(tcp_send_at(&g_a, base, part1, 10u));
    tcp_advance_snd(&g_a, 30u);
}

// sec 3.10.7.4 seventh: "A segment that begins past RCV.NXT is held". Each held one pins the receive
// descriptor its octets lie in, which is what IDEMIP_MAX_PINNED_FRAMES counts IDEMIP_TCP_OOSEQ_SEGS
// of per connection.
void test_a_segment_past_rcv_nxt_is_held_on_a_pinned_descriptor(void)
{
    static const uint8_t part2[10] = "BBBBBBBBBB";

    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);

    uint32_t base = tcp_snd_nxt(&g_a);
    TEST_ASSERT_TRUE(tcp_send_at(&g_a, base + 10u, part2, 10u));
    pump(6);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_b.oos_held, "the out-of-order segment was not held");
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0u, g_b.tcp.rx_len, "a segment past RCV.NXT was delivered early");
    Dma.pinned(g_b.b.dma);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(1u, IDEMIP_DMA_IO(g_b.b.dma)->pinned, "the held segment pinned no descriptor");
}

// The gap closes, RCV.NXT advances over the in-order segment, and every held segment that is now in
// order goes with it, in sequence.
void test_the_gap_closing_re_delivers_the_held_segments_in_order(void)
{
    tcp_three_out_of_order();
    pump(10);

    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g_b.oos_delivered, "the held segments were not re-delivered");
    TEST_ASSERT_EQUAL_INT(0, g_b.oos_held);
    TEST_ASSERT_EQUAL_size_t(30u, g_b.tcp.rx_len);
    TEST_ASSERT_EQUAL_MEMORY("AAAAAAAAAABBBBBBBBBBCCCCCCCCCC", g_b.tcp.rx, 30u);
}

// Every descriptor a held segment pinned comes back once that segment is delivered.
void test_re_delivery_hands_every_held_descriptor_back(void)
{
    tcp_three_out_of_order();
    pump(10);

    Dma.pinned(g_b.b.dma);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(g_b.b.dma)->status);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_DMA_IO(g_b.b.dma)->pinned,
                                     "a re-delivered segment left its descriptor pinned");
}

// RFC 9293 sec 3.10.7.4 (MUST-58, MUST-59): "if the TCP endpoint is processing a series of queued
// segments, it MUST process them all before sending any ACK segments". Three segments in one drain
// draw one acknowledgment, and it names the RCV.NXT past all three.
void test_a_series_of_queued_segments_draws_one_acknowledgment(void)
{
    tcp_three_out_of_order();
    int before = g_b.acks_sent;
    pump(10);

    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g_b.acks_aggregated, "three queued segments did not aggregate two ACKs");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_b.acks_sent - before, "the series drew more than one acknowledgment");

    IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->pcb_args.index = g_b.tcp.tcb;
    TcpPcb.load(g_b.b.tpcb);
    uint32_t b_rcv_nxt = IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->vars.rcv_nxt;
    IDEMIP_TCP_PCB_IO(g_a.b.tpcb)->pcb_args.index = g_a.tcp.tcb;
    TcpPcb.load(g_a.b.tpcb);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(b_rcv_nxt, IDEMIP_TCP_PCB_IO(g_a.b.tpcb)->vars.snd_una,
                                    "the one acknowledgment did not carry the RCV.NXT past all three");
}

// The out-of-order queue is B's borrow: holding two segments on B leaves A's queue empty.
void test_the_held_segments_are_bs_borrow_alone(void)
{
    static const uint8_t part2[10] = "BBBBBBBBBB";

    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);

    uint32_t base = tcp_snd_nxt(&g_a);
    TEST_ASSERT_TRUE(tcp_send_at(&g_a, base + 10u, part2, 10u));
    pump(6);

    IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->pcb_args.index = g_b.tcp.tcb;
    TcpPcb.load(g_b.b.tpcb);
    TEST_ASSERT_NOT_EQUAL(IDEMIP_TCP_PCB_NONE, IDEMIP_TCP_PCB_IO(g_b.b.tpcb)->info.ooseq);

    IDEMIP_TCP_PCB_IO(g_a.b.tpcb)->pcb_args.index = g_a.tcp.tcb;
    TcpPcb.load(g_a.b.tpcb);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(IDEMIP_TCP_PCB_NONE, IDEMIP_TCP_PCB_IO(g_a.b.tpcb)->info.ooseq,
                                     "A's out-of-order queue holds what B held");
    Dma.pinned(g_a.b.dma);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_DMA_IO(g_a.b.dma)->pinned);
}

// The two TCB tables are two borrows: B's connection is not in A's table.
void test_the_two_tcb_tables_are_two_borrows(void)
{
    uint8_t a16[IDEMIP_TCP_PCB_ADDR_BYTES];
    uint8_t b16[IDEMIP_TCP_PCB_ADDR_BYTES];

    resolve_both();
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);

    memset(a16, 0, sizeof a16);
    memset(b16, 0, sizeof b16);
    idemip_wr32(a16, IP_A);
    idemip_wr32(b16, IP_B);

    // B's own four-tuple, looked up in A's table: the local end is B's, which A never bound.
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(g_a.b.tpcb);
    tp->find_args.local_ip = b16;
    tp->find_args.remote_ip = a16;
    tp->find_args.local_port = TCP_PORT_B;
    tp->find_args.remote_port = g_a.tcp.local_port;
    tp->find_args.ip_version = 4u;
    tp->find_args.netif = 0u;
    TcpPcb.find(g_a.b.tpcb);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, tp->status);
}

// =============================================================================
// RFC 791 sec 3.2 fragmentation and reassembly
// =============================================================================

// Build one datagram larger than the MTU, cut it, and put every fragment on the wire.
static uint16_t g_frag_payload_len;

// One built fragment, framed and put on the wire. False when there was no transmit descriptor to
// claim or the MAC refused the frame; either one ends the run with the fragments already sent.
static idemip_bool node_send_one_fragment(Node *n, const uint8_t *dst_mac, uint16_t frag_len)
{
    uint8_t desc = 0;
    uint8_t *frame = node_tx_claim(n, &desc);

    if (frame == NULL)
    {
        return IDEMIP_FALSE;
    }
    memcpy(frame + IDEMIP_ETH_HDR_LEN, n->scratch, frag_len);
    return node_send_frame(n, frame, desc, dst_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4, frag_len);
}

static int send_fragmented(Node *n, uint32_t dst_ip, uint16_t mtu, uint16_t payload_len)
{
    static uint8_t dgram[2048];
    const uint8_t *dst_mac = node_resolve(n, dst_ip);
    IdemIpIp4Fields f;
    int sent = 0;

    if (dst_mac == NULL)
    {
        return 0;
    }
    memset(&f, 0, sizeof f);
    f.total_len = (uint16_t)(IDEMIP_IPV4_HDR_LEN + payload_len);
    f.id = 0x5A5Au;
    f.ttl = (uint8_t)IDEMIP_IP_DEFAULT_TTL;
    f.proto = (uint8_t)IDEMIP_IP4_PROTO_UDP;
    f.src = n->ip;
    f.dst = dst_ip;
    idemip_ip4_build(dgram, &f);

    uint8_t *udp = dgram + IDEMIP_IPV4_HDR_LEN;
    idemip_udp_build(udp, UDP_PORT_A, UDP_PORT_B, payload_len);
    for (size_t i = IDEMIP_UDP_HDR_LEN; i < payload_len; i++)
    {
        udp[i] = (uint8_t)(i & 0xFFu);
    }
    idemip_udp_cksum_write(udp, payload_len, n->ip, dst_ip);
    g_frag_payload_len = payload_len;

    Ip4FragIo *io = IDEMIP_IP4_FRAG_IO(n->b.frag);
    io->begin_args.dgram = dgram;
    io->begin_args.len = (size_t)IDEMIP_IPV4_HDR_LEN + payload_len;
    io->begin_args.mtu = mtu;
    Ip4Frag.begin(n->b.frag);
    if (io->status != IDEMIP_OK)
    {
        return 0;
    }
    for (;;)
    {
        io->next_args.out = n->scratch;
        io->next_args.cap = IDEMIP_ETH_MAX_PAYLOAD;
        Ip4Frag.next(n->b.frag);
        // Three ways to stop, and they are one thing: the builder has no fragment left, or the one
        // it built could not be sent. The length is read only once the status says there is one.
        if (io->status != IDEMIP_OK || !node_send_one_fragment(n, dst_mac, io->len))
        {
            break;
        }
        sent++;
        idemip_fake_phy_poll(n->rig);
        Dma.tx_reap(n->b.dma);
    }
    return sent;
}

// "If the total length is larger than the maximum transmission unit ... then fragment", so a
// datagram over the MTU comes out as more than one fragment and the last one clears MF.
void test_an_oversized_datagram_is_cut_into_fragments(void)
{
    resolve_both();
    int sent = send_fragmented(&g_a, IP_B, 600u, 1200u);

    TEST_ASSERT_TRUE_MESSAGE(sent >= 3, "a 1220-octet datagram at an MTU of 600 is at least three fragments");
    TEST_ASSERT_TRUE(idemip_fake_phy_tx_count(g_a.rig) >= 1u);
}

// RFC 815 sec 3 step 8: "If the hole descriptor list is now empty, the datagram is now complete."
void test_the_fragments_reassemble_into_the_original_datagram(void)
{
    resolve_both();
    node_open_udp(&g_a, UDP_PORT_A);
    node_open_udp(&g_b, UDP_PORT_B);

    TEST_ASSERT_TRUE(send_fragmented(&g_a, IP_B, 600u, 1200u) >= 3);
    pump(30);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_b.reassembled, "B did not complete the datagram");
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_IPV4_HDR_LEN + g_frag_payload_len, g_b.big_rx_len);
    TEST_ASSERT_FALSE_MESSAGE(idemip_ip4_is_fragment(g_b.big_rx), "the reassembled datagram still reads as a fragment");
    TEST_ASSERT_EQUAL_HEX32(IP_A, idemip_ip4_src(g_b.big_rx));
    TEST_ASSERT_EQUAL_HEX32(IP_B, idemip_ip4_dst(g_b.big_rx));
}

// The reassembled datagram is handed on to the transport, RFC 791 sec 3.2 step (15).
void test_the_reassembled_datagram_reaches_the_binding(void)
{
    resolve_both();
    node_open_udp(&g_a, UDP_PORT_A);
    node_open_udp(&g_b, UDP_PORT_B);

    TEST_ASSERT_TRUE(send_fragmented(&g_a, IP_B, 600u, 1200u) >= 3);
    pump(30);

    TEST_ASSERT_EQUAL_INT(1, g_b.udp_rx_count);
    TEST_ASSERT_EQUAL_size_t((size_t)(g_frag_payload_len - IDEMIP_UDP_HDR_LEN), g_b.udp_rx_len);
    for (size_t i = 0; i < g_b.udp_rx_len; i++)
    {
        TEST_ASSERT_EQUAL_HEX8((uint8_t)((i + IDEMIP_UDP_HDR_LEN) & 0xFFu), g_b.udp_rx[i]);
    }
}

// Every held fragment pins its receive descriptor, and every pin is dropped once the datagram is
// released: IDEMIP_MAX_PINNED_FRAMES is a bound, not a leak.
void test_reassembly_hands_every_pinned_descriptor_back(void)
{
    resolve_both();
    node_open_udp(&g_a, UDP_PORT_A);
    node_open_udp(&g_b, UDP_PORT_B);

    TEST_ASSERT_TRUE(send_fragmented(&g_a, IP_B, 600u, 1200u) >= 3);
    pump(30);

    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_b.reassembled, "nothing was reassembled, so nothing was ever pinned");
    TEST_ASSERT_TRUE_MESSAGE(g_b.max_pinned >= 2u, "the fragments never pinned more than one descriptor at once");
    TEST_ASSERT_TRUE_MESSAGE(g_b.max_pinned <= IDEMIP_MAX_PINNED_FRAMES,
                             "the pin count went past IDEMIP_MAX_PINNED_FRAMES");

    Dma.pinned(g_b.b.dma);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DMA_IO(g_b.b.dma)->status);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(0u, IDEMIP_DMA_IO(g_b.b.dma)->pinned, "a reassembled datagram left a pin behind");
    TEST_ASSERT_EQUAL_INT(0, g_b.fragments_held);
}

// The refill cursor never laps the release cursor, so no receive buffer is written over while a
// unit still pins it.
void test_the_receive_ring_never_laps_a_pinned_buffer(void)
{
    resolve_both();
    node_open_udp(&g_b, UDP_PORT_B);
    TEST_ASSERT_TRUE(send_fragmented(&g_a, IP_B, 600u, 1200u) >= 3);
    pump(30);

    TEST_ASSERT_TRUE_MESSAGE((g_b.rig->rx_fill - g_b.rig->rx_free) < IDEMIP_RX_DESCRIPTORS,
                             "the engine wrote over a buffer that was never released");
    TEST_ASSERT_EQUAL_UINT32(0u, g_b.rig->dropped_feeds);
}

// =============================================================================
// the capture
// =============================================================================

// The file header a libpcap reader opens: magic, version 2.4, snaplen, and DLT_EN10MB, all
// little-endian.
void test_the_pcap_global_header_declares_dlt_en10mb(void)
{
    uint8_t hdr[IDEMIP_PCAP_GLOBAL_HDR_LEN];

    TEST_ASSERT_EQUAL_size_t(sizeof hdr, idemip_pcap_global_header(hdr, sizeof hdr, IDEMIP_DLT_EN10MB));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(((const uint8_t[]){0xD4, 0xC3, 0xB2, 0xA1}), hdr, 4);
    TEST_ASSERT_EQUAL_HEX8(2u, hdr[4]);
    TEST_ASSERT_EQUAL_HEX8(0u, hdr[5]);
    TEST_ASSERT_EQUAL_HEX8(4u, hdr[6]);
    TEST_ASSERT_EQUAL_HEX8(0u, hdr[7]);
    TEST_ASSERT_EQUAL_HEX8(0xFFu, hdr[16]);
    TEST_ASSERT_EQUAL_HEX8(0xFFu, hdr[17]);
    TEST_ASSERT_EQUAL_HEX8(1u, hdr[20]);
    TEST_ASSERT_EQUAL_HEX8(0u, hdr[21]);
    TEST_ASSERT_EQUAL_HEX8(0u, hdr[22]);
    TEST_ASSERT_EQUAL_HEX8(0u, hdr[23]);
    TEST_ASSERT_EQUAL_size_t(0u, idemip_pcap_global_header(hdr, sizeof hdr - 1u, IDEMIP_DLT_EN10MB));
}

// The per-frame header: seconds, microseconds, stored octets, wire octets.
void test_the_pcap_record_header_layout(void)
{
    uint8_t hdr[IDEMIP_PCAP_REC_HDR_LEN];

    TEST_ASSERT_EQUAL_size_t(sizeof hdr, idemip_pcap_record_header(hdr, sizeof hdr, 3u, 250000u, 60u, 60u));
    TEST_ASSERT_EQUAL_HEX8(3u, hdr[0]);
    TEST_ASSERT_EQUAL_HEX8(0u, hdr[1]);
    TEST_ASSERT_EQUAL_HEX8(0x90u, hdr[4]);
    TEST_ASSERT_EQUAL_HEX8(0xD0u, hdr[5]);
    TEST_ASSERT_EQUAL_HEX8(0x03u, hdr[6]);
    TEST_ASSERT_EQUAL_HEX8(60u, hdr[8]);
    TEST_ASSERT_EQUAL_HEX8(60u, hdr[12]);
    TEST_ASSERT_EQUAL_size_t(0u, idemip_pcap_record_header(hdr, sizeof hdr - 1u, 0u, 0u, 0u, 0u));
}

// The whole exchange, written out. Every frame that crossed the wire is one record, so a failing
// run is openable in Wireshark.
void test_the_whole_exchange_is_written_as_a_pcap(void)
{
    static const uint8_t msg[] = "loopback";

    TEST_ASSERT_TRUE_MESSAGE(idemip_pcap_open(&g_pcap, "loopback.pcap"), "could not open loopback.pcap");
    g_pcap_open = 1;

    resolve_both();
    node_open_udp(&g_a, UDP_PORT_A);
    node_open_udp(&g_b, UDP_PORT_B);
    (void)send_udp(&g_a, IP_B, UDP_PORT_A, UDP_PORT_B, msg, sizeof msg - 1u);
    pump(10);
    (void)send_echo(&g_a, IP_B, 0x1111u, 1u, 8u);
    pump(10);
    tcp_listen(&g_b, TCP_PORT_B);
    tcp_connect(&g_a, IP_B, 0u, TCP_PORT_B);
    pump(20);
    (void)tcp_write(&g_a, msg, (uint16_t)(sizeof msg - 1u));
    pump(12);
    (void)tcp_close(&g_a);
    pump(16);
    (void)tcp_close(&g_b);
    pump(16);
    TEST_ASSERT_TRUE(send_fragmented(&g_a, IP_B, 600u, 1200u) >= 3);
    pump(30);

    TEST_ASSERT_TRUE_MESSAGE(g_a.rig->tx_commits >= 10u, "A transmitted less than the exchange");
    uint32_t frames = g_pcap.frames;
    size_t expect = idemip_pcap_expected_size(&g_pcap);
    idemip_pcap_close(&g_pcap);
    g_pcap_open = 0;

    TEST_ASSERT_TRUE_MESSAGE(frames >= 12u, "the capture is short of the exchange");

    FILE *fp = fopen("loopback.pcap", "rb");
    TEST_ASSERT_NOT_NULL(fp);
    uint8_t hdr[IDEMIP_PCAP_GLOBAL_HDR_LEN];
    TEST_ASSERT_EQUAL_size_t(sizeof hdr, fread(hdr, 1, sizeof hdr, fp));
    TEST_ASSERT_EQUAL_HEX8(0xD4u, hdr[0]);
    TEST_ASSERT_EQUAL_HEX8(1u, hdr[20]);
    TEST_ASSERT_EQUAL_INT(0, fseek(fp, 0, SEEK_END));
    long size = ftell(fp);
    fclose(fp);
    TEST_ASSERT_EQUAL_size_t(expect, (size_t)size);
}
