// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for the receive path, shaped on test/unit/ethernet/test_phy. Every case tests the
// CONTRACT and stays valid however the logic behind it is written:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two receive paths share not one byte
//   4. a canary past IDEMIP_DISPATCH_BORROW is intact after every case
//   5. the published offsets are ordered and do not overlap
//   6. every drop bumps the one RFC 1213 counter whose own wording names that reason
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/core/dispatch.h"

#include "src/arp/arp.h"
#include "src/icmp/icmp.h"
#include "src/ip/ipv4.h"
#if IDEMIP_ENABLE_IPV6
#include "src/ip/ipv6.h"
#include "src/ip/pseudo.h" // idemip_pseudo_accum, which a case below builds a checksum with
#endif
#if IDEMIP_ENABLE_TCP
#include "src/tcp/tcp.h"
#endif
#if IDEMIP_ENABLE_UDP
#include "src/udp/udp.h"
#endif

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_DISPATCH_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_DISPATCH_BORROW + 16];

// Every borrow the path calls into, each the caller's own.
static _Alignas(8) uint8_t stats_mem[IDEMIP_STATS_BORROW];
static _Alignas(8) uint8_t netif_mem[IDEMIP_NETIF_BORROW];
static _Alignas(8) uint8_t loopif_mem[IDEMIP_LOOPIF_BORROW];
static _Alignas(8) uint8_t vlan_mem[IDEMIP_VLAN_BORROW];
static _Alignas(8) uint8_t arp_mem[IDEMIP_ARP_BORROW];
static _Alignas(8) uint8_t ip4_addr_mem[IDEMIP_IP4_ADDR_BORROW];
static _Alignas(8) uint8_t ip4_reass_mem[IDEMIP_IP4_REASS_BORROW];
static _Alignas(8) uint8_t icmp_in_mem[IDEMIP_ICMP_IN_BORROW];
static _Alignas(8) uint8_t igmp_mem[IDEMIP_IGMP_BORROW];
#if IDEMIP_ENABLE_IPV6
static _Alignas(8) uint8_t ip6_addr_mem[IDEMIP_IP6_ADDR_BORROW];
static _Alignas(8) uint8_t ip6_reass_mem[IDEMIP_IP6_REASS_BORROW];
static _Alignas(8) uint8_t icmp6_in_mem[IDEMIP_ICMP6_IN_BORROW];
static _Alignas(8) uint8_t mld6_mem[IDEMIP_MLD6_BORROW];
#endif
static _Alignas(8) uint8_t raw_mem[IDEMIP_RAW_PCB_BORROW];
#if IDEMIP_ENABLE_UDP
static _Alignas(8) uint8_t udp_mem[IDEMIP_UDP_PCB_BORROW];
static _Alignas(8) uint8_t udplite_mem[IDEMIP_UDPLITE_BORROW];
#endif
#if IDEMIP_ENABLE_TCP
static _Alignas(8) uint8_t tcp_pcb_mem[IDEMIP_TCP_PCB_BORROW];
static _Alignas(8) uint8_t tcp_in_mem[IDEMIP_TCP_IN_BORROW];
#endif
static _Alignas(8) uint8_t phy_mem[IDEMIP_PHY_BORROW];

// The caller's frame and its transmit buffer.
static uint8_t g_frame[256];
static uint8_t g_out[256];

// RFC 5737 sec 3: 192.0.2.0/24 is "TEST-NET-1 ... for use in documentation".
#define LOCAL_IP4 0xC0000201u
#define REMOTE_IP4 0xC0000209u
#define OTHER_IP4 0xC6336409u
#define NETMASK4 0xFFFFFF00u

static const uint8_t g_local_mac[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t g_remote_mac[IDEMIP_MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x09};
static const uint8_t g_bcast_mac[IDEMIP_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#if IDEMIP_ENABLE_IPV6
// RFC 3849: 2001:DB8::/32 is "for use in documentation".
static const uint8_t g_ip6_any[IDEMIP_IP6_ADDR_LEN] = {0};
static const uint8_t g_local_ip6[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_remote_ip6[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09};
static const uint8_t g_other_ip6[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};
static const uint8_t g_lo6[IDEMIP_IP6_ADDR_LEN] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
#endif

#define VID_OURS 100u
#define VID_THEIRS 200u

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_DISPATCH_BORROW, CANARY, cap - IDEMIP_DISPATCH_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_DISPATCH_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_DISPATCH_BORROW");
    }
}

static void bind_all(uint8_t *w)
{
    DispatchIo *io = IDEMIP_DISPATCH_IO(w);
    io->bind_args.stats = stats_mem;
    io->bind_args.netif = netif_mem;
    io->bind_args.loopif = loopif_mem;
    io->bind_args.vlan = vlan_mem;
    io->bind_args.arp = arp_mem;
    io->bind_args.ip4_addr = ip4_addr_mem;
    io->bind_args.ip4_reass = ip4_reass_mem;
    io->bind_args.icmp_in = icmp_in_mem;
    io->bind_args.igmp = igmp_mem;
#if IDEMIP_ENABLE_IPV6
    io->bind_args.ip6_addr = ip6_addr_mem;
    io->bind_args.ip6_reass = ip6_reass_mem;
    io->bind_args.icmp6_in = icmp6_in_mem;
    io->bind_args.mld6 = mld6_mem;
#endif
    io->bind_args.raw_pcb = raw_mem;
#if IDEMIP_ENABLE_UDP
    io->bind_args.udp_pcb = udp_mem;
    io->bind_args.udplite = udplite_mem;
#endif
#if IDEMIP_ENABLE_TCP
    io->bind_args.tcp_pcb = tcp_pcb_mem;
    io->bind_args.tcp_in = tcp_in_mem;
#endif
    Dispatch.bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
}

static void if_untagged(uint8_t *w, uint8_t index)
{
    DispatchIo *io = IDEMIP_DISPATCH_IO(w);
    io->if_args.index = index;
    io->if_args.dma = NULL;
    io->if_args.vid = 0u;
    io->if_args.tagged = IDEMIP_FALSE;
    Dispatch.if_bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
}

static void if_tagged(uint8_t *w, uint8_t index, uint16_t vid)
{
    DispatchIo *io = IDEMIP_DISPATCH_IO(w);
    io->if_args.index = index;
    io->if_args.dma = NULL;
    io->if_args.vid = vid;
    io->if_args.tagged = IDEMIP_TRUE;
    Dispatch.if_bind(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
}

static uint32_t if_ctr(uint8_t netif, IdemIpStatsIfCounter id)
{
    IDEMIP_STATS_IO(stats_mem)->if_args.netif = netif;
    IDEMIP_STATS_IO(stats_mem)->if_args.id = id;
    Stats.if_read(stats_mem);
    return (IDEMIP_STATS_IO(stats_mem)->status == IDEMIP_OK) ? IDEMIP_STATS_IO(stats_mem)->value : 0xFFFFFFFFu;
}

static uint32_t ctr(IdemIpStatsCounter id)
{
    IDEMIP_STATS_IO(stats_mem)->ctr_args.id = id;
    Stats.read(stats_mem);
    return (IDEMIP_STATS_IO(stats_mem)->status == IDEMIP_OK) ? IDEMIP_STATS_IO(stats_mem)->value : 0xFFFFFFFFu;
}

#if IDEMIP_ENABLE_UDP
static uint16_t bind_udp4(uint16_t port)
{
    UdpPcbIo *up = IDEMIP_UDP_PCB_IO(udp_mem);
    up->open_args.ip_version = 4u;
    up->open_args.lite = IDEMIP_FALSE;
    UdpPcb.open(udp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, up->status);
    uint16_t pcb = up->index;
    static uint8_t local[4];
    idemip_wr32(local, LOCAL_IP4);
    up->bind_args.index = pcb;
    up->bind_args.ip = local;
    up->bind_args.port = port;
    up->bind_args.zone = 0u;
    up->bind_args.netif = 0u;
    UdpPcb.bind(udp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, up->status);
    return pcb;
}

#if IDEMIP_ENABLE_IPV6
static uint16_t bind_udp6(uint16_t port)
{
    UdpPcbIo *up = IDEMIP_UDP_PCB_IO(udp_mem);
    up->open_args.ip_version = 6u;
    up->open_args.lite = IDEMIP_FALSE;
    UdpPcb.open(udp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, up->status);
    uint16_t pcb = up->index;
    up->bind_args.index = pcb;
    up->bind_args.ip = g_local_ip6;
    up->bind_args.port = port;
    up->bind_args.zone = 0u;
    up->bind_args.netif = 0u;
    UdpPcb.bind(udp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, up->status);
    return pcb;
}
#endif
#endif

static void wire_units(void)
{
    Stats.clear(stats_mem);
    Vlan.clear(vlan_mem);
    ArpTable.clear(arp_mem);
    Ip4Addr.clear(ip4_addr_mem);
    Ip4Reass.clear(ip4_reass_mem);
    IcmpIn.clear(icmp_in_mem);
    Igmp.clear(igmp_mem);
#if IDEMIP_ENABLE_IPV6
    Ip6Addr.clear(ip6_addr_mem);
    Ip6Reass.clear(ip6_reass_mem);
    Icmp6In.clear(icmp6_in_mem);
    Mld6.clear(mld6_mem);
#endif
    RawPcb.clear(raw_mem);
#if IDEMIP_ENABLE_UDP
    UdpPcb.clear(udp_mem);
    UdpLite.clear(udplite_mem);
#endif
#if IDEMIP_ENABLE_TCP
    TcpPcb.clear(tcp_pcb_mem);
    TcpIn.clear(tcp_in_mem);
#endif

    Loopif.clear(loopif_mem);
    IDEMIP_LOOPIF_IO(loopif_mem)->bind_args.addr4 = 0x7F000001u;
#if IDEMIP_ENABLE_IPV6
    IDEMIP_LOOPIF_IO(loopif_mem)->bind_args.addr6 = g_lo6;
#endif
    IDEMIP_LOOPIF_IO(loopif_mem)->bind_args.mtu = 1500u;
    IDEMIP_LOOPIF_IO(loopif_mem)->bind_args.index = 0u;
    Loopif.bind(loopif_mem);

    Netif.clear(netif_mem);
    NetifIo *ni = IDEMIP_NETIF_IO(netif_mem);
    ni->bind_args.index = 0u;
    ni->bind_args.phy = phy_mem;
    ni->bind_args.hwaddr = g_local_mac;
    ni->bind_args.mtu = 1500u;
    Netif.bind(netif_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ni->status);
    ni->addr4_args.index = 0u;
    ni->addr4_args.addr = LOCAL_IP4;
    ni->addr4_args.mask = NETMASK4;
    ni->addr4_args.gw = REMOTE_IP4;
    Netif.set_addr4(netif_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ni->status);
    ni->if_args.index = 0u;
    ni->if_args.set = (uint16_t)(IDEMIP_NETIF_FLAG_UP | IDEMIP_NETIF_FLAG_LINK_UP | IDEMIP_NETIF_FLAG_BROADCAST |
                                 IDEMIP_NETIF_FLAG_ETHARP);
    ni->if_args.clear = 0u;
    Netif.set_flags(netif_mem);
#if IDEMIP_ENABLE_IPV6
    ni->addr6_args.index = 0u;
    ni->addr6_args.addr = g_local_ip6;
    ni->addr6_args.state = IDEMIP_NETIF_ADDR6_PREFERRED;
    ni->addr6_args.preferred_s = IDEMIP_NETIF_LIFETIME_INFINITE;
    ni->addr6_args.valid_s = IDEMIP_NETIF_LIFETIME_INFINITE;
    Netif.add_addr6(netif_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ni->status);
#endif
}

// --- frame building ----------------------------------------------------------

static size_t build_eth(uint8_t *f, const uint8_t *dst, uint16_t type)
{
    idemip_eth_build(f, dst, g_remote_mac, type);
    return IDEMIP_ETH_OFF_PAYLOAD;
}

static size_t build_eth_tagged(uint8_t *f, const uint8_t *dst, uint16_t type, uint16_t vid)
{
    idemip_eth_build(f, dst, g_remote_mac, type);
    IDEMIP_VLAN_IO(vlan_mem)->build_args.frame = f;
    IDEMIP_VLAN_IO(vlan_mem)->build_args.type = type;
    IDEMIP_VLAN_IO(vlan_mem)->tag_args.vid = vid;
    IDEMIP_VLAN_IO(vlan_mem)->tag_args.pcp = 0u;
    IDEMIP_VLAN_IO(vlan_mem)->tag_args.dei = IDEMIP_FALSE;
    Vlan.build(vlan_mem);
    return IDEMIP_VLAN_OFF_PAYLOAD;
}

// A tag the build entry refuses to write, because RFC 6325 sec 4.1.1 reserves it. A switch that is
// broken or an attacker still puts it on the wire, so the suite writes the octets by hand.
static size_t build_eth_tagged_raw(uint8_t *f, const uint8_t *dst, uint16_t type, uint16_t tci)
{
    idemip_eth_build(f, dst, g_remote_mac, (uint16_t)IDEMIP_VLAN_TPID);
    idemip_wr16(f + IDEMIP_VLAN_OFF_TCI, tci);
    idemip_wr16(f + IDEMIP_VLAN_OFF_TYPE, type);
    return IDEMIP_VLAN_OFF_PAYLOAD;
}

static size_t build_ip4(uint8_t *f, size_t off, uint8_t proto, uint32_t src, uint32_t dst, size_t payload_len,
                        uint16_t flags_frag)
{
    IdemIpIp4Fields fields;
    memset(&fields, 0, sizeof fields);
    fields.total_len = (uint16_t)(IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN) + payload_len);
    fields.id = 0x1234u;
    fields.flags_frag = flags_frag;
    fields.ttl = 64u;
    fields.proto = proto;
    fields.src = src;
    fields.dst = dst;
    idemip_ip4_build(f + off, &fields);
    return off + IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN);
}

#if IDEMIP_ENABLE_UDP
static size_t build_udp(uint8_t *f, size_t off, uint16_t sport, uint16_t dport, size_t data_len)
{
    idemip_udp_build(f + off, sport, dport, (uint16_t)(IDEMIP_UDP_HDR_LEN + data_len));
    memset(f + off + IDEMIP_UDP_HDR_LEN, 0xAB, data_len);
    return off + IDEMIP_UDP_HDR_LEN + data_len;
}

// The checksum over the pseudo-header RFC 768 prefixes, written into the datagram already at off.
// Left zero, an IPv4 datagram still arrives (RFC 768's "no checksum" encoding) but an IPv6 one must
// not (RFC 8200 sec 8.1), so a frame built without this tests less than it appears to.
static void seal_udp4(uint8_t *f, size_t off, uint32_t src, uint32_t dst)
{
    uint8_t *u = f + off;
    size_t len = (size_t)idemip_udp_len(u);
    idemip_wr16(u + IDEMIP_UDP_OFF_CKSUM, 0u);
    idemip_wr16(u + IDEMIP_UDP_OFF_CKSUM, idemip_udp_cksum_compute(u, len, src, dst));
}

static void seal_udp6(uint8_t *f, size_t off, const uint8_t *src, const uint8_t *dst)
{
    uint8_t *u = f + off;
    size_t len = (size_t)idemip_udp_len(u);
    idemip_wr16(u + IDEMIP_UDP_OFF_CKSUM, 0u);
    uint32_t sum = idemip_ip6_pseudo_accum(0u, src, dst, (uint32_t)len, IDEMIP_IP6_NH_UDP);
    uint16_t c = idemip_cksum_final(idemip_cksum_accum(sum, u, len));
    idemip_wr16(u + IDEMIP_UDP_OFF_CKSUM, (c == 0u) ? (uint16_t)IDEMIP_UDP_CKSUM_ZERO_AS : c);
}
#endif

static size_t build_icmp_echo(uint8_t *f, size_t off, size_t data_len)
{
    f[off + IDEMIP_ICMP_OFF_TYPE] = IDEMIP_ICMP_ECHO;
    f[off + 1u] = 0u;
    idemip_wr16(f + off + 2u, 0u);
    idemip_wr16(f + off + 4u, 0x0AAAu);
    idemip_wr16(f + off + 6u, 0x0001u);
    memset(f + off + IDEMIP_ICMP_ECHO_HDR_LEN, 0x77, data_len);
    size_t len = IDEMIP_ICMP_ECHO_HDR_LEN + data_len;
    idemip_wr16(f + off + 2u, idemip_cksum(f + off, len));
    return off + len;
}

// One RFC 792 error message: the eight-octet header the five error types share, then the "Internet
// Header + 64 bits of Original Data Datagram" that RFC 1122 sec 3.2.2's demux reads out of it.
// @p gateway is the Redirect's own field, and is the unused word for the other four.
static size_t build_icmp_error(uint8_t *f, size_t off, uint8_t type, uint32_t gateway)
{
    memset(f + off, 0, IDEMIP_ICMP_ERR_HDR_LEN);
    f[off + IDEMIP_ICMP_OFF_TYPE] = type;
    idemip_wr32(f + off + 4u, gateway);
    const size_t quoted =
        build_ip4(f, off + IDEMIP_ICMP_OFF_QUOTE, IDEMIP_IP4_PROTO_UDP, LOCAL_IP4, REMOTE_IP4, 8u, 0u);
    memset(f + quoted, 0, 8u);
    const size_t len = (quoted + 8u) - off;
    idemip_wr16(f + off + 2u, idemip_cksum(f + off, len));
    return off + len;
}

static size_t build_ip4_echo(uint8_t *f, size_t off, uint32_t src, uint32_t dst)
{
    size_t ip = off;
    off = build_ip4(f, off, IDEMIP_IP4_PROTO_ICMP, src, dst, IDEMIP_ICMP_ECHO_HDR_LEN + 4u, 0u);
    size_t end = build_icmp_echo(f, off, 4u);
    idemip_ip4_set_total_len(f + ip, (uint16_t)(end - ip));
    idemip_ip4_recksum(f + ip);
    return end;
}

static size_t build_arp(uint8_t *f, size_t off, uint16_t op, uint32_t tpa)
{
    if (op == IDEMIP_ARP_OP_REQUEST)
    {
        idemip_arp_build_request(f + off, g_remote_mac, REMOTE_IP4, tpa);
    }
    else
    {
        idemip_arp_build_reply(f + off, g_remote_mac, REMOTE_IP4, g_local_mac, tpa);
    }
    return off + IDEMIP_ARP_LEN;
}

#if IDEMIP_ENABLE_IPV6
static size_t build_ip6(uint8_t *f, size_t off, uint8_t next_hdr, const uint8_t *src, const uint8_t *dst,
                        size_t payload_len)
{
    IdemIpIp6BuildArgs a;
    memset(&a, 0, sizeof a);
    a.src = src;
    a.dst = dst;
    a.payload_len = (uint16_t)payload_len;
    a.next_hdr = next_hdr;
    a.hop_limit = 64u;
    idemip_ip6_build(f + off, &a);
    return off + IDEMIP_IPV6_HDR_LEN;
}
#endif

// The random word every input in this file is handed. Deliberately unequal to the now_ms below it,
// and deliberately large in its high half, since that is the half a draw scales by: a path that
// reached for the clock instead would come out at the bottom of its range rather than here.
#define DISPATCH_TEST_RAND 0x5A5A0000u
static uint32_t g_rand = DISPATCH_TEST_RAND;

static void input(uint8_t *w, size_t len, uint8_t netif, uint16_t desc)
{
    DispatchIo *io = IDEMIP_DISPATCH_IO(w);
    io->input_args.frame = g_frame;
    io->input_args.len = len;
    io->input_args.out = g_out;
    io->input_args.out_cap = sizeof g_out;
    io->input_args.now_ms = 1000u;
    io->input_args.rand = g_rand;
    io->input_args.desc = desc;
    io->input_args.netif = netif;
    Dispatch.input(w);
}

void setUp(void)
{
    g_rand = DISPATCH_TEST_RAND;
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_frame, 0, sizeof g_frame);
    memset(g_out, 0, sizeof g_out);
    memset(phy_mem, 0, sizeof phy_mem);
    wire_units();
    Dispatch.clear(work_a);
    Dispatch.clear(work_b);
    bind_all(work_a);
    if_untagged(work_a, 0u);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Dispatch.clear(NULL);
    Dispatch.bind(NULL);
    Dispatch.if_bind(NULL);
    Dispatch.if_get(NULL);
    Dispatch.input(NULL);
#if IDEMIP_ENABLE_TCP
    Dispatch.tcp_deliver(NULL);
    Dispatch.tcp_ack(NULL);
#endif
    TEST_PASS();
}

// A zeroed borrow is not this module's until clear has marked it, so every entry refuses one.
void test_every_entry_refuses_an_uncleared_borrow(void)
{
    static _Alignas(8) uint8_t raw[IDEMIP_DISPATCH_BORROW];
    memset(raw, 0, sizeof raw);
    Dispatch.bind(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DISPATCH_IO(raw)->status);
    Dispatch.if_bind(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DISPATCH_IO(raw)->status);
    Dispatch.if_get(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DISPATCH_IO(raw)->status);
    Dispatch.input(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DISPATCH_IO(raw)->status);
#if IDEMIP_ENABLE_TCP
    Dispatch.tcp_deliver(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DISPATCH_IO(raw)->status);
    Dispatch.tcp_ack(raw);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DISPATCH_IO(raw)->status);
#endif
}

// The borrow IS the instance, and the operand block is in it, so two paths share no byte at all.
void test_two_borrows_share_no_byte(void)
{
    bind_all(work_b);
    if_tagged(work_a, 0u, VID_OURS);
    if_tagged(work_b, 0u, VID_THEIRS);

    IDEMIP_DISPATCH_IO(work_a)->if_args.index = 0u;
    Dispatch.if_get(work_a);
    TEST_ASSERT_EQUAL_UINT16(VID_OURS, IDEMIP_DISPATCH_IO(work_a)->vid);
    IDEMIP_DISPATCH_IO(work_b)->if_args.index = 0u;
    Dispatch.if_get(work_b);
    TEST_ASSERT_EQUAL_UINT16(VID_THEIRS, IDEMIP_DISPATCH_IO(work_b)->vid);

    // And a's row is still a's after b's call.
    IDEMIP_DISPATCH_IO(work_a)->if_args.index = 0u;
    Dispatch.if_get(work_a);
    TEST_ASSERT_EQUAL_UINT16(VID_OURS, IDEMIP_DISPATCH_IO(work_a)->vid);
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    bind_all(work_b);
    if_tagged(work_a, 0u, VID_OURS);
    if_tagged(work_b, 0u, VID_THEIRS);

    IDEMIP_DISPATCH_IO(work_a)->if_args.index = 0u;
    Dispatch.if_get(work_a);
    uint16_t first = IDEMIP_DISPATCH_IO(work_a)->vid;
    IDEMIP_DISPATCH_IO(work_b)->if_args.index = 0u;
    Dispatch.if_get(work_b);
    IDEMIP_DISPATCH_IO(work_a)->if_args.index = 0u;
    Dispatch.if_get(work_a);
    TEST_ASSERT_EQUAL_UINT16(first, IDEMIP_DISPATCH_IO(work_a)->vid);
}

// The map is published, so a reader can see every region without opening the .c. The regions are in
// order, none overlaps the one before it, and the last ends inside the borrow.
void test_the_published_offsets_are_ordered_and_fit(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_DISPATCH_OFF_IO);
    TEST_ASSERT_TRUE(IDEMIP_DISPATCH_OFF_CTX >= sizeof(DispatchIo));
    TEST_ASSERT_TRUE(IDEMIP_DISPATCH_OFF_IF >= IDEMIP_DISPATCH_OFF_CTX);
    TEST_ASSERT_TRUE(IDEMIP_DISPATCH_OFF_PCB > IDEMIP_DISPATCH_OFF_IF);
    TEST_ASSERT_TRUE(IDEMIP_DISPATCH_OFF_END > IDEMIP_DISPATCH_OFF_PCB);
    TEST_ASSERT_TRUE(IDEMIP_DISPATCH_OFF_END <= IDEMIP_DISPATCH_BORROW);
}

void test_input_refuses_a_null_frame_and_a_bad_interface(void)
{
    DispatchIo *io = IDEMIP_DISPATCH_IO(work_a);
    io->input_args.frame = NULL;
    io->input_args.len = 64u;
    io->input_args.netif = 0u;
    Dispatch.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    io->input_args.frame = g_frame;
    io->input_args.len = 0u;
    Dispatch.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);

    io->input_args.len = 64u;
    io->input_args.netif = (uint8_t)IDEMIP_NETIF_COUNT;
    Dispatch.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// --- the link layer, and what each drop counts -------------------------------

// RFC 1213 sec 6.4 ifInOctets is "the total number of octets received on the interface", whatever
// becomes of the frame after that.
void test_every_arriving_frame_counts_its_octets(void)
{
    size_t off = build_eth(g_frame, g_local_mac, 0x9999u);
    input(work_a, off + 46u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)(off + 46u), if_ctr(0u, IDEMIP_STAT_IF_IN_OCTETS));
}

// Shorter than the Ethernet II header it claims: ifInErrors, "contained errors preventing them from
// being deliverable to a higher-layer protocol".
void test_a_short_frame_is_an_error_not_a_discard(void)
{
    input(work_a, 8u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_ERRORS));
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_DISCARDS));
}

// A type code nothing here handles: ifInUnknownProtos, "discarded because of an unknown or
// unsupported protocol". The frame is intact, so it is neither an error nor a discard.
void test_an_unhandled_ethertype_counts_unknown_protos(void)
{
    size_t off = build_eth(g_frame, g_local_mac, 0x88CCu);
    input(work_a, off + 46u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_ETHERTYPE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS));
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_ERRORS));
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_DISCARDS));
}

// --- the VLAN policy, which lives here and not in the parser -----------------

// An untagged interface accepts every frame.
void test_an_untagged_interface_accepts_an_untagged_frame(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_FALSE(IDEMIP_DISPATCH_IO(work_a)->tagged);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_DISCARDS));
}

// An untagged interface accepts a tagged frame too, and reads the payload behind the tag.
void test_an_untagged_interface_accepts_a_tagged_frame(void)
{
    size_t off = build_eth_tagged(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4, VID_THEIRS);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE(IDEMIP_DISPATCH_IO(work_a)->tagged);
    TEST_ASSERT_EQUAL_UINT16(VID_THEIRS, IDEMIP_DISPATCH_IO(work_a)->vid);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_DISCARDS));
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_VLAN_OFF_PAYLOAD, IDEMIP_DISPATCH_IO(work_a)->ip_off);
}

// A tagged interface accepts its own VLAN ID.
void test_a_tagged_interface_accepts_its_own_vid(void)
{
    if_tagged(work_a, 0u, VID_OURS);
    size_t off = build_eth_tagged(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4, VID_OURS);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_DISCARDS));
}

// A tagged interface discards the rest. RFC 1213 ifInDiscards: "chosen to be discarded even though no
// errors had been detected". The frame is intact, so this is not ifInErrors.
void test_a_tagged_interface_discards_another_vid(void)
{
    if_tagged(work_a, 0u, VID_OURS);
    size_t off = build_eth_tagged(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4, VID_THEIRS);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_VLAN_POLICY, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_DISCARDS));
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_ERRORS));
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS));
}

// The count alone cannot be acted on, so the offending VLAN ID is recorded beside it. It rises and
// falls rather than accumulating, so it is a Gauge (RFC 1155 sec 3.2.3.4): assigned, never bumped.
void test_a_policy_drop_records_the_offending_vid(void)
{
    if_tagged(work_a, 0u, VID_OURS);
    IDEMIP_DISPATCH_IO(work_a)->if_args.index = 0u;
    Dispatch.if_get(work_a);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DISPATCH_VID_NONE, IDEMIP_DISPATCH_IO(work_a)->last_vid);

    size_t off = build_eth_tagged(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4, VID_THEIRS);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    IDEMIP_DISPATCH_IO(work_a)->if_args.index = 0u;
    Dispatch.if_get(work_a);
    TEST_ASSERT_EQUAL_UINT16(VID_THEIRS, IDEMIP_DISPATCH_IO(work_a)->last_vid);

    // A second drop on another VLAN assigns, and does not accumulate.
    off = build_eth_tagged(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4, 300u);
    end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    IDEMIP_DISPATCH_IO(work_a)->if_args.index = 0u;
    Dispatch.if_get(work_a);
    TEST_ASSERT_EQUAL_UINT16(300u, IDEMIP_DISPATCH_IO(work_a)->last_vid);
}

// THE SENTINEL IS 4095 AND NOT 0. RFC 6325 sec 4.1.1: "VLAN ID zero is the null VLAN identifier and
// indicates that no VLAN is specified", which is a priority-tagged frame and a real value on the
// wire. A drop of one records 0, which must read as a drop and not as "nothing discarded".
void test_a_discarded_priority_tagged_frame_records_zero_not_the_sentinel(void)
{
    if_tagged(work_a, 0u, VID_OURS);
    size_t off = build_eth_tagged(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4, IDEMIP_VLAN_VID_NULL);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_VLAN_POLICY, IDEMIP_DISPATCH_IO(work_a)->drop);
    IDEMIP_DISPATCH_IO(work_a)->if_args.index = 0u;
    Dispatch.if_get(work_a);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_VLAN_VID_NULL, IDEMIP_DISPATCH_IO(work_a)->last_vid);
    TEST_ASSERT_NOT_EQUAL_UINT16(IDEMIP_DISPATCH_VID_NONE, IDEMIP_DISPATCH_IO(work_a)->last_vid);
}

// RFC 6325 sec 4.1.1: "The VLAN ID 0xFFF MUST NOT be used", and a receiver "MUST discard any frame"
// carrying it. A value the standard forbids on the wire makes the frame malformed, so it is
// ifInErrors and not the deliberate ifInDiscards.
void test_the_reserved_vid_is_an_error_not_a_policy_discard(void)
{
    if_tagged(work_a, 0u, VID_OURS);
    size_t off = build_eth_tagged_raw(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4,
                                      (uint16_t)IDEMIP_VLAN_VID_RESERVED);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_VLAN_RESERVED, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_ERRORS));
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_DISCARDS));
}

// The reserved VLAN ID is refused on an untagged interface too, the frame being malformed however
// this interface is configured.
void test_the_reserved_vid_is_refused_on_an_untagged_interface(void)
{
    size_t off = build_eth_tagged_raw(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4,
                                      (uint16_t)IDEMIP_VLAN_VID_RESERVED);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_VLAN_RESERVED, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_ERRORS));
}

// RFC 6325 sec 4.1.1 runs the usable range 0x001 through 0xFFE, so a membership outside it names no
// VLAN and cannot be configured.
void test_if_bind_refuses_a_membership_outside_the_usable_range(void)
{
    DispatchIo *io = IDEMIP_DISPATCH_IO(work_a);
    io->if_args.index = 0u;
    io->if_args.tagged = IDEMIP_TRUE;
    io->if_args.vid = IDEMIP_VLAN_VID_NULL;
    Dispatch.if_bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
    io->if_args.vid = (uint16_t)IDEMIP_VLAN_VID_RESERVED;
    Dispatch.if_bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
    io->if_args.vid = (uint16_t)IDEMIP_VLAN_VID_LAST;
    Dispatch.if_bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
}

void test_if_bind_and_if_get_refuse_an_index_past_the_table(void)
{
    DispatchIo *io = IDEMIP_DISPATCH_IO(work_a);
    io->if_args.index = (uint8_t)IDEMIP_NETIF_COUNT;
    io->if_args.tagged = IDEMIP_FALSE;
    Dispatch.if_bind(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
    Dispatch.if_get(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, io->status);
}

// clear leaves every row saying nothing has been discarded, which is 4095 and never 0.
void test_clear_sets_every_row_to_the_sentinel(void)
{
    for (uint8_t i = 0u; i < (uint8_t)IDEMIP_NETIF_COUNT; i++)
    {
        IDEMIP_DISPATCH_IO(work_a)->if_args.index = i;
        Dispatch.if_get(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DISPATCH_IO(work_a)->status);
        TEST_ASSERT_EQUAL_UINT16(IDEMIP_DISPATCH_VID_NONE, IDEMIP_DISPATCH_IO(work_a)->last_vid);
    }
}

// --- IPv4, the five steps of RFC 1122 sec 3.1 --------------------------------

// (1) verifies that the datagram is correctly formatted.
void test_a_bad_ipv4_checksum_is_a_header_error(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    idemip_ip4_set_cksum(g_frame + ip, (uint16_t)(idemip_ip4_cksum(g_frame + ip) ^ 0xFFFFu));
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP4_IN_HDR_ERRORS));
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_ERRORS));
}

// (2) verifies that it is destined to the local host. One that is not leaves the input path: RFC 1122
// sec 3.1 puts the first-hop choice on the outgoing side, so this reports and routes nothing.
void test_a_datagram_for_somewhere_else_is_reported_for_forwarding(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, OTHER_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_FORWARD) != 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
}

// RFC 1122 sec 3.2.1.3 case (c) "{ -1, -1 }", the limited broadcast, is this host's.
void test_the_limited_broadcast_is_local(void)
{
    size_t off = build_eth(g_frame, g_bcast_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, 0xFFFFFFFFu);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_FORWARD) == 0u);
}

// RFC 1122 sec 3.2.1.3 case (e) "{ <Network-number>, <Subnet-number>, -1 }", the directed broadcast
// of the receiving interface's own subnet, is this host's too.
void test_the_directed_broadcast_of_our_subnet_is_local(void)
{
    size_t off = build_eth(g_frame, g_bcast_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4 | ~NETMASK4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_FORWARD) == 0u);

    // The rule that decision rests on, in the unit that owns it. Nothing else in dispatch tells a
    // directed broadcast from a host address in the same subnet.
    Ip4AddrIo *ia = IDEMIP_IP4_ADDR_IO(ip4_addr_mem);
    ia->match_args.addr = LOCAL_IP4 | ~NETMASK4;
    ia->match_args.net = LOCAL_IP4;
    ia->match_args.mask = NETMASK4;
    Ip4Addr.match(ip4_addr_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ia->status);
    TEST_ASSERT_TRUE(ia->on_subnet);
    TEST_ASSERT_TRUE_MESSAGE(ia->is_broadcast, "the all-ones host part is the subnet's directed broadcast");

    ia->match_args.addr = REMOTE_IP4;
    ia->match_args.net = LOCAL_IP4;
    ia->match_args.mask = NETMASK4;
    Ip4Addr.match(ip4_addr_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ia->status);
    TEST_ASSERT_TRUE(ia->on_subnet);
    TEST_ASSERT_FALSE_MESSAGE(ia->is_broadcast, "a host address on the subnet is not its broadcast");
}

// A class D group this node never joined is not this host's, and RFC 1213 ipInAddrErrors counts it.
void test_a_group_we_never_joined_is_an_address_error(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, 0xE0000105u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_ADDRESS, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP4_IN_ADDR_ERRORS));
}

#if IDEMIP_ENABLE_UDP

// (5) passes the encapsulated message to the appropriate transport-layer protocol module.
void test_a_bound_udp_port_takes_the_datagram(void)
{
    uint16_t pcb = bind_udp4(4001u);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN + 4u, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 4u);
    seal_udp4(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_UDP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_EQUAL_UINT16(pcb, IDEMIP_DISPATCH_IO(work_a)->pcb);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_UDP_IN_DATAGRAMS));
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP4_IN_DELIVERS));
    // RFC 1213 counts a delivery, not an arrival, and this one went to a unicast link address.
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_UCAST_PKTS));
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_NUCAST_PKTS));
}

// RFC 1122 sec 3.2.1.3 case (g): "{ 127, <any> } Internal host loopback address. Addresses of this
// form MUST NOT appear outside a host." A 127/8 destination that arrived on a wire is discarded for
// that reason, and the interface no wire reaches is the exception - there the address is this host's
// and loopif is what owns it. The two outcomes are told apart by where the datagram stops: an address
// error at the IP layer, or the transport, which then has no binding for port 4001.
void test_a_loopback_interface_carries_the_address_loopif_owns(void)
{
    NetifIo *ni = IDEMIP_NETIF_IO(netif_mem);
    ni->if_args.index = 0u;
    ni->if_args.set = (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK;
    ni->if_args.clear = 0u;
    Netif.set_flags(netif_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ni->status);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, 0x7F000001u, IDEMIP_UDP_HDR_LEN, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp4(g_frame, off, REMOTE_IP4, 0x7F000001u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "the address loopif owns was not this host's on the loopback interface");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_IP4_IN_ADDR_ERRORS),
                                     "a datagram that reached the transport was counted as an address error");
}

// RFC 1122 sec 4.1.3.1: with no binding, "UDP SHOULD send an ICMP Port Unreachable message", and
// udpNoPorts is what counts it.
void test_an_unbound_udp_port_counts_no_ports(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp4(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_UDP_NO_PORTS));
}

// RFC 1122 sec 3.2.1.3: "A host MUST silently discard an incoming datagram containing an IP source
// address that is invalid by the rules of this section", restated for this transport by sec 4.1.3.6,
// "A UDP datagram received with an invalid IP source address (e.g., a broadcast or multicast
// address) must be discarded by UDP or by the IP layer". Case (c) bars the limited broadcast, cases
// (d), (e) and (f) bar every directed broadcast, case (g) keeps 127/8 off the wire, and the
// section's sending rule bars multicast. Each is fed to a bound port that would otherwise take it.
void test_a_datagram_whose_source_address_is_barred_is_discarded(void)
{
    static const uint32_t barred[] = {
        0xFFFFFFFFu, // case (c), the limited broadcast
        0xE0000001u, // 224.0.0.1, "not a broadcast or multicast address"
        0x7F000001u, // case (g), 127.0.0.1 arriving on a wire
        0xC00002FFu, // case (e), 192.0.2.255, this interface's own directed broadcast
    };
    (void)bind_udp4(4001u);
    for (size_t i = 0u; i < (sizeof barred / sizeof barred[0]); i++)
    {
        size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
        off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, barred[i], LOCAL_IP4, IDEMIP_UDP_HDR_LEN + 4u, 0u);
        size_t end = build_udp(g_frame, off, 4000u, 4001u, 4u);
        seal_udp4(g_frame, off, barred[i], LOCAL_IP4);
        input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_IP_SOURCE, IDEMIP_DISPATCH_IO(work_a)->drop,
                                      "a source address RFC 1122 sec 3.2.1.3 bars was accepted");
        TEST_ASSERT_FALSE_MESSAGE(IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER,
                                  "a datagram with a barred source address was delivered");
    }
}

// Cases (a) and (b) keep { 0, 0 } and { 0, <Host-number> } valid as a source, "as part of an
// initialization procedure by which the host learns its own IP address". That is what a DHCP
// client's first datagram carries, so barring it would break the exchange that gives the host the
// address every other rule here is written against.
void test_the_unspecified_source_an_address_request_carries_still_arrives(void)
{
    uint16_t pcb = bind_udp4(68u);
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, 0u, LOCAL_IP4, IDEMIP_UDP_HDR_LEN + 4u, 0u);
    size_t end = build_udp(g_frame, off, 67u, 68u, 4u);
    seal_udp4(g_frame, off, 0u, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "the source RFC 1122 sec 3.2.1.3 (a) permits was dropped");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_UINT16(pcb, IDEMIP_DISPATCH_IO(work_a)->pcb);
}

// --- IGMP, RFC 2236 ----------------------------------------------------------
// The IGMP borrow was bound here from the start and no case ever fed it a message, which is how a
// missing MUST survived: an unexercised path cannot fail.

#if IDEMIP_ENABLE_IPV4

// One RFC 2236 sec 2 message at off, checksum sealed over all eight octets (sec 2.3, no
// pseudo-header).
static size_t build_igmp(uint8_t *f, size_t off, uint8_t type, uint8_t max_resp, uint32_t group)
{
    uint8_t *m = f + off;
    m[IDEMIP_IGMP_OFF_TYPE] = type;
    m[IDEMIP_IGMP_OFF_MAX_RESP] = max_resp;
    idemip_wr16(m + IDEMIP_IGMP_OFF_CKSUM, 0u);
    idemip_wr32(m + IDEMIP_IGMP_OFF_GROUP, group);
    idemip_wr16(m + IDEMIP_IGMP_OFF_CKSUM, idemip_cksum(m, IDEMIP_IGMP_MSG_LEN));
    return off + IDEMIP_IGMP_MSG_LEN;
}

static void join_group(uint32_t group)
{
    IgmpIo *ig = IDEMIP_IGMP_IO(igmp_mem);
    ig->group_args.group = group;
    ig->group_args.rand = 0x1234u;
    ig->group_args.now_ms = 0u;
    ig->group_args.netif = 0u;
    Igmp.join(igmp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ig->status);
}

void test_an_igmp_query_with_a_good_checksum_is_processed(void)
{
    join_group(0xE0000102u);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IGMP_IP_PROTO, REMOTE_IP4, 0xE0000102u, IDEMIP_IGMP_MSG_LEN, 0u);
    size_t end = build_igmp(g_frame, off, (uint8_t)IDEMIP_IGMP_TYPE_QUERY, 100u, 0xE0000102u);

    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
}


// The report delay a Query arms, and where it comes from. RFC 2236 sec 3: "When a host receives a
// General Query, it sets delay timers for each group ... of which it is a member on the interface
// from which it received the query. ... Timers are set to a different random value, using the
// highest clock granularity available on the host, selected from the range (0, Max Response Time]",
// and the sentence before it says what the randomness is for: "In order to avoid an 'implosion' of
// concurrent reports". A delay every member of the group draws independently is what lets the first
// Report suppress the rest, which is the whole of sec 3's suppression rule.
//
// The word that value comes out of is DispatchInputArgs::rand, and this path took now_ms instead.
// A monotonic count is not a random value: it is the same on every host that has been up as long,
// it never decreases, and igmp_draw scales by its HIGH half - the half that moves once every 65.536
// seconds - so a ten-second Max Response Time came out as 1 ms for the first seven minutes of
// uptime, 202 ms after a day, and reached ten seconds only after 49.7 days of it.
static uint32_t igmp_deadline(uint32_t group)
{
    IgmpIo *ig = IDEMIP_IGMP_IO(igmp_mem);
    ig->group_args.group = group;
    ig->group_args.netif = 0u;
    Igmp.find(igmp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ig->status);
    return ig->deadline_ms;
}

// Another host's Report puts the membership in sec 6's Idle Member state, so the next Query arms a
// fresh timer rather than deciding whether to shorten a running one.
static void quiet_group(uint32_t group)
{
    IgmpIo *ig = IDEMIP_IGMP_IO(igmp_mem);
    ig->report_args.group = group;
    ig->report_args.netif = 0u;
    Igmp.report_in(igmp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ig->status);
}

void test_the_igmp_report_delay_is_drawn_from_the_random_word_and_not_the_clock(void)
{
    const uint32_t group = 0xE0000102u;
    const uint32_t max_resp_ms = 100u * IDEMIP_IGMP_MAX_RESP_UNIT_MS; // sec 2.2, in units of 1/10 s

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IGMP_IP_PROTO, REMOTE_IP4, group, IDEMIP_IGMP_MSG_LEN, 0u);
    const size_t end = build_igmp(g_frame, off, (uint8_t)IDEMIP_IGMP_TYPE_QUERY, 100u, group);

    join_group(group);

    // Two Queries, one clock, two words. input() holds now_ms at 1000 for every case in this file,
    // so anything the clock decided would be equal across the pair.
    quiet_group(group);
    g_rand = 0x20000000u;
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    const uint32_t low = igmp_deadline(group);

    quiet_group(group);
    g_rand = 0xC0000000u;
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    const uint32_t high = igmp_deadline(group);

    TEST_ASSERT_TRUE_MESSAGE(low != high,
                             "one clock and two random words drew the same delay: the draw is not "
                             "reading the word");

    // Both inside sec 3's range, and the second past its middle. The clock the caller supplies is
    // 1000 ms, whose high half is zero, so a path drawing from it lands one millisecond out however
    // large the Max Response Time is.
    TEST_ASSERT_TRUE_MESSAGE(low > 1000u && low <= 1000u + max_resp_ms, "outside (0, Max Response Time]");
    TEST_ASSERT_TRUE_MESSAGE(high > 1000u && high <= 1000u + max_resp_ms, "outside (0, Max Response Time]");
    TEST_ASSERT_TRUE_MESSAGE(high - 1000u > (max_resp_ms >> 1),
                             "a word in the top quarter drew a delay in the bottom half: the range is "
                             "not being spread, and every member answers at once");
}

// RFC 2236 sec 2.5: "As long as the Type is one that is recognized, an IGMPv2 implementation MUST
// ignore anything past the first 8 octets while processing the packet. However, the IGMP checksum is
// always computed over the whole IP payload, not just over the first 8 octets", and sec 2.3: "The
// checksum is the 16-bit one's complement of the one's complement sum of the whole IGMP message (the
// entire IP payload)."
void test_an_igmp_message_longer_than_eight_octets_sums_over_the_whole_payload(void)
{
    join_group(0xE0000102u);

    // Twelve octets, the extra four sec 2.5 has a recognized Type ignore, with the sum over all of
    // them the way sec 2.3 requires.
    const size_t msg_len = IDEMIP_IGMP_MSG_LEN + 4u;
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IGMP_IP_PROTO, REMOTE_IP4, 0xE0000102u, msg_len, 0u);
    uint8_t *m = g_frame + off;
    m[IDEMIP_IGMP_OFF_TYPE] = (uint8_t)IDEMIP_IGMP_TYPE_QUERY;
    m[IDEMIP_IGMP_OFF_MAX_RESP] = 100u;
    idemip_wr16(m + IDEMIP_IGMP_OFF_CKSUM, 0u);
    idemip_wr32(m + IDEMIP_IGMP_OFF_GROUP, 0xE0000102u);
    memset(m + IDEMIP_IGMP_MSG_LEN, 0xA5, 4u);
    idemip_wr16(m + IDEMIP_IGMP_OFF_CKSUM, idemip_cksum(m, msg_len));

    input(work_a, off + msg_len, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "the sum is over the whole IP payload, not the first 8 octets");

    // The same message with the sum over the first 8 octets alone does not hold.
    idemip_wr16(m + IDEMIP_IGMP_OFF_CKSUM, 0u);
    idemip_wr16(m + IDEMIP_IGMP_OFF_CKSUM, idemip_cksum(m, IDEMIP_IGMP_MSG_LEN));
    input(work_a, off + msg_len, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_DISPATCH_IO(work_a)->drop);
}

// RFC 2236 sec 2.1: "Unrecognized message types should be silently ignored." The IP Protocol field
// was 2, which this build supports, so RFC 1213 ipInUnknownProtos, "discarded because of an unknown
// or unsupported protocol", names a different event and must not move.
void test_an_unrecognized_igmp_type_is_silently_ignored(void)
{
    join_group(0xE0000102u);
    const uint32_t unknown = ctr(IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS);

    // IGMPv2 Leave Group, which this build does not act on, and IGMPv3 Membership Report.
    const uint8_t types[2] = {0x17u, 0x22u};
    for (int i = 0; i < 2; i++)
    {
        size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
        off = build_ip4(g_frame, off, IDEMIP_IGMP_IP_PROTO, REMOTE_IP4, 0xE0000102u, IDEMIP_IGMP_MSG_LEN, 0u);
        size_t end = build_igmp(g_frame, off, types[i], 0u, 0xE0000102u);
        input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop,
                                      "silently ignored means no drop reason");
        TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u,
                                 "an unrecognized Type reaches no module");
    }
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(unknown, ctr(IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS),
                                     "IP protocol 2 is supported, so ipInUnknownProtos must not move");
}

// RFC 1122 sec 2.3.3, of a host on a 10Mbps Ethernet: "SHOULD be able to receive RFC-1042 packets,
// intermixed with RFC-894 packets", which its sec 2.5 table lists as "Receive RFC-1042
// encapsulation". RFC 1042 puts the DSAP and SSAP at 170, the Control at 3, a zero Organization Code,
// and the EtherType behind them.
void test_an_rfc_1042_encapsulated_datagram_is_received(void)
{
    UdpPcbIo *up = IDEMIP_UDP_PCB_IO(udp_mem);
    up->open_args.ip_version = 4u;
    up->open_args.lite = IDEMIP_FALSE;
    UdpPcb.open(udp_mem);
    uint8_t local[IDEMIP_UDP_PCB_ADDR_BYTES];
    memset(local, 0, sizeof local);
    idemip_wr32(local, LOCAL_IP4);
    up->bind_args.index = up->index;
    up->bind_args.ip = local;
    up->bind_args.port = 4001u;
    up->bind_args.zone = 0u;
    up->bind_args.netif = 0u;
    UdpPcb.bind(udp_mem);

    // The two octets at offset 12 hold an 802.3 Length rather than a type code, so the LLC and SNAP
    // headers follow and the EtherType is read from behind them.
    idemip_eth_build(g_frame, g_local_mac, g_remote_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    uint8_t *llc = g_frame + IDEMIP_ETH_OFF_PAYLOAD;
    llc[IDEMIP_LLC_OFF_DSAP] = (uint8_t)IDEMIP_LLC_SAP_SNAP;
    llc[IDEMIP_LLC_OFF_SSAP] = (uint8_t)IDEMIP_LLC_SAP_SNAP;
    llc[IDEMIP_LLC_OFF_CONTROL] = (uint8_t)IDEMIP_LLC_CONTROL_UI;
    llc[IDEMIP_LLC_OFF_ORG] = 0u;
    llc[IDEMIP_LLC_OFF_ORG + 1u] = 0u;
    llc[IDEMIP_LLC_OFF_ORG + 2u] = 0u;
    idemip_wr16(llc + IDEMIP_LLC_OFF_TYPE, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t off = IDEMIP_ETH_OFF_PAYLOAD + IDEMIP_LLC_SNAP_LEN;
    size_t ip = off;
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp4(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    // The Length field the 802.3 frame carries, which is what separates it from an RFC 894 frame.
    idemip_wr16(g_frame + IDEMIP_ETH_OFF_TYPE, (uint16_t)(end - IDEMIP_ETH_OFF_PAYLOAD));
    (void)ip;

    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "an RFC 1042 frame was dropped as an unknown EtherType");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);

    // A Length in the type position with no SNAP header behind it is not ours.
    idemip_eth_build(g_frame, g_local_mac, g_remote_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    idemip_wr16(g_frame + IDEMIP_ETH_OFF_TYPE, 0x002Eu);
    memset(g_frame + IDEMIP_ETH_OFF_PAYLOAD, 0x11, 0x2Eu);
    input(work_a, IDEMIP_ETH_OFF_PAYLOAD + 0x2Eu, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_ETHERTYPE, IDEMIP_DISPATCH_IO(work_a)->drop);
}

// RFC 2236 sec 2.3: "When receiving packets, the checksum MUST be verified before processing a
// packet." sec 6 restates it: a Query is valid only if it is "at least 8 octets long, and have a
// correct IGMP checksum". Without this an off-path forgery moved a group's timer.
void test_an_igmp_query_with_a_bad_checksum_is_discarded(void)
{
    join_group(0xE0000102u);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IGMP_IP_PROTO, REMOTE_IP4, 0xE0000102u, IDEMIP_IGMP_MSG_LEN, 0u);
    size_t end = build_igmp(g_frame, off, (uint8_t)IDEMIP_IGMP_TYPE_QUERY, 100u, 0xE0000102u);
    idemip_wr16(g_frame + off + IDEMIP_IGMP_OFF_CKSUM,
                (uint16_t)(idemip_rd16(g_frame + off + IDEMIP_IGMP_OFF_CKSUM) ^ 0x5A5Au));

    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_DISPATCH_IO(work_a)->drop);
}

// RFC 1112 sec 7.2: "every level 2 host must join the 'all-hosts' group (address 224.0.0.1) on each
// network interface at initialization time and must remain a member for as long as the host is
// active", and Appendix I: "The host starts in Idle Member state for that group on every interface".
// RFC 2236 sec 9 addresses a General Query to it, so a node that does not recognize it as its own
// receives no General Query at all, whatever else the IGMP path checks.
void test_the_all_hosts_group_is_this_node_s_whether_or_not_it_joined_one(void)
{
    join_group(0xE0000102u);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IGMP_IP_PROTO, REMOTE_IP4, IDEMIP_IGMP_ALL_SYSTEMS, IDEMIP_IGMP_MSG_LEN,
                    0u);
    size_t end = build_igmp(g_frame, off, (uint8_t)IDEMIP_IGMP_TYPE_QUERY, 100u, 0u); // group zero: General

    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "a General Query is addressed to the group sec 7.2 makes every host a member of");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_GROUP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
}

// A Report suppresses this node's own pending Report (sec 3), so a forged one is worth the same
// check as a forged Query.
void test_an_igmp_report_with_a_bad_checksum_is_discarded(void)
{
    join_group(0xE0000102u);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IGMP_IP_PROTO, REMOTE_IP4, 0xE0000102u, IDEMIP_IGMP_MSG_LEN, 0u);
    size_t end = build_igmp(g_frame, off, (uint8_t)IDEMIP_IGMP_TYPE_REPORT_V2, 0u, 0xE0000102u);
    g_frame[off + IDEMIP_IGMP_OFF_CKSUM] ^= 0xFFu;

    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_DISPATCH_IO(work_a)->drop);
}

#endif // IDEMIP_ENABLE_IPV4

// RFC 1122 sec 4.1.3.4: "If a UDP datagram is received with a checksum that is non-zero and
// invalid, UDP MUST silently discard the datagram." Before this check existed dispatch read the
// ports and delivered, so every datagram on the link reached a bound service whatever its sum said.
void test_a_bad_udp_checksum_is_discarded(void)
{
    uint16_t pcb = bind_udp4(4001u);
    (void)pcb;

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN + 4u, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 4u);
    seal_udp4(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    // One bit of the sealed sum, so the field is non-zero and wrong.
    idemip_wr16(g_frame + off + IDEMIP_UDP_OFF_CKSUM,
                (uint16_t)(idemip_udp_cksum(g_frame + off) ^ 0x0001u));

    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_UDP_IN_ERRORS));
}

// RFC 768 leaves the field all-zero when the sender computed none, and RFC 1122 sec 4.1.3.4 accepts
// that over IPv4. The exemption is the reason the check above tests a NON-ZERO wrong sum.
void test_a_zero_udp_checksum_is_accepted_over_ipv4(void)
{
    uint16_t pcb = bind_udp4(4001u);
    (void)pcb;

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    idemip_wr16(g_frame + off + IDEMIP_UDP_OFF_CKSUM, 0u);

    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
}

// The other end of the same field: RFC 768 gives the header eight octets, so an IP payload shorter
// than that carries no Length to read and no ports to demux on. RFC 1213 udpInErrors is "The number
// of received UDP datagrams that could not be delivered for reasons other than the lack of an
// application at the destination port", which is this, and it is an interface error as well because
// the octets arrived.
void test_a_udp_datagram_shorter_than_its_header_is_an_error(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN - 4u, 0u);
    memset(g_frame + off, 0, IDEMIP_UDP_HDR_LEN - 4u);
    input(work_a, off + (IDEMIP_UDP_HDR_LEN - 4u), 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "four octets were read as a UDP header");
    TEST_ASSERT_FALSE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_UDP_IN_ERRORS));
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_ERRORS));
}

// RFC 768's Length "including this header and the data", minimum eight. A Length past the octets
// the IP layer delivered would take the sum over bytes that are not the datagram's.
void test_a_udp_length_past_the_ip_payload_is_an_error(void)
{
    uint16_t pcb = bind_udp4(4001u);
    (void)pcb;

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    idemip_wr16(g_frame + off + IDEMIP_UDP_OFF_LEN, 4000u);

    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
}

#endif // IDEMIP_ENABLE_UDP

// A delivery to a link broadcast is non-unicast, which is the other half of the RFC 1213 pair. An
// Echo Reply carries it rather than an Echo Request: RFC 1122 sec 3.2.2.6 lets a request "destined to
// an IP broadcast or IP multicast address" be silently discarded, and IDEMIP_ICMP_ECHO_BROADCAST
// takes that option, so a request would be dropped before any delivery is counted.
void test_a_broadcast_delivery_counts_non_unicast(void)
{
    size_t off = build_eth(g_frame, g_bcast_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, 0xFFFFFFFFu, IDEMIP_ICMP_ECHO_HDR_LEN + 4u, 0u);
    size_t end = build_icmp_echo(g_frame, off, 4u);
    g_frame[off + IDEMIP_ICMP_OFF_TYPE] = IDEMIP_ICMP_ECHO_REPLY;
    idemip_wr16(g_frame + off + 2u, 0u);
    idemip_wr16(g_frame + off + 2u, idemip_cksum(g_frame + off, IDEMIP_ICMP_ECHO_HDR_LEN + 4u));
    idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
    idemip_ip4_recksum(g_frame + ip);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_NUCAST_PKTS));
    TEST_ASSERT_EQUAL_UINT32(0u, if_ctr(0u, IDEMIP_STAT_IF_IN_UCAST_PKTS));
}

// RFC 2011 icmpInMsgs: "The total number of ICMP messages which the entity received. Note that this
// counter includes all those counted by icmpInErrors." Each Type it names carries its own counter as
// well, so an Echo is both an icmpInMsgs and an icmpInEchos. Nothing under src/ bumped one of the
// fifty-three ICMP counters, while the IP, interface, TCP and UDP receive paths all counted.
void test_an_icmp_echo_counts_itself_by_message_and_by_type(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, LOCAL_IP4, IDEMIP_ICMP_ECHO_HDR_LEN + 4u, 0u);
    size_t end = build_icmp_echo(g_frame, off, 4u);
    idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
    idemip_ip4_recksum(g_frame + ip);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP4_IN_MSGS), "icmpInMsgs counted nothing");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP4_IN_ECHOS), "icmpInEchos counted nothing");
    TEST_ASSERT_EQUAL_UINT32(0u, ctr(IDEMIP_STAT_ICMP4_IN_ERRORS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP4_IN_ECHO_REPS),
                                     "an Echo was counted as an Echo Reply");
}

// RFC 2011 gives each Type its own counter, and dispatch counts the type of every message icmp_in
// accepted. The five RFC 1122 sec 3.2.2 groups as errors reach that count: sec 3.2.2.1 Destination
// Unreachable, sec 3.2.2.3 Source Quench, sec 3.2.2.2 Redirect, sec 3.2.2.4 Time Exceeded and
// sec 3.2.2.5 Parameter Problem. Each is counted once, as itself, and as an icmpInMsgs.
//
// The Redirect names REMOTE_IP4 as its gateway because sec 3.2.2.2 discards one whose gateway is not
// "on the same connected (sub-) net through which the Redirect arrived", and that address is.
void test_each_icmp_error_type_counts_itself_by_type(void)
{
    static const struct
    {
        uint8_t type;
        IdemIpStatsCounter id;
        const char *name;
    } rows[] = {
        {(uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_STAT_ICMP4_IN_DEST_UNREACHS, "icmpInDestUnreachs"},
        {(uint8_t)IDEMIP_ICMP_SOURCE_QUENCH, IDEMIP_STAT_ICMP4_IN_SRC_QUENCHS, "icmpInSrcQuenchs"},
        {(uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_STAT_ICMP4_IN_REDIRECTS, "icmpInRedirects"},
        {(uint8_t)IDEMIP_ICMP_TIME_EXCEEDED, IDEMIP_STAT_ICMP4_IN_TIME_EXCDS, "icmpInTimeExcds"},
        {(uint8_t)IDEMIP_ICMP_PARAMETER_PROBLEM, IDEMIP_STAT_ICMP4_IN_PARM_PROBS, "icmpInParmProbs"},
    };

    for (size_t r = 0; r < sizeof rows / sizeof rows[0]; r++)
    {
        // Each row starts from the state setUp built, so the counts below are this message's alone.
        wire_units();
        Dispatch.clear(work_a);
        bind_all(work_a);
        if_untagged(work_a, 0u);
        memset(g_frame, 0, sizeof g_frame);

        size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
        const size_t ip = off;
        off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, LOCAL_IP4, 0u, 0u);
        const size_t end = build_icmp_error(g_frame, off, rows[r].type, REMOTE_IP4);
        idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
        idemip_ip4_recksum(g_frame + ip);
        input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

        TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP4_IN_MSGS), rows[r].name);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(rows[r].id), rows[r].name);
    }
}

// RFC 1122 sec 3.2.2.8: "A host MAY implement Timestamp and Timestamp Reply", and this build does
// not, so icmp_in discards both on their Type before it reads a field of either. RFC 2011 still names
// icmpInTimestamps and icmpInTimestampReps and this table still carries them, so what has to be true
// is that they stay at zero and that nothing calls the message an error: sec 3.2.2's silent discard
// is what a build declining a MAY owes, and icmpInErrors is for "ICMP-specific errors (bad ICMP
// checksums, bad length, etc.)", which a well-formed Timestamp is not. The message is counted in
// icmpInMsgs, which is every ICMP message, and discarded.
void test_a_timestamp_is_discarded_without_counting_as_an_error(void)
{
    static const struct
    {
        uint8_t type;
        IdemIpStatsCounter id;
        const char *name;
    } rows[] = {
        {(uint8_t)IDEMIP_ICMP_TIMESTAMP, IDEMIP_STAT_ICMP4_IN_TIMESTAMPS, "icmpInTimestamps"},
        {(uint8_t)IDEMIP_ICMP_TIMESTAMP_REPLY, IDEMIP_STAT_ICMP4_IN_TIMESTAMP_REPS, "icmpInTimestampReps"},
    };

    for (size_t r = 0; r < sizeof rows / sizeof rows[0]; r++)
    {
        wire_units();
        Dispatch.clear(work_a);
        bind_all(work_a);
        if_untagged(work_a, 0u);
        memset(g_frame, 0, sizeof g_frame);

        // RFC 792's Timestamp: type, code and checksum, an Identifier and a Sequence Number, then the
        // three timestamps. Twenty octets and a checksum that holds, so neither length nor checksum is
        // what stops it - the Type is, which is the whole point of the two assertions below.
        size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
        const size_t ip = off;
        off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, LOCAL_IP4, 20u, 0u);
        memset(g_frame + off, 0, 20u);
        g_frame[off + IDEMIP_ICMP_OFF_TYPE] = rows[r].type;
        idemip_wr16(g_frame + off + 4u, 0x0AAAu);
        idemip_wr16(g_frame + off + 6u, 0x0001u);
        idemip_wr16(g_frame + off + 2u, idemip_cksum(g_frame + off, 20u));
        const size_t end = off + 20u;
        idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
        idemip_ip4_recksum(g_frame + ip);
        input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

        TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP4_IN_MSGS), rows[r].name);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(rows[r].id), rows[r].name);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP4_IN_ERRORS),
                                         "a Type this build declines to implement is not an ICMP error");
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_IP4_IN_DISCARDS), rows[r].name);
    }
}

// RFC 1213 sec 6.7 icmpOutMsgs is "the total number of ICMP messages which this entity attempted to
// send" and icmpOutEchoReps is "the number of ICMP Echo Reply messages sent". The Echo Reply this
// path builds is the one ICMPv4 message the library emits itself, so it is the one whose out
// counters no caller could take without re-parsing what dispatch handed back at @c out: ACT_SEND
// alone does not say whether that is an ARP reply, an echo reply or a TCP reset. Every ICMPv4 out
// counter read zero, this one included, while tcpOutRsts was counted three functions away.
void test_the_echo_reply_this_path_builds_takes_its_two_out_counters(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t end = build_ip4_echo(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_SEND) != 0u,
                             "the request built no reply, so this case counts nothing either way");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP4_OUT_MSGS), "icmpOutMsgs counted nothing");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP4_OUT_ECHO_REPS),
                                     "icmpOutEchoReps counted nothing");

    // An Echo Reply arriving is an ICMPv4 message this path does not answer, so the two stay where
    // they are: the counters attach to what dispatch built and not to what it saw.
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, LOCAL_IP4, IDEMIP_ICMP_ECHO_HDR_LEN + 4u, 0u);
    end = build_icmp_echo(g_frame, off, 4u);
    g_frame[off + IDEMIP_ICMP_OFF_TYPE] = IDEMIP_ICMP_ECHO_REPLY;
    idemip_wr16(g_frame + off + 2u, 0u);
    idemip_wr16(g_frame + off + 2u, idemip_cksum(g_frame + off, IDEMIP_ICMP_ECHO_HDR_LEN + 4u));
    idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
    idemip_ip4_recksum(g_frame + ip);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP4_OUT_MSGS),
                                     "a message that built no reply was counted as one sent");
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP4_OUT_ECHO_REPS));
}

// icmpInErrors: "The number of ICMP messages which the entity received but determined as having
// ICMP-specific errors (bad ICMP checksums, bad length, etc.)", and icmpInMsgs counts it too.
void test_an_icmp_message_with_a_bad_checksum_counts_as_an_error(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, LOCAL_IP4, IDEMIP_ICMP_ECHO_HDR_LEN + 4u, 0u);
    size_t end = build_icmp_echo(g_frame, off, 4u);
    idemip_wr16(g_frame + off + 2u, (uint16_t)(idemip_rd16(g_frame + off + 2u) ^ 0x5A5Au));
    idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
    idemip_ip4_recksum(g_frame + ip);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP4_IN_MSGS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP4_IN_ERRORS), "icmpInErrors counted nothing");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP4_IN_ECHOS),
                                     "a message with a bad checksum was counted by its Type");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "a message whose checksum does not hold was not dropped");
    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER,
                              "a message whose checksum does not hold was delivered");
}

// RFC 1122 sec 3.2.2: "If an ICMP message of unknown type is received, it MUST be silently
// discarded." icmp_in raises IDEMIP_ICMP_IN_ACT_DISCARD for that and for seven other conditions -
// a checksum that does not hold, a message shorter than its own type requires, and the types sec
// 3.2.2.7 and sec 3.2.2.8 leave unimplemented - and dispatch, its only caller, named the flag
// nowhere. Every one of them was delivered.
void test_an_icmp_message_of_unknown_type_is_discarded(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, LOCAL_IP4, IDEMIP_ICMP_ECHO_HDR_LEN + 4u, 0u);
    size_t end = build_icmp_echo(g_frame, off, 4u);
    g_frame[off + IDEMIP_ICMP_OFF_TYPE] = 200u; // no type RFC 792 assigns
    idemip_wr16(g_frame + off + 2u, 0u);
    idemip_wr16(g_frame + off + 2u, idemip_cksum(g_frame + off, IDEMIP_ICMP_ECHO_HDR_LEN + 4u));
    idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
    idemip_ip4_recksum(g_frame + ip);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER,
                              "a message of unknown type was delivered");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP4_IN_MSGS),
                                     "icmpInMsgs counts every message received, this one included");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP4_IN_ERRORS),
                                     "an unknown type is not an ICMP-specific error");
}

// RFC 2011 icmpInErrors: "The number of ICMP messages which the entity received but determined as
// having ICMP-specific errors (bad ICMP checksums, bad length, etc.)." An Echo Request that stops
// before its Sequence Number is a bad length, and its checksum holds, so nothing about the checksum
// tells it from the unknown type above, which RFC 1122 sec 3.2.2 discards SILENTLY and is no error.
void test_an_icmp_message_too_short_for_its_type_is_an_error(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    const size_t len = (size_t)IDEMIP_ICMP_ECHO_HDR_LEN - 2u; // through the Identifier, and no more
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, LOCAL_IP4, len, 0u);
    memset(g_frame + off, 0, len);
    g_frame[off + IDEMIP_ICMP_OFF_TYPE] = IDEMIP_ICMP_ECHO;
    idemip_wr16(g_frame + off + 2u, idemip_cksum(g_frame + off, len));
    idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(off + len - ip));
    idemip_ip4_recksum(g_frame + ip);
    input(work_a, off + len, 0u, IDEMIP_DISPATCH_DESC_NONE);

    const IcmpInIo *ic = IDEMIP_ICMP_IN_IO(icmp_in_mem);
    TEST_ASSERT_TRUE_MESSAGE(ic->cksum_ok, "this case is about a bad length, so its checksum must hold");
    TEST_ASSERT_TRUE((ic->act & IDEMIP_ICMP_IN_ACT_DISCARD) != 0u);
    TEST_ASSERT_FALSE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP4_IN_MSGS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP4_IN_ERRORS),
                                     "RFC 2011 names bad length an ICMP-specific error");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop);
}

// A protocol nothing here claims and no raw binding takes: ipInUnknownProtos.
void test_an_unclaimed_ip_protocol_counts_unknown_protos(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, 253u, REMOTE_IP4, LOCAL_IP4, 8u, 0u);
    input(work_a, off + 8u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_PROTO, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS));
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS));
}

#if IDEMIP_ENABLE_IPV6
// The IPv6 twin, on RFC 2465 ipv6IfStatsInUnknownProtos: "The number of locally-addressed datagrams
// received successfully but discarded because of an unknown or unsupported protocol." One site
// answers for both families, and only the IPv4 half was ever named, so nothing said which it reached.
void test_an_unclaimed_ipv6_next_header_counts_unknown_protos(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, 253u, g_remote_ip6, g_local_ip6, 8u); // RFC 3692 leaves 253 to testing
    memset(g_frame + off, 0, 8u);
    input(work_a, off + 8u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_PROTO, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_IN_UNKNOWN_PROTOS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_IP4_IN_UNKNOWN_PROTOS),
                                     "an IPv6 packet was counted against the IPv4 counter");
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS));
}
#endif


#if IDEMIP_ENABLE_IPV6
// RFC 3542 sec 3.1: "the application must set the new IPV6_CHECKSUM socket option to have the kernel
// (1) compute and store a checksum for output, and (2) verify the received checksum on input,
// discarding the packet if the checksum is in error." The same paragraph names the sum: "The checksum
// will incorporate the IPv6 pseudo-header, defined in Section 8.1 of [RFC-2460]."
void test_a_raw_ipv6_binding_with_ipv6_checksum_verifies_the_received_checksum(void)
{
    RawPcbIo *rp = IDEMIP_RAW_PCB_IO(raw_mem);
    rp->open_args.ip_version = 6u;
    rp->open_args.proto = 253u; // RFC 3692 leaves 253 to testing, so no built-in module claims it
    RawPcb.open(raw_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, rp->status);
    const uint16_t pcb = rp->index;
    rp->bind_args.index = pcb;
    rp->bind_args.ip = g_local_ip6;
    rp->bind_args.zone = 0u;
    rp->bind_args.netif = 0u;
    RawPcb.bind(raw_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, rp->status);

    rp->opt_args.index = pcb;
    rp->opt_args.ttl = 64u;
    rp->opt_args.tos = 0u;
    rp->opt_args.cksum_offset = 2; // an even offset into the user data, sec 3.1's IPV6_CHECKSUM
    RawPcb.set_opts(raw_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, rp->status);

    // Eight octets of payload whose 16-bit field at offset 2 holds a wrong sum.
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, 253u, g_remote_ip6, g_local_ip6, 8u);
    memset(g_frame + off, 0x5A, 8u);
    idemip_wr16(g_frame + off + 2u, 0x0000u);
    input(work_a, off + 8u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "a raw packet whose IPV6_CHECKSUM is in error must be discarded");
    TEST_ASSERT_BITS_LOW(IDEMIP_DISPATCH_ACT_DELIVER, IDEMIP_DISPATCH_IO(work_a)->act);

    // The same payload with the sum RFC 8200 sec 8.1's pseudo-header makes correct.
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, 253u, g_remote_ip6, g_local_ip6, 8u);
    memset(g_frame + off, 0x5A, 8u);
    idemip_wr16(g_frame + off + 2u, 0x0000u);
    uint32_t sum = 0u;
    TEST_ASSERT_TRUE(idemip_pseudo_accum(&sum, 6u, 253u, g_remote_ip6, g_local_ip6, 8u));
    idemip_wr16(g_frame + off + 2u, idemip_cksum_final(idemip_cksum_accum(sum, g_frame + off, 8u)));
    input(work_a, off + 8u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_RAW, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_BITS_HIGH(IDEMIP_DISPATCH_ACT_DELIVER, IDEMIP_DISPATCH_IO(work_a)->act);

    // sec 3.1's disabled state, "-1 ... disables the checksum", takes the packet either way.
    rp->opt_args.index = pcb;
    rp->opt_args.ttl = 64u;
    rp->opt_args.cksum_offset = -1;
    RawPcb.set_opts(raw_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, rp->status);
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, 253u, g_remote_ip6, g_local_ip6, 8u);
    memset(g_frame + off, 0x5A, 8u);
    input(work_a, off + 8u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_RAW, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_BITS_HIGH(IDEMIP_DISPATCH_ACT_DELIVER, IDEMIP_DISPATCH_IO(work_a)->act);
}
#endif

// RFC 1122 sec 3.2: a raw binding takes the protocol number itself, so a protocol no built-in module
// claims still reaches a pcb.
void test_a_raw_binding_takes_an_unclaimed_protocol(void)
{
    RawPcbIo *rp = IDEMIP_RAW_PCB_IO(raw_mem);
    rp->open_args.ip_version = 4u;
    rp->open_args.proto = 253u;
    RawPcb.open(raw_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, rp->status);
    uint16_t pcb = rp->index;
    uint8_t local[4];
    idemip_wr32(local, LOCAL_IP4);
    rp->bind_args.index = pcb;
    rp->bind_args.ip = local;
    rp->bind_args.zone = 0u;
    rp->bind_args.netif = 0u;
    RawPcb.bind(raw_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, rp->status);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, 253u, REMOTE_IP4, LOCAL_IP4, 8u, 0u);
    input(work_a, off + 8u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_RAW, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
}

// RFC 792 Echo, answered into the caller's transmit buffer.
void test_an_echo_request_builds_a_reply(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, LOCAL_IP4, IDEMIP_ICMP_ECHO_HDR_LEN + 8u, 0u);
    size_t end = build_icmp_echo(g_frame, off, 8u);
    idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
    idemip_ip4_recksum(g_frame + ip);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DISPATCH_IO(work_a)->status);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_SEND) != 0u);
    TEST_ASSERT_TRUE(IDEMIP_DISPATCH_IO(work_a)->out_len > 0u);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_ECHO_REPLY, g_out[IDEMIP_ICMP_OFF_TYPE]);

    // The unit's own decision, which is what dispatch turned into ACT_SEND. RFC 792: an Echo Reply
    // carries back the Identifier and Sequence Number of the request.
    const IcmpInIo *ic = IDEMIP_ICMP_IN_IO(icmp_in_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ic->status);
    TEST_ASSERT_TRUE(ic->cksum_ok);
    TEST_ASSERT_TRUE((ic->act & IDEMIP_ICMP_IN_ACT_REPLY) != 0u);
    TEST_ASSERT_TRUE((ic->act & IDEMIP_ICMP_IN_ACT_DISCARD) == 0u);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_ECHO, ic->type);
    // RFC 1122 sec 3.2.2.6: the reply's Source Address is the request's specific-destination address.
    TEST_ASSERT_EQUAL_UINT32(LOCAL_IP4, ic->src);
    TEST_ASSERT_EQUAL_UINT32(REMOTE_IP4, ic->dst);
    TEST_ASSERT_EQUAL_UINT16(ic->id, idemip_rd16(g_out + IDEMIP_ICMP_OFF_ID));
    TEST_ASSERT_EQUAL_UINT16(ic->seq, idemip_rd16(g_out + IDEMIP_ICMP_OFF_SEQ));
}

// A reply with nowhere to be built is BUSY, not ERR: a transmit buffer frees on a later tick and the
// same frame dispatched then answers. Reported as ERR the caller would give up on a healthy stack.
void test_a_reply_with_no_transmit_buffer_is_busy(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, LOCAL_IP4, IDEMIP_ICMP_ECHO_HDR_LEN + 8u, 0u);
    size_t end = build_icmp_echo(g_frame, off, 8u);
    idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
    idemip_ip4_recksum(g_frame + ip);

    DispatchIo *io = IDEMIP_DISPATCH_IO(work_a);
    io->input_args.frame = g_frame;
    io->input_args.len = end;
    io->input_args.out = NULL;
    io->input_args.out_cap = 0u;
    io->input_args.now_ms = 1000u;
    io->input_args.desc = IDEMIP_DISPATCH_DESC_NONE;
    io->input_args.netif = 0u;
    Dispatch.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, io->status);
}

// --- ARP ---------------------------------------------------------------------

// RFC 826 "Packet Reception": a REQUEST for this end's protocol address owes a REPLY.
void test_an_arp_request_for_us_builds_a_reply(void)
{
    size_t off = build_eth(g_frame, g_bcast_mac, (uint16_t)IDEMIP_ETHERTYPE_ARP);
    size_t end = build_arp(g_frame, off, IDEMIP_ARP_OP_REQUEST, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DISPATCH_IO(work_a)->status);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_SEND) != 0u);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_ETH_FRAME_MIN, IDEMIP_DISPATCH_IO(work_a)->out_len);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_ETHERTYPE_ARP, idemip_eth_type(g_out));
    TEST_ASSERT_TRUE(idemip_arp_is_reply(g_out + IDEMIP_ETH_OFF_PAYLOAD));
    TEST_ASSERT_EQUAL_UINT32(LOCAL_IP4, idemip_arp_spa(g_out + IDEMIP_ETH_OFF_PAYLOAD));
    TEST_ASSERT_EQUAL_UINT32(REMOTE_IP4, idemip_arp_tpa(g_out + IDEMIP_ETH_OFF_PAYLOAD));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_local_mac, idemip_eth_src(g_out), IDEMIP_MAC_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_remote_mac, idemip_eth_dst(g_out), IDEMIP_MAC_LEN);
}

// RFC 826 "Packet Reception" owes a REPLY only for "?Am I the target protocol address?", and adds
// the triplet only then: "If Merge_flag is false, add the triplet <protocol type, sender protocol
// address, sender hardware address> to the translation table." A REQUEST for someone else therefore
// neither answers nor populates the table.
void test_an_arp_request_for_someone_else_neither_answers_nor_is_learned(void)
{
    size_t off = build_eth(g_frame, g_bcast_mac, (uint16_t)IDEMIP_ETHERTYPE_ARP);
    size_t end = build_arp(g_frame, off, IDEMIP_ARP_OP_REQUEST, OTHER_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_SEND) == 0u);
    IDEMIP_ARP_IO(arp_mem)->find_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(arp_mem)->find_args.spa = REMOTE_IP4;
    ArpTable.find(arp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ARP_IO(arp_mem)->status);
}

// The same REQUEST addressed to us is answered, and the sender's triplet IS added.
void test_an_arp_request_for_us_is_learned(void)
{
    size_t off = build_eth(g_frame, g_bcast_mac, (uint16_t)IDEMIP_ETHERTYPE_ARP);
    size_t end = build_arp(g_frame, off, IDEMIP_ARP_OP_REQUEST, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    IDEMIP_ARP_IO(arp_mem)->find_args.pro = (uint16_t)IDEMIP_ARP_PRO_IPV4;
    IDEMIP_ARP_IO(arp_mem)->find_args.spa = REMOTE_IP4;
    ArpTable.find(arp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ARP_IO(arp_mem)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_remote_mac, IDEMIP_ARP_IO(arp_mem)->mac, IDEMIP_MAC_LEN);
}

// A tagged interface answers inside its own VLAN, so the REPLY carries the tag the frame arrived on.
void test_an_arp_reply_on_a_tagged_interface_carries_the_tag(void)
{
    if_tagged(work_a, 0u, VID_OURS);
    size_t off = build_eth_tagged(g_frame, g_bcast_mac, (uint16_t)IDEMIP_ETHERTYPE_ARP, VID_OURS);
    size_t end = build_arp(g_frame, off, IDEMIP_ARP_OP_REQUEST, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_SEND) != 0u);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_VLAN_TPID, idemip_rd16(g_out + IDEMIP_VLAN_OFF_TPID));
    TEST_ASSERT_EQUAL_UINT16(VID_OURS, (uint16_t)(idemip_rd16(g_out + IDEMIP_VLAN_OFF_TCI) & IDEMIP_VLAN_VID_MASK));
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_ETHERTYPE_ARP, idemip_rd16(g_out + IDEMIP_VLAN_OFF_TYPE));
    TEST_ASSERT_TRUE(idemip_arp_is_reply(g_out + IDEMIP_VLAN_OFF_PAYLOAD));
}

// A REPLY owed with no transmit buffer is BUSY for the same reason an ICMP reply is.
void test_an_arp_reply_with_no_transmit_buffer_is_busy(void)
{
    size_t off = build_eth(g_frame, g_bcast_mac, (uint16_t)IDEMIP_ETHERTYPE_ARP);
    size_t end = build_arp(g_frame, off, IDEMIP_ARP_OP_REQUEST, LOCAL_IP4);
    DispatchIo *io = IDEMIP_DISPATCH_IO(work_a);
    io->input_args.frame = g_frame;
    io->input_args.len = end;
    io->input_args.out = NULL;
    io->input_args.out_cap = 0u;
    io->input_args.now_ms = 1000u;
    io->input_args.desc = IDEMIP_DISPATCH_DESC_NONE;
    io->input_args.netif = 0u;
    Dispatch.input(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, io->status);
}

// An ARP payload shorter than RFC 826's twenty-eight octets is a malformed frame.
void test_a_short_arp_packet_is_an_error(void)
{
    size_t off = build_eth(g_frame, g_bcast_mac, (uint16_t)IDEMIP_ETHERTYPE_ARP);
    input(work_a, off + 10u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, if_ctr(0u, IDEMIP_STAT_IF_IN_ERRORS));
}

// --- reassembly, which pins the buffer the engine wrote ----------------------

// Retention is a pin on a descriptor. A frame that lies in none cannot be held past the call, so the
// fragment is discarded rather than a pointer into a buffer the engine may recycle being kept.
void test_a_fragment_with_no_descriptor_is_discarded(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, 8u, IDEMIP_IP4_FLAG_MF);
    input(work_a, off + 8u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NO_DESC, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP4_REASM_REQDS));
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP4_REASM_FAILS));
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_PINNED) == 0u);
}

#define IP4_FRAG_DESC 2u

// One fragment, held. RFC 815 sec 3 leaves a hole from the end of this fragment to infinity, so the
// row is HOLDING and hands on nothing, and the frame it lies in must not go back to the ring.
void test_a_fragment_the_reassembler_kept_pins_its_descriptor(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, 8u, IDEMIP_IP4_FLAG_MF);
    input(work_a, off + 8u, 0u, IP4_FRAG_DESC);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_PINNED) != 0u,
                             "a retained fragment must report the pin, or its buffer is recycled under it");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_REASSEMBLED) == 0u);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP4_REASM_REQDS));

    // The reassembler's own state, not dispatch's report of it.
    Ip4ReassIo *re = IDEMIP_IP4_REASS_IO(ip4_reass_mem);
    re->next_args.index = IDEMIP_DISPATCH_IO(work_a)->datagram;
    Ip4Reass.next(ip4_reass_mem);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, re->status, "a row with a hole left hands on no datagram");
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_HOLDING, re->state);
}

// RFC 791 sec 3.2 step (10) fixes TDL from the last fragment, so a later fragment claiming to end
// past it contradicts one already held and the reassembler refuses it. RFC 1213 ipInDiscards: "Note
// that this counter does not include any datagrams discarded while awaiting re-assembly", and
// ipReasmFails is "The number of failures detected by the IP re-assembly algorithm (for whatever
// reason: timed out, errors, etc)". A refusal is that failure, and is not an ipInDiscards.
void test_a_fragment_the_reassembler_refuses_counts_a_reassembly_failure(void)
{
    // The last fragment first, one unit in, which fixes the datagram's end at 16.
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, 8u, 1u);
    input(work_a, off + 8u, 0u, IP4_FRAG_DESC);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);

    // A fragment ending at 24, past the 16 the one above fixed.
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, 8u, 2u | IDEMIP_IP4_FLAG_MF);
    input(work_a, off + 8u, 0u, IP4_FRAG_DESC + 1u);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_REASS, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_PINNED) == 0u,
                             "a fragment the reassembler refused must not leave its descriptor pinned");
    TEST_ASSERT_EQUAL_UINT32(2u, ctr(IDEMIP_STAT_IP4_REASM_REQDS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_IP4_REASM_FAILS),
                                     "a refusal is a failure the re-assembly algorithm detected");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_IP4_IN_DISCARDS),
                                     "ipInDiscards excludes datagrams discarded while awaiting re-assembly");
}

// RFC 815 sec 3 step 8: the fragment carrying MF clear fixes where the datagram ends, and with the
// hole list empty the row is COMPLETE. Its fragments come back in ascending offset, each naming the
// descriptor handle, interface in the high octet, that lets the right ring take the buffer back.
void test_the_last_fragment_completes_the_datagram(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, 8u, IDEMIP_IP4_FLAG_MF);
    input(work_a, off + 8u, 0u, IP4_FRAG_DESC);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_REASSEMBLED) == 0u);

    // Offset 1 is one eight-octet unit in, which is where the first fragment's data ended.
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, 8u, 1u);
    input(work_a, off + 8u, 0u, IP4_FRAG_DESC + 1u);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_REASSEMBLED) != 0u,
                             "the fragment that empties the hole list completes the datagram");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_PINNED) != 0u);
    TEST_ASSERT_EQUAL_UINT32(2u, ctr(IDEMIP_STAT_IP4_REASM_REQDS));
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP4_REASM_OKS));

    Ip4ReassIo *re = IDEMIP_IP4_REASS_IO(ip4_reass_mem);
    const uint8_t row = IDEMIP_DISPATCH_IO(work_a)->datagram;
    re->next_args.index = row;
    Ip4Reass.next(ip4_reass_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, re->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_IP4_REASS_COMPLETE, re->state);
    TEST_ASSERT_EQUAL_UINT16(0u, re->off);
    TEST_ASSERT_EQUAL_UINT16(8u, re->len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN), re->hdr_len);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DISPATCH_DESC_HANDLE(0u, IP4_FRAG_DESC), re->desc);

    re->next_args.index = row;
    Ip4Reass.next(ip4_reass_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, re->status);
    TEST_ASSERT_EQUAL_UINT16(8u, re->off);
    TEST_ASSERT_EQUAL_UINT16(8u, re->len);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DISPATCH_DESC_HANDLE(0u, IP4_FRAG_DESC + 1u), re->desc);

    re->next_args.index = row;
    Ip4Reass.next(ip4_reass_mem);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, re->status, "the walk ends once every held fragment is reported");
}

// --- IPv6 --------------------------------------------------------------------

#if IDEMIP_ENABLE_IPV6
#if IDEMIP_ENABLE_UDP

void test_an_ipv6_packet_for_our_address_is_delivered(void)
{
    UdpPcbIo *up = IDEMIP_UDP_PCB_IO(udp_mem);
    up->open_args.ip_version = 6u;
    up->open_args.lite = IDEMIP_FALSE;
    UdpPcb.open(udp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, up->status);
    up->bind_args.index = up->index;
    up->bind_args.ip = g_local_ip6;
    up->bind_args.port = 4001u;
    up->bind_args.zone = 0u;
    up->bind_args.netif = 0u;
    UdpPcb.bind(udp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, up->status);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, g_local_ip6, IDEMIP_UDP_HDR_LEN);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, off, g_remote_ip6, g_local_ip6);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_UDP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_IN_RECEIVES));
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_IN_DELIVERS));
}

// A Fragment header at Fragment Offset zero with M clear, ahead of an ICMPv6 message of @p type.
// That is an atomic fragment: RFC 8200 sec 4.5 says it "does not need any further reassembly".
static size_t build_ip6_atomic_icmp6(uint8_t *f, size_t off, uint8_t type)
{
    const size_t fh = off + IDEMIP_IPV6_HDR_LEN;
    const size_t msg_len = 8u;
    (void)build_ip6(f, off, IDEMIP_IP6_NH_FRAGMENT, g_remote_ip6, g_local_ip6,
                    IDEMIP_IP6_FRAG_HDR_LEN + msg_len);
    idemip_ip6_frag_build(f + fh, IDEMIP_IP6_NH_ICMPV6, 0u, IDEMIP_FALSE, 0x12345678u);
    const size_t m = fh + IDEMIP_IP6_FRAG_HDR_LEN;
    for (size_t i = 0u; i < msg_len; i++)
    {
        f[m + i] = 0u;
    }
    f[m] = type;
    return m + msg_len;
}

// RFC 6980 sec 5: "Nodes MUST silently ignore the following Neighbor Discovery and SEcure Neighbor
// Discovery messages if the packets carrying them include an IPv6 Fragmentation Header". The rule is
// on the presence of the header, so an atomic fragment carrying a Router Advertisement is covered.
void test_a_fragmented_neighbor_discovery_message_is_ignored(void)
{
    static const uint8_t nd_types[] = {133u, 134u, 135u, 136u, 137u};
    for (size_t i = 0u; i < sizeof nd_types; i++)
    {
        size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
        size_t end = build_ip6_atomic_icmp6(g_frame, off, nd_types[i]);
        input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_IP6_FRAG_ND, IDEMIP_DISPATCH_IO(work_a)->drop,
                                      "a fragmented Neighbor Discovery message was processed");
        TEST_ASSERT_EQUAL_UINT32(0u, ctr(IDEMIP_STAT_IP6_REASM_REQDS));
    }
}

// The same shape carrying an ICMPv6 type RFC 6980 does not name reaches the reassembler as usual.
void test_a_fragmented_echo_request_is_not_ignored(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t end = build_ip6_atomic_icmp6(g_frame, off, 128u); // Echo Request
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP6_FRAG_ND, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_REASM_REQDS));
}

// A Routing header carrying @p segs_left, ahead of an eight-octet UDP header. The Routing Type is 43,
// which no allocation names and this library executes none of either way.
static size_t build_ip6_routing(uint8_t *f, size_t off, uint8_t segs_left)
{
    const size_t rt = off + IDEMIP_IPV6_HDR_LEN;
    (void)build_ip6(f, off, IDEMIP_IP6_NH_ROUTING, g_remote_ip6, g_local_ip6,
                    IDEMIP_IP6_EXT_UNIT + IDEMIP_UDP_HDR_LEN);
    f[rt + IDEMIP_IP6_EXT_OFF_NEXT_HDR] = IDEMIP_IP6_NH_UDP;
    f[rt + IDEMIP_IP6_EXT_OFF_LEN] = 0u; // 8 octets, the header alone
    f[rt + IDEMIP_IP6_RT_OFF_TYPE] = 43u;
    f[rt + IDEMIP_IP6_RT_OFF_SEGS_LEFT] = segs_left;
    for (size_t i = 4u; i < IDEMIP_IP6_EXT_UNIT; i++)
    {
        f[rt + i] = 0u;
    }
    return rt + IDEMIP_IP6_EXT_UNIT;
}

// RFC 8200 sec 4.4: "If, while processing a received packet, a node encounters a Routing header with
// an unrecognized Routing Type value, the required behavior of the node depends on the value of the
// Segments Left field ... If Segments Left is non-zero, the node must discard the packet and send an
// ICMP Parameter Problem, Code 0, message to the packet's Source Address, pointing to the
// unrecognized Routing Type."
//
// This library executes no Routing Type, so every one of them is that case. The chain walk stepped
// over the header on its length alone and delivered the packet.
void test_a_routing_header_with_segments_left_is_discarded(void)
{
    (void)bind_udp6(4001u);
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t udp_off = build_ip6_routing(g_frame, off, 1u);
    size_t end = build_udp(g_frame, udp_off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, udp_off, g_remote_ip6, g_local_ip6);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_IP6_ROUTING, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "a Routing header this node cannot execute was stepped over");
    TEST_ASSERT_FALSE(IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER);
    // "pointing to the unrecognized Routing Type", which is the third octet of that header
    TEST_ASSERT_EQUAL_UINT16_MESSAGE((uint16_t)(IDEMIP_IPV6_HDR_LEN + IDEMIP_IP6_RT_OFF_TYPE),
                                     IDEMIP_DISPATCH_IO(work_a)->err_ptr,
                                     "the Pointer a Parameter Problem would carry is wrong");
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_IN_HDR_ERRORS));
}

// "If Segments Left is zero, the node must ignore the Routing header and proceed to process the next
// header in the packet, whose type is identified by the Next Header field in the Routing header."
void test_a_routing_header_with_no_segments_left_is_ignored(void)
{
    uint16_t pcb = bind_udp6(4001u);
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t udp_off = build_ip6_routing(g_frame, off, 0u);
    size_t end = build_udp(g_frame, udp_off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, udp_off, g_remote_ip6, g_local_ip6);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "sec 4.4 ignores a Routing header whose Segments Left is zero");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_UINT16(pcb, IDEMIP_DISPATCH_IO(work_a)->pcb);
}

// A Destination Options header carrying one option of @p opt_type padded out to eight octets, ahead
// of an eight-octet UDP header.
static size_t build_ip6_dstopts(uint8_t *f, size_t off, uint8_t opt_type)
{
    const size_t dh = off + IDEMIP_IPV6_HDR_LEN;
    (void)build_ip6(f, off, IDEMIP_IP6_NH_DSTOPTS, g_remote_ip6, g_local_ip6,
                    IDEMIP_IP6_EXT_UNIT + IDEMIP_UDP_HDR_LEN);
    f[dh + IDEMIP_IP6_EXT_OFF_NEXT_HDR] = IDEMIP_IP6_NH_UDP;
    f[dh + IDEMIP_IP6_EXT_OFF_LEN] = 0u; // 8 octets, the header alone
    f[dh + 2u] = opt_type;
    f[dh + 3u] = 2u; // Opt Data Len, so the option spans four octets
    f[dh + 4u] = 0u;
    f[dh + 5u] = 0u;
    f[dh + 6u] = IDEMIP_IP6_OPT_PADN; // PadN over the last two octets
    f[dh + 7u] = 0u;
    return dh + IDEMIP_IP6_EXT_UNIT;
}

// RFC 8200 sec 4.2: "The Option Type identifiers are internally encoded such that their highest-order
// 2 bits specify the action that must be taken if the processing IPv6 node does not recognize the
// Option Type: 00 - skip over this option and continue processing the header. 01 - discard the
// packet. 10 - discard the packet and, regardless of whether or not the packet's Destination Address
// was a multicast address, send an ICMP Parameter Problem, Code 2 ... 11 - discard the packet and,
// only if the packet's Destination Address was not a multicast address, send [one]."
//
// This library recognizes only the two padding options sec 4.2 says "must be recognized by all IPv6
// implementations", so every other type takes its own action bits. Nothing walked the options at all,
// so all four behaved as 00 and the packet was delivered whatever it carried.
void test_an_option_the_node_refuses_discards_the_packet(void)
{
    static const uint8_t discarding[] = {
        (uint8_t)(IDEMIP_IP6_OPT_ACT_DISCARD | 0x1Fu),      // 01
        (uint8_t)(IDEMIP_IP6_OPT_ACT_DISCARD_ICMP | 0x1Fu), // 10
        (uint8_t)(IDEMIP_IP6_OPT_ACT_DISCARD_UNI | 0x1Fu),  // 11
    };
    (void)bind_udp6(4001u);
    for (size_t i = 0u; i < (sizeof discarding / sizeof discarding[0]); i++)
    {
        size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
        size_t udp_off = build_ip6_dstopts(g_frame, off, discarding[i]);
        size_t end = build_udp(g_frame, udp_off, 4000u, 4001u, 0u);
        seal_udp6(g_frame, udp_off, g_remote_ip6, g_local_ip6);
        input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_IP6_OPTION, IDEMIP_DISPATCH_IO(work_a)->drop,
                                      "an option whose action bits discard was skipped over");
        TEST_ASSERT_FALSE(IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER);
        // "pointing to the unrecognized Option Type", which is two octets into the header
        TEST_ASSERT_EQUAL_UINT16((uint16_t)(IDEMIP_IPV6_HDR_LEN + 2u), IDEMIP_DISPATCH_IO(work_a)->err_ptr);
    }
}

// "00 - skip over this option and continue processing the header." The Router Alert option RFC 2711
// gives MLD is type 5, whose high bits are 00, so this is the case that keeps a Query arriving.
void test_an_unrecognized_option_that_says_skip_is_skipped(void)
{
    uint16_t pcb = bind_udp6(4001u);
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t udp_off = build_ip6_dstopts(g_frame, off, (uint8_t)(IDEMIP_IP6_OPT_ACT_SKIP | 0x05u));
    size_t end = build_udp(g_frame, udp_off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, udp_off, g_remote_ip6, g_local_ip6);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "sec 4.2 skips an unrecognized option whose high bits are 00");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_UINT16(pcb, IDEMIP_DISPATCH_IO(work_a)->pcb);
}

// RFC 4443 sec 2.4 (b): "If an ICMPv6 informational message of unknown type is received, it MUST be
// silently discarded." icmp6_in raises IDEMIP_ICMP6_IN_ACT_DISCARD for that, for a message shorter
// than its own type requires, and for one whose sec 2.3 checksum does not hold, and dispatch named
// the flag nowhere.
void test_an_icmpv6_message_of_unknown_type_is_discarded(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_ICMPV6, g_remote_ip6, g_local_ip6, IDEMIP_ICMP6_ECHO_HDR_LEN);
    g_frame[off + IDEMIP_ICMP6_OFF_TYPE] = 200u; // informational, and no type RFC 4443 assigns
    g_frame[off + IDEMIP_ICMP6_OFF_CODE] = 0u;
    idemip_wr16(g_frame + off + IDEMIP_ICMP6_OFF_CKSUM, 0u);
    idemip_wr16(g_frame + off + 4u, 0u);
    idemip_wr16(g_frame + off + 6u, 0u);
    uint32_t sum = idemip_ip6_pseudo_accum(0u, g_remote_ip6, g_local_ip6, (uint32_t)IDEMIP_ICMP6_ECHO_HDR_LEN,
                                           IDEMIP_IP6_NH_ICMPV6);
    idemip_wr16(g_frame + off + IDEMIP_ICMP6_OFF_CKSUM,
                idemip_cksum_final(idemip_cksum_accum(sum, g_frame + off, IDEMIP_ICMP6_ECHO_HDR_LEN)));
    input(work_a, off + IDEMIP_ICMP6_ECHO_HDR_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_FALSE_MESSAGE(IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER,
                              "an informational message of unknown type was delivered");
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP6_IN_MSGS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP6_IN_ERRORS),
                                     "an unknown type is not an ICMP-specific error");

    // The unit's own decision, which is the flag dispatch read. A checksum that holds is what tells
    // sec 2.4 (b)'s unknown type from a corrupted message, and they take different drop paths.
    const Icmp6InIo *ic = IDEMIP_ICMP6_IN_IO(icmp6_in_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ic->status);
    TEST_ASSERT_TRUE_MESSAGE(ic->cksum_ok, "the sec 2.3 checksum this case built must hold");
    TEST_ASSERT_TRUE((ic->act & IDEMIP_ICMP6_IN_ACT_DISCARD) != 0u);
    TEST_ASSERT_TRUE((ic->act & IDEMIP_ICMP6_IN_ACT_REPLY) == 0u);
    TEST_ASSERT_EQUAL_UINT8(200u, ic->type);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "a message whose checksum holds is not a checksum error");
    TEST_ASSERT_FALSE_MESSAGE(ic->bad_len, "an unknown type is not a bad length");
    // RFC 2465 ipv6IfStatsInDiscards, the IPv6 half of a pair where only the IPv4 one was named.
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_IN_DISCARDS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_IP4_IN_DISCARDS),
                                     "an IPv6 packet was counted against the IPv4 counter");
}

// The other half of sec 2.4. (b) silently discards an informational message of unknown type, which is
// the case above; (a) says an ERROR message of unknown type "MUST be passed to the upper-layer process
// that originated the packet that caused the error", so icmp6_in hands it on rather than dropping it
// and it reaches the RFC 2466 counters. It has none of its own - the table names a counter per type
// RFC 4443 assigns - so ipv6IfIcmpInMsgs is the only one that moves, and nothing calls it an error.
//
// Type 100 because RFC 4443 sec 6 leaves it to private experimentation: an error type, by being under
// 128, and one no implementation is expected to know. The same reason 253 is the next-header the IPv6
// cases above reach for.
void test_an_icmpv6_error_of_unknown_type_is_passed_up_and_counted_once(void)
{
    const size_t msg_len = (size_t)IDEMIP_ICMP6_ERR_HDR_LEN + IDEMIP_IP6_OFF_PAYLOAD + IDEMIP_UDP_HDR_LEN;
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_ICMPV6, g_remote_ip6, g_local_ip6, msg_len);
    memset(g_frame + off, 0, msg_len);
    g_frame[off + IDEMIP_ICMP6_OFF_TYPE] = 100u;
    g_frame[off + IDEMIP_ICMP6_OFF_CODE] = 0u;
    // sec 2.4 (c)'s invoking packet, whole enough that sec 2.4 (d) can read a protocol out of it. A
    // body that stops short of one is a different case: icmp6_in calls that a length error.
    (void)build_ip6(g_frame, off + IDEMIP_ICMP6_ERR_HDR_LEN, IDEMIP_IP6_NH_UDP, g_local_ip6, g_remote_ip6,
                    IDEMIP_UDP_HDR_LEN);
    uint32_t sum = idemip_ip6_pseudo_accum(0u, g_remote_ip6, g_local_ip6, (uint32_t)msg_len, IDEMIP_IP6_NH_ICMPV6);
    idemip_wr16(g_frame + off + IDEMIP_ICMP6_OFF_CKSUM,
                idemip_cksum_final(idemip_cksum_accum(sum, g_frame + off, msg_len)));
    input(work_a, off + msg_len, 0u, IDEMIP_DISPATCH_DESC_NONE);

    const Icmp6InIo *ic = IDEMIP_ICMP6_IN_IO(icmp6_in_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ic->status);
    TEST_ASSERT_TRUE_MESSAGE(ic->cksum_ok, "the sec 2.3 checksum this case built must hold");
    TEST_ASSERT_TRUE_MESSAGE((ic->act & IDEMIP_ICMP6_IN_ACT_DISCARD) == 0u,
                             "sec 2.4 (a) passes an error message of unknown type up, it does not discard it");
    TEST_ASSERT_EQUAL_UINT8(100u, ic->type);

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP6_IN_MSGS), "ipv6IfIcmpInMsgs is every message");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP6_IN_ERRORS),
                                     "an unknown error type is not an ICMP-specific error");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP6_IN_DEST_UNREACHS), "a type it is not");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP6_IN_PKT_TOO_BIGS), "a type it is not");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP6_IN_ECHOS), "a type it is not");
}

// An eight-octet ICMPv6 Echo message of @p type, 128 being a Request and 129 a Reply, carrying
// RFC 4443 sec 2.3's checksum over the pseudo-header. The message is the whole payload, so the IPv6
// Payload Length is its own length.
static size_t build_ip6_echo6(uint8_t *f, size_t off, uint8_t type)
{
    off = build_ip6(f, off, IDEMIP_IP6_NH_ICMPV6, g_remote_ip6, g_local_ip6, IDEMIP_ICMP6_ECHO_HDR_LEN);
    f[off + IDEMIP_ICMP6_OFF_TYPE] = type;
    f[off + IDEMIP_ICMP6_OFF_CODE] = 0u;
    idemip_wr16(f + off + IDEMIP_ICMP6_OFF_CKSUM, 0u);
    idemip_wr16(f + off + 4u, 0x0AAAu);
    idemip_wr16(f + off + 6u, 0x0001u);
    uint32_t sum = idemip_ip6_pseudo_accum(0u, g_remote_ip6, g_local_ip6, (uint32_t)IDEMIP_ICMP6_ECHO_HDR_LEN,
                                           IDEMIP_IP6_NH_ICMPV6);
    idemip_wr16(f + off + IDEMIP_ICMP6_OFF_CKSUM,
                idemip_cksum_final(idemip_cksum_accum(sum, f + off, IDEMIP_ICMP6_ECHO_HDR_LEN)));
    return off + IDEMIP_ICMP6_ECHO_HDR_LEN;
}

// The RFC 2466 sec 4 twins of the v4 case above, and not the same objects under IPv6 names:
// ipv6IfIcmpOutMsgs is "the total number of ICMP messages which this interface attempted to send",
// ipv6IfIcmpOutEchoReplies "the number of ICMP Echo Reply messages sent by the interface". Both are
// entries RFC 1213 sec 6.7 has no field for at all, so before the two groups were separated there
// was nothing here to count with.
void test_the_icmpv6_echo_reply_this_path_builds_takes_its_two_out_counters(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t end = build_ip6_echo6(g_frame, off, IDEMIP_ICMP6_ECHO_REQUEST);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_SEND) != 0u,
                             "the request built no reply, so this case counts nothing either way");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP6_OUT_MSGS),
                                     "ipv6IfIcmpOutMsgs counted nothing");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP6_OUT_ECHO_REPLIES),
                                     "ipv6IfIcmpOutEchoReplies counted nothing");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP4_OUT_MSGS),
                                     "an ICMPv6 message was counted against the RFC 1213 group");

    // An Echo Reply arriving is answered by nothing, so neither counter moves for it.
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    end = build_ip6_echo6(g_frame, off, IDEMIP_ICMP6_ECHO_REPLY);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP6_OUT_MSGS),
                                     "a message that built no reply was counted as one sent");
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP6_OUT_ECHO_REPLIES));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP6_IN_ECHO_REPLIES),
                                     "the reply that arrived is still an in count");
}

// RFC 8200 sec 8.1: "IPv6 receivers must discard UDP packets containing a zero checksum". The
// IPv4 exemption does not carry over, because an IPv6 header carries no checksum of its own, so a
// zero here leaves the whole datagram unprotected.
void test_a_zero_udp_checksum_is_discarded_over_ipv6(void)
{
    UdpPcbIo *up = IDEMIP_UDP_PCB_IO(udp_mem);
    up->open_args.ip_version = 6u;
    up->open_args.lite = IDEMIP_FALSE;
    UdpPcb.open(udp_mem);
    up->bind_args.index = up->index;
    up->bind_args.ip = g_local_ip6;
    up->bind_args.port = 4001u;
    up->bind_args.zone = 0u;
    up->bind_args.netif = 0u;
    UdpPcb.bind(udp_mem);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, g_local_ip6, IDEMIP_UDP_HDR_LEN);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    idemip_wr16(g_frame + off + IDEMIP_UDP_OFF_CKSUM, 0u);

    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
}

// The same datagram with a wrong non-zero sum, so the two IPv6 rejections are told apart.
void test_a_bad_udp_checksum_is_discarded_over_ipv6(void)
{
    UdpPcbIo *up = IDEMIP_UDP_PCB_IO(udp_mem);
    up->open_args.ip_version = 6u;
    up->open_args.lite = IDEMIP_FALSE;
    UdpPcb.open(udp_mem);
    up->bind_args.index = up->index;
    up->bind_args.ip = g_local_ip6;
    up->bind_args.port = 4001u;
    up->bind_args.zone = 0u;
    up->bind_args.netif = 0u;
    UdpPcb.bind(udp_mem);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, g_local_ip6, IDEMIP_UDP_HDR_LEN);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, off, g_remote_ip6, g_local_ip6);
    idemip_wr16(g_frame + off + IDEMIP_UDP_OFF_CKSUM,
                (uint16_t)(idemip_udp_cksum(g_frame + off) ^ 0x0001u));

    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
}

#endif // IDEMIP_ENABLE_UDP

void test_an_ipv6_packet_for_somewhere_else_is_reported_for_forwarding(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, g_other_ip6, IDEMIP_UDP_HDR_LEN);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, off, g_remote_ip6, g_other_ip6);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_FORWARD) != 0u);
}

// RFC 8200 sec 3's Payload Length reaching past the octets that arrived is RFC 2465's
// ipv6IfStatsInTruncatedPkts, "discarded because datagram frame didn't carry enough data", and not
// ipv6IfStatsInHdrErrors, whose list is "version number mismatch, other format errors, hop count
// exceeded, errors discovered in processing their IPv6 options". The header here is well formed and
// says so; what is missing is the payload it names. RFC 1213 has no such counter, which is why the
// IPv4 twin of this case reads ipInHdrErrors and this one does not.
void test_an_ipv6_payload_length_past_the_frame_is_a_truncated_packet(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t ip = off;
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, g_local_ip6, IDEMIP_UDP_HDR_LEN);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, off, g_remote_ip6, g_local_ip6);
    idemip_ip6_set_payload_len(g_frame + ip, 4000u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_IP6_IN_TRUNCATED_PKTS),
                                     "ipv6IfStatsInTruncatedPkts counted nothing");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_IP6_IN_HDR_ERRORS),
                                     "a truncated frame was counted as a header error");
}

// The other half of the same split. A Version that is not 6 is the first entry on
// ipv6IfStatsInHdrErrors' own list, and the frame carrying it is long enough to hold the header it
// misstates, so nothing here was truncated.
void test_an_ipv6_version_that_is_not_six_is_a_header_error(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t ip = off;
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, g_local_ip6, IDEMIP_UDP_HDR_LEN);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, off, g_remote_ip6, g_local_ip6);
    g_frame[ip] = (uint8_t)((g_frame[ip] & 0x0Fu) | 0x40u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_IP6_IN_HDR_ERRORS),
                                     "ipv6IfStatsInHdrErrors counted nothing");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_IP6_IN_TRUNCATED_PKTS),
                                     "a malformed header was counted as a truncated frame");
}

// A frame with no room for the 40-octet fixed header carried too little to read, so there is no
// Version to disagree with and nothing but the length to report.
void test_a_frame_too_short_for_the_ipv6_header_is_a_truncated_packet(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    (void)build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, g_local_ip6, 0u);
    input(work_a, off + (size_t)IDEMIP_IPV6_HDR_LEN - 1u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_IP6_IN_TRUNCATED_PKTS),
                                     "ipv6IfStatsInTruncatedPkts counted nothing");
    TEST_ASSERT_EQUAL_UINT32(0u, ctr(IDEMIP_STAT_IP6_IN_HDR_ERRORS));
}

// RFC 2465's ipv6IfStatsInMcastPkts, "the number of multicast packets received by the interface",
// which RFC 1213 has no counter for on either side. What it counts is arrival and not acceptance: a
// packet to a group this node never joined is still one the interface received, and it is counted
// before the destination decides anything. A unicast packet is not counted by it at all.
void test_a_multicast_destination_counts_an_ipv6_multicast_arrival(void)
{
    static const uint8_t unjoined[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42};

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, unjoined, IDEMIP_UDP_HDR_LEN);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, off, g_remote_ip6, unjoined);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_IP6_IN_MCAST_PKTS),
                                     "ipv6IfStatsInMcastPkts counted nothing for a group not joined");

    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, g_local_ip6, IDEMIP_UDP_HDR_LEN);
    end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, off, g_remote_ip6, g_local_ip6);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_IP6_IN_MCAST_PKTS),
                                     "a unicast destination was counted as a multicast arrival");
    // Both arrived, so ipv6IfStatsInReceives took both either way.
    TEST_ASSERT_EQUAL_UINT32(2u, ctr(IDEMIP_STAT_IP6_IN_RECEIVES));
}

// RFC 4291 sec 2.7.1: a node joins the Solicited-Node address of every unicast address it holds, so
// a packet to one is this host's.
void test_the_solicited_node_address_of_our_own_is_local(void)
{
    // A binding to answer with, so delivery is what the case reads rather than the absence of a
    // forward, which no multicast destination ever takes.
    UdpPcbIo *up = IDEMIP_UDP_PCB_IO(udp_mem);
    up->open_args.ip_version = 6u;
    up->open_args.lite = IDEMIP_FALSE;
    UdpPcb.open(udp_mem);
    up->bind_args.index = up->index;
    up->bind_args.ip = g_ip6_any;
    up->bind_args.port = 4001u;
    up->bind_args.zone = 0u;
    up->bind_args.netif = 0u;
    UdpPcb.bind(udp_mem);

    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    idemip_ip6_addr_solicited(solicited, g_local_ip6);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, solicited, IDEMIP_UDP_HDR_LEN);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, off, g_remote_ip6, solicited);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u,
                             "the solicited-node address of a configured address is this node's");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_FORWARD) == 0u);

    // The solicited-node address of an address this node does not hold is not.
    uint8_t other[IDEMIP_IP6_ADDR_LEN];
    memcpy(other, g_local_ip6, IDEMIP_IP6_ADDR_LEN);
    other[IDEMIP_IP6_ADDR_LEN - 1u] = (uint8_t)(other[IDEMIP_IP6_ADDR_LEN - 1u] ^ 0x5Au);
    idemip_ip6_addr_solicited(solicited, other);
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    off = build_ip6(g_frame, off, IDEMIP_IP6_NH_UDP, g_remote_ip6, solicited, IDEMIP_UDP_HDR_LEN);
    end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp6(g_frame, off, g_remote_ip6, solicited);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u,
                             "a solicited-node group this node did not join is not its own");
}


// --- RFC 4861 Neighbor Discovery and RFC 2710 MLD ----------------------------
// These are ICMPv6 types this library implements, so RFC 4443 sec 2.4 (b)'s silent discard of an
// informational message "of unknown type" is not theirs. icmp6_in answers Echo and nothing else, so
// dispatch names the message and the module that owns it and the caller drives that module, which
// is what it already does for an RFC 826 packet and acd.

// The ICMPv6 header of a message with a zeroed body, at the offset the body starts.
static size_t build_icmp6_msg(uint8_t *f, size_t off, uint8_t type, const uint8_t *src, const uint8_t *dst,
                              size_t msg_len)
{
    size_t ip = off;
    off = build_ip6(f, off, IDEMIP_IP6_NH_ICMPV6, src, dst, msg_len);
    // RFC 4861 sec 6.1.1, sec 6.1.2, sec 7.1.1, sec 7.1.2 and sec 8.1 all require 255 of the five ND
    // types, and RFC 2710 sec 3 sends its three with 1. A frame built any other way is one a
    // neighbor never sent, so the valid cases here carry what the RFC that owns the type states.
    if (idemip_icmp6_is_nd(type))
    {
        idemip_ip6_set_hop_limit(f + ip, IDEMIP_ICMP6_ND_HOP_LIMIT);
    }
    else if (idemip_icmp6_is_mld(type))
    {
        idemip_ip6_set_hop_limit(f + ip, 1u);
    }
    memset(f + off, 0, msg_len);
    f[off + IDEMIP_ICMP6_OFF_TYPE] = type;
    f[off + IDEMIP_ICMP6_OFF_CODE] = 0u;
    return off;
}

static void seal_icmp6(uint8_t *f, size_t off, size_t msg_len, const uint8_t *src, const uint8_t *dst)
{
    idemip_wr16(f + off + IDEMIP_ICMP6_OFF_CKSUM, 0u);
    idemip_wr16(f + off + IDEMIP_ICMP6_OFF_CKSUM, idemip_icmp6_cksum_compute(f + off, msg_len, src, dst));
}

// RFC 4861 sec 7.2.4 answers a Neighbor Solicitation for one of this node's addresses with a
// Neighbor Advertisement, which nothing can do if the solicitation never leaves the receive path.
void test_a_neighbor_solicitation_reaches_the_neighbor_discovery_module(void)
{
    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    idemip_ip6_addr_solicited(solicited, g_local_ip6);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT, g_remote_ip6, solicited,
                                 IDEMIP_ICMP6_NS_HDR_LEN);
    memcpy(g_frame + msg + IDEMIP_ICMP6_OFF_NS_TARGET, g_local_ip6, IDEMIP_IP6_ADDR_LEN);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_NS_HDR_LEN, g_remote_ip6, solicited);
    input(work_a, msg + IDEMIP_ICMP6_NS_HDR_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "a Neighbor Solicitation is not an informational message of unknown type");
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u,
                             "the solicitation must reach the module that answers it");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_ND, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    // where the caller reads the Target Address from
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_local_ip6,
                                  idemip_icmp6_nd_target(g_frame + IDEMIP_DISPATCH_IO(work_a)->payload_off),
                                  IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP6_IN_MSGS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP6_IN_ERRORS),
                                     "a type this library implements is not an ICMP-specific error");

    // What made that destination this host's. RFC 4291 sec 2.7.1: the Solicited-Node address is
    // "formed by taking the low-order 24 bits of an address ... and appending those bits to the
    // prefix FF02:0:0:0:0:1:FF00::/104". Dispatch walks the interface's addresses and compares each
    // one's against the destination, so this unit is the whole of that decision.
    static const uint8_t prefix[13] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF};
    Ip6AddrIo *i6 = IDEMIP_IP6_ADDR_IO(ip6_addr_mem);
    i6->solicited_args.addr = g_local_ip6;
    Ip6Addr.solicited(ip6_addr_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, i6->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(solicited, i6->solicited, IDEMIP_IP6_ADDR_LEN,
                                          "the address the case addressed is not this node's solicited-node one");
    TEST_ASSERT_EQUAL_UINT8_ARRAY(prefix, i6->solicited, sizeof prefix);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_local_ip6 + IDEMIP_IP6_ADDR_LEN - 3u, i6->solicited + sizeof prefix, 3u);
}

// RFC 4861 sec 4.4, the reply to the above, which sec 7.2.5 feeds to the Neighbor Cache.
void test_a_neighbor_advertisement_reaches_the_neighbor_discovery_module(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_NEIGHBOR_ADVERT, g_remote_ip6, g_local_ip6,
                                 IDEMIP_ICMP6_NA_HDR_LEN);
    g_frame[msg + IDEMIP_ICMP6_OFF_NA_FLAGS] = IDEMIP_ICMP6_NA_FLAG_S | IDEMIP_ICMP6_NA_FLAG_O;
    memcpy(g_frame + msg + IDEMIP_ICMP6_OFF_NA_TARGET, g_remote_ip6, IDEMIP_IP6_ADDR_LEN);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_NA_HDR_LEN, g_remote_ip6, g_local_ip6);
    input(work_a, msg + IDEMIP_ICMP6_NA_HDR_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_ND, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_NA_FLAG_S | IDEMIP_ICMP6_NA_FLAG_O,
                            idemip_icmp6_na_flags(g_frame + IDEMIP_DISPATCH_IO(work_a)->payload_off));
}

// RFC 4861 sec 4.2, which slaac, rdnss and nd6 each read a part of. Its options are what carry the
// Prefix Information sec 4.6.2 defines, so the message is built with one.
void test_a_router_advertisement_carrying_a_prefix_option_reaches_the_module(void)
{
    size_t opt = (size_t)IDEMIP_ICMP6_ND_OPT_PREFIX_LEN << IDEMIP_ICMP6_ND_OPT_UNIT_SHIFT;
    size_t len = (size_t)IDEMIP_ICMP6_RA_HDR_LEN + opt;

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg =
        build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_ROUTER_ADVERT, g_remote_ip6, g_local_ip6, len);
    g_frame[msg + IDEMIP_ICMP6_OFF_RA_CUR_HOP] = 64u;
    idemip_wr16(g_frame + msg + IDEMIP_ICMP6_OFF_RA_LIFETIME, 1800u);
    uint8_t *o = g_frame + msg + IDEMIP_ICMP6_RA_HDR_LEN;
    o[IDEMIP_ICMP6_ND_OPT_OFF_TYPE] = IDEMIP_ICMP6_ND_OPT_PREFIX;
    o[IDEMIP_ICMP6_ND_OPT_OFF_LEN] = IDEMIP_ICMP6_ND_OPT_PREFIX_LEN;
    o[IDEMIP_ICMP6_ND_OPT_OFF_PREFIX_LEN] = 64u;
    o[IDEMIP_ICMP6_ND_OPT_OFF_PREFIX_FLAGS] = IDEMIP_ICMP6_ND_PREFIX_FLAG_L | IDEMIP_ICMP6_ND_PREFIX_FLAG_A;
    memcpy(o + IDEMIP_ICMP6_ND_OPT_OFF_PREFIX, g_local_ip6, IDEMIP_IP6_ADDR_LEN);
    seal_icmp6(g_frame, msg, len, g_remote_ip6, g_local_ip6);
    input(work_a, msg + len, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_ND, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_EQUAL_UINT16(1800u, idemip_icmp6_ra_lifetime(g_frame + IDEMIP_DISPATCH_IO(work_a)->payload_off));
}

// RFC 2710 sec 3, the IPv6 counterpart of the RFC 2236 Query d_igmp has always handled. sec 3.4
// puts the Maximum Response Delay in milliseconds, and sec 3.6 makes a zero Multicast Address a
// General Query.
void test_an_mld_query_reaches_the_group_module(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_MLD_QUERY, g_remote_ip6, g_local_ip6,
                                 IDEMIP_ICMP6_MLD_MSG_LEN);
    idemip_wr16(g_frame + msg + IDEMIP_ICMP6_OFF_MLD_MAX_RESP, 10000u);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_MLD_MSG_LEN, g_remote_ip6, g_local_ip6);
    input(work_a, msg + IDEMIP_ICMP6_MLD_MSG_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_PCB_GROUP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind,
                                  "an MLD message belongs to the group table, as an IGMP one does");
    TEST_ASSERT_EQUAL_UINT16(10000u,
                             idemip_icmp6_mld_max_resp(g_frame + IDEMIP_DISPATCH_IO(work_a)->payload_off));
}

// RFC 2466 sec 4 gives every ICMPv6 type this library carries a counter of its own. Seven of them
// leave dispatch by the Neighbor Discovery door rather than through icmp6_in, so their counters are
// taken there, and none of the seven has an RFC 1213 sec 6.7 equivalent to have been counted under
// before: ipv6IfIcmpInRouterSolicits, InRouterAdvertisements, InNeighborSolicits,
// InNeighborAdvertisements, InRedirects, InGroupMembQueries, InGroupMembResponses and
// InGroupMembReductions. Each is driven through and read back on its own counter.
void test_every_neighbor_discovery_and_listener_type_takes_its_own_rfc_2466_counter(void)
{
    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    idemip_ip6_addr_solicited(solicited, g_local_ip6);

    static const struct
    {
        uint8_t type;
        size_t len;
        IdemIpStatsCounter id;
    } table[] = {
        {(uint8_t)IDEMIP_ICMP6_ROUTER_SOLICIT, (size_t)IDEMIP_ICMP6_RS_HDR_LEN,
         IDEMIP_STAT_ICMP6_IN_ROUTER_SOLICITS},
        {(uint8_t)IDEMIP_ICMP6_ROUTER_ADVERT, (size_t)IDEMIP_ICMP6_RA_HDR_LEN,
         IDEMIP_STAT_ICMP6_IN_ROUTER_ADVERTISEMENTS},
        {(uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT, (size_t)IDEMIP_ICMP6_NS_HDR_LEN,
         IDEMIP_STAT_ICMP6_IN_NEIGHBOR_SOLICITS},
        {(uint8_t)IDEMIP_ICMP6_NEIGHBOR_ADVERT, (size_t)IDEMIP_ICMP6_NA_HDR_LEN,
         IDEMIP_STAT_ICMP6_IN_NEIGHBOR_ADVERTISEMENTS},
        {(uint8_t)IDEMIP_ICMP6_REDIRECT, (size_t)IDEMIP_ICMP6_RD_HDR_LEN, IDEMIP_STAT_ICMP6_IN_REDIRECTS},
        {(uint8_t)IDEMIP_ICMP6_MLD_QUERY, (size_t)IDEMIP_ICMP6_MLD_MSG_LEN,
         IDEMIP_STAT_ICMP6_IN_GROUP_MEMB_QUERIES},
        {(uint8_t)IDEMIP_ICMP6_MLD_REPORT, (size_t)IDEMIP_ICMP6_MLD_MSG_LEN,
         IDEMIP_STAT_ICMP6_IN_GROUP_MEMB_RESPONSES},
        {(uint8_t)IDEMIP_ICMP6_MLD_DONE, (size_t)IDEMIP_ICMP6_MLD_MSG_LEN,
         IDEMIP_STAT_ICMP6_IN_GROUP_MEMB_REDUCTIONS},
    };

    for (size_t i = 0u; i < sizeof table / sizeof table[0]; i++)
    {
        const uint8_t *dst = (table[i].type == (uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT) ? solicited : g_local_ip6;
        size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
        size_t msg = build_icmp6_msg(g_frame, off, table[i].type, g_remote_ip6, dst, table[i].len);
        if (table[i].type == (uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT)
        {
            memcpy(g_frame + msg + IDEMIP_ICMP6_OFF_NS_TARGET, g_local_ip6, IDEMIP_IP6_ADDR_LEN);
        }
        seal_icmp6(g_frame, msg, table[i].len, g_remote_ip6, dst);
        input(work_a, msg + table[i].len, 0u, IDEMIP_DISPATCH_DESC_NONE);

        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop,
                                      "a type this library carries was dropped before it could be counted");
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(table[i].id), "the type's own RFC 2466 counter took nothing");
    }
    // ipv6IfIcmpInMsgs is "the total number of ICMP messages received by the interface", so the
    // per-type counters above sum to it and none of the eight double-counted.
    TEST_ASSERT_EQUAL_UINT32(8u, ctr(IDEMIP_STAT_ICMP6_IN_MSGS));
    TEST_ASSERT_EQUAL_UINT32(0u, ctr(IDEMIP_STAT_ICMP6_IN_ERRORS));
}

// The one RFC 2466 counter with no RFC 1213 twin that this library could already have taken and did
// not: ipv6IfIcmpInPktTooBigs. RFC 4443 sec 3.2's Packet Too Big is what RFC 8201 Path MTU Discovery
// runs on, and until now an IPv6 stack that implements pmtu6 could not report having received one.
void test_a_packet_too_big_takes_the_rfc_2466_counter_of_its_own(void)
{
    const size_t quoted = (size_t)IDEMIP_IPV6_HDR_LEN + (size_t)IDEMIP_UDP_HDR_LEN;
    const size_t msg_len = (size_t)IDEMIP_ICMP6_ERR_HDR_LEN + quoted;

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG, g_remote_ip6, g_local_ip6,
                                 msg_len);
    // sec 3.2's MTU field, and the invoking packet the error quotes: a datagram this node sent.
    idemip_wr32(g_frame + msg + IDEMIP_ICMP6_OFF_MTU, 1280u);
    size_t q = build_ip6(g_frame, msg + IDEMIP_ICMP6_ERR_HDR_LEN, IDEMIP_IP6_NH_UDP, g_local_ip6, g_remote_ip6,
                         IDEMIP_UDP_HDR_LEN);
    (void)build_udp(g_frame, q, 4000u, 4001u, 0u);
    seal_icmp6(g_frame, msg, msg_len, g_remote_ip6, g_local_ip6);
    input(work_a, msg + msg_len, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP6_IN_PKT_TOO_BIGS),
                                     "ipv6IfIcmpInPktTooBigs counted nothing");
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP6_IN_MSGS));
    TEST_ASSERT_EQUAL_UINT32(0u, ctr(IDEMIP_STAT_ICMP6_IN_ERRORS));
}

// The other two RFC 4443 error types, sec 3.3 Time Exceeded and sec 3.4 Parameter Problem. Each
// carries an RFC 2466 counter of its own, and each is an ipv6IfIcmpInMsgs as well, that counter
// including "all those counted by ipv6IfIcmpInErrors" and every other type besides.
//
// sec 2.4 (d) has the upper-layer type "extracted from the original packet", so each message quotes
// a whole datagram this node sent; a quote too short to walk is discarded before the count, which is
// what the length cases elsewhere in this suite hold.
void test_the_remaining_icmp6_error_types_take_their_own_counters(void)
{
    static const struct
    {
        uint8_t type;
        IdemIpStatsCounter id;
        const char *name;
    } rows[] = {
        {(uint8_t)IDEMIP_ICMP6_TIME_EXCEEDED, IDEMIP_STAT_ICMP6_IN_TIME_EXCDS, "ipv6IfIcmpInTimeExcds"},
        {(uint8_t)IDEMIP_ICMP6_PARAMETER_PROBLEM, IDEMIP_STAT_ICMP6_IN_PARM_PROBLEMS, "ipv6IfIcmpInParmProblems"},
    };

    for (size_t r = 0; r < sizeof rows / sizeof rows[0]; r++)
    {
        // Each row starts from the state setUp built, so the counts below are this message's alone.
        wire_units();
        Dispatch.clear(work_a);
        bind_all(work_a);
        if_untagged(work_a, 0u);
        memset(g_frame, 0, sizeof g_frame);

        const size_t quoted = (size_t)IDEMIP_IPV6_HDR_LEN + (size_t)IDEMIP_UDP_HDR_LEN;
        const size_t msg_len = (size_t)IDEMIP_ICMP6_ERR_HDR_LEN + quoted;
        const size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
        const size_t msg = build_icmp6_msg(g_frame, off, rows[r].type, g_remote_ip6, g_local_ip6, msg_len);
        const size_t q = build_ip6(g_frame, msg + IDEMIP_ICMP6_ERR_HDR_LEN, IDEMIP_IP6_NH_UDP, g_local_ip6,
                                   g_remote_ip6, IDEMIP_UDP_HDR_LEN);
        (void)build_udp(g_frame, q, 4000u, 4001u, 0u);
        seal_icmp6(g_frame, msg, msg_len, g_remote_ip6, g_local_ip6);
        input(work_a, msg + msg_len, 0u, IDEMIP_DISPATCH_DESC_NONE);

        TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(rows[r].id), rows[r].name);
        TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP6_IN_MSGS));
        TEST_ASSERT_EQUAL_UINT32(0u, ctr(IDEMIP_STAT_ICMP6_IN_ERRORS));
    }
}

// RFC 2466 counts one Code as well as its Type. ipv6IfIcmpInAdminProhibs is "the number of ICMP
// destination unreachable/communication administratively prohibited messages received", RFC 4443
// sec 3.1's Code 1 - and such a message is a Destination Unreachable, so it is counted in both.
void test_a_prohibited_destination_unreachable_counts_under_both_its_counters(void)
{
    const size_t quoted = (size_t)IDEMIP_IPV6_HDR_LEN + (size_t)IDEMIP_UDP_HDR_LEN;
    const size_t msg_len = (size_t)IDEMIP_ICMP6_ERR_HDR_LEN + quoted;

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, g_remote_ip6, g_local_ip6,
                                 msg_len);
    g_frame[msg + IDEMIP_ICMP6_OFF_CODE] = IDEMIP_ICMP6_DU_PROHIBITED;
    size_t q = build_ip6(g_frame, msg + IDEMIP_ICMP6_ERR_HDR_LEN, IDEMIP_IP6_NH_UDP, g_local_ip6, g_remote_ip6,
                         IDEMIP_UDP_HDR_LEN);
    (void)build_udp(g_frame, q, 4000u, 4001u, 0u);
    seal_icmp6(g_frame, msg, msg_len, g_remote_ip6, g_local_ip6);
    input(work_a, msg + msg_len, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP6_IN_DEST_UNREACHS),
                                     "a Code 1 is still a Destination Unreachable");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP6_IN_ADMIN_PROHIBS),
                                     "ipv6IfIcmpInAdminProhibs counted nothing");
}

// The same message at Code 0 is a Destination Unreachable and nothing more, so the Code is read and
// not assumed.
void test_a_destination_unreachable_at_another_code_is_not_an_admin_prohibition(void)
{
    const size_t quoted = (size_t)IDEMIP_IPV6_HDR_LEN + (size_t)IDEMIP_UDP_HDR_LEN;
    const size_t msg_len = (size_t)IDEMIP_ICMP6_ERR_HDR_LEN + quoted;

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, g_remote_ip6, g_local_ip6,
                                 msg_len);
    g_frame[msg + IDEMIP_ICMP6_OFF_CODE] = IDEMIP_ICMP6_DU_NO_ROUTE;
    size_t q = build_ip6(g_frame, msg + IDEMIP_ICMP6_ERR_HDR_LEN, IDEMIP_IP6_NH_UDP, g_local_ip6, g_remote_ip6,
                         IDEMIP_UDP_HDR_LEN);
    (void)build_udp(g_frame, q, 4000u, 4001u, 0u);
    seal_icmp6(g_frame, msg, msg_len, g_remote_ip6, g_local_ip6);
    input(work_a, msg + msg_len, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP6_IN_DEST_UNREACHS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_ICMP6_IN_ADMIN_PROHIBS),
                                     "a Code 0 is not an administrative prohibition");
}

// RFC 4443 sec 2.3: the checksum "MUST be verified" before the message is processed. icmp6_in keeps
// this for the types it answers, and these do not go through it.
void test_a_neighbor_solicitation_with_a_bad_checksum_is_discarded(void)
{
    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    idemip_ip6_addr_solicited(solicited, g_local_ip6);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT, g_remote_ip6, solicited,
                                 IDEMIP_ICMP6_NS_HDR_LEN);
    memcpy(g_frame + msg + IDEMIP_ICMP6_OFF_NS_TARGET, g_local_ip6, IDEMIP_IP6_ADDR_LEN);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_NS_HDR_LEN, g_remote_ip6, solicited);
    g_frame[msg + IDEMIP_ICMP6_OFF_CKSUM] = (uint8_t)(g_frame[msg + IDEMIP_ICMP6_OFF_CKSUM] ^ 0xFFu);
    input(work_a, msg + IDEMIP_ICMP6_NS_HDR_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP6_IN_ERRORS));
}

// RFC 4861 sec 4.3 ends a Neighbor Solicitation's fixed part at its Target Address, and sec 7.1.1
// refuses one shorter than that. A message cut before the field the caller reads must not be handed
// on as though the field were there.
void test_a_neighbor_solicitation_without_its_target_address_is_discarded(void)
{
    size_t len = (size_t)IDEMIP_ICMP6_OFF_NS_TARGET;
    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    idemip_ip6_addr_solicited(solicited, g_local_ip6);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg =
        build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT, g_remote_ip6, solicited, len);
    seal_icmp6(g_frame, msg, len, g_remote_ip6, solicited);
    input(work_a, msg + len, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
    // RFC 2466 ipv6IfIcmpInErrors: "determined as having ICMP-specific errors (bad ICMP checksums,
    // bad length, etc.)", and ipv6IfIcmpInMsgs "includes all those counted by ipv6IfIcmpInErrors".
    // This message never reaches icmp6_in, dispatch holding the per-type length itself, and is a bad
    // length either way.
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP6_IN_MSGS));
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP6_IN_ERRORS));
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_IN_DISCARDS));
}

// The same rule on the path that does reach icmp6_in: an Echo Request stopping before its Sequence
// Number, its checksum holding, so nothing about the checksum tells it from sec 2.4 (b)'s unknown
// informational type, which is discarded silently and is no error.
void test_an_icmpv6_message_too_short_for_its_type_is_an_error(void)
{
    const size_t len = (size_t)IDEMIP_ICMP6_ECHO_HDR_LEN - 2u;
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, g_remote_ip6, g_local_ip6, len);
    seal_icmp6(g_frame, msg, len, g_remote_ip6, g_local_ip6);
    input(work_a, msg + len, 0u, IDEMIP_DISPATCH_DESC_NONE);

    const Icmp6InIo *ic = IDEMIP_ICMP6_IN_IO(icmp6_in_mem);
    TEST_ASSERT_TRUE_MESSAGE(ic->cksum_ok, "this case is about a bad length, so its checksum must hold");
    TEST_ASSERT_TRUE(ic->bad_len);
    TEST_ASSERT_TRUE((ic->act & IDEMIP_ICMP6_IN_ACT_DISCARD) != 0u);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_ICMP6_IN_MSGS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_ICMP6_IN_ERRORS),
                                     "RFC 2466 names bad length an ICMP-specific error");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop);
}

// RFC 4861 sec 7.1.1, and the same line in sec 6.1.1, sec 6.1.2, sec 7.1.2 and sec 8.1: a node MUST
// silently discard a message whose "IP Hop Limit field has a value of 255, i.e., the packet could not
// possibly have been forwarded by a router" does not hold. sec 11.2 is why: "The protocol reduces the
// exposure to the above threats in the absence of authentication by ignoring ND packets received from
// off-link senders ... Because routers decrement the Hop Limit on all packets they forward, received
// packets containing a Hop Limit of 255 must have originated from a neighbor." It is the whole of ND's
// security model, and a forged Advertisement from off-link is what it stops.
void test_a_neighbor_solicitation_from_off_link_is_discarded(void)
{
    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    idemip_ip6_addr_solicited(solicited, g_local_ip6);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t ip = off;
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT, g_remote_ip6, solicited,
                                 IDEMIP_ICMP6_NS_HDR_LEN);
    memcpy(g_frame + msg + IDEMIP_ICMP6_OFF_NS_TARGET, g_local_ip6, IDEMIP_IP6_ADDR_LEN);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_NS_HDR_LEN, g_remote_ip6, solicited);
    // A router forwarded it, so it is not a neighbor's. The sec 2.3 checksum covers no Hop Limit, so
    // the message is otherwise exactly the one the valid case sends.
    idemip_ip6_set_hop_limit(g_frame + ip, 254u);
    input(work_a, msg + IDEMIP_ICMP6_NS_HDR_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u,
                             "an off-link Neighbor Solicitation reached the module that answers it");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_DISPATCH_IO(work_a)->drop);
}

// The same line, on the message that would install a default router, and on the one that would
// redirect traffic. sec 6.1.2 and sec 8.1 each state it in their own list.
void test_a_router_advertisement_from_off_link_is_discarded(void)
{
    static const uint8_t all_nodes[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t ip = off;
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_ROUTER_ADVERT, g_remote_ip6, all_nodes,
                                 IDEMIP_ICMP6_RA_HDR_LEN);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_RA_HDR_LEN, g_remote_ip6, all_nodes);
    idemip_ip6_set_hop_limit(g_frame + ip, 64u);
    input(work_a, msg + IDEMIP_ICMP6_RA_HDR_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u,
                             "an off-link Router Advertisement reached the module that installs a router");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_HEADER, IDEMIP_DISPATCH_IO(work_a)->drop);
}

// Every one of the five lists also states "ICMP Code is 0", and every one of the five types is a
// message whose Code the RFC never assigns a meaning.
void test_a_neighbor_solicitation_with_a_nonzero_code_is_discarded(void)
{
    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    idemip_ip6_addr_solicited(solicited, g_local_ip6);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT, g_remote_ip6, solicited,
                                 IDEMIP_ICMP6_NS_HDR_LEN);
    memcpy(g_frame + msg + IDEMIP_ICMP6_OFF_NS_TARGET, g_local_ip6, IDEMIP_IP6_ADDR_LEN);
    g_frame[msg + IDEMIP_ICMP6_OFF_CODE] = 1u;
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_NS_HDR_LEN, g_remote_ip6, solicited);
    input(work_a, msg + IDEMIP_ICMP6_NS_HDR_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
}

// RFC 4861 sec 4.6: "Nodes MUST silently discard an ND packet that contains an option with length
// zero." A zero Length also never advances an option walk, so this is what stops one.
void test_an_nd_option_of_length_zero_discards_the_packet(void)
{
    size_t len = (size_t)IDEMIP_ICMP6_NS_HDR_LEN + 8u;
    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    idemip_ip6_addr_solicited(solicited, g_local_ip6);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg =
        build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT, g_remote_ip6, solicited, len);
    memcpy(g_frame + msg + IDEMIP_ICMP6_OFF_NS_TARGET, g_local_ip6, IDEMIP_IP6_ADDR_LEN);
    uint8_t *o = g_frame + msg + IDEMIP_ICMP6_NS_HDR_LEN;
    o[IDEMIP_ICMP6_ND_OPT_OFF_TYPE] = IDEMIP_ICMP6_ND_OPT_SLLA;
    o[IDEMIP_ICMP6_ND_OPT_OFF_LEN] = 0u;
    seal_icmp6(g_frame, msg, len, g_remote_ip6, solicited);
    input(work_a, msg + len, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
}

// RFC 4291 sec 2.8: "A host is required to recognize the following addresses as identifying itself:
// ... The All-Nodes multicast addresses defined in Section 2.7.1." sec 2.7.1 defines two,
// FF01:0:0:0:0:0:0:1 and FF02:0:0:0:0:0:0:1. A Router Advertisement is addressed to the link-scope
// one, so a node that does not recognize it never sees a router.
void test_the_all_nodes_address_identifies_this_host(void)
{
    static const uint8_t all_nodes[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg =
        build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_ROUTER_ADVERT, g_remote_ip6, all_nodes,
                        IDEMIP_ICMP6_RA_HDR_LEN);
    idemip_wr16(g_frame + msg + IDEMIP_ICMP6_OFF_RA_LIFETIME, 1800u);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_RA_HDR_LEN, g_remote_ip6, all_nodes);
    input(work_a, msg + IDEMIP_ICMP6_RA_HDR_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_FORWARD) == 0u,
                             "an address sec 2.8 requires this host to recognize is not someone else's");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_ND, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
}

// The interface-local one sec 2.7.1 defines beside it, which sec 2.8 names in the same line.
void test_the_interface_local_all_nodes_address_identifies_this_host(void)
{
    static const uint8_t all_nodes[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_MLD_QUERY, g_remote_ip6, all_nodes,
                                 IDEMIP_ICMP6_MLD_MSG_LEN);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_MLD_MSG_LEN, g_remote_ip6, all_nodes);
    input(work_a, msg + IDEMIP_ICMP6_MLD_MSG_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_FORWARD) == 0u);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
}

// A multicast address the node did not join and sec 2.8 does not require is still not this host's.
void test_a_multicast_group_this_node_never_joined_is_not_local(void)
{
    static const uint8_t other[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09};

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_MLD_QUERY, g_remote_ip6, other,
                                 IDEMIP_ICMP6_MLD_MSG_LEN);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_MLD_MSG_LEN, g_remote_ip6, other);
    input(work_a, msg + IDEMIP_ICMP6_MLD_MSG_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    // RFC 2465 ipv6IfStatsInAddrErrors: "The number of input datagrams discarded because the IPv6
    // address in their IPv6 header's destination field was not a valid address to be received at
    // this entity ... For entities which are not IPv6 routers and therefore do not forward
    // datagrams, this counter includes datagrams discarded because the destination address was not
    // a local address." A group the node never joined is that, and the IPv4 twin,
    // test_a_group_we_never_joined_is_an_address_error, already reads this way.
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_ADDRESS, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_IN_ADDR_ERRORS));
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_FORWARD) == 0u,
                             "a multicast group this node never joined is not a forwarding candidate");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
}

// A non-local UNICAST destination is the other outcome and stays what it was: RFC 2465's sentence is
// about an address "not a valid address to be received at this entity", and a unicast address of
// some other node is a valid address, elsewhere. The IPv4 twin forwards it the same way.
void test_a_unicast_address_that_is_not_ours_is_still_forwarded(void)
{
    static const uint8_t elsewhere[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0,    0,
                                                            0,    0,    0,    0,    0, 0, 0x77, 0x77};

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, g_remote_ip6, elsewhere,
                                 IDEMIP_ICMP6_ECHO_HDR_LEN);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_ECHO_HDR_LEN, g_remote_ip6, elsewhere);
    input(work_a, msg + IDEMIP_ICMP6_ECHO_HDR_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_FORWARD) != 0u);
    TEST_ASSERT_EQUAL_UINT32(0u, ctr(IDEMIP_STAT_IP6_IN_ADDR_ERRORS));
}

// The positive twin, and the only thing that makes the negative one mean anything: RFC 4291 sec 2.8
// puts "All other Multicast addresses of groups to which the node belongs" on the list a host must
// recognize as its own, and belonging is what Mld6 records. The group table is the one thing that
// tells this destination from the address above it.
void test_a_multicast_group_this_node_joined_is_local(void)
{
    static const uint8_t joined[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09};

    Mld6Io *ml = IDEMIP_MLD6_IO(mld6_mem);
    ml->group_args.group = joined;
    ml->group_args.netif = 0u;
    Mld6.join(mld6_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ml->status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_MLD6_DELAYING_LISTENER, ml->state,
                                  "RFC 2710 sec 3: a join starts the report delay timer");

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_MLD_QUERY, g_remote_ip6, joined,
                                 IDEMIP_ICMP6_MLD_MSG_LEN);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_MLD_MSG_LEN, g_remote_ip6, joined);
    input(work_a, msg + IDEMIP_ICMP6_MLD_MSG_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u,
                             "a group the node joined was not recognized as its own");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_FORWARD) == 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_GROUP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);

    // Leaving takes it back off the list, and the same frame is forwarded again.
    ml->group_args.group = joined;
    ml->group_args.netif = 0u;
    Mld6.leave(mld6_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ml->status);
    ml->group_args.group = joined;
    ml->group_args.netif = 0u;
    Mld6.find(mld6_mem);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, ml->status, "a left group is still on the list");

    // The same frame, now addressed to a group the node no longer belongs to.
    input(work_a, msg + IDEMIP_ICMP6_MLD_MSG_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_IP_ADDRESS, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_IN_ADDR_ERRORS));
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
}

// The same walk, over an option whose Length reaches past the octets the message carries.
void test_an_nd_option_running_past_the_message_discards_the_packet(void)
{
    size_t len = (size_t)IDEMIP_ICMP6_NS_HDR_LEN + 8u;
    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    idemip_ip6_addr_solicited(solicited, g_local_ip6);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg =
        build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT, g_remote_ip6, solicited, len);
    memcpy(g_frame + msg + IDEMIP_ICMP6_OFF_NS_TARGET, g_local_ip6, IDEMIP_IP6_ADDR_LEN);
    uint8_t *o = g_frame + msg + IDEMIP_ICMP6_NS_HDR_LEN;
    o[IDEMIP_ICMP6_ND_OPT_OFF_TYPE] = IDEMIP_ICMP6_ND_OPT_SLLA;
    o[IDEMIP_ICMP6_ND_OPT_OFF_LEN] = 2u; // 16 octets, and 8 arrived
    seal_icmp6(g_frame, msg, len, g_remote_ip6, solicited);
    input(work_a, msg + len, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
}

// --- RFC 8200 sec 4.5 reassembly ---------------------------------------------
// test_dispatch bound the ip6_reass borrow and no case ever fed it a fragment, which is the shape
// that hid the missing IGMP checksum. Retention is a pin, so what these check is the descriptor
// contract as much as the reassembly: a fragment the reassembler keeps must leave ACT_PINNED set,
// and one it refuses must leave it clear or the caller returns a buffer that is still being read.

// One fragment: an IPv6 header whose Next Header is 44, the eight-octet Fragment header, then this
// fragment's part of the Fragmentable Part.
typedef struct
{
    uint8_t *f;
    size_t off;
    const uint8_t *src;
    const uint8_t *dst;
    uint8_t next_hdr;
    uint16_t frag_off;
    idemip_bool more;
    uint32_t ident;
    size_t data_len;
} BuildIp6FragmentArgs;

static size_t build_ip6_fragment_ctx(const BuildIp6FragmentArgs *args)
{
    // The operand block is read-only, so where the flat form advanced its own `off` parameter this
    // walks a local from it.
    const size_t off =
        build_ip6(args->f, args->off, IDEMIP_IP6_NH_FRAGMENT, args->src, args->dst,
                  (size_t)IDEMIP_IP6_FRAG_HDR_LEN + args->data_len);
    idemip_ip6_frag_build(args->f + off, args->next_hdr, args->frag_off, args->more, args->ident);
    memset(args->f + off + IDEMIP_IP6_FRAG_HDR_LEN, 0x5C, args->data_len);
    return off + IDEMIP_IP6_FRAG_HDR_LEN + args->data_len;
}

#define build_ip6_fragment(...) IDEMIP_CALL(build_ip6_fragment_ctx, BuildIp6FragmentArgs, __VA_ARGS__)

#define FRAG_DESC 3u
#define FRAG_IDENT 0xA5A50001u

// A fragment the reassembler kept is a frame the caller must not hand back to the ring.
void test_an_ipv6_fragment_the_reassembler_kept_pins_its_descriptor(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t end = build_ip6_fragment(g_frame, off, g_remote_ip6, g_local_ip6, IDEMIP_IP6_NH_UDP, 0u, IDEMIP_TRUE,
                                    FRAG_IDENT, 8u);
    input(work_a, end, 0u, FRAG_DESC);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_PINNED) != 0u,
                             "a retained fragment must report the pin, or its buffer is recycled under it");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_REASSEMBLED) == 0u);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_REASM_REQDS));

    // The reassembler's own state, not just dispatch's report of it. The descriptor it recorded is
    // the handle, interface in the high octet, which is what lets the right ring take it back.
    Ip6ReassIo *re = IDEMIP_IP6_REASS_IO(ip6_reass_mem);
    re->frag_args.datagram = IDEMIP_DISPATCH_IO(work_a)->datagram;
    re->frag_args.index = 0u;
    Ip6Reass.frag_at(ip6_reass_mem);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, re->status, "the datagram dispatch named holds no fragment");
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_DISPATCH_DESC_HANDLE(0u, FRAG_DESC), re->frag_desc);
    TEST_ASSERT_EQUAL_UINT16(0u, re->frag_offset);
    TEST_ASSERT_EQUAL_UINT16(8u, re->frag_len);
}

// "0 = last fragment": the one that fixes where the datagram ends completes it.
void test_the_last_ipv6_fragment_completes_the_datagram(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t end = build_ip6_fragment(g_frame, off, g_remote_ip6, g_local_ip6, IDEMIP_IP6_NH_UDP, 0u, IDEMIP_TRUE,
                                    FRAG_IDENT, 8u);
    input(work_a, end, 0u, FRAG_DESC);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_REASSEMBLED) == 0u);

    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    end = build_ip6_fragment(g_frame, off, g_remote_ip6, g_local_ip6, IDEMIP_IP6_NH_UDP, 8u, IDEMIP_FALSE,
                             FRAG_IDENT, 8u);
    input(work_a, end, 0u, FRAG_DESC + 1u);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_REASSEMBLED) != 0u,
                             "the fragment carrying M clear at the end of the hole completes the datagram");
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_PINNED) != 0u);
    TEST_ASSERT_EQUAL_UINT32(2u, ctr(IDEMIP_STAT_IP6_REASM_REQDS));
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_REASM_OKS));
}

// The IPv6 twin of test_a_fragment_with_no_descriptor_is_discarded. A frame lying in no descriptor
// cannot be retained, so the fragment goes rather than a pointer into a recycled buffer being kept.
void test_an_ipv6_fragment_with_no_descriptor_is_discarded(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t end = build_ip6_fragment(g_frame, off, g_remote_ip6, g_local_ip6, IDEMIP_IP6_NH_UDP, 0u, IDEMIP_TRUE,
                                    FRAG_IDENT, 8u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NO_DESC, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_PINNED) == 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_REASM_REQDS));
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_IP6_REASM_FAILS));
    // RFC 2465 ipv6IfStatsInDiscards: "Note that this counter does not include any datagrams
    // discarded while awaiting re-assembly." This one was, so ipv6IfStatsReasmFails holds it alone.
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_IP6_IN_DISCARDS),
                                     "ipv6IfStatsInDiscards excludes datagrams discarded awaiting re-assembly");
}

// The IPv6 twin of test_a_fragment_the_reassembler_refuses_counts_a_reassembly_failure. RFC 8200
// sec 4.5 ends a datagram at the fragment carrying M clear, so one reaching past that end is the
// same contradiction, and RFC 2465 puts the refusal in ipv6IfStatsReasmFails, not InDiscards.
void test_an_ipv6_fragment_the_reassembler_refuses_counts_a_reassembly_failure(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t end = build_ip6_fragment(g_frame, off, g_remote_ip6, g_local_ip6, IDEMIP_IP6_NH_UDP, 8u, IDEMIP_FALSE,
                                    FRAG_IDENT, 8u);
    input(work_a, end, 0u, FRAG_DESC);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NONE, IDEMIP_DISPATCH_IO(work_a)->drop);

    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    end = build_ip6_fragment(g_frame, off, g_remote_ip6, g_local_ip6, IDEMIP_IP6_NH_UDP, 16u, IDEMIP_TRUE,
                             FRAG_IDENT, 8u);
    input(work_a, end, 0u, FRAG_DESC + 1u);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_REASS, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_PINNED) == 0u);
    TEST_ASSERT_EQUAL_UINT32(2u, ctr(IDEMIP_STAT_IP6_REASM_REQDS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_IP6_REASM_FAILS),
                                     "a refusal is a failure the re-assembly algorithm detected");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, ctr(IDEMIP_STAT_IP6_IN_DISCARDS),
                                     "ipv6IfStatsInDiscards excludes datagrams discarded awaiting re-assembly");
}

#endif // IDEMIP_ENABLE_IPV6

// --- TCP, the three joins ----------------------------------------------------

#if IDEMIP_ENABLE_TCP

static uint16_t listen_on(uint16_t port)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    uint8_t local[IDEMIP_TCP_PCB_ADDR_BYTES];
    memset(local, 0, sizeof local);
    idemip_wr32(local, LOCAL_IP4);
    tp->listen_args.ip = local;
    tp->listen_args.port = port;
    tp->listen_args.zone = 0u;
    tp->listen_args.netif = 0u;
    tp->listen_args.backlog = 2u;
    tp->listen_args.ip_version = 4u;
    TcpPcb.listen(tcp_pcb_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    return tp->index;
}

static size_t build_tcp4(uint8_t *f, uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags,
                         size_t data_len)
{
    size_t off = build_eth(f, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(f, off, IDEMIP_IP4_PROTO_TCP, REMOTE_IP4, LOCAL_IP4, IDEMIP_TCP_HDR_LEN + data_len, 0u);
    uint8_t *seg = f + off;
    memset(seg, 0, IDEMIP_TCP_HDR_LEN);
    idemip_wr16(seg + IDEMIP_TCP_OFF_SRC_PORT, sport);
    idemip_wr16(seg + IDEMIP_TCP_OFF_DST_PORT, dport);
    idemip_wr32(seg + IDEMIP_TCP_OFF_SEQ, seq);
    idemip_wr32(seg + IDEMIP_TCP_OFF_ACK, ack);
    idemip_wr16(seg + IDEMIP_TCP_OFF_OFFS_FLAGS,
                (uint16_t)(((uint16_t)IDEMIP_TCP_DOFF_MIN << IDEMIP_TCP_DOFF_SHIFT) | flags));
    idemip_wr16(seg + IDEMIP_TCP_OFF_WINDOW, (uint16_t)IDEMIP_TCP_WND);
    memset(seg + IDEMIP_TCP_HDR_LEN, 0x5A, data_len);
    idemip_wr16(seg + IDEMIP_TCP_OFF_CKSUM, 0u);
    idemip_wr16(seg + IDEMIP_TCP_OFF_CKSUM,
                idemip_tcp_cksum_compute(seg, IDEMIP_TCP_HDR_LEN + data_len, REMOTE_IP4, LOCAL_IP4));
    idemip_ip4_set_total_len(f + ip, (uint16_t)(IDEMIP_IP4_HDR_BYTES(IDEMIP_IP4_IHL_MIN) + IDEMIP_TCP_HDR_LEN + data_len));
    idemip_ip4_recksum(f + ip);
    return off + IDEMIP_TCP_HDR_LEN + data_len;
}

// RFC 9293 sec 3.10.7.2 LISTEN STATE, first check: "An incoming RST segment could not be valid since
// it could not have been sent in response to anything sent by this incarnation of the connection. An
// incoming RST should be ignored. Return." Nothing is created for it, so it cannot shadow the
// listener for that peer afterwards.
void test_a_bare_rst_at_a_listener_creates_no_tcb(void)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    listen_on(5001u);

    size_t end = build_tcp4(g_frame, 5000u, 5001u, 100u, 0u, (uint8_t)IDEMIP_TCP_RST, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_PCB_NONE, IDEMIP_DISPATCH_IO(work_a)->pcb_kind,
                                  "a RST at a listener must not take a TCB");

    // The four-tuple is still free, so a genuine SYN from the same peer reaches SYN-RECEIVED.
    end = build_tcp4(g_frame, 5000u, 5001u, 100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_PCB_TCP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind,
                                  "the RST left a phantom TCB shadowing the listener");
    tp->pcb_args.index = IDEMIP_DISPATCH_IO(work_a)->pcb;
    TcpPcb.load(tcp_pcb_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_SYN_RECEIVED, tp->state);
}

// The backlog the passive OPEN named, applied where a SYN would take a connection. listen_on asks
// for two, so the third SYN from a fresh peer gets none: no TCB, no tcpPassiveOpens, and no reset -
// sec 3.10.7.4 resets a segment that belongs to no connection, and this one belongs to a listener
// with no room for it right now, so the peer's own retransmission is what recovers it. The TCB
// opened before the refusal goes back, which the opens after it prove: five in the build, two held,
// three left. One leaked and there would be two.
void test_a_syn_past_the_listeners_backlog_takes_no_connection(void)
{
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    listen_on(5001u);

    for (uint16_t port = 5000u; port < 5002u; port++)
    {
        size_t end = build_tcp4(g_frame, port, 5001u, 100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 0u);
        input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_PCB_TCP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind,
                                      "a SYN within the backlog was refused");
    }

    const uint32_t opens = ctr(IDEMIP_STAT_TCP_PASSIVE_OPENS);
    const uint32_t rsts = ctr(IDEMIP_STAT_TCP_OUT_RSTS);
    size_t end = build_tcp4(g_frame, 5002u, 5001u, 100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_PCB_NONE, IDEMIP_DISPATCH_IO(work_a)->pcb_kind,
                                  "a third SYN went past a backlog of two");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_NO_PCB, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_FALSE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_TCP) != 0u);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(opens, ctr(IDEMIP_STAT_TCP_PASSIVE_OPENS),
                                     "nothing transitioned to SYN-RECEIVED, so nothing is a passive open");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(rsts, ctr(IDEMIP_STAT_TCP_OUT_RSTS),
                                     "a listener with no room reset a peer it should have left to retransmit");

    uint16_t free_left = 0u;
    for (;;)
    {
        tp->open_args.ip_version = 4u;
        TcpPcb.open(tcp_pcb_mem);
        if (tp->status != IDEMIP_OK)
        {
            break;
        }
        free_left++;
    }
    TEST_ASSERT_EQUAL_UINT16_MESSAGE((uint16_t)(IDEMIP_TCP_PCBS - 2u), free_left,
                                     "the connection the refused SYN opened was never given back");
}

// The second check: an ACK-bearing segment at a listener draws "<SEQ=SEG.ACK><CTL=RST>" and returns,
// creating nothing. RFC 1213 sec 6.5 tcpPassiveOpens counts "the number of times TCP connections have
// made a direct transition to the SYN-RCVD state from the LISTEN state", which this is not, and
// tcpOutRsts counts "The number of TCP segments sent containing the RST flag", which this is.
void test_a_bare_ack_at_a_listener_resets_without_a_passive_open(void)
{
    listen_on(5001u);
    const uint32_t opens = ctr(IDEMIP_STAT_TCP_PASSIVE_OPENS);

    size_t end = build_tcp4(g_frame, 5000u, 5001u, 100u, 200u, (uint8_t)IDEMIP_TCP_ACK, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_NONE, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->tcp_act & IDEMIP_TCP_IN_ACT_RST) != 0u,
                             "the second check forms a reset for an ACK-bearing segment");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(opens, ctr(IDEMIP_STAT_TCP_PASSIVE_OPENS),
                                     "tcpPassiveOpens counts only the LISTEN to SYN-RCVD transition");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_TCP_OUT_RSTS), "the reset it sent is counted");
}

// The SYN is the one segment the section creates a TCB for, and the one tcpPassiveOpens counts.
void test_a_syn_at_a_listener_is_the_one_passive_open(void)
{
    listen_on(5001u);
    size_t end = build_tcp4(g_frame, 5000u, 5001u, 100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_TCP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_TCP_PASSIVE_OPENS));
}

// RFC 1213 sec 6.5 tcpOutRsts: "The number of TCP segments sent containing the RST flag." RFC 9293
// sec 3.10.7.1: "An incoming segment not containing a RST causes a RST to be sent in response."
void test_a_reset_sent_for_a_segment_with_no_tcb_is_counted(void)
{
    size_t end = build_tcp4(g_frame, 5000u, 5999u, 100u, 0u, (uint8_t)IDEMIP_TCP_SYN, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->tcp_act & IDEMIP_TCP_IN_ACT_RST) != 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_TCP_OUT_RSTS));
}

// RFC 1213 sec 6.5 tcpInSegs: "The total number of segments received, including those received in
// error." A payload shorter than the fixed header is one of those.
void test_tcp_in_segs_counts_a_segment_shorter_than_the_header(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_TCP, REMOTE_IP4, LOCAL_IP4, 12u, 0u);
    memset(g_frame + off, 0, 12u);
    input(work_a, off + 12u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_TCP_IN_ERRS));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1u, ctr(IDEMIP_STAT_TCP_IN_SEGS),
                                     "tcpInErrs cannot exceed the segments tcpInSegs says arrived");
}

// RFC 9293 sec 3.10.7.1 CLOSED STATE: "If the state is CLOSED (i.e., TCB does not exist)", the
// segment is answered with a reset and reaches no pcb.
void test_a_segment_with_no_tcb_reaches_the_closed_state(void)
{
    size_t end = build_tcp4(g_frame, 5000u, 5001u, 100u, 0u, IDEMIP_TCP_SYN, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_TCP) != 0u);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->tcp_act & IDEMIP_TCP_IN_ACT_RST) != 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_NONE, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_TCP_IN_SEGS));

    // The segment the unit parsed, and the reset it built from it. RFC 9293 sec 3.5.2 group 2: with
    // no ACK field "the reset has sequence number zero and the ACK field is set to the sum of the
    // sequence number and segment length of the incoming segment", and sec 3.4 counts SEG.LEN
    // "counting SYN and FIN", so a bare SYN at 100 is answered at 101.
    const TcpInIo *ti = IDEMIP_TCP_IN_IO(tcp_in_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ti->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_TCP_SYN, ti->seg.flags);
    TEST_ASSERT_EQUAL_UINT32(100u, ti->seg.seq);
    TEST_ASSERT_EQUAL_UINT32(1u, ti->seg.len);
    TEST_ASSERT_EQUAL_UINT16(0u, ti->seg.data_len);
    TEST_ASSERT_TRUE((ti->res.act & IDEMIP_TCP_IN_ACT_RST) != 0u);
    TEST_ASSERT_EQUAL_UINT32(0u, ti->reply.seq);
    TEST_ASSERT_EQUAL_UINT32(101u, ti->reply.ack);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)(IDEMIP_TCP_RST | IDEMIP_TCP_ACK), ti->reply.flags);
}

// RFC 9293 sec 3.10.7.2 LISTEN STATE: a SYN to a listener creates the connection, which sec 3.5
// (MUST-11) records the listener on.
void test_a_syn_to_a_listener_creates_the_connection(void)
{
    uint16_t listener = listen_on(5001u);
    size_t end = build_tcp4(g_frame, 5000u, 5001u, 100u, 0u, IDEMIP_TCP_SYN, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_TCP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    uint16_t pcb = IDEMIP_DISPATCH_IO(work_a)->pcb;
    TEST_ASSERT_NOT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, pcb);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_TCP_PASSIVE_OPENS));

    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_SYN_RECEIVED, tp->state);
    TEST_ASSERT_EQUAL_UINT16(listener, tp->info.listener);
}

// The connection a listener created is the one the next segment of that four-tuple finds.
void test_the_second_segment_finds_the_connection(void)
{
    (void)listen_on(5001u);
    size_t end = build_tcp4(g_frame, 5000u, 5001u, 100u, 0u, IDEMIP_TCP_SYN, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    uint16_t pcb = IDEMIP_DISPATCH_IO(work_a)->pcb;

    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    uint32_t iss = tp->vars.iss;

    end = build_tcp4(g_frame, 5000u, 5001u, 101u, iss + 1u, IDEMIP_TCP_ACK, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_TCP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_EQUAL_UINT16(pcb, IDEMIP_DISPATCH_IO(work_a)->pcb);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_TCP_STATE_ESTABLISHED, tp->state);
}

// Brings one connection to ESTABLISHED and reports it, so the joins below start from a real TCB.
//
// RFC 9293 sec 3.3.1 has RCV.WND come from the receive buffer the user's OPEN supplied, and no entry
// in this tree invents one, so the suite sets it the way an application would. Left at zero, sec
// 3.10.7.4 Table 6 makes every segment carrying data unacceptable.
static uint16_t establish(void)
{
    (void)listen_on(5001u);
    size_t end = build_tcp4(g_frame, 5000u, 5001u, 100u, 0u, IDEMIP_TCP_SYN, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    uint16_t pcb = IDEMIP_DISPATCH_IO(work_a)->pcb;
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    tp->vars.rcv_wnd = IDEMIP_TCP_WND;
    tp->pcb_args.index = pcb;
    TcpPcb.store(tcp_pcb_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    uint32_t iss = tp->vars.iss;
    end = build_tcp4(g_frame, 5000u, 5001u, 101u, iss + 1u, IDEMIP_TCP_ACK, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    return pcb;
}

// JOIN 3, RFC 9293 sec 3.10.7.4 (MUST-58): the acknowledgment a segment earns is recorded rather than
// reported, so a batch of segments does not put one acknowledgment each on the wire.
void test_an_ordinary_acknowledgment_is_aggregated_and_not_reported(void)
{
    uint16_t pcb = establish();
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    uint32_t iss = tp->vars.iss;

    size_t end = build_tcp4(g_frame, 5000u, 5001u, 101u, iss + 1u, (uint8_t)(IDEMIP_TCP_ACK | IDEMIP_TCP_PSH), 4u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    const DispatchIo *io = IDEMIP_DISPATCH_IO(work_a);
    TEST_ASSERT_TRUE((io->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_TRUE((io->act & IDEMIP_DISPATCH_ACT_ACK_OWED) != 0u);
    TEST_ASSERT_TRUE_MESSAGE((io->tcp_act & IDEMIP_TCP_IN_ACT_ACK) == 0u,
                             "an ordinary acknowledgment was reported per segment rather than aggregated");
}

// (MUST-59) "it MUST process them all before sending any ACK segments": two segments earn one
// acknowledgment, and that one carries the RCV.NXT the second left behind.
void test_two_segments_earn_one_acknowledgment(void)
{
    uint16_t pcb = establish();
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    uint32_t iss = tp->vars.iss;

    size_t end = build_tcp4(g_frame, 5000u, 5001u, 101u, iss + 1u, IDEMIP_TCP_ACK, 4u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    end = build_tcp4(g_frame, 5000u, 5001u, 105u, iss + 1u, IDEMIP_TCP_ACK, 4u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    uint32_t rcv_nxt = tp->vars.rcv_nxt;
    TEST_ASSERT_EQUAL_UINT32(109u, rcv_nxt);

    Dispatch.tcp_ack(work_a);
    const DispatchIo *io = IDEMIP_DISPATCH_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT16(pcb, io->pcb);
    TEST_ASSERT_EQUAL_UINT32(rcv_nxt, io->reply.ack);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)IDEMIP_TCP_ACK, io->reply.flags);

    // One per connection per batch: the second call has nothing left to take.
    Dispatch.tcp_ack(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, io->status);
}

// Nothing owed is BUSY, not ERR: a segment on a later tick makes the same call succeed.
void test_an_ack_flush_with_nothing_owed_is_busy(void)
{
    Dispatch.tcp_ack(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DISPATCH_IO(work_a)->status);
}

// JOIN 1, RFC 9293 sec 3.10.7.4 (SHLD-31): "Segments with higher beginning sequence numbers SHOULD be
// held for later processing." Held is pinned and queued, so a segment ahead of RCV.NXT reaches the
// out-of-order queue instead of being dropped.
void test_a_segment_ahead_of_the_window_is_held(void)
{
    uint16_t pcb = establish();
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    uint32_t iss = tp->vars.iss;

    // Sequence 105 with RCV.NXT at 101 leaves a four-octet gap in front of it.
    size_t end = build_tcp4(g_frame, 5000u, 5001u, 105u, iss + 1u, IDEMIP_TCP_ACK, 4u);
    input(work_a, end, 0u, 3u);
    const DispatchIo *io = IDEMIP_DISPATCH_IO(work_a);
    TEST_ASSERT_TRUE_MESSAGE((io->tcp_act & IDEMIP_TCP_IN_ACT_HOLD) != 0u,
                             "a segment above RCV.NXT was not reported as one to hold");

    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    TEST_ASSERT_NOT_EQUAL_UINT16_MESSAGE(IDEMIP_TCP_PCB_NONE, tp->info.ooseq,
                                         "nothing joined tcp_in's hold to the out-of-order queue");
    tp->oos_args.index = tp->info.ooseq;
    TcpPcb.oos_load(tcp_pcb_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, tp->status);
    TEST_ASSERT_EQUAL_UINT32(105u, tp->oos.seq);
    TEST_ASSERT_EQUAL_UINT16(4u, tp->oos.len);
    TEST_ASSERT_EQUAL_UINT16(3u, tp->oos.desc);
}

// JOIN 2: nothing re-delivers a held segment until RCV.NXT reaches it, and BUSY is what says so.
void test_a_held_segment_waits_until_rcv_nxt_reaches_it(void)
{
    uint16_t pcb = establish();
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    uint32_t iss = tp->vars.iss;

    size_t end = build_tcp4(g_frame, 5000u, 5001u, 105u, iss + 1u, IDEMIP_TCP_ACK, 4u);
    input(work_a, end, 0u, 3u);

    IDEMIP_DISPATCH_IO(work_a)->tcp_args.pcb = pcb;
    Dispatch.tcp_deliver(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IDEMIP_DISPATCH_IO(work_a)->status,
                                  "a held segment was delivered while the gap in front of it was open");
}

// JOIN 2: once the gap is filled, the held segment is delivered and RCV.NXT advances over it.
void test_a_held_segment_is_redelivered_once_the_gap_is_filled(void)
{
    uint16_t pcb = establish();
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    uint32_t iss = tp->vars.iss;

    // The segment at 105 is held; the one at 101 fills the gap and takes RCV.NXT to 105.
    size_t end = build_tcp4(g_frame, 5000u, 5001u, 105u, iss + 1u, IDEMIP_TCP_ACK, 4u);
    input(work_a, end, 0u, 3u);
    end = build_tcp4(g_frame, 5000u, 5001u, 101u, iss + 1u, IDEMIP_TCP_ACK, 4u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    TEST_ASSERT_EQUAL_UINT32(105u, tp->vars.rcv_nxt);

    IDEMIP_DISPATCH_IO(work_a)->tcp_args.pcb = pcb;
    Dispatch.tcp_deliver(work_a);
    const DispatchIo *io = IDEMIP_DISPATCH_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_TRUE((io->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_UINT32(105u, io->text_seq);
    TEST_ASSERT_EQUAL_UINT16(4u, io->text_len);
    TEST_ASSERT_EQUAL_UINT16(3u, io->desc);

    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    TEST_ASSERT_EQUAL_UINT32(109u, tp->vars.rcv_nxt);
    TEST_ASSERT_EQUAL_UINT16(IDEMIP_TCP_PCB_NONE, tp->info.ooseq);

    // The queue is empty now, so the next call has nothing to re-deliver.
    IDEMIP_DISPATCH_IO(work_a)->tcp_args.pcb = pcb;
    Dispatch.tcp_deliver(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_DISPATCH_IO(work_a)->status);
}

// A re-delivery advances the window, so it owes the aggregate acknowledgment the same way an
// in-order segment does.
void test_a_redelivery_owes_the_aggregate_acknowledgment(void)
{
    uint16_t pcb = establish();
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    uint32_t iss = tp->vars.iss;

    size_t end = build_tcp4(g_frame, 5000u, 5001u, 105u, iss + 1u, IDEMIP_TCP_ACK, 4u);
    input(work_a, end, 0u, 3u);
    end = build_tcp4(g_frame, 5000u, 5001u, 101u, iss + 1u, IDEMIP_TCP_ACK, 4u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    // Take the acknowledgment the two arriving segments owed, so what is left is the re-delivery's.
    Dispatch.tcp_ack(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DISPATCH_IO(work_a)->status);

    IDEMIP_DISPATCH_IO(work_a)->tcp_args.pcb = pcb;
    Dispatch.tcp_deliver(work_a);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_ACK_OWED) != 0u);

    Dispatch.tcp_ack(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DISPATCH_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(109u, IDEMIP_DISPATCH_IO(work_a)->reply.ack);
}

void test_tcp_deliver_refuses_a_pcb_past_the_table(void)
{
    IDEMIP_DISPATCH_IO(work_a)->tcp_args.pcb = (uint16_t)IDEMIP_TCP_PCBS;
    Dispatch.tcp_deliver(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_DISPATCH_IO(work_a)->status);
}

// A segment shorter than the RFC 9293 sec 3.1 header is a malformed frame, and tcpInErrs counts it.
void test_a_short_tcp_segment_is_an_error(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_TCP, REMOTE_IP4, LOCAL_IP4, 12u, 0u);
    input(work_a, off + 12u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_TCP_IN_ERRS));
}

// RFC 5961 sec 4.2: a SYN arriving on an established connection makes the receiver "send an ACK
// (also referred to as challenge ACK)". That answer belongs to that one segment, so it is NOT the
// aggregate of RFC 9293 sec 3.10.7.4 MUST-58 and must reach the caller on the call that earned it.
void test_a_challenge_acknowledgment_is_not_aggregated(void)
{
    uint16_t pcb = establish();
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
    tp->pcb_args.index = pcb;
    TcpPcb.load(tcp_pcb_mem);
    uint32_t iss = tp->vars.iss;

    // Drain what the handshake owed, so what is left is this segment's own answer.
    Dispatch.tcp_ack(work_a);

    size_t end = build_tcp4(g_frame, 5000u, 5001u, 101u, iss + 1u, (uint8_t)(IDEMIP_TCP_SYN | IDEMIP_TCP_ACK), 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    const DispatchIo *io = IDEMIP_DISPATCH_IO(work_a);
    TEST_ASSERT_TRUE_MESSAGE((io->tcp_act & IDEMIP_TCP_IN_ACT_CHALLENGE) != 0u,
                             "RFC 5961 sec 4.2's challenge was not reported for a SYN in the window");
    TEST_ASSERT_TRUE_MESSAGE((io->tcp_act & IDEMIP_TCP_IN_ACT_ACK) != 0u,
                             "a challenge acknowledgment was aggregated away");
    TEST_ASSERT_TRUE((io->act & IDEMIP_DISPATCH_ACT_ACK_OWED) == 0u);
}

#endif // IDEMIP_ENABLE_TCP

#if IDEMIP_ENABLE_UDP

// RFC 3828 sec 3.1 puts a Checksum Coverage where RFC 768 puts a Length, so a protocol 136 datagram
// is checked over the octets that field names and the binding is matched on the coverage.
void test_a_udp_lite_datagram_reaches_a_lite_binding(void)
{
    UdpPcbIo *up = IDEMIP_UDP_PCB_IO(udp_mem);
    up->open_args.ip_version = 4u;
    up->open_args.lite = IDEMIP_TRUE;
    UdpPcb.open(udp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, up->status);
    uint16_t pcb = up->index;
    uint8_t local[4];
    idemip_wr32(local, LOCAL_IP4);
    up->bind_args.index = pcb;
    up->bind_args.ip = local;
    up->bind_args.port = 4001u;
    up->bind_args.zone = 0u;
    up->bind_args.netif = 0u;
    UdpPcb.bind(udp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, up->status);
    up->opt_args.index = pcb;
    up->opt_args.cksum_len_tx = (uint16_t)IDEMIP_UDPLITE_COV_MIN;
    up->opt_args.cksum_len_rx = (uint16_t)IDEMIP_UDPLITE_COV_MIN;
    up->opt_args.tos = 0u;
    up->opt_args.ttl = 64u;
    up->opt_args.mcast_ttl = 1u;
    up->opt_args.mcast_netif = 0u;
    up->opt_args.flags = 0u;
    UdpPcb.set_opts(udp_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, up->status);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, (uint8_t)IDEMIP_UDPLITE_PROTO, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN + 4u, 0u);
    memset(g_frame + off + IDEMIP_UDP_HDR_LEN, 0xC3, 4u);
    UdpLiteIo *ul = IDEMIP_UDPLITE_IO(udplite_mem);
    ul->build_args.dgram = g_frame + off;
    ul->build_args.src = g_frame + ip + IDEMIP_IP4_OFF_SRC;
    ul->build_args.dst = g_frame + ip + IDEMIP_IP4_OFF_DST;
    ul->build_args.ip_payload_len = (uint32_t)(IDEMIP_UDP_HDR_LEN + 4u);
    ul->build_args.src_port = 4000u;
    ul->build_args.dst_port = 4001u;
    ul->build_args.cov = (uint16_t)IDEMIP_UDPLITE_COV_MIN;
    ul->build_args.ip_version = 4u;
    UdpLite.build(udplite_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ul->status);

    input(work_a, off + IDEMIP_UDP_HDR_LEN + 4u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_UDP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_EQUAL_UINT16(pcb, IDEMIP_DISPATCH_IO(work_a)->pcb);
}

// RFC 3828 sec 3.1: "A UDP-Lite packet with a Checksum Coverage of 1 to 7 is illegal, and MUST be
// discarded by the receiver."
void test_a_udp_lite_datagram_with_an_illegal_coverage_is_discarded(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, (uint8_t)IDEMIP_UDPLITE_PROTO, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN + 4u, 0u);
    idemip_udp_build(g_frame + off, 4000u, 4001u, 4u); // a coverage of 4, which sec 3.1 forbids
    memset(g_frame + off + IDEMIP_UDP_HDR_LEN, 0xC3, 4u);
    input(work_a, off + IDEMIP_UDP_HDR_LEN + 4u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_UDP_IN_ERRORS));
    // A Coverage sec 3.1 bars is a fault in a length field, and that is what is reported.
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_SHORT, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "an illegal Coverage was not reported as a length fault");
}

// RFC 3828 sec 3.1: "Irrespective of the Checksum Coverage, the computed Checksum field MUST include
// a pseudo-header". A datagram whose sum does not come out is a checksum fault, and the RFC 768 arm
// beside this one already separates the two - a Length past the delivered octets is DROP_SHORT and a
// sum that fails is DROP_CKSUM. Both are udpInErrors, so the counter alone cannot tell them apart.
void test_a_udp_lite_datagram_with_a_bad_checksum_is_refused_as_a_checksum_fault(void)
{
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, (uint8_t)IDEMIP_UDPLITE_PROTO, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN + 4u, 0u);
    memset(g_frame + off + IDEMIP_UDP_HDR_LEN, 0xC3, 4u);

    UdpLiteIo *ul = IDEMIP_UDPLITE_IO(udplite_mem);
    ul->build_args.dgram = g_frame + off;
    ul->build_args.src = g_frame + ip + IDEMIP_IP4_OFF_SRC;
    ul->build_args.dst = g_frame + ip + IDEMIP_IP4_OFF_DST;
    ul->build_args.ip_payload_len = (uint32_t)(IDEMIP_UDP_HDR_LEN + 4u);
    ul->build_args.src_port = 4000u;
    ul->build_args.dst_port = 4001u;
    ul->build_args.cov = (uint16_t)IDEMIP_UDPLITE_COV_ALL; // the whole datagram, so the payload is covered
    ul->build_args.ip_version = 4u;
    UdpLite.build(udplite_mem);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, ul->status);

    // One covered octet turned over. The Coverage field is untouched and still legal, so the only
    // thing wrong with this datagram is its sum.
    g_frame[off + IDEMIP_UDP_HDR_LEN] ^= 0xFFu;

    input(work_a, off + IDEMIP_UDP_HDR_LEN + 4u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    TEST_ASSERT_TRUE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) == 0u);
    TEST_ASSERT_EQUAL_UINT32(1u, ctr(IDEMIP_STAT_UDP_IN_ERRORS));
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_CKSUM, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "a failed UDP-Lite sum was reported as a length fault");
}

#endif // IDEMIP_ENABLE_UDP

// --- the borrows a build did not bind ----------------------------------------

// dispatch.h: a path "that would have needed it reports IDEMIP_DISPATCH_DROP_UNBOUND rather than
// calling through a null pointer". Every unit is optional, a build selecting what it carries, so
// each of these branches is what a frame meets in a build that left one out. The contract was
// written down and raised at ten sites, and no case named it, so nothing distinguished a reported
// refusal from a null dereference that happened not to fault on the host.

// Everything bound but one, which is the shape of a build that does not carry that unit.
#define BIND_WITHOUT(w, field)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        bind_all(w);                                                                                                   \
        IDEMIP_DISPATCH_IO(w)->bind_args.field = NULL;                                                                 \
        Dispatch.bind(w);                                                                                              \
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_DISPATCH_IO(w)->status);                                               \
    } while (0)

#define ASSERT_UNBOUND(w, who)                                                                                         \
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_UNBOUND, IDEMIP_DISPATCH_IO(w)->drop,                           \
                                  "a frame reached " who " and it was never bound")

// stats is the one unit whose absence a frame cannot see. d_bump and d_if_bump return without
// writing and every path carries on, so the contract here is not DROP_UNBOUND but that the same
// datagram still reaches the same binding with nothing counted anywhere.
void test_a_frame_with_no_stats_borrow_is_still_delivered(void)
{
    uint16_t pcb = bind_udp4(4001u);
    BIND_WITHOUT(work_a, stats);
    if_untagged(work_a, 0u);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN + 4u, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 4u);
    seal_udp4(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_TRUE_MESSAGE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u,
                             "a build carrying no stats borrow stopped delivering");
    TEST_ASSERT_EQUAL_INT(IDEMIP_DISPATCH_PCB_UDP, IDEMIP_DISPATCH_IO(work_a)->pcb_kind);
    TEST_ASSERT_EQUAL_UINT16(pcb, IDEMIP_DISPATCH_IO(work_a)->pcb);
}

// netif is not read for a broadcast, a multicast or a loopback destination, which are answered before
// it, so the unicast case is the one that needs it: with no interface table there is no address to
// match and no route to find, and RFC 1213 ipInAddrErrors - "discarded because the IP address in
// their IP header's destination field was not a valid address to be received at this entity" - is
// what that is.
void test_a_unicast_destination_with_no_netif_borrow_is_an_address_error(void)
{
    BIND_WITHOUT(work_a, netif);
    if_untagged(work_a, 0u);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp4(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_IP_ADDRESS, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "an address was matched with no interface table to match it against");
    TEST_ASSERT_FALSE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
}

// RFC 1112 sec 7.2 makes the all-hosts group a membership no table holds, so it is answered without
// igmp. Every other group is a table lookup, and a build with no igmp borrow holds no memberships at
// all: the datagram is for a group this host has not joined.
void test_a_multicast_destination_with_no_igmp_borrow_is_not_ours(void)
{
    BIND_WITHOUT(work_a, igmp);
    if_untagged(work_a, 0u);

    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    // 224.0.0.2, all-routers, which is a group and is not the one sec 7.2 joins for you.
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, 0xE0000002u, IDEMIP_UDP_HDR_LEN, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 0u);
    seal_udp4(g_frame, off, REMOTE_IP4, 0xE0000002u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);

    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_DISPATCH_DROP_IP_ADDRESS, IDEMIP_DISPATCH_IO(work_a)->drop,
                                  "a group this host never joined was taken as its own");
    TEST_ASSERT_FALSE((IDEMIP_DISPATCH_IO(work_a)->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u);
}

// The tag is read before anything else, so an unbound vlan stops every frame there.
void test_a_frame_with_no_vlan_borrow_is_refused(void)
{
    BIND_WITHOUT(work_a, vlan);
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, 8u, 0u);
    input(work_a, off + 8u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    ASSERT_UNBOUND(work_a, "vlan");
}

#if IDEMIP_ENABLE_IPV4

void test_an_ipv4_frame_with_an_unbound_unit_is_refused(void)
{
    // RFC 826, which arp_table answers.
    BIND_WITHOUT(work_a, arp);
    if_untagged(work_a, 0u);
    size_t off = build_eth(g_frame, g_bcast_mac, (uint16_t)IDEMIP_ETHERTYPE_ARP);
    size_t end = build_arp(g_frame, off, IDEMIP_ARP_OP_REQUEST, LOCAL_IP4);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    ASSERT_UNBOUND(work_a, "arp");

    // RFC 792, which icmp_in answers.
    BIND_WITHOUT(work_a, icmp_in);
    if_untagged(work_a, 0u);
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_ICMP, REMOTE_IP4, LOCAL_IP4, IDEMIP_ICMP_ECHO_HDR_LEN + 8u, 0u);
    end = build_icmp_echo(g_frame, off, 8u);
    idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
    idemip_ip4_recksum(g_frame + ip);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    ASSERT_UNBOUND(work_a, "icmp_in");

    // RFC 2236, addressed to the all-hosts group, which needs no table entry to be this host's.
    BIND_WITHOUT(work_a, igmp);
    if_untagged(work_a, 0u);
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IGMP_IP_PROTO, REMOTE_IP4, IDEMIP_IGMP_ALL_SYSTEMS, IDEMIP_IGMP_MSG_LEN, 0u);
    end = build_igmp(g_frame, off, (uint8_t)IDEMIP_IGMP_TYPE_QUERY, 100u, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    ASSERT_UNBOUND(work_a, "igmp");

    // RFC 791 sec 3.2, which ip4_reass holds. A fragment reaches it before its descriptor matters.
    BIND_WITHOUT(work_a, ip4_reass);
    if_untagged(work_a, 0u);
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, 8u, IDEMIP_IP4_FLAG_MF);
    input(work_a, off + 8u, 0u, IP4_FRAG_DESC);
    ASSERT_UNBOUND(work_a, "ip4_reass");
}

#endif // IDEMIP_ENABLE_IPV4

#if IDEMIP_ENABLE_IPV6

void test_an_ipv6_frame_with_an_unbound_unit_is_refused(void)
{
    // RFC 4443, which icmp6_in answers.
    BIND_WITHOUT(work_a, icmp6_in);
    if_untagged(work_a, 0u);
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t msg = build_icmp6_msg(g_frame, off, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, g_remote_ip6, g_local_ip6,
                                 IDEMIP_ICMP6_ECHO_HDR_LEN);
    seal_icmp6(g_frame, msg, IDEMIP_ICMP6_ECHO_HDR_LEN, g_remote_ip6, g_local_ip6);
    input(work_a, msg + IDEMIP_ICMP6_ECHO_HDR_LEN, 0u, IDEMIP_DISPATCH_DESC_NONE);
    ASSERT_UNBOUND(work_a, "icmp6_in");

    // RFC 8200 sec 4.5, which ip6_reass holds.
    BIND_WITHOUT(work_a, ip6_reass);
    if_untagged(work_a, 0u);
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    size_t end = build_ip6_fragment(g_frame, off, g_remote_ip6, g_local_ip6, IDEMIP_IP6_NH_UDP, 0u, IDEMIP_TRUE,
                                    FRAG_IDENT, 8u);
    input(work_a, end, 0u, FRAG_DESC);
    ASSERT_UNBOUND(work_a, "ip6_reass");
}

#endif // IDEMIP_ENABLE_IPV6

#if IDEMIP_ENABLE_UDP

void test_a_udp_datagram_with_an_unbound_unit_is_refused(void)
{
    // RFC 768, which udp_pcb holds the bindings for.
    BIND_WITHOUT(work_a, udp_pcb);
    if_untagged(work_a, 0u);
    size_t off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    size_t ip = off;
    off = build_ip4(g_frame, off, IDEMIP_IP4_PROTO_UDP, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN + 4u, 0u);
    size_t end = build_udp(g_frame, off, 4000u, 4001u, 4u);
    seal_udp4(g_frame, off, REMOTE_IP4, LOCAL_IP4);
    idemip_ip4_set_total_len(g_frame + ip, (uint16_t)(end - ip));
    idemip_ip4_recksum(g_frame + ip);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    ASSERT_UNBOUND(work_a, "udp_pcb");

    // RFC 3828, which udplite reads the Checksum Coverage for.
    BIND_WITHOUT(work_a, udplite);
    if_untagged(work_a, 0u);
    off = build_eth(g_frame, g_local_mac, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    off = build_ip4(g_frame, off, (uint8_t)IDEMIP_UDPLITE_PROTO, REMOTE_IP4, LOCAL_IP4, IDEMIP_UDP_HDR_LEN + 4u, 0u);
    idemip_udp_build(g_frame + off, 4000u, 4001u, 0u); // coverage 0, the whole datagram
    memset(g_frame + off + IDEMIP_UDP_HDR_LEN, 0xC3, 4u);
    input(work_a, off + IDEMIP_UDP_HDR_LEN + 4u, 0u, IDEMIP_DISPATCH_DESC_NONE);
    ASSERT_UNBOUND(work_a, "udplite");
}

#endif // IDEMIP_ENABLE_UDP

#if IDEMIP_ENABLE_TCP

// RFC 9293. Both borrows are one branch, a segment needing the table and the parser together.
void test_a_tcp_segment_with_an_unbound_unit_is_refused(void)
{
    BIND_WITHOUT(work_a, tcp_in);
    if_untagged(work_a, 0u);
    size_t end = build_tcp4(g_frame, 5000u, 5001u, 100u, 0u, IDEMIP_TCP_SYN, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    ASSERT_UNBOUND(work_a, "tcp_in");

    BIND_WITHOUT(work_a, tcp_pcb);
    if_untagged(work_a, 0u);
    end = build_tcp4(g_frame, 5000u, 5001u, 100u, 0u, IDEMIP_TCP_SYN, 0u);
    input(work_a, end, 0u, IDEMIP_DISPATCH_DESC_NONE);
    ASSERT_UNBOUND(work_a, "tcp_pcb");
}

#endif // IDEMIP_ENABLE_TCP

