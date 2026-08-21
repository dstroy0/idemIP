// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file fuzz_dispatch.c
 * @brief Dispatch.input, driven by libFuzzer, from a state each input starts over from.
 *
 * The receive path is one entry over one frame, and it allocates nothing, so a fuzzer needs no
 * driver, no socket and no allocator interposition: it needs the borrows, a frame, and the four
 * numbers the caller reads for it. That is the whole harness. RFC 1122 sec 3.1 is what it walks -
 * the link layer, the internet layer, the transport layer and the address checks between them -
 * and a mutated frame is exactly the input those steps are written to survive.
 *
 * WHAT THE INPUT IS
 * -----------------
 * A sequence of frames, each a two-octet big-endian length and that many octets. A record naming
 * more octets than remain is fed as what remains, so a mutation that truncates the input still
 * produces a frame, and a truncated frame is a case the walk has to answer for. One input is one
 * sequence: the state is cleared and rebuilt before the first record and carried across the rest,
 * which is what lets a sequence reach the states a single frame cannot - RFC 791 sec 3.2 and RFC
 * 8200 sec 4.5 reassembly, RFC 826's pending queue, and the RFC 9293 sec 3.10.7 machine past the
 * first segment.
 *
 * WHY IT REPRODUCES
 * -----------------
 * Every borrow is cleared and rebound at the head of each input, and the clock and the random word
 * are functions of the record index alone, so the same file gives the same walk on every run and
 * on every machine. A crash file is the whole reproduction, and `Dispatch.input` is a function of
 * its borrow, so the state it crashed from is in the file too.
 *
 * WHAT IT ASSERTS
 * ---------------
 * A crash is not the only finding. The invariants below are the ones the interface states, and
 * each is checked after every frame, so a frame that breaks one is reported as a crash by a
 * harness that would otherwise only see a segfault.
 */

#include "src/idemip.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The interface this node answers on. The addresses are RFC 5737 sec 3's TEST-NET-1 and RFC 3849's
// documentation prefix, so nothing here names a host that exists.
#define FUZZ_LOCAL_IP4 0xC0000201u  // 192.0.2.1
#define FUZZ_NETMASK4 0xFFFFFF00u   // /24
#define FUZZ_GATEWAY4 0xC00002FEu   // 192.0.2.254
#define FUZZ_UDP_PORT 5001u
#define FUZZ_TCP_PORT 5002u

#define FUZZ_FRAME_MAX 2048u
#define FUZZ_CANARY 0xA5u

static const uint8_t fuzz_local_mac[6] = {0x02u, 0x00u, 0x5Eu, 0x10u, 0x00u, 0x01u};
#if IDEMIP_ENABLE_IPV6
// Behind the capability that reads them: a build without IPv6 has no address to give the interface
// and no ::1 for the loopback, and a constant nothing names is a warning the two-build run refuses.
static const uint8_t fuzz_local_ip6[16] = {0x20u, 0x01u, 0x0Du, 0xB8u, 0u, 0u, 0u, 0u,
                                           0u,    0u,    0u,    0u,    0u, 0u, 0u, 0x01u};
static const uint8_t fuzz_lo6[16] = {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0x01u};
#endif

// One array per borrow, which is the whole footprint: the library holds no file-scope mutable of
// its own. The dispatch borrow carries a tail of canary octets so a write past
// IDEMIP_DISPATCH_BORROW is a finding here and not a corruption somewhere later.
static _Alignas(IDEMIP_ALIGN) uint8_t work[IDEMIP_DISPATCH_BORROW + 64u];
static _Alignas(IDEMIP_ALIGN) uint8_t stats_mem[IDEMIP_STATS_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t phy_mem[IDEMIP_PHY_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t netif_mem[IDEMIP_NETIF_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t loopif_mem[IDEMIP_LOOPIF_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t vlan_mem[IDEMIP_VLAN_BORROW];
#if IDEMIP_ENABLE_IPV4
static _Alignas(IDEMIP_ALIGN) uint8_t arp_mem[IDEMIP_ARP_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t ip4_addr_mem[IDEMIP_IP4_ADDR_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t ip4_reass_mem[IDEMIP_IP4_REASS_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t icmp_in_mem[IDEMIP_ICMP_IN_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t igmp_mem[IDEMIP_IGMP_BORROW];
#endif
#if IDEMIP_ENABLE_IPV6
static _Alignas(IDEMIP_ALIGN) uint8_t ip6_addr_mem[IDEMIP_IP6_ADDR_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t ip6_reass_mem[IDEMIP_IP6_REASS_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t icmp6_in_mem[IDEMIP_ICMP6_IN_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t mld6_mem[IDEMIP_MLD6_BORROW];
#endif
#if IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6
static _Alignas(IDEMIP_ALIGN) uint8_t raw_mem[IDEMIP_RAW_PCB_BORROW];
#endif
#if IDEMIP_ENABLE_UDP
static _Alignas(IDEMIP_ALIGN) uint8_t udp_mem[IDEMIP_UDP_PCB_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t udplite_mem[IDEMIP_UDPLITE_BORROW];
#endif
#if IDEMIP_ENABLE_TCP
static _Alignas(IDEMIP_ALIGN) uint8_t tcp_pcb_mem[IDEMIP_TCP_PCB_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t tcp_in_mem[IDEMIP_TCP_IN_BORROW];
#endif

// The frame is copied out of the fuzzer's buffer so the walk reads a span this harness owns: the
// sanitizer then reports a read past the length as a read past this array, at the octet it
// happened on.
//
// Both carry a word of slack behind the octets a frame may occupy, which is what a driver's
// receive buffer has: IDEMIP_DMA_BUF_STRIDE is wider than a frame, and the span helpers in
// common.h read the tail of a span out to the end of its word and mask it. A buffer sized to the
// octet would make that read leave the object, which is the caller's arrangement to get right and
// not a finding about the walk.
static uint8_t frame[FUZZ_FRAME_MAX + sizeof(IdemIpWord)];
static uint8_t out[FUZZ_FRAME_MAX + sizeof(IdemIpWord)];

// Off under libFuzzer, which wants no output per input. The standalone replay turns it on with -v,
// so a seed or a crash file can be read frame by frame without a debugger.
static int fuzz_verbose;

// A finding that is not a crash. abort() is what libFuzzer records, and the string is what the
// crash report carries back.
#define FUZZ_CHECK(cond, why)                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            (void)fputs("idemIP fuzz invariant: " why "\n", stderr);                                                   \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

static void fuzz_wire(void)
{
    memset(work, 0, IDEMIP_DISPATCH_BORROW);
    memset(work + IDEMIP_DISPATCH_BORROW, FUZZ_CANARY, sizeof work - IDEMIP_DISPATCH_BORROW);
    memset(phy_mem, 0, sizeof phy_mem);
    memset(out, 0, sizeof out);

    Stats.clear(stats_mem);
    Vlan.clear(vlan_mem);
#if IDEMIP_ENABLE_IPV4
    ArpTable.clear(arp_mem);
    Ip4Addr.clear(ip4_addr_mem);
    Ip4Reass.clear(ip4_reass_mem);
    IcmpIn.clear(icmp_in_mem);
    Igmp.clear(igmp_mem);
#endif
#if IDEMIP_ENABLE_IPV6
    Ip6Addr.clear(ip6_addr_mem);
    Ip6Reass.clear(ip6_reass_mem);
    Icmp6In.clear(icmp6_in_mem);
    Mld6.clear(mld6_mem);
#endif
#if IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6
    RawPcb.clear(raw_mem); // raw_pcb.h stands behind the same two: a raw binding names an IP version
#endif
#if IDEMIP_ENABLE_UDP
    UdpPcb.clear(udp_mem);
    UdpLite.clear(udplite_mem);
#endif
#if IDEMIP_ENABLE_TCP
    TcpPcb.clear(tcp_pcb_mem);
    TcpIn.clear(tcp_in_mem);
#endif

    Loopif.clear(loopif_mem);
    LoopifIo *lo = IDEMIP_LOOPIF_IO(loopif_mem);
    lo->bind_args.addr4 = 0x7F000001u;
#if IDEMIP_ENABLE_IPV6
    lo->bind_args.addr6 = fuzz_lo6;
#endif
    lo->bind_args.mtu = 1500u;
    lo->bind_args.index = 0u;
    Loopif.bind(loopif_mem);

    Netif.clear(netif_mem);
    NetifIo *ni = IDEMIP_NETIF_IO(netif_mem);
    ni->bind_args.index = 0u;
    ni->bind_args.phy = phy_mem;
    ni->bind_args.hwaddr = fuzz_local_mac;
    ni->bind_args.mtu = 1500u;
    Netif.bind(netif_mem);
    FUZZ_CHECK(ni->status == IDEMIP_OK, "the interface would not bind");
#if IDEMIP_ENABLE_IPV4
    ni->addr4_args.index = 0u;
    ni->addr4_args.addr = FUZZ_LOCAL_IP4;
    ni->addr4_args.mask = FUZZ_NETMASK4;
    ni->addr4_args.gw = FUZZ_GATEWAY4;
    Netif.set_addr4(netif_mem);
    FUZZ_CHECK(ni->status == IDEMIP_OK, "the interface would not take its IPv4 address");
#endif
    ni->if_args.index = 0u;
    ni->if_args.set = (uint16_t)(IDEMIP_NETIF_FLAG_UP | IDEMIP_NETIF_FLAG_LINK_UP | IDEMIP_NETIF_FLAG_BROADCAST |
                                 IDEMIP_NETIF_FLAG_ETHARP);
    ni->if_args.clear = 0u;
    Netif.set_flags(netif_mem);
#if IDEMIP_ENABLE_IPV6
    ni->addr6_args.index = 0u;
    ni->addr6_args.addr = fuzz_local_ip6;
    ni->addr6_args.state = IDEMIP_NETIF_ADDR6_PREFERRED;
    ni->addr6_args.preferred_s = IDEMIP_NETIF_LIFETIME_INFINITE;
    ni->addr6_args.valid_s = IDEMIP_NETIF_LIFETIME_INFINITE;
    Netif.add_addr6(netif_mem);
    FUZZ_CHECK(ni->status == IDEMIP_OK, "the interface would not take its IPv6 address");
#endif

    // A binding on each transport, so the delivery half of the walk is reachable and not only the
    // refusal half: an unbound port is answered by RFC 1122 sec 4.1.3.1 and stops there.
#if IDEMIP_ENABLE_UDP && IDEMIP_ENABLE_IPV4
    UdpPcbIo *up = IDEMIP_UDP_PCB_IO(udp_mem);
    up->open_args.ip_version = 4u;
    up->open_args.lite = IDEMIP_FALSE;
    UdpPcb.open(udp_mem);
    if (up->status == IDEMIP_OK)
    {
        static uint8_t local4[4];
        idemip_wr32(local4, FUZZ_LOCAL_IP4);
        up->bind_args.index = up->index;
        up->bind_args.ip = local4;
        up->bind_args.port = (uint16_t)FUZZ_UDP_PORT;
        up->bind_args.zone = 0u;
        up->bind_args.netif = 0u;
        UdpPcb.bind(udp_mem);
    }
#endif
#if IDEMIP_ENABLE_UDP && IDEMIP_ENABLE_IPV6
    UdpPcbIo *up6 = IDEMIP_UDP_PCB_IO(udp_mem);
    up6->open_args.ip_version = 6u;
    up6->open_args.lite = IDEMIP_FALSE;
    UdpPcb.open(udp_mem);
    if (up6->status == IDEMIP_OK)
    {
        up6->bind_args.index = up6->index;
        up6->bind_args.ip = fuzz_local_ip6;
        up6->bind_args.port = (uint16_t)FUZZ_UDP_PORT;
        up6->bind_args.zone = 0u;
        up6->bind_args.netif = 0u;
        UdpPcb.bind(udp_mem);
    }
#endif
#if IDEMIP_ENABLE_TCP
    TcpPcbIo *tp = IDEMIP_TCP_PCB_IO(tcp_pcb_mem);
#if IDEMIP_ENABLE_IPV4
    static uint8_t tcp_local[IDEMIP_TCP_PCB_ADDR_BYTES];
    memset(tcp_local, 0, sizeof tcp_local);
    idemip_wr32(tcp_local, FUZZ_LOCAL_IP4);
    tp->listen_args.ip = tcp_local;
    tp->listen_args.port = (uint16_t)FUZZ_TCP_PORT;
    tp->listen_args.zone = 0u;
    tp->listen_args.netif = 0u;
    tp->listen_args.backlog = 2u;
    tp->listen_args.ip_version = 4u;
    TcpPcb.listen(tcp_pcb_mem);
    FUZZ_CHECK(tp->status == IDEMIP_OK, "the IPv4 listener would not open");
#endif
#if IDEMIP_ENABLE_IPV6
    tp->listen_args.ip = fuzz_local_ip6;
    tp->listen_args.port = (uint16_t)FUZZ_TCP_PORT;
    tp->listen_args.zone = 0u;
    tp->listen_args.netif = 0u;
    tp->listen_args.backlog = 2u;
    tp->listen_args.ip_version = 6u;
    TcpPcb.listen(tcp_pcb_mem);
    FUZZ_CHECK(tp->status == IDEMIP_OK, "the IPv6 listener would not open");
#endif
#endif

    // clear first: it zeroes the context and both tables, and every other entry refuses a borrow it
    // has not run on. The operands are written after it, or it would take them back.
    Dispatch.clear(work);
    DispatchIo *io = IDEMIP_DISPATCH_IO(work);
    io->bind_args.stats = stats_mem;
    io->bind_args.netif = netif_mem;
    io->bind_args.loopif = loopif_mem;
    io->bind_args.vlan = vlan_mem;
#if IDEMIP_ENABLE_IPV4
    io->bind_args.arp = arp_mem;
    io->bind_args.ip4_addr = ip4_addr_mem;
    io->bind_args.ip4_reass = ip4_reass_mem;
    io->bind_args.icmp_in = icmp_in_mem;
    io->bind_args.igmp = igmp_mem;
#endif
#if IDEMIP_ENABLE_IPV6
    io->bind_args.ip6_addr = ip6_addr_mem;
    io->bind_args.ip6_reass = ip6_reass_mem;
    io->bind_args.icmp6_in = icmp6_in_mem;
    io->bind_args.mld6 = mld6_mem;
#endif
#if IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6
    io->bind_args.raw_pcb = raw_mem;
#endif
#if IDEMIP_ENABLE_UDP
    io->bind_args.udp_pcb = udp_mem;
    io->bind_args.udplite = udplite_mem;
#endif
#if IDEMIP_ENABLE_TCP
    io->bind_args.tcp_pcb = tcp_pcb_mem;
    io->bind_args.tcp_in = tcp_in_mem;
#endif
    Dispatch.bind(work);
    FUZZ_CHECK(io->status == IDEMIP_OK, "the dispatch borrow would not bind");

    // The interface's row, with no ring pair: a descriptor is then the caller's own token and
    // nothing is pinned, which is what lets this harness run with no driver at all.
    io->if_args.index = 0u;
    io->if_args.dma = NULL;
    io->if_args.vid = 0u;
    io->if_args.tagged = IDEMIP_FALSE;
    Dispatch.if_bind(work);
    FUZZ_CHECK(io->status == IDEMIP_OK, "the interface row would not bind");
}

// The invariants the interface states, read back after each frame.
static void fuzz_check(size_t len)
{
    const DispatchIo *io = IDEMIP_DISPATCH_IO(work);

    for (size_t i = IDEMIP_DISPATCH_BORROW; i < sizeof work; i++)
    {
        FUZZ_CHECK(work[i] == FUZZ_CANARY, "a write landed past IDEMIP_DISPATCH_BORROW");
    }
    FUZZ_CHECK(io->status == IDEMIP_OK || io->status == IDEMIP_BUSY || io->status == IDEMIP_ERR,
               "the call reported something that is not OK, BUSY or ERR");
    if ((io->act & IDEMIP_DISPATCH_ACT_SEND) != 0u)
    {
        FUZZ_CHECK(io->out_len <= (size_t)FUZZ_FRAME_MAX, "a reply was built past the out buffer's capacity");
    }
    if ((io->act & IDEMIP_DISPATCH_ACT_DELIVER) != 0u && (io->act & IDEMIP_DISPATCH_ACT_REASSEMBLED) == 0u)
    {
        // The payload a delivery names is measured from the frame it was read from, which is what
        // lets the caller hand those octets on without measuring them again. A datagram that came
        // out of a reassembler is the exception and says so with its own flag: those octets are in
        // the reassembler's storage and not in this frame.
        FUZZ_CHECK(io->payload_off <= len, "a delivery named a payload beginning past the frame");
        FUZZ_CHECK(io->payload_len <= len - io->payload_off, "a delivery named a payload running past the frame");
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_wire();

    size_t at = 0u;
    uint32_t step = 0u;
    while (at < size)
    {
        size_t want;
        if (size - at < 2u)
        {
            // A record with no room for a length is the octets themselves. `at` is left where it
            // is: the copy below reads from it, and the one advance at the end of the loop is what
            // moves it. Advancing here as well read one octet past the input, which is the first
            // thing this harness found - about itself.
            want = size - at;
        }
        else
        {
            want = ((size_t)data[at] << 8) | (size_t)data[at + 1u];
            at += 2u;
            if (want > size - at)
            {
                want = size - at; // a length past the input is the rest of it, truncated as it stands
            }
        }
        const size_t len = (want > FUZZ_FRAME_MAX) ? (size_t)FUZZ_FRAME_MAX : want;
        memcpy(frame, data + at, len);
        at += want;

        DispatchIo *io = IDEMIP_DISPATCH_IO(work);
        io->input_args.frame = frame;
        io->input_args.len = len;
        io->input_args.out = out;
        io->input_args.out_cap = (size_t)FUZZ_FRAME_MAX;
        // Both are functions of the record's place in the input and of nothing else, so a file
        // replays exactly. The clock moves so that a sequence can cross a deadline.
        io->input_args.now_ms = 1000u + (step * 250u);
        io->input_args.rand = 0x9E3779B9u + (step * 0x85EBCA6Bu);
        // A descriptor per frame, and a different one each time, which is what a driver hands over.
        // Without one the reassemblers cannot retain a fragment at all - retention needs a
        // descriptor - and RFC 791 sec 3.2 and RFC 8200 sec 4.5 would be unreachable from here.
        io->input_args.desc = (uint16_t)(step % (uint32_t)IDEMIP_RX_DESCRIPTORS);
        io->input_args.netif = 0u;
        Dispatch.input(work);

        fuzz_check(len);
        if (fuzz_verbose)
        {
            (void)fprintf(stdout, "   frame %u  len=%u  status=%d  act=0x%03X  drop=%d\n", (unsigned)step,
                          (unsigned)len, (int)io->status, (unsigned)io->act, (int)io->drop);
        }
        step++;
    }
    return 0;
}

#ifdef IDEMIP_FUZZ_STANDALONE

// The same harness with no fuzzer behind it: it replays the files it is handed and reports the
// first one that does not come back. That is what makes the corpus a regression suite rather than
// a directory - it runs on every build and every compiler, not only where libFuzzer is - and it is
// how a crash file is reproduced by someone who has no clang.
int main(int argc, char **argv)
{
    static uint8_t buf[64u * 1024u];
    int first = 1;
    if (argc > 1 && strcmp(argv[1], "-v") == 0)
    {
        fuzz_verbose = 1;
        first = 2;
    }
    for (int i = first; i < argc; i++)
    {
        if (fuzz_verbose)
        {
            (void)fprintf(stdout, "%s\n", argv[i]);
        }
        FILE *fh = fopen(argv[i], "rb");
        if (fh == NULL)
        {
            (void)fprintf(stderr, "fuzz_replay: cannot read %s\n", argv[i]);
            return 1;
        }
        const size_t n = fread(buf, 1u, sizeof buf, fh);
        (void)fclose(fh);
        (void)LLVMFuzzerTestOneInput(buf, n);
    }
    (void)fprintf(stdout, "fuzz_replay: %d inputs replayed, every invariant held\n", argc - first);
    return 0;
}

#endif
