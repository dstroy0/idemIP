// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file idemip.h
 * @brief The one header an application includes: every unit's namespace, borrow map and constant.
 *
 * This file adds no type, no macro and no call of its own. It includes the public header of each
 * unit and states what a caller allocates, in what order it clears and binds, and what one tick
 * does. Each included header carries its own capability gate, so a header whose capability is off
 * contributes nothing.
 *
 * WHAT THE CALLER ALLOCATES
 * -------------------------
 * One `static _Alignas(IDEMIP_ALIGN) uint8_t` array per borrow, sized by that unit's
 * IDEMIP_<UNIT>_BORROW. The library allocates nothing and holds no file-scope mutable, so the
 * whole footprint is these arrays. IDEMIP_TOTAL_BORROW is their sum:
 * IDEMIP_SHARED_BORROW for the units holding one table across every interface, plus
 * IDEMIP_NETIF_COUNT times IDEMIP_PER_NETIF_BORROW for the units the RFC puts on one interface.
 * tools/idemip_sizes.c prints every term and the sum the compiler computed.
 *
 * Two further arrays are the DRIVER's frame storage and are in no borrow, so IDEMIP_TOTAL_BORROW
 * does not count them: IDEMIP_RX_DESCRIPTORS and IDEMIP_TX_DESCRIPTORS buffers of
 * IDEMIP_DMA_BUF_STRIDE octets each, both `_Alignas(IDEMIP_CACHE_LINE_BYTES)`, one pair per
 * interface. Dma.bind refuses a base that does not start on a cache line.
 *
 * THE ORDER
 * ---------
 * 1. clear   every unit that exports a `clear`, on its own borrow. Every other entry of that unit
 *            refuses a borrow clear has not run on, because a zeroed borrow reads a list link as
 *            index zero rather than as that unit's terminator.
 * 2. bind    Phy.bind takes the IdemIpPhyDriver and its Clause 22 management address; Dma.bind
 *            takes the same driver and the two buffer arrays; Netif.bind takes the phy borrow, the
 *            hardware address and the link MTU. Netif.set_addr4 takes the address, mask and
 *            gateway. TcpIsn.seed takes the RFC 6528 sec 3 secret.
 * 3. tick    the three stages of PLAN.md sec 3.4b, in order, on a millisecond clock the caller
 *            reads once per pass: drain receive, run each service's timers, flush deferred
 *            transmit. A later stage consumes what an earlier one produced.
 *
 * Every entry is `void (*const)(uint8_t *restrict work)` and reports OK, BUSY or ERR in its
 * operand block. Nothing blocks: BUSY is a retry on a later tick, ERR is not.
 *
 * Millisecond deadlines wrap, so every comparison against one is the signed-difference form
 * `(int32_t)(a - b) >= 0` and never a plain less-than.
 *
 * A WORKED EXAMPLE
 * ----------------
 *   #include "src/idemip.h"
 *
 *   // the borrows, one array each, all .bss
 *   static _Alignas(IDEMIP_ALIGN) uint8_t phy_w[IDEMIP_PHY_BORROW];
 *   static _Alignas(IDEMIP_ALIGN) uint8_t dma_w[IDEMIP_DMA_BORROW];
 *   static _Alignas(IDEMIP_ALIGN) uint8_t netif_w[IDEMIP_NETIF_BORROW];
 *   static _Alignas(IDEMIP_ALIGN) uint8_t arp_w[IDEMIP_ARP_BORROW];
 *   static _Alignas(IDEMIP_ALIGN) uint8_t reass_w[IDEMIP_IP4_REASS_BORROW];
 *   static _Alignas(IDEMIP_ALIGN) uint8_t icmp_w[IDEMIP_ICMP_IN_BORROW];
 *   static _Alignas(IDEMIP_ALIGN) uint8_t udp_w[IDEMIP_UDP_PCB_BORROW];
 *   static _Alignas(IDEMIP_ALIGN) uint8_t stats_w[IDEMIP_STATS_BORROW];
 *   static _Alignas(IDEMIP_ALIGN) uint8_t timeouts_w[IDEMIP_TIMEOUTS_BORROW];
 *   static _Alignas(IDEMIP_ALIGN) uint8_t dispatch_w[IDEMIP_DISPATCH_BORROW];
 *   static _Alignas(IDEMIP_ALIGN) uint8_t tick_w[IDEMIP_TICK_BORROW];
 *
 *   // the driver's frame storage, not a borrow
 *   static _Alignas(IDEMIP_CACHE_LINE_BYTES) uint8_t rx_bufs[IDEMIP_RX_DESCRIPTORS * IDEMIP_DMA_BUF_STRIDE];
 *   static _Alignas(IDEMIP_CACHE_LINE_BYTES) uint8_t tx_bufs[IDEMIP_TX_DESCRIPTORS * IDEMIP_DMA_BUF_STRIDE];
 *
 *   static const uint8_t mac[IDEMIP_MAC_LEN] = {0x02, 0, 0, 0, 0, 1};
 *
 *   void net_start(const IdemIpPhyDriver *drv)
 *   {
 *       // phy exports no clear: its whole context is what bind writes, and the array is already
 *       // zero, being .bss
 *       Dma.clear(dma_w);
 *       Netif.clear(netif_w);
 *       ArpTable.clear(arp_w);
 *       Ip4Reass.clear(reass_w);
 *       IcmpIn.clear(icmp_w);
 *       UdpPcb.clear(udp_w);
 *       Stats.clear(stats_w);
 *
 *       IDEMIP_PHY_IO(phy_w)->bind_args.drv = drv;
 *       IDEMIP_PHY_IO(phy_w)->bind_args.addr = 1u;
 *       Phy.bind(phy_w);
 *
 *       IDEMIP_DMA_IO(dma_w)->bind_args.drv = drv;
 *       IDEMIP_DMA_IO(dma_w)->bind_args.rx_base = rx_bufs;
 *       IDEMIP_DMA_IO(dma_w)->bind_args.tx_base = tx_bufs;
 *       Dma.bind(dma_w);
 *
 *       IDEMIP_NETIF_IO(netif_w)->bind_args.index = 0u;
 *       IDEMIP_NETIF_IO(netif_w)->bind_args.phy = phy_w;
 *       IDEMIP_NETIF_IO(netif_w)->bind_args.hwaddr = mac;
 *       IDEMIP_NETIF_IO(netif_w)->bind_args.mtu = IDEMIP_ETH_MAX_PAYLOAD;
 *       Netif.bind(netif_w);
 *
 *       IDEMIP_NETIF_IO(netif_w)->addr4_args.index = 0u;
 *       IDEMIP_NETIF_IO(netif_w)->addr4_args.addr = 0xC0A80102u;
 *       IDEMIP_NETIF_IO(netif_w)->addr4_args.mask = 0xFFFFFF00u;
 *       IDEMIP_NETIF_IO(netif_w)->addr4_args.gw = 0xC0A80101u;
 *       Netif.set_addr4(netif_w);
 *   }
 *
 *   void net_tick(uint32_t now_ms)
 *   {
 *       // 1. drain receive: every frame the engine filled, dispatched and posted back
 *       for (;;)
 *       {
 *           Dma.rx_take(dma_w);
 *           if (IDEMIP_DMA_IO(dma_w)->status != IDEMIP_OK)
 *           {
 *               break;
 *           }
 *           uint8_t desc = IDEMIP_DMA_IO(dma_w)->index;
 *           app_dispatch_one_frame(IDEMIP_DMA_IO(dma_w)->buf, IDEMIP_DMA_IO(dma_w)->len, desc, now_ms);
 *           IDEMIP_DMA_IO(dma_w)->desc_args.index = desc;
 *           Dma.rx_post(dma_w);
 *       }
 *
 *       // 2. run each service's timers, in dependency order: resolution before what waits on it,
 *       //    reassembly before the protocols that read a completed datagram
 *       IDEMIP_ARP_IO(arp_w)->now_ms = now_ms;
 *       while (ArpTable.tick(arp_w), IDEMIP_ARP_IO(arp_w)->status == IDEMIP_OK)
 *       {
 *           app_arp_report(arp_w);
 *       }
 *       IDEMIP_IP4_REASS_IO(reass_w)->now_ms = now_ms;
 *       while (Ip4Reass.tick(reass_w), IDEMIP_IP4_REASS_IO(reass_w)->status == IDEMIP_OK)
 *       {
 *       }
 *
 *       // 3. flush deferred transmit: what reported BUSY on an earlier tick, and the engine's
 *       //    finished transmit descriptors
 *       Dma.tx_reap(dma_w);
 *       app_flush_deferred(now_ms);
 *   }
 *
 * THE SAME PASS, WITH THE SCHEDULER
 * ---------------------------------
 * `net_tick` writes the three stages out longhand, which is what they are, and what
 * `app_dispatch_one_frame` stands for is one call to @ref DispatchNs::input. Neither has to be the
 * caller's: `src/core/dispatch.h` is that one frame in, one decision out, and `src/core/tick.h` is
 * the same three stages with the order ENFORCED rather than described. Tick holds the phase in its
 * own context, @ref TickNs::open puts it at DRAIN, and an entry called out of its phase reports
 * IDEMIP_ERR, so the services cannot silently run before the ring is drained. Each phase reports
 * OK per step and IDEMIP_BUSY when that phase is through, which is the same shape the loop above
 * already uses for ArpTable.tick:
 *
 *   void net_tick(uint32_t now_ms)
 *   {
 *       IDEMIP_TICK_IO(tick_w)->open_args.now_ms = now_ms;
 *       Tick.open(tick_w);
 *       while (Tick.drain(tick_w), IDEMIP_TICK_IO(tick_w)->status == IDEMIP_OK)
 *       {
 *       }
 *       while (Tick.service(tick_w), IDEMIP_TICK_IO(tick_w)->status == IDEMIP_OK)
 *       {
 *       }
 *       while (Tick.flush(tick_w), IDEMIP_TICK_IO(tick_w)->status == IDEMIP_OK)
 *       {
 *       }
 *   }
 *
 * Tick.bind takes the borrows it drives and Tick.if_bind takes one interface's rings, neighbor
 * machine and transmit buffer, both in step 2 above; Dispatch.bind takes the borrows the receive
 * path calls into and Dispatch.if_bind one interface's ring pair and its IEEE 802.1Q membership.
 * Tick's own bind takes the dispatch borrow, so the two are bound once and in that order. Both
 * borrows are unconditional terms of IDEMIP_SHARED_BORROW, so the footprint is the same either way
 * and hand-writing the loop saves nothing but the two bind calls.
 */

#ifndef IDEMIP_IDEMIP_H
#define IDEMIP_IDEMIP_H

#include "src/idemip_config.h" // the entry point: every count, every constant, every borrow

// --- base ----------------------------------------------------------------------------------------
#include "src/checksum.h" // RFC 1071
#include "src/common.h"   // the sizes and widths each standard fixes
#include "src/endian.h"   // the wire-integer accessors

// --- link ----------------------------------------------------------------------------------------
#include "src/ethernet/ethernet.h" // RFC 894 framing
#include "src/ethernet/mii.h"      // IEEE 802.3 Clause 22 management registers
#include "src/ethernet/phy.h"      // the driver contract and the claim/release frame path
#include "src/ethernet/vlan.h"     // IEEE 802.1Q C-Tag
#include "src/netif/dma.h"         // the descriptor rings and the pin count
#include "src/netif/loopif.h"      // RFC 1122 sec 3.2.1.3, RFC 4291 sec 2.5.3
#include "src/netif/netif.h"       // the interface table

// --- core ----------------------------------------------------------------------------------------
#include "src/core/stats.h"    // RFC 1213, RFC 2465 and RFC 2466 counters
#include "src/core/timeouts.h" // the deadline list

// --- IPv4 ----------------------------------------------------------------------------------------
#include "src/acd/acd.h"           // RFC 5227
#include "src/arp/arp.h"           // RFC 826 packet format
#include "src/arp/arp_table.h"     // RFC 826 translation table and pending holds
#include "src/autoip/autoip.h"     // RFC 3927
#include "src/dhcp/dhcp4.h"        // RFC 2131
#include "src/icmp/icmp.h"         // RFC 792 message format
#include "src/icmp/icmp_in.h"      // RFC 792 message path, RFC 1122 sec 3.2.2
#include "src/igmp/igmp.h"         // RFC 2236
#include "src/ip/ip4_addr.h"       // RFC 1122 sec 3.2.1.3 address classification
#include "src/ip/ip4_forward.h"    // RFC 1812 sec 5.2.1.2
#include "src/ip/ip4_frag.h"       // RFC 791 sec 3.2 fragmentation
#include "src/ip/ip4_reass.h"      // RFC 791 sec 3.2, RFC 815 reassembly
#include "src/ip/ip4_route.h"      // RFC 1122 sec 3.3.1
#include "src/ip/ipv4.h"           // RFC 791 sec 3.1 internet header
#include "src/pmtu/pmtu4.h"        // RFC 1191

// --- IPv6 ----------------------------------------------------------------------------------------
#include "src/dhcp/dhcp6.h"        // RFC 8415
#include "src/ethernet/ethip6.h"   // RFC 2464
#include "src/icmp/icmp6_in.h"     // RFC 4443 message path
#include "src/icmp/icmpv6.h"       // RFC 4443 message format
#include "src/ip/ip6_addr.h"       // RFC 4291 sec 2, RFC 4007
#include "src/ip/ip6_forward.h"    // RFC 8200 sec 3, RFC 4861 sec 8
#include "src/ip/ip6_frag.h"       // RFC 8200 sec 4.5 fragmentation
#include "src/ip/ip6_reass.h"      // RFC 8200 sec 4.5 reassembly
#include "src/ip/ip6_select.h"     // RFC 6724
#include "src/ip/ipv6.h"           // RFC 8200 sec 3 header
#include "src/mld/mld6.h"          // RFC 2710
#include "src/nd/dad.h"            // RFC 4862 sec 5.4
#include "src/nd/nd6.h"            // RFC 4861 sec 5.1
#include "src/nd/rdnss.h"          // RFC 8106
#include "src/nd/slaac.h"          // RFC 4862 sec 5.3, sec 5.5
#include "src/pmtu/pmtu6.h"        // RFC 8201

// --- transport -----------------------------------------------------------------------------------
#include "src/raw/raw_pcb.h"  // RFC 1122 sec 3.4 raw bindings
#include "src/tcp/tcp.h"      // RFC 9293 sec 3.1 header and sec 3.2 options
#include "src/tcp/tcp_in.h"   // RFC 9293 sec 3.10.7 SEGMENT ARRIVES
#include "src/tcp/tcp_isn.h"  // RFC 6528
#include "src/tcp/tcp_out.h"  // RFC 9293 sec 3.7, sec 3.8
#include "src/tcp/tcp_pcb.h"  // RFC 9293 sec 3.3.1 Transmission Control Blocks
#include "src/udp/udp.h"      // RFC 768 header
#include "src/udp/udp_pcb.h"  // RFC 768 bindings
#include "src/udp/udplite.h"  // RFC 3828

// --- services ------------------------------------------------------------------------------------
#include "src/dns/dns.h" // RFC 1035, RFC 5452

// --- scheduling ----------------------------------------------------------------------------------
// Last, because these two drive every unit above and are the only ones that decide what runs when.
#include "src/core/dispatch.h" // one frame in, one decision out
#include "src/core/tick.h"     // PLAN.md sec 3.4b's drain, service and flush, in that order

#endif // IDEMIP_IDEMIP_H
