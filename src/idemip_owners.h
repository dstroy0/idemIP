// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file idemip_owners.h
 * @brief The MMgr owner of each unit's borrow, for a program that takes its borrows as LocusCarcerum cells.
 *
 * A program has one owner table, and MMGR_OWNERS defines it in one translation unit. idemIP adds no owner
 * of its own to that table. IDEMIP_OWNERS lists one owner for each unit that has a borrow, and the program
 * splices that list into its own:
 *
 *     #define PROGRAM_OWNERS(macro_) IDEMIP_OWNERS(macro_) macro_(app_owner_log, "app.log")
 *     MMGR_OWNERS(PROGRAM_OWNERS)
 *
 * A borrow then comes from a cell that its unit's owner counts:
 *
 *     uint8_t *const arp_w = site.pool.persistent_buf_alloc(IDEMIP_ARP_BORROW, idemip_owner_arp);
 *
 * A unit on each interface has one owner, and that owner counts the borrows of every interface.
 */

#ifndef IDEMIP_IDEMIP_OWNERS_H
#define IDEMIP_IDEMIP_OWNERS_H

#include "src/idemip_config.h"

/**
 * @brief Applies macro_ to the identity and the printed name of the owner of each unit's borrow.
 * @param macro_ A macro of two arguments, as MMGR_OWNERS takes: the identity and the name.
 */
// clang-format off
#define IDEMIP_OWNERS(macro_) \
    macro_(idemip_owner_netif, "idemip.netif") \
    macro_(idemip_owner_loopif, "idemip.loopif") \
    macro_(idemip_owner_arp, "idemip.arp") \
    macro_(idemip_owner_ip4_route, "idemip.ip4_route") \
    macro_(idemip_owner_ip4_forward, "idemip.ip4_forward") \
    macro_(idemip_owner_ip6_forward, "idemip.ip6_forward") \
    macro_(idemip_owner_ip4_reass, "idemip.ip4_reass") \
    macro_(idemip_owner_ip4_frag, "idemip.ip4_frag") \
    macro_(idemip_owner_igmp, "idemip.igmp") \
    macro_(idemip_owner_ip6_reass, "idemip.ip6_reass") \
    macro_(idemip_owner_ip6_frag, "idemip.ip6_frag") \
    macro_(idemip_owner_mld6, "idemip.mld6") \
    macro_(idemip_owner_icmp_in, "idemip.icmp_in") \
    macro_(idemip_owner_icmp6_in, "idemip.icmp6_in") \
    macro_(idemip_owner_raw_pcb, "idemip.raw_pcb") \
    macro_(idemip_owner_udp_pcb, "idemip.udp_pcb") \
    macro_(idemip_owner_udplite, "idemip.udplite") \
    macro_(idemip_owner_tcp_pcb, "idemip.tcp_pcb") \
    macro_(idemip_owner_tcp_in, "idemip.tcp_in") \
    macro_(idemip_owner_tcp_out, "idemip.tcp_out") \
    macro_(idemip_owner_tcp_isn, "idemip.tcp_isn") \
    macro_(idemip_owner_ip4_addr, "idemip.ip4_addr") \
    macro_(idemip_owner_ip6_addr, "idemip.ip6_addr") \
    macro_(idemip_owner_ip6_select, "idemip.ip6_select") \
    macro_(idemip_owner_pmtu4, "idemip.pmtu4") \
    macro_(idemip_owner_dns, "idemip.dns") \
    macro_(idemip_owner_timeouts, "idemip.timeouts") \
    macro_(idemip_owner_tick, "idemip.tick") \
    macro_(idemip_owner_dispatch, "idemip.dispatch") \
    macro_(idemip_owner_stats, "idemip.stats") \
    macro_(idemip_owner_vlan, "idemip.vlan") \
    macro_(idemip_owner_ethip6, "idemip.ethip6") \
    macro_(idemip_owner_phy, "idemip.phy") \
    macro_(idemip_owner_dma, "idemip.dma") \
    macro_(idemip_owner_nd6, "idemip.nd6") \
    macro_(idemip_owner_acd, "idemip.acd") \
    macro_(idemip_owner_autoip, "idemip.autoip") \
    macro_(idemip_owner_pmtu6, "idemip.pmtu6") \
    macro_(idemip_owner_dhcp4, "idemip.dhcp4") \
    macro_(idemip_owner_dhcp6, "idemip.dhcp6") \
    macro_(idemip_owner_dad, "idemip.dad") \
    macro_(idemip_owner_slaac, "idemip.slaac") \
    macro_(idemip_owner_rdnss, "idemip.rdnss")
// clang-format on

EMBED_BEGIN_DECLS

// Each owner's identity, which the program's MMGR_OWNERS defines.
IDEMIP_OWNERS(MMGR_OWNER_EXTERN)

EMBED_END_DECLS

#endif // IDEMIP_IDEMIP_OWNERS_H
