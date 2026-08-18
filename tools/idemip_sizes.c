// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file idemip_sizes.c
 * @brief Print every borrow and their sum, as the compiler computed them.
 *
 * The whole .bss cost of this library is the sum below, and it is the compiler's arithmetic over
 * idemip_config.h rather than a figure anyone maintains by hand. A borrow moves whenever a unit's
 * context or one of its counts moves, so this is run rather than remembered.
 *
 * tools/ is exempt from the src/ style rules, so this reads as plain host C.
 */

#include "idemIP/idemip_config.h"

#include <stdio.h>

#define ROW(name) printf("  %-28s %7zu\n", #name, (size_t)(name))

int main(void)
{
    printf("idemIP borrows, at the counts in idemip_config.h\n\n");

    printf("shared, one table across every interface:\n");
    ROW(IDEMIP_NETIF_BORROW);
    ROW(IDEMIP_LOOPIF_BORROW);
    ROW(IDEMIP_ARP_BORROW);
    ROW(IDEMIP_IP4_ROUTE_BORROW);
    ROW(IDEMIP_IP4_REASS_BORROW);
    ROW(IDEMIP_IGMP_BORROW);
    ROW(IDEMIP_IP6_REASS_BORROW);
    ROW(IDEMIP_MLD6_BORROW);
    ROW(IDEMIP_RAW_PCB_BORROW);
    ROW(IDEMIP_UDP_PCB_BORROW);
    ROW(IDEMIP_TCP_PCB_BORROW);
    ROW(IDEMIP_TCP_IN_BORROW);
    ROW(IDEMIP_TCP_OUT_BORROW);
    ROW(IDEMIP_TCP_ISN_BORROW);
    ROW(IDEMIP_DNS_BORROW);
    ROW(IDEMIP_TIMEOUTS_BORROW);
    ROW(IDEMIP_STATS_BORROW);
    ROW(IDEMIP_VLAN_BORROW);
    ROW(IDEMIP_ETHIP6_BORROW);
    printf("  %-28s %7zu\n\n", "= IDEMIP_SHARED_BORROW", (size_t)IDEMIP_SHARED_BORROW);

    printf("per interface, taken IDEMIP_NETIF_COUNT times:\n");
    ROW(IDEMIP_PHY_BORROW);
    ROW(IDEMIP_DMA_BORROW);
    ROW(IDEMIP_ND6_BORROW);
    ROW(IDEMIP_ACD_BORROW);
    ROW(IDEMIP_AUTOIP_BORROW);
    ROW(IDEMIP_DHCP4_BORROW);
    ROW(IDEMIP_DHCP6_BORROW);
    printf("  %-28s %7zu  x %u\n\n", "= IDEMIP_PER_NETIF_BORROW",
           (size_t)IDEMIP_PER_NETIF_BORROW, (unsigned)IDEMIP_NETIF_COUNT);

    printf("  %-28s %7zu\n", "IDEMIP_TOTAL_BORROW", (size_t)IDEMIP_TOTAL_BORROW);

    printf("\nnot counted: the driver's frame buffers (%u octets each, stride %zu),\n",
           (unsigned)IDEMIP_DMA_FRAME_MAX, (size_t)IDEMIP_DMA_BUF_STRIDE);
    printf("             and the caller's stack.\n");
    return 0;
}
