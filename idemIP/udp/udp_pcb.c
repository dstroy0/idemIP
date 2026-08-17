// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file udp_pcb.c
 * @brief The RFC 768 binding table, in the caller's borrow.
 *
 * The context and the table are regions of the one pointer each entry is handed, at compile-time
 * offsets, and no entry reads or writes a byte outside it. Two borrows therefore share nothing, and
 * the same call on the same borrow does the same thing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_UDP

#include "idemIP/udp/udp_pcb.h"

IDEMIP_BEGIN_DECLS

// One binding: the RFC 768 Source Port and Destination Port with the addresses they belong to, the
// RFC 4007 sec 6 zone of each address, the RFC 1122 sec 3.4 Type-of-Service and Time-to-Live, the
// RFC 1112 sec 6.1 multicast time-to-live and outgoing interface, and the two RFC 3828 sec 3.1
// Checksum Coverage lengths.
typedef struct
{
    uint8_t local_ip[IDEMIP_UDP_PCB_ADDR_BYTES];
    uint8_t remote_ip[IDEMIP_UDP_PCB_ADDR_BYTES];
    uint16_t local_port;
    uint16_t remote_port;
    uint16_t cksum_len_tx;
    uint16_t cksum_len_rx;
    uint8_t local_zone;
    uint8_t remote_zone;
    uint8_t netif;
    uint8_t tos;
    uint8_t ttl;
    uint8_t mcast_ttl;
    uint8_t mcast_netif;
    uint8_t flags;
    uint8_t ip_version;
    idemip_bool lite;
    idemip_bool connected;
    idemip_bool in_use;
} UdpPcbFields;

// Entry i sits at (i << IDEMIP_UDP_PCB_ENTRY_SHIFT), so the entry is exactly that wide.
typedef union
{
    UdpPcbFields f;
    uint8_t raw[1u << IDEMIP_UDP_PCB_ENTRY_SHIFT];
} UdpPcbEntry;

static_assert(sizeof(UdpPcbEntry) == (1u << IDEMIP_UDP_PCB_ENTRY_SHIFT),
              "a UDP binding must be 1 << IDEMIP_UDP_PCB_ENTRY_SHIFT wide - raise the shift in idemip_config.h");
static_assert(sizeof(UdpPcbFields) <= sizeof(UdpPcbEntry),
              "the RFC 768 field set outgrew one entry - raise IDEMIP_UDP_PCB_ENTRY_SHIFT");

// The one definition, private to this TU. A borrow that was never cleared carries no mark, so every
// entry refuses it rather than reading a table that was never zeroed. next_port is where a bind of
// IDEMIP_UDP_PCB_PORT_ANY starts looking, RFC 768 reading a Source Port of zero as "not used".
typedef struct
{
    uint32_t ready;
    uint16_t next_port;
} UdpPcbCtx;

// The mark clear leaves.
#define UDP_PCB_READY 0x55445050u

// The caller's borrow, split: the operand block, the context, then the table. udp_pcb.h publishes
// the offsets; the asserts below prove the span covers them before anything runs.
static_assert(IDEMIP_UDP_PCB_OFF_CTX + sizeof(UdpPcbCtx) <= IDEMIP_UDP_PCB_CTX_BYTES,
              "IDEMIP_UDP_PCB_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_UDP_PCB_OFF_TAB + (IDEMIP_UDP_PCBS << IDEMIP_UDP_PCB_ENTRY_SHIFT) <= IDEMIP_UDP_PCB_BORROW,
              "IDEMIP_UDP_PCB_BORROW is short of the context and the table - raise it in idemip_config.h");

// Every index reported through the operand block is 16 bits, so the table may hold no more entries
// than that, and IDEMIP_UDP_PCB_NONE must name none of them.
static_assert(IDEMIP_UDP_PCBS < IDEMIP_UDP_PCB_NONE,
              "the table outgrew the 16-bit index the operand block reports");

// The regions, at their offsets in the caller's borrow.
#define UDP_PCB_CTX(w) ((UdpPcbCtx *)(void *)((w) + IDEMIP_UDP_PCB_OFF_CTX))
#define UDP_PCB_IO(w) IDEMIP_UDP_PCB_IO(w)
#define UDP_PCB_AT(w, i)                                                                                               \
    ((UdpPcbEntry *)(void *)((w) + IDEMIP_UDP_PCB_OFF_TAB + ((size_t)(i) << IDEMIP_UDP_PCB_ENTRY_SHIFT)))

// --- the entries -----------------------------------------------------------

// The context and the table are contiguous from IDEMIP_UDP_PCB_OFF_CTX to the end of the borrow, so
// one store covers both. The operand block is the caller's and is left as it was found, except for
// the members a call reports through.
static void udp_pcb_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    UdpPcbIo *io = UDP_PCB_IO(work);
    memset(work + IDEMIP_UDP_PCB_OFF_CTX, 0, (size_t)IDEMIP_UDP_PCB_BORROW - IDEMIP_UDP_PCB_OFF_CTX);
    UDP_PCB_CTX(work)->ready = UDP_PCB_READY;
    memset(&io->info, 0, sizeof io->info);
    io->index = IDEMIP_UDP_PCB_NONE;
    io->port = IDEMIP_UDP_PCB_PORT_ANY;
    io->status = IDEMIP_OK;
}

static void udp_pcb_open(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpPcbIo *io = UDP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_UDP_PCB_NONE;
    if (UDP_PCB_CTX(work)->ready != UDP_PCB_READY)
    {
        return;
    }
    // PHASE 3: RFC 768 "the creation of new receive ports"
    io->status = IDEMIP_ERR;
}

static void udp_pcb_close(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpPcbIo *io = UDP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (UDP_PCB_CTX(work)->ready != UDP_PCB_READY || io->pcb_args.index >= IDEMIP_UDP_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 768, releasing a receive port
    io->status = IDEMIP_ERR;
}

static void udp_pcb_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpPcbIo *io = UDP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->port = IDEMIP_UDP_PCB_PORT_ANY;
    if (UDP_PCB_CTX(work)->ready != UDP_PCB_READY || io->bind_args.index >= IDEMIP_UDP_PCBS ||
        io->bind_args.ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 768 Source Port with RFC 1122 sec 4.1.3.6 on which source addresses are the
    // host's own
    io->status = IDEMIP_ERR;
}

static void udp_pcb_connect(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpPcbIo *io = UDP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (UDP_PCB_CTX(work)->ready != UDP_PCB_READY || io->connect_args.index >= IDEMIP_UDP_PCBS ||
        io->connect_args.ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 768 Destination Port, which "has a meaning within the context of a particular
    // internet destination address"
    io->status = IDEMIP_ERR;
}

static void udp_pcb_disconnect(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpPcbIo *io = UDP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (UDP_PCB_CTX(work)->ready != UDP_PCB_READY || io->pcb_args.index >= IDEMIP_UDP_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 768, clearing the Destination Port and address a connect set
    io->status = IDEMIP_ERR;
}

static void udp_pcb_set_opts(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpPcbIo *io = UDP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (UDP_PCB_CTX(work)->ready != UDP_PCB_READY || io->opt_args.index >= IDEMIP_UDP_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 1122 sec 3.4 TOS and TTL, RFC 1112 sec 6.1 multicast TTL and interface, and RFC
    // 3828 sec 3.1's Checksum Coverage of "either 0 or at least 8"
    io->status = IDEMIP_ERR;
}

static void udp_pcb_load(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpPcbIo *io = UDP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    memset(&io->info, 0, sizeof io->info);
    if (UDP_PCB_CTX(work)->ready != UDP_PCB_READY || io->pcb_args.index >= IDEMIP_UDP_PCBS)
    {
        return;
    }
    // PHASE 3: RFC 768 and RFC 1122 sec 4.1.4, reporting one binding's ports and options
    io->status = IDEMIP_ERR;
}

static void udp_pcb_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpPcbIo *io = UDP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_UDP_PCB_NONE;
    if (UDP_PCB_CTX(work)->ready != UDP_PCB_READY || io->find_args.local_ip == NULL ||
        io->find_args.remote_ip == NULL)
    {
        return;
    }
    // PHASE 3: RFC 768 Destination Port with RFC 1122 sec 4.1.3.5's specific-destination address,
    // and RFC 3828 sec 3.1 discarding a coverage of 1 through 7
    io->status = IDEMIP_ERR;
}

const UdpPcbNs UdpPcb = {.clear = udp_pcb_clear,
                         .open = udp_pcb_open,
                         .close = udp_pcb_close,
                         .bind = udp_pcb_bind,
                         .connect = udp_pcb_connect,
                         .disconnect = udp_pcb_disconnect,
                         .set_opts = udp_pcb_set_opts,
                         .load = udp_pcb_load,
                         .find = udp_pcb_find};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_UDP
