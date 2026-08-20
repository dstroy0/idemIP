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

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/udp/udp_pcb.h"

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
// entry refuses it rather than reading a table that was never zeroed.
typedef struct
{
    uint32_t ready;
} UdpPcbCtx;

// The mark clear leaves.
#define UDP_PCB_READY 0x55445050u

// The two versions a binding takes: RFC 791 sec 3.1 Version 4 and RFC 8200 sec 3 Version 6.
#define UDP_PCB_V4 4u
#define UDP_PCB_V6 6u

// RFC 791 sec 3.1 addresses are four octets; RFC 4291 sec 2 ones fill the field.
#define UDP_PCB_ADDR4_BYTES 4u

static_assert(UDP_PCB_ADDR4_BYTES <= IDEMIP_UDP_PCB_ADDR_BYTES,
              "an RFC 791 address must fit the field RFC 4291 sizes (IDEMIP_UDP_PCB_ADDR_BYTES)");

// The ephemeral range laid out as a base and a mask, so a candidate port is an OR and an AND.
#define UDP_PCB_PORT_MASK ((uint16_t)(IDEMIP_UDP_PCB_PORT_LAST - IDEMIP_UDP_PCB_PORT_FIRST))

static_assert((IDEMIP_UDP_PCB_PORT_FIRST & UDP_PCB_PORT_MASK) == 0u,
              "RFC 6335 sec 6's dynamic range must start on its own width for the mask to name it");
static_assert(IDEMIP_UDP_PCB_PORT_LAST == 0xFFFFu, "RFC 6335 sec 6: the dynamic range ends at the 16-bit maximum");
static_assert(IDEMIP_UDP_PCBS <= UDP_PCB_PORT_MASK,
              "the ephemeral walk is IDEMIP_UDP_PCBS + 1 candidates wide, and one of them is free only when the "
              "table holds fewer bindings than RFC 6335 sec 6's range holds ports");

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

// --- the statics -----------------------------------------------------------

// The octets one version's address spans: RFC 791 sec 3.1 gives four, RFC 4291 sec 2 gives sixteen.
static uint8_t udp_pcb_addr_len(uint8_t ip_version)
{
    return (ip_version == UDP_PCB_V6) ? (uint8_t)IDEMIP_UDP_PCB_ADDR_BYTES : (uint8_t)UDP_PCB_ADDR4_BYTES;
}

// True when the two addresses hold the same @p n octets.
static idemip_bool udp_pcb_addr_eq(const uint8_t *a, const uint8_t *b, uint8_t n)
{
    return (memcmp(a, b, (size_t)n) == 0) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// True when the @p n octets are all zero: RFC 1122 sec 3.2.1.3's "{ 0, 0 } This host on this
// network", and RFC 4291 sec 2.5.2's "The address 0:0:0:0:0:0:0:0 ... indicates the absence of an
// address". A local address of that form is the wild one RFC 1122 sec 4.1.3.5 has an application
// leave unspecified.
static idemip_bool udp_pcb_addr_any(const uint8_t *a, uint8_t n)
{
    uint8_t acc = 0u;
    for (uint8_t i = 0u; i < n; i++)
    {
        acc |= a[i];
    }
    return (acc == 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// Stores @p n octets and zeroes the rest of the field, so a version-4 address leaves behind no octet
// of a version-6 one.
static void udp_pcb_addr_store(uint8_t *dst, const uint8_t *src, uint8_t n)
{
    memcpy(dst, src, (size_t)n);
    memset(dst + n, 0, (size_t)IDEMIP_UDP_PCB_ADDR_BYTES - (size_t)n);
}

// The first entry no binding holds, or IDEMIP_UDP_PCB_NONE when every one is open.
static uint16_t udp_pcb_free_entry(uint8_t *restrict work)
{
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_UDP_PCBS; i++)
    {
        if (!UDP_PCB_AT(work, i)->f.in_use)
        {
            return i;
        }
    }
    return IDEMIP_UDP_PCB_NONE;
}

// True when an open entry other than @p skip carries @p port as its RFC 768 Source Port.
static idemip_bool udp_pcb_port_held(uint8_t *restrict work, uint16_t port, uint16_t skip)
{
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_UDP_PCBS; i++)
    {
        const UdpPcbFields *f = &UDP_PCB_AT(work, i)->f;
        if (i != skip && f->in_use && f->local_port == port)
        {
            return IDEMIP_TRUE;
        }
    }
    return IDEMIP_FALSE;
}

// The first port in RFC 6335 sec 6's dynamic range no other open entry holds, or
// IDEMIP_UDP_PCB_PORT_ANY when the walk found none. RFC 6056 sec 3.3.1 Algorithm 1 places the first
// candidate at "min_ephemeral + (random() % num_ephemeral)" and walks from there, and sec 3.3 makes
// the obfuscation a SHOULD "since this helps to mitigate a number of attacks that depend on the
// attacker's ability to guess or know the five-tuple". The range is a power of two wide, so the
// modulo is an AND and the wrap is an AND and an OR: no divide runs. A walk from where the last
// assignment left off is guessable from one observed port.
static uint16_t udp_pcb_free_port(uint8_t *restrict work, uint16_t skip, uint32_t rand)
{
    for (uint16_t n = 0u; n <= (uint16_t)IDEMIP_UDP_PCBS; n++)
    {
        uint16_t step = (uint16_t)(((uint16_t)rand + n) & UDP_PCB_PORT_MASK);
        uint16_t port = (uint16_t)(IDEMIP_UDP_PCB_PORT_FIRST | step);
        if (!udp_pcb_port_held(work, port, skip))
        {
            return port;
        }
    }
    return IDEMIP_UDP_PCB_PORT_ANY;
}

// True when two endpoints name the same address in the same RFC 4007 sec 6 zone. Two unspecified
// addresses are the same endpoint; an unspecified one and a named one are not.
static idemip_bool udp_pcb_addr_same(const uint8_t *a, uint8_t az, const uint8_t *b, uint8_t bz, uint8_t n)
{
    return (udp_pcb_addr_eq(a, b, n) && az == bz) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// True when two interface pins admit a common datagram: either takes any, or both take the one.
static idemip_bool udp_pcb_netif_overlap(uint8_t a, uint8_t b)
{
    return (a == 0u || b == 0u || a == b) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// True when an open entry other than @p skip already carries the identity a bind of @p port with
// operand @p a would give entry @p e: the same version, the same RFC 768 Source Port on the same
// address in the same zone, an overlapping interface, and the same Destination Port and address. Two
// entries carrying it rank the same in a find, so nothing separates them and the second is refused.
// A Source Port of zero is RFC 768's "not used", so an entry no bind has named collides with none.
static idemip_bool udp_pcb_bind_taken(uint8_t *restrict work, uint16_t skip, const UdpPcbFields *e,
                                      const UdpPcbAddrArgs *a, uint16_t port)
{
    uint8_t n = udp_pcb_addr_len(e->ip_version);
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_UDP_PCBS; i++)
    {
        const UdpPcbFields *o = &UDP_PCB_AT(work, i)->f;
        if (i == skip || !o->in_use || o->ip_version != e->ip_version || o->local_port != port ||
            o->connected != e->connected)
        {
            continue;
        }
        if (!udp_pcb_addr_same(o->local_ip, o->local_zone, a->ip, a->zone, n) ||
            !udp_pcb_netif_overlap(o->netif, a->netif))
        {
            continue;
        }
        if (!e->connected || (udp_pcb_addr_same(o->remote_ip, o->remote_zone, e->remote_ip, e->remote_zone, n) &&
                              o->remote_port == e->remote_port))
        {
            return IDEMIP_TRUE;
        }
    }
    return IDEMIP_FALSE;
}

// True when an open entry other than @p skip already carries the identity a connect with operand
// @p a would give entry @p e, on the same terms as udp_pcb_bind_taken.
static idemip_bool udp_pcb_connect_taken(uint8_t *restrict work, uint16_t skip, const UdpPcbFields *e,
                                         const UdpPcbAddrArgs *a)
{
    uint8_t n = udp_pcb_addr_len(e->ip_version);
    uint8_t netif = (a->netif != 0u) ? a->netif : e->netif;
    if (e->local_port == (uint16_t)IDEMIP_UDP_PCB_PORT_ANY)
    {
        return IDEMIP_FALSE;
    }
    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_UDP_PCBS; i++)
    {
        const UdpPcbFields *o = &UDP_PCB_AT(work, i)->f;
        if (i == skip || !o->in_use || o->ip_version != e->ip_version || o->local_port != e->local_port ||
            !o->connected || o->remote_port != a->port)
        {
            continue;
        }
        if (udp_pcb_addr_same(o->local_ip, o->local_zone, e->local_ip, e->local_zone, n) &&
            udp_pcb_addr_same(o->remote_ip, o->remote_zone, a->ip, a->zone, n) &&
            udp_pcb_netif_overlap(o->netif, netif))
        {
            return IDEMIP_TRUE;
        }
    }
    return IDEMIP_FALSE;
}

// The entry's local endpoint admits the datagram's destination: an unspecified address takes any,
// which is RFC 1122 sec 4.1.3.5's wild local address, and a specific one takes only its own octets
// in its own RFC 4007 sec 6 zone.
static idemip_bool udp_pcb_local_admits(const UdpPcbFields *f, const UdpPcbFindArgs *a, uint8_t n)
{
    if (udp_pcb_addr_any(f->local_ip, n))
    {
        return IDEMIP_TRUE;
    }
    return (udp_pcb_addr_eq(f->local_ip, a->local_ip, n) && f->local_zone == a->local_zone) ? IDEMIP_TRUE
                                                                                           : IDEMIP_FALSE;
}

// The entry's remote endpoint admits the datagram's source: a connected binding takes only the
// RFC 768 Source Port and address its connect set, in that address's zone.
static idemip_bool udp_pcb_remote_admits(const UdpPcbFields *f, const UdpPcbFindArgs *a, uint8_t n)
{
    return (f->remote_port == a->remote_port && udp_pcb_addr_eq(f->remote_ip, a->remote_ip, n) &&
            f->remote_zone == a->remote_zone)
               ? IDEMIP_TRUE
               : IDEMIP_FALSE;
}

// The entry accepts the coverage the datagram arrived with. RFC 3828 sec 3.1: "A Checksum Coverage
// of zero indicates that the entire UDP-Lite packet is covered by the checksum", so zero clears any
// minimum and is also what an RFC 768 datagram reports. A partial coverage reaches only a UDP-Lite
// binding, protocol 136 by RFC 3828 sec 7, and only one whose minimum it meets, sec 3.3 letting an
// application "block delivery of packets with coverage values less than a value provided by the
// application".
static idemip_bool udp_pcb_cov_admits(const UdpPcbFields *f, uint16_t cov)
{
    if (cov == (uint16_t)IDEMIP_UDPLITE_COV_ALL)
    {
        return IDEMIP_TRUE;
    }
    if (!f->lite)
    {
        return IDEMIP_FALSE;
    }
    // sec 3.3: "It is RECOMMENDED that the default behavior of UDP-Lite be set to mimic UDP by having
    // the Checksum Coverage field match the length of the UDP-Lite packet and verify the entire
    // packet", and "Applications that wish to receive payloads that were only partially covered by a
    // checksum should inform the receiving system by an explicit system call." A stored coverage of
    // IDEMIP_UDPLITE_COV_ALL is that default and admits nothing partial; a set_opts naming a minimum
    // is the explicit call that lowers it.
    if (f->cksum_len_rx == (uint16_t)IDEMIP_UDPLITE_COV_ALL)
    {
        return IDEMIP_FALSE;
    }
    return (cov >= f->cksum_len_rx) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// The binding a received datagram belongs to, IDEMIP_UDP_PCB_NONE when none does. Every open entry
// bound to the datagram's RFC 768 Destination Port on an admitting interface is ranked: a connected
// binding outranks an unconnected one, and a specific local address outranks the RFC 1122 sec
// 4.1.3.5 wild one, so the most specific binding takes the datagram and the lowest index wins a tie.
// An entry whose Source Port is still zero is not bound, RFC 768 reading that value as "not used",
// and is passed over.
static uint16_t udp_pcb_match(uint8_t *restrict work)
{
    const UdpPcbFindArgs *a = &UDP_PCB_IO(work)->find_args;
    uint8_t n = udp_pcb_addr_len(a->ip_version);
    uint16_t best = IDEMIP_UDP_PCB_NONE;
    uint8_t best_rank = 0u;

    for (uint16_t i = 0u; i < (uint16_t)IDEMIP_UDP_PCBS; i++)
    {
        const UdpPcbFields *f = &UDP_PCB_AT(work, i)->f;
        if (!f->in_use || f->ip_version != a->ip_version || f->local_port == (uint16_t)IDEMIP_UDP_PCB_PORT_ANY ||
            f->local_port != a->local_port)
        {
            continue;
        }
        if (f->netif != 0u && f->netif != a->netif)
        {
            continue;
        }
        if (!udp_pcb_local_admits(f, a, n) || !udp_pcb_cov_admits(f, a->cksum_len))
        {
            continue;
        }
        if (f->connected && !udp_pcb_remote_admits(f, a, n))
        {
            continue;
        }

        uint8_t rank = (uint8_t)((f->connected ? 2u : 0u) | (udp_pcb_addr_any(f->local_ip, n) ? 0u : 1u));
        if (best == IDEMIP_UDP_PCB_NONE || rank > best_rank)
        {
            best = i;
            best_rank = rank;
        }
    }
    return best;
}

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

// Takes a free entry and stamps the defaults onto it: RFC 1122 sec 3.2.1.7's configurable
// Time-to-Live, and RFC 1112 sec 6.1's multicast time-to-live, which "should default to 1 for all
// multicast IP datagrams". RFC 3828 sec 3.3 recommends "the default behavior of UDP-Lite be set to
// mimic UDP", which is the full coverage a Checksum Coverage of zero names. A version other than
// RFC 791 sec 3.1's 4 and RFC 8200 sec 3's 6 is ERR, no retry making it one of them. A table with
// every entry open is BUSY, since a close frees one.
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
    if (io->open_args.ip_version != UDP_PCB_V4 && io->open_args.ip_version != UDP_PCB_V6)
    {
        return;
    }
    // RFC 768 "the creation of new receive ports"
    uint16_t i = udp_pcb_free_entry(work);
    if (i == IDEMIP_UDP_PCB_NONE)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    UdpPcbEntry *e = UDP_PCB_AT(work, i);
    memset(e->raw, 0, sizeof e->raw);
    e->f.ip_version = io->open_args.ip_version;
    e->f.lite = io->open_args.lite ? IDEMIP_TRUE : IDEMIP_FALSE;
    e->f.ttl = (uint8_t)IDEMIP_IP_DEFAULT_TTL;
    e->f.mcast_ttl = 1u;
    e->f.local_port = IDEMIP_UDP_PCB_PORT_ANY;
    e->f.remote_port = IDEMIP_UDP_PCB_PORT_ANY;
    e->f.cksum_len_tx = (uint16_t)IDEMIP_UDPLITE_COV_ALL;
    e->f.cksum_len_rx = (uint16_t)IDEMIP_UDPLITE_COV_ALL;
    e->f.in_use = IDEMIP_TRUE;
    io->index = i;
    io->status = IDEMIP_OK;
}

// Zeroes the entry, which is the state open reads as free. An entry that is not open is ERR: no
// retry opens it.
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
    UdpPcbEntry *e = UDP_PCB_AT(work, io->pcb_args.index);
    if (!e->f.in_use)
    {
        return;
    }
    // RFC 768, releasing a receive port
    memset(e->raw, 0, sizeof e->raw);
    io->status = IDEMIP_OK;
}

// Sets the RFC 768 Source Port and the address it belongs to, that port having "a meaning within the
// context of a particular internet destination address", so the pair is the endpoint and not the port
// alone. An endpoint another entry already carries is ERR, since no retry frees it; a port of
// IDEMIP_UDP_PCB_PORT_ANY is assigned one no entry holds out of RFC 6335 sec 6's dynamic range, and a
// range with none left is BUSY, since a close frees one.
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
    UdpPcbEntry *e = UDP_PCB_AT(work, io->bind_args.index);
    if (!e->f.in_use)
    {
        return;
    }
    // RFC 768 Source Port, "If not used, a value of zero is inserted"
    uint16_t port = io->bind_args.port;
    if (port == (uint16_t)IDEMIP_UDP_PCB_PORT_ANY)
    {
        port = udp_pcb_free_port(work, io->bind_args.index, io->bind_args.rand);
        if (port == (uint16_t)IDEMIP_UDP_PCB_PORT_ANY)
        {
            io->status = IDEMIP_BUSY;
            return;
        }
    }
    else if (udp_pcb_bind_taken(work, io->bind_args.index, &e->f, &io->bind_args, port))
    {
        return;
    }
    udp_pcb_addr_store(e->f.local_ip, io->bind_args.ip, udp_pcb_addr_len(e->f.ip_version));
    e->f.local_zone = io->bind_args.zone;
    e->f.netif = io->bind_args.netif;
    e->f.local_port = port;
    io->port = port;
    io->status = IDEMIP_OK;
}

// Sets the RFC 768 Destination Port and the address it belongs to. A port of zero is that field's
// "not used" value on the Source Port only, an unspecified address names no destination at all
// (RFC 4291 sec 2.5.2: it "must not be used as the destination address of IPv6 packets"), and an
// identity another entry already carries leaves the two indistinguishable to a find, so all three are
// ERR. A nonzero interface pins the binding to it.
static void udp_pcb_connect(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    UdpPcbIo *io = UDP_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (UDP_PCB_CTX(work)->ready != UDP_PCB_READY || io->connect_args.index >= IDEMIP_UDP_PCBS ||
        io->connect_args.ip == NULL || io->connect_args.port == (uint16_t)IDEMIP_UDP_PCB_PORT_ANY)
    {
        return;
    }
    UdpPcbEntry *e = UDP_PCB_AT(work, io->connect_args.index);
    if (!e->f.in_use)
    {
        return;
    }
    uint8_t n = udp_pcb_addr_len(e->f.ip_version);
    if (udp_pcb_addr_any(io->connect_args.ip, n) ||
        udp_pcb_connect_taken(work, io->connect_args.index, &e->f, &io->connect_args))
    {
        return;
    }
    udp_pcb_addr_store(e->f.remote_ip, io->connect_args.ip, n);
    e->f.remote_zone = io->connect_args.zone;
    if (io->connect_args.netif != 0u)
    {
        e->f.netif = io->connect_args.netif;
    }
    e->f.remote_port = io->connect_args.port;
    e->f.connected = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

// Zeroes the RFC 768 Destination Port and the address a connect set, leaving the local endpoint and
// its interface as the bind left them.
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
    UdpPcbEntry *e = UDP_PCB_AT(work, io->pcb_args.index);
    if (!e->f.in_use)
    {
        return;
    }
    // RFC 768, clearing the Destination Port and address a connect set
    memset(e->f.remote_ip, 0, sizeof e->f.remote_ip);
    e->f.remote_port = IDEMIP_UDP_PCB_PORT_ANY;
    e->f.remote_zone = 0u;
    e->f.connected = IDEMIP_FALSE;
    io->status = IDEMIP_OK;
}

// Sets the RFC 1122 sec 3.4 mechanisms of one binding. A Time-to-Live of zero is ERR, RFC 1122 sec
// 3.2.1.7 stating "A host MUST NOT send a datagram with a Time-to-Live (TTL) value of zero". A
// Checksum Coverage that is neither zero nor at least eight is ERR, RFC 3828 sec 3.1 stating "the
// value of the Checksum Coverage field MUST be either 0 or at least 8"; so is a nonzero coverage on
// a binding that is not UDP-Lite, RFC 768 carrying a Length in those octets.
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
    UdpPcbEntry *e = UDP_PCB_AT(work, io->opt_args.index);
    // RFC 1122 sec 3.2.1.7: "A host MUST NOT send a datagram with a Time-to-Live (TTL) value of
    // zero." RFC 1112 sec 6.1 calls the multicast operand "the IP time-to-live of an outgoing
    // multicast datagram", which is the same octet, so the same rule refuses it.
    if (!e->f.in_use || io->opt_args.ttl == 0u || io->opt_args.mcast_ttl == 0u)
    {
        return;
    }
    uint16_t tx = io->opt_args.cksum_len_tx;
    uint16_t rx = io->opt_args.cksum_len_rx;
    if ((tx != (uint16_t)IDEMIP_UDPLITE_COV_ALL && tx < (uint16_t)IDEMIP_UDPLITE_COV_MIN) ||
        (rx != (uint16_t)IDEMIP_UDPLITE_COV_ALL && rx < (uint16_t)IDEMIP_UDPLITE_COV_MIN))
    {
        return;
    }
    if (!e->f.lite && (tx != (uint16_t)IDEMIP_UDPLITE_COV_ALL || rx != (uint16_t)IDEMIP_UDPLITE_COV_ALL))
    {
        return;
    }
    e->f.cksum_len_tx = tx;
    e->f.cksum_len_rx = rx;
    e->f.tos = io->opt_args.tos;
    e->f.ttl = io->opt_args.ttl;
    e->f.mcast_ttl = io->opt_args.mcast_ttl;
    e->f.mcast_netif = io->opt_args.mcast_netif;
    e->f.flags = io->opt_args.flags;
    io->status = IDEMIP_OK;
}

// Reports one binding. The two addresses point into the entry, which is a region of this borrow, so
// they stay valid until the next call that writes it.
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
    UdpPcbEntry *e = UDP_PCB_AT(work, io->pcb_args.index);
    if (!e->f.in_use)
    {
        return;
    }
    // RFC 768 and RFC 1122 sec 4.1.4, reporting one binding's ports and options
    io->info.local_ip = e->f.local_ip;
    io->info.remote_ip = e->f.remote_ip;
    io->info.local_port = e->f.local_port;
    io->info.remote_port = e->f.remote_port;
    io->info.cksum_len_tx = e->f.cksum_len_tx;
    io->info.cksum_len_rx = e->f.cksum_len_rx;
    io->info.local_zone = e->f.local_zone;
    io->info.remote_zone = e->f.remote_zone;
    io->info.netif = e->f.netif;
    io->info.tos = e->f.tos;
    io->info.ttl = e->f.ttl;
    io->info.mcast_ttl = e->f.mcast_ttl;
    io->info.mcast_netif = e->f.mcast_netif;
    io->info.flags = e->f.flags;
    io->info.ip_version = e->f.ip_version;
    io->info.lite = e->f.lite;
    io->info.connected = e->f.connected;
    io->status = IDEMIP_OK;
}

// Matches a received datagram to a binding. A coverage of 1 through 7 is ERR, RFC 3828 sec 3.1
// stating "A UDP-Lite packet with a Checksum Coverage value of 1 to 7 MUST be discarded by the
// receiver", and so is a version other than 4 or 6. No binding is ERR too, not BUSY: nothing frees
// later, and it is the RFC 1122 sec 4.1.3.1 case where "UDP SHOULD send an ICMP Port Unreachable
// message".
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
    if (io->find_args.ip_version != UDP_PCB_V4 && io->find_args.ip_version != UDP_PCB_V6)
    {
        return;
    }
    if (io->find_args.cksum_len != (uint16_t)IDEMIP_UDPLITE_COV_ALL &&
        io->find_args.cksum_len < (uint16_t)IDEMIP_UDPLITE_COV_MIN)
    {
        return;
    }
    // RFC 768 Destination Port with RFC 1122 sec 4.1.3.5's specific-destination address
    uint16_t i = udp_pcb_match(work);
    io->index = i;
    io->status = (i == IDEMIP_UDP_PCB_NONE) ? IDEMIP_ERR : IDEMIP_OK;
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
