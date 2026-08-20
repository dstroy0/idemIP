// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file raw_pcb.c
 * @brief The RFC 1122 sec 3.4 raw binding table, in the caller's borrow.
 *
 * The context and the table are regions of the one pointer each entry is handed, at compile-time
 * offsets, and no entry reads or writes a byte outside it. Two borrows therefore share nothing, and
 * the same call on the same borrow does the same thing.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/raw/raw_pcb.h"

#if IDEMIP_ENABLE_IPV6
#include "src/ip/ipv6.h" // IDEMIP_IP6_NH_ICMPV6, the Next Header value RFC 3542 sec 3.1 excludes
#endif

IDEMIP_BEGIN_DECLS

// One binding: the RFC 1122 sec 3.4 SEND parameters src, dst, prot, TOS and TTL, the RFC 4007 sec 6
// zone of each address, the interface it is pinned to, its option bits, and the RFC 3542 sec 3.1
// IPV6_CHECKSUM offset.
typedef struct
{
    uint8_t local_ip[IDEMIP_RAW_PCB_ADDR_BYTES];
    uint8_t remote_ip[IDEMIP_RAW_PCB_ADDR_BYTES];
    int16_t cksum_offset;
    uint8_t local_zone;
    uint8_t remote_zone;
    uint8_t netif;
    uint8_t proto;
    uint8_t tos;
    uint8_t ttl;
    uint8_t flags;
    uint8_t ip_version;
    idemip_bool connected;
    idemip_bool in_use;
} RawPcbFields;

// Entry i sits at (i << IDEMIP_RAW_PCB_ENTRY_SHIFT), so the entry is exactly that wide.
typedef union
{
    RawPcbFields f;
    uint8_t raw[1u << IDEMIP_RAW_PCB_ENTRY_SHIFT];
} RawPcbEntry;

static_assert(sizeof(RawPcbEntry) == (1u << IDEMIP_RAW_PCB_ENTRY_SHIFT),
              "a raw binding must be 1 << IDEMIP_RAW_PCB_ENTRY_SHIFT wide - raise the shift in idemip_config.h");
static_assert(sizeof(RawPcbFields) <= sizeof(RawPcbEntry),
              "the RFC 1122 sec 3.4 field set outgrew one entry - raise IDEMIP_RAW_PCB_ENTRY_SHIFT");

// The one definition, private to this TU. A borrow that was never cleared carries no mark, so every
// entry refuses it rather than reading a table that was never zeroed.
typedef struct
{
    uint32_t ready;
} RawPcbCtx;

// The mark clear leaves.
#define RAW_PCB_READY 0x52415750u

// The caller's borrow, split: the operand block, the context, then the table. raw_pcb.h publishes
// the offsets; the asserts below prove the span covers them before anything runs.
static_assert(IDEMIP_RAW_PCB_OFF_CTX + sizeof(RawPcbCtx) <= IDEMIP_RAW_PCB_CTX_BYTES,
              "IDEMIP_RAW_PCB_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_RAW_PCB_OFF_TAB + (IDEMIP_RAW_PCBS << IDEMIP_RAW_PCB_ENTRY_SHIFT) <= IDEMIP_RAW_PCB_BORROW,
              "IDEMIP_RAW_PCB_BORROW is short of the context and the table - raise it in idemip_config.h");

// Every index reported through the operand block is 16 bits, so the table may hold no more entries
// than that, and IDEMIP_RAW_PCB_NONE must name none of them.
static_assert(IDEMIP_RAW_PCBS < IDEMIP_RAW_PCB_NONE,
              "the table outgrew the 16-bit index the operand block reports");

// The regions, at their offsets in the caller's borrow.
#define RAW_PCB_CTX(w) ((RawPcbCtx *)(void *)((w) + IDEMIP_RAW_PCB_OFF_CTX))
#define RAW_PCB_IO(w) IDEMIP_RAW_PCB_IO(w)
#define RAW_PCB_AT(w, i)                                                                                               \
    ((RawPcbEntry *)(void *)((w) + IDEMIP_RAW_PCB_OFF_TAB + ((size_t)(i) << IDEMIP_RAW_PCB_ENTRY_SHIFT)))

// RFC 791 sec 3.1 Source Address and Destination Address are four octets each; RFC 4291 sec 2
// addresses are sixteen. A version this build does not carry measures zero.
#define RAW_PCB_ADDR4_BYTES 4u

// RFC 3542 sec 3.1: "Setting the offset to -1 also disables the option."
#define RAW_PCB_CKSUM_OFF_NONE ((int16_t)-1)

// What a find ranks a candidate by. A binding whose remote the source matched outranks one that
// named no remote, and a binding whose local address the destination matched exactly outranks a
// wildcard, the precedence lwIP states at src/core/udp.c:249-252 and applies at src/core/udp.c:281.
#define RAW_PCB_SCORE_REMOTE 2u
#define RAW_PCB_SCORE_LOCAL 1u

// --- the address rules -----------------------------------------------------

// Four octets for RFC 791 sec 3.1, sixteen for RFC 4291 sec 2, zero for a version this build has no
// layer for, which every caller reads as a refusal.
static size_t raw_pcb_addr_len(uint8_t ip_version)
{
#if IDEMIP_ENABLE_IPV4
    if (ip_version == 4u)
    {
        return RAW_PCB_ADDR4_BYTES;
    }
#endif
#if IDEMIP_ENABLE_IPV6
    if (ip_version == 6u)
    {
        return IDEMIP_RAW_PCB_ADDR_BYTES;
    }
#endif
    return 0u;
}

// RFC 1122 sec 3.2.1.3 (a) { 0, 0 } and RFC 4291 sec 2.5.2's unspecified address are all-zero
// octets. A binding holding one names no address, and a find matches it against any.
static idemip_bool raw_pcb_is_any(const uint8_t *addr, size_t len)
{
    return idemip_bytes_zero(addr, len);
}

// RFC 1122 sec 3.2.1.3: "the IP source address MUST be one of its own IP addresses (but not a
// broadcast or multicast address)". A leading 1110 is that section's Class D multicast, and
// { -1, -1 } is its (c) limited broadcast, "It MUST NOT be used as a source address". RFC 4291
// sec 2.7: "Multicast addresses must not be used as source addresses in IPv6 packets", which
// sec 2.7's figure identifies by a leading 11111111.
static idemip_bool raw_pcb_src_allowed(uint8_t ip_version, const uint8_t *addr)
{
    if (ip_version == 4u)
    {
        if ((addr[0] & 0xF0u) == 0xE0u)
        {
            return IDEMIP_FALSE;
        }
        if (addr[0] == 0xFFu && addr[1] == 0xFFu && addr[2] == 0xFFu && addr[3] == 0xFFu)
        {
            return IDEMIP_FALSE;
        }
        return IDEMIP_TRUE;
    }
    return (addr[0] == 0xFFu) ? IDEMIP_FALSE : IDEMIP_TRUE;
}

// RFC 4007 sec 6 qualifies a non-global address by a zone index, since "the same non-global address
// may be in use in more than one zone of the same scope". Index zero is that section's default
// zone, which names no one zone, so a binding carrying it is compared on the octets alone. Only an
// RFC 4291 address is scoped.
static idemip_bool raw_pcb_zone_ok(uint8_t ip_version, uint8_t entry_zone, uint8_t dgram_zone)
{
    if (ip_version != 6u || entry_zone == 0u)
    {
        return IDEMIP_TRUE;
    }
    return (entry_zone == dgram_zone) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- the statics the entries delegate to -----------------------------------

// Takes the first entry no open holds, initialized to the RFC 1122 sec 3.2.1.6 TOS default, "all
// zero bits", a nonzero TTL since sec 3.2.1.7 states "A host MUST NOT send a datagram with a
// Time-to-Live (TTL) value of zero", and the RFC 3542 sec 3.1 checksum offset "By default, this
// socket option is disabled".
static void raw_pcb_take(uint8_t *restrict work, uint8_t proto, uint8_t ip_version)
{
    RawPcbIo *io = RAW_PCB_IO(work);
    for (uint16_t i = 0; i < (uint16_t)IDEMIP_RAW_PCBS; i++)
    {
        RawPcbEntry *e = RAW_PCB_AT(work, i);
        if (e->f.in_use)
        {
            continue;
        }
        memset(e->raw, 0, sizeof e->raw);
        e->f.proto = proto;
        e->f.ip_version = ip_version;
        e->f.tos = 0u;
        e->f.ttl = (uint8_t)IDEMIP_IP_DEFAULT_TTL;
        e->f.cksum_offset = RAW_PCB_CKSUM_OFF_NONE;
        e->f.in_use = IDEMIP_TRUE;
        io->index = i;
        io->status = IDEMIP_OK;
        return;
    }
    // Every entry is held. A close frees one, so the caller comes back on a later tick.
    io->status = IDEMIP_BUSY;
}

// Writes the RFC 1122 sec 3.4 SEND parameter src, its RFC 4007 sec 6 zone, and the interface an
// inbound datagram must have arrived on for this binding to match it.
static void raw_pcb_set_local(uint8_t *restrict work, const RawPcbAddrArgs *args)
{
    RawPcbIo *io = RAW_PCB_IO(work);
    RawPcbEntry *e = RAW_PCB_AT(work, args->index);
    if (!e->f.in_use)
    {
        return;
    }
    size_t len = raw_pcb_addr_len(e->f.ip_version);
    if (len == 0u || !raw_pcb_src_allowed(e->f.ip_version, args->ip))
    {
        return;
    }
    memset(e->f.local_ip, 0, sizeof e->f.local_ip);
    memcpy(e->f.local_ip, args->ip, len);
    e->f.local_zone = args->zone;
    e->f.netif = args->netif;
    io->status = IDEMIP_OK;
}

// Writes the RFC 1122 sec 3.4 SEND parameter dst and its RFC 4007 sec 6 zone, and marks the binding
// connected so a find requires the datagram's source to be it.
static void raw_pcb_set_remote(uint8_t *restrict work, const RawPcbAddrArgs *args)
{
    RawPcbIo *io = RAW_PCB_IO(work);
    RawPcbEntry *e = RAW_PCB_AT(work, args->index);
    if (!e->f.in_use)
    {
        return;
    }
    size_t len = raw_pcb_addr_len(e->f.ip_version);
    if (len == 0u)
    {
        return;
    }
    // RFC 1122 sec 3.2.1.3 (a) { 0, 0 } "MUST NOT be sent, except as a source address", and RFC 4291
    // sec 2.5.2 "The unspecified address must not be used as the destination address of IPv6
    // packets". disconnect is the entry that leaves a binding with no dst.
    if (raw_pcb_is_any(args->ip, len))
    {
        return;
    }
    memset(e->f.remote_ip, 0, sizeof e->f.remote_ip);
    memcpy(e->f.remote_ip, args->ip, len);
    e->f.remote_zone = args->zone;
    e->f.connected = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

// RFC 3542 sec 3.1 admits -1, "Setting the offset to -1 also disables the option", and an even
// offset: "specifying a positive odd value as offset is invalid". The option is IPV6_CHECKSUM, and
// that section fails it on a socket that is not a raw IPv6 one and on an ICMPv6 one, "since this
// checksum is mandatory" and the kernel writes it.
static idemip_bool raw_pcb_cksum_ok(const RawPcbEntry *e, int16_t offset)
{
    if (offset == RAW_PCB_CKSUM_OFF_NONE)
    {
        return IDEMIP_TRUE;
    }
    if (offset < 0 || (offset & 1) != 0)
    {
        return IDEMIP_FALSE;
    }
    if (e->f.ip_version != 6u)
    {
        return IDEMIP_FALSE;
    }
#if IDEMIP_ENABLE_IPV6
    if (e->f.proto == IDEMIP_IP6_NH_ICMPV6)
    {
        return IDEMIP_FALSE;
    }
#endif
    return IDEMIP_TRUE;
}

// Reports every RFC 1122 sec 3.4 SEND parameter the entry carries. The two addresses point into the
// entry, which is this borrow.
static void raw_pcb_read(uint8_t *restrict work, uint16_t index)
{
    RawPcbIo *io = RAW_PCB_IO(work);
    RawPcbEntry *e = RAW_PCB_AT(work, index);
    if (!e->f.in_use)
    {
        return;
    }
    io->info.local_ip = e->f.local_ip;
    io->info.remote_ip = e->f.remote_ip;
    io->info.cksum_offset = e->f.cksum_offset;
    io->info.local_zone = e->f.local_zone;
    io->info.remote_zone = e->f.remote_zone;
    io->info.netif = e->f.netif;
    io->info.proto = e->f.proto;
    io->info.tos = e->f.tos;
    io->info.ttl = e->f.ttl;
    io->info.flags = e->f.flags;
    io->info.ip_version = e->f.ip_version;
    io->info.connected = e->f.connected;
    io->status = IDEMIP_OK;
}

// Scores one binding against the RFC 1122 sec 3.4 RECV parameters prot, dst and src. The Protocol
// field of RFC 791 sec 3.1 selects the binding; the interface the datagram arrived on is a filter,
// not a rank, as lwIP applies it at src/core/raw.c:74-77. A binding whose src is all-zero is the
// wildcard and matches any destination, per RFC 1122 sec 3.2.1.3 (a). One with no dst matches any
// source, one with a dst matches only that source.
static idemip_bool raw_pcb_score(const RawPcbEntry *e, const RawPcbFindArgs *a, uint8_t *score)
{
    if (!e->f.in_use || e->f.ip_version != a->ip_version || e->f.proto != a->proto)
    {
        return IDEMIP_FALSE;
    }
    if (e->f.netif != 0u && e->f.netif != a->netif)
    {
        return IDEMIP_FALSE;
    }
    size_t len = raw_pcb_addr_len(e->f.ip_version);
    if (len == 0u)
    {
        return IDEMIP_FALSE;
    }
    uint8_t s = 0u;
    if (!raw_pcb_is_any(e->f.local_ip, len))
    {
        if (!idemip_bytes_eq(e->f.local_ip, a->local_ip, len) ||
            !raw_pcb_zone_ok(e->f.ip_version, e->f.local_zone, a->local_zone))
        {
            return IDEMIP_FALSE;
        }
        s = (uint8_t)(s + RAW_PCB_SCORE_LOCAL);
    }
    if (e->f.connected)
    {
        if (!idemip_bytes_eq(e->f.remote_ip, a->remote_ip, len) ||
            !raw_pcb_zone_ok(e->f.ip_version, e->f.remote_zone, a->remote_zone))
        {
            return IDEMIP_FALSE;
        }
        s = (uint8_t)(s + RAW_PCB_SCORE_REMOTE);
    }
    *score = s;
    return IDEMIP_TRUE;
}

// Walks the table once and keeps the highest-scoring binding, the lowest index breaking a tie.
static void raw_pcb_scan(uint8_t *restrict work)
{
    RawPcbIo *io = RAW_PCB_IO(work);
    const RawPcbFindArgs *a = &io->find_args;
    uint16_t best = IDEMIP_RAW_PCB_NONE;
    uint8_t best_score = 0u;
    for (uint16_t i = 0; i < (uint16_t)IDEMIP_RAW_PCBS; i++)
    {
        uint8_t score = 0u;
        if (!raw_pcb_score(RAW_PCB_AT(work, i), a, &score))
        {
            continue;
        }
        if (best == IDEMIP_RAW_PCB_NONE || score > best_score)
        {
            best = i;
            best_score = score;
        }
    }
    if (best == IDEMIP_RAW_PCB_NONE)
    {
        return;
    }
    io->index = best;
    io->status = IDEMIP_OK;
}

// --- the entries -----------------------------------------------------------

// The context and the table are contiguous from IDEMIP_RAW_PCB_OFF_CTX to the end of the borrow, so
// one store covers both. The operand block is the caller's and is left as it was found, except for
// the members a call reports through.
static void raw_pcb_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    memset(work + IDEMIP_RAW_PCB_OFF_CTX, 0, (size_t)IDEMIP_RAW_PCB_BORROW - IDEMIP_RAW_PCB_OFF_CTX);
    RAW_PCB_CTX(work)->ready = RAW_PCB_READY;
    memset(&io->info, 0, sizeof io->info);
    io->index = IDEMIP_RAW_PCB_NONE;
    io->status = IDEMIP_OK;
}

// A version with no IP layer in this build can never be bound, so it is ERR. A table with every
// entry held is BUSY, since a close frees one and the same call then succeeds.
static void raw_pcb_open(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_RAW_PCB_NONE;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY)
    {
        return;
    }
    // RFC 1122 sec 3.4 SEND(src, dst, prot, ...), the prot one binding answers on. RFC 791 sec 3.1
    // gives it eight bits and names no reserved value, so every one of them binds.
    if (raw_pcb_addr_len(io->open_args.ip_version) == 0u)
    {
        return;
    }
    raw_pcb_take(work, io->open_args.proto, io->open_args.ip_version);
}

// An entry no open holds is ERR: a close cannot start succeeding on it, only another open can.
static void raw_pcb_close(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->pcb_args.index >= IDEMIP_RAW_PCBS)
    {
        return;
    }
    // RFC 1122 sec 3.4, releasing the binding a prot was opened on
    RawPcbEntry *e = RAW_PCB_AT(work, io->pcb_args.index);
    if (!e->f.in_use)
    {
        return;
    }
    memset(e->raw, 0, sizeof e->raw);
    io->status = IDEMIP_OK;
}

// An address no host may send from is ERR: no later call makes it sendable.
static void raw_pcb_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->bind_args.index >= IDEMIP_RAW_PCBS ||
        io->bind_args.ip == NULL)
    {
        return;
    }
    // RFC 1122 sec 3.4 SEND's src, and RFC 1122 sec 3.2.1.3 on which addresses are the host's own
    raw_pcb_set_local(work, &io->bind_args);
}

static void raw_pcb_connect(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->connect_args.index >= IDEMIP_RAW_PCBS ||
        io->connect_args.ip == NULL)
    {
        return;
    }
    // RFC 1122 sec 3.4 SEND's dst
    raw_pcb_set_remote(work, &io->connect_args);
}

static void raw_pcb_disconnect(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->pcb_args.index >= IDEMIP_RAW_PCBS)
    {
        return;
    }
    // RFC 1122 sec 3.4 SEND's dst, cleared so the binding sends to any destination
    RawPcbEntry *e = RAW_PCB_AT(work, io->pcb_args.index);
    if (!e->f.in_use)
    {
        return;
    }
    memset(e->f.remote_ip, 0, sizeof e->f.remote_ip);
    e->f.remote_zone = 0u;
    e->f.connected = IDEMIP_FALSE;
    io->status = IDEMIP_OK;
}

// A TTL of zero and an offset RFC 3542 sec 3.1 fails are both ERR: the operand is what is wrong, and
// the same operand fails again on any later tick.
static void raw_pcb_set_opts(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->opt_args.index >= IDEMIP_RAW_PCBS)
    {
        return;
    }
    // RFC 1122 sec 3.4 TOS and TTL, and RFC 3542 sec 3.1's even IPV6_CHECKSUM offset
    RawPcbEntry *e = RAW_PCB_AT(work, io->opt_args.index);
    if (!e->f.in_use)
    {
        return;
    }
    // RFC 1122 sec 3.2.1.7: "A host MUST NOT send a datagram with a Time-to-Live (TTL) value of
    // zero." Over IPv6 the field is the RFC 8200 sec 3 Hop Limit, which sec 3 discards at zero.
    if (io->opt_args.ttl == 0u || !raw_pcb_cksum_ok(e, io->opt_args.cksum_offset))
    {
        return;
    }
    e->f.tos = io->opt_args.tos;
    e->f.ttl = io->opt_args.ttl;
    e->f.flags = io->opt_args.flags;
    e->f.cksum_offset = io->opt_args.cksum_offset;
    io->status = IDEMIP_OK;
}

static void raw_pcb_load(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    memset(&io->info, 0, sizeof io->info);
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->pcb_args.index >= IDEMIP_RAW_PCBS)
    {
        return;
    }
    // RFC 1122 sec 3.4, reporting one binding's SEND parameters
    raw_pcb_read(work, io->pcb_args.index);
}

// No binding is ERR, never BUSY: the table is the whole answer, so the same call on the same table
// reports the same thing however long the caller waits.
static void raw_pcb_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RawPcbIo *io = RAW_PCB_IO(work);
    io->status = IDEMIP_ERR;
    io->index = IDEMIP_RAW_PCB_NONE;
    if (RAW_PCB_CTX(work)->ready != RAW_PCB_READY || io->find_args.local_ip == NULL ||
        io->find_args.remote_ip == NULL)
    {
        return;
    }
    // RFC 1122 sec 3.4 RECV(BufPTR, prot => result, src, dst, SpecDest, TOS, len, opt)
    if (raw_pcb_addr_len(io->find_args.ip_version) == 0u)
    {
        return;
    }
    raw_pcb_scan(work);
}

const RawPcbNs RawPcb = {.clear = raw_pcb_clear,
                         .open = raw_pcb_open,
                         .close = raw_pcb_close,
                         .bind = raw_pcb_bind,
                         .connect = raw_pcb_connect,
                         .disconnect = raw_pcb_disconnect,
                         .set_opts = raw_pcb_set_opts,
                         .load = raw_pcb_load,
                         .find = raw_pcb_find};

IDEMIP_END_DECLS
