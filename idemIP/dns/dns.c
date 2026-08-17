// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dns.c
 * @brief The resolver's four tables, and the entries over them.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block, the context, the questions, the answers, the names and the servers are all regions of that
 * borrow, at compile-time offsets, and no entry reads or writes a byte outside it. Every table entry
 * is a power of two wide, so entry i sits at (i << SHIFT) and no index is ever multiplied.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_UDP

#include "idemIP/dns/dns.h"

IDEMIP_BEGIN_DECLS

// The definitions, private to this TU.

/**
 * One outstanding question. RFC 5452 sec 9.1 matches a response on the query ID, the port the
 * question left from, the name, and the class and type, so each of those is here; the server index
 * names the address the same section matches the response's source against.
 */
typedef struct
{
    uint16_t id;
    uint16_t src_port;
    uint16_t type;
    uint16_t qclass;
    uint32_t deadline_ms;
    uint8_t server;
    uint8_t retries;
    uint8_t name; ///< the name region this question asked about
    IdemIpDnsQueryState state;
    uint8_t pad[16];
} DnsQuery;

// One cached answer: the address, the RFC 1035 sec 4.1.3 TTL it was given, and the deadline that TTL
// runs out at.
typedef struct
{
    uint8_t addr[IDEMIP_DNS_ADDR_LEN];
    uint32_t expire_ms;
    uint32_t ttl_s;
    uint16_t type;
    uint8_t name;
    IdemIpDnsEntryState state;
    idemip_bool ipv6;
    uint8_t pad[3];
} DnsEntry;

// One server, from DHCP option 6, RFC 3646 sec 3, or RFC 8106 RDNSS.
typedef struct
{
    uint8_t addr[IDEMIP_DNS_ADDR_LEN];
    uint32_t zone;
    uint16_t port;
    idemip_bool ipv6;
    idemip_bool used;
    uint8_t pad[8];
} DnsServer;

// The running context, outside every table.
typedef struct
{
    const IdemIpDnsCfg *cfg;
    uint32_t now_ms;
    uint8_t next_server; ///< the server the next question goes to first (RFC 1035 sec 4.2.1)
} DnsCtx;

// An index is a shift, so every entry width is a power of two and the struct is padded to it.
static_assert(sizeof(DnsQuery) == (1u << IDEMIP_DNS_QUERY_ENTRY_SHIFT),
              "DnsQuery is not 1 << IDEMIP_DNS_QUERY_ENTRY_SHIFT wide: pad it, or raise the shift");
static_assert(sizeof(DnsEntry) == (1u << IDEMIP_DNS_ENTRY_SHIFT),
              "DnsEntry is not 1 << IDEMIP_DNS_ENTRY_SHIFT wide: pad it, or raise the shift");
static_assert(sizeof(DnsServer) == (1u << IDEMIP_DNS_SERVER_ENTRY_SHIFT),
              "DnsServer is not 1 << IDEMIP_DNS_SERVER_ENTRY_SHIFT wide: pad it, or raise the shift");

// The caller's borrow, split: the operand block and the context in the first IDEMIP_DNS_CTX_BYTES
// octets, then the four tables. dns.h publishes the offsets; the asserts below prove the span covers
// them before anything runs.
static_assert(IDEMIP_DNS_OFF_CTX + sizeof(DnsCtx) <= IDEMIP_DNS_CTX_BYTES,
              "IDEMIP_DNS_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_DNS_OFF_SERVERS + (IDEMIP_DNS_SERVERS << IDEMIP_DNS_SERVER_ENTRY_SHIFT) <= IDEMIP_DNS_BORROW,
              "IDEMIP_DNS_BORROW is short of the context region and the four tables");
static_assert(((IDEMIP_DNS_OFF_CTX | IDEMIP_DNS_OFF_QUERIES | IDEMIP_DNS_OFF_ENTRIES | IDEMIP_DNS_OFF_NAMES |
                IDEMIP_DNS_OFF_SERVERS) &
               (IDEMIP_ALIGN - 1u)) == 0u,
              "every region starts on IDEMIP_ALIGN");

// The regions, at their offsets in the caller's borrow.
#define DNS_CTX(w) ((DnsCtx *)(void *)((w) + IDEMIP_DNS_OFF_CTX))
#define DNS_QUERY_AT(w, i)                                                                                             \
    ((DnsQuery *)(void *)((w) + IDEMIP_DNS_OFF_QUERIES + ((size_t)(i) << IDEMIP_DNS_QUERY_ENTRY_SHIFT)))
#define DNS_ENTRY_AT(w, i)                                                                                             \
    ((DnsEntry *)(void *)((w) + IDEMIP_DNS_OFF_ENTRIES + ((size_t)(i) << IDEMIP_DNS_ENTRY_SHIFT)))
#define DNS_NAME_AT(w, i) ((char *)(void *)((w) + IDEMIP_DNS_OFF_NAMES + ((size_t)(i) << IDEMIP_DNS_NAME_SHIFT)))
#define DNS_SERVER_AT(w, i)                                                                                            \
    ((DnsServer *)(void *)((w) + IDEMIP_DNS_OFF_SERVERS + ((size_t)(i) << IDEMIP_DNS_SERVER_ENTRY_SHIFT)))
#define DNS_IO(w) IDEMIP_DNS_IO(w)

// Octets one name region spans.
#define DNS_NAME_BYTES ((size_t)1u << IDEMIP_DNS_NAME_SHIFT)

// --- the entries -----------------------------------------------------------

// Every byte of the borrow, the operand block included, which leaves every query and every cached
// answer at state zero: free.
static void dns_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work, 0, IDEMIP_DNS_BORROW);
    DNS_IO(work)->status = IDEMIP_OK;
}

static void dns_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DnsIo *io = DNS_IO(work);
    io->status = IDEMIP_ERR;
    const IdemIpDnsCfg *cfg = io->bind_args.cfg;
    if (cfg == NULL || cfg->netif >= IDEMIP_NETIF_COUNT || cfg->retries == 0u)
    {
        return;
    }
    DnsCtx *ctx = DNS_CTX(work);
    ctx->cfg = cfg;
    ctx->next_server = 0u;
    io->status = IDEMIP_OK;
}

// An IPv4 server occupies the first IDEMIP_DNS_A_RDLEN octets of the entry and an IPv6 one all
// IDEMIP_DNS_ADDR_LEN of them, so the entry is zeroed first and the rest of it stays zero.
static void dns_set_server(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    io->status = IDEMIP_ERR;
    if (ctx->cfg == NULL)
    {
        return;
    }
    const DnsServerArgs *a = &io->server_args;
    if (a->addr == NULL || a->index >= IDEMIP_DNS_SERVERS)
    {
        return;
    }
    DnsServer *s = DNS_SERVER_AT(work, a->index);
    memset(s, 0, sizeof *s);
    memcpy(s->addr, a->addr, a->ipv6 ? (size_t)IDEMIP_DNS_ADDR_LEN : (size_t)IDEMIP_DNS_A_RDLEN);
    s->zone = a->zone;
    s->port = (uint16_t)((a->port != 0u) ? a->port : IDEMIP_DNS_PORT);
    s->ipv6 = a->ipv6;
    s->used = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

static void dns_query(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 1035 sec 4.1.2 QNAME, QTYPE and QCLASS, with the RFC 5452 sec 9.2 ID and port
    io->status = IDEMIP_ERR;
}

static void dns_lookup(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 1035 sec 2.3.3, a cached answer matched on a case-insensitive name and its TYPE
    io->status = IDEMIP_ERR;
}

static void dns_build(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    io->len = 0;
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 1035 sec 4.1.1 header and sec 4.1.2 question, the name in sec 3.1 label form
    io->status = IDEMIP_ERR;
}

static void dns_input(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 5452 sec 9.1 match rules, then RFC 1035 sec 4.1.3 answer records into the cache
    io->status = IDEMIP_ERR;
}

static void dns_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 1035 sec 4.2.1 retransmission across servers, and sec 4.1.3 TTL expiry
    io->status = IDEMIP_ERR;
}

// A slot holding no question has nothing to drop, and asking again cannot change that, so it is ERR
// rather than BUSY.
static void dns_cancel(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    io->status = IDEMIP_ERR;
    if (ctx->cfg == NULL || io->cancel_args.query >= IDEMIP_DNS_QUERIES)
    {
        return;
    }
    DnsQuery *q = DNS_QUERY_AT(work, io->cancel_args.query);
    if (q->state == IDEMIP_DNS_QUERY_FREE)
    {
        return;
    }
    memset(DNS_NAME_AT(work, io->cancel_args.query), 0, DNS_NAME_BYTES);
    memset(q, 0, sizeof *q);
    io->status = IDEMIP_OK;
}

// The answer table and the name regions the answers own, which are the ones at and above
// IDEMIP_DNS_QUERIES. The questions and the servers are left as they are.
static void dns_flush(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    io->status = IDEMIP_ERR;
    if (ctx->cfg == NULL)
    {
        return;
    }
    memset(work + IDEMIP_DNS_OFF_ENTRIES, 0, (size_t)IDEMIP_DNS_ENTRIES << IDEMIP_DNS_ENTRY_SHIFT);
    memset(DNS_NAME_AT(work, IDEMIP_DNS_QUERIES), 0, (size_t)IDEMIP_DNS_ENTRIES << IDEMIP_DNS_NAME_SHIFT);
    io->status = IDEMIP_OK;
}

const DnsNs Dns = {.clear = dns_clear,
                   .bind = dns_bind,
                   .set_server = dns_set_server,
                   .query = dns_query,
                   .lookup = dns_lookup,
                   .build = dns_build,
                   .input = dns_input,
                   .tick = dns_tick,
                   .cancel = dns_cancel,
                   .flush = dns_flush};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_UDP
