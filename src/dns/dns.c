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
 *
 * A received message is read where the caller left it and never held: the 4 or 16 answer octets and
 * the name are copied into the cache inside the call, so no descriptor is pinned past dispatch.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/dns/dns.h"
#include "src/endian.h"

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
    uint8_t rcode; ///< the RFC 1035 sec 4.1.1 RCODE the last response to it carried
    uint8_t pad[15];
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

// The name region a cached answer owns: query i owns name i, answer j owns name IDEMIP_DNS_QUERIES + j.
#define DNS_ENTRY_NAME_IDX(j) ((size_t)IDEMIP_DNS_QUERIES + (size_t)(j))

// --- the clock -------------------------------------------------------------

// A deadline is a millisecond count that wraps, so the comparison is on the signed difference and
// holds across the wrap (PLAN sec 5.2).
static idemip_bool dns_reached(uint32_t now_ms, uint32_t deadline_ms)
{
    return ((int32_t)(now_ms - deadline_ms) >= 0) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// --- names -----------------------------------------------------------------

// RFC 1035 sec 3.1: labels are compared "in a case-insensitive manner (i.e., A=a), assuming ASCII
// with zero parity. Non-alphabetic codes must match exactly."
static uint8_t dns_fold(uint8_t c)
{
    return (uint8_t)(((c >= (uint8_t)'A') && (c <= (uint8_t)'Z')) ? (c + 0x20u) : c);
}

/**
 * Step over the RFC 1035 sec 4.1.4 pointers at @p off until a length octet stands there.
 *
 * A pointer must land strictly below itself, which sec 4.1.4's "a pointer to a prior occurance of
 * the same name" states, so the offset falls on every hop and a pointer at itself fails on the first
 * one. IDEMIP_DNS_PTR_HOPS_MAX bounds the count as well, which is what holds when a caller resumes
 * the walk at a higher offset after a label.
 */
static idemip_bool dns_deref(const uint8_t *msg, size_t len, size_t *off, size_t *hops)
{
    while (*off < len)
    {
        uint8_t n = msg[*off];
        if ((n & IDEMIP_DNS_LABEL_PTR) != IDEMIP_DNS_LABEL_PTR)
        {
            return IDEMIP_TRUE;
        }
        if (((*off) + 1u) >= len || *hops >= IDEMIP_DNS_PTR_HOPS_MAX)
        {
            return IDEMIP_FALSE;
        }
        size_t next = (size_t)(idemip_rd16(msg + *off) & IDEMIP_DNS_LABEL_PTR_MASK);
        if (next >= *off)
        {
            return IDEMIP_FALSE;
        }
        *off = next;
        (*hops)++;
    }
    return IDEMIP_FALSE;
}

/**
 * Report the offset of the octet after the name encoded at @p off.
 *
 * The encoding a name occupies ends at its zero octet or at the second octet of its sec 4.1.4
 * pointer, so this walk never follows one and the offset only rises.
 */
static idemip_bool dns_name_end(const uint8_t *msg, size_t len, size_t off, size_t *out_end)
{
    size_t spent = 0;
    while (off < len)
    {
        uint8_t n = msg[off];
        if ((n & IDEMIP_DNS_LABEL_PTR) == IDEMIP_DNS_LABEL_PTR)
        {
            if ((off + 2u) > len)
            {
                return IDEMIP_FALSE;
            }
            *out_end = off + 2u;
            return IDEMIP_TRUE;
        }
        if (n > IDEMIP_DNS_LABEL_MAX)
        {
            return IDEMIP_FALSE; // sec 4.1.4 reserves the 01 and 10 length forms
        }
        if (n == 0u)
        {
            *out_end = off + 1u;
            return IDEMIP_TRUE;
        }
        if ((off + 1u + (size_t)n) > len)
        {
            return IDEMIP_FALSE;
        }
        spent += 1u + (size_t)n;
        if (spent > IDEMIP_DNS_NAME_WIRE_MAX)
        {
            return IDEMIP_FALSE; // sec 3.1 bounds a name at 255 octets
        }
        off += 1u + (size_t)n;
    }
    return IDEMIP_FALSE;
}

/**
 * Compare the name at @p off against a NUL terminated dotted string.
 *
 * Case is folded per sec 2.3.3 and the sec 4.1.4 pointers are followed. The octets a name spends and
 * the hops it takes are both bounded, so the walk ends whatever the message holds.
 */
static idemip_bool dns_name_eq_text(const uint8_t *msg, size_t len, size_t off, const char *text)
{
    size_t hops = 0;
    size_t spent = 0;
    const char *t = text;
    for (;;)
    {
        if (!dns_deref(msg, len, &off, &hops))
        {
            return IDEMIP_FALSE;
        }
        uint8_t n = msg[off];
        if (n > IDEMIP_DNS_LABEL_MAX)
        {
            return IDEMIP_FALSE;
        }
        if (n == 0u)
        {
            // The dotted form ends either at its terminator or at the separator standing for the root.
            return (idemip_bool)((*t == '\0') || ((*t == '.') && (t[1] == '\0')));
        }
        if ((off + 1u + (size_t)n) > len)
        {
            return IDEMIP_FALSE;
        }
        spent += 1u + (size_t)n;
        if (spent > IDEMIP_DNS_NAME_WIRE_MAX)
        {
            return IDEMIP_FALSE;
        }
        for (uint8_t i = 0; i < n; i++)
        {
            if (*t == '\0')
            {
                return IDEMIP_FALSE; // a label octet may itself be zero, so the terminator is tested first
            }
            if (dns_fold(msg[off + 1u + (size_t)i]) != dns_fold((uint8_t)*t))
            {
                return IDEMIP_FALSE;
            }
            t++;
        }
        if (*t == '.')
        {
            t++;
        }
        else if (*t != '\0')
        {
            return IDEMIP_FALSE;
        }
        off += 1u + (size_t)n;
    }
}

/**
 * Compare two names in the same message, each following its own sec 4.1.4 pointers.
 *
 * This is what an answer record's owner NAME is checked against, so a record for a name nobody asked
 * about cannot reach the cache (RFC 5452 sec 6).
 */
static idemip_bool dns_name_eq_wire(const uint8_t *msg, size_t len, size_t a, size_t b)
{
    size_t hops_a = 0;
    size_t hops_b = 0;
    size_t spent = 0;
    for (;;)
    {
        if (!dns_deref(msg, len, &a, &hops_a) || !dns_deref(msg, len, &b, &hops_b))
        {
            return IDEMIP_FALSE;
        }
        uint8_t na = msg[a];
        if (na != msg[b])
        {
            return IDEMIP_FALSE;
        }
        if (na == 0u)
        {
            return IDEMIP_TRUE;
        }
        if (na > IDEMIP_DNS_LABEL_MAX)
        {
            return IDEMIP_FALSE;
        }
        if (((a + 1u + (size_t)na) > len) || ((b + 1u + (size_t)na) > len))
        {
            return IDEMIP_FALSE;
        }
        spent += 1u + (size_t)na;
        if (spent > IDEMIP_DNS_NAME_WIRE_MAX)
        {
            return IDEMIP_FALSE;
        }
        for (uint8_t i = 0; i < na; i++)
        {
            if (dns_fold(msg[a + 1u + (size_t)i]) != dns_fold(msg[b + 1u + (size_t)i]))
            {
                return IDEMIP_FALSE;
            }
        }
        a += 1u + (size_t)na;
        b += 1u + (size_t)na;
    }
}

/**
 * Measure the dotted form of a name and report the octets its sec 3.1 encoding spans.
 *
 * RFC 2181 sec 11: "The length of any one label is limited to between 1 and 63 octets. A full domain
 * name is limited to 255 octets (including the separators)." An empty label, a label past
 * IDEMIP_DNS_LABEL_MAX, and an encoding past IDEMIP_DNS_NAME_WIRE_MAX are each refused.
 */
static idemip_bool dns_text_wire_len(const char *text, size_t *out_wire, size_t *out_text)
{
    size_t wire = 1u; // the root octet the encoding ends with
    size_t at = 0;
    size_t label = 0;
    if (text == NULL || text[0] == '\0')
    {
        return IDEMIP_FALSE;
    }
    for (;;)
    {
        char c = text[at];
        if ((c != '\0') && (c != '.'))
        {
            label++;
            at++;
            if (at > IDEMIP_DNS_NAME_TEXT_MAX)
            {
                return IDEMIP_FALSE;
            }
            continue;
        }
        if ((label == 0u) || (label > IDEMIP_DNS_LABEL_MAX))
        {
            return IDEMIP_FALSE; // an empty label, or one past the sec 2.3.4 limit
        }
        wire += 1u + label;
        if (wire > IDEMIP_DNS_NAME_WIRE_MAX)
        {
            return IDEMIP_FALSE;
        }
        label = 0;
        if (c == '\0')
        {
            break;
        }
        at++;
        if (text[at] == '\0')
        {
            break; // the separator standing for the root, which the encoding's zero octet is
        }
    }
    if (out_wire != NULL)
    {
        *out_wire = wire;
    }
    if (out_text != NULL)
    {
        *out_text = at;
    }
    return IDEMIP_TRUE;
}

// Put the dotted form in a name region, terminator included. The caller measured it first, so it
// fits.
static void dns_name_store(uint8_t *work, size_t idx, const char *text, size_t text_len)
{
    char *dst = DNS_NAME_AT(work, idx);
    memset(dst, 0, DNS_NAME_BYTES);
    memcpy(dst, text, text_len);
}

// --- the tables ------------------------------------------------------------

// Two names held as dotted forms, compared sec 2.3.3 case insensitively. The region is bounded, so a
// caller's string that never terminates inside it simply does not match.
static idemip_bool dns_held_eq(const char *held, const char *text)
{
    size_t k = 0;
    while ((k < DNS_NAME_BYTES) && (dns_fold((uint8_t)held[k]) == dns_fold((uint8_t)text[k])))
    {
        if (text[k] == '\0')
        {
            return IDEMIP_TRUE;
        }
        k++;
    }
    return IDEMIP_FALSE;
}

// The question asking about this name for this type, whatever state it is in, or IDEMIP_DNS_QUERIES.
static uint8_t dns_query_find(uint8_t *work, const char *text, uint16_t type)
{
    for (uint8_t i = 0; i < IDEMIP_DNS_QUERIES; i++)
    {
        const DnsQuery *q = DNS_QUERY_AT(work, i);
        if (q->state == IDEMIP_DNS_QUERY_FREE || q->type != type)
        {
            continue;
        }
        if (dns_held_eq(DNS_NAME_AT(work, i), text))
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_DNS_QUERIES;
}

// The cached answer for this name and type that is still inside its TTL, or IDEMIP_DNS_ENTRIES.
static uint8_t dns_cache_find(uint8_t *work, const char *text, uint16_t type, uint32_t now_ms)
{
    for (uint8_t j = 0; j < IDEMIP_DNS_ENTRIES; j++)
    {
        const DnsEntry *e = DNS_ENTRY_AT(work, j);
        if (e->state != IDEMIP_DNS_ENTRY_VALID || e->type != type || dns_reached(now_ms, e->expire_ms))
        {
            continue;
        }
        if (dns_held_eq(DNS_NAME_AT(work, DNS_ENTRY_NAME_IDX(j)), text))
        {
            return j;
        }
    }
    return (uint8_t)IDEMIP_DNS_ENTRIES;
}

/**
 * The cache slot an answer goes in.
 *
 * RFC 2181 sec 5.4: a response that "would form an RRSet with data in a server's cache" replaces the
 * cached set rather than merging with it, so a slot already holding this name and type is the one
 * taken. Failing that it is a free slot, and failing that the answer closest to expiry.
 */
static uint8_t dns_cache_slot(uint8_t *work, const char *text, uint16_t type, uint32_t now_ms)
{
    uint8_t same = dns_cache_find(work, text, type, now_ms);
    if (same < IDEMIP_DNS_ENTRIES)
    {
        return same;
    }
    uint8_t oldest = 0;
    for (uint8_t j = 0; j < IDEMIP_DNS_ENTRIES; j++)
    {
        const DnsEntry *e = DNS_ENTRY_AT(work, j);
        if (e->state != IDEMIP_DNS_ENTRY_VALID || dns_reached(now_ms, e->expire_ms))
        {
            return j;
        }
        if ((int32_t)(e->expire_ms - DNS_ENTRY_AT(work, oldest)->expire_ms) < 0)
        {
            oldest = j;
        }
    }
    return oldest;
}

// The next server at or after @p from that set_server filled, or IDEMIP_DNS_SERVERS when the table
// is empty.
static uint8_t dns_server_used_from(uint8_t *work, uint8_t from)
{
    for (uint8_t k = 0; k < IDEMIP_DNS_SERVERS; k++)
    {
        uint8_t i = (uint8_t)((from + k) & (uint8_t)(IDEMIP_DNS_SERVERS - 1u));
        if (DNS_SERVER_AT(work, i)->used)
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_DNS_SERVERS;
}

static_assert((IDEMIP_DNS_SERVERS & (IDEMIP_DNS_SERVERS - 1u)) == 0u,
              "IDEMIP_DNS_SERVERS must be a power of two: the walk wraps with an AND, never a modulo");

/**
 * The TTL an answer is held for.
 *
 * RFC 2181 sec 8: a TTL is "an unsigned number, with a minimum value of 0, and a maximum value of
 * 2147483647", and "Implementations should treat TTL values received with the most significant bit
 * set as if the entire value received was zero". A larger value than the ceiling becomes the ceiling,
 * which the same section permits.
 */
static uint32_t dns_ttl_clamp(uint32_t raw)
{
    if ((raw & IDEMIP_DNS_TTL_SIGN) != 0u)
    {
        return 0u;
    }
    return (raw > IDEMIP_DNS_TTL_MAX_S) ? (uint32_t)IDEMIP_DNS_TTL_MAX_S : raw;
}

/**
 * Move a question on after a try that produced no answer.
 *
 * RFC 1035 sec 4.2.1: "The client should try other servers and server addresses before repeating a
 * query to a specific address of a server", so the next server the table holds is taken and a try is
 * counted only once the walk has come back round to where it started. The question lands in
 * IDEMIP_DNS_QUERY_NEW, which is the state build sends, or in IDEMIP_DNS_QUERY_FAILED once the
 * configured tries are spent.
 */
static void dns_advance(uint8_t *work, DnsQuery *q)
{
    const DnsCtx *ctx = DNS_CTX(work);
    uint8_t next = dns_server_used_from(work, (uint8_t)((q->server + 1u) & (uint8_t)(IDEMIP_DNS_SERVERS - 1u)));
    if ((next >= IDEMIP_DNS_SERVERS) || (next <= q->server))
    {
        q->retries++;
    }
    if (q->retries >= ctx->cfg->retries)
    {
        q->state = IDEMIP_DNS_QUERY_FAILED;
        return;
    }
    if (next < IDEMIP_DNS_SERVERS)
    {
        q->server = next;
    }
    q->state = IDEMIP_DNS_QUERY_NEW;
}

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

/**
 * Register one question, or hand back the slot one just like it already occupies.
 *
 * RFC 5452 sec 5: an attacker gains "if it can force the target resolver to have multiple equivalent
 * (identical QNAME, QTYPE, and QCLASS) outstanding queries at any one time to the same authoritative
 * server", so a second ask for a question already on the wire returns that slot and draws nothing.
 * A slot whose exchange finished is asked again with the new ID and port.
 */
static void dns_query_register(uint8_t *restrict work)
{
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    const DnsQueryArgs *a = &io->query_args;
    size_t text = 0;

    io->query = (uint8_t)IDEMIP_DNS_QUERIES;
    if ((a->type != (uint16_t)IDEMIP_DNS_TYPE_A) && (a->type != (uint16_t)IDEMIP_DNS_TYPE_AAAA))
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // RFC 5452 sec 9.2: a source port comes "from the range of available ports (53, or 1024 and above)".
    if ((a->src_port != (uint16_t)IDEMIP_DNS_PORT) && (a->src_port < IDEMIP_DNS_SRC_PORT_MIN))
    {
        io->status = IDEMIP_ERR;
        return;
    }
    if (!dns_text_wire_len(a->name, NULL, &text))
    {
        io->status = IDEMIP_ERR;
        return;
    }

    uint8_t slot = dns_query_find(work, a->name, a->type);
    if (slot < IDEMIP_DNS_QUERIES)
    {
        DnsQuery *held = DNS_QUERY_AT(work, slot);
        if ((held->state == IDEMIP_DNS_QUERY_NEW) || (held->state == IDEMIP_DNS_QUERY_SENT))
        {
            io->query = slot;
            io->xid = held->id;
            io->src_port = held->src_port;
            io->status = IDEMIP_OK;
            return;
        }
    }
    else
    {
        for (uint8_t i = 0; i < IDEMIP_DNS_QUERIES; i++)
        {
            if (DNS_QUERY_AT(work, i)->state == IDEMIP_DNS_QUERY_FREE)
            {
                slot = i;
                break;
            }
        }
    }
    if (slot >= IDEMIP_DNS_QUERIES)
    {
        // Every slot holds a question a caller has not read or cancelled yet, and one frees on the
        // next completion, so this is BUSY rather than ERR.
        io->status = IDEMIP_BUSY;
        return;
    }

    DnsQuery *q = DNS_QUERY_AT(work, slot);
    memset(q, 0, sizeof *q);
    q->id = a->xid;
    q->src_port = a->src_port;
    q->type = a->type;
    q->qclass = (uint16_t)IDEMIP_DNS_CLASS_IN;
    q->name = slot;
    q->server = ctx->next_server;
    q->state = IDEMIP_DNS_QUERY_NEW;
    dns_name_store(work, slot, a->name, text);

    // RFC 1035 sec 4.2.1 asks a client to "try other servers and server addresses before repeating a
    // query", so the next question starts at the server after this one's.
    uint8_t first = dns_server_used_from(work, ctx->next_server);
    if (first < IDEMIP_DNS_SERVERS)
    {
        q->server = first;
        ctx->next_server = (uint8_t)((first + 1u) & (uint8_t)(IDEMIP_DNS_SERVERS - 1u));
    }

    io->query = slot;
    io->xid = q->id;
    io->src_port = q->src_port;
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
    dns_query_register(work);
}

// RFC 1035 sec 2.3.3, a cached answer matched on a case-insensitive name and its TYPE. A name that is
// not cached is BUSY, so a caller polls; io->query names the question working on it, or
// IDEMIP_DNS_QUERIES when nobody asked.
static void dns_lookup_cached(uint8_t *restrict work)
{
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    const DnsLookupArgs *a = &io->lookup_args;

    memset(io->addr, 0, sizeof io->addr);
    io->ipv6 = IDEMIP_FALSE;
    io->type = 0u;
    io->ttl_s = 0u;
    io->rcode = 0u;
    io->query = (uint8_t)IDEMIP_DNS_QUERIES;
    if (a->name == NULL || a->name[0] == '\0')
    {
        io->status = IDEMIP_ERR;
        return;
    }

    uint8_t pending = dns_query_find(work, a->name, a->type);
    if (pending < IDEMIP_DNS_QUERIES)
    {
        io->query = pending;
        io->rcode = DNS_QUERY_AT(work, pending)->rcode;
    }

    uint8_t j = dns_cache_find(work, a->name, a->type, ctx->now_ms);
    if (j >= IDEMIP_DNS_ENTRIES)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    const DnsEntry *e = DNS_ENTRY_AT(work, j);
    memcpy(io->addr, e->addr, sizeof io->addr);
    io->ipv6 = e->ipv6;
    io->type = e->type;
    io->ttl_s = e->ttl_s;
    io->status = IDEMIP_OK;
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
    dns_lookup_cached(work);
}

/**
 * Write the sec 4.1.1 header and the sec 4.1.2 question of one registered slot.
 *
 * QR is zero and the Opcode is QUERY. RD is set, which sec 4.1.1 says "directs the name server to
 * pursue the query recursively", the only way a stub resolver gets an answer. QDCOUNT is one and the
 * other three counts are zero, since a query carries no records.
 */
static void dns_build_query(uint8_t *restrict work)
{
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    const DnsBuildArgs *a = &io->build_args;

    if (a->out == NULL || a->query >= IDEMIP_DNS_QUERIES)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    DnsQuery *q = DNS_QUERY_AT(work, a->query);
    if (q->state != IDEMIP_DNS_QUERY_NEW)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    uint8_t si = dns_server_used_from(work, q->server);
    if (si >= IDEMIP_DNS_SERVERS)
    {
        // DHCP option 6 or an RFC 8106 RDNSS option may still fill the table, so an empty one is BUSY.
        io->status = IDEMIP_BUSY;
        return;
    }
    q->server = si;

    const char *name = DNS_NAME_AT(work, a->query);
    size_t wire = 0;
    size_t text = 0;
    if (!dns_text_wire_len(name, &wire, &text))
    {
        io->status = IDEMIP_ERR;
        return;
    }
    size_t need = (size_t)IDEMIP_DNS_HDR_LEN + wire + (size_t)IDEMIP_DNS_QFIXED_LEN;
    if ((a->cap < need) || (need > IDEMIP_DNS_MSG_MAX))
    {
        io->status = IDEMIP_ERR;
        return;
    }

    uint8_t *out = a->out;
    idemip_wr16(out + IDEMIP_DNS_HDR_OFF_ID, q->id);
    idemip_wr16(out + IDEMIP_DNS_HDR_OFF_FLAGS,
                (uint16_t)(((uint16_t)IDEMIP_DNS_OPCODE_QUERY << IDEMIP_DNS_OPCODE_SHIFT) | IDEMIP_DNS_FLAG_RD));
    idemip_wr16(out + IDEMIP_DNS_HDR_OFF_QDCOUNT, 1u);
    idemip_wr16(out + IDEMIP_DNS_HDR_OFF_ANCOUNT, 0u);
    idemip_wr16(out + IDEMIP_DNS_HDR_OFF_NSCOUNT, 0u);
    idemip_wr16(out + IDEMIP_DNS_HDR_OFF_ARCOUNT, 0u);

    // sec 4.1.2 QNAME: "each label consists of a length octet followed by that number of octets", and
    // "The domain name terminates with the zero length octet for the null label of the root."
    size_t at = IDEMIP_DNS_HDR_LEN;
    size_t k = 0;
    while (k < text)
    {
        size_t label = 0;
        while (((k + label) < text) && (name[k + label] != '.'))
        {
            label++;
        }
        if (label == 0u)
        {
            break; // the separator standing for the root, which the zero octet below writes
        }
        out[at] = (uint8_t)label;
        memcpy(out + at + 1u, name + k, label);
        at += 1u + label;
        k += label;
        if ((k < text) && (name[k] == '.'))
        {
            k++;
        }
    }
    out[at] = 0u;
    at++;
    idemip_wr16(out + at + IDEMIP_DNS_RR_OFF_TYPE, q->type);
    idemip_wr16(out + at + IDEMIP_DNS_RR_OFF_CLASS, q->qclass);
    at += IDEMIP_DNS_QFIXED_LEN;

    const DnsServer *s = DNS_SERVER_AT(work, si);
    io->len = at;
    memcpy(io->dst, s->addr, sizeof io->dst);
    io->dst_zone = s->zone;
    io->dst_port = s->port;
    io->ipv6 = s->ipv6;
    io->src_port = q->src_port;
    io->xid = q->id;
    io->type = q->type;
    io->query = a->query;

    q->state = IDEMIP_DNS_QUERY_SENT;
    q->deadline_ms = ctx->now_ms + IDEMIP_DNS_RETRY_MS;
    io->status = IDEMIP_OK;
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
    dns_build_query(work);
}

/**
 * The question slot a received message answers, or IDEMIP_DNS_QUERIES.
 *
 * RFC 5452 sec 9.1 requires a match on the response's source address against the question's
 * destination, its destination port against the question's source port, the query ID, the query name,
 * and the query class and type. Each is tested here; the question's own destination address is the
 * server entry it was sent to.
 */
static uint8_t dns_match(uint8_t *work, const uint8_t *msg, size_t len)
{
    const DnsIo *io = DNS_IO(work);
    const DnsInputArgs *a = &io->input_args;
    uint16_t id = idemip_rd16(msg + IDEMIP_DNS_HDR_OFF_ID);

    for (uint8_t i = 0; i < IDEMIP_DNS_QUERIES; i++)
    {
        const DnsQuery *q = DNS_QUERY_AT(work, i);
        if (q->state != IDEMIP_DNS_QUERY_SENT || q->id != id || q->src_port != a->dst_port)
        {
            continue;
        }
        if (q->server >= IDEMIP_DNS_SERVERS)
        {
            continue;
        }
        const DnsServer *s = DNS_SERVER_AT(work, q->server);
        if (!s->used || s->ipv6 != a->ipv6 || s->port != a->src_port)
        {
            continue;
        }
        size_t alen = a->ipv6 ? (size_t)IDEMIP_DNS_ADDR_LEN : (size_t)IDEMIP_DNS_A_RDLEN;
        if (memcmp(s->addr, a->src, alen) != 0)
        {
            continue;
        }
        // The echoed question: its QNAME, then the QTYPE and QCLASS behind it (sec 4.1.2).
        size_t qend = 0;
        if (!dns_name_eq_text(msg, len, IDEMIP_DNS_HDR_LEN, DNS_NAME_AT(work, i)))
        {
            continue;
        }
        if (!dns_name_end(msg, len, IDEMIP_DNS_HDR_LEN, &qend) || ((qend + IDEMIP_DNS_QFIXED_LEN) > len))
        {
            continue;
        }
        if ((idemip_rd16(msg + qend + IDEMIP_DNS_RR_OFF_TYPE) != q->type) ||
            (idemip_rd16(msg + qend + IDEMIP_DNS_RR_OFF_CLASS) != q->qclass))
        {
            continue;
        }
        return i;
    }
    return (uint8_t)IDEMIP_DNS_QUERIES;
}

/**
 * Read the answer section for the address the question asked about.
 *
 * The name of interest starts as the echoed QNAME and a CNAME whose owner is that name moves it to
 * the RDATA name, which is RFC 1035 sec 3.3.1's alias. A record whose owner is not the name of
 * interest is skipped, which is RFC 5452 sec 6's "only accept data if it is part of the domain for
 * which the query was intended". The TTL reported is the lowest over the matching records, which RFC
 * 2181 sec 5.2 requires of a client seeing an RRSet with differing TTLs.
 *
 * The section is walked once forward, so an alias record stands before the record it names.
 */
static idemip_bool dns_answers_read(const uint8_t *msg, size_t len, size_t at, uint16_t ancount, uint16_t type,
                                    uint8_t *out_addr, uint32_t *out_ttl)
{
    size_t want = (type == (uint16_t)IDEMIP_DNS_TYPE_AAAA) ? (size_t)IDEMIP_DNS_AAAA_RDLEN : (size_t)IDEMIP_DNS_A_RDLEN;
    size_t interest = IDEMIP_DNS_HDR_LEN;
    idemip_bool found = IDEMIP_FALSE;
    uint32_t ttl = 0;

    for (uint16_t n = 0; n < ancount; n++)
    {
        size_t owner = at;
        size_t fixed = 0;
        if (!dns_name_end(msg, len, owner, &fixed) || ((fixed + IDEMIP_DNS_RR_FIXED_LEN) > len))
        {
            return found;
        }
        uint16_t rtype = idemip_rd16(msg + fixed + IDEMIP_DNS_RR_OFF_TYPE);
        uint16_t rclass = idemip_rd16(msg + fixed + IDEMIP_DNS_RR_OFF_CLASS);
        uint32_t rttl = idemip_rd32(msg + fixed + IDEMIP_DNS_RR_OFF_TTL);
        size_t rdlen = (size_t)idemip_rd16(msg + fixed + IDEMIP_DNS_RR_OFF_RDLENGTH);
        size_t rdata = fixed + IDEMIP_DNS_RR_FIXED_LEN;
        if ((rdata + rdlen) > len)
        {
            return found;
        }
        at = rdata + rdlen;

        if ((rclass == (uint16_t)IDEMIP_DNS_CLASS_IN) && dns_name_eq_wire(msg, len, owner, interest))
        {
            if (rtype == type && rdlen == want)
            {
                uint32_t clamped = dns_ttl_clamp(rttl);
                if (!found)
                {
                    memcpy(out_addr, msg + rdata, want);
                    ttl = clamped;
                    found = IDEMIP_TRUE;
                }
                else if (clamped < ttl)
                {
                    ttl = clamped;
                }
            }
            else if ((rtype == (uint16_t)IDEMIP_DNS_TYPE_CNAME) && !found && (rdlen != 0u))
            {
                interest = rdata; // sec 3.3.1: the RDATA of a CNAME is one domain name
            }
        }
    }
    *out_ttl = ttl;
    return found;
}

/**
 * Take one response.
 *
 * A message that matches nothing leaves every question exactly as it was, which is what RFC 5452 sec
 * 9.1's "A mismatch and the response MUST be considered invalid" requires: a forgery must not retire
 * the question the real answer is still coming for.
 */
static void dns_take(uint8_t *restrict work)
{
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    const DnsInputArgs *a = &io->input_args;
    const uint8_t *msg = a->msg;
    size_t len = a->len;

    memset(io->addr, 0, sizeof io->addr);
    io->ipv6 = IDEMIP_FALSE;
    io->type = 0u;
    io->ttl_s = 0u;
    io->answers = 0u;
    io->rcode = 0u;
    io->query = (uint8_t)IDEMIP_DNS_QUERIES;
    io->status = IDEMIP_ERR;

    // The shortest response is a header, a root QNAME and its fixed fields, and sec 4.2.1 restricts a
    // UDP message to 512 octets.
    if ((msg == NULL) || (a->src == NULL) || (len < ((size_t)IDEMIP_DNS_HDR_LEN + 1u + IDEMIP_DNS_QFIXED_LEN)) ||
        (len > IDEMIP_DNS_MSG_MAX))
    {
        return;
    }
    uint16_t flags = idemip_rd16(msg + IDEMIP_DNS_HDR_OFF_FLAGS);
    if ((flags & IDEMIP_DNS_FLAG_QR) == 0u)
    {
        return; // sec 4.1.1 QR: a query, not a response
    }
    if (((flags & IDEMIP_DNS_FLAG_OPCODE) >> IDEMIP_DNS_OPCODE_SHIFT) != IDEMIP_DNS_OPCODE_QUERY)
    {
        return;
    }
    if (idemip_rd16(msg + IDEMIP_DNS_HDR_OFF_QDCOUNT) != 1u)
    {
        return; // one question was asked, so one is echoed
    }

    uint8_t i = dns_match(work, msg, len);
    if (i >= IDEMIP_DNS_QUERIES)
    {
        return;
    }
    DnsQuery *q = DNS_QUERY_AT(work, i);
    io->query = i;
    io->xid = q->id;
    io->src_port = q->src_port;
    io->answers = idemip_rd16(msg + IDEMIP_DNS_HDR_OFF_ANCOUNT);

    // RFC 2181 sec 9: a client receiving a reply with TC set "should ignore that response, and query
    // again, using a mechanism, such as a TCP connection, that will permit larger replies". There is
    // no such mechanism here, so the question is left outstanding for the retry sweep.
    if ((flags & IDEMIP_DNS_FLAG_TC) != 0u)
    {
        io->answers = 0u;
        return;
    }

    uint8_t rcode = (uint8_t)(flags & IDEMIP_DNS_FLAG_RCODE);
    io->rcode = rcode;
    q->rcode = rcode;
    if (rcode != (uint8_t)IDEMIP_DNS_RCODE_NO_ERROR)
    {
        io->answers = 0u;
        // sec 4.1.1 says a Name Error is "Meaningful only for responses from an authoritative name
        // server", and a stub resolver asking a recursive one has nowhere better to go, so it is final.
        // Any other RCODE is a fault of the server asked, so sec 4.2.1's "try other servers" applies.
        if (rcode == (uint8_t)IDEMIP_DNS_RCODE_NAME_ERR)
        {
            q->state = IDEMIP_DNS_QUERY_FAILED;
        }
        else
        {
            dns_advance(work, q);
        }
        io->status = IDEMIP_OK;
        return;
    }

    size_t at = 0;
    if (!dns_name_end(msg, len, IDEMIP_DNS_HDR_LEN, &at))
    {
        return;
    }
    at += IDEMIP_DNS_QFIXED_LEN;

    uint32_t ttl = 0;
    if (!dns_answers_read(msg, len, at, io->answers, q->type, io->addr, &ttl))
    {
        // The name exists and carries no record of the type asked for, so the exchange is over.
        memset(io->addr, 0, sizeof io->addr);
        q->state = IDEMIP_DNS_QUERY_FAILED;
        io->status = IDEMIP_OK;
        return;
    }

    io->type = q->type;
    io->ipv6 = (idemip_bool)((q->type == (uint16_t)IDEMIP_DNS_TYPE_AAAA) ? IDEMIP_TRUE : IDEMIP_FALSE);
    io->ttl_s = ttl;
    q->state = IDEMIP_DNS_QUERY_DONE;

    // sec 4.1.3: a zero TTL means "the RR can only be used for the transaction in progress, and should
    // not be cached", so it is reported and no slot is taken.
    if (ttl != 0u)
    {
        const char *name = DNS_NAME_AT(work, i);
        uint8_t j = dns_cache_slot(work, name, q->type, ctx->now_ms);
        DnsEntry *e = DNS_ENTRY_AT(work, j);
        size_t text = 0;
        while ((text < (DNS_NAME_BYTES - 1u)) && (name[text] != '\0'))
        {
            text++;
        }
        memset(e, 0, sizeof *e);
        memcpy(e->addr, io->addr, sizeof e->addr);
        e->expire_ms = ctx->now_ms + (ttl * IDEMIP_DNS_MS_PER_S);
        e->ttl_s = ttl;
        e->type = q->type;
        e->name = (uint8_t)DNS_ENTRY_NAME_IDX(j);
        e->state = IDEMIP_DNS_ENTRY_VALID;
        e->ipv6 = io->ipv6;
        dns_name_store(work, DNS_ENTRY_NAME_IDX(j), name, text);
    }
    io->status = IDEMIP_OK;
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
    dns_take(work);
}

// Run the retry deadlines and the sec 4.1.3 TTLs. A question past its deadline moves on the way
// dns_advance describes; a cached answer past its TTL frees its slot and its name region.
static void dns_sweep(uint8_t *work)
{
    DnsIo *io = DNS_IO(work);
    DnsCtx *ctx = DNS_CTX(work);
    uint32_t now = io->tick_args.now_ms;
    ctx->now_ms = now;

    for (uint8_t i = 0; i < IDEMIP_DNS_QUERIES; i++)
    {
        DnsQuery *q = DNS_QUERY_AT(work, i);
        if (q->state != IDEMIP_DNS_QUERY_SENT || !dns_reached(now, q->deadline_ms))
        {
            continue;
        }
        dns_advance(work, q);
    }

    for (uint8_t j = 0; j < IDEMIP_DNS_ENTRIES; j++)
    {
        DnsEntry *e = DNS_ENTRY_AT(work, j);
        if (e->state != IDEMIP_DNS_ENTRY_VALID || !dns_reached(now, e->expire_ms))
        {
            continue;
        }
        memset(DNS_NAME_AT(work, DNS_ENTRY_NAME_IDX(j)), 0, DNS_NAME_BYTES);
        memset(e, 0, sizeof *e);
    }
    io->status = IDEMIP_OK;
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
    dns_sweep(work);
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
