// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file rdnss.c
 * @brief The RFC 8106 sec 5.1 option and the sec 6.1 DNS Server List, in the caller's borrow.
 *
 * The context holds the mark clear leaves; the list holds one entry per RDNSS address with its
 * Expiration-time, packed from slot zero so the order sec 6.2 requires is the order a caller reads
 * them back in. Every entry is a function of the one pointer it is handed: the operand block, the
 * context and the list are all regions of that borrow, at compile-time offsets, and no entry reads or
 * writes a byte outside it.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/endian.h" // the option's 32-bit Lifetime, big-endian on the wire
#include "src/nd/rdnss.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads something else here and
// every entry but clear refuses it.
#define RDNSS_READY 0x52444E31u

// One entry of the sec 6.1 DNS Server List: "a pair of an RDNSS address ... and Expiration-time".
typedef struct
{
    IdemIpMs expire_at;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    idemip_bool infinite;
    idemip_bool used;
    uint8_t pad[(1u << IDEMIP_RDNSS_ENTRY_SHIFT) -
                (sizeof(IdemIpMs) + IDEMIP_IP6_ADDR_LEN + (2u * sizeof(idemip_bool)))];
} RdnssEntry;

// The running context: the mark clear leaves, and the two readings that carry the caller's 32-bit
// millisecond clock across its wrap onto the one every deadline sits on.
typedef struct
{
    uint32_t ready;
    uint32_t tick_ms;
    uint32_t tick_hi;
} RdnssCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_RDNSS_OFF_CTX, sizeof(RdnssCtx), IDEMIP_RDNSS_OFF_ENTRIES, "rdnss's context");

// An index is (i << SHIFT), so each entry is exactly its width.
static_assert(sizeof(RdnssEntry) == (1u << IDEMIP_RDNSS_ENTRY_SHIFT),
              "an RDNSS entry must be 1 << IDEMIP_RDNSS_ENTRY_SHIFT wide");

// The caller's borrow, split: the operand block, the context, then the list. rdnss.h publishes the
// offsets; these two asserts prove the span covers them before anything runs. The first keeps the
// context inside the region ahead of the list, the second the whole map inside the borrow.
static_assert(IDEMIP_RDNSS_OFF_CTX + sizeof(RdnssCtx) <= IDEMIP_RDNSS_OFF_ENTRIES,
              "IDEMIP_RDNSS_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_RDNSS_OFF_END <= IDEMIP_RDNSS_BORROW,
              "IDEMIP_RDNSS_BORROW is short of the map - raise IDEMIP_RDNSS_CTX_BYTES in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define RDNSS_IO(w) IDEMIP_RDNSS_IO(w)
#define RDNSS_CTX(w) ((RdnssCtx *)(void *)((w) + IDEMIP_RDNSS_OFF_CTX))
#define RDNSS_AT(w, i)                                                                                                 \
    ((RdnssEntry *)(void *)((w) + IDEMIP_RDNSS_OFF_ENTRIES + ((size_t)(i) << IDEMIP_RDNSS_ENTRY_SHIFT)))

// Octets the context and the list span, which is what clear zeroes.
#define RDNSS_STATE_BYTES ((size_t)IDEMIP_RDNSS_OFF_END - (size_t)IDEMIP_RDNSS_OFF_CTX)

// The count as the octet an index is compared against.
#define RDNSS_ENTRIES ((uint8_t)IDEMIP_RDNSS_SERVERS)

// A deadline is one absolute millisecond on the 64-bit clock, so every finite value RFC 8106 sec
// 5.1's 32-bit Lifetime field can name is representable and none is held at a bound.

// A borrow clear has not run on holds no mark, so every entry but clear refuses it.
static idemip_bool rdnss_ready(uint8_t *restrict work)
{
    return (idemip_bool)(RDNSS_CTX(work)->ready == RDNSS_READY);
}

// --- addresses -------------------------------------------------------------

static idemip_bool rdnss_addr_eq(const uint8_t *a, const uint8_t *b)
{
    return (idemip_bool)(idemip_bytes_eq(a, b, IDEMIP_IP6_ADDR_LEN));
}

// sec 5.3.1 checks "the validity of the RDNSS option ... with the 'Addresses of IPv6 Recursive DNS
// Servers' field; that is, the addresses should be unicast addresses". RFC 4291 sec 2.7 gives
// multicast FF00::/8 and sec 2.5.2 the unspecified address, and neither is a unicast address.
static idemip_bool rdnss_is_unicast(const uint8_t *addr)
{
    if (addr[0] == 0xFFu)
    {
        return IDEMIP_FALSE;
    }
    return (idemip_bool)!idemip_bytes_zero(addr, IDEMIP_IP6_ADDR_LEN);
}

// --- the clock -------------------------------------------------------------

// sec 6.1 states the expiry strictly: "When the current time becomes larger than Expiration-time, this
// entry is regarded as expired". At exactly Expiration-time the entry still stands, which is why this
// is a greater-than and not the at-or-past comparison RFC 4862 sec 5.5.4's wording takes. Both sit on
// the same 64-bit millisecond clock, so this is one comparison and nothing wraps under it.
static idemip_bool rdnss_due(IdemIpMs now, IdemIpMs deadline)
{
    return (now > deadline) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// sec 6.1: "Expiration-time is set to the value of the Lifetime field of the RDNSS option ... plus the
// current time." Both terms are on the 64-bit clock, so the widest finite Lifetime the field carries
// lands ahead of the current time and nothing is clamped.
static IdemIpMs rdnss_expiration(IdemIpMs now, uint32_t lifetime_s)
{
    return now + idemip_ms_from_s(lifetime_s);
}

// --- the list --------------------------------------------------------------
// The list is packed from slot zero, so a walk over the slots reads the servers in the order sec 6.2
// puts them in the Resolver Repository.

static uint8_t rdnss_count(uint8_t *restrict work)
{
    uint8_t n = 0u;
    while (n < RDNSS_ENTRIES && RDNSS_AT(work, n)->used)
    {
        n++;
    }
    return n;
}

static uint8_t rdnss_find_addr(uint8_t *restrict work, const uint8_t *addr)
{
    uint8_t count = rdnss_count(work);
    for (uint8_t i = 0; i < count; i++)
    {
        if (rdnss_addr_eq(RDNSS_AT(work, i)->addr, addr))
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_RDNSS_NONE;
}

// One entry out of the list, the ones behind it closing up so the order holds.
static void rdnss_delete_at(uint8_t *restrict work, uint8_t index)
{
    uint8_t count = rdnss_count(work);
    if (index >= count)
    {
        return;
    }
    for (uint8_t i = index; (uint8_t)(i + 1u) < count; i++)
    {
        memcpy(RDNSS_AT(work, i), RDNSS_AT(work, i + 1u), sizeof(RdnssEntry));
    }
    memset(RDNSS_AT(work, count - 1u), 0, sizeof(RdnssEntry));
}

// sec 6.2 step (d): "delete from the DNS Server List the entry with the shortest Expiration-time
// (i.e., the entry that will expire first)". An infinite one expires last, so it is never the choice
// while a finite one stands.
static uint8_t rdnss_soonest(uint8_t *restrict work, IdemIpMs now)
{
    uint8_t count = rdnss_count(work);
    uint8_t best = (uint8_t)IDEMIP_RDNSS_NONE;
    IdemIpMs best_left = 0u;
    idemip_bool best_infinite = IDEMIP_TRUE;
    for (uint8_t i = 0; i < count; i++)
    {
        const RdnssEntry *e = RDNSS_AT(work, i);
        IdemIpMs left = rdnss_due(now, e->expire_at) ? 0u : (IdemIpMs)(e->expire_at - now);
        idemip_bool take;
        if (best == (uint8_t)IDEMIP_RDNSS_NONE)
        {
            take = IDEMIP_TRUE;
        }
        else if (e->infinite)
        {
            take = IDEMIP_FALSE;
        }
        else
        {
            take = (idemip_bool)(best_infinite || left < best_left);
        }
        if (take)
        {
            best = i;
            best_left = left;
            best_infinite = e->infinite;
        }
    }
    return best;
}

// One address into the list at @p index, the ones from there back shifting one slot along, which is
// what sec 6.2 step (d) means by inserting "as the first one in the Resolver Repository".
static void rdnss_insert_at(uint8_t *restrict work, uint8_t index, const uint8_t *addr, uint32_t lifetime_s,
                            IdemIpMs now)
{
    uint8_t count = rdnss_count(work);
    for (uint8_t i = count; i > index; i--)
    {
        memcpy(RDNSS_AT(work, i), RDNSS_AT(work, i - 1u), sizeof(RdnssEntry));
    }
    RdnssEntry *e = RDNSS_AT(work, index);
    memcpy(e->addr, addr, IDEMIP_IP6_ADDR_LEN);
    e->infinite = (idemip_bool)(lifetime_s == IDEMIP_RDNSS_LIFETIME_INFINITE);
    e->expire_at = e->infinite ? 0u : rdnss_expiration(now, lifetime_s);
    e->used = IDEMIP_TRUE;
}

// Every result member, cleared, so an entry reports what this call found and never what the last one
// did.
static void rdnss_clear_results(RdnssIo *io)
{
    memset(io->addr, 0, sizeof io->addr);
    io->expire_at = 0u;
    io->lifetime_s = 0u;
    io->entry = (uint8_t)IDEMIP_RDNSS_NONE;
    io->servers = 0u;
    io->added = 0u;
    io->updated = 0u;
    io->deleted = 0u;
    io->evicted = 0u;
    io->expired = IDEMIP_FALSE;
    io->ignored = IDEMIP_FALSE;
    io->infinite = IDEMIP_FALSE;
}

// One entry, into the result members of the operand block. The address is copied rather than pointed
// at, so an expired one is still readable after its slot is freed.
static void rdnss_publish(uint8_t *restrict work, uint8_t index)
{
    RdnssIo *io = RDNSS_IO(work);
    const RdnssEntry *e = RDNSS_AT(work, index);
    io->entry = index;
    memcpy(io->addr, e->addr, IDEMIP_IP6_ADDR_LEN);
    io->expire_at = e->expire_at;
    io->infinite = e->infinite;
}

// --- sec 6.2, one address at a time ----------------------------------------

/*
 * sec 6.2 steps (b), (c) and (d) over one address of the option:
 *
 *   (b) "If the RDNSS address already exists in the DNS Server List and the RDNSS option's Lifetime
 *       field is set to zero, delete the corresponding RDNSS entry."
 *   (c) "if it already exists in the DNS Server List and the RDNSS option's Lifetime field is not set
 *       to zero, then just update the value of the Expiration-time field."
 *   (d) "if it does not exist in the DNS Server List, register the RDNSS address and Lifetime with
 *       the DNS Server List and then insert the RDNSS address as the first one in the Resolver
 *       Repository."
 *
 * @p cursor holds where the next address of this option goes, so the first address of the option
 * lands at the head and each later one behind it, which is the order sec 6.2 closes with.
 *
 * An address that is not in the list and carries a zero Lifetime is not registered: sec 5.1 states
 * "A value of zero means that the RDNSS addresses MUST no longer be used."
 */
static void rdnss_apply(uint8_t *restrict work, const uint8_t *addr, uint32_t lifetime_s, IdemIpMs now,
                        uint8_t *cursor)
{
    RdnssIo *io = RDNSS_IO(work);
    uint8_t index = rdnss_find_addr(work, addr);

    if (index != (uint8_t)IDEMIP_RDNSS_NONE)
    {
        if (lifetime_s == 0u)
        {
            rdnss_delete_at(work, index);
            io->deleted++;
            if (*cursor > index)
            {
                (*cursor)--;
            }
            return;
        }
        RdnssEntry *e = RDNSS_AT(work, index);
        e->infinite = (idemip_bool)(lifetime_s == IDEMIP_RDNSS_LIFETIME_INFINITE);
        e->expire_at = e->infinite ? 0u : rdnss_expiration(now, lifetime_s);
        io->updated++;
        return;
    }

    if (lifetime_s == 0u)
    {
        return;
    }
    if (rdnss_count(work) == RDNSS_ENTRIES)
    {
        uint8_t victim = rdnss_soonest(work, now);
        rdnss_delete_at(work, victim);
        io->evicted++;
        if (*cursor > victim)
        {
            (*cursor)--;
        }
    }
    rdnss_insert_at(work, *cursor, addr, lifetime_s, now);
    (*cursor)++;
    io->added++;
}

// --- the entries -----------------------------------------------------------

// The context and the list, zeroed, then the mark. The operand block is the caller's and is left as
// it stands.
void idemip_rdnss_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_RDNSS_OFF_CTX, 0, RDNSS_STATE_BYTES);
    RDNSS_CTX(work)->ready = RDNSS_READY;
    RDNSS_IO(work)->status = IDEMIP_OK;
}

// sec 6.2 step (a): "Receive and parse the RDNSS option(s). For the RDNSS addresses in each RDNSS
// option, perform Steps (b) through (d)."
//
// sec 5.3.1 validates first: "the value of the Length field in the RDNSS option is greater than or
// equal to the minimum value (3) and satisfies the requirement that (Length - 1) % 2 == 0", and the
// addresses "should be unicast addresses". An option that fails is discarded whole, since "Otherwise,
// the host MUST discard the options."
void idemip_rdnss_option_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RdnssIo *io = RDNSS_IO(work);
    io->status = IDEMIP_ERR;
    rdnss_clear_results(io);
    const uint8_t *opt = io->option_args.option;
    if (!rdnss_ready(work) || opt == NULL || io->option_args.len < (size_t)IDEMIP_RDNSS_OPT_OFF_ADDRS)
    {
        return;
    }
    io->servers = rdnss_count(work);

    uint8_t length = opt[IDEMIP_RDNSS_OPT_OFF_LEN];
    // (Length - 1) % 2 == 0 is the low bit of Length - 1, so no divide and no modulo runs.
    if (opt[IDEMIP_RDNSS_OPT_OFF_TYPE] != (uint8_t)IDEMIP_RDNSS_OPT_TYPE || length < IDEMIP_RDNSS_OPT_LEN_MIN ||
        (uint8_t)((length - 1u) & 1u) != 0u)
    {
        io->ignored = IDEMIP_TRUE;
        io->status = IDEMIP_OK;
        return;
    }
    // RFC 4861 sec 4.6 states the Length "in units of 8 octets", so the option spans that many and
    // must lie inside what the caller says it may read.
    size_t span = (size_t)length * IDEMIP_RDNSS_OPT_UNIT;
    if (span > io->option_args.len)
    {
        io->ignored = IDEMIP_TRUE;
        io->status = IDEMIP_OK;
        return;
    }

    // sec 5.1: "the number of addresses is equal to (Length - 1) / 2", which is a shift by one.
    uint8_t addresses = (uint8_t)((length - 1u) >> 1);
    for (uint8_t i = 0; i < addresses; i++)
    {
        const uint8_t *addr = opt + IDEMIP_RDNSS_OPT_OFF_ADDRS + ((size_t)i * IDEMIP_IP6_ADDR_LEN);
        if (!rdnss_is_unicast(addr))
        {
            io->ignored = IDEMIP_TRUE;
            io->status = IDEMIP_OK;
            return;
        }
    }

    uint32_t lifetime_s = idemip_rd32(opt + IDEMIP_RDNSS_OPT_OFF_LIFETIME);
    io->lifetime_s = lifetime_s;
    // The caller's 32-bit reading, extended across its wrap onto the one clock every Expiration-time
    // sits on. sec 6.1 forms that stamp from "the current time", so it is taken here, where one is
    // about to be stamped.
    const IdemIpMs now = idemip_ms_extend(&RDNSS_CTX(work)->tick_ms, &RDNSS_CTX(work)->tick_hi, io->option_args.now_ms);
    uint8_t cursor = 0u;
    for (uint8_t i = 0; i < addresses; i++)
    {
        rdnss_apply(work, opt + IDEMIP_RDNSS_OPT_OFF_ADDRS + ((size_t)i * IDEMIP_IP6_ADDR_LEN), lifetime_s, now,
                    &cursor);
    }
    io->servers = rdnss_count(work);
    io->status = IDEMIP_OK;
}

void idemip_rdnss_get(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RdnssIo *io = RDNSS_IO(work);
    io->status = IDEMIP_ERR;
    rdnss_clear_results(io);
    if (!rdnss_ready(work))
    {
        return;
    }
    io->servers = rdnss_count(work);
    if (io->addr_args.index >= RDNSS_ENTRIES || !RDNSS_AT(work, io->addr_args.index)->used)
    {
        return;
    }
    rdnss_publish(work, io->addr_args.index);
    io->status = IDEMIP_OK;
}

void idemip_rdnss_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RdnssIo *io = RDNSS_IO(work);
    io->status = IDEMIP_ERR;
    rdnss_clear_results(io);
    if (!rdnss_ready(work) || io->addr_args.addr == NULL)
    {
        return;
    }
    io->servers = rdnss_count(work);
    uint8_t index = rdnss_find_addr(work, io->addr_args.addr);
    if (index == (uint8_t)IDEMIP_RDNSS_NONE)
    {
        return;
    }
    rdnss_publish(work, index);
    io->status = IDEMIP_OK;
}

// sec 6.2 step (b) deletes an entry "in order to prevent the RDNSS address from being used any more".
void idemip_rdnss_remove(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RdnssIo *io = RDNSS_IO(work);
    io->status = IDEMIP_ERR;
    rdnss_clear_results(io);
    if (!rdnss_ready(work) || io->addr_args.addr == NULL)
    {
        return;
    }
    uint8_t index = rdnss_find_addr(work, io->addr_args.addr);
    if (index == (uint8_t)IDEMIP_RDNSS_NONE)
    {
        io->servers = rdnss_count(work);
        return;
    }
    rdnss_publish(work, index);
    rdnss_delete_at(work, index);
    io->deleted++;
    io->servers = rdnss_count(work);
    io->status = IDEMIP_OK;
}

// sec 6.2: "Whenever an entry expires in the DNS Server List, the expired entry is deleted from the
// DNS Server List, and also the RDNSS address corresponding to the entry is deleted from the Resolver
// Repository." One per call, the address reported so the caller drops it from the resolver too.
//
// Nothing expired reports BUSY, since the same call on a later tick fires one.
void idemip_rdnss_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    RdnssIo *io = RDNSS_IO(work);
    io->status = IDEMIP_ERR;
    rdnss_clear_results(io);
    if (!rdnss_ready(work))
    {
        return;
    }
    // The same extension the option path takes, on the same two readings, so a sweep and a stamp
    // read one clock and not two.
    const IdemIpMs now = idemip_ms_extend(&RDNSS_CTX(work)->tick_ms, &RDNSS_CTX(work)->tick_hi, io->tick_args.now_ms);
    uint8_t count = rdnss_count(work);
    for (uint8_t i = 0; i < count; i++)
    {
        const RdnssEntry *e = RDNSS_AT(work, i);
        if (!e->infinite && rdnss_due(now, e->expire_at))
        {
            rdnss_publish(work, i);
            rdnss_delete_at(work, i);
            io->expired = IDEMIP_TRUE;
            io->servers = rdnss_count(work);
            io->status = IDEMIP_OK;
            return;
        }
    }
    io->servers = count;
    io->status = IDEMIP_BUSY;
}

IDEMIP_END_DECLS
