// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file slaac.c
 * @brief RFC 4862 sec 5.3 and sec 5.5 over one interface's address list, in the caller's borrow.
 *
 * The context holds the mark clear leaves; the list holds one entry per autoconfigured address, each
 * with the prefix length it was formed at and its two lifetimes as millisecond deadlines. Every entry
 * is a function of the one pointer it is handed: the operand block, the context and the list are all
 * regions of that borrow, at compile-time offsets, and no entry reads or writes a byte outside it.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/nd/slaac.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads something else here and
// every entry but clear refuses it.
#define SLAAC_READY 0x534C4131u

// One autoconfigured address and its lifetimes (RFC 4862 sec 5.2's "list of addresses together with
// their corresponding lifetimes"). prefix_len is what sec 5.5.3 (e) compares an advertised prefix
// against, "the two prefix lengths are the same and the first prefix-length bits of the prefixes are
// identical".
typedef struct
{
    IdemIpMs valid_at;
    IdemIpMs preferred_at;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    uint8_t prefix_len;
    IdemIpSlaacAddrState state;
    idemip_bool valid_infinite;
    idemip_bool preferred_infinite;
    idemip_bool used;
    uint8_t pad[(1u << IDEMIP_SLAAC_ENTRY_SHIFT) -
                ((2u * sizeof(IdemIpMs)) + IDEMIP_IP6_ADDR_LEN + 2u + (3u * sizeof(idemip_bool)))];
} SlaacEntry;

// The running context: the mark clear leaves, and the two readings that carry the caller's 32-bit
// millisecond clock across its wrap onto the one every deadline sits on.
typedef struct
{
    uint32_t ready;
    uint32_t tick_ms;
    uint32_t tick_hi;
} SlaacCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_SLAAC_OFF_CTX, sizeof(SlaacCtx), IDEMIP_SLAAC_OFF_ENTRIES, "slaac's context");

// An index is (i << SHIFT), so each entry is exactly its width.
static_assert(sizeof(SlaacEntry) == (1u << IDEMIP_SLAAC_ENTRY_SHIFT),
              "a SLAAC entry must be 1 << IDEMIP_SLAAC_ENTRY_SHIFT wide");

// The caller's borrow, split: the operand block, the context, then the list. slaac.h publishes the
// offsets; these two asserts prove the span covers them before anything runs. The first keeps the
// context inside the region ahead of the list, the second the whole map inside the borrow.
static_assert(IDEMIP_SLAAC_OFF_CTX + sizeof(SlaacCtx) <= IDEMIP_SLAAC_OFF_ENTRIES,
              "IDEMIP_SLAAC_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_SLAAC_OFF_END <= IDEMIP_SLAAC_BORROW,
              "IDEMIP_SLAAC_BORROW is short of the map - raise IDEMIP_SLAAC_CTX_BYTES in idemip_config.h");

// clear zeroes the list, so the state a cleared slot reads is the free one.
static_assert(IDEMIP_SLAAC_ADDR_FREE == 0, "IDEMIP_SLAAC_ADDR_FREE must be zero: clear zeroes the list");

// The regions, at their offsets in the caller's borrow.
#define SLAAC_IO(w) IDEMIP_SLAAC_IO(w)
#define SLAAC_CTX(w) ((SlaacCtx *)(void *)((w) + IDEMIP_SLAAC_OFF_CTX))
#define SLAAC_AT(w, i)                                                                                                 \
    ((SlaacEntry *)(void *)((w) + IDEMIP_SLAAC_OFF_ENTRIES + ((size_t)(i) << IDEMIP_SLAAC_ENTRY_SHIFT)))

// Octets the context and the list span, which is what clear zeroes.
#define SLAAC_STATE_BYTES ((size_t)IDEMIP_SLAAC_OFF_END - (size_t)IDEMIP_SLAAC_OFF_CTX)

// The count as the octet an index is compared against.
#define SLAAC_ENTRIES ((uint8_t)IDEMIP_IP6_ADDRESSES)

// A deadline is one absolute millisecond on the 64-bit clock, so every finite value RFC 4861 sec
// 4.6.2's 32-bit seconds fields can name is representable and none is held at a bound.

// RFC 4291 sec 2.5.6 gives the link-local prefix FE80::/10, which sec 5.3 forms an address on and
// sec 5.5.3 (b) refuses to autoconfigure from.
#define SLAAC_LINK_LOCAL_LEN 10u

// The whole address, in bits, which sec 5.5.3 (d) requires the prefix length and the interface
// identifier length to sum to.
#define SLAAC_ADDR_BITS 128u

// A borrow clear has not run on holds no mark, so every entry but clear refuses it.
static idemip_bool slaac_ready(uint8_t *restrict work)
{
    return (idemip_bool)(SLAAC_CTX(work)->ready == SLAAC_READY);
}

// --- addresses -------------------------------------------------------------

static idemip_bool slaac_addr_eq(const uint8_t *a, const uint8_t *b)
{
    return (idemip_bool)(idemip_bytes_eq(a, b, IDEMIP_IP6_ADDR_LEN));
}

// sec 5.5.3 (d): "equal" over the first @p len bits. The (len >> 3) whole octets compare exactly, and
// the remaining (len & 7) bits compare under a mask of that many leading bits.
static idemip_bool slaac_prefix_eq(const uint8_t *a, const uint8_t *b, uint8_t len)
{
    size_t whole = (size_t)(len >> 3);
    uint8_t bits = (uint8_t)(len & 7u);
    if (whole != 0u && !idemip_bytes_eq(a, b, whole))
    {
        return IDEMIP_FALSE;
    }
    if (bits != 0u)
    {
        uint8_t mask = (uint8_t)(0xFFu << (8u - bits));
        if ((uint8_t)((a[whole] ^ b[whole]) & mask) != 0u)
        {
            return IDEMIP_FALSE;
        }
    }
    return IDEMIP_TRUE;
}

// RFC 4291 sec 2.5.6: the first ten bits of a link-local address are 1111111010.
static idemip_bool slaac_is_link_local(const uint8_t *addr)
{
    return (idemip_bool)(addr[0] == 0xFEu && (uint8_t)(addr[1] & 0xC0u) == 0x80u);
}

// sec 5.3 step 3 and sec 5.5.3 (d): "the right-most N bits of the address are replaced by the
// interface identifier". N arrives in octets, so the identifier lands at (16 - (N >> 3)).
static void slaac_place_iid(uint8_t *out, const uint8_t *iid, uint8_t iid_bits)
{
    size_t octets = (size_t)(iid_bits >> 3);
    memcpy(out + (IDEMIP_IP6_ADDR_LEN - octets), iid, octets);
}

// sec 5.3: the left-most bits are the link-local prefix RFC 4291 sec 2.5.6 gives as FE80::/10, "the
// bits in the address to the right of the link-local prefix are set to all zeroes", and the
// right-most N bits are the interface identifier.
static void slaac_form_link_local(uint8_t *out, const uint8_t *iid, uint8_t iid_bits)
{
    memset(out, 0, IDEMIP_IP6_ADDR_LEN);
    out[0] = 0xFEu;
    out[1] = 0x80u;
    slaac_place_iid(out, iid, iid_bits);
}

// sec 5.5.3 (d): the link prefix over 128 - N bits, then the interface identifier over N. The sum is
// exactly 128, checked by the caller, so the prefix octets and the identifier octets meet with no gap.
static void slaac_form_global(uint8_t *out, const uint8_t *prefix, uint8_t prefix_len, const uint8_t *iid,
                              uint8_t iid_bits)
{
    memset(out, 0, IDEMIP_IP6_ADDR_LEN);
    memcpy(out, prefix, (size_t)(prefix_len >> 3));
    slaac_place_iid(out, iid, iid_bits);
}

// sec 5.3: "If the sum of the link-local prefix length and N is larger than 128, autoconfiguration
// fails and manual configuration is required." The identifier arrives as whole octets, so a length
// that is not a multiple of eight cannot be laid into an address held as octets. RFC 2464 sec 4 fixes
// N at 64 for Ethernet, and this stack's link layer is Ethernet II.
static idemip_bool slaac_iid_ok(const uint8_t *iid, uint8_t iid_bits, uint8_t prefix_len)
{
    return (idemip_bool)(iid != NULL && iid_bits != 0u && (uint8_t)(iid_bits & 7u) == 0u &&
                         (uint32_t)prefix_len + (uint32_t)iid_bits <= SLAAC_ADDR_BITS &&
                         (uint8_t)(prefix_len >> 3) <= (uint8_t)(IDEMIP_IP6_ADDR_LEN - (iid_bits >> 3)));
}

// --- the clock -------------------------------------------------------------

// True once @p now has reached @p deadline. Both sit on the same 64-bit millisecond clock, so this is
// one comparison and nothing wraps under it.
static idemip_bool slaac_due(IdemIpMs now, IdemIpMs deadline)
{
    return (now >= deadline) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// Milliseconds still to run on a deadline, and zero once it is due.
static IdemIpMs slaac_remaining(IdemIpMs now, IdemIpMs deadline)
{
    return slaac_due(now, deadline) ? (IdemIpMs)0 : (deadline - now);
}

// --- the list --------------------------------------------------------------

static uint8_t slaac_find_addr(uint8_t *restrict work, const uint8_t *addr)
{
    for (uint8_t i = 0; i < SLAAC_ENTRIES; i++)
    {
        const SlaacEntry *e = SLAAC_AT(work, i);
        if (e->used && slaac_addr_eq(e->addr, addr))
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_SLAAC_NONE;
}

// sec 5.5.3 (d) and (e) match "the prefix of an address configured by stateless autoconfiguration
// already in the list", which is the same prefix length and the same leading bits.
static uint8_t slaac_find_prefix(uint8_t *restrict work, const uint8_t *prefix, uint8_t prefix_len)
{
    for (uint8_t i = 0; i < SLAAC_ENTRIES; i++)
    {
        const SlaacEntry *e = SLAAC_AT(work, i);
        if (e->used && e->prefix_len == prefix_len && slaac_prefix_eq(e->addr, prefix, prefix_len))
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_SLAAC_NONE;
}

static uint8_t slaac_free_slot(uint8_t *restrict work)
{
    for (uint8_t i = 0; i < SLAAC_ENTRIES; i++)
    {
        if (!SLAAC_AT(work, i)->used)
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_SLAAC_NONE;
}

static uint8_t slaac_count(uint8_t *restrict work)
{
    uint8_t n = 0u;
    for (uint8_t i = 0; i < SLAAC_ENTRIES; i++)
    {
        if (SLAAC_AT(work, i)->used)
        {
            n++;
        }
    }
    return n;
}

// Every result member, cleared, so an entry reports what this call found and never what the last one
// did.
static void slaac_clear_results(SlaacIo *io)
{
    memset(io->addr, 0, sizeof io->addr);
    io->valid_at = 0;
    io->preferred_at = 0;
    io->entry = (uint8_t)IDEMIP_SLAAC_NONE;
    io->state = IDEMIP_SLAAC_ADDR_FREE;
    io->prefix_len = 0u;
    io->addresses = 0u;
    io->valid_infinite = IDEMIP_FALSE;
    io->preferred_infinite = IDEMIP_FALSE;
    io->created = IDEMIP_FALSE;
    io->updated = IDEMIP_FALSE;
    io->ignored = IDEMIP_FALSE;
    io->two_hour = IDEMIP_FALSE;
    io->deprecated = IDEMIP_FALSE;
    io->invalidated = IDEMIP_FALSE;
}

// One entry, into the result members of the operand block. The address is copied rather than pointed
// at, so an invalidated one is still readable after its slot is freed.
static void slaac_publish(uint8_t *restrict work, uint8_t index)
{
    SlaacIo *io = SLAAC_IO(work);
    const SlaacEntry *e = SLAAC_AT(work, index);
    io->entry = index;
    memcpy(io->addr, e->addr, IDEMIP_IP6_ADDR_LEN);
    io->valid_at = e->valid_at;
    io->preferred_at = e->preferred_at;
    io->state = e->state;
    io->prefix_len = e->prefix_len;
    io->valid_infinite = e->valid_infinite;
    io->preferred_infinite = e->preferred_infinite;
    io->addresses = slaac_count(work);
}

// --- lifetimes -------------------------------------------------------------

// sec 5.5.3 (e): "the preferred lifetime of the corresponding address is always reset to the Preferred
// Lifetime in the received Prefix Information option, regardless of whether the valid lifetime is also
// reset or ignored". A preferred lifetime of zero deprecates the address at once, sec 5.5.4 making an
// address deprecated "when its preferred lifetime expires".
static void slaac_set_preferred(SlaacEntry *e, IdemIpMs now, uint32_t preferred_s)
{
    e->preferred_infinite = (idemip_bool)(preferred_s == IDEMIP_SLAAC_LIFETIME_INFINITE);
    e->preferred_at = e->preferred_infinite ? (IdemIpMs)0 : (now + idemip_ms_from_s(preferred_s));
    e->state = (preferred_s != 0u) ? IDEMIP_SLAAC_ADDR_PREFERRED : IDEMIP_SLAAC_ADDR_DEPRECATED;
}

static void slaac_set_valid(SlaacEntry *e, IdemIpMs now, uint32_t valid_s)
{
    e->valid_infinite = (idemip_bool)(valid_s == IDEMIP_SLAAC_LIFETIME_INFINITE);
    e->valid_at = e->valid_infinite ? (IdemIpMs)0 : (now + idemip_ms_from_s(valid_s));
}

/*
 * sec 5.5.3 (e), the two-hour rule, over the remaining time to the valid lifetime expiration of the
 * address already in the list, which the section calls RemainingLifetime:
 *
 *   1. "If the received Valid Lifetime is greater than 2 hours or greater than RemainingLifetime, set
 *      the valid lifetime of the corresponding address to the advertised Valid Lifetime."
 *   2. "If RemainingLifetime is less than or equal to 2 hours, ignore the Prefix Information option
 *      with regards to the valid lifetime, unless the Router Advertisement from which this option was
 *      obtained has been authenticated... If the Router Advertisement was authenticated, the valid
 *      lifetime of the corresponding address should be set to the Valid Lifetime in the received
 *      option."
 *   3. "Otherwise, reset the valid lifetime of the corresponding address to 2 hours."
 *
 * An infinite received lifetime is greater than 2 hours, so it takes rule 1. An infinite
 * RemainingLifetime is neither less than the received lifetime nor at or under 2 hours, so it takes
 * rule 1 or rule 3.
 */
static void slaac_two_hour_rule(uint8_t *restrict work, SlaacEntry *e, IdemIpMs now, uint32_t valid_s,
                                idemip_bool authenticated)
{
    SlaacIo *io = SLAAC_IO(work);
    idemip_bool received_infinite = (idemip_bool)(valid_s == IDEMIP_SLAAC_LIFETIME_INFINITE);
    IdemIpMs received_ms = idemip_ms_from_s(valid_s);
    IdemIpMs remaining_ms = e->valid_infinite ? (IdemIpMs)0 : slaac_remaining(now, e->valid_at);

    if (received_infinite || received_ms > (IdemIpMs)IDEMIP_SLAAC_TWO_HOURS_MS ||
        (!e->valid_infinite && received_ms > remaining_ms))
    {
        slaac_set_valid(e, now, valid_s);
        return;
    }
    if (!e->valid_infinite && remaining_ms <= (IdemIpMs)IDEMIP_SLAAC_TWO_HOURS_MS)
    {
        if (authenticated)
        {
            slaac_set_valid(e, now, valid_s);
        }
        else
        {
            io->two_hour = IDEMIP_TRUE;
        }
        return;
    }
    e->valid_infinite = IDEMIP_FALSE;
    e->valid_at = now + (IdemIpMs)IDEMIP_SLAAC_TWO_HOURS_MS;
    io->two_hour = IDEMIP_TRUE;
}

// --- the entries -----------------------------------------------------------

// The context and the list, zeroed, then the mark. A zeroed slot is IDEMIP_SLAAC_ADDR_FREE and holds
// no address. The operand block is the caller's and is left as it stands.
void idemip_slaac_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_SLAAC_OFF_CTX, 0, SLAAC_STATE_BYTES);
    SLAAC_CTX(work)->ready = SLAAC_READY;
    SLAAC_IO(work)->status = IDEMIP_OK;
}

// sec 5.3: "A node forms a link-local address whenever an interface becomes enabled", and that
// address "has an infinite preferred and valid lifetime; it is never timed out". An address already in
// the list is reported rather than added twice.
void idemip_slaac_link_local(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    SlaacIo *io = SLAAC_IO(work);
    io->status = IDEMIP_ERR;
    slaac_clear_results(io);
    if (!slaac_ready(work) || !slaac_iid_ok(io->link_local_args.iid, io->link_local_args.iid_bits, SLAAC_LINK_LOCAL_LEN))
    {
        return;
    }
    slaac_form_link_local(io->addr, io->link_local_args.iid, io->link_local_args.iid_bits);
    uint8_t index = slaac_find_addr(work, io->addr);
    if (index != (uint8_t)IDEMIP_SLAAC_NONE)
    {
        slaac_publish(work, index);
        io->status = IDEMIP_OK;
        return;
    }
    index = slaac_free_slot(work);
    if (index == (uint8_t)IDEMIP_SLAAC_NONE)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    SlaacEntry *e = SLAAC_AT(work, index);
    memcpy(e->addr, io->addr, IDEMIP_IP6_ADDR_LEN);
    e->prefix_len = SLAAC_LINK_LOCAL_LEN;
    e->used = IDEMIP_TRUE;
    slaac_set_preferred(e, 0u, IDEMIP_SLAAC_LIFETIME_INFINITE);
    slaac_set_valid(e, 0u, IDEMIP_SLAAC_LIFETIME_INFINITE);
    slaac_publish(work, index);
    io->created = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

// sec 5.5.3, one Prefix Information option, rule by rule. Rules (a), (b), (c) and the two tests in (d)
// each "silently ignore the Prefix Information option", which is IDEMIP_OK with ignored set: the
// option was well formed and this node has nothing to do with it.
void idemip_slaac_prefix_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    SlaacIo *io = SLAAC_IO(work);
    io->status = IDEMIP_ERR;
    slaac_clear_results(io);
    const SlaacPrefixArgs *a = &io->prefix_args;
    // The caller's 32-bit reading, on the one clock every deadline this sets sits on.
    const IdemIpMs now = idemip_ms_extend(&SLAAC_CTX(work)->tick_ms, &SLAAC_CTX(work)->tick_hi, a->now_ms);
    // RFC 4861 sec 4.6.2 puts Prefix Length "from 0 to 128", so anything above is not a field this
    // unit can match or form on.
    if (!slaac_ready(work) || a->prefix == NULL || a->prefix_len > SLAAC_ADDR_BITS)
    {
        return;
    }

    // (a) "If the Autonomous flag is not set, silently ignore the Prefix Information option."
    // (b) "If the prefix is the link-local prefix, silently ignore the Prefix Information option."
    // (c) "If the preferred lifetime is greater than the valid lifetime, silently ignore the Prefix
    //     Information option."
    if (!a->autonomous || slaac_is_link_local(a->prefix) || a->preferred_s > a->valid_s)
    {
        io->ignored = IDEMIP_TRUE;
        io->addresses = slaac_count(work);
        io->status = IDEMIP_OK;
        return;
    }

    uint8_t index = slaac_find_prefix(work, a->prefix, a->prefix_len);
    if (index == (uint8_t)IDEMIP_SLAAC_NONE)
    {
        // (d) forms an address when the prefix is not one already in the list "and if the Valid
        // Lifetime is not 0". "If the sum of the prefix length and interface identifier length does
        // not equal 128 bits, the Prefix Information option MUST be ignored."
        if (a->valid_s == 0u || (uint32_t)a->prefix_len + (uint32_t)a->iid_bits != SLAAC_ADDR_BITS)
        {
            io->ignored = IDEMIP_TRUE;
            io->addresses = slaac_count(work);
            io->status = IDEMIP_OK;
            return;
        }
        if (!slaac_iid_ok(a->iid, a->iid_bits, a->prefix_len))
        {
            return;
        }
        slaac_form_global(io->addr, a->prefix, a->prefix_len, a->iid, a->iid_bits);
        // "If an address is formed successfully and the address is not yet in the list, the host adds
        // it to the list", so one already there is reported and not added twice.
        uint8_t held = slaac_find_addr(work, io->addr);
        if (held != (uint8_t)IDEMIP_SLAAC_NONE)
        {
            slaac_publish(work, held);
            io->status = IDEMIP_OK;
            return;
        }
        // A full list frees a slot when a valid lifetime expires or the caller removes an address, so
        // this is a retry and not a fault.
        uint8_t slot = slaac_free_slot(work);
        if (slot == (uint8_t)IDEMIP_SLAAC_NONE)
        {
            io->status = IDEMIP_BUSY;
            return;
        }
        SlaacEntry *e = SLAAC_AT(work, slot);
        memcpy(e->addr, io->addr, IDEMIP_IP6_ADDR_LEN);
        e->prefix_len = a->prefix_len;
        e->used = IDEMIP_TRUE;
        // "initializing its preferred and valid lifetime values from the Prefix Information option"
        slaac_set_preferred(e, now, a->preferred_s);
        slaac_set_valid(e, now, a->valid_s);
        slaac_publish(work, slot);
        io->created = IDEMIP_TRUE;
        io->status = IDEMIP_OK;
        return;
    }

    // (e) the prefix is one an address in the list was configured from.
    SlaacEntry *e = SLAAC_AT(work, index);
    slaac_two_hour_rule(work, e, now, a->valid_s, a->authenticated);
    slaac_set_preferred(e, now, a->preferred_s);
    slaac_publish(work, index);
    io->updated = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

void idemip_slaac_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    SlaacIo *io = SLAAC_IO(work);
    io->status = IDEMIP_ERR;
    slaac_clear_results(io);
    if (!slaac_ready(work) || io->addr_args.addr == NULL)
    {
        return;
    }
    uint8_t index = slaac_find_addr(work, io->addr_args.addr);
    if (index == (uint8_t)IDEMIP_SLAAC_NONE)
    {
        return;
    }
    slaac_publish(work, index);
    io->status = IDEMIP_OK;
}

void idemip_slaac_get(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    SlaacIo *io = SLAAC_IO(work);
    io->status = IDEMIP_ERR;
    slaac_clear_results(io);
    if (!slaac_ready(work) || io->addr_args.index >= SLAAC_ENTRIES || !SLAAC_AT(work, io->addr_args.index)->used)
    {
        return;
    }
    slaac_publish(work, io->addr_args.index);
    io->status = IDEMIP_OK;
}

// sec 5.5.4: an address "becomes invalid when its valid lifetime expires", and an invalid address is
// "an address that is not assigned to any interface", so its slot is freed.
void idemip_slaac_remove(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    SlaacIo *io = SLAAC_IO(work);
    io->status = IDEMIP_ERR;
    slaac_clear_results(io);
    if (!slaac_ready(work) || io->addr_args.addr == NULL)
    {
        return;
    }
    uint8_t index = slaac_find_addr(work, io->addr_args.addr);
    if (index == (uint8_t)IDEMIP_SLAAC_NONE)
    {
        return;
    }
    slaac_publish(work, index);
    memset(SLAAC_AT(work, index), 0, sizeof(SlaacEntry));
    io->addresses = slaac_count(work);
    io->status = IDEMIP_OK;
}

// sec 5.5.4, one event per call: "A preferred address becomes deprecated when its preferred lifetime
// expires" and "An address (and its association with an interface) becomes invalid when its valid
// lifetime expires". A slot with both due is invalidated, the valid lifetime being the outer one.
//
// Nothing due reports BUSY, since the same call on a later tick fires one.
void idemip_slaac_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    SlaacIo *io = SLAAC_IO(work);
    io->status = IDEMIP_ERR;
    slaac_clear_results(io);
    if (!slaac_ready(work))
    {
        return;
    }
    const IdemIpMs now = idemip_ms_extend(&SLAAC_CTX(work)->tick_ms, &SLAAC_CTX(work)->tick_hi, io->tick_args.now_ms);
    for (uint8_t i = 0; i < SLAAC_ENTRIES; i++)
    {
        SlaacEntry *e = SLAAC_AT(work, i);
        if (!e->used)
        {
            continue;
        }
        if (!e->valid_infinite && slaac_due(now, e->valid_at))
        {
            slaac_publish(work, i);
            memset(e, 0, sizeof(SlaacEntry));
            io->addresses = slaac_count(work);
            io->invalidated = IDEMIP_TRUE;
            io->status = IDEMIP_OK;
            return;
        }
        if (e->state == IDEMIP_SLAAC_ADDR_PREFERRED && !e->preferred_infinite && slaac_due(now, e->preferred_at))
        {
            e->state = IDEMIP_SLAAC_ADDR_DEPRECATED;
            slaac_publish(work, i);
            io->deprecated = IDEMIP_TRUE;
            io->status = IDEMIP_OK;
            return;
        }
    }
    io->addresses = slaac_count(work);
    io->status = IDEMIP_BUSY;
}

IDEMIP_END_DECLS
