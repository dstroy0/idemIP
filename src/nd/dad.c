// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dad.c
 * @brief The RFC 4862 sec 5.4 machine over each tentative address, in the caller's borrow.
 *
 * The context holds the bound configuration and the mark clear leaves; the table holds one machine
 * per tentative address, each with its state, the solicitations sent and received, its RetransTimer
 * and its next deadline. Every entry is a function of the one pointer it is handed: the operand
 * block, the context and the table are all regions of that borrow, at compile-time offsets, and no
 * entry reads or writes a byte outside it.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/nd/dad.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads something else here and
// every entry but clear refuses it.
#define DAD_READY 0x44414431u

// A deadline is one absolute millisecond on the 64-bit clock. RFC 4862 sec 5.4 waits RetransTimer
// milliseconds for a defence and RFC 4861 sec 6.3.4 lets a Router Advertisement set that timer, so the
// value reaching idemip_dad_start is a remote party's; it is served whole rather than held at a bound.

// One machine over one tentative address (RFC 4862 sec 5.4). sent counts the solicitations sec 5.4.2
// transmits, received the ones sec 5.4.3 counts against the loopback semantics, and hw_derived is
// sec 5.4.5's "interface identifier based on the hardware address".
typedef struct
{
    IdemIpMs deadline;
    uint32_t retrans_ms;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    IdemIpDadState state;
    uint8_t sent;
    uint8_t received;
    idemip_bool hw_derived;
    idemip_bool used;
    uint8_t pad[(1u << IDEMIP_DAD_ENTRY_SHIFT) -
                (sizeof(IdemIpMs) + 4u + IDEMIP_IP6_ADDR_LEN + sizeof(IdemIpDadState) +
                 (4u * sizeof(idemip_bool)))];
} DadEntry;

// The running context: the sec 5.1 configuration this interface was bound to, and the mark.
typedef struct
{
    uint32_t ready;
    const IdemIpDadCfg *cfg;
    uint32_t tick_ms; // the last reading of the caller's 32-bit millisecond clock
    uint32_t tick_hi; // its high word, raised each time that reading wraps
} DadCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_DAD_OFF_CTX, sizeof(DadCtx), IDEMIP_DAD_OFF_ENTRIES, "dad's context");

// An index is (i << SHIFT), so each entry is exactly its width.
static_assert(sizeof(DadEntry) == (1u << IDEMIP_DAD_ENTRY_SHIFT),
              "a DAD entry must be 1 << IDEMIP_DAD_ENTRY_SHIFT wide");

// The caller's borrow, split: the operand block, the context, then the table. dad.h publishes the
// offsets; these two asserts prove the span covers them before anything runs. The first keeps the
// context inside the region ahead of the table, the second the whole map inside the borrow.
static_assert(IDEMIP_DAD_OFF_CTX + sizeof(DadCtx) <= IDEMIP_DAD_OFF_ENTRIES,
              "IDEMIP_DAD_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_DAD_OFF_END <= IDEMIP_DAD_BORROW,
              "IDEMIP_DAD_BORROW is short of the map - raise IDEMIP_DAD_CTX_BYTES in idemip_config.h");

// clear zeroes the table, so the state a cleared slot reads is the free one.
static_assert(IDEMIP_DAD_STATE_FREE == 0, "IDEMIP_DAD_STATE_FREE must be zero: clear zeroes the table");

// The sec 5.4.2 delay is drawn over [0, MAX_RTR_SOLICITATION_DELAY] by scaling a 16-bit slice of a
// random word, so that bound times 2^16 stays inside 32 bits.
static_assert(IDEMIP_ND6_MAX_RTR_SOLICITATION_DELAY_MS < 0x10000u,
              "the [0, MAX_RTR_SOLICITATION_DELAY] draw multiplies a 16-bit word by the bound + 1 in 32 bits");

// The regions, at their offsets in the caller's borrow.
#define DAD_IO(w) IDEMIP_DAD_IO(w)
#define DAD_CTX(w) ((DadCtx *)(void *)((w) + IDEMIP_DAD_OFF_CTX))
#define DAD_AT(w, i) ((DadEntry *)(void *)((w) + IDEMIP_DAD_OFF_ENTRIES + ((size_t)(i) << IDEMIP_DAD_ENTRY_SHIFT)))

// Octets the context and the table span, which is what clear zeroes.
#define DAD_STATE_BYTES ((size_t)IDEMIP_DAD_OFF_END - (size_t)IDEMIP_DAD_OFF_CTX)

// The count as the octet an index is compared against.
#define DAD_ENTRIES ((uint8_t)IDEMIP_IP6_ADDRESSES)

// RFC 4291 sec 2.7.1: a solicited-node multicast address "is formed by taking the low-order 24 bits
// of an address (unicast or anycast) and appending those bits to the prefix
// FF02:0:0:0:0:1:FF00::/104", which is these 13 octets.
static const uint8_t dad_solicited_prefix[13] = {0xFFu, 0x02u, 0u, 0u, 0u, 0u, 0u,
                                                 0u,    0u,    0u, 0u, 0x01u, 0xFFu};

// A borrow clear has not run on holds no mark, so every entry but clear refuses it.
static idemip_bool dad_ready(uint8_t *restrict work)
{
    return (idemip_bool)(DAD_CTX(work)->ready == DAD_READY);
}

// --- addresses -------------------------------------------------------------

static idemip_bool dad_addr_eq(const uint8_t *a, const uint8_t *b)
{
    return (idemip_bool)(idemip_bytes_eq(a, b, IDEMIP_IP6_ADDR_LEN));
}

// RFC 4291 sec 2.7: a multicast address begins with FF.
static idemip_bool dad_is_multicast(const uint8_t *addr)
{
    return (idemip_bool)(addr[0] == 0xFFu);
}

// RFC 4291 sec 2.5.2: "The address 0:0:0:0:0:0:0:0 is called the unspecified address."
static idemip_bool dad_is_unspecified(const uint8_t *addr)
{
    return idemip_bytes_zero(addr, IDEMIP_IP6_ADDR_LEN);
}

// RFC 4291 sec 2.5.6: the first ten bits of a link-local address are 1111111010.
static idemip_bool dad_is_link_local(const uint8_t *addr)
{
    return (idemip_bool)(addr[0] == 0xFEu && (uint8_t)(addr[1] & 0xC0u) == 0x80u);
}

// RFC 4291 sec 2.7.1's FF02:0:0:0:0:1:FFXX:XXXX over the low-order 24 bits of @p addr.
static void dad_solicited(uint8_t *out, const uint8_t *addr)
{
    memcpy(out, dad_solicited_prefix, sizeof dad_solicited_prefix);
    out[13] = addr[13];
    out[14] = addr[14];
    out[15] = addr[15];
}

// --- the clock and the draw ------------------------------------------------

// True once @p now has reached @p deadline. Both sit on the same 64-bit millisecond clock, so this is
// one comparison and nothing wraps under it.
static idemip_bool dad_due(IdemIpMs now, IdemIpMs deadline)
{
    return (now >= deadline) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// A draw over [0, span]. sec 5.4.2 delays "by a random delay between 0 and
// MAX_RTR_SOLICITATION_DELAY". The low 16 bits scale by span + 1 and shift back, so the result covers
// 0 through span and no divide runs.
static uint32_t dad_draw(uint32_t rand, uint32_t span)
{
    return (uint32_t)(((rand & 0xFFFFu) * (span + 1u)) >> 16);
}

// --- the table -------------------------------------------------------------

// The slot holding @p addr, or IDEMIP_DAD_NONE.
static uint8_t dad_find_addr(uint8_t *restrict work, const uint8_t *addr)
{
    for (uint8_t i = 0; i < DAD_ENTRIES; i++)
    {
        const DadEntry *e = DAD_AT(work, i);
        if (e->used && dad_addr_eq(e->addr, addr))
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_DAD_NONE;
}

// The lowest free slot, or IDEMIP_DAD_NONE.
static uint8_t dad_free_slot(uint8_t *restrict work)
{
    for (uint8_t i = 0; i < DAD_ENTRIES; i++)
    {
        if (!DAD_AT(work, i)->used)
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_DAD_NONE;
}

// Every result member, cleared, so an entry reports what this call found and never what the last one
// did.
static void dad_clear_results(DadIo *io)
{
    io->target = NULL;
    io->deadline = 0;
    memset(io->solicited, 0, sizeof io->solicited);
    io->entry = (uint8_t)IDEMIP_DAD_NONE;
    io->state = IDEMIP_DAD_STATE_FREE;
    io->sent = 0u;
    io->received = 0u;
    io->join = IDEMIP_FALSE;
    io->send_ns = IDEMIP_FALSE;
    io->unique = IDEMIP_FALSE;
    io->duplicate = IDEMIP_FALSE;
    io->disable_ip = IDEMIP_FALSE;
    io->tentative = IDEMIP_FALSE;
}

// One entry, into the result members of the operand block. target and solicited are what sec 5.4.2
// puts in a solicitation's Target Address and IP destination.
static void dad_publish(uint8_t *restrict work, uint8_t index)
{
    DadIo *io = DAD_IO(work);
    DadEntry *e = DAD_AT(work, index);
    io->entry = index;
    io->target = e->addr;
    io->deadline = e->deadline;
    io->state = e->state;
    io->sent = e->sent;
    io->received = e->received;
    dad_solicited(io->solicited, e->addr);
}

// --- the machine -----------------------------------------------------------

// sec 5.4.5: a duplicate "MUST NOT be assigned to an interface", and where it is "a link-local
// address formed from an interface identifier based on the hardware address ... IP operation on the
// interface SHOULD be disabled". The address stays in the table in the duplicate state, so a caller
// that asks again gets the same answer until it stops the machine.
static void dad_fail(uint8_t *restrict work, uint8_t index)
{
    DadIo *io = DAD_IO(work);
    DadEntry *e = DAD_AT(work, index);
    e->state = IDEMIP_DAD_STATE_DUPLICATE;
    e->deadline = 0;
    io->duplicate = IDEMIP_TRUE;
    io->disable_ip = (idemip_bool)(e->hw_derived && dad_is_link_local(e->addr));
}

// sec 5.4: the procedure ends when "none of the tests indicate the presence of a duplicate address
// within RetransTimer milliseconds after having sent DupAddrDetectTransmits Neighbor Solicitations",
// after which the address "may be assigned to an interface".
static void dad_pass(uint8_t *restrict work, uint8_t index)
{
    DadEntry *e = DAD_AT(work, index);
    e->state = IDEMIP_DAD_STATE_UNIQUE;
    e->deadline = 0;
    DAD_IO(work)->unique = IDEMIP_TRUE;
}

// sec 5.4.2: "To check an address, a node sends DupAddrDetectTransmits Neighbor Solicitations, each
// separated by RetransTimer milliseconds", and sec 5.1 makes RetransTimer "the time a node waits
// after sending the last Neighbor Solicitation before ending the Duplicate Address Detection
// process", which is the WAIT the last transmission enters.
static void dad_send(uint8_t *restrict work, uint8_t index, IdemIpMs now)
{
    DadIo *io = DAD_IO(work);
    DadEntry *e = DAD_AT(work, index);
    const DadCtx *ctx = DAD_CTX(work);
    io->send_ns = IDEMIP_TRUE;
    e->sent++;
    e->deadline = now + (IdemIpMs)e->retrans_ms;
    e->state = (e->sent >= ctx->cfg->transmits) ? IDEMIP_DAD_STATE_WAIT : IDEMIP_DAD_STATE_PROBING;
}

// The deadline that has passed on the lowest slot holding one: sec 5.4.2's delay before joining and
// soliciting, the next of DupAddrDetectTransmits solicitations, and the RetransTimer that ends the
// procedure.
//
// A slot whose deadline is still ahead is passed over, and a call that found none reports BUSY, since
// the same call on a later tick fires one.
static void dad_fire(uint8_t *restrict work)
{
    DadIo *io = DAD_IO(work);
    const IdemIpMs now = idemip_ms_extend(&DAD_CTX(work)->tick_ms, &DAD_CTX(work)->tick_hi, io->tick_args.now_ms);

    for (uint8_t i = 0; i < DAD_ENTRIES; i++)
    {
        DadEntry *e = DAD_AT(work, i);
        if (!e->used || e->state == IDEMIP_DAD_STATE_FREE || e->state == IDEMIP_DAD_STATE_UNIQUE ||
            e->state == IDEMIP_DAD_STATE_DUPLICATE || !dad_due(now, e->deadline))
        {
            continue;
        }
        switch (e->state)
        {
        case IDEMIP_DAD_STATE_DELAY:
            // sec 5.4.2: "Before sending a Neighbor Solicitation, an interface MUST join the
            // all-nodes multicast address and the solicited-node multicast address of the tentative
            // address", the delay above having held the join back.
            io->join = IDEMIP_TRUE;
            dad_send(work, i, now);
            break;
        case IDEMIP_DAD_STATE_PROBING:
            dad_send(work, i, now);
            break;
        case IDEMIP_DAD_STATE_WAIT:
            dad_pass(work, i);
            break;
        default:
            break;
        }
        dad_publish(work, i);
        io->status = IDEMIP_OK;
        return;
    }
    io->status = IDEMIP_BUSY;
}

// sec 5.4.3's two tests over one solicitation whose IP source is the unspecified address, which is
// "from a node performing Duplicate Address Detection".
//
// The first: "If a Neighbor Solicitation for a tentative address is received before one is sent, the
// tentative address is a duplicate." The second: "If the actual number of Neighbor Solicitations
// received exceeds the number expected based on the loopback semantics (e.g., the interface does not
// loop back the packet, yet one or more solicitations was received), the tentative address is a
// duplicate." An interface that loops its own multicast back expects the ones it sent.
static void dad_solicitation(uint8_t *restrict work, uint8_t index)
{
    DadEntry *e = DAD_AT(work, index);
    const DadCtx *ctx = DAD_CTX(work);
    if (e->sent == 0u)
    {
        dad_fail(work, index);
        return;
    }
    if (e->received < 0xFFu)
    {
        e->received++;
    }
    uint8_t expected = ctx->cfg->loopback ? e->sent : 0u;
    if (e->received > expected)
    {
        dad_fail(work, index);
    }
}

// --- the entries -----------------------------------------------------------

// The context and the table, zeroed, then the mark. A zeroed slot is IDEMIP_DAD_STATE_FREE and holds
// no address. The operand block is the caller's and is left as it stands.
void idemip_dad_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_DAD_OFF_CTX, 0, DAD_STATE_BYTES);
    DAD_CTX(work)->ready = DAD_READY;
    DAD_IO(work)->status = IDEMIP_OK;
}

// sec 5.1's node configuration variables, which the caller holds in rodata.
void idemip_dad_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DadIo *io = DAD_IO(work);
    io->status = IDEMIP_ERR;
    dad_clear_results(io);
    if (!dad_ready(work) || io->bind_args.cfg == NULL)
    {
        return;
    }
    DAD_CTX(work)->cfg = io->bind_args.cfg;
    io->status = IDEMIP_OK;
}

// sec 5.4: the procedure runs on a unicast address "prior to assigning them to an interface". A
// multicast or unspecified address carries no such assignment, and neither does an address already in
// the table, so all three are refused rather than retried.
//
// sec 5.4: "An interface whose DupAddrDetectTransmits variable is set to zero does not perform
// Duplicate Address Detection", so the address is unique on the call that opened it.
void idemip_dad_start(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DadIo *io = DAD_IO(work);
    io->status = IDEMIP_ERR;
    dad_clear_results(io);
    const DadCtx *ctx = DAD_CTX(work);
    if (!dad_ready(work) || ctx->cfg == NULL || io->start_args.addr == NULL)
    {
        return;
    }
    // sec 5.4: "Duplicate Address Detection MUST NOT be performed on anycast addresses (note that
    // anycast addresses cannot syntactically be distinguished from unicast addresses)." The octets
    // cannot say which it is, so the operand does.
    if (dad_is_multicast(io->start_args.addr) || dad_is_unspecified(io->start_args.addr) ||
        io->start_args.anycast)
    {
        return;
    }
    if (dad_find_addr(work, io->start_args.addr) != (uint8_t)IDEMIP_DAD_NONE)
    {
        return;
    }
    // A full table frees a slot when the caller stops a machine, so this is a retry and not a fault.
    uint8_t index = dad_free_slot(work);
    if (index == (uint8_t)IDEMIP_DAD_NONE)
    {
        io->status = IDEMIP_BUSY;
        return;
    }

    DadEntry *e = DAD_AT(work, index);
    memcpy(e->addr, io->start_args.addr, IDEMIP_IP6_ADDR_LEN);
    const uint32_t retrans = (io->start_args.retrans_ms != 0u) ? io->start_args.retrans_ms
                                                         : (uint32_t)IDEMIP_ND6_RETRANS_TIMER_MS;
    e->retrans_ms = retrans;
    e->sent = 0u;
    e->received = 0u;
    e->hw_derived = io->start_args.hw_derived;
    e->used = IDEMIP_TRUE;
    if (ctx->cfg->transmits == 0u)
    {
        dad_pass(work, index);
    }
    else
    {
        e->state = IDEMIP_DAD_STATE_DELAY;
        // sec 5.4.2 draws the delay "between 0 and MAX_RTR_SOLICITATION_DELAY"; without one the
        // first solicitation is due on the next tick.
        const IdemIpMs start = idemip_ms_extend(&DAD_CTX(work)->tick_ms, &DAD_CTX(work)->tick_hi, io->start_args.now_ms);
        e->deadline = io->start_args.delay
                          ? start + (IdemIpMs)dad_draw(io->start_args.rand,
                                                       (uint32_t)IDEMIP_ND6_MAX_RTR_SOLICITATION_DELAY_MS)
                          : start;
    }
    dad_publish(work, index);
    io->status = IDEMIP_OK;
}

// The machine over an address, dropped, freeing its slot.
void idemip_dad_stop(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DadIo *io = DAD_IO(work);
    io->status = IDEMIP_ERR;
    dad_clear_results(io);
    if (!dad_ready(work) || io->addr_args.addr == NULL)
    {
        return;
    }
    uint8_t index = dad_find_addr(work, io->addr_args.addr);
    if (index == (uint8_t)IDEMIP_DAD_NONE)
    {
        return;
    }
    io->entry = index;
    memset(DAD_AT(work, index), 0, sizeof(DadEntry));
    io->status = IDEMIP_OK;
}

void idemip_dad_find(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DadIo *io = DAD_IO(work);
    io->status = IDEMIP_ERR;
    dad_clear_results(io);
    if (!dad_ready(work) || io->addr_args.addr == NULL)
    {
        return;
    }
    uint8_t index = dad_find_addr(work, io->addr_args.addr);
    if (index == (uint8_t)IDEMIP_DAD_NONE)
    {
        return;
    }
    dad_publish(work, index);
    io->tentative = (idemip_bool)(io->state == IDEMIP_DAD_STATE_DELAY || io->state == IDEMIP_DAD_STATE_PROBING ||
                                  io->state == IDEMIP_DAD_STATE_WAIT);
    io->status = IDEMIP_OK;
}

// sec 5.4.3: "If the target address is not tentative (i.e., it is assigned to the receiving
// interface), the solicitation is processed as described in [RFC4861]", which tentative false reports.
// "If the target address is tentative, and the source address is a unicast address, the solicitation's
// sender is performing address resolution on the target; the solicitation should be silently ignored."
// A node "MUST NOT respond to a Neighbor Solicitation for a tentative address" in any case.
void idemip_dad_ns_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DadIo *io = DAD_IO(work);
    io->status = IDEMIP_ERR;
    dad_clear_results(io);
    if (!dad_ready(work) || io->ns_in_args.target == NULL)
    {
        return;
    }
    uint8_t index = dad_find_addr(work, io->ns_in_args.target);
    if (index == (uint8_t)IDEMIP_DAD_NONE)
    {
        io->status = IDEMIP_OK;
        return;
    }
    IdemIpDadState state = DAD_AT(work, index)->state;
    idemip_bool tentative = (idemip_bool)(state == IDEMIP_DAD_STATE_DELAY || state == IDEMIP_DAD_STATE_PROBING ||
                                          state == IDEMIP_DAD_STATE_WAIT);
    if (tentative && io->ns_in_args.unspecified)
    {
        dad_solicitation(work, index);
    }
    dad_publish(work, index);
    io->tentative = tentative;
    io->status = IDEMIP_OK;
}

// sec 5.4.4 (1): "If the target address is tentative, the tentative address is not unique." Case 2, a
// target matching an assigned address, is "beyond the scope of this document", and case 3 is
// RFC 4861's, which tentative false reports.
void idemip_dad_na_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DadIo *io = DAD_IO(work);
    io->status = IDEMIP_ERR;
    dad_clear_results(io);
    if (!dad_ready(work) || io->na_in_args.target == NULL)
    {
        return;
    }
    uint8_t index = dad_find_addr(work, io->na_in_args.target);
    if (index == (uint8_t)IDEMIP_DAD_NONE)
    {
        io->status = IDEMIP_OK;
        return;
    }
    IdemIpDadState state = DAD_AT(work, index)->state;
    idemip_bool tentative = (idemip_bool)(state == IDEMIP_DAD_STATE_DELAY || state == IDEMIP_DAD_STATE_PROBING ||
                                          state == IDEMIP_DAD_STATE_WAIT);
    if (tentative)
    {
        dad_fail(work, index);
    }
    dad_publish(work, index);
    io->tentative = tentative;
    io->status = IDEMIP_OK;
}

void idemip_dad_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    DadIo *io = DAD_IO(work);
    io->status = IDEMIP_ERR;
    dad_clear_results(io);
    if (!dad_ready(work) || DAD_CTX(work)->cfg == NULL)
    {
        return;
    }
    dad_fire(work);
}

IDEMIP_END_DECLS
