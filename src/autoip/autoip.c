// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file autoip.c
 * @brief The RFC 3927 link-local address of one interface, in the caller's borrow.
 *
 * The context holds the selected address, the state, how many addresses have been drawn, and the
 * deadline the next attempt is held behind. Every entry is a function of the one pointer it is handed:
 * the operand block and the context are both regions of that borrow, at compile-time offsets, and no
 * entry reads or writes a byte outside it.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/autoip/autoip.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads something else here and
// every entry but clear refuses it.
#define AUTOIP_READY 0x41494F50u

// The word folded in with each octet of the interface address, and substituted for a zero state,
// which three shifts and three xors cannot leave.
#define AUTOIP_MIX 0x9E3779B9u

// Draws taken before the fold below is reached. RFC 3927 sec 2.1's range covers 65024 of the 65536
// values the low 16 bits of a draw land on, so a draw is kept 127 times in 128.
#define AUTOIP_DRAW_TRIES 4u

// The count of addresses sec 2.1 selects from: 169.254.1.0 through 169.254.254.255.
#define AUTOIP_SPAN (IDEMIP_AUTOIP_LAST - IDEMIP_AUTOIP_FIRST + 1u)

// Where both counters stop, so neither wraps back under MAX_CONFLICTS.
#define AUTOIP_COUNT_MAX 0xFFu

// The link-local address of one interface. tried counts the addresses drawn on it, conflicts is
// sec 2.2.1's counter against MAX_CONFLICTS, and held marks a draw waiting out RATE_LIMIT_INTERVAL
// over an address another host answered for.
typedef struct
{
    uint32_t ready;
    uint32_t ipaddr;
    uint32_t deadline_ms;
    uint32_t seed;
    IdemIpAutoIpState state;
    uint8_t tried;
    uint8_t conflicts;
    idemip_bool held;
} AutoIpCtx;

// The caller's borrow, split: the operand block, then the context. autoip.h publishes the offsets;
// these two asserts prove the span covers them before anything runs. The first keeps the context
// inside the region IDEMIP_AUTOIP_CTX_BYTES names, the second the whole map inside the borrow.
static_assert(IDEMIP_AUTOIP_OFF_CTX + sizeof(AutoIpCtx) <= IDEMIP_AUTOIP_OFF_END,
              "IDEMIP_AUTOIP_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_AUTOIP_OFF_END <= IDEMIP_AUTOIP_BORROW,
              "IDEMIP_AUTOIP_BORROW is short of the map - raise IDEMIP_AUTOIP_CTX_BYTES in idemip_config.h");

// clear zeroes the context, so the state a cleared borrow reads is the zero one.
static_assert(IDEMIP_AUTOIP_STATE_OFF == 0, "IDEMIP_AUTOIP_STATE_OFF must be zero: clear zeroes the context");

// RFC 3927 sec 2.1 draws over "169.254.1.0 to 169.254.254.255 inclusive", which is what the span the
// fold below adds and subtracts measures.
static_assert(AUTOIP_SPAN == 254u * 256u, "the fold steps by the whole RFC 3927 sec 2.1 range");

// The two edges of the fold: the lowest value it can raise lands at or below LAST, and the highest it
// can lower lands at or above FIRST, so a folded draw is inside sec 2.1's range either way.
static_assert(IDEMIP_AUTOIP_PREFIX + AUTOIP_SPAN <= IDEMIP_AUTOIP_LAST,
              "the fold raises 169.254.0.0 into RFC 3927 sec 2.1's range");
static_assert((IDEMIP_AUTOIP_PREFIX | ~IDEMIP_AUTOIP_NETMASK) - AUTOIP_SPAN >= IDEMIP_AUTOIP_FIRST,
              "the fold lowers 169.254.255.255 into RFC 3927 sec 2.1's range");

// The regions, at their offsets in the caller's borrow.
#define AUTOIP_IO(w) IDEMIP_AUTOIP_IO(w)
#define AUTOIP_CTX(w) ((AutoIpCtx *)(void *)((w) + IDEMIP_AUTOIP_OFF_CTX))

// Octets the context spans, which is what clear zeroes.
#define AUTOIP_STATE_BYTES ((size_t)IDEMIP_AUTOIP_OFF_END - (size_t)IDEMIP_AUTOIP_OFF_CTX)

// A borrow clear has not run on holds no mark, so every entry but clear refuses it.
static idemip_bool autoip_ready(uint8_t *restrict work)
{
    return (idemip_bool)(AUTOIP_CTX(work)->ready == AUTOIP_READY);
}

// --- the sec 2.1 generator -------------------------------------------------

// One step of the generator: three shifts and three xors over the state. A zero state reads as
// AUTOIP_MIX, the sequence having no way out of zero.
static uint32_t autoip_next(uint32_t seed)
{
    uint32_t s = (seed != 0u) ? seed : AUTOIP_MIX;
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
}

// RFC 3927 sec 2.1 seeds the generator "using a value derived from" per-host information "such as its
// IEEE 802 MAC address". Every octet of the interface address is folded through one step over the
// caller's word, and a step is one-to-one, so two interfaces whose addresses differ in any octet hold
// different states and step through different sequences.
static uint32_t autoip_seed(const uint8_t *mac, uint32_t rand)
{
    uint32_t s = rand;
    for (uint32_t i = 0; i < IDEMIP_ARP_HLN_ETHERNET; i++)
    {
        s = autoip_next(s ^ (uint32_t)mac[i] ^ AUTOIP_MIX);
    }
    return s;
}

// RFC 3927 sec 2.1's draw: the low 16 bits of a step under the 169.254/16 prefix, kept when they land
// in 169.254.1.0 through 169.254.254.255 and drawn again when they land in "The first 256 and last 256
// addresses in the 169.254/16 prefix", which the section reserves, or on the address taken. After
// AUTOIP_DRAW_TRIES draws the last value is folded by the span into the range and stepped one past a
// taken address, so the walk is bounded and lands in the range either way.
static uint32_t autoip_draw(AutoIpCtx *ctx, uint32_t taken)
{
    uint32_t addr = 0;
    for (uint32_t i = 0; i < AUTOIP_DRAW_TRIES; i++)
    {
        ctx->seed = autoip_next(ctx->seed);
        addr = IDEMIP_AUTOIP_PREFIX | (ctx->seed & 0xFFFFu);
        if (addr >= IDEMIP_AUTOIP_FIRST && addr <= IDEMIP_AUTOIP_LAST && addr != taken)
        {
            return addr;
        }
    }
    if (addr < IDEMIP_AUTOIP_FIRST)
    {
        addr += AUTOIP_SPAN;
    }
    if (addr > IDEMIP_AUTOIP_LAST)
    {
        addr -= AUTOIP_SPAN;
    }
    if (addr == taken)
    {
        addr = (addr == IDEMIP_AUTOIP_LAST) ? IDEMIP_AUTOIP_FIRST : addr + 1u;
    }
    return addr;
}

// --- the statics the entries delegate to -----------------------------------

// The next candidate and the count of addresses drawn on this interface. The word the caller carried
// is folded into the generator first, and the address just answered for is what the draw steps off,
// sec 2.2.1 requiring "a new pseudo-random address".
static void autoip_select(uint8_t *restrict work, uint32_t rand)
{
    AutoIpCtx *ctx = AUTOIP_CTX(work);
    ctx->seed = autoip_next(ctx->seed ^ rand);
    ctx->ipaddr = autoip_draw(ctx, ctx->ipaddr);
    if (ctx->tried < AUTOIP_COUNT_MAX)
    {
        ctx->tried = (uint8_t)(ctx->tried + 1u);
    }
    ctx->held = IDEMIP_FALSE;
    ctx->deadline_ms = 0;
}

// RFC 3927 sec 2.2.1: once the conflict count "exceeds MAX_CONFLICTS then the host MUST limit the rate
// at which it probes for new addresses to no more than one new address per RATE_LIMIT_INTERVAL". Over
// that count the draw is stamped RATE_LIMIT_INTERVAL out and the tick releases it; at or under it the
// draw happens now. Reports whether a candidate is ready to hand to acd.
static idemip_bool autoip_advance(uint8_t *restrict work, uint32_t rand, uint32_t now_ms)
{
    AutoIpCtx *ctx = AUTOIP_CTX(work);
    if (ctx->conflicts > IDEMIP_ACD_MAX_CONFLICTS)
    {
        ctx->held = IDEMIP_TRUE;
        ctx->deadline_ms = now_ms + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS;
        return IDEMIP_FALSE;
    }
    autoip_select(work, rand);
    return IDEMIP_TRUE;
}

// The difference of two millisecond clocks read as signed, so a clock past its rollover still orders
// against a deadline stamped before it.
static idemip_bool autoip_due(uint32_t now_ms, uint32_t deadline_ms)
{
    return (idemip_bool)((int32_t)(now_ms - deadline_ms) >= 0);
}

// What the context reports out: the address the interface holds, the mask sec 2.8 fixes at the prefix
// length once it is bound, the state, the count of addresses drawn, and the deadline a held draw waits
// on. An interface with nothing selected, and one whose candidate is the address another host answered
// for, both report no address.
static void autoip_report(uint8_t *restrict work)
{
    AutoIpIo *io = AUTOIP_IO(work);
    const AutoIpCtx *ctx = AUTOIP_CTX(work);
    io->ipaddr = (ctx->state == IDEMIP_AUTOIP_STATE_OFF || ctx->held) ? 0u : ctx->ipaddr;
    io->netmask = (ctx->state == IDEMIP_AUTOIP_STATE_BOUND) ? IDEMIP_AUTOIP_NETMASK : 0u;
    io->deadline_ms = ctx->deadline_ms;
    io->state = ctx->state;
    io->tried = ctx->tried;
}

// --- the entries -----------------------------------------------------------

// The context, zeroed, then the mark. A zeroed context is IDEMIP_AUTOIP_STATE_OFF with no address
// selected. The operand block is the caller's and is left as it stands.
static void autoip_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_AUTOIP_OFF_CTX, 0, AUTOIP_STATE_BYTES);
    AUTOIP_CTX(work)->ready = AUTOIP_READY;
    AUTOIP_IO(work)->status = IDEMIP_OK;
}

// RFC 3927 sec 2.1 draws the candidate and sec 2.2 hands it to acd, which "MUST test to see if the
// IPv4 Link-Local address is already in use before beginning to use it". A candidate already inside
// the range is kept rather than redrawn, sec 2.1 saying a host with "a previously recorded address
// SHOULD use that address as their first candidate when probing".
//
// An interface already claiming or holding an address is left as it stands and asks for no second
// claim: OK when it is claiming or bound, BUSY while its draw waits out sec 2.2.1's rate limit, since
// the same call on a later tick makes progress. A refused call reports the status and clears the
// claim, leaving the state the other members mirror as it stands.
static void autoip_start(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    AutoIpIo *io = AUTOIP_IO(work);
    io->status = IDEMIP_ERR;
    io->claim = IDEMIP_FALSE;
    if (!autoip_ready(work) || io->start_args.mac == NULL)
    {
        return;
    }
    AutoIpCtx *ctx = AUTOIP_CTX(work);
    if (ctx->state != IDEMIP_AUTOIP_STATE_OFF)
    {
        autoip_report(work);
        io->status = ctx->held ? IDEMIP_BUSY : IDEMIP_OK;
        return;
    }
    ctx->seed = autoip_seed(io->start_args.mac, io->start_args.rand);
    ctx->state = IDEMIP_AUTOIP_STATE_CHECKING;
    idemip_bool ready = IDEMIP_TRUE;
    if (ctx->held || ctx->ipaddr < IDEMIP_AUTOIP_FIRST || ctx->ipaddr > IDEMIP_AUTOIP_LAST)
    {
        ready = autoip_advance(work, 0u, io->start_args.now_ms);
    }
    autoip_report(work);
    io->claim = ready;
    io->status = ready ? IDEMIP_OK : IDEMIP_BUSY;
}

// RFC 3927 sec 2.2.1: a host that sees the address answered for "MUST treat this address as being in
// use by some other host, and MUST select a new pseudo-random address and repeat the process", and
// sec 2.5 runs the same test "for as long as a host is using an IPv4 Link-Local address", so a bound
// address takes this too and leaves the interface. The count this raises is sec 2.2.1's conflict
// counter.
//
// An interface with no address out reports ERR: nothing was handed to acd for another host to answer
// for, and calling again cannot change that. A conflict inside sec 2.2.1's rate limit reports BUSY,
// the draw being due on a later tick.
static void autoip_conflict(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    AutoIpIo *io = AUTOIP_IO(work);
    io->status = IDEMIP_ERR;
    io->claim = IDEMIP_FALSE;
    if (!autoip_ready(work))
    {
        return;
    }
    AutoIpCtx *ctx = AUTOIP_CTX(work);
    if (ctx->state == IDEMIP_AUTOIP_STATE_OFF || ctx->held)
    {
        return;
    }
    if (ctx->conflicts < AUTOIP_COUNT_MAX)
    {
        ctx->conflicts = (uint8_t)(ctx->conflicts + 1u);
    }
    ctx->state = IDEMIP_AUTOIP_STATE_CHECKING;
    idemip_bool ready = autoip_advance(work, io->conflict_args.rand, io->conflict_args.now_ms);
    autoip_report(work);
    io->claim = ready;
    io->status = ready ? IDEMIP_OK : IDEMIP_BUSY;
}

// RFC 3927 sec 2.4 announces the claimed address, after which it is in use, carrying the mask sec 2.8
// fixes at the prefix length with "The 169.254/16 address prefix MUST NOT be subnetted". sec 2.2.1
// counts conflicts "in the process of trying to acquire an address", which this ends, so the count
// starts over.
//
// An interface with no address out reports ERR: there is nothing acd could have announced.
static void autoip_bound(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    AutoIpIo *io = AUTOIP_IO(work);
    io->status = IDEMIP_ERR;
    io->claim = IDEMIP_FALSE;
    if (!autoip_ready(work))
    {
        return;
    }
    AutoIpCtx *ctx = AUTOIP_CTX(work);
    if (ctx->state == IDEMIP_AUTOIP_STATE_OFF || ctx->held)
    {
        return;
    }
    ctx->state = IDEMIP_AUTOIP_STATE_BOUND;
    ctx->conflicts = 0;
    ctx->deadline_ms = 0;
    autoip_report(work);
    io->status = IDEMIP_OK;
}

// RFC 3927 sec 1.9: "a host SHOULD NOT have both an operable routable address and an IPv4 Link-Local
// address configured on the same interface", so the address leaves the interface and the mask with it.
// The candidate, the count of addresses drawn and any rate limit stay in the context, sec 2.1 using
// "a previously recorded address" as "their first candidate when probing" and sec 2.2.1's limit
// counting new addresses rather than starts.
static void autoip_stop(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    AutoIpIo *io = AUTOIP_IO(work);
    io->status = IDEMIP_ERR;
    io->claim = IDEMIP_FALSE;
    if (!autoip_ready(work))
    {
        return;
    }
    AUTOIP_CTX(work)->state = IDEMIP_AUTOIP_STATE_OFF;
    autoip_report(work);
    io->status = IDEMIP_OK;
}

// RFC 3927 sec 2.2.1's rate limit, released once RATE_LIMIT_INTERVAL has passed: the draw held over
// the address another host answered for is taken and handed to acd. A sweep with no draw held ran and
// found nothing due, which is OK; a sweep inside the interval reports BUSY, the draw being due later.
// An interface stopped while a draw was held stays stopped: only start puts an address back on it.
static void autoip_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    AutoIpIo *io = AUTOIP_IO(work);
    io->status = IDEMIP_ERR;
    io->claim = IDEMIP_FALSE;
    if (!autoip_ready(work))
    {
        return;
    }
    AutoIpCtx *ctx = AUTOIP_CTX(work);
    if (ctx->state == IDEMIP_AUTOIP_STATE_OFF || !ctx->held)
    {
        autoip_report(work);
        io->status = IDEMIP_OK;
        return;
    }
    if (!autoip_due(io->tick_args.now_ms, ctx->deadline_ms))
    {
        autoip_report(work);
        io->status = IDEMIP_BUSY;
        return;
    }
    autoip_select(work, io->tick_args.rand);
    autoip_report(work);
    io->claim = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

const AutoIpNs AutoIp = {.clear = autoip_clear,
                         .start = autoip_start,
                         .conflict = autoip_conflict,
                         .bound = autoip_bound,
                         .stop = autoip_stop,
                         .tick = autoip_tick};

IDEMIP_END_DECLS
