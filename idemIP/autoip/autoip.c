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

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV4

#include "idemIP/autoip/autoip.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads something else here and
// every entry but clear refuses it.
#define AUTOIP_READY 0x41494F50u

// The link-local address of one interface. tried counts the addresses drawn on it, which is what steps
// the sec 2.1 draw when a candidate turns out to be taken.
typedef struct
{
    uint32_t ready;
    uint32_t ipaddr;
    uint32_t deadline_ms;
    uint32_t seed;
    IdemIpAutoIpState state;
    uint8_t tried;
    uint8_t reserved[2];
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
    // PHASE 3: RFC 3927 sec 2.1, which selects an address "using a pseudo-random number generator
    // with a uniform distribution in the range from 169.254.1.0 to 169.254.254.255 inclusive", seeded
    // from a per-host value, and keeps a previously held link-local address as the first candidate.
    io->status = IDEMIP_ERR;
}

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
    // PHASE 3: RFC 3927 sec 2.2.1, where a host that finds the address in use "MUST select a new
    // pseudo-random address and repeat the process", and once the conflict count "exceeds
    // MAX_CONFLICTS then the host MUST limit the rate at which it probes for new addresses to no more
    // than one new address per RATE_LIMIT_INTERVAL".
    io->status = IDEMIP_ERR;
}

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
    // PHASE 3: RFC 3927 sec 2.4, after which the announced address is in use, configured with the
    // sec 2.8 mask that the prefix "MUST NOT be subnetted" fixes at 169.254/16.
    io->status = IDEMIP_ERR;
}

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
    // PHASE 3: RFC 3927 sec 1.9, where "a host SHOULD NOT have both an operable routable address and
    // an IPv4 Link-Local address configured on the same interface", so the interface drops the
    // address and keeps the count of addresses drawn.
    io->status = IDEMIP_ERR;
}

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
    // PHASE 3: RFC 3927 sec 2.2.1's rate limit, which releases the next draw once
    // RATE_LIMIT_INTERVAL has passed since the last one.
    io->status = IDEMIP_ERR;
}

const AutoIpNs AutoIp = {.clear = autoip_clear,
                         .start = autoip_start,
                         .conflict = autoip_conflict,
                         .bound = autoip_bound,
                         .stop = autoip_stop,
                         .tick = autoip_tick};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4
