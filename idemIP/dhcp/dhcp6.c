// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dhcp6.c
 * @brief The RFC 8415 client state, the server's DUID region, and the entries over both.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block, the context and the DUID region are all regions of that borrow, at compile-time offsets, and
 * no entry reads or writes a byte outside it. Two borrows therefore share nothing, and the same call
 * on the same borrow does the same thing.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV6

#include "idemIP/dhcp/dhcp6.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. The sec 15 retransmission variables RT and the retry count
// sit beside the sec 21.4 T1 and T2 and the sec 21.6 lifetimes, all as millisecond deadlines against
// the clock tick hands in. The server's DUID is its own region; only its length is here.
typedef struct
{
    const IdemIpDhcp6Cfg *cfg;
    IdemIpDhcp6State state;
    uint8_t owed; ///< the sec 7.3 message type build still has to write, 0 when none
    uint8_t retries;
    uint16_t server_duid_len; ///< octets of the region at IDEMIP_DHCP6_OFF_SERVER_DUID
    uint16_t status_code;     ///< sec 21.13, what the last Reply carried
    uint32_t xid;             ///< sec 8, the low 24 bits
    uint32_t iaid;
    uint32_t now_ms;
    uint32_t rt_ms;        ///< sec 15 RT, the current retransmission timeout
    uint32_t retry_ms;     ///< when the message goes out again
    uint32_t started_ms;   ///< when the exchange began, which sec 21.9 elapsed-time counts from
    uint32_t t1_ms;        ///< the deadline RENEWING starts at
    uint32_t t2_ms;        ///< the deadline REBINDING starts at
    uint32_t preferred_ms; ///< the deadline the address stops being preferred at
    uint32_t valid_ms;     ///< the deadline the address stops being valid at
    uint32_t t1_s;
    uint32_t t2_s;
    uint32_t preferred_s;
    uint32_t valid_s;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];   ///< the sec 21.6 IPv6-address the lease assigned
    uint8_t server[IDEMIP_IP6_ADDR_LEN]; ///< where the assigning server answered from
} Dhcp6Ctx;

// The caller's borrow, split: the operand block and the context in the first IDEMIP_DHCP6_CTX_BYTES
// octets, then the server's DUID. dhcp6.h publishes the offsets; the asserts below prove the span
// covers them before anything runs.
static_assert(IDEMIP_DHCP6_OFF_CTX + sizeof(Dhcp6Ctx) <= IDEMIP_DHCP6_CTX_BYTES,
              "IDEMIP_DHCP6_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_DHCP6_OFF_SERVER_DUID + IDEMIP_DHCP6_SERVER_DUID_BYTES <= IDEMIP_DHCP6_BORROW,
              "IDEMIP_DHCP6_BORROW is short of the context region and the server DUID");
static_assert((IDEMIP_DHCP6_OFF_CTX & (IDEMIP_ALIGN - 1u)) == 0u &&
                  (IDEMIP_DHCP6_OFF_SERVER_DUID & (IDEMIP_ALIGN - 1u)) == 0u,
              "every region starts on IDEMIP_ALIGN");

// The regions, at their offsets in the caller's borrow.
#define DHCP6_CTX(w) ((Dhcp6Ctx *)(void *)((w) + IDEMIP_DHCP6_OFF_CTX))
#define DHCP6_SERVER_DUID(w) ((uint8_t *)((w) + IDEMIP_DHCP6_OFF_SERVER_DUID))
#define DHCP6_IO(w) IDEMIP_DHCP6_IO(w)

// --- the entries -----------------------------------------------------------

// Every byte of the borrow, the operand block and the DUID region included, which leaves the state at
// zero: IDLE, running no exchange.
static void dhcp6_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work, 0, IDEMIP_DHCP6_BORROW);
    DHCP6_IO(work)->status = IDEMIP_OK;
}

// RFC 8415 sec 11.1 puts a DUID at "at least 1 octet and at most 128 octets" behind a 2-octet type
// code, so a client DUID outside that, or a missing one, is refused here rather than written past at
// the first build.
static void dhcp6_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp6Io *io = DHCP6_IO(work);
    io->status = IDEMIP_ERR;
    const IdemIpDhcp6Cfg *cfg = io->bind_args.cfg;
    if (cfg == NULL || cfg->duid == NULL || cfg->duid_len < 3u || cfg->duid_len > IDEMIP_DHCP6_DUID_MAX ||
        cfg->netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    ctx->cfg = cfg;
    ctx->state = IDEMIP_DHCP6_IDLE;
    ctx->iaid = cfg->iaid;
    io->state = IDEMIP_DHCP6_IDLE;
    io->iaid = cfg->iaid;
    io->status = IDEMIP_OK;
}

static void dhcp6_start(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp6Io *io = DHCP6_IO(work);
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 8415 sec 18.2.1 Solicit, or sec 18.2.6 Information-request when stateless
    io->status = IDEMIP_ERR;
}

static void dhcp6_stop(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp6Io *io = DHCP6_IO(work);
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 8415 sec 18.2, end the running exchange and hold no lease
    io->status = IDEMIP_ERR;
}

static void dhcp6_input(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp6Io *io = DHCP6_IO(work);
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 8415 sec 16 validation, sec 18.2.9 Advertise and sec 18.2.10 Reply
    io->status = IDEMIP_ERR;
}

static void dhcp6_build(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp6Io *io = DHCP6_IO(work);
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    io->len = 0;
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 8415 sec 8 header and the sec 21 options each sec 18.2 exchange carries
    io->status = IDEMIP_ERR;
}

static void dhcp6_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp6Io *io = DHCP6_IO(work);
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 8415 sec 15 RT, MRC and MRD, and the sec 21.4 T1 and T2 deadlines
    io->status = IDEMIP_ERR;
}

static void dhcp6_confirm(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp6Io *io = DHCP6_IO(work);
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 8415 sec 18.2.3, the Confirm that asks whether the addresses suit this link
    io->status = IDEMIP_ERR;
}

static void dhcp6_release(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp6Io *io = DHCP6_IO(work);
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 8415 sec 18.2.7, the Release to the server that assigned the leases
    io->status = IDEMIP_ERR;
}

static void dhcp6_decline(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp6Io *io = DHCP6_IO(work);
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // PHASE 3: RFC 8415 sec 18.2.8, the Decline for an address already in use on the link
    io->status = IDEMIP_ERR;
}

const Dhcp6Ns Dhcp6 = {.clear = dhcp6_clear,
                       .bind = dhcp6_bind,
                       .start = dhcp6_start,
                       .stop = dhcp6_stop,
                       .input = dhcp6_input,
                       .build = dhcp6_build,
                       .tick = dhcp6_tick,
                       .confirm = dhcp6_confirm,
                       .release = dhcp6_release,
                       .decline = dhcp6_decline};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6
