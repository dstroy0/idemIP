// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file acd.c
 * @brief The RFC 5227 machine over one address, in the caller's borrow.
 *
 * The context holds the address being claimed, the state, how many probes or announcements have gone
 * out, the next deadline, the millisecond of the last defense, and the conflicts counted against
 * MAX_CONFLICTS. Every entry is a function of the one pointer it is handed: the operand block and the
 * context are both regions of that borrow, at compile-time offsets, and no entry reads or writes a
 * byte outside it.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/acd/acd.h"
#include "src/arp/arp_defines.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads something else here and
// every entry but clear refuses it.
#define ACD_READY 0x41434431u

// The machine over one address. last_defend_ms is the "time that the conflicting ARP packet was
// received" that sec 2.4 (b) and (c) record and compare against DEFEND_INTERVAL, and defended says
// whether one has been recorded, since millisecond zero is a valid clock reading.
typedef struct
{
    uint32_t ready;
    uint32_t ipaddr;
    uint32_t deadline_ms;
    uint32_t last_defend_ms;
    uint32_t next_claim_ms;
    const uint8_t *mac;
    IdemIpAcdState state;
    IdemIpAcdDefense defense;
    uint8_t sent;
    uint8_t conflicts;
    idemip_bool defended;
    uint8_t reserved[3];
} AcdCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_ACD_OFF_CTX, sizeof(AcdCtx), IDEMIP_ACD_OFF_END, "acd's context");

// The caller's borrow, split: the operand block, then the context. acd.h publishes the offsets; these
// two asserts prove the span covers them before anything runs. The first keeps the context inside the
// region IDEMIP_ACD_CTX_BYTES names, the second the whole map inside the borrow.
static_assert(IDEMIP_ACD_OFF_CTX + sizeof(AcdCtx) <= IDEMIP_ACD_OFF_END,
              "IDEMIP_ACD_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_ACD_OFF_END <= IDEMIP_ACD_BORROW,
              "IDEMIP_ACD_BORROW is short of the map - raise IDEMIP_ACD_CTX_BYTES in idemip_config.h");

// clear zeroes the context, so the state a cleared borrow reads is the zero one.
static_assert(IDEMIP_ACD_STATE_OFF == 0, "IDEMIP_ACD_STATE_OFF must be zero: clear zeroes the context");

// A draw over [0, span] scales a 16-bit slice of a random word by span + 1 and shifts the 16 bits back
// off, so each span the RFC names bounds a product that stays inside 32 bits.
static_assert(IDEMIP_ACD_PROBE_WAIT_MS < 0x10000u,
              "the [0, PROBE_WAIT] draw multiplies a 16-bit word by PROBE_WAIT + 1 in 32 bits");
static_assert(IDEMIP_ACD_PROBE_MAX_MS - IDEMIP_ACD_PROBE_MIN_MS < 0x10000u,
              "the [PROBE_MIN, PROBE_MAX] draw multiplies a 16-bit word by the span + 1 in 32 bits");

// sec 2.1.1 counts probes and sec 2.3 announcements from zero upward in one octet of the context, so a
// count of zero would send forever.
static_assert(IDEMIP_ACD_PROBE_NUM >= 1u, "RFC 5227 sec 1.1 PROBE_NUM is 3: at least one probe goes out");
static_assert(IDEMIP_ACD_ANNOUNCE_NUM >= 1u,
              "RFC 5227 sec 1.1 ANNOUNCE_NUM is 2: at least one Announcement goes out");

// The regions, at their offsets in the caller's borrow.
#define ACD_IO(w) IDEMIP_ACD_IO(w)
#define ACD_CTX(w) ((AcdCtx *)(void *)((w) + IDEMIP_ACD_OFF_CTX))

// Octets the context spans, which is what clear zeroes.
#define ACD_STATE_BYTES ((size_t)IDEMIP_ACD_OFF_END - (size_t)IDEMIP_ACD_OFF_CTX)

// The counter saturates here rather than wrapping back under MAX_CONFLICTS.
#define ACD_CONFLICTS_MAX 0xFFu

// A borrow clear has not run on holds no mark, so every entry but clear refuses it.
static idemip_bool acd_ready(uint8_t *work)
{
    return (idemip_bool)(ACD_CTX(work)->ready == ACD_READY);
}

// --- the clock and the draw ------------------------------------------------

// True once @p now has reached @p deadline. The difference is taken in 32 unsigned bits and read as a
// span below half the range, so a deadline the millisecond clock has passed stays passed across its
// wrap at 2^32.
static idemip_bool acd_due(uint32_t now, uint32_t deadline)
{
    return (idemip_bool)((now - deadline) < 0x80000000u);
}

// A draw over [0, span]. sec 2.1.1 selects the first delay "uniformly in the range zero to PROBE_WAIT
// seconds" and spaces each later probe "randomly and uniformly, PROBE_MIN to PROBE_MAX seconds apart".
// The low 16 bits scale by span + 1 and shift back, so the result covers 0 through span and no divide
// runs.
static uint32_t acd_draw(uint32_t rand, uint32_t span)
{
    return (uint32_t)(((rand & 0xFFFFu) * (span + 1u)) >> 16);
}

// --- the machine -----------------------------------------------------------

// The context, into the result members of the operand block.
static void acd_publish(uint8_t *work)
{
    AcdIo *io = ACD_IO(work);
    const AcdCtx *ctx = ACD_CTX(work);
    io->ipaddr = ctx->ipaddr;
    io->deadline_ms = ctx->deadline_ms;
    io->state = ctx->state;
    io->sent = ctx->sent;
    io->conflicts = ctx->conflicts;
}

// Every result member, cleared, so an entry reports what this call found and never what the last one
// did.
static void acd_clear_results(AcdIo *io)
{
    io->send_probe = IDEMIP_FALSE;
    io->send_announce = IDEMIP_FALSE;
    io->conflict = IDEMIP_FALSE;
    io->abandon = IDEMIP_FALSE;
}

// sec 2.1.1 counts "MAX_CONFLICTS or more address conflicts on a given interface", holding the count at
// its ceiling so a long-defended address cannot wrap it back below the limit.
//
// Reaching the limit arms the interval the next claim waits out. sec 2.1.1 applies the rule "not only
// to conflicts experienced during the initial probing phase, but also to conflicts experienced later,
// as described in Section 2.4", so a conflict that is defended rather than abandoned arms it too.
static void acd_count_conflict(AcdCtx *ctx, uint32_t now_ms)
{
    if (ctx->conflicts < ACD_CONFLICTS_MAX)
    {
        ctx->conflicts++;
    }
    if (ctx->conflicts >= IDEMIP_ACD_MAX_CONFLICTS)
    {
        ctx->next_claim_ms = now_ms + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS;
    }
}

// sec 2.4: "immediately cease using this address and signal an error to the configuring agent". The
// address leaves the machine and abandon carries the signal. sec 2.1.1 holds the next attempt for
// RATE_LIMIT_INTERVAL once MAX_CONFLICTS conflicts stand on the interface.
static void acd_abandon(uint8_t *work, uint32_t now_ms)
{
    AcdCtx *ctx = ACD_CTX(work);
    acd_count_conflict(ctx, now_ms);
    ctx->ipaddr = 0u;
    ctx->sent = 0u;
    ctx->defended = IDEMIP_FALSE;
    ctx->last_defend_ms = 0u;
    if (ctx->conflicts >= IDEMIP_ACD_MAX_CONFLICTS)
    {
        ctx->state = IDEMIP_ACD_STATE_RATE_LIMIT;
        ctx->deadline_ms = now_ms + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS;
    }
    else
    {
        ctx->state = IDEMIP_ACD_STATE_OFF;
        ctx->deadline_ms = 0u;
    }
    ACD_IO(work)->abandon = IDEMIP_TRUE;
}

// sec 2.1.1's two tests over the window "from the beginning of the probing process until ANNOUNCE_WAIT
// seconds after the last probe packet is sent": any ARP packet whose 'sender IP address' (ar$spa) is
// the address being probed for, and any ARP Probe whose 'target IP address' (ar$tpa) is it from a
// 'sender hardware address' (ar$sha) that is none of this host's interfaces.
static idemip_bool acd_probe_conflict(const AcdCtx *ctx, const uint8_t *packet)
{
    if (idemip_arp_spa(packet) == ctx->ipaddr)
    {
        return IDEMIP_TRUE;
    }
    // sec 1.1 names an 'ARP Probe' an ARP Request with an all-zero 'sender IP address'. The ar$sha test
    // is what the sec 2.1.1 NOTE requires, so a hub echoing this host's own probe back is not a
    // conflict.
    return (idemip_bool)(idemip_arp_is_request(packet) && idemip_arp_spa(packet) == 0u &&
                         idemip_arp_tpa(packet) == ctx->ipaddr &&
                         !idemip_bytes_eq(idemip_arp_sha(packet), ctx->mac, IDEMIP_ARP_HLN_ETHERNET));
}

// sec 2.4: an ARP packet "where the 'sender IP address' is (one of) the host's own IP address(es)
// configured on that interface, but the 'sender hardware address' does not match any of the host's own
// interface addresses" is a conflicting ARP packet.
static idemip_bool acd_ongoing_conflict(const AcdCtx *ctx, const uint8_t *packet)
{
    return (idemip_bool)(idemip_arp_spa(packet) == ctx->ipaddr &&
                         !idemip_bytes_eq(idemip_arp_sha(packet), ctx->mac, IDEMIP_ARP_HLN_ETHERNET));
}

// sec 2.4's (a), (b) and (c) over one conflicting ARP packet, as IdemIpAcdDefense selects.
//
// (a) ceases at once. (b) and (c) both record the time and broadcast one Announcement when no
// conflicting packet was recorded "within the last DEFEND_INTERVAL seconds". Inside that interval (b)
// "MUST immediately cease using this address", while (c) "MUST NOT send another defensive ARP
// Announcement" and keeps the address.
static void acd_defend(uint8_t *work, uint32_t now_ms)
{
    AcdIo *io = ACD_IO(work);
    AcdCtx *ctx = ACD_CTX(work);

    if (ctx->defense == IDEMIP_ACD_DEFEND_NEVER)
    {
        acd_abandon(work, now_ms);
        return;
    }

    idemip_bool recent = (idemip_bool)(ctx->defended && (now_ms - ctx->last_defend_ms) <
                                                            (uint32_t)IDEMIP_ACD_DEFEND_INTERVAL_MS);
    if (recent)
    {
        if (ctx->defense == IDEMIP_ACD_DEFEND_ONCE)
        {
            acd_abandon(work, now_ms);
        }
        else
        {
            acd_count_conflict(ctx, now_ms);
        }
        return;
    }
    ctx->last_defend_ms = now_ms;
    ctx->defended = IDEMIP_TRUE;
    io->send_announce = IDEMIP_TRUE;
    acd_count_conflict(ctx, now_ms);
}

// One received ARP packet, against sec 2.1.1's probe tests while the address is being claimed and
// sec 2.4's ongoing test once it is in use. sec 2.3 puts the address in use "immediately after sending
// the first of the two ARP Announcements", so ANNOUNCING takes the sec 2.4 test.
static void acd_receive(uint8_t *work)
{
    AcdIo *io = ACD_IO(work);
    const AcdCtx *ctx = ACD_CTX(work);
    const uint8_t *packet = io->arp_in_args.packet;
    uint32_t now_ms = io->arp_in_args.now_ms;

    // sec 1.1 reads 'sender IP address' and 'target IP address' as RFC 826's ar$spa and ar$tpa holding
    // an IPv4 address, so any other ar$hrd, ar$pro, ar$hln or ar$pln pair carries neither field.
    if (!idemip_arp_is_ethernet_ipv4(packet))
    {
        return; // status stands at IDEMIP_ERR
    }
    // sec 2.1.1 and sec 2.4 both test "any ARP packet (Request *or* Reply)", so no other ar$op is under
    // a rule of this specification.
    if (idemip_arp_is_request(packet) || idemip_arp_is_reply(packet))
    {
        switch (ctx->state)
        {
        case IDEMIP_ACD_STATE_PROBE_WAIT:
        case IDEMIP_ACD_STATE_PROBING:
        case IDEMIP_ACD_STATE_ANNOUNCE_WAIT:
            if (acd_probe_conflict(ctx, packet))
            {
                io->conflict = IDEMIP_TRUE;
                acd_abandon(work, now_ms);
            }
            break;
        case IDEMIP_ACD_STATE_ANNOUNCING:
        case IDEMIP_ACD_STATE_ONGOING:
            if (acd_ongoing_conflict(ctx, packet))
            {
                io->conflict = IDEMIP_TRUE;
                acd_defend(work, now_ms);
            }
            break;
        default:
            break; // OFF and RATE_LIMIT hold no address, so no field of the packet is this host's
        }
    }
    acd_publish(work);
    io->status = IDEMIP_OK;
}

// sec 2.1.1: PROBE_NUM probe packets, "each of these probe packets spaced randomly and uniformly,
// PROBE_MIN to PROBE_MAX seconds apart", then ANNOUNCE_WAIT after the last one.
static void acd_send_probe(uint8_t *work, uint32_t now_ms, uint32_t rand)
{
    AcdIo *io = ACD_IO(work);
    AcdCtx *ctx = ACD_CTX(work);
    io->send_probe = IDEMIP_TRUE;
    ctx->sent++;
    if (ctx->sent >= IDEMIP_ACD_PROBE_NUM)
    {
        ctx->state = IDEMIP_ACD_STATE_ANNOUNCE_WAIT;
        ctx->sent = 0u;
        ctx->deadline_ms = now_ms + IDEMIP_ACD_ANNOUNCE_WAIT_MS;
        return;
    }
    ctx->state = IDEMIP_ACD_STATE_PROBING;
    ctx->deadline_ms =
        now_ms + IDEMIP_ACD_PROBE_MIN_MS + acd_draw(rand, IDEMIP_ACD_PROBE_MAX_MS - IDEMIP_ACD_PROBE_MIN_MS);
}

// sec 2.3: ANNOUNCE_NUM ARP Announcements "spaced ANNOUNCE_INTERVAL seconds apart", after which the
// address is in use and sec 2.4's ongoing detection carries it with no deadline of its own.
static void acd_send_announce(uint8_t *work, uint32_t now_ms)
{
    AcdIo *io = ACD_IO(work);
    AcdCtx *ctx = ACD_CTX(work);
    io->send_announce = IDEMIP_TRUE;
    ctx->sent++;
    if (ctx->sent >= IDEMIP_ACD_ANNOUNCE_NUM)
    {
        ctx->state = IDEMIP_ACD_STATE_ONGOING;
        ctx->sent = 0u;
        ctx->deadline_ms = 0u;
        return;
    }
    ctx->state = IDEMIP_ACD_STATE_ANNOUNCING;
    ctx->deadline_ms = now_ms + IDEMIP_ACD_ANNOUNCE_INTERVAL_MS;
}

// The deadline that has passed: sec 2.1.1's next probe and the ANNOUNCE_WAIT after the last of them,
// sec 2.3's next Announcement, and sec 2.1.1's end of a RATE_LIMIT_INTERVAL.
//
// A deadline still ahead reports BUSY, since the same call on a later tick fires it. OFF holds no
// address and ONGOING waits on a packet rather than a clock, so neither carries a deadline and both
// report OK with nothing due.
static void acd_fire(uint8_t *work)
{
    AcdIo *io = ACD_IO(work);
    AcdCtx *ctx = ACD_CTX(work);
    uint32_t now_ms = io->tick_args.now_ms;

    switch (ctx->state)
    {
    case IDEMIP_ACD_STATE_PROBE_WAIT:
    case IDEMIP_ACD_STATE_PROBING:
        if (!acd_due(now_ms, ctx->deadline_ms))
        {
            io->status = IDEMIP_BUSY;
            return;
        }
        acd_send_probe(work, now_ms, io->tick_args.rand);
        break;
    case IDEMIP_ACD_STATE_ANNOUNCE_WAIT:
    case IDEMIP_ACD_STATE_ANNOUNCING:
        if (!acd_due(now_ms, ctx->deadline_ms))
        {
            io->status = IDEMIP_BUSY;
            return;
        }
        acd_send_announce(work, now_ms);
        break;
    case IDEMIP_ACD_STATE_RATE_LIMIT:
        if (!acd_due(now_ms, ctx->deadline_ms))
        {
            io->status = IDEMIP_BUSY;
            return;
        }
        ctx->state = IDEMIP_ACD_STATE_OFF;
        ctx->deadline_ms = 0u;
        break;
    default:
        break;
    }
    acd_publish(work);
    io->status = IDEMIP_OK;
}

// sec 2.1.1: the host "should then wait for a random time interval selected uniformly in the range zero
// to PROBE_WAIT seconds" before the first of PROBE_NUM probes.
//
// The conflict count is not reset here. sec 2.1.1 counts "MAX_CONFLICTS or more address conflicts on a
// given interface" and applies the limit "not only to conflicts experienced during the initial probing
// phase, but also to conflicts experienced later", so only clear takes the count back to zero.
static void acd_claim(uint8_t *work)
{
    AcdIo *io = ACD_IO(work);
    AcdCtx *ctx = ACD_CTX(work);

    // sec 2.1.1 limits a host past MAX_CONFLICTS "to no more than one attempted new address per
    // RATE_LIMIT_INTERVAL". The count is what the limit reads, not the state: a conflict sec 2.4 (b)
    // or (c) defends raises the count and leaves the machine claiming its address, so a machine that
    // never abandoned can still be past the limit. BUSY, not ERR: the interval ends, and the same call
    // then claims the address.
    if (ctx->conflicts >= IDEMIP_ACD_MAX_CONFLICTS && !acd_due(io->start_args.now_ms, ctx->next_claim_ms))
    {
        acd_publish(work);
        io->status = IDEMIP_BUSY;
        return;
    }
    // "no more than one attempted new address per RATE_LIMIT_INTERVAL": this attempt starts the next
    // interval, so the one after it waits too.
    if (ctx->conflicts >= IDEMIP_ACD_MAX_CONFLICTS)
    {
        ctx->next_claim_ms = io->start_args.now_ms + IDEMIP_ACD_RATE_LIMIT_INTERVAL_MS;
    }
    ctx->mac = io->start_args.mac;
    ctx->ipaddr = io->start_args.ipaddr;
    ctx->defense = io->start_args.defense;
    ctx->state = IDEMIP_ACD_STATE_PROBE_WAIT;
    ctx->sent = 0u;
    ctx->defended = IDEMIP_FALSE;
    ctx->last_defend_ms = 0u;
    ctx->deadline_ms = io->start_args.now_ms + acd_draw(io->start_args.rand, IDEMIP_ACD_PROBE_WAIT_MS);
    acd_publish(work);
    io->status = IDEMIP_OK;
}

// sec 2.4 (a): "immediately cease using the address, and signal an error to the configuring agent".
// The address leaves the machine and the conflict count sec 2.1.1 rate limits by is kept.
//
// A standing RATE_LIMIT holds no address, so the state and its deadline are left as they stand and the
// interval runs out under a tick.
static void acd_cease(uint8_t *work)
{
    AcdIo *io = ACD_IO(work);
    AcdCtx *ctx = ACD_CTX(work);
    ctx->ipaddr = 0u;
    ctx->sent = 0u;
    ctx->defended = IDEMIP_FALSE;
    ctx->last_defend_ms = 0u;
    if (ctx->state != IDEMIP_ACD_STATE_RATE_LIMIT)
    {
        ctx->state = IDEMIP_ACD_STATE_OFF;
        ctx->deadline_ms = 0u;
    }
    acd_publish(work);
    io->status = IDEMIP_OK;
}

// --- the entries -----------------------------------------------------------

// The context, zeroed, then the mark. A zeroed context is IDEMIP_ACD_STATE_OFF with no address in it.
// The operand block is the caller's and is left as it stands.
void idemip_acd_clear(uint8_t *work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_ACD_OFF_CTX, 0, ACD_STATE_BYTES);
    ACD_CTX(work)->ready = ACD_READY;
    ACD_IO(work)->status = IDEMIP_OK;
}

void idemip_acd_start(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    AcdIo *io = ACD_IO(work);
    io->status = IDEMIP_ERR;
    acd_clear_results(io);
    if (!acd_ready(work) || io->start_args.mac == NULL || io->start_args.ipaddr == 0u ||
        io->start_args.defense > IDEMIP_ACD_DEFEND_ALWAYS)
    {
        return;
    }
    acd_claim(work);
}

void idemip_acd_stop(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    AcdIo *io = ACD_IO(work);
    io->status = IDEMIP_ERR;
    acd_clear_results(io);
    if (!acd_ready(work))
    {
        return;
    }
    acd_cease(work);
}

void idemip_acd_arp_in(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    AcdIo *io = ACD_IO(work);
    io->status = IDEMIP_ERR;
    acd_clear_results(io);
    if (!acd_ready(work) || io->arp_in_args.packet == NULL)
    {
        return;
    }
    acd_receive(work);
}

void idemip_acd_tick(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    AcdIo *io = ACD_IO(work);
    io->status = IDEMIP_ERR;
    acd_clear_results(io);
    if (!acd_ready(work))
    {
        return;
    }
    acd_fire(work);
}

IDEMIP_END_DECLS
