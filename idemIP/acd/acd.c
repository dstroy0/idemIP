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

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV4

#include "idemIP/acd/acd.h"

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
    const uint8_t *mac;
    IdemIpAcdState state;
    IdemIpAcdDefense defense;
    uint8_t sent;
    uint8_t conflicts;
    idemip_bool defended;
    uint8_t reserved[3];
} AcdCtx;

// The caller's borrow, split: the operand block, then the context. acd.h publishes the offsets; these
// two asserts prove the span covers them before anything runs. The first keeps the context inside the
// region IDEMIP_ACD_CTX_BYTES names, the second the whole map inside the borrow.
static_assert(IDEMIP_ACD_OFF_CTX + sizeof(AcdCtx) <= IDEMIP_ACD_OFF_END,
              "IDEMIP_ACD_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_ACD_OFF_END <= IDEMIP_ACD_BORROW,
              "IDEMIP_ACD_BORROW is short of the map - raise IDEMIP_ACD_CTX_BYTES in idemip_config.h");

// clear zeroes the context, so the state a cleared borrow reads is the zero one.
static_assert(IDEMIP_ACD_STATE_OFF == 0, "IDEMIP_ACD_STATE_OFF must be zero: clear zeroes the context");

// The regions, at their offsets in the caller's borrow.
#define ACD_IO(w) IDEMIP_ACD_IO(w)
#define ACD_CTX(w) ((AcdCtx *)(void *)((w) + IDEMIP_ACD_OFF_CTX))

// Octets the context spans, which is what clear zeroes.
#define ACD_STATE_BYTES ((size_t)IDEMIP_ACD_OFF_END - (size_t)IDEMIP_ACD_OFF_CTX)

// A borrow clear has not run on holds no mark, so every entry but clear refuses it.
static idemip_bool acd_ready(uint8_t *restrict work)
{
    return (idemip_bool)(ACD_CTX(work)->ready == ACD_READY);
}

// --- the entries -----------------------------------------------------------

// The context, zeroed, then the mark. A zeroed context is IDEMIP_ACD_STATE_OFF with no address in it.
// The operand block is the caller's and is left as it stands.
static void acd_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_ACD_OFF_CTX, 0, ACD_STATE_BYTES);
    ACD_CTX(work)->ready = ACD_READY;
    ACD_IO(work)->status = IDEMIP_OK;
}

static void acd_start(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    AcdIo *io = ACD_IO(work);
    io->status = IDEMIP_ERR;
    io->send_probe = IDEMIP_FALSE;
    io->send_announce = IDEMIP_FALSE;
    io->conflict = IDEMIP_FALSE;
    io->abandon = IDEMIP_FALSE;
    if (!acd_ready(work) || io->start_args.mac == NULL || io->start_args.ipaddr == 0u ||
        io->start_args.defense > IDEMIP_ACD_DEFEND_ALWAYS)
    {
        return;
    }
    // PHASE 3: RFC 5227 sec 2.1.1, which waits "a random time interval selected uniformly in the
    // range zero to PROBE_WAIT seconds" before the first of PROBE_NUM probes, and sec 2.1.1's rate
    // limit, which holds a new address for RATE_LIMIT_INTERVAL once MAX_CONFLICTS is reached.
    io->status = IDEMIP_ERR;
}

static void acd_stop(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    AcdIo *io = ACD_IO(work);
    io->status = IDEMIP_ERR;
    io->send_probe = IDEMIP_FALSE;
    io->send_announce = IDEMIP_FALSE;
    if (!acd_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 5227 sec 2.4 (a), which lets a host "immediately cease using the address, and
    // signal an error to the configuring agent", leaving the machine with no address in it while the
    // conflict count sec 2.1.1 rate limits by is kept.
    io->status = IDEMIP_ERR;
}

static void acd_arp_in(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    AcdIo *io = ACD_IO(work);
    io->status = IDEMIP_ERR;
    io->conflict = IDEMIP_FALSE;
    io->abandon = IDEMIP_FALSE;
    io->send_announce = IDEMIP_FALSE;
    if (!acd_ready(work) || io->arp_in_args.packet == NULL)
    {
        return;
    }
    // PHASE 3: RFC 5227 sec 2.1.1 while probing, where any ARP packet whose 'sender IP address' is
    // the address being probed for, and any ARP Probe whose 'target IP address' is it from a 'sender
    // hardware address' that is not this host's, is a conflict; and sec 2.4 once the address is in
    // use, where a packet whose 'sender IP address' is this host's own but whose 'sender hardware
    // address' is not answers with (a), (b) or (c) as IDEMIP_ACD_DEFEND_* selects.
    io->status = IDEMIP_ERR;
}

static void acd_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    AcdIo *io = ACD_IO(work);
    io->status = IDEMIP_ERR;
    io->send_probe = IDEMIP_FALSE;
    io->send_announce = IDEMIP_FALSE;
    io->abandon = IDEMIP_FALSE;
    if (!acd_ready(work))
    {
        return;
    }
    // PHASE 3: RFC 5227 sec 2.1.1, which sends PROBE_NUM probes "spaced randomly and uniformly,
    // PROBE_MIN to PROBE_MAX seconds apart" and clears the address ANNOUNCE_WAIT after the last one;
    // sec 2.3, which then broadcasts ANNOUNCE_NUM Announcements "spaced ANNOUNCE_INTERVAL seconds
    // apart"; and sec 2.1.1's one attempted new address per RATE_LIMIT_INTERVAL.
    io->status = IDEMIP_ERR;
}

const AcdNs Acd = {.clear = acd_clear, .start = acd_start, .stop = acd_stop, .arp_in = acd_arp_in, .tick = acd_tick};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4
