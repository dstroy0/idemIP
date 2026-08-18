// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pmtu4.c
 * @brief The RFC 1191 decision: what a Datagram Too Big leaves the path MTU at, and when it rises.
 *
 * Table 7-1 is this file's, in rodata. Every entry is a function of the one pointer it is handed:
 * the operand block and the mark are regions of that borrow, at compile-time offsets, and no entry
 * reads or writes a byte outside it and the message the caller pointed at.
 */

#include "idemIP/idemip_config.h" // the entry point: the enable gate below, and the widths

#if IDEMIP_ENABLE_IPV4

#include "idemIP/pmtu/pmtu4.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and every
// entry refuses it.
#define PMTU4_READY 0x504D5434u

// The context: the mark alone. The estimate and its timestamp are the routing table's, RFC 1191
// sec 6.2 putting them "as a field in the routing table entries".
typedef struct
{
    uint32_t ready;
} Pmtu4Ctx;

// The caller's borrow, split: the operand block, then the context. pmtu4.h publishes the offsets;
// the assert proves the span covers them before anything runs.
static_assert(IDEMIP_PMTU4_OFF_CTX + sizeof(Pmtu4Ctx) <= IDEMIP_PMTU4_BORROW,
              "IDEMIP_PMTU4_BORROW is short of the operand block and the context - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define PMTU4_IO(w) IDEMIP_PMTU4_IO(w)
#define PMTU4_CTX(w) ((Pmtu4Ctx *)(void *)((w) + IDEMIP_PMTU4_OFF_CTX))

// RFC 1191 Table 7-1, "Common MTUs in the Internet", the Plateau column as printed, largest first.
// sec 5 searches it: "since designers tend to chose MTUs in similar ways, it is possible to collect
// groups of similar MTU values and use the lowest value in the group as our search plateau."
static const uint16_t pmtu4_plateau[IDEMIP_PMTU4_PLATEAUS] = {
    65535u, // Official maximum MTU, RFC 791; Hyperchannel, RFC 1044
    32000u, // "Just in case"
    17914u, // 16Mb IBM Token Ring
    8166u,  // IEEE 802.4, RFC 1042
    4352u,  // IEEE 802.5 (4Mb max) 4464, FDDI (Revised) 4352, RFC 1188; 1%
    2002u,  // Wideband Network 2048, RFC 907; IEEE 802.5 (4Mb recommended), RFC 1042; 2%
    1492u,  // Exp. Ethernet 1536, Ethernet 1500 RFC 894, Point-to-Point 1500, IEEE 802.3; 3%
    1006u,  // SLIP, RFC 1055; ARPANET, BBN 1822
    508u,   // X.25 576, DEC IP Portal 544, NETBIOS 512, Source-Rt Bridge 508, ARCNET 508; 13%
    296u,   // Point-to-Point (low delay), RFC 1144
    68u,    // Official minimum MTU, RFC 791
};

static_assert(sizeof pmtu4_plateau / sizeof pmtu4_plateau[0] == IDEMIP_PMTU4_PLATEAUS,
              "the plateau table is not IDEMIP_PMTU4_PLATEAUS rows: RFC 1191 Table 7-1 prints eleven");

// sec 3: "A host MUST never reduce its estimate of the Path MTU below 68 octets", which is the row
// Table 7-1 ends on.
static_assert(IDEMIP_IP4_MIN_FORWARD_MTU == 68u,
              "RFC 1191 sec 3 floors the estimate at 68 octets, which is RFC 791's minimum");

// A borrow clear has not run on carries no mark, so every entry but clear refuses it.
static idemip_bool pmtu4_ready(uint8_t *restrict work)
{
    return (idemip_bool)(PMTU4_CTX(work)->ready == PMTU4_READY);
}

// --- the table -------------------------------------------------------------

// sec 5: "the greatest plateau value that is less than the returned Total Length field". Zero when
// the length is at or under the last row, no plateau lying below it.
static uint16_t pmtu4_below(uint16_t size)
{
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_PMTU4_PLATEAUS; i++)
    {
        if (pmtu4_plateau[i] < size)
        {
            return pmtu4_plateau[i];
        }
    }
    return 0u;
}

// sec 7.1: "periodically increase the PMTU estimate to the next-highest value in the plateau table".
// Zero when the estimate is already at or over the first row.
static uint16_t pmtu4_above(uint16_t size)
{
    for (uint8_t i = (uint8_t)IDEMIP_PMTU4_PLATEAUS; i-- > 0u;)
    {
        if (pmtu4_plateau[i] > size)
        {
            return pmtu4_plateau[i];
        }
    }
    return 0u;
}

// --- the entries -----------------------------------------------------------

// The context, zeroed, then the mark. The operand block is the caller's and is left as it stands.
static void pmtu4_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_PMTU4_OFF_CTX, 0, (size_t)IDEMIP_PMTU4_BORROW - (size_t)IDEMIP_PMTU4_OFF_CTX);
    PMTU4_CTX(work)->ready = PMTU4_READY;
    PMTU4_IO(work)->status = IDEMIP_OK;
}

// sec 2's Datagram Too Big: "ICMP Destination Unreachable messages with a code meaning
// 'fragmentation needed and DF set'", which is RFC 792 Type 3 Code 4. sec 4 carries the constricting
// hop's MTU in the low half of the unused word; sec 3 reads a zero there as "a Datagram Too Big
// message from an unmodified router" and sec 5 then searches Table 7-1 from the quoted Total Length,
// corrected by the Note under it: "If the Total Length field returned is not less than the current
// PMTU estimate, it must be reduced by 4 times the value of the returned Header Length field."
//
// sec 3: "A host MUST not increase its estimate of the Path MTU in response to the contents of a
// Datagram Too Big message", so the reported estimate never rises above what the row holds.
//
// A message of another type or code, one short of its quoted internet header, one whose quote is not
// an internet header, a next-hop MTU below the 68 octets sec 4 states the field never falls under,
// and a search that lands under that floor are all ERR: none of them can be applied, now or on a
// later call. Nothing here waits on a resource, so nothing here is BUSY.
static void pmtu4_too_big(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Pmtu4Io *io = PMTU4_IO(work);
    io->status = IDEMIP_ERR;
    io->dst = 0u;
    io->mtu = 0u;
    io->total_len = 0u;
    io->next_hop_mtu = 0u;
    io->tos = 0u;
    io->decreased = IDEMIP_FALSE;
    io->old_style = IDEMIP_FALSE;
    if (!pmtu4_ready(work))
    {
        return;
    }
    const uint8_t *msg = io->too_big_args.msg;
    if (msg == NULL || io->too_big_args.len < (size_t)IDEMIP_PMTU4_MSG_MIN)
    {
        return;
    }
    if (idemip_icmp_type(msg) != (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE ||
        idemip_icmp_code(msg) != (uint8_t)IDEMIP_ICMP_DU_FRAG_NEEDED)
    {
        return;
    }

    // sec 5: "All ICMP Destination Unreachable messages, including this one, contain the IP header
    // of the original datagram", which names the path and carries the Total Length.
    const uint8_t *quote = idemip_icmp_quote(msg);
    if (!idemip_ip4_version_ok(quote) || !idemip_ip4_ihl_ok(quote))
    {
        return;
    }
    size_t hdr = idemip_ip4_hdr_len(quote);
    if (io->too_big_args.len < (size_t)IDEMIP_ICMP_OFF_QUOTE + hdr)
    {
        return;
    }
    io->dst = idemip_ip4_dst(quote);
    io->tos = idemip_ip4_tos(quote);
    io->total_len = idemip_ip4_total_len(quote);

    uint16_t held = io->too_big_args.held;
    uint16_t next = idemip_rd16(msg + IDEMIP_PMTU4_OFF_NEXT_HOP_MTU);
    io->next_hop_mtu = next;
    uint16_t mtu;
    if (next != 0u)
    {
        if (next < (uint16_t)IDEMIP_IP4_MIN_FORWARD_MTU)
        {
            return;
        }
        mtu = next;
    }
    else
    {
        io->old_style = IDEMIP_TRUE;
        uint16_t len = io->total_len;
        if (held != 0u && len >= held)
        {
            if (len <= (uint16_t)hdr)
            {
                return;
            }
            len = (uint16_t)(len - (uint16_t)hdr);
            io->total_len = len;
        }
        mtu = pmtu4_below(len);
        if (mtu == 0u)
        {
            return;
        }
    }

    if (held != 0u && mtu > held)
    {
        mtu = held;
    }
    io->mtu = mtu;
    io->decreased = (idemip_bool)(held == 0u || mtu < held);
    io->status = IDEMIP_OK;
}

// sec 5's search over Table 7-1, on its own. A size at or under the last row is ERR: no plateau lies
// below it, and sec 3 floors the estimate there anyway.
static void pmtu4_plateau_below(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Pmtu4Io *io = PMTU4_IO(work);
    io->status = IDEMIP_ERR;
    io->mtu = 0u;
    if (!pmtu4_ready(work))
    {
        return;
    }
    uint16_t mtu = pmtu4_below(io->plateau_args.size);
    if (mtu == 0u)
    {
        return;
    }
    io->mtu = mtu;
    io->status = IDEMIP_OK;
}

// sec 7.1's raise: "periodically increase the PMTU estimate to the next-highest value in the plateau
// table (or the first-hop MTU, if that is smaller)". A size already at the top of the table and one
// already at the first hop's MTU are both ERR: the table holds nothing above either.
static void pmtu4_plateau_above(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Pmtu4Io *io = PMTU4_IO(work);
    io->status = IDEMIP_ERR;
    io->mtu = 0u;
    if (!pmtu4_ready(work))
    {
        return;
    }
    uint16_t size = io->plateau_args.size;
    uint16_t bound = io->plateau_args.first_hop_mtu;
    uint16_t mtu = pmtu4_above(size);
    if (bound != 0u && (mtu == 0u || mtu > bound))
    {
        mtu = bound;
    }
    if (mtu == 0u || mtu <= size)
    {
        return;
    }
    io->mtu = mtu;
    io->status = IDEMIP_OK;
}

// sec 6.3: "for each entry whose timestamp is not 'reserved' and is older than the timeout interval:
// the PMTU estimate is set to the MTU of the associated first hop", by sec 7.1's step rather than in
// one jump, "at most one round-trip time is wasted before the correct value is rediscovered".
//
// A row carrying no estimate is sec 6.3's "reserved" timestamp, "indicating that the PMTU has never
// been changed": BUSY, since a Datagram Too Big installs one. An interval that has not elapsed is
// BUSY, sec 3 forbidding the attempt before it. An estimate already at the first hop's MTU is BUSY,
// since a later decrease is what leaves something to raise. A first hop that cannot carry RFC 791's
// 68 octets is ERR.
static void pmtu4_age(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Pmtu4Io *io = PMTU4_IO(work);
    io->status = IDEMIP_ERR;
    io->mtu = 0u;
    if (!pmtu4_ready(work))
    {
        return;
    }
    uint16_t first_hop = io->age_args.first_hop_mtu;
    if (first_hop < (uint16_t)IDEMIP_IP4_MIN_FORWARD_MTU)
    {
        return;
    }
    uint16_t pmtu = io->age_args.pmtu;
    if (pmtu == 0u)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    if ((uint32_t)(io->now_ms - io->age_args.stamp_ms) < (uint32_t)IDEMIP_PMTU4_INCREASE_MS)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    uint16_t mtu = pmtu4_above(pmtu);
    if (mtu == 0u || mtu > first_hop)
    {
        mtu = first_hop;
    }
    if (mtu <= pmtu)
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    io->mtu = mtu;
    io->status = IDEMIP_OK;
}

const Pmtu4Ns Pmtu4 = {.clear = pmtu4_clear,
                       .too_big = pmtu4_too_big,
                       .plateau_below = pmtu4_plateau_below,
                       .plateau_above = pmtu4_plateau_above,
                       .age = pmtu4_age};

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV4
