// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file pmtu6.c
 * @brief The RFC 8201 decision: what a Packet Too Big leaves the path MTU at, and when it is probed.
 *
 * The stamp row is this file's. Every entry is a function of the one pointer it is handed: the
 * operand block, the context and the stamp table are regions of that borrow, at compile-time
 * offsets, and no entry reads or writes a byte outside it and the message the caller pointed at.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/pmtu/pmtu6.h"

IDEMIP_BEGIN_DECLS

// The mark clear leaves in the context. A borrow that was never cleared reads zero here and every
// entry refuses it.
#define PMTU6_READY 0x504D5436u

// One path's aging clock, RFC 8201 sec 5.3: the address the estimate belongs to, and the millisecond
// that estimate was last decreased. The estimate itself is the Destination Cache's, sec 5.2 storing
// "a PMTU value ... with the corresponding entry in the destination cache". Padded to
// 1 << IDEMIP_PMTU6_ENTRY_SHIFT so stamp i sits at (i << IDEMIP_PMTU6_ENTRY_SHIFT).
typedef struct
{
    uint32_t stamp_ms;
    uint8_t dst[IDEMIP_IP6_ADDR_LEN];
    idemip_bool used;
    uint8_t reserved[11];
} Pmtu6Stamp;

// The context: the mark alone.
typedef struct
{
    uint32_t ready;
} Pmtu6Ctx;

// Stamp i is at (i << SHIFT), so the width has to be exactly the shift.
static_assert(sizeof(Pmtu6Stamp) == (1u << IDEMIP_PMTU6_ENTRY_SHIFT),
              "a Pmtu6Stamp must be exactly 1 << IDEMIP_PMTU6_ENTRY_SHIFT wide - pad it, or raise the shift");

// The head region carries the operand block and the context, both outside the table.
static_assert(IDEMIP_PMTU6_OFF_CTX + sizeof(Pmtu6Ctx) <= IDEMIP_PMTU6_OFF_STAMPS,
              "IDEMIP_PMTU6_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");

// The caller's borrow, split: the head region, then the stamps. pmtu6.h publishes the offsets; the
// assert proves the span covers them before anything runs.
static_assert(IDEMIP_PMTU6_OFF_END <= IDEMIP_PMTU6_BORROW,
              "IDEMIP_PMTU6_BORROW is short of the head region and the stamps - raise it in idemip_config.h");

// RFC 8200 sec 5: "IPv6 requires that every link in the Internet have an MTU of 1280 octets or
// greater", which sec 4 of RFC 8201 floors every estimate at.
static_assert(IDEMIP_IPV6_MIN_MTU == 1280u, "the IPv6 minimum link MTU is RFC 8200 sec 5's 1280 octets");

// The regions, at their offsets in the caller's borrow.
#define PMTU6_IO(w) IDEMIP_PMTU6_IO(w)
#define PMTU6_CTX(w) ((Pmtu6Ctx *)(void *)((w) + IDEMIP_PMTU6_OFF_CTX))
#define PMTU6_AT(w, i)                                                                                                 \
    ((Pmtu6Stamp *)(void *)((w) + IDEMIP_PMTU6_OFF_STAMPS + ((size_t)(i) << IDEMIP_PMTU6_ENTRY_SHIFT)))

// A borrow clear has not run on carries no stamps, so every entry but clear refuses it.
static idemip_bool pmtu6_ready(uint8_t *restrict work)
{
    return (idemip_bool)(PMTU6_CTX(work)->ready == PMTU6_READY);
}

// --- the path --------------------------------------------------------------

static idemip_bool pmtu6_addr_eq(const uint8_t *a, const uint8_t *b)
{
    return (idemip_bool)(idemip_bytes_eq(a, b, IDEMIP_IP6_ADDR_LEN));
}

// RFC 8201 sec 5.2 names the path a message applies to: "if the destination address is used as the
// local representation of a path, the destination address from the original packet would be used",
// and its Note: "If Segments Left is equal to zero, the destination address is in the Destination
// Address field in the IPv6 header. If Segments Left is greater than zero, the destination address
// is the last address (Address[n]) in the Routing header." The walk stops at the first header the
// quote does not carry whole, RFC 4443 sec 3.2 carrying only "as much of invoking packet as possible
// without the ICMPv6 packet exceeding the minimum IPv6 MTU".
static const uint8_t *pmtu6_path(const uint8_t *pkt, size_t len)
{
    const uint8_t *dst = idemip_ip6_dst(pkt);
    uint8_t nh = idemip_ip6_next_hdr(pkt);
    size_t at = IDEMIP_IP6_OFF_PAYLOAD;
    while (idemip_ip6_nh_is_ext(nh))
    {
        if (at + (size_t)IDEMIP_IP6_EXT_UNIT > len)
        {
            break;
        }
        // sec 4.5 fixes the Fragment header at eight octets; sec 4 sizes the other three from their
        // Hdr Ext Len.
        size_t ext = (nh == (uint8_t)IDEMIP_IP6_NH_FRAGMENT) ? (size_t)IDEMIP_IP6_FRAG_HDR_LEN
                                                             : idemip_ip6_ext_len(pkt + at);
        if (at + ext > len)
        {
            break;
        }
        if (nh == (uint8_t)IDEMIP_IP6_NH_ROUTING && pkt[at + IDEMIP_PMTU6_RH_OFF_SEGMENTS_LEFT] != 0u &&
            ext >= (size_t)IDEMIP_IP6_EXT_UNIT + (size_t)IDEMIP_IP6_ADDR_LEN)
        {
            dst = pkt + at + ext - (size_t)IDEMIP_IP6_ADDR_LEN;
            break;
        }
        nh = idemip_ip6_ext_next_hdr(pkt + at);
        at += ext;
    }
    return dst;
}

// --- the stamps ------------------------------------------------------------

static uint8_t pmtu6_find(uint8_t *restrict work, const uint8_t *dst)
{
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_PMTU6_PATHS; i++)
    {
        const Pmtu6Stamp *s = PMTU6_AT(work, i);
        if (s->used && pmtu6_addr_eq(s->dst, dst))
        {
            return i;
        }
    }
    return (uint8_t)IDEMIP_PMTU6_NONE;
}

// The stamp this path already holds, else the lowest free row, else the row whose clock has run
// longest: that one is nearest the sec 5.3 interval, so its probe is the one already overdue.
static uint8_t pmtu6_take(uint8_t *restrict work, const uint8_t *dst, uint32_t now_ms)
{
    uint8_t free_row = (uint8_t)IDEMIP_PMTU6_NONE;
    uint8_t oldest_row = 0;
    uint32_t oldest_age = 0;
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_PMTU6_PATHS; i++)
    {
        const Pmtu6Stamp *s = PMTU6_AT(work, i);
        if (!s->used)
        {
            if (free_row == (uint8_t)IDEMIP_PMTU6_NONE)
            {
                free_row = i;
            }
            continue;
        }
        if (pmtu6_addr_eq(s->dst, dst))
        {
            return i;
        }
        uint32_t age = (uint32_t)(now_ms - s->stamp_ms);
        if (age >= oldest_age)
        {
            oldest_age = age;
            oldest_row = i;
        }
    }
    return (free_row != (uint8_t)IDEMIP_PMTU6_NONE) ? free_row : oldest_row;
}

// --- the entries -----------------------------------------------------------

// The context and the stamps, zeroed, then the mark. The operand block is the caller's and is left
// as it stands.
static void pmtu6_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_PMTU6_OFF_CTX, 0, (size_t)IDEMIP_PMTU6_BORROW - (size_t)IDEMIP_PMTU6_OFF_CTX);
    PMTU6_CTX(work)->ready = PMTU6_READY;
    PMTU6_IO(work)->status = IDEMIP_OK;
}

// RFC 4443 sec 3.2's Type 2, whose Code is "Set to 0 (zero) by the originator and ignored by the
// receiver", so the code is not read. Its 32-bit MTU field is "The Maximum Transmission Unit of the
// next-hop link", and RFC 8201 sec 5.2 compares it: "If the tentative PMTU is less than the existing
// PMTU estimate, the tentative PMTU replaces the existing PMTU as the PMTU value for the path."
//
// sec 4: "If a node receives a Packet Too Big message reporting a next-hop MTU that is less than the
// IPv6 minimum link MTU, it must discard it", which is ERR, as are another type and a message short
// of the invoking IPv6 header: none of them can be applied on a later call either. Nothing here
// waits on a resource, so nothing here is BUSY. A field above what the Destination Cache row holds
// in sixteen bits is carried at that ceiling; the field as it arrived is reported whole.
//
// sec 5.3 ages by the last decrease, so a decrease is what stamps the path.
static void pmtu6_too_big(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Pmtu6Io *io = PMTU6_IO(work);
    io->status = IDEMIP_ERR;
    io->dst = NULL;
    io->reported_mtu = 0u;
    io->mtu = 0u;
    io->index = (uint8_t)IDEMIP_PMTU6_NONE;
    io->decreased = IDEMIP_FALSE;
    io->probe = IDEMIP_FALSE;
    if (!pmtu6_ready(work))
    {
        return;
    }
    const uint8_t *msg = io->too_big_args.msg;
    if (msg == NULL || io->too_big_args.len < (size_t)IDEMIP_PMTU6_MSG_MIN)
    {
        return;
    }
    if (idemip_icmp6_type(msg) != (uint8_t)IDEMIP_ICMP6_PACKET_TOO_BIG)
    {
        return;
    }
    const uint8_t *pkt = msg + IDEMIP_ICMP6_ERR_HDR_LEN;
    if (idemip_ip6_version(pkt) != (uint8_t)IDEMIP_IP6_VERSION)
    {
        return;
    }
    uint32_t reported = idemip_icmp6_mtu(msg);
    io->reported_mtu = reported;
    if (reported < (uint32_t)IDEMIP_IPV6_MIN_MTU)
    {
        return;
    }

    io->dst = pmtu6_path(pkt, io->too_big_args.len - (size_t)IDEMIP_ICMP6_ERR_HDR_LEN);
    uint16_t mtu = (reported > 0xFFFFu) ? (uint16_t)0xFFFFu : (uint16_t)reported;
    // sec 5.2: "Initially, the PMTU value for a path is assumed to be the (known) MTU of the
    // first-hop link", so a Destination Cache row carrying none still has an estimate and a zero held
    // is not the absence of a ceiling.
    uint16_t held = io->too_big_args.held;
    if (held == 0u)
    {
        held = io->too_big_args.link_mtu;
    }
    if (held != 0u && mtu >= held)
    {
        // sec 4: "A node must not increase its estimate of the Path MTU in response to the contents
        // of a Packet Too Big message." The estimate stands and the path is not restamped.
        io->mtu = held;
        io->status = IDEMIP_OK;
        return;
    }

    io->mtu = mtu;
    io->decreased = IDEMIP_TRUE;
    uint8_t i = pmtu6_take(work, io->dst, io->now_ms);
    Pmtu6Stamp *s = PMTU6_AT(work, i);
    memcpy(s->dst, io->dst, IDEMIP_IP6_ADDR_LEN);
    s->stamp_ms = io->now_ms;
    s->used = IDEMIP_TRUE;
    io->index = i;
    io->status = IDEMIP_OK;
}

// sec 5.3: "When a PMTU value has not been decreased for a while (on the order of 10 minutes), it
// should probe to find if a larger PMTU is supported", and sec 4 floors the wait: an attempt "must
// not be done less than 5 minutes after a Packet Too Big message has been received for the given
// path." One path per call, its stamp dropped so the probe is asked for once; the address stays
// where it lies until another call on this borrow writes that row.
//
// No path due is BUSY: a later tick or a later Packet Too Big makes one. A link MTU under the IPv6
// minimum is ERR, RFC 8200 sec 5 admitting no such link.
static void pmtu6_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Pmtu6Io *io = PMTU6_IO(work);
    io->status = IDEMIP_ERR;
    io->dst = NULL;
    io->mtu = 0u;
    io->index = (uint8_t)IDEMIP_PMTU6_NONE;
    io->decreased = IDEMIP_FALSE;
    io->probe = IDEMIP_FALSE;
    if (!pmtu6_ready(work))
    {
        return;
    }
    if (io->probe_args.link_mtu < (uint16_t)IDEMIP_IPV6_MIN_MTU)
    {
        return;
    }
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_PMTU6_PATHS; i++)
    {
        Pmtu6Stamp *s = PMTU6_AT(work, i);
        if (!s->used || (uint32_t)(io->now_ms - s->stamp_ms) < (uint32_t)IDEMIP_PMTU6_PROBE_MS)
        {
            continue;
        }
        s->used = IDEMIP_FALSE;
        io->index = i;
        io->dst = s->dst;
        io->mtu = io->probe_args.link_mtu;
        io->probe = IDEMIP_TRUE;
        io->status = IDEMIP_OK;
        return;
    }
    io->status = IDEMIP_BUSY;
}

// RFC 4861 sec 5.1 keeps the Destination Cache, and an entry leaving it takes the clock aging its
// estimate with it. A path carrying no stamp is ERR: this table cannot grow that row on its own.
static void pmtu6_forget(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Pmtu6Io *io = PMTU6_IO(work);
    io->status = IDEMIP_ERR;
    io->index = (uint8_t)IDEMIP_PMTU6_NONE;
    if (!pmtu6_ready(work) || io->path_args.dst == NULL)
    {
        return;
    }
    uint8_t i = pmtu6_find(work, io->path_args.dst);
    if (i == (uint8_t)IDEMIP_PMTU6_NONE)
    {
        return;
    }
    PMTU6_AT(work, i)->used = IDEMIP_FALSE;
    io->index = i;
    io->status = IDEMIP_OK;
}

const Pmtu6Ns Pmtu6 = {.clear = pmtu6_clear, .too_big = pmtu6_too_big, .tick = pmtu6_tick, .forget = pmtu6_forget};

IDEMIP_END_DECLS
