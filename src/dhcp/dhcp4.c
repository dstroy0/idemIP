// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dhcp4.c
 * @brief The RFC 2131 sec 4.4 client state, and the entries over it.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block and the context are both regions of that borrow, at compile-time offsets, and no entry reads
 * or writes a byte outside it. Two borrows therefore share nothing, and the same call on the same
 * borrow does the same thing.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/dhcp/dhcp4.h"
#include "src/endian.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. RFC 2131 sec 4.4.5 ages the lease off T1, T2 and the
// expiry, held here as millisecond deadlines, beside the sec 4.1 retransmission deadline and the
// millisecond the request went out that sec 4.4.5 measures the expiry from.
typedef struct
{
    const IdemIpDhcp4Cfg *cfg;
    IdemIpDhcp4State state;
    uint8_t owed; ///< the option 53 value build still has to write, 0 when none
    uint8_t sent; ///< the option 53 value of the request awaiting a reply, 0 when none
    uint8_t retries;
    uint32_t xid;
    IdemIpMs now_ms;
    IdemIpMs retry_ms;  ///< when the message goes out again (sec 4.1)
    uint32_t tick_ms;   ///< the last reading of the caller's 32-bit millisecond clock
    uint32_t tick_hi;   ///< its high word, raised each time that reading wraps
    IdemIpMs sent_ms;   ///< when it went out, which the expiry is measured from (sec 4.4.5)
    IdemIpMs t1_ms;     ///< the deadline RENEWING starts at
    IdemIpMs t2_ms;     ///< the deadline REBINDING starts at
    IdemIpMs expire_ms; ///< the deadline the lease ends at
    uint32_t server_id; ///< option 54, the server a unicast request goes to
    uint32_t offered_ip;
    uint32_t subnet_mask;
    uint32_t router;
    uint32_t lease_s;
    uint32_t t1_s;
    uint32_t t2_s;
    uint16_t secs; ///< the sec 2 'secs' field, seconds since acquisition began
} Dhcp4Ctx;

// The caller's borrow, split: the operand block, then the context. dhcp4.h publishes the offsets;
// the asserts below prove the span covers them before anything runs.
static_assert(IDEMIP_DHCP4_OFF_CTX + sizeof(Dhcp4Ctx) <= IDEMIP_DHCP4_CTX_BYTES,
              "IDEMIP_DHCP4_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_DHCP4_OFF_CTX + sizeof(Dhcp4Ctx) <= IDEMIP_DHCP4_BORROW,
              "IDEMIP_DHCP4_BORROW is short of the operand block and the context - raise IDEMIP_DHCP4_CTX_BYTES");
static_assert((IDEMIP_DHCP4_OFF_CTX & (IDEMIP_ALIGN - 1u)) == 0u,
              "the context does not start on IDEMIP_ALIGN: the operand block is rounded up to it");

// The regions, at their offsets in the caller's borrow.
#define DHCP4_CTX(w) ((Dhcp4Ctx *)(void *)((w) + IDEMIP_DHCP4_OFF_CTX))
#define DHCP4_IO(w) IDEMIP_DHCP4_IO(w)

// RFC 2131 sec 2, Figure 1: the octets 'sname' and 'file' span, which RFC 2132 sec 9.3 lets a server
// fill with options instead.
#define DHCP4_SNAME_LEN (IDEMIP_DHCP4_MSG_OFF_FILE - IDEMIP_DHCP4_MSG_OFF_SNAME)
#define DHCP4_FILE_LEN (IDEMIP_DHCP4_MSG_OFF_COOKIE - IDEMIP_DHCP4_MSG_OFF_FILE)

// RFC 2132 sec 9.3: option 52 value 1 puts options in 'file', 2 in 'sname', 3 in both.
#define DHCP4_OVERLOAD_FILE 1u
#define DHCP4_OVERLOAD_SNAME 2u

// RFC 2131 sec 4.1 doubles the retransmission delay four times to reach its 64-second maximum.
#define DHCP4_RETRY_SHIFT_MAX 4u

// One option each bit records as read, so an option that appears twice is taken once (RFC 2131
// sec 4.1: "Options may appear only once, unless otherwise specified in the options document").
#define DHCP4_HAS_MSG_TYPE 0x0001u
#define DHCP4_HAS_MASK 0x0002u
#define DHCP4_HAS_ROUTER 0x0004u
#define DHCP4_HAS_DNS 0x0008u
#define DHCP4_HAS_LEASE 0x0010u
#define DHCP4_HAS_SERVER_ID 0x0020u
#define DHCP4_HAS_T1 0x0040u
#define DHCP4_HAS_T2 0x0080u
#define DHCP4_HAS_OVERLOAD 0x0100u

// The options one message carried, gathered before any of them is committed, so a message that turns
// out to be malformed leaves the machine as it was. Scalars only: no array has automatic storage.
typedef struct
{
    uint32_t has;
    uint32_t subnet_mask;
    uint32_t router;
    uint32_t server_id;
    uint32_t lease_s;
    uint32_t t1_s;
    uint32_t t2_s;
    const uint8_t *dns;
    uint8_t dns_count;
    uint8_t msg_type;
    uint8_t overload;
} Dhcp4Opts;

// The option 55 codes this client asks for, which are the options input reads: RFC 2132 sec 3.3 the
// subnet mask, sec 3.5 the router list and sec 3.8 the domain name servers.
#define DHCP4_PARAM_COUNT 3u

// The widest option set any message carries: sec 9.6 the type, sec 9.10 the maximum message size,
// sec 9.1 the requested address, sec 9.7 the server, sec 9.2 the lease, sec 9.8 the request list, and
// sec 3.2 the end.
#define DHCP4_OPTS_MAX (3u + 4u + 6u + 6u + 6u + (2u + DHCP4_PARAM_COUNT) + 1u)
static_assert(IDEMIP_DHCP4_FIXED_LEN + DHCP4_OPTS_MAX <= IDEMIP_DHCP4_MSG_BOOTP_MIN,
              "every option a client message carries fits the 300-octet minimal BOOTP header (RFC 1542 sec 2.1)");

// --- the clock -------------------------------------------------------------

// Whether @p now has reached @p deadline. Both sit on the same 64-bit millisecond clock, so this is
// one comparison and nothing wraps under it.
static idemip_bool dhcp4_due(IdemIpMs now, IdemIpMs deadline)
{
    return (now >= deadline) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// A draw over [0, span] from one word: PLAN sec 3.4 masks to the power of two above the span and
// rejects an out-of-range draw. A second field of the same word is taken before falling back to the
// midpoint, so the draw is bounded and no divide appears. @p mask is 16 bits or fewer.
static uint32_t dhcp4_draw(uint32_t rand, uint32_t span, uint32_t mask)
{
    uint32_t v = rand & mask;
    if (v <= span)
    {
        return v;
    }
    v = (rand >> 16) & mask;
    if (v <= span)
    {
        return v;
    }
    return span >> 1;
}

// Whether a sec 3.3 time value runs a deadline at all: zero names no duration and 0xffffffff is
// infinity, and neither ages the lease.
static idemip_bool dhcp4_timed(uint32_t seconds)
{
    return ((seconds != 0u) && (seconds != IDEMIP_DHCP4_TIME_INFINITE)) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// Half the time left to a deadline, floored at the sec 4.4.5 minimum of 60 seconds: "the client
// SHOULD wait one-half of the remaining time until T2 (in RENEWING state) and one-half of the
// remaining lease time (in REBINDING state), down to a minimum of 60 seconds".
static uint32_t dhcp4_half_left(IdemIpMs now, IdemIpMs deadline, idemip_bool timed)
{
    IdemIpMs left = 0;
    if (timed && !dhcp4_due(now, deadline))
    {
        left = deadline - now;
    }
    IdemIpMs half = left >> 1;
    if (half > (IdemIpMs)0xFFFFFFFFu)
    {
        half = (IdemIpMs)0xFFFFFFFFu; // the interval is one word, and a lease this long is not bounded by it
    }
    return (half > (IdemIpMs)IDEMIP_DHCP4_RENEW_MIN_MS) ? (uint32_t)half : (uint32_t)IDEMIP_DHCP4_RENEW_MIN_MS;
}

// The delay before the message goes out again. sec 4.1: 4 seconds before the first retransmission,
// doubled with each one to a maximum of 64, "randomized by the value of a uniform random number
// chosen from the range -1 to +1". sec 4.4.5 replaces that in RENEWING and REBINDING with half the
// time left to T2 and to the expiry.
static uint32_t dhcp4_backoff(const Dhcp4Ctx *ctx, uint32_t rand)
{
    uint32_t base;
    if (ctx->state == IDEMIP_DHCP4_RENEWING)
    {
        base = dhcp4_half_left(ctx->now_ms, ctx->t2_ms, dhcp4_timed(ctx->t2_s));
    }
    else if (ctx->state == IDEMIP_DHCP4_REBINDING)
    {
        base = dhcp4_half_left(ctx->now_ms, ctx->expire_ms, dhcp4_timed(ctx->lease_s));
    }
    else
    {
        uint32_t shift = (ctx->retries < DHCP4_RETRY_SHIFT_MAX) ? (uint32_t)ctx->retries : DHCP4_RETRY_SHIFT_MAX;
        base = IDEMIP_DHCP4_RETRY_BASE_MS << shift;
    }
    uint32_t out = (base - IDEMIP_DHCP4_JITTER_MS) + dhcp4_draw(rand, IDEMIP_DHCP4_JITTER_MS << 1u, 0x7FFu);
    // sec 4.4.5 floors the RENEWING and REBINDING interval at 60 seconds, "down to a minimum of 60
    // seconds", so the jitter is applied inside that floor rather than allowed to carry it under.
    if ((ctx->state == IDEMIP_DHCP4_RENEWING || ctx->state == IDEMIP_DHCP4_REBINDING) &&
        out < (uint32_t)IDEMIP_DHCP4_RENEW_MIN_MS)
    {
        out = (uint32_t)IDEMIP_DHCP4_RENEW_MIN_MS;
    }
    return out;
}

// --- the context -----------------------------------------------------------

// What the caller reads after a call: the sec 4.4 state, the sec 4.1 'xid', and the lease the machine
// holds. The received option 6 addresses are not here: they live in the caller's message octets and
// only input reports them.
static void dhcp4_publish(uint8_t *restrict work)
{
    Dhcp4Io *io = DHCP4_IO(work);
    const Dhcp4Ctx *ctx = DHCP4_CTX(work);
    io->state = ctx->state;
    io->xid = ctx->xid;
    io->offered_ip = ctx->offered_ip;
    io->subnet_mask = ctx->subnet_mask;
    io->router = ctx->router;
    io->server_id = ctx->server_id;
    io->lease_s = ctx->lease_s;
    io->t1_s = ctx->t1_s;
    io->t2_s = ctx->t2_s;
}

// sec 4.4.5's "Halt network" and its lease expiry, and Figure 5's DHCPNAK restart: the machine returns
// to the INIT of sec 4.4.1 holding no address, so nothing of the lease is left for a later message to
// quote. The retransmission deadline is left alone, since the wait after a DHCPDECLINE outlives it.
static void dhcp4_halt(uint8_t *restrict work)
{
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    ctx->state = IDEMIP_DHCP4_INIT;
    ctx->owed = 0u;
    ctx->sent = 0u;
    ctx->retries = 0u;
    ctx->secs = 0u;
    ctx->sent_ms = 0;
    ctx->t1_ms = 0;
    ctx->t2_ms = 0;
    ctx->expire_ms = 0;
    ctx->server_id = 0u;
    ctx->offered_ip = 0u;
    ctx->subnet_mask = 0u;
    ctx->router = 0u;
    ctx->lease_s = 0u;
    ctx->t1_s = 0u;
    ctx->t2_s = 0u;
    dhcp4_publish(work);
}

// --- the option walk (RFC 2132) --------------------------------------------

// One options region. RFC 2132 sec 2: every option begins with a tag octet, "All other options are
// variable-length with a length octet following the tag octet", and only sec 3.1's pad and sec 3.2's
// end are the tag alone. False when an option's length runs past the region, or when a fixed-length
// option carries the wrong length, both of which make the message one to discard.
static idemip_bool dhcp4_walk(const uint8_t *base, size_t span, Dhcp4Opts *o)
{
    size_t i = 0;
    while (i < span)
    {
        uint8_t code = base[i];
        if (code == IDEMIP_DHCP4_OPT_END)
        {
            return IDEMIP_TRUE;
        }
        if (code == IDEMIP_DHCP4_OPT_PAD)
        {
            i++;
            continue;
        }
        if ((i + 2u) > span)
        {
            return IDEMIP_FALSE;
        }
        size_t olen = (size_t)base[i + 1u];
        if ((i + 2u + olen) > span)
        {
            return IDEMIP_FALSE;
        }
        const uint8_t *v = base + i + 2u;
        switch (code)
        {
        case IDEMIP_DHCP4_OPT_SUBNET_MASK: // sec 3.3, "its length is 4 octets"
            if (olen != 4u)
            {
                return IDEMIP_FALSE;
            }
            if ((o->has & DHCP4_HAS_MASK) == 0u)
            {
                o->subnet_mask = idemip_rd32(v);
                o->has |= DHCP4_HAS_MASK;
            }
            break;
        case IDEMIP_DHCP4_OPT_ROUTER: // sec 3.5, "the length MUST always be a multiple of 4"
            if ((olen < 4u) || ((olen & 3u) != 0u))
            {
                return IDEMIP_FALSE;
            }
            if ((o->has & DHCP4_HAS_ROUTER) == 0u)
            {
                o->router = idemip_rd32(v); // "Routers SHOULD be listed in order of preference"
                o->has |= DHCP4_HAS_ROUTER;
            }
            break;
        case IDEMIP_DHCP4_OPT_DNS_SERVER: // sec 3.8, a multiple of 4, in order of preference
            if ((olen < 4u) || ((olen & 3u) != 0u))
            {
                return IDEMIP_FALSE;
            }
            if ((o->has & DHCP4_HAS_DNS) == 0u)
            {
                o->dns = v;
                o->dns_count = (uint8_t)(olen >> 2);
                o->has |= DHCP4_HAS_DNS;
            }
            break;
        case IDEMIP_DHCP4_OPT_LEASE_TIME: // sec 9.2, length 4, seconds
            if (olen != 4u)
            {
                return IDEMIP_FALSE;
            }
            if ((o->has & DHCP4_HAS_LEASE) == 0u)
            {
                o->lease_s = idemip_rd32(v);
                o->has |= DHCP4_HAS_LEASE;
            }
            break;
        case IDEMIP_DHCP4_OPT_OVERLOAD: // sec 9.3, length 1, values 1, 2 and 3
            if ((olen != 1u) || (v[0] == 0u) || (v[0] > (DHCP4_OVERLOAD_FILE | DHCP4_OVERLOAD_SNAME)))
            {
                return IDEMIP_FALSE;
            }
            if ((o->has & DHCP4_HAS_OVERLOAD) == 0u)
            {
                o->overload = v[0];
                o->has |= DHCP4_HAS_OVERLOAD;
            }
            break;
        case IDEMIP_DHCP4_OPT_MSG_TYPE: // sec 9.6, length 1
            if (olen != 1u)
            {
                return IDEMIP_FALSE;
            }
            if ((o->has & DHCP4_HAS_MSG_TYPE) == 0u)
            {
                o->msg_type = v[0];
                o->has |= DHCP4_HAS_MSG_TYPE;
            }
            break;
        case IDEMIP_DHCP4_OPT_SERVER_ID: // sec 9.7, length 4
            if (olen != 4u)
            {
                return IDEMIP_FALSE;
            }
            if ((o->has & DHCP4_HAS_SERVER_ID) == 0u)
            {
                o->server_id = idemip_rd32(v);
                o->has |= DHCP4_HAS_SERVER_ID;
            }
            break;
        case IDEMIP_DHCP4_OPT_T1: // sec 9.11, length 4, seconds
            if (olen != 4u)
            {
                return IDEMIP_FALSE;
            }
            if ((o->has & DHCP4_HAS_T1) == 0u)
            {
                o->t1_s = idemip_rd32(v);
                o->has |= DHCP4_HAS_T1;
            }
            break;
        case IDEMIP_DHCP4_OPT_T2: // sec 9.12, length 4, seconds
            if (olen != 4u)
            {
                return IDEMIP_FALSE;
            }
            if ((o->has & DHCP4_HAS_T2) == 0u)
            {
                o->t2_s = idemip_rd32(v);
                o->has |= DHCP4_HAS_T2;
            }
            break;
        default: // an option this client does not read, skipped by its own length
            break;
        }
        i += 2u + olen;
    }
    return IDEMIP_TRUE;
}

// RFC 2131 sec 4.1: "The options in the 'options' field MUST be interpreted first, so that any
// 'option overload' options may be interpreted. The 'file' field MUST be interpreted next (if the
// 'option overload' option indicates that the 'file' field contains DHCP options), followed by the
// 'sname' field."
static idemip_bool dhcp4_parse(const uint8_t *msg, size_t len, Dhcp4Opts *o)
{
    memset(o, 0, sizeof *o);
    if (!dhcp4_walk(msg + IDEMIP_DHCP4_MSG_OFF_OPTIONS, len - IDEMIP_DHCP4_MSG_OFF_OPTIONS, o))
    {
        return IDEMIP_FALSE;
    }
    if ((o->has & DHCP4_HAS_OVERLOAD) == 0u)
    {
        return IDEMIP_TRUE;
    }
    if (((o->overload & DHCP4_OVERLOAD_FILE) != 0u) &&
        !dhcp4_walk(msg + IDEMIP_DHCP4_MSG_OFF_FILE, DHCP4_FILE_LEN, o))
    {
        return IDEMIP_FALSE;
    }
    if (((o->overload & DHCP4_OVERLOAD_SNAME) != 0u) &&
        !dhcp4_walk(msg + IDEMIP_DHCP4_MSG_OFF_SNAME, DHCP4_SNAME_LEN, o))
    {
        return IDEMIP_FALSE;
    }
    return IDEMIP_TRUE;
}

// --- what a received message changes ---------------------------------------

// The parameters a DHCPOFFER or DHCPACK carried. An option the message left out leaves what the
// machine already holds: RFC 2132 sec 9.7 makes the server identifier optional in a DHCPACK, and
// sec 3.1 says an ACK's parameters "SHOULD NOT conflict with those in the earlier DHCPOFFER".
static void dhcp4_adopt(uint8_t *restrict work, const Dhcp4Opts *o)
{
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if ((o->has & DHCP4_HAS_MASK) != 0u)
    {
        ctx->subnet_mask = o->subnet_mask;
    }
    if ((o->has & DHCP4_HAS_ROUTER) != 0u)
    {
        ctx->router = o->router;
    }
    if ((o->has & DHCP4_HAS_SERVER_ID) != 0u)
    {
        ctx->server_id = o->server_id;
    }
    if ((o->has & DHCP4_HAS_DNS) != 0u)
    {
        io->dns = o->dns; // in the caller's message octets, valid while the caller holds them
        io->dns_count = o->dns_count;
    }
}

// The lease a DHCPACK carried, and the sec 4.4.5 times over it. T1 and T2 default to "(0.5 *
// duration_of_lease)" and "(0.875 * duration_of_lease)", both exact as shifts, and sec 4.4.5 requires
// "T1 MUST be earlier than T2, which, in turn, MUST be earlier than the time at which the client's
// lease will expire", so an offered pair that is not is replaced by the defaults.
static void dhcp4_lease(uint8_t *restrict work, const Dhcp4Opts *o, const uint8_t *msg)
{
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    ctx->offered_ip = idemip_rd32(msg + IDEMIP_DHCP4_MSG_OFF_YIADDR); // sec 2, 'yiaddr'
    if ((o->has & DHCP4_HAS_LEASE) != 0u)
    {
        ctx->lease_s = o->lease_s;
    }
    uint32_t lease = ctx->lease_s;
    uint32_t t1 = lease >> 1;
    uint32_t t2 = lease - (lease >> 3);
    if (dhcp4_timed(lease))
    {
        // sec 4.4.5 makes each of T1 and T2 "configurable by the server through options" with its own
        // default, so a present option 58 governs T1 whether or not option 59 came with it. The
        // ordering test then runs over whatever pair that leaves, and an inconsistent one falls back
        // to both defaults: "T1 MUST be earlier than T2, which, in turn, MUST be earlier than the
        // time at which the client's lease will expire."
        uint32_t want_t1 = ((o->has & DHCP4_HAS_T1) != 0u) ? o->t1_s : t1;
        uint32_t want_t2 = ((o->has & DHCP4_HAS_T2) != 0u) ? o->t2_s : t2;
        if ((want_t1 < want_t2) && (want_t2 < lease))
        {
            t1 = want_t1;
            t2 = want_t2;
        }
    }
    else
    {
        t1 = lease; // a lease of zero or of sec 3.3's infinity runs no T1 and no T2
        t2 = lease;
    }
    ctx->t1_s = t1;
    ctx->t2_s = t2;
    // sec 4.4.5: "the client computes the lease expiration time as the sum of the time at which the
    // client sent the DHCPREQUEST message and the duration of the lease in the DHCPACK message".
    // sec 4.4.5: "T1 MUST be earlier than T2, which, in turn, MUST be earlier than the time at
    // which the client's lease will expire." The deadlines sit on the 64-bit millisecond clock, so
    // the full 32-bit second range sec 3.3 gives option 51 is representable and the three never
    // collapse onto one instant.
    ctx->t1_ms = ctx->sent_ms + idemip_ms_from_s(t1);
    ctx->t2_ms = ctx->sent_ms + idemip_ms_from_s(t2);
    ctx->expire_ms = ctx->sent_ms + idemip_ms_from_s(lease);
    ctx->state = IDEMIP_DHCP4_BOUND;
    ctx->owed = 0u;
    ctx->sent = 0u;
    ctx->retries = 0u;
    ctx->retry_ms = ctx->now_ms;
}

// sec 4.4.1: an offer is collected in SELECTING, and the selected one supplies the 'server identifier'
// that sec 3.1 makes the DHCPREQUEST carry, so an offer without option 54 cannot be selected. The
// first acceptable offer is taken, which sec 4.4.1 permits: "e.g., the first DHCPOFFER message".
static idemip_bool dhcp4_offer(uint8_t *restrict work, const Dhcp4Opts *o, const uint8_t *msg)
{
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if (ctx->state != IDEMIP_DHCP4_SELECTING)
    {
        return IDEMIP_FALSE; // Figure 5 discards an offer in every other state
    }
    if ((o->has & DHCP4_HAS_SERVER_ID) == 0u)
    {
        return IDEMIP_FALSE;
    }
    dhcp4_adopt(work, o);
    if ((o->has & DHCP4_HAS_LEASE) != 0u)
    {
        ctx->lease_s = o->lease_s; // sec 9.2: the lease "it is willing to offer"
    }
    ctx->offered_ip = idemip_rd32(msg + IDEMIP_DHCP4_MSG_OFF_YIADDR);
    // Figure 5: "Select offer/send DHCPREQUEST" moves SELECTING to REQUESTING.
    ctx->state = IDEMIP_DHCP4_REQUESTING;
    ctx->retries = 0u;
    ctx->sent = 0u;
    ctx->owed = (uint8_t)IDEMIP_DHCP4_REQUEST;
    return IDEMIP_TRUE;
}

// Figure 5: a DHCPACK records the lease and sets T1 and T2 out of REQUESTING, REBOOTING, RENEWING and
// REBINDING. sec 4.4.3's DHCPACK answering a DHCPINFORM carries no lease, so it sets the parameters
// alone: "Once a DHCPACK message with an 'xid' field matching that in the client's DHCPINFORM message
// arrives from any server, the client is initialized."
static idemip_bool dhcp4_ack(uint8_t *restrict work, const Dhcp4Opts *o, const uint8_t *msg)
{
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if (ctx->sent == (uint8_t)IDEMIP_DHCP4_INFORM)
    {
        dhcp4_adopt(work, o);
        ctx->sent = 0u;
        ctx->owed = 0u;
        ctx->retries = 0u;
        return IDEMIP_TRUE;
    }
    if ((ctx->state != IDEMIP_DHCP4_REQUESTING) && (ctx->state != IDEMIP_DHCP4_REBOOTING) &&
        (ctx->state != IDEMIP_DHCP4_RENEWING) && (ctx->state != IDEMIP_DHCP4_REBINDING))
    {
        return IDEMIP_FALSE; // sec 4.4.1 discards an ACK in SELECTING, Figure 5 discards one in BOUND
    }
    dhcp4_adopt(work, o);
    dhcp4_lease(work, o, msg);
    return IDEMIP_TRUE;
}

// Figure 5: a DHCPNAK restarts out of REQUESTING and REBOOTING and halts the network out of RENEWING
// and REBINDING, both of which hold no lease afterwards. sec 3.2: a client that cannot reuse its
// remembered address "must instead request a new address by restarting the configuration process",
// which is start with the fresh 'xid' sec 4.4.1 requires of it.
static idemip_bool dhcp4_nak(uint8_t *restrict work)
{
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if ((ctx->state != IDEMIP_DHCP4_REQUESTING) && (ctx->state != IDEMIP_DHCP4_REBOOTING) &&
        (ctx->state != IDEMIP_DHCP4_RENEWING) && (ctx->state != IDEMIP_DHCP4_REBINDING))
    {
        return IDEMIP_FALSE;
    }
    dhcp4_halt(work);
    return IDEMIP_TRUE;
}

// One received message. RFC 1542 sec 2.1 discards a message whose 'op' is neither code, sec 4.1 makes
// 'xid' what a reply is matched on, and sec 4.2 makes 'chaddr' the client's identity when no 'client
// identifier' was sent. A message that fails any test, or that this state discards, changes nothing.
static idemip_bool dhcp4_take(uint8_t *restrict work)
{
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    const IdemIpDhcp4Cfg *cfg = ctx->cfg;
    const uint8_t *msg = io->input_args.msg;
    // RFC 1542 sec 2.1: "The IP Total Length and UDP Length must be large enough to contain the
    // minimal BOOTP header of 300 octets (in the UDP data field)", and "BOOTP messages not meeting
    // these consistency checks MUST be silently discarded". The build path already holds to the same
    // 300 octets.
    if ((msg == NULL) || (io->input_args.len < IDEMIP_DHCP4_MSG_BOOTP_MIN))
    {
        return IDEMIP_FALSE;
    }
    if (msg[IDEMIP_DHCP4_MSG_OFF_OP] != IDEMIP_DHCP4_OP_BOOTREPLY)
    {
        return IDEMIP_FALSE;
    }
    // RFC 2132 sec 2: the cookie "identifies the mode in which the succeeding data is to be
    // interpreted", so options are read only behind it.
    if (idemip_rd32(msg + IDEMIP_DHCP4_MSG_OFF_COOKIE) != IDEMIP_DHCP4_MAGIC_COOKIE)
    {
        return IDEMIP_FALSE;
    }
    if (idemip_rd32(msg + IDEMIP_DHCP4_MSG_OFF_XID) != ctx->xid)
    {
        return IDEMIP_FALSE;
    }
    if ((msg[IDEMIP_DHCP4_MSG_OFF_HTYPE] != cfg->htype) || (msg[IDEMIP_DHCP4_MSG_OFF_HLEN] != cfg->hlen))
    {
        return IDEMIP_FALSE;
    }
    if (memcmp(msg + IDEMIP_DHCP4_MSG_OFF_CHADDR, cfg->chaddr, cfg->hlen) != 0)
    {
        return IDEMIP_FALSE;
    }
    Dhcp4Opts o;
    if (!dhcp4_parse(msg, io->input_args.len, &o))
    {
        return IDEMIP_FALSE;
    }
    if ((o.has & DHCP4_HAS_MSG_TYPE) == 0u)
    {
        return IDEMIP_FALSE; // sec 4.1: the type is an option, and a message without one says nothing
    }
    io->msg_type = o.msg_type;
    switch (o.msg_type)
    {
    case (uint8_t)IDEMIP_DHCP4_OFFER:
        return dhcp4_offer(work, &o, msg);
    case (uint8_t)IDEMIP_DHCP4_ACK:
        return dhcp4_ack(work, &o, msg);
    case (uint8_t)IDEMIP_DHCP4_NAK:
        return dhcp4_nak(work);
    default:
        // sec 4.4: "A client can receive the following messages from a server: DHCPOFFER, DHCPACK,
        // DHCPNAK." Every other type is a client's own and is discarded here.
        return IDEMIP_FALSE;
    }
}

// --- what a message to send looks like -------------------------------------

// RFC 2132 sec 2: a tag octet, a length octet, then that many octets of data.
static size_t dhcp4_opt_u8(uint8_t *out, size_t at, uint8_t code, uint8_t v)
{
    out[at] = code;
    out[at + 1u] = 1u;
    out[at + 2u] = v;
    return at + 3u;
}

static size_t dhcp4_opt_u16(uint8_t *out, size_t at, uint8_t code, uint16_t v)
{
    out[at] = code;
    out[at + 1u] = 2u;
    idemip_wr16(out + at + 2u, v);
    return at + 4u;
}

static size_t dhcp4_opt_u32(uint8_t *out, size_t at, uint8_t code, uint32_t v)
{
    out[at] = code;
    out[at + 1u] = 4u;
    idemip_wr32(out + at + 2u, v);
    return at + 6u;
}

// The message the state owes, as RFC 2131 Table 4 and Table 5 give its fields and options. Every
// octet past the last option is a sec 3.1 pad, left by the zeroing above, and the message spans the
// 300 octets RFC 1542 sec 2.1 checks for.
static void dhcp4_write(uint8_t *restrict work)
{
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    const IdemIpDhcp4Cfg *cfg = ctx->cfg;
    uint8_t *out = io->build_args.out;
    uint8_t type = ctx->owed;

    // Table 5 leaves 'hops', 'yiaddr', 'siaddr', 'giaddr', 'sname' and 'file' zero on every client
    // message, and every octet past the last option is a pad.
    memset(out, 0, IDEMIP_DHCP4_MSG_BOOTP_MIN);

    // Table 4: 'ciaddr' holds the address in RENEWING and REBINDING and is zero in INIT-REBOOT and
    // SELECTING. Table 5: it holds the address in a DHCPINFORM and a DHCPRELEASE and is zero in a
    // DHCPDECLINE.
    idemip_bool renewing =
        (ctx->state == IDEMIP_DHCP4_RENEWING) || (ctx->state == IDEMIP_DHCP4_REBINDING) ? IDEMIP_TRUE : IDEMIP_FALSE;
    idemip_bool ciaddr = IDEMIP_FALSE;
    idemip_bool want_server = IDEMIP_FALSE; // option 54
    idemip_bool want_req_ip = IDEMIP_FALSE; // option 50
    idemip_bool want_lease = IDEMIP_FALSE;  // option 51
    idemip_bool want_hints = IDEMIP_FALSE;  // options 55 and 57
    idemip_bool want_flag = IDEMIP_FALSE;   // the Figure 2 BROADCAST bit
    uint16_t secs = ctx->secs;
    uint32_t dst = 0xFFFFFFFFu; // sec 4.4.4 broadcasts unless the message names the server

    switch (type)
    {
    case (uint8_t)IDEMIP_DHCP4_DISCOVER:
        // Table 5: server identifier MUST NOT, requested address MAY, lease time MAY, and the
        // BROADCAST flag is set "if client requires broadcast reply".
        want_lease = IDEMIP_TRUE;
        want_hints = IDEMIP_TRUE;
        want_flag = IDEMIP_TRUE;
        break;
    case (uint8_t)IDEMIP_DHCP4_REQUEST:
        // Table 4: the server identifier is MUST in SELECTING and MUST NOT elsewhere, and the
        // requested address is MUST in SELECTING and INIT-REBOOT and MUST NOT in RENEWING and
        // REBINDING.
        want_server = (ctx->state == IDEMIP_DHCP4_REQUESTING) ? IDEMIP_TRUE : IDEMIP_FALSE;
        want_req_ip = renewing ? IDEMIP_FALSE : IDEMIP_TRUE;
        want_lease = IDEMIP_TRUE;
        want_hints = IDEMIP_TRUE;
        ciaddr = renewing;
        // sec 4.1: the BROADCAST bit is for "A client that cannot receive unicast IP datagrams until
        // its protocol software has been configured with an IP address", so a request that carries an
        // address in 'ciaddr' is past needing it.
        want_flag = renewing ? IDEMIP_FALSE : IDEMIP_TRUE;
        // sec 4.4.5: at T1 the client "sends (via unicast) a DHCPREQUEST message to the server", and
        // in REBINDING it "sends (via broadcast) a DHCPREQUEST message".
        if (ctx->state == IDEMIP_DHCP4_RENEWING)
        {
            dst = ctx->server_id;
        }
        break;
    case (uint8_t)IDEMIP_DHCP4_DECLINE:
        // Table 5: server identifier MUST, requested address MUST, 'ciaddr' zero, 'secs' 0, and the
        // lease time, request list and message size MUST NOT. sec 4.4.4 broadcasts it.
        want_server = IDEMIP_TRUE;
        want_req_ip = IDEMIP_TRUE;
        secs = 0u;
        break;
    case (uint8_t)IDEMIP_DHCP4_RELEASE:
        // Table 5: server identifier MUST, requested address MUST NOT, 'ciaddr' the address, 'secs' 0.
        // sec 4.4.4: "The client unicasts DHCPRELEASE messages to the server."
        want_server = IDEMIP_TRUE;
        ciaddr = IDEMIP_TRUE;
        secs = 0u;
        dst = ctx->server_id;
        break;
    default: // IDEMIP_DHCP4_INFORM
        // sec 4.4.3: "The client places its own network address in the 'ciaddr' field. The client
        // SHOULD NOT request lease time parameters", and it unicasts to a known server.
        ciaddr = IDEMIP_TRUE;
        want_hints = IDEMIP_TRUE;
        if (ctx->server_id != 0u)
        {
            dst = ctx->server_id;
        }
        break;
    }

    out[IDEMIP_DHCP4_MSG_OFF_OP] = IDEMIP_DHCP4_OP_BOOTREQUEST; // Table 5, every client message
    out[IDEMIP_DHCP4_MSG_OFF_HTYPE] = cfg->htype;
    out[IDEMIP_DHCP4_MSG_OFF_HLEN] = cfg->hlen;
    idemip_wr32(out + IDEMIP_DHCP4_MSG_OFF_XID, ctx->xid);
    idemip_wr16(out + IDEMIP_DHCP4_MSG_OFF_SECS, secs);
    // Table 5 carries the flag on a DHCPDISCOVER and a DHCPREQUEST and clears 'flags' on a
    // DHCPDECLINE and a DHCPRELEASE, and sec 4.1 leaves the choice to the client.
    if (cfg->broadcast && want_flag)
    {
        idemip_wr16(out + IDEMIP_DHCP4_MSG_OFF_FLAGS, IDEMIP_DHCP4_FLAG_BROADCAST);
    }
    if (ciaddr)
    {
        idemip_wr32(out + IDEMIP_DHCP4_MSG_OFF_CIADDR, ctx->offered_ip);
    }
    memcpy(out + IDEMIP_DHCP4_MSG_OFF_CHADDR, cfg->chaddr, cfg->hlen); // sec 2, 'chaddr'
    idemip_wr32(out + IDEMIP_DHCP4_MSG_OFF_COOKIE, IDEMIP_DHCP4_MAGIC_COOKIE);

    size_t at = IDEMIP_DHCP4_MSG_OFF_OPTIONS;
    at = dhcp4_opt_u8(out, at, IDEMIP_DHCP4_OPT_MSG_TYPE, type); // sec 9.6
    if (want_hints)
    {
        // sec 3.5: "The client SHOULD include the 'maximum DHCP message size' option to let the
        // server know how large the server may make its DHCP messages", and sec 9.10's minimum legal
        // value is 576.
        at = dhcp4_opt_u16(out, at, IDEMIP_DHCP4_OPT_MAX_MSG_SIZE, (uint16_t)IDEMIP_DHCP4_MSG_MIN);
    }
    if (want_req_ip)
    {
        at = dhcp4_opt_u32(out, at, IDEMIP_DHCP4_OPT_REQUESTED_IP, ctx->offered_ip); // sec 9.1
    }
    if (want_server)
    {
        at = dhcp4_opt_u32(out, at, IDEMIP_DHCP4_OPT_SERVER_ID, ctx->server_id); // sec 9.7
    }
    if (want_lease && (cfg->lease_s != 0u))
    {
        at = dhcp4_opt_u32(out, at, IDEMIP_DHCP4_OPT_LEASE_TIME, cfg->lease_s); // sec 9.2
    }
    if (want_hints)
    {
        // sec 9.8: "The list of requested parameters is specified as n octets, where each octet is a
        // valid DHCP option code."
        out[at] = IDEMIP_DHCP4_OPT_PARAM_LIST;
        out[at + 1u] = (uint8_t)DHCP4_PARAM_COUNT;
        out[at + 2u] = IDEMIP_DHCP4_OPT_SUBNET_MASK;
        out[at + 3u] = IDEMIP_DHCP4_OPT_ROUTER;
        out[at + 4u] = IDEMIP_DHCP4_OPT_DNS_SERVER;
        at += 2u + DHCP4_PARAM_COUNT;
    }
    out[at] = IDEMIP_DHCP4_OPT_END; // sec 3.2, "The last option must always be the 'end' option"
    io->len = IDEMIP_DHCP4_MSG_BOOTP_MIN;
    io->dst = dst;
    io->dst_port = (uint16_t)IDEMIP_DHCP4_PORT_SERVER;
    io->src_port = (uint16_t)IDEMIP_DHCP4_PORT_CLIENT;
    io->msg_type = type;

    // sec 4.4.1 and sec 4.4.5: the client records the local time the message went out, which the
    // lease expiration is measured from. The clock is the one the last tick or start supplied.
    IdemIpMs next_ms = ctx->now_ms + (IdemIpMs)dhcp4_backoff(ctx, io->tick_args.rand);
    ctx->sent_ms = ctx->now_ms;
    ctx->sent = type;
    ctx->owed = 0u;
    if (ctx->retries < 0xFFu)
    {
        ctx->retries++;
    }
    if (type == (uint8_t)IDEMIP_DHCP4_RELEASE)
    {
        // sec 4.4.6: the address is given up, and "the correct operation of DHCP does not depend on
        // the transmission of DHCPRELEASE messages", so nothing is retransmitted.
        dhcp4_halt(work);
        next_ms = ctx->now_ms;
    }
    else if (type == (uint8_t)IDEMIP_DHCP4_DECLINE)
    {
        // sec 3.1: the client "restarts the configuration process" and "SHOULD wait a minimum of ten
        // seconds before restarting", which start reports BUSY until.
        dhcp4_halt(work);
        next_ms = ctx->now_ms + (IdemIpMs)IDEMIP_DHCP4_DECLINE_WAIT_MS;
    }
    ctx->retry_ms = next_ms;
}

// --- what a deadline does --------------------------------------------------

// A retransmission of the request still outstanding, or the end of the transmissions sec 3.1 allows
// it. sec 3.1: "If the client receives neither a DHCPACK or a DHCPNAK message after employing the
// retransmission algorithm, the client reverts to INIT state and restarts the initialization process."
static idemip_bool dhcp4_retry(uint8_t *restrict work, uint8_t tries)
{
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if ((tries != 0u) && (ctx->retries >= tries))
    {
        dhcp4_halt(work);
        return IDEMIP_TRUE;
    }
    ctx->owed = ctx->sent;
    return IDEMIP_TRUE;
}

// The deadline that has passed, in the state it passed in.
static idemip_bool dhcp4_run(uint8_t *restrict work)
{
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if (ctx->owed != 0u)
    {
        return IDEMIP_FALSE; // build has not taken the message the last deadline owed
    }
    switch (ctx->state)
    {
    case IDEMIP_DHCP4_SELECTING:
        // sec 4.4.1: the DHCPDISCOVER goes out once the one-to-ten-second delay has passed, and again
        // on every sec 4.1 deadline after it. The client keeps trying, the delay capping at 64 seconds.
        if (!dhcp4_due(ctx->now_ms, ctx->retry_ms))
        {
            return IDEMIP_FALSE;
        }
        ctx->sent = (uint8_t)IDEMIP_DHCP4_DISCOVER;
        return dhcp4_retry(work, 0u);
    case IDEMIP_DHCP4_INIT_REBOOT:
        // Figure 5: "-/Send DHCPREQUEST" moves INIT-REBOOT to REBOOTING.
        if (!dhcp4_due(ctx->now_ms, ctx->retry_ms))
        {
            return IDEMIP_FALSE;
        }
        ctx->state = IDEMIP_DHCP4_REBOOTING;
        ctx->sent = (uint8_t)IDEMIP_DHCP4_REQUEST;
        ctx->retries = 0u;
        ctx->owed = (uint8_t)IDEMIP_DHCP4_REQUEST;
        return IDEMIP_TRUE;
    case IDEMIP_DHCP4_REQUESTING:
    case IDEMIP_DHCP4_REBOOTING:
        if (!dhcp4_due(ctx->now_ms, ctx->retry_ms))
        {
            return IDEMIP_FALSE;
        }
        return dhcp4_retry(work, (uint8_t)IDEMIP_DHCP4_REQUEST_TRIES);
    case IDEMIP_DHCP4_BOUND:
    case IDEMIP_DHCP4_RENEWING:
    case IDEMIP_DHCP4_REBINDING:
        // sec 4.4.5: "If the lease expires before the client receives a DHCPACK, the client moves to
        // INIT state, MUST immediately stop any other network processing."
        if (dhcp4_timed(ctx->lease_s) && dhcp4_due(ctx->now_ms, ctx->expire_ms))
        {
            dhcp4_halt(work);
            return IDEMIP_TRUE;
        }
        // "If no DHCPACK arrives before time T2, the client moves to REBINDING state and sends (via
        // broadcast) a DHCPREQUEST message to extend its lease."
        if ((ctx->state != IDEMIP_DHCP4_REBINDING) && dhcp4_timed(ctx->t2_s) &&
            dhcp4_due(ctx->now_ms, ctx->t2_ms))
        {
            ctx->state = IDEMIP_DHCP4_REBINDING;
            ctx->sent = (uint8_t)IDEMIP_DHCP4_REQUEST;
            ctx->retries = 0u;
            ctx->owed = (uint8_t)IDEMIP_DHCP4_REQUEST;
            return IDEMIP_TRUE;
        }
        // "At time T1 the client moves to RENEWING state and sends (via unicast) a DHCPREQUEST message
        // to the server to extend its lease."
        if ((ctx->state == IDEMIP_DHCP4_BOUND) && dhcp4_timed(ctx->t1_s) && dhcp4_due(ctx->now_ms, ctx->t1_ms))
        {
            ctx->state = IDEMIP_DHCP4_RENEWING;
            ctx->sent = (uint8_t)IDEMIP_DHCP4_REQUEST;
            ctx->retries = 0u;
            ctx->owed = (uint8_t)IDEMIP_DHCP4_REQUEST;
            return IDEMIP_TRUE;
        }
        if (ctx->state == IDEMIP_DHCP4_BOUND)
        {
            return IDEMIP_FALSE; // Figure 5 leaves BOUND on T1, T2 or the expiry and on nothing else
        }
        if (!dhcp4_due(ctx->now_ms, ctx->retry_ms))
        {
            return IDEMIP_FALSE;
        }
        return dhcp4_retry(work, 0u);
    default: // IDEMIP_DHCP4_INIT
        // sec 4.4.3's DHCPINFORM is the only exchange INIT runs, and it gives up after "60 seconds or
        // 4 tries".
        if ((ctx->sent != (uint8_t)IDEMIP_DHCP4_INFORM) || !dhcp4_due(ctx->now_ms, ctx->retry_ms))
        {
            return IDEMIP_FALSE;
        }
        if (ctx->retries >= (uint8_t)IDEMIP_DHCP4_INFORM_TRIES)
        {
            ctx->sent = 0u;
            ctx->retries = 0u;
            return IDEMIP_TRUE;
        }
        ctx->owed = (uint8_t)IDEMIP_DHCP4_INFORM;
        return IDEMIP_TRUE;
    }
}

// --- the entries -----------------------------------------------------------

// Every byte of the borrow, the operand block included, which leaves the state at zero: the INIT
// sec 4.4.1 begins in.
static void dhcp4_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work, 0, IDEMIP_DHCP4_BORROW);
    DHCP4_IO(work)->status = IDEMIP_OK;
}

// 'chaddr' is 16 octets and 'hlen' counts how many of them carry the address (RFC 2131 sec 2), so a
// length past that, or a missing address, is refused here rather than read past at the first build.
static void dhcp4_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp4Io *io = DHCP4_IO(work);
    io->status = IDEMIP_ERR;
    const IdemIpDhcp4Cfg *cfg = io->bind_args.cfg;
    if (cfg == NULL || cfg->chaddr == NULL || cfg->hlen == 0u || cfg->hlen > IDEMIP_DHCP4_CHADDR_LEN ||
        cfg->netif >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    ctx->cfg = cfg;
    ctx->state = IDEMIP_DHCP4_INIT;
    io->state = IDEMIP_DHCP4_INIT;
    io->status = IDEMIP_OK;
}

static void dhcp4_start(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // A machine already running a transaction is not restarted: sec 4.4 gives every state its own
    // exchange, and stop is what returns one to INIT.
    if (ctx->state != IDEMIP_DHCP4_INIT)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    ctx->now_ms = idemip_ms_extend(&ctx->tick_ms, &ctx->tick_hi, io->start_args.now_ms);
    // sec 3.1: the ten seconds a DHCPDECLINE asks for before the configuration process restarts. A
    // later call makes progress, so this is BUSY.
    if (!dhcp4_due(ctx->now_ms, ctx->retry_ms))
    {
        io->status = IDEMIP_BUSY;
        return;
    }
    // sec 4.4.1: "The client generates and records a random transaction identifier."
    ctx->xid = io->start_args.xid;
    ctx->retries = 0u;
    ctx->owed = 0u;
    ctx->sent = 0u;
    ctx->secs = 0u; // Table 5: 'secs' is "0 or seconds since DHCP process started"
    ctx->sent_ms = ctx->now_ms;
    if (io->offered_ip != 0u)
    {
        // sec 4.4.2: "The client begins in INIT-REBOOT state and sends a DHCPREQUEST message. The
        // client MUST insert its known network address as a 'requested IP address' option."
        ctx->offered_ip = io->offered_ip;
        ctx->state = IDEMIP_DHCP4_INIT_REBOOT;
        ctx->retry_ms = ctx->now_ms;
    }
    else
    {
        // sec 4.4.1: "The client SHOULD wait a random time between one and ten seconds to
        // desynchronize the use of DHCP at startup", and the DHCPDISCOVER goes out after it.
        ctx->state = IDEMIP_DHCP4_SELECTING;
        ctx->retry_ms = ctx->now_ms + IDEMIP_DHCP4_START_DELAY_MIN_MS +
                        dhcp4_draw(io->start_args.rand,
                                   IDEMIP_DHCP4_START_DELAY_MAX_MS - IDEMIP_DHCP4_START_DELAY_MIN_MS, 0x3FFFu);
    }
    dhcp4_publish(work);
    io->status = IDEMIP_OK;
}

static void dhcp4_stop(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // sec 4.4.5's "Halt network": the machine holds no address and runs no exchange. A machine
    // already in INIT is left there, so the same call twice does the same thing.
    dhcp4_halt(work);
    ctx->retry_ms = ctx->now_ms;
    io->status = IDEMIP_OK;
}

static void dhcp4_input(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    io->msg_type = 0u;
    io->dns = NULL;
    io->dns_count = 0u;
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // A message this machine discards reports ERR: sec 4.4.1 has the client discard one silently, and
    // the same octets on a later call are discarded again, so BUSY would spin the caller.
    idemip_bool took = dhcp4_take(work);
    dhcp4_publish(work);
    io->status = took ? IDEMIP_OK : IDEMIP_ERR;
}

static void dhcp4_build(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    io->len = 0;
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // A buffer shorter than RFC 1542 sec 2.1's minimal BOOTP header can never hold a message, so it
    // is ERR and not BUSY.
    if ((io->build_args.out == NULL) || (io->build_args.cap < IDEMIP_DHCP4_MSG_BOOTP_MIN))
    {
        io->status = IDEMIP_ERR;
        return;
    }
    if (ctx->owed == 0u)
    {
        io->status = IDEMIP_BUSY; // nothing owed now; a later tick owes one
        return;
    }
    // A unicast with no server to send to cannot be built: sec 4.1 requires that "DHCP clients MUST
    // use the IP address provided in the 'server identifier' option for any unicast requests".
    if ((ctx->server_id == 0u) && ((ctx->owed == (uint8_t)IDEMIP_DHCP4_RELEASE) ||
                                   (ctx->owed == (uint8_t)IDEMIP_DHCP4_DECLINE) ||
                                   ((ctx->owed == (uint8_t)IDEMIP_DHCP4_REQUEST) &&
                                    (ctx->state == IDEMIP_DHCP4_REQUESTING || ctx->state == IDEMIP_DHCP4_RENEWING))))
    {
        io->status = IDEMIP_ERR;
        return;
    }
    dhcp4_write(work);
    dhcp4_publish(work);
    io->status = IDEMIP_OK;
}

static void dhcp4_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    ctx->now_ms = idemip_ms_extend(&ctx->tick_ms, &ctx->tick_hi, io->tick_args.now_ms);
    // No deadline has passed, so nothing moved and a later tick may: BUSY.
    idemip_bool moved = dhcp4_run(work);
    dhcp4_publish(work);
    io->status = moved ? IDEMIP_OK : IDEMIP_BUSY;
}

static void dhcp4_release(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // sec 4.4.6: the client sends a DHCPRELEASE when it "no longer requires use of its assigned
    // network address", so only a machine holding one can, and Table 5 makes the server identifier
    // and 'ciaddr' both required.
    if (((ctx->state != IDEMIP_DHCP4_BOUND) && (ctx->state != IDEMIP_DHCP4_RENEWING) &&
         (ctx->state != IDEMIP_DHCP4_REBINDING)) ||
        (ctx->server_id == 0u) || (ctx->offered_ip == 0u))
    {
        io->status = IDEMIP_ERR;
        return;
    }
    ctx->owed = (uint8_t)IDEMIP_DHCP4_RELEASE;
    ctx->retries = 0u;
    dhcp4_publish(work);
    io->status = IDEMIP_OK;
}

static void dhcp4_decline(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // sec 3.1 point 5: the check follows the DHCPACK, and "If the client detects that the address is
    // already in use (e.g., through the use of ARP), the client MUST send a DHCPDECLINE message to
    // the server". Table 5 makes the server identifier and the requested address both required.
    if ((ctx->state != IDEMIP_DHCP4_BOUND) || (ctx->server_id == 0u) || (ctx->offered_ip == 0u))
    {
        io->status = IDEMIP_ERR;
        return;
    }
    ctx->owed = (uint8_t)IDEMIP_DHCP4_DECLINE;
    ctx->retries = 0u;
    dhcp4_publish(work);
    io->status = IDEMIP_OK;
}

static void dhcp4_inform(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    Dhcp4Io *io = DHCP4_IO(work);
    Dhcp4Ctx *ctx = DHCP4_CTX(work);
    if (ctx->cfg == NULL)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // sec 4.4.3: the address is one "obtained ... through some other means", so the machine holds no
    // lease and runs no other exchange, and 'ciaddr' has to carry that address.
    if ((ctx->state != IDEMIP_DHCP4_INIT) || (io->offered_ip == 0u))
    {
        io->status = IDEMIP_ERR;
        return;
    }
    // "The client generates and records a random transaction identifier and inserts that identifier
    // into the 'xid' field. The client places its own network address in the 'ciaddr' field."
    ctx->xid = io->start_args.xid;
    ctx->now_ms = idemip_ms_extend(&ctx->tick_ms, &ctx->tick_hi, io->start_args.now_ms);
    ctx->offered_ip = io->offered_ip;
    ctx->secs = 0u;
    ctx->retries = 0u;
    ctx->owed = (uint8_t)IDEMIP_DHCP4_INFORM;
    ctx->sent = 0u;
    dhcp4_publish(work);
    io->status = IDEMIP_OK;
}

const Dhcp4Ns Dhcp4 = {.clear = dhcp4_clear,
                       .bind = dhcp4_bind,
                       .start = dhcp4_start,
                       .stop = dhcp4_stop,
                       .input = dhcp4_input,
                       .build = dhcp4_build,
                       .tick = dhcp4_tick,
                       .release = dhcp4_release,
                       .decline = dhcp4_decline,
                       .inform = dhcp4_inform};

IDEMIP_END_DECLS
