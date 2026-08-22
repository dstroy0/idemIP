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
 *
 * The message octets are never held. An arriving message is read where the caller left it and the
 * server's DUID, the address and the lifetimes are copied out of it before input returns, so nothing
 * here pins a descriptor.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/dhcp/dhcp6.h"
#include "src/endian.h"
#include "src/ip/ipv6_defines.h"

IDEMIP_BEGIN_DECLS

// The one definition, private to this TU. The sec 15 retransmission variables RT and the retry count
// sit beside the sec 21.4 T1 and T2 and the sec 21.6 lifetimes, all as millisecond deadlines against
// the clock tick hands in. The server's DUID is its own region; only its length is here.
typedef struct
{
    const IdemIpDhcp6Cfg *cfg;
    IdemIpDhcp6State state;
    uint8_t owed;  ///< the sec 7.3 message type build still has to write, 0 when none
    uint8_t phase; ///< where in the sec 15 schedule the exchange is
    uint8_t retries;
    uint8_t pref;             ///< sec 21.8 pref-value of the recorded server, 0 when none was sent
    uint8_t inf;              ///< which lifetimes came in as sec 7.7 infinity
    idemip_bool have_adv;     ///< a sec 18.2.9 usable Advertise is recorded
    uint16_t server_duid_len; ///< octets of the region at IDEMIP_DHCP6_OFF_SERVER_DUID
    uint16_t status_code;     ///< sec 21.13, what the last Reply carried
    uint32_t xid;             ///< sec 8, the low 24 bits
    uint32_t iaid;
    IdemIpMs now_ms;
    uint32_t tick_ms;         ///< the last reading of the caller's 32-bit millisecond clock
    uint32_t tick_hi;         ///< its high word, raised each time that reading wraps
    uint32_t rt_ms;           ///< sec 15 RT, the current retransmission timeout
    IdemIpMs retry_ms;        ///< when the message goes out again
    IdemIpMs started_ms;      ///< when the first message went out, which sec 21.9 elapsed-time counts from
    IdemIpMs t1_ms;           ///< the deadline RENEWING starts at
    IdemIpMs t2_ms;           ///< the deadline REBINDING starts at
    IdemIpMs valid_ms;        ///< the deadline the address stops being valid at
    uint32_t max_rt_ms;       ///< the sec 21.24 or sec 21.25 MRT this client runs with
    uint32_t max_rt_seen_s;   ///< the first value this exchange carried, 0 when none has
    idemip_bool max_rt_split; ///< two of them disagreed, so sec 18.2.9 holds the default
    uint32_t t1_s;
    uint32_t t2_s;
    uint32_t preferred_s;
    uint32_t valid_s;
    uint8_t addr[IDEMIP_IP6_ADDR_LEN]; ///< the sec 21.6 IPv6-address the lease assigned
} Dhcp6Ctx;

// No record of where the server answered from, which this held for three writes and no read. A
// client identifies its server by the sec 11.1 DUID, which server_duid_len and the DUID region hold
// and which every Request, Renew and Release puts back in a sec 21.3 Server Identifier option. It
// does not identify it by address: sec 21.12 has the server send the Server Unicast option "to
// indicate to the client that it is allowed to unicast messages to the server", and this client
// neither asks for nor parses that option, so every message it sends goes to
// All_DHCP_Relay_Agents_and_Servers whatever the last reply's Source Address was.

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_DHCP6_OFF_CTX, sizeof(Dhcp6Ctx), IDEMIP_DHCP6_BORROW, "dhcp6's context");

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

// Where an exchange sits in the sec 15 schedule. NEW has no transaction-id yet, DELAY is running the
// sec 18.2 first-message delay, and RUN has the first message out and RT ticking.
#define DHCP6_PHASE_NEW 0u
#define DHCP6_PHASE_DELAY 1u
#define DHCP6_PHASE_RUN 2u

// Which of the sec 7.7 lifetimes arrived as 0xffffffff.
#define DHCP6_INF_T1 0x01u
#define DHCP6_INF_T2 0x02u
#define DHCP6_INF_VALID 0x04u

// --- arithmetic ------------------------------------------------------------

// A value in 0 through @p limit. The mask is @p limit smeared up to the next power of two less one,
// and a draw past the limit is rejected in favor of the next rotation of the word (PLAN sec 3.4).
static uint32_t dhcp6_draw(uint32_t rand, uint32_t limit)
{
    if (limit == 0u)
    {
        return 0u;
    }
    uint32_t mask = limit;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
    uint32_t r = rand;
    for (uint8_t i = 0u; i < 8u; i++)
    {
        uint32_t v = r & mask;
        if (v <= limit)
        {
            return v;
        }
        r = (r >> 5) | (r << 27);
    }
    return limit >> 1;
}

// The largest x whose product with the widest draw still fits one word.
#define DHCP6_RAND_X_MAX (0xFFFFFFFFu / IDEMIP_DHCP6_RAND_K_MAX)

// The sec 15 RAND magnitude for @p x: (x * k) >> 10 with k drawn over 0 through
// IDEMIP_DHCP6_RAND_K_MAX, so it never passes 102/1024 of x and stays inside sec 15's tenth.
static uint32_t dhcp6_rand_mag(uint32_t x, uint32_t rand)
{
    // The product passes 32 bits once x is above about 42107 seconds, which a server may set through
    // SOL_MAX_RT or INF_MAX_RT, and a wrapped product is neither uniform nor inside sec 15's tenth.
    // x is held at the largest value the multiply carries, so the magnitude saturates there instead
    // and the arithmetic stays one word wide. The sign is applied after, by dhcp6_rand_apply.
    uint32_t capped = (x > DHCP6_RAND_X_MAX) ? (uint32_t)DHCP6_RAND_X_MAX : x;
    return (capped * dhcp6_draw(rand >> 1, IDEMIP_DHCP6_RAND_K_MAX)) >> IDEMIP_DHCP6_RAND_SHIFT;
}

// sec 15 puts RAND uniformly over -0.1 to +0.1, so the low bit of the word picks the side. Both sides
// saturate: a sum past the word or a difference below zero would wrap the interval to the far end of
// the range, which reads as a timer already due or one that never fires.
static uint32_t dhcp6_rand_apply(uint32_t base, uint32_t mag, uint32_t rand)
{
    // Neither saturation is measured: dhcp6_rand_mag draws the magnitude as a fraction of the base
    // with a numerator of at most IDEMIP_DHCP6_RAND_K_MAX over 1024, so it is at most about a tenth
    // of the base - never more than the base, and never more than the room left above a base that is
    // itself a millisecond count. They are written because sec 15 states RAND as a term applied to
    // whatever interval a caller is holding, and an interval that wrapped would read as a timer
    // already due or one that never fires.
    if ((rand & 1u) != 0u)
    {
        return (mag > (0xFFFFFFFFu - base)) ? 0xFFFFFFFFu : (base + mag); // GCOVR_EXCL_BR_LINE
    }
    return (mag > base) ? 0u : (base - mag); // GCOVR_EXCL_BR_LINE
}

// sec 15: RT for the first transmission is IRT + RAND*IRT. @p positive forces a magnitude of at least
// one and the additive side, which is sec 18.2.1's "the first RT MUST be selected to be strictly
// greater than IRT by choosing RAND to be strictly greater than 0".
static uint32_t dhcp6_first_rt(uint32_t irt_ms, uint32_t rand, idemip_bool positive)
{
    uint32_t mag = dhcp6_rand_mag(irt_ms, rand);
    if (positive)
    {
        return irt_ms + ((mag == 0u) ? 1u : mag);
    }
    return dhcp6_rand_apply(irt_ms, mag, rand);
}

// sec 15: RT for each later transmission is 2*RTprev + RAND*RTprev, then bounded by
// "if (RT > MRT) RT = MRT + RAND*MRT". An MRT of zero is sec 15's "no upper limit on the value of RT".
static uint32_t dhcp6_next_rt(uint32_t prev_ms, uint32_t mrt_ms, uint32_t rand)
{
    uint32_t rt = dhcp6_rand_apply(prev_ms << 1, dhcp6_rand_mag(prev_ms, rand), rand);
    if (mrt_ms != 0u && rt > mrt_ms)
    {
        rt = dhcp6_rand_apply(mrt_ms, dhcp6_rand_mag(mrt_ms, rand), rand);
    }
    return rt;
}

// sec 21.9: elapsed-time is "expressed in hundredths of a second", and "The client uses the value
// 0xffff to represent any elapsed-time values greater than the largest time value that can be
// represented". floor(ms/100) is the reciprocal multiply and shift below over that whole range.
static uint16_t dhcp6_elapsed_cs(IdemIpMs now, IdemIpMs started)
{
    IdemIpMs ms = now - started;
    if (ms >= (IdemIpMs)IDEMIP_DHCP6_ELAPSED_MAX_MS)
    {
        return 0xFFFFu;
    }
    return (uint16_t)(((uint64_t)ms * (uint64_t)IDEMIP_DHCP6_CS_RECIP) >> IDEMIP_DHCP6_CS_SHIFT);
}

// A sec 7.7 lifetime in seconds as a millisecond deadline on the 64-bit clock, so the whole 32-bit
// second range the field can name is representable and T1, T2 and the valid lifetime never collapse
// onto one instant.
static IdemIpMs dhcp6_deadline(IdemIpMs now, uint32_t seconds)
{
    return now + idemip_ms_from_s(seconds);
}

// The millisecond clock wraps, so a deadline is reached when the signed difference is not negative.
static idemip_bool dhcp6_reached(IdemIpMs now, IdemIpMs deadline)
{
    return (now >= deadline) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 8415 sec 7.1: "All_DHCP_Relay_Agents_and_Servers (ff02::1:2)".
static void dhcp6_all_agents(uint8_t *dst)
{
    memset(dst, 0, IDEMIP_IP6_ADDR_LEN);
    dst[0] = 0xffu;
    dst[1] = 0x02u;
    dst[13] = 0x01u;
    dst[15] = 0x02u;
}

// --- the sec 15 parameters of each sec 18.2 exchange -----------------------

// sec 7.3, the type each exchange transmits.
static uint8_t dhcp6_msg_for(uint8_t state)
{
    // gcov counts a switch's arms on the switch line, so the line is out of the measurement and the
    // reason is written at the default below. Every arm that does run keeps its own line count.
    switch (state) // GCOVR_EXCL_BR_LINE
    {
    case IDEMIP_DHCP6_SOLICITING:
        return (uint8_t)IDEMIP_DHCP6_SOLICIT;
    case IDEMIP_DHCP6_REQUESTING:
        return (uint8_t)IDEMIP_DHCP6_REQUEST;
    case IDEMIP_DHCP6_CONFIRMING:
        return (uint8_t)IDEMIP_DHCP6_CONFIRM;
    case IDEMIP_DHCP6_RENEWING:
        return (uint8_t)IDEMIP_DHCP6_RENEW;
    case IDEMIP_DHCP6_REBINDING:
        return (uint8_t)IDEMIP_DHCP6_REBIND;
    case IDEMIP_DHCP6_INFO_REQUESTING:
        return (uint8_t)IDEMIP_DHCP6_INFORMATION_REQUEST;
    case IDEMIP_DHCP6_RELEASING:
        return (uint8_t)IDEMIP_DHCP6_RELEASE;
    case IDEMIP_DHCP6_DECLINING:
        return (uint8_t)IDEMIP_DHCP6_DECLINE;
    // Every state that transmits is above, and the callers are dhcp6_arm_first, dhcp6_arm_again and
    // the sec 18.2.10 UseMulticast resend, all three of which run inside a running exchange. IDLE and
    // BOUND are answered before the tick arms anything, so this arm is unreachable and not measured.
    default:       // GCOVR_EXCL_LINE
        return 0u; // GCOVR_EXCL_LINE
    }
}

// IRT, from the sec 7.6 Table 1 value each sec 18.2 subsection names.
static uint32_t dhcp6_irt_ms(uint8_t state)
{
    // Not measured on this line, for the reason written at dhcp6_msg_for.
    switch (state) // GCOVR_EXCL_BR_LINE
    {
    case IDEMIP_DHCP6_SOLICITING:
        return IDEMIP_DHCP6_SOL_TIMEOUT_MS;
    case IDEMIP_DHCP6_REQUESTING:
        return IDEMIP_DHCP6_REQ_TIMEOUT_MS;
    case IDEMIP_DHCP6_CONFIRMING:
        return IDEMIP_DHCP6_CNF_TIMEOUT_MS;
    case IDEMIP_DHCP6_RENEWING:
        return IDEMIP_DHCP6_REN_TIMEOUT_MS;
    case IDEMIP_DHCP6_REBINDING:
        return IDEMIP_DHCP6_REB_TIMEOUT_MS;
    case IDEMIP_DHCP6_INFO_REQUESTING:
        return IDEMIP_DHCP6_INF_TIMEOUT_MS;
    case IDEMIP_DHCP6_RELEASING:
        return IDEMIP_DHCP6_REL_TIMEOUT_MS;
    case IDEMIP_DHCP6_DECLINING:
        return IDEMIP_DHCP6_DEC_TIMEOUT_MS;
    // As above: dhcp6_arm_first is the only caller and it arms an exchange that is already running.
    default:       // GCOVR_EXCL_LINE
        return 0u; // GCOVR_EXCL_LINE
    }
}

// MRT. sec 18.2.1 takes SOL_MAX_RT and sec 18.2.6 INF_MAX_RT from the running value, which sec 21.24
// and sec 21.25 let a server override. sec 18.2.7 and sec 18.2.8 name MRT 0, which sec 15 reads as no
// upper bound.
static uint32_t dhcp6_mrt_ms(uint8_t state, const Dhcp6Ctx *ctx)
{
    switch (state)
    {
    case IDEMIP_DHCP6_SOLICITING:
    case IDEMIP_DHCP6_INFO_REQUESTING:
        return ctx->max_rt_ms;
    case IDEMIP_DHCP6_REQUESTING:
        return IDEMIP_DHCP6_REQ_MAX_RT_MS;
    case IDEMIP_DHCP6_CONFIRMING:
        return IDEMIP_DHCP6_CNF_MAX_RT_MS;
    case IDEMIP_DHCP6_RENEWING:
        return IDEMIP_DHCP6_REN_MAX_RT_MS;
    case IDEMIP_DHCP6_REBINDING:
        return IDEMIP_DHCP6_REB_MAX_RT_MS;
    default:
        return 0u;
    }
}

// MRC. sec 18.2.2 takes REQ_MAX_RC, sec 18.2.7 REL_MAX_RC and sec 18.2.8 DEC_MAX_RC; every other
// exchange names 0, which sec 15 reads as no bound on the count.
static uint8_t dhcp6_mrc(uint8_t state)
{
    switch (state)
    {
    case IDEMIP_DHCP6_REQUESTING:
        return IDEMIP_DHCP6_REQ_MAX_RC;
    case IDEMIP_DHCP6_RELEASING:
        return IDEMIP_DHCP6_REL_MAX_RC;
    case IDEMIP_DHCP6_DECLINING:
        return IDEMIP_DHCP6_DEC_MAX_RC;
    default:
        return 0u;
    }
}

// The first-message delay. sec 18.2.1 SHOULD delay a first Solicit by 0 to SOL_MAX_DELAY, sec 18.2.3
// MUST delay a first Confirm by 0 to CNF_MAX_DELAY and sec 18.2.6 MUST delay a first
// Information-request by 0 to INF_MAX_DELAY. No other exchange names one.
static uint32_t dhcp6_max_delay_ms(uint8_t state)
{
    switch (state)
    {
    case IDEMIP_DHCP6_SOLICITING:
        return IDEMIP_DHCP6_SOL_MAX_DELAY_MS;
    case IDEMIP_DHCP6_CONFIRMING:
        return IDEMIP_DHCP6_CNF_MAX_DELAY_MS;
    case IDEMIP_DHCP6_INFO_REQUESTING:
        return IDEMIP_DHCP6_INF_MAX_DELAY_MS;
    default:
        return 0u;
    }
}

// --- options -------------------------------------------------------------

// sec 21.1, Figure 12: option-code, option-len, then option-len octets. A member whose option-len runs
// past the region is malformed and the walk stops.
static const uint8_t *dhcp6_find(const uint8_t *buf, size_t len, uint16_t code, uint16_t *dlen)
{
    size_t at = 0u;
    while (at + IDEMIP_DHCP6_OPT_HDR_LEN <= len)
    {
        uint16_t c = idemip_rd16(buf + at + IDEMIP_DHCP6_OPT_OFF_CODE);
        uint16_t l = idemip_rd16(buf + at + IDEMIP_DHCP6_OPT_OFF_LEN);
        size_t next = at + IDEMIP_DHCP6_OPT_HDR_LEN + (size_t)l;
        if (next > len)
        {
            return NULL;
        }
        if (c == code)
        {
            *dlen = l;
            return buf + at + IDEMIP_DHCP6_OPT_OFF_DATA;
        }
        at = next;
    }
    return NULL;
}

// Every option-len in the region stays inside it. sec 16 keeps a client from discarding a message over
// an option it does not know, so only a length that runs off the end fails here.
static idemip_bool dhcp6_opts_ok(const uint8_t *buf, size_t len)
{
    size_t at = 0u;
    while (at + IDEMIP_DHCP6_OPT_HDR_LEN <= len)
    {
        size_t next = at + IDEMIP_DHCP6_OPT_HDR_LEN + (size_t)idemip_rd16(buf + at + IDEMIP_DHCP6_OPT_OFF_LEN);
        if (next > len)
        {
            return IDEMIP_FALSE;
        }
        at = next;
    }
    return IDEMIP_TRUE;
}

// One option written at @p at, with @p len octets reserved for its data and @p data copied in when it
// is given. Returns the offset past it, or 0 when the buffer is short; a 0 handed in comes back out,
// so a chain of these carries the one failure to the end.
static size_t dhcp6_put(uint8_t *out, size_t cap, size_t at, uint16_t code, const uint8_t *data, uint16_t len)
{
    if (at == 0u || at + IDEMIP_DHCP6_OPT_HDR_LEN + (size_t)len > cap)
    {
        return 0u;
    }
    idemip_wr16(out + at + IDEMIP_DHCP6_OPT_OFF_CODE, code);
    idemip_wr16(out + at + IDEMIP_DHCP6_OPT_OFF_LEN, len);
    if (len != 0u && data != NULL)
    {
        memcpy(out + at + IDEMIP_DHCP6_OPT_OFF_DATA, data, len);
    }
    return at + IDEMIP_DHCP6_OPT_HDR_LEN + (size_t)len;
}

// sec 21.4, Figure 15: IAID, T1, T2, then IA_NA-options. sec 21.4 has a client send T1 and T2 as 0,
// and sec 21.6 has it send both lifetimes as 0, so the held address rides in an IAADDR of zeroed
// lifetimes when @p with_addr asks for it.
static size_t dhcp6_put_ia_na(uint8_t *work, uint8_t *out, size_t cap, size_t at, idemip_bool with_addr)
{
    const Dhcp6Ctx *ctx = DHCP6_CTX(work);
    uint16_t body = IDEMIP_DHCP6_IA_NA_FIXED_LEN;
    if (with_addr)
    {
        body = (uint16_t)(body + IDEMIP_DHCP6_OPT_HDR_LEN + IDEMIP_DHCP6_IAADDR_FIXED_LEN);
    }
    size_t past = dhcp6_put(out, cap, at, IDEMIP_DHCP6_OPT_IA_NA, NULL, body);
    if (past == 0u)
    {
        return 0u;
    }
    uint8_t *ia = out + at + IDEMIP_DHCP6_OPT_OFF_DATA;
    idemip_wr32(ia, ctx->iaid);
    idemip_wr32(ia + 4u, 0u);
    idemip_wr32(ia + 8u, 0u);
    if (with_addr)
    {
        uint8_t *sub = ia + IDEMIP_DHCP6_IA_NA_FIXED_LEN;
        idemip_wr16(sub + IDEMIP_DHCP6_OPT_OFF_CODE, IDEMIP_DHCP6_OPT_IAADDR);
        idemip_wr16(sub + IDEMIP_DHCP6_OPT_OFF_LEN, IDEMIP_DHCP6_IAADDR_FIXED_LEN);
        uint8_t *a = sub + IDEMIP_DHCP6_OPT_OFF_DATA;
        memcpy(a, ctx->addr, IDEMIP_IP6_ADDR_LEN);
        idemip_wr32(a + IDEMIP_IP6_ADDR_LEN, 0u);
        idemip_wr32(a + IDEMIP_IP6_ADDR_LEN + 4u, 0u);
    }
    return past;
}

// A lease is held once the sec 21.6 IPv6-address is not the unspecified address.
static idemip_bool dhcp6_has_addr(const Dhcp6Ctx *ctx)
{
    return (idemip_bool)!idemip_bytes_zero(ctx->addr, IDEMIP_IP6_ADDR_LEN);
}

// --- building ------------------------------------------------------------

// sec 8, Figure 2, then the sec 21 options each sec 18.2 exchange names. Returns the octets written,
// or 0 when the caller's buffer cannot carry them.
static size_t dhcp6_write(uint8_t *work, uint8_t type, uint8_t *out, size_t cap)
{
    const Dhcp6Ctx *ctx = DHCP6_CTX(work);

    // sec 8: msg-type is one octet and transaction-id is the three that follow it.
    out[IDEMIP_DHCP6_MSG_OFF_TYPE] = type;
    out[IDEMIP_DHCP6_MSG_OFF_XID] = (uint8_t)(ctx->xid >> 16);
    out[IDEMIP_DHCP6_MSG_OFF_XID + 1u] = (uint8_t)(ctx->xid >> 8);
    out[IDEMIP_DHCP6_MSG_OFF_XID + 2u] = (uint8_t)ctx->xid;
    size_t at = IDEMIP_DHCP6_MSG_OFF_OPTIONS;

    // sec 21.3. sec 18.2.2, sec 18.2.4, sec 18.2.7 and sec 18.2.8 each make the Server Identifier a
    // MUST; sec 16.2, sec 16.5, sec 16.7 and sec 16.12 have a server discard the message when the
    // other exchanges carry one.
    idemip_bool wants_server = (type == (uint8_t)IDEMIP_DHCP6_REQUEST) || (type == (uint8_t)IDEMIP_DHCP6_RENEW) ||
                               (type == (uint8_t)IDEMIP_DHCP6_RELEASE) || (type == (uint8_t)IDEMIP_DHCP6_DECLINE);
    if (wants_server)
    {
        // sec 18.2.2 and sec 18.2.4 reach REQUESTING and RENEWING only through an Advertise or a Reply
        // whose Server Identifier was recorded, and sec 18.2.7 and sec 18.2.8 refuse a Release or a
        // Decline without one, so this holds a case the state machine does not produce.
        if (ctx->server_duid_len == 0u) // GCOVR_EXCL_BR_LINE
        {
            return 0u; // GCOVR_EXCL_LINE
        }
        at = dhcp6_put(out, cap, at, IDEMIP_DHCP6_OPT_SERVERID, DHCP6_SERVER_DUID(work), ctx->server_duid_len);
    }

    // sec 21.2, the client's own DUID. A MUST in every exchange sec 18.2 names but the
    // Information-request of sec 18.2.6, where it is a SHOULD, and it goes out there too.
    at = dhcp6_put(out, cap, at, IDEMIP_DHCP6_OPT_CLIENTID, ctx->cfg->duid, ctx->cfg->duid_len);

    // sec 21.9, hundredths of a second since the first message of this exchange went out.
    at = dhcp6_put(out, cap, at, IDEMIP_DHCP6_OPT_ELAPSED_TIME, NULL, IDEMIP_DHCP6_ELAPSED_LEN);
    if (at == 0u)
    {
        return 0u;
    }
    idemip_wr16(out + at - IDEMIP_DHCP6_ELAPSED_LEN, dhcp6_elapsed_cs(ctx->now_ms, ctx->started_ms));

    // sec 21.4. sec 16.12 has a server discard an Information-request that carries an IA option, so
    // the IA_NA goes in every other exchange. sec 18.2.1 makes an address hint a MAY and leaves the
    // Solicit's IA_NA empty; sec 18.2.3, sec 18.2.4, sec 18.2.7 and sec 18.2.8 each carry the address.
    if (type != (uint8_t)IDEMIP_DHCP6_INFORMATION_REQUEST)
    {
        // Not measured on the second: the exchanges that reach here past the Solicit are the ones
        // sec 18.2.3 through sec 18.2.8 name, and each is entered from a Reply or an Advertise whose
        // IA Address was recorded - the NoBinding Request of sec 18.2.10.1 included, which keeps the
        // lease it is recovering. It is written because sec 18.2.1 leaves the Solicit's IA_NA empty
        // and the same option is built for both.
        idemip_bool with_addr = (type != (uint8_t)IDEMIP_DHCP6_SOLICIT) && // GCOVR_EXCL_BR_LINE
                                dhcp6_has_addr(ctx);
        at = dhcp6_put_ia_na(work, out, cap, at, with_addr);
    }

    // sec 21.7. sec 21.24 makes the SOL_MAX_RT code a MUST in a Solicit's ORO and sec 18.2.2 and
    // sec 18.2.4 ask for it too; sec 21.25 makes INF_MAX_RT and sec 21.23 the Information Refresh Time
    // a MUST in an Information-request's, and sec 21.23 forbids that code anywhere else. RFC 3646
    // sec 3 and sec 4 are the two this client reads back out of a Reply.
    idemip_bool wants_oro = (type == (uint8_t)IDEMIP_DHCP6_SOLICIT) || (type == (uint8_t)IDEMIP_DHCP6_REQUEST) ||
                            (type == (uint8_t)IDEMIP_DHCP6_RENEW) || (type == (uint8_t)IDEMIP_DHCP6_REBIND) ||
                            (type == (uint8_t)IDEMIP_DHCP6_INFORMATION_REQUEST);
    if (wants_oro)
    {
        idemip_bool info = (type == (uint8_t)IDEMIP_DHCP6_INFORMATION_REQUEST);
        uint16_t codes = info ? 4u : 3u;
        uint16_t olen = (uint16_t)(codes << 1u);
        at = dhcp6_put(out, cap, at, IDEMIP_DHCP6_OPT_ORO, NULL, olen);
        if (at == 0u)
        {
            return 0u;
        }
        uint8_t *o = out + at - olen;
        if (info)
        {
            idemip_wr16(o, IDEMIP_DHCP6_OPT_INF_MAX_RT);
            idemip_wr16(o + 2u, IDEMIP_DHCP6_OPT_INFO_REFRESH);
            o += 4u;
        }
        else
        {
            idemip_wr16(o, IDEMIP_DHCP6_OPT_SOL_MAX_RT);
            o += 2u;
        }
        idemip_wr16(o, IDEMIP_DHCP6_OPT_DNS_SERVERS);
        idemip_wr16(o + 2u, IDEMIP_DHCP6_OPT_DOMAIN_LIST);
    }

    // sec 21.14, option-len 0. sec 18.2.1 puts it in a Solicit when the client wants the two-message
    // exchange.
    if (type == (uint8_t)IDEMIP_DHCP6_SOLICIT && ctx->cfg->rapid_commit)
    {
        at = dhcp6_put(out, cap, at, IDEMIP_DHCP6_OPT_RAPID_COMMIT, NULL, 0u);
    }
    return at;
}

// --- the state machine ---------------------------------------------------

// The context's view of the exchange and the lease, out to the operand block the caller reads.
static void dhcp6_publish(uint8_t *work)
{
    Dhcp6Io *io = DHCP6_IO(work);
    const Dhcp6Ctx *ctx = DHCP6_CTX(work);
    io->state = ctx->state;
    io->xid = ctx->xid;
    io->iaid = ctx->iaid;
    io->status_code = ctx->status_code;
    io->preferred_s = ctx->preferred_s;
    io->valid_s = ctx->valid_s;
    io->t1_s = ctx->t1_s;
    io->t2_s = ctx->t2_s;
    memcpy(io->addr, ctx->addr, IDEMIP_IP6_ADDR_LEN);
}

// The lease and the server it came from, dropped.
static void dhcp6_forget_lease(uint8_t *work)
{
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    memset(ctx->addr, 0, IDEMIP_IP6_ADDR_LEN);
    memset(DHCP6_SERVER_DUID(work), 0, IDEMIP_DHCP6_DUID_MAX);
    ctx->server_duid_len = 0u;
    ctx->preferred_s = 0u;
    ctx->valid_s = 0u;
    ctx->t1_s = 0u;
    ctx->t2_s = 0u;
    ctx->t1_ms = 0;
    ctx->t2_ms = 0;
    ctx->valid_ms = 0;
    ctx->inf = 0u;
    ctx->pref = 0u;
    ctx->have_adv = IDEMIP_FALSE;
}

// A fresh exchange. rt_ms of 0 and phase NEW are what the arming tick reads as "no transaction-id and
// no first message yet", so sec 16.1's new random transaction-id is drawn there.
static void dhcp6_begin(Dhcp6Ctx *ctx, uint8_t state)
{
    ctx->state = (IdemIpDhcp6State)state;
    ctx->phase = DHCP6_PHASE_NEW;
    ctx->owed = 0u;
    ctx->retries = 0u;
    ctx->rt_ms = 0u;
    ctx->retry_ms = ctx->now_ms;
    ctx->started_ms = ctx->now_ms;
    ctx->status_code = 0u;
}

// sec 21.4 and sec 21.6 in a Reply: T1 and T2 "are the number of seconds until T1 and T2 and are
// calculated since reception of the message", and the two lifetimes are "the number of seconds
// remaining in each lifetime". sec 7.7's 0xffffffff is infinity and gets no deadline.
static void dhcp6_arm_lease(Dhcp6Ctx *ctx)
{
    ctx->inf = 0u;
    if (ctx->t1_s == IDEMIP_DHCP6_INFINITY)
    {
        ctx->inf |= DHCP6_INF_T1;
        ctx->t1_ms = ctx->now_ms;
    }
    else
    {
        ctx->t1_ms = dhcp6_deadline(ctx->now_ms, ctx->t1_s);
    }
    if (ctx->t2_s == IDEMIP_DHCP6_INFINITY)
    {
        ctx->inf |= DHCP6_INF_T2;
        ctx->t2_ms = ctx->now_ms;
    }
    else
    {
        ctx->t2_ms = dhcp6_deadline(ctx->now_ms, ctx->t2_s);
    }
    if (ctx->valid_s == IDEMIP_DHCP6_INFINITY)
    {
        ctx->inf |= DHCP6_INF_VALID;
        ctx->valid_ms = ctx->now_ms;
    }
    else
    {
        ctx->valid_ms = dhcp6_deadline(ctx->now_ms, ctx->valid_s);
    }
}

// sec 21.24 and sec 21.25: an override is taken only when "60 <= value <= 86400", and is otherwise
// ignored.
static void dhcp6_take_max_rt(Dhcp6Ctx *ctx, const uint8_t *opts, size_t olen)
{
    uint16_t dlen = 0u;
    uint16_t code = ctx->cfg->stateless ? IDEMIP_DHCP6_OPT_INF_MAX_RT : IDEMIP_DHCP6_OPT_SOL_MAX_RT;
    const uint8_t *d = dhcp6_find(opts, olen, code, &dlen);
    if (d == NULL || dlen != IDEMIP_DHCP6_MAX_RT_LEN)
    {
        return;
    }
    uint32_t s = idemip_rd32(d);
    if (s < IDEMIP_DHCP6_MAX_RT_MIN_S || s > IDEMIP_DHCP6_MAX_RT_MAX_S)
    {
        return;
    }
    // sec 18.2.9: "A client SHOULD only update its SOL_MAX_RT and INF_MAX_RT values if all received
    // Advertise messages that contained the corresponding option specified the same value; otherwise,
    // it should use the default value." The first value this exchange carried is remembered, and a
    // later one that differs puts the default back for the rest of it.
    if (ctx->max_rt_split)
    {
        return;
    }
    if (ctx->max_rt_seen_s != 0u && ctx->max_rt_seen_s != s)
    {
        ctx->max_rt_split = IDEMIP_TRUE;
        ctx->max_rt_ms = ctx->cfg->stateless ? IDEMIP_DHCP6_INF_MAX_RT_MS : IDEMIP_DHCP6_SOL_MAX_RT_MS;
        return;
    }
    ctx->max_rt_seen_s = s;
    ctx->max_rt_ms = s * 1000u;
}

// sec 21.3, the server's DUID out of the message and into its own region. sec 11.1 bounds it at
// "at least 1 octet and at most 128 octets" behind a 2-octet type code.
static idemip_bool dhcp6_take_server_duid(uint8_t *work, const uint8_t *opts, size_t olen)
{
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    uint16_t dlen = 0u;
    const uint8_t *d = dhcp6_find(opts, olen, IDEMIP_DHCP6_OPT_SERVERID, &dlen);
    // Not measured on the first: sec 16.10 has clients "discard any received Reply message" where "the
    // message does not include a Server Identifier option", and sec 16.3 says the same of an
    // Advertise, both of which idemip_dhcp6_input takes before any of this runs - so the option is
    // there by the time it is read for its DUID. It is written because this reads the option itself
    // rather than the finding that it exists.
    if (d == NULL || dlen < 3u || dlen > IDEMIP_DHCP6_DUID_MAX) // GCOVR_EXCL_BR_LINE
    {
        return IDEMIP_FALSE;
    }
    memcpy(DHCP6_SERVER_DUID(work), d, dlen);
    ctx->server_duid_len = dlen;
    return IDEMIP_TRUE;
}

// sec 16.3 and sec 16.10: a client discards a message whose Client Identifier does not carry its own
// DUID. sec 11.1 has DUIDs compared for equality and nothing else.
static idemip_bool dhcp6_client_id_matches(const Dhcp6Ctx *ctx, const uint8_t *opts, size_t olen)
{
    uint16_t dlen = 0u;
    const uint8_t *d = dhcp6_find(opts, olen, IDEMIP_DHCP6_OPT_CLIENTID, &dlen);
    if (d == NULL || dlen != ctx->cfg->duid_len)
    {
        return IDEMIP_FALSE;
    }
    return (idemip_bytes_eq(d, ctx->cfg->duid, dlen)) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// sec 21.13: "If the Status Code option does not appear in a message in which the option could appear,
// the status of the message is assumed to be Success."
static uint16_t dhcp6_status_of(const uint8_t *opts, size_t olen)
{
    uint16_t dlen = 0u;
    const uint8_t *d = dhcp6_find(opts, olen, IDEMIP_DHCP6_OPT_STATUS_CODE, &dlen);
    if (d == NULL || dlen < IDEMIP_DHCP6_STATUS_LEN)
    {
        return (uint16_t)IDEMIP_DHCP6_STATUS_SUCCESS;
    }
    return idemip_rd16(d);
}

// RFC 3646 sec 3: the DNS Recursive Name Server option carries one 16-octet address per server and its
// "option-len ... must be a multiple of 16". The addresses stay in the caller's message octets.
static void dhcp6_take_dns(uint8_t *work, const uint8_t *opts, size_t olen)
{
    Dhcp6Io *io = DHCP6_IO(work);
    uint16_t dlen = 0u;
    const uint8_t *d = dhcp6_find(opts, olen, IDEMIP_DHCP6_OPT_DNS_SERVERS, &dlen);
    if (d == NULL || dlen == 0u || (dlen & (IDEMIP_IP6_ADDR_LEN - 1u)) != 0u)
    {
        return;
    }
    uint16_t n = (uint16_t)(dlen >> 4u);
    io->dns = d;
    // Not measured: 256 addresses is 4096 octets of one option, and sec 21.1 gives an option a
    // 16-bit length inside a datagram this client takes at IDEMIP_DHCP6_MSG_MAX. The clamp is written
    // because the count is reported in one octet and a wrapped count would name the wrong servers.
    io->dns_count = (n > 0xFFu) ? 0xFFu : (uint8_t)n; // GCOVR_EXCL_BR_LINE
}

// sec 21.23: the refresh time a stateless client holds until its next Information-request. "If the
// Reply to an Information-request message does not contain this option, the client MUST behave as if
// the option with the value IRT_DEFAULT was provided", and the value is never under IRT_MINIMUM.
static uint32_t dhcp6_take_info_refresh(const uint8_t *opts, size_t olen)
{
    uint16_t dlen = 0u;
    const uint8_t *d = dhcp6_find(opts, olen, IDEMIP_DHCP6_OPT_INFO_REFRESH, &dlen);
    if (d == NULL || dlen != IDEMIP_DHCP6_INFO_REFRESH_LEN)
    {
        return IDEMIP_DHCP6_IRT_DEFAULT_S;
    }
    uint32_t s = idemip_rd32(d);
    if (s == IDEMIP_DHCP6_INFINITY)
    {
        return s;
    }
    return (s < IDEMIP_DHCP6_IRT_MINIMUM_S) ? IDEMIP_DHCP6_IRT_MINIMUM_S : s;
}

// The sec 21.4 IA_NA this client's IAID names, and the sec 21.6 IAADDR inside it. sec 21.4 discards an
// IA_NA whose T1 is past T2 with both nonzero; sec 18.2.10.1 discards a lease of valid lifetime 0; and
// sec 21.6 discards an address "for which the preferred lifetime is greater than the valid lifetime".
// sec 14.2 has the client pick T1 and T2 itself when the server sent 0.
static idemip_bool dhcp6_take_lease(uint8_t *work, const uint8_t *opts, size_t olen)
{
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    uint16_t dlen = 0u;
    const uint8_t *ia = dhcp6_find(opts, olen, IDEMIP_DHCP6_OPT_IA_NA, &dlen);
    if (ia == NULL || dlen < IDEMIP_DHCP6_IA_NA_FIXED_LEN)
    {
        return IDEMIP_FALSE;
    }
    if (idemip_rd32(ia) != ctx->iaid)
    {
        return IDEMIP_FALSE;
    }
    uint32_t t1 = idemip_rd32(ia + 4u);
    uint32_t t2 = idemip_rd32(ia + 8u);
    if (t1 != 0u && t2 != 0u && t1 > t2)
    {
        return IDEMIP_FALSE;
    }

    const uint8_t *sub = ia + IDEMIP_DHCP6_IA_NA_FIXED_LEN;
    size_t sublen = (size_t)dlen - IDEMIP_DHCP6_IA_NA_FIXED_LEN;
    // sec 21.4: "The status of any operations involving this IA_NA is indicated in a Status Code option
    // ... in the IA_NA-options field", which is where NoAddrsAvail of sec 21.13 Table 3 arrives.
    uint16_t ia_status = dhcp6_status_of(sub, sublen);
    if (ia_status != (uint16_t)IDEMIP_DHCP6_STATUS_SUCCESS)
    {
        ctx->status_code = ia_status;
        return IDEMIP_FALSE;
    }

    uint16_t alen = 0u;
    const uint8_t *a = dhcp6_find(sub, sublen, IDEMIP_DHCP6_OPT_IAADDR, &alen);
    if (a == NULL || alen < IDEMIP_DHCP6_IAADDR_FIXED_LEN)
    {
        return IDEMIP_FALSE;
    }
    uint32_t preferred = idemip_rd32(a + IDEMIP_IP6_ADDR_LEN);
    uint32_t valid = idemip_rd32(a + IDEMIP_IP6_ADDR_LEN + 4u);
    if (valid == 0u || preferred > valid)
    {
        return IDEMIP_FALSE;
    }

    memcpy(ctx->addr, a, IDEMIP_IP6_ADDR_LEN);
    ctx->preferred_s = preferred;
    ctx->valid_s = valid;
    // sec 14.2: T1 or T2 of 0 leaves the time to the client, which "MUST NOT transmit immediately".
    // sec 21.4 recommends 0.5 and 0.8 of the shortest preferred lifetime, and an infinite preferred
    // lifetime makes both infinite. Half is x >> 1 exactly; four fifths is taken as
    // (x >> 1) + (x >> 2) + (x >> 5), which is 0.78125 and so never later than the recommendation.
    if (t1 == 0u || t2 == 0u)
    {
        if (preferred == IDEMIP_DHCP6_INFINITY)
        {
            if (t1 == 0u)
            {
                t1 = IDEMIP_DHCP6_INFINITY;
            }
            if (t2 == 0u)
            {
                t2 = IDEMIP_DHCP6_INFINITY;
            }
        }
        else
        {
            if (t1 == 0u)
            {
                t1 = preferred >> 1;
            }
            if (t2 == 0u)
            {
                t2 = (preferred >> 1) + (preferred >> 2) + (preferred >> 5);
            }
            // sec 14.1 bounds the transmission rate, so a client-picked time of zero takes the
            // sec 7.6 REN_TIMEOUT instead of going out at once.
            if (t1 == 0u)
            {
                t1 = 10u;
            }
            if (t2 == 0u)
            {
                t2 = 10u;
            }
        }
    }
    ctx->t1_s = t1;
    ctx->t2_s = t2;
    dhcp6_arm_lease(ctx);
    return IDEMIP_TRUE;
}

// sec 18.2.9: an Advertise is recorded when it carries an address, "Those Advertise messages with the
// highest server preference value SHOULD be preferred over all other Advertise messages", and sec 21.8
// gives an Advertise with no Preference option a preference of 0.
static idemip_bool dhcp6_take_advertise(uint8_t *work, const uint8_t *opts, size_t olen)
{
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    uint16_t plen = 0u;
    const uint8_t *p = dhcp6_find(opts, olen, IDEMIP_DHCP6_OPT_PREFERENCE, &plen);
    uint8_t pref = (p != NULL && plen >= IDEMIP_DHCP6_PREFERENCE_LEN) ? p[0] : 0u;
    if (ctx->have_adv && pref <= ctx->pref)
    {
        return IDEMIP_FALSE;
    }
    // The recorded server survives a worse Advertise, so nothing is written until both the sec 21.3
    // DUID and the sec 21.4 IA_NA of this one have passed.
    uint16_t slen = 0u;
    const uint8_t *sid = dhcp6_find(opts, olen, IDEMIP_DHCP6_OPT_SERVERID, &slen);
    // Not measured on the first, for the reason written at dhcp6_take_server_duid.
    if (sid == NULL || slen < 3u || slen > IDEMIP_DHCP6_DUID_MAX) // GCOVR_EXCL_BR_LINE
    {
        return IDEMIP_FALSE;
    }
    if (!dhcp6_take_lease(work, opts, olen))
    {
        return IDEMIP_FALSE;
    }
    memcpy(DHCP6_SERVER_DUID(work), sid, slen);
    ctx->server_duid_len = slen;
    ctx->pref = pref;
    ctx->have_adv = IDEMIP_TRUE;
    return IDEMIP_TRUE;
}

// --- the entries -----------------------------------------------------------

// Every byte of the borrow, the operand block and the DUID region included, which leaves the state at
// zero: IDLE, running no exchange.
void idemip_dhcp6_clear(uint8_t *work)
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
void idemip_dhcp6_bind(uint8_t *work)
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
    // sec 7.6 Table 1 until sec 21.24 or sec 21.25 overrides it.
    ctx->max_rt_ms = cfg->stateless ? IDEMIP_DHCP6_INF_MAX_RT_MS : IDEMIP_DHCP6_SOL_MAX_RT_MS;
    io->state = IDEMIP_DHCP6_IDLE;
    io->iaid = cfg->iaid;
    io->status = IDEMIP_OK;
}

// sec 18.2.1 Solicit for a stateful client, sec 18.2.6 Information-request for a stateless one. The
// transaction-id sec 16.1 asks for and the word the first-message delay is drawn from both arrive as
// operands, so this entry stays a function of the borrow. ERR from any state but IDLE: an exchange is
// already running and repeating the call cannot change that.
void idemip_dhcp6_start(uint8_t *work)
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
    if (ctx->state != IDEMIP_DHCP6_IDLE)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    ctx->now_ms = idemip_ms_extend(&ctx->tick_ms, &ctx->tick_hi, io->start_args.now_ms);
    uint8_t state = ctx->cfg->stateless ? (uint8_t)IDEMIP_DHCP6_INFO_REQUESTING : (uint8_t)IDEMIP_DHCP6_SOLICITING;
    dhcp6_begin(ctx, state);
    // sec 16.1: "A client SHOULD generate a random number that cannot easily be guessed or predicted
    // to use as the transaction ID", and sec 8 holds it in three octets.
    ctx->xid = io->start_args.xid & IDEMIP_DHCP6_XID_MASK;
    // sec 18.2.1 and sec 18.2.6: the first message is delayed by "a random amount of time between 0
    // and" the exchange's MAX_DELAY.
    ctx->retry_ms = ctx->now_ms + dhcp6_draw(io->start_args.rand, dhcp6_max_delay_ms(state));
    ctx->phase = DHCP6_PHASE_DELAY;
    io->status = IDEMIP_OK;
    dhcp6_publish(work);
}

// sec 18.2 names no stop, so this is the unit's off switch: the running exchange ends and no lease is
// held. Idempotent, so an already-idle client reports OK.
void idemip_dhcp6_stop(uint8_t *work)
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
    dhcp6_forget_lease(work);
    ctx->state = IDEMIP_DHCP6_IDLE;
    ctx->phase = DHCP6_PHASE_NEW;
    ctx->owed = 0u;
    ctx->retries = 0u;
    ctx->rt_ms = 0u;
    ctx->status_code = 0u;
    ctx->max_rt_seen_s = 0u;
    ctx->max_rt_split = IDEMIP_FALSE;
    ctx->max_rt_ms = ctx->cfg->stateless ? IDEMIP_DHCP6_INF_MAX_RT_MS : IDEMIP_DHCP6_SOL_MAX_RT_MS;
    io->msg_type = 0u;
    io->len = 0u;
    io->dns = NULL;
    io->dns_count = 0u;
    io->status = IDEMIP_OK;
    dhcp6_publish(work);
}

// sec 18.2.10.1: a Reply that assigns leases takes the client to BOUND with T1 and T2 running.
static void dhcp6_enter_bound(uint8_t *work)
{
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    ctx->state = IDEMIP_DHCP6_BOUND;
    ctx->phase = DHCP6_PHASE_NEW;
    ctx->owed = 0u;
    ctx->retries = 0u;
    ctx->rt_ms = 0u;
}

// One received message, validated as sec 16 requires and acted on per sec 18.2.9 and sec 18.2.10. A
// message the RFC has the client discard is ERR: the same octets can never be accepted, so there is
// nothing for a caller to come back for.
void idemip_dhcp6_input(uint8_t *work)
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
    io->status = IDEMIP_ERR;
    io->msg_type = 0u;
    io->dns = NULL;
    io->dns_count = 0u;

    const uint8_t *msg = io->input_args.msg;
    size_t len = io->input_args.len;
    if (msg == NULL || io->input_args.src == NULL || len < IDEMIP_DHCP6_FIXED_LEN)
    {
        return;
    }
    const uint8_t *opts = msg + IDEMIP_DHCP6_MSG_OFF_OPTIONS;
    size_t olen = len - IDEMIP_DHCP6_FIXED_LEN;
    if (!dhcp6_opts_ok(opts, olen))
    {
        return;
    }

    uint8_t type = msg[IDEMIP_DHCP6_MSG_OFF_TYPE];
    io->msg_type = type;
    // sec 16.2 and sec 16.4 through sec 16.14: the only types a client does not discard outright are
    // Advertise, Reply and Reconfigure. sec 16.11 has a client discard a Reconfigure that "does not
    // include authentication ... or fails authentication validation", and this client implements none,
    // so every Reconfigure is discarded here.
    if (type != (uint8_t)IDEMIP_DHCP6_ADVERTISE && type != (uint8_t)IDEMIP_DHCP6_REPLY)
    {
        return;
    }
    // sec 16.3 and sec 16.10: the transaction-id must match the one the client sent.
    uint32_t xid = ((uint32_t)msg[IDEMIP_DHCP6_MSG_OFF_XID] << 16) |
                   ((uint32_t)msg[IDEMIP_DHCP6_MSG_OFF_XID + 1u] << 8) | (uint32_t)msg[IDEMIP_DHCP6_MSG_OFF_XID + 2u];
    if (ctx->state == IDEMIP_DHCP6_IDLE || ctx->state == IDEMIP_DHCP6_BOUND || xid != ctx->xid)
    {
        return;
    }
    // sec 16.3 and sec 16.10: both need a Server Identifier, and both need a Client Identifier that
    // carries this client's DUID, since every message this client sends includes one.
    uint16_t dlen = 0u;
    if (dhcp6_find(opts, olen, IDEMIP_DHCP6_OPT_SERVERID, &dlen) == NULL)
    {
        return;
    }
    if (!dhcp6_client_id_matches(ctx, opts, olen))
    {
        return;
    }

    // sec 18.2.9 and sec 18.2.10: the SOL_MAX_RT and INF_MAX_RT options are processed "even if the
    // message contains a Status Code option indicating a failure", and even when the message is then
    // discarded.
    dhcp6_take_max_rt(ctx, opts, olen);
    uint16_t status = dhcp6_status_of(opts, olen);

    if (type == (uint8_t)IDEMIP_DHCP6_ADVERTISE)
    {
        // sec 16.3 has a client discard an Advertise only on the four conditions checked above, and
        // sec 18.2.9 has it ignore one that carries no address. A Solicit is the only exchange an
        // Advertise answers.
        if (ctx->state != IDEMIP_DHCP6_SOLICITING)
        {
            return;
        }
        ctx->status_code = status;
        if (!dhcp6_take_advertise(work, opts, olen))
        {
            dhcp6_publish(work);
            return;
        }
        // sec 18.2.1: with a Preference of 255 "the client immediately begins a client-initiated message
        // exchange ... by sending a Request message to the server from which the Advertise message was
        // received", and past the first RT it "terminates the retransmission process as soon as it
        // receives any valid Advertise message".
        if (ctx->pref == IDEMIP_DHCP6_PREF_IMMEDIATE || ctx->retries > 1u)
        {
            dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_REQUESTING);
        }
        io->status = IDEMIP_OK;
        dhcp6_publish(work);
        return;
    }

    // sec 18.2.10: "If the client receives a Reply message with a status code of UseMulticast, the
    // client records the receipt of the message and sends subsequent messages to the server ... using
    // multicast. The client resends the original message using multicast." Every message this client
    // sends already goes to the sec 7.1 multicast address, so the resend is all that is owed.
    ctx->status_code = status;
    if (status == (uint16_t)IDEMIP_DHCP6_STATUS_USE_MULTICAST)
    {
        ctx->owed = dhcp6_msg_for((uint8_t)ctx->state);
        io->status = IDEMIP_OK;
        dhcp6_publish(work);
        return;
    }
    // sec 18.2.10: UnspecFail says the server "was unable to process the client's message due to an
    // unspecified failure condition". The exchange is left running, so the sec 15 backoff is the
    // rate limit sec 14.1 asks for.
    if (status == (uint16_t)IDEMIP_DHCP6_STATUS_UNSPEC_FAIL)
    {
        dhcp6_publish(work);
        return;
    }

    // Not measured on this line, for the reason written at dhcp6_msg_for.
    switch (ctx->state) // GCOVR_EXCL_BR_LINE
    {
    case IDEMIP_DHCP6_SOLICITING:
        // sec 18.2.1: with a Rapid Commit option in the Solicit the client takes a Reply that carries
        // one and "will discard any Reply messages that do not contain the Rapid Commit option".
        if (!ctx->cfg->rapid_commit || dhcp6_find(opts, olen, IDEMIP_DHCP6_OPT_RAPID_COMMIT, &dlen) == NULL)
        {
            return;
        }
        if (!dhcp6_take_server_duid(work, opts, olen) || !dhcp6_take_lease(work, opts, olen))
        {
            dhcp6_publish(work);
            return;
        }
        dhcp6_enter_bound(work);
        break;

    case IDEMIP_DHCP6_REQUESTING:
    case IDEMIP_DHCP6_RENEWING:
    case IDEMIP_DHCP6_REBINDING:
        // sec 18.2.10.1: a NotOnLink in answer to a Request has the client "either reissue the message
        // without specifying any addresses or restart the DHCP server discovery process".
        if (status == (uint16_t)IDEMIP_DHCP6_STATUS_NOT_ON_LINK)
        {
            dhcp6_forget_lease(work);
            dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_SOLICITING);
            io->status = IDEMIP_OK;
            dhcp6_publish(work);
            return;
        }
        if (ctx->state == IDEMIP_DHCP6_REBINDING && !dhcp6_take_server_duid(work, opts, olen))
        {
            dhcp6_publish(work);
            return;
        }
        if (!dhcp6_take_lease(work, opts, olen))
        {
            // sec 18.2.10.1: the client "Sends a Request message to the server that responded if any
            // of the IAs in the Reply message contain the NoBinding status code." Without this the
            // Renew or Rebind just keeps retransmitting until its MRD is spent, taking minutes to
            // hours to recover a binding one Request would have restored.
            if ((ctx->status_code == (uint16_t)IDEMIP_DHCP6_STATUS_NO_BINDING) &&
                (ctx->state == IDEMIP_DHCP6_RENEWING || ctx->state == IDEMIP_DHCP6_REBINDING) &&
                dhcp6_take_server_duid(work, opts, olen))
            {
                dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_REQUESTING);
                io->status = IDEMIP_OK;
            }
            dhcp6_publish(work);
            return;
        }
        dhcp6_enter_bound(work);
        break;

    case IDEMIP_DHCP6_CONFIRMING:
        // sec 18.2.10.3: a Success, explicit or implicit, lets the client keep the addresses in the IA,
        // and a NotOnLink sends it to the sec 18 discovery process.
        if (status == (uint16_t)IDEMIP_DHCP6_STATUS_NOT_ON_LINK)
        {
            dhcp6_forget_lease(work);
            dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_SOLICITING);
            break;
        }
        dhcp6_enter_bound(work);
        break;

    case IDEMIP_DHCP6_INFO_REQUESTING:
        // sec 18.2.10.4 and sec 21.23: the configuration is taken and the refresh time becomes the next
        // scheduled contact, which BOUND holds as T1.
        dhcp6_take_dns(work, opts, olen);
        ctx->t1_s = dhcp6_take_info_refresh(opts, olen);
        ctx->t2_s = IDEMIP_DHCP6_INFINITY;
        ctx->valid_s = IDEMIP_DHCP6_INFINITY;
        dhcp6_arm_lease(ctx);
        dhcp6_enter_bound(work);
        break;

    case IDEMIP_DHCP6_RELEASING:
        // sec 18.2.10.2: "the client considers the Release event completed, regardless of the Status
        // Code option ... returned by the server".
        dhcp6_forget_lease(work);
        ctx->state = IDEMIP_DHCP6_IDLE;
        ctx->phase = DHCP6_PHASE_NEW;
        ctx->owed = 0u;
        ctx->rt_ms = 0u;
        break;

    case IDEMIP_DHCP6_DECLINING:
        // sec 18.2.10.2 completes the Decline event regardless of status, and sec 18.2.8 has the client
        // "treat the failure to acquire a binding (due to the conflict) as equivalent to not having
        // received the binding".
        dhcp6_forget_lease(work);
        ctx->state = IDEMIP_DHCP6_IDLE;
        ctx->phase = DHCP6_PHASE_NEW;
        ctx->owed = 0u;
        ctx->rt_ms = 0u;
        break;

    // sec 16.3 and sec 16.10 turn IDLE and BOUND away above, so the eight exchanges are every state
    // that reaches this switch.
    default:    // GCOVR_EXCL_LINE
        return; // GCOVR_EXCL_LINE
    }
    io->status = IDEMIP_OK;
    dhcp6_publish(work);
}

// The message the state owes, into the caller's buffer. BUSY when nothing is owed, which is every call
// until a tick arms one and every call after the message has been taken. A buffer too short for the
// message is ERR: retrying the same buffer cannot make it fit.
void idemip_dhcp6_build(uint8_t *work)
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
    uint8_t type = ctx->owed;
    if (type == 0u)
    {
        io->msg_type = 0u;
        io->status = IDEMIP_BUSY;
        return;
    }
    uint8_t *out = io->build_args.out;
    size_t cap = io->build_args.cap;
    if (out == NULL || cap < IDEMIP_DHCP6_FIXED_LEN)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    size_t n = dhcp6_write(work, type, out, cap);
    if (n == 0u)
    {
        io->status = IDEMIP_ERR;
        return;
    }
    ctx->owed = 0u;
    io->len = n;
    io->msg_type = type;
    dhcp6_all_agents(io->dst);
    io->dst_port = IDEMIP_DHCP6_PORT_SERVER;
    io->src_port = IDEMIP_DHCP6_PORT_CLIENT;
    io->status = IDEMIP_OK;
    dhcp6_publish(work);
}

// The first transmission of an exchange: sec 15's "RT for the first message transmission is based on
// IRT". sec 21.9 counts elapsed-time from here, so the exchange clock starts here too.
static void dhcp6_arm_first(Dhcp6Ctx *ctx, uint32_t rand)
{
    idemip_bool solicit = (ctx->state == IDEMIP_DHCP6_SOLICITING) ? IDEMIP_TRUE : IDEMIP_FALSE;
    ctx->started_ms = ctx->now_ms;
    ctx->rt_ms = dhcp6_first_rt(dhcp6_irt_ms((uint8_t)ctx->state), rand, solicit);
    ctx->retry_ms = ctx->now_ms + ctx->rt_ms;
    ctx->retries = 1u;
    ctx->owed = dhcp6_msg_for((uint8_t)ctx->state);
    ctx->phase = DHCP6_PHASE_RUN;
}

// A later transmission: sec 15's "RT = 2*RTprev + RAND*RTprev", bounded by MRT.
static void dhcp6_arm_again(Dhcp6Ctx *ctx, uint32_t rand)
{
    ctx->rt_ms = dhcp6_next_rt(ctx->rt_ms, dhcp6_mrt_ms((uint8_t)ctx->state, ctx), rand);
    ctx->retry_ms = ctx->now_ms + ctx->rt_ms;
    if (ctx->retries < 0xFFu)
    {
        ctx->retries++;
    }
    ctx->owed = dhcp6_msg_for((uint8_t)ctx->state);
}

// sec 15's MRD, which sec 18.2.3, sec 18.2.4 and sec 18.2.5 each state as a running deadline rather
// than a span. TRUE once the exchange has run out of time.
static idemip_bool dhcp6_mrd_spent(const Dhcp6Ctx *ctx)
{
    switch (ctx->state)
    {
    case IDEMIP_DHCP6_CONFIRMING:
        return dhcp6_reached(ctx->now_ms, ctx->started_ms + IDEMIP_DHCP6_CNF_MAX_RD_MS);
    case IDEMIP_DHCP6_RENEWING:
        return ((ctx->inf & DHCP6_INF_T2) != 0u) ? IDEMIP_FALSE : dhcp6_reached(ctx->now_ms, ctx->t2_ms);
    case IDEMIP_DHCP6_REBINDING:
        return ((ctx->inf & DHCP6_INF_VALID) != 0u) ? IDEMIP_FALSE : dhcp6_reached(ctx->now_ms, ctx->valid_ms);
    default:
        return IDEMIP_FALSE;
    }
}

// What each exchange does when sec 15's MRC or MRD runs out. sec 18.2.3 keeps the leases, sec 18.2.4
// goes on to the Rebind of sec 18.2.5, sec 18.2.5 goes back to the Solicit of sec 18 with the leases
// gone, and sec 18.2.2 takes one of the actions it lists, which here is that same discovery restart.
static void dhcp6_exchange_failed(uint8_t *work)
{
    Dhcp6Ctx *ctx = DHCP6_CTX(work);
    switch (ctx->state)
    {
    case IDEMIP_DHCP6_CONFIRMING:
        dhcp6_enter_bound(work);
        return;
    case IDEMIP_DHCP6_RENEWING:
        dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_REBINDING);
        return;
    case IDEMIP_DHCP6_REBINDING:
    case IDEMIP_DHCP6_REQUESTING:
        dhcp6_forget_lease(work);
        dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_SOLICITING);
        return;
    default:
        dhcp6_forget_lease(work);
        ctx->state = IDEMIP_DHCP6_IDLE;
        ctx->phase = DHCP6_PHASE_NEW;
        ctx->owed = 0u;
        ctx->rt_ms = 0u;
        return;
    }
}

// The sec 15 retransmission timer and the sec 21.4 T1 and T2 deadlines. OK when the tick moved the
// client on, BUSY when nothing was due yet, which is the ordinary answer on most ticks.
void idemip_dhcp6_tick(uint8_t *work)
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
    ctx->now_ms = idemip_ms_extend(&ctx->tick_ms, &ctx->tick_hi, io->tick_args.now_ms);
    uint32_t rand = io->tick_args.rand;

    if (ctx->state == IDEMIP_DHCP6_IDLE)
    {
        io->status = IDEMIP_BUSY;
        return;
    }

    if (ctx->state == IDEMIP_DHCP6_BOUND)
    {
        // sec 18.2.5: the leases are gone once "the valid lifetimes of all leases across all IAs have
        // expired", "at which time the client uses the Solicit message to locate a new DHCP server".
        // Not measured on the second: BOUND is entered from a Reply that assigned an address, and
        // the address is given up only by leaving BOUND. It is written because the lifetime being
        // tested is that address's, and a client with no address has no lifetime to reach.
        if ((ctx->inf & DHCP6_INF_VALID) == 0u && dhcp6_has_addr(ctx) && // GCOVR_EXCL_BR_LINE
            dhcp6_reached(ctx->now_ms, ctx->valid_ms))
        {
            dhcp6_forget_lease(work);
            dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_SOLICITING);
            io->status = IDEMIP_OK;
            dhcp6_publish(work);
            return;
        }
        // sec 18.2.4: "At time T1, the client initiates a Renew/Reply message exchange". sec 7.7 has a
        // client with T1 at infinity never extend the lifetimes. For a stateless client the deadline is
        // the sec 21.23 refresh, so the exchange is another Information-request.
        if ((ctx->inf & DHCP6_INF_T1) == 0u && dhcp6_reached(ctx->now_ms, ctx->t1_ms))
        {
            uint8_t next = ctx->cfg->stateless ? (uint8_t)IDEMIP_DHCP6_INFO_REQUESTING : (uint8_t)IDEMIP_DHCP6_RENEWING;
            dhcp6_begin(ctx, next);
            io->status = IDEMIP_OK;
            dhcp6_publish(work);
            return;
        }
        io->status = IDEMIP_BUSY;
        return;
    }

    // sec 15's MRD ends the exchange on its own deadline, whether or not an RT is due and whether or
    // not the first message has gone out yet.
    if (dhcp6_mrd_spent(ctx))
    {
        dhcp6_exchange_failed(work);
        io->status = IDEMIP_OK;
        dhcp6_publish(work);
        return;
    }

    if (ctx->phase == DHCP6_PHASE_NEW)
    {
        // sec 16.1 wants a new transaction-id per new exchange, and sec 18.2 delays a first Confirm,
        // Solicit or Information-request; both come out of the one random word this tick carries, the
        // id from the low 24 bits and the delay from a rotation of it.
        ctx->xid = rand & IDEMIP_DHCP6_XID_MASK;
        uint32_t delay = dhcp6_draw((rand >> 11) | (rand << 21), dhcp6_max_delay_ms((uint8_t)ctx->state));
        ctx->retry_ms = ctx->now_ms + delay;
        ctx->phase = DHCP6_PHASE_DELAY;
        if (delay != 0u)
        {
            io->status = IDEMIP_BUSY;
            dhcp6_publish(work);
            return;
        }
    }

    if (!dhcp6_reached(ctx->now_ms, ctx->retry_ms))
    {
        io->status = IDEMIP_BUSY;
        return;
    }

    if (ctx->phase == DHCP6_PHASE_DELAY)
    {
        dhcp6_arm_first(ctx, rand);
        io->status = IDEMIP_OK;
        dhcp6_publish(work);
        return;
    }

    // sec 18.2.1: past the first RT a collected Advertise ends the Solicit exchange rather than
    // retransmitting it, since "If the first RT elapses and the client has received a valid Advertise
    // message, the client SHOULD continue with a client-initiated message exchange by sending a
    // Request message."
    if (ctx->state == IDEMIP_DHCP6_SOLICITING && ctx->have_adv)
    {
        dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_REQUESTING);
        io->status = IDEMIP_OK;
        dhcp6_publish(work);
        return;
    }

    // sec 15: "Unless MRC is zero, the message exchange fails once the client has transmitted the
    // message MRC times".
    uint8_t mrc = dhcp6_mrc((uint8_t)ctx->state);
    if (mrc != 0u && ctx->retries >= mrc)
    {
        dhcp6_exchange_failed(work);
        io->status = IDEMIP_OK;
        dhcp6_publish(work);
        return;
    }
    dhcp6_arm_again(ctx, rand);
    io->status = IDEMIP_OK;
    dhcp6_publish(work);
}

// sec 18.2.3, the Confirm that asks whether the addresses still suit this link. It carries the IAs
// "assigned to the interface", so ERR without a lease: there is nothing to confirm and repeating the
// call cannot produce one.
void idemip_dhcp6_confirm(uint8_t *work)
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
    if (ctx->cfg->stateless || !dhcp6_has_addr(ctx))
    {
        io->status = IDEMIP_ERR;
        return;
    }
    dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_CONFIRMING);
    io->status = IDEMIP_OK;
    dhcp6_publish(work);
}

// sec 18.2.7, the Release to the server that assigned the leases. The Server Identifier of sec 21.3 is
// a MUST here, so a client that never recorded one is refused.
void idemip_dhcp6_release(uint8_t *work)
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
    // Not measured on the second: an address is recorded by the Reply that assigned it, and that
    // same Reply is where the Server Identifier came from, so a client holding one holds both. It is
    // written because sec 18.2.7 and sec 18.2.8 make the Server Identifier a MUST in these two
    // messages and the message cannot be built without it.
    if (!dhcp6_has_addr(ctx) || ctx->server_duid_len == 0u) // GCOVR_EXCL_BR_LINE
    {
        io->status = IDEMIP_ERR;
        return;
    }
    dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_RELEASING);
    io->status = IDEMIP_OK;
    dhcp6_publish(work);
}

// sec 18.2.8, the Decline for an address already in use on the link. It names the server that
// allocated the address in a sec 21.3 Server Identifier, so a client without one is refused.
void idemip_dhcp6_decline(uint8_t *work)
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
    // Not measured on the second: an address is recorded by the Reply that assigned it, and that
    // same Reply is where the Server Identifier came from, so a client holding one holds both. It is
    // written because sec 18.2.7 and sec 18.2.8 make the Server Identifier a MUST in these two
    // messages and the message cannot be built without it.
    if (!dhcp6_has_addr(ctx) || ctx->server_duid_len == 0u) // GCOVR_EXCL_BR_LINE
    {
        io->status = IDEMIP_ERR;
        return;
    }
    dhcp6_begin(ctx, (uint8_t)IDEMIP_DHCP6_DECLINING);
    io->status = IDEMIP_OK;
    dhcp6_publish(work);
}

IDEMIP_END_DECLS
