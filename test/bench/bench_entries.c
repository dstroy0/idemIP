// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// What one entry costs, and how far that cost moves when only the bits of its input change.
//
// This is the number IDEMIP_ENABLE_TIME_DETERMINISM's window is derived from. An entry runs to
// stamp() + pad rather than to whatever its inputs cost, so the pad has to cover the widest cost
// the entry has; the floor of the window is the narrowest. Everything between them is the spread,
// and an entry whose spread is zero is already constant in the time domain and wants no pad.
//
// The entries are called through their namespaces, so what is measured is the translation unit the
// library built, under the library's own flags, and not a copy of it recompiled here. That is why
// this links libidemip rather than including the .c files.
//
// The inputs are swept the same way bench_words sweeps a span: density, distribution, and the
// alignment of the interesting field inside the word. An entry that walks a structure - an option
// list, a hole list, a table - will move with them; one that folds a fixed-width field will not.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/idemip.h"

#include "bench_harness.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__GNUC__) && !defined(__clang__)
volatile uint64_t idemip_bench_sink;
#endif

#define FRAME_MAX 1600u

static _Alignas(IDEMIP_ALIGN) uint8_t g_work[IDEMIP_TOTAL_BORROW];
static uint8_t g_frame[FRAME_MAX];
static uint8_t g_out[FRAME_MAX];
static uint8_t *g_borrow;

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------
// One case is a name, a setup that builds the input, and the call to time. Setup runs outside the
// timed region; only `run` is timed.

// A ramp, a constant, alternating octets, or a fixed walk: four ways to fill the same number of
// octets so a walk over them meets a different shape each time.
static void pattern_fill(uint8_t *p, size_t n, unsigned density_pct, unsigned pattern)
{
    const size_t set = (n * density_pct) / 100u;
    memset(p, 0, n);
    switch (pattern)
    {
    case 0: // clustered: the set octets first
        memset(p, 0xFFu, set);
        break;
    case 1: // spread: every k-th octet
        for (size_t i = 0; i < set; i++)
        {
            p[(n == set) ? i : ((i * n) / (set ? set : 1u))] = 0xFFu;
        }
        break;
    case 2: // edges: half at each end
        for (size_t i = 0; i < set; i++)
        {
            p[(i & 1u) ? (n - 1u - (i >> 1)) : (i >> 1)] = 0xFFu;
        }
        break;
    default: // walking: a fixed linear-congruential fill, no clock and no rand
    {
        uint32_t s = 0x9E3779B9u;
        for (size_t i = 0; i < set; i++)
        {
            s = (uint32_t)(s * 1664525u + 1013904223u);
            p[(size_t)(s >> 8) % n] = (uint8_t)(s >> 24);
        }
        break;
    }
    }
}

// --- ip4_frag: an option area to walk and a datagram to cut ----------------

static uint16_t g_frag_len;

static void setup_ip4_frag(unsigned density_pct, unsigned pattern)
{
    // A datagram with the widest option area RFC 791 sec 3.1 allows, filled so the copied-flag walk
    // meets a different number of options each time.
    const uint8_t ihl = 15u; // 60 octets, the sec 3.1 maximum
    const uint16_t hdr = (uint16_t)(ihl * 4u);
    const uint16_t data = 1200u;

    memset(g_frame, 0, sizeof g_frame);
    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.total_len = (uint16_t)(hdr + data);
    f.id = 0xBEEFu;
    f.ttl = 64u;
    f.proto = IDEMIP_IP4_PROTO_UDP;
    f.src = 0xC0A80001u;
    f.dst = 0xC0A800FEu;
    idemip_ip4_build(g_frame, &f);

    // The option area: a run of copied and not-copied options, laid out by the pattern. Every one is
    // four octets so the area stays well formed however many of them are set.
    uint8_t opts[40];
    pattern_fill(opts, sizeof opts, density_pct, pattern);
    for (size_t i = 0; i + 4u <= sizeof opts; i += 4u)
    {
        // The top bit is RFC 791 sec 3.1's copied flag: the pattern decides which options carry it.
        opts[i] = (uint8_t)((opts[i] & 0x80u) | 0x07u);
        opts[i + 1u] = 4u;
    }
    memcpy(g_frame + IDEMIP_IPV4_HDR_LEN, opts, sizeof opts);
    idemip_ip4_set_ver_ihl(g_frame, ihl);
    idemip_ip4_recksum(g_frame);
    g_frag_len = (uint16_t)(hdr + data);

    Ip4Frag.clear(g_borrow);
    IDEMIP_IP4_FRAG_IO(g_borrow)->begin_args.dgram = g_frame;
    IDEMIP_IP4_FRAG_IO(g_borrow)->begin_args.len = g_frag_len;
    IDEMIP_IP4_FRAG_IO(g_borrow)->begin_args.mtu = 576u;
}

static void run_ip4_frag_begin(void)
{
    uint8_t *w = g_borrow;
    Ip4Frag.begin(w);
    BENCH_KEEP(IDEMIP_IP4_FRAG_IO(w)->status);
}

static void run_ip4_frag_next(void)
{
    uint8_t *w = g_borrow;
    Ip4Frag.begin(w);
    IDEMIP_IP4_FRAG_IO(w)->next_args.out = g_out;
    IDEMIP_IP4_FRAG_IO(w)->next_args.cap = sizeof g_out;
    Ip4Frag.next(w);
    BENCH_KEEP(IDEMIP_IP4_FRAG_IO(w)->len);
}

// --- ip4_addr: fixed-width fields, nothing to walk -------------------------

static void setup_ip4_addr(unsigned density_pct, unsigned pattern)
{
    uint8_t bits[4];
    pattern_fill(bits, sizeof bits, density_pct, pattern);
    uint32_t a = 0u;
    for (unsigned i = 0; i < 4u; i++)
    {
        a = (a << 8) | bits[i];
    }
    Ip4Addr.clear(g_borrow);
    IDEMIP_IP4_ADDR_IO(g_borrow)->classify_args.addr = a;
    IDEMIP_IP4_ADDR_IO(g_borrow)->match_args.addr = a;
    IDEMIP_IP4_ADDR_IO(g_borrow)->match_args.net = a & 0xFFFFFF00u;
    IDEMIP_IP4_ADDR_IO(g_borrow)->match_args.mask = 0xFFFFFF00u;
}

static void run_ip4_addr_classify(void)
{
    uint8_t *w = g_borrow;
    Ip4Addr.classify(w);
    BENCH_KEEP(IDEMIP_IP4_ADDR_IO(w)->type);
}

static void run_ip4_addr_match(void)
{
    uint8_t *w = g_borrow;
    Ip4Addr.match(w);
    BENCH_KEEP(IDEMIP_IP4_ADDR_IO(w)->prefix_len);
}

// --- ip4_route: a table to walk, four passes deep --------------------------

static uint32_t g_route_dst;

static void setup_ip4_route(unsigned density_pct, unsigned pattern)
{
    uint8_t bits[4];
    pattern_fill(bits, sizeof bits, density_pct, pattern);
    g_route_dst = 0x0A000000u | ((uint32_t)bits[1] << 16) | ((uint32_t)bits[2] << 8) | bits[3];

    Ip4Route.clear(g_borrow);
    // Fill the table, so the four passes over it are the widest they get.
    for (unsigned i = 0; i < (unsigned)IDEMIP_IP4_ROUTES; i++)
    {
        Ip4RouteIo *io = IDEMIP_IP4_ROUTE_IO(g_borrow);
        io->add_args.dst = 0x0A000000u | ((uint32_t)i << 16);
        io->add_args.mask = 0xFFFF0000u;
        io->add_args.gw = 0u;
        io->add_args.metric = (uint16_t)i;
        io->add_args.netif = 0u;
        io->add_args.tos = 0u;
        io->add_args.flags = 0u;
        Ip4Route.add(g_borrow);
    }
}

static void run_ip4_route_lookup(void)
{
    uint8_t *w = g_borrow;
    IDEMIP_IP4_ROUTE_IO(w)->lookup_args.dst = g_route_dst;
    IDEMIP_IP4_ROUTE_IO(w)->lookup_args.tos = 0u;
    Ip4Route.lookup(w);
    BENCH_KEEP(IDEMIP_IP4_ROUTE_IO(w)->next_hop);
}

// --- the checksum over a frame: the per-octet path everything shares -------

static uint16_t g_cksum_len;

static void setup_cksum(unsigned density_pct, unsigned pattern)
{
    g_cksum_len = 1500u;
    pattern_fill(g_frame, g_cksum_len, density_pct, pattern);
}

static void run_cksum(void)
{
    const uint16_t v = idemip_cksum(g_frame, g_cksum_len);
    BENCH_KEEP(v);
}

// --- the span helpers as shipped -------------------------------------------
// bench_words models a word by turning the vectorizer off. This is the other half: common.h's own
// helper, at the host's IdemIpWord, compiled and optimised exactly as the library compiles it. The
// gap between the two is what the vector unit is worth on this host.

static size_t g_span_len;
static _Alignas(IDEMIP_ALIGN) uint8_t g_span_a[1536u + 16u];
static _Alignas(IDEMIP_ALIGN) uint8_t g_span_b[1536u + 16u];

static void setup_span16(unsigned density_pct, unsigned pattern)
{
    g_span_len = IDEMIP_IP6_ADDR_LEN;
    memset(g_span_a, 0, sizeof g_span_a);
    memset(g_span_b, 0, sizeof g_span_b);
    pattern_fill(g_span_a, g_span_len, density_pct, pattern);
    memcpy(g_span_b, g_span_a, g_span_len);
}

static void setup_span1500(unsigned density_pct, unsigned pattern)
{
    g_span_len = 1500u;
    memset(g_span_a, 0, sizeof g_span_a);
    memset(g_span_b, 0, sizeof g_span_b);
    pattern_fill(g_span_a, g_span_len, density_pct, pattern);
    memcpy(g_span_b, g_span_a, g_span_len);
}

static void run_bytes_zero(void)
{
    const int v = (int)idemip_bytes_zero(g_span_a, g_span_len);
    BENCH_KEEP(v);
}

static void run_bytes_eq(void)
{
    const int v = (int)idemip_bytes_eq(g_span_a, g_span_b, g_span_len);
    BENCH_KEEP(v);
}

// --- nothing, so the loop can be taken off every row -----------------------

static void setup_nop(unsigned density_pct, unsigned pattern)
{
    (void)density_pct;
    (void)pattern;
}

static void run_nop(void)
{
    const unsigned v = 0u;
    BENCH_KEEP(v);
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------
// Written as a macro rather than a table of function pointers on purpose. A pointer stops the entry
// inlining into the loop, which is a cost the bench brought and the library never pays, and at these
// durations it is a large part of the reading. Spelled out here, each call is the call the library
// makes.

static const char *pattern_name(unsigned p)
{
    static const char *n[4] = {"clustered", "spread", "edges", "walking"};
    return n[p & 3u];
}

#define ITERS 200000ul

// The twenty points one entry is measured at: four distributions by five densities.
#define POINTS 20u

static double g_best[POINTS];

// Rounds on the OUTSIDE, points on the inside, each point keeping its own least round.
//
// Point-at-a-time the twenty are minutes apart, and this machine drifts further over those minutes
// than the input moves the code: the same helper measured that way reported a 57 percent spread on
// something that cannot branch on its input. The spread is the whole deliverable here - it is the
// window a determinism pad is tuned inside - so it has to be about the input and not about the hour.
#define SWEEP(UNIT, ENTRY, SETUP, RUN)                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        for (unsigned k_ = 0; k_ < POINTS; k_++)                                                                       \
        {                                                                                                              \
            g_best[k_] = 1e30;                                                                                         \
        }                                                                                                              \
        for (unsigned round_ = 0; round_ < BENCH_REPEATS; round_++)                                                    \
        {                                                                                                              \
            for (unsigned k_ = 0; k_ < POINTS; k_++)                                                                   \
            {                                                                                                          \
                SETUP((k_ % 5u) * 25u, k_ / 5u);                                                                       \
                BENCH_CLOBBER();                                                                                       \
                const uint64_t c0_ = bench_cycles();                                                                   \
                for (unsigned long i_ = 0; i_ < ITERS; i_++)                                                           \
                {                                                                                                      \
                    BENCH_CLOBBER();                                                                                   \
                    RUN();                                                                                             \
                }                                                                                                      \
                const double cy_ = (double)(bench_cycles() - c0_) / (double)ITERS;                                     \
                if (cy_ < g_best[k_])                                                                                  \
                {                                                                                                      \
                    g_best[k_] = cy_;                                                                                  \
                }                                                                                                      \
            }                                                                                                          \
        }                                                                                                              \
        for (unsigned k_ = 0; k_ < POINTS; k_++)                                                                       \
        {                                                                                                              \
            const double ns_ = g_best[k_] / bench_cycles_per_s() * 1e9;                                                \
            printf("%s,%s,%u,%s,%.2f,%.2f,%.4f\n", UNIT, ENTRY, (k_ % 5u) * 25u, pattern_name(k_ / 5u), g_best[k_],    \
                   ns_, ns_ / 1000.0);                                                                                 \
        }                                                                                                              \
        fflush(stdout);                                                                                                \
    } while (0)

int main(void)
{
    g_borrow = g_work;

    printf("# idemIP entry bench: cost per call against input density and distribution\n");
    printf("# the spread of each entry is the window IDEMIP_ENABLE_TIME_DETERMINISM tunes its pad inside\n");
    printf("unit,entry,density_pct,distribution,cycles_per_call,ns_per_call,us_per_call\n");

    SWEEP("bench", "nop", setup_nop, run_nop);
    SWEEP("common", "bytes_zero_16", setup_span16, run_bytes_zero);
    SWEEP("common", "bytes_eq_16", setup_span16, run_bytes_eq);
    SWEEP("common", "bytes_zero_1500", setup_span1500, run_bytes_zero);
    SWEEP("common", "bytes_eq_1500", setup_span1500, run_bytes_eq);
    SWEEP("ip4_addr", "classify", setup_ip4_addr, run_ip4_addr_classify);
    SWEEP("ip4_addr", "match", setup_ip4_addr, run_ip4_addr_match);
    SWEEP("ip4_route", "lookup", setup_ip4_route, run_ip4_route_lookup);
    SWEEP("ip4_frag", "begin", setup_ip4_frag, run_ip4_frag_begin);
    SWEEP("ip4_frag", "next", setup_ip4_frag, run_ip4_frag_next);
    SWEEP("checksum", "cksum_1500", setup_cksum, run_cksum);

    return 0;
}
