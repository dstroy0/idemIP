// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// What a span operation costs, swept over every axis that can change it: the system's word width,
// the endianness of the tail mask, the span's length, and the density and distribution of the bits
// in it.
//
// Two questions.
//
// The first is the shape. common.h's span helpers read a word at a time and mask the tail, so the
// body runs floor(n/W) times and the tail runs once. Cost is therefore n/W plus a constant, which
// says per-octet cost falls as 1/W and throughput rises linearly in W - until W reaches n, when the
// body stops running at all and the constant is the whole of it. Where that knee sits for the span
// widths this stack actually asks for is the thing to measure, because past it a wider word buys
// nothing.
//
// The second is the pad. IDEMIP_ENABLE_TIME_DETERMINISM tunes each function to a fixed duration,
// and the width of the window it tunes inside is exactly the spread of that function's cost over
// its inputs. A function whose cost does not move with density or distribution needs no pad at all.
// This reports that spread as the number the window is derived from.
//
// The host is one machine with one word width, so the widths are reached by instantiating the
// helpers on a 16-, 32- and 64-bit word rather than by pretending. That is what changes between the
// targets: the same source, a different IdemIpWord. Endianness reaches only the tail mask - every
// other load here is a memcpy of a constant width, which has no byte order - so the two arms are
// measured as the two arms, and their answers are checked against each other before either is
// timed.
//
// THIS FILE IS A MODEL, and the vectorizer is off in it for that reason. A row here says what a
// loop over a word of that width costs; it does not say what this host runs, because this host will
// gladly do sixteen octets at a time whatever the nominal word is. With the vectorizer on, the
// numbers stopped being about the word: the two tail-mask arms differ by one mask computed once, and
// came out 7.8 ns apart at a 576-octet span, while two instantiations of identical code came out
// 28 percent apart. Both are readings about gcc's vectorizer and neither is a reading about a word.
//
// What the library actually costs on this host, vectorizer and all, is bench_entries' business. The
// two questions are not the same question and they do not belong in one binary.
//
// Every call below is written at its call site and inlines, and the two clock reads have nothing
// between them but the work: see bench_harness.h.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "bench_harness.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__GNUC__) && !defined(__clang__)
volatile uint64_t idemip_bench_sink;
#endif

// ---------------------------------------------------------------------------
// The helpers, on a word of each width and with each tail mask
// ---------------------------------------------------------------------------
// One expansion per (word, endianness). The bodies are common.h's, verbatim in shape: a memcpy of a
// constant width per word, an or or an xor to fold it, and one masked word for the tail.

#define SPAN_ON(NAME, WORD, BIG)                                                                                       \
    static inline WORD NAME##_tail(const uint8_t *p, size_t r)                                                         \
    {                                                                                                                  \
        WORD w;                                                                                                        \
        memcpy(&w, p, sizeof w);                                                                                       \
        const WORD mask = (BIG) ? (WORD) ~(((((WORD)1u) << (8u * (sizeof(WORD) - r - 1u))) << 8u) - 1u)                 \
                                : (WORD)((((WORD)1u) << (8u * r)) - 1u);                                               \
        return (WORD)(w & mask);                                                                                       \
    }                                                                                                                  \
    static inline int NAME##_zero(const uint8_t *p, size_t n)                                                          \
    {                                                                                                                  \
        WORD any = 0u;                                                                                                 \
        size_t i = 0u;                                                                                                 \
        while (i + sizeof(WORD) <= n)                                                                                  \
        {                                                                                                              \
            WORD w;                                                                                                    \
            memcpy(&w, p + i, sizeof w);                                                                               \
            any |= w;                                                                                                  \
            i += sizeof w;                                                                                             \
        }                                                                                                              \
        any |= NAME##_tail(p + i, n - i);                                                                              \
        return any == 0u;                                                                                              \
    }

SPAN_ON(w16le, uint16_t, 0)
SPAN_ON(w32le, uint32_t, 0)
SPAN_ON(w64le, uint64_t, 0)
SPAN_ON(w16be, uint16_t, 1)
SPAN_ON(w32be, uint32_t, 1)
SPAN_ON(w64be, uint64_t, 1)

// The one octet-at-a-time form the helpers replaced, as the floor every width is measured against.
// It is the only row here that can exit early, so it is the only one whose cost should move with
// where the set bits are.
static inline int byte_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        if (p[i] != 0u)
        {
            return 0;
        }
    }
    return 1;
}

// Nothing at all, so the loop and its counter can be taken off every row above.
static inline int nop_zero(const uint8_t *p, size_t n)
{
    (void)p;
    return (int)(n & 1u);
}

// ---------------------------------------------------------------------------
// The two mask arms have to agree before either is timed
// ---------------------------------------------------------------------------
// The arms differ only in which end of the word the kept octets sit at, so on one host only one of
// them is the host's own. The other is checked by building the same span byte-reversed inside the
// word, masking it with the other arm, and reversing the answer back: a mask that keeps the same
// octets answers the same value. A disagreement means one arm is wrong and no timing below would
// mean anything.

static int masks_agree(void)
{
    uint8_t buf[8];
    uint8_t rev[8];
    for (size_t i = 0; i < sizeof buf; i++)
    {
        buf[i] = (uint8_t)(0xA0u + i);
    }
    for (size_t i = 0; i < sizeof rev; i++)
    {
        rev[i] = buf[(sizeof rev) - 1u - i];
    }
    for (size_t r = 0; r < 8u; r++)
    {
        const uint64_t lo = w64le_tail(buf, r);
        const uint64_t hi = w64be_tail(rev, r);
        uint64_t hi_swapped = 0u;
        for (unsigned b = 0; b < 8u; b++)
        {
            hi_swapped |= ((hi >> (8u * b)) & 0xFFu) << (8u * (7u - b));
        }
        if (lo != hi_swapped)
        {
            printf("MASK MISMATCH at r=%llu: le=%016llx be=%016llx\n", (unsigned long long)r, (unsigned long long)lo,
                   (unsigned long long)hi_swapped);
            return 0;
        }
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Inputs: density and distribution
// ---------------------------------------------------------------------------
// Density is how many of the span's bits are set, distribution is where they sit. A helper with no
// early exit should not care about either, and proving that is what makes its pad zero.

typedef enum
{
    DIST_CLUSTERED = 0, // every set bit packed at the front
    DIST_SPREAD,        // set bits evenly spaced across the span
    DIST_EDGES,         // half at the first octet, half at the last
    DIST_WALKING,       // a fixed linear-congruential walk, so no two spans repeat a pattern
    DIST_COUNT
} Distribution;

static const char *dist_name(unsigned d)
{
    static const char *n[DIST_COUNT] = {"clustered", "spread", "edges", "walking"};
    return n[d % (unsigned)DIST_COUNT];
}

// @p bits set out of @p n * 8, arranged as @p d says. Deterministic: no clock and no rand, so two
// runs of this bench compare.
static void fill(uint8_t *p, size_t n, size_t bits, unsigned d)
{
    memset(p, 0, n + 16u); // the tail reads out to a word past the span
    const size_t total = n * 8u;
    if (bits > total)
    {
        bits = total;
    }
    if (bits == 0u)
    {
        return;
    }
    switch (d)
    {
    case DIST_CLUSTERED:
        for (size_t i = 0; i < bits; i++)
        {
            p[i >> 3] |= (uint8_t)(1u << (i & 7u));
        }
        break;
    case DIST_SPREAD:
        for (size_t i = 0; i < bits; i++)
        {
            const size_t at = ((i * total) / bits) % total;
            p[at >> 3] |= (uint8_t)(1u << (at & 7u));
        }
        break;
    case DIST_EDGES:
        for (size_t i = 0; i < bits; i++)
        {
            const size_t at = ((i & 1u) ? (total - 1u - (i >> 1)) : (i >> 1)) % total;
            p[at >> 3] |= (uint8_t)(1u << (at & 7u));
        }
        break;
    default:
    {
        uint32_t s = 0x9E3779B9u;
        size_t placed = 0;
        while (placed < bits)
        {
            s = (uint32_t)(s * 1664525u + 1013904223u);
            const size_t at = (size_t)(s >> 8) % total;
            if ((p[at >> 3] & (uint8_t)(1u << (at & 7u))) == 0u)
            {
                p[at >> 3] |= (uint8_t)(1u << (at & 7u));
                placed++;
            }
        }
        break;
    }
    }
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

// The span widths this stack asks for. 4 is RFC 1122 sec 3.2.1.3 (a)'s "{ 0, 0 }", 6 an Ethernet
// address, 15 and 16 RFC 4291's ::1 and its addresses, 20 an option-free IPv4 header, 40 an IPv6
// one, and the rest reach well past the knee so the curve has somewhere to flatten.
static const size_t g_spans[] = {4u, 6u, 8u, 15u, 16u, 20u, 32u, 40u, 64u, 128u, 576u, 1500u};
#define SPANS (sizeof g_spans / sizeof g_spans[0])

#define BUF_MAX 1536u
static uint8_t g_a[BUF_MAX + 16u];

// Long enough that even the widest word over the shortest span runs well above the clock's
// resolution, and short enough that the whole sweep finishes.
static unsigned long iters_for(size_t n)
{
    return (n <= 32u) ? 8000000ul : ((n <= 128u) ? 2000000ul : 200000ul);
}

// ---------------------------------------------------------------------------
// The tail mask, alone
// ---------------------------------------------------------------------------
// The two endian arms differ by one mask computed once per call, so differencing two whole-loop
// timings cannot see it: over 1500 octets the loop's own scheduling moves further between two builds
// than the mask costs in total. Measured that way the big-endian arm came out 29 ns FASTER, which is
// not a fact about a mask.
//
// So the tail is timed on its own, with no loop body above it. What is left between the two counter
// reads is one load and one mask, which is the thing the two arms disagree about.
//
// The remainder has to move with the iteration. Held fixed it is loop-invariant, gcc hoists the
// whole mask out of the loop, and what gets timed is a load and an AND against a constant - which is
// why both arms first read as one cycle flat with the difference between them wandering between
// runs. Walking it means the mask is computed every time, which is the point.

#define TAIL_SWEEP(LABEL, FN, MAXR)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        double cy_ = 0.0;                                                                                              \
        BENCH_TIME_CYCLES(cy_, 20000000ul, {                                                                           \
            const size_t r_ = (size_t)(bench_i_ & ((MAXR)-1u));                                                        \
            const uint64_t v_ = (uint64_t)FN(g_a + r_, r_);                                                            \
            BENCH_KEEP(v_);                                                                                            \
        });                                                                                                            \
        printf("tail,%s,%u,%.4f,%.4f\n", LABEL, (unsigned)(MAXR), cy_, cy_ / bench_cycles_per_s() * 1e9);               \
        fflush(stdout);                                                                                                \
    } while (0)

static void tails(void)
{
    memset(g_a, 0xA5u, sizeof g_a);
    printf("# the tail alone: one load and one mask, at each remainder\n");
    printf("kind,arm,remainders_walked,cycles_per_call,ns_per_call\n");
    TAIL_SWEEP("w64le", w64le_tail, 8u);
    TAIL_SWEEP("w64be", w64be_tail, 8u);
    TAIL_SWEEP("w32le", w32le_tail, 4u);
    TAIL_SWEEP("w32be", w32be_tail, 4u);
    printf("\n");
}

// The twenty points one span is measured at: four distributions by five densities.
#define POINTS ((unsigned)DIST_COUNT * 5u)

static double g_best[POINTS];

// One row per (variant, span, distribution, density).
//
// The rounds are on the OUTSIDE and the points on the inside, so all twenty are measured close
// together and each keeps its own least round. Taken the other way - one point run to completion
// before the next begins - the twenty are minutes apart, and this machine drifts further over those
// minutes than the input moves the code: it read as a 57 percent spread on a helper that cannot
// branch on its input at all. Interleaving puts the drift on every point equally, so what is left
// between them is about the input, which is the number this bench exists to produce.
#define SWEEP(LABEL, WORD_BITS, BIG, FN)                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        for (size_t si_ = 0; si_ < SPANS; si_++)                                                                       \
        {                                                                                                              \
            const size_t n_ = g_spans[si_];                                                                            \
            const unsigned long it_ = iters_for(n_);                                                                   \
            for (unsigned k_ = 0; k_ < POINTS; k_++)                                                                   \
            {                                                                                                          \
                g_best[k_] = 1e30;                                                                                     \
            }                                                                                                          \
            for (unsigned round_ = 0; round_ < BENCH_REPEATS; round_++)                                                \
            {                                                                                                          \
                for (unsigned k_ = 0; k_ < POINTS; k_++)                                                               \
                {                                                                                                      \
                    fill(g_a, n_, (n_ * 8u * ((k_ % 5u) * 25u)) / 100u, k_ / 5u);                                      \
                    BENCH_CLOBBER();                                                                                   \
                    const uint64_t c0_ = bench_cycles();                                                               \
                    for (unsigned long i_ = 0; i_ < it_; i_++)                                                         \
                    {                                                                                                  \
                        BENCH_CLOBBER();                                                                               \
                        const int v_ = FN(g_a, n_);                                                                    \
                        BENCH_KEEP(v_);                                                                                \
                    }                                                                                                  \
                    const double cy_ = (double)(bench_cycles() - c0_) / (double)it_;                                   \
                    if (cy_ < g_best[k_])                                                                              \
                    {                                                                                                  \
                        g_best[k_] = cy_;                                                                              \
                    }                                                                                                  \
                }                                                                                                      \
            }                                                                                                          \
            for (unsigned k_ = 0; k_ < POINTS; k_++)                                                                   \
            {                                                                                                          \
                printf("%s,%u,%d,%llu,%u,%s,%.4f,%.4f,%.4f\n", LABEL, (unsigned)(WORD_BITS), (BIG),                    \
                       (unsigned long long)n_, (k_ % 5u) * 25u, dist_name(k_ / 5u), g_best[k_],                        \
                       g_best[k_] / bench_cycles_per_s() * 1e9, g_best[k_] / (double)n_);                              \
            }                                                                                                          \
            fflush(stdout);                                                                                            \
        }                                                                                                              \
    } while (0)

int main(void)
{
    if (!masks_agree())
    {
        return 1;
    }

    printf("# idemIP span bench: word width, tail-mask endianness, span, density, distribution\n");
    printf("# host word = %llu bits; vectorizer OFF, so a row models a word and not this host\n",
           (unsigned long long)(sizeof(void *) * 8u));
    tails();

    printf("variant,word_bits,big_endian,span,density_pct,distribution,cycles_per_call,ns_per_call,cycles_per_octet\n");

    SWEEP("nop", 0u, 0, nop_zero);
    SWEEP("byte", 8u, 0, byte_zero);
    SWEEP("w16le", 16u, 0, w16le_zero);
    SWEEP("w32le", 32u, 0, w32le_zero);
    SWEEP("w64le", 64u, 0, w64le_zero);
    SWEEP("w16be", 16u, 1, w16be_zero);
    SWEEP("w32be", 32u, 1, w32be_zero);
    SWEEP("w64be", 64u, 1, w64be_zero);

    return 0;
}
