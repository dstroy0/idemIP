// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The measurement, and nothing else in the measured path.
//
// A bench that defends its timing loop with a function pointer, a volatile store or a memory sink
// is timing those. A function pointer stops the call inlining, so the code measured is not the code
// the library ships; a volatile store adds a load and a store per iteration; a sink accumulates.
// Each is a bottleneck the bench brought with it, and at these durations - a span helper is a
// handful of nanoseconds - they are the whole reading.
//
// What is used instead is an empty asm with a memory clobber. It emits no instruction at all. It
// tells the compiler that memory may have changed and that the value handed to it has escaped, so
// a pure call cannot be hoisted out of the loop and its result cannot be discarded, and the loop is
// left holding the work and the loop counter and nothing else.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#ifndef IDEMIP_BENCH_HARNESS_H
#define IDEMIP_BENCH_HARNESS_H

#include <stdint.h>
#include <time.h>

#if defined(__GNUC__) || defined(__clang__)

// The value has escaped: it cannot be folded away and the call producing it cannot be deleted.
#define BENCH_KEEP(v) __asm__ __volatile__("" : : "r,m"(v) : "memory")

// Memory may have changed: what was read before this cannot be reused after it, so a call whose
// arguments are loop-invariant is still made once per iteration.
#define BENCH_CLOBBER() __asm__ __volatile__("" : : : "memory")

#else

// No such barrier here, so the fallback pays for one volatile store per iteration. The nop row in
// the results is what that costs; on a compiler that reaches the arm above it costs nothing.
extern volatile uint64_t idemip_bench_sink;
#define BENCH_KEEP(v) (idemip_bench_sink = (uint64_t)(v))
#define BENCH_CLOBBER() ((void)0)

#endif

#if defined(CLOCK_MONOTONIC)
static inline double bench_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + ((double)t.tv_nsec * 1e-9);
}
#else
#include <stdlib.h>
static inline double bench_now(void)
{
    return (double)clock() / (double)CLOCKS_PER_SEC;
}
#endif

// ---------------------------------------------------------------------------
// Cycles
// ---------------------------------------------------------------------------
// A wall clock reads to about a third of a nanosecond here, which is one tick, so anything costing
// one or two of them reads as noise: the tail mask measured that way came out somewhere between
// 0.27 and 0.47 ns with no order to it, which is a statement about the clock. A cycle counter reads
// the thing itself.
//
// What this counts on x86 is the invariant TSC, which advances at a fixed rate rather than at the
// core's current frequency, so a "cycle" here is a reference tick and not a core clock. That makes
// it steadier for comparing two costs - turbo and thermal drift do not move it - and means it must
// not be read as an instruction count. On AArch64 it is the virtual counter, which is the same kind
// of thing.

#if defined(__x86_64__) || defined(__i386__)
static inline uint64_t bench_cycles(void)
{
    uint32_t lo;
    uint32_t hi;
    // lfence on both sides, so the read does not drift across the work being measured.
    __asm__ __volatile__("lfence; rdtsc; lfence" : "=a"(lo), "=d"(hi)::"memory");
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}
#define BENCH_HAS_CYCLES 1
#elif defined(__aarch64__)
static inline uint64_t bench_cycles(void)
{
    uint64_t v;
    __asm__ __volatile__("isb; mrs %0, cntvct_el0" : "=r"(v)::"memory");
    return v;
}
#define BENCH_HAS_CYCLES 1
#else
static inline uint64_t bench_cycles(void)
{
    return 0u;
}
#define BENCH_HAS_CYCLES 0
#endif

/** How many of this counter's ticks a second holds, measured once against the wall clock. */
static inline double bench_cycles_per_s(void)
{
    static double rate = 0.0;
    if (rate > 0.0)
    {
        return rate;
    }
    const double t0 = bench_now();
    const uint64_t c0 = bench_cycles();
    double t1 = t0;
    while ((t1 - t0) < 0.05) // long enough that the clock's own resolution does not decide this
    {
        t1 = bench_now();
    }
    const uint64_t c1 = bench_cycles();
    rate = (double)(c1 - c0) / (t1 - t0);
    return rate;
}

// How many runs to take, and which one to keep. The least of them is the run the scheduler and the
// rest of the host disturbed least, which is the one that is about the code.
#define BENCH_REPEATS 7u

/**
 * Time CALL over ITERS iterations, keep the least of BENCH_REPEATS runs, and leave the seconds per
 * call in OUT.
 *
 * CALL is written at the call site rather than passed as a pointer, so it inlines exactly as it does
 * in the library. Nothing between the two clock reads belongs to the bench.
 */
#define BENCH_TIME(OUT, ITERS, CALL)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        double bench_best_ = 1e30;                                                                                     \
        for (unsigned bench_r_ = 0; bench_r_ < BENCH_REPEATS; bench_r_++)                                              \
        {                                                                                                              \
            BENCH_CLOBBER();                                                                                           \
            const double bench_t0_ = bench_now();                                                                      \
            for (unsigned long bench_i_ = 0; bench_i_ < (ITERS); bench_i_++)                                           \
            {                                                                                                          \
                BENCH_CLOBBER();                                                                                       \
                CALL;                                                                                                  \
            }                                                                                                          \
            const double bench_dt_ = bench_now() - bench_t0_;                                                          \
            if (bench_dt_ < bench_best_)                                                                               \
            {                                                                                                          \
                bench_best_ = bench_dt_;                                                                               \
            }                                                                                                          \
        }                                                                                                              \
        (OUT) = bench_best_ / (double)(ITERS);                                                                         \
    } while (0)

/**
 * The same, counted in cycles. Use this for anything that costs single-figure nanoseconds, where the
 * wall clock's own tick is the whole reading.
 *
 * Leaves cycles per call in OUT, as a double, because a cost below one cycle per call is a real
 * answer: it means the work pipelined with the loop around it.
 */
#define BENCH_TIME_CYCLES(OUT, ITERS, CALL)                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        uint64_t bench_best_ = (uint64_t)-1;                                                                           \
        for (unsigned bench_r_ = 0; bench_r_ < BENCH_REPEATS; bench_r_++)                                              \
        {                                                                                                              \
            BENCH_CLOBBER();                                                                                           \
            const uint64_t bench_c0_ = bench_cycles();                                                                 \
            for (unsigned long bench_i_ = 0; bench_i_ < (ITERS); bench_i_++)                                           \
            {                                                                                                          \
                BENCH_CLOBBER();                                                                                       \
                CALL;                                                                                                  \
            }                                                                                                          \
            const uint64_t bench_dc_ = bench_cycles() - bench_c0_;                                                     \
            if (bench_dc_ < bench_best_)                                                                               \
            {                                                                                                          \
                bench_best_ = bench_dc_;                                                                               \
            }                                                                                                          \
        }                                                                                                              \
        (OUT) = (double)bench_best_ / (double)(ITERS);                                                                  \
    } while (0)

#endif // IDEMIP_BENCH_HARNESS_H
