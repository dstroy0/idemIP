// idemIP v0.2.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// clock.h's three readings and the wrap that sets them apart, and the padded call of
// time_determinism.h.
//
// now(), stamp() and epoch() are in every build. The padded call is in the build that chooses it.
// This suite turns it on for itself, so that each build tests it. Unity's runner generator reads the
// case names from the source text with no preprocessor. A case behind a #if is still a case that the
// runner calls, and the link then fails.
//
// IDEMIP_ENABLE_TIME_DETERMINISM comes as 1 for this suite from test/CMakeLists.txt, with the clock
// of the suite. A #undef here would change a value that the build system owns.
//
// The suite defines idemip_clock_ticks over a fake clock. The entry that it pads moves the fake
// clock by the cost that a case sets, so a case sets the cost of the body to the tick.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/common.h"
#include "src/time_determinism.h"
#include "src/time_determinism_defines.h" // the layout of the pad word

#include "embed_clock.h"     // the ticks in one microsecond, which scale the window
#include "embed_turnstile.h" // embed_thread_place, which selects the slot

#include <unity.h>

static IdemIpClock c;

// --- the fake clock and the padded entry -------------------------------------

// Ticks in one unit of the window: a millisecond at COARSE, a microsecond at FINE and LITERAL.
#if IDEMIP_TIME_DETERMINISM_GRADE == IDEMIP_DETERMINISM_COARSE
#define PER_UNIT ((uint32_t)EMBED_CLOCK_TICKS_PER_MICRO * 1000u)
#else
#define PER_UNIT ((uint32_t)EMBED_CLOCK_TICKS_PER_MICRO)
#endif

// The pad of a cleared slot, and the ceiling, in ticks.
#define PAD0 ((uint32_t)IDEMIP_DETERMINISM_PAD_DEFAULT * PER_UNIT)
#define HI ((uint32_t)IDEMIP_DETERMINISM_PAD_MAX * PER_UNIT)

// 1 where the grade walks a pad up on an overrun.
#define WALKS (IDEMIP_TIME_DETERMINISM_GRADE != IDEMIP_DETERMINISM_LITERAL)

static uint32_t g_ticks;      // the fake clock
static uint32_t g_cost;       // the ticks that one run of the entry costs
static unsigned g_runs;       // the runs of the entry
static IdemIpStatus g_gives;  // the status that the entry gives
static IdemIpStatus g_status; // the status member that the entry writes

static _Alignas(IDEMIP_ALIGN) uint8_t g_pads[IDEMIP_PAD_BORROW];

uint32_t idemip_clock_ticks(void)
{
    return g_ticks;
}

// The work that run passes to the entry. The entry counts its runs in the first octet, so a case can
// see that the work reached it.
static uint8_t g_work[1];

static void entry(uint8_t *work)
{
    work[0] = (uint8_t)(work[0] + 1u);
    g_runs++;
    g_ticks += g_cost;
    g_status = g_gives;
}

static void run(void)
{
    time_determinism.run(g_pads, entry, g_work, &g_status);
}

// The slot of this thread, as time_determinism.c selects it.
static const IdemIpPadSlot *my_slot(void)
{
    const size_t place = (size_t)(embed_thread_place() & (IDEMIP_PAD_THREADS - 1u));
    return (const IdemIpPadSlot *)(const void *)(g_pads + (place * IDEMIP_PAD_SLOT_BYTES));
}

void setUp(void)
{
    c = (IdemIpClock){0};
    g_ticks = 1000u;
    g_cost = 0u;
    g_runs = 0u;
    g_work[0] = 0u;
    g_gives = IDEMIP_OK;
    g_status = IDEMIP_ERR;
    mmgr_zero_buf(g_pads, sizeof g_pads);
    time_determinism.clear(g_pads);
}

void tearDown(void)
{
    // Nothing to release: this suite holds no allocation, only file-scope storage.
}

// --- the epoch -------------------------------------------------------------

void test_a_refresh_reports_the_reading_it_was_handed(void)
{
    TEST_ASSERT_EQUAL_UINT64(1234u, idemip_clock_refresh(&c, 1234u));
    TEST_ASSERT_EQUAL_UINT32(1234u, idemip_clock_now(&c));
    TEST_ASSERT_EQUAL_UINT64(1234u, idemip_clock_epoch(&c));
}

// The whole point of the epoch: a reading that turns over goes on climbing.
void test_the_epoch_climbs_through_a_reading_that_wraps(void)
{
    idemip_clock_refresh(&c, 0xFFFFFFF0u);
    const IdemIpMs before = idemip_clock_epoch(&c);

    idemip_clock_refresh(&c, 0x00000010u);
    const IdemIpMs after = idemip_clock_epoch(&c);

    TEST_ASSERT_TRUE_MESSAGE(after > before, "the epoch went backwards across a wrap");
    TEST_ASSERT_EQUAL_UINT64(0x100000010u, after);
    TEST_ASSERT_EQUAL_UINT32(0x10u, idemip_clock_now(&c));
}

// now() is the reading verbatim and is NOT the epoch: past one wrap they disagree, which is the
// confusion the header exists to stop.
void test_now_and_the_epoch_disagree_once_the_reading_has_wrapped(void)
{
    idemip_clock_refresh(&c, 0xFFFFFFFFu);
    idemip_clock_refresh(&c, 5u);
    TEST_ASSERT_EQUAL_UINT32(5u, idemip_clock_now(&c));
    TEST_ASSERT_EQUAL_UINT64(0x100000005u, idemip_clock_epoch(&c));
}

void test_many_wraps_each_raise_the_epoch_by_one_period(void)
{
    IdemIpMs last = 0u;
    for (unsigned turn = 1u; turn <= 4u; turn++)
    {
        idemip_clock_refresh(&c, 0xFFFFFFFFu);
        idemip_clock_refresh(&c, 1u);
        const IdemIpMs now = idemip_clock_epoch(&c);
        TEST_ASSERT_TRUE(now > last);
        TEST_ASSERT_EQUAL_UINT64(((IdemIpMs)turn << 32) | 1u, now);
        last = now;
    }
}

// --- the stamp -------------------------------------------------------------

// Refreshing is every pass; taking a stamp is a separate decision, so a refresh must not move one.
void test_a_refresh_leaves_the_stamp_where_it_was(void)
{
    idemip_clock_refresh(&c, 100u);
    idemip_clock_open(&c);
    TEST_ASSERT_EQUAL_UINT32(100u, idemip_clock_stamp(&c));

    idemip_clock_refresh(&c, 175u);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(100u, idemip_clock_stamp(&c), "a refresh moved the stamp");
    TEST_ASSERT_EQUAL_UINT32(75u, idemip_clock_elapsed(&c));
}

void test_opening_a_pass_takes_the_reading_standing_now(void)
{
    idemip_clock_refresh(&c, 900u);
    idemip_clock_open(&c);
    idemip_clock_refresh(&c, 950u);
    idemip_clock_open(&c);
    TEST_ASSERT_EQUAL_UINT32(950u, idemip_clock_stamp(&c));
    TEST_ASSERT_EQUAL_UINT32(0u, idemip_clock_elapsed(&c));
}

// The elapsed difference is taken unsigned between two of the caller's own readings, so a wrap
// between the stamp and the reading subtracts out.
void test_elapsed_survives_a_wrap_between_the_stamp_and_the_reading(void)
{
    idemip_clock_refresh(&c, 0xFFFFFFF0u);
    idemip_clock_open(&c);
    idemip_clock_refresh(&c, 0x0000000Fu);
    TEST_ASSERT_EQUAL_UINT32(31u, idemip_clock_elapsed(&c));
}

// --- a span off the wire ---------------------------------------------------

void test_a_lifetime_in_seconds_scales_exactly(void)
{
    TEST_ASSERT_EQUAL_UINT64(0u, idemip_ms_from_s(0u));
    TEST_ASSERT_EQUAL_UINT64(1000u, idemip_ms_from_s(1u));
    TEST_ASSERT_EQUAL_UINT64(600000u, idemip_ms_from_s(600u));
    // The shift-and-subtract form has to agree with the multiply it replaces, at the widest input.
    TEST_ASSERT_EQUAL_UINT64((IdemIpMs)0xFFFFFFFFu * 1000u, idemip_ms_from_s(0xFFFFFFFFu));
}

// RFC 8106 sec 5.1 and RFC 4862 sec 5.5.3 both state a lifetime in a 32-bit seconds field. The
// widest finite one has to land ahead of a stamp taken now, or a deadline would sit behind it.
void test_the_widest_lifetime_still_lands_ahead_of_a_stamp(void)
{
    const IdemIpMs stamped = 0x100000000u;
    TEST_ASSERT_TRUE(stamped + idemip_ms_from_s(0xFFFFFFFEu) > stamped);
    TEST_ASSERT_TRUE_MESSAGE(idemip_ms_from_s(0xFFFFFFFEu) > 0xFFFFFFFFu,
                             "a lifetime this wide must not fit a 32-bit millisecond count");
}

// --- one epoch value in two words ------------------------------------------

void test_a_split_epoch_rejoins_to_itself(void)
{
    static const IdemIpMs cases[5] = {0u, 1u, 0xFFFFFFFFu, 0x100000000u, 0xDEADBEEFCAFEF00Du};
    for (unsigned i = 0; i < 5u; i++)
    {
        const IdemIpMs t = cases[i];
        TEST_ASSERT_EQUAL_UINT64(t, idemip_ms_join(idemip_ms_hi(t), idemip_ms_lo(t)));
    }
}

// --- the loose-word extension ----------------------------------------------

// idemip_ms_extend is the same wrap rule over two words a module keeps itself, so it must answer
// what a refresh answers.
void test_the_loose_word_extension_matches_a_refresh(void)
{
    uint32_t last = 0u;
    uint32_t hi = 0u;
    static const uint32_t readings[5] = {10u, 0xFFFFFFFFu, 7u, 0xFFFFFF00u, 3u};
    for (unsigned i = 0; i < 5u; i++)
    {
        const IdemIpMs a = idemip_ms_extend(&last, &hi, readings[i]);
        const IdemIpMs b = idemip_clock_refresh(&c, readings[i]);
        TEST_ASSERT_EQUAL_UINT64(b, a);
    }
}

// --- the padded call ---------------------------------------------------------

// The window is a window, and its ceiling fits the thirty bits of a pad.
void test_the_configured_window_is_a_window(void)
{
    TEST_ASSERT_TRUE(IDEMIP_DETERMINISM_PAD_MIN <= IDEMIP_DETERMINISM_PAD_DEFAULT);
    TEST_ASSERT_TRUE(IDEMIP_DETERMINISM_PAD_DEFAULT <= IDEMIP_DETERMINISM_PAD_MAX);
    TEST_ASSERT_TRUE_MESSAGE(HI <= IDEMIP_CLOCK_PAD_MASK, "the ceiling in ticks reaches the state bits");
    TEST_ASSERT_TRUE(PAD0 > 0u);
}

// clear sets each slot to the default pad, with no result held.
void test_a_cleared_slot_holds_the_default_pad_and_no_result(void)
{
    TEST_ASSERT_EQUAL_UINT32(PAD0, time_determinism.pad_ticks(g_pads));
    TEST_ASSERT_EQUAL_INT(IDEMIP_CLOCK_PAD_UNSET, time_determinism.state(g_pads));
    for (size_t place = 0u; place < (size_t)IDEMIP_PAD_THREADS; place++)
    {
        const IdemIpPadSlot *slot = (const IdemIpPadSlot *)(const void *)(g_pads + (place * IDEMIP_PAD_SLOT_BYTES));
        TEST_ASSERT_FALSE(slot->held);
        TEST_ASSERT_EQUAL_UINT32(PAD0, slot->word & IDEMIP_CLOCK_PAD_MASK);
    }
}

// The entry runs on the first call. The calls after it run no entry until the result goes.
void test_the_entry_runs_once_for_each_held_result(void)
{
    run();
    TEST_ASSERT_EQUAL_UINT(1u, g_runs);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, g_work[0], "run did not pass the work to the entry");
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, g_status, "a call inside the pad gave its result");

    g_ticks += PAD0 - 1u;
    run();
    TEST_ASSERT_EQUAL_UINT_MESSAGE(1u, g_runs, "a held call ran the entry again");
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, g_status);

    g_ticks += 1u;
    run();
    TEST_ASSERT_EQUAL_UINT(1u, g_runs);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, g_status, "the release did not give the status of the body");
    TEST_ASSERT_FALSE(my_slot()->held);
}

// The release comes on the first call at or past the pad, and on no call before it.
void test_the_release_never_comes_before_the_pad(void)
{
    const uint32_t stamp = g_ticks;
    run();
    while (g_ticks - stamp < PAD0)
    {
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, g_status, "a release came before the pad");
        g_ticks += 1u;
        run();
    }
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, g_status);
    TEST_ASSERT_EQUAL_UINT32(PAD0, g_ticks - stamp);
    TEST_ASSERT_EQUAL_INT(IDEMIP_CLOCK_PAD_MET, time_determinism.state(g_pads));
}

// Two bodies of different cost inside the pad give their results at the same reading.
void test_two_costs_inside_the_pad_release_at_the_same_reading(void)
{
    uint32_t released[2] = {0u, 0u};
    const uint32_t costs[2] = {0u, PAD0 - 1u};
    for (unsigned i = 0; i < 2u; i++)
    {
        setUp();
        g_cost = costs[i];
        const uint32_t stamp = g_ticks;
        run();
        while (g_status == IDEMIP_BUSY)
        {
            g_ticks += 1u;
            run();
        }
        released[i] = g_ticks - stamp;
    }
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(released[0], released[1], "the cost of the body reached the release");
    TEST_ASSERT_EQUAL_UINT32(PAD0, released[0]);
}

// A late call gives the result with OVER, and the pad stays: the gap is the caller's, not the body's.
void test_a_late_call_reports_over_and_keeps_the_pad(void)
{
    run();
    g_ticks += PAD0 + 5u;
    run();
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, g_status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_CLOCK_PAD_OVER, time_determinism.state(g_pads));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(PAD0, time_determinism.pad_ticks(g_pads), "a held call walked the pad");
}

// A body that overruns its pad gives its result at once. The pad walks up to its cost, except at
// LITERAL.
void test_an_overrun_raises_the_pad_to_the_cost_of_the_body(void)
{
    g_cost = PAD0 + 3u;
    run();
    TEST_ASSERT_EQUAL_UINT(1u, g_runs);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, g_status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_CLOCK_PAD_OVER, time_determinism.state(g_pads));
    // The cost of the body, up to the ceiling, where the grade walks. The default pad at LITERAL.
    uint32_t want = PAD0;
    if (WALKS)
    {
        want = (PAD0 + 3u < HI) ? PAD0 + 3u : HI;
    }
    TEST_ASSERT_EQUAL_UINT32(want, time_determinism.pad_ticks(g_pads));
}

// A pad never walks down, however many bodies fit it with room to spare.
void test_the_pad_never_walks_down(void)
{
    g_cost = HI;
    run();
    const uint32_t raised = time_determinism.pad_ticks(g_pads);
    g_cost = 0u;
    for (unsigned i = 0; i < 64u; i++)
    {
        run();
        TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, g_status);
        g_ticks += raised;
        run();
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, g_status);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(raised, time_determinism.pad_ticks(g_pads), "the pad walked down");
    }
}

// A pad never passes the ceiling.
void test_the_pad_never_passes_the_ceiling(void)
{
    g_cost = HI + 100u;
    run();
    TEST_ASSERT_EQUAL_UINT32(WALKS ? HI : PAD0, time_determinism.pad_ticks(g_pads));
    run();
    TEST_ASSERT_TRUE(time_determinism.pad_ticks(g_pads) <= HI);
}

// The difference of two readings subtracts a wrap out, so a held call across the wrap still waits.
void test_a_held_result_waits_out_the_pad_across_a_wrap(void)
{
    g_ticks = 0xFFFFFFFFu - 1u;
    const uint32_t stamp = g_ticks;
    run();
    g_ticks += PAD0 - 1u;
    run();
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, g_status);
    g_ticks += 1u;
    run();
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, g_status);
    TEST_ASSERT_EQUAL_UINT32(PAD0, g_ticks - stamp);
}

// An entry that answers IDEMIP_BUSY itself gives it at the release. The next call runs the entry
// again, as for an entry with no pad.
void test_a_busy_body_runs_again_after_its_release(void)
{
    g_gives = IDEMIP_BUSY;
    run();
    g_ticks += PAD0;
    run();
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, g_status);
    TEST_ASSERT_EQUAL_UINT(1u, g_runs);
    TEST_ASSERT_FALSE(my_slot()->held);

    g_gives = IDEMIP_OK;
    run();
    TEST_ASSERT_EQUAL_UINT_MESSAGE(2u, g_runs, "the call after a release did not run the entry");
}

// A call writes the slot of its own thread place and no other slot.
void test_a_call_writes_the_slot_of_its_own_thread(void)
{
    g_cost = HI;
    run();
    for (size_t place = 0u; place < (size_t)IDEMIP_PAD_THREADS; place++)
    {
        const IdemIpPadSlot *slot = (const IdemIpPadSlot *)(const void *)(g_pads + (place * IDEMIP_PAD_SLOT_BYTES));
        if (slot == my_slot())
        {
            TEST_ASSERT_EQUAL_UINT32(WALKS ? HI : PAD0, slot->word & IDEMIP_CLOCK_PAD_MASK);
        }
        else
        {
            TEST_ASSERT_EQUAL_UINT32_MESSAGE(PAD0, slot->word & IDEMIP_CLOCK_PAD_MASK, "a call wrote another slot");
        }
    }
}

// A pad of zero is no pad. The first call gives the result of the body at once, with UNSET, and a
// later overrun does not walk a pad that is not set.
void test_a_slot_with_no_pad_gives_its_result_at_once(void)
{
    const size_t place = (size_t)(embed_thread_place() & (IDEMIP_PAD_THREADS - 1u));
    IdemIpPadSlot *slot = (IdemIpPadSlot *)(void *)(g_pads + (place * IDEMIP_PAD_SLOT_BYTES));
    slot->word = 0u;
    g_cost = 5u;
    run();
    TEST_ASSERT_EQUAL_UINT(1u, g_runs);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, g_status, "a slot with no pad held its result");
    TEST_ASSERT_EQUAL_INT(IDEMIP_CLOCK_PAD_UNSET, time_determinism.state(g_pads));
    TEST_ASSERT_EQUAL_UINT32(0u, time_determinism.pad_ticks(g_pads));
}

// The state of a release sits in the top of the word, and the pad in the low bits never reaches it.
void test_the_state_and_the_pad_share_no_bit(void)
{
    g_cost = HI;
    run();
    const uint32_t word = my_slot()->word;
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_CLOCK_PAD_OVER, word >> IDEMIP_CLOCK_PAD_SHIFT);
    TEST_ASSERT_EQUAL_UINT32(time_determinism.pad_ticks(g_pads), word & IDEMIP_CLOCK_PAD_MASK);
}
