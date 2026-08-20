// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// clock.h's four readings, and the wrap that is the reason three of them are told apart.
//
// now(), stamp() and epoch() are every build's. determinism_pad() is the one a build chooses, and
// this suite turns it on for itself below rather than testing it only in the build that wants it:
// the logic is the header's either way, and Unity's runner generator reads the case names out of
// the source text without a preprocessor, so a case behind a #if is one the runner still calls and
// the linker then cannot find.
//
// That the gate really removes the section is not a case here, because there is nothing left to
// call once it has: it is checked by compiling against the header with the macro either way.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.
//
// IDEMIP_ENABLE_TIME_DETERMINISM arrives as 1 for this suite whatever the build selected, and it
// arrives from test/CMakeLists.txt rather than from a #undef here: the value is a PUBLIC definition
// of the idemip target, so undefining it in the source would be a source file reaching around the
// build system for a value the build system owns.

#include "src/common.h"

#include <string.h>
#include <unity.h>

static IdemIpClock c;

void setUp(void)
{
    memset(&c, 0, sizeof c);
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

// --- determinism_pad() -----------------------------------------------------

// Move the reading the pad is measured against, whichever one this grade uses, and leave the epoch
// where it was: the two are separate on purpose and a case that moves both proves less.
static void tick_to(uint32_t v)
{
#if IDEMIP_DETERMINISM_HAS_TICK
    idemip_clock_refresh_fine(&c, v);
#else
    idemip_clock_refresh(&c, v);
#endif
}

void test_the_pad_is_the_stamp_plus_the_pad_ticks(void)
{
    tick_to(500u);
    idemip_clock_open(&c);
    TEST_ASSERT_EQUAL_UINT32(500u, idemip_determinism_tick_stamp(&c));
    TEST_ASSERT_EQUAL_UINT32(540u, idemip_determinism_pad(&c, 40u));
}

// The state rides in the top of the same word, so reading the pad has to mask it off.
void test_the_state_in_the_word_does_not_reach_the_pad(void)
{
    const uint32_t word = ((uint32_t)IDEMIP_CLOCK_PAD_OVER << IDEMIP_CLOCK_PAD_SHIFT) | 40u;
    tick_to(500u);
    idemip_clock_open(&c);
    TEST_ASSERT_EQUAL_UINT32(40u, idemip_determinism_pad_ticks(word));
    TEST_ASSERT_EQUAL_UINT32(540u, idemip_determinism_pad(&c, word));
}

// The pad's reading and the epoch are two clocks. Moving one must not move the other, or a pad
// would be measuring system time and a deadline would be measuring how long an entry took.
void test_the_pad_reading_and_the_epoch_are_separate(void)
{
#if IDEMIP_DETERMINISM_HAS_TICK
    idemip_clock_refresh(&c, 1000u);
    idemip_clock_refresh_fine(&c, 7u);
    idemip_clock_open(&c);

    idemip_clock_refresh_fine(&c, 9u);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(2u, idemip_determinism_spent(&c), "the pad did not read its own tick");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, idemip_clock_elapsed(&c), "a pad reading moved the epoch");

    idemip_clock_refresh(&c, 1400u);
    TEST_ASSERT_EQUAL_UINT32(400u, idemip_clock_elapsed(&c));
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(2u, idemip_determinism_spent(&c), "an epoch reading moved the pad");
#else
    // At COARSE there is one reading and it is the epoch's, which is the whole of that grade.
    idemip_clock_refresh(&c, 1000u);
    idemip_clock_open(&c);
    idemip_clock_refresh(&c, 1002u);
    TEST_ASSERT_EQUAL_UINT32(2u, idemip_determinism_spent(&c));
    TEST_ASSERT_EQUAL_UINT32(2u, idemip_clock_elapsed(&c));
#endif
}

// 32 bits of microseconds is 71 minutes, and the difference is taken unsigned between two readings
// of the one clock, so a wrap inside a pass subtracts out.
void test_the_pad_reading_survives_its_own_wrap(void)
{
    tick_to(0xFFFFFFF0u);
    idemip_clock_open(&c);
    tick_to(0x0000000Fu);
    TEST_ASSERT_EQUAL_UINT32(31u, idemip_determinism_spent(&c));
}

void test_the_four_states_are_told_apart(void)
{
    tick_to(1000u);
    idemip_clock_open(&c);
    TEST_ASSERT_EQUAL_INT(IDEMIP_CLOCK_PAD_UNSET, idemip_clock_pad_state(&c, 0u));

    TEST_ASSERT_EQUAL_INT(IDEMIP_CLOCK_PAD_EARLY, idemip_clock_pad_state(&c, 10u));
    tick_to(1010u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_CLOCK_PAD_MET, idemip_clock_pad_state(&c, 10u));
    tick_to(1011u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_CLOCK_PAD_OVER, idemip_clock_pad_state(&c, 10u));
}

// The state rides in the top of the pad word, so a state test has to mask it off too, or a tuned
// pad would read as a different pad the moment it recorded what it saw.
void test_the_state_in_the_word_does_not_reach_the_state_test(void)
{
    const uint32_t word = ((uint32_t)IDEMIP_CLOCK_PAD_OVER << IDEMIP_CLOCK_PAD_SHIFT) | 10u;
    tick_to(1000u);
    idemip_clock_open(&c);
    tick_to(1010u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_CLOCK_PAD_MET, idemip_clock_pad_state(&c, word));
}

// The hysteresis, which is the whole reason the last state is kept: one pass never moves the pad.
void test_a_single_state_moves_the_pad_not_at_all(void)
{
    const uint32_t start = 10u; // state UNSET in the top bits, so OVER does not agree with it
    const uint32_t after = idemip_determinism_tune(start, IDEMIP_CLOCK_PAD_OVER, 1u, 100u);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(10u, idemip_determinism_pad_ticks(after),
                                     "one pass moved the pad, so an outlier would move it");
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_CLOCK_PAD_OVER, after >> IDEMIP_CLOCK_PAD_SHIFT);
}

// Two agreeing passes step the pad - unless this build pinned it, which is what LITERAL is.
void test_the_same_state_twice_steps_the_pad(void)
{
    uint32_t w = 10u;
    w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_OVER, 1u, 100u); // remembers OVER
    w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_OVER, 1u, 100u); // agrees
#if IDEMIP_TIME_DETERMINISM_GRADE == IDEMIP_DETERMINISM_LITERAL
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(10u, idemip_determinism_pad_ticks(w),
                                     "LITERAL pinned the pad to a measured ceiling and must not walk it");
#else
    TEST_ASSERT_EQUAL_UINT32(11u, idemip_determinism_pad_ticks(w));

    w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_EARLY, 1u, 100u); // disagrees
    TEST_ASSERT_EQUAL_UINT32(11u, idemip_determinism_pad_ticks(w));
    w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_EARLY, 1u, 100u); // agrees
    TEST_ASSERT_EQUAL_UINT32(10u, idemip_determinism_pad_ticks(w));
#endif
}

// Whatever the grade, the tune records the state it was handed: at LITERAL that record is the only
// thing it does, and OVER there is a fault the caller reads rather than a step this takes.
void test_the_tune_always_records_the_state_it_saw(void)
{
    uint32_t w = 20u;
    w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_OVER, 1u, 100u);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_CLOCK_PAD_OVER, w >> IDEMIP_CLOCK_PAD_SHIFT);
    w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_EARLY, 1u, 100u);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_CLOCK_PAD_EARLY, w >> IDEMIP_CLOCK_PAD_SHIFT);
}

// An outlier between two agreeing passes costs the step but never a tick of pad.
void test_one_disturbed_pass_does_not_disturb_the_pad(void)
{
    uint32_t w = 20u;
    w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_MET, 1u, 100u);
    w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_MET, 1u, 100u);
    TEST_ASSERT_EQUAL_UINT32(20u, idemip_determinism_pad_ticks(w));

    w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_OVER, 1u, 100u); // the outlier
    TEST_ASSERT_EQUAL_UINT32(20u, idemip_determinism_pad_ticks(w));
    w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_MET, 1u, 100u); // settled again
    TEST_ASSERT_EQUAL_UINT32(20u, idemip_determinism_pad_ticks(w));
}

// MET is where a tuned pad stays, however many times it repeats.
void test_a_met_pad_never_moves(void)
{
    uint32_t w = 33u;
    for (unsigned i = 0; i < 16u; i++)
    {
        w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_MET, 1u, 100u);
        TEST_ASSERT_EQUAL_UINT32(33u, idemip_determinism_pad_ticks(w));
    }
}

void test_the_pad_never_steps_outside_its_range(void)
{
    uint32_t w = 5u;
    for (unsigned i = 0; i < 64u; i++)
    {
        w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_OVER, 3u, 8u);
        TEST_ASSERT_TRUE(idemip_determinism_pad_ticks(w) <= 8u);
    }
    for (unsigned i = 0; i < 64u; i++)
    {
        w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_EARLY, 3u, 8u);
        TEST_ASSERT_TRUE(idemip_determinism_pad_ticks(w) >= 3u);
    }
}

// A pad at zero is a function with none, and UNSET repeating must not walk it up off zero.
void test_an_unset_pad_stays_unset(void)
{
    uint32_t w = 0u;
    for (unsigned i = 0; i < 8u; i++)
    {
        w = idemip_determinism_tune(w, IDEMIP_CLOCK_PAD_UNSET, 0u, 100u);
        TEST_ASSERT_EQUAL_UINT32(0u, idemip_determinism_pad_ticks(w));
    }
}

// A pad walks to the cost the function has and settles there rather than oscillating around it.
void test_the_pad_converges_and_stays(void)
{
    const uint32_t cost = 12u;
    uint32_t w = 3u;
    for (unsigned i = 0; i < 200u; i++)
    {
        const uint32_t ticks = idemip_determinism_pad_ticks(w);
        IdemIpClockPad state = IDEMIP_CLOCK_PAD_MET;
        if (ticks < cost)
        {
            state = IDEMIP_CLOCK_PAD_OVER;
        }
        else if (ticks > cost)
        {
            state = IDEMIP_CLOCK_PAD_EARLY;
        }
        w = idemip_determinism_tune(w, state, 1u, 100u);
    }
#if IDEMIP_TIME_DETERMINISM_GRADE == IDEMIP_DETERMINISM_LITERAL
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(3u, idemip_determinism_pad_ticks(w), "LITERAL must not walk a pinned pad");
#else
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(cost, idemip_determinism_pad_ticks(w), "the pad did not settle on the cost");
#endif
}

// The pad occupies the low bits and never carries into the state, at the widest value it can hold.
void test_the_widest_pad_does_not_reach_the_state_bits(void)
{
    const uint32_t w = idemip_determinism_tune(IDEMIP_CLOCK_PAD_MASK, IDEMIP_CLOCK_PAD_UNSET, 0u, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_UINT32(IDEMIP_CLOCK_PAD_MASK, idemip_determinism_pad_ticks(w));
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_CLOCK_PAD_UNSET, w >> IDEMIP_CLOCK_PAD_SHIFT);
}

// The window every pad is tuned inside, which idemip_config.h states and test/bench/results
// measured. A floor above a ceiling would make the two bounds fight and the pad never settle.
void test_the_configured_window_is_a_window(void)
{
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_DETERMINISM_PAD_MIN <= IDEMIP_DETERMINISM_PAD_MAX,
                             "IDEMIP_DETERMINISM_PAD_MIN is above IDEMIP_DETERMINISM_PAD_MAX");
    TEST_ASSERT_TRUE(IDEMIP_DETERMINISM_PAD_DEFAULT >= IDEMIP_DETERMINISM_PAD_MIN);
    TEST_ASSERT_TRUE(IDEMIP_DETERMINISM_PAD_DEFAULT <= IDEMIP_DETERMINISM_PAD_MAX);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_DETERMINISM_PAD_MAX <= IDEMIP_CLOCK_PAD_MASK,
                             "a pad that wide would carry into the state bits");
}
