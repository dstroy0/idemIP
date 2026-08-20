// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for rdnss, modeled on test_phy. It tests two things and nothing else:
//
//   the contract
//     1. the borrow is the caller's, so the suite declares it and passes it to every entry
//     2. every entry is called with a null borrow and must refuse
//     3. the borrow IS the interface, so two interfaces share not one byte
//     4. a canary past IDEMIP_RDNSS_BORROW is intact after every case
//     5. the published offset map is ordered, aligned, and does not overlap
//     6. clear zeroes the regions, and a borrow no one cleared is refused
//     7. BUSY and ERR are separated by whether retrying can ever succeed
//
//   RFC 8106 sec 5.1, sec 5.3.1 and sec 6
//     the option's fields as Figure 1 prints them, the validity checks sec 5.3.1 names, and steps (b)
//     through (d) of sec 6.2 with the ordering and eviction the section states.
//
// RFC 8106 prints Figure 1's field layout but no worked byte example, so every option here is built
// to that figure and what is asserted is the rule the prose states.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/nd/rdnss.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because RFC 8106 sec 6.1 refreshes an entry when the option
// arrives "on the same interface". A canary follows each so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(IDEMIP_ALIGN) uint8_t work_a[IDEMIP_RDNSS_BORROW + 16];
static _Alignas(IDEMIP_ALIGN) uint8_t work_b[IDEMIP_RDNSS_BORROW + 16];

#define STATE_OFF ((size_t)IDEMIP_RDNSS_OFF_CTX)
#define TABLE_OFF ((size_t)IDEMIP_RDNSS_OFF_ENTRIES)
#define STATE_END ((size_t)IDEMIP_RDNSS_OFF_END)

#define IO(w) IDEMIP_RDNSS_IO(w)

// RFC 3849 reserves 2001:DB8::/32 for documentation.
static const uint8_t g_a[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A};
static const uint8_t g_b[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0B};
static const uint8_t g_c[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0C};
static const uint8_t g_d[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0D};
static const uint8_t g_multicast[IDEMIP_IP6_ADDR_LEN] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t g_unspecified[IDEMIP_IP6_ADDR_LEN] = {0};

// One option, built to RFC 8106 sec 5.1 Figure 1: Type, Length, Reserved, Lifetime, then addresses.
static uint8_t g_opt[8u + (16u * 4u)];

static size_t build(uint8_t type, uint8_t length, uint32_t lifetime, const uint8_t *const *addrs, uint8_t n)
{
    memset(g_opt, 0, sizeof g_opt);
    g_opt[IDEMIP_RDNSS_OPT_OFF_TYPE] = type;
    g_opt[IDEMIP_RDNSS_OPT_OFF_LEN] = length;
    g_opt[IDEMIP_RDNSS_OPT_OFF_LIFETIME + 0u] = (uint8_t)(lifetime >> 24);
    g_opt[IDEMIP_RDNSS_OPT_OFF_LIFETIME + 1u] = (uint8_t)(lifetime >> 16);
    g_opt[IDEMIP_RDNSS_OPT_OFF_LIFETIME + 2u] = (uint8_t)(lifetime >> 8);
    g_opt[IDEMIP_RDNSS_OPT_OFF_LIFETIME + 3u] = (uint8_t)lifetime;
    for (uint8_t i = 0; i < n; i++)
    {
        memcpy(g_opt + IDEMIP_RDNSS_OPT_OFF_ADDRS + ((size_t)i * IDEMIP_IP6_ADDR_LEN), addrs[i], IDEMIP_IP6_ADDR_LEN);
    }
    return (size_t)IDEMIP_RDNSS_OPT_OFF_ADDRS + ((size_t)n * IDEMIP_IP6_ADDR_LEN);
}

// sec 5.1: "The minimum value is 3 if one IPv6 address is contained in the option. Every additional
// RDNSS address increases the length by 2."
static uint8_t length_for(uint8_t addresses)
{
    return (uint8_t)(1u + (2u * addresses));
}

static void option_in(uint8_t *w, size_t len, uint32_t now_ms)
{
    IO(w)->option_args.option = g_opt;
    IO(w)->option_args.len = len;
    IO(w)->option_args.now_ms = now_ms;
    Rdnss.option_in(w);
}

static void feed(uint8_t *w, uint32_t lifetime, uint32_t now_ms, const uint8_t *const *addrs, uint8_t n)
{
    size_t len = build((uint8_t)IDEMIP_RDNSS_OPT_TYPE, length_for(n), lifetime, addrs, n);
    option_in(w, len, now_ms);
}

static void get_slot(uint8_t *w, uint8_t index)
{
    IO(w)->addr_args.index = index;
    Rdnss.get(w);
}

static void find_addr(uint8_t *w, const uint8_t *addr)
{
    IO(w)->addr_args.addr = addr;
    Rdnss.find(w);
}

static void tick_at(uint8_t *w, uint32_t now_ms)
{
    IO(w)->tick_args.now_ms = now_ms;
    Rdnss.tick(w);
}

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_RDNSS_BORROW, CANARY, cap - IDEMIP_RDNSS_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_RDNSS_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_RDNSS_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(g_opt, 0, sizeof g_opt);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// Every entry, in namespace order, so a new one added to RdnssNs is added here too.
static void call_every_entry(uint8_t *w)
{
    Rdnss.clear(w);
    Rdnss.option_in(w);
    Rdnss.get(w);
    Rdnss.find(w);
    Rdnss.remove(w);
    Rdnss.tick(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    call_every_entry(NULL);
    TEST_PASS();
}

// The borrow IS the interface, and the operand block is in it, so two interfaces share no byte at
// all. This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    Rdnss.clear(work_b);
    feed(work_a, 100u, 0u, one, 1u);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->added);

    find_addr(work_b, g_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_b)->status, "one borrow found the other's server");
    find_addr(work_a, g_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// A call on one borrow reaches no byte of another, clear included, which is the widest-reaching entry
// this module has.
void test_clear_on_one_borrow_leaves_the_other_untouched(void)
{
    memset(work_b + STATE_OFF, 0xC3, STATE_END - STATE_OFF);
    Rdnss.clear(work_a);
    for (size_t i = STATE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[i], "clear on one borrow wrote into another");
    }
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    Rdnss.clear(work_b);
    feed(work_a, 100u, 0u, one, 1u);
    find_addr(work_a, g_a);
    uint32_t first = IO(work_a)->expire_at;

    feed(work_b, 5u, 9000u, one, 1u);
    find_addr(work_a, g_a);
    TEST_ASSERT_EQUAL_UINT32(first, IO(work_a)->expire_at);
}

// --- the published map -------------------------------------------------------

void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_RDNSS_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_RDNSS_OFF_CTX >= sizeof(RdnssIo),
                             "the context starts inside the operand block");
    TEST_ASSERT_TRUE_MESSAGE(TABLE_OFF >= (size_t)IDEMIP_RDNSS_OFF_CTX, "the list starts before the context");
    TEST_ASSERT_EQUAL_size_t(TABLE_OFF + ((size_t)IDEMIP_RDNSS_SERVERS << IDEMIP_RDNSS_ENTRY_SHIFT), STATE_END);
    TEST_ASSERT_TRUE_MESSAGE(STATE_END <= (size_t)IDEMIP_RDNSS_BORROW, "the map runs past IDEMIP_RDNSS_BORROW");
}

void test_every_published_offset_is_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_RDNSS_OFF_CTX & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, TABLE_OFF & (IDEMIP_ALIGN - 1u));
}

void test_the_io_macro_reaches_the_operand_block(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_RDNSS_OFF_IO, (uint8_t *)IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_RDNSS_OFF_IO, (uint8_t *)IO(work_b));
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Rdnss.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

void test_clear_zeroes_the_list(void)
{
    memset(work_a, 0xFF, IDEMIP_RDNSS_BORROW);
    Rdnss.clear(work_a);
    for (size_t i = TABLE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00u, work_a[i], "clear left a list byte set");
    }
}

void test_clear_zeroes_the_context_apart_from_the_mark(void)
{
    memset(work_a, 0xFF, IDEMIP_RDNSS_BORROW);
    Rdnss.clear(work_a);
    size_t set = 0;
    for (size_t i = STATE_OFF; i < TABLE_OFF; i++)
    {
        if (work_a[i] != 0x00u)
        {
            set++;
        }
    }
    TEST_ASSERT_EQUAL_size_t_MESSAGE(4u, set, "clear must zero the context apart from the cleared mark");
}

void test_clear_leaves_the_operand_block_alone(void)
{
    Rdnss.clear(work_a);
    IO(work_a)->option_args.option = g_opt;
    IO(work_a)->option_args.len = 24u;
    Rdnss.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_opt, IO(work_a)->option_args.option);
    TEST_ASSERT_EQUAL_size_t(24u, IO(work_a)->option_args.len);
}

// A borrow no one cleared holds no mark, so every entry but clear refuses it.
void test_an_uncleared_borrow_is_refused(void)
{
    static const uint8_t *const one[1] = {g_a};
    feed(work_a, 100u, 0u, one, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    get_slot(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    find_addr(work_a, g_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    tick_at(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// --- the option, sec 5.1 and sec 5.3.1 ---------------------------------------

void test_option_in_refuses_a_null_option(void)
{
    Rdnss.clear(work_a);
    IO(work_a)->option_args.option = NULL;
    IO(work_a)->option_args.len = 24u;
    Rdnss.option_in(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// Fewer octets than the fields Figure 1 puts ahead of the addresses is not an option at all.
void test_option_in_refuses_fewer_octets_than_the_header(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    build((uint8_t)IDEMIP_RDNSS_OPT_TYPE, length_for(1u), 100u, one, 1u);
    option_in(work_a, (size_t)IDEMIP_RDNSS_OPT_OFF_ADDRS - 1u, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// sec 5.1: "Type 8-bit identifier of the RDNSS option type as assigned by IANA: 25."
void test_another_option_type_is_discarded(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    size_t len = build(3u, length_for(1u), 100u, one, 1u); // 3 is RFC 4861 sec 4.6.2 Prefix Information
    option_in(work_a, len, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
}

// sec 5.3.1: "the value of the Length field in the RDNSS option is greater than or equal to the
// minimum value (3)".
void test_a_length_below_three_is_discarded(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    size_t len = build((uint8_t)IDEMIP_RDNSS_OPT_TYPE, 1u, 100u, one, 1u);
    option_in(work_a, len, 0u);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
}

// sec 5.3.1: the Length "satisfies the requirement that (Length - 1) % 2 == 0", so an even Length is
// not one this option can carry.
void test_an_even_length_is_discarded(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    size_t len = build((uint8_t)IDEMIP_RDNSS_OPT_TYPE, 4u, 100u, one, 1u);
    option_in(work_a, len + 8u, 0u);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
}

// RFC 4861 sec 4.6 states the Length "in units of 8 octets", so an option claiming more octets than
// the caller can read is discarded rather than read past.
void test_an_option_longer_than_the_octets_available_is_discarded(void)
{
    static const uint8_t *const two[2] = {g_a, g_b};
    Rdnss.clear(work_a);
    build((uint8_t)IDEMIP_RDNSS_OPT_TYPE, length_for(2u), 100u, two, 2u);
    option_in(work_a, (size_t)IDEMIP_RDNSS_OPT_OFF_ADDRS + IDEMIP_IP6_ADDR_LEN, 0u);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
}

// sec 5.3.1: "the validity of the RDNSS option is checked with the 'Addresses of IPv6 Recursive DNS
// Servers' field; that is, the addresses should be unicast addresses", and "Otherwise, the host MUST
// discard the options", so one bad address discards the whole option.
void test_a_multicast_address_discards_the_whole_option(void)
{
    static const uint8_t *const pair[2] = {g_a, g_multicast};
    Rdnss.clear(work_a);
    feed(work_a, 100u, 0u, pair, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IO(work_a)->servers, "a discarded option must register nothing");
}

void test_the_unspecified_address_discards_the_option(void)
{
    static const uint8_t *const one[1] = {g_unspecified};
    Rdnss.clear(work_a);
    feed(work_a, 100u, 0u, one, 1u);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
}

// sec 5.1: "the number of addresses is equal to (Length - 1) / 2".
void test_the_address_count_comes_from_the_length_field(void)
{
    static const uint8_t *const three[3] = {g_a, g_b, g_c};
    Rdnss.clear(work_a);
    feed(work_a, 100u, 0u, three, 3u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(3u, IO(work_a)->added);
    TEST_ASSERT_EQUAL_UINT8(3u, IO(work_a)->servers);
}

// sec 5.3.1 RECOMMENDS room for at least three addresses.
void test_the_list_holds_at_least_three(void)
{
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_RDNSS_SERVERS >= 3u,
                             "RFC 8106 sec 5.3.1 recommends storing at least three RDNSS addresses");
}

// --- sec 6.1 and sec 6.2 -----------------------------------------------------

// sec 6.1: "Expiration-time is set to the value of the Lifetime field of the RDNSS option ... plus
// the current time."
void test_the_expiration_is_the_lifetime_plus_the_current_time(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    feed(work_a, 30u, 5000u, one, 1u);
    find_addr(work_a, g_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32(5000u + (30u * 1000u), IO(work_a)->expire_at);
    TEST_ASSERT_FALSE(IO(work_a)->infinite);
}

// sec 5.1: "A value of all one bits (0xffffffff) represents infinity."
void test_an_infinite_lifetime_never_expires(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    feed(work_a, IDEMIP_RDNSS_LIFETIME_INFINITE, 0u, one, 1u);
    find_addr(work_a, g_a);
    TEST_ASSERT_TRUE(IO(work_a)->infinite);

    tick_at(work_a, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    find_addr(work_a, g_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// sec 6.2 step (c): an address already held "and the RDNSS option's Lifetime field is not set to
// zero, then just update the value of the Expiration-time field".
void test_a_repeated_address_updates_the_expiration(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    feed(work_a, 30u, 0u, one, 1u);
    feed(work_a, 60u, 1000u, one, 1u);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->updated);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->added);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IO(work_a)->servers, "an update must not add a second entry");
    find_addr(work_a, g_a);
    TEST_ASSERT_EQUAL_UINT32(1000u + (60u * 1000u), IO(work_a)->expire_at);
}

// sec 6.2 step (b): an address already held with a zero Lifetime is deleted "in order to prevent the
// RDNSS address from being used any more".
void test_a_zero_lifetime_deletes_a_held_address(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    feed(work_a, 30u, 0u, one, 1u);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->servers);

    feed(work_a, 0u, 1000u, one, 1u);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->deleted);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
    find_addr(work_a, g_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// sec 5.1: "A value of zero means that the RDNSS addresses MUST no longer be used", so an address
// that is not in the list and carries a zero Lifetime is not registered by step (d) either.
void test_a_zero_lifetime_registers_nothing_for_an_address_not_held(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    feed(work_a, 0u, 0u, one, 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->added);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
}

// sec 6.2 step (d): "position the first RDNSS address in the RDNSS option as the first one in the
// Resolver Repository, the second RDNSS address in the option as the second one in the repository,
// and so on."
void test_the_option_order_is_the_list_order(void)
{
    static const uint8_t *const three[3] = {g_a, g_b, g_c};
    Rdnss.clear(work_a);
    feed(work_a, 100u, 0u, three, 3u);

    get_slot(work_a, 0u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_a, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
    get_slot(work_a, 1u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_b, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
    get_slot(work_a, 2u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_c, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
}

// sec 6.2 step (d) inserts a newly registered address "as the first one in the Resolver Repository",
// so a later option's server is asked before the ones already held.
void test_a_new_address_is_inserted_at_the_head(void)
{
    static const uint8_t *const two[2] = {g_a, g_b};
    static const uint8_t *const one[1] = {g_c};
    Rdnss.clear(work_a);
    feed(work_a, 100u, 0u, two, 2u);
    feed(work_a, 100u, 0u, one, 1u);
    TEST_ASSERT_EQUAL_UINT8(3u, IO(work_a)->servers);

    get_slot(work_a, 0u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_c, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
    get_slot(work_a, 1u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_a, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
    get_slot(work_a, 2u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_b, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
}

// sec 6.2 step (d): "In the case where the data structure for the DNS Server List is full of RDNSS
// entries ... delete from the DNS Server List the entry with the shortest Expiration-time (i.e., the
// entry that will expire first)."
void test_a_full_list_evicts_the_entry_that_expires_first(void)
{
    static const uint8_t *const two[2] = {g_a, g_b};
    static const uint8_t *const soon[1] = {g_c};
    static const uint8_t *const fresh[1] = {g_d};
    Rdnss.clear(work_a);
    feed(work_a, 1000u, 0u, two, 2u);
    feed(work_a, 10u, 0u, soon, 1u);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_RDNSS_SERVERS, IO(work_a)->servers);

    feed(work_a, 1000u, 0u, fresh, 1u);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IO(work_a)->evicted, "a full list evicts one entry");
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->added);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_RDNSS_SERVERS, IO(work_a)->servers);

    find_addr(work_a, g_c);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "the soonest-expiring entry was not the one dropped");
    find_addr(work_a, g_d);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    get_slot(work_a, 0u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_d, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
}

// An infinite entry expires last, so it is not the one a full list drops while a finite one stands.
void test_eviction_prefers_a_finite_entry_over_an_infinite_one(void)
{
    static const uint8_t *const forever[1] = {g_a};
    static const uint8_t *const two[2] = {g_b, g_c};
    static const uint8_t *const fresh[1] = {g_d};
    Rdnss.clear(work_a);
    feed(work_a, IDEMIP_RDNSS_LIFETIME_INFINITE, 0u, forever, 1u);
    feed(work_a, 1000u, 0u, two, 2u);
    feed(work_a, 1000u, 0u, fresh, 1u);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->evicted);
    find_addr(work_a, g_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status, "the infinite entry was dropped before a finite one");
}

// --- expiry, sec 6.2 ---------------------------------------------------------

// sec 6.1: "When the current time becomes larger than Expiration-time, this entry is regarded as
// expired", and sec 6.2 deletes it.
void test_an_expired_entry_is_deleted(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    feed(work_a, 10u, 0u, one, 1u);

    tick_at(work_a, 9999u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);

    // sec 6.1 expires the entry when the current time becomes *larger* than Expiration-time, so at
    // exactly Expiration-time it still stands.
    tick_at(work_a, 10000u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IO(work_a)->status,
                                  "an entry expired at Expiration-time rather than past it");

    tick_at(work_a, 10001u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->expired);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(g_a, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN,
                                          "an expired server must still be readable so the resolver can drop it");
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
}

// The caller's reading is 32 bits and its wrap is not an event sec 6.1 knows about: "When the
// current time becomes larger than Expiration-time, this entry is regarded as expired" is one
// comparison on one clock, and the clock the entry was stamped on has to be the clock the sweep
// reads. A ten-second lifetime taken 4096 ms before the wrap expires 5904 ms after it.
void test_an_entry_stamped_before_the_clock_wraps_still_expires(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    feed(work_a, 10u, 0xFFFFF000u, one, 1u);

    // Still before the wrap, and still inside the lifetime.
    tick_at(work_a, 0xFFFFF001u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);

    // Past it. 0xFFFFF000 + 10000 is 5904 once the reading has turned over.
    tick_at(work_a, 5904u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IO(work_a)->status,
                                  "an entry expired at Expiration-time rather than past it");
    tick_at(work_a, 5905u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status,
                                  "the clock wrapping under an entry left it unable to expire");
    TEST_ASSERT_TRUE(IO(work_a)->expired);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
}

// sec 5.1 makes Lifetime "32-bit unsigned integer" in seconds and reserves only "all one bits
// (0xffffffff)" for infinity, so 5,000,000 seconds is a finite lifetime that has to expire. Its
// deadline is 5e9 milliseconds, which is past what 32 bits of milliseconds can count, so a sweep
// reading the caller's 32-bit clock can never reach it.
void test_a_lifetime_past_the_thirty_two_bit_millisecond_range_still_expires(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    feed(work_a, 5000000u, 0u, one, 1u);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->servers);

    tick_at(work_a, 0x80000000u); // 2.1e9 ms, inside the lifetime
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    tick_at(work_a, 1u); // the reading turns over: 4.3e9 ms, still inside it
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);

    tick_at(work_a, 0x80000000u); // 6.4e9 ms, past it
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status,
                                  "a finite lifetime past the 32-bit millisecond range never expired");
    TEST_ASSERT_TRUE(IO(work_a)->expired);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
}

// One expiry per call, so two entries due at once take two ticks and neither is lost.
void test_a_tick_reports_one_expiry_per_call(void)
{
    static const uint8_t *const two[2] = {g_a, g_b};
    Rdnss.clear(work_a);
    feed(work_a, 10u, 0u, two, 2u);

    tick_at(work_a, 10001u);
    TEST_ASSERT_TRUE(IO(work_a)->expired);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->servers);
    tick_at(work_a, 10001u);
    TEST_ASSERT_TRUE(IO(work_a)->expired);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->servers);
    tick_at(work_a, 10001u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
}

// A tick with nothing expired is BUSY: nothing is wrong, and a later tick makes progress.
void test_a_tick_with_nothing_expired_is_busy(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    feed(work_a, 1000u, 0u, one, 1u);
    tick_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
}

// An expiry closes the gap, so the order the survivors are asked in is the order they were in.
void test_an_expiry_closes_the_gap(void)
{
    static const uint8_t *const soon[1] = {g_a};
    static const uint8_t *const later[2] = {g_b, g_c};
    Rdnss.clear(work_a);
    feed(work_a, 10u, 0u, soon, 1u);
    feed(work_a, 1000u, 0u, later, 2u);
    // later's two went in at the head, so the list is b, c, a.
    get_slot(work_a, 2u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_a, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);

    tick_at(work_a, 10001u);
    TEST_ASSERT_TRUE(IO(work_a)->expired);
    TEST_ASSERT_EQUAL_UINT8(2u, IO(work_a)->servers);
    get_slot(work_a, 0u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_b, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
    get_slot(work_a, 1u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_c, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
    get_slot(work_a, 2u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// --- get, find and remove ----------------------------------------------------

void test_get_refuses_a_slot_that_holds_nothing(void)
{
    Rdnss.clear(work_a);
    get_slot(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    get_slot(work_a, (uint8_t)IDEMIP_RDNSS_SERVERS);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

void test_find_refuses_an_address_that_is_not_held(void)
{
    static const uint8_t *const one[1] = {g_a};
    Rdnss.clear(work_a);
    feed(work_a, 100u, 0u, one, 1u);
    find_addr(work_a, g_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->servers);
}

void test_remove_deletes_one_entry(void)
{
    static const uint8_t *const two[2] = {g_a, g_b};
    Rdnss.clear(work_a);
    feed(work_a, 100u, 0u, two, 2u);
    IO(work_a)->addr_args.addr = g_a;
    Rdnss.remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->servers);
    get_slot(work_a, 0u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_b, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
}

void test_remove_refuses_an_address_that_is_not_held(void)
{
    Rdnss.clear(work_a);
    IO(work_a)->addr_args.addr = g_a;
    Rdnss.remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}
