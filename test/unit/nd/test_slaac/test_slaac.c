// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The suite for slaac, modeled on test_phy. It tests two things and nothing else:
//
//   the contract
//     1. the borrow is the caller's, so the suite declares it and passes it to every entry
//     2. every entry is called with a null borrow and must refuse
//     3. the borrow IS the interface, so two interfaces share not one byte
//     4. a canary past IDEMIP_SLAAC_BORROW is intact after every case
//     5. the published offset map is ordered, aligned, and does not overlap
//     6. clear zeroes the regions, and a borrow no one cleared is refused
//     7. BUSY and ERR are separated by whether retrying can ever succeed
//
//   RFC 4862 sec 5.3, sec 5.5.3 (a) through (e), and sec 5.5.4
//     every rule the sections state, each case naming the sentence it holds to. sec 5.5.3 (e), the
//     two-hour rule, gets one case per branch and one for the attack it exists to stop.
//
// RFC 4862 prints no byte vectors. The one printed vector this unit touches is RFC 2464 sec 4's
// worked interface identifier, 34-56-78-9A-BC-DE giving 36-56-78-FF-FE-9A-BC-DE, which sec 5 appends
// to FE80::/64; that address is asserted directly. Everything else asserts the property the prose
// states.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/nd/slaac.h"

#include <string.h>
#include <unity.h>
#include "src/ip/ipv6_defines.h"

// The borrow, the caller's. Two of them, because RFC 4862 sec 5 performs autoconfiguration "on a
// per-interface basis". A canary follows each so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(IDEMIP_ALIGN) uint8_t work_a[IDEMIP_SLAAC_BORROW + 16];
static _Alignas(IDEMIP_ALIGN) uint8_t work_b[IDEMIP_SLAAC_BORROW + 16];

#define STATE_OFF ((size_t)IDEMIP_SLAAC_OFF_CTX)
#define TABLE_OFF ((size_t)IDEMIP_SLAAC_OFF_ENTRIES)
#define STATE_END ((size_t)IDEMIP_SLAAC_OFF_END)

#define IO(w) IDEMIP_SLAAC_IO(w)

#define HOUR_S 3600u
#define TWO_HOURS_S 7200u

// RFC 2464 sec 4: "the Interface Identifier for an Ethernet interface whose built-in address is, in
// hexadecimal, 34-56-78-9A-BC-DE would be 36-56-78-FF-FE-9A-BC-DE."
static const uint8_t g_iid[8] = {0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE};
static const uint8_t g_iid2[8] = {0x02, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x02};

// RFC 2464 sec 5: the link-local address is that identifier appended to FE80::/64.
static const uint8_t g_link_local[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0x80, 0,    0,    0,    0,    0,    0,
                                                          0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE};

// RFC 3849 reserves 2001:DB8::/32 for documentation.
static const uint8_t g_prefix[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t g_prefix2[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t g_formed[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0,    0,    0,    0x01,
                                                      0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE};
// RFC 4291 sec 2.5.6 gives the link-local prefix as FE80::/10.
static const uint8_t g_ll_prefix[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_SLAAC_BORROW, CANARY, cap - IDEMIP_SLAAC_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_SLAAC_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_SLAAC_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// Every entry, in namespace order, so a new one added to SlaacNs is added here too.
static void call_every_entry(uint8_t *w)
{
    Slaac.clear(w);
    Slaac.link_local(w);
    Slaac.prefix_in(w);
    Slaac.find(w);
    Slaac.get(w);
    Slaac.remove(w);
    Slaac.tick(w);
}

static void link_local(uint8_t *w, const uint8_t *iid, uint8_t iid_bits)
{
    IO(w)->link_local_args.iid = iid;
    IO(w)->link_local_args.iid_bits = iid_bits;
    Slaac.link_local(w);
}

typedef struct
{
    uint8_t *w;
    const uint8_t *prefix;
    uint8_t prefix_len;
    uint32_t valid_s;
    uint32_t preferred_s;
    uint32_t now_ms;
    idemip_bool autonomous;
    idemip_bool authenticated;
} FeedPrefixArgs;

static void feed_prefix_ctx(const FeedPrefixArgs *args)
{
    IO(args->w)->prefix_args.prefix = args->prefix;
    IO(args->w)->prefix_args.prefix_len = args->prefix_len;
    IO(args->w)->prefix_args.iid = g_iid;
    IO(args->w)->prefix_args.iid_bits = 64u;
    IO(args->w)->prefix_args.valid_s = args->valid_s;
    IO(args->w)->prefix_args.preferred_s = args->preferred_s;
    IO(args->w)->prefix_args.now_ms = args->now_ms;
    IO(args->w)->prefix_args.autonomous = args->autonomous;
    IO(args->w)->prefix_args.authenticated = args->authenticated;
    Slaac.prefix_in(args->w);
}

#define feed_prefix(...) IDEMIP_CALL(feed_prefix_ctx, FeedPrefixArgs, __VA_ARGS__)

static void tick_at(uint8_t *w, uint32_t now_ms)
{
    IO(w)->tick_args.now_ms = now_ms;
    Slaac.tick(w);
}

static void find_addr(uint8_t *w, const uint8_t *addr)
{
    IO(w)->addr_args.addr = addr;
    Slaac.find(w);
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
    Slaac.clear(work_a);
    Slaac.clear(work_b);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_TRUE(IO(work_a)->created);

    find_addr(work_b, g_formed);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_b)->status, "one borrow found the other's address");
    find_addr(work_a, g_formed);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// A call on one borrow reaches no byte of another, clear included, which is the widest-reaching entry
// this module has.
void test_clear_on_one_borrow_leaves_the_other_untouched(void)
{
    memset(work_b + STATE_OFF, 0xC3, STATE_END - STATE_OFF);
    Slaac.clear(work_a);
    for (size_t i = STATE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0xC3u, work_b[i], "clear on one borrow wrote into another");
    }
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    Slaac.clear(work_a);
    Slaac.clear(work_b);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    find_addr(work_a, g_formed);
    IdemIpMs first = IO(work_a)->valid_at;

    feed_prefix(work_b, g_prefix, 64u, 10u, 10u, 500u, IDEMIP_TRUE, IDEMIP_FALSE);
    find_addr(work_a, g_formed);
    TEST_ASSERT_EQUAL_UINT64(first, IO(work_a)->valid_at);
}

// --- the published map -------------------------------------------------------

void test_the_published_offsets_are_ordered_and_do_not_overlap(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_SLAAC_OFF_IO);
    TEST_ASSERT_TRUE_MESSAGE((size_t)IDEMIP_SLAAC_OFF_CTX >= sizeof(SlaacIo),
                             "the context starts inside the operand block");
    TEST_ASSERT_TRUE_MESSAGE(TABLE_OFF >= (size_t)IDEMIP_SLAAC_OFF_CTX, "the list starts before the context");
    TEST_ASSERT_EQUAL_size_t(TABLE_OFF + ((size_t)IDEMIP_IP6_ADDRESSES << IDEMIP_SLAAC_ENTRY_SHIFT), STATE_END);
    TEST_ASSERT_TRUE_MESSAGE(STATE_END <= (size_t)IDEMIP_SLAAC_BORROW, "the map runs past IDEMIP_SLAAC_BORROW");
}

void test_every_published_offset_is_aligned(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_SLAAC_OFF_CTX & (IDEMIP_ALIGN - 1u));
    TEST_ASSERT_EQUAL_size_t(0u, TABLE_OFF & (IDEMIP_ALIGN - 1u));
}

void test_the_io_macro_reaches_the_operand_block(void)
{
    TEST_ASSERT_EQUAL_PTR(work_a + IDEMIP_SLAAC_OFF_IO, (uint8_t *)IO(work_a));
    TEST_ASSERT_EQUAL_PTR(work_b + IDEMIP_SLAAC_OFF_IO, (uint8_t *)IO(work_b));
}

// --- clear -------------------------------------------------------------------

void test_clear_reports_ok(void)
{
    Slaac.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

void test_clear_zeroes_the_list(void)
{
    memset(work_a, 0xFF, IDEMIP_SLAAC_BORROW);
    Slaac.clear(work_a);
    for (size_t i = TABLE_OFF; i < STATE_END; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00u, work_a[i], "clear left a list byte set");
    }
}

void test_clear_zeroes_the_context_apart_from_the_mark(void)
{
    memset(work_a, 0xFF, IDEMIP_SLAAC_BORROW);
    Slaac.clear(work_a);
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
    Slaac.clear(work_a);
    IO(work_a)->prefix_args.prefix = g_prefix;
    IO(work_a)->prefix_args.prefix_len = 64u;
    Slaac.clear(work_a);
    TEST_ASSERT_EQUAL_PTR(g_prefix, IO(work_a)->prefix_args.prefix);
    TEST_ASSERT_EQUAL_UINT8(64u, IO(work_a)->prefix_args.prefix_len);
}

// A borrow no one cleared holds no mark, so every entry but clear refuses it.
void test_an_uncleared_borrow_is_refused(void)
{
    link_local(work_a, g_iid, 64u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    tick_at(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
    find_addr(work_a, g_formed);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// --- link-local addresses, sec 5.3 -------------------------------------------

// RFC 2464 sec 4 and sec 5, the one printed vector: the identifier for 34-56-78-9A-BC-DE appended to
// FE80::/64.
void test_the_link_local_address_is_the_rfc_2464_example(void)
{
    Slaac.clear(work_a);
    link_local(work_a, g_iid, 64u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->created);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_link_local, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
}

// sec 5.3: "A link-local address has an infinite preferred and valid lifetime; it is never timed
// out."
void test_the_link_local_address_has_infinite_lifetimes(void)
{
    Slaac.clear(work_a);
    link_local(work_a, g_iid, 64u);
    TEST_ASSERT_TRUE(IO(work_a)->valid_infinite);
    TEST_ASSERT_TRUE(IO(work_a)->preferred_infinite);
    TEST_ASSERT_EQUAL_INT(IDEMIP_SLAAC_ADDR_PREFERRED, IO(work_a)->state);

    // Which no tick ever ages, however far the clock runs.
    tick_at(work_a, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
    find_addr(work_a, g_link_local);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// sec 5.3 step 1: "The left-most 'prefix length' bits of the address are those of the link-local
// prefix", which RFC 4291 sec 2.5.6 gives as 1111111010, and step 2 zeroes what lies between.
void test_the_link_local_address_carries_the_prefix_and_zeroes_between(void)
{
    Slaac.clear(work_a);
    link_local(work_a, g_iid, 64u);
    TEST_ASSERT_EQUAL_HEX8(0xFEu, IO(work_a)->addr[0]);
    TEST_ASSERT_EQUAL_HEX8(0x80u, IO(work_a)->addr[1]);
    for (size_t i = 2; i < 8; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00u, IO(work_a)->addr[i], "sec 5.3 zeroes the bits below the prefix");
    }
}

void test_link_local_refuses_a_null_identifier(void)
{
    Slaac.clear(work_a);
    link_local(work_a, NULL, 64u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// An identifier that is not whole octets cannot be laid into an address held as octets, and a retry
// with the same length cannot change that.
void test_link_local_refuses_an_identifier_that_is_not_whole_octets(void)
{
    Slaac.clear(work_a);
    link_local(work_a, g_iid, 63u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// sec 5.3: "If the sum of the link-local prefix length and N is larger than 128, autoconfiguration
// fails and manual configuration is required."
void test_link_local_refuses_an_identifier_the_prefix_has_no_room_for(void)
{
    Slaac.clear(work_a);
    link_local(work_a, g_iid, 120u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// The same interface enabled twice holds one address, not two.
void test_link_local_twice_holds_one_address(void)
{
    Slaac.clear(work_a);
    link_local(work_a, g_iid, 64u);
    TEST_ASSERT_TRUE(IO(work_a)->created);
    link_local(work_a, g_iid, 64u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE(IO(work_a)->created);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->addresses);
}

// --- sec 5.5.3 (a), (b), (c) -------------------------------------------------

// (a) "If the Autonomous flag is not set, silently ignore the Prefix Information option."
void test_a_prefix_without_the_autonomous_flag_is_ignored(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_FALSE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_FALSE(IO(work_a)->created);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->addresses);
}

// (b) "If the prefix is the link-local prefix, silently ignore the Prefix Information option."
void test_the_link_local_prefix_is_ignored(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_ll_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->addresses);
}

// (c) "If the preferred lifetime is greater than the valid lifetime, silently ignore the Prefix
// Information option."
void test_a_preferred_lifetime_above_the_valid_lifetime_is_ignored(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S + 1u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->addresses);
}

// --- sec 5.5.3 (d), forming an address ---------------------------------------

// (d) forms the address by "combining the advertised prefix with an interface identifier of the
// link", the prefix over the left 128 - N bits and the identifier over the right N.
void test_a_new_prefix_forms_the_address_from_the_prefix_and_the_identifier(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->created);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_formed, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
    TEST_ASSERT_EQUAL_UINT8(64u, IO(work_a)->prefix_len);
}

// (d) "initializing its preferred and valid lifetime values from the Prefix Information option".
void test_the_lifetimes_are_initialized_from_the_option(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, TWO_HOURS_S, HOUR_S, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_UINT32(1000u + (TWO_HOURS_S * 1000u), IO(work_a)->valid_at);
    TEST_ASSERT_EQUAL_UINT32(1000u + (HOUR_S * 1000u), IO(work_a)->preferred_at);
    TEST_ASSERT_EQUAL_INT(IDEMIP_SLAAC_ADDR_PREFERRED, IO(work_a)->state);
}

// (d) forms an address only "if the Valid Lifetime is not 0".
void test_a_new_prefix_with_a_zero_valid_lifetime_is_ignored(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 0u, 0u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->addresses);
}

// (d) "If the sum of the prefix length and interface identifier length does not equal 128 bits, the
// Prefix Information option MUST be ignored."
void test_a_prefix_length_that_does_not_sum_to_128_is_ignored(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 48u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->addresses);

    feed_prefix(work_a, g_prefix, 96u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_TRUE(IO(work_a)->ignored);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->addresses);
}

// RFC 4861 sec 4.6.2 puts Prefix Length "from 0 to 128", so a field above that is not one this unit
// can match or form on, and a retry cannot fix it.
void test_a_prefix_length_past_128_is_refused(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 129u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// A list with no free slot is BUSY, because a removal or an expiry frees one and the same call then
// succeeds.
void test_a_full_list_is_busy_and_a_removal_frees_a_slot(void)
{
    Slaac.clear(work_a);
    uint8_t prefix[IDEMIP_IP6_ADDR_LEN];
    memcpy(prefix, g_prefix, sizeof prefix);
    for (uint8_t i = 0; i < (uint8_t)IDEMIP_IP6_ADDRESSES; i++)
    {
        prefix[7] = (uint8_t)(0x10u + i);
        feed_prefix(work_a, prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
        TEST_ASSERT_TRUE(IO(work_a)->created);
    }
    prefix[7] = 0xEE;
    feed_prefix(work_a, prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);

    uint8_t held[IDEMIP_IP6_ADDR_LEN];
    memcpy(held, g_formed, sizeof held);
    held[7] = 0x10u;
    IO(work_a)->addr_args.addr = held;
    Slaac.remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    prefix[7] = 0xEE;
    feed_prefix(work_a, prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->created);
}

// Two prefixes are two addresses, and neither disturbs the other.
void test_two_prefixes_are_two_addresses(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    feed_prefix(work_a, g_prefix2, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_TRUE(IO(work_a)->created);
    TEST_ASSERT_EQUAL_UINT8(2u, IO(work_a)->addresses);
}

// --- sec 5.5.3 (e), the two-hour rule ----------------------------------------

// (e) opens: "If the advertised prefix is equal to the prefix of an address configured by stateless
// autoconfiguration in the list", which is the same prefix length and the same leading bits, so the
// second advertisement updates rather than adding.
void test_the_same_prefix_updates_rather_than_adding(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_TRUE(IO(work_a)->created);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->updated);
    TEST_ASSERT_FALSE(IO(work_a)->created);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->addresses);
}

// sec 5.5.3 (d) initializes the lifetimes "from the Prefix Information option", and RFC 4861 sec
// 4.6.2 reserves only all-ones for infinity, so every other 32-bit value is a finite lifetime a
// router may advertise. The sec 6.2.1 defaults are 2592000 s valid and 604800 s preferred, both past
// what a 32-bit millisecond deadline could hold, and both must be kept whole.
void test_a_lifetime_past_a_32_bit_millisecond_deadline_is_kept_whole(void)
{
    const uint32_t valid_s = 2592000u;    // sec 6.2.1 AdvValidLifetime, 30 days
    const uint32_t preferred_s = 604800u; // sec 6.2.1 AdvPreferredLifetime, 7 days

    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, valid_s, preferred_s, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->created);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE((IdemIpMs)valid_s * 1000u, IO(work_a)->valid_at,
                                     "the advertised Valid Lifetime was truncated");
    TEST_ASSERT_EQUAL_UINT64_MESSAGE((IdemIpMs)preferred_s * 1000u, IO(work_a)->preferred_at,
                                     "the advertised Preferred Lifetime was truncated");

    // 28.9 days in, past the 24.86-day bound a 32-bit deadline forced, the address is still held.
    tick_at(work_a, 2500000000u);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->invalidated, "the address went invalid before its lifetime");

    // At 30 days it is invalidated.
    tick_at(work_a, 2592000000u);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->invalidated, "the address outlived its valid lifetime");
}

// (e): "the preferred lifetime of the corresponding address is always reset to the Preferred Lifetime
// in the received Prefix Information option, regardless of whether the valid lifetime is also reset
// or ignored".
void test_the_preferred_lifetime_is_always_reset(void)
{
    Slaac.clear(work_a);
    // Ten minutes valid, so the valid lifetime below takes rule 2 and is ignored.
    feed_prefix(work_a, g_prefix, 64u, 600u, 600u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    IdemIpMs held_valid = IO(work_a)->valid_at;

    feed_prefix(work_a, g_prefix, 64u, 300u, 120u, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_TRUE(IO(work_a)->two_hour);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(held_valid, IO(work_a)->valid_at, "rule 2 must leave the valid lifetime alone");
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(1000u + (120u * 1000u), IO(work_a)->preferred_at,
                                     "the preferred lifetime is reset whatever the valid lifetime does");
}

// (e) 1: "If the received Valid Lifetime is greater than 2 hours ... set the valid lifetime of the
// corresponding address to the advertised Valid Lifetime."
void test_rule_1_a_valid_lifetime_above_two_hours_is_taken(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 600u, 600u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    feed_prefix(work_a, g_prefix, 64u, TWO_HOURS_S + 1u, 600u, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_UINT32(1000u + ((TWO_HOURS_S + 1u) * 1000u), IO(work_a)->valid_at);
    TEST_ASSERT_FALSE(IO(work_a)->two_hour);
}

// (e) 1, the other half: "or greater than RemainingLifetime". One hour is under two hours, but it is
// more than the ten minutes left, so it is taken.
void test_rule_1_a_valid_lifetime_above_the_remaining_lifetime_is_taken(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 600u, 600u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, 600u, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_UINT32(1000u + (HOUR_S * 1000u), IO(work_a)->valid_at);
    TEST_ASSERT_FALSE(IO(work_a)->two_hour);
}

// (e) 2: "If RemainingLifetime is less than or equal to 2 hours, ignore the Prefix Information option
// with regards to the valid lifetime". Ten minutes remain and five are advertised, so the five are
// ignored.
void test_rule_2_a_shorter_lifetime_is_ignored_when_under_two_hours_remain(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 600u, 600u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    IdemIpMs held = IO(work_a)->valid_at;
    feed_prefix(work_a, g_prefix, 64u, 300u, 300u, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(held, IO(work_a)->valid_at, "a short lifetime cut an address that was expiring");
    TEST_ASSERT_TRUE(IO(work_a)->two_hour);
}

// (e) 2's one exception: "unless the Router Advertisement from which this option was obtained has
// been authenticated ... the valid lifetime of the corresponding address should be set to the Valid
// Lifetime in the received option."
void test_rule_2_an_authenticated_advertisement_sets_the_shorter_lifetime(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 600u, 600u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    feed_prefix(work_a, g_prefix, 64u, 300u, 300u, 1000u, IDEMIP_TRUE, IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_UINT32(1000u + (300u * 1000u), IO(work_a)->valid_at);
    TEST_ASSERT_FALSE(IO(work_a)->two_hour);
}

// (e) 3: "Otherwise, reset the valid lifetime of the corresponding address to 2 hours." Ten hours
// remain, five minutes are advertised, and neither rule 1 nor rule 2 applies.
void test_rule_3_a_short_lifetime_against_a_long_one_resets_to_two_hours(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 10u * HOUR_S, 10u * HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    feed_prefix(work_a, g_prefix, 64u, 300u, 300u, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_UINT32(1000u + (uint32_t)IDEMIP_SLAAC_TWO_HOURS_MS, IO(work_a)->valid_at);
    TEST_ASSERT_TRUE(IO(work_a)->two_hour);
}

// (e) 3 again with the boundary the section names: a valid lifetime of exactly 2 hours is not
// "greater than 2 hours", so rule 1's first half does not fire.
void test_rule_3_holds_at_exactly_two_hours(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 10u * HOUR_S, 10u * HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    feed_prefix(work_a, g_prefix, 64u, TWO_HOURS_S, TWO_HOURS_S, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_UINT32(1000u + (uint32_t)IDEMIP_SLAAC_TWO_HOURS_MS, IO(work_a)->valid_at);
    TEST_ASSERT_TRUE(IO(work_a)->two_hour);
}

// The rules exist for this: "a bogus advertisement could contain prefixes with very small Valid
// Lifetimes ... could cause all of a node's addresses to expire prematurely". A single unauthenticated
// advertisement of one second must not bring a ten-hour address down to one second.
void test_the_two_hour_rule_stops_an_advertisement_expiring_an_address_early(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 10u * HOUR_S, 10u * HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    feed_prefix(work_a, g_prefix, 64u, 1u, 1u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_TRUE(IO(work_a)->two_hour);

    // A second later the address is deprecated, the preferred lifetime always being taken, but it is
    // still valid and still in the list. That is the whole point of the rule.
    tick_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->deprecated);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->invalidated, "one bogus advertisement invalidated the address");
    find_addr(work_a, g_formed);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)IDEMIP_SLAAC_TWO_HOURS_MS, IO(work_a)->valid_at);
}

// RFC 4861 sec 4.6.2: a Valid Lifetime "of all one bits (0xffffffff) represents infinity", which is
// greater than 2 hours and so takes rule 1.
void test_rule_1_an_infinite_valid_lifetime_is_taken(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    feed_prefix(work_a, g_prefix, 64u, IDEMIP_SLAAC_LIFETIME_INFINITE, HOUR_S, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_TRUE(IO(work_a)->valid_infinite);
    TEST_ASSERT_FALSE(IO(work_a)->two_hour);
}

// An infinite RemainingLifetime is neither below a finite received lifetime nor at or under 2 hours,
// so a short advertisement against it lands on rule 3, which is what the section states.
void test_a_short_lifetime_against_an_infinite_one_resets_to_two_hours(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, IDEMIP_SLAAC_LIFETIME_INFINITE, IDEMIP_SLAAC_LIFETIME_INFINITE, 0u, IDEMIP_TRUE,
                IDEMIP_FALSE);
    TEST_ASSERT_TRUE(IO(work_a)->valid_infinite);
    feed_prefix(work_a, g_prefix, 64u, 300u, 300u, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_FALSE(IO(work_a)->valid_infinite);
    TEST_ASSERT_EQUAL_UINT32(1000u + (uint32_t)IDEMIP_SLAAC_TWO_HOURS_MS, IO(work_a)->valid_at);
    TEST_ASSERT_TRUE(IO(work_a)->two_hour);
}

// A zero Valid Lifetime on a prefix already in the list is not (d)'s "not 0" test: it is (e), and it
// takes the same three rules, so it cannot invalidate the address on the spot.
void test_a_zero_valid_lifetime_on_a_held_prefix_takes_the_two_hour_rule(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 10u * HOUR_S, 10u * HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    feed_prefix(work_a, g_prefix, 64u, 0u, 0u, 1000u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_TRUE(IO(work_a)->updated);
    TEST_ASSERT_EQUAL_UINT32(1000u + (uint32_t)IDEMIP_SLAAC_TWO_HOURS_MS, IO(work_a)->valid_at);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_SLAAC_ADDR_DEPRECATED, IO(work_a)->state,
                                  "a zero preferred lifetime deprecates the address at once");
}

// --- sec 5.5.4, lifetime expiry ----------------------------------------------

// "A preferred address becomes deprecated when its preferred lifetime expires."
void test_a_preferred_lifetime_expiry_deprecates_the_address(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, 10u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    tick_at(work_a, 9999u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);

    tick_at(work_a, 10000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->deprecated);
    TEST_ASSERT_EQUAL_INT(IDEMIP_SLAAC_ADDR_DEPRECATED, IO(work_a)->state);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_formed, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);

    // Deprecation fires once, not on every later tick.
    tick_at(work_a, 20000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
}

// "An address (and its association with an interface) becomes invalid when its valid lifetime
// expires", and sec 2 makes an invalid address "an address that is not assigned to any interface".
void test_a_valid_lifetime_expiry_invalidates_the_address_and_frees_the_slot(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 10u, 10u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    tick_at(work_a, 10000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE(IO(work_a)->invalidated);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(g_formed, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN,
                                          "an invalidated address must still be readable");
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->addresses);

    find_addr(work_a, g_formed);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// A tick with no lifetime reached is BUSY: nothing is wrong, and a later tick makes progress.
void test_a_tick_with_nothing_due_is_busy(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    tick_at(work_a, 1000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
}

// One event per call, so two addresses due at once take two ticks and neither is lost.
void test_a_tick_reports_one_event_per_call(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 10u, 10u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    feed_prefix(work_a, g_prefix2, 64u, 10u, 10u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_UINT8(2u, IO(work_a)->addresses);

    tick_at(work_a, 10000u);
    TEST_ASSERT_TRUE(IO(work_a)->invalidated);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->addresses);
    tick_at(work_a, 10000u);
    TEST_ASSERT_TRUE(IO(work_a)->invalidated);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->addresses);
    tick_at(work_a, 10000u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IO(work_a)->status);
}

// sec 5.5.4 makes the valid lifetime the outer one, so a slot with both expired is invalidated rather
// than deprecated.
void test_both_lifetimes_expired_invalidates_rather_than_deprecating(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, 10u, 5u, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    tick_at(work_a, 10000u);
    TEST_ASSERT_TRUE(IO(work_a)->invalidated);
    TEST_ASSERT_FALSE(IO(work_a)->deprecated);
}

// --- find, get and remove ----------------------------------------------------

void test_find_refuses_an_address_that_is_not_in_the_list(void)
{
    Slaac.clear(work_a);
    find_addr(work_a, g_formed);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

void test_get_walks_the_list(void)
{
    Slaac.clear(work_a);
    link_local(work_a, g_iid, 64u);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);

    IO(work_a)->addr_args.index = 0u;
    Slaac.get(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_link_local, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);

    IO(work_a)->addr_args.index = 1u;
    Slaac.get(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_formed, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);
}

void test_get_refuses_a_slot_that_holds_nothing(void)
{
    Slaac.clear(work_a);
    IO(work_a)->addr_args.index = 0u;
    Slaac.get(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);

    IO(work_a)->addr_args.index = (uint8_t)IDEMIP_IP6_ADDRESSES;
    Slaac.get(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

void test_remove_refuses_an_address_that_is_not_in_the_list(void)
{
    Slaac.clear(work_a);
    IO(work_a)->addr_args.addr = g_formed;
    Slaac.remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IO(work_a)->status);
}

// A removed address is gone, and its prefix forms it again from scratch.
void test_remove_frees_the_slot(void)
{
    Slaac.clear(work_a);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    IO(work_a)->addr_args.addr = g_formed;
    Slaac.remove(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IO(work_a)->addresses);

    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);
    TEST_ASSERT_TRUE(IO(work_a)->created);
}

// A different interface identifier on the same prefix is a different address, which is what (d)
// forms, so the two lists hold different addresses from the same advertisement.
void test_two_interfaces_form_their_own_addresses(void)
{
    Slaac.clear(work_a);
    Slaac.clear(work_b);
    feed_prefix(work_a, g_prefix, 64u, HOUR_S, HOUR_S, 0u, IDEMIP_TRUE, IDEMIP_FALSE);

    IO(work_b)->prefix_args.prefix = g_prefix;
    IO(work_b)->prefix_args.prefix_len = 64u;
    IO(work_b)->prefix_args.iid = g_iid2;
    IO(work_b)->prefix_args.iid_bits = 64u;
    IO(work_b)->prefix_args.valid_s = HOUR_S;
    IO(work_b)->prefix_args.preferred_s = HOUR_S;
    IO(work_b)->prefix_args.now_ms = 0u;
    IO(work_b)->prefix_args.autonomous = IDEMIP_TRUE;
    IO(work_b)->prefix_args.authenticated = IDEMIP_FALSE;
    Slaac.prefix_in(work_b);
    TEST_ASSERT_TRUE(IO(work_b)->created);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(g_iid2, IO(work_b)->addr + 8, 8);
    find_addr(work_b, g_formed);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_b)->status, "one interface holds the other's address");
}

// --- the fields an option arrives with -----------------------------------------

// RFC 4861 sec 4.6.2 puts Prefix Length "from 0 to 128", so a longer one is not that field at all,
// and an option with no prefix in it is not a Prefix Information option. Neither can become one on a
// later advertisement, so both are ERR rather than sec 5.5.3's silent ignore.
void test_a_prefix_option_outside_its_own_fields_is_refused(void)
{
    Slaac.clear(work_a);

    feed_prefix(.w = work_a, .prefix = g_prefix, .prefix_len = 129u, .valid_s = 100u, .preferred_s = 100u,
                .now_ms = 1000u, .autonomous = IDEMIP_TRUE, .authenticated = IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "a Prefix Length past 128 was taken");

    feed_prefix(.w = work_a, .prefix = NULL, .prefix_len = 64u, .valid_s = 100u, .preferred_s = 100u, .now_ms = 1000u,
                .autonomous = IDEMIP_TRUE, .authenticated = IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "an option with no prefix was taken");
}

// RFC 4291 sec 2.5.6: the link-local prefix is "1111111010" followed by 54 zero bits, so the ten bits
// are the test and not the first octet alone. FEC0::/10 carries the same first octet and is not it.
void test_the_link_local_prefix_is_the_first_ten_bits_and_not_the_first_octet(void)
{
    Slaac.clear(work_a);

    static const uint8_t site_local[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    feed_prefix(.w = work_a, .prefix = site_local, .prefix_len = 64u, .valid_s = 100u, .preferred_s = 100u,
                .now_ms = 1000u, .autonomous = IDEMIP_TRUE, .authenticated = IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_FALSE_MESSAGE(IO(work_a)->ignored,
                              "a prefix sharing the link-local first octet was read as link-local");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IO(work_a)->addresses, "no address was formed on the prefix");
}

// RFC 4862 sec 5.3: "If the sum of the link-local prefix length and N is larger than 128,
// autoconfiguration fails and manual configuration is required." An identifier this unit can lay
// into an address arrives as whole octets and is not nothing, so a prefix that leaves room for one
// but names none, or names one measured in bits that are not octets, forms no address.
void test_an_identifier_this_unit_cannot_lay_into_an_address_forms_none(void)
{
    Slaac.clear(work_a);

    // The sum is right and there is no identifier.
    IO(work_a)->prefix_args.prefix = g_prefix;
    IO(work_a)->prefix_args.prefix_len = 64u;
    IO(work_a)->prefix_args.iid = NULL;
    IO(work_a)->prefix_args.iid_bits = 64u;
    IO(work_a)->prefix_args.valid_s = 100u;
    IO(work_a)->prefix_args.preferred_s = 100u;
    IO(work_a)->prefix_args.now_ms = 1000u;
    IO(work_a)->prefix_args.autonomous = IDEMIP_TRUE;
    IO(work_a)->prefix_args.authenticated = IDEMIP_TRUE;
    Slaac.prefix_in(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "an address was formed with no identifier");

    // The sum is right and the identifier is measured in bits that are not whole octets.
    IO(work_a)->prefix_args.prefix_len = 63u;
    IO(work_a)->prefix_args.iid = g_iid;
    IO(work_a)->prefix_args.iid_bits = 65u;
    Slaac.prefix_in(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status,
                                  "an identifier that is not whole octets was laid into an address");
}

// RFC 4862 sec 5.5.3 (d): "If an address is formed successfully and the address is not yet in the
// list, the host adds it to the list." One that is already there is the address it already is, so it
// is reported rather than added twice - and two options can form it, since the prefix length and the
// identifier length only have to sum to 128.
void test_an_address_already_in_the_list_is_reported_rather_than_added_twice(void)
{
    Slaac.clear(work_a);

    feed_prefix(.w = work_a, .prefix = g_prefix, .prefix_len = 64u, .valid_s = 100u, .preferred_s = 100u,
                .now_ms = 1000u, .autonomous = IDEMIP_TRUE, .authenticated = IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(1u, IO(work_a)->addresses);
    uint8_t formed[IDEMIP_IP6_ADDR_LEN];
    memcpy(formed, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN);

    // The same address, out of a shorter prefix and a longer identifier: the option is a new one to
    // the list, and the address it forms is not.
    uint8_t wide_iid[IDEMIP_IP6_ADDR_LEN];
    memcpy(wide_iid, &formed[IDEMIP_IP6_ADDR_LEN - 9u], 9u);
    IO(work_a)->prefix_args.prefix = g_prefix;
    IO(work_a)->prefix_args.prefix_len = 56u;
    IO(work_a)->prefix_args.iid = wide_iid;
    IO(work_a)->prefix_args.iid_bits = 72u;
    IO(work_a)->prefix_args.valid_s = 100u;
    IO(work_a)->prefix_args.preferred_s = 100u;
    IO(work_a)->prefix_args.now_ms = 1000u;
    IO(work_a)->prefix_args.autonomous = IDEMIP_TRUE;
    IO(work_a)->prefix_args.authenticated = IDEMIP_TRUE;
    Slaac.prefix_in(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(formed, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN,
                                         "the second option formed a different address");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IO(work_a)->addresses, "an address already in the list was added twice");
}

// The list is finite, and RFC 4862 sec 5.5.3 (e) frees a slot when a valid lifetime runs out, so a
// full list is BUSY rather than ERR: the room the caller asked for arrives on a later tick.
void test_a_full_list_is_busy_for_a_link_local_address(void)
{
    Slaac.clear(work_a);

    uint8_t iid[8];
    memcpy(iid, g_iid, sizeof iid);
    for (uint8_t k = 0u; k < (uint8_t)IDEMIP_IP6_ADDRESSES; k++)
    {
        iid[7] = (uint8_t)(0x10u + k);
        link_local(work_a, iid, 64u);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IO(work_a)->status, "a link-local address was refused a free slot");
    }

    iid[7] = 0xEEu;
    link_local(work_a, iid, 64u);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_BUSY, IO(work_a)->status, "a full list was ERR rather than BUSY");
}

// RFC 4862 sec 5.5.3 (d) looks for the prefix "in the list", and the list holds the link-local
// prefix of RFC 4291 sec 2.5.6 too - which is ten bits, so the comparison is over one whole octet
// and two bits of the next. A prefix that shares the octet and differs inside those two bits is not
// the same prefix.
void test_a_prefix_is_compared_over_the_bits_its_length_names(void)
{
    Slaac.clear(work_a);
    link_local(work_a, g_iid, 64u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    // Same first octet as the link-local prefix, different second: the two bits are what separate
    // them, and this is not link-local, so it is not silently ignored on the way in either.
    static const uint8_t near_ll[IDEMIP_IP6_ADDR_LEN] = {0xFE, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    feed_prefix(.w = work_a, .prefix = near_ll, .prefix_len = 10u, .valid_s = 100u, .preferred_s = 100u,
                .now_ms = 1000u, .autonomous = IDEMIP_TRUE, .authenticated = IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->ignored, "a prefix of ten bits and an identifier of 118 formed an address");

    // A prefix of no bits at all is compared over no octets, and 128 bits of identifier is the whole
    // address: sec 5.3's sum is met, so this one does form.
    static const uint8_t any[IDEMIP_IP6_ADDR_LEN] = {0};
    static const uint8_t whole_iid[IDEMIP_IP6_ADDR_LEN] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0x02,
                                                           0,    0,    0,    0,    0, 0, 0, 0x01};
    IO(work_a)->prefix_args.prefix = any;
    IO(work_a)->prefix_args.prefix_len = 0u;
    IO(work_a)->prefix_args.iid = whole_iid;
    IO(work_a)->prefix_args.iid_bits = 128u;
    IO(work_a)->prefix_args.valid_s = 100u;
    IO(work_a)->prefix_args.preferred_s = 100u;
    IO(work_a)->prefix_args.now_ms = 1000u;
    IO(work_a)->prefix_args.autonomous = IDEMIP_TRUE;
    IO(work_a)->prefix_args.authenticated = IDEMIP_TRUE;
    Slaac.prefix_in(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(whole_iid, IO(work_a)->addr, IDEMIP_IP6_ADDR_LEN,
                                         "128 bits of identifier did not form the whole address");

    // The same option again finds that prefix in the list, over no octets and no bits.
    Slaac.prefix_in(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(2u, IO(work_a)->addresses, "the prefix of no bits was added twice");
}

// RFC 4862 sec 5.3 needs an identifier to form an address with, and one of no bits is none.
void test_an_identifier_of_no_bits_forms_no_address(void)
{
    Slaac.clear(work_a);

    IO(work_a)->prefix_args.prefix = g_prefix;
    IO(work_a)->prefix_args.prefix_len = 128u;
    IO(work_a)->prefix_args.iid = g_iid;
    IO(work_a)->prefix_args.iid_bits = 0u;
    IO(work_a)->prefix_args.valid_s = 100u;
    IO(work_a)->prefix_args.preferred_s = 100u;
    IO(work_a)->prefix_args.now_ms = 1000u;
    IO(work_a)->prefix_args.autonomous = IDEMIP_TRUE;
    IO(work_a)->prefix_args.authenticated = IDEMIP_TRUE;
    Slaac.prefix_in(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "an identifier of no bits formed an address");
}

// An address is looked up by the address, a slot by its index, and a removal by the address again:
// each entry reads what it was given, so a call that names nothing is refused rather than answered
// from whatever slot was there.
void test_the_address_entries_refuse_what_names_no_address(void)
{
    Slaac.clear(work_a);
    link_local(work_a, g_iid, 64u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);

    IO(work_a)->addr_args.addr = NULL;
    Slaac.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "a lookup for no address was answered");
    Slaac.remove(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "a removal of no address was made");

    IO(work_a)->addr_args.index = (uint8_t)IDEMIP_IP6_ADDRESSES;
    Slaac.get(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "a slot past the list was read");

    // A slot inside the list that nobody has taken is not an address either.
    IO(work_a)->addr_args.index = (uint8_t)(IDEMIP_IP6_ADDRESSES - 1u);
    Slaac.get(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "a slot nobody took was read as an address");

    // The one that was taken reads back, with the lifetime it has left rather than none.
    IO(work_a)->addr_args.index = 0u;
    Slaac.get(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
}

// Bytes clear has not run on are not a list, so every entry refuses them rather than reading an
// address out of whatever was there.
void test_the_address_entries_refuse_an_uncleared_borrow(void)
{
    memset(work_a, 0xFF, IDEMIP_SLAAC_BORROW);
    IO(work_a)->addr_args.addr = g_prefix;
    IO(work_a)->addr_args.index = 0u;
    Slaac.find(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "find read an uncleared borrow");
    Slaac.get(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "get read an uncleared borrow");
    Slaac.remove(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_ERR, IO(work_a)->status, "remove read an uncleared borrow");
}

// RFC 4862 sec 5.5.3 (e) compares the received Valid Lifetime against "the remaining time to the
// valid lifetime expiration of the previously autoconfigured address", which it calls
// "RemainingLifetime". An address whose lifetime is already behind it has none remaining. The sweep that removes such an
// address runs on a tick, so an advertisement arriving before that tick meets it still in the list
// with nothing left - which is at or under two hours, so rule 3 is what the option takes.
void test_an_advertisement_meeting_an_address_with_nothing_left_takes_the_two_hour_rule(void)
{
    Slaac.clear(work_a);

    feed_prefix(.w = work_a, .prefix = g_prefix, .prefix_len = 64u, .valid_s = 100u, .preferred_s = 100u,
                .now_ms = 1000u, .autonomous = IDEMIP_TRUE, .authenticated = IDEMIP_TRUE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    const IdemIpMs first_at = IO(work_a)->valid_at;

    // The same prefix again, past the lifetime the first one set, carrying a lifetime under two
    // hours and no authentication: rule 3 puts the address at two hours rather than at that value.
    feed_prefix(.w = work_a, .prefix = g_prefix, .prefix_len = 64u, .valid_s = 100u, .preferred_s = 100u,
                .now_ms = 1000u + (200u * 1000u), .autonomous = IDEMIP_TRUE, .authenticated = IDEMIP_FALSE);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IO(work_a)->status);
    TEST_ASSERT_TRUE_MESSAGE(IO(work_a)->valid_at > first_at,
                             "an advertisement meeting an address with nothing left did not move its lifetime");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1u, IO(work_a)->addresses, "the address was formed a second time");
}
