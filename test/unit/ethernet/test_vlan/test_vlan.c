// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The IEEE 802.1Q C-Tag. The suite checks the four things every unit's suite checks:
//
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//
// VECTORS. IEEE Std 802.1Q is not readable without purchase, so nothing here is asserted against it
// and no clause of it is cited. The open documents that state the layout print figures and no
// numbered example bytes, so what is asserted below is the properties their text states:
//
//   - RFC 7042 Appendix B.2: "0x8100  IEEE Std 802.1Q  - Customer VLAN Tag Type (C-Tag, formerly
//     called the Q-Tag)"
//   - RFC 6325 sec 4.1 Figure 7: the two MAC addresses, then "Ethertype = C-Tag [802.1Q-2005] |
//     Inner.VLAN Tag Information", then "Ethertype of Original Payload"
//   - RFC 6325 sec 4.1.1 Figure 8: "Priority | C | VLAN ID", three bits, one bit, twelve bits; "the
//     priority field contains an unsigned value from 0 through 7"; "VLAN ID zero is the null VLAN
//     identifier"; "VLAN ID 0xFFF is reserved" and "MUST NOT be used"
//
// Every tag byte string below is composed here from those rules, not copied from a document.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/ethernet/vlan.h"

#include <string.h>
#include <unity.h>

// The borrow, the caller's. Two of them, because the borrow is the instance. A canary follows each
// so a write past the map is visible.
#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_VLAN_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_VLAN_BORROW + 16];

// A frame, the caller's too, with its own canary past the octets a build may touch.
#define FRAME_BYTES 32u
#define FRAME_CANARY 0xC3u
static uint8_t frame[FRAME_BYTES + 8];

static const uint8_t dst_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
static const uint8_t src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_VLAN_BORROW, CANARY, cap - IDEMIP_VLAN_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_VLAN_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_VLAN_BORROW");
    }
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(frame, 0, FRAME_BYTES);
    memset(frame + FRAME_BYTES, FRAME_CANARY, sizeof frame - FRAME_BYTES);
    memcpy(frame + IDEMIP_ETH_OFF_DST, dst_mac, 6);
    memcpy(frame + IDEMIP_ETH_OFF_SRC, src_mac, 6);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
    for (size_t i = FRAME_BYTES; i < sizeof frame; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(FRAME_CANARY, frame[i], "a write landed past the caller's frame");
    }
}

static void ready(uint8_t *w)
{
    Vlan.clear(w);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(w)->status);
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

// An untagged frame carrying @p type.
static void make_untagged(uint16_t type)
{
    put16(frame + IDEMIP_ETH_OFF_TYPE, type);
}

// A tagged frame: the C-Tag Ethertype, the Tag Control Information, then the payload's own type.
static void make_tagged(uint16_t tci, uint16_t type)
{
    put16(frame + IDEMIP_VLAN_OFF_TPID, (uint16_t)IDEMIP_VLAN_TPID);
    put16(frame + IDEMIP_VLAN_OFF_TCI, tci);
    put16(frame + IDEMIP_VLAN_OFF_TYPE, type);
}

static void parse_frame(uint8_t *w, size_t len)
{
    IDEMIP_VLAN_IO(w)->parse_args.frame = frame;
    IDEMIP_VLAN_IO(w)->parse_args.len = len;
    Vlan.parse(w);
}

static void build_tag(uint8_t *w, uint8_t pcp, idemip_bool dei, uint16_t vid, uint16_t type)
{
    IDEMIP_VLAN_IO(w)->build_args.frame = frame;
    IDEMIP_VLAN_IO(w)->build_args.type = type;
    IDEMIP_VLAN_IO(w)->tag_args.pcp = pcp;
    IDEMIP_VLAN_IO(w)->tag_args.dei = dei;
    IDEMIP_VLAN_IO(w)->tag_args.vid = vid;
    Vlan.build(w);
}

static void pack_tag(uint8_t *w, uint8_t pcp, idemip_bool dei, uint16_t vid)
{
    IDEMIP_VLAN_IO(w)->tag_args.pcp = pcp;
    IDEMIP_VLAN_IO(w)->tag_args.dei = dei;
    IDEMIP_VLAN_IO(w)->tag_args.vid = vid;
    Vlan.pack(w);
}

static void split_tci(uint8_t *w, uint16_t tci)
{
    IDEMIP_VLAN_IO(w)->tci_args.tci = tci;
    Vlan.split(w);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    Vlan.clear(NULL);
    Vlan.parse(NULL);
    Vlan.build(NULL);
    Vlan.pack(NULL);
    Vlan.split(NULL);
    TEST_PASS();
}

// The borrow IS the instance, and the operand block is in it, so two frames read at once share no
// byte.
void test_two_borrows_share_no_byte(void)
{
    ready(work_a);
    ready(work_b);
    IDEMIP_VLAN_IO(work_a)->tci_args.tci = 0xA064u;
    IDEMIP_VLAN_IO(work_b)->tci_args.tci = 0x0001u;

    TEST_ASSERT_EQUAL_HEX16(0xA064u, IDEMIP_VLAN_IO(work_a)->tci_args.tci);
    TEST_ASSERT_EQUAL_HEX16(0x0001u, IDEMIP_VLAN_IO(work_b)->tci_args.tci);

    Vlan.split(work_a);
    Vlan.split(work_b);

    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_VLAN_IO(work_a)->pcp);
    TEST_ASSERT_EQUAL_UINT16(0x064u, IDEMIP_VLAN_IO(work_a)->vid);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_VLAN_IO(work_b)->pcp);
    TEST_ASSERT_EQUAL_UINT16(0x001u, IDEMIP_VLAN_IO(work_b)->vid);
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    ready(work_a);
    ready(work_b);
    make_tagged(0xA064u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);

    parse_frame(work_a, IDEMIP_VLAN_HDR_LEN + 4u);
    uint16_t first = IDEMIP_VLAN_IO(work_a)->vid;
    split_tci(work_b, 0xFFFEu);
    parse_frame(work_a, IDEMIP_VLAN_HDR_LEN + 4u);

    TEST_ASSERT_EQUAL_UINT16(0x064u, first);
    TEST_ASSERT_EQUAL_UINT16(first, IDEMIP_VLAN_IO(work_a)->vid);
}

// Zeroed, never cleared: every entry must refuse rather than answer out of bytes no one gave it.
void test_an_uncleared_borrow_refuses_work(void)
{
    make_untagged((uint16_t)IDEMIP_ETHERTYPE_IPV4);
    parse_frame(work_a, FRAME_BYTES);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
    build_tag(work_a, 0u, IDEMIP_FALSE, 100u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
    pack_tag(work_a, 0u, IDEMIP_FALSE, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
    split_tci(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
}

// A build on an uncleared borrow wrote nothing into the frame either.
void test_a_refused_build_writes_no_octet(void)
{
    make_untagged((uint16_t)IDEMIP_ETHERTYPE_IPV4);
    build_tag(work_a, 0u, IDEMIP_FALSE, 100u, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)IDEMIP_ETHERTYPE_IPV4, get16(frame + IDEMIP_ETH_OFF_TYPE));
    TEST_ASSERT_EQUAL_HEX16(0x0000u, get16(frame + IDEMIP_VLAN_OFF_TCI));
}

void test_clear_reports_ok_and_opens_the_borrow(void)
{
    ready(work_a);
    split_tci(work_a, 0u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
}

// Nothing here waits on hardware or a peer, so a call that cannot finish now cannot finish later.
// Every refusal is ERR and BUSY never appears.
void test_no_entry_ever_reports_busy(void)
{
    ready(work_a);
    IDEMIP_VLAN_IO(work_a)->parse_args.frame = NULL;
    IDEMIP_VLAN_IO(work_a)->parse_args.len = 0u;
    Vlan.parse(work_a);
    TEST_ASSERT_NOT_EQUAL(IDEMIP_BUSY, IDEMIP_VLAN_IO(work_a)->status);
    build_tag(work_a, 9u, IDEMIP_FALSE, 100u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_NOT_EQUAL(IDEMIP_BUSY, IDEMIP_VLAN_IO(work_a)->status);
    pack_tag(work_a, 0u, IDEMIP_FALSE, (uint16_t)IDEMIP_VLAN_VID_RESERVED);
    TEST_ASSERT_NOT_EQUAL(IDEMIP_BUSY, IDEMIP_VLAN_IO(work_a)->status);
    split_tci(work_a, 0xFFFFu);
    TEST_ASSERT_NOT_EQUAL(IDEMIP_BUSY, IDEMIP_VLAN_IO(work_a)->status);
}

// The published map must be the layout the module actually uses.
void test_the_published_map_covers_the_private_layout(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, (size_t)IDEMIP_VLAN_OFF_IO);
    TEST_ASSERT_TRUE(sizeof(VlanIo) <= (size_t)IDEMIP_VLAN_OFF_CTX);
    TEST_ASSERT_TRUE((size_t)IDEMIP_VLAN_OFF_CTX < (size_t)IDEMIP_VLAN_OFF_END);
    TEST_ASSERT_TRUE((size_t)IDEMIP_VLAN_OFF_END <= (size_t)IDEMIP_VLAN_BORROW);
    TEST_ASSERT_EQUAL_PTR(work_a, IDEMIP_VLAN_IO(work_a));
}

// --- the constants -------------------------------------------------------------

// RFC 7042 Appendix B.2, and RFC 6325 sec 4.1.1: "The C-Tag Ethertype [RFC5342] is 0x8100."
void test_the_c_tag_ethertype_is_8100(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x8100u, (uint16_t)IDEMIP_VLAN_TPID);
}

// RFC 7042 Appendix B.2: "0x88A8 IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)".
void test_the_s_tag_ethertype_is_88a8(void)
{
    TEST_ASSERT_EQUAL_HEX16(0x88A8u, (uint16_t)IDEMIP_VLAN_STAG_TPID);
}

// RFC 6325 sec 4.1 Figure 7 puts the tag where the type code sits, and the payload's type behind it.
void test_the_tag_sits_in_the_type_field_and_adds_four_octets(void)
{
    TEST_ASSERT_EQUAL_UINT8(12u, (uint8_t)IDEMIP_VLAN_OFF_TPID);
    TEST_ASSERT_EQUAL_UINT8(14u, (uint8_t)IDEMIP_VLAN_OFF_TCI);
    TEST_ASSERT_EQUAL_UINT8(16u, (uint8_t)IDEMIP_VLAN_OFF_TYPE);
    TEST_ASSERT_EQUAL_UINT8(18u, (uint8_t)IDEMIP_VLAN_OFF_PAYLOAD);
    TEST_ASSERT_EQUAL_UINT8(4u, (uint8_t)IDEMIP_VLAN_TAG_LEN);
    TEST_ASSERT_EQUAL_UINT8(18u, (uint8_t)IDEMIP_VLAN_HDR_LEN);
}

// A tagged frame is four octets longer than an untagged one.
void test_a_tagged_frame_is_four_octets_longer(void)
{
    TEST_ASSERT_EQUAL_UINT16(1518u, (uint16_t)IDEMIP_VLAN_FRAME_MAX);
    TEST_ASSERT_EQUAL_UINT16((uint16_t)(IDEMIP_ETH_FRAME_MAX + 4u), (uint16_t)IDEMIP_VLAN_FRAME_MAX);
}

// RFC 6325 sec 4.1.1: the usable range is 0x001 through 0xFFE, zero is the null identifier, and
// 0xFFF is reserved.
void test_the_vlan_id_range_is_the_stated_one(void)
{
    TEST_ASSERT_EQUAL_UINT16(0x000u, (uint16_t)IDEMIP_VLAN_VID_NULL);
    TEST_ASSERT_EQUAL_UINT16(0x001u, (uint16_t)IDEMIP_VLAN_VID_FIRST);
    TEST_ASSERT_EQUAL_UINT16(0xFFEu, (uint16_t)IDEMIP_VLAN_VID_LAST);
    TEST_ASSERT_EQUAL_UINT16(0xFFFu, (uint16_t)IDEMIP_VLAN_VID_RESERVED);
    TEST_ASSERT_EQUAL_UINT16(4096u, (uint16_t)IDEMIP_VLAN_VIDS);
}

// RFC 6325 sec 4.1.1: "the priority field contains an unsigned value from 0 through 7".
void test_the_priority_field_is_three_bits(void)
{
    TEST_ASSERT_EQUAL_UINT8(7u, (uint8_t)IDEMIP_VLAN_PCP_MAX);
    TEST_ASSERT_EQUAL_UINT8(13u, (uint8_t)IDEMIP_VLAN_PCP_SHIFT);
}

// --- parse ---------------------------------------------------------------------

// An untagged frame is not an error: OK, tagged false, and the frame's own type code.
void test_parse_of_an_untagged_frame_reports_its_own_type(void)
{
    ready(work_a);
    make_untagged((uint16_t)IDEMIP_ETHERTYPE_IPV4);
    parse_frame(work_a, FRAME_BYTES);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_VLAN_IO(work_a)->tagged);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)IDEMIP_ETHERTYPE_IPV4, IDEMIP_VLAN_IO(work_a)->type);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_ETH_HDR_LEN, IDEMIP_VLAN_IO(work_a)->payload_off);
    TEST_ASSERT_EQUAL_PTR(frame + IDEMIP_ETH_OFF_PAYLOAD, IDEMIP_VLAN_IO(work_a)->payload);
}

// An untagged frame carries no tag fields, so none are reported.
void test_parse_of_an_untagged_frame_reports_no_tag_fields(void)
{
    ready(work_a);
    make_untagged((uint16_t)IDEMIP_ETHERTYPE_IPV6);
    parse_frame(work_a, FRAME_BYTES);
    TEST_ASSERT_EQUAL_HEX16(0x0000u, IDEMIP_VLAN_IO(work_a)->tci);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_VLAN_IO(work_a)->pcp);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_VLAN_IO(work_a)->vid);
    TEST_ASSERT_FALSE(IDEMIP_VLAN_IO(work_a)->dei);
    TEST_ASSERT_FALSE(IDEMIP_VLAN_IO(work_a)->vid_null);
}

// The S-Tag Ethertype is not the C-Tag Ethertype, so this module reads such a frame as untagged.
void test_parse_reads_an_s_tag_frame_as_untagged(void)
{
    ready(work_a);
    make_untagged((uint16_t)IDEMIP_VLAN_STAG_TPID);
    parse_frame(work_a, FRAME_BYTES);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_VLAN_IO(work_a)->tagged);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)IDEMIP_VLAN_STAG_TPID, IDEMIP_VLAN_IO(work_a)->type);
}

// A tagged frame: the tag fields, the payload's own type, and the data field eighteen octets in.
void test_parse_of_a_tagged_frame(void)
{
    ready(work_a);
    make_tagged(0xA064u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    parse_frame(work_a, FRAME_BYTES);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->tagged);
    TEST_ASSERT_EQUAL_HEX16(0xA064u, IDEMIP_VLAN_IO(work_a)->tci);
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_VLAN_IO(work_a)->pcp);
    TEST_ASSERT_FALSE(IDEMIP_VLAN_IO(work_a)->dei);
    TEST_ASSERT_EQUAL_UINT16(100u, IDEMIP_VLAN_IO(work_a)->vid);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)IDEMIP_ETHERTYPE_IPV4, IDEMIP_VLAN_IO(work_a)->type);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_VLAN_OFF_PAYLOAD, IDEMIP_VLAN_IO(work_a)->payload_off);
    TEST_ASSERT_EQUAL_PTR(frame + IDEMIP_VLAN_OFF_PAYLOAD, IDEMIP_VLAN_IO(work_a)->payload);
}

// The C bit is the one between the Priority and the VLAN ID.
void test_parse_reports_the_c_bit(void)
{
    ready(work_a);
    make_tagged(0xB064u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    parse_frame(work_a, FRAME_BYTES);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->dei);
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_VLAN_IO(work_a)->pcp);
    TEST_ASSERT_EQUAL_UINT16(100u, IDEMIP_VLAN_IO(work_a)->vid);
}

// "VLAN ID zero is the null VLAN identifier ... such frames are called 'priority tagged'."
void test_parse_reports_the_null_vlan_identifier(void)
{
    ready(work_a);
    make_tagged(0xE000u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    parse_frame(work_a, FRAME_BYTES);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->tagged);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->vid_null);
    TEST_ASSERT_EQUAL_UINT8(7u, IDEMIP_VLAN_IO(work_a)->pcp);
}

// "VLAN ID 0xFFF is reserved." The octets already arrived, so the parse reports it rather than
// refusing what is already on the wire.
void test_parse_reports_the_reserved_vlan_identifier(void)
{
    ready(work_a);
    make_tagged(0x0FFFu, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    parse_frame(work_a, FRAME_BYTES);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->vid_reserved);
    TEST_ASSERT_EQUAL_UINT16(0x0FFFu, IDEMIP_VLAN_IO(work_a)->vid);
}

// A frame with no room for the type field cannot be read at all.
void test_parse_refuses_a_frame_shorter_than_the_ethernet_header(void)
{
    ready(work_a);
    make_untagged((uint16_t)IDEMIP_ETHERTYPE_IPV4);
    parse_frame(work_a, (size_t)IDEMIP_ETH_HDR_LEN - 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
}

// Exactly the header is enough for an untagged frame, its data field being empty.
void test_parse_accepts_a_frame_of_exactly_the_ethernet_header(void)
{
    ready(work_a);
    make_untagged((uint16_t)IDEMIP_ETHERTYPE_ARP);
    parse_frame(work_a, (size_t)IDEMIP_ETH_HDR_LEN);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16((uint16_t)IDEMIP_ETHERTYPE_ARP, IDEMIP_VLAN_IO(work_a)->type);
}

// A frame claiming the C-Tag Ethertype but too short to hold the tag and the type behind it.
void test_parse_refuses_a_tagged_frame_short_of_the_tag(void)
{
    ready(work_a);
    make_tagged(0xA064u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    parse_frame(work_a, (size_t)IDEMIP_VLAN_HDR_LEN - 1u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_FALSE(IDEMIP_VLAN_IO(work_a)->tagged);
}

void test_parse_accepts_a_tagged_frame_of_exactly_the_tagged_header(void)
{
    ready(work_a);
    make_tagged(0xA064u, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    parse_frame(work_a, (size_t)IDEMIP_VLAN_HDR_LEN);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->tagged);
}

void test_parse_refuses_a_null_frame(void)
{
    ready(work_a);
    IDEMIP_VLAN_IO(work_a)->parse_args.frame = NULL;
    IDEMIP_VLAN_IO(work_a)->parse_args.len = FRAME_BYTES;
    Vlan.parse(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
}

// A refused parse leaves nothing an earlier call found.
void test_a_refused_parse_reports_nothing_stale(void)
{
    ready(work_a);
    make_tagged(0xA064u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    parse_frame(work_a, FRAME_BYTES);
    TEST_ASSERT_EQUAL_UINT16(100u, IDEMIP_VLAN_IO(work_a)->vid);
    parse_frame(work_a, 4u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT16(0u, IDEMIP_VLAN_IO(work_a)->vid);
    TEST_ASSERT_EQUAL_HEX16(0u, IDEMIP_VLAN_IO(work_a)->tci);
    TEST_ASSERT_NULL(IDEMIP_VLAN_IO(work_a)->payload);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_VLAN_IO(work_a)->payload_off);
}

// A parse reads the frame and writes not one octet of it.
void test_parse_writes_no_octet_of_the_frame(void)
{
    uint8_t before[FRAME_BYTES];
    ready(work_a);
    make_tagged(0xA064u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    memcpy(before, frame, sizeof before);
    parse_frame(work_a, FRAME_BYTES);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(before, frame, FRAME_BYTES);
}

// --- build ----------------------------------------------------------------------

// The C-Tag Ethertype where the type code sits, the Tag Control Information behind it, then the
// type code the payload is.
void test_build_writes_the_tag_and_the_encapsulated_type(void)
{
    ready(work_a);
    build_tag(work_a, 5u, IDEMIP_FALSE, 100u, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(0x8100u, get16(frame + IDEMIP_VLAN_OFF_TPID));
    TEST_ASSERT_EQUAL_HEX16(0xA064u, get16(frame + IDEMIP_VLAN_OFF_TCI));
    TEST_ASSERT_EQUAL_HEX16((uint16_t)IDEMIP_ETHERTYPE_IPV6, get16(frame + IDEMIP_VLAN_OFF_TYPE));
}

// It reports the same fields a parse of what it wrote would.
void test_build_reports_what_it_wrote(void)
{
    ready(work_a);
    build_tag(work_a, 5u, IDEMIP_TRUE, 100u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->tagged);
    TEST_ASSERT_EQUAL_HEX16(0xB064u, IDEMIP_VLAN_IO(work_a)->tci);
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_VLAN_IO(work_a)->pcp);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->dei);
    TEST_ASSERT_EQUAL_UINT16(100u, IDEMIP_VLAN_IO(work_a)->vid);
    TEST_ASSERT_EQUAL_size_t((size_t)IDEMIP_VLAN_OFF_PAYLOAD, IDEMIP_VLAN_IO(work_a)->payload_off);
}

// What a build writes, a parse reads back, over every Priority and both C bit values.
void test_build_and_parse_round_trip(void)
{
    ready(work_a);
    for (unsigned pcp = 0; pcp <= 7u; pcp++)
    {
        for (unsigned dei = 0; dei < 2u; dei++)
        {
            build_tag(work_a, (uint8_t)pcp, (idemip_bool)dei, (uint16_t)(0x123u), (uint16_t)IDEMIP_ETHERTYPE_IPV4);
            TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
            parse_frame(work_a, FRAME_BYTES);
            TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
            TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->tagged);
            TEST_ASSERT_EQUAL_UINT8((uint8_t)pcp, IDEMIP_VLAN_IO(work_a)->pcp);
            TEST_ASSERT_EQUAL_UINT8((uint8_t)dei, IDEMIP_VLAN_IO(work_a)->dei);
            TEST_ASSERT_EQUAL_UINT16(0x123u, IDEMIP_VLAN_IO(work_a)->vid);
            TEST_ASSERT_EQUAL_HEX16((uint16_t)IDEMIP_ETHERTYPE_IPV4, IDEMIP_VLAN_IO(work_a)->type);
        }
    }
}

// Every VLAN ID the field holds and the range allows round trips.
void test_build_and_parse_round_trip_every_vlan_id(void)
{
    ready(work_a);
    for (unsigned vid = IDEMIP_VLAN_VID_NULL; vid <= IDEMIP_VLAN_VID_LAST; vid++)
    {
        build_tag(work_a, 3u, IDEMIP_FALSE, (uint16_t)vid, (uint16_t)IDEMIP_ETHERTYPE_IPV6);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status, "a VLAN ID in range was refused");
        parse_frame(work_a, FRAME_BYTES);
        TEST_ASSERT_EQUAL_UINT16((uint16_t)vid, IDEMIP_VLAN_IO(work_a)->vid);
    }
}

// The build touches the six octets it names and nothing else: the addresses ahead of them and the
// data field behind them are the caller's.
void test_build_touches_only_the_six_octets_it_names(void)
{
    uint8_t before[FRAME_BYTES];
    ready(work_a);
    memset(frame + IDEMIP_VLAN_OFF_PAYLOAD, 0xEE, FRAME_BYTES - IDEMIP_VLAN_OFF_PAYLOAD);
    memcpy(before, frame, sizeof before);
    build_tag(work_a, 1u, IDEMIP_FALSE, 7u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(before, frame, IDEMIP_VLAN_OFF_TPID, "the addresses moved");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(before + IDEMIP_VLAN_OFF_PAYLOAD, frame + IDEMIP_VLAN_OFF_PAYLOAD,
                                          FRAME_BYTES - IDEMIP_VLAN_OFF_PAYLOAD, "the data field moved");
}

// "the priority field contains an unsigned value from 0 through 7", so eight and above is not a
// Priority and no retry makes it one.
void test_build_refuses_a_priority_above_seven(void)
{
    ready(work_a);
    build_tag(work_a, (uint8_t)(IDEMIP_VLAN_PCP_MAX + 1u), IDEMIP_FALSE, 100u, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(0x0000u, get16(frame + IDEMIP_VLAN_OFF_TPID));
}

// The VLAN ID is twelve bits, so 0x1000 is not one.
void test_build_refuses_a_vlan_id_outside_the_field(void)
{
    ready(work_a);
    build_tag(work_a, 0u, IDEMIP_FALSE, (uint16_t)(IDEMIP_VLAN_VID_MASK + 1u), (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(0x0000u, get16(frame + IDEMIP_VLAN_OFF_TPID));
}

// RFC 6325 sec 4.1.1: "The VLAN ID 0xFFF MUST NOT be used."
void test_build_refuses_the_reserved_vlan_id(void)
{
    ready(work_a);
    build_tag(work_a, 0u, IDEMIP_FALSE, (uint16_t)IDEMIP_VLAN_VID_RESERVED, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(0x0000u, get16(frame + IDEMIP_VLAN_OFF_TPID));
}

// The null VLAN identifier is a priority tag, which is written rather than refused.
void test_build_accepts_the_null_vlan_identifier(void)
{
    ready(work_a);
    build_tag(work_a, 6u, IDEMIP_FALSE, (uint16_t)IDEMIP_VLAN_VID_NULL, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->vid_null);
    TEST_ASSERT_EQUAL_HEX16(0xC000u, get16(frame + IDEMIP_VLAN_OFF_TCI));
}

void test_build_refuses_a_null_frame(void)
{
    ready(work_a);
    IDEMIP_VLAN_IO(work_a)->build_args.frame = NULL;
    IDEMIP_VLAN_IO(work_a)->build_args.type = (uint16_t)IDEMIP_ETHERTYPE_IPV4;
    IDEMIP_VLAN_IO(work_a)->tag_args.pcp = 0u;
    IDEMIP_VLAN_IO(work_a)->tag_args.dei = IDEMIP_FALSE;
    IDEMIP_VLAN_IO(work_a)->tag_args.vid = 100u;
    Vlan.build(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
}

// --- pack and split ----------------------------------------------------------------

// The three fields into one word: Priority high, the C bit below it, the VLAN ID in the low twelve.
void test_pack_places_each_field_where_the_figure_draws_it(void)
{
    ready(work_a);
    pack_tag(work_a, 7u, IDEMIP_FALSE, 0u);
    TEST_ASSERT_EQUAL_HEX16(0xE000u, IDEMIP_VLAN_IO(work_a)->tci);
    pack_tag(work_a, 0u, IDEMIP_TRUE, 0u);
    TEST_ASSERT_EQUAL_HEX16(0x1000u, IDEMIP_VLAN_IO(work_a)->tci);
    pack_tag(work_a, 0u, IDEMIP_FALSE, 0x0FFEu);
    TEST_ASSERT_EQUAL_HEX16(0x0FFEu, IDEMIP_VLAN_IO(work_a)->tci);
}

// A pack refuses exactly what a build refuses, the field being the same field.
void test_pack_refuses_what_build_refuses(void)
{
    ready(work_a);
    pack_tag(work_a, (uint8_t)(IDEMIP_VLAN_PCP_MAX + 1u), IDEMIP_FALSE, 100u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
    pack_tag(work_a, 0u, IDEMIP_FALSE, (uint16_t)(IDEMIP_VLAN_VID_MASK + 1u));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
    pack_tag(work_a, 0u, IDEMIP_FALSE, (uint16_t)IDEMIP_VLAN_VID_RESERVED);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_VLAN_IO(work_a)->status);
}

// A split takes what a MAC that stripped the tag reports, so every 16-bit value splits.
void test_split_reports_each_field(void)
{
    ready(work_a);
    split_tci(work_a, 0xB064u);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_VLAN_IO(work_a)->pcp);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->dei);
    TEST_ASSERT_EQUAL_UINT16(100u, IDEMIP_VLAN_IO(work_a)->vid);
    TEST_ASSERT_EQUAL_HEX16(0xB064u, IDEMIP_VLAN_IO(work_a)->tci);
}

// The octets already arrived, so the reserved identifier is reported rather than refused.
void test_split_reports_the_reserved_vlan_id_rather_than_refusing_it(void)
{
    ready(work_a);
    split_tci(work_a, 0xFFFFu);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->vid_reserved);
    TEST_ASSERT_EQUAL_UINT8(7u, IDEMIP_VLAN_IO(work_a)->pcp);
    TEST_ASSERT_TRUE(IDEMIP_VLAN_IO(work_a)->dei);
}

// The three fields cover the whole word: splitting any value and packing it back is that value.
void test_split_and_pack_round_trip_over_every_value(void)
{
    ready(work_a);
    for (unsigned tci = 0; tci < 0x10000u; tci++)
    {
        split_tci(work_a, (uint16_t)tci);
        uint8_t pcp = IDEMIP_VLAN_IO(work_a)->pcp;
        idemip_bool dei = IDEMIP_VLAN_IO(work_a)->dei;
        uint16_t vid = IDEMIP_VLAN_IO(work_a)->vid;
        if (vid == IDEMIP_VLAN_VID_RESERVED)
        {
            continue; // a pack refuses to write it back
        }
        pack_tag(work_a, pcp, dei, vid);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_VLAN_IO(work_a)->status);
        TEST_ASSERT_EQUAL_HEX16_MESSAGE((uint16_t)tci, IDEMIP_VLAN_IO(work_a)->tci,
                                        "a bit of the Tag Control Information was lost");
    }
}

// Splitting reports the same three fields a parse of a frame carrying that word reports.
void test_split_agrees_with_parse(void)
{
    ready(work_a);
    make_tagged(0x5ABCu, (uint16_t)IDEMIP_ETHERTYPE_IPV4);
    parse_frame(work_a, FRAME_BYTES);
    uint8_t pcp = IDEMIP_VLAN_IO(work_a)->pcp;
    idemip_bool dei = IDEMIP_VLAN_IO(work_a)->dei;
    uint16_t vid = IDEMIP_VLAN_IO(work_a)->vid;
    split_tci(work_a, 0x5ABCu);
    TEST_ASSERT_EQUAL_UINT8(pcp, IDEMIP_VLAN_IO(work_a)->pcp);
    TEST_ASSERT_EQUAL_UINT8(dei, IDEMIP_VLAN_IO(work_a)->dei);
    TEST_ASSERT_EQUAL_UINT16(vid, IDEMIP_VLAN_IO(work_a)->vid);
}

// A pack writes no octet of any frame.
void test_pack_writes_no_octet_of_the_frame(void)
{
    uint8_t before[FRAME_BYTES];
    ready(work_a);
    make_untagged((uint16_t)IDEMIP_ETHERTYPE_IPV4);
    memcpy(before, frame, sizeof before);
    pack_tag(work_a, 4u, IDEMIP_TRUE, 42u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(before, frame, FRAME_BYTES);
}
