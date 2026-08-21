// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// icmp_in against RFC 792, RFC 1122 sec 3.2.2 and RFC 1122 sec 3.2.1.3.
//
// The shape checks are test_phy's, in the same order:
//   1. the borrow is the caller's, so the suite declares it and passes it to every entry
//   2. every entry is called with a null borrow and must refuse
//   3. the borrow IS the instance, so two borrows share not one byte
//   4. an entry is a function of its borrow alone, so the same call on the same bytes repeats
//   5. BUSY and ERR are separated by whether retrying can ever succeed
//
// RFC 792 prints field diagrams and no numeric example, and neither RFC 1122 sec 3.2.2 nor its
// subsections prints one, so there is no vector to copy. Every case below therefore asserts a
// property one of those texts states, quoted at the case.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/icmp/icmp_in.h"

#include <string.h>
#include <unity.h>

// --- the borrow, the caller's ------------------------------------------------
// Two of them, because the borrow is the instance. A canary follows each so a write past the map is
// visible.

#define CANARY 0x5Au
static _Alignas(8) uint8_t work_a[IDEMIP_ICMP_IN_BORROW + 16];
static _Alignas(8) uint8_t work_b[IDEMIP_ICMP_IN_BORROW + 16];

static void arm(uint8_t *w, size_t cap)
{
    memset(w, 0, cap);
    memset(w + IDEMIP_ICMP_IN_BORROW, CANARY, cap - IDEMIP_ICMP_IN_BORROW);
}

static void check_canary(const uint8_t *w, size_t cap)
{
    for (size_t i = IDEMIP_ICMP_IN_BORROW; i < cap; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, w[i], "a write landed past IDEMIP_ICMP_IN_BORROW");
    }
}

// --- the wire ----------------------------------------------------------------

#define HOST_IP 0xC0A80105u   // 192.168.1.5
#define PEER_IP 0xC0A80101u   // 192.168.1.1
#define HOST_MASK 0xFFFFFF00u // /24
#define SUBNET_BCAST 0xC0A801FFu
#define LIMITED_BCAST 0xFFFFFFFFu
#define MCAST_IP 0xE0000001u // 224.0.0.1
#define CLASS_E_IP 0xF0000001u
#define LOOPBACK_IP 0x7F000001u

static uint8_t dgram[512];
static size_t dgram_len;
static uint8_t out[512];

// One option-free header, then whatever the caller already placed at dgram + IDEMIP_IPV4_HDR_LEN.
static void put_ip(uint32_t src, uint32_t dst, uint8_t proto, uint16_t flags_frag, size_t payload)
{
    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.total_len = (uint16_t)(IDEMIP_IPV4_HDR_LEN + payload);
    f.ttl = 64u;
    f.proto = proto;
    f.flags_frag = flags_frag;
    f.src = src;
    f.dst = dst;
    idemip_ip4_build(dgram, &f);
    dgram_len = IDEMIP_IPV4_HDR_LEN + payload;
}

// An RFC 792 echo or echo reply carrying @p data_len octets of 0xA5 data.
static size_t put_echo(uint8_t type, uint16_t id, uint16_t seq, size_t data_len)
{
    uint8_t *m = dgram + IDEMIP_IPV4_HDR_LEN;
    memset(m + IDEMIP_ICMP_ECHO_HDR_LEN, 0xA5, data_len);
    const size_t len = IDEMIP_ICMP_ECHO_HDR_LEN + data_len;
    idemip_icmp_build_echo(m, type, id, seq, len);
    return len;
}

// An arriving RFC 792 error message quoting a UDP datagram, so the quoted Protocol is 17.
static size_t put_error(uint8_t type, uint8_t code, uint32_t word)
{
    uint8_t *m = dgram + IDEMIP_IPV4_HDR_LEN;
    uint8_t *quote = m + IDEMIP_ICMP_OFF_QUOTE;
    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.total_len = (uint16_t)(IDEMIP_IPV4_HDR_LEN + 8u);
    f.ttl = 64u;
    f.proto = IDEMIP_IP4_PROTO_UDP;
    f.src = HOST_IP;
    f.dst = PEER_IP;
    idemip_ip4_build(quote, &f);
    memset(quote + IDEMIP_IPV4_HDR_LEN, 0x11, 8u);
    const size_t len = IDEMIP_ICMP_ERR_HDR_LEN + IDEMIP_IPV4_HDR_LEN + 8u;
    idemip_icmp_build_error(m, type, code, word, len);
    return len;
}

// A whole datagram to originate an error about: a UDP one from PEER_IP to HOST_IP.
static void put_victim(void)
{
    memset(dgram + IDEMIP_IPV4_HDR_LEN, 0x33, 16u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_UDP, 0u, 16u);
}

static void load_recv(uint8_t *w)
{
    IcmpInIo *io = IDEMIP_ICMP_IN_IO(w);
    io->recv_args.datagram = dgram;
    io->recv_args.len = dgram_len;
    io->recv_args.out = out;
    io->recv_args.out_cap = sizeof out;
    io->recv_args.if_addr = HOST_IP;
    io->recv_args.if_mask = HOST_MASK;
    io->recv_args.link_bcast = IDEMIP_FALSE;
}

static void load_error(uint8_t *w, uint8_t type, uint8_t code)
{
    IcmpInIo *io = IDEMIP_ICMP_IN_IO(w);
    io->err_args.datagram = dgram;
    io->err_args.len = dgram_len;
    io->err_args.out = out;
    io->err_args.out_cap = sizeof out;
    io->err_args.if_mask = HOST_MASK;
    io->err_args.word = 0u;
    io->err_args.type = type;
    io->err_args.code = code;
    io->err_args.link_bcast = IDEMIP_FALSE;
}

// The rule a call was refused by, after loading a victim datagram and asking for a port unreachable.
static uint8_t suppress_of(uint8_t *w)
{
    load_error(w, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(w);
    return IDEMIP_ICMP_IN_IO(w)->suppress;
}

void setUp(void)
{
    arm(work_a, sizeof work_a);
    arm(work_b, sizeof work_b);
    memset(dgram, 0, sizeof dgram);
    memset(out, 0, sizeof out);
    dgram_len = 0;
    IcmpIn.clear(work_a);
    IcmpIn.clear(work_b);
}

void tearDown(void)
{
    check_canary(work_a, sizeof work_a);
    check_canary(work_b, sizeof work_b);
}

// --- the borrow --------------------------------------------------------------

// Nothing to report into, so nothing is written and nothing faults.
void test_every_entry_survives_a_null_borrow(void)
{
    IcmpIn.clear(NULL);
    IcmpIn.recv(NULL);
    IcmpIn.error(NULL);
    TEST_PASS();
}

// A borrow clear has not run on carries no mark, so every entry refuses it rather than reading a
// context of whatever the caller's .bss held.
void test_uncleared_borrow_refuses_work(void)
{
    arm(work_a, sizeof work_a);
    put_echo((uint8_t)IDEMIP_ICMP_ECHO, 1u, 1u, 8u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, IDEMIP_ICMP_ECHO_HDR_LEN + 8u);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);

    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
}

void test_clear_reports_ok_and_zeroes_the_block(void)
{
    IDEMIP_ICMP_IN_IO(work_a)->act = 0xFFu;
    IDEMIP_ICMP_IN_IO(work_a)->out_len = 99u;
    IcmpIn.clear(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ICMP_IN_IO(work_a)->act);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_ICMP_IN_IO(work_a)->out_len);
}

// The borrow IS the instance, and the operand block is in it, so two message paths share no byte.
// This is the property the whole storage model rests on.
void test_two_borrows_share_no_byte(void)
{
    IDEMIP_ICMP_IN_IO(work_a)->recv_args.if_addr = HOST_IP;
    IDEMIP_ICMP_IN_IO(work_b)->recv_args.if_addr = PEER_IP;
    TEST_ASSERT_EQUAL_HEX32(HOST_IP, IDEMIP_ICMP_IN_IO(work_a)->recv_args.if_addr);
    TEST_ASSERT_EQUAL_HEX32(PEER_IP, IDEMIP_ICMP_IN_IO(work_b)->recv_args.if_addr);

    put_echo((uint8_t)IDEMIP_ICMP_ECHO, 0x1234u, 7u, 8u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, IDEMIP_ICMP_ECHO_HDR_LEN + 8u);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(0x1234u, IDEMIP_ICMP_IN_IO(work_a)->id);

    // b was never given a datagram, so its call is refused and a's result is untouched.
    IcmpIn.recv(work_b);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_b)->status);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_HEX16(0x1234u, IDEMIP_ICMP_IN_IO(work_a)->id);
}

// An entry is a function of its borrow alone, so a call interleaved on another borrow cannot change
// what this one reports. This is the determinism the design is named for.
void test_a_call_is_a_function_of_its_borrow_alone(void)
{
    put_echo((uint8_t)IDEMIP_ICMP_ECHO, 0xBEEFu, 3u, 16u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, IDEMIP_ICMP_ECHO_HDR_LEN + 16u);
    load_recv(work_a);
    load_recv(work_b);
    IDEMIP_ICMP_IN_IO(work_b)->recv_args.if_addr = PEER_IP;

    IcmpIn.recv(work_a);
    const size_t first = IDEMIP_ICMP_IN_IO(work_a)->out_len;
    const uint32_t first_src = IDEMIP_ICMP_IN_IO(work_a)->src;
    IcmpIn.recv(work_b);
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_size_t(first, IDEMIP_ICMP_IN_IO(work_a)->out_len);
    TEST_ASSERT_EQUAL_HEX32(first_src, IDEMIP_ICMP_IN_IO(work_a)->src);
}

// --- RFC 792 Echo or Echo Reply ---------------------------------------------

// RFC 1122 sec 3.2.2.6: "Every host MUST implement an ICMP Echo server function that receives Echo
// Requests and sends corresponding Echo Replies." RFC 792: "the type code changed to 0".
void test_echo_request_is_answered_with_an_echo_reply(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 0x0102u, 0x0304u, 20u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);

    const IcmpInIo *io = IDEMIP_ICMP_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_REPLY, io->act);
    TEST_ASSERT_EQUAL_size_t(len, io->out_len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_ECHO_REPLY, idemip_icmp_type(out));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_CODE_ECHO, idemip_icmp_code(out));
    TEST_ASSERT_EQUAL_HEX16(0x0102u, idemip_icmp_id(out));
    TEST_ASSERT_EQUAL_HEX16(0x0304u, idemip_icmp_seq(out));
}

// RFC 1122 sec 3.2.2.6: "Data received in an ICMP Echo Request MUST be entirely included in the
// resulting Echo Reply."
void test_echo_reply_carries_the_data_entirely(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 1u, 1u, 40u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);

    TEST_ASSERT_FALSE(IDEMIP_ICMP_IN_IO(work_a)->truncated);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dgram + IDEMIP_IPV4_HDR_LEN + IDEMIP_ICMP_ECHO_HDR_LEN,
                                  out + IDEMIP_ICMP_ECHO_HDR_LEN, 40u);
}

// RFC 792: "the checksum recomputed", over the reply as it will be sent.
void test_echo_reply_checksum_verifies(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 9u, 9u, 13u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_TRUE(idemip_cksum_valid(out, IDEMIP_ICMP_IN_IO(work_a)->out_len));
}

// RFC 1122 sec 3.2.2.6: "The IP source address in an ICMP Echo Reply MUST be the same as the
// specific-destination address ... of the corresponding ICMP Echo Request message", and sec 3.2.1.3
// makes the specific-destination the header's destination for a unicast datagram.
void test_echo_reply_source_is_the_specific_destination(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 1u, 1u, 4u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_HEX32(HOST_IP, IDEMIP_ICMP_IN_IO(work_a)->src);
    TEST_ASSERT_EQUAL_HEX32(PEER_IP, IDEMIP_ICMP_IN_IO(work_a)->dst);
}

// RFC 1122 sec 3.2.2.6: "An ICMP Echo Request destined to an IP broadcast or IP multicast address MAY
// be silently discarded." IDEMIP_ICMP_ECHO_BROADCAST is zero, so this build discards it.
void test_echo_to_a_broadcast_destination_is_discarded(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_ICMP_ECHO_BROADCAST);
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 1u, 1u, 4u);
    put_ip(PEER_IP, SUBNET_BCAST, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_DISCARD, IDEMIP_ICMP_IN_IO(work_a)->act);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_ICMP_IN_IO(work_a)->out_len);
}

void test_echo_to_a_multicast_destination_is_discarded(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 1u, 1u, 4u);
    put_ip(PEER_IP, MCAST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_DISCARD, IDEMIP_ICMP_IN_IO(work_a)->act);
}

// RFC 1122 sec 3.2.2.6: "if sending the Echo Reply requires intentional fragmentation that is not
// implemented, the datagram MUST be truncated to maximum transmission size ... and sent."
void test_echo_reply_is_truncated_to_the_maximum_transmission_size(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 1u, 2u, 100u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IDEMIP_ICMP_IN_IO(work_a)->recv_args.out_cap = 40u;
    IcmpIn.recv(work_a);

    const IcmpInIo *io = IDEMIP_ICMP_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_REPLY, io->act);
    TEST_ASSERT_TRUE(io->truncated);
    TEST_ASSERT_EQUAL_size_t(40u, io->out_len);
    TEST_ASSERT_TRUE(idemip_cksum_valid(out, 40u));
}

// RFC 1122 sec 3.2.2.6: "Echo Reply messages MUST be passed to the ICMP user interface".
void test_an_arriving_echo_reply_goes_to_the_user(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO_REPLY, 0x55AAu, 4u, 8u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);

    const IcmpInIo *io = IDEMIP_ICMP_IN_IO(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_USER, io->act);
    TEST_ASSERT_EQUAL_size_t(0u, io->out_len);
    TEST_ASSERT_EQUAL_HEX16(0x55AAu, io->id);
    TEST_ASSERT_EQUAL_HEX16(4u, io->seq);
}

// RFC 792 fixes the checksum over "the ICMP message starting with the ICMP Type", so a message that
// does not sum is not the one that was sent.
void test_a_bad_checksum_is_discarded(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 1u, 1u, 8u);
    dgram[IDEMIP_IPV4_HDR_LEN + IDEMIP_ICMP_OFF_CKSUM] ^= 0xFFu;
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);

    const IcmpInIo *io = IDEMIP_ICMP_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_FALSE(io->cksum_ok);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_DISCARD, io->act);
    TEST_ASSERT_EQUAL_size_t(0u, io->out_len);
}

// RFC 1122 sec 3.2.2: "If an ICMP message of unknown type is received, it MUST be silently
// discarded."
void test_an_unknown_type_is_discarded(void)
{
    uint8_t *m = dgram + IDEMIP_IPV4_HDR_LEN;
    idemip_icmp_build_echo(m, 99u, 0u, 0u, IDEMIP_ICMP_ECHO_HDR_LEN);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, IDEMIP_ICMP_ECHO_HDR_LEN);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_DISCARD, IDEMIP_ICMP_IN_IO(work_a)->act);
    TEST_ASSERT_EQUAL_UINT8(99u, IDEMIP_ICMP_IN_IO(work_a)->type);
}

// RFC 1122 sec 3.2.2.7: "A host SHOULD NOT implement these messages."
void test_an_information_request_is_discarded(void)
{
    uint8_t *m = dgram + IDEMIP_IPV4_HDR_LEN;
    idemip_icmp_build_echo(m, (uint8_t)IDEMIP_ICMP_INFO_REQUEST, 1u, 1u, IDEMIP_ICMP_INFO_LEN);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, IDEMIP_ICMP_INFO_LEN);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_DISCARD, IDEMIP_ICMP_IN_IO(work_a)->act);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_ICMP_IN_IO(work_a)->out_len);
}

// RFC 1122 sec 3.2.2.8: "A host MAY implement Timestamp and Timestamp Reply." This build does not,
// so the message is discarded rather than answered.
void test_a_timestamp_request_is_discarded(void)
{
    uint8_t *m = dgram + IDEMIP_IPV4_HDR_LEN;
    memset(m, 0, IDEMIP_ICMP_TS_LEN);
    idemip_icmp_build_echo(m, (uint8_t)IDEMIP_ICMP_TIMESTAMP, 1u, 1u, IDEMIP_ICMP_TS_LEN);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, IDEMIP_ICMP_TS_LEN);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_DISCARD, IDEMIP_ICMP_IN_IO(work_a)->act);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_ICMP_IN_IO(work_a)->out_len);
}

// RFC 792 puts Type, Code and Checksum at the head of every message, so anything shorter carries no
// message at all.
void test_a_message_shorter_than_the_common_header_is_discarded(void)
{
    dgram[IDEMIP_IPV4_HDR_LEN] = (uint8_t)IDEMIP_ICMP_ECHO;
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, 2u);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_DISCARD, IDEMIP_ICMP_IN_IO(work_a)->act);
}

// An Echo shorter than its own Identifier and Sequence Number carries neither.
void test_an_echo_shorter_than_its_header_is_discarded(void)
{
    uint8_t *m = dgram + IDEMIP_IPV4_HDR_LEN;
    m[IDEMIP_ICMP_OFF_TYPE] = (uint8_t)IDEMIP_ICMP_ECHO;
    m[IDEMIP_ICMP_OFF_CODE] = 0u;
    idemip_wr16(m + IDEMIP_ICMP_OFF_CKSUM, 0u);
    idemip_wr16(m + IDEMIP_ICMP_OFF_CKSUM, idemip_cksum(m, IDEMIP_ICMP_HDR_LEN));
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, IDEMIP_ICMP_HDR_LEN);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_DISCARD, IDEMIP_ICMP_IN_IO(work_a)->act);
}

// A datagram idemip_ip4_verify refuses never reaches ICMP, so handing one here is a caller fault and
// no later call on the same bytes succeeds.
void test_recv_refuses_a_datagram_the_internet_layer_would_discard(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 1u, 1u, 8u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    dgram[IDEMIP_IP4_OFF_CKSUM] ^= 0xFFu; // RFC 1122 sec 3.2.1.2
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
}

void test_recv_refuses_a_null_datagram_and_a_null_out(void)
{
    load_recv(work_a);
    IDEMIP_ICMP_IN_IO(work_a)->recv_args.datagram = NULL;
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);

    load_recv(work_a);
    IDEMIP_ICMP_IN_IO(work_a)->recv_args.out = NULL;
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
}

// A buffer that cannot hold even an echo head can never hold a reply, so the refusal is ERR and not
// BUSY: retrying it forever makes no progress.
void test_recv_refuses_an_out_buffer_below_the_echo_header(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 1u, 1u, 8u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IDEMIP_ICMP_IN_IO(work_a)->recv_args.out_cap = IDEMIP_ICMP_ECHO_HDR_LEN - 1u;
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
}

// --- RFC 792 error messages arriving -----------------------------------------

// RFC 1122 sec 3.2.2: "the IP protocol number MUST be extracted from the original header and used to
// select the appropriate transport protocol entity to handle the error."
void test_destination_unreachable_demuxes_on_the_quoted_protocol(void)
{
    const size_t len = put_error((uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT, 0u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);

    const IcmpInIo *io = IDEMIP_ICMP_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_TRANSPORT, io->act);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_PROTO_UDP, io->proto);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_DU_PORT, io->code);
}

// The other three error types RFC 1122 sec 3.2.2.3, sec 3.2.2.4 and sec 3.2.2.5 pass to the transport
// layer take the same path.
void test_source_quench_time_exceeded_and_parameter_problem_reach_the_transport(void)
{
    const uint8_t types[3] = {(uint8_t)IDEMIP_ICMP_SOURCE_QUENCH, (uint8_t)IDEMIP_ICMP_TIME_EXCEEDED,
                              (uint8_t)IDEMIP_ICMP_PARAMETER_PROBLEM};
    for (int i = 0; i < 3; i++)
    {
        memset(dgram, 0, sizeof dgram);
        const size_t len = put_error(types[i], 0u, 0u);
        put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
        load_recv(work_a);
        IcmpIn.recv(work_a);
        TEST_ASSERT_BITS_HIGH_MESSAGE(IDEMIP_ICMP_IN_ACT_TRANSPORT, IDEMIP_ICMP_IN_IO(work_a)->act,
                                      "an RFC 1122 sec 3.2.2 error type did not reach the transport layer");
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_IP4_PROTO_UDP, IDEMIP_ICMP_IN_IO(work_a)->proto);
    }
}

// RFC 1122 sec 3.2.2.2: "A host receiving a Redirect message MUST update its routing information
// accordingly." RFC 792 puts the new first hop in the Gateway Internet Address.
void test_a_redirect_reports_the_gateway(void)
{
    const size_t len = put_error((uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_ICMP_RD_HOST, PEER_IP);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);

    const IcmpInIo *io = IDEMIP_ICMP_IN_IO(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_ROUTE, io->act);
    TEST_ASSERT_BITS_LOW(IDEMIP_ICMP_IN_ACT_TRANSPORT, io->act);
    TEST_ASSERT_EQUAL_HEX32(PEER_IP, io->gateway);
}

// RFC 1122 sec 3.2.2.2: "A Redirect message SHOULD be silently discarded if the new gateway address
// it specifies is not on the same connected (sub-) net through which the Redirect arrived", which the
// sec 4.2.2 requirements table lists as "Discard illegal Redirect".
void test_a_redirect_naming_an_off_link_gateway_is_discarded(void)
{
    const uint32_t off_link = 0xCB007109u; // outside HOST_IP under HOST_MASK
    const size_t len = put_error((uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_ICMP_RD_HOST, off_link);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);

    const IcmpInIo *io = IDEMIP_ICMP_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_BITS_LOW_MESSAGE(IDEMIP_ICMP_IN_ACT_ROUTE, io->act,
                                 "a gateway off the arrival subnet must not become a next hop");
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_DISCARD, io->act);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_REDIRECT, io->suppress);
}

// A gateway address that is on the subnet but names no single host is not a first hop either: RFC
// 1122 sec 3.2.1.3 (e) makes the all-ones host part the subnet's directed broadcast.
void test_a_redirect_naming_a_broadcast_or_multicast_gateway_is_discarded(void)
{
    const uint32_t forms[2] = {0xC0A801FFu, 0xE0000001u};
    for (int i = 0; i < 2; i++)
    {
        memset(dgram, 0, sizeof dgram);
        const size_t len = put_error((uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_ICMP_RD_HOST, forms[i]);
        put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
        load_recv(work_a);
        IcmpIn.recv(work_a);
        TEST_ASSERT_BITS_LOW_MESSAGE(IDEMIP_ICMP_IN_ACT_ROUTE, IDEMIP_ICMP_IN_IO(work_a)->act,
                                     "a gateway address that names no single host is not a next hop");
        TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_REDIRECT, IDEMIP_ICMP_IN_IO(work_a)->suppress);
    }
}

// The second half of sec 3.2.2.2 is "or if the source of the Redirect is not the current first-hop
// gateway for the specified destination", which needs the route the caller holds. sec 3.3.1.2 (c)
// keys the route cache entry on the quoted datagram's Destination Address, so an accepted Redirect
// reports it.
void test_an_accepted_redirect_reports_the_destination_it_names(void)
{
    const size_t len = put_error((uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_ICMP_RD_HOST, PEER_IP);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);

    const IcmpInIo *io = IDEMIP_ICMP_IN_IO(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_ROUTE, io->act);
    TEST_ASSERT_EQUAL_HEX32(PEER_IP, io->gateway);
    // put_error quotes a datagram from HOST_IP to PEER_IP.
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(PEER_IP, io->quoted_dst, "the route cache entry keys on this address");
}

// RFC 1122 sec 3.2.2 demuxes on the quoted internet header, so an error carrying less than a whole
// one names no transport entity.
void test_an_error_without_a_whole_quoted_header_is_discarded(void)
{
    uint8_t *m = dgram + IDEMIP_IPV4_HDR_LEN;
    const size_t len = IDEMIP_ICMP_ERR_HDR_LEN + 4u;
    memset(m + IDEMIP_ICMP_OFF_QUOTE, 0x45, 4u);
    idemip_icmp_build_dest_unreachable(m, IDEMIP_ICMP_DU_PORT, len);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_BITS_HIGH(IDEMIP_ICMP_IN_ACT_DISCARD, IDEMIP_ICMP_IN_IO(work_a)->act);
}

// --- originating an error message --------------------------------------------

// RFC 1122 sec 3.2.2.1: a host "SHOULD generate Destination Unreachable messages with code ... 3
// (Port Unreachable)".
void test_a_port_unreachable_is_built(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(work_a);

    const IcmpInIo *io = IDEMIP_ICMP_IN_IO(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, io->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_NONE, io->suppress);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_DEST_UNREACHABLE, idemip_icmp_type(out));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_DU_PORT, idemip_icmp_code(out));
}

// RFC 792: "The internet header plus the first 64 bits of the original datagram's data", which
// RFC 1122 sec 3.2.2 restates as "the Internet header and at least the first 8 data octets ... this
// header and data MUST be unchanged from the received datagram."
void test_an_error_quotes_the_header_and_eight_data_octets(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(work_a);

    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP_ERR_HDR_LEN + IDEMIP_IPV4_HDR_LEN + IDEMIP_ICMP_ERR_QUOTE_DATA,
                             IDEMIP_ICMP_IN_IO(work_a)->out_len);
    TEST_ASSERT_EQUAL_size_t(idemip_icmp_err_len(dgram), IDEMIP_ICMP_IN_IO(work_a)->out_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dgram, out + IDEMIP_ICMP_OFF_QUOTE, IDEMIP_IPV4_HDR_LEN + IDEMIP_ICMP_ERR_QUOTE_DATA);
}

// RFC 792 recomputes the checksum over the whole message, quote included.
void test_an_error_checksum_verifies(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_TIME_EXCEEDED, IDEMIP_ICMP_TE_REASSEMBLY);
    IcmpIn.error(work_a);
    TEST_ASSERT_TRUE(idemip_cksum_valid(out, IDEMIP_ICMP_IN_IO(work_a)->out_len));
}

// RFC 792 sends every error to "The source network and address from the original datagram's data".
void test_an_error_goes_back_to_the_datagrams_source(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PROTOCOL);
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_HEX32(PEER_IP, IDEMIP_ICMP_IN_IO(work_a)->dst);
    TEST_ASSERT_EQUAL_HEX32(HOST_IP, IDEMIP_ICMP_IN_IO(work_a)->src);
}

// RFC 792: "The pointer identifies the octet of the original datagram's header where the error was
// detected", carried as the top octet of the word at offset 4.
void test_a_parameter_problem_carries_the_pointer(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_PARAMETER_PROBLEM, IDEMIP_ICMP_PP_POINTER);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.word = (uint32_t)20u << IDEMIP_ICMP_POINTER_SHIFT;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(20u, idemip_icmp_pointer(out));
}

// --- the RFC 1122 sec 3.2.2 MUST NOT rules, one case each ---------------------

// "An ICMP error message MUST NOT be sent as the result of receiving: an ICMP error message".
void test_no_error_about_an_icmp_error_message(void)
{
    const size_t len = put_error((uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT, 0u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_ICMP_ERROR, suppress_of(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_ICMP_IN_IO(work_a)->out_len);
}

// RFC 1122 sec 3.2.2 names the five error types and groups the rest as queries, so an error about an
// Echo Request is allowed. RFC 792's introduction is wider: "no ICMP messages are sent about ICMP
// messages". RFC 1122 updates RFC 792 and states the narrower rule, so the narrower one is what runs.
void test_an_error_about_an_icmp_query_is_allowed(void)
{
    const size_t len = put_echo((uint8_t)IDEMIP_ICMP_ECHO, 1u, 1u, 8u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_NONE, suppress_of(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
}

// "a datagram destined to an IP broadcast ... address", RFC 1122 sec 3.2.1.3 (c) "{ -1, -1 } Limited
// broadcast."
void test_no_error_about_a_limited_broadcast_destination(void)
{
    put_victim();
    idemip_ip4_set_dst(dgram, LIMITED_BCAST);
    idemip_ip4_recksum(dgram);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_DST_BCAST, suppress_of(work_a));
}

// RFC 1122 sec 3.2.1.3 (e) "{ <Network-number>, <Subnet-number>, -1 } Directed broadcast to the
// specified subnet", which is the interface's own mask.
void test_no_error_about_a_subnet_directed_broadcast_destination(void)
{
    put_victim();
    idemip_ip4_set_dst(dgram, SUBNET_BCAST);
    idemip_ip4_recksum(dgram);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_DST_BCAST, suppress_of(work_a));
}

// "or IP multicast address", which RFC 1112 sec 4 gives the high-order four bits 1110.
void test_no_error_about_a_multicast_destination(void)
{
    put_victim();
    idemip_ip4_set_dst(dgram, MCAST_IP);
    idemip_ip4_recksum(dgram);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_DST_MCAST, suppress_of(work_a));
}

// "a datagram sent as a link-layer broadcast", which RFC 1122 sec 3.2.2 IMPLEMENTATION has the link
// layer report: "This requires that the link layer inform the IP layer when a link-layer broadcast
// datagram has been received".
void test_no_error_about_a_link_layer_broadcast(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.link_bcast = IDEMIP_TRUE;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_LINK_BCAST, IDEMIP_ICMP_IN_IO(work_a)->suppress);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
}

// "a non-initial fragment", which RFC 792 states as "ICMP messages are only sent about errors in
// handling fragment zero of fragemented datagrams."
void test_no_error_about_a_non_initial_fragment(void)
{
    memset(dgram + IDEMIP_IPV4_HDR_LEN, 0x33, 16u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_UDP, (uint16_t)(IDEMIP_IP4_FLAG_MF | 2u), 16u);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_FRAGMENT, suppress_of(work_a));
}

// Fragment zero is the one an error may be sent about, MF or not.
void test_an_error_about_the_first_fragment_is_allowed(void)
{
    memset(dgram + IDEMIP_IPV4_HDR_LEN, 0x33, 16u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_UDP, IDEMIP_IP4_FLAG_MF, 16u);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_NONE, suppress_of(work_a));
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
}

// "a datagram whose source address does not define a single host -- e.g., a zero address".
void test_no_error_about_a_zero_source(void)
{
    put_victim();
    idemip_ip4_set_src(dgram, 0u);
    idemip_ip4_recksum(dgram);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_SRC, suppress_of(work_a));
}

// "a loopback address", RFC 1122 sec 3.2.1.3 (g) "{ 127, <any> }".
void test_no_error_about_a_loopback_source(void)
{
    put_victim();
    idemip_ip4_set_src(dgram, LOOPBACK_IP);
    idemip_ip4_recksum(dgram);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_SRC, suppress_of(work_a));
}

// "a broadcast address".
void test_no_error_about_a_broadcast_source(void)
{
    put_victim();
    idemip_ip4_set_src(dgram, SUBNET_BCAST);
    idemip_ip4_recksum(dgram);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_SRC, suppress_of(work_a));
}

// "a multicast address".
void test_no_error_about_a_multicast_source(void)
{
    put_victim();
    idemip_ip4_set_src(dgram, MCAST_IP);
    idemip_ip4_recksum(dgram);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_SRC, suppress_of(work_a));
}

// "or a Class E address", which RFC 1112 sec 4 gives the high-order four bits 1111.
void test_no_error_about_a_class_e_source(void)
{
    put_victim();
    idemip_ip4_set_src(dgram, CLASS_E_IP);
    idemip_ip4_recksum(dgram);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_SRC, suppress_of(work_a));
}

// RFC 1122 sec 3.2.2.2: "A host SHOULD NOT send an ICMP Redirect message; Redirects are to be sent
// only by gateways."
void test_a_host_does_not_originate_a_redirect(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_ICMP_RD_HOST);
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_REDIRECT, IDEMIP_ICMP_IN_IO(work_a)->suppress);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
}

// A query type is not one of the five RFC 1122 sec 3.2.2 groups as errors, so it is a bad argument
// rather than a suppression.
void test_error_refuses_a_query_type(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_ECHO, 0u);
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_NONE, IDEMIP_ICMP_IN_IO(work_a)->suppress);
}

// A buffer that cannot hold the head and the quote RFC 1122 sec 3.2.2 requires can never hold them,
// so this is ERR and never BUSY.
void test_error_refuses_a_buffer_short_of_the_quote(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.out_cap = IDEMIP_ICMP_ERR_HDR_LEN + 4u;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t(0u, IDEMIP_ICMP_IN_IO(work_a)->out_len);
}

void test_error_refuses_a_datagram_the_internet_layer_would_discard(void)
{
    put_victim();
    dgram[IDEMIP_IP4_OFF_VER_IHL] = 0x54u; // version 5
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
}

void test_error_refuses_a_null_datagram_and_a_null_out(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.datagram = NULL;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);

    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.out = NULL;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
}

// Nothing here holds a resource a later call frees, so no entry ever reports BUSY: a refused error
// stays refused however many times it is asked for.
void test_a_suppressed_error_never_becomes_ok_on_a_retry(void)
{
    put_victim();
    idemip_ip4_set_dst(dgram, MCAST_IP);
    idemip_ip4_recksum(dgram);
    for (int i = 0; i < 4; i++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
        IcmpIn.error(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_ERR, IDEMIP_ICMP_IN_IO(work_a)->status);
        TEST_ASSERT_NOT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ICMP_IN_IO(work_a)->status);
    }
}

// An error the rules allow is built the same way however many times it is asked for.
// RFC 1812 sec 4.3.2.8: "A router which sends ICMP Source Quench messages MUST be able to limit the
// rate at which the messages can be generated. A router SHOULD also be able to limit the rate at
// which it sends other sorts of ICMP error messages (Destination Unreachable, Redirect, Time
// Exceeded, Parameter Problem). The rate limit parameters SHOULD be settable as part of the
// configuration of the router."
void test_originated_errors_are_rate_limited(void)
{
    // A full bucket allows a burst. The section leaves the mechanism to "the implementor's discretion";
    // the bucket is RFC 4443 sec 2.4 (f)'s recommendation for the IPv6 twin.
    put_victim();
    for (uint8_t n = 0u; n < (uint8_t)IDEMIP_ICMP4_ERR_BUCKET; n++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
        IDEMIP_ICMP_IN_IO(work_a)->err_args.now_ms = 0u;
        IcmpIn.error(work_a);
        TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status, "the burst is short of the bucket");
    }

    // The next one is refused, and BUSY because the clock refills the bucket.
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.now_ms = 0u;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_IN_SUPPRESS_RATE, IDEMIP_ICMP_IN_IO(work_a)->suppress);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0u, IDEMIP_ICMP_IN_IO(work_a)->out_len, "a refused call builds nothing");
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ICMP_IN_IO(work_a)->tokens);

    // One token's worth of milliseconds later, exactly one more message goes out.
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.now_ms = (uint32_t)IDEMIP_ICMP4_ERR_TOKEN_MS;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.now_ms = (uint32_t)IDEMIP_ICMP4_ERR_TOKEN_MS;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ICMP_IN_IO(work_a)->status);

    // A gap of a whole bucket refills it.
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.now_ms =
        (uint32_t)IDEMIP_ICMP4_ERR_BUCKET * (uint32_t)IDEMIP_ICMP4_ERR_TOKEN_MS * 4u;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)IDEMIP_ICMP4_ERR_BUCKET - 1u, IDEMIP_ICMP_IN_IO(work_a)->tokens);
}

// The section names Source Quench first: "A router which sends ICMP Source Quench messages MUST be
// able to limit the rate at which the messages can be generated."
void test_source_quench_is_rate_limited(void)
{
    put_victim();
    for (uint8_t n = 0u; n < (uint8_t)IDEMIP_ICMP4_ERR_BUCKET; n++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP_SOURCE_QUENCH, 0u);
        IDEMIP_ICMP_IN_IO(work_a)->err_args.now_ms = 0u;
        IcmpIn.error(work_a);
        TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    }
    load_error(work_a, (uint8_t)IDEMIP_ICMP_SOURCE_QUENCH, 0u);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.now_ms = 0u;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ICMP_IN_IO(work_a)->status);
}

// The bucket is one borrow's, so a burst through one does not spend another's tokens.
void test_the_rate_limit_is_per_borrow(void)
{
    put_victim();
    for (uint8_t n = 0u; n < (uint8_t)IDEMIP_ICMP4_ERR_BUCKET; n++)
    {
        load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
        IcmpIn.error(work_a);
    }
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_BUSY, IDEMIP_ICMP_IN_IO(work_a)->status);

    load_error(work_b, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(work_b);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_b)->status, "one borrow spent another's tokens");
}

// RFC 1122 sec 3.2.2: an error carries "the Internet header and at least the first 8 data octets of
// the datagram that triggered the error; ... this header and data MUST be unchanged from the received
// datagram", so a header carrying RFC 791 sec 3.1 options is quoted whole, options included.
void test_an_error_quotes_a_header_with_options_whole(void)
{
    // A Router Alert option (RFC 2113), padded to the 32-bit boundary sec 3.1 requires.
    static const uint8_t opts[4] = {0x94u, 0x04u, 0x00u, 0x00u};
    IdemIpIp4Fields f;
    memset(&f, 0, sizeof f);
    f.total_len = (uint16_t)(IDEMIP_IPV4_HDR_LEN + sizeof opts + 16u);
    f.ttl = 64u;
    f.proto = IDEMIP_IP4_PROTO_UDP;
    f.src = PEER_IP;
    f.dst = HOST_IP;
    idemip_ip4_build(dgram, &f);
    // sec 3.1: a caller that appends options raises IHL and reseals the checksum.
    memcpy(dgram + IDEMIP_IPV4_HDR_LEN, opts, sizeof opts);
    idemip_ip4_set_ver_ihl(dgram, (uint8_t)((IDEMIP_IPV4_HDR_LEN + sizeof opts) >> 2));
    idemip_ip4_recksum(dgram);
    memset(dgram + IDEMIP_IPV4_HDR_LEN + sizeof opts, 0x33, 16u);
    dgram_len = IDEMIP_IPV4_HDR_LEN + sizeof opts + 16u;

    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);

    const size_t hdr = IDEMIP_IPV4_HDR_LEN + sizeof opts;
    TEST_ASSERT_EQUAL_size_t_MESSAGE(IDEMIP_ICMP_ERR_HDR_LEN + hdr + 8u, IDEMIP_ICMP_IN_IO(work_a)->out_len,
                                     "the quote is the whole header, options included, plus 8 data octets");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(dgram, out + IDEMIP_ICMP_OFF_QUOTE, hdr + 8u,
                                          "the quoted header and data MUST be unchanged");
}

void test_a_built_error_repeats(void)
{
    put_victim();
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(work_a);
    const size_t first = IDEMIP_ICMP_IN_IO(work_a)->out_len;
    uint8_t copy[64];
    memcpy(copy, out, first);

    memset(out, 0, sizeof out);
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_size_t(first, IDEMIP_ICMP_IN_IO(work_a)->out_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(copy, out, first);
}

// --- the classful forms behind the four broadcasts ------------------------------

// RFC 1122 sec 3.2.1.3 (d) and (f) are broadcasts under the network's own mask rather than the
// interface's, and RFC 791 sec 3.2 gives that mask by the leading bits: eight under a leading 0,
// sixteen under 10, twenty-four under 110. An interface that has not been given a mask yet leaves
// those the only forms there are, and a Redirect naming one of them names no single host.
void test_a_redirect_naming_a_classful_broadcast_is_discarded(void)
{
    // One address per class, each with its network part intact and its host part all ones.
    const uint32_t gateway[3] = {0x0AFFFFFFu, 0x8001FFFFu, 0xC0A801FFu};
    for (int i = 0; i < 3; i++)
    {
        memset(dgram, 0, sizeof dgram);
        const size_t len = put_error((uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_ICMP_RD_HOST, gateway[i]);
        put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
        load_recv(work_a);
        IDEMIP_ICMP_IN_IO(work_a)->recv_args.if_addr = 0u;
        IDEMIP_ICMP_IN_IO(work_a)->recv_args.if_mask = 0u;
        IcmpIn.recv(work_a);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(IDEMIP_ICMP_IN_SUPPRESS_REDIRECT, IDEMIP_ICMP_IN_IO(work_a)->suppress,
                                        "a Redirect to a directed broadcast of the network was taken");
    }

    // A host address in each of those networks is a first hop, so the walk over the forms is what
    // separates them and not the leading bits alone.
    const uint32_t host[3] = {0x0A000002u, 0x80010002u, 0xC0A80102u};
    for (int i = 0; i < 3; i++)
    {
        memset(dgram, 0, sizeof dgram);
        const size_t len = put_error((uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_ICMP_RD_HOST, host[i]);
        put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
        load_recv(work_a);
        IDEMIP_ICMP_IN_IO(work_a)->recv_args.if_addr = 0u;
        IDEMIP_ICMP_IN_IO(work_a)->recv_args.if_mask = 0u;
        IcmpIn.recv(work_a);
        TEST_ASSERT_BITS_HIGH_MESSAGE(IDEMIP_ICMP_IN_ACT_ROUTE, IDEMIP_ICMP_IN_IO(work_a)->act,
                                      "a Redirect to a host address was discarded as a broadcast");
    }

    // RFC 1112 sec 4's class D and the class E above it name no network, so neither carries a host
    // part that could be all ones: the broadcast forms pass them by, and what is left is sec
    // 3.2.2.2's own test of the gateway. A multicast address is not a first hop; an address in the
    // class E block is one this test does not reach, and it is left as the section leaves it.
    const uint32_t not_hosts[2] = {0xE0000001u, 0xF0000001u};
    const uint8_t expect[2] = {(uint8_t)IDEMIP_ICMP_IN_SUPPRESS_REDIRECT, 0u};
    for (int i = 0; i < 2; i++)
    {
        memset(dgram, 0, sizeof dgram);
        const size_t len = put_error((uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_ICMP_RD_HOST, not_hosts[i]);
        put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
        load_recv(work_a);
        IDEMIP_ICMP_IN_IO(work_a)->recv_args.if_addr = not_hosts[i] + 1u;
        IDEMIP_ICMP_IN_IO(work_a)->recv_args.if_mask = 0xFF000000u;
        IcmpIn.recv(work_a);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(expect[i], IDEMIP_ICMP_IN_IO(work_a)->suppress,
                                        "a Redirect naming an address in a reserved block was not answered as it is");
    }
}

// An interface whose mask is all ones has no host part of its own, so RFC 1122 sec 3.2.1.3 (e) names
// nothing there and the classful forms are the only ones left to test.
void test_a_single_host_interface_has_no_subnet_broadcast(void)
{
    memset(dgram, 0, sizeof dgram);
    const size_t len = put_error((uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_ICMP_RD_HOST, 0xC0A801FFu);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IDEMIP_ICMP_IN_IO(work_a)->recv_args.if_mask = 0xFFFFFFFFu;
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(IDEMIP_ICMP_IN_SUPPRESS_REDIRECT, IDEMIP_ICMP_IN_IO(work_a)->suppress,
                                    "a gateway off a single-host interface was taken as on it");
}

// RFC 792's Redirect carries a gateway address and the datagram that provoked it. A message too
// short for the gateway field is not one, and one whose quote is not an IPv4 header names no
// destination for sec 3.2.2.2's "first-hop gateway for the specified destination" to be tested on.
void test_a_redirect_with_no_gateway_field_or_no_readable_quote(void)
{
    memset(dgram, 0, sizeof dgram);
    uint8_t *m = dgram + IDEMIP_IPV4_HDR_LEN;
    m[0] = (uint8_t)IDEMIP_ICMP_REDIRECT;
    m[1] = IDEMIP_ICMP_RD_HOST;
    m[IDEMIP_ICMP_OFF_CKSUM] = 0u;
    m[IDEMIP_ICMP_OFF_CKSUM + 1u] = 0u;
    idemip_wr16(m + IDEMIP_ICMP_OFF_CKSUM, idemip_cksum(m, 4u));
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, 4u);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_TRUE_MESSAGE(IDEMIP_ICMP_IN_IO(work_a)->bad_len, "a Redirect with no gateway field was read");

    // The gateway is on this subnet and the quote behind it is not an IPv4 header at all.
    memset(dgram, 0, sizeof dgram);
    const size_t len = put_error((uint8_t)IDEMIP_ICMP_REDIRECT, IDEMIP_ICMP_RD_HOST, PEER_IP);
    uint8_t *msg = dgram + IDEMIP_IPV4_HDR_LEN;
    msg[IDEMIP_ICMP_OFF_QUOTE] = 0x00u; // version zero: not IPv4
    idemip_wr16(msg + IDEMIP_ICMP_OFF_CKSUM, 0u);
    idemip_wr16(msg + IDEMIP_ICMP_OFF_CKSUM, idemip_cksum(msg, len));
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_BITS_HIGH_MESSAGE(IDEMIP_ICMP_IN_ACT_ROUTE, IDEMIP_ICMP_IN_IO(work_a)->act,
                                  "a Redirect with an unreadable quote was discarded rather than taken");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0u, IDEMIP_ICMP_IN_IO(work_a)->quoted_dst,
                                     "a destination was read out of a quote that is not a header");
}

// RFC 1122 sec 3.2.2 keeps an ICMP error from being sent about "an ICMP error message" and about "a
// non-initial fragment" of any datagram, which are its clauses (1) and (4). The
// message it would be about is read out of the datagram, so a datagram that is not carrying one -
// because it is a later fragment, or because it is too short to hold the header - is not one of
// those, and the error goes.
void test_the_icmp_error_suppression_reads_the_message_the_datagram_carries(void)
{
    // A later fragment of an ICMP datagram. sec 3.2.2 (4) refuses it for being a non-initial
    // fragment, and the ICMP-error rule above passes it by for the same reason: the message head is
    // in fragment zero, which this is not.
    memset(dgram, 0, sizeof dgram);
    memset(dgram + IDEMIP_IPV4_HDR_LEN, 0x33, 16u);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 2u, 16u);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(IDEMIP_ICMP_IN_SUPPRESS_FRAGMENT, suppress_of(work_a),
                                    "a later fragment was answered as something other than one");

    // An ICMP datagram with no room for a Type and Code at all.
    memset(dgram, 0, sizeof dgram);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, 2u);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, suppress_of(work_a),
                                    "a datagram too short to carry a message was read for one");
}

// RFC 792: an error message carries "the internet header plus the first 64 bits of the original
// datagram's data", and a datagram with fewer than 64 bits behind its header carries what there is.
void test_an_error_about_a_datagram_shorter_than_the_quote_carries_what_there_is(void)
{
    memset(dgram, 0, sizeof dgram);
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_UDP, 0u, 0u); // header only, no data at all
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_size_t_MESSAGE((size_t)IDEMIP_ICMP_ERR_HDR_LEN + IDEMIP_IPV4_HDR_LEN,
                                     IDEMIP_ICMP_IN_IO(work_a)->out_len,
                                     "the quote ran past the datagram it was taken from");
    TEST_ASSERT_TRUE(idemip_cksum_valid(out, IDEMIP_ICMP_IN_IO(work_a)->out_len));
}

// RFC 1812 sec 4.3.2.8's rate limit is a token bucket, and a bucket that is already full takes no
// more: the refill stops at the top whatever time has passed, so a gap long enough for two tokens
// with one to give back leaves the bucket full and not over.
void test_the_token_bucket_refill_stops_at_the_top(void)
{
    memset(dgram, 0, sizeof dgram);
    put_victim();

    // One token spent.
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.now_ms = 0u;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);

    // A gap long enough for two tokens, but shorter than the one that refills the whole bucket. The
    // one that was spent comes back and the second has nowhere to go.
    load_error(work_a, (uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT);
    IDEMIP_ICMP_IN_IO(work_a)->err_args.now_ms = 2u * (uint32_t)IDEMIP_ICMP4_ERR_TOKEN_MS;
    IcmpIn.error(work_a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status,
                                  "the token that was spent did not come back");
}

// RFC 791 sec 3.1 fixes the Internet Header Length at "the minimum value for a correct header is 5",
// so a quote claiming fewer than five words is not a header this stack can read a Protocol out of -
// the version alone is not enough to say it is one.
void test_a_quote_whose_header_length_is_below_the_minimum_names_no_protocol(void)
{
    memset(dgram, 0, sizeof dgram);
    const size_t len = put_error((uint8_t)IDEMIP_ICMP_DEST_UNREACHABLE, IDEMIP_ICMP_DU_PORT, 0u);
    uint8_t *msg = dgram + IDEMIP_IPV4_HDR_LEN;
    msg[IDEMIP_ICMP_OFF_QUOTE] = 0x44u; // version 4, IHL 4: one word short of a header
    idemip_wr16(msg + IDEMIP_ICMP_OFF_CKSUM, 0u);
    idemip_wr16(msg + IDEMIP_ICMP_OFF_CKSUM, idemip_cksum(msg, len));
    put_ip(PEER_IP, HOST_IP, IDEMIP_IP4_PROTO_ICMP, 0u, len);
    load_recv(work_a);
    IcmpIn.recv(work_a);
    TEST_ASSERT_EQUAL_INT(IDEMIP_OK, IDEMIP_ICMP_IN_IO(work_a)->status);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0u, IDEMIP_ICMP_IN_IO(work_a)->proto,
                                    "a Protocol was read out of a quote shorter than a header");
}
