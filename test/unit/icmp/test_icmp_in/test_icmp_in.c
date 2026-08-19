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

#define HOST_IP 0xC0A80105u    // 192.168.1.5
#define PEER_IP 0xC0A80101u    // 192.168.1.1
#define HOST_MASK 0xFFFFFF00u  // /24
#define SUBNET_BCAST 0xC0A801FFu
#define LIMITED_BCAST 0xFFFFFFFFu
#define MCAST_IP 0xE0000001u   // 224.0.0.1
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
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dgram, out + IDEMIP_ICMP_OFF_QUOTE,
                                  IDEMIP_IPV4_HDR_LEN + IDEMIP_ICMP_ERR_QUOTE_DATA);
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
