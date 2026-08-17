// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 792, internet control messages, plus the additions RFC 1122 sec 3.2.2 makes to it.
//
// RFC 792 prints no hex captures, so every vector here is a message laid out field by field from one
// of its figures, and every expected checksum is the RFC 1071 sum over those exact octets. What the
// suite checks:
//
//   1. every offset lands where the figure draws the field
//   2. every type number and code value is the one the RFC assigns
//   3. a build helper writes only the message it was given a length for
//   4. a built message carries a checksum that verifies (RFC 1071 sec 1)
//   5. the RFC 1122 error/query split, which decides whether an error may be sent at all
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "idemIP/icmp/icmp.h"

#include <string.h>
#include <unity.h>

// A message buffer with a canary past the end, so a helper writing outside the length it was handed
// is visible. Every build helper takes a total length, and nothing past it may move.
#define CANARY 0x5Au
#define MSG_CAP 64u
static uint8_t msg[MSG_CAP + 16u];

static void arm(void)
{
    memset(msg, 0, MSG_CAP);
    memset(msg + MSG_CAP, CANARY, sizeof msg - MSG_CAP);
}

static void check_canary(void)
{
    for (size_t i = MSG_CAP; i < sizeof msg; i++)
    {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(CANARY, msg[i], "a build helper wrote past the message");
    }
}

void setUp(void)
{
    arm();
}
void tearDown(void)
{
    check_canary();
}

// RFC 792 Echo or Echo Reply, the figure's fields: Type 8, Code 0, Checksum, Identifier 0x1234,
// Sequence Number 1, then eight octets of data.
static const uint8_t echo_req[16] = {8,    0,    0x54, 0x35, 0x12, 0x34, 0x00, 0x01,
                                     0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68};

// The reply to it: "the type code changed to 0, and the checksum recomputed".
static const uint8_t echo_rep[16] = {0,    0,    0x5c, 0x35, 0x12, 0x34, 0x00, 0x01,
                                     0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68};

// The datagram an error message quotes: an RFC 791 sec 3.1 header, IHL 5, protocol 17, then the
// first 64 bits of its data, which RFC 792 says hold the port numbers.
static const uint8_t quoted[28] = {0x45, 0x00, 0x00, 0x54, 0xAB, 0xCD, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0x00,
                                   0x02, 0x01, 0xC0, 0x00, 0x02, 0x02, 0x04, 0x00, 0x00, 0x35, 0x00, 0x10, 0x00, 0x00};

// --- the three fields every message shares ------------------------------------

// RFC 792 Message Formats: "The first octet of the data portion of the datagram is a ICMP type
// field", then Code, then a 16-bit Checksum. Every figure draws the same first word.
void test_rfc792_common_fields_are_the_first_word(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_ICMP_OFF_TYPE);
    TEST_ASSERT_EQUAL_UINT(1u, IDEMIP_ICMP_OFF_CODE);
    TEST_ASSERT_EQUAL_UINT(2u, IDEMIP_ICMP_OFF_CKSUM);
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP_HDR_LEN);

    TEST_ASSERT_EQUAL_UINT8(8u, idemip_icmp_type(echo_req));
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_icmp_code(echo_req));
    TEST_ASSERT_EQUAL_HEX16(0x5435u, idemip_icmp_cksum(echo_req));
}

// RFC 792 "Summary of Message Types", read as printed: 0, 3, 4, 5, 8, 11, 12, 13, 14, 15, 16.
void test_rfc792_summary_of_message_types(void)
{
    TEST_ASSERT_EQUAL_INT(0, IDEMIP_ICMP_ECHO_REPLY);
    TEST_ASSERT_EQUAL_INT(3, IDEMIP_ICMP_DEST_UNREACHABLE);
    TEST_ASSERT_EQUAL_INT(4, IDEMIP_ICMP_SOURCE_QUENCH);
    TEST_ASSERT_EQUAL_INT(5, IDEMIP_ICMP_REDIRECT);
    TEST_ASSERT_EQUAL_INT(8, IDEMIP_ICMP_ECHO);
    TEST_ASSERT_EQUAL_INT(11, IDEMIP_ICMP_TIME_EXCEEDED);
    TEST_ASSERT_EQUAL_INT(12, IDEMIP_ICMP_PARAMETER_PROBLEM);
    TEST_ASSERT_EQUAL_INT(13, IDEMIP_ICMP_TIMESTAMP);
    TEST_ASSERT_EQUAL_INT(14, IDEMIP_ICMP_TIMESTAMP_REPLY);
    TEST_ASSERT_EQUAL_INT(15, IDEMIP_ICMP_INFO_REQUEST);
    TEST_ASSERT_EQUAL_INT(16, IDEMIP_ICMP_INFO_REPLY);
}

// RFC 1122 sec 3.2.2 sorts the type space into errors and queries, and the errors are the five
// listed there. The split gates "An ICMP error message MUST NOT be sent as the result of receiving
// an ICMP error message", so a type on the wrong side of it turns into a message storm.
void test_rfc1122_error_and_query_classes(void)
{
    const uint8_t errors[5] = {3u, 4u, 5u, 11u, 12u};
    const uint8_t queries[6] = {0u, 8u, 13u, 14u, 15u, 16u};
    uint8_t m[IDEMIP_ICMP_HDR_LEN] = {0, 0, 0, 0};

    for (size_t i = 0; i < sizeof errors; i++)
    {
        m[IDEMIP_ICMP_OFF_TYPE] = errors[i];
        TEST_ASSERT_TRUE_MESSAGE(idemip_icmp_is_error(m), "an RFC 1122 sec 3.2.2 error read as a query");
    }
    for (size_t i = 0; i < sizeof queries; i++)
    {
        m[IDEMIP_ICMP_OFF_TYPE] = queries[i];
        TEST_ASSERT_FALSE_MESSAGE(idemip_icmp_is_error(m), "an RFC 1122 sec 3.2.2 query read as an error");
    }
}

// --- echo and echo reply ------------------------------------------------------

// RFC 792 Echo or Echo Reply: Identifier at octet 4, Sequence Number at 6, Data from 8.
void test_rfc792_echo_figure_offsets(void)
{
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP_OFF_ID);
    TEST_ASSERT_EQUAL_UINT(6u, IDEMIP_ICMP_OFF_SEQ);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP_ECHO_HDR_LEN);

    TEST_ASSERT_EQUAL_HEX16(0x1234u, idemip_icmp_id(echo_req));
    TEST_ASSERT_EQUAL_HEX16(0x0001u, idemip_icmp_seq(echo_req));
    TEST_ASSERT_EQUAL_UINT8('a', echo_req[IDEMIP_ICMP_ECHO_HDR_LEN]);
}

// The vector's own checksum verifies: RFC 1071 sec 1, a span carrying its checksum sums to all ones.
void test_echo_vector_carries_a_valid_checksum(void)
{
    TEST_ASSERT_TRUE(idemip_cksum_valid(echo_req, sizeof echo_req));
    TEST_ASSERT_TRUE(idemip_cksum_valid(echo_rep, sizeof echo_rep));
}

// RFC 792: "To form an echo reply message ... the type code changed to 0, and the checksum
// recomputed." The expected bytes are the request's with those two changes and nothing else.
void test_rfc792_echo_reply_is_the_request_retyped(void)
{
    memcpy(msg, echo_req, sizeof echo_req);
    idemip_icmp_echo_reply(msg, sizeof echo_req);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(echo_rep, msg, sizeof echo_rep);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_ECHO_REPLY, idemip_icmp_type(msg));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_CODE_ECHO, idemip_icmp_code(msg));
    TEST_ASSERT_EQUAL_HEX16(0x5c35u, idemip_icmp_cksum(msg));
    TEST_ASSERT_TRUE(idemip_cksum_valid(msg, sizeof echo_req));
}

// RFC 792: "The data received in the echo message must be returned in the echo reply message." and
// RFC 1122 sec 3.2.2.6: "Data received in an ICMP Echo Request MUST be entirely included in the
// resulting Echo Reply." The identifier and sequence number ride along: "The echoer returns these
// same values in the echo reply."
void test_rfc1122_echo_reply_returns_every_data_octet(void)
{
    memcpy(msg, echo_req, sizeof echo_req);
    idemip_icmp_echo_reply(msg, sizeof echo_req);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(echo_req + IDEMIP_ICMP_ECHO_HDR_LEN, msg + IDEMIP_ICMP_ECHO_HDR_LEN,
                                  sizeof echo_req - IDEMIP_ICMP_ECHO_HDR_LEN);
    TEST_ASSERT_EQUAL_HEX16(idemip_icmp_id(echo_req), idemip_icmp_id(msg));
    TEST_ASSERT_EQUAL_HEX16(idemip_icmp_seq(echo_req), idemip_icmp_seq(msg));
}

// RFC 792, Echo checksum: "If the total length is odd, the received data is padded with one octet of
// zeros for computing the checksum." The pad is not sent, so a nine-octet payload and the same nine
// followed by a zero reach the same checksum.
void test_rfc792_odd_length_echo_pads_with_one_zero_octet(void)
{
    memcpy(msg, echo_req, sizeof echo_req);
    msg[sizeof echo_req] = 0x69u; // a ninth data octet, making the message odd
    idemip_icmp_echo_reply(msg, sizeof echo_req + 1u);
    uint16_t odd = idemip_icmp_cksum(msg);

    msg[sizeof echo_req + 1u] = 0x00u; // the pad, written out this time
    idemip_icmp_echo_reply(msg, sizeof echo_req + 2u);

    TEST_ASSERT_EQUAL_HEX16(odd, idemip_icmp_cksum(msg));
    TEST_ASSERT_EQUAL_HEX16(0xf334u, odd);
}

// A fresh echo request, built rather than transformed. Same octets as the vector, so the checksum is
// the same number.
void test_build_echo_reproduces_the_vector(void)
{
    memcpy(msg + IDEMIP_ICMP_ECHO_HDR_LEN, echo_req + IDEMIP_ICMP_ECHO_HDR_LEN,
           sizeof echo_req - IDEMIP_ICMP_ECHO_HDR_LEN);
    idemip_icmp_build_echo(msg, (uint8_t)IDEMIP_ICMP_ECHO, 0x1234u, 1u, sizeof echo_req);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(echo_req, msg, sizeof echo_req);
}

// --- destination unreachable --------------------------------------------------

// RFC 792, type 3: "0 = net unreachable; 1 = host unreachable; 2 = protocol unreachable; 3 = port
// unreachable; 4 = fragmentation needed and DF set; 5 = source route failed."
void test_rfc792_destination_unreachable_codes(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_ICMP_DU_NET);
    TEST_ASSERT_EQUAL_UINT(1u, IDEMIP_ICMP_DU_HOST);
    TEST_ASSERT_EQUAL_UINT(2u, IDEMIP_ICMP_DU_PROTOCOL);
    TEST_ASSERT_EQUAL_UINT(3u, IDEMIP_ICMP_DU_PORT);
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP_DU_FRAG_NEEDED);
    TEST_ASSERT_EQUAL_UINT(5u, IDEMIP_ICMP_DU_SRC_ROUTE_FAILED);
}

// RFC 1122 sec 3.2.2.1: "The following additional codes are hereby defined: 6 = destination network
// unknown, 7 = destination host unknown, 8 = source host isolated, 9 = communication with
// destination network administratively prohibited, 10 = communication with destination host
// administratively prohibited, 11 = network unreachable for type of service, 12 = host unreachable
// for type of service."
void test_rfc1122_destination_unreachable_added_codes(void)
{
    TEST_ASSERT_EQUAL_UINT(6u, IDEMIP_ICMP_DU_NET_UNKNOWN);
    TEST_ASSERT_EQUAL_UINT(7u, IDEMIP_ICMP_DU_HOST_UNKNOWN);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP_DU_SRC_HOST_ISOLATED);
    TEST_ASSERT_EQUAL_UINT(9u, IDEMIP_ICMP_DU_NET_PROHIBITED);
    TEST_ASSERT_EQUAL_UINT(10u, IDEMIP_ICMP_DU_HOST_PROHIBITED);
    TEST_ASSERT_EQUAL_UINT(11u, IDEMIP_ICMP_DU_NET_TOS);
    TEST_ASSERT_EQUAL_UINT(12u, IDEMIP_ICMP_DU_HOST_TOS);
}

// RFC 1122 sec 3.2.2.1: a host generates code 3 when the transport "is unable to demultiplex the
// datagram". The message is type 3, the unused word is zero, and the quoted datagram follows at
// octet 8 unchanged: "this header and data MUST be unchanged from the received datagram".
void test_rfc1122_port_unreachable_message(void)
{
    const size_t len = IDEMIP_ICMP_ERR_HDR_LEN + sizeof quoted;
    memset(msg, 0xFFu, MSG_CAP); // the unused word must be zeroed by the helper, not by the caller
    memcpy(msg + IDEMIP_ICMP_OFF_QUOTE, quoted, sizeof quoted);
    idemip_icmp_build_dest_unreachable(msg, IDEMIP_ICMP_DU_PORT, len);

    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_DEST_UNREACHABLE, idemip_icmp_type(msg));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_DU_PORT, idemip_icmp_code(msg));
    TEST_ASSERT_EQUAL_HEX32(0u, idemip_rd32(msg + IDEMIP_ICMP_OFF_UNUSED));
    TEST_ASSERT_EQUAL_HEX16(0x4380u, idemip_icmp_cksum(msg));
    TEST_ASSERT_TRUE(idemip_cksum_valid(msg, len));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(quoted, idemip_icmp_quote(msg), sizeof quoted);
}

// RFC 792: "Any field labeled "unused" is reserved for later extensions and must be zero when sent".
// Types 3, 4 and 11 all label the word at octet 4 unused.
void test_rfc792_unused_word_is_zero_when_sent(void)
{
    const size_t len = IDEMIP_ICMP_ERR_HDR_LEN + sizeof quoted;
    memset(msg, 0xFFu, MSG_CAP);
    idemip_icmp_build_dest_unreachable(msg, IDEMIP_ICMP_DU_NET, len);
    TEST_ASSERT_EQUAL_HEX32(0u, idemip_rd32(msg + IDEMIP_ICMP_OFF_UNUSED));

    memset(msg, 0xFFu, MSG_CAP);
    idemip_icmp_build_time_exceeded(msg, IDEMIP_ICMP_TE_TTL, len);
    TEST_ASSERT_EQUAL_HEX32(0u, idemip_rd32(msg + IDEMIP_ICMP_OFF_UNUSED));

    memset(msg, 0xFFu, MSG_CAP);
    idemip_icmp_build_source_quench(msg, len);
    TEST_ASSERT_EQUAL_HEX32(0u, idemip_rd32(msg + IDEMIP_ICMP_OFF_UNUSED));
}

// --- time exceeded ------------------------------------------------------------

// RFC 792, type 11: "0 = time to live exceeded in transit; 1 = fragment reassembly time exceeded."
// "Code 0 may be received from a gateway. Code 1 may be received from a host."
void test_rfc792_time_exceeded_codes(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_ICMP_TE_TTL);
    TEST_ASSERT_EQUAL_UINT(1u, IDEMIP_ICMP_TE_REASSEMBLY);
}

// RFC 792: a host "reassembling a fragmented datagram" that times out "may send a time exceeded
// message", which is code 1.
void test_rfc792_reassembly_time_exceeded_message(void)
{
    const size_t len = IDEMIP_ICMP_ERR_HDR_LEN + sizeof quoted;
    memcpy(msg + IDEMIP_ICMP_OFF_QUOTE, quoted, sizeof quoted);
    idemip_icmp_build_time_exceeded(msg, IDEMIP_ICMP_TE_REASSEMBLY, len);

    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_TIME_EXCEEDED, idemip_icmp_type(msg));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_TE_REASSEMBLY, idemip_icmp_code(msg));
    TEST_ASSERT_EQUAL_HEX16(0x3b82u, idemip_icmp_cksum(msg));
    TEST_ASSERT_TRUE(idemip_cksum_valid(msg, len));
}

// --- parameter problem --------------------------------------------------------

// RFC 792, type 12: "0 = pointer indicates the error." RFC 1122 sec 3.2.2.5 adds "Code 1 = required
// option is missing."
void test_rfc792_and_rfc1122_parameter_problem_codes(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_ICMP_PP_POINTER);
    TEST_ASSERT_EQUAL_UINT(1u, IDEMIP_ICMP_PP_MISSING_OPTION);
}

// RFC 792: the Pointer is the first octet of the third word, and "(if there are options present) 20
// indicates something is wrong with the type code of the first option". The remaining 24 bits of
// that word are unused, so they are zero when sent.
void test_rfc792_parameter_problem_pointer_at_octet_four(void)
{
    const size_t len = IDEMIP_ICMP_ERR_HDR_LEN + sizeof quoted;
    memset(msg, 0xFFu, MSG_CAP);
    memcpy(msg + IDEMIP_ICMP_OFF_QUOTE, quoted, sizeof quoted);
    idemip_icmp_build_parameter_problem(msg, IDEMIP_ICMP_PP_POINTER, 20u, len);

    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_PARAMETER_PROBLEM, idemip_icmp_type(msg));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_PP_POINTER, idemip_icmp_code(msg));
    TEST_ASSERT_EQUAL_UINT8(20u, idemip_icmp_pointer(msg));
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP_OFF_POINTER);
    TEST_ASSERT_EQUAL_HEX32(0x14000000u, idemip_rd32(msg + IDEMIP_ICMP_OFF_POINTER));
    TEST_ASSERT_EQUAL_HEX16(0x2683u, idemip_icmp_cksum(msg));
    TEST_ASSERT_TRUE(idemip_cksum_valid(msg, len));
}

// RFC 792: "For example, 1 indicates something is wrong with the Type of Service", which is octet 1
// of the RFC 791 header.
void test_rfc792_pointer_one_is_the_type_of_service_octet(void)
{
    const size_t len = IDEMIP_ICMP_ERR_HDR_LEN + sizeof quoted;
    memcpy(msg + IDEMIP_ICMP_OFF_QUOTE, quoted, sizeof quoted);
    idemip_icmp_build_parameter_problem(msg, IDEMIP_ICMP_PP_POINTER, IDEMIP_IP4_OFF_TOS, len);

    TEST_ASSERT_EQUAL_UINT8(1u, idemip_icmp_pointer(msg));
    // The pointer indexes the quoted datagram, so it names that datagram's Type of Service octet and
    // not the Version and IHL octet before it.
    TEST_ASSERT_EQUAL_PTR(msg + IDEMIP_ICMP_OFF_QUOTE + IDEMIP_IP4_OFF_TOS,
                          idemip_icmp_quote(msg) + idemip_icmp_pointer(msg));
    TEST_ASSERT_EQUAL_HEX8(quoted[IDEMIP_IP4_OFF_TOS], idemip_icmp_quote(msg)[idemip_icmp_pointer(msg)]);
    TEST_ASSERT_EQUAL_HEX8(0x45u, idemip_icmp_quote(msg)[0]);
}

// --- source quench ------------------------------------------------------------

// RFC 792, type 4: "Code 0". RFC 1122 sec 3.2.2.3 keeps it a host option.
void test_rfc792_source_quench_message(void)
{
    const size_t len = IDEMIP_ICMP_ERR_HDR_LEN + sizeof quoted;
    memcpy(msg + IDEMIP_ICMP_OFF_QUOTE, quoted, sizeof quoted);
    idemip_icmp_build_source_quench(msg, len);

    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_SOURCE_QUENCH, idemip_icmp_type(msg));
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_icmp_code(msg));
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_ICMP_CODE_SOURCE_QUENCH);
    TEST_ASSERT_TRUE(idemip_cksum_valid(msg, len));
}

// --- redirect -----------------------------------------------------------------

// RFC 792, type 5: "0 = Redirect datagrams for the Network. 1 = Redirect datagrams for the Host.
// 2 = ... for the Type of Service and Network. 3 = ... for the Type of Service and Host."
void test_rfc792_redirect_codes(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_ICMP_RD_NET);
    TEST_ASSERT_EQUAL_UINT(1u, IDEMIP_ICMP_RD_HOST);
    TEST_ASSERT_EQUAL_UINT(2u, IDEMIP_ICMP_RD_TOS_NET);
    TEST_ASSERT_EQUAL_UINT(3u, IDEMIP_ICMP_RD_TOS_HOST);
}

// RFC 792 Redirect puts the "Gateway Internet Address" in the third word, where the other error
// types have an unused one. RFC 1122 sec 3.2.2.2: "A host receiving a Redirect message MUST update
// its routing information accordingly", so this end reads that address.
void test_rfc792_redirect_gateway_address(void)
{
    const uint8_t rd[12] = {5, 1, 0, 0, 0xC0, 0x00, 0x02, 0xFE, 0x45, 0x00, 0x00, 0x54};
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP_OFF_GATEWAY);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_REDIRECT, idemip_icmp_type(rd));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_RD_HOST, idemip_icmp_code(rd));
    TEST_ASSERT_EQUAL_HEX32(0xC00002FEu, idemip_icmp_gateway(rd));
}

// --- what an error message quotes ---------------------------------------------

// RFC 792: "The internet header plus the first 64 bits of the original datagram's data."
// RFC 1122 sec 3.2.2: "at least the first 8 data octets". The quoted header is IHL 32-bit words, so
// the message grows with the options the original carried.
void test_rfc792_error_quotes_header_plus_sixty_four_bits(void)
{
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP_ERR_QUOTE_DATA);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP_ERR_HDR_LEN);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP_OFF_QUOTE);

    // IHL 5, the option-free header: 8 + 20 + 8.
    TEST_ASSERT_EQUAL_size_t(36u, idemip_icmp_err_len(quoted));
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP_ERR_HDR_LEN + sizeof quoted, idemip_icmp_err_len(quoted));

    // IHL 7, a header carrying two words of options: 8 + 28 + 8.
    uint8_t with_options[IDEMIP_IPV4_HDR_LEN + 8u];
    memcpy(with_options, quoted, sizeof with_options);
    with_options[IDEMIP_IP4_OFF_VER_IHL] = 0x47u;
    TEST_ASSERT_EQUAL_UINT8(7u, idemip_ip4_ihl(with_options));
    TEST_ASSERT_EQUAL_size_t(44u, idemip_icmp_err_len(with_options));
}

// --- timestamp and information request ----------------------------------------

// RFC 792 Timestamp or Timestamp Reply: the echo fields, then Originate, Receive and Transmit
// Timestamps, each "32 bits of milliseconds since midnight UT".
void test_rfc792_timestamp_figure_offsets(void)
{
    const uint8_t ts[IDEMIP_ICMP_TS_LEN] = {13,   0,    0,    0,    0x12, 0x34, 0x00, 0x01, 0x00, 0x00,
                                            0x00, 0x0A, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x1E};
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP_OFF_ORIG_TS);
    TEST_ASSERT_EQUAL_UINT(12u, IDEMIP_ICMP_OFF_RECV_TS);
    TEST_ASSERT_EQUAL_UINT(16u, IDEMIP_ICMP_OFF_XMIT_TS);
    TEST_ASSERT_EQUAL_UINT(20u, IDEMIP_ICMP_TS_LEN);

    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_TIMESTAMP, idemip_icmp_type(ts));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_CODE_TIMESTAMP, idemip_icmp_code(ts));
    TEST_ASSERT_EQUAL_HEX32(10u, idemip_icmp_orig_ts(ts));
    TEST_ASSERT_EQUAL_HEX32(20u, idemip_icmp_recv_ts(ts));
    TEST_ASSERT_EQUAL_HEX32(30u, idemip_icmp_xmit_ts(ts));
}

// RFC 792: "any time can be inserted in a timestamp provided the high order bit of the timestamp is
// also set to indicate this non-standard value."
void test_rfc792_nonstandard_timestamp_high_order_bit(void)
{
    uint8_t ts[IDEMIP_ICMP_TS_LEN];
    memset(ts, 0, sizeof ts);
    idemip_wr32(ts + IDEMIP_ICMP_OFF_ORIG_TS, IDEMIP_ICMP_TS_NONSTANDARD | 5u);
    TEST_ASSERT_EQUAL_HEX32(0x80000000u, IDEMIP_ICMP_TS_NONSTANDARD);
    TEST_ASSERT_EQUAL_HEX8(0x80u, ts[IDEMIP_ICMP_OFF_ORIG_TS]);
    TEST_ASSERT_TRUE((idemip_icmp_orig_ts(ts) & IDEMIP_ICMP_TS_NONSTANDARD) != 0u);
}

// RFC 792 Information Request or Information Reply: the figure ends at the Sequence Number, so the
// message is eight octets and carries no data.
void test_rfc792_information_request_is_eight_octets(void)
{
    const uint8_t info[IDEMIP_ICMP_INFO_LEN] = {15, 0, 0xDE, 0xCA, 0x12, 0x34, 0x00, 0x01};
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP_INFO_LEN);
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_INFO_REQUEST, idemip_icmp_type(info));
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP_CODE_INFO, idemip_icmp_code(info));
    TEST_ASSERT_EQUAL_HEX16(0x1234u, idemip_icmp_id(info));
    TEST_ASSERT_EQUAL_HEX16(0x0001u, idemip_icmp_seq(info));
    TEST_ASSERT_TRUE(idemip_cksum_valid(info, sizeof info));
}

// --- the accessors read the caller's bytes wherever they lie -------------------

// A message lands 14 octets into an Ethernet frame plus 20 of internet header, so octet 2 of the
// checksum sits at an odd address. Every accessor assembles its field from bytes, so the same
// message read at an odd offset gives the same answers.
void test_accessors_read_the_same_at_an_odd_offset(void)
{
    uint8_t frame[1u + sizeof echo_req];
    frame[0] = 0xFFu;
    memcpy(frame + 1u, echo_req, sizeof echo_req);

    TEST_ASSERT_EQUAL_UINT8(idemip_icmp_type(echo_req), idemip_icmp_type(frame + 1u));
    TEST_ASSERT_EQUAL_HEX16(idemip_icmp_cksum(echo_req), idemip_icmp_cksum(frame + 1u));
    TEST_ASSERT_EQUAL_HEX16(idemip_icmp_id(echo_req), idemip_icmp_id(frame + 1u));
    TEST_ASSERT_EQUAL_HEX16(idemip_icmp_seq(echo_req), idemip_icmp_seq(frame + 1u));
    TEST_ASSERT_TRUE(idemip_cksum_valid(frame + 1u, sizeof echo_req));
}

// A build helper writes the message and nothing else: the same call on the same bytes gives the same
// bytes, and the octets past the length it was handed never move. The canary tearDown checks covers
// the far side; this covers repeating the call.
void test_building_twice_gives_the_same_bytes(void)
{
    uint8_t first[MSG_CAP];
    const size_t len = IDEMIP_ICMP_ERR_HDR_LEN + sizeof quoted;

    memcpy(msg + IDEMIP_ICMP_OFF_QUOTE, quoted, sizeof quoted);
    idemip_icmp_build_dest_unreachable(msg, IDEMIP_ICMP_DU_PROTOCOL, len);
    memcpy(first, msg, MSG_CAP);

    idemip_icmp_build_dest_unreachable(msg, IDEMIP_ICMP_DU_PROTOCOL, len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(first, msg, MSG_CAP);
}
