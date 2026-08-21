// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RFC 4443, ICMPv6. Every vector is the RFC's own: the sec 2.1 general format figure, the code
// lists of sec 3.1 / 3.3 / 3.4, the worked Type 4 / Code 1 / Pointer 40 example of sec 3.4, the
// sec 4.1 and 4.2 echo figures, and the minimum-MTU bound of sec 2.4 (c). The MLD types come from
// RFC 2710 sec 3.1.
//
// RFC 4443 publishes no checksum example, so the sec 2.3 cases assert the two properties the text
// states instead: a message carrying its own checksum sums to zero (RFC 1071 sec 1), and the sum
// covers the IPv6 addresses through the sec 8.1 pseudo-header, which RFC 792 did not.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#include "src/icmp/icmpv6.h"

#include <string.h>
#include <unity.h>

// Big enough for a full error message: eight octets plus the largest quote sec 2.4 (c) allows.
static uint8_t msg[IDEMIP_ICMP6_ERR_HDR_LEN + IDEMIP_ICMP6_ERR_QUOTE_MAX + 64];
static uint8_t invoking[2048];

// Arbitrary addresses. Nothing here asserts a published checksum value, only that the sum covers
// what sec 2.3 says it covers.
static const uint8_t src6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const uint8_t dst6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

void setUp(void)
{
    memset(msg, 0xEE, sizeof msg);
    for (size_t i = 0; i < sizeof invoking; i++)
    {
        invoking[i] = (uint8_t)(i & 0xFFu);
    }
}
void tearDown(void)
{
    // Nothing to release: this suite holds no allocation, only file-scope storage.
}

// The 16-bit one's complement sum of the pseudo-header and the whole message, folded. RFC 1071
// sec 1: a span carrying its own checksum sums to all ones, whose complement is zero.
static uint16_t verify(const uint8_t *m, size_t len)
{
    uint32_t sum = idemip_ip6_pseudo_accum(0u, src6, dst6, (uint32_t)len, IDEMIP_IP6_NH_ICMPV6);
    return idemip_cksum_final(idemip_cksum_accum(sum, m, len));
}

// --- sec 2.1, message general format -----------------------------------------

// The figure is Type, Code, Checksum, then Message Body. These bytes are read out at those offsets.
void test_rfc4443_sec21_head_fields_read_out_of_the_message(void)
{
    const uint8_t m[8] = {0x04, 0x01, 0x12, 0x34, 0x00, 0x00, 0x00, 0x28};
    TEST_ASSERT_EQUAL_UINT8(0x04u, idemip_icmp6_type(m));
    TEST_ASSERT_EQUAL_UINT8(0x01u, idemip_icmp6_code(m));
    TEST_ASSERT_EQUAL_HEX16(0x1234u, idemip_icmp6_cksum(m));
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_ICMP6_OFF_TYPE);
    TEST_ASSERT_EQUAL_UINT(1u, IDEMIP_ICMP6_OFF_CODE);
    TEST_ASSERT_EQUAL_UINT(2u, IDEMIP_ICMP6_OFF_CKSUM);
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP6_OFF_BODY);
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP6_HDR_LEN);
}

// sec 2.1: "error messages have message types from 0 to 127; informational messages have message
// types from 128 to 255."
void test_rfc4443_sec21_type_class_split(void)
{
    uint8_t m[4] = {0, 0, 0, 0};
    for (unsigned t = 0; t <= 255u; t++)
    {
        m[IDEMIP_ICMP6_OFF_TYPE] = (uint8_t)t;
        if (t < 128u)
        {
            TEST_ASSERT_FALSE_MESSAGE(idemip_icmp6_is_informational(m), "a type below 128 is an error message");
        }
        else
        {
            TEST_ASSERT_TRUE_MESSAGE(idemip_icmp6_is_informational(m), "a type of 128 and above is informational");
        }
    }
    TEST_ASSERT_EQUAL_HEX8(0x80u, IDEMIP_ICMP6_INFORMATIONAL);
}

// The type numbers sec 2.1 lists for the messages sections 3 and 4 describe.
void test_rfc4443_sec21_assigned_types(void)
{
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ICMP6_DEST_UNREACHABLE);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_ICMP6_PACKET_TOO_BIG);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_ICMP6_TIME_EXCEEDED);
    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_ICMP6_PARAMETER_PROBLEM);
    TEST_ASSERT_EQUAL_UINT8(128u, IDEMIP_ICMP6_ECHO_REQUEST);
    TEST_ASSERT_EQUAL_UINT8(129u, IDEMIP_ICMP6_ECHO_REPLY);
}

// The 32-bit field sec 3 puts at offset 4 is one field under three names, so all three offsets are
// the head of the Message Body.
void test_rfc4443_sec3_body_word_is_one_field(void)
{
    TEST_ASSERT_EQUAL_UINT(IDEMIP_ICMP6_OFF_BODY, IDEMIP_ICMP6_OFF_MTU);
    TEST_ASSERT_EQUAL_UINT(IDEMIP_ICMP6_OFF_BODY, IDEMIP_ICMP6_OFF_POINTER);
    TEST_ASSERT_EQUAL_UINT(IDEMIP_ICMP6_OFF_BODY, IDEMIP_ICMP6_OFF_UNUSED);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP6_ERR_HDR_LEN);
}

// --- RFC 2710 sec 3.1, the MLD types ----------------------------------------

// "Multicast Listener Query (Type = decimal 130) ... Multicast Listener Report (Type = decimal 131)
// ... Multicast Listener Done (Type = decimal 132)". All three are informational by RFC 4443
// sec 2.1, so a node that does not implement MLD silently discards them under sec 2.4 (b).
void test_rfc2710_sec31_mld_types(void)
{
    uint8_t m[4] = {0, 0, 0, 0};
    TEST_ASSERT_EQUAL_UINT8(130u, IDEMIP_ICMP6_MLD_QUERY);
    TEST_ASSERT_EQUAL_UINT8(131u, IDEMIP_ICMP6_MLD_REPORT);
    TEST_ASSERT_EQUAL_UINT8(132u, IDEMIP_ICMP6_MLD_DONE);

    m[IDEMIP_ICMP6_OFF_TYPE] = (uint8_t)IDEMIP_ICMP6_MLD_QUERY;
    TEST_ASSERT_TRUE(idemip_icmp6_is_informational(m));
    m[IDEMIP_ICMP6_OFF_TYPE] = (uint8_t)IDEMIP_ICMP6_MLD_REPORT;
    TEST_ASSERT_TRUE(idemip_icmp6_is_informational(m));
    m[IDEMIP_ICMP6_OFF_TYPE] = (uint8_t)IDEMIP_ICMP6_MLD_DONE;
    TEST_ASSERT_TRUE(idemip_icmp6_is_informational(m));
}

// --- sec 3, the codes --------------------------------------------------------

// sec 3.1: "0 - No route to destination / 1 - Communication with destination administratively
// prohibited / 2 - Beyond scope of source address / 3 - Address unreachable / 4 - Port unreachable /
// 5 - Source address failed ingress/egress policy / 6 - Reject route to destination".
void test_rfc4443_sec31_destination_unreachable_codes(void)
{
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ICMP6_DU_NO_ROUTE);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ICMP6_DU_PROHIBITED);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_ICMP6_DU_BEYOND_SCOPE);
    TEST_ASSERT_EQUAL_UINT8(3u, IDEMIP_ICMP6_DU_ADDR_UNREACH);
    TEST_ASSERT_EQUAL_UINT8(4u, IDEMIP_ICMP6_DU_PORT_UNREACH);
    TEST_ASSERT_EQUAL_UINT8(5u, IDEMIP_ICMP6_DU_SRC_POLICY);
    TEST_ASSERT_EQUAL_UINT8(6u, IDEMIP_ICMP6_DU_REJECT_ROUTE);
}

// sec 3.3: "0 - Hop limit exceeded in transit / 1 - Fragment reassembly time exceeded".
void test_rfc4443_sec33_time_exceeded_codes(void)
{
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ICMP6_TE_HOP_LIMIT);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ICMP6_TE_REASSEMBLY);
}

// sec 3.4: "0 - Erroneous header field encountered / 1 - Unrecognized Next Header type encountered /
// 2 - Unrecognized IPv6 option encountered".
void test_rfc4443_sec34_parameter_problem_codes(void)
{
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ICMP6_PP_ERRONEOUS_HDR);
    TEST_ASSERT_EQUAL_UINT8(1u, IDEMIP_ICMP6_PP_UNREC_NEXT_HDR);
    TEST_ASSERT_EQUAL_UINT8(2u, IDEMIP_ICMP6_PP_UNREC_OPTION);
}

// sec 3.2: Code is "Set to 0 (zero) by the originator and ignored by the receiver". sec 4.1 and
// sec 4.2: "Code 0".
void test_rfc4443_sec32_and_sec4_codes_are_zero(void)
{
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ICMP6_CODE_PTB);
    TEST_ASSERT_EQUAL_UINT8(0u, IDEMIP_ICMP6_CODE_ECHO);
}

// --- sec 3, building the four error types -------------------------------------

// sec 3.1: Type 1, the code, and an Unused field that "must be initialized to zero by the
// originator", then the quote.
void test_rfc4443_sec31_dest_unreach_build(void)
{
    size_t len = idemip_icmp6_dest_unreach_build(msg, IDEMIP_ICMP6_DU_PORT_UNREACH, invoking, 64u);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_HDR_LEN + 64u, len);
    TEST_ASSERT_EQUAL_UINT8(1u, idemip_icmp6_type(msg));
    TEST_ASSERT_EQUAL_UINT8(4u, idemip_icmp6_code(msg));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_icmp6_cksum(msg));
    TEST_ASSERT_EQUAL_HEX32(0u, idemip_rd32(msg + IDEMIP_ICMP6_OFF_UNUSED));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(invoking, msg + IDEMIP_ICMP6_ERR_HDR_LEN, 64u);
    TEST_ASSERT_FALSE(idemip_icmp6_is_informational(msg));
}

// sec 3.2: Type 2, Code 0, and "The Maximum Transmission Unit of the next-hop link". The minimum
// IPv6 MTU of RFC 8200 sec 5 is the smallest a next hop can report.
void test_rfc4443_sec32_packet_too_big_build(void)
{
    size_t len = idemip_icmp6_packet_too_big_build(msg, IDEMIP_IPV6_MIN_MTU, invoking, 32u);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_HDR_LEN + 32u, len);
    TEST_ASSERT_EQUAL_UINT8(2u, idemip_icmp6_type(msg));
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_icmp6_code(msg));
    TEST_ASSERT_EQUAL_UINT32(1280u, idemip_icmp6_mtu(msg));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(invoking, msg + IDEMIP_ICMP6_ERR_HDR_LEN, 32u);
}

// sec 3.3: Type 3, Code 1 for "Fragment reassembly time exceeded", Unused zero.
void test_rfc4443_sec33_time_exceeded_build(void)
{
    size_t len = idemip_icmp6_time_exceeded_build(msg, IDEMIP_ICMP6_TE_REASSEMBLY, invoking, 16u);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_HDR_LEN + 16u, len);
    TEST_ASSERT_EQUAL_UINT8(3u, idemip_icmp6_type(msg));
    TEST_ASSERT_EQUAL_UINT8(1u, idemip_icmp6_code(msg));
    TEST_ASSERT_EQUAL_HEX32(0u, idemip_rd32(msg + IDEMIP_ICMP6_OFF_UNUSED));
}

// sec 3.4's own example: "an ICMPv6 message with a Type field of 4, Code field of 1, and Pointer
// field of 40 would indicate that the IPv6 extension header following the IPv6 header of the
// original packet holds an unrecognized Next Header field value." 40 is IDEMIP_IPV6_HDR_LEN.
void test_rfc4443_sec34_pointer_example(void)
{
    size_t len =
        idemip_icmp6_param_problem_build(msg, IDEMIP_ICMP6_PP_UNREC_NEXT_HDR, IDEMIP_IPV6_HDR_LEN, invoking, 128u);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_HDR_LEN + 128u, len);
    TEST_ASSERT_EQUAL_UINT8(4u, idemip_icmp6_type(msg));
    TEST_ASSERT_EQUAL_UINT8(1u, idemip_icmp6_code(msg));
    TEST_ASSERT_EQUAL_UINT32(40u, idemip_icmp6_pointer(msg));
    // The pointer names an octet of the invoking packet the message carries, so the octet is there.
    TEST_ASSERT_EQUAL_UINT8(invoking[40], msg[IDEMIP_ICMP6_ERR_HDR_LEN + 40u]);
}

// The four error types write their 32-bit field at the same offset, so a Pointer read back as an
// MTU is the same number. This is the aliasing the figures show, checked on built bytes.
void test_rfc4443_sec3_the_body_word_is_written_at_offset_four(void)
{
    (void)idemip_icmp6_param_problem_build(msg, IDEMIP_ICMP6_PP_ERRONEOUS_HDR, 0x01020304u, invoking, 8u);
    TEST_ASSERT_EQUAL_UINT32(0x01020304u, idemip_icmp6_pointer(msg));
    TEST_ASSERT_EQUAL_UINT32(0x01020304u, idemip_icmp6_mtu(msg));
    TEST_ASSERT_EQUAL_HEX8(0x01u, msg[4]);
    TEST_ASSERT_EQUAL_HEX8(0x02u, msg[5]);
    TEST_ASSERT_EQUAL_HEX8(0x03u, msg[6]);
    TEST_ASSERT_EQUAL_HEX8(0x04u, msg[7]);
}

// --- sec 2.4 (c), the quote bound --------------------------------------------

// "as much of the IPv6 offending (invoking) packet ... as possible without making the error message
// packet exceed the minimum IPv6 MTU". The packet is the IPv6 header, the eight octets, and the
// quote, so the quote is 1280 - 40 - 8.
void test_rfc4443_sec24c_quote_max_derivation(void)
{
    TEST_ASSERT_EQUAL_size_t(1232u, (size_t)IDEMIP_ICMP6_ERR_QUOTE_MAX);
    TEST_ASSERT_EQUAL_size_t(1280u,
                             (size_t)IDEMIP_IPV6_HDR_LEN + IDEMIP_ICMP6_ERR_HDR_LEN + IDEMIP_ICMP6_ERR_QUOTE_MAX);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_IPV6_MIN_MTU,
                             (size_t)IDEMIP_IPV6_HDR_LEN + IDEMIP_ICMP6_ERR_HDR_LEN + IDEMIP_ICMP6_ERR_QUOTE_MAX);
}

// An invoking packet longer than the bound is truncated, and the message plus its IPv6 header lands
// exactly on the minimum MTU.
void test_rfc4443_sec24c_long_invoking_packet_is_truncated(void)
{
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_QUOTE_MAX, idemip_icmp6_err_quote_len(2000u));
    size_t len = idemip_icmp6_dest_unreach_build(msg, IDEMIP_ICMP6_DU_NO_ROUTE, invoking, 2000u);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_HDR_LEN + IDEMIP_ICMP6_ERR_QUOTE_MAX, len);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_IPV6_MIN_MTU, len + IDEMIP_IPV6_HDR_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(invoking, msg + IDEMIP_ICMP6_ERR_HDR_LEN, IDEMIP_ICMP6_ERR_QUOTE_MAX);
    // Nothing past the truncation point was written.
    TEST_ASSERT_EQUAL_HEX8(0xEEu, msg[len]);
}

// A packet at or below the bound is carried whole, and never padded up to it.
void test_rfc4443_sec24c_short_invoking_packet_is_carried_whole(void)
{
    TEST_ASSERT_EQUAL_size_t(0u, idemip_icmp6_err_quote_len(0u));
    TEST_ASSERT_EQUAL_size_t(1u, idemip_icmp6_err_quote_len(1u));
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_QUOTE_MAX, idemip_icmp6_err_quote_len(IDEMIP_ICMP6_ERR_QUOTE_MAX));
    size_t len = idemip_icmp6_time_exceeded_build(msg, IDEMIP_ICMP6_TE_HOP_LIMIT, invoking, 40u);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_HDR_LEN + 40u, len);
    TEST_ASSERT_EQUAL_HEX8(0xEEu, msg[len]);
}

// --- sec 4, echo -------------------------------------------------------------

// The sec 4.1 figure puts Identifier at offset 4 and Sequence Number at offset 6, then Data.
void test_rfc4443_sec41_echo_field_offsets(void)
{
    const uint8_t m[10] = {0x80, 0x00, 0x00, 0x00, 0xAB, 0xCD, 0x00, 0x07, 0x61, 0x62};
    TEST_ASSERT_EQUAL_UINT8(128u, idemip_icmp6_type(m));
    TEST_ASSERT_EQUAL_HEX16(0xABCDu, idemip_icmp6_id(m));
    TEST_ASSERT_EQUAL_HEX16(0x0007u, idemip_icmp6_seq(m));
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP6_OFF_ID);
    TEST_ASSERT_EQUAL_UINT(6u, IDEMIP_ICMP6_OFF_SEQ);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP6_ECHO_HDR_LEN);
}

// sec 4.2: Type 129, Code 0, the Identifier and Sequence Number "from the invoking Echo Request
// message", and "The data received in the ICMPv6 Echo Request message MUST be returned entirely and
// unmodified".
void test_rfc4443_sec42_echo_reply_build(void)
{
    // A request, built as the sec 4.1 figure lays it out, then answered from its own fields.
    uint8_t req[IDEMIP_ICMP6_ECHO_HDR_LEN + 24];
    idemip_icmp6_hdr_write(req, (uint8_t)IDEMIP_ICMP6_ECHO_REQUEST, IDEMIP_ICMP6_CODE_ECHO);
    idemip_wr16(req + IDEMIP_ICMP6_OFF_ID, 0xABCDu);
    idemip_wr16(req + IDEMIP_ICMP6_OFF_SEQ, 0x0007u);
    for (size_t i = 0; i < 24u; i++)
    {
        req[IDEMIP_ICMP6_ECHO_HDR_LEN + i] = (uint8_t)(0x40u + i);
    }

    size_t len = idemip_icmp6_echo_reply_build(msg, idemip_icmp6_id(req), idemip_icmp6_seq(req),
                                               req + IDEMIP_ICMP6_ECHO_HDR_LEN, 24u);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ECHO_HDR_LEN + 24u, len);
    TEST_ASSERT_EQUAL_UINT8(129u, idemip_icmp6_type(msg));
    TEST_ASSERT_EQUAL_UINT8(0u, idemip_icmp6_code(msg));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_icmp6_cksum(msg));
    TEST_ASSERT_EQUAL_HEX16(0xABCDu, idemip_icmp6_id(msg));
    TEST_ASSERT_EQUAL_HEX16(0x0007u, idemip_icmp6_seq(msg));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(req + IDEMIP_ICMP6_ECHO_HDR_LEN, msg + IDEMIP_ICMP6_ECHO_HDR_LEN, 24u);
    TEST_ASSERT_TRUE(idemip_icmp6_is_informational(msg));
}

// sec 4.1: "Data  Zero or more octets of arbitrary data", so a request with none is answered with
// none and nothing past the eight octets is written.
void test_rfc4443_sec42_echo_reply_with_no_data(void)
{
    size_t len = idemip_icmp6_echo_reply_build(msg, 0u, 0u, NULL, 0u);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ECHO_HDR_LEN, len);
    TEST_ASSERT_EQUAL_UINT8(129u, idemip_icmp6_type(msg));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_icmp6_id(msg));
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_icmp6_seq(msg));
    TEST_ASSERT_EQUAL_HEX8(0xEEu, msg[IDEMIP_ICMP6_ECHO_HDR_LEN]);
}

// sec 4.2 returns the data "entirely and unmodified", so an odd-length payload is not padded and
// the last octet survives.
void test_rfc4443_sec42_echo_reply_data_of_odd_length(void)
{
    const uint8_t data[5] = {0x11, 0x22, 0x33, 0x44, 0x55};
    size_t len = idemip_icmp6_echo_reply_build(msg, 1u, 2u, data, sizeof data);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ECHO_HDR_LEN + 5u, len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, msg + IDEMIP_ICMP6_ECHO_HDR_LEN, sizeof data);
    TEST_ASSERT_EQUAL_HEX8(0xEEu, msg[len]);
}

// --- sec 2.3, the checksum ---------------------------------------------------

// "For computing the checksum, the checksum field is first set to zero." Every build helper leaves
// it zero, so the sum a caller computes next covers a zeroed field.
void test_rfc4443_sec23_checksum_field_starts_zero(void)
{
    (void)idemip_icmp6_echo_reply_build(msg, 0x1234u, 0x5678u, invoking, 16u);
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_icmp6_cksum(msg));
    (void)idemip_icmp6_dest_unreach_build(msg, IDEMIP_ICMP6_DU_ADDR_UNREACH, invoking, 16u);
    TEST_ASSERT_EQUAL_HEX16(0u, idemip_icmp6_cksum(msg));
}

// "the 16-bit one's complement of the one's complement sum of the entire ICMPv6 message, starting
// with the ICMPv6 message type field, and prepended with a 'pseudo-header' of IPv6 header fields".
// Summing a message that carries its own checksum therefore folds to zero (RFC 1071 sec 1).
void test_rfc4443_sec23_checksum_verifies_over_itself(void)
{
    size_t len = idemip_icmp6_echo_reply_build(msg, 0xABCDu, 0x0007u, invoking, 24u);
    idemip_wr16(msg + IDEMIP_ICMP6_OFF_CKSUM, idemip_icmp6_cksum_compute(msg, len, src6, dst6));
    TEST_ASSERT_NOT_EQUAL_UINT16(0u, idemip_icmp6_cksum(msg));
    TEST_ASSERT_EQUAL_HEX16(0u, verify(msg, len));
}

// An error message with an odd-length quote checks out the same way: RFC 1071 sec 1 takes the final
// byte as [Z,0], and the pad is not sent.
void test_rfc4443_sec23_checksum_verifies_over_an_odd_length_message(void)
{
    size_t len = idemip_icmp6_param_problem_build(msg, IDEMIP_ICMP6_PP_UNREC_OPTION, 41u, invoking, 41u);
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_ERR_HDR_LEN + 41u, len);
    idemip_wr16(msg + IDEMIP_ICMP6_OFF_CKSUM, idemip_icmp6_cksum_compute(msg, len, src6, dst6));
    TEST_ASSERT_EQUAL_HEX16(0u, verify(msg, len));
}

// The pseudo-header carries the addresses, so the same message between different addresses has a
// different checksum. This is what sec 2.3 calls "a change from IPv4": RFC 792 covered the message
// alone.
void test_rfc4443_sec23_checksum_covers_the_addresses(void)
{
    uint8_t other[16];
    memcpy(other, dst6, sizeof other);
    other[15] = 0x03u;

    size_t len = idemip_icmp6_echo_reply_build(msg, 1u, 1u, invoking, 8u);
    uint16_t a = idemip_icmp6_cksum_compute(msg, len, src6, dst6);
    uint16_t b = idemip_icmp6_cksum_compute(msg, len, src6, other);
    TEST_ASSERT_NOT_EQUAL_UINT16(a, b);

    // And the RFC 792 form, which sums the message alone, matches neither.
    TEST_ASSERT_NOT_EQUAL_UINT16(a, idemip_cksum(msg, len));
    TEST_ASSERT_NOT_EQUAL_UINT16(b, idemip_cksum(msg, len));
}

// "The Next Header value used in the pseudo-header is 58." A sum built with any other value differs,
// which is what makes 58 load-bearing rather than decorative.
void test_rfc4443_sec23_pseudo_header_next_header_is_58(void)
{
    TEST_ASSERT_EQUAL_UINT8(58u, IDEMIP_IP6_NH_ICMPV6);

    size_t len = idemip_icmp6_echo_reply_build(msg, 1u, 1u, invoking, 8u);
    uint16_t with58 = idemip_icmp6_cksum_compute(msg, len, src6, dst6);
    uint32_t wrong = idemip_ip6_pseudo_accum(0u, src6, dst6, (uint32_t)len, IDEMIP_IP6_NH_ICMPV6 + 1u);
    TEST_ASSERT_NOT_EQUAL_UINT16(with58, idemip_cksum_final(idemip_cksum_accum(wrong, msg, len)));
}

// The sum covers "the entire ICMPv6 message", quote included, so a flipped octet in the quote is
// caught.
void test_rfc4443_sec23_checksum_covers_the_quote(void)
{
    size_t len = idemip_icmp6_dest_unreach_build(msg, IDEMIP_ICMP6_DU_PORT_UNREACH, invoking, 64u);
    idemip_wr16(msg + IDEMIP_ICMP6_OFF_CKSUM, idemip_icmp6_cksum_compute(msg, len, src6, dst6));
    TEST_ASSERT_EQUAL_HEX16(0u, verify(msg, len));
    msg[len - 1u] = (uint8_t)(msg[len - 1u] ^ 0x01u);
    TEST_ASSERT_NOT_EQUAL_UINT16(0u, verify(msg, len));
}

// --- RFC 4861 sec 4, the five message bodies, and RFC 2710 sec 3 ------------
// These formats and their accessors are icmpv6.h's, which nd6.h:14 states, and dispatch classifies a
// message without reading past the type and the length. Reading the body is the CALLER's, exactly as
// an RFC 826 packet's body is, so every accessor below is one no library .c file names and only a
// case can hold to its offset.

// sec 3: "Maximum Response Delay" at octet 4, "Reserved" at 6, "Multicast Address" at 8, and the
// message ends there. sec 3.5: the Reserved field is "ignored by receivers".
void test_rfc2710_sec3_mld_field_offsets(void)
{
    static const uint8_t group[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09};
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP6_OFF_MLD_MAX_RESP);
    TEST_ASSERT_EQUAL_UINT(6u, IDEMIP_ICMP6_OFF_MLD_RESERVED);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP6_OFF_MLD_GROUP);
    TEST_ASSERT_EQUAL_UINT(24u, IDEMIP_ICMP6_MLD_MSG_LEN);

    memset(msg, 0, IDEMIP_ICMP6_MLD_MSG_LEN);
    msg[IDEMIP_ICMP6_OFF_TYPE] = (uint8_t)IDEMIP_ICMP6_MLD_QUERY;
    idemip_wr16(msg + IDEMIP_ICMP6_OFF_MLD_MAX_RESP, 10000u); // sec 7.3's default, in milliseconds
    idemip_wr16(msg + IDEMIP_ICMP6_OFF_MLD_RESERVED, 0xFFFFu);
    memcpy(msg + IDEMIP_ICMP6_OFF_MLD_GROUP, group, 16u);

    TEST_ASSERT_EQUAL_UINT16(10000u, idemip_icmp6_mld_max_resp(msg));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(group, idemip_icmp6_mld_group(msg), 16u);
    TEST_ASSERT_TRUE(idemip_icmp6_is_mld((uint8_t)IDEMIP_ICMP6_MLD_QUERY));
    TEST_ASSERT_FALSE_MESSAGE(idemip_icmp6_is_nd((uint8_t)IDEMIP_ICMP6_MLD_QUERY),
                              "an MLD type is RFC 2710's, not one of RFC 4861 sec 4's five");
}

// sec 4.2's figure: Cur Hop Limit at octet 4, then M and O as the top two bits of octet 5, Router
// Lifetime at 6, Reachable Time at 8, Retrans Timer at 12, and the options after octet 16.
void test_rfc4861_sec42_router_advertisement_field_offsets(void)
{
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP6_OFF_RA_CUR_HOP);
    TEST_ASSERT_EQUAL_UINT(5u, IDEMIP_ICMP6_OFF_RA_FLAGS);
    TEST_ASSERT_EQUAL_UINT(6u, IDEMIP_ICMP6_OFF_RA_LIFETIME);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP6_OFF_RA_REACHABLE);
    TEST_ASSERT_EQUAL_UINT(12u, IDEMIP_ICMP6_OFF_RA_RETRANS);
    TEST_ASSERT_EQUAL_UINT(16u, IDEMIP_ICMP6_RA_HDR_LEN);
    // M is the first bit of the octet and O the second, so they are the top two, in that order.
    TEST_ASSERT_EQUAL_HEX8(0x80u, IDEMIP_ICMP6_RA_FLAG_M);
    TEST_ASSERT_EQUAL_HEX8(0x40u, IDEMIP_ICMP6_RA_FLAG_O);

    memset(msg, 0, IDEMIP_ICMP6_RA_HDR_LEN);
    msg[IDEMIP_ICMP6_OFF_TYPE] = (uint8_t)IDEMIP_ICMP6_ROUTER_ADVERT;
    msg[IDEMIP_ICMP6_OFF_RA_CUR_HOP] = 64u;
    msg[IDEMIP_ICMP6_OFF_RA_FLAGS] = (uint8_t)(IDEMIP_ICMP6_RA_FLAG_M | IDEMIP_ICMP6_RA_FLAG_O);
    idemip_wr16(msg + IDEMIP_ICMP6_OFF_RA_LIFETIME, 1800u);
    idemip_wr32(msg + IDEMIP_ICMP6_OFF_RA_REACHABLE, 30000u);
    idemip_wr32(msg + IDEMIP_ICMP6_OFF_RA_RETRANS, 1000u);

    TEST_ASSERT_EQUAL_UINT8(64u, idemip_icmp6_ra_cur_hop(msg));
    TEST_ASSERT_EQUAL_HEX8(0xC0u, idemip_icmp6_ra_flags(msg));
    TEST_ASSERT_EQUAL_UINT16(1800u, idemip_icmp6_ra_lifetime(msg));
    TEST_ASSERT_EQUAL_UINT32(30000u, idemip_icmp6_ra_reachable(msg));
    TEST_ASSERT_EQUAL_UINT32(1000u, idemip_icmp6_ra_retrans(msg));

    // Each flag alone, so neither reads the other's bit.
    msg[IDEMIP_ICMP6_OFF_RA_FLAGS] = IDEMIP_ICMP6_RA_FLAG_M;
    TEST_ASSERT_TRUE((idemip_icmp6_ra_flags(msg) & IDEMIP_ICMP6_RA_FLAG_M) != 0u);
    TEST_ASSERT_FALSE((idemip_icmp6_ra_flags(msg) & IDEMIP_ICMP6_RA_FLAG_O) != 0u);
    msg[IDEMIP_ICMP6_OFF_RA_FLAGS] = IDEMIP_ICMP6_RA_FLAG_O;
    TEST_ASSERT_FALSE((idemip_icmp6_ra_flags(msg) & IDEMIP_ICMP6_RA_FLAG_M) != 0u);
    TEST_ASSERT_TRUE((idemip_icmp6_ra_flags(msg) & IDEMIP_ICMP6_RA_FLAG_O) != 0u);
}

// sec 4.4's figure: R, S and O are the top three bits of octet 4, and the Target Address runs from
// octet 8 to the end of the message at 24.
void test_rfc4861_sec44_neighbor_advertisement_field_offsets(void)
{
    static const uint8_t target[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};
    TEST_ASSERT_EQUAL_UINT(4u, IDEMIP_ICMP6_OFF_NA_FLAGS);
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP6_OFF_NA_TARGET);
    TEST_ASSERT_EQUAL_UINT(24u, IDEMIP_ICMP6_NA_HDR_LEN);
    TEST_ASSERT_EQUAL_HEX8(0x80u, IDEMIP_ICMP6_NA_FLAG_R);
    TEST_ASSERT_EQUAL_HEX8(0x40u, IDEMIP_ICMP6_NA_FLAG_S);
    TEST_ASSERT_EQUAL_HEX8(0x20u, IDEMIP_ICMP6_NA_FLAG_O);

    memset(msg, 0, IDEMIP_ICMP6_NA_HDR_LEN);
    msg[IDEMIP_ICMP6_OFF_TYPE] = (uint8_t)IDEMIP_ICMP6_NEIGHBOR_ADVERT;
    msg[IDEMIP_ICMP6_OFF_NA_FLAGS] = (uint8_t)(IDEMIP_ICMP6_NA_FLAG_S | IDEMIP_ICMP6_NA_FLAG_O);
    memcpy(msg + IDEMIP_ICMP6_OFF_NA_TARGET, target, 16u);

    TEST_ASSERT_EQUAL_HEX8(0x60u, idemip_icmp6_na_flags(msg));
    TEST_ASSERT_FALSE_MESSAGE((idemip_icmp6_na_flags(msg) & IDEMIP_ICMP6_NA_FLAG_R) != 0u,
                              "sec 4.4's Router flag was not set and must not read as set");
    // sec 4.3 puts the Target Address of a Solicitation at octet 8 too, which nd_target reads for
    // both, so the same accessor answers a message of either type.
    TEST_ASSERT_EQUAL_UINT8_ARRAY(target, idemip_icmp6_nd_target(msg), 16u);
}

// sec 4.5's figure: Target at octet 8 and Destination at 24, the message ending at 40. The two are
// distinct addresses, so an accessor reading one must not answer with the other.
void test_rfc4861_sec45_redirect_field_offsets(void)
{
    static const uint8_t target[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    static const uint8_t dest[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};
    TEST_ASSERT_EQUAL_UINT(8u, IDEMIP_ICMP6_OFF_RD_TARGET);
    TEST_ASSERT_EQUAL_UINT(24u, IDEMIP_ICMP6_OFF_RD_DEST);
    TEST_ASSERT_EQUAL_UINT(40u, IDEMIP_ICMP6_RD_HDR_LEN);

    memset(msg, 0, IDEMIP_ICMP6_RD_HDR_LEN);
    msg[IDEMIP_ICMP6_OFF_TYPE] = (uint8_t)IDEMIP_ICMP6_REDIRECT;
    memcpy(msg + IDEMIP_ICMP6_OFF_RD_TARGET, target, 16u);
    memcpy(msg + IDEMIP_ICMP6_OFF_RD_DEST, dest, 16u);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(target, idemip_icmp6_nd_target(msg), 16u);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dest, idemip_icmp6_rd_dest(msg), 16u);
}

// sec 4.1 through sec 4.5 fix one length per type, which is what dispatch checks a message against
// before naming its module.
void test_rfc4861_sec4_each_type_has_its_own_length(void)
{
    TEST_ASSERT_EQUAL_UINT(8u, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_ROUTER_SOLICIT));
    TEST_ASSERT_EQUAL_UINT(16u, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_ROUTER_ADVERT));
    TEST_ASSERT_EQUAL_UINT(24u, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT));
    TEST_ASSERT_EQUAL_UINT(24u, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_NEIGHBOR_ADVERT));
    TEST_ASSERT_EQUAL_UINT(40u, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_REDIRECT));

    for (uint8_t t = 133u; t <= 137u; t++)
    {
        TEST_ASSERT_TRUE(idemip_icmp6_is_nd(t));
        TEST_ASSERT_FALSE(idemip_icmp6_is_mld(t));
    }
    TEST_ASSERT_FALSE(idemip_icmp6_is_nd(132u));
    TEST_ASSERT_FALSE(idemip_icmp6_is_nd(138u));
}

// sec 4.6: "The length of the option (including the type and length fields) in units of 8 octets."
void test_rfc4861_sec46_option_length_counts_eight_octet_units(void)
{
    TEST_ASSERT_EQUAL_UINT(0u, IDEMIP_ICMP6_ND_OPT_OFF_TYPE);
    TEST_ASSERT_EQUAL_UINT(1u, IDEMIP_ICMP6_ND_OPT_OFF_LEN);
    TEST_ASSERT_EQUAL_UINT(2u, IDEMIP_ICMP6_ND_OPT_HDR_LEN);

    uint8_t opt[16];
    memset(opt, 0, sizeof opt);
    opt[IDEMIP_ICMP6_ND_OPT_OFF_TYPE] = IDEMIP_ICMP6_ND_OPT_SLLA;
    opt[IDEMIP_ICMP6_ND_OPT_OFF_LEN] = 1u;
    TEST_ASSERT_EQUAL_UINT8(IDEMIP_ICMP6_ND_OPT_SLLA, idemip_icmp6_nd_opt_type(opt));
    TEST_ASSERT_EQUAL_UINT_MESSAGE(8u, idemip_icmp6_nd_opt_len(opt), "a Length of 1 is eight octets");
    opt[IDEMIP_ICMP6_ND_OPT_OFF_LEN] = 2u;
    TEST_ASSERT_EQUAL_UINT(16u, idemip_icmp6_nd_opt_len(opt));

    // sec 4.6.2's Prefix Information carries a Length of 4, which is the 32 octets its fields need.
    opt[IDEMIP_ICMP6_ND_OPT_OFF_LEN] = IDEMIP_ICMP6_ND_OPT_PREFIX_LEN;
    TEST_ASSERT_EQUAL_UINT(32u, idemip_icmp6_nd_opt_len(opt));
    TEST_ASSERT_EQUAL_UINT(32u, IDEMIP_ICMP6_ND_OPT_OFF_PREFIX + 16u);
}

// sec 4.6: "Nodes MUST silently discard an ND packet that contains an option with length zero." A
// zero also never advances a walk, so the same rule is what keeps the walk finite.
void test_rfc4861_sec46_the_option_walk_refuses_zero_and_overrun(void)
{
    uint8_t opts[24];
    memset(opts, 0, sizeof opts);

    // Two well-formed options, eight octets each.
    opts[0] = IDEMIP_ICMP6_ND_OPT_SLLA;
    opts[1] = 1u;
    opts[8] = IDEMIP_ICMP6_ND_OPT_TLLA;
    opts[9] = 1u;
    TEST_ASSERT_TRUE(idemip_icmp6_nd_opts_ok(opts, 16u));
    TEST_ASSERT_TRUE_MESSAGE(idemip_icmp6_nd_opts_ok(opts, 0u), "no options at all is a walk that ends");

    // A Length of zero, which sec 4.6 discards.
    opts[9] = 0u;
    TEST_ASSERT_FALSE(idemip_icmp6_nd_opts_ok(opts, 16u));

    // A Length reaching past the octets that arrived.
    opts[9] = 2u;
    TEST_ASSERT_FALSE(idemip_icmp6_nd_opts_ok(opts, 16u));

    // An option header split by the end of the message, so not even the Length is there to read.
    opts[9] = 1u;
    TEST_ASSERT_FALSE_MESSAGE(idemip_icmp6_nd_opts_ok(opts, 17u), "a trailing octet is not an option");
}

// RFC 4861 sec 4 defines five message types, and each one's fixed fields are a length of their own.
// A type outside those five is not one of them, so it has no such length.
void test_a_type_outside_the_five_has_no_neighbor_discovery_header(void)
{
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0u, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_ECHO_REQUEST),
                                     "a type sec 4 does not define was given one of its headers");
    TEST_ASSERT_EQUAL_size_t(0u, idemip_icmp6_nd_hdr_len(0u));

    // The five it does define each carry their own.
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_RS_HDR_LEN, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_ROUTER_SOLICIT));
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_RA_HDR_LEN, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_ROUTER_ADVERT));
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_NS_HDR_LEN, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_NEIGHBOR_SOLICIT));
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_NA_HDR_LEN, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_NEIGHBOR_ADVERT));
    TEST_ASSERT_EQUAL_size_t(IDEMIP_ICMP6_RD_HDR_LEN, idemip_icmp6_nd_hdr_len((uint8_t)IDEMIP_ICMP6_REDIRECT));
}

// RFC 4443 sec 3.1: an error message carries "as much of invoking packet as possible without the
// ICMPv6 packet exceeding the minimum IPv6 MTU", and a packet of no octets leaves nothing to carry.
void test_an_error_about_a_packet_of_no_octets_carries_no_quote(void)
{
    uint8_t out[IDEMIP_ICMP6_ERR_HDR_LEN + 8u];
    static const uint8_t invoking[8] = {0};
    memset(out, 0xEE, sizeof out);

    const size_t len = idemip_icmp6_err_build(out, (uint8_t)IDEMIP_ICMP6_DEST_UNREACHABLE, IDEMIP_ICMP6_DU_PORT_UNREACH,
                                              0u, invoking, 0u);
    TEST_ASSERT_EQUAL_size_t_MESSAGE((size_t)IDEMIP_ICMP6_ERR_HDR_LEN, len,
                                     "an error about no octets carried a quote of some");
}
