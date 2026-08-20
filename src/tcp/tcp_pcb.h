// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file tcp_pcb.h
 * @brief The Transmission Control Blocks, the listeners, the send queue and the out-of-order queue.
 *
 * RFC 9293 sec 3.3.1: "We conceive of these variables being stored in a connection record called a
 * Transmission Control Block or TCB. Among the variables stored in the TCB are the local and remote
 * IP addresses and port numbers... In addition, several variables relating to the send and receive
 * sequence numbers are stored in the TCB." One table entry is one TCB, holding the address pair, the
 * port pair, the sec 3.3.1 Table 2 send variables, the sec 3.3.1 Table 3 receive variables, and the
 * sec 3.3.2 state.
 *
 * The TCB type is this module's. Every field a connection needs from outside reaches it through
 * @ref TcpPcbNs::load and @ref TcpPcbNs::store, which copy the sec 3.3.1 variables, the sec 3.3.2
 * state and the estimator and congestion state between one entry and the operand block. Nothing here
 * holds a segment's octets: a queued segment names the caller's data, and a held out-of-order
 * segment names the receive descriptor it is pinned in.
 */

#ifndef IDEMIP_TCP_PCB_H
#define IDEMIP_TCP_PCB_H

#include "src/tcp/tcp.h"

#if IDEMIP_ENABLE_TCP

IDEMIP_BEGIN_DECLS

/**
 * @brief Octets an address operand and an address in an entry span.
 *
 * RFC 4291 sec 2: "IPv6 addresses are 128-bit identifiers for interfaces and sets of interfaces".
 * An RFC 791 sec 3.1 address is the first four of them.
 */
#define IDEMIP_TCP_PCB_ADDR_BYTES 16u

/** @brief The index that names no entry. Reported when nothing matched and nothing was free. */
#define IDEMIP_TCP_PCB_NONE 0xFFFFu

/**
 * @brief RFC 9293 sec 3.1: a port of zero, which is the request for an unused one rather than a bind
 * of port zero.
 */
#define IDEMIP_TCP_PCB_PORT_ANY 0u

/**
 * @brief The first port a bind of IDEMIP_TCP_PCB_PORT_ANY draws from.
 *
 * RFC 6056 sec 3.2: "the dynamic ports consist of the range 49152-65535. However, ephemeral port
 * selection algorithms should use the whole range 1024-65535", and "Ephemeral port selection
 * algorithms SHOULD use the largest possible port range, since this reduces the chances of an
 * off-path attacker of guessing the selected port numbers." The pool wraps with a mask so no divide
 * runs, which makes it a power of two, and 32768-65535 is the largest such window inside 1024-65535:
 * 32768 ports against the 16384 of RFC 6335 sec 6's Dynamic Ports alone. RFC 6056 sec 3.1's
 * exclusion of the ports a listener holds is what keeps the wider pool off the host's own services.
 */
#define IDEMIP_TCP_PCB_PORT_EPH_FIRST 32768u

/** @brief The last ephemeral port, the last port there is. */
#define IDEMIP_TCP_PCB_PORT_EPH_LAST 65535u

/** @brief The ephemeral ports, 32768 of them, a power of two so the walk wraps with a mask. */
#define IDEMIP_TCP_PCB_PORT_EPH_COUNT (IDEMIP_TCP_PCB_PORT_EPH_LAST - IDEMIP_TCP_PCB_PORT_EPH_FIRST + 1u)

/** @brief The mask that wraps an ephemeral port walk, IDEMIP_TCP_PCB_PORT_EPH_COUNT - 1. */
#define IDEMIP_TCP_PCB_PORT_EPH_MASK (IDEMIP_TCP_PCB_PORT_EPH_COUNT - 1u)

static_assert((IDEMIP_TCP_PCB_PORT_EPH_COUNT & IDEMIP_TCP_PCB_PORT_EPH_MASK) == 0u,
              "the ephemeral ports must number a power of two so the walk wraps with a mask");
static_assert((IDEMIP_TCP_PCB_PORT_EPH_FIRST & IDEMIP_TCP_PCB_PORT_EPH_MASK) == 0u,
              "the first ephemeral port must be a multiple of their count so an OR rebuilds the port");
static_assert(IDEMIP_TCP_PCB_PORT_EPH_FIRST >= 1024u,
              "RFC 6056 sec 3.2 bounds an ephemeral pool below at 1024, the first non-System Port");

/**
 * @brief The eleven states of RFC 9293 sec 3.3.2.
 *
 * "The states are: LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT,
 * CLOSING, LAST-ACK, TIME-WAIT, and the fictional state CLOSED. CLOSED is fictional because it
 * represents the state when there is no TCB, and therefore, no connection." CLOSED is zero, so a
 * zeroed entry reads as the state that has no TCB.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_TCP_STATE_CLOSED = 0,   ///< "represents no connection state at all"
    IDEMIP_TCP_STATE_LISTEN,       ///< "waiting for a connection request from any remote TCP peer and port"
    IDEMIP_TCP_STATE_SYN_SENT,     ///< "waiting for a matching connection request after having sent a
                                   ///< connection request"
    IDEMIP_TCP_STATE_SYN_RECEIVED, ///< "waiting for a confirming connection request acknowledgment after
                                   ///< having both received and sent a connection request"
    IDEMIP_TCP_STATE_ESTABLISHED,  ///< "an open connection, data received can be delivered to the user"
    IDEMIP_TCP_STATE_FIN_WAIT_1,   ///< "waiting for a connection termination request from the remote TCP
                                   ///< peer, or an acknowledgment of the connection termination request
                                   ///< previously sent"
    IDEMIP_TCP_STATE_FIN_WAIT_2,   ///< "waiting for a connection termination request from the remote TCP peer"
    IDEMIP_TCP_STATE_CLOSE_WAIT,   ///< "waiting for a connection termination request from the local user"
    IDEMIP_TCP_STATE_CLOSING,      ///< "waiting for a connection termination request acknowledgment from the
                                   ///< remote TCP peer"
    IDEMIP_TCP_STATE_LAST_ACK,     ///< "waiting for an acknowledgment of the connection termination request
                                   ///< previously sent to the remote TCP peer"
    IDEMIP_TCP_STATE_TIME_WAIT,    ///< "waiting for enough time to pass to be sure the remote TCP peer
                                   ///< received the acknowledgment of its connection termination request"
} IdemIpTcpState;

/** @brief The eleven states, so a walk over them is bounded by a constant. */
#define IDEMIP_TCP_STATES 11u

/**
 * @brief The RFC 9293 sec 3.3.1 send and receive sequence variables of one TCB.
 *
 * Table 2, the send sequence variables, then Table 3, the receive sequence variables, at the widths
 * sec 3.4 fixes: "This space ranges from 0 to 2^32 - 1." A window is 32 bits wide because RFC 7323
 * sec 2.2 shifts the 16-bit Window field left by Snd.Wind.Shift.
 *
 * @var IdemIpTcpVars::snd_una SND.UNA, "send unacknowledged"
 * @var IdemIpTcpVars::snd_nxt SND.NXT, "send next"
 * @var IdemIpTcpVars::snd_wnd SND.WND, "send window"
 * @var IdemIpTcpVars::snd_up  SND.UP, "send urgent pointer"
 * @var IdemIpTcpVars::snd_wl1 SND.WL1, "segment sequence number used for last window update"
 * @var IdemIpTcpVars::snd_wl2 SND.WL2, "segment acknowledgment number used for last window update"
 * @var IdemIpTcpVars::iss     ISS, "initial send sequence number"
 * @var IdemIpTcpVars::rcv_nxt RCV.NXT, "receive next"
 * @var IdemIpTcpVars::rcv_wnd RCV.WND, "receive window"
 * @var IdemIpTcpVars::rcv_up  RCV.UP, "receive urgent pointer"
 * @var IdemIpTcpVars::irs     IRS, "initial receive sequence number"
 */
typedef struct
{
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t snd_wnd;
    uint32_t snd_up;
    uint32_t snd_wl1;
    uint32_t snd_wl2;
    uint32_t iss;
    uint32_t rcv_nxt;
    uint32_t rcv_wnd;
    uint32_t rcv_up;
    uint32_t irs;
} IdemIpTcpVars;

// ---------------------------------------------------------------------------
// The bits of TcpPcbCtl::flags
// ---------------------------------------------------------------------------

/** @brief RFC 6298 (5.7), the retransmission timer expired awaiting the ACK of a SYN. */
#define IDEMIP_TCP_CTL_SYN_RTX (1u << 0)

/**
 * @brief RFC 7323 sec 3.2 Snd.TS.OK, set "Once TSopt has been successfully negotiated, that is both
 * <SYN> and <SYN,ACK> contain TSopt".
 *
 * sec 5.3's PAWS check runs on a synchronized connection only while this is set.
 */
#define IDEMIP_TCP_CTL_TS_OK (1u << 1)

/**
 * @brief The estimator, congestion, option and keepalive state of one TCB.
 *
 * Everything a connection carries that RFC 9293 sec 3.3.1 does not name, each field from the RFC that
 * defines it. Held in one struct so load and store move a whole TCB in one call.
 *
 * @var TcpPcbCtl::srtt          RFC 6298 sec 2 SRTT, "smoothed round-trip time", in milliseconds
 * @var TcpPcbCtl::rttvar        RFC 6298 sec 2 RTTVAR, "round-trip time variation", in milliseconds
 * @var TcpPcbCtl::rto           RFC 6298 sec 2 RTO, "RTO <- SRTT + max (G, K*RTTVAR)", in
 *                               milliseconds
 * @var TcpPcbCtl::rtseq         the sequence number the round-trip sample is being timed on
 * @var TcpPcbCtl::rtx_deadline  the millisecond the RFC 6298 sec 5 retransmission timer expires at
 * @var TcpPcbCtl::persist_deadline the millisecond the RFC 9293 sec 3.8.6.1 zero-window probe is due
 * @var TcpPcbCtl::cwnd          RFC 5681 sec 2 cwnd, the congestion window
 * @var TcpPcbCtl::ssthresh      RFC 5681 sec 2 ssthresh, the slow start threshold
 * @var TcpPcbCtl::bytes_acked   RFC 3465 sec 2.1 bytes_acked, the byte counter Appropriate Byte
 *                               Counting keeps "in the TCP control block"
 * @var TcpPcbCtl::max_snd_wnd   RFC 5961 sec 5.2 MAX.SND.WND, "the largest window that the local
 *                               sender has ever received from its peer", which RFC 9293 sec 3.10.7.4
 *                               fifth checks SEG.ACK against and RFC 9293 sec 3.8.6.2.1 calls
 *                               Max(SND.WND)
 * @var TcpPcbCtl::ts_recent     RFC 7323 sec 3.2 TS.Recent, which "holds a timestamp to be echoed in
 *                               TSecr whenever a segment is sent"
 * @var TcpPcbCtl::last_ack_sent RFC 7323 sec 3.2 Last.ACK.sent, which "holds the ACK field from the
 *                               last segment sent"
 * @var TcpPcbCtl::ts_recent_ms  the millisecond TS.Recent was last saved, which RFC 7323 sec 5.5's
 *                               24-day idle test measures from
 * @var TcpPcbCtl::last_send_ms  the millisecond data was last sent, which RFC 5681 sec 4.1 measures
 *                               the idle interval from, zero until the first send
 * @var TcpPcbCtl::keep_idle_ms  RFC 1122 sec 4.2.3.6: keep-alives "MUST only be sent when no data or
 *                               acknowledgement packets have been received for the connection within
 *                               an interval", and that interval "MUST default to no less than two
 *                               hours"
 * @var TcpPcbCtl::keep_intvl_ms milliseconds between two keep-alive probes, lwIP
 *                               TCP_KEEPINTVL_DEFAULT
 * @var TcpPcbCtl::keep_cnt      probes sent before the connection is dropped, lwIP
 *                               TCP_KEEPCNT_DEFAULT
 * @var TcpPcbCtl::sack_left     RFC 2018 sec 3 "Left Edge of Block", one per block
 * @var TcpPcbCtl::sack_right    RFC 2018 sec 3 "Right Edge of Block", one per block
 * @var TcpPcbCtl::mss           the RFC 9293 sec 3.7.1 send MSS this connection settled on
 * @var TcpPcbCtl::rcv_ann_wnd   the receive window last announced in a Window field
 * @var TcpPcbCtl::flags         the connection's option bits
 * @var TcpPcbCtl::snd_scale     RFC 7323 sec 2.2 Snd.Wind.Shift, applied to an incoming Window field
 * @var TcpPcbCtl::rcv_scale     RFC 7323 sec 2.2 Rcv.Wind.Shift, applied to an outgoing one
 * @var TcpPcbCtl::time_wait_deadline the millisecond RFC 9293 sec 3.6 MUST-13's linger expires at,
 *                               "a time 2xMSL (Maximum Segment Lifetime)"
 * @var TcpPcbCtl::nrtx          retransmissions of the oldest unacknowledged segment, compared
 *                               against r2 and r2_syn
 * @var TcpPcbCtl::r2            RFC 1122 sec 4.2.3.5 and RFC 9293 sec 3.8.3 R2, counted as
 *                               retransmissions, which clause (a) allows: "R1 and R2 might be
 *                               measured in time units or as a count of retransmissions". Reaching
 *                               it closes the connection, clause (c). Zero is the "infinity"
 *                               clause (d) names.
 * @var TcpPcbCtl::r2_syn        the same threshold while the SYN is unacknowledged, which sec 3.8.3
 *                               MUST-23 bounds below: "R2 for a SYN segment MUST be set large enough
 *                               to provide retransmission of the segment for at least 3 minutes"
 * @var TcpPcbCtl::backoff       RFC 6298 sec 5.5 doublings of RTO, "the value of RTO SHOULD be
 *                               doubled"
 * @var TcpPcbCtl::dupacks       duplicate acknowledgments counted toward RFC 5681 sec 3.2's
 *                               threshold
 * @var TcpPcbCtl::keep_cnt_sent keep-alive probes sent since the last segment from the peer
 */
typedef struct
{
    uint32_t srtt;
    uint32_t rttvar;
    uint32_t rto;
    uint32_t rtseq;
    uint32_t rtx_deadline;
    uint32_t persist_deadline;
    uint32_t cwnd;
    uint32_t ssthresh;
    uint32_t bytes_acked;
    uint32_t max_snd_wnd;
    uint32_t ts_recent;
    uint32_t last_ack_sent;
    uint32_t ts_recent_ms;
    uint32_t last_send_ms;
    uint32_t keep_idle_ms;
    uint32_t keep_intvl_ms;
    uint32_t time_wait_deadline;
    uint32_t sack_left[IDEMIP_TCP_SACK_BLOCKS_MAX];
    uint32_t sack_right[IDEMIP_TCP_SACK_BLOCKS_MAX];
    uint32_t rcv_ann_wnd;
    uint16_t mss;
    uint16_t flags;
    uint8_t keep_cnt;
    uint8_t snd_scale;
    uint8_t rcv_scale;
    uint8_t nrtx;
    uint8_t r2;
    uint8_t r2_syn;
    uint8_t backoff;
    uint8_t dupacks;
    uint8_t keep_cnt_sent;
} TcpPcbCtl;

/**
 * @brief What an open takes.
 *
 * @var TcpPcbOpenArgs::ip_version 4 for an RFC 791 sec 3.1 Version 4 connection, 6 for an RFC 8200
 *                                 sec 3 Version 6 one
 */
typedef struct
{
    uint8_t ip_version;
} TcpPcbOpenArgs;

/**
 * @brief What an opt takes: the per-connection parameters RFC 9293 sec 3.10.1's OPEN names, which
 * says to "Fill in local socket identifier, remote socket, Diffserv field, security/compartment, and
 * user timeout information".
 *
 * @var TcpPcbOptArgs::index  the entry an open reported
 * @var TcpPcbOptArgs::tos    RFC 9293 sec 3.9.1.9 MUST-48: "The application layer MUST be able to
 *                            specify the Differentiated Services field for segments that are sent on
 *                            a connection". The RFC 791 sec 3.1 Type of Service octet, the RFC 8200
 *                            sec 3 Traffic Class over IPv6.
 * @var TcpPcbOptArgs::ttl    RFC 791 sec 3.1 Time to Live, the RFC 8200 sec 3 Hop Limit over IPv6
 * @var TcpPcbOptArgs::r2     RFC 9293 sec 3.8.3 MUST-21: "An application MUST be able to set the
 *                            value for R2 for a particular connection." Zero is clause (d)'s
 *                            "infinity".
 * @var TcpPcbOptArgs::r2_syn the same threshold while the SYN is unacknowledged
 */
typedef struct
{
    uint16_t index;
    uint8_t tos;
    uint8_t ttl;
    uint8_t r2;
    uint8_t r2_syn;
} TcpPcbOptArgs;

/**
 * @brief What a bind and a connect take: one end of the RFC 9293 sec 3.3.1 address and port pair.
 *
 * @var TcpPcbAddrArgs::ip    IDEMIP_TCP_PCB_ADDR_BYTES octets in the caller's storage, the first
 *                            four read when the connection's version is 4
 * @var TcpPcbAddrArgs::index the TCB an open reported
 * @var TcpPcbAddrArgs::port  the local port on a bind, IDEMIP_TCP_PCB_PORT_ANY to be assigned one;
 *                            the remote port on a connect
 * @var TcpPcbAddrArgs::zone  the RFC 4007 sec 6 zone index qualifying a non-global IPv6 address
 * @var TcpPcbAddrArgs::netif the interface this end is pinned to, 0 for none
 * @var TcpPcbAddrArgs::rand  an unpredictable 32-bit word, read only by a bind of
 *                            IDEMIP_TCP_PCB_PORT_ANY. RFC 6056 sec 3.3: "Ephemeral port selection
 *                            algorithms SHOULD obfuscate the selection of their ephemeral ports,
 *                            since this helps to mitigate a number of attacks that depend on the
 *                            attacker's ability to guess or know the five-tuple". sec 3.3.1 notes
 *                            "the output needs to be unpredictable", so a counter will not do.
 */
typedef struct
{
    const uint8_t *ip;
    uint32_t rand;
    uint16_t index;
    uint16_t port;
    uint8_t zone;
    uint8_t netif;
} TcpPcbAddrArgs;

/**
 * @brief What a close, a load, a store and an unlisten take.
 *
 * @var TcpPcbPcbArgs::index the TCB an open reported, or the listener a listen reported
 */
typedef struct
{
    uint16_t index;
} TcpPcbPcbArgs;

/**
 * @brief What an accept takes: the connection a listener's SYN created, and that listener.
 *
 * RFC 9293 sec 3.10.7.2 creates the connection in SYN-RECEIVED out of the LISTEN state, and sec 3.5
 * (MUST-11) requires that "a TCP implementation MUST keep track of whether a connection has reached
 * SYN-RECEIVED state as the result of a passive OPEN or an active OPEN", which sec 3.10.7.4 second
 * and fourth then read to decide whether a RST or a SYN returns the connection to LISTEN.
 *
 * @var TcpPcbAcceptArgs::index    the TCB an open reported
 * @var TcpPcbAcceptArgs::listener the listener a listen reported, IDEMIP_TCP_PCB_NONE for an active
 *                                 OPEN
 */
typedef struct
{
    uint16_t index;
    uint16_t listener;
} TcpPcbAcceptArgs;

/**
 * @brief What a listen takes: the passive OPEN of RFC 9293 sec 3.3.2.
 *
 * "A passive OPEN request means that the process wants to accept incoming connection requests, in
 * contrast to an active OPEN attempting to initiate a connection."
 *
 * @var TcpPcbListenArgs::ip         the local address to accept on, IDEMIP_TCP_PCB_ADDR_BYTES octets
 *                                   in the caller's storage
 * @var TcpPcbListenArgs::port       the local port to accept on
 * @var TcpPcbListenArgs::zone       the RFC 4007 sec 6 zone index of that address
 * @var TcpPcbListenArgs::netif      the interface to accept on, 0 for any
 * @var TcpPcbListenArgs::backlog    connections held in SYN-RECEIVED before a further request is
 *                                   refused, which @ref TcpPcbNs::accept applies. Zero holds none
 *                                   and is refused here, since a listener that can accept nothing
 *                                   is not one.
 * @var TcpPcbListenArgs::ip_version 4 or 6
 */
typedef struct
{
    const uint8_t *ip;
    uint16_t port;
    uint8_t zone;
    uint8_t netif;
    uint8_t backlog;
    uint8_t ip_version;
} TcpPcbListenArgs;

/**
 * @brief What a find and a find_listener take: the four-tuple of one arriving segment.
 *
 * RFC 9293 sec 3.3.1 keys a TCB on "the local and remote IP addresses and port numbers", so a
 * segment's own pair is swapped against it: its Destination Port is the local port.
 *
 * @var TcpPcbFindArgs::local_ip    the segment's destination address
 * @var TcpPcbFindArgs::remote_ip   its source address
 * @var TcpPcbFindArgs::local_port  its RFC 9293 sec 3.1 Destination Port
 * @var TcpPcbFindArgs::remote_port its RFC 9293 sec 3.1 Source Port
 * @var TcpPcbFindArgs::ip_version  4 or 6
 * @var TcpPcbFindArgs::local_zone  the RFC 4007 sec 6 zone index of the destination
 * @var TcpPcbFindArgs::remote_zone the zone index of the source
 * @var TcpPcbFindArgs::netif       the interface it arrived on
 */
typedef struct
{
    const uint8_t *local_ip;
    const uint8_t *remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t ip_version;
    uint8_t local_zone;
    uint8_t remote_zone;
    uint8_t netif;
} TcpPcbFindArgs;

/**
 * @brief What a seg_alloc writes, and which segment a seg_load and a seg_free name.
 *
 * A send-queue entry names the caller's octets rather than holding them, so nothing is copied onto
 * the queue.
 *
 * @var TcpPcbSegArgs::data  the segment's data, in the caller's storage, null for a segment that
 *                           carries only control bits
 * @var TcpPcbSegArgs::seq   the RFC 9293 sec 3.1 Sequence Number of its first octet
 * @var TcpPcbSegArgs::pcb   the TCB whose queue it belongs on
 * @var TcpPcbSegArgs::index the segment a seg_load or a seg_free names
 * @var TcpPcbSegArgs::len   its data octets, SEG.LEN of RFC 9293 sec 3.3.1 Table 4
 * @var TcpPcbSegArgs::flags the RFC 9293 sec 3.1 control bits it carries
 * @var TcpPcbSegArgs::opts  which options it must carry, one bit each for RFC 9293 sec 3.2 MSS and
 *                           RFC 7323 window scale and timestamps
 */
typedef struct
{
    const uint8_t *data;
    uint32_t seq;
    uint16_t pcb;
    uint16_t index;
    uint16_t len;
    uint16_t flags;
    uint16_t opts;
} TcpPcbSegArgs;

/**
 * @brief What an oos_alloc writes, and which held segment an oos_load and an oos_free name.
 *
 * A held out-of-order segment stays in the receive buffer the DMA engine wrote it to, so the entry
 * names the pinned descriptor rather than the octets.
 *
 * @var TcpPcbOosArgs::seq    the RFC 9293 sec 3.1 Sequence Number of its first data octet
 * @var TcpPcbOosArgs::pcb    the TCB it was received on
 * @var TcpPcbOosArgs::index  the held segment an oos_load or an oos_free names
 * @var TcpPcbOosArgs::desc   the pinned receive descriptor holding the frame
 * @var TcpPcbOosArgs::offset octets from the start of that frame to the segment's first data octet
 * @var TcpPcbOosArgs::len    its data octets
 */
typedef struct
{
    uint32_t seq;
    uint16_t pcb;
    uint16_t index;
    uint16_t desc;
    uint16_t offset;
    uint16_t len;
} TcpPcbOosArgs;

/**
 * @brief What a load reports of the connection's identity: the RFC 9293 sec 3.3.1 four-tuple.
 *
 * The two addresses point into the entry, which is the caller's own borrow, and stay valid until the
 * next call that writes that entry.
 *
 * @var TcpPcbInfo::local_ip    "the local... IP address"
 * @var TcpPcbInfo::remote_ip   "the... remote IP address"
 * @var TcpPcbInfo::local_port  the local port number
 * @var TcpPcbInfo::remote_port the remote port number
 * @var TcpPcbInfo::local_zone  the RFC 4007 sec 6 zone index of the local address
 * @var TcpPcbInfo::remote_zone the zone index of the remote address
 * @var TcpPcbInfo::netif       the interface the connection is pinned to, 0 for none
 * @var TcpPcbInfo::tos         RFC 791 sec 3.1 Type of Service
 * @var TcpPcbInfo::ttl         RFC 791 sec 3.1 Time to Live, the RFC 8200 sec 3 Hop Limit over IPv6
 * @var TcpPcbInfo::ip_version  4 or 6
 * @var TcpPcbInfo::listener    the listener this connection was accepted through, or
 *                              IDEMIP_TCP_PCB_NONE
 * @var TcpPcbInfo::unsent      the first segment queued but not yet sent, or IDEMIP_TCP_PCB_NONE
 * @var TcpPcbInfo::unacked     the first segment sent but not acknowledged, or IDEMIP_TCP_PCB_NONE
 * @var TcpPcbInfo::ooseq       the first held out-of-order segment, or IDEMIP_TCP_PCB_NONE
 */
typedef struct
{
    const uint8_t *local_ip;
    const uint8_t *remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint16_t listener;
    uint16_t unsent;
    uint16_t unacked;
    uint16_t ooseq;
    uint8_t local_zone;
    uint8_t remote_zone;
    uint8_t netif;
    uint8_t tos;
    uint8_t ttl;
    uint8_t ip_version;
} TcpPcbInfo;

/**
 * @brief What a seg_load reports of one send-queue entry.
 *
 * @var TcpPcbSegInfo::data  the segment's data, in the caller's storage
 * @var TcpPcbSegInfo::seq   the Sequence Number of its first octet
 * @var TcpPcbSegInfo::next  the next segment on the same queue, or IDEMIP_TCP_PCB_NONE
 * @var TcpPcbSegInfo::pcb   the TCB whose queue it is on
 * @var TcpPcbSegInfo::len   its data octets
 * @var TcpPcbSegInfo::flags the control bits it carries
 * @var TcpPcbSegInfo::opts  which options it must carry
 */
typedef struct
{
    const uint8_t *data;
    uint32_t seq;
    uint16_t next;
    uint16_t pcb;
    uint16_t len;
    uint16_t flags;
    uint16_t opts;
} TcpPcbSegInfo;

/**
 * @brief What an oos_load reports of one held out-of-order segment.
 *
 * @var TcpPcbOosInfo::seq    the Sequence Number of its first data octet
 * @var TcpPcbOosInfo::next   the next held segment on the same queue, or IDEMIP_TCP_PCB_NONE
 * @var TcpPcbOosInfo::pcb    the TCB it was received on
 * @var TcpPcbOosInfo::desc   the pinned receive descriptor holding the frame
 * @var TcpPcbOosInfo::offset octets from the start of that frame to the first data octet
 * @var TcpPcbOosInfo::len    its data octets
 */
typedef struct
{
    uint32_t seq;
    uint16_t next;
    uint16_t pcb;
    uint16_t desc;
    uint16_t offset;
    uint16_t len;
} TcpPcbOosInfo;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns. Two workers on two borrows share no byte
 * of this.
 *
 * @var TcpPcbIo::open_args     the version an open opens a TCB for
 * @var TcpPcbIo::bind_args     the local address and port a bind sets
 * @var TcpPcbIo::connect_args  the remote address and port a connect sets
 * @var TcpPcbIo::pcb_args      the entry a close, a load, a store and an unlisten name
 * @var TcpPcbIo::accept_args   the connection an accept records a listener on
 * @var TcpPcbIo::listen_args   the passive OPEN a listen takes
 * @var TcpPcbIo::find_args     the arriving segment a find and a find_listener match
 * @var TcpPcbIo::opt_args      the per-connection parameters an opt writes
 * @var TcpPcbIo::seg_args      the send-queue segment a seg_alloc writes, and the one a seg_load or
 *                              a seg_free names
 * @var TcpPcbIo::oos_args      the held segment an oos_alloc writes, and the one an oos_load or an
 *                              oos_free names
 * @var TcpPcbIo::vars          the RFC 9293 sec 3.3.1 variables: a load's result and a store's
 *                              operand, so a caller loads, adjusts and stores
 * @var TcpPcbIo::ctl           the estimator, congestion, option and keepalive state, the same way
 * @var TcpPcbIo::state         the RFC 9293 sec 3.3.2 state, the same way
 * @var TcpPcbIo::status        what the call reports: OK, BUSY, or ERR
 * @var TcpPcbIo::index         the entry an open, a listen, a seg_alloc, an oos_alloc, a find or a
 *                              find_listener settled on, IDEMIP_TCP_PCB_NONE for none
 * @var TcpPcbIo::port          the local port a bind settled on, which is the one it was given unless
 *                              that was IDEMIP_TCP_PCB_PORT_ANY
 * @var TcpPcbIo::info          the four-tuple a load read
 * @var TcpPcbIo::seg           what a seg_load read
 * @var TcpPcbIo::oos           what an oos_load read
 */
typedef struct
{
    TcpPcbOpenArgs open_args;
    TcpPcbOptArgs opt_args;
    TcpPcbAddrArgs bind_args;
    TcpPcbAddrArgs connect_args;
    TcpPcbPcbArgs pcb_args;
    TcpPcbAcceptArgs accept_args;
    TcpPcbListenArgs listen_args;
    TcpPcbFindArgs find_args;
    TcpPcbSegArgs seg_args;
    TcpPcbOosArgs oos_args;

    IdemIpTcpVars vars;
    TcpPcbCtl ctl;
    IdemIpTcpState state;

    IdemIpStatus status;
    uint16_t index;
    uint16_t port;
    TcpPcbInfo info;
    TcpPcbSegInfo seg;
    TcpPcbOosInfo oos;
} TcpPcbIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The four tables start at
// IDEMIP_TCP_PCB_CTX_BYTES, which idemip_config.h asserts is a multiple of IDEMIP_ALIGN, so the
// operand block and the context growing does not move an entry.

#define IDEMIP_TCP_PCB_OFF_IO 0u ///< the operand and result block
#define IDEMIP_TCP_PCB_OFF_CTX (IDEMIP_TCP_PCB_OFF_IO + IDEMIP_ROUND_UP(sizeof(TcpPcbIo), IDEMIP_ALIGN)) ///< the running context
#define IDEMIP_TCP_PCB_OFF_TCB IDEMIP_TCP_PCB_CTX_BYTES ///< IDEMIP_TCP_PCBS Transmission Control Blocks

/** @brief IDEMIP_TCP_LISTEN_PCBS listeners, one per passive OPEN. */
#define IDEMIP_TCP_PCB_OFF_LISTEN (IDEMIP_TCP_PCB_OFF_TCB + (IDEMIP_TCP_PCBS << IDEMIP_TCP_PCB_ENTRY_SHIFT))

/** @brief IDEMIP_TCP_SEGS send-queue segments, shared by every TCB. */
#define IDEMIP_TCP_PCB_OFF_SEG (IDEMIP_TCP_PCB_OFF_LISTEN + (IDEMIP_TCP_LISTEN_PCBS << IDEMIP_TCP_LISTEN_ENTRY_SHIFT))

/** @brief IDEMIP_TCP_PCBS times IDEMIP_TCP_OOSEQ_SEGS held out-of-order segments. */
#define IDEMIP_TCP_PCB_OFF_OOSEQ (IDEMIP_TCP_PCB_OFF_SEG + (IDEMIP_TCP_SEGS << IDEMIP_TCP_SEG_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_TCP_PCB_IO(w) ((TcpPcbIo *)(void *)((w) + IDEMIP_TCP_PCB_OFF_IO))

/**
 * @brief The RFC 9293 sec 3.3.1 Transmission Control Blocks and the three queues they draw on.
 *
 *   TcpPcb.clear(work);
 *   IDEMIP_TCP_PCB_IO(work)->open_args.ip_version = 4u;
 *   TcpPcb.open(work);
 *   if (IDEMIP_TCP_PCB_IO(work)->status == IDEMIP_OK) { ... }
 *
 * @c work is IDEMIP_TCP_PCB_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * tables are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. An entry that cannot finish now reports IDEMIP_BUSY and returns, and the
 * caller comes back on a later tick. A table with no free entry and a bind with no free port are
 * BUSY, since a close frees both, and a close of a TCB still holding an out-of-order segment is BUSY,
 * since an oos_free frees one. A borrow that was never cleared, an index past a table, an entry that
 * is not open, and a state that forbids the call are ERR.
 *
 * @var TcpPcbNs::clear         zero the context and the four tables, and mark the borrow usable
 * @var TcpPcbNs::open          take a free TCB, reporting it in @ref TcpPcbIo::index. BUSY when every
 *                              TCB is open.
 * @var TcpPcbNs::opt           set the per-connection parameters RFC 9293 sec 3.10.1's OPEN names:
 *                              the sec 3.9.1.9 Diffserv field, the Time to Live, and the sec 3.8.3 R2
 *                              thresholds. ERR when the index names no open TCB.
 * @var TcpPcbNs::close         release the TCB @ref TcpPcbPcbArgs::index names, with every segment on
 *                              its two send queues. BUSY while its out-of-order queue still holds a
 *                              segment, since each names a pinned receive descriptor that only an
 *                              oos_free reports back; drain the hold from @ref TcpPcbInfo::ooseq and
 *                              the call succeeds.
 * @var TcpPcbNs::bind          set that TCB's local address and port, reporting the port it settled
 *                              on in @ref TcpPcbIo::port. IDEMIP_TCP_PCB_PORT_ANY draws from RFC
 *                              6335 sec 6's Dynamic Ports. sec 3.9.1.1 (MUST-45) fixes the local
 *                              socket once a segment has passed, so a TCB past CLOSED is ERR.
 * @var TcpPcbNs::connect       set that TCB's remote address and port, completing the four-tuple.
 *                              A remote port of IDEMIP_TCP_PCB_PORT_ANY is sec 3.10.1's "error:
 *                              remote socket unspecified" and is ERR; a pair another open TCB
 *                              already holds is BUSY.
 * @var TcpPcbNs::load          read the four-tuple, the sec 3.3.1 variables, the sec 3.3.2 state and
 *                              the control state of that TCB into the operand block
 * @var TcpPcbNs::store         write the sec 3.3.1 variables, the sec 3.3.2 state and the control
 *                              state back to that TCB. A sec 3.3.2 state RFC 9293 does not reach
 *                              from the state the TCB is in is ERR, and nothing is written.
 * @var TcpPcbNs::accept        record on the TCB @ref TcpPcbAcceptArgs::index the listener its SYN
 *                              arrived on, which sec 3.5 (MUST-11) requires be kept. A listener that
 *                              is not taken is ERR; IDEMIP_TCP_PCB_NONE clears it, which is an
 *                              active OPEN. BUSY when that listener already holds
 *                              @ref TcpPcbListenArgs::backlog connections in SYN-RECEIVED, which is
 *                              where the passive OPEN's backlog is applied and the only place it is.
 * @var TcpPcbNs::listen        take a free listener for a passive OPEN, reporting it in
 *                              @ref TcpPcbIo::index. An all-zero address is sec 3.9.1.1's
 *                              unspecified "local IP address" parameter, which "will await an
 *                              incoming connection request to any local IP address". A port of
 *                              IDEMIP_TCP_PCB_PORT_ANY names no socket and is ERR, and so is a
 *                              backlog of zero. BUSY when every listener is taken, and when another
 *                              listener holds the same socket.
 * @var TcpPcbNs::unlisten      release the listener @ref TcpPcbPcbArgs::index names
 * @var TcpPcbNs::find          match an arriving segment's four-tuple to a TCB, reporting it in
 *                              @ref TcpPcbIo::index. No TCB is ERR, which is the RFC 9293 sec 3.10.7.1
 *                              CLOSED case.
 * @var TcpPcbNs::find_listener match it to a listener instead
 * @var TcpPcbNs::seg_alloc     take a free send-queue segment and link it behind a TCB's queue. BUSY
 *                              when every segment is queued.
 * @var TcpPcbNs::seg_load      read the segment @ref TcpPcbSegArgs::index names into
 *                              @ref TcpPcbIo::seg
 * @var TcpPcbNs::seg_sent      move the segment @ref TcpPcbSegArgs::index names off the head of its
 *                              TCB's unsent queue onto the tail of the retransmission queue sec
 *                              3.3.1 names, which is where sec 3.10.7.4 fifth removes it from once
 *                              it is entirely acknowledged. A segment that is not that head is a
 *                              broken link and is ERR.
 * @var TcpPcbNs::seg_free      unlink and release that segment
 * @var TcpPcbNs::oos_alloc     take a free out-of-order entry and link it into a TCB's queue in
 *                              sequence order. BUSY when that TCB holds IDEMIP_TCP_OOSEQ_SEGS
 *                              already.
 * @var TcpPcbNs::oos_load      read the held segment @ref TcpPcbOosArgs::index names into
 *                              @ref TcpPcbIo::oos
 * @var TcpPcbNs::oos_free      unlink and release that held segment, so its receive descriptor is
 *                              unpinned
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const open)(uint8_t *restrict work);
    void (*const opt)(uint8_t *restrict work);
    void (*const close)(uint8_t *restrict work);
    void (*const bind)(uint8_t *restrict work);
    void (*const connect)(uint8_t *restrict work);
    void (*const load)(uint8_t *restrict work);
    void (*const store)(uint8_t *restrict work);
    void (*const accept)(uint8_t *restrict work);
    void (*const listen)(uint8_t *restrict work);
    void (*const unlisten)(uint8_t *restrict work);
    void (*const find)(uint8_t *restrict work);
    void (*const find_listener)(uint8_t *restrict work);
    void (*const seg_alloc)(uint8_t *restrict work);
    void (*const seg_load)(uint8_t *restrict work);
    void (*const seg_sent)(uint8_t *restrict work);
    void (*const seg_free)(uint8_t *restrict work);
    void (*const oos_alloc)(uint8_t *restrict work);
    void (*const oos_load)(uint8_t *restrict work);
    void (*const oos_free)(uint8_t *restrict work);
} TcpPcbNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_tcp_pcb_clear(uint8_t *restrict work);
void idemip_tcp_pcb_open(uint8_t *restrict work);
void idemip_tcp_pcb_opt(uint8_t *restrict work);
void idemip_tcp_pcb_close(uint8_t *restrict work);
void idemip_tcp_pcb_bind(uint8_t *restrict work);
void idemip_tcp_pcb_connect(uint8_t *restrict work);
void idemip_tcp_pcb_load(uint8_t *restrict work);
void idemip_tcp_pcb_store(uint8_t *restrict work);
void idemip_tcp_pcb_accept(uint8_t *restrict work);
void idemip_tcp_pcb_listen(uint8_t *restrict work);
void idemip_tcp_pcb_unlisten(uint8_t *restrict work);
void idemip_tcp_pcb_find(uint8_t *restrict work);
void idemip_tcp_pcb_find_listener(uint8_t *restrict work);
void idemip_tcp_pcb_seg_alloc(uint8_t *restrict work);
void idemip_tcp_pcb_seg_load(uint8_t *restrict work);
void idemip_tcp_pcb_seg_sent(uint8_t *restrict work);
void idemip_tcp_pcb_seg_free(uint8_t *restrict work);
void idemip_tcp_pcb_oos_alloc(uint8_t *restrict work);
void idemip_tcp_pcb_oos_load(uint8_t *restrict work);
void idemip_tcp_pcb_oos_free(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `TcpPcb.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const TcpPcbNs TcpPcb IDEMIP_UNUSED = {
    .clear = idemip_tcp_pcb_clear,
    .open = idemip_tcp_pcb_open,
    .opt = idemip_tcp_pcb_opt,
    .close = idemip_tcp_pcb_close,
    .bind = idemip_tcp_pcb_bind,
    .connect = idemip_tcp_pcb_connect,
    .load = idemip_tcp_pcb_load,
    .store = idemip_tcp_pcb_store,
    .accept = idemip_tcp_pcb_accept,
    .listen = idemip_tcp_pcb_listen,
    .unlisten = idemip_tcp_pcb_unlisten,
    .find = idemip_tcp_pcb_find,
    .find_listener = idemip_tcp_pcb_find_listener,
    .seg_alloc = idemip_tcp_pcb_seg_alloc,
    .seg_load = idemip_tcp_pcb_seg_load,
    .seg_sent = idemip_tcp_pcb_seg_sent,
    .seg_free = idemip_tcp_pcb_seg_free,
    .oos_alloc = idemip_tcp_pcb_oos_alloc,
    .oos_load = idemip_tcp_pcb_oos_load,
    .oos_free = idemip_tcp_pcb_oos_free};
IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_TCP

#endif // IDEMIP_TCP_PCB_H
