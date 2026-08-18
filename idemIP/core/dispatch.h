// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dispatch.h
 * @brief The receive path: one frame, to the pcb that owns it.
 *
 * RFC 1122 sec 3.1 states the five steps this walks, in this order: "(1) verifies that the datagram
 * is correctly formatted; (2) verifies that it is destined to the local host; (3) processes options;
 * (4) reassembles the datagram if necessary; and (5) passes the encapsulated message to the
 * appropriate transport-layer protocol module."
 *
 * The frame is read where the DMA engine left it. Nothing here copies one, and nothing here holds
 * one past the call: a unit that retains a frame pins its receive descriptor and the pin is reported,
 * so the caller returns the descriptor to the ring only when it was not pinned.
 *
 * POLICY LIVES HERE, NEVER IN A PARSER. vlan.h reads and writes the IEEE 802.1Q C-Tag and decides
 * nothing; the membership decision and the counter each drop bumps are this module's.
 *
 * Nothing here sends. An entry reports what to send in @ref DispatchIo::act and, where a unit built
 * the octets, at the @c out the caller supplied.
 */

#ifndef IDEMIP_DISPATCH_H
#define IDEMIP_DISPATCH_H

#include "idemIP/core/stats.h"
#include "idemIP/ethernet/vlan.h"
#include "idemIP/netif/dma.h"
#include "idemIP/netif/loopif.h"
#include "idemIP/netif/netif.h"

#if IDEMIP_ENABLE_IPV4
#include "idemIP/arp/arp_table.h"
#include "idemIP/icmp/icmp_in.h"
#include "idemIP/igmp/igmp.h"
#include "idemIP/ip/ip4_addr.h"
#include "idemIP/ip/ip4_reass.h"
#endif

#if IDEMIP_ENABLE_IPV6
#include "idemIP/icmp/icmp6_in.h"
#include "idemIP/ip/ip6_addr.h"
#include "idemIP/ip/ip6_reass.h"
#include "idemIP/mld/mld6.h"
#endif

#if IDEMIP_ENABLE_UDP
#include "idemIP/udp/udp_pcb.h"
#include "idemIP/udp/udplite.h"
#endif

#if IDEMIP_ENABLE_TCP
#include "idemIP/tcp/tcp_in.h"
#include "idemIP/tcp/tcp_pcb.h"
#endif

#if IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6
#include "idemIP/raw/raw_pcb.h"
#endif

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// The interface a call names, and the descriptor a frame lies in
// ---------------------------------------------------------------------------

/** @brief The interface index that names none. */
#define IDEMIP_DISPATCH_NETIF_NONE 0xFFu

/**
 * @brief The descriptor index that names none: the frame is not in a DMA buffer.
 *
 * A looped frame (RFC 1122 sec 3.2.1.3 case (g)) lies in loopif's own region and pins nothing, so a
 * unit that would retain it is refused rather than handed a descriptor that does not exist.
 */
#define IDEMIP_DISPATCH_DESC_NONE 0xFFFFu

/**
 * @brief A pinned descriptor, named together with the ring it belongs to.
 *
 * A retaining unit stores what it is handed and reads no interface out of it: ip4_reass.h and
 * ip6_reass.h key a fragment on {source, destination, protocol, identification} and tcp_pcb.h keys
 * an out-of-order segment on its sequence number, so neither carries the interface the frame
 * arrived on. A bare index is therefore ambiguous the moment two interfaces have a ring, and the
 * descriptor cannot be handed back to the right engine.
 *
 * The handle closes that: the low octet is the index into the ring, the high octet is the
 * interface. IDEMIP_DISPATCH_DESC_NONE stays distinct because its high octet is
 * IDEMIP_DISPATCH_NETIF_NONE, which no interface index reaches.
 */
#define IDEMIP_DISPATCH_DESC_HANDLE(netif, index) ((uint16_t)(((uint16_t)(netif) << 8) | (uint16_t)(index)))
#define IDEMIP_DISPATCH_DESC_NETIF(handle) ((uint8_t)((handle) >> 8))
#define IDEMIP_DISPATCH_DESC_INDEX(handle) ((uint8_t)((handle) & 0xFFu))

/**
 * @brief The VLAN ID a per-interface row holds when no policy drop has happened since clear.
 *
 * RFC 6325 sec 4.1.1: "VLAN ID zero is the null VLAN identifier and indicates that no VLAN is
 * specified while VLAN ID 0xFFF is reserved", and "The VLAN ID 0xFFF MUST NOT be used". Zero is a
 * value that reaches the wire, on a frame carrying priority and no membership, so a row reading zero
 * has to mean a priority-tagged frame was discarded and not that nothing was.
 */
#define IDEMIP_DISPATCH_VID_NONE IDEMIP_VLAN_VID_RESERVED

// ---------------------------------------------------------------------------
// What a call asks the caller to do
// ---------------------------------------------------------------------------
// One bit per action. A caller acts on the set and nothing else: no entry here sends a frame,
// signals a user, or returns a descriptor to the ring.

#define IDEMIP_DISPATCH_ACT_SEND (1u << 0)    ///< @ref DispatchIo::out_len octets were built at @c out
#define IDEMIP_DISPATCH_ACT_DELIVER (1u << 1) ///< the payload named below goes to the pcb named below
#define IDEMIP_DISPATCH_ACT_PINNED (1u << 2)  ///< a unit retained the frame: do NOT return the descriptor
#define IDEMIP_DISPATCH_ACT_REASSEMBLED (1u << 3) ///< a datagram completed; walk it out of the reassembler
#define IDEMIP_DISPATCH_ACT_FORWARD (1u << 4)     ///< not for this host, and the caller routes it
#define IDEMIP_DISPATCH_ACT_USER (1u << 5)        ///< signal the user, as the protocol unit asked
#define IDEMIP_DISPATCH_ACT_DROP (1u << 6)        ///< the frame goes no further; @ref DispatchIo::drop says why
#define IDEMIP_DISPATCH_ACT_TCP (1u << 7)         ///< @ref DispatchIo::tcp_act carries what tcp_in decided

/**
 * @brief The acknowledgment tcp_in asked for was recorded rather than sent.
 *
 * RFC 9293 sec 3.10.7.4 (MUST-58): "the processing of received segments MUST be implemented to
 * aggregate ACK segments whenever possible", and (MUST-59) "if the TCP endpoint is processing a
 * series of queued segments, it MUST process them all before sending any ACK segments." So
 * IDEMIP_TCP_IN_ACT_ACK is cleared out of @ref DispatchIo::tcp_act and one acknowledgment is taken
 * from @ref DispatchNs::tcp_ack once the batch is through. An RFC 5961 challenge and every reset are
 * left where they are: each answers one specific segment and aggregating it would lose it.
 */
#define IDEMIP_DISPATCH_ACT_ACK_OWED (1u << 8)

/**
 * @brief Why a frame went no further, and which RFC 1213 sec 6.4 counter that bumped.
 *
 * The three link-layer reasons are the ones PLAN.md sec 3.4b fixes. Each names a counter whose own
 * RFC 1213 wording is the reason it is the right one.
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DISPATCH_DROP_NONE = 0, ///< nothing was dropped

    /** Shorter than the header it claims. ifInErrors: "contained errors preventing them from being
     *  deliverable to a higher-layer protocol." */
    IDEMIP_DISPATCH_DROP_SHORT,
    /** A tag this interface is not a member of. ifInDiscards: "chosen to be discarded even though no
     *  errors had been detected". */
    IDEMIP_DISPATCH_DROP_VLAN_POLICY,
    /** A tag carrying the reserved VLAN ID 0xFFF, which RFC 6325 sec 4.1.1 says "MUST NOT be used"
     *  and MUST be discarded, so the frame is malformed: ifInErrors. */
    IDEMIP_DISPATCH_DROP_VLAN_RESERVED,
    /** A type code nothing here handles. ifInUnknownProtos: "discarded because of an unknown or
     *  unsupported protocol." */
    IDEMIP_DISPATCH_DROP_ETHERTYPE,

    IDEMIP_DISPATCH_DROP_IP_HEADER,  ///< ipInHdrErrors: version, IHL, length or checksum
    IDEMIP_DISPATCH_DROP_IP_ADDRESS, ///< ipInAddrErrors: the destination is not this host's
    IDEMIP_DISPATCH_DROP_IP_SOURCE,  ///< ipInAddrErrors: the source is one RFC 1122 sec 3.2.1.3 bars
    IDEMIP_DISPATCH_DROP_IP_PROTO,   ///< ipInUnknownProtos: no pcb kind claims the Protocol field
    /** ipInHdrErrors: a RFC 8200 sec 4.4 Routing header carrying a non-zero Segments Left, whose
     *  Routing Type this library executes none of. sec 4.4: "the node must discard the packet and send
     *  an ICMP Parameter Problem, Code 0, message to the packet's Source Address, pointing to the
     *  unrecognized Routing Type." The discard is here; the message is the caller's to build through
     *  icmp6_in.h, the same division DROP_NO_PCB uses for Port Unreachable. */
    IDEMIP_DISPATCH_DROP_IP6_ROUTING,
    /** ipInHdrErrors: an RFC 8200 sec 4.2 option this node does not recognize whose two high-order
     *  bits are 01, 10 or 11. All three discard; 10 and 11 also owe a Parameter Problem, Code 2,
     *  pointing to the Option Type, which @ref DispatchIo::err_ptr names and whose own octet says
     *  which. 11 owes it "only if the packet's Destination Address was not a multicast address". */
    IDEMIP_DISPATCH_DROP_IP6_OPTION,
    IDEMIP_DISPATCH_DROP_NO_PCB,     ///< ipInDiscards: nothing is bound to the port or protocol
    IDEMIP_DISPATCH_DROP_REASS,      ///< ipInDiscards: the reassembler had no room, or refused it
    IDEMIP_DISPATCH_DROP_NO_DESC,    ///< ipInDiscards: retention needs a descriptor and there is none
    IDEMIP_DISPATCH_DROP_UNBOUND,    ///< the borrow the path needs was never bound

    /** The transport or control checksum over the datagram did not check out. Kept apart from
     *  DROP_SHORT so a bad sum reads as a bad sum: RFC 1122 sec 4.1.3.4 requires a UDP datagram
     *  with a non-zero invalid checksum to be discarded silently, and RFC 2236 sec 2.3 requires an
     *  IGMP checksum to be "verified before processing a packet". */
    IDEMIP_DISPATCH_DROP_CKSUM,
} IdemIpDispatchDrop;

/** @brief Which table the pcb index a delivery names belongs to. */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DISPATCH_PCB_NONE = 0, ///< no pcb was reached
    IDEMIP_DISPATCH_PCB_RAW,      ///< raw_pcb, RFC 1122 sec 3.2
    IDEMIP_DISPATCH_PCB_UDP,      ///< udp_pcb, RFC 768
    IDEMIP_DISPATCH_PCB_TCP,      ///< tcp_pcb, RFC 9293 sec 3.3.1
    IDEMIP_DISPATCH_PCB_LISTEN,   ///< a tcp_pcb listener, RFC 9293 sec 3.10.7.2
    IDEMIP_DISPATCH_PCB_ICMP,     ///< the message went to icmp_in or icmp6_in
    IDEMIP_DISPATCH_PCB_GROUP,    ///< the message went to igmp or mld6
    IDEMIP_DISPATCH_PCB_ARP,      ///< the packet went to the RFC 826 table
} IdemIpDispatchPcb;

/**
 * @brief The borrows the receive path calls into, each the caller's own.
 *
 * An address this module carries and never frees. A null one is not a fault at bind: a build without
 * a resolver, a group table or a transport still dispatches everything else, and the path that would
 * have needed it reports IDEMIP_DISPATCH_DROP_UNBOUND rather than calling through a null pointer.
 *
 * @var DispatchBindArgs::stats    the RFC 1213 counters every drop and delivery bumps
 * @var DispatchBindArgs::netif    the interface table, for the addresses a destination test reads
 * @var DispatchBindArgs::loopif   the RFC 1122 sec 3.2.1.3 case (g) interface
 * @var DispatchBindArgs::vlan     the IEEE 802.1Q tag parser
 * @var DispatchBindArgs::arp      the RFC 826 translation table
 * @var DispatchBindArgs::ip4_addr the RFC 1122 sec 3.2.1.3 address forms, which the destination test
 *                                 places a Destination Address against
 * @var DispatchBindArgs::ip4_reass the RFC 791 sec 3.2 reassembler
 * @var DispatchBindArgs::icmp_in  the RFC 792 receiver
 * @var DispatchBindArgs::igmp     the RFC 2236 group table
 * @var DispatchBindArgs::ip6_addr the RFC 4291 sec 2.7.1 solicited-node form, which the destination
 *                                 test builds from each of the interface's own addresses
 * @var DispatchBindArgs::ip6_reass the RFC 8200 sec 4.5 reassembler
 * @var DispatchBindArgs::icmp6_in the RFC 4443 receiver
 * @var DispatchBindArgs::mld6     the RFC 2710 group table
 * @var DispatchBindArgs::raw_pcb  the RFC 1122 sec 3.2 raw bindings
 * @var DispatchBindArgs::udp_pcb  the RFC 768 bindings
 * @var DispatchBindArgs::udplite  the RFC 3828 partial-coverage checksum, which reads the Checksum
 *                                 Coverage a protocol 136 datagram carries where RFC 768 carries a
 *                                 Length
 * @var DispatchBindArgs::tcp_pcb  the RFC 9293 sec 3.3.1 Transmission Control Blocks
 * @var DispatchBindArgs::tcp_in   the RFC 9293 sec 3.10.7 SEGMENT ARRIVES machine
 */
typedef struct
{
    uint8_t *stats;
    uint8_t *netif;
    uint8_t *loopif;
    uint8_t *vlan;
#if IDEMIP_ENABLE_IPV4
    uint8_t *arp;
    uint8_t *ip4_addr;
    uint8_t *ip4_reass;
    uint8_t *icmp_in;
    uint8_t *igmp;
#endif
#if IDEMIP_ENABLE_IPV6
    uint8_t *ip6_addr;
    uint8_t *ip6_reass;
    uint8_t *icmp6_in;
    uint8_t *mld6;
#endif
#if IDEMIP_ENABLE_IPV4 || IDEMIP_ENABLE_IPV6
    uint8_t *raw_pcb;
#endif
#if IDEMIP_ENABLE_UDP
    uint8_t *udp_pcb;
    uint8_t *udplite;
#endif
#if IDEMIP_ENABLE_TCP
    uint8_t *tcp_pcb;
    uint8_t *tcp_in;
#endif
} DispatchBindArgs;

/**
 * @brief What one interface's row takes: its ring pair, and its IEEE 802.1Q membership.
 *
 * An untagged interface accepts every frame, tagged or not, and reads the payload behind whatever
 * tag it carries. A tagged interface accepts its own VLAN ID and discards the rest.
 *
 * @var DispatchIfArgs::dma    the IDEMIP_DMA_BORROW bytes this interface's rings run in, which the
 *                             pin protocol is called through. Null on an interface whose frames are
 *                             not in a DMA buffer.
 * @var DispatchIfArgs::vid    the VLAN ID this interface is a member of, 1 through 0xFFE
 * @var DispatchIfArgs::tagged the interface is a member of one VLAN, so a frame outside it is
 *                             discarded by policy
 * @var DispatchIfArgs::index  which interface
 */
typedef struct
{
    uint8_t *dma;
    uint16_t vid;
    idemip_bool tagged;
    uint8_t index;
} DispatchIfArgs;

/**
 * @brief What dispatching one frame takes.
 *
 * @var DispatchInputArgs::frame  the frame from its Destination address on, where the engine left it
 * @var DispatchInputArgs::len    octets readable at @c frame
 * @var DispatchInputArgs::out    where a unit builds a reply, @c out_cap octets, not overlapping
 *                                @c frame. Null when the caller has no transmit buffer this tick,
 *                                which makes a reply BUSY rather than lost.
 * @var DispatchInputArgs::out_cap octets available at @c out
 * @var DispatchInputArgs::now_ms the caller's monotonic millisecond count, which every deadline the
 *                                path stamps is measured from
 * @var DispatchInputArgs::desc   the receive descriptor the frame lies in, or
 *                                IDEMIP_DISPATCH_DESC_NONE
 * @var DispatchInputArgs::netif  the interface it arrived on
 */
typedef struct
{
    const uint8_t *frame;
    size_t len;
    uint8_t *out;
    size_t out_cap;
    uint32_t now_ms;
    uint16_t desc;
    uint8_t netif;
} DispatchInputArgs;

/**
 * @brief What a TCP entry names.
 *
 * @var DispatchTcpArgs::pcb    the Transmission Control Block, as a find reported it
 * @var DispatchTcpArgs::now_ms the millisecond the call runs at
 */
typedef struct
{
    uint16_t pcb;
    uint32_t now_ms;
} DispatchTcpArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var DispatchIo::bind_args   the borrows the path calls into
 * @var DispatchIo::if_args     one interface's ring pair and VLAN membership
 * @var DispatchIo::input_args  the frame a dispatch reads
 * @var DispatchIo::tcp_args    the connection a TCP entry names
 * @var DispatchIo::status      what the call reports: OK, BUSY, or ERR
 * @var DispatchIo::act         the actions above, ORed
 * @var DispatchIo::drop        why the frame went no further
 * @var DispatchIo::pcb_kind    which table @ref DispatchIo::pcb indexes
 * @var DispatchIo::pcb         the pcb a delivery reached, or IDEMIP_DISPATCH_PCB_NONE's zero
 * @var DispatchIo::type        the type code behind whatever tag the frame carried
 * @var DispatchIo::vid         the VLAN ID the frame carried, IDEMIP_DISPATCH_VID_NONE when untagged
 * @var DispatchIo::pcp         its Priority (RFC 6325 sec 4.1.1)
 * @var DispatchIo::tagged      the frame carried a C-Tag
 * @var DispatchIo::last_vid    what an if_get reports: the last VLAN ID a policy drop discarded on
 *                              that interface, IDEMIP_DISPATCH_VID_NONE when none has. A Gauge, so it
 *                              is assigned and never accumulated (RFC 1155 sec 3.2.3.4).
 * @var DispatchIo::ip_off      octets from the frame to the IP header
 * @var DispatchIo::ip_version  4, 6, or 0 when the frame carried neither
 * @var DispatchIo::proto       the RFC 791 sec 3.1 Protocol, or the RFC 8200 sec 4 upper-layer Next
 *                              Header
 * @var DispatchIo::payload_off octets from the frame to the upper-layer header a delivery names
 * @var DispatchIo::payload_len octets of it
 * @var DispatchIo::out_len     octets a unit built at the caller's @c out
 * @var DispatchIo::datagram    the reassembler row a completion names
 * @var DispatchIo::desc        the descriptor a retention pinned, or a re-delivery reported
 * @var DispatchIo::netif       the interface the call worked on
 * @var DispatchIo::tcp_act     what tcp_in decided, the IDEMIP_TCP_IN_ACT_* set unchanged
 * @var DispatchIo::text_seq    the Sequence Number of the first octet a delivery covers
 * @var DispatchIo::text_off    octets from the frame to that octet
 * @var DispatchIo::text_len    octets of segment text the delivery covers
 * @var DispatchIo::acked       octets SND.UNA advanced by
 * @var DispatchIo::reply       the segment tcp_in asked to be sent, or the aggregate an ack flush owes
 * @var DispatchIo::err_ptr     octets from the start of the IP header to the field a drop points at,
 *                              which is what an RFC 4443 sec 3.4 Parameter Problem carries in its
 *                              Pointer. Read only for a drop whose reason names it.
 */
typedef struct
{
    DispatchBindArgs bind_args;
    DispatchIfArgs if_args;
    DispatchInputArgs input_args;
    DispatchTcpArgs tcp_args;

    IdemIpStatus status;
    uint32_t act;
    IdemIpDispatchDrop drop;
    IdemIpDispatchPcb pcb_kind;
    uint16_t pcb;
    uint16_t type;
    uint16_t vid;
    uint16_t last_vid;
    uint8_t pcp;
    idemip_bool tagged;

    size_t ip_off;
    size_t payload_off;
    size_t payload_len;
    size_t out_len;
    uint8_t ip_version;
    uint8_t proto;
    uint8_t datagram;
    uint8_t netif;
    uint16_t desc;
    uint16_t err_ptr;

#if IDEMIP_ENABLE_TCP
    uint32_t tcp_act;
    uint32_t text_seq;
    uint32_t acked;
    uint16_t text_off;
    uint16_t text_len;
    TcpInReply reply;
#endif
} DispatchIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The operand block and the context share the
// IDEMIP_DISPATCH_CTX_BYTES ahead of the two tables, so neither table moves when either grows.

#define IDEMIP_DISPATCH_OFF_IO 0u ///< the operand and result block
#define IDEMIP_DISPATCH_OFF_CTX IDEMIP_ROUND_UP(IDEMIP_DISPATCH_OFF_IO + sizeof(DispatchIo), IDEMIP_ALIGN)
#define IDEMIP_DISPATCH_OFF_IF IDEMIP_DISPATCH_CTX_BYTES ///< IDEMIP_NETIF_COUNT interface rows

/** @brief IDEMIP_TCP_PCBS aggregation rows, one per Transmission Control Block. */
#define IDEMIP_DISPATCH_OFF_PCB                                                                                        \
    (IDEMIP_DISPATCH_OFF_IF + (IDEMIP_NETIF_COUNT << IDEMIP_DISPATCH_IF_ENTRY_SHIFT))

#define IDEMIP_DISPATCH_OFF_END                                                                                        \
    (IDEMIP_DISPATCH_OFF_PCB + (IDEMIP_TCP_PCBS << IDEMIP_DISPATCH_PCB_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_DISPATCH_IO(w) ((DispatchIo *)(void *)((w) + IDEMIP_DISPATCH_OFF_IO))

/**
 * @brief Frame to EtherType to protocol to pcb.
 *
 *   Dispatch.clear(work);
 *   IDEMIP_DISPATCH_IO(work)->bind_args.stats = stats_mem;
 *   Dispatch.bind(work);
 *   IDEMIP_DISPATCH_IO(work)->if_args.index = 0u;
 *   IDEMIP_DISPATCH_IO(work)->if_args.vid = 100u;
 *   IDEMIP_DISPATCH_IO(work)->if_args.tagged = IDEMIP_TRUE;
 *   Dispatch.if_bind(work);
 *   IDEMIP_DISPATCH_IO(work)->input_args.frame = frame;
 *   Dispatch.input(work);
 *   if (IDEMIP_DISPATCH_IO(work)->act & IDEMIP_DISPATCH_ACT_DELIVER) { ... }
 *
 * @c work is IDEMIP_DISPATCH_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. The borrow IS the instance, so two
 * receive paths are two borrows and share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * Nothing here blocks. BUSY is only ever "come back and it can work": a reply with no transmit buffer
 * to build into, and an ack flush with nothing owed. A frame that is malformed, addressed elsewhere,
 * or carrying a protocol nothing claims is finished with rather than retried, so it is reported OK
 * with IDEMIP_DISPATCH_ACT_DROP and the counter already bumped; a null borrow, an unbound borrow, an
 * index past a table, and a frame with no octets are ERR.
 *
 * @var DispatchNs::clear       zero the context and both tables, set every row's last discarded VLAN
 *                              ID to IDEMIP_DISPATCH_VID_NONE, and mark the borrow usable. Every
 *                              other entry refuses a borrow this has not run on.
 * @var DispatchNs::bind        take the borrows the receive path calls into
 * @var DispatchNs::if_bind     take one interface's ring pair and its IEEE 802.1Q membership
 * @var DispatchNs::if_get      report one interface's row, its last discarded VLAN ID included
 * @var DispatchNs::input       walk one frame the five RFC 1122 sec 3.1 steps, bumping the RFC 1213
 *                              counter that names each outcome
 * @var DispatchNs::tcp_deliver take the next held out-of-order segment RCV.NXT has reached, deliver
 *                              it, advance RCV.NXT over it and unpin its descriptor. BUSY when the
 *                              queue holds nothing RCV.NXT has reached, which a later segment
 *                              changes.
 * @var DispatchNs::tcp_ack     take one connection owing the aggregate acknowledgment of RFC 9293
 *                              sec 3.10.7.4 (MUST-58, MUST-59), reported in @ref DispatchIo::reply.
 *                              BUSY when none owes one.
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const bind)(uint8_t *restrict work);
    void (*const if_bind)(uint8_t *restrict work);
    void (*const if_get)(uint8_t *restrict work);
    void (*const input)(uint8_t *restrict work);
#if IDEMIP_ENABLE_TCP
    void (*const tcp_deliver)(uint8_t *restrict work);
    void (*const tcp_ack)(uint8_t *restrict work);
#endif
} DispatchNs;

/** @brief The one symbol this module exports. Immutable, so it costs no RAM. */
extern const DispatchNs Dispatch;

// RFC 6325 sec 4.1.1 reserves 0xFFF, so no membership can ever equal the sentinel.
static_assert(IDEMIP_DISPATCH_VID_NONE > IDEMIP_VLAN_VID_LAST,
              "the sentinel must lie above the usable VLAN ID range (RFC 6325 sec 4.1.1)");

// An interface index and a descriptor index each fit the width the row and the operand block hold.
static_assert(IDEMIP_NETIF_COUNT < IDEMIP_DISPATCH_NETIF_NONE,
              "IDEMIP_NETIF_COUNT must stay below IDEMIP_DISPATCH_NETIF_NONE: an index is one octet");
static_assert(IDEMIP_RX_DESCRIPTORS < IDEMIP_DISPATCH_DESC_NONE,
              "IDEMIP_RX_DESCRIPTORS must stay below IDEMIP_DISPATCH_DESC_NONE: the sentinel names no "
              "descriptor");
static_assert(IDEMIP_RX_DESCRIPTORS <= 0x100u,
              "IDEMIP_RX_DESCRIPTORS must fit the low octet of a descriptor handle, which carries the "
              "ring index; the high octet carries the interface");
static_assert(IDEMIP_NETIF_COUNT < IDEMIP_DISPATCH_NETIF_NONE,
              "IDEMIP_NETIF_COUNT must fit the high octet of a descriptor handle, below the value "
              "IDEMIP_DISPATCH_DESC_NONE reserves");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_DISPATCH_H
