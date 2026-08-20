// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file dad.h
 * @brief Duplicate Address Detection, RFC 4862 sec 5.4: the tests a tentative address passes before
 *        it is assigned to an interface.
 *
 * sec 5.4: "Duplicate Address Detection MUST be performed on all unicast addresses prior to
 * assigning them to an interface", so one interface runs one machine per tentative address and the
 * borrow holds IDEMIP_IP6_ADDRESSES of them. The borrow IS the interface, so two interfaces are two
 * borrows.
 *
 * Every deadline here is a millisecond. sec 5.1 states RetransTimer in milliseconds and RFC 4861
 * sec 10 states MAX_RTR_SOLICITATION_DELAY in seconds, which idemip_config.h holds as milliseconds,
 * so no conversion and no divide exists.
 *
 * Nothing here builds or parses a Neighbor Solicitation or Advertisement: this unit reports which
 * solicitation is due and reads the Target Address of one that arrived.
 */

#ifndef IDEMIP_DAD_H
#define IDEMIP_DAD_H

#include "src/ip/ipv6.h"

#if IDEMIP_ENABLE_IPV6

IDEMIP_BEGIN_DECLS

/** @brief No entry. Every index below is a table slot, so this names none of them. */
#define IDEMIP_DAD_NONE 0xFFu

/**
 * @brief Where the machine is over one address (RFC 4862 sec 5.4).
 *
 * sec 5.4: "An address on which the Duplicate Address Detection procedure is applied is said to be
 * tentative until the procedure has completed successfully", and the procedure completes when "none
 * of the tests indicate the presence of a duplicate address within RetransTimer milliseconds after
 * having sent DupAddrDetectTransmits Neighbor Solicitations".
 */
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_DAD_STATE_FREE = 0,  ///< the slot holds no address, which is what clear leaves
    IDEMIP_DAD_STATE_DELAY,     ///< sec 5.4.2, waiting out the delay before joining and soliciting
    IDEMIP_DAD_STATE_PROBING,   ///< sec 5.4.2, sending DupAddrDetectTransmits solicitations
    IDEMIP_DAD_STATE_WAIT,      ///< sec 5.4, the RetransTimer after the last solicitation
    IDEMIP_DAD_STATE_UNIQUE,    ///< the procedure completed, so the address "may be assigned"
    IDEMIP_DAD_STATE_DUPLICATE, ///< sec 5.4.5, the address "MUST NOT be assigned to an interface"
} IdemIpDadState;

/**
 * @brief What this interface is configured with, in the caller's rodata.
 *
 * RFC 4862 sec 5.1: "A node MUST allow the following autoconfiguration-related variable to be
 * configured by system management for each multicast-capable interface", which is why this is a
 * per-interface config pointer rather than a build-wide constant.
 *
 * @var IdemIpDadCfg::transmits DupAddrDetectTransmits, "The number of consecutive Neighbor
 *                              Solicitation messages sent while performing Duplicate Address
 *                              Detection on a tentative address. A value of zero indicates that
 *                              Duplicate Address Detection is not performed on tentative
 *                              addresses." Default 1.
 * @var IdemIpDadCfg::loopback  true when this interface loops its own multicast back, which
 *                              sec 5.4.3 counts against: "If the actual number of Neighbor
 *                              Solicitations received exceeds the number expected based on the
 *                              loopback semantics ... the tentative address is a duplicate."
 */
typedef struct
{
    uint8_t transmits;
    idemip_bool loopback;
} IdemIpDadCfg;

/** @brief What bind takes. */
typedef struct
{
    const IdemIpDadCfg *cfg;
} DadBindArgs;

/**
 * @brief What start takes: the tentative address, and the clock the first deadline is stamped from.
 *
 * @var DadStartArgs::addr       the tentative address, IDEMIP_IP6_ADDR_LEN octets
 * @var DadStartArgs::retrans_ms RetransTimer, which sec 5.1 makes "the delay between consecutive
 *                               Neighbor Solicitation transmissions ... as well as the time a node
 *                               waits after sending the last Neighbor Solicitation before ending
 *                               the Duplicate Address Detection process". Zero takes RFC 4861
 *                               sec 10's IDEMIP_ND6_RETRANS_TIMER_MS.
 * @var DadStartArgs::rand       a random word the sec 5.4.2 delay is drawn from
 * @var DadStartArgs::now_ms     the millisecond clock that delay is added to
 * @var DadStartArgs::delay      sec 5.4.2: the node "SHOULD delay joining the solicited-node
 *                               multicast address by a random delay between 0 and
 *                               MAX_RTR_SOLICITATION_DELAY" when this is the first message after
 *                               interface (re)initialization, and again "if the address being
 *                               checked is configured by a router advertisement message sent to a
 *                               multicast address"
 * @var DadStartArgs::hw_derived sec 5.4.5: the address is "formed from an interface identifier
 *                               based on the hardware address, which is supposed to be uniquely
 *                               assigned (e.g., EUI-64 for an Ethernet interface)"
 */
typedef struct
{
    const uint8_t *addr;
    uint32_t retrans_ms;
    uint32_t rand;
    uint32_t now_ms;
    idemip_bool delay;
    idemip_bool hw_derived;
    /** RFC 4862 sec 5.4: "Duplicate Address Detection MUST NOT be performed on anycast addresses
     *  (note that anycast addresses cannot syntactically be distinguished from unicast addresses)."
     *  The octets cannot say which it is, so the caller that assigned the address says. */
    idemip_bool anycast;
} DadStartArgs;

/** @brief What a call keyed on an address takes. */
typedef struct
{
    const uint8_t *addr; ///< IDEMIP_IP6_ADDR_LEN octets
} DadAddrArgs;

/**
 * @brief What an arriving Neighbor Solicitation takes (RFC 4862 sec 5.4.3).
 *
 * @var DadNsInArgs::target       the solicitation's Target Address, IDEMIP_IP6_ADDR_LEN octets
 * @var DadNsInArgs::unspecified  the IP source was the unspecified address, which sec 5.4.3 reads as
 *                                "the solicitation is from a node performing Duplicate Address
 *                                Detection"
 */
typedef struct
{
    const uint8_t *target;
    idemip_bool unspecified;
} DadNsInArgs;

/**
 * @brief What an arriving Neighbor Advertisement takes (RFC 4862 sec 5.4.4).
 *
 * @var DadNaInArgs::target the advertisement's Target Address, IDEMIP_IP6_ADDR_LEN octets
 */
typedef struct
{
    const uint8_t *target;
} DadNaInArgs;

/** @brief What a tick takes: the clock every deadline is compared against. */
typedef struct
{
    uint32_t now_ms;
} DadTickArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var DadIo::bind_args   the per-interface configuration
 * @var DadIo::start_args  the tentative address a machine is opened on
 * @var DadIo::addr_args   the address a stop or a find names
 * @var DadIo::ns_in_args  the arriving Neighbor Solicitation
 * @var DadIo::na_in_args  the arriving Neighbor Advertisement
 * @var DadIo::tick_args   the clock a tick fires deadlines against
 * @var DadIo::status      what the call reports: OK, BUSY, or ERR
 * @var DadIo::target      the entry's address, IDEMIP_IP6_ADDR_LEN octets where it lies in the
 *                         borrow, which is a solicitation's Target Address
 * @var DadIo::solicited   the solicited-node multicast address of @ref DadIo::target, RFC 4291
 *                         sec 2.7.1's FF02:0:0:0:0:1:FFXX:XXXX, which sec 5.4.2 joins and addresses
 *                         the solicitation to
 * @var DadIo::deadline when the next solicitation, or the end of the procedure, is due
 * @var DadIo::entry       the table slot the call touched, or IDEMIP_DAD_NONE
 * @var DadIo::state       where the machine is over that address
 * @var DadIo::sent        solicitations sent on it, against DupAddrDetectTransmits
 * @var DadIo::received    solicitations received on it from a node performing sec 5.4 (sec 5.4.3)
 * @var DadIo::join        sec 5.4.2: "an interface MUST join the all-nodes multicast address and the
 *                         solicited-node multicast address of the tentative address"
 * @var DadIo::send_ns     a Neighbor Solicitation is due, "the solicitation's Target Address is set
 *                         to the address being checked, the IP source is set to the unspecified
 *                         address, and the IP destination is set to the solicited-node multicast
 *                         address of the target address" (sec 5.4.2)
 * @var DadIo::unique      the procedure completed and the address "may be assigned to an interface"
 * @var DadIo::duplicate   a test found the address in use, so it "MUST NOT be assigned to an
 *                         interface" (sec 5.4.5)
 * @var DadIo::disable_ip  sec 5.4.5: the duplicate is a link-local address formed from a
 *                         hardware-based interface identifier, so "IP operation on the interface
 *                         SHOULD be disabled"
 * @var DadIo::tentative   the target named a tentative address of this interface, which sec 5.4
 *                         processes here and never as RFC 4861 would. A node "MUST NOT respond to a
 *                         Neighbor Solicitation for a tentative address" (sec 5.4.3).
 */
typedef struct
{
    DadBindArgs bind_args;
    DadStartArgs start_args;
    DadAddrArgs addr_args;
    DadNsInArgs ns_in_args;
    DadNaInArgs na_in_args;
    DadTickArgs tick_args;

    const uint8_t *target;
    IdemIpMs deadline;
    uint8_t solicited[IDEMIP_IP6_ADDR_LEN];
    IdemIpStatus status;
    uint8_t entry;
    IdemIpDadState state;
    uint8_t sent;
    uint8_t received;
    idemip_bool join;
    idemip_bool send_ns;
    idemip_bool unique;
    idemip_bool duplicate;
    idemip_bool disable_ip;
    idemip_bool tentative;
} DadIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only the
// map is public.
//
// IDEMIP_DAD_CTX_BYTES spans the operand block and the context together, the way IDEMIP_PHY_BORROW
// covers both, so the table starts at a constant that no growth in either moves.

#define IDEMIP_DAD_OFF_IO 0u ///< the operand and result block
#define IDEMIP_DAD_OFF_CTX (IDEMIP_DAD_OFF_IO + IDEMIP_ROUND_UP(sizeof(DadIo), IDEMIP_ALIGN))
#define IDEMIP_DAD_OFF_ENTRIES (IDEMIP_DAD_OFF_IO + IDEMIP_DAD_CTX_BYTES)
#define IDEMIP_DAD_OFF_END (IDEMIP_DAD_OFF_ENTRIES + (IDEMIP_IP6_ADDRESSES << IDEMIP_DAD_ENTRY_SHIFT))

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_DAD_IO(w) ((DadIo *)(void *)((w) + IDEMIP_DAD_OFF_IO))

/**
 * @brief One interface's RFC 4862 sec 5.4 machines.
 *
 *   Dad.clear(work);
 *   IDEMIP_DAD_IO(work)->bind_args.cfg = &my_dad_cfg;
 *   Dad.bind(work);
 *   IDEMIP_DAD_IO(work)->start_args.addr = tentative;
 *   IDEMIP_DAD_IO(work)->start_args.now_ms = now;
 *   Dad.start(work);
 *   Dad.tick(work);
 *   if (IDEMIP_DAD_IO(work)->send_ns) { ... }
 *
 * @c work is IDEMIP_DAD_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are carved
 * is this module's and is never named here beyond the map above. sec 5 runs autoconfiguration "on a
 * per-interface basis", so the borrow IS the interface and two interfaces share not one byte.
 *
 * Every member is `const`, and the struct holds no mutable state, so this symbol lives in rodata and
 * the module occupies no RAM of its own.
 *
 * A borrow is refused until @ref DadNs::clear has run on it: clear zeroes the context and the table
 * and leaves the mark that says these bytes are this module's. It does not touch the operand block.
 *
 * Nothing here blocks. A table with no free slot reports IDEMIP_BUSY, a slot freeing when an address
 * is stopped, and a tick with no deadline due reports IDEMIP_BUSY, the same call on a later tick
 * making progress. A bad argument, an uncleared or unbound borrow, and an address that is not in the
 * table report IDEMIP_ERR.
 *
 * @var DadNs::clear  zero the context and the table, and mark the borrow cleared
 * @var DadNs::bind   take the sec 5.1 node configuration variables
 * @var DadNs::start  open a machine on a tentative address, which sec 5.4 requires "prior to
 *                    assigning them to an interface"
 * @var DadNs::stop   drop a machine, freeing its slot
 * @var DadNs::find   report the machine over an address
 * @var DadNs::ns_in  one received Neighbor Solicitation, against sec 5.4.3's two tests
 * @var DadNs::na_in  one received Neighbor Advertisement, against sec 5.4.4 (1)
 * @var DadNs::tick   fire the deadline that has passed: the sec 5.4.2 delay, the next solicitation,
 *                    or the RetransTimer that ends the procedure
 */
typedef struct
{
    void (*const clear)(uint8_t *restrict work);
    void (*const bind)(uint8_t *restrict work);
    void (*const start)(uint8_t *restrict work);
    void (*const stop)(uint8_t *restrict work);
    void (*const find)(uint8_t *restrict work);
    void (*const ns_in)(uint8_t *restrict work);
    void (*const na_in)(uint8_t *restrict work);
    void (*const tick)(uint8_t *restrict work);
} DadNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_dad_clear(uint8_t *restrict work);
void idemip_dad_bind(uint8_t *restrict work);
void idemip_dad_start(uint8_t *restrict work);
void idemip_dad_stop(uint8_t *restrict work);
void idemip_dad_find(uint8_t *restrict work);
void idemip_dad_ns_in(uint8_t *restrict work);
void idemip_dad_na_in(uint8_t *restrict work);
void idemip_dad_tick(uint8_t *restrict work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Dad.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const DadNs Dad IDEMIP_UNUSED = {
    .clear = idemip_dad_clear,
    .bind = idemip_dad_bind,
    .start = idemip_dad_start,
    .stop = idemip_dad_stop,
    .find = idemip_dad_find,
    .ns_in = idemip_dad_ns_in,
    .na_in = idemip_dad_na_in,
    .tick = idemip_dad_tick};
// Every slot index counts the machines the borrow holds, so IDEMIP_DAD_NONE names none of them.
static_assert(IDEMIP_IP6_ADDRESSES < IDEMIP_DAD_NONE,
              "the table is wider than the index a result member carries");

// sec 5.4.2 sends DupAddrDetectTransmits solicitations and sec 5.4.3 counts what arrives, both held
// in one octet of the operand block.
static_assert(IDEMIP_DAD_TRANSMITS_DEFAULT <= 0xFFu, "DupAddrDetectTransmits is counted in one octet");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_IPV6

#endif // IDEMIP_DAD_H
