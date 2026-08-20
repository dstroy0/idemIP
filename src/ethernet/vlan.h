// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file vlan.h
 * @brief The IEEE 802.1Q C-Tag: four octets between the Ethernet II addresses and the type code
 *        that names the payload.
 *
 * A tagged frame carries the C-Tag Ethertype 0x8100 where an untagged one carries its own type
 * code, then a 16-bit Tag Control Information field, then the type code the payload actually is.
 * The tag adds four octets, so the payload starts eighteen octets in rather than fourteen.
 *
 * WHAT IS CITED AND WHAT IS NOT. IEEE Std 802.1Q itself is not readable without purchase, so no
 * clause of it is cited here. Every constant below is taken from an open document that states it:
 *
 *   - RFC 7042 Appendix B.2: "0x8100  IEEE Std 802.1Q  - Customer VLAN Tag Type (C-Tag, formerly
 *     called the Q-Tag)", and "0x88A8  IEEE Std 802.1Q  - Service VLAN tag identifier (S-Tag)",
 *     which this module does not write.
 *   - RFC 6325 sec 4.1 Figure 7 draws the tag's place in the frame: the two MAC addresses, then
 *     "Ethertype = C-Tag [802.1Q-2005] | Inner.VLAN Tag Information", then "Ethertype of Original
 *     Payload".
 *   - RFC 6325 sec 4.1.1 Figure 8 draws the Tag Control Information as "Priority | C | VLAN ID",
 *     three bits, one bit and twelve bits, and states "The C-Tag Ethertype [RFC5342] is 0x8100",
 *     "the priority field contains an unsigned value from 0 through 7", "VLAN ID zero is the null
 *     VLAN identifier and indicates that no VLAN is specified while VLAN ID 0xFFF is reserved", and
 *     "The VLAN ID 0xFFF MUST NOT be used".
 *
 * The one-bit field between Priority and VLAN ID is named "C" by RFC 6325 sec 4.1.1, for the
 * Canonical Format Indicator. It is called the Drop Eligible Indicator here, which is the name lwIP
 * `src/include/lwip/ip.h:102` gives it in `pcb_tci_set_pcp_dei_vid(pcb, pcp, dei, vid)` and Linux
 * `include/linux/if_vlan.h:75` gives it in "Canonical Format Indicator / Drop Eligible Indicator".
 * The rename is IEEE's and is not stated in any document read here; only the bit's position is.
 */

#ifndef IDEMIP_VLAN_H
#define IDEMIP_VLAN_H

#include "src/ethernet/ethernet.h"

#if IDEMIP_ENABLE_ETHERNET

IDEMIP_BEGIN_DECLS

// ---------------------------------------------------------------------------
// The tag, and where it sits
// ---------------------------------------------------------------------------

/** @brief RFC 6325 sec 4.1.1: "The C-Tag Ethertype [RFC5342] is 0x8100." */
#define IDEMIP_VLAN_TPID 0x8100u

/** @brief The Ethertype an 802.1ad S-Tag carries (RFC 7042 Appendix B.2). Not written here. */
#define IDEMIP_VLAN_STAG_TPID 0x88A8u

/**
 * @brief Octets the tag adds to a frame: the C-Tag Ethertype and the Tag Control Information.
 *
 * RFC 6325 sec 4.1 Figure 7 draws both as 16-bit fields. lwIP `SIZEOF_VLAN_HDR` and Linux
 * `VLAN_HLEN` are the same four.
 */
#define IDEMIP_VLAN_TAG_LEN 4u

/** @brief The C-Tag Ethertype, where an untagged frame carries its own type code. */
#define IDEMIP_VLAN_OFF_TPID IDEMIP_ETH_OFF_TYPE

/** @brief 16-bit Tag Control Information. */
#define IDEMIP_VLAN_OFF_TCI (IDEMIP_VLAN_OFF_TPID + IDEMIP_ETH_TYPE_LEN)

/** @brief The type code the payload is, which RFC 6325 sec 4.1 Figure 7 puts behind the tag. */
#define IDEMIP_VLAN_OFF_TYPE (IDEMIP_VLAN_OFF_TCI + IDEMIP_ETH_TYPE_LEN)

/** @brief The data field of a tagged frame. */
#define IDEMIP_VLAN_OFF_PAYLOAD (IDEMIP_VLAN_OFF_TYPE + IDEMIP_ETH_TYPE_LEN)

/** @brief Header octets a tagged frame carries ahead of its data field. Linux `VLAN_ETH_HLEN`. */
#define IDEMIP_VLAN_HDR_LEN (IDEMIP_ETH_HDR_LEN + IDEMIP_VLAN_TAG_LEN)

/**
 * @brief Whole tagged frame on the wire, the tag included.
 *
 * The tag is four octets no untagged frame carries. Linux `include/linux/if_vlan.h` states the same
 * 1518 as `VLAN_ETH_FRAME_LEN`, noting "According to 802.3ac, the packet can be 4 bytes longer";
 * IEEE Std 802.3ac is not readable without purchase and is not cited.
 */
#define IDEMIP_VLAN_FRAME_MAX (IDEMIP_ETH_FRAME_MAX + IDEMIP_VLAN_TAG_LEN)

// ---------------------------------------------------------------------------
// The Tag Control Information (RFC 6325 sec 4.1.1 Figure 8)
// ---------------------------------------------------------------------------
// "Priority | C | VLAN ID", three bits then one bit then twelve, in one 16-bit field. Each field is
// a shift and a mask; nothing here divides.

#define IDEMIP_VLAN_PCP_SHIFT 13u  ///< Priority, the three high bits
#define IDEMIP_VLAN_PCP_MASK 0x07u ///< the value once shifted down
#define IDEMIP_VLAN_DEI_SHIFT 12u  ///< the "C" bit RFC 6325 sec 4.1.1 draws between the two fields
#define IDEMIP_VLAN_DEI_MASK 0x01u
#define IDEMIP_VLAN_VID_MASK 0x0FFFu ///< VLAN ID, the twelve low bits

/** @brief RFC 6325 sec 4.1.1: "the priority field contains an unsigned value from 0 through 7". */
#define IDEMIP_VLAN_PCP_MAX 7u

/** @brief Values the 12-bit VLAN ID field spans. Linux `VLAN_N_VID`. */
#define IDEMIP_VLAN_VIDS 4096u

/**
 * @brief RFC 6325 sec 4.1.1: "VLAN ID zero is the null VLAN identifier and indicates that no VLAN
 * is specified", a frame carrying it being "called 'priority tagged' rather than 'VLAN tagged'".
 */
#define IDEMIP_VLAN_VID_NULL 0x000u

/** @brief RFC 6325 sec 4.1.1: "allow use of the full range of VLAN IDs from 0x001 through 0xFFE". */
#define IDEMIP_VLAN_VID_FIRST 0x001u
#define IDEMIP_VLAN_VID_LAST 0x0FFEu

/** @brief RFC 6325 sec 4.1.1: "VLAN ID 0xFFF is reserved", and "MUST NOT be used". */
#define IDEMIP_VLAN_VID_RESERVED 0x0FFFu

// ---------------------------------------------------------------------------
// What a call takes
// ---------------------------------------------------------------------------

/**
 * @brief What a parse takes.
 *
 * @var VlanParseArgs::frame the frame where the engine left it, from its Destination address on
 * @var VlanParseArgs::len   octets of it that are readable
 */
typedef struct
{
    const uint8_t *frame;
    size_t len;
} VlanParseArgs;

/**
 * @brief What a build takes, beyond the three tag fields.
 *
 * @var VlanBuildArgs::frame the frame being built, from its Destination address on. The build
 *                           writes IDEMIP_VLAN_TAG_LEN + IDEMIP_ETH_TYPE_LEN octets at
 *                           IDEMIP_VLAN_OFF_TPID and touches nothing else.
 * @var VlanBuildArgs::type  the type code the payload is, which goes behind the tag
 */
typedef struct
{
    uint8_t *frame;
    uint16_t type;
} VlanBuildArgs;

/**
 * @brief The three fields of the Tag Control Information (RFC 6325 sec 4.1.1 Figure 8).
 *
 * @var VlanTagArgs::vid the 12-bit VLAN ID
 * @var VlanTagArgs::pcp the 3-bit Priority, 0 through 7
 * @var VlanTagArgs::dei the one bit RFC 6325 sec 4.1.1 draws as "C"
 */
typedef struct
{
    uint16_t vid;
    uint8_t pcp;
    idemip_bool dei;
} VlanTagArgs;

/**
 * @brief What a split takes: one Tag Control Information field, as a MAC that strips the tag
 *        reports it.
 */
typedef struct
{
    uint16_t tci;
} VlanTciArgs;

/**
 * @brief The operands and results of a call, in the caller's borrow.
 *
 * Not on the namespace. An entry is a function of @c work alone, so everything a call reads and
 * everything it reports lives in the bytes the caller owns.
 *
 * @var VlanIo::parse_args   the frame a parse reads
 * @var VlanIo::build_args   the frame a build writes, and the type code behind the tag
 * @var VlanIo::tag_args     the three tag fields a build or a pack takes
 * @var VlanIo::tci_args     the field a split takes
 * @var VlanIo::status       what the call reports: OK or ERR
 * @var VlanIo::payload      where the data field starts, in the caller's frame
 * @var VlanIo::payload_off  how far in that is: IDEMIP_VLAN_OFF_PAYLOAD tagged, IDEMIP_ETH_HDR_LEN
 *                           untagged
 * @var VlanIo::tci          the whole 16-bit Tag Control Information
 * @var VlanIo::type         the type code the payload is, tag or no tag. On an 802.3 frame it is the
 *                           EtherType RFC 1042 puts in the SNAP header, not the 802.3 Length field
 * @var VlanIo::llc          the frame was in the RFC 1042 802.3 framing, so RFC 1122 sec 2.3.3's
 *                           discriminator found a Length at or below 1500 and the payload starts
 *                           past the eight LLC and SNAP octets
 * @var VlanIo::vid          the 12-bit VLAN ID
 * @var VlanIo::pcp          the 3-bit Priority
 * @var VlanIo::dei          the "C" bit
 * @var VlanIo::tagged       the type code at IDEMIP_VLAN_OFF_TPID was IDEMIP_VLAN_TPID
 * @var VlanIo::vid_null     the VLAN ID was zero, so the frame is priority tagged rather than VLAN
 *                           tagged (RFC 6325 sec 4.1.1)
 * @var VlanIo::vid_reserved the VLAN ID was 0xFFF, which RFC 6325 sec 4.1.1 reserves
 */
typedef struct
{
    VlanParseArgs parse_args;
    VlanBuildArgs build_args;
    VlanTagArgs tag_args;
    VlanTciArgs tci_args;

    const uint8_t *payload;
    size_t payload_off;
    IdemIpStatus status;
    uint16_t tci;
    uint16_t type;
    uint16_t vid;
    uint8_t pcp;
    idemip_bool dei;
    idemip_bool tagged;
    idemip_bool llc;
    idemip_bool vid_null;
    idemip_bool vid_reserved;
} VlanIo;

// ---------------------------------------------------------------------------
// The borrow map
// ---------------------------------------------------------------------------
// Every offset is a constant. An entry computes each region as the one pointer it was handed plus a
// compile-time offset, so nothing is derived at runtime. The region types are this module's; only
// the map is public.

#define IDEMIP_VLAN_OFF_IO 0u ///< the operand and result block
#define IDEMIP_VLAN_OFF_CTX (IDEMIP_VLAN_OFF_IO + IDEMIP_ROUND_UP(sizeof(VlanIo), IDEMIP_ALIGN))
#define IDEMIP_VLAN_OFF_END (IDEMIP_VLAN_OFF_IO + IDEMIP_VLAN_CTX_BYTES)

/** @brief The operand block, at its offset in the caller's borrow. */
#define IDEMIP_VLAN_IO(w) ((VlanIo *)(void *)((w) + IDEMIP_VLAN_OFF_IO))

/**
 * @brief The C-Tag, read out of a frame and written into one.
 *
 *   Vlan.clear(work);
 *   IDEMIP_VLAN_IO(work)->parse_args.frame = frame;
 *   IDEMIP_VLAN_IO(work)->parse_args.len = len;
 *   Vlan.parse(work);
 *   if (IDEMIP_VLAN_IO(work)->tagged) { ... IDEMIP_VLAN_IO(work)->vid ... }
 *
 * @c work is IDEMIP_VLAN_BORROW bytes the CALLER took, at an address it knows. It is
 * not held past the call, so nothing here aliases it. The borrow IS the
 * instance, so two frames read at once are two borrows and share not one byte.
 *
 * A borrow is refused until @ref VlanNs::clear has run on it: clear zeroes the context region and
 * leaves one nonzero octet in it, the mark that says these bytes are this module's. It does not
 * touch the operand block.
 *
 * Nothing here blocks, and nothing here ever reports IDEMIP_BUSY. Every entry is a function of the
 * octets the caller supplied, so a call that cannot finish now cannot finish on a later tick
 * either: a null borrow, a null frame, a borrow no one cleared, a frame too short for the header it
 * claims, a Priority above 7, and a VLAN ID outside the field or equal to the reserved 0xFFF are
 * all IDEMIP_ERR.
 *
 * An untagged frame is not an error. A parse reports it as OK with @ref VlanIo::tagged false, the
 * frame's own type code in @ref VlanIo::type, and the data field at IDEMIP_ETH_HDR_LEN.
 *
 * @var VlanNs::clear zero the context and mark the borrow cleared
 * @var VlanNs::parse read the type code at IDEMIP_VLAN_OFF_TPID, and the tag behind it when it is
 *                    the C-Tag Ethertype
 * @var VlanNs::build write the C-Tag Ethertype, the Tag Control Information, and the payload's own
 *                    type code
 * @var VlanNs::pack  the three tag fields into one Tag Control Information field
 * @var VlanNs::split one Tag Control Information field into its three fields
 */
typedef struct
{
    void (*const clear)(uint8_t *work);
    void (*const parse)(uint8_t *work);
    void (*const build)(uint8_t *work);
    void (*const pack)(uint8_t *work);
    void (*const split)(uint8_t *work);
} VlanNs;

// What the table binds. Each takes the one borrow and nothing else: everything an
// entry reads is an operand in the block at offset zero, or a region of the borrow
// at a fixed offset.
void idemip_vlan_clear(uint8_t *work);
void idemip_vlan_parse(uint8_t *work);
void idemip_vlan_build(uint8_t *work);
void idemip_vlan_pack(uint8_t *work);
void idemip_vlan_split(uint8_t *work);

/**
 * @brief The one symbol this module exports. Immutable, so it costs no RAM.
 *
 * Aggregate-initialised HERE rather than declared `extern` against a definition in the .c. A
 * `const` object whose initializer every translation unit can see is a compile-time fact, so
 * `Vlan.entry(w)` resolves to a named function and becomes a direct call, and the table itself is
 * read by nothing at run time and is not emitted. An `extern` table leaves the call indirect: the
 * caller loads the pointer and branches through it, because nothing at the call site says what it
 * holds.
 */
static const VlanNs Vlan IDEMIP_UNUSED = {
    .clear = idemip_vlan_clear,
    .parse = idemip_vlan_parse,
    .build = idemip_vlan_build,
    .pack = idemip_vlan_pack,
    .split = idemip_vlan_split};
// RFC 6325 sec 4.1 Figure 7: the C-Tag Ethertype and the Tag Control Information, two 16-bit fields.
static_assert(IDEMIP_VLAN_OFF_TYPE - IDEMIP_VLAN_OFF_TPID == IDEMIP_VLAN_TAG_LEN,
              "the tag is the C-Tag Ethertype and the Tag Control Information, four octets");

// The tag sits where an untagged frame's type code sits, and the payload's type code follows it.
static_assert(IDEMIP_VLAN_OFF_TPID == IDEMIP_ETH_OFF_TYPE,
              "the C-Tag Ethertype occupies the Ethernet II type field (RFC 6325 sec 4.1 Figure 7)");
static_assert(IDEMIP_VLAN_OFF_PAYLOAD == IDEMIP_ETH_OFF_PAYLOAD + IDEMIP_VLAN_TAG_LEN,
              "a tag moves the data field four octets further in");
static_assert(IDEMIP_VLAN_HDR_LEN == IDEMIP_VLAN_OFF_PAYLOAD,
              "the field offsets must sum to the tagged header length");

// RFC 6325 sec 4.1.1 Figure 8: three bits of Priority, one C bit, twelve bits of VLAN ID.
static_assert(IDEMIP_VLAN_PCP_SHIFT == IDEMIP_VLAN_DEI_SHIFT + 1u,
              "the C bit sits directly below the three Priority bits (RFC 6325 sec 4.1.1)");
static_assert(IDEMIP_VLAN_DEI_SHIFT == 12u && IDEMIP_VLAN_VID_MASK == 0x0FFFu,
              "the VLAN ID is the twelve low bits, the C bit the one above them");
static_assert(((IDEMIP_VLAN_PCP_MASK << IDEMIP_VLAN_PCP_SHIFT) | (IDEMIP_VLAN_DEI_MASK << IDEMIP_VLAN_DEI_SHIFT) |
               IDEMIP_VLAN_VID_MASK) == 0xFFFFu,
              "the three fields must cover the whole 16-bit Tag Control Information");
static_assert(IDEMIP_VLAN_PCP_MAX == IDEMIP_VLAN_PCP_MASK,
              "RFC 6325 sec 4.1.1 puts the Priority at 0 through 7, which is the three-bit field");
static_assert(IDEMIP_VLAN_VIDS == IDEMIP_VLAN_VID_MASK + 1u, "the VLAN ID field spans IDEMIP_VLAN_VIDS values");
static_assert(IDEMIP_VLAN_VID_RESERVED == IDEMIP_VLAN_VID_MASK && IDEMIP_VLAN_VID_LAST + 1u == IDEMIP_VLAN_VID_RESERVED,
              "RFC 6325 sec 4.1.1 runs the usable range 0x001 through 0xFFE and reserves 0xFFF");

IDEMIP_END_DECLS

#endif // IDEMIP_ENABLE_ETHERNET

#endif // IDEMIP_VLAN_H
