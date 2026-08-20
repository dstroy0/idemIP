// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file vlan.c
 * @brief The C-Tag, read out of the caller's frame and written into it.
 *
 * Every entry is a function of the one pointer it is handed: the operand block and the context are
 * both regions of that borrow, at compile-time offsets, and no entry reads or writes a byte outside
 * it and the frame an operand points at. The module holds no frame between calls.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/ethernet/vlan.h"

IDEMIP_BEGIN_DECLS

// The running context. ready is the mark clear leaves, so a borrow no one cleared is refused.
typedef struct
{
    idemip_bool ready;
    uint8_t pad[7];
} VlanCtx;

// Where this unit's context sits, as a compile-time fact: on the alignment, and inside what
// holds it. common.h's IDEMIP_ASSERT_REGION states both.
IDEMIP_ASSERT_REGION(IDEMIP_VLAN_OFF_CTX, sizeof(VlanCtx), IDEMIP_VLAN_OFF_END, "vlan's context");

// The caller's borrow, split: the operand block, then the context. vlan.h publishes the offsets;
// these two asserts prove the span covers them before anything runs.
static_assert(IDEMIP_VLAN_OFF_CTX + sizeof(VlanCtx) <= IDEMIP_VLAN_OFF_END,
              "IDEMIP_VLAN_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_VLAN_OFF_END <= IDEMIP_VLAN_BORROW,
              "IDEMIP_VLAN_BORROW is short of the map - raise IDEMIP_VLAN_CTX_BYTES in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define VLAN_IO(w) IDEMIP_VLAN_IO(w)
#define VLAN_CTX(w) ((VlanCtx *)(void *)((w) + IDEMIP_VLAN_OFF_CTX))

// Octets the context spans, which is what clear zeroes.
#define VLAN_STATE_BYTES (IDEMIP_VLAN_OFF_END - IDEMIP_VLAN_OFF_CTX)

// --- the tag fields --------------------------------------------------------

// RFC 6325 sec 4.1.1 Figure 8, "Priority | C | VLAN ID", into the result members.
static void vlan_split_tci(VlanIo *io, uint16_t tci)
{
    io->tci = tci;
    io->pcp = (uint8_t)((tci >> IDEMIP_VLAN_PCP_SHIFT) & IDEMIP_VLAN_PCP_MASK);
    io->dei = (idemip_bool)((tci >> IDEMIP_VLAN_DEI_SHIFT) & IDEMIP_VLAN_DEI_MASK);
    io->vid = (uint16_t)(tci & IDEMIP_VLAN_VID_MASK);
    io->vid_null = (idemip_bool)(io->vid == IDEMIP_VLAN_VID_NULL);
    io->vid_reserved = (idemip_bool)(io->vid == IDEMIP_VLAN_VID_RESERVED);
}

// The same three fields, back into one word.
static uint16_t vlan_pack_tci(const VlanTagArgs *tag)
{
    return (uint16_t)(((uint16_t)(tag->pcp & IDEMIP_VLAN_PCP_MASK) << IDEMIP_VLAN_PCP_SHIFT) |
                      ((uint16_t)(tag->dei & IDEMIP_VLAN_DEI_MASK) << IDEMIP_VLAN_DEI_SHIFT) |
                      (uint16_t)(tag->vid & IDEMIP_VLAN_VID_MASK));
}

// What a written tag has to satisfy: RFC 6325 sec 4.1.1 puts the Priority at "0 through 7", holds
// the VLAN ID in twelve bits, and states "The VLAN ID 0xFFF MUST NOT be used".
static idemip_bool vlan_tag_writable(const VlanTagArgs *tag)
{
    if (tag->pcp > IDEMIP_VLAN_PCP_MAX || tag->vid > IDEMIP_VLAN_VID_MASK)
    {
        return IDEMIP_FALSE;
    }
    return (tag->vid == IDEMIP_VLAN_VID_RESERVED) ? IDEMIP_FALSE : IDEMIP_TRUE;
}

// Every result member a call leaves behind, so no entry reports what an earlier one found.
static void vlan_reset(VlanIo *io)
{
    io->status = IDEMIP_ERR;
    io->payload = NULL;
    io->payload_off = 0u;
    io->llc = IDEMIP_FALSE;
    io->tci = 0u;
    io->type = 0u;
    io->vid = 0u;
    io->pcp = 0u;
    io->dei = IDEMIP_FALSE;
    io->tagged = IDEMIP_FALSE;
    io->vid_null = IDEMIP_FALSE;
    io->vid_reserved = IDEMIP_FALSE;
}

// --- the entries -----------------------------------------------------------

void idemip_vlan_clear(uint8_t *work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_VLAN_OFF_CTX, 0, VLAN_STATE_BYTES);
    VLAN_CTX(work)->ready = IDEMIP_TRUE;
    VLAN_IO(work)->status = IDEMIP_OK;
}

// The type code at IDEMIP_VLAN_OFF_TPID, and the tag behind it when it is the C-Tag Ethertype (RFC
// 6325 sec 4.1 Figure 7). An untagged frame is OK with tagged false: the caller reads the same
// result members either way. A frame shorter than the header it claims is ERR, no retry over the
// same octets reaching further.
void idemip_vlan_parse(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    VlanIo *io = VLAN_IO(work);
    vlan_reset(io);
    const uint8_t *frame = io->parse_args.frame;
    if (!VLAN_CTX(work)->ready || frame == NULL || io->parse_args.len < IDEMIP_ETH_HDR_LEN)
    {
        return;
    }
    uint16_t tpid = idemip_rd16(frame + IDEMIP_VLAN_OFF_TPID);
    if (tpid != IDEMIP_VLAN_TPID)
    {
        // RFC 1122 sec 2.3.3: "the 802.3 Length field must be less than or equal to 1500, while all
        // valid Ether-Type values are greater than 1500." A Length names an 802.3 frame, whose IP is
        // behind the RFC 1042 LLC and SNAP headers, and the EtherType is the last two octets of them.
        if (tpid <= (uint16_t)IDEMIP_ETH_MAX_PAYLOAD)
        {
            const size_t need = (size_t)IDEMIP_ETH_HDR_LEN + IDEMIP_LLC_SNAP_LEN;
            if (io->parse_args.len < need || !idemip_llc_is_snap(frame + IDEMIP_ETH_OFF_PAYLOAD))
            {
                return; // not an encapsulation this decodes, and no retry over the same octets does
            }
            io->type = idemip_rd16(frame + IDEMIP_ETH_OFF_PAYLOAD + IDEMIP_LLC_OFF_TYPE);
            io->payload_off = (uint16_t)need;
            io->payload = frame + need;
            io->llc = IDEMIP_TRUE;
            io->status = IDEMIP_OK;
            return;
        }
        io->type = tpid;
        io->payload_off = IDEMIP_ETH_OFF_PAYLOAD;
        io->payload = frame + IDEMIP_ETH_OFF_PAYLOAD;
        io->status = IDEMIP_OK;
        return;
    }
    if (io->parse_args.len < IDEMIP_VLAN_HDR_LEN)
    {
        return;
    }
    vlan_split_tci(io, idemip_rd16(frame + IDEMIP_VLAN_OFF_TCI));
    uint16_t type = idemip_rd16(frame + IDEMIP_VLAN_OFF_TYPE);
    io->tagged = IDEMIP_TRUE;
    // The same sec 2.3.3 discriminator behind the tag, where the field sits at
    // IDEMIP_VLAN_OFF_TYPE rather than at IDEMIP_VLAN_OFF_TPID.
    if (type <= (uint16_t)IDEMIP_ETH_MAX_PAYLOAD)
    {
        const size_t need = (size_t)IDEMIP_VLAN_OFF_PAYLOAD + IDEMIP_LLC_SNAP_LEN;
        if (io->parse_args.len < need || !idemip_llc_is_snap(frame + IDEMIP_VLAN_OFF_PAYLOAD))
        {
            io->tagged = IDEMIP_FALSE;
            return;
        }
        io->type = idemip_rd16(frame + IDEMIP_VLAN_OFF_PAYLOAD + IDEMIP_LLC_OFF_TYPE);
        io->payload_off = (uint16_t)need;
        io->payload = frame + need;
        io->llc = IDEMIP_TRUE;
        io->status = IDEMIP_OK;
        return;
    }
    io->type = type;
    io->payload_off = IDEMIP_VLAN_OFF_PAYLOAD;
    io->payload = frame + IDEMIP_VLAN_OFF_PAYLOAD;
    io->status = IDEMIP_OK;
}

// Six octets at IDEMIP_VLAN_OFF_TPID: the C-Tag Ethertype, the Tag Control Information, then the
// type code the payload is. The two addresses ahead of them are the caller's, and the data field
// starts at IDEMIP_VLAN_OFF_PAYLOAD.
void idemip_vlan_build(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    VlanIo *io = VLAN_IO(work);
    uint8_t *frame = io->build_args.frame;
    uint16_t type = io->build_args.type;
    vlan_reset(io);
    if (!VLAN_CTX(work)->ready || frame == NULL || !vlan_tag_writable(&io->tag_args))
    {
        return;
    }
    uint16_t tci = vlan_pack_tci(&io->tag_args);
    idemip_wr16(frame + IDEMIP_VLAN_OFF_TPID, (uint16_t)IDEMIP_VLAN_TPID);
    idemip_wr16(frame + IDEMIP_VLAN_OFF_TCI, tci);
    idemip_wr16(frame + IDEMIP_VLAN_OFF_TYPE, type);
    vlan_split_tci(io, tci);
    io->type = type;
    io->payload_off = IDEMIP_VLAN_OFF_PAYLOAD;
    io->payload = frame + IDEMIP_VLAN_OFF_PAYLOAD;
    io->tagged = IDEMIP_TRUE;
    io->status = IDEMIP_OK;
}

// The three fields into one Tag Control Information field, for a MAC that inserts the tag itself.
// Refuses what a build refuses, the field being the same field.
void idemip_vlan_pack(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    VlanIo *io = VLAN_IO(work);
    vlan_reset(io);
    if (!VLAN_CTX(work)->ready || !vlan_tag_writable(&io->tag_args))
    {
        return;
    }
    vlan_split_tci(io, vlan_pack_tci(&io->tag_args));
    io->status = IDEMIP_OK;
}

// One Tag Control Information field into its three, for a MAC that stripped the tag and reported
// the field. Every 16-bit value splits, the reserved VLAN ID included, which is reported rather
// than refused: the octets already arrived.
void idemip_vlan_split(uint8_t *work)
{
    if (!work)
    {
        return;
    }
    VlanIo *io = VLAN_IO(work);
    uint16_t tci = io->tci_args.tci;
    vlan_reset(io);
    if (!VLAN_CTX(work)->ready)
    {
        return;
    }
    vlan_split_tci(io, tci);
    io->status = IDEMIP_OK;
}

IDEMIP_END_DECLS
