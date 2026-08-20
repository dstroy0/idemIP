// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file netif.c
 * @brief The interface table, and the IPv6 address table behind it.
 *
 * The context is this file's. Every entry is a function of the one pointer it is handed: the operand
 * block, the context and both tables are regions of that borrow, at compile-time offsets, and no
 * entry reads or writes a byte outside it. Two borrows therefore share nothing, and the same call on
 * the same borrow does the same thing.
 */

#include "src/idemip_config.h" // the entry point: the enable gate below, and the widths

#include "src/netif/netif.h"

IDEMIP_BEGIN_DECLS

// The stamp clear writes into the context. Every other entry refuses a borrow without it, so bytes
// that were never cleared are refused rather than read as a table.
#define NETIF_READY 0x4E544946u

// The one definition, private to this TU.
typedef struct
{
    uint32_t ready;   // NETIF_READY once clear has run
    uint32_t tick_ms; // the last reading of the caller's 32-bit millisecond clock
    uint32_t tick_hi; // its high word, raised each time that reading wraps
} NetifCtx;

// One interface. RFC 1122 sec 3.3.1.1 routes by addr and mask, sec 3.3.1.2 by gw. hwaddr is the
// RFC 894 48-bit address, phy is the borrow this interface's link was bound in, mtu6 is what an
// RFC 4861 sec 4.6.4 MTU option revised the link MTU to.
typedef struct
{
    uint8_t *phy;
    uint32_t addr;
    uint32_t mask;
    uint32_t gw;
    uint16_t mtu;
    uint16_t mtu6;
    uint16_t flags;
    uint16_t chksum;
    uint8_t hwaddr[IDEMIP_MAC_LEN];
    uint8_t pad[(1u << IDEMIP_NETIF_ENTRY_SHIFT) - (sizeof(uint8_t *) + (3u * 4u) + (4u * 2u) + IDEMIP_MAC_LEN)];
} NetifEntry;

static_assert(sizeof(NetifEntry) == (1u << IDEMIP_NETIF_ENTRY_SHIFT),
              "a NetifEntry is not 1 << IDEMIP_NETIF_ENTRY_SHIFT octets wide - raise the shift in idemip_config.h");

#if IDEMIP_ENABLE_IPV6

// One IPv6 address on one interface. state holds an IdemIpNetifAddr6State, INVALID being the free
// slot. The two lifetimes are the RFC 4861 sec 4.6.2 fields in seconds as they arrived, kept for the
// caller to read back, and the two _at are the millisecond of the interface clock each runs out at.
// Turning a lifetime into a deadline is done once, where it is taken; the sweep that reads them
// compares two clock values and scales nothing. The clock is milliseconds in sixty-four bits, so the
// whole 32-bit range the fields can name is reachable and nothing is rounded to a second.
typedef struct
{
    uint8_t addr[IDEMIP_IP6_ADDR_LEN];
    uint32_t preferred_s;
    uint32_t valid_s;
    IdemIpMs valid_at;
    IdemIpMs preferred_at;
    uint8_t state;
    uint8_t pad[(1u << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT) -
                (IDEMIP_IP6_ADDR_LEN + (2u * 4u) + (2u * sizeof(IdemIpMs)) + 1u)];
} NetifAddr6Entry;

static_assert(sizeof(NetifAddr6Entry) == (1u << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT),
              "a NetifAddr6Entry is not 1 << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT octets wide - raise the shift in "
              "idemip_config.h");

// The sweep reports how many addresses it moved in one octet, so the whole table has to fit one.
static_assert((IDEMIP_NETIF_COUNT * IDEMIP_IP6_ADDRESSES) <= 255u,
              "NetifIo::aged counts the addresses one sweep moved in a uint8_t - lower "
              "IDEMIP_NETIF_COUNT or IDEMIP_IP6_ADDRESSES");

#endif // IDEMIP_ENABLE_IPV6

// The caller's borrow, split: the operand block, the context, the interface table, then the IPv6
// addresses. netif.h publishes the offsets; the asserts below prove the span covers them and that
// each table starts aligned before anything runs.
static_assert(IDEMIP_NETIF_OFF_CTX + sizeof(NetifCtx) <= IDEMIP_NETIF_CTX_BYTES,
              "IDEMIP_NETIF_CTX_BYTES is short of the operand block and the context - raise it in idemip_config.h");
static_assert(IDEMIP_NETIF_OFF_END <= IDEMIP_NETIF_BORROW,
              "IDEMIP_NETIF_BORROW is short of the operand block, the context and both tables - raise "
              "IDEMIP_NETIF_CTX_BYTES in idemip_config.h");
static_assert(((IDEMIP_NETIF_OFF_TAB | IDEMIP_NETIF_OFF_ADDR6) & (IDEMIP_ALIGN - 1u)) == 0u,
              "a table does not start on IDEMIP_ALIGN: entry i sits at (i << SHIFT) from it");

// The regions, at their offsets in the caller's borrow.
#define NETIF_IO(w) IDEMIP_NETIF_IO(w)
#define NETIF_CTX(w) ((NetifCtx *)(void *)((w) + IDEMIP_NETIF_OFF_CTX))
#define NETIF_AT(w, i) ((NetifEntry *)(void *)((w) + IDEMIP_NETIF_OFF_TAB + ((size_t)(i) << IDEMIP_NETIF_ENTRY_SHIFT)))
#if IDEMIP_ENABLE_IPV6
#define NETIF_ADDR6_AT(w, i, s)                                                                                        \
    ((NetifAddr6Entry *)(void *)((w) + IDEMIP_NETIF_OFF_ADDR6 +                                                         \
                                 ((((size_t)(i) * IDEMIP_IP6_ADDRESSES) + (size_t)(s))                                 \
                                  << IDEMIP_NETIF_ADDR6_ENTRY_SHIFT)))
#endif

// --- the address forms an interface may not hold ---------------------------

// RFC 1122 sec 3.2.1.3 case (c) { -1, -1 }, "Limited broadcast. It MUST NOT be used as a source
// address."
#define NETIF_IP4_LIMITED_BROADCAST 0xFFFFFFFFu

// RFC 1122 sec 3.2.1.3 case (g) { 127, <any> }, "Internal host loopback address."
#define NETIF_IP4_LOOPBACK_NET 0x7F000000u
#define NETIF_IP4_LOOPBACK_PREFIX 0xFF000000u

// RFC 1112 sec 4: host groups are "class D IP addresses, i.e., those with '1110' as their high-order
// four bits".
#define NETIF_IP4_MULTICAST_NET 0xE0000000u
#define NETIF_IP4_MULTICAST_PREFIX 0xF0000000u

// RFC 4291 sec 2.7: "binary 11111111 at the start of the address identifies the address as being a
// multicast address."
#define NETIF_IP6_MULTICAST_OCTET 0xFFu

// --- what a value means ----------------------------------------------------

// RFC 1112 sec 4, the high-order four bits "1110".
static idemip_bool netif_ip4_multicast(uint32_t addr)
{
    return ((addr & NETIF_IP4_MULTICAST_PREFIX) == NETIF_IP4_MULTICAST_NET) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// The high-order three bits "111": RFC 1112 sec 4's class D and the class E above it, "those with
// '1111' as their high-order four bits, are reserved for future addressing modes". RFC 6890 Table 15
// gives 240.0.0.0/4 Source False and Destination False, so neither block is an interface's own.
static idemip_bool netif_ip4_reserved(uint32_t addr)
{
    return ((addr & NETIF_IP4_MULTICAST_NET) == NETIF_IP4_MULTICAST_NET) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 1122 sec 3.2.1.3 case (g), the 127 network.
static idemip_bool netif_ip4_loopback(uint32_t addr)
{
    return ((addr & NETIF_IP4_LOOPBACK_PREFIX) == NETIF_IP4_LOOPBACK_NET) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// The forms RFC 1122 sec 3.2.1.3 bars from an interface's own address: (c) the limited broadcast,
// (d) and (e) the directed broadcast the mask names, a class D multicast, an address whose
// <Host-number> field is all zeros, and (g) the 127 net on an interface that is not the loopback,
// those addresses "MUST NOT appear outside a host". The section reads "When a host sends any
// datagram, the IP source address MUST be one of its own IP addresses (but not a broadcast or
// multicast address)", and "IP addresses are not permitted to have the value 0 or -1 for any of the
// <Host-number>, <Network-number>, or <Subnet-number> fields (except in the special cases listed
// above)". { 0, 0 } is one of those cases, "a source address as part of an initialization procedure
// by which the host learns its own IP address", so it is left through.
static idemip_bool netif_addr4_barred(uint32_t addr, uint32_t mask, uint16_t flags)
{
    if (addr == NETIF_IP4_LIMITED_BROADCAST || netif_ip4_reserved(addr))
    {
        return IDEMIP_TRUE;
    }
    if (netif_ip4_loopback(addr) && (flags & (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK) == 0u)
    {
        return IDEMIP_TRUE;
    }
    if ((~mask) != 0u && addr != 0u)
    {
        if ((addr & ~mask) == (~mask) || (addr & ~mask) == 0u)
        {
            return IDEMIP_TRUE;
        }
    }
    // The <Network-number> half of the same sentence, which the host half above leaves. { 0, 0 } is
    // the initialization case and stays through, and a mask with no host field at all is a single
    // host address whose prefix is the address itself, which this rule does not reach.
    if (mask != 0u && (~mask) != 0u && addr != 0u)
    {
        if ((addr & mask) == 0u || (addr & mask) == mask)
        {
            return IDEMIP_TRUE;
        }
    }
    return IDEMIP_FALSE;
}

#if IDEMIP_ENABLE_IPV6

// RFC 4291 sec 2.5.2, the unspecified address "must never be assigned to any node".
static idemip_bool netif_ip6_unspecified(const uint8_t *addr)
{
    for (uint8_t i = 0u; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        if (addr[i] != 0u)
        {
            return IDEMIP_FALSE;
        }
    }
    return IDEMIP_TRUE;
}

// RFC 4291 sec 2.5.3, the loopback address 0:0:0:0:0:0:0:1 "must not be assigned to any physical
// interface".
static idemip_bool netif_ip6_loopback(const uint8_t *addr)
{
    for (uint8_t i = 0u; i < (IDEMIP_IP6_ADDR_LEN - 1u); i++)
    {
        if (addr[i] != 0u)
        {
            return IDEMIP_FALSE;
        }
    }
    return (addr[IDEMIP_IP6_ADDR_LEN - 1u] == 1u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

static idemip_bool netif_ip6_same(const uint8_t *a, const uint8_t *b)
{
    for (uint8_t i = 0u; i < IDEMIP_IP6_ADDR_LEN; i++)
    {
        if (a[i] != b[i])
        {
            return IDEMIP_FALSE;
        }
    }
    return IDEMIP_TRUE;
}

// The forms an address slot may not hold: RFC 4291 sec 2.5.2's unspecified address, sec 2.7's
// multicast form, whose 8 leading bits are all ones, and sec 2.5.3's loopback address on an
// interface that is not the loopback. The slot carries the RFC 4862 sec 2 states, which sec 5.4
// reaches through Duplicate Address Detection, "performed on all unicast addresses prior to
// assigning them to an interface", so a group address has no state here to hold.
static idemip_bool netif_addr6_barred(const uint8_t *addr, uint16_t flags)
{
    if (netif_ip6_unspecified(addr) || addr[0] == NETIF_IP6_MULTICAST_OCTET)
    {
        return IDEMIP_TRUE;
    }
    return (netif_ip6_loopback(addr) && (flags & (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK) == 0u) ? IDEMIP_TRUE
                                                                                             : IDEMIP_FALSE;
}

// RFC 4861 sec 4.6.2 states both lifetimes in seconds, and "A value of all one bits (0xffffffff)
// represents infinity", which never expires. Every other value the field can hold is a finite number
// of seconds, which the millisecond clock reaches all of. The deadline is taken once, here, so the
// sweep that reads it scales nothing.
#define NETIF_DEADLINE_NEVER UINT64_MAX

static IdemIpMs netif_deadline(IdemIpMs now, uint32_t lifetime_s)
{
    return (lifetime_s == IDEMIP_NETIF_LIFETIME_INFINITE) ? (IdemIpMs)NETIF_DEADLINE_NEVER
                                                          : (now + idemip_ms_from_s(lifetime_s));
}

// RFC 4862 sec 5.4.5: a duplicate address "MUST NOT be assigned to an interface". sec 5.4: a
// tentative one "is not considered 'assigned to an interface' in the traditional sense", and only
// the sec 5.4.3 Target Address match may see it.
static idemip_bool netif_addr6_assigned(uint8_t state, idemip_bool tentative)
{
    if (state == (uint8_t)IDEMIP_NETIF_ADDR6_PREFERRED || state == (uint8_t)IDEMIP_NETIF_ADDR6_DEPRECATED)
    {
        return IDEMIP_TRUE;
    }
    return (tentative && state == (uint8_t)IDEMIP_NETIF_ADDR6_TENTATIVE) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// Zeroes one interface's run of the address table, which leaves every slot holding
// IDEMIP_NETIF_ADDR6_INVALID, RFC 4862 sec 2's "address that is not assigned to any interface".
static void netif_drop_addr6(uint8_t *restrict work, uint8_t index)
{
    for (uint8_t s = 0u; s < IDEMIP_IP6_ADDRESSES; s++)
    {
        memset(NETIF_ADDR6_AT(work, index, s), 0, sizeof(NetifAddr6Entry));
    }
}

#endif // IDEMIP_ENABLE_IPV6

// --- the statics the entries delegate to -----------------------------------

// Zeroes the interface entry and every IPv6 address on it, then writes the link, the RFC 894 48-bit
// address and the MTU. A rebind therefore lands in the state its operands alone name.
static void netif_bind_at(uint8_t *restrict work, uint8_t index)
{
    NetifIo *io = NETIF_IO(work);
    NetifEntry *entry = NETIF_AT(work, index);
    memset(entry, 0, sizeof(*entry));
    entry->phy = io->bind_args.phy;
    memcpy(entry->hwaddr, io->bind_args.hwaddr, IDEMIP_MAC_LEN);
    entry->mtu = io->bind_args.mtu;
#if IDEMIP_ENABLE_IPV6
    netif_drop_addr6(work, index);
#endif
}

// Zeroes the interface entry and every IPv6 address on it, leaving a null link, which every other
// entry reads as unbound.
static void netif_unbind_at(uint8_t *restrict work, uint8_t index)
{
    memset(NETIF_AT(work, index), 0, sizeof(NetifEntry));
#if IDEMIP_ENABLE_IPV6
    netif_drop_addr6(work, index);
#endif
}

// Copies one interface's whole record into the operand block. hwaddr points at the entry's own
// octets in this borrow.
static void netif_report(uint8_t *restrict work, uint8_t index)
{
    NetifIo *io = NETIF_IO(work);
    const NetifEntry *entry = NETIF_AT(work, index);
    io->phy = entry->phy;
    io->hwaddr = entry->hwaddr;
    io->addr = entry->addr;
    io->mask = entry->mask;
    io->gw = entry->gw;
    io->mtu = entry->mtu;
    io->mtu6 = entry->mtu6;
    io->flags = entry->flags;
    io->chksum = entry->chksum;
    io->index = index;
}

// RFC 1122 sec 3.2.1.3 (a): "{ 0, 0 } This host on this network. MUST NOT be sent, except as a
// source address as part of an initialization procedure by which the host learns its own IP
// address." A bound interface is zeroed until set_addr4 gives it one, so 0.0.0.0 is the address it
// does not have rather than an address it holds.
static idemip_bool netif_has_addr4(const NetifEntry *entry)
{
    return (entry->phy != NULL && entry->addr != 0u) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

// RFC 1122 sec 3.3.1.1 (b): "If the IP destination address bits extracted by the address mask match
// the IP source address bits extracted by the same mask, then the destination is on the
// corresponding connected network". The same section's special cases, "For a limited broadcast or a
// multicast address, simply pass the datagram to the link layer for the appropriate interface", are
// on the link without extracting anything, which is the form an address this host does not have yet
// still sends. An interface with no address extracts no bits, so nothing else is on its link.
static idemip_bool netif_on_link(const NetifEntry *entry, uint32_t dst)
{
    if (dst == NETIF_IP4_LIMITED_BROADCAST || netif_ip4_multicast(dst))
    {
        return IDEMIP_TRUE;
    }
    if (!netif_has_addr4(entry))
    {
        return IDEMIP_FALSE;
    }
    return ((dst & entry->mask) == (entry->addr & entry->mask)) ? IDEMIP_TRUE : IDEMIP_FALSE;
}

#if IDEMIP_ENABLE_IPV6

// Copies one address slot into the operand block. addr6 points at the slot's own octets in this
// borrow.
static void netif_report_addr6(uint8_t *restrict work, uint8_t index, uint8_t slot)
{
    NetifIo *io = NETIF_IO(work);
    const NetifAddr6Entry *addr6 = NETIF_ADDR6_AT(work, index, slot);
    io->addr6 = addr6->addr;
    io->preferred_s = addr6->preferred_s;
    io->valid_s = addr6->valid_s;
    io->addr6_state = (IdemIpNetifAddr6State)addr6->state;
    io->index = index;
    io->slot = slot;
}

// RFC 4862 sec 5.5.4: "A preferred address becomes deprecated when its preferred lifetime expires",
// and "An address (and its association with an interface) becomes invalid when its valid lifetime
// expires". An invalidated slot is zeroed, which returns it to IDEMIP_NETIF_ADDR6_INVALID and so to
// the free list. The valid lifetime retires a slot in any state; the preferred lifetime deprecates
// only one the RFC names preferred.
static uint8_t netif_age_addr6(uint8_t *restrict work, uint32_t now_ms)
{
    NetifCtx *ctx = NETIF_CTX(work);
    // The caller's 32-bit reading, extended across its wrap into the one clock every deadline sits
    // on. Reaching a deadline is one comparison of two clock values: nothing is scaled here.
    IdemIpMs now = idemip_ms_extend(&ctx->tick_ms, &ctx->tick_hi, now_ms);

    uint8_t moved = 0u;
    for (uint8_t i = 0u; i < IDEMIP_NETIF_COUNT; i++)
    {
        for (uint8_t s = 0u; s < IDEMIP_IP6_ADDRESSES; s++)
        {
            NetifAddr6Entry *addr6 = NETIF_ADDR6_AT(work, i, s);
            if (addr6->state == (uint8_t)IDEMIP_NETIF_ADDR6_INVALID)
            {
                continue;
            }
            if (now >= addr6->valid_at)
            {
                memset(addr6, 0, sizeof(*addr6));
                moved = (uint8_t)(moved + 1u);
                continue;
            }
            if (addr6->state == (uint8_t)IDEMIP_NETIF_ADDR6_PREFERRED && now >= addr6->preferred_at)
            {
                addr6->state = (uint8_t)IDEMIP_NETIF_ADDR6_DEPRECATED;
                moved = (uint8_t)(moved + 1u);
            }
        }
    }
    return moved;
}

#endif // IDEMIP_ENABLE_IPV6

// --- the entries -----------------------------------------------------------

// Zeroes the context and both tables, then stamps the context. A zeroed interface holds a null phy
// and a zeroed address table holds IDEMIP_NETIF_ADDR6_INVALID in every slot, which is the state
// every other entry reads as empty. The operand block is the caller's and is left alone.
static void netif_clear(uint8_t *restrict work)
{
    if (!work)
    {
        return; // no borrow, so nowhere to report
    }
    memset(work + IDEMIP_NETIF_OFF_CTX, 0, (size_t)IDEMIP_NETIF_OFF_END - (size_t)IDEMIP_NETIF_OFF_CTX);
    NETIF_CTX(work)->ready = NETIF_READY;
    NETIF_IO(work)->status = IDEMIP_OK;
}

// RFC 894 bounds the data field: "the maximum length of an IP datagram sent over an Ethernet is 1500
// octets". An MTU outside that, a missing link and a missing hardware address are all ERR: no retry
// turns any of them into a frame this link can carry.
static void netif_bind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->bind_args.index >= IDEMIP_NETIF_COUNT ||
        io->bind_args.hwaddr == NULL || io->bind_args.phy == NULL)
    {
        return;
    }
    if (io->bind_args.mtu == 0u || io->bind_args.mtu > IDEMIP_ETH_MAX_PAYLOAD)
    {
        return;
    }
    netif_bind_at(work, io->bind_args.index);
    io->status = IDEMIP_OK;
}

// RFC 4862 sec 2, an invalid address "is not assigned to any interface". An index inside the table
// is dropped whether or not it held a link, so the entry ends where the call names either way.
static void netif_unbind(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->if_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    netif_unbind_at(work, io->if_args.index);
    io->status = IDEMIP_OK;
}

// RFC 1122 sec 3.3.1.6 makes the IP address, the address mask and the gateway configurable.
// RFC 1122 sec 3.2.1.3 bars the broadcast, multicast and loopback forms from an interface's own
// address, and a barred form is ERR: no retry makes it a legal source address.
static void netif_set_addr4(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->addr4_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    NetifEntry *entry = NETIF_AT(work, io->addr4_args.index);
    if (entry->phy == NULL)
    {
        return;
    }
    if (netif_addr4_barred(io->addr4_args.addr, io->addr4_args.mask, entry->flags))
    {
        return;
    }
    entry->addr = io->addr4_args.addr;
    entry->mask = io->addr4_args.mask;
    entry->gw = io->addr4_args.gw;
    io->status = IDEMIP_OK;
}

// RFC 4861 sec 6.3.4: "hosts SHOULD copy the option's value into LinkMTU so long as the value is
// greater than or equal to the minimum link MTU [IPv6] and does not exceed the maximum LinkMTU value
// specified in the link-type-specific document". The floor is RFC 8200 sec 5's 1280 octets, the
// ceiling is the MTU bind took for this link. Outside that the value is ERR: it is the option's own
// value and no later tick changes it.
static void netif_set_mtu(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->if_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    NetifEntry *entry = NETIF_AT(work, io->if_args.index);
    if (entry->phy == NULL || io->if_args.mtu < IDEMIP_IPV6_MIN_MTU || io->if_args.mtu > entry->mtu)
    {
        return;
    }
    entry->mtu6 = io->if_args.mtu;
    io->status = IDEMIP_OK;
}

// RFC 1122 sec 3.2.1.3 broadcast forms and RFC 1112 group membership run per interface, so the flags
// that say which the link carries are one word on the entry. The raised bits go up, then the cleared
// bits come down, so a bit named in both ends down.
static void netif_set_flags(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->if_args.index >= IDEMIP_NETIF_COUNT ||
        (io->if_args.set & (uint16_t)~IDEMIP_NETIF_FLAG_MASK) != 0u ||
        (io->if_args.clear & (uint16_t)~IDEMIP_NETIF_FLAG_MASK) != 0u)
    {
        return;
    }
    NetifEntry *entry = NETIF_AT(work, io->if_args.index);
    if (entry->phy == NULL)
    {
        return;
    }
    const uint16_t next = (uint16_t)((entry->flags | io->if_args.set) & (uint16_t)~io->if_args.clear);
    // The loopback flag is what admitted the addresses this interface holds: RFC 1122 sec 3.2.1.3
    // case (g) says a 127 address "MUST NOT appear outside a host", and RFC 4291 sec 2.5.3 says ::1
    // "must not be assigned to any physical interface". Lowering the flag would leave those on an
    // interface with a link, so the addresses are tested against the flags they would end up under
    // and the call is refused rather than the addresses quietly becoming illegal.
    if ((next & (uint16_t)IDEMIP_NETIF_FLAG_LOOPBACK) == 0u)
    {
        if (entry->addr != 0u && netif_addr4_barred(entry->addr, entry->mask, next))
        {
            return;
        }
#if IDEMIP_ENABLE_IPV6
        for (uint8_t s = 0u; s < IDEMIP_IP6_ADDRESSES; s++)
        {
            const NetifAddr6Entry *addr6 = NETIF_ADDR6_AT(work, io->if_args.index, s);
            if (addr6->state != (uint8_t)IDEMIP_NETIF_ADDR6_INVALID && netif_addr6_barred(addr6->addr, next))
            {
                return;
            }
        }
#endif
    }
    entry->flags = next;
    io->status = IDEMIP_OK;
}

// A header whose bit is set here is left to the MAC, so RFC 1071 is not run over it.
static void netif_set_offload(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->if_args.index >= IDEMIP_NETIF_COUNT ||
        (io->if_args.chksum & (uint16_t)~IDEMIP_NETIF_CHKSUM_MASK) != 0u)
    {
        return;
    }
    NetifEntry *entry = NETIF_AT(work, io->if_args.index);
    if (entry->phy == NULL)
    {
        return;
    }
    entry->chksum = io->if_args.chksum;
    io->status = IDEMIP_OK;
}

// RFC 1122 sec 3.3.1.1 names the record a route decision reads. An entry with no link is not an
// interface, and no retry gives it one, so it is ERR.
static void netif_get(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    io->phy = NULL;
    io->hwaddr = NULL;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->if_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    if (NETIF_AT(work, io->if_args.index)->phy == NULL)
    {
        return;
    }
    netif_report(work, io->if_args.index);
    io->status = IDEMIP_OK;
}

// RFC 1122 sec 3.2.1.3, "the IP source address MUST be one of its own IP addresses". Walks the
// bound interfaces for the one holding the named address. A miss is ERR: the table is what it is,
// and no later tick puts the address on an interface.
static void netif_find4(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY)
    {
        return;
    }
    for (uint8_t i = 0u; i < IDEMIP_NETIF_COUNT; i++)
    {
        const NetifEntry *entry = NETIF_AT(work, i);
        if (netif_has_addr4(entry) && entry->addr == io->route_args.dst)
        {
            netif_report(work, i);
            io->status = IDEMIP_OK;
            return;
        }
    }
}

// RFC 1122 sec 3.3.1.1 extracts both addresses with the mask and compares them. The answer is OK
// whichever way it went, the decision itself being the result; only an entry with no mask to extract
// by is ERR.
static void netif_local4(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    io->local = IDEMIP_FALSE;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->route_args.index >= IDEMIP_NETIF_COUNT)
    {
        return;
    }
    const NetifEntry *entry = NETIF_AT(work, io->route_args.index);
    if (entry->phy == NULL)
    {
        return;
    }
    io->local = netif_on_link(entry, io->route_args.dst);
    io->status = IDEMIP_OK;
}

#if IDEMIP_ENABLE_IPV6

// RFC 4862 sec 5.4 starts an address tentative, sec 2 orders the two lifetimes: "The valid lifetime
// must be greater than or equal to the preferred lifetime". An address already on the interface is
// rewritten in its slot, which is what RFC 4862 sec 5.5.3 e) does to a lifetime a later
// advertisement revises. A table with no free slot is BUSY: RFC 4862 sec 5.5.4 invalidates a slot
// when its valid lifetime expires, so a later tick frees one.
static void netif_add_addr6(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->addr6_args.index >= IDEMIP_NETIF_COUNT ||
        io->addr6_args.addr == NULL || io->addr6_args.state == IDEMIP_NETIF_ADDR6_INVALID ||
        io->addr6_args.state > IDEMIP_NETIF_ADDR6_DUPLICATE || io->addr6_args.valid_s < io->addr6_args.preferred_s)
    {
        return;
    }
    const NetifEntry *entry = NETIF_AT(work, io->addr6_args.index);
    if (entry->phy == NULL || netif_addr6_barred(io->addr6_args.addr, entry->flags))
    {
        return;
    }

    uint8_t slot = (uint8_t)IDEMIP_IP6_ADDRESSES;
    for (uint8_t s = 0u; s < IDEMIP_IP6_ADDRESSES; s++)
    {
        const NetifAddr6Entry *held = NETIF_ADDR6_AT(work, io->addr6_args.index, s);
        if (held->state != (uint8_t)IDEMIP_NETIF_ADDR6_INVALID && netif_ip6_same(held->addr, io->addr6_args.addr))
        {
            slot = s;
            break;
        }
        if (held->state == (uint8_t)IDEMIP_NETIF_ADDR6_INVALID && slot == (uint8_t)IDEMIP_IP6_ADDRESSES)
        {
            slot = s;
        }
    }
    if (slot >= IDEMIP_IP6_ADDRESSES)
    {
        io->status = IDEMIP_BUSY;
        return;
    }

    NetifAddr6Entry *addr6 = NETIF_ADDR6_AT(work, io->addr6_args.index, slot);
    memcpy(addr6->addr, io->addr6_args.addr, IDEMIP_IP6_ADDR_LEN);
    addr6->preferred_s = io->addr6_args.preferred_s;
    addr6->valid_s = io->addr6_args.valid_s;
    const IdemIpMs now = idemip_ms_join(NETIF_CTX(work)->tick_hi, NETIF_CTX(work)->tick_ms);
    addr6->valid_at = netif_deadline(now, io->addr6_args.valid_s);
    addr6->preferred_at = netif_deadline(now, io->addr6_args.preferred_s);
    addr6->state = (uint8_t)io->addr6_args.state;
    netif_report_addr6(work, io->addr6_args.index, slot);
    io->status = IDEMIP_OK;
}

// RFC 4862 sec 2, an invalid address "is not assigned to any interface", so the slot is zeroed back
// to it. An address the interface does not hold is ERR: the table holds what it holds, and no retry
// changes the answer.
static void netif_remove_addr6(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->addr6_args.index >= IDEMIP_NETIF_COUNT ||
        io->addr6_args.addr == NULL)
    {
        return;
    }
    for (uint8_t s = 0u; s < IDEMIP_IP6_ADDRESSES; s++)
    {
        NetifAddr6Entry *addr6 = NETIF_ADDR6_AT(work, io->addr6_args.index, s);
        if (addr6->state != (uint8_t)IDEMIP_NETIF_ADDR6_INVALID && netif_ip6_same(addr6->addr, io->addr6_args.addr))
        {
            memset(addr6, 0, sizeof(*addr6));
            io->index = io->addr6_args.index;
            io->slot = s;
            io->status = IDEMIP_OK;
            return;
        }
    }
}

// RFC 4862 sec 5.4.3 matches a Target Address against the interface's own addresses. Walks every
// interface's slots. A miss is ERR for the same reason find4's is.
//
// A duplicate address is not one of them: sec 5.4.5 says one "MUST NOT be assigned to an interface".
// Nor is a tentative one, which sec 5.4 says "is not considered 'assigned to an interface' in the
// traditional sense" and whose other packets "should be silently discarded"; the Target Address match
// sec 5.4.3 does want it, so that arrives through @ref NetifAddr6Args::tentative.
static void netif_find_addr6(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    io->addr6 = NULL;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->addr6_args.addr == NULL)
    {
        return;
    }
    for (uint8_t i = 0u; i < IDEMIP_NETIF_COUNT; i++)
    {
        if (NETIF_AT(work, i)->phy == NULL)
        {
            continue;
        }
        for (uint8_t s = 0u; s < IDEMIP_IP6_ADDRESSES; s++)
        {
            const NetifAddr6Entry *addr6 = NETIF_ADDR6_AT(work, i, s);
            if (!netif_addr6_assigned(addr6->state, io->addr6_args.tentative))
            {
                continue;
            }
            if (netif_ip6_same(addr6->addr, io->addr6_args.addr))
            {
                netif_report_addr6(work, i, s);
                io->status = IDEMIP_OK;
                return;
            }
        }
    }
}

// RFC 4862 sec 2 names the state and the two lifetimes an assigned address carries. A slot holding
// IDEMIP_NETIF_ADDR6_INVALID carries none of them, so it is ERR.
static void netif_get_addr6(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    io->addr6 = NULL;
    if (NETIF_CTX(work)->ready != NETIF_READY || io->addr6_args.index >= IDEMIP_NETIF_COUNT ||
        io->addr6_args.slot >= IDEMIP_IP6_ADDRESSES)
    {
        return;
    }
    if (NETIF_ADDR6_AT(work, io->addr6_args.index, io->addr6_args.slot)->state ==
        (uint8_t)IDEMIP_NETIF_ADDR6_INVALID)
    {
        return;
    }
    netif_report_addr6(work, io->addr6_args.index, io->addr6_args.slot);
    io->status = IDEMIP_OK;
}

// RFC 4862 sec 5.5.4, "A preferred address becomes deprecated when its preferred lifetime expires".
// The sweep is the whole table, and the millisecond it ran at is kept so a later add ages from it.
static void netif_tick(uint8_t *restrict work)
{
    if (!work)
    {
        return;
    }
    NetifIo *io = NETIF_IO(work);
    io->status = IDEMIP_ERR;
    io->aged = 0u;
    if (NETIF_CTX(work)->ready != NETIF_READY)
    {
        return;
    }
    // tick_ms is advanced by the sweep itself, by whole seconds only, so the sub-second remainder is
    // carried to the next call rather than dropped here.
    io->aged = netif_age_addr6(work, io->tick_args.now_ms);
    io->status = IDEMIP_OK;
}

#endif // IDEMIP_ENABLE_IPV6

const NetifNs Netif = {.clear = netif_clear,
                       .bind = netif_bind,
                       .unbind = netif_unbind,
                       .set_addr4 = netif_set_addr4,
                       .set_mtu = netif_set_mtu,
                       .set_flags = netif_set_flags,
                       .set_offload = netif_set_offload,
                       .get = netif_get,
                       .find4 = netif_find4,
                       .local4 = netif_local4,
#if IDEMIP_ENABLE_IPV6
                       .add_addr6 = netif_add_addr6,
                       .remove_addr6 = netif_remove_addr6,
                       .find_addr6 = netif_find_addr6,
                       .get_addr6 = netif_get_addr6,
                       .tick = netif_tick
#endif
};

IDEMIP_END_DECLS
