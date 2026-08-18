# idemIP: design and build plan

Status: design settled. Awaiting `ultracode`. Nothing in `idemIP/` has been modified yet.

Full TCP/IP, v4 and v6, everything in scope. All storage is caller-provided and statically sized.
Nothing is computed at runtime that can be computed at compile time. No allocation of any kind.

---

## 1. What exists today

`idemIP/` is 13 headers and one `.c`, 1572 lines: constants, field offsets, and `static inline`
accessors over the caller's bytes. That layer is sound and stays. Two blockers:

1. **Not self-contained.** Every file includes `protocore_config.h` and uses `PROTOCORE_*` /
   `proto_bool`. None of that is in this tree.
2. **`ethernet/phy.c:17` is `static IdemIpPhyCtx s_phy;`** which is the internal RAM the design
   forbids.

Nothing above the header-parse layer exists. No build, no tests.

---

## 2. The base: `idemIP/idemip_config.h`

One new file replaces the external dependency. libc includes are permitted, so this uses them
rather than hand-rolling:

```c
#include <stdint.h>   // fixed-width types
#include <stddef.h>   // size_t, NULL, offsetof
#include <string.h>   // memcpy, memset, memcmp
#include <assert.h>   // static_assert
```

**No allocation.** No `malloc`, `calloc`, `realloc`, `free`, `alloca`, or VLA, anywhere, ever.
That is the one libc line that does not move.

Rename table:

| ProtoCore name | idemIP name |
| --- | --- |
| `PROTOCORE_BEGIN_DECLS` / `_END_DECLS` | `IDEMIP_BEGIN_DECLS` / `IDEMIP_END_DECLS` |
| `PROTOCORE_INLINE` | `IDEMIP_INLINE` |
| `PROTO_ENUM_PACKED` | `IDEMIP_ENUM_PACKED` |
| `proto_bool` / `PROTO_TRUE` / `PROTO_FALSE` | `idemip_bool` / `IDEMIP_TRUE` / `IDEMIP_FALSE` |
| guard `PROTOCORE_IDEMIP_ARP_H` | guard `IDEMIP_ARP_H` |
| banner `ProtoCore v1.0.16` | banner `idemIP v0.1.0` |

`idemip_config.h` also holds every count and every tunable, each `#ifndef`-guarded.

---

## 3. Storage model

### 3.1 The four rules

1. **Every count is a compile-time constant.** `IDEMIP_ARP_ENTRIES`, `IDEMIP_TCP_PCBS`, and the
   rest come from `idemip_config.h`. No unit ever receives a count at runtime, and no unit ever
   computes one. There is no sizing arithmetic on any path.
2. **Every offset is a compile-time constant, and the map is public.** Each unit publishes its
   full borrow map in its header as `IDEMIP_X_OFF_*` macros. A reader can see exactly where every
   region sits without opening the `.c`. The region *types* stay private; only the map is public.
3. **No local buffers.** No array with automatic storage duration anywhere in `idemIP/`. Every
   scratch byte comes from a mapped `IDEMIP_X_OFF_SCRATCH` region in the caller's borrow. Scalar
   locals are fine; arrays are not.
4. **Config arrives as a `const` pointer or a constant.** A unit that needs configuration takes
   `const IdemIpXCfg *cfg`, pointing at a caller-owned `static const` struct in rodata. Each unit
   declares its own config struct; there are as many as there are units.

The caller's storage is one `static` array per unit, so the whole footprint is `.bss`, sized and
placed at link time.

### 3.2 The canonical form is the sha256 golden

`ProtoCore/src/crypto/hash/sha256.{h,c}` is the shape. An earlier draft of this plan proposed an
`init()` that returns an opaque handle holding a pointer to the storage. That is the shape this
codebase already migrated away from, and `tools/dev_env/pimpl.py` names the fault: it "hands every
entry a `struct <X>Internal *ctx` that holds a pointer to the module's storage ... so the state is
a file-static the entry reaches through two indirections and **nothing proves any span covers
it**." The golden proves coverage with a `static_assert` and needs no runtime check at all.

The golden, stated:

- **One exported symbol per module**, its namespace. No handle type, no context object.
- **The borrow is passed to every entry and never held.**
  `void (*const entry)(uint8_t *restrict work)`. sha256.h: work "arrives `restrict` and is not
  held past the call, so nothing here aliases it".
- **The borrow is the instance.** "The borrow IS the digest, so two running hashes are two borrows
  and never collide." N interfaces and N pcbs are N borrows over one set of entries, with no
  instance table anywhere.
- **Operands and results ride on the namespace**, not the signature.
- **Entries are thin.** Null-check, set `ok`, delegate to a static. All logic lives in statics that
  take `work` and derive their regions once at the top.

Header, `idemIP/arp/arp_table.h`:

```c
/** @brief What an insert takes. */
typedef struct
{
    uint32_t ip;
    const uint8_t *mac; ///< IDEMIP_MAC_LEN bytes
} ArpAddArgs;

/** @brief What a lookup takes. */
typedef struct
{
    uint32_t ip;
} ArpFindArgs;

/**
 * @brief The RFC 826 translation table.
 *
 *   ArpTable.clear(work);
 *   ArpTable.add_args.ip = spa;
 *   ArpTable.add_args.mac = sha;
 *   ArpTable.add(work);
 *
 * @c work is IDEMIP_ARP_BORROW bytes the CALLER took, at an address it knows. It arrives
 * @c restrict and is not held past the call, so nothing here aliases it. How those bytes are
 * carved is this module's and is never named here.
 */
typedef struct
{
    ArpAddArgs add_args;
    ArpFindArgs find_args;

    idemip_bool ok;
    const uint8_t *mac; ///< what find reports

    void (*const clear)(uint8_t *restrict work);
    void (*const add)(uint8_t *restrict work);
    void (*const find)(uint8_t *restrict work);
    void (*const age)(uint8_t *restrict work);
} ArpTableNs;

/** @brief The one symbol this module exports. */
extern ArpTableNs ArpTable;
```

`IDEMIP_ARP_BORROW` is stated in `idemip_config.h`, exactly as `PROTOCORE_SHA256_BORROW` is
stated in `protocore_config.h`.

Private, `idemIP/arp/arp_table.c`:

```c
typedef struct
{
    uint32_t tick;
    uint16_t count;
} ArpCtx;

// The caller's borrow, split: the running context, then the table.
#define ARP_OFF_CTX 0u
#define ARP_OFF_TAB (ARP_OFF_CTX + sizeof(ArpCtx))
static_assert(ARP_OFF_TAB + (IDEMIP_ARP_ENTRIES << IDEMIP_ARP_ENTRY_SHIFT) <= IDEMIP_ARP_BORROW,
              "IDEMIP_ARP_BORROW is short of the context and the table - raise it in idemip_config.h");

// The regions, at their offsets in the caller's borrow.
#define ARP_CTX(w) ((ArpCtx *)(void *)((w) + ARP_OFF_CTX))
#define ARP_AT(w, i) ((ArpEntry *)(void *)((w) + ARP_OFF_TAB + ((size_t)(i) << IDEMIP_ARP_ENTRY_SHIFT)))

// A static helper derives its regions once, the way sha256_absorb does.
static void arp_insert(uint8_t *restrict work, uint32_t ip, const uint8_t *mac)
{
    ArpCtx *ctx = ARP_CTX(work);
    ...
}
```

Caller:

```c
static _Alignas(IDEMIP_ALIGN) uint8_t arp_mem[IDEMIP_ARP_BORROW];   // .bss
ArpTable.clear(arp_mem);
```

### 3.3 What the namespace costs: single-entrancy, not a lock

The namespace object is a file-scope mutable, and it is the **only** one permitted. It carries
call operands and results, never per-instance state, so the storage rule holds: two interfaces are
two borrows, not two namespaces.

It does make a module non-reentrant. `Phy.bind_args.drv = X; Phy.bind(work);` is a critical section
spanning two statements: a second caller setting `bind_args` in between leaves the first call
running on the second's operands. No atomic closes that, because the invariant spans the operands
and the call together, not a single word.

**The answer is single-entrancy, not a mutex.** An earlier draft of this plan put one mutex over
the public API. That could not be justified. The hazard needs two tasks inside the same namespace,
and nothing here needs a second task:

- The ISR touches descriptor ring indices and nothing else. It never enters a namespace.
- Every namespace call happens on the tick (sec 3.4b).
- An application runs on that same tick, either from a callback or between ticks.

So the call graph has one entrant by construction, and because every count and every offset is a
compile-time constant, that is provable by reading the tree rather than enforced at runtime. A lock
would be paying, on every call and forever, for a race the design does not contain.

**State is disjoint by construction, so parallel workers need no synchronization for it.** This is
what the published borrow map buys beyond bounds-proving. Every unit's state is at a known offset in
a borrow the caller placed, and two borrows never alias. Worker 0 driving interface A's borrow and
worker 1 driving interface B's borrow touch different addresses, so there is nothing between them
to race: not a lock, not an atomic, not a barrier. The memory map is the proof, and it is compile
time.

That narrows the constraint considerably. It is **not** one entrant per library. It is:

| Shared between workers? | What | Needs |
| --- | --- | --- |
| No | every unit's state, in per-instance borrows at published offsets | nothing |
| No | the DMA buffers, owned by whichever borrow claimed the descriptor | nothing |
| **Yes** | a module's namespace `*_args` and result members | one entrant per namespace |
| **Yes**, ISR to tick | the descriptor ring index | one atomic word (sec 3.5) |

### 3.3a The invariant is "workers never touch each other". One thing violates it.

The rule is absolute: two workers never reach the same memory. Borrows satisfy it by construction.
The namespace `*_args` do not. `Phy.bind_args` is one object, and two workers on two disjoint
interface borrows still both write it. It is the only shared mutable in the tree, and under an
absolute invariant it cannot stay where it is.

**The fix is to move the operands and results into the borrow**, at a published offset like every
other region:

```c
// idemIP/ethernet/phy.h - the operand block, in the caller's borrow
typedef struct
{
    PhyBindArgs bind_args;
    PhyTxArgs tx_args;
    PhyRegArgs reg_args;

    IdemIpStatus status;
    IdemIpPhyLink link;
    const uint8_t *mac;
    const uint8_t *frame;
    size_t len;
    uint8_t *tx;
    uint16_t reg;
} PhyIo;

#define PHY_OFF_IO 0u
#define PHY_IO(w) ((PhyIo *)(void *)((w) + PHY_OFF_IO))

// The namespace is then entries only, and every member is const.
typedef struct
{
    void (*const bind)(uint8_t *restrict work);
    void (*const rx_claim)(uint8_t *restrict work);
    ...
} PhyNs;
extern const PhyNs Phy;
```

Caller:

```c
PHY_IO(work)->bind_args.drv = &my_driver;
PHY_IO(work)->bind_args.addr = 1u;
Phy.bind(work);
if (PHY_IO(work)->status == IDEMIP_OK) { ... }
```

What that buys, beyond the invariant:

- **Zero shared mutable state in the whole library.** Not one byte. The invariant holds absolutely
  rather than by discipline, so there is no precondition to document and no reentrancy guard to
  test.
- **The namespace becomes `const`** and lives in rodata or flash, not `.bss`. Nothing writes it
  ever.
- **"The borrow IS the instance" becomes literally complete.** Under the current shape the
  instance is the borrow *plus* a slice of shared namespace, which is the seam that made a lock
  look necessary. This closes it.
- Two workers on the same module in parallel become safe, so the last constraint disappears too.

The cost is caller syntax: `PHY_IO(work)->bind_args.drv` rather than `Phy.bind_args.drv`. Same
instruction count, since both are a constant offset from a pointer the caller already holds.

**This is not a preference. It is what the name means.**

Determinism: the same call, on the same bytes, does the same thing, always. Idempotency:
`entry(work)` is a function of `work` and nothing else, so repeating it is safe and reordering
independent operations is safe.

Operands on a shared namespace break both. `Phy.bind(work)` reading `Phy.bind_args` is not a
function of `work`: its result depends on what some other worker last wrote to a global. Same
borrow, same bytes, different outcome. That is the definition of the thing this library is named
against, and no amount of documented discipline converts it back into determinism, because
discipline is a runtime property and this design's guarantees are compile-time ones.

With the operand block in the borrow, every entry is a pure function of one pointer. Determinism
stops being a rule agreed to and becomes a fact about the type signature.

**It does depart from the sha256 golden, and that departure is stated rather than hidden.**
ProtoCore's golden puts args on the namespace and answers the sharing with one entrant. For a hash
driven by one task that is sound. It does not survive here, because a stack has N interfaces and N
connections and the whole storage model exists to keep them from touching. Everything else about
the golden is kept exactly: one exported symbol, `uint8_t *restrict work` on every entry, published
offset map, `static_assert` proving the span, thin entries delegating to statics, no handle, no
context object. Only the operands move, and they move *into* the borrow, which is the golden's own
principle followed one step further.

The namespace also becomes fully `const` as a result, which is strictly better on a target that
puts rodata in flash: the module's only exported symbol stops occupying RAM at all.

### 3.4 goldenize does the conversion

`ProtoCore/tools/dev_env/goldenize.py` is the tool. Every agent uses it rather than hand-shaping
a module:

| Command | What it does |
| --- | --- |
| `goldenize.py scan <module.h>` | print the spec it infers, as JSON, before anything is written |
| `goldenize.py gen <spec.json>` | write the header, restructure the `.c`, rewrite call sites |
| `goldenize.py shape <files...>` | enforce the golden file shape: the config include above the gate, everything else below it |
| `goldenize.py funnel <module.c>` | move a file-static context into the borrow |
| `goldenize.py pimpl <module.h>` | convert an Internal-handle module to the golden |
| `--dry` | on every writing subcommand, print the diff and write nothing |

`funnel` is the automated fix for `ethernet/phy.c`'s `s_phy`. `shape` is the conformance gate CI
runs over the whole tree. The spec is hand-editable JSON, so a module the scanner reads wrong is
corrected by editing one file rather than by writing another script.

### 3.4 Where the arithmetic rule bites, and the answers

- **Table indexing.** Entry widths are powers of two, asserted. Index to offset is `i << SHIFT`.
- **Table walks.** Bounded by a literal constant, wrapped with a mask, never a modulo.
- **RFC 4861 random factors.** `MIN_RANDOM_FACTOR` .5 and `MAX_RANDOM_FACTOR` 1.5 are exact in
  shifts: `x >> 1` and `x + (x >> 1)`.
- **MLD Maximum Response Delay.** See sec 5.2. Resolved by storing deadlines in milliseconds, so
  no conversion exists.
- **Bounded random draws.** A value in `[0, n]` for arbitrary `n` is drawn by masking to the next
  power of two above `n` and rejecting out-of-range draws. No modulo, no divide.

### 3.4a Nothing blocks. Every entry reports a ternary, and timers drive progress.

No entry in this tree waits. Not on hardware, not on a peer, not on a lock. An entry that cannot
finish now says so and returns, and the caller comes back on a later tick.

```c
typedef enum IDEMIP_ENUM_PACKED
{
    IDEMIP_OK = 0, ///< the call finished, and any result member is set
    IDEMIP_BUSY,   ///< no progress now: nothing waiting, no room, or still in flight. Call again.
    IDEMIP_ERR,    ///< refused: a null borrow, a bad argument, or the wrong state. Do not retry.
} IdemIpStatus;
```

`status` replaces the golden's `ok` on every namespace. Three states, because three is what a
timer-driven caller acts on: go on, come back, or stop.

**A service knows why it is busy. A caller does not need to.** An empty receive ring, a full
transmit ring, and a management transaction still on the wire are all BUSY, because the caller does
the same thing for each. A unit may expose a reason member for diagnostics where it has cause to,
but no control flow branches on it.

**The line between BUSY and ERR is whether retrying can ever succeed.** This is not a stylistic
split, it is the difference between a caller that makes progress and one that spins forever.
`phy` shows both, and the distinction found a real defect in the first draft of this plan: a
transmit claim larger than an Ethernet frame can carry and a transmit ring with no room both reach
the driver as a null buffer. Reported as BUSY, the impossible one is retried forever. So `phy`
bounds the length against RFC 894 itself and answers ERR, leaving BUSY to mean only "a descriptor
will free". A `idemip_bool ok` could not express either case: it conflated an empty ring with
success, and a full ring with a bad argument.

### 3.4b Per-service queues, not a central dispatch queue

Nothing blocks, so something has to drive progress. That is a tick, and the deferred work lives
**in each service's own borrow**, not in one shared queue.

Each unit that can defer work owns its pending state at a mapped offset in its borrow, because it
already has to: the ARP pending queue, the TCP retransmit and OOSEQ queues, the reassembly holds,
the MLD and IGMP report delays, the DHCP and DNS retry timers. Each exposes a `tick` entry, and
`core/dispatch.c` calls them in a fixed order.

A single central queue was considered and is worse here. A shared queue of deferred operations has
to hold heterogeneous records, which means either a union sized by the largest argument set, which
couples every unit to every other, or a function pointer plus a `void *`, which is dynamic dispatch
and reintroduces exactly the indirection the golden shape removes. Per-service queues are static
calls in a fixed order over state each unit already owns.

The tick order is fixed and matters, because a later stage consumes what an earlier one produced:

1. **drain receive** while `Phy.rx_claim` reports OK, dispatching each frame and releasing or
   pinning its descriptor
2. **run each service's timers**, in dependency order: ARP and ND before the queues that wait on
   resolution, reassembly before the protocols that read a completed datagram
3. **flush deferred transmit**, retrying what reported BUSY on an earlier tick

`core/tick.h` is therefore not just a clock: it is the scheduler, and it is the only thing in the
tree that decides what runs when.

**Policy lives in dispatch, never in a parser.** `vlan.h` reads and writes the 802.1Q tag and
decides nothing. Dispatch holds the decisions, and each one that drops a frame bumps the MIB-II
counter that names why:

| Decision | Counter | Why that one |
| --- | --- | --- |
| the frame's VID is not this interface's | `IDEMIP_STAT_IF_IN_DISCARDS` | RFC 1213: "chosen to be discarded even though no errors had been detected". A VLAN policy drop is deliberate and the frame is intact, so it is not `IF_IN_ERRORS`. |
| a malformed or short frame | `IDEMIP_STAT_IF_IN_ERRORS` | the frame itself is bad |
| an EtherType nothing here handles | `IDEMIP_STAT_IF_IN_UNKNOWN_PROTOS` | the frame is fine and the protocol is not ours |

The 802.1Q Tag Control Information is PCP in bits 15:13, DEI in bit 12, and the 12-bit VID in bits
11:0, behind the 0x8100 TPID that sits in the EtherType field. An untagged interface accepts every
frame and reports the VID as absent; a tagged one accepts its own VID and discards the rest.

### 3.5 The DMA seam

Frames arrive by DMA into a descriptor ring, not by a copy out of the driver. This is the correct
model and it settles the mailbox question completely, but it forces four things into the design
that a copying interface would have hidden.

**The current `phy.h` interface cannot express it.** As written:

```c
proto_bool (*send)(const uint8_t *frame, size_t len);
size_t (*recv)(uint8_t *out, size_t cap);
```

`recv` copies into `out`. `send`'s contract is documented as "A frame handed to send is the
caller's until the call returns; a driver that transmits asynchronously copies or holds it
itself", and DMA transmit is asynchronous by definition, so that wording mandates a copy on every
frame in both directions. Replaced with claim/release:

```c
// Receive: the next DMA-filled frame, in place. 0 when the ring is empty.
size_t (*rx_claim)(const uint8_t **frame);
// Give the descriptor back to the DMA engine. Must follow every nonzero rx_claim.
void (*rx_release)(void);
// Transmit: a DMA-capable buffer to build into, or null when the ring is full.
uint8_t *(*tx_claim)(size_t len);
// Hand the built frame to the MAC.
idemip_bool (*tx_commit)(size_t len);
// Cache maintenance, no-ops on a part without a data cache.
void (*cache_invalidate)(const void *p, size_t len);
void (*cache_clean)(const void *p, size_t len);
```

**1. Retention pins the descriptor. The pin count is a compile-time fact, so it is proven, not
copied around.** Three places retain data past dispatch, and none may hold a pointer into a
buffer the driver is about to recycle:

- IPv4 and IPv6 reassembly, holding fragments until the datagram is complete
- the TCP out-of-order segment queue
- the ARP and ND pending-packet queues, holding a frame until resolution completes

Every one of those capacities is a compile-time constant. So the worst case, every retaining unit
simultaneously full, is a number known at build time, and the ring can be proven never to starve
rather than defended against at runtime:

```c
#define IDEMIP_MAX_PINNED_FRAMES                                     \
    (IDEMIP_IP4_REASS_FRAGS + IDEMIP_IP6_REASS_FRAGS +               \
     (IDEMIP_TCP_PCBS * IDEMIP_TCP_OOSEQ_SEGS) +                     \
     IDEMIP_ARP_PENDING + IDEMIP_ND6_PENDING)

static_assert(IDEMIP_RX_DESCRIPTORS > IDEMIP_MAX_PINNED_FRAMES,
              "the RX ring starves when every retaining unit is full; raise IDEMIP_RX_DESCRIPTORS");
```

That is strictly better than copying on retain, which an earlier draft of this plan proposed. The
objection to pinning was unbounded pin time, and that objection does not survive the counts being
compile-time: the ring is sized so that even permanent pinning of every retainable slot leaves
descriptors free. Retention is therefore zero-copy, the whole receive path is zero-copy, and the
guarantee is a `static_assert` rather than a runtime check.

A pinned descriptor is released when the retaining unit is done with it: reassembly on
completion or timeout, OOSEQ on delivery or window advance, the pending queues on resolution or
timeout. Every one of those already has a timer, so no pin outlives its unit's own bound.

**2. Cache maintenance is a correctness requirement, not an optimization.** On any part with a
data cache, Cortex-M7 and Cortex-A and ESP32-P4 among the targets, the CPU must invalidate a
receive buffer before reading it and clean a transmit buffer after writing it. Skipping either
corrupts silently and intermittently. Hence the two driver hooks above.

**3. Alignment is set by the cache line, not by the struct.** A partial cache line invalidate
clobbers whatever shares the line. DMA buffers must therefore start on a cache-line boundary and
occupy a whole number of lines. `IDEMIP_NETIF_ALIGN` becomes `IDEMIP_CACHE_LINE_BYTES`, a config
macro defaulting to 32, and the receive buffer stride rounds up to it. Every other unit's borrow
keeps its natural alignment.

**4. Ordering needs a barrier, not just an atomic.** Descriptor field writes must be visible
before the OWN bit flip that hands the descriptor to hardware. That is a release barrier around
the ownership store.

**The revised OS and platform primitive set:**

| Primitive | Why | Kind |
| --- | --- | --- |
| Atomics | the descriptor ring index, stored in the ISR and loaded in the tick. Keeps the word moving in one piece and carries the ordering. | platform |
| Memory barrier | ordering descriptor field writes before the OWN bit store that hands one to hardware | platform |
| Cache invalidate / clean | DMA buffer coherency, driver-supplied | platform |
| ~~Mutex~~ | **not needed.** It protected the namespace operands against a second caller, and there is one caller. See sec 3.3. |
| ~~Semaphore~~ | **not needed.** Nothing blocks, so nothing parks a thread. An ISR notification is a latency optimization over the tick, never a requirement. |
| ~~Mailbox~~ | **not needed.** The descriptor ring is the queue, and deferred work lives in each service's own borrow (sec 3.4b). |
| ~~Thread-local storage~~ | **not needed**, and it would break the storage rule. See sec 8.1a. |

**idemIP requires no OS primitive at all.** All three that remain are platform facts about DMA
hardware: what the ISR and the tick share is one ring index, and an atomic store and load over it
is the whole of the concurrency. There is no lock, no queue object, no per-thread state, and no
scheduler dependency. The library runs from a bare `while (1)` with a millisecond clock.

The concurrency surface is small enough to enumerate, which is the point: **one word**, shared
between exactly two contexts, in one direction.

---

## 4. Module map

`[K]` keep and rename. `[F]` finish, stateless. `[N]` new, takes a borrow.

### Layer 0, base

| File | RFC / source | State |
| --- | --- | --- |
| `idemip_config.h` | - | `[N]` no storage |
| `endian.h` | - | `[K]` |
| `checksum.h` | RFC 1071 | `[K]` |
| `common.h` | RFC 1122, 8200, 9293 | `[K]` |

### Layer 1, link

| File | RFC / source | State |
| --- | --- | --- |
| `ethernet/ethernet.h` | RFC 894 | `[F]` frame build and parse |
| `ethernet/mii.h` | IEEE 802.3 cl.22 | `[K]` |
| `ethernet/phy.h` `.c` | IEEE 802.3 cl.22 | `[N]` **delete `s_phy`**, driver into the netif borrow, **claim/release DMA interface per sec 3.5** |
| `netif/dma.h` | - | `[N]` descriptor ring, ownership protocol, cache hooks |
| `ethernet/vlan.h` | IEEE 802.1Q | `[N]` tag parse and build, PCP; no storage |
| `ethernet/ethip6.c` | RFC 2464 | `[N]` 33:33 multicast MAC, EUI-64 IID, fe80::/64 |
| `netif/netif.h` `.c` | RFC 1122 sec 3.3.1 | `[N]` **N interfaces**, addresses, MTU, flags, driver, v6 address list |
| `netif/loopif.c` | RFC 1122 sec 3.2.1.3 | `[N]` 127.0.0.1 and ::1 |

### Layer 2, IPv4

| File | RFC / source | State |
| --- | --- | --- |
| `ip/ipv4.h` | RFC 791 sec 3.1 | `[F]` header build and verify |
| `ip/ip4_addr.h` | RFC 791, RFC 1112 sec 6.4 | `[N]` classification, broadcast, 01:00:5e MAC map; no storage |
| `ip/ip4_reass.h` `.c` | RFC 791 sec 3.2, RFC 815 | `[N]` reassembly buffers, hole list |
| `ip/ip4_frag.c` | RFC 791 sec 3.2 | `[F]` writes the caller's bytes |
| `ip/ip4_route.h` `.c` | RFC 1122 sec 3.3.1 | `[N]` routing table |
| `ip/ip4_forward.c` | RFC 1812 sec 5, RFC 1122 | `[F]` forward between netifs |
| `arp/arp.h` | RFC 826 | `[F]` packet build |
| `arp/arp_table.h` `.c` | RFC 826, RFC 1122 sec 2.3.2.1 | `[N]` translation table, pending queue |
| `acd/acd.h` `.c` | RFC 5227 | `[N]` probe, announce, defend state machine |
| `autoip/autoip.h` `.c` | RFC 3927 | `[N]` 169.254/16 link-local, drives ACD |
| `icmp/icmp.h` | RFC 792 | `[K]` |
| `icmp/icmp_in.c` | RFC 792, RFC 1122 sec 3.2.2 | `[F]` echo reply, error generation |
| `igmp/igmp.h` `.c` | RFC 2236, RFC 1112, RFC 2113 | `[N]` group table, Router Alert option |

### Layer 3, IPv6

| File | RFC / source | State |
| --- | --- | --- |
| `ip/ipv6.h` | RFC 8200 | `[F]` header build, extension header walk |
| `ip/ip6_addr.h` | RFC 4291, RFC 4007 | `[N]` scopes and zones, solicited-node form; no storage |
| `ip/ip6_select.c` | RFC 6724 sec 5 | `[F]` default source and destination address selection |
| `ip/ip6_reass.h` `.c` | RFC 8200 sec 4.5 | `[N]` reassembly buffers |
| `ip/ip6_frag.c` | RFC 8200 sec 4.5 | `[F]` stateless |
| `ip/ip6_forward.c` | RFC 8200, RFC 4861 sec 8 | `[F]` forward between netifs |
| `icmp/icmpv6.h` | RFC 4443 | `[K]` |
| `icmp/icmp6_in.c` | RFC 4443 | `[F]` echo reply, error generation |
| `nd/nd6.h` `.c` | RFC 4861 sec 5.1, RFC 5942 | `[N]` neighbor + destination cache, prefix + router list |
| `nd/dad.c` | RFC 4862 sec 5.4 | `[N]` duplicate address detection, shares the nd6 borrow |
| `nd/slaac.c` | RFC 4862 | `[N]` shares the nd6 borrow |
| `nd/rdnss.c` | RFC 8106 | `[F]` recursive DNS server option, writes into the dns borrow |
| `mld/mld6.h` `.c` | RFC 2710 | `[N]` group membership table |

### Layer 4, path MTU

| File | RFC / source | State |
| --- | --- | --- |
| `pmtu/pmtu4.c` | RFC 1191 | `[F]` writes into the route table |
| `pmtu/pmtu6.c` | RFC 8201 | `[F]` writes into the nd6 destination cache |

### Layer 5, transport

| File | RFC / source | State |
| --- | --- | --- |
| `raw/raw_pcb.h` `.c` | RFC 1122 sec 3.2 | `[N]` raw IP protocol pcbs |
| `udp/udp.h` | RFC 768 | `[K]` |
| `udp/udp_pcb.h` `.c` | RFC 768, RFC 1122 sec 4.1 | `[N]` binding table |
| `udp/udplite.c` | RFC 3828 | `[F]` partial-coverage checksum |
| `tcp/tcp.h` | RFC 9293 sec 3.1 | `[F]` option walk and build |
| `tcp/tcp_opt.c` | RFC 7323, RFC 2018 | `[F]` window scale, timestamps, SACK |
| `tcp/tcp_isn.c` | RFC 6528 | `[N]` ISN generation; lwIP leaves this in contrib, it belongs in core |
| `tcp/tcp_pcb.h` `.c` | RFC 9293 sec 3.3.1 | `[N]` TCB table, listen table, send queue, OOSEQ queue |
| `tcp/tcp_in.c` | RFC 9293 sec 3.10.7, RFC 5961, RFC 1337 | `[F]` SEGMENT ARRIVES, challenge ACK, TIME-WAIT hardening |
| `tcp/tcp_out.c` | RFC 9293 sec 3.10 | `[F]` segment send |
| `tcp/tcp_timer.c` | RFC 6298, RFC 9293 sec 3.8.1, RFC 1122 sec 4.2.3.6 | `[F]` RTO, retransmit, TIME-WAIT, keepalive |
| `tcp/tcp_cc.c` | RFC 5681, RFC 3465 | `[F]` slow start, congestion avoidance, fast retransmit, ABC |

### Layer 6, services

| File | RFC / source | State |
| --- | --- | --- |
| `dhcp/dhcp4.h` `.c` | RFC 2131, RFC 2132, RFC 1542 | `[N]` lease state machine, drives ACD |
| `dhcp/dhcp6.h` `.c` | RFC 8415, RFC 3646, RFC 3736 | `[N]` stateful and stateless lease |
| `dns/dns.h` `.c` | RFC 1035, RFC 2181, RFC 5452 | `[N]` resolver, query table, answer cache |

### Layer 7, core

| File | RFC / source | State |
| --- | --- | --- |
| `core/tick.h` | - | `[N]` monotonic milliseconds in from the caller |
| `core/timeouts.h` `.c` | - | `[N]` the timeout list every unit registers into |
| `core/stats.h` `.c` | RFC 1213 | `[N]` per-protocol counters |
| `core/dispatch.h` `.c` | RFC 1122 sec 3.1 | `[N]` frame to ethertype to protocol to pcb |
| `idemip.h` | - | `[N]` the one public umbrella header |

Roughly 55 files and 22 borrows. `tools/idemip_sizes.c` prints every `IDEMIP_*_BORROW` and their
sum, so the total `.bss` cost is a single auditable number.

### 4.9 What the lwIP audit turned up

I enumerated every `.c` in `lwip_ref/src/core` and `netif`, every `LWIP_*` / `TCP_*` / `IP_*`
feature toggle in `opt.h`, and every RFC cited anywhere in the tree (79 of them). Set against the
previous draft of this plan, these were missing. Each is now in a table above.

**Security and robustness, the group that matters most:**

| Gap | RFC | Where lwIP has it |
| --- | --- | --- |
| TCP ISN generation | 6528 | `opt.h:2848`, and only as `contrib/addons/tcp_isn`. lwIP's default ISN is a plain counter. This goes in idemIP core, not an addon. |
| Blind in-window attack defense, challenge ACK | 5961 sec 3.2 | `tcp_in.c:819`, noting it "addresses CVE-2004-0230" |
| TIME-WAIT assassination | 1337 | `tcp_in.c:744` |
| DNS answer forgery resilience | 5452 | `dns.c:1239`, random XID and source port |

**Protocol coverage:**

| Gap | RFC | Note |
| --- | --- | --- |
| Address Conflict Detection | 5227 | `acd.c`. DHCP calls it via `LWIP_DHCP_DOES_ACD_CHECK`. |
| IPv4 link-local, 169.254/16 | 3927 | `autoip.c`, cooperates with DHCP per `LWIP_DHCP_AUTOIP_COOP` |
| IPv6 over Ethernet | 2464 | `ethip6.c`. Not cited by number in lwIP. Fixes 33:33 multicast MAC, EUI-64 IID, fe80::/64. |
| IPv4 multicast MAC map, 01:00:5e | 1112 sec 6.4 | needed by IGMP, was absent |
| IGMP Router Alert option | 2113 | `igmp.c:76` |
| IPv6 default address selection | 6724 sec 5 | `ip6.c:261`. Without it, source address choice on a multi-address v6 host is wrong. |
| IPv6 subnet model, on-link determination | 5942 | `ip6.c:191`, `nd6.c:1681` |
| IPv6 scoped address architecture | 4007 | `ip6_zone.h` |
| Duplicate Address Detection | 4862 sec 5.4 | was folded into slaac, now explicit |
| Appropriate Byte Counting | 3465 | `tcp_in.c:1267` slow start, `:1272` congestion avoidance |
| TCP keepalive | 1122 sec 4.2.3.6 | `LWIP_TCP_KEEPALIVE` |
| Out-of-order segment queue | 9293 | `TCP_QUEUE_OOSEQ`. A borrow region, was unnamed. |
| UDP-Lite | 3828 | `udp.c:340` |
| Raw IP pcbs | 1122 sec 3.2 | `raw.c` |
| IPv4 and IPv6 forwarding | 1812, 8200 | `IP_FORWARD`, `LWIP_IPV6_FORWARD` |
| Loopback interface | 1122 sec 3.2.1.3 | `LWIP_HAVE_LOOPIF` |
| 802.1Q VLAN | IEEE 802.1Q | `ETHARP_SUPPORT_VLAN`, `LWIP_VLAN_PCP` |
| RDNSS option | 8106 | lwIP cites 6106, which 8106 obsoletes |
| Timeout subsystem | - | `timeouts.c`. `core/tick.h` alone was not enough. |
| Per-protocol counters | 1213 | `stats.c` |
| Multiple interfaces | - | `LWIP_SINGLE_NETIF`. `phy.h` says "One interface for now"; forwarding needs N. |
| Checksum offload control | - | `LWIP_CHECKSUM_CTRL_PER_NETIF`. Real MACs compute checksums; the stack must be able to skip them per netif. |

**Deliberately still out:** PPP and its 14 RFCs, 6LoWPAN, `altcp` and its TLS shim, SNMP/MIB
agent, mDNS (RFC 6762), and the `apps/` tree. IGMPv3 (RFC 3376) and MLDv2 (RFC 3810) remain out
in favor of IGMPv2 and MLDv1, per sec 4.

**One question this audit raises that I cannot answer for you.** See sec 8.

### Explicitly out

RFC 9926 and the 6LoWPAN chain. Recorded so the reading is not repeated: RFC 9926 sec 7 requires
that "A node that implements this MUST also implement [RFC8505]", and its entire update to
RFC 4861 (sec 4) applies only when NS/NA carries an RFC 8505 registration. It does not alter
baseline ND on an Ethernet link, so leaving it out costs this stack nothing.

IGMPv3 (RFC 3376) and MLDv2 (RFC 3810) are the source-filtering successors. The plan builds
IGMPv2 and MLDv1, matching lwIP. Say if you want the v3/v2 pair instead.

---

## 5. Engineering constants

From `lwip_ref/src/include/lwip/opt.h`, `include/lwip/priv/tcp_priv.h`, `include/lwip/mld6.h`,
and `core/ipv6/mld6.c`, cited at the point of use.

| idemIP macro | Value | lwIP source |
| --- | --- | --- |
| `IDEMIP_ARP_ENTRIES` | 10 | `ARP_TABLE_SIZE` |
| `IDEMIP_ARP_MAXAGE_S` | 300 | `ARP_MAXAGE` |
| `IDEMIP_IP_REASS_MAXAGE_S` | 15 | `IP_REASS_MAXAGE` |
| `IDEMIP_IP_DEFAULT_TTL` | 255 | `IP_DEFAULT_TTL` |
| `IDEMIP_ND6_NUM_NEIGHBORS` | 10 | `LWIP_ND6_NUM_NEIGHBORS` |
| `IDEMIP_ND6_NUM_DESTINATIONS` | 10 | `LWIP_ND6_NUM_DESTINATIONS` |
| `IDEMIP_ND6_NUM_PREFIXES` | 5 | `LWIP_ND6_NUM_PREFIXES` |
| `IDEMIP_ND6_NUM_ROUTERS` | 3 | `LWIP_ND6_NUM_ROUTERS` |
| `IDEMIP_TCP_PCBS` | 5 | `MEMP_NUM_TCP_PCB` |
| `IDEMIP_TCP_LISTEN_PCBS` | 8 | `MEMP_NUM_TCP_PCB_LISTEN` |
| `IDEMIP_TCP_SEGS` | 16 | `MEMP_NUM_TCP_SEG` |
| `IDEMIP_TCP_MSS` | 536 | `TCP_MSS` |
| `IDEMIP_TCP_WND` | `(4 * MSS)` | `TCP_WND` |
| `IDEMIP_TCP_MAXRTX` | 12 | `TCP_MAXRTX` |
| `IDEMIP_TCP_SYNMAXRTX` | 6 | `TCP_SYNMAXRTX` |
| `IDEMIP_TCP_TMR_INTERVAL_MS` | 250 | `TCP_TMR_INTERVAL` |
| `IDEMIP_TCP_MSL_MS` | 60000 | `TCP_MSL` |
| `IDEMIP_MLD6_GROUPS` | 4 | `MEMP_NUM_MLD6_GROUP` |
| `IDEMIP_MLD6_TMR_INTERVAL_MS` | 100 | `MLD6_TMR_INTERVAL` |
| `IDEMIP_MLD6_JOIN_DELAY_MS` | 500 | `MLD6_JOIN_DELAYING_MEMBER_TMR_MS` |
| `IDEMIP_MLD6_HL` | 1 | `MLD6_HL` |

Counts that index a table are powers of two, or the entry width is, so indexing is a shift.

### 5.1 RFC 4861 sec 10, read in full

The web fetcher truncates a 97-page RFC before sec 10 on every URL form. Downloaded and read
locally instead. Values as printed, page 78:

| Group | Constant | Value |
| --- | --- | --- |
| Router | `MAX_INITIAL_RTR_ADVERT_INTERVAL` | 16 seconds |
| Router | `MAX_INITIAL_RTR_ADVERTISEMENTS` | 3 transmissions |
| Router | `MAX_FINAL_RTR_ADVERTISEMENTS` | 3 transmissions |
| Router | `MIN_DELAY_BETWEEN_RAS` | 3 seconds |
| Router | `MAX_RA_DELAY_TIME` | .5 seconds |
| Host | `MAX_RTR_SOLICITATION_DELAY` | 1 second |
| Host | `RTR_SOLICITATION_INTERVAL` | 4 seconds |
| Host | `MAX_RTR_SOLICITATIONS` | 3 transmissions |
| Node | `MAX_MULTICAST_SOLICIT` | 3 transmissions |
| Node | `MAX_UNICAST_SOLICIT` | 3 transmissions |
| Node | `MAX_ANYCAST_DELAY_TIME` | 1 second |
| Node | `MAX_NEIGHBOR_ADVERTISEMENT` | 3 transmissions |
| Node | `REACHABLE_TIME` | 30,000 milliseconds |
| Node | `RETRANS_TIMER` | 1,000 milliseconds |
| Node | `DELAY_FIRST_PROBE_TIME` | 5 seconds |
| Node | `MIN_RANDOM_FACTOR` | .5 |
| Node | `MAX_RANDOM_FACTOR` | 1.5 |

Every ND6 value in the lwIP table matches this, units converted. Checked, not assumed.

sec 10 closes: "The constants in this specification may be overridden by specific documents that
describe how IPv6 operates over different link layers." All are therefore `#ifndef`-guarded.

### 5.2 MLD timer: keeping lwIP's 100 ms

An earlier draft of this plan set the MLD tick to 128 ms to turn lwIP's
`maxresp_in / MLD6_TMR_INTERVAL` (`core/ipv6/mld6.c:531`) into a shift. That was working around a
problem this design does not have to create. RFC 2710 says:

> sec 3.4: "The Maximum Response Delay field ... specifies the maximum allowed delay before
> sending a responding Report, in units of milliseconds."

> sec 4: "Each timer is set to a different random value, using the highest clock granularity
> available on the node, selected from the range [0, Maximum Response Delay] with Maximum Response
> Delay as specified in the Query packet."

The RFC fixes no tick period and states the delay in milliseconds. The division exists only
because lwIP stores timers in tick units. idemIP stores each group's deadline in milliseconds and
compares against the millisecond clock, so no conversion exists at any tick period, and
`IDEMIP_MLD6_TMR_INTERVAL_MS` stays lwIP's 100. The random draw over `[0, maxresp]` uses the
mask-and-reject method from sec 3.4 above.

96 is not a power of two: it is 2^5 x 3. The nearest are 64 and 128. Neither is needed.

---

## 6. Test and tools

Modeled on `ProtoCore/test/`: Unity with a generated runner per suite.

```
idemIP_work/
  CMakeLists.txt              idemip static lib, C11
  idemIP/...                  the library
  test/
    CMakeLists.txt            Unity via FetchContent, one CTest target per suite
    harness.py                suite discovery, runner gen, size report
    vectors/rfc0791_ipv4.json RFC-derived byte vectors, one file per RFC
    support/pcap.h            golden capture writer, DLT_EN10MB
    support/dma_host.h        claim/release driver over protocore_dma_host.h
    support/cache_probe.h     recording cache_invalidate / cache_clean hooks
    unit/<layer>/test_<name>/test_<name>.c
    integration/test_loopback/
  tools/
    idemip_sizes.c            prints every _BORROW and their sum
    gen_vectors.py            builds test/vectors/*.json from RFC figures
```

Unity comes from `FetchContent_Declare` pinned to a release tag. Configure needs network once;
`FETCHCONTENT_FULLY_DISCONNECTED=ON` with a warm `_deps` cache is offline after that. Unity lands
under `build/_deps/`, outside `idemIP/`, and nothing in `idemIP/` ever includes it.

Test tiers:

1. **Vector tests.** Every constant, offset, and accessor against bytes from the RFC's own figures.
2. **Storage tests.** Per unit: short buffer refused, misaligned refused, null refused,
   exactly-sized accepted, and a canary past the end proving nothing wrote out of bounds. This is
   what makes the storage model a tested property rather than a claim.
3. **Offset map tests.** Every published `IDEMIP_X_OFF_*` asserted against the region the `.c`
   actually uses, so the public map cannot drift from the private layout.
4. **State machine tests.** ARP per RFC 826's reception algorithm, including the merge-flag rule
   and that a triplet is added only when this node is the target. TCP through every RFC 9293
   sec 3.3.2 state. ND6 through INCOMPLETE / REACHABLE / STALE / DELAY / PROBE.
5. **DMA tests, on the host.** `ProtoCore/core_setup/hal/host/protocore_dma_host.h` already
   provides the rig, and idemIP's `test/support/dma_host.h` binds the claim/release driver to it.
   What makes it usable is that the engine advances only inside `protocore_dma_hw_poll()`, so a
   test decides exactly when a transfer completes and the completion callback runs where the ISR
   would. That buys deterministic coverage of the things DMA breaks:

   - `protocore_dma_host_feed()` injects a frame; the stack must `rx_claim` it in place and
     `rx_release` it, with no copy on the dispatch path.
   - **Pin exhaustion.** Fill every retaining unit, then keep feeding. `IDEMIP_RX_DESCRIPTORS >
     IDEMIP_MAX_PINNED_FRAMES` says the ring cannot starve; this test is what proves the macro
     matches the code.
   - **Pin integrity.** The host driver's ping-pong pair (`buf[2][PROTOCORE_DMA_BUF_SIZE]`,
     `bank ^= 1`) models a completed buffer staying intact while the engine fills the other. Pin
     a fragment, poll until the bank has flipped several times, and assert the pinned bytes are
     unchanged. A stack that released too early fails here and nowhere else.
   - **Cache hook ordering.** The test driver's `cache_invalidate` / `cache_clean` record their
     calls, and the suite asserts invalidate-before-read and clean-before-commit on every frame.
     On the host these are no-ops functionally, so recording the call order is the only way this
     is checkable off silicon.
   - `cfg.loopback` gives a wired loopback for free; two channels give the two-node case.

6. **Integration.** `test_loopback` wires two instances through the DMA rig and runs ARP
   resolution, a TCP three-way handshake, data both ways, and a four-way close, writing the
   exchange to a `.pcap` openable in Wireshark.
7. **Footprint.** `idemip_sizes` output asserted against a checked-in table, so any borrow change
   is a visible diff.

**CI gates**, each a build failure:

- any file-scope mutable in `idemIP/`
- any array with automatic storage duration in `idemIP/`
- any `malloc` / `calloc` / `realloc` / `free` / `alloca` / VLA
- any `auto` in `idemIP/`
- any `/` or `%` outside a `static_assert`

---

## 7. The agentic workflow

Seven phases. `git init` is done, so fan-out phases use `isolation: 'worktree'` and each agent
works on its own copy. I read the diffs and merge to main between phases.

### 7.1 The base is built and green. Agents inherit it, they do not invent it.

Phase 0 is done, on main, before any agent runs. What exists and passes right now:

```
idemIP_work/
  CMakeLists.txt                              idemip static lib, C11, -Os + LTO on Release
  .clangd                                     points clangd at build/, so phantom errors stop
  idemIP/idemip_config.h                      every count, every constant, the pin assert
  idemIP/ethernet/phy.h  phy.c                THE GOLDEN EXAMPLE. Copy this shape.
  idemIP/...                                  13 headers, renamed off ProtoCore's vocabulary
  test/CMakeLists.txt                         Unity by FetchContent, one CTest target per suite
  test/harness.py                             suite discovery, Unity runner generation
  test/unit/base/test_checksum/               RFC 1071 vectors, 6 cases
  test/unit/ethernet/test_phy/                THE GOLDEN SUITE. Copy this shape. 15 cases.
```

Verified on this machine, this session:

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
    100% tests passed, 0 tests failed out of 2
```

Toolchain confirmed present: ruby 3.4.10, cmake 4.3.3, gcc 13.2.0, clang 22.1.7, ninja 1.12.0,
python 3.11.7, git 2.54.0.

**The feedback loop, which every agent runs before reporting anything:**

| Command | What it answers |
| --- | --- |
| `cmake --build build` | does it compile |
| `ctest --test-dir build --output-on-failure` | does it pass, and which case failed |
| `python test/harness.py suites` | every suite and its case count |
| `python test/harness.py cases <dir>` | which cases Unity registered, and which it **walked past** |
| `python ProtoCore/tools/dev_env/goldenize.py shape <files>` | is the file shape golden |

`harness.py cases` exists because a function that is not named `test_<name>` is not an error to
Unity's generator: it is never registered, so the suite passes while the case never ran. An agent
reporting "all tests pass" without checking this has reported nothing.

### 7.2 The golden example is `ethernet/phy`

Every phase-3 agent reads `idemIP/ethernet/phy.h`, `phy.c` and `test/unit/ethernet/test_phy/`
first, and produces the same shape. It is small on purpose: it carries no algorithm, so what is
visible in it is only the shape.

It demonstrates, in order: the borrow map as compile-time offsets, the `static_assert` that proves
the span covers the map, the `X_CTX(w)` region macro, thin entries that null-check and set `ok`
and delegate, the namespace with `*_args` operands and `const` function pointer entries, one
exported symbol, and the DMA claim/release contract with its cache hooks.

`test_phy` demonstrates the four things every unit's suite must check:

1. the borrow is the caller's, declared in the suite and passed to every entry
2. **every** entry refuses a null borrow
3. **two borrows do not collide**, which is the property the whole storage model rests on
4. the DMA contract is an ordering claim, so ordering is recorded and asserted

### 7.3 Standing rules injected into every agent prompt:

**This is the design. It is not a suggestion, a starting point, or a style preference. If you
cannot meet it, stop and say so. Do not work around it, do not paper over it, do not substitute
your own judgment for it.** A unit that does not meet the design and says so is useful. A unit
that does not meet the design and hides it is worse than nothing, because the forty units after
it are built on top of it.

**Shape**

- Read `idemIP/ethernet/phy.h`, `phy.c`, and `test/unit/ethernet/test_phy/` before writing a line.
  Produce that shape. Not something like it.
- One exported symbol: your namespace. No handle type. No context object. No `init()` returning a
  pointer.
- Every entry is `void (*const name)(uint8_t *restrict work)`. The borrow is passed to every call
  and never held past it.
- Publish your full borrow map in your header as compile-time `X_OFF_*` macros.
- `static_assert` that the map fits `IDEMIP_X_BORROW`. That assert is what proves the span covers
  the regions. It replaces a runtime check; do not add one.
- The borrow IS the instance. Never add an instance table, an index, or an array of contexts.
- Use `goldenize.py` rather than hand-shaping. `--dry` first, always.

**Hard bans**

- No file-scope mutable other than your one namespace object.
- No array with automatic storage duration. Scratch comes from a mapped region in the borrow.
- No allocation. No `malloc`, `calloc`, `realloc`, `free`, `alloca`, VLA.
- No `auto` in `idemIP/`. Spell the type.
- No `/` or `%` outside a `static_assert`. Shift and mask. Entry widths are powers of two.
- No runtime sizing. Every count is a compile-time macro from `idemip_config.h`.

**RFC**

- Fetch your RFC section before writing. Do not recall it. Cite section and field in the comment.
- **The web fetcher silently truncates long RFCs.** RFC 4861 cut off before sec 10 on `.txt`,
  `.html`, and the datatracker anchor. Download with `Invoke-WebRequest` to the scratchpad and
  read the section from the file. A truncated fetch is not a read; say so rather than filling the
  gap from memory.
- If the RFC and lwIP disagree, the RFC wins and you report the disagreement. lwIP is the source
  for engineering constants, not for correctness.
- If the RFC and this plan disagree, stop and report it. Do not choose.

**Honesty**

- Report only what you ran. "Measured", "verified", "confirmed", "passing" mean a command ran in
  your session and printed that. If it did not, the words are "I don't know" plus how to find out.
- Run `ctest --output-on-failure` and `harness.py cases` on your suite before reporting. A suite
  that passes because Unity walked past every case is a failure you must catch and report.
- A test you disabled, skipped, loosened, or wrote to match the code rather than the RFC is a
  finding to report, not a problem to solve quietly.
- clangd reports missing `uint8_t` and missing `idemIP/` headers without the compilation database.
  `.clangd` fixes it. Those are phantom errors: never edit source to silence them.
- Comments say what the code does and how. Nothing about why it exists.
- No em-dashes. American spelling. `const char *name`.

| Phase | Agents | Work | Isolation |
| --- | --- | --- | --- |
| 0. Base | **done** | Built and green before any agent runs. See sec 7.1. | Main |
| 1. Stateless headers | 9 | One per header: `ethernet`, `arp`, `ipv4`, `ipv6`, `ip6_addr`, `icmp`, `icmpv6`, `tcp`+`tcp_opt`, `udp`. Verify every constant and offset against the RFC, add build helpers, write the vector suite. | Worktree |
| 2. Borrow maps | 1 | Every `IDEMIP_X_OFF_*` map, `_BORROW`, config struct, `init()`, and `static_assert` block across all 18 units, with no logic. Sets the contract phase 3 compiles against. | Main |
| 3. Stateful units | 25 | One per unit: `dma`+`phy` (the claim/release driver seam and its host rig, per sec 3.5), `netif`+`loopif`, `arp_table`, `ip4_reass`, `ip4_route`+`forward`, `acd`, `autoip`, `igmp`, `ip6_reass`+`forward`, `nd6`+`dad`, `slaac`+`rdnss`, `mld6`, `ethip6`+`ip6_select`, `pmtu`, `raw_pcb`, `udp_pcb`+`udplite`, `tcp_isn`, `tcp_pcb`, `tcp_in`+`out`, `tcp_timer`+`cc`, `dhcp4`, `dhcp6`, `dns`, `timeouts`, `stats`. Implement against the phase-2 contract, plus storage, offset-map, and state-machine suites. | Worktree |
| 4. Input path | 1 | `core/dispatch.c`, `idemip.h`. Needs every final public header in one tree. | Main |
| 5. Adversarial conformance | 30 | One skeptic per unit, prompted to **refute** conformance against a freshly downloaded RFC. Six extra skeptics on the security-critical lenses, one each: RFC 6528 ISN predictability, RFC 5961 challenge ACK and CVE-2004-0230, RFC 1337 TIME-WAIT, RFC 5452 DNS forgery, RFC 5942 on-link determination, RFC 6724 source address selection. A finding must name the exact section and field or it is dropped. | Worktree, read-only |
| 6. Integration and audit | 1 | `test_loopback`, pcap goldens, `idemip_sizes` table, full `cmake --build` + `ctest`, CI gates green. Reports real pass/fail counts. | Main |

68 agents across 7 phases, 3 fan-outs. Phase 5 is where RFC correctness is established, so it
runs regardless of how clean phase 3 looks.

The `dma`+`phy` unit runs first inside phase 3 and its worktree merges before the rest launch:
every retaining unit codes against the claim/release and pin/unpin contract, so that contract
cannot still be moving while they are written.

`nd6` is the largest unit, carrying four RFC 4861 sec 5.1 structures plus the five-state
reachability machine. If its agent returns thin it splits in two on the re-run: neighbor cache
plus NUD, and prefix list plus default router list.

A phase that produces a merge conflict gets the conflicting pair re-run against merged main
rather than hand-reconciled by me.

---

## 8. Open items

### 8.1 The OS seam: what is actually required, and what is not

OS dependency is permitted, so a blocking sequential API is on the table. I claimed earlier that
it needs a mailbox. **That was wrong.** Having read lwIP's API layer, here is what a mailbox is
for there and why idemIP does not need one.

**lwIP uses mailboxes in two unrelated roles.**

*Role 1, the API request queue.* `api/tcpip.c:277` posts a `tcpip_msg` to `tcpip_mbox`; the
application thread then blocks on the `op_completed` semaphore (`api.h:234`) while
`tcpip_thread()` (`tcpip.c:136`) fetches and executes it. This exists because lwIP's core is not
reentrant and every core call must be marshalled into one context. It is **already avoidable in
lwIP itself**: `LWIP_TCPIP_CORE_LOCKING=1` replaces the whole round trip with a mutex around
direct calls.

*Role 2, the receive queue.* This is the one that is not optional in lwIP. The stack's receive
callback posts the incoming buffer from the stack's context, `api_msg.c:193` for TCP and
`api_msg.c:273` for UDP, both `sys_mbox_trypost(&conn->recvmbox, buf)`. The application thread
consumes it in `api_lib.c:600/615/620` via `sys_arch_mbox_fetch(&conn->recvmbox, &buf, timeout)`.
`acceptmbox` (`api_msg.c:579`) does the same for inbound connections.

**Why lwIP cannot drop role 2, and idemIP can.** Packet arrival is asynchronous: it happens in
the stack's context, at a time the application did not choose. The data must be *held* somewhere
until the application asks for it. In lwIP the mailbox **is** that storage: it is a queue of
pointers to pool-allocated pbufs, with bounded depth for backpressure (`recv_bufsize`,
`api.h:264`) and a timed fetch for `SO_RCVTIMEO`. lwIP needs a mailbox because it has nowhere
else to put the data.

idemIP already has somewhere else to put it. Every pcb owns a statically sized region of the
caller's borrow. The receive queue is therefore a **fixed-capacity ring at a mapped offset in the
pcb's own borrow**, not a queue of pointers into a pool. Nothing is allocated, nothing is posted,
and no mailbox object exists.

**And with frames arriving by DMA the conclusion is stronger still.** The descriptor ring is
already the receive queue, in hardware. There is nothing for a mailbox to do that the ring and
the pcb's own borrow do not already do. See sec 3.5 for the full primitive set.

**Settled: none of the three.** The options once offered here were a blocking-API question, and
the answer is that nothing blocks. There is no blocking `recv`, no blocking `accept`, no `select`
and no `poll`, so the choice between a blocking shim and BSD sockets does not arise.

The surface is: every entry returns immediately with `IdemIpStatus`, the caller drives progress
from its tick, and each service holds its own deferred work in its own borrow. See sec 3.4a and
sec 3.4b.

That removes the OS abstraction layer this question was really about. What remains is sec 3.5's
set: three platform primitives for DMA, and one optional mutex for a build where an application
task calls in alongside the stack tick.

### 8.1a Thread-local storage: not needed, and it would break the storage rule

Raised as a candidate OS primitive. It is not one, and this is recorded so it does not come back.

lwIP's only thread-local use is `LWIP_NETCONN_SEM_PER_THREAD` (`opt.h:1988`), and its own
rationale names it as an allocation trade: "one (thread-local) semaphore per thread calling
socket/netconn functions **instead of allocating one semaphore per netconn** (and per select
etc.)". `opt.h:2004` adds that it is required to use one socket from more than one thread.

Neither reason survives here:

- **The allocation it optimizes does not exist.** lwIP allocates a semaphore per netconn
  dynamically, so trading N of those for T per-thread ones is a real saving. idemIP's counts are
  compile-time, so a semaphore per pcb is `IDEMIP_TCP_PCBS` semaphores placed at link time. There
  is nothing to optimize away.
- **The multi-thread case is the core lock's.** One mutex over the public API gives
  one-socket-from-many-threads by construction, which is the same mutex the namespace pattern
  already requires (sec 3.3).

And a `_Thread_local` object is internal storage: per-thread, sized by thread count, invisible to
the caller. It is exactly what the storage rule forbids, and it would be the one place that rule
leaked. The OS and platform primitive set stays as sec 3.5 states it: mutex, semaphore or task
notification, atomics, memory barrier, cache invalidate and clean. No mailbox, no thread-local
storage.

### 8.2 Non-blocking, decided by default unless you object

1. **IGMPv2 + MLDv1** (lwIP's pair) rather than IGMPv3 + MLDv2.
2. **`bytes` stays** in every `init()` as a single fail-closed compare at startup, per sec 3.3.
3. **RFC 6528 ISN in core**, not as an optional addon the way lwIP does it. A predictable ISN is
   a live vulnerability, not a configuration preference.
4. **`IDEMIP_MLD6_TMR_INTERVAL_MS` stays 100**, lwIP's value, per sec 5.2.

Answer 8.1 and say `ultracode`, and I will run the workflow.
