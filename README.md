# idemIP

A TCP/IP stack in C11 for targets that have no heap and no operating system.

The library allocates nothing. Every unit that holds state is handed one `uint8_t` array by the
caller, sized by a macro that unit publishes, and reads and writes nothing outside it. There is no
file-scope mutable anywhere in `src/`, so two instances of a unit share not one byte and the whole
footprint of a build is the arrays the application declared.

```c
#include "src/idemip.h"

static _Alignas(IDEMIP_ALIGN) uint8_t netif_w[IDEMIP_NETIF_BORROW];
static _Alignas(IDEMIP_ALIGN) uint8_t arp_w[IDEMIP_ARP_BORROW];
```

`src/idemip.h` is the only header an application includes. It adds no type, macro or call of its
own; it names every unit's header, what the caller allocates, and the order things run in. Read its
opening comment for the worked example.

## Requirements

| | |
| --- | --- |
| CMake | 3.20 or newer |
| C compiler | any C11 compiler; the warning set and `-Os` apply to GCC and Clang |
| Python 3 | drives `test/harness.py`, which generates the Unity runners |
| Ruby | runs Unity's `generate_test_runner.rb` |
| Network | once, so `FetchContent` can clone Unity v2.6.1 |

Python and Ruby are needed only to build the tests.

## Build

The build directory lives outside the repository, and `.clangd` expects it at `../build`:

```
cmake -S . -B ../build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build ../build
ctest --test-dir ../build --output-on-failure
```

Release builds take `-Os` and link-time optimization, which is what folds the namespace
indirection. `IDEMIP_LTO=OFF` turns the latter off.

## Capabilities

A capability is a set of translation units. CMake selects them, so a capability that is off reaches
the compiler as no file at all rather than as a file that compiles to nothing.

```
cmake -S . -B ../build -G Ninja -DIDEMIP_ENABLE_TCP=OFF -DIDEMIP_ENABLE_UDP=OFF
```

The feature tree is declared child to parent in `CMakeLists.txt`, over the helpers in
`cmake/FeatureTree.cmake`. `ETHERNET` is the root; each child names the parent it sits on, and a
build that turns a parent off is refused with the reason:

| capability | sits on | because |
| --- | --- | --- |
| `IDEMIP_ENABLE_ETHERNET` | root | |
| `IDEMIP_ENABLE_IPV4` | ETHERNET | `arp.h` resolves to a 48-bit Ethernet address (RFC 826) |
| `IDEMIP_ENABLE_IPV6` | ETHERNET | the link layer here is Ethernet II (RFC 2464) |
| `IDEMIP_ENABLE_TCP` | IPV4 or IPV6 | the checksum covers a pseudo-header |
| `IDEMIP_ENABLE_UDP` | IPV4 or IPV6 | the checksum covers a pseudo-header |

Each value reaches the library and every consumer as a compile definition, because
`idemip_config.h` sizes tables with them: `IDEMIP_TIMEOUTS` is arithmetic over the five.

Where one unit serves both IP versions, the version arm is its own translation unit and the build
swaps in a stub for a version it left out. `src/ip/pseudo.c` holds the transport pseudo-header
branch once; `pseudo_v4.c` and `pseudo_v6.c` are the two forms, `pseudo_v4_off.c` and
`pseudo_v6_off.c` answer a version this build does not carry.

## Layout

```
CMakeLists.txt   the library, the capability tree, the tools and the test subdirectory
cmake/           FeatureTree.cmake: add_root_option, add_child_option, feature_sources,
                 feature_source_swap, enforce_mutually_exclusive_with_fallback
src/             the library, included as "src/..." with the repo root as the one include path
test/            one CTest target per suite, plus harness.py and unwired.py
tools/           idemip_sizes.c
```

## What is here

**Link.** Ethernet II framing (RFC 894), the IEEE 802.1Q C-Tag, the MII management registers
(IEEE 802.3 Clause 22), the PHY driver contract, the DMA descriptor rings and their pin protocol,
the interface table, and a loopback interface (RFC 1122 sec 3.2.1.3, RFC 4291 sec 2.5.3).

**IPv4.** The header (RFC 791 sec 3.1), addresses (RFC 1122 sec 3.2.1.3), the routing table
(RFC 1122 sec 3.3.1), forwarding (RFC 1812 sec 5.2.1.2), fragmentation (RFC 791 sec 3.2) and
reassembly by the RFC 815 hole list, Path MTU Discovery (RFC 1191), ARP (RFC 826) with its
translation table, Address Conflict Detection (RFC 5227), Link-Local addressing (RFC 3927), ICMP
(RFC 792) under the RFC 1122 sec 3.2.2 origination rules, IGMPv2 (RFC 2236), and DHCP (RFC 2131).

**IPv6.** The header and its extension chain (RFC 8200 sec 3), addresses (RFC 4291 sec 2) with the
zones of RFC 4007, default address selection (RFC 6724), forwarding, fragmentation and reassembly
(RFC 8200 sec 4.5), Path MTU Discovery (RFC 8201), IPv6 over Ethernet (RFC 2464), ICMPv6 (RFC 4443),
Neighbor Discovery (RFC 4861) with Duplicate Address Detection (RFC 4862 sec 5.4), SLAAC
(RFC 4862 sec 5.3), the RDNSS option (RFC 8106), MLD (RFC 2710), and DHCPv6 (RFC 8415).

**Transport.** TCP (RFC 9293) — SEGMENT ARRIVES of sec 3.10.7, the send path with its timers and
windows, the transmission control blocks and queues, and RFC 6528 initial sequence numbers. UDP
(RFC 768), UDP-Lite (RFC 3828), raw bindings on an IP protocol number, and a stub resolver
(RFC 1035).

**Core.** The receive path from one frame to the pcb that owns it, the scheduler, the deadline
list, and the RFC 1213 counters.

## Footprint

`tools/idemip_sizes.c` links the library and prints every borrow and their sum, as the compiler
computed them over `idemip_config.h`. It is run, never remembered. At the default counts
(`IDEMIP_NETIF_COUNT 2`, `IDEMIP_TCP_PCBS 5`, `IDEMIP_UDP_PCBS 8`, `IDEMIP_IP6_ADDRESSES 4`):

```
= IDEMIP_SHARED_BORROW         20328
= IDEMIP_PER_NETIF_BORROW       4976  x 2
  IDEMIP_TOTAL_BORROW          30280
```

The driver's frame buffers are the driver's and are in no borrow, so that total does not count
them.

Every count is an `#ifndef` in `idemip_config.h`, so a definition reaching the compiler overrides
it. These are preprocessor definitions rather than CMake options:

```
cmake -S . -B ../build -G Ninja -DCMAKE_C_FLAGS=-DIDEMIP_TCP_PCBS=2
```

which takes the total above to 29296. Each borrow is a formula over the counts, never a number, and
each unit's `.c` carries `static_assert(sizeof(<Unit>Ctx) <= IDEMIP_<UNIT>_CTX_BYTES)`, so a
context that outgrows its budget fails the build naming the macro to raise.

## Tests

One CTest target per suite. A suite is a directory holding exactly one `.c` of file-scope
`void test_<name>(void)` cases; `harness.py` turns it into `unity_runner.c` through Unity's own
generator, and says so when the generator would walk past a case.

`test/CMakeLists.txt` maps each suite to the capabilities it drives. A suite whose capabilities are
off is skipped loudly, because silently dropping it would leave a passing run that tested less than
it looks like.

```
python test/harness.py suites            every suite, its cases, and the capabilities it needs
python test/harness.py cases <dir>       what Unity registered, and what it walked past
python test/harness.py deps --strict     dependencies a suite binds that no case asserts on
python test/unwired.py .                 identifiers a header defines that no library .c names
```

The last two are audit tools, not pass/fail gates. Both exist because a requirement encoded in a
header and never wired to a caller is invisible to a green test run.

## Style

`src/` is C11 with no heap, no `auto`, and no array with automatic storage duration. The only
system headers it takes are `<assert.h>` for `static_assert`, `<stddef.h>`, `<stdint.h>` for the
fixed widths, and `<string.h>` for `memcpy`, `memset` and `memcmp`; there is no `<stdlib.h>` and
nothing is parsed by the library. Names are flat `idemip_snake_case` in one namespace. Sizes are
powers of two so an index is a shift, because hardware divide is not on every target in the list.
`test/` and `tools/` are exempt and read as plain host C.

Warnings are attached to an INTERFACE target so they reach the suites as well as the library:
`-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-align -Wundef`, with
`-Wstrict-prototypes -Wmissing-prototypes` on the library.

## License

AGPL-3.0-or-later. Every file carries the SPDX identifier.
