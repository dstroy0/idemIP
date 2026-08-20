# The benches

Measurement, not test. Nothing here asserts, ctest never runs them, and a normal build does not
carry them. They are built by asking for them:

```
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release -DIDEMIP_BENCH=ON -DBUILD_TESTING=OFF
cmake --build build-bench
./build-bench/bench_words   > test/bench/results/<date>-words.csv
./build-bench/bench_entries > test/bench/results/<date>-entries.csv
python tools/dev_env/benchreport.py <words.csv> <entries.csv>
```

Both link `libidemip`, so what they time is the translation unit that build produced under that
build's flags, not a copy recompiled beside them.

## The two binaries answer different questions

**`bench_entries`** is what the library costs on this host, vectorizer and all. Its rows are the
real thing: an entry called through its namespace, the library compiled as it ships.

**`bench_words`** is a model. It instantiates the span helpers on a 16-, 32- and 64-bit word to
stand for three architectures, and it is built with `-fno-tree-vectorize` because otherwise the
rows are not about a word at all: this host does sixteen octets at a time whatever the nominal
width is. The two questions do not belong in one binary and are not in one binary.

## What the harness costs

Nothing. `bench_harness.h` defends the timing loop with an empty `asm` carrying a memory clobber,
which emits no instruction: it tells the compiler memory may have changed and that a value has
escaped, so a pure call cannot be hoisted out of the loop and its result cannot be discarded. No
function pointers (they stop the call inlining, so the code measured would not be the code
shipped), no volatile stores, no accumulator. Every sweep also carries a `nop` row, which is the
loop and its counter alone, so it can be subtracted.

Costs are in **cycles**, read from the invariant TSC. A wall clock reads to about a third of a
nanosecond here, which is one tick, so anything costing one or two of them reads as noise. Note
that the invariant TSC advances at a fixed rate rather than at the core's current frequency, so a
cycle here is a reference tick and not a core clock: steady for comparing two costs, not an
instruction count.

## The four validity gates

`benchreport.py` checks these first, and a run that fails one is not evidence of anything:

| gate | what it catches |
|---|---|
| `nop` is flat across every span | the loop itself varying, which would contaminate every row |
| `byte` moves with density | the early-exit walk must be visibly input-sensitive, or nothing is being measured |
| a wider word is never slower | an instantiation that did not compile to what it says |
| 32→64 halves the work at n ≥ 64 | the model matching `floor(n/W)` bodies plus one tail |

## Two methods that produced wrong answers, and why

**Points measured one at a time.** The twenty (density, distribution) points of one span were run
to completion one after another, so they were minutes apart. This machine drifts further over
those minutes than the input moves the code: `idemip_bytes_zero` over 1500 octets — which has no
branch on its input at all — reported a 57% spread. Rounds are on the outside now and points on the
inside, each keeping its own least round, which puts the drift on every point equally. The same
measurement then reports 0.6%.

**A loop-invariant remainder.** The tail was timed at a fixed remainder, so gcc hoisted the whole
mask out of the loop and what was being timed was a load and an AND against a constant. Both endian
arms read as one cycle flat with the difference between them wandering between runs. The remainder
walks with the iteration now, so the mask is computed every time.

**Differencing two whole loops.** Before that, the endian arms were compared by subtracting two
1500-octet timings. They differ by one mask computed once; the loop's own scheduling moves further
between two builds than the mask costs in total, and the big-endian arm came out 29 ns *faster*.
The tail is timed on its own now.

## The archive

`results/` holds every validated run with a `provenance.txt` naming the commit, compiler, CPU and
build flags. A number here is only comparable to another number taken on the same host with the
same flags, which is what the provenance is for. Runs are kept rather than overwritten: the point
is to be able to prove later what a change did.
