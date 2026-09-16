# idemIP after the repo migration

**Purpose:** Find this repository's tools, build it from one entry point, and hand the work that crosses repository boundaries to whoever owns it.
**Scope:** `tools/`, `CMakeLists.txt`, `README.md`, and the boundaries between this repository and `theory_bucket`, `repos/owned/private/anchor_sift_citations`, and `include/MMgr`.

An agent picking up idemIP reads this before touching the tree. It records what the migration changed, what it deliberately did not change, and which questions belong to another session.

## Where the tools are

Every tool this repository owns sits under `tools/`. Nothing was moved to get there, because idemIP never grew the scattered `maint/`, `evidence/` and `proof/` directories that migration objective 5 exists to collapse. The consolidation that objective asks for was already true here.

`tools/build.py` is the build entry point, added by the migration. `tools/idemip_sizes.c` is the footprint tool, and it compiles as a real target (`CMakeLists.txt:299`) so the footprint is the compiler's arithmetic over `idemip_config.h` and not a number kept by hand. `tools/dev_env/` holds the fifteen checkers this repository runs over its own source, including `rfc.py`, `guards.py`, `deadstate.py` and `strip_comments.py`.

`test/harness.py` stays under `test/` and is not a general tool. It discovers suites and writes the Unity runners, so it only means anything next to the suites it reads.

## Building

One entry point covers every tree:

```
python tools/build.py check
python tools/build.py all
```

`check` names each prerequisite, what that part is needed for, and whether the host has it, so a first build fails with a sentence instead of a stack of CMake output. `all` builds the library, then `examples/`, then the suites, and runs ctest over them. `lib`, `examples`, `tests` and `configure` each build one tree. Every subcommand takes `--dry-run`, which prints the `cmake` and `ctest` invocations without running them, and `-D`, which forwards a define to the configure step.

The README Build section carries the same commands. Migration objective 8 requires that worked invocation in the README of every repository, because a build discoverable only by reading the script is a build that lives in an agent's transcript.

## What examples/ still owes

There is no `examples/` tree in this repository. Migration objective 18 requires one that a build script can walk a user through, so idemIP owes it.

The wiring is already in place and inert. `CMakeLists.txt` declares `IDEMIP_EXAMPLES`, off by default, and adds the subdirectory only when `examples/CMakeLists.txt` exists. A configure with the option on and no tree present prints a status line and continues. Dropping an `examples/CMakeLists.txt` into the tree is all that remains; `python tools/build.py examples` picks it up on the next configure with no change to the script.

An example is an application, so it links `idemip` through `src/idemip.h` the way a consumer does. That include is the only compile the front door gets outside the fuzz harness (`CMakeLists.txt:334`), which is a second reason to want the tree.

## Theory

idemIP has no theory chapter, and `theory/` does not exist here.

Migration objective 4 moves each library's theory to `theory/` as a submodule pulled from the `theory_bucket` remote. A survey of `repos/owned/public/theory_bucket` on the date below found nothing belonging to idemIP: `Salishan` and `delta_null` both name anchor_sift in their `.tex`, `precision` is the FFT work (`engine_workbook`, `relation_search`, `twiddle_proof`), and `cryptography`, `crystallography`, `millennium`, `thought_experiments` and `cell_tracking` are the remainder. No file in the bucket mentions idemip.

The migration session ruled on this directly: idemIP gets no `theory/` until idemIP has theory, and `theory_bucket` is not to be vendored whole into a public networking library.

Carry the rule behind the ruling forward. `theory/` is a dependency mount point and not a layout ornament. Each repository holds locally authored work in `workbook/` and mounts `theory/` as a pure dependency on `theory_bucket`. Uniformity applies to that rule and not to the presence of the directory, so a repository with no theory has no `theory/` in the same way a repository with no local book has no `workbook/`. Creating an empty mount for symmetry would make the directory the point instead of the dependency.

idemIP is also the case that broke objective 4's literal wording. A git submodule points at a repository and not at a subdirectory inside one, so its minimum unit is the whole bucket. anchor_sift needs seven trees and idemIP needs none, and one mechanism at whole-bucket granularity serves neither. The replacement mechanism is being decided and will land as `PLANS/DEPENDENCY_STANDARD.md`.

**The contract for whoever adds the first idemIP chapter.** The chapter is authored upstream in the `theory_bucket` repository, the same as every other chapter. It then arrives here at `theory/<name>`, where `<name>` is that one theory folder and not the bucket. The command that mounts it is whatever `PLANS/DEPENDENCY_STANDARD.md` specifies; read that document instead of assuming a submodule, because the standard exists precisely to replace submodule-whole. Never commit `.tex` sources directly into idemIP.

Whether idemIP is supposed to have a chapter at all is an open design decision that belongs to Douglas, and the migration session has put it to him with this survey as evidence. Do not write one speculatively and do not assign an owner.

## The texbuild hand-off

The `main.tex` files in `theory_bucket` still carry the paths from the layout before the migration. `precision/main.tex` tells a reader to compile with `latexmk -pdf -outdir=../../build/theory/precision main.tex`, and `delta_null/main.tex` names `sh maint/texbuild/build_theory.sh anchor_sift` and states that `theory/` is the source. Both paths describe the old arrangement.

Fixing them belongs to the repository agents that own those chapters, not to a captain of a repository with no theory. This note records the breakage so that the move does not look like a regression introduced later: the `.tex` files were already pointing at `maint/texbuild` and at a `build/theory` output directory before anyone touched them for the migration.

## Citations leave this repository

idemIP cites 94 distinct RFCs plus six IEEE standards, and every borrowed claim carries an RFC number and section inline. Two algorithms are named after their authors, Nagle and Karn in `src/tcp/tcp_out.c` and `src/tcp/tcp_out.h`, and both sit beside the citation that governs them: Nagle at RFC 9293 sec 3.7.4, Karn at RFC 6298 sec 3. The surname is descriptive and never stands in for the reference.

Those two reach their original papers transitively. RFC 9293 sec 3.7.4 opens "The 'Nagle algorithm' was described in RFC 896", and RFC 6298 sec 3 carries `[KP87]` inside the sentence `tcp_out.c:468` quotes. A work a standard cites is not a work this code rests on; idemIP implements the RFC's requirement. The session holding `repos/owned/private/anchor_sift_citations` keeps the corpus and has the inventory.

A citation here names a section, and the section decides. RFC 9293 puts the Minshall variation of the Nagle algorithm in Appendix A.3 and the baseline in sec 3.7.4. This tree cites sec 3.7.4 and never Appendix A.3, so the citation answers which of the two it implements. Cite the section, not the document.

No third-party copyrighted document may be committed to this repository. The rule is about who holds the copyright and not about the file format: a PDF this project builds from its own sources is fine, and somebody else's paper is not, whatever extension it carries. Copies of other people's work live only in the private corpus at `repos/owned/private/anchor_sift_citations`. idemIP carries none today and that is the state to preserve.

`docs/learn/RFC/` is a separate case and stays. It holds 112 verbatim IETF RFC text files, which the IETF Trust's terms permit redistributing. Treat them as read-only: they are normative standards text, and an edit to one silently changes what every citation pointing at it claims.

## Prose and comments

Comment prose belongs to the prose compliance session, which reviews and sends edit requests without editing this tree. Two standing points for anyone writing here.

This repository carries 58 British spellings across 50 files, and migration objective 13 bans them in tool comments and description blocks. Do not hand-edit them. The objective 13 gate is being built with a `--fix` mode, and running it over the whole tree at once proves the gate catches them; a tree cleaned by hand beforehand tests nothing.

Most of the count is one repeated block. `initialised` accounts for 44 of the 58, nearly all of them in the Doxygen note beginning "Aggregate-initialised HERE" that appears once per protocol header. `licence` accounts for 4, all inside `tools/dev_env/readclean.py` and `tools/dev_env/strip_comments.py`, and every one of them is prose describing a license block instead of license text itself, so the gate may rewrite them. The remainder is `optimisation` three times in the `CMakeLists.txt` bench block at lines 305, 311 and 321, plus single hits on `optimised`, `modelled`, `behaviour`, `initialiser` and three on `signalled`.

`SHOULD` and `MUST` in this repository's comments are RFC 2119 normative keywords and are not hedging. Rewording one breaks the citation it sits inside.

## What the migration did not change

No file under `src/` or `test/` was modified. The changes are `tools/build.py` (new), the `IDEMIP_EXAMPLES` block in `CMakeLists.txt`, the README Build and Layout sections, and this note. `include/MMgr` is a submodule and belongs to the MMgr captain.

**Author:** dstroy0 (Douglas Quigg) <dquigg123@gmail.com>
**Date:** 2026-09-16
