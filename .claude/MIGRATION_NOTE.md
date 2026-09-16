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

This repository carried 58 British spellings across 50 files. 43 of them were corrected in commit 242ec74, on a request from the prose compliance session: the repeated Doxygen note beginning "Aggregate-initialised HERE" appeared once per protocol header, and the same sentence already read `initializer` in American four words later. The block contradicted itself, so the fix was internal consistency and not a locale imposed on the tree. Lead with the contradiction wherever one exists; a house rule invites an argument that a self-contradiction does not.

15 remain and they are deliberate. Migration holds them as fixtures for the objective 13 gate, which is being built with a `--fix` mode, and a tree cleaned by hand proves nothing about a gate. Do not fix them. They are `optimisation` at `CMakeLists.txt` lines 305, 311 and 321 and `behaviour` at line 123; `initialiser` and "zero initialised" at `src/idemip_config.h:270`; `optimised` at `test/bench/bench_entries.c:232`; `modelled` at `test/unit/netif/test_dma/test_dma.c:51`; `signalled` at `test/unit/tcp/test_tcp_in/test_tcp_in.c:1607`, `:1615` and `:1700`; and `licence` at `tools/dev_env/readclean.py:12` and `:36` and at `tools/dev_env/strip_comments.py:4` and `:12`. The 43 that were fixed are recoverable from commit 82dc143, which is the state before the correction.

Those four `licence` sites describe a license block instead of being one, so a gate may rewrite them. Every file here carries an SPDX line, and a gate that edits inside one is changing a legal artifact, so the exclusion has to be a rule and not a habit.

`rather than` is banned outright by the `code-comments` standard and survives in all 43 of those headers and in the commit message that spawned them, `f9202c7`. It was left alone deliberately. Removing it needs the sentence rebuilt, because the hinge carries the contrast against the `extern` form, and that is a separate decision from the spelling.

`SHOULD` and `MUST` in this repository's comments are RFC 2119 normative keywords and are not hedging. Rewording one breaks the citation it sits inside.

## Commit gates

No git hook is installed. `core.hooksPath` is unset and `.git/hooks` holds only the `.sample` files git ships, so nothing runs on commit and nothing has. The four migration commits passed through no gate.

`repotools.toml` reads otherwise, and that is the trap in it. Line 47 declares `gates = ["docs_check", "fetch_check"]` and line 50 gives `[hooks.docs_check]` its roots, so a reader takes both for live. They are configuration for gates nobody wired. A gate that is declared and not installed prints nothing at all, which is quieter than one that fails to find its tool and quieter than one that checks the wrong tree.

Installing one would still not reach the code. The declared roots are `README.md` and `test`, so `src/` sits outside them and so does `CMakeLists.txt`.

When a hook does go in, compute the tree with `git rev-parse --show-toplevel`. From a linked worktree under `.claude/worktrees/` that returns the worktree while `--git-dir` returns the per-worktree git directory, both checked in this repository.

Two ways of finding the tree are known to fail, and both were found in this tree by other captains during the migration. Deriving it from the script's own location reconciles the main checkout instead, reports that every file matches, and lets an unrecorded file through. Climbing parent directories until one holding `build/` appears fails in both directions, because `build/` is generated: a linked worktree has none, so the climb walks past it into the main checkout and lands on a real repository, and a fresh clone has none anywhere, so the climb runs to the filesystem root.

`--show-toplevel` on its own is not sufficient inside a hook. Git exports `GIT_DIR` to a hook, and a `rev-parse` that inherits it answers about that repository instead of the directory it was asked from; with `GIT_DIR` set and no work tree named, `--show-toplevel` is reported to return the current directory. So clear `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_PREFIX` and `GIT_COMMON_DIR` before every git query a hook makes. Nothing in this paragraph was checked here, and every other claim in this section was. The session isolation that protects these worktrees refuses the git calls the test needs, so this rests on the migration session's report of anchoring's fix hitting it on first run. Verify it before relying on it.

Nothing weaker than a destructive test proves a gate runs. Commit a deliberately bad file from a linked worktree and check whether it lands. An exit status of zero cannot tell a real pass from a gate that reconciled the wrong tree, and neither can a gate that was never installed, which is the state this repository is in today.

## What the migration did not change

`include/MMgr` is a submodule and belongs to the MMgr captain. This repository's whole dependency on it is three lines at `src/idemip_config.h:26-27`, which take `mmgr_string_shim.h` for `memcpy`, `memset`, `memcmp` and `memmove` when `IDEMIP_MMGR` is on. That option is off by default (`CMakeLists.txt:51`), so a default build compiles and links nothing from the submodule.

The `src/` changes are confined to one comment line per file in the 43 headers named above. No code changed: the diff over `src/` is 43 insertions and 43 deletions, every one of them the same sentence. The other changes are `tools/build.py` (new), the `IDEMIP_EXAMPLES` block in `CMakeLists.txt`, the `ProtoCore` path in `tools/dev_env/rfc.py`, the toolkit path in this file's own `repotools.toml` header, the README Build and Layout sections, and this note.

**Author:** dstroy0 (Douglas Quigg) <dquigg123@gmail.com>
**Date:** 2026-09-16
