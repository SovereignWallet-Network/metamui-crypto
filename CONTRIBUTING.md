# Contributing to MetaMUI Crypto

MetaMUI Crypto is published under the Apache License 2.0 (`LICENSE`). This
file says how a change gets in, what a reviewer will ask for, and what the
project will not accept. It is deliberately short; the rules that matter for
cryptographic code are the strict ones.

## How this repository is maintained

This tree is a curated export of the MetaMUI Crypto source repository (see
`README.md` and `EXPORT_MANIFEST.json`). Issues and pull requests are
welcome here and are reviewed here; an accepted change is applied to the
source tree by a maintainer with your authorship preserved (`Author` and
`Signed-off-by` lines are kept) and reaches this repository in the next
export. Do not be surprised when a merged change arrives as part of an
export commit rather than as a merge of your branch.

## Before you write code

- Open an issue first for anything that changes bytes on the wire, adds an
  algorithm or parameter set, or touches randomness, key handling or
  decapsulation. Say which **profile** (algorithm + parameter set + encoding,
  as named in the support table) you are changing.
- New KEM/KDF/AEAD combinations, "hybrid" constructions and convenience
  wrappers that pick an algorithm for the caller are out of scope unless they
  have a separately reviewed design. A profile identifier never changes
  meaning; a change to any byte of an encoding is a new profile.
- Do not add dependencies on external cryptographic libraries to a core
  implementation. Every digest, cipher and DRBG in this workspace is
  MetaMUI's own code; RustCrypto crates appear only as dev-dependencies, as
  test oracles.
- Anything that might be a security vulnerability is not an issue or a pull
  request: write to **security@metamui.id** first (`SECURITY.md`).

## What a pull request must contain

1. **Tests that would have failed before the change.** For a cryptographic
   change: known-answer vectors from the algorithm's upstream source (NIST
   ACVP, the reference package, the RFC), not values produced by the code
   under test. A test that skips when a vector file is missing is a failing
   test in this project.
2. **No output change without a vector change.** A change that alters the
   output of a primitive must come with the test-vector update that shows the
   new output is the specified one.
3. **A description that names the profile(s) affected**, the specification
   section or reference commit you implemented, and the commands you ran
   with their observed results.
4. **A `Signed-off-by:` line on every commit** (the Developer Certificate of
   Origin, `git commit -s`). There is no contributor licence agreement;
   contributions are accepted under the Apache License 2.0, and you certify
   that you have the right to submit them.
5. **Constant-time discipline** in the cores: no secret-dependent branches,
   memory indices or early returns. Documentation may say that code is
   designed for constant time; it may not claim measured resistance.
6. **No seeded entry point on a public surface.** Known-answer and
   deterministic functions live behind the `kat-internal` (Falcon) and
   `fips203-internal` (ML-KEM) features and the facade exposes none.

## Review

Every change is reviewed by a maintainer before merge; cryptographic changes
are reviewed by the maintainer of that algorithm area (see `SUPPORT.md` for
what is supported and who owns it at this release). Reviewers check the
vectors, the encodings and the error paths before they read the style.
Expect questions; expect to be asked for the upstream reference.

There are no per-pull-request CI checks on this repository at this release.
Run `cargo test --workspace --release` in `metamui-crypto-rust/` and paste
the results in the pull request.

## Reporting a problem

Bugs and feature requests: open an issue. Anything that might be a security
vulnerability: **do not open an issue** — follow `SECURITY.md`.

## Conduct

Be respectful and specific. Discuss the change, not the person. Maintainers
may close discussions that stop being about the code.
