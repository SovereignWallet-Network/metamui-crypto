# MetaMUI Crypto

Post-quantum cryptography in Rust for applications and blockchains, under
the Apache License 2.0 (see `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md`).

## Status

Preview candidate, source only. This tree is a curated export of the MetaMUI
Crypto source repository: the file list, every file's SHA-256 and the digest
of the whole tree are in `EXPORT_MANIFEST.json`. Changes are made upstream
and re-exported; maintainers do not edit this repository directly. No
package has been published to a registry from this tree.

## What is here

| profile | crate | operations |
|---|---|---|
| `falcon-512.r3-compressed`, `falcon-512.r3-padded` | `metamui-crypto-rust/metamui-crypto` over `metamui-falcon512` | keygen, sign, verify |
| `ml-kem-768` | `metamui-crypto-rust/metamui-crypto` over `metamui-mlkem` | keygen, encapsulate, decapsulate |

`metamui-crypto` is the facade: explicit profiles, typed byte boundaries,
caller-supplied randomness, no seeded entry point. The workspace also carries
the crates it is built on (SHA-2, SHA-3, SHAKE, AES-256, AES CTR_DRBG and the
shared utilities), all MetaMUI's own implementations.

Every crate here is portable scalar Rust: no SIMD, assembly, GPU or
CPU-feature-detection path is in this tree, so the same arithmetic runs on
every target the compiler supports. Accelerated variants are not part of
the public release.

```
cd metamui-crypto-rust && cargo test --workspace --release
```

The tests replay the NIST Round-3 Falcon and PQClean `falcon-padded-512`
answer files and the NIST ACVP FIPS 203 vectors under `test-vectors/`
through the public API. A missing vector file fails the run.

## What is not claimed

Passing the upstream vectors is conformance, not an audit. No independent
audit, no timing or side-channel measurement and no fuzzing campaign has
been performed on this tree; the cores are designed for constant time and
unmeasured. See `SECURITY.md` for the reporting process and `SUPPORT.md` for
what a support mark means.

## Not yet here

Other languages, other algorithms and registry packages arrive as the
release program admits them. Nothing is claimed for a target or algorithm
that is not in this tree.

## Contact

Bugs and questions: GitHub issues and pull requests on this repository are
welcome (`CONTRIBUTING.md`). Anything that might be a security
vulnerability: **security@metamui.id**, never a public issue (`SECURITY.md`).
