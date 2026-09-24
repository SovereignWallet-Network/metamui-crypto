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

| family | crate | parameter sets | operations |
|---|---|---|---|
| Falcon (Round 3) | `metamui-falcon512`; profiles `falcon-512.r3-compressed`, `falcon-512.r3-padded` through the `metamui-crypto` facade | Falcon-512, Falcon-1024 | keygen, sign, verify |
| ML-KEM (FIPS 203) | `metamui-mlkem`; profile `ml-kem-768` through the facade | 512, 768, 1024 | keygen, encapsulate, decapsulate |
| ML-DSA (FIPS 204) | `metamui-dilithium` | 44, 65, 87 | keygen, sign, verify |
| SLH-DSA (FIPS 205) | `metamui-slhdsa` | SHA2/SHAKE × 128/192/256 × s/f | keygen, sign, verify |
| SMAUG-T (KpqC, v1.2.0) | `metamui-smaug-t` | mode 1, 3, 5 | keygen, encapsulate, decapsulate |
| HAETAE (KpqC) | `metamui-haetae` | 2, 3, 5 (one per build) | keygen, sign, verify |
| AIMer (KpqC) | `metamui-aimer` | 128/192/256 × s/f | keygen, sign, verify |
| NTRU+ (KpqC) | `metamui-ntru-plus` | 768, 864, 1152 | keygen, encapsulate, decapsulate |

`metamui-crypto` is the facade for the Falcon-512 and ML-KEM-768 profiles:
explicit profiles, typed byte boundaries, caller-supplied randomness, no
seeded entry point. The other algorithm crates are published as they are;
each README states its parameter sets, sizes, API and the known-answer
files its tests replay. The workspace also carries the crates they are built
on (SHA-2, SHA-3, SHAKE, AES-256, AES CTR_DRBG, the shared utilities and the
error type), all MetaMUI's own implementations.

Every crate here is portable scalar Rust: no SIMD, assembly, GPU or
CPU-feature-detection path is in this tree, so the same arithmetic runs on
every target the compiler supports. Accelerated variants are not part of
the public release.

```
cd metamui-crypto-rust && cargo test --workspace --release
```

The tests replay the upstream answer files under `test-vectors/` through
the public API: the NIST Round-3 Falcon and PQClean `falcon-padded-512`
files, the NIST ACVP FIPS 203/204/205 vectors, and the KpqC authors' KAT
files for SMAUG-T, HAETAE, AIMer and NTRU+. A missing vector file fails the
run.

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
