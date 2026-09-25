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
| BLAKE3 | `metamui-blake3` | hash, keyed hash, derive-key | hash |
| BLAKE2b (RFC 7693) | `metamui-blake2b` | 256, 384, 512 | hash |
| Keccak-256 | `metamui-keccak256` | pre-FIPS padding (Ethereum) | hash |
| HKDF (RFC 5869) | `metamui-hkdf` | HKDF-SHA256 | extract, expand |
| Ed25519 (RFC 8032) | `metamui-ed25519` | Ed25519 | keygen, sign, verify |
| sr25519 (schnorrkel) | `metamui-sr25519` | Ristretto255 | keygen, sign, verify |
| X25519 (RFC 7748) | `metamui-x25519` | Curve25519 | keygen, key agreement |
| Argon2 (RFC 9106) | `metamui-argon2` | Argon2d, Argon2i, Argon2id | password hash |
| PBKDF2 (RFC 8018) | `metamui-pbkdf2` | HMAC-SHA256, HMAC-SHA512 | key derivation |
| BIP-39 | `metamui-bip39` | English wordlist | mnemonic, seed |
| HMAC_DRBG (SP 800-90A) | `metamui-hmac-drbg` | SHA-256, SHA-384, SHA-512 | instantiate, generate, reseed |
| Camellia (RFC 3713) | `metamui-camellia` | 128, 192, 256; ECB, CBC, CTR, GCM | encrypt, decrypt |
| Deoxys-II (CAESAR) | `metamui-deoxys` | Deoxys-II-256-128 | AEAD encrypt, decrypt |
| Ascon (SP 800-232) | `metamui-ascon` | AEAD128, Hash256, XOF128, CXOF128 | AEAD, hash, XOF |
| AES-CMAC (SP 800-38B) | `metamui-cmac` | AES-256 | mac, verify |
| Poly1305 (RFC 8439) | `metamui-poly1305` | one-time key | mac, verify |
| SipHash | `metamui-siphash` | 2-4, 1-3, 4-8; 64- and 128-bit | prf, mac |
| FlatHash | `metamui-flathash` | MetaMUI canonical JSON hash | hash |

`metamui-crypto` is the facade for the Falcon-512 and ML-KEM-768 profiles:
explicit profiles, typed byte boundaries, caller-supplied randomness, no
seeded entry point. The other algorithm crates, post-quantum and classic,
are published as they are;
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
files, the NIST ACVP FIPS 203/204/205 vectors, the KpqC authors' KAT
files for SMAUG-T, HAETAE, AIMer and NTRU+, the BLAKE3 team's official
vectors, the RFC 7693 / 8032 / 5869 / 3713 / 7748 / 8439 appendices, the RFC 7914
PBKDF2 vectors, the schnorrkel and Ethereum test suites for sr25519 and
Keccak-256, the ascon-c, argon2-cffi, oasisprotocol Deoxys-II, Trezor
BIP-39 and SipHash reference answers, Wycheproof for AES-CMAC and the NIST
ACVP hmacDRBG vectors. A missing vector file fails the run.

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
