# metamui-slhdsa

SLH-DSA (NIST FIPS 205, the standardised SPHINCS+) stateless hash-based
signatures in Rust, all twelve parameter sets, verified against the NIST ACVP
answer files. The public entry surface of MetaMUI Crypto is the
`metamui-crypto` facade in this workspace; this crate is the implementation
behind its `slhdsa` module and can also be used directly.

## Parameter sets

Each set exists with SHAKE256 (`SlhDsa128s` …) and with SHA-2
(`SlhDsa128sSha2` …); the sizes are the same for both hash families.

| parameter set | security category | public key | secret key | signature |
|---|---|---|---|---|
| SLH-DSA-128s | 1 | 32 | 64 | 7 856 |
| SLH-DSA-128f | 1 | 32 | 64 | 17 088 |
| SLH-DSA-192s | 3 | 48 | 96 | 16 224 |
| SLH-DSA-192f | 3 | 48 | 96 | 35 664 |
| SLH-DSA-256s | 5 | 64 | 128 | 29 792 |
| SLH-DSA-256f | 5 | 64 | 128 | 49 856 |

`s` (small) sets sign slowly and produce the shorter signature; `f` (fast)
sets sign faster and produce the longer one. Verification cost is similar
across a security category. The FIPS 205 Table 2 constants (n, h, d, h', a,
k, w) of every set are the `Parameters` associated constants in `params`.

## Usage

```rust
use metamui_slhdsa::{SlhDsa128s, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

let signing_key = SigningKey::<SlhDsa128s>::generate(&mut OsRng);
let verifying_key = signing_key.verifying_key();

let signature = signing_key.sign(b"hello");                       // deterministic variant
let hedged = signing_key.sign_with_rng(b"hello", &mut OsRng);      // randomised variant
assert!(verifying_key.verify(b"hello", &signature).is_ok());
assert!(verifying_key.verify(b"hello", &hedged).is_ok());

// keys and signatures travel as bytes
let vk = VerifyingKey::<SlhDsa128s>::from_bytes(&verifying_key.to_bytes())?;
assert!(vk.verify(b"hello", &signature).is_ok());
# Ok::<(), metamui_slhdsa::Error>(())
```

Both calls are the FIPS 205 pure interface (Algorithm 22) with the empty
context string. `sign` is the standard's deterministic variant (randomizer =
PK.seed, the same signature for the same message); `sign_with_rng` is the
hedged variant that draws the randomizer from the caller's `RngCore`.
`verify_with_context` and `signing::slh_sign` take a context string of at
most 255 bytes. The pre-hash interface (Algorithm 23, HashSLH-DSA) is
`signing::slh_hash_sign_deterministic` with a `PreHashAlgorithm`. The free
functions `slh_keygen`, `slh_sign` and `slh_verify` work on raw key bytes.

The internal interfaces of FIPS 205 §9 — key generation from
(SK.seed, SK.prf, PK.seed) and signing with a caller-supplied randomizer —
are compiled only with the `kat-internal` feature; an application is never
offered a seed.

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | `std::error::Error` for `Error`, the ACVP JSON parser |
| `all-params`, `slh-dsa-128s` … `slh-dsa-256f` | no | selectors kept for consumers that name a set; every set is always compiled |
| `sha256` | no | selector kept for consumers that name the SHA-2 family; both families are always compiled |
| `kat-internal` | no | seeded and known-answer entry points (`slh_keygen_from_seeds`, `signing::slh_sign_core`, `signing::slh_sign_internal`, `test_vector_generator`). Compiled for this crate's own tests; an application is never offered a seed |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. Hashing is MetaMUI's own
`metamui-sha2` and `metamui-shake`. The crate is `#![forbid(unsafe_code)]`
and builds without `std`.

## Tests

```
cargo test -p metamui-slhdsa --release
```

* `tests/upstream_acvp_gate.rs` — the unmodified NIST ACVP-Server
  `keyGen`, `sigGen` and `sigVer` prompt/expected-result files replayed
  byte-for-byte across every parameter set
  (`test-vectors/slh-dsa-upstream/`).
* `tests/test_json_vectors.rs` — the cross-language portable fixtures and
  the ACVP-shaped fixtures in `test-vectors/slh-dsa/`, which every language
  binding in the distribution also replays.
* `tests/keygen_validation.rs`, `tests/signing_properties.rs`,
  `tests/test_nist_vectors.rs` — FIPS 205 sizes, sign/verify round trips,
  tamper rejection, determinism of the deterministic variant.
* `tests/kat_surface_gated.rs` — every seeded entry point stays behind
  `kat-internal`.

A missing vector file fails the run; nothing skips.
`examples/verify_acvp_upstream.rs` runs the same ACVP replay against any
directory of prompt/expected-result files.

## What is and is not claimed

The Rust core is written with constant-time idioms where a secret is
compared or selected, and secret material is zeroized on drop. **No timing
or side-channel measurement has been made and no independent audit has
taken place**; treat the implementation as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md` at
the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution. An implementation of FIPS 205 from the standard's text.
