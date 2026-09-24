# metamui-haetae

HAETAE lattice-based signatures in Rust: a port of the official HAETAE
v1.2.0 reference implementation (Team HAETAE, CryptoLab; KpqC winner,
specification v260825), transcribed function for function and verified
byte-for-byte against the reference's own known-answer files. The public
entry surface of MetaMUI Crypto is the `metamui-crypto` facade in this
workspace; this crate is the implementation behind its `haetae` module and
can also be used directly.

## Parameter sets

| parameter set | NIST category | (k, l) | public key | secret key | signature |
|---|---|---|---|---|---|
| HAETAE-2 | 1 | (2, 4) | 992 | 1 408 | 1 474 |
| HAETAE-3 | 3 | (3, 6) | 1 472 | 2 112 | 2 349 |
| HAETAE-5 | 5 | (4, 7) | 2 080 | 2 752 | 2 948 |

Sizes in bytes, from the reference `api.h`; every size is a constant in
`params` (`CRYPTO_PUBLICKEYBYTES`, `CRYPTO_SECRETKEYBYTES`, `CRYPTO_BYTES`).
Signatures are fixed-length; a signing attempt whose rANS-coded hint does
not fit is rejected and resampled, as in the reference.

The crate compiles **one parameter set at a time**, selected by a cargo
feature: `haetae2` (the default), `haetae3` or `haetae5`. Enabling two is a
compile error, so a non-default level is selected with
`default-features = false`:

```toml
[dependencies]
metamui-haetae = { version = "1.0.0-rc.2", default-features = false, features = ["std", "haetae3"] }
```

## Usage

```rust
use metamui_haetae::{KeyPair, SigningKey, VerifyingKey, Signature, Error};

let keypair = KeyPair::generate()?;
let signature = keypair.sign(b"hello")?;
keypair.verify(b"hello", &signature)?;

// keys and signatures travel as fixed-size byte arrays
let vk = VerifyingKey::from_bytes(keypair.verifying_key().to_bytes());
let sig = Signature::from_bytes(signature.as_bytes()).ok_or(Error::InvalidSignatureLength)?;
vk.verify(b"hello", &sig)?;
# Ok::<(), Error>(())
```

Signing is randomized: every signature mixes a fresh 32-byte hedging seed
from the operating system with the secret key, so two signatures of one
message differ and both verify. `ExpandedVerifyingKey` caches the expanded
matrix for a public key that verifies many signatures. The `sign` module
carries the reference's C-shaped free functions (`crypto_sign_keypair`,
`crypto_sign_signature`, `crypto_sign_verify`) on raw byte arrays.

The seeded entry points the reference KAT harness replays —
`sign::crypto_sign_keypair_internal(seed)` and
`sign::crypto_sign_signature_internal(.., pre, rnd, ..)` — are compiled only
with the `kat-internal` feature; an application is never offered a seed.

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | operating-system randomness (`getrandom`) for key generation and signing; required — the crate does not build without it |
| `haetae2` / `haetae3` / `haetae5` | `haetae2` | the parameter set; exactly one |
| `kat-internal` | no | seeded entry points (`crypto_sign_keypair_internal`, `crypto_sign_signature_internal`). Compiled for this crate's own tests; an application is never offered a seed |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. The fixed-point
hyperball sampler is the reference's integer arithmetic, so the sampled
values are the same on every target. Hashing is MetaMUI's own
`metamui-shake`. The rANS entropy coder of the signature encoding is the one
place with `unsafe` blocks (a transcription of the reference's
pointer-walking coder).

## Tests

```
cargo test -p metamui-haetae --release
cargo test -p metamui-haetae --release --no-default-features --features haetae3,std
cargo test -p metamui-haetae --release --no-default-features --features haetae5,std
```

* `tests/haetae_upstream_kat.rs` — the unmodified reference
  `PQCsignKAT_haetae_mode{2,3,5}.rsp` replayed through the NIST
  AES-256-CTR-DRBG: pk, sk and sig must match byte-for-byte and verify
  (`test-vectors/haetae-upstream/haetae{2,3,5}/`). The previous release's
  (v1.1.2) signatures under `v1.1.2-verify-only/` must still verify —
  v1.2.0 changed only the sampler — while no longer being what this crate
  produces.
* `tests/kat_vectors.rs` — the cross-language consensus fixtures
  `test-vectors/haetae/haetae{2,3,5}_kat.json` (keygen seed, `rnd` and
  context `pre` per record), which every language binding in the
  distribution also replays.
* `tests/kat_surface_gated.rs` — every seeded entry point stays behind
  `kat-internal`.
* unit tests under `src/` — NTT/FFT identities, fixed-point arithmetic,
  packing round trips, sign/verify and tamper rejection.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The Rust core follows the reference's arithmetic for secret-dependent
selection and comparison (challenge comparison by XOR accumulation, sampler
sign handling without secret-dependent branches), and secret keys are
zeroized on drop. **No timing or side-channel measurement has been made and
no independent audit has taken place**; treat the implementation as designed
for constant time and unmeasured. Fault and power attacks are out of scope.
HAETAE is a KpqC standard, not a NIST FIPS; no NIST validation exists for
it. See `SECURITY.md` at the root of the distribution for what a security
report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution. Written against the HAETAE v1.2.0 reference implementation by
Team HAETAE (MIT) and the rANS byte coder by Fabian Giesen (public domain);
their notices are in `THIRD_PARTY_NOTICES.md`.
