# metamui-hmac-drbg

HMAC_DRBG (NIST SP 800-90A Rev. 1) in Rust over the in-tree `metamui-sha2`
— HMAC-SHA256, HMAC-SHA384 and HMAC-SHA512 — verified against the NIST
ACVP hmacDRBG vectors.

## What is implemented

| entry point | what it does |
|---|---|
| `HmacDrbg::new(entropy, nonce, personalization, HashAlgorithm)` | instantiate; entropy is 32 to 1000 bytes and comes from the caller |
| `generate(out, additional_input)` | up to `MAX_REQUEST_LENGTH` bytes per call; the reseed counter is enforced |
| `generate_with_resistance(out, additional_input, prediction_resistance)` | as above, refusing when a reseed is due |
| `reseed(entropy, additional_input)` | SP 800-90A §10.1.2.4 |
| `run_self_tests()` | known-answer self-test of the three hash variants |
| `uninstantiate()` | zeroes the state |
| `health_tests::{HealthTests, ContinuousTest}` | SP 800-90B-style repetition and adaptive-proportion checks on output |

The DRBG is deterministic in its inputs by definition: this crate draws no
entropy of its own and every byte of seed material is the caller's.
Choosing that seed material is the caller's protocol decision.

## Usage

```rust
use metamui_hmac_drbg::{HashAlgorithm, HmacDrbg};

let entropy = [0x11u8; 32];               // from a real entropy source in use
let mut drbg = HmacDrbg::new(&entropy, Some(b"nonce"), Some(b"app"), HashAlgorithm::Sha256).unwrap();
let mut out = [0u8; 64];
drbg.generate(&mut out, None).unwrap();
drbg.reseed(&[0x22u8; 32], None).unwrap();
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | standard library; without it the crate is `no_std` + `alloc` |
| `cavp` | no | the `cavp` module: `serde` types for CAVP/ACVP response files and a runner that replays them |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection.

## Tests

```
cargo test -p metamui-hmac-drbg --release
```

* `tests/kat_vectors.rs` — `test-vectors/hmac-drbg/hmac-drbg-vectors.json`,
  the ACVP hmacDRBG-1.0 internal projection: the six SHA2-256/384/512
  groups (with and without prediction resistance, each with a reseed),
  replayed through the public API; the SHA-1, SHA2-224/512-224/512-256 and
  SHA-3 groups in the file are for hashes this crate does not offer.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

This is an implementation of SP 800-90A, not a validated module: no CMVP or CAVP certificate exists for it. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
