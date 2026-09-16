# metamui-falcon512

Falcon-512 (NIST Round 3) digital signatures in Rust, with the two Round-3
wire encodings and a Falcon-1024 module, verified against the algorithm
authors' own known-answer files. The public entry surface of MetaMUI Crypto
is the `metamui-crypto` facade in this workspace; this crate is the
implementation behind its `falcon512` module and can also be used directly.

## Profiles and encodings

| profile | public key | secret key | signature |
|---|---|---|---|
| `falcon-512.r3-compressed` | 897 bytes (`0x09 ‖ 14-bit h`) | 1281 bytes (`0x59 ‖ f ‖ g ‖ F`) | `0x39 ‖ nonce(40) ‖ Golomb-Rice(s2)`, variable, at most 752 bytes |
| `falcon-512.r3-padded` | 897 bytes | 1281 bytes | exactly 666 bytes; non-zero padding is rejected |

The compressed verifier rejects trailing bytes; the reference `CRYPTO_BYTES`
of 690 is signed-message overhead, not a signature bound. Falcon-1024 uses the
same layouts with 1793 / 2305 / at most 1462 (compressed) / 1280 (padded)
bytes through the `falcon1024` module. Every size is a constant in `sizes`.

## Usage

```rust
use metamui_falcon512::{generate_keypair, sign, sign_padded, verify, verify_padded};

let mut rng = rand::rngs::OsRng;
let kp = generate_keypair(&mut rng)?;

// compressed profile (variable length)
let sig = sign(b"hello", &kp.private_key, &mut rng)?;
assert!(verify(b"hello", &sig, &kp.public_key)?);

// padded profile (fixed 666 bytes)
let sig = sign_padded(b"hello", &kp.private_key, &mut rng)?;
assert!(verify_padded(b"hello", &sig, &kp.public_key)?);
# Ok::<(), metamui_falcon512::Falcon512Error>(())
```

Every randomized operation takes a caller-supplied `RngCore`. `sign_hedged`
and `sign_padded_hedged` (feature `std`, on by default) draw from the
operating system and return `EntropyUnavailable` where no source exists
instead of signing with short randomness. Key generation and signing use
rejection sampling and retry internally; `sign_no_retry` exposes a single
attempt for callers that manage retries themselves.

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | operating-system randomness helpers |
| `kat-internal` | no | seeded and known-answer entry points (`kat_api`, `deterministic_mode`, the NIST DRBG replay). Compiled for this crate's own tests; an application is never offered a seed |
| `fn-dsa-draft` | no | FN-DSA (FIPS 206) draft hooks; not wire-compatible with Round-3 Falcon and out of contract until the standard is final |
| `optimized`, `avx512`, `sve2`, `metal`, `multithreading`, `batch-api` | no | platform acceleration and batch APIs; the outputs are the same bytes |
| `wasm-bindgen` | no | browser bindings |
| `fips` | no | requires `initialize()` (power-on self-tests) before use |

## Tests

```
cargo test -p metamui-falcon512 --release
```

* `tests/falcon_upstream_kat.rs` — the unmodified NIST Round-3
  `falcon512-KAT.rsp` and `falcon1024-KAT.rsp` replayed against the verifier
  (`test-vectors/falcon-upstream/`).
* `tests/falcon_padded_upstream_kat.rs` — PQClean `falcon-padded-{512,1024}`
  records for the padded profile.
* `tests/signature_framing.rs` — every malformed shape (truncated, trailing
  byte, wrong header, non-zero padding) is rejected before any success value.
* `tests/distribution_conformance.rs` — a two-sided band on the signature
  norm distribution, which a KAT cannot see.
* `tests/htp_golden_test.rs` — hash-to-point golden vectors.
* `tests/kat_surface_gated.rs` — every seeded module stays behind `kat-internal`.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The Rust core is written with constant-time idioms for secret-dependent
selection and comparison, and secret material is zeroized on drop. **No
timing or side-channel measurement has been made and no independent audit
has taken place**; treat the implementation as designed for constant time
and unmeasured. Fault and power attacks are out of scope. See `SECURITY.md` at the
root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution. Written against the Falcon reference implementation by Thomas
Pornin and the Falcon Project (MIT); its notice is in `THIRD_PARTY_NOTICES.md`.
