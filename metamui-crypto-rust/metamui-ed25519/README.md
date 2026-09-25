# metamui-ed25519

Ed25519 digital signatures (RFC 8032, §5.1) in portable scalar Rust, verified
against the RFC 8032 §7.1 vectors and a strict-profile corpus. The
`metamui-ed25519-wasm` wrapper in this distribution is a thin binding over
this crate; the crate can also be used directly.

## What is implemented

| operation | rule |
|---|---|
| key generation | `(a, prefix) = SHA-512(seed)`, `a` clamped, `A = [a]B`; the 32-byte seed is the secret key (RFC 8032 §5.1.5) |
| signing | deterministic: `r = SHA-512(prefix ‖ M)`, `R = [r]B`, `S = r + SHA-512(R ‖ A ‖ M)·a mod L` (§5.1.6). The same seed and message always give the same 64 bytes |
| verification | RFC 8032 as written: §5.1.3 decoding of `A` and `R`, `S < L`, the cofactored equation `[8][S]B = [8]R + [8][H(R ‖ A ‖ M)]A`, and no small-order screen (one policy on every target, decided 2026-09-24) |

Verification is *not* the ZIP-215 rule set (which admits non-canonical
encodings); that is a separate crate, `metamui-crypto-ed25519-zip215`.
`verify_strict` is the same policy as `verify` and is kept for source
compatibility. Both return
`Err(InvalidSignature | InvalidPoint)` when a component does not decode and
`Ok(false)` when it decodes but the equation fails.

## Sizes

| item | bytes |
|---|---|
| seed (`SEED_SIZE`) | 32 |
| public key (`PUBLIC_KEY_SIZE`) | 32 (compressed Edwards `y` with the `x` sign bit) |
| private key (`PRIVATE_KEY_SIZE`) | 64 = seed ‖ SHA-512 prefix; `PrivateKey::as_seed` returns the 32-byte seed |
| signature (`SIGNATURE_SIZE`) | 64 = `R` ‖ `S` |

## Usage

```rust
use metamui_ed25519::{generate_keypair, keypair_from_seed, sign, verify, Signature};

let kp = generate_keypair()?;                  // seed from the operating system
let sig = sign(&kp.private, b"hello")?;
assert!(verify(&sig, b"hello", &kp.public)?);

// A seed is an ordinary secret key: the same seed reproduces the same keypair.
let kp2 = keypair_from_seed(kp.private.as_seed())?;
assert_eq!(kp.public, kp2.public);

// Wire round trip.
let sig2 = Signature::from_bytes(sig.to_bytes());
assert!(kp.public.verify(&sig2, b"hello")?);
# Ok::<(), metamui_ed25519::Ed25519Error>(())
```

`Keypair::generate` draws the seed from `getrandom`; every other entry point
is deterministic. `batch_verify`, `batch_verify_same_message` and
`BatchVerifier` return one `bool` per signature and are computed by verifying
each signature on its own; there is no aggregated multi-scalar equation, so
their decisions are exactly those of `verify`.

The `field`, `point`, `scalar`, `constant_time` and `montgomery` modules are
the arithmetic the API above is built on and are public for the tests. The
`ed25519_montgomery` module is an unfinished
Montgomery-arithmetic backend: its `keypair_from_seed_montgomery`,
`sign_montgomery` and `verify_montgomery` return `Ed25519Error::NotImplemented`
and are not part of the contract.

## Features

None. Every code path is portable scalar Rust; there is no SIMD, assembly or
GPU path and no CPU-feature detection. Hashing is the in-tree
`metamui-sha2`; no external crypto crate is in the dependency closure.

## Tests

```
cargo test -p metamui-ed25519 --release
```

Every gate reads its vectors from `test-vectors/ed25519/` at the root of the
distribution; a missing file fails the run, nothing skips.

* `tests/rfc8032_tests.rs` — `rfc8032-vectors.json`: for each RFC 8032 §7.1
  vector, public-key derivation, the byte-exact signature, acceptance by
  `verify` and `verify_strict`, determinism, and rejection of a tampered
  message, signature and public key.
* `tests/kat_vectors.rs` — `zip215-vectors.json`: the RFC 8032-as-written
  verdict pinned per case must match; it differs from the corpus's retired
  `valid_strict` column only on the canonical small-order keys, which the
  test asserts too.
* `tests/ed25519_policy_vectors.rs` — `ed25519-policy-vectors.json`: the
  policy oracle shared by every target.
* `tests/comprehensive_tests.rs` — `ed25519-comprehensive-vectors.json`:
  basic operations, edge cases (empty and long messages), the malleability
  set (`S ≥ L`, non-canonical encodings), batch decisions, public-key
  derivation and zeroization.
* `tests/basic_tests.rs`, `tests/security_tests.rs` — deterministic signing,
  invalid-point rejection, signature-size enforcement, zeroization on drop.

## What is and is not claimed

Secret-dependent selection and comparison use `subtle` idioms, and secret
material is zeroized on drop. **No timing or side-channel measurement has
been made and no independent audit has taken place**; treat the
implementation as designed for constant time and unmeasured. Fault and power
attacks are out of scope. See `SECURITY.md` at the root of the distribution
for what a security report should contain.

### Package name

Until 1.0.0-rc.4 this package was published as `metamui-crypto-ed25519`
(library `metamui_crypto_ed25519`). The code is the same portable scalar
implementation; a consumer pinning the old name must update the dependency
name and the `use` path:

```toml
metamui-ed25519 = "1.0.0-rc.4"
```

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution. The field arithmetic follows the public-domain ref10
implementation (Daniel J. Bernstein et al., SUPERCOP); its notice is in
`THIRD_PARTY_NOTICES.md`.
