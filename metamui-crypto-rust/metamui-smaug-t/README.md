# metamui-smaug-t

SMAUG-T v1.2.0 key encapsulation in Rust: the KpqC standard KEM
(Module-LWR with sparse ternary secrets, Fujisaki-Okamoto transform with
implicit rejection), byte-exact to the CryptoLab reference implementation's
known-answer vectors, and to the other language bindings of MetaMUI Crypto
(https://github.com/SovereignWallet-Network/metamui-crypto).

The crate implements reference implementation v1.2.0 (specification
v260521), which fixed the v1.1.1 discrete-Gaussian tape unpacking bug; every
key and ciphertext byte differs from v1.1.1. There is no "SMAUG-T v4.0".

## Parameter sets and sizes

| set | NIST level | k | log2 q | public key | secret key | ciphertext | shared secret |
|---|---|---|---|---|---|---|---|
| SMAUG-T1 (`Mode1` / `Level1`) | 1 | 2 | 10 | 672 bytes | 832 bytes | 672 bytes | 32 bytes |
| SMAUG-T3 (`Mode3` / `Level3`) | 3 | 3 | 11 | 1088 bytes | 1312 bytes | 992 bytes | 32 bytes |
| SMAUG-T5 (`Mode5` / `Level5`) | 5 | 4 | 11 | 1440 bytes | 1728 bytes | 1376 bytes | 32 bytes |
| TiMER (`ModeT` / `LevelT`) | 1 | 2 | 10 | 672 bytes | 832 bytes | 608 bytes | 32 bytes |

The secret key embeds the public key (the `crypto_kem_*` layout of the
reference), so decapsulation takes only `(secret_key, ciphertext)`. TiMER is
the compact set with D2 encoding and a 16-byte encapsulation message; it is
not a NIST level and is reachable only as `SmaugV1Mode::ModeT` /
`SecurityLevel::LevelT`, never from a numeric level. Every size is derived
from the constants in `smaug_v1_2_0::params`.

## Usage

```rust
use metamui_smaug_t::{SmaugTV1, SmaugV1Mode};
use rand_core::OsRng;

let kem = SmaugTV1::new(SmaugV1Mode::Mode3);
let (public_key, secret_key) = kem.keygen(&mut OsRng);
let (ciphertext, ss_sender) = kem.encapsulate(&public_key, &mut OsRng)?;
let ss_receiver = kem.decapsulate(&secret_key, &ciphertext)?;
assert_eq!(ss_sender, ss_receiver);
# Ok::<(), metamui_smaug_t::SmaugV1Error>(())
```

`SmaugTV1` is the reference-shaped API over `Vec<u8>`. `SmaugT` is the same
algorithm behind the crate's newtypes (`PublicKey`, `SecretKey`,
`Ciphertext`, `SharedSecret`) and draws from operating-system randomness;
it is a thin facade with no behavioural difference. Every input is
length-checked before any arithmetic runs; the KEM itself never fails, since a
malformed-but-correct-length ciphertext yields a pseudorandom secret
(implicit rejection) rather than an error. Secret keys and shared secrets are
zeroized on drop, and `SharedSecret` compares with `subtle::ConstantTimeEq`.

## Features

| feature | default | what it does |
|---|---|---|
| `serde_feature` | no | `serde` derives on `SecurityLevel` |
| `kat-internal` | no | seeded entry points (`keygen_from_seed` on both APIs). Compiled for this crate's own tests; an application is never offered a seed |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. Hashing is the in-house
`metamui-shake` / `metamui-sha3`; no RustCrypto crate is in the closure.

### Package name

Until 1.0.0-rc.3 this package was published as `metamui-smaug-t-optimized`
(library `metamui_smaug_t_optimized`). The code is the same portable scalar
implementation; a consumer pinning the old name must update the dependency
name and the `use` path:

```toml
metamui-smaug-t = "1.0.0-rc.3"
```

## Tests

```
cargo test -p metamui-smaug-t --release
```

* `tests/v1_2_0_kat_byte_equality.rs` — decapsulation of every record in
  `test-vectors/smaug-t/v1.2.0-kat/smaugt-mode{1,3,5,t}-v1.2.0-kat.json`
  reproduces the reference shared secret.
* `tests/v1_2_0_full_kat_byte_equality.rs` — the full NIST KAT flow
  (AES-CTR-DRBG → `keypair_internal` → `enc_internal`) reproduces the
  reference public key, secret key, ciphertext and shared secret bytes from
  the same files.
* `tests/public_api_v1_2_0.rs` — the same byte-equality through the public
  `SmaugTV1` surface, plus length-error typing and round trips.
* `tests/pack_ring_v1_2_0.rs` — ring packing against
  `test-vectors/smaug-t/v1.1.1-packring/mode{1,3,5,t}.txt`.
* `tests/python_compatibility_test.rs` — the cross-binding size table.
* `tests/seed_keygen_test.rs` — the seeded convenience is deterministic
  (behind `kat-internal`).
* `tests/kat_surface_gated.rs` — every seeded entry point stays behind
  `kat-internal`.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The Rust core is written with constant-time idioms for secret-dependent
selection and comparison, and secret material is zeroized on drop. **No
timing or side-channel measurement has been made and no independent audit
has taken place**; treat the implementation as designed for constant time
and unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution. Written against the SMAUG-T v1.2.0 reference implementation
by the SMAUG-T team (MIT); its notice belongs in `THIRD_PARTY_NOTICES.md` at
the root of the distribution.
