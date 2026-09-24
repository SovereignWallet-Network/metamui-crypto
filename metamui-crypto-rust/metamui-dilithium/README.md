# metamui-dilithium

ML-DSA-44, ML-DSA-65 and ML-DSA-87 (NIST FIPS 204) digital signatures in
Rust, verified against the NIST ACVP answer files. The crate and type names
keep the CRYSTALS-Dilithium history (`Dilithium2/3/5`); `MlDsa44/65/87` are
the FIPS 204 names for the same types.

## Parameter sets

| parameter set | type | (k, ℓ) | public key | secret key | signature |
|---|---|---|---|---|---|
| ML-DSA-44 | `Dilithium2` / `MlDsa44` | (4, 4) | 1312 bytes | 2560 bytes | 2420 bytes |
| ML-DSA-65 | `Dilithium3` / `MlDsa65` | (6, 5) | 1952 bytes | 4032 bytes | 3309 bytes |
| ML-DSA-87 | `Dilithium5` / `MlDsa87` | (8, 7) | 2592 bytes | 4896 bytes | 4627 bytes |

Every size is an associated constant (`PUBLIC_KEY_SIZE`, `SECRET_KEY_SIZE`,
`SIGNATURE_SIZE`) and a field of the `params::ML_DSA_*_PARAMS` records.

## Usage

```rust
use metamui_dilithium::MlDsa65;

let mut rng = rand::rngs::OsRng;
let (pk, sk) = MlDsa65::generate_keypair_with_rng(&mut rng);

// deterministic ML-DSA.Sign (FIPS 204 Algorithm 2 with rnd = 0^32)
let sig = MlDsa65::sign(&sk, b"hello");
assert!(MlDsa65::verify(&pk, b"hello", &sig));

// hedged ML-DSA.Sign: 32 fresh bytes of rnd from the caller's RNG
let sig = MlDsa65::sign_with_rng(&sk, b"hello", &mut rng);
assert!(MlDsa65::verify(&pk, b"hello", &sig));
```

`generate_keypair`, `sign_hedged` and `sign_randomized` draw from the
operating-system RNG (feature `std`, on by default). `sign` is the
deterministic variant and stays so because consumers pin its bytes;
`sign_deterministic` on `Dilithium3`/`Dilithium5` is the same function under
the FIPS 204 name. The remaining FIPS 204 interfaces are
`sign_with_context`/`verify_with_context` (pure ML-DSA with a context string
of at most 255 bytes), `hash_sign_with`/`hash_verify_with` (HashML-DSA with
the pre-hash OIDs from `metamui-prehash-oids`), `sign_internal`/
`verify_internal` and `sign_external_mu`/`verify_external_mu` (the internal
and external-μ interfaces the ACVP vectors exercise). The `signature` crate
traits are implemented by `Dilithium{2,3,5}SigningKey`/`VerifyingKey`.

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | operating-system randomness helpers |
| `kat-internal` | no | seeded entry points (`generate_keypair_from_seed`, FIPS 204 `ML-DSA.KeyGen_internal(ξ)`). Compiled for this crate's own tests; an application is never offered a seed |
| `legacy-benches` | no | opt-in gate for the bit-rotted `benches/dilithium_bench.rs` |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. The arithmetic that
decides a signature's bytes is the same arithmetic on every target.

## Tests

```
cargo test -p metamui-dilithium --release
```

* `tests/upstream_acvp_gate.rs` — the genuine NIST ACVP-Server keyGen,
  sigGen and sigVer answer files (`test-vectors/ml-dsa-upstream/keygen.json`,
  `siggen.json`, `siggen-tr1.json`, `sigver.json`) replayed byte-for-byte
  across every FIPS 204 interface: pure with context, HashML-DSA pre-hash,
  internal and external μ, deterministic and hedged with explicit `rnd`.
* `tests/ml_dsa_test_vectors.rs` and `tests/acvp_integration_tests.rs` —
  the keyGen records in `test-vectors/ml-dsa/ml-dsa-{44,65,87}-kat.json`,
  and the ACVP parser round trip over `ml-dsa-44-kat.json`.
* `tests/fips204_integration.rs`, `tests/fips204_compliance_tests.rs`,
  `tests/nist_test_vectors.rs` — parameter, encoding and round-trip checks
  for all three parameter sets.
* `tests/test_cross_language_compat.rs`, `tests/test_key_generation.rs` —
  the deterministic signing contract the other language bindings pin, and
  the `t = A·s1 + s2` key derivation.
* `tests/kat_surface_gated.rs` — the seeded key generation stays behind
  `kat-internal`.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The Rust core is written with constant-time idioms for secret-dependent
selection and comparison. **No timing or side-channel measurement has been
made and no independent audit has taken place**; treat the implementation
as designed for constant time and unmeasured. Fault and power attacks are
out of scope. See `SECURITY.md` at the root of the distribution for what a
security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
