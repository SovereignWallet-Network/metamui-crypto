# metamui-ntru-plus

NTRU+ lattice-based key encapsulation in Rust: a port of the NTRU+ authors'
2026 reference implementation (ntruplus.org, commit 621c667, specification of
2026-02-02; KpqC final round), verified byte-for-byte against the
reference's own known-answer files. The public entry surface of MetaMUI
Crypto is the `metamui-crypto` facade in this workspace; this crate is the
implementation behind its `ntru_plus` module and can also be used directly.

## Parameter sets

Ring R_q = Z_q[X] / (X^N − X^(N/2) + 1) with the prime q = 3457 for every
set; the shared secret is 32 bytes.

| parameter set | NIST category | N | public key | secret key | ciphertext |
|---|---|---|---|---|---|
| `NtruPlus768` | 3 | 768 | 1 152 | 2 336 | 1 152 |
| `NtruPlus864` | 5 | 864 | 1 296 | 2 624 | 1 296 |
| `NtruPlus1152` | 5 | 1152 | 1 728 | 3 488 | 1 728 |

Sizes in bytes, from the reference `api.h`; every size is an associated
constant of `NtruPlusParams` (`PUBLIC_KEY_SIZE`, `SECRET_KEY_SIZE`,
`CIPHERTEXT_SIZE`). The 576 set of the 2025 KpqClean revision was dropped by
the 2026 revision and is not implemented.

## Usage

```rust
use metamui_ntru_plus::{NtruPlus, NtruPlus768, PublicKey, SecretKey, Ciphertext, NtruPlusError};

let (pk, sk) = NtruPlus::<NtruPlus768>::generate_keypair()?;
let (ct, ss_sender) = NtruPlus::<NtruPlus768>::encapsulate(&pk)?;
let ss_receiver = NtruPlus::<NtruPlus768>::decapsulate(&ct, &sk)?;
assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());

// keys and ciphertexts travel as bytes
let pk2 = PublicKey::from_bytes::<NtruPlus768>(&pk.to_bytes())?;
let sk2 = SecretKey::from_bytes::<NtruPlus768>(&sk.to_bytes())?;
let ct2 = Ciphertext::from_bytes::<NtruPlus768>(&ct.to_bytes())?;
assert_eq!(NtruPlus::<NtruPlus768>::decapsulate(&ct2, &sk2)?.as_bytes(), ss_sender.as_bytes());
# Ok::<(), NtruPlusError>(())
```

Key generation and encapsulation draw their coins from the operating system
(`getrandom`) and return `RngError` when no source is available.
Decapsulation of a ciphertext that fails the re-encryption check returns an
all-zero shared secret rather than an error, exactly as the reference's
`ss[i] & ~(-fail)` does; a caller that needs an explicit failure compares
against zero. Wrong-size inputs are rejected as `InvalidKeySize` /
`InvalidCiphertext` before any arithmetic.

The deterministic entry points the reference KAT harness replays —
`kem::generate_keypair_det(randombytes)` and
`kem::encapsulate_det(pk, randombytes)` — are compiled only with the
`kat-internal` feature; an application is never offered a seed.

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | `std::error::Error` for `NtruPlusError`, `getrandom/std`; without it the crate is `no_std` + `alloc` |
| `kat-internal` | no | deterministic entry points (`generate_keypair_det`, `encapsulate_det`). Compiled for this crate's own tests; an application is never offered a seed |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. The mixed-radix NTT with
Montgomery and Barrett reduction is ported butterfly for butterfly so that
serialized NTT-domain bytes match the reference. Hashing is MetaMUI's own
`metamui-shake` (SHAKE-256 for hash_f, hash_g, hash_h and the keygen tape).

## Tests

```
cargo test -p metamui-ntru-plus --release
```

* `tests/upstream_ntru_plus_kat.rs` — the NTRU+ authors' own
  `PQCkemKAT_*.rsp` records (`test-vectors/ntru-plus-upstream/ntru-plus-upstream.json`,
  five per parameter set) replayed through the NIST AES-256-CTR-DRBG: pk, sk,
  ct and ss must match byte-for-byte and decapsulation must recover ss. The
  oracle's provenance line must name the ntruplus.org reference.
* `tests/kat_surface_gated.rs` — every deterministic entry point stays
  behind `kat-internal`.
* unit tests under `src/` — KEM round trips, wrong-key and tampered-ciphertext
  rejection, NTT/INTT identity, the reference `api.h` sizes.

A missing or altered vector file fails the run; nothing skips.

## What is and is not claimed

Decapsulation compares the re-derived ciphertext with a constant-time byte
comparison and masks the shared secret on failure without a
secret-dependent branch, as the reference does. **No timing or side-channel
measurement has been made and no independent audit has taken place**; treat
the implementation as designed for constant time and unmeasured. Secret key
material is not zeroized on drop. Fault and power attacks are out of scope.
NTRU+ is a KpqC selection, not a NIST FIPS; no NIST validation exists for
it. See `SECURITY.md` at the root of the distribution for what a security
report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution. Written against the NTRU+ reference implementation by the
NTRU+ team (MIT); its notice is in `THIRD_PARTY_NOTICES.md`.
