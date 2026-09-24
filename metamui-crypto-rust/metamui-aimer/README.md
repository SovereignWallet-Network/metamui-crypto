# metamui-aimer

AIMer digital signatures in Rust: the MPC-in-the-head scheme over the AIM
one-way function by Samsung SDS and KAIST, a winner of the Korean
post-quantum cryptography competition (KpqC). The crate carries two
generations of the scheme, both verified against the algorithm authors' own
known-answer files, and they are not interoperable:

* **Specification v3** (2026-08-26; the `v3` module) — the AIM3 one-way
  function, per-S-box multiplication checks and keygen retry. This is what
  new code should use.
* **Specification v2.1** (spec v260130; the `Aimer<P>` / `Aim2er*` types) —
  the AIM2 scheme, kept because existing signatures are verified with it.

## Parameter sets and sizes

Specification v3 (`v3::Aimer*`), bytes:

| set | level | τ / N | public key | secret key | signature |
|---|---|---|---|---|---|
| `Aimer128f` | 1 | 33 / 16 | 32 | 48 | 6944 |
| `Aimer128s` | 1 | 17 / 256 | 32 | 48 | 4704 |
| `Aimer192f` | 3 | 49 / 16 | 48 | 72 | 15408 |
| `Aimer192s` | 3 | 25 / 256 | 48 | 72 | 10320 |
| `Aimer256f` | 5 | 65 / 16 | 64 | 96 | 31360 |
| `Aimer256s` | 5 | 33 / 256 | 64 | 96 | 20224 |

Wire formats: `pk = iv ‖ ct`, `sk = pt ‖ iv ‖ ct`, signature
`salt ‖ h₁ ‖ h₂ ‖ τ proofs`; the attached form is `m ‖ sig`. Every size is
a constant of `v3::AimerV3Params`.

Specification v2.1 (`Aim2er*`), bytes:

| set | public key | secret key | signature |
|---|---|---|---|
| `Aim2erI` (128s) | 32 | 48 | 4160 |
| `Aim2erIF` (128f) | 32 | 48 | 5888 |
| `Aim2erIII` (192s) | 48 | 72 | 9120 |
| `Aim2erIIIF` (192f) | 48 | 72 | 13056 |
| `Aim2erV` (256s) | 64 | 96 | 17056 |
| `Aim2erVF` (256f) | 64 | 96 | 25120 |

## Usage

Specification v3, with a context string as the reference API has it:

```rust
use metamui_aimer::v3::{self, Aimer128f};

let (pk, sk) = v3::generate_keypair::<Aimer128f>()?;
let sig = v3::sign_with_ctx::<Aimer128f>(b"hello", b"ctx", &sk)?;
assert!(v3::verify_with_ctx::<Aimer128f>(&sig, b"hello", b"ctx", &pk));

// empty-context shorthands
let sig = v3::sign::<Aimer128f>(b"hello", &sk)?;
assert!(v3::verify::<Aimer128f>(&sig, b"hello", &pk));
# Ok::<(), metamui_aimer::v3::V3Error>(())
```

`v3::sign_with_rnd` and `v3::generate_keypair_with` take the randomness from
the caller; `v3::keypair_from_pt_iv`, `v3::sign_internal` and
`v3::verify_internal` are the reference's `*_internal` entry points.

Specification v2.1:

```rust
use metamui_aimer::{Aimer, Aim2erI};

let (pk, sk) = Aimer::<Aim2erI>::generate_keypair()?;
let sig = Aimer::<Aim2erI>::sign(b"hello", &sk)?;
assert!(Aimer::<Aim2erI>::verify(b"hello", &sig, &pk)?);
let bytes = sig.to_bytes::<Aim2erI>();
# Ok::<(), metamui_aimer::AimerError>(())
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | operating-system randomness (`getrandom`) and the `v3::backend::install` hook; without it the crate is `no_std` + `alloc` |
| `parallel` | no | Rayon parallelism inside the v2.1 signer and verifier; the outputs are the same bytes |
| `aim-v2` | yes | accepted no-op. AIM2 is the only v2.1 cipher this crate implements; the name is kept so manifests that still pass it keep resolving |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection, and the carry-less
multiply of the field arithmetic is the software one. There is no `accel`
feature any more. The v3 key generation, signing and verification go through
`v3::backend::backend()`, which is `None` — the reference in `v3::sign` —
unless a separately maintained crate installs an implementation of the same
scheme once, with `v3::backend::install`, before the first v3 operation of
the process. A backend must reproduce the reference bytes exactly. This crate
ships no backend.

## Tests

```
cargo test -p metamui-aimer --release
```

The gates read the vendored upstream vectors under
`test-vectors/aimer-upstream/`; a missing vector file fails the run, nothing
skips.

* `tests/aimer_v3_upstream_kat.rs` — specification v3: every record of the
  authors' `PQCsignKAT_{48,72,96}.rsp` for all six sets
  (`test-vectors/aimer-upstream/aimer-{128,192,256}{f,s}/`) replayed through
  the NIST DRBG schedule; pk, sk and `sm` byte-exact, the signature verifies,
  a flipped byte does not.
* `tests/aimer_upstream_kat.rs` — specification v2.1, verify side: genuine
  upstream signatures from `test-vectors/aimer-upstream/v2.1/` are accepted.
* `tests/aimer_sign_kat.rs` — specification v2.1, sign side: seeded keygen and
  signing reproduce the upstream `pk`, `sk` and `sig` bytes.
* `tests/aimer_v2_kat.rs`, `tests/aim2_signing.rs`,
  `tests/signing_properties.rs` — v2.1 structure, round trips and rejection
  of tampered signatures.

## What is and is not claimed

The v3 port compares digests in constant time and its field multiply is
written without secret-dependent branches; the v2.1 secret key and MPC state
are zeroized on drop. **No timing or side-channel measurement has been made
and no independent audit has taken place**; treat the implementation as
designed for constant time and unmeasured. Fault and power attacks are out of scope.
See `SECURITY.md` at the root of the distribution for what a security report
should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution. Written against the AIMer reference implementations by
Samsung SDS; their notice is in `THIRD_PARTY_NOTICES.md`.
