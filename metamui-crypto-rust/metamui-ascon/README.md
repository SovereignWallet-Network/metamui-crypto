# metamui-ascon

The four functions of NIST SP 800-232 in Rust — Ascon-AEAD128,
Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 — verified byte for byte
against the reference implementation's known-answer files.

## What is implemented

| function | entry point | sizes |
|---|---|---|
| Ascon-AEAD128 | `AsconAead128::new(key)`, `AsconAead::{encrypt, decrypt}` | 16-byte key, nonce and tag |
| Ascon-Hash256 | `ascon_hash256`, `AsconHash256` (streaming) | 32-byte digest (`DIGEST_LEN`) |
| Ascon-XOF128 | `ascon_xof128`, `AsconXof128` + `AsconXof128Reader` | any output length |
| Ascon-CXOF128 | `ascon_cxof128`, `AsconCxof128` + `AsconCxof128Reader` | any output length; customization string up to `MAX_CUSTOMIZATION_LEN` bytes |

Decryption returns `Err(AsconError::AuthenticationFailed)` on a wrong tag
and releases no plaintext. Key material is zeroed on drop.

## Usage

```rust
use metamui_ascon::{AsconAead, AsconAead128, ascon_hash256};

let key = [0u8; 16];
let nonce = [0u8; 16];
let ascon = AsconAead128::new(key);
let (ciphertext, tag) = ascon.encrypt(&nonce, b"hello", b"aad").unwrap();
let plaintext = ascon.decrypt(&nonce, &ciphertext, &tag, b"aad").unwrap();
assert_eq!(plaintext, b"hello");
assert_eq!(ascon_hash256(b"").len(), 32);
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | `std::error::Error` on `AsconError`; without it the crate is `no_std` + `alloc` |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. `#![deny(unsafe_code)]`.

## Tests

```
cargo test -p metamui-ascon --release
```

* `tests/upstream_sp800232_gate.rs` — the reference implementation's
  `LWC_*_KAT` files under `test-vectors/ascon-upstream/` (AEAD128 1089
  cases, Hash256, XOF128 and CXOF128), replayed through the public API.
* `tests/kat_vectors.rs`, `tests/hash_kat.rs` —
  `test-vectors/ascon/ascon-vectors.json` and
  `test-vectors/ascon/ascon-hash256-kat.json`.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The permutation is fixed-shape arithmetic on 64-bit words with no secret-dependent branch or table index. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
