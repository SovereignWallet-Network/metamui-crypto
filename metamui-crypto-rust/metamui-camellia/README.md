# metamui-camellia

Camellia-128, -192 and -256 (RFC 3713) in Rust with ECB, CBC, CTR and GCM
modes, verified against the RFC 3713 Appendix A vectors.

## What is implemented

| entry point | what it does |
|---|---|
| `Camellia::new(&key)` | a cipher for a 16-, 24- or 32-byte key; `Camellia128/192/256::new` take the fixed-size array |
| `BlockCipher::{encrypt_block, decrypt_block}` | one 16-byte block in place |
| `ecb::{encrypt_ecb, decrypt_ecb}` | whole blocks only; provided for completeness, not recommended |
| `cbc::{encrypt_cbc, decrypt_cbc}` | 16-byte IV, PKCS#7 padded |
| `ctr::{process_ctr, encrypt_ctr, decrypt_ctr}` | 16-byte nonce/counter block |
| `gcm::{encrypt_gcm, decrypt_gcm}` | 12-byte nonce recommended, associated data, 16-byte tag; decryption releases nothing on a wrong tag |
| `generate_key(size)`, `generate_iv()` | from the operating system RNG (`random` feature); a failed RNG is `CamelliaError::RngFailure`, never a fixed value |

Keys are zeroed on drop.

## Usage

```rust
use metamui_camellia::{Camellia, gcm};

let key = [0u8; 32];
let cipher = Camellia::new(&key).unwrap();
let nonce = [1u8; 12];
let (ciphertext, tag) = gcm::encrypt_gcm(&cipher, &nonce, b"hello", b"aad").unwrap();
let plaintext = gcm::decrypt_gcm(&cipher, &nonce, &ciphertext, &tag, b"aad").unwrap();
assert_eq!(plaintext, b"hello");
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | standard library; without it the crate is `no_std` + `alloc` |
| `random` | yes | `generate_key` / `generate_iv` through `getrandom` |
| `no-std` | no | historical alias; has no effect beyond leaving `std` off |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. `#![forbid(unsafe_code)]`.

## Tests

```
cargo test -p metamui-camellia --release
```

* `tests/kat_vectors.rs` — `test-vectors/camellia/rfc3713-vectors.json`:
  the Appendix A block vectors for all three key sizes, encrypt and
  decrypt.
* unit tests in `src/` — mode round trips, tag rejection, key zeroing.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The S-boxes are table lookups indexed by key- and data-dependent bytes, as in the reference; that is the usual Camellia structure and is not claimed to be free of cache-timing effects. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
