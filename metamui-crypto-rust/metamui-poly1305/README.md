# metamui-poly1305

Poly1305 (RFC 8439 §2.5) in Rust, verified against the RFC 8439 vectors.
Two implementations of the same function ship: the default one evaluates
the polynomial with arbitrary-precision integers, the `optimized` one with
five 26-bit limbs in 64-bit words; both are portable scalar code and both
are replayed against the vectors.

## What is implemented

| entry point | what it does |
|---|---|
| `poly1305_mac(message, key)` | 16-byte tag for a 32-byte one-time key |
| `poly1305_verify(message, key, tag)` | constant-shape comparison |
| `Poly1305::new(key)`, `update`, `finalize` | streaming |
| `Poly1305Optimized`, `poly1305_mac_optimized` (`optimized` feature) | the limb implementation, same API |

**A Poly1305 key is used once.** Two messages under one key let anyone
forge tags. In practice the key is derived per message by a cipher, as
ChaCha20-Poly1305 does.

## Usage

```rust
use metamui_poly1305::{poly1305_mac, poly1305_verify};

let key = [7u8; 32];                       // one-time key from the protocol
let tag = poly1305_mac(b"hello", &key).unwrap();
assert!(poly1305_verify(b"hello", &key, &tag).unwrap());
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | standard library; without it the crate is `no_std` + `alloc` |
| `optimized` | yes | the 26-bit-limb implementation next to the big-integer one |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection.

## Tests

```
cargo test -p metamui-poly1305 --release
```

* `tests/kat_vectors.rs` — `test-vectors/chacha20/rfc8439-vectors.json`,
  section `poly1305_mac` (RFC 8439 §2.5.2 and Appendix A.3), through
  `poly1305_mac`, the streaming `Poly1305` split at every block boundary,
  and `poly1305_mac_optimized`.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The big-integer path allocates and its running time depends on the operand values, so it is not designed for constant time; the limb path is fixed-shape arithmetic. Neither has been measured. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
