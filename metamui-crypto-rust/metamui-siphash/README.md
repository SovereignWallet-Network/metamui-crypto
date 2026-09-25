# metamui-siphash

SipHash in Rust — SipHash-2-4, SipHash-1-3 and SipHash-4-8 with 64- and
128-bit outputs — verified against the reference vectors of Aumasson and
Bernstein.

## What is implemented

| entry point | what it does |
|---|---|
| `hash64(&key, data)`, `hash128(&key, data)` | one-shot SipHash-2-4 with a 16-byte key |
| `SipHash64::new(&key)` / `SipHash128::new(&key)`, `new_with_params`, `update`, `finalize`, `reset` | streaming; `Parameters` selects `SIPHASH_2_4`, `SIPHASH_1_3` or `SIPHASH_4_8` |
| `mac(&key, message)`, `verify(mac, &key, message)` | 8-byte tag and its constant-shape check |
| `generate_key()` | 16 random bytes from the operating system (`std` feature) |

SipHash is a keyed PRF for short inputs (hash tables, short-message MACs).
Its 64-bit output is not collision resistant and it is not a general
cryptographic hash.

## Usage

```rust
use metamui_siphash::{hash64, SipHash64, SIPHASH_1_3};

let key = [0u8; 16];
let h = hash64(&key, b"hello");
let mut s = SipHash64::new_with_params(&key, SIPHASH_1_3);
s.update(b"hello");
assert_ne!(s.finalize(), h);           // a different variant, a different value
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | `generate_key` through `getrandom`; without it the crate is `no_std` |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection.

## Tests

```
cargo test -p metamui-siphash --release
```

* `tests/kat_vectors.rs` — `test-vectors/siphash/siphash-reference-vectors.json`,
  the 64 reference vectors (veorq/SipHash) through the one-shot and
  streaming APIs.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The round function is fixed-shape arithmetic on 64-bit words with no secret-dependent branch or table index. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
