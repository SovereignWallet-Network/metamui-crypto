# metamui-x25519

X25519 Diffie-Hellman key agreement (RFC 7748) in Rust, verified against
the RFC 7748 §5.2 and §6.1 vectors.

## What is implemented

| entry point | what it does |
|---|---|
| `generate_keypair()` | a `KeyPair` (32-byte private and public keys) from the operating system RNG |
| `keypair_from_seed(seed)` | the key pair whose private key is the caller's 32 bytes (clamped as RFC 7748 §5 requires) |
| `public_key_from_private(private)` | X25519(k, 9) |
| `key_exchange(private, peer_public)` | the 32-byte `SharedSecret`; an all-zero result is refused (`X25519Error`) |
| `is_valid_private_key`, `is_valid_public_key`, `is_valid_shared_secret` | length and low-order checks |
| `*_hex` variants, `format_hex`, `parse_hex` | the same over `0x`-prefixed hex strings |

Both a function-based API and the `MetaMUIX25519` type expose the same
operations. A private key is the seed here: `keypair_from_seed` is the
key-import path of RFC 7748, not a test hook.

## Usage

```rust
use metamui_x25519::{generate_keypair, key_exchange};

let alice = generate_keypair().unwrap();
let bob = generate_keypair().unwrap();
let ab = key_exchange(alice.private_key.clone(), bob.public_key.clone()).unwrap();
let ba = key_exchange(bob.private_key.clone(), alice.public_key.clone()).unwrap();
assert_eq!(ab.bytes, ba.bytes);
```

## Features

| feature | default | what it does |
|---|---|---|
| `native` | yes | a no-op kept for callers that still name it; there is one implementation |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection.

## Tests

```
cargo test -p metamui-x25519 --release
```

* `tests/kat_vectors.rs` — `test-vectors/x25519/rfc7748-vectors.json`: the
  §5.2 scalar-multiplication vectors, the iterated vector and the §6.1
  Alice/Bob exchange.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The Montgomery ladder is fixed-shape field arithmetic; the field elements are limbs in ordinary integers with no secret-dependent branch. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
