# metamui-flathash

FlatHash, the MetaMUI canonical hash of a JSON object: the document is
parsed, flattened to dot/bracket key paths, sorted by key, serialised to
one canonical string and hashed with the in-tree SHA-256. Two JSON texts
that describe the same object give the same 32-byte digest whatever their
key order or whitespace.

This crate re-exports the implementation that lives in
`metamui-crypto-utilities` (`flathash` feature) under a name of its own.

## What is implemented

| entry point | what it does |
|---|---|
| `flat_hash(&str)` | 32-byte digest of a JSON text |
| `flat_hash_hex(&str)` | the same, `0x`-prefixed hex |
| `MetaMUIFlatHash::new().hash(&str)` | the same through a hasher value |
| `FlatHash`, `FLATHASH_OUTPUT_SIZE` | the result type and its size (32) |

FlatHash is a MetaMUI convention, not a standard; the reference is this
implementation and the vectors under `test-vectors/flathash/` are the
contract every other MetaMUI binding must match.

## Usage

```rust
use metamui_flathash::{flat_hash, flat_hash_hex};

let a = flat_hash(r#"{"b": 1, "a": {"c": [1, 2]}}"#).unwrap();
let b = flat_hash(r#"{ "a": {"c": [1,2]}, "b": 1 }"#).unwrap();
assert_eq!(a, b);
assert!(flat_hash_hex(r#"{}"#).unwrap().starts_with("0x"));
```

## Features

None. Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection.

## Tests

```
cargo test -p metamui-flathash --release
```

* `tests/kat_vectors.rs` — `test-vectors/flathash/flathash-reference-vectors.json`,
  the 13 reference cases.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

FlatHash inherits SHA-256's properties for the canonical string; the canonicalisation itself is a deterministic transformation, not a cryptographic one. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
