# metamui-keccak256

Keccak-256 in Rust: the original Keccak with the `0x01` domain byte in its
pad10*1 padding, as Ethereum uses it, verified against Ethereum answer
files. This is **not** SHA3-256 (FIPS 202), which pads with `0x06` and gives
different digests for the same input; SHA3-256 lives in `metamui-sha3`.

## What is implemented

| item | value |
|---|---|
| permutation | Keccak-f[1600], 24 rounds |
| rate / capacity | 1088 / 512 bits (`BLOCK_SIZE` = 136 bytes) |
| padding | `0x01 … 0x80` (pre-FIPS 202 Keccak) |
| output | 32 bytes (`HASH_SIZE`), the first four state lanes little-endian |

## Usage

```rust
use metamui_keccak256::{keccak256, keccak256_hex, Keccak256};

let digest = keccak256(b"hello");                 // [u8; 32]
assert_eq!(keccak256_hex(b"hello"), format!("0x{}", hex::encode(digest)));

let mut hasher = Keccak256::new();
hasher.update(b"hel");
hasher.update(b"lo");
assert_eq!(hasher.finalize(), digest);
```

`keccak256` is the one-shot digest, `keccak256_hex` the same as a
`0x`-prefixed lowercase hex string, and `Keccak256` (`new`, `update`,
`finalize`) the streaming form.

## Features

| feature | default | what it does |
|---|---|---|
| `std` | no | links `std`; without it the crate is `no_std` and uses `alloc` for `keccak256_hex` |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection.

## Tests

```
cargo test -p metamui-keccak256 --release
```

* `tests/kat_vectors.rs` — `test-vectors/keccak256/keccak256-vectors.json`,
  Keccak-256 answers taken from the Ethereum test suites (the empty message
  and short ASCII inputs), replayed through `keccak256`.
* unit tests in `src/lib.rs` — the empty-message and `"hello"` digests,
  streaming equals one-shot, and the digest differing from SHA3-256.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

Keccak-256 hashes public data; the permutation is fixed-shape arithmetic on
64-bit lanes with no data-dependent branch or table index, and the hasher
does not zero its state on drop. **No timing or side-channel measurement has
been made and no independent audit has taken place.** Fault and power
attacks are out of scope. See `SECURITY.md` at the root of the distribution
for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
