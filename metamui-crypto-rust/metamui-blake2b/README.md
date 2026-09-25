# metamui-blake2b

BLAKE2b (RFC 7693) in Rust: 256-, 384- and 512-bit digests, any output
length from 1 to 64 bytes, and keyed hashing with a key of up to 64 bytes,
verified against the RFC 7693 answer file and a block-boundary answer file.

## What is implemented

| output | entry point | result |
|---|---|---|
| BLAKE2b-256 | `blake2b256`, `hash`, `blake2_256` | `[u8; 32]`, `Blake2b256`, `[u8; 32]` |
| BLAKE2b-384 | `blake2b384` | `[u8; 48]` |
| BLAKE2b-512 | `blake2b_512`, `blake2b_512_hex`, `MetaMUIBlake2b512` | `Blake2b512Hash` (a `[u8; 64]` newtype), `0x`-prefixed hex |
| 1–64 bytes | `blake2b_variable`, `blake2b_variable_keyed` | `Vec<u8>` |
| streaming | `Blake2bHasher` (`new`, `new_with_output_size`, `new_keyed_with_output_size`, `update`, `finalize_256` / `finalize_512` / `finalize_variable`) | as above |

`blake2_256` and the `Blake2b256` wrapper exist for callers that expect the
Substrate `blake2_256` shape; they are the same digest as `blake2b256`. The
hasher follows RFC 7693 lazy finalization: the last block, full or partial,
is compressed by `finalize` with the final flag, so streamed input whose
`update` boundaries land on 128-byte multiples and the keyed hash of the
empty message produce the digest the specification gives. Hasher state is
zeroed when the hasher is finalized or dropped.

## Usage

```rust
use metamui_blake2b::{blake2b256, blake2b_512, blake2b_variable_keyed, Blake2bHasher};

let h256 = blake2b256(b"hello");                 // [u8; 32]
let h512 = blake2b_512(b"hello");                // Blake2b512Hash
let mac  = blake2b_variable_keyed(b"key", b"hello", 32);

let mut hasher = Blake2bHasher::new_with_output_size(32);
hasher.update(b"hel");
hasher.update(b"lo");
assert_eq!(hasher.finalize_256(), h256);
assert_eq!(h512.as_bytes().len(), 64);
```

## Features

| feature | default | what it does |
|---|---|---|
| `serde` | no | `Serialize`/`Deserialize` on the `Blake2b256` wrapper |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. The one-shot BLAKE2b-512
entry points (`blake2b_512`, `blake2b_512_hex`, `MetaMUIBlake2b512::hash`)
go through `backend::backend()`, whose default is `backend::PORTABLE`, the
streaming hasher run over the whole input; `backend::install` lets a
separate crate replace it once, before the first one-shot hash of the
process, with an implementation of the same function. The streaming hasher
and the 256-, 384-bit, variable-length and keyed entry points do not consult
the hook. This crate ships no other backend.

## Tests

```
cargo test -p metamui-blake2b --release
```

* `tests/kat_vectors.rs` — the RFC 7693 BLAKE2b-512 answer
  (`test-vectors/blake2/rfc7693-vectors.json`) and inline BLAKE2b-256
  answers.
* `tests/boundary_kat.rs` — `test-vectors/blake2/blake2-boundary-vectors.json`:
  unkeyed and 64-byte-keyed BLAKE2b-512 digests at input lengths from 0 to
  4096 bytes around the 128-byte block boundary (0, 1, 3, 63, 64, 65, 127,
  128, 129, 255, 256, 1024, 4096), each also replayed through the streaming
  hasher in block-aligned pieces.
* `src/backend.rs` — the default backend is the portable one and a second
  install is refused.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The compression function is fixed-shape arithmetic on 64-bit words with no
secret-dependent branch or table index, and hasher state is zeroed on drop.
**No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the keyed mode as designed for constant time
and unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
