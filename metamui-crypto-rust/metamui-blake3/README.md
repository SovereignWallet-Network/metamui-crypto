# metamui-blake3

BLAKE3 in Rust — hash, keyed hash, key derivation and the extendable output —
verified against the BLAKE3 team's official test vectors. The public entry
surface of MetaMUI Crypto is the `metamui-crypto` facade in this workspace;
this crate is the implementation behind its `blake3` module and can also be
used directly.

## Modes and output

| mode | entry point | key / context | output |
|---|---|---|---|
| hash | `hash`, `MetaMUIBlake3::hash`, `Hasher` | none | 32 bytes, or any length through the XOF |
| keyed hash | `keyed_hash`, `MetaMUIBlake3::hash_keyed`, `Blake3Mac` | 32-byte key | 32 bytes, or any length |
| derive key | `MetaMUIBlake3::derive_key`, `Hasher::new_derive_key`, `kdf` | context string | any length |

The output of any length is the BLAKE3 XOF (successive root-block
compressions), so the first 32 bytes of a long output are the 32-byte digest,
and every length agrees with the reference implementation. `finalize_seek`
returns the 32-byte digest and ignores its argument.

## Usage

```rust
use metamui_blake3::{MetaMUIBlake3, Blake3Key, Blake3Mac};

// one-shot and incremental
let digest = MetaMUIBlake3::new().hash(b"hello world");
let mut hasher = MetaMUIBlake3::new();
hasher.update(b"hello ");
hasher.update(b"world");
assert_eq!(hasher.finalize(), digest);

// extendable output
let xof = hasher.finalize_variable(131);
assert_eq!(&xof[..32], digest.as_bytes());

// keyed hash and MAC
let key = Blake3Key::new([42u8; 32]);
let tag = Blake3Mac::new(key).mac(b"message");

// derive key
let derived = MetaMUIBlake3::derive_key("MyApp 2025-01-01 session key", b"input key material", 32);
# let _ = (tag, derived);
```

`hash`, `keyed_hash`, `Hash` and `Hasher` at the crate root mirror the
`blake3` crate's API, so `blake3 = { package = "metamui-blake3" }` in a
`Cargo.toml` needs no source change for those calls.

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | operating-system randomness for `Blake3Key::random` |
| `serde` | no | `Serialize`/`Deserialize` on the hash and key types |
| `multithreading` | no | the `parallel` module: tree hashing of one message across threads (`parallel::hash`) and many messages at once (`ParallelHasher`), on Rayon; the outputs are the same bytes |
| `batch-api` | no | the `batch` module: up to sixteen messages per call; the same bytes |
| `lthash` | no | `batch::lthash`, a homomorphic (LtHash) construction over BLAKE3 output — not part of BLAKE3 |
| `kdf` | no | the `kdf` module, a wrapper around derive_key mode |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. The single-message API
runs the compression function directly. The two many-input operations —
hashing several inputs at once, and the chunk chaining values of the tree
hash — go through `backend::backend()`, whose default is the portable
implementation in `backend::portable`; `backend::install` lets a separate
crate replace it once, before the first many-input operation of the
process, with an implementation that must reproduce the portable output
exactly. This crate ships no other backend.

`--no-default-features` builds `no_std` (with `alloc`).

## Tests

```
cargo test -p metamui-blake3 --release
```

* `tests/kat_vectors.rs` — the BLAKE3 team's `test_vectors.json`
  (`test-vectors/blake3/blake3-official-vectors.json`, 35 cases): the 32-byte
  digest and the full 131-byte output in hash, keyed and derive_key mode,
  odd-sized streaming splits, and the same cases again through `hash_many`,
  `batch::batch_hash`, `parallel::hash` and `parallel::hash_keyed`.
* `tests/multi_chunk_vectors.rs` — block and chunk boundaries of the public API.
* `tests/basic_correctness.rs`, `tests/derive_key_reference.rs` — digests
  recorded from `b3sum`.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The compression function is straight-line arithmetic with no
secret-dependent branch or index, and key material is zeroized on drop; MAC
verification compares in constant time. **No timing or side-channel
measurement has been made and no independent audit has taken place**; treat
the implementation as designed for constant time and unmeasured. Fault and
power attacks are out of scope. See `SECURITY.md` at the root of the
distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution. BLAKE3 is specified by Jack O'Connor, Jean-Philippe Aumasson,
Samuel Neves and Zooko Wilcox-O'Hearn; the test vectors are theirs
(CC0 / Apache-2.0), and their notice is in `THIRD_PARTY_NOTICES.md`.
