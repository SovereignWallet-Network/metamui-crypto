# metamui-argon2

Argon2d, Argon2i and Argon2id (RFC 9106) in Rust, written after the PHC
reference implementation and verified against the RFC 9106 test vectors,
the argon2-cffi (reference C) known answers and two MetaMUI oracles for
parameter edges and the pre-RFC version 0x10.

## What is implemented

| entry point | what it does |
|---|---|
| `argon2_hash(pwd, salt, t_cost, m_cost, parallelism, hash_len, Argon2Type, version)` | one-shot tag; `version` is `ARGON2_VERSION_13` (RFC 9106) or `ARGON2_VERSION_10` |
| `Context::new(..)`, `.with_secret(..)`, `initialize`, `fill_memory_blocks`, `finalize` | the reference's stages, for callers that carry a secret key or associated data |
| `Argon2Type::{Argon2d, Argon2i, Argon2id}` | the three variants of RFC 9106 §3.1 |
| `blake2b::blake2b_long` | the H′ variable-length hash of RFC 9106 §3.3 (exposed because the reference exposes it) |

Memory cost is in KiB, time cost in passes, parallelism in lanes; the
parameter bounds of RFC 9106 §3.1 are enforced and the tag length may be
any value from 4 bytes. Memory is filled lane by lane in one thread whatever the
parallelism value; the result is the same as the reference's threaded fill.

## Usage

```rust
use metamui_argon2::{argon2_hash, Argon2Type, ARGON2_VERSION_13};

let tag = argon2_hash(b"password", b"somesalt", 2, 65536, 1, 32,
                      Argon2Type::Argon2id, ARGON2_VERSION_13).unwrap();
assert_eq!(tag.len(), 32);
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | `thiserror` errors and hex helpers; without it the crate is `no_std` + `alloc` |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection.

## Tests

```
cargo test -p metamui-argon2 --release
```

* `tests/argon2_kat_vectors.rs` — `test-vectors/argon2/argon2-cffi-kat.json`
  (the argon2-cffi / libargon2 known answers for the three variants) and
  `test-vectors/argon2/argon2-test-vectors.json` (RFC 9106 §5 and the PHC
  reference, 13 cases).
* `tests/test_vectors.rs` — the PHC reference answers, inline.
* `tests/argon2_edge_oracle.rs` — `test-vectors/argon2/argon2-edge-oracle.json`:
  memory not a multiple of 4·p, tag lengths 4 to 100, secret and associated
  data, the §3.1 bounds.
* `tests/argon2_v10_oracle.rs` — `test-vectors/argon2/argon2-v10-oracle.json`:
  21 version-0x10 cases with their 0x13 counterparts.
* `tests/blake2b_reference_test.rs` — H′ against the reference.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The memory-filling loop of Argon2i and the Argon2i half of Argon2id index memory independently of the password, as the specification requires; Argon2d does not, by design. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
