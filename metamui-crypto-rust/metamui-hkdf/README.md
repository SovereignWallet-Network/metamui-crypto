# metamui-hkdf

HKDF (RFC 5869) in Rust with HMAC-SHA-256 and HMAC-SHA-512, verified against
the RFC 5869 Appendix A answer file. HMAC (RFC 2104) is built in this crate
on the one-shot hashes of `metamui-sha2`; nothing is taken from another
crypto crate.

## What is implemented

| entry point | hash | what it does |
|---|---|---|
| `MetaMUIHkdfSha256::derive`, `hkdf_sha256`, `hkdf_sha256_hex` | SHA-256 | extract-and-expand in one step |
| `MetaMUIHkdfSha256::extract`, `hkdf_extract_sha256` | SHA-256 | extract only: `PRK = HMAC(salt, IKM)` |
| `MetaMUIHkdfSha256::expand`, `hkdf_expand_sha256` | SHA-256 | expand only, from a 32-byte PRK |
| `MetaMUIHkdfSha512::…`, `hkdf_sha512`, `hkdf_extract_sha512`, `hkdf_expand_sha512`, `hkdf_sha512_hex` | SHA-512 | the same three shapes, 64-byte PRK |

A `None` salt is the RFC's default: `HashLen` zero bytes. The output length
must be at least 1 and at most `255 × HashLen` (8160 bytes for SHA-256,
16320 for SHA-512); anything else is `HkdfError::InvalidOutputLength`, and a
PRK of the wrong length is `HkdfError::InvalidKey`. The struct entry points
return `HkdfResult { output_key_material, length }`; the free functions
return the bytes. `format_hex` and `parse_hex` handle `0x`-prefixed hex.

## Usage

```rust
use metamui_hkdf::{hkdf_sha256, hkdf_extract_sha256, hkdf_expand_sha256};

let ikm  = b"input keying material".to_vec();
let salt = Some(b"salt".to_vec());
let info = b"context".to_vec();

let okm = hkdf_sha256(ikm.clone(), salt.clone(), info.clone(), 42)?;

// the same in two phases
let prk = hkdf_extract_sha256(ikm, salt);
assert_eq!(hkdf_expand_sha256(prk, info, 42)?, okm);
# Ok::<(), metamui_hkdf::HkdfError>(())
```

## Features

The crate has no features. Every code path is portable scalar Rust; there
is no SIMD, assembly or GPU path and no CPU-feature detection.

## Tests

```
cargo test -p metamui-hkdf --release
```

* `tests/kat_vectors.rs` — `test-vectors/hkdf/rfc5869-vectors.json`, the
  three RFC 5869 Appendix A SHA-256 cases (basic, longer inputs, zero-length
  salt and info), checking both the PRK and the OKM.
* unit tests in `src/lib.rs` and `src/hkdf_native.rs` — the same RFC cases
  inline, the RFC 2104 HMAC-SHA-256 answer, and the length and salt rules.

HKDF-SHA-512 has no answer file in this repository; it is exercised by the
inline length tests only. A missing vector file fails the run; nothing
skips.

## What is and is not claimed

HMAC and HKDF are fixed-shape compositions of the hash; the only
data-dependent step is the RFC's key-longer-than-block hashing in HMAC,
which depends on the salt or PRK length, not its bytes. Intermediate
buffers are not zeroed. **No timing or side-channel measurement has been
made and no independent audit has taken place**; treat the implementation
as designed for constant time and unmeasured. Fault and power attacks are
out of scope. See `SECURITY.md` at the root of the distribution for what a
security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
