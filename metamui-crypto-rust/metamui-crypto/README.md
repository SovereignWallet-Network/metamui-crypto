# metamui-crypto

The public facade of MetaMUI Crypto: explicit profiles over the validated
algorithm crates of this workspace.

| profile | module | operations |
|---|---|---|
| `falcon-512.r3-compressed` | `falcon512` (`sign_compressed` / `verify_compressed`) | keygen, sign, verify |
| `falcon-512.r3-padded` | `falcon512` (`sign_padded` / `verify_padded`) | keygen, sign, verify |
| `ml-kem-768` | `mlkem768` | keygen, encapsulate, decapsulate |

## Contract

* **Encodings are fixed per profile.** Falcon-512 public key `0x09 ‖ 14-bit h`
  (897 bytes), secret key `0x59 ‖ f ‖ g ‖ F` (1281 bytes);
  `falcon-512.r3-compressed` signature `0x39 ‖ nonce(40) ‖ Golomb-Rice(s2)`,
  at most 752 bytes, trailing bytes rejected; `falcon-512.r3-padded`
  signature exactly 666 bytes, non-zero padding rejected. ML-KEM-768
  encapsulation key 1184, decapsulation key 2400, ciphertext 1088, shared
  secret 32 bytes, with the FIPS 203 §7.2/§7.3 input checks applied when a
  key is constructed from bytes.
* **Strict decoding.** Every typed value checks the exact length and the
  format header on construction; verification returns `Result<(), Error>`.
* **Randomness.** Every randomized operation takes a caller-supplied
  `RngCore + CryptoRng`; the `*_os` helpers (feature `std`) probe the
  operating-system source first and fail closed. There is no deterministic,
  seeded or known-answer entry point in this crate.
* **Compatibility.** A profile identifier never changes meaning; a change to
  any byte of an encoding is a new profile with a new identifier.

```rust
use metamui_crypto::{falcon512, mlkem768, Profile};

let mut rng = rand::rngs::OsRng;
let kp = falcon512::generate_keypair(&mut rng)?;
let sig = falcon512::sign_padded(&kp.secret_key, b"hello", &mut rng)?;
falcon512::verify_padded(&kp.public_key, b"hello", &sig)?;

let kem = mlkem768::generate_keypair(&mut rng)?;
let (ct, ss) = mlkem768::encapsulate(&kem.encapsulation_key, &mut rng)?;
assert_eq!(mlkem768::decapsulate(&kem.decapsulation_key, &ct)?, ss);

assert!(Profile::parse("ml-kem-512").is_err()); // not admitted: refused, not substituted
# Ok::<(), metamui_crypto::Error>(())
```

## Tests

```
cargo test -p metamui-crypto --release
```

* `tests/falcon512_upstream.rs` — NIST Round-3 and PQClean `falcon-padded-512`
  answer files replayed through the public API (verify every upstream
  signature; reject tampered, trailing-byte and non-zero-padding variants;
  sign with the upstream secret key).
* `tests/mlkem768_upstream.rs` — NIST ACVP FIPS 203 / FIPS203-tr1 vectors
  reproduced byte-for-byte through `generate_keypair` and `encapsulate` by
  scripting the caller's RNG; §7.2/§7.3 key-check rows rejected.
* `tests/negative.rs` — lengths, headers, padding, cross-profile misuse,
  implicit rejection, `Debug` redaction, `*_os` entry points.
* `tests/no_test_entropy_surface.rs` — no public function offers seeded or
  deterministic entropy; every RNG parameter is bound by `CryptoRng`.

`publish = false` until registry publication is authorized.
