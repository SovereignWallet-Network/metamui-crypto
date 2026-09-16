# Falcon — genuine upstream KAT (conformance gate)

This directory holds the **unmodified** Known-Answer-Test vectors produced by the
official Falcon **Round 3** reference implementation. It exists to answer the one
question nothing else in the tree answers:

> Does our Falcon port accept a signature produced by the *real* upstream Falcon?

## Why this is needed

Every other Falcon vector in `test-vectors/falcon/` carries
`"generator": "metamui-falcon512 Rust reference"` — i.e. it was produced by the
same code it is meant to validate. The 10-language cross-language suite proves the
bindings agree *with each other* (real interop value) but **cannot** detect a
shared divergence from the actual Falcon spec. These upstream `.rsp` files are the
external ground truth that closes that gap, exactly as
`test-vectors/aimer-upstream/` did for AIMer.

## Source (pinned for reproducibility)

Official Falcon Round 3 submission package:

- URL: `https://falcon-sign.info/falcon-round3.zip`
- `falcon-round3.zip` SHA-256:
  `d625407dbda9e5835f610aaeba1147e029988a6610e0107dfd292033138e1d47`
- KAT files inside the archive (`falcon-round3/KAT/`), full-file SHA-256:
  - `falcon512-KAT.rsp`  → `dd75c946fdedef4ec46a2bee7e10c65c9126f1a839b9ced6921fd45f7354b5cd`
  - `falcon1024-KAT.rsp` → `036a0bf5260573cec44977284dfef756cd1143db9961b981bd1fb55828acb20d`

The signed-message (`sm`) format is defined by the reference `nist.c`
(`crypto_sign`) — **not** the standalone `falcon.c` API:

```
sm = | sig_len (2 bytes, big-endian) | nonce (40 bytes) | message (mlen) | esig (sig_len) |
     esig[0]      = 0x20 + logn            # NIST KAT signature header (0x29 for n=512, 0x2A for n=1024)
     esig[1..]    = comp_encode(s2)        # Golomb-Rice compressed signature polynomial
     message hash = SHAKE256(nonce || message)   # NO domain-separation byte → this is Round 3, not FN-DSA
```

Key/header bytes: `pk[0] = 0x00 + logn` (0x09 / 0x0A), `sk[0] = 0x50 + logn`
(0x59 / 0x5A). The randomness for keygen + signing comes from the NIST
**AES-256 CTR_DRBG** seeded by the 48-byte `seed` field (see
`falcon-round3/KAT/generator/katrng.c`), which is why byte-exact reproduction of
`pk`/`sk`/`sm` requires that exact DRBG, not an ad-hoc SHA-256 stream.

## What is vendored here

The two `.rsp` files are trimmed to the **first 5 records per parameter set**
(full upstream files are 100 records / ~1–2 MB; record 0 alone catches
divergence). Each vendored file is a **byte-exact prefix** of the upstream file —
the `# Falcon-512` / `# Falcon-1024` header, LF line endings, and 48-byte NIST
seeds are preserved verbatim:

```
falcon-upstream/
  falcon512/falcon512-KAT.rsp     # 5 records, byte-exact prefix of upstream
  falcon1024/falcon1024-KAT.rsp   # 5 records, byte-exact prefix of upstream
  SHA256SUMS                      # pins the trimmed files
```

Verify the vendored bytes have not drifted:

```sh
cd test-vectors/falcon-upstream && shasum -a 256 -c SHA256SUMS
```

## Padded profile (Round-3 `falcon.h` FALCON_SIG_PADDED)

`falcon-padded-512/` and `falcon-padded-1024/` hold the NIST KAT record of PQClean's
`crypto_sign/falcon-padded-{512,1024}/clean` (version `20211101 with PQClean
patches`, PQClean @ `3730b32a`). PQClean
publishes no `.rsp` for these; its conformance artefact is `META.yml:
nistkat-sha256` — the SHA-256 of the single-record output of
`test/crypto_sign/nistkat.c` driven by the NIST AES-256 CTR_DRBG
(`test/common/nistkatrng.c`, entropy `00..2f`). `tools/falcon-padded-upstream-gen/genrun.sh`
rebuilds that harness from the vendored sources and refuses to write a file whose
hash differs from META.yml:

```
falcon-padded-512/falcon-padded-512-KAT.rsp    sha256 91842d41…3c0395  (= META.yml)
falcon-padded-1024/falcon-padded-1024-KAT.rsp  sha256 ddcc5683…8c8390  (= META.yml)
```

Record layout (`pqclean.c` `crypto_sign`): `sm = sig(CRYPTO_BYTES) ‖ message`,
`sig = (0x30+logn) ‖ nonce(40) ‖ comp_encode(s2) ‖ zero padding`, with
`CRYPTO_BYTES` = 666 (512) / 1280 (1024). Verification must reject a wrong total
length and any non-zero byte after the compressed body.

Gate: `metamui-crypto-rust/metamui-falcon512/tests/falcon_padded_upstream_kat.rs`
(`verify_padded` / `verify_padded_1024`; hard-fails when the file is absent).

### Size table (the numbers consumers must use)

| Profile | Falcon-512 | Falcon-1024 | Source |
|---|---|---|---|
| compressed, detached, **maximum** | 752 | 1462 | `falcon.h FALCON_SIG_COMPRESSED_MAXSIZE(logn)` |
| padded, exact | 666 | 1280 | `falcon.h FALCON_SIG_PADDED_SIZE(logn)`, PQClean `CRYPTO_BYTES` |
| CT, exact (not implemented) | 809 | 1577 | `falcon.h FALCON_SIG_CT_SIZE(logn)` |
| NIST `api.h CRYPTO_BYTES` (signed-message overhead, **not** a signature size) | 690 | 1330 | Round-3 `api.h` |

`metamui_falcon512::sizes` is the in-crate copy of this table. Sizing a buffer from
690 and copying `min(690)` bytes truncates valid compressed signatures
(consumer issue #7057).

## How the gate consumes these

`metamui-crypto-rust/metamui-falcon512/tests/falcon_upstream_kat.rs` (and the
per-binding equivalents) parse each record's `pk`, `msg`, and `sm`, then:

1. **Tier A — verify-only (hard gate).** Re-frame the upstream `sm` into the
   port's own wire format (strip the `0x20+logn` esig header, keep the compressed
   payload), feed `pk + signature + msg` to the port's verifier, and assert
   ACCEPT. A one-byte tamper must be REJECTED. Any rejection of a genuine
   signature is an **algorithm-level divergence** from canonical Falcon and fails
   the gate.
2. **Tier B — byte-exact reproduction (diagnostic, allowed to skip).** Drive the
   real NIST AES-256 CTR_DRBG from the 48-byte `seed` and attempt to reproduce
   `pk`/`sk`/`sm` byte-for-byte. A clean-room port may legitimately diverge on the
   Gaussian sampler (cf. SMAUG-T Finding #29), so this is reported, not enforced.

Gate behaviour mirrors the AIMer gate: file absent → **skip loudly**; file
self-generated (carries the `metamui-falcon512 Rust reference` marker) → **fail**
(anti-circularity guard); file genuine → verify **every** record, any rejection
fails. There is deliberately no self-sign fallback.

## Tier-B flat oracle (`flat/falcon-tierb.tsv`)

`flat/falcon-tierb.tsv` is derived from `falcon512/falcon512-KAT.rsp` by
`metamui-crypto-rust/metamui-falcon512/examples/derive_tierb.rs`
(`cargo run -p metamui-falcon512 --release --example derive_tierb`). For each
record it replays the official generator's NIST AES-256 CTR_DRBG schedule
(`katrng.c`, no derivation function; `randombytes(kg_seed,48)`,
`randombytes(nonce,40)`, `randombytes(sig_seed,48)`) and writes the derived
inputs beside the upstream answers:

```
variant  count  kg_seed(48)  nonce(40)  sig_seed(48)  msg  pk  sk  esig(0x29‖comp(s2))
```

so a binding can attempt byte-exact keygen (`SHAKE256(kg_seed)` PRNG) and
signing (`SHAKE256(sig_seed)` PRNG with the given nonce) without implementing
the DRBG. The replay is validated by the fact that every derived `nonce` equals
the nonce embedded in the upstream `sm`. In Rust the same seam is
`metamui_falcon512::kat_api::{derive_kat_inputs, keypair_from_kg_seed,
sign_with_nonce_seed}`, and `tests/falcon_upstream_kat.rs::upstream_reproduce_falcon512_byte_exact`
(`cargo test … -- --ignored --nocapture`) reports the first divergent stage per
record. Status 2026-09-03: DRBG schedule and nonce match on 5/5 records; keygen
and the sampler diverge from the reference's randomness-consumption order
(clean-room port), so `pk`/`sk`/`esig` are not yet byte-exact — see the audit
plan (WS1 P1.5 steps 2–3).

## Note on FN-DSA / FIPS 206

These are **Round 3** vectors — the only stable Falcon spec as of June 2026. NIST
submitted the FN-DSA draft (FIPS 206) for approval on 2025-08-28; the Initial
Public Draft and final standard are expected ~late 2026 / 2027. FN-DSA is expected
to add a message context / domain-separation prefix and possibly new encodings, so
when it publishes these vectors will need to be supplemented (not replaced) with
FN-DSA KATs.
