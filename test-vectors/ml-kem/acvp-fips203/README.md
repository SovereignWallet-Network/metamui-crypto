# ML-KEM NIST FIPS 203 ACVP Vectors

NIST-authoritative ML-KEM test vectors vendored from
[`GiacomoPope/kyber-py`](https://github.com/GiacomoPope/kyber-py) — the
same mirror convention used by `test-vectors/ml-dsa/ml-dsa-{44,65,87}-kat.json`.

This directory complements [`../nist-kat.json`](../nist-kat.json):
- `../nist-kat.json` is the **MetaMUI cross-language consensus** set
  (deterministic from a single 32-byte seed via the in-house
  `d := seed`, `z := SHA3-256(seed || "z_derivation")` derivation).
- This directory is the **bare-FIPS-203 compliance** set (canonical
  ACVP vectors with independent `d` / `z` inputs as the spec defines).

The two attestations are independent.

## File layout

| File | Test mode | Inputs | Outputs | Vectors |
|---|---|---|---|---|
| `ml-kem-{512,768,1024}-keygen-acvp.json` | keyGen (AFT) | `d`, `z` (each 32 B) | `ek`, `dk` | 25 |
| `ml-kem-{512,768,1024}-encapdecap-acvp.json` | encapDecap (AFT + VAL) | encap: `ek`, `m`; decap: per-group `dk` + per-test `c` | encap: `c`, `k`; decap: `k` | encap=25, decap=10 |

## Source provenance

| Field | Value |
|---|---|
| Upstream repo | `https://github.com/GiacomoPope/kyber-py` |
| Upstream commit | `897923667b2fa80afcf910fc8c1825dddf54a97d` (2025-12-15) |
| Vendored | 2026-05-18 |
| ACVP vsId | 42 |
| ACVP revision | FIPS203 |

Each JSON file carries a `source` + `source_commit` field for grep-friendly traceability.

## How to consume

The crate at [`metamui-crypto-rust/metamui-mlkem`](../../../metamui-crypto-rust/metamui-mlkem/) already has an [`acvp_parser.rs`](../../../metamui-crypto-rust/metamui-mlkem/src/acvp_parser.rs) that consumes raw ACVP format. The vendored files in this directory have been transformed to the MetaMUI `test_vectors`-array convention but the per-vector `(d, z, ek, dk)` and `(ek, m, c, k)` fields are preserved verbatim from the ACVP source.

### Encapsulation byte-equality

Direct mapping to the existing deterministic API in `metamui_mlkem::mlkem{512,768,1024}::encapsulate_deterministic`:

```rust
let ek = PublicKey::from_bytes(&hex::decode(test["ek"])?)?;
let mut m = [0u8; 32];
m.copy_from_slice(&hex::decode(test["m"])?);
let (c, k) = encapsulate_deterministic(&ek, &m)?;
assert_eq!(c.as_ref(), &hex::decode(test["c"])?);
assert_eq!(k.as_ref(), &hex::decode(test["k"])?);
```

Wired in [`metamui-crypto-rust/metamui-mlkem/tests/acvp_fips203.rs`](../../../metamui-crypto-rust/metamui-mlkem/tests/acvp_fips203.rs).

### Decapsulation byte-equality

```rust
let dk = SecretKey::from_bytes(&hex::decode(group["decapsulation"]["dk"])?)?;
for test in group["decapsulation"]["test_vectors"] {
    let c = Ciphertext::from_bytes(&hex::decode(test["c"])?)?;
    let k = decapsulate(&dk, &c)?;
    assert_eq!(k.as_ref(), &hex::decode(test["k"])?);
}
```

### Key generation byte-equality — separate API needed

The ACVP keyGen vectors use FIPS 203 §6.1's `(d, z)` interface — two independent 32-byte inputs. The current `metamui_mlkem::*::generate_keypair_from_seed` API takes a single seed and derives `(d, z)` via the in-house convention, so it cannot byte-validate against ACVP keyGen vectors directly.

A future commit should add `generate_keypair_from_dz(d, z)` to each variant (~3 lines per variant, delegating to a new `kem::mlkem_keygen_from_dz`) to close this gap. The data files in this directory are ready to consume once that API lands.

## Finding #28 — CLOSED (2026-06-03, in-tree FIPS 203 port)

All 9 ACVP byte-equality tests (keyGen + encap + decap × 3 variants)
now **PASS** from **MetaMUI's own in-tree implementation**
(`metamui_mlkem::mlkem{512,768,1024}`), verified by
[`metamui-crypto-rust/metamui-mlkem/tests/acvp_fips203.rs`](../../../metamui-crypto-rust/metamui-mlkem/tests/acvp_fips203.rs)
and an in-crate engine test in `src/kem.rs`.

The earlier interim closure (2026-05-20) had routed the ACVP tests
through a thin wrapper over the third-party
[`fips203`](https://crates.io/crates/fips203) crate
(`src/fips203_backend.rs`). That shim — and the `fips203` dependency
— have been **removed**: the crate is internal-dependencies-only again.

### What the in-tree fix was

The in-tree implementation was a CRYSTALS-Kyber **Round-3** port whose
arithmetic (NTT/inverse-NTT/basemul, ByteEncode/ByteDecode, Compress,
SampleNTT, CBD, the FO transform and the implicit-reject KDF) was
already correct in VALUES. The only divergence from FIPS 203 final was
**orchestration**: a handful of misplaced NTT transforms that stored
`t̂`/`ŝ` in the wrong (normal) domain. The fix removed them so the keys
are packed in the NTT domain as FIPS 203 §5.1/§6.1 require — see
`src/{kem,indcpa}.rs`. ML-KEM byte-equality is representation-independent,
so normal-form arithmetic is retained (no Montgomery rewrite).

### Single source of truth

FIPS 203's native `(d, z)` interface is now the canonical interface
(`generate_keypair_from_dz` on each variant). The single-seed
`generate_keypair_from_seed` convenience (`d := seed`,
`z := SHA3-256(seed ‖ "z_derivation")`) is retained as a thin layer on
top, but its outputs now reflect the corrected FIPS-domain engine — so
`test-vectors/ml-kem/nist-kat.json` and `rust-fixtures-mlkem768.json`
must be regenerated (and the other 9 language bindings re-ported) as
part of the cross-language closure.

The historical bisection trail is preserved below for the audit
record (note: its pessimistic "multi-day rewrite" estimate did not
hold — the real fix was a few transform deletions).

---

## Surfaced finding (2026-05-18): MetaMUI ML-KEM is not FIPS 203 byte-equal

The first run of the byte-equality test wired in
[`metamui-crypto-rust/metamui-mlkem/tests/acvp_fips203.rs`](../../../metamui-crypto-rust/metamui-mlkem/tests/acvp_fips203.rs)
**FAILED at the first ACVP test vector for every variant**. This is the
silent-broken-crypto class Phase 2's audit cycle predicted: MetaMUI's
ML-KEM-{512,768,1024} implementations are deterministic, self-consistent
(`encap.ss == decap.ss` round-trip always), and produce plausible byte
counts — but they do not match FIPS 203 final-spec ACVP vectors at
either ciphertext or shared-secret level.

### Partial closure progress (2026-05-18, same day)

Three FIPS 203 IPD → final-spec divergences identified and fixed:

| # | Divergence | Where fixed |
|---|---|---|
| 1 | `K = SHAKE256(K_bar || H(c), 32)` (Round 3 KDF wrap) instead of `K = K_bar` (FIPS 203 final §6.2) | `src/kem.rs::mlkem_encapsulate`, `mlkem_encapsulate_deterministic`; `src/mlkem768/kem.rs::encapsulate_deterministic` |
| 2 | Decap rejection used `SHAKE256( (K_bar' OR z) || H(c), 32)` instead of `K_bar'` on valid + `SHAKE256(z &#124;&#124; c, 32)` on invalid | `src/kem.rs::mlkem_decapsulate`; `src/mlkem768/kem.rs::decapsulate` |
| 3 | `sample_noise(eta=3, ...)` read PRF bytes MSB-first; FIPS 203 §4.2.1 `BytesToBits` is LSB-first | `src/sampling.rs::sample_noise` eta=3 branch |

All 109 lib tests still pass (round-trip consistency preserved — the
in-house cross-language consensus set continues to interoperate).
`nist-kat.json` and `rust-fixtures-mlkem768.json` regenerated to reflect
the new shared-secret bytes.

The ACVP byte-equality tests still fail at the **ciphertext** level for
all encap tests and at the **shared secret** level for decap.

### Bisection update (2026-05-18 session 2)

To localise the remaining divergence, a 7th ACVP byte-equality test
([`acvp_mlkem512_keygen_byte_equality`](../../../metamui-crypto-rust/metamui-mlkem/tests/acvp_fips203.rs))
was added that exercises ONLY K-PKE.KeyGen against FIPS 203 ACVP
keyGen vectors via the new
[`generate_keypair_from_dz(d, z)`](../../../metamui-crypto-rust/metamui-mlkem/src/mlkem512.rs)
API (which matches FIPS 203 §6.1's two-32-byte-input interface
verbatim).

That test also fails — 766 of 800 ek bytes diverge from ACVP, with
the trailing 32 bytes (ρ) matching exactly. That means:
- `G(d || k)` correctly produces ρ ✓ (only 32 of 800 bytes match)
- Everything that produces `t_hat` (matrix A sampling, noise s/e
  sampling, NTT, matrix multiply, ByteEncode_12 packing) diverges

This is a **cumulative, deep-rooted divergence** rather than a single
isolated bug. The in-tree implementation is a Kyber Round 3 port, and
the gap to FIPS 203 final includes at least:

- `SampleNTT(B)` outputs are treated as NTT-domain representation
  directly (FIPS 203 §4.2.2). MetaMUI applies `ntt()` to the uniform
  sample output, double-transforming.
- `ek = ByteEncode_12(t_hat) || ρ` packs the NTT-domain `t_hat`
  (FIPS 203 §6.1). MetaMUI inverse-NTTs `t` before packing.
- Likewise `dk = ByteEncode_12(s_hat) || ek || H(ek) || z` packs
  NTT-domain `s_hat`. MetaMUI inverse-NTTs `s` before packing.

Attempting any subset of these changes in isolation breaks the
in-tree round-trip tests — the implementation has compensating
inversions across keygen, encap, and decap that all need to flip
together. The required scope is a multi-day FIPS-203-port rewrite.

### Recommended closure path

Two viable options for closing Finding #28 fully:

**(A) `fips203` crate migration** (~1-2 days, recommended):
Replace the in-tree `metamui-mlkem` implementation with a thin
wrapper over the [`fips203`](https://crates.io/crates/fips203) crate
(pure-Rust FIPS 203 final-spec implementation, NIST-CAVP validated).
This matches the project's established pattern: `metamui-dilithium`
already delegates to `fips204` and `metamui-slhdsa` to `fips205` (the
reference harness's `Cargo.toml` in the source repository).
Pros: high confidence, immediate ACVP byte-equality. Cons: BREAKING
to all language ports that depend on MetaMUI's current key-layout
convention.

**(B) Multi-day in-tree FIPS 203 port** (~5-10 days):
Rewrite `metamui-mlkem/src/{kem,indcpa,sampling,polynomial,ntt}.rs`
to FIPS 203 final spec line-by-line. Mirrors the C tree's Argon2
Finding #18 closure pattern (also ~5 days). Pros: preserves educational
value of pure in-house impl. Cons: long, error-prone, redundant with
the verified `fips203` crate.

### Infrastructure ready for whichever path is taken

The following pieces of infrastructure landed in this session and are
ready to consume the closure work:

- 6 ACVP test-vector JSONs (keyGen + encapDecap × 3 variants)
- 6 `#[ignore]`d byte-equality tests in `tests/acvp_fips203.rs`
- `mlkem_keygen_from_dz` / `generate_keypair_from_dz` API on all three
  variants (matches FIPS 203 §6.1 `(d, z)` interface verbatim)
- `mlkem-kat-generator` tooling with full-suite regenerate.sh
- Lint tier-3 `lengths-only-kat` check preventing antipattern regression

When the chosen closure path lands, removing the 6 `#[ignore]`s is the
green-light signal. The regression net is wired.

| Test | First failing tcId | Mismatch |
|---|---|---|
| `acvp_mlkem512_encapsulation_byte_equality` | tc 1 | ciphertext + shared secret |
| `acvp_mlkem512_decapsulation_byte_equality` | tc 76 | shared secret |
| `acvp_mlkem768_encapsulation_byte_equality` | tc 26 | ciphertext + shared secret |
| `acvp_mlkem1024_encapsulation_byte_equality` | tc 51 | ciphertext + shared secret |
| `acvp_mlkem1024_decapsulation_byte_equality` | tc 96 | shared secret |

The five tests are gated behind `#[ignore]` until the implementation is
brought to byte-equality. Re-run explicitly:

```bash
cargo test --manifest-path metamui-crypto-rust/Cargo.toml \
    -p metamui-mlkem --release \
    --features "mlkem512 mlkem768 mlkem1024" \
    --test acvp_fips203 -- --ignored
```

The cross-language consensus set at [`../nist-kat.json`](../nist-kat.json)
remains valid and unaffected — implementations targeting the in-house
seed-derivation convention will continue to interoperate byte-equally
under that contract. Only FIPS 203 final-spec compliance is gapped.

Likely root cause domains (not yet bisected):

1. K-PKE.Encrypt (`metamui-mlkem/src/indcpa.rs`) — between FIPS 203 IPD
   and final, the input ordering / sampling convention changed
2. NTT zeta constants or Barrett-reduction split
3. Polynomial-vector compression boundary

This is **Finding #28** in the Phase 2 audit-cycle index. Closure
requires:
1. Bisect to the diverging primitive via the existing in-tree generator
   (compare per-stage intermediate state to FIPS 203 final-spec).
2. Fix the divergence in-place.
3. Remove the `#[ignore]` attributes from the five tests; suite must turn
   green at the next CI run.

## What the lint protects

The tier-1/2/3 lint (`tools/swift-review/lint_test_vectors.py` in the source repository) scans every file in this directory:
- Tier 1 (universal placeholder): none of these files contains pseudocode markers — the bytes are raw ACVP hex.
- Tier 2 (strict hex): `d`/`z`/`ek`/`dk`/`c`/`k`/`m` fields are all valid even-length hex.
- Tier 3 (lengths-only KAT): these are NOT lengths-only — every test vector carries real bytes.

Running `python3 tools/swift-review/lint_test_vectors.py` after editing any file in this directory must produce `Scanned NNN JSON file(s) — all clean ✓`.

## Why two sources (kyber-py mirror, not usnistgov/ACVP-Server directly)?

The GiacomoPope mirror provides the same JSON content with a stable, single-commit URL pattern (one Python repo with `assets/ML-KEM-keyGen-FIPS203/{prompt,expectedResults}.json` and `assets/ML-KEM-encapDecap-FIPS203/{prompt,expectedResults}.json`). The authoritative `github.com/usnistgov/ACVP-Server` repo is multiple gigabytes with vectors spread across `gen-val/json-files/ML-KEM-*-FIPS203/` directories — same content, harder to pin. We chose the mirror to match the precedent set by `test-vectors/ml-dsa/ml-dsa-44-kat.json` (which cites `GiacomoPope/dilithium-py`).

If a discrepancy is ever found between the mirror and the upstream NIST source, the upstream wins — re-fetch via:

```bash
gh api -H "Accept: application/vnd.github.raw" \
   repos/usnistgov/ACVP-Server/contents/gen-val/json-files/ML-KEM-keyGen-FIPS203/prompt.json \
   > /tmp/prompt.json
```
